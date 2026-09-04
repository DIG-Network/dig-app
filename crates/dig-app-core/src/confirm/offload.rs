//! Run a biometric prompt on a worker thread while the caller keeps servicing its own event loop.
//!
//! # Why this exists
//!
//! The tray dispatches menu actions from INSIDE its event loop, on the UI thread. On Windows the
//! biometric step was `UserConsentVerifier::RequestVerificationAsync(..).get()`, and
//! `IAsyncOperation::get()` blocks the thread it is called on. Windows Hello needs that thread to pump
//! messages in order to raise its prompt, so the thread waited for Hello and Hello waited for the
//! thread: the consent window never appeared and the tray stopped responding. "Nothing happens" and
//! "the app is frozen" were one event, not two (dig_ecosystem#1926).
//!
//! That froze the whole biometric CLASS — replace-with-new, restore-from-phrase, remove-account,
//! reveal-the-recovery-phrase, and every `confirm_sign`/`confirm_pair`/`confirm_connect` reaching the
//! tray. The seam that makes custody safe was the seam that made custody unusable.
//!
//! [`verify_off_thread`] fixes the SHAPE rather than one call site: the OS verification runs on its own
//! thread, and the caller waits by polling with an idle hook — the Windows backend passes its message
//! pump, so the UI thread keeps drawing and Hello keeps being able to raise its prompt.
//!
//! # Fail-closed, structurally
//!
//! [`VerifyOutcome::Verified`] is never NAMED in this module's implementation. The single value
//! [`verify_off_thread`] can return other than the literal [`VerifyOutcome::Unavailable`] is the one the
//! worker itself produced and delivered in time. A deadline, a panicked worker, a dropped sender, a
//! thread that could not be spawned, or an outcome that arrives too late therefore cannot be read as
//! approval — not because each case is checked, but because there is no expression here that could
//! construct an approval.

use std::sync::mpsc::{self, RecvTimeoutError};
use std::thread;
use std::time::{Duration, Instant};

use super::VerifyOutcome;

/// How long the caller sleeps between checks for the worker's answer.
///
/// Short enough that the idle hook runs often enough to keep a UI responsive, long enough that waiting
/// for a human to touch a fingerprint reader is not a spin loop.
const POLL: Duration = Duration::from_millis(10);

/// Run `verify` on a dedicated worker thread, calling `while_waiting` on THIS thread until it answers.
///
/// `while_waiting` is the caller's "I am still alive" work — on Windows, its message pump. It runs only
/// between polls, so it never re-enters the caller's own dispatch.
///
/// Returns the worker's outcome when it arrives within `deadline`, and [`VerifyOutcome::Unavailable`] in
/// every other circumstance (see the module docs for why that is structural rather than checked).
pub(crate) fn verify_off_thread<V, W>(
    reason: &str,
    verify: V,
    mut while_waiting: W,
    deadline: Duration,
) -> VerifyOutcome
where
    V: FnOnce(String) -> VerifyOutcome + Send + 'static,
    W: FnMut(),
{
    // A bounded channel with a slot to spare: a worker whose answer arrives after the caller has given
    // up sends into a receiver that is already gone and simply exits, rather than parking forever.
    let (tx, rx) = mpsc::sync_channel::<VerifyOutcome>(1);
    let reason = reason.to_owned();

    let spawned = thread::Builder::new()
        .name("dig-biometric".to_string())
        .spawn(move || {
            let _ = tx.send(verify(reason));
        });
    if spawned.is_err() {
        // No worker, so no verification happened at all.
        return VerifyOutcome::Unavailable;
    }

    let started = Instant::now();
    loop {
        match rx.recv_timeout(POLL) {
            Ok(outcome) => return outcome,
            // The worker panicked, or dropped its sender without answering.
            Err(RecvTimeoutError::Disconnected) => return VerifyOutcome::Unavailable,
            Err(RecvTimeoutError::Timeout) => {
                if started.elapsed() >= deadline {
                    return VerifyOutcome::Unavailable;
                }
                while_waiting();
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::{
        gated_consent, BiometricVerifier, ConfirmContent, ConfirmDecision, DestroyPrompt,
        ForegroundWindow, WindowIntent,
    };
    use super::*;
    use std::sync::mpsc::channel;
    use std::thread::ThreadId;

    /// A deadline no honest wait in these tests can reach, for the cases that are not about timing out.
    const PATIENT: Duration = Duration::from_secs(30);

    /// The property the shipped bug violated: the OS call must NOT run on the caller's thread.
    ///
    /// An implementation that called the verifier inline would satisfy every outcome-mapping test in
    /// this module and still deadlock the tray, so the PLACEMENT is asserted directly rather than
    /// inferred from a result.
    #[test]
    fn verification_runs_off_the_calling_thread() {
        let (report, observed) = channel::<ThreadId>();
        let caller = thread::current().id();

        let outcome = verify_off_thread(
            "reveal",
            move |_| {
                report.send(thread::current().id()).expect("id delivered");
                VerifyOutcome::Verified
            },
            || {},
            PATIENT,
        );

        assert_eq!(outcome, VerifyOutcome::Verified);
        let ran_on = observed.recv().expect("the worker reported its thread");
        assert_ne!(
            ran_on, caller,
            "verification ran on the caller's thread, which is the deadlock"
        );
    }

    /// The caller's event loop must keep being serviced while verification is outstanding.
    ///
    /// The verifier parks for far longer than one poll interval; a caller blocked inside it would run
    /// the idle hook exactly zero times.
    #[test]
    fn the_caller_keeps_working_while_verification_is_outstanding() {
        let mut ticks = 0usize;

        let outcome = verify_off_thread(
            "reveal",
            |_| {
                thread::sleep(Duration::from_millis(300));
                VerifyOutcome::Verified
            },
            || ticks += 1,
            PATIENT,
        );

        assert_eq!(outcome, VerifyOutcome::Verified);
        assert!(
            ticks > 0,
            "the caller never got control back while the authenticator was up"
        );
    }

    /// Every outcome the platform can report is delivered unchanged — the offload adds no policy.
    #[test]
    fn each_outcome_is_delivered_unchanged() {
        for expected in [
            VerifyOutcome::Verified,
            VerifyOutcome::Declined,
            VerifyOutcome::Failed,
            VerifyOutcome::Unavailable,
        ] {
            assert_eq!(
                verify_off_thread("reveal", move |_| expected, || {}, PATIENT),
                expected
            );
        }
    }

    /// The reason string reaches the platform verbatim — it is what the Hello prompt shows the user.
    #[test]
    fn the_reason_reaches_the_verifier_verbatim() {
        let (report, observed) = channel::<String>();
        verify_off_thread(
            "Destroy",
            move |reason| {
                report.send(reason).expect("reason delivered");
                VerifyOutcome::Declined
            },
            || {},
            PATIENT,
        );
        assert_eq!(observed.recv().expect("the worker reported"), "Destroy");
    }

    /// A verification that answers only AFTER the deadline must never be read as approval.
    ///
    /// The worker returns `Verified` deliberately: a fixture that timed out returning `Declined` could
    /// not tell an honest refusal apart from a fail-closed default, so it would prove nothing.
    #[test]
    fn an_outcome_that_arrives_after_the_deadline_is_not_approval() {
        let outcome = verify_off_thread(
            "reveal",
            |_| {
                thread::sleep(Duration::from_millis(400));
                VerifyOutcome::Verified
            },
            || {},
            Duration::from_millis(50),
        );

        assert_eq!(outcome, VerifyOutcome::Unavailable);
    }

    /// A worker that dies without answering fails closed rather than leaving the caller waiting.
    #[test]
    fn a_panicked_worker_fails_closed() {
        let previous = std::panic::take_hook();
        std::panic::set_hook(Box::new(|_| {}));
        let outcome = verify_off_thread(
            "reveal",
            |_| panic!("the authenticator exploded"),
            || {},
            PATIENT,
        );
        std::panic::set_hook(previous);

        assert_eq!(outcome, VerifyOutcome::Unavailable);
    }

    /// A window that approves and a verification that never answers: the gate must still refuse.
    ///
    /// Asserted at the SEAM that authorizes rather than on the helper alone, because the property the
    /// offload must not break is the one `gated_consent` exists for — no approval without a `Verified`.
    #[test]
    fn a_timed_out_verification_does_not_authorize_the_gated_action() {
        struct SlowVerifier;
        impl BiometricVerifier for SlowVerifier {
            fn verify(&self, reason: &str) -> VerifyOutcome {
                verify_off_thread(
                    reason,
                    |_| {
                        thread::sleep(Duration::from_millis(400));
                        VerifyOutcome::Verified
                    },
                    || {},
                    Duration::from_millis(50),
                )
            }
        }

        struct ApprovingWindow;
        impl ForegroundWindow for ApprovingWindow {
            fn show(&self, _content: &ConfirmContent) -> WindowIntent {
                WindowIntent::Approve
            }
        }

        let content = ConfirmContent::destroy(&DestroyPrompt {
            subject: "the DIG Account on this computer",
            replacement: "",
            recoverable: true,
        });

        assert_eq!(
            gated_consent(&content, &ApprovingWindow, &SlowVerifier),
            ConfirmDecision::Unavailable
        );
    }
}
