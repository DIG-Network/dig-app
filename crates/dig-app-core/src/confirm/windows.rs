//! The Windows native confirmer (SIGN-3): the branded prompt window + Windows Hello.
//!
//! The window is drawn by [`super::gui`], the same one Linux draws. The biometric step is the WinRT
//! [`UserConsentVerifier`], which raises the secure Windows Hello prompt (fingerprint / face / PIN — the
//! PIN/password being the built-in fallback, §5.6.1). The FFI call reduces to a result code, and the
//! code→outcome mapping is a pure function unit-tested here.
//!
//! # How the window got here
//!
//! It was a `MessageBoxW` until dig_ecosystem#1832: a message box cannot relabel its buttons, so every
//! two-choice window had to spell its choice out in a sentence beneath the body, and the destroy
//! window's way out was a button labelled "Cancel" — which names the dialog, not the outcome a
//! hesitating person is looking for. That was replaced by a hand-built, DPI-scaled Win32 GDI window,
//! and that in turn by the branded GUI (dig_ecosystem#2038), which draws the same window on every
//! platform that can draw one. There is exactly one prompt renderer left in the app.
//!
//! An interactive user on Windows always has a window station, so [`confirmer`] returns the backend
//! unconditionally; a session-0 service host degrades naturally (the confirm window cannot be created and
//! `UserConsentVerifier` reports the device unavailable, which fails closed via [`VerifyOutcome`]).

use std::time::Duration;

use windows::core::HSTRING;
use windows::Security::Credentials::UI::{UserConsentVerificationResult, UserConsentVerifier};
use windows::Win32::Foundation::HWND;
use windows::Win32::System::WinRT::{RoInitialize, RoUninitialize, RO_INIT_MULTITHREADED};
use windows::Win32::UI::WindowsAndMessaging::{
    DispatchMessageW, PeekMessageW, PostQuitMessage, TranslateMessage, MSG, PM_REMOVE, WM_QUIT,
};

use super::offload::verify_off_thread;
use super::{BackedConfirmer, BiometricVerifier, NativeConfirmer, VerifyOutcome};

/// How long to wait for Windows Hello before giving up and failing closed.
///
/// Generous, because the person may have to find their fingerprint reader or type a PIN, but finite: an
/// authenticator that never answers must cost the user one refused action, never a permanently wedged
/// tray. Hello's own prompt expires well inside this. It lives here rather than beside the offload
/// because it is THIS backend's policy, not a property of running work on another thread.
const VERIFY_DEADLINE: Duration = Duration::from_secs(180);

/// The most messages one idle tick will dispatch before returning to check for Hello's answer.
///
/// Bounded so a busy window cannot starve the check: the caller must come back and notice that
/// verification finished, however much repainting the desktop is asking for.
///
/// This bound belongs to the Hello wait ALONE. The other caller — the prompt window's deferred
/// destruction — needs the opposite guarantee and gets [`drain_pending`].
const PUMP_BUDGET: usize = 64;

/// A [`BiometricVerifier`] backed by the WinRT [`UserConsentVerifier`] (Windows Hello).
///
/// # Why the call is not made here
///
/// [`UserConsentVerifier::RequestVerificationAsync`] returns an `IAsyncOperation`, and `get()` BLOCKS
/// the thread it is called on. This verifier is reached from the tray's menu dispatch, which runs
/// inside the tray's event loop — so `get()` used to block the very UI thread Windows Hello needs to
/// raise its prompt. The thread waited for Hello, Hello waited for the thread, and every custody
/// action in the app hung the tray permanently (dig_ecosystem#1926).
///
/// So the WinRT call runs on its own thread via [`verify_off_thread`], where it is free to block, and
/// the caller waits by pumping its messages. Nothing about the DECISION changes: only a `Verified`
/// delivered by that thread within the deadline authorizes anything.
struct HelloVerifier;

impl BiometricVerifier for HelloVerifier {
    fn verify(&self, reason: &str) -> VerifyOutcome {
        let message = format!("Confirm to {reason} with your DIG identity");
        verify_off_thread(
            &message,
            holding_the_surface_open(request_consent),
            pump_pending,
            VERIFY_DEADLINE,
        )
    }
}

/// Wrap `verify` so the consent surface stays reported for as long as the WORKER THREAD that runs
/// it is alive, not merely for as long as the caller's own wait lasts (dig_ecosystem#105).
///
/// `BackedConfirmer::gate` raises its own [`surface::Raised`] around the whole gate, but that guard
/// drops the instant `gate` returns -- which on a timeout is exactly `VERIFY_DEADLINE` after the
/// wait began, whatever the real Windows Hello prompt is doing. Hello's own `IAsyncOperation` has no
/// deadline of its own and nothing here cancels it (dig_ecosystem#105's harder candidate fix), so the
/// worker thread stays blocked in it -- with the platform prompt still genuinely on screen -- for as
/// long as the user leaves it unanswered.
///
/// Moving a SECOND, independent guard into the worker closure keeps the count honest for that whole
/// span: it raises right before `verify` runs and drops the instant `verify` returns, on the WORKER's
/// own timeline, decoupled from whatever the caller decided at its deadline. Over-reporting past a
/// deadline the caller already gave up on is the fail-safe direction (surface.rs's own contract) --
/// it can only ever decline a foreground claim, never grant one that should have been refused.
fn holding_the_surface_open<F>(verify: F) -> impl FnOnce(String) -> VerifyOutcome
where
    F: FnOnce(String) -> VerifyOutcome,
{
    move |message| {
        let _on_screen = crate::confirm::surface::Raised::now();
        verify(message)
    }
}

/// Raise the Windows Hello prompt and report what it said. Runs on the worker thread.
///
/// The thread joins the multi-threaded apartment first: a freshly spawned thread belongs to no
/// apartment, and WinRT activation from one fails outright. The MTA is also what makes the blocking
/// `get()` legal — the completion is delivered directly rather than through a message pump this thread
/// does not have.
fn request_consent(message: String) -> VerifyOutcome {
    // SAFETY: called once on a thread that has just been created and has no apartment; the matching
    // `RoUninitialize` below runs before the thread ends.
    let initialized = unsafe { RoInitialize(RO_INIT_MULTITHREADED) }.is_ok();

    let outcome = match UserConsentVerifier::RequestVerificationAsync(&HSTRING::from(message))
        .and_then(|op| op.get())
    {
        Ok(result) => outcome_from_consent(result),
        // A failure to even start verification (no authenticator, RPC error, no apartment) fails closed.
        Err(_) => VerifyOutcome::Unavailable,
    };

    if initialized {
        // SAFETY: balances the successful `RoInitialize` above, on the same thread.
        unsafe { RoUninitialize() };
    }
    outcome
}

/// Dispatch up to [`PUMP_BUDGET`] of the messages waiting for this thread, then return.
///
/// The "I am still alive" hook for the Hello wait above, so the tray keeps painting while the
/// authenticator is up (dig_ecosystem#1926). The BUDGET is the point: the caller must get control
/// back and notice that verification finished, however much repainting the desktop is asking for.
///
/// A `WM_QUIT` is put back rather than consumed: it belongs to the event loop that owns this thread,
/// and swallowing it here would leave the app unable to exit.
pub(super) fn pump_pending() {
    pump(Some(PUMP_BUDGET));
}

/// Dispatch the messages waiting for this thread, up to [`DRAIN_BUDGET`].
///
/// The prompt window calls this after its event loop exits, to deliver the destroy message `winit`
/// posted rather than performed (see `gui::window::flush_deferred_window_destruction`). Here the
/// requirement is the opposite of the Hello wait's: nothing is waiting for control back, and a
/// budget that ran out one message before the destroy would leave the consent window on screen with
/// a dead message pump — the exact defect the flush exists to prevent (dig_ecosystem#2038). The two
/// callers shared a bound chosen for one of them (dig_ecosystem#2074).
///
/// # Why it is still BOUNDED, generously, rather than unbounded
///
/// An unbounded drain here looks safe and is not. The flush runs after winit's `reset_runner()`, so
/// `should_buffer()` is true and winit's own `WM_PAINT` handler RE-INVALIDATES the window on every
/// paint (winit 0.30.13 `windows/event_loop.rs:1276`) — the queue refills itself as fast as it is
/// drained. Measured against a handler of winit's exact shape: **330,021 `WM_PAINT`s in 5 s without
/// terminating.**
///
/// The only reason that is not live today is an undocumented OS scheduling rule — `WM_PAINT` is a
/// synthesised low-priority message, so the `PostMessageW` destroy that `winit::Window::drop` sends
/// is always returned first and the loop ends on iteration 1. Depending on that would put an
/// unbounded loop on the single thread the entire consent surface runs on, one dependency bump away
/// from a permanent lockout.
///
/// So: bounded, but two orders of magnitude above anything a real teardown queues. Termination is
/// structural; the #2074 concern — a destroy sitting past message 64 — is still covered.
pub(super) fn drain_pending() {
    pump(Some(DRAIN_BUDGET));
}

/// The ceiling on the deferred-destruction drain.
///
/// Not a tuning knob: it is the "this queue is pathological, stop" guard described on
/// [`drain_pending`]. A real teardown dispatches single-digit messages.
const DRAIN_BUDGET: usize = 8192;

/// The crate's one message pump. `budget` of `None` drains until the queue is empty.
fn pump(budget: Option<usize>) {
    let mut message = MSG::default();
    let mut dispatched = 0usize;
    while budget.map_or(true, |budget| dispatched < budget) {
        // SAFETY: a plain message-queue read on the calling thread's own queue.
        unsafe {
            if !PeekMessageW(&mut message, HWND::default(), 0, 0, PM_REMOVE).as_bool() {
                return;
            }
            if message.message == WM_QUIT {
                PostQuitMessage(message.wParam.0 as i32);
                return;
            }
            let _ = TranslateMessage(&message);
            DispatchMessageW(&message);
        }
        dispatched += 1;
    }
}

/// Map a [`UserConsentVerificationResult`] to a verification outcome. Only [`Verified`] authorizes;
/// an explicit cancel is a denial, and every device/enrollment problem fails closed as unavailable.
///
/// [`Verified`]: UserConsentVerificationResult::Verified
fn outcome_from_consent(result: UserConsentVerificationResult) -> VerifyOutcome {
    match result {
        UserConsentVerificationResult::Verified => VerifyOutcome::Verified,
        UserConsentVerificationResult::Canceled => VerifyOutcome::Declined,
        UserConsentVerificationResult::RetriesExhausted => VerifyOutcome::Failed,
        // DeviceNotPresent / NotConfiguredForUser / DisabledByPolicy / DeviceBusy — no usable Hello.
        _ => VerifyOutcome::Unavailable,
    }
}

/// The Windows confirmer (always available for an interactive user; see the module docs).
///
/// Both windows come from [`super::gui`]: the consent window and the typed-input window are one
/// implementation parameterised by whether it has a field, so the type hierarchy and the keyboard
/// behaviour cannot drift apart between them (dig_ecosystem#1832).
pub(super) fn confirmer() -> Option<Box<dyn NativeConfirmer>> {
    // The branded GUI (dig_ecosystem#2038) draws every window; Windows Hello still authorises.
    // The hand-built Win32 GDI dialog it replaces is gone — there is exactly one way a DIG prompt
    // is drawn, on every platform that can draw one.
    Some(Box::new(BackedConfirmer::new(
        super::gui::BrandedWindow::default(),
        HelloVerifier,
        super::gui::BrandedInput::default(),
    )))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn consent_result_maps_only_verified_to_success() {
        assert_eq!(
            outcome_from_consent(UserConsentVerificationResult::Verified),
            VerifyOutcome::Verified
        );
        assert_eq!(
            outcome_from_consent(UserConsentVerificationResult::Canceled),
            VerifyOutcome::Declined
        );
        assert_eq!(
            outcome_from_consent(UserConsentVerificationResult::RetriesExhausted),
            VerifyOutcome::Failed
        );
        assert_eq!(
            outcome_from_consent(UserConsentVerificationResult::DeviceNotPresent),
            VerifyOutcome::Unavailable
        );
        assert_eq!(
            outcome_from_consent(UserConsentVerificationResult::DisabledByPolicy),
            VerifyOutcome::Unavailable
        );
    }

    #[test]
    fn confirmer_is_constructed() {
        assert!(confirmer().is_some());
    }

    /// **The pump DELIVERS a posted message to its window procedure.**
    ///
    /// Delivery is the whole point, and it is not the same as draining the queue: the prompt window
    /// calls this after its event loop has exited so that the `DestroyWindow` `winit` merely POSTED
    /// actually runs (`gui::window::flush_deferred_window_destruction`). A pump that removed
    /// messages without dispatching them would empty the queue and still leave the consent window on
    /// screen with a dead message pump — the *"press any button and the program stops responding"*
    /// defect (dig_ecosystem#2038). So the assertion is on what the window procedure RECEIVED.
    ///
    /// A message-only window is used so this needs no display and runs on a CI runner.
    #[test]
    fn the_pump_delivers_a_posted_message_to_its_window() {
        use std::sync::atomic::{AtomicBool, Ordering};
        use windows::core::PCWSTR;
        use windows::Win32::Foundation::{LPARAM, LRESULT, WPARAM};
        use windows::Win32::System::LibraryLoader::GetModuleHandleW;
        use windows::Win32::UI::WindowsAndMessaging::{
            CreateWindowExW, DefWindowProcW, DestroyWindow, PostMessageW, RegisterClassW,
            HWND_MESSAGE, WINDOW_EX_STYLE, WINDOW_STYLE, WM_APP, WNDCLASSW,
        };

        /// A private message no other code in the process sends.
        const PROBE: u32 = WM_APP + 7;
        static DELIVERED: AtomicBool = AtomicBool::new(false);

        unsafe extern "system" fn record(
            window: HWND,
            message: u32,
            w: WPARAM,
            l: LPARAM,
        ) -> LRESULT {
            if message == PROBE {
                DELIVERED.store(true, Ordering::SeqCst);
                return LRESULT(0);
            }
            // SAFETY: the default handling for every message this probe does not claim.
            unsafe { DefWindowProcW(window, message, w, l) }
        }

        let class = windows::core::w!("DigPumpProbe");
        // SAFETY: registering a class and creating a message-only window on this thread, then
        // destroying it below. Every pointer is either null or a `'static` wide literal.
        let window = unsafe {
            let module = GetModuleHandleW(PCWSTR::null()).expect("this module's handle");
            let _ = RegisterClassW(&WNDCLASSW {
                lpfnWndProc: Some(record),
                hInstance: module.into(),
                lpszClassName: class,
                ..Default::default()
            });
            CreateWindowExW(
                WINDOW_EX_STYLE(0),
                class,
                PCWSTR::null(),
                WINDOW_STYLE(0),
                0,
                0,
                0,
                0,
                HWND_MESSAGE,
                None,
                module,
                None,
            )
            .expect("a message-only window")
        };

        // SAFETY: posting to a window this thread owns.
        unsafe {
            PostMessageW(window, PROBE, WPARAM(0), LPARAM(0)).expect("the probe is queued");
        }
        assert!(
            !DELIVERED.load(Ordering::SeqCst),
            "a POSTED message must not reach the window until something pumps"
        );

        pump_pending();

        let delivered = DELIVERED.load(Ordering::SeqCst);
        // SAFETY: destroying a window this thread created.
        unsafe {
            let _ = DestroyWindow(window);
        }
        assert!(
            delivered,
            "the pump returned without delivering the posted message — a deferred window \
             destruction would never run, and the consent window would stay on screen frozen"
        );
    }

    /// **The DRAIN delivers every queued message, however many are waiting.**
    ///
    /// The destroy message `winit` posts sits at an arbitrary depth in a queue that also carries
    /// paint, input and timer messages for a window that was just answered. Under the shared
    /// [`PUMP_BUDGET`] — a bound chosen for the Hello wait, where returning early is the
    /// REQUIREMENT — a busy window's destroy could fall past message 64 and never be delivered,
    /// leaving the consent window on screen with a dead message pump (dig_ecosystem#2074).
    ///
    /// So the assertion is deliberately on a queue LONGER than that budget, with the message that
    /// matters posted LAST. A drain that stops at 64 leaves the final probe undelivered and fails.
    #[test]
    fn the_drain_delivers_every_queued_message_however_many() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        use windows::core::PCWSTR;
        use windows::Win32::Foundation::{LPARAM, LRESULT, WPARAM};
        use windows::Win32::System::LibraryLoader::GetModuleHandleW;
        use windows::Win32::UI::WindowsAndMessaging::{
            CreateWindowExW, DefWindowProcW, DestroyWindow, PostMessageW, RegisterClassW,
            HWND_MESSAGE, WINDOW_EX_STYLE, WINDOW_STYLE, WM_APP, WNDCLASSW,
        };

        /// A private message no other code in the process sends.
        const PROBE: u32 = WM_APP + 9;
        /// Comfortably past the Hello wait's budget, so a bounded drain cannot pass this test.
        const QUEUED: usize = PUMP_BUDGET * 3;
        static SEEN: AtomicUsize = AtomicUsize::new(0);

        unsafe extern "system" fn count(
            window: HWND,
            message: u32,
            w: WPARAM,
            l: LPARAM,
        ) -> LRESULT {
            if message == PROBE {
                SEEN.fetch_add(1, Ordering::SeqCst);
                return LRESULT(0);
            }
            // SAFETY: the default handling for every message this probe does not claim.
            unsafe { DefWindowProcW(window, message, w, l) }
        }

        let class = windows::core::w!("DigDrainProbe");
        // SAFETY: registering a class and creating a message-only window on this thread, then
        // destroying it below. Every pointer is either null or a `'static` wide literal.
        let window = unsafe {
            let module = GetModuleHandleW(PCWSTR::null()).expect("this module's handle");
            let _ = RegisterClassW(&WNDCLASSW {
                lpfnWndProc: Some(count),
                hInstance: module.into(),
                lpszClassName: class,
                ..Default::default()
            });
            CreateWindowExW(
                WINDOW_EX_STYLE(0),
                class,
                PCWSTR::null(),
                WINDOW_STYLE(0),
                0,
                0,
                0,
                0,
                HWND_MESSAGE,
                None,
                module,
                None,
            )
            .expect("a message-only window")
        };

        SEEN.store(0, Ordering::SeqCst);
        for _ in 0..QUEUED {
            // SAFETY: posting to a window this thread owns.
            unsafe {
                PostMessageW(window, PROBE, WPARAM(0), LPARAM(0)).expect("the probe is queued");
            }
        }

        drain_pending();

        let seen = SEEN.load(Ordering::SeqCst);
        // SAFETY: destroying a window this thread created.
        unsafe {
            let _ = DestroyWindow(window);
        }
        assert_eq!(
            seen, QUEUED,
            "the drain stopped after {seen} of {QUEUED} messages; a deferred window destruction \
             queued behind a busy window would never be delivered and the consent window would \
             stay on screen"
        );
    }

    /// **The consent surface stays reported for as long as the WORKER is genuinely running Hello,
    /// not merely for as long as the caller's own wait lasts (dig_ecosystem#105).**
    ///
    /// `verify_off_thread` fails closed the instant its `deadline` elapses, but the worker thread it
    /// spawned keeps running -- on Windows that thread is still blocked inside the real
    /// `UserConsentVerifier::RequestVerificationAsync(..).get()`, with the Hello prompt still on
    /// screen. `BackedConfirmer::gate`'s own guard drops the moment `gate` returns, which is right at
    /// the deadline -- so between the deadline and the worker's eventual (real) return, the count
    /// would read `false` while a genuine platform consent surface is up, and the tray could claim
    /// the foreground off it.
    ///
    /// `holding_the_surface_open` closes that gap by moving a SECOND `Raised` into the worker
    /// closure, dropped only when the worker itself returns -- decoupled from whatever the caller
    /// decided at its own deadline. This test proves the property directly against
    /// `verify_off_thread`, without touching real WinRT: a fake verifier sleeps past a short
    /// deadline, and the guard must still read `true` until that sleep (standing in for Hello still
    /// being on screen) actually ends.
    #[test]
    fn the_surface_stays_reported_past_the_deadline_while_the_worker_is_still_running() {
        use crate::confirm::surface;
        use std::sync::mpsc;

        // Every raiser in this crate takes this lock (`surface.rs` module docs).
        let _exclusive = surface::one_surface_at_a_time();
        assert!(
            !surface::consent_surface_is_up(),
            "nothing may be on screen before the gate opens, or the assertions below prove nothing"
        );

        let (worker_finished_tx, worker_finished_rx) = mpsc::channel::<()>();
        let deadline = Duration::from_millis(100);
        let worker_runs_for = Duration::from_secs(3);

        // The span a real `BackedConfirmer::gate` guard would cover: raised before the wait, exactly
        // as `gate()` raises before calling `gated_consent`.
        let gate_guard = surface::Raised::now();

        let outcome = verify_off_thread(
            "reveal",
            holding_the_surface_open(move |_message| {
                std::thread::sleep(worker_runs_for);
                let _ = worker_finished_tx.send(());
                VerifyOutcome::Verified
            }),
            || {},
            deadline,
        );

        // `gate()` would return here (right after `verify_off_thread`), dropping ITS guard. Do the
        // same, so the remaining assertions are about the WORKER's guard alone.
        drop(gate_guard);

        assert_eq!(
            outcome,
            VerifyOutcome::Unavailable,
            "a deadline must still fail closed, whatever the surface guard is doing"
        );
        assert!(
            surface::consent_surface_is_up(),
            "the worker (standing in for Hello) is still genuinely running, so the surface must \
             still read as up even though the caller already gave up at its deadline"
        );

        worker_finished_rx
            .recv_timeout(Duration::from_secs(10))
            .expect("the fake worker must finish on its own");
        // Give the worker's own guard a moment to actually drop after its `send` -- the drop happens
        // on the return path immediately after, but this keeps the assertion below robust to
        // scheduling jitter rather than asserting in the same instant as the channel send.
        std::thread::sleep(Duration::from_millis(50));

        assert!(
            !surface::consent_surface_is_up(),
            "and the guard must lower once the worker genuinely finishes -- a leak here would \
             silently disable the tray's foreground claim for the rest of the process"
        );
    }
}
