//! WHICH consent prompt is on screen right now, and what is waiting behind it.
//!
//! # Why this exists, beside [`crate::confirm::surface`]
//!
//! [`surface`](crate::confirm::surface) answers one question — *is anything up?* — for one reader:
//! a bare Win32 window proc that may not block and may not touch the prompt. A count is the whole
//! of what that reader needs and the whole of what it may have.
//!
//! Two other questions arrived with dig-app#86 and neither fits in a count:
//!
//! * **A second request must ATTEND the prompt already on screen** rather than queue in silence.
//!   Every consent prompt in this process is served by ONE thread, one at a time
//!   (`confirm::gui::window`), so a request made while a prompt is up simply waits — the
//!   person sees nothing, and the window they must answer first may be behind their browser. That
//!   is the reported symptom, not a theoretical one, and answering it needs a way to reach the open
//!   prompt from the requesting thread.
//! * **The tray must be able to SAY what is open.** *"Predictable, inspectable state"* is the
//!   ticket's fifth requirement, and a surface that cannot name the window it is waiting on cannot
//!   satisfy it.
//!
//! # Why the raise is a callback and not an `egui::Context`
//!
//! The obvious handle to store is the live window's context. It is deliberately not stored here,
//! because this module's OTHER reader is the tray tick, which builds a
//! [`TrayView`](crate::tray_menu::TrayView) in builds that do not compile the GUI at all (`egui` is
//! behind the `gui` feature). Storing the toolkit's type would drag the whole renderer into every
//! build that only wants to read a title.
//!
//! So the renderer registers HOW to bring itself forward and this module never learns what a window
//! is. The seam is honest in both directions: nothing here can accidentally paint, and nothing in
//! the renderer has to be reachable from the tray.
//!
//! # What this module may never do
//!
//! **Nothing here can author an answer.** It raises, counts, and reports. A prompt is answered by
//! the person, by its own deadline, or by a host closing it — all in
//! `confirm::gui::window`, all unchanged by anything in this file. That boundary is what
//! makes an attention mechanism safe to put on the consent surface at all.

use std::sync::{Arc, Mutex, MutexGuard};

/// How to bring the prompt on screen forward, supplied by whoever drew it.
///
/// **Reports whether it reached a window.** A prompt is registered from the moment it is handed to
/// the renderer, which is BEFORE the platform has necessarily produced a window for it — a run that
/// hangs in GL context initialisation never produces one at all, and that is precisely the state in
/// which a person makes a second request and gets nothing. So "a prompt is open" and "the raise
/// reached something" are different facts, and a raise that silently did nothing is the very
/// failure this mechanism exists to remove: it must not be indistinguishable from one that worked.
///
/// `Arc` rather than `Box` so [`attend`] can take a clone out from under the lock and call it with
/// nothing held. Calling a foreign closure while holding this module's mutex would put an unknown
/// amount of the renderer inside our critical section, which is how a lock ordering nobody wrote
/// down becomes a deadlock on the one thread that draws consent.
pub(crate) type Raise = Arc<dyn Fn() -> bool + Send + Sync>;

/// One prompt on screen, and the way back to it.
struct Showing {
    /// Which prompt it is, in the words its own title bar uses.
    title: String,
    /// Bring it forward, reporting whether it reached a window — see [`Raise`].
    raise: Raise,
    /// Which registration this is, so [`OnScreen`]'s drop removes ITS OWN entry and no other.
    serial: u64,
}

/// Every prompt believed to be on screen, innermost last.
///
/// # Why a stack and not an `Option`
///
/// One prompt is drawn at a time, so this holds zero or one entry in practice. It is a stack anyway
/// for the reason [`surface`](crate::confirm::surface) uses a count and not a flag: with an
/// `Option`, a second registration would overwrite the first and the INNER one's drop would then
/// report the outer prompt gone while it was still on screen. The tray would say nothing is open
/// over a live consent window — a surface lying about the consent surface.
///
/// A stack cannot be wrong that way, costs one allocation that never happens on the shipping path,
/// and makes the invariant a property of the structure rather than of everyone who ever touches it.
static SHOWING: Mutex<Vec<Showing>> = Mutex::new(Vec::new());

/// How many consent requests are in flight process-wide — see [`Requested`].
static REQUESTS: Mutex<usize> = Mutex::new(0);

/// Hands out [`Showing::serial`]s. Monotonic, so no two live registrations can collide.
static NEXT_SERIAL: Mutex<u64> = Mutex::new(0);

/// Lock `slot`, recovering rather than propagating a poisoning.
///
/// A poisoned lock here means some earlier prompt panicked mid-registration. Refusing every later
/// reading over that would disable the attention mechanism for the life of the process — silently,
/// because a disabled raise looks exactly like a raise the window manager refused. The same
/// reasoning, and the same shape, as `gui::window`'s `poisonless`.
fn poisonless<T>(slot: &Mutex<T>) -> MutexGuard<'_, T> {
    slot.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// The prompt on screen is registered for as long as this value lives.
///
/// Its whole contract is in [`Drop`]: a registration that outlived its window would leave the tray
/// naming a prompt that is not there and [`attend`] raising a window that has been destroyed. Every
/// way out of a draw — answered, escaped, expired, panicked out of — drops this.
#[derive(Debug)]
#[must_use = "the prompt is only reported as on screen for as long as this guard is held"]
pub(crate) struct OnScreen {
    /// Which entry in [`SHOWING`] this guard owns.
    serial: u64,
}

impl OnScreen {
    /// Report `title` as the prompt on screen, reachable through `raise`.
    ///
    /// The open transition is logged at INFO rather than DEBUG, and so is the close in [`Drop`].
    /// dig-app#86's whole history is of a consent surface failing in silence — four times, each
    /// with a different mechanism — and the transitions of the one window that gates signing are
    /// worth a line in a log a user is asked to send in. There are two per prompt.
    pub(crate) fn now(title: &str, raise: Raise) -> Self {
        let serial = {
            let mut next = poisonless(&NEXT_SERIAL);
            *next = next.wrapping_add(1);
            *next
        };
        poisonless(&SHOWING).push(Showing {
            title: title.to_owned(),
            raise,
            serial,
        });
        tracing::info!(prompt = %title, "a DIG consent prompt is on screen");
        Self { serial }
    }
}

impl Drop for OnScreen {
    fn drop(&mut self) {
        let mut showing = poisonless(&SHOWING);
        if let Some(at) = showing.iter().position(|open| open.serial == self.serial) {
            let gone = showing.remove(at);
            // Dropped before the log line so nothing holds the lock across a formatting call.
            drop(showing);
            tracing::info!(prompt = %gone.title, "the DIG consent prompt closed");
        }
    }
}

/// A consent request is in flight for as long as this value lives.
///
/// Held by the blocked caller for the whole of its wait, which is what makes
/// [`others_waiting`] exact without anyone having to remember to decrement it. Every way out of
/// that wait — an answer, the window's own deadline, the caller's backstop timeout, a dead prompt
/// thread — drops this.
#[derive(Debug)]
#[must_use = "the request is only counted as in flight for as long as this guard is held"]
pub(crate) struct Requested(());

impl Requested {
    /// Count one more consent request as waiting for the renderer.
    pub(crate) fn now() -> Self {
        *poisonless(&REQUESTS) += 1;
        Self(())
    }
}

impl Drop for Requested {
    fn drop(&mut self) {
        let mut count = poisonless(&REQUESTS);
        *count = count.saturating_sub(1);
    }
}

/// The title of the consent prompt on screen, or `None` when none is.
///
/// Read by the tray tick, which carries it into [`TrayView`](crate::tray_menu::TrayView) so the
/// `Status and details…` window can say what the app is waiting on. Deliberately a `String` and not
/// a handle: the tick must be able to hold this across a repaint without holding anything the
/// renderer owns.
pub fn showing() -> Option<String> {
    poisonless(&SHOWING).last().map(|open| open.title.clone())
}

/// How many consent requests are waiting BEHIND the one on screen.
///
/// # Why this is derived rather than counted directly
///
/// Every consent request — including the one currently drawn — holds a [`Requested`] for the whole
/// of its blocked wait, so the total is "requests in flight" and exactly one of them is the prompt
/// the person is looking at. Subtracting that one is the whole arithmetic.
///
/// Counting "others" directly would need someone to decrement when a queued job is finally drawn,
/// and the queue has three exits (drawn, refused as stale, caller timed out). A count with three
/// places to forget is how a window comes to say *another request is waiting* forever. This has
/// one exit, and it is a `Drop`.
///
/// `saturating_sub` because a reading taken with nothing in flight is 0, not an underflow.
pub(crate) fn others_waiting() -> usize {
    poisonless(&REQUESTS).saturating_sub(1)
}

/// What [`attend`] was able to do about a request arriving while a prompt is open.
///
/// Returned rather than swallowed so the caller — and a test — can tell the two apart. They are
/// genuinely different situations and only one of them is the defect dig-app#86 reports.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Attended {
    /// Nothing was on screen. The request goes to the renderer and is drawn immediately.
    NothingWasOpen,
    /// A prompt was on screen and was brought forward, naming it.
    Raised(String),
    /// A prompt was on screen and the raise did not reach a window.
    ///
    /// Not a hypothetical arm. A prompt is registered when it is handed to the renderer, and the
    /// platform may not have produced its window yet — a run that hangs in GL context
    /// initialisation never produces one, which is exactly the state in which a person makes a
    /// second request. Distinct from [`Self::Raised`] because a silent no-op IS the reported
    /// symptom: a raise that reached nothing must be visible in the log, not indistinguishable
    /// from one the window manager honoured (#86, requirement 4).
    CouldNotRaise(String),
}

/// A second consent request has arrived while a prompt is open: bring the open one forward.
///
/// # What this is for
///
/// Prompts are served one at a time, so a request made while one is up waits in a queue with
/// nothing on screen to say so. The person is looking at an app that appears to have ignored them,
/// while the window they must answer first may be behind another window entirely.
///
/// So the request ATTENDS the open prompt on its way past: raise it, and — through
/// [`others_waiting`], which the window reads every frame — let it say that something is waiting.
/// Never silence.
///
/// # What it cannot do
///
/// It cannot answer, dismiss, replace, or reorder anything. The open prompt keeps its own deadline
/// and its own answer; the arriving request keeps its place in the queue and is drawn when the
/// renderer is free. The worst a mistake in here can do is bring a window forward that did not need
/// it.
///
/// **A raise is a REQUEST.** Windows' foreground lock may refuse it (dig_ecosystem#2079) and this
/// says so rather than assuming: the outcome is logged either way, and the window's own on-screen
/// flag is what remains true whether or not the compositor cooperates. That flag is the part that
/// does not depend on the platform agreeing.
pub(crate) fn attend(waiting_for: &str) -> Attended {
    // Cloned out from under the lock, then called with nothing held — see [`Raise`].
    let open = {
        let showing = poisonless(&SHOWING);
        showing
            .last()
            .map(|open| (open.title.clone(), open.raise.clone()))
    };
    let Some((title, raise)) = open else {
        return Attended::NothingWasOpen;
    };
    if !raise() {
        tracing::warn!(
            open = %title,
            waiting = %waiting_for,
            "a DIG request arrived while a prompt was open, and that prompt has no window yet to \
             bring forward; it must still be answered before this one can be shown"
        );
        return Attended::CouldNotRaise(title);
    }
    tracing::info!(
        open = %title,
        waiting = %waiting_for,
        "a DIG request arrived while a prompt was open; the open prompt was brought forward and \
         must be answered first"
    );
    Attended::Raised(title)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::confirm::surface::one_surface_at_a_time;
    use std::sync::atomic::{AtomicUsize, Ordering};

    /// A raise that records how many times it was called, so a test can tell "brought forward" from
    /// "reported as brought forward".
    fn counting_raise() -> (Raise, Arc<AtomicUsize>) {
        let calls = Arc::new(AtomicUsize::new(0));
        let seen = Arc::clone(&calls);
        let raise: Raise = Arc::new(move || {
            seen.fetch_add(1, Ordering::AcqRel);
            true
        });
        (raise, calls)
    }

    /// A prompt whose window does not exist yet, so the raise reaches nothing.
    ///
    /// The real production state this models: `draw_watched` registers BEFORE `run_native` reaches
    /// its creator, so a run hanging in GL init is a registered prompt with no window.
    fn no_window_yet() -> Raise {
        Arc::new(|| false)
    }

    /// A raise nothing in the test asserts on, for the cases about the registration itself.
    fn ignored_raise() -> Raise {
        Arc::new(|| true)
    }

    #[test]
    fn nothing_is_showing_until_a_prompt_registers() {
        let _held = one_surface_at_a_time();
        assert_eq!(
            showing(),
            None,
            "a process with no prompt on screen must not name one; the tray reports this verbatim"
        );
        let open = OnScreen::now("DIG — Sign", ignored_raise());
        assert_eq!(showing().as_deref(), Some("DIG — Sign"));
        drop(open);
        assert_eq!(showing(), None, "the guard must clear the registration");
    }

    /// The nearest wrong implementation is an `Option<Showing>`, and this is the input that tells
    /// them apart: an overwrite-and-clear reports NOTHING open here, while the outer prompt is
    /// still on screen.
    ///
    /// Two registrations, dropped innermost first — one cannot express the bug.
    #[test]
    fn an_inner_registration_closing_does_not_report_the_outer_prompt_gone() {
        let _held = one_surface_at_a_time();
        let outer = OnScreen::now("DIG — Unlock", ignored_raise());
        let inner = OnScreen::now("DIG — Sign", ignored_raise());
        drop(inner);
        assert_eq!(
            showing().as_deref(),
            Some("DIG — Unlock"),
            "the outer prompt is STILL on screen; an `Option` would report nothing open here and \
             the tray would deny a live consent window"
        );
        drop(outer);
        assert_eq!(showing(), None, "and now genuinely nothing is open");
    }

    /// A panic unwinding out of a draw must clear the registration.
    ///
    /// The renderer catches panics and keeps serving (`gui::window::serve_with`), so a leaked
    /// registration would not crash anything — it would leave the tray naming a prompt nobody can
    /// see and `attend` raising a destroyed window, for the rest of the process.
    #[test]
    fn a_panicking_draw_still_clears_the_registration() {
        let _held = one_surface_at_a_time();
        let panicked = std::panic::catch_unwind(|| {
            let _open = OnScreen::now("DIG — Destroy", ignored_raise());
            panic!("a prompt window panicked mid-draw");
        });
        assert!(panicked.is_err(), "the fixture must actually have panicked");
        assert_eq!(
            showing(),
            None,
            "an unwind past the guard must still clear it"
        );
    }

    /// The defect dig-app#86 reports: a second request while a prompt is open was SILENT.
    ///
    /// The fixture varies exactly one actor — a second request — against a truthful control below,
    /// and asserts the raise MECHANISM ran, not merely that a value came back saying it had.
    #[test]
    fn a_request_arriving_while_a_prompt_is_open_brings_that_prompt_forward() {
        let _held = one_surface_at_a_time();
        let (raise, calls) = counting_raise();
        let _open = OnScreen::now("DIG — Unlock", raise);

        let attended = attend("DIG — Sign");

        assert_eq!(attended, Attended::Raised("DIG — Unlock".to_owned()));
        assert_eq!(
            calls.load(Ordering::Acquire),
            1,
            "the OPEN prompt must actually have been brought forward, not merely reported as such"
        );
    }

    /// The control for the test above: the same registration, no second request, and the window is
    /// left exactly where the person put it.
    ///
    /// Without this, an implementation that raises on every registration — fighting the user for
    /// the foreground for the life of every prompt — passes the test above and is a worse defect
    /// than the one it fixes.
    #[test]
    fn an_open_prompt_nobody_is_waiting_behind_is_not_raised() {
        let _held = one_surface_at_a_time();
        let (raise, calls) = counting_raise();
        let _open = OnScreen::now("DIG — Unlock", raise);
        assert_eq!(
            calls.load(Ordering::Acquire),
            0,
            "registering a prompt must not raise it; only a request arriving behind it may"
        );
    }

    /// A request with nothing open must not report that it attended anything — the ordinary case,
    /// and the one that must stay free of any raise at all.
    #[test]
    fn a_request_with_nothing_open_attends_nothing() {
        let _held = one_surface_at_a_time();
        assert_eq!(attend("DIG — Sign"), Attended::NothingWasOpen);
    }

    /// A prompt drawn by a host that gave no way to raise it is reported as such, never as raised.
    ///
    /// `Raised` and `CouldNotRaise` must not collapse: a silent no-op where a raise was expected is
    /// the reported symptom of #86 requirement 4, so the log has to be able to tell them apart.
    #[test]
    fn a_prompt_with_no_window_yet_is_reported_as_unraised_rather_than_raised() {
        let _held = one_surface_at_a_time();
        let _open = OnScreen::now("DIG — Unlock", no_window_yet());
        assert_eq!(
            attend("DIG — Sign"),
            Attended::CouldNotRaise("DIG — Unlock".to_owned())
        );
    }

    /// One request in flight is the prompt being looked at, so nothing is waiting behind it.
    ///
    /// The off-by-one this pins is the difference between an honest window and one that tells every
    /// person answering an ordinary prompt that something else is waiting.
    #[test]
    fn the_prompt_on_screen_is_not_waiting_behind_itself() {
        let _held = one_surface_at_a_time();
        let _first = Requested::now();
        assert_eq!(
            others_waiting(),
            0,
            "one request in flight IS the open prompt"
        );

        let second = Requested::now();
        assert_eq!(
            others_waiting(),
            1,
            "now one request is genuinely behind it"
        );

        drop(second);
        assert_eq!(
            others_waiting(),
            0,
            "a caller that gave up must stop being counted, or the window says `waiting` forever"
        );
    }

    /// With nothing in flight the reading is zero rather than an underflow to `usize::MAX`, which
    /// would render as an absurd count on the one window that must never look confused.
    #[test]
    fn no_requests_in_flight_reads_as_nothing_waiting() {
        let _held = one_surface_at_a_time();
        assert_eq!(others_waiting(), 0);
    }
}
