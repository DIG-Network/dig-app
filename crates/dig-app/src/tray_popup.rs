//! Keeping the tray's context menu dismissable, and refusing to fight for the foreground when the
//! screen belongs to someone else.
//!
//! Tray-only: it exists entirely to guard `tray-icon`'s `TrackPopupMenu`, and a headless build has
//! no tray menu to track.
//!
//! # What this module is now, and what it stopped being
//!
//! It used to do two things: claim the foreground before a popup was tracked, and BREAK a popup that
//! got tracked anyway. The second one is gone, because the condition it recovered from is gone.
//!
//! `TrackPopupMenu` is a nested modal message loop. It used to run on the thread that also ran the
//! app's tick, so an undismissable menu was not a broken menu — it was a broken *app*, permanently
//! and silently (dig-app#86). The tray now owns a thread of its own (see `tray::spawn_renderer`), so
//! a wedged menu costs the user the menu and nothing else: the tick keeps running, the next view
//! keeps being computed, and the paint that cannot be applied waits for the menu to close. The
//! rescue existed to survive an app-wide stall that can no longer happen, and it never worked
//! anyway — a `PostMessageW` returning `Ok` means the message was *enqueued*, which the old code
//! logged as though it were an effect.
//!
//! # What remains: the Q135788 dance, which is PREVENTION and not recovery
//!
//! A popup tracked without foreground rights cannot be dismissed by clicking away, by Escape, or by
//! anything else — measured here, holding a loop 180 s (MSDN Q135788, still printed in the current
//! `TrackPopupMenu` Remarks; wxWidgets has carried the same dance in `src/msw/taskbar.cpp` for about
//! thirty years). Isolating the tray does not make a menu dismiss itself. So [`claim_foreground`]
//! stays, moved to the tray thread.
//!
//! Be precise about what it is, because an earlier version of this comment overstated it.
//! `tray-icon` has **always** called `SetForegroundWindow` immediately before the track (0.23.1 at
//! `mod.rs:544`). That half of Q135788 was never missing; it was **refused**. This is the same Win32
//! call, on the same window, tried one input edge sooner — a widening of the window in which rights
//! may be held, never a guarantee. See [`Edge`] for which edge is the required one.
//!
//! # Two reasons to decline the claim (dig-app#91)
//!
//! `WM_USER_TRAYICON` (6002) is an ordinary window message, so any process running as this user can
//! post one and drive this whole path. Bounded honestly: that is a **nuisance lever against the
//! consent surface**, not an authorization bypass — nothing in this path selects a menu item or
//! answers a prompt, and an attacker already at this integrity level has easier options. What it can
//! do is yank the foreground off a prompt the user is mid-read of, so they re-focus it and answer
//! having lost their place.
//!
//! So the claim is DECLINED in two situations, and the distinction from a FAILED claim is kept in
//! the type ([`Claim`]) because they call for opposite reactions in the log:
//!
//! 1. **A consent surface is on screen** ([`dig_app_core::confirm::consent_surface_is_up`]). The
//!    prompt outranks the menu; a menu opening without foreground rights is a menu the user has to
//!    click twice, which is a far smaller harm than a consent window losing focus.
//! 2. **The click was not preceded by real input** ([`input_evidence`]). A genuine tray click IS a
//!    system input event, so the message's timestamp sits within milliseconds of the system's
//!    last-input tick. A *naive* forged post carries no input at all.
//!
//! **What (2) does NOT do**, stated over the whole class of attacker rather than over one attacker
//! behaviour, because the narrower statement was wrong twice:
//!
//! - It gates only OUR claim. `tray-icon` makes its own `SetForegroundWindow` call inside
//!   `show_tray_menu`, which this module cannot reach, so a forged post still reaches that one.
//! - **It contributes nothing at all against an attacker who is trying.** The evidence it checks is
//!   the same-user, unprivileged `GetLastInputInfo` counter, and one `SendInput` call with a
//!   zero-delta `MOUSEEVENTF_MOVE` refreshes it — invisibly, with no cursor motion, on a completely
//!   idle machine. Measured: a last-input age of 5,454,546 ms became 63 ms after a single call, well
//!   inside [`INPUT_TOLERANCE`]. So the sequence `SendInput` → `PostMessageW(tray_hwnd, 6002, …,
//!   WM_RBUTTONUP)` passes this gate every time. The earlier claim here — that it narrows the lever
//!   to "only during active input" — understated it: the real cost to an attacker is one extra Win32
//!   call, at any moment of their choosing.
//!
//! The gate STAYS. It costs nothing, it stops the unsophisticated forgery, and removing it would only
//! make the lazy case free too. But it MUST NOT be sized as a bound, and [`INPUT_TOLERANCE`] MUST NOT
//! be tightened in the hope of making it one: the attacker controls the numerator, so a shorter
//! window declines real clicks under load and still admits every deliberate forgery. The only real
//! remedy is refuse-to-track, which needs the window service to own the popup (SPEC §3.1b-tp).
//!
//! Bounded honestly, then: gate (1) is the one that protects the asset dig-app#91 names, and it is
//! not bypassable this way — a consent surface being on screen is this process's own state, not a
//! counter the attacker can write.

/// The class name `tray-icon` gives its hidden tray window.
///
/// **Not a message-only (`HWND_MESSAGE`) window** — it is a hidden top-level window created with
/// `WS_EX_TOOLWINDOW` (`tray-icon` `mod.rs:100-118`). That distinction is load-bearing rather than
/// pedantic: `EnumWindows` does not enumerate message-only windows.
///
/// A private detail of that crate, and named here on purpose rather than reached for through an
/// accessor that does not exist. Pinned by
/// `tests::the_tray_window_class_matches_the_crates_own_source`, which reads the literal out of the
/// vendored dependency — if a bump renames it, [`tray_window`] finds nothing and [`claim_foreground`]
/// becomes a silent no-op, which is the worst failure a guard has because it is indistinguishable
/// from a guard that is working.
#[cfg(target_os = "windows")]
const TRAY_WINDOW_CLASS: &str = "tray_icon_app";

/// How far apart a tray click's message timestamp and the system's last-input tick may be before the
/// click is treated as having no input behind it.
///
/// Both are millisecond tick counts from the same `GetTickCount` base, so this is a real duration
/// and not a fudge factor. One second is chosen from what has to fit inside it: the shell's own hop
/// from the input event to `Shell_NotifyIcon`'s callback, plus this message's wait in the tray
/// thread's queue. That queue is short by construction now — the tray thread does nothing but draw —
/// and a second is roughly three orders of magnitude more than the hop costs.
///
/// Erring generous is the right direction, and the asymmetry is total rather than merely favourable.
/// Too tight silently drops the foreground claim on ordinary clicks under load, which reintroduces
/// the wedge this module exists to prevent. Too loose costs nothing whatsoever against a deliberate
/// attacker, because the counter this is compared against can be refreshed on demand with one
/// `SendInput` call — see the module docs. Shrinking this value buys no security and spends real
/// reliability, so it MUST NOT be tuned downward as a hardening measure.
#[cfg(target_os = "windows")]
const INPUT_TOLERANCE: std::time::Duration = std::time::Duration::from_secs(1);

/// Why the foreground could not be taken, when it was actually attempted.
///
/// Carried rather than collapsed to a `bool` so the log says which of the two happened: a refusal is
/// the interesting case (an undismissable menu is now reachable), a missing window means the tray is
/// not mounted and there is nothing to protect.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NoForeground {
    /// The tray's own window could not be found in this process.
    NoTrayWindow,
    /// Windows refused the request. The next tracked popup may be undismissable.
    Refused,
}

/// Why the foreground claim was deliberately not attempted (dig-app#91).
///
/// Kept apart from [`NoForeground`] because the two are opposite news. A refusal is a warning that
/// the menu may wedge; a decline is this process behaving correctly, and reporting it at ERROR would
/// be crying wolf on the one line an investigation is meant to trust.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decline {
    /// A consent prompt is on screen and outranks the menu.
    ConsentSurfaceUp,
    /// No real input preceded this click, so it did not come from the user's hand.
    NoRecentInput,
}

/// What came of a foreground claim.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Claim {
    /// This process now holds the foreground.
    Taken,
    /// Not attempted, for a reason that is this process working as intended.
    Declined(Decline),
    /// Attempted, and did not succeed.
    Failed(NoForeground),
}

/// Whether a tray click's timing is consistent with a human having caused it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InputEvidence {
    /// The message sits beside a real system input event.
    Recent,
    /// It does not, so nothing the user did produced it.
    Absent,
}

/// What a tray click edge means for the popup that may follow it.
///
/// # Why the edge has to be classified at all
///
/// `tray-icon` 0.23.1 tracks the menu on button-**UP** (`mod.rs:491-492`), where 0.19.3 tracked on
/// DOWN. Its event handler fires synchronously on *both* edges, so a handler that does not
/// distinguish them either misses the moment that matters or speaks at a moment where nothing
/// happens. The first version of this module claimed on DOWN only, which did nothing at the instant
/// `SPEC.md` §3.1b-tp names, and fired its ERROR on middle clicks that open no menu at all.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Edge {
    /// A button-DOWN on a button that opens the menu. The track is one whole click away.
    ///
    /// Worth a foreground attempt — that is the widening, and it is free — but NOT worth a word in
    /// the log: rights absent here may still be granted by UP, so a refusal predicts nothing.
    Speculative,
    /// The button-UP `tray-icon` tracks on: the last point our code runs before `TrackPopupMenu`.
    ///
    /// This is where §3.1b-tp's MUST applies, and the only edge where a refusal is real news.
    BeforeTrack,
    /// No menu follows this edge — a middle click, or a button that cannot open the menu.
    Irrelevant,
}

/// Classify a tray click for the popup that may follow.
///
/// `opens_menu` is whether this button is configured to open the menu at all
/// (`menu_on_left_click` / `menu_on_right_click`; both default on, and dig-app does not change
/// them). Taken as an argument rather than assumed so the classification stays true if it ever is.
pub fn edge_of(opens_menu: bool, pressed: bool) -> Edge {
    match (opens_menu, pressed) {
        (false, _) => Edge::Irrelevant,
        (true, true) => Edge::Speculative,
        (true, false) => Edge::BeforeTrack,
    }
}

/// Whether `message_time` sits close enough to `last_input` to have been caused by it.
///
/// Both are `GetTickCount`-based millisecond counters, which is why this takes them as bare `u32`s
/// and does its own arithmetic: the counter **wraps every 49.7 days**, and a plain subtraction on
/// either side of a wrap yields a gap of weeks. The modular distance — the smaller of the two
/// directions — is correct across the wrap and is what this computes.
///
/// The backward direction is not a curiosity either. The system's last-input tick can be NEWER than
/// the message being handled, because moving the mouse after releasing the button is itself input;
/// that ordinary sequence must read as [`InputEvidence::Recent`], and a one-directional subtraction
/// would call it a forgery.
///
/// Pure, and takes its inputs rather than reading the clock, so the table in
/// `tests::input_evidence_is_a_modular_distance_in_both_directions` can state every case.
pub fn input_evidence(
    message_time: u32,
    last_input: u32,
    tolerance: std::time::Duration,
) -> InputEvidence {
    let forward = message_time.wrapping_sub(last_input);
    let backward = last_input.wrapping_sub(message_time);
    let apart = u64::from(forward.min(backward));
    match apart <= tolerance.as_millis() as u64 {
        true => InputEvidence::Recent,
        false => InputEvidence::Absent,
    }
}

/// Whether the foreground may be claimed at all, and why not if not.
///
/// Pure and separate from the Win32 call so the policy is a value a test can assert on. The order is
/// deliberate: a consent surface is reported even when the input evidence is also absent, because it
/// is the reason a reader would act on.
pub fn refusal_to_claim(consent_surface_up: bool, evidence: InputEvidence) -> Option<Decline> {
    if consent_surface_up {
        return Some(Decline::ConsentSurfaceUp);
    }
    match evidence {
        InputEvidence::Absent => Some(Decline::NoRecentInput),
        InputEvidence::Recent => None,
    }
}

/// Take the foreground for the tray's window, so the popup about to be tracked can be dismissed.
///
/// Call it from `tray-icon`'s event handler and nowhere else: that handler is the last of our code
/// to run before `show_tray_menu`, and the value of the call is entirely in its timing. It runs on
/// the tray thread, inside a window proc, so it must never block — everything it consults is an
/// atomic load or a Win32 read.
#[cfg(target_os = "windows")]
pub fn claim_foreground() -> Claim {
    let evidence = input_evidence(message_time(), last_input_tick(), INPUT_TOLERANCE);
    if let Some(decline) =
        refusal_to_claim(dig_app_core::confirm::consent_surface_is_up(), evidence)
    {
        return Claim::Declined(decline);
    }

    let Some(hwnd) = tray_window() else {
        return Claim::Failed(NoForeground::NoTrayWindow);
    };
    // SAFETY: `hwnd` was just enumerated from THIS PROCESS's windows (`tray_window` filters on the
    // owning process id), so it is a live handle we own. `SetForegroundWindow` has no other
    // precondition and cannot fail unsoundly; a refusal is a `false` return, not undefined behaviour.
    let taken = unsafe { windows::Win32::UI::WindowsAndMessaging::SetForegroundWindow(hwnd) };
    match taken.as_bool() {
        true => Claim::Taken,
        false => Claim::Failed(NoForeground::Refused),
    }
}

/// When the message being handled right now was posted, as a `GetTickCount` millisecond value.
///
/// Thread-local to the caller and therefore only meaningful inside a window proc, which is the only
/// place this module is called from.
#[cfg(target_os = "windows")]
fn message_time() -> u32 {
    // SAFETY: no arguments and no preconditions; returns the current thread's last message time.
    unsafe { windows::Win32::UI::WindowsAndMessaging::GetMessageTime() as u32 }
}

/// When the system last saw input from the user, as a `GetTickCount` millisecond value.
///
/// A failure is reported as a tick half the counter away from now, which is the farthest any value
/// can be in BOTH modular directions — so [`input_evidence`] reads `Absent` and the claim is
/// DECLINED. Failing closed is right here: the cost is one menu that may need a second click, and
/// the alternative — treating an unreadable clock as evidence of a human — hands the forgery back
/// the path this check exists to narrow.
#[cfg(target_os = "windows")]
fn last_input_tick() -> u32 {
    use windows::Win32::System::SystemInformation::GetTickCount;
    use windows::Win32::UI::Input::KeyboardAndMouse::{GetLastInputInfo, LASTINPUTINFO};

    let mut info = LASTINPUTINFO {
        cbSize: std::mem::size_of::<LASTINPUTINFO>() as u32,
        dwTime: 0,
    };
    // SAFETY: `info` is a live local whose `cbSize` is set to its own size, which is the call's one
    // precondition.
    let read = unsafe { GetLastInputInfo(&mut info) };
    match read.as_bool() {
        true => info.dwTime,
        false => {
            // SAFETY: no arguments and no preconditions.
            let now = unsafe { GetTickCount() };
            now.wrapping_add(u32::MAX / 2)
        }
    }
}

/// Find `tray-icon`'s hidden tray window.
///
/// Process-scoped rather than thread-scoped, filtered by owning process. The tray thread that calls
/// [`claim_foreground`] does own this window, so a thread-scoped lookup would work today — but that
/// was the shape that made the old rescue a silent no-op once its caller moved threads, and a lookup
/// that is only correct because of where it happens to be called from is a trap for the next caller.
#[cfg(target_os = "windows")]
fn tray_window() -> Option<windows::Win32::Foundation::HWND> {
    use std::sync::atomic::{AtomicIsize, Ordering};
    use windows::Win32::Foundation::{BOOL, HWND, LPARAM, TRUE};
    use windows::Win32::System::Threading::GetCurrentProcessId;
    use windows::Win32::UI::WindowsAndMessaging::{
        EnumWindows, GetClassNameW, GetWindowThreadProcessId,
    };

    /// Where the callback leaves what it found.
    ///
    /// A `static` rather than a thread-local: `EnumWindows` takes a bare `extern "system"` function
    /// pointer. A racing second search can only store the same handle — there is exactly one such
    /// window per process — so the store is benign, and it is reset before each enumeration.
    static FOUND: AtomicIsize = AtomicIsize::new(0);

    unsafe extern "system" fn visit(hwnd: HWND, _: LPARAM) -> BOOL {
        // Ours, or some other process's window that happens to share the class.
        let mut owner = 0u32;
        // SAFETY: `hwnd` comes from the enumerator and `owner` is a live local.
        unsafe { GetWindowThreadProcessId(hwnd, Some(&mut owner)) };
        // SAFETY: no preconditions.
        if owner != unsafe { GetCurrentProcessId() } {
            return TRUE;
        }

        let mut name = [0u16; 64];
        // SAFETY: `name` is a live buffer of the length passed; `GetClassNameW` writes at most that
        // many code units and returns how many it wrote.
        let written = unsafe { GetClassNameW(hwnd, &mut name) };
        if written > 0 && String::from_utf16_lossy(&name[..written as usize]) == TRAY_WINDOW_CLASS {
            FOUND.store(hwnd.0 as isize, Ordering::Release);
            // Stop: there is exactly one.
            return BOOL(0);
        }
        TRUE
    }

    FOUND.store(0, Ordering::Release);
    // SAFETY: `visit` matches the required callback signature and touches only a static atomic.
    // `EnumWindows` returns `Err` when a callback stops the enumeration early, which is how the
    // match below is reached with a handle — so the result is deliberately not consulted.
    let _ = unsafe { EnumWindows(Some(visit), LPARAM(0)) };
    match FOUND.load(Ordering::Acquire) {
        0 => None,
        raw => Some(HWND(raw as *mut std::ffi::c_void)),
    }
}

/// Nothing to do off Windows: no other platform draws its tray menu with a nested modal loop, so
/// there is no foreground to claim.
#[cfg(not(target_os = "windows"))]
pub fn claim_foreground() -> Claim {
    Claim::Taken
}

/// How often a repeated foreground refusal may be restated.
///
/// The condition is worth saying and worth saying AGAIN, but not on every occurrence.
/// `WM_USER_TRAYICON` is an ordinary window message, so any process running as this user can drive
/// this path as fast as it likes; without a bound that is a log-flooding lever (dig-app#91).
/// Bounded, it is a nuisance that costs one line every half minute.
const RESTATE_REFUSAL_AFTER: std::time::Duration = std::time::Duration::from_secs(30);

/// Rate-limits a repeated condition to one report per interval.
///
/// Deliberately not a latch. The permanent case is the one that matters, and a latch reports it once
/// and then goes quiet forever.
#[derive(Debug)]
struct Throttle {
    every: std::time::Duration,
    last: std::sync::Mutex<Option<std::time::Instant>>,
}

impl Throttle {
    const fn new(every: std::time::Duration) -> Self {
        Self {
            every,
            last: std::sync::Mutex::new(None),
        }
    }

    /// Whether the condition may be reported as of `now`, recording it if so.
    fn allows(&self, now: std::time::Instant) -> bool {
        let mut last = match self.last.lock() {
            Ok(last) => last,
            // A poisoned throttle must not silence a diagnostic; recover and carry on.
            Err(poisoned) => poisoned.into_inner(),
        };
        // `Option::is_none_or` is 1.82; this crate's MSRV is 1.75.
        let due = last.map_or(true, |then| now.duration_since(then) >= self.every);
        if due {
            *last = Some(now);
        }
        due
    }
}

/// The one throttle for the refusal line.
static REFUSALS: Throttle = Throttle::new(RESTATE_REFUSAL_AFTER);

/// Log the outcome of a foreground claim made on the way into a tray menu.
///
/// Call this ONLY for [`Edge::BeforeTrack`]. At that edge a refusal genuinely predicts an
/// undismissable menu, which is the moment the wedge becomes reachable and the line a future
/// investigation will search for. At [`Edge::Speculative`] a refusal predicts nothing — UP may still
/// be granted — so reporting there would be crying wolf on an ordinary click.
///
/// A DECLINE is not a refusal and is reported at DEBUG. It is this process choosing correctly, and
/// putting it at ERROR would teach the reader to skip the one line that means something.
pub fn report_claim(outcome: Claim) {
    match outcome {
        Claim::Taken => {}
        Claim::Declined(Decline::ConsentSurfaceUp) => tracing::debug!(
            "a DIG consent prompt is on screen, so the tray did not take the foreground from it"
        ),
        Claim::Declined(Decline::NoRecentInput) => tracing::debug!(
            "a tray click arrived with no input behind it, so the tray did not take the foreground"
        ),
        Claim::Failed(NoForeground::NoTrayWindow) => {
            tracing::debug!("no DIG tray window to bring forward before its menu opens")
        }
        Claim::Failed(NoForeground::Refused) if REFUSALS.allows(std::time::Instant::now()) => {
            tracing::error!(
                "Windows refused to bring the DIG tray forward, so the menu about to open may not \
                 be dismissable by clicking away or by Escape. The rest of DIG keeps running \
                 either way — the tray draws on its own thread — but the menu may need a second \
                 click to clear."
            )
        }
        Claim::Failed(NoForeground::Refused) => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The class name is a private detail of `tray-icon`, so a bump can rename it and [`tray_window`]
    /// would then find nothing and [`claim_foreground`] would silently do nothing at all.
    ///
    /// # Why this reads the dependency's source instead of restating the literal
    ///
    /// The previous version of this test was `assert_eq!(TRAY_WINDOW_CLASS, "tray_icon_app")`, whose
    /// own doc claimed the value was "read from the dependency's own source rather than restated, so
    /// the assertion cannot drift into agreeing with itself". It was exactly a restatement and it
    /// agreed with itself by construction (dig-app#90): a `tray-icon` bump that renamed the class
    /// would leave this test GREEN and the guard dead.
    ///
    /// So the version is read out of `Cargo.lock` and the literal out of the vendored crate. A run
    /// that cannot find either FAILS rather than skipping — a skip here reproduces the same
    /// self-agreement, just more quietly.
    #[cfg(target_os = "windows")]
    #[test]
    fn the_tray_window_class_matches_the_crates_own_source() {
        let source = vendored_tray_icon_source();
        let registration = source
            .lines()
            .find(|line| line.contains("encode_wide(\""))
            .unwrap_or_else(|| {
                panic!(
                    "tray-icon no longer registers its window class with `encode_wide(\"…\")`; \
                     this pin cannot read the class name any more and must be rewritten against \
                     however the crate spells it now"
                )
            });

        assert!(
            registration.contains(&format!("\"{TRAY_WINDOW_CLASS}\"")),
            "tray-icon registers its window class in `{}`, which is not `{TRAY_WINDOW_CLASS}`; \
             `claim_foreground` is now a silent no-op",
            registration.trim()
        );
    }

    /// The `platform_impl/windows/mod.rs` of the exact `tray-icon` this workspace locks.
    ///
    /// Resolved from `Cargo.lock` rather than from a hardcoded version so the pin follows a bump
    /// instead of quietly reading the source of a crate that is no longer built.
    #[cfg(target_os = "windows")]
    fn vendored_tray_icon_source() -> String {
        let lock = workspace_root().join("Cargo.lock");
        let locked = std::fs::read_to_string(&lock)
            .unwrap_or_else(|e| panic!("Cargo.lock must be readable at {}: {e}", lock.display()));
        let version = locked_version(&locked, "tray-icon").unwrap_or_else(|| {
            panic!("tray-icon must appear in Cargo.lock; this crate depends on it directly")
        });

        let registry = cargo_home().join("registry").join("src");
        let indexes = std::fs::read_dir(&registry).unwrap_or_else(|e| {
            panic!(
                "the cargo registry source dir must exist at {}: {e}",
                registry.display()
            )
        });
        for index in indexes.flatten() {
            let candidate = index
                .path()
                .join(format!("tray-icon-{version}"))
                .join("src")
                .join("platform_impl")
                .join("windows")
                .join("mod.rs");
            if let Ok(source) = std::fs::read_to_string(&candidate) {
                return source;
            }
        }
        panic!(
            "tray-icon {version}'s vendored source was not found under {}; this pin must read the \
             dependency's own source, and a run that cannot is the self-agreeing assertion \
             dig-app#90 removed",
            registry.display()
        )
    }

    /// The version `Cargo.lock` pins for `name`.
    ///
    /// A three-line parse rather than a TOML dependency: the lock's `[[package]]` blocks put `name`
    /// and `version` on consecutive lines, and pulling in a parser for one field would be the more
    /// surprising choice in a test.
    #[cfg(target_os = "windows")]
    fn locked_version(lock: &str, name: &str) -> Option<String> {
        let mut lines = lock.lines();
        while let Some(line) = lines.next() {
            if line.trim() == format!("name = \"{name}\"") {
                let version = lines.next()?.trim().strip_prefix("version = \"")?;
                return Some(version.trim_end_matches('"').to_owned());
            }
        }
        None
    }

    /// The workspace root: two levels up from `crates/dig-app`.
    #[cfg(target_os = "windows")]
    fn workspace_root() -> std::path::PathBuf {
        std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .ancestors()
            .nth(2)
            .expect("crates/dig-app sits two levels below the workspace root")
            .to_path_buf()
    }

    /// Where cargo keeps its registry, honouring `CARGO_HOME`.
    #[cfg(target_os = "windows")]
    fn cargo_home() -> std::path::PathBuf {
        if let Ok(home) = std::env::var("CARGO_HOME") {
            return std::path::PathBuf::from(home);
        }
        let profile = std::env::var("USERPROFILE").expect("USERPROFILE on Windows");
        std::path::Path::new(&profile).join(".cargo")
    }

    /// Every click edge is classified, and the three outcomes are genuinely distinct.
    ///
    /// This is the table an earlier version got wrong twice over: it claimed on DOWN, which is not
    /// the edge `tray-icon` 0.23.1 tracks on, and it did not constrain the button, so a middle click
    /// produced an ERROR predicting that "the menu about to open may not be dismissable" at an edge
    /// where no menu ever opens.
    ///
    /// All four inputs are asserted rather than a representative one, because the two mistakes were
    /// in different cells.
    #[test]
    fn every_click_edge_is_classified_and_only_the_tracking_one_may_speak() {
        assert_eq!(
            edge_of(true, false),
            Edge::BeforeTrack,
            "button-UP on a menu button is where tray-icon tracks and where the MUST applies"
        );
        assert_eq!(
            edge_of(true, true),
            Edge::Speculative,
            "button-DOWN is a free early attempt, but a refusal there predicts nothing"
        );
        assert_eq!(
            edge_of(false, true),
            Edge::Irrelevant,
            "a button that opens no menu must not produce a claim or a prediction"
        );
        assert_eq!(edge_of(false, false), Edge::Irrelevant, "…on either edge");
    }

    /// The input cross-check is a MODULAR distance, measured in both directions.
    ///
    /// Three neighbouring wrong implementations get a row each, because each is a plausible way to
    /// write this and each is silently wrong in only some inputs:
    ///
    /// * A one-directional `message_time - last_input` calls the ordinary sequence of moving the
    ///   mouse *after* releasing the button a forgery, so real clicks silently lose their claim.
    /// * Ignoring the `GetTickCount` wrap makes every click in the first second after 49.7 days of
    ///   uptime read as a forgery.
    /// * A tolerance applied to only one side lets a post fifty seconds after the last input pass.
    ///
    /// The bound is pinned from BOTH sides: exactly at tolerance must pass, one millisecond over
    /// must fail. A bound tested only from below can only confirm itself.
    #[test]
    fn input_evidence_is_a_modular_distance_in_both_directions() {
        let tolerance = std::time::Duration::from_secs(1);

        assert_eq!(
            input_evidence(10_000, 10_000, tolerance),
            InputEvidence::Recent,
            "a click whose message time IS the last input time is as genuine as it gets"
        );
        assert_eq!(
            input_evidence(11_000, 10_000, tolerance),
            InputEvidence::Recent,
            "exactly at the tolerance is inside it; a bound tested only from below confirms itself"
        );
        assert_eq!(
            input_evidence(11_001, 10_000, tolerance),
            InputEvidence::Absent,
            "one millisecond over the tolerance is outside it"
        );
        assert_eq!(
            input_evidence(10_000, 10_500, tolerance),
            InputEvidence::Recent,
            "input NEWER than the message is the ordinary mouse-move-after-release sequence, not a \
             forgery; a one-directional subtraction rejects every one of those clicks"
        );
        assert_eq!(
            input_evidence(50, u32::MAX - 50, tolerance),
            InputEvidence::Recent,
            "101 ms apart across the 49.7-day GetTickCount wrap is 101 ms, not seven weeks"
        );
        assert_eq!(
            input_evidence(60_000, 10_000, tolerance),
            InputEvidence::Absent,
            "a message posted fifty seconds after the user last touched anything had no hand \
             behind it — the forged post dig-app#91 demonstrated"
        );
    }

    /// The claim is declined for a consent surface and for a forged click, and for nothing else.
    ///
    /// The first row is the one that makes the other three mean anything: with both conditions
    /// healthy the claim MUST go ahead, or this "fix" would have disabled the Q135788 dance
    /// altogether and turned every ordinary menu into the wedge the dance prevents.
    #[test]
    fn the_claim_is_declined_only_for_a_prompt_or_a_click_with_no_hand_behind_it() {
        assert_eq!(
            refusal_to_claim(false, InputEvidence::Recent),
            None,
            "an ordinary click with no prompt on screen MUST still claim the foreground; \
             declining here reintroduces the undismissable menu"
        );
        assert_eq!(
            refusal_to_claim(true, InputEvidence::Recent),
            Some(Decline::ConsentSurfaceUp),
            "a real click must not yank the foreground off a prompt the user is reading"
        );
        assert_eq!(
            refusal_to_claim(false, InputEvidence::Absent),
            Some(Decline::NoRecentInput),
            "a forged post gets no help from us"
        );
        assert_eq!(
            refusal_to_claim(true, InputEvidence::Absent),
            Some(Decline::ConsentSurfaceUp),
            "when both hold, the prompt is the reason a reader would act on"
        );
    }

    /// A decline and a failure are different values, because they are opposite news: one says this
    /// process chose correctly, the other says a menu may be about to wedge.
    #[test]
    fn a_decline_is_never_reported_as_a_refusal() {
        assert_ne!(
            Claim::Declined(Decline::ConsentSurfaceUp),
            Claim::Failed(NoForeground::Refused)
        );
        assert_ne!(NoForeground::Refused, NoForeground::NoTrayWindow);
        assert_ne!(Decline::ConsentSurfaceUp, Decline::NoRecentInput);
    }

    /// The refusal line is rate-limited, and NOT latched.
    ///
    /// Both halves matter and the two neighbouring wrong implementations get one each: reporting
    /// every occurrence hands a log-flooding lever to any process running as this user, and
    /// latching after the first goes quiet on the permanent case — which is the one worth hearing
    /// about. The bound is checked from both sides.
    #[test]
    fn a_repeated_refusal_is_restated_on_a_backoff_and_not_latched() {
        let every = std::time::Duration::from_millis(100);
        let throttle = Throttle::new(every);
        let base = std::time::Instant::now();

        assert!(
            throttle.allows(base),
            "the first occurrence is always reported"
        );
        assert!(
            !throttle.allows(base + every - std::time::Duration::from_millis(1)),
            "one millisecond under the backoff must NOT report again"
        );
        assert!(
            throttle.allows(base + every),
            "exactly at the backoff it reports again"
        );
        assert!(
            throttle.allows(base + every + every),
            "and keeps reporting — a latch would go quiet exactly when the condition is permanent"
        );
    }

    /// `report_claim` is total and never panics on any outcome — it runs inside a window proc, where
    /// a panic unwinds through foreign frames.
    #[test]
    fn reporting_is_total() {
        report_claim(Claim::Taken);
        report_claim(Claim::Declined(Decline::ConsentSurfaceUp));
        report_claim(Claim::Declined(Decline::NoRecentInput));
        report_claim(Claim::Failed(NoForeground::Refused));
        report_claim(Claim::Failed(NoForeground::NoTrayWindow));
    }

    /// A real consent surface makes the real [`claim_foreground`] decline, without touching a window.
    ///
    /// This is the end-to-end of dig-app#91's first fix, and it is worth driving through the actual
    /// function rather than only through [`refusal_to_claim`]: the pure policy being right proves
    /// nothing if `claim_foreground` never consults it, which is exactly the placement mistake this
    /// pair of assertions can see.
    ///
    /// The control is what makes it a placement test rather than an outcome test. With nothing on
    /// screen the call must produce something OTHER than the consent decline — whatever the rest of
    /// the path decides in a windowless test process — so the second assertion is pinning the
    /// consent gate specifically and not a value the function returns anyway. And because a test
    /// process owns no tray window, a gate placed after the lookup would answer `NoTrayWindow` there
    /// and fail that second assertion.
    #[cfg(target_os = "windows")]
    #[test]
    fn a_live_consent_surface_declines_the_claim_before_any_window_is_touched() {
        let control = claim_foreground();
        assert_ne!(
            control,
            Claim::Declined(Decline::ConsentSurfaceUp),
            "no prompt is on screen in this fixture, so the consent decline must not fire; if it \
             does, the control proves nothing"
        );

        // Raised WITHOUT `dig_app_core`'s `ONE_SURFACE_AT_A_TIME` exclusion, because that mutex is
        // `pub(crate)` to dig-app-core and unreachable from this crate. Safe only because this is the
        // one test in this binary that touches the process-global count, and `cargo test` gives each
        // crate its own test process — so nothing here can run beside it.
        //
        // That is a property of the current test set, not of the design. Adding a SECOND
        // count-touching test to this binary breaks it, and the symptom is a parallel-only flake in
        // whichever test asserts "nothing is up". Closing it properly means exporting the exclusion
        // across the crate boundary (dig-app#99).
        let _on_screen = dig_app_core::confirm::surface::Raised::now();
        assert_eq!(
            claim_foreground(),
            Claim::Declined(Decline::ConsentSurfaceUp),
            "with a consent surface up the claim must be declined before the tray window is even \
             looked for"
        );
    }
}
