//! Is anybody there? The one platform-specific half of the activity gate (dig-app#312).
//!
//! # What counts as activity
//!
//! **Input to the MACHINE, not input to dig-app.** dig-app runs as a tray application whose window
//! is closed most of the time, so "a frame drawn in response to a real interaction" — the cheap
//! app-local signal that needs no platform API — answers a much narrower question than the one
//! asked: it would hold a notification through an entire working day because the person never
//! happened to open this particular app. The signal has to be system-wide idle time.
//!
//! | OS | how | exact? |
//! |---|---|---|
//! | Windows | `GetLastInputInfo`, in-process, no privileges | yes — keyboard + mouse, session-wide |
//! | macOS | `ioreg -c IOHIDSystem` → `HIDIdleTime` (nanoseconds) | yes — the same counter the screensaver uses |
//! | Linux | — | **no: [`Presence::Unobservable`]** |
//! | anything else | — | **no: [`Presence::Unobservable`]** |
//!
//! The macOS backend is a subprocess for the same reason its notification backend is: the platform
//! provides one, and a subprocess is the smaller surface in a custody-adjacent binary. Its parsing
//! half ([`hid_idle_from_ioreg`](crate::notify::presence::hid_idle_from_ioreg)) is pure and unit-tested, so the only untested part is the spawn.
//!
//! # Linux is unobservable, deliberately
//!
//! There is no portable Linux idle time. X11 has `XScreenSaverQueryInfo` — a new C dependency that
//! covers only X11 — and **Wayland has no equivalent at all**, by design: a client that could read
//! global idle time could fingerprint the user's presence, which is exactly what the compositor
//! security model exists to prevent. `org.freedesktop.ScreenSaver` reports whether the screen is
//! LOCKED, which is not the same question. Rather than ship a probe that is right on one of the two
//! major Linux display stacks and silently wrong on the other, this reports `Unobservable` and says
//! so. Follow-up: teach the gate an app-local interaction signal for exactly this case.
//!
//! # Unobservable means NEVER DELIVER, and that is a choice with an argument
//!
//! The alternative — degrade to *deliver immediately* — is the 03:00 toast the directive forbids,
//! and it is worst precisely where it fires most: a headless Ubuntu Server (dig-app#303) has no
//! display, so "deliver" means a `notify-send` that fails, every time, forever. Holding instead
//! costs nothing (the gate's entries expire and the queue is bounded by construction) and the
//! information is not lost: the same funding position is a readout in the settings pane and an
//! answer from `dign` on the CLI. **A notification is an interruption, and there is nobody to
//! interrupt.** So a display-less host completes silently, which is the supported outcome for it,
//! not an error and not a retry.
//!
//! The price, stated plainly: a Linux DESKTOP user gets no held notification either, because this
//! module cannot tell that host apart from the server. That is a capability gap, not a silent one.

use std::time::Duration;

/// How long without input before somebody is treated as away.
///
/// Long enough that a person reading a page without touching anything is still present, short
/// enough that a notification does not go out into an empty room. This is the only threshold in the
/// mechanism, and it is about presence — never about the time of day.
pub const AWAY_AFTER: Duration = Duration::from_secs(5 * 60);

/// Whether the person is at the machine.
///
/// The third arm is load-bearing and is NOT a synonym for away: away is a measurement, unobservable
/// is the absence of one. The gate treats them the same way today (hold), but conflating them in
/// the type would make a host that lost its probe indistinguishable from an empty chair, and a
/// later decision to treat them differently would have nothing to branch on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Presence {
    /// Input was seen within [`AWAY_AFTER`].
    Present,
    /// Idle time was measured, and it is longer than that.
    Away,
    /// This host cannot report idle time at all. See the module docs.
    Unobservable,
}

/// Turn a measured idle time into a verdict.
///
/// Pure, so the threshold rule is tested without a machine anybody has to stop touching. `None` —
/// no measurement — is `Unobservable` rather than a guess in either direction.
#[must_use]
pub fn presence_from_idle(idle: Option<Duration>, away_after: Duration) -> Presence {
    match idle {
        None => Presence::Unobservable,
        Some(idle) if idle <= away_after => Presence::Present,
        Some(_) => Presence::Away,
    }
}

/// This host's presence right now, measured through whatever it provides.
#[must_use]
pub fn presence() -> Presence {
    presence_from_idle(system_idle(), AWAY_AFTER)
}

/// How long since the machine last saw keyboard or mouse input, or `None` where that cannot be
/// asked. Never blocks for longer than the platform call itself.
#[must_use]
pub fn system_idle() -> Option<Duration> {
    #[cfg(target_os = "windows")]
    {
        windows_idle::since_last_input()
    }
    #[cfg(target_os = "macos")]
    {
        macos_idle::since_last_input()
    }
    #[cfg(not(any(target_os = "windows", target_os = "macos")))]
    {
        None
    }
}

/// `GetLastInputInfo` — the session-wide keyboard/mouse idle time Windows already maintains.
///
/// Both values are millisecond tick counts that wrap at ~49.7 days, so the subtraction is a
/// `wrapping_sub`: an unwrapped one would produce a ~49-day idle time across the wrap and make a
/// present user look away. The API needs no privileges and no window.
#[cfg(target_os = "windows")]
mod windows_idle {
    use std::time::Duration;
    use windows::Win32::System::SystemInformation::GetTickCount;
    use windows::Win32::UI::Input::KeyboardAndMouse::{GetLastInputInfo, LASTINPUTINFO};

    pub(super) fn since_last_input() -> Option<Duration> {
        let mut info = LASTINPUTINFO {
            cbSize: u32::try_from(std::mem::size_of::<LASTINPUTINFO>()).ok()?,
            dwTime: 0,
        };
        // SAFETY: `info` is a correctly sized, fully initialised `LASTINPUTINFO`, which is the
        // entire contract of this call. It writes one `u32` and returns a BOOL.
        let ok = unsafe { GetLastInputInfo(&mut info) };
        if !ok.as_bool() {
            return None;
        }
        // SAFETY: `GetTickCount` takes nothing and returns a `u32`; it cannot fail.
        let now = unsafe { GetTickCount() };
        Some(Duration::from_millis(u64::from(
            now.wrapping_sub(info.dwTime),
        )))
    }
}

/// `ioreg -c IOHIDSystem` — the HID idle counter the screensaver itself is driven by.
///
/// A subprocess rather than an IOKit binding for the same reason the macOS notification backend is
/// one: the platform provides the command, and the parsing is a pure function that can be tested
/// against real output without a Mac.
#[cfg(target_os = "macos")]
mod macos_idle {
    use std::time::Duration;

    pub(super) fn since_last_input() -> Option<Duration> {
        let output = std::process::Command::new("ioreg")
            .args(["-c", "IOHIDSystem", "-d", "4"])
            .output()
            .ok()?;
        if !output.status.success() {
            return None;
        }
        super::hid_idle_from_ioreg(&String::from_utf8_lossy(&output.stdout))
    }
}

/// Pull `HIDIdleTime` out of `ioreg` output.
///
/// The field is NANOSECONDS and routinely exceeds `u32`, which is why it is parsed as `u128` before
/// being divided down — a narrower parse would fail on any machine idle for more than four seconds
/// and report `Unobservable` on a perfectly observable host.
///
/// Compiled on every target so the parser is covered by the ordinary `cargo test` run rather than
/// only on macOS hardware; only its caller is platform-gated.
#[must_use]
pub fn hid_idle_from_ioreg(output: &str) -> Option<Duration> {
    let line = output.lines().find(|line| line.contains("HIDIdleTime"))?;
    let digits: String = line
        .rsplit('=')
        .next()?
        .chars()
        .filter(char::is_ascii_digit)
        .collect();
    let nanos: u128 = digits.parse().ok()?;
    u64::try_from(nanos / 1_000_000_000)
        .ok()
        .map(Duration::from_secs)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// **The away threshold is pinned from both sides**, and an unmeasured host is neither.
    ///
    /// At the threshold the person is still present: an idle time exactly equal to it is the last
    /// instant of presence, and rounding it to away would let a notification out while somebody is
    /// mid-sentence.
    #[test]
    fn the_presence_verdict_is_pinned_at_its_boundary() {
        let away = Duration::from_secs(300);
        assert_eq!(
            presence_from_idle(Some(Duration::ZERO), away),
            Presence::Present
        );
        assert_eq!(presence_from_idle(Some(away), away), Presence::Present);
        assert_eq!(
            presence_from_idle(Some(away + Duration::from_secs(1)), away),
            Presence::Away
        );
        assert_eq!(presence_from_idle(None, away), Presence::Unobservable);
    }

    /// **A measurement and the absence of one are never confused, in either direction.**
    ///
    /// Named for what it asserts. The first half sweeps every idle length: a host that MEASURED
    /// something must never be reported as unobservable, however long it has been idle. The second
    /// half is the converse — no measurement is never reported as away — which is the direction a
    /// broken probe would take, and it is asserted here beside its twin rather than only inside the
    /// threshold test, so neither can be lost without the other going red.
    #[test]
    fn a_measurement_and_its_absence_are_never_confused_in_either_direction() {
        assert_eq!(
            presence_from_idle(None, AWAY_AFTER),
            Presence::Unobservable,
            "an unmeasurable host is never reported as merely away"
        );
        for secs in [0, 1, 299, 300, 301, 86_400] {
            assert_ne!(
                presence_from_idle(Some(Duration::from_secs(secs)), AWAY_AFTER),
                Presence::Unobservable,
                "a measurement of {secs}s is a measurement"
            );
        }
    }

    /// **Real `ioreg` output, at a magnitude that overflows a 32-bit parse.**
    ///
    /// 6,061,404,721 ns is a little over six seconds and already exceeds `u32::MAX`; the fixture is
    /// chosen from the units the field actually uses rather than from a small round number, because
    /// a small one would pass against the narrow parse this test exists to forbid.
    #[test]
    fn the_hid_idle_field_is_read_in_nanoseconds() {
        let output = "\
    +-o IOHIDSystem  <class IOHIDSystem, id 0x1000004a1, registered>
      {
        \"HIDIdleTime\" = 6061404721
        \"HIDPointerAcceleration\" = 45056
      }
";
        assert_eq!(
            hid_idle_from_ioreg(output),
            Some(Duration::from_secs(6)),
            "six seconds, not an overflow"
        );
    }

    /// A very long idle time — a machine untouched for a day — still parses, which is exactly the
    /// case the gate has to get right.
    #[test]
    fn a_days_idle_time_parses() {
        let output = "\"HIDIdleTime\" = 86400000000000";
        assert_eq!(
            hid_idle_from_ioreg(output),
            Some(Duration::from_secs(86_400))
        );
    }

    /// Output with no such field yields no measurement — never a fabricated zero, which would read
    /// as "somebody is right here" and release every held notification into an empty room.
    #[test]
    fn absent_output_yields_no_measurement_rather_than_zero() {
        assert_eq!(hid_idle_from_ioreg(""), None);
        assert_eq!(hid_idle_from_ioreg("+-o IOHIDSystem\n  {\n  }\n"), None);
        assert_eq!(
            presence_from_idle(hid_idle_from_ioreg(""), AWAY_AFTER),
            Presence::Unobservable
        );
    }

    /// The real probe on THIS host answers without panicking, and its verdict is consistent with
    /// what the host can measure. It cannot assert a value — the machine running CI may be idle or
    /// busy — so it asserts the invariant that ties the two functions together.
    #[test]
    fn the_host_probe_is_callable_and_agrees_with_its_own_measurement() {
        let measured = system_idle();
        let verdict = presence();
        assert_eq!(verdict, presence_from_idle(measured, AWAY_AFTER));
        if cfg!(any(target_os = "windows", target_os = "macos")) {
            // Both platforms maintain the counter unconditionally; a `None` here would mean the
            // probe is broken, which is the failure this whole module must not report silently.
            assert!(measured.is_some(), "an observable host measured nothing");
        } else {
            assert_eq!(verdict, Presence::Unobservable);
        }
    }
}
