//! Surviving a desktop stack that PANICS instead of failing (tray builds only).
//!
//! Mounting a tray touches the host's desktop libraries, and on Linux one of them does not report a
//! missing dependency as an error — it panics. This module is the one guard that turns that into an
//! ordinary failure the shell can degrade from, kept separate from the event loop so it is small, pure,
//! and covered by tests.

/// Run a tray-mounting step, converting a PANIC into an ordinary error so the shell can degrade.
///
/// # Why this exists (the Linux indicator library panics, it does not fail)
///
/// The shell's degrade path assumed a missing system tray library yields a running process with no
/// icon — an invisible but *alive* app. On a pristine `ubuntu:24.04` with GTK present and
/// `libayatana-appindicator3-1` absent, the truth is worse: `libappindicator-sys` **panics** inside its
/// lazy `dlopen`:
///
/// ```text
/// thread 'main' panicked at libappindicator-sys-0.9.0/src/lib.rs:41:5:
/// Failed to load ayatana-appindicator3 or appindicator3 dynamic library
/// ```
///
/// A panic unwinds straight past the `Result` the degrade path is written around, so the process DIES.
/// The user gets no tray, no agent, no headless fallback and no advice — and
/// [`tray_unavailable_advice`](dig_app_core::tray_menu::tray_unavailable_advice), written precisely for
/// this case, could never be reached on the one platform it addresses.
///
/// Catching the unwind restores the intended behaviour: a host missing a desktop library gets the
/// working headless agent plus a message naming the package to install. This deliberately does NOT
/// suppress the panic message itself — the default hook still prints it, and it names the exact
/// `.so` files that were tried, which is the most useful diagnostic available.
///
/// Only mounting is wrapped. A panic anywhere else is a real bug and must still abort loudly.
pub fn mount_or_degrade<T>(mount: impl FnOnce() -> Result<T, String>) -> Result<T, String> {
    // `AssertUnwindSafe` is sound here because the closure's captures are DISCARDED on panic: a failed
    // mount is followed by degrading to headless, never by reusing the half-built tray.
    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(mount)) {
        Ok(result) => result,
        Err(panic) => Err(format!(
            "the desktop tray library failed to load ({})",
            panic_reason(&panic)
        )),
    }
}

/// The human-readable reason out of a caught panic payload, for the advice text.
///
/// A panic payload is `Any`, and the two shapes that carry a message in practice are `&'static str` and
/// `String`; anything else has no readable text to offer, so it is named as such rather than rendered as
/// a debug blob a user cannot act on.
fn panic_reason(panic: &Box<dyn std::any::Any + Send>) -> String {
    if let Some(message) = panic.downcast_ref::<&'static str>() {
        return (*message).to_string();
    }
    if let Some(message) = panic.downcast_ref::<String>() {
        return message.clone();
    }
    "no reason given — see the log for the panic".to_string()
}

/// Tests for the panic guard. Cross-platform: they exercise the guard, not a real tray.
#[cfg(test)]
mod guard_tests {
    use super::*;

    #[test]
    fn a_successful_mount_passes_its_value_through() {
        assert_eq!(mount_or_degrade(|| Ok(7)), Ok(7));
    }

    #[test]
    fn an_ordinary_error_is_returned_unchanged() {
        let result: Result<(), String> = mount_or_degrade(|| Err("tray build failed".to_string()));
        assert_eq!(result, Err("tray build failed".to_string()));
    }

    /// **Regression (#1756).** The defect: `libappindicator-sys` PANICS when the indicator library is
    /// absent, so the process died instead of degrading. The fixture panics with the real payload shape
    /// (a `String`, as `panic!("{}", ..)` produces) and asserts the reason SURVIVES into the message —
    /// a guard that returned a generic error would satisfy "did not die" while throwing away the one
    /// detail that tells the user which library to install.
    #[test]
    fn a_panicking_mount_becomes_an_error_that_keeps_the_reason() {
        let result: Result<(), String> = mount_or_degrade(|| {
            panic!(
                "{}",
                "Failed to load ayatana-appindicator3 or appindicator3 dynamic library".to_string()
            )
        });

        let message = result.expect_err("a panicking mount must not propagate the panic");
        assert!(
            message.contains("ayatana-appindicator3"),
            "the reason must survive so the advice can name the library: {message}"
        );
    }

    /// The other payload shape a dependency may panic with. Both must be readable, because we do not
    /// control which one the library chooses.
    #[test]
    fn a_static_str_panic_reason_is_also_readable() {
        let result: Result<(), String> = mount_or_degrade(|| panic!("static reason"));
        assert!(result.unwrap_err().contains("static reason"));
    }

    /// A payload with no string in it must still degrade rather than lose the failure — the fixture uses
    /// a non-string payload precisely because the two happy shapes above cannot exercise this branch.
    #[test]
    fn an_unreadable_panic_payload_still_degrades() {
        let result: Result<(), String> = mount_or_degrade(|| std::panic::panic_any(42_u32));
        assert!(result
            .unwrap_err()
            .contains("desktop tray library failed to load"));
    }
}
