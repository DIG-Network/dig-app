//! Notification rendering: honest amount/asset formatting + the per-OS native toast backends.
//!
//! The formatting half ([`direction_line`], [`format_amount`], [`asset_label`]) is pure and
//! unit-tested. The per-OS half drives the platform's native notification API:
//!
//! | OS | API | Shape |
//! |---|---|---|
//! | Linux | `notify-send` (libnotify) | subprocess, args passed separately |
//! | macOS | `osascript -e 'display notification …'` | subprocess, AppleScript literal neutralized |
//! | Windows | `Windows.UI.Notifications.ToastNotificationManager` (WinRT) | in-process, via the `windows` crate already in the tree |
//!
//! The two unix backends stay subprocesses because their platforms provide one and a subprocess is
//! the smaller surface in a custody-adjacent binary. Windows provides no notification command, so it
//! is the one platform where the native API has to be called directly (dig_ecosystem#2548 — this is
//! the #970 follow-up that module header used to defer).
//!
//! Every backend is best-effort: a failure is logged and swallowed, because a missed awareness toast
//! must never break the app.

#[cfg(target_os = "windows")]
pub use windows_toast::{prepare, AUMID};

use std::collections::BTreeMap;

use dig_events_protocol::AssetId;

use crate::amount::{format_units, CAT_DECIMALS, XCH_DECIMALS};

use super::{AssetTotal, NativeNotifier, Notification};

/// Format one direction's coalesced totals as a line, or `None` when nothing moved that way.
///
/// One payment reads naturally (`"Received 1 XCH"`); a burst is counted and totalled (`"Received 3
/// payments: 2 XCH total"`); a multi-asset burst lists each asset (`"Received 4 payments: 2 XCH,
/// 1.5 $DIG"`).
pub(super) fn direction_line(
    verb: &str,
    totals: &BTreeMap<Option<AssetId>, AssetTotal>,
    dig_asset_id: Option<&AssetId>,
) -> Option<String> {
    if totals.is_empty() {
        return None;
    }
    let count: u64 = totals.values().map(|t| t.count).sum();
    let amounts = totals
        .iter()
        .map(|(asset, total)| {
            format!(
                "{} {}",
                format_amount(asset.as_ref(), total.mojos),
                asset_label(asset.as_ref(), dig_asset_id)
            )
        })
        .collect::<Vec<_>>()
        .join(", ");

    Some(match (count, totals.len()) {
        (1, _) => format!("{verb} {amounts}"),
        (_, 1) => format!("{verb} {count} payments: {amounts} total"),
        (_, _) => format!("{verb} {count} payments: {amounts}"),
    })
}

/// The human label for an asset: `XCH` for the native asset, `$DIG` for the DIG CAT, otherwise a
/// short form of the CAT asset id. Never a false ticker (§6.0 honest).
pub(super) fn asset_label(asset: Option<&AssetId>, dig_asset_id: Option<&AssetId>) -> String {
    match asset {
        None => "XCH".to_string(),
        Some(id) if Some(id) == dig_asset_id => "$DIG".to_string(),
        Some(id) => short_asset(&id.to_string()),
    }
}

/// Abbreviate a long asset id for display (`abcdef…7890`), leaving short ids intact.
fn short_asset(id: &str) -> String {
    if id.len() > 12 {
        format!("{}…{}", &id[..6], &id[id.len() - 4..])
    } else {
        id.to_string()
    }
}

/// Format a base-unit amount for an asset: XCH has 12 decimals (mojos), CATs 3 (the Chia CAT
/// convention), with trailing zeros trimmed for a glanceable value.
pub(super) fn format_amount(asset: Option<&AssetId>, mojos: u128) -> String {
    let decimals = match asset {
        None => XCH_DECIMALS,
        Some(_) => CAT_DECIMALS,
    };
    format_units(mojos, decimals)
}

/// A fail-safe notifier that logs instead of drawing a toast — the headless / unsupported-target
/// fallback, and the base for the #970 native-backend follow-ups. Never panics.
#[derive(Debug, Default, Clone, Copy)]
pub struct LoggingNotifier;

impl NativeNotifier for LoggingNotifier {
    fn show(&self, notification: &Notification) {
        tracing::info!(
            title = %notification.title,
            body = %notification.body,
            "wallet notification (no native toast backend on this host)"
        );
    }
}

/// Select the native notifier for this host: the per-OS subprocess backend, or the fail-safe
/// [`LoggingNotifier`] when none is available.
pub fn native_notifier() -> Box<dyn NativeNotifier> {
    #[cfg(target_os = "linux")]
    {
        Box::new(platform::NotifySend)
    }
    #[cfg(target_os = "macos")]
    {
        Box::new(platform::OsaScript)
    }
    #[cfg(target_os = "windows")]
    {
        Box::new(windows_toast::WinToast::for_this_app())
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
    {
        Box::new(LoggingNotifier)
    }
}

/// The Windows toast backend, and the Start Menu registration that makes it visible.
///
/// # Why this is not just three WinRT calls
///
/// An UNPACKAGED Win32 process has no package identity, so Windows has nothing to attribute a toast
/// to. The documented substitute is an AppUserModelID carried by a Start Menu shortcut: without one,
/// `CreateToastNotifierWithId` still succeeds and `Show` still returns `Ok`, and **nothing appears**.
/// That is the exact shape of a feature that ships green and does nothing, so the shortcut is
/// created here rather than assumed — idempotently, once, pointing at the running executable.
///
/// dig-installer is the natural long-term home for it (it already owns Windows autostart, which
/// `autostart.rs` delegates there for the same reason). Creating it here too is deliberate
/// belt-and-braces: a build run from a zip, a developer build, and an installed build all notify.
#[cfg(target_os = "windows")]
mod windows_toast {
    use windows::core::{Interface, HSTRING, PCWSTR, PROPVARIANT};
    use windows::Win32::System::Com::StructuredStorage::PropVariantClear;
    use windows::Win32::System::Com::{
        CoCreateInstance, CoInitializeEx, CoUninitialize, IPersistFile, CLSCTX_INPROC_SERVER,
        COINIT_APARTMENTTHREADED, STGM_READ,
    };
    use windows::Win32::UI::Shell::PropertiesSystem::{IPropertyStore, PROPERTYKEY};
    use windows::Win32::UI::Shell::{IShellLinkW, ShellLink};
    use windows::UI::Notifications::{ToastNotification, ToastNotificationManager};

    use super::{LoggingNotifier, NativeNotifier, Notification};

    /// This application's AppUserModelID.
    ///
    /// A CANONICAL value: it is the name Windows files every DIG toast under, so the Start Menu
    /// shortcut, the notifier and anything dig-installer writes must all use this exact string.
    /// Changing it orphans every notification setting the user has already chosen — Windows keys
    /// per-app notification permissions on it.
    pub const AUMID: &str = "DIGNetwork.DIG";

    /// What the Start Menu entry is called. It is what the toast is attributed to on screen, so it
    /// is the product name and not the executable's.
    const SHORTCUT_NAME: &str = "DIG.lnk";

    /// `PKEY_AppUserModel_ID`, written out rather than imported.
    ///
    /// The `windows` crate does not export the shell property keys as constants, and this one is a
    /// documented, frozen value. Spelling it here is the alternative to not being able to set it at
    /// all; the fmtid/pid pair is from the Windows SDK's `propkey.h`.
    const PKEY_APP_USER_MODEL_ID: PROPERTYKEY = PROPERTYKEY {
        fmtid: windows::core::GUID::from_u128(0x9F4C2855_9F79_4B39_A8D0_E1D42DE1D5F3),
        pid: 5,
    };

    /// Draws toasts through the Windows notification platform.
    pub struct WinToast {
        aumid: HSTRING,
    }

    impl WinToast {
        /// The notifier for this process.
        pub fn for_this_app() -> Self {
            Self {
                aumid: HSTRING::from(AUMID),
            }
        }
    }

    /// Register this app's notification identity, early, without showing anything.
    ///
    /// # Why this is a separate call the shell makes at start-up
    ///
    /// MEASURED on Windows 11: the run that CREATES the Start Menu shortcut still gets its toast
    /// dropped — `Show` returns `Ok` and nothing appears, and the app does not appear under
    /// `HKCU\…\Notifications\Settings`. The next run's toast is delivered and the key appears. The
    /// shell resolves an AppUserModelID through an index over the Start Menu, and that index has not
    /// caught up within the same process.
    ///
    /// So the identity is written when the app STARTS, minutes before any payment could arrive,
    /// rather than at the moment of the first toast.
    ///
    /// # Why this is the ONLY path that writes the Start Menu
    ///
    /// Writing it from [`deliver`] as well used to look like free belt-and-braces, and it was the
    /// opposite: `deliver` is reachable from `native_notifier().show(…)`, so every `cargo test` run
    /// on a Windows developer machine rewrote the user's real `DIG.lnk` to point at the ephemeral
    /// `target/debug/deps/*.exe` the harness happened to be running — a path the next rebuild
    /// deletes, leaving the generic icon this very change exists to fix. The measurement above also
    /// says that same-process write cannot help the toast being delivered, so the fallback bought
    /// nothing and cost the user's Start Menu.
    ///
    /// The shortcut write therefore lives on exactly one call path — this function, called once by
    /// the app shell at start-up — and [`start_menu_write_is_refused`] makes even that path
    /// default-deny for any executable built into `target/`.
    pub fn prepare() {
        if start_menu_write_is_refused() {
            return;
        }
        let aumid = HSTRING::from(AUMID);
        let _ = std::thread::Builder::new()
            .name("dig-toast-identity".to_string())
            .spawn(move || unsafe {
                let started = CoInitializeEx(None, COINIT_APARTMENTTHREADED);
                if let Err(e) = ensure_start_menu_identity(&aumid) {
                    tracing::debug!(error = %e, "the Start Menu notification identity was not written");
                }
                if started.is_ok() {
                    CoUninitialize();
                }
            });
    }

    /// Decide whether THIS process may write the user's Start Menu, and complain loudly when the
    /// caller is a test harness.
    ///
    /// The user's `%APPDATA%\…\Start Menu\Programs\DIG.lnk` is a real, durable artifact of THEIR
    /// machine: it carries the AUMID every DIG toast is filed under, and its target is whatever
    /// executable wrote it last. So the question the guard has to answer is whether the running
    /// executable is one the shortcut may still point at tomorrow.
    ///
    /// A test harness is additionally a defect rather than a config: nothing in a test suite has any
    /// business here, so it trips a `debug_assert` and fails the suite instead of passing quietly.
    /// A `cargo run` gets the silent refusal, because refusing a developer's app launch by panicking
    /// would be a worse bug than the one being prevented.
    fn start_menu_write_is_refused() -> bool {
        let exe = std::env::current_exe().ok();
        if !write_is_refused(launched_by_cargo(), exe.as_deref()) {
            return false;
        }
        debug_assert!(
            !exe.as_deref().is_some_and(is_test_harness_path),
            "a test reached the Start Menu identity writer; it must not touch the user's machine"
        );
        tracing::debug!(
            "skipping the Start Menu identity: this process runs from a build directory, so its \
             executable is not one the shortcut may point at"
        );
        true
    }

    /// The refusal itself, as a decision over facts rather than over the ambient process — so both
    /// directions of it can be tested, including the one that matters most.
    ///
    /// **The refusal is about WHERE the executable lives, not about who started it.** An executable
    /// under `target/` is by construction one the next rebuild or `cargo clean` deletes, so pointing
    /// the shortcut at it trades a working Start Menu entry for a dangling one — which is the very
    /// generic-icon state this module exists to repair. That is true of `target\debug\dig-app.exe`
    /// double-clicked from Explorer, which carries none of cargo's environment; keying the refusal on
    /// the environment alone would let exactly that case through. The cargo environment is kept as a
    /// second, independent signal because it catches the converse — a `cargo run` whose binary has
    /// been copied somewhere that looks shipped.
    ///
    /// **An unknown executable is ALLOWED, deliberately.** The costs are asymmetric: a wrong refusal
    /// means the installed app never registers its AUMID and notifications break for every user,
    /// which is strictly worse than the icon defect a wrong permit could reintroduce on a developer's
    /// own machine. The guard therefore fails open when it cannot see the path.
    fn write_is_refused(launched_by_cargo: bool, exe: Option<&std::path::Path>) -> bool {
        launched_by_cargo || exe.is_some_and(runs_from_a_cargo_build_directory)
    }

    /// Was this process started by cargo (`cargo run`, `cargo test`, `cargo bench`)?
    ///
    /// Cargo exports the manifest environment to the programs it runs; neither variable is set for a
    /// binary started from Explorer, a service, or the installer.
    fn launched_by_cargo() -> bool {
        std::env::var_os("CARGO").is_some() || std::env::var_os("CARGO_MANIFEST_DIR").is_some()
    }

    /// Does `exe` sit inside a cargo `target/` build directory?
    ///
    /// Cargo emits binaries at a bounded depth below `target/`: `target/<profile>/` for an
    /// application, one deeper for a test or bench harness, and one deeper again for each when a
    /// `--target <triple>` is in play. Four ancestors is therefore the whole layout, and the bound is
    /// what keeps the guard from over-reaching: an installed path that merely happens to contain a
    /// directory named `target` further up — the false positive that would silently disable the
    /// shipped app's repair — is out of range.
    fn runs_from_a_cargo_build_directory(exe: &std::path::Path) -> bool {
        const CARGO_BUILD_DIR_MAX_DEPTH: usize = 4;
        exe.ancestors()
            .skip(1)
            .take(CARGO_BUILD_DIR_MAX_DEPTH)
            .any(|dir| dir.file_name() == Some(std::ffi::OsStr::new("target")))
    }

    /// A cargo test/bench binary is emitted into `target/<profile>/deps/`; an application binary is
    /// emitted a directory above it. The parent directory name is therefore the discriminator.
    fn is_test_harness_path(exe: &std::path::Path) -> bool {
        exe.parent().and_then(|parent| parent.file_name()) == Some(std::ffi::OsStr::new("deps"))
    }

    impl NativeNotifier for WinToast {
        /// Show `notification` as a Windows toast, falling back to the log if the platform refuses.
        ///
        /// The work happens on its own thread because it needs a COM apartment, and this process's
        /// threads are in whatever apartment their own purpose put them in (dig_ecosystem#1926 puts
        /// the Hello prompt's thread in the MTA). A fresh thread is the only way to be sure of the
        /// apartment without disturbing anybody else's, and it is joined so a failure is observed
        /// rather than lost.
        fn show(&self, notification: &Notification) {
            let aumid = self.aumid.clone();
            let payload = notification.clone();
            let delivered = std::thread::Builder::new()
                .name("dig-toast".to_string())
                .spawn(move || unsafe {
                    // A failure here is not fatal: it usually means the apartment is already
                    // initialized differently, and the calls below work regardless.
                    let started = CoInitializeEx(None, COINIT_APARTMENTTHREADED);
                    let outcome = deliver(&aumid, &payload);
                    if started.is_ok() {
                        CoUninitialize();
                    }
                    outcome
                })
                .and_then(|handle| {
                    handle
                        .join()
                        .map_err(|_| std::io::Error::other("the toast thread panicked"))
                });

            match delivered {
                Ok(Ok(())) => {}
                Ok(Err(e)) => {
                    tracing::warn!(error = %e, "the Windows toast was refused");
                    LoggingNotifier.show(notification);
                }
                Err(e) => {
                    tracing::warn!(error = %e, "the Windows toast could not be attempted");
                    LoggingNotifier.show(notification);
                }
            }
        }
    }

    /// Raise the toast, against the identity [`prepare`] registered at start-up.
    ///
    /// Deliberately writes NOTHING to the file system: this function is reachable from
    /// `native_notifier().show(…)`, which a test may legitimately call, and the user's Start Menu is
    /// not a test's to touch. See [`prepare`] for why that separation is the fix and not a caveat.
    ///
    /// # Safety
    /// Calls COM/WinRT on the current thread, which the caller has put in an apartment.
    unsafe fn deliver(aumid: &HSTRING, notification: &Notification) -> windows::core::Result<()> {
        let document = windows::Data::Xml::Dom::XmlDocument::new()?;
        document.LoadXml(&HSTRING::from(toast_xml(notification)))?;
        let toast = ToastNotification::CreateToastNotification(&document)?;
        ToastNotificationManager::CreateToastNotifierWithId(aumid)?.Show(&toast)
    }

    /// Create the Start Menu shortcut carrying [`AUMID`], or repair one that is already there.
    ///
    /// # Why an existing shortcut is not left alone
    ///
    /// Windows attributes an unpackaged Win32 toast to this shortcut, so the shortcut's icon IS the
    /// toast's icon. Every machine that ran an earlier build already has a shortcut written without
    /// one, and skipping on existence would mean the icon fix reached only brand-new installs —
    /// leaving the generic file icon in place for exactly the users who reported it (#3076). So the
    /// shortcut is rewritten whenever it does not already point at the icon this build expects, and
    /// left untouched once it does.
    ///
    /// # Safety
    /// Calls COM on the current thread, which the caller has put in an apartment.
    unsafe fn ensure_start_menu_identity(aumid: &HSTRING) -> windows::core::Result<()> {
        let Some(path) = shortcut_path() else {
            return Ok(());
        };
        if path.exists() && shortcut_icon_is_current(&path) {
            return Ok(());
        }
        if let Some(parent) = path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        let executable = std::env::current_exe().map_err(|e| {
            windows::core::Error::new(windows::Win32::Foundation::E_FAIL, e.to_string())
        })?;

        let link: IShellLinkW = CoCreateInstance(&ShellLink, None, CLSCTX_INPROC_SERVER)?;
        link.SetPath(&HSTRING::from(executable.as_os_str()))?;
        if let Some(parent) = executable.parent() {
            link.SetWorkingDirectory(&HSTRING::from(parent.as_os_str()))?;
        }

        // The icon lives in the executable's own resources, so index 0 — the binary's lowest icon
        // group — is the DIG Mark that `dig-app/build.rs` embeds. Setting it explicitly rather than
        // relying on the shell inheriting it keeps the toast's appearance a property of this code.
        link.SetIconLocation(&HSTRING::from(executable.as_os_str()), ICON_INDEX)?;

        let properties: IPropertyStore = link.cast()?;
        let mut value = PROPVARIANT::from(AUMID);
        properties.SetValue(&PKEY_APP_USER_MODEL_ID, &value)?;
        properties.Commit()?;
        // `PROPVARIANT::from` allocates the string through COM's allocator; clearing it is how that
        // memory goes back, and the value has already been copied into the store by `SetValue`.
        let _ = PropVariantClear(std::ptr::addr_of_mut!(value).cast());

        let file: IPersistFile = link.cast()?;
        file.Save(PCWSTR(HSTRING::from(path.as_os_str()).as_ptr()), true)?;
        let _ = aumid;
        Ok(())
    }

    /// Does the shortcut at `path` already draw this build's icon?
    ///
    /// Answers `false` on any doubt — an unreadable shortcut, a missing icon, one pointing at a
    /// different executable — because rewriting a shortcut is cheap and idempotent, while wrongly
    /// concluding it is current leaves the generic icon on screen forever.
    ///
    /// # Safety
    /// Calls COM on the current thread, which the caller has put in an apartment.
    unsafe fn shortcut_icon_is_current(path: &std::path::Path) -> bool {
        let Ok(executable) = std::env::current_exe() else {
            return false;
        };
        let Ok(link) = CoCreateInstance::<_, IShellLinkW>(&ShellLink, None, CLSCTX_INPROC_SERVER)
        else {
            return false;
        };
        let Ok(file) = link.cast::<IPersistFile>() else {
            return false;
        };
        if file
            .Load(PCWSTR(HSTRING::from(path.as_os_str()).as_ptr()), STGM_READ)
            .is_err()
        {
            return false;
        }

        // MAX_PATH is the buffer the shell writes an icon location into; anything longer is
        // truncated by the API itself, not by this call.
        let mut icon = [0u16; 260];
        let mut index = 0i32;
        if link
            .GetIconLocation(&mut icon, std::ptr::addr_of_mut!(index))
            .is_err()
        {
            return false;
        }
        let end = icon.iter().position(|c| *c == 0).unwrap_or(icon.len());
        let icon = std::path::PathBuf::from(String::from_utf16_lossy(&icon[..end]));

        index == ICON_INDEX && icon == executable
    }

    /// The icon index within the executable's resources: its lowest icon group, the DIG Mark.
    const ICON_INDEX: i32 = 0;

    /// Where the per-user Start Menu shortcut goes, or `None` when `%APPDATA%` is not set.
    ///
    /// Per-user rather than all-users on purpose: dig-app is a per-user agent, writing here needs no
    /// elevation, and an identity registered for one user is the correct scope for that user's
    /// notification settings.
    fn shortcut_path() -> Option<std::path::PathBuf> {
        let appdata = std::env::var_os("APPDATA")?;
        Some(
            std::path::PathBuf::from(appdata)
                .join("Microsoft")
                .join("Windows")
                .join("Start Menu")
                .join("Programs")
                .join(SHORTCUT_NAME),
        )
    }

    /// The toast payload, as the notification platform's `ToastGeneric` XML.
    ///
    /// Both fields are attacker-influenced in principle (an amount and an asset label are rendered
    /// from chain data), so each is escaped for XML before it is interpolated — the same rule the
    /// macOS backend applies to its AppleScript literal.
    pub(super) fn toast_xml(notification: &Notification) -> String {
        format!(
            "<toast><visual><binding template=\"ToastGeneric\">\
             <text>{}</text><text>{}</text>\
             </binding></visual></toast>",
            xml_escape(&notification.title),
            xml_escape(&notification.body),
        )
    }

    /// Neutralize text for interpolation into an XML text node or attribute.
    pub(super) fn xml_escape(text: &str) -> String {
        let mut out = String::with_capacity(text.len());
        for ch in text.chars() {
            match ch {
                '&' => out.push_str("&amp;"),
                '<' => out.push_str("&lt;"),
                '>' => out.push_str("&gt;"),
                '"' => out.push_str("&quot;"),
                '\'' => out.push_str("&apos;"),
                _ => out.push(ch),
            }
        }
        out
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        /// **Notification text cannot break out of the toast document.**
        ///
        /// A body carrying markup would otherwise either fail `LoadXml` (no toast at all) or inject
        /// elements into the payload. The control is the ordinary body, which must pass through
        /// unchanged — an escaper that mangled normal text would pass the first half alone.
        #[test]
        fn notification_text_is_neutralized_before_it_reaches_the_document() {
            let hostile = Notification {
                title: "DIG".to_string(),
                body: "</text><audio src=\"x\"/><text>& 'pwned'".to_string(),
            };
            let xml = toast_xml(&hostile);
            assert!(
                !xml.contains("<audio"),
                "markup survived into the toast: {xml}"
            );
            assert!(xml.contains("&lt;/text&gt;"), "{xml}");
            assert!(xml.contains("&amp;"), "{xml}");

            let ordinary = Notification {
                title: "DIG — Funds received".to_string(),
                body: "Received 2.5 $DIG".to_string(),
            };
            assert!(
                toast_xml(&ordinary).contains("Received 2.5 $DIG"),
                "ordinary text was mangled"
            );
        }

        /// **The identity string is the one Windows keys notification permissions on.**
        ///
        /// Pinned as a literal because changing it silently resets every choice a user has already
        /// made about DIG's notifications, and because the shortcut and the notifier have to agree.
        #[test]
        fn the_app_identity_is_stable() {
            assert_eq!(AUMID, "DIGNetwork.DIG");
        }

        /// **This very test binary is refused the user's Start Menu, on both of the guard's signals.**
        ///
        /// The guard is only worth anything if it fires in the situation it exists for, and that
        /// situation is the process running this assertion. Asserting on a synthesised path alone
        /// would prove the classifier and nothing about the harness, which is exactly how the
        /// original defect survived: `deliver` looked harmless until you noticed which executable
        /// was calling it. Each signal is pinned separately as well as through the decision, so that
        /// one of them going silent shows up here rather than being masked by the other.
        #[test]
        fn a_cargo_test_binary_is_refused_the_start_menu() {
            let exe = std::env::current_exe().expect("a test binary knows its own path");
            assert!(
                launched_by_cargo(),
                "cargo no longer exports its environment to test binaries; the refusal that keeps \
                 `cargo test` out of the user's Start Menu has gone silent"
            );
            assert!(
                runs_from_a_cargo_build_directory(&exe),
                "this harness was not recognised as running from a build directory: {exe:?}"
            );
            assert!(write_is_refused(launched_by_cargo(), Some(&exe)));
        }

        /// **A binary run STRAIGHT out of `target/` is refused, with no cargo environment at all.**
        ///
        /// This is the variant the environment check cannot see. Double-clicking
        /// `target\debug\dig-app.exe` in Explorer exports no `CARGO*`, so a guard keyed only on the
        /// environment permits it — and it then writes a shortcut pointing into `target/` that the
        /// next rebuild deletes, which is precisely the dangling-shortcut damage this change exists
        /// to stop. `launched_by_cargo` is passed as `false` deliberately: with `true` the assertion
        /// would pass on the environment alone and prove nothing about the path.
        #[test]
        fn an_executable_run_directly_out_of_target_is_refused() {
            for exe in [
                r"C:\repo\target\debug\dig-app.exe",
                r"C:\repo\target\release\dig-app.exe",
                r"C:\repo\target\debug\deps\dig_app_core-e5b8b4388e0565db.exe",
                r"C:\repo\target\x86_64-pc-windows-msvc\release\dig-app.exe",
            ] {
                assert!(
                    write_is_refused(false, Some(std::path::Path::new(exe))),
                    "a build-directory executable was allowed to rewrite the user's shortcut: {exe}"
                );
            }
        }

        /// **The SHIPPED app is still allowed to write the shortcut — the direction that breaks the
        /// product if it ever inverts.**
        ///
        /// A refusal that false-positives on an installed binary is strictly worse than the icon
        /// defect: the app never registers its AUMID and every DIG notification stops arriving, for
        /// every user, silently. Nothing else in this suite fails if the guard becomes over-broad —
        /// an always-refuse implementation satisfies every other assertion here — so this test is
        /// the only thing standing between that and a release. The last path is the near miss the
        /// depth bound exists for: `target` appears, but far above the executable.
        #[test]
        fn a_shipped_executable_may_still_write_the_shortcut() {
            for exe in [
                r"C:\Program Files\DIG\bin\dig-app.exe",
                r"C:\Users\someone\AppData\Local\DIG\dig-app.exe",
                r"C:\build\target\one\two\three\four\dig-app.exe",
            ] {
                assert!(
                    !write_is_refused(false, Some(std::path::Path::new(exe))),
                    "the installed app was refused its own AUMID registration: {exe}"
                );
            }
        }

        /// **An executable the process cannot identify is allowed, not refused.**
        ///
        /// `current_exe()` can fail, and the guard fails open there on purpose (see
        /// [`write_is_refused`]): breaking notifications for everyone is a worse outcome than a
        /// developer's shortcut going stale.
        #[test]
        fn an_unknown_executable_is_allowed() {
            assert!(!write_is_refused(false, None));
        }

        /// **The harness classifier that arms the `debug_assert` separates a harness from a shipped
        /// binary.**
        ///
        /// This one drives the loud-failure path only. It is kept distinct from the write decision
        /// because a test reaching the writer is a defect to shout about, while a `cargo run` is
        /// merely something to decline.
        #[test]
        fn only_the_deps_directory_reads_as_a_test_harness() {
            assert!(is_test_harness_path(std::path::Path::new(
                r"C:\repo\target\debug\deps\dig_app_core-e5b8b4388e0565db.exe"
            )));
            assert!(!is_test_harness_path(std::path::Path::new(
                r"C:\Program Files\DIG\bin\dig-app.exe"
            )));
            assert!(!is_test_harness_path(std::path::Path::new(
                r"C:\repo\target\debug\dig-app.exe"
            )));
        }
    }
}

/// The per-OS subprocess backends. Each shells out to the platform's notification tool WITHOUT a
/// shell (args are passed directly), so notification text cannot inject a command; macOS additionally
/// neutralizes the AppleScript string literal (per the native-dialog-markup-neutralize rule).
#[cfg(any(target_os = "linux", target_os = "macos"))]
mod platform {
    use super::{NativeNotifier, Notification};

    /// Linux: `notify-send <title> <body>` (libnotify). Args are separate, so no shell injection.
    #[cfg(target_os = "linux")]
    pub struct NotifySend;

    #[cfg(target_os = "linux")]
    impl NativeNotifier for NotifySend {
        fn show(&self, notification: &Notification) {
            let _ = std::process::Command::new("notify-send")
                .arg(&notification.title)
                .arg(&notification.body)
                .spawn();
        }
    }

    /// macOS: `osascript -e 'display notification "body" with title "title"'`. The two fields are
    /// interpolated into an AppleScript string literal, so each is neutralized (backslashes +
    /// double-quotes escaped) before interpolation.
    #[cfg(target_os = "macos")]
    pub struct OsaScript;

    #[cfg(target_os = "macos")]
    impl NativeNotifier for OsaScript {
        fn show(&self, notification: &Notification) {
            let script = format!(
                "display notification \"{}\" with title \"{}\"",
                applescript_escape(&notification.body),
                applescript_escape(&notification.title),
            );
            let _ = std::process::Command::new("osascript")
                .arg("-e")
                .arg(script)
                .spawn();
        }
    }

    /// Escape a string for safe interpolation into an AppleScript double-quoted literal.
    #[cfg(target_os = "macos")]
    fn applescript_escape(text: &str) -> String {
        text.replace('\\', "\\\\").replace('"', "\\\"")
    }

    #[cfg(all(test, target_os = "macos"))]
    mod tests {
        use super::applescript_escape;

        #[test]
        fn escaping_neutralizes_quotes_and_backslashes() {
            assert_eq!(applescript_escape(r#"a"b\c"#), r#"a\"b\\c"#);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn total(count: u64, mojos: u128) -> AssetTotal {
        AssetTotal { count, mojos }
    }

    #[test]
    fn xch_amount_trims_trailing_zeros() {
        assert_eq!(format_amount(None, 2_000_000_000_000), "2");
        assert_eq!(format_amount(None, 1_500_000_000_000), "1.5");
        assert_eq!(format_amount(None, 1), "0.000000000001");
    }

    #[test]
    fn cat_amount_uses_three_decimals() {
        assert_eq!(format_amount(Some(&AssetId("t".into())), 3_000), "3");
        assert_eq!(format_amount(Some(&AssetId("t".into())), 1_500), "1.5");
    }

    #[test]
    fn asset_label_names_native_dig_and_other_cats() {
        let dig = AssetId("dig".into());
        assert_eq!(asset_label(None, Some(&dig)), "XCH");
        assert_eq!(asset_label(Some(&dig), Some(&dig)), "$DIG");
        let other = AssetId("0123456789abcdef0123".into());
        assert_eq!(asset_label(Some(&other), Some(&dig)), "012345…0123");
    }

    #[test]
    fn direction_line_singular_plural_and_multi_asset() {
        let mut single = BTreeMap::new();
        single.insert(None, total(1, 1_000_000_000_000));
        assert_eq!(
            direction_line("Received", &single, None).unwrap(),
            "Received 1 XCH"
        );

        let mut burst = BTreeMap::new();
        burst.insert(None, total(3, 2_000_000_000_000));
        assert_eq!(
            direction_line("Received", &burst, None).unwrap(),
            "Received 3 payments: 2 XCH total"
        );

        let dig = AssetId("dig".into());
        let mut multi = BTreeMap::new();
        multi.insert(None, total(1, 1_000_000_000_000));
        multi.insert(Some(dig.clone()), total(1, 1_500));
        let line = direction_line("Received", &multi, Some(&dig)).unwrap();
        assert!(line.contains("2 payments"), "{line}");
        assert!(line.contains("1 XCH"), "{line}");
        assert!(line.contains("1.5 $DIG"), "{line}");
    }

    #[test]
    fn empty_direction_is_none() {
        assert!(direction_line("Received", &BTreeMap::new(), None).is_none());
    }

    #[test]
    fn logging_notifier_never_panics() {
        LoggingNotifier.show(&Notification {
            title: "t".into(),
            body: "b".into(),
        });
    }

    #[test]
    fn native_notifier_factory_returns_a_usable_notifier() {
        native_notifier().show(&Notification {
            title: "DIG".into(),
            body: "Received 1 XCH".into(),
        });
    }
}
