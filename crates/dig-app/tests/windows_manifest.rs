//! The application manifest says what it must, and it is actually IN the shipped binary.
//!
//! # Why both halves are here
//!
//! A manifest is a file that does nothing until a linker embeds it, and a build script that fails to
//! embed one fails silently — the binary simply carries the linker's default instead, and behaves
//! exactly as it did before. So asserting the file's CONTENT proves only that somebody wrote the
//! right XML; the second test opens the built `dig-app.exe` and reads the manifest back out of its
//! resources, which is the only assertion that can tell "embedded" from "written and ignored".
//!
//! Both matter for dig-app#87. The content test pins WHICH awareness is declared — the neighbouring
//! wrong manifest declares the legacy system-wide `dpiAware`, which reads as "DPI aware" in every
//! summary and still leaves a window blurry the moment it is dragged to a second monitor.

/// The manifest as it sits in the source tree.
fn manifest_source() -> String {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("dig-app.manifest");
    std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("the manifest must exist at {}: {e}", path.display()))
}

/// The awareness declared must be PER-MONITOR v2, not the legacy system-wide setting.
///
/// # Why the legacy element is checked too rather than merely tolerated
///
/// Windows reads `<dpiAware>` on hosts older than the 1703 release that introduced v2, and its
/// value is a two-way choice: `true` means system-aware (one scale factor for the whole desktop,
/// chosen at logon) and `true/pm` means per-monitor. A manifest carrying `PerMonitorV2` beside a
/// bare `true` is per-monitor on new Windows and system-aware on old, which is the drift this
/// asserts against — and it is invisible to any test that only greps for "PerMonitorV2".
#[test]
fn the_manifest_declares_per_monitor_v2_awareness_on_both_spellings() {
    let manifest = manifest_source();

    assert!(
        manifest.contains(">PerMonitorV2<"),
        "the manifest must declare PerMonitorV2 awareness; without it this process's awareness is \
         decided by whichever event loop is constructed first (dig-app#87)"
    );
    assert!(
        manifest.contains(">true/pm<"),
        "the pre-1703 spelling must say true/pm (per-monitor), not a bare true (system-aware)"
    );
    assert!(
        !manifest.contains(">true<"),
        "a bare <dpiAware>true</dpiAware> is SYSTEM awareness and would silently downgrade older \
         hosts to one scale factor for the whole desktop"
    );
}

/// The shell must run as the user who launched it, and must never ask to be elevated.
///
/// An elevated process cannot be sent input by the unelevated desktop around it, and a tray app that
/// prompts for admin teaches its user to grant admin to tray apps. This is a consent-bearing
/// binary; the requested level is part of that posture, so it is pinned rather than left to the
/// linker's default.
#[test]
fn the_manifest_never_asks_to_be_elevated() {
    let manifest = manifest_source();

    assert!(
        manifest.contains(r#"level="asInvoker""#),
        "the requested execution level must be stated, and must be asInvoker"
    );
    for elevated in [
        "requireAdministrator",
        "highestAvailable",
        r#"uiAccess="true""#,
    ] {
        assert!(
            !manifest.contains(elevated),
            "the manifest must not request {elevated}: dig-app guards custody actions with its own \
             consent windows and has nothing to do as an administrator"
        );
    }
}

/// The manifest is present in the BUILT binary's resources — the half a content test cannot see.
///
/// # Why this reads the artifact instead of the build script
///
/// `build.rs` emits `/MANIFESTINPUT` for `bins` only, so this test's own harness carries no
/// manifest and cannot answer the question by inspecting itself; and a test asserting that
/// `build.rs` *contains* the right string is a transcription of the thing under test. Cargo builds
/// the real `dig-app` binary for this integration test and hands over its path, so the resource is
/// read from the file that ships.
///
/// MSVC-only for the same reason the build script is: the flags are MSVC linker syntax, and on any
/// other Windows toolchain the build script warns and embeds nothing, which this would then
/// correctly but uselessly fail on.
#[cfg(all(windows, target_env = "msvc"))]
#[test]
fn the_built_binary_carries_the_manifest_in_its_resources() {
    use windows::core::PCWSTR;
    use windows::Win32::Foundation::FreeLibrary;
    use windows::Win32::System::LibraryLoader::{
        FindResourceW, LoadLibraryExW, LoadResource, LockResource, SizeofResource,
        LOAD_LIBRARY_AS_DATAFILE,
    };

    /// `RT_MANIFEST`, as `MAKEINTRESOURCE` spells it: a resource TYPE is either a string pointer or
    /// a small integer stuffed into one, and 24 is the manifest type.
    const RT_MANIFEST: PCWSTR = PCWSTR(24 as *const u16);
    /// `CREATEPROCESS_MANIFEST_RESOURCE_ID` — where `/MANIFEST:EMBED` puts an executable's manifest.
    const EXE_MANIFEST_ID: PCWSTR = PCWSTR(1 as *const u16);

    let exe: Vec<u16> = env!("CARGO_BIN_EXE_dig-app")
        .encode_utf16()
        .chain([0])
        .collect();

    // SAFETY: every pointer below is to a live local that outlives its call, and the module is
    // loaded AS A DATA FILE — nothing in it is executed, no entry point runs, and the handle is
    // freed at the end. The resource bytes are read only while that handle is alive.
    let manifest = unsafe {
        let module = LoadLibraryExW(PCWSTR(exe.as_ptr()), None, LOAD_LIBRARY_AS_DATAFILE)
            .expect("the built dig-app.exe must be loadable as a data file");
        let found = FindResourceW(module, EXE_MANIFEST_ID, RT_MANIFEST);
        assert!(
            !found.is_invalid(),
            "the built dig-app.exe carries NO embedded manifest, so its DPI awareness is still \
             decided by event-loop construction order; build.rs did not reach the linker"
        );
        let size = SizeofResource(module, found) as usize;
        let handle = LoadResource(module, found).expect("the manifest resource must load");
        let bytes = LockResource(handle) as *const u8;
        assert!(
            !bytes.is_null() && size > 0,
            "the manifest resource is empty"
        );
        let embedded = std::slice::from_raw_parts(bytes, size).to_vec();
        let _ = FreeLibrary(module);
        embedded
    };

    let embedded = String::from_utf8_lossy(&manifest);
    assert!(
        embedded.contains("PerMonitorV2"),
        "a manifest is embedded but it is not OURS — the linker's default was used and the \
         PerMonitorV2 declaration was dropped. Embedded manifest was:\n{embedded}"
    );
    assert!(
        embedded.contains("asInvoker"),
        "the embedded manifest must carry the asInvoker execution level"
    );
}
