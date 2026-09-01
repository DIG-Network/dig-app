//! The Linux runtime-dependency contract of the tray shell (dig_ecosystem#1753).
//!
//! `dig-app` is delivered as a single prebuilt binary that a stranger downloads and runs. Every
//! library in its `DT_NEEDED` list is therefore a hard, pre-`main` install requirement on the user's
//! machine: if the loader cannot find one, the process dies with rc=127 before a single line of our
//! code executes — no runtime probe, no graceful degradation, no log line. So the shell may only
//! link libraries whose capability it actually uses.
//!
//! `libxdo` (the X11 automation library behind `xdotool`) failed that test. `tray-icon` enables it
//! by default and passes it down to `muda`, which uses it in exactly ONE place: synthesizing
//! `ctrl+c`/`ctrl+x`/`ctrl+v`/`ctrl+a` keystrokes so the PREDEFINED Copy/Cut/Paste/SelectAll menu
//! items work. Our tray menu contains none of those items, so `libxdo.so.3` was an unconditional
//! runtime dependency buying nothing — and stock Ubuntu does not ship it.
//!
//! This test pins that contract at the resolved dependency graph rather than at the manifest text,
//! because the manifest is only one of several ways `libxdo` can come back: another crate, another
//! feature list, or a `tray-icon` upgrade whose defaults differ would all reintroduce it while the
//! `default-features = false` spelling still sits in `Cargo.toml`.

use std::process::Command;

/// The dependency graph `cargo` resolves for the Linux tray build — the exact set of crates whose
/// `build.rs` link directives end up in the shipped Linux binary.
fn linux_tray_dependency_graph() -> String {
    linux_dependency_graph(&[])
}

/// The same graph for the HEADLESS build — `--no-default-features`, the flags
/// `build-binaries.yml` uses to produce the `-headless` artifact.
fn linux_headless_dependency_graph() -> String {
    linux_dependency_graph(&["--no-default-features"])
}

fn linux_dependency_graph(extra: &[&str]) -> String {
    let output = Command::new(env!("CARGO"))
        .args([
            "tree",
            "--package",
            "dig-app",
            "--edges",
            "normal,build",
            "--target",
            "x86_64-unknown-linux-gnu",
            "--prefix",
            "none",
        ])
        .args(extra)
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .output()
        .expect("`cargo tree` must be runnable to check the Linux link contract");

    assert!(
        output.status.success(),
        "`cargo tree` failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).expect("`cargo tree` emits UTF-8")
}

/// The default Linux build MUST NOT link `libxdo`, whose only capability (X11 keystroke synthesis
/// for predefined clipboard menu items) the tray does not use.
///
/// The `tray-icon` assertion is the control: without it this test would also pass if the tray were
/// disabled outright, which would "fix" the missing library by deleting the feature under test.
#[test]
fn linux_tray_build_does_not_depend_on_libxdo() {
    let graph = linux_tray_dependency_graph();

    assert!(
        graph.contains("tray-icon "),
        "expected the default Linux build to still contain the tray shell; \
         a tray-less graph cannot prove anything about the tray's link set:\n{graph}"
    );
    assert!(
        !graph.contains("libxdo"),
        "the Linux tray build must not link libxdo — it is absent from stock Ubuntu and the loader \
         kills the process before `main`. Graph:\n{graph}"
    );
}

/// `muda` is the transitive owner of the `libxdo` link, so an upgrade that re-enables it by default
/// must fail here too. Asserting on `muda` as well as `tray-icon` keeps the property attached to the
/// crate that actually pulls the library in, not just to our direct dependency.
#[test]
fn linux_tray_build_keeps_muda_without_its_libxdo_feature() {
    let graph = linux_tray_dependency_graph();

    assert!(
        graph.contains("muda "),
        "the tray menu is built on muda; if it is gone this test no longer guards anything:\n{graph}"
    );
    assert!(
        !graph.contains("libxdo-sys"),
        "libxdo-sys emits `cargo:rustc-link-lib=xdo`, which is the DT_NEEDED entry that breaks \
         stock Linux hosts. Graph:\n{graph}"
    );
}

/// **The headless artifact's defining property, guarded at the resolved graph (dig-app#309).**
///
/// The default Linux build carries hard `DT_NEEDED` entries on `libgtk-3.so.0`, `libgdk-3.so.0` and
/// `libcairo.so.2`, so on a server with no desktop packages the dynamic loader kills it at exit 127
/// — before `main()`, before any log line, before the shell's own headless degrade can be reached.
/// The `-headless` artifact exists because of that, and it is only useful for as long as it links
/// none of them.
///
/// This is asserted at the graph rather than at `Cargo.toml`'s `default = ["tray"]` for the same
/// reason the `libxdo` tests above are: a manifest spelling is one of several ways a desktop
/// dependency can come back. Another crate, another default feature set, or a dependency upgrade
/// would all reintroduce it while the manifest still reads correctly.
///
/// It also runs on every platform, unlike the `ldd` checks in `build-binaries.yml`, which can only
/// speak after a Linux artifact has been built.
#[test]
fn the_headless_linux_build_links_no_desktop_stack() {
    let headless = linux_headless_dependency_graph();

    // The control FIRST: a graph that resolved nothing would satisfy every absence assertion below
    // while proving nothing at all.
    assert!(
        headless.contains("dig-app-core "),
        "the headless graph did not resolve; it cannot prove anything:
{headless}"
    );

    for desktop in ["gtk-sys", "gdk-sys", "cairo-sys-rs", "tao ", "tray-icon "] {
        assert!(
            !headless.contains(desktop),
            "the headless build must link no desktop stack, but the graph contains `{desktop}`.              A missing library kills the process in the loader, before `main`, which is exactly              what this artifact exists to avoid. Graph:
{headless}"
        );
    }
}

/// The control for the test above, and the measurement behind dig-app#309: the DEFAULT build really
/// does pull the desktop stack in. Without this, removing the `tray` feature entirely would satisfy
/// every absence assertion — "fixing" the exit-127 by deleting the desktop shell.
///
/// The two together state the actual contract: **the choice between them is made when the artifact
/// is selected, never at run time.**
#[test]
fn the_default_linux_build_does_link_the_desktop_stack() {
    let tray = linux_tray_dependency_graph();

    for desktop in ["gtk-sys", "gdk-sys", "cairo-sys-rs", "tao "] {
        assert!(
            tray.contains(desktop),
            "the default Linux build is expected to link `{desktop}` — if it no longer does, the              headless artifact and the `--help` wording that points a server operator at it are              both describing a distinction that has stopped existing. Graph:
{tray}"
        );
    }
}
