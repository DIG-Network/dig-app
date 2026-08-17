//! Embeds `dig-app.manifest` and the DIG Mark icon into the Windows binaries this crate builds.
//!
//! # Why a build script rather than a crate
//!
//! Embedding a manifest is two linker flags. `embed-manifest`/`winresource` would add a
//! build-dependency and its transitive tree to a consent-bearing app to save writing them, and the
//! only thing they buy over this is windows-gnu support, which nothing here targets
//! (`.github/workflows/build-binaries.yml:75` builds `x86_64-pc-windows-msvc` and no other Windows
//! triple).
//!
//! # What happens on a target this does not cover
//!
//! Nothing, deliberately, and loudly. A non-Windows build has no manifest to embed. A Windows build
//! on a non-MSVC toolchain WARNS rather than failing: the flags below are MSVC linker syntax, and a
//! silent skip is how a process quietly goes back to deciding its DPI awareness by event-loop
//! construction order — the exact defect the manifest exists to remove (dig-app#87).

use std::path::{Path, PathBuf};

#[path = "build/res.rs"]
mod res;

fn main() {
    let crate_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    let manifest = crate_dir.join("dig-app.manifest");
    let icon = crate_dir.join("icons").join("mark.ico");
    println!("cargo:rerun-if-changed={}", manifest.display());
    println!("cargo:rerun-if-changed={}", icon.display());
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=build/res.rs");

    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() != Ok("windows") {
        return;
    }

    match std::env::var("CARGO_CFG_TARGET_ENV").as_deref() {
        Ok("msvc") => {
            embed(&manifest);
            embed_icon(&icon);
        }
        other => println!(
            "cargo:warning=dig-app.manifest and the DIG Mark icon were NOT embedded on this \
             Windows toolchain ({}), so this binary's DPI awareness is decided by whichever event \
             loop is constructed first (dig-app#87) and its notifications, taskbar and Explorer \
             entries fall back to a generic icon (#3076). Build with the MSVC toolchain for a \
             release.",
            other.unwrap_or("unknown")
        ),
    }
}

/// Ask the MSVC linker to merge our manifest into the default one it already generates.
///
/// `/MANIFEST:EMBED` puts the result in the binary's resources rather than beside it as a
/// `.exe.manifest`, which a loose file the installer could fail to copy would leave unapplied.
/// Applied to bins only: a test harness or an rlib has no manifest of its own to carry one.
fn embed(manifest: &Path) {
    println!("cargo:rustc-link-arg-bins=/MANIFEST:EMBED");
    println!(
        "cargo:rustc-link-arg-bins=/MANIFESTINPUT:{}",
        manifest.display()
    );
}

/// Compile the DIG Mark into a `.res` object and hand it to the linker as an ordinary input.
///
/// The icon has to live in the binary rather than only beside it: Windows attributes an unpackaged
/// Win32 toast to a Start Menu shortcut, and that shortcut draws whatever the executable it points
/// at carries. With no icon resource, every surface that samples one — the toast, the taskbar,
/// Explorer, Alt-Tab — falls back to the generic file icon (#3076).
///
/// A failure here WARNS rather than panicking, for the same reason the manifest branch does: an
/// unbuildable icon must not stop a developer building, but it must never be silent either.
fn embed_icon(icon: &Path) {
    let Some(out_dir) = std::env::var_os("OUT_DIR") else {
        println!("cargo:warning=OUT_DIR is unset, so the DIG Mark icon was not embedded (#3076).");
        return;
    };

    let written = std::fs::read(icon)
        .map_err(|e| format!("{} could not be read: {e}", icon.display()))
        .and_then(|bytes| res::ico_to_res(&bytes))
        .and_then(|res| {
            let path = PathBuf::from(out_dir).join("dig-app-icon.res");
            match std::fs::write(&path, res) {
                Ok(()) => Ok(path),
                Err(e) => Err(format!("{} could not be written: {e}", path.display())),
            }
        });

    match written {
        Ok(path) => println!("cargo:rustc-link-arg-bins={}", path.display()),
        Err(reason) => println!(
            "cargo:warning=the DIG Mark icon was NOT embedded ({reason}), so this binary's \
             notifications, taskbar and Explorer entries will show a generic icon (#3076)."
        ),
    }
}
