//! Embeds `dig-app.manifest` into the Windows binaries this crate builds.
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

use std::path::Path;

fn main() {
    let manifest = Path::new(env!("CARGO_MANIFEST_DIR")).join("dig-app.manifest");
    println!("cargo:rerun-if-changed={}", manifest.display());
    println!("cargo:rerun-if-changed=build.rs");

    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() != Ok("windows") {
        return;
    }

    match std::env::var("CARGO_CFG_TARGET_ENV").as_deref() {
        Ok("msvc") => embed(&manifest),
        other => println!(
            "cargo:warning=dig-app.manifest was NOT embedded on this Windows toolchain ({}), so \
             this binary's DPI awareness is decided by whichever event loop is constructed first \
             (dig-app#87). Build with the MSVC toolchain for a release.",
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
