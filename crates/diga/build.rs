//! Embeds the canonical DIG icon (`assets/dig.ico`, repo root) into `diga.exe`.
//!
//! # Why this mounts `dig-app`'s encoder rather than declaring a second one (dig_ecosystem#2917)
//!
//! `crates/dig-app/build/res.rs` turns an `.ico` into the Windows `.res` object the MSVC linker
//! embeds as a binary's icon, and it is already covered by `dig-app`'s own
//! `tests/icon_resource.rs`. `diga` never had an icon before this change, so the choice is between
//! reusing that tested encoder by path and writing a second copy of the same fixed-width binary
//! format — the second copy is two chances to get the `.res` header layout wrong instead of one.
//! Sharing by `#[path = ...]` costs no new dependency and no crate boundary: a build script is
//! compiled as its own standalone unit regardless.
//!
//! SHARED WITH `../dig-app/build/res.rs` — see the matching comment there. If that module moves,
//! this path must move with it.
#[path = "../dig-app/build/res.rs"]
mod res;

use std::path::{Path, PathBuf};

fn main() {
    let crate_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    // The canonical, byte-pinned icon lives at the repo root (`assets/dig.ico`), shared by every
    // crate in this repo that produces a shipped binary — never a per-crate copy.
    let icon = crate_dir.join("..").join("..").join("assets").join("dig.ico");
    println!("cargo:rerun-if-changed={}", icon.display());
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=../dig-app/build/res.rs");

    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() != Ok("windows") {
        return;
    }

    // Mirrors `dig-app/build.rs`'s WARN-not-fail structure exactly, for the same reason (dig-app#87):
    // an environment that cannot compile a resource must not stop a developer building `diga`.
    match std::env::var("CARGO_CFG_TARGET_ENV").as_deref() {
        Ok("msvc") => embed_icon(&icon),
        other => println!(
            "cargo:warning=the DIG icon was NOT embedded on this Windows toolchain ({}), so \
             diga.exe's Explorer/Alt-Tab/taskbar entries fall back to a generic icon.",
            other.unwrap_or("unknown")
        ),
    }
}

/// Compile the DIG icon into a `.res` object and hand it to the linker as an ordinary input.
///
/// A failure here WARNS rather than panicking — same reasoning as `dig-app/build.rs::embed_icon`.
fn embed_icon(icon: &Path) {
    let Some(out_dir) = std::env::var_os("OUT_DIR") else {
        println!("cargo:warning=OUT_DIR is unset, so the DIG icon was not embedded.");
        return;
    };

    let written = std::fs::read(icon)
        .map_err(|e| format!("{} could not be read: {e}", icon.display()))
        .and_then(|bytes| res::ico_to_res(&bytes))
        .and_then(|res| {
            let path = PathBuf::from(out_dir).join("diga-icon.res");
            match std::fs::write(&path, res) {
                Ok(()) => Ok(path),
                Err(e) => Err(format!("{} could not be written: {e}", path.display())),
            }
        });

    match written {
        Ok(path) => println!("cargo:rustc-link-arg-bins={}", path.display()),
        Err(reason) => println!(
            "cargo:warning=the DIG icon was NOT embedded ({reason}), so diga.exe's Explorer/Alt-Tab/\
             taskbar entries will show a generic icon."
        ),
    }
}
