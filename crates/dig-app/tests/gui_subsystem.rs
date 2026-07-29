//! The GUI-subsystem gate (dig_ecosystem#1797): the built `dig-app.exe` MUST declare subsystem 2.
//!
//! # Why a header parse and not a claim
//!
//! `dig-app.exe` v3.4.0 declared PE subsystem **3 (`WINDOWS_CUI`)**, so Windows allocated a console for a
//! tray application: a black window appeared at every launch and the tray's lifetime was tied to it. The
//! fix is one attribute, `#![windows_subsystem = "windows"]`, and an attribute is exactly the kind of thing
//! a later refactor drops without anyone noticing — the binary still builds, still runs, and the console
//! quietly comes back. WireGuard's tray app on the same machine is subsystem 2; `dig-node` is 3 and
//! correctly so, being a service and a CLI.
//!
//! So the claim is GATED: this test reads the produced binary's own optional header. `CARGO_BIN_EXE_dig-app`
//! is set by Cargo for integration tests and points at the binary built from this crate, so the bytes under
//! test are the bytes that ship.
//!
//! # The second half, which is the one that bites
//!
//! A GUI-subsystem process has NO CONSOLE, so `println!` goes nowhere — and the update beacon health-gates
//! this component by spawning `dig-app --version` and requiring one line on stdout
//! (`dig_updater_broker::probe`). Flipping the subsystem without handling that would silently regress
//! `--version` to empty output, reintroducing the defect #1749 closed. The version test below runs the real
//! binary with a captured (piped) stdout — the same shape the beacon uses — and asserts the line is there.

/// Where the PE signature's offset is stored in the DOS header (`e_lfanew`).
const E_LFANEW_OFFSET: usize = 0x3C;

/// The optional header begins 24 bytes after the `PE\0\0` signature: 4 signature + 20 COFF header.
const OPTIONAL_HEADER_OFFSET: usize = 24;

/// `Subsystem` sits at offset 68 in the optional header, in both PE32 and PE32+ — the fields before it are
/// identical in the two layouts, which is why this needs no 32/64-bit branch.
const SUBSYSTEM_OFFSET: usize = 68;

/// `IMAGE_SUBSYSTEM_WINDOWS_GUI` — no console is allocated. What a tray application must be.
const WINDOWS_GUI: u16 = 2;

/// `IMAGE_SUBSYSTEM_WINDOWS_CUI` — Windows allocates a console. What v3.4.0 wrongly shipped as.
const WINDOWS_CUI: u16 = 3;

/// Read a PE image's declared subsystem, or `None` if the file is not a PE image at all.
///
/// Deliberately a hand parse rather than a dependency: three offsets and two little-endian reads is less
/// code than the wiring to add and pin an object-file crate for one field, and every step is named above.
fn pe_subsystem(bytes: &[u8]) -> Option<u16> {
    if bytes.get(..2)? != b"MZ" {
        return None;
    }
    let pe_offset = u32::from_le_bytes(
        bytes
            .get(E_LFANEW_OFFSET..E_LFANEW_OFFSET + 4)?
            .try_into()
            .ok()?,
    ) as usize;
    if bytes.get(pe_offset..pe_offset + 4)? != b"PE\0\0" {
        return None;
    }
    let at = pe_offset + OPTIONAL_HEADER_OFFSET + SUBSYSTEM_OFFSET;
    Some(u16::from_le_bytes(bytes.get(at..at + 2)?.try_into().ok()?))
}

/// **The gate (#1797).** The shipped binary must declare `WINDOWS_GUI`, so no console window is created and
/// the tray's lifetime is its own.
#[test]
#[cfg(target_os = "windows")]
fn the_shipped_binary_declares_the_gui_subsystem() {
    let exe = std::path::Path::new(env!("CARGO_BIN_EXE_dig-app"));
    let bytes = std::fs::read(exe).expect("the built dig-app binary must be readable");

    let subsystem = pe_subsystem(&bytes).expect("dig-app.exe must be a PE image");
    assert_ne!(
        subsystem, WINDOWS_CUI,
        "dig-app is a tray application: subsystem {WINDOWS_CUI} (WINDOWS_CUI) makes Windows allocate a \
         console window and ties the tray's lifetime to it (dig_ecosystem#1797)"
    );
    assert_eq!(
        subsystem, WINDOWS_GUI,
        "dig-app must declare subsystem {WINDOWS_GUI} (WINDOWS_GUI), got {subsystem}"
    );
}

/// The parser itself must be able to tell the two subsystems apart and reject a non-PE file.
///
/// Without this, a parser that returned a constant 2 — or that read the wrong offset and happened to find a
/// 2 there — would make the gate above a rubber stamp that passes on any input. The negative cases are what
/// prove it is reading the field.
#[test]
fn the_header_parser_rejects_anything_that_is_not_a_pe_image() {
    assert_eq!(pe_subsystem(b"not an executable at all"), None);
    assert_eq!(pe_subsystem(b""), None);
    // An `MZ` header whose PE offset points past the end of the file: truncated, not a PE image.
    let mut truncated = vec![0u8; 64];
    truncated[0..2].copy_from_slice(b"MZ");
    truncated[E_LFANEW_OFFSET..E_LFANEW_OFFSET + 4].copy_from_slice(&9999u32.to_le_bytes());
    assert_eq!(pe_subsystem(&truncated), None);
}

/// The parser reads the SUBSYSTEM field specifically — proven by handing it a synthetic image with a
/// known-CUI value and requiring it to say 3.
///
/// This is the control the gate needs: it shows a failing binary WOULD be detected, so the passing assertion
/// above is evidence rather than a coincidence.
#[test]
fn the_header_parser_reports_a_cui_image_as_cui() {
    let mut image = vec![0u8; 512];
    image[0..2].copy_from_slice(b"MZ");
    let pe_offset = 128usize;
    image[E_LFANEW_OFFSET..E_LFANEW_OFFSET + 4].copy_from_slice(&(pe_offset as u32).to_le_bytes());
    image[pe_offset..pe_offset + 4].copy_from_slice(b"PE\0\0");
    let at = pe_offset + OPTIONAL_HEADER_OFFSET + SUBSYSTEM_OFFSET;
    image[at..at + 2].copy_from_slice(&WINDOWS_CUI.to_le_bytes());

    assert_eq!(pe_subsystem(&image), Some(WINDOWS_CUI));

    image[at..at + 2].copy_from_slice(&WINDOWS_GUI.to_le_bytes());
    assert_eq!(pe_subsystem(&image), Some(WINDOWS_GUI));
}

/// **The regression the subsystem flip could have caused (#1797 × #1749).** `dig-app --version` must still
/// print exactly one line on stdout and exit 0, from a GUI-subsystem binary with no console of its own.
///
/// `Command::output` gives the child a PIPE for stdout, which is precisely the shape
/// `dig_updater_broker::probe` uses to health-gate this component — so this exercises the beacon's real
/// path, not a console-attached approximation. (A console-attached run is not scriptable and is verified by
/// observation from a real `cmd.exe` and PowerShell; see the PR.)
#[test]
fn version_still_answers_on_a_piped_stdout_from_a_gui_subsystem_binary() {
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_dig-app"))
        .arg("--version")
        .output()
        .expect("dig-app --version must run");

    assert!(output.status.success(), "--version must exit 0: {output:?}");
    let stdout = String::from_utf8_lossy(&output.stdout);
    let lines: Vec<&str> = stdout
        .lines()
        .filter(|line| !line.trim().is_empty())
        .collect();
    assert_eq!(
        lines.len(),
        1,
        "the beacon reads ONE line and gives up after 10s; got {lines:?}"
    );
    assert!(
        lines[0].contains(env!("CARGO_PKG_VERSION")),
        "the line must carry the version the manifest declares: {:?}",
        lines[0]
    );
}
