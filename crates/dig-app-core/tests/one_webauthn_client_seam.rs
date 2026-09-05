//! The WebAuthn CLIENT lives behind exactly one seam, and no future edit may open a second one
//! (dig-app#348, SPEC §3.1e *The client seam*).
//!
//! # The property this defends
//!
//! A WebAuthn ceremony has two halves. The VERIFIER (`second_factor/verifier.rs`) mints challenges and
//! judges responses; it is pure, platform-independent, and every other module may use it. The CLIENT
//! asks the operating system to put a dialog on the screen and get a real authenticator to answer —
//! and it is the only platform-specific half.
//!
//! Confining the client to `second_factor/authenticator.rs` is what lets the rest of the crate be
//! written once and tested anywhere. It is also what makes the platform story honest: `ClientSupport`
//! and `NoProvider` can only be the whole truth about what a build can do if there is nowhere else a
//! ceremony could be driven from. A second client added beside this one would make the tray say *not
//! available on this platform in this version* while some other module quietly ran a ceremony.
//!
//! # Why this test had to be written
//!
//! `authenticator.rs`'s own module doc has always CLAIMED this rule is "enforced directly" by the
//! conformance suite. It was not — no such test existed, so the claim was false in the commit that
//! wrote it, and the seam was held only by everyone remembering it. This is that test.
//!
//! # Why a source scan rather than a behavioural test
//!
//! The property is an ABSENCE, and absence has no runtime witness: there is no call to make that
//! observes a second client failing to exist. A behavioural test would pass identically in a build
//! that had grown one. So the witness is the source itself.
//!
//! Only `src/` trees are scanned, never `tests/` — the forbidden tokens appear in THIS file as data,
//! and a scan that included its own text could never pass.

use std::path::{Path, PathBuf};

/// Spellings that mean "this file drives a platform WebAuthn ceremony".
///
/// Deliberately NOT `webauthn_rs` or `webauthn_rs_proto`: those are the VERIFIER and the wire types,
/// they carry no platform behaviour, and several modules use them correctly. Forbidding them would
/// make this guard fire on the code it exists to protect.
const FORBIDDEN: &[&str] = &[
    // The client crate, by module path and by manifest name.
    "webauthn_authenticator_rs",
    "webauthn-authenticator-rs",
    // Its error type and its backend trait — the two symbols that would surface first if a second
    // client were wired up through a re-export rather than a direct dependency.
    "WebauthnCError",
    "AuthenticatorBackend",
];

/// The ONE file permitted to name them: the seam itself.
const THE_SEAM: &str = "authenticator.rs";

/// The `src/` trees that make up the app: the core crate and the binary crates that wire it.
fn scanned_source_roots() -> Vec<PathBuf> {
    let workspace = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("dig-app-core lives inside crates/")
        .to_path_buf();
    vec![
        workspace.join("dig-app-core").join("src"),
        workspace.join("dig-app").join("src"),
        workspace.join("diga").join("src"),
    ]
}

/// Every `.rs` file under `root`, recursively.
fn rust_sources(root: &Path) -> Vec<PathBuf> {
    let mut found = Vec::new();
    let Ok(entries) = std::fs::read_dir(root) else {
        return found;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            found.extend(rust_sources(&path));
        } else if path.extension().is_some_and(|ext| ext == "rs") {
            found.push(path);
        }
    }
    found
}

#[test]
fn only_the_client_seam_names_a_platform_webauthn_client() {
    let mut offences = Vec::new();
    let mut scanned = 0;
    let mut seam_seen = false;

    for root in scanned_source_roots() {
        assert!(
            root.is_dir(),
            "expected a source tree at {}",
            root.display()
        );
        for file in rust_sources(&root) {
            scanned += 1;
            let is_seam = file.file_name().is_some_and(|name| name == THE_SEAM)
                && file
                    .parent()
                    .is_some_and(|dir| dir.file_name().is_some_and(|name| name == "second_factor"));
            let text = std::fs::read_to_string(&file).expect("a source file is readable");
            if is_seam {
                // The seam must actually CONTAIN a client, or the rule is being satisfied by an empty
                // file and this test is guarding nothing.
                seam_seen |= FORBIDDEN.iter().any(|token| text.contains(token));
                continue;
            }
            for (line_no, line) in text.lines().enumerate() {
                for token in FORBIDDEN {
                    if line.contains(token) {
                        offences.push(format!("{}:{}: {token}", file.display(), line_no + 1));
                    }
                }
            }
        }
    }

    assert!(
        scanned >= 100,
        "the client-seam guard scanned only {scanned} source files; a scan that reads almost nothing \
         passes for the wrong reason"
    );

    assert!(
        seam_seen,
        "the guard never found a platform WebAuthn client inside second_factor/{THE_SEAM}. Either the \
         seam moved — in which case move this guard with it — or there is no client left, and this \
         test is now asserting an absence that would hold trivially."
    );

    assert!(
        offences.is_empty(),
        "a second WebAuthn CLIENT appeared outside second_factor/{}.\n\n{}\n\nThe platform ceremony \
         lives behind ONE seam (SPEC §3.1e) so that `ClientSupport` and `NoProvider` are the whole \
         truth about what a build can do. A ceremony driven from anywhere else would let the tray say \
         \"not available on this platform in this version\" while some other module ran one. If the \
         seam genuinely needs to move, change SPEC §3.1e and this test with it; do not delete the \
         test to make a second client compile.",
        THE_SEAM,
        offences.join("\n")
    );
}
