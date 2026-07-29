//! Raise one real, OS-drawn DIG confirm window so a human can LOOK at it (dig_ecosystem#1773).
//!
//! # Why this exists
//!
//! The defect this example was written to verify — every tray notice arriving as a warning triangle with
//! a meaningless Cancel — was found by inspecting a SCREENSHOT, not by reading code. Every code path
//! involved was already correct, so no unit test caught it and none could: the bug was in the presentation
//! the OS drew. Native dialogs also cannot be constructed inside a `cargo test` process on this stack, so
//! there is nowhere in the test suite this could live.
//!
//! So the presentation is verified the only way it can be: raise the real window and photograph it.
//!
//! ```text
//! cargo run -p dig-app-core --example dialog_gallery -- notice
//! ```
//!
//! `which` selects the window:
//!
//! | `which` | the window |
//! |---|---|
//! | `notice` | informational, one button |
//! | `claim` | the enrolment retention either/or |
//! | `authorization` | the reveal gate |
//! | `destroy` | the replace/remove authorization (dig_ecosystem#1799) |
//! | `input` | the native recovery-phrase FIELD (dig_ecosystem#1798) |
//! | `passphrase` | the same field, masked |
//!
//! Dismissing with Escape denies, so `authorization` and `destroy` never reach the biometric step and
//! nothing is revealed or destroyed — this example only ever DRAWS. The `input` cases print the LENGTH of
//! what was typed, never the text, so a screenshot session cannot leak a phrase into a terminal.

use dig_app_core::confirm::{
    native_confirmer, ClaimPrompt, DestroyPrompt, InputPrompt, NoticePrompt, RevealPrompt,
};

fn main() {
    let which = std::env::args().nth(1).unwrap_or_else(|| "notice".into());
    let confirmer = native_confirmer();

    let decision = match which.as_str() {
        // The most-shown tray message, and the one whose screenshot exposed the defect: a plain success.
        "notice" => confirmer.show_notice(&NoticePrompt {
            title: "DIG — DIG ID copied",
            heading: "Your DIG ID is on the clipboard.",
            body: "b6f1c0a94e2d7c5183ab0f39d84e6c72b1590adf3e7c48d2916b05fa7c3d81e4",
            acknowledge: "OK",
        }),
        // The enrolment retention claim: a genuine either/or where Cancel abandons setup.
        "claim" => confirmer.confirm_claim(&ClaimPrompt {
            title: "DIG — Confirm you saved it",
            heading: "Do you have your 24 words written down somewhere safe?",
            body: "If you continue without them and later lose this computer, your DIG Account, its \
                   address and everything sealed under it are gone for good. You can view the words \
                   again later from the DIG tray menu.",
            affirm: "Yes, I have them",
        }),
        // The reveal gate: an authorization, which keeps the warning icon honestly.
        "authorization" => confirmer.confirm_reveal(&RevealPrompt {
            secret: "your 24-word DIG recovery phrase",
        }),
        // The destructive authorization (#1799): the window a user sees before their custody root is
        // discarded. It must wear the warning icon, keep a real Cancel, and name the irreversible loss.
        "destroy" => confirmer.confirm_destroy(&DestroyPrompt {
            subject: "the DIG Account on this computer",
            // Copied from `Replacement::WithNewAccount.promise()` rather than referenced, because that
            // method is private to the journey module and this example exists to show the WINDOW.
            replacement: concat!(
                "A brand-new DIG Account will be created in its place, with a new recovery phrase, ",
                "a new identity and a new address."
            ),
            recoverable: false,
        }),
        // The native input FIELD (#1798) — the window that replaced "(in a terminal)". Nothing typed here
        // is echoed back: only its length is reported.
        "input" | "passphrase" => {
            let masked = which == "passphrase";
            let outcome = confirmer.request_input(&InputPrompt {
                title: "DIG — Recovery phrase",
                heading: "Restore your DIG Account from its recovery phrase.",
                body: concat!(
                    "Type or paste all 24 words in order, separated by spaces. Capitals do not ",
                    "matter.\n\n",
                    "Use the words DIG gave you. A recovery phrase from a Chia wallet such as Sage ",
                    "is NOT a DIG recovery phrase — DIG would accept it and build a DIFFERENT, ",
                    "empty account from it."
                ),
                field_label: match masked {
                    true => "Passphrase:",
                    false => "Your 24 words:",
                },
                submit: "Continue",
                masked,
                revealable: !masked,
            });
            // `InputOutcome`'s Debug redacts the text by design, so this is safe to print.
            println!("{which}: {outcome:?}");
            return;
        }
        other => {
            eprintln!(
                "unknown window `{other}` — expected notice, claim, authorization, destroy, input or passphrase"
            );
            std::process::exit(2);
        }
    };

    println!("{which}: {decision:?}");
}
