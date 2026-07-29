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
//! `which` selects the window: `notice` (informational, one button), `claim` (the enrolment retention
//! either/or) or `authorization` (the reveal gate). Dismissing with Escape denies, so the `authorization`
//! case never reaches the biometric step and nothing is revealed.

use dig_app_core::confirm::{native_confirmer, ClaimPrompt, NoticePrompt, RevealPrompt};

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
        other => {
            eprintln!("unknown window `{other}` — expected notice, claim or authorization");
            std::process::exit(2);
        }
    };

    println!("{which}: {decision:?}");
}
