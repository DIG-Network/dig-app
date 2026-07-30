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
//! | `open` | the tray's "Open…" DIG-link field (dig_ecosystem#1821) — unmasked, a link is not secret |
//! | `passphrase` | the same field, masked |
//! | `bar` | the Alt+Space launcher bar (dig_ecosystem#1839) — the same field, frameless and centred high |
//! | `unopenable` | the wedged-legacy-account explainer (dig_ecosystem#1799) — the ONLY window that state
//!   offers, so its copy is checked by eye here as well as by its rendering test |
//!
//! Dismissing with Escape denies, so `authorization` and `destroy` never reach the biometric step and
//! nothing is revealed or destroyed — this example only ever DRAWS. The `input` cases print the LENGTH of
//! what was typed, never the text, so a screenshot session cannot leak a phrase into a terminal.

use dig_app_core::confirm::{
    native_confirmer, ClaimPrompt, DestroyPrompt, InputPrompt, InputStyle, NoticePrompt,
    RevealPrompt,
};

/// Match the tray's DPI posture, so a screenshot taken here is what the user actually sees.
///
/// `dig-app` is per-monitor DPI-aware because tao sets that when it builds the tray, and that is what makes
/// the windows responsible for their own scaling (dig_ecosystem#1832). This example has no tao, so without
/// this call Windows DPI-virtualises it, `GetDpiForMonitor` reports 96, and the gallery would render the
/// 100% layout on a scaled display — a preview that quietly disagrees with the thing it previews, which is
/// worse than no preview.
#[cfg(windows)]
fn match_the_trays_dpi_awareness() {
    // SAFETY: a documented, idempotent process-wide call with a constant argument; a failure (an older
    // Windows, or awareness already set) is reported by the return value and is harmless — the gallery then
    // renders exactly as it did before.
    unsafe {
        let _ = windows::Win32::UI::HiDpi::SetProcessDpiAwarenessContext(
            windows::Win32::UI::HiDpi::DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2,
        );
    }
}

fn main() {
    #[cfg(windows)]
    match_the_trays_dpi_awareness();

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
        // The one window an account that cannot be opened offers. Drawn here because its copy previously
        // rendered with a ten-space hole mid-sentence, which no substring assertion could see.
        "unopenable" => dig_app_core::account::journey::explain_unopenable(confirmer.as_ref()),
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
                style: InputStyle::Dialog,
            });
            // `InputOutcome`'s Debug redacts the text by design, so this is safe to print.
            println!("{which}: {outcome:?}");
            return;
        }
        // The tray's "Open…" field (#1821). A DIG link is not secret, so unlike the phrase field it is
        // neither masked nor revealable — this case exists so the wording and layout of the window a user
        // actually meets can be LOOKED AT, which is the only way spacing and clipping are ever caught.
        "open" => {
            let outcome = confirmer.request_input(&InputPrompt {
                title: "DIG — Open",
                heading: "Which DIG link would you like to open?",
                body: concat!(
                    "Paste a DIG link. Both forms work:\n\n",
                    "chia://<store id>[:<generation root>]/<path>\n",
                    "urn:dig:chia:<store id>[:<generation root>]/<path>\n\n",
                    "It opens in your browser, served by your own DIG node."
                ),
                field_label: "DIG link:",
                submit: "Open",
                masked: false,
                revealable: false,
                style: InputStyle::Dialog,
            });
            println!("{which}: {outcome:?}");
            return;
        }
        // The Alt+Space launcher bar (#1839) — the SAME prompt as "open" above, presented as the
        // frameless bar. Having both in one gallery is what makes the two presentations comparable at a
        // glance, and it is how the bar gets photographed at each display scale without a global hotkey.
        "bar" => {
            let outcome = confirmer.request_input(&InputPrompt {
                title: "DIG",
                heading: "Open a DIG link",
                body: "Paste a chia:// or urn:dig:chia: link and press Enter. Esc closes this.",
                field_label: "DIG link:",
                submit: "Open",
                masked: false,
                revealable: false,
                style: InputStyle::Bar,
            });
            println!("{which}: {outcome:?}");
            return;
        }
        other => {
            eprintln!(
                "unknown window `{other}` — expected notice, claim, authorization, destroy, unopenable, input, passphrase, open or bar"
            );
            std::process::exit(2);
        }
    };

    println!("{which}: {decision:?}");
}
