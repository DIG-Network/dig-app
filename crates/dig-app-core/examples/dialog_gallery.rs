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
//! | `qr` | the two-factor enrolment window WITH its scannable QR (dig_ecosystem#1849) — the one window
//!   whose correctness a screenshot cannot settle, since a camera has to read it |
//! | `authorization` | the reveal gate |
//! | `destroy` | the replace/remove authorization (dig_ecosystem#1799) |
//! | `input` | the native recovery-phrase FIELD (dig_ecosystem#1798) |
//! | `open` | the tray's "Open…" DIG-link field (dig_ecosystem#1821) — unmasked, a link is not secret |
//! | `passphrase` | the same field, masked |
//! | `bar` | the Alt+Space launcher bar (dig_ecosystem#1839) — the same field, frameless and centred high |
//! | `wallet-balance` | the wallet window with a balance that WAS read (dig_ecosystem#1850) |
//! | `wallet-no-node` | the same window with no chain source — the balance is unknown, not zero |
//! | `wallet-not-synced` | the same window with a source still catching up |
//! | `unopenable` | the wedged-legacy-account explainer (dig_ecosystem#1799) — the ONLY window that state
//!   offers, so its copy is checked by eye here as well as by its rendering test |
//!
//! Dismissing with Escape denies, so `authorization` and `destroy` never reach the biometric step and
//! nothing is revealed or destroyed — this example only ever DRAWS. The `input` cases print the LENGTH of
//! what was typed, never the text, so a screenshot session cannot leak a phrase into a terminal.

use dig_app_core::confirm::{
    native_confirmer, ClaimPrompt, DestroyPrompt, InputPrompt, InputStyle, NoticePrompt, QrArt,
    RevealPrompt,
};

/// Match the tray's DPI posture, so a screenshot taken here is what the user actually sees.
///
/// `dig-app` is per-monitor DPI-aware because tao sets that when it builds the tray, and that is what makes
/// the windows responsible for their own scaling (dig_ecosystem#1832). This example has no tao, so without
/// this call Windows DPI-virtualises it, `GetDpiForMonitor` reports 96, and the gallery would render the
/// 100% layout on a scaled display — a preview that quietly disagrees with the thing it previews, which is
/// worse than no preview.
/// # Photographing the 100% layout on a scaled display
///
/// Setting `DIG_GALLERY_DPI_UNAWARE=1` SKIPS this call, which is the only way to see the reference
/// (96 DPI) layout without owning a 96 DPI monitor: Windows then virtualises the process,
/// `GetDpiForMonitor` reports 96, and the window lays itself out exactly as it would at 100% — the
/// shell upscales the result for display, so the screenshot shows the right LAYOUT at the wrong
/// sharpness. That is a fair way to check proportions and a useless one for checking a QR's
/// scannability, so it is opt-in and named for what it does.
#[cfg(windows)]
fn match_the_trays_dpi_awareness() {
    if std::env::var("DIG_GALLERY_DPI_UNAWARE").is_ok_and(|v| v == "1") {
        eprintln!("DIG_GALLERY_DPI_UNAWARE=1 — rendering the 100% layout, upscaled by Windows");
        return;
    }
    // SAFETY: a documented, idempotent process-wide call with a constant argument; a failure (an older
    // Windows, or awareness already set) is reported by the return value and is harmless — the gallery then
    // renders exactly as it did before.
    unsafe {
        let _ = windows::Win32::UI::HiDpi::SetProcessDpiAwarenessContext(
            windows::Win32::UI::HiDpi::DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2,
        );
    }
}

/// A balance source that always answers with the same figures — enough to DRAW the read-balance window
/// without a node. It exists only for the gallery; nothing here reaches a chain.
struct FixedBalances(dig_app_core::wallet::overview::Balances);

impl dig_app_core::wallet::engine::WalletEngine for FixedBalances {
    fn broadcast(
        &self,
        _: dig_app_core::wallet::engine::BroadcastRequest,
    ) -> Result<dig_app_core::wallet::engine::BroadcastResponse, dig_app_core::wallet::WalletError>
    {
        unreachable!("the gallery never broadcasts")
    }

    fn coins(
        &self,
        _: dig_app_core::wallet::engine::CoinsRequest,
    ) -> Result<dig_app_core::wallet::engine::CoinsResponse, dig_app_core::wallet::WalletError>
    {
        unreachable!("the wallet window reads balances, not coins")
    }

    fn balance(
        &self,
        request: dig_app_core::wallet::engine::BalanceRequest,
    ) -> Result<dig_app_core::wallet::engine::BalanceResponse, dig_app_core::wallet::WalletError>
    {
        let balance = match request.asset {
            dig_app_core::wallet::state::Asset::Xch => self.0.xch_mojos,
            dig_app_core::wallet::state::Asset::Dig => self.0.dig_units,
        };
        Ok(dig_app_core::wallet::engine::BalanceResponse { balance })
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
        identifier: None,
        }),
        // The wallet window in the three states whose DIFFERENCE is the point (dig_ecosystem#1850): a
        // balance that was read, and two that were not. A screenshot is how "an unknown balance never
        // renders as a zero" is checked by eye as well as by its rendering tests — the failure being
        // guarded against is a person reading `0` and concluding their money is gone.
        "wallet-balance" | "wallet-no-node" | "wallet-not-synced" => {
            use dig_app_core::wallet::overview::{
                window_body, AddressReading, Balances, ChainSource, WalletOverview,
            };

            let address = AddressReading::Known(
                "xch1up0vfatgtwrcgcvc360jd57t3p2kjskncutvzakh9mhdmlvejj3shn8wln".to_string(),
            );
            // A read balance needs a source that answers; the gallery supplies a fixed one, because what
            // is being photographed is the WINDOW, not a chain read.
            let funded = FixedBalances(Balances {
                xch_mojos: 1_250_000_000_000,
                dig_units: 3_400_000_000_000,
            });
            let source = match which.as_str() {
                "wallet-balance" => ChainSource::Ready(&funded),
                "wallet-not-synced" => ChainSource::NotSynced,
                _ => ChainSource::Absent,
            };
            confirmer.show_notice(&NoticePrompt {
                title: "DIG — Wallet",
                heading: "This is your DIG wallet.",
                body: &window_body(&WalletOverview::read(address, &source)),
                acknowledge: "OK",
            identifier: None,
            })
        }
        // The enrolment retention claim: a genuine either/or where Cancel abandons setup.
        "claim" => confirmer.confirm_claim(&ClaimPrompt {
            title: "DIG — Confirm you saved it",
            heading: "Do you have your 24 words written down somewhere safe?",
            body: "If you continue without them and later lose this computer, your DIG Account, its \
                   address and everything sealed under it are gone for good. You can view the words \
                   again later from the DIG tray menu.",
            affirm: "Yes, I have them",
            decline: None,
            refusal_is_default: true,
            scannable: None,
        identifier: None,
        }),
        // The two-factor enrolment window (#1849). The URI below is a FIXED, PUBLISHED test vector —
        // RFC 4648's `JBSWY3DPEHPK3PXP...` — not a generated secret, so a photograph of this window,
        // and anything a camera reads off it, exposes nothing. The point of drawing it here is that a
        // QR is the one element whose correctness a screenshot cannot settle: it has to be SCANNED.
        "qr" => {
            // `concat!` rather than backslash line-continuations: this file has been bitten before by
            // a literal that acquired a hole mid-sentence, which no assertion could see and only a
            // photograph caught. A URI is worse than prose there — spaces would silently make it an
            // `otpauth://` string no authenticator can parse, in a square that still LOOKS like a QR.
            const DEMO_URI: &str = concat!(
                "otpauth://totp/DIG%20Network",
                "?secret=JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP",
                "&issuer=DIG%20Network&algorithm=SHA1&digits=6&period=30",
            );
            let art = QrArt::encode(DEMO_URI).expect("the demo URI encodes");
            confirmer.confirm_claim(&ClaimPrompt {
                title: "DIG — Add DIG to your authenticator",
                heading: "Add DIG to your authenticator app.",
                body: concat!(
                    "Scan the square below with your authenticator app.\n\n",
                    "Or add it by hand — choose to add an account by ENTERING A KEY, and type:\n\n",
                    "JBSW Y3DP EHPK 3PXP JBSW Y3DP EHPK 3PXP\n\n",
                    "Name it anything you like — DIG will appear as \"DIG Network\". If your app ",
                    "asks for settings, they are: time-based, 6 digits, 30 seconds.",
                ),
                affirm: "I've added it",
                decline: None,
                refusal_is_default: true,
                scannable: Some(&art),
            identifier: None,
            })
        }
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
