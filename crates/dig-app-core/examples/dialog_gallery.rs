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
//! | `wallet-welcome` | the once-only greeting for a wallet the node made by itself
//!   (dig_ecosystem#3139) — the window whose whole claim is that it shows nothing private |
//! | `claim` | the enrolment retention either/or |
//! | `qr` | the two-factor enrolment window WITH its scannable QR (dig_ecosystem#1849) — the one window
//!   whose correctness a screenshot cannot settle, since a camera has to read it |
//! | `first-profile` | the zero-profile fund-and-create prompt (dig_ecosystem#2950) — the one window
//!   nobody can reach by clicking, since the state loop raises it on a schedule |
//! | `first-profile-ready` | the same prompt when the wallet holds enough — the OFFER whose affirming
//!   control spends real XCH (dig_ecosystem#2989) |
//! | `creating-submitted` | the identity submitted and nothing yet proven |
//! | `creating-did-confirmed` | the identity on chain, its store not yet launched |
//! | `creating-store-submitted` | the store submitted against a confirmed identity |
//! | `created` | the one success window, naming the evidence |
//! | `creation-stopped` | a creation that stopped with the money UNKNOWN — the window whose
//!   wording decides whether somebody pays twice |
//! | `creation-stopped-refused` | one refused at the start while another was already under way |
//! | `creation-stopped-spent` | one that stopped with both halves partly on chain |
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
        // Whatever this fixture was built holding, by asset — so a preview reads the same way the
        // application does rather than through a pair of arms that only know two tokens.
        let balance = self.0.of(request.asset);
        Ok(dig_app_core::wallet::engine::BalanceResponse {
            balance,
            as_of: dig_app_core::wallet::engine::BalanceAsOf::Replica {
                height: 7_000_000,
                caught_up: true,
            },
        })
    }
}

/// A [`WalletEngine`] double for a node whose chain view is still catching up, so the gallery can
/// photograph the "still syncing" window without a real node behind it.
struct SyncingNode;

impl dig_app_core::wallet::engine::WalletEngine for SyncingNode {
    fn broadcast(
        &self,
        _: dig_app_core::wallet::engine::BroadcastRequest,
    ) -> Result<dig_app_core::wallet::engine::BroadcastResponse, dig_app_core::wallet::WalletError>
    {
        unreachable!("the wallet window never broadcasts")
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
        _: dig_app_core::wallet::engine::BalanceRequest,
    ) -> Result<dig_app_core::wallet::engine::BalanceResponse, dig_app_core::wallet::WalletError>
    {
        Err(dig_app_core::wallet::WalletError::EngineNotSynced)
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
        // The welcome shown once when the node auto-created a wallet (dig_ecosystem#3139). Raised
        // from its own copy consts, so what is photographed here is what the shell draws — a gallery
        // case that retyped the words could go stale against the product without anything failing.
        "wallet-welcome" => {
            use dig_app_core::account::wallet_welcome::copy;

            confirmer.show_notice(&NoticePrompt {
                title: copy::TITLE,
                heading: copy::HEADING,
                body: copy::BODY,
                // The point of the picture: a welcome shows no address, no balance and no words.
                identifier: None,
                acknowledge: copy::ACKNOWLEDGE,
            })
        }
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
            let funded = FixedBalances(Balances::of_xch_and_dig(1_250_000_000_000, 3_400));
            // A node that answers "still catching up" — the reason now comes from what the node
            // says, not from a variant the caller picks (dig_ecosystem#2206).
            let syncing = SyncingNode;
            let source = match which.as_str() {
                "wallet-balance" => ChainSource::Ready(&funded),
                "wallet-not-synced" => ChainSource::Ready(&syncing),
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
        // The first-run DID wizard (dig_ecosystem#2341). ONE screen per invocation, so a capture
        // never needs a click driven at the window before it — and every screen is built by the
        // journey's own builder, so this photographs the product rather than a re-typed copy of it.
        //
        // ```text
        // cargo run -p dig-app-core --example dialog_gallery -- did fund
        // ```
        //
        // | screen | what it is |
        // |---|---|
        // | `fund` | the funding claim, with the scannable code and the address in mono |
        // | `offer` | the mint offer — the window that spends real XCH |
        // | `waiting` | the confirmation check-in, four minutes in |
        // | `waiting-offline` | the same check-in with the chain unreachable |
        // | `pending` | the mint that never confirmed |
        // | `rejected` | the mint the chain refused |
        // | `offline` | the watch that lost its connection |
        // | `confirmed` | the one success screen |
        "did" => {
            let screen = std::env::args().nth(2).unwrap_or_else(|| "fund".into());
            wizard::draw(confirmer.as_ref(), &screen);
            return;
        }
        // The zero-profile funding prompt (dig_ecosystem#2950) — the window the state loop raises,
        // by itself, once a day, on an account that has no profiles yet.
        //
        // Photographed here because it is the ONE window in the app nobody can reach by clicking:
        // raising it needs an unlocked account with zero profiles AND a node answering both mint
        // probes, which is not a state a person can arrange on demand. Without this arm the only
        // evidence it renders correctly would be its assertions, and an assertion cannot see a
        // sentence that wraps into an unreadable column or a cost that fell off the bottom.
        //
        // The address is a FIXED published-format example and the cost comes from
        // `first_profile_cost_mojos`, so what is photographed is the real arithmetic rather than a
        // number typed into a screenshot.
        "first-profile" => {
            use dig_app_core::account::first_profile::copy;
            use dig_app_core::account::first_profile::first_profile_claim;
            use dig_app_core::account::first_profile::first_profile_cost_mojos;

            const ADDRESS: &str =
                "xch1up0vfatgtwrcgcvc360jd57t3p2kjskncutvzakh9mhdmlvejj3shn8wln";
            // A wallet at zero profiles and zero funds: the shortfall IS the whole cost, which is
            // the state this window exists for.
            let cost = first_profile_cost_mojos();
            let body = copy::body(0, cost, cost);
            let scannable = QrArt::encode(ADDRESS);
            confirmer.confirm_claim(&first_profile_claim(ADDRESS, &body, scannable.as_ref()))
        }
        // The same prompt, when the wallet can now pay — the OFFER (dig_ecosystem#2989). This is the
        // one window in this gallery whose affirming control spends real XCH in production, so what
        // a photograph has to show is that the cost is legible and that a real decline stands beside
        // it. Drawn through `copy::create_offer`, the same builder the binary calls, so the controls
        // and the default answer are the product's rather than this file's.
        //
        // Answering it here reaches nothing: this example only ever DRAWS.
        "first-profile-ready" => {
            use dig_app_core::account::first_profile::copy;
            use dig_app_core::account::first_profile::first_profile_cost_mojos;

            let body = copy::ready_body(first_profile_cost_mojos());
            confirmer.confirm_claim(&copy::create_offer(&body))
        }
        // The creation itself, one window per state (dig_ecosystem#2989).
        //
        // These are photographed because they are the windows a person reads while their money is in
        // the air, and the two stopped ones carry the sentences that decide whether they start a
        // SECOND paid creation. Every body comes from `profile_creation::copy`, built from the plain
        // evidence values the production caller passes — the evidence types themselves have no
        // public producer, and adding one so a gallery could fake a confirmation would destroy the
        // property that a profile cannot be recorded without a chain read.
        "creating-submitted"
        | "creating-did-confirmed"
        | "creating-store-submitted"
        | "created"
        | "creation-stopped"
        | "creation-stopped-refused"
        | "creation-stopped-spent" => {
            use dig_app_core::account::profile_creation::{
                copy, ConfirmedProfile, CreationStep, Spent, Stopped,
            };

            // Full-length fixture ids, since how they wrap is part of what a screenshot checks.
            const DID: &str =
                "did:chia:1galleryfixturedid000000000000000000000000000000000000000000";
            const DID_COIN: &str =
                "0x9f2c41a7e5b8d03c6a1f7e94b2d8c05e3a7f61b9d4c28e07a5f3b1c9d6e024f80";
            const STORE: &str =
                "0x3b7d05e1c4a92680d5e3c1a7b94f062d8e15c30a7b9f42d68c05e1a3b7d94f0a";

            let profile = ConfirmedProfile {
                did: DID.to_owned(),
                did_coin_id: DID_COIN.to_owned(),
                did_confirmed_height: 5_412_009,
                store_launcher_id: STORE.to_owned(),
                store_confirmed_height: 5_412_013,
            };
            let stopped = |spent| Stopped {
                reached: Some(CreationStep::DidSubmitted {
                    did_coin_id: DID_COIN.to_owned(),
                }),
                spent,
                why: "chain unreachable: connection refused".to_owned(),
                may_be_forgotten: false,
            };

            let (heading, body) = match which.as_str() {
                "creating-submitted" => (
                    copy::RUNNING_HEADING,
                    copy::step_line(&CreationStep::DidSubmitted {
                        did_coin_id: DID_COIN.to_owned(),
                    }),
                ),
                "creating-did-confirmed" => (
                    copy::RUNNING_HEADING,
                    copy::step_line(&CreationStep::DidConfirmed {
                        did: DID.to_owned(),
                        did_coin_id: DID_COIN.to_owned(),
                        confirmed_height: 5_412_009,
                    }),
                ),
                "creating-store-submitted" => (
                    copy::RUNNING_HEADING,
                    copy::step_line(&CreationStep::StoreSubmitted {
                        did: DID.to_owned(),
                        store_launcher_id: STORE.to_owned(),
                    }),
                ),
                "created" => (copy::CREATED_HEADING, copy::created_body(&profile)),
                "creation-stopped" => (
                    copy::STOPPED_HEADING,
                    copy::stopped_body(&stopped(Spent::Unknown {
                        detail: "connection refused".to_owned(),
                    })),
                ),
                // The window a person reaches when `begin` itself was refused while a creation was
                // already under way (dig_ecosystem#2989). Nothing was reached, so the only thing on
                // screen is the money sentence — which is exactly why it is photographed: this is
                // the state that used to read "No money left your wallet" over a paid-for mint.
                "creation-stopped-refused" => (
                    copy::STOPPED_HEADING,
                    copy::stopped_body(&Stopped {
                        reached: None,
                        spent: Spent::Unknown {
                            detail: "DIG could not start this creation because one has already been started for this account, and that one may already have been paid for."
                                .to_owned(),
                        },
                        why: "a mint is already in progress there".to_owned(),
                        may_be_forgotten: false,
                    }),
                ),
                _ => (
                    copy::STOPPED_HEADING,
                    copy::stopped_body(&Stopped {
                        reached: Some(CreationStep::DidConfirmed {
                            did: DID.to_owned(),
                            did_coin_id: DID_COIN.to_owned(),
                            confirmed_height: 5_412_009,
                        }),
                        spent: Spent::Committed,
                        why: "chain unreachable: connection refused".to_owned(),
                        may_be_forgotten: false,
                    }),
                ),
            };
            let title = match which.as_str() {
                "created" => copy::CREATED_TITLE,
                "creation-stopped" | "creation-stopped-refused" | "creation-stopped-spent" => {
                    copy::STOPPED_TITLE
                }
                _ => copy::TITLE,
            };
            confirmer.show_notice(&NoticePrompt {
                title,
                heading,
                body: &body,
                acknowledge: "OK",
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
                "unknown window `{other}` — expected notice, claim, did, first-profile, first-profile-ready, creating-submitted, creating-did-confirmed, creating-store-submitted, created, creation-stopped, creation-stopped-refused, creation-stopped-spent, authorization, destroy, unopenable, input, passphrase, open or bar"
            );
            std::process::exit(2);
        }
    };

    println!("{which}: {decision:?}");
}

/// The fixtures the first-run wizard's funding step is drawn against, kept together so nothing
/// here can be mistaken for a production path: no chain is reached, no key is used, and no DID is
/// recorded.
///
/// The DID-only mint offer/wait/confirm screens this module used to also draw are retired
/// (dig-app#210): the funding step is the only screen of the old "did" gallery entry still shown
/// by a real build.
mod wizard {
    use dig_app_core::account::journey::funding_claim;
    use dig_app_core::confirm::{NativeConfirmer, QrArt};

    /// A mainnet-shaped receiving address, so the code and the mono line are photographed at the real
    /// length. It is a fixture, not anyone's address.
    const ADDRESS: &str = "xch1galleryfixtureaddress0000000000000000000000000000000000000000";

    /// Draw exactly the screen `which` names.
    pub fn draw(confirmer: &dyn NativeConfirmer, which: &str) {
        match which {
            "fund" => {
                let art = confirmer
                    .draws_qr()
                    .then(|| QrArt::encode(ADDRESS))
                    .flatten();
                let decision = confirmer.confirm_claim(&funding_claim(ADDRESS, art.as_ref()));
                println!("did fund: {decision:?}");
            }
            other => {
                eprintln!("unknown screen `{other}` — expected fund");
                std::process::exit(2);
            }
        }
    }
}
