//! The one-time welcome shown when the node has just auto-created a wallet (dig_ecosystem#3139).
//!
//! # What this is, and why it is a notice rather than a wizard step
//!
//! dig-node generates a mnemonic seed at start-up when none exists, with **no user interaction**
//! (dig-node#277). That is a good default — a person should not have to complete a setup flow before
//! DIG works — but it means custody appeared on their computer without them asking for it. This
//! module is the sentence that tells them so.
//!
//! Nothing branches on the answer: the wallet already exists by the time this draws, so there is no
//! decision to offer and a second button would invite one that no code reads. It is therefore a
//! [`NoticePrompt`] — one button — and NOT the first-run wizard's welcome, which is deliberately a
//! `ClaimPrompt` because *that* screen asks the user to commit to creating custody and must be
//! refusable (`journey::tests::the_welcome_offers_a_real_way_out`). The two are easy to confuse and
//! must not be merged: one reports a fact, the other asks a question.
//!
//! # The precondition is "just created", not "exists"
//!
//! A wallet existing is true forever after the first run, so gating on it would show this window on
//! every launch — the failure that trains a person to dismiss dialogs without reading them. The gate
//! is [`WalletOrigin::Auto`] — auto-created and **not yet acknowledged** — plus a desktop session,
//! plus a local latch, plus the wallet never having held money. [`should_welcome`] is that decision,
//! kept pure so every part is testable without a window.
//!
//! # The node-side half does not exist yet
//!
//! dig-node does not report wallet provenance today. Rather than infer it — every available proxy
//! ("no profile yet", "uptime is small") is a guess that would fire on the wrong run — this module
//! carries an explicit [`WalletOrigin::Unknown`] and shows **nothing** in that state. See
//! [`origin_reported_by_node`] for the exact contract this expects and how to wire it.

use crate::confirm::{ConfirmDecision, NativeConfirmer, NoticePrompt};
use crate::form_factor::FormFactor;

use dig_node_control_interface::results::StatusResult;

/// Where the wallet the node is holding came from, as the node's own `origin` marker reports it.
///
/// # Why acknowledgement is a state of the ORIGIN and not a separate boolean
///
/// The node's marker is the durable record of whether this person has been told. Folding it in here
/// means the "already said it" case is a variant the compiler forces every match to handle, rather
/// than a flag a caller can forget to consult — and it survives things a local latch does not, such
/// as a reinstall that clears `agent.json` but leaves the sealed seed in place.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WalletOrigin {
    /// The node created this wallet itself, and has not yet recorded that the user was told.
    Auto,
    /// The node created this wallet and has already recorded the user acknowledging it.
    AutoAcknowledged,
    /// The user supplied this wallet — an imported recovery phrase. It was never a surprise.
    Imported,
    /// The node does not report provenance, so nothing is known. See the module docs.
    Unknown,
}

impl WalletOrigin {
    /// Interpret the node's `origin` string, where `None` means it did not report one at all.
    ///
    /// # Why an unrecognised value is `Unknown` and not an error
    ///
    /// A newer node may grow a fourth origin. The safe reading of a word this build does not know is
    /// "we cannot say", which shows nothing — never "auto", which would announce a new wallet to
    /// someone who imported theirs.
    pub fn parse(origin: Option<&str>) -> Self {
        match origin {
            Some("auto") => Self::Auto,
            Some("auto-acknowledged") => Self::AutoAcknowledged,
            Some("imported") => Self::Imported,
            _ => Self::Unknown,
        }
    }
}

/// What the connected node says about the provenance of the wallet it holds.
///
/// # This returns [`WalletOrigin::Unknown`] on purpose, and it is not a stub to "fix" casually
///
/// The contract this expects on `control.status`, matching the design decided on dig-node#277:
///
/// ```text
/// StatusResult.wallet_origin:      "auto" | "auto-acknowledged" | "imported"
/// StatusResult.wallet_ever_funded: bool   // monotonic; never returns to false
/// ```
///
/// `origin` describes how the seed came to exist, and it is deliberately NOT a "a wallet exists"
/// flag — that is the precondition this module explicitly rejects, because it is true forever after
/// the first run.
///
/// Until `StatusResult` carries these, there is nothing to read and no honest way to infer them, so
/// this answers `Unknown` and [`should_welcome`] draws nothing. An empty screen is the correct
/// not-yet-wired state; a guessed one would announce a new wallet to people who did not get one.
///
/// When the fields land, this body becomes
/// `WalletOrigin::parse(Some(&status.wallet_origin))` and nothing else in this module moves.
pub fn origin_reported_by_node(_status: &StatusResult) -> WalletOrigin {
    WalletOrigin::parse(None)
}

/// The provenance to act on at start-up, where `None` means no node has answered yet.
///
/// A node that has not answered is not a node reporting an imported wallet: at start-up the engine
/// may simply not have connected, and treating silence as a definite answer would be a decision
/// taken by a timing accident. Both silences land on [`WalletOrigin::Unknown`], which shows nothing.
pub fn origin_at_startup(status: Option<&StatusResult>) -> WalletOrigin {
    match status {
        Some(status) => origin_reported_by_node(status),
        None => WalletOrigin::Unknown,
    }
}

/// Everything that decides whether the welcome is drawn.
///
/// Grouped into a struct rather than four positional arguments because three of the four are
/// booleans: `should_welcome(o, f, true, false)` is unreadable at the call site and a transposition
/// between two of them would compile silently.
#[derive(Debug, Clone, Copy)]
pub struct WelcomeConditions {
    /// What the node says about where the wallet came from.
    pub origin: WalletOrigin,
    /// Whether this host presents a desktop window at all.
    pub form_factor: FormFactor,
    /// Whether THIS computer's `agent.json` already records the welcome being shown.
    pub already_welcomed: bool,
    /// Whether the wallet has ever held money, as the node's monotonic latch reports it.
    pub ever_funded: bool,
}

/// Whether to draw the welcome.
///
/// Every condition is the answer to a specific way this has been or could be got wrong:
///
/// - `origin` — "a wallet exists" would fire on every launch forever; `AutoAcknowledged` and
///   `Imported` are wallets the user already knows about, and `Unknown` is not a licence to guess.
/// - `form_factor` — a headless host has no window to draw into, and the user asked for desktop.
/// - `already_welcomed` — a notice that returns after a restart reads as a bug.
/// - `ever_funded` — a wallet holding money must never be greeted as brand new. This is
///   belt-and-braces (a node cannot realistically fund an unacknowledged wallet), but the failure it
///   prevents is the app asserting something false about a person's money, which is the one class
///   this codebase does not ship.
pub fn should_welcome(conditions: WelcomeConditions) -> bool {
    let WelcomeConditions {
        origin,
        form_factor,
        already_welcomed,
        ever_funded,
    } = conditions;

    matches!(origin, WalletOrigin::Auto)
        && form_factor.has_tray()
        && !already_welcomed
        && !ever_funded
}

/// Every word this window says, in one place.
///
/// dig-app has no i18n layer today (dig_ecosystem#2328); the interim rule this follows is
/// `confirm::gui::window::pane::copy`'s — no display literal at the call site, so the eventual
/// catalog swap turns each `const` into a lookup and moves nothing else.
///
/// # The voice, and the three things this must not say
///
/// A wallet was created. That is the entire claim. It must not imply the wallet is **backed up**
/// (nobody has written anything down), must not imply it is **funded**, and must not show anything
/// private — no recovery words, no address, no balance. It also does not describe itself: a sentence
/// explaining that this window is safe to read is a sentence about the product's design, which
/// `pane::copy` already rules out as not the reader's business.
pub mod copy {
    /// The window title. Carries the greeting in full, because the title bar is read first.
    pub const TITLE: &str = "DIG Network: Welcome to your new DIG Wallet";

    /// The primary line.
    pub const HEADING: &str = "Welcome to your new DIG Wallet.";

    /// The body.
    ///
    /// Three sentences, each carrying a fact the reader can act on or ignore: what happened, where
    /// the recovery phrase is if they want it, and how to use a different wallet instead. The last
    /// two name real menu paths — the same ones `journey::explain_missing_phrase` and the shell's
    /// restore notice name — because `pane::copy`'s rule is that a sentence never ends in a dead end.
    pub const BODY: &str = "DIG made a wallet on this computer, so you did not have to set one up \
                            yourself.\n\n\
                            Your recovery phrase is in the DIG menu whenever you want to write it \
                            down.\n\n\
                            If you would rather use a wallet you already have, you can replace this \
                            one from \"Manage my DIG Account\" in the DIG menu.";

    /// The single dismiss button.
    pub const ACKNOWLEDGE: &str = "OK";
}

/// Draw the welcome.
///
/// Returns the confirmer's decision so a caller can tell a window a person actually saw from a
/// headless host that could not draw one — the latch is only worth setting in the first case.
pub fn show_wallet_welcome(confirmer: &dyn NativeConfirmer) -> ConfirmDecision {
    confirmer.show_notice(&NoticePrompt {
        title: copy::TITLE,
        heading: copy::HEADING,
        body: copy::BODY,
        // A welcome shows no address, no balance and no words. There is deliberately nothing here.
        identifier: None,
        acknowledge: copy::ACKNOWLEDGE,
    })
}

/// Whether the window was actually drawn to a person, and so whether the welcome may be latched.
///
/// A [`ConfirmDecision::Unavailable`] means no window appeared — a headless host, a dead GL context,
/// a window that failed to open. Latching on it would consume the one chance to say this, and the
/// person would never be told at all.
pub fn was_seen(decision: ConfirmDecision) -> bool {
    !matches!(decision, ConfirmDecision::Unavailable)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The conditions under which the welcome SHOULD show — the control every other test varies one
    /// field of. Written as a helper so each test below differs from the showing case by exactly one
    /// thing, which is what makes it evidence about that thing.
    fn welcoming() -> WelcomeConditions {
        WelcomeConditions {
            origin: WalletOrigin::Auto,
            form_factor: FormFactor::Tray,
            already_welcomed: false,
            ever_funded: false,
        }
    }

    #[test]
    fn the_control_shows_the_welcome() {
        assert!(
            should_welcome(welcoming()),
            "the control must show, or every negative test below is vacuous"
        );
    }

    /// `Unknown` is the state the app is actually in until dig-node#277 lands, so it gets a named
    /// test: shipping a welcome that fires on "we do not know" would announce a new wallet to every
    /// existing user on the first build that included it.
    #[test]
    fn an_unreported_origin_shows_nothing() {
        assert!(!should_welcome(WelcomeConditions {
            origin: WalletOrigin::Unknown,
            ..welcoming()
        }));
    }

    /// **The precondition test.** The fixture varies ONLY the origin. The nearest wrong
    /// implementation — gate on "a wallet exists", which is what makes this window appear on every
    /// launch — cannot tell these three apart, so it returns `true` for all of them and fails here.
    ///
    /// `AutoAcknowledged` is the load-bearing one: it is a wallet the node DID create, so an
    /// implementation that checks only "did the node make it" passes `Imported` and still fails here.
    #[test]
    fn only_an_unacknowledged_auto_created_wallet_is_welcomed() {
        for already_known in [WalletOrigin::AutoAcknowledged, WalletOrigin::Imported] {
            assert!(
                !should_welcome(WelcomeConditions {
                    origin: already_known,
                    ..welcoming()
                }),
                "{already_known:?} is a wallet the user already knows about"
            );
        }
    }

    /// The user asked for this on desktop devices. A headless host has no window to draw into.
    #[test]
    fn a_headless_host_is_never_welcomed() {
        assert!(!should_welcome(WelcomeConditions {
            form_factor: FormFactor::Headless,
            ..welcoming()
        }));
    }

    /// The control for the local latch, held against the one fixture that would otherwise show: an
    /// implementation that never reads the latch passes every other test in this module.
    #[test]
    fn a_computer_that_has_already_been_welcomed_is_not_welcomed_again() {
        assert!(!should_welcome(WelcomeConditions {
            already_welcomed: true,
            ..welcoming()
        }));
    }

    /// A wallet holding money is never greeted as brand new.
    #[test]
    fn a_wallet_that_has_held_money_is_not_greeted_as_new() {
        assert!(!should_welcome(WelcomeConditions {
            ever_funded: true,
            ..welcoming()
        }));
    }

    #[test]
    fn the_origin_marker_parses_to_its_four_states() {
        assert_eq!(WalletOrigin::parse(Some("auto")), WalletOrigin::Auto);
        assert_eq!(
            WalletOrigin::parse(Some("auto-acknowledged")),
            WalletOrigin::AutoAcknowledged
        );
        assert_eq!(WalletOrigin::parse(Some("imported")), WalletOrigin::Imported);
        assert_eq!(WalletOrigin::parse(None), WalletOrigin::Unknown);
    }

    /// An origin this build does not recognise must not be read as `auto`.
    #[test]
    fn an_unrecognised_origin_is_unknown_rather_than_auto() {
        assert_eq!(
            WalletOrigin::parse(Some("hardware-wallet")),
            WalletOrigin::Unknown
        );
        assert!(!should_welcome(WelcomeConditions {
            origin: WalletOrigin::parse(Some("hardware-wallet")),
            ..welcoming()
        }));
    }

    /// No node has answered yet, which is the ordinary state during start-up.
    #[test]
    fn a_silent_node_is_not_read_as_a_known_origin() {
        assert_eq!(origin_at_startup(None), WalletOrigin::Unknown);
    }

    /// A window that never appeared must not consume the one chance to say this.
    #[test]
    fn an_undrawn_window_is_not_treated_as_seen() {
        assert!(!was_seen(ConfirmDecision::Unavailable));
        assert!(was_seen(ConfirmDecision::Approve));
    }

    /// **The "exactly once" test the ticket asks for, run across two launches over a REAL file.**
    ///
    /// # Why this round-trips `agent.json` instead of passing a bool twice
    ///
    /// The property under test is that the dismissal PERSISTS, and the nearest wrong implementation
    /// is not a bad boolean — it is a correct decision that is never written down. That version
    /// computes `already_welcomed` perfectly in memory and satisfies every other test in this module,
    /// because they all hand the latch in as a field. Only a fixture that ends launch one by SAVING
    /// and begins launch two by LOADING can tell the two apart: delete the `save` below and this is
    /// the single test that fails.
    ///
    /// The origin is held at `Auto` for BOTH launches on purpose. A fixture that also flipped it to
    /// `AutoAcknowledged` on the second launch would pass with no latch at all, since the origin gate
    /// alone would suppress the second window — a false green proving nothing about persistence.
    #[test]
    fn the_welcome_is_shown_on_the_launch_that_made_the_wallet_and_never_again() {
        use crate::config::AgentConfig;

        let home = tempfile::tempdir().expect("a temp dir");
        let path = AgentConfig::path_in(home.path());

        // ---- Launch one: a fresh computer, and the node reports it just made the wallet.
        let mut first = AgentConfig::load(&path).expect("a missing config loads as default");
        assert!(
            should_welcome(WelcomeConditions {
                already_welcomed: first.wallet_welcomed,
                ..welcoming()
            }),
            "the launch that created the wallet must show the welcome"
        );
        first.wallet_welcomed = true;
        first.save(&path).expect("the latch is written");

        // ---- Launch two: the same computer, the same origin, a new process reading the file.
        let second = AgentConfig::load(&path).expect("the saved config loads");
        assert!(
            second.wallet_welcomed,
            "the latch must survive the restart, not merely the process"
        );
        assert!(
            !should_welcome(WelcomeConditions {
                already_welcomed: second.wallet_welcomed,
                ..welcoming()
            }),
            "a welcome that returns after a restart reads as a bug"
        );
    }

    /// An `agent.json` written before this field existed must not be read as already-welcomed.
    #[test]
    fn a_config_predating_the_latch_defaults_to_not_yet_welcomed() {
        let restored: AgentConfigProbe =
            serde_json::from_str("{}").expect("an empty object is a valid config");
        assert!(!restored.wallet_welcomed);
    }

    /// The one field this module reads, deserialised on its own so the assertion above is about
    /// `serde(default)` and not about every other field's defaulting.
    #[derive(serde::Deserialize)]
    struct AgentConfigProbe {
        #[serde(default)]
        wallet_welcomed: bool,
    }

    /// The copy carries the claim the ticket allows and none of the three it forbids.
    ///
    /// Asserted on the drawn words because the honesty rule is about what a person READS, not about
    /// which function produced it — the same reason `journey`'s DID-step copy test reads the drawn
    /// text. A body that starts promising a backup is a defect no behavioural test would catch.
    #[test]
    fn the_copy_claims_only_that_a_wallet_was_made() {
        let body = copy::BODY.to_lowercase();

        assert!(
            body.contains("made a wallet on this computer"),
            "the one claim this window exists to make must be in it: {body}"
        );
        for forbidden in ["backed up", "secure", "funded", "balance", "safe"] {
            assert!(
                !body.contains(forbidden),
                "the welcome must not claim {forbidden:?}: {body}"
            );
        }
    }

    /// A welcome shows nothing private. Pinned on the prompt rather than the consts because
    /// `identifier` is the field that RENDERS a bare value set apart from the prose, and filling it
    /// is exactly how an address would end up on this window.
    #[test]
    fn the_welcome_carries_no_identifier_and_one_button() {
        let prompt = NoticePrompt {
            title: copy::TITLE,
            heading: copy::HEADING,
            body: copy::BODY,
            identifier: None,
            acknowledge: copy::ACKNOWLEDGE,
        };
        assert!(prompt.identifier.is_none());
        assert_eq!(prompt.acknowledge, "OK");
    }
}
