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
//! every launch — which is the failure that trains a person to dismiss dialogs without reading them.
//! The gate is [`WalletBirth::CreatedThisRun`] **and** a desktop session **and** a latch saying this
//! computer has not already said it. [`should_welcome`] is that decision, kept pure so all three
//! halves are testable without a window.
//!
//! # The node-side half does not exist yet
//!
//! dig-node does not report wallet provenance today. Rather than infer it — every available proxy
//! ("no profile yet", "uptime is small") is a guess that would fire on the wrong run — this module
//! carries an explicit [`WalletBirth::Unknown`] and shows **nothing** in that state. See
//! [`birth_reported_by_node`] for the exact field this expects and how to wire it.

use crate::confirm::{ConfirmDecision, NativeConfirmer, NoticePrompt};
use crate::form_factor::FormFactor;

use dig_node_control_interface::results::StatusResult;

/// Where the wallet the node is holding came from.
///
/// Three states and not a `bool`, because "the node did not tell us" is a real and currently
/// permanent answer that must not collapse into either "new" (which would show a false welcome) or
/// "established" (which would silently hide a true one once the node starts reporting).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WalletBirth {
    /// The node generated this wallet's seed during the run that is happening now.
    CreatedThisRun,
    /// The wallet was already on this computer when the node started.
    Established,
    /// The node does not report provenance, so nothing is known. See the module docs.
    Unknown,
}

impl WalletBirth {
    /// Interpret the node's own answer, where `None` means it did not answer at all.
    ///
    /// Split from [`birth_reported_by_node`] so the mapping is unit-tested today and the seam that
    /// currently cannot answer is the only thing that changes when dig-node#277 lands.
    pub fn from_node_report(created_this_run: Option<bool>) -> Self {
        match created_this_run {
            Some(true) => Self::CreatedThisRun,
            Some(false) => Self::Established,
            None => Self::Unknown,
        }
    }
}

/// What the connected node says about the provenance of the wallet it holds.
///
/// # This returns [`WalletBirth::Unknown`] on purpose, and that is not a stub to "fix" casually
///
/// The contract this wants is a single field on `control.status`:
///
/// ```text
/// StatusResult.wallet_created_this_run: bool
/// ```
///
/// `true` exactly when this process generated the seed during the current run — the auto-creation
/// path dig-node#277 is adding — and `false` on every run that found a seed already present. It must
/// describe the RUN, not the file: a field meaning "a wallet exists" is the precondition this module
/// explicitly rejects, because it is true forever afterwards.
///
/// Until `StatusResult` carries it, there is nothing here to read and no honest way to infer it, so
/// this answers `Unknown` and [`should_welcome`] draws nothing. An empty screen is the correct
/// not-yet-wired state; a guessed one would announce a new wallet to people who did not get one.
///
/// When the field lands, this function body becomes
/// `WalletBirth::from_node_report(Some(status.wallet_created_this_run))` and nothing else moves.
pub fn birth_reported_by_node(_status: &StatusResult) -> WalletBirth {
    WalletBirth::from_node_report(None)
}

/// The provenance to act on at start-up, where `None` means no node has answered yet.
///
/// A node that has not answered is not a node reporting an established wallet: at start-up the
/// engine may simply not have connected, and treating silence as `Established` would be a decision
/// taken by a timing accident. Both silences therefore land on [`WalletBirth::Unknown`], which shows
/// nothing.
pub fn birth_at_startup(status: Option<&StatusResult>) -> WalletBirth {
    match status {
        Some(status) => birth_reported_by_node(status),
        None => WalletBirth::Unknown,
    }
}

/// Whether to draw the welcome, given everything that decides it.
///
/// All three conditions are required, and each one is the answer to a way this has been got wrong:
/// `birth` because "a wallet exists" would fire forever, `form_factor` because a headless host has
/// no window to draw into, and `already_welcomed` because a notice that returns after a restart
/// reads as a bug.
pub fn should_welcome(
    birth: WalletBirth,
    form_factor: FormFactor,
    already_welcomed: bool,
) -> bool {
    matches!(birth, WalletBirth::CreatedThisRun) && form_factor.has_tray() && !already_welcomed
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
    /// The window title. Carries the greeting in full, because the title bar is the first thing read.
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
/// Returns the confirmer's decision so a caller can tell a drawn window from a headless host that
/// could not draw one — the latch is only worth setting when the window actually reached a person.
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

#[cfg(test)]
mod tests {
    use super::*;

    /// `Unknown` is the state the app is actually in until dig-node#277 lands, so it gets a named
    /// test rather than riding along in a table: shipping a welcome that fires on "we do not know"
    /// would announce a new wallet to every existing user on the first build that included it.
    #[test]
    fn an_unreported_provenance_shows_nothing() {
        assert!(!should_welcome(
            WalletBirth::Unknown,
            FormFactor::Tray,
            false
        ));
    }

    /// **The precondition test.** The fixture varies ONLY provenance: same desktop session, same
    /// un-latched computer. The nearest wrong implementation — gate on "a wallet exists", which is
    /// what makes this window appear on every launch — cannot tell `Established` from
    /// `CreatedThisRun`, so it returns `true` for both and fails here.
    #[test]
    fn only_a_wallet_created_this_run_is_welcomed() {
        assert!(should_welcome(
            WalletBirth::CreatedThisRun,
            FormFactor::Tray,
            false
        ));
        assert!(!should_welcome(
            WalletBirth::Established,
            FormFactor::Tray,
            false
        ));
    }

    /// The user asked for this on desktop devices. A headless host has no window to draw into, and
    /// `show_notice` there would return `Unavailable` — a latch set against a window nobody saw.
    #[test]
    fn a_headless_host_is_never_welcomed() {
        assert!(!should_welcome(
            WalletBirth::CreatedThisRun,
            FormFactor::Headless,
            false
        ));
    }

    /// The control for the latch, held against the one fixture that would otherwise show: a
    /// implementation that never reads the latch passes every other test in this module.
    #[test]
    fn a_computer_that_has_already_been_welcomed_is_not_welcomed_again() {
        assert!(!should_welcome(
            WalletBirth::CreatedThisRun,
            FormFactor::Tray,
            true
        ));
    }

    /// No node has answered yet, which is the ordinary state during start-up.
    #[test]
    fn a_silent_node_is_not_read_as_an_established_wallet() {
        assert_eq!(birth_at_startup(None), WalletBirth::Unknown);
    }

    /// **The "exactly once" test the ticket asks for, run across two launches over a REAL file.**
    ///
    /// # Why this round-trips `agent.json` instead of passing a bool twice
    ///
    /// The property under test is that the dismissal PERSISTS, and the nearest wrong implementation
    /// is not a bad boolean — it is a correct decision that is never written down. That version
    /// computes `already_welcomed` perfectly in memory and satisfies every other test in this module,
    /// because they all hand the latch in as an argument. Only a fixture that ends launch one by
    /// SAVING and begins launch two by LOADING can tell the two apart: delete the `save` below and
    /// this is the single test that fails.
    ///
    /// The provenance is held at `CreatedThisRun` for BOTH launches on purpose. A fixture that also
    /// flipped it to `Established` on the second launch would pass with no latch at all, since the
    /// provenance gate alone would suppress the second window — a false green that would prove
    /// nothing about persistence.
    #[test]
    fn the_welcome_is_shown_on_the_launch_that_made_the_wallet_and_never_again() {
        use crate::config::AgentConfig;

        let home = tempfile::tempdir().expect("a temp dir");
        let path = AgentConfig::path_in(home.path());

        // ---- Launch one: a fresh computer, and the node reports it just made the wallet.
        let mut first = AgentConfig::load(&path).expect("a missing config loads as default");
        assert!(
            should_welcome(WalletBirth::CreatedThisRun, FormFactor::Tray, first.wallet_welcomed),
            "the launch that created the wallet must show the welcome"
        );
        first.wallet_welcomed = true;
        first.save(&path).expect("the latch is written");

        // ---- Launch two: the same computer, the same provenance, a new process reading the file.
        let second = AgentConfig::load(&path).expect("the saved config loads");
        assert!(
            second.wallet_welcomed,
            "the latch must survive the restart, not merely the process"
        );
        assert!(
            !should_welcome(WalletBirth::CreatedThisRun, FormFactor::Tray, second.wallet_welcomed),
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

    #[test]
    fn the_node_report_maps_to_the_three_states() {
        assert_eq!(
            WalletBirth::from_node_report(Some(true)),
            WalletBirth::CreatedThisRun
        );
        assert_eq!(
            WalletBirth::from_node_report(Some(false)),
            WalletBirth::Established
        );
        assert_eq!(WalletBirth::from_node_report(None), WalletBirth::Unknown);
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
        for forbidden in ["backed up", "safe", "secure", "funded", "balance"] {
            assert!(
                !body.contains(forbidden),
                "the welcome must not claim {forbidden:?}: {body}"
            );
        }
        assert!(
            !body.contains("written down") && !body.contains("you have recorded"),
            "the welcome must not imply the phrase has been recorded: {body}"
        );
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
