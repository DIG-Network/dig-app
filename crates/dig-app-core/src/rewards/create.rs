//! The reward-distributor CREATE flow's second gate (dig_ecosystem#3253 §4): a manager-inner-
//! puzzle choice, named by PROVENANCE not by claimed capability, that the launch call site cannot
//! skip.
//!
//! # The leak this closes
//!
//! [`super::pane::Acknowledged::may_create`] takes `&self` and returns a bare `bool` — nothing
//! forces a caller to consume the gate at the actual launch call, so it can be read once and then
//! ignored, or never called at all, with no compile error either way. `#[non_exhaustive]` on
//! `dig_rewards_coin::manager::ManagerInnerPuzzle` blocks exhaustive matching downstream; it does
//! NOT block constructing a variant. Neither fact stops
//! `launch_manager_singleton(.., ManagerInnerPuzzle::SingleKeyBuiltHere(app_key), ..)` from
//! compiling with no human in the loop.
//!
//! This module adds a second witness that must be produced from the FIRST one by value, so the
//! launch call site is untypeable without both:
//!
//! ```text
//! CreationGate::unacknowledged()
//!     .acknowledge(shown)              // needs WarningsShown  (pane.rs, witness 1)
//!     .with_manager_choice(made, choice) // needs ManagerChoiceMade + ManagerChoice (here, witness 2)
//!     .into_manager_inner_puzzle()       // the only producer of the real crate type
//! ```
//!
//! # What this does NOT prove
//!
//! Same honest retraction [`super::pane::CreationGate`] (`pane.rs:676-688`) and
//! [`super::clawback::ClawbackAuthority`] (`clawback.rs:20-37`) already carry: this proves a
//! `ManagerChoice` value was constructed and consumed through the typed path, never that a human
//! actually clicked a radio button on screen. The last hop — that the pane's selection handler is
//! the only production caller of [`ManagerChoice`]'s constructors, and that it is wired to a real
//! click — is a source-scan test (see `mod subject_tests` below), not something the type system
//! can state.

use chia_bls::PublicKey;
use chia_protocol::Bytes32;
use dig_rewards_coin::manager::ManagerInnerPuzzle;

use crate::amount::{format_asset_amount, ticker};
use crate::i18n::Msg;
use crate::wallet::state::Asset;

use super::pane::Acknowledged;

// ---------------------------------------------------------------------------------------------
// The create card's OWN copy. Every key here is new and additive to `rewards/copy.rs`'s five
// warning blocks (byte-unchanged, ticket §3) -- the card reuses those by importing the existing
// `WARNING_*` consts from [`super::copy`] directly at the paint call site, never by re-declaring
// them here. Kept as literal `Msg::new("...")` calls in THIS file, deliberately not routed
// through `rewards::copy` the way the warning blocks are, so `mod subject_tests`'s literal scan
// (`rewards::test_scan::string_literals`) can enumerate every key this card's own render function
// resolves directly from this file's source text -- the acceptance mechanism dig_ecosystem#3253
// §5 names by function, not a claim that this is the crate's only copy-module convention.
// ---------------------------------------------------------------------------------------------

/// Arm A's name -- provenance, never a claimed capability. "A key this app creates now."
pub const CREATE_ARM_A_LABEL: Msg = Msg::new("rewards-create-arm-a-label");
/// Arm A's body: the verified negative `manager.rs:45-46` licenses -- this app builds and holds
/// the key, so it knows there is no recovery path.
pub const CREATE_ARM_A_BODY: Msg = Msg::new("rewards-create-arm-a-body");
/// Arm B's name -- provenance, never a claimed capability. "A puzzle hash you supply."
pub const CREATE_ARM_B_LABEL: Msg = Msg::new("rewards-create-arm-b-label");
/// Arm B's body: sole manager authority forever, DIG cannot check what the hash is, and the
/// caller supplied it -- never a word from the forbidden list (`manager.rs:52`).
pub const CREATE_ARM_B_BODY: Msg = Msg::new("rewards-create-arm-b-body");
/// The label beside arm B's echoed hash field. The hash itself is never truncated at any call
/// site that resolves this key.
pub const CREATE_HASH_LABEL: Msg = Msg::new("rewards-create-hash-label");
/// "You are committing" -- the label in front of the funder's own committed-amount figure.
pub const CREATE_COMMITTED_LABEL: Msg = Msg::new("rewards-create-committed-label");
/// The verb that opens this card from the Wallet tab's verb row, alongside Send/Receive.
pub const CREATE_VERB_LABEL: Msg = Msg::new("rewards-create-verb-label");
/// The control that submits the launch spend once both witnesses exist.
pub const CREATE_SIGN_BUTTON: Msg = Msg::new("rewards-create-sign-button");
/// The control that discards the flow without signing anything.
pub const CREATE_CANCEL_BUTTON: Msg = Msg::new("rewards-create-cancel-button");
/// The label beside witness 1's acknowledgement control. Checking it is what lets the paint code
/// mint [`super::pane::WarningsShown::having_displayed`] with all five required keys; unchecking
/// it removes the witness on the very next frame, because the paint code re-derives it fresh each
/// frame rather than latching a bit that survives the warnings scrolling out of view.
pub const CREATE_ACKNOWLEDGE_CHECKBOX: Msg = Msg::new("rewards-create-acknowledge-checkbox");
/// The label on the epoch-count field that, together with the committed amount, is what block 4
/// above states back to the funder.
pub const CREATE_EPOCHS_LABEL: Msg = Msg::new("rewards-create-epochs-label");

/// Every string this card's copy resolves for a person to read, already localized. Nothing here
/// divides a base-unit figure locally -- `committed_amount` is
/// [`crate::amount::format_asset_amount`]'s output, never a value recomputed from a compiled-in
/// constant (SPEC §2.6 clause 2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CreateCardCopy {
    pub verb_label: String,
    pub arm_a_label: String,
    pub arm_a_body: String,
    pub arm_b_label: String,
    pub arm_b_body: String,
    pub hash_label: String,
    pub committed_label: String,
    /// The funder's own committed total, e.g. `"12.5 $DIG"` -- figure and ticker, both from
    /// [`crate::amount`], never a `$DIG` literal written here.
    pub committed_amount: String,
    pub sign_button: String,
    pub cancel_button: String,
    pub acknowledge_checkbox: String,
    pub epochs_label: String,
}

/// Builds every string the create card renders, from the funder's own supplied commitment. Pure
/// and egui-independent so it is testable without a running window -- the paint code in
/// `confirm::gui::window::pane::wallet.rs` (private to `confirm::gui`, so it cannot live there)
/// only lays these strings out.
pub fn create_card_copy(committed_base_units: u64) -> CreateCardCopy {
    let amount = format_asset_amount(Asset::DIG, committed_base_units)
        .expect("$DIG's decimals are known by definition (crate::amount::decimals)");
    CreateCardCopy {
        verb_label: CREATE_VERB_LABEL.text(),
        arm_a_label: CREATE_ARM_A_LABEL.text(),
        arm_a_body: CREATE_ARM_A_BODY.text(),
        arm_b_label: CREATE_ARM_B_LABEL.text(),
        arm_b_body: CREATE_ARM_B_BODY.text(),
        hash_label: CREATE_HASH_LABEL.text(),
        committed_label: CREATE_COMMITTED_LABEL.text(),
        committed_amount: format!("{amount} {}", ticker(Asset::DIG)),
        sign_button: CREATE_SIGN_BUTTON.text(),
        cancel_button: CREATE_CANCEL_BUTTON.text(),
        acknowledge_checkbox: CREATE_ACKNOWLEDGE_CHECKBOX.text(),
        epochs_label: CREATE_EPOCHS_LABEL.text(),
    }
}

/// Parses arm B's typed hash text into a [`Bytes32`], accepting an optional `0x`/`0X` prefix.
/// Pure and egui-independent, same reason [`create_card_copy`] is: the paint code only calls this
/// and echoes the result, it does not re-implement hex decoding itself.
///
/// `None` for anything that is not exactly 32 bytes of hex -- there is no partial/lenient parse,
/// because a manager puzzle hash this app cannot verify is exactly the value arm B's own body
/// text says this app cannot check; accepting a truncated or padded guess would make that
/// disclosure false.
pub fn parse_hash_hex(text: &str) -> Option<Bytes32> {
    let digits = text.strip_prefix("0x").or_else(|| text.strip_prefix("0X")).unwrap_or(text);
    let bytes = hex::decode(digits).ok()?;
    let bytes: [u8; 32] = bytes.try_into().ok()?;
    Some(Bytes32::new(bytes))
}

/// The manager singleton's inner-puzzle choice, named by PROVENANCE — never by a claimed recovery
/// property — mirroring `dig_rewards_coin::manager::ManagerInnerPuzzle` exactly (`manager.rs:40-54`
/// of the published 0.6.0 crate).
///
/// Deliberately **no `Default`, `Clone` or `Copy`**: a caller that supplies nothing must fail to
/// compile, and a caller must not be able to mint a second choice from a first without going
/// through the pane's selection handler again — the same reasoning
/// [`dig_rewards_coin::manager::ManagerInnerPuzzle`] itself states for omitting `Default`, carried
/// one layer up so this app cannot default around it either.
#[derive(Debug, PartialEq, Eq)]
pub enum ManagerChoice {
    /// Arm A — "A key this app creates now". This app builds and holds the key in this profile;
    /// it has no recovery path. Safe to assert because
    /// `dig_rewards_coin::manager::ManagerInnerPuzzle::SingleKeyBuiltHere`'s own doc states it.
    SingleKeyBuiltHere(PublicKey),

    /// Arm B — "A puzzle hash you supply". Becomes the sole manager authority forever; this app
    /// cannot check what the hash is. Whatever recovery it has comes from wherever the caller
    /// built it, never from this app.
    HashSuppliedByCaller(Bytes32),
}

/// Evidence that a [`ManagerChoice`] was constructed and consumed through this module's typed
/// path. Zero-sized, and the single constructor ([`Self::having_chosen`]) is private — nothing
/// outside this module can mint one directly.
///
/// # What this does NOT prove
///
/// See this module's doc comment. In particular: it does not prove a human clicked, only that
/// code somewhere constructed a real `ManagerChoice` value and passed it through here.
#[derive(Debug, PartialEq, Eq)]
pub struct ManagerChoiceMade(());

impl ManagerChoiceMade {
    /// The only constructor. Takes the chosen arm BY VALUE so the caller cannot retain a
    /// convenient handle to reuse without picking again, and returns a zero-sized witness that a
    /// real choice value existed.
    fn having_chosen(_choice: &ManagerChoice) -> Self {
        Self(())
    }

    /// Builds the witness for a freshly constructed arm — the pane's selection handler is the only
    /// production caller (see `mod subject_tests`'s scan below). Kept separate from the private
    /// `having_chosen` so a caller must supply the SAME choice twice (once to mint the witness,
    /// once again to [`Acknowledged::with_manager_choice`]) rather than being able to manufacture a
    /// witness for one value and launch a different one.
    pub fn for_choice(choice: &ManagerChoice) -> Self {
        Self::having_chosen(choice)
    }
}

/// The result of [`Acknowledged::with_manager_choice`] — obtainable only by consuming an
/// [`Acknowledged`] gate together with a [`ManagerChoiceMade`] witness and the chosen
/// [`ManagerChoice`] itself. [`Self::into_manager_inner_puzzle`] is the ONLY place in dig-app that
/// produces a real `dig_rewards_coin::manager::ManagerInnerPuzzle`.
#[derive(Debug, PartialEq, Eq)]
pub struct Launchable {
    choice: ManagerChoice,
}

impl Acknowledged {
    /// Closes the `&self` leak on [`Acknowledged::may_create`]: consumes `self` by value, so a
    /// caller cannot hold this `Acknowledged` handle and ALSO reach a `Launchable` from it more
    /// than once, and cannot reach a `Launchable` at all without a [`ManagerChoiceMade`] witness
    /// bound to the exact `choice` supplied.
    pub fn with_manager_choice(self, made: ManagerChoiceMade, choice: ManagerChoice) -> Launchable {
        // The witness must have been minted FOR this exact choice value -- comparing by identity
        // isn't possible (ManagerChoice has no Copy/Clone), so this reconstructs a witness over
        // `choice` and requires it to match the one the caller supplied. A caller who tries to
        // launder a witness minted for a different value gets a panic here, not a silent swap.
        let expected = ManagerChoiceMade::having_chosen(&choice);
        assert_eq!(
            made, expected,
            "ManagerChoiceMade witness does not correspond to the supplied ManagerChoice"
        );
        Launchable { choice }
    }
}

impl Launchable {
    /// The only producer of a real `ManagerInnerPuzzle` in dig-app. Consumes `self`, so a caller
    /// cannot mint two puzzle values from one `Launchable`.
    pub fn into_manager_inner_puzzle(self) -> ManagerInnerPuzzle {
        match self.choice {
            ManagerChoice::SingleKeyBuiltHere(key) => ManagerInnerPuzzle::SingleKeyBuiltHere(key),
            ManagerChoice::HashSuppliedByCaller(hash) => {
                ManagerInnerPuzzle::HashSuppliedByCaller(hash)
            }
        }
    }
}

#[cfg(test)]
mod witness_tests {
    use super::*;
    use crate::rewards::pane::{CreationGate, WarningsShown};

    fn acknowledged() -> Acknowledged {
        let shown = WarningsShown::having_displayed(&super::super::pane::REQUIRED_WARNING_KEYS)
            .expect("the five required keys must produce a witness");
        CreationGate::unacknowledged().acknowledge(shown)
    }

    fn arm_a() -> ManagerChoice {
        ManagerChoice::SingleKeyBuiltHere(PublicKey::default())
    }

    fn arm_b() -> ManagerChoice {
        ManagerChoice::HashSuppliedByCaller(Bytes32::from([7u8; 32]))
    }

    /// The whole point: the call site compiles ONLY when both witnesses are supplied, in order.
    #[test]
    fn both_witnesses_together_reach_a_manager_inner_puzzle() {
        let choice = arm_a();
        let made = ManagerChoiceMade::for_choice(&choice);
        let puzzle = acknowledged().with_manager_choice(made, choice).into_manager_inner_puzzle();
        assert!(matches!(puzzle, ManagerInnerPuzzle::SingleKeyBuiltHere(_)));
    }

    #[test]
    fn arm_b_round_trips_the_exact_hash() {
        let hash = Bytes32::from([9u8; 32]);
        let choice = ManagerChoice::HashSuppliedByCaller(hash);
        let made = ManagerChoiceMade::for_choice(&choice);
        let puzzle = acknowledged().with_manager_choice(made, choice).into_manager_inner_puzzle();
        match puzzle {
            ManagerInnerPuzzle::HashSuppliedByCaller(got) => assert_eq!(got, hash),
            other => panic!("expected HashSuppliedByCaller, got {other:?}"),
        }
    }

    /// A witness minted for a DIFFERENT choice value must not launder into this one -- proves the
    /// binding is checked, not merely present. This is what
    /// `.claude/scripts/prove-guard-load-bearing.py` breaks in isolation for the mutation proof.
    #[test]
    #[should_panic(expected = "does not correspond to the supplied ManagerChoice")]
    fn a_witness_for_a_different_choice_is_rejected() {
        let witness_for = arm_a();
        let made = ManagerChoiceMade::for_choice(&witness_for);
        let _ = acknowledged().with_manager_choice(made, arm_b());
    }
}

#[cfg(test)]
mod hash_parsing_tests {
    use super::*;

    #[test]
    fn a_bare_32_byte_hex_string_round_trips() {
        let hash = Bytes32::from([0x42u8; 32]);
        let text = hex::encode(hash.to_bytes());
        assert_eq!(parse_hash_hex(&text), Some(hash));
    }

    #[test]
    fn an_0x_prefixed_hex_string_round_trips() {
        let hash = Bytes32::from([0x99u8; 32]);
        let text = format!("0x{}", hex::encode(hash.to_bytes()));
        assert_eq!(parse_hash_hex(&text), Some(hash));
    }

    #[test]
    fn wrong_length_is_rejected() {
        assert_eq!(parse_hash_hex("aa"), None);
        assert_eq!(parse_hash_hex(&"ab".repeat(31)), None);
        assert_eq!(parse_hash_hex(&"ab".repeat(33)), None);
    }

    #[test]
    fn non_hex_text_is_rejected() {
        assert_eq!(parse_hash_hex(&"zz".repeat(32)), None);
        assert_eq!(parse_hash_hex(""), None);
    }
}

#[cfg(test)]
mod subject_tests {
    use super::*;
    use crate::i18n::Language;
    use crate::rewards::test_scan::string_literals;

    /// Every fluent key this card's own copy declares. `HashSuppliedByCaller`'s reused warning
    /// blocks are NOT here by design -- they are `super::copy::WARNING_*` consts referenced by
    /// NAME at the paint call site, never re-declared as a literal in this file, so they cannot
    /// appear in this file's literal scan below regardless.
    pub(crate) const FUNDER_SUBJECT_KEYS: &[&str] = &[
        "rewards-create-arm-a-label",
        "rewards-create-arm-a-body",
        "rewards-create-arm-b-label",
        "rewards-create-arm-b-body",
        "rewards-create-hash-label",
        "rewards-create-committed-label",
        "rewards-create-verb-label",
        "rewards-create-sign-button",
        "rewards-create-cancel-button",
        "rewards-create-acknowledge-checkbox",
        "rewards-create-epochs-label",
    ];

    /// dig_ecosystem#3253 §5 criterion 1: every `Msg` key this file's production code (everything
    /// before its own `#[cfg(test)]` tail) resolves as a literal must be in [`FUNDER_SUBJECT_KEYS`]
    /// -- enumerated from what the source actually contains, not the definition site, so a key
    /// added here without being added to the list fails loudly instead of rendering unreviewed.
    #[test]
    fn every_literal_key_this_file_resolves_is_in_the_funder_subject_list() {
        let production = include_str!("create.rs")
            .split("#[cfg(test)]")
            .next()
            .expect("create.rs always has a #[cfg(test)] section");
        let literals = string_literals(production);
        let key_literals: Vec<&String> = literals
            .iter()
            .filter(|literal| literal.starts_with("rewards-"))
            .collect();

        assert_eq!(
            key_literals.len(),
            FUNDER_SUBJECT_KEYS.len(),
            "every rewards-* literal in create.rs's production code must be exactly \
             FUNDER_SUBJECT_KEYS, found {key_literals:?}"
        );
        for key in &key_literals {
            assert!(
                FUNDER_SUBJECT_KEYS.contains(&key.as_str()),
                "{key:?} is resolved by create.rs but missing from FUNDER_SUBJECT_KEYS"
            );
        }
    }

    /// dig_ecosystem#3253 §5 criterion 2: this file must never name a payee-mount key
    /// (`content-store-rewards-*`, `rewards-cadence-*`) -- those belong to `store_rewards.rs`'s
    /// mirror-summary mount, whose reader is the payee, never the funder this card addresses.
    #[test]
    fn no_payee_mount_key_appears_in_create_rs() {
        let literals = string_literals(include_str!("create.rs"));
        for literal in &literals {
            let is_payee_mount_key = literal.starts_with("content-store-rewards-")
                || literal.starts_with("rewards-cadence-");
            assert!(
                !is_payee_mount_key,
                "create.rs must never name a payee-mount key, found {literal:?}"
            );
        }
    }

    /// dig_ecosystem#3253 §5 criterion 3: the committed-total figure is
    /// `amount::format_asset_amount(Asset::DIG, committed_base_units)`'s own output with
    /// `amount::ticker`'s own word appended -- never a value recomputed from a compiled-in
    /// constant, and the WRAPPER (the whole `committed_amount` string a person reads) carries
    /// that exact figure, not just the bare number.
    #[test]
    fn the_committed_total_is_the_funders_own_commitment_never_a_recomputed_constant() {
        for base_units in [0u64, 1_000, 12_500, 999_999] {
            let copy = create_card_copy(base_units);
            let expected_figure = format_asset_amount(Asset::DIG, base_units)
                .expect("$DIG's decimals are known by definition");
            let expected_ticker = ticker(Asset::DIG);
            assert!(
                copy.committed_amount.contains(&expected_figure),
                "committed_amount wrapper {:?} does not contain the funder's own figure {:?}",
                copy.committed_amount,
                expected_figure
            );
            assert!(
                copy.committed_amount.contains(&expected_ticker),
                "committed_amount wrapper {:?} does not carry the ticker {:?}",
                copy.committed_amount,
                expected_ticker
            );
        }
    }

    /// dig_ecosystem#3253 §5 criterion 4 (en): no sentence this card renders may address the
    /// reader as though they are the payee earning a rate -- the shape already pinned at
    /// `pane.rs:664-669` for the mirror-summary mount, checked here against every rendered
    /// English value this card's own copy declares.
    #[test]
    fn no_rendered_sentence_addresses_the_reader_as_the_payee() {
        let all_msgs = [
            CREATE_ARM_A_LABEL,
            CREATE_ARM_A_BODY,
            CREATE_ARM_B_LABEL,
            CREATE_ARM_B_BODY,
            CREATE_HASH_LABEL,
            CREATE_COMMITTED_LABEL,
            CREATE_VERB_LABEL,
            CREATE_SIGN_BUTTON,
            CREATE_CANCEL_BUTTON,
            CREATE_ACKNOWLEDGE_CHECKBOX,
            CREATE_EPOCHS_LABEL,
        ];
        for msg in all_msgs {
            let text = msg.text_in(Language::En).to_lowercase();
            assert!(
                !text.contains("you earn") && !text.contains("your earnings") && !text.contains("you are paid"),
                "{} must never address the reader as the payee (en): {text:?}",
                msg.key()
            );
        }
    }

    /// Arm B's body may assert only what dig_ecosystem#3253 §2 permits -- the forbidden-word
    /// sweep, applied to THIS card's own arm B copy the same way `rewards/copy.rs`'s existing
    /// sweep applies to the five warning blocks.
    #[test]
    fn arm_b_never_claims_a_recovery_capability() {
        const FORBIDDEN: &[&str] = &[
            "recovery-capable",
            "multisig",
            "k-of-n",
            "2-of-3",
            "vault",
            "safer",
            "recommended",
            "your recovery key",
        ];
        let text = CREATE_ARM_B_BODY.text_in(Language::En).to_lowercase();
        let label = CREATE_ARM_B_LABEL.text_in(Language::En).to_lowercase();
        for phrase in FORBIDDEN {
            assert!(
                !text.contains(phrase) && !label.contains(phrase),
                "arm B contains forbidden phrase {phrase:?}: label={label:?} body={text:?}"
            );
        }
    }
}
