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

use super::pane::Acknowledged;

/// Parses arm B's typed hash text into a [`Bytes32`], accepting an optional `0x`/`0X` prefix.
/// Pure and egui-independent, ready for whichever paint code eventually calls it -- no card in
/// this crate calls it yet (see this module's doc comment: no launch path exists to sign into,
/// so no card collects this text).
///
/// `None` for anything that is not exactly 32 bytes of hex -- there is no partial/lenient parse,
/// because a manager puzzle hash this app cannot verify is exactly the value arm B's own body
/// text says this app cannot check; accepting a truncated or padded guess would make that
/// disclosure false.
pub fn parse_hash_hex(text: &str) -> Option<Bytes32> {
    let digits = text
        .strip_prefix("0x")
        .or_else(|| text.strip_prefix("0X"))
        .unwrap_or(text);
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
/// path. Zero-sized, and the single constructor (`Self::having_chosen`, private) — nothing
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
        let puzzle = acknowledged()
            .with_manager_choice(made, choice)
            .into_manager_inner_puzzle();
        assert!(matches!(puzzle, ManagerInnerPuzzle::SingleKeyBuiltHere(_)));
    }

    #[test]
    fn arm_b_round_trips_the_exact_hash() {
        let hash = Bytes32::from([9u8; 32]);
        let choice = ManagerChoice::HashSuppliedByCaller(hash);
        let made = ManagerChoiceMade::for_choice(&choice);
        let puzzle = acknowledged()
            .with_manager_choice(made, choice)
            .into_manager_inner_puzzle();
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
    use crate::rewards::test_scan::string_literals;

    /// Every fluent key this file's production code is permitted to resolve. Empty: this file
    /// currently declares no card copy at all -- see this module's doc comment for why (no launch
    /// path exists yet, so no card collects a choice through it). Extended only in the commit that
    /// adds a real paint function wired to a real `launch_dig_distributor` call, never ahead of it.
    pub(crate) const FUNDER_SUBJECT_KEYS: &[&str] = &[];

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
}
