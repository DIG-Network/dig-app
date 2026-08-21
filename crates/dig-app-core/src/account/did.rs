//! Whether this account has an on-chain DID, and the EVIDENCE that says so (dig_ecosystem#2341).
//!
//! # The one rule this module exists to enforce
//!
//! A DID is recorded **only from evidence of an actual on-chain mint** — never inferred from a key.
//! [`crate::account::boot::account_scoped_id`] returns the seed-derived identity public key precisely
//! *because* nothing has been minted, so a key is exactly the thing that must not be mistaken for a DID.
//!
//! That rule is held by the TYPES rather than by discipline: a [`DidRecord`] cannot be built without a
//! [`MintEvidence`], and a `MintEvidence` cannot be built without a confirmation height — the number a
//! chain produces and a key cannot. There is deliberately no `DidRecord::from_public_key`, no
//! `Default`, and no way to deserialize a record whose evidence is absent (see [`DidFile::recorded`]).
//!
//! # What the presence of a DID decides
//!
//! It gates the surfaces that BEAR an identity — publishing, signing for an app, messaging — and
//! nothing else. Reading content stays reachable with no account and no DID at all, which is what
//! dig-app has always told its users and what [`Capability::ReadContent`] keeps true.

use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

/// Proof that a DID mint actually landed on chain.
///
/// The fields are private and there is one constructor, [`MintEvidence::confirmed`], which requires a
/// block height. A caller holding only a public key, an address, or a submitted-but-unconfirmed spend
/// cannot produce this type — which is the whole point: it is the thing a [`DidRecord`] cannot be
/// written without.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MintEvidence {
    /// The id of the spend that created the DID, as the chain reports it.
    spend_id: String,
    /// The block height the spend was confirmed at. A submission has no height; only a confirmation does.
    confirmed_height: u32,
}

impl MintEvidence {
    /// Record that the spend `spend_id` was seen CONFIRMED at `confirmed_height`.
    ///
    /// Called only from a chain observation ([`crate::account::mint::Sighting::Confirmed`]) — never from
    /// a submission, because a submitted spend can still be rejected, and never from key material.
    pub fn confirmed(spend_id: impl Into<String>, confirmed_height: u32) -> Self {
        Self {
            spend_id: spend_id.into(),
            confirmed_height,
        }
    }

    /// The spend that minted the DID, for a user who wants to look it up on a block explorer.
    pub fn spend_id(&self) -> &str {
        &self.spend_id
    }

    /// The height the mint was confirmed at.
    pub fn confirmed_height(&self) -> u32 {
        self.confirmed_height
    }
}

/// A `did:chia:` DID that this account provably owns, and the mint that proves it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DidRecord {
    /// The DID itself, in `did:chia:…` form.
    did: String,
    /// How we know it exists. Not optional, at rest or in memory — see the module docs.
    evidence: MintEvidence,
}

impl DidRecord {
    /// Bind `did` to the mint that created it.
    pub fn from_mint(did: impl Into<String>, evidence: MintEvidence) -> Self {
        Self {
            did: did.into(),
            evidence,
        }
    }

    /// The DID, for display and for the tray.
    pub fn did(&self) -> &str {
        &self.did
    }

    /// The mint that proves it.
    pub fn evidence(&self) -> &MintEvidence {
        &self.evidence
    }
}

/// Where a minted DID is remembered between runs.
///
/// A trait so the wizard and the gate can be driven against a double, and so the on-disk shape is one
/// implementation rather than a format every caller re-parses.
pub trait DidLedger {
    /// The DID this account has minted, or `None` when it has minted none.
    ///
    /// `None` is also the answer for a ledger that cannot be read or does not parse: an unreadable
    /// ledger means "no proof", never "assume one". The fail-closed direction here costs a user a
    /// re-mint prompt; the other direction would tell them they have an identity they do not have.
    fn recorded(&self) -> Option<DidRecord>;

    /// Remember `record`. Returns whether it was durably written.
    fn record(&self, record: &DidRecord) -> bool;
}

/// The name of the ledger file inside the brand directory.
const LEDGER_FILE: &str = "did.json";

/// The production [`DidLedger`] — one JSON file beside the account's other at-rest state.
///
/// It holds no secret (a DID and a spend id are public facts), so it is not sealed; what it must do is
/// refuse to answer with anything it cannot back up, which is [`DidFile::recorded`]'s whole job.
///
/// # Why it is scoped to the ACCOUNT and not to a profile
///
/// It is written at a moment when no profile index exists yet: the first-run wizard mints before the
/// account has a registry entry to hang a DID on, so there is nothing to scope it TO.
///
/// It is **not** because an account has only one identity. It does not: an account owns many
/// profiles, each with its own DID, and exactly one is active — the registry's active slot is
/// [`ProfileSession::active_ix`](crate::account::profile_session::ProfileSession::active_ix), a
/// scalar read live from `active: Option<ProfileIx>`. A previous version of this comment asserted a
/// pinned-to-one-profile invariant and cited an `ActiveProfile::SOLE` constant, and neither survives
/// (dig_ecosystem#2582): the constant was removed in dig_ecosystem#2236 and the invariant was never
/// true afterwards. Widening this ledger to per-profile belongs with the profile mint
/// (dig_ecosystem#2398), whose registry journal is where a per-profile DID is already recorded.
#[derive(Debug, Clone)]
pub struct DidFile {
    /// The file the record lives in.
    path: PathBuf,
}

impl DidFile {
    /// The ledger for the account housed in `brand_dir`.
    pub fn new(brand_dir: &Path) -> Self {
        Self {
            path: brand_dir.join(LEDGER_FILE),
        }
    }
}

impl DidLedger for DidFile {
    /// Read the record, accepting it ONLY if it carries its mint evidence.
    ///
    /// A file holding `{"did": "did:chia:…"}` and nothing else fails to deserialize, because
    /// [`DidRecord::evidence`] is a required field — so a hand-written, copied, or truncated ledger
    /// cannot conjure a DID that was never minted.
    fn recorded(&self) -> Option<DidRecord> {
        let raw = std::fs::read_to_string(&self.path).ok()?;
        match serde_json::from_str::<DidRecord>(&raw) {
            Ok(record) => Some(record),
            Err(e) => {
                tracing::warn!(error = %e, "the DID ledger does not carry mint evidence; treating this account as having no DID");
                None
            }
        }
    }

    fn record(&self, record: &DidRecord) -> bool {
        let Some(dir) = self.path.parent() else {
            return false;
        };
        if std::fs::create_dir_all(dir).is_err() {
            return false;
        }
        match serde_json::to_string_pretty(record) {
            Ok(json) => std::fs::write(&self.path, json).is_ok(),
            Err(_) => false,
        }
    }
}

/// Something a person can ask dig-app to do, classified by whether it BEARS their identity.
///
/// The classification is the gate. It lives here, as data, so the answer for a new surface is a match
/// arm somebody has to write deliberately rather than a condition scattered across the shell.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Capability {
    /// Read content from the DIG Network. Needs no account, no wallet and no DID — dig-app says exactly
    /// that on its wallet screen, and [`Allowance::of`] keeps it true.
    ReadContent,
    /// Hold and receive funds. A wallet does this; an identity is not involved.
    HoldFunds,
    /// Publish content under this identity.
    Publish,
    /// Sign something for a paired app or a dapp, under this identity.
    SignForAnApp,
    /// Send a directed message as this identity.
    Message,
}

impl Capability {
    /// Whether doing this thing puts the user's identity on it.
    fn bears_an_identity(self) -> bool {
        match self {
            Self::ReadContent | Self::HoldFunds => false,
            Self::Publish | Self::SignForAnApp | Self::Message => true,
        }
    }
}

/// Whether a capability is available right now, and why not when it is not.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Allowance {
    /// Go ahead.
    Allowed,
    /// This surface bears the user's identity and no DID has been minted. The caller sends the user to
    /// the first-run wizard rather than failing obscurely.
    NeedsDid,
}

impl Allowance {
    /// Rule on `capability` for an account whose ledger holds `did`.
    ///
    /// The DID is passed as the RECORD, not a boolean, so the only way to reach [`Allowance::Allowed`]
    /// on an identity-bearing surface is to be holding evidence of a mint.
    pub fn of(did: Option<&DidRecord>, capability: Capability) -> Self {
        Self::rule(did.is_some(), capability)
    }

    /// Rule on `capability` for a surface carrying only the DID STRING the ledger yielded.
    ///
    /// The tray and the window are built from a [`TrayView`](crate::tray_menu::TrayView), which holds
    /// the DID as a string because a menu row has no use for the mint evidence behind it. That view
    /// is only ever populated FROM a [`DidRecord`], so a `Some` here still traces to evidence of a
    /// mint — this is a narrower carrier of the same fact, not a second way to be allowed.
    ///
    /// # `None` means "no DID" and "could not tell", and they share an answer on purpose
    ///
    /// A surface that has not yet read the ledger, or could not, reaches this with `None`. Letting
    /// the unknown case through would make the gate weakest exactly when it knows least
    /// (dig_ecosystem#2350), so an unanswerable gate refuses. Refusing costs a person one visible
    /// row naming the remedy; passing costs them an identity-bearing action taken on a guess.
    pub fn of_did(did: Option<&str>, capability: Capability) -> Self {
        Self::rule(did.is_some(), capability)
    }

    /// The rule itself, in one place, so the two carriers above cannot drift into two policies.
    fn rule(has_did: bool, capability: Capability) -> Self {
        match capability.bears_an_identity() && !has_did {
            true => Self::NeedsDid,
            false => Self::Allowed,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A DID that could not be mistaken for a fragment of any surrounding copy.
    const DID: &str = "did:chia:1didledgerfixture000000000000000000000000000000000000000000";

    fn a_record() -> DidRecord {
        DidRecord::from_mint(DID, MintEvidence::confirmed("0xspend", 5_412_009))
    }

    /// **A ledger file with no mint evidence reads as NO DID.**
    ///
    /// This is the fixture the whole module exists for. The nearest wrong implementation — trust any
    /// `did` string that was written down — reads this file as a minted DID and unlocks publishing for
    /// an account that has never spent anything. Asserting on a well-formed record could not tell the
    /// two implementations apart, so the fixture is deliberately the malformed one.
    #[test]
    fn a_recorded_did_without_evidence_is_not_a_did() {
        let dir = tempfile::tempdir().unwrap();
        let ledger = DidFile::new(dir.path());
        std::fs::write(dir.path().join("did.json"), format!(r#"{{"did":"{DID}"}}"#)).unwrap();

        assert_eq!(
            ledger.recorded(),
            None,
            "a DID with no mint evidence must not be honoured"
        );
    }

    /// A record written WITH its evidence survives a round trip, so the fail-closed read above is not
    /// simply a ledger that never works.
    #[test]
    fn a_did_minted_with_evidence_round_trips() {
        let dir = tempfile::tempdir().unwrap();
        let ledger = DidFile::new(dir.path());

        assert!(ledger.record(&a_record()), "the record must be written");
        let read = ledger.recorded().expect("the record must be read back");
        assert_eq!(read.did(), DID);
        assert_eq!(read.evidence().confirmed_height(), 5_412_009);
        assert_eq!(read.evidence().spend_id(), "0xspend");
    }

    /// An account that has never minted reads as having no DID, rather than as an error.
    #[test]
    fn an_account_that_never_minted_has_no_did() {
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(DidFile::new(dir.path()).recorded(), None);
    }

    /// **Reading content is never gated.** dig-app tells users that reading needs no account and no
    /// wallet; a gate that broke that promise would brick the app for the one user who installed it
    /// only to read.
    #[test]
    fn reading_content_never_needs_a_did() {
        assert_eq!(
            Allowance::of(None, Capability::ReadContent),
            Allowance::Allowed
        );
        assert_eq!(
            Allowance::of(None, Capability::HoldFunds),
            Allowance::Allowed
        );
    }

    /// Every identity-bearing surface is gated when no DID has been minted — asserted over the whole
    /// set, so a capability added without a deliberate classification cannot slip through ungated.
    #[test]
    fn every_identity_bearing_surface_needs_a_did() {
        for capability in [
            Capability::Publish,
            Capability::SignForAnApp,
            Capability::Message,
        ] {
            assert_eq!(
                Allowance::of(None, capability),
                Allowance::NeedsDid,
                "{capability:?} bears the user's identity and must be gated"
            );
            assert_eq!(
                Allowance::of(Some(&a_record()), capability),
                Allowance::Allowed,
                "{capability:?} must open once a DID is minted"
            );
        }
    }
}
