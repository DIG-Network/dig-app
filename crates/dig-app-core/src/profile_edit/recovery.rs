//! Rebuilding a profile body that was minted and never published.
//!
//! # The hole this fills (dig_ecosystem#3036)
//!
//! A mint launches the store at the SEED's root and the body that root commits to lives off chain.
//! Until dig-account 0.16.0 the mint computed that root and dropped the bytes, so every profile
//! minted before it anchors a root whose preimage nothing on earth holds. The profile is real, the
//! chain is right, and no read can ever succeed.
//!
//! It is recoverable because the seed is DETERMINISTIC: `ProfileSeed::root()` is defined as
//! `Ok(self.body()?.root())`, over one private constructor shared with `body_bytes()`, so the bytes
//! are a pure function of the slots. Rebuild the seed, and you have the preimage — no chain write,
//! no spend, and nothing signed.
//!
//! # The candidates, and why the list is not longer
//!
//! Two sources, and neither of them guesses. The first is `Seed::new()` — the schema-stamped empty
//! profile, which every profile minted before the creation wizard collected any content seeds from.
//! The second is [`mint_seed`](super::mint_seed): the bodies this app WROTE DOWN before each mint it
//! ran, so a wizard-authored first profile has its preimage on disk rather than in a process that
//! has since exited (dig_ecosystem#3073).
//!
//! Nothing else may be added. A candidate invented rather than recorded would, on a collision,
//! publish a body the person never authored under their identity.
//!
//! # The rule that outranks recovering anything
//!
//! **A rebuild is published only when it hashes to the root the CHAIN anchors.** [`VerifiedBody::open`]
//! decides that, against [`AnchoredRoot::from_chain_read`], which is the same check dig-account
//! performs on the way in and the node performs again on `putBody`. A body that does not verify is
//! not a worse rebuild — it is a body for a DIFFERENT profile, and publishing it would make the app
//! serve content the chain contradicts. That case returns `None` and nothing is stored.

use std::sync::{Arc, OnceLock, RwLock};

use dig_account::mint::ProfileSeed;
use dig_social_profile::body::{AnchoredRoot, VerifiedBody};

use super::mint_seed::MintSeedBodies;

/// The recorded seed bodies this app may rebuild from, once the app edge has resolved storage.
///
/// # Why a holder rather than an argument
///
/// [`seed_body_for`] is reached from a profile READ, several layers below anything that knows where
/// this user's sealed data lives, and threading a store down that path would put a storage argument
/// on every content source in the app to serve one recovery. It is the same shape
/// [`ProfileSeedRequest::collect`](super::seed::ProfileSeedRequest::collect) and
/// [`EditService::install`](super::service::EditService::install) already use for the same reason.
///
/// Empty is the correct default and not a degraded one: with nothing installed the app rebuilds the
/// empty seed exactly as it did before, which is right for every profile minted before #3073.
static RECORDED: OnceLock<RwLock<Option<Arc<dyn MintSeedBodies>>>> = OnceLock::new();

/// The holder, created empty on first use.
fn recorded() -> &'static RwLock<Option<Arc<dyn MintSeedBodies>>> {
    RECORDED.get_or_init(|| RwLock::new(None))
}

/// Tell recovery where the seed bodies this app wrote down before its mints are kept.
///
/// Called once at the app edge, and replaceable so a locked account that later unlocks can install
/// the store it could not resolve at start-up.
pub fn install_recorded_seeds(store: Arc<dyn MintSeedBodies>) {
    if let Ok(mut held) = recorded().write() {
        *held = Some(store);
    }
}

/// The seed bodies that were RECORDED before a mint, or nothing when there is nowhere to read them.
///
/// A store that cannot be read yields no candidates rather than an error: a locked account makes a
/// rebuild impossible, not illegitimate, and the read that asked simply reports the profile
/// unpublished as it did before.
fn recorded_bodies() -> Vec<Vec<u8>> {
    recorded()
        .read()
        .ok()
        .and_then(|held| held.as_ref().map(|store| store.all().unwrap_or_default()))
        .unwrap_or_default()
}

/// The canonical body bytes of every seed this app could have minted from.
///
/// The empty seed always, plus everything written down before a mint. Order does not matter: each
/// candidate is accepted only by hashing to the root the chain anchors, and two candidates cannot
/// both do that.
fn seed_bodies() -> Vec<Vec<u8>> {
    ProfileSeed::new()
        .body_bytes()
        .into_iter()
        .chain(recorded_bodies())
        .collect()
}

/// The seed body for `root`, when this app can produce one that commits to it.
///
/// `None` means *no seed this app mints from hashes to that root* — the store was launched from
/// something else, and no local reconstruction of it would be legitimate. It is never "try harder".
///
/// Spends nothing, signs nothing and reads no chain: it rebuilds bytes and compares a hash.
pub fn seed_body_for(root: [u8; 32]) -> Option<Vec<u8>> {
    seed_bodies()
        .into_iter()
        .find(|bytes| VerifiedBody::open(bytes, AnchoredRoot::from_chain_read(root)).is_ok())
}

#[cfg(test)]
mod tests {
    use dig_social_profile::profile::Profile;
    use dig_social_profile::slot::standard::DISPLAY_NAME;
    use dig_social_profile::value::Value;

    use super::super::mint_seed::MemoryMintSeeds;
    use super::*;

    /// The root every profile this app has minted anchors, lowercase 64-hex.
    const SEED_ROOT: &str = "716513ed55e19d882a87d35f60e83a0fa13e92bc7eb81ddecf88d4364aa96184";

    /// The root the shipped mint actually anchors, computed the way the mint computes it.
    fn minted_root() -> [u8; 32] {
        ProfileSeed::new().root().expect("the seed builds")
    }

    /// The recovery, end to end: the root the mint wrote is a root this app can produce a body for.
    #[test]
    fn the_root_a_mint_anchors_can_be_rebuilt_from_the_seed() {
        let bytes = seed_body_for(minted_root()).expect("the minted root rebuilds");
        assert!(
            VerifiedBody::open(&bytes, AnchoredRoot::from_chain_read(minted_root())).is_ok(),
            "the rebuild does not commit to the root it was produced for"
        );
    }

    /// A root this app cannot produce a body for yields NOTHING, rather than the nearest body it
    /// happens to hold.
    ///
    /// # Why the fixture is a REAL profile's root and not random bytes
    ///
    /// The nearest wrong implementation returns the single candidate unconditionally and lets a
    /// later layer notice, and against random bytes the two versions are told apart only by which
    /// layer refuses — a placement, not an outcome. So the miss here is a root that genuinely
    /// belongs to a different, well-formed profile: the answer must be `None` because the seed is
    /// wrong for that store, not because the bytes were malformed.
    #[test]
    fn a_root_this_app_did_not_mint_rebuilds_to_nothing() {
        let mut other = Profile::new();
        other.set(DISPLAY_NAME, Value::Utf8("Ada".into()));
        let elsewhere = VerifiedBody::from_profile(&other).expect("a body").root();
        assert_ne!(
            elsewhere,
            minted_root(),
            "the fixture must be a DIFFERENT root"
        );

        assert!(
            seed_body_for(elsewhere).is_none(),
            "a body was produced for a root this app cannot have minted"
        );
    }

    /// The seed root this app mints from, PINNED, so a change to the seed is loud rather than
    /// silent.
    ///
    /// # What this is for, given it is derived from the same code it checks
    ///
    /// It cannot prove the value is RIGHT — only the chain can, and that comparison is
    /// [`seed_body_for`]'s job on every read. What it pins is that the value does not MOVE. Every
    /// profile already minted anchors this root, so a future change to `ProfileSeed::new`, to the
    /// schema stamp, or to the DPB encoding would silently make every one of them unrecoverable
    /// again — the exact failure #3036 exists to close, arriving a second time by a different door.
    ///
    /// It is also the number to compare a real store against: a store whose anchored root is not
    /// this is a store this app did not mint, or a seed derivation that has drifted from what the
    /// mint used — a bug to report, never a reason to publish anyway.
    #[test]
    fn the_seed_root_this_app_mints_from_does_not_move() {
        assert_eq!(
            hex::encode(minted_root()),
            SEED_ROOT,
            "the mint seed changed, so every profile already minted at the old root became \n             unrecoverable"
        );
    }

    /// **dig_ecosystem#3073.** A profile whose FIRST body came from the creation wizard is
    /// rebuildable — from what recovery can reach after a restart, not from the process that typed
    /// it.
    ///
    /// # Why the fixture is a named profile and not the empty one
    ///
    /// The nearest wrong implementation is the one shipped before this: a candidate list holding
    /// only `ProfileSeed::new()`. Against an EMPTY wizard form it answers correctly — the empty
    /// form seeds the empty seed — so a fixture with nothing filled in cannot tell the two versions
    /// apart at all. The name is what makes the anchored root unreachable without the recorded body,
    /// and it is asserted to differ from the empty root so the distinction is pinned rather than
    /// assumed.
    ///
    /// # The control in the same test
    ///
    /// A second wizard root that was never recorded must still answer `None`. Without it this
    /// passes for an implementation that returns whatever body it holds and lets a later layer
    /// notice — which is a placement, and would keep passing if the verification moved.
    #[test]
    fn a_wizard_authored_first_body_is_rebuildable_after_the_process_that_typed_it_is_gone() {
        let typed = ProfileSeed::new().with_display_name("ada lovelace");
        let anchored = typed.root().expect("the seed builds");
        assert_ne!(
            anchored,
            minted_root(),
            "the fixture must be a root the EMPTY seed cannot answer, or it proves nothing"
        );

        // What the mint path writes down before it spends, read back by a store that shares nothing
        // with the writer — the restart, in the one respect recovery depends on.
        let disk = MemoryMintSeeds::default();
        disk.remember(&typed.body_bytes().expect("the seed has a body"))
            .expect("remembers");
        install_recorded_seeds(Arc::new(disk));

        let bytes = seed_body_for(anchored).expect("the wizard's own body was not rebuildable");
        assert!(
            VerifiedBody::open(&bytes, AnchoredRoot::from_chain_read(anchored)).is_ok(),
            "the rebuild does not commit to the root the chain anchors"
        );

        // The control: a wizard root nobody recorded is still unanswerable.
        let unrecorded = ProfileSeed::new()
            .with_display_name("grace hopper")
            .root()
            .expect("the seed builds");
        assert!(
            seed_body_for(unrecorded).is_none(),
            "a body was produced for a root this app never recorded a seed for"
        );

        // And the empty seed still answers, so widening the list did not displace the original.
        assert!(seed_body_for(minted_root()).is_some());
    }

    /// An all-zero root — the root of a literally EMPTY tree — is not answerable either.
    ///
    /// `SmtTree::new()` roots at all zeros and `hash_leaf_value` returns zeros for an empty value
    /// regardless of key, so a bare header verifies against all zeros: a universal forgery. The
    /// format refuses it (`UnanchoredZeroRoot`) and this must inherit that refusal rather than
    /// route around it by producing bytes for it.
    #[test]
    fn the_all_zero_root_is_not_something_this_can_answer() {
        assert!(seed_body_for([0u8; 32]).is_none());
    }
}
