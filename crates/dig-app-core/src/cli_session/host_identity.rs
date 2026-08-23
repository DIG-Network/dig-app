//! The production [`LocalIdentity`] the CLI lane serves with: this host's real profile registry.
//!
//! # Why this reads the registry rather than an unlocked account
//!
//! dig-app leaves the account LOCKED on almost every start-up path (dig_ecosystem#1817) — a password
//! window at login with nothing asking for it is a window people click away. If the CLI lane were
//! only bound after an unlock, `diga` would report *"dig-app is not running"* to a person whose app
//! is running and visible, which is the one thing the lane must never say.
//!
//! So the lane binds at start-up and serves what is honestly readable with the seed away. The
//! profile registry is exactly that: `<brand_dir>/profiles/registry.json` holds each profile's DID,
//! store id and label, none of which is secret and none of which needs the master seed to read. A
//! person can therefore run `diga profiles list` against a locked app and get the truth.
//!
//! Everything that genuinely needs the seed — the wallet address, a signature — reports
//! [`ErrorCode::Locked`] naming the remedy. That is a refusal, not a fabrication, and it is the
//! distinction this module exists to hold: a value that cannot be read is never substituted with a
//! plausible one.
//!
//! # dig_ecosystem#908: the CLI cannot become a signing oracle
//!
//! [`HostIdentity::sign`] is unimplemented ON PURPOSE and refuses. The gateway does run the native
//! confirm ceremony in front of it, so wiring it here would not bypass the ceremony — but the
//! ceremony's window belongs to the app's own event loop, and a signature raised from a background
//! lane thread is a design that must be shown to work before it is shipped, not assumed to. Refusing
//! is the honest state of the art; a `diga sign` that half-works would be worse than one that says so.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use crate::account::profile_session::{FileRegistryStore, ProfileSession};
use crate::gateway::{
    ErrorCode, GatewayError, LocalIdentity, PendingProfileCreation, ProfileSeedRequest,
    ProfileSummary,
};
use crate::profiles::ProfilesReading;

/// The hint every seed-bound refusal carries, so a person is told the ONE thing that changes the
/// answer instead of being told merely that something is unavailable.
const UNLOCK_HINT: &str = "open the DIG app and unlock your account, then run this command again";

/// Serves the CLI lane's local commands from this host's real profile registry.
pub struct HostIdentity {
    brand_dir: PathBuf,
}

impl HostIdentity {
    /// The identity rooted at this user's `brand_dir` — the same directory that holds the session
    /// token and the socket, so one per-user location backs the whole lane.
    pub fn under(brand_dir: impl Into<PathBuf>) -> Self {
        Self {
            brand_dir: brand_dir.into(),
        }
    }

    /// Load the registry session, reporting an unreadable registry as a catalogued error.
    ///
    /// A registry that has never been written is NOT an error: it is an account with no profiles
    /// yet, and it reads as an empty list.
    fn session(&self) -> Result<ProfileSession, GatewayError> {
        let store = Arc::new(FileRegistryStore::under(&self.brand_dir));
        ProfileSession::load(store).map_err(|why| {
            GatewayError::new(
                ErrorCode::IoError,
                format!("this host's profile registry could not be read: {why}"),
            )
            .with_hint("the registry lives at profiles/registry.json in the DIG data directory")
        })
    }

    /// The refusal every seed-bound verb returns while the account is locked.
    fn locked(what: &str) -> GatewayError {
        GatewayError::new(
            ErrorCode::Locked,
            format!("{what} needs your unlocked DIG account, and the app is holding it locked"),
        )
        .with_hint(UNLOCK_HINT)
    }

    /// Where this identity reads from — the seam an integration test points at a temporary directory.
    pub fn brand_dir(&self) -> &Path {
        &self.brand_dir
    }
}

impl LocalIdentity for HostIdentity {
    /// Every profile in this host's registry, with the active one flagged.
    ///
    /// Hidden profiles are included. Hiding is a LOCAL view preference for the app's own lists, and
    /// a command line whose `list` silently omitted rows would make a person believe a profile they
    /// still own is gone.
    fn profiles(&self) -> Result<Vec<ProfileSummary>, GatewayError> {
        let session = self.session()?;
        let reading = ProfilesReading::of_session(&session);
        Ok(reading
            .rows()
            .unwrap_or_default()
            .iter()
            .map(|row| ProfileSummary {
                did: row.did.clone(),
                name: row.display_name(),
                active: row.active,
            })
            .collect())
    }

    /// Minting a profile spends real XCH and shows a recovery-relevant ceremony, so it is the app's
    /// window to raise, never a background lane's.
    fn begin_profile_creation(
        &self,
        _seed: ProfileSeedRequest,
    ) -> Result<PendingProfileCreation, GatewayError> {
        Err(GatewayError::new(
            ErrorCode::Denied,
            "creating a profile is done in the DIG app, because it spends XCH and is confirmed there",
        )
        .with_hint("open the DIG app and create the profile from the Profiles tab"))
    }

    /// Switching the active profile rewrites the registry the unlocked account derives from, so it
    /// is refused while the seed is away rather than written behind the app's back.
    fn select_profile(&self, _did: &str) -> Result<(), GatewayError> {
        Err(Self::locked("switching the active profile"))
    }

    /// The active profile's DID, read straight from the registry.
    fn default_profile(&self) -> Result<Option<String>, GatewayError> {
        Ok(self
            .profiles()?
            .into_iter()
            .find(|profile| profile.active)
            .map(|profile| profile.did))
    }

    /// See [`HostIdentity::select_profile`]: the same registry write, the same refusal.
    fn set_default_profile(&self, _did: &str) -> Result<(), GatewayError> {
        Err(Self::locked("setting the default profile"))
    }

    /// The receive address is derived from the master seed, so it cannot be read while locked.
    fn wallet_address(&self) -> Result<String, GatewayError> {
        Err(Self::locked("reading your receive address"))
    }

    /// The balance is a CHAIN reading, and reading it needs this account's ADDRESS — which is
    /// derived from the master seed. So it refuses for the same reason
    /// [`wallet_address`](Self::wallet_address) does, and says so.
    ///
    /// It refuses rather than returning `0`. A zero here is indistinguishable from an empty wallet,
    /// and a command line that reports a funded account as empty is the money lie this whole seam is
    /// shaped to make impossible — the app's own model keeps `Pending` and `Unknown` distinct from
    /// `Known { 0 }` for exactly this reason.
    ///
    /// # Why this stopped saying NOT_CONNECTED
    ///
    /// It used to report "not served here yet", which was true while the lane could not reach a node
    /// at all. The lane now proxies to a node ([`super::NodeEngineProxy`], dig-app#226), so that
    /// sentence had become the wrong fault: it would send a person to check whether their node is
    /// running when the node has nothing to do with it. The blocker is, and always was, the lock.
    fn wallet_balance(&self) -> Result<u64, GatewayError> {
        Err(Self::locked("reading your balance"))
    }

    /// Refused — see this module's `dig_ecosystem#908` note.
    fn sign(&self, _message: &[u8]) -> Result<Vec<u8>, GatewayError> {
        Err(GatewayError::new(
            ErrorCode::Denied,
            "signing is confirmed in the DIG app itself, so the approval window is one you can see",
        )
        .with_hint("run the signature from the DIG app"))
    }
}

/// The link opener the CLI lane serves with: a refusal naming where links are opened.
///
/// Opening a `dig://` link means resolving it and launching a browser at the result. That is the
/// desktop shell's job and it belongs to the app's own event loop, so the lane refuses rather than
/// launching a process from a background thread on the CLI's say-so.
pub struct UnopenedLinks;

impl crate::gateway::LinkOpener for UnopenedLinks {
    fn open(&self, _link: &str) -> Result<crate::gateway::Outcome, GatewayError> {
        Err(GatewayError::new(
            ErrorCode::Denied,
            "opening a link is done by the DIG app, which owns the window it opens into",
        )
        .with_hint("open the link from the DIG app"))
    }
}

/// The confirm seam the CLI lane serves with: every ceremony reports `Unavailable`.
///
/// # This is the dig_ecosystem#908 boundary, expressed as a type
///
/// A confirm window belongs to the app's own event loop. A lane thread cannot raise one, and the
/// fail-closed default across this whole trait is that a ceremony which cannot be SHOWN is a
/// ceremony that was not APPROVED. Returning `Unavailable` therefore makes it structurally
/// impossible for a `diga` invocation to obtain a signature: there is no decision here that any
/// caller could read as approval, so the CLI cannot become a signing oracle even by mistake.
pub struct UnavailableConfirmer;

impl crate::confirm::NativeConfirmer for UnavailableConfirmer {
    fn confirm_pair(&self, _: &crate::confirm::PairPrompt<'_>) -> crate::confirm::ConfirmDecision {
        crate::confirm::ConfirmDecision::Unavailable
    }

    fn confirm_connect(
        &self,
        _: &crate::confirm::ConnectPrompt<'_>,
    ) -> crate::confirm::ConfirmDecision {
        crate::confirm::ConfirmDecision::Unavailable
    }

    fn confirm_sign(&self, _: &crate::confirm::SignPrompt<'_>) -> crate::confirm::ConfirmDecision {
        crate::confirm::ConfirmDecision::Unavailable
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::account::profile_session::test_support;

    /// Write a registry holding `profiles` with `active_ix` active, exactly where the production
    /// store reads it, so the test exercises the real path resolution rather than a handed-in store.
    fn registry_under(dir: &Path, profiles: &[(u32, Option<&str>)], active_ix: u32) {
        let entries: Vec<_> = profiles
            .iter()
            .map(|(ix, label)| (dig_account::ProfileIx(*ix), *label))
            .collect();
        let json = test_support::registry_json(&entries, dig_account::ProfileIx(active_ix));
        let path = FileRegistryStore::under(dir).path().to_path_buf();
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, json).unwrap();
    }

    /// The acceptance verb, against a registry on disk and NO unlocked account — which is the state
    /// the app is actually in when a person runs `diga profiles list`.
    #[test]
    fn profiles_are_listed_from_the_registry_without_an_unlocked_account() {
        let dir = tempfile::tempdir().unwrap();
        registry_under(dir.path(), &[(0, Some("home")), (1, Some("work"))], 1);

        let listed = HostIdentity::under(dir.path()).profiles().unwrap();

        assert_eq!(listed.len(), 2);
        // The ACTIVE flag must follow the registry, not the list order. A fixture whose active
        // profile were the first row could not tell a real read from `first().active = true`.
        assert!(!listed[0].active, "profile 0 is not the active one here");
        assert!(listed[1].active, "the registry says index 1 is active");
        assert_eq!(listed[1].name, "\u{201c}work\u{201d}");
        assert_ne!(listed[0].did, listed[1].did, "each profile has its own DID");
    }

    /// A host that has never minted has no registry file. That is an empty list, not a failure —
    /// a stranger who installs DIG and runs `diga profiles list` must get an answer.
    #[test]
    fn a_host_that_never_minted_lists_nothing_rather_than_failing() {
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(HostIdentity::under(dir.path()).profiles().unwrap(), vec![]);
        assert_eq!(
            HostIdentity::under(dir.path()).default_profile().unwrap(),
            None
        );
    }

    /// The default profile is the registry's ACTIVE one, read through the same path.
    #[test]
    fn the_default_profile_is_the_active_registry_entry() {
        let dir = tempfile::tempdir().unwrap();
        registry_under(dir.path(), &[(0, Some("home")), (1, Some("work"))], 1);

        let identity = HostIdentity::under(dir.path());
        let default = identity
            .default_profile()
            .unwrap()
            .expect("a profile is active");
        let listed = identity.profiles().unwrap();

        assert_eq!(default, listed[1].did);
        assert_ne!(
            default, listed[0].did,
            "the default is not merely the first row"
        );
    }

    /// Every seed-bound verb refuses with a catalogued code and a remedy — and, critically, none of
    /// them invents a value. A `wallet_balance` of `0` would read as an empty wallet.
    #[test]
    fn seed_bound_verbs_refuse_with_a_remedy_and_never_substitute_a_value() {
        let dir = tempfile::tempdir().unwrap();
        registry_under(dir.path(), &[(0, Some("home"))], 0);
        let identity = HostIdentity::under(dir.path());

        for error in [
            identity.wallet_address().unwrap_err(),
            identity.select_profile("did:chia:whatever").unwrap_err(),
            identity
                .set_default_profile("did:chia:whatever")
                .unwrap_err(),
        ] {
            assert_eq!(error.code, ErrorCode::Locked);
            assert_eq!(error.hint.as_deref(), Some(UNLOCK_HINT));
        }

        // The balance joined the LOCKED set when the lane gained a node proxy: it needs the
        // seed-derived address, never the node's reachability (dig-app#226). Asserted alongside the
        // others rather than as a special case, because it is no longer a special case.
        let balance = identity.wallet_balance().unwrap_err();
        assert_eq!(balance.code, ErrorCode::Locked);
        assert_eq!(balance.hint.as_deref(), Some(UNLOCK_HINT));
        assert!(identity.sign(b"anything").is_err(), "the CLI never signs");
    }
}
