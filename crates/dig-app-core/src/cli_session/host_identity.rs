//! The production [`LocalIdentity`] the CLI lane serves with: this host's real profile registry,
//! plus whatever the running app has published as its unlocked account.
//!
//! # Two sources, consulted at two different times
//!
//! dig-app leaves the account LOCKED on almost every start-up path (dig_ecosystem#1817) — a password
//! window at login with nothing asking for it is a window people click away. So the lane binds at
//! start-up, before any unlock, and it must still answer. That is why it holds a **directory** (read
//! whenever asked) rather than an account (which may not exist yet).
//!
//! The registry at `<brand_dir>/profiles/registry.json` is what it can always read: each profile's
//! DID, store id and label, none of it secret and none of it needing the master seed. A person can
//! run `diga profiles list` against a locked app and get the truth.
//!
//! Everything seed-bound consults the [`LiveAccount`] slot **per operation** — the discipline
//! [`ActiveSlot`](crate::account::active_profile::ActiveSlot) already holds for the active profile
//! index, and [`sign_service`](crate::sign_service) already holds for the loopback channel. The lane
//! therefore answers from the account state at the instant of the call, not the state at bind time.
//!
//! # dig-app#270: why these verbs stopped refusing unconditionally
//!
//! Each of them used to refuse whether or not the account was unlocked, so a person looking at a
//! running, unlocked DIG app was told to unlock it. The refusals' stated reasons were sound for a
//! lane that could not SEE the account; they do not survive a lane that can. What survives unchanged
//! is the shape of an honest refusal: **a value that cannot be read is never substituted with a
//! plausible one**, so a locked account still yields [`ErrorCode::Locked`] naming the remedy, and
//! never a zero, an empty string, or a stale figure.
//!
//! # dig_ecosystem#908: the CLI still cannot become a signing oracle
//!
//! [`HostIdentity::sign`] still refuses, and that is deliberate rather than unfinished. A signature
//! is authorized by a human at a native confirm window, and that window belongs to the app's own
//! event loop; a lane thread cannot raise one. [`UnavailableConfirmer`] makes that structural rather
//! than conventional — every ceremony reports `Unavailable`, so there is no decision here any caller
//! could read as approval. Unlocking the account does not change that, because the missing thing was
//! never the key.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use dig_account::ProfileIx;

use crate::account::live_account::LiveAccount;
use crate::account::profile_session::{FileRegistryStore, ProfileSession};
use crate::account::residency::{AccountResidency, AddressObservation};
use crate::gateway::{
    ErrorCode, GatewayError, LocalIdentity, PendingProfileCreation, ProfileSeedRequest,
    ProfileSummary,
};
use crate::profiles::ProfilesReading;
use crate::session_lock::SessionKeys;
use crate::wallet::engine::{BalanceRequest, WalletEngine};
use crate::wallet::state::Asset;
use crate::wallet::WalletError;

/// The hint every seed-bound refusal carries, so a person is told the ONE thing that changes the
/// answer instead of being told merely that something is unavailable.
const UNLOCK_HINT: &str = "open the DIG app and unlock your account, then run this command again";

/// The hint a balance refusal carries when the account is open but no node answered.
const NO_NODE_HINT: &str = "start the DIG node (`dig-node start`), or set a node endpoint in the \
     DIG app's Settings if yours runs elsewhere";

/// Serves the CLI lane's local commands from this host's real profile registry and the app's live
/// unlocked account.
pub struct HostIdentity {
    brand_dir: PathBuf,
    /// Where the running app publishes its unlocked account. Read per operation, never stored as an
    /// account — see the [module docs](self).
    account: LiveAccount,
    /// How a balance is read from chain, when there is one to read it with.
    ///
    /// `None` on a lane with no node endpoint, which refuses the balance by name rather than
    /// reporting a figure nothing measured.
    wallet: Option<Box<dyn WalletEngine>>,
}

impl HostIdentity {
    /// The identity rooted at this user's `brand_dir` — the same directory that holds the session
    /// token and the socket, so one per-user location backs the whole lane.
    ///
    /// It sees no account and no node until [`with_account`](Self::with_account) /
    /// [`with_wallet`](Self::with_wallet) say otherwise, so a caller that wires neither gets a lane
    /// that serves the registry and refuses everything seed-bound.
    pub fn under(brand_dir: impl Into<PathBuf>) -> Self {
        Self {
            brand_dir: brand_dir.into(),
            account: LiveAccount::empty(),
            wallet: None,
        }
    }

    /// Consult `account` for the unlocked account on every seed-bound operation.
    #[must_use]
    pub fn with_account(mut self, account: LiveAccount) -> Self {
        self.account = account;
        self
    }

    /// Read balances through `wallet` — in production the node the lane already proxies to.
    #[must_use]
    pub fn with_wallet(mut self, wallet: Box<dyn WalletEngine>) -> Self {
        self.wallet = Some(wallet);
        self
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

    /// The unlocked account at this instant, or the refusal that names the lock.
    ///
    /// The one place a seed-bound verb turns "what the app is holding right now" into an answer, so
    /// every such verb refuses identically and none of them can drift into a softer check.
    ///
    /// An EMPTY slot and a LOCKED residency both land here, and both are `LOCKED` — because the
    /// remedy is the same one either way, and a person at a terminal is owed the remedy rather than
    /// a taxonomy of the app's internal states.
    ///
    /// The predicate is [`SessionKeys::is_any_unlocked`], the same one the tray reads
    /// (`tray_menu.rs`), rather than a check invented here: two lock predicates that could disagree
    /// would let the tray say locked while a terminal signs. It is deliberately not a probe that
    /// treats an error as "locked-ish" — it reads the residency under the residency's own mutex,
    /// which panics on poison instead of answering. A custody predicate that answers `false` when it
    /// cannot tell would be the safe direction; one that answers `true` would not, and the only way
    /// to be sure it never does the latter is for it never to guess at all.
    fn unlocked(&self, what: &str) -> Result<AccountResidency, GatewayError> {
        match self.account.read() {
            Some(residency) if residency.is_any_unlocked() => Ok(residency),
            _ => Err(Self::locked(what)),
        }
    }

    /// The refusal every seed-bound verb returns while the account is locked.
    fn locked(what: &str) -> GatewayError {
        GatewayError::new(
            ErrorCode::Locked,
            format!("{what} needs your unlocked DIG account, and the app is not holding one open"),
        )
        .with_hint(UNLOCK_HINT)
    }

    /// The active profile's receive address from `residency`, or the refusal that names why not.
    ///
    /// Split out because the balance needs the SAME address, resolved the same way: two derivations
    /// could disagree, and a balance attributed to the wrong profile is the money lie this seam is
    /// shaped to make impossible.
    fn receive_address(residency: &AccountResidency) -> Result<String, GatewayError> {
        match residency.observe_receiving_address() {
            AddressObservation::Derived(address) => Ok(address),
            AddressObservation::Locked => Err(Self::locked("reading your receive address")),
            // Unlocking is NOT the way back here — unlocking is not what is missing — so this must
            // not carry the unlock hint, which would send a person to do a thing that cannot help.
            AddressObservation::DerivationFailed => Err(GatewayError::new(
                ErrorCode::IoError,
                "your account is unlocked, but its receive address could not be derived",
            )
            .with_hint("check the DIG app's Wallet tab, which reports the same fault in full")),
            // The open unlock derives at a profile the user has since left, so the only address in
            // reach belongs to somebody else's name (dig_ecosystem#2496). Naming the wrong profile's
            // address would be a worse answer than none.
            AddressObservation::WalletBehindActiveProfile => Err(GatewayError::new(
                ErrorCode::Locked,
                "your open account is still deriving at the profile you switched away from, so it \
                 has no address for the active one",
            )
            .with_hint(UNLOCK_HINT)),
        }
    }

    /// The registry index of the profile called `did`, or a `NOT_FOUND` naming it.
    ///
    /// Resolved from the LIVE registry inside `residency` — never from a separately loaded file
    /// session — so the index handed to a switch is one the app itself currently recognises.
    fn index_of(residency: &AccountResidency, did: &str) -> Result<ProfileIx, GatewayError> {
        ProfilesReading::of_session(residency.profiles())
            .rows()
            .unwrap_or_default()
            .iter()
            .find(|row| row.did == did)
            .map(|row| row.ix)
            .ok_or_else(|| {
                GatewayError::new(
                    ErrorCode::NotFound,
                    format!("no profile on this host has the DID {did}"),
                )
                .with_hint("run `diga profiles list` to see the DIDs this account holds")
            })
    }

    /// Make `did` the profile the account derives at, through the registry the app itself holds.
    ///
    /// # Why it goes through the residency and not through [`session`](Self::session)
    ///
    /// The app's [`ProfileSession`] is an in-memory registry that persists to the same file. Writing
    /// that file through a second, independently loaded session would leave the app deriving at the
    /// OLD index — its receive address, its per-profile DEK and its identity key all unchanged —
    /// while the file said otherwise. The switch would read as done and would not be.
    fn switch_active(&self, did: &str, what: &str) -> Result<(), GatewayError> {
        let residency = self.unlocked(what)?;
        let ix = Self::index_of(&residency, did)?;
        residency
            .profiles()
            .switch_to(ix)
            .map(|_| ())
            .map_err(|why| {
                GatewayError::new(
                    ErrorCode::IoError,
                    format!("the active profile could not be changed: {why}"),
                )
                .with_hint("the registry lives at profiles/registry.json in the DIG data directory")
            })
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
    ///
    /// Read from the LIVE registry when the app has an account open, and from the file otherwise —
    /// so a `list` immediately after a `select` reflects the switch that just happened rather than
    /// whatever the file said when the session was last loaded.
    fn profiles(&self) -> Result<Vec<ProfileSummary>, GatewayError> {
        let reading = match self.account.read() {
            Some(residency) => ProfilesReading::of_session(residency.profiles()),
            None => ProfilesReading::of_session(&self.session()?),
        };
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
    ///
    /// # This one refuses on purpose even with the account open
    ///
    /// Unlike the verbs above it, the blocker here was never the lock. A mint spends the user's
    /// money and discloses what it will cost before it takes consent (dig_ecosystem#2989); a lane
    /// that started one would spend from a terminal invocation with no window to disclose anything.
    /// So it stays `DENIED`, and it names the money as the reason rather than the lock, because
    /// unlocking would not change the answer.
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

    /// Make the profile identified by `did` the active one.
    fn select_profile(&self, did: &str) -> Result<(), GatewayError> {
        self.switch_active(did, "switching the active profile")
    }

    /// The active profile's DID, read straight from the registry.
    fn default_profile(&self) -> Result<Option<String>, GatewayError> {
        Ok(self
            .profiles()?
            .into_iter()
            .find(|profile| profile.active)
            .map(|profile| profile.did))
    }

    /// See [`HostIdentity::select_profile`]: the same registry write, and on this host the same
    /// meaning — the profile the account derives at IS the one it presents.
    fn set_default_profile(&self, did: &str) -> Result<(), GatewayError> {
        self.switch_active(did, "setting the default profile")
    }

    /// The active profile's wallet receive address, derived from the open account.
    fn wallet_address(&self) -> Result<String, GatewayError> {
        let residency = self.unlocked("reading your receive address")?;
        Self::receive_address(&residency)
    }

    /// The active profile's spendable XCH balance, in mojos.
    ///
    /// Two things must both be true: the account is open (the address is seed-derived) and a node
    /// answered (the balance is a CHAIN reading). Each failure is reported as itself — the lock and
    /// the node are different remedies, and telling a person to start a node they are already
    /// running was the exact fault dig_ecosystem#2325 removed.
    ///
    /// It refuses rather than returning `0`. A zero here is indistinguishable from an empty wallet,
    /// and a command line that reports a funded account as empty is the money lie this whole seam is
    /// shaped to make impossible — the app's own model keeps `Pending` and `Unknown` distinct from
    /// `Known { 0 }` for exactly this reason.
    fn wallet_balance(&self) -> Result<u64, GatewayError> {
        let residency = self.unlocked("reading your balance")?;
        let address = Self::receive_address(&residency)?;
        let Some(wallet) = self.wallet.as_ref() else {
            return Err(GatewayError::new(
                ErrorCode::NotConnected,
                "your balance is a chain reading, and this app has no node to read it from",
            )
            .with_hint(NO_NODE_HINT));
        };
        wallet
            .balance(BalanceRequest {
                address,
                asset: Asset::Xch,
            })
            .map(|answer| answer.balance)
            .map_err(balance_refusal)
    }

    /// Refused — see this module's `dig_ecosystem#908` note. Unlocking does not change the answer,
    /// so this refusal names the confirm window rather than the lock.
    fn sign(&self, _message: &[u8]) -> Result<Vec<u8>, GatewayError> {
        Err(GatewayError::new(
            ErrorCode::Denied,
            "signing is confirmed in the DIG app itself, so the approval window is one you can see",
        )
        .with_hint("run the signature from the DIG app"))
    }
}

/// Turn a failed chain read into the refusal that names its OWN remedy.
///
/// The split that matters is reachability versus everything else: "no node answered" sends a person
/// to start one, and every other failure must not, because a person whose node is running and
/// healthy would then be chasing a fault that is not theirs.
fn balance_refusal(why: WalletError) -> GatewayError {
    match why {
        WalletError::EngineUnreachable(detail) => GatewayError::new(
            ErrorCode::NotConnected,
            format!("no DIG node answered the balance read: {detail}"),
        )
        .with_hint(NO_NODE_HINT),
        other => GatewayError::new(
            ErrorCode::EngineError,
            format!("the balance could not be read: {other}"),
        )
        .with_hint("the DIG app's Wallet tab reports the same read, with the node it asked"),
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
    use crate::account::residency::test_support::residency_with_profiles;
    use crate::session_lock::SessionKeys;
    use crate::wallet::engine::{
        BalanceResponse, BroadcastRequest, BroadcastResponse, CoinsRequest, CoinsResponse,
    };
    use dig_session::ENTROPY_LEN;

    /// Write a registry holding `profiles` with `active_ix` active, exactly where the production
    /// store reads it, so the test exercises the real path resolution rather than a handed-in store.
    fn registry_under(dir: &Path, profiles: &[(u32, Option<&str>)], active_ix: u32) {
        let entries: Vec<_> = profiles
            .iter()
            .map(|(ix, label)| (ProfileIx(*ix), *label))
            .collect();
        let json = test_support::registry_json(&entries, ProfileIx(active_ix));
        let path = FileRegistryStore::under(dir).path().to_path_buf();
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, json).unwrap();
    }

    /// A residency over the registry FILE under `dir`, exactly as the app's own boot builds one —
    /// so a switch made through it lands where [`HostIdentity`] reads, and a test cannot pass by
    /// writing somewhere nobody looks.
    /// The fixed seed every fixture residency here derives from. Fixed rather than random so a test
    /// may assert the address the balance verb read is THIS account's, not merely address-shaped.
    const FIXTURE_SEED: [u8; ENTROPY_LEN] = [7u8; ENTROPY_LEN];

    fn residency_over(dir: &Path) -> AccountResidency {
        let session = ProfileSession::load(Arc::new(FileRegistryStore::under(dir)))
            .expect("the fixture registry loads");
        residency_with_profiles(&FIXTURE_SEED, session)
    }

    /// A [`WalletEngine`] that answers one balance, or one failure.
    ///
    /// It records the WHOLE request — address AND asset — not just the address. Recording only the
    /// address would make the double answer the same figure for XCH and for DIG, so a verb that
    /// asked for the wrong asset would return a number the test would happily accept: a DIG balance
    /// reported as XCH, which is the money lie this seam exists to prevent. The double has to be
    /// able to tell the two apart before a test can assert the verb does.
    /// What the double was asked. An `Rc` so the TEST can keep a handle while the identity owns the
    /// engine — the engine is moved into the identity under test, so a log reachable only through
    /// the engine would be unreachable exactly when the assertion needs it.
    type AskedLog = std::rc::Rc<std::cell::RefCell<Vec<(String, Asset)>>>;

    struct OneAnswerWallet(Result<u64, WalletError>, AskedLog);

    impl OneAnswerWallet {
        fn answering(mojos: u64) -> Self {
            Self(Ok(mojos), AskedLog::default())
        }

        fn failing(why: WalletError) -> Self {
            Self(Err(why), AskedLog::default())
        }

        /// A handle on every (address, asset) this engine is asked for, so a test can assert WHICH
        /// account and WHICH asset were read rather than only that a number came back.
        fn asked(&self) -> AskedLog {
            AskedLog::clone(&self.1)
        }
    }

    impl WalletEngine for OneAnswerWallet {
        fn broadcast(&self, _: BroadcastRequest) -> Result<BroadcastResponse, WalletError> {
            unreachable!("the lane never broadcasts")
        }

        fn coins(&self, _: CoinsRequest) -> Result<CoinsResponse, WalletError> {
            unreachable!("the lane never reads coins")
        }

        fn balance(&self, request: BalanceRequest) -> Result<BalanceResponse, WalletError> {
            self.1.borrow_mut().push((request.address, request.asset));
            match &self.0 {
                Ok(balance) => Ok(BalanceResponse {
                    balance: *balance,
                    // The node's own replica, caught up — the ordinary case, so the verb is exercised
                    // on the reading it will almost always be handed rather than an exotic one.
                    as_of: crate::wallet::engine::BalanceAsOf::Replica {
                        height: 9_000_000,
                        caught_up: true,
                    },
                }),
                Err(why) => Err(clone_wallet_error(why)),
            }
        }
    }

    /// [`WalletError`] is not `Clone`, and the double must be able to answer twice.
    fn clone_wallet_error(why: &WalletError) -> WalletError {
        match why {
            WalletError::EngineUnreachable(d) => WalletError::EngineUnreachable(d.clone()),
            other => WalletError::Engine(other.to_string()),
        }
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

    /// A lane with NO account published refuses every seed-bound verb with a catalogued code and a
    /// remedy — and, critically, none of them invents a value. A `wallet_balance` of `0` would read
    /// as an empty wallet.
    ///
    /// This is the state the lane serves in from start-up until the user unlocks.
    #[test]
    fn with_no_account_published_seed_bound_verbs_refuse_and_never_substitute_a_value() {
        let dir = tempfile::tempdir().unwrap();
        registry_under(dir.path(), &[(0, Some("home"))], 0);
        let did = test_support::expected_did(ProfileIx(0));
        // A WORKING wallet engine is wired deliberately: the refusal must come from the lock, not
        // from the absence of a node. Without this the test could not tell the two apart.
        let identity = HostIdentity::under(dir.path())
            .with_wallet(Box::new(OneAnswerWallet::answering(42_000_000_000)));

        for error in [
            identity.wallet_address().unwrap_err(),
            identity.wallet_balance().unwrap_err(),
            identity.select_profile(&did).unwrap_err(),
            identity.set_default_profile(&did).unwrap_err(),
        ] {
            assert_eq!(error.code, ErrorCode::Locked);
            assert_eq!(error.hint.as_deref(), Some(UNLOCK_HINT));
        }
        assert!(identity.sign(b"anything").is_err(), "the CLI never signs");
    }

    /// **The unlocked direction.** With the app's account published and open, the address verb
    /// returns a real `xch1…` rather than a refusal — the whole point of dig-app#270.
    #[test]
    fn an_unlocked_account_answers_the_address_verb() {
        let dir = tempfile::tempdir().unwrap();
        registry_under(dir.path(), &[(0, Some("home"))], 0);
        let live = LiveAccount::empty();
        live.publish(residency_over(dir.path()));

        let address = HostIdentity::under(dir.path())
            .with_account(live)
            .wallet_address()
            .expect("an unlocked account has a receive address");

        assert!(
            address.starts_with("xch1"),
            "a real mainnet receive address, not a placeholder: {address}"
        );
    }

    /// **The locked direction, on an account that WAS open.** The truthful control matters: this
    /// residency demonstrably answered before the lock, so a refusal afterwards can only come from
    /// the lock being consulted — an implementation that never refuses would pass a
    /// never-was-unlocked fixture and fail this one.
    #[test]
    fn locking_an_open_account_returns_the_lane_to_refusing() {
        let dir = tempfile::tempdir().unwrap();
        registry_under(dir.path(), &[(0, Some("home"))], 0);
        let residency = residency_over(dir.path());
        let live = LiveAccount::empty();
        live.publish(residency.clone());
        let identity = HostIdentity::under(dir.path())
            .with_account(live)
            .with_wallet(Box::new(OneAnswerWallet::answering(42_000_000_000)));

        assert!(
            identity.wallet_address().is_ok(),
            "control: the account answers before the lock, or this test proves nothing"
        );
        assert!(
            identity.wallet_balance().is_ok(),
            "control: so does the balance"
        );

        residency.lock_all();

        for error in [
            identity.wallet_address().unwrap_err(),
            identity.wallet_balance().unwrap_err(),
        ] {
            assert_eq!(error.code, ErrorCode::Locked);
            assert_eq!(error.hint.as_deref(), Some(UNLOCK_HINT));
        }
    }

    /// **The unlocked balance direction**, and it asserts WHICH address was read — a balance
    /// attributed to the wrong account is the failure this verb exists to avoid, and a test that
    /// only checked the number could not see it.
    #[test]
    fn an_unlocked_account_answers_the_balance_verb_for_its_own_address() {
        let dir = tempfile::tempdir().unwrap();
        registry_under(dir.path(), &[(0, Some("home"))], 0);
        let live = LiveAccount::empty();
        live.publish(residency_over(dir.path()));
        let wallet = OneAnswerWallet::answering(42_000_000_000);
        // Take the address independently of the verb under test, so the assertion below compares
        // two separately obtained facts rather than one fact with itself.
        let expected = HostIdentity::under(dir.path())
            .with_account(live.clone())
            .wallet_address()
            .expect("unlocked");

        // Keep the log before the engine is moved into the identity under test.
        let asked = wallet.asked();
        let identity = HostIdentity::under(dir.path())
            .with_account(live)
            .with_wallet(Box::new(wallet));

        let balance = identity
            .wallet_balance()
            .expect("an open account and a node");
        assert_eq!(balance, 42_000_000_000, "the node's own figure, unmodified");

        assert_eq!(
            asked.borrow().as_slice(),
            [(expected, Asset::Xch)],
            "the balance must be read for THIS account's address, and for XCH — a figure read for \
             another address or another asset is the money lie this verb exists to avoid"
        );
    }

    /// An open account with no node reachable refuses by naming the NODE, not the lock. Telling a
    /// person to unlock an app they just unlocked is the fault dig-app#270 is about, inverted.
    #[test]
    fn an_open_account_with_no_node_names_the_node_rather_than_the_lock() {
        let dir = tempfile::tempdir().unwrap();
        registry_under(dir.path(), &[(0, Some("home"))], 0);
        let live = LiveAccount::empty();
        live.publish(residency_over(dir.path()));

        let no_engine = HostIdentity::under(dir.path())
            .with_account(live.clone())
            .wallet_balance()
            .unwrap_err();
        assert_eq!(no_engine.code, ErrorCode::NotConnected);

        let unreachable = HostIdentity::under(dir.path())
            .with_account(live)
            .with_wallet(Box::new(OneAnswerWallet::failing(
                WalletError::EngineUnreachable("connection refused".into()),
            )))
            .wallet_balance()
            .unwrap_err();
        assert_eq!(unreachable.code, ErrorCode::NotConnected);
        assert_ne!(
            unreachable.hint.as_deref(),
            Some(UNLOCK_HINT),
            "an unreachable node is not fixed by unlocking"
        );
    }

    /// **The switch, proved by PLACEMENT.** The assertion that matters is on the residency's OWN
    /// live registry, not on the file: an implementation that wrote the file through a second
    /// session would leave the app deriving at the old index while the file said otherwise, and a
    /// file-only assertion would call that a pass.
    #[test]
    fn selecting_a_profile_moves_the_registry_the_app_itself_derives_from() {
        let dir = tempfile::tempdir().unwrap();
        registry_under(dir.path(), &[(0, Some("home")), (1, Some("work"))], 0);
        let residency = residency_over(dir.path());
        let live = LiveAccount::empty();
        live.publish(residency.clone());
        let identity = HostIdentity::under(dir.path()).with_account(live);
        let target = test_support::expected_did(ProfileIx(1));
        assert_eq!(
            residency.profiles().active_ix(),
            ProfileIx(0),
            "control: the app starts on profile 0"
        );

        identity.select_profile(&target).expect("the switch lands");

        assert_eq!(
            residency.profiles().active_ix(),
            ProfileIx(1),
            "the LIVE registry the app derives from must have moved, not merely the file"
        );
        assert_eq!(
            identity.default_profile().unwrap().as_deref(),
            Some(target.as_str()),
            "and the lane reports the profile it just selected"
        );
    }

    /// `set-default` is the same operation and must reach the same live registry — asserted
    /// separately, because two verbs sharing an implementation today is a fact about today.
    #[test]
    fn setting_the_default_profile_moves_the_same_live_registry() {
        let dir = tempfile::tempdir().unwrap();
        registry_under(dir.path(), &[(0, Some("home")), (1, Some("work"))], 0);
        let residency = residency_over(dir.path());
        let live = LiveAccount::empty();
        live.publish(residency.clone());

        HostIdentity::under(dir.path())
            .with_account(live)
            .set_default_profile(&test_support::expected_did(ProfileIx(1)))
            .expect("the switch lands");

        assert_eq!(residency.profiles().active_ix(), ProfileIx(1));
    }

    /// A DID this account does not hold is `NOT_FOUND`, not `LOCKED` — the account IS open, so the
    /// lock is the wrong fault and would send a person to do a thing that cannot help.
    #[test]
    fn selecting_an_unknown_did_reports_not_found_rather_than_locked() {
        let dir = tempfile::tempdir().unwrap();
        registry_under(dir.path(), &[(0, Some("home"))], 0);
        let live = LiveAccount::empty();
        live.publish(residency_over(dir.path()));

        let error = HostIdentity::under(dir.path())
            .with_account(live)
            .select_profile("did:chia:1nobodyholdsthisone")
            .unwrap_err();

        assert_eq!(error.code, ErrorCode::NotFound);
    }

    /// Creating a profile and signing stay refused with the account OPEN, and each names its own
    /// reason — money and the confirm window respectively. Unlocking changes neither, so a refusal
    /// carrying the unlock hint would be misdirection.
    #[test]
    fn creation_and_signing_stay_refused_with_the_account_open_and_name_their_own_reasons() {
        let dir = tempfile::tempdir().unwrap();
        registry_under(dir.path(), &[(0, Some("home"))], 0);
        let live = LiveAccount::empty();
        live.publish(residency_over(dir.path()));
        let identity = HostIdentity::under(dir.path()).with_account(live);

        // CONTROL, and it comes first: this test claims these two verbs refuse for a reason that is
        // NOT the lock, which is only meaningful if the account is genuinely open. Without this the
        // test passes just as happily against a lane that refuses everything -- measured, by
        // reverting the unlock path and watching it stay green while its six siblings went red.
        assert!(
            identity.wallet_address().is_ok(),
            "the account must be OPEN here, or this test proves nothing about WHY these two refuse"
        );

        let create = identity
            .begin_profile_creation(ProfileSeedRequest::new())
            .unwrap_err();
        assert_eq!(create.code, ErrorCode::Denied);
        assert!(
            create.message.contains("XCH"),
            "the reason is the money it spends: {}",
            create.message
        );
        assert_ne!(create.hint.as_deref(), Some(UNLOCK_HINT));

        let sign = identity.sign(b"anything").unwrap_err();
        assert_eq!(sign.code, ErrorCode::Denied);
        assert_ne!(
            sign.hint.as_deref(),
            Some(UNLOCK_HINT),
            "the missing thing is the confirm window, not the key"
        );
    }
}
