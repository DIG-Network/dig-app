//! [`ProfileSession`] — the app's ONE live copy of `dig_account::ProfileRegistry`, and the only
//! place the active profile is stored (dig_ecosystem#2398).
//!
//! # The rule
//!
//! **Nothing else in dig-app owns the active index.** Every derivation seam re-reads it here per
//! operation, exactly as [`AccountResidency`](crate::account::residency::AccountResidency) already
//! re-reads the unlocked account per operation for lock liveness. That is what makes a stale index
//! unrepresentable rather than merely detectable: `ResidencySigner` and `ResidencySealer` have no
//! index field to go stale, so a switch cannot half-land across handles a serving thread already
//! holds.
//!
//! # Lock ordering, stated so it can be checked
//!
//! [`active_ix`](ProfileSession::active_ix) takes the registry read lock, copies a `u32`, and
//! releases it **before** any caller touches the account mutex. **No path may hold a registry guard
//! across `AccountResidency`'s `inner.lock()`** — the two locks are always taken in that order and
//! never nested, so the pair cannot deadlock. This is satisfiable precisely because every derivation
//! seam needs nothing but the scalar.
//!
//! # Why it is a registry and not a preference
//!
//! The registry is what the CHAIN confirmed, so a switch is not a display setting: it changes the
//! per-profile DEK and the identity signing key at once, and moves where money will arrive as soon
//! as the wallet can follow (`dig_account::ActiveSwitch`). [`ProfileSwitched`] is `#[must_use]` for
//! the same reason dig-account's own switch value is — but the obligation it carries is
//! **disclosure**, not a rebuild. Nothing is rebuilt on a switch because nothing holds a copy to
//! rebuild: every profile-scoped seam re-reads the active index per operation (the rule above), and
//! the sign-service router lives on a serving thread no switching code can reach, so a rebuild
//! contract would be one no consumer could satisfy.
//!
//! # Persistence
//!
//! `<brand_dir>/profiles/registry.json`, in PLAINTEXT. Two deliberate choices:
//!
//! - **The `profiles/` namespace**, not the keystore's directory. `profiles/<did-hash>/` is already
//!   where per-profile state lives ([`crate::storage::profile_dir`]), so a registry *of* profiles
//!   belongs beside it — and `<brand_dir>/account/` is owned by `dig_session::FileBackend`, which is
//!   another crate's directory to write into.
//! - **Plaintext, via [`write_durably`](crate::storage::write_durably) rather than a sealed blob.**
//!   The registry holds no secret — an HD index, a `did:chia:` string, coin ids, heights, a label,
//!   all public. Sealing it under the profile DEK would make an account's profile list unreadable
//!   while LOCKED, which defeats the property dig-account built the registry for: a host can list
//!   profiles on its first frame, before any unlock ceremony.

use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};

use dig_account::mint::MintError;
use dig_account::registry::{ProfileEndOutcome, ProfileRegistry, ProfileVisibility};
use dig_account::{AccountError, ActiveSwitch, ProfileIx};

use crate::account::active_profile::{ActiveSlot, MintTarget, WalletSlot};

/// A failure to read, mutate or persist the profile registry.
#[derive(Debug, thiserror::Error)]
pub enum ProfileError {
    /// The registry itself refused the change — most often
    /// [`ProfileNotFound`](AccountError::ProfileNotFound) when a switch names a profile the chain has
    /// not confirmed. Fail-closed: the active slot is left exactly where it was.
    #[error("the profile registry refused the change: {0}")]
    Registry(#[source] AccountError),

    /// The registry file could not be read or written. A switch that cannot be persisted is REFUSED
    /// and rolled back, because a switch that silently reverts on the next start would move the
    /// user's receive address back without telling them.
    #[error("the profile registry could not be {action}: {source}")]
    Io {
        /// `read` or `written` — which half failed, so a permissions fault is distinguishable from a
        /// missing directory.
        action: &'static str,
        /// The underlying filesystem error.
        #[source]
        source: std::io::Error,
    },

    /// The stored registry is not a registry any more: unparseable, or violating one of the four
    /// invariants dig-account re-checks on deserialize (a hand-edited file is untrusted input).
    #[error("the stored profile registry is unusable: {0}")]
    Corrupt(String),
}

/// Whether the registry reached the disk. Carried BESIDE a mint's own outcome, never folded into it.
#[derive(Debug)]
pub enum PersistOutcome {
    /// The store accepted the write. This host will remember the mint across a restart.
    Written,
    /// The store refused it. The registry in memory is still correct and the next start will not
    /// know about it.
    NotWritten(ProfileError),
}

/// What went wrong inside [`ProfileSession::with_journal`] — the mint, the persist, or both.
///
/// # Why this is not simply a [`MintError`]
///
/// A mint that SUCCEEDED against a store that refused the write is not a mint failure, and it is
/// not a success either: the user may have paid for a DID this computer will not remember. Returning
/// `MintError` would have no way to say that, so a caller would either lose the fact or have to
/// remember to ask a second question. Here the persist result is a field, so there is nothing to
/// forget — reading the error at all puts it in front of the reader.
#[derive(Debug)]
pub struct MintDoorError {
    /// The mint's own failure, or `None` when the mint SUCCEEDED and only the write did not.
    pub mint: Option<MintError>,
    /// Whether the registry reached the disk, whatever the mint did.
    pub persisted: PersistOutcome,
}

impl MintDoorError {
    /// Whether this host may have paid for a mint it will not remember after a restart.
    ///
    /// The one question a surface must ask before telling anybody to try again.
    pub fn may_be_forgotten(&self) -> bool {
        matches!(self.persisted, PersistOutcome::NotWritten(_))
    }
}

impl std::fmt::Display for MintDoorError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match (&self.mint, &self.persisted) {
            (Some(mint), PersistOutcome::Written) => write!(f, "the profile mint failed: {mint}"),
            (Some(mint), PersistOutcome::NotWritten(io)) => write!(
                f,
                "the profile mint failed ({mint}) AND its record could not be saved ({io}); \
                 a bundle may already have been pushed"
            ),
            (None, PersistOutcome::NotWritten(io)) => write!(
                f,
                "the profile mint went ahead and its record could not be saved ({io}); \
                 do NOT start another one"
            ),
            // Unreachable by construction: `with_journal` returns `Ok` for this pair.
            (None, PersistOutcome::Written) => write!(f, "the profile mint door reported no fault"),
        }
    }
}

impl std::error::Error for MintDoorError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match (&self.mint, &self.persisted) {
            (Some(mint), _) => Some(mint),
            (None, PersistOutcome::NotWritten(io)) => Some(io),
            (None, PersistOutcome::Written) => None,
        }
    }
}

/// Where a [`ProfileSession`] reads and writes its registry.
///
/// A trait — modelled on the settings pane's `ConfigStore` — so
/// the session's behaviour around a write, **including a write that does not land**, is testable
/// without a filesystem. That is not a convenience: the rollback path is the one that protects a
/// user's receive address, and a test that could not lose a write could not exercise it.
pub trait RegistryStore: Send + Sync {
    /// The registry as it is stored right now. A store that has never been written yields
    /// [`ProfileRegistry::empty`] — an account that has never minted, which is the truth rather than
    /// an error.
    fn read(&self) -> Result<ProfileRegistry, ProfileError>;

    /// Persist `registry`, durably enough that a crash immediately afterwards still sees it.
    fn write(&self, registry: &ProfileRegistry) -> Result<(), ProfileError>;
}

/// `<brand_dir>/profiles/registry.json` — the production store.
pub struct FileRegistryStore {
    path: PathBuf,
}

impl FileRegistryStore {
    /// The store under `brand_dir`. Creating the file is deferred to the first write, so merely
    /// booting an account that has never minted touches no disk.
    pub fn under(brand_dir: &Path) -> Self {
        Self {
            path: brand_dir.join("profiles").join("registry.json"),
        }
    }

    /// The file this store reads and writes.
    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl RegistryStore for FileRegistryStore {
    fn read(&self) -> Result<ProfileRegistry, ProfileError> {
        match std::fs::read_to_string(&self.path) {
            Ok(json) => ProfileRegistry::from_json(&json)
                .map_err(|why| ProfileError::Corrupt(why.to_string())),
            // Never minted, so nothing was ever written. An empty registry IS that state.
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(ProfileRegistry::empty()),
            Err(source) => Err(ProfileError::Io {
                action: "read",
                source,
            }),
        }
    }

    fn write(&self, registry: &ProfileRegistry) -> Result<(), ProfileError> {
        let json = registry
            .to_json()
            .map_err(|why| ProfileError::Corrupt(why.to_string()))?;
        let io = |source| ProfileError::Io {
            action: "written",
            source,
        };

        let directory = self.path.parent().expect("the registry path has a parent");
        std::fs::create_dir_all(directory).map_err(io)?;
        crate::storage::restrict_to_owner(directory).map_err(io)?;

        // The same crash-safe idiom every security-critical file here is written with: an owner-only
        // temp file, fsynced, renamed over the target, and the parent directory fsynced so the rename
        // itself is durable.
        crate::storage::write_durably(
            &self.path,
            &self.path.with_extension("json.tmp"),
            json.as_bytes(),
        )
        .map_err(io)?;
        crate::storage::restrict_to_owner(&self.path).map_err(io)
    }
}

/// A registry held in memory only — for an account with nowhere to persist, and for tests.
#[derive(Default)]
pub struct MemoryRegistryStore {
    stored: std::sync::Mutex<Option<String>>,
}

impl MemoryRegistryStore {
    /// An empty store: an account that has never minted.
    pub fn empty() -> Self {
        Self::default()
    }

    /// A store already holding `json` — how a test stands up an account with confirmed profiles
    /// without needing dig-account's crate-private mint evidence.
    pub fn seeded(json: impl Into<String>) -> Self {
        Self {
            stored: std::sync::Mutex::new(Some(json.into())),
        }
    }
}

impl RegistryStore for MemoryRegistryStore {
    fn read(&self) -> Result<ProfileRegistry, ProfileError> {
        match self.guard().as_deref() {
            None => Ok(ProfileRegistry::empty()),
            Some(json) => ProfileRegistry::from_json(json)
                .map_err(|why| ProfileError::Corrupt(why.to_string())),
        }
    }

    fn write(&self, registry: &ProfileRegistry) -> Result<(), ProfileError> {
        let json = registry
            .to_json()
            .map_err(|why| ProfileError::Corrupt(why.to_string()))?;
        *self.guard() = Some(json);
        Ok(())
    }
}

impl MemoryRegistryStore {
    fn guard(&self) -> std::sync::MutexGuard<'_, Option<String>> {
        self.stored.lock().expect("memory registry store poisoned")
    }
}

/// What a completed switch changed, and what the app must now DISCLOSE.
///
/// `#[must_use]` because a switch changes who the person is to every dapp they are connected to, and
/// changes where their money will arrive as soon as their wallet can follow. That is a fact they have
/// to be told, so a caller that means to say nothing has to say so in code.
///
/// It is deliberately NOT a rebuild obligation. Every profile-scoped seam re-reads the active index
/// per operation ([module docs](self)), so there is no captured assembly left to tear down — and the
/// one that could not have been reached to rebuild anyway is the sign-service router, which lives on
/// a serving thread for the process lifetime.
#[derive(Debug, Clone, PartialEq, Eq)]
#[must_use = "a switch changes the identity key, the at-rest DEK, and where money will arrive — the \
              change MUST be disclosed to the user"]
pub struct ProfileSwitched {
    /// Which index the app moved from and to, as dig-account reported it.
    switch: ActiveSwitch,
    /// The slot as it reads AFTER the mutation — taken from the registry, never assembled from the
    /// caller's request.
    slot: ActiveSlot,
}

impl ProfileSwitched {
    /// The index the app was deriving at before, or `None` when this is the account's first profile.
    pub fn from_ix(&self) -> Option<ProfileIx> {
        self.switch.from
    }

    /// The slot now in force.
    pub fn slot(&self) -> &ActiveSlot {
        &self.slot
    }

    /// The index now in force.
    pub fn to_ix(&self) -> ProfileIx {
        self.switch.to
    }
}

/// The app's live profile registry: one `Arc<RwLock<..>>`, cheap to clone, shared by every seam.
///
/// See the [module docs](self) for the ownership rule and the lock ordering this type's methods
/// hold.
#[derive(Clone)]
pub struct ProfileSession {
    registry: Arc<RwLock<ProfileRegistry>>,
    store: Arc<dyn RegistryStore>,
    /// Why this session's registry could not be LOADED, when that is what happened.
    ///
    /// A session that failed to load falls back to an empty registry so the user still reaches their
    /// money and their recovery phrase — both of which come from the seed alone. But an empty
    /// registry and an unreadable one are different facts, and a list surface that could not tell
    /// them apart would tell somebody who may hold several profiles that they hold none. Carried
    /// here so [`ProfilesReading`](crate::profiles::ProfilesReading) can say which one this is.
    unreadable: Option<Arc<str>>,
}

impl ProfileSession {
    /// Load the session from `store`. A store that has never been written yields an account with no
    /// confirmed profile — [`ActiveSlot::Unprofiled`], deriving at [`ProfileIx::ROOT`].
    pub fn load(store: Arc<dyn RegistryStore>) -> Result<Self, ProfileError> {
        let registry = store.read()?;
        Ok(Self {
            registry: Arc::new(RwLock::new(registry)),
            store,
            unreadable: None,
        })
    }

    /// A session with nothing minted and nowhere to persist — the bootstrap, and the default every
    /// residency starts from.
    pub fn unprofiled() -> Self {
        Self {
            registry: Arc::new(RwLock::new(ProfileRegistry::empty())),
            store: Arc::new(MemoryRegistryStore::empty()),
            unreadable: None,
        }
    }

    /// The session an account boots into when its registry file would not LOAD.
    ///
    /// Behaves exactly like [`unprofiled`](Self::unprofiled) — nothing derives at anything but
    /// [`ProfileIx::ROOT`], and the user's money and recovery phrase stay reachable — while
    /// remembering `why`, so a list surface reports *the registry could not be read* rather than
    /// *this account has no profiles*. The two are different claims and only one of them is true.
    pub fn unreadable(why: impl Into<Arc<str>>) -> Self {
        Self {
            unreadable: Some(why.into()),
            ..Self::unprofiled()
        }
    }

    /// Why this session's registry could not be loaded, or `None` when it loaded.
    pub fn unreadable_reason(&self) -> Option<&str> {
        self.unreadable.as_deref()
    }

    /// The index every key derivation should use, read live.
    ///
    /// **This is the hot path and the lock-ordering rule's whole justification**: it takes the
    /// registry read lock, copies one `u32`, and has released it before returning — so a caller may
    /// take the account mutex immediately afterwards without ever nesting the two.
    pub fn active_ix(&self) -> ProfileIx {
        // The temporary guard is dropped at the end of this statement, before the return.
        let ix = self.read_guard().active().map(|active| active.ix());
        ix.unwrap_or(ProfileIx::ROOT)
    }

    /// The active slot, read live — index, DID and label together, so a surface cannot pair one
    /// profile's index with another's name.
    pub fn slot(&self) -> ActiveSlot {
        ActiveSlot::read(&self.read_guard())
    }

    /// The slot a wallet-bearing account should be OPENED at — the bootstrap while nothing is
    /// confirmed, the active profile's otherwise.
    pub fn wallet_slot(&self) -> WalletSlot {
        let guard = self.read_guard();
        match guard.active() {
            None => WalletSlot::unprofiled(),
            Some(active) => WalletSlot::from_active(active),
        }
    }

    /// The index the NEXT profile mint must target, or `None` when this account has none free.
    /// Distinct from [`wallet_slot`](Self::wallet_slot), which is the index that PAYS for it — see
    /// [`MintTarget`].
    ///
    /// `None` is a terminal fact about the account, never an error to retry and never an invitation
    /// to substitute an index: see [`MintTarget::next_free`] for why any fallback would hand the
    /// mint an index that may already hold a profile.
    pub fn next_mint_target(&self) -> Option<MintTarget> {
        MintTarget::next_free(&self.read_guard())
    }

    /// Run `f` over the registry under the read lock — the door for list surfaces, which need whole
    /// entries rather than the active index.
    ///
    /// It works while the account is LOCKED, deliberately: nothing here is key material.
    pub fn with_registry<T>(&self, f: impl FnOnce(&ProfileRegistry) -> T) -> T {
        f(&self.read_guard())
    }

    /// Make `ix` the active profile, persist it, and report what changed.
    ///
    /// The order is deliberate. The write lock is taken once; `set_active` mutates; the slot is read
    /// back from the registry **after** the mutation (never assembled from `ix`, which would report
    /// the request rather than the result); the registry is persisted and re-read, so the returned
    /// value is evidence rather than an assumption.
    ///
    /// # The switch cannot be dropped in silence
    ///
    /// [`ProfileSwitched`] is `#[must_use]`, so a caller that discards one is refused under
    /// `deny(unused_must_use)` — which is what makes the disclosure obligation a compiler rule
    /// rather than a convention. This example exists to FAIL to compile; deleting the attribute
    /// makes it compile and the doctest goes red.
    ///
    /// The `Result` is unwrapped FIRST, deliberately. Writing `session.switch_to(..);` would fail to
    /// compile whatever this type is annotated with, because `Result` carries its own `#[must_use]` —
    /// so it would pin nothing here while looking exactly like a guard that did. What is discarded
    /// below is a bare [`ProfileSwitched`].
    ///
    /// ```compile_fail
    /// #![deny(unused_must_use)]
    /// use dig_app_core::account::profile_session::ProfileSession;
    /// use dig_app_core::account::ProfileIx;
    ///
    /// let session = ProfileSession::unprofiled();
    /// match session.switch_to(ProfileIx::ROOT) {
    ///     Ok(switched) => switched,
    ///     Err(why) => panic!("{why}"),
    /// };
    /// ```
    ///
    /// Saying so in code is still allowed, and is the control for the case above: the two differ by
    /// the `let _ =` alone, so the refusal cannot be blamed on anything else in the snippet. Neither
    /// is RUN — an unprofiled session has no confirmed profile to switch to, and what is under test
    /// here is what the compiler accepts, not what the switch returns.
    ///
    /// ```no_run
    /// #![deny(unused_must_use)]
    /// use dig_app_core::account::profile_session::ProfileSession;
    /// use dig_app_core::account::ProfileIx;
    ///
    /// let session = ProfileSession::unprofiled();
    /// let _ = match session.switch_to(ProfileIx::ROOT) {
    ///     Ok(switched) => switched,
    ///     Err(why) => panic!("{why}"),
    /// };
    /// ```
    ///
    /// # Errors
    ///
    /// [`ProfileError::Registry`] when `ix` names no confirmed profile, and [`ProfileError::Io`] /
    /// [`ProfileError::Corrupt`] when the change cannot be persisted. **In every failure the previous
    /// active profile is restored in memory**, so a refused switch leaves the wallet deriving exactly
    /// where the user last saw it — a switch that only half-persisted would move their receive
    /// address back on the next start with no notice.
    pub fn switch_to(&self, ix: ProfileIx) -> Result<ProfileSwitched, ProfileError> {
        let mut guard = self.write_guard();
        let previous = guard.clone();

        let switch = match guard.set_active(ix) {
            Ok(switch) => switch,
            Err(why) => return Err(ProfileError::Registry(why)),
        };

        // Persist, then re-read: the value this returns must describe the registry as it now IS.
        let persisted = match self.store.write(&guard).and_then(|()| self.store.read()) {
            Ok(persisted) => persisted,
            Err(why) => {
                *guard = previous;
                return Err(why);
            }
        };

        if ActiveSlot::read(&persisted).ix() != ix {
            *guard = previous;
            return Err(ProfileError::Corrupt(format!(
                "the registry was persisted but does not name profile {ix} as active"
            )));
        }

        *guard = persisted;
        let slot = ActiveSlot::read(&guard);
        Ok(ProfileSwitched { switch, slot })
    }

    /// Show `ix` in this host's lists, or stop showing it, and persist the change.
    ///
    /// # This is a view preference, and the type is what says so
    ///
    /// It returns `()`, not a [`ProfileSwitched`]: nothing derives differently afterwards. The
    /// active profile, the receive address, the DEK and the identity key are all untouched, and the
    /// profile itself — a DID singleton and a store on chain — is untouched too. That is the whole
    /// difference between this and [`switch_to`](Self::switch_to), and it is why this one needs no
    /// disclosure and no `#[must_use]`.
    ///
    /// # Errors
    ///
    /// [`ProfileError::Registry`] when `ix` names no confirmed profile, and — the one worth knowing
    /// about — when `ix` is the ACTIVE profile and `hidden` is true: dig-account refuses that
    /// (`AccountError::ActiveProfileCannotBeHidden`), which is what makes "a hidden active profile
    /// shows an empty list while the wallet derives there" unrepresentable rather than merely
    /// guarded against. [`ProfileError::Io`] / [`ProfileError::Corrupt`] when the change cannot be
    /// persisted, in which case **the previous visibility is restored in memory** — a preference
    /// that only half-persisted would come back on the next start with nothing said.
    pub fn set_visibility(&self, ix: ProfileIx, hidden: bool) -> Result<(), ProfileError> {
        let visibility = match hidden {
            true => ProfileVisibility::HiddenFromLists,
            false => ProfileVisibility::Shown,
        };

        let mut guard = self.write_guard();
        let previous = guard.clone();
        if let Err(why) = guard.set_visibility(ix, visibility) {
            return Err(ProfileError::Registry(why));
        }

        match self.store.write(&guard).and_then(|()| self.store.read()) {
            Ok(persisted) => {
                *guard = persisted;
                Ok(())
            }
            Err(why) => {
                *guard = previous;
                Err(why)
            }
        }
    }

    /// Record that `ix` ENDED on chain — both singletons melted, PROVED by a chain read at
    /// `at_height` — and persist it (dig-app#206).
    ///
    /// # Why this exists at all
    ///
    /// A deletion that ends two singletons and leaves this computer still listing the profile is a
    /// surface telling a person something the chain contradicts. The melt is the destruction; this
    /// is the only thing that makes the app agree with it.
    ///
    /// # Only ever from a CONFIRMED melt
    ///
    /// `at_height` must come from a chain read proving BOTH coins spent. dig-account refuses a
    /// height of 0 (`AccountError::ProfileEndHeightZero`) precisely because 0 is what an
    /// unconfirmed read looks like, so a pushed-but-unproved melt cannot be written down as an
    /// ending.
    ///
    /// # The ACTIVE profile, which is the case this is written for
    ///
    /// Deleting the profile the person is currently using is allowed, and dig-account moves the
    /// active slot to the lowest-indexed remaining live profile — or reports
    /// [`ProfileEndOutcome::NoLiveProfileRemains`] when the account has none left. The caller is
    /// handed that outcome rather than a bare `Ok` because those two states read differently to a
    /// person and the app has to say which happened.
    ///
    /// # There is NO rollback, deliberately
    ///
    /// [`switch_to`](Self::switch_to) and [`set_visibility`](Self::set_visibility) restore the
    /// previous registry when a write fails, and that is right for them: both change a recoverable
    /// preference. This one records a destruction that has ALREADY happened on chain and can never
    /// be undone, so reverting it in memory would leave the app confidently listing a profile whose
    /// coins are gone. A failed write is reported, and the in-memory registry keeps the truth.
    ///
    /// # Errors
    ///
    /// [`ProfileError::Registry`] when `ix` names no confirmed profile or `at_height` is 0, and
    /// [`ProfileError::Io`] / [`ProfileError::Corrupt`] when the ending could not be persisted — in
    /// which case it is still in effect in memory and will be re-recorded on a later confirmation.
    pub fn record_melted(
        &self,
        ix: ProfileIx,
        at_height: u32,
    ) -> Result<ProfileEndOutcome, ProfileError> {
        let mut guard = self.write_guard();
        let outcome = guard
            .record_melted(ix, at_height)
            .map_err(ProfileError::Registry)?;
        self.store.write(&guard)?;
        Ok(outcome)
    }

    /// Run a MINT step over the registry and persist the result — the one door through which a
    /// profile mint may touch the journal (dig_ecosystem#2398).
    ///
    /// # Why the persist is inside, and not the caller's to remember
    ///
    /// `dig_account::ProfileMinter::begin_profile_mint` inserts its journal entry **before** it
    /// pushes, and deliberately KEEPS that entry when the push ends in
    /// [`MintError::ChainUnreachable`] — the bundle may yet be included, so the reservation is the
    /// only record naming a DID the user may already have paid for. A call site written as
    /// `minter.begin_profile_mint(&mut registry, ..)?` therefore discards that record on exactly the
    /// path where it matters most, and a real mainnet harness hit precisely that.
    ///
    /// Putting the write between the mutation and the return makes the omission unexpressible: there
    /// is no arrangement of `?` that returns from here without the store having been asked.
    ///
    /// # Why it departs from [`switch_to`](Self::switch_to) and
    /// [`set_visibility`](Self::set_visibility): **there is no rollback**
    ///
    /// Those two restore the previous registry when a write fails, and that is right for them — they
    /// change a view preference or a derivation index, both of which are recoverable by repeating
    /// the action. This one is not: `act` may have PUSHED A BUNDLE, and a journal entry naming a
    /// pushed bundle must never be un-written. Rolling back here would delete the app's only memory
    /// of a spend that is already on the network. They are the pattern somebody will copy; this
    /// paragraph is why they must not copy it here.
    ///
    /// The in-memory registry is likewise kept as `act` left it rather than replaced with a re-read,
    /// so a store that round-trips lossily cannot silently drop the reservation either.
    ///
    /// # Lock ordering
    ///
    /// This holds the registry WRITE lock for the whole of `act`, so `act` MUST NOT take
    /// [`AccountResidency`](crate::account::residency::AccountResidency)'s account mutex — see the
    /// [module docs](self). Callers derive their `ProfileMinter` **before** calling in, which is
    /// exactly what [`crate::account::profile_mint::ProfileMint`] does.
    ///
    /// # Errors
    ///
    /// [`MintDoorError`], which reports the mint and the persist SEPARATELY — including the case
    /// where the mint succeeded and the write did not, which is the loudest outcome here and cannot
    /// be flattened into a mint failure.
    pub fn with_journal<T>(
        &self,
        act: impl FnOnce(&mut ProfileRegistry) -> Result<T, MintError>,
    ) -> Result<T, MintDoorError> {
        let mut guard = self.write_guard();
        let acted = act(&mut guard);

        // Unconditional, and BEFORE the mint's own outcome is inspected: a failed mint may still
        // have left a reservation naming a pushed bundle.
        let persisted = match self.store.write(&guard) {
            Ok(()) => PersistOutcome::Written,
            Err(why) => PersistOutcome::NotWritten(why),
        };

        match (acted, persisted) {
            (Ok(value), PersistOutcome::Written) => Ok(value),
            (Ok(_), persisted) => Err(MintDoorError {
                mint: None,
                persisted,
            }),
            (Err(mint), persisted) => Err(MintDoorError {
                mint: Some(mint),
                persisted,
            }),
        }
    }

    fn read_guard(&self) -> std::sync::RwLockReadGuard<'_, ProfileRegistry> {
        // A poisoned lock means a thread panicked mid-mutation of custody-adjacent state. Fail
        // loudly rather than derive keys from a half-updated registry.
        self.registry.read().expect("profile registry poisoned")
    }

    fn write_guard(&self) -> std::sync::RwLockWriteGuard<'_, ProfileRegistry> {
        self.registry.write().expect("profile registry poisoned")
    }
}

impl std::fmt::Debug for ProfileSession {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ProfileSession")
            .field("slot", &self.slot())
            .finish_non_exhaustive()
    }
}

/// Building registries with CONFIRMED profiles in them, for the tests of every module that switches.
///
/// dig-account's mint evidence (`MintedDid`, `ConfirmedStore`) has no public producer, so no test
/// can construct one and therefore no test can call `record_minted` — that is the unforgeability
/// property, not a gap. (Production reaches it through
/// [`ProfileMintDoor::record`](crate::account::profile_mint::ProfileMintDoor::record), from a
/// `ProfileMintStatus::Confirmed` the chain produced. There is no `ProfileMinter::mint`; the
/// ceremony is the three calls the door wraps.) The one door left open here is the deserialize path,
/// which is not a loophole: it is
/// the SAME path production loads a real registry through, and dig-account re-checks all four
/// invariants on it. A fixture that got past those checks is a registry the production loader would
/// also accept.
#[cfg(any(test, feature = "profile-test-support"))]
pub mod test_support {
    use super::*;

    /// A distinct, stable 32-byte id per `(profile, slot)`.
    ///
    /// # Neither argument is cryptographic, and the second one's name used to say otherwise
    ///
    /// `slot` selects WHICH of a profile's three ids this is — its launcher, its DID coin, or its
    /// store — and `profile` distinguishes one profile's set from another's. Nothing here is a
    /// secret, a key or a salt: these are placeholder chain ids for fixtures, and the values they
    /// produce are recomputed by dig-account's own invariant checks before a fixture is accepted.
    /// The parameter was called `salt`, which is what made a static analyser read a deterministic
    /// test id as a hard-coded cryptographic value (dig_ecosystem#2403).
    fn id(profile: u8, slot: u8) -> chia_protocol::Bytes32 {
        let mut bytes = [0u8; 32];
        bytes[0] = profile;
        bytes[31] = slot;
        chia_protocol::Bytes32::new(bytes)
    }

    /// The `"0x…"` form `chia_protocol::Bytes32` deserializes from.
    fn hex_id(bytes: chia_protocol::Bytes32) -> String {
        format!("0x{}", hex::encode(bytes))
    }

    /// JSON for a registry holding one confirmed profile per `(index, label)`, with `active_ix`
    /// active.
    ///
    /// Each profile gets its own DID coin, and its store is launched FROM that coin — the one
    /// relationship `ProfileAnchor` exists to assert — so these are anchors the real loader accepts.
    pub fn registry_json(profiles: &[(ProfileIx, Option<&str>)], active_ix: ProfileIx) -> String {
        let entries: Vec<String> = profiles
            .iter()
            .map(|(ix, label)| {
                let tag = u8::try_from(ix.0 % 251).unwrap_or(0).saturating_add(1);
                let label = label.map_or("null".to_owned(), |l| format!("\"{l}\""));
                let launcher = id(tag, 1);
                format!(
                    r#"{{"ix":{ix},"anchor":{{"did":"{did}","launcher_id":"{launcher}","did_coin_id":"{did_coin}","did_confirmed_height":{height},"store_launcher_id":"{store}","store_confirmed_height":{height}}},"label":{label},"visibility":"Shown"}}"#,
                    ix = ix.0,
                    // Encoded, never written by hand: dig-account recomputes the DID from the launcher
                    // id and refuses an anchor whose DID does not belong to it — which is exactly the
                    // forgery that check exists to catch, so a literal here would be refused.
                    did = dig_did::did_string_from_launcher_id(launcher),
                    launcher = hex_id(launcher),
                    did_coin = hex_id(id(tag, 2)),
                    store = hex_id(id(tag, 3)),
                    // Saturating, so the helper can express the WHOLE `ProfileIx` range. A plain
                    // add overflows at `u32::MAX` and panics inside the fixture, which reads as a
                    // failing assertion in whatever test needed the ceiling — the exhaustion case
                    // (dig-app#263) is exactly that test.
                    height = 1_000u32.saturating_add(ix.0),
                )
            })
            .collect();
        format!(
            r#"{{"entries":[{}],"active":{},"in_progress":[]}}"#,
            entries.join(","),
            active_ix.0
        )
    }

    /// The DID a fixture profile at `ix` will carry — recomputed the same way the fixture and
    /// dig-account both do, so a test names it without embedding a literal that could drift from the
    /// launcher id it must belong to.
    pub fn expected_did(ix: ProfileIx) -> String {
        let tag = u8::try_from(ix.0 % 251).unwrap_or(0).saturating_add(1);
        dig_did::did_string_from_launcher_id(id(tag, 1))
    }

    /// The store id a fixture profile at `ix` will carry, in the `0x…` form every DIG surface
    /// prints — derived the same way [`registry_json`] derives it, so a test names it without
    /// embedding a literal that could drift from the fixture it is meant to describe.
    pub fn expected_store_id(ix: ProfileIx) -> String {
        let tag = u8::try_from(ix.0 % 251).unwrap_or(0).saturating_add(1);
        hex_id(id(tag, 3))
    }

    /// A registry holding `profiles`, active on the FIRST of them.
    pub fn registry_with(profiles: &[(ProfileIx, Option<&str>)]) -> ProfileRegistry {
        let active = profiles.first().expect("at least one profile").0;
        ProfileRegistry::from_json(&registry_json(profiles, active))
            .expect("the fixture must satisfy dig-account's own invariants")
    }

    /// A session over `profiles`, persisting into memory.
    pub fn session_with(profiles: &[(ProfileIx, Option<&str>)]) -> ProfileSession {
        let active = profiles.first().expect("at least one profile").0;
        ProfileSession::load(Arc::new(MemoryRegistryStore::seeded(registry_json(
            profiles, active,
        ))))
        .expect("the fixture must load")
    }
}

#[cfg(test)]
mod tests {
    use super::test_support::{registry_json, session_with};
    use super::*;

    /// The fee a mint fixture journals. A plausible real figure (0.01 XCH), so nothing passes
    /// because the number is zero.
    const FEE: u64 = 10_000_000;

    /// A mint reservation at `ix`, shaped exactly as `begin_profile_mint` writes one: pushed, with
    /// nothing yet proven.
    fn reserve(registry: &mut ProfileRegistry, ix: ProfileIx) -> Result<(), MintError> {
        use dig_account::registry::journal::{MintStage, PendingMintRecord};
        registry
            .begin_seeded_mint(
                ix,
                MintStage::DidPushed {
                    pending: PendingMintRecord {
                        launcher_id: chia_protocol::Bytes32::new([0x11; 32]),
                        did_coin_id: chia_protocol::Bytes32::new([0x22; 32]),
                        source_coin_id: chia_protocol::Bytes32::new([0x33; 32]),
                        pushed_at_height: 5_412_009,
                    },
                },
                [0x44; 32],
                FEE,
            )
            .map_err(|why| MintError::Journal(why.to_string()))
    }

    /// A store that reads an account with nothing minted and refuses every write — a full disk, or
    /// a directory the user cannot write to.
    struct WriteRefusingStore;

    impl RegistryStore for WriteRefusingStore {
        fn read(&self) -> Result<ProfileRegistry, ProfileError> {
            Ok(ProfileRegistry::empty())
        }
        fn write(&self, _registry: &ProfileRegistry) -> Result<(), ProfileError> {
            Err(ProfileError::Io {
                action: "written",
                source: std::io::Error::other("the disk is full"),
            })
        }
    }

    /// **A mint whose chain could not be reached STILL persists its reservation — provably, by
    /// reloading a fresh session from the same store.**
    ///
    /// Makes impossible: the `?`-discards-the-journal defect. `begin_profile_mint` writes its entry
    /// BEFORE pushing and keeps it on `ChainUnreachable`, because the bundle may yet be included; a
    /// caller that returned early would throw away the only record naming a DID the user may already
    /// have paid for. A real mainnet harness hit exactly that.
    ///
    /// The proof is the RELOAD, not the in-memory registry. Asserting on the live session would be
    /// satisfied by an implementation that never wrote at all — which is the very failure under
    /// test. A second [`ProfileSession`] over the same store can only see what actually landed.
    #[test]
    fn a_mint_that_could_not_reach_the_chain_still_leaves_a_reservation_on_disk() {
        let store = Arc::new(MemoryRegistryStore::empty());
        let session = ProfileSession::load(store.clone()).expect("an empty store loads");

        let failed = session
            .with_journal(|registry| {
                reserve(registry, ProfileIx::ROOT)?;
                // What a push against a dead network returns. The entry above must stay.
                Err::<(), _>(MintError::ChainUnreachable("connection refused".into()))
            })
            .expect_err("an unreachable chain is a failed mint");

        assert!(
            matches!(failed.mint, Some(MintError::ChainUnreachable(_))),
            "the mint's own failure is reported as itself: {failed:?}"
        );
        assert!(
            !failed.may_be_forgotten(),
            "the write succeeded, so nothing here may claim the mint could be forgotten"
        );

        let reloaded = ProfileSession::load(store).expect("the store still parses");
        assert_eq!(
            reloaded.with_registry(|registry| registry.in_progress().len()),
            1,
            "a fresh session must see the reservation, or it never reached the store"
        );
    }

    /// **A reserved index is STILL reserved after a restart, and a second mint at it is refused.**
    ///
    /// Makes impossible: paying twice for one profile by closing and reopening the app.
    /// The retired DID-only mint path's second-push guard (dig-app#210) was a process-lifetime
    /// `Mutex`, which a restart resets; this one is the persisted registry, which a restart does not.
    ///
    /// The control is the SECOND index: the same reloaded session accepts a mint at an index nobody
    /// reserved, so the refusal above is about the reservation rather than about the session being
    /// unable to mint at all.
    #[test]
    fn a_reserved_index_survives_a_reload_and_refuses_a_second_mint() {
        let store = Arc::new(MemoryRegistryStore::empty());
        let session = ProfileSession::load(store.clone()).expect("an empty store loads");
        session
            .with_journal(|registry| reserve(registry, ProfileIx::ROOT))
            .expect("the first reservation goes through");

        let restarted = ProfileSession::load(store).expect("the store still parses");

        let refused = restarted
            .with_journal(|registry| reserve(registry, ProfileIx::ROOT))
            .expect_err("an index already reserved must not be reserved again");
        assert!(
            matches!(refused.mint, Some(MintError::Journal(_))),
            "the registry itself refuses it: {refused:?}"
        );

        // Control: a DIFFERENT index is still mintable, so the refusal is about the reservation.
        restarted
            .with_journal(|registry| reserve(registry, ProfileIx(1)))
            .expect("an unreserved index is still available after a reload");
    }

    /// **A mint that SUCCEEDED against a store that would not write is its own, distinct, louder
    /// outcome.**
    ///
    /// Makes impossible: flattening *you may have paid for a DID this computer cannot remember* into
    /// an ordinary mint failure — after which a surface would sensibly invite a retry, and the
    /// retry pays again.
    ///
    /// The load-bearing assertion is the first: `mint` is `None`, so nothing here can be mistaken
    /// for the mint having failed. The control runs the SAME closure against a store that writes and
    /// requires an `Ok`, so an implementation that failed every mint cannot pass.
    #[test]
    fn a_successful_mint_that_could_not_be_saved_is_not_reported_as_a_failed_mint() {
        let refusing =
            ProfileSession::load(Arc::new(WriteRefusingStore)).expect("the fixture store reads");

        let unsaved = refusing
            .with_journal(|registry| reserve(registry, ProfileIx::ROOT))
            .expect_err("a write that did not land cannot be reported as success");

        assert!(
            unsaved.mint.is_none(),
            "the MINT succeeded; only the write did not: {unsaved:?}"
        );
        assert!(
            unsaved.may_be_forgotten(),
            "the one question a surface must be able to ask, and it must answer yes here"
        );
        assert!(
            unsaved.to_string().contains("do NOT start another one"),
            "the message must warn against the retry that would pay twice: {unsaved}"
        );

        // Control: the identical closure over a store that writes really does succeed.
        ProfileSession::load(Arc::new(MemoryRegistryStore::empty()))
            .expect("an empty store loads")
            .with_journal(|registry| reserve(registry, ProfileIx::ROOT))
            .expect("the same mint against a working store must succeed");
    }

    /// A session over a store that has never been written is unprofiled at ROOT — and says so,
    /// rather than inventing a profile.
    #[test]
    fn an_unwritten_store_loads_as_an_unprofiled_account() {
        let session = ProfileSession::load(Arc::new(MemoryRegistryStore::empty())).unwrap();

        assert_eq!(ActiveSlot::Unprofiled, session.slot());
        assert_eq!(ProfileIx::ROOT, session.active_ix());
        assert_eq!(ProfileIx::ROOT, session.wallet_slot().ix());
        assert_eq!(
            Some(ProfileIx::ROOT),
            session.next_mint_target().map(MintTarget::ix),
            "the first mint must land where the pre-mint address was funded"
        );
    }

    /// A switch moves the live index, reports both ends, and PERSISTS — so a fresh session over the
    /// same store comes up on the new profile.
    ///
    /// The reload is what makes this more than a field assignment: an in-memory-only switch would
    /// satisfy every other assertion here and still put the user back on the old receive address at
    /// the next start.
    #[test]
    fn a_switch_moves_the_live_index_and_survives_a_reload() {
        let store = Arc::new(MemoryRegistryStore::seeded(registry_json(
            &[
                (ProfileIx::ROOT, Some("home")),
                (ProfileIx(1), Some("work")),
            ],
            ProfileIx::ROOT,
        )));
        let session = ProfileSession::load(store.clone()).unwrap();
        assert_eq!(ProfileIx::ROOT, session.active_ix());

        let switched = session.switch_to(ProfileIx(1)).unwrap();

        assert_eq!(Some(ProfileIx::ROOT), switched.from_ix());
        assert_eq!(ProfileIx(1), switched.to_ix());
        assert_eq!(ProfileIx(1), session.active_ix());
        assert_eq!(
            Some(super::test_support::expected_did(ProfileIx(1)).as_str()),
            session.slot().did(),
            "the slot must name the profile switched TO, not the one switched from"
        );
        assert_ne!(
            session.slot().did(),
            Some(super::test_support::expected_did(ProfileIx::ROOT).as_str()),
            "the two fixture profiles must have distinguishable DIDs, or this assertion proves nothing"
        );

        let reloaded = ProfileSession::load(store).unwrap();
        assert_eq!(
            ProfileIx(1),
            reloaded.active_ix(),
            "a switch that does not survive a restart moves the receive address back silently"
        );
    }

    /// Switching to a profile the chain has not confirmed is REFUSED, and leaves the wallet exactly
    /// where it was.
    #[test]
    fn a_switch_to_an_unconfirmed_profile_is_refused_and_changes_nothing() {
        let session = session_with(&[(ProfileIx::ROOT, None)]);

        let refusal = session.switch_to(ProfileIx(9)).unwrap_err();

        assert!(
            matches!(refusal, ProfileError::Registry(_)),
            "expected a registry refusal, got {refusal:?}"
        );
        assert_eq!(ProfileIx::ROOT, session.active_ix());
    }

    /// A switch whose PERSISTENCE fails is rolled back in memory — the wallet does not move.
    ///
    /// This is the assertion the [`RegistryStore`] trait exists for. Without the rollback the app
    /// would derive at the new profile for the rest of the session and revert to the old one on the
    /// next start: the receive address the tray shows and the address the user's funds arrive at
    /// would disagree across a restart, with nothing said.
    #[test]
    fn a_switch_that_cannot_be_persisted_is_rolled_back() {
        struct RefusesToWrite(String);
        impl RegistryStore for RefusesToWrite {
            fn read(&self) -> Result<ProfileRegistry, ProfileError> {
                ProfileRegistry::from_json(&self.0)
                    .map_err(|why| ProfileError::Corrupt(why.to_string()))
            }
            fn write(&self, _registry: &ProfileRegistry) -> Result<(), ProfileError> {
                Err(ProfileError::Io {
                    action: "written",
                    source: std::io::Error::other("the disk is full"),
                })
            }
        }

        let session = ProfileSession::load(Arc::new(RefusesToWrite(registry_json(
            &[(ProfileIx::ROOT, None), (ProfileIx(1), None)],
            ProfileIx::ROOT,
        ))))
        .unwrap();

        let refusal = session.switch_to(ProfileIx(1)).unwrap_err();

        assert!(
            matches!(refusal, ProfileError::Io { .. }),
            "expected an IO refusal, got {refusal:?}"
        );
        assert_eq!(
            ProfileIx::ROOT,
            session.active_ix(),
            "a switch that could not be written must not take effect in memory either"
        );
    }

    /// The file store round-trips through a real directory, and reads an absent file as an account
    /// that has never minted rather than as a fault.
    #[test]
    fn the_file_store_round_trips_and_treats_an_absent_file_as_empty() {
        let dir = tempfile::tempdir().unwrap();
        let store = FileRegistryStore::under(dir.path());

        assert!(store.read().unwrap().is_empty(), "nothing minted yet");
        assert!(!store.path().exists(), "a read must not create the file");

        let registry = super::test_support::registry_with(&[(ProfileIx(2), Some("work"))]);
        store.write(&registry).unwrap();

        assert_eq!(registry, store.read().unwrap());
        assert!(store.path().ends_with("profiles/registry.json") || store.path().exists());
    }

    /// A hand-edited registry file is refused rather than half-trusted.
    #[test]
    fn a_corrupt_registry_file_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let store = FileRegistryStore::under(dir.path());
        std::fs::create_dir_all(dir.path().join("profiles")).unwrap();
        // Active on an index with no entry — invariant 2, which dig-account re-checks on deserialize.
        std::fs::write(
            store.path(),
            r#"{"entries":[],"active":3,"in_progress":[]}"#,
        )
        .unwrap();

        assert!(matches!(store.read(), Err(ProfileError::Corrupt(_))));
    }

    /// **Hiding a profile persists, survives a reload, and changes nothing about derivation.**
    ///
    /// Two properties in one, because a `set_visibility` that quietly moved the active profile would
    /// satisfy a persistence-only test. The reload is what makes the first half load-bearing: an
    /// in-memory-only change would put the profile back in the list at the next start, with nothing
    /// said to the person who hid it.
    #[test]
    fn hiding_a_profile_persists_and_leaves_the_wallet_deriving_where_it_was() {
        let store = Arc::new(MemoryRegistryStore::seeded(registry_json(
            &[
                (ProfileIx::ROOT, Some("home")),
                (ProfileIx(1), Some("work")),
            ],
            ProfileIx::ROOT,
        )));
        let session = ProfileSession::load(store.clone()).unwrap();

        session.set_visibility(ProfileIx(1), true).unwrap();

        assert_eq!(
            ProfileIx::ROOT,
            session.active_ix(),
            "hiding a profile moved the index the wallet derives at"
        );
        let hidden = |session: &ProfileSession| {
            session.with_registry(|r| !r.get(ProfileIx(1)).expect("the entry").is_shown())
        };
        assert!(hidden(&session), "the profile was not hidden in memory");
        assert!(
            hidden(&ProfileSession::load(store.clone()).unwrap()),
            "a hidden profile came back on the next start, so the preference did not persist"
        );

        // And back again: hiding must be undoable, because a minted profile is permanent on chain
        // and a one-way hide would be the closest thing to deleting one this app could do.
        session.set_visibility(ProfileIx(1), false).unwrap();
        assert!(!hidden(&session));
        assert!(!hidden(&ProfileSession::load(store).unwrap()));
    }

    /// **Deleting the ACTIVE profile moves the wallet to the remaining live one, and persists.**
    ///
    /// The case the user asked for by name: *"we should be able to delete all profiles even the
    /// default or active one."* A session that refused, or that left the active slot pointing at a
    /// profile whose coins are gone, fails here.
    ///
    /// # The fixture varies ONE actor
    ///
    /// Two profiles, and only the ACTIVE one is ended. The survivor is the control: it proves the
    /// ending is about the profile that was melted rather than a registry that forgot everything,
    /// and it is the only thing the active slot can legally move TO — so an implementation that
    /// cleared the slot instead of moving it is caught here rather than passing.
    ///
    /// The reload is what makes the persistence half load-bearing. An in-memory-only ending puts a
    /// destroyed profile back in the list at the next start, deriving a wallet at an index whose
    /// singletons no longer exist.
    #[test]
    fn deleting_the_active_profile_moves_the_wallet_to_the_survivor_and_persists() {
        let store = Arc::new(MemoryRegistryStore::seeded(registry_json(
            &[
                (ProfileIx::ROOT, Some("home")),
                (ProfileIx(1), Some("work")),
            ],
            ProfileIx::ROOT,
        )));
        let session = ProfileSession::load(store.clone()).unwrap();

        let outcome = session
            .record_melted(ProfileIx::ROOT, 4_200)
            .expect("the active profile can be deleted");

        assert!(
            matches!(outcome, ProfileEndOutcome::ActiveMoved(_)),
            "deleting the active profile did not move the wallet off it: {outcome:?}"
        );
        let live_ixs = |session: &ProfileSession| {
            session.with_registry(|r| r.live().map(|entry| entry.ix()).collect::<Vec<_>>())
        };
        assert_eq!(
            vec![ProfileIx(1)],
            live_ixs(&session),
            "the melted profile is still listed as live on this computer"
        );
        assert_eq!(
            ProfileIx(1),
            session.active_ix(),
            "the wallet is still deriving at a profile whose singletons are gone"
        );
        // The reload: an ending that only lived in memory would come back at the next start.
        let restarted = ProfileSession::load(store).unwrap();
        assert_eq!(vec![ProfileIx(1)], live_ixs(&restarted));
        assert_eq!(ProfileIx(1), restarted.active_ix());
    }

    /// **Deleting the LAST profile is allowed and says so, rather than being refused.**
    ///
    /// The other half of *"delete all profiles"*. An account with nothing left is a real state, and
    /// the outcome names it — the caller cannot draw an honest surface from a bare `Ok`, because
    /// "moved you to another profile" and "you now have none" are opposite things to be told.
    #[test]
    fn deleting_the_last_profile_reports_that_none_remains() {
        let store = Arc::new(MemoryRegistryStore::seeded(registry_json(
            &[(ProfileIx::ROOT, Some("home"))],
            ProfileIx::ROOT,
        )));
        let session = ProfileSession::load(store).unwrap();

        assert!(
            matches!(
                session.record_melted(ProfileIx::ROOT, 4_200).unwrap(),
                ProfileEndOutcome::NoLiveProfileRemains
            ),
            "deleting the only profile did not report an account with none left"
        );
        assert!(session.with_registry(|r| r.live().next().is_none()));
    }

    /// **An UNCONFIRMED melt cannot be written down as an ending.**
    ///
    /// Height 0 is what an unproved read looks like, and this is the guard that stops a pushed melt
    /// — which may still be rejected — from removing a profile a person can still use. Pinned from
    /// both sides: the same call at a real height succeeds on the same fixture, so a `record_melted`
    /// that refused everything would fail the test above and this one would not carry it alone.
    #[test]
    fn a_melt_no_block_has_proved_is_refused_as_an_ending() {
        let store = Arc::new(MemoryRegistryStore::seeded(registry_json(
            &[(ProfileIx::ROOT, Some("home"))],
            ProfileIx::ROOT,
        )));
        let session = ProfileSession::load(store).unwrap();

        assert!(
            session.record_melted(ProfileIx::ROOT, 0).is_err(),
            "a melt with no proved height was recorded as a deleted profile"
        );
        assert!(
            session.with_registry(|r| r.live().next().is_some()),
            "the refusal still took the profile off the list"
        );
    }

    /// **The ACTIVE profile cannot be hidden, and the refusal changes nothing.**
    ///
    /// dig-account's own invariant, asserted here because this is the seam a surface calls: the trap
    /// it closes is a hidden active profile, which would show an empty list while the wallet went on
    /// deriving at it. The control is the non-active profile, which hides fine on the same fixture —
    /// without it, a `set_visibility` that refused everything would pass.
    #[test]
    fn the_active_profile_cannot_be_hidden_and_the_refusal_leaves_it_shown() {
        let session = session_with(&[(ProfileIx::ROOT, None), (ProfileIx(1), None)]);

        let refusal = session.set_visibility(ProfileIx::ROOT, true).unwrap_err();

        assert!(
            matches!(refusal, ProfileError::Registry(_)),
            "expected a registry refusal, got {refusal:?}"
        );
        assert!(
            session.with_registry(|r| r.get(ProfileIx::ROOT).expect("the entry").is_shown()),
            "the active profile was hidden anyway, so a list could show nothing while the wallet              derives there"
        );
        session
            .set_visibility(ProfileIx(1), true)
            .expect("a non-active profile hides, so the refusal above is about being active");
    }

    /// **Making a HIDDEN profile active un-hides it.**
    ///
    /// The other half of the trap, and it belongs to dig-account rather than to this type — pinned
    /// here because this session is what a surface calls, and a surface that had to defend against
    /// the trap itself would be re-implementing an invariant it cannot see.
    #[test]
    fn switching_to_a_hidden_profile_brings_it_back_into_the_list() {
        let session = session_with(&[(ProfileIx::ROOT, None), (ProfileIx(1), None)]);
        session.set_visibility(ProfileIx(1), true).unwrap();

        let _ = session.switch_to(ProfileIx(1)).unwrap();

        assert!(
            session.with_registry(|r| r.get(ProfileIx(1)).expect("the entry").is_shown()),
            "the profile now in use is hidden from the list that manages it"
        );
    }

    /// **A visibility change that cannot be persisted is rolled back.**
    ///
    /// The same property `a_switch_that_cannot_be_persisted_is_rolled_back` pins for a switch, and
    /// for the same reason: a preference that took effect in memory and not on disk would come back
    /// at the next start, having silently un-hidden a profile the person hid.
    #[test]
    fn a_visibility_change_that_cannot_be_persisted_is_rolled_back() {
        struct RefusesToWrite(String);
        impl RegistryStore for RefusesToWrite {
            fn read(&self) -> Result<ProfileRegistry, ProfileError> {
                ProfileRegistry::from_json(&self.0)
                    .map_err(|why| ProfileError::Corrupt(why.to_string()))
            }
            fn write(&self, _registry: &ProfileRegistry) -> Result<(), ProfileError> {
                Err(ProfileError::Io {
                    action: "written",
                    source: std::io::Error::other("the disk is full"),
                })
            }
        }

        let session = ProfileSession::load(Arc::new(RefusesToWrite(registry_json(
            &[(ProfileIx::ROOT, None), (ProfileIx(1), None)],
            ProfileIx::ROOT,
        ))))
        .unwrap();

        let refusal = session.set_visibility(ProfileIx(1), true).unwrap_err();

        assert!(matches!(refusal, ProfileError::Io { .. }), "{refusal:?}");
        assert!(
            session.with_registry(|r| r.get(ProfileIx(1)).expect("the entry").is_shown()),
            "a hide that could not be written took effect in memory anyway"
        );
    }

    /// A session that failed to LOAD says so, and one that loaded says nothing.
    ///
    /// Both sides, because a `unreadable_reason` that always answered `Some` would make every
    /// account's profile list read as unreadable — which is the opposite lie.
    #[test]
    fn only_a_session_that_failed_to_load_reports_a_reason() {
        assert_eq!(None, ProfileSession::unprofiled().unreadable_reason());
        assert_eq!(
            None,
            session_with(&[(ProfileIx::ROOT, None)]).unreadable_reason()
        );
        assert_eq!(
            Some("the file is not JSON"),
            ProfileSession::unreadable("the file is not JSON").unreadable_reason()
        );
    }

    /// The switch value carries the slot it LANDED on, read back from the registry rather than
    /// assembled from the request — so a caller disclosing the change names the profile actually in
    /// force, not the one that was asked for.
    ///
    /// The `#[must_use]` attribute itself is pinned by the `compile_fail` doctest on
    /// [`ProfileSession::switch_to`], not by this test. A runtime test cannot observe an attribute,
    /// and this doc used to claim it could — a guard that does not exist reads exactly like one that
    /// does.
    #[test]
    fn the_switch_value_carries_the_slot_it_landed_on() {
        let session = session_with(&[(ProfileIx::ROOT, None), (ProfileIx(1), Some("work"))]);
        let switched = session.switch_to(ProfileIx(1)).unwrap();

        assert!(switched.slot().is_profiled());
        assert_eq!(ProfileIx(1), switched.slot().ix());
        assert_eq!(
            Some(super::test_support::expected_did(ProfileIx(1)).as_str()),
            switched.slot().did()
        );
    }
}
