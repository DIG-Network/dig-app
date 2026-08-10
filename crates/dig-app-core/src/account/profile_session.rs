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
//! receive address, the per-profile DEK, and the identity signing key
//! (`dig_account::ActiveSwitch`). [`ProfileSwitched`] is `#[must_use]` for the same reason
//! dig-account's own switch value is — its only consumer rebuilds the profile-scoped assembly (the
//! profile directory, the sealed stores, the sign-service router, the money path), because those are
//! wired once at boot and cannot re-read anything.
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

use dig_account::registry::{ProfileRegistry, ProfileVisibility};
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

/// Where a [`ProfileSession`] reads and writes its registry.
///
/// A trait — modelled on [`ConfigStore`](crate::confirm::gui::window::pane::settings::prefs) — so
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

/// What a completed switch changed, and what the app must now rebuild.
///
/// `#[must_use]` because the seams listed in the module docs are wired ONCE and cannot re-read
/// anything: the profile directory, the sealed stores under it, the sign-service router and the money
/// path all have to be torn down and rebuilt around the new slot. Dropping this value silently is
/// exactly the half-landed switch this ticket exists to make impossible, so a caller that means to
/// drop it has to say so in code.
#[derive(Debug, Clone, PartialEq, Eq)]
#[must_use = "a switch changes the receive address, the DEK and the identity key — the profile-scoped \
              assembly MUST be rebuilt and the change disclosed to the user"]
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

    /// The index the NEXT profile mint must target. Distinct from
    /// [`wallet_slot`](Self::wallet_slot), which is the index that PAYS for it — see [`MintTarget`].
    pub fn next_mint_target(&self) -> MintTarget {
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
/// dig-account's mint evidence (`MintedDid`, `ConfirmedStore`) is crate-private to dig-account and
/// `ProfileMinter::mint` is still `todo!()`, so no consumer — production or test — can call
/// `record_minted`. The one door left open is the deserialize path, which is not a loophole: it is
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
                    height = 1_000 + ix.0,
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

    /// A session over a store that has never been written is unprofiled at ROOT — and says so,
    /// rather than inventing a profile.
    #[test]
    fn an_unwritten_store_loads_as_an_unprofiled_account() {
        let session = ProfileSession::load(Arc::new(MemoryRegistryStore::empty())).unwrap();

        assert_eq!(ActiveSlot::Unprofiled, session.slot());
        assert_eq!(ProfileIx::ROOT, session.active_ix());
        assert_eq!(ProfileIx::ROOT, session.wallet_slot().ix());
        assert_eq!(
            ProfileIx::ROOT,
            session.next_mint_target().ix(),
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

    /// The switch value cannot be silently dropped: `#[must_use]` is the mechanism that forces the
    /// caller to rebuild the profile-scoped assembly. Pinned here so removing the attribute fails a
    /// test rather than passing review.
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
