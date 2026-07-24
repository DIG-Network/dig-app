//! The per-profile wallet state and its DIGOP1-sealed-at-rest store (NC-2 / NC-3).
//!
//! The **`wallet-state.seal`** blob lives in the profile's own AppData directory
//! (`<brand>/profiles/<did-hash>/`), sealed under that profile's DEK through the [`ProfileSealer`]
//! seam — never plaintext at rest. It holds the public-facing [`WalletState`] (addresses / coins view
//! / balance cache / spend history): user data (SPEC §3.4), but NO key material.
//!
//! The wallet's spending KEY is NOT stored here: in the master-HD model it is derived on demand from
//! the account master seed by the [`MoneyPath`](crate::account::money::MoneyPath) — nothing per-profile
//! is persisted for it.
//!
//! The `.dig` content cache is explicitly OUT of scope here (SPEC §3.4 exemption): it is public,
//! on-chain-anchored, machine-owned, and unsealed. Only identity/wallet/subscriptions/config/
//! profile-metadata are sealed.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::sealer::ProfileSealer;
use crate::storage::{did_hash, profile_dir, write_durably};

use super::WalletError;

/// The asset a coin or balance is denominated in. Kept small + explicit; extended additively as the
/// wallet grows to hold more CAT types.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Asset {
    /// Native Chia (XCH), in mojos.
    Xch,
    /// The DIG CAT, in base units.
    Dig,
}

/// A single spendable coin as the wallet last saw it — the cached view the engine's chain reads
/// populate. Amounts are the asset's base unit (mojos for XCH, base units for DIG).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CoinRecord {
    /// The coin id (32-byte hash), lowercase hex.
    pub coin_id: String,
    /// The asset this coin holds.
    pub asset: Asset,
    /// The coin's value in the asset's base unit.
    pub amount: u64,
}

/// A record of an outbound spend the wallet broadcast — the public metadata the wallet-security
/// wave-2 lanes read (address-book auto-populate #963, adaptive step-up on prior spend history, and
/// the net-effect coin-state view #964). It holds **only public metadata** — recipient, asset,
/// amount, time, and the on-chain transaction id — never key material and never the bundle bytes, so
/// exposing it never crosses the custody boundary.
///
/// Appended additively (`#[serde(default)]` on the owning [`WalletState::history`]) so an older
/// sealed state without history still deserializes to an empty log.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SpendRecord {
    /// The recipient `xch1…` address the spend paid.
    pub recipient: String,
    /// The asset that was sent.
    pub asset: Asset,
    /// The amount sent, in the asset's base unit (mojos for XCH, base units for DIG).
    pub amount: u64,
    /// Unix seconds when the spend was broadcast.
    pub broadcast_at: u64,
    /// The broadcast transaction id (spend-bundle name), lowercase hex.
    pub transaction_id: String,
}

/// A profile's wallet view — its receive addresses, its last-known spendable coins, and its
/// outbound spend history. This is the cached, user-facing state; it is authoritative for display +
/// coin selection between chain reads, and is refreshed from the engine's chain-read seam
/// ([`super::engine`]). It holds NO private key (the money key is derived from the master-HD account,
/// never stored per profile).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct WalletState {
    /// The profile's receive addresses (`xch1…`). The first is the primary / change address.
    #[serde(default)]
    pub addresses: Vec<String>,
    /// The wallet's last-known spendable coins across all held assets.
    #[serde(default)]
    pub coins: Vec<CoinRecord>,
    /// The wallet's outbound spends, oldest first — the substrate the wave-2 security lanes read.
    #[serde(default)]
    pub history: Vec<SpendRecord>,
}

impl WalletState {
    /// The spendable balance for `asset` — the sum of the cached coins of that asset, in base units.
    pub fn balance(&self, asset: Asset) -> u64 {
        self.coins
            .iter()
            .filter(|c| c.asset == asset)
            .map(|c| c.amount)
            .sum()
    }

    /// Append an outbound spend to the history log. History is kept oldest-first, so the read
    /// helpers ([`recent_recipients`](Self::recent_recipients)) treat the tail as most-recent.
    pub fn record_spend(&mut self, record: SpendRecord) {
        self.history.push(record);
    }

    /// The outbound spend history, oldest first.
    pub fn history(&self) -> &[SpendRecord] {
        &self.history
    }

    /// The distinct recipient addresses this wallet has paid, most-recent first, capped at `limit`.
    ///
    /// The substrate WSEC-A (#963) auto-populates the address book from: a recipient paid more
    /// recently ranks ahead of one paid earlier, and each address appears once (its most-recent
    /// send wins its position).
    pub fn recent_recipients(&self, limit: usize) -> Vec<&str> {
        let mut seen = std::collections::HashSet::new();
        let mut recipients = Vec::new();
        for record in self.history.iter().rev() {
            if recipients.len() == limit {
                break;
            }
            if seen.insert(record.recipient.as_str()) {
                recipients.push(record.recipient.as_str());
            }
        }
        recipients
    }

    /// The total amount of `asset` this wallet has sent across all recorded spends, in base units —
    /// the substrate WSEC-G's adaptive step-up reads to size a confirm against spend history.
    pub fn total_sent(&self, asset: Asset) -> u64 {
        self.history
            .iter()
            .filter(|s| s.asset == asset)
            .map(|s| s.amount)
            .sum()
    }
}

/// The file name of the sealed wallet-state blob within a profile's directory.
const STATE_SEAL_FILE: &str = "wallet-state.seal";

/// Seals and loads a profile's wallet state under that profile's DEK, in the profile's AppData
/// directory. Generic over the [`ProfileSealer`] seam so the crypto stays in exactly one place
/// (the master-HD [`AccountResidency`](crate::account::residency::AccountResidency)) and the store is
/// testable in isolation.
///
/// The wallet's spending KEY is NOT stored here: it is derived on demand from the master-HD account
/// by the [`MoneyPath`](crate::account::money::MoneyPath). This store persists only the public-facing
/// wallet view (addresses / coins / balance / history), which is user data sealed at rest (SPEC §3.4).
pub struct WalletStore<S: ProfileSealer> {
    brand_dir: PathBuf,
    sealer: S,
}

impl<S: ProfileSealer> WalletStore<S> {
    /// Build a store rooted at `brand_dir` (the per-user AppData directory) sealing through `sealer`.
    pub fn new(brand_dir: impl Into<PathBuf>, sealer: S) -> Self {
        Self {
            brand_dir: brand_dir.into(),
            sealer,
        }
    }

    /// Seal `state` under `did`'s DEK and write it durably to the profile's directory.
    pub fn save_state(&self, did: &str, state: &WalletState) -> Result<(), WalletError> {
        let plaintext = serde_json::to_vec(state)
            .map_err(|e| WalletError::State(format!("serializing wallet state: {e}")))?;
        self.seal_to(did, STATE_SEAL_FILE, &plaintext)
    }

    /// Load the wallet state for `did`; a profile with no saved state yet yields the default (empty)
    /// state — a fresh wallet, not an error.
    pub fn load_state(&self, did: &str) -> Result<WalletState, WalletError> {
        match self.read_seal(did, STATE_SEAL_FILE) {
            Some(ciphertext) => {
                let plaintext = self.open_bytes(did, &ciphertext)?;
                serde_json::from_slice(plaintext.as_slice())
                    .map_err(|e| WalletError::State(format!("deserializing wallet state: {e}")))
            }
            None => Ok(WalletState::default()),
        }
    }

    // --- sealing plumbing -----------------------------------------------------------------------

    /// Seal `plaintext` under `did`'s DEK and write it to `file` in the profile's directory,
    /// creating the (owner-restricted) directory if needed.
    fn seal_to(&self, did: &str, file: &str, plaintext: &[u8]) -> Result<(), WalletError> {
        let dir = self.dir_for(did);
        std::fs::create_dir_all(&dir).map_err(WalletError::Io)?;
        restrict_to_owner(&dir);

        let ciphertext = self.sealer.seal(did, plaintext)?;
        let path = dir.join(file);
        let temp_path = path.with_extension("tmp");
        write_durably(&path, &temp_path, &ciphertext).map_err(WalletError::Io)?;
        restrict_to_owner(&path);
        Ok(())
    }

    /// Open `ciphertext` under `did`'s DEK. The plaintext stays in a zeroizing buffer so a decrypted
    /// wallet blob is scrubbed from memory once the caller is done with it.
    fn open_bytes(&self, did: &str, ciphertext: &[u8]) -> Result<Zeroizing<Vec<u8>>, WalletError> {
        Ok(self.sealer.open(did, ciphertext)?)
    }

    /// Read the raw sealed bytes at `file`, or `None` if the file does not exist.
    fn read_seal(&self, did: &str, file: &str) -> Option<Vec<u8>> {
        std::fs::read(self.dir_for(did).join(file)).ok()
    }

    /// The profile's own AppData directory (`<brand>/profiles/<did-hash>/`).
    fn dir_for(&self, did: &str) -> PathBuf {
        profile_dir(&self.brand_dir, &did_hash(did))
    }
}

/// Restrict a path to owner-only access on Unix (`0700`), best-effort. Defense-in-depth beside the
/// home-directory ACL; a failure to tighten permissions is not fatal (the seal is the real barrier).
fn restrict_to_owner(path: &Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700));
    }
    #[cfg(not(unix))]
    let _ = path;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::account::sealer::AccountSealer;
    use crate::test_support::test_sealer;

    const DID_A: &str = "did:chia:profile-a";
    const DID_B: &str = "did:chia:profile-b";

    /// A store over `dir` sealing under `did`'s per-profile DEK (the fast test KDF), exercising the
    /// production DIGOP1 crypto. Distinct DIDs → distinct DEKs → cross-profile isolation.
    fn store(dir: &Path, did: &str) -> WalletStore<AccountSealer> {
        WalletStore::new(dir, test_sealer(did))
    }

    #[test]
    fn balance_sums_only_the_requested_asset() {
        let state = WalletState {
            addresses: vec!["xch1a".into()],
            coins: vec![
                CoinRecord {
                    coin_id: "01".into(),
                    asset: Asset::Dig,
                    amount: 100,
                },
                CoinRecord {
                    coin_id: "02".into(),
                    asset: Asset::Dig,
                    amount: 50,
                },
                CoinRecord {
                    coin_id: "03".into(),
                    asset: Asset::Xch,
                    amount: 7,
                },
            ],
            history: Vec::new(),
        };
        assert_eq!(state.balance(Asset::Dig), 150);
        assert_eq!(state.balance(Asset::Xch), 7);
    }

    /// A spend to `recipient` for `amount` DIG at time `at` — a compact fixture for the history API.
    fn dig_spend(recipient: &str, amount: u64, at: u64) -> SpendRecord {
        SpendRecord {
            recipient: recipient.into(),
            asset: Asset::Dig,
            amount,
            broadcast_at: at,
            transaction_id: format!("{at:064x}"),
        }
    }

    #[test]
    fn recorded_spends_accumulate_oldest_first() {
        let mut state = WalletState::default();
        state.record_spend(dig_spend("xch1alice", 10, 1));
        state.record_spend(dig_spend("xch1bob", 20, 2));
        assert_eq!(state.history().len(), 2);
        assert_eq!(state.history()[0].recipient, "xch1alice");
        assert_eq!(state.history()[1].recipient, "xch1bob");
    }

    #[test]
    fn recent_recipients_are_most_recent_first_deduped_and_capped() {
        let mut state = WalletState::default();
        state.record_spend(dig_spend("xch1alice", 10, 1));
        state.record_spend(dig_spend("xch1bob", 20, 2));
        // A second send to alice — her most-recent send moves her ahead of bob.
        state.record_spend(dig_spend("xch1alice", 30, 3));
        state.record_spend(dig_spend("xch1carol", 40, 4));

        assert_eq!(
            state.recent_recipients(10),
            vec!["xch1carol", "xch1alice", "xch1bob"],
            "distinct recipients, most-recent first"
        );
        assert_eq!(
            state.recent_recipients(2),
            vec!["xch1carol", "xch1alice"],
            "capped at the limit"
        );
    }

    #[test]
    fn recent_recipients_of_an_empty_history_is_empty() {
        assert!(WalletState::default().recent_recipients(5).is_empty());
    }

    #[test]
    fn total_sent_sums_only_the_requested_asset() {
        let mut state = WalletState::default();
        state.record_spend(dig_spend("xch1alice", 100, 1));
        state.record_spend(dig_spend("xch1bob", 50, 2));
        state.record_spend(SpendRecord {
            asset: Asset::Xch,
            ..dig_spend("xch1carol", 7, 3)
        });
        assert_eq!(state.total_sent(Asset::Dig), 150);
        assert_eq!(state.total_sent(Asset::Xch), 7);
    }

    #[test]
    fn history_round_trips_through_the_seal() {
        let dir = tempfile::tempdir().unwrap();
        let store = store(dir.path(), DID_A);
        let mut state = WalletState {
            addresses: vec!["xch1primary".into()],
            ..WalletState::default()
        };
        state.record_spend(dig_spend("xch1recipient", 42, 99));
        store.save_state(DID_A, &state).unwrap();
        assert_eq!(store.load_state(DID_A).unwrap(), state);
    }

    #[test]
    fn state_round_trips_through_the_seal() {
        let dir = tempfile::tempdir().unwrap();
        let store = store(dir.path(), DID_A);
        let state = WalletState {
            addresses: vec!["xch1primary".into()],
            coins: vec![CoinRecord {
                coin_id: "ab".into(),
                asset: Asset::Dig,
                amount: 42,
            }],
            history: Vec::new(),
        };
        store.save_state(DID_A, &state).unwrap();
        assert_eq!(store.load_state(DID_A).unwrap(), state);
    }

    #[test]
    fn a_profile_with_no_saved_state_loads_the_empty_default() {
        let dir = tempfile::tempdir().unwrap();
        let store = store(dir.path(), DID_A);
        assert_eq!(store.load_state(DID_A).unwrap(), WalletState::default());
    }

    #[test]
    fn the_sealed_state_blob_is_ciphertext_never_the_plaintext_address() {
        // The custody-critical property: the user-facing plaintext (a receive address) must NOT appear
        // in the sealed bytes on disk.
        let dir = tempfile::tempdir().unwrap();
        let store = store(dir.path(), DID_A);
        let state = WalletState {
            addresses: vec!["xch1secretaddress".into()],
            ..WalletState::default()
        };
        store.save_state(DID_A, &state).unwrap();

        let on_disk = std::fs::read(store.dir_for(DID_A).join(STATE_SEAL_FILE)).unwrap();
        assert!(
            !on_disk
                .windows(b"xch1secretaddress".len())
                .any(|w| w == b"xch1secretaddress"),
            "plaintext leaked into the sealed wallet-state blob"
        );
    }

    #[test]
    fn one_profile_cannot_open_anothers_sealed_wallet() {
        // A's wallet is sealed under A's DEK; a store bound to a DIFFERENT profile's DEK fails the AEAD
        // tag — cross-profile isolation is cryptographic, not a filesystem convention.
        let dir = tempfile::tempdir().unwrap();
        let store_a = store(dir.path(), DID_A);
        let state = WalletState {
            addresses: vec!["xch1a".into()],
            ..WalletState::default()
        };
        store_a.save_state(DID_A, &state).unwrap();

        // Relocate A's sealed blob into B's directory and open it through B's DEK (a distinct label).
        let a_blob = std::fs::read(store_a.dir_for(DID_A).join(STATE_SEAL_FILE)).unwrap();
        let store_b = store(dir.path(), DID_B);
        std::fs::create_dir_all(store_b.dir_for(DID_B)).unwrap();
        std::fs::write(store_b.dir_for(DID_B).join(STATE_SEAL_FILE), &a_blob).unwrap();

        assert!(
            matches!(store_b.load_state(DID_B), Err(WalletError::Seal(_))),
            "B must not open A's sealed wallet"
        );
    }

    #[test]
    fn a_locked_profile_cannot_seal_its_wallet() {
        use crate::account::residency::AccountResidency;
        use crate::session_lock::SessionKeys;
        use dig_account::ProfileIx;
        use dig_keystore::KdfParams;

        // A live-view sealer over a LOCKED residency must fail closed on seal.
        let dir = tempfile::tempdir().unwrap();
        let residency = crate::test_support::test_residency();
        let sealer = residency.sealer(ProfileIx::ROOT, KdfParams::FAST_TEST);
        AccountResidency::lock_all(&residency);
        let store = WalletStore::new(dir.path(), sealer);
        let err = store
            .save_state(DID_A, &WalletState::default())
            .unwrap_err();
        assert!(matches!(err, WalletError::Seal(_)));
    }
}
