//! The per-profile wallet state and its DIGOP1-sealed-at-rest store (NC-2 / NC-3).
//!
//! Two secret-bearing blobs live in the profile's own AppData directory
//! (`<brand>/profiles/<did-hash>/`), each sealed under that profile's DEK through the U4/U5
//! [`ProfileSealer`] seam — never a shared key, never plaintext at rest:
//!
//! - **`wallet-key.seal`** — the 32-byte wallet-key seed ([`super::signing::WalletKey`]). The only
//!   serialized form of the private key; sealed before it ever touches disk.
//! - **`wallet-state.seal`** — the public-facing [`WalletState`] (addresses / coins view / balance
//!   cache). Sealed too, because it is user data (SPEC §3.4) — but it holds no key material.
//!
//! The `.dig` content cache is explicitly OUT of scope here (SPEC §3.4 exemption): it is public,
//! on-chain-anchored, machine-owned, and unsealed. Only identity/wallet/subscriptions/config/
//! profile-metadata are sealed.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::profiles::{did_hash, ProfileSealer};
use crate::storage::{profile_dir, write_durably};

use super::signing::WalletKey;
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

/// A profile's wallet view — its receive addresses and its last-known spendable coins. This is the
/// cached, user-facing state; it is authoritative for display + coin selection between chain reads,
/// and is refreshed from the engine's chain-read seam ([`super::engine`]). It holds NO private key
/// (the key lives sealed separately, [`WalletStore::save_key`]).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct WalletState {
    /// The profile's receive addresses (`xch1…`). The first is the primary / change address.
    #[serde(default)]
    pub addresses: Vec<String>,
    /// The wallet's last-known spendable coins across all held assets.
    #[serde(default)]
    pub coins: Vec<CoinRecord>,
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
}

/// The file name of the sealed wallet-key seed blob within a profile's directory.
const KEY_SEAL_FILE: &str = "wallet-key.seal";
/// The file name of the sealed wallet-state blob within a profile's directory.
const STATE_SEAL_FILE: &str = "wallet-state.seal";

/// Seals and loads a profile's wallet blobs under that profile's DEK, in the profile's AppData
/// directory. Generic over the [`ProfileSealer`] seam so the crypto stays in exactly one place (U4)
/// and the store is testable in isolation — mirroring [`crate::profiles::ProfileManager`].
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

    /// Seal `key`'s seed under `did`'s DEK and write it durably to the profile's directory. The
    /// plaintext seed exists only inside the zeroizing buffer and the sealer's transient input; the
    /// bytes reaching disk are AEAD ciphertext.
    pub fn save_key(&self, did: &str, key: &WalletKey) -> Result<(), WalletError> {
        let seed = key.sealed_seed();
        self.seal_to(did, KEY_SEAL_FILE, &*seed)
    }

    /// Load the wallet key for `did` by opening its sealed seed. Fails closed if the profile is
    /// locked or the blob was sealed by another profile's DEK.
    pub fn load_key(&self, did: &str) -> Result<WalletKey, WalletError> {
        let plaintext = self.open_from(did, KEY_SEAL_FILE)?;
        let seed: [u8; 32] = plaintext.as_slice().try_into().map_err(|_| {
            WalletError::State("sealed wallet seed has an unexpected length".into())
        })?;
        // `seed` is a stack copy of the 32 key bytes; the zeroizing `plaintext` scrubs the heap
        // buffer, and `WalletKey::from_seed` moves the copy into its own zeroizing store.
        Ok(WalletKey::from_seed(seed))
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

    /// Read + open the sealed blob at `file`, returning its plaintext (zeroizing). A missing blob is
    /// an error here (use [`WalletStore::load_state`] for the tolerant path).
    fn open_from(&self, did: &str, file: &str) -> Result<Zeroizing<Vec<u8>>, WalletError> {
        let ciphertext = self
            .read_seal(did, file)
            .ok_or_else(|| WalletError::State(format!("no sealed {file} for this profile")))?;
        self.open_bytes(did, &ciphertext)
    }

    /// Open `ciphertext` under `did`'s DEK. The plaintext stays in a zeroizing buffer so a decrypted
    /// key seed / wallet blob is scrubbed from memory once the caller is done with it.
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
    use crate::keystore::IdentitySecrets;
    use crate::profiles::{KeystoreSealer, UnlockedIdentities};
    use dig_keystore::KdfParams;

    const DID_A: &str = "did:chia:profile-a";
    const DID_B: &str = "did:chia:profile-b";

    /// A store over `dir` whose real (fast-KDF) [`KeystoreSealer`] has `dids` unlocked to fresh,
    /// distinct identities — so sealing/opening exercises the production DIGOP1 crypto.
    fn store(dir: &Path, dids: &[&str]) -> WalletStore<KeystoreSealer> {
        let identities = UnlockedIdentities::new();
        for did in dids {
            identities.unlock(*did, IdentitySecrets::generate());
        }
        WalletStore::new(
            dir,
            KeystoreSealer::with_kdf(identities, KdfParams::FAST_TEST),
        )
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
        };
        assert_eq!(state.balance(Asset::Dig), 150);
        assert_eq!(state.balance(Asset::Xch), 7);
    }

    #[test]
    fn state_round_trips_through_the_seal() {
        let dir = tempfile::tempdir().unwrap();
        let store = store(dir.path(), &[DID_A]);
        let state = WalletState {
            addresses: vec!["xch1primary".into()],
            coins: vec![CoinRecord {
                coin_id: "ab".into(),
                asset: Asset::Dig,
                amount: 42,
            }],
        };
        store.save_state(DID_A, &state).unwrap();
        assert_eq!(store.load_state(DID_A).unwrap(), state);
    }

    #[test]
    fn a_profile_with_no_saved_state_loads_the_empty_default() {
        let dir = tempfile::tempdir().unwrap();
        let store = store(dir.path(), &[DID_A]);
        assert_eq!(store.load_state(DID_A).unwrap(), WalletState::default());
    }

    #[test]
    fn the_wallet_key_round_trips_through_the_seal() {
        let dir = tempfile::tempdir().unwrap();
        let store = store(dir.path(), &[DID_A]);
        let key = WalletKey::from_seed([9u8; 32]);
        store.save_key(DID_A, &key).unwrap();

        let loaded = store.load_key(DID_A).unwrap();
        assert_eq!(loaded.public_key(), key.public_key());
    }

    #[test]
    fn the_sealed_key_blob_is_ciphertext_never_the_plaintext_seed() {
        // The custody-critical property: the 32-byte seed must NOT appear in the sealed bytes.
        let dir = tempfile::tempdir().unwrap();
        let store = store(dir.path(), &[DID_A]);
        let seed = [0x5au8; 32];
        store.save_key(DID_A, &WalletKey::from_seed(seed)).unwrap();

        let on_disk = std::fs::read(store.dir_for(DID_A).join(KEY_SEAL_FILE)).unwrap();
        assert!(
            !on_disk.windows(seed.len()).any(|w| w == seed),
            "the plaintext wallet seed leaked into the sealed blob"
        );
    }

    #[test]
    fn one_profile_cannot_open_anothers_sealed_wallet() {
        // A's wallet is sealed under A's DEK; B holds a different identity, so B's open fails the
        // AEAD tag — cross-profile isolation is cryptographic, not a filesystem convention.
        let dir = tempfile::tempdir().unwrap();
        let store = store(dir.path(), &[DID_A, DID_B]);
        store
            .save_key(DID_A, &WalletKey::from_seed([1u8; 32]))
            .unwrap();

        // Relocate A's sealed blob into B's directory and try to open it as B.
        let a_blob = std::fs::read(store.dir_for(DID_A).join(KEY_SEAL_FILE)).unwrap();
        std::fs::create_dir_all(store.dir_for(DID_B)).unwrap();
        std::fs::write(store.dir_for(DID_B).join(KEY_SEAL_FILE), &a_blob).unwrap();

        assert!(
            matches!(store.load_key(DID_B), Err(WalletError::Seal(_))),
            "B must not open A's sealed wallet"
        );
    }

    #[test]
    fn a_locked_profile_cannot_seal_its_wallet() {
        let dir = tempfile::tempdir().unwrap();
        let store = store(dir.path(), &[]); // no profile unlocked
        let err = store
            .save_key(DID_A, &WalletKey::from_seed([2u8; 32]))
            .unwrap_err();
        assert!(matches!(err, WalletError::Seal(_)));
    }
}
