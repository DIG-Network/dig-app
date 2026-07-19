//! The on-disk shapes of a profile: the non-secret registry (plaintext) and the sealed per-profile
//! blob (ciphertext).
//!
//! Two tiers, mirroring SPEC §3.4:
//!
//! - **Non-secret** — the active-profile pointer and a small metadata cache (DID, public keys,
//!   display name) live in a plaintext [`ProfileRegistry`] so the app can list profiles and restore
//!   the last active one *before any profile is unlocked*.
//! - **Secret-bearing** — each profile's [`ProfileData`] (subscriptions, prefs, cached persona
//!   metadata) is DIGOP1-sealed under that profile's own DEK ([`super::sealer`]) and written to its
//!   own directory. Identity keys and wallet state are sealed separately by their owning modules
//!   (U4) under the *same* per-profile DEK.

use crate::profiles::metadata::ProfileMetadata;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Derives the per-profile AppData directory key from a profile's DID: lowercase-hex
/// `sha256(did)`. Stable and filesystem-safe, so `<brand>/profiles/<did-hash>/` isolates each
/// profile's blobs on disk regardless of how exotic the DID string is.
pub fn did_hash(did: &str) -> String {
    hex::encode(Sha256::digest(did.as_bytes()))
}

/// The user's per-profile runtime preferences — the non-wallet, non-subscription settings that
/// nonetheless live *inside* the sealed blob because they are user data (SPEC §3.4).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProfilePrefs {
    /// A profile-specific custom engine/node endpoint override (§5.3). `None` uses the agent-level
    /// resolution ladder.
    #[serde(default)]
    pub node_url: Option<String>,

    /// Whether the default-on creator/dev auto-tip is enabled for this profile (the $DIG North Star,
    /// #377 — visible + one-click-off). Defaults to `true`.
    #[serde(default = "default_true")]
    pub auto_tip: bool,
}

fn default_true() -> bool {
    true
}

impl Default for ProfilePrefs {
    fn default() -> Self {
        Self {
            node_url: None,
            auto_tip: true,
        }
    }
}

/// A profile's secret-bearing state — the plaintext that is DIGOP1-sealed at rest under the
/// profile's DEK. Never written to disk unsealed.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProfileData {
    /// The persona metadata (a local cache of the on-chain dig-identity SMT).
    #[serde(default)]
    pub metadata: ProfileMetadata,

    /// Store ids this profile subscribes to.
    #[serde(default)]
    pub subscriptions: Vec<String>,

    /// The profile's runtime preferences.
    #[serde(default)]
    pub prefs: ProfilePrefs,
}

/// The non-secret record of a profile, kept in the plaintext [`ProfileRegistry`].
///
/// It carries only public information — the DID, the identity public key (hex), a cached display
/// name for pre-unlock listing, and the directory hash — never anything that must be sealed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProfileRecord {
    /// The profile's canonical `did:chia:` DID.
    pub did: String,
    /// The per-profile AppData directory key, `sha256(did)` hex ([`did_hash`]).
    pub did_hash: String,
    /// The 48-byte BLS12-381 G1 identity public key (slot `0x0010`), lowercase hex. The v2 model's
    /// single key — it both signs (G2 AugScheme) and seals (G1 ECDH).
    pub signing_public_key: String,
    /// Launcher id of the paired chip35 profile store, if one exists.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub paired_store_id: Option<String>,
    /// A cached display name for listing profiles before any is unlocked. Kept in sync with the
    /// sealed metadata on edit.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
}

/// The plaintext registry of every profile plus which one is active — the file the app reads at
/// boot to render the profile list and restore the last active profile without unlocking anything.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProfileRegistry {
    /// The DID of the active profile, if one is selected.
    #[serde(default)]
    pub active: Option<String>,
    /// The DID of the user's configured DEFAULT profile — the identity presented by default (in the
    /// social selector, as the primary identity). Distinct from [`active`](Self::active): "active" is
    /// the profile currently loaded in memory, while "default" is the user's persisted preferred
    /// identity. `None` until the user sets one, in which case callers fall back (active, then first).
    ///
    /// A DID is public (it already appears in each [`ProfileRecord`]), so this pointer lives in the
    /// plaintext registry alongside `active` — no sealing is required for a non-secret selection.
    #[serde(default)]
    pub default: Option<String>,
    /// Every known profile, in creation order.
    #[serde(default)]
    pub profiles: Vec<ProfileRecord>,
}

impl ProfileRegistry {
    /// Finds a profile record by DID.
    pub fn find(&self, did: &str) -> Option<&ProfileRecord> {
        self.profiles.iter().find(|p| p.did == did)
    }

    /// Finds a mutable profile record by DID.
    pub fn find_mut(&mut self, did: &str) -> Option<&mut ProfileRecord> {
        self.profiles.iter_mut().find(|p| p.did == did)
    }
}
