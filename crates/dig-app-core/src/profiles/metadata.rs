//! The editable persona fields of a profile, and their mapping onto the canonical dig-identity SMT.
//!
//! [`ProfileMetadata`] is the human-facing view a user edits (display name, bio, avatar, …). Its
//! on-chain representation is a `dig-identity` [`Profile`] — the additive sparse-merkle-tree of
//! standard slots (dig_ecosystem#771). This module is where U5 CONSUMES that canonical format: it
//! never reinvents the slot map or the tree; it maps each field onto its standard
//! [`slot`](dig_identity::slot::standard) id so any implementation reads and writes the same bytes
//! and every field is provable against one 32-byte root.

use dig_identity::slot::standard;
use dig_identity::{Profile, Value};
use serde::{Deserialize, Serialize};

/// The editable persona fields of a profile.
///
/// Every field is optional: an unset field is simply an absent SMT slot (provable-absent against the
/// root). Fields map to dig-identity standard slots `0x0001`–`0x0008`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProfileMetadata {
    /// Display name (slot `0x0001`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
    /// Free-text bio (slot `0x0002`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bio: Option<String>,
    /// `dig://` URN of the avatar image (slot `0x0003`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub avatar: Option<String>,
    /// `dig://` URN of the banner image (slot `0x0004`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub banner: Option<String>,
    /// Pronouns (slot `0x0005`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pronouns: Option<String>,
    /// Location (slot `0x0006`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub location: Option<String>,
    /// Newline-separated social/verification links (slot `0x0007`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub links: Option<String>,
    /// Canonical mainnet `xch1…` receive address (slot `0x0008`) — the $DIG-payments seam.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub xch_address: Option<String>,
}

impl ProfileMetadata {
    /// Materializes this metadata plus the profile's two published public keys into a canonical
    /// dig-identity [`Profile`], ready to compute the SMT root or mint proofs for an on-chain write.
    ///
    /// The keys are set into the standard signing (`0x0010`) and encryption (`0x0011`) slots so the
    /// published profile resolves DID→keys for the rest of the ecosystem (dig-chat, dig-node).
    pub fn to_identity_profile(
        &self,
        signing_public_key: &[u8; 32],
        encryption_public_key: &[u8; 32],
    ) -> Profile {
        let mut profile = Profile::with_schema_v1();
        set_utf8(&mut profile, standard::DISPLAY_NAME, &self.display_name);
        set_utf8(&mut profile, standard::BIO, &self.bio);
        set_utf8(&mut profile, standard::AVATAR, &self.avatar);
        set_utf8(&mut profile, standard::BANNER, &self.banner);
        set_utf8(&mut profile, standard::PRONOUNS, &self.pronouns);
        set_utf8(&mut profile, standard::LOCATION, &self.location);
        set_utf8(&mut profile, standard::LINKS, &self.links);
        set_utf8(&mut profile, standard::XCH_ADDRESS, &self.xch_address);
        profile.set(
            standard::SIGNING_PUBLIC_KEY,
            Value::Bytes(signing_public_key.to_vec()),
        );
        profile.set(
            standard::ENCRYPTION_PUBLIC_KEY,
            Value::Bytes(encryption_public_key.to_vec()),
        );
        profile
    }
}

/// Sets a UTF-8 slot when the field is present, leaving it absent otherwise.
fn set_utf8(profile: &mut Profile, slot: dig_identity::SlotId, field: &Option<String>) {
    if let Some(text) = field {
        profile.set(slot, Value::Utf8(text.clone()));
    }
}
