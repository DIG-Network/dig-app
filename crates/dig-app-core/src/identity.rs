//! The two-identity model — transport peer-identity vs the user identity.
//!
//! The DIG Node conflates two identities today; the #908 architecture splits them cleanly, and this
//! module names the split so the rest of the code (and its readers) can be precise about which
//! identity a value is:
//!
//! - **Transport peer-identity** ([`IdentityKind::TransportPeer`]) — a machine/network credential,
//!   `peer_id = SHA-256(TLS SPKI DER)`. It lets the engine be a network peer (mTLS P2P, relay
//!   reservation) **headless at boot**. It lives in the SYSTEM service, NOT here. dig-app never
//!   holds it.
//! - **User identity** ([`IdentityKind::User`]) — the per-user, per-profile DID plus its signing
//!   (`0x0010`) and encryption (`0x0011`) keys, wallet, and profile data. It lives HERE, sealed to
//!   the user key. **The user key never enters the engine:** dig-app signs and hands finished bytes
//!   to the engine, or answers a service→user-app `sign` callback for engine-initiated signatures.
//!
//! U4 ([`crate::keystore`]) implements the user-identity key handling; the transport peer-identity
//! stays in the engine (dig-node) and is out of this crate's scope.

/// Which of the two DIG identities a value belongs to. Naming the distinction in the type system
/// keeps the boundary invariant (§the SPEC) legible: user-identity material must never be handed to
/// the engine, and transport material never lives in dig-app.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IdentityKind {
    /// The machine/network transport peer-identity — engine-side, never held by dig-app.
    TransportPeer,
    /// The per-user, per-profile DID identity — dig-app-side, sealed to the user key.
    User,
}

impl IdentityKind {
    /// Whether material of this kind may legitimately be held by the dig-app user process.
    ///
    /// Only the [`IdentityKind::User`] identity belongs to dig-app; the transport peer-identity is
    /// engine-only. This encodes the boundary invariant as a checkable predicate.
    pub fn belongs_to_user_app(self) -> bool {
        matches!(self, IdentityKind::User)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_the_user_identity_belongs_to_the_user_app() {
        assert!(IdentityKind::User.belongs_to_user_app());
        assert!(!IdentityKind::TransportPeer.belongs_to_user_app());
    }
}
