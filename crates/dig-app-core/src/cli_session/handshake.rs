//! The mutual proof that opens the CLI lane: each half shows it knows the session secret, and
//! NEITHER half ever puts that secret on the wire.
//!
//! # Why the token is not simply presented
//!
//! An earlier shape had `dign` read the session token and send it as the first frame. That made the
//! token a bearer credential in one direction only: the server learned whether the client knew the
//! secret, and the client learned nothing at all about the server. The endpoint name is derived from
//! the login name (see [`super::endpoint`]) and creating a named pipe or a socket needs no privilege,
//! so a local principal that reaches the name FIRST is handed the token by the genuine client on its
//! very first frame -- and can then answer anything it likes, up to and including a wallet receive
//! address. That is a surface lying to a person about money, so the proof has to run in BOTH
//! directions, and the server half has to run BEFORE the secret would otherwise move.
//!
//! # The handshake
//!
//! 1. The client mints a fresh 32-byte [`Nonce`] and sends it. A nonce is not a secret; losing one to
//!    an impostor costs nothing.
//! 2. The server mints its own nonce and answers with the [`SERVER_PROOF_CONTEXT`] MAC over both
//!    nonces. Only a holder of the session secret can compute it.
//! 3. The client verifies that MAC in constant time. On a mismatch the conversation ends THERE: no
//!    attach, no command, and above all no secret.
//! 4. The client answers with the [`CLIENT_PROOF_CONTEXT`] MAC over the same two nonces, which the
//!    server verifies the same way. The lane is now mutually authenticated.
//!
//! Both nonces enter both MACs, so neither side can pin the transcript alone, and the two context
//! strings mean a server proof can never be replayed as a client proof. Both strings carry the
//! protocol name and a version, so a MAC minted for this handshake cannot be replayed into a future
//! one built on the same secret.
//!
//! The primitive is HMAC-SHA-256 from the `hmac`/`sha2` dependencies this crate already carries for
//! the loopback pairing MAC. Nothing here is a new construction.

use hmac::{Hmac, Mac};
use sha2::Sha256;

use crate::constant_time::constant_time_eq;

use super::auth::SessionToken;

/// Domain separation for the proof the SERVER computes, so it can never be replayed as a client one.
pub const SERVER_PROOF_CONTEXT: &str = "dignetwork/cli-session/v1/server-proof";

/// Domain separation for the proof the CLIENT computes.
pub const CLIENT_PROOF_CONTEXT: &str = "dignetwork/cli-session/v1/client-proof";

/// The nonce width in bytes -- the same 32 bytes the session token itself uses.
const NONCE_BYTES: usize = 32;

/// A single-use random value one half of the handshake contributes to the transcript.
///
/// Public by construction: it travels in the clear, and its only job is to make the MACs of one
/// handshake unrepeatable in another.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Nonce(String);

impl Nonce {
    /// Mint a fresh nonce from the OS CSPRNG -- the same source [`SessionToken::mint`] draws from.
    pub fn mint() -> Self {
        use rand_core::RngCore;

        let mut bytes = [0u8; NONCE_BYTES];
        rand_core::OsRng.fill_bytes(&mut bytes);
        Self(hex::encode(bytes))
    }

    /// The lowercase-hex form that travels on the wire.
    pub fn as_hex(&self) -> &str {
        &self.0
    }

    /// Read a peer-supplied nonce, refusing anything that is not exactly 32 bytes of hex.
    ///
    /// A peer able to shorten the nonce could shrink the transcript it has to guess, so the width is
    /// a requirement rather than a convention.
    pub fn from_peer_hex(hex_text: &str) -> Result<Self, ProofError> {
        let decoded = hex::decode(hex_text).map_err(|_| ProofError::MalformedNonce)?;
        if decoded.len() != NONCE_BYTES {
            return Err(ProofError::MalformedNonce);
        }
        Ok(Self(hex_text.to_ascii_lowercase()))
    }
}

/// Why a handshake value could not be accepted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProofError {
    /// The nonce was not exactly 32 bytes of hex.
    MalformedNonce,
    /// The MAC did not match the one this half computed over the same transcript.
    ProofMismatch,
}

impl std::fmt::Display for ProofError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MalformedNonce => f.write_str("the handshake nonce is not 32 bytes of hex"),
            Self::ProofMismatch => {
                f.write_str("the peer did not prove it holds the session secret of this app")
            }
        }
    }
}

/// The MAC over `(context, client_nonce, server_nonce)` under the session secret, lowercase hex.
///
/// Both nonces are fixed width, so concatenating them is unambiguous; the context string is
/// separated from them by a NUL byte, which hex text can never contain.
pub fn proof(secret: &SessionToken, context: &str, client: &Nonce, server: &Nonce) -> String {
    let mut mac = <Hmac<Sha256>>::new_from_slice(secret.as_hex().as_bytes())
        .expect("HMAC accepts a key of any length");
    mac.update(context.as_bytes());
    mac.update(&[0u8]);
    mac.update(client.as_hex().as_bytes());
    mac.update(server.as_hex().as_bytes());
    hex::encode(mac.finalize().into_bytes())
}

/// Verify `presented` against the proof this half computes over the same transcript.
///
/// The comparison is constant-time on the hex text: a `==` would leak, through timing, how
/// many leading characters a forged MAC got right, which turns one search of a 256-bit space into a
/// short sequence of 16-symbol ones.
pub fn verify(
    secret: &SessionToken,
    context: &str,
    client: &Nonce,
    server: &Nonce,
    presented: &str,
) -> Result<(), ProofError> {
    let expected = proof(secret, context, client, server);
    if constant_time_eq(expected.as_bytes(), presented.as_bytes()) {
        Ok(())
    } else {
        Err(ProofError::ProofMismatch)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn secret() -> SessionToken {
        SessionToken::from_hex("00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff")
    }

    #[test]
    fn a_minted_nonce_is_full_width_hex_and_never_repeats() {
        let (a, b) = (Nonce::mint(), Nonce::mint());
        assert_eq!(a.as_hex().len(), NONCE_BYTES * 2);
        assert!(a.as_hex().chars().all(|c| c.is_ascii_hexdigit()));
        assert_ne!(a, b, "two mints must not collide");
    }

    #[test]
    fn a_proof_verifies_only_under_the_same_secret_context_and_transcript() {
        let (client, server) = (Nonce::mint(), Nonce::mint());
        let tag = proof(&secret(), SERVER_PROOF_CONTEXT, &client, &server);
        assert!(verify(&secret(), SERVER_PROOF_CONTEXT, &client, &server, &tag).is_ok());

        // The nearest wrong values, one variable at a time. Each is a real attack: a different
        // secret is an impostor, a different context is a cross-direction replay, and a different
        // nonce is a replay of a previous handshake.
        let other_secret = SessionToken::from_hex(
            "ffeeddccbbaa99887766554433221100ffeeddccbbaa99887766554433221100",
        );
        assert_eq!(
            verify(&other_secret, SERVER_PROOF_CONTEXT, &client, &server, &tag),
            Err(ProofError::ProofMismatch),
            "an impostor that never read the secret must not produce a valid proof"
        );
        assert_eq!(
            verify(&secret(), CLIENT_PROOF_CONTEXT, &client, &server, &tag),
            Err(ProofError::ProofMismatch),
            "a server proof must not verify as a client proof"
        );
        assert_eq!(
            verify(
                &secret(),
                SERVER_PROOF_CONTEXT,
                &Nonce::mint(),
                &server,
                &tag
            ),
            Err(ProofError::ProofMismatch),
            "a proof must not survive a different client nonce"
        );
        assert_eq!(
            verify(
                &secret(),
                SERVER_PROOF_CONTEXT,
                &client,
                &Nonce::mint(),
                &tag
            ),
            Err(ProofError::ProofMismatch),
            "a proof must not survive a different server nonce"
        );
    }

    /// The two directions are different MACs over the SAME transcript. One shared proof would let an
    /// impostor echo the frame of the client back as the server proof.
    #[test]
    fn the_two_directions_produce_different_proofs() {
        let (client, server) = (Nonce::mint(), Nonce::mint());
        assert_ne!(
            proof(&secret(), SERVER_PROOF_CONTEXT, &client, &server),
            proof(&secret(), CLIENT_PROOF_CONTEXT, &client, &server)
        );
    }

    /// The nonce order is part of the transcript: swapping the two halves must not verify, or a
    /// reflected handshake would authenticate.
    #[test]
    fn the_nonce_order_is_part_of_the_transcript() {
        let (client, server) = (Nonce::mint(), Nonce::mint());
        let tag = proof(&secret(), SERVER_PROOF_CONTEXT, &client, &server);
        assert_eq!(
            verify(&secret(), SERVER_PROOF_CONTEXT, &server, &client, &tag),
            Err(ProofError::ProofMismatch)
        );
    }

    #[test]
    fn a_peer_nonce_must_be_exactly_thirty_two_bytes_of_hex() {
        let good = Nonce::mint();
        assert_eq!(Nonce::from_peer_hex(good.as_hex()).unwrap(), good);
        let too_long = format!("{}00", good.as_hex());
        for bad in ["", "zz", &good.as_hex()[..62], &too_long] {
            assert_eq!(
                Nonce::from_peer_hex(bad),
                Err(ProofError::MalformedNonce),
                "a {}-character nonce must be refused",
                bad.len()
            );
        }
    }

    /// Neither a proof nor an error text may carry the secret. A MAC is not reversible, but a
    /// diagnostic that interpolated the key would undo that in one line.
    #[test]
    fn no_handshake_value_contains_the_secret() {
        let (client, server) = (Nonce::mint(), Nonce::mint());
        let tag = proof(&secret(), SERVER_PROOF_CONTEXT, &client, &server);
        assert!(!tag.contains(secret().as_hex()));
        assert!(!ProofError::ProofMismatch
            .to_string()
            .contains(secret().as_hex()));
    }
}
