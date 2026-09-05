//! The **WebAuthn verifier** and the relying-party identity it is built from (dig-app#348, SPEC
//! §3.1e *Relying-party identity*).
//!
//! This is the half of a ceremony that mints challenges and judges responses. It consumes public
//! keys and signatures only: nothing it is handed is secret, and nothing it produces is.
//!
//! # The three constants are IMMUTABLE once a release ships them
//!
//! Every credential a user enrols is scoped on their authenticator to a hash of [`RP_ID`]. Change
//! that value and every existing enrolment is orphaned — the platform finds no matching credential,
//! which fails closed but locks the owner out of the destructive verbs until they recover. It is the
//! most expensive wrong value in this feature, and it cannot be corrected after the fact.
//!
//! # Why `dig-app.dig.net`, and why NOT `dig.net`
//!
//! A relying-party id may be a registrable suffix of the origin, which means `dig.net` would put
//! every DIG credential in scope of anything served under it. `*.on.dig.net` and
//! `*.usercontent.dig.net` are USER-CONTROLLED, so a stranger could stand up `evil.on.dig.net` and
//! ask for assertions intended for DIG. The specificity of `dig-app.dig.net` is what prevents that,
//! and it is the reason the value is not the obvious one.
//!
//! **`dig-app.dig.net` must never be given a DNS record and must never serve content.** It exists as
//! an identifier and has no web property. Nothing here resolves it: a native application asserts its
//! own origin, and no request is ever made to it.
//!
//! # What these values do NOT provide
//!
//! They scope credentials on the authenticator and keep the client and the verifier self-consistent.
//! They provide no browser-style origin isolation. Any local process that can drive the platform
//! WebAuthn API with this relying-party id and a stored credential id can ask for an assertion —
//! subject to the user's physical gesture on the key, which is the whole guarantee this factor
//! makes.

use webauthn_rs::prelude::{Url, Webauthn, WebauthnBuilder, WebauthnError};

use super::authenticator::CEREMONY_DEADLINE;

/// The relying-party id every credential is scoped to. **Immutable once shipped** — see the module
/// docs.
pub const RP_ID: &str = "dig-app.dig.net";

/// The single origin the verifier accepts and the client presents. **Immutable once shipped.**
pub const RP_ORIGIN: &str = "https://dig-app.dig.net";

/// The relying-party name the platform dialog shows the user. **Immutable once shipped.**
pub const RP_NAME: &str = "DIG";

/// The user name handed to the authenticator at registration.
///
/// The ISSUER, not the account: nothing identifying this DIG Account may reach the key, its screen,
/// or anything it is backed up to. Same rule §3.1e already applied to the authenticator-app label.
pub const USER_NAME: &str = "DIG";

/// The user display name handed to the authenticator at registration. See [`USER_NAME`].
pub const USER_DISPLAY_NAME: &str = "DIG account";

/// The origin, parsed.
///
/// # Errors
///
/// [`WebauthnError::InvalidRPOrigin`] if [`RP_ORIGIN`] is not a URL, which is a defect in the constant
/// rather than a runtime condition — but it is returned rather than unwrapped, because this is
/// reached from a tray dispatch where a panic would take the whole app down instead of refusing one
/// action.
pub fn origin() -> Result<Url, WebauthnError> {
    Url::parse(RP_ORIGIN).map_err(|_| WebauthnError::InvalidRPOrigin)
}

/// Build the verifier.
///
/// # The four settings, and why each is not a default
///
/// - `danger_set_user_presence_only_security_keys(true)` — a security key satisfies user
///   VERIFICATION only with a PIN or an on-key biometric. Requiring it would make a touch-only key
///   unusable as a second factor. What this factor adds is POSSESSION; identity stays with the
///   platform biometric (§3.1d).
/// - `allow_subdomains(false)` — the whole point of the relying-party id chosen above (module docs).
/// - `allow_any_port(false)` — the origin is exact.
/// - `timeout(CEREMONY_DEADLINE)` — the same wait the client enforces, so the platform's dialog
///   gives up when the app stops listening rather than lingering after it.
///
/// No attestation CA list is ever passed, so attestation is conveyed as `none` and is never
/// verified. This app makes NO claim about the make or model of a user's key, and no copy may.
///
/// # Errors
///
/// [`WebauthnError`] if the constants above are not a self-consistent relying party. Returned rather
/// than unwrapped for the reason [`origin`] gives.
pub fn build() -> Result<Webauthn, WebauthnError> {
    let origin = origin()?;
    WebauthnBuilder::new(RP_ID, &origin)?
        .rp_name(RP_NAME)
        .allow_subdomains(false)
        .allow_any_port(false)
        .timeout(CEREMONY_DEADLINE)
        .danger_set_user_presence_only_security_keys(true)
        .build()
}

/// A registration and an authentication challenge, for tests that need real options to hand a
/// client without caring what is in them.
///
/// The authentication half is minted against an EMPTY credential list, which the verifier permits
/// because the user-presence policy is set explicitly rather than inferred from a stored credential.
#[cfg(test)]
pub(crate) fn ceremony_fixtures() -> (
    webauthn_rs::prelude::CreationChallengeResponse,
    webauthn_rs::prelude::RequestChallengeResponse,
) {
    let webauthn = build().expect("the relying-party constants are self-consistent");
    let (creation, _) = webauthn
        .start_securitykey_registration(
            webauthn_rs::prelude::Uuid::new_v4(),
            USER_NAME,
            USER_DISPLAY_NAME,
            None,
            None,
            None,
        )
        .expect("a registration challenge can be minted");
    let (request, _) = webauthn
        .start_securitykey_authentication(&[])
        .expect("an authentication challenge can be minted");
    (creation, request)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The verifier this crate builds is buildable, and its allowed origin is the ONE origin.
    ///
    /// Asserting the origin list rather than just `is_ok()` is the point: a builder that silently
    /// accepted a second origin, or that had subdomains left on, would still build.
    #[test]
    fn the_verifier_accepts_exactly_one_origin() {
        let webauthn = build().expect("the relying-party constants are self-consistent");
        let allowed = webauthn.get_allowed_origins();
        assert_eq!(allowed.len(), 1, "exactly one origin, got {allowed:?}");
        assert_eq!(allowed[0].as_str(), "https://dig-app.dig.net/");
    }

    /// The three literals, pinned by value.
    ///
    /// This is a test about IMMUTABILITY rather than about behaviour: changing any of them orphans
    /// every credential already enrolled on a user's key, and that cannot be undone from this side.
    /// A failure here is the reminder that the change is not a rename.
    #[test]
    fn the_relying_party_identity_is_the_shipped_one() {
        assert_eq!(RP_ID, "dig-app.dig.net");
        assert_eq!(RP_ORIGIN, "https://dig-app.dig.net");
        assert_eq!(RP_NAME, "DIG");
    }

    /// `dig.net` is not the relying-party id, and the reason is a live one: `*.on.dig.net` is
    /// user-controlled, so a registrable-suffix id would put every credential in scope of a
    /// stranger's page.
    #[test]
    fn the_relying_party_id_is_not_a_registrable_suffix_of_user_content() {
        assert_ne!(RP_ID, "dig.net");
        assert!(
            RP_ID.ends_with(".dig.net") && RP_ID != "dig.net",
            "the id must be a specific host under dig.net, never dig.net itself"
        );
    }

    /// Nothing identifying the account is handed to the authenticator.
    #[test]
    fn the_authenticator_is_told_the_issuer_and_nothing_about_the_account() {
        assert_eq!(USER_NAME, "DIG");
        assert_eq!(USER_DISPLAY_NAME, "DIG account");
    }

}
