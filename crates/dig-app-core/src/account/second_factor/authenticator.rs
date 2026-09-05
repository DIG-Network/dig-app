//! The **WebAuthn client seam** — the one place in dig-app that drives a platform WebAuthn API
//! (dig-app#348, SPEC §3.1e *The client seam*).
//!
//! # Why this is a trait with exactly two operations
//!
//! A WebAuthn ceremony has two halves that live in different processes: the VERIFIER
//! ([`super::verifier`]) mints a challenge and judges a response, and the CLIENT asks the platform
//! to put a dialog on the screen and get a real authenticator to answer it. Only the second half is
//! platform-specific, and only the second half can fail for reasons that are not the verifier's
//! business — no dialog, no key, a user who walked away.
//!
//! Confining that half to `register` and `assert` is what lets everything else in the crate be
//! written once and tested on a Linux runner. It is also the rule the conformance suite enforces
//! directly: **no file in `src` outside this module may name `webauthn_authenticator_rs` or a
//! `WebAuthN*` symbol**, so a second client cannot appear beside this one without the test saying so.
//!
//! # The outcome set is three-valued, and two of the three are NOT distinguishable
//!
//! [`ClientOutcome`] is `Completed | NotCompleted | NoProvider`, and that is the whole set on
//! purpose. The 0.5.5 Windows backend flattens **every** Win32 failure into a single
//! `WebauthnCError::Internal` (`win10/mod.rs:168-172`, `:295-299`), so a cancelled dialog, an expired
//! timeout, a key that was never inserted and a platform that errored are indistinguishable HERE.
//! Nothing above this seam may claim to tell them apart, and no copy may report one of them as
//! though it were another — in particular, `NotCompleted` MUST NOT be read as "there is no key".
//!
//! [`NoProvider`] is the one absence that IS knowable in advance, because it is a property of the
//! BUILD rather than of the world: this build carries no client at all. It is reported through
//! [`ClientSupport`] before any window is drawn, so a person on macOS or Linux is told about a
//! platform limit instead of being walked into a dialog that cannot appear.
//!
//! # Fail-closed, structurally
//!
//! [`ClientOutcome::Completed`] is constructed in exactly two expressions in this file, each of them
//! directly out of an `Ok` that the platform delivered inside the deadline. A timeout, a panicked
//! worker, a thread that could not be spawned, a late answer and every platform error therefore
//! cannot become a `Completed` — not because each case is checked, but because there is no
//! expression here that could build one from them.

use std::time::Duration;

use webauthn_rs::prelude::{
    CreationChallengeResponse, PublicKeyCredential, RegisterPublicKeyCredential,
    RequestChallengeResponse, Url,
};
use webauthn_rs_proto::AuthenticatorTransport;

/// How long a ceremony may take before the wait is abandoned as [`ClientOutcome::NotCompleted`].
///
/// Deliberately the same 180 seconds the Windows Hello wait uses (`confirm::windows`), because it is
/// the same kind of wait for the same kind of person: someone who has to find a key in a drawer,
/// plug it in, and touch it — or unlock a phone and approve a prompt on it. Generous, but finite: an
/// authenticator that never answers must cost the user one refused action, never a permanently
/// wedged tray.
///
/// The same value is handed to the platform as its OWN timeout, so the dialog gives up at the moment
/// this wait does rather than lingering on screen after the app has stopped listening.
pub const CEREMONY_DEADLINE: Duration = Duration::from_secs(180);

/// Whether THIS BUILD carries a WebAuthn client at all.
///
/// # Why a build property and not a runtime probe
///
/// It answers "can this copy of dig-app run a ceremony", which is decided when the binary is
/// compiled. It does NOT answer "is there a key nearby": a security key can be plugged in while the
/// platform dialog is already open, and a phone over the hybrid transport has no local presence to
/// detect at all. That absence is unknowable in advance and reaches the app only as
/// [`ClientOutcome::NotCompleted`].
///
/// The distinction is the difference between two sentences a user must never see swapped: *"this
/// version cannot do that on this operating system"* is a limit they cannot act on, and *"that did
/// not finish"* is one they can retry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClientSupport {
    /// A client is compiled in and a ceremony can be attempted.
    Available,
    /// This build has no client. Enrolment is refused before any window, and every surface says so
    /// as a PLATFORM limitation — never as a setting that is switched off (dig-app#372).
    NotOnThisPlatform,
}

/// What a ceremony produced.
///
/// See the module docs: `NotCompleted` deliberately covers cancel, timeout, no-key and platform
/// error together, because the backend cannot separate them and neither may this app.
#[derive(Debug, Clone, PartialEq)]
pub enum ClientOutcome<T> {
    /// The platform returned a response. It has NOT been verified yet — that is the verifier's job.
    Completed(T),
    /// Nothing usable came back. Nothing may be enrolled, and nothing may be passed.
    NotCompleted,
    /// This build has no client (see [`ClientSupport::NotOnThisPlatform`]).
    NoProvider,
}

/// Drives the platform's WebAuthn ceremonies.
///
/// `Send + Sync` because the production implementation hands its work to a worker thread and the
/// journeys that call it are reached from the tray's dispatch.
pub trait Authenticator: Send + Sync {
    /// Whether this build can run a ceremony at all — answerable BEFORE any window is drawn.
    fn support(&self) -> ClientSupport;

    /// Run a registration ceremony for the options the verifier produced.
    ///
    /// `origin` is passed rather than read from a constant so that the value the client presents and
    /// the value the verifier was built with are the SAME value at the call site. Two independent
    /// reads of one constant is how they drift.
    fn register(
        &self,
        origin: &Url,
        options: &CreationChallengeResponse,
        deadline: Duration,
    ) -> ClientOutcome<RegisterPublicKeyCredential>;

    /// Run an authentication ceremony for the options the verifier produced.
    fn assert(
        &self,
        origin: &Url,
        options: &RequestChallengeResponse,
        deadline: Duration,
    ) -> ClientOutcome<PublicKeyCredential>;
}

/// The client on every platform that has none: it refuses, honestly and early.
///
/// It is not a stub and not a failure mode — it is the correct implementation for a build that
/// carries no WebAuthn backend (SPEC §3.1e *Platform scope*). macOS and Linux support is tracked as
/// <https://github.com/DIG-Network/dig-app/issues/372>; until it lands, every surface on those
/// platforms says *not available on this platform in this version* rather than anything that reads
/// as a switch the user could flip.
#[derive(Debug, Default, Clone, Copy)]
pub struct NoProvider;

impl Authenticator for NoProvider {
    fn support(&self) -> ClientSupport {
        ClientSupport::NotOnThisPlatform
    }

    fn register(
        &self,
        _origin: &Url,
        _options: &CreationChallengeResponse,
        _deadline: Duration,
    ) -> ClientOutcome<RegisterPublicKeyCredential> {
        ClientOutcome::NoProvider
    }

    fn assert(
        &self,
        _origin: &Url,
        _options: &RequestChallengeResponse,
        _deadline: Duration,
    ) -> ClientOutcome<PublicKeyCredential> {
        ClientOutcome::NoProvider
    }
}

/// Whether the platform REPORTED that the credential lives in a built-in authenticator.
///
/// # Two bounds a reader must hold, because this check is weaker than it looks
///
/// 1. It reads unsigned client metadata — on Windows, whatever `dwUsedTransport` said
///    (`win10/mod.rs:204`). A platform that misreports is not caught by it. The PRIMARY control is
///    asking for a `CrossPlatform` attachment in the first place, which Windows honours by not
///    offering Hello; this is the secondary one.
/// 2. An EMPTY or absent list is NOT a platform authenticator. A phone reached over the hybrid
///    transport reports exactly that through this backend, because hybrid has no native transport
///    bit to map (`win10/credential.rs:26-35`, `:39-56`), and refusing an empty list would refuse the
///    phone — one of the two authenticators this feature is for.
///
/// The reason a built-in authenticator must be refused: Windows Hello already unlocks this account
/// (§3.1d), so enrolling it as the SECOND factor would collapse the two into one.
pub fn reports_platform_authenticator(response: &RegisterPublicKeyCredential) -> bool {
    response
        .response
        .transports
        .as_ref()
        .is_some_and(|t| t.contains(&AuthenticatorTransport::Internal))
}

/// What this build supports, as a value a SURFACE can read without constructing a client.
///
/// The tray row and the account pane need to say *"not available on this platform in this version"*
/// while they are being laid out, which is long before any ceremony would run. They take it as a
/// PARAMETER rather than reading it here, so a test can render both sentences on one platform — a
/// surface whose only copy path is `cfg`-selected is a surface whose other copy is never seen until a
/// user on another operating system sees it first.
///
/// `the_constant_agrees_with_the_client_this_build_ships` keeps it honest.
pub const CLIENT_SUPPORT: ClientSupport = if cfg!(target_os = "windows") {
    ClientSupport::Available
} else {
    ClientSupport::NotOnThisPlatform
};

/// The client this build ships.
///
/// One expression, so which client a platform gets is decided in exactly one place and cannot
/// disagree with what [`ClientSupport`] reports.
pub fn platform_authenticator() -> Box<dyn Authenticator> {
    #[cfg(target_os = "windows")]
    {
        Box::new(windows::PlatformAuthenticator)
    }
    #[cfg(not(target_os = "windows"))]
    {
        Box::new(NoProvider)
    }
}

/// The Windows client, over the platform's own WebAuthn broker.
#[cfg(target_os = "windows")]
mod windows {
    use super::{
        Authenticator, ClientOutcome, ClientSupport, CreationChallengeResponse, Duration,
        PublicKeyCredential, RegisterPublicKeyCredential, RequestChallengeResponse, Url,
    };
    use crate::confirm::offload::run_off_thread;
    use crate::confirm::pump_host_messages;
    use webauthn_authenticator_rs::win10::Win10;
    use webauthn_authenticator_rs::AuthenticatorBackend;

    /// Drives `webauthn.dll` through `webauthn-authenticator-rs`'s `win10` backend.
    ///
    /// # Why the OS call does not run on the calling thread
    ///
    /// `WebAuthNAuthenticatorMakeCredential` / `…GetAssertion` block the thread they are called on
    /// while the platform draws a modal dialog. The tray dispatches menu actions from inside its own
    /// event loop, so calling them there is the deadlock dig_ecosystem#1926 already cost this app
    /// once with Windows Hello: the thread waits for the dialog and the dialog waits for the thread.
    ///
    /// So the ceremony runs on a worker through the same [`run_off_thread`] shape the biometric
    /// uses, and the caller stays responsive by pumping its own message queue between polls. The
    /// worker builds its own [`Win10`] because the backend takes `&mut self` and must not be shared
    /// across the wait.
    pub(super) struct PlatformAuthenticator;

    impl Authenticator for PlatformAuthenticator {
        fn support(&self) -> ClientSupport {
            ClientSupport::Available
        }

        fn register(
            &self,
            origin: &Url,
            options: &CreationChallengeResponse,
            deadline: Duration,
        ) -> ClientOutcome<RegisterPublicKeyCredential> {
            let origin = origin.clone();
            let options = options.public_key.clone();
            let timeout_ms = platform_timeout_ms(deadline);
            ceremony(deadline, move || {
                Win10::default().perform_register(origin, options, timeout_ms)
            })
        }

        fn assert(
            &self,
            origin: &Url,
            options: &RequestChallengeResponse,
            deadline: Duration,
        ) -> ClientOutcome<PublicKeyCredential> {
            let origin = origin.clone();
            let options = options.public_key.clone();
            let timeout_ms = platform_timeout_ms(deadline);
            ceremony(deadline, move || {
                Win10::default().perform_auth(origin, options, timeout_ms)
            })
        }
    }

    /// Run one ceremony off-thread and collapse everything that is not a delivered `Ok` into
    /// [`ClientOutcome::NotCompleted`].
    ///
    /// This is the single place `Completed` is built on Windows, and it is built only from an `Ok`
    /// the worker delivered inside the deadline. A late answer, a panicked worker, a thread that
    /// could not be spawned, and every `WebauthnCError` the backend can produce all land in the same
    /// arm — which is the honest shape, since the backend cannot tell them apart either.
    fn ceremony<T, F>(deadline: Duration, work: F) -> ClientOutcome<T>
    where
        F: FnOnce() -> Result<T, webauthn_authenticator_rs::error::WebauthnCError> + Send + 'static,
        T: Send + 'static,
    {
        match run_off_thread("dig-webauthn", work, pump_host_messages, deadline) {
            Some(Ok(response)) => ClientOutcome::Completed(response),
            Some(Err(e)) => {
                // The backend flattens every Win32 failure into one error, so this line records that
                // a ceremony ended without a response — never WHY, which it does not know.
                tracing::info!(error = ?e, "a WebAuthn ceremony did not complete");
                ClientOutcome::NotCompleted
            }
            None => ClientOutcome::NotCompleted,
        }
    }

    /// The deadline as the platform's own millisecond timeout.
    ///
    /// Saturating rather than wrapping: a deadline that overflowed a `u32` would otherwise become a
    /// tiny timeout and refuse a ceremony the moment it started.
    fn platform_timeout_ms(deadline: Duration) -> u32 {
        u32::try_from(deadline.as_millis()).unwrap_or(u32::MAX)
    }
}

#[cfg(test)]
pub(crate) mod double {
    //! Authenticators for tests: a scripted one for the journeys, and a REAL soft FIDO2 token for
    //! the conformance tests that must exercise the verifier end to end.
    //!
    //! They live in this file rather than in `test_support` because of the rule the module docs open
    //! with: only the client module may name `webauthn_authenticator_rs`, and the soft token comes
    //! from that crate.

    use super::*;
    use crate::account::second_factor::verifier;
    use std::sync::Mutex;
    use webauthn_authenticator_rs::softtoken::SoftToken;
    use webauthn_authenticator_rs::AuthenticatorBackend;
    use webauthn_rs::prelude::{
        AuthenticatorAttachment, SecurityKey, SecurityKeyAuthentication, Uuid, Webauthn,
    };

    /// One completed registration: the credential the verifier accepted, and the raw response the
    /// platform produced — so a test can inspect what the client reported as well as what was stored.
    pub(crate) struct Enrolled {
        pub(crate) credential: SecurityKey,
        pub(crate) response: RegisterPublicKeyCredential,
    }

    /// One completed assertion, with the verifier and the one-use state that minted its challenge.
    ///
    /// All three are returned together because they are only meaningful together: the state is
    /// consumed by exactly one `finish` call against exactly this verifier, and a test that mixed a
    /// response with somebody else's state would be exercising the replay path by accident.
    pub(crate) struct Asserted {
        pub(crate) webauthn: Webauthn,
        pub(crate) response: PublicKeyCredential,
        pub(crate) state: SecurityKeyAuthentication,
    }

    /// Run a real registration ceremony through `client` and verify it.
    ///
    /// The whole path production takes: the shipped verifier mints the options, the client answers,
    /// and the shipped verifier judges the answer. A fixture that hand-built a `SecurityKey` would
    /// prove only that the test agrees with itself.
    pub(crate) fn enrol_through(client: &dyn Authenticator) -> Enrolled {
        let webauthn = verifier::build().expect("the verifier builds");
        let origin = verifier::origin().expect("the origin constant parses");
        let (challenge, state) = webauthn
            .start_securitykey_registration(
                Uuid::new_v4(),
                verifier::USER_NAME,
                verifier::USER_DISPLAY_NAME,
                None,
                None,
                Some(AuthenticatorAttachment::CrossPlatform),
            )
            .expect("a registration challenge can be minted");
        let response = match client.register(&origin, &challenge, CEREMONY_DEADLINE) {
            ClientOutcome::Completed(response) => response,
            other => panic!("the test client completes its ceremony, got {other:?}"),
        };
        let credential = webauthn
            .finish_securitykey_registration(&response, &state)
            .expect("the soft token's registration verifies");
        Enrolled {
            credential,
            response,
        }
    }

    /// Run a real authentication ceremony against `credential` through `client`.
    pub(crate) fn assert_through(client: &dyn Authenticator, credential: &SecurityKey) -> Asserted {
        let webauthn = verifier::build().expect("the verifier builds");
        let origin = verifier::origin().expect("the origin constant parses");
        let (challenge, state) = webauthn
            .start_securitykey_authentication(std::slice::from_ref(credential))
            .expect("an authentication challenge can be minted");
        let response = match client.assert(&origin, &challenge, CEREMONY_DEADLINE) {
            ClientOutcome::Completed(response) => response,
            other => panic!("the test client completes its ceremony, got {other:?}"),
        };
        Asserted {
            webauthn,
            response,
            state,
        }
    }

    /// A real in-process FIDO2 authenticator, presenting itself as a ROAMING one.
    ///
    /// # Why the transports are rewritten
    ///
    /// `SoftToken` reports `AuthenticatorTransport::Internal` (`softtoken.rs:270`, `:603`) — it
    /// models a platform authenticator. The attachment rule refuses exactly that, so an unwrapped
    /// soft token can only ever drive the NEGATIVE test. Presenting `Usb` instead is what makes it
    /// usable for the positive path, and it changes nothing the verifier judges: transports are
    /// unsigned client metadata either way.
    ///
    /// The cryptography is untouched. Every key pair, attestation object and signature is the soft
    /// token's own, so a test that enrols through this drives the same verifier path production
    /// does.
    pub(crate) struct SoftAuthenticator {
        token: Mutex<SoftToken>,
        transports: Option<Vec<AuthenticatorTransport>>,
    }

    impl SoftAuthenticator {
        /// A soft token presenting itself over USB — a roaming key, which is what enrols.
        pub(crate) fn roaming() -> Self {
            Self::presenting(Some(vec![AuthenticatorTransport::Usb]))
        }

        /// A soft token presenting no transports at all — what a phone over the hybrid transport
        /// looks like through the Windows backend, and which MUST be accepted.
        pub(crate) fn silent_about_transport() -> Self {
            Self::presenting(None)
        }

        /// A soft token presenting itself as built in — what the attachment rule must refuse.
        pub(crate) fn platform() -> Self {
            Self::presenting(Some(vec![AuthenticatorTransport::Internal]))
        }

        fn presenting(transports: Option<Vec<AuthenticatorTransport>>) -> Self {
            let (token, _ca) = SoftToken::new(false).expect("a soft token can be created");
            Self {
                token: Mutex::new(token),
                transports,
            }
        }
    }

    impl Authenticator for SoftAuthenticator {
        fn support(&self) -> ClientSupport {
            ClientSupport::Available
        }

        fn register(
            &self,
            origin: &Url,
            options: &CreationChallengeResponse,
            deadline: Duration,
        ) -> ClientOutcome<RegisterPublicKeyCredential> {
            let mut token = self.token.lock().expect("the soft token is not poisoned");
            match token.perform_register(
                origin.clone(),
                options.public_key.clone(),
                deadline.as_millis() as u32,
            ) {
                Ok(mut response) => {
                    response.response.transports = self.transports.clone();
                    ClientOutcome::Completed(response)
                }
                Err(_) => ClientOutcome::NotCompleted,
            }
        }

        fn assert(
            &self,
            origin: &Url,
            options: &RequestChallengeResponse,
            deadline: Duration,
        ) -> ClientOutcome<PublicKeyCredential> {
            let mut token = self.token.lock().expect("the soft token is not poisoned");
            match token.perform_auth(
                origin.clone(),
                options.public_key.clone(),
                deadline.as_millis() as u32,
            ) {
                Ok(response) => ClientOutcome::Completed(response),
                Err(_) => ClientOutcome::NotCompleted,
            }
        }
    }

    /// A key that REGISTERS and then cannot assert.
    ///
    /// The one shape that isolates the confirming assertion from everything around it: a client that
    /// failed at registration would never reach that step, and a client that succeeded at both would
    /// not show whether the step exists at all. Without this double, deleting the confirmation would
    /// break no test.
    pub(crate) struct RegistersButCannotAssert {
        token: SoftAuthenticator,
        calls: Mutex<usize>,
    }

    impl RegistersButCannotAssert {
        pub(crate) fn new() -> Self {
            Self {
                token: SoftAuthenticator::roaming(),
                calls: Mutex::new(0),
            }
        }

        /// How many times the platform was asked to do something.
        pub(crate) fn call_count(&self) -> usize {
            *self.calls.lock().expect("not poisoned")
        }

        fn count(&self) {
            *self.calls.lock().expect("not poisoned") += 1;
        }
    }

    impl Authenticator for RegistersButCannotAssert {
        fn support(&self) -> ClientSupport {
            ClientSupport::Available
        }

        fn register(
            &self,
            origin: &Url,
            options: &CreationChallengeResponse,
            deadline: Duration,
        ) -> ClientOutcome<RegisterPublicKeyCredential> {
            self.count();
            self.token.register(origin, options, deadline)
        }

        fn assert(
            &self,
            _origin: &Url,
            _options: &RequestChallengeResponse,
            _deadline: Duration,
        ) -> ClientOutcome<PublicKeyCredential> {
            self.count();
            ClientOutcome::NotCompleted
        }
    }

    /// An authenticator whose every answer is written by the test.
    ///
    /// For the journey tests, which are about ORDER and REFUSAL rather than about cryptography: what
    /// is written when a ceremony does not complete, what is shown before it starts, and what is
    /// left on disk when it fails.
    pub(crate) struct ScriptedAuthenticator {
        support: ClientSupport,
        /// Answers for successive `register` calls, consumed front to back. An exhausted script
        /// answers `NotCompleted`, so a test can never accidentally pass on a call it did not write.
        registrations: Mutex<Vec<ClientOutcome<RegisterPublicKeyCredential>>>,
        assertions: Mutex<Vec<ClientOutcome<PublicKeyCredential>>>,
        /// Every call, in order, so a test can assert that a refused flow never reached the client.
        pub(crate) calls: Mutex<Vec<&'static str>>,
    }

    impl ScriptedAuthenticator {
        /// A client that is present and answers `NotCompleted` to everything.
        pub(crate) fn never_completes() -> Self {
            Self {
                support: ClientSupport::Available,
                registrations: Mutex::new(Vec::new()),
                assertions: Mutex::new(Vec::new()),
                calls: Mutex::new(Vec::new()),
            }
        }

        /// A client this build does not have.
        pub(crate) fn absent() -> Self {
            Self {
                support: ClientSupport::NotOnThisPlatform,
                ..Self::never_completes()
            }
        }

        /// How many times the platform was actually asked to do something.
        pub(crate) fn call_count(&self) -> usize {
            self.calls.lock().expect("not poisoned").len()
        }
    }

    impl Authenticator for ScriptedAuthenticator {
        fn support(&self) -> ClientSupport {
            self.support
        }

        fn register(
            &self,
            _origin: &Url,
            _options: &CreationChallengeResponse,
            _deadline: Duration,
        ) -> ClientOutcome<RegisterPublicKeyCredential> {
            self.calls.lock().expect("not poisoned").push("register");
            if self.support == ClientSupport::NotOnThisPlatform {
                return ClientOutcome::NoProvider;
            }
            let mut scripted = self.registrations.lock().expect("not poisoned");
            match scripted.is_empty() {
                true => ClientOutcome::NotCompleted,
                false => scripted.remove(0),
            }
        }

        fn assert(
            &self,
            _origin: &Url,
            _options: &RequestChallengeResponse,
            _deadline: Duration,
        ) -> ClientOutcome<PublicKeyCredential> {
            self.calls.lock().expect("not poisoned").push("assert");
            if self.support == ClientSupport::NotOnThisPlatform {
                return ClientOutcome::NoProvider;
            }
            let mut scripted = self.assertions.lock().expect("not poisoned");
            match scripted.is_empty() {
                true => ClientOutcome::NotCompleted,
                false => scripted.remove(0),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::double::{ScriptedAuthenticator, SoftAuthenticator};
    use super::*;
    use crate::account::second_factor::verifier;

    /// A build with no client refuses BOTH operations and reports the refusal as a platform limit,
    /// not as a failed attempt.
    ///
    /// Both halves are asserted together because either alone passes under a wrong implementation:
    /// one that answered `NotCompleted` satisfies "nothing was produced" while telling the user to
    /// retry something this build can never do.
    #[test]
    fn a_build_with_no_client_reports_a_platform_limit_rather_than_a_failure() {
        let origin = verifier::origin().expect("the origin constant parses");
        let (registration, authentication) = verifier::ceremony_fixtures();

        assert_eq!(NoProvider.support(), ClientSupport::NotOnThisPlatform);
        assert_eq!(
            NoProvider.register(&origin, &registration, CEREMONY_DEADLINE),
            ClientOutcome::NoProvider,
        );
        assert_eq!(
            NoProvider.assert(&origin, &authentication, CEREMONY_DEADLINE),
            ClientOutcome::NoProvider,
        );
    }

    /// The attachment rule reads the three cases the Windows backend can actually produce, and the
    /// EMPTY one is the case a wrong implementation gets backwards.
    ///
    /// A phone over the hybrid transport reports no transports at all, so "refuse anything that is
    /// not explicitly roaming" would refuse a phone — one of the two authenticators this feature
    /// exists to support.
    #[test]
    fn only_an_explicitly_internal_transport_is_a_platform_authenticator() {
        let origin = verifier::origin().expect("the origin constant parses");
        let (registration, _) = verifier::ceremony_fixtures();

        let roaming = SoftAuthenticator::roaming().register(&origin, &registration, CEREMONY_DEADLINE);
        let silent =
            SoftAuthenticator::silent_about_transport().register(&origin, &registration, CEREMONY_DEADLINE);
        let platform =
            SoftAuthenticator::platform().register(&origin, &registration, CEREMONY_DEADLINE);

        let completed = |outcome: ClientOutcome<RegisterPublicKeyCredential>| match outcome {
            ClientOutcome::Completed(r) => r,
            other => panic!("the soft token completes its ceremony, got {other:?}"),
        };

        assert!(!reports_platform_authenticator(&completed(roaming)));
        assert!(
            !reports_platform_authenticator(&completed(silent)),
            "an empty transport list is what a phone reports, and it MUST NOT be refused"
        );
        assert!(reports_platform_authenticator(&completed(platform)));
    }

    /// An exhausted script answers `NotCompleted` rather than panicking or repeating its last
    /// answer, so a journey test cannot pass on a call it never wrote.
    #[test]
    fn a_scripted_client_that_has_run_out_does_not_complete() {
        let origin = verifier::origin().expect("the origin constant parses");
        let (registration, _) = verifier::ceremony_fixtures();
        let client = ScriptedAuthenticator::never_completes();

        assert_eq!(
            client.register(&origin, &registration, CEREMONY_DEADLINE),
            ClientOutcome::NotCompleted,
        );
        assert_eq!(client.call_count(), 1);
    }

    /// The constant every surface reads and the client every ceremony uses must agree.
    ///
    /// They are two `cfg` decisions in two places, and a surface that said "not available" while a
    /// client happily ran — or the reverse — is exactly the kind of drift nobody notices on the
    /// platform they develop on.
    #[test]
    fn the_constant_agrees_with_the_client_this_build_ships() {
        assert_eq!(platform_authenticator().support(), CLIENT_SUPPORT);
    }

    /// The ceremony deadline is the Hello deadline. Pinned as a value because the two windows ask
    /// the same person for the same kind of physical act, and a shorter one here would fail a user
    /// who is still looking for their key.
    #[test]
    fn the_ceremony_deadline_matches_the_platform_authorization_wait() {
        assert_eq!(CEREMONY_DEADLINE, Duration::from_secs(180));
    }
}
