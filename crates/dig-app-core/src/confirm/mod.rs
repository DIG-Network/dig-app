//! The native-confirm seam — the ONLY authorization to pair, connect, or sign (SIGN-1, `SPEC.md`
//! §5.6.1, **security-critical**).
//!
//! Every privileged action on the [`crate::loopback`] identity channel — pairing an extension,
//! first-connecting a dapp origin, and signing a transaction — is gated on a real OS-drawn
//! foreground confirm window owned by the dig-app tray process, backed by the platform biometric
//! (Windows Hello / macOS Touch ID / Linux polkit-or-fprintd) with a passphrase fallback. The
//! transport guards (loopback bind, `Host`/`Origin` allowlist, pairing-token MAC) only narrow *who
//! may talk on the channel*; they are explicitly NOT permission to act. This trait is that terminal
//! human gate.
//!
//! SIGN-1 defines the seam and ships the fail-closed [`HeadlessConfirmer`] only. The per-OS
//! implementations (Windows Hello, macOS `LAContext`, Linux polkit/fprintd) land in SIGN-3a/b/c and
//! build against exactly this trait — hence the prompt structs carry everything a confirm window
//! must display, and nothing a per-OS backend must re-fetch.

/// The human's ruling on one native-confirm prompt.
///
/// Each variant maps to a stable §5.6.7 error code when it is not [`ConfirmDecision::Approve`], so the
/// extension keys its UX off the outcome. The mapping lives in [`crate::loopback::dispatch`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConfirmDecision {
    /// The user authenticated (biometric/passphrase) and approved the action.
    Approve,
    /// The user explicitly declined.
    Deny,
    /// The prompt was not answered within the confirm window's deadline.
    Timeout,
    /// No native confirmer is available — a headless host with no desktop session. The endpoint MUST
    /// fail closed (`SIGN_NO_CONFIRMER`); a headless build never signs without a human (§5.6.1).
    Unavailable,
}

/// The pairing-confirm prompt: *"Pair this browser extension with your DIG identity?"* (§5.6.3).
///
/// Borrows the request so a backend renders it without copying. `ext_id` has already been checked
/// against the pinned extension id by the time the confirmer sees it (the `Origin`/`ext_id` guard).
#[derive(Debug, Clone, Copy)]
pub struct PairPrompt<'a> {
    /// The extension id requesting to pair (already pinned-id-checked).
    pub ext_id: &'a str,
    /// An optional human label the extension supplied for display.
    pub ext_label: Option<&'a str>,
}

/// The connect-confirm prompt: *"`<origin>` wants to connect to your DIG identity"* (§5.6.4).
#[derive(Debug, Clone, Copy)]
pub struct ConnectPrompt<'a> {
    /// The dapp's TRUE committed tab origin, vouched by the paired extension (browser-sourced).
    pub origin: &'a str,
    /// An optional dapp display name.
    pub dapp_name: Option<&'a str>,
}

/// The sign-confirm prompt: the decoded transaction plus its vouched origin (§5.6.5).
///
/// `decoded_tx` is the human-readable render (coins, per-asset amounts, recipient, fee) the confirm
/// window MUST show — never raw bytes. SIGN-1 does not decode (that lands in SIGN-2), so this field
/// is populated by later work units; the seam is shaped for it now.
#[derive(Debug, Clone, Copy)]
pub struct SignPrompt<'a> {
    /// The vouched dapp origin the sign request arrived from.
    pub origin: &'a str,
    /// The `payload_type` tag naming what is being signed (selects the decoder, §5.6.5).
    pub payload_type: &'a str,
    /// The human-readable decoded transaction to display, once a decoder produces one (SIGN-2).
    pub decoded_tx: Option<&'a str>,
}

/// The terminal human authorization for the identity channel. The one production implementation is
/// the per-OS native confirm (SIGN-3); [`HeadlessConfirmer`] is the fail-closed default, and tests
/// use a scripted double. There is deliberately no default-approve — an unimplemented backend denies.
///
/// `Send + Sync` because the [`crate::loopback`] server shares one confirmer across connection tasks.
pub trait NativeConfirmer: Send + Sync {
    /// Confirm pairing an extension with the active profile's identity.
    fn confirm_pair(&self, prompt: &PairPrompt<'_>) -> ConfirmDecision;

    /// Confirm first-connecting a dapp origin to the active profile.
    fn confirm_connect(&self, prompt: &ConnectPrompt<'_>) -> ConfirmDecision;

    /// Confirm signing the decoded transaction with the in-memory identity key.
    fn confirm_sign(&self, prompt: &SignPrompt<'_>) -> ConfirmDecision;
}

/// The fail-closed confirmer for a host with no desktop session — the SIGN-1 default until the per-OS
/// backends land (SIGN-3). Every prompt returns [`ConfirmDecision::Unavailable`], so the identity
/// endpoint refuses to pair, connect, or sign (`SIGN_NO_CONFIRMER`): a headless build never acts
/// without a human at the biometric gate (§5.6.1, headless degrade MUST fail closed).
#[derive(Debug, Default, Clone, Copy)]
pub struct HeadlessConfirmer;

impl NativeConfirmer for HeadlessConfirmer {
    fn confirm_pair(&self, _prompt: &PairPrompt<'_>) -> ConfirmDecision {
        ConfirmDecision::Unavailable
    }

    fn confirm_connect(&self, _prompt: &ConnectPrompt<'_>) -> ConfirmDecision {
        ConfirmDecision::Unavailable
    }

    fn confirm_sign(&self, _prompt: &SignPrompt<'_>) -> ConfirmDecision {
        ConfirmDecision::Unavailable
    }
}

// The per-OS backends (SIGN-3). Each is compiled only for its own target and provides a
// `confirmer()` returning `Some(Box<dyn NativeConfirmer>)` when a desktop session is present, or
// `None` on a headless host so [`native_confirmer`] falls back to the fail-closed
// [`HeadlessConfirmer`]. They are thin adapters: they build the OS foreground window + the OS
// biometric verifier and delegate all decision logic to the shared, unit-tested [`gated_consent`].
#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "macos")]
mod macos;
#[cfg(target_os = "windows")]
mod windows;

/// Select the confirmer this host uses as the terminal identity gate (SIGN-3).
///
/// Returns the per-OS native confirmer (Windows Hello / macOS Touch ID / Linux polkit) when this
/// host has an interactive desktop session, and the fail-closed [`HeadlessConfirmer`] otherwise — so
/// a server / headless build can never sign without a human at the biometric gate (§5.6.1). SIGN-2's
/// loopback server startup calls this to obtain the confirmer it hands to the frame router, in place
/// of the SIGN-1 [`HeadlessConfirmer`] default.
pub fn native_confirmer() -> Box<dyn NativeConfirmer> {
    #[cfg(target_os = "linux")]
    {
        linux::confirmer().unwrap_or_else(|| Box::new(HeadlessConfirmer))
    }
    #[cfg(target_os = "macos")]
    {
        macos::confirmer().unwrap_or_else(|| Box::new(HeadlessConfirmer))
    }
    #[cfg(target_os = "windows")]
    {
        windows::confirmer().unwrap_or_else(|| Box::new(HeadlessConfirmer))
    }
    // No native backend for this target (e.g. a BSD or a wasm build): fail closed.
    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
    {
        Box::new(HeadlessConfirmer)
    }
}

/// The human-readable content one native confirm window must display, built purely from a prompt.
///
/// Centralizing the render here keeps the security-critical "what the user is shown" decision in ONE
/// unit-tested place: every per-OS backend draws exactly these fields, so no backend can accidentally
/// omit the origin, mislabel the action, or (for a sign) present opaque bytes. The struct is owned
/// (not borrowed) so a backend can move it across an FFI / thread boundary to the UI.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ConfirmContent {
    /// The window title bar text (e.g. `"DIG — Approve signing"`).
    pub title: String,
    /// The primary, origin-bound heading (e.g. `"example.com wants you to sign a transaction"`).
    pub heading: String,
    /// The detail body the window shows beneath the heading — the decoded transaction for a sign, the
    /// extension id for a pairing, already formatted for a human. Never raw signable bytes.
    pub body: String,
    /// The label of the approve action (`"Pair"`, `"Connect"`, `"Sign"`), reused as the reason string
    /// the biometric prompt shows.
    pub action: &'static str,
}

impl ConfirmContent {
    /// The content for a pairing confirm (§5.6.3): approve making this extension the paired relay.
    fn pair(prompt: &PairPrompt<'_>) -> Self {
        let who = match prompt.ext_label {
            Some(label) => format!("{label} ({})", prompt.ext_id),
            None => prompt.ext_id.to_string(),
        };
        Self {
            title: "DIG — Pair extension".to_string(),
            heading: format!("Pair {who} with your DIG identity?"),
            body:
                "This browser extension will be allowed to relay connect and signing requests to \
                   your DIG identity. You approve every signature individually."
                    .to_string(),
            action: "Pair",
        }
    }

    /// The content for a first-connect confirm (§5.6.4): approve a dapp origin talking to this identity.
    fn connect(prompt: &ConnectPrompt<'_>) -> Self {
        let who = match prompt.dapp_name {
            Some(name) => format!("{name} ({})", prompt.origin),
            None => prompt.origin.to_string(),
        };
        Self {
            title: "DIG — Connect dapp".to_string(),
            heading: format!("{who} wants to connect to your DIG identity"),
            body: format!(
                "The site {} (via your paired DIG extension) is requesting to connect. It will still \
                 need your approval for every signature.",
                prompt.origin
            ),
            action: "Connect",
        }
    }

    /// The content for a sign confirm (§5.6.5), or [`None`] when there is nothing safe to display.
    ///
    /// **Never blind-sign (defense-in-depth).** A [`SignPrompt`] whose `decoded_tx` is absent carries
    /// no human-readable transaction, so no window is raised and [`BackedConfirmer::confirm_sign`]
    /// denies. SIGN-2's dispatch already refuses an undecodable payload (`SIGN_UNKNOWN_TYPE` /
    /// `SIGN_BAD_PAYLOAD`) before reaching the confirmer; this is the second, independent guard so a
    /// confirmer can NEVER present "sign these opaque bytes?" even if a caller bypassed dispatch.
    fn sign(prompt: &SignPrompt<'_>) -> Option<Self> {
        let decoded = prompt.decoded_tx?;
        Some(Self {
            title: "DIG — Approve signing".to_string(),
            heading: format!("{} wants you to sign a transaction", prompt.origin),
            body: format!(
                "Requested via your paired DIG extension.\n\nType: {}\n\n{decoded}",
                prompt.payload_type
            ),
            action: "Sign",
        })
    }
}

/// The user's raw intent from the foreground window, BEFORE the biometric step.
///
/// The two-step gate (show the decoded transaction, then re-authenticate) is what gives *informed*
/// consent: the window explains WHAT is being approved; the [`BiometricVerifier`] proves WHO approved
/// it. A backend maps its native dialog result to this, and [`gated_consent`] combines it with the
/// biometric outcome.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum WindowIntent {
    /// The user clicked the approve action; proceed to the biometric step.
    Approve,
    /// The user dismissed / cancelled the window.
    Deny,
    /// The window closed on its own deadline with no answer. Only some backends have a dialog timeout
    /// (the Linux helper's `--timeout`); the modal Windows/macOS dialogs never self-close, so this is
    /// constructed on those targets' `#[allow(dead_code)]`-permitted paths only.
    #[allow(dead_code)]
    Timeout,
    /// No foreground window could be shown (e.g. the desktop dialog helper is missing) — fail closed.
    /// Constructed only by backends that can detect that condition (Linux); permitted dead elsewhere.
    #[allow(dead_code)]
    Unavailable,
}

/// The outcome of the OS user re-authentication (biometric with the platform's built-in
/// password/PIN fallback: Windows Hello, Touch ID with password, the polkit agent).
///
/// This gate proves the human at the keyboard is the machine's owner; it is deliberately NOT the DIG
/// vault passphrase (unlocking the identity key stays in the keystore/dispatch path — one user action
/// authorizes here and doubles as the vault unlock there, §5.6.5). "Passphrase fallback everywhere"
/// (§5.6.1) is the OS authenticator's own password fallback, so no key material is handled here.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum VerifyOutcome {
    /// The user re-authenticated successfully (biometric or the OS password fallback).
    Verified,
    /// The user cancelled the authentication prompt.
    Declined,
    /// Authentication ran but failed (wrong credential, too many attempts) — treated as a denial.
    Failed,
    /// No authenticator is available or enrolled — fail closed.
    Unavailable,
}

/// Raises the foreground confirm window showing decoded content and returns the user's intent.
pub(crate) trait ForegroundWindow: Send + Sync {
    /// Show `content` as a real, focus-stealing OS window and block until the user answers or the
    /// window's deadline elapses.
    fn show(&self, content: &ConfirmContent) -> WindowIntent;
}

/// Performs the OS user re-authentication (biometric + built-in password fallback).
pub(crate) trait BiometricVerifier: Send + Sync {
    /// Prompt the platform authenticator, showing `reason`, and block until it resolves.
    fn verify(&self, reason: &str) -> VerifyOutcome;
}

/// Combine the foreground-window intent with the biometric outcome into the final decision.
///
/// This is the shared, exhaustively-tested heart of every per-OS confirmer — the security policy in
/// ONE place: a signature is authorized ONLY when the user both approved the *shown, decoded* action
/// AND re-authenticated. Every non-approval maps to the honest [`ConfirmDecision`], and every failure
/// mode (dismissed window, cancelled/failed/unavailable biometric) fails closed. No path returns
/// [`ConfirmDecision::Approve`] without a [`VerifyOutcome::Verified`].
pub(crate) fn gated_consent(
    content: &ConfirmContent,
    window: &dyn ForegroundWindow,
    verifier: &dyn BiometricVerifier,
) -> ConfirmDecision {
    match window.show(content) {
        WindowIntent::Deny => ConfirmDecision::Deny,
        WindowIntent::Timeout => ConfirmDecision::Timeout,
        WindowIntent::Unavailable => ConfirmDecision::Unavailable,
        WindowIntent::Approve => match verifier.verify(content.action) {
            VerifyOutcome::Verified => ConfirmDecision::Approve,
            VerifyOutcome::Declined => ConfirmDecision::Deny,
            VerifyOutcome::Failed => ConfirmDecision::Deny,
            VerifyOutcome::Unavailable => ConfirmDecision::Unavailable,
        },
    }
}

/// A [`NativeConfirmer`] built from a [`ForegroundWindow`] + [`BiometricVerifier`] pair.
///
/// Every per-OS backend is one of these: it supplies the two OS adapters, and this type maps each of
/// the three trait prompts to its [`ConfirmContent`] and runs the shared [`gated_consent`]. Keeping
/// the composition here means a backend cannot diverge in its security logic — it only implements the
/// two thin OS adapters.
pub(crate) struct BackedConfirmer<W: ForegroundWindow, V: BiometricVerifier> {
    window: W,
    verifier: V,
}

impl<W: ForegroundWindow, V: BiometricVerifier> BackedConfirmer<W, V> {
    /// Assemble a confirmer over the given OS window + biometric verifier.
    pub(crate) fn new(window: W, verifier: V) -> Self {
        Self { window, verifier }
    }
}

impl<W: ForegroundWindow, V: BiometricVerifier> NativeConfirmer for BackedConfirmer<W, V> {
    fn confirm_pair(&self, prompt: &PairPrompt<'_>) -> ConfirmDecision {
        gated_consent(&ConfirmContent::pair(prompt), &self.window, &self.verifier)
    }

    fn confirm_connect(&self, prompt: &ConnectPrompt<'_>) -> ConfirmDecision {
        gated_consent(
            &ConfirmContent::connect(prompt),
            &self.window,
            &self.verifier,
        )
    }

    fn confirm_sign(&self, prompt: &SignPrompt<'_>) -> ConfirmDecision {
        // Never blind-sign: no decoded transaction ⇒ deny WITHOUT raising a window (§5.6.5).
        match ConfirmContent::sign(prompt) {
            Some(content) => gated_consent(&content, &self.window, &self.verifier),
            None => ConfirmDecision::Deny,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn headless_confirmer_fails_closed_on_every_prompt() {
        let confirmer = HeadlessConfirmer;
        assert_eq!(
            confirmer.confirm_pair(&PairPrompt {
                ext_id: "id",
                ext_label: None
            }),
            ConfirmDecision::Unavailable
        );
        assert_eq!(
            confirmer.confirm_connect(&ConnectPrompt {
                origin: "https://dapp.example",
                dapp_name: None
            }),
            ConfirmDecision::Unavailable
        );
        assert_eq!(
            confirmer.confirm_sign(&SignPrompt {
                origin: "https://dapp.example",
                payload_type: "spend",
                decoded_tx: None
            }),
            ConfirmDecision::Unavailable
        );
    }

    // ---- Test doubles: a foreground window + biometric that return scripted outcomes. ----

    struct FakeWindow(WindowIntent);
    impl ForegroundWindow for FakeWindow {
        fn show(&self, _content: &ConfirmContent) -> WindowIntent {
            self.0
        }
    }

    struct FakeVerifier(VerifyOutcome);
    impl BiometricVerifier for FakeVerifier {
        fn verify(&self, _reason: &str) -> VerifyOutcome {
            self.0
        }
    }

    /// A window that records the content it was asked to show, to assert what the user would see.
    struct RecordingWindow(std::sync::Mutex<Option<ConfirmContent>>);
    impl ForegroundWindow for RecordingWindow {
        fn show(&self, content: &ConfirmContent) -> WindowIntent {
            *self.0.lock().unwrap() = Some(content.clone());
            WindowIntent::Approve
        }
    }

    const SPEND_TX: &str = "Send 100 $DIG to xch1abc… (fee 0.0001 XCH)";

    fn sign_prompt(decoded: Option<&'static str>) -> SignPrompt<'static> {
        SignPrompt {
            origin: "https://dapp.example",
            payload_type: "spend",
            decoded_tx: decoded,
        }
    }

    // ---- gated_consent: the shared security policy, exhaustively. ----

    #[test]
    fn approve_requires_both_the_shown_action_and_a_verified_biometric() {
        let content = ConfirmContent::sign(&sign_prompt(Some(SPEND_TX))).unwrap();
        let decision = gated_consent(
            &content,
            &FakeWindow(WindowIntent::Approve),
            &FakeVerifier(VerifyOutcome::Verified),
        );
        assert_eq!(decision, ConfirmDecision::Approve);
    }

    #[test]
    fn window_denial_short_circuits_before_the_biometric() {
        // Even a would-be-verified biometric cannot rescue a denied/timed-out window.
        for (intent, expected) in [
            (WindowIntent::Deny, ConfirmDecision::Deny),
            (WindowIntent::Timeout, ConfirmDecision::Timeout),
            (WindowIntent::Unavailable, ConfirmDecision::Unavailable),
        ] {
            let content = ConfirmContent::pair(&PairPrompt {
                ext_id: "id",
                ext_label: None,
            });
            let decision = gated_consent(
                &content,
                &FakeWindow(intent),
                &FakeVerifier(VerifyOutcome::Verified),
            );
            assert_eq!(decision, expected, "intent {intent:?}");
        }
    }

    #[test]
    fn a_dismissed_or_failed_biometric_fails_closed_after_an_approved_window() {
        for (outcome, expected) in [
            (VerifyOutcome::Declined, ConfirmDecision::Deny),
            (VerifyOutcome::Failed, ConfirmDecision::Deny),
            (VerifyOutcome::Unavailable, ConfirmDecision::Unavailable),
        ] {
            let content = ConfirmContent::connect(&ConnectPrompt {
                origin: "https://dapp.example",
                dapp_name: None,
            });
            let decision = gated_consent(
                &content,
                &FakeWindow(WindowIntent::Approve),
                &FakeVerifier(outcome),
            );
            assert_eq!(decision, expected, "outcome {outcome:?}");
        }
    }

    // ---- BackedConfirmer: the trait wiring + the never-blind-sign guard. ----

    fn confirmer(
        intent: WindowIntent,
        outcome: VerifyOutcome,
    ) -> BackedConfirmer<FakeWindow, FakeVerifier> {
        BackedConfirmer::new(FakeWindow(intent), FakeVerifier(outcome))
    }

    #[test]
    fn backed_confirmer_approves_each_prompt_when_window_and_biometric_agree() {
        let c = confirmer(WindowIntent::Approve, VerifyOutcome::Verified);
        assert_eq!(
            c.confirm_pair(&PairPrompt {
                ext_id: "id",
                ext_label: Some("My Wallet")
            }),
            ConfirmDecision::Approve
        );
        assert_eq!(
            c.confirm_connect(&ConnectPrompt {
                origin: "https://dapp.example",
                dapp_name: None
            }),
            ConfirmDecision::Approve
        );
        assert_eq!(
            c.confirm_sign(&sign_prompt(Some(SPEND_TX))),
            ConfirmDecision::Approve
        );
    }

    #[test]
    fn sign_with_no_decoded_tx_is_denied_without_ever_showing_a_window() {
        // A window that would approve — but a missing decoded tx must short-circuit to Deny so a
        // caller can never coax a blind-sign approval (§5.6.5, defense-in-depth over dispatch).
        let recorder = RecordingWindow(std::sync::Mutex::new(None));
        let confirmer = BackedConfirmer::new(recorder, FakeVerifier(VerifyOutcome::Verified));
        assert_eq!(
            confirmer.confirm_sign(&sign_prompt(None)),
            ConfirmDecision::Deny
        );
        assert!(
            confirmer.window.0.lock().unwrap().is_none(),
            "no window may be raised for a blind-sign request"
        );
    }

    // ---- ConfirmContent: the origin binding + decoded-tx display. ----

    #[test]
    fn sign_content_shows_origin_type_and_the_decoded_transaction() {
        let content = ConfirmContent::sign(&sign_prompt(Some(SPEND_TX))).unwrap();
        assert_eq!(content.action, "Sign");
        assert!(content.heading.contains("https://dapp.example"));
        assert!(content.body.contains("spend"));
        assert!(content.body.contains(SPEND_TX));
    }

    #[test]
    fn sign_content_is_none_without_a_decoded_transaction() {
        assert!(ConfirmContent::sign(&sign_prompt(None)).is_none());
    }

    #[test]
    fn pair_content_shows_the_extension_label_and_id() {
        let content = ConfirmContent::pair(&PairPrompt {
            ext_id: "abcdef",
            ext_label: Some("My Wallet"),
        });
        assert_eq!(content.action, "Pair");
        assert!(content.heading.contains("My Wallet"));
        assert!(content.heading.contains("abcdef"));
    }

    #[test]
    fn connect_content_binds_the_origin() {
        let content = ConfirmContent::connect(&ConnectPrompt {
            origin: "https://dapp.example",
            dapp_name: Some("Cool Dapp"),
        });
        assert_eq!(content.action, "Connect");
        assert!(content.heading.contains("Cool Dapp"));
        assert!(content.body.contains("https://dapp.example"));
    }

    #[test]
    fn native_confirmer_factory_returns_a_working_confirmer() {
        // On a headless CI host the factory falls back to the fail-closed confirmer; on a desktop it
        // returns the per-OS backend. Either way the returned trait object must be usable.
        let confirmer = native_confirmer();
        let _ = confirmer.confirm_sign(&sign_prompt(None));
    }
}
