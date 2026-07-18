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
}
