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

/// The reveal-confirm prompt: *"Show your recovery phrase?"* (dig_ecosystem#1752).
///
/// Revealing the phrase hands over the whole account, so it is gated exactly like a signature — a real
/// foreground window plus a biometric re-authentication. The prompt names WHAT is about to be shown so
/// the window can warn about the surroundings ("anyone who can see your screen…").
#[derive(Debug, Clone, Copy)]
pub struct RevealPrompt<'a> {
    /// What is about to be revealed, in the user's words (e.g. `"your 24-word recovery phrase"`).
    pub secret: &'a str,
}

/// A display-only notice: text the user acknowledges once, with no decision and no biometric step
/// (dig_ecosystem#1752).
///
/// This is how the recovery phrase itself reaches the screen, and how every tray message is drawn. It is
/// NOT an authorization surface — the authorization already happened (a [`RevealPrompt`] confirm, or a
/// first-run setup the user initiated) — so it carries no verifier; it exists so the words are drawn by
/// the same OS-owned, focus-stealing, never-logged window every other DIG prompt uses, rather than a
/// console print or a log line.
///
/// **A notice has ONE choice.** Nothing downstream of a notice branches on how it was dismissed, so a
/// second button would be a decision the user is invited to make and that no code reads — see
/// [`Presentation`]. A screen where the negative answer genuinely changes the outcome is a
/// [`ClaimPrompt`], not a notice.
#[derive(Debug, Clone, Copy)]
pub struct NoticePrompt<'a> {
    /// The window title.
    pub title: &'a str,
    /// The primary line.
    pub heading: &'a str,
    /// The body — for a phrase reveal, the numbered words.
    pub body: &'a str,
    /// The label of the single dismiss button (e.g. `"OK"`, `"Done"`).
    pub acknowledge: &'static str,
}

/// A **claim** prompt: a real either/or where the user asserts something about the world, and refusing
/// changes what happens (dig_ecosystem#1773).
///
/// The distinguishing property, and the reason this is not a [`NoticePrompt`]: the caller BRANCHES on the
/// answer. The enrolment flow asks "do you have your 24 words written down?" and abandons setup on a
/// refusal — so the negative choice is load-bearing and must be offered as a real, labelled way out.
///
/// It is not a [`RevealPrompt`]/[`SignPrompt`] either: nothing is being authorized, so there is no
/// biometric step. It sits deliberately between the two.
#[derive(Debug, Clone, Copy)]
pub struct ClaimPrompt<'a> {
    /// The window title.
    pub title: &'a str,
    /// The question being put to the user.
    pub heading: &'a str,
    /// The consequence of each answer, in the user's words.
    pub body: &'a str,
    /// The label of the affirming choice — a first-person claim (e.g. `"I have written these down"`).
    pub affirm: &'static str,
}

/// A **destroy** prompt: the user is about to lose key material for good (dig_ecosystem#1799).
///
/// Replacing or removing a DIG Account discards its master seed, and everything sealed under it becomes
/// unreadable. That is at least as consequential as one signature, so it goes through the same two-step
/// AUTHORIZATION gate — a foreground window naming exactly what is lost, then an OS re-authentication —
/// and never through [`NoticePrompt`] (one button, no decision) or [`ClaimPrompt`] (two buttons, no
/// biometric). A user who has walked away from an unlocked machine must not lose their account to a
/// passer-by clicking two menu items.
#[derive(Debug, Clone, Copy)]
pub struct DestroyPrompt<'a> {
    /// What is about to be destroyed, in the user's words (e.g. `"the DIG Account on this computer"`).
    pub subject: &'a str,
    /// What happens next, if anything (e.g. `"A brand-new account will be created in its place."`).
    /// Empty when the action only destroys.
    pub replacement: &'a str,
    /// Whether the account being destroyed has a recovery phrase.
    ///
    /// Drives the WARNING, not the permission: without a phrase the loss is absolute and the window says
    /// so in the strongest terms; with one, the words still restore it elsewhere. Never used to skip the
    /// gate — both cases are irreversible on THIS computer.
    pub recoverable: bool,
}

/// A request for the user to TYPE something in a native window (dig_ecosystem#1798).
///
/// # Why this seam exists
///
/// A recovery phrase is 24 words of typed input, and a tray menu has no text field: the OS hands a tray
/// only menu items. That is a property of the tray API, not a reason to send a person to a terminal — and
/// the tray shipped `"Restore from a recovery phrase (in a terminal)…"` for exactly that reason. The
/// honest destination is a real OS window with a real input control, which is what every backend behind
/// this seam draws (Win32 `EDIT`, `NSAlert` accessory field, `zenity --entry`).
///
/// **The subprocess-helper alternative was rejected on security grounds.** Shelling out to a small
/// "ask for a phrase" binary would need a verify-the-helper-is-ours check, or a `PATH` impostor
/// harvests recovery phrases. Every backend here draws the window IN THIS PROCESS.
#[derive(Debug, Clone, Copy)]
pub struct InputPrompt<'a> {
    /// The window title.
    pub title: &'a str,
    /// The primary line — what is being asked for.
    pub heading: &'a str,
    /// The body: the format expected, and the consequence of getting it wrong.
    pub body: &'a str,
    /// The label beside the field itself (e.g. `"Your 24 words:"`).
    pub field_label: &'a str,
    /// The label of the submit button (e.g. `"Restore"`).
    pub submit: &'static str,
    /// Whether the typed characters start out hidden.
    ///
    /// Secret material is masked by DEFAULT (`SPEC.md` §3.1d): the words already exist on paper, so a
    /// person who can see the screen is the live risk, and a typo costs only a retry.
    pub masked: bool,
    /// Whether the window offers a reveal-while-typing control.
    ///
    /// §3.1d's own escape from the masking rule, and what makes it humane: masking is right by default, but
    /// 24 words typed entirely blind cannot be checked, so the field is masked AND deliberately un-maskable
    /// rather than defaulting to clear text. A short passphrase needs no such control.
    pub revealable: bool,
}

/// What came back from an [`InputPrompt`].
///
/// [`Debug`] is implemented by hand and REDACTS the text: this type carries recovery phrases, and a
/// derived `Debug` would put one into any log line, panic message or test failure that formatted it
/// (`tests/never_log.rs` pins the rule).
pub enum InputOutcome {
    /// The user typed something and submitted it. Wrapped in [`Zeroizing`] so the buffer is wiped when
    /// the caller drops it.
    Provided(zeroize::Zeroizing<String>),
    /// The user cancelled or closed the window. Nothing was typed that the caller may act on.
    Cancelled,
    /// No input window could be drawn (a headless host, no dialog helper). Callers MUST fail closed —
    /// never treat it as an empty answer.
    Unavailable,
}

impl std::fmt::Debug for InputOutcome {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            // The LENGTH is safe and is what a debugging session actually needs ("did anything arrive?").
            Self::Provided(text) => write!(f, "Provided(<{} redacted chars>)", text.len()),
            Self::Cancelled => f.write_str("Cancelled"),
            Self::Unavailable => f.write_str("Unavailable"),
        }
    }
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

    /// Confirm revealing a secret (the recovery phrase) on screen.
    ///
    /// Defaults to [`ConfirmDecision::Unavailable`] so a backend that has not implemented it refuses to
    /// reveal rather than revealing unguarded — the same fail-closed default the rest of this trait has.
    fn confirm_reveal(&self, _prompt: &RevealPrompt<'_>) -> ConfirmDecision {
        ConfirmDecision::Unavailable
    }

    /// Draw a display-only notice — ONE dismiss button, no decision — and report whether it reached the
    /// screen.
    ///
    /// Returns [`ConfirmDecision::Approve`] when the user saw and dismissed it, and
    /// [`ConfirmDecision::Unavailable`] when no window could be drawn, which callers MUST treat as "the
    /// user never saw this". A notice offers nothing to decline, so [`ConfirmDecision::Deny`] means only
    /// that the window was closed by its frame rather than its button — the same "it was seen" outcome.
    fn show_notice(&self, _prompt: &NoticePrompt<'_>) -> ConfirmDecision {
        ConfirmDecision::Unavailable
    }

    /// Put a real either/or to the user, where refusing changes what happens (dig_ecosystem#1773).
    ///
    /// Unlike [`show_notice`](Self::show_notice) this draws two labelled choices, because the caller
    /// branches on the answer; unlike [`confirm_reveal`](Self::confirm_reveal) it runs no biometric,
    /// because nothing is being authorized. Defaults to [`ConfirmDecision::Unavailable`] so a backend that
    /// cannot ask refuses to proceed rather than assuming a "yes" — the enrolment path relies on that to
    /// refuse creating an account whose retention could not be confirmed.
    fn confirm_claim(&self, _prompt: &ClaimPrompt<'_>) -> ConfirmDecision {
        ConfirmDecision::Unavailable
    }

    /// Authorize destroying key material — replacing or removing an account (dig_ecosystem#1799).
    ///
    /// Runs the SAME two-step gate as a signature (foreground window + OS re-authentication), because a
    /// destroyed master seed is unrecoverable. Defaults to [`ConfirmDecision::Unavailable`] so a backend
    /// that cannot authorize refuses to destroy rather than destroying unguarded.
    fn confirm_destroy(&self, _prompt: &DestroyPrompt<'_>) -> ConfirmDecision {
        ConfirmDecision::Unavailable
    }

    /// Ask the user to TYPE something in a native window (dig_ecosystem#1798).
    ///
    /// Defaults to [`InputOutcome::Unavailable`] so a backend with no input window reports that it could
    /// not ask, rather than an empty answer a caller might treat as submitted text.
    fn request_input(&self, _prompt: &InputPrompt<'_>) -> InputOutcome {
        InputOutcome::Unavailable
    }
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

    fn confirm_reveal(&self, _prompt: &RevealPrompt<'_>) -> ConfirmDecision {
        ConfirmDecision::Unavailable
    }

    fn show_notice(&self, _prompt: &NoticePrompt<'_>) -> ConfirmDecision {
        ConfirmDecision::Unavailable
    }

    fn confirm_claim(&self, _prompt: &ClaimPrompt<'_>) -> ConfirmDecision {
        ConfirmDecision::Unavailable
    }

    fn confirm_destroy(&self, _prompt: &DestroyPrompt<'_>) -> ConfirmDecision {
        ConfirmDecision::Unavailable
    }

    fn request_input(&self, _prompt: &InputPrompt<'_>) -> InputOutcome {
        InputOutcome::Unavailable
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
// Windows keeps every window in `windows_input`: one hand-built window class with a message loop, drawn with
// or without a field. `windows` holds only the Windows Hello step and the backend's construction.
#[cfg(target_os = "windows")]
mod windows_input;

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
    /// The label of the affirmative action (`"Pair"`, `"Connect"`, `"Sign"`, `"OK"`), reused as the reason
    /// string the biometric prompt shows.
    pub action: &'static str,
    /// How many choices this window offers, and how they read — see [`Presentation`].
    pub presentation: Presentation,
}

/// Whether a confirm window asks the user to DECIDE something or merely to acknowledge it.
///
/// # Why this is a type and not a flag
///
/// Every DIG confirm window used to be drawn with two buttons and, on Windows, a warning triangle —
/// including the eleven purely informational tray messages ("Your DIG ID is on the clipboard", "DIG could
/// not open the folder for you"). A window with a Cancel nobody reads asks the user to make a decision
/// that does not exist, and a triangle on "here is your DIG ID" reads as an error the user must resolve;
/// both were visible only in a screenshot, since every code path involved was working correctly
/// (dig_ecosystem#1773).
///
/// The presentation is therefore part of the CONTENT, decided once where the content is composed and
/// unit-tested, rather than a per-backend styling choice. Because the choice sentence lives inside
/// [`Decide`](Self::Decide), a notice cannot carry one even by accident.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Presentation {
    /// ONE dismiss button. Informational: nothing branches on the answer, so nothing is asked.
    Acknowledge,
    /// TWO labelled choices, because refusing genuinely changes what happens.
    Decide {
        /// Whether the REFUSING choice must be the pre-selected default.
        ///
        /// A dialog defaults to its FIRST button, so a destroy window would confirm irreversible key
        /// destruction on a bare Enter — a review finding (dig_ecosystem#1799). For a destroy the safe answer
        /// is therefore pre-selected; for a sign, a pairing or a connect the affirmative stays the default,
        /// because those are the actions the user just asked for and refusing them costs nothing but a retry.
        refusal_is_default: bool,
    },
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
            presentation: Self::authorize(),
        }
    }

    /// The content for a reveal confirm (dig_ecosystem#1752): approve putting a secret on screen.
    ///
    /// The body warns about the *surroundings*, not the mechanics, because that is the actual risk at
    /// this moment: the account is already unlocked and the user already asked — what they may not have
    /// considered is who else can see the screen, or a screen recorder.
    fn reveal(prompt: &RevealPrompt<'_>) -> Self {
        Self {
            title: "DIG — Reveal recovery phrase".to_string(),
            heading: format!("Show {} on this screen?", prompt.secret),
            body: "Anyone who can see your screen — or any screen-sharing or recording that is running \
                   — will see it, and anyone who has it can take your DIG Account. Make sure you are \
                   alone before continuing."
                .to_string(),
            action: "Reveal",
            presentation: Self::authorize(),
        }
    }

    /// The content for a display-only notice (dig_ecosystem#1752), passed through verbatim: the caller
    /// owns this copy because it is showing secret material it composed itself.
    ///
    /// [`Presentation::Acknowledge`] is the whole point of the type — an informational window gets one
    /// button and an informational icon, so it does not read as a question the user must answer or an
    /// error they must resolve (dig_ecosystem#1773).
    fn notice(prompt: &NoticePrompt<'_>) -> Self {
        Self {
            title: prompt.title.to_string(),
            heading: prompt.heading.to_string(),
            body: prompt.body.to_string(),
            action: prompt.acknowledge,
            presentation: Presentation::Acknowledge,
        }
    }

    /// The content for a claim prompt (dig_ecosystem#1773): a real either/or with no biometric.
    fn claim(prompt: &ClaimPrompt<'_>) -> Self {
        Self {
            title: prompt.title.to_string(),
            heading: prompt.heading.to_string(),
            body: prompt.body.to_string(),
            action: prompt.affirm,
            // The affirming label is a first-person CLAIM ("I have written these down"), so it is quoted as
            // a choice rather than slotted into a "Choose OK to <verb>" sentence that cannot read
            // correctly (#1752). "Not yet" names what Cancel actually does here — it does not reject an
            // authorization, it says the claim is not true yet.
            presentation: Presentation::Decide {
                refusal_is_default: false,
            },
        }
    }

    /// The content for a destroy confirm (dig_ecosystem#1799): authorize losing key material.
    ///
    /// The body states the irreversible consequence FIRST and in the user's own terms, because this is the
    /// last screen before the seed is gone. `recoverable` changes the SEVERITY of the warning, never the
    /// gate: an account with a phrase can be brought back from the words *somewhere else*, but on this
    /// computer both cases are equally final.
    fn destroy(prompt: &DestroyPrompt<'_>) -> Self {
        let loss = if prompt.recoverable {
            "Everything sealed under it on this computer becomes unreadable. You can only get this \
             account back with its 24-word recovery phrase — if you do not have those words written \
             down, it is gone for good."
        } else {
            "This account has NO recovery phrase, so it exists ONLY on this computer. Once it is \
             destroyed, it and everything sealed under it are gone for good — not recoverable by you \
             and not by DIG."
        };
        Self {
            title: "DIG — Destroy this account".to_string(),
            heading: format!("Permanently destroy {}?", prompt.subject),
            body: match prompt.replacement.is_empty() {
                true => loss.to_string(),
                false => format!("{loss}\n\n{}", prompt.replacement),
            },
            action: "Destroy",
            // NOT `Self::authorize`: this is the one window where a bare Enter must not confirm. Both
            // platform dialogs default to their first button, so the refusal is pre-selected here.
            presentation: Presentation::Decide {
                refusal_is_default: true,
            },
        }
    }

    /// The two-choice presentation for an AUTHORIZATION prompt.
    ///
    /// The affirmative stays the default: the user asked for this, and a refusal costs only a retry. The one
    /// exception is a DESTROY, which composes its presentation directly (see [`ConfirmContent::destroy`]).
    ///
    /// Named rather than written inline at each call site so that "an authorization defaults to its
    /// affirmative" is stated ONCE. Four prompts sharing a literal is four places for the destroy window's
    /// rule to be copied into by mistake.
    fn authorize() -> Presentation {
        Presentation::Decide {
            refusal_is_default: false,
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
            presentation: Self::authorize(),
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
            presentation: Self::authorize(),
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
    /// Only the backends that distinguish this from a plain cancel construct it (Windows Hello's
    /// `RetriesExhausted`, a polkit error exit); macOS collapses it into `Declined`, so it is
    /// permitted dead on that target.
    #[allow(dead_code)]
    Failed,
    /// No authenticator is available or enrolled — fail closed.
    Unavailable,
}

/// What one native INPUT window must display, built purely from an [`InputPrompt`].
///
/// The same reason [`ConfirmContent`] is owned: a backend may need to move it across an FFI or thread
/// boundary to the UI, and centralizing the render keeps "what the user is shown" in one tested place.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct InputContent {
    /// The window title bar text.
    pub title: String,
    /// The primary line — what is being asked for.
    pub heading: String,
    /// The detail beneath it: the expected format and the consequence of getting it wrong.
    pub body: String,
    /// The label beside the field.
    pub field_label: String,
    /// The submit button's label.
    pub submit: &'static str,
    /// Whether typed characters start out hidden.
    pub masked: bool,
    /// Whether a reveal-while-typing control is offered.
    pub revealable: bool,
}

impl InputContent {
    /// Compose the window content for `prompt`, passed through verbatim: the caller owns this copy
    /// because it is asking for material it will handle itself.
    fn of(prompt: &InputPrompt<'_>) -> Self {
        Self {
            title: prompt.title.to_string(),
            heading: prompt.heading.to_string(),
            body: prompt.body.to_string(),
            field_label: prompt.field_label.to_string(),
            submit: prompt.submit,
            masked: prompt.masked,
            revealable: prompt.revealable,
        }
    }
}

/// Raises a foreground window with a real text-input control and returns what the user typed.
///
/// Separate from [`ForegroundWindow`] because the RESULT is different in kind: this one returns text the
/// caller must handle as a secret, and conflating "the user consented" with "the user typed this" is how a
/// window's answer gets acted on as an empty string. On Windows both are now drawn by the same window class
/// (dig_ecosystem#1832); the seams stay separate because the outcomes do.
pub(crate) trait ForegroundInput: Send + Sync {
    /// Show `content` as a real, focus-stealing OS window and block until the user submits or cancels.
    fn ask(&self, content: &InputContent) -> InputOutcome;
}

/// A [`ForegroundInput`] for a platform that has no input window yet: it always reports that it could not
/// ask, so a caller fails closed rather than reading a phantom empty answer.
///
/// Kept as the explicit, named alternative to silently omitting the seam, so a backend that has not built
/// its input window says so in its own construction rather than inheriting a default nobody notices.
///
/// No production backend uses it today — Windows, macOS and Linux all draw a real input window — so it is
/// reachable only from the seam's own tests. It is kept rather than deleted because it is the named,
/// fail-closed thing a FUTURE backend (a new platform, a stripped build) must pass, and the alternative is
/// that backend silently omitting the seam.
#[derive(Debug, Default, Clone, Copy)]
#[allow(dead_code)]
pub(crate) struct NoInputWindow;

impl ForegroundInput for NoInputWindow {
    fn ask(&self, _content: &InputContent) -> InputOutcome {
        InputOutcome::Unavailable
    }
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
pub(crate) struct BackedConfirmer<W: ForegroundWindow, V: BiometricVerifier, I: ForegroundInput> {
    window: W,
    verifier: V,
    input: I,
}

impl<W: ForegroundWindow, V: BiometricVerifier, I: ForegroundInput> BackedConfirmer<W, V, I> {
    /// Assemble a confirmer over the given OS confirm window, biometric verifier and input window.
    ///
    /// The input window is a required constructor argument rather than an optional extra: a platform that
    /// has not built one must pass [`NoInputWindow`] and say so out loud, because a silently-absent input
    /// seam is how the tray came to point at a terminal (dig_ecosystem#1798).
    pub(crate) fn new(window: W, verifier: V, input: I) -> Self {
        Self {
            window,
            verifier,
            input,
        }
    }

    /// Draw `content` and report what came back, with NO biometric step — the shared body of the two
    /// non-authorizing prompts (a notice and a claim).
    fn draw(&self, content: &ConfirmContent) -> ConfirmDecision {
        match self.window.show(content) {
            WindowIntent::Approve => ConfirmDecision::Approve,
            WindowIntent::Deny => ConfirmDecision::Deny,
            WindowIntent::Timeout => ConfirmDecision::Timeout,
            WindowIntent::Unavailable => ConfirmDecision::Unavailable,
        }
    }
}

impl<W: ForegroundWindow, V: BiometricVerifier, I: ForegroundInput> NativeConfirmer
    for BackedConfirmer<W, V, I>
{
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

    fn confirm_reveal(&self, prompt: &RevealPrompt<'_>) -> ConfirmDecision {
        // The same two-step gate as a signature: the window explains the risk, the biometric proves who
        // is asking. Revealing the phrase is at least as consequential as one signature.
        gated_consent(
            &ConfirmContent::reveal(prompt),
            &self.window,
            &self.verifier,
        )
    }

    fn show_notice(&self, prompt: &NoticePrompt<'_>) -> ConfirmDecision {
        // Display only: no biometric, because nothing is being authorized here — the authorization
        // happened before we composed the content this window is showing.
        self.draw(&ConfirmContent::notice(prompt))
    }

    fn confirm_claim(&self, prompt: &ClaimPrompt<'_>) -> ConfirmDecision {
        // Two choices, still no biometric: the user is asserting something about the world (their words
        // are written down), not authorizing DIG to act with their key.
        self.draw(&ConfirmContent::claim(prompt))
    }

    fn confirm_destroy(&self, prompt: &DestroyPrompt<'_>) -> ConfirmDecision {
        // The SAME gate as a signature, deliberately: the window states the irreversible loss, the
        // biometric proves it is the machine's owner asking. Destroying a master seed must never be
        // reachable by a passer-by at an unlocked desk clicking two menu items (dig_ecosystem#1799).
        gated_consent(
            &ConfirmContent::destroy(prompt),
            &self.window,
            &self.verifier,
        )
    }

    fn request_input(&self, prompt: &InputPrompt<'_>) -> InputOutcome {
        // No biometric: typing a recovery phrase is not an authorization to act with an existing key —
        // it SUPPLIES one. What the typed words then authorize (a restore, which destroys any account
        // already here) is gated separately by `confirm_destroy` in the journey.
        self.input.ask(&InputContent::of(prompt))
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
    ) -> BackedConfirmer<FakeWindow, FakeVerifier, NoInputWindow> {
        BackedConfirmer::new(FakeWindow(intent), FakeVerifier(outcome), NoInputWindow)
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
        let confirmer = BackedConfirmer::new(
            recorder,
            FakeVerifier(VerifyOutcome::Verified),
            NoInputWindow,
        );
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

    /// The label on `content`'s affirmative BUTTON, or `None` when it offers no choice.
    ///
    /// This replaced a `hint_of` that returned the choice SENTENCE. Windows drew its own window from
    /// dig_ecosystem#1832 onward, so there is no longer a sentence anywhere — every platform now puts
    /// `action` directly on the button, which is what macOS and Linux always did.
    fn affirm_label_of(content: &ConfirmContent) -> Option<&str> {
        match &content.presentation {
            Presentation::Acknowledge => None,
            Presentation::Decide { .. } => Some(content.action),
        }
    }

    /// **Regression (#1752, now structural).** A CLAIM window's first-person affirming label must reach the
    /// user VERBATIM. The original defect was a live Windows window reading *"Choose OK to I have written
    /// these down, or Cancel to reject."* — the label slotted into an authorization sentence.
    ///
    /// The sentence is gone: from dig_ecosystem#1832 Windows draws its own window and puts `action` on the
    /// button, so there is no template left to slot a label into. This test pins the property that replaced
    /// it — the label passes through untouched — which is a stronger assertion than the old one, because it
    /// fails on ANY rewording, not only on the one wrong template.
    ///
    /// The fixture is the real label from the display-once phrase screen: a first-person claim rather than an
    /// imperative verb, because a verb-shaped label ("Done", "OK") reads fine either way and so could not
    /// distinguish the bug from the fix.
    #[test]
    fn a_claim_puts_its_first_person_label_on_the_button_verbatim() {
        let content = ConfirmContent::claim(&ClaimPrompt {
            title: "DIG — Your recovery phrase",
            heading: "Write these 24 words down.",
            body: " 1. abandon",
            affirm: "I have written these down",
        });

        let label = affirm_label_of(&content)
            .expect("a claim is a real either/or, so it has an affirmative button");
        assert_eq!(
            label, "I have written these down",
            "the claim's own words must reach the button unchanged"
        );
    }

    /// The control: an AUTHORIZATION prompt puts its imperative VERB on the button, so the two kinds of
    /// affirmative stay distinguishable rather than collapsing into one generic label.
    #[test]
    fn an_authorization_puts_its_imperative_verb_on_the_button() {
        assert_eq!(
            affirm_label_of(&ConfirmContent::reveal(&RevealPrompt {
                secret: "your recovery phrase"
            })),
            Some("Reveal")
        );
    }

    /// **Regression (#1773).** A notice offers NO second choice at all, on any platform — so it has no
    /// affirmative-versus-refusal to label, only a dismiss.
    ///
    /// Paired with `an_authorization_puts_its_imperative_verb_on_the_button` above: together they pin that the
    /// presentation distinguishes the two kinds rather than collapsing them, which a one-sided assertion
    /// could not.
    #[test]
    fn a_notice_offers_no_second_choice() {
        let content = ConfirmContent::notice(&NoticePrompt {
            title: "DIG — DIG ID copied",
            heading: "Your DIG ID is on the clipboard.",
            body: "abc123",
            acknowledge: "OK",
        });

        assert_eq!(content.presentation, Presentation::Acknowledge);
        assert_eq!(affirm_label_of(&content), None);
    }

    /// A claim is drawn WITHOUT a biometric step: the user is asserting something about the world, not
    /// authorizing DIG to act with their key. Asserted by scripting a verifier that would REFUSE — if the
    /// claim path consulted it, the approval could not come back.
    #[test]
    fn a_claim_is_answered_by_the_window_alone_with_no_biometric() {
        let confirmer = confirmer(WindowIntent::Approve, VerifyOutcome::Unavailable);
        assert_eq!(
            confirmer.confirm_claim(&ClaimPrompt {
                title: "DIG — Confirm you saved it",
                heading: "Do you have your 24 words written down somewhere safe?",
                body: "If you continue without them…",
                affirm: "Yes, I have them",
            }),
            ConfirmDecision::Approve
        );
    }

    /// …and the control: an AUTHORIZATION with that same refusing verifier fails closed. Without this, a
    /// confirmer that ignored the biometric everywhere would pass the test above.
    #[test]
    fn an_authorization_with_the_same_unavailable_verifier_fails_closed() {
        let confirmer = confirmer(WindowIntent::Approve, VerifyOutcome::Unavailable);
        assert_eq!(
            confirmer.confirm_reveal(&RevealPrompt {
                secret: "your recovery phrase"
            }),
            ConfirmDecision::Unavailable
        );
    }

    /// The fail-closed default: a backend that has not implemented `confirm_claim` refuses rather than
    /// assuming a "yes", so enrolment cannot proceed on an unasked retention claim.
    #[test]
    fn an_unimplemented_claim_backend_refuses_rather_than_assuming_yes() {
        assert_eq!(
            HeadlessConfirmer.confirm_claim(&ClaimPrompt {
                title: "t",
                heading: "h",
                body: "b",
                affirm: "Yes",
            }),
            ConfirmDecision::Unavailable
        );
    }
}
