//! The **enrolment, challenge and disable journeys** — the order these screens happen in for a human
//! (dig-app#348, superseding dig_ecosystem#1840).
//!
//! The pieces underneath are narrow on purpose: [`authenticator`](super::authenticator) knows how to
//! reach a key, [`verifier`](super::verifier) knows how to judge what it says,
//! [`recovery_codes`](super::recovery_codes) knows codes, [`vault`](super::vault) knows at-rest, and
//! [`confirm`](crate::confirm) knows how to draw an OS-owned window. This module is the only place
//! that knows the SEQUENCE, which is where the safety rules live:
//!
//! - **Nothing is written until the key has proved it can assert.** Every failure and every escape
//!   before that point leaves no enrolment at all, so a person can back out of any screen and be
//!   exactly where they started. A setup flow that enrols first and confirms afterwards is how someone
//!   ends up locked out of their own account by the feature that was meant to protect it — and with an
//!   asymmetric factor that is worse, not better, because there is no secret they could write down.
//! - **A refusal that this build can predict comes BEFORE any window.** An existing enrolment, a
//!   superseded one, and a platform with no client are all knowable without asking the user for
//!   anything, so none of them may be discovered halfway through a ceremony.
//! - **The recovery codes are claimed, not merely shown.** Same two-step treatment the recovery phrase
//!   gets ([`ClaimPrompt`]), because refusing is load-bearing: it abandons the enrolment rather than
//!   proceeding with codes nobody kept.
//! - **Turning it off is an authorization AND the factor.** The platform window
//!   ([`NativeConfirmer::confirm_security_change`]) first, the factor's own evidence second.
//! - **Nothing here logs a credential, an assertion or a code.**

use crate::confirm::{
    ClaimPrompt, ConfirmDecision, InputOutcome, InputPrompt, InputStyle, NativeConfirmer,
    NoticePrompt, SecurityPrompt,
};
use crate::sealer::ProfileSealer;

use super::authenticator::{Authenticator, ClientOutcome, ClientSupport, CEREMONY_DEADLINE};
use super::recovery_codes::RecoveryCodeSet;
use super::vault::{ChallengeOutcome, Enrolment, RecordKind, SecondFactorVault, VaultError};
use super::verifier;

/// The most characters a window HEADING may carry.
///
/// The native window draws its heading as ONE unwrapped line in a larger face, and a `STATIC` control
/// silently clips what does not fit — so an over-long heading loses its tail with no error anywhere. A
/// screenshot of the first build caught exactly that: "Save these codes. They are how you get in if you
/// lose your phone." was drawn as "…if you lose", cutting the sentence at its most important word.
///
/// 50 is measured from that render, not guessed: the clip fell at roughly 52 characters at the window's
/// design width, so this leaves a character of slack. It is asserted by
/// `every_heading_fits_the_window_that_draws_it`, because "it looked fine" is exactly the kind of claim
/// that drifts the next time copy is edited. Test-only, because it is a BUDGET the copy is written
/// against rather than a value any code reads — production simply passes headings that fit.
#[cfg(test)]
const MAX_HEADING_CHARS: usize = 50;

/// The wall clock, injected so every journey is testable at a pinned instant.
///
/// A journey that read `SystemTime::now` directly could not be tested against a chosen throttle
/// deadline, and a test that passed small literals through a wall-clock API would silently be
/// exercising only the long-expired path.
pub trait Clock: Send + Sync {
    /// Seconds since the unix epoch.
    fn now_unix(&self) -> u64;
}

/// The production clock.
#[derive(Debug, Default, Clone, Copy)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now_unix(&self) -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            // A clock set before 1970 is not a state this app can reason about; treating it as the
            // epoch makes every deadline read as long past, which is the safe direction.
            .map(|d| d.as_secs())
            .unwrap_or(0)
    }
}

/// What happened when the user tried to set up a second factor.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EnrolOutcome {
    /// Enrolled. Carries how many recovery codes the user was given.
    Enrolled {
        /// How many recovery codes were issued.
        recovery_codes: usize,
    },
    /// The user backed out at one of the screens. NOTHING was enrolled.
    Abandoned,
    /// The platform ceremony did not finish — a cancelled dialog, a timeout, no key, or a platform
    /// error, which this app cannot tell apart (see [`ClientOutcome`]). Nothing was enrolled.
    ///
    /// Kept distinct from [`Abandoned`](Self::Abandoned) precisely BECAUSE it cannot be attributed:
    /// `Abandoned` is something the app watched the user do, and claiming that here would assert a
    /// cause nobody observed.
    NotCompleted,
    /// The ceremony finished but the response did not verify, or the enrolled key could not then
    /// produce a verified assertion. Nothing was enrolled — which is the whole point of confirming
    /// before writing.
    NotVerified,
    /// The authenticator reported itself as BUILT IN to this computer, which cannot be the second
    /// factor: the platform biometric already unlocks this account, so enrolling it would collapse
    /// the two factors into one. Nothing was enrolled.
    PlatformAuthenticatorRefused,
    /// A second factor is already enrolled. Re-running setup would silently invalidate the codes the
    /// user is holding, so it is refused and the caller says so.
    AlreadyEnrolled,
    /// The older TOTP enrolment is still on this account (dig-app#348). It must be retired before a
    /// key can be enrolled, and the copy names that path.
    Superseded,
    /// This build has no WebAuthn client, so no ceremony is possible on this platform in this version.
    /// Reported BEFORE any window is drawn, and never as a setting that could be switched on.
    NoProvider,
    /// No window could be drawn, or the account locked mid-flow. Nothing was enrolled.
    Unavailable,
    /// The enrolment was confirmed but could not be stored.
    Failed,
}

/// What happened when the user was challenged for the second factor.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChallengeVerdict {
    /// A verified assertion from the enrolled key.
    Passed,
    /// A correct recovery code, which is now spent.
    PassedWithRecoveryCode {
        /// How many unspent recovery codes are left.
        remaining: usize,
    },
    /// The user closed the window without answering. The action must not proceed.
    Cancelled,
    /// The assertion did not verify, or the typed code was wrong.
    Failed,
    /// Too many attempts have failed in a row, so the user must WAIT before trying again
    /// (dig_ecosystem#1847). A rate limit, not a lockout — kept distinct from [`Failed`](Self::Failed)
    /// so the window can tell the user to wait rather than to try again and be refused unread.
    RateLimited {
        /// Whole seconds the user must wait before another attempt will be checked.
        retry_after_seconds: u64,
    },
    /// No second factor is enrolled, so there was nothing to ask. Deliberately NOT collapsed into
    /// [`Passed`](Self::Passed): a caller must decide what "no factor" means for its own action, and a
    /// silent pass is how a guard becomes vacuous.
    NotEnrolled,
    /// The older TOTP enrolment is on this account (dig-app#348). It clears NOTHING — callers fail
    /// closed — and it is never reported as [`NotEnrolled`](Self::NotEnrolled), because the gate
    /// genuinely still binds. The way forward is to retire it and enrol a key.
    Superseded,
    /// No window could be drawn, or the account is locked. Callers MUST fail closed.
    Unavailable,
}

/// What happened when the user tried to turn the second factor off.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DisableOutcome {
    /// The second factor is off.
    Disabled,
    /// The user, or the OS authenticator, refused. It is still on.
    Refused,
    /// There was nothing enrolled.
    NotEnrolled,
    /// The enrolment could not be removed.
    Failed,
    /// The evidence was wrong. It is still on (dig-app#349).
    ///
    /// Distinct from [`Refused`](Self::Refused) because the two mean opposite things to the person
    /// reading the window: a refusal is their own decision, a wrong code is a retry.
    WrongCode,
    /// Too many attempts have failed in a row, so the user must WAIT (dig-app#349). A rate limit, not a
    /// lockout -- a recovery code still goes through once the delay has elapsed.
    RateLimited {
        /// Whole seconds to wait before another attempt will be judged.
        retry_after_seconds: u64,
    },
    /// The account is LOCKED, so nothing it holds can be verified and the factor stays on
    /// (dig-app#349). See [`disable_locked`].
    NeedsUnlock,
    /// A factor is enrolled and the challenge could not be judged -- an unreadable record, or no window.
    /// Fails closed: it is still on.
    Unavailable,
}

/// Run the enrolment flow: refuse early if this cannot work, explain, register a key, confirm the key
/// can assert, hand over recovery codes, store.
///
/// Nothing account-identifying is passed to the authenticator — the relying party is told the ISSUER
/// and nothing else — so no DIG ID reaches a key or anything it is backed up to.
///
/// Every screen before the final store is escapable and leaves NOTHING enrolled — the property the
/// module docs open with, and the one the `enrolment_can_be_abandoned_at_every_screen` test pins.
pub fn enrol<S: ProfileSealer>(
    confirmer: &dyn NativeConfirmer,
    vault: &SecondFactorVault<S>,
    authenticator: &dyn Authenticator,
) -> EnrolOutcome {
    // Step 1: every refusal this build can predict, BEFORE any window. A person must not be walked
    // into a ceremony that was never going to be allowed to finish.
    if vault.is_enrolled() {
        return match vault.kind() {
            Ok(RecordKind::Current) => EnrolOutcome::AlreadyEnrolled,
            Ok(RecordKind::Superseded) => EnrolOutcome::Superseded,
            // A record is present and could not be read. Refusing is the only safe direction:
            // enrolling over it would destroy codes the user may still be holding.
            Err(e) => {
                tracing::warn!(error = %e, "an existing second-factor record could not be read");
                EnrolOutcome::Unavailable
            }
        };
    }
    if authenticator.support() == ClientSupport::NotOnThisPlatform {
        return EnrolOutcome::NoProvider;
    }

    let (webauthn, origin) = match (verifier::build(), verifier::origin()) {
        (Ok(webauthn), Ok(origin)) => (webauthn, origin),
        _ => return EnrolOutcome::Unavailable,
    };

    // Step 2: explain, in the user's words, both what this does and what it does not do.
    match confirmer.confirm_claim(&ClaimPrompt {
        title: "DIG — Two-factor security key",
        heading: "Add a security key to this account?",
        body: EXPLAINER,
        affirm: "Set it up",
        decline: None,
        // The user just chose this from the menu; refusing costs them a retry and nothing else.
        refusal_is_default: false,
        scannable: None,
        identifier: None,
    }) {
        ConfirmDecision::Approve => {}
        ConfirmDecision::Deny => return EnrolOutcome::Abandoned,
        _ => return EnrolOutcome::Unavailable,
    }

    // Step 3: register. No exclusion list — a second enrolment was already refused at step 1 — and no
    // attestation CA list, so attestation is conveyed as `none` and never verified.
    let (challenge, state) = match webauthn.start_securitykey_registration(
        webauthn_rs::prelude::Uuid::new_v4(),
        verifier::USER_NAME,
        verifier::USER_DISPLAY_NAME,
        None,
        None,
        Some(webauthn_rs::prelude::AuthenticatorAttachment::CrossPlatform),
    ) {
        Ok(started) => started,
        Err(e) => {
            tracing::warn!(error = ?e, "a second-factor registration could not be started");
            return EnrolOutcome::Unavailable;
        }
    };
    let response = match authenticator.register(&origin, &challenge, CEREMONY_DEADLINE) {
        ClientOutcome::Completed(response) => response,
        ClientOutcome::NotCompleted => return EnrolOutcome::NotCompleted,
        // Unreachable through the refusal above, and handled rather than asserted: a client whose
        // support answer disagreed with its behaviour must still enrol nothing.
        ClientOutcome::NoProvider => return EnrolOutcome::NoProvider,
    };
    let credential = match webauthn.finish_securitykey_registration(&response, &state) {
        Ok(credential) => credential,
        Err(e) => {
            tracing::info!(error = ?e, "a second-factor registration did not verify");
            return EnrolOutcome::NotVerified;
        }
    };

    // Step 4: enforce the attachment. See `reports_platform_authenticator` for the two bounds on what
    // this check can and cannot catch.
    if super::authenticator::reports_platform_authenticator(&response) {
        return EnrolOutcome::PlatformAuthenticatorRefused;
    }

    // Step 5: confirm the key can actually ASSERT, before anything is written. A factor that enrols
    // but cannot be satisfied locks the owner out of the verbs it guards.
    match confirm_it_asserts(&webauthn, authenticator, &origin, &credential) {
        Confirmation::Confirmed(credential) => {
            // Step 6: the recovery codes, shown exactly once and claimed rather than merely displayed.
            let codes = RecoveryCodeSet::generate();
            match confirmer.confirm_claim(&ClaimPrompt {
                title: "DIG — Your recovery codes",
                heading: "Save these codes and keep them safe.",
                body: &format!(
                    "{codes}\nEach code works ONCE. Keep them somewhere other than the key.\n\n\
                     This is the only time they will be shown. Lose the key with no codes saved, and \
                     you will not be able to replace or remove this account on this computer.",
                    codes = *codes.printable(),
                ),
                affirm: "I have saved these",
                decline: None,
                // The recovery codes are the way back in. Enter must not claim they are saved.
                refusal_is_default: true,
                scannable: None,
                identifier: None,
            }) {
                ConfirmDecision::Approve => {}
                ConfirmDecision::Deny => return EnrolOutcome::Abandoned,
                _ => return EnrolOutcome::Unavailable,
            }

            // Step 7: the ONLY write, and it happens last — everything above can be walked away from.
            match vault.enrol(&credential, &codes) {
                Ok(()) => EnrolOutcome::Enrolled {
                    recovery_codes: codes.len(),
                },
                Err(VaultError::Seal(_)) => EnrolOutcome::Unavailable,
                Err(e) => {
                    tracing::warn!(error = %e, "the second-factor enrolment could not be stored");
                    EnrolOutcome::Failed
                }
            }
        }
        Confirmation::NotCompleted => EnrolOutcome::NotCompleted,
        Confirmation::NotVerified => EnrolOutcome::NotVerified,
        Confirmation::Unavailable => EnrolOutcome::Unavailable,
    }
}

/// Ask for the second factor and judge it, for an action that demands it.
///
/// `purpose` names what the factor is FOR, in the user's words (e.g. `"replace the DIG Account on this
/// computer"`), so no window ever asks for it without saying why.
pub fn challenge<S: ProfileSealer>(
    confirmer: &dyn NativeConfirmer,
    vault: &SecondFactorVault<S>,
    authenticator: &dyn Authenticator,
    purpose: &str,
    clock: &dyn Clock,
) -> ChallengeVerdict {
    if !vault.is_enrolled() {
        return ChallengeVerdict::NotEnrolled;
    }

    // Reading the credential is also how the SUPERSEDED record is detected, and it must be detected
    // before anything else happens: it clears no gate, and it is never "not enrolled".
    let credential = match vault.credential() {
        Ok(credential) => credential,
        Err(VaultError::Superseded) => return ChallengeVerdict::Superseded,
        Err(e) => {
            tracing::warn!(error = %e, "a second-factor record could not be read");
            return ChallengeVerdict::Unavailable;
        }
    };

    // Tell a rate-limited user to wait BEFORE any window is drawn, not after they have acted only to
    // be refused unread (dig_ecosystem#1970). This peek judges nothing and mutates nothing (see
    // `SecondFactorVault::current_throttle`); the post-judge `RateLimited` arms below stay as the
    // backstop for a throttle that arms *during* the flow.
    match vault.current_throttle(clock.now_unix()) {
        Ok(Some(retry_after_seconds)) => {
            return ChallengeVerdict::RateLimited {
                retry_after_seconds,
            };
        }
        Ok(None) => {}
        // Fail closed exactly as the post-judge path does: a locked or unreadable vault is not a pass.
        Err(e) => {
            tracing::warn!(error = %e, "a second-factor throttle could not be read");
            return ChallengeVerdict::Unavailable;
        }
    }

    let (webauthn, origin) = match (verifier::build(), verifier::origin()) {
        (Ok(webauthn), Ok(origin)) => (webauthn, origin),
        _ => return ChallengeVerdict::Unavailable,
    };
    let (request, state) =
        match webauthn.start_securitykey_authentication(std::slice::from_ref(&credential)) {
            Ok(started) => started,
            Err(e) => {
                tracing::warn!(error = ?e, "a second-factor challenge could not be minted");
                return ChallengeVerdict::Unavailable;
            }
        };

    match authenticator.assert(&origin, &request, CEREMONY_DEADLINE) {
        ClientOutcome::Completed(response) => {
            match vault.judge_assertion(&webauthn, &response, &state, clock.now_unix()) {
                Ok(outcome) => verdict_of(outcome),
                Err(e) => {
                    tracing::warn!(error = %e, "a second-factor assertion could not be judged");
                    ChallengeVerdict::Unavailable
                }
            }
        }
        // A ceremony that did not finish is NOT evidence that the key is gone — the backend cannot
        // tell a cancel from a timeout from an absent key. So the recovery-code path is OFFERED rather
        // than forced, and a user who still has their key can close it and try again.
        //
        // `NoProvider` lands here too, and deliberately: on a host with no client the key step fails
        // closed and the recovery-code path is the only thing left that can work.
        ClientOutcome::NotCompleted | ClientOutcome::NoProvider => ask_for_a_recovery_code(
            confirmer,
            vault,
            clock,
            &format!("Enter a recovery code to {purpose}."),
            RECOVERY_BODY,
        ),
    }
}

/// Turn the second factor off on an UNLOCKED account: the platform authorization AND the factor's own
/// material (dig-app#349).
///
/// # Why BOTH, and why that is not a lockout
///
/// The platform authenticator alone is not enough, because it is not a bar to the attacker this
/// feature is for. The enrolment window says so in its own words: the factor exists to stop *"someone
/// who has learned or guessed how to unlock this computer"*, and that person satisfies Windows Hello.
/// A disable gated on Hello alone hands them the whole feature back in one click.
///
/// It is not a lost-key lockout, because a **recovery code** passes this challenge exactly as an
/// assertion does. The recovery codes were always meant to be this escape hatch.
///
/// # The superseded record retires HERE, through this same door
///
/// A `DIG2FA1` record cannot answer an assertion, so its challenge is its OWN material: an unspent
/// recovery code, or a code from the authenticator app it was set up with. The platform window still
/// comes first and is still not sufficient on its own — Windows Hello alone must never retire a
/// factor, because that is de-gating, and de-gating is silent.
///
/// # The order, which is load-bearing
///
/// The security window comes FIRST, the challenge second. Challenging before the user has said what
/// they want burns rate-limit attempts on a flow they may be about to abandon -- and the rate limit is
/// persisted, so those attempts follow them to the next real one.
pub fn disable_unlocked<S: ProfileSealer>(
    confirmer: &dyn NativeConfirmer,
    vault: &SecondFactorVault<S>,
    authenticator: &dyn Authenticator,
    clock: &dyn Clock,
) -> DisableOutcome {
    if !vault.is_enrolled() {
        return DisableOutcome::NotEnrolled;
    }
    let kind = match vault.kind() {
        Ok(kind) => kind,
        Err(e) => {
            tracing::warn!(error = %e, "a second-factor record could not be read to disable it");
            return DisableOutcome::Unavailable;
        }
    };

    if confirmer.confirm_security_change(&disable_prompt(kind)) != ConfirmDecision::Approve {
        return DisableOutcome::Refused;
    }

    let verdict = match kind {
        RecordKind::Current => challenge(confirmer, vault, authenticator, DISABLE_PURPOSE, clock),
        // The retirement path. No key can answer for this record, so its own material is the whole
        // challenge — and it is still a challenge: the security window alone must not retire it.
        RecordKind::Superseded => ask_for_a_recovery_code(
            confirmer,
            vault,
            clock,
            &format!("Enter a code to {DISABLE_PURPOSE}."),
            RETIREMENT_BODY,
        ),
    };

    match verdict {
        ChallengeVerdict::Passed => remove_enrolment(vault),
        ChallengeVerdict::PassedWithRecoveryCode { remaining } => {
            let outcome = remove_enrolment(vault);
            // Reported ONLY when the factor survived. A spent code the user still has to live with is
            // news; a count of codes that were destroyed a line later is a contradiction, because the
            // "turned off" window it would sit beside says every recovery code has stopped working.
            if outcome != DisableOutcome::Disabled {
                report_recovery_code_spent(confirmer, remaining);
            }
            outcome
        }
        ChallengeVerdict::Cancelled => DisableOutcome::Refused,
        ChallengeVerdict::Failed => DisableOutcome::WrongCode,
        ChallengeVerdict::RateLimited {
            retry_after_seconds,
        } => DisableOutcome::RateLimited {
            retry_after_seconds,
        },
        // All fail closed. `NotEnrolled` here can only mean the enrolment went away mid-flow, and
        // `Superseded` can only mean the record changed shape under us — neither is a pass.
        ChallengeVerdict::NotEnrolled => DisableOutcome::NotEnrolled,
        ChallengeVerdict::Superseded | ChallengeVerdict::Unavailable => DisableOutcome::Unavailable,
    }
}

/// Refuse to turn the second factor off on a LOCKED account, and that is the security boundary rather
/// than an oversight (dig-app#349).
///
/// A locked account has no DEK, so NOTHING it holds can be verified -- not a recovery code, and not an
/// assertion, whose public key sits in the same sealed envelope. The only authorization available is
/// the platform biometric, and accepting it here would let anyone able to satisfy Windows Hello press
/// `Lock now`, delete the enrolment, and then replace or remove the account with no factor at all --
/// walking around the very gate [`enrolment_present`](super::vault::enrolment_present) is unlock-free
/// to protect.
///
/// The rule this encodes: **the biometric alone may DESTROY, never DE-GATE.** De-gating is the worse of
/// the two because it is SILENT -- it leaves an intact, healthy-looking account whose owner still
/// believes it is protected, and an attacker who can return at leisure. Destruction is loud, immediate
/// and grants them nothing they can come back and use.
///
/// A person who genuinely cannot open this account is not trapped: they remove it outright through the
/// break-glass discard
/// ([`authorize_locked_break_glass`](crate::account::journey::authorize_locked_break_glass)), which
/// takes the seed and the enrolment together.
///
/// # Why this takes no confirmer
///
/// It draws no window, and cannot: asking for a confirmation that will not be honoured teaches the user
/// that the security prompt is decorative. Having no confirmer to draw with makes that structural
/// rather than a rule someone has to keep.
pub fn disable_locked(enrolment: &dyn Enrolment) -> DisableOutcome {
    match enrolment.is_enrolled() {
        true => DisableOutcome::NeedsUnlock,
        false => DisableOutcome::NotEnrolled,
    }
}

/// What the window says the factor is FOR when it is being turned off. One constant, so the window and
/// the docs cannot drift.
const DISABLE_PURPOSE: &str = "turn off the second factor";

/// The security window for turning the factor off.
///
/// The consequence sentence differs by record shape because the two states lose different things: a
/// current enrolment loses a working key, and a superseded one was already not clearing any gate — so
/// telling its owner that "your key stops working" would be false, and telling them nothing changes
/// would hide that their recovery codes die with it.
fn disable_prompt(kind: RecordKind) -> SecurityPrompt<'static> {
    SecurityPrompt {
        change: DISABLE_PURPOSE,
        consequence: match kind {
            RecordKind::Current => {
                "Replacing or removing this account will no longer ask for your security key — \
                 knowing how to unlock this computer will be enough. Your recovery codes stop \
                 working, and setting it up again will enrol a new key and issue new codes."
            }
            RecordKind::Superseded => {
                "This account still has the older authenticator-app setup, which no longer unlocks \
                 anything. Removing it lets you replace or remove this account without a second \
                 factor, and your old recovery codes stop working. You can set up a security key \
                 afterwards from the Security menu."
            }
        },
        affirm: "Turn it off",
    }
}

/// The storage half, reached ONLY after an authorization has passed. Never public: an entry point that
/// could remove an enrolment without deciding how it was authorized is the defect dig-app#349 fixed.
fn remove_enrolment(enrolment: &dyn Enrolment) -> DisableOutcome {
    match enrolment.remove() {
        Ok(()) => DisableOutcome::Disabled,
        Err(e) => {
            tracing::warn!(error = %e, "the second factor could not be turned off");
            DisableOutcome::Failed
        }
    }
}

/// Draw the typed-material window and judge what comes back.
///
/// Shared by the recovery-code fallback and by the superseded record's retirement, because the two are
/// the same act — a person typing something the vault can check without a key — and only the copy
/// differs. Keeping one implementation is what stops the throttle handling and the fail-closed
/// mapping from drifting between them.
fn ask_for_a_recovery_code<S: ProfileSealer>(
    confirmer: &dyn NativeConfirmer,
    vault: &SecondFactorVault<S>,
    clock: &dyn Clock,
    heading: &str,
    body: &str,
) -> ChallengeVerdict {
    let typed = match confirmer.request_input(&InputPrompt {
        title: "DIG — Second factor",
        heading,
        body,
        field_label: "Code:",
        submit: "Continue",
        // A one-time code is ephemeral and mistyping it costs an attempt, so it is shown as it is
        // typed. §3.1d's masking rule is about material that keeps its value after it is read; this
        // does not.
        masked: false,
        revealable: false,
        // A titled dialog, not the launcher bar: this window is standing between the user and an
        // irreversible action and has to have room to say which one.
        style: InputStyle::Dialog,
    }) {
        InputOutcome::Provided(text) => text,
        // Nothing was judged, so the attempt bound is untouched.
        InputOutcome::Cancelled => return ChallengeVerdict::Cancelled,
        InputOutcome::Unavailable => return ChallengeVerdict::Unavailable,
    };

    match vault.judge_typed(&typed, clock.now_unix()) {
        Ok(outcome) => verdict_of(outcome),
        Err(e) => {
            tracing::warn!(error = %e, "a second-factor challenge could not be judged");
            ChallengeVerdict::Unavailable
        }
    }
}

/// Map a vault outcome onto the journey's verdict.
///
/// One function, so the two challenge paths cannot disagree about what an outcome means — and in
/// particular so neither can quietly turn an `AlreadyUsed` or a `Rejected` into anything but a
/// failure.
fn verdict_of(outcome: ChallengeOutcome) -> ChallengeVerdict {
    match outcome {
        ChallengeOutcome::Accepted => ChallengeVerdict::Passed,
        ChallengeOutcome::AcceptedRecoveryCode { remaining } => {
            ChallengeVerdict::PassedWithRecoveryCode { remaining }
        }
        ChallengeOutcome::AlreadyUsed | ChallengeOutcome::Rejected => ChallengeVerdict::Failed,
        ChallengeOutcome::RateLimited {
            retry_after_seconds,
        } => ChallengeVerdict::RateLimited {
            retry_after_seconds,
        },
    }
}

/// Tell the user how many recovery codes they have left, once one has been spent.
///
/// Drawn as a notice rather than folded into the previous window because it arrives AFTER the action
/// the code authorized: a person who has just used their last code needs to be told plainly, at the
/// moment it becomes true.
pub fn report_recovery_code_spent(confirmer: &dyn NativeConfirmer, remaining: usize) {
    let body = match remaining {
        0 => "That was your LAST recovery code. If you also lose your security key, you will not be \
              able to replace or remove this account on this computer. Turn the second factor off and \
              set it up again from the Security menu to get a new set."
            .to_string(),
        _ => format!(
            "You have {remaining} recovery code(s) left. When you run low, turn the second factor \
             off and set it up again from the Security menu to get a fresh set."
        ),
    };
    confirmer.show_notice(&NoticePrompt {
        title: "DIG — Recovery code used",
        heading: "You used a recovery code, and it is now spent.",
        body: &body,
        acknowledge: "OK",
        identifier: None,
    });
}

/// The honest explanation, shown before anything is registered.
///
/// It states what this does NOT protect against, because the alternative is a person believing their
/// unlocked machine is now safe from someone sitting at it. The justification it gives is the true one:
/// Windows Hello is already a factor, and it is bound to this machine and this logon session, whereas a
/// key you carry is not.
///
/// The third paragraph is the sentence that changed with the primitive, and it is not a softening. With
/// a shared secret the honest claim was "your code is checked here, so the key for it is stored here
/// too". With an asymmetric credential nothing stored here can answer for the key — so what a fully
/// compromised machine can do is REPLACE this setup, not use it. That distinction is what the copy has
/// to carry, and it must not be rounded up into a promise.
const EXPLAINER: &str = "\
Your DIG Account already asks Windows to check it is you. That check lives on THIS computer, in THIS \
sign-in session — a security key you carry lives somewhere else.\n\n\
It stops someone who has learned or guessed how to unlock this computer, or who sits down at it while \
it is unlocked, from replacing or removing your DIG Account. Nothing kept on this computer can answer \
for your key: the part that signs stays on the key and never leaves it.\n\n\
What it does NOT stop is someone who has fully taken over this computer. They could not use your key, \
but they could replace this setup with one of their own. This raises the bar; it is not a wall.\n\n\
You will need a security key on USB, or a phone that can act as one. Windows will ask for it next.";

/// The body of the recovery-code window, offered when a ceremony does not finish.
///
/// It must NOT say the key is missing. The platform cannot tell a cancelled dialog from a timeout from
/// an absent key, so a sentence that named one of those would be asserting a cause nobody observed.
const RECOVERY_BODY: &str = "\
Your security key did not answer, so nothing has happened yet. If you have it with you, close this \
window and try again.\n\n\
If you do not have it, type one of the recovery codes you saved when you set this up. Each of those \
works once.";

/// The body of the retirement window for a superseded TOTP enrolment.
const RETIREMENT_BODY: &str = "\
This account still has the older authenticator-app setup. It no longer unlocks anything, and it has to \
be removed before you can enrol a security key.\n\n\
Type the current 6-digit code from that authenticator app, or one of the recovery codes you saved when \
you set it up. Each recovery code works once.";

/// The result of the confirming assertion, kept separate from [`EnrolOutcome`] so the enrol flow reads
/// as a sequence of steps rather than a nest of matches.
// One of these exists at a time, for the length of one enrolment, and it is matched where it is
// produced. It is never collected, never stored and never crosses a queue, so the size the lint
// measures is a stack frame in a flow that is already waiting on a human touching a key. Boxing it
// would buy nothing and would move a credential onto the heap, which is the wrong direction for
// material this module works hard to keep in one place.
#[allow(clippy::large_enum_variant)]
enum Confirmation {
    /// The key asserted and the verifier accepted it. Carries the credential with its counter updated,
    /// so what is stored reflects the assertion that was just seen rather than the registration.
    Confirmed(webauthn_rs::prelude::SecurityKey),
    NotCompleted,
    NotVerified,
    Unavailable,
}

/// Run one full authentication ceremony against a credential that has just been registered, and refuse
/// to enrol anything that cannot answer it.
///
/// This is the WebAuthn analogue of "require a correct code to be verified before anything is stored",
/// and it exists for the same reason: a factor that enrols but cannot be satisfied locks the owner out
/// of the verbs it guards. It costs the user a second touch of the key, which is a fair price for not
/// being locked out by a setup flow.
fn confirm_it_asserts(
    webauthn: &webauthn_rs::prelude::Webauthn,
    authenticator: &dyn Authenticator,
    origin: &webauthn_rs::prelude::Url,
    credential: &webauthn_rs::prelude::SecurityKey,
) -> Confirmation {
    let (request, state) =
        match webauthn.start_securitykey_authentication(std::slice::from_ref(credential)) {
            Ok(started) => started,
            Err(e) => {
                tracing::warn!(error = ?e, "the confirming challenge could not be minted");
                return Confirmation::Unavailable;
            }
        };
    let response = match authenticator.assert(origin, &request, CEREMONY_DEADLINE) {
        ClientOutcome::Completed(response) => response,
        ClientOutcome::NotCompleted => return Confirmation::NotCompleted,
        ClientOutcome::NoProvider => return Confirmation::NotCompleted,
    };
    match webauthn.finish_securitykey_authentication(&response, &state) {
        Ok(result) => {
            let mut credential = credential.clone();
            credential.update_credential(&result);
            Confirmation::Confirmed(credential)
        }
        Err(e) => {
            tracing::info!(error = ?e, "a newly registered key could not produce a verified assertion");
            Confirmation::NotVerified
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::account::second_factor::authenticator::double::{
        enrol_through, RegistersButCannotAssert, ScriptedAuthenticator, SoftAuthenticator,
    };
    use crate::account::second_factor::totp::TotpSecret;
    use crate::account::second_factor::totp::{SECRET_BYTES, STEP_SECONDS};
    use crate::account::second_factor::vault::EnrolmentState;
    use crate::confirm::{ConnectPrompt, DestroyPrompt, PairPrompt, RevealPrompt, SignPrompt};
    use crate::test_support::FakeSealer;
    use std::path::Path;
    use std::sync::Mutex;
    use zeroize::Zeroizing;

    /// A pinned instant, never the wall clock: the fixture must be able to place a throttle deadline
    /// at a chosen moment, and a wall-clock fixture cannot.
    const NOW: u64 = 1_700_000_000;
    const DID: &str = "did:chia:profile-a";
    /// A guess shaped like a recovery code — in the alphabet, dashed — that matches no digest.
    const WRONG: &str = "ZZZZZ-ZZZZZ";

    struct FixedClock(u64);
    impl Clock for FixedClock {
        fn now_unix(&self) -> u64 {
            self.0
        }
    }

    fn vault(dir: &Path) -> SecondFactorVault<FakeSealer> {
        SecondFactorVault::new(FakeSealer::default(), dir, DID)
    }

    /// What one screen of a scripted run does.
    #[derive(Clone)]
    enum Act {
        /// Answer the next claim/security window this way.
        Decide(ConfirmDecision),
        /// Submit this text at the next input window. [`SAVED_CODE`] is replaced by a recovery code
        /// scraped off the window that showed it — the only way a scripted double can answer with a
        /// code the flow generated after the script was written.
        Type(String),
        /// Cancel the next input window.
        CancelInput,
        /// Report that no window could be drawn.
        NoWindow,
    }

    /// The marker a script uses to mean "one of the recovery codes this run issued".
    const SAVED_CODE: &str = "<saved>";

    /// A confirmer that plays a script and records what it was shown.
    ///
    /// It deliberately answers claim windows and input windows from ONE queue, in order, because the
    /// ORDER of the screens is part of what these tests assert — a double with a separate answer per
    /// prompt TYPE could not distinguish "asked for a code before showing the recovery codes" from
    /// the reverse.
    struct ScriptedConfirmer {
        script: Mutex<std::collections::VecDeque<Act>>,
        /// The recovery codes this run issued, scraped off the window that showed them — exactly what
        /// a person copies onto paper. Without this, the enrolled-then-challenged path could only ever
        /// be tested with a WRONG code.
        codes: Mutex<Vec<String>>,
        shown: Mutex<Vec<String>>,
        /// Every HEADING drawn, kept apart from the bodies because the heading has its own (much
        /// tighter) width budget and is clipped silently when it overruns.
        headings: Mutex<Vec<String>>,
    }

    impl ScriptedConfirmer {
        fn new(acts: &[Act]) -> Self {
            Self {
                script: Mutex::new(acts.iter().cloned().collect()),
                codes: Mutex::new(Vec::new()),
                shown: Mutex::new(Vec::new()),
                headings: Mutex::new(Vec::new()),
            }
        }

        fn next(&self) -> Act {
            self.script
                .lock()
                .unwrap()
                .pop_front()
                .expect("the flow asked for more screens than the script has")
        }

        fn record(&self, text: &str) {
            self.shown.lock().unwrap().push(text.to_string());
        }

        fn record_heading(&self, text: &str) {
            self.headings.lock().unwrap().push(text.to_string());
        }

        /// Everything the user was shown, joined — for asserting what a window did and did not say.
        fn transcript(&self) -> String {
            self.shown.lock().unwrap().join("\n---\n")
        }

        /// Learn the recovery codes from the window that presents them, by reading the printed block
        /// off the screen exactly as a person would.
        ///
        /// Scraping rather than being handed them is what makes the scripted run answer with a REAL
        /// code: the enrolment generates them internally and never returns them.
        fn learn_codes(&self, body: &str) {
            let scraped: Vec<String> = body
                .split_whitespace()
                .filter(|token| {
                    let mut halves = token.split('-');
                    matches!((halves.next(), halves.next(), halves.next()), (Some(a), Some(b), None)
                        if a.len() == 5
                            && b.len() == 5
                            && token
                                .chars()
                                .all(|c| c == '-' || c.is_ascii_uppercase() || c.is_ascii_digit()))
                })
                .map(str::to_string)
                .collect();
            if !scraped.is_empty() {
                *self.codes.lock().unwrap() = scraped;
            }
        }

        fn saved_code(&self, index: usize) -> String {
            self.codes
                .lock()
                .unwrap()
                .get(index)
                .expect("the recovery-code window must have come first")
                .clone()
        }
    }

    impl NativeConfirmer for ScriptedConfirmer {
        fn confirm_pair(&self, _: &PairPrompt<'_>) -> ConfirmDecision {
            unreachable!("this journey never pairs")
        }
        fn confirm_connect(&self, _: &ConnectPrompt<'_>) -> ConfirmDecision {
            unreachable!("this journey never connects")
        }
        fn confirm_sign(&self, _: &SignPrompt<'_>) -> ConfirmDecision {
            unreachable!("this journey never signs")
        }
        fn confirm_reveal(&self, _: &RevealPrompt<'_>) -> ConfirmDecision {
            unreachable!("this journey never reveals a phrase")
        }
        fn confirm_destroy(&self, _: &DestroyPrompt<'_>) -> ConfirmDecision {
            unreachable!("this journey never destroys")
        }

        fn show_notice(&self, prompt: &NoticePrompt<'_>) -> ConfirmDecision {
            self.record(prompt.body);
            self.record_heading(prompt.heading);
            ConfirmDecision::Approve
        }

        fn confirm_claim(&self, prompt: &ClaimPrompt<'_>) -> ConfirmDecision {
            self.record(prompt.body);
            self.record_heading(prompt.heading);
            self.learn_codes(prompt.body);
            match self.next() {
                Act::Decide(decision) => decision,
                Act::NoWindow => ConfirmDecision::Unavailable,
                _ => panic!("the script offered typed text to a window with no field"),
            }
        }

        fn confirm_security_change(&self, prompt: &SecurityPrompt<'_>) -> ConfirmDecision {
            self.record(prompt.consequence);
            match self.next() {
                Act::Decide(decision) => decision,
                Act::NoWindow => ConfirmDecision::Unavailable,
                _ => panic!("the script offered typed text to a window with no field"),
            }
        }

        fn request_input(&self, prompt: &InputPrompt<'_>) -> InputOutcome {
            self.record(prompt.body);
            self.record_heading(prompt.heading);
            match self.next() {
                Act::Type(text) if text == SAVED_CODE => {
                    InputOutcome::Provided(Zeroizing::new(self.saved_code(0)))
                }
                Act::Type(text) => InputOutcome::Provided(Zeroizing::new(text)),
                Act::CancelInput => InputOutcome::Cancelled,
                Act::NoWindow => InputOutcome::Unavailable,
                Act::Decide(_) => panic!("the script offered a decision to a window with a field"),
            }
        }
    }

    /// The two screens an enrolment draws, both approved.
    fn happy_path() -> Vec<Act> {
        vec![
            Act::Decide(ConfirmDecision::Approve), // the explainer
            Act::Decide(ConfirmDecision::Approve), // "I have saved these"
        ]
    }

    /// Run an enrolment against a fresh soft key, and hand back everything the run produced.
    fn run_enrolment(
        dir: &Path,
        acts: &[Act],
    ) -> (EnrolOutcome, ScriptedConfirmer, SoftAuthenticator) {
        let confirmer = ScriptedConfirmer::new(acts);
        let key = SoftAuthenticator::roaming();
        let outcome = enrol(&confirmer, &vault(dir), &key);
        (outcome, confirmer, key)
    }

    /// Plant a SUPERSEDED `DIG2FA1` record, and hand back the secret its owner still has.
    ///
    /// Written through the vault's own writer rather than by hand, so the fixture cannot drift from
    /// the shape the reader accepts.
    fn plant_superseded(dir: &Path) -> TotpSecret {
        let secret = TotpSecret::from_bytes(&[0x2a; SECRET_BYTES]).expect("a fixed secret");
        crate::account::second_factor::vault::test_support::plant_superseded(
            &vault(dir),
            &secret,
            &RecoveryCodeSet::generate(),
        );
        secret
    }

    // ──────────────── Enrolment ────────────────

    /// The whole point, end to end: a real soft key registers, confirms it can assert, the codes are
    /// claimed, the record is written — and the SAME key then clears a challenge.
    ///
    /// The final challenge is what makes this more than a round-trip test: an enrolment that stored a
    /// credential nothing could satisfy would pass every assertion above it.
    #[test]
    fn a_complete_enrolment_stores_a_working_second_factor() {
        let dir = tempfile::tempdir().unwrap();
        let (outcome, _, key) = run_enrolment(dir.path(), &happy_path());

        assert_eq!(
            outcome,
            EnrolOutcome::Enrolled {
                recovery_codes: crate::account::second_factor::recovery_codes::CODE_COUNT
            }
        );
        assert_eq!(
            vault(dir.path()).classified_state(),
            EnrolmentState::Enrolled
        );
        assert_eq!(
            challenge(
                &ScriptedConfirmer::new(&[]),
                &vault(dir.path()),
                &key,
                "remove this account",
                &FixedClock(NOW)
            ),
            ChallengeVerdict::Passed
        );
    }

    /// **Nothing is enrolled by a flow the user escaped from, at ANY screen.**
    ///
    /// Driven from the length of the happy path rather than a hand-written list of screens, so a
    /// screen added later is covered without anyone remembering to extend this.
    #[test]
    fn enrolment_can_be_abandoned_at_every_screen() {
        for escape_at in 0..happy_path().len() {
            for escape in [ConfirmDecision::Deny, ConfirmDecision::Unavailable] {
                let dir = tempfile::tempdir().unwrap();
                let mut acts = happy_path();
                acts[escape_at] = Act::Decide(escape);
                acts.truncate(escape_at + 1);

                let (outcome, _, _) = run_enrolment(dir.path(), &acts);
                assert_ne!(
                    outcome,
                    EnrolOutcome::Enrolled {
                        recovery_codes: crate::account::second_factor::recovery_codes::CODE_COUNT
                    },
                    "escaping at screen {escape_at} with {escape:?} must not enrol"
                );
                assert!(
                    !vault(dir.path()).is_enrolled(),
                    "escaping at screen {escape_at} with {escape:?} left a record on disk"
                );
            }
        }
    }

    /// A registration ceremony that never completes enrols nothing, and reports a cause it can
    /// actually justify — `NotCompleted`, never `Abandoned`, because nobody watched the user cancel.
    #[test]
    fn a_registration_that_never_completes_enrols_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let confirmer = ScriptedConfirmer::new(&[Act::Decide(ConfirmDecision::Approve)]);
        let client = ScriptedAuthenticator::never_completes();

        assert_eq!(
            enrol(&confirmer, &vault(dir.path()), &client),
            EnrolOutcome::NotCompleted
        );
        assert!(!vault(dir.path()).is_enrolled());
        assert_eq!(client.call_count(), 1, "and it stopped after the register");
    }

    /// **The confirming assertion is not decoration.** A key that registers and then cannot assert
    /// enrols NOTHING — the failure this step exists to catch, because such a credential would gate
    /// the destructive verbs behind something that can never answer.
    ///
    /// The double registers successfully by borrowing a real soft-token response and then refuses to
    /// assert, which is the only way to separate the two ceremonies.
    #[test]
    fn a_key_that_registers_but_cannot_assert_enrols_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let confirmer = ScriptedConfirmer::new(&[Act::Decide(ConfirmDecision::Approve)]);
        let client = RegistersButCannotAssert::new();

        assert_eq!(
            enrol(&confirmer, &vault(dir.path()), &client),
            EnrolOutcome::NotCompleted
        );
        assert!(
            !vault(dir.path()).is_enrolled(),
            "a key that cannot assert must leave nothing on disk"
        );
        assert_eq!(
            client.call_count(),
            2,
            "it registered, then tried to assert"
        );
    }

    /// A built-in authenticator is refused and enrols nothing: Windows Hello already unlocks this
    /// account, so enrolling it as the second factor collapses the two into one.
    ///
    /// The control is the neighbouring test — a soft token presenting a ROAMING transport enrols fine
    /// — so this cannot pass merely because the soft token is refused for some other reason.
    #[test]
    fn a_platform_authenticator_is_refused_and_enrols_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let confirmer = ScriptedConfirmer::new(&[Act::Decide(ConfirmDecision::Approve)]);
        let key = SoftAuthenticator::platform();

        assert_eq!(
            enrol(&confirmer, &vault(dir.path()), &key),
            EnrolOutcome::PlatformAuthenticatorRefused
        );
        assert!(!vault(dir.path()).is_enrolled());
    }

    /// A phone over the hybrid transport reports NO transports at all, and must enrol normally.
    ///
    /// This is the case a "refuse anything not explicitly roaming" implementation gets backwards, and
    /// getting it backwards refuses one of the two authenticators this feature is for.
    #[test]
    fn an_authenticator_that_reports_no_transport_still_enrols() {
        let dir = tempfile::tempdir().unwrap();
        let confirmer = ScriptedConfirmer::new(&happy_path());
        let key = SoftAuthenticator::silent_about_transport();

        assert!(matches!(
            enrol(&confirmer, &vault(dir.path()), &key),
            EnrolOutcome::Enrolled { .. }
        ));
    }

    /// **A build with no client refuses BEFORE any window.** The user is told about a platform limit
    /// rather than walked into a ceremony that could never have happened.
    ///
    /// The screen count is the assertion that matters: a refusal AFTER the explainer would satisfy an
    /// outcome-only check while still showing a person a setup flow their computer cannot run.
    #[test]
    fn a_build_with_no_client_refuses_before_any_window() {
        let dir = tempfile::tempdir().unwrap();
        let confirmer = ScriptedConfirmer::new(&[]);
        let client = ScriptedAuthenticator::absent();

        assert_eq!(
            enrol(&confirmer, &vault(dir.path()), &client),
            EnrolOutcome::NoProvider
        );
        assert!(
            confirmer.transcript().is_empty(),
            "no window may be drawn on a platform that has no client"
        );
        assert_eq!(client.call_count(), 0);
        assert!(!vault(dir.path()).is_enrolled());
    }

    /// Setup will not quietly replace an enrolment the user is already holding codes for.
    #[test]
    fn setup_will_not_silently_replace_an_existing_enrolment() {
        let dir = tempfile::tempdir().unwrap();
        run_enrolment(dir.path(), &happy_path());

        let confirmer = ScriptedConfirmer::new(&[]);
        assert_eq!(
            enrol(
                &confirmer,
                &vault(dir.path()),
                &SoftAuthenticator::roaming()
            ),
            EnrolOutcome::AlreadyEnrolled
        );
        assert!(confirmer.transcript().is_empty(), "and it drew no window");
    }

    /// A superseded record is reported as such — not as "already enrolled", which would send the user
    /// looking for a key they never had.
    #[test]
    fn setup_over_a_superseded_record_names_the_state_it_found() {
        let dir = tempfile::tempdir().unwrap();
        plant_superseded(dir.path());

        let confirmer = ScriptedConfirmer::new(&[]);
        assert_eq!(
            enrol(
                &confirmer,
                &vault(dir.path()),
                &SoftAuthenticator::roaming()
            ),
            EnrolOutcome::Superseded
        );
        assert!(confirmer.transcript().is_empty(), "and it drew no window");
    }

    // ──────────────── The copy ────────────────

    /// The explainer must state the limit, not oversell the protection.
    ///
    /// Three things are asserted, and the third is the one the primitive change makes newly wrong to
    /// get wrong: it must NOT claim that a fully compromised computer cannot touch the factor. Such a
    /// machine cannot USE the key — and it can REPLACE the enrolment, because the record is sealed
    /// under a DEK it holds.
    #[test]
    fn the_explainer_states_the_limit_rather_than_overselling() {
        let dir = tempfile::tempdir().unwrap();
        let (_, confirmer, _) = run_enrolment(dir.path(), &happy_path());
        let shown = confirmer.transcript();

        assert!(
            shown.contains("does NOT stop"),
            "the window must say what this does not protect against"
        );
        assert!(
            shown.contains("replace this setup"),
            "and must name REPLACEMENT as what a taken-over computer can still do"
        );
        assert!(
            !shown.to_lowercase().contains("cannot be tampered")
                && !shown.to_lowercase().contains("completely safe"),
            "no sentence may promise more than possession of a key delivers"
        );
    }

    /// The recovery codes are shown exactly once, with the warning that says what losing them costs.
    #[test]
    fn the_recovery_codes_are_shown_once_with_their_warning() {
        let dir = tempfile::tempdir().unwrap();
        let (_, confirmer, _) = run_enrolment(dir.path(), &happy_path());
        let shown = confirmer.transcript();

        assert!(shown.contains("only time they will be shown"));
        assert!(shown.contains("Each code works ONCE"));
        assert_eq!(
            confirmer.codes.lock().unwrap().len(),
            crate::account::second_factor::recovery_codes::CODE_COUNT,
            "every issued code must reach the screen"
        );
    }

    /// Every heading fits the one unwrapped line the native window draws it on.
    ///
    /// A `STATIC` control clips silently, so an over-long heading loses its tail with no error
    /// anywhere — which shipped once, cutting a sentence at its most important word.
    #[test]
    fn every_heading_fits_the_window_that_draws_it() {
        let dir = tempfile::tempdir().unwrap();
        let (_, confirmer, key) = run_enrolment(dir.path(), &happy_path());
        let _ = challenge(
            &ScriptedConfirmer::new(&[]),
            &vault(dir.path()),
            &key,
            "remove this account",
            &FixedClock(NOW),
        );

        for heading in confirmer.headings.lock().unwrap().iter() {
            assert!(
                heading.chars().count() <= MAX_HEADING_CHARS,
                "heading is {} characters and will be clipped: {heading:?}",
                heading.chars().count()
            );
        }
    }

    /// No screen's copy carries a formatting hole or a placeholder that never got filled in.
    #[test]
    fn no_screens_copy_carries_a_hole_mid_sentence() {
        let dir = tempfile::tempdir().unwrap();
        let (_, confirmer, _) = run_enrolment(dir.path(), &happy_path());
        let shown = confirmer.transcript();

        for hole in ["{", "}", "TODO", "TBD", "<", "  ."] {
            assert!(
                !shown.contains(hole),
                "a window's copy carries {hole:?}: {shown}"
            );
        }
    }

    // ──────────────── The challenge ────────────────

    /// Enrol, then hand back the vault and the key that can answer for it.
    fn enrolled(dir: &Path) -> (SecondFactorVault<FakeSealer>, SoftAuthenticator, String) {
        let (outcome, confirmer, key) = run_enrolment(dir, &happy_path());
        assert!(
            matches!(outcome, EnrolOutcome::Enrolled { .. }),
            "{outcome:?}"
        );
        (vault(dir), key, confirmer.saved_code(0))
    }

    /// An assertion from the enrolled key passes; one from a STRANGER's key fails.
    ///
    /// Both halves together: a check that only asserted the pass would be satisfied by an
    /// implementation that accepted any assertion at all.
    #[test]
    fn a_challenge_passes_on_the_enrolled_key_and_fails_on_a_strangers() {
        let dir = tempfile::tempdir().unwrap();
        let (vault, key, _) = enrolled(dir.path());

        assert_eq!(
            challenge(
                &ScriptedConfirmer::new(&[]),
                &vault,
                &key,
                "remove",
                &FixedClock(NOW)
            ),
            ChallengeVerdict::Passed
        );

        let stranger = SoftAuthenticator::roaming();
        let _ = enrol_through(&stranger);
        assert_eq!(
            challenge(
                &ScriptedConfirmer::new(&[]),
                &vault,
                &stranger,
                "remove",
                &FixedClock(NOW)
            ),
            ChallengeVerdict::Failed,
            "another person's key must not answer for this account"
        );
    }

    /// When the key does not answer, the recovery-code window is offered and a real code passes.
    #[test]
    fn a_recovery_code_passes_a_challenge_without_the_key() {
        let dir = tempfile::tempdir().unwrap();
        let (vault, _, code) = enrolled(dir.path());
        let confirmer = ScriptedConfirmer::new(&[Act::Type(code)]);

        assert!(matches!(
            challenge(
                &confirmer,
                &vault,
                &ScriptedAuthenticator::never_completes(),
                "remove",
                &FixedClock(NOW)
            ),
            ChallengeVerdict::PassedWithRecoveryCode { .. }
        ));
        assert!(
            confirmer.transcript().contains("did not answer"),
            "the window must not claim the key is missing, only that it did not answer"
        );
    }

    /// Cancelling the recovery-code window does not pass, and judges nothing.
    #[test]
    fn cancelling_the_recovery_window_does_not_pass() {
        let dir = tempfile::tempdir().unwrap();
        let (vault, _, _) = enrolled(dir.path());

        assert_eq!(
            challenge(
                &ScriptedConfirmer::new(&[Act::CancelInput]),
                &vault,
                &ScriptedAuthenticator::never_completes(),
                "remove",
                &FixedClock(NOW)
            ),
            ChallengeVerdict::Cancelled
        );
    }

    /// A throttled account is told to WAIT before any window is drawn, rather than after acting.
    ///
    /// The transcript assertion is the load-bearing half: an implementation that judged first and
    /// reported the throttle afterwards returns the same verdict and still wastes the user's action.
    #[test]
    fn a_throttled_account_is_told_to_wait_before_any_window_is_drawn() {
        let dir = tempfile::tempdir().unwrap();
        let (vault, _, _) = enrolled(dir.path());
        for _ in 0..6 {
            let _ = vault.judge_typed(WRONG, NOW);
        }

        let confirmer = ScriptedConfirmer::new(&[]);
        assert!(matches!(
            challenge(
                &confirmer,
                &vault,
                &ScriptedAuthenticator::never_completes(),
                "remove",
                &FixedClock(NOW)
            ),
            ChallengeVerdict::RateLimited { .. }
        ));
        assert!(
            confirmer.transcript().is_empty(),
            "a throttled user must not be asked for anything first"
        );
    }

    /// A healthy account is still asked — the peek must not turn into a refusal of its own.
    #[test]
    fn a_healthy_account_is_still_asked_for_the_factor() {
        let dir = tempfile::tempdir().unwrap();
        let (vault, key, _) = enrolled(dir.path());

        assert_eq!(
            challenge(
                &ScriptedConfirmer::new(&[]),
                &vault,
                &key,
                "remove",
                &FixedClock(NOW)
            ),
            ChallengeVerdict::Passed
        );
    }

    /// The pre-check must not itself consume an attempt: repeated throttled challenges leave the
    /// account exactly as able to answer as it was.
    #[test]
    fn peeking_at_the_throttle_does_not_reset_or_consume_it() {
        let dir = tempfile::tempdir().unwrap();
        let (vault, key, _) = enrolled(dir.path());

        for _ in 0..5 {
            assert_eq!(
                challenge(
                    &ScriptedConfirmer::new(&[]),
                    &vault,
                    &key,
                    "remove",
                    &FixedClock(NOW)
                ),
                ChallengeVerdict::Passed,
                "peeking must neither throttle nor consume the free budget"
            );
        }
    }

    /// An unenrolled account reports NOT ENROLLED rather than passing. A silent pass is how a guard
    /// becomes vacuous.
    #[test]
    fn an_unenrolled_account_reports_not_enrolled_rather_than_passing() {
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(
            challenge(
                &ScriptedConfirmer::new(&[]),
                &vault(dir.path()),
                &SoftAuthenticator::roaming(),
                "remove",
                &FixedClock(NOW)
            ),
            ChallengeVerdict::NotEnrolled
        );
    }

    /// **A superseded record clears nothing, and is never reported as absent.**
    ///
    /// Both halves matter and they fail differently: reported as `Passed` it un-gates the destructive
    /// verbs outright, and reported as `NotEnrolled` it un-gates them just as completely while looking
    /// like a healthy account with no factor.
    #[test]
    fn a_superseded_record_never_passes_and_is_never_not_enrolled() {
        let dir = tempfile::tempdir().unwrap();
        plant_superseded(dir.path());
        let confirmer = ScriptedConfirmer::new(&[]);

        let verdict = challenge(
            &confirmer,
            &vault(dir.path()),
            &SoftAuthenticator::roaming(),
            "remove",
            &FixedClock(NOW),
        );
        assert_eq!(verdict, ChallengeVerdict::Superseded);
        assert_ne!(verdict, ChallengeVerdict::Passed);
        assert_ne!(verdict, ChallengeVerdict::NotEnrolled);
        assert!(confirmer.transcript().is_empty(), "and it drew no window");
    }

    /// A challenge that cannot draw its window is UNAVAILABLE, which callers fail closed on.
    #[test]
    fn a_challenge_with_no_window_is_unavailable() {
        let dir = tempfile::tempdir().unwrap();
        let (vault, _, _) = enrolled(dir.path());

        assert_eq!(
            challenge(
                &ScriptedConfirmer::new(&[Act::NoWindow]),
                &vault,
                &ScriptedAuthenticator::never_completes(),
                "remove",
                &FixedClock(NOW)
            ),
            ChallengeVerdict::Unavailable
        );
    }

    // ──────────────── Turning it off ────────────────

    /// **Both gates.** The platform window AND the factor's own evidence are required, and the
    /// platform window alone is not enough.
    #[test]
    fn disabling_unlocked_needs_the_platform_and_the_factor() {
        let dir = tempfile::tempdir().unwrap();
        let (vault, key, _) = enrolled(dir.path());

        assert_eq!(
            disable_unlocked(
                &ScriptedConfirmer::new(&[Act::Decide(ConfirmDecision::Approve)]),
                &vault,
                &key,
                &FixedClock(NOW)
            ),
            DisableOutcome::Disabled
        );
        assert!(!vault.is_enrolled());
    }

    /// A wrong code leaves the factor ON. Failing closed is the only correct direction: a wrongly
    /// refused disable costs a retry, a wrongly accepted one costs the gate.
    #[test]
    fn a_wrong_code_leaves_the_factor_on() {
        let dir = tempfile::tempdir().unwrap();
        let (vault, _, _) = enrolled(dir.path());

        assert_eq!(
            disable_unlocked(
                &ScriptedConfirmer::new(&[
                    Act::Decide(ConfirmDecision::Approve),
                    Act::Type(WRONG.to_string()),
                ]),
                &vault,
                &ScriptedAuthenticator::never_completes(),
                &FixedClock(NOW)
            ),
            DisableOutcome::WrongCode
        );
        assert!(vault.is_enrolled(), "the factor must survive a wrong code");
    }

    /// A recovery code turns the factor off without the key — the lost-key escape hatch.
    #[test]
    fn a_recovery_code_turns_the_factor_off_without_the_key() {
        let dir = tempfile::tempdir().unwrap();
        let (vault, _, code) = enrolled(dir.path());

        assert_eq!(
            disable_unlocked(
                &ScriptedConfirmer::new(&[Act::Decide(ConfirmDecision::Approve), Act::Type(code),]),
                &vault,
                &ScriptedAuthenticator::never_completes(),
                &FixedClock(NOW)
            ),
            DisableOutcome::Disabled
        );
        assert!(!vault.is_enrolled());
    }

    /// Declining the security window never reaches the challenge, so a flow the user abandoned burns
    /// none of their persisted attempts.
    #[test]
    fn declining_the_security_window_never_reaches_the_challenge() {
        let dir = tempfile::tempdir().unwrap();
        let (vault, key, _) = enrolled(dir.path());
        let confirmer = ScriptedConfirmer::new(&[Act::Decide(ConfirmDecision::Deny)]);

        assert_eq!(
            disable_unlocked(&confirmer, &vault, &key, &FixedClock(NOW)),
            DisableOutcome::Refused
        );
        assert!(vault.is_enrolled());
    }

    /// An unreadable record fails closed: the factor stays on rather than being removed on a read
    /// nobody could complete.
    #[test]
    fn disabling_unlocked_fails_closed_on_an_unreadable_record() {
        let dir = tempfile::tempdir().unwrap();
        let (vault, key, _) = enrolled(dir.path());
        crate::account::second_factor::vault::test_support::sealer_of(&vault).lock();

        assert_eq!(
            disable_unlocked(&ScriptedConfirmer::new(&[]), &vault, &key, &FixedClock(NOW)),
            DisableOutcome::Unavailable
        );
        assert!(vault.is_enrolled());
    }

    /// A throttled account is told the wait rather than being asked for evidence it will not judge.
    #[test]
    fn disabling_unlocked_while_throttled_reports_the_wait() {
        let dir = tempfile::tempdir().unwrap();
        let (vault, key, _) = enrolled(dir.path());
        for _ in 0..6 {
            let _ = vault.judge_typed(WRONG, NOW);
        }

        assert!(matches!(
            disable_unlocked(
                &ScriptedConfirmer::new(&[Act::Decide(ConfirmDecision::Approve)]),
                &vault,
                &key,
                &FixedClock(NOW)
            ),
            DisableOutcome::RateLimited { .. }
        ));
        assert!(vault.is_enrolled());
    }

    /// Disabling nothing reports nothing to disable, and draws no window.
    #[test]
    fn disabling_nothing_reports_nothing_to_disable() {
        let dir = tempfile::tempdir().unwrap();
        let confirmer = ScriptedConfirmer::new(&[]);

        assert_eq!(
            disable_unlocked(
                &confirmer,
                &vault(dir.path()),
                &SoftAuthenticator::roaming(),
                &FixedClock(NOW)
            ),
            DisableOutcome::NotEnrolled
        );
        assert!(confirmer.transcript().is_empty());
    }

    /// **The walk-around this refusal exists to close.** A LOCKED account cannot turn the factor off,
    /// so `Lock now` → disable → replace is not a path.
    #[test]
    fn locking_the_account_must_not_walk_around_the_second_factor() {
        let dir = tempfile::tempdir().unwrap();
        enrolled(dir.path());

        assert_eq!(
            disable_locked(
                &crate::account::second_factor::vault::DirectoryEnrolment::new(dir.path())
            ),
            DisableOutcome::NeedsUnlock
        );
        assert!(
            crate::account::second_factor::vault::enrolment_present(dir.path()),
            "the enrolment must survive"
        );
    }

    /// The disable window states what is LOST, in both record shapes — and the two sentences differ,
    /// because a superseded record was never clearing a gate and saying "your key stops working"
    /// about it would be false.
    #[test]
    fn the_disable_window_states_what_is_lost_in_each_state() {
        let dir = tempfile::tempdir().unwrap();
        // Named for the state it holds, not `vault`, so it cannot shadow the `vault(dir)` helper the
        // superseded half of this test needs a line later.
        let (current_vault, key, _) = enrolled(dir.path());
        let current = ScriptedConfirmer::new(&[Act::Decide(ConfirmDecision::Deny)]);
        let _ = disable_unlocked(&current, &current_vault, &key, &FixedClock(NOW));

        let old_dir = tempfile::tempdir().unwrap();
        plant_superseded(old_dir.path());
        let old = ScriptedConfirmer::new(&[Act::Decide(ConfirmDecision::Deny)]);
        let _ = disable_unlocked(&old, &vault(old_dir.path()), &key, &FixedClock(NOW));

        assert!(current.transcript().contains("security key"));
        assert!(current.transcript().contains("recovery codes stop working"));
        assert!(old.transcript().contains("authenticator-app"));
        assert_ne!(
            current.transcript(),
            old.transcript(),
            "the two states lose different things and must not share a sentence"
        );
    }

    // ──────────────── Retiring the superseded record ────────────────

    /// The retirement path, both ways in: a TOTP code from the app it was set up with, and an unspent
    /// recovery code.
    ///
    /// Both are asserted because the whole reason Q1 was answered YES is that recovery-codes-only
    /// leaves a person with their phone and no codes holding only break glass — which, for anyone
    /// without a saved recovery phrase, is loss of funds.
    #[test]
    fn a_superseded_record_is_retired_by_a_code_from_its_own_app() {
        let dir = tempfile::tempdir().unwrap();
        let secret = plant_superseded(dir.path());

        assert_eq!(
            disable_unlocked(
                &ScriptedConfirmer::new(&[
                    Act::Decide(ConfirmDecision::Approve),
                    Act::Type(secret.code_at(NOW).to_string()),
                ]),
                &vault(dir.path()),
                &SoftAuthenticator::roaming(),
                &FixedClock(NOW)
            ),
            DisableOutcome::Disabled
        );
        assert!(!vault(dir.path()).is_enrolled());
    }

    /// **The security window alone must NEVER retire a superseded record.** Windows Hello satisfies
    /// exactly the attacker this factor is for, so accepting it here would be de-gating — and
    /// de-gating is silent.
    #[test]
    fn a_superseded_record_is_never_retired_by_the_security_window_alone() {
        let dir = tempfile::tempdir().unwrap();
        plant_superseded(dir.path());

        assert_eq!(
            disable_unlocked(
                &ScriptedConfirmer::new(&[
                    Act::Decide(ConfirmDecision::Approve),
                    Act::Type(WRONG.to_string()),
                ]),
                &vault(dir.path()),
                &SoftAuthenticator::roaming(),
                &FixedClock(NOW)
            ),
            DisableOutcome::WrongCode
        );
        assert!(
            vault(dir.path()).is_enrolled(),
            "approving the platform window is not evidence of the factor"
        );
    }

    /// A stale code from the superseded app is refused as well, so its own single-use rule still binds
    /// on the path that removes it.
    #[test]
    fn a_replayed_superseded_code_does_not_retire_the_record() {
        let dir = tempfile::tempdir().unwrap();
        let secret = plant_superseded(dir.path());
        let code = secret.code_at(NOW).to_string();
        let _ = vault(dir.path()).judge_typed(&code, NOW);

        assert_eq!(
            disable_unlocked(
                &ScriptedConfirmer::new(&[Act::Decide(ConfirmDecision::Approve), Act::Type(code),]),
                &vault(dir.path()),
                &SoftAuthenticator::roaming(),
                &FixedClock(NOW + STEP_SECONDS / 2)
            ),
            DisableOutcome::WrongCode
        );
        assert!(vault(dir.path()).is_enrolled());
    }

    /// Running out of recovery codes is reported differently from having some left, because the two
    /// leave the user in different situations and only one of them needs acting on now.
    #[test]
    fn running_out_of_recovery_codes_is_reported_differently() {
        let none_left = ScriptedConfirmer::new(&[]);
        report_recovery_code_spent(&none_left, 0);
        let some_left = ScriptedConfirmer::new(&[]);
        report_recovery_code_spent(&some_left, 3);

        assert!(none_left.transcript().contains("LAST recovery code"));
        assert!(some_left.transcript().contains("3 recovery code(s) left"));
    }
}
