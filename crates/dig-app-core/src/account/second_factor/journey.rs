//! The **enrolment, challenge and disable journeys** — the order these screens happen in for a human
//! (dig_ecosystem#1840).
//!
//! The pieces underneath are narrow on purpose: [`totp`](super::totp) knows arithmetic,
//! [`recovery_codes`](super::recovery_codes) knows codes, [`vault`](super::vault) knows at-rest, and
//! [`confirm`](crate::confirm) knows how to draw an OS-owned window. This module is the only place
//! that knows the SEQUENCE, which is where the safety rules live:
//!
//! - **Nothing is written until the user has proved a code works.** Every failure and every escape
//!   before that point leaves no enrolment at all, so a person can back out of any screen and be
//!   exactly where they started. A setup flow that enrols first and verifies afterwards is how someone
//!   ends up locked out of their own account by the feature that was meant to protect it.
//! - **The recovery codes are claimed, not merely shown.** Same two-step treatment the recovery phrase
//!   gets ([`ClaimPrompt`]), because refusing is load-bearing: it abandons the enrolment rather than
//!   proceeding with codes nobody kept.
//! - **Turning it off is an authorization, not a toggle.** It goes through the biometric seam
//!   ([`NativeConfirmer::confirm_security_change`]).
//! - **Nothing here logs the key or a code.**

use crate::confirm::QrArt;
use crate::confirm::{
    ClaimPrompt, ConfirmDecision, InputOutcome, InputPrompt, InputStyle, NativeConfirmer,
    NoticePrompt, SecurityPrompt,
};
use crate::sealer::ProfileSealer;

use super::recovery_codes::RecoveryCodeSet;
use super::totp::{TotpSecret, CODE_DIGITS};
use super::vault::{ChallengeOutcome, Enrolment, SecondFactorVault, VaultError};

/// How many times the user may mistype the verification code during enrolment before the flow gives
/// up.
///
/// Three is enough to absorb a transcription slip and a phone whose clock has just ticked over, and
/// small enough that a flow which is going wrong (the secret was typed in incorrectly) ends with an
/// explanation rather than an unbounded loop the user has to close by force.
const VERIFY_ATTEMPTS: usize = 3;

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
/// A journey that read `SystemTime::now` directly could not be tested against a chosen TOTP step, and a
/// test that passed small literals through a wall-clock API would silently be exercising only the
/// long-expired path.
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
            // epoch makes every code wrong, which is the safe direction (nothing is accepted).
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
    /// The user could not produce a correct code within `VERIFY_ATTEMPTS`. Nothing was enrolled —
    /// which is the whole point of verifying before writing.
    NotVerified,
    /// A second factor is already enrolled. Re-running setup would silently invalidate the codes the
    /// user is holding, so it is refused and the caller says so.
    AlreadyEnrolled,
    /// No window could be drawn, or the account locked mid-flow. Nothing was enrolled.
    Unavailable,
    /// The enrolment was verified but could not be stored.
    Failed,
}

/// The body of the "add DIG to your authenticator" screen.
///
/// # Why the typed key is here whether or not there is a QR
///
/// The QR is a convenience for one kind of user in one kind of moment: sighted, with a second device,
/// with a camera that focuses. It is useless to someone using a screen reader, to someone whose
/// authenticator is a password manager on THIS machine, and to anyone whose camera will not lock onto
/// a glowing panel. Those people are not edge cases and they do not get a lesser flow, so the base32
/// key stays on the screen and stays typeable — the QR was ADDED beside it (dig_ecosystem#1849), it did
/// not replace it.
///
/// # Why the copy changes with `has_qr`
///
/// "Scan the code below" printed over an empty space is worse than never offering a scan: it reads as
/// a window that failed to load, and the user goes looking for the missing picture instead of using
/// the key that is right there. `has_qr` comes from the confirmer's own
/// [`draws_qr`](crate::confirm::NativeConfirmer::draws_qr), so the sentence and the square agree.
///
/// Pure, so both bodies are unit-testable without a display.
fn add_to_authenticator_body(secret: &TotpSecret, has_qr: bool) -> String {
    let opening = match has_qr {
        true => {
            "Scan the square below with your authenticator app.\n\nOr add it by hand — choose to \
                 add an account by ENTERING A KEY, and type:"
        }
        false => "Choose to add an account by ENTERING A KEY, and type:",
    };
    format!(
        "{opening}\n\n{key}\n\nName it anything you like — DIG will appear as \"{issuer}\". If your \
         app asks for settings, they are: time-based, {digits} digits, {period} seconds.",
        key = *secret.base32_grouped(),
        issuer = super::totp::ISSUER,
        digits = CODE_DIGITS,
        period = super::totp::STEP_SECONDS,
    )
}

/// What happened when the user was challenged for a code.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChallengeVerdict {
    /// A correct authenticator code.
    Passed,
    /// A correct recovery code, which is now spent.
    PassedWithRecoveryCode {
        /// How many unspent recovery codes are left.
        remaining: usize,
    },
    /// The user closed the window without answering. The action must not proceed.
    Cancelled,
    /// The code was wrong, or was one already used inside its own window.
    Failed,
    /// Too many codes have failed in a row, so the user must WAIT before trying again
    /// (dig_ecosystem#1847). A rate limit, not a lockout — kept distinct from [`Failed`](Self::Failed)
    /// so the window can tell the user to wait rather than to type a fresh code that will be refused
    /// unread.
    RateLimited {
        /// Whole seconds the user must wait before another code will be checked.
        retry_after_seconds: u64,
    },
    /// No second factor is enrolled, so there was nothing to ask. Deliberately NOT collapsed into
    /// [`Passed`](Self::Passed): a caller must decide what "no factor" means for its own action, and a
    /// silent pass is how a guard becomes vacuous.
    NotEnrolled,
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
}

/// Run the enrolment flow: explain, show the key, verify a code, hand over recovery codes, store.
///
/// The user names the entry in their own authenticator, so nothing account-identifying is passed in or
/// shown — one less place a DIG ID can end up on a phone's screen.
///
/// Every screen before the final store is escapable and leaves NOTHING enrolled — the property the
/// module docs open with, and the one the `enrolment_can_be_abandoned_at_every_screen` test pins.
pub fn enrol<S: ProfileSealer>(
    confirmer: &dyn NativeConfirmer,
    vault: &SecondFactorVault<S>,
    clock: &dyn Clock,
) -> EnrolOutcome {
    if vault.is_enrolled() {
        return EnrolOutcome::AlreadyEnrolled;
    }

    match confirmer.confirm_claim(&ClaimPrompt {
        title: "DIG — Two-factor codes",
        heading: "Add a code from your phone to this account?",
        body: EXPLAINER,
        affirm: "Set it up",
        scannable: None,
    }) {
        ConfirmDecision::Approve => {}
        ConfirmDecision::Deny => return EnrolOutcome::Abandoned,
        _ => return EnrolOutcome::Unavailable,
    }

    let secret = TotpSecret::generate();
    // The URI carries the secret in the clear. It is built here, consumed by the encoder on the next
    // line, and dropped at the end of this screen — it is never logged, stored, or shown as text.
    let scannable = confirmer
        .draws_qr()
        .then(|| QrArt::encode(&secret.provisioning_uri()))
        .flatten();
    match confirmer.confirm_claim(&ClaimPrompt {
        title: "DIG — Add DIG to your authenticator",
        heading: "Add DIG to your authenticator app.",
        body: &add_to_authenticator_body(&secret, scannable.is_some()),
        affirm: "I've added it",
        scannable: scannable.as_ref(),
    }) {
        ConfirmDecision::Approve => {}
        ConfirmDecision::Deny => return EnrolOutcome::Abandoned,
        _ => return EnrolOutcome::Unavailable,
    }

    match verify_a_code(confirmer, &secret, clock) {
        Verification::Verified => {}
        Verification::Abandoned => return EnrolOutcome::Abandoned,
        Verification::Exhausted => return EnrolOutcome::NotVerified,
        Verification::Unavailable => return EnrolOutcome::Unavailable,
    }

    let codes = RecoveryCodeSet::generate();
    match confirmer.confirm_claim(&ClaimPrompt {
        title: "DIG — Your recovery codes",
        heading: "Save these codes and keep them safe.",
        body: &format!(
            "{codes}\nEach code works ONCE. Keep them somewhere other than your phone.\n\n\
             This is the only time they will be shown. Lose your phone with no codes saved, and you \
             will not be able to replace or remove this account on this computer.",
            codes = *codes.printable(),
        ),
        affirm: "I have saved these",
        scannable: None,
    }) {
        ConfirmDecision::Approve => {}
        ConfirmDecision::Deny => return EnrolOutcome::Abandoned,
        _ => return EnrolOutcome::Unavailable,
    }

    // The ONLY write in this function, and it happens last: everything above can be walked away from.
    match vault.enrol(&secret, &codes) {
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

/// Ask for a code and judge it, for an action that demands the second factor.
///
/// `purpose` names what the code is FOR, in the user's words (e.g. `"replace the DIG Account on this
/// computer"`), so the window never asks for a code without saying why.
pub fn challenge<S: ProfileSealer>(
    confirmer: &dyn NativeConfirmer,
    vault: &SecondFactorVault<S>,
    purpose: &str,
    clock: &dyn Clock,
) -> ChallengeVerdict {
    if !vault.is_enrolled() {
        return ChallengeVerdict::NotEnrolled;
    }

    // Tell a rate-limited user to wait BEFORE drawing the code window, not after they have typed a full
    // code only to have it refused unread (dig_ecosystem#1970). This peek judges no code and mutates
    // nothing (see `SecondFactorVault::current_throttle`); the post-judge `RateLimited` arm below stays
    // as the backstop for a throttle that arms *during* the flow.
    match vault.current_throttle(clock.now_unix()) {
        Ok(Some(retry_after_seconds)) => {
            return ChallengeVerdict::RateLimited {
                retry_after_seconds,
            };
        }
        Ok(None) => {}
        // Fail closed exactly as the post-judge path does: a locked or unreadable vault is not a pass,
        // and must not prompt as though nothing were wrong.
        Err(e) => {
            tracing::warn!(error = %e, "a second-factor throttle could not be read");
            return ChallengeVerdict::Unavailable;
        }
    }

    let typed = match confirmer.request_input(&InputPrompt {
        title: "DIG — Two-factor code",
        heading: &format!("Enter your code to {purpose}."),
        body:
            "Open your authenticator app and type the current 6-digit DIG code. If you do not have \
               your phone, type one of your recovery codes instead — each of those works once.",
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
        InputOutcome::Cancelled => return ChallengeVerdict::Cancelled,
        InputOutcome::Unavailable => return ChallengeVerdict::Unavailable,
    };

    match vault.challenge(&typed, clock.now_unix()) {
        Ok(ChallengeOutcome::Accepted) => ChallengeVerdict::Passed,
        Ok(ChallengeOutcome::AcceptedRecoveryCode { remaining }) => {
            ChallengeVerdict::PassedWithRecoveryCode { remaining }
        }
        Ok(ChallengeOutcome::AlreadyUsed) | Ok(ChallengeOutcome::Rejected) => {
            ChallengeVerdict::Failed
        }
        Ok(ChallengeOutcome::RateLimited {
            retry_after_seconds,
        }) => ChallengeVerdict::RateLimited {
            retry_after_seconds,
        },
        // A locked account cannot answer a challenge, and an unreadable record is not a pass.
        Err(e) => {
            tracing::warn!(error = %e, "a second-factor challenge could not be judged");
            ChallengeVerdict::Unavailable
        }
    }
}

/// Turn the second factor off, behind the biometric authorization seam.
///
/// # Why this does NOT also demand a code
///
/// Requiring the second factor in order to remove the second factor turns a lost phone into a
/// permanently degraded account: the recovery codes exist for the lost-phone case, and making them the
/// only way out of *lost phone AND lost codes* would leave a person with an account they can never
/// fully manage again — the trap §6.1 forbids. The gate is therefore the platform authenticator
/// (Windows Hello / Touch ID), which is a real factor a passer-by at an unlocked machine does not
/// have, and the window states plainly what is being given up.
///
/// Takes the [`Enrolment`] seam rather than a vault so it serves a LOCKED account too — which is what
/// keeps an account that will not open from becoming permanently unremovable (see
/// [`DirectoryEnrolment`](super::vault::DirectoryEnrolment)).
pub fn disable(confirmer: &dyn NativeConfirmer, enrolment: &dyn Enrolment) -> DisableOutcome {
    if !enrolment.is_enrolled() {
        return DisableOutcome::NotEnrolled;
    }

    if confirmer.confirm_security_change(&SecurityPrompt {
        change: "turn off two-factor codes",
        consequence: "Replacing or removing this account will no longer ask for a code from your \
                      phone — knowing how to unlock this computer will be enough. Your recovery codes \
                      stop working, and setting two-factor up again will issue a new key and new codes.",
        affirm: "Turn it off",
    }) != ConfirmDecision::Approve
    {
        return DisableOutcome::Refused;
    }

    match enrolment.remove() {
        Ok(()) => DisableOutcome::Disabled,
        Err(e) => {
            tracing::warn!(error = %e, "the second factor could not be turned off");
            DisableOutcome::Failed
        }
    }
}

/// Tell the user how many recovery codes they have left, once one has been spent.
///
/// Drawn as a notice rather than folded into the previous window because it arrives AFTER the action
/// the code authorized: a person who has just used their last code needs to be told plainly, at the
/// moment it becomes true.
pub fn report_recovery_code_spent(confirmer: &dyn NativeConfirmer, remaining: usize) {
    let body = match remaining {
        0 => "That was your LAST recovery code. If you also lose your phone, you will not be able to \
              replace or remove this account on this computer. Turn two-factor off and set it up \
              again from the Security menu to get a new set."
            .to_string(),
        _ => format!(
            "You have {remaining} recovery code(s) left. When you run low, turn two-factor off and \
             set it up again from the Security menu to get a fresh set."
        ),
    };
    confirmer.show_notice(&NoticePrompt {
        title: "DIG — Recovery code used",
        heading: "You used a recovery code, and it is now spent.",
        body: &body,
        acknowledge: "OK",
    });
}

/// The honest explanation, shown before anything is generated.
///
/// It states what this does NOT protect against, in the first paragraph, because the alternative is a
/// person believing their unlocked machine is now safe from someone sitting at it. The justification it
/// gives — another DEVICE — is the true one: Windows Hello is already a factor, and it is bound to this
/// machine and this logon session.
const EXPLAINER: &str = "\
Your DIG Account already asks Windows to check it is you. That check lives on THIS computer, in THIS \
sign-in session — a code from your phone lives somewhere else.\n\n\
It stops someone who has learned or guessed how to unlock this computer, or who sits down at it while \
it is unlocked, from replacing or removing your DIG Account.\n\n\
What it does NOT stop is someone who has fully taken over this computer. Your code is checked here, so \
the key for it is stored here too. This raises the bar; it is not a wall.";

/// The result of the verify step, kept separate from [`EnrolOutcome`] so the enrol flow reads as a
/// sequence of steps rather than a nest of matches.
enum Verification {
    Verified,
    Abandoned,
    Exhausted,
    Unavailable,
}

/// Ask for a code until one verifies against `secret`, the user gives up, or the attempts run out.
///
/// Checked against the SECRET directly rather than through the vault, because the vault deliberately
/// holds nothing yet — this is the step that decides whether anything gets written at all.
fn verify_a_code(
    confirmer: &dyn NativeConfirmer,
    secret: &TotpSecret,
    clock: &dyn Clock,
) -> Verification {
    for attempt in 1..=VERIFY_ATTEMPTS {
        let retry = match attempt {
            1 => String::new(),
            _ => format!(
                "\n\nThat code was not right. Codes change every 30 seconds, so wait for a fresh one. \
                 {left} attempt(s) left.",
                left = VERIFY_ATTEMPTS - attempt + 1
            ),
        };
        let typed = match confirmer.request_input(&InputPrompt {
            title: "DIG — Check it works",
            heading: "Type the current code from your authenticator.",
            body: &format!(
                "This proves the key was copied correctly. Nothing is turned on until a code works — \
                 if you cannot get one, close this window and your account is unchanged.{retry}"
            ),
            field_label: &format!("{CODE_DIGITS}-digit code:"),
            submit: "Verify",
            masked: false,
            revealable: false,
            style: InputStyle::Dialog,
        }) {
            InputOutcome::Provided(text) => text,
            InputOutcome::Cancelled => return Verification::Abandoned,
            InputOutcome::Unavailable => return Verification::Unavailable,
        };

        if secret.matching_step(&typed, clock.now_unix()).is_some() {
            return Verification::Verified;
        }
    }
    Verification::Exhausted
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::confirm::{ConnectPrompt, DestroyPrompt, PairPrompt, RevealPrompt, SignPrompt};
    use crate::test_support::FakeSealer;
    use std::path::Path;
    use std::sync::Mutex;
    use zeroize::Zeroizing;

    /// A pinned instant, never the wall clock: the fixture must be able to place a code at a chosen
    /// step, and a wall-clock fixture cannot.
    const NOW: u64 = 1_700_000_000;
    const DID: &str = "did:chia:profile-a";

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
        /// Submit this text at the next input window. `TYPED_CODE` is replaced by a live code for the
        /// secret the flow just generated — the only way a scripted double can answer a challenge it
        /// could not have known in advance.
        Type(String),
        /// Cancel the next input window.
        CancelInput,
        /// Report that no window could be drawn.
        NoWindow,
    }

    /// The marker a script uses to mean "whatever the correct code is right now".
    const LIVE_CODE: &str = "<live>";

    /// A confirmer that plays a script and records what it was shown.
    ///
    /// It deliberately answers claim windows and input windows from ONE queue, in order, because the
    /// ORDER of the screens is part of what these tests assert — a double with a separate answer per
    /// prompt TYPE could not distinguish "asked for the code before showing the recovery codes" from
    /// the reverse.
    struct ScriptedConfirmer {
        script: Mutex<std::collections::VecDeque<Act>>,
        /// The secret the flow generated, learned by scraping the key out of the window that shows it,
        /// so a scripted run can answer with a REAL code. Without this the enrolment path could only
        /// ever be tested with a wrong code.
        secret: Mutex<Option<TotpSecret>>,
        shown: Mutex<Vec<String>>,
        /// Every HEADING drawn, kept apart from the bodies because the heading has its own (much
        /// tighter) width budget and is clipped silently when it overruns.
        headings: Mutex<Vec<String>>,
        /// Whether this double claims it can DRAW a QR — the capability the enrolment copy branches on.
        draws_qr: bool,
        /// The QR the flow handed to a window, so a test can check WHAT it encodes rather than merely
        /// that one was passed.
        scanned: Mutex<Option<QrArt>>,
        now: u64,
    }

    impl ScriptedConfirmer {
        fn new(now: u64, acts: &[Act]) -> Self {
            Self {
                script: Mutex::new(acts.iter().cloned().collect()),
                secret: Mutex::new(None),
                shown: Mutex::new(Vec::new()),
                headings: Mutex::new(Vec::new()),
                draws_qr: false,
                scanned: Mutex::new(None),
                now,
            }
        }

        /// The same double, but able to draw a QR — one field varied, so a comparison between the two
        /// isolates the QR from everything else about the flow.
        fn drawing_qr(now: u64, acts: &[Act]) -> Self {
            Self {
                draws_qr: true,
                ..Self::new(now, acts)
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

        /// Learn the key from the window that presents it, exactly as a user's phone would — by
        /// reading the grouped base32 block off the screen.
        ///
        /// Scraping rather than being handed the secret is what makes the scripted run answer with a
        /// REAL code: the enrolment generates the key internally and never returns it, so a double that
        /// could not read it off the window could only ever submit a wrong code.
        fn learn_secret(&self, body: &str) {
            let Some(line) = body
                .lines()
                .map(str::trim)
                .find(|line| line.len() == 39 && line.split(' ').all(|group| group.len() == 4))
            else {
                return;
            };
            let mut bytes = Vec::new();
            let (mut buffer, mut bits) = (0u16, 0u32);
            for ch in line.chars().filter(|c| !c.is_whitespace()) {
                let value = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
                    .find(ch)
                    .expect("an RFC 4648 base32 character") as u16;
                buffer = (buffer << 5) | value;
                bits += 5;
                if bits >= 8 {
                    bits -= 8;
                    bytes.push((buffer >> bits) as u8);
                }
            }
            *self.secret.lock().unwrap() = TotpSecret::from_bytes(&bytes).ok();
        }

        fn live_code(&self) -> String {
            let guard = self.secret.lock().unwrap();
            let secret = guard.as_ref().expect("the secret window must come first");
            secret.code_at(self.now).to_string()
        }
    }

    impl NativeConfirmer for ScriptedConfirmer {
        fn draws_qr(&self) -> bool {
            self.draws_qr
        }

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
            self.learn_secret(prompt.body);
            if let Some(art) = prompt.scannable {
                *self.scanned.lock().unwrap() = Some(art.clone());
            }
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
                Act::Type(text) if text == LIVE_CODE => {
                    InputOutcome::Provided(Zeroizing::new(self.live_code()))
                }
                Act::Type(text) => InputOutcome::Provided(Zeroizing::new(text)),
                Act::CancelInput => InputOutcome::Cancelled,
                Act::NoWindow => InputOutcome::Unavailable,
                Act::Decide(_) => panic!("the script offered a decision to a window with a field"),
            }
        }
    }

    /// The full happy path, driven end to end by a double that learns the secret from the window and
    /// answers with a REAL code — the same thing a phone does.
    fn run_enrolment(dir: &Path, acts: &[Act]) -> (EnrolOutcome, ScriptedConfirmer) {
        let confirmer = ScriptedConfirmer::new(NOW, acts);
        let outcome = enrol(&confirmer, &vault(dir), &FixedClock(NOW));
        (outcome, confirmer)
    }

    // ──────────────── The enrolment QR (dig_ecosystem#1849) ────────────────

    /// The QR handed to the window encodes a provisioning URI for THE SAME secret the window shows as
    /// text.
    ///
    /// This is the property the whole feature rests on, and it is the one a screenshot cannot check: a
    /// square that is a perfectly valid QR of the WRONG string photographs identically to the right
    /// one, imports without complaint, and produces an authenticator whose every code is refused.
    ///
    /// It is checked by rebuilding the expected QR from the key scraped OFF THE SCREEN — the same
    /// characters a person would type — and comparing matrices. Comparing against the secret the flow
    /// generated internally would be weaker: it would still pass if the text and the QR came from two
    /// different secrets, which is exactly the failure that leaves a user enrolled on a code their
    /// phone will never produce.
    #[test]
    fn the_qr_encodes_a_uri_for_the_key_the_window_shows_as_text() {
        let dir = tempfile::tempdir().unwrap();
        let confirmer = ScriptedConfirmer::drawing_qr(NOW, &happy_path());
        assert_eq!(
            enrol(&confirmer, &vault(dir.path()), &FixedClock(NOW)),
            EnrolOutcome::Enrolled { recovery_codes: 10 }
        );

        let on_screen = confirmer
            .secret
            .lock()
            .unwrap()
            .clone()
            .expect("the key was shown as text");
        let drawn = confirmer
            .scanned
            .lock()
            .unwrap()
            .clone()
            .expect("a QR was handed to the window");

        assert_eq!(
            drawn,
            QrArt::encode(&on_screen.provisioning_uri()).expect("the URI encodes"),
            "the QR must encode the provisioning URI of the key on screen"
        );
        // ...and NOT the key alone, nor its grouped rendering — both are strings an authenticator
        // cannot import, and both would still draw a plausible-looking square.
        assert_ne!(drawn, QrArt::encode(&on_screen.base32()).expect("encodes"));
        assert_ne!(
            drawn,
            QrArt::encode(&on_screen.base32_grouped()).expect("encodes")
        );
    }

    /// The typed key is on the screen whether or not a QR is.
    ///
    /// Both runs are asserted, because the regression this guards against is one-directional: adding a
    /// QR and quietly dropping the key would leave the flow working perfectly for everyone with a
    /// phone camera and impossible for everyone using a screen reader, a same-machine authenticator, or
    /// a camera that will not focus.
    #[test]
    fn the_typed_key_stays_on_screen_with_and_without_a_qr() {
        for drawing in [false, true] {
            let dir = tempfile::tempdir().unwrap();
            let confirmer = match drawing {
                true => ScriptedConfirmer::drawing_qr(NOW, &happy_path()),
                false => ScriptedConfirmer::new(NOW, &happy_path()),
            };
            assert_eq!(
                enrol(&confirmer, &vault(dir.path()), &FixedClock(NOW)),
                EnrolOutcome::Enrolled { recovery_codes: 10 },
                "drawing a QR: {drawing}"
            );

            let secret = confirmer.secret.lock().unwrap().clone();
            let secret = secret.expect("the key must be readable off the screen");
            assert!(
                confirmer.transcript().contains(&*secret.base32_grouped()),
                "the grouped key must be shown as text (drawing a QR: {drawing})"
            );
            assert!(
                confirmer.transcript().contains("ENTERING A KEY"),
                "the manual path must stay offered (drawing a QR: {drawing})"
            );
        }
    }

    /// A confirmer that cannot draw a QR is never given one, and is never told to scan.
    ///
    /// Two distinct failures, and the second is the visible one: a window that says "scan the square
    /// below" over empty space reads as broken, and sends the user looking for a missing picture
    /// instead of typing the key that is right in front of them. The first matters too — encoding a URI
    /// that will never be drawn puts the secret through an encoder for no reason at all.
    #[test]
    fn a_window_that_cannot_draw_a_qr_is_neither_given_one_nor_told_to_scan() {
        let dir = tempfile::tempdir().unwrap();
        let confirmer = ScriptedConfirmer::new(NOW, &happy_path());
        let _ = enrol(&confirmer, &vault(dir.path()), &FixedClock(NOW));

        assert!(confirmer.scanned.lock().unwrap().is_none());
        assert!(
            !confirmer.transcript().to_lowercase().contains("scan"),
            "no scan instruction without a square to scan:\n{}",
            confirmer.transcript()
        );
    }

    /// The window that DOES draw one says so — otherwise the square is an unexplained picture on a
    /// security screen, which is a thing people are right to distrust.
    #[test]
    fn a_window_that_draws_a_qr_tells_the_user_to_scan_it() {
        let dir = tempfile::tempdir().unwrap();
        let confirmer = ScriptedConfirmer::drawing_qr(NOW, &happy_path());
        let _ = enrol(&confirmer, &vault(dir.path()), &FixedClock(NOW));

        assert!(
            confirmer.transcript().contains("Scan the square below"),
            "{}",
            confirmer.transcript()
        );
    }

    /// The `otpauth://` URI is never SHOWN — not in a body, not in a heading.
    ///
    /// It is a third rendering of the same secret and it buys nothing beside the QR and the key, so it
    /// is a third place the credential can be photographed or read over a shoulder. It is also the
    /// string whose unbreakable 130 characters made the first build clip (#1840); the window layer now
    /// breaks such runs, but not putting it on screen at all is the stronger guarantee.
    #[test]
    fn the_provisioning_uri_is_never_drawn_as_text() {
        let dir = tempfile::tempdir().unwrap();
        let confirmer = ScriptedConfirmer::drawing_qr(NOW, &happy_path());
        let _ = enrol(&confirmer, &vault(dir.path()), &FixedClock(NOW));

        assert!(
            !confirmer.transcript().contains("otpauth://"),
            "{}",
            confirmer.transcript()
        );
        assert!(!confirmer
            .headings
            .lock()
            .unwrap()
            .join("\n")
            .contains("otpauth://"));
    }

    /// No screen carries a run of spaces mid-sentence.
    ///
    /// A source literal broken across lines with a trailing `\` resolves cleanly in Rust — but a body
    /// assembled by any tool that does NOT strip the indentation ships a sentence with a hole in the
    /// middle of it. That has already happened twice in this codebase, and both times it was invisible
    /// to every substring assertion (`contains("…")` still matched) and obvious in a photograph. This
    /// is the cheap assertion that would have caught it: prose has single spaces.
    ///
    /// Three is the threshold, not two: an author may legitimately double-space after a full stop, and
    /// the numbered recovery-code block aligns its columns with runs it means.
    #[test]
    fn no_screens_copy_carries_a_hole_mid_sentence() {
        let dir = tempfile::tempdir().unwrap();
        let confirmer = ScriptedConfirmer::drawing_qr(NOW, &happy_path());
        let _ = enrol(&confirmer, &vault(dir.path()), &FixedClock(NOW));

        for line in confirmer.transcript().lines() {
            // Only PROSE is checked. The recovery-code block and the base32 key are column-aligned
            // runs of upper-case tokens whose spacing is deliberate — and both have their own tests.
            // A sentence is identified by carrying lower-case letters, which no code block does.
            if !line.contains(char::is_lowercase) {
                continue;
            }
            assert!(
                !line.contains("   "),
                "a run of spaces mid-sentence: {line:?}"
            );
        }
    }

    /// The affirmative answer to every screen, with a live code at the verify step.
    fn happy_path() -> Vec<Act> {
        vec![
            Act::Decide(ConfirmDecision::Approve), // the explainer
            Act::Decide(ConfirmDecision::Approve), // "I've added it"
            Act::Type(LIVE_CODE.to_string()),      // verify
            Act::Decide(ConfirmDecision::Approve), // "I have saved these"
        ]
    }

    #[test]
    fn a_complete_enrolment_stores_a_working_second_factor() {
        let dir = tempfile::tempdir().unwrap();
        let (outcome, _) = run_enrolment(dir.path(), &happy_path());

        assert_eq!(
            outcome,
            EnrolOutcome::Enrolled {
                recovery_codes: super::super::recovery_codes::CODE_COUNT
            }
        );
        assert!(vault(dir.path()).is_enrolled());
    }

    /// The single most important property of the flow: EVERY screen can be walked away from, and none
    /// of those exits leaves an enrolment behind.
    ///
    /// Driven by truncating the happy path at each screen in turn and refusing there, so the test grows
    /// automatically with the flow rather than pinning today's screen count.
    #[test]
    fn enrolment_can_be_abandoned_at_every_screen() {
        let happy = happy_path();
        for stop in 0..happy.len() {
            let dir = tempfile::tempdir().unwrap();
            let mut script: Vec<Act> = happy[..stop].to_vec();
            script.push(match happy[stop] {
                Act::Type(_) => Act::CancelInput,
                _ => Act::Decide(ConfirmDecision::Deny),
            });

            let (outcome, _) = run_enrolment(dir.path(), &script);
            assert_eq!(
                outcome,
                EnrolOutcome::Abandoned,
                "backing out at screen {stop}"
            );
            assert!(
                !vault(dir.path()).is_enrolled(),
                "backing out at screen {stop} must leave NOTHING enrolled"
            );
        }
    }

    /// A user who cannot produce a correct code is not enrolled — the property that keeps a mistyped
    /// key from locking someone out of their own account. Three wrong codes, then nothing.
    #[test]
    fn a_code_that_never_verifies_enrols_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let (outcome, _) = run_enrolment(
            dir.path(),
            &[
                Act::Decide(ConfirmDecision::Approve),
                Act::Decide(ConfirmDecision::Approve),
                Act::Type("000000".into()),
                Act::Type("111111".into()),
                Act::Type("222222".into()),
            ],
        );

        assert_eq!(outcome, EnrolOutcome::NotVerified);
        assert!(!vault(dir.path()).is_enrolled());
    }

    /// …but a user who mistypes and then gets it right IS enrolled. Without this control the test above
    /// would also pass for a flow that refused every code.
    #[test]
    fn a_mistyped_code_can_be_retried() {
        let dir = tempfile::tempdir().unwrap();
        let (outcome, _) = run_enrolment(
            dir.path(),
            &[
                Act::Decide(ConfirmDecision::Approve),
                Act::Decide(ConfirmDecision::Approve),
                Act::Type("000000".into()),
                Act::Type(LIVE_CODE.to_string()),
                Act::Decide(ConfirmDecision::Approve),
            ],
        );

        assert!(matches!(outcome, EnrolOutcome::Enrolled { .. }));
    }

    /// A host that cannot draw a window must not enrol — the fail-closed default the whole confirm seam
    /// is built on.
    #[test]
    fn a_host_with_no_window_enrols_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let (outcome, _) = run_enrolment(dir.path(), &[Act::NoWindow]);

        assert_eq!(outcome, EnrolOutcome::Unavailable);
        assert!(!vault(dir.path()).is_enrolled());
    }

    /// Re-running setup on an enrolled account is refused rather than silently issuing a new key — that
    /// would invalidate the recovery codes the user is holding without telling them.
    #[test]
    fn setup_will_not_silently_replace_an_existing_enrolment() {
        let dir = tempfile::tempdir().unwrap();
        run_enrolment(dir.path(), &happy_path());

        let (outcome, _) = run_enrolment(dir.path(), &[]);
        assert_eq!(outcome, EnrolOutcome::AlreadyEnrolled);
    }

    /// The threat model must be STATED, and must not be overstated. The explainer has to say what this
    /// does not protect against, and must not promise safety from a compromised machine.
    #[test]
    fn the_explainer_states_the_limit_rather_than_overselling() {
        let dir = tempfile::tempdir().unwrap();
        let (_, confirmer) = run_enrolment(dir.path(), &happy_path());
        let shown = confirmer.transcript();

        assert!(
            shown.contains("does NOT stop"),
            "the limit must be stated in the user's words"
        );
        assert!(
            shown.contains("fully taken over this computer"),
            "the case it does not cover must be named"
        );
        assert!(
            shown.contains("not a wall"),
            "the copy must not read as a guarantee"
        );
        assert!(
            shown.contains("somewhere else"),
            "the honest justification — another device — must be given"
        );
    }

    /// The recovery codes must actually be shown, and shown with the warning that this is the only
    /// time. A flow that generated codes and never displayed them would pass every other test here.
    #[test]
    fn the_recovery_codes_are_shown_once_with_their_warning() {
        let dir = tempfile::tempdir().unwrap();
        let (_, confirmer) = run_enrolment(dir.path(), &happy_path());
        let shown = confirmer.transcript();

        assert!(shown.contains("only time they will be shown"));
        assert!(shown.contains("works ONCE"));
        // Ten dashed codes, whatever line they were paired onto: the count is what matters, and
        // asserting on the LINE shape would break the moment the block is re-laid-out to fit the window.
        let codes = shown
            .split_whitespace()
            .filter(|token| {
                token.len() == 11
                    && token.chars().nth(5) == Some('-')
                    && token
                        .chars()
                        .filter(|c| *c != '-')
                        .all(|c| c.is_ascii_alphanumeric())
            })
            .count();
        assert_eq!(codes, super::super::recovery_codes::CODE_COUNT);
    }

    /// **No heading may overrun the window that draws it.** A `STATIC` clips silently, so an over-long
    /// heading is invisible to every other test and visible only in a screenshot — which is how the
    /// recovery-code window shipped its first build with its warning cut in half.
    ///
    /// Driven across the WHOLE feature (enrolment, a challenge, a spent-code notice) rather than one
    /// screen, because the failure is per-string: checking one heading proves nothing about the next
    /// one someone writes.
    #[test]
    fn every_heading_fits_the_window_that_draws_it() {
        let dir = tempfile::tempdir().unwrap();
        let (_, enrolling) = run_enrolment(dir.path(), &happy_path());

        let challenging = ScriptedConfirmer::new(NOW, &[Act::Type("000000".into())]);
        challenge(
            &challenging,
            &vault(dir.path()),
            // The longest purpose any caller passes, so the heading is measured at its worst case
            // rather than at a convenient one.
            "replace this account",
            &FixedClock(NOW),
        );
        report_recovery_code_spent(&challenging, 0);

        for confirmer in [&enrolling, &challenging] {
            for heading in confirmer.headings.lock().unwrap().iter() {
                assert!(
                    heading.chars().count() <= MAX_HEADING_CHARS,
                    "heading is {} characters and will be clipped: {heading:?}",
                    heading.chars().count()
                );
            }
        }
    }

    // ---- Challenge ----

    /// Enrol a vault directly (no windows) and return the secret and codes the user holds.
    fn enrolled(dir: &Path) -> (TotpSecret, RecoveryCodeSet) {
        let secret = TotpSecret::generate();
        let codes = RecoveryCodeSet::generate();
        vault(dir).enrol(&secret, &codes).unwrap();
        (secret, codes)
    }

    #[test]
    fn a_challenge_passes_on_the_current_code_and_fails_on_a_wrong_one() {
        let dir = tempfile::tempdir().unwrap();
        let (secret, _) = enrolled(dir.path());
        let code = secret.code_at(NOW).to_string();

        for (typed, expected) in [
            (code.as_str(), ChallengeVerdict::Passed),
            ("000000", ChallengeVerdict::Failed),
        ] {
            let confirmer = ScriptedConfirmer::new(NOW, &[Act::Type(typed.to_string())]);
            assert_eq!(
                challenge(
                    &confirmer,
                    &vault(dir.path()),
                    "do the thing",
                    &FixedClock(NOW)
                ),
                expected
            );
        }
    }

    /// The lost-phone path through the real journey, not just the vault: a recovery code passes the
    /// challenge and reports how many are left.
    #[test]
    fn a_recovery_code_passes_a_challenge_without_the_phone() {
        let dir = tempfile::tempdir().unwrap();
        let (_, codes) = enrolled(dir.path());
        let confirmer = ScriptedConfirmer::new(NOW, &[Act::Type(codes.code(0).to_string())]);

        assert_eq!(
            challenge(
                &confirmer,
                &vault(dir.path()),
                "do the thing",
                &FixedClock(NOW)
            ),
            ChallengeVerdict::PassedWithRecoveryCode {
                remaining: super::super::recovery_codes::CODE_COUNT - 1
            }
        );
    }

    /// Closing the code window must NOT pass. `Cancelled` is kept distinct from `Failed` because the
    /// caller says different things about them, but neither may proceed.
    #[test]
    fn cancelling_the_code_window_does_not_pass() {
        let dir = tempfile::tempdir().unwrap();
        enrolled(dir.path());
        let confirmer = ScriptedConfirmer::new(NOW, &[Act::CancelInput]);

        assert_eq!(
            challenge(
                &confirmer,
                &vault(dir.path()),
                "do the thing",
                &FixedClock(NOW)
            ),
            ChallengeVerdict::Cancelled
        );
    }

    /// A vault throttled by too many failed attempts reports `RateLimited` through the journey, not a
    /// plain `Failed` — the window must be able to tell the user to WAIT rather than to keep typing
    /// codes that will be refused unread (dig_ecosystem#1847). The throttle is armed through fresh vault
    /// handles, mirroring the window being closed and reopened between guesses.
    #[test]
    fn a_throttled_vault_reports_rate_limited_through_the_journey() {
        let dir = tempfile::tempdir().unwrap();
        enrolled(dir.path());
        // Six consecutive wrong answers is comfortably past any sane free budget.
        for _ in 0..6 {
            let _ = vault(dir.path()).challenge("000000", NOW);
        }

        let confirmer = ScriptedConfirmer::new(NOW, &[Act::Type("000000".into())]);
        assert!(matches!(
            challenge(
                &confirmer,
                &vault(dir.path()),
                "do the thing",
                &FixedClock(NOW)
            ),
            ChallengeVerdict::RateLimited { .. }
        ));
    }

    /// A throttled account is told to WAIT before the code-input window is ever drawn
    /// (dig_ecosystem#1970) — the point of the pre-check is that a rate-limited user does not type a
    /// full code first.
    ///
    /// # Why the verdict alone cannot see the fix
    ///
    /// A live-looking code IS queued, so WITHOUT the pre-check `request_input` would be called (drawing
    /// the window and recording its body) and the post-judge path would STILL return `RateLimited` —
    /// the verdict is identical either way. The load-bearing assertion is therefore that no window was
    /// drawn: `transcript()` stays empty only because `request_input` was never reached. Revert the
    /// pre-check and this test fails on the non-empty transcript, not the verdict.
    #[test]
    fn a_throttled_account_is_told_to_wait_before_the_code_window_is_drawn() {
        let dir = tempfile::tempdir().unwrap();
        enrolled(dir.path());
        // Six consecutive wrong answers is comfortably past the free budget; fresh handles each time
        // mirror the window being closed and reopened between guesses.
        for _ in 0..6 {
            let _ = vault(dir.path()).challenge("000000", NOW);
        }

        let confirmer = ScriptedConfirmer::new(NOW, &[Act::Type("000000".into())]);
        let verdict = challenge(
            &confirmer,
            &vault(dir.path()),
            "do the thing",
            &FixedClock(NOW),
        );

        assert!(matches!(verdict, ChallengeVerdict::RateLimited { .. }));
        assert!(
            confirmer.transcript().is_empty(),
            "a throttled account must not be shown the code-input window"
        );
    }

    /// The control for the test above: a healthy (un-throttled) account IS prompted normally, so the
    /// pre-check gates only on a real throttle and never suppresses the window wholesale.
    #[test]
    fn a_healthy_account_is_still_shown_the_code_window() {
        let dir = tempfile::tempdir().unwrap();
        let (secret, _) = enrolled(dir.path());
        let confirmer = ScriptedConfirmer::new(NOW, &[Act::Type(secret.code_at(NOW).to_string())]);

        assert_eq!(
            challenge(
                &confirmer,
                &vault(dir.path()),
                "do the thing",
                &FixedClock(NOW)
            ),
            ChallengeVerdict::Passed
        );
        assert!(
            !confirmer.transcript().is_empty(),
            "an un-throttled account must be shown the code window"
        );
    }

    /// The pre-check is a pure read: peeking at the throttle through the journey must not reset,
    /// shorten, or otherwise consume it — a subsequent real attempt is still throttled.
    #[test]
    fn peeking_at_the_throttle_does_not_reset_it() {
        let dir = tempfile::tempdir().unwrap();
        enrolled(dir.path());
        for _ in 0..6 {
            let _ = vault(dir.path()).challenge("000000", NOW);
        }

        // Drive the journey pre-check (no window is drawn, so an empty script is never popped)...
        let confirmer = ScriptedConfirmer::new(NOW, &[]);
        let _ = challenge(
            &confirmer,
            &vault(dir.path()),
            "do the thing",
            &FixedClock(NOW),
        );

        // ...and the throttle is untouched: the vault still turns a real attempt away.
        assert!(matches!(
            vault(dir.path()).challenge("000000", NOW),
            Ok(ChallengeOutcome::RateLimited { .. })
        ));
    }

    /// An account with no second factor reports `NotEnrolled` rather than a silent pass, so a caller
    /// cannot mistake "there was no factor" for "the factor was satisfied".
    #[test]
    fn an_unenrolled_account_reports_not_enrolled_rather_than_passing() {
        let dir = tempfile::tempdir().unwrap();
        let confirmer = ScriptedConfirmer::new(NOW, &[]);

        assert_eq!(
            challenge(
                &confirmer,
                &vault(dir.path()),
                "do the thing",
                &FixedClock(NOW)
            ),
            ChallengeVerdict::NotEnrolled
        );
    }

    /// A host that cannot draw the code window fails closed.
    #[test]
    fn a_challenge_with_no_window_is_unavailable() {
        let dir = tempfile::tempdir().unwrap();
        enrolled(dir.path());
        let confirmer = ScriptedConfirmer::new(NOW, &[Act::NoWindow]);

        assert_eq!(
            challenge(
                &confirmer,
                &vault(dir.path()),
                "do the thing",
                &FixedClock(NOW)
            ),
            ChallengeVerdict::Unavailable
        );
    }

    // ---- Disable ----

    /// Turning it off requires the authorization to be GRANTED, and a refusal leaves it on. The refusal
    /// case is the load-bearing one — a disable that ignored the verdict would satisfy the first
    /// assertion alone.
    #[test]
    fn disabling_requires_authorization_and_a_refusal_leaves_it_on() {
        for (decision, expected, still_on) in [
            (ConfirmDecision::Approve, DisableOutcome::Disabled, false),
            (ConfirmDecision::Deny, DisableOutcome::Refused, true),
            (ConfirmDecision::Unavailable, DisableOutcome::Refused, true),
        ] {
            let dir = tempfile::tempdir().unwrap();
            enrolled(dir.path());
            let confirmer = ScriptedConfirmer::new(NOW, &[Act::Decide(decision)]);

            assert_eq!(disable(&confirmer, &vault(dir.path())), expected);
            assert_eq!(
                vault(dir.path()).is_enrolled(),
                still_on,
                "after {decision:?} the enrolment should {}",
                match still_on {
                    true => "survive",
                    false => "be gone",
                }
            );
        }
    }

    /// Disabling what is not enrolled says so rather than reporting a success that did nothing.
    #[test]
    fn disabling_nothing_reports_nothing_to_disable() {
        let dir = tempfile::tempdir().unwrap();
        let confirmer = ScriptedConfirmer::new(NOW, &[]);

        assert_eq!(
            disable(&confirmer, &vault(dir.path())),
            DisableOutcome::NotEnrolled
        );
    }

    /// The disable window must name what is GIVEN UP, not merely ask a yes/no question.
    #[test]
    fn the_disable_window_states_what_is_lost() {
        let dir = tempfile::tempdir().unwrap();
        enrolled(dir.path());
        let confirmer = ScriptedConfirmer::new(NOW, &[Act::Decide(ConfirmDecision::Deny)]);
        disable(&confirmer, &vault(dir.path()));

        let shown = confirmer.transcript();
        assert!(shown.contains("no longer ask for a code"));
        assert!(shown.contains("recovery codes stop working"));
    }

    /// Spending the LAST recovery code must be reported differently from spending one of several —
    /// running out is the moment a person needs to act, and a single message for both would bury it.
    #[test]
    fn running_out_of_recovery_codes_is_reported_differently() {
        for (remaining, expected) in [
            (0usize, "LAST recovery code"),
            (3, "3 recovery code(s) left"),
        ] {
            let confirmer = ScriptedConfirmer::new(NOW, &[]);
            report_recovery_code_spent(&confirmer, remaining);
            assert!(
                confirmer.transcript().contains(expected),
                "with {remaining} left the user must be told {expected:?}"
            );
        }
    }
}
