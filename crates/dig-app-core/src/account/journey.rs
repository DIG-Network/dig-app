//! The user-facing account **journeys** — the flows the tray menu triggers (dig_ecosystem#1752).
//!
//! The pieces underneath are deliberately narrow: [`recovery`](crate::account::recovery) knows words and
//! seeds, [`lifecycle`](crate::account::lifecycle) knows enrolment, [`phrase_vault`](crate::account::phrase_vault)
//! knows at-rest, and [`confirm`](crate::confirm) knows how to draw an OS-owned window. This module is
//! the only place that knows the ORDER those happen in for a human, which is where the safety rules live:
//!
//! - **Setup shows the words, then asks twice.** One acknowledgement is a reflex; the second screen is
//!   what makes "I have written these down" an actual claim. Either refusal abandons setup, and
//!   [`open_or_enroll`](crate::account::lifecycle::open_or_enroll) then leaves nothing enrolled.
//! - **A re-reveal is gated like a signature.** [`reveal_phrase`] asks the OS to re-authenticate the
//!   human (`confirm_reveal`) BEFORE the vault is even opened, so a passer-by at an unlocked machine
//!   cannot read the account off a tray menu.
//! - **Nothing here logs, returns, or persists the words.** They travel from the vault to the window and
//!   are dropped; the functions return an outcome, never a phrase.

use crate::account::boot::{
    DiscardOutcome, EnrolFailure, UnlockFailure, ENROLLED_BUT_LOCKED_NOTICE,
};
use crate::account::lifecycle::{PhrasePresenter, RetentionDecision};
use crate::account::phrase_vault::PhraseVault;
use crate::account::profile_mint::ChainReadiness;
use crate::account::recovery::RecoveryPhrase;
use crate::confirm::{
    ClaimPrompt, ConfirmDecision, DestroyPrompt, InputOutcome, InputPrompt, InputStyle,
    NativeConfirmer, NoticePrompt, QrArt, RevealPrompt,
};
use crate::sealer::ProfileSealer;
use zeroize::Zeroizing;

/// How the user's own phrase is described to them, in one place so setup and reveal agree.
const PHRASE_NAME: &str = "your 24-word DIG recovery phrase";

/// What happened when the user asked to see their recovery phrase.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RevealOutcome {
    /// The words were shown.
    Shown,
    /// The user (or the OS authenticator) refused, or no confirm surface exists. Nothing was read.
    Refused,
    /// This account has no stored phrase — it was enrolled before recovery phrases existed and cannot
    /// be recovered from words. The tray offers the remedy rather than pretending otherwise.
    NoPhraseStored,
    /// The vault could not be opened (the account locked, or the file is damaged).
    Unavailable,
}

/// The production [`PhrasePresenter`]: draws a fresh phrase in an OS-owned window and takes the user's
/// retention claim.
///
/// Borrowed rather than owned because the shell already holds the one process-wide confirmer.
pub struct WindowedPresenter<'a> {
    confirmer: &'a dyn NativeConfirmer,
}

impl<'a> WindowedPresenter<'a> {
    /// Present through `confirmer` (in production, [`native_confirmer`](crate::confirm::native_confirmer)).
    pub fn new(confirmer: &'a dyn NativeConfirmer) -> Self {
        Self { confirmer }
    }
}

impl PhrasePresenter for WindowedPresenter<'_> {
    fn present_new_phrase(&self, phrase: &RecoveryPhrase) -> RetentionDecision {
        let words = phrase.numbered_lines();
        let body = format!(
            "{}\nThese words ARE your DIG Account. Anyone who has them can take it, and \
             nobody — including DIG — can recover your account without them.",
            *words
        );
        // Both enrolment screens are CLAIMS, not notices: backing out of either abandons setup, so the
        // declining choice is load-bearing and must be offered as a real, labelled way out
        // (dig_ecosystem#1773 — this is the one place a two-button window is correct in this flow).
        // Each claim is built by a named function so its `refusal_is_default` can be asserted directly
        // rather than being an inline literal a test cannot reach (dig_ecosystem#2098).
        let shown = self
            .confirmer
            .confirm_claim(&phrase_written_down_claim(&body));
        if shown != ConfirmDecision::Approve {
            return decision_for(shown);
        }

        let confirmed = self
            .confirmer
            .confirm_claim(&phrase_saved_confirmation_claim());
        decision_for(confirmed)
    }
}

/// The first enrolment screen: the 24 words themselves, with the claim "I have written these down".
///
/// Named rather than written inline so its `refusal_is_default` is reachable from a test — flipping it
/// must fail a named assertion, not leave the suite green (dig_ecosystem#2098). The `body` carries the
/// numbered words, so it is passed in rather than built here.
fn phrase_written_down_claim(body: &str) -> ClaimPrompt<'_> {
    ClaimPrompt {
        title: "DIG — Your recovery phrase",
        heading: "Write these 24 words down, in order, and keep them somewhere safe.",
        body,
        affirm: "I have written these down",
        decline: None,
        // An assertion about the world, and affirming it costs the account: a reflexive Enter
        // would record that a seed is safely written down for somebody holding nothing.
        refusal_is_default: true,
        scannable: None,
        identifier: None,
    }
}

/// The second enrolment screen: confirm the words are saved SOMEWHERE OTHER than this screen.
///
/// Named for the same reason as [`phrase_written_down_claim`] — the `refusal_is_default` guard is what
/// makes a reflexive Enter stop and check rather than affirm (dig_ecosystem#2098).
fn phrase_saved_confirmation_claim() -> ClaimPrompt<'static> {
    ClaimPrompt {
        title: "DIG — Confirm you saved it",
        heading: "Do you have your 24 words written down somewhere safe?",
        body: "If you continue without them and later lose this computer, your DIG Account, its \
               address and everything sealed under it are gone for good. You can view the words \
               again later from the DIG tray menu.",
        affirm: "Yes, I have them",
        decline: None,
        // This screen exists precisely to make the user stop and check, so a bare Enter refuses.
        refusal_is_default: true,
        scannable: None,
        identifier: None,
    }
}

/// Map a notice outcome onto a retention ruling. A dismissal is a decline; anything the OS could not
/// show is [`RetentionDecision::Unavailable`], which refuses to enrol at all.
fn decision_for(decision: ConfirmDecision) -> RetentionDecision {
    match decision {
        ConfirmDecision::Approve => RetentionDecision::Confirmed,
        ConfirmDecision::Deny => RetentionDecision::Declined,
        ConfirmDecision::Timeout | ConfirmDecision::Unavailable => RetentionDecision::Unavailable,
    }
}

/// Show the account's stored recovery phrase again, behind an OS re-authentication.
///
/// The order is load-bearing and is what this function exists to guarantee: the confirm runs FIRST, so a
/// refusal means the vault was never opened and the words were never decrypted — not merely that they
/// were decrypted and then not displayed.
pub fn reveal_phrase<S: ProfileSealer>(
    confirmer: &dyn NativeConfirmer,
    vault: &PhraseVault<S>,
) -> RevealOutcome {
    if confirmer.confirm_reveal(&RevealPrompt {
        secret: PHRASE_NAME,
    }) != ConfirmDecision::Approve
    {
        return RevealOutcome::Refused;
    }

    let phrase = match open_vault(vault, "could not open the recovery-phrase vault") {
        PhraseLookup::Found(phrase) => phrase,
        PhraseLookup::Missing => return RevealOutcome::NoPhraseStored,
        PhraseLookup::Unavailable => return RevealOutcome::Unavailable,
    };

    let words = phrase.numbered_lines();
    match confirmer.show_notice(&NoticePrompt {
        title: "DIG — Your recovery phrase",
        heading: "These 24 words are your DIG Account. Keep them secret.",
        body: &words,
        acknowledge: "Done",
        identifier: None,
    }) {
        ConfirmDecision::Approve | ConfirmDecision::Deny => RevealOutcome::Shown,
        // The window itself could not be drawn, so nothing reached the screen.
        ConfirmDecision::Timeout | ConfirmDecision::Unavailable => RevealOutcome::Unavailable,
    }
}

/// The three ways opening the phrase vault can end, before a ceremony maps them onto its own outcome.
///
/// The reveal and backup egress paths are DISTINCT ceremonies — one warns first, the other does not —
/// but they read the vault identically: a stored phrase, a legacy account with none, or an unopenable
/// vault. Naming the three cases once, here, is what keeps the two paths from drifting on which one
/// means "no phrase" versus "unavailable". It deliberately does NOT merge the ceremonies themselves.
enum PhraseLookup {
    /// A phrase was stored and decrypted.
    Found(RecoveryPhrase),
    /// The account is legacy — no phrase was ever stored.
    Missing,
    /// The vault could not be opened (locked or damaged); the reason has been logged.
    Unavailable,
}

/// Open `vault`, logging an open failure under `context`, and report which of the three cases occurred.
///
/// Shared by [`reveal_phrase`] and [`back_up_phrase`] so the `load()` mapping lives in one place; each
/// caller supplies its own log context and maps the result onto its own outcome enum.
fn open_vault<S: ProfileSealer>(vault: &PhraseVault<S>, context: &str) -> PhraseLookup {
    match vault.load() {
        Ok(Some(phrase)) => PhraseLookup::Found(phrase),
        Ok(None) => PhraseLookup::Missing,
        Err(e) => {
            tracing::warn!(error = %e, "{context}");
            PhraseLookup::Unavailable
        }
    }
}

/// Where a backup of the recovery phrase is being sent (dig_ecosystem#1564).
///
/// Chosen as a type rather than a boolean so the STARK unencrypted-storage warning and the confirmation
/// wording for each destination are decided in one place, and a caller cannot ask for "both" — each
/// backup targets exactly one place the user then has to look after.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BackupTarget {
    /// The OS clipboard — plaintext, until the next copy replaces it.
    Clipboard,
    /// A plain `.txt` file on disk — plaintext, until the user deletes it.
    File,
}

/// What a backup attempt did (dig_ecosystem#1564). Every variant states whether the words left the
/// vault, because that is the only fact a caller — or a reader — needs from this flow.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BackupOutcome {
    /// The words reached the destination. **This is the one variant where the phrase left the vault.**
    BackedUp,
    /// The user declined the stark warning or the reveal gate, or cancelled the destination (e.g. a save
    /// dialog). **Nothing was decrypted or delivered on a refusal before the gate; nothing was delivered
    /// on a cancel after it.**
    Refused,
    /// This account has no stored phrase (a legacy account) — there is nothing to back up.
    NoPhraseStored,
    /// The vault could not be opened, no window could be drawn, or the destination write failed.
    Unavailable,
}

/// The untestable egress a backup ends in — putting plaintext on the clipboard or writing it to a file.
///
/// A seam, for the same reason the destructive verbs have [`AccountCustodian`]: the ORDER that guards the
/// words (warn, then authorize, then decrypt, then deliver) is the security property, and it lives in the
/// library where a test can drive it against a recording double. The platform specifics — which clipboard
/// utility, which file path, which permissions — are behind this one method, implemented by the shell.
pub trait PhraseBackupSink {
    /// Deliver `words` (the space-joined 24-word phrase) to `target`. Called ONLY after the warning and
    /// the reveal gate have both been approved and the phrase has been decrypted — never speculatively.
    ///
    /// The implementation MUST NOT log, copy, or otherwise retain `words` beyond the delivery itself.
    fn deliver(&self, target: BackupTarget, words: &str) -> BackupDelivery;
}

/// What a [`PhraseBackupSink`] did with the words.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BackupDelivery {
    /// Delivered. `where_to` names the destination for the confirmation window (e.g. `"your clipboard"`
    /// or the file's path), so the user knows exactly where the plaintext now sits.
    Delivered {
        /// A human phrase naming where the words went, shown back to the user.
        where_to: String,
    },
    /// The user cancelled at the destination itself (a save dialog dismissed). Nothing was written.
    Cancelled,
    /// The destination write failed (no clipboard utility, an unwritable path).
    Failed,
}

/// Back up the account's recovery phrase to the clipboard or a file, behind the SAME gate as a reveal
/// and behind a stark, explicit unencrypted-storage warning (dig_ecosystem#1564).
///
/// # The order, which is the whole point
///
/// 1. **Warn first.** A copy-to-clipboard or save-to-file puts the entire account, in plaintext, somewhere
///    another program or person can read it. So the user is told exactly that — naming the destination —
///    and must approve it BEFORE anything is decrypted. A refusal here decrypts nothing.
/// 2. **Authorize like a reveal.** The words are then gated on a fresh OS re-authentication
///    ([`RevealPrompt`]/`confirm_reveal`), identically to [`reveal_phrase`], because backing up hands over
///    the whole account exactly as showing it does. A refusal here decrypts nothing either.
/// 3. **Only then decrypt and deliver.** The vault is opened after both approvals, and the words are
///    handed to the [`PhraseBackupSink`] in a zeroizing buffer that is wiped the moment this returns.
///
/// Returns [`BackupOutcome::Refused`] for any non-approval and never delivers the words on one, so the
/// fail-closed direction is the default rather than a branch a caller must remember.
pub fn back_up_phrase<S: ProfileSealer>(
    confirmer: &dyn NativeConfirmer,
    vault: &PhraseVault<S>,
    target: BackupTarget,
    sink: &dyn PhraseBackupSink,
) -> BackupOutcome {
    // 1. The stark warning, BEFORE any decryption. Refusing it must leave the vault unopened, which is
    // why it is placed ahead of both the gate and the load.
    if confirmer.confirm_claim(&backup_warning(target)) != ConfirmDecision::Approve {
        return BackupOutcome::Refused;
    }

    // 2. The reveal gate — the identical authorization `reveal_phrase` runs, and for the identical
    // reason: this hands over the whole account. Still before the load, so a refusal never decrypts.
    if confirmer.confirm_reveal(&RevealPrompt {
        secret: PHRASE_NAME,
    }) != ConfirmDecision::Approve
    {
        return BackupOutcome::Refused;
    }

    // 3. Decrypt, then deliver. Nothing above this line has touched the ciphertext.
    let phrase = match open_vault(vault, "could not open the recovery-phrase vault for backup") {
        PhraseLookup::Found(phrase) => phrase,
        PhraseLookup::Missing => return BackupOutcome::NoPhraseStored,
        PhraseLookup::Unavailable => return BackupOutcome::Unavailable,
    };

    // The words live only in this zeroizing buffer for the length of the delivery, then are wiped. The
    // sink is contractually forbidden from retaining them (see [`PhraseBackupSink::deliver`]).
    let words = Zeroizing::new(phrase.words().join(" "));
    match sink.deliver(target, &words) {
        BackupDelivery::Delivered { where_to } => {
            notify(
                confirmer,
                "DIG — Recovery phrase backed up",
                "Your 24 words have been backed up.",
                &format!(
                    "They are now in {where_to}, in plain text. Anyone who can read that can take your \
                     DIG Account, so move them somewhere safe and remove this copy when you are done.",
                ),
            );
            BackupOutcome::BackedUp
        }
        // A cancel at the destination is the user's choice, and the words never left — treat it exactly
        // like refusing the warning.
        BackupDelivery::Cancelled => BackupOutcome::Refused,
        BackupDelivery::Failed => {
            notify(
                confirmer,
                "DIG — Backup did not complete",
                "Your recovery phrase could not be backed up.",
                "Your account is fine and nothing was changed. You can still view your words from the \
                 DIG menu and write them down. The log folder (in this menu) has the details.",
            );
            BackupOutcome::Unavailable
        }
    }
}

/// The stark, destination-specific warning shown before a backup decrypts anything.
///
/// A CLAIM, not a notice: refusing it genuinely stops the backup, so the negative choice is load-bearing
/// and must be a real, labelled way out. The copy names the concrete unencrypted-storage risk of the
/// chosen destination in the user's own terms — a clipboard the next copy overwrites but any app can read
/// until then, or a file that persists until it is deleted.
fn backup_warning(target: BackupTarget) -> ClaimPrompt<'static> {
    match target {
        BackupTarget::Clipboard => ClaimPrompt {
            title: "DIG — Copy your recovery phrase",
            heading: "This puts your 24 words on the clipboard in PLAIN TEXT.",
            // The "about 45 seconds" mirrors `CLIPBOARD_CLEAR_DELAY` in the dig-app shell, which owns
            // the timer (dig_ecosystem#1964). The wording is deliberately hedged — "usually", "may still
            // retain" — because the clear is best-effort: it only fires if the clipboard still holds our
            // copy, and clipboard history/sync can keep a copy the clear cannot reach.
            body: "Until you copy something else, any app or person with access to this computer's \
                   clipboard can read them — and anyone who has your 24 words can take your DIG Account. \
                   DIG will usually clear them from the clipboard automatically after about 45 seconds, \
                   but clipboard history or sync services may still retain a copy. Only do this to move \
                   them somewhere safe, and copy something else afterwards to clear them sooner.",
            affirm: "I understand — copy my phrase",
            decline: None,
            // Affirming puts the 24 words on the clipboard in plain text. Enter must not.
            refusal_is_default: true,
            scannable: None,
        identifier: None,
        },
        BackupTarget::File => ClaimPrompt {
            title: "DIG — Save your recovery phrase",
            heading: "This saves your 24 words to a plain, UNENCRYPTED file.",
            body: "Anyone who can read that file — including backup software, sync services and anyone \
                   who uses this computer — can take your DIG Account. Save it only somewhere you \
                   control, and delete it once your words are somewhere safe.",
            affirm: "I understand — save my phrase",
            decline: None,
            // Affirming writes the 24 words to an unencrypted file. Enter must not.
            refusal_is_default: true,
            scannable: None,
        identifier: None,
        },
    }
}

/// What a phrase-less (legacy) account is told.
///
/// This function ONLY informs — it changes nothing. What it must do, and what it failed to do before
/// dig_ecosystem#1800, is name a remedy the user can actually reach: it used to explain that the only fix
/// was a new account while every control that could create one was greyed out, which is a dead end dressed
/// as advice. The copy now names the exact menu path, and the menu really offers it.
pub fn explain_missing_phrase(confirmer: &dyn NativeConfirmer) -> ConfirmDecision {
    confirmer.show_notice(&NoticePrompt {
        title: "DIG — No recovery phrase",
        heading: "This DIG Account has no recovery phrase.",
        body: "It was created before DIG had recovery phrases, so its key exists only on this \
               computer: if you lose this machine, the account, its address and everything sealed \
               under it cannot be recovered — not by you and not by DIG.\n\n\
               Words cannot be added to an existing account. To get a recoverable account, replace \
               this one: in the DIG menu choose \"Manage Account\" then \"Replace this account \
               with a NEW one…\". You will be shown 24 words to write down, and you will get a NEW \
               identity and address — this account's data stays sealed to its old key and becomes \
               unreadable.\n\n\
               Nothing has changed yet. Your account still works exactly as before.",
        acknowledge: "I understand",
        identifier: None,
    })
}

/// What the user asked a destructive account verb to do — and, for a replace, what comes after.
///
/// A type rather than a pair of booleans so a caller cannot express "remove it and then restore from a
/// phrase", which is not a thing, and so the warning copy for each is chosen in one place.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Replacement {
    /// Discard this account and enrol a brand-new one, with a fresh recovery phrase.
    WithNewAccount,
    /// Discard this account and enrol the one the user's typed recovery phrase describes.
    FromPhrase,
    /// Discard this account and leave the host with none.
    Nothing,
}

impl Replacement {
    /// What the destroy window tells the user happens after the account is gone.
    fn promise(self) -> &'static str {
        match self {
            Self::WithNewAccount => {
                "A brand-new DIG Account will be created in its place, with a new recovery phrase, a \
                 new identity and a new address."
            }
            Self::FromPhrase => {
                "The account your recovery phrase describes will be set up in its place. Check the \
                 words are the right ones before you continue — a different phrase gives a different, \
                 empty account."
            }
            Self::Nothing => {
                "This computer will be left with no DIG Account. You can set one up again, or restore \
                 one, from the DIG menu at any time."
            }
        }
    }
}

/// The user's answer to a destructive account verb, BEFORE anything is destroyed.
///
/// Returned rather than acted on so the decision and the destruction stay separable — which is what lets
/// the placement rule ("nothing is destroyed until this says [`Authorized`](Self::Authorized)") be tested
/// without a real keystore.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DestroyRuling {
    /// The user saw exactly what is lost and re-authenticated. The caller may destroy.
    Authorized,
    /// The user declined, or the OS could not authorize. **Nothing may be destroyed.**
    Refused,
}

/// Put a destructive account verb to the user, offering to show their recovery phrase first.
///
/// # The order, which is the whole point
///
/// 1. **Offer the phrase first.** The commonest reason a replace goes wrong is a user who believes they
///    have their words and does not. Offering the reveal BEFORE the destroy — through the ordinary
///    [`reveal_phrase`] gate, so it is authorized and audited exactly as it always is — is the cheapest
///    possible way to turn that mistake into a non-event. Skipped when the account has no phrase to show.
/// 2. **Then authorize the destruction**, through [`confirm_destroy`](NativeConfirmer::confirm_destroy):
///    a foreground window naming the irreversible loss, then an OS re-authentication. Never a notice
///    (one button, no decision) and never a claim (two buttons, no biometric) — a passer-by at an
///    unlocked machine must not be able to destroy an account by clicking twice.
///
/// Returns [`DestroyRuling::Refused`] for anything other than an explicit, authenticated approval, so the
/// fail-closed direction is the default rather than a branch a caller has to remember.
pub fn authorize_destroy<S: ProfileSealer>(
    confirmer: &dyn NativeConfirmer,
    what: Replacement,
    vault: Option<&PhraseVault<S>>,
) -> DestroyRuling {
    let recoverable = vault.is_some_and(|vault| vault.is_recoverable());
    if recoverable {
        offer_a_last_look(confirmer, vault);
    }

    let approved = confirmer.confirm_destroy(&DestroyPrompt {
        subject: "the DIG Account on this computer",
        replacement: what.promise(),
        recoverable,
    });
    match approved {
        ConfirmDecision::Approve => DestroyRuling::Authorized,
        _ => DestroyRuling::Refused,
    }
}

/// What a destructive account verb may do on a LOCKED account whose second factor cannot be judged
/// (dig-app#349).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LockedFactorRuling {
    /// Proceed. The verb destroys the account outright, and the discard takes the second-factor
    /// enrolment with it — so it cannot leave a de-gated account behind.
    BreakGlass,
    /// The user was offered the break glass and declined. They already know what they chose, so the
    /// caller says nothing further.
    Declined,
    /// This verb is not available while the account is locked. The caller must name the remedy.
    NotAvailableWhileLocked,
}

/// Rule on a destructive verb for a LOCKED account that has a second factor nothing can verify
/// (dig-app#349).
///
/// # The rule: the biometric alone may DESTROY, never DE-GATE
///
/// A locked account has no DEK, so no code, recovery code or assertion it holds can be checked — the
/// only authorization available is the platform biometric, which is exactly the credential the second
/// factor exists to stop being sufficient. Refusing everything would be safe and would also brick the
/// account: with a lost password and a factor enrolled, the challenge already fails closed, so nothing
/// could ever remove the account from the machine. That is the trap §6.1 forbids.
///
/// The line drawn here is between the two things a destructive verb can leave behind:
///
/// - **Removing** the account destroys the seed AND, through
///   [`discard_sealed_vaults`](super::boot::discard_account), the enrolment — together, and only after
///   the seed has actually gone. An attacker gains nothing they can return and use, and the owner finds
///   out immediately. This is offered.
/// - **Replacing** it leaves a working account on the machine with the gate gone. That is de-gating
///   with extra steps, and it is worse than destruction precisely because it is SILENT: the owner is
///   left with something that looks healthy and is no longer protected. This is refused.
///
/// The claim is drawn before [`authorize_destroy`]'s own window rather than instead of it, so the
/// break glass is TWO deliberate acts — this one naming what makes it different, then the ordinary
/// destroy window and its OS re-authentication. `refusal_is_default` is set, because a reflexive Enter
/// must never destroy an account.
pub fn authorize_locked_break_glass(
    confirmer: &dyn NativeConfirmer,
    what: Replacement,
) -> LockedFactorRuling {
    if what != Replacement::Nothing {
        return LockedFactorRuling::NotAvailableWhileLocked;
    }
    match confirmer.confirm_claim(&break_glass_claim()) {
        ConfirmDecision::Approve => LockedFactorRuling::BreakGlass,
        _ => LockedFactorRuling::Declined,
    }
}

/// The break-glass window: what is destroyed, in the order a person cares about.
///
/// It names the two-factor enrolment explicitly. Without that sentence the window would be
/// indistinguishable from an ordinary removal, and the one fact that makes this route acceptable — that
/// the gate dies with the account rather than before it — would be the one fact the user never read.
fn break_glass_claim() -> ClaimPrompt<'static> {
    ClaimPrompt {
        title: "DIG — Remove this account from this computer",
        heading: "This account cannot be opened, so it can only be removed.",
        body: "Two-factor codes are on for this account, and DIG can only check a code while the \
               account is unlocked — so there is no way to turn them off from here, and no way to \
               replace this account with another one.\n\n\
               Removing it is the way out. It destroys, permanently and on this computer only: the \
               sealed master seed, every profile's data, and the two-factor enrolment itself. \
               Your 24 words are the ONLY way to get this account back, anywhere.\n\n\
               If you know the password, close this and choose Unlock instead — nothing is lost that \
               way.",
        affirm: "Remove it permanently",
        decline: None,
        // Affirming destroys an account nothing can recover without the words. Enter must not.
        refusal_is_default: true,
        scannable: None,
        identifier: None,
    }
}

/// Ask whether the user wants to see their words one last time, and show them if so.
///
/// A CLAIM, not a notice: the answer decides whether the reveal runs, so both choices are real. Declining
/// costs nothing and does not abandon the verb — the user may simply already have the words on paper.
fn offer_a_last_look<S: ProfileSealer>(
    confirmer: &dyn NativeConfirmer,
    vault: Option<&PhraseVault<S>>,
) {
    let wants_to_see = confirmer.confirm_claim(&last_look_claim());
    if wants_to_see != ConfirmDecision::Approve {
        return;
    }
    if let Some(vault) = vault {
        // Through the ordinary gate: this is a reveal like any other, so it re-authenticates and warns
        // about the surroundings on its own. A separate, laxer path here would be a way around that gate.
        reveal_phrase(confirmer, vault);
    }
}

/// The pre-destroy last look: offer to show the recovery phrase before the account is destroyed.
///
/// Named for the same reason as the enrolment claims (dig_ecosystem#2098): affirming puts the phrase on
/// screen, so a reflexive Enter must NOT — the `refusal_is_default` guard is reachable from a test here,
/// where an inline literal would not be.
fn last_look_claim() -> ClaimPrompt<'static> {
    ClaimPrompt {
        title: "DIG — Before you destroy this account",
        heading: "Do you want to see this account's recovery phrase first?",
        body: "Once the account is destroyed, these 24 words are the ONLY way to get it back — and \
               only somewhere else, since it will be gone from this computer. If you are not certain \
               you have them written down, look now.",
        affirm: "Show me the words first",
        decline: None,
        // Affirming puts the recovery phrase on screen; declining just carries on.
        refusal_is_default: true,
        scannable: None,
        identifier: None,
    }
}

/// Ask the user for a recovery phrase in a native window and parse it, re-asking on a bad phrase.
///
/// # Why it loops
///
/// A mistyped word is the normal case, not the exceptional one, and a window that closes on the first
/// mistake and leaves the user to find the menu item again is the kind of surface people give up on. So a
/// rejected phrase is re-asked, with the REASON in the window ("that is 23 words, not 24") — and the loop
/// is BOUNDED, so a broken dialog backend cannot spin a window forever.
///
/// Returns `None` when the user cancels, when no input window could be drawn, or when the attempts run
/// out; the caller then changes nothing.
pub fn ask_for_phrase(confirmer: &dyn NativeConfirmer, purpose: &str) -> Option<RecoveryPhrase> {
    let mut problem = String::new();
    for _ in 0..PHRASE_ATTEMPTS {
        let body = format!(
            "{problem}Type or paste all 24 words in order, separated by spaces. Capitals do not \
             matter.\n\n\
             Use the words DIG gave you. A recovery phrase from a Chia wallet such as Sage is NOT a \
             DIG recovery phrase — DIG would accept it and build a DIFFERENT, empty account from it."
        );
        let typed = match confirmer.request_input(&InputPrompt {
            title: "DIG — Recovery phrase",
            heading: purpose,
            body: &body,
            field_label: "Your 24 words:",
            submit: "Continue",
            // Masked by DEFAULT (`SPEC.md` §3.1d): the words already exist on paper, so someone watching
            // the screen is the live risk and a typo costs only a retry. `revealable` is §3.1d's own escape
            // from that rule — 24 words typed entirely blind cannot be checked, so the window offers a
            // deliberate un-mask rather than defaulting to clear text.
            masked: true,
            revealable: true,
            style: InputStyle::Dialog,
        }) {
            InputOutcome::Provided(text) => text,
            // Cancelled or undrawable: either way the user has not supplied a phrase, so stop. Retrying an
            // Unavailable would loop against a backend that cannot draw at all.
            InputOutcome::Cancelled | InputOutcome::Unavailable => return None,
        };

        match RecoveryPhrase::parse(&typed) {
            Ok(phrase) => return Some(phrase),
            Err(why) => problem = format!("That is not a valid DIG recovery phrase: {why}.\n\n"),
        }
    }
    // Out of attempts. Say so rather than closing silently, so the user knows the app heard them.
    confirmer.show_notice(&NoticePrompt {
        title: "DIG — Recovery phrase",
        heading: "Those words were not a valid DIG recovery phrase.",
        body: "Nothing has been changed on this computer. Check the words against what you wrote \
               down — all 24, in the original order — and try again from the DIG menu.",
        acknowledge: "OK",
        identifier: None,
    });
    None
}

/// What a user whose account will not open is told, and where to go (`SPEC.md` §3.1c).
///
/// # Why this window exists
///
/// dig-app USED to auto-enrol `account.default` at first boot on every Windows/macOS host, so real
/// legacy raw-seed blobs exist in the field — one was found on a developer machine. That auto-enrolment
/// is long gone (an account now exists only because a user asked, dig_ecosystem#1820) and no boot path
/// creates one; the blobs it left behind are why this window still has work to do. Reading the old
/// behaviour as current sends an investigation looking for a first-boot enrolment that no longer exists
/// (dig_ecosystem#2128). Such a blob will not
/// unlock under a newer custody model AND cannot re-enrol at the same id, so it is WEDGED, not merely
/// fail-closed. The boot used to reduce that to a `tracing::warn!` and return `None`, which cost the user
/// signing permanently and silently, with no route out.
///
/// This is the route out, and it is the ONLY window an [`Unopenable`](crate::tray_menu::AccountState::Unopenable)
/// account offers — so it carries the whole explanation, the "nothing has been changed or deleted"
/// guarantee, and the exact menu path to the remedy.
///
/// # Why the copy is `concat!` and why it lives here
///
/// `cargo fmt` collapses a `\`-continued literal onto one line and KEEPS the source indentation as real
/// spaces, so a continued body grows multi-space holes in the middle of sentences. That happened to this
/// very window: the rendered text read *"cannot sign anything or&nbsp;&nbsp;… show you its recovery phrase"*
/// with a ten-space gap, in the highest-stakes message in the app. `concat!` cannot be reflowed, so what is
/// written is what renders — and the copy lives in the LIBRARY rather than the tray binary so
/// the `the_unopenable_copy_renders_without_holes` test can actually read it.
pub fn explain_unopenable(confirmer: &dyn NativeConfirmer) -> ConfirmDecision {
    confirmer.show_notice(&NoticePrompt {
        title: "DIG — This account cannot be opened",
        heading: "DIG cannot open the account stored on this computer.",
        body: UNOPENABLE_BODY,
        acknowledge: "I understand",
        identifier: None,
    })
}

/// The body [`explain_unopenable`] shows, as a `const` so a test can render and inspect it.
const UNOPENABLE_BODY: &str = concat!(
    "The account is here, but the key that unlocks it cannot be read, so DIG cannot sign anything or ",
    "show you its recovery phrase. This normally means the account was created by an older version of ",
    "DIG whose format this version can no longer open.\n\n",
    "Nothing has been changed or deleted. The only way forward is to put a different account on this ",
    "computer: in the DIG menu choose \"Manage Account\", then either \"Replace this account with ",
    "a NEW one…\" or, if you have 24 words for an account you want back, \"Replace it with an account ",
    "from a recovery phrase…\".\n\n",
    "If you kept this account's 24 words, restoring from them will bring it back exactly as it was."
);

/// The folder-cannot-hold-an-account paragraph, shared by both post-removal flows.
///
/// A macro rather than a `const` because `concat!` takes literals only, and the copy MUST be `concat!`:
/// `cargo fmt` flattens a `\`-continued literal and keeps its indentation as real spaces, which has
/// already put a twelve-space hole mid-sentence into two shipped messages.
macro_rules! unusable_root_after_removal {
    () => {
        concat!(
            "This computer now has no DIG Account, and trying again will not help until the folder is ",
            "fixed. The folder is either a shortcut or link pointing somewhere else, or it sits ",
            "somewhere that cannot keep it private to you - a network drive, a shared folder mounted in ",
            "from another computer, or an external disk. Give DIG a folder on this computer's own disk, ",
            "or point it at the real folder instead of the link, then set up or restore your account ",
            "from the DIG menu. The log folder (in the DIG menu) names the exact folder and what was ",
            "wrong with it."
        )
    };
}

/// Shown when a replacement enrolment failed because the keystore root cannot hold an account.
///
/// The previous account is already gone at this point, so the words must not send the user back to a
/// remedy that cannot work: the honest answer names the FOLDER, which is the only thing a person can
/// change.
///
/// # Which copy covers which reachability (exhaustive)
///
/// There are three unusable-root paragraphs in the app and FOUR ways to reach one. The count differing
/// is deliberate, and it is stated here because a re-gate found the mapping was being argued from three
/// (dig_ecosystem#3145 re-gate F1):
///
/// | # | how it is reached | custody | copy |
/// |---|---|---|---|
/// | 1 | the tray's own "Set up my DIG Account" or "Restore from a recovery phrase" row | INTACT — this host has no account to lose | [`UNUSABLE_ROOT_NOTICE`](crate::account::boot::UNUSABLE_ROOT_NOTICE), which says so |
/// | 2 | "Replace this account with a NEW one…", then the wizard's CREATE route | DISCARDED | this const |
/// | 3 | "Replace this account with a NEW one…", then the wizard's IMPORT route | DISCARDED | this const |
/// | 4 | "Replace it with an account from a recovery phrase…" | DISCARDED | [`UNUSABLE_ROOT_AFTER_REMOVAL_WITH_WORDS_BODY`] |
///
/// Rows 2 and 3 share this paragraph because `AccountCustodian::enrol_new` is one method: the shell
/// cannot tell the flow which route the person took inside the wizard, and adding a signal for it would
/// buy a fourth variant of the same seven sentences. This copy is TRUE for both — it names the folder,
/// and its remedy sentence is "set up **or restore** your account from the DIG menu", which is the route
/// a row-3 person's words are still good for. What it deliberately does not do is PROMISE the 24 words
/// are intact, because on row 2 the only copy of them was on a screen that has now closed.
///
/// Row 1 is the one that must never be reachable after a discard: *"Your account has not been changed"*
/// is a falsehood there. **Kept out by convention and a test, not by the type system** (dig-app#358
/// item 3 — this paragraph previously overclaimed "structurally"): the replacement path goes through
/// `set_up_account_reporting`, which today draws no window itself, but nothing in the types stops a
/// future call site from drawing one — `failure_notice` and `UNUSABLE_ROOT_NOTICE`
/// (`boot.rs`) are both `pub`, and this function holds only a `&dyn NativeConfirmer`, which cannot
/// refuse to be handed to a caller that decided to notify twice. What actually holds row 1 out is
/// `set_up_account_reporting`'s own body doing so, plus the source-text test in
/// `crates/dig-app/tests/honest_copy_reaches_the_tray_surface.rs` that fails if a call site starts
/// naming a verdict itself instead of threading it through.
const UNUSABLE_ROOT_AFTER_REMOVAL_BODY: &str = unusable_root_after_removal!();

/// [`UNUSABLE_ROOT_AFTER_REMOVAL_BODY`] for the from-a-phrase flow, which additionally must say the 24
/// words are untouched — they are the only copy of the account that still exists.
///
/// Row 4 of the table on [`UNUSABLE_ROOT_AFTER_REMOVAL_BODY`], and the only reachability that may make
/// that promise: this flow HOLDS the phrase, having asked for it before anything was destroyed.
const UNUSABLE_ROOT_AFTER_REMOVAL_WITH_WORDS_BODY: &str = concat!(
    unusable_root_after_removal!(),
    " Your 24 words are still valid and nothing about them has changed."
);

/// The host effects a destructive account verb has, behind a trait so the ORDER can be tested.
///
/// # Why this trait exists (a review finding, dig_ecosystem#1799)
///
/// The first implementation put the ordering — authorize, collect the replacement, lock, discard, enrol —
/// in `dig-app`'s `bin` target behind `#[cfg(feature = "tray")]`, where **no test can reach it**. The
/// consequence was measured: inverting one character in that function so that a REFUSED destroy destroyed
/// the account and an AUTHORIZED one aborted left `cargo test --workspace` green and clippy silent. The
/// gate's own words were *"the custody proof is vacuous at the only place custody is destroyed"*.
///
/// So the ordering lives here, in the library, and the untestable parts — which directory, which credential
/// store, which live session — are behind these four methods. The shell implements them and holds no
/// ordering logic at all.
pub trait AccountCustodian {
    /// Drop the live session's key material, before the seed it guards is deleted.
    ///
    /// Called even when there is no live session (a no-op then): the caller must not have to know, and
    /// "lock before discard" is a rule about ORDER, not about whether a session happens to exist.
    fn lock_current(&self);

    /// **Irreversibly** discard the account's custody root. The one destructive step.
    fn discard(&self) -> DiscardOutcome;

    /// Enrol a brand-new account, showing and confirming its recovery phrase.
    ///
    /// Reports WHY it failed rather than merely that it did, in BOTH the dimensions a post-discard
    /// caller needs (see [`EnrolFailure`]). The enrolment WRITES, so it is one of the only places
    /// `UnlockFailure::Unusable` can arise — and this flow reaches it with the previous account already
    /// gone, so telling the user to "set one up whenever you are ready" when the folder cannot hold an
    /// account is a retry invitation for a condition no retry moves. It is also the only step that can
    /// leave an account BEHIND a failure, which is the other half the verdict alone cannot say.
    fn enrol_new(&self) -> Result<(), EnrolFailure>;

    /// Enrol the account `phrase` describes. Reports WHY it failed, for the reason above.
    fn enrol_from(&self, phrase: &RecoveryPhrase) -> Result<(), EnrolFailure>;

    /// Re-open the account that is still here after a FAILED discard, so the user is not left with a
    /// working account the tray reports as locked forever.
    fn reopen(&self);
}

/// What a destructive account verb did. Every variant states whether custody was destroyed, because that is
/// the only fact a caller — or a reader — actually needs from this flow.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReplaceOutcome {
    /// Destroyed, and the replacement is enrolled and live.
    Replaced,
    /// Destroyed, and nothing was put in its place, as asked.
    Removed,
    /// **Nothing destroyed.** The user declined the authorization, or the OS could not authorize.
    RefusedByUser,
    /// **Nothing destroyed.** The user was authorized but supplied no replacement phrase, so the flow
    /// stopped before the point of no return — which is the whole reason the phrase is collected first.
    AbandonedAtPhrase,
    /// **Nothing destroyed.** The discard itself failed; the account is still here and has been re-opened.
    DiscardFailed,
    /// **Destroyed**, but the replacement could not be enrolled. The worst outcome available, and the one
    /// the user must be told about most clearly.
    EnrolFailed,
    /// **Destroyed**, and the replacement IS enrolled — but it did not re-open, so this host now holds a
    /// complete account that is locked.
    ///
    /// Its own variant rather than [`EnrolFailed`](Self::EnrolFailed) because the two differ in the one
    /// fact a caller reads this type for: whether an account exists afterwards. Reporting this as
    /// `EnrolFailed` is what let the flow tell a user their computer has no DIG Account while the
    /// account it had just written sat on disk (dig-app#235).
    ReplacedButLocked,
}

impl ReplaceOutcome {
    /// Whether custody was destroyed. The single question every one of this flow's tests turns on.
    pub fn destroyed_custody(self) -> bool {
        matches!(
            self,
            Self::Replaced | Self::Removed | Self::EnrolFailed | Self::ReplacedButLocked
        )
    }
}

/// Run a destructive account verb: authorize, collect the replacement, lock, discard, enrol.
///
/// # The order IS the safety property
///
/// 1. **Authorize** ([`authorize_destroy`]) — offers a last look at the recovery phrase where one exists,
///    then puts the destruction through the biometric authorization gate. Anything other than
///    [`DestroyRuling::Authorized`] returns [`ReplaceOutcome::RefusedByUser`] **without calling a single
///    method on `custodian`**.
/// 2. **Collect the replacement phrase FIRST**, while the old account is still intact. Asking afterwards
///    would leave a user who cancels — or mistypes past the retry bound — with no account at all.
///    Destroying something before knowing its replacement is good is the one ordering mistake this flow
///    must not make.
/// 3. **Lock**, so the residency is not holding key material for a seed about to be deleted.
/// 4. **Discard**, and only then enrol.
///
/// Every step the user needs to hear about ends in a window, because they pressed a button and are waiting.
pub fn replace_account<S: ProfileSealer>(
    confirmer: &dyn NativeConfirmer,
    custodian: &dyn AccountCustodian,
    what: Replacement,
    vault: Option<&PhraseVault<S>>,
) -> ReplaceOutcome {
    if authorize_destroy(confirmer, what, vault) != DestroyRuling::Authorized {
        // Declining is a normal outcome, not an error, and the user already saw the window they declined —
        // so nothing more is said. Nothing was changed.
        return ReplaceOutcome::RefusedByUser;
    }

    let replacement = match what {
        Replacement::FromPhrase => match ask_for_phrase(
            confirmer,
            "Type the recovery phrase of the account you want on this computer.",
        ) {
            Some(phrase) => Some(phrase),
            None => {
                // The existing account is untouched, which is the point of asking before destroying. Say so
                // explicitly, because the user DID approve a destruction and would otherwise assume it ran.
                notify(
                    confirmer,
                    "DIG — Nothing was changed",
                    "Your existing DIG Account is still here.",
                    "No recovery phrase was entered, so nothing was replaced or removed.",
                );
                return ReplaceOutcome::AbandonedAtPhrase;
            }
        },
        Replacement::WithNewAccount | Replacement::Nothing => None,
    };

    custodian.lock_current();

    match custodian.discard() {
        DiscardOutcome::Discarded | DiscardOutcome::NothingToDiscard => {}
        DiscardOutcome::Failed => {
            notify(
                confirmer,
                "DIG — Nothing was changed",
                "Your DIG Account could not be removed.",
                "It is still here and still works — it is now locked, so unlock it from the DIG menu. \
                 The log folder (in the DIG menu) has the details.",
            );
            custodian.reopen();
            return ReplaceOutcome::DiscardFailed;
        }
    }

    // Past this line custody is GONE. Every path below must leave the user knowing that.
    match (what, replacement) {
        (Replacement::WithNewAccount, _) => match custodian.enrol_new() {
            Ok(()) => ReplaceOutcome::Replaced,
            // The folder itself cannot hold an account, so "set one up whenever you are ready" would be
            // an invitation to retry something that cannot succeed — and custody is already gone here.
            Err(f) if f.verdict() == UnlockFailure::Unusable => {
                notify(
                    confirmer,
                    "DIG — Account folder cannot be used",
                    "The previous account was removed, and the folder DIG keeps accounts in cannot be \
                     used.",
                    UNUSABLE_ROOT_AFTER_REMOVAL_BODY,
                );
                ReplaceOutcome::EnrolFailed
            }
            Err(EnrolFailure::NotReopened(_)) => {
                notify(
                    confirmer,
                    ENROLLED_BUT_LOCKED_NOTICE.title,
                    ENROLLED_BUT_LOCKED_NOTICE.heading,
                    ENROLLED_BUT_LOCKED_NOTICE.body,
                );
                ReplaceOutcome::ReplacedButLocked
            }
            Err(_) => {
                notify(
                    confirmer,
                    "DIG — Setup not completed",
                    "The previous account was removed, and a new one was not created.",
                    "This computer now has no DIG Account. Set one up, or restore one from its 24 \
                     words, from the DIG menu whenever you are ready.",
                );
                ReplaceOutcome::EnrolFailed
            }
        },
        (Replacement::FromPhrase, Some(phrase)) => match custodian.enrol_from(&phrase) {
            Ok(()) => {
                notify(
                    confirmer,
                    "DIG — Account replaced",
                    "The DIG Account from your recovery phrase is now on this computer.",
                    "The account that was here before is gone and its data is no longer readable.",
                );
                ReplaceOutcome::Replaced
            }
            Err(f) if f.verdict() == UnlockFailure::Unusable => {
                notify(
                    confirmer,
                    "DIG — Account folder cannot be used",
                    "The previous account was removed, and your 24 words could not be put back into \
                     the folder DIG keeps accounts in.",
                    UNUSABLE_ROOT_AFTER_REMOVAL_WITH_WORDS_BODY,
                );
                ReplaceOutcome::EnrolFailed
            }
            Err(EnrolFailure::NotReopened(_)) => {
                notify(
                    confirmer,
                    ENROLLED_BUT_LOCKED_NOTICE.title,
                    ENROLLED_BUT_LOCKED_NOTICE.heading,
                    ENROLLED_BUT_LOCKED_NOTICE.body,
                );
                ReplaceOutcome::ReplacedButLocked
            }
            Err(_) => {
                notify(
                    confirmer,
                    "DIG — Restore did not complete",
                    "The previous account was removed, but the new one could not be set up.",
                    "Your 24 words are still valid — try \"Restore from a recovery phrase…\" in the DIG \
                     menu. The log folder has the details.",
                );
                ReplaceOutcome::EnrolFailed
            }
        },
        // Unreachable by construction (step 2 returns early without a phrase), but expressed as a REFUSAL to
        // enrol rather than an `unwrap`: a future edit that reordered the collection must not turn into a
        // panic in the one flow that has already destroyed the user's key material.
        (Replacement::FromPhrase, None) => ReplaceOutcome::EnrolFailed,
        (Replacement::Nothing, _) => {
            notify(
                confirmer,
                "DIG — Account removed",
                "Your DIG Account has been removed from this computer.",
                "Nothing on this computer can open it any more. If you kept its 24 words you can restore \
                 it here, or anywhere else, from the DIG menu.",
            );
            ReplaceOutcome::Removed
        }
    }
}

/// What a first run ended in.
///
/// # Why there is no identity outcome here (dig-app#210)
///
/// There used to be an `IdentityReady`, produced only by a confirmed DID mint inside this wizard.
/// The DID-only mint is retired: a DIG profile is a DID singleton **and** a store, and minting the
/// DID alone strands an account half-created. Creating an identity is now the whole-profile
/// ceremony, offered by [`first_profile`](crate::account::first_profile) against a node that was
/// actually measured — so this wizard's job ends at a funded, usable wallet, and it says so.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FirstRunOutcome {
    /// A wallet was created. It has a seed, a confirmed recovery phrase and a password, and it can
    /// read content and hold funds. It has no profile yet, which is the next, separate step.
    WalletCreated,
    /// The user backed out. Nothing was created and the host is exactly as it was.
    Declined,
    /// Creation was attempted and did not complete. The creating step has already told the user why.
    Failed,
}

/// What this computer already has when the wizard starts (dig_ecosystem#2341).
///
/// The wizard is gated on the DID, not on the account — a person who set up a wallet in an earlier
/// version has no DID and must still be able to reach the funding step without being walked through
/// creating a second account they do not want.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AccountPresence<'a> {
    /// No account at all. The wizard runs from the beginning: orient, then create or import.
    Absent,
    /// A wallet already exists at this receiving address. The wizard starts at the funding step.
    Wallet {
        /// Where funds are sent — the address the QR encodes.
        address: &'a str,
    },
}

/// Puts the account's receiving address on the clipboard.
///
/// A seam, because the clipboard is a platform concern and the wizard is not: the shell already owns a
/// clipboard helper for the tray's "copy my DIG ID". It exists because a QR is useless to the person
/// this step is most likely to serve — someone funding from a desktop wallet on the SAME machine, who
/// cannot point a camera at their own screen.
pub trait AddressCopier {
    /// Copy `address`. Returns whether it actually reached the clipboard.
    fn copy(&self, address: &str) -> bool;
}

/// Run the FIRST-RUN flow: orient the user, let them CREATE a new account or IMPORT an existing one
/// from its recovery phrase, then show them where to send funds (dig_ecosystem#1826,
/// dig_ecosystem#1564).
///
/// `create` is the new-account step — in production the shell's setup path, which shows the 24 words,
/// takes the retention claim, asks for a password and enrols. `import` is the restore step, handed the
/// user's typed [`RecoveryPhrase`] to re-derive and seal that account. Each returns the account's
/// receiving address, or `None` if it did not complete; both feed the SAME `show_account_ready`
/// screens so the two routes cannot drift.
///
/// # The route choice, and why it takes two screens (dig_ecosystem#1564)
///
/// A stranger who already holds a DIG recovery phrase must be able to restore at first run, not only
/// create afresh. But a native window offers two buttons, and the choice has three outcomes — create,
/// import, or leave. So the orient screen carries the ONE escape (its refusal ends the flow and creates
/// nothing), and the screen after it is the real either/or: "yes" imports, "no" creates. A user who
/// closes the route window lands in the create path, which is itself fully escapable — it shows the
/// words and asks for the retention claim before anything is enrolled — so no account is ever created
/// without an explicit choice.
///
/// # The last screen, and where the identity step went (dig-app#210)
///
/// **Funding is shown, not awaited — and the reason has CHANGED, so do not re-derive the old one.**
/// The original reason was that dig-app had no window toolkit, so a modal could not poll a chain or
/// update itself. **That is no longer true**: egui + eframe landed under dig_ecosystem#2038 and this
/// app now draws its own windows, so a live "waiting for funds…" screen is buildable
/// (dig_ecosystem#1826). What still blocks it is that the step AFTER funding does not live here any
/// more: this wizard used to end on a DID-only mint, and minting a DID alone strands an account
/// half-created, because a DIG profile is a DID singleton **and** a store. Creating an identity is
/// therefore the whole-profile ceremony, offered by
/// [`first_profile`](crate::account::first_profile) against a node it actually measured — and this
/// wizard ends at a wallet the person can fund.
///
/// # What gates it, and what it does NOT block (dig_ecosystem#2341)
///
/// It is gated on the DID — `did.is_none()` — not on the account, because a DID is what an identity-
/// bearing surface needs and a wallet from an earlier version has none. What it must NOT be is a wall:
/// dig-app tells its users that reading content never needs an account or a wallet, and that stays
/// true. Every screen here can be left, and what declining costs is publishing, signing and
/// messaging — the surfaces
/// [`Allowance::of`](crate::account::did::Allowance::of) gates — not the app.
pub fn first_run_wizard(
    confirmer: &dyn NativeConfirmer,
    presence: AccountPresence<'_>,
    create: impl FnOnce() -> Option<String>,
    import: impl FnOnce(&RecoveryPhrase) -> Option<String>,
    copier: &dyn AddressCopier,
) -> FirstRunOutcome {
    // A wallet that already exists needs no orienting and no route choice: the only thing missing is
    // the funding, so the wizard starts where the missing part is.
    if let AccountPresence::Wallet { address } = presence {
        return finish_the_wallet(confirmer, address, copier);
    }

    // 1. Orient. A person who opened the menu out of curiosity can leave here having changed nothing —
    // this is the flow's ONE cancel point, which is why it is a claim whose refusal ends everything.
    if confirmer.confirm_claim(&ClaimPrompt {
        title: "DIG — Set up your DIG Account",
        heading: "Let's set up your DIG Account.",
        body: "You can create a brand-new account, or — if you have used DIG before — import an \
               existing one from its 24-word recovery phrase.\n\n\
               Nothing is created until you choose, and you can stop at any point.\n\n\
               You do not need an account to read content on the DIG Network — that already works.",
        affirm: "Get started",
        decline: None,
        // Neither answer creates anything, so the friendly default is the affirmative — this is an
        // invitation the user is answering, not a claim they are making.
        refusal_is_default: false,
        scannable: None,
        identifier: None,
    }) != ConfirmDecision::Approve
    {
        return FirstRunOutcome::Declined;
    }

    // 2. Choose the route — see `route_fork`, which is the one claim in the app where BOTH controls
    // act, and where the usual "a claim defaults to its refusal" rule is therefore inverted. A host
    // that cannot ask creates nothing rather than guessing.
    match confirmer.confirm_claim(&route_fork()) {
        ConfirmDecision::Approve => import_existing_account(confirmer, import, copier),
        ConfirmDecision::Deny => create_new_account(confirmer, create, copier),
        // No confirm surface at all: create nothing, exactly as the orient screen does on such a host.
        ConfirmDecision::Timeout | ConfirmDecision::Unavailable => FirstRunOutcome::Declined,
    }
}

/// The first-run route fork: import an existing phrase, or CREATE A NEW ACCOUNT.
///
/// Named rather than written inline so its two safety properties can be asserted directly, and
/// so a future edit has to walk past the reason they are what they are.
fn route_fork() -> ClaimPrompt<'static> {
    ClaimPrompt {
            title: "DIG — Set up your DIG Account",
            heading: "Do you already have a DIG recovery phrase?",
            body:
                "If you have used DIG on another computer, import that account by typing its 24 words. \
                   Choose \"Create a new account\" to start fresh with a brand-new recovery phrase.\n\n\
                   A recovery phrase from a Chia wallet such as Sage is NOT a DIG recovery phrase.",
            affirm: "Import my recovery phrase",
            // NOT "Cancel". This control GENERATES AND SEALS A NEW MASTER SEED, and the body has
            // already told the user to look for "Create a new account" (dig_ecosystem#2074).
            decline: Some("Create a new account"),
            // NOT pre-focused, unlike every other claim in the app. Both controls ACT here, so the
            // usual "a claim defaults to its refusal" rule is inverted: pre-selecting the refusal
            // would put a brand-new account one bare Enter away. The affirmative keeps the default
            // because importing is the reversible half — it asks for 24 words and creates nothing
            // until they are typed.
            refusal_is_default: false,
            scannable: None,
            identifier: None,
    }
}

/// Create a brand-new account through the load-bearing `create` step, then the shared ready screens.
///
/// Everything consequential happens inside `create` — words shown, retention claimed, password chosen,
/// seed sealed — and it reports its own failures, so nothing is added on the failing path.
fn create_new_account(
    confirmer: &dyn NativeConfirmer,
    create: impl FnOnce() -> Option<String>,
    copier: &dyn AddressCopier,
) -> FirstRunOutcome {
    let Some(address) = create() else {
        return FirstRunOutcome::Failed;
    };
    finish_the_wallet(confirmer, &address, copier)
}

/// Import an existing account from a typed recovery phrase, then the shared ready screens.
///
/// The words are collected through the SAME native input gate the tray restore uses ([`ask_for_phrase`])
/// — masked, re-asking on a bad phrase, refusing a Chia wallet phrase — so a stranger with a phrase gets
/// the identical, tested entry. A user who cancels the phrase window has created nothing.
fn import_existing_account(
    confirmer: &dyn NativeConfirmer,
    import: impl FnOnce(&RecoveryPhrase) -> Option<String>,
    copier: &dyn AddressCopier,
) -> FirstRunOutcome {
    let Some(phrase) = ask_for_phrase(
        confirmer,
        "Type the recovery phrase of the DIG Account you want on this computer.",
    ) else {
        return FirstRunOutcome::Declined;
    };
    let Some(address) = import(&phrase) else {
        return FirstRunOutcome::Failed;
    };
    finish_the_wallet(confirmer, &address, copier)
}

/// The step every route ends on, whichever way the wallet got here: show where to FUND it.
///
/// Shared so create, import and an already-existing wallet cannot drift, and so all three routes end
/// on the same screen.
///
/// # Why it no longer mints (dig-app#210)
///
/// It used to end on a DID mint, and the outcome it returned depended on whether that mint confirmed.
/// A DID minted alone strands an account half-created — a DIG profile is a DID singleton **and** a
/// store — so the whole DID-only path is retired, and creating an identity is the whole-profile
/// ceremony [`first_profile`](crate::account::first_profile) offers against a node it measured. The
/// wallet exists once this returns, which is exactly what it reports.
fn finish_the_wallet(
    confirmer: &dyn NativeConfirmer,
    address: &str,
    copier: &dyn AddressCopier,
) -> FirstRunOutcome {
    show_where_to_send_funds(confirmer, address, copier);
    FirstRunOutcome::WalletCreated
}

/// The funding step: the address as a scannable code, as mono text, and on the clipboard if asked.
///
/// # Why all three, and why the QR is not enough on its own
///
/// A QR serves a phone. It is useless to the person most likely to be here — someone funding from a
/// desktop wallet on this same computer, who cannot point a camera at their own screen — and to anyone
/// using a screen reader. So the address is ALSO the window's one mono identifier, and the second
/// control on the row copies it. Both controls continue; the fork the user actually has to decide is
/// the next screen.
///
/// The code itself is drawn black-on-white whatever the theme, because a camera reads contrast and a
/// dark-theme code is one most phones refuse — [`crate::confirm::gui`] owns that and this step does not
/// second-guess it. It is only offered where the confirmer will actually draw it
/// ([`NativeConfirmer::draws_qr`]), so the copy never points at a picture that is not there.
fn show_where_to_send_funds(
    confirmer: &dyn NativeConfirmer,
    address: &str,
    copier: &dyn AddressCopier,
) {
    let scannable = confirmer
        .draws_qr()
        .then(|| QrArt::encode(address))
        .flatten();
    let decision = confirmer.confirm_claim(&funding_claim(address, scannable.as_ref()));

    if decision != ConfirmDecision::Deny {
        return;
    }
    match copier.copy(address) {
        true => notify(
            confirmer,
            copy::fund::COPIED_TITLE,
            copy::fund::COPIED_HEADING,
            copy::fund::COPIED_BODY,
        ),
        // A copy that silently did nothing would leave someone pasting whatever was on the clipboard
        // before into a send field. The address is repeated so the screen is still a way forward.
        false => notify(
            confirmer,
            copy::fund::COPY_FAILED_TITLE,
            copy::fund::COPY_FAILED_HEADING,
            &format!("{}\n\n{}", address, copy::fund::COPY_FAILED_BODY),
        ),
    }
}

/// The funding window, built in one place so the wizard and the screenshot gallery draw the SAME
/// screen (dig_ecosystem#2341).
///
/// Public because a photograph of re-typed copy is a photograph of a second implementation of it,
/// which is how a screenshot stops being evidence about the product. `scannable` is `None` on a host
/// whose windows draw no code, and the body changes with it rather than pointing at a picture that is
/// not there.
pub fn funding_claim<'a>(address: &'a str, scannable: Option<&'a QrArt>) -> ClaimPrompt<'a> {
    ClaimPrompt {
        title: copy::fund::TITLE,
        heading: copy::fund::HEADING,
        body: match scannable.is_some() {
            true => copy::fund::BODY_WITH_A_CODE,
            false => copy::fund::BODY_TEXT_ONLY,
        },
        affirm: copy::fund::CONTINUE,
        decline: Some(copy::fund::COPY_ADDRESS),
        // Both controls continue and neither spends anything, so the friendly default is the one that
        // simply moves on — this is not a claim the user is making about the world.
        refusal_is_default: false,
        scannable,
        identifier: Some(address),
    }
}

/// The tray's DID explainer (`TrayAction::AboutDid`), as a notice the shell renders.
///
/// The tray offers an EXPLANATION rather than a control because a mint spends real XCH and so
/// belongs behind a cost-and-consent window, not a menu row — and a greyed row explains nothing
/// (§3.7). What the explanation may say is bounded by the same rule
/// every pre-spend screen obeys: it may not promise a cost screen the flow does not have
/// (dig_ecosystem#2377).
///
/// # Why this is a function in the core rather than three literals in the shell
///
/// The shell is `src/bin`, which no test can reach — the same blind spot that let an inverted
/// authorization check ship green elsewhere in this ecosystem. Returning the notice from here puts
/// its words inside
/// `nothing_shown_before_a_spend_may_promise_a_cost_screen_that_does_not_exist`, so the promise this
/// screen used to make is now unmakeable rather than merely removed (dig_ecosystem#2560).
/// # It reports what was MEASURED, and the four answers are four different sentences
///
/// The body used to be `explainer_body(NoChainTransport)` — a constant. That was accurate only
/// while the binary hardcoded its seam, and it went false the moment a node could answer: a machine
/// whose node serves both mint reads was still told *"on-chain minting is not available in this
/// version"*. `chain` is the reading [`NodeChainReadiness`](crate::chain::NodeChainReadiness) took
/// off the painting thread, and `None` means nobody has asked yet — which is NOT a blocker and must
/// not be rendered as one (dig_ecosystem#2690).
///
/// Every answer still withholds the offer, because there is no control to offer: this screen names
/// what is missing, it does not gate anything. That is why it may safely say *your node can do
/// this* without becoming the availability drift dig_ecosystem#2377 measured — no capability is
/// read off this function, and nothing branches on its words.
pub fn did_explainer(chain: Option<&ChainReadiness>) -> WizardNotice {
    WizardNotice {
        title: copy::did::EXPLAINER_TITLE,
        heading: copy::did::EXPLAINER_HEADING,
        body: copy::did::explainer_body_for(chain),
        identifier: None,
    }
}

/// One of the wizard's report screens, composed rather than drawn.
///
/// A value so the gallery can photograph every ending without a chain, and so the copy for each
/// ending is decided in one unit-tested place instead of inside a `match` that also draws.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WizardNotice {
    /// The window title.
    pub title: &'static str,
    /// The one-line heading.
    pub heading: &'static str,
    /// The body — prose, and the chain's own reason where there is one.
    pub body: String,
    /// The one bare identifier this screen shows: the DID, or the spend to look up. `None` where the
    /// screen shows neither.
    ///
    /// Kept out of the body because the window sets it in Space Mono, and a DID or a spend id is read
    /// or transcribed character by character — in prose it wraps mid-token and `1`/`l` stop being
    /// distinguishable.
    pub identifier: Option<String>,
}

/// Every word the DID wizard puts on screen, in one place (dig_ecosystem#2328).
///
/// There is no i18n layer in dig-app yet. Naming each string here is what makes the copy reviewable as
/// copy, keeps a sentence from being edited in one branch and not its twin, and gives the catalog a
/// single door to come in through when it arrives.
mod copy {
    /// The funding step.
    pub(super) mod fund {
        /// The window title.
        pub const TITLE: &str = "DIG — Add funds to your DIG Account";
        /// The heading. Short enough to survive the native window's single unwrapped line.
        pub const HEADING: &str = "Send XCH to this address to pay for your DID.";
        /// The body where the window will draw a scannable code.
        pub const BODY_WITH_A_CODE: &str =
            "Your address is below, with the same thing as a code beneath it. Scan the code with a \
             Chia wallet on your phone, or use \"Copy my address\" and send from a wallet on this \
             computer.\n\n\
             Creating your on-chain DID is a real Chia transaction, so it costs a small amount of XCH. \
             You do not need any funds to read content, and DIG spends nothing until you approve the \
             transaction on the next screen.\n\n\
             You can see this address again at any time from the DIG menu.";
        /// The body on a host that draws no code, where the text address is the whole path.
        pub const BODY_TEXT_ONLY: &str =
            "Your address is below. Use \"Copy my address\" and send to it from any Chia wallet.\n\n\
             Creating your on-chain DID is a real Chia transaction, so it costs a small amount of XCH. \
             You do not need any funds to read content, and DIG spends nothing until you approve the \
             transaction on the next screen.\n\n\
             You can see this address again at any time from the DIG menu.";
        /// The control that moves on.
        pub const CONTINUE: &str = "Continue";
        /// The control that copies the address. NOT "Cancel" — it does not back out of anything.
        pub const COPY_ADDRESS: &str = "Copy my address";
        /// The confirmation after a successful copy.
        pub const COPIED_TITLE: &str = "DIG — Address copied";
        /// Its heading.
        pub const COPIED_HEADING: &str = "Your DIG address is on the clipboard.";
        /// Its body. A receiving address is public, so this carries no secrecy warning — unlike the
        /// recovery-phrase copy, which does.
        pub const COPIED_BODY: &str =
            "Paste it into the \"send to\" field of any Chia wallet. An address is public — sharing it \
             only lets people send you funds.";
        /// The title when the clipboard could not be written.
        pub const COPY_FAILED_TITLE: &str = "DIG — Could not copy";
        /// Its heading.
        pub const COPY_FAILED_HEADING: &str = "DIG could not reach the clipboard.";
        /// Its body, shown beneath the address itself so the screen is still a way forward.
        pub const COPY_FAILED_BODY: &str =
            "Nothing was copied, so whatever was on your clipboard before is still there. Select the \
             address above and copy it by hand, or find it again from the DIG menu.";
    }

    /// The DID step, from the offer through every way the wait can end.
    pub(super) mod did {
        use crate::account::profile_mint::ChainReadiness;
        use crate::profiles::CreationBlocked;

        /// The tray's DID explainer title (`TrayAction::AboutDid`).
        ///
        /// # Why the tray's explainer lives beside the wizard's copy
        ///
        /// It used to live inline in `src/bin/dig-app.rs`, where no test can read it — and it spent
        /// three releases promising *"you will see the exact cost before anything is spent"*, the
        /// exact sentence dig_ecosystem#2377 removed from the mint offer's body (since retired
        /// along with the rest of the DID-only mint path, dig-app#210). The guard that removed it
        /// enumerates copy bodies by name, so a body the guard could not name was a body the guard
        /// could not check: the rule was fixed in one place and left standing in the other.
        ///
        /// Naming it here is what puts it inside that enumeration. The bin now renders these
        /// constants rather than literals of its own, so the promise cannot be re-made in the one
        /// file whose contents no test can see (dig_ecosystem#2560).
        pub const EXPLAINER_TITLE: &str = "DIG — On-chain DID";
        /// Its heading.
        pub const EXPLAINER_HEADING: &str =
            "An on-chain DID is the remaining step, and it costs XCH.";
        /// The explainer's opening, shared by every build.
        pub const EXPLAINER_OPENING: &str = concat!(
            "A DID publishes your identity on the Chia blockchain so others can find and verify ",
            "it. Creating one is a real transaction that spends real XCH from your DIG Account, so ",
            "DIG will never create one without you asking.",
        );
        /// The explainer's closing, shared by every build.
        ///
        /// It describes what WILL happen rather than what a future version might do, because the
        /// wizard it points at already exists and already works this way: the window that asks IS
        /// the approval. Promising a separate cost screen described a flow that was never built
        /// (dig_ecosystem#2377).
        pub const EXPLAINER_CLOSING: &str = concat!(
            "The window that asks will state the cost and sending it is the approval, so nothing ",
            "is spent unless you choose it there.",
        );
        /// The middle sentence when this build cannot reach the chain at all.
        pub const EXPLAINER_NO_TRANSPORT: &str = concat!(
            "It is what turns the wallet on this computer into a full DIG Account. On-chain ",
            "minting is not available in this version — when it arrives, this is where you will ",
            "start it.",
        );
        /// The middle sentence when this build can reach the chain and cannot finish a mint.
        pub const EXPLAINER_NO_LINEAGE: &str = concat!(
            "It is what turns the wallet on this computer into a full DIG Account. This version ",
            "can reach the blockchain and cannot yet finish creating one, so it will not start ",
            "one — when it can, this is where you will start it.",
        );

        /// The middle sentence when the account is locked.
        ///
        /// Names the lock rather than the node, for [`MINTING_UNAVAILABLE_LOCKED`]'s reason: no
        /// probe runs while the account is closed, so any claim about this machine's node here
        /// would be one nobody measured (dig_ecosystem#3059).
        pub const EXPLAINER_LOCKED: &str = concat!(
            "It is what turns the wallet on this computer into a full DIG Account. Your account ",
            "is locked, so DIG cannot make one yet — unlock it and DIG will check whether this ",
            "computer can.",
        );

        /// The middle sentence before any node has been asked.
        ///
        /// It names no cause, because none has been measured. Telling somebody their version cannot
        /// mint, when the truth is that nothing has looked yet, sends them to wait for a release
        /// when what they need is to start their node (dig_ecosystem#2690).
        pub const EXPLAINER_NOT_MEASURED: &str = concat!(
            "It is what turns the wallet on this computer into a full DIG Account. DIG has not yet ",
            "been able to ask your node whether it can create one — if your node is not running, ",
            "starting it is what lets DIG find out.",
        );
        /// The middle sentence when the node CAN mint and DIG has no control to start one.
        ///
        /// # This sentence exists because the one it replaced became false
        ///
        /// A build whose node answers both mint reads was still told *"on-chain minting is not
        /// available in this version"* — a statement about DIG that was, on such a machine, simply
        /// untrue. The honest version names the half that is actually missing. It promises no date
        /// and offers no control, so it cannot become the dead end dig_ecosystem#1800 removed.
        pub const EXPLAINER_NO_CONTROL_YET: &str = concat!(
            "It is what turns the wallet on this computer into a full DIG Account. Your node can ",
            "do this — DIG does not yet offer the step that starts it, so nothing here will spend ",
            "anything yet.",
        );

        /// The tray explainer's body, selected by WHY this build cannot mint.
        ///
        /// Composed rather than written twice, for the reason [`unavailable_body`] is: only the
        /// middle sentence differs, and it is the only thing the exhaustive match chooses.
        pub fn explainer_body(why: CreationBlocked) -> String {
            let middle = match why {
                CreationBlocked::NoChainTransport => EXPLAINER_NO_TRANSPORT.to_string(),
                CreationBlocked::NoLineageWalk => EXPLAINER_NO_LINEAGE.to_string(),
                // Unreachable from the first-run wizard for `unavailable_body`'s reason, and
                // written out so the match stays total.
                CreationBlocked::AccountLocked => EXPLAINER_LOCKED.to_string(),
                // Unreachable from the first-run wizard for the reason given at `unavailable_body`
                // — an unprofiled account's two indices are both ROOT — and written out so the
                // match stays total.
                CreationBlocked::FundingElsewhere { funding, target } => {
                    // Ordinals, matching the profiles card and `ProfileRow::display_name`:
                    // an HD index is not a name a person has ever been shown.
                    let (funding, target) = (funding.0 + 1, target.0 + 1);
                    format!(
                        "It is what turns the wallet on this computer into a full DIG Account. This \
                         account's XCH is held by profile {funding} and profile {target} is paid for \
                         from its own wallet, so DIG will not begin it until funds reach profile \
                         {target}'s address.",
                    )
                }
                // See `unavailable_body`: this one is genuinely reachable, and its remedy is a
                // restart rather than anything to do with the node.
                CreationBlocked::RegistryUnreadable => concat!(
                    "It is what turns the wallet on this computer into a full DIG Account. DIG ",
                    "could not read this account's profile list, so it will not create one that ",
                    "this computer would forget — close DIG and open it again to try reading it.",
                )
                .to_string(),
                // Written for totality, and offering no next step because none exists.
                CreationBlocked::IndexesExhausted => concat!(
                    "It is what turns the wallet on this computer into a full DIG Account. This ",
                    "account has no room left for another profile, so DIG will not create one.",
                )
                .to_string(),
            };
            format!("{EXPLAINER_OPENING}\n\n{middle} {EXPLAINER_CLOSING}")
        }

        /// The tray explainer's body for the reading the poller took, `None` meaning *not asked*.
        ///
        /// Routed through [`explainer_body`] for the two blocked answers rather than composing a
        /// second time, so the shared opening and closing cannot come to differ between the two
        /// entry points — which is the drift the copy guard below exists to catch.
        pub fn explainer_body_for(chain: Option<&ChainReadiness>) -> String {
            let middle = match chain {
                None => EXPLAINER_NOT_MEASURED,
                Some(ChainReadiness::WalksLineages) => EXPLAINER_NO_CONTROL_YET,
                Some(ChainReadiness::NoChainTransport { .. }) => {
                    return explainer_body(CreationBlocked::NoChainTransport)
                }
                Some(ChainReadiness::NoLineageWalk { .. }) => {
                    return explainer_body(CreationBlocked::NoLineageWalk)
                }
            };
            format!("{EXPLAINER_OPENING}\n\n{middle} {EXPLAINER_CLOSING}")
        }
    }
}

/// Draw a plain informational window, so every message this module shows goes through the same OS-owned
/// surface rather than a mix of dialogs and silence.
fn notify(confirmer: &dyn NativeConfirmer, title: &str, heading: &str, body: &str) {
    confirmer.show_notice(&NoticePrompt {
        title,
        heading,
        body,
        acknowledge: "OK",
        identifier: None,
    });
}

/// How many times a user may retype a phrase before the window gives up.
///
/// Bounded so a dialog backend that returns instantly (a misconfigured helper, a scripted double) cannot
/// spin windows forever; generous enough that a person correcting one word twice is not shut out.
const PHRASE_ATTEMPTS: usize = 5;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::account::boot::ENROLLED_BUT_LOCKED_NOTICE;
    use crate::account::recovery::PHRASE_WORDS;
    use crate::confirm::{ConnectPrompt, PairPrompt, SignPrompt};
    use crate::profiles::CreationBlocked;
    use crate::sealer::SealError;
    use crate::tray_menu::TrayAction;
    use std::sync::Mutex;
    use zeroize::Zeroizing;

    // ---- The first-run wizard (dig_ecosystem#1826) ------------------------------------------------

    /// A distinctive address so "the real address reached the screen" is checkable, and no substring of
    /// the surrounding copy could satisfy the assertion by accident.
    const ADDRESS: &str = "xch1firstrunwizardfixtureaddress0000000000000000000000000000000";

    /// A recovery phrase the never-called import closure would reject, so a test that accidentally
    /// routed through import (rather than create) fails loudly rather than silently passing.
    fn never_imports(_phrase: &RecoveryPhrase) -> Option<String> {
        panic!("this flow must take the CREATE route, not import");
    }

    /// A clipboard that records what it was asked to copy and whether it agreed to.
    struct RecordingCopier {
        succeeds: bool,
        copied: Mutex<Vec<String>>,
    }

    impl RecordingCopier {
        fn working() -> Self {
            Self {
                succeeds: true,
                copied: Mutex::new(Vec::new()),
            }
        }

        fn broken() -> Self {
            Self {
                succeeds: false,
                copied: Mutex::new(Vec::new()),
            }
        }

        fn copied(&self) -> Vec<String> {
            self.copied.lock().unwrap().clone()
        }
    }

    impl AddressCopier for RecordingCopier {
        fn copy(&self, address: &str) -> bool {
            self.copied.lock().unwrap().push(address.to_owned());
            self.succeeds
        }
    }

    /// **Every reason a build cannot mint gets its OWN non-empty sentence, on both screens.**
    ///
    /// Makes impossible: a new blocker silently inheriting another one's explanation. Telling
    /// somebody whose chain is plainly working that DIG "has no way to reach the chain" sends them
    /// to debug a network that is fine.
    ///
    /// Distinctness is asserted PAIRWISE over the whole set rather than between two named arms, so
    /// the check widens with `CreationBlocked::EVERY` instead of needing a new assertion per
    /// variant. The composed bodies are compared, not the fragments: two reasons could differ in
    /// their fragment and still compose to the same paragraph.
    #[test]
    fn every_blocked_reason_has_its_own_unavailable_sentence() {
        let bodies: Vec<String> = CreationBlocked::EVERY
            .into_iter()
            .map(copy::did::explainer_body)
            .collect();
        for body in &bodies {
            assert!(!body.trim().is_empty(), "every reason needs a sentence");
            assert!(
                body.contains(copy::did::EXPLAINER_OPENING),
                "the shared opening must be composed in, not retyped: {body}"
            );
        }
        for (i, one) in bodies.iter().enumerate() {
            for other in &bodies[i + 1..] {
                assert_ne!(
                    one, other,
                    "two reasons share a body, so one of them is being explained wrongly"
                );
            }
        }
    }

    /// **The binary contains no sentence about whether minting is available.**
    ///
    /// Makes impossible: the dig_ecosystem#2560 defect returning. The tray explainer lived as a
    /// literal in `src/bin`, which no test can read, and kept a promise the wizard had already
    /// dropped for three releases — a rule is only ever as wide as the text it can see.
    ///
    /// Reads the SOURCE rather than the rendered output deliberately: the point is not that the
    /// current bin renders the right words, it is that the bin has no words of its own to get wrong.
    #[test]
    fn the_binary_states_nothing_about_minting_availability() {
        let bin = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("..")
            .join("dig-app")
            .join("src")
            .join("bin");
        let mut checked = 0usize;

        for entry in std::fs::read_dir(&bin).expect("the binary crate's bin directory") {
            let path = entry.expect("a readable directory entry").path();
            if path.extension().is_none_or(|ext| ext != "rs") {
                continue;
            }
            let source = std::fs::read_to_string(&path).expect("a readable source file");
            checked += 1;
            for claim in [
                "not available in this version",
                "when minting arrives",
                "Minting one is",
            ] {
                assert!(
                    !source.contains(claim),
                    "{} states \"{claim}\" itself; copy belongs in dig-app-core where a test can \
                     read it",
                    path.display()
                );
            }

            // A DIFFERENT defect in the same files, and the reason this loop is worth widening: a
            // string literal written through a shell heredoc loses its line-continuation backslash,
            // so what survives is an escaped newline followed by the source file's own indentation.
            // A person then reads a sentence with a gap torn through it — two shipped this way in
            // the WalletConnect notices, one of which read "Nothing                  was connected."
            //
            // The needle is ASSEMBLED rather than written, so this test cannot match itself; and it
            // is an escaped newline followed by TWO SPACES rather than an escaped newline alone,
            // because deliberate paragraph breaks ("\n\n") are ordinary and correct.
            let torn = format!("{}n  ", '\\');
            assert!(
                !source.contains(&torn),
                "{} holds a string literal with an escaped newline followed by source indentation \
                 — a heredoc ate its line continuation, and a person reads the gap. Write the \
                 literal with the editor, not a heredoc.",
                path.display()
            );
        }

        assert!(
            checked > 0,
            "the guard read no files at all, so it proves nothing about the binary"
        );
    }

    /// **A machine whose node CAN mint is never told this version cannot.**
    ///
    /// Makes impossible: the shipped constant. `did_explainer` composed its body from
    /// `CreationBlocked::NoChainTransport` unconditionally, so every reading produced the sentence
    /// *"On-chain minting is not available in this version"* — a claim about DIG that is false on a
    /// node serving both mint reads, which is the ordinary state of a healthy machine.
    ///
    /// The fixture varies ONE thing, the reading, and keeps a truthful control: the same sentence
    /// must STILL appear for a genuinely transport-less node. A test that merely banned the string
    /// would pass against an implementation that had deleted it everywhere, including where it is
    /// true — and deleting an honest sentence is not the deliverable.
    #[test]
    fn a_node_that_can_mint_is_never_told_this_version_cannot() {
        const THE_FALSE_CLAIM: &str = "not available in this version";

        let walks = did_explainer(Some(&ChainReadiness::WalksLineages)).body;
        assert!(
            !walks.contains(THE_FALSE_CLAIM),
            "a node that answered both mint reads was told the version cannot mint: {walks}"
        );

        let unreachable = did_explainer(Some(&ChainReadiness::NoChainTransport {
            why: "the node is not running".into(),
        }))
        .body;
        assert!(
            unreachable.contains(THE_FALSE_CLAIM),
            "the sentence must survive where it is TRUE, or this rule is a deletion: {unreachable}"
        );
    }

    /// **An unmeasured node is reported as unmeasured, not as a blocked one.**
    ///
    /// Makes impossible: rendering `None` as any of the three measured readings. A person whose node
    /// is merely stopped, told *this version cannot mint*, goes to wait for a release when what they
    /// need is to start their node (dig_ecosystem#2690). The four readings must be four distinct
    /// bodies, so the fixture compares all four rather than asserting one — a pair that collapsed
    /// would name a cause nobody observed, and no single-body assertion can see that.
    #[test]
    fn each_reading_of_the_node_gets_its_own_explanation() {
        let bodies = [
            ("not asked", did_explainer(None).body),
            (
                "walks lineages",
                did_explainer(Some(&ChainReadiness::WalksLineages)).body,
            ),
            (
                "no transport",
                did_explainer(Some(&ChainReadiness::NoChainTransport { why: "x".into() })).body,
            ),
            (
                "no lineage walk",
                did_explainer(Some(&ChainReadiness::NoLineageWalk { why: "x".into() })).body,
            ),
        ];

        for (i, (name, body)) in bodies.iter().enumerate() {
            for (other_name, other) in &bodies[i + 1..] {
                assert_ne!(
                    body, other,
                    "`{name}` and `{other_name}` share a body, so one of them explains the wrong                      thing"
                );
            }
        }
    }

    /// Every sentence of every screen the DID step can show, named so a rule can be held over all of
    /// them at once.
    ///
    /// The enumeration is the point. A rule is only ever as wide as the list it runs over, and the copy
    /// this module ships was wrong for three releases in the one place the list could not reach — a
    /// literal in `src/bin`, where no test can read it (dig_ecosystem#2560). Anything a person reads on
    /// this step belongs here, so a new screen is checked by every rule below the day it is written.
    ///
    /// The DID-only mint offer/wait/confirm sequence this used to also enumerate is retired
    /// (dig-app#210): [`did_explainer`]'s tray notice is the only DID-step screen left to hold this
    /// rule over.
    fn every_did_screen() -> Vec<(&'static str, String)> {
        vec![
            (
                "the tray's DID explainer",
                copy::did::explainer_body(CreationBlocked::NoChainTransport),
            ),
            (
                "the tray's DID explainer (no lineage walk)",
                copy::did::explainer_body(CreationBlocked::NoLineageWalk),
            ),
            (
                "the tray's DID explainer (nobody has asked yet)",
                copy::did::explainer_body_for(None),
            ),
            (
                "the tray's DID explainer (the node can mint)",
                copy::did::explainer_body_for(Some(&ChainReadiness::WalksLineages)),
            ),
        ]
    }

    /// Sentences, near enough for a copy rule: the unit a claim is made in.
    fn sentences(body: &str) -> impl Iterator<Item = &str> {
        body.split(['.', '\n'])
            .map(str::trim)
            .filter(|s| !s.is_empty())
    }

    /// **A DID screen may name the DIG menu only for something the menu actually does.**
    ///
    /// The decline screen used to end *"You can also start it any time from the DIG menu."* There is no
    /// such row — [`TrayAction::AboutDid`] is a notice that cannot call the wizard, and the rows nearest
    /// it (`ReplaceWithNewAccount`, `ReplaceFromPhrase`, `RemoveAccount`) DESTROY the account. The one
    /// sentence telling a hesitant person how to come back pointed them at losing their custody.
    ///
    /// # Why the rule is an allow-list and not a list of banned phrases
    ///
    /// Banned phrases only catch the wording that has already been wrong once; the next invented route
    /// will be worded differently and sail through. Here a sentence that names the menu must match a
    /// claim paired with the [`TrayAction`] that makes it true, so NEW copy is refused until its author
    /// finds the row — and if the row is later removed, the pairing stops compiling.
    #[test]
    fn a_did_screen_may_name_the_dig_menu_only_for_a_row_the_menu_has() {
        // The claim a sentence may make, and the row that makes it true. Denials need no row: telling
        // somebody the menu will NOT do a thing cannot send them anywhere.
        let justified: [(&str, Option<TrayAction>); 4] = [
            ("no row that starts this", None),
            ("log folder", Some(TrayAction::OpenLogs)),
            (
                "shows it and copies it",
                Some(TrayAction::CopyReceiveAddress),
            ),
            ("your DID is in the DIG menu", Some(TrayAction::CopyDigId)),
        ];

        for (screen, body) in every_did_screen() {
            for sentence in sentences(&body) {
                if !sentence.contains("DIG menu") {
                    continue;
                }
                assert!(
                    justified.iter().any(|(claim, _)| sentence.contains(claim)),
                    "{screen} sends the user to the DIG menu — \"{sentence}\" — and no row there does \
                     that. The menu has no way to start the DID step; the rows nearest it destroy the \
                     account."
                );
            }
        }
    }

    /// **No DID screen may say a DID is needed for something that works without one.**
    ///
    /// The decline screen used to say *"Publishing, signing for an app and messaging need a DID"*.
    /// Signing does not need one: [`Allowance::of`](crate::account::did::Allowance::of) is the app's
    /// only DID capability gate and no production surface consults it, so pairing another program with
    /// this account and signing for it work today on a wallet that has never minted. Reading content
    /// and holding funds are not identity-bearing at all
    /// ([`Capability`](crate::account::did::Capability)), so no screen may gate those on a DID either.
    #[test]
    fn a_screen_may_not_say_a_did_is_needed_for_something_that_works_without_one() {
        for (screen, body) in every_did_screen() {
            for sentence in sentences(&body) {
                if !sentence.contains("need a DID") && !sentence.contains("needs a DID") {
                    continue;
                }
                for works_anyway in ["read", "Read", "fund", "pair", "Pair", "sign", "Sign"] {
                    assert!(
                        !sentence.contains(works_anyway),
                        "{screen} says \"{sentence}\", which tells the user something they can do \
                         today needs a DID first"
                    );
                }
            }
        }
    }

    /// Run the wizard on a machine with no account at all, so the pre-existing first-run tests keep
    /// asserting the same flow.
    fn run_wizard(
        confirmer: &ScriptedConfirmer,
        create: impl FnOnce() -> Option<String>,
        import: impl FnOnce(&RecoveryPhrase) -> Option<String>,
    ) -> FirstRunOutcome {
        first_run_wizard(
            confirmer,
            AccountPresence::Absent,
            create,
            import,
            &RecordingCopier::working(),
        )
    }

    /// Approving the welcome and choosing "create a new account" (declining the phrase-import question)
    /// runs the creating step and finishes the flow, and the user's ACTUAL address reaches the screen.
    #[test]
    fn a_first_run_creates_the_wallet_and_shows_its_address() {
        // Orient=Approve, route=Deny (→ create), fund=Approve, DID=Approve.
        let confirmer = ScriptedConfirmer::new(
            vec![],
            vec![
                ConfirmDecision::Approve,
                ConfirmDecision::Deny,
                ConfirmDecision::Approve,
                ConfirmDecision::Approve,
            ],
        );
        let created = Mutex::new(false);

        let outcome = run_wizard(
            &confirmer,
            || {
                *created.lock().unwrap() = true;
                Some(ADDRESS.to_string())
            },
            never_imports,
        );

        assert_eq!(outcome, FirstRunOutcome::WalletCreated);
        assert!(*created.lock().unwrap(), "the creating step must have run");
        assert!(
            confirmer.drawn().contains(ADDRESS),
            "the account's own address must reach the screen, not a placeholder"
        );
    }

    /// Backing out of the welcome must create NOTHING.
    ///
    /// The recorded flag is the load-bearing assertion: checking only that the outcome is `Declined`
    /// would pass identically for an implementation that created an account and then reported a
    /// decline, which is the one behaviour a first run must never have.
    #[test]
    fn declining_the_welcome_never_reaches_the_creating_step() {
        let confirmer = ScriptedConfirmer::new(vec![], vec![ConfirmDecision::Deny]);
        let created = Mutex::new(false);

        let outcome = run_wizard(
            &confirmer,
            || {
                *created.lock().unwrap() = true;
                Some(ADDRESS.to_string())
            },
            never_imports,
        );

        assert_eq!(outcome, FirstRunOutcome::Declined);
        assert!(
            !*created.lock().unwrap(),
            "a declined welcome must not create an account"
        );
        assert_eq!(
            confirmer.windows_drawn(),
            1,
            "nothing after the welcome may be shown"
        );
    }

    /// The welcome is a CLAIM, not a notice: a one-button window would be a screen a person cannot say
    /// no to, at the exact moment they are being asked to commit to creating custody.
    #[test]
    fn the_welcome_offers_a_real_way_out() {
        let confirmer = ScriptedConfirmer::new(vec![], vec![ConfirmDecision::Deny]);
        run_wizard(&confirmer, || Some(ADDRESS.to_string()), never_imports);
        assert_eq!(confirmer.kinds(), vec!["claim"]);
    }

    /// A creating step that did not complete must not be followed by "your account is ready" — the
    /// screens after it are all statements about an account that does not exist.
    #[test]
    fn a_failed_creation_shows_no_success_screens() {
        // Orient=Approve, route=Deny (→ create); create returns None.
        let confirmer = ScriptedConfirmer::new(
            vec![],
            vec![ConfirmDecision::Approve, ConfirmDecision::Deny],
        );

        assert_eq!(
            run_wizard(&confirmer, || None, never_imports),
            FirstRunOutcome::Failed
        );
        assert_eq!(
            confirmer.windows_drawn(),
            2,
            "only the welcome and the route choice were drawn; the creating step reports its own failure"
        );
    }

    // ---- The DID gate, the QR fund step and the wait (dig_ecosystem#2341) -------------------------

    /// **The wizard is gated on the DID, not on the account.**
    ///
    /// The fixture is a machine that ALREADY has a wallet: the nearest wrong implementation — gate on
    /// "no account", which is what this wizard did before — skips the wizard entirely here, so the
    /// funding step never draws and this fails. A no-account fixture could not tell the two apart.
    #[test]
    fn a_wallet_with_no_did_still_gets_the_wizard_starting_at_the_funding_step() {
        let confirmer = ScriptedConfirmer::new(vec![], vec![ConfirmDecision::Approve; 4]);

        let outcome = first_run_wizard(
            &confirmer,
            AccountPresence::Wallet { address: ADDRESS },
            || panic!("an existing wallet must not be re-created"),
            never_imports,
            &RecordingCopier::working(),
        );

        assert_eq!(outcome, FirstRunOutcome::WalletCreated);
        assert!(
            confirmer.drawn().contains(ADDRESS),
            "the existing wallet's address must reach the funding step"
        );
        assert_eq!(
            confirmer.kinds().first(),
            Some(&"claim"),
            "an existing wallet skips the welcome and starts at the funding claim"
        );
    }

    /// **The funding step offers the address BOTH ways: as a scannable code and as the window's mono
    /// identifier.** A QR alone strands the person funding from a wallet on this same computer.
    #[test]
    fn the_funding_step_offers_the_address_as_a_code_and_as_text() {
        let confirmer = ScriptedConfirmer::drawing_qr(vec![ConfirmDecision::Approve; 4]);

        first_run_wizard(
            &confirmer,
            AccountPresence::Wallet { address: ADDRESS },
            || panic!("must not create"),
            never_imports,
            &RecordingCopier::working(),
        );

        let fund = confirmer
            .claim_values()
            .into_iter()
            .find(|(identifier, _)| identifier.as_deref() == Some(ADDRESS))
            .expect("the address must be the funding window's own identifier, not prose");
        assert!(
            fund.1,
            "a host that draws codes must be given one to draw for the funding step"
        );
    }

    /// On a host that draws no code, the funding copy must not point at a picture that is not there.
    ///
    /// The two hosts are driven through the SAME flow and their bodies compared, so an implementation
    /// that wrote one sentence for both would fail — asserting only on the QR-less host would pass for
    /// copy that always mentions scanning.
    #[test]
    fn a_host_that_draws_no_code_is_not_told_to_scan_one() {
        let mut bodies = Vec::new();
        for confirmer in [
            ScriptedConfirmer::new(vec![], vec![ConfirmDecision::Approve; 4]),
            ScriptedConfirmer::drawing_qr(vec![ConfirmDecision::Approve; 4]),
        ] {
            first_run_wizard(
                &confirmer,
                AccountPresence::Wallet { address: ADDRESS },
                || panic!("must not create"),
                never_imports,
                &RecordingCopier::working(),
            );
            bodies.push(confirmer.drawn().to_lowercase());
        }

        assert!(
            !bodies[0].contains("scan the code"),
            "a host with no code must not tell anyone to scan one: {}",
            bodies[0]
        );
        assert!(
            bodies[1].contains("scan the code"),
            "a host that draws a code should say so: {}",
            bodies[1]
        );
    }

    /// The funding step's second control COPIES the real address — the affordance for someone funding
    /// from a desktop wallet on this same machine, who cannot scan their own screen.
    #[test]
    fn the_funding_step_can_copy_the_address_to_the_clipboard() {
        // fund=Deny (→ copy), then the copy confirmation, then the mint offer.
        let confirmer = ScriptedConfirmer::new(
            vec![],
            vec![
                ConfirmDecision::Deny,
                ConfirmDecision::Approve,
                ConfirmDecision::Approve,
            ],
        );
        let copier = RecordingCopier::working();

        first_run_wizard(
            &confirmer,
            AccountPresence::Wallet { address: ADDRESS },
            || panic!("must not create"),
            never_imports,
            &copier,
        );

        assert_eq!(
            copier.copied(),
            vec![ADDRESS.to_string()],
            "the user's own address must be what reaches the clipboard"
        );
        assert!(
            confirmer
                .drawn()
                .to_lowercase()
                .contains("on the clipboard"),
            "a copy the user cannot see happen is not an affordance"
        );
    }

    /// A clipboard that refused must say so — and must not claim the address was copied.
    ///
    /// The claim-that-it-worked is the load-bearing half: a screen reading "copied" over an untouched
    /// clipboard sends someone to paste whatever was there before into a send field.
    #[test]
    fn a_clipboard_that_refuses_is_not_reported_as_a_copy() {
        let confirmer = ScriptedConfirmer::new(
            vec![],
            vec![
                ConfirmDecision::Deny,
                ConfirmDecision::Approve,
                ConfirmDecision::Approve,
            ],
        );

        first_run_wizard(
            &confirmer,
            AccountPresence::Wallet { address: ADDRESS },
            || panic!("must not create"),
            never_imports,
            &RecordingCopier::broken(),
        );

        let drawn = confirmer.drawn().to_lowercase();
        assert!(
            drawn.contains("could not"),
            "a failed copy must say so: {drawn}"
        );
        assert!(
            !drawn.contains("is on the clipboard"),
            "a failed copy must not claim the address was copied: {drawn}"
        );
    }

    // ---- The first-run IMPORT route (dig_ecosystem#1564) ------------------------------------------

    /// Choosing "I have a recovery phrase" routes into the import step and NEVER the create step — the
    /// #1564 gap was that a stranger holding a phrase had no way to restore at first run.
    ///
    /// The two recorded flags are the load-bearing part: an outcome of `WalletCreated` alone is
    /// satisfied identically by an implementation that ran CREATE, so the test pins which step ran.
    #[test]
    fn first_run_offers_import_and_takes_the_import_route() {
        // Orient=Approve, route=Approve (→ import), [phrase typed], fund=Approve, DID=Approve.
        let phrase = RecoveryPhrase::generate();
        let typed = phrase.words().join(" ");
        let confirmer = ScriptedConfirmer::new(
            vec![],
            vec![
                ConfirmDecision::Approve,
                ConfirmDecision::Approve,
                ConfirmDecision::Approve,
                ConfirmDecision::Approve,
            ],
        );
        *confirmer.typed.lock().unwrap() = vec![Some(typed)];

        let created = Mutex::new(false);
        let imported = Mutex::new(false);
        let outcome = run_wizard(
            &confirmer,
            || {
                *created.lock().unwrap() = true;
                Some(ADDRESS.to_string())
            },
            |_phrase| {
                *imported.lock().unwrap() = true;
                Some(ADDRESS.to_string())
            },
        );

        assert_eq!(outcome, FirstRunOutcome::WalletCreated);
        assert!(*imported.lock().unwrap(), "the import step must have run");
        assert!(
            !*created.lock().unwrap(),
            "the create step must NOT run on the import route"
        );
        assert!(confirmer.drawn().contains(ADDRESS));
    }

    /// The phrase the user TYPED must reach the import step UNCHANGED — the wizard's own responsibility.
    ///
    /// Asserted on the master seed, not the word strings, because that is the custody root a restore must
    /// reproduce (the same-identity guarantee itself is proven in `lifecycle`); a wizard that re-generated
    /// or truncated the phrase would hand `import` a different seed and fail here.
    #[test]
    fn importing_at_first_run_hands_the_typed_phrase_through_unchanged() {
        let phrase = RecoveryPhrase::generate();
        let expected_seed = phrase.master_seed();
        let confirmer = ScriptedConfirmer::new(vec![], vec![ConfirmDecision::Approve; 4]);
        *confirmer.typed.lock().unwrap() = vec![Some(phrase.words().join(" "))];

        let seen_seed: Mutex<Option<[u8; 32]>> = Mutex::new(None);
        let outcome = run_wizard(
            &confirmer,
            || panic!("must not create"),
            |imported| {
                *seen_seed.lock().unwrap() = Some(*imported.master_seed());
                Some(ADDRESS.to_string())
            },
        );

        assert_eq!(outcome, FirstRunOutcome::WalletCreated);
        assert_eq!(
            seen_seed.lock().unwrap().expect("import ran"),
            *expected_seed,
            "the wizard must pass the typed phrase's exact master seed to the restore step"
        );
    }

    /// Cancelling the phrase window on the import route creates NOTHING and reports `Declined`.
    #[test]
    fn cancelling_the_import_phrase_creates_nothing() {
        let confirmer = ScriptedConfirmer::new(
            vec![],
            vec![ConfirmDecision::Approve, ConfirmDecision::Approve],
        );
        *confirmer.typed.lock().unwrap() = vec![None]; // the user cancels the phrase window

        let imported = Mutex::new(false);
        let outcome = run_wizard(
            &confirmer,
            || panic!("must not create"),
            |_p| {
                *imported.lock().unwrap() = true;
                Some(ADDRESS.to_string())
            },
        );

        assert_eq!(outcome, FirstRunOutcome::Declined);
        assert!(
            !*imported.lock().unwrap(),
            "a cancelled phrase window must not enrol anything"
        );
    }

    /// An import step that could not complete reports `Failed`, not `WalletCreated`.
    #[test]
    fn a_failed_import_reports_failure() {
        let phrase = RecoveryPhrase::generate();
        let confirmer = ScriptedConfirmer::new(
            vec![],
            vec![ConfirmDecision::Approve, ConfirmDecision::Approve],
        );
        *confirmer.typed.lock().unwrap() = vec![Some(phrase.words().join(" "))];

        let outcome = run_wizard(&confirmer, || panic!("must not create"), |_p| None);
        assert_eq!(outcome, FirstRunOutcome::Failed);
    }

    // ---- The backup ceremony (dig_ecosystem#1564) -------------------------------------------------

    /// A [`PhraseBackupSink`] that records what it was handed and returns a scripted delivery.
    struct RecordingSink {
        delivery: BackupDelivery,
        got: Mutex<Option<(BackupTarget, String)>>,
    }

    impl RecordingSink {
        fn delivering(where_to: &str) -> Self {
            Self {
                delivery: BackupDelivery::Delivered {
                    where_to: where_to.to_string(),
                },
                got: Mutex::new(None),
            }
        }

        fn returning(delivery: BackupDelivery) -> Self {
            Self {
                delivery,
                got: Mutex::new(None),
            }
        }

        fn received(&self) -> Option<(BackupTarget, String)> {
            self.got.lock().unwrap().clone()
        }
    }

    impl PhraseBackupSink for RecordingSink {
        fn deliver(&self, target: BackupTarget, words: &str) -> BackupDelivery {
            *self.got.lock().unwrap() = Some((target, words.to_string()));
            self.delivery.clone()
        }
    }

    /// Approving the warning and the reveal gate delivers the EXACT 24 words to the sink, decrypting
    /// once.
    ///
    /// The fixture asserts the delivered string equals the space-joined phrase — not a substring, not the
    /// numbered block — so an implementation that handed the sink the numbered display form, a partial
    /// phrase, or anything else would fail here.
    #[test]
    fn backup_copies_words_and_warns() {
        let dir = tempfile::tempdir().unwrap();
        let vault = vault(dir.path());
        let phrase = RecoveryPhrase::generate();
        vault.store(&phrase).unwrap();
        // reveal gate = Approve; notices = [warning Approve, success-notice Approve].
        let confirmer = ScriptedConfirmer::new(
            vec![ConfirmDecision::Approve],
            vec![ConfirmDecision::Approve, ConfirmDecision::Approve],
        );
        let sink = RecordingSink::delivering("your clipboard");

        let outcome = back_up_phrase(&confirmer, &vault, BackupTarget::Clipboard, &sink);

        assert_eq!(outcome, BackupOutcome::BackedUp);
        let (target, words) = sink
            .received()
            .expect("the sink must have been handed the words");
        assert_eq!(target, BackupTarget::Clipboard);
        assert_eq!(
            words,
            phrase.words().join(" "),
            "the sink must receive the exact space-joined 24 words"
        );
        assert_eq!(
            vault.sealer_for_test().opens(),
            1,
            "the phrase is decrypted exactly once, only after both approvals"
        );
        assert!(
            confirmer.drawn().contains("PLAIN TEXT"),
            "a stark unencrypted-storage warning must reach the screen before the copy"
        );
    }

    /// Refusing the warning delivers NOTHING and never even reaches the reveal gate or the vault.
    ///
    /// The control makes it load-bearing: the reveal script is `Approve`, so if the code reached the gate
    /// it would approve and then decrypt (opens == 1). `opens == 0` AND the absence of a `REVEAL-GATE`
    /// window together prove the warning short-circuits BEFORE both — a placement no outcome-only
    /// assertion could pin.
    #[test]
    fn refusing_the_backup_warning_never_reveals_or_delivers() {
        let dir = tempfile::tempdir().unwrap();
        let vault = vault(dir.path());
        vault.store(&RecoveryPhrase::generate()).unwrap();
        let confirmer = ScriptedConfirmer::new(
            vec![ConfirmDecision::Approve], // would approve the gate, if it were ever reached
            vec![ConfirmDecision::Deny],    // the warning is refused
        );
        let sink = RecordingSink::delivering("your clipboard");

        assert_eq!(
            back_up_phrase(&confirmer, &vault, BackupTarget::Clipboard, &sink),
            BackupOutcome::Refused
        );
        assert!(
            sink.received().is_none(),
            "a refused warning must not deliver"
        );
        assert_eq!(
            vault.sealer_for_test().opens(),
            0,
            "a refused warning must run before the phrase is decrypted"
        );
        assert!(
            !confirmer.kinds().contains(&"REVEAL-GATE"),
            "the reveal gate must not even be drawn when the warning is refused"
        );
    }

    /// Refusing the reveal gate (after approving the warning) delivers NOTHING and never decrypts — the
    /// same placement property `reveal_phrase` has, now for the backup path.
    #[test]
    fn refusing_the_reveal_gate_never_delivers_the_words() {
        let dir = tempfile::tempdir().unwrap();
        let vault = vault(dir.path());
        vault.store(&RecoveryPhrase::generate()).unwrap();
        let confirmer = ScriptedConfirmer::new(
            vec![ConfirmDecision::Deny],    // the gate is refused
            vec![ConfirmDecision::Approve], // the warning is approved
        );
        let sink = RecordingSink::delivering("your clipboard");

        assert_eq!(
            back_up_phrase(&confirmer, &vault, BackupTarget::Clipboard, &sink),
            BackupOutcome::Refused
        );
        assert!(sink.received().is_none());
        assert_eq!(
            vault.sealer_for_test().opens(),
            0,
            "a refused gate must run BEFORE the phrase is decrypted, not after"
        );
        assert!(
            confirmer.kinds().contains(&"REVEAL-GATE"),
            "the gate must have been drawn (and refused) after the approved warning"
        );
    }

    /// A legacy account with no stored phrase reports it distinctly, and hands the sink nothing.
    #[test]
    fn backing_up_a_phraseless_account_reports_no_phrase() {
        let dir = tempfile::tempdir().unwrap();
        let confirmer = ScriptedConfirmer::new(
            vec![ConfirmDecision::Approve],
            vec![ConfirmDecision::Approve],
        );
        let sink = RecordingSink::delivering("your clipboard");

        assert_eq!(
            back_up_phrase(&confirmer, &vault(dir.path()), BackupTarget::File, &sink),
            BackupOutcome::NoPhraseStored
        );
        assert!(sink.received().is_none());
    }

    /// Each destination's warning names its OWN unencrypted-storage risk — a single generic warning would
    /// tell a file-saver about a clipboard and vice versa. Asserted on the private copy directly.
    #[test]
    fn the_backup_warnings_name_the_destination_and_plaintext() {
        let clip = backup_warning(BackupTarget::Clipboard);
        assert!(clip.heading.contains("PLAIN TEXT"));
        assert!(
            clip.body.to_lowercase().contains("clipboard"),
            "the clipboard warning must name the clipboard: {}",
            clip.body
        );

        let file = backup_warning(BackupTarget::File);
        assert!(file.heading.contains("UNENCRYPTED"));
        assert!(
            file.body.to_lowercase().contains("file"),
            "the file warning must name the file: {}",
            file.body
        );
    }

    /// A cancel at the destination (a dismissed save dialog) is a refusal, and the words — though
    /// decrypted and offered — are never confirmed as backed up.
    #[test]
    fn a_cancelled_destination_is_a_refusal() {
        let dir = tempfile::tempdir().unwrap();
        let vault = vault(dir.path());
        vault.store(&RecoveryPhrase::generate()).unwrap();
        let confirmer = ScriptedConfirmer::new(
            vec![ConfirmDecision::Approve],
            vec![ConfirmDecision::Approve],
        );
        let sink = RecordingSink::returning(BackupDelivery::Cancelled);

        assert_eq!(
            back_up_phrase(&confirmer, &vault, BackupTarget::File, &sink),
            BackupOutcome::Refused
        );
        assert!(
            sink.received().is_some(),
            "a cancel is reported by the sink, so it must have been called"
        );
    }

    /// A failed destination write reports `Unavailable`, not success.
    #[test]
    fn a_failed_destination_is_unavailable() {
        let dir = tempfile::tempdir().unwrap();
        let vault = vault(dir.path());
        vault.store(&RecoveryPhrase::generate()).unwrap();
        let confirmer = ScriptedConfirmer::new(
            vec![ConfirmDecision::Approve],
            vec![ConfirmDecision::Approve, ConfirmDecision::Approve],
        );
        let sink = RecordingSink::returning(BackupDelivery::Failed);

        assert_eq!(
            back_up_phrase(&confirmer, &vault, BackupTarget::File, &sink),
            BackupOutcome::Unavailable
        );
    }

    /// What a claim's window will do with a bare Enter, and what its negative control is called.
    fn safe_side(prompt: &ClaimPrompt<'_>) -> (bool, Option<&'static str>) {
        let content = crate::confirm::ConfirmContent::claim(prompt);
        match content.presentation {
            crate::confirm::Presentation::Decide { refusal_is_default } => {
                (refusal_is_default, content.decline)
            }
            other => panic!("a claim must be a two-choice window, got {other:?}"),
        }
    }

    /// **A bare Enter on the first-run route fork must not create an account.**
    ///
    /// This is the one claim in the app where BOTH controls act: affirming imports an existing
    /// phrase, and DECLINING generates and seals a brand-new master seed. Applying the ordinary
    /// claim rule here — pre-select the refusal, because nobody asks to make a claim — puts a new
    /// account one keystroke away, behind a control that would otherwise be labelled "Cancel"
    /// (dig_ecosystem#2074).
    #[test]
    fn a_bare_enter_on_the_first_run_route_fork_does_not_create_an_account() {
        let (refusal_is_default, decline) = safe_side(&route_fork());
        assert!(
            !refusal_is_default,
            "the route fork pre-selects its negative control, and that control CREATES AND SEALS A              NEW MASTER ACCOUNT — the refusal is only the safe default where refusing does nothing"
        );
        assert_eq!(
            decline,
            Some("Create a new account"),
            "the control that creates a brand-new account must say so, not read \"Cancel\""
        );
    }

    /// **Every OTHER claim still pre-selects its refusal.**
    ///
    /// The companion to the test above: making the fork an exception must not quietly become an
    /// exemption for the claims the rule exists for. Driven through the REAL prompts the enrolment
    /// flow builds, so a call site that flips back is caught here rather than in review.
    #[test]
    fn the_claims_that_assert_something_still_refuse_on_a_bare_enter() {
        for (what, prompt) in [
            (
                "the clipboard backup warning",
                backup_warning(BackupTarget::Clipboard),
            ),
            (
                "the file backup warning",
                backup_warning(BackupTarget::File),
            ),
            // The three most custody-critical claims, previously built inline and so unreachable from
            // this guard — flipping any of them left the suite green (dig_ecosystem#2098). The body of
            // the first is a runtime string; its content does not affect the guard, so a stand-in is
            // fine here.
            (
                "the recovery-phrase display claim",
                phrase_written_down_claim("<the 24 words>"),
            ),
            (
                "the saved-it confirmation claim",
                phrase_saved_confirmation_claim(),
            ),
            ("the pre-destroy last-look claim", last_look_claim()),
        ] {
            let (refusal_is_default, _) = safe_side(&prompt);
            assert!(
                refusal_is_default,
                "a bare Enter affirms {what} — which puts the 24 words somewhere in plain text on behalf of somebody who only pressed a key"
            );
        }
    }

    /// A confirmer that plays a SCRIPT of decisions and records every window it drew.
    ///
    /// A script (not a single fixed answer) is what lets the tests distinguish "asked twice" from
    /// "asked once and reused the answer" — a double that could only return one value could not express
    /// a user who acknowledges the words and then backs out of the confirmation.
    struct ScriptedConfirmer {
        reveal: Mutex<Vec<ConfirmDecision>>,
        /// Answers for the DESTROY gate, on its own script so a test can approve every ordinary window and
        /// still refuse the destruction — the combination that distinguishes "asked" from "acted".
        destroy: Mutex<Vec<ConfirmDecision>>,
        /// What the user "types", per input window. `None` models a cancel.
        typed: Mutex<Vec<Option<String>>>,
        notices: Mutex<Vec<ConfirmDecision>>,
        drawn: Mutex<Vec<String>>,
        /// Which SEAM each window came through, in order — `"notice"` (one button) or `"claim"` (two).
        ///
        /// Recorded because the seam IS the user-visible presentation (dig_ecosystem#1773): a screen sent
        /// through `show_notice` gets one button and an information icon on every platform, and a screen sent
        /// through `confirm_claim` gets a real way out. A test that only inspected the drawn TEXT could not
        /// tell the two apart, which is exactly how every tray message came to be drawn as a warning with a
        /// meaningless Cancel.
        kinds: Mutex<Vec<&'static str>>,
        /// Whether this confirmer claims it will DRAW a scannable code, so a test can drive both the
        /// host that shows a QR and the host whose text address is the whole path.
        draws_qr: bool,
        /// The `identifier`/`scannable` of every claim drawn, in order.
        ///
        /// Recorded separately from [`Self::drawn`] because neither reaches the body text: an
        /// assertion on the drawn prose cannot tell an address set as the window's mono identifier
        /// from one buried in a paragraph, nor see whether a code was offered at all.
        claim_values: Mutex<Vec<(Option<String>, bool)>>,
    }

    impl ScriptedConfirmer {
        fn new(reveal: Vec<ConfirmDecision>, notices: Vec<ConfirmDecision>) -> Self {
            Self {
                reveal: Mutex::new(reveal),
                destroy: Mutex::new(Vec::new()),
                typed: Mutex::new(Vec::new()),
                notices: Mutex::new(notices),
                drawn: Mutex::new(Vec::new()),
                kinds: Mutex::new(Vec::new()),
                draws_qr: false,
                claim_values: Mutex::new(Vec::new()),
            }
        }

        /// The same scripted confirmer on a host that DRAWS the scannable code.
        fn drawing_qr(notices: Vec<ConfirmDecision>) -> Self {
            Self {
                draws_qr: true,
                ..Self::new(vec![], notices)
            }
        }

        /// The `(identifier, had_a_scannable)` of every claim drawn, in order.
        fn claim_values(&self) -> Vec<(Option<String>, bool)> {
            self.claim_values.lock().unwrap().clone()
        }

        /// A confirmer that approves every ordinary window, answers the destroy gate with `destroy`, and
        /// hands back `typed` from successive input windows.
        fn destroying(destroy: Vec<ConfirmDecision>, typed: Vec<Option<String>>) -> Self {
            Self {
                destroy: Mutex::new(destroy),
                typed: Mutex::new(typed),
                reveal: Mutex::new(vec![ConfirmDecision::Approve; 4]),
                notices: Mutex::new(vec![ConfirmDecision::Approve; 8]),
                drawn: Mutex::new(Vec::new()),
                kinds: Mutex::new(Vec::new()),
                draws_qr: false,
                claim_values: Mutex::new(Vec::new()),
            }
        }

        /// The seams every window was drawn through, in order.
        fn kinds(&self) -> Vec<&'static str> {
            self.kinds.lock().unwrap().clone()
        }

        fn notices() -> Self {
            Self::new(vec![], vec![ConfirmDecision::Approve; 4])
        }

        /// Everything ever drawn, concatenated — used to assert the words did (or did not) reach a
        /// window.
        fn drawn(&self) -> String {
            self.drawn.lock().unwrap().join("\n")
        }

        fn windows_drawn(&self) -> usize {
            self.drawn.lock().unwrap().len()
        }
    }

    impl NativeConfirmer for ScriptedConfirmer {
        fn confirm_pair(&self, _p: &PairPrompt<'_>) -> ConfirmDecision {
            ConfirmDecision::Unavailable
        }
        fn confirm_connect(&self, _p: &ConnectPrompt<'_>) -> ConfirmDecision {
            ConfirmDecision::Unavailable
        }
        fn confirm_sign(&self, _p: &SignPrompt<'_>) -> ConfirmDecision {
            ConfirmDecision::Unavailable
        }
        fn confirm_reveal(&self, prompt: &RevealPrompt<'_>) -> ConfirmDecision {
            self.kinds.lock().unwrap().push("REVEAL-GATE");
            self.drawn
                .lock()
                .unwrap()
                .push(format!("REVEAL-GATE {}", prompt.secret));
            let mut script = self.reveal.lock().unwrap();
            if script.is_empty() {
                ConfirmDecision::Deny
            } else {
                script.remove(0)
            }
        }
        fn show_notice(&self, prompt: &NoticePrompt<'_>) -> ConfirmDecision {
            self.record(
                "notice",
                prompt.title,
                prompt.heading,
                &with_identifier(prompt.body, prompt.identifier),
            );
            self.next_window_answer()
        }

        fn confirm_claim(&self, prompt: &ClaimPrompt<'_>) -> ConfirmDecision {
            self.record(
                "claim",
                prompt.title,
                prompt.heading,
                &with_identifier(prompt.body, prompt.identifier),
            );
            self.claim_values.lock().unwrap().push((
                prompt.identifier.map(str::to_owned),
                prompt.scannable.is_some(),
            ));
            self.next_window_answer()
        }

        fn draws_qr(&self) -> bool {
            self.draws_qr
        }

        fn confirm_destroy(&self, prompt: &DestroyPrompt<'_>) -> ConfirmDecision {
            // Recorded under its OWN seam name, because the seam IS the security property under test: an
            // implementation that routed a destroy through `show_notice` would look identical in the drawn
            // TEXT and be catastrophically weaker (one button, no biometric).
            self.record(
                "DESTROY-GATE",
                "DIG - Destroy",
                prompt.subject,
                prompt.replacement,
            );
            let mut script = self.destroy.lock().unwrap();
            if script.is_empty() {
                ConfirmDecision::Deny
            } else {
                script.remove(0)
            }
        }

        fn request_input(&self, prompt: &InputPrompt<'_>) -> InputOutcome {
            self.record("input", prompt.title, prompt.heading, prompt.body);
            let mut script = self.typed.lock().unwrap();
            if script.is_empty() {
                InputOutcome::Cancelled
            } else {
                match script.remove(0) {
                    Some(text) => InputOutcome::Provided(zeroize::Zeroizing::new(text)),
                    None => InputOutcome::Cancelled,
                }
            }
        }
    }

    /// What a window actually PUT ON SCREEN: its prose plus its one bare identifier.
    ///
    /// The identifier is a separate field on the prompt because the window sets it in Space Mono — but
    /// it is displayed all the same, so a recording that dropped it would report the funding step as
    /// showing no address at all.
    fn with_identifier(body: &str, identifier: Option<&str>) -> String {
        match identifier {
            Some(value) => format!(
                "{body}
{value}"
            ),
            None => body.to_owned(),
        }
    }

    impl ScriptedConfirmer {
        /// Note that a window was drawn, through which seam, and what it displayed.
        fn record(&self, kind: &'static str, title: &str, heading: &str, body: &str) {
            self.kinds.lock().unwrap().push(kind);
            self.drawn
                .lock()
                .unwrap()
                .push(format!("{title}\n{heading}\n{body}"));
        }

        /// The next scripted answer for a drawn window.
        ///
        /// Notices and claims share ONE script on purpose: the flows under test draw them in a fixed
        /// sequence, and a shared script keeps "the third window the user saw" expressible whichever kind it
        /// was — which is what lets `setup_shows_the_words_and_asks_twice…` distinguish two screens from one.
        /// Running dry answers `Deny`, so an unexpected extra window fails rather than passing silently.
        fn next_window_answer(&self) -> ConfirmDecision {
            let mut script = self.notices.lock().unwrap();
            if script.is_empty() {
                ConfirmDecision::Deny
            } else {
                script.remove(0)
            }
        }
    }

    /// A sealer good enough to exercise the vault end of the journey; cross-profile isolation is proven
    /// in the vault's own tests, so this one only needs to round-trip and to be lockable.
    /// It also COUNTS decryptions, which is the load-bearing part. "The gate runs before the vault is
    /// opened" is a statement about PLACEMENT, and a test that only checks the returned outcome — or even
    /// that no words reached a window — is satisfied identically by a gate placed AFTER the decryption.
    /// Only the decryption count changes when the guard moves.
    #[derive(Default)]
    struct PassthroughSealer {
        locked: Mutex<bool>,
        opens: Mutex<usize>,
    }

    impl PassthroughSealer {
        fn opens(&self) -> usize {
            *self.opens.lock().unwrap()
        }
    }

    impl ProfileSealer for PassthroughSealer {
        fn seal(&self, _did: &str, plaintext: &[u8]) -> Result<Vec<u8>, SealError> {
            if *self.locked.lock().unwrap() {
                return Err(SealError::Seal("locked".into()));
            }
            Ok(plaintext.to_vec())
        }
        fn open(&self, _did: &str, ciphertext: &[u8]) -> Result<Zeroizing<Vec<u8>>, SealError> {
            *self.opens.lock().unwrap() += 1;
            if *self.locked.lock().unwrap() {
                return Err(SealError::Open);
            }
            Ok(Zeroizing::new(ciphertext.to_vec()))
        }
    }

    const DID: &str = "did:chia:journey";

    fn vault(dir: &std::path::Path) -> PhraseVault<PassthroughSealer> {
        PhraseVault::new(PassthroughSealer::default(), dir, DID)
    }

    #[test]
    fn setup_shows_the_words_and_asks_twice_before_confirming_retention() {
        let confirmer = ScriptedConfirmer::notices();
        let phrase = RecoveryPhrase::generate();

        let decision = WindowedPresenter::new(&confirmer).present_new_phrase(&phrase);

        assert_eq!(decision, RetentionDecision::Confirmed);
        assert_eq!(
            confirmer.windows_drawn(),
            2,
            "one acknowledgement is a reflex; the retention claim needs its own screen"
        );
        // Matched as the whole numbered block, not per word: a per-word presence check would be satisfied
        // by prompt copy that happens to contain a BIP-39 word (`act` sits inside "redacted", `cover`
        // inside "recovery"), so it could pass without the phrase ever being drawn.
        assert!(
            drew_the_words(&confirmer, &phrase),
            "the generated words must reach the screen, in full and in order"
        );
    }

    /// Backing out of the FIRST screen declines. The fixture scripts a decline followed by an approve,
    /// so an implementation that ignored the first answer and used the second would fail here.
    #[test]
    fn dismissing_the_words_screen_declines() {
        let confirmer = ScriptedConfirmer::new(
            vec![],
            vec![ConfirmDecision::Deny, ConfirmDecision::Approve],
        );

        assert_eq!(
            WindowedPresenter::new(&confirmer).present_new_phrase(&RecoveryPhrase::generate()),
            RetentionDecision::Declined
        );
        assert_eq!(
            confirmer.windows_drawn(),
            1,
            "the second screen must not be shown after a decline"
        );
    }

    /// Backing out of the SECOND screen also declines — the case a single-screen flow could not express,
    /// and the reason the second screen exists.
    #[test]
    fn backing_out_of_the_retention_screen_declines() {
        let confirmer = ScriptedConfirmer::new(
            vec![],
            vec![ConfirmDecision::Approve, ConfirmDecision::Deny],
        );

        assert_eq!(
            WindowedPresenter::new(&confirmer).present_new_phrase(&RecoveryPhrase::generate()),
            RetentionDecision::Declined
        );
        assert_eq!(confirmer.windows_drawn(), 2);
    }

    /// A host with no confirm surface reports `Unavailable`, NOT `Declined` — the distinction matters
    /// because enrolment refuses on both, but only one of them is the user's choice.
    #[test]
    fn a_host_that_cannot_draw_the_words_reports_unavailable() {
        let confirmer = ScriptedConfirmer::new(vec![], vec![ConfirmDecision::Unavailable]);
        assert_eq!(
            WindowedPresenter::new(&confirmer).present_new_phrase(&RecoveryPhrase::generate()),
            RetentionDecision::Unavailable
        );
    }

    #[test]
    fn revealing_shows_the_stored_words_after_the_gate_approves() {
        let dir = tempfile::tempdir().unwrap();
        let vault = vault(dir.path());
        let phrase = RecoveryPhrase::generate();
        vault.store(&phrase).unwrap();
        let confirmer = ScriptedConfirmer::new(
            vec![ConfirmDecision::Approve],
            vec![ConfirmDecision::Approve],
        );

        assert_eq!(reveal_phrase(&confirmer, &vault), RevealOutcome::Shown);
        // The control for the placement test below: an APPROVED reveal decrypts exactly once, so a count
        // of zero there is a real observation rather than a counter that never moves.
        assert_eq!(vault.sealer_for_test().opens(), 1);
        assert!(
            drew_the_words(&confirmer, &phrase),
            "the stored words must reach a window"
        );
    }

    /// **A placement assertion, and it needs the right observable.** "The gate runs before the vault is
    /// opened" is a statement about WHERE the guard sits, and the tempting assertions — the outcome is
    /// `Refused`, no words reached a window — are satisfied IDENTICALLY by a gate placed after the
    /// decryption. Moving the guard below `vault.load()` leaves both of those green.
    ///
    /// The one observable that moves is whether the ciphertext was decrypted at all, which is why the test
    /// sealer counts its `open` calls. Verified by reverting exactly that ordering: with the count
    /// asserted the test fails, without it the test passes on the wrong placement.
    #[test]
    fn a_refused_gate_never_opens_the_vault() {
        let dir = tempfile::tempdir().unwrap();
        let vault = vault(dir.path());
        let phrase = RecoveryPhrase::generate();
        vault.store(&phrase).unwrap();
        let confirmer =
            ScriptedConfirmer::new(vec![ConfirmDecision::Deny], vec![ConfirmDecision::Approve]);

        assert_eq!(reveal_phrase(&confirmer, &vault), RevealOutcome::Refused);
        assert_eq!(
            vault.sealer_for_test().opens(),
            0,
            "a refused gate must run BEFORE the phrase is decrypted, not after"
        );
        assert_eq!(
            confirmer.windows_drawn(),
            1,
            "only the gate should have been drawn — no words window"
        );
        assert!(
            !drew_the_words(&confirmer, &phrase),
            "the words leaked past a refused gate"
        );
    }

    /// Whether the words window was drawn, matched on the WHOLE phrase as one numbered block.
    ///
    /// A per-word substring search over everything drawn is quietly wrong: BIP-39 words are ordinary
    /// English, and several are substrings of the prompt copy itself — `cover` sits inside "recovery",
    /// `over` inside "recover". Such a check reports a leak at random depending on which words were
    /// generated. Matching the rendered block is exact.
    fn drew_the_words(confirmer: &ScriptedConfirmer, phrase: &RecoveryPhrase) -> bool {
        confirmer.drawn().contains(&*phrase.numbered_lines())
    }

    /// An unavailable authenticator refuses too — a machine with no Hello/Touch ID must not become a
    /// machine where anyone can read the phrase.
    #[test]
    fn an_unavailable_authenticator_refuses_the_reveal() {
        let dir = tempfile::tempdir().unwrap();
        let vault = vault(dir.path());
        vault.store(&RecoveryPhrase::generate()).unwrap();
        let confirmer = ScriptedConfirmer::new(
            vec![ConfirmDecision::Unavailable],
            vec![ConfirmDecision::Approve],
        );

        assert_eq!(reveal_phrase(&confirmer, &vault), RevealOutcome::Refused);
        assert_eq!(
            vault.sealer_for_test().opens(),
            0,
            "an unavailable authenticator must not decrypt the phrase either"
        );
    }

    /// A legacy account is distinguished from a broken one, because the tray offers different things.
    #[test]
    fn an_account_with_no_stored_phrase_reports_it_distinctly() {
        let dir = tempfile::tempdir().unwrap();
        let confirmer = ScriptedConfirmer::new(
            vec![ConfirmDecision::Approve],
            vec![ConfirmDecision::Approve],
        );

        assert_eq!(
            reveal_phrase(&confirmer, &vault(dir.path())),
            RevealOutcome::NoPhraseStored
        );
    }

    #[test]
    fn a_locked_vault_reports_unavailable_rather_than_no_phrase() {
        let dir = tempfile::tempdir().unwrap();
        let vault = vault(dir.path());
        vault.store(&RecoveryPhrase::generate()).unwrap();
        *vault_sealer_lock(&vault) = true;
        let confirmer = ScriptedConfirmer::new(
            vec![ConfirmDecision::Approve],
            vec![ConfirmDecision::Approve],
        );

        assert_eq!(
            reveal_phrase(&confirmer, &vault),
            RevealOutcome::Unavailable
        );
    }

    /// Reach into the test sealer's lock flag. A helper rather than a method on the vault, because
    /// production code has no business locking a sealer from the outside.
    fn vault_sealer_lock<'a>(
        vault: &'a PhraseVault<PassthroughSealer>,
    ) -> std::sync::MutexGuard<'a, bool> {
        vault.sealer_for_test().locked.lock().unwrap()
    }

    /// **Regression (#1773).** Both enrolment screens are real either/ors, so both must go through the
    /// two-button CLAIM seam — a Cancel here abandons setup, which is a decision the user must be able to
    /// make.
    ///
    /// This asserts the SEAM, not the returned decision: `RetentionDecision::Declined` comes back
    /// identically whichever seam drew the window, so an implementation that routed these through
    /// `show_notice` — one button, nothing to decline, the user trapped into "yes" — would leave every
    /// other test in this module green. Only the seam changes.
    #[test]
    fn both_enrolment_screens_offer_a_real_way_out() {
        let confirmer = ScriptedConfirmer::notices();

        WindowedPresenter::new(&confirmer).present_new_phrase(&RecoveryPhrase::generate());

        assert_eq!(
            confirmer.kinds(),
            vec!["claim", "claim"],
            "declining either enrolment screen abandons setup, so neither may be a one-button notice"
        );
    }

    /// The control that makes the test above load-bearing: the purely informational screens go through the
    /// ONE-button notice seam. Without this pair, routing every window through `confirm_claim` — the old
    /// behaviour, a Cancel on "here are your words" that no caller reads — would satisfy the test above.
    #[test]
    fn the_informational_screens_are_one_button_notices() {
        let dir = tempfile::tempdir().unwrap();
        let vault = vault(dir.path());
        vault.store(&RecoveryPhrase::generate()).unwrap();
        let confirmer = ScriptedConfirmer::new(
            vec![ConfirmDecision::Approve],
            vec![ConfirmDecision::Approve],
        );

        assert_eq!(reveal_phrase(&confirmer, &vault), RevealOutcome::Shown);
        assert_eq!(
            confirmer.kinds(),
            vec!["REVEAL-GATE", "notice"],
            "the reveal is gated (two choices), then the words are merely displayed (one)"
        );

        let explainer = ScriptedConfirmer::notices();
        explain_missing_phrase(&explainer);
        assert_eq!(
            explainer.kinds(),
            vec!["notice"],
            "an explanation asks nothing, so it offers one dismissal"
        );
    }

    /// The legacy explainer must name the CONSEQUENCE and must not act. Asserting the copy mentions the
    /// irreversibility is the only machine-checkable part of "told honestly"; the "does not act" half is
    /// structural — the function returns a decision and touches no store.
    #[test]
    fn the_missing_phrase_explainer_names_the_consequence_and_changes_nothing() {
        let confirmer = ScriptedConfirmer::notices();

        assert_eq!(explain_missing_phrase(&confirmer), ConfirmDecision::Approve);
        let drawn = confirmer.drawn().to_lowercase();
        assert!(drawn.contains("cannot be recovered"));
        assert!(drawn.contains("new identity and address"));
        assert!(drawn.contains("nothing has changed yet"));
    }

    // ---- The destructive verbs (dig_ecosystem#1799). ----

    /// **The custody guard.** Destroying an account MUST go through the AUTHORIZATION seam — a window plus
    /// a biometric — never a notice or a claim.
    ///
    /// Asserted on the SEAM the window was drawn through, not on its text, because that is the property: a
    /// destroy routed through `show_notice` would display the same warning, offer one button, run no
    /// biometric, and be catastrophically weaker. A text-only assertion cannot tell the two apart, which is
    /// exactly how eleven tray messages came to be drawn as warnings with a meaningless Cancel (#1773).
    #[test]
    fn destroying_an_account_is_authorized_through_the_biometric_gate() {
        let confirmer = ScriptedConfirmer::destroying(vec![ConfirmDecision::Approve], vec![]);
        let ruling = authorize_destroy(
            &confirmer,
            Replacement::WithNewAccount,
            None::<&PhraseVault<PassthroughSealer>>,
        );

        assert_eq!(ruling, DestroyRuling::Authorized);
        assert!(
            confirmer.kinds().contains(&"DESTROY-GATE"),
            "the destroy must ride the authorization seam, not a notice: {:?}",
            confirmer.kinds()
        );
        assert!(
            !confirmer.kinds().contains(&"notice"),
            "a notice cannot authorize anything: {:?}",
            confirmer.kinds()
        );
    }

    // ---- The locked break glass (dig-app#349). ----

    /// **The boundary this feature turns on.** On a locked account with an unjudgeable second factor,
    /// only REMOVAL is offered; replacing is refused outright.
    ///
    /// The distinction is the whole rule. Removing destroys the seed and the enrolment together, so an
    /// attacker gains nothing they can return and use. Replacing would leave a WORKING account on the
    /// machine with the gate silently gone — de-gating with extra steps, and worse than destruction
    /// precisely because its owner cannot tell it happened.
    ///
    /// Both halves are asserted, and the refusing half asserts that NO WINDOW WAS DRAWN. Checking only
    /// the ruling would pass against a version that drew the destroy-everything window, let the user
    /// approve it, and then declined — teaching them the confirmation is decorative.
    #[test]
    fn the_locked_break_glass_is_offered_for_removal_only() {
        for what in [Replacement::WithNewAccount, Replacement::FromPhrase] {
            let confirmer = ScriptedConfirmer::destroying(vec![ConfirmDecision::Approve], vec![]);
            assert_eq!(
                authorize_locked_break_glass(&confirmer, what),
                LockedFactorRuling::NotAvailableWhileLocked,
                "{what:?} would leave a usable account with its gate deleted"
            );
            assert!(
                confirmer.kinds().is_empty(),
                "{what:?}: a confirmation that will not be honoured must not be drawn: {:?}",
                confirmer.kinds()
            );
        }

        // The control. Without it the loop above passes against a version that refuses everything and
        // leaves a lost-password account permanently unremovable.
        let confirmer = ScriptedConfirmer::destroying(vec![ConfirmDecision::Approve], vec![]);
        assert_eq!(
            authorize_locked_break_glass(&confirmer, Replacement::Nothing),
            LockedFactorRuling::BreakGlass
        );
        assert!(
            confirmer.kinds().contains(&"claim"),
            "the break glass must state what it destroys before it is taken: {:?}",
            confirmer.kinds()
        );
    }

    /// Every non-approving answer to the break-glass window declines it, so a timeout or a window that
    /// could not be drawn can never destroy an account nothing can recover.
    #[test]
    fn every_non_approval_declines_the_locked_break_glass() {
        for answer in [
            ConfirmDecision::Deny,
            ConfirmDecision::Timeout,
            ConfirmDecision::Unavailable,
        ] {
            let confirmer = ScriptedConfirmer::destroying(vec![], vec![]);
            *confirmer.notices.lock().unwrap() = vec![answer];
            assert_eq!(
                authorize_locked_break_glass(&confirmer, Replacement::Nothing),
                LockedFactorRuling::Declined,
                "{answer:?} must not destroy an account"
            );
        }
    }

    /// The break-glass window must name the SECOND FACTOR among what it destroys, and must not be a
    /// reflexive Enter away from taking it.
    ///
    /// Naming the enrolment is the one sentence that makes this route acceptable rather than a renamed
    /// bypass: the reason a locked removal may proceed on the biometric alone is that the gate dies with
    /// the account. A window that did not say so would be indistinguishable from an ordinary removal,
    /// and the fact that justifies it would be the fact the user never read.
    #[test]
    fn the_locked_break_glass_window_names_the_gate_it_destroys() {
        let confirmer = ScriptedConfirmer::destroying(vec![ConfirmDecision::Approve], vec![]);
        authorize_locked_break_glass(&confirmer, Replacement::Nothing);

        let drawn = confirmer.drawn();
        for named in ["two-factor enrolment", "master seed", "24 words"] {
            assert!(
                drawn.contains(named),
                "the break glass must name {named:?} among what it destroys: {drawn}"
            );
        }
        assert!(
            break_glass_claim().refusal_is_default,
            "Enter must not destroy an account nothing can recover"
        );
    }

    /// A refused destroy must return REFUSED for every non-approving answer, so fail-closed is the default
    /// rather than one branch. Iterating all three non-approvals is what makes this load-bearing — a rule
    /// that mapped only `Deny` would let a TIMEOUT destroy an account.
    #[test]
    fn every_non_approval_refuses_the_destruction() {
        for answer in [
            ConfirmDecision::Deny,
            ConfirmDecision::Timeout,
            ConfirmDecision::Unavailable,
        ] {
            let confirmer = ScriptedConfirmer::destroying(vec![answer], vec![]);
            assert_eq!(
                authorize_destroy(
                    &confirmer,
                    Replacement::Nothing,
                    None::<&PhraseVault<PassthroughSealer>>
                ),
                DestroyRuling::Refused,
                "{answer:?} must not authorize destroying an account"
            );
        }
    }

    /// A recoverable account is offered a LAST LOOK at its words before they become the only copy — and the
    /// offer must come BEFORE the destroy gate, which is a statement about ORDER that only the recorded
    /// sequence can prove. A test asserting merely that both windows appeared would pass for an
    /// implementation that offered the phrase after the account was already gone.
    #[test]
    fn a_recoverable_account_is_offered_its_phrase_before_the_destroy_gate() {
        let dir = tempfile::tempdir().unwrap();
        let vault = vault(dir.path());
        vault.store(&RecoveryPhrase::generate()).unwrap();
        let confirmer = ScriptedConfirmer::destroying(vec![ConfirmDecision::Approve], vec![]);

        authorize_destroy(&confirmer, Replacement::WithNewAccount, Some(&vault));

        let kinds = confirmer.kinds();
        let gate = kinds
            .iter()
            .position(|kind| *kind == "DESTROY-GATE")
            .expect("the destroy gate must run");
        let look = kinds
            .iter()
            .position(|kind| *kind == "claim")
            .expect("the last-look offer must be a claim, so declining it is a real choice");
        assert!(
            look < gate,
            "the words must be offered BEFORE the point of no return: {kinds:?}"
        );
    }

    /// The control that proves the offer reads the vault rather than always appearing: an account with NO
    /// phrase has nothing to show, so it goes straight to the gate.
    #[test]
    fn a_phrase_less_account_is_not_offered_a_look_at_words_it_does_not_have() {
        let confirmer = ScriptedConfirmer::destroying(vec![ConfirmDecision::Approve], vec![]);
        authorize_destroy(
            &confirmer,
            Replacement::WithNewAccount,
            None::<&PhraseVault<PassthroughSealer>>,
        );

        assert_eq!(
            confirmer.kinds(),
            vec!["DESTROY-GATE"],
            "one window, the authorization — there are no words to look at"
        );
    }

    /// Each destructive verb must tell the user what happens AFTER, in its own words — "a new account will
    /// be created" and "this computer will be left with no account" are different outcomes, and a user must
    /// not have to guess which one they picked.
    #[test]
    fn each_destructive_verb_states_its_own_consequence() {
        assert!(Replacement::WithNewAccount.promise().contains("new"));
        assert!(Replacement::FromPhrase
            .promise()
            .contains("recovery phrase"));
        assert!(Replacement::Nothing.promise().contains("no DIG Account"));
        // And they must genuinely DIFFER — three identical strings would satisfy the checks above.
        let promises = [
            Replacement::WithNewAccount.promise(),
            Replacement::FromPhrase.promise(),
            Replacement::Nothing.promise(),
        ];
        for (index, first) in promises.iter().enumerate() {
            for second in &promises[index + 1..] {
                assert_ne!(first, second, "each verb needs its own sentence");
            }
        }
    }

    // ---- Typing a recovery phrase in a native window (dig_ecosystem#1798). ----

    /// A valid phrase typed into the native window comes back parsed — no terminal, no command.
    #[test]
    fn a_typed_phrase_is_accepted_from_the_native_input_window() {
        let phrase = RecoveryPhrase::generate();
        let words = phrase.words().join(" ");
        let confirmer = ScriptedConfirmer::destroying(vec![], vec![Some(words.clone())]);

        let parsed = ask_for_phrase(&confirmer, "Restore your DIG Account").expect("valid words");
        assert_eq!(parsed.words().join(" "), words);
        assert!(
            confirmer.kinds().contains(&"input"),
            "the words must be taken in a native INPUT window: {:?}",
            confirmer.kinds()
        );
    }

    /// **The reason the loop exists.** A mistyped phrase must be re-asked WITH THE REASON, not silently
    /// dropped — and the second attempt must be accepted.
    ///
    /// The fixture supplies a wrong phrase first and a valid one second, which is what distinguishes
    /// "re-asks" from "gives up on the first mistake": a single-answer double could not express a user who
    /// corrects a typo.
    #[test]
    fn a_bad_phrase_is_re_asked_with_the_reason_and_the_correction_is_accepted() {
        let good = RecoveryPhrase::generate().words().join(" ");
        let confirmer = ScriptedConfirmer::destroying(
            vec![],
            vec![Some("not even close".to_string()), Some(good.clone())],
        );

        let parsed = ask_for_phrase(&confirmer, "Restore your DIG Account");
        assert_eq!(
            parsed
                .expect("the correction must be accepted")
                .words()
                .join(" "),
            good
        );

        let drawn = confirmer.drawn();
        assert!(
            drawn.contains("not a valid DIG recovery phrase"),
            "the second window must say WHAT was wrong: {drawn}"
        );
        assert_eq!(
            confirmer.kinds(),
            vec!["input", "input"],
            "exactly two windows: the mistake and the correction"
        );
    }

    /// A cancelled input window returns nothing and must NOT be retried — the user said no.
    #[test]
    fn cancelling_the_phrase_window_returns_nothing_and_asks_once() {
        let confirmer = ScriptedConfirmer::destroying(vec![], vec![None]);
        assert!(ask_for_phrase(&confirmer, "Restore your DIG Account").is_none());
        assert_eq!(
            confirmer.kinds(),
            vec!["input"],
            "a cancel must not be re-asked: {:?}",
            confirmer.kinds()
        );
    }

    /// The retry loop is BOUNDED: past its limit it ends with an explanation rather than another window, so
    /// a backend that answers instantly cannot spin forever.
    ///
    /// Pinned at the bound rather than merely "stops eventually" — a loop that gave up after one attempt
    /// would also "stop", and would be the give-up-on-the-first-typo behaviour this loop exists to avoid.
    #[test]
    fn the_retry_loop_stops_exactly_at_its_bound_and_says_nothing_was_lost() {
        let wrong = vec![Some("wrong words here".to_string()); PHRASE_ATTEMPTS + 3];
        let confirmer = ScriptedConfirmer::destroying(vec![], wrong);

        assert!(ask_for_phrase(&confirmer, "Restore your DIG Account").is_none());
        let inputs = confirmer
            .kinds()
            .iter()
            .filter(|kind| **kind == "input")
            .count();
        assert_eq!(
            inputs, PHRASE_ATTEMPTS,
            "the loop must offer exactly its bound of attempts, no more and no fewer"
        );
        assert!(
            confirmer.drawn().contains("Nothing has been changed"),
            "the user must be told the attempt is over and nothing was lost: {}",
            confirmer.drawn()
        );
    }

    /// The phrase window must WARN that a Sage/Chia phrase is not a DIG phrase. DIG would happily accept one
    /// and build a different, empty account from it, which is the most expensive silent mistake available on
    /// this screen.
    #[test]
    fn the_phrase_window_warns_that_a_chia_wallet_phrase_is_a_different_account() {
        let confirmer = ScriptedConfirmer::destroying(vec![], vec![None]);
        ask_for_phrase(&confirmer, "Restore your DIG Account");

        let drawn = confirmer.drawn();
        assert!(drawn.contains("Sage"), "{drawn}");
        assert!(drawn.contains("DIFFERENT"), "{drawn}");
        assert!(
            drawn.contains(&PHRASE_WORDS.to_string()),
            "the window must say how many words are expected: {drawn}"
        );
    }

    /// The phrase-less explainer must name a remedy the MENU actually offers, by its real label. Before
    /// #1800 it advised creating a new account while every control that could was greyed out — advice that
    /// is a dead end is worse than no advice.
    #[test]
    fn the_phrase_less_explainer_names_the_menu_path_to_its_remedy() {
        let confirmer = ScriptedConfirmer::notices();
        explain_missing_phrase(&confirmer);

        let drawn = confirmer.drawn();
        assert!(drawn.contains("Manage Account"), "{drawn}");
        assert!(
            drawn.contains("Replace this account with a NEW one"),
            "the remedy must be named by the label the user will see: {drawn}"
        );
        assert!(
            drawn.contains("Nothing has changed yet"),
            "the explainer changes nothing and must say so: {drawn}"
        );
    }

    // ---- The net under the destroy PATH (review finding, dig_ecosystem#1799). ----
    //
    // The seam test above proves `authorize_destroy` reaches `confirm_destroy`. It does NOT prove that the
    // code which destroys custody HONOURS that answer — and while that code lived in `dig-app`'s `bin`
    // target behind `#[cfg(feature = "tray")]`, nothing could: inverting one character so a REFUSED destroy
    // destroyed the account and an AUTHORIZED one aborted left the whole workspace green. These tests are
    // that missing net, and they are what makes moving the ordering into this module worth doing.

    /// A custodian that RECORDS what it was asked to do, in order, and never touches a real account.
    ///
    /// Recording the SEQUENCE rather than a set of counters is deliberate: "lock before discard" is a claim
    /// about order, and counters cannot express it.
    struct RecordingCustodian {
        steps: Mutex<Vec<&'static str>>,
        /// What [`AccountCustodian::discard`] reports. Varied so the failure branch is reachable.
        discard: Mutex<Option<DiscardOutcome>>,
        /// How the enrolments answer. A separate field from `discard`, because the interesting case is
        /// a SUCCESSFUL discard followed by a FAILED enrol — a double that could only vary one of the two
        /// could not express it, and that is the one path where custody is gone and nothing replaces it.
        ///
        /// It carries the VERDICT rather than a bool for the same reason: a double that can only say
        /// "failed" cannot distinguish a retryable failure from a folder that will never hold an account,
        /// and those two must reach different words.
        enrol: Mutex<Result<(), EnrolFailure>>,
    }

    impl RecordingCustodian {
        fn new() -> Self {
            Self {
                steps: Mutex::new(Vec::new()),
                discard: Mutex::new(Some(DiscardOutcome::Discarded)),
                enrol: Mutex::new(Ok(())),
            }
        }

        fn failing_discard() -> Self {
            let custodian = Self::new();
            *custodian.discard.lock().unwrap() = Some(DiscardOutcome::Failed);
            custodian
        }

        fn failing_enrol() -> Self {
            Self::failing_enrol_with(UnlockFailure::Refused)
        }

        fn failing_enrol_with(failure: UnlockFailure) -> Self {
            Self::failing_with(EnrolFailure::NotEnrolled(failure))
        }

        /// An enrolment that WROTE the account and then failed to re-open it.
        ///
        /// The arm the flattening hid: custody exists after this failure, so a caller that reports it
        /// as "no account" is describing a host that is not this one (dig-app#235).
        fn failing_reopen_with(failure: UnlockFailure) -> Self {
            Self::failing_with(EnrolFailure::NotReopened(failure))
        }

        fn failing_with(failure: EnrolFailure) -> Self {
            let custodian = Self::new();
            *custodian.enrol.lock().unwrap() = Err(failure);
            custodian
        }

        fn steps(&self) -> Vec<&'static str> {
            self.steps.lock().unwrap().clone()
        }

        /// How many times the one destructive step ran. THE assertion of this whole group.
        fn discards(&self) -> usize {
            self.steps().iter().filter(|s| **s == "DISCARD").count()
        }

        fn note(&self, step: &'static str) {
            self.steps.lock().unwrap().push(step);
        }
    }

    impl AccountCustodian for RecordingCustodian {
        fn lock_current(&self) {
            self.note("lock");
        }
        fn discard(&self) -> DiscardOutcome {
            self.note("DISCARD");
            self.discard.lock().unwrap().unwrap()
        }
        fn enrol_new(&self) -> Result<(), EnrolFailure> {
            self.note("enrol_new");
            *self.enrol.lock().unwrap()
        }
        fn enrol_from(&self, _phrase: &RecoveryPhrase) -> Result<(), EnrolFailure> {
            self.note("enrol_from");
            *self.enrol.lock().unwrap()
        }
        fn reopen(&self) {
            self.note("reopen");
        }
    }

    /// A confirmer that answers the destroy gate with `answer` and types `words` into every input window.
    fn gate(answer: ConfirmDecision, words: Option<String>) -> ScriptedConfirmer {
        ScriptedConfirmer::destroying(vec![answer], vec![words])
    }

    /// **THE GATING TEST (#1799).** A REFUSED destroy MUST NOT destroy anything — asserted on the
    /// custodian, which is the only thing that can actually destroy custody.
    ///
    /// This is the test whose absence made the whole design's strongest part unprotected: with the ordering
    /// in an untestable `bin` target, inverting `!=` to `==` here — so a refusal destroys and an
    /// authorization aborts — passed the entire suite. Run over ALL THREE verbs and ALL THREE non-approvals,
    /// because a rule that honoured only `Deny`, or only one verb, is the same defect in milder form.
    #[test]
    fn a_refused_destroy_never_touches_the_account() {
        for what in [
            Replacement::WithNewAccount,
            Replacement::FromPhrase,
            Replacement::Nothing,
        ] {
            for answer in [
                ConfirmDecision::Deny,
                ConfirmDecision::Timeout,
                ConfirmDecision::Unavailable,
            ] {
                let custodian = RecordingCustodian::new();
                let outcome = replace_account(
                    &gate(answer, None),
                    &custodian,
                    what,
                    None::<&PhraseVault<PassthroughSealer>>,
                );

                assert_eq!(
                    outcome,
                    ReplaceOutcome::RefusedByUser,
                    "{what:?}/{answer:?}"
                );
                assert!(!outcome.destroyed_custody(), "{what:?}/{answer:?}");
                assert_eq!(
                    custodian.discards(),
                    0,
                    "{what:?}/{answer:?}: a refusal MUST NOT discard the account"
                );
                assert_eq!(
                    custodian.steps(),
                    Vec::<&str>::new(),
                    "{what:?}/{answer:?}: a refusal must not touch the host at all"
                );
            }
        }
    }

    /// **The control that makes the test above load-bearing.** An AUTHORIZED destroy MUST actually destroy —
    /// for all three verbs. Without this pair, a `replace_account` that never discarded anything would
    /// satisfy the refusal test perfectly, and the polarity inversion would still not be caught.
    #[test]
    fn an_authorized_destroy_discards_exactly_once_for_every_verb() {
        let words = RecoveryPhrase::generate().words().join(" ");
        for (what, expected_enrol) in [
            (Replacement::WithNewAccount, Some("enrol_new")),
            (Replacement::FromPhrase, Some("enrol_from")),
            (Replacement::Nothing, None),
        ] {
            let custodian = RecordingCustodian::new();
            let outcome = replace_account(
                &gate(ConfirmDecision::Approve, Some(words.clone())),
                &custodian,
                what,
                None::<&PhraseVault<PassthroughSealer>>,
            );

            assert!(
                outcome.destroyed_custody(),
                "{what:?}: an authorized destroy must destroy: {outcome:?}"
            );
            assert_eq!(
                custodian.discards(),
                1,
                "{what:?}: exactly once — never twice, never not at all"
            );
            match expected_enrol {
                Some(step) => assert!(custodian.steps().contains(&step), "{what:?}"),
                None => assert!(
                    !custodian.steps().iter().any(|s| s.starts_with("enrol")),
                    "{what:?}: removal enrols nothing"
                ),
            }
        }
    }

    /// The lock MUST come before the discard: the residency must not be holding key material for a seed that
    /// is being deleted underneath it. Asserted on the recorded ORDER, which is the only way to see it — a
    /// test that merely checked both happened would pass for the reverse sequence.
    #[test]
    fn the_session_is_locked_before_the_seed_is_deleted() {
        let custodian = RecordingCustodian::new();
        replace_account(
            &gate(ConfirmDecision::Approve, None),
            &custodian,
            Replacement::Nothing,
            None::<&PhraseVault<PassthroughSealer>>,
        );

        let steps = custodian.steps();
        let lock = steps.iter().position(|s| *s == "lock").expect("must lock");
        let discard = steps
            .iter()
            .position(|s| *s == "DISCARD")
            .expect("must discard");
        assert!(lock < discard, "lock must precede the discard: {steps:?}");
    }

    /// **The ordering rule that protects a user from losing everything to a typo.** A replace-from-phrase
    /// that is abandoned at the phrase window MUST leave the account intact — the phrase is collected while
    /// the old account is still there precisely so this is survivable.
    ///
    /// The fixture authorizes the destroy and THEN cancels the phrase window, which is the only combination
    /// that can distinguish "collects first" from "destroys first": a refused authorization would never
    /// reach the phrase window at all.
    #[test]
    fn abandoning_the_phrase_window_leaves_the_account_intact() {
        let custodian = RecordingCustodian::new();
        let outcome = replace_account(
            &gate(ConfirmDecision::Approve, None),
            &custodian,
            Replacement::FromPhrase,
            None::<&PhraseVault<PassthroughSealer>>,
        );

        assert_eq!(outcome, ReplaceOutcome::AbandonedAtPhrase);
        assert!(!outcome.destroyed_custody());
        assert_eq!(
            custodian.discards(),
            0,
            "the replacement was never supplied, so nothing may be destroyed"
        );
    }

    /// A FAILED discard must report itself, re-open the account, and enrol nothing — the account is still
    /// here, so leaving it locked forever or stacking a second account on top of it would both be wrong.
    #[test]
    fn a_failed_discard_reopens_the_account_and_enrols_nothing() {
        let confirmer = gate(ConfirmDecision::Approve, None);
        let custodian = RecordingCustodian::failing_discard();
        let outcome = replace_account(
            &confirmer,
            &custodian,
            Replacement::WithNewAccount,
            None::<&PhraseVault<PassthroughSealer>>,
        );

        assert_eq!(outcome, ReplaceOutcome::DiscardFailed);
        assert!(!outcome.destroyed_custody());
        assert!(custodian.steps().contains(&"reopen"));
        assert!(
            !custodian.steps().iter().any(|s| s.starts_with("enrol")),
            "nothing was destroyed, so nothing may replace it: {:?}",
            custodian.steps()
        );
        assert!(
            confirmer.drawn().contains("still here"),
            "the user must be told their account survived: {}",
            confirmer.drawn()
        );
    }

    /// The worst outcome available — custody destroyed and the replacement failed — MUST be reported, not
    /// swallowed. A user left with no account and no message would have no idea what state their machine is
    /// in, which is the one situation where silence is unforgivable.
    #[test]
    fn a_failed_enrolment_after_a_successful_discard_says_so_plainly() {
        // Each verb's own sentence, because the two situations differ: after a failed NEW account the host
        // has nothing, while after a failed restore the user's words are still good and the message must
        // say so. Asserting one shared substring would let either message drift into the other's wording.
        for (what, words, expected) in [
            (
                Replacement::WithNewAccount,
                None,
                "This computer now has no DIG Account",
            ),
            (
                Replacement::FromPhrase,
                Some(RecoveryPhrase::generate().words().join(" ")),
                "Your 24 words are still valid",
            ),
        ] {
            let confirmer = gate(ConfirmDecision::Approve, words);
            let custodian = RecordingCustodian::failing_enrol();
            let outcome = replace_account(
                &confirmer,
                &custodian,
                what,
                None::<&PhraseVault<PassthroughSealer>>,
            );

            assert_eq!(outcome, ReplaceOutcome::EnrolFailed, "{what:?}");
            assert!(
                outcome.destroyed_custody(),
                "{what:?}: the discard DID happen and the outcome must admit it"
            );
            assert_eq!(custodian.discards(), 1, "{what:?}");
            assert!(
                confirmer.drawn().contains(expected),
                "{what:?}: the user must be told what state their machine is in: {}",
                confirmer.drawn()
            );
        }
    }

    /// **dig-app#235.** An enrolment that WROTE the account and then failed to re-open it MUST NOT be
    /// reported as leaving this computer with no account — because the account is right there.
    ///
    /// # Why the fixture has two actors rather than one
    ///
    /// The defect is a DISCARD of a distinction, not a wrong string, so a test that only drove the
    /// re-open case could be satisfied by a flow that showed the new copy for *every* enrolment failure
    /// — which would replace one false claim with another, on the arm where "this computer now has no
    /// DIG Account" is the true and necessary thing to say. So each row asserts both directions: the
    /// written-and-locked case must NOT say the computer is empty, and the nothing-was-written control
    /// must still say exactly that, and must not borrow the unlock words.
    ///
    /// Both verbs are driven because both re-open: `enrol_from` runs the same
    /// `start_sign_service_reporting` step one line later, and its own copy — *"the new one could not
    /// be set up"* — is false in the same way.
    ///
    /// Reverting only the `NotReopened` arm of `replace_account` leaves the two `NotEnrolled` rows green
    /// and fails both `NotReopened` rows, which is what makes this test load-bearing rather than a
    /// restatement of the copy.
    #[test]
    fn an_account_that_was_written_but_did_not_reopen_is_never_reported_as_absent() {
        const ABSENT: &str = "no DIG Account";

        for what in [Replacement::WithNewAccount, Replacement::FromPhrase] {
            let typed = matches!(what, Replacement::FromPhrase)
                .then(|| RecoveryPhrase::generate().words().join(" "));

            // The account WAS created and only the re-open failed.
            let reopen_failed = gate(ConfirmDecision::Approve, typed.clone());
            let custodian = RecordingCustodian::failing_reopen_with(UnlockFailure::Refused);
            let outcome = replace_account(
                &reopen_failed,
                &custodian,
                what,
                None::<&PhraseVault<PassthroughSealer>>,
            );

            // Side effects first, so the copy below is the copy from THIS path: custody really went,
            // and the enrolment really ran.
            assert_eq!(custodian.discards(), 1, "{what:?} must have discarded once");
            assert!(
                custodian
                    .steps()
                    .iter()
                    .any(|step| step.starts_with("enrol")),
                "{what:?} must have reached the enrolment: {:?}",
                custodian.steps()
            );
            assert_eq!(
                outcome,
                ReplaceOutcome::ReplacedButLocked,
                "{what:?}: the replacement IS enrolled, so the outcome must not say it failed to enrol"
            );

            let drawn = reopen_failed.drawn();
            assert!(
                !drawn.contains(ABSENT),
                "{what:?}: the flow claimed this computer has no account while the account it just \
                 wrote is on disk:\n{drawn}"
            );
            assert!(
                drawn.contains("Unlock"),
                "{what:?}: the user must be pointed at the remedy that works — unlocking:\n{drawn}"
            );

            // The control. Nothing was written here, so the empty-host sentence is the true one and
            // must survive; a fix applied at the wrong layer would take it away from this row too.
            let nothing_written = gate(ConfirmDecision::Approve, typed);
            replace_account(
                &nothing_written,
                &RecordingCustodian::failing_enrol_with(UnlockFailure::Refused),
                what,
                None::<&PhraseVault<PassthroughSealer>>,
            );
            let drawn = nothing_written.drawn();
            assert!(
                !drawn.contains(ENROLLED_BUT_LOCKED_NOTICE.heading),
                "{what:?}: an enrolment that wrote nothing must not claim an account was created:\n{drawn}"
            );
        }
    }

    /// `destroyed_custody` is what every test above turns on, so it is pinned directly: it MUST be true for
    /// exactly the three outcomes that ran a discard, and false for the three that did not. A classifier
    /// that always answered `false` would quietly disarm the whole group.
    #[test]
    fn the_outcome_classifier_names_exactly_the_destructive_results() {
        for destructive in [
            ReplaceOutcome::Replaced,
            ReplaceOutcome::Removed,
            ReplaceOutcome::EnrolFailed,
            ReplaceOutcome::ReplacedButLocked,
        ] {
            assert!(destructive.destroyed_custody(), "{destructive:?}");
        }
        for safe in [
            ReplaceOutcome::RefusedByUser,
            ReplaceOutcome::AbandonedAtPhrase,
            ReplaceOutcome::DiscardFailed,
        ] {
            assert!(!safe.destroyed_custody(), "{safe:?}");
        }
    }

    // ---- The RENDERED copy, not the source (review finding, dig_ecosystem#1799). ----

    /// **Regression.** No window's rendered body may contain a run of three or more spaces.
    ///
    /// # Why a whole class, and why a `contains()` assertion could never catch it
    ///
    /// **The second instance of the same defect (dig_ecosystem#3145 gate).** The replacement flows are
    /// WRITE paths, so they are exactly where a keystore root the backend refuses to own shows up — and
    /// they reach it with the previous account already discarded. Answering that with "set one up …
    /// whenever you are ready" or "try Restore … in the DIG menu" invites a retry of the one failure a
    /// retry cannot move, at the worst possible moment.
    ///
    /// Asserted on the WORDS the user is shown, not on the returned outcome: both verdicts return
    /// `EnrolFailed`, so an outcome assertion cannot tell the honest window from the misleading one.
    ///
    /// # Why the double is faithful (it was not, and the re-gate caught it)
    ///
    /// `RecordingCustodian` answers `Unusable` from `enrol_new`, and for one release the production
    /// `ShellCustodian` **structurally could not**: it discarded the verdict and answered `Refused` for
    /// every unsuccessful setup, so this test proved a path the shipped type had no way to take and the
    /// arm below was dead code. A double MORE capable than production is exactly as blind as one less
    /// capable. That the real type now reaches every verdict is asserted where it can be —
    /// `dig-app`'s `shell_custodian_verdict_tests::the_enrolment_verdict_reaches_the_journey_unchanged`,
    /// against `ShellCustodian` itself.
    #[test]
    fn an_unusable_account_folder_is_never_answered_with_another_try() {
        for (what, typed) in [
            (Replacement::WithNewAccount, None),
            (
                Replacement::FromPhrase,
                Some(RecoveryPhrase::generate().words().join(" ")),
            ),
        ] {
            let confirmer =
                ScriptedConfirmer::destroying(vec![ConfirmDecision::Approve], vec![typed]);
            let custodian = RecordingCustodian::failing_enrol_with(UnlockFailure::Unusable);

            let outcome = replace_account(
                &confirmer,
                &custodian,
                what,
                None::<&PhraseVault<PassthroughSealer>>,
            );

            // Side effects first: the flow must really have destroyed custody and really have tried to
            // enrol, or the copy assertion below would be inspecting a window from some other path.
            assert_eq!(custodian.discards(), 1, "{what:?} must have discarded once");
            assert_eq!(outcome, ReplaceOutcome::EnrolFailed, "{what:?}");

            let drawn = confirmer.drawn();
            assert!(
                drawn.contains("will not help until the folder is fixed"),
                "{what:?} must say another attempt cannot work until the FOLDER changes:\n{drawn}"
            );
            assert!(
                !drawn.contains("whenever you are ready"),
                "{what:?} must not invite a retry it cannot honour:\n{drawn}"
            );
            assert!(
                !drawn.contains("Restore from a recovery phrase"),
                "{what:?} must not point at a menu route that fails the same way:\n{drawn}"
            );
        }
    }

    /// The RETRYABLE enrol failure keeps its own words, so the test above is not passing merely because
    /// one message replaced two.
    #[test]
    fn a_retryable_enrol_failure_still_offers_the_way_back() {
        let confirmer = ScriptedConfirmer::destroying(vec![ConfirmDecision::Approve], vec![None]);
        replace_account(
            &confirmer,
            &RecordingCustodian::failing_enrol_with(UnlockFailure::Refused),
            Replacement::WithNewAccount,
            None::<&PhraseVault<PassthroughSealer>>,
        );
        let drawn = confirmer.drawn();
        assert!(
            drawn.contains("whenever you are ready"),
            "a retryable failure must still tell the user how to come back:\n{drawn}"
        );
    }

    /// `cargo fmt` collapses a `\`-continued string literal onto one line and KEEPS the source indentation
    /// as real spaces. The result is a body that reads *"cannot sign anything or&nbsp;&nbsp;&nbsp;… show you
    /// its recovery phrase"* with a ten-space hole mid-sentence — and it landed in the highest-stakes message
    /// in the app, the only window an unopenable account offers. Every substring assertion still passed,
    /// because the words are all present and in order; only the SPACING is wrong, and only a reader (or this)
    /// can see it.
    ///
    /// So the rule is asserted over the rendered text of EVERY window this module draws, not over the one
    /// that broke: the defect is a property of how the copy is written, so any future window written the same
    /// way fails here rather than shipping.
    #[test]
    fn no_rendered_notice_body_contains_a_run_of_spaces() {
        let confirmer = ScriptedConfirmer::notices();
        explain_unopenable(&confirmer);
        explain_missing_phrase(&confirmer);

        // Plus every window the destructive flow draws, in the shape that draws the most of them.
        //
        // The confirmer is BOUND. It used to be a temporary, so every window this flow drew went into a
        // value nobody read and the guard covered none of them despite saying it did — the same
        // hand-enumerated-inputs failure the rule itself is about. Both enrol verdicts are run, because
        // they draw different copy.
        let destroying = [UnlockFailure::Refused, UnlockFailure::Unusable].map(|failure| {
            let confirmer =
                ScriptedConfirmer::destroying(vec![ConfirmDecision::Approve], vec![None]);
            replace_account(
                &confirmer,
                &RecordingCustodian::failing_enrol_with(failure),
                Replacement::WithNewAccount,
                None::<&PhraseVault<PassthroughSealer>>,
            );
            confirmer.drawn()
        });

        // Plus the funding step the wizard draws for an existing wallet (dig_ecosystem#2341). Added
        // because a past version of this screen shipped with exactly this defect — a hole
        // mid-sentence that every substring assertion in this file passed straight over and only a
        // screenshot showed. The DID confirmation/wait screens this used to also cover were retired
        // with the DID-only mint path (dig-app#210); there is nothing left to drive there.
        let wizard = ScriptedConfirmer::drawing_qr(vec![ConfirmDecision::Approve; 8]);
        first_run_wizard(
            &wizard,
            AccountPresence::Wallet { address: ADDRESS },
            || panic!("must not create"),
            never_imports,
            &RecordingCopier::working(),
        );

        // The `boot` notices are included because that module's copy reaches the SAME tray windows
        // through `failure_notice`, and its list is not hand-picked: `UNLOCK_NOTICES` is proved complete
        // against boot.rs's own source by `every_notice_in_this_module_is_in_the_catalog`, so a notice
        // added there cannot quietly escape this guard.
        let boot_notices = crate::account::boot::UNLOCK_NOTICES
            .iter()
            .map(|notice| format!("{}\n{}\n{}", notice.title, notice.heading, notice.body))
            .collect::<Vec<_>>()
            .join("\n");

        for window in [
            confirmer.drawn(),
            wizard.drawn(),
            RETENTION_AND_REVEAL_COPY.to_string(),
            destroying.join("\n"),
            boot_notices,
        ] {
            for (index, line) in window.lines().enumerate() {
                assert!(
                    !line.contains("   "),
                    "line {index} renders a run of spaces — a `\\`-continued literal that `cargo fmt` \
                     flattened? Use `concat!`:\n{line:?}"
                );
                assert!(
                    !line.starts_with(' '),
                    "line {index} renders a leading space:\n{line:?}"
                );
            }
        }
    }

    /// The copy every OTHER window in this module shows, concatenated, so the rule above covers them too
    /// without needing to drive each flow.
    ///
    /// Kept beside the test rather than derived, because the point is to inspect the literals as they will
    /// RENDER; anything that reaches a user through this module belongs in this list.
    const RETENTION_AND_REVEAL_COPY: &str = concat!(
        "Write these 24 words down, in order, and keep them somewhere safe.\n",
        "Do you have your 24 words written down somewhere safe?\n",
        "These 24 words are your DIG Account. Keep them secret."
    );

    /// The unopenable body must also SAY the three things it exists to say — the words, not just their
    /// spacing. Read together with the test above: that one proves it is legible, this one proves it is
    /// correct.
    #[test]
    fn the_unopenable_copy_renders_without_holes() {
        // The reassurance the state's whole design rests on: reaching it destroys nothing.
        assert!(
            UNOPENABLE_BODY.contains("Nothing has been changed or deleted"),
            "{UNOPENABLE_BODY}"
        );
        // The exact menu path to the only remedy, by the labels the user will actually see.
        assert!(
            UNOPENABLE_BODY.contains("Manage Account"),
            "{UNOPENABLE_BODY}"
        );
        assert!(
            UNOPENABLE_BODY.contains("Replace this account with a NEW one"),
            "{UNOPENABLE_BODY}"
        );
        // And that a kept phrase brings the account back, which is the one good outcome available here.
        assert!(
            UNOPENABLE_BODY.contains("bring it back exactly as it was"),
            "{UNOPENABLE_BODY}"
        );
        // Three paragraphs, so the wall of text is broken up where it was written to be.
        assert_eq!(
            UNOPENABLE_BODY.split("\n\n").count(),
            3,
            "the paragraph breaks must survive: {UNOPENABLE_BODY:?}"
        );
    }
}
