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

use crate::account::boot::DiscardOutcome;
use crate::account::chain_mint::MintAvailability;
use crate::account::did::{DidLedger, DidRecord};
use crate::account::lifecycle::{PhrasePresenter, RetentionDecision};
use crate::account::mint::{
    await_confirmation, DidMinter, KeepWaiting, MintObserver, MintOutcome, Submission,
    WaitProgress, WaitSurface, POLL_EVERY_SECS,
};
use crate::account::phrase_vault::PhraseVault;
use crate::account::recovery::RecoveryPhrase;
use crate::account::second_factor::journey::Clock;
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
               this one: in the DIG menu choose \"Manage my DIG Account\" then \"Replace this account \
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
    "computer: in the DIG menu choose \"Manage my DIG Account\", then either \"Replace this account with ",
    "a NEW one…\" or, if you have 24 words for an account you want back, \"Replace it with an account ",
    "from a recovery phrase…\".\n\n",
    "If you kept this account's 24 words, restoring from them will bring it back exactly as it was."
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

    /// Enrol a brand-new account, showing and confirming its recovery phrase. `true` on success.
    fn enrol_new(&self) -> bool;

    /// Enrol the account `phrase` describes. `true` on success.
    fn enrol_from(&self, phrase: &RecoveryPhrase) -> bool;

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
}

impl ReplaceOutcome {
    /// Whether custody was destroyed. The single question every one of this flow's tests turns on.
    pub fn destroyed_custody(self) -> bool {
        matches!(self, Self::Replaced | Self::Removed | Self::EnrolFailed)
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
            true => ReplaceOutcome::Replaced,
            false => {
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
            true => {
                notify(
                    confirmer,
                    "DIG — Account replaced",
                    "The DIG Account from your recovery phrase is now on this computer.",
                    "The account that was here before is gone and its data is no longer readable.",
                );
                ReplaceOutcome::Replaced
            }
            false => {
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

/// How far a DIG account has actually got (dig_ecosystem#1820).
///
/// #1820 is explicit that a DID is the bedrock of an account and that an account is not complete without
/// one — so "wallet exists, no DID yet" MUST NOT be collapsed into any existing account state, and the
/// app must stop telling people their account "fully works without a DID".
///
/// It is modelled here, beside the journey that produces it, rather than as another
/// [`AccountState`](crate::tray_menu::AccountState) variant. The reason is that completeness is a real
/// fact about an account and is reported as one; it is not a lock state, and pretending otherwise would
/// make the lock states lie.
///
/// # What gates on this, and the one condition that can still withhold the gate
///
/// [`startup_wizard`] gates on it: an account that is [`WalletOnly`](Self::WalletOnly) meets the DID
/// wizard when the app starts, which is dig_ecosystem#2359's instruction — *"the DiD wizard should
/// appear when the program starts and it detects no DiD was minted"*.
///
/// The mint itself is real and proven: `dig-account` 0.6.0 exposes `UnlockedAccount::profile_minter`,
/// and [`crate::account::chain_mint`] drives it through a Chia consensus validator end to end. What
/// remains conditional is the TRANSPORT — a chain reader and a publisher this host can reach — which
/// is why `startup_wizard` also takes a
/// [`MintAvailability`]. Showing the wizard on a build
/// that cannot reach a chain would put every account on every machine in front of a window with no
/// control that could clear it, which is the dead end dig_ecosystem#1800 removed once already.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AccountCompleteness {
    /// A wallet exists — a seed, a recovery phrase, an address, a working signer — but no on-chain DID
    /// is bound to it. Usable for reading content and for holding funds; NOT the finished article.
    WalletOnly,
    /// An on-chain `did:chia:` DID is bound to the account. Only ever set from evidence of a real mint.
    DidBound,
}

impl AccountCompleteness {
    /// Read completeness off the DID the tray holds. `None` means no DID has been minted — the honest
    /// reading, since a DID is recorded only from evidence of an actual on-chain mint.
    pub fn of(did: Option<&str>) -> Self {
        match did {
            Some(_) => Self::DidBound,
            None => Self::WalletOnly,
        }
    }
}

/// What a first run ended in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FirstRunOutcome {
    /// A wallet was created. It has a seed, a confirmed recovery phrase and a password, and it can read
    /// content and hold funds — but it has no DID yet, so it is [`AccountCompleteness::WalletOnly`].
    WalletCreated,
    /// A DID was minted AND confirmed on chain, so the account is [`AccountCompleteness::DidBound`].
    /// Reachable only from [`MintOutcome::Confirmed`] — never from a submission.
    IdentityReady,
    /// The user backed out. Nothing was created and the host is exactly as it was.
    Declined,
    /// Creation was attempted and did not complete. The creating step has already told the user why.
    Failed,
}

/// What this computer already has when the wizard starts (dig_ecosystem#2341).
///
/// The wizard is gated on the DID, not on the account — a person who set up a wallet in an earlier
/// version has no DID and must still be able to reach the funding and minting steps without being
/// walked through creating a second account they do not want.
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

/// Whether the first-run wizard should run at all (dig_ecosystem#2341).
///
/// The gate is the DID and NOTHING else. A wallet from an earlier version has no DID, so it still needs
/// the wizard; an account that has minted one never sees it again. It takes the RECORD rather than a
/// boolean so the only way to answer "no wizard" is to be holding evidence of a mint — a caller cannot
/// satisfy this with a key, an address, or a hopeful flag.
pub fn wizard_needed(did: Option<&DidRecord>) -> bool {
    did.is_none()
}

/// What this host has, at rest, when the app starts — read without unlocking anything.
///
/// Both facts are readable from disk: whether an account is enrolled, and whether a DID has been
/// recorded with its mint evidence. The app deliberately starts LOCKED (dig_ecosystem#1817), so a
/// startup decision that needed a key could not be made at startup at all.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StartupAccount {
    /// No DIG account on this computer. Nothing has been set up.
    NotEnrolled,
    /// An account exists, and this is how far it has got.
    Enrolled(AccountCompleteness),
}

/// What the app should do about the DID when it starts (dig_ecosystem#2359).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StartupWizard {
    /// Show nothing. The account already has a DID, there is no account to give one to, or no mint
    /// could be completed on this build.
    NotNeeded,
    /// Open the wizard at its DID step: fund, then mint. The account exists and has no DID.
    AtTheDidStep,
}

/// Decide whether the DID wizard opens when the program starts.
///
/// The user's instruction is the whole of the intent: *"The DiD wizard should appear when the program
/// starts and it detects no DiD was minted."* This is that sentence, with the two conditions that keep
/// it from becoming a trap.
///
/// # The two things it refuses to do, and why each would be worse than not gating
///
/// - **It never opens on a host that cannot mint.** A wizard whose only forward control cannot work is
///   a window with no way out but the close button, on every launch, for every account — the dead end
///   dig_ecosystem#1800 removed. A wallet with no FUNDS is a different case entirely and is NOT
///   withheld: that person can act on what they are told, and the funding step is what tells them.
/// - **It never opens on a computer with no account.** Reading DIG content needs no account and no
///   wallet, which is what dig-app tells its users on its own wallet screen. Someone who installed DIG
///   to read must reach the app; setting up an account stays the deliberate choice it is today, from
///   the DIG menu. "No DID was minted" is true of that machine too, and answering it with an
///   unrequested account-creation flow at every launch would break a promise the app makes elsewhere.
pub fn startup_wizard(account: StartupAccount, mint: MintAvailability) -> StartupWizard {
    match (account, mint) {
        (StartupAccount::Enrolled(AccountCompleteness::WalletOnly), MintAvailability::Possible) => {
            StartupWizard::AtTheDidStep
        }
        _ => StartupWizard::NotNeeded,
    }
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

/// Everything the DID step needs to mint and then WAIT (dig_ecosystem#2341).
///
/// Grouped into one struct so the wizard's signature states one dependency rather than five, and so a
/// test can swap the whole chain — minter, chain, wait surface, clock, ledger — at once.
pub struct DidMinting<'a> {
    /// Builds, signs and pushes the mint spend. [`UnavailableMinter`](crate::account::mint::UnavailableMinter) until `dig-account`'s minter is
    /// real; the wizard's copy is honest about that on its own.
    pub minter: &'a dyn DidMinter,
    /// Watches the chain for the submitted spend.
    pub observer: &'a dyn MintObserver,
    /// Where the wait is drawn and where "stop watching" comes from.
    pub surface: &'a dyn WaitSurface,
    /// The wall clock the wait measures elapsed time against.
    pub clock: &'a dyn Clock,
    /// Where a CONFIRMED mint is remembered. Written on exactly one path: the arm of
    /// [`mint_report`] that handles [`MintOutcome::Confirmed`], and nowhere else.
    pub ledger: &'a dyn DidLedger,
}

/// Run the FIRST-RUN flow: orient the user, let them CREATE a new account or IMPORT an existing one from
/// its recovery phrase, then show them where to send funds and tell them the truth about the DID step
/// (dig_ecosystem#1826, dig_ecosystem#1564).
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
/// # The last two screens, and why they are what they are
///
/// - **Funding is shown, not awaited.** The wizard is a chain of OS-owned modal windows — dig-app has no
///   window toolkit and adding one to a custody-holding binary is a security surface, not a crate pick —
///   and a modal cannot poll a chain or update itself. So the user is given their address and told to
///   fund it when they are ready, instead of a "waiting for funds…" screen that could never be waiting.
/// - **The DID step cannot mint, and says so.** Nothing in this build can mint (see
///   [`crate::account::mint`]) and no [`TrayAction`](crate::tray_menu::TrayAction) can either — that is
///   structural, not an oversight. #1820
///   requires a DID be presented as REQUIRED rather than optional, so the step names it as the remaining,
///   required step and states plainly that it is not available in this version, rather than presenting a
///   button that silently does nothing or claiming the account "fully works without a DID".
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
    minting: &DidMinting<'_>,
) -> FirstRunOutcome {
    // A wallet that already exists needs no orienting and no route choice: the only thing missing is
    // the DID, so the wizard starts where the missing part is.
    if let AccountPresence::Wallet { address } = presence {
        return finish_the_identity(confirmer, address, copier, minting);
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
        ConfirmDecision::Approve => import_existing_account(confirmer, import, copier, minting),
        ConfirmDecision::Deny => create_new_account(confirmer, create, copier, minting),
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
    minting: &DidMinting<'_>,
) -> FirstRunOutcome {
    let Some(address) = create() else {
        return FirstRunOutcome::Failed;
    };
    finish_the_identity(confirmer, &address, copier, minting)
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
    minting: &DidMinting<'_>,
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
    finish_the_identity(confirmer, &address, copier, minting)
}

/// The two steps every route ends on, whichever way the wallet got here: FUND it, then MINT the DID.
///
/// Shared so create, import and an already-existing wallet cannot drift, and so the wizard's gate
/// (no DID) and its remaining work (fund, then mint) are the same two screens for all three.
fn finish_the_identity(
    confirmer: &dyn NativeConfirmer,
    address: &str,
    copier: &dyn AddressCopier,
    minting: &DidMinting<'_>,
) -> FirstRunOutcome {
    show_where_to_send_funds(confirmer, address, copier);
    match mint_the_did(confirmer, minting) {
        // The ONE path to a finished identity, and it required evidence to get here.
        Some(MintOutcome::Confirmed { .. }) => FirstRunOutcome::IdentityReady,
        // Every other ending has already told the user, in its own words, what happened and what to do
        // next. The wallet exists either way, which is what this reports.
        _ => FirstRunOutcome::WalletCreated,
    }
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

/// The DID step: offer the mint, submit it, and WAIT for the chain — or say plainly why none of that
/// can happen yet.
///
/// Returns the outcome of a mint that was actually attempted, or `None` when nothing was submitted.
///
/// # Why there is no success message anywhere but one arm
///
/// A pushed spend is not a DID. Every other ending here — refused, unaffordable, rejected, still
/// pending, unreachable — reports itself as what it is, and only [`MintOutcome::Confirmed`] writes the
/// [`DidLedger`] and congratulates anybody. That is why the evidence travels all the way from the
/// chain sighting into [`DidRecord::from_mint`] rather than being reconstructed here.
fn mint_the_did(confirmer: &dyn NativeConfirmer, minting: &DidMinting<'_>) -> Option<MintOutcome> {
    if confirmer.confirm_claim(&mint_offer()) != ConfirmDecision::Approve {
        notify(
            confirmer,
            copy::did::LATER_TITLE,
            copy::did::LATER_HEADING,
            copy::did::LATER_BODY,
        );
        return None;
    }

    // The submitted DID is deliberately dropped here. It names what the bundle was built to create,
    // and the DID that gets reported and recorded must come from the chain's confirmation instead —
    // see `Sighting::Confirmed`.
    let spend_id = match minting.minter.submit() {
        Submission::Submitted { spend_id, .. } => spend_id,
        // The state this build is actually in. The wording is the one #1820 settled on: the DID is
        // REQUIRED, and minting it is not available in this version — not "optional", not a button
        // that quietly does nothing.
        Submission::NotAvailable => {
            notify(
                confirmer,
                copy::did::UNAVAILABLE_TITLE,
                copy::did::UNAVAILABLE_HEADING,
                copy::did::UNAVAILABLE_BODY,
            );
            return None;
        }
        Submission::InsufficientFunds { needed } => {
            notify(
                confirmer,
                copy::did::UNAFFORDABLE_TITLE,
                copy::did::UNAFFORDABLE_HEADING,
                &format!(
                    "{}{needed}{}",
                    copy::did::UNAFFORDABLE_BEFORE_COST,
                    copy::did::UNAFFORDABLE_AFTER_COST
                ),
            );
            return None;
        }
        Submission::Refused { reason } => {
            notify(
                confirmer,
                copy::did::REFUSED_TITLE,
                copy::did::REFUSED_HEADING,
                &format!("{reason}\n\n{}", copy::did::REFUSED_BODY),
            );
            return None;
        }
    };

    let outcome = await_confirmation(&spend_id, minting.observer, minting.surface, minting.clock);
    report_the_mint(confirmer, minting.ledger, &outcome);
    Some(outcome)
}

/// The offer that starts a mint: what a DID is for, that it costs real XCH, and a real way to say no.
///
/// Public for the same reason [`funding_claim`] is: the gallery photographs THIS screen, not a copy.
///
/// Named rather than inline so its `refusal_is_default` is reachable from a test: affirming it SPENDS
/// REAL MONEY, so a bare Enter must not (the rule dig_ecosystem#2098 exists for).
pub fn mint_offer() -> ClaimPrompt<'static> {
    ClaimPrompt {
        title: copy::did::OFFER_TITLE,
        heading: copy::did::OFFER_HEADING,
        body: copy::did::OFFER_BODY,
        affirm: copy::did::OFFER_AFFIRM,
        decline: Some(copy::did::OFFER_DECLINE),
        // Affirming pushes a real mainnet spend. Enter must not.
        refusal_is_default: true,
        scannable: None,
        identifier: None,
    }
}

/// The wait screen itself: what is being waited for, how long it has been, and a way to stop.
///
/// Returned as a value (rather than drawn here) for the same reason the report screens are: one
/// unit-tested place decides the words, and the gallery photographs the real thing.
///
/// The elapsed figure is the whole point. A wait that says only "please wait" is indistinguishable
/// from a wedged one, and cannot be told apart from a spinner that will never stop.
pub fn waiting_screen(progress: &WaitProgress) -> WizardNotice {
    WizardNotice {
        title: copy::wait::TITLE,
        heading: match progress.connection_lost() {
            true => copy::wait::HEADING_OFFLINE,
            false => copy::wait::HEADING,
        },
        body: format!(
            "{}{}{}",
            copy::wait::BEFORE_WAITED,
            minutes(progress.elapsed_secs),
            match progress.connection_lost() {
                true => copy::wait::AFTER_WAITED_OFFLINE,
                false => copy::wait::AFTER_WAITED,
            }
        ),
        identifier: None,
    }
}

/// The production [`WaitSurface`]: an OS-owned window that reports the wait and offers to stop it.
///
/// # Why the window is a CLAIM and not a notice
///
/// Refusing it genuinely changes what happens — the watch stops — so the negative choice is
/// load-bearing and must be a real, labelled control. It is also the ONLY reason this wait is not the
/// trap `professional-ui`'s first rule forbids: a person who does not want to sit through a dozen
/// blocks can leave, and leaving costs them nothing, because the spend is on the chain either way.
pub struct WindowedWait<'a> {
    /// Where the check-in is drawn.
    confirmer: &'a dyn NativeConfirmer,
}

impl<'a> WindowedWait<'a> {
    /// Wait through `confirmer`.
    pub fn new(confirmer: &'a dyn NativeConfirmer) -> Self {
        Self { confirmer }
    }
}

/// The check-in as a prompt: [`waiting_screen`]'s words, plus the two answers it offers.
///
/// Split from `checking_in` so ONE place decides that this screen has two buttons. A gallery that
/// rebuilt it would eventually photograph a one-button lookalike — a picture of a wait that cannot be
/// stopped, which is the specific thing this screen exists to avoid being.
pub fn waiting_claim(screen: &WizardNotice) -> ClaimPrompt<'_> {
    ClaimPrompt {
        title: screen.title,
        heading: screen.heading,
        body: &screen.body,
        affirm: copy::wait::KEEP_WAITING,
        decline: Some(copy::wait::STOP_WATCHING),
        // Keeping the watch is what the user asked for and costs nothing; stopping is the deliberate
        // choice, so the affirmative stays the default.
        refusal_is_default: false,
        scannable: None,
        identifier: None,
    }
}

impl WaitSurface for WindowedWait<'_> {
    fn checking_in(&self, progress: &WaitProgress) -> KeepWaiting {
        let screen = waiting_screen(progress);
        match self.confirmer.confirm_claim(&waiting_claim(&screen)) {
            ConfirmDecision::Approve => KeepWaiting::Yes,
            // A refusal stops the watch; so does a host that could not draw the window, because
            // waiting on a check-in nobody can answer is the wedged spinner in another costume.
            _ => KeepWaiting::No,
        }
    }

    fn wait_a_moment(&self) {
        std::thread::sleep(std::time::Duration::from_secs(POLL_EVERY_SECS));
    }
}

/// Tell the user how the wait ended, and record the DID on the ONE ending that earned it.
///
/// The write and the congratulation live on the same arm deliberately: they are the same claim, so
/// they cannot drift into a screen that says "your DID is ready" over a ledger that holds nothing.
fn report_the_mint(confirmer: &dyn NativeConfirmer, ledger: &dyn DidLedger, outcome: &MintOutcome) {
    // The write happens BEFORE the screen is composed, because what the screen says depends on
    // whether it succeeded: a confirmed mint whose note could not be saved must not be congratulated
    // as if it had been.
    let recorded = match outcome {
        MintOutcome::Confirmed { did, evidence } => {
            Some(ledger.record(&DidRecord::from_mint(did, evidence.clone())))
        }
        _ => None,
    };
    let screen = mint_report(outcome, recorded);
    confirmer.show_notice(&NoticePrompt {
        title: screen.title,
        heading: screen.heading,
        body: &screen.body,
        acknowledge: "OK",
        identifier: screen.identifier.as_deref(),
    });
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

/// What the user is told about `outcome`.
///
/// `recorded` is `Some(true)` when a confirmed DID was written down, `Some(false)` when the write
/// failed, and `None` for every ending that has no DID to record — so the "confirmed but not saved"
/// screen cannot be reached by any ending except a real confirmation.
pub fn mint_report(outcome: &MintOutcome, recorded: Option<bool>) -> WizardNotice {
    match outcome {
        MintOutcome::Confirmed { did, .. } => WizardNotice {
            title: copy::did::CONFIRMED_TITLE,
            heading: copy::did::CONFIRMED_HEADING,
            body: match recorded {
                // The chain is the truth and it says the DID exists; what failed is this computer's
                // note of it. Saying so is better than a silent re-mint offer that would spend again.
                Some(false) => copy::did::CONFIRMED_BUT_UNRECORDED_BODY.to_owned(),
                _ => copy::did::CONFIRMED_BODY.to_owned(),
            },
            identifier: Some(did.clone()),
        },
        MintOutcome::Rejected { reason } => WizardNotice {
            title: copy::did::REJECTED_TITLE,
            heading: copy::did::REJECTED_HEADING,
            // The chain's own words are LABELLED and put last rather than led with. Unlabelled, a
            // lowercase fragment from a node reads as a broken first sentence of DIG's own prose.
            body: format!(
                "{}

{}
{reason}",
                copy::did::REJECTED_BODY,
                copy::did::REJECTED_REASON_LABEL
            ),
            // A rejected spend is not something to look up or keep; the chain's reason is the
            // whole answer, and it is prose.
            identifier: None,
        },
        MintOutcome::StillPending {
            spend_id,
            waited_secs,
        } => WizardNotice {
            title: copy::did::PENDING_TITLE,
            heading: copy::did::PENDING_HEADING,
            body: format!(
                "{}{}{}

{}",
                copy::did::PENDING_BEFORE_WAITED,
                minutes(*waited_secs),
                copy::did::PENDING_AFTER_WAITED,
                copy::did::PENDING_BODY,
            ),
            identifier: Some(spend_id.clone()),
        },
        MintOutcome::ConnectionLost { spend_id } => WizardNotice {
            title: copy::did::OFFLINE_TITLE,
            heading: copy::did::OFFLINE_HEADING,
            body: copy::did::OFFLINE_BODY.to_owned(),
            identifier: Some(spend_id.clone()),
        },
    }
}

/// A duration a person can read, from seconds. "1 minute", "7 minutes", "less than a minute".
///
/// Rounded down rather than up: a wait reported as longer than it was invites the reader to conclude
/// the app is guessing, and the exact second is not what this sentence is for.
fn minutes(seconds: u64) -> String {
    match seconds / 60 {
        0 => copy::did::LESS_THAN_A_MINUTE.to_owned(),
        1 => "1 minute".to_owned(),
        many => format!("{many} minutes"),
    }
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

    /// The check-in shown while the chain is being waited on.
    pub(super) mod wait {
        /// The window title.
        pub const TITLE: &str = "DIG — Waiting for the blockchain";
        /// The heading on a healthy wait.
        pub const HEADING: &str = "Your DID is on its way.";
        /// The heading when the watcher cannot reach the chain.
        pub const HEADING_OFFLINE: &str = "DIG is having trouble reaching the blockchain.";
        /// The sentence before the elapsed figure.
        pub const BEFORE_WAITED: &str = "DIG has been waiting ";
        /// The sentence after it, on a healthy wait.
        ///
        /// `concat!` rather than backslash continuations: this file has been bitten before by a
        /// literal that acquired a hole mid-sentence, and this very sentence acquired two — visible
        /// in the screenshot, invisible to every assertion that only looked for substrings.
        pub const AFTER_WAITED: &str = concat!(
            " for the blockchain to confirm the transaction that creates your DID. ",
            "A few minutes is normal.\n\n",
            "You can stop watching at any time. That does not cancel anything — the transaction is ",
            "already on the blockchain, and the DIG menu will tell you how it went.",
        );
        /// The sentence after it when the connection is the problem.
        pub const AFTER_WAITED_OFFLINE: &str = concat!(
            " and cannot currently reach the blockchain to check. Your transaction was sent and is ",
            "probably fine; what stopped is this computer's ability to watch for it.\n\n",
            "Check this computer's internet connection. You can stop watching at any time — that ",
            "cancels nothing, and the DIG menu will tell you how it went.",
        );
        /// The control that keeps the watch running.
        pub const KEEP_WAITING: &str = "Keep waiting";
        /// The control that stops it. NOT "Cancel" — nothing is cancelled.
        pub const STOP_WATCHING: &str = "Stop watching";
    }

    /// The DID step, from the offer through every way the wait can end.
    pub(super) mod did {
        /// The offer window's title.
        pub const OFFER_TITLE: &str = "DIG — Create your on-chain DID";
        /// Its heading.
        pub const OFFER_HEADING: &str = "Create your DID on the Chia blockchain?";
        /// Its body: what a DID is for, what it costs, and what waiting will look like.
        pub const OFFER_BODY: &str =
            "A DID publishes your identity on the Chia blockchain so others can find and verify it. It \
             is what turns the wallet on this computer into a full DIG Account, and it is what \
             publishing, signing for an app and messaging need.\n\n\
             Creating one is a real transaction that spends real XCH from your account: a small \
             network fee, plus one mojo that becomes the DID itself. Choosing \"Create my DID\" is \
             the approval — the transaction is sent straight away and cannot be called back.\n\n\
             Once it is sent, the blockchain takes a few minutes to confirm it. DIG will wait with you \
             and tell you how it went — you can stop watching at any time without cancelling anything.";
        /// The affirming control.
        pub const OFFER_AFFIRM: &str = "Create my DID";
        /// The declining control. Names what it does; it is not a cancel out of the app.
        pub const OFFER_DECLINE: &str = "Not now";
        /// The title shown after declining.
        pub const LATER_TITLE: &str = "DIG — You can do this later";
        /// Its heading.
        pub const LATER_HEADING: &str = "Your wallet is set up. Your DID is not.";
        /// Its body — the honest cost of declining, and where the step lives afterwards.
        pub const LATER_BODY: &str =
            "Reading content on the DIG Network works right now, with no DID and no funds — that has \
             not changed.\n\n\
             Publishing, signing for an app and messaging need a DID, so those will ask you to create \
             one when you first use them. You can also start it any time from the DIG menu.";
        /// The title on a build that cannot mint.
        pub const UNAVAILABLE_TITLE: &str = "DIG — One step still to come";
        /// Its heading.
        pub const UNAVAILABLE_HEADING: &str = "Your wallet is set up. Your DID is not.";
        /// Its body. The #1820 wording: REQUIRED, and not available in this version — never "optional",
        /// and never the retired claim that the account fully works without one.
        pub const UNAVAILABLE_BODY: &str =
            "A DID is what publishes your identity on the Chia blockchain so others can find and verify \
             it, and it is the step that turns this wallet into a full DIG Account.\n\n\
             Minting one is not available in this version of DIG. Nothing is missing from your setup and \
             there is nothing for you to do — when minting arrives, the DIG menu will offer it here.\n\n\
             Until then your account holds funds, signs, and reads content normally.";
        /// The title when the wallet cannot pay for the mint.
        pub const UNAFFORDABLE_TITLE: &str = "DIG — Not enough XCH yet";
        /// Its heading.
        pub const UNAFFORDABLE_HEADING: &str = "There is not enough XCH to create your DID.";
        /// The sentence before the cost figure.
        pub const UNAFFORDABLE_BEFORE_COST: &str = "Creating a DID costs about ";
        /// The sentence after it.
        pub const UNAFFORDABLE_AFTER_COST: &str =
            " XCH, and your account does not hold that yet. Nothing was sent and nothing was \
             spent.\n\n\
             Send XCH to your DIG address — it is in the DIG menu — and start this again whenever you \
             are ready. Reading content needs no funds at all.";
        /// The title when the spend never left this computer.
        pub const REFUSED_TITLE: &str = "DIG — Nothing was sent";
        /// Its heading.
        pub const REFUSED_HEADING: &str = "Your DID was not created.";
        /// Its body, shown beneath the reason.
        pub const REFUSED_BODY: &str =
            "Nothing was spent and nothing on your account changed. You can start again from the DIG \
             menu whenever you are ready.";
        /// The title of the ONE success screen in this flow.
        pub const CONFIRMED_TITLE: &str = "DIG — Your DID is live";
        /// Its heading.
        pub const CONFIRMED_HEADING: &str = "Your DID is on the blockchain.";
        /// Its body, shown beneath the DID itself.
        pub const CONFIRMED_BODY: &str =
            "Your DIG Account is complete. Publishing, signing for an app and messaging are all open to \
             you now, and your DID is in the DIG menu whenever you need it.";
        /// The same screen when this computer could not write its own note of the DID.
        pub const CONFIRMED_BUT_UNRECORDED_BODY: &str =
            "Your DID exists on the blockchain — that part is done and cannot be undone. DIG could not \
             save its note of it on this computer, so it may ask about your DID again. Do NOT create a \
             second one: that would spend again. The log folder, in the DIG menu, has the details.";
        /// The title when the chain refused the spend.
        pub const REJECTED_TITLE: &str = "DIG — Your DID was not created";
        /// Its heading.
        pub const REJECTED_HEADING: &str = "The blockchain did not accept the transaction.";
        /// The label the chain's own words are put under.
        pub const REJECTED_REASON_LABEL: &str = "The blockchain's reason:";
        /// Its body, shown above the reason the chain gave.
        pub const REJECTED_BODY: &str =
            "No DID was created. A rejected transaction does not spend the amount it was for, though a \
             fee may have been used.\n\n\
             You can try again from the DIG menu. If it keeps happening, the log folder in that menu has \
             the details.";
        /// The title when the watch ended with no answer.
        pub const PENDING_TITLE: &str = "DIG — Still waiting on the blockchain";
        /// Its heading.
        pub const PENDING_HEADING: &str = "Your DID has been sent but is not confirmed.";
        /// The sentence before the elapsed figure.
        pub const PENDING_BEFORE_WAITED: &str = "DIG waited ";
        /// The sentence after it.
        ///
        /// It does NOT end in a blank line: [`mint_report`] joins the paragraphs, and a trailing
        /// separator here made the rendered screen open with a hole the height of two lines.
        pub const PENDING_AFTER_WAITED: &str = " and the blockchain has not confirmed it yet.";
        /// The rest of the body. It ends by introducing the spend id, which the window draws beneath
        /// the prose as its one mono identifier.
        pub const PENDING_BODY: &str =
            "Nothing has gone wrong — a busy blockchain can take longer than this, and your \
             transaction is still out there. Do NOT create a second DID; that would spend again.\n\n\
             Open the DIG menu later and it will tell you whether this one confirmed. This is the \
             transaction:";
        /// How a sub-minute wait is described.
        pub const LESS_THAN_A_MINUTE: &str = "less than a minute";
        /// The title when the chain could not be reached.
        pub const OFFLINE_TITLE: &str = "DIG — Lost contact with the blockchain";
        /// Its heading.
        pub const OFFLINE_HEADING: &str = "DIG cannot reach the blockchain right now.";
        /// Its body, shown beneath the spend id.
        pub const OFFLINE_BODY: &str =
            "Your transaction was sent and is probably fine — what stopped is this computer's ability \
             to watch for it. Do NOT create a second DID; that would spend again.\n\n\
             Check this computer's internet connection, then open the DIG menu to see whether the DID \
             confirmed. This is the transaction:";
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
    use crate::account::did::MintEvidence;
    use crate::account::mint::{KeepWaiting, Sighting, WaitProgress, POLL_EVERY_SECS};
    use crate::account::recovery::PHRASE_WORDS;
    use crate::confirm::{ConnectPrompt, PairPrompt, SignPrompt};
    use crate::sealer::SealError;
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

    // ---- The DID wizard's doubles (dig_ecosystem#2341) --------------------------------------------

    /// The DID the SUBMISSION names — the one the bundle was built to create, before the chain has
    /// said anything. Distinct from [`CONFIRMED_DID`] on purpose: the two are the same value in
    /// reality, so a fixture that used one string could not tell "recorded from the confirmation"
    /// apart from "recorded from the push", which is the property the ledger's whole rule rests on.
    const MINTED_DID: &str = "did:chia:1wizardfixturedid00000000000000000000000000000000000000000";
    /// The DID the CONFIRMATION attests to. Only this may reach the ledger.
    const CONFIRMED_DID: &str =
        "did:chia:1wizardconfirmeddid0000000000000000000000000000000000000000";
    /// The spend the scripted minter reports.
    const MINTED_SPEND: &str = "0xwizardfixturespend";

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

    /// A minter that returns one scripted [`Submission`].
    struct ScriptedMinter(Submission);

    impl DidMinter for ScriptedMinter {
        fn submit(&self) -> Submission {
            self.0.clone()
        }
    }

    /// A minter that records HOW MANY windows the user had been shown at the instant it spent.
    ///
    /// The count is what makes the property observable. Whether a cost is shown before a spend is a
    /// statement about the ORDER of two things, and no assertion on the returned outcome — or on the
    /// text of the windows afterwards — can tell a flow that showed a cost screen from one that did
    /// not. Only the count taken INSIDE the spend can.
    struct WindowCountingMinter<'a> {
        confirmer: &'a ScriptedConfirmer,
        windows_at_spend: Mutex<Option<usize>>,
        /// The text of everything drawn when it spent, so the ONE window can be identified.
        text_at_spend: Mutex<String>,
    }

    impl DidMinter for WindowCountingMinter<'_> {
        fn submit(&self) -> Submission {
            *self.windows_at_spend.lock().unwrap() = Some(self.confirmer.windows_drawn());
            *self.text_at_spend.lock().unwrap() = self.confirmer.drawn();
            Submission::Submitted {
                spend_id: MINTED_SPEND.to_owned(),
                did: MINTED_DID.to_owned(),
            }
        }
    }

    /// **The offer IS the approval, and the copy may not promise otherwise** (dig_ecosystem#2377).
    ///
    /// `OFFER_BODY` used to promise *"You will see the exact cost, and approve it, before anything is
    /// spent"*, and the funding screen promised DIG *"will never spend anything without showing you
    /// exactly what it is spending first"*. Both were true only while nothing could spend. The first
    /// half of this test measures what the flow actually does — exactly ONE window stands between the
    /// person and a real mainnet spend, and it is the offer — and the second half holds every
    /// pre-spend sentence to that measurement.
    ///
    /// Written as a measurement rather than a transcription on purpose: if a cost screen is ever
    /// added, the first assertion fails and the copy rule below is the one that should then change.
    #[test]
    fn nothing_shown_before_a_spend_may_promise_a_cost_screen_that_does_not_exist() {
        let confirmer = ScriptedConfirmer::new(Vec::new(), vec![ConfirmDecision::Approve]);
        let minter = WindowCountingMinter {
            confirmer: &confirmer,
            windows_at_spend: Mutex::new(None),
            text_at_spend: Mutex::new(String::new()),
        };
        let clock = TestClock::default();
        let surface = PatientWait(&clock);
        let ledger = MemoryLedger::default();
        let chain = ChainDouble(Sighting::Pending);

        mint_the_did(
            &confirmer,
            &DidMinting {
                minter: &minter,
                observer: &chain,
                surface: &surface,
                clock: &clock,
                ledger: &ledger,
            },
        );

        let count = minter
            .windows_at_spend
            .lock()
            .unwrap()
            .expect("the approved offer must reach the spend");
        let text = minter.text_at_spend.lock().unwrap().clone();
        assert_eq!(
            count, 1,
            "the offer is the ONLY thing between a person and a real spend: {text}"
        );
        assert!(
            text.contains(copy::did::OFFER_HEADING),
            "and that one window is the offer: {text}"
        );

        // So no screen a person sees before that spend may defer the approval to a later one.
        for (name, body) in [
            ("the mint offer", copy::did::OFFER_BODY),
            ("the unavailable notice", copy::did::UNAVAILABLE_BODY),
            ("the funding screen", copy::fund::BODY_WITH_A_CODE),
            ("the funding screen (text only)", copy::fund::BODY_TEXT_ONLY),
        ] {
            for promise in [
                "before anything is spent",
                "showing you exactly what it is spending first",
                "see the exact cost",
            ] {
                assert!(
                    !body.contains(promise),
                    "{name} promises \"{promise}\", and no such screen exists"
                );
            }
        }
    }

    /// A chain that answers every look the same way — enough for the wizard's tests, since the WAIT's
    /// own sequencing is proven in [`crate::account::mint`].
    struct ChainDouble(Sighting);

    impl MintObserver for ChainDouble {
        fn look(&self, _spend_id: &str) -> Sighting {
            self.0.clone()
        }
    }

    /// A clock the wait surface advances, so a wait that never confirms still reaches its bound.
    #[derive(Default)]
    struct TestClock(std::sync::atomic::AtomicU64);

    impl Clock for TestClock {
        fn now_unix(&self) -> u64 {
            self.0.load(std::sync::atomic::Ordering::Relaxed)
        }
    }

    /// A wait surface that never stops watching and advances `clock` a poll at a time.
    struct PatientWait<'a>(&'a TestClock);

    impl WaitSurface for PatientWait<'_> {
        fn checking_in(&self, _progress: &WaitProgress) -> KeepWaiting {
            KeepWaiting::Yes
        }

        fn wait_a_moment(&self) {
            self.0
                 .0
                .fetch_add(POLL_EVERY_SECS, std::sync::atomic::Ordering::Relaxed);
        }
    }

    /// A [`DidLedger`] in memory, so a test can ask what the wizard actually recorded.
    #[derive(Default)]
    struct MemoryLedger(Mutex<Option<DidRecord>>);

    impl DidLedger for MemoryLedger {
        fn recorded(&self) -> Option<DidRecord> {
            self.0.lock().unwrap().clone()
        }

        fn record(&self, record: &DidRecord) -> bool {
            *self.0.lock().unwrap() = Some(record.clone());
            true
        }
    }

    /// The DID step's whole dependency chain, wired to doubles.
    struct Bench {
        minter: ScriptedMinter,
        chain: ChainDouble,
        clock: TestClock,
        ledger: MemoryLedger,
    }

    impl Bench {
        /// The PRODUCTION shape today: nothing can mint.
        fn unable_to_mint() -> Self {
            Self::submitting(Submission::NotAvailable, Sighting::Pending)
        }

        /// A minter that pushes a spend, and a chain that answers `sighting` every time.
        fn submitting(submission: Submission, sighting: Sighting) -> Self {
            Self {
                minter: ScriptedMinter(submission),
                chain: ChainDouble(sighting),
                clock: TestClock::default(),
                ledger: MemoryLedger::default(),
            }
        }

        /// A minter that pushes the fixture spend.
        fn minting_successfully(sighting: Sighting) -> Self {
            Self::submitting(
                Submission::Submitted {
                    spend_id: MINTED_SPEND.to_owned(),
                    did: MINTED_DID.to_owned(),
                },
                sighting,
            )
        }

        fn wiring<'a>(&'a self, surface: &'a PatientWait<'a>) -> DidMinting<'a> {
            DidMinting {
                minter: &self.minter,
                observer: &self.chain,
                surface,
                clock: &self.clock,
                ledger: &self.ledger,
            }
        }
    }

    /// Run the wizard on a machine with no account and no DID, against a minter that cannot mint —
    /// exactly what this build does — so the pre-existing first-run tests keep asserting the same flow.
    fn run_wizard(
        confirmer: &ScriptedConfirmer,
        create: impl FnOnce() -> Option<String>,
        import: impl FnOnce(&RecoveryPhrase) -> Option<String>,
    ) -> FirstRunOutcome {
        let bench = Bench::unable_to_mint();
        let surface = PatientWait(&bench.clock);
        first_run_wizard(
            confirmer,
            AccountPresence::Absent,
            create,
            import,
            &RecordingCopier::working(),
            &bench.wiring(&surface),
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

    /// **The #1820 copy correction.** The DID step must name the DID as the remaining REQUIRED step and
    /// must not repeat the retired claim that the account "fully works without a DID".
    ///
    /// Asserted on the drawn text because that claim is exactly what the user reads, and it was a
    /// sentence in the product — not a behaviour — that made a mandatory step look optional.
    #[test]
    fn the_did_step_names_it_as_required_and_admits_it_cannot_mint() {
        let confirmer = ScriptedConfirmer::new(
            vec![],
            vec![
                ConfirmDecision::Approve,
                ConfirmDecision::Deny,
                ConfirmDecision::Approve,
                ConfirmDecision::Approve,
            ],
        );
        run_wizard(&confirmer, || Some(ADDRESS.to_string()), never_imports);
        let drawn = confirmer.drawn().to_lowercase();

        assert!(
            drawn.contains("not available in this version"),
            "the DID step must admit minting cannot run yet: {drawn}"
        );
        assert!(
            !drawn.contains("fully works without"),
            "the retired 'works without a DID' copy must not come back: {drawn}"
        );
        assert!(
            !drawn.contains("optional"),
            "a DID is the bedrock of the account and must not be described as optional: {drawn}"
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
        let bench = Bench::unable_to_mint();
        let surface = PatientWait(&bench.clock);

        let outcome = first_run_wizard(
            &confirmer,
            AccountPresence::Wallet { address: ADDRESS },
            || panic!("an existing wallet must not be re-created"),
            never_imports,
            &RecordingCopier::working(),
            &bench.wiring(&surface),
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

    /// An account holding a minted DID is not sent through the wizard at all.
    #[test]
    fn an_account_with_a_minted_did_does_not_need_the_wizard() {
        let minted = DidRecord::from_mint(MINTED_DID, MintEvidence::confirmed(MINTED_SPEND, 12));
        assert!(wizard_needed(None), "no DID means the wizard is needed");
        assert!(
            !wizard_needed(Some(&minted)),
            "a minted DID must not re-run the wizard"
        );
    }

    /// **The funding step offers the address BOTH ways: as a scannable code and as the window's mono
    /// identifier.** A QR alone strands the person funding from a wallet on this same computer.
    #[test]
    fn the_funding_step_offers_the_address_as_a_code_and_as_text() {
        let confirmer = ScriptedConfirmer::drawing_qr(vec![ConfirmDecision::Approve; 4]);
        let bench = Bench::unable_to_mint();
        let surface = PatientWait(&bench.clock);

        first_run_wizard(
            &confirmer,
            AccountPresence::Wallet { address: ADDRESS },
            || panic!("must not create"),
            never_imports,
            &RecordingCopier::working(),
            &bench.wiring(&surface),
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
            let bench = Bench::unable_to_mint();
            let surface = PatientWait(&bench.clock);
            first_run_wizard(
                &confirmer,
                AccountPresence::Wallet { address: ADDRESS },
                || panic!("must not create"),
                never_imports,
                &RecordingCopier::working(),
                &bench.wiring(&surface),
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
        let bench = Bench::unable_to_mint();
        let surface = PatientWait(&bench.clock);

        first_run_wizard(
            &confirmer,
            AccountPresence::Wallet { address: ADDRESS },
            || panic!("must not create"),
            never_imports,
            &copier,
            &bench.wiring(&surface),
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
        let bench = Bench::unable_to_mint();
        let surface = PatientWait(&bench.clock);

        first_run_wizard(
            &confirmer,
            AccountPresence::Wallet { address: ADDRESS },
            || panic!("must not create"),
            never_imports,
            &RecordingCopier::broken(),
            &bench.wiring(&surface),
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

    /// Minting spends real money, so a bare Enter must not start it.
    #[test]
    fn the_mint_offer_does_not_spend_on_a_reflexive_enter() {
        assert!(
            mint_offer().refusal_is_default,
            "affirming the mint offer pushes a real mainnet spend"
        );
        assert!(
            mint_offer().decline.is_some(),
            "declining the mint is choosing something else, not cancelling"
        );
    }

    /// Declining the mint leaves the app usable and says what it costs — the escape that keeps this
    /// wizard from being a wall for someone who only wants to read.
    #[test]
    fn declining_the_mint_leaves_reading_open() {
        // fund=Approve, mint offer=Deny, the "later" notice.
        let confirmer = ScriptedConfirmer::new(
            vec![],
            vec![
                ConfirmDecision::Approve,
                ConfirmDecision::Deny,
                ConfirmDecision::Approve,
            ],
        );
        let bench = Bench::minting_successfully(Sighting::Pending);
        let surface = PatientWait(&bench.clock);

        let outcome = first_run_wizard(
            &confirmer,
            AccountPresence::Wallet { address: ADDRESS },
            || panic!("must not create"),
            never_imports,
            &RecordingCopier::working(),
            &bench.wiring(&surface),
        );

        assert_eq!(outcome, FirstRunOutcome::WalletCreated);
        assert!(
            bench.ledger.recorded().is_none(),
            "declining must not record a DID"
        );
        let drawn = confirmer.drawn().to_lowercase();
        assert!(
            drawn.contains("reading content"),
            "the user must be told what still works: {drawn}"
        );
    }

    /// **A submitted spend that never confirms produces NO success — and NO recorded DID.**
    ///
    /// This is the false-green trap the whole design is against: the minter succeeded, so an
    /// implementation that treated submission as the outcome would look completely correct. The
    /// assertion is therefore on the LEDGER as well as the copy — a screen can be reworded, but a
    /// recorded DID for a spend the chain never confirmed is the defect itself.
    #[test]
    fn a_submitted_mint_that_never_confirms_is_never_reported_as_a_success() {
        let confirmer = ScriptedConfirmer::new(vec![], vec![ConfirmDecision::Approve; 4]);
        let bench = Bench::minting_successfully(Sighting::Pending);
        let surface = PatientWait(&bench.clock);

        let outcome = first_run_wizard(
            &confirmer,
            AccountPresence::Wallet { address: ADDRESS },
            || panic!("must not create"),
            never_imports,
            &RecordingCopier::working(),
            &bench.wiring(&surface),
        );

        assert_eq!(
            outcome,
            FirstRunOutcome::WalletCreated,
            "a wallet, not an identity: the chain never confirmed"
        );
        assert!(
            bench.ledger.recorded().is_none(),
            "a DID must never be recorded without confirmation"
        );
        let drawn = confirmer.drawn();
        assert!(
            drawn.contains(MINTED_SPEND),
            "a pending mint must give the user the spend to look up: {drawn}"
        );
        assert!(
            !drawn
                .to_lowercase()
                .contains("your did is on the blockchain"),
            "nothing may claim the DID is live: {drawn}"
        );
    }

    /// A CONFIRMED mint — and only that — records the DID with its evidence and reports an identity.
    #[test]
    fn a_confirmed_mint_records_the_did_with_its_evidence() {
        let confirmer = ScriptedConfirmer::new(vec![], vec![ConfirmDecision::Approve; 4]);
        let bench = Bench::minting_successfully(Sighting::Confirmed {
            did: CONFIRMED_DID.to_owned(),
            evidence: MintEvidence::confirmed(MINTED_SPEND, 5_412_009),
        });
        let surface = PatientWait(&bench.clock);

        let outcome = first_run_wizard(
            &confirmer,
            AccountPresence::Wallet { address: ADDRESS },
            || panic!("must not create"),
            never_imports,
            &RecordingCopier::working(),
            &bench.wiring(&surface),
        );

        assert_eq!(outcome, FirstRunOutcome::IdentityReady);
        let recorded = bench.ledger.recorded().expect("the DID must be recorded");
        assert_eq!(
            recorded.did(),
            CONFIRMED_DID,
            "the DID recorded must be the one the chain attested to, not the one that was pushed"
        );
        assert_eq!(recorded.evidence().confirmed_height(), 5_412_009);
        assert!(confirmer.drawn().contains(CONFIRMED_DID));
    }

    /// A chain that REJECTS the spend gets its own honest screen and records nothing.
    #[test]
    fn a_rejected_mint_records_nothing_and_says_what_happened() {
        let confirmer = ScriptedConfirmer::new(vec![], vec![ConfirmDecision::Approve; 4]);
        let bench = Bench::minting_successfully(Sighting::Rejected {
            reason: "the coin was already spent".to_owned(),
        });
        let surface = PatientWait(&bench.clock);

        let outcome = first_run_wizard(
            &confirmer,
            AccountPresence::Wallet { address: ADDRESS },
            || panic!("must not create"),
            never_imports,
            &RecordingCopier::working(),
            &bench.wiring(&surface),
        );

        assert_eq!(outcome, FirstRunOutcome::WalletCreated);
        assert!(bench.ledger.recorded().is_none());
        let drawn = confirmer.drawn();
        assert!(
            drawn.contains("the coin was already spent"),
            "the chain's own reason must reach the user: {drawn}"
        );
    }

    /// A lost connection is reported as a lost connection — never as a failed mint — and points the
    /// user at the spend rather than at a second one.
    #[test]
    fn a_lost_connection_does_not_tell_the_user_their_mint_failed() {
        let confirmer = ScriptedConfirmer::new(vec![], vec![ConfirmDecision::Approve; 4]);
        let bench = Bench::minting_successfully(Sighting::Unreachable);
        let surface = PatientWait(&bench.clock);

        first_run_wizard(
            &confirmer,
            AccountPresence::Wallet { address: ADDRESS },
            || panic!("must not create"),
            never_imports,
            &RecordingCopier::working(),
            &bench.wiring(&surface),
        );

        let drawn = confirmer.drawn();
        assert!(drawn.contains(MINTED_SPEND));
        let lowered = drawn.to_lowercase();
        assert!(
            lowered.contains("cannot reach the blockchain"),
            "the connection must be named as what failed: {drawn}"
        );
        assert!(
            lowered.contains("do not create a second did"),
            "a user must be warned off spending twice: {drawn}"
        );
    }

    /// Every ending of the mint carries a way forward — none of them is a dead end (#1800's rule).
    ///
    /// Driven over the whole set of endings rather than one, because a single-ending test cannot see
    /// the arm somebody adds later without a remedy.
    #[test]
    fn every_mint_ending_names_something_the_user_can_do() {
        for sighting in [
            Sighting::Pending,
            Sighting::Rejected {
                reason: "the coin was already spent".to_owned(),
            },
            Sighting::Unreachable,
        ] {
            let confirmer = ScriptedConfirmer::new(vec![], vec![ConfirmDecision::Approve; 4]);
            let bench = Bench::minting_successfully(sighting.clone());
            let surface = PatientWait(&bench.clock);
            first_run_wizard(
                &confirmer,
                AccountPresence::Wallet { address: ADDRESS },
                || panic!("must not create"),
                never_imports,
                &RecordingCopier::working(),
                &bench.wiring(&surface),
            );

            let drawn = confirmer.drawn().to_lowercase();
            assert!(
                drawn.contains("dig menu"),
                "{sighting:?} left the user with nowhere to go: {drawn}"
            );
        }
    }

    /// A wallet that cannot pay is told the cost and that nothing was spent.
    #[test]
    fn an_unaffordable_mint_names_the_cost_and_spends_nothing() {
        let confirmer = ScriptedConfirmer::new(vec![], vec![ConfirmDecision::Approve; 4]);
        let bench = Bench::submitting(
            Submission::InsufficientFunds {
                needed: "0.000000000001".to_owned(),
            },
            Sighting::Pending,
        );
        let surface = PatientWait(&bench.clock);

        first_run_wizard(
            &confirmer,
            AccountPresence::Wallet { address: ADDRESS },
            || panic!("must not create"),
            never_imports,
            &RecordingCopier::working(),
            &bench.wiring(&surface),
        );

        let drawn = confirmer.drawn();
        assert!(
            drawn.contains("0.000000000001"),
            "the cost must be shown as given, not re-derived: {drawn}"
        );
        assert!(drawn.to_lowercase().contains("nothing was spent"));
        assert!(bench.ledger.recorded().is_none());
    }

    /// **The wait screen names the elapsed time and a way to stop.**
    ///
    /// Both halves matter: a check-in with no duration cannot be told from a wedged one, and a
    /// check-in with no way out is the trap this whole design exists to avoid.
    #[test]
    fn the_wait_screen_reports_how_long_it_has_been_and_how_to_stop() {
        let screen = waiting_screen(&WaitProgress {
            elapsed_secs: 240,
            give_up_after_secs: 600,
            unreachable_looks: 0,
        });
        assert!(
            screen.body.contains("4 minutes"),
            "the real elapsed time must be on the screen: {}",
            screen.body
        );
        assert!(
            screen.body.to_lowercase().contains("stop watching"),
            "the way out must be named: {}",
            screen.body
        );
        assert!(
            screen.body.to_lowercase().contains("cancel"),
            "stopping must be explained as not cancelling anything: {}",
            screen.body
        );
    }

    /// A wait whose watcher cannot reach the chain SAYS so, rather than looking identical to a healthy
    /// one. The two screens are compared, so copy that never varied would fail.
    #[test]
    fn a_wait_that_cannot_see_the_chain_looks_different_from_a_healthy_one() {
        let healthy = WaitProgress {
            elapsed_secs: 240,
            give_up_after_secs: 600,
            unreachable_looks: 0,
        };
        let offline = WaitProgress {
            unreachable_looks: 6,
            ..healthy
        };
        assert_ne!(waiting_screen(&healthy), waiting_screen(&offline));
        assert!(waiting_screen(&offline)
            .heading
            .to_lowercase()
            .contains("reaching the blockchain"));
    }

    /// **A host that cannot draw the check-in STOPS the watch.**
    ///
    /// The alternative — treat an undrawable window as "keep waiting" — is a loop nobody can see and
    /// nobody can leave, on a machine that by definition cannot ask.
    #[test]
    fn a_check_in_that_cannot_be_drawn_stops_the_watch() {
        let progress = WaitProgress {
            elapsed_secs: 240,
            give_up_after_secs: 600,
            unreachable_looks: 0,
        };
        assert_eq!(
            WindowedWait::new(&crate::confirm::HeadlessConfirmer).checking_in(&progress),
            KeepWaiting::No
        );
        // ... and a host that CAN draw, and whose user says keep going, keeps going — so the assertion
        // above is about the undrawable host, not about a surface that always stops.
        let willing = ScriptedConfirmer::new(vec![], vec![ConfirmDecision::Approve]);
        assert_eq!(
            WindowedWait::new(&willing).checking_in(&progress),
            KeepWaiting::Yes
        );
    }

    /// The elapsed wait is described in the user's terms, and never rounded UP into a longer wait than
    /// actually happened.
    #[test]
    fn a_wait_is_described_in_minutes_without_overstating_it() {
        assert_eq!(minutes(0), copy::did::LESS_THAN_A_MINUTE);
        assert_eq!(minutes(59), copy::did::LESS_THAN_A_MINUTE);
        assert_eq!(minutes(60), "1 minute");
        assert_eq!(minutes(119), "1 minute");
        assert_eq!(minutes(600), "10 minutes");
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

    /// Completeness is read from a MINTED DID and nothing else — an account with no DID is
    /// `WalletOnly`, which is every account today.
    #[test]
    fn completeness_follows_the_minted_did() {
        assert_eq!(
            AccountCompleteness::of(None),
            AccountCompleteness::WalletOnly
        );
        assert_eq!(
            AccountCompleteness::of(Some("did:chia:abc")),
            AccountCompleteness::DidBound
        );
    }

    /// **The wizard opens at startup for exactly one state: an enrolled account with no DID, on a
    /// host that can mint.**
    ///
    /// Asserted over the WHOLE cross-product rather than the one true case, because the property is
    /// the shape of the decision, not a single answer. The nearest wrong implementation — "open
    /// whenever no DID is recorded" — agrees with this test on the true case and disagrees on three
    /// of the four false ones, which is exactly what the enumeration is for.
    #[test]
    fn the_startup_wizard_opens_only_for_an_enrolled_account_that_can_still_mint() {
        use MintAvailability::{NoChainTransport, Possible};
        use StartupAccount::{Enrolled, NotEnrolled};

        assert_eq!(
            startup_wizard(Enrolled(AccountCompleteness::WalletOnly), Possible),
            StartupWizard::AtTheDidStep,
            "an account with a wallet and no DID is precisely what dig_ecosystem#2359 describes"
        );

        for (account, mint, why) in [
            (
                Enrolled(AccountCompleteness::DidBound),
                Possible,
                "an account that already holds a DID must never see the wizard again",
            ),
            (
                Enrolled(AccountCompleteness::WalletOnly),
                NoChainTransport,
                "a host that cannot mint must not show a window with no control that could clear it",
            ),
            (
                NotEnrolled,
                Possible,
                "reading DIG content needs no account, so a reader is never made to create one",
            ),
            (
                NotEnrolled,
                NoChainTransport,
                "neither condition holds, so neither reason to open it does",
            ),
        ] {
            assert_eq!(
                startup_wizard(account, mint),
                StartupWizard::NotNeeded,
                "{why}"
            );
        }
    }

    /// The two startup states, read the way the shell reads them: off a [`DidLedger`].
    ///
    /// This is the second half of the same property — that the decision is driven by RECORDED mint
    /// evidence rather than by a flag — so the fixture writes a real record and reads it back through
    /// the production ledger rather than passing a hand-made enum.
    #[test]
    fn a_recorded_mint_is_what_turns_the_startup_wizard_off() {
        let dir = tempfile::tempdir().unwrap();
        let ledger = crate::account::did::DidFile::new(dir.path());

        let before = ledger.recorded();
        assert_eq!(
            startup_wizard(
                StartupAccount::Enrolled(AccountCompleteness::of(
                    before.as_ref().map(DidRecord::did)
                )),
                MintAvailability::Possible
            ),
            StartupWizard::AtTheDidStep,
            "before any mint, the wizard opens"
        );

        assert!(ledger.record(&DidRecord::from_mint(
            MINTED_DID,
            MintEvidence::confirmed(MINTED_SPEND, 5_412_009)
        )));

        let after = ledger.recorded();
        assert_eq!(
            startup_wizard(
                StartupAccount::Enrolled(AccountCompleteness::of(
                    after.as_ref().map(DidRecord::did)
                )),
                MintAvailability::Possible
            ),
            StartupWizard::NotNeeded,
            "once a mint is recorded with its evidence, the wizard stays shut"
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
        assert!(drawn.contains("Manage my DIG Account"), "{drawn}");
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
    #[derive(Default)]
    struct RecordingCustodian {
        steps: Mutex<Vec<&'static str>>,
        /// What [`AccountCustodian::discard`] reports. Varied so the failure branch is reachable.
        discard: Mutex<Option<DiscardOutcome>>,
        /// Whether the enrolments succeed. A separate field from `discard`, because the interesting case is
        /// a SUCCESSFUL discard followed by a FAILED enrol — a double that could only vary one of the two
        /// could not express it, and that is the one path where custody is gone and nothing replaces it.
        enrol_succeeds: Mutex<bool>,
    }

    impl RecordingCustodian {
        fn new() -> Self {
            Self {
                steps: Mutex::new(Vec::new()),
                discard: Mutex::new(Some(DiscardOutcome::Discarded)),
                enrol_succeeds: Mutex::new(true),
            }
        }

        fn failing_discard() -> Self {
            let custodian = Self::new();
            *custodian.discard.lock().unwrap() = Some(DiscardOutcome::Failed);
            custodian
        }

        fn failing_enrol() -> Self {
            let custodian = Self::new();
            *custodian.enrol_succeeds.lock().unwrap() = false;
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
        fn enrol_new(&self) -> bool {
            self.note("enrol_new");
            *self.enrol_succeeds.lock().unwrap()
        }
        fn enrol_from(&self, _phrase: &RecoveryPhrase) -> bool {
            self.note("enrol_from");
            *self.enrol_succeeds.lock().unwrap()
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

    /// `destroyed_custody` is what every test above turns on, so it is pinned directly: it MUST be true for
    /// exactly the three outcomes that ran a discard, and false for the three that did not. A classifier
    /// that always answered `false` would quietly disarm the whole group.
    #[test]
    fn the_outcome_classifier_names_exactly_the_destructive_results() {
        for destructive in [
            ReplaceOutcome::Replaced,
            ReplaceOutcome::Removed,
            ReplaceOutcome::EnrolFailed,
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
        let custodian = RecordingCustodian::failing_enrol();
        replace_account(
            &ScriptedConfirmer::destroying(vec![ConfirmDecision::Approve], vec![None]),
            &custodian,
            Replacement::WithNewAccount,
            None::<&PhraseVault<PassthroughSealer>>,
        );

        // Plus every screen the DID wizard draws (dig_ecosystem#2341). Added because two of them
        // shipped with exactly this defect — a hole mid-sentence that every substring assertion in
        // this file passed straight over and only a screenshot showed.
        let wizard = ScriptedConfirmer::drawing_qr(vec![ConfirmDecision::Approve; 8]);
        let bench = Bench::minting_successfully(Sighting::Pending);
        let surface = PatientWait(&bench.clock);
        first_run_wizard(
            &wizard,
            AccountPresence::Wallet { address: ADDRESS },
            || panic!("must not create"),
            never_imports,
            &RecordingCopier::working(),
            &bench.wiring(&surface),
        );
        let wait_screens = [
            waiting_screen(&WaitProgress {
                elapsed_secs: 240,
                give_up_after_secs: 600,
                unreachable_looks: 0,
            }),
            waiting_screen(&WaitProgress {
                elapsed_secs: 240,
                give_up_after_secs: 600,
                unreachable_looks: 6,
            }),
            mint_report(
                &MintOutcome::Confirmed {
                    did: MINTED_DID.to_owned(),
                    evidence: MintEvidence::confirmed(MINTED_SPEND, 12),
                },
                Some(false),
            ),
        ]
        .map(|screen| screen.body)
        .join("\n");

        for window in [
            confirmer.drawn(),
            wizard.drawn(),
            wait_screens,
            RETENTION_AND_REVEAL_COPY.to_string(),
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
            UNOPENABLE_BODY.contains("Manage my DIG Account"),
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
