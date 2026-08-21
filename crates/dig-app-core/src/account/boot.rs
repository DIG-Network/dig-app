//! The production account BOOT glue — assembles the master-HD unlock/enroll flow the tray shell mounts
//! (#1547, custody switchover).
//!
//! Two verbs, deliberately separate (dig_ecosystem#1820, #1817):
//!
//! - [`open_account`] CREATES an account — the first-run/restore path, reached only because a user
//!   asked. It shows the 24-word recovery phrase, requires them to confirm they kept it, asks them to
//!   CHOOSE a password, seals the seed under it, and vaults a copy of the phrase so the tray can show it
//!   again (dig_ecosystem#1752).
//! - [`unlock_existing_account`] OPENS one that already exists, asking for that password.
//!
//! **Nothing here runs at start-up.** The app boots with the account LOCKED and unlocks on demand, like
//! a password manager: an account is never opened without the person who owns it, and the signing
//! channel stays refused until they turn up. Before #1817 the boot unlocked with a machine-generated
//! password out of the OS credential store, which meant "Unlock…" asked for nothing and any code in the
//! user's session could reach the master seed.
//!
//! [`assemble_residency`] is the testable core: over any keystore backend and any
//! [`AuthCeremony`] it enrols-or-unlocks the account (through
//! [`open_or_enroll`]) and houses the result in an
//! [`AccountResidency`]. The cfg-gated wrappers wire the host's real
//! [`PromptedCeremony`] + a per-user
//! [`FileBackend`](dig_session::FileBackend), and defer on Linux, which has no window stack for the
//! prompt yet.
//!
//! This is the ONE place the app turns "a brand directory" into "a live, lockable unlocked account",
//! so the tray shell stays a thin caller and every piece underneath (lifecycle, ceremony, residency)
//! is unit-tested on its own.
//!
//! [`PromptedCeremony`]: crate::account::ceremony::PromptedCeremony

use std::sync::Arc;

use crate::account::active_profile::WalletSlot;
use crate::account::profile_session::{FileRegistryStore, ProfileSession};
use dig_account::{AccountId, PasswordOnlyPolicy, ProfileIx, Result as AccountResult};

/// A [`PhrasePresenter`] that can never approve an enrolment — used on paths where enrolment is
/// impossible by construction (a RE-unlock of an account that already exists), so an unexpected
/// first-run would fail closed instead of creating an account with an unseen recovery phrase.
struct NeverEnrols;

impl PhrasePresenter for NeverEnrols {
    fn present_new_phrase(&self, _phrase: &RecoveryPhrase) -> RetentionDecision {
        RetentionDecision::Unavailable
    }
}
use dig_session::KeychainBackend;

use crate::account::auth::{AuthCeremony, HarnessAuthProvider};
#[cfg(any(target_os = "windows", target_os = "macos"))]
use crate::account::ceremony::PromptedCeremony;
use crate::account::lifecycle::{
    account_store, open_or_enroll, Opened, PhrasePresenter, RetentionDecision, Seeding,
};
use crate::account::phrase_vault::PhraseVault;
use crate::account::recovery::RecoveryPhrase;
use crate::account::residency::{AccountResidency, ResidencySealer};
use crate::account::second_factor::vault::SecondFactorVault;
use crate::live::{LiveDid, LiveProfileDir};

/// The single-account id the app boots by default. The account model supports many accounts (the
/// [`registry`](crate::account::registry)); the tray boot currently opens the one default account, so
/// its id is fixed here rather than derived from key material (an app-local handle, not a DID).
pub const DEFAULT_ACCOUNT_ID: &str = "default";

/// Enrol-or-unlock `account` over `backend`, collecting the password through `ceremony`.
///
/// The ceremony is the whole custody question: in production it is a
/// [`PromptedCeremony`], so the password comes from the
/// USER (dig_ecosystem#1817) and this call cannot succeed without them. A first run settles its custody
/// root from `seeding` (a shown-and-confirmed new recovery phrase, or one the user is restoring from)
/// and seals it under that password; a later unlock reproduces it. Fail-closed: any ceremony/keystore
/// error — or a recovery phrase the user did not confirm — yields no account at all.
///
/// [`PromptedCeremony`]: crate::account::ceremony::PromptedCeremony
pub fn unlock_account<A>(
    backend: Arc<dyn KeychainBackend>,
    ceremony: A,
    account: AccountId,
    wallet_slot: WalletSlot,
    seeding: Seeding<'_>,
) -> AccountResult<Opened>
where
    A: AuthCeremony + 'static,
{
    let store = account_store(backend);
    let provider = HarnessAuthProvider::new(ceremony);
    block_on(open_or_enroll(
        store,
        account,
        &provider,
        &PasswordOnlyPolicy,
        wallet_slot,
        seeding,
    ))
}

/// Enrol-or-unlock `account` and house it in a fresh [`AccountResidency`] — the boot-time assembly.
///
/// The second element is the enrolment phrase, present ONLY on a first run. The caller must vault it
/// (see [`vault_for`]) so the account can show its phrase again later; dropping it instead leaves an
/// account that works but can never re-display its words.
/// The wallet is opened at `profiles`' ACTIVE slot, so the address it derives is the address the
/// profile the user is on actually receives at. An account with nothing minted opens at
/// [`WalletSlot::unprofiled`].
pub fn assemble_residency<A>(
    backend: Arc<dyn KeychainBackend>,
    ceremony: A,
    account: AccountId,
    profiles: ProfileSession,
    seeding: Seeding<'_>,
) -> AccountResult<(AccountResidency, Option<RecoveryPhrase>)>
where
    A: AuthCeremony + 'static,
{
    let wallet_slot = profiles.wallet_slot();
    let house = |unlocked| AccountResidency::with_profiles(unlocked, wallet_slot, profiles.clone());
    match unlock_account(backend, ceremony, account, wallet_slot, seeding)? {
        Opened::Existing(unlocked) => Ok((house(unlocked), None)),
        Opened::Enrolled { account, phrase } => Ok((house(account), Some(phrase))),
    }
}

/// The profile registry for the account under `brand_dir`, or an unprofiled session when it cannot be
/// read.
///
/// A registry that will not load must not stop a user reaching their account: their money and their
/// recovery phrase are reachable from the seed alone, and the registry holds no secret. It is logged
/// loudly and the app comes up unprofiled, which is the honest rendering of "this host does not know
/// which profiles you have" — every identity surface then says it has no DID rather than naming one.
///
/// The failure is CARRIED on the session ([`ProfileSession::unreadable`]) rather than only logged,
/// because "unprofiled" and "unreadable" look identical from a list surface and only one of them is
/// a statement a person's own profiles support (dig_ecosystem#2403).
pub fn profiles_for(brand_dir: &std::path::Path) -> ProfileSession {
    match ProfileSession::load(Arc::new(FileRegistryStore::under(brand_dir))) {
        Ok(session) => session,
        Err(e) => {
            tracing::error!(error = %e, "the profile registry could not be read — booting unprofiled");
            ProfileSession::unreadable(e.to_string())
        }
    }
}

/// The ACCOUNT's stable id for a live `residency` — pinned at [`ProfileIx::ROOT`] forever, whatever
/// profile is active. `None` when the account is locked.
///
/// It is the seed-derived identity public key in hex, because there is no on-chain DID mint yet (see
/// [`crate::tray_menu`] for what the user is told about that). That is precisely why it is
/// **account-scoped and not profile-scoped**: it identifies the master seed, so it must not move when
/// the active profile does, or an account would appear to become a different account on every switch.
/// Use [`active_profile_id`] for anything keyed to the profile in force.
pub fn account_scoped_id(residency: &AccountResidency) -> Option<String> {
    residency.signing_public_key_hex_at(ProfileIx::ROOT)
}

/// The ACTIVE profile's stable id for a live `residency` — the key
/// [`profile_dir`](crate::storage::profile_dir) and the connect advertisement use. `None` when the
/// account is locked.
///
/// This one MUST follow the active slot. Sharing one directory across profiles would put profile B's
/// sealed stores beside A's under a DEK that cannot open them, and would leak each profile's metadata
/// into the other's directory listing.
pub fn active_profile_id(residency: &AccountResidency) -> Option<String> {
    residency.signing_public_key_hex()
}

/// [`active_profile_id`] as a value the sign-service assembly can HOLD — re-read on every use rather
/// than sampled once (dig_ecosystem#2398).
///
/// The APP-SIGN router is built at boot and moved onto a serving thread for the life of the process,
/// so nothing that switches profiles can reach it. Handing it a `String` froze the identity it seals,
/// advertises and persists under at whichever profile was active at boot, while the live signer
/// beside it followed the switch — publishing profile A's DID against profile B's key, and sealing
/// B's new grants into A's directory. This is the same fact as [`active_profile_id`], in the one
/// shape that cannot go stale.
pub fn live_profile_did(residency: &AccountResidency) -> LiveDid {
    let residency = residency.clone();
    LiveDid::read(move || active_profile_id(&residency))
}

/// The ACTIVE profile's directory under `brand_dir`, re-read on every use — the companion to
/// [`live_profile_did`], derived from the same function — so neither can go stale, and each answers for
/// the profile active when it is asked.
///
/// They are two INDEPENDENT reads, not one: a caller that resolves the DID and then the directory can
/// have a switch land between them and get a matched-looking pair that names two profiles. Nothing here
/// can prevent that; only handing both out from a single acquisition could.
///
/// Reads as `None` while the account is locked, because the directory is keyed by the DID and a
/// locked account has none. See [`FileSealedStore`](crate::loopback::FileSealedStore) for what that
/// means at the write itself.
pub fn live_profile_dir(
    residency: &AccountResidency,
    brand_dir: &std::path::Path,
) -> LiveProfileDir {
    let residency = residency.clone();
    let brand_dir = brand_dir.to_path_buf();
    LiveProfileDir::read(move || {
        let did = active_profile_id(&residency)?;
        Some(crate::storage::profile_dir(
            &brand_dir,
            &crate::storage::did_hash(&did),
        ))
    })
}

/// The phrase vault for a live `residency`, or `None` when it is locked.
///
/// # Always account-scoped, never per-profile
///
/// The 24 words are the **account's** custody root: every profile derives from them, so they belong
/// to no single profile. Sealing them under a per-profile DEK would make a user's own recovery words
/// unreadable the moment they switched profiles — losing the one artifact that recovers everything.
/// Hence [`account_scoped_id`] and a ROOT-pinned sealer, deliberately, not the active slot.
///
/// The vault seals through the residency's LIVE-view sealer, so it fails closed the instant the account
/// locks — a reveal can never outlive an unlock.
pub fn vault_for(
    brand_dir: &std::path::Path,
    residency: &AccountResidency,
) -> Option<PhraseVault<ResidencySealer>> {
    let profile_id = account_scoped_id(residency)?;
    Some(PhraseVault::new(
        residency.account_scoped_sealer(),
        brand_dir,
        &profile_id,
    ))
}

/// The second-factor vault for a live `residency`, or `None` when it is locked
/// (dig_ecosystem#1840).
///
/// Account-scoped for the same class of reason as [`vault_for`], and a different one specifically:
/// **2FA gates UNLOCK**, which happens before any profile is active, so a second factor sealed
/// per-profile could not be read at the moment it is needed. Deliberately the same shape as
/// [`vault_for`], down to the live-view sealer: both vaults live in the same account directory under
/// the same DEK, so two different construction paths would be two places for the at-rest rules to
/// drift apart.
pub fn second_factor_vault_for(
    brand_dir: &std::path::Path,
    residency: &AccountResidency,
) -> Option<SecondFactorVault<ResidencySealer>> {
    let profile_id = account_scoped_id(residency)?;
    Some(SecondFactorVault::new(
        residency.account_scoped_sealer(),
        brand_dir,
        &profile_id,
    ))
}

/// Re-unlock `account` through `ceremony` and INSTALL it into an existing `residency` — the sign-path
/// re-auth after a lock. Returns whether the re-unlock succeeded.
///
/// In production the ceremony asks the user for their password, so a signature after an idle lock costs
/// a password entry. That is the point: before #1817 this path re-opened the seed from the credential
/// store with no human involved, which made the lock decorative.
pub fn reunlock_into<A>(
    backend: Arc<dyn KeychainBackend>,
    ceremony: A,
    account: AccountId,
    residency: &AccountResidency,
) -> bool
where
    A: AuthCeremony + 'static,
{
    // A re-unlock is never an enrolment: the account provably exists (we just locked it), so the
    // seeding arm is unreachable. `NeverEnrols` makes that a type-level guarantee rather than a comment
    // — if the invariant ever broke, this path would refuse rather than silently mint a second account
    // with a phrase nobody saw.
    match unlock_account(
        backend,
        ceremony,
        account,
        // Re-open at EXACTLY the slot this residency's wallet already derives at. Re-opening
        // elsewhere would silently move the receive address behind a lock/unlock cycle.
        residency.wallet_slot(),
        Seeding::NewPhrase(&NeverEnrols),
    ) {
        Ok(opened) => {
            residency.install(opened.into_account());
            true
        }
        Err(e) => {
            tracing::warn!(error = %e, "account re-unlock failed — sign stays locked");
            false
        }
    }
}

/// Block on `fut` on a private current-thread runtime. The unlock flow is async (the auth ceremony is
/// an `async` seam), but the tray boot is synchronous; this bridges the two without requiring the shell
/// to own a runtime. Cheap — it runs exactly one enrol/unlock to completion then drops.
fn block_on<F: std::future::Future>(fut: F) -> F::Output {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("a current-thread tokio runtime for the account unlock")
        .block_on(fut)
}

/// Why an unlock did not produce an account — the ONE distinction that decides whether the user is
/// offered another try or told their account cannot be read (dig_ecosystem#2128).
///
/// Getting this wrong is expensive in one direction only. Reporting a retryable failure as a wedge sends
/// someone who mistyped their password to a window whose sole remedy is to REPLACE their account; the
/// reverse merely offers a retry that will not work. So the wedge set is enumerated and everything else —
/// including anything unrecognised — is [`Refused`](Self::Refused).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnlockFailure {
    /// The unlock did not complete for a reason another attempt could fix, or that the user chose: a
    /// cancelled prompt, a wrong password, a host that could not draw the window, a transient I/O error.
    Refused,
    /// The place the account lives cannot hold one, so no attempt can succeed until the HOST changes.
    ///
    /// The keystore root is a symbolic link, or exists as something other than a directory, or sits on a
    /// filesystem that ignores the owner-only permissions the backend requires (a mode-ignoring mount).
    /// None of that is transient and none of it is about the password, so offering another try would be
    /// telling the user to retry something structurally impossible. The account itself is intact, which
    /// is what separates this from [`Wedged`](Self::Wedged): there is nothing to replace, only a folder
    /// to fix.
    Unusable,
    /// The sealed blob itself cannot be read by this build — a legacy raw-seed account, or a seed
    /// envelope / keystore format from a version this one does not understand. No password opens it.
    Wedged,
}

/// The words shown for a failure whose remedy is not another attempt.
///
/// Copy lives here rather than at the notification call site so it can be asserted by the library's own
/// tests — the tray binary is a test-free zone, and a sentence that lies about whether an action can take
/// effect is exactly the kind of defect a test must be able to see.
pub struct UnlockNotice {
    /// The window title.
    pub title: &'static str,
    /// The one-line statement of what happened.
    pub heading: &'static str,
    /// What is wrong, what it is not, and what would fix it.
    pub body: &'static str,
}

/// What the user is told after an [`UnlockFailure::Unusable`] verdict.
///
/// Three properties are load-bearing. It says the account is UNCHANGED, so nobody reaches for the
/// replace path. It says another attempt will NOT help, because it will not — the previous copy for this
/// case invited a retry at a symlinked root and a mode-ignoring mount, neither of which a retry can move.
/// And it names the remedy the upstream error names, in the user's terms rather than the backend's.
///
/// It deliberately does NOT interpolate the offending path: the classifier matches on message text, so
/// echoing a path back into user copy is a second place a pathname can be mistaken for a diagnosis
/// (dig-app#233). The log line already carries the exact path, and this points there.
pub const UNUSABLE_ROOT_NOTICE: UnlockNotice = UnlockNotice {
    title: "DIG - Account folder cannot be used",
    heading: "DIG cannot use the folder it keeps your account in.",
    // `concat!`, never a `\`-continued literal: `cargo fmt` collapses a continuation onto one line and
    // KEEPS the source indentation as real spaces, so the sentence renders with a twelve-space hole in
    // the middle of it. That has already shipped once here, in `journey::UNOPENABLE_BODY` — the
    // highest-stakes message in the app — and it shipped a second time in THIS constant. `concat!`
    // cannot be reflowed, so what is written is what renders, and
    // `no_notice_in_this_module_renders_a_run_of_spaces` holds every notice below to it.
    body: concat!(
        "Your account has not been changed, and trying your password again will not help. ",
        "The folder is either a shortcut or link pointing somewhere else, or it sits somewhere that ",
        "cannot keep it private to you - a network drive, a shared folder mounted in from another ",
        "computer, or an external disk. Give DIG a folder on this computer's own disk, or point it at ",
        "the real folder instead of the link, then choose Unlock... again. The log folder (in this ",
        "menu) names the exact folder and what was wrong with it.",
    ),
};

/// What the user is told when CREATING an account did not complete for a retryable reason.
///
/// Moved out of the tray binary (`bin/dig-app.rs`) so [`failure_notice`] can choose between it and
/// [`UNUSABLE_ROOT_NOTICE`] in code a test can reach. While this copy lived at the call site the choice
/// could not be made at all: the create path threw the verdict away, so an unusable root was answered
/// with "you can start again … whenever you are ready" — a retry invitation for a condition no retry
/// moves.
pub const SETUP_FAILED_NOTICE: UnlockNotice = UnlockNotice {
    title: "DIG - Setup not completed",
    heading: "Your DIG Account was not created.",
    body: concat!(
        "Nothing was changed on this computer. You can start again from the DIG tray menu whenever ",
        "you are ready.",
    ),
};

/// What the user is told when RESTORING an account from its recovery phrase did not complete for a
/// retryable reason. Same reason for living here as [`SETUP_FAILED_NOTICE`].
pub const RESTORE_FAILED_NOTICE: UnlockNotice = UnlockNotice {
    title: "DIG - Restore did not complete",
    heading: "Your DIG Account could not be restored.",
    body: concat!(
        "Nothing was changed on this computer. The log folder (in the DIG menu) has the details, and ",
        "you can try again from the DIG menu whenever you are ready.",
    ),
};

/// EVERY notice this module can put in front of a user.
///
/// The list exists so the space-run guard and the copy tests iterate the module's real surface instead of
/// a hand-picked sample. `every_notice_in_this_module_is_in_the_catalog` proves the list is complete by
/// counting the `UnlockNotice` constants in this file's own source, so a notice added tomorrow fails the
/// suite until it is listed here — a hand-enumerated guard that silently misses the next new message is
/// exactly how the space-run defect shipped twice.
pub const UNLOCK_NOTICES: &[&UnlockNotice] = &[
    &UNUSABLE_ROOT_NOTICE,
    &SETUP_FAILED_NOTICE,
    &RESTORE_FAILED_NOTICE,
];

/// Which account-establishing flow a failure came from — the only thing that changes the RETRYABLE words.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AccountAction {
    /// A brand-new account was being created.
    Create,
    /// An account was being restored from 24 words the user typed.
    Restore,
}

/// The words to show after an account-establishing flow failed.
///
/// This is the routing the create and restore paths were missing. `UnsafeRoot` and
/// `InsecurePermissions` are raised by the keystore backend's WRITE, which is a path only these flows
/// take — the unlock path never writes — so before this existed the honest copy was reachable only from
/// a flow that cannot produce the condition, and the flows that do produce it invited a retry.
///
/// [`UnlockFailure::Unusable`] outranks the action: whichever flow was running, the folder is the problem
/// and the remedy is the same, so there is one set of words for it.
pub fn failure_notice(action: AccountAction, failure: UnlockFailure) -> &'static UnlockNotice {
    match (failure, action) {
        (UnlockFailure::Unusable, _) => &UNUSABLE_ROOT_NOTICE,
        (_, AccountAction::Create) => &SETUP_FAILED_NOTICE,
        (_, AccountAction::Restore) => &RESTORE_FAILED_NOTICE,
    }
}

/// What the tray records at rest after an unlock produced `failure`.
///
/// Lives here, not at the tray call site, because this mapping is the WHOLE safety claim of the wedge
/// verdict: [`OpenAttempt::Wedged`](crate::tray_menu::OpenAttempt::Wedged) is the one value
/// `at_rest_of` turns into
/// [`AtRest::PresentButUnopenable`](crate::tray_menu::AtRest::PresentButUnopenable) and its
/// replace-my-account window. While it was a single line in the binary, changing `Refused` to `Wedged`
/// on the [`Unusable`](UnlockFailure::Unusable) arm left the suite green, clippy silent, and an intact
/// account one click from the destructive remedy — the same defect `AccountCustodian` was created to
/// answer (dig_ecosystem#1799).
pub fn attempt_after(failure: UnlockFailure) -> crate::tray_menu::OpenAttempt {
    use crate::tray_menu::OpenAttempt;

    match failure {
        // The account is intact in both cases: a mistyped password, and a folder that cannot hold an
        // account. Only the WORDS differ (see `failure_notice`), never the state.
        UnlockFailure::Refused | UnlockFailure::Unusable => OpenAttempt::Refused,
        UnlockFailure::Wedged => OpenAttempt::Wedged,
    }
}

/// The substrings that identify a FORMAT verdict in an unlock failure.
///
/// dig-account flattens the underlying [`dig_session::SessionError`] /
/// [`dig_keystore::KeystoreError`] into `AccountError::Keystore(String)`, so the message text is the only
/// signal that survives to here. Matching it is a bridge, not a design — see the test below, which builds
/// the REAL upstream errors and asserts their verdicts, so an upstream reword fails the suite rather than
/// silently reclassifying a user's wedged account as a retryable one. dig_ecosystem#2130 tracks exposing a
/// typed kind upstream so this can be deleted.
/// The substrings that identify a HOST verdict — the keystore root cannot hold an account.
///
/// Same bridge as [`WEDGE_MARKERS`], for the same reason: the typed `dig_keystore::KeystoreError` does
/// not survive dig-account's flattening, so the rendered text is the only signal. These come from
/// `KeystoreError::UnsafeRoot` ("{path} is not usable as a keystore root: {reason}") and
/// `InsecurePermissions` ("{path} has mode {mode:04o}, which grants access beyond its owner; ...").
/// The test below builds both from the real 0.9 types, so an upstream reword fails the suite.
const UNUSABLE_ROOT_MARKERS: [&str; 2] = [
    "is not usable as a keystore root",
    "which grants access beyond its owner",
];

const WEDGE_MARKERS: [&str; 7] = [
    "legacy raw-seed format",
    "unsupported seed-envelope version",
    "unsupported stored seed kind",
    "unknown magic",
    "unsupported format version",
    "unsupported KDF id",
    "unsupported cipher id",
];

/// Classify why an unlock failed, so the tray reports what actually happened.
pub fn classify_unlock_failure(error: &dig_account::AccountError) -> UnlockFailure {
    let message = error.to_string();
    let hits = |markers: &[&str]| markers.iter().any(|marker| message.contains(marker));
    // Host before format, though the two marker sets are disjoint and a test holds them so: a root the
    // backend refuses to own is answered by fixing the folder, never by replacing the account, so if the
    // sets ever did overlap the non-destructive verdict is the one to win.
    if hits(&UNUSABLE_ROOT_MARKERS) {
        UnlockFailure::Unusable
    } else if hits(&WEDGE_MARKERS) {
        UnlockFailure::Wedged
    } else {
        UnlockFailure::Refused
    }
}

/// A booted account: the live residency plus the two facts the tray needs to describe it honestly.
pub struct BootedAccount {
    /// The live, unlocked account.
    pub residency: AccountResidency,
    /// The ACTIVE profile's stable id (see [`active_profile_id`]) — what `profile_dir` is keyed by.
    pub profile_id: String,
    /// Whether this account has a recovery phrase stored. `false` means it was enrolled before recovery
    /// phrases existed and **cannot be recovered from words** — the tray says so plainly rather than
    /// implying a safety that is not there.
    pub recoverable: bool,
}

/// Whether the default account is already enrolled on this host.
///
/// A pure existence check on the sealed-seed blob — no unlock, no credential store, no prompt — so the
/// shell can decide between "unlock the account we have" and "offer to set one up" without any side
/// effect. This is what keeps first-run setup a DELIBERATE tray action rather than a modal that ambushes
/// the user at login.
pub fn account_exists(brand_dir: &std::path::Path) -> bool {
    use dig_session::FileBackend;

    let backend = Arc::new(FileBackend::new(brand_dir.join("account")));
    account_store(backend)
        .exists(&AccountId::new(DEFAULT_ACCOUNT_ID))
        .unwrap_or(false)
}

/// What happened when an account was discarded.
///
/// A three-state outcome rather than a `bool`, because "there was nothing here" and "it would not go" call
/// for different things to say to the user, and the tray must not report a successful removal for either.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DiscardOutcome {
    /// The sealed seed is gone. This is irreversible.
    Discarded,
    /// There was no account on this host to begin with, so nothing changed.
    NothingToDiscard,
    /// The seed could not be removed; the account is still here and still works.
    Failed,
}

/// **Irreversibly** discard the default account's custody root from `brand_dir`.
///
/// # Why this primitive exists
///
/// `open_account` OPENS an account that already exists and ignores its `seeding`, so "replace this account
/// with a different one" is not expressible as an enrolment — the old seed has to go first. That makes this
/// the one function that destroys custody, which is exactly why it is one function: a single place to
/// audit, and a single place the authorization gate must be in front of (it is —
/// [`replace_account`](crate::account::journey::replace_account) runs
/// [`confirm_destroy`](crate::confirm::NativeConfirmer::confirm_destroy) first, and is itself tested against
/// a recording custodian so a refusal is PROVEN not to reach this function).
///
/// # What it removes, and in what order
///
/// 1. the **sealed master seed** (`AccountStore::delete`) — the custody root, and the thing whose absence
///    makes the account gone;
/// 2. the **stored unlock password** in the OS credential store — otherwise a credential entry for an
///    account that no longer exists lingers in Windows Credential Manager / the macOS Keychain forever;
/// 3. the **sealed recovery-phrase vault**, which is a copy of the same secret.
///
/// The seed goes FIRST and its failure aborts the rest: leaving a live seed beside a deleted password is
/// the one combination that produces an account that exists and can never be unlocked again. The two later
/// steps are best-effort — once the seed is gone the account IS gone, and a leftover file must not make
/// the tray report a failure that would send the user looking for an account that no longer exists.
///
/// This function does NOT ask the user anything. Every caller MUST hold an approving
/// [`confirm_destroy`](crate::confirm::NativeConfirmer::confirm_destroy) first.
#[cfg(any(target_os = "windows", target_os = "macos"))]
pub fn discard_account(brand_dir: &std::path::Path) -> DiscardOutcome {
    use crate::keystore::{CredentialStore, OsCredentialStore};
    use dig_session::FileBackend;

    if !account_exists(brand_dir) {
        return DiscardOutcome::NothingToDiscard;
    }
    let backend = Arc::new(FileBackend::new(brand_dir.join("account")));
    let id = AccountId::new(DEFAULT_ACCOUNT_ID);
    if let Err(e) = account_store(backend).delete(&id) {
        tracing::error!(error = %e, "the account's sealed seed could not be removed — nothing was changed");
        return DiscardOutcome::Failed;
    }
    tracing::warn!("the DIG account's sealed master seed was discarded at the user's request");

    if let Some(cred) = OsCredentialStore::open(DEFAULT_ACCOUNT_ID) {
        if let Err(e) = cred.delete(DEFAULT_ACCOUNT_ID) {
            // Harmless on its own — the seed it unlocked is already gone — but worth a line, because a
            // stale credential entry is confusing to anyone auditing their own credential store.
            tracing::warn!(error = %e, "the stored account password could not be removed");
        }
    }
    discard_sealed_vaults(brand_dir);
    DiscardOutcome::Discarded
}

/// Linux (and any host without a per-application-ACL credential store) never enrols an account, so there
/// is never one to discard — see [`open_account`].
#[cfg(not(any(target_os = "windows", target_os = "macos")))]
pub fn discard_account(_brand_dir: &std::path::Path) -> DiscardOutcome {
    DiscardOutcome::NothingToDiscard
}

/// Remove every sealed per-profile vault under `brand_dir` — the recovery-phrase copy AND the
/// second-factor enrolment.
///
/// The vault lives in a per-profile directory keyed by a hash of the profile id, and by the time an account
/// is being discarded it is locked — so the profile id is no longer readable and the exact directory cannot
/// be computed. Sweeping for the vault FILE NAME instead is what makes this work at all, and it is safe
/// because the name is specific to this one artifact.
///
/// Best-effort for the PHRASE copy: it holds a copy of the seed that was just destroyed, so a leftover
/// file is undecryptable ciphertext rather than exposure. It is still removed, because a file named
/// `recovery-phrase.seal` sitting in the data directory of an account that no longer exists is exactly the
/// kind of residue that makes a user doubt a removal happened.
///
/// For the SECOND-FACTOR enrolment it is load-bearing rather than tidy (dig_ecosystem#1840). The tray
/// reads "is a second factor enrolled?" from the file's EXISTENCE, which needs no unlock — so a leftover
/// blob would make a brand-new account report a second factor it does not have, offer "Turn off two-factor
/// codes…", and then fail every challenge, because the record was sealed under a seed that no longer
/// exists. That is a trap with no way out, not residue.
///
/// Gated to the same targets as [`discard_account`], its only caller: a host with no per-application
/// credential store never enrols an account, so it never has one to discard either.
#[cfg(any(target_os = "windows", target_os = "macos"))]
fn discard_sealed_vaults(brand_dir: &std::path::Path) {
    let Ok(entries) = std::fs::read_dir(brand_dir.join("profiles")) else {
        return;
    };
    for profile in entries.flatten() {
        for name in [
            crate::account::phrase_vault::VAULT_FILE,
            crate::account::second_factor::vault::VAULT_FILE,
        ] {
            let vault = profile.path().join(name);
            if vault.exists() {
                if let Err(e) = std::fs::remove_file(&vault) {
                    tracing::warn!(error = %e, file = name, "a sealed vault could not be removed");
                }
            }
        }
    }
}

/// CREATE the default account in `brand_dir` from `seeding`, sealed under a password the user chooses.
///
/// This is the deliberate first-run/restore path and nothing else calls it: an account comes into
/// existence because a person asked for one (dig_ecosystem#1820). The phrase is shown and its retention
/// confirmed BEFORE the password is asked for and before anything is sealed, so a user who backs out at
/// any point leaves the host exactly as it was — the ordering that matters most here is that nothing
/// becomes load-bearing until the words are written down.
///
/// Returns `None` when the account already exists, when the user cancels, or on any keystore failure.
#[cfg(any(target_os = "windows", target_os = "macos"))]
pub fn open_account(brand_dir: &std::path::Path, seeding: Seeding<'_>) -> Option<BootedAccount> {
    create_account_reporting(brand_dir, seeding).ok()
}

/// UNLOCK the default account in `brand_dir`, asking the user for its password.
///
/// `reason` says why the account is being opened right now, so the password window is never an
/// unexplained demand for a secret. Returns `None` when there is no account, when the user cancels, or
/// when the password does not open the seal — in every case leaving the account locked.
#[cfg(any(target_os = "windows", target_os = "macos"))]
pub fn unlock_existing_account(brand_dir: &std::path::Path, reason: &str) -> Option<BootedAccount> {
    unlock_existing_account_reporting(brand_dir, reason).ok()
}

/// [`unlock_existing_account`], reporting WHY it failed.
///
/// The tray needs the reason, not merely the absence of a session: a wrong password leaves the account
/// merely locked and retryable, while an unreadable seal is the one condition whose honest remedy is to
/// replace the account (dig_ecosystem#2128). A host with no account at all is `Refused` — there is
/// nothing here to be wedged.
#[cfg(any(target_os = "windows", target_os = "macos"))]
pub fn unlock_existing_account_reporting(
    brand_dir: &std::path::Path,
    reason: &str,
) -> Result<BootedAccount, UnlockFailure> {
    if !account_exists(brand_dir) {
        tracing::info!("no DIG account on this host yet — the tray will offer to set one up");
        return Err(UnlockFailure::Refused);
    }
    open_account_reporting(
        brand_dir,
        Seeding::NewPhrase(&NeverEnrols),
        PromptedCeremony::unlocking(reason),
    )
}

/// UNLOCK the default account in `brand_dir` through `ceremony` — the testable form of
/// [`unlock_existing_account`].
///
/// Refuses when no account exists, and can NEVER enrol one (`NeverEnrols`, private), so an unlock is
/// structurally incapable of creating an account with a recovery phrase nobody saw.
#[cfg(any(target_os = "windows", target_os = "macos"))]
pub fn unlock_existing_account_with<A>(
    brand_dir: &std::path::Path,
    ceremony: A,
) -> Option<BootedAccount>
where
    A: AuthCeremony + 'static,
{
    if !account_exists(brand_dir) {
        return None;
    }
    open_account_with(brand_dir, Seeding::NewPhrase(&NeverEnrols), ceremony)
}

/// The shared body of [`open_account`] and [`unlock_existing_account`]: assemble the residency over the
/// host's file backend using `ceremony`, then finish the boot.
///
/// Public so the integration suite can drive the real production assembly with a scripted ceremony —
/// the two wrappers above differ only in the question they ask, and a path that only ever runs behind a
/// live native window is a path no test can reach.
#[cfg(any(target_os = "windows", target_os = "macos"))]
pub fn open_account_with<A>(
    brand_dir: &std::path::Path,
    seeding: Seeding<'_>,
    ceremony: A,
) -> Option<BootedAccount>
where
    A: AuthCeremony + 'static,
{
    open_account_reporting(brand_dir, seeding, ceremony).ok()
}

/// [`open_account`], reporting WHY the establishment failed — see [`UnlockFailure`].
///
/// The create/restore paths are the ONLY ones that make the keystore backend WRITE, so they are the only
/// ones that can raise `UnsafeRoot` or `InsecurePermissions`. They must therefore be able to see the
/// verdict: routing them through [`open_account`], which discards it, is what left the honest copy
/// unreachable while the retry invitation survived.
#[cfg(any(target_os = "windows", target_os = "macos"))]
pub fn create_account_reporting(
    brand_dir: &std::path::Path,
    seeding: Seeding<'_>,
) -> Result<BootedAccount, UnlockFailure> {
    open_account_reporting(
        brand_dir,
        seeding,
        PromptedCeremony::establishing(
            "Choose a password for your DIG account. You will type it to unlock the account \
             whenever DIG needs to sign something.",
        ),
    )
}

/// [`open_account_with`], reporting WHY the open failed — see [`UnlockFailure`].
#[cfg(any(target_os = "windows", target_os = "macos"))]
pub fn open_account_reporting<A>(
    brand_dir: &std::path::Path,
    seeding: Seeding<'_>,
    ceremony: A,
) -> Result<BootedAccount, UnlockFailure>
where
    A: AuthCeremony + 'static,
{
    use dig_session::FileBackend;

    let backend = Arc::new(FileBackend::new(brand_dir.join("account")));
    let assembled = assemble_residency(
        backend,
        ceremony,
        AccountId::new(DEFAULT_ACCOUNT_ID),
        profiles_for(brand_dir),
        seeding,
    );
    let (residency, fresh_phrase) = match assembled {
        Ok(pair) => pair,
        Err(e) => {
            let failure = classify_unlock_failure(&e);
            // ERROR, not warn: an account that exists and will not open means this host has NO signing for
            // the rest of the session, which is an outage rather than a curiosity. Before this line
            // existed the user silently lost signing (dig_ecosystem#1799 review).
            //
            // A WRONG PASSWORD lands here too, and the two must not be conflated: only a `Wedged`
            // verdict reaches `AccountState::Unopenable` and its replace-the-account remedy
            // (dig_ecosystem#2128). The verdict is logged beside the error so a support reader can see
            // which of the two the app decided this was.
            tracing::error!(
                error = %e,
                ?failure,
                "the DIG account could not be opened"
            );
            return Err(failure);
        }
    };
    Ok(finish_boot(brand_dir, residency, fresh_phrase))
}

/// Linux (and any host without a per-application-ACL credential store) has no account paths yet, so
/// setup yields nothing — mirroring the retired path's Linux deferral.
#[cfg(not(any(target_os = "windows", target_os = "macos")))]
pub fn open_account(_brand_dir: &std::path::Path, _seeding: Seeding<'_>) -> Option<BootedAccount> {
    create_account_reporting(_brand_dir, _seeding).ok()
}

/// The deferred-OS form of [`create_account_reporting`].
///
/// `Refused` and not `Unusable`: no account folder was examined here at all, so claiming the folder
/// cannot hold an account would be a diagnosis this build never made.
#[cfg(not(any(target_os = "windows", target_os = "macos")))]
pub fn create_account_reporting(
    _brand_dir: &std::path::Path,
    _seeding: Seeding<'_>,
) -> Result<BootedAccount, UnlockFailure> {
    tracing::info!("account setup deferred: accounts are not supported on this OS yet");
    Err(UnlockFailure::Refused)
}

/// Linux stub — see [`open_account`].
#[cfg(not(any(target_os = "windows", target_os = "macos")))]
pub fn unlock_existing_account(
    _brand_dir: &std::path::Path,
    _reason: &str,
) -> Option<BootedAccount> {
    None
}

/// Linux stub — see [`open_account`]. `Refused` rather than `Wedged`: this host holds no account, so
/// there is nothing here that could be unreadable, and the destructive remedy must stay out of reach.
#[cfg(not(any(target_os = "windows", target_os = "macos")))]
pub fn unlock_existing_account_reporting(
    _brand_dir: &std::path::Path,
    _reason: &str,
) -> Result<BootedAccount, UnlockFailure> {
    Err(UnlockFailure::Refused)
}

/// Complete a boot: vault a first run's phrase and read back whether the account is recoverable.
///
/// Public so the integration suite can drive it on any platform (the cfg-gated [`open_account`] above
/// is the only production caller).
///
/// Split out (and platform-independent) so the vaulting rule — *a fresh phrase is sealed immediately,
/// while the account is unlocked and the words are still in hand* — is unit-tested rather than living
/// only inside the cfg-gated production path.
pub fn finish_boot(
    brand_dir: &std::path::Path,
    residency: AccountResidency,
    fresh_phrase: Option<RecoveryPhrase>,
) -> BootedAccount {
    let profile_id = active_profile_id(&residency).unwrap_or_default();
    let vault = vault_for(brand_dir, &residency);

    if let (Some(phrase), Some(vault)) = (&fresh_phrase, &vault) {
        // A vault write failure must not abandon the account the user just created — they have the
        // words on paper, which is the copy that matters. It DOES mean the tray must report the account
        // as not-recoverable, which `is_recoverable` below does on its own.
        if let Err(e) = vault.store(phrase) {
            tracing::warn!(error = %e, "could not store the recovery phrase for later display");
        }
    }

    BootedAccount {
        recoverable: vault.map(|v| v.is_recoverable()).unwrap_or(false),
        residency,
        profile_id,
    }
}

/// Re-unlock the default account into `residency` from `brand_dir` — the production sign-path re-auth.
///
/// Asks the user for their password, because that is what a re-auth after a lock now means.
#[cfg(any(target_os = "windows", target_os = "macos"))]
pub fn reboot_reunlock(brand_dir: &std::path::Path, residency: &AccountResidency) -> bool {
    use dig_session::FileBackend;

    let backend = Arc::new(FileBackend::new(brand_dir.join("account")));
    reunlock_into(
        backend,
        PromptedCeremony::unlocking("DIG needs to unlock your account to sign a request."),
        AccountId::new(DEFAULT_ACCOUNT_ID),
        residency,
    )
}

#[cfg(not(any(target_os = "windows", target_os = "macos")))]
pub fn reboot_reunlock(_brand_dir: &std::path::Path, _residency: &AccountResidency) -> bool {
    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::account::auth::CeremonyError;
    use crate::session_lock::SessionKeys;
    use async_trait::async_trait;
    use dig_account::{AuthFactors, SpendDecision, SpendSummary};
    use dig_ipc_protocol::signer::SessionSigner;
    use dig_keystore::MemoryBackend;
    use dig_session::Password;

    /// An [`AuthCeremony`] double that supplies a fixed password — the stand-in for a user typing the
    /// same thing every time.
    ///
    /// It is constructed from a LABEL and hashes it, so the tests can hold several distinct passwords
    /// apart without any inline secret for static analysis to flag, and so "the right password" and
    /// "a different one" are trivially expressible. A double that could only ever produce one value
    /// could not express a wrong-password unlock at all.
    #[derive(Clone)]
    struct Types(String);

    impl Types {
        fn password(label: &str) -> Self {
            use sha2::{Digest, Sha256};
            Self(hex::encode(Sha256::digest(label.as_bytes())))
        }
    }

    #[async_trait]
    impl AuthCeremony for Types {
        async fn collect_unlock_factors(
            &self,
            _account: &AccountId,
            _reason: Option<&str>,
        ) -> Result<AuthFactors, CeremonyError> {
            Ok(AuthFactors::password_only(Password::new(self.0.as_bytes())))
        }
        async fn confirm_spend(
            &self,
            _account: &AccountId,
            _profile: ProfileIx,
            _summary: &SpendSummary,
        ) -> Result<SpendDecision, CeremonyError> {
            Ok(SpendDecision::Approve)
        }
    }

    /// A ceremony the user backs out of — nothing may be enrolled or unlocked through it.
    struct Refuses;

    #[async_trait]
    impl AuthCeremony for Refuses {
        async fn collect_unlock_factors(
            &self,
            _account: &AccountId,
            _reason: Option<&str>,
        ) -> Result<AuthFactors, CeremonyError> {
            Err(CeremonyError::Cancelled)
        }
        async fn confirm_spend(
            &self,
            _account: &AccountId,
            _profile: ProfileIx,
            _summary: &SpendSummary,
        ) -> Result<SpendDecision, CeremonyError> {
            Err(CeremonyError::Cancelled)
        }
    }

    fn account() -> AccountId {
        AccountId::new(DEFAULT_ACCOUNT_ID)
    }

    /// Flatten a real upstream error exactly as dig-account does, so the classifier is measured against
    /// the text it will actually receive rather than a hand-typed approximation of it.
    fn as_account_error(source: impl std::fmt::Display) -> dig_account::AccountError {
        dig_account::AccountError::Keystore(source.to_string())
    }

    /// **The custody-safety half of dig_ecosystem#2128.** Only a genuine FORMAT verdict may be reported
    /// as a wedge, because a wedge is the one state whose offered remedy destroys the account.
    ///
    /// Every case is built from the REAL `dig_session` / `dig_keystore` error, not from a literal
    /// message: the classifier reads text, so an upstream reword must break this test rather than
    /// quietly reclassify a user's account. The wrong-password case is the load-bearing one — it is the
    /// common failure, and calling it a wedge is what sends someone who mistyped to the replace window.
    #[test]
    fn only_a_format_failure_is_a_wedge_and_a_wrong_password_never_is() {
        use dig_keystore::KeystoreError;
        use dig_session::SessionError;

        for wedge in [
            as_account_error(SessionError::LegacySeedFormat),
            as_account_error(SessionError::UnsupportedEnvelopeVersion(0x09)),
            as_account_error(SessionError::UnsupportedSeedKind(0x07)),
            as_account_error(KeystoreError::UnsupportedFormat { found: 9 }),
            as_account_error(KeystoreError::UnsupportedKdf(0x05)),
            as_account_error(KeystoreError::UnsupportedCipher(0x06)),
        ] {
            assert_eq!(
                classify_unlock_failure(&wedge),
                UnlockFailure::Wedged,
                "must be reported as unreadable: {wedge}"
            );
        }

        for retryable in [
            // The wrong password — indistinguishable from a tampered file at the AEAD tag, and in both
            // cases another attempt is the only honest offer.
            as_account_error(KeystoreError::DecryptFailed),
            dig_account::AccountError::Auth("the user cancelled the password window".into()),
            as_account_error(KeystoreError::Backend(std::sync::Arc::new(
                std::io::Error::other("the disk was busy"),
            ))),
            // Anything this build does not recognise fails toward the NON-destructive answer.
            as_account_error("a failure mode invented after this code was written"),
        ] {
            assert_eq!(
                classify_unlock_failure(&retryable),
                UnlockFailure::Refused,
                "must stay retryable: {retryable}"
            );
        }
    }

    /// **The honesty half of dig-app#233 / dig_ecosystem#3145.** A keystore root the backend refuses to
    /// own must NOT be reported as retryable, because neither of its causes is transient: a symbolic
    /// link is a statement about where the keystore lives, and a mode-ignoring mount cannot be made to
    /// honour a mode by asking twice. Before this verdict existed both fell into the closed-by-default
    /// arm and the tray offered another password attempt at something no password can reach.
    ///
    /// Every case is constructed from the REAL `dig_keystore` 0.9 error — the variants did not exist on
    /// 0.8, which is why this test could not be written until the pin resolved. A literal message here
    /// would assert nothing: it could not fail whatever the classifier did, and could not notice an
    /// upstream reword.
    #[test]
    fn a_root_the_backend_refuses_to_own_is_never_offered_another_try() {
        use dig_keystore::KeystoreError;

        for unusable in [
            // Both `UnsafeRoot` reasons, verbatim from `backend/file.rs`.
            as_account_error(KeystoreError::UnsafeRoot {
                path: "/home/dev/.local/share/DIG/account".into(),
                reason: "it is a symbolic link; pass the resolved target if that is intended",
            }),
            as_account_error(KeystoreError::UnsafeRoot {
                path: "/home/dev/.local/share/DIG/account".into(),
                reason: "it exists and is not a directory",
            }),
            // The reworded permission floor, now enforced on a root that already exists.
            as_account_error(KeystoreError::InsecurePermissions {
                path: "/mnt/c/Users/dev/DIG/account".into(),
                mode: 0o777,
            }),
        ] {
            assert_eq!(
                classify_unlock_failure(&unusable),
                UnlockFailure::Unusable,
                "a host that cannot hold the account must not be offered a retry: {unusable}"
            );
        }
    }

    /// The two marker sets must not overlap, so the classifier's ORDER cannot silently decide a user's
    /// verdict. A host string that also matched a wedge marker would put an intact account one click from
    /// the remedy that destroys it.
    #[test]
    fn the_host_and_format_marker_sets_are_disjoint() {
        for host in UNUSABLE_ROOT_MARKERS {
            for wedge in WEDGE_MARKERS {
                assert!(
                    !host.contains(wedge) && !wedge.contains(host),
                    "marker sets overlap: {host:?} vs {wedge:?}"
                );
            }
        }
    }

    /// The copy for the non-retryable verdict must not invite a retry, must say the account is intact,
    /// and must not echo a path back at the user (dig-app#233). Asserted here because the tray binary
    /// that renders it cannot be tested.
    #[test]
    fn the_unusable_root_notice_does_not_invite_a_retry_of_the_password() {
        let body = UNUSABLE_ROOT_NOTICE.body;
        assert!(
            body.contains("will not help"),
            "the copy must say another password attempt cannot work: {body}"
        );
        assert!(
            body.contains("has not been changed"),
            "the copy must say the account is intact, so nobody reaches for the replace path: {body}"
        );
        assert!(
            !body.contains('/') && !body.contains('\u{5c}'), // a backslash, which a Windows path would carry
            "the copy must not interpolate or imply a concrete path: {body}"
        );
    }

    /// The classifier's ARM ORDER is load-bearing, and nothing but a comment held it.
    ///
    /// The two marker sets are disjoint as STRINGS, which is what the test above proves — but the
    /// classifier matches against a rendered message that INTERPOLATES the keystore path, and that path
    /// is env-derived and unvalidated (`storage.rs` reads `XDG_DATA_HOME` / `HOME` / `LOCALAPPDATA`
    /// verbatim). So a root whose own pathname carries a wedge marker renders a message that hits BOTH
    /// sets, and then only the order decides: host-first says `Unusable` and leaves the account alone,
    /// wedge-first says `Wedged` and puts an intact account one click from the window whose sole remedy
    /// is to replace it.
    ///
    /// Swapping the two arms leaves every other test in this module green, which is why this one exists.
    #[test]
    fn a_wedge_marker_inside_the_path_must_not_outrank_the_host_verdict() {
        use dig_keystore::KeystoreError;

        let contaminated = as_account_error(KeystoreError::UnsafeRoot {
            // A real directory name is free to contain anything; this one contains a wedge marker.
            path: "/home/dev/unsupported format version/DIG/account".into(),
            reason: "it is a symbolic link; pass the resolved target if that is intended",
        });
        let message = contaminated.to_string();
        // The fixture is only meaningful if it really does hit both sets — assert that BEFORE the verdict,
        // so a reworded upstream message cannot leave this test passing while testing nothing.
        assert!(
            UNUSABLE_ROOT_MARKERS.iter().any(|m| message.contains(m)),
            "fixture no longer hits a host marker: {message}"
        );
        assert!(
            WEDGE_MARKERS.iter().any(|m| message.contains(m)),
            "fixture no longer hits a wedge marker: {message}"
        );

        assert_eq!(
            classify_unlock_failure(&contaminated),
            UnlockFailure::Unusable,
            "with both marker sets hit, the verdict that does NOT offer to destroy the account must \
             win — the host arm must be matched FIRST: {message}"
        );
    }

    /// The catalog must list every notice this module can show, established by COUNTING the constants in
    /// this file's own source rather than by trusting the list.
    ///
    /// A guard whose inputs are hand-enumerated stops covering the code the moment somebody adds a
    /// message and forgets the list — which is how the space-run defect below shipped twice. This makes
    /// forgetting fail the suite.
    #[test]
    fn every_notice_in_this_module_is_in_the_catalog() {
        let source = include_str!("boot.rs");
        // Assembled from pieces so this test's own needle is not one of the hits it counts — a
        // self-matching scan reports one too many and the count stops meaning anything.
        let needle = [": UnlockNotice = Unlock", "Notice {"].concat();
        let declared = source.matches(needle.as_str()).count();
        assert_eq!(
            declared,
            UNLOCK_NOTICES.len(),
            "{declared} `UnlockNotice` constants are declared in boot.rs but UNLOCK_NOTICES lists \
             {}; add the new one to the catalog so the copy guards cover it",
            UNLOCK_NOTICES.len()
        );
    }

    /// `cargo fmt` flattens a `\`-continued literal and keeps the source indentation as real spaces, so
    /// continued copy renders with holes mid-sentence. It happened in `journey::UNOPENABLE_BODY` and then
    /// again in `UNUSABLE_ROOT_NOTICE`. Every field of every notice in the catalog is checked.
    #[test]
    fn no_notice_in_this_module_renders_a_run_of_spaces() {
        for notice in UNLOCK_NOTICES {
            for (field, text) in [
                ("title", notice.title),
                ("heading", notice.heading),
                ("body", notice.body),
            ] {
                for (index, line) in text.lines().enumerate() {
                    assert!(
                        !line.contains("   "),
                        "{field} line {index} renders a run of spaces — a `\\`-continued literal that \
                         `cargo fmt` flattened? Use `concat!`:\n{line:?}"
                    );
                    assert!(
                        !line.starts_with(' '),
                        "{field} line {index} renders a leading space:\n{line:?}"
                    );
                }
            }
        }
    }

    /// The honest copy must reach the surface of the flows that can actually PRODUCE the condition — the
    /// create and restore paths, which are the only ones that write. A verdict routed correctly but
    /// rendered as the retry copy would be the original defect with an extra enum.
    #[test]
    fn an_unusable_root_is_answered_with_the_honest_copy_in_every_flow() {
        for action in [AccountAction::Create, AccountAction::Restore] {
            let notice = failure_notice(action, UnlockFailure::Unusable);
            assert_eq!(
                notice.body, UNUSABLE_ROOT_NOTICE.body,
                "{action:?} must show the folder-cannot-be-used words"
            );
            assert!(
                !notice.body.contains("try again") && !notice.body.contains("start again"),
                "{action:?} must not invite a retry of something no retry moves: {}",
                notice.body
            );
        }
        // The retryable verdicts keep their own words, so this routing did not flatten two answers into
        // one: a cancelled password window really is retryable.
        assert_eq!(
            failure_notice(AccountAction::Create, UnlockFailure::Refused).body,
            SETUP_FAILED_NOTICE.body
        );
        assert_eq!(
            failure_notice(AccountAction::Restore, UnlockFailure::Refused).body,
            RESTORE_FAILED_NOTICE.body
        );
    }

    /// Only a WEDGE may reach the state whose remedy destroys the account.
    #[test]
    fn nothing_but_a_wedge_reaches_the_replace_my_account_state() {
        use crate::tray_menu::{at_rest_of, AtRest, OpenAttempt};

        for intact in [UnlockFailure::Refused, UnlockFailure::Unusable] {
            assert_eq!(
                attempt_after(intact),
                OpenAttempt::Refused,
                "{intact:?} leaves the account intact, so the tray must stay merely locked"
            );
            assert_ne!(
                at_rest_of(true, false, attempt_after(intact)),
                AtRest::PresentButUnopenable,
                "{intact:?} must not reach the window whose only remedy is to replace the account"
            );
        }
        assert_eq!(
            attempt_after(UnlockFailure::Wedged),
            OpenAttempt::Wedged,
            "an unreadable seal must reach its explainer, which is the one place the replace path belongs"
        );
        assert_eq!(
            at_rest_of(true, false, attempt_after(UnlockFailure::Wedged)),
            AtRest::PresentButUnopenable
        );
    }

    /// A presenter that always confirms — the fixture for "the user wrote the words down".
    struct AlwaysKeeps;

    impl PhrasePresenter for AlwaysKeeps {
        fn present_new_phrase(&self, _phrase: &RecoveryPhrase) -> RetentionDecision {
            RetentionDecision::Confirmed
        }
    }

    /// Assemble over a shared backend with the user typing `password`, confirming any recovery phrase.
    fn assemble(
        backend: Arc<dyn KeychainBackend>,
        password: Types,
    ) -> (AccountResidency, Option<RecoveryPhrase>) {
        assemble_residency(
            backend,
            password,
            account(),
            ProfileSession::unprofiled(),
            Seeding::NewPhrase(&AlwaysKeeps),
        )
        .unwrap()
    }

    /// The password the tests' notional user types.
    fn typed() -> Types {
        Types::password("the-password-the-user-chose")
    }

    #[test]
    fn assemble_first_run_then_returning_boot_derive_the_same_key() {
        // A shared backend + credential store models one machine across a restart. Both boots must
        // yield the SAME master-seed-derived identity — proving zero-prompt enrol-then-unlock.
        let backend: Arc<dyn KeychainBackend> = Arc::new(MemoryBackend::new());
        let cred = typed();

        let (first, first_phrase) = assemble(backend.clone(), cred.clone());
        let first_pk = first
            .signing_public_key_hex_at(ProfileIx::ROOT)
            .expect("unlocked");
        assert!(
            first_phrase.is_some(),
            "a first run must hand back the phrase it enrolled from"
        );

        let (second, second_phrase) = assemble(backend, cred);
        assert_eq!(
            second.signing_public_key_hex_at(ProfileIx::ROOT),
            Some(first_pk),
            "a returning boot must recover the enrolled seed's identity"
        );
        assert!(
            second_phrase.is_none(),
            "a returning boot holds no phrase — it never saw the words"
        );
    }

    /// Discarding an account must sweep BOTH sealed vaults out of every profile directory
    /// (dig_ecosystem#1840).
    ///
    /// The second-factor blob is the load-bearing one: the tray reads enrolment from the file's mere
    /// EXISTENCE (no unlock needed), so a leftover would make the NEXT account report a second factor it
    /// cannot possibly satisfy — every destructive verb blocked, with no way to turn off a factor that
    /// was never set up.
    ///
    /// The fixture plants the phrase vault too, and asserts on both, because a sweep that removed only
    /// one file would otherwise pass: with a single planted file the test cannot tell "sweeps this name"
    /// from "sweeps every name".
    #[cfg(any(target_os = "windows", target_os = "macos"))]
    #[test]
    fn discarding_an_account_sweeps_both_sealed_vaults() {
        let dir = tempfile::tempdir().unwrap();
        let profile = dir.path().join("profiles").join("some-profile-hash");
        std::fs::create_dir_all(&profile).unwrap();
        let planted: Vec<std::path::PathBuf> = [
            crate::account::phrase_vault::VAULT_FILE,
            crate::account::second_factor::vault::VAULT_FILE,
        ]
        .iter()
        .map(|name| {
            let path = profile.join(name);
            std::fs::write(&path, b"sealed").unwrap();
            path
        })
        .collect();

        discard_sealed_vaults(dir.path());

        for path in planted {
            assert!(!path.exists(), "{} survived the discard", path.display());
        }
    }

    /// **The #1817 core.** An account sealed under the password its owner chose must NOT open under a
    /// different one — the property that makes "Unlock…" a gate rather than a ceremony.
    ///
    /// The fixture is a shared backend across two assemblies with DIFFERENT passwords: the second
    /// stands for anyone (or anything) that has the machine but not the secret. Asserting only that the
    /// right password works would pass identically against the old zero-prompt path, which accepted
    /// whatever the credential store handed it — the WRONG-password arm is the load-bearing half.
    #[test]
    fn an_account_does_not_open_under_a_password_it_was_not_sealed_under() {
        let backend: Arc<dyn KeychainBackend> = Arc::new(MemoryBackend::new());
        let (first, _) = assemble(backend.clone(), typed());
        let enrolled_pk = first
            .signing_public_key_hex_at(ProfileIx::ROOT)
            .expect("unlocked");

        let wrong = assemble_residency(
            backend.clone(),
            Types::password("not-the-password-they-chose"),
            account(),
            ProfileSession::unprofiled(),
            Seeding::NewPhrase(&AlwaysKeeps),
        );
        assert!(
            wrong.is_err(),
            "a wrong password must not open the sealed seed"
        );

        // The control: the RIGHT password still opens the same account, so the test above measures the
        // password and not some incidental breakage of the store.
        let (right, _) = assemble(backend, typed());
        assert_eq!(
            right.signing_public_key_hex_at(ProfileIx::ROOT),
            Some(enrolled_pk)
        );
    }

    /// A user who backs out of the password window must leave NO account behind. Asserting only the
    /// error would pass for an implementation that sealed a seed and then reported a failure, so the
    /// blob's absence is what carries this test.
    #[test]
    fn backing_out_of_the_password_window_creates_no_account() {
        let backend: Arc<dyn KeychainBackend> = Arc::new(MemoryBackend::new());

        assert!(assemble_residency(
            backend.clone(),
            Refuses,
            account(),
            ProfileSession::unprofiled(),
            Seeding::NewPhrase(&AlwaysKeeps),
        )
        .is_err());
        assert!(
            !account_store(backend).exists(&account()).unwrap(),
            "no seed blob may be left behind by a cancelled password prompt"
        );
    }

    /// A cancelled setup must leave the machine exactly as it was, so the user can try again.
    #[test]
    fn a_declined_phrase_yields_no_account() {
        struct AlwaysDeclines;
        impl PhrasePresenter for AlwaysDeclines {
            fn present_new_phrase(&self, _phrase: &RecoveryPhrase) -> RetentionDecision {
                RetentionDecision::Declined
            }
        }
        let backend: Arc<dyn KeychainBackend> = Arc::new(MemoryBackend::new());

        assert!(assemble_residency(
            backend.clone(),
            typed(),
            account(),
            ProfileSession::unprofiled(),
            Seeding::NewPhrase(&AlwaysDeclines),
        )
        .is_err());
        assert!(
            !account_store(backend).exists(&account()).unwrap(),
            "no seed blob may be left behind"
        );
    }

    /// The vaulting rule: a first run's phrase is sealed immediately, so the tray can show it again —
    /// and the SAME words come back, not merely *some* words.
    #[test]
    fn a_first_run_vaults_the_phrase_it_showed() {
        let dir = tempfile::tempdir().unwrap();
        let backend: Arc<dyn KeychainBackend> = Arc::new(MemoryBackend::new());
        let (residency, phrase) = assemble(backend, typed());
        let shown = phrase.as_ref().unwrap().words().join(" ");

        let booted = finish_boot(dir.path(), residency, phrase);

        assert!(booted.recoverable, "a fresh account must be recoverable");
        let stored = vault_for(dir.path(), &booted.residency)
            .expect("unlocked")
            .load()
            .expect("the vault opens")
            .expect("a phrase is stored");
        assert_eq!(stored.words().join(" "), shown);
    }

    /// A LEGACY account — one whose seed was enrolled with no phrase — must be reported as NOT
    /// recoverable rather than quietly treated as safe. The fixture models it exactly: an account that
    /// exists at rest, booted with no fresh phrase to vault.
    #[test]
    fn an_account_with_no_vaulted_phrase_is_reported_unrecoverable() {
        let dir = tempfile::tempdir().unwrap();
        let backend: Arc<dyn KeychainBackend> = Arc::new(MemoryBackend::new());
        let cred = typed();
        // Enrol, then boot AGAIN so the second boot carries no phrase — the shape of every account
        // enrolled before recovery phrases existed.
        let _ = assemble(backend.clone(), cred.clone());
        let (residency, phrase) = assemble(backend, cred);
        assert!(phrase.is_none());

        let booted = finish_boot(dir.path(), residency, phrase);
        assert!(
            !booted.recoverable,
            "an account with no vaulted phrase must be reported unrecoverable"
        );
    }

    /// The root profile id must be stable across boots — the per-profile directories and the phrase
    /// vault are keyed by it, so a changing id would orphan a user's sealed data.
    #[test]
    fn the_root_profile_id_is_stable_across_boots() {
        let backend: Arc<dyn KeychainBackend> = Arc::new(MemoryBackend::new());
        let cred = typed();

        let (first, _) = assemble(backend.clone(), cred.clone());
        let (second, _) = assemble(backend, cred);

        assert_eq!(account_scoped_id(&first), account_scoped_id(&second));
        assert!(account_scoped_id(&first).is_some());
    }

    #[test]
    fn a_locked_residency_has_no_profile_id_and_no_vault() {
        let dir = tempfile::tempdir().unwrap();
        let backend: Arc<dyn KeychainBackend> = Arc::new(MemoryBackend::new());
        let (residency, _) = assemble(backend, typed());
        residency.lock_all();

        assert!(account_scoped_id(&residency).is_none());
        assert!(
            vault_for(dir.path(), &residency).is_none(),
            "a locked account exposes no phrase vault"
        );
    }

    #[test]
    fn reunlock_refills_a_locked_residency() {
        let backend: Arc<dyn KeychainBackend> = Arc::new(MemoryBackend::new());
        let cred = typed();

        let (residency, _) = assemble(backend.clone(), cred.clone());
        let signer = residency.signer();
        residency.lock_all();
        assert!(signer.try_sign(b"m").is_none(), "locked");

        assert!(reunlock_into(backend, cred, account(), &residency));
        assert!(
            signer.try_sign(b"m").is_some(),
            "re-unlock must refill the residency so the live signer works again"
        );
    }

    #[test]
    fn reunlock_fails_closed_when_the_password_is_gone() {
        // Enrol under one credential store, then attempt a re-unlock with an EMPTY one: the ceremony
        // would generate a NEW password, so the keystore unlock fails the AEAD tag — fail-closed.
        let backend: Arc<dyn KeychainBackend> = Arc::new(MemoryBackend::new());
        let (residency, _) = assemble(backend.clone(), typed());
        residency.lock_all();

        assert!(
            !reunlock_into(
                backend,
                Types::password("a-different-password"),
                account(),
                &residency
            ),
            "a re-unlock with the wrong (freshly-generated) password must fail closed"
        );
        assert!(!residency.is_any_unlocked());
    }

    /// A re-unlock must never ENROL. The fixture is an EMPTY backend, so a re-unlock would have to
    /// first-run — and `NeverEnrols` must refuse rather than mint an account from a phrase nobody saw.
    #[test]
    fn reunlock_refuses_to_enrol_a_missing_account() {
        let backend: Arc<dyn KeychainBackend> = Arc::new(MemoryBackend::new());
        let residency = AccountResidency::empty();

        assert!(!reunlock_into(
            backend.clone(),
            typed(),
            account(),
            &residency
        ));
        assert!(
            !account_store(backend).exists(&account()).unwrap(),
            "a re-unlock must never create an account"
        );
    }
}
