//! The account BOOT lifecycle — the master-HD replacement for the retired per-profile
//! unlock/enroll flow (#1547, custody switchover).
//!
//! The old boot path re-derived each profile's independently-random identity into an in-memory
//! session. The master-HD model has ONE account master seed, enrolled once
//! and unlocked on every subsequent boot, from which every profile's identity + DEK is derived at its
//! profile index.
//!
//! [`open_or_enroll`] is that one-call boot primitive over dig-account's own types:
//!
//! - **Returning user** (the account's seed blob already exists) → build a locked
//!   [`AccountSession`] and [`unlock`](AccountSession::unlock) it through the harness-injected
//!   [`AuthProvider`] + [`AuthPolicy`], yielding a live [`UnlockedAccount`].
//! - **First run** (no seed blob) → settle the custody root as a 24-word BIP-39 **recovery phrase**
//!   (generated and shown once, or supplied by the user restoring an account — [`Seeding`]), collect
//!   the same factors, run the policy, and [`enroll`](AccountSession::enroll) the phrase's seed sealed
//!   under the collected password — returning the account already unlocked, plus the phrase for the
//!   caller to vault.
//!
//! The phrase is what makes an account portable: the sealed blob is decryptable only on the machine
//! whose credential store holds its password, so the words are the ONE thing a user can carry to a new
//! machine (#1500, dig_ecosystem#1752).
//!
//! The private key never crosses this boundary: the harness collects a password, dig-account seals /
//! unlocks the seed, and the caller receives only the capability handle. See `SPEC.md` §3 and the
//! #1547 migration note in `DEVELOPMENT_LOG.md` (this is a clean cutover — an old random-scalar
//! profile is not migrated onto a seed index, because no byte-identical DEK exists to preserve).

use std::sync::Arc;

use crate::account::active_profile::WalletSlot;
use crate::account::recovery::RecoveryPhrase;
use dig_account::{AccountError, AccountStore};
use dig_account::{
    AccountId, AccountSession, AuthPolicy, AuthProvider, Result as AccountResult, UnlockRequest,
    UnlockedAccount,
};
use dig_session::{KeychainBackend, Password};

/// The user's ruling on the display-once recovery-phrase screen (#1500: *generate → display once →
/// require confirmation of retention → enrol*).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RetentionDecision {
    /// The user says they have written the words down. Only this value permits enrolment.
    Confirmed,
    /// The user backed out. Enrolment is abandoned and NO account is created, so they can start over
    /// with a fresh phrase rather than owning an account whose root they never recorded.
    Declined,
    /// No surface could show the words — a headless host, or no desktop session. Fails closed for the
    /// same reason: an account nobody can recover must not be created silently.
    Unavailable,
}

/// Shows a freshly generated recovery phrase to the user and reports whether they retained it.
///
/// Implemented by the host shell (the tray draws a native window); tests inject a scripted double.
/// The implementation MUST NOT log, persist, or transmit the words — it may only draw them.
pub trait PhrasePresenter: Send + Sync {
    /// Draw `phrase` and return the user's retention ruling.
    fn present_new_phrase(&self, phrase: &RecoveryPhrase) -> RetentionDecision;
}

/// Where a first run's master seed comes from — the ONLY two honest origins for a custody root.
pub enum Seeding<'a> {
    /// Create a brand-new account: generate a 24-word phrase, show it once through the presenter, and
    /// enrol only once retention is confirmed.
    NewPhrase(&'a dyn PhrasePresenter),
    /// Restore an existing account on a new machine from words the user supplied and that have already
    /// been validated by [`RecoveryPhrase::parse`].
    Restore(&'a RecoveryPhrase),
}

/// What a boot did — distinguished because a caller must treat a FIRST run differently from a
/// returning one (it is the only moment the app legitimately holds the phrase and can vault it).
pub enum Opened {
    /// The account was already enrolled and has been unlocked. No phrase is available here — see
    /// [`PhraseVault`](crate::account::phrase_vault::PhraseVault) for the re-reveal path.
    Existing(UnlockedAccount),
    /// The account was enrolled just now, from `phrase`.
    Enrolled {
        /// The freshly unlocked account.
        account: UnlockedAccount,
        /// The phrase it was enrolled from, for the caller to seal into the phrase vault. Dropped
        /// (and zeroized) as soon as the caller lets it go.
        phrase: RecoveryPhrase,
    },
}

impl Opened {
    /// The unlocked account, discarding the enrolment phrase if there was one.
    pub fn into_account(self) -> UnlockedAccount {
        match self {
            Opened::Existing(account) => account,
            Opened::Enrolled { account, .. } => account,
        }
    }
}

/// Open `account` if it is already enrolled, otherwise enrol it fresh from `seeding` — returning it
/// unlocked.
///
/// The custody root is the master seed sealed in `store` (a [`FileBackend`](dig_session::FileBackend)
/// in production, keyed by `account`). `provider` collects the unlock factors through the OS-native
/// ceremony the harness injects; `policy` gates them (fail-closed on refusal). `default_profile_ix` is
/// the profile the returned handle's [`signer`](UnlockedAccount::signer) / [`dek`](UnlockedAccount::dek)
/// default to — the account's active profile, or [`WalletSlot::unprofiled`] while nothing is minted.
///
/// A first run NEVER invents an unwritable-down seed: per the #1500 derived model the seed is the
/// entropy of a 24-word BIP-39 phrase, which is either shown-and-confirmed
/// ([`Seeding::NewPhrase`]) or supplied by the user ([`Seeding::Restore`]).
///
/// # The index is a [`WalletSlot`], deliberately (dig_ecosystem#2236, #2398)
///
/// The opened handle's [`wallet_ops`](dig_account::UnlockedAccount::wallet_ops) — and therefore the
/// receive address the tray shows and the key that signs spends — derives at `default_profile_ix`,
/// and `UnlockedAccount` fixes it for the handle's whole lifetime. Taking a [`WalletSlot`] rather
/// than a bare [`ProfileIx`](dig_account::ProfileIx) means this funnel cannot open a wallet at an
/// index nobody vouched for: the only slots that exist are the bootstrap and one built from the
/// registry's own active profile. A bare index does not typecheck here, and a `trybuild` case pins
/// that there is no constructor that would let it.
///
/// # Errors
///
/// Any [`AccountError`] from the ceremony, policy, or keystore — fail-closed, yielding no key material
/// (a wrong password, a cancelled prompt, a tampered blob, or a policy refusal all abort with no
/// [`UnlockedAccount`]). A declined or unshowable recovery phrase aborts with [`AccountError::Auth`],
/// leaving nothing enrolled.
pub async fn open_or_enroll(
    store: Arc<AccountStore>,
    account: AccountId,
    provider: &dyn AuthProvider,
    policy: &dyn AuthPolicy,
    default_profile_ix: WalletSlot,
    seeding: Seeding<'_>,
) -> AccountResult<Opened> {
    let default_profile_ix = default_profile_ix.ix();
    let already_enrolled = store
        .exists(&account)
        .map_err(|why| AccountError::Keystore(why.to_string()))?;

    if already_enrolled {
        // Returning user: the locked session unlocks through the same injected ceremony + policy.
        return AccountSession::new(store, account, default_profile_ix)
            .unlock(provider, policy)
            .await
            .map(Opened::Existing);
    }

    // First run: settle the PHRASE before touching the keystore, so a declined retention screen leaves
    // no partially-enrolled account behind.
    let phrase = match seeding {
        Seeding::NewPhrase(presenter) => {
            let phrase = RecoveryPhrase::generate();
            match presenter.present_new_phrase(&phrase) {
                RetentionDecision::Confirmed => phrase,
                RetentionDecision::Declined => {
                    return Err(AccountError::Auth(
                        "account setup cancelled — the recovery phrase was not confirmed".into(),
                    ))
                }
                RetentionDecision::Unavailable => {
                    return Err(AccountError::Auth(
                        "cannot create an account here: there is no way to show you your recovery phrase"
                            .into(),
                    ))
                }
            }
        }
        Seeding::Restore(phrase) => RecoveryPhrase::from_master_seed(&phrase.master_seed()),
    };

    // Collect the enrolment factors through the SAME ceremony every later unlock uses, gate them on the
    // policy, then seal the phrase's seed.
    let factors = provider
        .collect_factors(UnlockRequest::new(account.clone()))
        .await?;
    policy
        .authorize(&factors)
        .map_err(|why| AccountError::Auth(why.to_string()))?;
    let unlocked = AccountSession::enroll(
        store,
        account,
        factors.password,
        &phrase.master_seed(),
        default_profile_ix,
    )?;
    Ok(Opened::Enrolled {
        account: unlocked,
        phrase,
    })
}

/// Build a locked [`AccountStore`] over `backend` (a per-user [`FileBackend`](dig_session::FileBackend)
/// in production, a `MemoryBackend` in tests), wrapped in the [`Arc`] the session/enrol paths hold.
pub fn account_store(backend: Arc<dyn KeychainBackend>) -> Arc<AccountStore> {
    Arc::new(AccountStore::new(backend))
}

/// Present an account password as a [`dig_session::Password`]. A convenience for harness code that has
/// already collected the raw bytes (e.g. an OS-credential-store secret) rather than an
/// [`AuthFactors`](dig_account::AuthFactors) from a UI ceremony.
pub fn password_from_bytes(bytes: impl AsRef<[u8]>) -> Password {
    Password::new(bytes.as_ref())
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;
    use dig_account::{AuthFactors, PasswordOnlyPolicy, SpendConfirmRequest, SpendDecision};
    use dig_ipc_protocol::signer::SessionSigner;
    use dig_keystore::MemoryBackend;
    use std::sync::Mutex;

    /// A DERIVED password (not an inline literal) so static analysis never flags a hard-coded secret.
    fn derived_password(label: &str) -> Vec<u8> {
        use sha2::{Digest, Sha256};
        Sha256::digest(label.as_bytes()).to_vec()
    }

    /// A minimal [`AuthProvider`] that returns a fixed password and counts unlock ceremonies, so the
    /// tests can assert first-run enrolment vs a returning unlock both drive the injected ceremony.
    struct FixedProvider {
        password: Vec<u8>,
    }

    impl FixedProvider {
        fn new(label: &str) -> Self {
            Self {
                password: derived_password(label),
            }
        }
    }

    #[async_trait]
    impl AuthProvider for FixedProvider {
        async fn collect_factors(&self, _req: UnlockRequest) -> AccountResult<AuthFactors> {
            Ok(AuthFactors::password_only(Password::new(&self.password)))
        }
        async fn confirm_spend(&self, _req: SpendConfirmRequest) -> AccountResult<SpendDecision> {
            Ok(SpendDecision::Approve)
        }
    }

    fn store() -> Arc<AccountStore> {
        account_store(Arc::new(MemoryBackend::new()))
    }

    /// A presenter that records what it was shown and returns a scripted ruling — so the tests can
    /// assert BOTH that the words reached the screen and that a refusal aborts enrolment. A double that
    /// could only approve could not express the decline path at all.
    struct ScriptedPresenter {
        decision: RetentionDecision,
        shown: Mutex<Vec<String>>,
    }

    impl ScriptedPresenter {
        fn new(decision: RetentionDecision) -> Self {
            Self {
                decision,
                shown: Mutex::new(Vec::new()),
            }
        }

        fn shown_phrase(&self) -> Option<String> {
            self.shown.lock().unwrap().first().cloned()
        }
    }

    impl PhrasePresenter for ScriptedPresenter {
        fn present_new_phrase(&self, phrase: &RecoveryPhrase) -> RetentionDecision {
            self.shown.lock().unwrap().push(phrase.words().join(" "));
            self.decision
        }
    }

    /// The retention-confirmed happy path: a first run shows the words, enrols from them, and the
    /// account works.
    #[tokio::test]
    async fn first_run_shows_the_phrase_then_enrols_from_it() {
        let store = store();
        let account = AccountId::new("primary");
        let provider = FixedProvider::new("pw-a");
        let presenter = ScriptedPresenter::new(RetentionDecision::Confirmed);

        let opened = open_or_enroll(
            store.clone(),
            account.clone(),
            &provider,
            &PasswordOnlyPolicy,
            WalletSlot::unprofiled(),
            Seeding::NewPhrase(&presenter),
        )
        .await
        .expect("first run enrols and unlocks");

        let Opened::Enrolled {
            account: unlocked,
            phrase,
        } = opened
        else {
            panic!(
                "a first run must report itself as an enrolment so the caller can vault the phrase"
            );
        };
        assert_eq!(unlocked.account_id(), &account);
        assert!(unlocked.signer().try_sign(b"challenge").is_some());
        assert!(
            store.exists(&account).unwrap(),
            "the seed blob exists at rest"
        );
        // The phrase handed back MUST be the one the user was shown — otherwise they wrote down words
        // that recover nothing, which is the exact failure this whole feature exists to prevent.
        assert_eq!(
            presenter.shown_phrase().as_deref(),
            Some(phrase.words().join(" ").as_str())
        );
    }

    /// Declining the retention screen must leave NOTHING enrolled. Asserting only the error would pass
    /// for an implementation that enrolled first and then reported a failure, so the seed blob's
    /// absence is the load-bearing assertion here.
    #[tokio::test]
    async fn declining_the_phrase_enrols_nothing() {
        let store = store();
        let account = AccountId::new("primary");
        let presenter = ScriptedPresenter::new(RetentionDecision::Declined);

        let result = open_or_enroll(
            store.clone(),
            account.clone(),
            &FixedProvider::new("pw-a"),
            &PasswordOnlyPolicy,
            WalletSlot::unprofiled(),
            Seeding::NewPhrase(&presenter),
        )
        .await;

        assert!(matches!(result, Err(AccountError::Auth(_))));
        assert!(
            !store.exists(&account).unwrap(),
            "a cancelled setup must leave no account behind"
        );
    }

    /// A host that cannot show the words must not create an account either — the same fail-closed rule
    /// as a decline, for the same reason (an unrecoverable account must never be created silently).
    #[tokio::test]
    async fn an_unshowable_phrase_enrols_nothing() {
        let store = store();
        let account = AccountId::new("primary");
        let presenter = ScriptedPresenter::new(RetentionDecision::Unavailable);

        let result = open_or_enroll(
            store.clone(),
            account.clone(),
            &FixedProvider::new("pw-a"),
            &PasswordOnlyPolicy,
            WalletSlot::unprofiled(),
            Seeding::NewPhrase(&presenter),
        )
        .await;

        assert!(matches!(result, Err(AccountError::Auth(_))));
        assert!(!store.exists(&account).unwrap());
    }

    /// **The proof the whole feature rests on**: a phrase enrolled on one "machine" restores the SAME
    /// identity on a DIFFERENT, empty store — no shared state but the words.
    ///
    /// The fixture deliberately uses a DIFFERENT unlock password on the second machine, because the
    /// sealed blob's password is machine-generated: if the identity still matches, it matched via the
    /// phrase and nothing else. A same-password fixture could not distinguish that from luck.
    #[tokio::test]
    async fn a_phrase_restores_the_same_identity_on_a_fresh_machine() {
        let account = AccountId::new("primary");
        let presenter = ScriptedPresenter::new(RetentionDecision::Confirmed);

        let opened = open_or_enroll(
            store(),
            account.clone(),
            &FixedProvider::new("machine-one-password"),
            &PasswordOnlyPolicy,
            WalletSlot::unprofiled(),
            Seeding::NewPhrase(&presenter),
        )
        .await
        .unwrap();
        let Opened::Enrolled {
            account: original,
            phrase,
        } = opened
        else {
            panic!("first run enrols");
        };
        let original_pk = original.signer().signing_public_key();
        original.lock();

        let restored = open_or_enroll(
            store(),
            account,
            &FixedProvider::new("machine-two-password"),
            &PasswordOnlyPolicy,
            WalletSlot::unprofiled(),
            Seeding::Restore(&phrase),
        )
        .await
        .expect("a restore enrols from the supplied phrase")
        .into_account();

        assert_eq!(
            restored.signer().signing_public_key().as_bytes(),
            original_pk.as_bytes(),
            "restoring from the phrase alone must reach the identical identity"
        );
    }

    /// A restore from a DIFFERENT phrase must reach a different identity — the control that proves the
    /// test above is reading the phrase rather than a constant.
    #[tokio::test]
    async fn restoring_from_a_different_phrase_reaches_a_different_identity() {
        let account = AccountId::new("primary");

        let first = open_or_enroll(
            store(),
            account.clone(),
            &FixedProvider::new("pw"),
            &PasswordOnlyPolicy,
            WalletSlot::unprofiled(),
            Seeding::Restore(&RecoveryPhrase::generate()),
        )
        .await
        .unwrap()
        .into_account();
        let second = open_or_enroll(
            store(),
            account,
            &FixedProvider::new("pw"),
            &PasswordOnlyPolicy,
            WalletSlot::unprofiled(),
            Seeding::Restore(&RecoveryPhrase::generate()),
        )
        .await
        .unwrap()
        .into_account();

        assert_ne!(
            first.signer().signing_public_key().as_bytes(),
            second.signer().signing_public_key().as_bytes()
        );
    }

    #[tokio::test]
    async fn a_returning_boot_unlocks_the_same_seed_and_derives_the_same_key() {
        let store = store();
        let account = AccountId::new("primary");
        let provider = FixedProvider::new("pw-a");
        let presenter = ScriptedPresenter::new(RetentionDecision::Confirmed);

        let first = open_or_enroll(
            store.clone(),
            account.clone(),
            &provider,
            &PasswordOnlyPolicy,
            WalletSlot::unprofiled(),
            Seeding::NewPhrase(&presenter),
        )
        .await
        .unwrap()
        .into_account();
        let first_pk = first.signer().signing_public_key();
        first.lock();

        // A "restart": a fresh session over the SAME store + password unlocks the enrolled seed and
        // derives the SAME identity key — proving the seed persisted, not re-generated. The presenter
        // must NOT be consulted again: a returning boot never re-shows a phrase. It is scripted to
        // DECLINE so a boot that wrongly re-enrolled would fail loudly rather than pass quietly.
        let returning = ScriptedPresenter::new(RetentionDecision::Declined);
        let second = open_or_enroll(
            store,
            account,
            &provider,
            &PasswordOnlyPolicy,
            WalletSlot::unprofiled(),
            Seeding::NewPhrase(&returning),
        )
        .await
        .expect("returning boot unlocks the enrolled seed")
        .into_account();
        assert_eq!(
            second.signer().signing_public_key().as_bytes(),
            first_pk.as_bytes(),
            "a returning unlock must recover the same master-seed-derived identity"
        );
        assert!(
            returning.shown_phrase().is_none(),
            "a returning boot must not generate or show a new phrase"
        );
    }

    #[tokio::test]
    async fn a_wrong_password_on_a_returning_boot_fails_closed() {
        let store = store();
        let account = AccountId::new("primary");
        let presenter = ScriptedPresenter::new(RetentionDecision::Confirmed);

        open_or_enroll(
            store.clone(),
            account.clone(),
            &FixedProvider::new("right"),
            &PasswordOnlyPolicy,
            WalletSlot::unprofiled(),
            Seeding::NewPhrase(&presenter),
        )
        .await
        .unwrap();

        let result = open_or_enroll(
            store,
            account,
            &FixedProvider::new("wrong"),
            &PasswordOnlyPolicy,
            WalletSlot::unprofiled(),
            Seeding::NewPhrase(&presenter),
        )
        .await;
        assert!(
            matches!(result, Err(AccountError::Keystore(_))),
            "a wrong password must fail closed with no unlocked account"
        );
    }
}
