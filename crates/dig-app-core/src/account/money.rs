//! The LIVE money path — a REAL custody gate before every signature (#1548, dig_ecosystem#2359).
//!
//! # What this module is, in one sentence
//!
//! It turns a set of unsigned [`CoinSpend`]s into a signed [`SpendBundle`], and the only route from
//! one to the other runs through `dig-account`'s [`PolicyAuthorizer`] — the concrete custody gate.
//!
//! # Why there is no authorizer SEAM here any more
//!
//! Until `dig-account` 0.5.0 this module was generic over an injectable `SpendAuthorizer`, and dig-app
//! injected `AlwaysConfirmAuthorizer`, whose entire body was `Ok(())`. Every bound the custody model
//! advertised — per-transaction limits, the rolling period cap, the vault's hot-wallet-only outflow
//! rule — was therefore absent from the running application, while the code read as though a gate were
//! present. dig-account removed the trait for exactly that reason, and `SpendApproval`'s constructor is
//! `pub(crate)`, so [`PolicyAuthorizer`] is now mechanically the only thing that can permit a spend.
//!
//! The policy is no longer a per-call argument either. It is fixed when the gate is built, from the
//! host's persisted configuration, because a caller that could hand the gate a policy alongside the
//! spend could raise its own limit on the way through.
//!
//! # The gate, in order
//!
//! 1. **rule** — [`PolicyAuthorizer::authorize_op`] re-parses and summarizes the coin spends ITSELF
//!    (the caller supplies bytes, never a description) and returns a [`SpendRuling`]. A structural
//!    refusal — a vault outflow to anyone but this profile's own hot wallet, a spend no configured
//!    limit can bound — never reaches step 2.
//! 2. **confirm** — [`SpendRuling::RequiresConfirmation`] carries a `PendingApproval`, and
//!    `PendingApproval::confirm_with` is the ONLY route from it to a signable approval. It runs the
//!    injected [`AuthProvider`]'s ceremony; a decline is terminal.
//! 3. **sign** — [`MoneySigner::sign_approved`] takes the `SpendApproval` **by value**. The approval
//!    owns the exact coin spends the gate judged and the summary the user was shown, so what is
//!    displayed and what is signed are two borrows of one value; there is nothing to compare and
//!    therefore nothing that can compare wrongly. It is neither `Clone` nor `Copy`, so re-using one is
//!    a use-after-move compile error rather than a replay to defend against at runtime.
//!
//! # One gate per account, held for the unlock's lifetime
//!
//! The rolling period cap's ledger lives inside the [`PolicyAuthorizer`] and nowhere else, so a host
//! that built a gate per request would start each one with an empty ledger and turn a period cap into
//! N per-transaction limits. [`MoneyPath`] therefore OWNS its authorizer and is itself the long-lived
//! per-account handle.
//!
//! # The custody boundary (#908, Model A)
//!
//! The seed and every derived money secret stay owned by dig-account; the signer holds the key inside
//! its vetted core and exposes signing only. What leaves this module is the signed [`SpendBundle`] —
//! the same bytes that cross the dig-app→dig-node IPC wire (`control.wallet.broadcast`,
//! [`crate::wallet::engine`]). No key material ever crosses that wire (asserted at the wire level by
//! the `no_user_key_on_wire` integration test).

use chia_protocol::{CoinSpend, SpendBundle};
use dig_account::{
    AccountError, AccountId, AuthProvider, AutoSendPolicy, Clock, CustodyPolicy, MoneySigner,
    PolicyAuthorizer, SpendOpClass, SpendRuling,
};
use dig_wallet_backend::types::Network;
use std::sync::Arc;

use crate::account::residency::AccountResidency;

/// A failure of the [`MoneyPath`] gate. Each variant names exactly which gate refused, so a custody
/// review can see where a spend was stopped — and so no failure is silently indistinguishable from a
/// successful, unsigned no-op.
#[derive(Debug, thiserror::Error)]
pub enum MoneyPathError {
    /// The account residency is locked (at construction or at sign) — nothing is signed. Fail-closed.
    #[error("the account is locked — the spend was not signed")]
    Locked,

    /// The spend could not be re-derived from its coin spends (an undecodable, unaccountable spend).
    /// Fail-closed, and decided by the gate rather than by anything the caller said about the spend.
    #[error("could not summarize the spend: {0}")]
    Summary(String),

    /// The custody gate refused the spend outright — a policy limit, the vault's hot-wallet-only
    /// outflow rule, or a value no configured bound can judge. No ceremony can permit it.
    #[error("the spend was not authorized: {0}")]
    Unauthorized(String),

    /// The user DECLINED the confirm ceremony (or the ceremony failed to complete) — nothing is
    /// signed. Distinct from [`Unauthorized`](Self::Unauthorized): the custody policy would have
    /// permitted this spend with the user's agreement, and the user did not give it.
    #[error("the spend was declined at the confirm ceremony{}", .0.as_ref().map(|w| format!(": {w}")).unwrap_or_default())]
    Declined(Option<String>),

    /// Signing the approved spend failed inside dig-account's money signer.
    #[error("spend signing failed: {0}")]
    Sign(String),

    /// The active profile moved between the confirm ceremony and the signature — nothing is signed.
    ///
    /// The ceremony names a profile, and a human agreed to a spend from THAT profile. Signing under a
    /// different one afterwards would take the user's consent for one identity's money and apply it to
    /// another's, so this fails closed and the user is asked again under the profile now in force.
    #[error("the active profile changed during the confirmation — the spend was not signed")]
    ProfileSwitched,

    /// Vault custody is configured, and this app cannot honour it. See
    /// [`MoneyPath::new`](MoneyPath::new).
    #[error("vault custody needs a second derivation index, and this app has only one: the vault \
             and the hot wallet would be the same key, so every payment out of the vault would be \
             classified as change and refused. Use hot-wallet custody until per-profile vaults ship \
             (dig_ecosystem#2373).")]
    VaultNeedsASecondIndex,
}

impl MoneyPathError {
    /// Classify a `dig-account` error by WHICH gate produced it.
    ///
    /// The distinction that matters to a caller is refused-outright versus the-user-said-no, because
    /// only the second is a decision a person could revisit. Everything the gate refuses structurally
    /// — [`PolicyDenied`](AccountError::PolicyDenied) and the "no bound can judge this"
    /// [`PolicyIndeterminate`](AccountError::PolicyIndeterminate) — becomes
    /// [`Unauthorized`](Self::Unauthorized), and an undecodable spend becomes
    /// [`Summary`](Self::Summary), which is a defect in the spend rather than a ruling on it.
    fn from_gate(error: AccountError) -> Self {
        match error {
            AccountError::UserDeclined(why) => Self::Declined(Some(why)),
            AccountError::Spend(why) => Self::Summary(why),
            other => Self::Unauthorized(other.to_string()),
        }
    }
}

/// The live money path for one account: `dig-account`'s custody gate, the confirm ceremony, and the
/// signer, over the shared [`AccountResidency`] (the SAME lockable seed home the identity signer
/// reads, so a lock relocks BOTH).
///
/// Generic over the injected [`AuthProvider`] only — production wires the OS-native ceremony and tests
/// drive a fake. The gate itself is NOT injectable; see the [module docs](self).
pub struct MoneyPath<P>
where
    P: AuthProvider,
{
    residency: AccountResidency,
    /// The one gate for this account, held for the handle's whole lifetime so the rolling period cap
    /// measures a window rather than a single request.
    authorizer: PolicyAuthorizer,
    auth_provider: P,
    account_id: AccountId,
    network: Network,
}

impl<P> MoneyPath<P>
where
    P: AuthProvider,
{
    /// Assemble the money path over `residency`, gating every spend on a [`PolicyAuthorizer`] built
    /// from the host's persisted `custody` and `auto_send` configuration.
    ///
    /// The gate needs the profile's own hot-wallet receive address — it is what the vault's outflow
    /// rule compares against — so this reads it live from the residency and fails with
    /// [`MoneyPathError::Locked`] if the account is not unlocked. Decoding it at construction means an
    /// unusable address is a construction error rather than a comparison that silently never matches
    /// at authorization time.
    pub fn new(
        residency: AccountResidency,
        auth_provider: P,
        account_id: AccountId,
        network: Network,
        custody: CustodyPolicy,
        auto_send: AutoSendPolicy,
        clock: Arc<dyn Clock>,
    ) -> Result<Self, MoneyPathError> {
        // REFUSE Vault custody here, by name, rather than let it fail silently at every spend
        // (dig_ecosystem#2373). dig-account's `Vault` is legitimately usable by a host with two
        // derivation indices — the vault's outflow rule compares a payment's destination against the
        // HOT wallet's address, and permits only a move to it — but this app derives one wallet, so
        // the vault and the hot wallet are the same key and every outbound payment reads as change to
        // itself. That refusal is correct; what was wrong was that it was anonymous. This breaks no
        // working behaviour: a Vault user cannot pay anyone today, so this converts a silent
        // always-refuse into a named one the settings surface can act on.
        if matches!(custody, CustodyPolicy::Vault(_)) {
            return Err(MoneyPathError::VaultNeedsASecondIndex);
        }
        let address = residency
            .receiving_address()
            .ok_or(MoneyPathError::Locked)?
            .map_err(|e| MoneyPathError::Unauthorized(e.to_string()))?;
        let profile = residency.profiles().active_ix();
        let authorizer = PolicyAuthorizer::new(profile, custody, auto_send, &address, clock)
            .map_err(MoneyPathError::from_gate)?;
        Ok(Self {
            residency,
            authorizer,
            auth_provider,
            account_id,
            network,
        })
    }

    /// Rule on `coin_spends`, obtain the user's agreement where the ruling requires it, and sign —
    /// returning the broadcast-ready [`SpendBundle`] only when every gate passes.
    ///
    /// `op_class` declares what the spend is FOR. Only an in-process caller that built the spend can
    /// make that statement truthfully, so anything arriving from outside the process (a dapp, an IPC
    /// peer) passes [`SpendOpClass::Undeclared`], which can never auto-approve — it routes to the
    /// human instead, which is what keeps an undeclared request spendable-with-consent rather than
    /// unspendable.
    pub async fn authorize_and_sign(
        &self,
        coin_spends: Vec<CoinSpend>,
        op_class: SpendOpClass,
    ) -> Result<SpendBundle, MoneyPathError> {
        // 1. The gate re-derives the spend from these very bytes and rules on it. A structural
        //    refusal returns here and no ceremony can overturn it.
        // The profile the gate was built for, and the profile the ceremony will name. Read once here
        // so the SAME value is shown to the user and re-checked below.
        let confirming_profile = self.residency.profiles().active_ix();
        let approval = match self
            .authorizer
            .authorize_op(&coin_spends, op_class)
            .map_err(MoneyPathError::from_gate)?
        {
            SpendRuling::Approved(approval) => approval,
            // 2. The gate will permit this only with the user's agreement. `confirm_with` runs the
            //    ceremony and is the ONLY route from a pending approval to a signable one — a host
            //    cannot assert consent it did not obtain.
            SpendRuling::RequiresConfirmation(pending) => pending
                .confirm_with(
                    &self.auth_provider,
                    self.account_id.clone(),
                    confirming_profile,
                )
                .await
                .map_err(MoneyPathError::from_gate)?,
        };

        // FAIL CLOSED if the profile moved while the human was deciding (dig_ecosystem#2398). This is
        // the one seam a live re-read cannot protect on its own: a person looked at a dialog naming
        // one identity and agreed to a spend from it, and a switch landing in that window would apply
        // that consent to a different identity's money. A design that captured the index once and
        // signed blind returns `Ok` here, which is what the ceremony test drives.
        //
        // dig-account's `CustodyScope::assert_signable_by` backstops this inside the signer, and this
        // check exists ahead of it so the refusal names the real reason rather than surfacing as a
        // generic signing failure.
        if self.residency.profiles().active_ix() != confirming_profile {
            return Err(MoneyPathError::ProfileSwitched);
        }

        // 3. Build the signer LAST. Reading the residency here rather than at construction means a
        //    lock that landed during the confirm ceremony fails the sign closed, instead of signing a
        //    spend under an unlock the user has since revoked.
        let signer = self
            .residency
            .money_signer(self.network)
            .ok_or(MoneyPathError::Locked)?;
        signer
            .sign_approved(approval)
            .map_err(|e| MoneyPathError::Sign(e.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::account::residency::AccountResidency;
    use crate::session_lock::SessionKeys;
    use async_trait::async_trait;
    use chia_protocol::{Bytes32, Coin};
    use chia_puzzle_types::Memos;
    use chia_sdk_driver::{SpendContext, StandardLayer};
    use chia_sdk_types::Conditions;
    use chia_sdk_utils::Address;
    use dig_account::SpendRecipient;
    use dig_account::{
        AccountSession, AccountStore, AuthFactors, FixedClock, HotWallet, OpClassLimits, ProfileIx,
        Result as AccountResult, SpendConfirmRequest, SpendDecision, UnlockRequest, Vault,
        WalletKey, DEFAULT_PERIOD_SECONDS,
    };
    use dig_keystore::MemoryBackend;
    use dig_session::{Password, ENTROPY_LEN};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Mutex;

    /// A fixed 32-byte entropy that gets BIP-39-expanded before key derivation so the test's
    /// independently-built coin spend (via dig-account's [`WalletKey`]) and the residency's
    /// dig-account money signer derive the SAME canonical wallet key at [`ProfileIx::ROOT`].
    const SEED: [u8; ENTROPY_LEN] = [0x7c; ENTROPY_LEN];

    /// An explicit fixture "now", pinned rather than read from the wall clock.
    ///
    /// The rolling period cap is measured over a window ending at the clock's answer, so a fixture
    /// that passed a small number through a real clock would place every recorded spend billions of
    /// seconds in the past — the window would always be empty and the cap tests would assert nothing.
    /// 2026-01-01T00:00:00Z, comfortably larger than any window these tests use.
    const NOW: u64 = 1_767_225_600;

    /// A clock frozen at [`NOW`], so nothing in these tests depends on how long they take to run.
    fn frozen_clock() -> Arc<dyn Clock> {
        Arc::new(FixedClock::new(NOW))
    }

    /// The account id every fixture here uses.
    fn account_id() -> AccountId {
        AccountId::new("money-path-test")
    }

    /// A residency over a fresh account enrolled at [`SEED`].
    fn residency_at_seed() -> AccountResidency {
        let store = Arc::new(AccountStore::new(Arc::new(MemoryBackend::new())));
        let unlocked = AccountSession::enroll(
            store,
            account_id(),
            Password::new("pw"),
            &SEED,
            ProfileIx::ROOT,
        )
        .unwrap();
        AccountResidency::new(unlocked)
    }

    /// The wallet key these fixtures build spends against — the same one the residency's money signer
    /// derives, so a spend built here is a spend that account can actually sign.
    fn wallet_key() -> WalletKey {
        let expanded = bip39::Mnemonic::from_entropy_in(bip39::Language::English, &SEED)
            .expect("32 bytes is valid 24-word BIP-39 entropy")
            .to_seed("");
        WalletKey::from_seed(&expanded)
    }

    /// A real standard-layer XCH send out of the wallet's own coin, paying `destination`.
    ///
    /// `native_out` mojos go to `destination` as a HINTED output (the money signer's exfiltration
    /// guard refuses a bare unhinted output, reading it as a possible drain); the remainder, less
    /// `fee`, returns to the wallet as change.
    fn send_to(destination: Bytes32, native_out: u64, fee: u64) -> Vec<CoinSpend> {
        let key = wallet_key();
        let wallet_ph = key.puzzle_hash();
        let mut ctx = SpendContext::new();
        let coin = Coin::new(Bytes32::new([1u8; 32]), wallet_ph, 1_000_000);
        let hint = ctx.hint(destination).unwrap();
        let change = 1_000_000 - native_out - fee;
        let conditions = Conditions::new()
            .create_coin(destination, native_out, hint)
            .create_coin(wallet_ph, change, Memos::None)
            .reserve_fee(fee);
        StandardLayer::new(key.public_key())
            .spend(&mut ctx, coin, conditions)
            .unwrap();
        ctx.take()
    }

    /// Somebody who is NOT this wallet. A spend paying here genuinely leaves the user's control.
    const A_STRANGER: Bytes32 = Bytes32::new([9u8; 32]);

    /// A spend paying a third party — the shape a vault outflow must never take without first
    /// passing through the hot wallet's clawback window.
    fn send_to_a_stranger(native_out: u64, fee: u64) -> Vec<CoinSpend> {
        send_to(A_STRANGER, native_out, fee)
    }

    /// A spend paying nobody but this wallet itself, so the vault's outflow rule has nothing to
    /// refuse. `native_out` still leaves the spent coin, so the spend is a real one with a real total.
    fn send_to_ourselves(native_out: u64, fee: u64) -> Vec<CoinSpend> {
        send_to(wallet_key().puzzle_hash(), native_out, fee)
    }

    /// What [`send_to_a_stranger`] / [`send_to_ourselves`] with these arguments totals to under the
    /// gate's accounting: the native amounts that leave, plus the fee.
    const SPEND_TOTAL: u64 = 610;

    /// A hot-wallet custody policy whose allowance is far above [`SPEND_TOTAL`], so a fixture spend
    /// classifies as [`SpendTier::AutoSend`](dig_account::SpendTier) and the AUTO-SEND policy — not
    /// the tier — is what the test is varying.
    fn hot_wallet_that_tiers_our_fixture_as_auto_send() -> CustodyPolicy {
        CustodyPolicy::Hot(HotWallet {
            auto_send_limit: 1_000_000,
        })
    }

    /// An auto-send policy that permits small sends up to `per_tx` and no more than `period_cap`
    /// mojos across the whole rolling window.
    fn small_sends_up_to(per_tx: u64, period_cap: u64) -> AutoSendPolicy {
        AutoSendPolicy {
            enabled: true,
            small_send: OpClassLimits::enabled_up_to(per_tx),
            period_seconds: DEFAULT_PERIOD_SECONDS,
            period_cap_mojos: period_cap,
            ..AutoSendPolicy::default()
        }
    }

    /// A recording [`AuthProvider`] that returns a canned [`SpendDecision`] and counts how many times
    /// the confirm ceremony ran — so a test can prove the ceremony DID or did NOT run, rather than
    /// only checking where the spend ended up.
    ///
    /// It also KEEPS each request. Counting ceremonies proves one ran; it says nothing about what the
    /// user was shown, and a provider that discarded the request would be satisfied identically by a
    /// dialog naming the wrong account or the wrong profile — asserting that the ceremony happened
    /// rather than that it was right, which is the same shape as the always-approve authorizer #139
    /// removed.
    struct RecordingProvider {
        decision: SpendDecision,
        confirms: AtomicUsize,
        /// Every request put to the ceremony, in order.
        requests: Mutex<Vec<SpendConfirmRequest>>,
        /// Locked from INSIDE the ceremony when set, to reproduce a user locking their account while
        /// the confirm window is open.
        lock_during_the_ceremony: Option<AccountResidency>,
    }

    impl RecordingProvider {
        fn new(decision: SpendDecision) -> Self {
            Self {
                decision,
                confirms: AtomicUsize::new(0),
                requests: Mutex::new(Vec::new()),
                lock_during_the_ceremony: None,
            }
        }

        /// Read the single request this provider was asked to confirm.
        fn with_sole_request<T>(&self, f: impl FnOnce(&SpendConfirmRequest) -> T) -> T {
            let requests = self.requests.lock().expect("not poisoned");
            assert_eq!(requests.len(), 1, "exactly one ceremony was expected");
            f(&requests[0])
        }

        /// A ceremony that approves the spend and locks `residency` before returning.
        fn approving_but_locks(residency: AccountResidency) -> Self {
            Self {
                lock_during_the_ceremony: Some(residency),
                ..Self::new(SpendDecision::Approve)
            }
        }
    }

    #[async_trait]
    impl AuthProvider for RecordingProvider {
        async fn collect_factors(&self, _request: UnlockRequest) -> AccountResult<AuthFactors> {
            unreachable!("the money path never collects unlock factors")
        }

        async fn confirm_spend(
            &self,
            request: SpendConfirmRequest,
        ) -> AccountResult<SpendDecision> {
            self.confirms.fetch_add(1, Ordering::SeqCst);
            self.requests.lock().expect("not poisoned").push(request);
            if let Some(residency) = &self.lock_during_the_ceremony {
                residency.lock_all();
            }
            Ok(self.decision.clone())
        }
    }

    /// An [`AuthProvider`] that PANICS if the confirm ceremony is ever invoked — used to prove a spend
    /// signed WITHOUT any confirmation, rather than merely that it signed.
    struct NeverConfirm;

    #[async_trait]
    impl AuthProvider for NeverConfirm {
        async fn collect_factors(&self, _request: UnlockRequest) -> AccountResult<AuthFactors> {
            unreachable!("no unlock factors on the money path")
        }

        async fn confirm_spend(
            &self,
            _request: SpendConfirmRequest,
        ) -> AccountResult<SpendDecision> {
            panic!("confirm_spend must NOT run for an auto-approved spend");
        }
    }

    /// Build a money path over a fresh residency, with the given policies and a frozen clock.
    fn money_path<P: AuthProvider>(
        provider: P,
        custody: CustodyPolicy,
        auto_send: AutoSendPolicy,
    ) -> MoneyPath<P> {
        MoneyPath::new(
            residency_at_seed(),
            provider,
            account_id(),
            Network::Mainnet,
            custody,
            auto_send,
            frozen_clock(),
        )
        .expect("an unlocked residency yields a money path")
    }

    /// How many ceremonies this path has raised.
    fn ceremonies(path: &MoneyPath<RecordingProvider>) -> usize {
        path.auth_provider.confirms.load(Ordering::SeqCst)
    }

    // -----------------------------------------------------------------------------------------
    // The gate is REAL — the property the dig-account 0.5.0 adoption exists to establish.
    // -----------------------------------------------------------------------------------------

    /// **A vault outflow to a third party is refused by the gate, before any ceremony — while the
    /// same spend to nobody but ourselves reaches one.**
    ///
    /// The two halves differ in exactly ONE thing: who is paid. That pairing is what makes the test
    /// load-bearing, and it is aimed at a specific wrong implementation — the one dig-app actually
    /// shipped. Under the old injectable seam, `AlwaysConfirmAuthorizer::authorize` returned `Ok(())`
    /// for every summary, so BOTH halves reached the ceremony and BOTH signed on approval. Asserting
    /// only the refusal would not have distinguished the real gate from a gate that refuses every
    /// vault spend, which is why the second half is here and why it must genuinely get through.
    ///
    /// A note so the second half is not read as more than it is: dig-app's wallet is pinned to one
    /// derivation index, so a payment to its own puzzle hash is classified as CHANGE and never enters
    /// `summary.recipients` at all. The hot-wallet half therefore passes the outflow rule vacuously,
    /// over an empty recipient list. It is an honest control for "the gate does not refuse all vault
    /// spends"; the address COMPARISON itself is dig-account's own property and is tested there.
    ///
    /// What the FIRST half additionally pins, measured rather than assumed: rebuilding the gate with
    /// the stranger's own address as the configured hot wallet makes this spend authorize and SIGN —
    /// a real signature paying a third party out of a vault. So the refusal is not merely "vaults
    /// refuse strangers"; it discriminates the address `MoneyPath::new` hands the gate from the one
    /// wrong value that matters most. Any OTHER foreign address leaves both halves passing here, and
    /// is caught elsewhere: under `CustodyPolicy::Hot` the gate's scope carries the configured wallet
    /// and the signer compares it against the puzzle hash it derives live from the seed, so every
    /// hot-path test in this module fails on a substituted address. Between them the input is pinned;
    /// neither alone would be enough.
    #[tokio::test]
    async fn a_vault_spend_to_a_stranger_is_refused_outright_but_one_to_ourselves_is_not() {
        let to_a_stranger = money_path(
            RecordingProvider::new(SpendDecision::Approve),
            CustodyPolicy::Vault(Vault::default()),
            AutoSendPolicy::default(),
        );
        let refused = to_a_stranger
            .authorize_and_sign(send_to_a_stranger(600, 10), SpendOpClass::Undeclared)
            .await;

        assert!(
            matches!(refused, Err(MoneyPathError::Unauthorized(_))),
            "a vault spend leaving to a third party must be refused by the gate: {refused:?}"
        );
        assert_eq!(
            ceremonies(&to_a_stranger),
            0,
            "the refusal is structural, so the user is never asked to approve it"
        );

        let to_ourselves = money_path(
            RecordingProvider::new(SpendDecision::Approve),
            CustodyPolicy::Vault(Vault::default()),
            AutoSendPolicy::default(),
        );
        to_ourselves
            .authorize_and_sign(send_to_ourselves(600, 10), SpendOpClass::Undeclared)
            .await
            .expect("a vault spend that leaves nothing to a third party still signs, with consent");

        assert_eq!(
            ceremonies(&to_ourselves),
            1,
            "the control spend reached the ceremony — the gate is not refusing every vault spend"
        );
    }

    /// **The rolling period cap binds ACROSS calls**, which is only true of a gate the host holds for
    /// its lifetime.
    ///
    /// The cap sits between one fixture spend and two, so the first auto-approves with no ceremony
    /// and the second — identical in every respect — is escalated to the human. The wrong
    /// implementation this is aimed at is the one dig-account's own docs warn about: building a
    /// `PolicyAuthorizer` per request. That gate starts each call with an empty ledger, auto-approves
    /// both spends and raises zero ceremonies, so a test that drove a single spend could not tell the
    /// two apart. The first spend is a truthful control: auto-approval genuinely happens here.
    #[tokio::test]
    async fn the_rolling_period_cap_is_measured_across_calls_not_reset_by_each_one() {
        let path = money_path(
            RecordingProvider::new(SpendDecision::Approve),
            hot_wallet_that_tiers_our_fixture_as_auto_send(),
            small_sends_up_to(SPEND_TOTAL, SPEND_TOTAL + 1),
        );

        path.authorize_and_sign(send_to_a_stranger(600, 10), SpendOpClass::SmallSend)
            .await
            .expect("the first spend fits inside the period cap");
        assert_eq!(
            ceremonies(&path),
            0,
            "the first spend was inside the cap, so it auto-approved with no ceremony"
        );

        path.authorize_and_sign(send_to_a_stranger(600, 10), SpendOpClass::SmallSend)
            .await
            .expect("the second spend signs, but only because the user approved it");
        assert_eq!(
            ceremonies(&path),
            1,
            "the second identical spend exceeded the cumulative cap and was escalated to the human"
        );
    }

    /// **An UNDECLARED spend can never auto-approve**, even when a declared one of the very same
    /// value, under the very same policy, does.
    ///
    /// This is the boundary between an in-process caller that built the spend and can truthfully say
    /// what it is for, and anything arriving from outside the process — a dapp, an IPC peer — which
    /// cannot. Varying only `op_class` is what distinguishes the real rule from an implementation
    /// where nothing auto-approves at all, and the declared half proves auto-approval is reachable.
    #[tokio::test]
    async fn an_undeclared_spend_goes_to_the_human_where_a_declared_one_auto_approves() {
        let policy = small_sends_up_to(SPEND_TOTAL, SPEND_TOTAL * 10);

        let declared = money_path(
            NeverConfirm,
            hot_wallet_that_tiers_our_fixture_as_auto_send(),
            policy,
        );
        declared
            .authorize_and_sign(send_to_a_stranger(600, 10), SpendOpClass::SmallSend)
            .await
            .expect(
                "a declared small send inside its limits auto-approves — NeverConfirm proves it",
            );

        let undeclared = money_path(
            RecordingProvider::new(SpendDecision::Approve),
            hot_wallet_that_tiers_our_fixture_as_auto_send(),
            policy,
        );
        undeclared
            .authorize_and_sign(send_to_a_stranger(600, 10), SpendOpClass::Undeclared)
            .await
            .expect("an undeclared spend still signs once the user approves it");
        assert_eq!(
            ceremonies(&undeclared),
            1,
            "the same spend, undeclared, was routed to the human instead of auto-approved"
        );
    }

    // -----------------------------------------------------------------------------------------
    // Consent, and the fail-closed edges.
    // -----------------------------------------------------------------------------------------

    /// A declined ceremony refuses the spend, and no signature is ever produced. The custody policy
    /// would have permitted it; the user did not.
    #[tokio::test]
    async fn a_declined_ceremony_refuses_the_spend_and_never_signs() {
        let path = money_path(
            RecordingProvider::new(SpendDecision::Decline(Some("not me".into()))),
            hot_wallet_that_tiers_our_fixture_as_auto_send(),
            AutoSendPolicy::default(),
        );

        let result = path
            .authorize_and_sign(send_to_a_stranger(600, 10), SpendOpClass::SmallSend)
            .await;

        assert!(
            matches!(&result, Err(MoneyPathError::Declined(Some(why))) if why.contains("not me")),
            "a declined ceremony must refuse the spend: {result:?}"
        );
        assert_eq!(
            ceremonies(&path),
            1,
            "the ceremony ran and its decline was honoured — the signer was never reached"
        );
    }

    /// **A lock that lands DURING the confirm ceremony fails the sign closed.**
    ///
    /// This is a placement test, not an outcome test: the money path builds its signer after the
    /// ceremony rather than before it, and an implementation that captured the signer up front would
    /// sign this spend under an unlock the user has since revoked. Locking from inside the ceremony
    /// is what makes the two placements observably different — with the lock taken before the call
    /// instead, both implementations refuse and the ordering would be pinned by nothing.
    #[tokio::test]
    async fn a_lock_during_the_confirm_ceremony_fails_the_sign_closed() {
        let residency = residency_at_seed();
        let path = MoneyPath::new(
            residency.clone(),
            RecordingProvider::approving_but_locks(residency.clone()),
            account_id(),
            Network::Mainnet,
            hot_wallet_that_tiers_our_fixture_as_auto_send(),
            AutoSendPolicy::default(),
            frozen_clock(),
        )
        .expect("the residency is unlocked when the path is built");

        let result = path
            .authorize_and_sign(send_to_a_stranger(600, 10), SpendOpClass::SmallSend)
            .await;

        assert!(
            matches!(result, Err(MoneyPathError::Locked)),
            "the user locked their account while the confirm window was open: {result:?}"
        );
        assert_eq!(
            ceremonies(&path),
            1,
            "the ceremony did run and did approve — the refusal came from the lock, not the user"
        );
    }

    /// A money path cannot even be BUILT over a locked residency: the gate needs the profile's own
    /// hot-wallet address, and a locked account has none to give.
    #[test]
    fn a_locked_residency_yields_no_money_path_at_all() {
        let residency = residency_at_seed();
        residency.lock_all();

        let built = MoneyPath::new(
            residency,
            NeverConfirm,
            account_id(),
            Network::Mainnet,
            hot_wallet_that_tiers_our_fixture_as_auto_send(),
            AutoSendPolicy::default(),
            frozen_clock(),
        );

        assert!(
            matches!(built, Err(MoneyPathError::Locked)),
            "a locked account has no hot-wallet address, so there is no gate to build"
        );
    }

    /// **The consent surface describes THIS spend, drawn from THIS account, signed by THIS profile.**
    ///
    /// A confirm ceremony that runs is not a confirm ceremony that is right. Nothing in this suite
    /// read the request at all, so substituting a foreign account id — or a profile index the wallet
    /// does not sign at — left every test green: a dialog can be truthful about the money and still
    /// ask the user to approve it for the wrong identity.
    ///
    /// The profile is pinned to [`ProfileIx::ROOT`] rather than to `ActiveProfile::SOLE.ix()`, which
    /// is the value the code under test passes: restating a production constant agrees with itself
    /// whatever it becomes. `ROOT` is where this fixture's wallet key is derived and therefore where
    /// the signature actually comes from, so what is asserted is that the dialog names the profile
    /// whose key signs — two independently obtained facts rather than one repeated.
    #[tokio::test]
    async fn the_confirm_ceremony_names_this_account_this_profile_and_this_spend() {
        let path = money_path(
            RecordingProvider::new(SpendDecision::Approve),
            hot_wallet_that_tiers_our_fixture_as_auto_send(),
            // No auto-send allowance, so the spend is escalated and there is a request to read.
            AutoSendPolicy::default(),
        );

        path.authorize_and_sign(send_to_a_stranger(600, 10), SpendOpClass::SmallSend)
            .await
            .expect("the user approved it");

        path.auth_provider.with_sole_request(|request| {
            assert_eq!(
                request.account,
                account_id(),
                "the dialog must name the account the money leaves"
            );
            assert_eq!(
                request.profile,
                ProfileIx::ROOT,
                "the dialog must name the profile whose key signs"
            );
            assert_eq!(
                request.summary.recipients,
                vec![SpendRecipient {
                    address: Address::new(A_STRANGER, "xch".to_string())
                        .encode()
                        .expect("a puzzle hash encodes"),
                    amount_mojos: 600,
                    asset_id: None,
                }],
                "the dialog must show who is paid, and how much"
            );
            assert_eq!(
                request.summary.fee, 10,
                "and the fee that is burned with it"
            );
        });
    }

    /// **A money signer obtained BEFORE a lock must refuse to sign AFTER it** — the retained-capability
    /// half of the lock, which no other test in this crate could see.
    ///
    /// Every other lock test here interrogates the residency about ITSELF: it locks, then asks for a
    /// NEW signer and is told `None`. That is a true statement about the accessor and says nothing
    /// about a capability already handed out — and a capability already handed out is the only thing a
    /// lock has to defeat. So this one takes the signer out ONCE, while unlocked, keeps it across the
    /// transition, and asks it to sign afterwards.
    ///
    /// The wrong implementation it is aimed at is the one dig-app shipped: `lock_all` dropping the
    /// `UnlockedAccount` instead of calling [`UnlockedAccount::lock`]. The drop releases one reference
    /// to a seed this very signer also holds, so the bytes stay resident, the unlock is never revoked,
    /// and the retained signer produces a real mainnet signature while the app reports itself locked.
    ///
    /// Both approvals are minted BEFORE the lock so the lock is the only thing that changes between
    /// the two signatures, and the first one is a truthful control: this exact signer, holding this
    /// exact approval, genuinely does sign — so "refused" cannot be read as "the fixture never worked".
    #[test]
    fn a_money_signer_taken_out_before_a_lock_refuses_to_sign_after_it() {
        let residency = residency_at_seed();
        let address = residency
            .receiving_address()
            .expect("unlocked")
            .expect("an address encodes");
        let authorizer = PolicyAuthorizer::new(
            residency.profiles().active_ix(),
            hot_wallet_that_tiers_our_fixture_as_auto_send(),
            small_sends_up_to(SPEND_TOTAL, SPEND_TOTAL * 10),
            &address,
            frozen_clock(),
        )
        .expect("the fixture address is a valid hot-wallet address");

        let approve_a_send = |authorizer: &PolicyAuthorizer| match authorizer
            .authorize_op(&send_to_a_stranger(600, 10), SpendOpClass::SmallSend)
            .expect("the fixture spend is decodable")
        {
            SpendRuling::Approved(approval) => approval,
            SpendRuling::RequiresConfirmation(_) => {
                panic!("the fixture spend is inside its limits and must auto-approve")
            }
        };

        // The capability under test, taken out ONCE while unlocked and held across the lock.
        let retained_signer = residency
            .money_signer(Network::Mainnet)
            .expect("an unlocked residency yields a money signer");
        let before_the_lock = approve_a_send(&authorizer);
        let after_the_lock = approve_a_send(&authorizer);

        retained_signer
            .sign_approved(before_the_lock)
            .expect("control: this very signer signs while the account is unlocked");

        residency.lock_all();
        assert!(!residency.is_any_unlocked(), "the account is locked");

        let signed_anyway = retained_signer.sign_approved(after_the_lock);
        assert!(
            matches!(signed_anyway, Err(AccountError::Locked)),
            "a signer handed out before the lock must be REVOKED by it, not merely un-reissuable: \
             {signed_anyway:?}"
        );
    }

    /// An undecodable spend fails closed at the gate's own derivation, before any ruling is made.
    #[tokio::test]
    async fn an_undecodable_spend_fails_closed_before_any_ruling() {
        let path = money_path(
            RecordingProvider::new(SpendDecision::Approve),
            hot_wallet_that_tiers_our_fixture_as_auto_send(),
            AutoSendPolicy::default(),
        );

        let result = path
            .authorize_and_sign(vec![], SpendOpClass::SmallSend)
            .await;

        assert!(
            matches!(result, Err(MoneyPathError::Summary(_))),
            "an empty coin-spend set is not a spend the gate can account for: {result:?}"
        );
        assert_eq!(ceremonies(&path), 0, "nothing was put to the user");
    }
}
