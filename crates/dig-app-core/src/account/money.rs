//! The LIVE money path — authorize-BEFORE-sign, over the master-HD [`AccountResidency`] (#1548,
//! custody switchover slice C — **SECURITY-CRITICAL, money goes live**).
//!
//! # The one custody flow money moves through
//!
//! A spend is a set of unsigned [`CoinSpend`]s the app has built (via the canonical chip35 builders,
//! [`crate::wallet::spend`]). This module turns those into a signed [`SpendBundle`] through a
//! FAIL-CLOSED gate that runs, in order:
//!
//! 1. **summarize** — [`AccountResidency::summarize`] independently re-derives the recipients + fee
//!    from the coin spends (never a caller's claim) and classifies the [`SpendTier`] under the
//!    profile's [`CustodyPolicy`]. A locked residency summarizes nothing → refused.
//! 2. **authorize** — the injected [`SpendAuthorizer`] rules on the [`SpendSummary`] (spend limits /
//!    allowlists / programmatic policy). An `Err` refuses the spend.
//! 3. **confirm ceremony (where the tier requires it)** — for any tier that
//!    [`requires_confirmation`] (everything except a within-allowance [`SpendTier::AutoSend`]), the
//!    injected [`AuthProvider::confirm_spend`] MUST run and return [`SpendDecision::Approve`] before
//!    a signature is ever produced. **`authorize() == Ok` is NOT sufficient on its own** (the #1522
//!    gate note): a `RequireAuth`-class spend (Vault / over-allowance Confirm) that skips the confirm
//!    ceremony is REFUSED — the signer is never even built.
//! 4. **sign** — ONLY after the gate passes, [`AccountResidency::money_signer`] builds the live
//!    dig-account money signer and signs the coin spends. The residency is re-read here, so a lock
//!    that lands DURING the confirm dialog fails the sign closed rather than signing a spend the user
//!    meant to relock.
//!
//! # The custody boundary (#908, Model A)
//!
//! The seed + every derived money secret stay owned by dig-account: the signer holds the key inside
//! its vetted core and exposes signing only. What leaves this module is the signed [`SpendBundle`] —
//! the same bytes that cross the dig-app→dig-node IPC wire (`control.wallet.broadcast`,
//! [`crate::wallet::engine`]). No key material ever crosses that wire (asserted at the wire level by
//! the `no_user_key_on_wire` integration test).

use chia_protocol::{CoinSpend, SpendBundle};
use dig_account::{
    AccountId, AuthProvider, CustodyPolicy, MoneySigner, ProfileIx, SpendAuthorizer,
    SpendConfirmRequest, SpendDecision, SpendTier,
};
use dig_wallet_backend::types::Network;

use crate::account::residency::AccountResidency;

/// A failure of the [`MoneyPath`] gate. Each variant names exactly which gate refused, so a custody
/// review can see where a spend was stopped — and so no failure is silently indistinguishable from a
/// successful, unsigned no-op.
#[derive(Debug, thiserror::Error)]
pub enum MoneyPathError {
    /// The account residency is locked (at summarize or at sign) — nothing is signed. Fail-closed.
    #[error("the account is locked — the spend was not signed")]
    Locked,

    /// The spend summary could not be re-derived from the coin spends (an undecodable / unaccountable
    /// spend). Fail-closed: the same gate the money signer enforces before signing.
    #[error("could not summarize the spend: {0}")]
    Summary(String),

    /// The programmatic [`SpendAuthorizer`] refused the spend (a policy limit / allowlist).
    #[error("the spend was not authorized: {0}")]
    Unauthorized(String),

    /// The user DECLINED the confirm ceremony (or the ceremony failed to complete) — nothing is
    /// signed. Distinct from [`Unauthorized`](Self::Unauthorized): the programmatic policy allowed it,
    /// but the required human confirmation did not approve it.
    #[error("the spend was declined at the confirm ceremony{}", .0.as_ref().map(|w| format!(": {w}")).unwrap_or_default())]
    Declined(Option<String>),

    /// Signing the (authorized + confirmed) spend failed inside dig-account's money signer.
    #[error("spend signing failed: {0}")]
    Sign(String),
}

/// Whether a spend of this [`SpendTier`] MUST pass the human confirm ceremony before it may be
/// signed. Only a within-allowance [`SpendTier::AutoSend`] skips it; [`SpendTier::Confirm`] and the
/// clawback-protected [`SpendTier::Vault`] both require the ceremony (the `RequireAuth` class).
pub fn requires_confirmation(tier: SpendTier) -> bool {
    !matches!(tier, SpendTier::AutoSend)
}

/// The live money path for one account: the fail-closed authorize-before-sign gate over the shared
/// [`AccountResidency`] (the SAME lockable seed home the identity signer reads, so a lock relocks
/// BOTH). Generic over the injected [`SpendAuthorizer`] + [`AuthProvider`] so production wires the
/// real two-tier custody brain + the OS-native ceremony, while tests drive fakes.
pub struct MoneyPath<A, P>
where
    A: SpendAuthorizer,
    P: AuthProvider,
{
    residency: AccountResidency,
    authorizer: A,
    auth_provider: P,
    account_id: AccountId,
    network: Network,
}

impl<A, P> MoneyPath<A, P>
where
    A: SpendAuthorizer,
    P: AuthProvider,
{
    /// Assemble the money path over `residency`, gating every spend on `authorizer` then
    /// `auth_provider`, drawing from `account_id` on `network`.
    pub fn new(
        residency: AccountResidency,
        authorizer: A,
        auth_provider: P,
        account_id: AccountId,
        network: Network,
    ) -> Self {
        Self {
            residency,
            authorizer,
            auth_provider,
            account_id,
            network,
        }
    }

    /// Run the full authorize-before-sign gate over `coin_spends` under `policy`, returning the
    /// broadcast-ready signed [`SpendBundle`] ONLY when every gate passes.
    ///
    /// See the [module docs](self) for the ordered gate. Fail-closed at each step; a signature is
    /// produced only after summarize + authorize + (where required) an approving confirm ceremony all
    /// pass, and only if the residency is still unlocked at the moment of signing.
    pub async fn authorize_and_sign(
        &self,
        coin_spends: Vec<CoinSpend>,
        policy: &CustodyPolicy,
    ) -> Result<SpendBundle, MoneyPathError> {
        // 1. Re-derive + tier the spend from the coin spends themselves (fail-closed when locked).
        let summary = self
            .residency
            .summarize(&coin_spends, policy)
            .ok_or(MoneyPathError::Locked)?
            .map_err(|e| MoneyPathError::Summary(e.to_string()))?;

        // 2. Programmatic authorization. An Ok here is necessary but NOT sufficient (see step 3).
        self.authorizer
            .authorize(&summary)
            .map_err(|e| MoneyPathError::Unauthorized(e.to_string()))?;

        // 3. The human confirm ceremony, REQUIRED for every tier above auto-send. This is the #1522
        //    gate: a RequireAuth-class spend cannot complete on authorize()==Ok alone.
        if requires_confirmation(summary.tier) {
            let request =
                SpendConfirmRequest::new(self.account_id.clone(), ProfileIx::ROOT, summary.clone());
            match self
                .auth_provider
                .confirm_spend(request)
                .await
                .map_err(|e| MoneyPathError::Declined(Some(e.to_string())))?
            {
                SpendDecision::Approve => {}
                SpendDecision::Decline(why) => return Err(MoneyPathError::Declined(why)),
            }
        }

        // 4. Only now build the signer + sign. Re-reading the residency means a lock that landed
        //    during the confirm dialog fails the sign closed (no snapshot escape).
        let signer = self
            .residency
            .money_signer(self.network)
            .ok_or(MoneyPathError::Locked)?
            .map_err(|e| MoneyPathError::Sign(e.to_string()))?;
        let signature = signer
            .sign_coin_spends(&coin_spends)
            .map_err(|e| MoneyPathError::Sign(e.to_string()))?;

        Ok(SpendBundle::new(coin_spends, signature))
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
    use dig_account::{
        AccountSession, AccountStore, AuthFactors, HotWallet, Result as AccountResult,
        SpendSummary, UnlockRequest, Vault, WalletKey,
    };
    use dig_keystore::MemoryBackend;
    use dig_session::{Password, SEED_LEN};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    /// A fixed 32-byte master seed so the test's independently-built coin spend (via dig-account's
    /// [`WalletKey`]) and the residency's dig-account money signer derive the SAME canonical wallet
    /// key at [`ProfileIx::ROOT`].
    const SEED: [u8; SEED_LEN] = [0x7c; SEED_LEN];

    /// A residency over a fresh account enrolled at [`SEED`].
    fn residency_at_seed() -> AccountResidency {
        let store = Arc::new(AccountStore::new(Arc::new(MemoryBackend::new())));
        let unlocked = AccountSession::enroll(
            store,
            AccountId::new("money-path-test"),
            Password::new("pw"),
            &SEED,
            ProfileIx::ROOT,
        )
        .unwrap();
        AccountResidency::new(unlocked)
    }

    /// A real standard-layer XCH send OUT of the wallet's own coin — the same shape a genuine spend
    /// takes, so dig-account's money signer can actually verify + sign it. `native_out` mojos leave to
    /// a recipient; the remainder (minus `fee`) returns as change to the wallet.
    fn real_send(native_out: u64, fee: u64) -> Vec<CoinSpend> {
        let key = WalletKey::from_seed(&SEED);
        let wallet_ph = key.puzzle_hash();
        let mut ctx = SpendContext::new();
        let coin = Coin::new(Bytes32::new([1u8; 32]), wallet_ph, 1_000_000);
        let recipient = Bytes32::new([9u8; 32]);
        // The money signer's exfiltration guard requires every non-change output to be a HINTED
        // recipient (a bare unhinted output reads as a possible drain and is refused). Hint the
        // recipient; the change coin returns to the wallet's own puzzle hash.
        let hint = ctx.hint(recipient).unwrap();
        let change = 1_000_000 - native_out - fee;
        let conditions = Conditions::new()
            .create_coin(recipient, native_out, hint)
            .create_coin(wallet_ph, change, Memos::None)
            .reserve_fee(fee);
        StandardLayer::new(key.public_key())
            .spend(&mut ctx, coin, conditions)
            .unwrap();
        ctx.take()
    }

    /// A [`SpendAuthorizer`] that always permits (the fail-closed default's programmatic half —
    /// authorization then rests entirely on the confirm ceremony).
    struct AllowAll;
    impl SpendAuthorizer for AllowAll {
        fn authorize(&self, _summary: &SpendSummary) -> AccountResult<()> {
            Ok(())
        }
    }

    /// A [`SpendAuthorizer`] that always refuses.
    struct DenyAll;
    impl SpendAuthorizer for DenyAll {
        fn authorize(&self, _summary: &SpendSummary) -> AccountResult<()> {
            Err(dig_account::AccountError::Auth("policy refused".into()))
        }
    }

    /// A recording [`AuthProvider`] that returns a canned [`SpendDecision`] and counts how many times
    /// the confirm ceremony ran — so a test can prove the ceremony DID (or did not) run.
    struct RecordingProvider {
        decision: SpendDecision,
        confirms: AtomicUsize,
    }
    impl RecordingProvider {
        fn new(decision: SpendDecision) -> Self {
            Self {
                decision,
                confirms: AtomicUsize::new(0),
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
            _request: SpendConfirmRequest,
        ) -> AccountResult<SpendDecision> {
            self.confirms.fetch_add(1, Ordering::SeqCst);
            Ok(self.decision.clone())
        }
    }

    /// An [`AuthProvider`] that PANICS if the confirm ceremony is ever invoked — used to prove that an
    /// auto-send spend signs WITHOUT any confirmation.
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
            panic!("confirm_spend must NOT run for an auto-send spend");
        }
    }

    #[tokio::test]
    async fn a_vault_spend_signs_after_an_approving_confirm_ceremony() {
        let provider = RecordingProvider::new(SpendDecision::Approve);
        let path = MoneyPath::new(
            residency_at_seed(),
            AllowAll,
            provider,
            AccountId::new("money-path-test"),
            Network::Mainnet,
        );
        let bundle = path
            .authorize_and_sign(real_send(600, 10), &CustodyPolicy::Vault(Vault::default()))
            .await
            .expect("an approved vault spend signs");
        assert_ne!(
            bundle.aggregated_signature,
            chia_bls::Signature::default(),
            "a signed vault spend carries a real aggregate signature"
        );
        assert_eq!(
            path.auth_provider.confirms.load(Ordering::SeqCst),
            1,
            "the vault spend passed through EXACTLY one confirm ceremony before signing"
        );
    }

    #[tokio::test]
    async fn a_vault_spend_without_the_confirm_ceremony_is_refused_and_never_signs() {
        // THE #1522 gate: authorize()==Ok is not enough — a Vault (RequireAuth) spend the user
        // DECLINES at the confirm ceremony must be refused, and no signature is ever produced.
        let provider = RecordingProvider::new(SpendDecision::Decline(Some("not me".into())));
        let path = MoneyPath::new(
            residency_at_seed(),
            AllowAll, // programmatic policy ALLOWS it …
            provider,
            AccountId::new("money-path-test"),
            Network::Mainnet,
        );
        let result = path
            .authorize_and_sign(real_send(600, 10), &CustodyPolicy::Vault(Vault::default()))
            .await;
        assert!(
            matches!(result, Err(MoneyPathError::Declined(Some(ref w)) ) if w == "not me"),
            "… yet a declined confirm ceremony REFUSES the spend (never signs): {result:?}"
        );
        assert_eq!(
            path.auth_provider.confirms.load(Ordering::SeqCst),
            1,
            "the confirm ceremony ran and its decline was honoured — the signer was never reached"
        );
    }

    #[tokio::test]
    async fn a_within_allowance_auto_send_signs_without_any_confirmation() {
        // A hot wallet with a generous allowance classifies a small send as AutoSend; it must NOT
        // invoke the confirm ceremony (NeverConfirm panics if it does).
        let path = MoneyPath::new(
            residency_at_seed(),
            AllowAll,
            NeverConfirm,
            AccountId::new("money-path-test"),
            Network::Mainnet,
        );
        let policy = CustodyPolicy::Hot(HotWallet {
            auto_send_limit: 1_000_000,
        });
        let bundle = path
            .authorize_and_sign(real_send(600, 10), &policy)
            .await
            .expect("a within-allowance auto-send signs with no ceremony");
        assert_ne!(bundle.aggregated_signature, chia_bls::Signature::default());
    }

    #[tokio::test]
    async fn a_programmatically_unauthorized_spend_is_refused_before_any_confirmation() {
        let provider = RecordingProvider::new(SpendDecision::Approve);
        let path = MoneyPath::new(
            residency_at_seed(),
            DenyAll,
            provider,
            AccountId::new("money-path-test"),
            Network::Mainnet,
        );
        let result = path
            .authorize_and_sign(real_send(600, 10), &CustodyPolicy::Vault(Vault::default()))
            .await;
        assert!(matches!(result, Err(MoneyPathError::Unauthorized(_))));
        assert_eq!(
            path.auth_provider.confirms.load(Ordering::SeqCst),
            0,
            "a programmatic refusal short-circuits BEFORE the confirm ceremony"
        );
    }

    #[tokio::test]
    async fn a_locked_residency_refuses_the_spend_fail_closed() {
        let residency = residency_at_seed();
        let path = MoneyPath::new(
            residency.clone(),
            AllowAll,
            RecordingProvider::new(SpendDecision::Approve),
            AccountId::new("money-path-test"),
            Network::Mainnet,
        );
        residency.lock_all();
        let result = path
            .authorize_and_sign(real_send(600, 10), &CustodyPolicy::Vault(Vault::default()))
            .await;
        assert!(
            matches!(result, Err(MoneyPathError::Locked)),
            "a locked residency summarizes nothing and never signs: {result:?}"
        );
    }

    #[tokio::test]
    async fn an_undecodable_spend_fails_closed_at_summarize() {
        let path = MoneyPath::new(
            residency_at_seed(),
            AllowAll,
            RecordingProvider::new(SpendDecision::Approve),
            AccountId::new("money-path-test"),
            Network::Mainnet,
        );
        // An empty coin-spend set is not a decodable spend.
        let result = path
            .authorize_and_sign(vec![], &CustodyPolicy::Hot(HotWallet::default()))
            .await;
        assert!(matches!(result, Err(MoneyPathError::Summary(_))));
    }

    #[test]
    fn requires_confirmation_is_true_for_every_tier_above_auto_send() {
        assert!(!requires_confirmation(SpendTier::AutoSend));
        assert!(requires_confirmation(SpendTier::Confirm));
        assert!(requires_confirmation(SpendTier::Vault));
    }
}
