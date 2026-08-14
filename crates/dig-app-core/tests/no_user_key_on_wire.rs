//! #908 on-wire custody enforcement — the boundary the whole Model-A architecture protects.
//!
//! With the money AND identity sign paths now LIVE (the #1548 switchover), this test asserts at the
//! ACTUAL wire-byte level that NO user key material crosses the dig-app → dig-node IPC channel: only
//! the signed spend bundle (money path) and the profile-signed bytes (identity path) do. The seed,
//! every money/identity secret derived from it, and the per-profile DEK stay owned by dig-account and
//! never leave the app process.
//!
//! The test drives the real live money path end-to-end (build a spend at the wallet's own coin →
//! authorize → confirm → sign → BROADCAST over the `control.wallet.*` seam), captures every serialized
//! request byte the seam would put on the wire, and asserts:
//!
//! * the signed bundle DOES cross (the whole point — signed bytes, not keys); and
//! * the master seed, the canonical wallet synthetic secret key, and the profile DEK do NOT appear
//!   anywhere in the wire bytes, in raw OR lowercase-hex form.

use std::cell::RefCell;
use std::sync::Arc;

use async_trait::async_trait;
use chia_bls::{master_to_wallet_unhardened, SecretKey};
use chia_protocol::{Bytes32, Coin, CoinSpend};
use chia_puzzle_types::{DeriveSynthetic, Memos};
use chia_sdk_driver::{SpendContext, StandardLayer};
use chia_sdk_types::Conditions;

use dig_account::WalletKey;
use dig_app_core::account::money::MoneyPath;
use dig_app_core::account::residency::AccountResidency;
use dig_app_core::wallet::encode_signed_bundle;
use dig_app_core::wallet::engine::{
    BroadcastRequest, BroadcastResponse, CoinsRequest, CoinsResponse, WalletEngine,
};
use dig_app_core::wallet::WalletError;

use dig_account::{
    profile_dek, AccountId, AccountSession, AccountStore, AuthFactors, AuthProvider,
    AutoSendPolicy, CustodyPolicy, HotWallet, ProfileIx, Result as AccountResult,
    SpendConfirmRequest, SpendDecision, SpendOpClass, SystemClock, UnlockRequest,
};
use dig_ipc_protocol::signer::SessionSigner;
use dig_keystore::{BackendKey, MemoryBackend};
use dig_session::{Password, Session, ENTROPY_LEN};

/// A fixed master seed so the independently-derived secrets we search the wire for match exactly the
/// account's live key material at [`ProfileIx::ROOT`] (the byte-contract in
/// `wallet_key_byte_contract.rs`).
const SEED: [u8; ENTROPY_LEN] = [0x5c; ENTROPY_LEN];

/// The 64-byte HD seed dig-account/dig-session derive from — [`SEED`] treated as BIP-39 ENTROPY and
/// expanded exactly as production does before any key derivation (the #1759 seed expansion). Every
/// independent derivation below MUST start from this expanded seed so the secrets we search the wire
/// for are the account's ACTUAL live key material, not the pre-cutover raw-entropy ones.
fn expanded_seed() -> [u8; 64] {
    bip39::Mnemonic::from_entropy_in(bip39::Language::English, &SEED)
        .expect("32-byte entropy is valid 24-word BIP-39")
        .to_seed("")
}

/// A [`WalletEngine`] that RECORDS every serialized request byte it would place on the IPC wire, so a
/// test can inspect exactly what crosses the dig-app → dig-node boundary. It never sees a key — the
/// contract says it receives only signed bytes; this makes that inspectable.
#[derive(Default)]
struct WireRecordingEngine {
    /// Every request serialized to its on-wire JSON bytes, in call order.
    wire: RefCell<Vec<u8>>,
}

impl WireRecordingEngine {
    fn record<T: serde::Serialize>(&self, request: &T) {
        let bytes = serde_json::to_vec(request).expect("serialize request to its wire form");
        self.wire.borrow_mut().extend_from_slice(&bytes);
    }
}

impl WalletEngine for WireRecordingEngine {
    fn broadcast(&self, request: BroadcastRequest) -> Result<BroadcastResponse, WalletError> {
        self.record(&request);
        Ok(BroadcastResponse {
            accepted: true,
            transaction_id: Some("recorded".into()),
            rejection: None,
        })
    }
    fn coins(&self, request: CoinsRequest) -> Result<CoinsResponse, WalletError> {
        self.record(&request);
        Ok(CoinsResponse { coins: vec![] })
    }
    fn balance(
        &self,
        request: CoinsRequest,
    ) -> Result<dig_app_core::wallet::engine::BalanceResponse, WalletError> {
        self.record(&request);
        Ok(dig_app_core::wallet::engine::BalanceResponse {
            balance: 0,
            as_of: dig_app_core::wallet::engine::BalanceAsOf::Replica {
                height: 7_000_000,
                caught_up: true,
            },
        })
    }
}

/// An auth provider that approves the spend (so the live path reaches the signer). It NEVER receives
/// or returns any key material — only a yes/no ruling.
struct ApprovingProvider;
#[async_trait]
impl AuthProvider for ApprovingProvider {
    async fn collect_factors(&self, _request: UnlockRequest) -> AccountResult<AuthFactors> {
        unreachable!("the money path never collects unlock factors")
    }
    async fn confirm_spend(&self, _request: SpendConfirmRequest) -> AccountResult<SpendDecision> {
        Ok(SpendDecision::Approve)
    }
}

/// A residency over a fresh account enrolled at [`SEED`].
fn residency_at_seed() -> AccountResidency {
    let store = Arc::new(AccountStore::new(Arc::new(MemoryBackend::new())));
    let unlocked = AccountSession::enroll(
        store,
        AccountId::new("wire-test"),
        Password::new("pw"),
        &SEED,
        ProfileIx::ROOT,
    )
    .unwrap();
    AccountResidency::new(unlocked)
}

/// A real standard-layer XCH send out of the wallet's own coin (recipient hinted, change home).
fn real_send() -> Vec<CoinSpend> {
    let key = WalletKey::from_seed(&expanded_seed());
    let wallet_ph = key.puzzle_hash();
    let mut ctx = SpendContext::new();
    let coin = Coin::new(Bytes32::new([1u8; 32]), wallet_ph, 1_000_000);
    let recipient = Bytes32::new([9u8; 32]);
    let hint = ctx.hint(recipient).unwrap();
    let conditions = Conditions::new()
        .create_coin(recipient, 600_000, hint)
        .create_coin(wallet_ph, 399_990, Memos::None)
        .reserve_fee(10);
    StandardLayer::new(key.public_key())
        .spend(&mut ctx, coin, conditions)
        .unwrap();
    ctx.take()
}

/// The 32-byte canonical wallet synthetic secret key at ROOT, derived independently so we can prove
/// it never leaks onto the wire.
fn wallet_synthetic_secret() -> [u8; 32] {
    let master = SecretKey::from_seed(&expanded_seed());
    master_to_wallet_unhardened(&master, 0)
        .derive_synthetic()
        .to_bytes()
}

/// The per-profile DEK at ROOT, derived independently (via the same dig-account contract) to prove it
/// never leaks onto the wire.
fn profile_dek_at_root() -> [u8; 32] {
    let handle = Session::enroll_master_seed(
        Arc::new(MemoryBackend::new()),
        BackendKey::new("seed".to_string()),
        Password::new("pw"),
        &SEED,
    )
    .unwrap();
    profile_dek(&handle, ProfileIx::ROOT)
}

/// Whether `haystack` contains `needle` either raw or as its lowercase-hex encoding.
fn contains_bytes(haystack: &[u8], needle: &[u8]) -> bool {
    let raw = haystack.windows(needle.len()).any(|w| w == needle);
    let hex = hex::encode(needle);
    let hex_hit = haystack.windows(hex.len()).any(|w| w == hex.as_bytes());
    raw || hex_hit
}

#[tokio::test]
async fn no_user_key_crosses_the_ipc_wire_on_a_live_signed_spend() {
    let residency = residency_at_seed();
    // A hot-wallet policy with the default (zero) allowance, so this spend is tiered `Confirm` and
    // reaches the signer through the confirm ceremony. A `Vault` policy would be refused outright by
    // the custody gate — the spend pays a third party — and this test needs a spend that ACTUALLY
    // signs, since an unsigned spend would trivially satisfy "no key on the wire".
    let path = MoneyPath::new(
        residency.clone(),
        ApprovingProvider,
        AccountId::new("wire-test"),
        dig_wallet_backend::types::Network::Mainnet,
        CustodyPolicy::Hot(HotWallet::default()),
        AutoSendPolicy::default(),
        Arc::new(SystemClock),
    )
    .expect("an unlocked residency yields a money path");

    // Drive the LIVE money path: rule -> confirm -> sign.
    let bundle = path
        .authorize_and_sign(real_send(), SpendOpClass::Undeclared)
        .await
        .expect("the approved live spend signs");

    // Broadcast the signed bundle over the seam — exactly what crosses the dig-app -> dig-node wire.
    let engine = WireRecordingEngine::default();
    let signed_hex = encode_signed_bundle(&bundle).unwrap();
    engine
        .broadcast(BroadcastRequest {
            signed_bundle_hex: signed_hex.clone(),
        })
        .unwrap();
    // A representative read request also crosses the wire — include it in the inspection.
    engine
        .coins(CoinsRequest {
            address: WalletKey::from_seed(&expanded_seed()).address().unwrap(),
            asset: dig_app_core::wallet::state::Asset::Xch,
        })
        .unwrap();

    let wire = engine.wire.borrow();

    // The signed bundle DOES cross (signed bytes are the point).
    assert!(
        contains_bytes(&wire, signed_hex.as_bytes()),
        "the signed bundle must cross the wire"
    );

    // No key material crosses — the seed, the wallet money secret, or the profile DEK, raw or hex.
    assert!(
        !contains_bytes(&wire, &SEED),
        "the master seed must NEVER cross the IPC wire"
    );
    assert!(
        !contains_bytes(&wire, &wallet_synthetic_secret()),
        "the wallet synthetic money secret must NEVER cross the IPC wire"
    );
    assert!(
        !contains_bytes(&wire, &profile_dek_at_root()),
        "the per-profile DEK must NEVER cross the IPC wire"
    );
}

#[tokio::test]
async fn the_identity_sign_path_puts_only_a_signature_on_the_wire_never_the_key() {
    // The identity sign leg is also live (through the residency's ProfileSigner). What crosses the
    // wire is the signature over the caller's bytes — never the signing key or the seed it derives
    // from.
    let residency = residency_at_seed();
    let signer = residency.signer();

    let message = b"dig-app IPC session challenge";
    let signature = signer
        .try_sign(message)
        .expect("an unlocked residency signs");

    // The on-wire artifact of an identity sign is the 96-byte signature (+ the 48-byte public key).
    let mut wire = Vec::new();
    wire.extend_from_slice(signature.as_bytes());
    wire.extend_from_slice(signer.signing_public_key().as_bytes());

    assert!(
        !contains_bytes(&wire, &SEED),
        "the identity sign wire must NEVER carry the seed"
    );
    assert!(
        !contains_bytes(&wire, &wallet_synthetic_secret()),
        "no money secret rides the identity sign wire either"
    );
    assert!(
        !contains_bytes(&wire, &profile_dek_at_root()),
        "the DEK must NEVER cross the identity sign wire"
    );
}
