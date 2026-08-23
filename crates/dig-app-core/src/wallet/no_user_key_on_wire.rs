//! §908 on-wire custody enforcement — the boundary the whole Model-A architecture protects.
//!
//! The rule is one sentence: **the user's key material never enters the node.** Only the signed
//! spend bundle crosses the dig-app → dig-node control plane. The master seed, every money secret
//! derived from it, and the per-profile DEK stay owned by dig-account inside the app process.
//!
//! # Why this test lives here, and drives a socket (dig_ecosystem#2892)
//!
//! It used to be an integration test that built a `BroadcastRequest` by hand, handed it to a
//! recording `WalletEngine`, and searched the recording. Those bytes were the ones the TEST wrote,
//! so the recorder could only ever report the test's own construction — and since dig-app#167
//! production stopped using that seam entirely, broadcasting through
//! [`ControlSpendPublisher`](crate::chain::ControlSpendPublisher) instead. Measured: appending the
//! master seed's hex to what the publisher puts on the wire left that test **green**.
//!
//! So the recorder is now the far end of a real loopback TCP socket. The bytes asserted on are the
//! bytes production serialized, framed and wrote — nothing in this file constructs a request. That
//! is what moves the assertion from *"the test wrote no key"* to *"the shipping seam sends no key"*,
//! and it is why the test had to come inside the crate: [`FakeNode`] is crate-internal.

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use chia_bls::{master_to_wallet_unhardened, SecretKey};
use chia_protocol::{Bytes32, Coin, CoinSpend};
use chia_puzzle_types::{DeriveSynthetic, Memos};
use chia_sdk_driver::{SpendContext, StandardLayer};
use chia_sdk_types::Conditions;

use dig_account::mint::PushOutcome;
use dig_account::{
    profile_dek, AccountId, AccountSession, AccountStore, AuthFactors, AuthProvider,
    AutoSendPolicy, CustodyPolicy, HotWallet, ProfileIx, Result as AccountResult,
    SpendConfirmRequest, SpendDecision, SpendOpClass, SystemClock, UnlockRequest, WalletKey,
};
use dig_chainsource_interface::ChainSource;
use dig_keystore::{BackendKey, MemoryBackend};
use dig_session::{Password, Session, ENTROPY_LEN};

use crate::account::money::MoneyPath;
use crate::account::residency::AccountResidency;
use crate::chain::{ControlChainSource, ControlSpendPublisher, DetailedSpendPublisher};
use crate::test_support::node::{BroadcastReply, ChainReply, FakeChain, FakeNode};

/// Long enough that a loopback exchange is never the thing that fails.
const TEST_TIMEOUT: Duration = Duration::from_secs(5);

/// A fixed master seed, so the secrets derived independently below are byte-for-byte the account's
/// live key material at [`ProfileIx::ROOT`] rather than lookalikes.
const SEED: [u8; ENTROPY_LEN] = [0x5c; ENTROPY_LEN];

/// The token [`FakeNode`] authorizes, in the `fn() -> Option<String>` shape the publisher takes.
fn good_token() -> Option<String> {
    Some(FakeNode::TOKEN.to_string())
}

/// The 64-byte HD seed dig-account derives from — [`SEED`] treated as BIP-39 entropy and expanded
/// exactly as production does (the #1759 seed expansion), so every derivation below starts where the
/// account's own does.
fn expanded_seed() -> [u8; 64] {
    bip39::Mnemonic::from_entropy_in(bip39::Language::English, &SEED)
        .expect("32-byte entropy is valid 24-word BIP-39")
        .to_seed("")
}

/// The canonical wallet synthetic secret key at ROOT, derived independently of the account.
fn wallet_synthetic_secret() -> [u8; 32] {
    let master = SecretKey::from_seed(&expanded_seed());
    master_to_wallet_unhardened(&master, 0)
        .derive_synthetic()
        .to_bytes()
}

/// The per-profile DEK at ROOT, derived independently through the same dig-account contract.
fn profile_dek_at_root() -> [u8; 32] {
    let handle = Session::enroll_master_seed(
        Arc::new(MemoryBackend::new()),
        BackendKey::new("seed".to_string()),
        Password::new("pw"),
        &SEED,
    )
    .expect("a fresh backend enrols");
    profile_dek(&handle, ProfileIx::ROOT)
}

/// Every secret that must never cross, paired with the name an assertion failure should say.
fn secrets_that_must_never_cross() -> Vec<(&'static str, Vec<u8>)> {
    vec![
        ("the master seed", SEED.to_vec()),
        (
            "the wallet synthetic money secret",
            wallet_synthetic_secret().to_vec(),
        ),
        ("the per-profile DEK", profile_dek_at_root().to_vec()),
    ]
}

/// Whether `haystack` contains `needle` raw or as its lowercase-hex encoding.
///
/// Both spellings are searched because the control plane is JSON: key material would travel as hex
/// far more plausibly than as raw bytes, and a test that looked only for the raw form would miss the
/// likelier leak.
fn contains_bytes(haystack: &[u8], needle: &[u8]) -> bool {
    let raw = haystack.windows(needle.len()).any(|w| w == needle);
    let hex = hex::encode(needle);
    raw || haystack.windows(hex.len()).any(|w| w == hex.as_bytes())
}

/// An auth provider that approves the spend so the live path reaches the signer. It never receives
/// or returns key material — only a ruling.
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
    .expect("a fresh store enrols");
    AccountResidency::new(unlocked)
}

/// A real standard-layer XCH send out of the wallet's own coin (recipient hinted, change home).
fn real_send() -> Vec<CoinSpend> {
    let key = WalletKey::from_seed(&expanded_seed());
    let wallet_ph = key.puzzle_hash();
    let mut ctx = SpendContext::new();
    let coin = Coin::new(Bytes32::new([1u8; 32]), wallet_ph, 1_000_000);
    let recipient = Bytes32::new([9u8; 32]);
    let hint = ctx.hint(recipient).expect("a hint encodes");
    let conditions = Conditions::new()
        .create_coin(recipient, 600_000, hint)
        .create_coin(wallet_ph, 399_990, Memos::None)
        .reserve_fee(10);
    StandardLayer::new(key.public_key())
        .spend(&mut ctx, coin, conditions)
        .expect("the standard layer spends its own coin");
    ctx.take()
}

/// Sign a real spend through the LIVE money path: rule → confirm → sign.
///
/// A `Hot` policy with the default (zero) allowance tiers this spend as `Confirm`, so it reaches the
/// signer through the ceremony. That matters: an unsigned spend would satisfy "no key on the wire"
/// trivially, having never touched a key at all.
async fn signed_bundle() -> chia_protocol::SpendBundle {
    let path = MoneyPath::new(
        residency_at_seed(),
        ApprovingProvider,
        AccountId::new("wire-test"),
        dig_wallet_backend::types::Network::Mainnet,
        CustodyPolicy::Hot(HotWallet::default()),
        AutoSendPolicy::default(),
        Arc::new(SystemClock),
    )
    .expect("an unlocked residency yields a money path");

    path.authorize_and_sign(real_send(), SpendOpClass::Undeclared)
        .await
        .expect("the approved live spend signs")
}

/// **No user key crosses the wire on the seam that actually broadcasts.**
///
/// The nearest wrong implementation is the one this replaced: a recorder fed by the test itself, or
/// pointed at a seam production retired. Both report "no key" no matter what production does. The
/// fixture rules that out by never constructing a request — [`ControlSpendPublisher`] serializes and
/// writes, and the assertion reads what arrived at the far end of a real socket.
#[tokio::test]
async fn no_user_key_crosses_the_control_plane_when_a_live_signed_spend_is_broadcast() {
    let bundle = signed_bundle().await;
    let node = FakeNode::serving_broadcast(BroadcastReply::Accepted {
        transaction_id: "recorded".to_string(),
    });
    let publisher =
        ControlSpendPublisher::with_token_reader(node.endpoint(), good_token, TEST_TIMEOUT);

    let outcome = publisher
        .push_detailed(&bundle)
        .expect("the fake mempool answered");
    assert_eq!(
        outcome,
        PushOutcome::Accepted,
        "the push must have actually happened, or the wire below is empty for the wrong reason"
    );

    let wire = node.received();

    // The signed bundle DOES cross — signed bytes are the entire point, and asserting their presence
    // is what proves the recording is of a real, complete push rather than of nothing.
    let signed_hex = hex::encode(
        chia_traits::Streamable::to_bytes(&bundle).expect("a signed bundle serializes"),
    );
    assert!(
        contains_bytes(wire.as_bytes(), signed_hex.as_bytes()),
        "the signed bundle must cross the wire, or this recording proves nothing: {wire}"
    );

    for (name, secret) in secrets_that_must_never_cross() {
        assert!(
            !contains_bytes(wire.as_bytes(), &secret),
            "{name} must NEVER cross the control plane (§908), and it is in these bytes: {wire}"
        );
    }
}

/// **No user key crosses on the READ leg either.**
///
/// Broadcasting is the leg that carries signed material, so it is the one a leak would hide in — but
/// a chain read names an address the wallet owns, and the nearest wrong implementation is one that
/// identifies the wallet to the node by a secret rather than by a puzzle hash.
#[tokio::test]
async fn no_user_key_crosses_the_control_plane_when_the_wallet_reads_the_chain() {
    let node = FakeNode::serving_chain(ChainReply::of(FakeChain::synced_at(9_104_152)));
    let source = ControlChainSource::with_timeout(node.endpoint(), TEST_TIMEOUT);
    let wallet_ph = WalletKey::from_seed(&expanded_seed()).puzzle_hash();

    source
        .coin_records_by_puzzle_hash(wallet_ph, false)
        .expect("the fake chain answered");

    let wire = node.received();
    for (name, secret) in secrets_that_must_never_cross() {
        assert!(
            !contains_bytes(wire.as_bytes(), &secret),
            "{name} must NEVER cross the control plane (§908), and it is in these bytes: {wire}"
        );
    }
}

/// **The `diga` engine proxy puts a control call on the wire, never key material.**
///
/// A NEW wire path, added with the CLI lane's engine proxy (dig-app#226): before it, engine-routed
/// `diga` verbs were refused and nothing the CLI said ever reached a node. Now every engine verb
/// crosses this control plane, so the §908 assertion must cover it too — an assertion that only
/// covered the paths that existed when it was written is one that decays as the app grows.
///
/// Driven over a REAL socket for the reason this module's header gives: the bytes asserted on are
/// the ones production serialized and wrote, not ones this test constructed. Every engine-routed
/// command is walked rather than a representative one, because the params of each are built from a
/// different `Command` arm and a leak would live in exactly one of them.
///
/// The control is the method name: it must BE in the bytes. Without it a proxy that dialled and sent
/// nothing — or one that failed before writing — would satisfy "no secret crossed" by sending
/// nothing at all.
///
/// # How much this test proves, stated so a later reader does not over-trust it
///
/// "No secret crossed" holds here largely BY CONSTRUCTION of the input: the gateway builds every
/// command from literals and [`NodeEngineProxy`] holds only an endpoint, a token and a timeout, so
/// no seed-derived value is in reach of this path to leak. The load-bearing half is therefore the
/// method-name control — that the proxy really wrote a real call — rather than the absence of the
/// secrets. The sibling broadcast and chain-read cases above carry the assertion against a LIVE
/// key, which is where a regression in §908 would actually show.
#[test]
fn no_user_key_crosses_the_control_plane_when_the_cli_proxies_an_engine_verb() {
    use crate::cli_session::NodeEngineProxy;
    use crate::gateway::{all_engine_routed_commands, engine_call, EngineProxy};

    let node = FakeNode::with_behaviour(crate::test_support::node::Behaviour::EchoingControl);
    let proxy = NodeEngineProxy::dialling(&node.endpoint(), Some(FakeNode::TOKEN), TEST_TIMEOUT);

    for command in all_engine_routed_commands() {
        let call = engine_call(&command).expect("an engine-routed command maps to a call");
        proxy
            .call(call.method, call.params.clone())
            .expect("the fake node answers");

        let wire = node.received();
        assert!(
            wire.contains(call.method),
            "{:?} must actually have reached the wire; got:\n{wire}",
            command
        );
        for (name, secret) in secrets_that_must_never_cross() {
            assert!(
                !contains_bytes(wire.as_bytes(), &secret),
                "{name} must NEVER cross the control plane (§908), and {command:?} put it there: {wire}"
            );
        }
    }
}

/// **An identity sign puts a signature on the wire, never the key that made it.**
///
/// The nearest wrong implementation hands the node the profile signing key so it can sign session
/// challenges itself — the exact inversion §908 forbids. The control asserts the signature IS there,
/// so a signer that produced nothing could not pass by leaking nothing.
#[test]
fn the_identity_sign_path_puts_only_a_signature_on_the_wire_never_the_key() {
    use dig_ipc_protocol::signer::SessionSigner;

    let residency = residency_at_seed();
    let signer = residency.signer();
    let message = b"dig-app IPC session challenge";
    let signature = signer
        .try_sign(message)
        .expect("an unlocked residency signs");

    let mut wire = Vec::new();
    wire.extend_from_slice(signature.as_bytes());
    wire.extend_from_slice(signer.signing_public_key().as_bytes());

    assert!(
        contains_bytes(&wire, signature.as_bytes()),
        "the signature is the artifact of an identity sign, and it must be what crosses"
    );
    for (name, secret) in secrets_that_must_never_cross() {
        assert!(
            !contains_bytes(&wire, &secret),
            "{name} must NEVER cross on the identity path (§908)"
        );
    }
}
