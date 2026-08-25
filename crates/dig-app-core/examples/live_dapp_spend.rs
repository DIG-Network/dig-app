//! Drive a REAL `spend.request` against the running dig-app, as an outside application would
//! (`SPEC.md` §5.6.9, dig_ecosystem#1552).
//!
//! This is the WU5 acceptance harness. It exists so that the only thing a person has to do to see
//! the money boundary work end to end is: generate a pairing code in the DIG App, run one command,
//! read the confirm window, and approve it. Everything else — the WebSocket upgrade, pairing,
//! connecting, coin selection, building the unsigned bundle — happens here.
//!
//! # What this proves that a test cannot
//!
//! A unit test can prove the router refuses the wrong things and calls the right seam. It cannot
//! prove that a person is shown the real recipient and the real amount, that the signature dig-app
//! produces is accepted by a mainnet mempool, or that those two agree. Only a real run does that,
//! and the screenshot of the confirm window is the acceptance — never a green suite.
//!
//! # Safety
//!
//! - **Every value is an argument; nothing is defaulted.** There is no hard-coded recipient and no
//!   hard-coded amount, because a default here is a way to send real money somewhere unintended.
//! - **The human is the last gate and sees the recipient before approving.** This harness is
//!   deliberately unable to approve anything.
//! - **Nothing secret is read, derived, printed or held.** The sender is named by its PUBLIC key,
//!   addresses are public bech32m, and the private key never leaves dig-app: this process hands over
//!   an UNSIGNED bundle and receives a signed one (dig_ecosystem#908).
//! - This is mainnet. The amount passed will actually leave, plus the fee.
//!
//! # Why it sends no `Origin` header
//!
//! §5.6.2's admission rule takes a browser-extension `Origin`, or NO `Origin` at all — a browser
//! never omits it, so its absence is exactly what distinguishes a desktop tool from a web page. This
//! is a desktop tool, so it omits the header rather than inventing an extension id it does not have.
//!
//! # Usage
//!
//! ```text
//! # In the DIG App: Paired apps -> Pair an app -> copy the 8-character code.
//! cargo run --example live_dapp_spend -- \
//!     <PAIRING_CODE> <SENDER_PUBKEY_HEX> <RECIPIENT_xch1...> <AMOUNT_MOJOS> <FEE_MOJOS> [--broadcast]
//! ```
//!
//! `SENDER_PUBKEY_HEX` is the 48-byte G1 wallet key whose address holds the coins — public data,
//! printable with `dign wallet watched`. Without `--broadcast` the app signs and pushes NOTHING,
//! which is the safe way to see the whole path before letting any money move.

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine as _;
use chia_protocol::{Bytes32, Coin, SpendBundle};
use chia_traits::Streamable as _;
use futures_util::{SinkExt as _, StreamExt as _};
use serde_json::{json, Value};
use tokio_tungstenite::tungstenite::client::IntoClientRequest as _;
use tokio_tungstenite::tungstenite::http::header::ORIGIN;
use tokio_tungstenite::tungstenite::Message;

/// The canonical dig-app identity loopback port (§5.6.2).
const PORT: u16 = 9779;

/// What this harness calls itself. Untrusted by the app, and shown beside the pairing code.
const APP_ID: &str = "net.dig.example.live-dapp-spend";

/// The dapp origin this harness vouches for — the value in the `params`, NOT the WS upgrade header.
const ORIGIN_VOUCHED: &str = "https://live-dapp-spend.example";

#[tokio::main(flavor = "current_thread")]
async fn main() {
    let mut args = std::env::args().skip(1);
    let parsed = (
        args.next(),
        args.next(),
        args.next(),
        args.next(),
        args.next(),
    );
    let (code, sender_pubkey, recipient, amount, fee) = match parsed {
        (Some(a), Some(b), Some(c), Some(d), Some(e)) => (a, b, c, d, e),
        _ => {
            eprintln!(
                "usage: live_dapp_spend <PAIRING_CODE> <SENDER_PUBKEY_HEX> <RECIPIENT_xch1...> \
                 <AMOUNT_MOJOS> <FEE_MOJOS> [--broadcast]"
            );
            eprintln!();
            eprintln!("Generate the pairing code in the DIG App: Paired apps -> Pair an app.");
            eprintln!("Find the sender public key with: dign wallet watched");
            std::process::exit(2);
        }
    };
    let broadcast = args.any(|a| a == "--broadcast");
    let amount: u64 = amount.parse().expect("AMOUNT_MOJOS must be a whole number");
    let fee: u64 = fee.parse().expect("FEE_MOJOS must be a whole number");

    let mut wire = Wire::connect().await;
    println!("connected to the APP-SIGN channel on {PORT}");

    // 1. Pair, asking for the money capability BY NAME. The app raises a confirm window that says
    //    payments are being granted; a pairing that does not ask is refused at step 4.
    let paired = wire
        .call(
            "pair.begin",
            json!({
                "ext_id": APP_ID,
                "ext_label": "Live dapp-spend harness",
                "requested_at": now_secs(),
                "requested_capabilities": ["spend.request"],
                "pairing_code": code,
            }),
            None,
        )
        .await;
    let pairing_id = paired["pairing_id"]
        .as_str()
        .expect("a pairing id")
        .to_string();
    let token = paired["channel_token_b64"]
        .as_str()
        .expect("a channel token")
        .to_string();
    println!("paired            {pairing_id}");
    println!("granted           {}", paired["granted_capabilities"]);
    assert!(
        paired["granted_capabilities"]
            .as_array()
            .is_some_and(|caps| caps.iter().any(|c| c == "spend.request")),
        "the app did not grant spend.request, so the spend below cannot be permitted"
    );

    let mut auth = Authed::new(pairing_id, token);

    // 2. Connect the origin. The spend gate checks this FIRST, and again after the re-auth.
    let connected = wire
        .call(
            "connect.request",
            json!({ "origin": ORIGIN_VOUCHED }),
            Some(&mut auth),
        )
        .await;
    println!("connected origin  {}", connected["granted"]);

    // 3. Build the UNSIGNED bundle, exactly as an outside application does. No private key is
    //    involved, and none is reachable from this process.
    let sender = wallet_key(&sender_pubkey);
    let coin = select_coin(sender.puzzle_hash, amount + fee);
    println!(
        "spending coin     {} ({} mojos)",
        hex::encode(coin.coin_id()),
        coin.amount
    );
    let unsigned = build_unsigned(&sender, coin, &recipient, amount, fee);

    println!();
    println!("The DIG App is about to ask. Read the window: it must name");
    println!("  recipient  {recipient}");
    println!("  amount     {amount} mojos");
    println!("Approve it ONLY if those are what you expect.");
    println!();

    // 4. The money boundary itself.
    let result = wire
        .call(
            "spend.request",
            json!({
                "origin": ORIGIN_VOUCHED,
                "payload_type": "spend",
                "payload_b64": BASE64.encode(unsigned.to_bytes().expect("a streamable bundle")),
                "broadcast": broadcast,
            }),
            Some(&mut auth),
        )
        .await;

    println!("bundle_id         {}", result["bundle_id"]);
    println!("push              {}", result["push"]);
    println!(
        "signed bundle     {} base64 chars",
        result["bundle_b64"].as_str().map_or(0, str::len)
    );
    match result["push"].as_str() {
        Some("pending") => println!(
            "\nA mempool ACCEPTED it. That is an acceptance, not a confirmation - watch the coin \
             on chain to see it settle."
        ),
        Some("unknown") => println!(
            "\nThe push was not answered. It MAY be in a mempool: do NOT rebuild and resend, or the \
             recipient can be paid twice."
        ),
        Some("not_broadcast") => println!("\nNo mempool holds this bundle."),
        _ => {}
    }
}

/// The sender's public wallet key and the address it spends from.
struct WalletKey {
    public_key: chia_bls::PublicKey,
    puzzle_hash: Bytes32,
}

/// Read a 48-byte G1 public key and derive the standard-p2 address it spends from.
///
/// Public data only. A public key cannot sign, which is the point: this process builds a bundle it is
/// structurally unable to authorize.
fn wallet_key(hex_pubkey: &str) -> WalletKey {
    let bytes: [u8; 48] = hex::decode(hex_pubkey)
        .expect("SENDER_PUBKEY_HEX must be hex")
        .try_into()
        .expect("a 48-byte G1 public key");
    let public_key = chia_bls::PublicKey::from_bytes(&bytes).expect("a valid G1 public key");
    let puzzle_hash = chia_puzzle_types::standard::StandardArgs::curry_tree_hash(public_key).into();
    WalletKey {
        public_key,
        puzzle_hash,
    }
}

/// Pick one unspent coin at `puzzle_hash` that covers `needed`.
///
/// Deliberately the simplest selection that can work — one coin, no aggregation. A harness that
/// re-implemented the wallet's coin selection would be a second implementation of something the app
/// already owns, and any difference between them would be a bug nobody could see.
fn select_coin(puzzle_hash: Bytes32, needed: u64) -> Coin {
    use dig_chainsource_interface::ChainSource as _;

    let endpoint =
        std::env::var("DIG_NODE_URL").unwrap_or_else(|_| "http://localhost:4161".to_string());
    let chain = dig_app_core::chain::ControlChainSource::new(&endpoint);
    chain
        .coin_records_by_puzzle_hash(puzzle_hash, false)
        .unwrap_or_else(|e| panic!("could not read coins at the sender's address: {e}"))
        .into_iter()
        .map(|record| record.coin)
        .find(|coin| coin.amount >= needed)
        .unwrap_or_else(|| {
            panic!(
                "no single unspent coin at the sender's address covers {needed} mojos; \
                 this harness deliberately does not aggregate"
            )
        })
}

/// Build the unsigned coin spend: pay the recipient, return the change to the sender.
///
/// Built with the canonical `chia-wallet-sdk` driver, never hand-rolled CLVM — CLAUDE.md §4.1 forbids
/// a consumer hand-rolling spend bundles, and this harness is a consumer.
fn build_unsigned(
    sender: &WalletKey,
    coin: Coin,
    recipient: &str,
    amount: u64,
    fee: u64,
) -> SpendBundle {
    use chia_wallet_sdk::driver::{SpendContext, StandardLayer};
    use chia_wallet_sdk::types::Conditions;

    let recipient_hash: Bytes32 = chia_wallet_sdk::utils::Address::decode(recipient)
        .expect("RECIPIENT must be a bech32m xch1 address")
        .puzzle_hash;
    let change = coin
        .amount
        .checked_sub(amount + fee)
        .expect("the selected coin must cover the amount and the fee");

    let mut conditions = Conditions::new()
        .create_coin(recipient_hash, amount, chia_puzzle_types::Memos::None)
        .reserve_fee(fee);
    // A zero-amount change coin is a real coin worth nothing, so it is created only when there IS
    // change; otherwise the remainder would have to go somewhere, and it goes to the fee.
    if change > 0 {
        conditions =
            conditions.create_coin(sender.puzzle_hash, change, chia_puzzle_types::Memos::None);
    }

    let mut ctx = SpendContext::new();
    StandardLayer::new(sender.public_key)
        .spend(&mut ctx, coin, conditions)
        .expect("a standard-p2 spend");

    SpendBundle::new(
        ctx.take(),
        // UNSIGNED. dig-app produces the aggregate signature; whatever is supplied here is DISCARDED
        // by the router, so a caller can neither contribute to nor pin any part of it.
        chia_bls::Signature::default(),
    )
}

/// A JSON-RPC conversation over the loopback WebSocket.
struct Wire {
    ws: tokio_tungstenite::WebSocketStream<tokio::net::TcpStream>,
    id: u64,
}

impl Wire {
    /// Dial the channel and complete the upgrade, sending NO `Origin` (see the module docs).
    async fn connect() -> Self {
        let mut request = format!("ws://127.0.0.1:{PORT}/")
            .into_client_request()
            .expect("a well-formed ws URL");
        request.headers_mut().remove(ORIGIN);

        let stream = tokio::net::TcpStream::connect(("127.0.0.1", PORT))
            .await
            .unwrap_or_else(|e| panic!("the DIG App is not answering on {PORT}: {e}"));
        let (ws, _) = tokio_tungstenite::client_async(request, stream)
            .await
            .unwrap_or_else(|e| panic!("the APP-SIGN upgrade was refused: {e}"));
        Self { ws, id: 0 }
    }

    /// Send one request and return its `result`, failing loudly with the wire symbol on an error.
    ///
    /// Text frames that are not the answer are skipped rather than treated as one: the channel is
    /// bidirectional and dig-app pushes the async confirm outcome on the same socket.
    async fn call(&mut self, method: &str, params: Value, auth: Option<&mut Authed>) -> Value {
        self.id += 1;
        let mut frame = json!({
            "jsonrpc": "2.0",
            "id": self.id,
            "method": method,
            "params": params,
        });
        if let Some(auth) = auth {
            frame["auth"] = auth.sign(method, &frame["params"]);
        }

        self.ws
            .send(Message::Text(frame.to_string()))
            .await
            .expect("the channel accepts a frame");

        loop {
            let message = self
                .ws
                .next()
                .await
                .expect("the channel stays open")
                .expect("a readable frame");
            let Message::Text(text) = message else {
                continue;
            };
            let response: Value = serde_json::from_str(&text).expect("a JSON-RPC response");
            if response["id"] != json!(self.id) {
                continue;
            }
            if let Some(error) = response.get("error").filter(|e| !e.is_null()) {
                panic!("{method} was refused: {error}");
            }
            return response["result"].clone();
        }
    }
}

/// The pairing credential and its strictly-increasing nonce.
struct Authed {
    pairing_id: String,
    token: Vec<u8>,
    nonce: u64,
}

impl Authed {
    fn new(pairing_id: String, token_b64: String) -> Self {
        Self {
            pairing_id,
            token: BASE64.decode(token_b64).expect("a base64 channel token"),
            nonce: 0,
        }
    }

    /// The per-frame MAC the app verifies before dispatch.
    ///
    /// The MAC INPUT comes from `dig_app_core::pairing::frame_mac_input` — the app's own function —
    /// rather than being re-derived here. A first draft concatenated the three fields directly and
    /// was silently wrong: the real input separates them with `0x00` bytes and canonicalises the
    /// params JSON, so every frame would have failed `AUTH_BAD_MAC` in a way that reads like a broken
    /// pairing. A harness that re-implements the thing it is exercising only tests its own copy.
    fn sign(&mut self, method: &str, params: &Value) -> Value {
        use hmac::{Hmac, Mac};
        use sha2::Sha256;

        self.nonce += 1;
        let mut mac = <Hmac<Sha256>>::new_from_slice(&self.token).expect("any key length");
        mac.update(&dig_app_core::pairing::frame_mac_input(
            self.nonce, method, params,
        ));
        json!({
            "pairing_id": self.pairing_id,
            "nonce": self.nonce,
            "mac_b64": BASE64.encode(mac.finalize().into_bytes()),
        })
    }
}

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("a clock after 1970")
        .as_secs()
}
