//! Shared test doubles for the master-HD custody path (test-only).
//!
//! The custody path is the master-HD
//! [`AccountResidency`](crate::account::residency::AccountResidency), so these helpers give every test
//! module ONE way to build the two seams the loopback/pairing/whitelist/wallet stores depend on:
//!
//! - [`test_sealer`] — a cheap-KDF [`AccountSealer`] at a deterministic per-label DEK. Two sealers
//!   built from the SAME label share a DEK (so a "restart" round-trips a sealed blob); DISTINCT labels
//!   derive DISTINCT DEKs, which is exactly the model's cross-profile isolation (isolation rests on the
//!   DEK, not on the advisory DID argument — see [`crate::account::sealer`]).
//! - [`test_residency`] — a freshly-enrolled, unlocked residency; call `.signer(ProfileIx::ROOT)` for
//!   its live-view [`SessionSigner`], which fails closed the instant the residency is locked
//!   ([`lock_all`](crate::session_lock::SessionKeys::lock_all)).

use std::sync::{Arc, Mutex};

use dig_account::{AccountId, AccountSession, AccountStore, ProfileIx};
use dig_keystore::{KdfParams, MemoryBackend};
use dig_session::{Password, ENTROPY_LEN};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::account::residency::AccountResidency;
use crate::account::sealer::AccountSealer;
use crate::sealer::{ProfileSealer, SealError};

/// A keyed-prefix [`ProfileSealer`] double, shared by every vault-level test (the recovery-phrase
/// vault, the second-factor vault, the second-factor journey).
///
/// It is deliberately reversible-but-keyed: prefixing the profile DID means opening under a DIFFERENT
/// DID fails exactly where a real DEK mismatch would, so cross-profile isolation is exercised for real
/// rather than assumed. It can also be driven into a LOCKED state, because "the account locked
/// mid-operation" is a state the vaults must fail closed on and a sealer that could only ever succeed
/// could never express it. A test that never calls [`lock`](FakeSealer::lock) sees a plain,
/// always-open keyed sealer.
#[derive(Default)]
pub struct FakeSealer {
    locked: Mutex<bool>,
}

impl FakeSealer {
    /// Drive the sealer closed, so every subsequent seal/open fails as a locked account would.
    pub fn lock(&self) {
        *self.locked.lock().unwrap() = true;
    }
}

impl ProfileSealer for FakeSealer {
    fn seal(&self, profile_did: &str, plaintext: &[u8]) -> Result<Vec<u8>, SealError> {
        if *self.locked.lock().unwrap() {
            return Err(SealError::Seal("locked".into()));
        }
        let mut out = format!("{profile_did}|").into_bytes();
        out.extend_from_slice(plaintext);
        Ok(out)
    }

    fn open(&self, profile_did: &str, ciphertext: &[u8]) -> Result<Zeroizing<Vec<u8>>, SealError> {
        if *self.locked.lock().unwrap() {
            return Err(SealError::Open);
        }
        let prefix = format!("{profile_did}|").into_bytes();
        ciphertext
            .strip_prefix(&prefix[..])
            .map(|rest| Zeroizing::new(rest.to_vec()))
            .ok_or(SealError::Open)
    }
}

/// A cheap-KDF [`AccountSealer`] bound to a DEK deterministically derived from `label`. Same label →
/// same DEK (a persisted blob re-opens across a simulated restart); different label → different DEK
/// (cross-profile isolation, cryptographically enforced by the AEAD tag).
pub fn test_sealer(label: &str) -> AccountSealer {
    let dek: [u8; 32] = Sha256::digest(label.as_bytes()).into();
    AccountSealer::with_kdf(dek, KdfParams::FAST_TEST)
}

/// A freshly-enrolled, unlocked master-HD residency over a random seed. Cheap (an in-memory keystore
/// backend); each call is an independent account with its own key material.
pub fn test_residency() -> AccountResidency {
    use rand_core::RngCore;
    let mut seed = [0u8; ENTROPY_LEN];
    rand_core::OsRng.fill_bytes(&mut seed);
    let store = Arc::new(AccountStore::new(Arc::new(MemoryBackend::new())));
    let unlocked = AccountSession::enroll(
        store,
        AccountId::new("test-account"),
        Password::new("pw"),
        &seed,
        ProfileIx::ROOT,
    )
    .expect("enrol a fresh test account");
    AccountResidency::new(unlocked)
}

/// A FAKE dig-node control plane, served over a real loopback TCP socket.
///
/// The connector under test is a transport, so its tests must exercise a transport: this stands up
/// an actual [`TcpListener`](std::net::TcpListener), speaks real HTTP/1.1 back, and replies with the
/// real JSON shape `dig-node`'s `control.rs::status` emits. A double that shared a helper with the
/// client — or wrote into a discarding sink — could pass while the bytes on the wire were wrong.
pub mod node {
    use std::io::{Read, Write};
    use std::net::{SocketAddr, TcpListener};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::mpsc;
    use std::sync::Arc;
    use std::thread::JoinHandle;
    use std::time::Duration;

    use dig_node_control_interface::method::ControlMethod;

    use crate::control::CONTROL_TOKEN_HEADER;

    /// How a [`FakeNode`] should answer the requests it accepts.
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub enum Behaviour {
        /// Reply `200` with a `control.status` result — a healthy, authorized node.
        Status,
        /// Reply `200` with a JSON-RPC `error` — what an unauthorized/refused call looks like.
        JsonRpcError(String),
        /// Reply with an HTTP status and body — e.g. the `401` an unknown token draws.
        Http(u16, String),
        /// Accept the connection and close it without replying — a node that is up but mute.
        Silent,
        /// A healthy node that also answers `control.wallet.balance` per the given [`WalletReply`],
        /// serving it as the OPEN read a real node does (dig_ecosystem#1851) while every other
        /// method stays behind the control token.
        Wallet(WalletReply),
        /// A healthy node that answers exactly like [`Wallet`](Self::Wallet), but only after
        /// `delay` — the live node's actual behaviour on a real chain read (dig_ecosystem#2325).
        ///
        /// The delay is the ONE knob, deliberately: raised past the client's budget it is a node
        /// that is up, connected, and simply late; kept under the budget it is the ordinary slow
        /// read that must still yield a figure. A fixture that only ever closed the socket (as
        /// [`Silent`](Self::Silent) does) could not tell those two apart, because in both cases the
        /// client would merely see "no answer".
        SlowWallet {
            /// The answer eventually given.
            reply: WalletReply,
            /// How long the node takes to give it.
            delay: Duration,
        },
        /// A healthy node that also answers `control.wallet.coins` per the given [`CoinsReply`],
        /// serving it as the OPEN read the 0.6.0 contract declares it (dig_ecosystem#2378).
        WalletCoins(CoinsReply),
        /// A healthy node that also answers `control.wallet.broadcast` per the given
        /// [`BroadcastReply`].
        ///
        /// Unlike the two wallet READS this stays behind the control token, because the contract
        /// says so ([`ControlMethod::is_open_read`] is false for it) — and the fake derives that
        /// from the contract rather than from its own list, so a push served tokenless here would
        /// be a contract change and not a fixture liberty.
        WalletBroadcast(BroadcastReply),
        /// A healthy node that also answers `control.hostedStores.list` per the given
        /// [`StoresReply`] (dig_ecosystem#2330).
        ///
        /// Unlike the wallet read this stays BEHIND the control token, exactly as the real node
        /// gates it — so a client that forgot the header sees the `401` it would really get, and
        /// "the node would not tell this app" stays a distinguishable outcome rather than
        /// collapsing into "no stores".
        HostedStores(StoresReply),
        /// [`HostedStores`](Self::HostedStores), answered only after `delay` — a node that is up,
        /// authorized, and simply slow (the shape dig_ecosystem#2325 was mistaken for an absent
        /// node).
        SlowHostedStores {
            /// The answer eventually given.
            reply: StoresReply,
            /// How long the node takes to give it.
            delay: Duration,
        },
    }

    /// How a [`FakeNode`] should answer `control.hostedStores.list`.
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub enum StoresReply {
        /// Answer with these stores, in this order.
        Stores(Vec<FakeStore>),
        /// Refuse, in the node's error envelope: a numeric wire code plus the stable UPPER_SNAKE
        /// `data.code` symbol a client is contractually required to branch on.
        Rejected {
            /// The numeric JSON-RPC error code.
            code: i64,
            /// The stable `data.code` symbol.
            symbol: String,
        },
    }

    impl StoresReply {
        /// A refusal carrying `code` + its stable `symbol`.
        pub fn rejected(code: i64, symbol: &str) -> Self {
            StoresReply::Rejected {
                code,
                symbol: symbol.to_string(),
            }
        }
    }

    /// One store a [`FakeNode`] reports from `control.hostedStores.list`.
    ///
    /// It carries `capsule_count` rather than a capsule list because the fixture GENERATES that many
    /// capsule entries into the wire body: the real node's `capsules` array is a field dig-app
    /// deliberately drops, and a fixture that sent an empty array could not prove the drop was a
    /// decision rather than an accident of the fixture.
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct FakeStore {
        /// The canonical lowercase 64-hex store id.
        pub store_id: String,
        /// Whether the operator has pinned this store.
        pub pinned: bool,
        /// How many cached capsules of this store the node reports.
        pub capsule_count: u64,
        /// The total cached bytes across those capsules.
        pub total_bytes: u64,
    }

    /// How a [`FakeNode`] should answer `control.wallet.balance`.
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub enum WalletReply {
        /// Answer with per-asset figures and the node's own view of whether they are current.
        ///
        /// The two amounts are separate so a fixture can distinguish an implementation that reads
        /// each asset from one that reads a single figure and reuses it.
        Balance {
            /// The XCH balance in mojos.
            xch: u64,
            /// The DIG balance in base units.
            dig: u64,
            /// The node's `synced` flag: `false` means the figures are STALE.
            synced: bool,
        },
        /// Refuse, exactly as the node's error envelope does: a numeric wire code plus the stable
        /// UPPER_SNAKE `data.code` symbol a client is contractually required to branch on.
        Rejected {
            /// The numeric JSON-RPC error code.
            code: i64,
            /// The stable `data.code` symbol.
            symbol: String,
        },
    }

    impl WalletReply {
        /// A refusal carrying `code` + its stable `symbol`.
        pub fn rejected(code: i64, symbol: &str) -> Self {
            WalletReply::Rejected {
                code,
                symbol: symbol.to_string(),
            }
        }
    }

    /// How a [`FakeNode`] should answer `control.wallet.coins`.
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub enum CoinsReply {
        /// Answer with these coins. An EMPTY vector is a real answer — "the node consulted a chain
        /// and this address holds nothing" — and the contract is explicit that it is never what a
        /// caller gets from an unreachable chain.
        Coins(Vec<FakeCoin>),
        /// Refuse, in the node's error envelope: a numeric wire code plus the stable UPPER_SNAKE
        /// `data.code` symbol a client is contractually required to branch on.
        Rejected {
            /// The numeric JSON-RPC error code.
            code: i64,
            /// The stable `data.code` symbol.
            symbol: String,
        },
    }

    impl CoinsReply {
        /// A refusal carrying `code` + its stable `symbol`.
        pub fn rejected(code: i64, symbol: &str) -> Self {
            CoinsReply::Rejected {
                code,
                symbol: symbol.to_string(),
            }
        }
    }

    /// One coin a [`FakeNode`] reports from `control.wallet.coins`.
    ///
    /// It carries ALL SEVEN fields the 0.6.0 contract defines, including the four dig-app's own
    /// `CoinRecord` drops. That is deliberate: the contract calls the adoption a lossless
    /// deserialization of a SUPERSET, and a fixture that sent only the three fields dig-app keeps
    /// could not tell a client that tolerates the extra fields from one that would reject them.
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct FakeCoin {
        /// The coin id, lowercase 64-hex.
        pub coin_id: String,
        /// `"xch"` or `"dig"` — the asset token exactly as it travels.
        pub asset: &'static str,
        /// The amount in the asset's base unit.
        pub amount: u64,
        /// The parent coin's id, lowercase 64-hex.
        pub parent_coin_info: String,
        /// The coin's puzzle hash, lowercase 64-hex.
        pub puzzle_hash: String,
        /// The height the coin was created at, or `None` while it is only in the mempool.
        pub created_height: Option<u32>,
        /// The height the coin was spent at, or `None` when unspent.
        pub spent_height: Option<u32>,
    }

    impl FakeCoin {
        /// A confirmed, unspent coin of `amount` in `asset`, with distinct filler ids.
        ///
        /// The three 32-byte ids are derived from `amount` and differ from one another, so a client
        /// that read the puzzle hash where it meant the coin id cannot pass.
        pub fn confirmed(asset: &'static str, amount: u64) -> Self {
            Self {
                coin_id: format!("{:064x}", amount),
                asset,
                amount,
                parent_coin_info: format!("{:064x}", amount + 1),
                puzzle_hash: format!("{:064x}", amount + 2),
                created_height: Some(5_412_000),
                spent_height: None,
            }
        }
    }

    /// How a [`FakeNode`] should answer `control.wallet.broadcast`.
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub enum BroadcastReply {
        /// The mempool took the bundle, and named it.
        Accepted {
            /// The transaction id the node reports.
            transaction_id: String,
        },
        /// The mempool LOOKED at the bundle and said no. A successful call carrying a refusal —
        /// not an error, because the bundle was seen and judged.
        RefusedByMempool {
            /// Why the mempool refused.
            reason: String,
        },
        /// The call itself failed, in the node's error envelope.
        Rejected {
            /// The numeric JSON-RPC error code.
            code: i64,
            /// The stable `data.code` symbol.
            symbol: String,
        },
    }

    impl BroadcastReply {
        /// A refusal carrying `code` + its stable `symbol`.
        pub fn rejected(code: i64, symbol: &str) -> Self {
            BroadcastReply::Rejected {
                code,
                symbol: symbol.to_string(),
            }
        }
    }

    /// A fake control plane on loopback, serving requests until dropped (dropping it joins the
    /// server thread).
    pub struct FakeNode {
        addr: SocketAddr,
        token: String,
        requests: mpsc::Receiver<String>,
        served: Arc<AtomicUsize>,
        server: Option<JoinHandle<()>>,
    }

    impl FakeNode {
        /// The node version this fake reports, so a test can assert the value travelled rather than
        /// that *some* string arrived.
        pub const VERSION: &'static str = "0.64.0";

        /// The token this fake accepts. A request without it draws the `401` a real node would send.
        pub const TOKEN: &'static str = "f00dcafe";

        /// A fake that answers `control.status` like a healthy node.
        pub fn serving_status() -> Self {
            Self::with_behaviour(Behaviour::Status)
        }

        /// A fake that answers `control.status` like a healthy node AND `control.wallet.balance`
        /// with `reply`.
        pub fn serving_wallet(reply: WalletReply) -> Self {
            Self::with_behaviour(Behaviour::Wallet(reply))
        }

        /// A fake that answers `control.wallet.balance` with `reply`, but only after `delay`.
        pub fn serving_wallet_slowly(reply: WalletReply, delay: Duration) -> Self {
            Self::with_behaviour(Behaviour::SlowWallet { reply, delay })
        }

        /// A fake that answers `control.wallet.coins` with `reply` (dig_ecosystem#2378).
        pub fn serving_coins(reply: CoinsReply) -> Self {
            Self::with_behaviour(Behaviour::WalletCoins(reply))
        }

        /// A fake that answers `control.wallet.broadcast` with `reply` (dig_ecosystem#2378).
        pub fn serving_broadcast(reply: BroadcastReply) -> Self {
            Self::with_behaviour(Behaviour::WalletBroadcast(reply))
        }

        /// A fake that answers `control.hostedStores.list` with `reply` (dig_ecosystem#2330).
        pub fn serving_stores(reply: StoresReply) -> Self {
            Self::with_behaviour(Behaviour::HostedStores(reply))
        }

        /// A fake that answers `control.hostedStores.list` with `reply`, but only after `delay`.
        pub fn serving_stores_slowly(reply: StoresReply, delay: Duration) -> Self {
            Self::with_behaviour(Behaviour::SlowHostedStores { reply, delay })
        }

        /// A fake with an explicit [`Behaviour`], bound to an ephemeral loopback port.
        pub fn with_behaviour(behaviour: Behaviour) -> Self {
            let listener = TcpListener::bind(("127.0.0.1", 0)).expect("bind loopback");
            let addr = listener.local_addr().expect("local addr");
            let (tx, requests) = mpsc::channel();
            let served = Arc::new(AtomicUsize::new(0));
            let counter = Arc::clone(&served);
            let server = std::thread::spawn(move || serve(listener, behaviour, tx, counter));
            Self {
                addr,
                token: Self::TOKEN.to_string(),
                requests,
                served,
                server: Some(server),
            }
        }

        /// How many requests the fake has actually served.
        ///
        /// Counted at the SERVER so a test can prove a call did — or did not — reach the wire,
        /// rather than trusting the client's own account of what it sent.
        pub fn request_count(&self) -> usize {
            self.served.load(Ordering::SeqCst)
        }

        /// The `http://…` endpoint a client should dial.
        pub fn endpoint(&self) -> String {
            format!("http://{}", self.addr)
        }

        /// The token this fake authorizes.
        pub fn token(&self) -> &str {
            &self.token
        }

        /// The raw request text the fake received, so a test can assert what actually went out on
        /// the wire (the method name, the token header) rather than trusting the client's own view.
        pub fn received(&self) -> String {
            self.requests
                .recv_timeout(std::time::Duration::from_secs(5))
                .expect("the fake node received no request")
        }
    }

    impl Drop for FakeNode {
        fn drop(&mut self) {
            if let Some(server) = self.server.take() {
                // The server thread is parked in a BLOCKING `accept`, so a fake that no test ever
                // dialled would never return and the join would hang the test run forever — a hang
                // is a far worse failure than an assertion, because it reports nothing. Poke the
                // listener with a throwaway connection so `accept` returns and the thread finishes.
                let _ = std::net::TcpStream::connect(self.addr);
                let _ = server.join();
            }
        }
    }

    /// Serve connections until the listener is closed or a caller connects without sending anything
    /// (which is how [`FakeNode::drop`] unblocks the accept).
    ///
    /// Serving repeatedly rather than once is what lets a test drive a client that makes more than
    /// one call — a balance read asks per asset, so a one-shot fake could only ever prove half of it.
    fn serve(
        listener: TcpListener,
        behaviour: Behaviour,
        tx: mpsc::Sender<String>,
        served: Arc<AtomicUsize>,
    ) {
        while let Ok((mut stream, _)) = listener.accept() {
            let request = read_request(&mut stream);
            // The wake-up poke from `Drop` sends no bytes; anything else is a real request.
            if request.trim().is_empty() {
                return;
            }
            served.fetch_add(1, Ordering::SeqCst);
            let authorized = request
                .to_lowercase()
                .contains(&format!("{}: {}", CONTROL_TOKEN_HEADER, FakeNode::TOKEN).to_lowercase());
            // Which method was asked for, and whether the CONTRACT says it needs no token. Taken
            // from `ControlMethod` rather than from a list kept here, so the fake cannot serve
            // tokenless something the real node gates -- the trap that would let a client which
            // never learned to present its token pass a push test.
            let method = requested_method(&request);
            let method_is_open_read = method.is_some_and(ControlMethod::is_open_read);
            let is = |wanted: ControlMethod| method == Some(wanted);
            let method_is_balance = is(ControlMethod::WalletBalance);
            let method_is_coins = is(ControlMethod::WalletCoins);
            let method_is_broadcast = is(ControlMethod::WalletBroadcast);
            let method_is_hosted_list = is(ControlMethod::HostedStoresList);
            let asset = if request.contains("\"asset\":\"dig\"") {
                Asset::Dig
            } else {
                Asset::Xch
            };
            let _ = tx.send(request);

            let (code, body) = match &behaviour {
                Behaviour::Silent => return,
                // `control.wallet.balance` is an OPEN read on every node build that has it, so the
                // fake must serve it without a token — otherwise a client that never learned to work
                // tokenless would still pass.
                Behaviour::Wallet(reply) if method_is_balance => (200, wallet_result(reply, asset)),
                Behaviour::SlowWallet { reply, .. } if method_is_balance => {
                    (200, wallet_result(reply, asset))
                }
                // `control.wallet.coins` is the other OPEN wallet read, served tokenless for the
                // same reason the balance is.
                Behaviour::WalletCoins(reply) if method_is_coins && method_is_open_read => {
                    (200, coins_result(reply))
                }
                // Every other `control.*` method is gated exactly as the real node gates it,
                // otherwise a client that forgot the header would still see a green test.
                _ if !authorized => (401, "401: unauthorized control request".to_string()),
                // Authorized, and asking for the hosted-store list: answer it. Any OTHER method
                // falls through to the status body below, so a fake set up for stores still
                // supports a client that probes `control.status` first.
                // Authorized, and pushing: the token gate above is what this arm sits behind, so a
                // client that presented no token never reaches it.
                Behaviour::WalletBroadcast(reply) if method_is_broadcast => {
                    (200, broadcast_result(reply))
                }
                Behaviour::HostedStores(reply) if method_is_hosted_list => {
                    (200, stores_result(reply))
                }
                Behaviour::SlowHostedStores { reply, .. } if method_is_hosted_list => {
                    (200, stores_result(reply))
                }
                Behaviour::Status
                | Behaviour::Wallet(_)
                | Behaviour::SlowWallet { .. }
                | Behaviour::WalletCoins(_)
                | Behaviour::WalletBroadcast(_)
                | Behaviour::HostedStores(_)
                | Behaviour::SlowHostedStores { .. } => (200, status_result()),
                Behaviour::JsonRpcError(message) => (200, json_rpc_error(message)),
                Behaviour::Http(code, body) => (*code, body.clone()),
            };
            // Up, authorized, and simply LATE. The sleep happens after the request is read and
            // before the reply is written, so the client sees a connection that succeeded and a
            // read that did not finish -- precisely the state dig_ecosystem#2325 mistook for a
            // missing node.
            match &behaviour {
                Behaviour::SlowWallet { delay, .. } | Behaviour::SlowHostedStores { delay, .. } => {
                    std::thread::sleep(*delay)
                }
                _ => {}
            }
            let _ = write!(
                stream,
                "HTTP/1.1 {code} X\r\nContent-Type: application/json\r\n\
                 Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
            let _ = stream.flush();
        }
    }

    /// Which asset a balance request named.
    #[derive(Clone, Copy)]
    enum Asset {
        Xch,
        Dig,
    }

    /// The `control.wallet.balance` reply for `asset`, in the exact envelope
    /// `dig-node-service`'s `control::wallet_balance` emits.
    fn wallet_result(reply: &WalletReply, asset: Asset) -> String {
        match reply {
            WalletReply::Balance { xch, dig, synced } => {
                let balance = match asset {
                    Asset::Xch => *xch,
                    Asset::Dig => *dig,
                };
                serde_json::json!({
                    "jsonrpc": "2.0",
                    "id": 1,
                    "result": {
                        "balance": balance,
                        "pending": 0,
                        "synced": synced,
                        "peak_height": 6_000_000,
                    }
                })
                .to_string()
            }
            WalletReply::Rejected { code, symbol } => serde_json::json!({
                "jsonrpc": "2.0",
                "id": 1,
                "error": {
                    "code": code,
                    "message": "the node refused this balance read",
                    "data": { "code": symbol, "origin": "node" }
                }
            })
            .to_string(),
        }
    }

    /// Which [`ControlMethod`] a raw request body names, if any.
    ///
    /// Matched against the contract's own name table rather than a substring the fake chooses, so
    /// the fake and the client agree on what was asked by construction.
    fn requested_method(request: &str) -> Option<ControlMethod> {
        ControlMethod::ALL
            .iter()
            .copied()
            .find(|method| request.contains(&format!("\"method\":\"{}\"", method.name())))
    }

    /// The `control.wallet.coins` reply, field-for-field as the 0.6.0 contract defines it.
    fn coins_result(reply: &CoinsReply) -> String {
        match reply {
            CoinsReply::Coins(coins) => {
                let coins: Vec<serde_json::Value> = coins
                    .iter()
                    .map(|coin| {
                        serde_json::json!({
                            "coin_id": coin.coin_id,
                            "asset": coin.asset,
                            "amount": coin.amount,
                            "parent_coin_info": coin.parent_coin_info,
                            "puzzle_hash": coin.puzzle_hash,
                            "created_height": coin.created_height,
                            "spent_height": coin.spent_height,
                        })
                    })
                    .collect();
                serde_json::json!({
                    "jsonrpc": "2.0",
                    "id": 1,
                    "result": {
                        "coins": coins,
                        "source": "db",
                        "synced": true,
                        "peak_height": 5_412_009,
                    }
                })
                .to_string()
            }
            CoinsReply::Rejected { code, symbol } => rejection(*code, symbol, "coin read"),
        }
    }

    /// The `control.wallet.broadcast` reply, field-for-field as the 0.6.0 contract defines it.
    fn broadcast_result(reply: &BroadcastReply) -> String {
        let result = match reply {
            BroadcastReply::Accepted { transaction_id } => serde_json::json!({
                "accepted": true,
                "transaction_id": transaction_id,
                "rejection": serde_json::Value::Null,
            }),
            BroadcastReply::RefusedByMempool { reason } => serde_json::json!({
                "accepted": false,
                "transaction_id": serde_json::Value::Null,
                "rejection": reason,
            }),
            BroadcastReply::Rejected { code, symbol } => return rejection(*code, symbol, "push"),
        };
        serde_json::json!({ "jsonrpc": "2.0", "id": 1, "result": result }).to_string()
    }

    /// The node's error envelope: a numeric wire code plus the stable `data.code` symbol.
    fn rejection(code: i64, symbol: &str, what: &str) -> String {
        serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "error": {
                "code": code,
                "message": format!("the node refused this {what}"),
                "data": { "code": symbol, "origin": "node" }
            }
        })
        .to_string()
    }

    /// The `control.hostedStores.list` reply, field-for-field as dig-node's
    /// `control::hosted_stores_list` emits it — including the per-store `capsules` array dig-app
    /// drops (see [`FakeStore`]).
    fn stores_result(reply: &StoresReply) -> String {
        match reply {
            StoresReply::Stores(stores) => {
                let stores: Vec<serde_json::Value> = stores.iter().map(fake_store_json).collect();
                serde_json::json!({
                    "jsonrpc": "2.0",
                    "id": 1,
                    "result": { "stores": stores }
                })
                .to_string()
            }
            StoresReply::Rejected { code, symbol } => serde_json::json!({
                "jsonrpc": "2.0",
                "id": 1,
                "error": {
                    "code": code,
                    "message": "the node refused this hosted-store read",
                    "data": { "code": symbol, "origin": "node" }
                }
            })
            .to_string(),
        }
    }

    /// One `HostedStore` entry, with `capsule_count` synthetic capsules so the body is faithful to
    /// what the node really sends.
    fn fake_store_json(store: &FakeStore) -> serde_json::Value {
        let capsules: Vec<serde_json::Value> = (0..store.capsule_count)
            .map(|i| {
                serde_json::json!({
                    "capsule": format!("{}:{i:064x}", store.store_id),
                    "root": format!("{i:064x}"),
                    "size_bytes": 1_024 * (i + 1),
                    "last_used_unix_ms": 1_700_000_000_000u64 + i,
                })
            })
            .collect();
        serde_json::json!({
            "store_id": store.store_id,
            "pinned": store.pinned,
            "capsule_count": store.capsule_count,
            "total_bytes": store.total_bytes,
            "capsules": capsules,
        })
    }

    /// The `control.status` snapshot as a typed result, for a test that needs an
    /// [`EngineState::Connected`](crate::engine::EngineState::Connected) without running a probe.
    pub fn fake_status_result() -> dig_node_control_interface::results::StatusResult {
        serde_json::from_value(
            serde_json::from_str::<serde_json::Value>(&status_result()).expect("valid JSON")
                ["result"]
                .clone(),
        )
        .expect("the fake's status body must match the contract's StatusResult")
    }

    /// Read the request head plus its declared `Content-Length` body.
    fn read_request(stream: &mut std::net::TcpStream) -> String {
        let mut buf = Vec::new();
        let mut byte = [0u8; 1];
        // Read to the end of the headers first: the body length is only knowable from them.
        while !buf.ends_with(b"\r\n\r\n") {
            match stream.read(&mut byte) {
                Ok(0) | Err(_) => return String::from_utf8_lossy(&buf).to_string(),
                Ok(_) => buf.push(byte[0]),
            }
        }
        let head = String::from_utf8_lossy(&buf).to_string();
        let len = head
            .lines()
            .find_map(|l| {
                let (name, value) = l.split_once(':')?;
                name.trim()
                    .eq_ignore_ascii_case("content-length")
                    .then(|| value.trim().parse::<usize>().ok())?
            })
            .unwrap_or(0);
        let mut body = vec![0u8; len];
        if stream.read_exact(&mut body).is_ok() {
            buf.extend_from_slice(&body);
        }
        String::from_utf8_lossy(&buf).to_string()
    }

    /// The `control.status` reply, field-for-field as `dig-node-service`'s `control::status` emits it.
    fn status_result() -> String {
        serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "result": {
                "running": true,
                "service": "dig-node",
                "version": FakeNode::VERSION,
                "commit": "deadbee",
                "protocol": "1",
                "uptime_secs": 4242,
                "addr": "127.0.0.1:9778",
                "upstream": "https://rpc.dig.net",
                "cache": { "cap_bytes": 1024, "used_bytes": 512, "dir": "/tmp/cache", "shared": false },
                "hosted_store_count": 3,
                "cached_capsule_count": 9,
                "pinned_store_count": 1,
                "sync": { "available": true }
            }
        })
        .to_string()
    }

    /// A JSON-RPC error reply carrying `message`.
    fn json_rpc_error(message: &str) -> String {
        serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "error": {
                "code": -32000,
                "message": message,
                "data": { "code": "UNAUTHORIZED", "origin": "shell" }
            }
        })
        .to_string()
    }
}
