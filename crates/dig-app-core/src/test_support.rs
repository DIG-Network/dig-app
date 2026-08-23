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
//! - [`test_residency`] — a freshly-enrolled, unlocked residency; call `.signer()` for
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
        /// A healthy, authorized node that ECHOES every `control.*` call back: the method it was
        /// asked for, the params it received, and its own [`FakeNode::VERSION`] marker.
        ///
        /// The fixture the `diga` engine proxy is tested against (dig-app#226). A canned reply
        /// cannot tell a proxy that forwarded the RIGHT method from one that forwarded any method,
        /// and a client-side assertion cannot tell a real reply from a fabricated one. Echoing the
        /// request and stamping a server-only marker distinguishes both.
        EchoingControl,
        /// Reply `200` with a JSON-RPC `error` — what an unauthorized/refused call looks like.
        JsonRpcError(String),
        /// Reply with an HTTP status and body — e.g. the `401` an unknown token draws.
        Http(u16, String),
        /// Accept the connection and close it without replying — a node that is up but mute.
        Silent,
        /// Accept the connection, read the request, then RESET the link without replying.
        ///
        /// The shape a mid-call reset really has, and distinct from [`Silent`](Self::Silent) in the
        /// one way that matters: the request was DELIVERED and may already have been acted on, so
        /// re-sending it elsewhere applies it twice. A graceful close cannot express that — the
        /// client reads a clean EOF and calls the reply unreadable — whereas a reset is the error a
        /// ladder used to treat as "nothing was there" (dig-app#226).
        ///
        /// The reset is forced by leaving the request's final byte unread and then dropping the
        /// socket: TCP requires a close with pending received data to send `RST`, which needs no
        /// per-OS socket option and behaves the same on every target. The withheld byte is the
        /// JSON's closing brace, so the method name is still delivered, counted and readable.
        ResetAfterReading,
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
        /// A healthy node that also answers the three key-enrolment methods —
        /// `control.wallet.watched` and `control.wallet.watch` — over a REAL enrolled set that a
        /// watch call mutates (dig_ecosystem#2848).
        ///
        /// Stateful rather than canned, because every property worth testing here is about the
        /// DIFFERENCE between what the node holds and what the app sends: a fake that replayed a
        /// fixed list would answer a client that reconciles and one that blindly re-sends its whole
        /// set identically. Kept BEHIND the control token, as the contract gates all three
        /// ([`ControlMethod::is_open_read`] is false for them) — the answer names the node's own
        /// key set, not the caller's.
        WalletWatch(WatchReply),
        /// A healthy node that also answers `control.wallet.coins` per the given [`CoinsReply`],
        /// serving it as the OPEN read the 0.6.0 contract declares it (dig_ecosystem#2378).
        WalletCoins(CoinsReply),
        /// A healthy node that also answers `control.wallet.arrivals` per the given
        /// [`ArrivalsReply`] (dig_ecosystem#2548), tokenless as the contract declares it.
        WalletArrivals(ArrivalsReply),
        /// A healthy node that also answers `control.wallet.broadcast` per the given
        /// [`BroadcastReply`].
        ///
        /// Unlike the two wallet READS this stays behind the control token, because the contract
        /// says so ([`ControlMethod::is_open_read`] is false for it) — and the fake derives that
        /// from the contract rather than from its own list, so a push served tokenless here would
        /// be a contract change and not a fixture liberty.
        WalletBroadcast(BroadcastReply),
        /// A healthy node that also answers `control.wallet.syncStatus` per the given
        /// [`SyncReply`] (dig_ecosystem#2569).
        ///
        /// Served TOKENLESS, because the contract declares this an open read — so a client that
        /// only worked while holding a control token fails here rather than passing on a fixture
        /// more generous than the real node.
        WalletSync(SyncReply),
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
        /// A healthy node that also answers the four OPEN chain reads a
        /// [`ChainSource`](dig_chainsource_interface::ChainSource) needs —
        /// `control.wallet.coinById`, `control.wallet.coinSpend`, `control.wallet.coinsByParent`
        /// and `control.wallet.peak` — from the scripted [`ChainReply`] (dig_ecosystem#2560).
        ///
        /// Served TOKENLESS, and the openness is read from [`ControlMethod::is_open_read`] rather
        /// than from a list here: a fixture more generous than the real node would let a client
        /// that only worked while holding a token pass, and a fixture stricter than it would fail a
        /// correct one.
        Chain(ChainReply),
    }

    /// How a [`FakeNode`] should answer the four OPEN chain reads.
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub enum ChainReply {
        /// Answer every chain read from this scripted chain.
        Chain(Box<FakeChain>),
        /// Refuse every chain read, in the node's error envelope: a numeric wire code plus the
        /// stable UPPER_SNAKE `data.code` symbol a client is contractually required to branch on.
        Rejected {
            /// The numeric JSON-RPC error code.
            code: i64,
            /// The stable `data.code` symbol.
            symbol: String,
        },
    }

    impl ChainReply {
        /// A refusal carrying `code` + its stable `symbol`.
        pub fn rejected(code: i64, symbol: &str) -> Self {
            ChainReply::Rejected {
                code,
                symbol: symbol.to_string(),
            }
        }

        /// Answer from `chain`.
        pub fn of(chain: FakeChain) -> Self {
            ChainReply::Chain(Box::new(chain))
        }
    }

    /// A scripted chain a [`FakeNode`] answers the four OPEN chain reads from.
    ///
    /// It is a small chain rather than a list of canned replies on purpose: the properties under
    /// test are all about what the client ASKS FOR NEXT, and a fixture that ignored `after_coin_id`
    /// would answer a correctly-paging client and a cursor-blind one identically.
    #[derive(Debug, Clone, Default, PartialEq, Eq)]
    pub struct FakeChain {
        /// The coins `control.wallet.coinById` can find, by their own ids.
        pub coins: Vec<FakeCoin>,
        /// The UNSPENT coins `control.wallet.coins` reports for any address it is asked about.
        ///
        /// A separate list from [`coins`](Self::coins) because the two reads answer different
        /// questions — one by coin id including spent coins, one by address excluding them — and a
        /// single list would let a client that asked the wrong method pass.
        pub address_coins: Vec<FakeCoin>,
        /// The spends `control.wallet.coinSpend` can find, keyed by the SPENT coin.
        pub spends: Vec<FakeSpend>,
        /// Each parent coin id and the direct children its spend created, in the ASCENDING
        /// `coin_id` order the contract fixes.
        pub children: Vec<(String, Vec<FakeCoin>)>,
        /// How many children this node puts in ONE page, whatever `limit` was asked for.
        ///
        /// A node is explicitly free to return a short page for its own reasons, and that freedom
        /// is the whole reason `complete` exists — so the fixture exercises it. `0` means "the
        /// whole child set in one page".
        pub child_page_size: usize,
        /// The peak `control.wallet.peak` reports, or `None` for a JSON `null`.
        pub peak_height: Option<u32>,
        /// The `synced` flag every answer carries.
        pub synced: bool,
        /// The `source` token every answer carries — `"db"` or `"fallback"`.
        pub source: &'static str,
        /// A node that NEVER says `complete`, always handing back an advancing cursor.
        ///
        /// Not a malformed node: each page is individually well-formed. It is the hostile shape the
        /// client's own page bound exists for, and it cannot be expressed by a child list alone
        /// because any finite list eventually completes.
        pub endless_children: bool,
        /// A node that answers `complete: false` with `cursor: null` — a self-contradiction the
        /// wire shape cannot forbid, and one that would spin a client re-asking the same page.
        pub incomplete_without_cursor: bool,
    }

    impl FakeChain {
        /// A synced chain answering from the node's own replica at `peak`, one page per child set.
        pub fn synced_at(peak: u32) -> Self {
            Self {
                peak_height: Some(peak),
                synced: true,
                source: "db",
                ..Self::default()
            }
        }

        /// Add a coin `control.wallet.coinById` can find.
        pub fn with_coin(mut self, coin: FakeCoin) -> Self {
            self.coins.push(coin);
            self
        }

        /// Add a spend `control.wallet.coinSpend` can find.
        pub fn with_spend(mut self, spend: FakeSpend) -> Self {
            self.spends.push(spend);
            self
        }

        /// Give `parent` these direct children, served `page_size` at a time.
        pub fn with_children(
            mut self,
            parent: &str,
            children: Vec<FakeCoin>,
            page_size: usize,
        ) -> Self {
            self.children.push((parent.to_string(), children));
            self.child_page_size = page_size;
            self
        }
    }

    /// One spend a [`FakeNode`] reports from `control.wallet.coinSpend`.
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct FakeSpend {
        /// The coin this spend consumed. Its `spent_height` decides whether the reply obeys the
        /// contract's rule that a spend's coin is never unspent.
        pub coin: FakeCoin,
        /// The puzzle reveal, lowercase hex of serialized CLVM.
        pub puzzle_reveal: String,
        /// The solution, lowercase hex of serialized CLVM.
        pub solution: String,
    }

    impl FakeSpend {
        /// A well-formed spend of `coin` at `height`, with distinguishable reveal and solution
        /// bytes so a client that swapped the two cannot pass.
        pub fn of(mut coin: FakeCoin, height: u32) -> Self {
            coin.spent_height = Some(height);
            Self {
                coin,
                puzzle_reveal: "ff01ff8080".into(),
                solution: "ff8203e880".into(),
            }
        }
    }

    /// How a [`FakeNode`] should answer `control.wallet.syncStatus`.
    ///
    /// The phase is a raw wire STRING rather than the contract's enum on purpose: a fixture that
    /// could only express the three tokens the client already understands could never present the
    /// unknown phase a newer node might send.
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub enum SyncReply {
        /// Answer both `control.wallet.syncStatus` and `control.peerCounts` from these fields.
        ///
        /// One reply for both methods because a conforming node MUST serve `chia_peer_count` from
        /// one source: a fixture with two independent knobs could express a node that contradicts
        /// itself, and a client tested against it would be tested against a node that cannot exist.
        Status {
            /// The `phase` token, as it goes on the wire.
            phase: String,
            /// The replica's peak height, or `None` for a JSON `null`.
            peak_height: Option<u32>,
            /// The DIG content-network peer count, or `None` for a JSON `null`.
            dig_peer_count: Option<u32>,
            /// The Chia peer count, or `None` for a JSON `null`.
            chia_peer_count: Option<u32>,
        },
        /// Refuse, in the node's error envelope: a numeric wire code plus the stable UPPER_SNAKE
        /// `data.code` symbol a client is contractually required to branch on.
        Rejected {
            /// The numeric JSON-RPC error code.
            code: i64,
            /// The stable `data.code` symbol.
            symbol: String,
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
            /// A THIRD token: its asset id as lowercase hex, and what this address holds of it.
            ///
            /// Present so a fixture can express a wallet holding a CAT dig-app was never built
            /// knowing about. Without it the fake could only ever answer the two assets the app
            /// knows by name, and every "reads an arbitrary CAT" assertion would be satisfied by an
            /// implementation that still had $DIG hard-coded — the fixture would be structurally
            /// unable to fail (dig_ecosystem#3077).
            other_cat: Option<(&'static str, u64)>,
            /// The node's `synced` flag: `false` means the figures are STALE.
            synced: bool,
            /// The disclosed read tier (`"db"` / `"fallback"`), or `None` for a node too old to
            /// disclose one — which serializes as an ABSENT field, exactly as such a node answers.
            source: Option<&'static str>,
            /// The peak height the figures reflect, or `None` when the answer carries none.
            ///
            /// Varies INDEPENDENTLY of `source` and `synced` because the three are independent facts
            /// on the wire, and a fake that could not separate them could not express the one answer
            /// that must not become a figure: a `db` read with no height at all.
            peak_height: Option<u32>,
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

    /// How a [`FakeNode`] should answer `control.wallet.arrivals`.
    ///
    /// The pages are answered IN ORDER, one per call, so a fixture scripts a whole conversation —
    /// which is what a cursor client needs, since the interesting properties are all about what the
    /// SECOND call asks for. Running out repeats the last page, the way a node whose ledger has not
    /// moved answers the same thing again.
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub enum ArrivalsReply {
        /// Answer these pages, in order.
        Pages(Vec<FakeArrivalPage>),
        /// Refuse, in the node's error envelope.
        Rejected {
            /// The numeric JSON-RPC error code.
            code: i64,
            /// The stable `data.code` symbol.
            symbol: String,
        },
    }

    impl ArrivalsReply {
        /// A refusal carrying `code` + its stable `symbol`.
        pub fn rejected(code: i64, symbol: &str) -> Self {
            ArrivalsReply::Rejected {
                code,
                symbol: symbol.to_string(),
            }
        }
    }

    /// One page a [`FakeNode`] serves from `control.wallet.arrivals`.
    ///
    /// `latest` is a field rather than derived from the rows precisely so a fixture can express the
    /// state the contract warns about — a ledger that has moved on past the page it just handed out.
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct FakeArrivalPage {
        /// The rows, oldest first: `(seq, amount_base_units, asset_id_hex_or_none)`.
        pub rows: Vec<(u64, u64, Option<String>)>,
        /// The ledger head this answer reports.
        pub latest: u64,
    }

    impl FakeArrivalPage {
        /// A page of XCH arrivals whose `latest` is its own last row — the ordinary case.
        pub fn of(rows: &[(u64, u64)]) -> Self {
            let latest = rows.last().map_or(0, |(seq, _)| *seq);
            Self {
                rows: rows.iter().map(|(s, a)| (*s, *a, None)).collect(),
                latest,
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
        /// `accepted: true` AND a rejection reason — the node asserting both halves at once.
        ///
        /// The mirror image of [`NeitherAcceptedNorRejected`](Self::NeitherAcceptedNorRejected),
        /// and the contract forbids it (`rejection` is null on acceptance) without the wire shape
        /// being able to. A fixture that could only express a CONSISTENT acceptance could not tell
        /// a client that believes `accepted` alone from one that reads the whole reply.
        AcceptedAndRefused {
            /// The refusal the node supplied beside its acceptance.
            reason: String,
        },
        /// `accepted: false` with NO rejection reason — the node declining to say what judged the
        /// bundle.
        ///
        /// A contract violation, and one the wire shape cannot forbid, which is why a client must
        /// handle it: the reply asserts the bundle is not in a mempool while supplying nothing that
        /// judged it. A fixture that could only express a REASONED refusal could not tell a client
        /// which reads this as a mempool rejection from one which does not.
        NeitherAcceptedNorRejected,
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

    /// How a [`FakeNode`] should answer the key-enrolment methods.
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub enum WatchReply {
        /// Serve a real enrolled set, seeded with these keys. `control.wallet.watched` returns the
        /// current set and `control.wallet.watch` adds to it, so re-watching an existing key is the
        /// no-op the live node performs.
        Holding(Vec<String>),
        /// Refuse both methods, in the node's error envelope: a numeric wire code plus the stable
        /// `data.code` symbol a client is contractually required to branch on.
        Rejected {
            /// The numeric JSON-RPC error code.
            code: i64,
            /// The stable `data.code` symbol.
            symbol: String,
        },
    }

    impl WatchReply {
        /// A node whose enrolled set already contains `keys`.
        pub fn holding(keys: &[String]) -> Self {
            WatchReply::Holding(keys.to_vec())
        }

        /// A refusal carrying `code` + its stable `symbol`.
        pub fn rejected(code: i64, symbol: &str) -> Self {
            WatchReply::Rejected {
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
        /// The keys this node currently follows, shared with the server thread — the enrolment
        /// fixture's whole point (see [`Behaviour::WalletWatch`]). Empty and unused for every other
        /// behaviour.
        enrolled: Arc<std::sync::Mutex<Vec<String>>>,
        /// The bodies of the `control.wallet.watch` calls that reached the wire, in order, so a test
        /// can assert WHAT was sent rather than only where the node ended up.
        watch_requests: Arc<std::sync::Mutex<Vec<String>>>,
        /// The method name of EVERY request that reached the wire, in order.
        ///
        /// Kept apart from the global [`request_count`](FakeNode::request_count) because "how many
        /// times did the node get asked to do THIS" is the only count that can see a mutating call
        /// applied twice; a total is also raised by an unrelated read.
        delivered: Arc<std::sync::Mutex<Vec<String>>>,
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

        /// A fake that answers `control.wallet.arrivals` with `reply` (dig_ecosystem#2548).
        pub fn serving_arrivals(reply: ArrivalsReply) -> Self {
            Self::with_behaviour(Behaviour::WalletArrivals(reply))
        }

        /// A fake that answers `control.wallet.broadcast` with `reply` (dig_ecosystem#2378).
        pub fn serving_broadcast(reply: BroadcastReply) -> Self {
            Self::with_behaviour(Behaviour::WalletBroadcast(reply))
        }

        /// A fake that answers `control.wallet.syncStatus` with `reply` (dig_ecosystem#2569).
        pub fn serving_sync(reply: SyncReply) -> Self {
            Self::with_behaviour(Behaviour::WalletSync(reply))
        }

        /// A fake that answers `control.hostedStores.list` with `reply` (dig_ecosystem#2330).
        pub fn serving_stores(reply: StoresReply) -> Self {
            Self::with_behaviour(Behaviour::HostedStores(reply))
        }

        /// A fake that answers `control.hostedStores.list` with `reply`, but only after `delay`.
        pub fn serving_stores_slowly(reply: StoresReply, delay: Duration) -> Self {
            Self::with_behaviour(Behaviour::SlowHostedStores { reply, delay })
        }

        /// A fake that answers the four OPEN chain reads with `reply` (dig_ecosystem#2560).
        pub fn serving_chain(reply: ChainReply) -> Self {
            Self::with_behaviour(Behaviour::Chain(reply))
        }

        /// A fake that answers the key-enrolment methods over a real, mutable enrolled set
        /// (dig_ecosystem#2848).
        pub fn serving_watch(reply: WatchReply) -> Self {
            Self::with_behaviour(Behaviour::WalletWatch(reply))
        }

        /// A fake with an explicit [`Behaviour`], bound to an ephemeral loopback port.
        pub fn with_behaviour(behaviour: Behaviour) -> Self {
            let listener = TcpListener::bind(("127.0.0.1", 0)).expect("bind loopback");
            let addr = listener.local_addr().expect("local addr");
            let (tx, requests) = mpsc::channel();
            let served = Arc::new(AtomicUsize::new(0));
            let counter = Arc::clone(&served);
            let enrolled = Arc::new(std::sync::Mutex::new(match &behaviour {
                Behaviour::WalletWatch(WatchReply::Holding(keys)) => keys.clone(),
                _ => Vec::new(),
            }));
            let watch_requests = Arc::new(std::sync::Mutex::new(Vec::new()));
            let delivered = Arc::new(std::sync::Mutex::new(Vec::new()));
            let set = Arc::clone(&enrolled);
            let sent = Arc::clone(&watch_requests);
            let seen = Arc::clone(&delivered);
            let server = std::thread::spawn(move || {
                serve(listener, behaviour, tx, counter, set, sent, seen)
            });
            Self {
                addr,
                token: Self::TOKEN.to_string(),
                requests,
                served,
                server: Some(server),
                enrolled,
                watch_requests,
                delivered,
            }
        }

        /// The keys this node currently follows — the fixture's own state, read back so a test can
        /// assert what enrolment actually did to the node rather than what the client believed.
        pub fn enrolled(&self) -> Vec<String> {
            self.enrolled
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .clone()
        }

        /// The `control.wallet.watch` request bodies that reached the wire, in order.
        pub fn watch_requests(&self) -> Vec<String> {
            self.watch_requests
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .clone()
        }

        /// How many requests the fake has actually served.
        ///
        /// Counted at the SERVER so a test can prove a call did — or did not — reach the wire,
        /// rather than trusting the client's own account of what it sent.
        pub fn request_count(&self) -> usize {
            self.served.load(Ordering::SeqCst)
        }

        /// How many times `method` was DELIVERED to this node, counted at the server.
        ///
        /// The count a non-idempotent call has to be measured by: a client that re-sent a
        /// `control.cache.clear` after a failure returns one error either way, so only the node's
        /// own tally distinguishes one application from two.
        pub fn deliveries_of(&self, method: &str) -> usize {
            self.delivered
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .iter()
                .filter(|seen| *seen == method)
                .count()
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
        enrolled: Arc<std::sync::Mutex<Vec<String>>>,
        watch_requests: Arc<std::sync::Mutex<Vec<String>>>,
        delivered: Arc<std::sync::Mutex<Vec<String>>>,
    ) {
        while let Ok((mut stream, _)) = listener.accept() {
            let withhold_last_byte = behaviour == Behaviour::ResetAfterReading;
            let request = read_request_but(&mut stream, withhold_last_byte);
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
            let method_is_arrivals = is(ControlMethod::WalletArrivals);
            let method_is_broadcast = is(ControlMethod::WalletBroadcast);
            let method_is_hosted_list = is(ControlMethod::HostedStoresList);
            let method_is_sync = is(ControlMethod::WalletSyncStatus);
            let method_is_peer_counts = is(ControlMethod::PeerCounts);
            let chain_method = [
                ControlMethod::WalletCoins,
                ControlMethod::WalletCoinById,
                ControlMethod::WalletCoinSpend,
                ControlMethod::WalletCoinsByParent,
                ControlMethod::WalletPeak,
            ]
            .into_iter()
            .find(|m| method == Some(*m));
            let asset = requested_asset(&request);
            if let Some(name) = method.map(ControlMethod::name) {
                delivered
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .push(name.to_string());
            }
            let _ = tx.send(request.clone());

            let (code, body) = match &behaviour {
                Behaviour::Silent => return,
                // Drop the stream with its last byte still unread, which is what makes the close a
                // reset rather than a graceful EOF. `continue`, not `return`: the whole point is
                // that the caller may come back on another tier, and a one-shot fake would refuse
                // the second delivery for the wrong reason.
                Behaviour::ResetAfterReading => {
                    drop(stream);
                    continue;
                }
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
                // `control.wallet.arrivals` is TOKEN-GATED (dig_ecosystem#2548): the caller supplies
                // only a cursor, so the answer names the node's OWN watched puzzle hashes. The
                // openness is still read from the CONTRACT rather than asserted here, so if the
                // contract ever reopens the method this fake follows it instead of contradicting
                // it. The page index comes from the SERVED counter, so successive calls walk the
                // scripted conversation.
                Behaviour::WalletArrivals(reply)
                    if method_is_arrivals && (method_is_open_read || authorized) =>
                {
                    (
                        200,
                        arrivals_result(
                            reply,
                            served.load(Ordering::SeqCst).saturating_sub(1),
                            &request,
                        ),
                    )
                }
                // Every other `control.*` method is gated exactly as the real node gates it,
                // otherwise a client that forgot the header would still see a green test.
                // `control.wallet.syncStatus` is an open read too — the node's own chain position
                // names no address at all — so the fake serves it tokenless, taking the openness
                // from the CONTRACT rather than from a list of its own.
                Behaviour::WalletSync(reply) if method_is_sync && method_is_open_read => {
                    (200, sync_result(reply))
                }
                Behaviour::WalletSync(reply) if method_is_peer_counts && method_is_open_read => {
                    (200, peer_counts_result(reply))
                }
                // The four chain reads, served TOKENLESS because the contract declares them open.
                // A client that only worked while presenting a token fails here rather than being
                // rescued by a fixture more generous than the real node.
                Behaviour::Chain(reply) if chain_method.is_some() && method_is_open_read => (
                    200,
                    chain_result(reply, chain_method.expect("checked above"), &request),
                ),
                _ if !authorized => (401, "401: unauthorized control request".to_string()),
                // Authorized, and asking about — or changing — the enrolled set. Both arms sit
                // behind the token gate above, exactly as the real node gates them.
                Behaviour::WalletWatch(reply) if is(ControlMethod::WalletWatched) => {
                    (200, watched_result(reply, &enrolled))
                }
                Behaviour::WalletWatch(reply) if is(ControlMethod::WalletWatch) => {
                    watch_requests
                        .lock()
                        .unwrap_or_else(|e| e.into_inner())
                        .push(request.clone());
                    (200, watch_result(reply, &enrolled, &request))
                }
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
                // Authorized, and echoing: the token gate above is what this arm sits behind, so an
                // untokened client sees the `401` a real node would send rather than an echo.
                Behaviour::EchoingControl => (200, echo_result(&request)),
                Behaviour::Status
                | Behaviour::Wallet(_)
                | Behaviour::SlowWallet { .. }
                | Behaviour::WalletCoins(_)
                | Behaviour::WalletArrivals(_)
                | Behaviour::WalletBroadcast(_)
                | Behaviour::WalletSync(_)
                | Behaviour::WalletWatch(_)
                | Behaviour::HostedStores(_)
                | Behaviour::SlowHostedStores { .. }
                | Behaviour::Chain(_) => (200, status_result()),
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

    /// The echo body [`Behaviour::EchoingControl`] answers with: what the node was ASKED, plus a
    /// marker only the node holds.
    ///
    /// Built by re-reading the request off the wire rather than from anything the client passed in,
    /// so the reply is evidence about the bytes that actually arrived.
    fn echo_result(request: &str) -> String {
        let sent: serde_json::Value =
            serde_json::from_str(body_of(request)).unwrap_or(serde_json::Value::Null);
        serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "result": {
                "served_by": FakeNode::VERSION,
                "method": sent.get("method").cloned().unwrap_or(serde_json::Value::Null),
                "params": sent.get("params").cloned().unwrap_or(serde_json::Value::Null),
            }
        })
        .to_string()
    }

    /// Which asset a balance request named, as the FAKE understands it.
    ///
    /// Three cases where the contract has two, deliberately and only here: this is a test double
    /// that has to distinguish "the request named $DIG" from "the request named some other token"
    /// in order to answer them differently. The production type must never make that distinction —
    /// see `wallet::state::Asset` for why a second spelling of $DIG halves a balance.
    #[derive(Clone, Debug, PartialEq, Eq)]
    enum Asset {
        Xch,
        Dig,
        OtherCat(String),
    }

    /// Which asset a raw request body named, read the way the node reads it.
    ///
    /// The tagged form is matched on the KEY rather than on a whole-body substring, so a request
    /// naming an arbitrary CAT is recognised as that CAT and not silently served XCH — which is what
    /// the previous `contains("\"asset\":\"dig\"")` check did to every token except $DIG.
    fn requested_asset(request: &str) -> Asset {
        if request.contains("\"asset\":\"dig\"") {
            return Asset::Dig;
        }
        match request.split_once("\"asset\":{\"cat\":\"") {
            Some((_, rest)) => match rest.split_once('"') {
                Some((id, _)) => Asset::OtherCat(id.to_string()),
                None => Asset::Xch,
            },
            None => Asset::Xch,
        }
    }

    /// The `control.wallet.balance` reply for `asset`, in the exact envelope
    /// `dig-node-service`'s `control::wallet_balance` emits.
    fn wallet_result(reply: &WalletReply, asset: Asset) -> String {
        match reply {
            WalletReply::Balance {
                xch,
                dig,
                other_cat,
                synced,
                source,
                peak_height,
            } => {
                let balance = match &asset {
                    Asset::Xch => *xch,
                    Asset::Dig => *dig,
                    // A token this fixture does not name holds NOTHING, never $DIG's figure. A fake
                    // that answered one asset's balance for another would let a wallet still keyed
                    // to $DIG pass every arbitrary-CAT assertion.
                    Asset::OtherCat(id) => match other_cat {
                        Some((fixture_id, held)) if fixture_id == id => *held,
                        _ => 0,
                    },
                };
                let mut result = serde_json::json!({
                    "balance": balance,
                    "pending": 0,
                    "synced": synced,
                    "peak_height": peak_height,
                });
                // Omitted rather than null: a node predating tier disclosure has no such field at
                // all, and a fake that always emits the key cannot exercise that node.
                if let Some(source) = source {
                    result["source"] = serde_json::json!(source);
                }
                serde_json::json!({ "jsonrpc": "2.0", "id": 1, "result": result }).to_string()
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

    /// The `control.wallet.arrivals` reply, field-for-field as the node emits it — `amount` as a
    /// decimal STRING and `asset_id` as `null` or a hex TAIL.
    ///
    /// `cursor` is derived the way the node derives it: the last row served, or the caller's own
    /// `after_seq` on an empty page. Deriving it here rather than letting the fixture state it is
    /// what keeps a client that resumes wrongly from being rescued by a helpful fake.
    fn arrivals_result(reply: &ArrivalsReply, call_index: usize, request: &str) -> String {
        let pages = match reply {
            ArrivalsReply::Pages(pages) => pages,
            ArrivalsReply::Rejected { code, symbol } => {
                return rejection(*code, symbol, "arrival read")
            }
        };
        let after_seq = request
            .split("\"after_seq\":")
            .nth(1)
            .and_then(|rest| {
                rest.trim_start()
                    .split(|c: char| !c.is_ascii_digit())
                    .find(|t| !t.is_empty())
            })
            .and_then(|digits| digits.parse::<u64>().ok())
            .unwrap_or(0);
        let Some(page) = pages.get(call_index).or_else(|| pages.last()) else {
            return rejection(-32004, "WALLET_READ_FAILED", "arrival read");
        };
        let rows: Vec<serde_json::Value> = page
            .rows
            .iter()
            .map(|(seq, amount, asset_id)| {
                serde_json::json!({
                    "seq": seq,
                    "coin_id": format!("{seq:064x}"),
                    "puzzle_hash": "cc".repeat(32),
                    "amount": amount.to_string(),
                    "asset_id": asset_id,
                    "confirmed_height": 5_412_000u32 + *seq as u32,
                })
            })
            .collect();
        let cursor = page.rows.last().map_or(after_seq, |(seq, _, _)| *seq);
        serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "result": { "arrivals": rows, "cursor": cursor, "latest": page.latest }
        })
        .to_string()
    }

    /// The `control.wallet.coins` reply, field-for-field as the 0.6.0 contract defines it.
    /// The `control.wallet.watched` reply: the node's CURRENT enrolled set, not a canned list.
    fn watched_result(reply: &WatchReply, enrolled: &Arc<std::sync::Mutex<Vec<String>>>) -> String {
        if let WatchReply::Rejected { code, symbol } = reply {
            return rejection(*code, symbol, "watched read");
        }
        let public_keys = enrolled.lock().unwrap_or_else(|e| e.into_inner()).clone();
        serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "result": { "public_keys": public_keys }
        })
        .to_string()
    }

    /// The `control.wallet.watch` reply, having actually ADDED the request's keys to the set.
    ///
    /// Idempotent exactly as the live node is — a key already present is not added twice and is not
    /// counted in `added` — so a client that re-sends its whole set every time is indistinguishable
    /// from one that reconciles WHEN JUDGED BY THE END STATE. That is deliberate: it forces a test
    /// that cares about the difference to assert on the request bodies instead.
    fn watch_result(
        reply: &WatchReply,
        enrolled: &Arc<std::sync::Mutex<Vec<String>>>,
        request: &str,
    ) -> String {
        if let WatchReply::Rejected { code, symbol } = reply {
            return rejection(*code, symbol, "enrolment");
        }
        let sent: Vec<String> = serde_json::from_str::<serde_json::Value>(body_of(request))
            .ok()
            .and_then(|value| {
                Some(
                    value["params"]["public_keys"]
                        .as_array()?
                        .iter()
                        .filter_map(|key| key.as_str().map(str::to_string))
                        .collect(),
                )
            })
            .unwrap_or_default();
        let mut set = enrolled.lock().unwrap_or_else(|e| e.into_inner());
        let mut added = 0u32;
        for key in sent {
            if !set.contains(&key) {
                set.push(key);
                added += 1;
            }
        }
        serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "result": { "added": added, "watched": set.len() }
        })
        .to_string()
    }

    /// The JSON body of a raw HTTP request — everything after the blank line.
    fn body_of(request: &str) -> &str {
        request.split_once("\r\n\r\n").map_or(request, |(_, b)| b)
    }

    fn coins_result(reply: &CoinsReply) -> String {
        let (coins, synced, peak_height) = match reply {
            CoinsReply::Coins(coins) => (coins, true, Some(5_412_009u32)),
            CoinsReply::Rejected { code, symbol } => return rejection(*code, symbol, "coin read"),
        };
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
                "synced": synced,
                "peak_height": peak_height,
            }
        })
        .to_string()
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
            BroadcastReply::AcceptedAndRefused { reason } => serde_json::json!({
                "accepted": true,
                "transaction_id": serde_json::Value::Null,
                "rejection": reason,
            }),
            BroadcastReply::NeitherAcceptedNorRejected => serde_json::json!({
                "accepted": false,
                "transaction_id": serde_json::Value::Null,
                "rejection": serde_json::Value::Null,
            }),
            BroadcastReply::Rejected { code, symbol } => return rejection(*code, symbol, "push"),
        };
        serde_json::json!({ "jsonrpc": "2.0", "id": 1, "result": result }).to_string()
    }

    /// The reply to one of the four OPEN chain reads, field-for-field as the 0.10 contract defines
    /// it — including the `source` / `synced` / `peak_height` freshness trio every wallet result
    /// carries, and the required-but-nullable keys (`coin`, `spend`, `cursor`) written as explicit
    /// `null`s rather than omitted, because the contract makes an ABSENT key a decode error and the
    /// difference is exactly what a client must not paper over.
    fn chain_result(reply: &ChainReply, method: ControlMethod, request: &str) -> String {
        let chain = match reply {
            ChainReply::Chain(chain) => chain,
            ChainReply::Rejected { code, symbol } => return rejection(*code, symbol, "chain read"),
        };
        let result = match method {
            ControlMethod::WalletPeak => serde_json::json!({
                "peak_height": chain.peak_height,
                "synced": chain.synced,
            }),
            ControlMethod::WalletCoinById => {
                let wanted = string_param(request, "coin_id").unwrap_or_default();
                let coin = chain.coins.iter().find(|c| c.coin_id == wanted);
                serde_json::json!({
                    "coin": coin.map(chain_coin_json),
                    "source": chain.source,
                    "synced": chain.synced,
                    "peak_height": chain.peak_height,
                })
            }
            ControlMethod::WalletCoinSpend => {
                let wanted = string_param(request, "coin_id").unwrap_or_default();
                let spend = chain.spends.iter().find(|s| s.coin.coin_id == wanted);
                serde_json::json!({
                    "spend": spend.map(|s| serde_json::json!({
                        "coin": chain_coin_json(&s.coin),
                        "puzzle_reveal": s.puzzle_reveal,
                        "solution": s.solution,
                    })),
                    "source": chain.source,
                    "synced": chain.synced,
                    "peak_height": chain.peak_height,
                })
            }
            ControlMethod::WalletCoinsByParent => coins_by_parent_json(chain, request),
            // `control.wallet.coins` is the ONE read that MUST report a concrete asset: it was
            // scoped to one, so a `null` there would be a different (and contract-breaking) reply
            // than the by-id reads give.
            ControlMethod::WalletCoins => serde_json::json!({
                "coins": chain
                    .address_coins
                    .iter()
                    .map(|c| {
                        let mut json = chain_coin_json(c);
                        json["asset"] = serde_json::Value::String(c.asset.to_string());
                        json
                    })
                    .collect::<Vec<_>>(),
                "source": chain.source,
                "synced": chain.synced,
                "peak_height": chain.peak_height,
            }),
            other => return rejection(-32601, "METHOD_NOT_FOUND", other.name()),
        };
        serde_json::json!({ "jsonrpc": "2.0", "id": 1, "result": result }).to_string()
    }

    /// One page of `control.wallet.coinsByParent`, resumed HONESTLY from `after_coin_id`.
    ///
    /// The page is derived from the scripted child list rather than canned, and `complete` is set
    /// only when this page genuinely exhausts that list — never from the page's length. A fixture
    /// that answered the whole child set regardless of the cursor would let a client which never
    /// paged pass, and one that inferred `complete` from a length would encode into the fixture the
    /// very mistake the client must not make.
    fn coins_by_parent_json(chain: &FakeChain, request: &str) -> serde_json::Value {
        let parent = string_param(request, "parent_coin_id").unwrap_or_default();
        let after = string_param(request, "after_coin_id");
        let all: &[FakeCoin] = chain
            .children
            .iter()
            .find(|(id, _)| *id == parent)
            .map_or(&[], |(_, kids)| kids.as_slice());

        let start = after.as_ref().map_or(0, |cursor| {
            all.iter()
                .position(|c| c.coin_id == *cursor)
                .map_or(0, |i| i + 1)
        });
        let remaining = &all[start.min(all.len())..];
        let page_size = if chain.child_page_size == 0 {
            remaining.len()
        } else {
            chain.child_page_size
        };
        let page = &remaining[..page_size.min(remaining.len())];

        // An endless node keeps handing back an ADVANCING cursor and never says `complete`. It
        // advances from the cursor the CLIENT sent rather than from any child index, so the value
        // is genuinely new on every page — a client that detected the loop by spotting a repeated
        // cursor would never be exercised, and the only thing that can stop this node is the
        // client's own page bound.
        let (coins, complete, cursor) = if chain.endless_children {
            let seen = after
                .as_ref()
                .and_then(|c| u64::from_str_radix(c.trim_start_matches('0'), 16).ok())
                .unwrap_or(0);
            (
                vec![FakeCoin::confirmed("xch", seen + 1)],
                false,
                Some(format!("{:064x}", seen + 1)),
            )
        } else if chain.incomplete_without_cursor {
            (page.to_vec(), false, None)
        } else {
            let complete = start + page.len() >= all.len();
            let cursor = page.last().map(|c| c.coin_id.clone());
            (page.to_vec(), complete, cursor)
        };

        serde_json::json!({
            "coins": coins.iter().map(chain_coin_json).collect::<Vec<_>>(),
            "complete": complete,
            "cursor": cursor,
            "source": chain.source,
            "synced": chain.synced,
            "peak_height": chain.peak_height,
        })
    }

    /// One coin in a chain-read reply.
    ///
    /// `asset` is `null` on every chain read, because the contract requires it: a coin id alone
    /// classifies nothing, so a node emitting a concrete asset would be asserting something it never
    /// verified. A client that read the asset off one of these would be reading the fixture's
    /// helpfulness rather than the node's answer.
    fn chain_coin_json(coin: &FakeCoin) -> serde_json::Value {
        serde_json::json!({
            "coin_id": coin.coin_id,
            "asset": serde_json::Value::Null,
            "amount": coin.amount,
            "parent_coin_info": coin.parent_coin_info,
            "puzzle_hash": coin.puzzle_hash,
            "created_height": coin.created_height,
            "spent_height": coin.spent_height,
        })
    }

    /// A string parameter's value, read back out of the raw request body.
    ///
    /// Read from the WIRE rather than from a structure the fake shares with the client, so a client
    /// that sent the right value under the wrong key cannot be rescued by a helpful fixture.
    fn string_param(request: &str, key: &str) -> Option<String> {
        request
            .split(&format!("\"{key}\":\""))
            .nth(1)
            .and_then(|rest| rest.split('"').next())
            .map(str::to_string)
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

    /// The `control.wallet.syncStatus` reply, field-for-field as dig-node emits it.
    ///
    /// `null` is written for an absent height or peer count rather than the field being omitted,
    /// because that is what the node sends and the difference is exactly what the client branches on.
    fn sync_result(reply: &SyncReply) -> String {
        match reply {
            SyncReply::Status {
                phase,
                peak_height,
                chia_peer_count,
                ..
            } => serde_json::json!({
                "jsonrpc": "2.0",
                "id": 1,
                "result": {
                    "phase": phase,
                    "peak_height": peak_height,
                    "chia_peer_count": chia_peer_count,
                }
            })
            .to_string(),
            SyncReply::Rejected { code, symbol } => serde_json::json!({
                "jsonrpc": "2.0",
                "id": 1,
                "error": {
                    "code": code,
                    "message": "the node refused this sync read",
                    "data": { "code": symbol, "origin": "node" }
                }
            })
            .to_string(),
        }
    }

    /// The `control.peerCounts` reply, from the same fixture the sync reply comes from.
    fn peer_counts_result(reply: &SyncReply) -> String {
        match reply {
            SyncReply::Status {
                dig_peer_count,
                chia_peer_count,
                ..
            } => serde_json::json!({
                "jsonrpc": "2.0",
                "id": 1,
                "result": {
                    "dig_peer_count": dig_peer_count,
                    "chia_peer_count": chia_peer_count,
                }
            })
            .to_string(),
            SyncReply::Rejected { code, symbol } => serde_json::json!({
                "jsonrpc": "2.0",
                "id": 1,
                "error": {
                    "code": code,
                    "message": "the node refused this peer-count read",
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

    /// Read the request head plus its declared `Content-Length` body, optionally leaving the body's
    /// FINAL byte unread.
    ///
    /// Withholding that byte is how [`Behaviour::ResetAfterReading`] forces a `RST`: closing a
    /// socket that still holds received data obliges TCP to reset rather than finish gracefully, on
    /// every platform and with no socket option. The byte withheld is the JSON's closing brace, so
    /// the request text this returns still carries the method and params a caller asserts on.
    fn read_request_but(stream: &mut std::net::TcpStream, withhold_last_byte: bool) -> String {
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
        let wanted = if withhold_last_byte {
            len.saturating_sub(1)
        } else {
            len
        };
        let mut body = vec![0u8; wanted];
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
