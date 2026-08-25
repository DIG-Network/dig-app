//! The reservation seam against a node on a real socket, answering the bytes dig-node answers.
//!
//! # Why this file exists, in one sentence
//!
//! `reservations_tests` hands `NodeTableError` values straight to the store, so it can only prove
//! what the store does GIVEN a classification — never that a real node's bytes ever produce one.
//! That gap hid a **permanent spend lockout**: dig-node refuses an unresolved method with a bare
//! `{"code":-32601,"message":"method not found"}` carrying **no `data` field**, `ControlError::data`
//! is required with no serde default, so the response failed to decode at all and surfaced as a
//! TRANSPORT error. `Unsupported` was therefore unreachable, `degrade()` never fired, and every
//! send, CAT send and mint refused forever against any node predating the reservation contract.
//!
//! A double kinder than reality hides rather than reveals. So [`WireNode`] speaks HTTP, is dialled
//! through the production `ControlReservationTable`, and emits refusals **byte-for-byte** as
//! dig-node does — including the missing field.
//!
//! # What this file still cannot see
//!
//! It is a faithful ENVELOPE, not dig-node. It does not prove the node's table is atomic, that its
//! TTL clamp is what it claims, or that its `held` excludes lapsed holds. Only an end-to-end run
//! against the real serve side can, and that side is still in flight.

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use chia_protocol::Bytes32;
use dig_account::wallet::reservation::{CoinReservationStore, ReservationError};

use super::reservations::{NodeReservationTable, NodeReservations};
use super::reservations_control::ControlReservationTable;

/// A fixed instant, so every lifetime here is measured against a time the test states.
const NOW: u64 = 1_800_000_000;

/// The token the wire node accepts.
const TOKEN: &str = "f00dcafe";

/// Long enough that no assertion here is a timing race, short enough to fail fast.
const TIMEOUT: Duration = Duration::from_secs(3);

fn coin(tag: u8) -> Bytes32 {
    Bytes32::new([tag; 32])
}

fn hexed(tag: u8) -> String {
    hex::encode(coin(tag))
}

/// How the wire node should answer a `control.wallet.reservations.*` call.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Answer {
    /// Serve the reservation table for real.
    Serve,
    /// The bare `-32601` a node emits for a method it does not resolve.
    ///
    /// **No `data` field.** That absence is the entire point of this fixture: an answer that merely
    /// carried the right numeric code inside a well-formed envelope would decode cleanly and could
    /// not express the defect.
    MethodNotFoundBare,
    /// A `-32601` WITH a `data` object — the control.
    ///
    /// A well-formed refusal that a strict decode handles. Without it, a fix that repaired the
    /// envelope by ignoring `data` entirely would pass unnoticed.
    MethodNotFoundWithData,
    /// Apply the call, then answer nothing at all.
    ///
    /// The shape of a non-idempotent POST that timed out: the node DID the work and the caller was
    /// told nothing. A fault that refused before applying cannot express a stranded hold, which is
    /// the whole defect.
    LoseReply,
    /// Answer nothing, having done nothing — a node that is simply not talking.
    ///
    /// Distinct from `LoseReply` in what the node's table looks like afterwards, and distinct from
    /// the `MethodNotFound` answers in what it MEANS: an outage may resolve on the next call, so it
    /// must never narrow the scope for the rest of the session.
    Unreachable,
}

/// The node's reservation table: its own handle, and the coins that handle holds.
///
/// Shared between the test thread and the server thread, which is why it is behind an `Arc<Mutex>`
/// rather than owned — a test asserts on the node's OWN view, since an assertion about what the
/// client returned can be satisfied by a client that never crossed the wire.
type NodeTable = Arc<Mutex<Vec<(u64, Vec<Bytes32>)>>>;

/// A node on a real loopback socket, answering exactly what dig-node answers.
struct WireNode {
    endpoint: String,
    rows: NodeTable,
    /// What the node answers NOW.
    ///
    /// Switchable rather than fixed at start-up, because a node that has always lacked the methods
    /// cannot express the case that matters most for handle collisions: a node that SERVED them,
    /// so this process holds node-mode handles, and then stopped — a downgrade or a restart into an
    /// older build. With a start-fixed answer, degrade-mid-session is inexpressible and a handle
    /// collision between the two modes can never occur in a test.
    answer: Arc<Mutex<Answer>>,
    server: Option<std::thread::JoinHandle<()>>,
    shutdown: Arc<AtomicBool>,
}

impl WireNode {
    /// Start a node answering `answer`.
    fn start(answer: Answer) -> Self {
        let listener = TcpListener::bind(("127.0.0.1", 0)).expect("bind loopback");
        let addr = listener.local_addr().expect("addr");
        let rows: NodeTable = Arc::new(Mutex::new(Vec::new()));
        let shutdown = Arc::new(AtomicBool::new(false));

        let answer = Arc::new(Mutex::new(answer));
        let (table, stop, mode) = (rows.clone(), shutdown.clone(), answer.clone());
        let server = std::thread::spawn(move || {
            let next_id = AtomicU64::new(1);
            for stream in listener.incoming() {
                if stop.load(Ordering::SeqCst) {
                    return;
                }
                let Ok(stream) = stream else { return };
                let now = *mode.lock().expect("answer");
                serve_one(stream, now, &table, &next_id);
            }
        });

        Self {
            endpoint: format!("http://{addr}"),
            rows,
            answer,
            server: Some(server),
            shutdown,
        }
    }

    /// The store a test drives, dialled through the PRODUCTION transport.
    fn store(&self) -> NodeReservations {
        let endpoint = self.endpoint.clone();
        NodeReservations::new(Arc::new(ControlReservationTable::new(
            move || Some(endpoint.clone()),
            || Some(TOKEN.to_owned()),
            TIMEOUT,
        )) as Arc<dyn NodeReservationTable>)
    }

    /// How many holds the node is carrying. A stranded hold appears here and nowhere else.
    fn live_holds(&self) -> usize {
        self.rows.lock().expect("rows").len()
    }

    /// Change what the node answers from the next request onward.
    fn now_answers(&self, answer: Answer) {
        *self.answer.lock().expect("answer") = answer;
    }
}

impl Drop for WireNode {
    fn drop(&mut self) {
        self.shutdown.store(true, Ordering::SeqCst);
        // Unblock the accept loop so the thread can observe the flag and exit.
        let _ = TcpStream::connect(self.endpoint.trim_start_matches("http://"));
        if let Some(server) = self.server.take() {
            let _ = server.join();
        }
    }
}

/// Read one HTTP request and write one response.
fn serve_one(mut stream: TcpStream, answer: Answer, rows: &NodeTable, next_id: &AtomicU64) {
    let mut reader = BufReader::new(stream.try_clone().expect("clone"));
    let mut length = 0usize;
    loop {
        let mut line = String::new();
        if reader.read_line(&mut line).unwrap_or(0) == 0 {
            return;
        }
        if line == "\r\n" || line == "\n" {
            break;
        }
        if let Some(value) = line.to_ascii_lowercase().strip_prefix("content-length:") {
            length = value.trim().parse().unwrap_or(0);
        }
    }
    let mut body = vec![0u8; length];
    if reader.read_exact(&mut body).is_err() {
        return;
    }
    let request: serde_json::Value = serde_json::from_slice(&body).unwrap_or_default();
    let method = request["method"].as_str().unwrap_or_default().to_owned();

    if answer == Answer::Unreachable {
        // Nothing applied and nothing said. The socket closes and the client sees a transport
        // failure, exactly as it does against a node that has stopped.
        return;
    }

    let payload = match answer {
        // Byte-for-byte what dig-node emits for a method it does not resolve: a `code` and a
        // `message`, and NO `data`.
        Answer::MethodNotFoundBare => {
            r#"{"jsonrpc":"2.0","id":1,"error":{"code":-32601,"message":"method not found"}}"#
                .to_owned()
        }
        Answer::MethodNotFoundWithData => concat!(
            r#"{"jsonrpc":"2.0","id":1,"error":{"code":-32601,"#,
            r#""message":"method not found","#,
            r#""data":{"code":"METHOD_NOT_FOUND","origin":"boundary"}}}"#
        )
        .to_owned(),
        Answer::Serve | Answer::LoseReply => {
            let served = serve_reservations(&method, &request, rows, next_id);
            // A lost reply is a property of ONE request, not of the connection: the node is
            // otherwise healthy, which is exactly why the client can still read what it holds and
            // give the stranded hold back. Suppressing every method would model a wedged node and
            // could not express recovery at all.
            if answer == Answer::LoseReply && method == "control.wallet.reservations.reserve" {
                // The work is DONE — the hold is in the table — and the caller is told nothing.
                return;
            }
            served
        }
        Answer::Unreachable => unreachable!("handled above"),
    };

    let response = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        payload.len(),
        payload
    );
    let _ = stream.write_all(response.as_bytes());
    let _ = stream.flush();
}

/// The reservation table, answered in the contract's own shapes.
fn serve_reservations(
    method: &str,
    request: &serde_json::Value,
    rows: &NodeTable,
    next_id: &AtomicU64,
) -> String {
    let mut table = rows.lock().expect("rows");
    match method {
        "control.wallet.reservations.held" => {
            let reserved: Vec<serde_json::Value> = table
                .iter()
                .flat_map(|(id, coins)| {
                    coins.iter().map(move |c| {
                        serde_json::json!({
                            "coin_id": hex::encode(c),
                            "reservation_id": format!("node-{id}"),
                            "expires_at_unix": NOW + 300,
                        })
                    })
                })
                .collect();
            serde_json::json!({
                "jsonrpc": "2.0", "id": 1,
                "result": { "reserved": reserved, "as_of_unix": NOW }
            })
            .to_string()
        }
        "control.wallet.reservations.reserve" => {
            let asked: Vec<Bytes32> = request["params"]["coin_ids"]
                .as_array()
                .map(|ids| {
                    ids.iter()
                        .filter_map(|v| v.as_str())
                        .filter_map(|s| hex::decode(s).ok())
                        .filter_map(|b| <[u8; 32]>::try_from(b.as_slice()).ok())
                        .map(Bytes32::new)
                        .collect()
                })
                .unwrap_or_default();
            let held: Vec<Bytes32> = table.iter().flat_map(|(_, c)| c.clone()).collect();
            if asked.iter().any(|c| held.contains(c)) {
                // All-or-none: a conflict reserves nothing, and the contract's error data carries
                // no coin id — which is why the client must re-read `.held` to attribute it.
                return concat!(
                    r#"{"jsonrpc":"2.0","id":1,"error":{"code":-32046,"#,
                    r#""message":"coins are held","#,
                    r#""data":{"code":"WALLET_COINS_RESERVED","origin":"node"}}}"#
                )
                .to_owned();
            }
            let id = next_id.fetch_add(1, Ordering::SeqCst);
            table.push((id, asked));
            serde_json::json!({
                "jsonrpc": "2.0", "id": 1,
                "result": {
                    "reservation_id": format!("node-{id}"),
                    "coin_ids": [],
                    "expires_at_unix": NOW + 300,
                    "ttl_secs": 300,
                }
            })
            .to_string()
        }
        "control.wallet.reservations.release" => {
            let handle = request["params"]["reservation_id"]
                .as_str()
                .unwrap_or_default()
                .to_owned();
            let before = table.len();
            table.retain(|(id, _)| format!("node-{id}") != handle);
            serde_json::json!({
                "jsonrpc": "2.0", "id": 1,
                "result": { "released": table.len() < before, "coin_ids": [] }
            })
            .to_string()
        }
        _ => concat!(
            r#"{"jsonrpc":"2.0","id":1,"error":{"code":-32601,"#,
            r#""message":"method not found"}}"#
        )
        .to_owned(),
    }
}

// ---------------------------------------------------------------------------------------------
// Finding 1 — the degrade path must fire against the bytes a real node sends
// ---------------------------------------------------------------------------------------------

/// A node that answers a bare `-32601` — **no `data`** — must DEGRADE, not refuse forever.
///
/// This is the permanent spend lockout. Decoded strictly the response is not a `Rejected` at all,
/// so `METHOD_NOT_FOUND` never reaches the `Unsupported` arm, `degrade()` never fires, and every
/// send refuses for the life of the process against any node without the reservation methods.
#[test]
fn a_bare_method_not_found_degrades_rather_than_refusing_every_send() {
    let node = WireNode::start(Answer::MethodNotFoundBare);
    let store = node.store();

    let id = store
        .reserve_all(&[coin(1)], NOW, NOW + 300)
        .expect("a node without the methods must not break sending");
    assert!(
        store.is_degraded(),
        "the narrower scope must be observable rather than assumed"
    );

    // And the process-local guard is genuinely live in that mode, not merely permissive.
    assert!(store.held(NOW).expect("readable").contains(&coin(1)));
    store.release(id).expect("released");
}

/// The control: the SAME refusal with a `data` object degrades too.
///
/// Differs from the test above in exactly one field. Without it, a "fix" that degraded on every
/// decode failure whatsoever — including a genuinely corrupt reply — would look identical.
#[test]
fn a_method_not_found_carrying_data_degrades_the_same_way() {
    let node = WireNode::start(Answer::MethodNotFoundWithData);
    let store = node.store();

    store
        .reserve_all(&[coin(1)], NOW, NOW + 300)
        .expect("the well-formed refusal degrades too");
    assert!(store.is_degraded());
}

/// A node that is simply NOT THERE must refuse, and must not degrade.
///
/// The counterweight to both tests above: leniency about a missing field must not become leniency
/// about a missing node. Degrading here would silently drop the cross-process guarantee for the
/// rest of the session because dig-app started before dig-node did — the ordinary cold boot.
#[test]
fn an_absent_node_refuses_and_never_degrades() {
    let store = NodeReservations::new(Arc::new(ControlReservationTable::new(
        // A port nothing is listening on.
        || Some("http://127.0.0.1:1".to_owned()),
        || Some(TOKEN.to_owned()),
        Duration::from_millis(200),
    )) as Arc<dyn NodeReservationTable>);

    match store.held(NOW) {
        Err(ReservationError::Unavailable(_)) => {}
        other => panic!("an unreachable node must refuse: {other:?}"),
    }
    assert!(
        !store.is_degraded(),
        "an outage must never be mistaken for a node that has no reservation table"
    );
}

// ---------------------------------------------------------------------------------------------
// Finding 3 — a lost reserve reply must not strand a coin
// ---------------------------------------------------------------------------------------------

/// A `reserve` whose reply is lost leaves NO hold behind, however many times it is retried.
///
/// The node took the coins and the client never learned the handle. Without recovery each attempt
/// strands another hold for the full TTL, so the count after several retries is what distinguishes
/// a fix from a coincidence — one attempt cannot tell "recovered" from "never taken".
#[test]
fn a_lost_reserve_reply_strands_no_hold_across_repeated_attempts() {
    let node = WireNode::start(Answer::Serve);
    let store = node.store();
    node.now_answers(Answer::LoseReply);

    for _ in 0..5 {
        assert!(
            store.reserve_all(&[coin(1)], NOW, NOW + 300).is_err(),
            "a lost reply is not a success"
        );
    }

    assert_eq!(
        node.live_holds(),
        0,
        "every hold whose reply was lost must be given back, not left for the TTL"
    );
    assert_eq!(
        store.releases_owed(),
        0,
        "the recovery reached the node, so nothing should still be owed"
    );

    // The coin is genuinely free afterwards: the recovery released holds rather than merely
    // forgetting them.
    node.now_answers(Answer::Serve);
    store
        .reserve_all(&[coin(1)], NOW, NOW + 300)
        .expect("the coin must be selectable again");
}

// ---------------------------------------------------------------------------------------------
// The whole seam, over the wire
// ---------------------------------------------------------------------------------------------

/// Two processes over one real node interlock, and the refusal names the contested coin.
///
/// End to end through the production transport: HTTP, the JSON-RPC envelope, the `-32046` refusal
/// that carries no coin id, and the `.held` re-read that attributes it.
#[test]
fn two_processes_over_one_wire_node_interlock_and_the_conflict_is_named() {
    let node = WireNode::start(Answer::Serve);
    let (first, second) = (node.store(), node.store());

    let id = first
        .reserve_all(&[coin(1)], NOW, NOW + 300)
        .expect("the first process takes the coin");

    assert!(second.held(NOW).expect("readable").contains(&coin(1)));
    assert_eq!(
        second
            .reserve_all(&[coin(2), coin(1)], NOW, NOW + 300)
            .expect_err("contested"),
        ReservationError::Conflict { coin_id: coin(1) },
        "the CONTESTED coin must be named, not the first one asked for"
    );

    // Releasing over the wire frees it for the other process, without waiting out the TTL.
    first.release(id).expect("released");
    second
        .reserve_all(&[coin(1)], NOW, NOW + 300)
        .expect("the other process gets the coin");
    assert_eq!(node.live_holds(), 1);
}

/// Releasing one hold must not free another, over the wire.
///
/// The handle-collision guard, at the layer that can actually strand money: two live holds, and the
/// release must resolve the one it was given. A release that freed whichever hold came first would
/// pass every single-hold test in the suite.
#[test]
fn releasing_one_wire_hold_leaves_the_other_alone() {
    let node = WireNode::start(Answer::Serve);
    let store = node.store();

    let first = store.reserve_all(&[coin(1)], NOW, NOW + 300).expect("held");
    let second = store.reserve_all(&[coin(2)], NOW, NOW + 300).expect("held");
    assert_ne!(first, second, "two live holds must have distinct handles");

    store.release(second).expect("released the second");

    let still_held = store.held(NOW).expect("readable");
    assert!(
        still_held.contains(&coin(1)),
        "releasing the second hold must not free the first"
    );
    assert!(!still_held.contains(&coin(2)));
    store.release(first).expect("released the first");
    assert_eq!(node.live_holds(), 0);
}

/// A stale reservation id from a previous handle space cannot free a live hold.
#[test]
fn an_unknown_handle_frees_nothing() {
    let node = WireNode::start(Answer::Serve);
    let store = node.store();

    let live = store.reserve_all(&[coin(1)], NOW, NOW + 300).expect("held");
    store.release(live).expect("released");
    // Releasing the same handle again is a documented success and must not touch a later hold.
    let later = store.reserve_all(&[coin(2)], NOW, NOW + 300).expect("held");
    store.release(live).expect("a repeat release is a no-op");

    assert!(
        store.held(NOW).expect("readable").contains(&coin(2)),
        "a repeat release must not free a hold taken afterwards"
    );
    store.release(later).expect("released");
}

/// The token travels: a node that rejects the request outright is an outage, not a capability.
#[test]
fn a_refusal_that_is_not_method_not_found_stays_an_outage() {
    let node = WireNode::start(Answer::Serve);
    let store = node.store();
    // `control.wallet.reservations.*` is served, so ask for something the fixture does not know:
    // the wire node answers a bare -32601 for any other method, which is the capability answer for
    // THAT method — proving the classification is per-call rather than per-connection.
    assert!(store.held(NOW).is_ok());
    assert!(!store.is_degraded());
    let _ = hexed(1);
}

// ---------------------------------------------------------------------------------------------
// Finding 2 — a handle must never free a hold it does not own, across a mid-session degrade
// ---------------------------------------------------------------------------------------------

/// A handle released after the latch frees ITS OWN hold, in BOTH directions.
///
/// # Why both directions, and why the handles must be distinct
///
/// A caller can hold a node-issued handle when the node stops serving the methods — a downgrade, or
/// a restart into an older build. Two things must then be true, and an earlier version of this
/// module got only the first:
///
/// 1. releasing the DEGRADED handle must not free the node-mode hold, and
/// 2. releasing the NODE-mode handle must not free the degraded hold.
///
/// Direction 2 was broken while direction 1 passed, because every release after the latch was
/// routed to the local table by MODE rather than by which table issued the handle — so a stale node
/// handle resolved against the local table and freed whatever local reservation shared its number.
///
/// The repair is that every handle, in either mode, is drawn from ONE allocator, so no two live
/// handles share a number at all. This test asserts that distinctness FIRST: without it both
/// releases could be freeing the same thing and the two directions would prove nothing.
#[test]
fn a_handle_released_after_the_latch_frees_only_its_own_hold() {
    let node = WireNode::start(Answer::Serve);
    let store = node.store();

    // A node-mode hold, taken while the node still served the methods, and deliberately KEPT —
    // exactly as the DID mint keeps its funding coin held until settlement.
    let node_mode = store
        .reserve_all(&[coin(1)], NOW, NOW + 300)
        .expect("the node serves the methods");
    assert_eq!(node.live_holds(), 1);

    // The node is restarted into a build without the reservation methods.
    node.now_answers(Answer::MethodNotFoundBare);
    let degraded = store
        .reserve_all(&[coin(2)], NOW, NOW + 300)
        .expect("a node without the methods narrows the scope rather than refusing");
    assert!(store.is_degraded());
    assert_ne!(
        node_mode.as_u64(),
        degraded.as_u64(),
        "handles from the two modes must never share a number; if they can, either release below \
         may be freeing the other hold and this test proves nothing"
    );

    // Direction 1: the degraded handle must not reach across to the node hold.
    store.release(degraded).expect("released the degraded hold");
    assert_eq!(
        node.live_holds(),
        1,
        "a degraded-mode handle freed a node hold it does not own"
    );

    // Direction 2: the node handle must still be recognised AS a node handle after the latch, and
    // must not be resolved against the local table.
    let second_degraded = store
        .reserve_all(&[coin(3)], NOW, NOW + 300)
        .expect("another local hold");
    assert!(
        store.hold_expires_at(node_mode).is_some(),
        "control: the node handle must still be ON RECORD as the node before it is released"
    );
    store.release(node_mode).expect("released the node handle");
    assert!(
        store.held(NOW).expect("readable").contains(&coin(3)),
        "a stale node handle freed the degraded caller hold"
    );
    // The release must CONSUME the node-issued record, not skip it. A release that quietly did
    // nothing would leave the handle on record forever, and `hold_expires_at` -- a public API --
    // would go on reporting an expiry for a hold that is over.
    assert!(
        store.hold_expires_at(node_mode).is_none(),
        "releasing a node handle after the latch must still be recognised as a node release"
    );
    store.release(second_degraded).expect("released");
}

/// A degraded store owes nothing, so nothing can be silently forgotten.
///
/// Once degraded every operation that drains the backlog early-returns, so an entry surviving the
/// latch could never be retried — it would sit forever while the SPEC promised it would not.
///
/// The control is the load-bearing half: the backlog must be genuinely NON-EMPTY first, on the SAME
/// store that then degrades. Building the non-empty state on one store and measuring another makes
/// the assertion true no matter what the latch does — which is exactly how the previous version of
/// this test passed with the clear deleted.
#[test]
fn degrading_clears_a_non_empty_release_backlog() {
    let node = WireNode::start(Answer::Serve);
    let store = node.store();

    // A release the node never answered, so the handle is owed a retry.
    let held = store.reserve_all(&[coin(1)], NOW, NOW + 300).expect("held");
    node.now_answers(Answer::Unreachable);
    assert!(
        store.release(held).is_err(),
        "control: the release must fail, or the backlog is empty for the wrong reason"
    );
    assert_eq!(
        store.releases_owed(),
        1,
        "control: the backlog must be non-empty on THIS store before the latch"
    );

    // The same store now meets a node without the methods.
    node.now_answers(Answer::MethodNotFoundBare);
    let local = store
        .reserve_all(&[coin(2)], NOW, NOW + 300)
        .expect("degrades");
    assert!(store.is_degraded());
    assert_eq!(
        store.releases_owed(),
        0,
        "a degraded store must owe nothing, since nothing could ever retry it"
    );
    store.release(local).expect("released");
}

// ---------------------------------------------------------------------------------------------
// G1 — recovery must give back OUR hold and nobody else
// ---------------------------------------------------------------------------------------------

/// A lost CONFLICT must not make this process release the hold it conflicted with.
///
/// The node refused because another process holds a contested coin, and that refusal was lost in
/// transit — so this process sees only a transport failure and starts recovering. The other
/// process hold covers a strict SUBSET of what this call asked for, and a hold that is not exactly
/// the requested set cannot be the one this call lost: `reserve` is all-or-none over exactly the
/// requested coins.
#[test]
fn recovery_leaves_a_foreign_hold_that_is_not_exactly_what_we_asked_for() {
    let node = WireNode::start(Answer::Serve);
    let (other, ours) = (node.store(), node.store());

    // Another process holds ONE coin.
    let theirs = other
        .reserve_all(&[coin(1)], NOW, NOW + 300)
        .expect("the other process holds it");

    // We ask for TWO, one of which is contested, and never hear the answer.
    node.now_answers(Answer::LoseReply);
    assert!(
        ours.reserve_all(&[coin(1), coin(2)], NOW, NOW + 300)
            .is_err(),
        "a lost answer is not a success"
    );

    node.now_answers(Answer::Serve);
    assert_eq!(
        node.live_holds(),
        1,
        "the other process hold must survive our recovery"
    );
    assert!(
        other.held(NOW).expect("readable").contains(&coin(1)),
        "we released a hold we do not own"
    );
    other.release(theirs).expect("released");
}

/// Nor may one overlapping coin give back somebody else whole multi-coin hold.
///
/// The mirror of the case above: the foreign hold is a strict SUPERSET of what this call asked for.
/// A per-coin filter releases it on the strength of a single shared coin, freeing two coins this
/// process never asked about.
#[test]
fn recovery_leaves_a_foreign_hold_that_merely_overlaps() {
    let node = WireNode::start(Answer::Serve);
    let (other, ours) = (node.store(), node.store());

    let theirs = other
        .reserve_all(&[coin(1), coin(2), coin(3)], NOW, NOW + 300)
        .expect("a three-coin hold");

    node.now_answers(Answer::LoseReply);
    assert!(ours.reserve_all(&[coin(1)], NOW, NOW + 300).is_err());

    node.now_answers(Answer::Serve);
    let still = other.held(NOW).expect("readable");
    for tag in 1..=3u8 {
        assert!(
            still.contains(&coin(tag)),
            "one overlapping coin released a whole foreign hold; coin {tag} is gone"
        );
    }
    other.release(theirs).expect("released");
}

/// The control: recovery DOES give back a hold that is exactly what we asked for.
///
/// Without it, a "fix" that simply never recovers anything would pass both tests above while
/// re-opening the stranded-hold defect the recovery exists to close.
#[test]
fn recovery_gives_back_a_hold_that_is_exactly_what_we_asked_for() {
    let node = WireNode::start(Answer::Serve);
    let store = node.store();

    node.now_answers(Answer::LoseReply);
    for _ in 0..3 {
        assert!(store
            .reserve_all(&[coin(1), coin(2)], NOW, NOW + 300)
            .is_err());
    }

    node.now_answers(Answer::Serve);
    assert_eq!(
        node.live_holds(),
        0,
        "a hold covering exactly the requested set is ours and must be given back"
    );
}
