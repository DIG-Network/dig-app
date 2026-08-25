//! What [`NodeReservations`] must do when the table it depends on lives in another process.
//!
//! # What the double here CANNOT see
//!
//! [`FakeNode`] is an in-memory table behind one mutex, standing in for dig-node's. It is honest
//! about conflicts, expiry, TTL clamping and release. It is blind to:
//!
//! - **The wire.** No IPC framing, no JSON-RPC envelope, no control token, no timeout. The mapping
//!   from a `ControlFailure` and from the codes `-32044` / `-32045` onto [`NodeTableError`] lives in
//!   [`super::reservations_control`] and is proved by ITS tests; nothing here exercises it.
//! - **The node's atomicity.** `reserve_all` is atomic here because one `Mutex` makes it so. That
//!   proves this store USES an atomic primitive correctly; it cannot prove dig-node's table is one.
//! - **Whether dig-node behaves as its contract says.** The double implements the contract; a serve
//!   side that violates it — a partial reservation, a lapsed hold still reported, an unclamped TTL —
//!   is by construction inexpressible here. That is what an end-to-end against a live node is for,
//!   and the serve side is still in flight.
//! - **Concurrency in wall-clock time.** The interlock tests are deterministic and sequenced. They
//!   prove the boundary is consulted, not that a real race resolves one way.
//!
//! It is deliberately faulty PER OPERATION rather than all-or-nothing. dig-account's own gate found
//! a false green in exactly this shape: a double that failed on both read and write let the write
//! path mask a read path that failed OPEN. Here `fail_held`, `fail_reserve` and `fail_release` move
//! independently, so a fix in one path cannot stand in for a missing one in another.

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use chia_protocol::Bytes32;
use dig_account::wallet::reservation::{
    CoinReservationStore, ReservationError, DEFAULT_RESERVATION_TTL_SECS,
};

use super::reservations::{
    HeldCoin, NodeHeld, NodeHold, NodeReservationTable, NodeReservations, NodeTableError,
};

/// A fixed instant, so every lifetime here is measured against a time the test states.
///
/// Passing a small literal like `100` through an API that also sees a real clock is the
/// fixture-time trap: every record is then already expired by ~1.8 billion seconds, and the test
/// exercises only the expired path while claiming to exercise establishment.
const NOW: u64 = 1_800_000_000;

/// A distinct coin id per byte, so a failure names WHICH coin.
fn coin(tag: u8) -> Bytes32 {
    Bytes32::new([tag; 32])
}

/// One reservation inside the fake node.
#[derive(Debug, Clone)]
struct Row {
    coins: Vec<Bytes32>,
    expires_at_unix: u64,
}

/// The node's table, shared by every dig-app process in a test.
///
/// Sharing ONE `Arc<FakeNode>` between two `NodeReservations` is what makes a test a two-process
/// test: each store is a separate process's view, and the node is the single thing between them.
#[derive(Debug)]
struct FakeNode {
    rows: Mutex<HashMap<u64, Row>>,
    next_id: AtomicU64,
    /// The node's own clock, which the caller never supplies.
    clock: AtomicU64,
    /// The longest lifetime this node grants, whatever a caller asks for.
    max_ttl_secs: AtomicU64,
    fail_held: AtomicBool,
    fail_reserve: AtomicBool,
    fail_release: AtomicBool,
    /// Take the hold, then lose the reply — the non-idempotent-POST failure a timeout produces.
    ///
    /// Distinct from `fail_reserve`, which models a call the node never applied. Collapsing the two
    /// would make the STRANDED hold inexpressible, and the stranded hold is the whole defect.
    lose_reserve_reply: AtomicBool,
    /// Every `ttl_secs` the node was ASKED for, so a test can prove the request was not echoed back.
    requested_ttls: Mutex<Vec<u64>>,
}

impl Default for FakeNode {
    fn default() -> Self {
        Self {
            rows: Mutex::new(HashMap::new()),
            next_id: AtomicU64::new(0),
            clock: AtomicU64::new(NOW),
            max_ttl_secs: AtomicU64::new(u64::MAX),
            fail_held: AtomicBool::new(false),
            fail_reserve: AtomicBool::new(false),
            fail_release: AtomicBool::new(false),
            lose_reserve_reply: AtomicBool::new(false),
            requested_ttls: Mutex::new(Vec::new()),
        }
    }
}

impl FakeNode {
    fn shared() -> Arc<Self> {
        Arc::new(Self::default())
    }

    fn set_clock(&self, at: u64) {
        self.clock.store(at, Ordering::SeqCst);
    }

    fn now(&self) -> u64 {
        self.clock.load(Ordering::SeqCst)
    }

    /// The coins the node believes are held, ignoring every fault switch.
    ///
    /// The tests' ground truth. An assertion about what the STORE returned can be satisfied by a
    /// store that never asked, so the node's own view is what says whether the boundary was crossed.
    fn truly_held(&self) -> Vec<Bytes32> {
        self.rows_now()
            .into_iter()
            .flat_map(|row| row.coins)
            .collect()
    }

    /// The unexpired rows, as of the node's own clock.
    fn rows_now(&self) -> Vec<Row> {
        let now = self.now();
        let rows = self.rows.lock().expect("fake node rows");
        rows.values()
            .filter(|row| row.expires_at_unix >= now)
            .map(|row| Row {
                coins: row.coins.clone(),
                expires_at_unix: row.expires_at_unix,
            })
            .collect()
    }
}

impl NodeReservationTable for FakeNode {
    fn held(&self) -> Result<NodeHeld, NodeTableError> {
        if self.fail_held.load(Ordering::SeqCst) {
            return Err(NodeTableError::Unavailable(
                "the node did not answer".into(),
            ));
        }
        let now = self.now();
        let rows = self.rows.lock().expect("fake node rows");
        let reserved = rows
            .iter()
            .filter(|(_, row)| row.expires_at_unix >= now)
            .flat_map(|(id, row)| {
                row.coins.iter().map(move |coin_id| HeldCoin {
                    coin_id: *coin_id,
                    reservation_id: format!("node-{id}"),
                    expires_at_unix: row.expires_at_unix,
                })
            })
            .collect();
        Ok(NodeHeld {
            reserved,
            as_of_unix: now,
        })
    }

    fn reserve_all(&self, coins: &[Bytes32], ttl_secs: u64) -> Result<NodeHold, NodeTableError> {
        self.requested_ttls
            .lock()
            .expect("requested ttls")
            .push(ttl_secs);
        if self.fail_reserve.load(Ordering::SeqCst) {
            return Err(NodeTableError::Unavailable(
                "the node did not answer".into(),
            ));
        }
        let now = self.now();
        let mut rows = self.rows.lock().expect("fake node rows");
        rows.retain(|_, row| row.expires_at_unix >= now);
        let held: Vec<Bytes32> = rows
            .values()
            .flat_map(|row| row.coins.iter().copied())
            .collect();
        if coins.iter().any(|c| held.contains(c)) {
            // The contract cannot name the clashing coin, and neither may the double: a double
            // that leaked the name would make attribution look solved when it is not.
            return Err(NodeTableError::Conflict);
        }
        let applied = ttl_secs.min(self.max_ttl_secs.load(Ordering::SeqCst));
        let id = self.next_id.fetch_add(1, Ordering::SeqCst);
        let expires_at_unix = now + applied;
        rows.insert(
            id,
            Row {
                coins: coins.to_vec(),
                expires_at_unix,
            },
        );
        if self.lose_reserve_reply.load(Ordering::SeqCst) {
            // The hold is TAKEN and the caller is told nothing — the exact shape of a non-idempotent
            // POST that timed out. A fault that refused before writing could not express this.
            return Err(NodeTableError::Unavailable("the reply was lost".into()));
        }
        Ok(NodeHold {
            reservation_id: format!("node-{id}"),
            ttl_secs: applied,
            expires_at_unix,
        })
    }

    fn release(&self, reservation_id: &str) -> Result<(), NodeTableError> {
        if self.fail_release.load(Ordering::SeqCst) {
            return Err(NodeTableError::Unavailable(
                "the release did not reach the node".into(),
            ));
        }
        if let Some(id) = reservation_id
            .strip_prefix("node-")
            .and_then(|n| n.parse().ok())
        {
            self.rows.lock().expect("fake node rows").remove(&id);
        }
        // A handle naming no live reservation is a SUCCESS, per the contract.
        Ok(())
    }
}

/// The store one "process" in a test gets, over a shared node.
fn app(node: &Arc<FakeNode>) -> NodeReservations {
    NodeReservations::new(node.clone() as Arc<dyn NodeReservationTable>)
}

fn expiry() -> u64 {
    NOW + DEFAULT_RESERVATION_TTL_SECS
}

// ---------------------------------------------------------------------------------------------
// The boundary this epic exists to close
// ---------------------------------------------------------------------------------------------

/// A reservation taken in one process is visible to the OTHER process.
///
/// The two stores are separate instances — separate allocators, separate backlogs — exactly as two
/// processes would be. A test where only one store reserves proves nothing about the boundary.
#[test]
fn a_coin_held_by_one_process_is_held_against_the_other() {
    let node = FakeNode::shared();
    let (first, second) = (app(&node), app(&node));

    first
        .reserve_all(&[coin(1)], NOW, expiry())
        .expect("the first process takes the coin");

    let seen = second.held(NOW).expect("the second process can ask");
    assert!(
        seen.contains(&coin(1)),
        "the second process must see the first process's reservation; it saw {seen:?}"
    );
}

/// And the other process is REFUSED that coin, BY NAME, as a conflict rather than a shortfall.
///
/// Naming it is the load-bearing half. The node cannot say which coin clashed, so the name can only
/// come from this store re-reading `.held` and intersecting — and dig-account's retry loop excludes
/// the named coin, so an unnamed or wrongly-named conflict cannot converge.
#[test]
fn the_second_process_is_refused_by_name_and_not_as_a_shortfall() {
    let node = FakeNode::shared();
    let (first, second) = (app(&node), app(&node));

    first.reserve_all(&[coin(1)], NOW, expiry()).expect("held");

    let refusal = second
        .reserve_all(&[coin(1)], NOW, expiry())
        .expect_err("the second process must not get the same coin");
    assert_eq!(
        refusal,
        ReservationError::Conflict { coin_id: coin(1) },
        "a busy coin is a conflict about THAT coin, never a shortfall and never an outage"
    );
}

/// The named coin is the CONTESTED one, not merely the first one asked for.
///
/// Two coins, only the second of which is held. A store that reported `coins[0]` would pass the test
/// above and still send the retry loop to exclude a free coin forever.
#[test]
fn the_conflict_names_the_contested_coin_not_the_first_requested() {
    let node = FakeNode::shared();
    let (first, second) = (app(&node), app(&node));

    first.reserve_all(&[coin(2)], NOW, expiry()).expect("held");

    let refusal = second
        .reserve_all(&[coin(1), coin(2)], NOW, expiry())
        .expect_err("contested");
    assert_eq!(refusal, ReservationError::Conflict { coin_id: coin(2) });
}

/// A conflict takes NOTHING — including the coins that were free.
///
/// One coin cannot express this: a store that reserved as it went would leave `coin(1)` held under a
/// reservation the caller has no handle for, and so could never release.
#[test]
fn a_conflicted_reservation_takes_none_of_its_coins() {
    let node = FakeNode::shared();
    let (first, second) = (app(&node), app(&node));

    first.reserve_all(&[coin(2)], NOW, expiry()).expect("held");
    let _ = second
        .reserve_all(&[coin(1), coin(2)], NOW, expiry())
        .expect_err("contested");

    assert!(
        !node.truly_held().contains(&coin(1)),
        "the uncontested coin must be left free after an all-or-none refusal"
    );
    second
        .reserve_all(&[coin(1)], NOW, expiry())
        .expect("the free coin remains selectable");
}

/// A conflict that cannot be attributed REFUSES, and never invents a coin id.
///
/// The clash lapsed between the refusal and the re-read, so the node now holds nothing. A store that
/// guessed would name a free coin, which dig-account then excludes while re-selecting the busy one —
/// a loop that cannot converge, reported as a confident lie about a specific coin.
#[test]
fn an_unattributable_conflict_refuses_rather_than_naming_a_coin() {
    /// A node that refuses every reservation as a conflict while holding nothing at all.
    #[derive(Debug, Default)]
    struct AlwaysConflicts;
    impl NodeReservationTable for AlwaysConflicts {
        fn held(&self) -> Result<NodeHeld, NodeTableError> {
            Ok(NodeHeld {
                reserved: Vec::new(),
                as_of_unix: NOW,
            })
        }
        fn reserve_all(&self, _: &[Bytes32], _: u64) -> Result<NodeHold, NodeTableError> {
            Err(NodeTableError::Conflict)
        }
        fn release(&self, _: &str) -> Result<(), NodeTableError> {
            Ok(())
        }
    }

    let store = NodeReservations::new(Arc::new(AlwaysConflicts));
    match store.reserve_all(&[coin(1)], NOW, expiry()) {
        Err(ReservationError::Unavailable(_)) => {}
        other => panic!("an unattributable conflict must refuse, not guess: {other:?}"),
    }
}

// ---------------------------------------------------------------------------------------------
// Release — on confirm, on reject, on timeout, and when the release call itself fails
// ---------------------------------------------------------------------------------------------

/// Releasing on a settled spend frees the coin AT THE NODE, not merely in this process.
///
/// Asserted against the node's own view: a store that released locally and never crossed the
/// boundary would satisfy an assertion about its own `held()` while leaving the other process
/// locked out for the full TTL.
#[test]
fn release_on_confirm_frees_the_coin_at_the_node() {
    let node = FakeNode::shared();
    let (first, second) = (app(&node), app(&node));

    let id = first.reserve_all(&[coin(1)], NOW, expiry()).expect("held");
    first.release(id).expect("release reaches the node");

    assert!(
        node.truly_held().is_empty(),
        "the node still holds {:?} after a release",
        node.truly_held()
    );
    second
        .reserve_all(&[coin(1)], NOW, expiry())
        .expect("the other process can now take the coin");
}

/// The reject path is the same call, and must free the coin just as completely.
///
/// This is how dig-account's guard behaves: a build that fails after reserving drops its handle,
/// which releases. The coin must come back for the OTHER process, not just this one.
#[test]
fn release_on_reject_frees_the_coin_for_the_other_process() {
    let node = FakeNode::shared();
    let (first, second) = (app(&node), app(&node));

    let id = first.reserve_all(&[coin(1)], NOW, expiry()).expect("held");
    first
        .release(id)
        .expect("the refused spend gives its coin back");

    second
        .reserve_all(&[coin(1)], NOW, expiry())
        .expect("a rejected spend must not hold the coin");
}

/// A process that dies without releasing loses the coin to the TTL, and not before it.
///
/// Both bounds are asserted. A test that only checks the far side cannot tell a 300 s TTL from a 3 s
/// one — and shortening the TTL is precisely the wrong trade, swapping a visible lockout for an
/// invisible double-select.
#[test]
fn an_abandoned_reservation_lapses_at_the_ttl_and_not_before() {
    let node = FakeNode::shared();
    let (first, second) = (app(&node), app(&node));

    first.reserve_all(&[coin(1)], NOW, expiry()).expect("held");
    drop(first); // the process is gone; nothing released.

    let at_the_bound = NOW + DEFAULT_RESERVATION_TTL_SECS;
    node.set_clock(at_the_bound);
    assert!(
        second
            .held(at_the_bound)
            .expect("readable")
            .contains(&coin(1)),
        "a reservation is still held AT its expiry instant"
    );

    node.set_clock(at_the_bound + 1);
    assert!(
        !second
            .held(at_the_bound + 1)
            .expect("readable")
            .contains(&coin(1)),
        "a reservation must lapse after its expiry instant"
    );
}

/// A release that does not reach the node is REMEMBERED and retried, so the coin is not stranded.
///
/// Without the retry the coin stays held at the node for the full TTL even though the spend it
/// guarded is long over — and dig-account's `Drop` can neither report that nor try again.
#[test]
fn a_failed_release_is_retried_and_the_coin_comes_back() {
    let node = FakeNode::shared();
    let (first, second) = (app(&node), app(&node));

    let id = first.reserve_all(&[coin(1)], NOW, expiry()).expect("held");
    node.fail_release.store(true, Ordering::SeqCst);

    assert!(
        first.release(id).is_err(),
        "a release that did not reach the node must say so rather than report success"
    );
    assert_eq!(
        first.releases_owed(),
        1,
        "the unreleased node reservation must be remembered"
    );
    assert!(
        node.truly_held().contains(&coin(1)),
        "control: while the node is unreachable the coin is genuinely still held there"
    );

    // The node comes back, and the next ordinary operation settles the debt.
    node.fail_release.store(false, Ordering::SeqCst);
    let _ = first.held(NOW).expect("readable");

    assert_eq!(first.releases_owed(), 0, "the backlog must drain");
    second
        .reserve_all(&[coin(1)], NOW, expiry())
        .expect("the other process gets the coin back without waiting out the TTL");
}

/// Releasing an id twice, or one the node has already expired, is a success and not an error.
///
/// dig-account makes this explicit, and so does the control contract (`released: false` is a
/// success): a caller releasing on confirmation cannot know whether the TTL got there first, and
/// making that race an error pushes callers toward ignoring the result.
#[test]
fn releasing_an_already_released_reservation_is_not_an_error() {
    let node = FakeNode::shared();
    let store = app(&node);

    let id = store.reserve_all(&[coin(1)], NOW, expiry()).expect("held");
    store.release(id).expect("first release");
    store
        .release(id)
        .expect("a second release is a no-op, not a failure");
}

/// The release backlog is bounded, so an hour of unreachable node cannot grow without limit.
#[test]
fn the_release_backlog_is_bounded() {
    let node = FakeNode::shared();
    let store = app(&node);

    node.fail_release.store(true, Ordering::SeqCst);
    for tag in 0..80u8 {
        let id = store
            .reserve_all(&[coin(tag)], NOW, expiry())
            .expect("distinct coins never conflict");
        let _ = store.release(id);
    }
    assert!(
        store.releases_owed() <= 64,
        "the backlog grew to {}",
        store.releases_owed()
    );
}

// ---------------------------------------------------------------------------------------------
// The node's terms: its clock, and its TTL
// ---------------------------------------------------------------------------------------------

/// The expiry the NODE applied is the one this store records, not the one it asked for.
///
/// The node clamps. A client that kept its own number would believe coins were held for another
/// four minutes after they had already become selectable, and would release far too late.
///
/// Asserted on the RECORDED expiry rather than on the outcome of a release, because a release is a
/// no-op either way — so an outcome assertion here passes for both the right implementation and the
/// wrong one. An earlier version of this test did exactly that and a mutation substituting the
/// requested lifetime survived it.
#[test]
fn the_expiry_the_node_applied_is_the_one_recorded_not_the_one_requested() {
    let node = FakeNode::shared();
    let store = app(&node);
    node.max_ttl_secs.store(60, Ordering::SeqCst); // far shorter than the 300 s asked for.

    let id = store
        .reserve_all(&[coin(1)], NOW, expiry())
        .expect("the node grants a shorter hold than requested");

    assert_eq!(
        node.requested_ttls.lock().expect("ttls").as_slice(),
        &[DEFAULT_RESERVATION_TTL_SECS],
        "the store must ASK for dig-account's TTL rather than pre-clamping it"
    );
    assert_eq!(
        store.hold_expires_at(id),
        Some(NOW + 60),
        "the recorded expiry must be the node's applied one, not the {DEFAULT_RESERVATION_TTL_SECS}s requested"
    );
    assert_ne!(
        store.hold_expires_at(id),
        Some(expiry()),
        "recording the REQUESTED expiry is the defect this test exists to catch"
    );
}

/// Releasing a hold the node has already lapsed is a success, and clears the record.
#[test]
fn a_lapsed_hold_releases_cleanly_and_stops_being_recorded() {
    let node = FakeNode::shared();
    let store = app(&node);
    node.max_ttl_secs.store(60, Ordering::SeqCst);

    let id = store.reserve_all(&[coin(1)], NOW, expiry()).expect("held");
    node.set_clock(NOW + 61);
    assert!(
        !node.truly_held().contains(&coin(1)),
        "control: the node's own clamp must have lapsed the hold"
    );

    store
        .release(id)
        .expect("releasing a lapsed hold is a success");
    assert_eq!(
        store.hold_expires_at(id),
        None,
        "a released handle must stop being recorded"
    );
}

/// A stale snapshot is not an answer.
///
/// A node replaying an old view UNDER-reports what is held, which is the one direction that restores
/// the double-select. `as_of_unix` exists so a client can see that; a client that read the field and
/// did nothing with it would make the contract decoration.
#[test]
fn a_snapshot_far_behind_this_clock_refuses_rather_than_under_reporting() {
    let node = FakeNode::shared();
    let store = app(&node);
    store.reserve_all(&[coin(1)], NOW, expiry()).expect("held");

    // The node's clock is frozen at NOW while this process has moved on by an hour.
    match store.held(NOW + 3600) {
        Err(ReservationError::Unavailable(_)) => {}
        other => panic!("a stale snapshot must refuse: {other:?}"),
    }
}

/// A node whose clock reads AHEAD of ours is fine, and must not be refused.
///
/// The control test for the guard above. Clock drift is ordinary; refusing on the SAFE direction
/// would turn a few seconds of skew into a wallet that cannot spend at all.
#[test]
fn a_node_clock_ahead_of_ours_is_still_an_answer() {
    let node = FakeNode::shared();
    let store = app(&node);
    node.set_clock(NOW + 3600);

    store
        .held(NOW)
        .expect("a node ahead of us expires holds LATER, which is the safe direction");
}

// ---------------------------------------------------------------------------------------------
// Fail direction
// ---------------------------------------------------------------------------------------------

/// A node that cannot answer a READ refuses the build, and never answers "nothing is held".
///
/// This is the fail-open that matters most: an empty set is indistinguishable at the call site from
/// a healthy wallet with no reservations, so it silently restores the double-select.
#[test]
fn an_unreadable_node_refuses_rather_than_reporting_an_empty_set() {
    let node = FakeNode::shared();
    let store = app(&node);
    node.fail_held.store(true, Ordering::SeqCst);

    match store.held(NOW) {
        Err(ReservationError::Unavailable(_)) => {}
        Err(other) => panic!("an unreachable node is not a conflict about a coin: {other:?}"),
        Ok(held) => panic!("a node that could not be read must not answer with {held:?}"),
    }
}

/// A node that cannot answer a WRITE refuses too, and leaves nothing held locally.
///
/// Independent of the read fault above: with a single fault switch the two tests would exercise one
/// guard, and a fail-open on either path could hide behind the other.
#[test]
fn a_node_that_refuses_a_write_leaves_nothing_reserved_locally() {
    let node = FakeNode::shared();
    let store = app(&node);
    node.fail_reserve.store(true, Ordering::SeqCst);

    match store.reserve_all(&[coin(1)], NOW, expiry()) {
        Err(ReservationError::Unavailable(_)) => {}
        other => panic!("an unreachable node must refuse the write: {other:?}"),
    }

    // Nothing may be left held on this side either, or the process would refuse its own coin over a
    // reservation that was never taken anywhere.
    node.fail_reserve.store(false, Ordering::SeqCst);
    store
        .reserve_all(&[coin(1)], NOW, expiry())
        .expect("a failed write must not leave the coin locally held");
}

/// A zero-length lifetime is refused rather than sent.
///
/// The contract reads an absent `ttl_secs` as "your default", so sending zero would silently ask for
/// something other than what the caller said — and a hold that lapses before the spend it guards is
/// a guard that is off while appearing to be on.
#[test]
fn a_zero_lifetime_is_refused_rather_than_asking_for_the_default() {
    let node = FakeNode::shared();
    let store = app(&node);

    match store.reserve_all(&[coin(1)], NOW, NOW) {
        Err(ReservationError::Unavailable(_)) => {}
        other => panic!("a zero lifetime must be refused: {other:?}"),
    }
    assert!(
        node.requested_ttls.lock().expect("ttls").is_empty(),
        "a zero lifetime must never reach the node at all"
    );
}

// ---------------------------------------------------------------------------------------------
// A node that serves no reservation table at all
// ---------------------------------------------------------------------------------------------

/// A node built before the reservation contract: every call resolves no such method.
///
/// # This double returns `Unsupported` DIRECTLY, and a real node cannot
///
/// A real dig-node answers an unresolved method with a bare `-32601` carrying no `data` field, and
/// turning that into `Unsupported` is `reservations_control::classify`'s job — a job this double
/// skips entirely. That skip is what let the strict-decode defect hide: the classification was
/// never exercised here, so a `data`-less refusal that never reached the `Unsupported` arm at all
/// looked fine.
///
/// So this double proves only what `NodeReservations` does GIVEN an `Unsupported`. That the wire
/// actually produces one is proved in `reservations_wire_tests`, over a real socket, against the
/// bytes dig-node emits. Neither is sufficient alone.
#[derive(Debug, Default)]
struct NodeWithoutReservations {
    calls: AtomicU64,
}

impl NodeReservationTable for NodeWithoutReservations {
    fn held(&self) -> Result<NodeHeld, NodeTableError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Err(NodeTableError::Unsupported)
    }
    fn reserve_all(&self, _: &[Bytes32], _: u64) -> Result<NodeHold, NodeTableError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Err(NodeTableError::Unsupported)
    }
    fn release(&self, _: &str) -> Result<(), NodeTableError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Err(NodeTableError::Unsupported)
    }
}

/// Against a node that serves no reservation table, the wallet still WORKS — narrowed, not broken.
///
/// This is the whole reason `Unsupported` is not `Unavailable`. Refusing here would leave every send
/// on every pre-contract node permanently unable to build, and no retry could fix it, because no
/// retry conjures a method that does not exist. The scope falls back to dig-account's own default:
/// the double-select is still closed among callers inside this process.
#[test]
fn a_node_without_the_table_narrows_the_scope_instead_of_refusing_every_build() {
    let store = NodeReservations::new(Arc::new(NodeWithoutReservations::default()));

    let id = store
        .reserve_all(&[coin(1)], NOW, expiry())
        .expect("a node without the table must not break sending");
    assert!(
        store.is_degraded(),
        "the narrower scope must be OBSERVABLE, or a surface will claim a guarantee it lacks"
    );

    // And the process-local guard is genuinely live, not merely absent-and-permissive.
    assert!(store.held(NOW).expect("readable").contains(&coin(1)));
    match store.reserve_all(&[coin(1)], NOW, expiry()) {
        Err(ReservationError::Conflict { coin_id }) => assert_eq!(coin_id, coin(1)),
        other => panic!("the in-process double-select must still be closed: {other:?}"),
    }

    store.release(id).expect("released");
    store
        .reserve_all(&[coin(1)], NOW, expiry())
        .expect("release frees the coin in degraded mode too");
}

/// Degraded mode LATCHES: it is decided once, not re-probed on every selection.
///
/// Re-asking would put a failing round trip in front of every coin selection on an old node, and —
/// worse — a node that gained the capability mid-session would then arbitrate against holds already
/// taken under the local table, which it cannot see.
#[test]
fn degraded_mode_is_latched_rather_than_re_probed() {
    let node = Arc::new(NodeWithoutReservations::default());
    let store = NodeReservations::new(node.clone() as Arc<dyn NodeReservationTable>);

    let _ = store
        .reserve_all(&[coin(1)], NOW, expiry())
        .expect("degrades");
    let after_first = node.calls.load(Ordering::SeqCst);

    for tag in 2..6u8 {
        let _ = store
            .reserve_all(&[coin(tag)], NOW, expiry())
            .expect("local");
        let _ = store.held(NOW).expect("local");
    }
    assert_eq!(
        node.calls.load(Ordering::SeqCst),
        after_first,
        "the node must not be re-probed once it has said it serves no table"
    );
}

/// An UNREACHABLE node is not an unsupported one, and must not degrade.
///
/// The control that keeps the fallback from becoming a universal fail-open. A node that is merely
/// down may answer next time, so refusing is correct; degrading on it would silently drop the
/// cross-process guarantee for the rest of the session over one dropped connection.
#[test]
fn an_unreachable_node_does_not_degrade_the_scope() {
    let node = FakeNode::shared();
    let store = app(&node);
    node.fail_held.store(true, Ordering::SeqCst);

    assert!(store.held(NOW).is_err(), "an outage refuses");
    assert!(
        !store.is_degraded(),
        "an outage must never be mistaken for a node that has no reservation table"
    );
}
