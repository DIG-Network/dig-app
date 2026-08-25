//! The cross-process coin-reservation table: dig-account's reservation seam, backed by dig-node
//! instead of by a table private to this process.
//!
//! # Why a second table exists at all
//!
//! `dig-account` closes the double-select *within one process*: between selecting a coin and that
//! coin's spend confirming, the chain still reports the input UNSPENT, so a second build in that
//! window picks the same coin. Its `LocalReservations` table makes that impossible for callers
//! inside one process, and its module docs say plainly what it cannot do:
//!
//! > Two processes sharing one wallet — dig-app and a dig-node serving the same keys — each holding
//! > their own `LocalReservations` would re-create exactly the double-select each of them fixes
//! > locally.
//!
//! This module is the store that removes that limit for dig-app.
//!
//! # Who owns the truth
//!
//! **dig-node does.** There is exactly ONE authoritative reservation table, it lives in the node,
//! and every conflict decision is the node's. `NodeReservations` holds no
//! opinion the node could disagree with: it asks, and it reports the answer.
//!
//! It does keep three pieces of purely local bookkeeping, and none of them is a rival table:
//!
//! - **A handle allocator.** `ReservationId` is minted by `dig-account`, has a private field and no
//!   public constructor, so the only way an out-of-crate store can produce one is to take it from a
//!   `LocalReservations`. One is kept for exactly that, and it is drawn against **synthetic ids
//!   that are not coins** — so it can never form an opinion about a coin and can never disagree
//!   with the node. `NodeReservations::held` returns the node's answer alone.
//! - **The node's own expiry per handle**, because the node clamps the requested lifetime and a
//!   client that kept its own number would believe coins were held after they became selectable.
//! - **A release backlog.** See "the release path" below.
//!
//! The one case where a genuinely local table answers is DEGRADED mode: a node that serves no
//! reservation table at all. That is a narrowing to `dig-account`'s own default scope rather than a
//! second opinion, it is latched for the session, and it is reported rather than assumed.
//!
//! # The fail direction, which is the whole point of a remote store
//!
//! A local table can fail in two ways: a poisoned lock and an unreadable clock. A remote one adds
//! every way a process boundary can fail — unreachable, slow, refused, answering something this
//! build cannot parse. Every one of those becomes `ReservationError::Unavailable`, which REFUSES
//! the build.
//!
//! It must never become an empty `held()`, because "the node holds nothing" and "I could not ask the
//! node" read identically at the call site and mean opposite things: the first permits a selection,
//! the second cannot vouch for one. A guard that answers "nothing is reserved" when it does not know
//! is a guard that is off.
//!
//! Nor may it become `ReservationError::Conflict`. A conflict is a *true statement about a coin* —
//! it reaches the person as "those coins are busy, try again in a few minutes", and it is
//! deliberately not `InsufficientFunds`, because insufficient funds sends someone to an exchange and
//! saying that about a five-minute wait is a lie. "I could not reach the node" is a third thing
//! again, and it says so.
//!
//! # The release path is the hard half
//!
//! A reservation that is never released is a wallet that locks itself out of its own money: coins
//! that are the user's, that the chain says are spendable, that this app refuses to select. Over a
//! wire, the release call itself can fail — and dig-account's `HeldCoins::drop` can neither report
//! nor retry.
//!
//! So a failed release is REMEMBERED, in this store's release backlog, and retried at the head of
//! the next `held` or `reserve_all` — both of which the wallet performs constantly. The backlog
//! holds node-minted ids and nothing else; it is bounded, and the oldest entry is dropped rather
//! than letting it grow without limit.
//!
//! The TTL remains the backstop, and it is deliberately NOT shortened to compensate. A shorter TTL
//! trades a lockout the user notices for a double-select they do not, which is the worse of the two.

use std::collections::{HashMap, HashSet, VecDeque};
use std::fmt::Debug;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, OnceLock};

use chia_protocol::Bytes32;
use dig_account::wallet::reservation::{
    CoinReservationStore, CoinReservations, LocalReservations, ReservationError, ReservationId,
};
use dig_account::SystemClock;

/// Why this store keeps a `LocalReservations` inside it.
///
/// `dig-account` documents `CoinReservationStore` as the seam an out-of-process table implements,
/// but `ReservationId` is a newtype with a private field, no public constructor and — by explicit
/// design — no `from_u64`. So `reserve_all` has a return type no crate outside `dig-account` can
/// build, and the only obtainable source of one is a real `LocalReservations::reserve_all`.
///
/// Borrowing the allocator is the honest way to satisfy that today. It is not free: it is a second
/// table, and this module's docs explain why it cannot cause a double-select. The right fix is
/// upstream — a mint a store implementation may call — and is recorded on
/// <https://github.com/DIG-Network/dig_ecosystem/issues/3127>. When it lands, the allocator deletes.
const RESERVATION_ID_MINT: () = ();

/// How many failed releases are remembered for retry.
///
/// Bounded because a node unreachable for an hour would otherwise accumulate a row per abandoned
/// build with nothing ever draining it. Past the bound the OLDEST entry is dropped: it is the one
/// whose TTL is closest to expiring, so the backstop covering it is the one about to fire.
const RELEASE_BACKLOG_LIMIT: usize = 64;

/// Why a node table refused a reservation.
///
/// Separate from `ReservationError` because the two carry different knowledge.
/// `WALLET_COINS_RESERVED` says a coin is held but **cannot say which**: the contract's
/// `ControlErrorData` is `{code, origin}` and has no field for one. `ReservationError::Conflict`
/// requires a coin id, so attributing the clash is [`NodeReservations`]'s job, not the transport's
/// — and a transport that guessed one would send the retry loop after the wrong coin.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NodeTableError {
    /// At least one requested coin is already held. Nothing was reserved.
    Conflict,
    /// This node does not serve a reservation table at all.
    ///
    /// A CAPABILITY answer, not an outage, and the difference decides the fail direction. An
    /// unreachable node might answer next time, so refusing is right. A node that resolves no such
    /// method has told us definitively what it is, and refusing would leave every send on every
    /// older node permanently unable to build — a far worse outcome than the double-select, which
    /// is what those nodes have today anyway.
    Unsupported,
    /// The node could not be reached, could not answer, or answered something unreadable.
    Unavailable(String),
}

impl From<NodeTableError> for ReservationError {
    /// The fallback rendering, for the paths that have no coin to attribute a conflict to.
    ///
    /// A `Conflict` that reached here unattributed becomes `Unavailable`, never a conflict about a
    /// coin picked at random: naming the wrong coin sends the retry loop to exclude a coin that was
    /// free while re-selecting the one that is not, so it cannot converge.
    fn from(e: NodeTableError) -> Self {
        match e {
            NodeTableError::Unavailable(why) => ReservationError::Unavailable(why),
            NodeTableError::Conflict => ReservationError::Unavailable(
                "the node reports a coin is already reserved but cannot say which".to_owned(),
            ),
            NodeTableError::Unsupported => ReservationError::Unavailable(UNSUPPORTED.to_owned()),
        }
    }
}

/// One coin the node holds, and the hold that holds it.
///
/// The `reservation_id` is carried rather than discarded because it is the ONLY way to recover a
/// hold whose `reserve` reply was lost: the node took the coins and this process never learned the
/// handle, so without the id on the read side that coin is stranded until its TTL — once per
/// attempt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HeldCoin {
    /// The held coin.
    pub coin_id: Bytes32,
    /// The node's opaque handle for the hold holding it.
    pub reservation_id: String,
    /// When the node will drop that hold, on the node's clock.
    pub expires_at_unix: u64,
}

/// What the node holds, as of the node's OWN clock.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NodeHeld {
    /// Every coin committed to an in-flight spend, with the hold holding it.
    pub reserved: Vec<HeldCoin>,
    /// The node's clock in unix seconds when it answered.
    ///
    /// The caller supplies no time — `control.wallet.reservations.held` takes no parameters — so
    /// this is the only clock the answer was measured against, and it is what lets a client see
    /// skew rather than assume there is none.
    pub as_of_unix: u64,
}

/// A hold the node took, on the node's terms.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NodeHold {
    /// The opaque handle to release with. Stored and sent back verbatim; never parsed or derived.
    pub reservation_id: String,
    /// The lifetime the node ACTUALLY applied, which may be shorter than the one requested.
    pub ttl_secs: u64,
    /// Unix seconds, on the node's clock, after which the hold lapses by itself.
    pub expires_at_unix: u64,
}

/// The node's reservation table, as this process can reach it.
///
/// One method per operation dig-account's seam needs, in the NODE's terms rather than
/// dig-account's: no caller-supplied clock, an opaque string handle, and a TTL that is a request
/// rather than a command.
///
/// Implementations MUST report an unreachable, slow or unparseable node as
/// [`NodeTableError::Unavailable`], and never as an empty answer.
pub trait NodeReservationTable: Send + Sync + Debug {
    /// Every coin the node holds under a live reservation, and the clock it answered on.
    ///
    /// Takes no time, deliberately. The node decides what has lapsed, using its own clock; a
    /// client-supplied instant would let a caller ask what WOULD be free at a time of its choosing.
    fn held(&self) -> Result<NodeHeld, NodeTableError>;

    /// Reserve every coin in `coins` or none of them, asking for `ttl_secs`.
    ///
    /// Atomicity is the node's to guarantee, and it is the reason this table is worth reaching for:
    /// a check-then-act across the wire races exactly the way a local one does.
    ///
    /// `ttl_secs` is a REQUEST. The node clamps it and reports what it applied, because a caller
    /// that asked for an hour and silently got ten minutes would believe its coins were held long
    /// after they were selectable again.
    fn reserve_all(&self, coins: &[Bytes32], ttl_secs: u64) -> Result<NodeHold, NodeTableError>;

    /// Free the hold named by `reservation_id`.
    ///
    /// A handle naming no live reservation is a SUCCESS, not an error: the TTL may simply have got
    /// there first, and making that race an error teaches callers to ignore the result — which is
    /// how the release path stops being used at all.
    fn release(&self, reservation_id: &str) -> Result<(), NodeTableError>;
}

/// dig-account's reservation store, answered by dig-node.
///
/// Construct one per process and share it — see [`install`].
#[derive(Debug)]
pub struct NodeReservations {
    table: Arc<dyn NodeReservationTable>,
    /// The handle allocator — see the `RESERVATION_ID_MINT` note in this module.
    ///
    /// It holds SYNTHETIC coin ids, never real ones, so it can never form an opinion about a coin
    /// and can never disagree with the node. That is what keeps it an allocator rather than a
    /// second reservation table (SPEC §4.2a: where a node is reachable, the node's set wins).
    mint: LocalReservations,
    /// How many synthetic ids have been drawn.
    minted: AtomicU64,
    /// Handles this store issued while DEGRADED -> the `fallback` reservation each one names.
    ///
    /// Every handle a caller ever receives is drawn from `mint`, in BOTH modes, so handle numbers
    /// are unique across the whole life of the store. This map is what makes a degraded handle
    /// resolvable without asking `fallback` to interpret a number `mint` chose.
    fallback_ids: Mutex<Vec<(u64, ReservationId)>>,
    /// dig-account's handle -> the node's opaque handle, and the instant the node will drop it.
    ///
    /// The expiry is recorded because it is the NODE's, not the one dig-account asked for. The node
    /// clamps, and a caller that went on believing its own number would think coins were held long
    /// after they became selectable again. Recording it is what makes the difference observable
    /// instead of an assumption nothing can check — see [`NodeReservations::hold_expires_at`].
    node_ids: Mutex<Vec<(u64, String, u64)>>,
    /// Node handles whose release did not reach the node, awaiting retry.
    owed: Mutex<VecDeque<String>>,
    /// The table used once the node has said it serves no reservations.
    ///
    /// It holds REAL coins and answers conflicts, but the handles it mints never leave this struct:
    /// they are recorded in `fallback_ids` and a `mint`-drawn handle is returned instead. Both
    /// `LocalReservations` number from zero, so returning `fallback`'s own handle would put two
    /// handle spaces in circulation and let one caller free another caller's hold.
    fallback: LocalReservations,
    /// Latched the first time the node answers [`NodeTableError::Unsupported`].
    degraded: AtomicBool,
}

/// How far behind this process's clock the node's snapshot may be before it is not an answer.
///
/// A node replaying a stale snapshot UNDER-reports what is held, and under-reporting is the one
/// direction that restores the double-select. The contract returns `as_of_unix` precisely so a
/// client can see that, and seeing it without acting on it would make the field decoration.
///
/// Only the node being BEHIND trips this, by saturating subtraction. A node whose clock reads ahead
/// of ours is the safe direction — it expires holds later than we would — and refusing on it would
/// turn a few seconds of ordinary clock drift into a wallet that cannot spend.
const MAX_SNAPSHOT_LAG_SECS: u64 = 120;

/// The message [`NodeTableError::Unsupported`] renders to, and the marker `held` recognises it by.
///
/// `held` returns dig-account's error type, which has no capability variant, so the one place that
/// can tell "no such method" from "no answer" is this exact string. Sharing the constant between the
/// producer and the reader is what keeps them from drifting apart into a fallback that never fires.
const UNSUPPORTED: &str = "this node serves no reservation table";

impl NodeReservations {
    /// A store answered by `table`.
    pub fn new(table: Arc<dyn NodeReservationTable>) -> Self {
        let () = RESERVATION_ID_MINT;
        Self {
            table,
            mint: LocalReservations::new(),
            minted: AtomicU64::new(0),
            node_ids: Mutex::new(Vec::new()),
            fallback_ids: Mutex::new(Vec::new()),
            owed: Mutex::new(VecDeque::new()),
            fallback: LocalReservations::new(),
            degraded: AtomicBool::new(false),
        }
    }

    /// Whether this store has fallen back to a table covering THIS PROCESS only.
    ///
    /// Latched the first time the node says it serves no reservation table, and never unlatched: a
    /// node that gains the capability mid-session would leave holds already taken under the local
    /// table invisible to it, so the honest scope for the rest of the session is the narrower one.
    ///
    /// A surface that names what is guarded MUST read this rather than assuming, or it will claim a
    /// cross-process guarantee against a node that cannot provide one.
    pub fn is_degraded(&self) -> bool {
        self.degraded.load(Ordering::Relaxed)
    }

    /// When the node will drop the hold behind `id`, on the NODE's clock.
    ///
    /// `None` once the handle has been released, or when it was never a node hold at all (degraded
    /// mode). This is the node's applied lifetime, which may be considerably shorter than the one
    /// dig-account requested; a surface that reports how long a spend has to settle must read this
    /// rather than assume [`DEFAULT_RESERVATION_TTL_SECS`](dig_account::wallet::reservation::DEFAULT_RESERVATION_TTL_SECS).
    pub fn hold_expires_at(&self, id: ReservationId) -> Option<u64> {
        let map = self.node_ids.lock().ok()?;
        map.iter()
            .find(|(local, _, _)| *local == id.as_u64())
            .map(|(_, _, expires_at)| *expires_at)
    }

    /// A coin id that is not a coin id, drawn only to obtain a fresh handle from the allocator.
    ///
    /// Unique per draw, so the allocator never reports a conflict of its own — which is the whole
    /// point of minting against synthetic ids rather than the real coins. The `0xAD` fill is a
    /// recognisable tag rather than a security boundary; nothing trusts these bytes.
    fn synthetic_id(&self) -> Bytes32 {
        let mut raw = [0xADu8; 32];
        raw[..8].copy_from_slice(&self.minted.fetch_add(1, Ordering::Relaxed).to_be_bytes());
        Bytes32::new(raw)
    }

    /// A lock, with a poisoned mutex refusing rather than unwrapping.
    ///
    /// A panic while holding one of these leaves the handle map in an unknown state, and an unknown
    /// map is exactly when a reservation must not be trusted.
    fn lock<'a, T>(what: &str, m: &'a Mutex<T>) -> Result<MutexGuard<'a, T>, ReservationError> {
        m.lock().map_err(|_| {
            ReservationError::Unavailable(format!(
                "the {what} was left in an unknown state by a panic"
            ))
        })
    }

    /// Try once more to release everything a previous release failed to.
    ///
    /// Best effort by construction: it runs at the head of operations that have their own answer to
    /// give, and a still-unreachable node simply leaves the backlog for the next attempt. Handles
    /// that still cannot be released are kept, oldest first.
    fn drain_release_backlog(&self) {
        let Ok(mut owed) = self.owed.lock() else {
            return;
        };
        let mut still_owed = VecDeque::new();
        while let Some(handle) = owed.pop_front() {
            if self.table.release(&handle).is_err() {
                still_owed.push_back(handle);
            }
        }
        *owed = still_owed;
    }

    /// Remember `handle` for a later release attempt.
    fn owe_release(&self, handle: String) {
        let Ok(mut owed) = self.owed.lock() else {
            return;
        };
        if owed.len() >= RELEASE_BACKLOG_LIMIT {
            owed.pop_front();
        }
        owed.push_back(handle);
    }

    /// How many releases are still owed to the node. For assertions and diagnostics.
    ///
    /// Always zero once degraded: `degrade` clears the backlog, and no degraded-mode path adds to
    /// it. That is what keeps "a failed release MUST be retried rather than forgotten" true rather
    /// than merely intended — an entry that survived the latch could never be retried, because
    /// every operation that drains the backlog early-returns in degraded mode, and the node it
    /// named no longer has a table to release against.
    pub fn releases_owed(&self) -> usize {
        self.owed.lock().map(|owed| owed.len()).unwrap_or(0)
    }

    /// Latch degraded mode and answer from the process-local table instead.
    ///
    /// The scope this leaves is exactly `dig-account`'s default — the double-select is still closed
    /// among callers inside this process — so falling back is a narrowing, never a hole.
    ///
    /// # The node handles are KEPT, and that is what makes a stale handle safe
    ///
    /// A caller may still be holding a handle this store issued while the node served the methods.
    /// Discarding the record of which handles were node-issued does not make that handle go away —
    /// it makes it UNRECOGNISABLE, so the next `release` treats it as a local one and frees whatever
    /// local reservation happens to share its number.
    ///
    /// The handle spaces are kept apart by CONSTRUCTION instead: every handle a caller receives, in
    /// either mode, is drawn from `mint`, so no two live handles ever share a number and this map
    /// stays a reliable answer to "was this one the node's?".
    ///
    /// The release BACKLOG is cleared, because nothing could ever drain it: every operation that
    /// retries it early-returns once degraded, and the node it named has no table to release
    /// against — it just said so.
    fn degrade(&self) {
        self.degraded.store(true, Ordering::Relaxed);
        if let Ok(mut owed) = self.owed.lock() {
            owed.clear();
        }
    }

    /// Take a reservation in the process-local table, returning a handle drawn from `mint`.
    ///
    /// The indirection is the point: `fallback` mints its own handle numbering from zero, which
    /// would collide with the numbers `mint` has already issued to node-mode callers. Keeping every
    /// issued handle in one sequence is what lets `release` tell the two apart forever.
    fn reserve_locally(
        &self,
        coins: &[Bytes32],
        now_unix: u64,
        expires_at_unix: u64,
    ) -> Result<ReservationId, ReservationError> {
        let local = self
            .fallback
            .reserve_all(coins, now_unix, expires_at_unix)?;
        let handle = match self
            .mint
            .reserve_all(&[self.synthetic_id()], now_unix, expires_at_unix)
        {
            Ok(handle) => handle,
            Err(e) => {
                // No handle means no way to release, so give the local hold straight back.
                let _ = self.fallback.release(local);
                return Err(e);
            }
        };
        match Self::lock("reservation handle map", &self.fallback_ids) {
            Ok(mut map) => map.push((handle.as_u64(), local)),
            Err(e) => {
                let _ = self.fallback.release(local);
                let _ = self.mint.release(handle);
                return Err(e);
            }
        }
        Ok(handle)
    }

    /// Give back a hold whose `reserve` reply never arrived.
    ///
    /// A `reserve` is a non-idempotent POST under a timeout: the node can take the coins and the
    /// reply can still be lost, leaving a hold this process has no handle for. Left alone that coin
    /// is held for the full TTL, and every retry strands another one.
    ///
    /// # A foreign hold is NOT indistinguishable, which is why this is narrow
    ///
    /// An earlier version of this comment called it indistinguishable and released any hold
    /// touching a requested coin. That was wrong twice over, and the node's own contract says why:
    /// **`reserve` is all-or-none over exactly the requested set**, so a hold this process lost
    /// covers exactly `requested` — no more and no less.
    ///
    /// Therefore a hold is given back only when its coin set EQUALS `requested`. Two consequences,
    /// both of which were live defects under the old per-coin filter:
    ///
    /// - A hold that is a strict SUBSET cannot be ours. Under the old rule, a lost *conflict* — the
    ///   node refusing because another process held one contested coin, with that refusal lost in
    ///   transit — made this process release the other process's hold on that very coin.
    /// - A hold that is a strict SUPERSET cannot be ours either. Under the old rule a single
    ///   overlapping coin released somebody else's whole three-coin hold.
    ///
    /// Equality is deliberately narrower than "wholly contained in `requested`": containment still
    /// admits the subset case above, and every hold equality releases is one containment would have
    /// released too, so nothing recoverable is given up.
    ///
    /// # The residual, bounded and stated
    ///
    /// A foreign hold over EXACTLY the set this call asked for is genuinely indistinguishable from
    /// our own lost one. It requires another process to have reserved precisely that set inside the
    /// window between our request and our re-read, and the alternative — stranding the user's own
    /// coin on every attempt — is a certainty rather than a race.
    fn recover_stranded(&self, requested: &[Bytes32]) {
        let Ok(answer) = self.table.held() else {
            return;
        };

        // Grouped by HOLD, never scanned per coin: the unit the node reserves and releases is the
        // hold, so a per-coin decision reasons about something the node has no way to act on.
        let mut holds: HashMap<String, HashSet<Bytes32>> = HashMap::new();
        for row in answer.reserved {
            holds
                .entry(row.reservation_id)
                .or_default()
                .insert(row.coin_id);
        }

        let asked: HashSet<Bytes32> = requested.iter().copied().collect();
        for (handle, coins) in holds {
            if coins != asked {
                continue;
            }
            if self.table.release(&handle).is_err() {
                self.owe_release(handle);
            }
        }
    }

    /// Take the node handle `id` names, if the node issued it.
    fn take_node_handle(&self, id: ReservationId) -> Result<Option<String>, ReservationError> {
        let mut map = Self::lock("reservation handle map", &self.node_ids)?;
        Ok(map
            .iter()
            .position(|(local, _, _)| *local == id.as_u64())
            .map(|at| map.swap_remove(at).1))
    }

    /// Take the local reservation `id` names, if the process-local table issued it.
    fn take_fallback_handle(
        &self,
        id: ReservationId,
    ) -> Result<Option<ReservationId>, ReservationError> {
        let mut map = Self::lock("reservation handle map", &self.fallback_ids)?;
        Ok(map
            .iter()
            .position(|(handle, _)| *handle == id.as_u64())
            .map(|at| map.swap_remove(at).1))
    }

    /// The node's held rows, refusing a snapshot too far behind this process's clock.
    fn node_held(&self, now_unix: u64) -> Result<Vec<HeldCoin>, ReservationError> {
        let answer = self.table.held().map_err(ReservationError::from)?;
        let lag = now_unix.saturating_sub(answer.as_of_unix);
        if lag > MAX_SNAPSHOT_LAG_SECS {
            return Err(ReservationError::Unavailable(format!(
                "the node's reservation snapshot is {lag}s behind this machine's clock, so what is \
                 in flight cannot be trusted"
            )));
        }
        Ok(answer.reserved)
    }

    /// Name a coin the node refused over, by asking it what it holds.
    ///
    /// `WALLET_COINS_RESERVED` says a coin is reserved and cannot say WHICH — the contract's error
    /// data is `{code, origin}` and has no field for one. Named by symbol rather than by number
    /// because the numbers moved between contract versions, and one of them moved onto a refusal
    /// with the opposite disposition. dig-account's retry loop needs a name, because it
    /// excludes the reported coin and re-selects. So the clash is attributed here by the documented
    /// remedy: re-read `.held`, intersect it with what was asked for, report the first coin in both.
    ///
    /// An EMPTY intersection means the clash lapsed between the two calls, and no coin can honestly
    /// be named. That becomes `Unavailable` rather than a guess: a fabricated name would make the
    /// loop exclude a coin that was free while re-selecting the one that is not, so it could never
    /// converge.
    fn attribute_conflict(&self, requested: &[Bytes32], now_unix: u64) -> ReservationError {
        let held = match self.node_held(now_unix) {
            Ok(held) => held,
            Err(e) => return e,
        };
        let held: HashSet<Bytes32> = held.into_iter().map(|row| row.coin_id).collect();
        match requested.iter().find(|coin| held.contains(coin)) {
            Some(coin_id) => ReservationError::Conflict { coin_id: *coin_id },
            None => ReservationError::Unavailable(
                "the node refused the reservation as already held, but holds none of the coins it \
                 was asked for, so the conflict cannot be attributed"
                    .to_owned(),
            ),
        }
    }
}

impl CoinReservationStore for NodeReservations {
    /// What the NODE holds.
    ///
    /// The node's answer alone, not merged with anything local: where a node is reachable it owns
    /// the truth (SPEC §4.2a), and a client that unioned in its own view would be a second table
    /// with a second opinion — which is the rival implementation this design exists to avoid.
    ///
    /// `now_unix` is dig-account's clock and is deliberately NOT sent. The node decides what has
    /// lapsed, on its own clock; ours is used only to judge whether its snapshot is current.
    fn held(&self, now_unix: u64) -> Result<Vec<Bytes32>, ReservationError> {
        if self.is_degraded() {
            return self.fallback.held(now_unix);
        }
        self.drain_release_backlog();
        match self.node_held(now_unix) {
            Ok(rows) => Ok(rows.into_iter().map(|row| row.coin_id).collect()),
            Err(ReservationError::Unavailable(why)) if why == UNSUPPORTED => {
                self.degrade();
                self.fallback.held(now_unix)
            }
            Err(e) => Err(e),
        }
    }

    /// Take every coin or none, with the node deciding and the node's TTL applying.
    ///
    /// The node moves FIRST and the handle is drawn after it, because the allocator draws synthetic
    /// ids that cannot conflict — so there is nothing a refusal would need to undo, and every
    /// successful hold ends up with a handle that can release it.
    fn reserve_all(
        &self,
        coins: &[Bytes32],
        now_unix: u64,
        expires_at_unix: u64,
    ) -> Result<ReservationId, ReservationError> {
        if self.is_degraded() {
            return self.reserve_locally(coins, now_unix, expires_at_unix);
        }
        self.drain_release_backlog();

        // dig-account expresses the lifetime as an absolute instant; the contract asks for a
        // duration. A zero one would be a hold that lapses before the spend it guards, so it is
        // refused rather than sent — the contract reads a missing ttl as "your default", so sending
        // zero would silently ask for something other than what the caller said.
        let requested_ttl = expires_at_unix.saturating_sub(now_unix);
        if requested_ttl == 0 {
            return Err(ReservationError::Unavailable(
                "a reservation lifetime of zero would lapse before the spend it guards".to_owned(),
            ));
        }

        let hold = match self.table.reserve_all(coins, requested_ttl) {
            Ok(hold) => hold,
            Err(NodeTableError::Conflict) => return Err(self.attribute_conflict(coins, now_unix)),
            Err(NodeTableError::Unsupported) => {
                self.degrade();
                return self.reserve_locally(coins, now_unix, expires_at_unix);
            }
            Err(other) => {
                // No answer, so the node may have taken the coins and lost the reply. Ask what it
                // holds, and give back anything covering a coin this call asked for.
                self.recover_stranded(coins);
                return Err(other.into());
            }
        };

        // The allocator's own expiry is nominal: it holds synthetic ids that nothing ever reads,
        // so the lifetime that MATTERS is the node's, recorded on the handle below.
        let id = match self
            .mint
            .reserve_all(&[self.synthetic_id()], now_unix, expires_at_unix)
        {
            Ok(id) => id,
            Err(e) => {
                // No handle means no way to release, so give the hold straight back.
                if self.table.release(&hold.reservation_id).is_err() {
                    self.owe_release(hold.reservation_id);
                }
                return Err(e);
            }
        };

        // The node's APPLIED expiry, never the requested one. A client that kept its own number
        // would believe coins were held long after they became selectable again.
        match Self::lock("reservation handle map", &self.node_ids) {
            Ok(mut map) => map.push((id.as_u64(), hold.reservation_id, hold.expires_at_unix)),
            Err(e) => {
                let _ = self.mint.release(id);
                if self.table.release(&hold.reservation_id).is_err() {
                    self.owe_release(hold.reservation_id);
                }
                return Err(e);
            }
        }
        Ok(id)
    }

    /// Free `id` at the node.
    ///
    /// The local handle is dropped FIRST and unconditionally, so a node that cannot be reached never
    /// leaves this process holding bookkeeping for a spend that is over. The node's half is then
    /// OWED rather than forgotten — an unreleased hold is a wallet locked out of its own funds, and
    /// dig-account's guard drops without being able to report or retry.
    fn release(&self, id: ReservationId) -> Result<(), ReservationError> {
        // Resolved by WHICH TABLE ISSUED IT, never by which mode the store is in now. A caller may
        // still hold a handle taken before the node lost its reservation methods, and routing that
        // one to the local table would free whatever local reservation shares its number.
        self.mint.release(id)?;

        if let Some(handle) = self.take_node_handle(id)? {
            // The node has no table to release against once degraded — that is what it said when it
            // refused the method — so the local record is dropped and the call is a no-op. Sending
            // it anyway would fail as unsupported and be owed forever.
            if self.is_degraded() {
                return Ok(());
            }
            return match self.table.release(&handle) {
                Ok(()) => Ok(()),
                Err(e) => {
                    self.owe_release(handle);
                    Err(e.into())
                }
            };
        }

        if let Some(local) = self.take_fallback_handle(id)? {
            return self.fallback.release(local);
        }

        // Unknown or already released. dig-account's contract makes this a success on purpose: a
        // caller releasing on confirmation cannot know whether the TTL got there first, and making
        // that race an error pushes callers toward ignoring the result.
        Ok(())
    }
}

/// The one store every coin selection in this process consults.
///
/// Installed once, at start-up, by whatever knows how to reach the node. Reservation is a process
/// singleton by nature — two stores in one process would each mint their own handles, and a coin
/// held under one would be invisible to the other — so it is held here rather than threaded through
/// every constructor between start-up and the four selection sites.
static INSTALLED: OnceLock<Box<dyn CoinReservationStore>> = OnceLock::new();

/// The scope this process has BEFORE a node table is installed.
///
/// Deliberately not an empty stub and deliberately not a refusal. It is exactly what `dig-account`
/// ships by default: a table that closes the double-select among callers inside this process, and
/// says nothing about any other. Falling back to it is therefore never a regression — it is the
/// status quo — while installing a node table is a strict widening of the scope.
#[cfg(not(test))]
static FALLBACK: OnceLock<LocalReservations> = OnceLock::new();

/// Make `store` the reservation table for this process, for good.
///
/// Returns `Err(store)` if one was already installed. Silently replacing it would orphan every
/// reservation the previous store minted: their handles would resolve nowhere, so nothing could
/// release them and the coins would sit held until their TTL.
///
/// # Errors
///
/// When a store has already been installed. The rejected store is handed back rather than dropped so
/// a caller can report what it tried to install.
pub fn install(store: Box<dyn CoinReservationStore>) -> Result<(), Box<dyn CoinReservationStore>> {
    INSTALLED.set(store)
}

/// Whether a cross-process table is backing selection, or only this process's own.
///
/// For a surface that must not overstate what is guarded: before a node table is installed the
/// guard is real but process-local, and a status line that said otherwise would be a claim about
/// another process that nothing has checked.
pub fn is_cross_process() -> bool {
    INSTALLED.get().is_some()
}

/// The reservation set every selection in this process must be measured against.
///
/// Timed by the system clock at dig-account's default TTL — the pairing the selectors are documented
/// against, and the one a shorter local value would quietly weaken.
pub fn shared() -> CoinReservations<'static> {
    CoinReservations::new(store(), &SystemClock)
}

/// The installed store, or the process-local fallback.
#[cfg(not(test))]
fn store() -> &'static dyn CoinReservationStore {
    match INSTALLED.get() {
        Some(installed) => installed.as_ref(),
        None => FALLBACK.get_or_init(LocalReservations::new),
    }
}

/// As above, except that an uninstalled test gets a table of its OWN.
///
/// The test harness runs each test on its own thread, so a per-thread fallback is a per-test one.
/// A single shared fallback would let one test's reservation change another's selection, which
/// produces a FALSE RED that looks exactly like the defect these tests exist to catch — dig-account
/// hit precisely that and says so in its own fixtures.
///
/// The leak is one table per test thread and lives as long as the process, which a test binary can
/// afford; nothing outside `cfg(test)` can reach this path.
#[cfg(test)]
fn store() -> &'static dyn CoinReservationStore {
    if let Some(installed) = INSTALLED.get() {
        return installed.as_ref();
    }
    thread_local! {
        static PER_TEST: &'static LocalReservations =
            Box::leak(Box::new(LocalReservations::new()));
    }
    PER_TEST.with(|table| *table as &'static dyn CoinReservationStore)
}
