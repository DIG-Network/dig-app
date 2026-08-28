//! The two contract traits: the client-facing call builder/parser and the node-facing handler.
//!
//! * [`ControlCall`] binds a typed params struct to its [`ControlMethod`] and its typed result — so
//!   a caller writes `client.request(&SetCapParams { cap_bytes })` and gets back a `SetCapResult`,
//!   never a stringly-typed `Value`.
//! * [`ControlClient`] is what a CLIENT depends on: build a JSON-RPC request from a typed call, and
//!   parse a response back into the typed result (or a [`ControlError`]). Pure — no transport; the
//!   consumer carries the bytes over dig-ipc / loopback-mTLS itself.
//! * [`ControlHandler`] is what a NODE implements to SERVE the surface: one typed method per control
//!   method, plus a provided [`dispatch`](ControlHandler::dispatch) that routes a raw request to the
//!   right method — the single anti-drift seam the conformance KATs exercise.

use async_trait::async_trait;
use serde::de::DeserializeOwned;
use serde::Serialize;
use serde_json::Value;

use crate::envelope::{JsonRpcRequest, JsonRpcResponse, RequestId};
use crate::error::{ControlError, ControlErrorCode};
use crate::method::ControlMethod;
use crate::params;
use crate::results;

/// A typed control call: a params struct that knows its [`ControlMethod`] and its result type.
///
/// Implemented by every struct in [`crate::params`]; this is what makes
/// [`ControlClient::parse_response`] return the right typed result for each method at compile time.
pub trait ControlCall: Serialize {
    /// The wire method this call invokes.
    const METHOD: ControlMethod;
    /// The typed result this call returns on success.
    type Output: DeserializeOwned;
}

/// Serialize a typed call's params into a JSON object (`{}` for a no-param call, never `null`).
fn params_value<C: ControlCall>(call: &C) -> Value {
    match serde_json::to_value(call) {
        Ok(Value::Null) => Value::Object(Default::default()),
        Ok(v) => v,
        Err(_) => Value::Object(Default::default()),
    }
}

/// Build the JSON-RPC request envelope for a typed control call. Pure.
pub fn build_request<C: ControlCall>(id: RequestId, call: &C) -> JsonRpcRequest {
    JsonRpcRequest::new(id, C::METHOD.name(), params_value(call))
}

/// Parse a JSON-RPC response into a typed result, or the [`ControlError`] it carried. Pure.
pub fn parse_response<C: ControlCall>(
    response: JsonRpcResponse,
) -> Result<C::Output, ControlError> {
    let value = response.into_result()?;
    serde_json::from_value(value).map_err(|e| {
        ControlError::of(
            ControlErrorCode::ControlError,
            format!("failed to parse {} result: {e}", C::METHOD.name()),
        )
    })
}

/// The client-facing half of the contract: turn typed calls into requests and responses back into
/// typed results.
///
/// The default implementations cover every client; a consumer implements this trait only to
/// customise request construction (e.g. attaching the control token in a bespoke way). The blanket
/// [`DefaultControlClient`] gives callers the standard behaviour for free.
pub trait ControlClient {
    /// Build the request envelope for a typed call with the given request `id`.
    fn build_request<C: ControlCall>(&self, id: RequestId, call: &C) -> JsonRpcRequest {
        build_request(id, call)
    }

    /// Parse a response envelope into the typed result for call type `C`.
    fn parse_response<C: ControlCall>(
        &self,
        response: JsonRpcResponse,
    ) -> Result<C::Output, ControlError> {
        parse_response::<C>(response)
    }
}

/// The standard, zero-configuration [`ControlClient`] using the default request/response behaviour.
#[derive(Debug, Clone, Copy, Default)]
pub struct DefaultControlClient;

impl ControlClient for DefaultControlClient {}

/// The node-facing half of the contract: a running node implements this to SERVE the control
/// surface. Each method is typed to the catalog's params/results; the provided
/// [`dispatch`](ControlHandler::dispatch) routes a raw [`JsonRpcRequest`] to the right method so a
/// server needs only one entry point and can never mis-route.
///
/// Open/proxied shapes (the updater beacon status, the pairing list, the peer-pool snapshot) return
/// [`Value`] rather than a frozen struct, matching the catalog's [`ControlCall::Output`] for those
/// methods.
#[async_trait]
pub trait ControlHandler: Sync {
    /// `control.status`
    async fn status(&self) -> Result<results::StatusResult, ControlError>;
    /// `control.config.get`
    async fn config_get(&self) -> Result<results::ConfigResult, ControlError>;
    /// `control.config.setUpstream`
    async fn config_set_upstream(
        &self,
        params: params::SetUpstreamParams,
    ) -> Result<results::SetUpstreamResult, ControlError>;
    /// `control.log.setLevel`
    async fn log_set_level(
        &self,
        params: params::SetLevelParams,
    ) -> Result<results::SetLevelResult, ControlError>;
    /// `control.cache.get`
    async fn cache_get(&self) -> Result<results::CacheView, ControlError>;
    /// `control.cache.setCap`
    async fn cache_set_cap(
        &self,
        params: params::SetCapParams,
    ) -> Result<results::SetCapResult, ControlError>;
    /// `control.cache.clear`
    async fn cache_clear(&self) -> Result<results::CacheClearResult, ControlError>;
    /// `control.hostedStores.list`
    async fn hosted_stores_list(&self) -> Result<results::HostedStoresListResult, ControlError>;
    /// `control.hostedStores.pin`
    async fn hosted_stores_pin(
        &self,
        params: params::PinParams,
    ) -> Result<results::PinResult, ControlError>;
    /// `control.hostedStores.unpin`
    async fn hosted_stores_unpin(
        &self,
        params: params::UnpinParams,
    ) -> Result<results::UnpinResult, ControlError>;
    /// `control.hostedStores.status`
    async fn hosted_stores_status(
        &self,
        params: params::HostedStoreStatusParams,
    ) -> Result<results::HostedStoreStatusResult, ControlError>;
    /// `control.capsule.fetch`
    async fn capsule_fetch(
        &self,
        params: params::CapsuleFetchParams,
    ) -> Result<results::CapsuleFetchResult, ControlError>;
    /// `control.sync.status`
    async fn sync_status(&self) -> Result<results::SyncStatusResult, ControlError>;
    /// `control.sync.trigger`
    async fn sync_trigger(
        &self,
        params: params::SyncTriggerParams,
    ) -> Result<results::SyncTriggerResult, ControlError>;
    /// `control.updater.status`
    async fn updater_status(&self) -> Result<Value, ControlError>;
    /// `control.updater.setChannel`
    async fn updater_set_channel(
        &self,
        params: params::SetChannelParams,
    ) -> Result<Value, ControlError>;
    /// `control.updater.pause`
    async fn updater_pause(&self, params: params::PauseParams) -> Result<Value, ControlError>;
    /// `control.updater.resume`
    async fn updater_resume(&self) -> Result<Value, ControlError>;
    /// `control.updater.checkNow`
    async fn updater_check_now(&self) -> Result<Value, ControlError>;
    /// `control.pairing.list`
    async fn pairing_list(&self) -> Result<Value, ControlError>;
    /// `control.pairing.approve`
    async fn pairing_approve(
        &self,
        params: params::ApproveParams,
    ) -> Result<results::PairingApproveResult, ControlError>;
    /// `control.pairing.revoke`
    async fn pairing_revoke(
        &self,
        params: params::RevokeParams,
    ) -> Result<results::PairingRevokeResult, ControlError>;
    /// `control.peerStatus`
    async fn peer_status(&self) -> Result<Value, ControlError>;
    /// `control.peers.connect`
    async fn peers_connect(
        &self,
        params: params::PeersConnectParams,
    ) -> Result<results::PeersConnectResult, ControlError>;
    /// `control.peers.disconnect`
    async fn peers_disconnect(
        &self,
        params: params::PeersDisconnectParams,
    ) -> Result<results::PeersDisconnectResult, ControlError>;
    /// `control.chiaPeers.add` — start trusting a Chia full node the operator RUNS.
    ///
    /// An implementation MUST write through to the ONE peer store its wallet replica reads; a
    /// second peer list is a drift bug waiting to happen.
    ///
    /// Three obligations the shell cannot infer from the types:
    ///
    /// - it requires the MASTER token ([`ControlMethod::requires_master_token`]). The entry it
    ///   writes carries authority that outlives the calling token, and `control.pairing.revoke`
    ///   does not remove it;
    /// - `params.ip` is canonicalised with [`crate::params::canonical_peer_ip`] and STORED in that
    ///   form, so `remove` and `list` can match what `add` wrote;
    /// - `corroboration_bypassed` reports the RESULTING trust state and `notice` carries the
    ///   node's own warning verbatim. Reporting a bypass that did not happen tells an operator
    ///   they configured a node they did not.
    async fn chia_peers_add(
        &self,
        params: params::ChiaPeersAddParams,
    ) -> Result<results::ChiaPeersAddResult, ControlError>;
    /// `control.chiaPeers.list` — the tracked Chia full-node peers, banned ones included.
    ///
    /// Ordinary token tier: a read that confers nothing, and a paired client that cannot show the
    /// operator this list cannot show them the trust state they are subject to.
    async fn chia_peers_list(&self) -> Result<results::ChiaPeersListResult, ControlError>;
    /// `control.chiaPeers.remove` — stop trusting a Chia full node.
    ///
    /// MASTER token, like `add`. This is the ONLY un-trust remedy, so an implementation MUST
    /// return [`results::ChiaPeerRemovalOutcome::NoSuchPeer`] when nothing matched rather than
    /// reporting a removal it did not perform.
    async fn chia_peers_remove(
        &self,
        params: params::ChiaPeersRemoveParams,
    ) -> Result<results::ChiaPeersRemoveResult, ControlError>;
    /// `control.subscribe`
    ///
    /// `params.kind` is OPTIONAL on the wire and absent means
    /// [`SubscriptionKind::Capsule`](params::SubscriptionKind::Capsule). An implementation MUST
    /// persist untagged rows it already holds as capsules rather than discarding them: a node that
    /// refuses to read its own pre-existing `subscriptions.json` starts with an empty one, and the
    /// upgrade silently unsubscribes the user from everything.
    async fn subscribe(
        &self,
        params: params::SubscribeParams,
    ) -> Result<results::SubscribeResult, ControlError>;
    /// `control.unsubscribe`
    async fn unsubscribe(
        &self,
        params: params::UnsubscribeParams,
    ) -> Result<results::UnsubscribeResult, ControlError>;
    /// `control.listSubscriptions`
    async fn list_subscriptions(&self) -> Result<results::ListSubscriptionsResult, ControlError>;
    /// `control.wallet.balance` (READ-only)
    async fn wallet_balance(
        &self,
        params: params::WalletBalanceParams,
    ) -> Result<results::WalletBalanceResult, ControlError>;
    /// `control.wallet.coins` (READ-only, OPEN)
    ///
    /// An empty `coins` list MUST mean "a chain was consulted and this address holds nothing".
    /// A read that could not consult a chain MUST return the matching catalogued error instead.
    async fn wallet_coins(
        &self,
        params: params::WalletCoinsParams,
    ) -> Result<results::WalletCoinsResult, ControlError>;
    /// `control.wallet.coinById` (READ-only, OPEN)
    ///
    /// `Ok(coin: None)` MUST mean "a chain was consulted and holds no such coin". A read that could
    /// not consult a chain MUST return the matching catalogued error instead — a caller that cannot
    /// tell those apart reports a spent mint as pending forever.
    ///
    /// The params are validated at DESERIALIZATION (lowercase 64-hex, `0x` stripped), so any path
    /// that decodes `WalletCoinByIdParams` refuses malformed ids as `INVALID_PARAMS` before this
    /// method is called.
    async fn wallet_coin_by_id(
        &self,
        params: params::WalletCoinByIdParams,
    ) -> Result<results::WalletCoinByIdResult, ControlError>;
    /// `control.wallet.coinSpend` (READ-only, OPEN)
    ///
    /// `Ok(spend: None)` MUST mean "a chain was consulted and holds no spend of that coin" — the
    /// coin is unspent, or unknown. A read that could not consult a chain MUST return the matching
    /// catalogued error instead: a caller following a singleton forward reads "no spend" as *this is
    /// the tip* and stops walking, so a failure disguised as absence produces a spend built against
    /// a superseded singleton.
    ///
    /// A returned spend's `puzzle_reveal` MUST tree-hash to the spent coin's own `puzzle_hash`, and
    /// the implementation MUST fail closed — an error, never an unverified reveal — when it does not
    /// or when the reveal will not parse. The reveal comes from a peer, and a peer can lie.
    ///
    /// The params are validated at DESERIALIZATION (lowercase 64-hex, `0x` stripped), so any path
    /// that decodes `WalletCoinSpendParams` refuses malformed ids as `INVALID_PARAMS` before this
    /// method is called.
    async fn wallet_coin_spend(
        &self,
        params: params::WalletCoinSpendParams,
    ) -> Result<results::WalletCoinSpendResult, ControlError>;
    /// `control.wallet.coinsByParent` (READ-only, OPEN)
    ///
    /// Returns the parent's DIRECT children and nothing further. An implementation MUST NOT recurse:
    /// a transitive walk over caller-supplied input is unbounded work the caller cannot bound, and a
    /// partial walk returned as a complete one is a lineage with a silent hole in it.
    ///
    /// An empty list MUST mean "a chain was consulted and this parent created no known children".
    /// A read that could not consult a chain MUST return the matching catalogued error instead.
    ///
    /// The answer is ONE PAGE. An implementation MUST return at most
    /// `params.effective_limit()` records, in ASCENDING `coin_id` order, starting strictly after
    /// `params.after_coin_id` when one is given; it MUST set `complete` to whether the page carries
    /// the last child; and it MUST set `cursor` to the last record it actually returned (`None` for
    /// an empty page). It MUST NOT report `complete: true` on a page it truncated — a caller reads
    /// that as the end of a lineage branch. The params are validated at DESERIALIZATION, so an
    /// out-of-range page size is refused as `INVALID_PARAMS` before this method is called.
    ///
    /// Every record MUST report `asset: None`: naming a coin by its parent classifies nothing, and
    /// asserting a class this read never verified is a claim a caller would then spend against.
    async fn wallet_coins_by_parent(
        &self,
        params: params::WalletCoinsByParentParams,
    ) -> Result<results::WalletCoinsByParentResult, ControlError>;
    /// `control.wallet.arrivals` (READ-only, TOKEN-GATED)
    ///
    /// Gated although it is a read: the caller supplies only a cursor, so the answer names this
    /// node's OWN watched puzzle hashes and the receive history behind them.
    ///
    /// Every returned row MUST be a CONFIRMED arrival that the node itself judged: above its arrival
    /// baseline, not previously reported, and not the wallet's own change. An implementation MUST NOT
    /// emit a mempool sighting here, and MUST answer an empty page rather than an error when it has
    /// no baseline — "nothing arrived" is the honest answer from a wallet that cannot yet tell
    /// history from news.
    ///
    /// `cursor` MUST be the position of the last row actually returned (or the caller's `after_seq`
    /// for an empty page) and MUST NOT be `latest`; see
    /// [`WalletArrivalsResult::latest`](results::WalletArrivalsResult::latest).
    async fn wallet_arrivals(
        &self,
        params: params::WalletArrivalsParams,
    ) -> Result<results::WalletArrivalsResult, ControlError>;
    /// `control.wallet.peak` (READ-only, OPEN)
    async fn wallet_peak(&self) -> Result<results::WalletPeakResult, ControlError>;
    /// `control.peerCounts` (READ-only, OPEN)
    ///
    /// `dig_peer_count` MUST be dig-node-core's `connected_peers` — the same figure
    /// `control.peerStatus` reports — and `chia_peer_count` MUST be the SAME observation
    /// `wallet_sync_status` reports, served from ONE source so the two answers agree. `None` means
    /// the count cannot be observed; a network that is not running is UNKNOWN, never `Some(0)`.
    async fn peer_counts(&self) -> Result<results::PeerCountsResult, ControlError>;
    /// `control.wallet.syncStatus` (READ-only, OPEN)
    ///
    /// `WalletSyncPhase::Synced` MUST require BOTH that the initial catch-up completed and that at
    /// least one Chia peer connection is live now, which makes it strictly stronger than
    /// `WalletPeakResult::synced`. `peak_height` MUST be the node's OWN replica's height or `None`,
    /// never an oracle's, and `chia_peer_count` counts CHIA full-node peers -- never DIG peers.
    async fn wallet_sync_status(&self) -> Result<results::WalletSyncStatusResult, ControlError>;
    /// `control.wallet.broadcast` (TOKEN-GATED)
    ///
    /// Pushes an ALREADY-SIGNED bundle: the implementation never signs, and never receives anything
    /// it could sign with (§908). A mempool refusal is `Ok` with `accepted: false`; failing to
    /// reach a mempool is `Err`.
    async fn wallet_broadcast(
        &self,
        params: params::WalletBroadcastParams,
    ) -> Result<results::WalletBroadcastResult, ControlError>;
    /// `control.wallet.watch` (TOKEN-GATED)
    ///
    /// Enrols PUBLIC keys for the node's chain replica to follow. The implementation MUST derive the
    /// addresses itself, from the SAME derivation it applies to the keys already in its own custody
    /// — a second derivation is a second opinion about which addresses a key covers, and the client
    /// would read the difference as missing money.
    ///
    /// It MUST be IDEMPOTENT: keys already enrolled are reported as `added: 0` and the call
    /// succeeds. It MUST persist the enrolment across restarts — a set that evaporates on restart
    /// makes a node that syncs today and reports a zero balance tomorrow.
    ///
    /// The params are validated at DESERIALIZATION (lowercase 96-hex, `0x` stripped), so any path
    /// that decodes `WalletWatchParams` refuses a malformed key as `INVALID_PARAMS` — for the WHOLE
    /// request — before this method is called.
    async fn wallet_watch(
        &self,
        params: params::WalletWatchParams,
    ) -> Result<results::WalletWatchResult, ControlError>;
    /// `control.wallet.unwatch` (TOKEN-GATED)
    ///
    /// Deregisters keys, and the following MUST actually stop: the addresses leave the replica's
    /// watched set, not merely the list this node reports. A registry that keeps syncing what it
    /// says it forgot is the failure this method exists to make impossible.
    ///
    /// Deregistering a key that was never enrolled is a success reporting `removed: 0`.
    async fn wallet_unwatch(
        &self,
        params: params::WalletUnwatchParams,
    ) -> Result<results::WalletUnwatchResult, ControlError>;
    /// `control.wallet.watched` (READ-only, TOKEN-GATED)
    ///
    /// Gated although it is a read: the caller supplies nothing, so the answer names this node's OWN
    /// enrolled keys.
    ///
    /// MUST return exactly the keys enrolment added, in the wire form they were accepted in, so a
    /// client can compare its own set against the node's by value. MUST NOT include the node's own
    /// custody keys: this method reports what was ENROLLED through it, and a caller reconciling
    /// against a superset would unwatch keys it never watched.
    async fn wallet_watched(&self) -> Result<results::WalletWatchedResult, ControlError>;
    /// `control.wallet.reservations.held` (READ-only, TOKEN-GATED)
    ///
    /// Gated although it is a read: the caller supplies nothing, so the answer names this node's OWN
    /// in-flight commitments.
    ///
    /// An implementation MUST read its own clock rather than accept one, MUST omit every reservation
    /// that has already lapsed at that instant, and MUST report the clock it used as `as_of_unix`.
    ///
    /// An implementation that cannot read its reservation set MUST return
    /// [`ControlErrorCode::WalletReservationsUnavailable`](crate::error::ControlErrorCode::WalletReservationsUnavailable)
    /// and MUST NOT return an empty list. "Nothing is held" permits a caller to spend; "I cannot
    /// tell" must stop it, and the two are indistinguishable once collapsed.
    async fn wallet_reservations_held(
        &self,
    ) -> Result<results::WalletReservationsHeldResult, ControlError>;
    /// `control.wallet.reservations.reserve` (TOKEN-GATED)
    ///
    /// Acquisition MUST be atomic across concurrent callers: take EVERY coin in `coin_ids` or take
    /// none. On a clash an implementation MUST have written nothing and MUST answer
    /// [`ControlErrorCode::WalletCoinsReserved`](crate::error::ControlErrorCode::WalletCoinsReserved)
    /// — never a shortfall code, because the user has the money and is waiting on a settlement, and
    /// never a partial success, because a caller believing it holds inputs it does not is the state
    /// all-or-none exists to make unreachable.
    ///
    /// An empty `coin_ids` MUST succeed, returning a handle that releases nothing.
    ///
    /// The hold MUST expire on its own. An implementation clamps the requested `ttl_secs` to its own
    /// maximum, applies its default when none is given, and MUST report the lifetime it actually
    /// applied — a caller told nothing would release on a schedule the node does not keep.
    ///
    /// An implementation MUST NOT require, accept or store key material here (§908). A reservation
    /// is bookkeeping: it narrows what a selector will choose and authorizes nothing.
    async fn wallet_reservations_reserve(
        &self,
        params: params::WalletReservationsReserveParams,
    ) -> Result<results::WalletReservationsReserveResult, ControlError>;
    /// `control.wallet.reservations.release` (TOKEN-GATED)
    ///
    /// Releasing a handle that names no live reservation — lapsed, or already released — MUST be a
    /// SUCCESS reporting `released: false`, never an error. A caller releasing on confirmation
    /// cannot know whether the TTL got there first, and an error there teaches callers to discard
    /// the result, which is how the release path stops being called at all.
    ///
    /// An implementation MUST free every coin the handle holds, or none of them, for the same reason
    /// acquisition is all-or-none: a half-freed reservation leaves coins held by a handle the caller
    /// has thrown away, and only the TTL would ever recover them.
    async fn wallet_reservations_release(
        &self,
        params: params::WalletReservationsReleaseParams,
    ) -> Result<results::WalletReservationsReleaseResult, ControlError>;
    /// `control.spends.list` (READ-only, TOKEN-GATED)
    ///
    /// One page of the automated-spend audit record — the spends this node made WITHOUT
    /// per-transaction approval. Gated although it is a read: the caller names no identifier, so the
    /// answer is this node's OWN spending history.
    ///
    /// An implementation MUST NOT let this call initiate, sign, retry, cancel or amend a spend, and
    /// MUST NOT expose any control method that edits or deletes an entry. The record replaces
    /// authorization with accountability, and an editable record accounts for nothing.
    ///
    /// Four obligations, each of which a plausible implementation gets wrong:
    ///
    /// - **Report the failure STAGE, never a bare "failed."** Only
    ///   [`SpendFailureStage::Signing`](results::SpendFailureStage::Signing) means the money
    ///   definitely did not move; a broadcast or confirmation failure is an unknown outcome. An
    ///   implementation that flattens the stage makes every client structurally unable to tell a
    ///   person the truth about their money.
    /// - **Keep [`Unresolved`](results::SpendOutcome::Unresolved) distinct from `Failed`.** It means
    ///   the node signed and does not know how it ended.
    /// - **State completeness explicitly.** `complete` MUST be `false` whenever a matching row was
    ///   withheld, and `cursor` MUST be the id of the last row actually returned.
    /// - **Report unreadable entries.** `unreadable_lines` MUST count entries the node could not
    ///   parse; a trail that lost rows must never read as a tidy shorter one. A record that could not
    ///   be read AT ALL is
    ///   [`SpendAuditUnreadable`](crate::error::ControlErrorCode::SpendAuditUnreadable), never an
    ///   empty page — while a record that was never written IS an empty page, because a node that has
    ///   never spent automatically is the ordinary case.
    async fn spends_list(
        &self,
        params: params::SpendsListParams,
    ) -> Result<results::SpendsListResult, ControlError>;
    /// `control.collateral.requirement` (TOKEN-GATED)
    ///
    /// This epoch's derived per-store collateral requirement, with the census inputs behind it.
    ///
    /// Gated although the figure itself is derivable from chain by anyone: the UNKNOWN branch names
    /// this node's own census position, and the caller supplies no identifier, so the answer is a
    /// fact about this node rather than a relayed public one.
    ///
    /// Three obligations, each of which a plausible implementation gets wrong:
    ///
    /// - **Answer `unknown` WITH a reason rather than a number the node does not have.** A node that
    ///   has not censused the epoch, or that sits inside `CENSUS_FINALITY_DEPTH_BLOCKS` of the tip,
    ///   MUST return [`Unknown`](results::CollateralRequirementResult::Unknown). It MUST NOT return
    ///   a zero, a stale epoch's figure presented as this epoch's, or an error that a client would
    ///   render as "no collateral required" — under-posting costs the operator that epoch's rewards.
    /// - **Report the protocol version that COMPUTED the epoch**, not the newest version this build
    ///   implements. The two differ exactly when a node has upgraded mid-schedule, which is the one
    ///   case where a client needs to know the difference.
    /// - **Never derive the figure from the local safety margin.** The margin MUST NOT reach any
    ///   value another node derives; `required_per_store_dig_base_units` is the pre-margin
    ///   requirement, and a node that returned the margined amount here would make its own
    ///   preference look like the network's price.
    async fn collateral_requirement(
        &self,
    ) -> Result<results::CollateralRequirementResult, ControlError>;

    /// `control.collateral.margin.get` (TOKEN-GATED)
    ///
    /// The node's local safety margin in basis points.
    ///
    /// A node whose stored configuration predates the field MUST answer
    /// [`DEFAULT_SAFETY_MARGIN_BP`](params::DEFAULT_SAFETY_MARGIN_BP), never `0`: a zero margin is a
    /// deliberate choice to post the requirement exactly, and reporting it for a config that never
    /// expressed one tells the operator they opted out of a cushion they never declined.
    async fn collateral_margin_get(&self) -> Result<results::CollateralMarginResult, ControlError>;

    /// `control.collateral.margin.set` (TOKEN-GATED)
    ///
    /// Persist the node's local safety margin and return the margin now in force.
    ///
    /// The node is the authoritative home for this setting — the flywheel is headless, so a machine
    /// with no GUI must be able to set it — and dig-app is a remote control for the same value.
    ///
    /// Two obligations:
    ///
    /// - **Persist it**, so it survives a restart. A margin that lapses to the default on reboot
    ///   silently changes what the node posts.
    /// - **Return what was actually stored.** The returned `margin_bp` MUST equal the accepted
    ///   request's, because a value above [`MAX_SAFETY_MARGIN_BP`](params::MAX_SAFETY_MARGIN_BP) is
    ///   REFUSED rather than clamped. An implementation that clamped and returned the clamped value
    ///   would leave the caller's stored intent and the node's behaviour disagreeing on the money
    ///   path.
    async fn collateral_margin_set(
        &self,
        params: params::CollateralMarginSetParams,
    ) -> Result<results::CollateralMarginResult, ControlError>;

    /// `control.profile.putBody` (TOKEN-GATED)
    ///
    /// An implementation MUST independently resolve the profile's root ON CHAIN, recompute the root
    /// of the supplied body, and REFUSE the call unless the two agree and that root is confirmed.
    /// The caller's `root` is a claim to be checked — never a fact to be trusted — and dig-app gets
    /// no exemption: it holds the key and signs the root (§908), but the bytes reach the node the
    /// same way a peer's bytes do, and the same check binds both. An implementation that stores
    /// what it is handed makes this node serve arbitrary bytes under someone else's profile id.
    ///
    /// A body whose DECODED length exceeds [`MAX_BODY_BYTES`](params::MAX_BODY_BYTES) (4 MiB) MUST
    /// be refused as `INVALID_PARAMS`, before it is persisted: a body larger than that cannot be
    /// served to a peer inside dig-gossip's frame ceiling, so accepting it would store something
    /// permanently unsyncable.
    ///
    /// Returning `Ok` therefore asserts BOTH that the root was confirmed on chain and that the body
    /// is persisted and servable. A refusal is an error, never an `Ok` carrying `stored: false`.
    async fn profile_put_body(
        &self,
        params: params::ProfilePutBodyParams,
    ) -> Result<results::ProfilePutBodyResult, ControlError>;
    /// `control.profile.getBody` (READ-only, TOKEN-GATED)
    ///
    /// `Ok(body_b64: None)` MUST mean "this node was consulted and holds no body at that root". A
    /// read that FAILED MUST return a catalogued error instead — a caller that reads a failure as
    /// absence renders an existing profile as an empty one.
    ///
    /// The returned `root` MUST be the root the caller asked for; a node MUST NOT substitute a
    /// newer body it happens to hold.
    async fn profile_get_body(
        &self,
        params: params::ProfileGetBodyParams,
    ) -> Result<results::ProfileGetBodyResult, ControlError>;
    /// `pairing.request` (OPEN)
    async fn pairing_request(
        &self,
        params: params::RequestParams,
    ) -> Result<results::PairingRequestResult, ControlError>;
    /// `pairing.poll` (OPEN)
    async fn pairing_poll(
        &self,
        params: params::PollParams,
    ) -> Result<results::PairingPollResult, ControlError>;

    /// Route a raw JSON-RPC request to the right typed method and build the response envelope.
    ///
    /// Deserializes the params for methods that take them, calls the handler, and serializes the
    /// typed result. An unknown method → `METHOD_NOT_FOUND`; malformed params → `INVALID_PARAMS`.
    /// This is the single seam a server dispatches through — the KATs exercise it end-to-end.
    async fn dispatch(&self, request: JsonRpcRequest) -> JsonRpcResponse {
        let id = request.id.clone();
        let Some(method) = ControlMethod::from_name(&request.method) else {
            return JsonRpcResponse::error(
                id,
                ControlError::of(
                    ControlErrorCode::MethodNotFound,
                    format!("unknown control method: {}", request.method),
                ),
            );
        };
        match self.dispatch_method(method, request.params).await {
            Ok(result) => JsonRpcResponse::success(id, result),
            Err(err) => JsonRpcResponse::error(id, err),
        }
    }

    /// Route to the typed method by [`ControlMethod`], returning the result as a [`Value`]. Split
    /// from [`dispatch`](ControlHandler::dispatch) so the envelope wrapping stays in one place.
    #[doc(hidden)]
    async fn dispatch_method(
        &self,
        method: ControlMethod,
        params: Value,
    ) -> Result<Value, ControlError> {
        /// Deserialize a method's params, mapping a shape error to `INVALID_PARAMS`.
        fn decode<T: DeserializeOwned>(params: Value) -> Result<T, ControlError> {
            serde_json::from_value(params)
                .map_err(|e| ControlError::of(ControlErrorCode::InvalidParams, e.to_string()))
        }
        /// Serialize a typed result to a `Value` (infallible for our derive-Serialize results).
        fn encode<T: Serialize>(value: T) -> Result<Value, ControlError> {
            serde_json::to_value(value)
                .map_err(|e| ControlError::of(ControlErrorCode::ControlError, e.to_string()))
        }
        match method {
            ControlMethod::Status => encode(self.status().await?),
            ControlMethod::ConfigGet => encode(self.config_get().await?),
            ControlMethod::ConfigSetUpstream => {
                encode(self.config_set_upstream(decode(params)?).await?)
            }
            ControlMethod::LogSetLevel => encode(self.log_set_level(decode(params)?).await?),
            ControlMethod::CacheGet => encode(self.cache_get().await?),
            ControlMethod::CacheSetCap => encode(self.cache_set_cap(decode(params)?).await?),
            ControlMethod::CacheClear => encode(self.cache_clear().await?),
            ControlMethod::HostedStoresList => encode(self.hosted_stores_list().await?),
            ControlMethod::HostedStoresPin => {
                encode(self.hosted_stores_pin(decode(params)?).await?)
            }
            ControlMethod::HostedStoresUnpin => {
                encode(self.hosted_stores_unpin(decode(params)?).await?)
            }
            ControlMethod::HostedStoresStatus => {
                encode(self.hosted_stores_status(decode(params)?).await?)
            }
            ControlMethod::CapsuleFetch => encode(self.capsule_fetch(decode(params)?).await?),
            ControlMethod::SyncStatus => encode(self.sync_status().await?),
            ControlMethod::SyncTrigger => encode(self.sync_trigger(decode(params)?).await?),
            ControlMethod::UpdaterStatus => self.updater_status().await,
            ControlMethod::UpdaterSetChannel => self.updater_set_channel(decode(params)?).await,
            ControlMethod::UpdaterPause => self.updater_pause(decode(params)?).await,
            ControlMethod::UpdaterResume => self.updater_resume().await,
            ControlMethod::UpdaterCheckNow => self.updater_check_now().await,
            ControlMethod::PairingList => self.pairing_list().await,
            ControlMethod::PairingApprove => encode(self.pairing_approve(decode(params)?).await?),
            ControlMethod::PairingRevoke => encode(self.pairing_revoke(decode(params)?).await?),
            ControlMethod::PeerStatus => self.peer_status().await,
            ControlMethod::PeerCounts => encode(self.peer_counts().await?),
            ControlMethod::PeersConnect => encode(self.peers_connect(decode(params)?).await?),
            ControlMethod::PeersDisconnect => encode(self.peers_disconnect(decode(params)?).await?),
            ControlMethod::ChiaPeersAdd => encode(self.chia_peers_add(decode(params)?).await?),
            ControlMethod::ChiaPeersList => encode(self.chia_peers_list().await?),
            ControlMethod::ChiaPeersRemove => {
                encode(self.chia_peers_remove(decode(params)?).await?)
            }
            ControlMethod::Subscribe => encode(self.subscribe(decode(params)?).await?),
            ControlMethod::Unsubscribe => encode(self.unsubscribe(decode(params)?).await?),
            ControlMethod::ListSubscriptions => encode(self.list_subscriptions().await?),
            ControlMethod::WalletBalance => encode(self.wallet_balance(decode(params)?).await?),
            ControlMethod::WalletCoins => encode(self.wallet_coins(decode(params)?).await?),
            // Re-validated here idempotently; deserialization already enforced the same rule.
            ControlMethod::WalletCoinById => {
                let params: params::WalletCoinByIdParams = decode(params)?;
                encode(self.wallet_coin_by_id(params.validated()?).await?)
            }
            // Re-validated here idempotently; deserialization already enforced the same rule.
            ControlMethod::WalletCoinSpend => {
                let params: params::WalletCoinSpendParams = decode(params)?;
                encode(self.wallet_coin_spend(params.validated()?).await?)
            }
            ControlMethod::WalletCoinsByParent => {
                let params: params::WalletCoinsByParentParams = decode(params)?;
                encode(self.wallet_coins_by_parent(params.validated()?).await?)
            }
            ControlMethod::WalletArrivals => encode(self.wallet_arrivals(decode(params)?).await?),
            ControlMethod::WalletPeak => encode(self.wallet_peak().await?),
            ControlMethod::WalletSyncStatus => encode(self.wallet_sync_status().await?),
            ControlMethod::WalletBroadcast => encode(self.wallet_broadcast(decode(params)?).await?),
            // Re-validated here idempotently; deserialization already enforced the same rule.
            ControlMethod::WalletWatch => {
                let params: params::WalletWatchParams = decode(params)?;
                encode(self.wallet_watch(params.validated()?).await?)
            }
            // Re-validated here idempotently; deserialization already enforced the same rule.
            ControlMethod::WalletUnwatch => {
                let params: params::WalletUnwatchParams = decode(params)?;
                encode(self.wallet_unwatch(params.validated()?).await?)
            }
            ControlMethod::WalletWatched => encode(self.wallet_watched().await?),
            ControlMethod::WalletReservationsHeld => encode(self.wallet_reservations_held().await?),
            ControlMethod::WalletReservationsReserve => {
                encode(self.wallet_reservations_reserve(decode(params)?).await?)
            }
            ControlMethod::WalletReservationsRelease => {
                encode(self.wallet_reservations_release(decode(params)?).await?)
            }
            ControlMethod::CollateralRequirement => encode(self.collateral_requirement().await?),
            ControlMethod::CollateralMarginGet => encode(self.collateral_margin_get().await?),
            // `CollateralMarginSetParams` derives `Deserialize`, so decoding enforces NOTHING beyond
            // the field's type. `validated()` here is the SOLE enforcement of `MAX_SAFETY_MARGIN_BP`
            // on this money-path mutation — dropping it admits an unbounded margin, and the margin
            // arithmetic saturates rather than failing, so the result is a silently enormous posting.
            ControlMethod::CollateralMarginSet => {
                let params: params::CollateralMarginSetParams = decode(params)?;
                encode(self.collateral_margin_set(params.validated()?).await?)
            }
            // Re-validated here idempotently; deserialization already enforced the same rule.
            ControlMethod::SpendsList => {
                let params: params::SpendsListParams = decode(params)?;
                encode(self.spends_list(params.validated()?).await?)
            }
            ControlMethod::ProfilePutBody => encode(self.profile_put_body(decode(params)?).await?),
            ControlMethod::ProfileGetBody => encode(self.profile_get_body(decode(params)?).await?),
            ControlMethod::PairingRequest => encode(self.pairing_request(decode(params)?).await?),
            ControlMethod::PairingPoll => encode(self.pairing_poll(decode(params)?).await?),
        }
    }
}
