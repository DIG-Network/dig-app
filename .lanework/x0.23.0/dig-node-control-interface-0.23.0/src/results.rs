//! Typed result payloads for the control methods.
//!
//! Each struct is field-for-field identical to what dig-node emits (snake_case wire fields), so a
//! client deserializes the node's real response and re-serializes the same bytes — the property the
//! conformance KATs pin. Genuinely open/proxied shapes (the updater beacon's status, the peer-pool
//! snapshot, the pairing list) stay [`serde_json::Value`] on the call's `Output` rather than being
//! frozen into a struct that would drift from the proxied source.

use serde::{Deserialize, Serialize};

/// The on-disk content-cache view (`control.cache.get`, and embedded in [`StatusResult`]).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CacheView {
    /// The configured cache size cap, in bytes.
    pub cap_bytes: u64,
    /// Bytes currently used on disk.
    pub used_bytes: u64,
    /// The cache directory.
    pub dir: String,
    /// Whether the cache directory is the machine-wide shared cache.
    pub shared: bool,
}

/// The §21 sync availability flag embedded in [`StatusResult`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SyncAvailability {
    /// Whether authenticated §21 whole-store sync is available on this node.
    pub available: bool,
}

/// How much of its own build a node reveals when it advertises (dig_ecosystem#2215).
///
/// Advertising an exact build is a fingerprinting aid — it tells an observer precisely which peers
/// run a version with a publicly disclosed defect. This is the operator's dial between that cost
/// and the diagnostic value of knowing what the network is running.
///
/// It lives here, beside [`PeerSoftware`], because rendering and parsing are two halves of one
/// format: a node that hand-rolled its own `product/version` string would be re-implementing half
/// the contract, and the two halves would drift. A node picks a mode; this type renders it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SoftwareVersionDetail {
    /// Advertise the exact build, e.g. `dig-node/0.99.1`. The default: the diagnostic value is why
    /// the field exists, and an operator who disagrees opts down explicitly.
    #[default]
    Full,
    /// Advertise only the major and minor level, e.g. `dig-node/0.99.0`. Hides the patch level, and
    /// any pre-release or build metadata, while remaining READABLE at the far end.
    Minor,
    /// Advertise nothing. Indistinguishable from a peer built before this field existed, and reads
    /// as [`PeerSoftware::Unknown`].
    Off,
}

impl SoftwareVersionDetail {
    /// Render the advertisement a node with this setting puts on its handshake.
    ///
    /// The result is ALWAYS either the empty string or a value [`PeerSoftware::parse`] reads back
    /// as `Reported`. Coarsening reduces PRECISION; it never produces a value that reads as
    /// Unknown while pretending to be a report. Two consequences follow, and both are tested:
    ///
    /// - [`Minor`](SoftwareVersionDetail::Minor) renders `MAJOR.MINOR.0`, never a bare
    ///   `MAJOR.MINOR` — two-part versions are not valid semver, so that spelling would read as
    ///   Unknown and become a second, confusing spelling of [`Off`](SoftwareVersionDetail::Off).
    /// - `Minor` of a `0.0.x` build renders the EMPTY STRING, because its coarsening is version
    ///   zero and version zero is the "unknown" sentinel. There is no coarser representable value,
    ///   so it advertises nothing rather than advertising the sentinel as if it were a report.
    ///
    /// A coarsened `1.4.0` is indistinguishable from a genuine `1.4.0`. That is the point of
    /// coarsening, not a defect in it.
    pub fn render(self, product: &str, version: &semver::Version) -> String {
        match self {
            Self::Full => format!("{product}/{version}"),
            // A pre-release identifier (`-nightly.20260805`) is more precisely identifying than the
            // patch number beside it, so a "coarse" advertisement that kept it would coarsen
            // nothing for exactly the builds that most want it. `Version::new` drops both it and
            // any build metadata.
            Self::Minor => {
                let coarsened = semver::Version::new(version.major, version.minor, 0);
                // Hiding the patch of a `0.0.x` build leaves version zero, which the wire reserves
                // as the "unknown" sentinel. There is no coarser representable value, so advertise
                // nothing rather than advertise the sentinel dressed up as a report. (This differs
                // from the rejected two-part `MAJOR.MINOR` spelling: there a representable coarse
                // value existed and the wrong one was chosen; here none exists.)
                if is_version_zero(&coarsened) {
                    return String::new();
                }
                format!("{product}/{coarsened}")
            }
            Self::Off => String::new(),
        }
    }
}

/// A peer's advertised SOFTWARE build, as read from the gossip handshake (dig_ecosystem#2215).
///
/// dig-gossip carries the peer's `Handshake.software_version` as an opaque sanitized string and
/// deliberately does not interpret it. This type is where that string becomes meaning, once, at the
/// control boundary — so the interpretation is defined in one place and every client agrees.
///
/// # This is NOT the protocol version
///
/// Wire compatibility is a separate field that dig-gossip gates connections on. Two peers can speak
/// the same protocol while running builds months apart; this type reports the latter. It MUST NOT
/// be used to decide whether to talk to a peer.
///
/// # Why there is no `Ord` and no `Default`
///
/// [`Unknown`](PeerSoftware::Unknown) has no position on a version line: it is the absence of a
/// measurement, not a low value. Deriving `Ord` would place it somewhere — and every peer built
/// before #2215 is Unknown, so "somewhere" would silently become a verdict about most of the live
/// network. Comparison is therefore reachable only by destructuring
/// [`Reported`](PeerSoftware::Reported), which forces the caller to say what Unknown means for
/// their question. There is no `Default` for the same reason: a defaulted Unknown that appears from
/// nowhere is a different fact from one that was measured, and the two must not be confusable.
///
/// # JSON
///
/// ```json
/// {"kind": "unknown"}
/// {"kind": "reported", "product": "dig-node", "version": "0.99.1", "raw": "dig-node/0.99.1"}
/// ```
///
/// Unknown carries no `version` member at all — never version zero, never `""`, never `null` in a
/// field a consumer might read as a version.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum PeerSoftware {
    /// The peer's build is not known: it advertised nothing, advertised VERSION ZERO — the legacy
    /// sentinel, in any decoration (`0.0.0`, `0.0.0-rc.1`, `0.0.0+build`) — or advertised something
    /// this contract cannot parse. See [`PeerSoftware::parse`] for why those three are one case.
    Unknown,
    /// The peer advertised a well-formed `product/semver` build.
    Reported {
        /// The product name, e.g. `dig-node`. Everything before the LAST `/`.
        product: String,
        /// The parsed semantic version, e.g. `0.99.1`. Serializes as its string form.
        version: semver::Version,
        /// Exactly what the peer advertised, after trimming.
        ///
        /// **Currently reconstructible, deliberately kept.** The grammar this parser accepts is
        /// lossless — `semver::Version` re-renders every string it accepts byte-identically — so
        /// today `raw` always equals `format!("{product}/{version}")`, and no test can distinguish
        /// this field from that expression. It is retained as the honest source: the moment the
        /// grammar accepts anything non-canonical (a `v` prefix, a two-part version, a vendor
        /// suffix), a diagnostic reader must see what the peer actually sent rather than this
        /// parser's opinion of it, and callers that already read `raw` will not need to change.
        raw: String,
    },
}

/// Is this VERSION ZERO — the legacy "no version" sentinel, whatever it is dressed in?
///
/// Three of dig-gossip's four handshake send sites hardcoded `"0.0.0"` before dig_ecosystem#2215,
/// so version zero is not a hypothetical value: it is what the live fleet is sending right now. It
/// means "this build predates the field", which is [`PeerSoftware::Unknown`]; mapping it to a
/// *version* would make the whole existing network read as ancient.
///
/// The test is over the major/minor/patch TRIPLE, ignoring any pre-release or build metadata. A
/// peer advertising `0.0.0-rc.1` is no more versioned than one advertising `0.0.0`, and matching
/// the bare string would let the decorated forms through as real builds at version zero.
fn is_version_zero(version: &semver::Version) -> bool {
    version.major == 0 && version.minor == 0 && version.patch == 0
}

/// The separator between the product and the version in a `product/semver` advertisement.
const PRODUCT_VERSION_SEPARATOR: char = '/';

impl PeerSoftware {
    /// Interpret a peer's advertised `software_version` string.
    ///
    /// Returns [`Unknown`](PeerSoftware::Unknown) for an empty or blank string, for anything that
    /// is not `product/semver` with both parts non-empty and the version parsing as semver, and for
    /// any advertisement whose version is VERSION ZERO.
    ///
    /// Version zero is the legacy sentinel and is matched as a CLASS, not as a string: the bare
    /// `0.0.0`, a product-qualified `dig-node/0.0.0`, and every decorated form (`0.0.0-rc.1`,
    /// `0.0.0+build`, `0.0.0-0`) all mean "unversioned". A peer advertising `0.0.0-rc.1` is no more
    /// versioned than one advertising `0.0.0`.
    ///
    /// A product name may contain `/`; the split is at the LAST separator.
    pub fn parse(advertised: &str) -> Self {
        let raw = advertised.trim();

        // No separator at all: an empty advertisement, a bare version, a product with no version,
        // or a bare version-zero sentinel (`0.0.0`, `0.0.0-rc.1`) — none of which contain a `/`, so
        // they land here rather than needing a clause of their own. None of them name a build.
        let Some((product, version)) = raw.rsplit_once(PRODUCT_VERSION_SEPARATOR) else {
            return Self::Unknown;
        };
        if product.is_empty() {
            return Self::Unknown;
        }
        let Ok(version) = version.parse::<semver::Version>() else {
            return Self::Unknown;
        };
        // The sentinel is VERSION ZERO, a class — not the three-character string. Comparing the
        // PARSED version is what makes `0.0.0+build`, `0.0.0-rc.1`, and `0.0.0-0` Unknown too; a
        // string comparison would report each of them as a real build at version zero.
        if is_version_zero(&version) {
            return Self::Unknown;
        }

        Self::Reported {
            product: product.to_string(),
            version,
            raw: raw.to_string(),
        }
    }
}

/// `control.status` — a rich node status snapshot.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StatusResult {
    /// Always `true` for a responding node.
    pub running: bool,
    /// The service name (`"dig-node"`).
    pub service: String,
    /// The node binary's semantic version.
    pub version: String,
    /// The git commit the binary was built from (or `"unknown"`).
    pub commit: String,
    /// The DIG read protocol version the node speaks.
    pub protocol: String,
    /// Process uptime in seconds.
    pub uptime_secs: u64,
    /// The loopback `host:port` the node is bound to.
    pub addr: String,
    /// The upstream DIG RPC the node proxies/syncs to.
    pub upstream: String,
    /// The on-disk cache view.
    pub cache: CacheView,
    /// Distinct stores held (from the cache).
    pub hosted_store_count: u64,
    /// Cached capsule count.
    pub cached_capsule_count: u64,
    /// Pinned-store count.
    pub pinned_store_count: u64,
    /// §21 sync availability.
    pub sync: SyncAvailability,
}

/// `control.config.get` — the node's effective configuration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConfigResult {
    /// The bound `host:port`.
    pub addr: String,
    /// The bound port, as a string.
    pub port: String,
    /// The effective upstream DIG RPC.
    pub upstream: String,
    /// The persisted upstream override, or `null` when unset.
    pub upstream_override: Option<String>,
    /// The cache directory.
    pub cache_dir: String,
    /// Whether the cache is the machine-wide shared cache.
    pub cache_shared: bool,
    /// The node's config.json path.
    pub config_path: String,
    /// Whether authenticated §21 sync is available.
    pub sync_available: bool,
}

/// `control.config.setUpstream` — the persisted override + a restart hint.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SetUpstreamResult {
    /// The normalized upstream that was persisted.
    pub upstream: String,
    /// Always `true` — the change takes effect on next node start.
    pub requires_restart: bool,
}

/// `control.log.setLevel` — the applied filter directive.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SetLevelResult {
    /// The EnvFilter directive now in effect.
    pub filter: String,
}

/// `control.cache.setCap` — the applied cap (after the 64 MiB floor).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SetCapResult {
    /// The cache cap now in effect, in bytes.
    pub cap_bytes: u64,
}

/// `control.cache.clear` — the clear acknowledgement.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CacheClearResult {
    /// Always `true`.
    pub cleared: bool,
}

/// One cached capsule of a store, as listed by the hosted-stores methods.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CapsuleEntry {
    /// The capsule reference (`storeId:rootHash`).
    pub capsule: String,
    /// The capsule root hash.
    pub root: String,
    /// The capsule size on disk, in bytes.
    pub size_bytes: u64,
    /// When the capsule was last served, in unix milliseconds.
    pub last_used_unix_ms: u64,
}

/// One hosted/pinned store (`control.hostedStores.list`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HostedStore {
    /// The canonical lowercase 64-hex store id.
    pub store_id: String,
    /// Whether the operator has pinned this store.
    pub pinned: bool,
    /// The number of cached capsules of this store.
    pub capsule_count: u64,
    /// The total cached bytes across this store's capsules.
    pub total_bytes: u64,
    /// The cached capsules of this store.
    pub capsules: Vec<CapsuleEntry>,
}

/// `control.hostedStores.list` — every held/pinned store.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HostedStoresListResult {
    /// The stores, one entry per distinct store id.
    pub stores: Vec<HostedStore>,
}

/// `control.hostedStores.pin` — the pin acknowledgement + the pre-fetch outcome.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PinResult {
    /// The store id that was pinned.
    pub store_id: String,
    /// The pinned root, or `null` when pinned at store level.
    pub root: Option<String>,
    /// Always `true`.
    pub pinned: bool,
    /// The in-band pre-fetch outcome (`{status, …}`) — its shape varies with the fetch path.
    pub fetch: serde_json::Value,
}

/// `control.hostedStores.unpin` — the unpin acknowledgement + eviction count.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UnpinResult {
    /// The store id that was unpinned.
    pub store_id: String,
    /// Whether a pin registry entry was actually removed.
    pub unpinned: bool,
    /// How many cached capsules of the store were evicted.
    pub evicted_capsules: u64,
}

/// `control.hostedStores.status` — per-store pinned flag + cached capsules.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HostedStoreStatusResult {
    /// The store id queried.
    pub store_id: String,
    /// Whether the store is pinned.
    pub pinned: bool,
    /// The number of cached capsules.
    pub capsule_count: u64,
    /// The total cached bytes.
    pub total_bytes: u64,
    /// The cached capsules.
    pub capsules: Vec<CapsuleEntry>,
}

/// `control.capsule.fetch` — the P2P pull acknowledgement.
///
/// This is a STARTED/ALREADY-CACHED acknowledgement, not a completion report: unlike
/// `control.sync.trigger`'s §21 HTTP fetch (synchronous, single hop), a P2P pull recursively
/// discovers a holder and may stream through several onion hops, so it can take arbitrarily
/// long. A caller wanting to know when the bytes actually land polls `control.hostedStores.status`
/// for the store, the same way `control.hostedStores.pin`'s pre-fetch is observed today.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CapsuleFetchResult {
    /// The store id the fetch was requested for.
    pub store: String,
    /// The capsule root requested.
    pub root: String,
    /// The outcome: `"started"` (a P2P pull was launched), `"already_cached"` (the capsule was
    /// already on disk and no pull was needed), or `"unavailable"` (recursive discovery found no
    /// holder to pull from right now — the caller may retry later).
    pub status: String,
}

/// `control.sync.status` — §21 sync availability + pin coverage.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SyncStatusResult {
    /// Whether authenticated §21 whole-store sync is available.
    pub available: bool,
    /// The sync method name.
    pub method: String,
    /// The number of pinned stores.
    pub pinned_total: u64,
    /// How many pinned stores currently have a cached capsule.
    pub pinned_synced: u64,
    /// Whether whole-store (root-less) sync is supported by this build.
    pub whole_store_trigger_supported: bool,
}

/// `control.sync.trigger` — the synced-capsule outcome.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SyncTriggerResult {
    /// The store id synced.
    pub store_id: String,
    /// The capsule root synced.
    pub root: String,
    /// The outcome status (`"synced"`).
    pub status: String,
    /// The synced capsule size, in bytes.
    pub size_bytes: u64,
    /// The served root the node verified against.
    pub served_root: String,
}

/// `control.pairing.approve` — the mint acknowledgement + the new token's id.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PairingApproveResult {
    /// Always `true`.
    pub approved: bool,
    /// The requesting client's declared name.
    pub client_name: String,
    /// The short id of the minted paired token (used to revoke it).
    pub token_id: String,
}

/// `control.pairing.revoke` — the revoke acknowledgement.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PairingRevokeResult {
    /// Whether a token was actually removed.
    pub revoked: bool,
    /// The token id that was targeted.
    pub token_id: String,
}

/// `control.peerCounts` — how many peers this node holds on EACH network.
///
/// # Two networks, two numbers, and neither is "peers"
///
/// A DIG node is connected to two entirely separate networks at once: the DIG content/gossip
/// network (port 9445), and the Chia full nodes its wallet chain sync talks to. The counts are
/// unrelated and move independently — a node with many DIG peers and no Chia peer is serving content
/// while its wallet is not syncing at all, and the reverse is equally possible.
///
/// So neither field is spelled `peers`, `connected_peers` or `peer_count`. A bare name forces a
/// consumer to KNOW which network a number describes, and the failure when it guesses wrong is
/// silent: a plausible integer in a right-looking place. This method exists so that one call answers
/// for both networks and each answer names its own.
///
/// # `relay.peer_count` from `control.peerStatus` is NOT this
///
/// That field counts the peers connected to THE RELAY, not to this node, and it is frequently the
/// only non-zero number on a node connected to nothing. It is never the answer to "how many peers
/// does this node have"; [`dig_peer_count`](Self::dig_peer_count) is.
///
/// # `Some(0)` is measured; `null` is unknown
///
/// `0` means the node looked at that network and found nothing connected. `null` means it cannot
/// observe the count at all — which is what a node whose peer network is not running reports, since
/// a zero there would claim "nothing is connected" about a network it never asked.
///
/// # Connected is not the same question as known
///
/// [`known_dig_peer_count`](PeerCountsResult::known_dig_peer_count) answers a THIRD question —
/// how many DIG peers this node has heard of, connected or not — so that a lonely node can say
/// which of the two ways it is lonely. Every count here is one node's local view; none of them is
/// the size of the network.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct PeerCountsResult {
    /// Peers on the DIG content/gossip network (port 9445) — dig-node-core's `connected_peers`, the
    /// same figure `control.peerStatus` reports. `0` is an observed zero; `null` is unobservable.
    pub dig_peer_count: Option<u32>,
    /// CHIA full-node peers the wallet's chain sync holds. The SAME observation
    /// [`WalletSyncStatusResult::chia_peer_count`] reports — a conforming node MUST serve both from
    /// one source, and the two MUST agree within a single node's view.
    pub chia_peer_count: Option<u32>,
    /// DIG peers this node has LEARNED OF but is not necessarily connected to — the size of its own
    /// discovered-peer address book (dig_ecosystem#2570).
    ///
    /// This exists so a client can distinguish "this node is connected to nobody" from "there is
    /// nobody to connect to", which [`dig_peer_count`](Self::dig_peer_count) alone cannot tell
    /// apart. A node reporting `dig_peer_count: 0` alongside a known count of 40 has a reachability
    /// problem; one reporting `0` alongside `0` has a discovery problem. Those are different faults
    /// with different remedies, and until this field existed both rendered as the same zero.
    ///
    /// # What it does NOT count
    ///
    /// **It is not the size of the DIG network, and no field on this interface is.** It is ONE
    /// node's local view and therefore a LOWER BOUND: it omits every peer this node has not been
    /// introduced to, every peer behind a relay it does not use, every peer that entered the
    /// network after this node's last discovery pass, and every entry its address book evicted
    /// under its bucket limits. Two healthy nodes on the same network will report different numbers
    /// and neither is wrong. A client MUST label it as discovered/known peers — rendering it as
    /// "total peers" or "network size" asserts global knowledge that nothing here has.
    ///
    /// It is also NOT `control.peerStatus`'s `relay.peer_count`, which counts peers registered with
    /// THE RELAY — a different party's view, scoped to that one relay.
    ///
    /// # Relationship to [`dig_peer_count`](Self::dig_peer_count)
    ///
    /// Normally `known_dig_peer_count >= dig_peer_count`, since a connected peer is a peer this node
    /// knows of. A client MUST NOT rely on that ordering as an invariant: the two are sampled from
    /// separate structures and a transient inversion during churn is not a protocol violation.
    ///
    /// # `Some(0)` is measured; `null` is unknown
    ///
    /// `0` means the node consulted its address book and found it empty. `null` means it could not
    /// consult it at all — which is what a node whose peer network is not running reports, and what
    /// a node too old to have this field reports by omitting it. Serde treats the missing field as
    /// `None`, so an older node's payload decodes here as "unknown" rather than being rejected, and
    /// an older CLIENT ignores the extra field: the addition is compatible in both directions.
    pub known_dig_peer_count: Option<u32>,
}

/// `control.peers.connect` — the connected peer's id.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PeersConnectResult {
    /// Always `true` on success.
    pub connected: bool,
    /// The connected peer's id.
    pub peer_id: String,
}

/// `control.peers.disconnect` — the dropped peer's id.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PeersDisconnectResult {
    /// Always `true` (idempotent — dropping an absent peer still succeeds).
    pub disconnected: bool,
    /// The peer id that was targeted (trimmed + lower-cased).
    pub peer_id: String,
}

/// One tracked Chia full-node peer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChiaPeerEntry {
    /// The peer's IP address, in the canonical form defined by
    /// [`crate::params::canonical_peer_ip`] — a bare literal, never bracketed and never carrying a
    /// port.
    pub ip: String,
    /// The peer's port (the standard full-node port unless the entry says otherwise).
    pub port: u16,
    /// The peak height this peer last reported, or `null` where the node has NO telemetry for it
    /// yet.
    ///
    /// `null` means UNOBSERVABLE, never zero — the convention `control.peerCounts` and
    /// `control.wallet.peak` already use, and it matters more here: this is the one signal an
    /// operator has for judging whether a peer they trust WITHOUT corroboration is current or
    /// stuck, and a peer nobody has polled must not read as a peer stalled at genesis.
    ///
    /// A reported height is that peer's CLAIM, never a fact this node verified — never a
    /// fabricated height, and never to be aggregated into a chain position (NC-12: a maximum over
    /// claimed peaks is whatever the most dishonest peer says).
    pub peak_height: Option<u32>,
    /// TRUE where a person added this peer by hand, which is exactly the set that is trusted
    /// WITHOUT corroboration. Discovered peers are `false` and stay subject to agreement.
    pub user_managed: bool,
    /// TRUE where this entry is BANNED — kept so discovery cannot re-add it, and excluded from
    /// every chain read.
    ///
    /// Banned entries appear in this list because it is the ONLY enumeration of the banned set,
    /// and a blocklist a person cannot read is a blocklist they cannot correct.
    pub banned: bool,
}

/// `control.chiaPeers.list` — every tracked Chia peer: trusted, discovered and banned alike.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChiaPeersListResult {
    /// The tracked peers — read `user_managed` to tell the trusted set from the discovered one,
    /// and `banned` to see the exclusions. A conforming node MUST NOT omit banned entries: this
    /// list is the only way to enumerate them.
    pub peers: Vec<ChiaPeerEntry>,
}

/// `control.chiaPeers.add` — the acknowledgement, including the cost that was paid.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChiaPeersAddResult {
    /// Always `true` on success (idempotent — re-adding a known peer succeeds and un-bans it).
    pub added: bool,
    /// The peer's IP address as stored, in the canonical form defined by
    /// [`crate::params::canonical_peer_ip`].
    pub ip: String,
    /// The port the entry was stored at.
    pub port: u16,
    /// Whether this peer is NOW believed without corroboration — the RESULTING trust state, not a
    /// restatement of what was asked for.
    ///
    /// `true` in the ordinary case, and a conforming node MUST report `false` where the entry did
    /// not end up trusted, however that came about (an upsert that touches other columns and
    /// leaves the trusted flag alone is how it happens in practice). Reported honestly, this is
    /// the only way an operator learns that the node they believe they configured is still subject
    /// to corroboration; reported as a constant, it is a claim about custody-grade authority that
    /// nothing checks.
    pub corroboration_bypassed: bool,
    /// The human-readable warning the node authored for this call, to be rendered VERBATIM to the
    /// person who made it.
    ///
    /// This is the field a client quotes instead of restating the cost locally and drifting from
    /// the node's wording. It MUST be non-empty and MUST name the corroboration bypass; a client
    /// MUST NOT paraphrase, truncate or suppress it.
    pub notice: String,
}

/// What `control.chiaPeers.remove` actually DID.
///
/// An enum rather than a boolean, and deliberately with no always-true companion field, because
/// `remove` is the ONLY way to un-trust a peer holding unbounded authority over the money-bearing
/// wallet replica. A remedy that cannot report its own failure is worse than no remedy: the
/// operator believes they revoked custody-grade trust and they did not. A consumer has to MATCH on
/// this, so it cannot render "nothing was there" as "it is gone".
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ChiaPeerRemovalOutcome {
    /// A matching entry existed and is gone — or, with `ban`, is now banned.
    Removed,
    /// NOTHING matched the address given. The trusted set is unchanged, so any peer the caller
    /// meant to un-trust is STILL trusted — most often because the address was spelled differently
    /// from the stored entry. A client MUST surface this as a failure to act, never as success.
    NoSuchPeer,
}

/// `control.chiaPeers.remove` — the acknowledgement.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChiaPeersRemoveResult {
    /// What happened — see [`ChiaPeerRemovalOutcome`]. There is no `removed: true` here, on
    /// purpose.
    pub outcome: ChiaPeerRemovalOutcome,
    /// The peer's IP address as targeted, in the canonical form defined by
    /// [`crate::params::canonical_peer_ip`].
    pub ip: String,
    /// Whether the peer is now BANNED rather than merely forgotten.
    pub banned: bool,
}

/// `control.subscribe` — the subscription acknowledgement.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SubscribeResult {
    /// Always `true`.
    pub subscribed: bool,
    /// Whether the store was newly added (vs already subscribed).
    pub added: bool,
    /// The canonical persisted store id (trimmed + lower-cased).
    pub store_id: String,
    /// What the node recorded the subscription as following. OMITTED means
    /// [`SubscriptionKind::Capsule`](crate::params::SubscriptionKind::Capsule), so a node build
    /// that predates the field still parses here rather than failing the whole response.
    #[serde(default)]
    pub kind: crate::params::SubscriptionKind,
}

/// `control.unsubscribe` — the unsubscription acknowledgement.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UnsubscribeResult {
    /// Always `false`.
    pub subscribed: bool,
    /// Whether the store was actually removed.
    pub removed: bool,
    /// The canonical store id.
    pub store_id: String,
}

/// `control.listSubscriptions` — the node's persisted subscription set.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ListSubscriptionsResult {
    /// The subscribed store ids.
    pub subscriptions: Vec<String>,
    /// The subscription count.
    pub count: u64,
}

/// `control.wallet.balance` — an address's balance for one asset, as the node's chain read saw it.
///
/// A READ-only result: this reports chain state, it never moves funds. It is a strict SUPERSET of
/// dig-app's frozen `BalanceResponse { balance }` — the node emits the richer shape, and because
/// dig-app's struct does not deny unknown fields it reads [`balance`](Self::balance) losslessly and
/// ignores the rest. That superset relationship is the "no dig-app code change" guarantee, pinned by
/// the conformance KAT.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WalletBalanceResult {
    /// The CONFIRMED, spendable balance in the asset's base unit (mojos for XCH, base units for DIG).
    /// The only field dig-app 3.x reads.
    pub balance: u64,
    /// Incoming funds seen but not yet confirmed (asset base units); not yet spendable.
    pub pending: u64,
    /// Which tier produced these figures, or `None` from a node too old to disclose it.
    ///
    /// See [`WalletReadSource`]. Absent (`null` / omitted) is a THIRD state, not a default tier:
    /// it means the answering node predates tier disclosure, so the caller knows the tier is
    /// unknown rather than being told a tier that was never reported.
    ///
    /// The [`Option`] carries the backwards compatibility on its own — serde treats a missing
    /// `Option` field as `None` — so no `#[serde(default)]` is needed and none is written; a
    /// REQUIRED field here would reject an older node's payload outright.
    pub source: Option<WalletReadSource>,
    /// Whether THESE figures reflect a caught-up local view. When `false`, they are STALE or came
    /// from the fallback tier.
    ///
    /// This describes the ANSWER, not the node: a [`WalletReadSource::Fallback`] answer is always
    /// `false`, however caught-up the node's own replica happens to be.
    pub synced: bool,
    /// The peak block height the reported figures reflect, or `null` when no height applies —
    /// including every [`WalletReadSource::Fallback`] answer, whose figures came from the oracle's
    /// chain view rather than the node's.
    pub peak_height: Option<u32>,
}

/// Which tier answered a wallet read (dig_ecosystem#2233).
///
/// A node serves a wallet read either from its own chain replica or from a third-party HTTP
/// oracle, and the two are not interchangeable to a caller: the oracle path is a network round
/// trip that **discloses the queried address off-node**, which a user on a metered or private
/// connection has a legitimate interest in knowing about. Reporting the tier is also what makes
/// "the node answered from its own chain state" a falsifiable claim — a sync-progress flag is not,
/// since a flag can flip while the oracle keeps answering.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum WalletReadSource {
    /// The node's own local chain replica. No third party was consulted.
    Db,
    /// A third-party coinset HTTP oracle. The queried value — an address, or a COIN ID on
    /// `control.wallet.coinById` — was disclosed off-node.
    ///
    /// The coin-id case is the more sensitive of the two, and the less obvious: an address is
    /// disclosed on every routine balance poll, whereas querying a freshly created coin id, from the
    /// spender's IP, at the moment of the spend, hands the oracle a `{IP, timestamp, coin id}` tuple
    /// that ties a network identity to a specific new on-chain identity.
    Fallback,
}

/// One coin, as the node's chain read saw it (`control.wallet.coins` / `control.wallet.coinById`).
///
/// The first three fields are byte-identical to dig-app's frozen `CoinRecord`, so its
/// `CoinsResponse` deserializes this losslessly and ignores the rest. The rest is what a spend
/// actually needs: a coin cannot be spent from an id and an amount alone — the parent and the
/// puzzle hash are what reconstruct the `Coin` — and the heights are how a caller tells a confirmed
/// coin from one it only saw in the mempool.
///
/// ONE record type serves both reads deliberately. A second coin shape would be a second thing to
/// keep in step with dig-app's frozen struct, and the two would drift byte-wise the first time only
/// one of them was touched.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WalletCoinRecord {
    /// The coin id, lowercase 64-hex, unprefixed.
    pub coin_id: String,
    /// The asset this coin is denominated in, or `null` when THIS READ DID NOT CLASSIFY THE COIN.
    ///
    /// `null` never means "no asset" and never means XCH by default. It means the answering read
    /// had no basis to say: a singleton, a CAT and a plain XCH coin are indistinguishable from a
    /// coin id alone — telling them apart requires inspecting the puzzle, and the node reads only
    /// the coin record. So `control.wallet.coinById` MUST report `null` here — emitting a concrete
    /// asset on an unclassified read would make the node assert a classification it never verified,
    /// which a caller would then spend against.
    ///
    /// `control.wallet.coins` MUST report the concrete asset it was SCOPED to and MUST NOT emit
    /// `null`. This field is optional only to serve the by-id read; the coins read has no
    /// unclassified case, and dig-app's frozen `CoinRecord` requires a non-null asset there, so a
    /// `null` breaks that read outright rather than degrading it. The type cannot enforce the split
    /// because ONE record shape deliberately serves both reads (see the type docs), which is why the
    /// rule is stated here and pinned by a KAT.
    pub asset: Option<crate::params::Asset>,
    /// The coin's amount, in the asset's base unit.
    pub amount: u64,
    /// The parent coin's id, lowercase 64-hex, unprefixed.
    pub parent_coin_info: String,
    /// The coin's puzzle hash, lowercase 64-hex, unprefixed.
    pub puzzle_hash: String,
    /// The height the coin was created at, or `null` while it is still only in the mempool.
    pub created_height: Option<u32>,
    /// The height the coin was spent at, or `null` when it is unspent.
    pub spent_height: Option<u32>,
}

/// `control.wallet.coins` — an address's spendable coins for one asset.
///
/// # An empty list is an ANSWER, never a fallback
///
/// `coins: []` means the node consulted a chain and that address holds nothing. It is NEVER what a
/// caller gets when the chain could not be reached: those are catalogued errors
/// ([`crate::error::ControlErrorCode::WalletNoChainSource`] / `WalletNotSynced` /
/// `WalletReadFailed` / `WalletRateLimited`). The distinction is the whole point of the method —
/// a well-shaped empty result on an unreachable chain would tell somebody who holds funds that they
/// hold nothing, and a spend built on that answer refuses with a shortfall that is not true.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WalletCoinsResult {
    /// The spendable coins found at the address, possibly empty (see the type docs).
    pub coins: Vec<WalletCoinRecord>,
    /// Which tier answered, or `None` from a node too old to disclose it. See [`WalletReadSource`].
    pub source: Option<WalletReadSource>,
    /// Whether THESE coins reflect a caught-up local view; always `false` for a fallback answer.
    pub synced: bool,
    /// The peak height these coins reflect, or `null` when none applies (every fallback answer).
    pub peak_height: Option<u32>,
}

/// Deserialize an `Option<T>` that is nullable but NOT omittable.
///
/// Serde special-cases a missing field of type `Option<T>` into `None`, so a required-but-nullable
/// field is not expressible by the derive alone. Naming a `deserialize_with` suppresses that
/// special case: an absent key becomes a `missing field` error, while an explicit `null` still
/// decodes to `None`.
fn required_option<'de, D, T>(deserializer: D) -> Result<Option<T>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: Deserialize<'de>,
{
    Option::<T>::deserialize(deserializer)
}

/// `control.wallet.coinById` — ONE coin, named by its own id, spent or unspent.
///
/// # An absent coin is an ANSWER; an unreachable chain is an ERROR
///
/// `coin: null` means a chain WAS consulted and holds no such coin. It is NEVER what a caller gets
/// when the chain could not be reached: those are the catalogued errors
/// ([`crate::error::ControlErrorCode::WalletNoChainSource`] / `WalletReadFailed` /
/// `WalletRateLimited`). Collapsing the two turns "your wifi dropped" into "your mint never
/// happened", and the remedies are opposite: retry the read, versus stop waiting.
///
/// # Why this method exists — observing a mint
///
/// `control.wallet.broadcast`'s `accepted: true` reports mempool admission only; only a buried
/// confirmation of the CREATED COIN is evidence that a mint happened. `control.wallet.coins`
/// cannot supply it — it answers by ADDRESS and lists UNSPENT coins only, so it can see neither the
/// created DID coin nor the funding coin the mint spent. This method is how that evidence is
/// obtained: read the created coin's id for a `created_height`, and the funding coin's id for a
/// [`spent_height`](WalletCoinRecord::spent_height). Without it a mint can be pushed, real XCH can
/// leave the wallet, and the outcome stays permanently "pending".
///
/// # The freshness fields are honest, not decorative
///
/// [`source`](Self::source) discloses which tier answered, and every freshness field describes THAT
/// tier — the same rule the by-address reads carry. A `fallback` answer MUST report
/// [`synced`](Self::synced) `false` and [`peak_height`](Self::peak_height) `null` however caught-up
/// the node's own replica is, because the oracle produced the figures and the replica neither
/// produced them nor bounds their freshness. A `db` answer means the node's OWN replica answered, so
/// it MUST report `synced: true` and the replica's peak.
///
/// # A negative answer requires a view that could have held the coin
///
/// `coin: null` is a VERDICT — it says stop waiting — so it MUST NOT be served from a view that
/// could not have seen the coin in the first place. A node whose replica is still catching up, or
/// whose local index is address-scoped rather than a full chain view, has NOT established that the
/// coin is absent; it has only established that IT cannot see it. Such a node MUST return
/// [`WalletNoChainSource`](crate::error::ControlErrorCode::WalletNoChainSource) or
/// [`WalletReadFailed`](crate::error::ControlErrorCode::WalletReadFailed) and MUST NOT answer
/// `coin: null`.
///
/// This matters precisely for the two coins this method exists to observe. A created coin sits at no
/// wallet address and a spent funding coin is gone from every unspent list, so an address-scoped
/// replica is guaranteed to miss both — and a `coin: null` from it would report a mint that DID
/// happen as never-having-happened, with the funds already gone. `control.wallet.peak` is no escape
/// hatch here: it reports that same replica's height, which can bound a positive confirmation but
/// can never license a negative one.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WalletCoinByIdResult {
    /// The coin, or `null` when the consulted chain holds no coin with that id (see the type docs).
    ///
    /// The key MUST be present. `null` is a verdict here, so an ABSENT key must not decode into one:
    /// serde's default treatment of `Option` makes a missing field indistinguishable from an
    /// explicit `null`, which would let an unrelated or truncated payload — anything at all carrying
    /// a `synced` field — decode into a confident "the chain holds no such coin". `deserialize_with`
    /// suppresses that default so the field is genuinely required.
    #[serde(deserialize_with = "required_option")]
    pub coin: Option<WalletCoinRecord>,
    /// Which tier answered, or `None` from a node too old to disclose it. See [`WalletReadSource`].
    pub source: Option<WalletReadSource>,
    /// Whether this answer reflects a caught-up local view; `false` for every fallback answer.
    pub synced: bool,
    /// The peak height this answer reflects, or `null` when none applies (every fallback answer).
    pub peak_height: Option<u32>,
}

/// One coin's SPEND: the coin that was consumed, plus the two programs that consumed it.
///
/// This is the chia `CoinSpend` in the contract's own wire form — the puzzle reveal and the solution
/// as lowercase hex of their serialized CLVM, beside the [`WalletCoinRecord`] for the spent coin.
/// The coin is carried as the SAME record type the other reads use rather than a trimmed
/// parent/puzzle-hash/amount triple, because a second coin shape is a second thing to keep in step
/// with dig-app's frozen `CoinRecord` (see [`WalletCoinRecord`]).
///
/// # The reveal is checkable, and a conforming node MUST have checked it
///
/// A puzzle reveal is supplied by a peer, and a lying peer can supply a different program. The
/// reveal's tree hash MUST equal the spent coin's own
/// [`puzzle_hash`](WalletCoinRecord::puzzle_hash), which makes the claim self-checking, and a node
/// MUST fail closed — a catalogued error, never a spend carrying an unverified reveal — when the
/// hashes disagree or the reveal does not parse. A caller MAY re-derive the same check from the two
/// fields it is handed; it never has to trust the node to have done it.
///
/// # `spent_height` is present on the coin, always
///
/// A spend exists only because the coin was spent, so
/// [`spent_height`](WalletCoinRecord::spent_height) MUST be non-null here. A spend reporting an
/// unspent coin is a contradiction the shape cannot forbid, so the contract forbids it instead.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WalletCoinSpend {
    /// The coin this spend consumed. Its `spent_height` MUST be non-null (see the type docs).
    pub coin: WalletCoinRecord,
    /// The puzzle reveal: lowercase hex of the serialized CLVM program. MUST tree-hash to
    /// [`coin.puzzle_hash`](WalletCoinRecord::puzzle_hash).
    pub puzzle_reveal: String,
    /// The solution the puzzle was run with: lowercase hex of the serialized CLVM.
    pub solution: String,
}

/// `control.wallet.coinSpend` — the spend that spent one coin, named by that coin's id.
///
/// # `spend: null` is an ANSWER with TWO honest causes; an unreachable chain is an ERROR
///
/// `null` means a chain WAS consulted and no spend of that coin exists there — either because the
/// coin is UNSPENT, or because the chain holds no such coin at all. Both are legitimately "there is
/// no spend", and the contract deliberately does not distinguish them here: a caller that needs to
/// tell them apart asks [`WalletCoinByIdResult`], whose `coin: null` separates the two.
///
/// What `null` NEVER means is that the node could not answer. That is a catalogued error
/// ([`WalletNoChainSource`](crate::error::ControlErrorCode::WalletNoChainSource) /
/// [`WalletReadFailed`](crate::error::ControlErrorCode::WalletReadFailed) /
/// [`WalletRateLimited`](crate::error::ControlErrorCode::WalletRateLimited)). The three-valued
/// distinction is money-critical: a caller following a singleton forward reads "no spend" as *this
/// is the current tip* and stops walking. Collapsing "could not answer" into it makes a stale coin
/// look like the tip, and a spend built against a superseded singleton is invalid.
///
/// # A negative answer requires a view that could have held the spend
///
/// `spend: null` is a VERDICT, and the same rule [`WalletCoinByIdResult`] states applies unchanged: a
/// node whose replica is still catching up, or whose index is address-scoped rather than a full
/// chain view, has established only that IT cannot see the spend. Such a node MUST return
/// `WalletNoChainSource` / `WalletReadFailed` and MUST NOT answer `null`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WalletCoinSpendResult {
    /// The spend, or `null` when the consulted chain holds no spend of that coin (see the type docs).
    ///
    /// The key MUST be present. `null` is a verdict here, so an ABSENT key must not decode into one —
    /// the same reason [`WalletCoinByIdResult::coin`] is required.
    #[serde(deserialize_with = "required_option")]
    pub spend: Option<WalletCoinSpend>,
    /// Which tier answered, or `None` from a node too old to disclose it. See [`WalletReadSource`].
    pub source: Option<WalletReadSource>,
    /// Whether this answer reflects a caught-up local view; `false` for every fallback answer.
    pub synced: bool,
    /// The peak height this answer reflects, or `null` when none applies (every fallback answer).
    pub peak_height: Option<u32>,
}

/// `control.wallet.coinsByParent` — the DIRECT children created by spending one coin.
///
/// # ONE hop, never a walk
///
/// The list is the coins the named parent's spend created, and nothing further. It is not a lineage,
/// not a subtree, and not transitive: a grandchild appears only when the caller asks again with the
/// child's id. A node MUST NOT recurse — an unbounded server-side walk over caller-supplied input is
/// work the caller cannot bound, and a partial walk returned as if complete would be a lineage with
/// a silent hole in it.
///
/// # A page, and it says so — the truncation rule
///
/// [`coins`](Self::coins) is ONE PAGE of the parent's children, bounded by
/// [`COINS_BY_PARENT_MAX_LIMIT`](crate::params::COINS_BY_PARENT_MAX_LIMIT). Whether it is the WHOLE
/// child set is stated by [`complete`](Self::complete) and never left to be inferred from the page's
/// length.
///
/// This is the money-critical shape in this type. A caller walking a lineage reads "no more
/// children" as *this branch ends here*, so a page that was truncated but looks whole terminates the
/// walk early and presents a partial lineage as a complete one. Inferring completeness from
/// `coins.len() < limit` is NOT equivalent and MUST NOT be done: a node is free to return a short
/// page for its own reasons, and a child set that is an exact multiple of the page size makes the
/// last full page indistinguishable from a truncated one.
///
/// # Resuming: the same lesson `control.wallet.arrivals` records
///
/// Resume from [`cursor`](Self::cursor) — the last child you were actually HANDED — by passing it
/// as [`after_coin_id`](crate::params::WalletCoinsByParentParams::after_coin_id). There is
/// deliberately no "where the chain got to" marker on this type to reach for instead; that is the
/// distinction `WalletArrivalsResult::latest` exists to warn about, and the cheapest way not to lose
/// a row to it is to give a caller nothing else to resume from.
///
/// # The order is part of the contract, because paging is meaningless without one
///
/// A node MUST return children in ASCENDING `coin_id` order, and MUST keep that order stable across
/// the pages of one walk. `after_coin_id` means *strictly after this id in that order*. Without a
/// fixed order a cursor names no position, and a walk would silently repeat some children and skip
/// others. Coin ids are fixed-length lowercase hex, so ascending lexicographic order and ascending
/// 32-byte numeric order are the SAME order — an implementation may use whichever it has, and the
/// two can never disagree.
///
/// # An empty list is an ANSWER, never a fallback
///
/// `coins: []` means the node consulted a chain and that parent created no children it knows of —
/// typically because the parent is unspent. It is NEVER what a caller gets when the chain could not
/// be reached: those are the catalogued errors
/// ([`WalletNoChainSource`](crate::error::ControlErrorCode::WalletNoChainSource) /
/// [`WalletReadFailed`](crate::error::ControlErrorCode::WalletReadFailed) /
/// [`WalletRateLimited`](crate::error::ControlErrorCode::WalletRateLimited)). The distinction is the
/// same one every read in this family carries, and it matters most here: a caller walking a
/// singleton forward reads an empty list as *this is the tip*.
///
/// # `asset` is `null` on every record
///
/// A child is named by its parent, not by an address and not by an asset, so this read classifies
/// nothing — exactly like [`WalletCoinByIdResult`]. Every record MUST report
/// [`asset`](WalletCoinRecord::asset) as `null` rather than assert a class the read never verified.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WalletCoinsByParentResult {
    /// One page of the parent's direct children, ascending by `coin_id`, possibly empty. One hop
    /// only, and NOT necessarily the whole child set — see [`complete`](Self::complete).
    pub coins: Vec<WalletCoinRecord>,
    /// Is this page the WHOLE child set?
    ///
    /// `true` means every child the node knows of is in [`coins`](Self::coins) and the walk of this
    /// hop is finished. `false` means the answer was TRUNCATED and more children exist — resume from
    /// [`cursor`](Self::cursor).
    ///
    /// Required on the wire, and stated positively so that the reading a caller falls into when the
    /// field is absent or defaulted is the SAFE one. A boolean spelled `truncated` would default to
    /// `false`, i.e. to "this is everything", which is the claim that ends a lineage walk early;
    /// `complete` defaults to "there may be more", which costs at worst one redundant request.
    pub complete: bool,
    /// The last child in this page — **the value to resume from** — or `null` for an empty page.
    ///
    /// It is the id the caller was HANDED, never a marker for where the chain got to. Pass it as
    /// [`after_coin_id`](crate::params::WalletCoinsByParentParams::after_coin_id) to fetch the next
    /// page.
    ///
    /// The key MUST be present. `null` is meaningful here — it says this page carried nothing — so
    /// an ABSENT key must not decode into it: serde's default treatment of `Option` would let a
    /// truncated or mis-routed payload decode into a confident "there was nothing to resume from".
    #[serde(deserialize_with = "required_option")]
    pub cursor: Option<String>,
    /// Which tier answered, or `None` from a node too old to disclose it. See [`WalletReadSource`].
    pub source: Option<WalletReadSource>,
    /// Whether these children reflect a caught-up local view; `false` for every fallback answer.
    pub synced: bool,
    /// The peak height these children reflect, or `null` when none applies (every fallback answer).
    pub peak_height: Option<u32>,
}

/// `control.wallet.peak` — the node's current chain peak height.
///
/// `peak_height: null` is an honest "this node tracks no height yet", not a zero. A caller bounding
/// a claimed confirmation MUST treat it as unknown rather than as height 0, which every block is
/// trivially above.
///
/// # This `synced` is the WEAKER of the contract's two same-named notions
///
/// [`synced`](Self::synced) here reports only that the replica's initial catch-up COMPLETED. It says
/// nothing about whether the wallet is still connected to a Chia peer, so a node that caught up
/// yesterday and has been offline since still reports `synced: true` beside a height that stopped
/// moving. [`WalletSyncStatusResult::phase`] answers the stronger question — *is this being kept
/// current?* — and `WalletSyncPhase::Synced` therefore IMPLIES this flag while this flag does not
/// imply that phase. The two are stated in terms of each other on purpose: they carry the same word
/// and would otherwise drift apart silently.
///
/// # The height is the last EXISTING block
///
/// It is the height of the last block the peer view reported, never a next-block height. A consumer
/// computing confirmation depth must floor its own arithmetic rather than assume a convention — see
/// [`WalletSyncStatusResult`], which records why.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WalletPeakResult {
    /// The peak block height the node's chain view has reached, or `null` when it has none.
    pub peak_height: Option<u32>,
    /// Whether the node's own chain replica COMPLETED its catch-up. Weaker than
    /// [`WalletSyncPhase::Synced`] — see the type docs.
    pub synced: bool,
}

/// How far the node's wallet chain replica has got — the states a background sync can be in.
///
/// Named states rather than a boolean, because "has never started" and "is caught up" are different
/// facts and a `bool` can only carry one of them. Paired with a `peak_height` a boolean forces a
/// never-started wallet to report some height, and 0 is the only one available — which reads as
/// *synced to the genesis block*, a claim about the chain that is simply false.
///
/// # Nothing to watch is TWO states, not one
///
/// A sync with no addresses to follow is idle for one of two reasons, and they are different
/// sentences to a user with different remedies. [`NoWalletEnrolled`](Self::NoWalletEnrolled) is the
/// honest all-clear: there is no wallet, so watching nothing is correct and complete.
/// [`WalletNotUnlocked`](Self::WalletNotUnlocked) is the opposite — a wallet EXISTS and is not being
/// watched — and reporting it as the all-clear tells a user with real coins that their balance is
/// fully accounted for while the node follows none of their addresses. Merging the two would put a
/// money-lie behind a green tick, so the contract keeps them apart.
///
/// # An unrecognised token is a VALUE, not a parse failure
///
/// [`Unrecognized`](Self::Unrecognized) exists because this enum was once closed, and a node that
/// grew a new phase took every consumer's whole response down with it — see the variant's own docs.
/// Consumers MUST treat an unrecognised phase as *unknown*, never as progress.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum WalletSyncPhase {
    /// No sync has begun: the wallet holds no replica of the chain and is not building one.
    NotStarted,
    /// A sync is running — either the initial catch-up, or the ongoing task that keeps the replica
    /// current. A wallet whose catch-up finished but whose peer connections have all dropped is
    /// `Syncing`, not [`Synced`](Self::Synced): it is trying to be current and is not.
    Syncing,
    /// The initial catch-up completed AND at least one Chia peer connection is currently live: the
    /// replica is caught up and CONNECTED, so it is in a position to be kept current.
    ///
    /// That is what the predicate delivers, and no more. A live connection to a stalled or lagging
    /// peer satisfies it while the replica quietly goes stale, so this phase MUST NOT be read as
    /// proof that the data is FRESH — only that nothing is known to be preventing freshness.
    Synced,
    /// **The honest all-clear: no wallet is enrolled on this node**, so there are no addresses to
    /// follow and a sync would have nothing to do. Not a degraded state and not an error — a node
    /// that has never had a wallet is working exactly as intended.
    ///
    /// A consumer MAY present this as settled. It is the ONLY nothing-to-watch phase for which that
    /// is true: [`WalletNotUnlocked`](Self::WalletNotUnlocked) looks identical from inside the sync
    /// loop and means the opposite.
    ///
    /// [`watched_addresses`](WalletSyncStatusResult::watched_addresses) accompanying this phase is
    /// `Some(0)` — an observed zero, and the zero that is genuinely fine.
    NoWalletEnrolled,
    /// **A wallet IS enrolled, but the node holds no addresses for it, so it is watching nothing.**
    /// The user's coins are not being followed and their balance is not being maintained.
    ///
    /// This is the common state after every restart, because the address set is derived from key
    /// material the node cannot reach until the wallet is unlocked, and nothing back-fills it while
    /// locked. It is emphatically NOT [`NoWalletEnrolled`](Self::NoWalletEnrolled): the difference
    /// between them is the difference between *nothing to do* and *something to do that is not being
    /// done*.
    ///
    /// A consumer MUST NOT render this as synced, settled, or up to date, and MUST NOT present a
    /// balance read under it as complete. The honest rendering names the wallet and the remedy —
    /// *"locked, so it is not being watched yet"* — because unlocking is the action that resolves
    /// it.
    ///
    /// The name says NOT UNLOCKED rather than *locked* on purpose. An empty address set is what the
    /// node can observe; a lock is only the usual cause of it, and a manifest that never carried the
    /// keys reaches the same state without anything having been locked. The phase claims the
    /// observation, and leaves the cause to whatever the node can actually establish.
    WalletNotUnlocked,
    /// **A phase token this build does not know**, carried verbatim.
    ///
    /// # Why this variant exists
    ///
    /// The enum shipped closed. dig-node then grew a phase, and because serde rejects an unknown
    /// variant, the unknown token did not degrade one field — it aborted the entire
    /// [`WalletSyncStatusResult`]. dig-app's sync read became `Err`, its chain-sync state collapsed
    /// to unknown, and the surface rendered nothing at all (dig_ecosystem#2609). Every consumer
    /// built against an older contract than the node it talks to hit it at once.
    ///
    /// # It is deliberately NOT silent
    ///
    /// The token is preserved rather than discarded so the state is *observable*: a consumer can say
    /// which token it failed to understand, and a developer can read it out of a log instead of
    /// reaching for a packet capture. This incident stayed invisible until somebody built a probe
    /// against the published crate; the variant that replaces it should not need one.
    ///
    /// Mapping an unknown token onto [`Synced`](Self::Synced) or [`Syncing`](Self::Syncing) would be
    /// far worse than the parse error it replaces. A parse error is loud and obviously wrong; a
    /// coerced phase is a confident, plausible statement about the user's money that the node never
    /// made. Consumers MUST render this as unknown and MUST NOT infer progress, completion, or a
    /// trustworthy balance from it.
    ///
    /// # The payload is untrusted text
    ///
    /// It is whatever the node sent. A consumer that displays it MUST escape and bound it like any
    /// other foreign string rather than splicing it into a message unchecked. `Debug` escapes it, as
    /// `String`'s always has; [`as_wire`](Self::as_wire) deliberately does not, because a relay must
    /// be able to hand on the exact bytes.
    ///
    /// # Not the same idea as [`PeerSoftware::Unknown`]
    ///
    /// The two look alike and are not. `PeerSoftware::Unknown` is the ABSENCE of a report — the peer
    /// said nothing, or said something unparseable, and there is no datum to keep. Here the node DID
    /// report, and the token it used is a real observation this build cannot interpret. That is why
    /// this variant carries a payload and that one does not, and why the names differ: calling it
    /// `Unknown` would suggest nothing was said.
    Unrecognized(UnknownPhaseToken),
}

/// A phase token this build does not recognise, held so it cannot be confused with one it does.
///
/// # Why the payload is a type and not a bare `String`
///
/// [`WalletSyncPhase::Unrecognized`] serializes whatever it holds. With a public `String` inside,
/// `Unrecognized("synced".to_owned())` was constructible by any consumer, reported
/// `is_recognized() == false` locally, went onto the wire as the bare token `"synced"`, and arrived
/// at the far side as a confident [`WalletSyncPhase::Synced`] — a value that claims the wallet is
/// caught up while calling itself unrecognised. It was also the one value in the type that did not
/// round-trip, contradicting the verbatim-carriage guarantee the variant exists to provide.
///
/// The field is private and this type has no public constructor, so the only way to reach
/// `Unrecognized` from outside the crate is [`WalletSyncPhase::from`], which is TOTAL: hand it a
/// known spelling and it returns that known variant instead. The dishonest value is therefore not
/// merely discouraged — it cannot be built.
///
/// This is deliberately a type-level guard rather than a documented rule. The whole family exists
/// because a wire-level mismatch went unnoticed until someone built a probe, and a rule that only a
/// doc comment enforces is the same shape of mistake one layer up.
///
/// # The seal is guarded by a test that can actually see it removed
///
/// The ordinary unit tests cannot. They reach `Unrecognized` only through
/// [`WalletSyncPhase::from`], and the seal is precisely what determines which values that route can
/// produce — so making this field `pub` again leaves every one of them green while the forged
/// value becomes constructible. Measured: the whole suite passed with the field public.
///
/// A doctest is the instrument that works, because doctests compile as a SEPARATE CRATE and
/// therefore see this type exactly as a consumer does. The one below must FAIL to compile; if the
/// field is ever made public it starts compiling, and `cargo test` reports the doctest as failed.
///
/// ```compile_fail
/// use dig_node_control_interface::results::{UnknownPhaseToken, WalletSyncPhase};
/// // A value that calls itself unrecognised while spelling itself `synced` on the wire.
/// let forged = WalletSyncPhase::Unrecognized(UnknownPhaseToken("synced".to_owned()));
/// ```
///
/// The honest route returns the KNOWN variant instead, which is the whole point:
///
/// ```
/// use dig_node_control_interface::results::WalletSyncPhase;
/// assert_eq!(WalletSyncPhase::from("synced"), WalletSyncPhase::Synced);
/// assert!(WalletSyncPhase::from("synced").is_recognized());
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct UnknownPhaseToken(String);

impl UnknownPhaseToken {
    /// The token's RAW bytes, exactly as the node sent them — the relay path.
    ///
    /// This is the escape hatch, not the default. It exists so a proxy can hand the token on
    /// byte-identically, and it is the ONE accessor that returns unescaped node-supplied text. Do
    /// not route it to a terminal, a log line, or a UI: use [`Display`](Self#impl-Display) or
    /// [`display_bounded`](Self::display_bounded), which escape.
    ///
    /// ```
    /// use dig_node_control_interface::results::WalletSyncPhase;
    /// let phase = WalletSyncPhase::from("a_newer_token");
    /// assert_eq!(phase.unrecognized_token(), Some("a_newer_token"));
    /// ```
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// The token escaped for display and truncated to `max_len` bytes of escaped output.
    ///
    /// What [`Display`](Self#impl-Display) does, plus a length bound — for a log line or a UI label
    /// that must not be handed an unbounded string. Nothing bounds a token's length on the wire (the
    /// contract is transport-agnostic, and rejecting an over-long token would reintroduce the
    /// fail-closed parse this type exists to remove), so the bound belongs at the point of display.
    ///
    /// The escaped content is at most `max_len` bytes. A single `…` is appended when anything was
    /// dropped, so a truncated rendering is never mistaken for the whole token.
    ///
    /// ```
    /// use dig_node_control_interface::results::WalletSyncPhase;
    /// let phase = WalletSyncPhase::from("a_very_long_token_from_a_newer_node");
    /// let token = phase.unrecognized_token_value().unwrap();
    /// assert_eq!(token.display_bounded(10), "a_very_lon…");
    /// ```
    pub fn display_bounded(&self, max_len: usize) -> String {
        let mut rendered = String::new();
        let mut dropped = false;

        for character in self.0.chars() {
            let escaped: String = character.escape_debug().collect();
            if rendered.len() + escaped.len() > max_len {
                dropped = true;
                break;
            }
            rendered.push_str(&escaped);
        }
        if dropped {
            rendered.push('…');
        }
        rendered
    }
}

impl std::fmt::Display for UnknownPhaseToken {
    /// The token ESCAPED — the safe default, because this is the accessor a log line reaches for.
    ///
    /// # Why the default escapes rather than the opposite
    ///
    /// The raw token is attacker-influenced text that is designed to be logged, and a node emitting
    /// `"\u{1b}[2K\rsynced"` turns `format!("unknown phase: {token}")` into a terminal line reading
    /// `synced` — the erase-line and carriage-return wipe the prefix that said it was unknown. A
    /// right-to-left override does the same to a UI label. Making the ergonomic path raw and the
    /// safe path opt-in gets that backwards: every consumer would have to remember, and one
    /// forgetting reproduces the exact false-reassurance this family exists to prevent.
    ///
    /// `char::escape_debug` is the escaper because it is the standard library's own, covering C0/C1
    /// controls, `DEL`, and the format characters that carry bidi overrides. A hand-rolled table
    /// here would be a second implementation of a security-relevant rule, and would drift.
    ///
    /// [`as_str`](Self::as_str) remains raw for relaying; [`display_bounded`](Self::display_bounded)
    /// adds a length bound.
    ///
    /// ```
    /// use dig_node_control_interface::results::WalletSyncPhase;
    /// let phase = WalletSyncPhase::from("\u{1b}[2K\rsynced");
    /// let token = phase.unrecognized_token_value().unwrap();
    /// assert_eq!(token.to_string(), "\\u{1b}[2K\\rsynced");
    /// ```
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        for character in self.0.chars() {
            write!(f, "{}", character.escape_debug())?;
        }
        Ok(())
    }
}

impl WalletSyncPhase {
    /// Every phase this build KNOWS, in progress order — the enumeration a machine reads, and the
    /// anchor the conformance KATs pin the wire tokens against.
    ///
    /// [`Unrecognized`](Self::Unrecognized) is absent by definition: it is the absence of a known
    /// token rather than one of them, and it has no fixed wire spelling to pin. A node MUST NOT emit
    /// anything outside this list; a consumer that meets something outside it gets `Unrecognized`
    /// instead of a failed response.
    pub const ALL: &'static [WalletSyncPhase] = &[
        WalletSyncPhase::NotStarted,
        WalletSyncPhase::Syncing,
        WalletSyncPhase::Synced,
        WalletSyncPhase::NoWalletEnrolled,
        WalletSyncPhase::WalletNotUnlocked,
    ];

    /// This phase's exact wire spelling, or the verbatim token for
    /// [`Unrecognized`](Self::Unrecognized).
    ///
    /// The one place a phase becomes a string, so serialization and any display path cannot drift
    /// into two different spellings of the same state.
    pub fn as_wire(&self) -> &str {
        match self {
            WalletSyncPhase::NotStarted => "not_started",
            WalletSyncPhase::Syncing => "syncing",
            WalletSyncPhase::Synced => "synced",
            WalletSyncPhase::NoWalletEnrolled => "no_wallet_enrolled",
            WalletSyncPhase::WalletNotUnlocked => "wallet_not_unlocked",
            WalletSyncPhase::Unrecognized(token) => token.as_str(),
        }
    }

    /// The token a build does not understand, or `None` for every phase it does.
    ///
    /// Lets a consumer log or surface the exact unrecognised spelling without matching the variant
    /// open-coded, which is how the two spellings drift apart.
    pub fn unrecognized_token(&self) -> Option<&str> {
        match self {
            WalletSyncPhase::Unrecognized(token) => Some(token.as_str()),
            _ => None,
        }
    }

    /// Whether this build understands the phase at all.
    ///
    /// The predicate a consumer branches its *"your node may be newer than this app"* path on.
    pub fn is_recognized(&self) -> bool {
        !matches!(self, WalletSyncPhase::Unrecognized(_))
    }

    /// The unrecognised token as its own type, giving access to the escaped renderings.
    ///
    /// [`unrecognized_token`](Self::unrecognized_token) hands back a raw `&str`; this hands back the
    /// [`UnknownPhaseToken`], whose `Display` escapes and whose
    /// [`display_bounded`](UnknownPhaseToken::display_bounded) also truncates.
    pub fn unrecognized_token_value(&self) -> Option<&UnknownPhaseToken> {
        match self {
            WalletSyncPhase::Unrecognized(token) => Some(token),
            _ => None,
        }
    }

    /// Whether a consumer may present this phase as SETTLED — nothing outstanding, nothing to do.
    ///
    /// # Why this is a method and not a rule in the docs
    ///
    /// Two phases mean "the sync is idle" and only one of them is good news.
    /// [`NoWalletEnrolled`](Self::NoWalletEnrolled) is complete and correct;
    /// [`WalletNotUnlocked`](Self::WalletNotUnlocked) is a wallet whose coins nobody is following.
    /// Rendering the second as settled is the money-lie this family exists to prevent, and it is one
    /// mistaken `||` away in every consumer that writes the rule itself.
    ///
    /// Stating it once here makes it a compiler-checked fact rather than a paragraph each consumer
    /// re-derives — a second implementation of a rule like this is a drift bug waiting to happen.
    /// An unrecognised phase is never settled: this build cannot know what the node meant.
    ///
    /// ```
    /// use dig_node_control_interface::results::WalletSyncPhase;
    /// assert!(WalletSyncPhase::Synced.may_render_as_settled());
    /// assert!(WalletSyncPhase::NoWalletEnrolled.may_render_as_settled());
    /// // A wallet exists and nothing is watching it — never settled.
    /// assert!(!WalletSyncPhase::WalletNotUnlocked.may_render_as_settled());
    /// assert!(!WalletSyncPhase::from("a_newer_token").may_render_as_settled());
    /// ```
    pub fn may_render_as_settled(&self) -> bool {
        // An exhaustive match, not a `matches!`: a phase added later must be classified here
        // deliberately, and the compiler is what forces that rather than a reviewer noticing.
        match self {
            WalletSyncPhase::Synced | WalletSyncPhase::NoWalletEnrolled => true,
            WalletSyncPhase::NotStarted
            | WalletSyncPhase::Syncing
            | WalletSyncPhase::WalletNotUnlocked
            | WalletSyncPhase::Unrecognized(_) => false,
        }
    }
}

impl From<&str> for WalletSyncPhase {
    /// Every token maps to a phase — an unknown one to
    /// [`Unrecognized`](WalletSyncPhase::Unrecognized). Total by construction, so no caller can
    /// reintroduce the fail-closed behaviour this type exists to remove.
    fn from(token: &str) -> Self {
        match token {
            "not_started" => WalletSyncPhase::NotStarted,
            "syncing" => WalletSyncPhase::Syncing,
            "synced" => WalletSyncPhase::Synced,
            "no_wallet_enrolled" => WalletSyncPhase::NoWalletEnrolled,
            "wallet_not_unlocked" => WalletSyncPhase::WalletNotUnlocked,
            other => WalletSyncPhase::Unrecognized(UnknownPhaseToken(other.to_owned())),
        }
    }
}

impl Serialize for WalletSyncPhase {
    /// A bare JSON string, exactly as the derived `rename_all = "snake_case"` produced before this
    /// type grew an unrecognised arm — so an [`Unrecognized`](WalletSyncPhase::Unrecognized) token
    /// round-trips back out byte-identical rather than being rewritten or dropped by a relay.
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.as_wire())
    }
}

impl<'de> Deserialize<'de> for WalletSyncPhase {
    /// Accepts ANY string. A non-string is still a type error — a number or an object where a phase
    /// belongs is a malformed response, not a newer node.
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let token = <std::borrow::Cow<'de, str>>::deserialize(deserializer)?;
        Ok(WalletSyncPhase::from(token.as_ref()))
    }
}

/// `control.wallet.syncStatus` — is the wallet's chain replica being kept current, how far has it
/// got, and how many Chia peers is it using?
///
/// # `Synced` means CAUGHT UP AND CONNECTED, not ONCE CAUGHT UP
///
/// [`phase`](Self::phase) is [`WalletSyncPhase::Synced`] only when the initial catch-up completed
/// AND at least one Chia peer connection is live right now. A wallet that caught up yesterday and
/// has been offline since MUST report [`Syncing`](WalletSyncPhase::Syncing). This makes `phase ==
/// Synced` STRICTLY STRONGER than [`WalletPeakResult::synced`], which reflects only the
/// completed-catch-up flag: `Synced` implies that flag, the flag does not imply `Synced`. Both types
/// say so, because the two notions share a word and nothing but the docs would keep them aligned.
///
/// This is the whole reason the method exists. A surface asking *does my wallet stay synced?* cannot
/// be answered by a flag that a disconnected wallet still sets.
///
/// **`Synced` is nevertheless not a freshness guarantee.** Being connected is not being up to date:
/// a live connection to a stalled or lagging peer satisfies the predicate while the replica goes
/// stale. The phase reports that catch-up finished and a peer is attached — that nothing KNOWN is
/// preventing the replica from being kept current — and a consumer needing actual freshness must
/// compare [`peak_height`](Self::peak_height) against something, not read this phase. Stating the
/// limit is the point: this family exists because a surface asserted more than it knew.
///
/// # The height NEVER comes from a third-party oracle
///
/// [`peak_height`](Self::peak_height) is the node's OWN replica's height or `null`. It MUST NOT fall
/// back to the coinset oracle. `control.wallet.peak` deliberately does fall back, because it answers
/// a different question — *what height is the chain at?* — whereas this field answers *how far has
/// this replica got?* An oracle's height here would report a caller's own sync progress using a
/// number the replica never reached, which is precisely the reading a progress display makes.
///
/// # `chia_peer_count: 0` is a disambiguator, not a phase
///
/// A sync that is running while connected to nothing reports `Syncing` with a count of `0`, and a
/// consumer SHOULD render the count alongside the phase for exactly that reason: "syncing — no
/// peers" is honest where a bare "syncing" implies progress that is not happening. `null` means the
/// node cannot observe the count at all and licenses no claim about connectivity either way.
///
/// # `watched_addresses` is what makes an idle sync readable
///
/// A sync following nothing is idle, and the phase alone does not say whether that is correct. The
/// count is the second fact that settles it: `0` beside [`WalletSyncPhase::NoWalletEnrolled`] is a
/// complete and honest picture, while `0` beside [`WalletSyncPhase::WalletNotUnlocked`] is a wallet
/// whose coins nobody is following. A consumer SHOULD render the two together for the same reason it
/// renders the peer count beside `Syncing`.
///
/// `Some(0)` is an OBSERVED zero — the node looked and is following no addresses. `None` means the
/// node did not report the number, which is not the same claim and MUST NOT be rendered as zero: a
/// node that cannot say how many addresses it follows has not told you that it follows none.
///
/// A `Synced` phase with `watched_addresses: Some(0)` is a contradiction a conforming node MUST NOT
/// emit — a sync following no addresses has not caught anything up. A consumer meeting it SHOULD
/// trust the count over the phase, because the count is the narrower claim.
///
/// # An older node's payload still parses
///
/// A node that predates `watched_addresses` omits the key, and it deserializes to `None` — *the node
/// did not report it*. That tolerance is required, not incidental: a mandatory new field would make
/// every older node unreadable to a client that has it, which is dig_ecosystem#2609 in mirror image
/// — the same fail-closed break with the old and new sides swapped. A contract that tolerates a
/// token from the future must equally tolerate a payload from the past.
///
/// **Every `Option` field here behaves this way**, because serde decodes a missing `Option` to
/// `None`. So `peak_height` and `chia_peer_count` are absent-tolerant too, and have been since this
/// type shipped. Only [`phase`](Self::phase) is structurally mandatory. A conforming node MUST still
/// emit all four keys — absence is a compatibility allowance for older builds, never a licence to
/// omit an observation — and a consumer MUST read an absent count as unreported rather than zero.
///
/// # These are CHIA peers, not DIG peers
///
/// [`chia_peer_count`](Self::chia_peer_count) counts CHIA FULL-NODE peers the wallet's chain sync is
/// connected to. It is NOT the DIG gossip/content peer count from `control.peerStatus`
/// (`connected_peers` / `relay_peer_count`); the two are unrelated numbers that move independently.
/// A surface that placed one of them beside a wallet sync status under a bare label of "peers" would
/// assert something false — a node with many DIG peers and no Chia peer is a wallet that is not
/// syncing at all. A caller that wants BOTH networks' counts reads [`PeerCountsResult`], which is
/// the one call that answers for each network by name.
///
/// # The duplicated field is ONE observation
///
/// [`chia_peer_count`](Self::chia_peer_count) also appears on [`PeerCountsResult`], and the two are
/// the SAME observation: a conforming node MUST serve them from one source, and they MUST agree
/// within a single node's view. The field is duplicated rather than moved because it is load-bearing
/// HERE — `chia_peer_count: 0` beside `Syncing` is the honest "syncing — no peers" state, and a
/// phase separated from its count reads as a contradiction. A DIG content-network count, by
/// contrast, is not a wallet fact and does not vary with wallet state, which is why it is absent
/// from this type rather than added for symmetry.
///
/// # Which field combinations are meaningful
///
/// `{phase: Synced, peak_height: null}` MUST NOT be emitted. A node records its peak BEFORE it marks
/// the initial catch-up complete, so a completed catch-up always has a height behind it; a `Synced`
/// with no height describes a state a conforming node cannot be in, and a consumer has no honest
/// reading for it.
///
/// `{phase: NotStarted, peak_height: <some height>}` is the opposite case, and is EXPLICITLY
/// LEGITIMATE — it is not a contradiction and MUST NOT be "fixed". The height is persisted in the
/// wallet database, while the phase describes whether a sync is running IN THIS PROCESS. A node that
/// synced yesterday and has just restarted reports exactly this, and reports it truthfully: *here is
/// the height I reached, and no sync is running right now.* Forbidding the pair would force a
/// conforming node to either fabricate a phase it is not in or discard a height it genuinely has —
/// which is the dishonesty this method was created to prevent. `peak_height: null` alongside
/// `NotStarted` is equally legitimate and means a wallet that has never synced at all.
///
/// # No confirmation-depth arithmetic happens here
///
/// The height recorded is the height of the LAST EXISTING block the peer view reported
/// (`NewPeakWallet.height` / `RespondPuzzleState.height` from a real full node). This surface
/// performs no depth arithmetic. dig_ecosystem#2483 records that `peak_height`'s meaning differs
/// between a simulator (the NEXT height) and a full node (the last existing one), so a consumer
/// computing depth must floor its own input rather than assume a convention.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WalletSyncStatusResult {
    /// Which state the wallet's chain sync is in. See [`WalletSyncPhase`].
    pub phase: WalletSyncPhase,
    /// The replica's own peak height, or `null` when it has none — never height 0 as a stand-in for
    /// unknown, and never an oracle's height. See the type docs.
    pub peak_height: Option<u32>,
    /// How many CHIA full-node peers the sync is connected to. `0` is an observed zero; `null` means
    /// the node cannot observe the count. Not the DIG peer count — see the type docs.
    pub chia_peer_count: Option<u32>,
    /// How many addresses the wallet sync is actually following. `Some(0)` is an observed zero;
    /// `None` means the node did not report the number at all — including because it predates the
    /// field. See the type docs for why that distinction is load-bearing.
    pub watched_addresses: Option<u32>,
    /// How many peers the REPLICA's own subscription supervisor is writing through. The supervisor
    /// holds AT MOST ONE subscription peer by design, so this is a 0-or-1 fact about whether the
    /// replica is currently being kept fed — never a measure of network reach. `None` means no
    /// supervisor is attached at all, not that it counted zero.
    ///
    /// This is deliberately NOT [`chia_peer_count`](Self::chia_peer_count) and MUST NOT be summed
    /// with it. Before dig_ecosystem#2806 this crate's `chia_peer_count` carried this narrower
    /// number instead of the wallet's true peer count, so a node with five peers serving every read
    /// reported `chia_peer_count: 1` — the subscription supervisor's single writer standing in for
    /// the whole peer set. The two fields exist side by side so that confusion cannot recur: one
    /// counts what the replica is fed BY, the other counts what the wallet's sync is actually
    /// CONNECTED to.
    pub subscription_peer_count: Option<u32>,
    /// The peak height this node's OWN Chia peers have ANNOUNCED — not the replica's own progress
    /// (see [`peak_height`](Self::peak_height)) and not any oracle's reading. `None` until at least
    /// one peer has said something; never `0`, which every real block height is trivially above and
    /// so can never be an honest "unobserved" stand-in.
    ///
    /// A value here is evidence those peers are live and talking, independent of whether the
    /// replica itself has caught up to it.
    pub chia_peer_peak_height: Option<u32>,
}

/// `control.wallet.broadcast` — the outcome of pushing an already-signed bundle.
///
/// # A rejection is a VALUE; an unreachable network is an ERROR
///
/// A mempool that looked at the bundle and said no is a successful call with `accepted: false` and
/// a [`rejection`](Self::rejection) reason — the bundle was seen and judged. Failing to REACH a
/// mempool is a catalogued error instead. Collapsing the two turns "your wifi dropped" into "your
/// mint failed", and the remedies are opposite: retry the same bundle, versus build a new one.
///
/// # Accepted is not confirmed
///
/// `accepted: true` says the mempool took the bundle. It is not evidence that anything reached a
/// block, and a caller must never record an outcome from it — only a buried confirmation of the
/// created coin is evidence.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WalletBroadcastResult {
    /// Whether the network accepted the bundle into its mempool.
    pub accepted: bool,
    /// The transaction id (the spend bundle's name), lowercase 64-hex, when accepted.
    pub transaction_id: Option<String>,
    /// Why the mempool refused, when it refused. `null` on acceptance.
    pub rejection: Option<String>,
}

/// `control.wallet.watch` — the outcome of enrolling public keys.
///
/// # Two numbers, because idempotence is only observable with both
///
/// [`added`](Self::added) counts the keys this call newly enrolled; [`watched`](Self::watched) is the
/// size of the whole enrolled set afterwards. A re-enrolment of keys the node already follows is a
/// SUCCESS that reports `added: 0` with `watched` unchanged — which is how a client tells "already
/// done" from "nothing happened because the request was ignored". A single number could not: a
/// caller seeing only the total cannot distinguish its own duplicate call from another client's
/// concurrent enrolment.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct WalletWatchResult {
    /// How many of the submitted keys were NOT already enrolled and are now.
    pub added: u32,
    /// How many keys the node follows in total after this call.
    pub watched: u32,
}

/// `control.wallet.unwatch` — the outcome of deregistering public keys.
///
/// [`removed`](Self::removed) counts the submitted keys that were actually enrolled; a key that was
/// never enrolled is not an error, for the same reason a re-enrolment is not one — a client
/// reconciling its own state must be able to say "make sure these are gone" without first asking.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct WalletUnwatchResult {
    /// How many of the submitted keys were enrolled and are no longer.
    pub removed: u32,
    /// How many keys the node follows in total after this call.
    pub watched: u32,
}

/// `control.wallet.watched` — the public keys the node currently follows.
///
/// # No count field
///
/// The list is the answer, and its length is the count. A separate number could disagree with the
/// list it is printed beside, and a client that trusted the number over the rows would reconcile
/// against a set that was never sent.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WalletWatchedResult {
    /// The enrolled public keys, lowercase 96-hex and unprefixed — the same wire form
    /// [`WalletWatchParams`](crate::params::WalletWatchParams) accepts, so a client can compare what
    /// it sent against what came back without normalizing either side.
    pub public_keys: Vec<String>,
}

/// One coin held by a live reservation, and when that hold lapses.
///
/// The expiry travels WITH the coin rather than being summarised once, because a client's honest
/// sentence is per-coin: "this coin is committed until 14:32". A single soonest-expiry figure would
/// be right about the set and wrong about every coin in it but one.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReservedCoin {
    /// The held coin id, lowercase 64-hex and unprefixed.
    pub coin_id: String,
    /// The reservation holding it — the handle
    /// [`release`](crate::params::WalletReservationsReleaseParams) takes. OPAQUE; never parsed.
    pub reservation_id: String,
    /// Unix seconds after which this hold no longer applies, whether or not anyone releases it.
    ///
    /// Always present. A hold with no expiry is a permanent funds lockout, so the contract has no
    /// way to express one.
    pub expires_at_unix: u64,
}

/// `control.wallet.reservations.held` — every coin currently committed to an in-flight spend.
///
/// # An empty list means EMPTY, and an error means UNKNOWN
///
/// `reserved: []` is a positive statement that nothing is held, and a caller may select freely on
/// it. A node that cannot read its reservation set answers
/// [`WalletReservationsUnavailable`](crate::error::ControlErrorCode::WalletReservationsUnavailable)
/// and NEVER an empty list — the two demand opposite actions, and collapsing them restores exactly
/// the cross-process double-select this method exists to prevent.
///
/// # This narrows SELECTION, never BALANCE
///
/// A reserved coin is still the user's money and still counts toward what they hold. Subtracting
/// these from a balance would report a shortfall the user does not have.
///
/// # No count field
///
/// The list is the answer and its length is the count. A separate number could disagree with the
/// rows printed beside it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WalletReservationsHeldResult {
    /// The held coins, each with its holding reservation and expiry.
    pub reserved: Vec<ReservedCoin>,
    /// The node's OWN clock, in unix seconds, at the moment it answered.
    ///
    /// Reported so a client can measure skew against the `expires_at_unix` values it just received.
    /// The caller never supplies a time — see
    /// [`WalletReservationsHeldParams`](crate::params::WalletReservationsHeldParams).
    pub as_of_unix: u64,
}

/// `control.wallet.reservations.reserve` — the handle for a hold that was taken in full.
///
/// Only ever returned when EVERY requested coin was taken. A conflict on any one of them is the
/// error [`WalletCoinsReserved`](crate::error::ControlErrorCode::WalletCoinsReserved) and reserves
/// nothing, so this type has deliberately no "partially reserved" shape to represent.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WalletReservationsReserveResult {
    /// The handle to release with. OPAQUE — store it and send it back; never parse or derive one.
    pub reservation_id: String,
    /// The coins now held, lowercase 64-hex, echoed back so a client can compare what it asked for
    /// against what it got without re-normalizing either side.
    pub coin_ids: Vec<String>,
    /// Unix seconds after which this hold lapses on its own.
    pub expires_at_unix: u64,
    /// The lifetime the node ACTUALLY applied, in seconds — which may be shorter than the
    /// `ttl_secs` requested.
    ///
    /// Returned rather than assumed, because a caller that asked for an hour and silently got ten
    /// minutes would release far too late and believe its coins were still held long after they
    /// were selectable again.
    pub ttl_secs: u64,
}

/// `control.wallet.reservations.release` — what a release actually freed.
///
/// # `released: false` is a SUCCESS
///
/// It means the handle named no live reservation: it lapsed on its TTL first, or was released
/// already. Both are the outcome the caller wanted, and reporting them as errors would push callers
/// toward ignoring the result — which is how the release path quietly stops being used and every
/// hold starts costing its full TTL.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WalletReservationsReleaseResult {
    /// Whether a live reservation was found and freed by THIS call.
    pub released: bool,
    /// The coins freed by this call — empty when `released` is false.
    pub coin_ids: Vec<String>,
}

/// `pairing.request` — the pairing handshake bootstrap (OPEN, no token).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PairingRequestResult {
    /// The opaque pairing id to poll with.
    pub pairing_id: String,
    /// A short numeric code the operator compares before approving.
    pub pairing_code: String,
    /// When the pending pairing expires, in unix milliseconds.
    pub expires_ms: u64,
}

/// `pairing.poll` — the pairing poll outcome (OPEN, no token).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PairingPollResult {
    /// The pairing status (`"pending"` / `"approved"` / …).
    pub status: String,
    /// The minted scoped token, present exactly once after approval.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub token: Option<String>,
}

/// One confirmed incoming payment, as the node's arrival ledger recorded it.
///
/// Every field is a public chain fact about an address this node already watches. There is
/// deliberately no ticker and no formatted amount: naming an asset the node did not attribute, or
/// choosing a divisor for it, would be a claim about WHICH money arrived that the node cannot
/// support.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WalletArrivalRecord {
    /// This arrival's monotonic ledger position. Strictly increasing and never reused, so a stored
    /// position cannot come to mean a different arrival after a reorg.
    pub seq: u64,
    /// The coin that arrived (lowercase hex).
    pub coin_id: String,
    /// The watched puzzle hash it arrived at (lowercase hex).
    pub puzzle_hash: String,
    /// The amount in the asset's own base unit, as a DECIMAL STRING.
    ///
    /// A string because the ledger stores the full `u64` range and a JSON number does not carry it
    /// losslessly — a large mojo amount silently rounds through an f64 parser, which is a wrong
    /// figure about somebody's money.
    pub amount: String,
    /// The CAT asset id (hex TAIL), or `None` for native XCH.
    pub asset_id: Option<String>,
    /// The height the coin was CONFIRMED at. Never optional: an arrival with no confirmed height is
    /// not an arrival, and a node MUST NOT emit a mempool sighting here.
    pub confirmed_height: u32,
}

/// One page of the arrival ledger (`control.wallet.arrivals`).
///
/// An empty [`arrivals`](Self::arrivals) list is an ANSWER — the node consulted its own replica and
/// nothing has arrived since the cursor. It is NOT a claim that the replica is current: a node that
/// has never completed a catch-up has no arrival baseline and reports an empty page forever, which
/// is the honest answer to "what arrived?" from a wallet that cannot tell history from news. A
/// caller that needs to know whether the replica is current asks `control.wallet.syncStatus`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WalletArrivalsResult {
    /// The page, oldest first.
    pub arrivals: Vec<WalletArrivalRecord>,
    /// Where the CLIENT got to: the position of the last row in this page, or the caller's own
    /// `after_seq` when the page is empty. **This is the value to resume from.**
    pub cursor: u64,
    /// Where the LEDGER got to when this answer was assembled.
    ///
    /// Read AFTER the page, so an arrival recorded in between sits above the page and below this
    /// value — which is exactly why resuming from it would step straight over that arrival and lose
    /// a notification silently. It exists for ONE question [`cursor`](Self::cursor) cannot answer: a
    /// first-run client passes it back as `after_seq` to start from NOW instead of replaying the
    /// whole ledger as a burst of toasts.
    pub latest: u64,
}

/// `control.profile.putBody` — the acknowledgement that the node accepted and persisted a body.
///
/// Reaching this result at all means the node RESOLVED the root on chain and found it confirmed and
/// matching the supplied bytes. A refusal is an error, never a success carrying `stored: false` —
/// a caller that has to inspect a boolean to learn whether its profile published is a caller that
/// will forget to.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProfilePutBodyResult {
    /// Always `true`: the body is persisted and this node will serve it to peers.
    pub stored: bool,
    /// The canonical store id the body was filed under (trimmed + lower-cased).
    pub store_id: String,
    /// The CONFIRMED chain root the node verified the body against — echoed so a caller can pin
    /// which root its bytes now stand behind.
    pub root: String,
    /// The DECODED body length in bytes, never above
    /// [`MAX_BODY_BYTES`](crate::params::MAX_BODY_BYTES).
    pub body_bytes: u64,
}

/// `control.profile.getBody` — the body this node holds at a store id + root, if it holds one.
///
/// `body_b64: None` MUST mean "this node was consulted and holds no body at that root". It NEVER
/// means the body could not be read: a read that failed MUST return a catalogued error instead. A
/// caller that cannot tell those apart shows an empty profile for a profile that exists.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProfileGetBodyResult {
    /// The canonical store id the read was scoped to.
    pub store_id: String,
    /// The root the read was scoped to — the SAME root the caller asked for, so a body for another
    /// root can never arrive here unnoticed.
    pub root: String,
    /// The body, standard base64 (padded) of its `DPB` serialization; `None` when this node holds
    /// no body at that root.
    pub body_b64: Option<String>,
    /// The DECODED body length in bytes; `0` when no body is held.
    pub body_bytes: u64,
}

/// Which asset an automated spend moved.
///
/// Externally tagged on `asset` so a CAT carries its asset id in the same object rather than in a
/// sibling field that could go missing: `{"asset":"xch"}`, `{"asset":"dig"}`,
/// `{"asset":"cat","asset_id":"…"}`. An amount is never readable without its asset, so the two
/// travel together.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "asset", rename_all = "snake_case")]
pub enum SpendAsset {
    /// Chia itself.
    Xch,
    /// The $DIG CAT.
    Dig,
    /// Any other CAT, identified by its asset id.
    Cat {
        /// The CAT's asset id, lowercase 64-hex.
        asset_id: String,
    },
}

/// ON WHOSE AUTHORITY the node signed without asking.
///
/// Two fields rather than one sentence, because a person auditing an unapproved spend asks two
/// separate questions: WHO holds the standing permission, and WHICH standing permission was used. A
/// prose sentence answers neither in a form a filter — or a revocation — can act on.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SpendAuthority {
    /// The principal whose funds moved and whose consent was relied on: an account id, a profile id,
    /// or `"node"` for the node's own operating wallet.
    pub principal: String,
    /// The standing grant relied on, in a form the operator can go and revoke — a setting name, a
    /// policy id, a pairing token id.
    pub grant: String,
}

/// Where an attempt died.
///
/// Coarse and stable on purpose: the point is which STEP failed, because that is what tells a person
/// whether their money is at risk. **This distinction is load-bearing and MUST NOT be flattened into
/// a bare "failed".** A client that collapses it is structurally unable to tell someone the truth
/// about their own money.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SpendFailureStage {
    /// The spend could not be built or signed. No signed bundle ever existed, so nothing could reach
    /// a mempool and nothing moved.
    Signing,
    /// A signed bundle was rejected by the mempool, **as far as this node saw**. The bundle may
    /// still have reached the network by another route, or been accepted after the rejection this
    /// node observed.
    Broadcast,
    /// The bundle went out and the chain then reported it could not succeed.
    Confirmation,
}

impl SpendFailureStage {
    /// Could the money have moved anyway, despite the attempt failing at this stage?
    ///
    /// [`Signing`](Self::Signing) is the only stage that answers NO, and it answers structurally: no
    /// signed bundle existed, so there was nothing that could reach a mempool.
    /// [`Broadcast`](Self::Broadcast) and [`Confirmation`](Self::Confirmation) both happen AFTER a
    /// valid signed bundle exists, and neither observation proves absence — a rejection this node
    /// saw does not bind a network it does not fully observe.
    ///
    /// This is the ONE place the distinction is decided. Every consumer asks the stage rather than
    /// re-listing the variants, so the "it did not happen" claim cannot be re-attached to a stage
    /// that never earned it. Written as an exhaustive `match` so adding a stage is a compile error
    /// here, forcing whoever adds it to choose a side.
    pub fn money_may_have_moved(self) -> bool {
        match self {
            SpendFailureStage::Signing => false,
            SpendFailureStage::Broadcast | SpendFailureStage::Confirmation => true,
        }
    }

    /// The stable lowercase wire token.
    pub const fn token(self) -> &'static str {
        match self {
            SpendFailureStage::Signing => "signing",
            SpendFailureStage::Broadcast => "broadcast",
            SpendFailureStage::Confirmation => "confirmation",
        }
    }
}

/// Where one automated spend got to.
///
/// Internally tagged on `state`, so a row is `{"state":"confirmed","height":…,"coin_id":"…"}`.
///
/// # Two shape rules, each from a measured money-lie
///
/// 1. **[`Confirmed`](Self::Confirmed) carries its evidence inside the variant.** There is no
///    optional height field to fill in optimistically, so a row cannot hold a confirmation height
///    without a confirmation.
/// 2. **[`Unresolved`](Self::Unresolved) is NOT a kind of failure.** "The node signed and does not
///    know how it ended" is not "it did not happen": money may well have moved, and saying `failed`
///    about a spend that landed is the same class of lie as claiming an unconfirmed success. A
///    client that maps it onto `failed` to keep a two-state UI has chosen the wrong UI.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum SpendOutcome {
    /// Recorded, not yet handed to the network. Written before the producer may sign.
    Pending,
    /// A signed bundle was accepted by the mempool. NOT a claim that it will confirm.
    Submitted,
    /// The chain shows the coin this spend created.
    Confirmed {
        /// The height the created coin was confirmed at.
        height: u32,
        /// The coin the spend CREATED — the reference a person can paste into an explorer.
        coin_id: String,
    },
    /// The attempt ended in a failure this node observed.
    ///
    /// **This is not uniformly a claim that the money stayed put.** Only
    /// [`SpendFailureStage::Signing`] carries that claim; at `Broadcast` and `Confirmation` a signed
    /// bundle already existed and the outcome is genuinely UNKNOWN. Ask
    /// [`SpendFailureStage::money_may_have_moved`] before rendering any `failed` row as settled.
    Failed {
        /// Which step failed — and, through [`SpendFailureStage::money_may_have_moved`], whether
        /// this row claims the money is untouched or merely records where the attempt died.
        stage: SpendFailureStage,
        /// One line a person can act on. "Insufficient funds" is the difference between a broken
        /// node and a wallet that needs topping up.
        reason: String,
    },
    /// The node signed and does not know how it ended — a timeout, a restart mid-flight, or a
    /// producer that dropped the spend.
    Unresolved {
        /// Why the outcome is unknown.
        reason: String,
    },
}

impl SpendOutcome {
    /// The stable lowercase token, matching the `state` tag and the
    /// [`status`](crate::params::SpendsListParams::status) filter.
    pub const fn token(&self) -> &'static str {
        match self {
            SpendOutcome::Pending => "pending",
            SpendOutcome::Submitted => "submitted",
            SpendOutcome::Confirmed { .. } => "confirmed",
            SpendOutcome::Failed { .. } => "failed",
            SpendOutcome::Unresolved { .. } => "unresolved",
        }
    }

    /// Is what happened to the money still UNKNOWN?
    ///
    /// True for [`Unresolved`](Self::Unresolved), and true for a [`Failed`](Self::Failed) row whose
    /// stage [may have moved money](SpendFailureStage::money_may_have_moved). Those two are the rows
    /// a person still has to chase, and a UI grouping them with settled failures hides exactly the
    /// spends worth looking at.
    ///
    /// `Pending` and `Submitted` are NOT unknown outcomes — they are outcomes that have not happened
    /// yet, and the node expects to learn them. Conflating "in flight" with "lost track of" would
    /// raise an alarm about every spend in progress.
    pub fn outcome_is_unknown(&self) -> bool {
        match self {
            SpendOutcome::Unresolved { .. } => true,
            SpendOutcome::Failed { stage, .. } => stage.money_may_have_moved(),
            SpendOutcome::Pending | SpendOutcome::Submitted | SpendOutcome::Confirmed { .. } => {
                false
            }
        }
    }
}

/// A chain reference, paired with whether this node actually OBSERVED it.
///
/// The [`confirmed`](Self::confirmed) flag is not decoration. Before confirmation the node knows the
/// coin id it INTENDS to create, and rendering that bare id beside a confirmed one presents an
/// intention as a fact. The two travel together so a client can render "expected" differently from
/// "on chain" without re-deriving the distinction — which is the derivation it would get wrong.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SpendChainReference {
    /// The coin id to look up.
    pub coin_id: String,
    /// `true` when this node observed the coin on chain; `false` when it is only the intended result.
    pub confirmed: bool,
}

/// One spend this node made WITHOUT per-transaction approval.
///
/// # Amounts are decimal STRINGS
///
/// `amount_mojos` and `fee_mojos` carry the full `u64` range, which a JSON number does not survive
/// through an f64 parser — and a silently rounded figure about somebody's money is exactly the lie
/// this record exists to prevent. Every money field in this crate is a string for that reason.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AutomatedSpend {
    /// The audit id — stable for the life of the spend, and the value
    /// [`after_id`](crate::params::SpendsListParams::after_id) resumes from.
    pub id: String,
    /// The revision of the record this row reflects. The audit trail is append-only and each entry
    /// is a snapshot; this row is the highest revision the node holds for this spend.
    pub revision: u32,
    /// What the spend was for, as the producer's stable token (`"mirror-coin"`, …).
    pub kind: String,
    /// One human sentence: why this happened without asking.
    pub purpose: String,
    /// Whose standing consent was relied on, and which grant.
    pub authority: SpendAuthority,
    /// Which asset moved.
    pub asset: SpendAsset,
    /// How much, in the asset's base units, as a decimal string.
    pub amount_mojos: String,
    /// The network fee in mojos of XCH, as a decimal string.
    pub fee_mojos: String,
    /// The store this spend serves, when it serves one.
    pub store_id: Option<String>,
    /// When the node decided to spend, unix ms. The field the ordering and the time filters use.
    pub initiated_ms: u64,
    /// When this revision was written, unix ms.
    pub updated_ms: u64,
    /// Where the spend got to.
    pub status: SpendOutcome,
    /// The coins this spend CONSUMED, once known.
    ///
    /// Never the confirmation evidence. The legacy implementation waited for a funding coin to be
    /// spent and called that confirmation, which a competing spend of the same coin satisfies
    /// identically while the intended coin never exists — so a client MUST NOT infer success from
    /// anything here. [`chain_reference`](Self::chain_reference) is the only reference that carries
    /// an observed/expected flag.
    pub funding_coin_ids: Vec<String>,
    /// The chain reference to show, or `null` when the node knows no coin id yet — which is honest:
    /// there is nothing to look up.
    ///
    /// The key MUST be present. `null` is meaningful, so an ABSENT key must not decode into it: a
    /// truncated or mis-routed payload would otherwise decode as a confident "there is nothing to
    /// look up".
    #[serde(deserialize_with = "required_option")]
    pub chain_reference: Option<SpendChainReference>,
}

/// `control.spends.list` — one page of the automated-spend audit record.
///
/// # Why this method is the only sanctioned reader
///
/// The record is a node-private file (dig-node SPEC §23). Every other view — dig-app's Activity tab
/// included — reads it THROUGH the node, and this is that route. A second process parsing the file
/// would be a second implementation of a growing append-only format, which is how two views of "what
/// did the node spend" start disagreeing, on the one subject where disagreeing is least affordable.
///
/// # A page, and it says so
///
/// [`spends`](Self::spends) is bounded by
/// [`SPENDS_LIST_MAX_LIMIT`](crate::params::SPENDS_LIST_MAX_LIMIT). Whether it is the whole matching
/// set is stated by [`complete`](Self::complete) and never left to be inferred from the page's
/// length: a node may return a short page for its own reasons, and a matching set that is an exact
/// multiple of the page size makes the last full page indistinguishable from a truncated one.
/// Without an explicit flag a caller cannot tell "there are no more spends" from "we stopped telling
/// you" — and on an audit record those read the same and mean opposite things.
///
/// # The order is part of the contract
///
/// A node MUST return rows by DESCENDING [`initiated_ms`](AutomatedSpend::initiated_ms), breaking
/// ties by ASCENDING [`id`](AutomatedSpend::id), and MUST keep that order stable across the pages of
/// one walk. [`after_id`](crate::params::SpendsListParams::after_id) means *strictly after this row
/// in that order*. The tiebreak is required rather than incidental: automated spends are issued by a
/// cycle and several can share a millisecond, so a time-only order names no position and a walk
/// would repeat some rows and skip others.
///
/// # An empty page is an ANSWER, never a fallback
///
/// `spends: []` with `complete: true` means this node has moved no money unattended that matches the
/// filters. It is NEVER what a caller gets when the record could not be read: that is
/// [`SpendAuditUnreadable`](crate::error::ControlErrorCode::SpendAuditUnreadable). "Nothing to
/// report" and "I could not look" are different answers, and the first is the one a person stops
/// investigating on.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SpendsListResult {
    /// One page of matching spends, newest-initiated first, possibly empty.
    pub spends: Vec<AutomatedSpend>,
    /// Is this page the WHOLE matching set?
    ///
    /// `true` means every matching spend the node holds is in [`spends`](Self::spends). `false`
    /// means the answer was TRUNCATED and more exist — resume from [`cursor`](Self::cursor).
    ///
    /// Required on the wire, and stated positively so the reading a caller falls into when the field
    /// is absent or defaulted is the SAFE one. A boolean spelled `truncated` would default to
    /// `false`, i.e. to "this is everything", which is the claim that ends a walk early; `complete`
    /// defaults to "there may be more", which costs at worst one redundant request.
    pub complete: bool,
    /// The id of the last row in this page — **the value to resume from** — or `null` for an empty
    /// page.
    ///
    /// It is the id the caller was HANDED, never a marker for where the record "got to". Pass it as
    /// [`after_id`](crate::params::SpendsListParams::after_id).
    ///
    /// The key MUST be present; `null` is meaningful and an absent key must not decode into it.
    #[serde(deserialize_with = "required_option")]
    pub cursor: Option<String>,
    /// How many entries in the record the node could NOT parse.
    ///
    /// Part of the answer rather than a log line, and a client MUST surface a non-zero value. An
    /// audit trail that lost entries to corruption and reads as a shorter, tidy list is
    /// indistinguishable from one where those spends never happened — which is the same lie as a
    /// missing entry, told more convincingly.
    ///
    /// It counts unreadable entries across the WHOLE record, not just this page: a corrupt entry has
    /// no parsed timestamp and no parsed id, so it cannot be attributed to a page or excluded by a
    /// filter. A caller therefore MUST NOT read it as "this many rows are missing from this page".
    pub unreadable_lines: u32,
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn status_result_round_trips_the_node_shape() {
        let v = json!({
            "running": true, "service": "dig-node", "version": "0.30.0", "commit": "abc",
            "protocol": "21", "uptime_secs": 5, "addr": "127.0.0.1:9256", "upstream": "https://rpc.dig.net",
            "cache": {"cap_bytes": 1024, "used_bytes": 10, "dir": "/c", "shared": false},
            "hosted_store_count": 2, "cached_capsule_count": 3, "pinned_store_count": 1,
            "sync": {"available": true}
        });
        let parsed: StatusResult = serde_json::from_value(v.clone()).unwrap();
        assert_eq!(serde_json::to_value(&parsed).unwrap(), v);
    }

    #[test]
    fn config_result_keeps_upstream_override_null_when_unset() {
        let parsed = ConfigResult {
            addr: "127.0.0.1:9256".into(),
            port: "9256".into(),
            upstream: "https://rpc.dig.net".into(),
            upstream_override: None,
            cache_dir: "/c".into(),
            cache_shared: false,
            config_path: "/c/config.json".into(),
            sync_available: true,
        };
        let v = serde_json::to_value(&parsed).unwrap();
        assert_eq!(v["upstream_override"], json!(null));
        assert!(v.as_object().unwrap().contains_key("upstream_override"));
    }

    #[test]
    fn pairing_poll_omits_token_until_approved() {
        let pending = PairingPollResult {
            status: "pending".into(),
            token: None,
        };
        let v = serde_json::to_value(&pending).unwrap();
        assert_eq!(v, json!({"status": "pending"}));
        let approved = PairingPollResult {
            status: "approved".into(),
            token: Some("deadbeef".into()),
        };
        assert_eq!(
            serde_json::to_value(&approved).unwrap(),
            json!({"status": "approved", "token": "deadbeef"})
        );
    }

    // ---- PeerSoftware (dig_ecosystem#2215) ----

    /// The mapping that matters most. Every peer built before #2215 advertises the LITERAL
    /// `"0.0.0"` — three of dig-gossip's four handshake send sites hardcoded it. A parser that
    /// maps only `""` to Unknown would therefore read the entire live fleet as "software version
    /// 0.0.0", which any later `>=` comparison treats as ancient. `""`, `"0.0.0"`, and anything
    /// unparseable must all be Unknown, and this test is that mapping's guard.
    #[test]
    fn unknown_covers_empty_the_legacy_sentinel_and_garbage() {
        for raw in [
            "",                       // a peer advertising nothing, or `off` coarsening
            "0.0.0",                  // the pre-#2215 legacy sentinel
            "   ",                    // whitespace only
            "dig-node",               // no version part
            "dig-node/",              // empty version part
            "dig-node/not-a-version", // unparseable version
            "/1.2.3",                 // empty product part
            "1.2.3",                  // bare version, no product
            "dig-node/0.0.0",         // the sentinel, however it is dressed up
        ] {
            assert_eq!(
                PeerSoftware::parse(raw),
                PeerSoftware::Unknown,
                "{raw:?} must map to Unknown"
            );
        }
    }

    /// A well-formed `product/semver` advertisement is reported with all three parts, and `raw`
    /// preserves exactly what the peer sent so a diagnostic reader is never shown a value the peer
    /// did not actually advertise.
    #[test]
    fn reported_carries_product_version_and_the_raw_advertisement() {
        let parsed = PeerSoftware::parse("dig-node/0.99.1");
        let PeerSoftware::Reported {
            product,
            version,
            raw,
        } = parsed
        else {
            panic!("a well-formed advertisement must be Reported");
        };
        assert_eq!(product, "dig-node");
        assert_eq!(version, semver::Version::new(0, 99, 1));
        assert_eq!(raw, "dig-node/0.99.1");
    }

    /// A product name may itself contain a `/`; only the LAST separator splits product from
    /// version. Pinning this stops a future reader from switching to a first-separator split,
    /// which would silently reclassify such a peer as Unknown.
    #[test]
    fn product_is_split_at_the_last_separator() {
        let PeerSoftware::Reported {
            product, version, ..
        } = PeerSoftware::parse("acme/dig-node/1.2.3")
        else {
            panic!("expected Reported");
        };
        assert_eq!(product, "acme/dig-node");
        assert_eq!(version, semver::Version::new(1, 2, 3));
    }

    /// Surrounding whitespace is trimmed before parsing, and `raw` records the TRIMMED
    /// advertisement. CON-008 sanitization strips Unicode Cc/Cf from the wire value but not
    /// spaces, so a padded advertisement reaches this parser intact and must not be classified as
    /// unparseable merely for having been padded.
    #[test]
    fn surrounding_whitespace_is_trimmed_before_parsing() {
        let PeerSoftware::Reported {
            product,
            version,
            raw,
        } = PeerSoftware::parse("  dig-node/1.2.3	")
        else {
            panic!("a padded advertisement must still be Reported");
        };
        assert_eq!(product, "dig-node");
        assert_eq!(version, semver::Version::new(1, 2, 3));
        assert_eq!(raw, "dig-node/1.2.3", "raw must record the trimmed value");
    }

    /// A pre-release/build-metadata semver survives intact, because that is what a nightly build
    /// advertises and dropping it would make every nightly indistinguishable from its release.
    #[test]
    fn prerelease_versions_are_preserved() {
        let PeerSoftware::Reported { version, raw, .. } =
            PeerSoftware::parse("dig-node/1.0.0-nightly.20260805")
        else {
            panic!("expected Reported");
        };
        assert_eq!(version.to_string(), "1.0.0-nightly.20260805");
        assert_eq!(raw, "dig-node/1.0.0-nightly.20260805");
    }

    /// Unknown's JSON is a tagged object — never `"0.0.0"`, never `""`, never a null sitting in a
    /// version field where a consumer might read it as a number.
    #[test]
    fn unknown_serializes_as_a_tagged_object_with_no_version_field() {
        let v = serde_json::to_value(PeerSoftware::Unknown).unwrap();
        assert_eq!(v, json!({"kind": "unknown"}));
        assert!(
            v.get("version").is_none(),
            "Unknown must not carry a version field at all"
        );
    }

    /// Both variants round-trip byte-identically, which is what lets a client re-encode a node's
    /// response unchanged.
    #[test]
    fn both_variants_round_trip_byte_identically() {
        for wire in [
            json!({"kind": "unknown"}),
            json!({
                "kind": "reported",
                "product": "dig-node",
                "version": "0.99.1",
                "raw": "dig-node/0.99.1"
            }),
        ] {
            let parsed: PeerSoftware = serde_json::from_value(wire.clone()).unwrap();
            assert_eq!(serde_json::to_value(&parsed).unwrap(), wire);
        }
    }

    /// Parsing a wire string and serializing the result produces the documented JSON, so the two
    /// halves of the contract cannot drift from each other.
    #[test]
    fn parse_then_serialize_matches_the_documented_json() {
        assert_eq!(
            serde_json::to_value(PeerSoftware::parse("dig-node/0.99.1")).unwrap(),
            json!({
                "kind": "reported",
                "product": "dig-node",
                "version": "0.99.1",
                "raw": "dig-node/0.99.1"
            })
        );
        assert_eq!(
            serde_json::to_value(PeerSoftware::parse("0.0.0")).unwrap(),
            json!({"kind": "unknown"})
        );
    }

    // ---- Trait-absence probes (dig_ecosystem#2215) ----
    //
    // `PeerSoftware` deriving `Ord` or `Default` would be a silent correctness regression rather
    // than a compile error anywhere, so it is pinned here. The probe exploits inherent-impl
    // precedence: `Probe::<T>::has_it()` resolves to the inherent impl (returning `true`) only when
    // `T` satisfies the bound, and otherwise falls back to the blanket trait impl (`false`).
    //
    // Each probe carries a CONTROL on a type that DOES implement the trait. Without the control, a
    // probe broken so that it always answers `false` would pass while proving nothing.

    struct Probe<T>(core::marker::PhantomData<T>);

    trait ProbeFallback {
        fn is_ord() -> bool {
            false
        }
    }
    impl<T> ProbeFallback for Probe<T> {}

    impl<T: Ord> Probe<T> {
        fn is_ord() -> bool {
            true
        }
    }

    struct PartialOrdProbe<T>(core::marker::PhantomData<T>);
    trait PartialOrdFallback {
        fn is_partial_ord() -> bool {
            false
        }
    }
    impl<T> PartialOrdFallback for PartialOrdProbe<T> {}
    impl<T: PartialOrd> PartialOrdProbe<T> {
        fn is_partial_ord() -> bool {
            true
        }
    }

    /// A version comparison must be unreachable without first destructuring `Reported`, so that a
    /// caller cannot order `Unknown` against a real version — which, since every pre-#2215 peer is
    /// Unknown, would quietly become a verdict about most of the live network.
    #[test]
    fn peer_software_is_not_ordered() {
        assert!(
            Probe::<u32>::is_ord(),
            "control: the probe must detect a type that IS Ord, or it proves nothing"
        );
        assert!(
            !Probe::<PeerSoftware>::is_ord(),
            "PeerSoftware must not implement Ord — comparison belongs after destructuring Reported"
        );
    }

    /// A defaulted `Unknown` appearing from nowhere is a different fact from a measured one, and
    /// `Default` would make the two indistinguishable at the point of construction.
    #[test]
    fn peer_software_has_no_default() {
        struct DefaultProbe<T>(core::marker::PhantomData<T>);
        trait DefaultFallback {
            fn is_default() -> bool {
                false
            }
        }
        impl<T> DefaultFallback for DefaultProbe<T> {}
        impl<T: Default> DefaultProbe<T> {
            fn is_default() -> bool {
                true
            }
        }

        assert!(
            DefaultProbe::<String>::is_default(),
            "control: the probe must detect a type that IS Default, or it proves nothing"
        );
        assert!(
            !DefaultProbe::<PeerSoftware>::is_default(),
            "PeerSoftware must not implement Default"
        );
    }

    // ---- SoftwareVersionDetail (dig_ecosystem#2215) ----

    /// Each mode renders a value the PARSER reads back at the intended level of detail.
    ///
    /// The fixture uses a version with a non-zero minor AND a non-zero patch, because that is the
    /// only shape where `Full` and `Minor` differ — a `1.0.0` fixture would let a renderer that
    /// ignores the mode entirely pass.
    #[test]
    fn each_detail_mode_round_trips_to_the_intended_precision() {
        let v = semver::Version::new(0, 99, 1);

        let full = SoftwareVersionDetail::Full.render("dig-node", &v);
        assert_eq!(full, "dig-node/0.99.1");
        assert_eq!(
            PeerSoftware::parse(&full),
            PeerSoftware::parse("dig-node/0.99.1")
        );

        let minor = SoftwareVersionDetail::Minor.render("dig-node", &v);
        assert_ne!(minor, full, "Minor must actually coarsen");
        let PeerSoftware::Reported { version, .. } = PeerSoftware::parse(&minor) else {
            panic!("a coarsened advertisement must still be READABLE, not Unknown");
        };
        assert_eq!(version.major, 0);
        assert_eq!(version.minor, 99);
        assert_eq!(version.patch, 0, "the patch level is what Minor hides");

        let off = SoftwareVersionDetail::Off.render("dig-node", &v);
        assert_eq!(off, "");
        assert_eq!(PeerSoftware::parse(&off), PeerSoftware::Unknown);
    }

    /// `Minor` renders `MAJOR.MINOR.0`, NOT `MAJOR.MINOR`.
    ///
    /// A bare two-part `0.99` is not valid semver, so the parser would classify a peer that
    /// coarsened its build as Unknown — turning "tell them less" into "tell them nothing", which
    /// is what `Off` is for. This test is the guard on that distinction.
    #[test]
    fn minor_mode_stays_valid_semver_rather_than_collapsing_to_unknown() {
        let rendered =
            SoftwareVersionDetail::Minor.render("dig-node", &semver::Version::new(1, 4, 7));
        assert_eq!(rendered, "dig-node/1.4.0");
        assert_ne!(
            PeerSoftware::parse(&rendered),
            PeerSoftware::Unknown,
            "a coarsened build must remain readable; `product/1.4` would not be"
        );
    }

    /// Coarsening strips pre-release and build metadata. A nightly's identifier is more precisely
    /// identifying than the patch number it accompanies, so leaving it in place would make `Minor`
    /// coarsen nothing at all for exactly the builds that most want it.
    #[test]
    fn minor_mode_strips_prerelease_and_build_metadata() {
        let v: semver::Version = "1.0.0-nightly.20260805+sha.abc123".parse().unwrap();
        let rendered = SoftwareVersionDetail::Minor.render("dig-node", &v);
        assert_eq!(rendered, "dig-node/1.0.0");
        assert!(
            !rendered.contains("nightly"),
            "the nightly identifier must not survive coarsening"
        );
        assert!(
            !rendered.contains("abc123"),
            "build metadata must not survive coarsening"
        );
    }

    /// `Off` renders the empty string for ANY version, which is what makes it indistinguishable
    /// from a peer built before the field existed.
    #[test]
    fn off_mode_reveals_nothing_for_any_version() {
        for v in ["0.0.1", "1.2.3", "99.99.99-rc.1"] {
            let rendered = SoftwareVersionDetail::Off.render("dig-node", &v.parse().unwrap());
            assert_eq!(
                rendered, "",
                "Off must reveal nothing, including the product name"
            );
        }
    }

    /// The default is the most informative setting: the diagnostic value is the reason the field
    /// exists, and an operator who disagrees opts down explicitly.
    #[test]
    fn detail_defaults_to_full() {
        assert_eq!(
            SoftwareVersionDetail::default(),
            SoftwareVersionDetail::Full
        );
    }

    /// The wire tokens are the lowercase words an operator writes in a config file, and they are a
    /// published contract once a config carries them.
    #[test]
    fn detail_uses_lowercase_wire_tokens() {
        for (mode, token) in [
            (SoftwareVersionDetail::Full, "\"full\""),
            (SoftwareVersionDetail::Minor, "\"minor\""),
            (SoftwareVersionDetail::Off, "\"off\""),
        ] {
            assert_eq!(serde_json::to_string(&mode).unwrap(), token);
            assert_eq!(
                serde_json::from_str::<SoftwareVersionDetail>(token).unwrap(),
                mode
            );
        }
    }

    // ---- Gate round 1 regressions (dig_ecosystem#2215) ----

    /// **`PartialOrd` is the hazard the `Ord` probe misses.** `Ord: PartialOrd`, so a type can
    /// derive only `PartialOrd` — satisfying an `Ord`-only probe — while `Unknown < Reported(..)`
    /// still compiles and evaluates. That one-word derive would sort `Unknown` below every real
    /// version, which is the verdict-about-the-live-network the contract forbids. SPEC §4.1 names
    /// all three traits; this pins the weakest of them, which subsumes `Ord`.
    #[test]
    fn peer_software_is_not_partially_ordered_either() {
        assert!(
            PartialOrdProbe::<f64>::is_partial_ord(),
            "control: the probe must detect a type that IS PartialOrd but NOT Ord, or it proves              nothing about the gap between the two"
        );
        assert!(
            PartialOrdProbe::<u32>::is_partial_ord(),
            "control: a fully-ordered type must also be detected"
        );
        assert!(
            !PartialOrdProbe::<PeerSoftware>::is_partial_ord(),
            "PeerSoftware must implement neither PartialOrd nor Ord"
        );
    }

    /// **The sentinel is VERSION ZERO, a class — not the three-character string `\"0.0.0\"`.**
    /// The constant's doc, `parse`'s doc, and SPEC §4.1 all state the rule over the class, so a
    /// string comparison lets `0.0.0+build`, `0.0.0-rc.1`, and `0.0.0-0` through as a *reported*
    /// version zero — the exact reading every one of those three prose statements forbids.
    #[test]
    fn version_zero_is_unknown_however_it_is_decorated() {
        for raw in [
            "dig-node/0.0.0",
            "dig-node/0.0.0+build",
            "dig-node/0.0.0-rc.1",
            "x/0.0.0-0",
            "dig-node/0.0.0-alpha+sha.abc123",
        ] {
            assert_eq!(
                PeerSoftware::parse(raw),
                PeerSoftware::Unknown,
                "{raw:?} is version zero and must be Unknown"
            );
        }
    }

    /// A version that is merely CLOSE to zero is still a real build and must be reported — without
    /// this, a parser that mapped everything below `0.1.0` to Unknown would pass the test above.
    #[test]
    fn a_nonzero_version_near_zero_is_still_reported() {
        for raw in ["dig-node/0.0.1", "dig-node/0.1.0", "dig-node/0.0.1-rc.1"] {
            assert_ne!(
                PeerSoftware::parse(raw),
                PeerSoftware::Unknown,
                "{raw:?} is a real build, not the sentinel"
            );
        }
    }

    /// **`render`'s stated invariant, tested over the class it is stated over.**
    ///
    /// The doc promises: every rendering is either the empty string or a value `parse` reads back
    /// as `Reported`. A `1.4.7` fixture cannot see the case that breaks it — a `0.0.x` build, whose
    /// `MAJOR.MINOR.0` coarsening IS version zero and therefore reads as Unknown. That is the same
    /// Minor-collapses-into-Off defect as the two-part spelling, arriving through the other door.
    #[test]
    fn every_rendering_is_empty_or_readable() {
        let versions = [
            "0.0.1",
            "0.0.7",
            "0.0.99", // the class the 1.4.7 fixture cannot see
            "0.1.0",
            "0.99.1",
            "1.0.0",
            "1.4.7",
            "10.20.30",
            "1.0.0-nightly.20260805+sha.abc123",
            "0.0.1-rc.1",
        ];
        for mode in [
            SoftwareVersionDetail::Full,
            SoftwareVersionDetail::Minor,
            SoftwareVersionDetail::Off,
        ] {
            for v in versions {
                let rendered = mode.render("dig-node", &v.parse().unwrap());
                if rendered.is_empty() {
                    continue;
                }
                assert_ne!(
                    PeerSoftware::parse(&rendered),
                    PeerSoftware::Unknown,
                    "{mode:?} rendered {rendered:?} for {v}, which reads back as Unknown — a                      non-empty rendering must always be readable"
                );
            }
        }
    }

    /// `Minor` on a `0.0.x` build advertises NOTHING, deliberately.
    ///
    /// Hiding the patch of a `0.0.x` version leaves only version zero, which the wire reserves as
    /// the "unknown" sentinel. There is no coarser representable value, so the honest rendering is
    /// the empty string rather than the sentinel dressed up as a report. This differs from the
    /// `0.99` case: there a representable coarse value existed and the wrong spelling was chosen;
    /// here none exists.
    #[test]
    fn minor_of_a_zero_zero_build_advertises_nothing_rather_than_the_sentinel() {
        let rendered = SoftwareVersionDetail::Minor.render("dig-node", &"0.0.7".parse().unwrap());
        assert_eq!(rendered, "");
        assert_ne!(
            rendered, "dig-node/0.0.0",
            "the sentinel must never be ADVERTISED; it is only ever received from a legacy peer"
        );
    }

    /// **Tripwire, not a guard.** `raw` is reconstructible from `product` + `version` for every
    /// string the current grammar accepts, because `semver::Version` re-renders losslessly. This
    /// asserts that equivalence deliberately.
    ///
    /// **When this test FAILS, `raw` has become load-bearing** — the grammar has started accepting
    /// something non-canonical (a `v` prefix, a two-part version, a vendor suffix) and `raw` is now
    /// the only record of what the peer actually sent. Do not "fix" it by deleting the field;
    /// replace this test with real assertions on the divergent inputs.
    #[test]
    fn raw_is_still_reconstructible_from_the_parsed_parts() {
        for advertised in [
            "dig-node/0.0.1",
            "dig-node/0.99.1",
            "dig-node/1.0.0-nightly.20260805",
            "dig-node/1.0.0+sha.abc123",
            "dig-node/1.0.0-rc.1+build.7",
            "acme/dig-node/1.2.3",
        ] {
            let PeerSoftware::Reported {
                product,
                version,
                raw,
            } = PeerSoftware::parse(advertised)
            else {
                panic!("{advertised:?} must be Reported");
            };
            assert_eq!(
                raw,
                format!("{product}/{version}"),
                "raw diverged from the parsed parts for {advertised:?} — `raw` is now                  load-bearing; see this test's doc comment before changing anything"
            );
        }
    }

    /// **`remove` can report that it removed NOTHING, and the two answers are distinguishable on
    /// the wire.**
    ///
    /// The fixture varies ONE thing — the outcome — and holds `ip` and `banned` fixed, so the
    /// difference it detects can only be the outcome itself. A result type carrying `removed: true`
    /// unconditionally would make these two JSON documents identical, which is exactly the state
    /// where an operator reads "un-trusted" off a call that un-trusted nothing.
    #[test]
    fn a_removal_that_matched_nothing_is_not_serialised_as_a_removal() {
        let removed = ChiaPeersRemoveResult {
            outcome: ChiaPeerRemovalOutcome::Removed,
            ip: "203.0.113.7".into(),
            banned: false,
        };
        let missed = ChiaPeersRemoveResult {
            outcome: ChiaPeerRemovalOutcome::NoSuchPeer,
            ..removed.clone()
        };

        let a = serde_json::to_value(&removed).unwrap();
        let b = serde_json::to_value(&missed).unwrap();
        assert_ne!(a, b, "the two outcomes must differ on the wire");
        assert_eq!(a["outcome"], "removed");
        assert_eq!(b["outcome"], "no_such_peer");

        // No field of the miss may be a success flag a client could render as one. Every other
        // field is identical by construction, so this asserts the outcome is the ONLY signal.
        let miss_obj = b.as_object().unwrap();
        assert!(
            !miss_obj
                .values()
                .any(|v| v == &serde_json::Value::Bool(true)),
            "a miss must carry no `true` a client can mistake for success: {b}"
        );

        // And it round-trips, so a consumer cannot lose the distinction by decoding.
        let back: ChiaPeersRemoveResult = serde_json::from_value(b).unwrap();
        assert_eq!(back.outcome, ChiaPeerRemovalOutcome::NoSuchPeer);
    }

    /// **An unpolled peer serialises as `null`, never as height zero.**
    ///
    /// `peak_height` is the one signal for judging whether a peer trusted WITHOUT corroboration is
    /// current or stuck. The fixture holds a genuinely-observed `0` beside the unobserved peer,
    /// because a `u32` field collapses those two into the same byte and the collapse is the defect.
    #[test]
    fn an_unobserved_peak_is_null_and_an_observed_zero_is_not() {
        let entry = |peak| ChiaPeerEntry {
            ip: "203.0.113.7".into(),
            port: 8444,
            peak_height: peak,
            user_managed: true,
            banned: false,
        };
        let unobserved = serde_json::to_value(entry(None)).unwrap();
        let genesis = serde_json::to_value(entry(Some(0))).unwrap();

        // Indexing a MISSING key also yields `Null`, so presence is asserted first — otherwise
        // an implementation that skipped the field entirely would pass this test while telling a
        // reader nothing at all about the peer.
        assert!(
            unobserved.get("peak_height").is_some(),
            "the key must be PRESENT and null, not omitted: {unobserved}"
        );
        assert_eq!(unobserved["peak_height"], serde_json::Value::Null);
        assert_eq!(genesis["peak_height"], 0);
        assert_ne!(
            unobserved["peak_height"], genesis["peak_height"],
            "unobservable and observed-zero must not render the same"
        );
    }

    /// **A banned peer is enumerable — `list` is the only place the blocklist is visible.**
    #[test]
    fn the_peer_list_can_carry_a_banned_entry() {
        let listed = ChiaPeersListResult {
            peers: vec![ChiaPeerEntry {
                ip: "203.0.113.9".into(),
                port: 8444,
                peak_height: None,
                user_managed: false,
                banned: true,
            }],
        };
        let json = serde_json::to_value(&listed).unwrap();
        assert_eq!(json["peers"][0]["banned"], true);
        let back: ChiaPeersListResult = serde_json::from_value(json).unwrap();
        assert!(back.peers[0].banned);
    }

    /// **The add result carries the warning TEXT, not only a flag saying a cost was paid.**
    ///
    /// The field exists so a client can quote the node's own sentence rather than restate it and
    /// drift. A boolean cannot be quoted, so the assertion is that a quotable, non-empty string
    /// naming the bypass reaches the wire under a stable key.
    #[test]
    fn the_add_result_carries_a_quotable_bypass_notice() {
        let json = serde_json::to_value(ChiaPeersAddResult {
            added: true,
            ip: "203.0.113.7".into(),
            port: 8444,
            corroboration_bypassed: true,
            notice: "believed WITHOUT corroboration".into(),
        })
        .unwrap();

        let notice = json["notice"]
            .as_str()
            .expect("notice is a string on the wire");
        assert!(
            !notice.trim().is_empty(),
            "an empty notice discloses nothing"
        );
        assert!(
            notice.to_lowercase().contains("corroboration"),
            "the notice must name the cost it exists to disclose: {notice}"
        );
    }
}

/// Why a node cannot state this epoch's collateral requirement.
///
/// Each variant names a DIFFERENT missing fact, because the remedies differ: a node that has not
/// censused the epoch needs to run the census, whereas a node inside the finality depth needs only
/// to wait for the chain to settle. Collapsing them into one "unavailable" would hand every client
/// the same unactionable sentence.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CollateralUnknownReason {
    /// This node has not censused the epoch, so it holds no record to answer from.
    NotCensused,
    /// The epoch's census inputs are not yet final — the node is inside
    /// `CENSUS_FINALITY_DEPTH_BLOCKS` of the chain tip and any figure it derived could still move.
    BehindFinalityDepth,
    /// The node holds a record for the epoch but could not read it.
    RecordUnreadable,
    /// The node cannot see the chain at all, so it cannot know whether a record should exist.
    NoChainSource,
}

impl CollateralUnknownReason {
    /// Every reason, for exhaustive rendering and for the wire-token uniqueness KAT.
    pub const ALL: &'static [CollateralUnknownReason] = &[
        CollateralUnknownReason::NotCensused,
        CollateralUnknownReason::BehindFinalityDepth,
        CollateralUnknownReason::RecordUnreadable,
        CollateralUnknownReason::NoChainSource,
    ];

    /// The stable snake_case wire token, matching the `reason` field.
    pub const fn as_wire(self) -> &'static str {
        match self {
            CollateralUnknownReason::NotCensused => "not_censused",
            CollateralUnknownReason::BehindFinalityDepth => "behind_finality_depth",
            CollateralUnknownReason::RecordUnreadable => "record_unreadable",
            CollateralUnknownReason::NoChainSource => "no_chain_source",
        }
    }
}

/// `control.collateral.requirement` — this epoch's per-store collateral requirement, or a named
/// reason the node cannot state it.
///
/// **UNKNOWN is a first-class answer, not an error.** A node that has not censused the epoch, or
/// that is inside the census finality depth, is not broken; it simply does not know yet. Making
/// that a tagged variant rather than an optional number means there is no representable state in
/// which a client holds a figure it has not been given — which is what dig-app `SPEC.md` §3.7b
/// requires when it forbids any path that renders an absent requirement as a zero cost.
///
/// **The census inputs travel with the figure on purpose.** A client that can show only the number
/// can say the price moved; a client holding `stores`, `owners`, `multiplier_micros` and
/// `handicap_dig_base_units` can say WHY it moved. The per-epoch record already holds all four, so
/// carrying them costs the node nothing and is the difference between a figure an operator can
/// weigh and one they can only accept.
///
/// **The margin is deliberately absent here.** The requirement is a consensus-derived value every
/// node derives identically; the margin is a local operator preference that MUST NOT be a consensus
/// input. Returning them from one method would invite exactly the conflation dig-app `SPEC.md`
/// §3.7b forbids — read the margin from
/// [`CollateralMarginResult`](crate::results::CollateralMarginResult) instead.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum CollateralRequirementResult {
    /// The node holds a final record for the epoch and states its requirement.
    Known {
        /// The epoch this requirement governs, one-based.
        epoch: u64,
        /// The collateral protocol version that COMPUTED this epoch.
        ///
        /// Travels with the figure because the model is versioned and upgradable: a client that
        /// knows only the number cannot tell a disagreement from a rule change.
        protocol_version: u16,
        /// The per-store requirement, in DIG base units, BEFORE any local safety margin.
        required_per_store_dig_base_units: u64,
        /// Qualifying `(owner, store, root)` advertisements counted in the census.
        ///
        /// An advertisement count, never a node count: one owner publishing two roots for one store
        /// id contributes two.
        stores: u64,
        /// Distinct owner puzzle hashes across those advertisements.
        ///
        /// Not a node count and not an operator count. A surface displaying it MUST say
        /// "collateralised owners".
        owners: u64,
        /// The controller multiplier for the epoch, in millionths (`MULT_SCALE` = 1_000_000).
        multiplier_micros: u64,
        /// The small-network handicap applied for the epoch, in DIG base units.
        handicap_dig_base_units: u64,
    },
    /// The node cannot state the requirement, and names which fact is missing.
    Unknown {
        /// Which fact the node is missing.
        reason: CollateralUnknownReason,
    },
}

/// `control.collateral.margin.get` / `.set` — the node's LOCAL safety margin.
///
/// `.set` returns the margin now in force, so a caller never has to re-read to learn what was
/// applied.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct CollateralMarginResult {
    /// The margin in BASIS POINTS over the requirement (`100` is +1%).
    ///
    /// The unit is basis points and is never converted, because it is the unit
    /// `dig_mirror_collateral::apply_safety_margin` takes and the one dig-app `SPEC.md` §3.7b
    /// normatively fixes. A conversion performed independently by two surfaces is a money-path
    /// drift bug.
    pub margin_bp: u64,
}
