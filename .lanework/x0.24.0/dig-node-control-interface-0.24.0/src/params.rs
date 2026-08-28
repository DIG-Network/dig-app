//! Typed request params for the control methods, each bound to its method + result via
//! [`crate::traits::ControlCall`].
//!
//! One params type per method (even where two methods share the same field shape, e.g. the four
//! `{ store }` methods) so the compile-time method↔params↔result binding is exact: a caller passes
//! `PinParams { store }` and the type system yields a [`PinResult`](crate::results::PinResult).
//! Field names are the exact wire names dig-node reads.

use serde::{Deserialize, Serialize};

use crate::error::{ControlError, ControlErrorCode};
use crate::method::ControlMethod;
use crate::results;
use crate::traits::ControlCall;

/// Bind a params type to its wire method + typed result.
macro_rules! control_call {
    ($ty:ty => $method:expr, $out:ty) => {
        impl ControlCall for $ty {
            const METHOD: ControlMethod = $method;
            type Output = $out;
        }
    };
}

/// Define a no-param call: an empty params struct (serializes to `{}`) bound to its method + result.
macro_rules! no_params {
    ($(#[$doc:meta])* $name:ident => $method:expr, $out:ty) => {
        $(#[$doc])*
        #[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
        pub struct $name {}
        control_call!($name => $method, $out);
    };
}

no_params!(
    /// `control.status` params (none).
    StatusParams => ControlMethod::Status, results::StatusResult
);
no_params!(
    /// `control.config.get` params (none).
    ConfigGetParams => ControlMethod::ConfigGet, results::ConfigResult
);
no_params!(
    /// `control.cache.get` params (none).
    CacheGetParams => ControlMethod::CacheGet, results::CacheView
);
no_params!(
    /// `control.cache.clear` params (none).
    CacheClearParams => ControlMethod::CacheClear, results::CacheClearResult
);
no_params!(
    /// `control.hostedStores.list` params (none).
    HostedStoresListParams => ControlMethod::HostedStoresList, results::HostedStoresListResult
);
no_params!(
    /// `control.sync.status` params (none).
    SyncStatusParams => ControlMethod::SyncStatus, results::SyncStatusResult
);
no_params!(
    /// `control.updater.status` params (none). Result is the proxied beacon status.
    UpdaterStatusParams => ControlMethod::UpdaterStatus, serde_json::Value
);
no_params!(
    /// `control.updater.resume` params (none).
    UpdaterResumeParams => ControlMethod::UpdaterResume, serde_json::Value
);
no_params!(
    /// `control.updater.checkNow` params (none).
    UpdaterCheckNowParams => ControlMethod::UpdaterCheckNow, serde_json::Value
);
no_params!(
    /// `control.pairing.list` params (none). Result is the pending + issued-token list.
    PairingListParams => ControlMethod::PairingList, serde_json::Value
);
no_params!(
    /// `control.peerStatus` params (none). Result is the peer-pool snapshot.
    PeerStatusParams => ControlMethod::PeerStatus, serde_json::Value
);
no_params!(
    /// `control.listSubscriptions` params (none).
    ListSubscriptionsParams => ControlMethod::ListSubscriptions, results::ListSubscriptionsResult
);

/// `control.config.setUpstream` params.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SetUpstreamParams {
    /// The upstream DIG RPC URL to persist (blank clears the override).
    pub upstream: String,
}
control_call!(SetUpstreamParams => ControlMethod::ConfigSetUpstream, results::SetUpstreamResult);

/// `control.log.setLevel` params.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SetLevelParams {
    /// An `EnvFilter` directive, e.g. `"debug"` or `"info,dig_node_core=debug"`.
    pub filter: String,
}
control_call!(SetLevelParams => ControlMethod::LogSetLevel, results::SetLevelResult);

/// `control.cache.setCap` params.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SetCapParams {
    /// The cache size cap in bytes (floored at 64 MiB by the node).
    pub cap_bytes: u64,
}
control_call!(SetCapParams => ControlMethod::CacheSetCap, results::SetCapResult);

/// `control.hostedStores.pin` params.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PinParams {
    /// A store reference: `storeId` or `storeId:rootHash`.
    pub store: String,
}
control_call!(PinParams => ControlMethod::HostedStoresPin, results::PinResult);

/// `control.hostedStores.unpin` params.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UnpinParams {
    /// A store reference: `storeId` or `storeId:rootHash`.
    pub store: String,
}
control_call!(UnpinParams => ControlMethod::HostedStoresUnpin, results::UnpinResult);

/// `control.hostedStores.status` params.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HostedStoreStatusParams {
    /// A store reference: `storeId` or `storeId:rootHash`.
    pub store: String,
}
control_call!(HostedStoreStatusParams => ControlMethod::HostedStoresStatus, results::HostedStoreStatusResult);

/// `control.capsule.fetch` params: WHICH capsule to pull, named by store id + root — the same
/// two-field shape as [`ProfileGetBodyParams`], not the colon-joined `store` string
/// [`PinParams`]/[`SyncTriggerParams`] use, because the caller always knows both parts already
/// (there is no store-level-only fetch).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CapsuleFetchParams {
    /// The store id to fetch a capsule of.
    pub store: String,
    /// The capsule root to fetch.
    pub root: String,
}
control_call!(CapsuleFetchParams => ControlMethod::CapsuleFetch, results::CapsuleFetchResult);

/// `control.sync.trigger` params.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SyncTriggerParams {
    /// A capsule reference: `storeId:rootHash` (a concrete root is required).
    pub store: String,
}
control_call!(SyncTriggerParams => ControlMethod::SyncTrigger, results::SyncTriggerResult);

/// `control.updater.setChannel` params.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SetChannelParams {
    /// The update channel (`"nightly"` | `"stable"`; the beacon CLI is the sole validator).
    pub channel: String,
}
control_call!(SetChannelParams => ControlMethod::UpdaterSetChannel, serde_json::Value);

/// `control.updater.pause` params.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct PauseParams {
    /// The unix-seconds time to pause until; omit to pause indefinitely.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub until: Option<u64>,
}
control_call!(PauseParams => ControlMethod::UpdaterPause, serde_json::Value);

/// `control.pairing.approve` params.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApproveParams {
    /// The pending pairing's id (from `pairing.request`).
    pub pairing_id: String,
}
control_call!(ApproveParams => ControlMethod::PairingApprove, results::PairingApproveResult);

/// `control.pairing.revoke` params.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RevokeParams {
    /// The short id of the paired token to revoke.
    pub token_id: String,
}
control_call!(RevokeParams => ControlMethod::PairingRevoke, results::PairingRevokeResult);

/// `control.peers.connect` params.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PeersConnectParams {
    /// A peer address to dial, or an already-connected peer_id to resolve.
    pub peer: String,
}
control_call!(PeersConnectParams => ControlMethod::PeersConnect, results::PeersConnectResult);

/// `control.peers.disconnect` params.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PeersDisconnectParams {
    /// The peer_id to drop.
    pub peer: String,
}
control_call!(PeersDisconnectParams => ControlMethod::PeersDisconnect, results::PeersDisconnectResult);

/// The CANONICAL textual form of a Chia peer address, or an `INVALID_PARAMS` error.
///
/// Every `ip` this crate declares — in `control.chiaPeers.add` / `.remove` params and in every
/// result that echoes one — is a bare IP literal in this form. A conforming node MUST canonicalise
/// through this function on the way IN and store the result, so `add`, `remove` and `list` all
/// spell the same peer the same way.
///
/// **Why the contract owns this rather than each implementation.** `remove` is the only way to
/// un-trust a peer that is believed WITHOUT corroboration, and it matches by address. If the form
/// is left to the implementation, an operator who adds `2001:db8::1` and removes `2001:DB8:0:0::1`
/// has named the same peer twice and un-trusted nothing — an un-trust that silently does not
/// happen. Canonicalising is what makes the two spellings one key.
///
/// The rules, normatively:
///
/// - the value MUST parse as an IPv4 or IPv6 literal ([`std::net::IpAddr`]). A hostname, an empty
///   string, an `ip:port`, a CIDR block or a bracketed `[..]` form is REJECTED. Rejecting
///   non-literals is also what bounds the ban list: `remove {ban: true}` persists a row keyed by
///   this string, so an unvalidated key is unbounded at-rest growth driven by one small call;
/// - surrounding whitespace is trimmed before parsing, and nothing else is;
/// - the canonical rendering is [`std::net::IpAddr`]'s own `Display` — dotted-quad for v4, and for
///   v6 the RFC 5952 lowercase, maximally-compressed form, WITHOUT brackets and WITHOUT a zone id.
///
/// Bracketing belongs to the socket-address form, never to this field: see
/// [`chia_peer_endpoint`], which is the ONLY sanctioned way to join an `ip` to a port.
///
/// ```
/// use dig_node_control_interface::params::canonical_peer_ip;
/// assert_eq!(canonical_peer_ip(" 2001:0DB8:0000::1 ").unwrap(), "2001:db8::1");
/// assert!(canonical_peer_ip("[::1]").is_err());
/// assert!(canonical_peer_ip("node.example.com").is_err());
/// ```
pub fn canonical_peer_ip(raw: &str) -> Result<String, ControlError> {
    raw.trim()
        .parse::<std::net::IpAddr>()
        .map(|ip| ip.to_string())
        .map_err(|_| {
            ControlError::of(
                ControlErrorCode::InvalidParams,
                format!(
                    "ip must be a bare IPv4 or IPv6 literal (no brackets, no port, no hostname), got: {raw:?}"
                ),
            )
        })
}

/// Join a canonical peer `ip` to a port, bracketing IPv6 as RFC 3986 requires.
///
/// The one place a peer address and a port are ever concatenated. Formatting `"{ip}:{port}"` by
/// hand is the bug this exists to prevent: `::1` and `8444` render as `::1:8444`, which is not a
/// malformed string a parser rejects — it is a DIFFERENT valid IPv6 address, so the mistake
/// survives validation and silently retargets the peer.
///
/// ```
/// use dig_node_control_interface::params::chia_peer_endpoint;
/// assert_eq!(chia_peer_endpoint("::1", 8444), "[::1]:8444");
/// assert_eq!(chia_peer_endpoint("203.0.113.7", 8444), "203.0.113.7:8444");
/// ```
pub fn chia_peer_endpoint(ip: &str, port: u16) -> String {
    match ip.trim().parse::<std::net::IpAddr>() {
        Ok(std::net::IpAddr::V6(v6)) => format!("[{v6}]:{port}"),
        Ok(std::net::IpAddr::V4(v4)) => format!("{v4}:{port}"),
        Err(_) => format!("{ip}:{port}"),
    }
}

/// The maximum number of BANNED Chia peers a conforming node persists.
///
/// A ban is a row written at the request of one small control call and kept across restarts, so
/// without a ceiling the blocklist is unbounded at-rest state a caller can grow for free. On
/// overflow a node MUST evict its OLDEST ban rather than refuse the newest — a bounded list that
/// forgets is recoverable, and a full one that refuses turns the ceiling into a denial of the ban
/// facility itself.
///
/// The value is deliberately generous against the honest use (a handful of misbehaving peers) and
/// small against the abusive one. Banned entries are enumerable through `control.chiaPeers.list`
/// and clearable through `control.chiaPeers.remove` with `ban: false`.
pub const MAX_BANNED_CHIA_PEERS: usize = 256;

/// `control.chiaPeers.add` params — the Chia full node to start TRUSTING.
///
/// Trust is the whole point of this call and it is not free: a trusted peer is exempted from the
/// corroboration this node otherwise requires (NC-12 — dialled peers are untrusted, and agreement
/// across several concurrently-queried peers is what makes a chain read safe). An implementation
/// MUST tell the person that before it writes the entry.
///
/// The trust NC-12 authorises is the operator declaring a node THEIR OWN. That is what justifies
/// the unbounded authority the entry carries, and it does not extend to a node somebody else runs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChiaPeersAddParams {
    /// The peer's IP address, canonical per [`canonical_peer_ip`] — a bare literal, no brackets,
    /// no port. The standard full-node port is assumed (the Sage `add_peer` request shape carries
    /// no port either).
    pub ip: String,
}
control_call!(ChiaPeersAddParams => ControlMethod::ChiaPeersAdd, results::ChiaPeersAddResult);

/// `control.chiaPeers.remove` params — the Chia full node to stop trusting.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChiaPeersRemoveParams {
    /// The peer's IP address, canonical per [`canonical_peer_ip`]. Matching is by that canonical
    /// form, so an address spelled differently from the stored entry still names the same peer.
    pub ip: String,
    /// Ban rather than forget: the peer is kept but excluded, so discovery cannot re-add it.
    /// Absent means `false`, which merely forgets the entry.
    ///
    /// A ban is EXACT-match on this one address — never a subnet — and it is local to this node,
    /// with no effect on any other node's peer set. It persists until removed, bounded by
    /// [`MAX_BANNED_CHIA_PEERS`], is enumerated by `control.chiaPeers.list` (`banned: true`), and
    /// is cleared by calling `remove` again with `ban: false`. **Clearing a ban that way grants no
    /// trust**: `add` also un-bans, but `add` confers the corroboration bypass, so it must not be
    /// the only route back — an over-broad ban is not a reason to trust the peer it hit.
    ///
    /// Every banned peer is one fewer source of agreement. NC-12 rests on several independently
    /// chosen peers agreeing, so a caller that bans steadily shrinks the honest pool toward the
    /// peers it chose; that is why banning is on the master-token tier
    /// ([`ControlMethod::requires_master_token`]) and why the set is bounded and visible.
    #[serde(default)]
    pub ban: bool,
}
control_call!(ChiaPeersRemoveParams => ControlMethod::ChiaPeersRemove, results::ChiaPeersRemoveResult);

/// WHAT a subscription follows: ordinary content, or a dig-profile.
///
/// Serializes to a lowercase, language-neutral wire token (`"capsule"` / `"profile"`).
///
/// # Absent means [`Capsule`](SubscriptionKind::Capsule), and that is a contract, not a convenience
///
/// Every subscription written before this field existed is untagged, and a node's
/// `subscriptions.json` on a real machine is FULL of them. A required `kind` would make those rows
/// fail to deserialize, and a node that cannot read its own subscription file starts with an empty
/// one — an upgrade that silently unsubscribes a user from everything they had. So the field is
/// `#[serde(default)]` everywhere it appears, and the default is the meaning those untagged rows
/// already had: a capsule.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SubscriptionKind {
    /// Ordinary store content — the meaning every untagged subscription already carries.
    #[default]
    Capsule,
    /// A dig-profile: the node additionally follows the profile ROOT and syncs its body from peers.
    Profile,
}

/// `control.subscribe` params.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SubscribeParams {
    /// The store id to subscribe to.
    pub store_id: String,
    /// What the subscription follows. OMITTED means [`SubscriptionKind::Capsule`], so an older
    /// client's request and an untagged on-disk row both keep their existing meaning.
    #[serde(default)]
    pub kind: SubscriptionKind,
}
control_call!(SubscribeParams => ControlMethod::Subscribe, results::SubscribeResult);

/// `control.unsubscribe` params.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UnsubscribeParams {
    /// The store id to stop watching.
    pub store_id: String,
}
control_call!(UnsubscribeParams => ControlMethod::Unsubscribe, results::UnsubscribeResult);

/// The length of a CAT asset id (TAIL hash) in hex characters: a 32-byte hash.
pub const ASSET_ID_HEX_LEN: usize = 64;

/// A CAT asset id — the TAIL hash that names one token on the Chia chain.
///
/// Stored as the 32 raw bytes rather than a `String` so two spellings of the same id (uppercase,
/// `0x`-prefixed) cannot compare unequal. Parsing normalizes; emission is always lowercase and
/// unprefixed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct AssetId([u8; 32]);

/// Why an asset id could not be parsed. Deliberately small — an id is either 32 bytes of hex or it
/// is not an id, and guessing at a near-miss is how a wallet ends up reading the wrong token.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AssetIdParseError {
    /// Not exactly [`ASSET_ID_HEX_LEN`] hex characters (after an optional `0x` is stripped).
    WrongLength {
        /// The length actually supplied.
        got: usize,
    },
    /// A character outside `[0-9a-fA-F]`.
    NotHex,
}

impl core::fmt::Display for AssetIdParseError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::WrongLength { got } => write!(
                f,
                "asset id must be {ASSET_ID_HEX_LEN} hex characters, got {got}"
            ),
            Self::NotHex => f.write_str("asset id contains a non-hexadecimal character"),
        }
    }
}

impl std::error::Error for AssetIdParseError {}

impl AssetId {
    /// Wrap 32 already-decoded bytes. `const` so canonical ids can be declared as constants.
    pub const fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// The raw 32 bytes.
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Parse a hex asset id. A `0x` prefix and uppercase digits are TOLERATED on input — both are
    /// what a block explorer prints — and normalized away; neither is ever emitted.
    pub fn from_hex(hex: &str) -> Result<Self, AssetIdParseError> {
        let body = hex.strip_prefix("0x").unwrap_or(hex);
        if body.len() != ASSET_ID_HEX_LEN {
            return Err(AssetIdParseError::WrongLength { got: body.len() });
        }
        let mut bytes = [0u8; 32];
        for (byte, pair) in bytes.iter_mut().zip(body.as_bytes().chunks_exact(2)) {
            let hi = decode_hex_digit(pair[0])?;
            let lo = decode_hex_digit(pair[1])?;
            *byte = (hi << 4) | lo;
        }
        Ok(Self(bytes))
    }

    /// The canonical wire spelling: lowercase, unprefixed, [`ASSET_ID_HEX_LEN`] characters.
    pub fn to_hex(&self) -> String {
        use core::fmt::Write as _;
        self.0
            .iter()
            .fold(String::with_capacity(ASSET_ID_HEX_LEN), |mut acc, byte| {
                let _ = write!(acc, "{byte:02x}");
                acc
            })
    }
}

/// Decode one ASCII hex digit into its nibble value.
fn decode_hex_digit(c: u8) -> Result<u8, AssetIdParseError> {
    match c {
        b'0'..=b'9' => Ok(c - b'0'),
        b'a'..=b'f' => Ok(c - b'a' + 10),
        b'A'..=b'F' => Ok(c - b'A' + 10),
        _ => Err(AssetIdParseError::NotHex),
    }
}

impl core::fmt::Display for AssetId {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(&self.to_hex())
    }
}

/// The asset a wallet balance/coin read is denominated in: native XCH, or any CAT by asset id.
///
/// # Why there is no separate `Dig` variant
///
/// $DIG is a CAT, so it is [`Asset::DIG`] — an associated constant, not a variant. A three-variant
/// `{Xch, Dig, Cat(id)}` would give $DIG two INEQUAL spellings, and a balance or coin list filtered
/// by one of them would silently omit everything carrying the other: a wallet reporting half a
/// balance as though it were the whole. One token, one value.
///
/// # Wire form (additive — CLAUDE.md §5.1)
///
/// | Value | JSON |
/// |---|---|
/// | [`Asset::Xch`] | `"xch"` |
/// | [`Asset::DIG`] | `"dig"` |
/// | any other CAT | `{"cat":"<64-hex>"}` |
///
/// Both legacy tokens are still ACCEPTED and `"dig"` is still EMITTED, so a node or client built
/// before this release keeps understanding, and being understood by, one built after it.
/// `{"cat":"<the $DIG asset id>"}` is also accepted and normalizes to [`Asset::DIG`].
///
/// Byte-identical to dig-app's consumer type (`dig-app-core::wallet::state::Asset`), recorded in the
/// `canonical` skill so the two implementations cannot drift.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Asset {
    /// Native Chia (XCH), denominated in mojos.
    Xch,
    /// A CAT, named by its asset id and denominated in its own base units.
    Cat(AssetId),
}

/// The legacy wire token for native Chia.
const XCH_TOKEN: &str = "xch";
/// The legacy wire token for $DIG, still emitted so older peers keep understanding this crate.
const DIG_TOKEN: &str = "dig";

impl Asset {
    /// Canonical $DIG CAT asset id (TAIL hash) on Chia mainnet, as lowercase hex.
    ///
    /// CONTRACT: byte-identical to `dig_constants::DIG_ASSET_ID`, `chip35_dl_coin::DIG_ASSET_ID`,
    /// and digstore-chain's. It is duplicated here rather than imported because this crate is a
    /// level-00 foundation crate and may not depend sideways on `dig-constants` (CLAUDE.md
    /// Appendix B). `dig_asset_id_hex_and_bytes_are_the_same_id` pins THIS crate's two spellings
    /// of it together; agreement with the ecosystem constant is a source-of-truth obligation on
    /// whoever changes it, recorded in the `canonical` skill.
    pub const DIG_ASSET_ID_HEX: &'static str =
        "a406d3a9de984d03c9591c10d917593b434d5263cabe2b42f6b367df16832f81";

    /// $DIG, the CAT every capsule payment is denominated in.
    pub const DIG: Asset = Asset::Cat(AssetId::new([
        0xa4, 0x06, 0xd3, 0xa9, 0xde, 0x98, 0x4d, 0x03, 0xc9, 0x59, 0x1c, 0x10, 0xd9, 0x17, 0x59,
        0x3b, 0x43, 0x4d, 0x52, 0x63, 0xca, 0xbe, 0x2b, 0x42, 0xf6, 0xb3, 0x67, 0xdf, 0x16, 0x83,
        0x2f, 0x81,
    ]));

    /// Whether this asset is $DIG, however it was spelled on the wire.
    pub fn is_dig(&self) -> bool {
        *self == Self::DIG
    }

    /// The CAT asset id, or `None` for native XCH.
    pub fn asset_id(&self) -> Option<&AssetId> {
        match self {
            Self::Xch => None,
            Self::Cat(id) => Some(id),
        }
    }
}

impl Serialize for Asset {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match self {
            Self::Xch => serializer.serialize_str(XCH_TOKEN),
            // $DIG keeps its legacy token: a node built before the widening understands only the
            // two bare strings, and emitting the tagged form for it would break that direction.
            other if other.is_dig() => serializer.serialize_str(DIG_TOKEN),
            Self::Cat(id) => {
                use serde::ser::SerializeMap as _;
                let mut map = serializer.serialize_map(Some(1))?;
                map.serialize_entry("cat", &id.to_hex())?;
                map.end()
            }
        }
    }
}

impl<'de> Deserialize<'de> for Asset {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        /// The two accepted wire shapes, kept private so the tagged form is the ONLY map that
        /// parses — an unknown key must be an error, never a silently ignored asset name.
        #[derive(Deserialize)]
        #[serde(untagged, deny_unknown_fields)]
        enum Wire {
            Token(String),
            Tagged { cat: String },
        }

        match Wire::deserialize(deserializer).map_err(|_| {
            serde::de::Error::custom(
                "expected \"xch\", \"dig\", or {\"cat\":\"<64-hex asset id>\"}",
            )
        })? {
            Wire::Token(token) if token == XCH_TOKEN => Ok(Self::Xch),
            Wire::Token(token) if token == DIG_TOKEN => Ok(Self::DIG),
            Wire::Token(token) => Err(serde::de::Error::custom(format!(
                "unknown asset {token:?}: expected \"xch\", \"dig\", or {{\"cat\":\"<64-hex asset id>\"}}"
            ))),
            Wire::Tagged { cat } => AssetId::from_hex(&cat)
                .map(Self::Cat)
                .map_err(serde::de::Error::custom),
        }
    }
}

/// `control.wallet.balance` params: which address + asset to read the balance of.
///
/// A READ over the loopback control plane — never a spend. Field names + the [`Asset`] wire form are
/// byte-identical to dig-app's frozen `BalanceRequest`, so the node reads exactly what dig-app emits.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WalletBalanceParams {
    /// The `xch1…` address to read the balance of.
    pub address: String,
    /// The asset to read the balance for.
    pub asset: Asset,
}
control_call!(WalletBalanceParams => ControlMethod::WalletBalance, results::WalletBalanceResult);

/// `control.wallet.coins` params: which address + asset to read spendable coins for.
///
/// Field-for-field identical to [`WalletBalanceParams`] — a balance is this read reduced to a sum —
/// and byte-identical to dig-app's frozen `CoinsRequest`, so adopting the method is a body swap
/// rather than a re-shape.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WalletCoinsParams {
    /// The `xch1…` address to read coins for.
    pub address: String,
    /// The asset to read coins for.
    pub asset: Asset,
}
control_call!(WalletCoinsParams => ControlMethod::WalletCoins, results::WalletCoinsResult);

/// The length of a coin id in lowercase hex characters: a 32-byte hash.
const COIN_ID_HEX_LEN: usize = 64;

/// `control.wallet.coinById` params: WHICH coin, named by its own id.
///
/// # Why there is no `asset` here
///
/// A coin id names one coin on one chain. It is not scoped to an address and not scoped to an
/// asset, and a node reading a coin record learns neither — so an asset parameter here could only
/// be a claim the read never checks. The answer's
/// [`asset`](crate::results::WalletCoinRecord::asset) is `null` for the same reason.
///
/// # Why the method exists at all
///
/// [`WalletCoinsParams`] answers by ADDRESS and lists UNSPENT coins only. A mint's evidence is the
/// opposite shape: the created DID coin (which sits at nobody's wallet address) and the funding
/// coin the mint SPENT (which is, by then, gone from every unspent list). Without a by-id read a
/// pushed mint can never be observed — a permanent "pending" with the money already spent.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct WalletCoinByIdParams {
    /// The coin id: lowercase 64-hex, unprefixed. A `0x` prefix is TOLERATED on input (block
    /// explorers print one) and normalized away by [`Self::validated`]; it is never emitted.
    pub coin_id: String,
}
control_call!(WalletCoinByIdParams => ControlMethod::WalletCoinById, results::WalletCoinByIdResult);

/// `control.wallet.coinSpend` params: WHICH coin's spend to read, named by that coin's own id.
///
/// # Why the spend and the coin record are separate methods
///
/// [`WalletCoinByIdParams`] answers *what is this coin, and was it spent?* — an id, an amount, a
/// puzzle HASH and two heights. None of that reveals what the spend DID. Reconstructing a lineage
/// (which is how a dig-profile's DID singleton is followed forward) needs the puzzle REVEAL and the
/// solution, and those exist only in the spend. A caller holding a coin record alone can see that a
/// coin is gone and cannot see what it became.
///
/// # The id names the SPENT coin, not the spend
///
/// A spend has no id of its own on chain; it is identified by the coin it consumed. So the parameter
/// is the same 64-hex coin id [`WalletCoinByIdParams`] takes, validated by the same rule, and the
/// two methods are asked with the identical value.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct WalletCoinSpendParams {
    /// The SPENT coin's id: lowercase 64-hex, unprefixed. A `0x` prefix is TOLERATED on input and
    /// normalized away by [`Self::validated`]; it is never emitted.
    pub coin_id: String,
}
control_call!(WalletCoinSpendParams => ControlMethod::WalletCoinSpend, results::WalletCoinSpendResult);

/// `control.wallet.coinsByParent` params: WHICH coin's direct children to read.
///
/// # One hop, and the field name says so
///
/// The field is `parent_coin_id` rather than `coin_id` because the coin named here is the one being
/// asked ABOUT as a parent — it is never the coin the caller wants back. A walk up or down a lineage
/// is the CALLER's composition of repeated single hops; the node performs exactly one. Naming it
/// `coin_id` would make a recursive reading of the method plausible from the request alone, and a
/// caller expecting a whole lineage from one call would read a one-hop answer as a truncated chain.
///
/// # Bounded, because a parent's child count is not
///
/// This is the only OPEN wallet read whose answer has unbounded cardinality — every other one
/// returns a single record (`coinById`, `peak`, `syncStatus`) or is already paged (`arrivals`). So
/// the read is PAGED, and the page is bounded by [`COINS_BY_PARENT_MAX_LIMIT`].
///
/// **The bound is the ONLY thing bounding this call — there is no rate limiter anywhere behind it.**
/// dig-node's control plane has no request rate limiting of any kind (dig_ecosystem#2577); the
/// bandwidth limiter it does have governs content serving and is not on this path. A future reader
/// weighing whether to relax this cap should assume no limiter exists, because none does.
///
/// That matters more than a local resource bound would, because the node does not necessarily answer
/// from its own replica: on the fallback tier it forwards a caller-supplied identifier to a
/// THIRD-PARTY coinset HTTPS oracle. An unbounded page is therefore unbounded work against somebody
/// else's service, requested by a token-less caller on a loopback endpoint.
///
/// Paging rather than a bare cap, because a bare cap is a dead end: a parent with more children than
/// the cap could never be fully enumerated, and this method exists to WALK a lineage. A walk that
/// cannot see past the cap is a walk that silently stops.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct WalletCoinsByParentParams {
    /// The PARENT coin's id: lowercase 64-hex, unprefixed. A `0x` prefix is TOLERATED on input and
    /// normalized away by [`Self::validated`]; it is never emitted.
    pub parent_coin_id: String,
    /// Resume STRICTLY AFTER this child, in the read's
    /// [documented order](results::WalletCoinsByParentResult). `None` starts at the first child.
    ///
    /// This is the value the previous page handed back as
    /// [`cursor`](results::WalletCoinsByParentResult::cursor) — never a value the caller invented,
    /// and never a marker for where the chain "got to". `control.wallet.arrivals` records why that
    /// distinction loses rows; this read avoids the trap by having no such marker to reach for.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub after_coin_id: Option<String>,
    /// The page size. `None` asks for [`COINS_BY_PARENT_DEFAULT_LIMIT`].
    ///
    /// A value above [`COINS_BY_PARENT_MAX_LIMIT`], or a zero, is REFUSED as `INVALID_PARAMS` rather
    /// than clamped — see [`Self::validated`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub limit: Option<u32>,
}
control_call!(WalletCoinsByParentParams => ControlMethod::WalletCoinsByParent, results::WalletCoinsByParentResult);

/// `control.wallet.arrivals` — confirmed INCOMING funds recorded since a cursor position.
///
/// The answer to "was I just paid?", which neither a balance nor a coin list can give: a balance
/// moves for the user's OWN change too, and an unspent-coin list cannot say which of its coins are
/// new. Each row the node returns is a coin it determined ARRIVED — confirmed on chain, above the
/// wallet's arrival baseline, not previously reported, and not created by spending one of the
/// wallet's own coins. The determination is the NODE's; a client MUST NOT re-derive it, because the
/// signals it takes (spent parents, the catch-up baseline) live only in the node's replica.
///
/// # A cursor, not a stream
///
/// The control envelope is strictly request→response, so this is polled. A client resumes from
/// [`WalletArrivalsResult::cursor`](results::WalletArrivalsResult::cursor) — the last position it
/// was actually handed — and NEVER from `latest`; see that field for why the distinction loses a
/// notification when it is collapsed.
///
/// # `after_seq` is unsigned so a rewind is unexpressible
///
/// Positions are monotonic and start at 1, so there is no meaning for a negative one. `0` is the
/// beginning of the ledger and is what a client sends when it deliberately wants everything.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct WalletArrivalsParams {
    /// Return arrivals STRICTLY after this position. `0` starts at the beginning of the ledger,
    /// and is also what an omitted field means — the same default the node applies.
    #[serde(default)]
    pub after_seq: u64,
    /// The page size. `None` asks for the node's default rather than a number this client invented;
    /// a node clamps whatever it is given to its own maximum.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub limit: Option<u32>,
}
control_call!(WalletArrivalsParams => ControlMethod::WalletArrivals, results::WalletArrivalsResult);

fn normalize_coin_id(coin_id: &str) -> Option<&str> {
    let normalized = coin_id.strip_prefix("0x").unwrap_or(coin_id);
    let well_formed = normalized.len() == COIN_ID_HEX_LEN
        && normalized
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b));
    well_formed.then_some(normalized)
}

/// Give a single-coin-id params type its validating `Deserialize` and its `validated` constructor.
///
/// The three by-coin reads (`coinById`, `coinSpend`, `coinsByParent`) enforce the IDENTICAL id rule
/// under three different field names, and the rule is normative rather than incidental — see
/// [`WalletCoinByIdParams::validated`] for why a malformed id must be refused BEFORE a chain is
/// consulted. Written once here so a fourth by-coin read cannot arrive with a subtly looser copy of
/// it, and so a change to the rule cannot land on two of three types.
macro_rules! coin_id_params {
    ($ty:ident, $field:ident, $raw:ident, $error:expr) => {
        impl<'de> Deserialize<'de> for $ty {
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
            where
                D: serde::Deserializer<'de>,
            {
                #[derive(Deserialize)]
                struct $raw {
                    $field: String,
                }

                let raw = $raw::deserialize(deserializer)?;
                let $field = normalize_coin_id(&raw.$field)
                    .ok_or_else(|| serde::de::Error::custom($error))?
                    .to_owned();
                Ok(Self { $field })
            }
        }

        impl $ty {
            /// Normalize and check the coin id, or reject the request as `-32602 INVALID_PARAMS`.
            ///
            /// A malformed id is a malformed REQUEST, and the node refuses it here — before
            /// consulting any chain. That ordering is normative rather than an optimisation: were a
            /// bad id allowed through, the read would come back empty, and the caller would be told
            /// the honest-looking answer *the chain holds nothing* about a coin it never actually
            /// asked after. An unanswerable question and a chain that answered "no" must never wear
            /// the same shape.
            ///
            /// Accepts exactly two spellings — 64 lowercase hex characters, or the same 64 preceded
            /// by `0x`. Uppercase, whitespace and every other length are refused, because the
            /// contract's hex wire form is lowercase and unprefixed everywhere else in this crate.
            pub fn validated(self) -> Result<Self, crate::error::ControlError> {
                let normalized = normalize_coin_id(&self.$field).ok_or_else(|| {
                    crate::error::ControlError::of(
                        crate::error::ControlErrorCode::InvalidParams,
                        $error,
                    )
                })?;
                Ok($ty {
                    $field: normalized.to_owned(),
                })
            }
        }
    };
}

const COIN_ID_ERROR: &str = "coin_id must be lowercase 64-hex, optionally 0x-prefixed";
const PARENT_COIN_ID_ERROR: &str =
    "parent_coin_id must be lowercase 64-hex, optionally 0x-prefixed";
const AFTER_COIN_ID_ERROR: &str = "after_coin_id must be lowercase 64-hex, optionally 0x-prefixed";

coin_id_params!(
    WalletCoinByIdParams,
    coin_id,
    RawWalletCoinByIdParams,
    COIN_ID_ERROR
);
coin_id_params!(
    WalletCoinSpendParams,
    coin_id,
    RawWalletCoinSpendParams,
    COIN_ID_ERROR
);
/// The page size `control.wallet.coinsByParent` uses when the caller names none.
///
/// A spend in the lineages this read exists to follow — a singleton, a DID, an ordinary transfer —
/// creates a small handful of children, so one default page covers a realistic hop in a single round
/// trip and a caller never pages at all.
pub const COINS_BY_PARENT_DEFAULT_LIMIT: u32 = 100;

/// The largest page `control.wallet.coinsByParent` will accept, derived from the transport's own
/// frame limit rather than chosen for feel.
///
/// dig-ipc-protocol caps a control frame at `MAX_FRAME_BYTES` = 1 MiB (its `SPEC.md` §
/// bounds), and that is the hard ceiling every answer on this plane has to fit inside. A
/// [`WalletCoinRecord`](results::WalletCoinRecord) is at most ~350 bytes of JSON — three 64-hex
/// hashes at 66 bytes quoted, a 20-digit `u64`, two 10-digit heights, and their keys — so the
/// arithmetic that fixes this number is:
///
/// ```text
/// 1 MiB / 350 B  ~=  2,996 records is where a page STOPS FITTING
/// 1,000 records  ~=  350 KB, roughly a third of the frame
/// ```
///
/// The cap is set at a third of what fits, not at what fits, so the envelope, the freshness fields
/// and any future additive member cannot push a legal page over the transport's limit. A larger
/// value would put the contract's own maximum inside the region where a conforming node's honest
/// answer is undeliverable — the failure would surface as a truncated frame, not as a refusal.
pub const COINS_BY_PARENT_MAX_LIMIT: u32 = 1_000;

const COINS_BY_PARENT_LIMIT_ERROR: &str = "limit must be between 1 and 1000";

impl<'de> Deserialize<'de> for WalletCoinsByParentParams {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct RawWalletCoinsByParentParams {
            parent_coin_id: String,
            #[serde(default)]
            after_coin_id: Option<String>,
            #[serde(default)]
            limit: Option<u32>,
        }

        let raw = RawWalletCoinsByParentParams::deserialize(deserializer)?;
        let parent_coin_id = normalize_coin_id(&raw.parent_coin_id)
            .ok_or_else(|| serde::de::Error::custom(PARENT_COIN_ID_ERROR))?
            .to_owned();
        let after_coin_id = raw
            .after_coin_id
            .map(|id| {
                normalize_coin_id(&id)
                    .map(str::to_owned)
                    .ok_or_else(|| serde::de::Error::custom(AFTER_COIN_ID_ERROR))
            })
            .transpose()?;
        if !raw.limit.map_or(true, is_legal_page) {
            return Err(serde::de::Error::custom(COINS_BY_PARENT_LIMIT_ERROR));
        }
        Ok(Self {
            parent_coin_id,
            after_coin_id,
            limit: raw.limit,
        })
    }
}

/// Is this a page size the contract accepts — at least one row, at most the frame-derived maximum?
fn is_legal_page(limit: u32) -> bool {
    (1..=COINS_BY_PARENT_MAX_LIMIT).contains(&limit)
}

impl WalletCoinsByParentParams {
    /// A first page of children for one parent: the node's default size, starting at the beginning.
    ///
    /// The common case, and the one a caller should not have to spell out — naming a page size means
    /// asserting a number this caller invented over the one the contract chose.
    pub fn first_page(parent_coin_id: impl Into<String>) -> Self {
        Self {
            parent_coin_id: parent_coin_id.into(),
            after_coin_id: None,
            limit: None,
        }
    }

    /// The page size this request asks for, resolving `None` to [`COINS_BY_PARENT_DEFAULT_LIMIT`].
    ///
    /// Stated once here so a node and a client cannot resolve the same omitted field to two
    /// different numbers — a disagreement that would show up as a page boundary in the wrong place,
    /// which is exactly where a paged walk loses rows.
    pub fn effective_limit(&self) -> u32 {
        self.limit.unwrap_or(COINS_BY_PARENT_DEFAULT_LIMIT)
    }

    /// Normalize and check both ids and the page bound, or reject as `-32602 INVALID_PARAMS`.
    ///
    /// The ids follow the rule every by-coin read in this crate follows (lowercase 64-hex, `0x`
    /// tolerated on input and never emitted).
    ///
    /// An out-of-range `limit` is REFUSED, never clamped. That is a deliberate departure from
    /// `control.wallet.arrivals`, which lets a node clamp: this read's page boundary is what a
    /// caller RESUMES from, so a silently shrunk page hands back a cursor for a position the caller
    /// did not ask about, and a caller that believed its own number would mis-size every subsequent
    /// request. Refusing keeps the caller's model of the page and the node's identical, which is the
    /// same reason a 65-hex coin id is refused rather than truncated.
    ///
    /// `limit: 0` is refused for a separate reason: a page that can hold nothing makes no progress,
    /// so a caller looping until a page comes back short would loop forever.
    pub fn validated(self) -> Result<Self, crate::error::ControlError> {
        fn invalid(message: &'static str) -> crate::error::ControlError {
            crate::error::ControlError::of(crate::error::ControlErrorCode::InvalidParams, message)
        }

        let parent_coin_id = normalize_coin_id(&self.parent_coin_id)
            .ok_or_else(|| invalid(PARENT_COIN_ID_ERROR))?
            .to_owned();
        let after_coin_id = self
            .after_coin_id
            .as_deref()
            .map(|id| {
                normalize_coin_id(id)
                    .map(str::to_owned)
                    .ok_or_else(|| invalid(AFTER_COIN_ID_ERROR))
            })
            .transpose()?;
        if !self.limit.map_or(true, is_legal_page) {
            return Err(invalid(COINS_BY_PARENT_LIMIT_ERROR));
        }
        Ok(WalletCoinsByParentParams {
            parent_coin_id,
            after_coin_id,
            limit: self.limit,
        })
    }
}

/// `control.wallet.peak` params — none.
///
/// The peak is a property of the node's chain view, not of any address, which is exactly why it is
/// its own method: [`results::WalletBalanceResult::peak_height`] is `null` on every fallback-tier
/// answer, so a caller bounding a claimed confirmation cannot rely on getting one from a balance.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct WalletPeakParams {}
control_call!(WalletPeakParams => ControlMethod::WalletPeak, results::WalletPeakResult);

/// `control.peerCounts` params — none.
///
/// The counts describe this node's own connectivity on each network, so there is nothing to scope
/// the question by. One call answers for BOTH networks deliberately: a consumer that had to collect
/// the DIG count from a peer method and the Chia count from a wallet method is a consumer that can
/// reach for the wrong one.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct PeerCountsParams {}
control_call!(PeerCountsParams => ControlMethod::PeerCounts, results::PeerCountsResult);

/// `control.wallet.syncStatus` params — none.
///
/// The wallet's sync progress is a property of the node's own chain replica, not of any address, so
/// there is nothing to scope the question by. Deliberately NOT confused with `control.sync.status`,
/// which reports §21 DIG STORE sync and has nothing to do with the chain.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct WalletSyncStatusParams {}
control_call!(WalletSyncStatusParams => ControlMethod::WalletSyncStatus, results::WalletSyncStatusResult);

/// `control.wallet.broadcast` params: an ALREADY-SIGNED spend bundle to push.
///
/// # The custody boundary (§908)
///
/// This carries signed bytes and nothing else. There is deliberately no key, no seed, no phrase and
/// no unsigned-spend-plus-key field here, and there never may be: the node's role on the money path
/// is to read chain state and to push what somebody else signed. A parameter that let the node
/// produce a signature would move custody into an identity-agnostic daemon, which is the one thing
/// the boundary exists to prevent.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WalletBroadcastParams {
    /// The signed spend bundle: lowercase hex of its chia `Streamable` serialization.
    pub signed_bundle_hex: String,
}
control_call!(WalletBroadcastParams => ControlMethod::WalletBroadcast, results::WalletBroadcastResult);

/// The length of a BLS G1 public key in lowercase hex characters: 48 bytes.
const PUBLIC_KEY_HEX_LEN: usize = 96;

/// `control.wallet.watch` params: which PUBLIC keys the node should follow.
///
/// # Keys, never puzzle hashes
///
/// The node already derives addresses from the public keys it holds in its own custody, through one
/// standard derivation. Enrolling KEYS reuses that exact derivation for a client's keys too, so the
/// ecosystem has ONE mapping from key to address and a client and a node can never disagree about
/// which addresses a key covers. Enrolling puzzle hashes instead would make every client re-derive
/// independently, and a client whose derivation window is narrower than the node's would silently
/// under-report the money it owns.
///
/// # No key material crosses (§908)
///
/// A G1 public key is public. There is deliberately no seed, phrase, private key or signature field
/// here, and there never may be: enrolment tells the node what to WATCH, and watching needs nothing
/// a signature could be produced from.
///
/// # Idempotent, so a client can reconcile without asking first
///
/// Submitting keys the node already follows is a SUCCESS that changes nothing — see
/// [`WalletWatchResult`](results::WalletWatchResult). Duplicates WITHIN one request count once. An
/// empty list is accepted and does nothing, because "enrol everything in this (currently empty) set"
/// is a reconciliation a client legitimately performs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct WalletWatchParams {
    /// The public keys to enrol: lowercase 96-hex, unprefixed. A `0x` prefix is TOLERATED on input
    /// and normalized away by [`Self::validated`]; it is never emitted.
    pub public_keys: Vec<String>,
}
control_call!(WalletWatchParams => ControlMethod::WalletWatch, results::WalletWatchResult);

/// `control.wallet.unwatch` params: which PUBLIC keys the node should stop following.
///
/// Takes the same wire form as [`WalletWatchParams`] under the same field name, so a client
/// reverses an enrolment by re-sending exactly what it sent. Deregistering a key that was never
/// enrolled is a success, not an error — the mirror of enrolment's idempotence, and what lets a
/// client assert an end state rather than compute a diff.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct WalletUnwatchParams {
    /// The public keys to deregister: lowercase 96-hex, unprefixed. A `0x` prefix is TOLERATED on
    /// input and normalized away by [`Self::validated`]; it is never emitted.
    pub public_keys: Vec<String>,
}
control_call!(WalletUnwatchParams => ControlMethod::WalletUnwatch, results::WalletUnwatchResult);

/// `control.wallet.watched` params — none.
///
/// The enrolled set is a property of the node, so there is nothing to scope the question by. This
/// is why the method is TOKEN-GATED although it only reads: the caller supplies nothing, so the
/// answer is the node's OWN key set — see [`ControlMethod::is_open_read`].
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct WalletWatchedParams {}
control_call!(WalletWatchedParams => ControlMethod::WalletWatched, results::WalletWatchedResult);

fn normalize_public_key(public_key: &str) -> Option<&str> {
    let normalized = public_key.strip_prefix("0x").unwrap_or(public_key);
    let well_formed = normalized.len() == PUBLIC_KEY_HEX_LEN
        && normalized
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b));
    well_formed.then_some(normalized)
}

/// Give an enrolment params type its validating `Deserialize` and its `validated` constructor.
///
/// `watch` and `unwatch` carry the IDENTICAL key list under the identical field name, and must
/// enforce the identical rule: a client reverses an enrolment by re-sending what it sent, so a
/// spelling one method accepts and the other refuses would leave a key enrolled forever. Written
/// once so the two cannot drift apart.
macro_rules! public_keys_params {
    ($ty:ident, $raw:ident, $error:expr) => {
        impl<'de> Deserialize<'de> for $ty {
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
            where
                D: serde::Deserializer<'de>,
            {
                #[derive(Deserialize)]
                struct $raw {
                    public_keys: Vec<String>,
                }

                let raw = $raw::deserialize(deserializer)?;
                let public_keys = raw
                    .public_keys
                    .iter()
                    .map(|key| {
                        normalize_public_key(key)
                            .map(str::to_owned)
                            .ok_or_else(|| serde::de::Error::custom($error))
                    })
                    .collect::<Result<Vec<_>, _>>()?;
                Ok(Self { public_keys })
            }
        }

        impl $ty {
            /// Normalize and check every key, or reject the request as `-32602 INVALID_PARAMS`.
            ///
            /// The whole request is refused when ANY key is malformed — never the well-formed
            /// subset. A partial enrolment would leave the node following fewer addresses than the
            /// client believes it asked for, and the client's next balance read would report a
            /// shortfall as though the money were not there. One bad key is a malformed REQUEST.
            ///
            /// Accepts exactly two spellings per key — 96 lowercase hex characters, or the same 96
            /// preceded by `0x`. Uppercase, whitespace and every other length are refused, because
            /// the contract's hex wire form is lowercase and unprefixed everywhere else.
            pub fn validated(self) -> Result<Self, crate::error::ControlError> {
                let public_keys = self
                    .public_keys
                    .iter()
                    .map(|key| {
                        normalize_public_key(key).map(str::to_owned).ok_or_else(|| {
                            crate::error::ControlError::of(
                                crate::error::ControlErrorCode::InvalidParams,
                                $error,
                            )
                        })
                    })
                    .collect::<Result<Vec<_>, _>>()?;
                Ok(Self { public_keys })
            }
        }
    };
}

const PUBLIC_KEYS_ERROR: &str =
    "public_keys must each be lowercase 96-hex (a 48-byte G1 key), optionally 0x-prefixed";

public_keys_params!(WalletWatchParams, RawWalletWatch, PUBLIC_KEYS_ERROR);
public_keys_params!(WalletUnwatchParams, RawWalletUnwatch, PUBLIC_KEYS_ERROR);

/// Every id in a reservation's `coin_ids` takes the same wire form the single-coin reads accept,
/// so a client can feed a coin straight from `control.wallet.coins` into a reservation.
const COIN_IDS_ERROR: &str =
    "coin_ids must each be lowercase 64-hex (a 32-byte coin id), optionally 0x-prefixed";

/// `control.wallet.reservations.held` params — none.
///
/// # Why the caller does not supply the time
///
/// dig-account's `CoinReservationStore::held(now_unix)` takes the current time from its caller,
/// because in-process both sides share one clock and one trust domain. Across the control boundary
/// they share neither, and a caller-supplied `now` would be a lapse oracle: a far-future value makes
/// every live reservation read as expired, and the caller then selects coins another process is
/// about to spend. The node reads its OWN clock and reports it back as
/// [`as_of_unix`](results::WalletReservationsHeldResult::as_of_unix), so a client can SEE skew
/// rather than impose it.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct WalletReservationsHeldParams {}
control_call!(WalletReservationsHeldParams => ControlMethod::WalletReservationsHeld, results::WalletReservationsHeldResult);

/// `control.wallet.reservations.reserve` params: take EVERY named coin, or take none.
///
/// The wire form of `dig_account::wallet::reservation::CoinReservationStore::reserve_all`, so a
/// client backing that seam with the node forwards its arguments rather than translating them.
///
/// # All-or-none is the whole contract
///
/// Reading the held set, selecting, then reserving is check-then-act: two processes both read an
/// empty set and both take the same coin. Atomic acquisition is what closes that window, so a
/// conflict on ANY coin refuses the WHOLE call and reserves nothing — see
/// [`ControlErrorCode::WalletCoinsReserved`]. A caller that loses re-reads
/// [`WalletReservationsHeldParams`] and re-selects from what remains.
///
/// # An empty list is a success, not an error
///
/// It yields a handle that releases nothing, which is what the caller asked for. This matches
/// dig-account exactly: an empty reservation can never conflict, so refusing it would make a
/// legitimate no-op selection look like a malformed request.
///
/// # No key material (§908)
///
/// A coin id is a public chain fact. There is no seed, key, signature or bundle field here and
/// there never may be: a reservation is BOOKKEEPING — it narrows what a selector will choose and
/// authorizes nothing.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct WalletReservationsReserveParams {
    /// The coin ids to hold: lowercase 64-hex, unprefixed. A `0x` prefix is TOLERATED on input and
    /// normalized away by [`Self::validated`]; it is never emitted.
    pub coin_ids: Vec<String>,
    /// How long the hold should live, in seconds; `None` asks for the node's default.
    ///
    /// A REQUEST, never a command. The node clamps this to its own maximum and returns the value it
    /// actually applied as
    /// [`ttl_secs`](results::WalletReservationsReserveResult::ttl_secs) — an unclamped caller-chosen
    /// lifetime is a lockout weapon, since one call could hold a wallet's coins away from its owner
    /// for as long as it liked.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ttl_secs: Option<u64>,
}
control_call!(WalletReservationsReserveParams => ControlMethod::WalletReservationsReserve, results::WalletReservationsReserveResult);

/// `control.wallet.reservations.release` params: free one reservation now, ahead of its TTL.
///
/// # The release path is why a reservation is safe at all
///
/// A hold with no way out is a wallet that locks itself out of its own funds, which is worse than
/// the double-select it prevents. Two mechanisms keep that impossible and BOTH are required: the
/// TTL bounds every hold whether or not anyone releases it, and this method lets a caller that
/// KNOWS the answer — the spend settled, or was definitively rejected — stop holding the user's
/// coins over a question the chain has already resolved.
///
/// # Releasing an unknown or lapsed id is a SUCCESS
///
/// A caller releasing on confirmation cannot know whether the TTL got there first, and making that
/// race an error would teach callers to ignore the result — which is how a release stops being
/// called at all. See [`WalletReservationsReleaseResult`](results::WalletReservationsReleaseResult).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WalletReservationsReleaseParams {
    /// The handle returned by
    /// [`reserve`](results::WalletReservationsReserveResult::reservation_id).
    ///
    /// OPAQUE: a client stores it and sends it back, and MUST NOT parse, derive or construct one.
    /// The node mints it, and how it is spelled is free to differ between a hold taken before a
    /// broadcast and one recorded for a bundle already in flight.
    pub reservation_id: String,
}
control_call!(WalletReservationsReleaseParams => ControlMethod::WalletReservationsRelease, results::WalletReservationsReleaseResult);

impl<'de> Deserialize<'de> for WalletReservationsReserveParams {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct RawReserve {
            coin_ids: Vec<String>,
            #[serde(default)]
            ttl_secs: Option<u64>,
        }

        let raw = RawReserve::deserialize(deserializer)?;
        let coin_ids = raw
            .coin_ids
            .iter()
            .map(|id| {
                normalize_coin_id(id)
                    .map(str::to_owned)
                    .ok_or_else(|| serde::de::Error::custom(COIN_IDS_ERROR))
            })
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Self {
            coin_ids,
            ttl_secs: raw.ttl_secs,
        })
    }
}

impl WalletReservationsReserveParams {
    /// Normalize and check every coin id, or reject the request as `-32602 INVALID_PARAMS`.
    ///
    /// The WHOLE request is refused when any id is malformed, never the well-formed subset. A
    /// partial reservation would leave the caller believing it holds inputs it does not — the exact
    /// state all-or-none acquisition exists to make unreachable.
    pub fn validated(self) -> Result<Self, ControlError> {
        let coin_ids = self
            .coin_ids
            .iter()
            .map(|id| {
                normalize_coin_id(id).map(str::to_owned).ok_or_else(|| {
                    ControlError::of(ControlErrorCode::InvalidParams, COIN_IDS_ERROR)
                })
            })
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Self {
            coin_ids,
            ttl_secs: self.ttl_secs,
        })
    }
}

/// `pairing.request` params (OPEN — no token).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RequestParams {
    /// A human-readable name for the requesting client (shown to the operator).
    pub client_name: String,
}
control_call!(RequestParams => ControlMethod::PairingRequest, results::PairingRequestResult);

/// `pairing.poll` params (OPEN — no token).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PollParams {
    /// The pairing id to poll.
    pub pairing_id: String,
}
control_call!(PollParams => ControlMethod::PairingPoll, results::PairingPollResult);

/// The largest dig-profile body the control plane accepts or returns, in bytes: **4 MiB**.
///
/// # Why the contract carries the cap instead of the implementation
///
/// A client that learns the bound by exceeding it learns it as a failed round trip, after paying to
/// serialize and send megabytes. Stated here, an app checks before it sends and can tell a person
/// *this profile is too large* rather than *something went wrong*.
///
/// # Why this number
///
/// It is HALF of dig-gossip's `WS_MAX_MESSAGE_BYTES` (8 MiB), the frame ceiling a body must fit
/// inside when a node serves it to a peer over `PROFILE_BODY` (opcode 225). A body accepted here
/// but unservable there would be stored and then permanently unsyncable — accepted by the node the
/// app talks to and invisible to every other node. The halving leaves room for the framing,
/// envelope and base64 expansion that sit around the bytes on that hop.
///
/// The cap is on the DECODED body, not on the base64 text that carries it.
pub const MAX_BODY_BYTES: usize = 4 * 1024 * 1024;

/// `control.profile.putBody` params: the profile body a confirmed chain root commits to.
///
/// # The node CHECKS the root; it does not take the caller's word for it
///
/// `root` is a CLAIM, and the node's obligation is to refuse it when it is false. An implementation
/// MUST independently resolve the profile's root on chain, recompute the root of the supplied body,
/// and reject the call unless the two agree and that root is CONFIRMED. dig-app is a caller like
/// any other here: it holds the key and signs the root (§908), but the bytes it then hands over
/// arrive at the node exactly as a peer's bytes do, and the standing rule for this epic is that a
/// body is checked against the on-chain root and anything that does not match is rejected.
///
/// A method documented as *the caller supplies a matching root* invites an implementation that
/// stores what it is given. That implementation turns the control plane into a way to make a node
/// serve arbitrary bytes to the network under someone else's profile id.
///
/// # No key material crosses (§908)
///
/// There is deliberately no seed, private key, signature or unsigned spend field here, and there
/// never may be. The node persists, serves and fetches bodies; it never signs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProfilePutBodyParams {
    /// The profile's store id: lowercase 64-hex, unprefixed.
    pub store_id: String,
    /// The root the body is claimed to hash to: lowercase 64-hex, unprefixed. Checked against the
    /// chain, never trusted.
    pub root: String,
    /// The body itself, standard base64 (padded) of its `DPB` serialization. The DECODED length
    /// MUST NOT exceed [`MAX_BODY_BYTES`]; a larger body is refused as `INVALID_PARAMS`.
    pub body_b64: String,
}
control_call!(ProfilePutBodyParams => ControlMethod::ProfilePutBody, results::ProfilePutBodyResult);

/// `control.profile.getBody` params: WHICH profile body to read, named by store id + root.
///
/// The root is part of the question rather than part of the answer: a caller asks for the body at a
/// root it already knows, so it can never be handed a body for a DIFFERENT root and mistake it for
/// the one it asked about. A node holding no body at that root answers `body_b64: null`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProfileGetBodyParams {
    /// The profile's store id: lowercase 64-hex, unprefixed.
    pub store_id: String,
    /// The root to read the body at: lowercase 64-hex, unprefixed.
    pub root: String,
}
control_call!(ProfileGetBodyParams => ControlMethod::ProfileGetBody, results::ProfileGetBodyResult);

/// The page size `control.spends.list` uses when the caller names none.
///
/// Stated on the contract rather than chosen by each side, so a node and a client cannot resolve the
/// same omitted field to two different numbers — a disagreement that shows up as a page boundary in
/// the wrong place, which is where a paged walk loses rows.
pub const SPENDS_LIST_DEFAULT_LIMIT: u32 = 50;

/// The largest page `control.spends.list` will serve.
///
/// The audit record grows without limit — it is append-only and every automated cycle adds to it —
/// so an unbounded read is unbounded work and an unbounded response. The bound is declared here from
/// the start rather than added later, because a method that ships unbounded teaches every client to
/// expect the whole record in one call, and bounding it afterwards is then a breaking change.
///
/// **This bound is the only thing bounding the call.** dig-node's control plane has no request rate
/// limiting of any kind (dig_ecosystem#2577), so a future reader weighing a larger cap should assume
/// no limiter exists behind it, because none does.
pub const SPENDS_LIST_MAX_LIMIT: u32 = 500;

/// The one refusal message for an out-of-range `control.spends.list` page size.
const SPENDS_LIST_LIMIT_ERROR: &str = "limit must be between 1 and 500 spends per page";

/// `control.spends.list` params: WHICH automated spends to read, and how much of the record at once.
///
/// # A read, and only a read
///
/// Nothing here initiates, signs, cancels or amends a spend, and the catalog offers no method that
/// does. The record exists to make automatic signing accountable, and a surface able to edit it
/// would be a surface able to edit the evidence.
///
/// # Every filter is an AND; an unset filter constrains nothing
///
/// Omitting a field means "do not narrow on this", never "match nothing". A client that sends no
/// field at all asks for the newest page of the whole record.
///
/// # Paged, and the page boundary is the caller's
///
/// Rows come newest-initiated first (the full ordering rule is on
/// [`SpendsListResult`](results::SpendsListResult)) and a caller resumes from
/// [`after_id`](Self::after_id) — the id of the last row it was actually HANDED. An out-of-range
/// [`limit`](Self::limit) is REFUSED rather than clamped, matching
/// [`WalletCoinsByParentParams`] and for the same reason: a silently shrunk page hands back a cursor
/// for a position the caller did not ask about.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct SpendsListParams {
    /// Only spends INITIATED at or after this unix-ms instant. Inclusive.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub since_ms: Option<u64>,
    /// Only spends INITIATED strictly before this unix-ms instant. Exclusive.
    ///
    /// Half-open with [`since_ms`](Self::since_ms) so consecutive windows tile the record exactly:
    /// one window's `until_ms` is the next window's `since_ms`, and no spend is counted twice or
    /// dropped between them.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub until_ms: Option<u64>,
    /// Only spends serving this store id.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub store_id: Option<String>,
    /// Only this kind of spend — the stable token the producer stamped (`"mirror-coin"`, …).
    ///
    /// An open string rather than an enum, because a new producer must be able to appear in the
    /// record without a release of this crate. An unrecognised kind matches nothing rather than
    /// erroring, which is the same answer a caller gets for a real kind that has no rows yet.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    /// Only this outcome, by its [`SpendOutcome::token`](results::SpendOutcome::token) —
    /// `pending` / `submitted` / `confirmed` / `failed` / `unresolved`.
    ///
    /// **`failed` does NOT mean "the money stayed put"**, so a client filtering on it must still
    /// read each row's stage — see [`SpendOutcome::Failed`](results::SpendOutcome::Failed). A UI
    /// that offers a "failed" filter and renders its rows as untouched money asserts something the
    /// node does not know.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status: Option<String>,
    /// Resume STRICTLY AFTER this audit id, in the read's documented order. `None` starts at the
    /// newest matching row.
    ///
    /// This is the value the previous page handed back as
    /// [`cursor`](results::SpendsListResult::cursor) — never an id the caller kept for another
    /// reason, and never a timestamp. Resuming by time would drop every spend sharing the boundary
    /// millisecond.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub after_id: Option<String>,
    /// The page size. `None` asks for [`SPENDS_LIST_DEFAULT_LIMIT`].
    ///
    /// A zero, or a value above [`SPENDS_LIST_MAX_LIMIT`], is REFUSED as `INVALID_PARAMS` rather
    /// than clamped — see [`Self::validated`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub limit: Option<u32>,
}

impl SpendsListParams {
    /// The page size this request asks for, resolving `None` to [`SPENDS_LIST_DEFAULT_LIMIT`].
    ///
    /// Stated once here so the node and the client cannot resolve the same omitted field to two
    /// different numbers.
    pub fn effective_limit(&self) -> u32 {
        self.limit.unwrap_or(SPENDS_LIST_DEFAULT_LIMIT)
    }

    /// Check the page bound, or reject as `-32602 INVALID_PARAMS`.
    ///
    /// `limit: 0` is refused because a page that can hold nothing makes no progress: a caller
    /// looping until [`complete`](results::SpendsListResult::complete) would loop forever. A limit
    /// above the cap is refused rather than clamped so the caller's model of the page and the node's
    /// stay identical.
    ///
    /// The time window is deliberately NOT validated. `since_ms > until_ms` is a well-formed request
    /// for an empty window, and an empty window has an honest answer — no rows — which is a
    /// different thing from a malformed request.
    pub fn validated(self) -> Result<Self, ControlError> {
        if let Some(limit) = self.limit {
            if limit == 0 || limit > SPENDS_LIST_MAX_LIMIT {
                return Err(ControlError::of(
                    ControlErrorCode::InvalidParams,
                    SPENDS_LIST_LIMIT_ERROR,
                ));
            }
        }
        Ok(self)
    }
}

impl<'de> Deserialize<'de> for SpendsListParams {
    /// Validates on the way in, so a node cannot forget to call [`Self::validated`].
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct Raw {
            #[serde(default)]
            since_ms: Option<u64>,
            #[serde(default)]
            until_ms: Option<u64>,
            #[serde(default)]
            store_id: Option<String>,
            #[serde(default)]
            kind: Option<String>,
            #[serde(default)]
            status: Option<String>,
            #[serde(default)]
            after_id: Option<String>,
            #[serde(default)]
            limit: Option<u32>,
        }
        let raw = Raw::deserialize(deserializer)?;
        SpendsListParams {
            since_ms: raw.since_ms,
            until_ms: raw.until_ms,
            store_id: raw.store_id,
            kind: raw.kind,
            status: raw.status,
            after_id: raw.after_id,
            limit: raw.limit,
        }
        .validated()
        .map_err(serde::de::Error::custom)
    }
}
control_call!(SpendsListParams => ControlMethod::SpendsList, results::SpendsListResult);

#[cfg(test)]
mod tests {
    use super::*;
    use crate::traits::build_request;
    use serde_json::json;

    /// An asset id that is emphatically NOT $DIG, so a round-trip through it cannot be satisfied
    /// by an implementation that only ever answers about $DIG.
    const OTHER_CAT_HEX: &str = "1c2b3a4d5e6f708192a3b4c5d6e7f8091a2b3c4d5e6f708192a3b4c5d6e7f809";

    /// The legacy spellings are what an ALREADY-DEPLOYED dig-node and dig-app emit today. This is
    /// the load-bearing additive-discipline test (§5.1): if widening the enum ever stops accepting
    /// them, every peer built before this release becomes unreadable.
    #[test]
    fn legacy_xch_and_dig_spellings_still_deserialize() {
        assert_eq!(
            serde_json::from_value::<Asset>(json!("xch")).unwrap(),
            Asset::Xch
        );
        assert_eq!(
            serde_json::from_value::<Asset>(json!("dig")).unwrap(),
            Asset::DIG
        );
    }

    /// $DIG keeps EMITTING its legacy token. A newer client talking to an OLDER node must still be
    /// understood, and an older node knows only `"xch"`/`"dig"` — so emitting `{"cat":…}` for $DIG
    /// would break the compatibility direction the legacy test above cannot see.
    #[test]
    fn dig_still_serializes_to_its_legacy_token() {
        assert_eq!(serde_json::to_value(Asset::DIG).unwrap(), json!("dig"));
        assert_eq!(serde_json::to_value(Asset::Xch).unwrap(), json!("xch"));
    }

    /// The new capability: an arbitrary CAT, named by asset id, survives a full round-trip.
    #[test]
    fn an_arbitrary_cat_round_trips_by_asset_id() {
        let asset = Asset::Cat(AssetId::from_hex(OTHER_CAT_HEX).unwrap());
        let wire = serde_json::to_value(asset).unwrap();
        assert_eq!(wire, json!({ "cat": OTHER_CAT_HEX }));
        assert_eq!(serde_json::from_value::<Asset>(wire).unwrap(), asset);
    }

    /// $DIG has exactly ONE value, however it was spelled on the wire.
    ///
    /// This is the test that rules out a three-variant `{Xch, Dig, Cat(id)}`, where
    /// `Dig != Cat(DIG_ASSET_ID)` and a balance filtered by one spelling silently omits the coins
    /// carrying the other — a wallet reporting half a balance as if it were the whole.
    #[test]
    fn dig_spelled_either_way_is_one_and_the_same_value() {
        let via_token: Asset = serde_json::from_value(json!("dig")).unwrap();
        let via_asset_id: Asset =
            serde_json::from_value(json!({ "cat": Asset::DIG_ASSET_ID_HEX })).unwrap();
        assert_eq!(via_token, via_asset_id);
        assert_eq!(via_token, Asset::DIG);
        assert!(via_asset_id.is_dig());
    }

    /// The 64-hex length is a published bound, so it is pinned from BOTH sides: one nibble short
    /// and one nibble long must both fail, and exactly 64 must pass.
    #[test]
    fn asset_id_hex_length_is_bounded_on_both_sides() {
        assert!(AssetId::from_hex(&"a".repeat(63)).is_err());
        assert!(AssetId::from_hex(&"a".repeat(64)).is_ok());
        assert!(AssetId::from_hex(&"a".repeat(65)).is_err());
    }

    /// Input is tolerant of the two forms a human copies out of a block explorer; output is not.
    #[test]
    fn asset_id_normalizes_prefix_and_case_but_emits_lowercase_unprefixed() {
        let upper = OTHER_CAT_HEX.to_uppercase();
        let canonical = AssetId::from_hex(OTHER_CAT_HEX).unwrap();
        assert_eq!(AssetId::from_hex(&upper).unwrap(), canonical);
        assert_eq!(AssetId::from_hex(&format!("0x{upper}")).unwrap(), canonical);
        assert_eq!(canonical.to_hex(), OTHER_CAT_HEX);
    }

    /// The $DIG asset id is written twice in this file — once as hex for callers, once as bytes so
    /// [`Asset::DIG`] can be `const`. A typo in either would make `"dig"` and the tagged form name
    /// different tokens, which is precisely the split this design exists to prevent.
    #[test]
    fn dig_asset_id_hex_and_bytes_are_the_same_id() {
        let from_hex = AssetId::from_hex(Asset::DIG_ASSET_ID_HEX).unwrap();
        assert_eq!(Asset::DIG.asset_id(), Some(&from_hex));
        assert_eq!(from_hex.to_hex(), Asset::DIG_ASSET_ID_HEX);
        assert_eq!(Asset::Xch.asset_id(), None);
    }

    /// A rejection has to say WHICH way the input was wrong, or the caller is left guessing at a
    /// value it can see but cannot fix.
    #[test]
    fn parse_errors_name_the_defect_and_reach_the_wire() {
        assert_eq!(
            AssetId::from_hex("ab").unwrap_err(),
            AssetIdParseError::WrongLength { got: 2 }
        );
        assert!(AssetIdParseError::WrongLength { got: 2 }
            .to_string()
            .contains("64 hex characters"));
        assert!(AssetIdParseError::NotHex
            .to_string()
            .contains("non-hexadecimal"));
        assert!(AssetId::from_hex(&"3c".repeat(32))
            .unwrap()
            .to_string()
            .starts_with("3c3c"));
        // The deserializer surfaces the reason rather than a bare "invalid value".
        let err = serde_json::from_value::<Asset>(json!({ "cat": "zz" })).unwrap_err();
        assert!(err.to_string().contains("64 hex characters"), "{err}");
    }

    #[test]
    fn malformed_assets_are_rejected_rather_than_guessed_at() {
        assert!(AssetId::from_hex(&"z".repeat(64)).is_err());
        // An unknown bare token is not silently treated as a CAT name.
        assert!(serde_json::from_value::<Asset>(json!("usdc")).is_err());
        // The tagged form carries exactly one recognized key.
        assert!(serde_json::from_value::<Asset>(json!({})).is_err());
        assert!(serde_json::from_value::<Asset>(json!({ "tail": OTHER_CAT_HEX })).is_err());
        assert!(serde_json::from_value::<Asset>(json!({ "cat": "ab" })).is_err());
    }

    /// The params types that CARRY an asset must carry the widened one — the whole point of the
    /// change is that these two questions become askable about an arbitrary CAT.
    #[test]
    fn balance_and_coins_reads_can_name_an_arbitrary_cat() {
        let cat = Asset::Cat(AssetId::from_hex(OTHER_CAT_HEX).unwrap());
        assert_eq!(
            serde_json::to_value(WalletBalanceParams {
                address: "xch1exampleaddr".into(),
                asset: cat,
            })
            .unwrap(),
            json!({ "address": "xch1exampleaddr", "asset": { "cat": OTHER_CAT_HEX } })
        );
        assert_eq!(
            serde_json::to_value(WalletCoinsParams {
                address: "xch1exampleaddr".into(),
                asset: cat,
            })
            .unwrap(),
            json!({ "address": "xch1exampleaddr", "asset": { "cat": OTHER_CAT_HEX } })
        );
    }

    #[test]
    fn no_param_call_serializes_params_to_empty_object() {
        let req = build_request(1.into(), &StatusParams {});
        assert_eq!(req.method, "control.status");
        assert_eq!(req.params, json!({}));
    }

    #[test]
    fn data_param_call_carries_its_fields() {
        let req = build_request(2.into(), &SetCapParams { cap_bytes: 128 });
        assert_eq!(req.method, "control.cache.setCap");
        assert_eq!(req.params, json!({ "cap_bytes": 128 }));
    }

    #[test]
    fn pause_omits_until_when_indefinite() {
        assert_eq!(
            serde_json::to_value(PauseParams { until: None }).unwrap(),
            json!({})
        );
        assert_eq!(
            serde_json::to_value(PauseParams { until: Some(99) }).unwrap(),
            json!({ "until": 99 })
        );
    }

    #[test]
    fn method_binding_matches_the_catalog_name() {
        assert_eq!(
            SetUpstreamParams::METHOD.name(),
            "control.config.setUpstream"
        );
        assert_eq!(RequestParams::METHOD.name(), "pairing.request");
        assert_eq!(PollParams::METHOD.name(), "pairing.poll");
    }

    /// **Two spellings of one address canonicalise to one key — which is what makes `remove` able
    /// to find what `add` stored.**
    ///
    /// The fixture is deliberately not a pair of identical strings: each pair differs in the ways
    /// a person actually types an address (case, leading zeroes, an uncompressed run, whitespace),
    /// so a canonicaliser that only trimmed would pass the last pair and fail the rest.
    #[test]
    fn spellings_of_the_same_peer_canonicalise_to_one_key() {
        for (typed, also_typed) in [
            ("2001:0db8:0000:0000:0000:0000:0000:0001", "2001:DB8::1"),
            ("::1", "0:0:0:0:0:0:0:1"),
            (" 203.0.113.7 ", "203.0.113.7"),
        ] {
            let a = canonical_peer_ip(typed).expect("typed form is a literal");
            let b = canonical_peer_ip(also_typed).expect("second form is a literal");
            assert_eq!(a, b, "{typed} and {also_typed} name one peer");
        }
        // And the canonical form is the compressed lowercase one, not merely SOME agreed form.
        assert_eq!(canonical_peer_ip("2001:DB8:0:0::1").unwrap(), "2001:db8::1");
    }

    /// **Anything that is not a bare IP literal is REFUSED.**
    ///
    /// This is the bound on the ban list: `remove {ban: true}` persists a row keyed by this
    /// string, so accepting arbitrary text is unbounded at-rest growth for the cost of one call.
    /// Each rejected case is one a naive implementation accepts: a hostname resolves, a bracketed
    /// form round-trips through some parsers, and `ip:port` is what a person copies out of a log.
    #[test]
    fn a_peer_ip_that_is_not_a_bare_literal_is_refused() {
        for bad in [
            "",
            "   ",
            "node.example.com",
            "[2001:db8::1]",
            "[2001:db8::1]:8444",
            "203.0.113.7:8444",
            "203.0.113.0/24",
            "not an address",
        ] {
            let Err(err) = canonical_peer_ip(bad) else {
                panic!("{bad:?} must be refused, it was accepted");
            };
            assert_eq!(
                err.code_enum(),
                Some(ControlErrorCode::InvalidParams),
                "{bad:?} must be an INVALID_PARAMS refusal, not some other failure"
            );
        }
    }

    /// **Joining an address to a port brackets IPv6 — the un-bracketed form is a DIFFERENT valid
    /// address, so the mistake survives validation.**
    ///
    /// `::1` + `8444` formatted by hand is `::1:8444`, which parses fine and points somewhere
    /// else. The assertion is therefore not merely "it contains brackets": the naive rendering is
    /// checked to be a parseable address that is NOT the peer, which is what makes the bug silent.
    #[test]
    fn joining_a_v6_peer_to_a_port_cannot_produce_a_different_address() {
        assert_eq!(chia_peer_endpoint("::1", 8444), "[::1]:8444");
        assert_eq!(
            chia_peer_endpoint("2001:db8::1", 8444),
            "[2001:db8::1]:8444"
        );
        assert_eq!(chia_peer_endpoint("203.0.113.7", 8444), "203.0.113.7:8444");

        let naive = format!("{}:{}", "::1", 8444);
        let hijacked: std::net::IpAddr =
            naive.parse().expect("the naive join is itself an address");
        assert_ne!(
            hijacked,
            "::1".parse::<std::net::IpAddr>().unwrap(),
            "the naive join must be a DIFFERENT address — that is why the helper exists"
        );
        assert_ne!(chia_peer_endpoint("::1", 8444), naive);
    }
}

/// The default local safety margin, in basis points — `+1%`.
///
/// The same value as `dig_mirror_collateral::SAFETY_MARGIN_BP_DEFAULT`, restated here rather than
/// imported: `dig-mirror-collateral` sits at the SAME crate level as this contract, and a
/// same-level dependency is forbidden (CLAUDE.md Appendix B). It is published on the contract so a
/// config written before the field existed loads as the default rather than as a zero margin.
///
/// The default errs HIGH because the failure is asymmetric: under-posting likely costs an epoch's
/// rewards, while over-posting costs only the opportunity cost of the locked $DIG.
pub const DEFAULT_SAFETY_MARGIN_BP: u64 = 100;

/// The largest safety margin a node accepts, in basis points — `10_000`, i.e. +100%.
///
/// A margin is a cushion against the requirement rising, so doubling the requirement is already far
/// past any honest cushion. The bound exists because `.set` is a MONEY-PATH mutation reachable with
/// an ordinary paired token: an unbounded `u64` lets a caller commit the operator to locking an
/// arbitrary multiple of every store's requirement, and the margin arithmetic saturates rather than
/// failing, so an absurd value produces a silently enormous posting instead of an error.
pub const MAX_SAFETY_MARGIN_BP: u64 = 10_000;

no_params!(
    /// `control.collateral.requirement` params (none).
    ///
    /// The caller supplies no epoch: the answer is the epoch the NODE currently derives, so a
    /// caller-named epoch would invite a client to render a requirement for an epoch that is not
    /// the one being posted against.
    CollateralRequirementParams => ControlMethod::CollateralRequirement,
    results::CollateralRequirementResult
);
/// The horizon, in future epochs, a node covers when it recommends a buffer without being told
/// otherwise — `4`.
///
/// Published on the contract so a client can recognise the ordinary case, NOT so it can assume one:
/// the horizon a node actually used always travels in
/// [`CollateralBufferResult::Known`](crate::results::CollateralBufferResult::Known), and a reader
/// that substituted this constant for a payload it failed to read would state a claim the node
/// never made.
///
/// Four epochs bounds the compounded escalation ceiling at roughly x1.60. Fewer leaves a node one
/// bad epoch from `dangerously_low`; many more prices in a x4.62 worst case the controller reaches
/// only by escalating every single epoch, and locking $DIG against it has a real opportunity cost.
pub const DEFAULT_BUFFER_HORIZON_EPOCHS: u32 = 4;

/// The per-epoch escalation step denominator — `8`, i.e. the requirement can rise by at most
/// `+1/8` (`+12.5%`) in one epoch.
///
/// The same value as `dig_mirror_collateral::UP_STEP_DENOM`, restated here for the same reason
/// [`DEFAULT_SAFETY_MARGIN_BP`] is: `dig-mirror-collateral` sits at the SAME crate level as this
/// contract and a same-level dependency is forbidden (CLAUDE.md Appendix B).
///
/// It is a CEILING on one epoch's rise, and it compounds across epochs — which is precisely why the
/// horizon must travel with any buffer derived from it. It is not a forecast: inside the
/// controller's dead band the requirement does not move at all.
pub const ESCALATION_UP_STEP_DENOM: u64 = 8;

no_params!(
    /// `control.collateral.margin.get` params (none).
    CollateralMarginGetParams => ControlMethod::CollateralMarginGet,
    results::CollateralMarginResult
);

/// `control.collateral.margin.set` params.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct CollateralMarginSetParams {
    /// The margin in BASIS POINTS over the requirement (`100` is +1%), at most
    /// [`MAX_SAFETY_MARGIN_BP`].
    ///
    /// Basis points, never a percentage and never a float: it is the unit
    /// `dig_mirror_collateral::apply_safety_margin` takes and the unit dig-app `SPEC.md` §3.7b
    /// fixes for `collateral.margin_bp`. A 1 bp margin (0.01%) is a legal choice and any conversion
    /// to whole percent would erase it.
    pub margin_bp: u64,
}

impl CollateralMarginSetParams {
    /// Refuse a margin above [`MAX_SAFETY_MARGIN_BP`] as `-32602 INVALID_PARAMS`.
    ///
    /// Refused rather than clamped, and the asymmetry with dig-app is deliberate. dig-app CLAMPS a
    /// stored margin that exceeds its own ceiling, because refusing a value already on disk would
    /// leave the node posting the lower amount it was trying to move away from. This is the
    /// opposite situation: a caller is stating an intent right now, and silently applying a
    /// different number than the one requested would make a subsequent
    /// [`CollateralMarginResult`](crate::results::CollateralMarginResult) disagree with what the
    /// caller believes it set — on the money path.
    pub fn validated(self) -> Result<Self, ControlError> {
        if self.margin_bp > MAX_SAFETY_MARGIN_BP {
            return Err(ControlError::of(
                ControlErrorCode::InvalidParams,
                format!(
                    "margin_bp must be at most {MAX_SAFETY_MARGIN_BP} basis points (+100%); got {}",
                    self.margin_bp
                ),
            ));
        }
        Ok(self)
    }
}
control_call!(CollateralMarginSetParams => ControlMethod::CollateralMarginSet, results::CollateralMarginResult);

no_params!(
    /// `control.collateral.buffer` params (none).
    ///
    /// The caller names neither an epoch nor a horizon. Both are the NODE's: the served set and
    /// the reclaim state the buffer rests on exist only for the epoch being posted against, and a
    /// caller-chosen horizon would let a client quietly shrink the recommendation on a money
    /// surface by asking for a shorter one. The horizon the node used is returned instead.
    CollateralBufferParams => ControlMethod::CollateralBuffer,
    results::CollateralBufferResult
);
