//! The `dign` command model and its routing classification.
//!
//! A [`Command`] is the parsed, transport-agnostic form of a `dign` invocation. It is the single
//! source of truth for two decisions the gateway makes about every command:
//!
//! - **[`Command::route`]** — is this served LOCALLY with the held user identity ([`Route::UserApp`]
//!   — sign / profiles / wallet), or PROXIED to the engine over the session ([`Route::Engine`] —
//!   info / config / cache / stores / sync / subscriptions / peers / pair / open)? This is the
//!   SPEC §3.5 "handle-locally vs proxy-to-engine" split.
//! - **[`Command::action`]** — the stable command name that labels the `--json` envelope.
//!
//! The `dign` binary parses argv into a `Command` and hands it to the gateway; it never decides the
//! route itself. Keeping the model here (not in the binary) means the routing is unit-tested in the
//! library and the binary stays a thin shell.

use super::outcome::{ErrorCode, GatewayError};

/// Where a gateway command is served.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Route {
    /// Served locally by the user app using the held user identity (sign / profiles / wallet).
    UserApp,
    /// Proxied over the identity-authenticated session to the engine (info / reads / peers / …).
    Engine,
}

/// A parsed `dign` command. Variants that need arguments carry them; sub-command groups nest their
/// own action enum so the routing + method mapping stay exhaustive.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Command {
    // ---- Local (Route::UserApp): served with the held user identity. ----
    /// Manage the user's DIG profiles (multi-DID identity).
    Profiles(ProfilesAction),
    /// Inspect the active profile's wallet (address / balance).
    Wallet(WalletAction),
    /// Sign an opaque message with the active profile's identity key, returning the signature.
    Sign {
        /// The message bytes to sign, as a UTF-8 string (the CLI accepts text or hex; the binary
        /// decides the encoding before constructing this command).
        message: String,
    },

    // ---- Engine (Route::Engine): proxied over the session to the identity-agnostic engine. ----
    /// The rich, gated node status (`control.status`).
    Info,
    /// View or change the node's config (`control.config.*`).
    Config(ConfigAction),
    /// View or manage the local content cache (`control.cache.*`).
    Cache(CacheAction),
    /// List / pin / unpin hosted stores (`control.hostedStores.*`).
    Stores(StoresAction),
    /// View §21 whole-store sync status or trigger a capsule sync (`control.sync.*`).
    Sync(SyncAction),
    /// List / add / remove the node's store subscriptions (`control.subscribe`/`unsubscribe`/
    /// `listSubscriptions`).
    Subscriptions(SubscriptionsAction),
    /// View + manage the node's peer connections (`control.peerStatus` / `control.peers.*`).
    Peers(PeersAction),
    /// Pair a browser controller with the node (`control.pairing.*`).
    Pair(PairAction),
    /// Open a DIG link (`chia://…` or `urn:dig:chia:…`) via the engine's local serve URL.
    Open {
        /// The DIG link. Only the two DIG schemes are accepted — see [`validate_open_link`].
        link: String,
    },
}

/// `dign profiles` sub-actions. With none, shows the active profile.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProfilesAction {
    /// List every profile with its DID, marking the active one.
    List,
    /// Show the active profile.
    Show,
    /// Create a new profile with the given display name.
    Create {
        /// The human display name for the new profile.
        name: String,
    },
    /// Make an existing profile (by DID) the active one.
    Select {
        /// The `did:chia:` DID of the profile to activate.
        did: String,
    },
    /// Show the configured default profile — the identity presented by default.
    ShowDefault,
    /// Set the default profile (by DID) — the identity presented by default in the social selector
    /// and as the primary identity.
    SetDefault {
        /// The `did:chia:` DID of the profile to make the default.
        did: String,
    },
}

/// `dign wallet` sub-actions. With none, shows the address.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WalletAction {
    /// Show the active profile's wallet receive address.
    Address,
    /// Show the active profile's confirmed balance.
    Balance,
}

/// `dign config` sub-actions. With none, prints the current config.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConfigAction {
    /// Print the node's effective config.
    Get,
    /// Persist the upstream DIG RPC override (blank clears it).
    SetUpstream {
        /// The upstream RPC URL (empty string clears the override).
        url: String,
    },
}

/// `dign cache` sub-actions. With none, prints the cache config.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CacheAction {
    /// Print the cache cap / used / dir.
    Get,
    /// Set the on-disk cache size cap in bytes.
    SetCap {
        /// The cap in bytes.
        bytes: u64,
    },
    /// Delete all locally cached DIG content.
    Clear,
}

/// `dign stores` sub-actions. With none, lists hosted stores.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StoresAction {
    /// List every hosted / pinned store.
    List,
    /// Pin a store (`storeId[:rootHash]`).
    Pin {
        /// The store reference.
        store: String,
    },
    /// Unpin a store + evict its cached capsules.
    Unpin {
        /// The store reference.
        store: String,
    },
    /// Show one store's pin / cache status.
    Status {
        /// The store reference.
        store: String,
    },
}

/// `dign sync` sub-actions. With none, prints §21 sync status.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SyncAction {
    /// Print §21 whole-store sync availability + coverage.
    Status,
    /// Trigger a §21 sync for one capsule (`storeId:rootHash`).
    Trigger {
        /// The capsule reference.
        store: String,
    },
}

/// `dign subscriptions` sub-actions. With none, lists subscriptions.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SubscriptionsAction {
    /// List the node's persisted store subscriptions.
    List,
    /// Subscribe the node to a store id (64-hex).
    Add {
        /// The store id.
        store_id: String,
    },
    /// Remove a store subscription.
    Remove {
        /// The store id.
        store_id: String,
    },
}

/// `dign peers` sub-actions. With none, lists the live peer status.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PeersAction {
    /// List the live peer status.
    List,
    /// Dial a peer by address or peer_id.
    Connect {
        /// The peer address or peer_id.
        peer: String,
    },
    /// Drop a connected peer.
    Disconnect {
        /// The peer address or peer_id.
        peer: String,
    },
    /// Set a peer's ban state (`ban`, `blacklist`, or `none`).
    Ban {
        /// The peer address or peer_id.
        peer: String,
        /// The ban state token, forwarded verbatim to the engine.
        state: String,
    },
    /// Set the peer-pool max-connections cap.
    PoolConfig {
        /// The maximum number of pool connections.
        max_connections: u32,
    },
}

/// `dign pair` sub-actions. With none, lists pending requests + issued tokens.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PairAction {
    /// List pending pairing requests + issued controller tokens.
    List,
    /// Approve a pending pairing by id.
    Approve {
        /// The pairing id.
        pairing_id: String,
    },
    /// Revoke an issued controller token by id.
    Revoke {
        /// The token id.
        token_id: String,
    },
}

impl Command {
    /// Where this command is served: LOCAL with the user identity, or PROXIED to the engine.
    ///
    /// The split is the SPEC §3.5 contract: operations that need the in-memory user key or the
    /// user's profile state ([`Command::Profiles`] / [`Command::Wallet`] / [`Command::Sign`]) are
    /// served locally; everything else is identity-agnostic engine work proxied over the session.
    pub fn route(&self) -> Route {
        match self {
            Command::Profiles(_) | Command::Wallet(_) | Command::Sign { .. } => Route::UserApp,
            Command::Info
            | Command::Config(_)
            | Command::Cache(_)
            | Command::Stores(_)
            | Command::Sync(_)
            | Command::Subscriptions(_)
            | Command::Peers(_)
            | Command::Pair(_)
            | Command::Open { .. } => Route::Engine,
        }
    }

    /// The stable command name that labels the `--json` envelope's `action` field.
    pub fn action(&self) -> &'static str {
        match self {
            Command::Profiles(_) => "profiles",
            Command::Wallet(_) => "wallet",
            Command::Sign { .. } => "sign",
            Command::Info => "info",
            Command::Config(_) => "config",
            Command::Cache(_) => "cache",
            Command::Stores(_) => "stores",
            Command::Sync(_) => "sync",
            Command::Subscriptions(_) => "subscriptions",
            Command::Peers(_) => "peers",
            Command::Pair(_) => "pair",
            Command::Open { .. } => "open",
        }
    }
}

/// The two DIG link schemes `dign open` accepts. Anything else is rejected BEFORE it reaches the
/// engine or a browser — matching the engine `open` handler, which never launches a shell and only
/// resolves DIG content (verified store content is attacker-controlled, so the scheme allowlist is
/// a security boundary, not a convenience).
const DIG_LINK_SCHEMES: [&str; 2] = ["chia://", "urn:dig:chia:"];

/// Validate a `dign open` link: it MUST be a `chia://` or `urn:dig:chia:` DIG link. Returns a
/// `USAGE` [`GatewayError`] otherwise, so a bad link fails fast with a scriptable code.
pub fn validate_open_link(link: &str) -> Result<(), GatewayError> {
    if DIG_LINK_SCHEMES
        .iter()
        .any(|scheme| link.starts_with(scheme))
    {
        return Ok(());
    }
    Err(
        GatewayError::new(ErrorCode::Usage, format!("not a DIG link: {link}"))
            .with_hint("open accepts only chia:// or urn:dig:chia: links"),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn local_commands_route_to_the_user_app() {
        assert_eq!(
            Command::Sign {
                message: "hi".into()
            }
            .route(),
            Route::UserApp
        );
        assert_eq!(
            Command::Profiles(ProfilesAction::List).route(),
            Route::UserApp
        );
        assert_eq!(
            Command::Wallet(WalletAction::Address).route(),
            Route::UserApp
        );
    }

    #[test]
    fn engine_commands_route_to_the_engine() {
        let engine = [
            Command::Info,
            Command::Config(ConfigAction::Get),
            Command::Cache(CacheAction::Clear),
            Command::Stores(StoresAction::List),
            Command::Sync(SyncAction::Status),
            Command::Subscriptions(SubscriptionsAction::List),
            Command::Peers(PeersAction::List),
            Command::Pair(PairAction::List),
            Command::Open {
                link: "chia://abc".into(),
            },
        ];
        for command in engine {
            assert_eq!(
                command.route(),
                Route::Engine,
                "{command:?} should proxy to the engine"
            );
        }
    }

    #[test]
    fn action_names_are_stable_and_lowercase() {
        assert_eq!(Command::Info.action(), "info");
        assert_eq!(
            Command::Sign {
                message: String::new()
            }
            .action(),
            "sign"
        );
        assert_eq!(Command::Profiles(ProfilesAction::List).action(), "profiles");
    }

    #[test]
    fn open_accepts_both_dig_schemes() {
        assert!(validate_open_link("chia://store/path").is_ok());
        assert!(validate_open_link("urn:dig:chia:abcdef").is_ok());
    }

    #[test]
    fn open_rejects_non_dig_schemes_as_usage_errors() {
        for bad in [
            "https://evil.example",
            "file:///etc/passwd",
            "javascript:alert(1)",
            "",
        ] {
            let err = validate_open_link(bad).expect_err("must reject");
            assert_eq!(err.code, ErrorCode::Usage, "{bad} should be a USAGE error");
        }
    }
}
