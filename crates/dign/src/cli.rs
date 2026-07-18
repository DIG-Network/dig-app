//! The `dign` argv surface — the clap command tree and its mapping onto the gateway [`Command`].
//!
//! clap owns parsing + the `--help` discovery surface; this module's ONLY job is to translate a
//! parsed invocation into the transport-agnostic [`Command`] the gateway understands. The routing
//! decision (local vs engine) lives in the gateway, not here, so the CLI never second-guesses it.

use clap::{Parser, Subcommand};
use dig_app_core::gateway::{
    CacheAction, Command, ConfigAction, PairAction, PeersAction, ProfilesAction, StoresAction,
    SubscriptionsAction, SyncAction, WalletAction,
};

/// `dign` — the DIG user CLI. Talks to the running dig-app, which serves each command locally with
/// the user identity or proxies it to the engine.
#[derive(Parser)]
#[command(
    name = "dign",
    about = "The DIG user CLI — your identity, profiles, wallet, and node."
)]
pub struct Cli {
    /// Emit a single machine-readable JSON object to stdout (human prose → stderr).
    #[arg(long, global = true)]
    pub json: bool,

    #[command(subcommand)]
    pub command: CliCommand,
}

/// The top-level `dign` verbs. Local verbs (profiles/wallet/sign) are served by the app with the
/// user identity; the rest are proxied to the engine.
#[derive(Subcommand)]
pub enum CliCommand {
    /// Manage your DIG profiles (multi-DID identity).
    Profiles {
        #[command(subcommand)]
        action: Option<ProfilesVerb>,
    },
    /// Inspect the active profile's wallet.
    Wallet {
        #[command(subcommand)]
        action: Option<WalletVerb>,
    },
    /// Sign a message with the active profile's identity key.
    Sign {
        /// The message to sign.
        message: String,
    },
    /// Rich node status (proxied `control.status`).
    Info,
    /// View or change the node's config.
    Config {
        #[command(subcommand)]
        action: Option<ConfigVerb>,
    },
    /// View or manage the local content cache.
    Cache {
        #[command(subcommand)]
        action: Option<CacheVerb>,
    },
    /// List / pin / unpin hosted stores.
    Stores {
        #[command(subcommand)]
        action: Option<StoresVerb>,
    },
    /// View §21 sync status or trigger a capsule sync.
    Sync {
        #[command(subcommand)]
        action: Option<SyncVerb>,
    },
    /// List / add / remove the node's store subscriptions.
    Subscriptions {
        #[command(subcommand)]
        action: Option<SubscriptionsVerb>,
    },
    /// View + manage the node's peer connections.
    Peers {
        #[command(subcommand)]
        action: Option<PeersVerb>,
    },
    /// Pair a browser controller with the node.
    Pair {
        #[command(subcommand)]
        action: Option<PairVerb>,
    },
    /// Open a DIG link (`chia://…` or `urn:dig:chia:…`) in the browser.
    Open {
        /// The DIG link.
        link: String,
    },
}

/// `dign profiles` verbs.
#[derive(Subcommand)]
pub enum ProfilesVerb {
    /// List every profile.
    List,
    /// Create a new profile.
    Create {
        /// The display name.
        name: String,
    },
    /// Make a profile (by DID) the active one.
    Select {
        /// The `did:chia:` DID.
        did: String,
    },
    /// Show the default profile, or set it by passing a DID. The default is the identity presented
    /// by default (in the social selector, as the primary identity).
    Default {
        /// The `did:chia:` DID to make the default. Omit to show the current default.
        did: Option<String>,
    },
}

/// `dign wallet` verbs.
#[derive(Subcommand)]
pub enum WalletVerb {
    /// Show the receive address.
    Address,
    /// Show the confirmed balance.
    Balance,
}

/// `dign config` verbs.
#[derive(Subcommand)]
pub enum ConfigVerb {
    /// Print the effective config.
    Get,
    /// Persist the upstream DIG RPC override (blank clears it).
    SetUpstream {
        /// The upstream RPC URL.
        url: String,
    },
}

/// `dign cache` verbs.
#[derive(Subcommand)]
pub enum CacheVerb {
    /// Print the cache cap / used / dir.
    Get,
    /// Set the cache size cap in bytes.
    SetCap {
        /// The cap in bytes.
        bytes: u64,
    },
    /// Delete all locally cached content.
    Clear,
}

/// `dign stores` verbs.
#[derive(Subcommand)]
pub enum StoresVerb {
    /// List hosted / pinned stores.
    List,
    /// Pin a store (`storeId[:rootHash]`).
    Pin {
        /// The store reference.
        store: String,
    },
    /// Unpin a store.
    Unpin {
        /// The store reference.
        store: String,
    },
    /// Show one store's status.
    Status {
        /// The store reference.
        store: String,
    },
}

/// `dign sync` verbs.
#[derive(Subcommand)]
pub enum SyncVerb {
    /// Print §21 sync status.
    Status,
    /// Trigger a §21 sync for a capsule (`storeId:rootHash`).
    Trigger {
        /// The capsule reference.
        store: String,
    },
}

/// `dign subscriptions` verbs.
#[derive(Subcommand)]
pub enum SubscriptionsVerb {
    /// List subscriptions.
    List,
    /// Subscribe to a store id.
    Add {
        /// The store id (64-hex).
        store_id: String,
    },
    /// Remove a subscription.
    Remove {
        /// The store id (64-hex).
        store_id: String,
    },
}

/// `dign peers` verbs.
#[derive(Subcommand)]
pub enum PeersVerb {
    /// List the live peer status.
    List,
    /// Dial a peer.
    Connect {
        /// The peer address or peer_id.
        peer: String,
    },
    /// Drop a connected peer.
    Disconnect {
        /// The peer address or peer_id.
        peer: String,
    },
    /// Set a peer's ban state (`ban`, `blacklist`, `none`).
    Ban {
        /// The peer address or peer_id.
        peer: String,
        /// The ban state.
        #[arg(long)]
        state: String,
    },
    /// Set the peer-pool max-connections cap.
    PoolConfig {
        /// The max connections.
        #[arg(long)]
        max_connections: u32,
    },
}

/// `dign pair` verbs.
#[derive(Subcommand)]
pub enum PairVerb {
    /// List pending pairings + issued tokens.
    List,
    /// Approve a pending pairing.
    Approve {
        /// The pairing id.
        pairing_id: String,
    },
    /// Revoke an issued token.
    Revoke {
        /// The token id.
        token_id: String,
    },
}

impl CliCommand {
    /// Translate the parsed invocation into the gateway [`Command`]. Sub-command groups invoked
    /// with no verb default to their natural read (list / show / get), matching the engine CLI.
    pub fn into_command(self) -> Command {
        match self {
            CliCommand::Profiles { action } => Command::Profiles(match action {
                None => ProfilesAction::Show,
                Some(ProfilesVerb::List) => ProfilesAction::List,
                Some(ProfilesVerb::Create { name }) => ProfilesAction::Create { name },
                Some(ProfilesVerb::Select { did }) => ProfilesAction::Select { did },
                Some(ProfilesVerb::Default { did: None }) => ProfilesAction::ShowDefault,
                Some(ProfilesVerb::Default { did: Some(did) }) => {
                    ProfilesAction::SetDefault { did }
                }
            }),
            CliCommand::Wallet { action } => Command::Wallet(match action {
                None | Some(WalletVerb::Address) => WalletAction::Address,
                Some(WalletVerb::Balance) => WalletAction::Balance,
            }),
            CliCommand::Sign { message } => Command::Sign { message },
            CliCommand::Info => Command::Info,
            CliCommand::Config { action } => Command::Config(match action {
                None | Some(ConfigVerb::Get) => ConfigAction::Get,
                Some(ConfigVerb::SetUpstream { url }) => ConfigAction::SetUpstream { url },
            }),
            CliCommand::Cache { action } => Command::Cache(match action {
                None | Some(CacheVerb::Get) => CacheAction::Get,
                Some(CacheVerb::SetCap { bytes }) => CacheAction::SetCap { bytes },
                Some(CacheVerb::Clear) => CacheAction::Clear,
            }),
            CliCommand::Stores { action } => Command::Stores(match action {
                None | Some(StoresVerb::List) => StoresAction::List,
                Some(StoresVerb::Pin { store }) => StoresAction::Pin { store },
                Some(StoresVerb::Unpin { store }) => StoresAction::Unpin { store },
                Some(StoresVerb::Status { store }) => StoresAction::Status { store },
            }),
            CliCommand::Sync { action } => Command::Sync(match action {
                None | Some(SyncVerb::Status) => SyncAction::Status,
                Some(SyncVerb::Trigger { store }) => SyncAction::Trigger { store },
            }),
            CliCommand::Subscriptions { action } => Command::Subscriptions(match action {
                None | Some(SubscriptionsVerb::List) => SubscriptionsAction::List,
                Some(SubscriptionsVerb::Add { store_id }) => SubscriptionsAction::Add { store_id },
                Some(SubscriptionsVerb::Remove { store_id }) => {
                    SubscriptionsAction::Remove { store_id }
                }
            }),
            CliCommand::Peers { action } => Command::Peers(match action {
                None | Some(PeersVerb::List) => PeersAction::List,
                Some(PeersVerb::Connect { peer }) => PeersAction::Connect { peer },
                Some(PeersVerb::Disconnect { peer }) => PeersAction::Disconnect { peer },
                Some(PeersVerb::Ban { peer, state }) => PeersAction::Ban { peer, state },
                Some(PeersVerb::PoolConfig { max_connections }) => {
                    PeersAction::PoolConfig { max_connections }
                }
            }),
            CliCommand::Pair { action } => Command::Pair(match action {
                None | Some(PairVerb::List) => PairAction::List,
                Some(PairVerb::Approve { pairing_id }) => PairAction::Approve { pairing_id },
                Some(PairVerb::Revoke { token_id }) => PairAction::Revoke { token_id },
            }),
            CliCommand::Open { link } => Command::Open { link },
        }
    }
}
