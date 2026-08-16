//! Photograph the REAL DIG app window on a chosen tab, theme, size and account state.
//!
//! # Why this and not `pane_preview`
//!
//! [`pane_preview`](../pane_preview.rs) draws a pane and deliberately leaves out the shell's chrome.
//! That is the right instrument for asking whether one pane reads well, and the wrong one for asking
//! what the application looks like: the sidebar, the title row and the close affordance are most of
//! what a person sees, and at the shell's minimum width they are where the layout is under the most
//! pressure. A gallery of panes is not a picture of the app.
//!
//! This drives the shipping shell through its own paint path and writes a PNG.
//!
//! ```text
//! cargo run -p dig-app-core --features gui --example window_gallery -- \
//!     account light 480 900 locked docs/gallery/account-light-480.png
//! ```
//!
//! # Nothing is clicked, and nothing is screen-captured
//!
//! Reaching the fourth tab, or a 480 px window, by clicking and dragging is what a capture harness
//! must never do: synthetic input takes the foreground off the window and photographs whatever was
//! behind it — which is how a committed screenshot labelled "Cache" turned out to be the Status tab
//! (dig_ecosystem#2326). Every axis that used to need input is an ARGUMENT here.
//!
//! The capture itself is a framebuffer readback rather than a screen grab, because GDI is blind to a
//! hardware GL surface and hands back a black rectangle of exactly the right size — a failure that
//! reports success. See `photograph_shell`.
//!
//! # Why every account state is reachable
//!
//! The Account and Security panes exist to express the six account states, and five of them are not
//! the rich one. dig_ecosystem#2059 was a defect in three states at once, invisible from a
//! screenshot of the sixth.
//!
//! This example only ever DRAWS: it raises no prompt, and nothing here reaches a chain, a key or a
//! wallet.

use std::sync::Arc;
use std::time::{Duration, Instant};

use dig_app_core::account::chain_mint::MintAvailability;
use dig_app_core::cache::{CacheSnapshot, GIB, MIB};
use dig_app_core::config::AgentConfig;
use dig_app_core::confirm::gui::{photograph_shell, Theme};
use dig_app_core::engine::{EngineConnector, EngineState, NodeConnector};
use dig_app_core::environment::AppEnvironment;
use dig_app_core::hosted_stores::{
    HostedStoresReading, HostedStoresUnknown, NodeHostedStores, REFRESH_INTERVAL,
    STORES_READ_TIMEOUT,
};
use dig_app_core::network::{ChainSync, NetworkStanding, NodeNetworkStanding, PeerCount};
use dig_app_core::node_facts::NodeFacts;
use dig_app_core::profiles::{ProfileCreation, ProfilesReading};
use dig_app_core::tray_menu::{AccountState, TrayView, WindowHost};
use dig_app_core::wallet::overview::{BalanceReading, Balances};
use dig_app_core::window_model::TabId;

/// The tab named by `argument`, or `None` when it names nothing.
fn tab(argument: &str) -> Option<TabId> {
    TabId::all().into_iter().find(|tab| name(*tab) == argument)
}

/// The command-line name of a tab — its label, lowercased.
///
/// Derived rather than listed, so the gallery cannot come to disagree with the window about which
/// tabs exist: the old hand-written match still accepted `status`, `security`, `apps` and `cache`
/// long after those tabs were merged away (dig_ecosystem#2358), which is how a file lands under a
/// name that describes a picture nobody can take.
fn name(tab: TabId) -> String {
    format!("{tab:?}").to_lowercase()
}

/// The account state named by `argument`, or `None` when it names nothing.
///
/// Every variant is reachable, including both unlocked ones: `recoverable` decides which management
/// verbs the model offers, so an account with no recovery phrase draws a different Account pane from
/// one that has it.
fn account_state(argument: &str) -> Option<AccountState> {
    match argument {
        "unsupported" => Some(AccountState::Unsupported),
        "absent" => Some(AccountState::Absent),
        "locked" => Some(AccountState::Locked),
        "unopenable" => Some(AccountState::Unopenable),
        "needs-password" => Some(AccountState::NeedsPassword),
        "unlocked" => Some(AccountState::Unlocked { recoverable: true }),
        "unlocked-no-phrase" => Some(AccountState::Unlocked { recoverable: false }),
        _ => None,
    }
}

/// The profile fixture a capture is taken with (dig_ecosystem#2403).
///
/// # Why this is an ARGUMENT and not something the harness clicks its way into
///
/// Same rule as the account state and the tab: every axis that used to need synthetic input is a
/// command-line argument here, because synthetic input takes the foreground off the window and
/// photographs whatever was behind it.
///
/// # Why these captures are FIXTURES, and the honest statement of it
///
/// Every real account holds ZERO profiles, because nothing in this build can mint one. `None` below
/// is therefore the only state a live machine can be photographed in, and it is the default. The
/// other three are registries built through `ProfileRegistry::from_json` — which is not a loophole:
/// it is the SAME path production loads a real registry through, and dig-account re-checks all four
/// of its invariants on the way in, so a fixture that gets past them is one the production loader
/// would also accept. A picture taken from one shows the card exactly as it will render the day a
/// mint exists; it does not show an end-to-end run, and nothing here claims it does.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Profiles {
    /// No profiles at all — production reality, and the empty state every real user reads.
    None,
    /// Two profiles, both shown, the first in use.
    Two,
    /// Two profiles with the SECOND hidden from this computer's lists.
    Hidden,
    /// The state AFTER a completed switch: the second profile is the one in use.
    Switched,
}

impl Profiles {
    /// The fixture named by `argument`, or `None` when it names nothing.
    fn named(argument: &str) -> Option<Self> {
        match argument {
            "none" => Some(Self::None),
            "two" => Some(Self::Two),
            "hidden" => Some(Self::Hidden),
            "switched" => Some(Self::Switched),
            _ => None,
        }
    }

    /// The reading this fixture produces, built through the real registry loader.
    ///
    /// The two profiles are LABELLED and the labels differ, so a capture shows which row is which —
    /// an unlabelled pair would render as "profile 1" and "profile 2" and prove nothing about a card
    /// that had swapped them.
    fn reading(self) -> ProfilesReading {
        use dig_account::registry::ProfileVisibility;
        use dig_account::ProfileIx;
        use dig_app_core::account::profile_session::test_support::registry_with;

        if self == Self::None {
            return ProfilesReading::Known(Vec::new());
        }

        let mut registry = registry_with(&[
            (ProfileIx::ROOT, Some("Everyday")),
            (ProfileIx(1), Some("Studio")),
        ]);
        match self {
            Self::None => unreachable!("returned above"),
            Self::Two => {}
            // Hidden, not active — dig-account refuses to hide the profile in use, which is what
            // makes "a hidden active profile shows an empty list while the wallet derives there"
            // unrepresentable rather than merely guarded against.
            Self::Hidden => registry
                .set_visibility(ProfileIx(1), ProfileVisibility::HiddenFromLists)
                .expect("a non-active profile can be hidden"),
            // The state a completed switch leaves behind, produced by performing the switch on the
            // registry rather than by hand-marking a row active — so the picture is of a switch that
            // dig-account itself carried out.
            Self::Switched => {
                let _ = registry
                    .set_active(ProfileIx(1))
                    .expect("a confirmed profile can be made active");
            }
        }
        ProfilesReading::of_registry(&registry)
    }
}

/// The balance the gallery shows: 12.5 $DIG and 0.25 XCH, in each asset's own base unit.
///
/// Written in base units rather than as decimals, because that is what the type holds and what the
/// pane's one formatter divides — a gallery that pre-divided would photograph a figure the
/// application does not produce.
const HELD: Balances = Balances {
    dig_units: 12_500,
    xch_mojos: 250_000_000_000,
};

/// The view to draw: one account state, on a machine that is otherwise working.
///
/// Everything around the account is held FIXED across the states, so what changes between two
/// captures is the account and nothing else. A sealed account has no key to derive an address from,
/// so it gets no address, no profile id and no balance — a gallery that showed them anyway would
/// photograph figures the application cannot produce in that state.
/// Install the edit service the `--profile-edit` fixture names, and report the offer that goes with
/// it. `None` when the name is not one of them.
///
/// The fixtures answer; they never reach a chain, and none of them can commit — `commit` refuses on
/// every one, so a gallery run cannot spend anything even if something pressed the control.
fn install_edit_fixture(named: &str) -> Option<dig_app_core::profile_edit::ProfileEditing> {
    use dig_app_core::profile_edit::{
        BodyRead, BodyStore, BodyStoreError, CommitOutcome, EditSeams, EditService,
        ProfileEditError, ProfileEditSeam, ProfileEditing, ProfileField, ProfileSnapshot,
        SlotChange,
    };

    /// A seam that answers one fixed read and refuses to commit.
    struct Fixture(Result<ProfileSnapshot, ProfileEditError>);

    impl ProfileEditSeam for Fixture {
        fn read(&self) -> Result<ProfileSnapshot, ProfileEditError> {
            self.0.clone()
        }
        fn commit(
            &self,
            _: &[(ProfileField, SlotChange)],
        ) -> Result<CommitOutcome, ProfileEditError> {
            Err(ProfileEditError::Locked)
        }
        fn confirmation(&self, _: &str) -> Result<Option<u32>, ProfileEditError> {
            Ok(None)
        }
    }

    /// A store that holds nothing and is never asked, since nothing here commits.
    struct NoBodies;

    impl BodyStore for NoBodies {
        fn put(&self, _: &str, _: &str, _: &[u8]) -> Result<(), BodyStoreError> {
            Err(BodyStoreError::NoToken)
        }
        fn get(&self, _: &str, _: &str) -> Result<BodyRead, BodyStoreError> {
            Ok(BodyRead::Nothing)
        }
    }

    let filled = || {
        let mut values = std::collections::BTreeMap::new();
        values.insert(ProfileField::DisplayName, "Ada Lovelace".to_string());
        values.insert(
            ProfileField::Bio,
            "Writes engines that write themselves.".to_string(),
        );
        values.insert(ProfileField::Pronouns, "she/her".to_string());
        values.insert(ProfileField::Location, "London".to_string());
        values.insert(
            ProfileField::Links,
            "https://example.org
https://example.org/notes"
                .to_string(),
        );
        values.insert(
            ProfileField::XchAddress,
            "xch1up0vfatgtwrcgcvc360jd57t3p2kjskncutvzakh9mhdmlvejj3shn8wln".to_string(),
        );
        ProfileSnapshot {
            store_id: "11".repeat(32),
            root: "22".repeat(32),
            values,
            body_len: 240,
        }
    };

    let (answer, offer) = match named {
        "filled" => (Ok(filled()), ProfileEditing::Possible),
        "empty" => (
            Ok(ProfileSnapshot {
                values: std::collections::BTreeMap::new(),
                body_len: 5,
                ..filled()
            }),
            ProfileEditing::Possible,
        ),
        "unreadable" => (
            Err(ProfileEditError::ChainUnreachable(
                "your node did not answer".to_string(),
            )),
            ProfileEditing::Possible,
        ),
        // The blocked case needs no service at all: the card never gets as far as a read.
        "locked" => {
            return Some(ProfileEditing::of_seams(
                &EditSeams::Wired {
                    seam: std::sync::Arc::new(Fixture(Ok(filled()))),
                    bodies: std::sync::Arc::new(NoBodies),
                },
                true,
                false,
            ))
        }
        _ => return None,
    };

    EditService::install(EditService::detached(EditSeams::Wired {
        seam: std::sync::Arc::new(Fixture(answer)),
        bodies: std::sync::Arc::new(NoBodies),
    }));
    Some(offer)
}

fn view_for(account: AccountState, second_factor: bool, profiles: Profiles) -> TrayView {
    let sealed = !matches!(account, AccountState::Unlocked { .. });
    TrayView {
        // Set by `--profile-edit`, which installs the matching service; left unmeasured otherwise,
        // which is what a gallery host with no chain transport genuinely is.
        profile_editing: Default::default(),
        running: true,
        node_connected: true,
        node: "Node v0.65.0 · 3 capsule(s) cached · 1 store(s) hosted".to_string(),
        account: Some(account),
        profile_id: (!sealed).then(|| {
            "4f3a9c2e7b81d05fa6c34e19b7d208fc5e6a1b93d47f0c28ae5b6139d0f7a24c".to_string()
        }),
        receive_address: (!sealed)
            .then(|| "xch1up0vfatgtwrcgcvc360jd57t3p2kjskncutvzakh9mhdmlvejj3shn8wln".to_string()),
        balance: match sealed {
            true => BalanceReading::default(),
            false => BalanceReading::Known {
                balances: HELD,
                as_of: dig_app_core::wallet::engine::BalanceAsOf::Replica {
                    height: 7_000_000,
                    caught_up: true,
                },
            },
        },
        second_factor,
        profiles: profiles.reading(),
        // STATED rather than defaulted, because the default no longer means what this picture must
        // show. `ProfileCreation::default()` is now `Unknown` — *nobody has asked the node yet*
        // (dig_ecosystem#2690) — while the shipped binary hardcodes `MintSeams::NoChainTransport`
        // and therefore renders the unreachable-chain sentence. Left on the default, every capture
        // in this gallery would show a *still checking* card that no build any user runs can
        // produce: a picture that contradicts the product, which is the one thing a gallery must
        // never do.
        profile_creation: ProfileCreation::of(MintAvailability::NoChainTransport),
        // A fixture takes no reading (dig_ecosystem#2398).
        mint_chain: None,
        window_host: WindowHost::Available,
        cache: Some(CacheSnapshot {
            cap_bytes: GIB,
            used_bytes: 350 * MIB,
        }),
        // The fixture's networks: a chain replica that has reached a block, six DIG peers and four
        // Chia peers. Three DIFFERENT figures, because a fixture whose counts agree is a picture in
        // which a strip that drew one number twice would look correct.
        //
        // The peers' announced peak is a FOURTH distinct figure, and sits three blocks above the
        // replica's own. Even a caught-up replica trails the tip by the blocks found since it last
        // wrote, so equal heights here would make the ordinary case look like the exceptional one —
        // and would hide a strip that drew the replica's height under both labels.
        network: NetworkStanding {
            sync: ChainSync::Synced {
                peak_height: 6_012_345,
            },
            dig_peers: PeerCount::Known(6),
            chia_peers: PeerCount::Known(4),
            chia_peer_peak_height: Some(6_012_348),
            // A wallet IS enrolled. The default is an unresolved subscription, under which the
            // catch-up reading is silent — so a gallery left on it would photograph a strip missing
            // a reading every real enrolled machine shows (dig_ecosystem#2820).
            watched_addresses: Some(3),
        },
        ..TrayView::default()
    }
}

/// Everything the node itself reports, as one capture carries it.
///
/// **All four travel together or the picture contradicts itself.** The first cut of `--live` carried
/// only the two fields the new cards read, and produced an image where the Node connection card said
/// `1 store(s) hosted` — the fixture's sentence — inches above a live sharing card reading `3
/// stores`. Both figures are the node's `hosted_store_count`; one of them was three weeks old and
/// invented. A capture that appears to disprove the behaviour it is evidence FOR is worse than no
/// capture, so the boundary is drawn at "the node reported it", not at "a card added in this ticket
/// reads it".
struct NodeReadings {
    /// The one-line link summary, from [`EngineState::summary`] — the SAME builder the shipped
    /// binary calls (`dig-app.rs`, `status.engine.summary()`). Retyping the sentence here would let
    /// the gallery's copy drift from the app's, which is the whole failure this ticket's own
    /// `store_contents`/`SHARING_LABELS` sharing exists to avoid.
    summary: String,
    /// The node's own cap and usage. `None` only when there is no node, which `--live` refuses.
    cache: Option<CacheSnapshot>,
    /// What the node says about itself. `Option` so a live view can be turned back into its fixture
    /// counterpart field for field, which is how the round-trip test proves nothing else moved.
    facts: Option<NodeFacts>,
    /// The stores it holds.
    stores: HostedStoresReading,
    /// Where it stands on both networks (dig_ecosystem#2569).
    standing: NetworkStanding,
}

/// `view` with every field the node supplies replaced, and every other field untouched.
///
/// Split out from the reading itself so what `--live` VARIES is one function with no node in it:
/// the capture must differ from its fixture counterpart in what the node reported and nothing else,
/// and `live_readings_replace_the_node_fields_and_leave_the_rest_alone` pins that here.
///
/// The fields deliberately left alone are the ones that are NOT node readings — the account, the
/// address, the second factor, the updater. Varying those would drag key and account state into a
/// capture harness that is documented to reach neither.
fn with_live(view: TrayView, readings: &NodeReadings) -> TrayView {
    TrayView {
        node: readings.summary.clone(),
        cache: readings.cache,
        node_facts: readings.facts.clone(),
        hosted_stores: readings.stores.clone(),
        network: readings.standing.clone(),
        ..view
    }
}

/// Whether the NODE ITSELF produced this reading, whatever it said.
///
/// The line a `--live` capture is allowed to be taken across. A node that answered `UNAUTHORIZED`,
/// or that does not serve the method, said something real about a machine that is demonstrably
/// running — those panes are worth photographing. `Pending` and the three unreachable reasons are
/// the absence of an answer, and a picture taken from one would be a file labelled live showing
/// fixture-shaped nothing. That is the failure this harness's own header exists to prevent.
fn answered(reading: &HostedStoresReading) -> bool {
    match reading {
        HostedStoresReading::Pending => false,
        HostedStoresReading::Known(_) => true,
        HostedStoresReading::Unknown(reason) => !matches!(
            reason,
            HostedStoresUnknown::NoNode
                | HostedStoresUnknown::Unreachable(_)
                | HostedStoresUnknown::TimedOut(_)
        ),
    }
}

/// How long the harness waits for the store read to land before giving up on it.
///
/// Taken FROM the poller's own budget rather than picked, and doubled: the read may be abandoned at
/// [`STORES_READ_TIMEOUT`] and the poller records the abandonment a moment later, so a wait fitted
/// exactly to the budget would report "no answer" for a node that was about to say `TimedOut`.
const LIVE_WAIT: Duration = Duration::from_secs(STORES_READ_TIMEOUT.as_secs() * 2);

/// The node address this machine is configured to use, or an empty string to walk the §5.3 ladder.
///
/// Resolved exactly as the application resolves it — the same [`AppEnvironment`] and the same
/// [`AgentConfig`] — because a capture is a claim about what the app draws on THIS machine, and a
/// harness with its own idea of where the node lives is photographing a different machine.
///
/// This used to be a hard-coded `""`, which silently ignored a configured node and always dialled
/// the ladder. On a host running a second node — the ordinary way to look at an unreleased one — the
/// picture came back showing the node the reader was not asking about, labelled live and entirely
/// plausible (dig_ecosystem#2806).
///
/// A config that cannot be read yields the ladder rather than an error: a missing config is the
/// ordinary case for a fresh install, and it is what `AgentConfig::load` already returns a default
/// for.
fn configured_node() -> String {
    let environment = AppEnvironment::from_host();
    let config = environment
        .config_path()
        .ok()
        .map(|path| AgentConfig::load(&path).unwrap_or_default())
        .unwrap_or_default();
    environment.endpoint(&config)
}

/// Everything a live capture shows, taken from the running node — or the reason there is nothing.
///
/// The node is found the way the application finds it: [`NodeConnector`] walking the §5.3 ladder,
/// rather than a second client invented here with its own idea of where a node lives. Only
/// `control.status` and `control.hostedStores.list` are called, so this reads a node and reaches no
/// key, wallet or chain — the standing constraint on this file.
///
/// **There is no fallback.** Every branch that cannot produce a reading returns an error naming what
/// did not answer, and the caller writes no file.
fn live_readings() -> Result<NodeReadings, String> {
    let link = NodeConnector::default().probe(&configured_node());
    let EngineState::Connected { .. } = &link else {
        return Err(format!(
            "no node answered control.status, so there is nothing live to photograph — {}",
            link.summary()
        ));
    };
    let status = link.status().expect("a connected link carries its status");
    let facts = NodeFacts::of_status(status);
    // The same two fields the shipped binary lifts out of the status snapshot for the tray
    // (`dig-app.rs`: `st.cache.cap_bytes` / `st.cache.used_bytes`). Read from the node rather than
    // held at the fixture's 350 MiB, which sat above a live store list of three 128.7 MiB stores —
    // arithmetic anyone reading the image can check, and it did not add up.
    let cache = Some(CacheSnapshot {
        cap_bytes: status.cache.cap_bytes,
        used_bytes: status.cache.used_bytes,
    });
    let summary = link.summary();

    let poller = NodeHostedStores::new(REFRESH_INTERVAL, STORES_READ_TIMEOUT);
    // Started alongside the store read so both are in flight during the one wait below.
    let standing_poller = NodeNetworkStanding::default();
    let _ = standing_poller.observe(&link);
    let deadline = Instant::now() + LIVE_WAIT;
    loop {
        let reading = poller.observe(&link);
        if answered(&reading) {
            // Read from the SAME running node, in the same wait, so a live picture's badges and
            // its cards describe one machine at one moment.
            let standing = standing_poller.observe(&link);
            return Ok(NodeReadings {
                summary,
                cache,
                facts: Some(facts),
                stores: reading,
                standing,
            });
        }
        if Instant::now() >= deadline {
            return Err(format!(
                "the node did not answer control.hostedStores.list within {LIVE_WAIT:?} \
                 ({reading:?}), so no live capture can be taken"
            ));
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}

const USAGE: &str = "usage: window_gallery <tab> <light|dark> <width> <height> <account-state> \
                     <out.png> [--second-factor] [--live]\n  \
                     --live: read the two node cards from the RUNNING node; refuses if none \
                     answers\n  \
                     account-state: unsupported absent locked unopenable needs-password unlocked \
                     unlocked-no-phrase";

/// Report `problem`, the tabs that exist, and the usage, then stop.
///
/// The tab list is asked of [`TabId`] rather than written here, for the reason [`name`] gives: the
/// hand-written one went on offering `status`, `security`, `apps` and `cache` long after those tabs
/// were merged away (dig_ecosystem#2358), so the one message a person reads after mistyping a tab
/// named four tabs they could not photograph.
fn tabs_line() -> String {
    let named: Vec<String> = TabId::all().into_iter().map(name).collect();
    format!("  tab: {}", named.join(" "))
}

/// Report `problem` alongside the usage and stop.
///
/// Nothing is half-written: a gallery that guessed at a mistyped argument would write a file under a
/// name that describes a different picture, which is the one failure a screenshot set cannot survive.
fn refuse(problem: &str) -> ! {
    eprintln!("{problem}\n{USAGE}\n{}", tabs_line());
    std::process::exit(2);
}

/// A chain write to photograph, named on the command line.
///
/// The values are the incident's own (dig_ecosystem#2995): the coin ids and heights below are what
/// the chain actually recorded, so a capture shows an id of the real length rather than a short
/// placeholder that would wrap differently.
fn transaction_fixture(named: &str) -> Option<dig_app_core::transaction::Transaction> {
    use dig_app_core::transaction::{Money, Stage, Transaction};

    let base = Transaction::starting(
        "Creating your profile",
        Some(Money {
            amount_mojos: 20_002,
            fee_mojos: None,
        }),
    );
    let did_coin = "0xe4e2b74f915e7f4a739b305aa086aa657a09a8a4df231d9307bb265c528ecc12";
    Some(match named {
        "building" => base,
        "pushed" => base.mid_ceremony(
            "Creating your profile",
            Stage::Pushed {
                id: format!("Identity coin {did_coin}"),
            },
        ),
        "halfway" => base.mid_ceremony(
            "Creating your profile — launching your store",
            Stage::Confirmed {
                height: 9_154_450,
                made: "Your identity exists. DIG is now launching your store.".to_string(),
            },
        ),
        "confirmed" => base.at(Stage::Confirmed {
            height: 9_154_458,
            made: "Your profile is on chain.".to_string(),
        }),
        "failed" => base.at(Stage::Failed {
            why: "DIG lost its connection to the node.

DIG cannot tell whether money left your                   wallet."
                .to_string(),
            next: dig_app_core::account::creation_progress::KEEP_DIG_RUNNING.to_string(),
        }),
        _ => return None,
    })
}

fn main() {
    let all: Vec<String> = std::env::args().skip(1).collect();
    // Flags are taken out before the positionals are read, so `--second-factor` cannot shift the
    // output path along by one. It did exactly that once, and the picture landed in a file named
    // for the flag -- a gallery is only as trustworthy as the name on each file.
    //
    // Flags that take a VALUE (currently `--profiles`) must also remove their value from the
    // positional list; leaving only the flag itself out while keeping the value shifts the output
    // path along by one and writes the fixture name as an extra file in the working directory.
    let args: Vec<&String> = {
        let value_flags: &[&str] = &["--profiles", "--transaction", "--profile-edit"];
        let mut skip_next = false;
        all.iter()
            .filter(|argument| {
                if skip_next {
                    skip_next = false;
                    return false;
                }
                if value_flags.contains(&argument.as_str()) {
                    skip_next = true;
                    return false;
                }
                !argument.starts_with("--")
            })
            .collect()
    };
    let Some(tab) = args.first().map(|a| a.as_str()).and_then(tab) else {
        refuse("no tab named");
    };
    let theme = match args.get(1).map(|a| a.as_str()) {
        Some("light") => Theme::Light,
        Some("dark") => Theme::Dark,
        other => refuse(&format!("unknown theme {other:?} — expected light or dark")),
    };
    let (Some(width), Some(height)) = (
        args.get(2).and_then(|value| value.parse().ok()),
        args.get(3).and_then(|value| value.parse().ok()),
    ) else {
        refuse("width and height must both be given, in logical pixels");
    };
    let Some(named) = args.get(4).copied() else {
        refuse("no account state named");
    };
    let Some(account) = account_state(named) else {
        refuse(&format!("unknown account state `{named}`"));
    };
    let Some(path) = args.get(5).copied() else {
        refuse("no output path given");
    };
    // Off by default so the Security pane's no-control second-factor line is what a plain run shows:
    // it is the case the design brief singles out, and the one an invented disabled button would
    // have hidden.
    let second_factor = all.iter().any(|argument| argument == "--second-factor");
    // `--profiles X` takes a value, so it is read from the FULL argument list by position after the
    // flag rather than from the positionals — which the filter above has already had it removed
    // from, along with its value.
    let profiles = match all.iter().position(|argument| argument == "--profiles") {
        None => Profiles::None,
        Some(at) => match all.get(at + 1).and_then(|named| Profiles::named(named)) {
            Some(fixture) => fixture,
            None => refuse("--profiles needs one of: none two hidden switched"),
        },
    };

    // A chain write to photograph (dig_ecosystem#2995). Published to the app's own feed, which is
    // where the shell reads it from, so the picture is the real surface rather than a mock of it.
    if let Some(at) = all.iter().position(|argument| argument == "--transaction") {
        match all.get(at + 1).map(String::as_str) {
            Some(named) => match transaction_fixture(named) {
                Some(fixture) => dig_app_core::transaction::Feed::app().publish(fixture),
                None => {
                    refuse("--transaction needs one of: building pushed halfway confirmed failed")
                }
            },
            None => refuse("--transaction needs one of: building pushed halfway confirmed failed"),
        }
    }

    // The profile editor's fixture (dig_ecosystem#2993). The pane reads the profile through
    // `EditService::app()`, so photographing its states means installing a service that answers the
    // way the state under test does — a filled profile, an empty one, or a read that failed.
    let editing = match all.iter().position(|argument| argument == "--profile-edit") {
        None => dig_app_core::profile_edit::ProfileEditing::default(),
        Some(at) => match all
            .get(at + 1)
            .map(String::as_str)
            .map(install_edit_fixture)
        {
            Some(Some(offer)) => offer,
            _ => refuse("--profile-edit needs one of: filled empty unreadable locked"),
        },
    };

    // A live capture takes its readings ONCE, before the window opens, so every frame of the
    // capture shows the same instant — and so a node that is not there stops the run here, with no
    // file written, rather than being papered over by the fixture the closure would otherwise build.
    let live = match all.iter().any(|argument| argument == "--live") {
        false => None,
        true => match live_readings() {
            Ok(readings) => Some(readings),
            Err(problem) => refuse(&format!("--live was asked for but {problem}")),
        },
    };

    let view = Arc::new(move || {
        let mut fixture = view_for(account.clone(), second_factor, profiles);
        // Applied over the fixture rather than threaded through `view_for`, so every other axis of
        // the gallery keeps the signature it had.
        fixture.profile_editing = editing;
        match &live {
            None => fixture,
            Some(readings) => with_live(fixture, readings),
        }
    });
    match photograph_shell(
        theme,
        tab,
        egui::Vec2::new(width, height),
        view,
        std::path::Path::new(path),
    ) {
        Ok((pixels_wide, pixels_high)) => println!("{path} — {pixels_wide} x {pixels_high} px"),
        Err(problem) => {
            eprintln!("{path} was not written: {problem}");
            std::process::exit(1);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use dig_app_core::hosted_stores::{HostedStore, HostedStoresUnknown};

    /// One store, so a `Known` reading under test is a list rather than an empty one.
    fn one_store() -> Vec<HostedStore> {
        vec![HostedStore {
            store_id: "ab".repeat(32),
            pinned: true,
            capsule_count: 2,
            total_bytes: 4_096,
        }]
    }

    fn some_facts() -> NodeFacts {
        NodeFacts {
            version: "0.99.10".to_string(),
            commit: "abcdef0".to_string(),
            protocol: "1".to_string(),
            addr: "127.0.0.1:9778".to_string(),
            upstream: "https://rpc.dig.net".to_string(),
            uptime_minutes: 42,
            sync_available: true,
            // Deliberately NOT the fixture summary's `1 store(s) hosted`: a live capture that left
            // the summary alone would then state the same quantity twice and differently, and
            // `a_live_capture_does_not_state_the_store_count_twice_and_differently` is blind to that
            // unless the two numbers differ.
            hosted_store_count: 3,
            cached_capsule_count: 3,
            pinned_store_count: 2,
        }
    }

    /// **The refusal rule.** A `--live` capture may only be written when the NODE ITSELF answered
    /// the store read — whatever it answered. Every reading that means "nobody answered" is refused,
    /// including the empty-looking [`HostedStoresReading::Pending`], because a picture taken from
    /// one would be labelled live while showing nothing the node said.
    ///
    /// The unknowns are split rather than lumped: `NodeCannotRead`, `Unauthorized` and `ReadFailed`
    /// are the node's OWN words on a node that is demonstrably reachable, so they are honest live
    /// readings and the pane must be photographable in them. `NoNode`, `Unreachable` and `TimedOut`
    /// are the absence of an answer.
    #[test]
    fn only_a_reading_the_node_itself_produced_counts_as_live() {
        for silent in [
            HostedStoresReading::Pending,
            HostedStoresReading::Unknown(HostedStoresUnknown::NoNode),
            HostedStoresReading::Unknown(HostedStoresUnknown::Unreachable("refused".into())),
            HostedStoresReading::Unknown(HostedStoresUnknown::TimedOut("10s".into())),
        ] {
            assert!(
                !answered(&silent),
                "{silent:?} is the absence of an answer, and a picture taken from it would be \
                 labelled live while showing nothing the node said"
            );
        }
        for spoken in [
            HostedStoresReading::Known(Vec::new()),
            HostedStoresReading::Known(one_store()),
            HostedStoresReading::Unknown(HostedStoresUnknown::NodeCannotRead),
            HostedStoresReading::Unknown(HostedStoresUnknown::Unauthorized),
            HostedStoresReading::Unknown(HostedStoresUnknown::ReadFailed("fell over".into())),
        ] {
            assert!(
                answered(&spoken),
                "{spoken:?} is what a reachable node said, so the pane must be photographable in it"
            );
        }
    }

    /// The four readings a live capture carries, all differing from the fixture's.
    fn readings() -> NodeReadings {
        NodeReadings {
            summary: "Node v0.103.0 · 3 capsule(s) cached · 3 store(s) hosted".to_string(),
            cache: Some(CacheSnapshot {
                cap_bytes: GIB,
                used_bytes: 388 * MIB,
            }),
            facts: Some(some_facts()),
            stores: HostedStoresReading::Known(one_store()),
            standing: NetworkStanding {
                sync: ChainSync::Syncing {
                    peak_height: 5_999_001,
                },
                dig_peers: PeerCount::Known(2),
                chia_peers: PeerCount::Known(3),
                // Well above the replica's own, which is what SYNCING means: the peers have told
                // this node where the chain is, and it has not copied that far yet.
                chia_peer_peak_height: Some(6_012_340),
                // A wallet IS enrolled, which is what makes the trailing heights above mean
                // anything: with an empty subscription the node never syncs at all and the honest
                // reading is "Nothing to sync", not a distance (dig_ecosystem#2820).
                watched_addresses: Some(2),
            },
        }
    }

    /// **`--live` varies the node's readings and NOTHING else**, so a live capture differs from its
    /// fixture counterpart only in what the node reported.
    ///
    /// Proven by a round trip rather than by listing the fields that must not move: putting the
    /// base's own readings back must restore the base exactly. The comparison is
    /// [`TrayView::renders_same_as`], which destructures with no `..` — so a field this harness
    /// starts overwriting cannot escape it, which a hand-written list of assertions could.
    #[test]
    fn live_readings_replace_the_node_fields_and_leave_the_rest_alone() {
        let base = view_for(
            AccountState::Unlocked { recoverable: true },
            false,
            Profiles::None,
        );
        let live = with_live(base.clone(), &readings());

        assert_eq!(live.node, readings().summary);
        assert_eq!(live.cache, readings().cache);
        assert_eq!(live.node_facts, Some(some_facts()));
        assert_eq!(
            live.hosted_stores,
            HostedStoresReading::Known(one_store()),
            "the node's list must reach the view it is photographed from"
        );
        assert_eq!(
            live.network,
            readings().standing,
            "the node's own peer counts must reach the strip the picture shows"
        );
        assert_ne!(
            live.network, base.network,
            "the fixture and the live standing are identical, so this proves nothing"
        );
        // The control: with the base's own readings restored, nothing else moved.
        let restored = with_live(
            live,
            &NodeReadings {
                summary: base.node.clone(),
                cache: base.cache,
                facts: base.node_facts.clone(),
                stores: base.hosted_stores.clone(),
                standing: base.network.clone(),
            },
        );
        assert!(
            restored.renders_same_as(&base),
            "a live capture must differ from its fixture counterpart in the node's readings alone"
        );
    }

    /// **The defect this pass exists to fix.** A live capture must not put the FIXTURE's summary
    /// sentence — which states a hosted-store count — above a live sharing card that states the same
    /// quantity from the node. The first cut of `--live` did exactly that and photographed `1
    /// store(s) hosted` above `3 stores`.
    ///
    /// The fixture is built so the nearest wrong implementation — the one that leaves `node` alone —
    /// cannot pass: the node's own count (3) differs from the count in the fixture's summary (1), so
    /// a summary left untouched leaves the picture stating both.
    #[test]
    fn a_live_capture_does_not_state_the_store_count_twice_and_differently() {
        let fixture = view_for(
            AccountState::Unlocked { recoverable: true },
            false,
            Profiles::None,
        );
        assert!(
            fixture.node.contains("1 store(s) hosted"),
            "this test is only meaningful while the fixture states a DIFFERENT count from the \
             node's: {}",
            fixture.node
        );

        let live = with_live(fixture, &readings());
        let hosted = live
            .node_facts
            .as_ref()
            .expect("live facts")
            .hosted_store_count;

        assert!(
            live.node.contains(&format!("{hosted} store(s) hosted")),
            "the sentence above the sharing card must carry the node's own hosted-store count: {}",
            live.node
        );
        assert!(
            !live.node.contains("1 store(s) hosted"),
            "the fixture's count survived into a live capture, so the image states the same \
             quantity twice and differently: {}",
            live.node
        );
    }
}
