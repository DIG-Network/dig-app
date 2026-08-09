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

use dig_app_core::cache::{CacheSnapshot, GIB, MIB};
use dig_app_core::confirm::gui::{photograph_shell, Theme};
use dig_app_core::engine::{EngineConnector, EngineState, NodeConnector};
use dig_app_core::hosted_stores::{
    HostedStoresReading, HostedStoresUnknown, NodeHostedStores, REFRESH_INTERVAL,
    STORES_READ_TIMEOUT,
};
use dig_app_core::node_facts::NodeFacts;
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
fn view_for(account: AccountState, second_factor: bool) -> TrayView {
    let sealed = !matches!(account, AccountState::Unlocked { .. });
    TrayView {
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
            false => BalanceReading::Known(HELD),
        },
        second_factor,
        window_host: WindowHost::Available,
        cache: Some(CacheSnapshot {
            cap_bytes: GIB,
            used_bytes: 350 * MIB,
        }),
        ..TrayView::default()
    }
}

/// `view` with the two fields the node supplies replaced, and every other field untouched.
///
/// Split out from the reading itself so what `--live` VARIES is one function with no node in it:
/// the capture must differ from its fixture counterpart in what the node reported and nothing else,
/// and `live_readings_replace_the_two_node_fields_and_leave_the_rest_alone` pins that here.
fn with_live(
    view: TrayView,
    node_facts: Option<NodeFacts>,
    hosted_stores: HostedStoresReading,
) -> TrayView {
    TrayView {
        node_facts,
        hosted_stores,
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

/// The two readings a live capture needs, taken from the running node — or the reason there are
/// none.
///
/// The node is found the way the application finds it: [`NodeConnector`] walking the §5.3 ladder,
/// rather than a second client invented here with its own idea of where a node lives. Only
/// `control.status` and `control.hostedStores.list` are called, so this reads a node and reaches no
/// key, wallet or chain — the standing constraint on this file.
///
/// **There is no fallback.** Every branch that cannot produce a reading returns an error naming what
/// did not answer, and the caller writes no file.
fn live_readings() -> Result<(NodeFacts, HostedStoresReading), String> {
    let link = NodeConnector::default().probe("");
    let EngineState::Connected { .. } = &link else {
        return Err(format!(
            "no node answered control.status, so there is nothing live to photograph — {}",
            link.summary()
        ));
    };
    let status = link.status().expect("a connected link carries its status");
    let facts = NodeFacts::of_status(status);

    let poller = NodeHostedStores::new(REFRESH_INTERVAL, STORES_READ_TIMEOUT);
    let deadline = Instant::now() + LIVE_WAIT;
    loop {
        let reading = poller.observe(&link);
        if answered(&reading) {
            return Ok((facts, reading));
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
            hosted_store_count: 1,
            cached_capsule_count: 2,
            pinned_store_count: 1,
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

    /// **`--live` varies the node's two readings and NOTHING else**, so a live capture differs from
    /// its fixture counterpart only in what the node reported.
    ///
    /// Proven by a round trip rather than by listing the fields that must not move: putting the
    /// base's own readings back must restore the base exactly. The comparison is
    /// [`TrayView::renders_same_as`], which destructures with no `..` — so a field this harness
    /// starts overwriting cannot escape it, which a hand-written list of assertions could.
    #[test]
    fn live_readings_replace_the_two_node_fields_and_leave_the_rest_alone() {
        let base = view_for(AccountState::Unlocked { recoverable: true }, false);
        let live = with_live(
            view_for(AccountState::Unlocked { recoverable: true }, false),
            Some(some_facts()),
            HostedStoresReading::Known(one_store()),
        );

        assert_eq!(live.node_facts, Some(some_facts()));
        assert_eq!(
            live.hosted_stores,
            HostedStoresReading::Known(one_store()),
            "the node's list must reach the view it is photographed from"
        );
        // The control: with the base's own readings restored, nothing else moved.
        let restored = with_live(live, base.node_facts.clone(), base.hosted_stores.clone());
        assert!(
            restored.renders_same_as(&base),
            "a live capture must differ from its fixture counterpart in the node's readings alone"
        );
    }
}

fn main() {
    let all: Vec<String> = std::env::args().skip(1).collect();
    // Flags are taken out before the positionals are read, so `--second-factor` cannot shift the
    // output path along by one. It did exactly that once, and the picture landed in a file named
    // for the flag -- a gallery is only as trustworthy as the name on each file.
    let args: Vec<&String> = all
        .iter()
        .filter(|argument| !argument.starts_with("--"))
        .collect();
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
        let fixture = view_for(account.clone(), second_factor);
        match &live {
            None => fixture,
            Some((facts, stores)) => with_live(fixture, Some(facts.clone()), stores.clone()),
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
