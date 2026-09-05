//! The mirror advertise-URL override: what this node is about to publish, and letting a person
//! change it (dig-app#387).
//!
//! # What this is a control over, and what it is not
//!
//! dig-node#562 gave every node a DERIVED default: its own discovered public address and
//! content-serving port. `DIG_MIRROR_ADVERTISE_URLS` let an operator override that default, but
//! only from an environment variable — set inside a Windows service's registry environment, in a
//! format documented nowhere a person setting it up would find. This module is the surface: read
//! what the node is about to publish, and let a person change it, without dig-app ever computing
//! an address itself.
//!
//! # Three requests this module can make, and why an empty list is not one of them
//!
//! [`write()`] sends `Some(vec![typed])` to SET an override, or `None` to CLEAR it back to the
//! derived default — it never sends `Some(vec![])`. `SetMirrorAdvertiseUrlsParams` itself refuses
//! an explicit empty list as `-32602 INVALID_PARAMS`, because that is genuinely ambiguous between
//! "advertise nothing" and "go back to automatic", and guessing wrong either forfeits a reward this
//! node could have earned or silently overrides a deliberate choice to stop advertising. So the
//! "use the automatic address" affordance this module exists for is `write(endpoint, None, ..)`,
//! never a blanked field saved as typed text.
//!
//! # This never validates routability, on purpose
//!
//! dig-node#562 established a deliberate asymmetry: an OPERATOR's LAN or private address is a
//! legitimate, deliberate choice risking only their own mirror stake, while the SAME address
//! DERIVED automatically is a broken reading of this node's own network position. [`looks_like_a_url`]
//! checks only that the input parses as an absolute URL with a scheme and a host — the same check
//! `SetMirrorAdvertiseUrlsParams::validated` performs node-side — and nothing stricter. A
//! well-meaning validator here would look like a safety improvement and would silently break every
//! LAN-only deployment instead.
//!
//! # Six named states, because an empty list alone cannot say why
//!
//! [`MirrorAdvertiseState`] is rendered directly rather than re-derived, because the four ways of
//! publishing nothing (switched off, no address yet, one uncorroborated source, no relay path) have
//! four different remedies and a bare empty [`AdvertiseInfo::urls`] cannot tell them apart. The one
//! that most needs care in the surface that renders it is
//! [`MirrorAdvertiseState::UncorroboratedAddress`]: that is the node correctly declining to publish
//! an address only one source has vouched for. It is not a fault, and typing a manual override does
//! not "fix" it — it replaces the derivation with a choice, which is a different act.
//!
//! # `requires_restart` must be rendered, never assumed
//!
//! [`AdvertiseApplied::requires_restart`] is the node's own report of whether
//! [`AdvertiseApplied::info`] is live yet or needs a restart to take effect. **Verified against
//! the serving code, not just the published doc**: dig-node's mirror-lifecycle task reads this
//! override exactly once at start-up, before its run loop
//! (`dig-node-service/src/server.rs:2768-2776`, dig-node#569), so a write DOES persist to
//! `config.json` but a running process has no way to observe it — the field answers `true`
//! unconditionally on every node running this code. A caller that assumed "saved" meant "live"
//! would tell an operator their node is advertising a URL it is not, while a second one that
//! hard-coded `true` here would break the day dig-node re-reads this live, without any contract
//! version change to signal it. Render whichever value the node actually sends, always.
//!
//! # A node too old to answer is one state, reached two ways
//!
//! A node that predates dig-node-control-interface 0.33.0 refuses
//! `control.config.setMirrorAdvertiseUrls` outright (`-32601 METHOD_NOT_FOUND`). A node that
//! predates dig-node#562 entirely still answers `control.config.get` — that method is not new — but
//! its `ConfigResult` carries no `mirror_advertise` field at all, which decodes to `None` rather
//! than failing the whole call (see `ConfigResult::mirror_advertise`'s own doc). Both land on
//! [`AdvertiseUnknown::NotSupported`], because both have the same remedy: update the node.
//!
//! # Nothing here re-derives an address
//!
//! Exactly the discipline [`crate::wallet::machine`] states for the operator wallet address: the
//! node is the one process that can discover, corroborate, and route to itself. This module only
//! asks, and relays back exactly what was asked for.

use std::time::Duration;

use dig_node_control_interface::error::ControlErrorCode;
use dig_node_control_interface::params::{ConfigGetParams, SetMirrorAdvertiseUrlsParams};
pub use dig_node_control_interface::results::MirrorAdvertiseState;
use dig_node_control_interface::results::{
    ConfigResult, MirrorAdvertiseView, SetMirrorAdvertiseUrlsResult,
};

use crate::activity::absence::ControlAbsence;
use crate::control::{self, ControlFailure};

/// How long a mirror-advertise read or write may take before it is abandoned.
///
/// This runs on the UI thread in response to a press or a pane load, the same constraint the
/// collateral margin read/write budget is chosen under: short enough that a stalled node cannot
/// freeze the pane, long enough that a busy local node still answers.
pub const ADVERTISE_TIMEOUT: Duration = Duration::from_secs(3);

/// What this node will publish, and whether that is the operator's choice or the derived default.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdvertiseInfo {
    /// The URLs this node will actually publish in its NEXT mirror-coin advertisement. Empty in
    /// every state but [`MirrorAdvertiseState::AdvertisingOverride`] and
    /// [`MirrorAdvertiseState::AdvertisingDerived`] — [`Self::state`] is why an empty list alone
    /// never says which.
    pub urls: Vec<String>,
    /// The operator's own persisted override, verbatim, or `None` when unset. `Some` even in
    /// [`MirrorAdvertiseState::Off`], where the override exists but nothing in it is publishable —
    /// so a caller can say "publishing your own address" versus "publishing the derived default"
    /// without inferring it from [`Self::state`] alone.
    pub operator_override: Option<Vec<String>>,
    /// Which of dig-node#562's six outcomes produced [`Self::urls`] this pass.
    pub state: MirrorAdvertiseState,
}

impl AdvertiseInfo {
    /// Carry the node's view across unchanged — nothing here recomputes any of it.
    fn of_wire(view: MirrorAdvertiseView) -> Self {
        Self {
            urls: view.urls,
            operator_override: view.operator_override,
            state: view.state,
        }
    }
}

/// What the app can honestly say about the node's mirror advertise-URL override.
///
/// Three states for the reason every node-backed reading in this app carries three: a read in
/// flight is not a fault, and a fault is not an absence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AdvertiseReading {
    /// A read is under way and nothing has failed.
    Pending,
    /// The node reported what it is about to publish.
    Known(AdvertiseInfo),
    /// Nothing could be read, and why.
    Unknown(AdvertiseUnknown),
}

impl Default for AdvertiseReading {
    /// Before anything has been asked, the reading is [`Pending`](Self::Pending) — not
    /// [`AdvertiseUnknown::NoNode`], which is a conclusion about a read that has not happened yet.
    fn default() -> Self {
        Self::Pending
    }
}

impl AdvertiseReading {
    /// The info, when there is some.
    pub fn info(&self) -> Option<&AdvertiseInfo> {
        match self {
            Self::Known(info) => Some(info),
            Self::Pending | Self::Unknown(_) => None,
        }
    }
}

/// Why no mirror-advertise reading is available. **One variant per remedy.**
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AdvertiseUnknown {
    /// Nothing answered the control-path endpoint ladder, so there is nothing to ask.
    NoNode,
    /// A node answered and is too old to know about a mirror advertise-URL override — see the
    /// module doc for the two different ways that happens. Not a fault on this machine; the remedy
    /// is a node update.
    NotSupported,
    /// The node refused the call — typically no valid control token on this machine.
    Refused,
    /// The node answered with something this app could not read.
    Unreadable,
    /// The node reached the method and refused the URL(s) sent, quoted verbatim because the node's
    /// own words are more use to whoever is typing than a category invented here.
    ///
    /// Reachable only from [`write()`]: a read sends no input the node could refuse.
    Rejected(String),
}

impl From<ControlAbsence> for AdvertiseUnknown {
    /// The shared control-failure taxonomy, in this surface's words.
    ///
    /// Exhaustive with **no wildcard arm**: a fifth absence must be a build error here rather than
    /// folding silently into whichever neighbour a `_ =>` happened to point at.
    fn from(absence: ControlAbsence) -> Self {
        match absence {
            ControlAbsence::NoNode => Self::NoNode,
            ControlAbsence::NotSupported => Self::NotSupported,
            ControlAbsence::Refused => Self::Refused,
            ControlAbsence::Unreadable => Self::Unreadable,
        }
    }
}

impl AdvertiseUnknown {
    /// What the pane says, naming the remedy rather than the fault.
    pub fn remedy(&self) -> String {
        match self {
            Self::NoNode => {
                "DIG is not connected to a node, so there is nothing to ask.".to_string()
            }
            // `concat!` rather than a `\`-continued literal: each piece is a complete string on
            // its own line, so there is no continuation for a formatter to collapse into a run of
            // literal spaces (dig-app#201 shipped that exact damage from the other shape).
            Self::NotSupported => concat!(
                "This node is too old to have a mirror advertise setting. ",
                "Update it to read or set one.",
            )
            .to_string(),
            Self::Refused => concat!(
                "Your node refused DIG's request. ",
                "Its control token is the thing to check.",
            )
            .to_string(),
            Self::Unreadable => "Your node answered with something DIG could not read.".to_string(),
            Self::Rejected(said) => format!("Your node refused that address: {said}"),
        }
    }
}

/// Ask the node what it will publish next, and whether that is chosen or derived.
pub fn read(endpoint: Option<&str>, token: Option<&str>, timeout: Duration) -> AdvertiseReading {
    let Some(endpoint) = endpoint else {
        return AdvertiseReading::Unknown(AdvertiseUnknown::NoNode);
    };
    match control::call_control_result(endpoint, &ConfigGetParams {}, token, timeout) {
        Ok(config) => reading_of_config(config),
        Err(failure) => AdvertiseReading::Unknown(ControlAbsence::of(&failure).into()),
    }
}

/// The pure half of [`read`]'s success path, split out so the field-absence case is testable
/// without a socket.
fn reading_of_config(config: ConfigResult) -> AdvertiseReading {
    match config.mirror_advertise {
        Some(view) => AdvertiseReading::Known(AdvertiseInfo::of_wire(view)),
        // A node old enough to answer `config.get` but built before dig-node#562 existed — see
        // `ConfigResult::mirror_advertise`'s own doc on why this decodes to `None` rather than
        // failing the whole call.
        None => AdvertiseReading::Unknown(AdvertiseUnknown::NotSupported),
    }
}

/// What happened when dig-app asked the node to change what it advertises.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AdvertiseWriteReading {
    /// The node applied the change (or the clear) and reports what it holds now.
    Applied(AdvertiseApplied),
    /// The write could not be completed, and why.
    Unknown(AdvertiseUnknown),
}

/// What the node applied, and whether it is live yet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdvertiseApplied {
    /// What a follow-up read will show once this takes effect.
    pub info: AdvertiseInfo,
    /// Whether the node must be restarted before [`Self::info`] is the answer a live read would
    /// give. **Render this** — see the module doc for why it is not safe to assume either value.
    pub requires_restart: bool,
}

/// Set the node's mirror advertise-URL override to `urls`, or clear it back to automatic with
/// `None`.
///
/// `urls` must never be `Some(vec![])` — build it from a [`looks_like_a_url`]-checked, non-empty
/// typed value, or pass `None` to clear. The "use the automatic address" affordance is
/// `write(endpoint, None, ..)`, never a blanked field saved as typed text (see the module doc).
///
/// The returned [`AdvertiseApplied`] is the node's OWN answer, never an echo of the request — the
/// same read-back discipline [`crate::collateral::node::write_margin`] follows, and for the same
/// reason: a write that was refused or landed differently than typed must never leave the pane
/// showing what was clicked instead of what the node holds.
pub fn write(
    endpoint: Option<&str>,
    urls: Option<Vec<String>>,
    token: Option<&str>,
    timeout: Duration,
) -> AdvertiseWriteReading {
    let Some(endpoint) = endpoint else {
        return AdvertiseWriteReading::Unknown(AdvertiseUnknown::NoNode);
    };
    let params = SetMirrorAdvertiseUrlsParams { urls };
    outcome_of(control::call_control_result(
        endpoint, &params, token, timeout,
    ))
}

/// The pure half of [`write()`], split out so every outcome is testable without a socket.
fn outcome_of(
    result: Result<SetMirrorAdvertiseUrlsResult, ControlFailure>,
) -> AdvertiseWriteReading {
    match result {
        Ok(result) => AdvertiseWriteReading::Applied(AdvertiseApplied {
            info: AdvertiseInfo::of_wire(result.mirror_advertise),
            requires_restart: result.requires_restart,
        }),
        // The node reached the handler and refused the input on its merits — a real answer to
        // branch on, distinct from every absence `ControlAbsence` buckets. Keyed on the stable
        // UPPER_SNAKE symbol, never the message, for the same reason every other classification in
        // this app is.
        Err(ControlFailure::Rejected(error))
            if error.data.code == ControlErrorCode::InvalidParams.name() =>
        {
            AdvertiseWriteReading::Unknown(AdvertiseUnknown::Rejected(error.message))
        }
        Err(failure) => AdvertiseWriteReading::Unknown(ControlAbsence::of(&failure).into()),
    }
}

/// Whether `typed` is something the node could publish as an absolute URL.
///
/// Deliberately shallow, and deliberately the SAME check the contract's own
/// `SetMirrorAdvertiseUrlsParams::validated` performs node-side: a scheme and a host, nothing about
/// whether the address is routable or private. See the module doc for why a stricter check here
/// would be a regression wearing a safety improvement's clothes.
///
/// Never called with a blank string — clearing the override is a different request
/// ([`write()`] with `None`), not a value this checks.
pub fn looks_like_a_url(typed: &str) -> Result<(), &'static str> {
    if typed.split_whitespace().count() != 1 {
        return Err("A mirror advertise URL is one word, with no spaces in it.");
    }
    match typed.split_once("://") {
        Some((scheme, rest)) if !scheme.is_empty() && !rest.trim_matches('/').is_empty() => Ok(()),
        _ => Err("This needs a scheme and a host, for example dig://203.0.113.5:9776."),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use dig_node_control_interface::error::{ControlError, ControlErrorData};

    /// This module's own source, read at compile time — the same mechanism
    /// `confirm::gui::window::pane::copy`'s whitespace guard uses, so a `\` continuation lost by a
    /// formatter is caught here too rather than only in files that copy already scans.
    const OWN_SOURCE: &str = include_str!("mirror_advertise.rs");

    /// **No literal in this file carries a run of spaces from a lost `\` continuation.**
    ///
    /// `remedy()` wraps its longer sentences across lines with a trailing `\`; `cargo fmt` has
    /// collapsed exactly this shape into a run of literal spaces elsewhere in this app (dig-app#201,
    /// `copy.rs::no_shipping_literal_carries_a_space_run`) and `cargo fmt --check` is satisfied by
    /// the damage, because the formatter produced it. Copied verbatim rather than referenced: this
    /// file is not part of `copy`'s enumeration, so its own literals were invisible to that guard
    /// until this one existed.
    #[test]
    fn no_shipping_literal_carries_a_space_run() {
        let mut damaged: Vec<String> = Vec::new();
        for (ix, line) in OWN_SOURCE.lines().enumerate() {
            if line == "#[cfg(test)]" {
                break;
            }
            let trimmed = line.trim_start();
            if trimmed.starts_with("//") || !line.contains('"') {
                continue;
            }
            let mut seen_text = false;
            let mut run = 0usize;
            for ch in line.chars() {
                if ch == ' ' {
                    if seen_text {
                        run += 1;
                    }
                    continue;
                }
                if seen_text && run >= 4 {
                    damaged.push(format!("line {}: {}", ix + 1, line.trim()));
                    break;
                }
                seen_text = true;
                run = 0;
            }
        }
        assert!(
            damaged.is_empty(),
            "a literal carries a run of 4+ spaces mid-sentence, which reaches the screen verbatim: \
             {damaged:#?}"
        );
    }

    /// A `ConfigResult` carrying `mirror_advertise`, with every other field a plausible constant —
    /// this module does not look at them, and a test that omitted them would prove nothing about
    /// this field either way.
    fn config_with(mirror_advertise: Option<MirrorAdvertiseView>) -> ConfigResult {
        ConfigResult {
            addr: "127.0.0.1:9778".to_string(),
            port: "9778".to_string(),
            upstream: "https://rpc.dig.net".to_string(),
            upstream_override: None,
            cache_dir: "C:/ProgramData/DigNode/cache".to_string(),
            cache_shared: true,
            config_path: "C:/ProgramData/DigNode/config.json".to_string(),
            sync_available: true,
            mirror_advertise,
        }
    }

    fn view(state: MirrorAdvertiseState, urls: &[&str]) -> MirrorAdvertiseView {
        MirrorAdvertiseView {
            urls: urls.iter().map(|u| u.to_string()).collect(),
            operator_override: None,
            state,
        }
    }

    /// A rejection carrying `code` in its stable symbol slot, the shape a real node sends.
    fn rejected(code: &str, message: &str) -> ControlFailure {
        ControlFailure::Rejected(ControlError {
            code: -1,
            message: message.to_string(),
            data: ControlErrorData {
                code: code.to_string(),
                origin: "node".to_string(),
            },
        })
    }

    // -- read: the field-absence case, and the ordinary case -----------------------------------

    /// **A node too old to know about dig-node#562 is `NotSupported`, not a decode failure.**
    ///
    /// The fixture is a config `mirror_advertise: None` — a call that SUCCEEDED, which is the
    /// property that distinguishes this from every `ControlAbsence` case: nothing was refused,
    /// nothing timed out, the node simply predates the field. A version that mapped this to
    /// `Unreadable` would send an operator to check their control token over a node that answered
    /// perfectly well.
    #[test]
    fn a_node_missing_the_field_entirely_is_not_supported_not_unreadable() {
        let reading = reading_of_config(config_with(None));
        assert_eq!(
            reading,
            AdvertiseReading::Unknown(AdvertiseUnknown::NotSupported)
        );
    }

    /// **A known view is carried through unchanged — the address a person reads is the node's own
    /// words.**
    #[test]
    fn a_known_view_is_carried_verbatim() {
        let reading = reading_of_config(config_with(Some(view(
            MirrorAdvertiseState::AdvertisingDerived,
            &["dig://203.0.113.5:9776"],
        ))));
        assert_eq!(
            reading,
            AdvertiseReading::Known(AdvertiseInfo {
                urls: vec!["dig://203.0.113.5:9776".to_string()],
                operator_override: None,
                state: MirrorAdvertiseState::AdvertisingDerived,
            })
        );
    }

    /// With no endpoint nothing was asked, and an unasked question has no answer.
    #[test]
    fn no_endpoint_is_no_node_rather_than_a_missing_reading() {
        assert_eq!(
            read(None, None, ADVERTISE_TIMEOUT),
            AdvertiseReading::Unknown(AdvertiseUnknown::NoNode)
        );
        assert_eq!(
            write(None, None, None, ADVERTISE_TIMEOUT),
            AdvertiseWriteReading::Unknown(AdvertiseUnknown::NoNode)
        );
    }

    /// **Every `ControlAbsence` survives into this surface's own words, distinctly.**
    ///
    /// Asserted pairwise rather than only against its intended arm, because the failure this
    /// guards against is a fold into a NEIGHBOUR — an assertion that only checks the right variant
    /// passes just as happily when a different absence lands there too.
    #[test]
    fn every_control_absence_lands_on_its_own_reading() {
        let all = [
            ControlAbsence::NoNode,
            ControlAbsence::NotSupported,
            ControlAbsence::Refused,
            ControlAbsence::Unreadable,
        ];
        let mapped: Vec<AdvertiseUnknown> = all.into_iter().map(AdvertiseUnknown::from).collect();
        for (i, left) in mapped.iter().enumerate() {
            for right in &mapped[i + 1..] {
                assert_ne!(left, right, "two absences collapsed into one reading");
            }
        }
        assert_eq!(mapped[0], AdvertiseUnknown::NoNode);
        assert_eq!(mapped[1], AdvertiseUnknown::NotSupported);
        assert_eq!(mapped[2], AdvertiseUnknown::Refused);
        assert_eq!(mapped[3], AdvertiseUnknown::Unreadable);
    }

    // -- write: applied, requires_restart both ways, and the refusal paths ---------------------

    /// **A successful write is read back from the node's own answer, requires_restart included.**
    ///
    /// Both values of `requires_restart` are asserted from the SAME `Applied` construction, so a
    /// version that hard-coded either one — the trap the module doc names — fails here rather than
    /// only in a manual check against a node nobody automates yet.
    #[test]
    fn a_successful_write_carries_the_nodes_own_requires_restart_both_ways() {
        for requires_restart in [true, false] {
            let outcome = outcome_of(Ok(SetMirrorAdvertiseUrlsResult {
                mirror_advertise: view(
                    MirrorAdvertiseState::AdvertisingOverride,
                    &["dig://198.51.100.9:9776"],
                ),
                requires_restart,
            }));
            let AdvertiseWriteReading::Applied(applied) = outcome else {
                panic!("a successful call is Applied");
            };
            assert_eq!(applied.requires_restart, requires_restart);
            assert_eq!(
                applied.info.state,
                MirrorAdvertiseState::AdvertisingOverride
            );
        }
    }

    /// **An explicit refusal (INVALID_PARAMS) is `Rejected`, quoting the node — never folded into
    /// `Unreadable`.**
    ///
    /// `Unreadable` means DIG could not interpret the answer; a node that refused the input on its
    /// merits interpreted the request just fine and said so. Collapsing the two would send a person
    /// to distrust their connection over a URL they mistyped.
    #[test]
    fn an_invalid_params_refusal_is_rejected_not_unreadable() {
        let outcome = outcome_of(Err(rejected(
            "INVALID_PARAMS",
            "\"ftp://x\" is not a well-formed absolute URL",
        )));
        let AdvertiseWriteReading::Unknown(AdvertiseUnknown::Rejected(said)) = outcome else {
            panic!("an INVALID_PARAMS refusal is Rejected: {outcome:?}");
        };
        assert!(said.contains("well-formed"), "the node's own words: {said}");
    }

    /// A node too old to serve the write at all refuses as `METHOD_NOT_FOUND`, which is
    /// `NotSupported` — the SAME reading a pre-#562 `config.get` produces, because both have the
    /// same remedy.
    #[test]
    fn a_node_without_the_write_method_is_not_supported() {
        let outcome = outcome_of(Err(rejected(ControlErrorCode::MethodNotFound.name(), "no")));
        assert_eq!(
            outcome,
            AdvertiseWriteReading::Unknown(AdvertiseUnknown::NotSupported)
        );
    }

    // -- looks_like_a_url: accepts what the node accepts, rejects only what is certainly wrong --

    /// **A LAN or private address is ACCEPTED — the node's own asymmetry, and the one this check
    /// must not silently narrow.**
    ///
    /// This is the constraint the ticket calls out by name: an operator's LAN address is a
    /// deliberate, legitimate choice, and a validator that rejected it would look like a safety
    /// improvement while breaking a supported configuration.
    #[test]
    fn a_lan_address_is_accepted_not_rejected() {
        assert!(looks_like_a_url("http://192.168.1.5:9776").is_ok());
        assert!(looks_like_a_url("dig://10.0.0.7:9776").is_ok());
    }

    /// The exact wire example the contract's own conformance KAT pins is accepted here too, so this
    /// check and the node's never disagree about the one string both sides already test against.
    #[test]
    fn the_contracts_own_ipv6_example_is_accepted() {
        assert!(looks_like_a_url("dig://[2001:db8::7]:9776").is_ok());
    }

    /// The certainly-wrong cases: no scheme, no host, and more than one word.
    #[test]
    fn inputs_with_no_scheme_or_no_host_are_refused() {
        for bad in ["not-a-url", "http://", "two words here", "://noscheme"] {
            assert!(looks_like_a_url(bad).is_err(), "{bad:?} should be refused");
        }
    }
}
