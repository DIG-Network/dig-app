//! The two things a person does with WalletConnect from the tray: connect an app, and manage the
//! apps already connected.
//!
//! Written as pure logic over the [`NativeConfirmer`] seam, exactly as [`crate::paired_apps`] is and
//! for the same reason: these are the decisions worth testing, and none of them should need a real
//! window, an unlocked account, or a relay to exercise.
//!
//! # Why the person always starts the connection
//!
//! Both journeys are reachable ONLY from the tray menu. Nothing a dapp or a relay can send puts a
//! window in front of somebody — a session proposal is only ever read after a human has pasted the
//! pairing string that invited it. That is what makes a mis-click impossible to provoke remotely,
//! and it is the same property that makes [`crate::paired_apps`] safe.
//!
//! # Why every window here can be closed
//!
//! `professional-ui`'s first hard rule. Cancelling closes, from any page, in both journeys — and the
//! empty-list case still draws a window that says the list is empty and names how to add to it,
//! rather than closing onto silence and leaving a person unsure whether the menu item worked.

use crate::confirm::{
    ClaimPrompt, ConfirmDecision, InputOutcome, InputPrompt, InputStyle, NativeConfirmer,
    NoticePrompt,
};

use super::request::SUPPORTED_METHODS;
use super::session::{DappMetadata, DisconnectOutcome, WcSession};
use super::uri::{UriError, WcUri};

/// How many sessions one management page lists.
///
/// Three, matching [`crate::paired_apps::APPS_PER_PAGE`], and for the arithmetic reason recorded
/// there: each session costs `LINES_PER_SESSION` lines and the page spends `FIXED_PAGE_LINES` on
/// its header and instruction, so a full page is 3 × 2 + 2 = 8 lines, inside the window's line
/// budget. The bound is pinned by a test, not by hope.
pub const SESSIONS_PER_PAGE: usize = 3;

/// Lines one listed session occupies: what it is, then when it connected and when it lapses.
const LINES_PER_SESSION: usize = 2;

/// Lines a page spends on anything other than the sessions themselves.
const FIXED_PAGE_LINES: usize = 2;

/// The largest body any management page emits, in lines.
pub const MAX_PAGE_LINES: usize = SESSIONS_PER_PAGE * LINES_PER_SESSION + FIXED_PAGE_LINES;

/// The most body lines the prompt window shows without the reader having to scroll. Derived in
/// [`crate::paired_apps`]; repeated as a bound here so a page that outgrows the window fails the
/// BUILD rather than shipping a list a person must scroll to finish.
const WINDOW_BODY_LINE_CEILING: usize = 17;

const _: () = assert!(MAX_PAGE_LINES <= WINDOW_BODY_LINE_CEILING);

/// The most of a dapp-declared string shown in a list row.
///
/// Attacker-chosen, so it is capped for the same layout reason the confirm body is capped: a name
/// containing a thousand characters would otherwise own the whole page and hide the other rows.
const LIST_FIELD_LIMIT: usize = 48;

/// The live WalletConnect surface, as the tray sees it.
///
/// A trait rather than the concrete store + relay so both journeys are exercised against a double.
/// The flows worth testing are "the user pasted a good string and approved", "they pasted rubbish",
/// and "they disconnected one of three" — none of which should need a websocket.
pub trait WalletConnectSurface {
    /// Whether a relay is configured at all. `false` means this build has nowhere to connect TO, and
    /// the journey says so plainly instead of failing at the end of a hopeful sequence.
    fn is_configured(&self) -> bool;

    /// Take a parsed pairing URI to the relay and wait for the dapp's session proposal.
    ///
    /// Returns what the dapp proposed, or a reason it did not arrive.
    fn propose(&self, uri: &WcUri) -> Result<SessionProposal, ProposalError>;

    /// Approve `proposal`, settling a session. Called only after the person approved it.
    fn approve(&self, proposal: SessionProposal) -> Result<WcSession, ProposalError>;

    /// Tell the dapp its proposal was declined, so it stops waiting.
    fn reject(&self, proposal: SessionProposal);

    /// Every live session, oldest first.
    fn list(&self) -> Vec<WcSession>;

    /// End one session and tell the dapp.
    fn disconnect(&self, topic: &str) -> DisconnectOutcome;
}

/// A session a dapp has proposed and the wallet has not yet answered.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionProposal {
    /// The relay request id to answer.
    pub request_id: u64,
    /// The pairing topic the proposal arrived on.
    pub pairing_topic: String,
    /// What the dapp says about itself. Attacker-controlled.
    pub peer: DappMetadata,
    /// The CAIP-2 chains it asked for.
    pub chains: Vec<String>,
    /// The methods it asked for. The wallet settles the INTERSECTION with what it implements, so
    /// this is what it wants, never what it gets.
    pub requested_methods: Vec<String>,
}

impl SessionProposal {
    /// The methods this wallet will actually settle: what the dapp asked for, intersected with what
    /// the wallet implements.
    ///
    /// Intersection rather than "everything the wallet has": settling a method the dapp never asked
    /// for widens the session beyond the proposal a person was shown, and the consent window is only
    /// honest about what it displayed.
    pub fn settled_methods(&self) -> Vec<String> {
        SUPPORTED_METHODS
            .iter()
            .filter(|m| self.requested_methods.iter().any(|r| r == *m))
            .map(|m| (*m).to_string())
            .collect()
    }

    /// The methods the dapp asked for that this wallet does not implement.
    ///
    /// Surfaced on the consent window rather than swallowed. A person approving a connection needs
    /// to know the dapp expects abilities it will not get, because the failure otherwise arrives
    /// later, mid-task, looking like a bug in DIG.
    pub fn unmet_methods(&self) -> Vec<String> {
        self.requested_methods
            .iter()
            .filter(|r| !SUPPORTED_METHODS.contains(&r.as_str()))
            .cloned()
            .collect()
    }
}

/// Why a proposal did not arrive, or could not be settled.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProposalError {
    /// No relay is configured in this build.
    NotConfigured,
    /// The relay could not be reached.
    Unreachable(String),
    /// The pairing string was accepted but the dapp never proposed within the wait.
    NoProposal,
    /// The account is locked, so a session could not be sealed.
    Locked,
    /// The active profile changed while the person was deciding.
    ProfileMoved,
}

impl ProposalError {
    /// The sentence a person is shown, which always names what to do next.
    ///
    /// Never a bare failure: a notice describing a problem with no answer is the dead end
    /// dig_ecosystem#1800 removed from this menu.
    pub fn advice(&self) -> String {
        match self {
            Self::NotConfigured => WC_NOT_CONFIGURED_ADVICE.to_string(),
            Self::Unreachable(why) => format!(
                "DIG could not reach the WalletConnect relay.\n\n{why}\n\n\
                 Check this computer is online, then choose \"Connect an app…\" again. The link in \
                 the app is usually still valid for a few minutes."
            ),
            Self::NoProposal => "The app never answered.\n\nWalletConnect links can only be used \
                 once and they expire quickly. Go back to the app, ask it for a NEW WalletConnect \
                 link, and paste that one."
                .to_string(),
            Self::Locked => "Your DIG account is locked, so the connection could not be saved.\n\n\
                 Choose \"Unlock…\" from the tray menu, then connect the app again."
                .to_string(),
            Self::ProfileMoved => "Your active DIG profile changed while you were deciding, so \
                 nothing was connected.\n\nConnect the app again to link it to the profile you are \
                 using now."
                .to_string(),
        }
    }
}

/// What a build without a configured relay tells the person.
///
/// It names the setting and the file, because "WalletConnect is not available" with no remedy is a
/// dead end, and the remedy here is genuinely reachable by the person reading it.
pub const WC_NOT_CONFIGURED_ADVICE: &str =
    "WalletConnect needs a relay project id, and this copy of DIG does not have one.\n\n\
     WalletConnect relays require every wallet to identify itself with a project id from \
     cloud.walletconnect.com. Once you have one, put it in your DIG settings file as \
     \"walletconnect\": { \"project_id\": \"…\" } and restart DIG.\n\n\
     Everything else in DIG works without this — it is only needed to connect outside apps.";

/// What came of the connect journey.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConnectOutcome {
    /// A session was approved and settled.
    Connected {
        /// The dapp's declared name, for the caller's log.
        peer_name: String,
    },
    /// The person closed the paste window without pasting anything.
    Cancelled,
    /// The person read the proposal and declined it.
    Declined,
    /// The pasted text was not a usable pairing string. The person was told which part was wrong.
    BadUri(UriError),
    /// The pairing could not be completed. The person was told why and what to do.
    Failed(ProposalError),
    /// No window could be drawn — a headless host. Nothing was connected.
    Unavailable,
}

/// What came of the management journey.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ManageOutcome {
    /// Nothing is connected. The person was told so, and told how to connect something.
    NothingConnected,
    /// The person looked through the list and disconnected `disconnected` apps — often zero, which
    /// is a fine outcome, since most openings of this window are to check rather than to change.
    Reviewed {
        /// How many sessions were ended.
        disconnected: usize,
    },
    /// No window could be drawn. Nothing was changed.
    Unavailable,
}

/// Ask for a WalletConnect link, then put the dapp's proposal to the person.
///
/// The precondition is checked FIRST and named: a build with no relay says so before asking for a
/// string it could not use, rather than taking the paste and failing at the end.
pub fn connect_walletconnect(
    confirmer: &dyn NativeConfirmer,
    surface: &dyn WalletConnectSurface,
) -> ConnectOutcome {
    if !surface.is_configured() {
        return match notice(
            confirmer,
            "Connect an app",
            "WalletConnect is not set up",
            WC_NOT_CONFIGURED_ADVICE,
        ) {
            ConfirmDecision::Unavailable => ConnectOutcome::Unavailable,
            _ => ConnectOutcome::Failed(ProposalError::NotConfigured),
        };
    }

    let typed = match confirmer.request_input(&InputPrompt {
        title: "DIG - Connect an app",
        heading: "Paste the app's WalletConnect link",
        body: "In the app or website you want to connect, choose WalletConnect and copy the link \
               it shows you. It starts with \"wc:\".\n\n\
               DIG will then show you what the app is asking for, and nothing is connected until \
               you approve it.",
        field_label: "WalletConnect link:",
        submit: "Continue",
        // Not a secret. Masking it would only stop a person checking they pasted the right thing,
        // and a pairing string is single-use and public to both parties by design.
        masked: false,
        revealable: false,
        style: InputStyle::Dialog,
    }) {
        InputOutcome::Provided(typed) => typed,
        InputOutcome::Cancelled => return ConnectOutcome::Cancelled,
        InputOutcome::Unavailable => return ConnectOutcome::Unavailable,
    };

    let uri = match WcUri::parse(&typed) {
        Ok(uri) => uri,
        Err(err) => {
            notice(
                confirmer,
                "Connect an app",
                "That link cannot be used",
                &format!(
                    "DIG could not read what you pasted: {err}.\n\n\
                     Go back to the app, copy its WalletConnect link again — the whole thing, \
                     starting with \"wc:\" — and try once more.",
                ),
            );
            return ConnectOutcome::BadUri(err);
        }
    };

    let proposal = match surface.propose(&uri) {
        Ok(proposal) => proposal,
        Err(err) => {
            notice(
                confirmer,
                "Connect an app",
                "The app was not connected",
                &err.advice(),
            );
            return ConnectOutcome::Failed(err);
        }
    };

    if !confirm_proposal(confirmer, &proposal) {
        surface.reject(proposal);
        return ConnectOutcome::Declined;
    }

    match surface.approve(proposal) {
        Ok(session) => ConnectOutcome::Connected {
            peer_name: session.peer.name,
        },
        Err(err) => {
            notice(
                confirmer,
                "Connect an app",
                "The app was not connected",
                &err.advice(),
            );
            ConnectOutcome::Failed(err)
        }
    }
}

/// Put the dapp's proposal to the person: who says they are asking, what they get, and what they
/// asked for that they will not get.
fn confirm_proposal(confirmer: &dyn NativeConfirmer, proposal: &SessionProposal) -> bool {
    let name = capped(
        &proposal.peer.name,
        LIST_FIELD_LIMIT,
        "An app that did not name itself",
    );
    let url = capped(&proposal.peer.url, LIST_FIELD_LIMIT, "it gave no address");
    let granted = describe_methods(&proposal.settled_methods());
    let unmet = proposal.unmet_methods();
    let unmet_line = if unmet.is_empty() {
        String::new()
    } else {
        format!(
            "\n\nIt also asked for things DIG cannot do ({}). Those will not work, and the app may \
             show an error when it tries.",
            capped(&unmet.join(", "), LIST_FIELD_LIMIT * 2, "some other things"),
        )
    };

    let body = format!(
        "The app says it is \"{name}\" at {url}.\n\n\
         DIG cannot check that — those are the app's own words about itself, and WalletConnect has \
         no way to prove them. Only continue if you just asked this app to connect.\n\n\
         If you connect, it will be able to:\n{granted}\n\n\
         It will ask you separately, every single time, before anything is signed.{unmet_line}"
    );

    matches!(
        confirmer.confirm_claim(&ClaimPrompt {
            scannable: None,
            title: "DIG - Connect an app",
            heading: "Connect this app to your DIG identity?",
            body: &body,
            affirm: "Connect it",
            identifier: None,
            decline: None,
            // The person just pasted a link on purpose, so they intend to connect — but the thing
            // being connected identified itself and nothing verified it, so the safe side wins the
            // default. Declining costs one retry.
            refusal_is_default: true,
        }),
        ConfirmDecision::Approve
    )
}

/// Turn the settled method list into sentences a person can weigh.
///
/// Method names are protocol jargon; a consent window that lists `chip0002_signMessage` has not
/// disclosed anything to anybody outside this repository (§6.1 — abstract the jargon by default).
fn describe_methods(methods: &[String]) -> String {
    let mut lines: Vec<&str> = Vec::new();
    for method in methods {
        let described = match method.as_str() {
            super::request::METHOD_GET_PUBLIC_KEYS => "  • see your DIG identity's public key",
            super::request::METHOD_GET_CURRENT_ADDRESS => "  • see your wallet's receiving address",
            super::request::METHOD_CHAIN_ID => "  • see which Chia network you are on",
            super::request::METHOD_SIGN_MESSAGE => {
                "  • ASK you to sign messages proving you control this identity"
            }
            // Connecting is the thing being approved, so listing it as a capability would be
            // circular. Silently dropped rather than described.
            super::request::METHOD_CONNECT => continue,
            _ => "  • something DIG does not recognise",
        };
        lines.push(described);
    }
    if lines.is_empty() {
        // Reachable: a dapp can propose only methods this wallet lacks. Saying so plainly beats an
        // empty bullet list, which reads as a rendering failure.
        return "  • nothing — it asked only for things DIG cannot do".to_string();
    }
    lines.join("\n")
}

/// Show what is connected and let the person disconnect any of it.
///
/// The loop mirrors [`crate::paired_apps::manage_paired_apps`] exactly — a page, a typed number to
/// disconnect, `n` for the next page, empty to close — because two management windows in one tray
/// that answer differently to the same keystroke is worse than either shape on its own.
pub fn manage_walletconnect(
    confirmer: &dyn NativeConfirmer,
    surface: &dyn WalletConnectSurface,
    now: u64,
) -> ManageOutcome {
    let mut disconnected = 0usize;
    let mut page = 0usize;

    loop {
        let listed = surface.list();
        if listed.is_empty() {
            let heading = if disconnected == 0 {
                "No apps are connected through WalletConnect"
            } else {
                "No apps are connected through WalletConnect any more"
            };
            let decision = notice(
                confirmer,
                "Connected apps",
                heading,
                "No outside app or website can currently ask your DIG identity for anything.\n\n\
                 To connect one, choose \"Connect an app…\" from the tray menu and paste the \
                 WalletConnect link it shows you.",
            );
            if matches!(decision, ConfirmDecision::Unavailable) && disconnected == 0 {
                return ManageOutcome::Unavailable;
            }
            return if disconnected == 0 {
                ManageOutcome::NothingConnected
            } else {
                ManageOutcome::Reviewed { disconnected }
            };
        }

        let pages = page_count(listed.len());
        page = page.min(pages - 1);
        let shown = page_slice(&listed, page);
        let body = paged_body(&listed, page, now);

        let outcome = confirmer.request_input(&InputPrompt {
            title: "DIG - Connected apps",
            heading: &page_heading(page, pages, listed.len()),
            body: &body,
            field_label: "Number to disconnect (or leave empty):",
            submit: "Continue",
            masked: false,
            revealable: false,
            style: InputStyle::Dialog,
        });

        let typed = match outcome {
            InputOutcome::Provided(typed) => typed.trim().to_string(),
            // The escape hatch, and it is unconditional: cancelling closes from any page.
            InputOutcome::Cancelled => return ManageOutcome::Reviewed { disconnected },
            InputOutcome::Unavailable => {
                return if disconnected == 0 {
                    ManageOutcome::Unavailable
                } else {
                    ManageOutcome::Reviewed { disconnected }
                }
            }
        };

        match parse_choice(&typed, shown.len()) {
            Choice::Close => return ManageOutcome::Reviewed { disconnected },
            Choice::NextPage => page = (page + 1) % pages,
            Choice::Disconnect(index) => {
                let session = &shown[index];
                if !confirm_disconnect(confirmer, session) {
                    continue;
                }
                let outcome = surface.disconnect(&session.topic);
                if outcome == DisconnectOutcome::DisconnectedForThisRunOnly {
                    // The confirmation just promised the app would not come back. That is now
                    // untrue, and only the person can decide what to do about it.
                    warn_disconnect_is_not_durable(confirmer, session);
                }
                if outcome.lost_session() {
                    disconnected += 1;
                    // Any page number may now be past the end; the top of the loop re-clamps it.
                    page = 0;
                }
            }
        }
    }
}

/// Put the disconnect to the person before doing it.
///
/// A [`ClaimPrompt`] rather than a notice because the answer branches, and not a biometric gate
/// because nothing is weakened: disconnecting withdraws access, which is the safe direction, and
/// demanding a fingerprint to make an account safer teaches people to leave it unsafe.
fn confirm_disconnect(confirmer: &dyn NativeConfirmer, session: &WcSession) -> bool {
    let name = capped(&session.peer.name, LIST_FIELD_LIMIT, "This app");
    let body = format!(
        "\"{}\" will be disconnected immediately — not at the next restart.\n\n\
         It stops being able to ask your DIG identity for anything. If you want it back later, \
         connect it again with a new WalletConnect link from the app.",
        name
    );
    matches!(
        confirmer.confirm_claim(&ClaimPrompt {
            scannable: None,
            title: "DIG - Disconnect an app",
            heading: "Disconnect this app?",
            body: &body,
            affirm: "Disconnect it",
            identifier: None,
            decline: None,
            // Cutting a connected app off mid-operation is the consequential side, so the safe
            // answer is the default.
            refusal_is_default: true,
        }),
        ConfirmDecision::Approve
    )
}

/// Take back the confirmation's promise when the disconnect could not be written down.
///
/// The session IS gone for this run, so this is not a failure notice — it is the difference between
/// "gone" and "gone until you restart DIG". It names the action that makes it stick, and that action
/// has to be one the person can actually take: removing it again from this list is impossible,
/// because the row has already gone.
fn warn_disconnect_is_not_durable(confirmer: &dyn NativeConfirmer, session: &WcSession) {
    let name = capped(&session.peer.name, LIST_FIELD_LIMIT, "That app");
    let body = format!(
        "\"{name}\" is disconnected right now, and cannot reach your DIG identity while DIG is \
         running.\n\n\
         DIG could not write the change down, because your account is locked. If you close DIG now, \
         the app is connected again at the next start.\n\n\
         To disconnect it for good: close DIG and open it again, unlock your account, then \
         disconnect the app from this list. It reappears here when DIG restarts."
    );
    notice(
        confirmer,
        "Disconnect an app",
        "Disconnected for now, but not written down",
        &body,
    );
}

/// What the person typed on a management page.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Choice {
    /// Close the window — an empty answer, or anything that is neither a listed number nor the page
    /// key. Anything unrecognised closes rather than re-prompting, so a stray keystroke cannot
    /// disconnect something and cannot trap a person in a loop.
    Close,
    /// Show the next page.
    NextPage,
    /// Disconnect the session at this index WITHIN THE CURRENT PAGE.
    Disconnect(usize),
}

/// Read the typed answer against a page holding `shown` sessions.
fn parse_choice(typed: &str, shown: usize) -> Choice {
    let typed = typed.trim();
    if typed.eq_ignore_ascii_case("n") {
        return Choice::NextPage;
    }
    match typed.parse::<usize>() {
        // One-based on the page, and bounded BY THE PAGE rather than by the whole list: the numbers
        // a person sees are the numbers they may type.
        Ok(n) if n >= 1 && n <= shown => Choice::Disconnect(n - 1),
        _ => Choice::Close,
    }
}

/// How many pages `total` sessions occupy. At least one, so an empty list still has a page zero.
fn page_count(total: usize) -> usize {
    total.div_ceil(SESSIONS_PER_PAGE).max(1)
}

/// The sessions on `page`.
fn page_slice(all: &[WcSession], page: usize) -> &[WcSession] {
    let start = (page * SESSIONS_PER_PAGE).min(all.len());
    let end = (start + SESSIONS_PER_PAGE).min(all.len());
    &all[start..end]
}

/// The heading above a page, naming where the person is in the list.
fn page_heading(page: usize, pages: usize, total: usize) -> String {
    if pages == 1 {
        return format!("{total} connected through WalletConnect");
    }
    format!(
        "{total} connected through WalletConnect (page {} of {pages})",
        page + 1
    )
}

/// The body of one management page: the sessions, numbered, then how to answer.
fn paged_body(all: &[WcSession], page: usize, now: u64) -> String {
    let shown = page_slice(all, page);
    let mut lines = Vec::with_capacity(MAX_PAGE_LINES);
    for (i, session) in shown.iter().enumerate() {
        let name = capped(&session.peer.name, LIST_FIELD_LIMIT, "An unnamed app");
        let url = capped(&session.peer.url, LIST_FIELD_LIMIT, "no address given");
        lines.push(format!("{}. {name} — {url}", i + 1));
        lines.push(format!(
            "   connected {}, lapses {}",
            ago(now, session.connected_at),
            within(session.expires_at, now)
        ));
    }
    let more = if page_count(all.len()) > 1 {
        ", \"n\" for the next page"
    } else {
        ""
    };
    lines.push(String::new());
    lines.push(format!(
        "Type a number to disconnect it{more}, or leave this empty to close."
    ));
    lines.join("\n")
}

/// A coarse "how long ago", in the units a person thinks in.
///
/// Coarse on purpose: nobody manages connections by the second, and a precise figure invites a
/// reader to trust a clock this window has no reason to be precise about.
fn ago(now: u64, then: u64) -> String {
    let secs = now.saturating_sub(then);
    match secs {
        0..=90 => "just now".to_string(),
        s if s < 3600 => format!("{} minutes ago", s / 60),
        s if s < 86_400 => format!("{} hours ago", s / 3600),
        s => format!("{} days ago", s / 86_400),
    }
}

/// A coarse "how long left", saying plainly when the answer is "already".
fn within(expires_at: u64, now: u64) -> String {
    let secs = expires_at.saturating_sub(now);
    match secs {
        0 => "now".to_string(),
        s if s < 3600 => format!("in {} minutes", s.div_ceil(60)),
        s if s < 86_400 => format!("in {} hours", s / 3600),
        s => format!("in {} days", s / 86_400),
    }
}

/// A dapp-declared string, flattened, capped, and replaced by `fallback` when it is empty.
///
/// Every string a dapp chose passes through here before it reaches a window. Flattening removes the
/// newlines that would let it forge extra rows in a numbered list; the cap stops one row owning the
/// page. Neither is about markup — the renderer draws glyphs literally — both are about LAYOUT,
/// which is the part of a consent window a hostile string can still forge.
fn capped(value: &str, limit: usize, fallback: &str) -> String {
    let flattened: String = value.split_whitespace().collect::<Vec<_>>().join(" ");
    if flattened.is_empty() {
        return fallback.to_string();
    }
    if flattened.chars().count() <= limit {
        return flattened;
    }
    let kept: String = flattened.chars().take(limit).collect();
    format!("{kept}\u{2026}")
}

/// Draw a notice and report what the window did, so a headless host is distinguishable from a
/// person clicking through.
fn notice(
    confirmer: &dyn NativeConfirmer,
    title_suffix: &str,
    heading: &str,
    body: &str,
) -> ConfirmDecision {
    confirmer.show_notice(&NoticePrompt {
        title: &format!("DIG - {title_suffix}"),
        heading,
        body,
        acknowledge: "Close",
        identifier: None,
    })
}

/// Re-exported so the tray shell advertises the same event set the session settles, rather than
/// keeping a second list that could drift from it.
pub use super::request::SUPPORTED_EVENTS as WC_EVENTS;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::confirm::{ConnectPrompt, PairPrompt, RevealPrompt, SignPrompt};
    use crate::walletconnect::request::METHOD_CHAIN_ID;
    use crate::walletconnect::session::SESSION_TTL_SECS;
    use std::sync::Mutex;
    use zeroize::Zeroizing;

    const NOW: u64 = 1_800_000_000;

    /// A scripted confirmer: it answers each window from a queue and records what it drew.
    ///
    /// Scripted rather than fixed-answer, because both journeys are SEQUENCES of windows and the
    /// interesting cases are "approved the first, declined the second". A double with one answer
    /// could not express those, and a test built on it would silently only ever exercise the first
    /// window.
    struct Scripted {
        inputs: Mutex<Vec<InputOutcome>>,
        claims: Mutex<Vec<ConfirmDecision>>,
        notices: Mutex<Vec<String>>,
        bodies: Mutex<Vec<String>>,
        notice_decision: ConfirmDecision,
    }

    impl Scripted {
        fn new(inputs: Vec<InputOutcome>, claims: Vec<ConfirmDecision>) -> Self {
            Self {
                inputs: Mutex::new(inputs),
                claims: Mutex::new(claims),
                notices: Mutex::new(Vec::new()),
                bodies: Mutex::new(Vec::new()),
                notice_decision: ConfirmDecision::Approve,
            }
        }
        fn typing(lines: &[&str]) -> Self {
            Self::new(
                lines
                    .iter()
                    .map(|l| InputOutcome::Provided(Zeroizing::new((*l).to_string())))
                    .collect(),
                Vec::new(),
            )
        }
        fn headless() -> Self {
            Self {
                notice_decision: ConfirmDecision::Unavailable,
                ..Self::new(vec![InputOutcome::Unavailable], Vec::new())
            }
        }
        /// Everything drawn, joined — used to assert a person was told a specific thing.
        fn everything_shown(&self) -> String {
            let mut all = self.notices.lock().unwrap().join("\n");
            all.push('\n');
            all.push_str(&self.bodies.lock().unwrap().join("\n"));
            all
        }
        fn notices_shown(&self) -> usize {
            self.notices.lock().unwrap().len()
        }
    }

    impl NativeConfirmer for Scripted {
        fn confirm_pair(&self, _p: &PairPrompt<'_>) -> ConfirmDecision {
            ConfirmDecision::Deny
        }
        fn confirm_connect(&self, _p: &ConnectPrompt<'_>) -> ConfirmDecision {
            ConfirmDecision::Deny
        }
        fn confirm_sign(&self, _p: &SignPrompt<'_>) -> ConfirmDecision {
            ConfirmDecision::Deny
        }
        fn confirm_reveal(&self, _p: &RevealPrompt<'_>) -> ConfirmDecision {
            ConfirmDecision::Deny
        }
        fn show_notice(&self, p: &NoticePrompt<'_>) -> ConfirmDecision {
            self.notices
                .lock()
                .unwrap()
                .push(format!("{}\n{}", p.heading, p.body));
            self.notice_decision
        }
        fn confirm_claim(&self, p: &ClaimPrompt<'_>) -> ConfirmDecision {
            self.bodies
                .lock()
                .unwrap()
                .push(format!("{}\n{}", p.heading, p.body));
            let mut queue = self.claims.lock().unwrap();
            if queue.is_empty() {
                // Nothing scripted means "declined": a test that runs off the end of its script must
                // stop rather than silently approve, which would turn a script bug into a passing
                // test that approved something it never meant to.
                return ConfirmDecision::Deny;
            }
            queue.remove(0)
        }
        fn request_input(&self, p: &InputPrompt<'_>) -> InputOutcome {
            self.bodies
                .lock()
                .unwrap()
                .push(format!("{}\n{}", p.heading, p.body));
            let mut queue = self.inputs.lock().unwrap();
            if queue.is_empty() {
                // Same reasoning: an exhausted script CLOSES the window rather than looping, so a
                // management test whose script is wrong fails instead of spinning forever.
                return InputOutcome::Cancelled;
            }
            queue.remove(0)
        }
    }

    /// A WalletConnect surface backed by a plain vector, recording every call.
    struct FakeSurface {
        configured: bool,
        proposal: Option<Result<SessionProposal, ProposalError>>,
        approval: Option<ProposalError>,
        sessions: Mutex<Vec<WcSession>>,
        durable: bool,
        /// Every call made, in order — how "propose was never reached" is asserted.
        calls: Mutex<Vec<String>>,
    }

    impl FakeSurface {
        fn ready(sessions: Vec<WcSession>) -> Self {
            Self {
                configured: true,
                proposal: Some(Ok(proposal())),
                approval: None,
                sessions: Mutex::new(sessions),
                durable: true,
                calls: Mutex::new(Vec::new()),
            }
        }
        fn unconfigured() -> Self {
            Self {
                configured: false,
                ..Self::ready(Vec::new())
            }
        }
        fn note(&self, what: &str) {
            self.calls.lock().unwrap().push(what.to_string());
        }
        fn called(&self, what: &str) -> bool {
            self.calls.lock().unwrap().iter().any(|c| c == what)
        }
        fn topics_left(&self) -> Vec<String> {
            self.sessions
                .lock()
                .unwrap()
                .iter()
                .map(|s| s.topic.clone())
                .collect()
        }
    }

    impl WalletConnectSurface for FakeSurface {
        fn is_configured(&self) -> bool {
            self.configured
        }
        fn propose(&self, _uri: &WcUri) -> Result<SessionProposal, ProposalError> {
            self.note("propose");
            self.proposal
                .clone()
                .unwrap_or(Err(ProposalError::NoProposal))
        }
        fn approve(&self, proposal: SessionProposal) -> Result<WcSession, ProposalError> {
            self.note("approve");
            if let Some(err) = self.approval.clone() {
                return Err(err);
            }
            Ok(session(&proposal.peer.name, NOW))
        }
        fn reject(&self, _proposal: SessionProposal) {
            self.note("reject");
        }
        fn list(&self) -> Vec<WcSession> {
            self.sessions.lock().unwrap().clone()
        }
        fn disconnect(&self, topic: &str) -> DisconnectOutcome {
            self.note(&format!("disconnect:{topic}"));
            let mut all = self.sessions.lock().unwrap();
            let before = all.len();
            all.retain(|s| s.topic != topic);
            if all.len() == before {
                return DisconnectOutcome::NotFound;
            }
            if self.durable {
                DisconnectOutcome::Disconnected
            } else {
                DisconnectOutcome::DisconnectedForThisRunOnly
            }
        }
    }

    fn session(name: &str, connected_at: u64) -> WcSession {
        WcSession {
            topic: name.to_string(),
            sym_key_hex: "aa".repeat(32),
            profile_did: "did:chia:me".into(),
            peer: DappMetadata {
                name: name.to_string(),
                description: String::new(),
                url: format!("https://{name}.example"),
                icons: Vec::new(),
            },
            chains: vec!["chia:mainnet".into()],
            methods: SUPPORTED_METHODS.iter().map(|m| (*m).to_string()).collect(),
            accounts: vec!["chia:mainnet:xch1abc".into()],
            connected_at,
            expires_at: connected_at + SESSION_TTL_SECS,
        }
    }

    fn proposal() -> SessionProposal {
        SessionProposal {
            request_id: 1,
            pairing_topic: "p".repeat(64),
            peer: DappMetadata {
                name: "Example Dapp".into(),
                description: String::new(),
                url: "https://dapp.example".into(),
                icons: Vec::new(),
            },
            chains: vec!["chia:mainnet".into()],
            requested_methods: SUPPORTED_METHODS.iter().map(|m| (*m).to_string()).collect(),
        }
    }

    fn valid_uri() -> String {
        format!(
            "wc:{}@2?relay-protocol=irn&symKey={}",
            "a".repeat(64),
            "b".repeat(64)
        )
    }

    // ---- connecting -------------------------------------------------------------------------

    /// The precondition is checked FIRST. Asking for a link and only then admitting there is nowhere
    /// to send it wastes a person's time and reads as a bug; `propose` must never be reached.
    #[test]
    fn an_unconfigured_build_says_so_before_asking_for_anything() {
        let confirmer = Scripted::typing(&[&valid_uri()]);
        let surface = FakeSurface::unconfigured();
        let outcome = connect_walletconnect(&confirmer, &surface);
        assert_eq!(
            outcome,
            ConnectOutcome::Failed(ProposalError::NotConfigured)
        );
        assert!(!surface.called("propose"));
        assert!(
            confirmer.everything_shown().contains("project id"),
            "the person must be told what is missing"
        );
    }

    /// A dead end is a notice that describes a problem and names no remedy. This one has to name a
    /// remedy the reader can actually reach.
    #[test]
    fn the_unconfigured_notice_names_a_remedy_rather_than_only_a_problem() {
        assert!(WC_NOT_CONFIGURED_ADVICE.contains("cloud.walletconnect.com"));
        assert!(WC_NOT_CONFIGURED_ADVICE.contains("project_id"));
        assert!(
            WC_NOT_CONFIGURED_ADVICE.contains("Everything else in DIG works"),
            "the person must be told the rest of the app is unaffected"
        );
    }

    #[test]
    fn cancelling_the_paste_window_connects_nothing() {
        let confirmer = Scripted::new(vec![InputOutcome::Cancelled], Vec::new());
        let surface = FakeSurface::ready(Vec::new());
        assert_eq!(
            connect_walletconnect(&confirmer, &surface),
            ConnectOutcome::Cancelled
        );
        assert!(!surface.called("propose"));
    }

    /// A bad paste is refused BEFORE the relay is touched, and the person is told which part failed
    /// rather than a generic refusal.
    #[test]
    fn an_unreadable_link_is_refused_without_reaching_the_relay() {
        let confirmer = Scripted::typing(&["https://not-walletconnect.example"]);
        let surface = FakeSurface::ready(Vec::new());
        let outcome = connect_walletconnect(&confirmer, &surface);
        assert_eq!(outcome, ConnectOutcome::BadUri(UriError::NotWalletConnect));
        assert!(
            !surface.called("propose"),
            "a bad link must not reach the relay"
        );
        assert!(confirmer.everything_shown().contains("wc:"));
    }

    /// A v1 link is a real WalletConnect link, so the person did nothing wrong and must be told the
    /// APP is old — the distinction the URI parser keeps, carried through to what is drawn.
    #[test]
    fn a_v1_link_tells_the_person_the_app_is_out_of_date() {
        let v1 = format!(
            "wc:{}@1?bridge=https%3A%2F%2Fb.org&key={}",
            "a".repeat(64),
            "b".repeat(64)
        );
        let confirmer = Scripted::typing(&[&v1]);
        let surface = FakeSurface::ready(Vec::new());
        let outcome = connect_walletconnect(&confirmer, &surface);
        assert_eq!(
            outcome,
            ConnectOutcome::BadUri(UriError::UnsupportedVersion("1".into()))
        );
        assert!(confirmer.everything_shown().contains("needs an update"));
    }

    /// Declining must tell the DAPP, not merely stop locally. A wallet that silently walks away
    /// leaves the dapp spinning on a proposal that will never be answered.
    #[test]
    fn declining_a_proposal_tells_the_dapp_and_settles_nothing() {
        let confirmer = Scripted::new(
            vec![InputOutcome::Provided(Zeroizing::new(valid_uri()))],
            vec![ConfirmDecision::Deny],
        );
        let surface = FakeSurface::ready(Vec::new());
        assert_eq!(
            connect_walletconnect(&confirmer, &surface),
            ConnectOutcome::Declined
        );
        assert!(surface.called("reject"), "the dapp must be told");
        assert!(!surface.called("approve"), "and nothing may be settled");
    }

    #[test]
    fn approving_a_proposal_settles_a_session() {
        let confirmer = Scripted::new(
            vec![InputOutcome::Provided(Zeroizing::new(valid_uri()))],
            vec![ConfirmDecision::Approve],
        );
        let surface = FakeSurface::ready(Vec::new());
        assert_eq!(
            connect_walletconnect(&confirmer, &surface),
            ConnectOutcome::Connected {
                peer_name: "Example Dapp".into()
            }
        );
        assert!(surface.called("approve"));
        assert!(!surface.called("reject"));
    }

    /// The consent window must refuse to vouch for the dapp, and must say the signing prompt comes
    /// back every time — otherwise connecting reads as granting signing.
    #[test]
    fn the_connect_window_disclaims_the_dapps_self_description() {
        let confirmer = Scripted::new(
            vec![InputOutcome::Provided(Zeroizing::new(valid_uri()))],
            vec![ConfirmDecision::Approve],
        );
        connect_walletconnect(&confirmer, &FakeSurface::ready(Vec::new()));
        let shown = confirmer.everything_shown();
        assert!(shown.contains("Example Dapp"));
        assert!(shown.contains("DIG cannot check that"), "{shown}");
        assert!(shown.contains("every single time"), "{shown}");
    }

    /// Capabilities are described in words a person outside this repository can weigh. A window
    /// listing `chip0002_signMessage` has disclosed nothing to anybody.
    #[test]
    fn the_connect_window_describes_capabilities_without_protocol_jargon() {
        let confirmer = Scripted::new(
            vec![InputOutcome::Provided(Zeroizing::new(valid_uri()))],
            vec![ConfirmDecision::Approve],
        );
        connect_walletconnect(&confirmer, &FakeSurface::ready(Vec::new()));
        let shown = confirmer.everything_shown();
        for jargon in SUPPORTED_METHODS {
            assert!(
                !shown.contains(jargon),
                "the window showed the raw method name {jargon}"
            );
        }
        assert!(shown.contains("receiving address"));
        assert!(shown.contains("sign messages"));
    }

    /// A dapp asking for abilities this wallet lacks must be disclosed at CONNECT time. Learning it
    /// later, mid-task, looks like a bug in DIG rather than a missing feature.
    #[test]
    fn a_dapp_asking_for_more_than_the_wallet_offers_is_disclosed_up_front() {
        let mut greedy = proposal();
        greedy.requested_methods.push("chia_sendTransaction".into());
        let confirmer = Scripted::new(
            vec![InputOutcome::Provided(Zeroizing::new(valid_uri()))],
            vec![ConfirmDecision::Approve],
        );
        let mut surface = FakeSurface::ready(Vec::new());
        surface.proposal = Some(Ok(greedy));
        connect_walletconnect(&confirmer, &surface);
        let shown = confirmer.everything_shown();
        assert!(shown.contains("things DIG cannot do"), "{shown}");
        assert!(shown.contains("chia_sendTransaction"), "{shown}");
    }

    /// The settled set is the INTERSECTION. A wallet that settled everything it can do would widen
    /// the session past the proposal the person was shown.
    #[test]
    fn the_settled_methods_are_the_intersection_of_asked_and_implemented() {
        let narrow = SessionProposal {
            requested_methods: vec![METHOD_CHAIN_ID.into(), "chia_sendTransaction".into()],
            ..proposal()
        };
        assert_eq!(narrow.settled_methods(), vec![METHOD_CHAIN_ID.to_string()]);
        assert_eq!(
            narrow.unmet_methods(),
            vec!["chia_sendTransaction".to_string()]
        );
        assert!(
            SUPPORTED_METHODS.len() > 1,
            "the fixture only distinguishes intersection from union while the wallet supports more"
        );
    }

    /// A dapp that asked ONLY for things the wallet lacks still gets a readable window, not an empty
    /// bullet list that reads as a rendering failure.
    #[test]
    fn a_proposal_granting_nothing_says_so_in_words() {
        let hopeless = SessionProposal {
            requested_methods: vec!["chia_sendTransaction".into()],
            ..proposal()
        };
        let described = describe_methods(&hopeless.settled_methods());
        assert!(described.contains("nothing"), "{described}");
    }

    /// A relay failure names the failure AND what to do about it.
    #[test]
    fn every_proposal_failure_tells_the_person_what_to_do_next() {
        for err in [
            ProposalError::NotConfigured,
            ProposalError::Unreachable("timed out".into()),
            ProposalError::NoProposal,
            ProposalError::Locked,
            ProposalError::ProfileMoved,
        ] {
            let advice = err.advice();
            assert!(advice.len() > 60, "terse advice for {err:?}: {advice}");
            let names_an_action = ["again", "Unlock", "restart", "put it in", "NEW"]
                .iter()
                .any(|verb| advice.contains(verb));
            assert!(names_an_action, "no remedy named for {err:?}: {advice}");
        }
    }

    #[test]
    fn a_headless_host_connects_nothing_and_reports_it_as_unavailable() {
        let confirmer = Scripted::headless();
        let surface = FakeSurface::ready(Vec::new());
        assert_eq!(
            connect_walletconnect(&confirmer, &surface),
            ConnectOutcome::Unavailable
        );
        assert!(!surface.called("propose"));
    }

    // ---- managing ---------------------------------------------------------------------------

    #[test]
    fn an_empty_list_still_draws_a_window_naming_how_to_connect_something() {
        let confirmer = Scripted::typing(&[]);
        let surface = FakeSurface::ready(Vec::new());
        assert_eq!(
            manage_walletconnect(&confirmer, &surface, NOW),
            ManageOutcome::NothingConnected
        );
        assert_eq!(
            confirmer.notices_shown(),
            1,
            "silence would read as a broken menu item"
        );
        assert!(confirmer.everything_shown().contains("Connect an app"));
    }

    #[test]
    fn closing_the_management_window_changes_nothing() {
        let confirmer = Scripted::new(vec![InputOutcome::Cancelled], Vec::new());
        let surface = FakeSurface::ready(vec![session("a", NOW), session("b", NOW + 1)]);
        assert_eq!(
            manage_walletconnect(&confirmer, &surface, NOW + 2),
            ManageOutcome::Reviewed { disconnected: 0 }
        );
        assert_eq!(surface.topics_left(), vec!["a", "b"]);
    }

    /// Typing a number must disconnect THAT row and no other. Three distinct sessions, so an
    /// off-by-one lands on a named neighbour rather than on nothing.
    #[test]
    fn typing_a_number_disconnects_exactly_that_row() {
        let confirmer = Scripted::new(
            vec![
                InputOutcome::Provided(Zeroizing::new("2".to_string())),
                InputOutcome::Cancelled,
            ],
            vec![ConfirmDecision::Approve],
        );
        let surface = FakeSurface::ready(vec![
            session("first", NOW),
            session("second", NOW + 1),
            session("third", NOW + 2),
        ]);
        assert_eq!(
            manage_walletconnect(&confirmer, &surface, NOW + 3),
            ManageOutcome::Reviewed { disconnected: 1 }
        );
        assert_eq!(surface.topics_left(), vec!["first", "third"]);
    }

    /// Declining the disconnect confirmation must leave the session alone — the second window is a
    /// real gate, not a formality.
    #[test]
    fn declining_the_disconnect_confirmation_keeps_the_session() {
        let confirmer = Scripted::new(
            vec![
                InputOutcome::Provided(Zeroizing::new("1".to_string())),
                InputOutcome::Cancelled,
            ],
            vec![ConfirmDecision::Deny],
        );
        let surface = FakeSurface::ready(vec![session("only", NOW)]);
        assert_eq!(
            manage_walletconnect(&confirmer, &surface, NOW + 1),
            ManageOutcome::Reviewed { disconnected: 0 }
        );
        assert_eq!(surface.topics_left(), vec!["only"]);
    }

    /// The typed number is bounded BY THE PAGE, not by the whole list. On a second page holding one
    /// row, "2" names nothing the person can see — and an implementation bounding by the full list
    /// would happily disconnect the second session on page ONE, which they are not looking at.
    #[test]
    fn a_number_past_the_end_of_the_current_page_disconnects_nothing() {
        let confirmer = Scripted::new(
            vec![
                InputOutcome::Provided(Zeroizing::new("n".to_string())),
                InputOutcome::Provided(Zeroizing::new("2".to_string())),
            ],
            vec![ConfirmDecision::Approve],
        );
        let surface = FakeSurface::ready(vec![
            session("a", NOW),
            session("b", NOW + 1),
            session("c", NOW + 2),
            session("d", NOW + 3),
        ]);
        assert_eq!(
            manage_walletconnect(&confirmer, &surface, NOW + 4),
            ManageOutcome::Reviewed { disconnected: 0 }
        );
        assert_eq!(surface.topics_left(), vec!["a", "b", "c", "d"]);
    }

    /// Page two shows the fourth session, and typing 1 there disconnects THAT one — the control
    /// proving the page arithmetic works rather than merely refusing everything.
    #[test]
    fn the_second_page_lists_and_disconnects_its_own_rows() {
        let confirmer = Scripted::new(
            vec![
                InputOutcome::Provided(Zeroizing::new("n".to_string())),
                InputOutcome::Provided(Zeroizing::new("1".to_string())),
                InputOutcome::Cancelled,
            ],
            vec![ConfirmDecision::Approve],
        );
        let surface = FakeSurface::ready(vec![
            session("a", NOW),
            session("b", NOW + 1),
            session("c", NOW + 2),
            session("d", NOW + 3),
        ]);
        manage_walletconnect(&confirmer, &surface, NOW + 4);
        assert_eq!(surface.topics_left(), vec!["a", "b", "c"]);
        assert!(surface.called("disconnect:d"));
    }

    /// `professional-ui`'s never-trap rule: cancelling closes from ANY page, including one reached
    /// by paging forward.
    #[test]
    fn cancelling_closes_from_a_later_page_too() {
        let confirmer = Scripted::new(
            vec![
                InputOutcome::Provided(Zeroizing::new("n".to_string())),
                InputOutcome::Cancelled,
            ],
            Vec::new(),
        );
        let surface = FakeSurface::ready(vec![
            session("a", NOW),
            session("b", NOW + 1),
            session("c", NOW + 2),
            session("d", NOW + 3),
        ]);
        assert_eq!(
            manage_walletconnect(&confirmer, &surface, NOW + 4),
            ManageOutcome::Reviewed { disconnected: 0 }
        );
    }

    /// An unrecognised keystroke closes rather than re-prompting, so a stray key can neither
    /// disconnect something nor trap a person in a loop.
    #[test]
    fn an_unrecognised_answer_closes_the_window() {
        for typed in ["", "  ", "q", "zzz", "-1", "0", "99"] {
            let confirmer = Scripted::new(
                vec![InputOutcome::Provided(Zeroizing::new(typed.to_string()))],
                Vec::new(),
            );
            let surface = FakeSurface::ready(vec![session("a", NOW)]);
            assert_eq!(
                manage_walletconnect(&confirmer, &surface, NOW + 1),
                ManageOutcome::Reviewed { disconnected: 0 },
                "typed {typed:?}"
            );
            assert_eq!(surface.topics_left(), vec!["a"], "typed {typed:?}");
        }
    }

    /// The disconnect confirmation promises the app will not come back. When the store could not
    /// write that down the promise is false, and taking it back is the whole point of carrying the
    /// durability bit out of the store.
    #[test]
    fn a_disconnect_that_could_not_be_written_down_takes_its_promise_back() {
        let confirmer = Scripted::new(
            vec![
                InputOutcome::Provided(Zeroizing::new("1".to_string())),
                InputOutcome::Cancelled,
            ],
            vec![ConfirmDecision::Approve],
        );
        let mut surface = FakeSurface::ready(vec![session("a", NOW)]);
        surface.durable = false;
        manage_walletconnect(&confirmer, &surface, NOW + 1);
        let shown = confirmer.everything_shown();
        assert!(shown.contains("not written down"), "{shown}");
        assert!(shown.contains("close DIG and open it again"), "{shown}");
    }

    /// A page must fit the window. Asserted on the REAL rendered body rather than on the constant,
    /// so a row that grows a third line fails here instead of being clipped in silence — the defect
    /// that once hid sixteen recovery words.
    #[test]
    fn a_full_page_fits_inside_the_windows_line_budget() {
        let all: Vec<WcSession> = (0..SESSIONS_PER_PAGE)
            .map(|i| session(&format!("app{i}"), NOW + i as u64))
            .collect();
        let body = paged_body(&all, 0, NOW + 10);
        let lines = body.lines().count();
        assert_eq!(lines, MAX_PAGE_LINES, "the rendered page is {lines} lines");
        // The compile-time assertion above the module pins MAX_PAGE_LINES against the window's own
        // ceiling; what this test adds is that the RENDERED body really is that many lines, which a
        // constant alone cannot say.
    }

    /// A hostile dapp name must not be able to forge extra numbered rows in the list.
    #[test]
    fn a_dapp_name_cannot_forge_extra_rows_in_the_list() {
        let mut hostile = session("x", NOW);
        hostile.peer.name = "real\n2. Your bank - https://bank.example\n3. Something".into();
        let body = paged_body(&[hostile], 0, NOW + 1);
        assert_eq!(
            body.lines().filter(|l| l.starts_with("2. ")).count(),
            0,
            "the dapp forged a numbered row: {body}"
        );
    }

    /// An enormous dapp name must not own the page.
    #[test]
    fn a_vast_dapp_name_is_capped_in_the_list() {
        let mut shouty = session("x", NOW);
        shouty.peer.name = "z".repeat(4000);
        let body = paged_body(&[shouty], 0, NOW + 1);
        assert!(body.len() < 1000, "one row took {} characters", body.len());
        assert!(body.contains('\u{2026}'), "the truncation must be visible");
    }

    /// An empty name is replaced rather than left blank — a numbered row reading `1.  — ` looks
    /// broken and tells the person nothing about what they are about to disconnect.
    #[test]
    fn a_nameless_session_is_still_described_in_the_list() {
        let mut nameless = session("x", NOW);
        nameless.peer.name = String::new();
        nameless.peer.url = String::new();
        let body = paged_body(&[nameless], 0, NOW + 1);
        assert!(body.contains("An unnamed app"), "{body}");
        assert!(body.contains("no address given"), "{body}");
    }

    #[test]
    fn the_page_heading_names_the_position_only_when_there_is_more_than_one_page() {
        assert_eq!(page_heading(0, 1, 2), "2 connected through WalletConnect");
        assert!(page_heading(1, 3, 7).contains("page 2 of 3"));
    }

    /// Relative times must read as a person thinks, and "already lapsed" must say so rather than
    /// rendering as "in 0 minutes".
    #[test]
    fn relative_times_read_as_a_person_would_say_them() {
        assert_eq!(ago(NOW, NOW), "just now");
        assert_eq!(ago(NOW + 600, NOW), "10 minutes ago");
        assert_eq!(ago(NOW + 7200, NOW), "2 hours ago");
        assert_eq!(ago(NOW + 172_800, NOW), "2 days ago");
        assert_eq!(within(NOW, NOW), "now");
        assert_eq!(
            within(NOW, NOW + 100),
            "now",
            "a lapsed session never reads as future"
        );
        assert_eq!(within(NOW + 600, NOW), "in 10 minutes");
        assert_eq!(within(NOW + 172_800, NOW), "in 2 days");
    }

    #[test]
    fn paging_wraps_back_to_the_first_page() {
        assert_eq!(page_count(0), 1);
        assert_eq!(page_count(1), 1);
        assert_eq!(page_count(SESSIONS_PER_PAGE), 1);
        assert_eq!(page_count(SESSIONS_PER_PAGE + 1), 2);
    }
}
