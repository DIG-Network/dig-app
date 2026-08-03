//! Pairing an app, and managing the ones already paired — the human half of dig_ecosystem#1848.
//!
//! [`crate::pairing_code`] can mint a code and [`crate::loopback`] can redeem one, but a code nobody can
//! ask for pairs nothing, and a pairing nobody can see cannot be revoked. This module is the journey
//! between them: the tray's two verbs, written as pure logic over the [`NativeConfirmer`] seam so every
//! decision is unit-tested rather than living untestably in the shell binary.
//!
//! # Why the user starts the pairing, and the app never does
//!
//! [`offer_pairing_code`] is reachable ONLY from the tray. An app cannot ask for a code, which is what
//! makes it impossible for a hostile local process to put a window in front of someone and hope for a
//! mis-click: with no code outstanding, `pair.begin` is refused having drawn nothing at all. The cost is
//! this entry point, and it is worth paying.
//!
//! # Why the list is paged rather than long
//!
//! The prompt window draws its body into a fixed area with no scrollbar, so a list of N apps would
//! overrun it for a large enough N — and a body that overran used to be CLIPPED IN SILENCE. That defect hid sixteen of twenty-four
//! recovery words (dig_ecosystem#49), so nothing here is allowed to depend on the list being short:
//! [`APPS_PER_PAGE`] apps are shown at a time, the page says how many there are in total, and moving
//! between pages is a typed choice. The page's line count is pinned by a test, not by hope.

use crate::confirm::{
    ClaimPrompt, ConfirmDecision, InputOutcome, InputPrompt, NativeConfirmer, NoticePrompt,
};
use crate::loopback::PairedAppsControl;
use crate::pairing::PairedApp;
use crate::pairing_code::{PairingCode, CODE_TTL_SECS};
use crate::sealer::ProfileSealer;

/// How many apps one management page lists.
///
/// Three, and the arithmetic is the reason: each app costs `LINES_PER_APP` lines and the page spends
/// `FIXED_PAGE_LINES` on its header and its instruction, so a full page is 3 × 2 + 2 = 8 lines —
/// comfortably inside the window's [`WINDOW_BODY_LINE_CEILING`] and short enough to survive a heavily
/// scaled display, where the derived budget is smaller than the ceiling. `paged_body` is tested
/// against that number rather than trusted to stay under it.
pub const APPS_PER_PAGE: usize = 3;

/// Lines one listed app occupies: its name and what it is, then when it was paired and last heard from.
const LINES_PER_APP: usize = 2;

/// Lines a page spends on anything other than the apps themselves.
const FIXED_PAGE_LINES: usize = 2;

/// The largest body any page of this window emits, in lines. Pinned by a test against the real
/// rendered body, and by the compile-time assertion below against the window's ceiling.
pub const MAX_PAGE_LINES: usize = APPS_PER_PAGE * LINES_PER_APP + FIXED_PAGE_LINES;

/// The most body lines the prompt window shows WITHOUT the reader having to scroll.
///
/// Derived, not guessed: the window is 560 px, of which 68 px is chrome and padding and 88 px is the
/// action row, leaving 404 px of body; a body line is `size::BASE * 1.55` = 23.25 px. So
/// `404 / 23.25` = 17 lines. The number that stood here — 32 — described no window that has ever
/// existed (32 lines is 744 px against 404 px of room), so the assertion below silently guarded
/// nothing (dig_ecosystem#2038).
const WINDOW_BODY_LINE_CEILING: usize = 17;

// A page that outgrew the window used to be CLIPPED IN SILENCE — the defect that hid sixteen recovery
// words (dig_ecosystem#49). The body now scrolls, so an overrun is reachable rather than lost; a page
// the user has to scroll to finish reading is still the wrong page, so raising APPS_PER_PAGE past what
// the window shows at a glance fails the BUILD rather than shipping a list that needs scrolling.
const _: () = assert!(MAX_PAGE_LINES <= WINDOW_BODY_LINE_CEILING);

/// The tray's view of the live pairing surface.
///
/// A trait rather than the concrete [`PairedAppsControl`] so the journey below is exercised against a
/// double — the flows worth testing are "the user typed 2 and confirmed" and "the user cancelled", and
/// neither should need an unlocked account and a sealed store to reach.
pub trait PairedApps {
    /// Mint a code for the user to carry to their app, replacing any outstanding one.
    fn issue_code(&self, now: u64) -> PairingCode;
    /// Every app currently paired, oldest first.
    fn list(&self) -> Vec<PairedApp>;
    /// Revoke one app; `true` if it was paired.
    fn revoke(&self, pairing_id: &str) -> bool;
    /// Destroy any outstanding code. Used when the window that was to display one could not be drawn:
    /// a secret nobody has seen must not sit there for its full lifetime waiting to be guessed at.
    fn cancel_code(&self);
}

impl<S: ProfileSealer> PairedApps for PairedAppsControl<S> {
    fn issue_code(&self, now: u64) -> PairingCode {
        PairedAppsControl::issue_code(self, now)
    }
    fn list(&self) -> Vec<PairedApp> {
        PairedAppsControl::list(self)
    }
    fn revoke(&self, pairing_id: &str) -> bool {
        PairedAppsControl::revoke(self, pairing_id)
    }
    fn cancel_code(&self) {
        PairedAppsControl::cancel_code(self)
    }
}

/// What came of offering a pairing code.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PairOutcome {
    /// The code reached the screen. Whether an app then redeems it is out of this journey's hands.
    CodeShown,
    /// No window could be drawn, so the user never saw the code. The code is CANCELLED rather than left
    /// outstanding — a secret nobody has seen must not sit there waiting to be guessed at.
    Unavailable,
}

/// What came of the management journey.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ManageOutcome {
    /// Nothing is paired. The user was told so, and told how to pair something.
    NothingPaired,
    /// The user looked through the list and revoked `revoked` apps (often zero, which is a fine
    /// outcome — most openings of this window are to check, not to change).
    Reviewed {
        /// How many apps had their access revoked.
        revoked: usize,
    },
    /// No window could be drawn. Nothing was changed.
    Unavailable,
}

/// Mint a pairing code and show it to the user (§5.6.3a).
///
/// The window says the code, how long it lasts, what to do with it, and — importantly — what the app
/// will be able to do once paired, because "approve" is not informed consent if the thing being
/// approved is unstated.
pub fn offer_pairing_code(
    confirmer: &dyn NativeConfirmer,
    apps: &dyn PairedApps,
    now: u64,
) -> PairOutcome {
    let code = apps.issue_code(now);
    let body = format!(
        "Type this code into the app you want to pair:\n\n    {}\n\n\
         The code works once, and only for the next {} minutes.\n\n\
         DIG will then ask you to approve the app by name before it gets access. An app paired this \
         way can connect websites to your DIG Account — it can NEVER ask you to sign anything.\n\n\
         Only give this code to an app you trust. Anyone who has it can ask to pair.",
        code.display(),
        CODE_TTL_SECS / 60,
    );
    let decision = confirmer.show_notice(&NoticePrompt {
        title: "DIG - Pair an app",
        heading: "Your pairing code",
        body: &body,
        acknowledge: "Done",
    });

    if matches!(decision, ConfirmDecision::Unavailable) {
        // The user never saw it, so nothing can legitimately redeem it. Leaving it outstanding would
        // leave a live secret behind a window that failed to open.
        apps.cancel_code();
        return PairOutcome::Unavailable;
    }
    PairOutcome::CodeShown
}

/// Show what is paired and let the user revoke any of it (§5.6.3a).
///
/// The loop is: a page of apps → the user types a number to revoke one, `n` for the next page, or
/// nothing to close. Cancelling ALWAYS closes, from any page — a management window a person cannot get
/// out of without answering something is the trap `professional-ui` forbids.
pub fn manage_paired_apps(
    confirmer: &dyn NativeConfirmer,
    apps: &dyn PairedApps,
    now: u64,
) -> ManageOutcome {
    let mut revoked = 0usize;
    let mut page = 0usize;

    loop {
        let listed = apps.list();
        if listed.is_empty() {
            // Either nothing was ever paired, or the user has just revoked the last one. Both deserve
            // the same window: saying "nothing is paired" and naming the way to change that, rather
            // than closing onto silence.
            let heading = if revoked == 0 {
                "No apps are paired with your DIG Account"
            } else {
                "No apps are paired with your DIG Account any more"
            };
            confirmer.show_notice(&NoticePrompt {
                title: "DIG - Paired apps",
                heading,
                body: "Nothing on this computer can use your DIG Account through another program.\n\n\
                       To pair one, choose \"Pair an app…\" from the Security menu. DIG shows you a \
                       code, you type it into the app, and DIG asks you to approve it by name.",
                acknowledge: "Close",
            });
            return if revoked == 0 {
                ManageOutcome::NothingPaired
            } else {
                ManageOutcome::Reviewed { revoked }
            };
        }

        let pages = page_count(listed.len());
        page = page.min(pages - 1);
        let shown = page_slice(&listed, page);
        let body = paged_body(&listed, page, now);

        let outcome = confirmer.request_input(&InputPrompt {
            title: "DIG - Paired apps",
            heading: &page_heading(page, pages, listed.len()),
            body: &body,
            field_label: "Number to remove (or leave empty):",
            submit: "Continue",
            // Nothing secret is typed here — masking a list index would only make it hard to check.
            masked: false,
            revealable: false,
            style: crate::confirm::InputStyle::Dialog,
        });

        let typed = match outcome {
            InputOutcome::Provided(typed) => typed.trim().to_string(),
            // The escape hatch, and it is unconditional: cancelling closes from any page.
            InputOutcome::Cancelled => return ManageOutcome::Reviewed { revoked },
            InputOutcome::Unavailable => {
                return if revoked == 0 {
                    ManageOutcome::Unavailable
                } else {
                    ManageOutcome::Reviewed { revoked }
                }
            }
        };

        match parse_choice(&typed, shown.len()) {
            Choice::Close => return ManageOutcome::Reviewed { revoked },
            Choice::NextPage => page = (page + 1) % pages,
            Choice::Revoke(index) => {
                let app = &shown[index];
                if confirm_revoke(confirmer, app) && apps.revoke(&app.pairing_id) {
                    revoked += 1;
                    // Any page number may now be past the end; the top of the loop re-clamps it.
                    page = 0;
                }
            }
        }
    }
}

/// Put the revoke to the user before doing it, and say what it costs.
///
/// A [`ClaimPrompt`] rather than a notice because the answer BRANCHES, and not a destroy/security
/// prompt because nothing is weakened or lost: revoking withdraws access, which is the safe direction,
/// and demanding a biometric to make an account safer would teach people to leave it unsafe.
fn confirm_revoke(confirmer: &dyn NativeConfirmer, app: &PairedApp) -> bool {
    let body = format!(
        "\"{}\" will lose access immediately - not at the next restart.\n\n\
         Anything it is doing through your DIG Account stops working straight away. If you want it \
         back later, pair it again with a new code.\n\n\
         Identified to DIG as: {}",
        display_name(app),
        app.ext_id,
    );
    matches!(
        confirmer.confirm_claim(&ClaimPrompt {
            // Nothing to scan: revoking access is a yes/no about an app already paired.
            scannable: None,
            title: "DIG - Remove an app's access",
            heading: "Remove this app's access?",
            body: &body,
            affirm: "Remove its access",
        }),
        ConfirmDecision::Approve
    )
}

/// What the user typed on a management page.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Choice {
    /// Close the window — an empty answer, or anything that is not a listed number or the page key.
    Close,
    /// Show the next page.
    NextPage,
    /// Revoke the app at this index WITHIN THE CURRENT PAGE.
    Revoke(usize),
}

/// Read the typed answer against a page holding `shown` apps.
///
/// Anything unrecognised CLOSES rather than being re-asked. A window that answers a typo by asking
/// again is a window a confused person cannot leave, and the cost of closing is one more menu click.
/// A number outside the page is treated the same way, so `9` on a page of two cannot revoke anything.
fn parse_choice(typed: &str, shown: usize) -> Choice {
    let typed = typed.trim();
    if typed.is_empty() {
        return Choice::Close;
    }
    if typed.eq_ignore_ascii_case("n") || typed.eq_ignore_ascii_case("next") {
        return Choice::NextPage;
    }
    match typed.parse::<usize>() {
        Ok(number) if number >= 1 && number <= shown => Choice::Revoke(number - 1),
        _ => Choice::Close,
    }
}

/// How many pages `total` apps occupy — at least one, so an empty list still has a page to clamp to.
fn page_count(total: usize) -> usize {
    total.div_ceil(APPS_PER_PAGE).max(1)
}

/// The apps on `page`.
fn page_slice(apps: &[PairedApp], page: usize) -> &[PairedApp] {
    let start = (page * APPS_PER_PAGE).min(apps.len());
    let end = (start + APPS_PER_PAGE).min(apps.len());
    &apps[start..end]
}

/// The heading for `page` — which page, and how many apps there are in total.
///
/// Kept short deliberately: this window class clips a heading at roughly 52 characters, so the count
/// belongs here and everything else belongs in the body.
fn page_heading(page: usize, pages: usize, total: usize) -> String {
    let apps = if total == 1 { "app" } else { "apps" };
    if pages == 1 {
        format!("{total} {apps} can use your DIG Account")
    } else {
        format!("{total} {apps} - page {} of {pages}", page + 1)
    }
}

/// The body for one page: the apps on it, numbered from 1, then how to answer.
///
/// Numbering restarts at 1 on every page, and the field label says "number to remove", so what the user
/// types always refers to what is in front of them — a running index across pages would mean typing 7
/// on a page showing 1–3.
fn paged_body(apps: &[PairedApp], page: usize, now: u64) -> String {
    let shown = page_slice(apps, page);
    let mut lines: Vec<String> = Vec::with_capacity(MAX_PAGE_LINES);
    for (index, app) in shown.iter().enumerate() {
        lines.push(format!(
            "{}. {} - {}",
            index + 1,
            display_name(app),
            app.scope.summary()
        ));
        // The two halves are built as whole clauses rather than one template with a substituted
        // phrase: "last used not since DIG started" is what the template produced, and it read as
        // broken English on the screenshot that caught it.
        lines.push(format!(
            "    paired {}, {}",
            since(app.paired_at, now),
            match app.last_seen_at {
                Some(seen) => format!("last used {}", since(seen, now)),
                None => "not used since DIG started".to_string(),
            }
        ));
    }
    lines.push(String::new());
    lines.push(if page_count(apps.len()) > 1 {
        "Type a number to remove that app, \"n\" for the next page, or leave it empty to close."
            .to_string()
    } else {
        "Type a number to remove that app, or leave it empty to close.".to_string()
    });
    lines.join("\n")
}

/// What to call an app on screen: the name it gave, else the id it authenticates as.
///
/// The name is CALLER-SUPPLIED and untrusted, which is why the id is always shown too — on the revoke
/// confirmation in full, so a program calling itself "DIG" cannot pass itself off as one.
fn display_name(app: &PairedApp) -> &str {
    match app.label.as_deref() {
        Some(label) if !label.trim().is_empty() => label,
        _ => &app.ext_id,
    }
}

/// A rough, human "how long ago" for `then` seen from `now`.
///
/// Rough on purpose: the question this answers is "is this thing still around", and to that "3 days
/// ago" is the whole answer. A clock that runs backwards (an NTP correction between the two readings)
/// reads as "just now" rather than as a negative duration.
fn since(then: u64, now: u64) -> String {
    let seconds = now.saturating_sub(then);
    let (count, unit) = match seconds {
        0..=90 => return "just now".to_string(),
        // The bands hand over exactly where the larger unit becomes whole, so nothing ever reads
        // "60 minutes ago" or "48 hours ago" — a person would say an hour, and two days.
        91..=3_599 => (seconds / 60, "minute"),
        3_600..=172_799 => (seconds / 3_600, "hour"),
        _ => (seconds / 86_400, "day"),
    };
    let plural = if count == 1 { "" } else { "s" };
    format!("{count} {unit}{plural} ago")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pairing::PairingScope;
    use std::cell::RefCell;
    use std::sync::Mutex;

    /// A PINNED instant. Every "how long ago" below is relative to this, so the fixture cannot drift
    /// into rendering everything as "a very long time ago" against a wall clock.
    const NOW: u64 = 1_800_000_000;

    fn app(id: &str, label: Option<&str>, paired_at: u64, last_seen: Option<u64>) -> PairedApp {
        PairedApp {
            pairing_id: format!("pairing-{id}"),
            ext_id: format!("com.example.{id}"),
            label: label.map(str::to_string),
            scope: PairingScope::ThirdParty,
            capabilities: Default::default(),
            paired_at,
            last_seen_at: last_seen,
        }
    }

    fn apps(count: usize) -> Vec<PairedApp> {
        (0..count)
            .map(|i| {
                app(
                    &format!("app{i}"),
                    Some(&format!("App {i}")),
                    NOW - 86_400,
                    None,
                )
            })
            .collect()
    }

    /// A double for the live surface, recording what the journey did to it.
    struct FakeApps {
        listed: RefCell<Vec<PairedApp>>,
        revoked: RefCell<Vec<String>>,
        issued: RefCell<Vec<u64>>,
        cancelled: RefCell<bool>,
    }

    impl FakeApps {
        fn with(listed: Vec<PairedApp>) -> Self {
            Self {
                listed: RefCell::new(listed),
                revoked: RefCell::new(Vec::new()),
                issued: RefCell::new(Vec::new()),
                cancelled: RefCell::new(false),
            }
        }
    }

    impl PairedApps for FakeApps {
        fn issue_code(&self, now: u64) -> PairingCode {
            self.issued.borrow_mut().push(now);
            crate::pairing_code::PairingCodeIssuer::new().issue(now)
        }
        fn list(&self) -> Vec<PairedApp> {
            self.listed.borrow().clone()
        }
        fn cancel_code(&self) {
            *self.cancelled.borrow_mut() = true;
        }
        fn revoke(&self, pairing_id: &str) -> bool {
            self.revoked.borrow_mut().push(pairing_id.to_string());
            let mut listed = self.listed.borrow_mut();
            let before = listed.len();
            listed.retain(|a| a.pairing_id != pairing_id);
            listed.len() != before
        }
    }

    /// A confirmer that replays a SCRIPT of typed answers and claim decisions, and records every body
    /// it was asked to draw.
    ///
    /// It can vary each answer independently — a double that could only return one fixed reply could
    /// not express "the user paged, then revoked, then closed", which is the only sequence that
    /// exercises the loop.
    struct ScriptedUser {
        typed: Mutex<Vec<InputOutcome>>,
        claims: Mutex<Vec<ConfirmDecision>>,
        bodies: Mutex<Vec<String>>,
        notices: Mutex<Vec<String>>,
        notice_decision: ConfirmDecision,
    }

    impl ScriptedUser {
        fn typing(answers: Vec<&str>) -> Self {
            Self {
                typed: Mutex::new(
                    answers
                        .into_iter()
                        .map(|a| InputOutcome::Provided(zeroize::Zeroizing::new(a.to_string())))
                        .rev()
                        .collect(),
                ),
                claims: Mutex::new(Vec::new()),
                bodies: Mutex::new(Vec::new()),
                notices: Mutex::new(Vec::new()),
                notice_decision: ConfirmDecision::Approve,
            }
        }

        fn approving_every_revoke(self) -> Self {
            *self.claims.lock().unwrap() = vec![ConfirmDecision::Approve; 8];
            self
        }

        fn refusing_every_revoke(self) -> Self {
            *self.claims.lock().unwrap() = vec![ConfirmDecision::Deny; 8];
            self
        }
    }

    impl NativeConfirmer for ScriptedUser {
        fn confirm_pair(&self, _: &crate::confirm::PairPrompt<'_>) -> ConfirmDecision {
            ConfirmDecision::Approve
        }
        fn confirm_connect(&self, _: &crate::confirm::ConnectPrompt<'_>) -> ConfirmDecision {
            ConfirmDecision::Approve
        }
        fn confirm_sign(&self, _: &crate::confirm::SignPrompt<'_>) -> ConfirmDecision {
            ConfirmDecision::Approve
        }
        fn show_notice(&self, prompt: &NoticePrompt<'_>) -> ConfirmDecision {
            // Heading AND body: a window's meaning is split across both, and recording only one
            // would let a test pass while the sentence the user actually reads went missing.
            self.notices.lock().unwrap().push(format!(
                "{}
{}",
                prompt.heading, prompt.body
            ));
            self.notice_decision
        }
        fn confirm_claim(&self, prompt: &ClaimPrompt<'_>) -> ConfirmDecision {
            self.bodies.lock().unwrap().push(prompt.body.to_string());
            self.claims
                .lock()
                .unwrap()
                .pop()
                .unwrap_or(ConfirmDecision::Deny)
        }
        fn request_input(&self, prompt: &InputPrompt<'_>) -> InputOutcome {
            self.bodies.lock().unwrap().push(prompt.body.to_string());
            self.typed
                .lock()
                .unwrap()
                .pop()
                .unwrap_or(InputOutcome::Cancelled)
        }
    }

    #[test]
    fn the_code_window_says_the_code_the_deadline_and_the_limit() {
        let apps = FakeApps::with(Vec::new());
        let user = ScriptedUser::typing(Vec::new());
        assert_eq!(
            offer_pairing_code(&user, &apps, NOW),
            PairOutcome::CodeShown
        );

        let shown = &user.notices.lock().unwrap()[0];
        assert!(shown.contains('-'), "the code is on screen: {shown}");
        assert!(shown.contains("2 minutes"), "the deadline is stated");
        assert!(
            shown.contains("NEVER ask you to sign"),
            "approving is not informed consent if the limit is unstated: {shown}"
        );
        assert_eq!(apps.issued.borrow().len(), 1);
    }

    #[test]
    fn a_code_the_user_never_saw_is_destroyed() {
        // A window that failed to open leaves a live secret nobody has read. It must not sit there for
        // its full lifetime waiting to be guessed at.
        let apps = FakeApps::with(Vec::new());
        let mut user = ScriptedUser::typing(Vec::new());
        user.notice_decision = ConfirmDecision::Unavailable;

        assert_eq!(
            offer_pairing_code(&user, &apps, NOW),
            PairOutcome::Unavailable
        );
        assert_eq!(apps.issued.borrow().len(), 1);
        assert!(
            *apps.cancelled.borrow(),
            "an unseen code must be destroyed, not left outstanding"
        );
    }

    #[test]
    fn with_nothing_paired_the_window_says_so_and_names_the_remedy() {
        // Not a dead end and not an empty list: the one thing a person can do next is named
        // (dig_ecosystem#1800).
        let apps = FakeApps::with(Vec::new());
        let user = ScriptedUser::typing(Vec::new());
        assert_eq!(
            manage_paired_apps(&user, &apps, NOW),
            ManageOutcome::NothingPaired
        );
        let notice = &user.notices.lock().unwrap()[0];
        assert!(notice.contains("Pair an app"), "{notice}");
    }

    #[test]
    fn typing_a_number_revokes_that_app_after_a_confirmation() {
        let apps = FakeApps::with(apps(2));
        // "2" revokes the second app; the list then holds one, and "" closes.
        let user = ScriptedUser::typing(vec!["2", ""]).approving_every_revoke();

        assert_eq!(
            manage_paired_apps(&user, &apps, NOW),
            ManageOutcome::Reviewed { revoked: 1 }
        );
        assert_eq!(*apps.revoked.borrow(), vec!["pairing-app1".to_string()]);
    }

    #[test]
    fn refusing_the_confirmation_revokes_nothing() {
        // The nearest wrong implementation revokes first and asks afterwards; it would pass the test
        // above and fail this one.
        let apps = FakeApps::with(apps(2));
        let user = ScriptedUser::typing(vec!["1", ""]).refusing_every_revoke();

        assert_eq!(
            manage_paired_apps(&user, &apps, NOW),
            ManageOutcome::Reviewed { revoked: 0 }
        );
        assert!(apps.revoked.borrow().is_empty());
        assert_eq!(apps.list().len(), 2, "both apps are still paired");
    }

    #[test]
    fn the_revoke_confirmation_names_the_app_and_its_real_id() {
        // The label is caller-supplied. Showing it WITHOUT the id would let a program calling itself
        // "DIG Browser Extension" be revoked — or kept — under a name it chose for itself.
        let apps = FakeApps::with(vec![app("tool", Some("DIG Browser Extension"), NOW, None)]);
        let user = ScriptedUser::typing(vec!["1", ""]).refusing_every_revoke();
        manage_paired_apps(&user, &apps, NOW);

        let confirmation = user
            .bodies
            .lock()
            .unwrap()
            .iter()
            .find(|b| b.contains("lose access immediately"))
            .cloned()
            .expect("a revoke confirmation was drawn");
        assert!(confirmation.contains("DIG Browser Extension"));
        assert!(
            confirmation.contains("com.example.tool"),
            "the id it actually authenticates as must be on screen: {confirmation}"
        );
    }

    #[test]
    fn cancelling_closes_from_any_page_without_revoking_anything() {
        // The escape hatch. A management window a person cannot leave without answering something is
        // the trap professional-ui forbids — and with more apps than fit on a page, "keep clicking
        // through" is not an exit.
        let apps = FakeApps::with(apps(7));
        let user = ScriptedUser::typing(vec!["n"]); // page forward, then the script runs dry: Cancelled
        assert_eq!(
            manage_paired_apps(&user, &apps, NOW),
            ManageOutcome::Reviewed { revoked: 0 }
        );
        assert!(apps.revoked.borrow().is_empty());
    }

    #[test]
    fn every_app_is_reachable_by_paging_and_none_is_silently_dropped() {
        // The anti-truncation property, stated as behaviour rather than as a line count: with more
        // apps than one page holds, paging must eventually SHOW each one. An implementation that
        // rendered only the first page — the #49 defect — passes every single-page test.
        let listed = apps(7);
        let apps_double = FakeApps::with(listed.clone());
        let user = ScriptedUser::typing(vec!["n", "n", "n", ""]);
        manage_paired_apps(&user, &apps_double, NOW);

        let everything_drawn = user.bodies.lock().unwrap().join("\n");
        for app in &listed {
            assert!(
                everything_drawn.contains(app.label.as_deref().unwrap()),
                "{} was never shown to the user",
                app.pairing_id
            );
        }
    }

    #[test]
    fn a_full_page_stays_within_the_window_classs_line_budget() {
        // The number in MAX_PAGE_LINES is a CLAIM about a window that clips in silence. This checks it
        // against the real rendered body rather than against the arithmetic that produced it.
        let listed = apps(APPS_PER_PAGE * 3);
        let body = paged_body(&listed, 0, NOW);
        assert_eq!(body.lines().count(), MAX_PAGE_LINES);
    }

    #[test]
    fn a_number_outside_the_page_closes_rather_than_revoking_something_else() {
        // Off-by-one insurance on the one control that removes access: `4` on a page of three must not
        // reach the first app of the next page.
        assert_eq!(parse_choice("4", 3), Choice::Close);
        assert_eq!(parse_choice("0", 3), Choice::Close);
        assert_eq!(parse_choice("1", 3), Choice::Revoke(0));
        assert_eq!(parse_choice("3", 3), Choice::Revoke(2));
        assert_eq!(parse_choice("-1", 3), Choice::Close);
        assert_eq!(parse_choice("banana", 3), Choice::Close);
        assert_eq!(parse_choice("", 3), Choice::Close);
        assert_eq!(parse_choice("  2  ", 3), Choice::Revoke(1));
        assert_eq!(parse_choice("n", 3), Choice::NextPage);
        assert_eq!(parse_choice("NEXT", 3), Choice::NextPage);
    }

    #[test]
    fn an_app_with_no_name_is_shown_by_the_id_it_authenticates_as() {
        // Never a blank row: an app that gave no label still has to be identifiable enough to revoke.
        let nameless = app("silent", None, NOW - 60, None);
        assert_eq!(display_name(&nameless), "com.example.silent");
        let blank = app("blank", Some("   "), NOW - 60, None);
        assert_eq!(display_name(&blank), "com.example.blank");
    }

    #[test]
    fn the_page_says_what_each_app_may_do_and_when_it_last_spoke() {
        let listed = vec![PairedApp {
            scope: PairingScope::ThirdParty,
            capabilities: Default::default(),
            last_seen_at: Some(NOW - 7_200),
            ..app("tool", Some("A Tool"), NOW - 172_800 * 2, None)
        }];
        let body = paged_body(&listed, 0, NOW);
        assert!(body.contains("A Tool"));
        assert!(body.contains("cannot ask you to sign anything"));
        assert!(body.contains("2 hours ago"), "{body}");
        assert!(body.contains("4 days ago"), "{body}");
    }

    #[test]
    fn an_app_that_has_not_spoken_says_so_rather_than_showing_a_time() {
        let listed = vec![app("quiet", Some("Quiet"), NOW - 3_600, None)];
        let body = paged_body(&listed, 0, NOW);
        assert!(body.contains("not used since DIG started"), "{body}");
        assert!(
            !body.contains("last used not"),
            "the two clauses must not be glued into broken English: {body}"
        );
    }

    #[test]
    fn how_long_ago_reads_like_a_person_would_say_it() {
        assert_eq!(since(NOW, NOW), "just now");
        assert_eq!(since(NOW - 90, NOW), "just now");
        assert_eq!(since(NOW - 120, NOW), "2 minutes ago");
        assert_eq!(since(NOW - 3_600, NOW), "1 hour ago");
        assert_eq!(since(NOW - 86_400 * 3, NOW), "3 days ago");
        // A clock that jumped backwards must not render a negative age.
        assert_eq!(since(NOW + 500, NOW), "just now");
    }

    #[test]
    fn the_heading_fits_the_window_classs_clip_point() {
        // Headings clip around 52 characters in this class, so a heading that names a count must stay
        // short whatever the count is.
        for (total, pages) in [(1usize, 1usize), (9, 3), (1_000, 334)] {
            let heading = page_heading(0, pages, total);
            assert!(
                heading.chars().count() <= 52,
                "heading too long ({}): {heading}",
                heading.chars().count()
            );
        }
        assert!(page_heading(0, 1, 1).contains("1 app"));
        assert!(page_heading(1, 3, 9).contains("page 2 of 3"));
    }

    #[test]
    fn revoking_the_last_app_ends_on_the_nothing_paired_window() {
        // The list empties under the user's feet. Closing onto silence, or onto a page of nothing,
        // would both be worse than saying what happened.
        let apps = FakeApps::with(apps(1));
        let user = ScriptedUser::typing(vec!["1"]).approving_every_revoke();
        assert_eq!(
            manage_paired_apps(&user, &apps, NOW),
            ManageOutcome::Reviewed { revoked: 1 }
        );
        let notice = user.notices.lock().unwrap().join("\n");
        assert!(notice.contains("any more"), "{notice}");
    }
}
