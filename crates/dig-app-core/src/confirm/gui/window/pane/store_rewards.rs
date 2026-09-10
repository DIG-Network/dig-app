//! The Rewards section a person reaches from a Content-tab store row (dig_ecosystem#3273).
//!
//! # Why this is a disclosure on the store row and not a seventh tab
//!
//! dig-app's `SPEC.md` fixes six tabs — Home, Account, Wallet, Activity, Content, Settings — and
//! [`crate::window_model`]'s own `tab_id_all_is_still_the_six_labels` pins them. A reward
//! distributor also cannot exist without the store it pays for, and the store is a
//! [`HostedStore`](crate::hosted_stores::HostedStore) row on the Content tab. So the section hangs
//! off that row rather than standing on its own: the parent object is right above it, and no tab
//! was added to reach it.
//!
//! There is no store-DETAIL screen in this window today, and building one would mean adding a
//! screen to [`crate::window_model`], which this lane does not own. The disclosure is therefore IN
//! PLACE: the row grows the section beneath itself when the affordance is pressed. Collapsed is the
//! default, because four fact sentences under every one of five store rows is a wall of text over a
//! list a person opened to read store ids.
//!
//! # Why the reading is a process global, and not a field on `TrayView`
//!
//! The same reason [`crate::wallet::machine`]'s reading is one: `TrayView` is compared field by
//! field on every tick and destructured without a rest pattern, so two lanes adding a field to it
//! conflict by construction. The window repaints from a snapshot it does not own, and a paint
//! function must never perform I/O — so whatever reads the node writes the READING here, and this
//! module only ever renders what it finds.
//!
//! # Why an unremembered store is amber rather than empty
//!
//! No released dig-node answers `dig.listRewardDistributors` — it returns JSON-RPC `-32601`, method
//! not found — so on today's nodes nothing can map a store to a distributor at all. That is a fact
//! about the MACHINE with a real remedy (a newer node), which is why it is painted as
//! [`PaneState::Unreachable`] and NOT as [`PaneState::Empty`]: "no distributor exists for this
//! store" is a positive claim only an answered read may make, and making it from an unanswerable
//! one is the absence-as-zero failure SPEC §12.5 clause 6 forbids.
//!
//! # What this section deliberately does not show
//!
//! No claim status, no accrual, no entitlement, and no `eligible`/`claiming` word derived from a
//! distributor existing (SPEC §12.5 clause 6). No create, mint, refill or clawback affordance, not
//! even a disabled one: `dig.listRewardDistributorCommitments` is unserved, so a control here could
//! only ever fail (ship no dead control). Nothing here distinguishes a peer never admitted to the
//! entry set from one evicted from it (clause 7). Every figure a person reads comes from
//! [`crate::rewards::pane::rewards_sections`], which formats money through [`crate::amount`] and
//! states whose money each figure is.

use egui::{Rect, Ui};

use super::action::{self, Action};
use super::card;
use super::flow::Flow;
use super::state::{self, PaneState};
use crate::confirm::gui::render::{space, Weight};
use crate::confirm::gui::theme::Tokens;
use crate::i18n::{Args, Msg};
use crate::rewards::pane::{rewards_sections, PaneReading};
use crate::rewards::wire::RewardDistributorStatusRecord;

/// The reading this section renders: the whole three-state value, never an `Option`.
///
/// Named through [`crate::rewards::pane::PaneReading`] rather than re-declared, so the states this
/// section paints are the states the shipped fact layer already decided (SPEC §2.3).
pub type StoreRewardsReading = PaneReading<RewardDistributorStatusRecord>;

/// The section's own heading.
pub(crate) const SECTION_TITLE: Msg = Msg::new("content-store-rewards-title");
/// The affordance that opens the section.
pub(crate) const SHOW: Msg = Msg::new("content-store-rewards-show");
/// The affordance that closes it again.
pub(crate) const HIDE: Msg = Msg::new("content-store-rewards-hide");
/// A read is in flight. Names what is being waited for, and claims nothing about the answer.
const WAITING: Msg = Msg::new("content-store-rewards-waiting");
/// An ANSWERED read that found no distributor — the one sentence entitled to say none exists.
const EMPTY: Msg = Msg::new("content-store-rewards-empty");
/// No read has been taken, because no released node serves the method that would map this store to
/// a distributor. A distinct sentence from [`UNREACHABLE`]: nothing failed, nothing was asked.
const NOT_ANSWERABLE: Msg = Msg::new("content-store-rewards-not-answerable");
/// A read that was taken and failed, wrapping the node's own reason. Placeable: `why`.
const UNREACHABLE: Msg = Msg::new("content-store-rewards-unreachable");

/// The daily funding rate the cadence sentence is computed against.
///
/// Zero, and deliberately: no funding control ships in this pass, so no rate has been chosen. Zero
/// is what makes `CadenceReading::NoFundingRateChosen` reachable, which is the honest sentence — a
/// made-up rate would print a cadence nobody asked for.
const NO_FUNDING_RATE_CHOSEN: u64 = 0;

/// What the section has to say, decided before anything is laid out.
///
/// Separate from the drawing for the reason [`super::wallet_coins`]'s `SectionBody` is: the one
/// distinction a painted panel cannot express — a read that failed against a read that answered
/// with nothing, both of which show no facts — is settled in a value a test can compare.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum RewardsBody {
    /// A read is under way. Not a fault, and not a finding.
    Waiting,
    /// No facts, and the sentence saying why. Two different inputs reach this arm — an unanswerable
    /// node, and a read that failed — and they carry DIFFERENT sentences; they share the arm only
    /// because they share the painted treatment, which is amber with a remedy in it.
    Unreachable(String),
    /// A node answered, and this store has no reward distributor. A positive claim.
    Empty,
    /// The fact sentences to draw, in the order [`rewards_sections`] produced them.
    Facts(Vec<String>),
}

/// Which of the four things the section has to say, for what the app has been told about a store.
///
/// `remembered` is `None` when nothing has ever reported on this store — see the module docs for
/// why that is not the empty state.
pub(crate) fn body_of(remembered: Option<&StoreRewardsReading>, now: u64) -> RewardsBody {
    match remembered {
        None => RewardsBody::Unreachable(NOT_ANSWERABLE.text()),
        Some(PaneReading::Waiting) => RewardsBody::Waiting,
        Some(PaneReading::Unreachable(why)) => {
            RewardsBody::Unreachable(UNREACHABLE.with(&Args::new().text("why", *why)))
        }
        Some(PaneReading::Answered(None)) => RewardsBody::Empty,
        Some(PaneReading::Answered(Some(record))) => RewardsBody::Facts(
            rewards_sections(record, now, NO_FUNDING_RATE_CHOSEN)
                .into_iter()
                .filter_map(|section| section.heading)
                .collect(),
        ),
    }
}

impl RewardsBody {
    /// The banner state this body is drawn as, or `None` when it has facts to draw instead.
    ///
    /// Exhaustive, so a fifth body arm cannot be added without deciding its treatment here.
    fn as_state(&self) -> Option<PaneState> {
        match self {
            Self::Waiting => Some(PaneState::Waiting(WAITING.text())),
            Self::Unreachable(sentence) => Some(PaneState::Unreachable(sentence.clone())),
            Self::Empty => Some(PaneState::Empty(EMPTY.text())),
            Self::Facts(_) => None,
        }
    }
}

/// This process's per-store distributor readings, keyed by canonical lowercase 64-hex store id.
type Readings = std::collections::HashMap<String, StoreRewardsReading>;

/// The one place those readings live. See the module docs for why this is not a `TrayView` field.
fn app_readings() -> &'static std::sync::Mutex<Readings> {
    static READINGS: std::sync::OnceLock<std::sync::Mutex<Readings>> = std::sync::OnceLock::new();
    READINGS.get_or_init(|| std::sync::Mutex::new(Readings::new()))
}

/// Record what a read of one store's reward distributor found.
///
/// `store_id` is normalised by [`store_key`], so a caller holding the wire's `[u8; 32]` (through
/// [`store_key_of_bytes`]) and a caller holding the pane's string reach the same entry.
pub fn remember(store_id: &str, reading: StoreRewardsReading) {
    let Some(key) = store_key(store_id) else {
        return;
    };
    let mut held = app_readings().lock().unwrap_or_else(|e| e.into_inner());
    held.insert(key, reading);
}

/// What the app currently knows about one store's reward distributor, or `None` when nothing has
/// reported on it.
pub(crate) fn reading(store_id: &str) -> Option<StoreRewardsReading> {
    let key = store_key(store_id)?;
    let held = app_readings().lock().unwrap_or_else(|e| e.into_inner());
    held.get(&key).cloned()
}

/// Drop every remembered reading. For a gallery and for tests, never on a user path.
pub fn forget_all() {
    let mut held = app_readings().lock().unwrap_or_else(|e| e.into_inner());
    held.clear();
}

/// The canonical key for a store id, or `None` when the text is not one.
///
/// # Why this conversion is a tested function rather than an assumption
///
/// [`crate::hosted_stores::HostedStore::store_id`] is a lowercase 64-hex STRING, while the rewards
/// wire carries `store_id: [u8; 32]` ([`crate::rewards::wire`]). A lookup that compared the two
/// without converting would silently never match, and a Rewards section that never matched would
/// look exactly like a store that has no distributor — a wrong claim about money that no green test
/// would catch. So the conversion is named, and it has its own cases: an `0x` prefix is accepted
/// because this window prints store ids both ways, case is folded, and anything that is not 32
/// bytes of hex is refused rather than truncated.
pub(crate) fn store_key(store_id: &str) -> Option<String> {
    let text = store_id
        .strip_prefix("0x")
        .or_else(|| store_id.strip_prefix("0X"))
        .unwrap_or(store_id);
    if text.len() != 64 || !text.chars().all(|c| c.is_ascii_hexdigit()) {
        return None;
    }
    Some(text.to_ascii_lowercase())
}

/// The canonical key for a store id held as the rewards wire holds it.
///
/// The other half of [`store_key`]: the two together are what let a reading taken against a
/// `[u8; 32]` be found again by the string a row is drawn from.
pub fn store_key_of_bytes(store_id: [u8; 32]) -> String {
    use std::fmt::Write as _;
    store_id.iter().fold(String::with_capacity(64), |mut out, byte| {
        let _ = write!(out, "{byte:02x}");
        out
    })
}

/// Where the open/closed state of one store's section lives.
///
/// egui's per-frame store, keyed by the store id, for the reason every other pane's transient
/// control state is there: it survives a repaint, it is per-window, and it is not persisted — so a
/// section a person opened does not silently reopen weeks later on a row that has changed.
fn expand_id(store_id: &str) -> egui::Id {
    egui::Id::new("dig-content-store-rewards").with(store_id)
}

/// Whether this store's section is open. Closed unless something opened it.
pub(crate) fn is_expanded(ui: &Ui, store_id: &str) -> bool {
    ui.data(|d| d.get_temp::<bool>(expand_id(store_id)))
        .unwrap_or(false)
}

/// Open or close this store's section.
fn set_expanded(ui: &Ui, store_id: &str, open: bool) {
    ui.data_mut(|d| d.insert_temp(expand_id(store_id), open));
}

/// Open one store's section before the first frame, so a gallery can photograph it.
///
/// A committed screenshot must never be taken after synthetic input (dig_ecosystem#2309), and the
/// open state lives in egui's per-frame store — so the only honest way to picture an open section is
/// to put it there before anything is drawn, exactly as a click would have.
pub fn seed_expanded(ctx: &egui::Context, store_id: &str) {
    ctx.data_mut(|d| d.insert_temp(expand_id(store_id), true));
}

/// Draw the disclosure for one store — the affordance, and the section itself when it is open.
///
/// Returns the height used. `live` is the pane's own liveness: a pane drawn behind a modal senses
/// nothing, and an affordance that could be pressed there would act on a window nobody is looking
/// at.
pub(crate) fn disclosure(
    ui: &mut Ui,
    at: Rect,
    t: &Tokens,
    live: bool,
    store_id: &str,
    now: u64,
) -> f32 {
    let open = is_expanded(ui, store_id);
    let verb = Action {
        label: if open { HIDE.text() } else { SHOW.text() },
        weight: Weight::Ghost,
        enabled: live,
        id: (),
        element: expand_id(store_id).with("toggle"),
    };
    let (mut height, pressed) = action::buttons(ui, at, t, live, std::slice::from_ref(&verb));
    if pressed.is_some() {
        set_expanded(ui, store_id, !open);
    }
    if !open {
        return height;
    }

    height += space::S3;
    let body = body_of(reading(store_id).as_ref(), now);
    let panel_at = Rect::from_min_max(
        egui::Pos2::new(at.left(), at.top() + height),
        at.right_bottom(),
    );
    height += card::panel(ui, panel_at, t, Some(&SECTION_TITLE.text()), |inner| {
        section(inner, t, &body);
    });
    height
}

/// The section's body: one banner, or the fact sentences.
fn section(inner: &mut Flow, t: &Tokens, body: &RewardsBody) {
    if let Some(banner) = body.as_state() {
        inner.place(|ui, at| (state::banner(ui, at, t, &banner), ()));
        return;
    }
    let RewardsBody::Facts(sentences) = body else {
        return;
    };
    for (index, sentence) in sentences.iter().enumerate() {
        if index > 0 {
            inner.gap(space::S3);
        }
        let sentence = sentence.clone();
        inner.place(move |ui, at| (super::text::body(ui, at, t, &sentence), ()));
    }
}

/// The clock the staleness sentences are judged against, in unix seconds.
///
/// Read here rather than taken from the shell's snapshot because that snapshot is a view of the
/// NODE, while "how long ago was this observed" is a question about the reader's own clock — which
/// is exactly the disagreement `rewards::reading`'s clock-unusable state exists to report.
pub(crate) fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|elapsed| elapsed.as_secs())
        .unwrap_or(0)
}

/// Serialises the tests that write [`remember`], because the readings are a PROCESS global.
///
/// The same hazard [`crate::wallet::machine::test_lock`] exists for: cargo runs tests in parallel
/// threads within one process, so two tests that each seed a reading and clear it afterwards
/// interleave — one clears while the other is still painting against a record it seeded. That
/// failure is order-dependent, and an intermittent red reads as flake rather than as a defect.
#[cfg(test)]
pub(crate) fn test_lock() -> std::sync::MutexGuard<'static, ()> {
    static LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
    LOCK.lock().unwrap_or_else(|e| e.into_inner())
}

#[cfg(test)]
#[path = "store_rewards_tests.rs"]
mod tests;
