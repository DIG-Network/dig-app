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
//! # Why an unasked store is a NEUTRAL note — not the empty state, and not amber
//!
//! No dig-node build, released or otherwise, implements `dig.listRewardDistributors` — v0.256.0
//! serves `dig.getRewardProverStatus` only, and a call to the missing method returns JSON-RPC
//! `-32601`, method not found. The gap is on both sides of the wire: dig-app never sends the call
//! either (`remember`'s only caller is [`seed_preview`], which is gallery-only), so nothing maps a
//! store to a distributor today regardless of which node version is running. Two rules meet on
//! that fact.
//!
//! It is not [`RewardsBody::Empty`], because "no distributor exists for this store" is a positive
//! claim only an ANSWERED read may make, and making it from an unanswerable one is the
//! absence-as-zero failure SPEC §12.5 clause 6 forbids.
//!
//! And it is not amber either. Nothing failed, and nothing was even asked. An earlier revision of
//! this module painted it [`PaneState::Unreachable`], which made amber the ONLY state a real
//! install could reach — every store row, every machine, because nothing on a user path takes this
//! read yet — and a warning colour that appears unconditionally teaches people to ignore warning
//! colours, which is the exact reasoning [`super::content`]'s `unread` is built on
//! (dig_ecosystem#3273 adversarial gate, finding 5). So the unanswerable case is
//! [`RewardsBody::NotAnswerable`], drawn in the recessed treatment with the true cause named in the
//! sentence and no promised fix, and amber is reserved for a read that was taken and genuinely
//! failed. A node that answers
//! `-32601` to the read itself routes to that same neutral note through [`is_method_not_found`]:
//! "this node version cannot be asked" is what happened, not "the call broke".
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
//!
//! And no claim CADENCE, which is the fourth thing that function has to say — see
//! [`FACTS_THIS_MOUNT_CAN_SUPPORT`] for why a mount read by a payee omits the sentence written for
//! a funder.

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

/// How many of [`rewards_sections`]'s four sections this mount renders: the prover status, the
/// entry set and the payout total — its first three, in that order.
///
/// # Why the fourth, the claim cadence, is not one of them
///
/// [`crate::rewards::cadence`] is scoped in its own first line to "the claim cadence a funder is
/// shown BESIDE A CHOSEN FUNDING AMOUNT". This mount is the Content tab's "Capsules mirrored here"
/// card — a store THIS computer mirrors for someone else — so its reader is a payee, and there is
/// no funding amount beside it: no funding affordance ships anywhere in this app, disabled or
/// otherwise.
///
/// So the fourth sentence had nothing real to be computed from. An earlier revision of this module
/// passed a compiled-in `0` as the daily funding rate, which made
/// `CadenceReading::NoFundingRateChosen` the answer for every distributor with a written entry set,
/// whose English reads "Choose a funding rate to see how often a mirror would claim." Three things
/// were wrong with that at once: it addressed a mirror operator as the FUNDER, telling them the
/// rate they are paid at is theirs to set and that nothing accrues until they act; it was a dead
/// control made of words, since no funding affordance exists to obey it; and it rendered a
/// compiled-in zero as a claim about on-chain funding, which SPEC §2.6 clause 2 forbids
/// (dig_ecosystem#3273 adversarial gate, finding 1).
///
/// The remedy is subtraction, not substitution: a cadence is a fact that belongs beside an amount
/// the reader chose, this surface has no such amount, so this surface omits that fact. The
/// dropped section is proved to be the cadence one by
/// `store_rewards_tests::the_dropped_section_is_the_cadence_one_and_nothing_here_renders_it`.
const FACTS_THIS_MOUNT_CAN_SUPPORT: usize = 3;

/// The `daily_funding_base_units` argument [`rewards_sections`] takes for the ONE section this
/// mount drops (see [`FACTS_THIS_MOUNT_CAN_SUPPORT`]).
///
/// Nothing a person reads here is computed from it: the cadence section is the only consumer of
/// this argument inside [`rewards_sections`], and that section is discarded before a single
/// sentence is laid out. It is named rather than written as a bare `0` at the call site so that a
/// reader who finds a zero flowing into the money layer finds this paragraph attached to it.
///
/// The shape that would need no value at all is a `rewards_sections` that does not take a funding
/// rate — which lives in `crate::rewards`, read-only to this lane; reported upward rather than
/// worked around here.
const CADENCE_ARGUMENT_THIS_MOUNT_DISCARDS: u64 = 0;

/// Whether a failed read's reason is the node saying it does not serve the method.
///
/// JSON-RPC's `-32601` and its standard message spellings, matched against the reason the transport
/// hands up. That is the answer every dig-node released today gives to
/// `dig.listRewardDistributors`, and it is not a failure: the call arrived, the node answered, and
/// the answer was "I cannot be asked that". Painting it amber would report a working node as broken
/// and would put a fault banner on every row of every install (finding 5).
///
/// The numeric code is matched first because it is unambiguous; the message spellings are matched
/// too, because a transport is free to forward the text without the code.
fn is_method_not_found(reason: &str) -> bool {
    let reason = reason.to_ascii_lowercase();
    reason.contains("-32601")
        || reason.contains("method not found")
        || reason.contains("method_not_found")
        || reason.contains("unknown method")
}

/// What the section has to say, decided before anything is laid out.
///
/// Separate from the drawing for the reason [`super::wallet_coins`]'s `SectionBody` is: the one
/// distinction a painted panel cannot express — a read that failed against a read that answered
/// with nothing, both of which show no facts — is settled in a value a test can compare.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum RewardsBody {
    /// A read is under way. Not a fault, and not a finding.
    Waiting,
    /// No read can be taken: nothing on this side asks the question that would map this store to a
    /// distributor. Drawn in the recessed treatment, with the true cause named and no promised fix
    /// — see the module docs for why this is deliberately NOT amber and NOT [`Self::Empty`].
    NotAnswerable(String),
    /// A read that was taken and genuinely failed, wrapping the node's own reason. The one body
    /// drawn in amber, and the only one a working node cannot produce.
    Unreachable(String),
    /// A node answered, and this store has no reward distributor. A positive claim.
    Empty,
    /// The fact sentences to draw, in the order [`rewards_sections`] produced them — the first
    /// [`FACTS_THIS_MOUNT_CAN_SUPPORT`] of them.
    Facts(Vec<String>),
}

/// Which of the four things the section has to say, for what the app has been told about a store.
///
/// `remembered` is `None` when nothing has ever reported on this store — see the module docs for
/// why that is not the empty state.
pub(crate) fn body_of(remembered: Option<&StoreRewardsReading>, now: u64) -> RewardsBody {
    match remembered {
        None => RewardsBody::NotAnswerable(NOT_ANSWERABLE.text()),
        Some(PaneReading::Waiting) => RewardsBody::Waiting,
        // Ordered before the general failure arm on purpose: a node that answers "I do not serve
        // that method" has not failed, and the sentence it deserves is the unanswerable one.
        Some(PaneReading::Unreachable(why)) if is_method_not_found(why) => {
            RewardsBody::NotAnswerable(NOT_ANSWERABLE.text())
        }
        Some(PaneReading::Unreachable(why)) => {
            RewardsBody::Unreachable(UNREACHABLE.with(&Args::new().text("why", *why)))
        }
        Some(PaneReading::Answered(None)) => RewardsBody::Empty,
        Some(PaneReading::Answered(Some(record))) => RewardsBody::Facts(
            rewards_sections(record, now, CADENCE_ARGUMENT_THIS_MOUNT_DISCARDS)
                .into_iter()
                .take(FACTS_THIS_MOUNT_CAN_SUPPORT)
                .filter_map(|section| section.heading)
                .collect(),
        ),
    }
}

/// How a [`RewardsBody`] is drawn.
///
/// A value rather than three branches buried in the paint closure, for the same reason
/// [`RewardsBody`] itself is one: WHICH bodies get the amber treatment is a claim about honesty
/// that a test has to be able to check, and a `match` inside a paint closure can only be checked by
/// photographing it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Painted<'a> {
    /// One of [`PaneState`]'s banners. The only variant that can be amber.
    Banner(PaneState),
    /// A recessed note: a sentence that is neither a fault nor an emptiness claim.
    Note(&'a str),
    /// The fact sentences themselves, and no banner at all.
    Facts(&'a [String]),
}

impl RewardsBody {
    /// How this body reaches the screen.
    ///
    /// Exhaustive, so a sixth body arm cannot be added without deciding its treatment here.
    pub(crate) fn painted(&self) -> Painted<'_> {
        match self {
            Self::Waiting => Painted::Banner(PaneState::Waiting(WAITING.text())),
            Self::NotAnswerable(sentence) => Painted::Note(sentence),
            Self::Unreachable(sentence) => {
                Painted::Banner(PaneState::Unreachable(sentence.clone()))
            }
            Self::Empty => Painted::Banner(PaneState::Empty(EMPTY.text())),
            Self::Facts(sentences) => Painted::Facts(sentences),
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

/// Drop one store's remembered reading, by the key [`store_key`] produced.
///
/// Staging only, and only for the absence of a reading: [`seed_preview`]'s unanswerable state is
/// "nothing has reported on this store", which cannot be planted, only cleared. Nothing on a user
/// path may forget a reading it was given — a section that forgot would fall back to the
/// unanswerable note and look like a node too old to ask, on a machine that had just answered.
fn forget(key: &str) {
    let mut held = app_readings().lock().unwrap_or_else(|e| e.into_inner());
    held.remove(key);
}

/// Drop every remembered reading.
///
/// Tests only — a gallery does not need it, because [`seed_preview`] overwrites the one entry it
/// cares about, and nothing on a user path may forget a reading it was given.
#[cfg(test)]
pub(crate) fn forget_all() {
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
    store_id
        .iter()
        .fold(String::with_capacity(64), |mut out, byte| {
            let _ = write!(out, "{byte:02x}");
            out
        })
}

/// A store id as the rewards wire holds it, or `None` when the text is not one.
///
/// The inverse of [`store_key_of_bytes`], and the conversion whatever reads the node needs in order
/// to ask about the store a ROW names: `dig.getRewardProverStatus` takes bytes, and the pane holds
/// text.
pub(crate) fn store_bytes(store_id: &str) -> Option<[u8; 32]> {
    let key = store_key(store_id)?;
    let mut bytes = [0u8; 32];
    for (index, slot) in bytes.iter_mut().enumerate() {
        *slot = u8::from_str_radix(&key[index * 2..index * 2 + 2], 16).ok()?;
    }
    Some(bytes)
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

/// The section's body: one banner, one recessed note, or the fact sentences.
fn section(inner: &mut Flow, t: &Tokens, body: &RewardsBody) {
    match body.painted() {
        Painted::Banner(banner) => {
            inner.place(move |ui, at| (state::banner(ui, at, t, &banner), ()));
        }
        Painted::Note(sentence) => {
            let sentence = sentence.to_owned();
            inner.place(move |ui, at| (state::neutral_note(ui, at, t, &sentence), ()));
        }
        Painted::Facts(sentences) => {
            for (index, sentence) in sentences.iter().enumerate() {
                if index > 0 {
                    inner.gap(space::S3);
                }
                let sentence = sentence.clone();
                inner.place(move |ui, at| (super::text::body(ui, at, t, &sentence), ()));
            }
        }
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

/// Which of the four states a gallery capture is of.
///
/// The same device as [`super::settings::CollateralPreview`], and for the same reason: the record a
/// capture is taken against is built INSIDE this crate, because
/// [`crate::rewards::wire::RewardCounters`]'s fields are `pub(crate)` on purpose and an example
/// must not be able to assemble a money record of its own.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RewardsPreview {
    /// A read in flight.
    Waiting,
    /// No read taken, because this node version does not serve the method — the state a real
    /// install shows today, on every store row, and therefore the one the capture set must
    /// photograph (dig_ecosystem#3273 adversarial gate, finding 5).
    NotAnswerable,
    /// A read that was taken and failed on the transport. The amber one.
    Unreachable,
    /// A read that answered, with no distributor for this store.
    Empty,
    /// A read that answered with a distributor's status record.
    Ready,
}

/// Put one store's section into `which` state and open it, before the first frame is drawn.
///
/// For a gallery, never on a user path: nothing in `dig-app` calls this. A committed screenshot must
/// never be taken after synthetic input (dig_ecosystem#2309), so the state and the open flag are
/// both planted rather than clicked into being.
pub fn seed_preview(ctx: &egui::Context, store_id: &str, which: RewardsPreview) {
    let Some(bytes) = store_bytes(store_id) else {
        return;
    };
    // Keyed off the WIRE's own store id, through the same conversion a node-backed read will use. A
    // fixture keyed by a retyped string would photograph a section whose record is about a different
    // store than the row above it, and the picture would not show that.
    let key = store_key_of_bytes(bytes);
    match fixture_reading(which, bytes) {
        Some(reading) => remember(&key, reading),
        // The unanswerable state IS the absence of a reading, so it is staged by removing one
        // rather than by planting a stand-in for one. A gallery photographs several states in a row
        // in one process against one store id, and a reading left behind by an earlier capture
        // would silently make this file a second picture of that earlier state.
        None => forget(&key),
    }
    seed_expanded(ctx, store_id);
}

/// The reading a gallery capture of `which` is taken against, or `None` for the one state that is
/// the absence of a reading.
fn fixture_reading(which: RewardsPreview, store_id: [u8; 32]) -> Option<StoreRewardsReading> {
    match which {
        RewardsPreview::Waiting => Some(PaneReading::Waiting),
        RewardsPreview::NotAnswerable => None,
        // A reason a node really gives, so the picture shows how long a wrapped sentence runs. A
        // TRANSPORT failure, deliberately: a `-32601` reason here would route to the unanswerable
        // note (see [`is_method_not_found`]) and this capture would not be of the amber state.
        RewardsPreview::Unreachable => {
            Some(PaneReading::Unreachable("the node closed the connection"))
        }
        RewardsPreview::Empty => Some(PaneReading::Answered(None)),
        RewardsPreview::Ready => Some(PaneReading::Answered(Some(fixture_record(store_id)))),
    }
}

/// A status record a healthy distributor would produce, for the READY capture.
///
/// Timed against this machine's clock rather than fixed constants, because every sentence in the
/// section is about how RECENT something is — a record stamped in 1970 would photograph the
/// heartbeat-lost state under a file named `ready`. The figures are plainly a fixture and are
/// labelled as one beside the capture; they are rendered by the shipping formatter
/// ([`crate::rewards::pane::rewards_sections`]), which is the part a picture is evidence about.
fn fixture_record(store_id: [u8; 32]) -> RewardDistributorStatusRecord {
    let now = now_unix();
    RewardDistributorStatusRecord {
        launcher_id: [0x11; 32],
        store_id,
        root: [0x33; 32],
        prover_state: crate::rewards::wire::ProverState::Running,
        prover_state_since: now.saturating_sub(86_400),
        last_cycle_started_at: Some(now.saturating_sub(3_600)),
        last_cycle_completed_at: Some(now.saturating_sub(3_540)),
        next_cycle_due_at: Some(now.saturating_add(3_600)),
        last_entry_write_at: Some(now.saturating_sub(7_200)),
        consecutive_cycle_failures: 0,
        pending_entry_writes: 0,
        observed_at: now.saturating_sub(60),
        counters: crate::rewards::wire::RewardCounters {
            mirrors_seen: 4,
            challenges_issued: 96,
            challenges_passed: 93,
            challenges_failed: 3,
            entries_added: 4,
            entries_removed: 1,
            entry_count: 3,
            reserve_base_units: 250_000,
            total_paid_out_base_units: 12_500,
        },
    }
}
