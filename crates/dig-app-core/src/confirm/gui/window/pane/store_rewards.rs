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
//! distributor existing (SPEC §12.5 clause 6). A create affordance now lives here
//! (dig_ecosystem#3253): the interactive card below, gated on
//! [`DistributorMintAvailability::Possible`](crate::rewards::mint::DistributorMintAvailability) —
//! it needs no node RPC at all, since [`DistributorMintDoor::begin`](crate::rewards::mint::DistributorMintDoor::begin)
//! signs and pushes the launch straight to the chain the same way every other spend in this app
//! does. Mint and refill affordances still do not exist (refill: dig-node#620 / dig_ecosystem#3357).
//! Clawback does not either, and unlike create it is not merely unpainted-for-now: measured against
//! dig-node v0.260.0, every reward-distributor RPC method it serves is a READ —
//! `dig.getRewardDistributor`, `dig.listRewardDistributorCommitments` and
//! `dig.getPayeeRewardClaimStatus` are peer-reachable, and `dig.listRewardDistributors` exists but
//! is CONTROL-tier, not peer-reachable at all — there is no clawback-authorizing RPC on the node's
//! side of the wire for a control here to drive, so painting one would still be a dead control
//! (ship no dead control). Nothing here distinguishes a peer never admitted to the
//! entry set from one evicted from it (clause 7). Every figure a person reads comes from
//! [`crate::rewards::pane::rewards_sections`], which formats money through [`crate::amount`] and
//! states whose money each figure is.
//!
//! And no claim CADENCE: [`crate::rewards::pane::rewards_sections`] no longer even carries that
//! sentence (dig_ecosystem#3301) — a funding rate belongs beside an amount a funder chose, this
//! mount's reader is a payee with no such amount, and `rewards_sections` itself now cannot invent
//! one. See [`crate::rewards::pane::cadence_section`]'s doc comment for the fact this mount does
//! not render and why.

use egui::{Rect, Ui};

use super::action::{self, Action};
use super::card;
use super::flow::Flow;
use super::state::{self, PaneState};
use crate::confirm::gui::render::{space, Weight};
use crate::confirm::gui::theme::Tokens;
use crate::i18n::{Args, Msg};
use crate::rewards::mint::DistributorMintAvailability;
use crate::rewards::pane::{create_availability_sentence, rewards_sections, PaneReading};
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
    /// The fact sentences to draw, in the order [`rewards_sections`] produced them: prover
    /// status and entry set always, payout total ONLY when the entry set is not
    /// [`crate::rewards::reading::EntrySetReading::Empty`] (dig_ecosystem#3297 -- rendering it
    /// beside "no mirror is currently earning" would leak evicted history) — never a cadence
    /// sentence, since `rewards_sections` cannot produce one.
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
            rewards_sections(record, now)
                .into_iter()
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
        // The refresh cadence's LAST probe answer, read from a paint-time cache -- never probed
        // here, because probing reads the chain. See `create_note`.
        section(
            inner,
            t,
            &body,
            crate::rewards::create_card::cached_availability(),
            store_id,
        );
    });
    height
}

/// The create-a-distributor sentence this build has to show, or `None` when a mint is actually
/// possible and the sentence would be a lie.
///
/// This is the PRODUCTION call site of [`create_availability_sentence`]: before it existed, that
/// function had no caller outside its own tests, so `SPEC.md` §11's "the create card paints the
/// availability reason" was not producible by any code that ships (dig-app#411 reviewer finding 3
/// / adversarial F5).
///
/// The availability is a PARAMETER, not something asked for here. It stopped being a compile-time
/// fact about which facades exist -- `DistributorMintAvailability::current`, the `const fn` that
/// made it one, is deleted -- and became a live answer about this account's unlock and this node's
/// reach, produced by `DistributorMintAvailability::probe`, which READS THE CHAIN. A paint function
/// must never perform I/O, so the probe belongs on the refresh cadence and its answer arrives here
/// already taken.
///
/// `None` means no probe has run yet, which is the honest state of this build: the refresh cadence
/// that probes lands with the create card, so today every frame passes `None` and every card paints
/// "not checked yet" rather than a claim about what is possible.
pub(crate) fn create_note(
    availability: Option<DistributorMintAvailability>,
) -> Option<&'static str> {
    create_availability_sentence(availability)
}

/// The section's body: one banner, one recessed note, or the fact sentences -- followed by the
/// create-availability sentence ([`create_note`]), which is a PLAIN LABEL and never a control.
///
/// The sentence sits under every body, including the unanswerable one, because what it says is
/// true of this build regardless of what any node answered about this store: nothing here can sign
/// a distributor launch. Conditioning it on a body would make it look like a property of the read.
///
/// `store_id` is used ONLY to look up [`crate::rewards::create_card::last_rendered`] -- a
/// paint-time, no-I/O read of whatever the refresh cadence last recorded for a pending mint this
/// store may hold (dig_ecosystem#3253 §6 acceptance item 7; the standing condition is "no publish
/// without `status` behind it" -- see `dig-app.rs`'s call to `create_card::refresh_and_render`,
/// which is what actually reads the chain, off this paint path).
fn section(
    inner: &mut Flow,
    t: &Tokens,
    body: &RewardsBody,
    availability: Option<DistributorMintAvailability>,
    store_id: &str,
) {
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

    if let Some(sentence) = create_note(availability) {
        inner.gap(space::S3);
        let sentence = sentence.to_owned();
        inner.place(move |ui, at| (state::neutral_note(ui, at, t, &sentence), ()));
    }

    // A pending mint's last-recorded status, if this store has one. Never fetched here -- see this
    // function's own doc comment -- only ever the last answer `refresh_and_render` wrote.
    if let Some(sentence) = crate::rewards::create_card::last_rendered(store_id) {
        inner.gap(space::S3);
        inner.place(move |ui, at| (state::neutral_note(ui, at, t, &sentence), ()));
    }

    // The interactive card, mounted ONLY on the arm that says a mint is actually possible. Every
    // other arm already painted its own reason through `create_note` above.
    if availability == Some(DistributorMintAvailability::Possible) {
        inner.gap(space::S3);
        create_card_steps(inner, t, store_id);
    }
}

/// The interactive create card: one step visible at a time, each gated by the previous step's
/// witness.
///
/// # What is painted, in order
///
/// 1. **Reserve and warnings.** The reward-CAT coin picker and the epoch-length field, then the
///    five ratified warning blocks with the heading and the closing line, then "I understand".
/// 2. **Manager.** Two arms with both bodies always visible, arm B's hex field, then "Continue".
/// 3. **Terms.** First-epoch start, network fee and store root, validated inline.
/// 4. **Submit.** "Sign and submit", which hands a job to the create-sink worker.
///
/// # Why the reserve and the epoch length sit ON the warnings step, ahead of the blocks
///
/// Warning block 4 quantifies the exposure -- the amount committed and how many days of a frozen
/// entry set it can pay for. Those numbers are the chosen coin's amount and the typed epoch
/// length; before either exists, the block can only be painted with invented figures, and an
/// invented figure in a money warning is worse than no warning. So the two inputs it names are
/// collected first and the block states them. Until they are, block 4 does not paint, exactly four
/// keys reach `WarningsShown::having_displayed`, it answers `None`, and the acknowledgement button
/// stays disabled -- the gate doing its job rather than being worked around.
///
/// # Paint is I/O-free
///
/// Everything read here comes from [`crate::rewards::create_card::cached_inputs`] and
/// [`crate::rewards::create_card::draft`]: a paint-time cache the refresh cadence in `dig-app.rs`
/// fills, and the person's own typing. No chain, account or publisher handle reaches this
/// function, which is the same boundary every other spend in this window crosses.
fn create_card_steps(inner: &mut Flow, t: &Tokens, store_id: &str) {
    use crate::rewards::create_card as card_state;

    let Some(cached) = card_state::cached_inputs() else {
        return;
    };
    let live = inner.live();
    let mut draft = card_state::draft(store_id);
    let before = draft.clone();

    if !draft.acknowledged {
        warnings_step(inner, t, store_id, &cached, &mut draft, live);
    } else if !draft.manager_committed {
        manager_step(inner, t, store_id, &mut draft, live);
    } else {
        terms_and_submit_step(inner, t, store_id, &cached, &mut draft, live);
    }

    if !drafts_match(&before, &draft) {
        card_state::set_draft(store_id, draft);
    }
}

/// Whether two drafts hold the same typed text and the same choices.
///
/// [`CardDraft`](crate::rewards::create_card::CardDraft) is deliberately plain data with no
/// `PartialEq` (it is cloned freely and compared nowhere else), so the paint's "did anything change
/// this frame" question is answered here rather than by widening the type's derives for one caller.
fn drafts_match(
    a: &crate::rewards::create_card::CardDraft,
    b: &crate::rewards::create_card::CardDraft,
) -> bool {
    a.acknowledged == b.acknowledged
        && a.arm == b.arm
        && a.manager_committed == b.manager_committed
        && a.arm_b_hex == b.arm_b_hex
        && a.selected_coin == b.selected_coin
        && a.root_hex == b.root_hex
        && a.epoch_seconds_text == b.epoch_seconds_text
        && a.first_epoch_text == b.first_epoch_text
        && a.fee_text == b.fee_text
}

/// Step 1 -- the reserve coin, the epoch length, the five warning blocks and the acknowledgement.
///
/// The acknowledgement button is enabled only when this frame actually painted all five required
/// keys: the slice of keys handed to `WarningsShown::having_displayed` is collected AS the blocks
/// are placed, never written out ahead of them, so a block that did not reach the screen cannot be
/// acknowledged.
fn warnings_step(
    inner: &mut Flow,
    t: &Tokens,
    store_id: &str,
    cached: &crate::rewards::create_card::CachedCreateInputs,
    draft: &mut crate::rewards::create_card::CardDraft,
    live: bool,
) {
    use crate::rewards::create_card as card_state;

    coin_picker(inner, t, store_id, cached, draft, live);

    inner.gap(space::S3);
    let epoch_label = card_state::terms_epoch_label();
    let mut epoch_text = draft.epoch_seconds_text.clone();
    inner.place(|ui, at| {
        let field = super::field::Field {
            label: &epoch_label,
            placeholder: "",
            help: "",
            error: None,
            id: element_id(store_id, "epoch"),
        };
        (
            super::field::text_field(ui, at, t, live, &field, &mut epoch_text),
            (),
        )
    });
    draft.epoch_seconds_text = epoch_text;

    inner.gap(space::S3);
    let heading = card_state::warning_heading();
    inner.place(|ui, at| (super::text::heading(ui, at, t, &heading), ()));

    let epoch_seconds: u64 = draft.epoch_seconds_text.trim().parse().unwrap_or(0);
    let reserve = draft
        .selected_coin
        .and_then(|index| cached.cat_coins.get(index))
        .map(|cat| cat.coin.amount);
    let block_4 = reserve.and_then(|amount| card_state::warning_block_4(amount, epoch_seconds));

    // The keys this frame really put on screen, collected as each block is placed.
    let mut painted: Vec<&str> = Vec::new();
    let blocks: [(&str, Option<String>); 5] = [
        (
            crate::rewards::pane::REQUIRED_WARNING_KEYS[0],
            Some(card_state::warning_block_1()),
        ),
        (
            crate::rewards::pane::REQUIRED_WARNING_KEYS[1],
            Some(card_state::warning_block_2()),
        ),
        (
            crate::rewards::pane::REQUIRED_WARNING_KEYS[2],
            Some(card_state::warning_block_3()),
        ),
        (crate::rewards::pane::REQUIRED_WARNING_KEYS[3], block_4),
        (
            crate::rewards::pane::REQUIRED_WARNING_KEYS[4],
            Some(card_state::warning_block_5()),
        ),
    ];
    for (key, body) in blocks {
        let Some(body) = body else {
            continue;
        };
        inner.gap(space::S3);
        inner.place(|ui, at| (super::text::body(ui, at, t, &body), ()));
        painted.push(key);
    }

    inner.gap(space::S3);
    let closing = card_state::warning_closing();
    inner.place(|ui, at| (super::text::body(ui, at, t, &closing), ()));

    let shown = crate::rewards::pane::WarningsShown::having_displayed(&painted);
    inner.gap(space::S3);
    let ack = Action {
        label: card_state::ack_button_label(),
        weight: Weight::Primary,
        enabled: live && shown.is_some(),
        id: (),
        element: element_id(store_id, "ack"),
    };
    let pressed = inner
        .place(|ui, at| action::buttons(ui, at, t, live, std::slice::from_ref(&ack)))
        .is_some();
    if pressed && shown.is_some() {
        draft.acknowledged = true;
    }
}

/// The reward-CAT coin rows, or the one sentence that says why there are none.
///
/// A locked account and an empty listing are different sentences, and coins the listing could not
/// build are counted rather than dropped -- all three through [`crate::rewards::create_card`]'s own
/// accessors.
fn coin_picker(
    inner: &mut Flow,
    t: &Tokens,
    store_id: &str,
    cached: &crate::rewards::create_card::CachedCreateInputs,
    draft: &mut crate::rewards::create_card::CardDraft,
    live: bool,
) {
    use crate::rewards::create_card as card_state;

    if cached.cat_locked {
        let sentence = card_state::coin_locked_sentence();
        inner.place(move |ui, at| (state::neutral_note(ui, at, t, &sentence), ()));
        return;
    }
    if cached.cat_coins.is_empty() {
        let sentence = card_state::coin_empty_sentence();
        inner.place(move |ui, at| (state::neutral_note(ui, at, t, &sentence), ()));
        return;
    }

    let rows: Vec<Action<usize>> = cached
        .cat_coins
        .iter()
        .enumerate()
        .filter_map(|(index, cat)| {
            let label =
                card_state::coin_row_sentence(crate::wallet::state::Asset::DIG, cat.coin.amount)?;
            Some(Action {
                label,
                weight: if draft.selected_coin == Some(index) {
                    Weight::Primary
                } else {
                    Weight::Ghost
                },
                enabled: live,
                id: index,
                element: element_id(store_id, &format!("coin-{index}")),
            })
        })
        .collect();
    if let Some(index) = inner.place(|ui, at| action::buttons(ui, at, t, live, &rows)) {
        draft.selected_coin = Some(index);
    }

    if let Some(sentence) = card_state::coin_omitted_sentence(cached.cat_omitted) {
        inner.gap(space::S3);
        inner.place(move |ui, at| (state::neutral_note(ui, at, t, &sentence), ()));
    }
}

/// Step 2 -- the manager choice.
///
/// BOTH bodies are painted under both labels, always: each states only what is verified about that
/// arm, and showing only the selected one would hide the comparison the choice is made on. The
/// wording is fixed in [`crate::rewards::copy`] and swept for forbidden claims across all 14
/// locales.
fn manager_step(
    inner: &mut Flow,
    t: &Tokens,
    store_id: &str,
    draft: &mut crate::rewards::create_card::CardDraft,
    live: bool,
) {
    use crate::rewards::create_card as card_state;
    use crate::rewards::create_card::ManagerArm;

    let arms = [
        (
            ManagerArm::A,
            card_state::manager_arm_a_label(),
            card_state::manager_arm_a_body(),
            "arm-a",
        ),
        (
            ManagerArm::B,
            card_state::manager_arm_b_label(),
            card_state::manager_arm_b_body(),
            "arm-b",
        ),
    ];
    for (arm, label, body, slot) in arms {
        let button = Action {
            label,
            weight: if draft.arm == Some(arm) {
                Weight::Primary
            } else {
                Weight::Ghost
            },
            enabled: live,
            id: arm,
            element: element_id(store_id, slot),
        };
        if inner
            .place(|ui, at| action::buttons(ui, at, t, live, std::slice::from_ref(&button)))
            .is_some()
        {
            draft.arm = Some(arm);
        }
        inner.gap(space::S2);
        inner.place(|ui, at| (super::text::body(ui, at, t, &body), ()));
        inner.gap(space::S3);
    }

    if draft.arm == Some(ManagerArm::B) {
        let label = card_state::manager_arm_b_field_label();
        let mut hex = draft.arm_b_hex.clone();
        let error = draft.arm_b_error.clone();
        inner.place(|ui, at| {
            let field = super::field::Field {
                label: &label,
                placeholder: "",
                help: "",
                error,
                id: element_id(store_id, "manager-hex"),
            };
            (
                super::field::text_field(ui, at, t, live, &field, &mut hex),
                (),
            )
        });
        draft.arm_b_hex = hex;
        inner.gap(space::S3);
    }

    let ready = match draft.arm {
        Some(ManagerArm::A) => true,
        Some(ManagerArm::B) => crate::rewards::create::parse_hash_hex(&draft.arm_b_hex).is_some(),
        None => false,
    };
    let go = Action {
        label: card_state::continue_button_label(),
        weight: Weight::Primary,
        enabled: live && ready,
        id: (),
        element: element_id(store_id, "manager-continue"),
    };
    if inner
        .place(|ui, at| action::buttons(ui, at, t, live, std::slice::from_ref(&go)))
        .is_some()
        && ready
    {
        draft.manager_committed = true;
    }
}

/// Steps 3 and 4 -- the remaining terms, their inline refusals, and the submit button.
///
/// The submit button is painted only when a create-sink worker is installed: without one, every
/// press could only ever be refused, and a control that cannot act is not painted at all.
fn terms_and_submit_step(
    inner: &mut Flow,
    t: &Tokens,
    store_id: &str,
    cached: &crate::rewards::create_card::CachedCreateInputs,
    draft: &mut crate::rewards::create_card::CardDraft,
    live: bool,
) {
    use crate::rewards::create_card as card_state;

    let now = now_unix();
    let labels = [
        ("first-epoch", card_state::terms_first_epoch_label()),
        ("fee", card_state::terms_fee_label()),
        ("root", card_state::terms_root_label()),
    ];
    for (slot, label) in labels {
        let mut text = match slot {
            "first-epoch" => draft.first_epoch_text.clone(),
            "fee" => draft.fee_text.clone(),
            _ => draft.root_hex.clone(),
        };
        inner.place(|ui, at| {
            let field = super::field::Field {
                label: &label,
                placeholder: "",
                help: "",
                error: None,
                id: element_id(store_id, slot),
            };
            (
                super::field::text_field(ui, at, t, live, &field, &mut text),
                (),
            )
        });
        match slot {
            "first-epoch" => draft.first_epoch_text = text,
            "fee" => draft.fee_text = text,
            _ => draft.root_hex = text,
        }
        inner.gap(space::S3);
    }

    // Inline, BEFORE the seam: the same refusal `attempt_submit` would return, shown while the
    // fields that cause it are still on screen.
    let epoch_seconds: u64 = draft.epoch_seconds_text.trim().parse().unwrap_or(0);
    let first_epoch: u64 = draft.first_epoch_text.trim().parse().unwrap_or(0);
    if let Err(refusal) = card_state::validate_epoch_terms(epoch_seconds, first_epoch, now) {
        let sentence = refusal.sentence();
        inner.place(move |ui, at| (state::neutral_note(ui, at, t, &sentence), ()));
        inner.gap(space::S3);
    } else if let Ok(fee) = draft.fee_text.trim().parse::<u64>() {
        if card_state::select_funding_coin(&cached.xch_coins, fee).is_none() {
            let sentence = card_state::TermsRefusal::NoFundingCoin.sentence();
            inner.place(move |ui, at| (state::neutral_note(ui, at, t, &sentence), ()));
            inner.gap(space::S3);
        }
    }

    if !card_state::sink_installed() {
        return;
    }

    let submit = Action {
        label: card_state::submit_button_label(),
        weight: Weight::Primary,
        enabled: live,
        id: (),
        element: element_id(store_id, "submit"),
    };
    let pressed = inner
        .place(|ui, at| action::buttons(ui, at, t, live, std::slice::from_ref(&submit)))
        .is_some();
    if !pressed {
        return;
    }

    let Some(bytes) = store_bytes(store_id) else {
        return;
    };
    match card_state::attempt_submit(
        store_id,
        draft,
        cached,
        chia_protocol::Bytes32::new(bytes),
        now,
    ) {
        // The draft was consumed by the sink; this frame's copy is stale, so the cleared one is
        // read back rather than written over.
        Ok(()) => *draft = card_state::draft(store_id),
        Err(refusal) => {
            if let Some(sentence) = refusal.sentence() {
                inner.gap(space::S3);
                inner.place(move |ui, at| (state::neutral_note(ui, at, t, &sentence), ()));
            }
        }
    }
}

/// A stable element id for one of this card's controls on one store's section.
fn element_id(store_id: &str, slot: &str) -> egui::Id {
    egui::Id::new("dig-rewards-create").with(store_id).with(slot)
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
