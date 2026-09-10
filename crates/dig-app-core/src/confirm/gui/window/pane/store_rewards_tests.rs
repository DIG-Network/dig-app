//! What the Rewards section must never get wrong: which state it claims, and whose money it is.

use super::*;
use crate::rewards::wire::{ProverState, RewardCounters, RewardDistributorStatusRecord};

/// A store id in the form a [`crate::hosted_stores::HostedStore`] row carries it.
const STORE_ID: &str = "3f9a1c0b7e2d48561a0c9f3b8d47e25610fa3c9b2e5d704816af39c2b0d5e871";

/// A record whose prover has answered but never completed a cycle — the shape every fact sentence
/// can be produced from without inventing a figure.
fn answered_record() -> RewardDistributorStatusRecord {
    RewardDistributorStatusRecord {
        launcher_id: [1; 32],
        store_id: [2; 32],
        root: [3; 32],
        prover_state: ProverState::Running,
        prover_state_since: 0,
        last_cycle_started_at: None,
        last_cycle_completed_at: None,
        next_cycle_due_at: None,
        last_entry_write_at: None,
        consecutive_cycle_failures: 0,
        pending_entry_writes: 0,
        observed_at: 0,
        counters: RewardCounters::default(),
    }
}

/// **The four states are four different bodies, and none of them is silence.**
///
/// The nearest wrong implementation collapses two of them — a read in flight and a read that
/// failed are both "no facts to show" — and it would satisfy any test that only checked the ready
/// case. So all four are built and every pair is required to differ.
#[test]
fn every_state_reaches_the_screen_as_its_own_body() {
    let record = answered_record();
    let waiting = body_of(Some(&PaneReading::Waiting), 0);
    let unreachable = body_of(Some(&PaneReading::Unreachable("the node refused")), 0);
    let empty = body_of(Some(&PaneReading::Answered::<RewardDistributorStatusRecord>(None)), 0);
    let ready = body_of(Some(&PaneReading::Answered(Some(record))), 0);

    assert_eq!(waiting, RewardsBody::Waiting);
    assert_eq!(empty, RewardsBody::Empty);
    assert!(matches!(unreachable, RewardsBody::Unreachable(_)));
    assert!(matches!(ready, RewardsBody::Facts(_)));

    let bodies = [waiting, unreachable, empty, ready];
    for (i, a) in bodies.iter().enumerate() {
        for (j, b) in bodies.iter().enumerate() {
            if i != j {
                assert_ne!(a, b, "states {i} and {j} say the same thing");
            }
        }
    }
}

/// **A store nothing has reported on is never reported as having no distributor.**
///
/// This is the money claim the section exists to not make. `None` means nobody asked — no released
/// node answers the method that would map a store to a distributor — and rendering that as the
/// empty state would tell an operator that the distributor paying for their store does not exist.
/// Both halves are asserted: the state is the amber one, and its sentence is not the empty one's.
#[test]
fn an_unremembered_store_is_not_reported_as_having_no_distributor() {
    let unasked = body_of(None, 0);
    let answered_empty = body_of(
        Some(&PaneReading::Answered::<RewardDistributorStatusRecord>(None)),
        0,
    );

    assert!(
        matches!(unasked, RewardsBody::Unreachable(_)),
        "an unasked store came out as {unasked:?}"
    );
    assert_ne!(unasked, answered_empty);
    let RewardsBody::Unreachable(sentence) = &unasked else {
        unreachable!("asserted above");
    };
    assert_ne!(sentence, &EMPTY.text());
}

/// **A read that FAILED and a read nobody took carry different sentences.**
///
/// They share [`RewardsBody::Unreachable`] because they share the amber treatment, and that shared
/// arm is exactly where the two could silently become one sentence. The node's own reason has to
/// reach the screen, or a person cannot tell a refused call from an unsupported one.
#[test]
fn a_failed_read_names_the_nodes_own_reason_and_an_unasked_one_does_not() {
    let failed = body_of(Some(&PaneReading::Unreachable("the node refused")), 0);
    let unasked = body_of(None, 0);

    let RewardsBody::Unreachable(failed) = failed else {
        panic!("a failed read is not amber");
    };
    let RewardsBody::Unreachable(unasked) = unasked else {
        panic!("an unasked read is not amber");
    };
    assert!(
        failed.contains("the node refused"),
        "the node's reason did not reach the screen: {failed:?}"
    );
    assert!(!unasked.contains("the node refused"));
    assert_ne!(failed, unasked);
}

/// **The string a row is drawn from and the bytes the wire carries resolve to ONE key.**
///
/// The whole lookup rests on this: [`crate::hosted_stores::HostedStore::store_id`] is 64-hex text
/// and [`crate::rewards::wire`] carries `[u8; 32]`. If the two disagree the section silently never
/// matches, which looks exactly like a store with no distributor. All three forms of the same id
/// are required to agree — lowercase, uppercase, and `0x`-prefixed — because the window prints
/// store ids in more than one of them.
#[test]
fn a_store_id_string_and_the_wires_bytes_agree_on_one_key() {
    let mut bytes = [0u8; 32];
    for (slot, pair) in bytes.iter_mut().zip(0..32) {
        *slot = u8::from_str_radix(&STORE_ID[pair * 2..pair * 2 + 2], 16).expect("hex");
    }

    let from_bytes = store_key_of_bytes(bytes);
    assert_eq!(from_bytes, STORE_ID);
    assert_eq!(store_key(STORE_ID).as_deref(), Some(STORE_ID));
    assert_eq!(
        store_key(&format!("0x{STORE_ID}")).as_deref(),
        Some(STORE_ID)
    );
    assert_eq!(
        store_key(&STORE_ID.to_ascii_uppercase()).as_deref(),
        Some(STORE_ID)
    );
}

/// **Anything that is not a store id is refused, never truncated into one.**
///
/// A key built by cutting text to 64 characters would map two different stores onto one reading,
/// and a Rewards section showing another store's distributor is the worst outcome this file has.
#[test]
fn text_that_is_not_a_store_id_is_refused_rather_than_truncated() {
    assert_eq!(store_key(""), None);
    assert_eq!(store_key("0x"), None);
    assert_eq!(store_key(&STORE_ID[..63]), None, "63 hex digits is not one");
    assert_eq!(
        store_key(&format!("{STORE_ID}ab")),
        None,
        "66 hex digits is not one either"
    );
    assert_eq!(
        store_key(&STORE_ID.replace('3', "z")),
        None,
        "non-hex is not one"
    );
}

/// **What was remembered against one form of an id is found again from another.**
#[test]
fn a_remembered_reading_is_found_from_either_form_of_the_id() {
    let _guard = test_lock();
    forget_all();
    remember(&format!("0x{}", STORE_ID.to_ascii_uppercase()), PaneReading::Waiting);

    let found = reading(STORE_ID).expect("the reading was remembered");
    assert!(matches!(found, PaneReading::Waiting));
    assert!(reading("not a store id").is_none());

    forget_all();
    assert!(reading(STORE_ID).is_none(), "forget_all left a reading behind");
}

/// **The section is closed until something opens it.**
///
/// Collapsed-by-default is an acceptance criterion, and the default is the one behaviour a
/// disclosure gets wrong for free: `unwrap_or(true)` reads identically and is wrong.
#[test]
fn the_section_is_collapsed_until_something_opens_it() {
    let ctx = egui::Context::default();
    crate::confirm::gui::window::install_fonts(&ctx);
    let closed = std::cell::Cell::new(true);
    let opened = std::cell::Cell::new(false);

    let _ = ctx.run(egui::RawInput::default(), |ctx| {
        egui::Area::new(egui::Id::new("collapsed-by-default")).show(ctx, |ui| {
            closed.set(is_expanded(ui, STORE_ID));
        });
    });
    assert!(!closed.get(), "the section opened without being asked to");

    seed_expanded(&ctx, STORE_ID);
    let _ = ctx.run(egui::RawInput::default(), |ctx| {
        egui::Area::new(egui::Id::new("collapsed-by-default")).show(ctx, |ui| {
            opened.set(is_expanded(ui, STORE_ID));
        });
    });
    assert!(opened.get(), "a seeded section did not open");
}

/// **The facts come from the shipped fact layer, not from a second renderer here.**
///
/// Four sentences, in the order [`rewards_sections`] produced them, compared against that function
/// directly — so a copy of its wording drifting out of step here fails rather than shipping a
/// second, staler set of money sentences.
#[test]
fn the_facts_shown_are_the_shipped_fact_layers_own() {
    let record = answered_record();
    let body = body_of(Some(&PaneReading::Answered(Some(record.clone()))), 0);
    let RewardsBody::Facts(shown) = body else {
        panic!("an answered record showed no facts");
    };
    let expected: Vec<String> = rewards_sections(&record, 0, NO_FUNDING_RATE_CHOSEN)
        .into_iter()
        .filter_map(|section| section.heading)
        .collect();

    assert_eq!(shown.len(), 4, "expected one sentence per fact");
    assert_eq!(shown, expected);
}

/// **Every sentence this module owns is a real catalog entry, not its own key echoed back.**
///
/// The failure this catches shipped once already on this ticket family: four sentence builders
/// hardcoded in English beside the 14-locale catalog the same PR added. A missing key resolves to
/// the key itself, so a rendered sentence equal to its key is the tell.
#[test]
fn every_sentence_resolves_through_the_catalog() {
    for msg in [SECTION_TITLE, SHOW, HIDE, WAITING, EMPTY, NOT_ANSWERABLE] {
        let rendered = msg.text();
        assert_ne!(
            rendered,
            msg.key(),
            "{} is not in the catalog",
            msg.key()
        );
        assert!(!rendered.is_empty(), "{} rendered nothing", msg.key());
    }
    let wrapped = UNREACHABLE.with(&Args::new().text("why", "the node refused"));
    assert_ne!(wrapped, UNREACHABLE.key());
    assert!(wrapped.contains("the node refused"));
}

/// **No sentence this module owns offers a claim, an entitlement or an eviction.**
///
/// SPEC §12.5 clause 6 forbids a claim status, an accrual, an entitlement and any
/// `eligible`/`claiming` word derived from a distributor existing; clause 7 forbids letting a
/// person reconstruct the never-admitted versus evicted split. Swept over this module's own English
/// values, since the fact sentences themselves are `rewards::copy`'s and are guarded there.
#[test]
fn no_sentence_here_offers_a_claim_status_or_an_eviction() {
    const BANNED: &[&str] = &[
        "eligible",
        "eligibility",
        "claiming",
        "entitle",
        "accru",
        "evict",
        "never admitted",
        "not admitted",
        "removed from",
    ];
    for msg in [
        SECTION_TITLE,
        SHOW,
        HIDE,
        WAITING,
        EMPTY,
        NOT_ANSWERABLE,
        UNREACHABLE,
    ] {
        let rendered = msg.text_in(crate::i18n::Language::En).to_ascii_lowercase();
        for banned in BANNED {
            assert!(
                !rendered.contains(banned),
                "{} says {banned:?}: {rendered:?}",
                msg.key()
            );
        }
    }
}

/// **No sentence here prints a base-unit integer of its own.**
///
/// Money reaches a person only through [`crate::amount`], and this module renders no figure at all
/// — every number in the section comes from [`rewards_sections`]. A digit appearing in one of these
/// sentences would mean a figure was written here, which is where a hand division by 1,000 gets in.
#[test]
fn this_modules_own_sentences_carry_no_figure() {
    for msg in [SECTION_TITLE, SHOW, HIDE, WAITING, EMPTY, NOT_ANSWERABLE] {
        let rendered = msg.text_in(crate::i18n::Language::En);
        assert!(
            !rendered.chars().any(|c| c.is_ascii_digit()),
            "{} prints a figure of its own: {rendered:?}",
            msg.key()
        );
    }
}
