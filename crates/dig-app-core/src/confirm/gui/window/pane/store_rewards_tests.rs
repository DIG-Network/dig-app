//! What the Rewards section must never get wrong: which state it claims, and whose money it is.

use super::*;
use crate::rewards::wire::{ProverState, RewardCounters, RewardDistributorStatusRecord};

/// A store id in the form a [`crate::hosted_stores::HostedStore`] row carries it.
const STORE_ID: &str = "3f9a1c0b7e2d48561a0c9f3b8d47e25610fa3c9b2e5d704816af39c2b0d5e871";

/// A reason a node gives when it does not serve the method — the answer every dig-node released
/// today gives to `dig.listRewardDistributors`.
const METHOD_NOT_FOUND: &str = "dig.listRewardDistributors: -32601 Method not found";

/// A reason a node gives when the call itself broke. Carries no method-not-found spelling, so it
/// must reach the amber treatment.
const TRANSPORT_FAILED: &str = "the node closed the connection";

/// The clock every dated sentence in the sweeps below is judged against.
const NOW: u64 = 1_700_000_000;

/// A record whose prover is live, whose entry set has been written, and which has paid out — the
/// one shape that produces a figure of money, a mirror count and a live status all at once.
fn live_paid_record() -> RewardDistributorStatusRecord {
    RewardDistributorStatusRecord {
        last_cycle_started_at: Some(NOW - 200),
        last_cycle_completed_at: Some(NOW - 100),
        next_cycle_due_at: Some(NOW + 3_600),
        last_entry_write_at: Some(NOW - 300),
        observed_at: NOW,
        counters: RewardCounters {
            entry_count: 3,
            total_paid_out_base_units: 12_500,
            ..RewardCounters::default()
        },
        ..answered_record()
    }
}

/// Every record shape whose sentences a person can reach, so a copy sweep covers the sentences the
/// mount can actually render rather than one convenient case.
///
/// Named cases, because a sweep whose failure message says "case 3" sends the next reader counting
/// array entries.
fn every_reachable_record() -> Vec<(&'static str, RewardDistributorStatusRecord)> {
    let live = live_paid_record();
    vec![
        ("never written, never ran", answered_record()),
        ("live, written entry set, paid", live.clone()),
        (
            "written entry set with no mirrors in it",
            RewardDistributorStatusRecord {
                counters: RewardCounters {
                    entry_count: 0,
                    ..live.counters
                },
                ..live.clone()
            },
        ),
        (
            "heartbeat lost",
            RewardDistributorStatusRecord {
                observed_at: NOW - 90 * 86_400,
                ..live.clone()
            },
        ),
        (
            "clock unusable",
            RewardDistributorStatusRecord {
                observed_at: NOW + 90 * 86_400,
                ..live.clone()
            },
        ),
        (
            "cycle overdue",
            RewardDistributorStatusRecord {
                next_cycle_due_at: Some(NOW - 90 * 86_400),
                ..live
            },
        ),
    ]
}

/// The sentences the section renders for `record`, as a person reads them.
fn sentences_for(record: &RewardDistributorStatusRecord) -> Vec<String> {
    let body = body_of(Some(&PaneReading::Answered(Some(record.clone()))), NOW);
    let RewardsBody::Facts(shown) = body else {
        panic!("an answered record showed no facts");
    };
    shown
}

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

/// **The five states are five different bodies, and none of them is silence.**
///
/// The nearest wrong implementation collapses two of them — a read in flight and a read that
/// failed are both "no facts to show" — and it would satisfy any test that only checked the ready
/// case. So all five are built and every pair is required to differ. The fifth, `NotAnswerable`,
/// was for one revision the same arm as `Unreachable`; keeping them apart is what stops a node
/// that simply cannot be asked from being painted as a fault (finding 5).
#[test]
fn every_state_reaches_the_screen_as_its_own_body() {
    let record = answered_record();
    let waiting = body_of(Some(&PaneReading::Waiting), 0);
    let not_answerable = body_of(None, 0);
    let unreachable = body_of(Some(&PaneReading::Unreachable(TRANSPORT_FAILED)), 0);
    let empty = body_of(
        Some(&PaneReading::Answered::<RewardDistributorStatusRecord>(
            None,
        )),
        0,
    );
    let ready = body_of(Some(&PaneReading::Answered(Some(record))), 0);

    assert_eq!(waiting, RewardsBody::Waiting);
    assert_eq!(empty, RewardsBody::Empty);
    assert!(matches!(not_answerable, RewardsBody::NotAnswerable(_)));
    assert!(matches!(unreachable, RewardsBody::Unreachable(_)));
    assert!(matches!(ready, RewardsBody::Facts(_)));

    let bodies = [waiting, not_answerable, unreachable, empty, ready];
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
/// Both halves are asserted: the state is the unanswerable one, and its sentence is not the empty
/// one's.
#[test]
fn an_unremembered_store_is_not_reported_as_having_no_distributor() {
    let unasked = body_of(None, 0);
    let answered_empty = body_of(
        Some(&PaneReading::Answered::<RewardDistributorStatusRecord>(
            None,
        )),
        0,
    );

    assert!(
        matches!(unasked, RewardsBody::NotAnswerable(_)),
        "an unasked store came out as {unasked:?}"
    );
    assert_ne!(unasked, answered_empty);
    let RewardsBody::NotAnswerable(sentence) = &unasked else {
        unreachable!("asserted above");
    };
    assert_ne!(sentence, &EMPTY.text());
}

/// **A read that FAILED and a read nobody took carry different sentences AND different colours.**
///
/// They were one arm for a revision, sharing the amber treatment, and that shared arm is exactly
/// where the two could silently become one sentence. The node's own reason has to reach the screen,
/// or a person cannot tell a refused call from an unsupported one.
#[test]
fn a_failed_read_names_the_nodes_own_reason_and_an_unasked_one_does_not() {
    let failed = body_of(Some(&PaneReading::Unreachable(TRANSPORT_FAILED)), 0);
    let unasked = body_of(None, 0);

    let RewardsBody::Unreachable(failed) = failed else {
        panic!("a failed read is not amber");
    };
    let RewardsBody::NotAnswerable(unasked) = unasked else {
        panic!("an unasked read is not the unanswerable note");
    };
    assert!(
        failed.contains(TRANSPORT_FAILED),
        "the node's reason did not reach the screen: {failed:?}"
    );
    assert!(!unasked.contains(TRANSPORT_FAILED));
    assert_ne!(failed, unasked);
}

/// **A node answering "I do not serve that method" is not painted as a fault.**
///
/// `dig-node` v0.256.0 serves `dig.getRewardProverStatus` and answers `-32601` to
/// `dig.listRewardDistributors`, so this is the answer a real install gets today — the call
/// arrived, the node replied, and the reply was that it cannot be asked. Routing it to amber
/// reports a working node as broken, and since nothing else on a user path reaches this section it
/// made amber the only state anybody could see (finding 5).
///
/// Both directions are asserted, because a classifier that answered `true` for everything would
/// satisfy the first half alone: the method-not-found reason becomes the unanswerable note, and a
/// transport failure still becomes amber.
#[test]
fn a_method_not_found_answer_becomes_the_unanswerable_note_and_not_amber() {
    let unsupported = body_of(Some(&PaneReading::Unreachable(METHOD_NOT_FOUND)), 0);
    let broken = body_of(Some(&PaneReading::Unreachable(TRANSPORT_FAILED)), 0);

    assert_eq!(
        unsupported,
        RewardsBody::NotAnswerable(NOT_ANSWERABLE.text()),
        "a method-not-found answer came out as {unsupported:?}"
    );
    assert!(
        matches!(broken, RewardsBody::Unreachable(_)),
        "a transport failure came out as {broken:?}"
    );

    // The reader is told what to do about it, not handed the wire's error code.
    let RewardsBody::NotAnswerable(sentence) = &unsupported else {
        unreachable!("asserted above");
    };
    assert!(
        !sentence.contains("32601"),
        "the JSON-RPC code reached the screen: {sentence:?}"
    );

    // The spellings a transport may forward instead of the code, and one that must NOT match:
    // "method" alone is a word an ordinary failure can contain.
    for reason in [
        "-32601",
        "Method Not Found",
        "method_not_found",
        "unknown method",
    ] {
        assert!(
            is_method_not_found(reason),
            "{reason:?} was not recognised as method-not-found"
        );
    }
    for reason in [TRANSPORT_FAILED, "the method timed out", "connection reset"] {
        assert!(
            !is_method_not_found(reason),
            "{reason:?} was wrongly recognised as method-not-found"
        );
    }
}

/// **Amber is reachable ONLY from a read that was taken and genuinely failed.**
///
/// The colour claim, asserted over every state rather than over the one under repair: exactly one
/// of the five bodies paints [`PaneState::Unreachable`], and the state a real install shows today
/// — nothing remembered, because no shipped node answers the mapping read — paints the recessed
/// note instead. A revision that reverted the split would fail here even if every sentence stayed
/// correct, because the sentences were never the defect; the colour was.
#[test]
fn amber_is_reachable_only_from_a_read_that_genuinely_failed() {
    let what_a_real_install_shows = body_of(None, 0);
    let cases = [
        ("a read in flight", body_of(Some(&PaneReading::Waiting), 0)),
        (
            "no read taken, the node cannot be asked",
            what_a_real_install_shows.clone(),
        ),
        (
            "a node that answered -32601",
            body_of(Some(&PaneReading::Unreachable(METHOD_NOT_FOUND)), 0),
        ),
        (
            "a read that failed on the transport",
            body_of(Some(&PaneReading::Unreachable(TRANSPORT_FAILED)), 0),
        ),
        (
            "answered: no distributor",
            body_of(
                Some(&PaneReading::Answered::<RewardDistributorStatusRecord>(
                    None,
                )),
                0,
            ),
        ),
        (
            "answered with a record",
            body_of(Some(&PaneReading::Answered(Some(live_paid_record()))), NOW),
        ),
    ];

    let amber: Vec<&str> = cases
        .iter()
        .filter(|(_, body)| matches!(body.painted(), Painted::Banner(PaneState::Unreachable(_))))
        .map(|(name, _)| *name)
        .collect();
    assert_eq!(
        amber,
        vec!["a read that failed on the transport"],
        "the amber states are wrong"
    );
    assert!(
        matches!(what_a_real_install_shows.painted(), Painted::Note(_)),
        "the state every install reaches is painted {:?}",
        what_a_real_install_shows.painted()
    );
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
    let bytes = store_bytes(STORE_ID).expect("a 64-hex id parses");

    assert_eq!(store_key_of_bytes(bytes), STORE_ID);
    assert_eq!(
        store_bytes(&format!("0x{}", STORE_ID.to_ascii_uppercase())),
        Some(bytes),
        "the same id in another form parsed to different bytes"
    );
    assert_eq!(store_bytes("not a store id"), None);
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
    remember(
        &format!("0x{}", STORE_ID.to_ascii_uppercase()),
        PaneReading::Waiting,
    );

    let found = reading(STORE_ID).expect("the reading was remembered");
    assert!(matches!(found, PaneReading::Waiting));
    assert!(reading("not a store id").is_none());

    forget_all();
    assert!(
        reading(STORE_ID).is_none(),
        "forget_all left a reading behind"
    );
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

/// **The three sentences a person reads are the catalog's own, spelled out here.**
///
/// This test replaces one that compared `body_of` against `rewards_sections` while passing it the
/// same funding constant the mount passed — green by construction, and green at any value, which is
/// why it "covered" the cadence sentence that finding 1 was about. The expected sentences are now
/// built from the catalog keys and this record's own numbers, so the assertion is about what
/// reaches the screen rather than about two call sites agreeing.
#[test]
fn the_three_sentences_shown_are_the_catalog_sentences_for_this_record() {
    use crate::amount::amount_with_unit;
    use crate::rewards::copy::{ENTRY_SET_KNOWN, PAID_OUT_TOTAL, STATUS_LIVE};
    use crate::wallet::state::Asset;

    let record = live_paid_record();
    let shown = sentences_for(&record);

    let expected = vec![
        STATUS_LIVE.text(),
        ENTRY_SET_KNOWN.with(
            &Args::new()
                .text("entry_count", "3")
                .text("last_entry_write_at", (NOW - 300).to_string()),
        ),
        PAID_OUT_TOTAL.with(
            &Args::new()
                .text("amount", amount_with_unit(Asset::DIG, 12_500))
                .text("last_cycle_completed_at", (NOW - 100).to_string()),
        ),
    ];
    assert_eq!(shown, expected);

    // The one money figure on this surface is formatted, never a base-unit integer.
    assert!(
        !shown[2].contains("12500") && !shown[2].contains("12,500"),
        "a base-unit integer reached the screen: {:?}",
        shown[2]
    );
}

/// **The section this mount drops is the CADENCE one, and no cadence sentence reaches the screen.**
///
/// Two halves, because dropping by count is only honest while the count still names the right
/// fact. First: the fact layer still produces four sections and the fourth is still the cadence
/// sentence — if `rewards_sections` reorders its output, this fails rather than silently dropping
/// the payout total instead. Second: nothing the mount renders is that sentence.
///
/// The dropped sentence is the one finding 1 was about: for any distributor with a written entry
/// set, a compiled-in `0` funding rate made `CadenceReading::NoFundingRateChosen` the answer, whose
/// English tells the reader to choose a funding rate — on a card listing stores this computer
/// mirrors FOR SOMEONE ELSE.
#[test]
fn the_dropped_section_is_the_cadence_one_and_nothing_here_renders_it() {
    use crate::rewards::copy::CADENCE_NO_FUNDING_RATE;

    let record = live_paid_record();
    let produced = rewards_sections(&record, NOW, CADENCE_ARGUMENT_THIS_MOUNT_DISCARDS)
        .into_iter()
        .map(|section| section.heading.unwrap_or_default())
        .collect::<Vec<String>>();
    assert_eq!(
        produced.len(),
        4,
        "the fact layer no longer says four things"
    );
    assert_eq!(
        produced[3],
        CADENCE_NO_FUNDING_RATE.text(),
        "the fourth section is not the cadence one any more, so this mount drops the wrong fact"
    );

    let shown = sentences_for(&record);
    assert_eq!(shown.len(), FACTS_THIS_MOUNT_CAN_SUPPORT);
    assert_eq!(
        shown.len(),
        3,
        "three facts, one per section this mount keeps"
    );
    assert_eq!(
        shown.as_slice(),
        &produced[..3],
        "the kept sentences are not the first three"
    );
    assert!(
        !shown.contains(&CADENCE_NO_FUNDING_RATE.text()),
        "the cadence sentence reached the screen: {shown:?}"
    );
}

/// **No sentence on this surface addresses its reader as the funder.**
///
/// The measurement finding 2 made: nothing in this file asserted WHO a figure or a sentence is
/// about. This card is "Capsules mirrored here" — a store this computer mirrors for someone else —
/// so its reader is a payee, and a sentence telling them to choose a funding rate tells them the
/// rate they are paid at is theirs to set, and that nothing accrues until they act. A false subject
/// is worse than a false number: the reader has no figure to look up and check.
///
/// Swept over every record shape a person can reach, and over the mount's own banner sentences too,
/// because a funding instruction in a banner would read exactly the same way.
#[test]
fn no_sentence_here_addresses_the_reader_as_the_funder() {
    // Every cadence sentence in `rewards::copy` contains "funding rate", so this list also keeps
    // the whole cadence family off this surface however it is reached.
    const FUNDER_ROLE: &[&str] = &[
        "funding rate",
        "funding amount",
        "choose a",
        "set a rate",
        "top up",
        "refill",
        "fund the",
        "your distributor",
    ];

    let mut swept = 0;
    for (name, record) in every_reachable_record() {
        for sentence in sentences_for(&record) {
            let lowered = sentence.to_lowercase();
            for term in FUNDER_ROLE {
                assert!(
                    !lowered.contains(term),
                    "the {name} record renders a sentence addressing a funder ({term:?}): \
                     {sentence:?}"
                );
            }
            swept += 1;
        }
    }
    assert_eq!(swept, 18, "the sweep covered the wrong number of sentences");

    for msg in [SECTION_TITLE, SHOW, HIDE, WAITING, EMPTY, NOT_ANSWERABLE] {
        let lowered = msg.text_in(crate::i18n::Language::En).to_lowercase();
        for term in FUNDER_ROLE {
            assert!(
                !lowered.contains(term),
                "{} addresses a funder ({term:?}): {lowered:?}",
                msg.key()
            );
        }
    }
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
        assert_ne!(rendered, msg.key(), "{} is not in the catalog", msg.key());
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
/// person reconstruct the never-admitted versus evicted split.
///
/// Swept over this module's OWN English values only. An earlier revision of this comment said the
/// fact sentences were "guarded there" in `rewards::copy`, which was false: that module's only copy
/// sweep (`no_rewards_copy_contains_a_forbidden_phrase`) is a funding-FLOOR sweep — "minimum
/// funding", "requires uptime", "floor", "gate" — with no eviction, entitlement or accrual term in
/// it, so clauses 6 and 7 over the rendered sentences were asserted by nothing at all
/// (dig_ecosystem#3273 adversarial gate, finding 4). `rewards/` is read-only to this lane, so the
/// missing assertion is made here instead, over the sentences this mount renders:
/// [`the_rendered_fact_sentences_carry_no_claim_entitlement_or_eviction`].
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

/// **The RENDERED fact sentences carry no claim status, entitlement, accrual or eviction.**
///
/// SPEC §12.5 clause 6 and clause 7 over the sentences a person actually reads here — the
/// assertion finding 4 found missing everywhere. `rewards::copy`'s own sweep checks a different
/// list (funding-floor phrases), and `no_sentence_here_offers_a_claim_status_or_an_eviction` above
/// checks only this module's four banner sentences; neither one looks at the three fact sentences
/// that come from the shipped fact layer.
///
/// Swept over every record shape a person can reach, so the arm that renders a given sentence is
/// exercised rather than assumed. Clause 7's terms are in the same list as clause 6's because both
/// clauses are about a WORD reaching the screen: the mount is allowed to say how many mirrors are
/// in the entry set, and not allowed to say that any of them was removed from it, was never
/// admitted to it, or is owed anything.
#[test]
fn the_rendered_fact_sentences_carry_no_claim_entitlement_or_eviction() {
    // Clause 6: a claim status, an accrual, an entitlement, or an `eligible`/`claiming` word
    // derived from a distributor existing.
    const CLAUSE_6: &[&str] = &[
        "eligible",
        "eligibility",
        "claimable",
        "claiming",
        "will claim",
        "entitle",
        "accru",
        "owed",
        "earned",
        "you will be paid",
    ];
    // Clause 7: the never-admitted versus evicted split.
    const CLAUSE_7: &[&str] = &[
        "evict",
        "removed from",
        "no longer in",
        "never admitted",
        "not admitted",
        "dropped from",
    ];

    for (name, record) in every_reachable_record() {
        for sentence in sentences_for(&record) {
            let lowered = sentence.to_lowercase();
            for (clause, terms) in [("6", CLAUSE_6), ("7", CLAUSE_7)] {
                for term in terms {
                    assert!(
                        !lowered.contains(term),
                        "the {name} record renders a sentence breaking SPEC 12.5 clause {clause} \
                         ({term:?}): {sentence:?}"
                    );
                }
            }
        }
    }
}
