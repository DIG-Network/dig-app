//! The Activity pane: every spend the node made without asking (dig-app#289).
//!
//! # What this pane is for
//!
//! The node signs the mirror-coin collateral cycle automatically. **This pane is what replaces
//! authorization with accountability** — the user cannot approve each spend, so they must be able to
//! review every one. That is the bar it is held to, and it is why the pane has no verbs: auditing is
//! reading, and a control here would be an action over money that has already moved.
//!
//! # It renders the record, it does not decide it
//!
//! Whether the tab is loading, empty, unreachable or ready is decided by
//! [`crate::window_model::build`] from [`ActivityReading`], and drawn by the shared banner every
//! pane uses. This module only lays out a ledger it has been given. The one thing it must never do
//! is draw a row set that disagrees with that banner — so an unreadable record reaches this function
//! as an empty draw, and the banner above carries the reason.
//!
//! # The honesty rules the layout enforces
//!
//! * **A chain reference is offered only where the chain confirmed it.** Evidence comes from
//!   [`AutomatedSpend::chain_reference`], which cannot produce anything for an unconfirmed spend, so
//!   this pane cannot show a coin id for a spend that may never have existed. An *expected* coin is a
//!   separate row with separate wording — see [`chain_row`].
//! * **"Failed" is never rendered as "no money moved" unless that is true.** Two of the three
//!   failure stages put a signed bundle on the wire, and `Unresolved` means the node signed and does
//!   not know. On the accountability surface for spends nobody approved, calling any of those
//!   un-spent is the money-lie class. Every arm goes through
//!   [`SpendOutcome::is_certainly_unspent`].
//! * **A failure is a full row**, badged and reasoned, never a gap. The entry a blocked user most
//!   needs is the one saying the node could not pay, and a record listing only successes makes a
//!   blocked node look idle.
//! * **Amounts go through [`crate::amount`]**, which knows $DIG is a CAT at three decimals. A local
//!   divisor here is the #2295 defect on a money surface.

use egui::Rect;

use super::card;
use super::data::{self, Readout, Tone, Value};
use super::flow::Flow;
use super::text;
use crate::activity::{ActivityReading, AutomatedSpend, SpendOutcome};
use crate::confirm::gui::render::space;
use crate::confirm::gui::theme::Tokens;
use crate::tray_menu::TrayAction;
use crate::window_model::Tab;

/// Draw the audit record, newest first.
///
/// Returns `Option<TrayAction>` to match every other pane's shape, and always `None`: this tab
/// offers no verbs. Keeping the signature uniform is what lets [`super::draw_tab`] stay one
/// exhaustive match rather than a special case.
pub(crate) fn draw(
    flow: &mut Flow,
    t: &Tokens,
    _tab: &Tab,
    facts: &super::facts::PaneFacts,
) -> Option<TrayAction> {
    flow.place(|ui, at| (text::body(ui, at, t, LEAD), ()));
    flow.gap(space::S4);

    // Only a READ record produces rows. Pending and Unknown draw no ENTRIES, because the banner the
    // model chose is already saying what is happening — and a row set drawn beside a "could not read
    // this" banner would be a second, contradictory answer on one screen.
    if let ActivityReading::Known(ledger) = &facts.activity {
        // Drawn ABOVE the entries, because it changes what the entries below it mean: a list that
        // may be missing rows is a different object from a complete one, and a person who reads the
        // list first and the caveat afterwards has already drawn the wrong conclusion.
        if !ledger.is_complete() {
            let notice = incomplete_notice(ledger.unreadable_lines);
            flow.place(move |ui, at| (text::body(ui, at, t, &notice), ()));
            flow.gap(space::S3);
        }
        for spend in &ledger.spends {
            flow.place(|ui, at| (entry(ui, at, t, spend), ()));
            flow.gap(space::S3);
        }
    }

    // Drawn in EVERY state, deliberately — see [`provenance`].
    flow.place(|ui, at| (provenance(ui, at, t), ()));
    None
}

/// Where this record actually lives, and how to read it without this window.
///
/// # Why this is drawn in every state, including the failed one
///
/// Two reasons, and the second is the load-bearing one.
///
/// First, a pane that draws NOTHING is a blank rectangle with a banner over it, and this tab has no
/// verbs to fall back on — so in three of its four states there would be nothing under the banner at
/// all. That is the one thing a window may not be.
///
/// Second, and this is the point: the out-of-funds notification repeats hourly, and an hourly
/// notification is the kind of thing people silence at the OS level, permanently and silently. The
/// mitigation the spec asks for is that **this tab and `dign` carry the same state**, so silencing
/// the notification does not silence the truth. Saying so is only useful if it is said when the
/// window itself cannot answer — which is precisely the state where a naive implementation prints
/// nothing.
///
/// It asserts no figure, so it is honest in all four states: it names where the record is kept and
/// what to type, and claims nothing about what the record contains.
fn provenance(ui: &mut egui::Ui, at: Rect, t: &Tokens) -> f32 {
    card::card(ui, at, t, Some(PROVENANCE_TITLE), |flow| {
        flow.place(|ui, at| (text::body(ui, at, t, PROVENANCE_BODY), ()));
        flow.gap(space::S2);
        flow.place(|ui, at| {
            (
                data::rows(
                    ui,
                    at,
                    t,
                    &[Readout::new(
                        "Same list, from a terminal",
                        Value::Identifier(CLI_VERB.to_string()),
                    )],
                ),
                (),
            )
        });
    })
}

/// The provenance card's heading.
const PROVENANCE_TITLE: &str = "Where this comes from";

/// The provenance card's body. Says where the record is KEPT — which is why a node that is not
/// running has nothing to show — and that this window is a view of it rather than a second copy.
const PROVENANCE_BODY: &str =
    "Your node keeps this record, not this window, so it is the same list however you read it — \
     including on a computer with no screen. If you ever turn these notifications off, this is \
     still here.";

/// The `dign` verb that prints the same record.
///
/// Named here rather than left to the reader because it is the escape hatch for somebody who has
/// silenced the notification, and an escape hatch nobody can find is not one.
const CLI_VERB: &str = "dign spends list";

/// The sentence under the tab title, saying what the reader is looking at and why it exists.
const LEAD: &str = "Everything DIG spent on your behalf without asking, so you can check it. Your \
                    node keeps these running on a weekly cycle, which is why it does not stop to \
                    ask each time.";

/// One spend, as a card.
fn entry(ui: &mut egui::Ui, at: Rect, t: &Tokens, spend: &AutomatedSpend) -> f32 {
    card::card(ui, at, t, Some(&spend.kind.summary()), |flow| {
        let mut readouts = vec![
            Readout::new("Amount", Value::Word(spend.amount())),
            Readout::new("Outcome", outcome_value(spend)),
        ];
        if let Some(store) = &spend.store {
            readouts.push(Readout::new("Store", Value::Identifier(store.clone())));
        }
        readouts.push(chain_row(spend));

        flow.place(move |ui, at| (data::rows(ui, at, t, &readouts), ()));
        flow.gap(space::S2);
        let word = spend.outcome.word();
        let tone = outcome_tone(&spend.outcome);
        flow.place(move |ui, at| {
            let badge = data::badge(ui, at.left_top(), t, word, tone);
            (badge.height(), ())
        });
    })
}

/// The sentence shown when part of the node's trail could not be read.
///
/// # Why the list is still shown, and still qualified
///
/// Hiding the entries would discard the ones that ARE readable, which is worse than showing them —
/// but presenting them unqualified would let a trail that is missing rows read as the whole story,
/// and on this surface a missing row is invisible money movement. So the readable part is shown,
/// under a sentence that says the list is short. The count is named because "some" and "four hundred"
/// call for different reactions.
fn incomplete_notice(lines: Option<u64>) -> String {
    // `None` is the node never having SAID, and it gets its own sentence rather than a count
    // of zero or a guessed number. "We cannot tell whether this is everything" is weaker than
    // "3 are missing" and stronger than silence, and it is the only one of the three that is
    // true when the node stayed quiet (dig-app#289).
    let Some(lines) = lines else {
        return concat!(
            "This node did not report whether its record is complete, so the list below may ",
            "not be everything. Run the DIG node's own check to see what is unaccounted for."
        )
        .to_string();
    };
    let lines = match lines {
        1 => "1 entry".to_string(),
        n => format!("{n} entries"),
    };
    format!(
        "Part of this record could not be read — {lines} are missing from the list below. What is \
         shown is accurate, but it is not everything. Run the DIG node's own check to see what is \
         unaccounted for."
    )
}

/// The chain row: what there is to check, and how strong a claim it is.
///
/// # The row that must not lie
///
/// Three different things can go here and they are three different claims:
///
/// * a coin the chain was **seen** to hold — evidence, and the only one drawn as a plain identifier;
/// * a coin the node **expected** to create, on a spend that may have landed — drawn as an
///   [`Value::Unknown`] and explicitly labelled *expected*, matching `dign`'s own `~<id> (expected)`;
/// * nothing at all, on a spend that certainly never left this machine.
///
/// The naive version has two arms — a coin id, or "nothing was spent" — and it puts the third
/// sentence on the second and fourth cases too. That is the money-lie: a spend whose broadcast or
/// confirmation failed **may have gone through**, and this tab is the accountability surface for
/// spends the user never approved, which makes it the worst possible place to assert otherwise.
fn chain_row(spend: &AutomatedSpend) -> Readout {
    if let Some(coin_id) = spend.chain_reference() {
        return Readout::new("Checkable on chain", Value::Identifier(coin_id.to_string()));
    }
    if let Some(expected) = spend.expected_coin() {
        // `Unknown`, not `Identifier`: it is drawn in the faint style reserved for the absence of a
        // value, so it cannot be mistaken at a glance for the confirmed row above.
        return Readout::new(
            "Coin to look for",
            Value::Unknown(format!("{expected} (expected, not confirmed)")),
        );
    }
    Readout::new(
        "Checkable on chain",
        // `Unknown` rather than an omitted row, because the ABSENCE is the fact and a missing row
        // would read as an oversight.
        Value::Unknown(match spend.outcome.is_certainly_unspent() {
            true => "Nothing was spent".to_string(),
            // Reached only when the node named no intended coin. Still must not claim nothing moved.
            false => "Not known".to_string(),
        }),
    )
}

/// What the outcome column says.
fn outcome_value(spend: &AutomatedSpend) -> Value {
    match &spend.outcome {
        SpendOutcome::Confirmed { height, .. } => Value::Measure {
            amount: height.to_string(),
            unit: "block".to_string(),
        },
        SpendOutcome::Pending => Value::Unknown("Not sent yet".to_string()),
        SpendOutcome::Submitted => Value::Unknown("Sent, not yet seen on chain".to_string()),
        // The two arms that may have moved money render as an ABSENCE of a reading, beside the
        // reason. A `Value::Word` here would set the sentence in the same weight as a confirmed
        // height, which is the visual form of the same overclaim the words avoid.
        SpendOutcome::Unresolved => Value::Unknown(
            "DIG signed this and could not find out what happened. It may have gone through."
                .to_string(),
        ),
        SpendOutcome::Failed { stage, reason } if stage.may_have_moved_money() => Value::Unknown(
            format!("{} — and it may still have gone through.", reason.summary()),
        ),
        SpendOutcome::Failed { reason, .. } => Value::Word(reason.summary()),
    }
}

/// The badge tone for an outcome.
///
/// A never-signed failure is [`Tone::Warn`] and never an alarm colour: no money moved, so nothing was
/// lost — something the node wanted to do is waiting on the user. The arms that may have moved money
/// are [`Tone::Neutral`], deliberately the same tone as "in flight": they are an open question rather
/// than a fault, and colouring an unknown as a failure is the same overclaim in a different medium.
fn outcome_tone(outcome: &SpendOutcome) -> Tone {
    match outcome {
        SpendOutcome::Confirmed { .. } => Tone::Good,
        SpendOutcome::Pending | SpendOutcome::Submitted | SpendOutcome::Unresolved => Tone::Neutral,
        SpendOutcome::Failed { stage, .. } if stage.may_have_moved_money() => Tone::Neutral,
        SpendOutcome::Failed { .. } => Tone::Warn,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::activity::{ActivityLedger, FailureStage, SpendFailure, SpendKind};
    use crate::wallet::state::Asset;

    /// A spend varying ONLY in its outcome, and always carrying an intended coin id — see the
    /// matching fixture note in `crate::activity`.
    fn spend(outcome: SpendOutcome) -> AutomatedSpend {
        AutomatedSpend {
            at_unix: 1_787_500_000,
            kind: SpendKind::MirrorCoinCollateral,
            asset: Asset::DIG,
            base_units: 20_000,
            store: Some("store-a".to_string()),
            fee_mojos: 1_000_000,
            intended_coin_id: Some("intended99".to_string()),
            outcome,
        }
    }

    fn failed_at(stage: FailureStage) -> SpendOutcome {
        SpendOutcome::Failed {
            stage,
            reason: SpendFailure::InsufficientFunds,
        }
    }

    /// The same spend with **no intended coin id**.
    ///
    /// # Why this fixture has to exist, and what it caught
    ///
    /// [`chain_row`] answers the expected-coin branch FIRST, so every entry that names an intended
    /// coin returns before reaching the final fallback. A guard written only against [`spend`]
    /// therefore never executes that fallback at all — and it demonstrably did not: reverting the
    /// fix to its original `_ => "Nothing was spent"` left every one of those assertions GREEN,
    /// because the lie lives on a line the fixture could not reach.
    ///
    /// A node is not obliged to name an intended coin, so this is a real entry shape rather than a
    /// contrived one — and it is the only shape that puts the fallback under test.
    fn spend_without_intended_coin(outcome: SpendOutcome) -> AutomatedSpend {
        AutomatedSpend {
            intended_coin_id: None,
            ..spend(outcome)
        }
    }

    fn confirmed() -> SpendOutcome {
        SpendOutcome::Confirmed {
            height: 9_172_077,
            coin_id: "ab12".to_string(),
        }
    }

    /// **Only a confirmed spend's coin is presented as evidence.**
    ///
    /// The fixture varies only the outcome and every entry carries an intended coin id, so a version
    /// reading the coin off the entry rather than off the outcome would render an `Identifier` — the
    /// same visual weight as a confirmation — for a spend the chain never showed.
    #[test]
    fn only_a_confirmed_spend_shows_a_coin_as_evidence() {
        let row = chain_row(&spend(confirmed()));
        assert_eq!(row.label, "Checkable on chain");
        assert!(row.value.is_known(), "a confirmation is a real reading");
        assert_eq!(row.value.shown(), "ab12");

        for unproven in [
            SpendOutcome::Submitted,
            SpendOutcome::Unresolved,
            failed_at(FailureStage::Broadcast),
            failed_at(FailureStage::Confirmation),
            failed_at(FailureStage::BeforeSigning),
        ] {
            let row = chain_row(&spend(unproven.clone()));
            assert!(
                !row.value.is_known(),
                "{unproven:?} rendered a coin at the same weight as a confirmation: {row:?}"
            );
        }
    }

    /// **NO unconfirmed outcome is described as money that did not move — except the one where that
    /// is true.**
    ///
    /// This is the money-lie guard at the rendering layer, and it is deliberately separate from the
    /// model's: the model can be right while the pane writes its own sentence, which is exactly what
    /// the first version of this file did (`_ => "Nothing was spent"`). The assertion is over the
    /// TEXT a person reads, on all five arms, with the never-signed arm as the truthful control —
    /// without that control the test would also pass on a pane that never says it at all.
    #[test]
    fn the_pane_never_says_nothing_was_spent_about_a_spend_that_may_have_landed() {
        const CLAIM: &str = "Nothing was spent";

        assert_eq!(
            chain_row(&spend(failed_at(FailureStage::BeforeSigning)))
                .value
                .shown(),
            CLAIM,
            "a spend that was never signed genuinely did not happen, and should say so"
        );

        for risky in [
            SpendOutcome::Submitted,
            SpendOutcome::Unresolved,
            failed_at(FailureStage::Broadcast),
            failed_at(FailureStage::Confirmation),
        ] {
            // BOTH fixtures, because they take different branches of `chain_row`, and the branch
            // without an intended coin is the one the original bug lived on. Sweeping only the
            // richer fixture is how this guard was green against the very defect it names.
            for entry in [
                spend(risky.clone()),
                spend_without_intended_coin(risky.clone()),
            ] {
                let rendered = format!(
                    "{} {} {}",
                    chain_row(&entry).value.shown(),
                    outcome_value(&entry).shown(),
                    entry.outcome.word()
                );
                assert!(
                    !rendered.contains(CLAIM),
                    "{risky:?} may have moved money and the pane claimed otherwise: {rendered}"
                );
                assert!(
                    !rendered.to_lowercase().contains("did not happen"),
                    "{risky:?}: {rendered}"
                );
            }
        }
    }

    /// **The fallback row does not claim nothing was spent when nobody knows.**
    ///
    /// This is the guard that actually covers the line the original bug was on. Every entry here
    /// names NO intended coin, so [`chain_row`] falls through its expected-coin branch and reaches
    /// the final arm — the arm that used to read `_ => "Nothing was spent"`.
    ///
    /// The never-signed entry is the truthful control and it is load-bearing in both directions: it
    /// is the one case that MUST still say the money did not move, so a "fix" that simply deleted
    /// the sentence would fail here rather than passing quietly.
    #[test]
    fn the_fallback_row_does_not_claim_nothing_was_spent_when_nobody_knows() {
        for risky in [
            SpendOutcome::Submitted,
            SpendOutcome::Unresolved,
            failed_at(FailureStage::Broadcast),
            failed_at(FailureStage::Confirmation),
        ] {
            let shown = chain_row(&spend_without_intended_coin(risky.clone()))
                .value
                .shown()
                .to_string();
            assert_eq!(
                shown, "Not known",
                "{risky:?} may have moved money, and with no coin to name the only honest answer \
                 is that we do not know"
            );
        }

        assert_eq!(
            chain_row(&spend_without_intended_coin(failed_at(
                FailureStage::BeforeSigning
            )))
            .value
            .shown(),
            "Nothing was spent",
            "a spend that was never signed must still say so plainly"
        );
    }

    /// **An unconfirmed spend that may have landed names the coin to go and look for, labelled as an
    /// expectation.**
    ///
    /// The label is asserted, not just the presence of the id: an expected coin rendered without the
    /// word "expected" is indistinguishable from evidence, which is the whole distinction the node's
    /// record keeps as two separate types.
    #[test]
    fn an_expected_coin_is_labelled_as_expected() {
        for open in [
            SpendOutcome::Submitted,
            SpendOutcome::Unresolved,
            failed_at(FailureStage::Confirmation),
        ] {
            let row = chain_row(&spend(open.clone()));
            assert_eq!(row.label, "Coin to look for", "{open:?}");
            assert!(row.value.shown().contains("intended99"), "{open:?}");
            assert!(
                row.value.shown().contains("expected"),
                "{open:?} presented an expectation as evidence: {}",
                row.value.shown()
            );
            assert!(!row.value.is_known(), "{open:?} must not read as a reading");
        }
    }

    /// **A post-signing failure is toned as an open question, not as a fault.**
    ///
    /// Same tone as "in flight", because that is what it is. Colouring an unknown as a failure is the
    /// same overclaim the words avoid, in a medium a person reads faster than words. The never-signed
    /// arm is the control that keeps this from being satisfied by a pane with one tone.
    #[test]
    fn the_badge_tone_does_not_overclaim_either() {
        assert_eq!(outcome_tone(&confirmed()), Tone::Good);
        assert_eq!(
            outcome_tone(&failed_at(FailureStage::BeforeSigning)),
            Tone::Warn,
            "a spend that never left is a thing waiting on the user"
        );
        for risky in [
            SpendOutcome::Unresolved,
            failed_at(FailureStage::Broadcast),
            failed_at(FailureStage::Confirmation),
        ] {
            assert_eq!(
                outcome_tone(&risky),
                Tone::Neutral,
                "{risky:?} is an open question, not a fault"
            );
        }
        assert_eq!(outcome_tone(&SpendOutcome::Submitted), Tone::Neutral);
    }

    /// **An unproven spend never renders a block height**, which IS the claim that the chain saw it.
    #[test]
    fn an_unproven_spend_shows_no_block_height() {
        let confirmed_value = outcome_value(&spend(confirmed()));
        assert!(confirmed_value.is_known());
        assert_eq!(confirmed_value.shown(), "9172077");

        for unproven in [
            SpendOutcome::Pending,
            SpendOutcome::Submitted,
            SpendOutcome::Unresolved,
            failed_at(FailureStage::Broadcast),
        ] {
            assert!(
                !outcome_value(&spend(unproven.clone())).is_known(),
                "{unproven:?} rendered as a reading"
            );
        }
        assert_eq!(
            outcome_value(&spend(failed_at(FailureStage::BeforeSigning))).shown(),
            "Not enough funds",
            "a settled failure states its reason where a height would sit"
        );
    }

    /// **An incomplete trail says so, names the count, and does not claim the list is everything.**
    #[test]
    fn an_incomplete_trail_is_qualified_rather_than_hidden() {
        let notice = incomplete_notice(Some(4));
        assert!(notice.contains("4 entries"), "{notice}");
        assert!(notice.contains("not everything"), "{notice}");
        assert!(
            incomplete_notice(Some(1)).contains("1 entry"),
            "one missing entry is not '1 entries'"
        );

        // And a ledger the node VOUCHED for draws no notice at all — the control, without which
        // this could pass on a pane that always warned.
        assert!(ActivityLedger {
            unreadable_lines: Some(0),
            ..Default::default()
        }
        .is_complete());
    }

    /// **A count the node never gave is not a count of zero**, and the pane says so in its own
    /// words rather than falling silent (dig-app#289).
    ///
    /// The control is the `Some(0)` case: an unknown must be qualified while a vouched-for record
    /// must not be, or a pane that warns unconditionally would pass this.
    #[test]
    fn an_unreported_count_is_qualified_rather_than_read_as_nothing_missing() {
        assert!(
            !ActivityLedger::default().is_complete(),
            "a ledger nobody vouched for must not present as the whole story"
        );

        let unknown = incomplete_notice(None);
        assert!(unknown.contains("did not report"), "{unknown}");
        assert!(unknown.contains("may not be everything"), "{unknown}");

        // It must NOT borrow the counted sentence's wording, which asserts entries are missing —
        // a claim nobody made. Checked on the distinctive phrase rather than on a digit, because
        // "0 entries" would also be absent from an honest unknown notice.
        assert!(
            !unknown.contains("could not be read"),
            "an unknown count must not assert that entries were unreadable: {unknown}"
        );
    }

    /// **The lead says why the node did not ask**, because a person reading an audit record of
    /// unapproved spends will want that answered before anything else on the screen.
    #[test]
    fn the_lead_explains_the_absence_of_approval() {
        assert!(LEAD.contains("without asking"), "{LEAD}");
        assert!(LEAD.contains("weekly"), "{LEAD}");
    }

    /// **The provenance card names the CLI escape hatch**, which is the whole mitigation for a user
    /// who silences the hourly notification at the OS level — and it must be the verb dig-node
    /// actually ships, not a plausible-looking one.
    #[test]
    fn the_pane_names_where_else_this_record_can_be_read() {
        assert_eq!(
            CLI_VERB, "dign spends list",
            "this is the verb dig-node#378 shipped; a near-miss is worse than no verb at all"
        );
        assert!(
            PROVENANCE_BODY.contains("no screen"),
            "a headless node is the reason the record is node-side: {PROVENANCE_BODY}"
        );
        assert!(
            PROVENANCE_BODY.contains("turn these notifications off"),
            "silencing the toast must not read as silencing the record: {PROVENANCE_BODY}"
        );
    }

    /// **The provenance card claims no figure**, so it stays true in all four states — including the
    /// one where the node could not be reached at all.
    #[test]
    fn the_provenance_card_asserts_nothing_measurable() {
        for text in [PROVENANCE_TITLE, PROVENANCE_BODY] {
            assert!(
                !text.chars().any(|c| c.is_ascii_digit()),
                "a figure here would be a claim the failed state cannot support: {text}"
            );
        }
    }
}
