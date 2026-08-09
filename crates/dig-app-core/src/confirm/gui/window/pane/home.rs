//! The Home tab: what DIG is doing on this computer, the other DIG apps it can open, and the way to
//! the logs when it cannot say.
//!
//! # Why Home is the exemplar
//!
//! It is the tab a person lands on, it is the most data-rich one that needs no new plumbing, and it
//! exercises the parts of the vocabulary a Phase-2 tab will reach for first: cards grouping facts,
//! readouts with units, a badge, an action group with a hierarchy, a launcher, and both honest
//! absences — a figure the node has not reported, and a card whose data is not wired up.
//!
//! # What it deliberately no longer holds (dig_ecosystem#2358)
//!
//! **The account rows.** `Account`, `Second factor` and the receive-address code all described the
//! account, which now has a whole tab of its own — and the receive card was a byte-identical second
//! copy of the Wallet tab's. A figure repeated is a figure that will eventually disagree with
//! itself, and a QR code repeated is that plus a person wondering which one is the real address.
//!
//! **The cache METER.** The Content tab owns it; this tab carries the one-line reading, from the
//! same [`crate::cache::CacheSnapshot`], so the two cannot report different disks.
//!
//! # What it does NOT do
//!
//! It does not decide which actions exist. `tab.sections` arrives already decided by
//! [`crate::window_model`], and this module renders those rows as buttons — same verbs, same
//! enablement, same labels, different weight. If you find yourself asking here whether a verb
//! should be shown, the model already answered.

use super::action::{self, Action};
use super::card;
use super::copy;
use super::data::{self, Readout, Value};
use super::facts::PaneFacts;
use super::flow::Flow;
use super::text;
use crate::confirm::gui::render::space;
use crate::confirm::gui::theme::Tokens;
use crate::tray_menu::TrayAction;
use crate::window_model::Tab;

/// Draw the Home pane's content into `flow`, and report the action pressed.
pub(crate) fn draw(
    flow: &mut Flow,
    t: &Tokens,
    tab: &Tab,
    facts: &PaneFacts,
) -> Option<TrayAction> {
    machine_card(flow, t, facts);
    flow.gap(space::S4);
    node_card(flow, t, facts);
    flow.gap(space::S4);
    // Verbs before figures. The diagnostics are what a person on a broken machine came here for, so
    // the sharing card — which is the least urgent thing on the tab, and which says nothing at all
    // on a machine with no node — must not push the log-folder button below the fold at the default
    // window size.
    let mut pressed = diagnostics_card(flow, t, tab);
    flow.gap(space::S4);
    // The launcher LAST, because it is what a person browses when nothing is wrong.
    pressed = pressed.or(super::apps::launcher(flow, t, tab));
    flow.gap(space::S4);
    sharing_card(flow, t, facts);
    pressed
}

/// What this computer is running: the agent, and the version of it.
///
/// The agent's state also sits in the window's header strip, one word wide. That is not the
/// duplication dig_ecosystem#2357 removed: both come from [`copy::agent_state`] applied to the same
/// [`PaneFacts::agent_running`], so there is one derivation and two presentations of it — where the
/// cache meter was one FIGURE laid out twice, in two files, either editable without the other.
fn machine_card(flow: &mut Flow, t: &Tokens, facts: &PaneFacts) {
    let items = vec![
        Readout::new(
            copy::home::AGENT_LABEL,
            Value::Word(copy::agent_state(facts.agent_running).to_string()),
        ),
        Readout::new(
            copy::home::VERSION_LABEL,
            Value::Word(facts.version.to_string()),
        ),
    ];
    flow.place(|ui, at| {
        (
            card::card(ui, at, t, Some(copy::home::AGENT_CARD), |inner| {
                inner.place(|ui, at| (data::readouts(ui, at, t, &items), ()));
            }),
            (),
        )
    });
}

/// What the node is doing, and how full the content cache is.
fn node_card(flow: &mut Flow, t: &Tokens, facts: &PaneFacts) {
    let summary = facts.node_summary.clone();
    let (word, tone) = facts.node_state();
    let cache = facts.cache;

    flow.place(|ui, at| {
        (
            card::card(ui, at, t, Some(copy::home::NODE_CARD), |inner| {
                // The badge sits on its own line above the summary rather than beside the card's
                // title: at 480 px a title plus a badge is two things competing for one row, and the
                // badge is the one that loses its padding first.
                inner.place(|ui, at| (data::badge(ui, at.left_top(), t, word, tone).height(), ()));
                inner.gap(space::S3);
                // The engine already writes this as a sentence ("connected to ..." or the
                // actionable reason it is not), so it is prose under the badge rather than a
                // labelled figure — a label reading "What the node is doing" above a sentence that
                // says what the node is doing is the label saying it twice.
                inner.place(|ui, at| (text::body(ui, at, t, &summary), ()));
                inner.gap(space::S4);
                // A one-line READOUT of what the cache holds, not the meter — the meter lives on
                // the Content tab and is drawn once (dig_ecosystem#2357). This card used to redraw it
                // byte-identically, so the same bar appeared on two tabs and either could be edited
                // without the other. A figure repeated is a figure that will eventually disagree
                // with itself.
                inner.place(|ui, at| {
                    (
                        data::readout(
                            ui,
                            at,
                            t,
                            &Readout::new(copy::home::CACHE_CARD, cache_reading(cache)),
                        ),
                        (),
                    )
                });
            }),
            (),
        )
    });
}

/// What the cache holds, as one line — or the reason there is no figure.
///
/// A summary, deliberately, and not the meter. The Content tab owns the meter and the limit; Home
/// says only how much is in use, which is what a person scanning this tab is asking. Both figures
/// come from the same [`crate::cache::CacheSnapshot`], so the two tabs cannot disagree.
///
/// With no snapshot this is an `Unknown` carrying its reason, never a zero: nobody has reported a
/// cache, and "0 B" is the claim that the cache is empty.
fn cache_reading(cache: Option<crate::cache::CacheSnapshot>) -> Value {
    match cache {
        Some(snapshot) => Value::Word(format!(
            "{} of {}",
            crate::cache::format_cap(snapshot.used_bytes),
            crate::cache::format_cap(snapshot.cap_bytes)
        )),
        None => Value::Unknown(copy::home::CACHE_UNKNOWN.to_string()),
    }
}

/// What this computer is sharing with the network, read from the node (dig_ecosystem#2397).
///
/// # Why there is no banner and no badge here
///
/// This card carried both while its figures were undrawn skeletons. Both are gone: the four values
/// are readings now, and when they are not, each one says so itself. `window_model` already draws a
/// tab-level banner for a machine with no node — a second amber paragraph inside this card, saying
/// the same thing about the same node, is how a reader learns to skip amber paragraphs. The card
/// follows the precedent [`copy::content::ADD_NOT_WIRED`] set: state an absence once, in the place
/// it is about.
fn sharing_card(flow: &mut Flow, t: &Tokens, facts: &PaneFacts) {
    let items = sharing_readouts(facts);
    flow.place(|ui, at| {
        (
            card::card(ui, at, t, Some(copy::home::SHARING_CARD), |inner| {
                inner.place(|ui, at| {
                    (
                        card::panel(ui, at, t, None, |panel| {
                            panel.place(|ui, at| (data::readouts(ui, at, t, &items), ()));
                        }),
                        (),
                    )
                });
            }),
            (),
        )
    });
}

/// The four sharing figures, each either a reading or the reason there is none.
///
/// # All four come from `control.status`, and the first one's LABEL is why (dig_ecosystem#2397)
///
/// The obvious-looking alternative is to take the store count from
/// [`PaneFacts::hosted_stores`](super::facts::PaneFacts::hosted_stores) — the same list the Content
/// tab draws — so the two tabs agree. That is wrong here, and the reason is directly above this card:
/// [`node_card`] renders [`PaneFacts::node_summary`], which `engine.rs` builds from the SAME
/// `hosted_store_count` and which reads *"Node v0.102.2 · 3 capsule(s) cached · 3 store(s) hosted"*.
/// A list-derived figure would put 5 inches below a 3 on one tab — a contradiction visible in a
/// single glance, which is worse than the cross-tab difference it would fix.
///
/// The two numbers are both correct and count different sets: `hosted_store_count` counts stores with
/// content CACHED, while `control.hostedStores.list` returns cached ∪ pinned — dig-node's `SPEC.md`
/// §7.6 makes a pinned-but-uncached store appearing in the list a MUST. So the figure stays on the
/// status field, agreeing with the sentence above it, and the LABEL says which set it counts. The
/// reconciliation happens on the Content tab, where the extra rows say for themselves that nothing is
/// cached for them yet.
///
/// **Do not "fix" this to match the Content tab's row count.** That reintroduces the same-tab
/// contradiction, and it does so while looking like a tidy-up.
fn sharing_readouts(facts: &PaneFacts) -> Vec<Readout> {
    let absent = copy::home::sharing_unknown(facts.agent_running, facts.node_connected);
    let reading =
        |value: Option<Value>| value.unwrap_or_else(|| Value::Unknown(absent.to_string()));
    let node = facts.node_facts.as_ref();

    let [stores, capsules, pinned, uptime] = copy::home::SHARING_LABELS;
    vec![
        Readout::new(
            stores,
            reading(node.map(|n| count(n.hosted_store_count, "store"))),
        ),
        Readout::new(
            capsules,
            reading(node.map(|n| count(n.cached_capsule_count, "capsule"))),
        ),
        Readout::new(
            pinned,
            reading(node.map(|n| count(n.pinned_store_count, "store"))),
        ),
        Readout::new(
            uptime,
            reading(node.map(|n| Value::Word(n.uptime_phrase()))),
        ),
    ]
}

/// A count and the thing it counts, as a measure.
///
/// Never a bare [`Value::Word`] of digits: [`data`]'s own rule is that a figure without its unit is a
/// figure a reader has to guess at, and these three counts sit in one column where `5`, `3` and `2`
/// with no units would read as one quantity measured three ways.
fn count(n: u64, singular: &str) -> Value {
    Value::Measure {
        amount: n.to_string(),
        unit: match n {
            1 => singular.to_string(),
            _ => format!("{singular}s"),
        },
    }
}

/// The tab's diagnostic verbs, as a weighted button group.
///
/// The launcher's rows are excluded: they are drawn as cards by [`super::apps::launcher`], and a
/// verb rendered twice on one tab is two controls a person has to tell apart before pressing either.
/// The split reads the model's own [`crate::window_model::APPS_HEADING`] rather than a position, so
/// reordering the sections upstream cannot silently move a launch row into this card.
fn diagnostics_card(flow: &mut Flow, t: &Tokens, tab: &Tab) -> Option<TrayAction> {
    let actions = actions_of(tab);
    if actions.is_empty() {
        return None;
    }
    let live = flow.live();
    flow.place(|ui, at| {
        let (height, pressed) =
            card::interactive_card(ui, at, t, live, Some(copy::home::ACTIONS_CARD), |inner| {
                let hit = inner.place(|ui, at| action::buttons(ui, at, t, live, &actions));
                inner.gap(space::S3);
                inner.place(|ui, at| (text::caption(ui, at, t, copy::home::DIAGNOSTICS_HINT), ()));
                hit
            });
        (height, pressed.flatten())
    })
}

/// The tab's diagnostic rows as weighted actions, in the model's order.
///
/// Built from the WHOLE tab through the ONE derivation in [`super::actions_in`] — including the
/// occurrence counting that gives each row its stable element id — and only then filtered. A second
/// copy of that derivation here is what previously addressed `Open the log folder` by its index and
/// made it unclickable, and filtering FIRST would renumber every row after a dropped one.
fn actions_of(tab: &Tab) -> Vec<Action<TrayAction>> {
    let launchers = super::apps::launch_actions(tab);
    super::actions_of(tab)
        .into_iter()
        .filter(|action| {
            !launchers
                .iter()
                .any(|launch| launch.element == action.element)
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::confirm::gui::render::Weight;
    use crate::tray_menu::{MenuRow, TrayView};

    /// **Between the diagnostics card and the launcher, every verb the model offers is drawn — each
    /// exactly once.**
    ///
    /// This is the single-source rule, made checkable, in the shape the merge requires
    /// (dig_ecosystem#2358). Home draws its verbs in two places now, so there are two ways to get
    /// it wrong and each has its own assertion: a row in NEITHER is a verb the tab claims to offer
    /// and does not, and a row in BOTH is two controls a person has to tell apart before pressing
    /// either. Checking only that the diagnostics card is a subset of the model would pass on both.
    ///
    /// Asserted against the REAL `window_model::build` output rather than a hand-written fixture,
    /// so a change to the Home tab upstream is reflected here without this test being edited.
    #[test]
    fn every_verb_is_drawn_once_across_the_diagnostics_card_and_the_launcher() {
        let view = TrayView {
            running: true,
            ..TrayView::default()
        };
        let model = crate::window_model::build(&view);
        let tab = model
            .tab(crate::window_model::TabId::Home)
            .expect("the Home tab is always emitted");

        let diagnostics: Vec<TrayAction> = actions_of(tab).into_iter().map(|a| a.id).collect();
        let launched: Vec<TrayAction> = super::super::apps::launch_actions(tab)
            .into_iter()
            .map(|a| a.id)
            .collect();

        assert!(
            !diagnostics.is_empty() && !launched.is_empty(),
            "one of the two groups is empty, so this cannot see a row moving between them:              {diagnostics:?} / {launched:?}"
        );
        for action in &diagnostics {
            assert!(
                !launched.contains(action),
                "{action:?} is drawn by the diagnostics card AND by the launcher"
            );
        }

        let mut drawn: Vec<TrayAction> = diagnostics.into_iter().chain(launched).collect();
        let mut offered = tab.actions();
        drawn.sort_by_key(|a| format!("{a:?}"));
        offered.sort_by_key(|a| format!("{a:?}"));
        assert_eq!(
            drawn, offered,
            "the pane's buttons are not the model's actions"
        );
    }

    /// **A disabled verb stays disabled, and a disabled row does not become the primary button.**
    ///
    /// Two actors: the fixture keeps one enabled action beside the disabled one, so a weighting that
    /// simply never produced a primary would be indistinguishable from one that respects the order.
    #[test]
    fn enablement_passes_through_untouched_and_never_promotes_a_disabled_verb() {
        let tab = Tab {
            id: crate::window_model::TabId::Home,
            label: "Home".to_string(),
            note: crate::window_model::PaneNote::Ready,
            sections: vec![crate::window_model::Section {
                heading: None,
                rows: vec![
                    MenuRow::Action {
                        action: TrayAction::ShowStatus,
                        label: "Show my recovery phrase (unlock first)".to_string(),
                        enabled: false,
                    },
                    MenuRow::Action {
                        action: TrayAction::OpenLogs,
                        label: "Open the log folder".to_string(),
                        enabled: true,
                    },
                ],
            }],
        };

        let actions = actions_of(&tab);
        assert!(!actions[0].enabled, "the model said disabled");
        assert!(actions[1].enabled, "the model said enabled");
        assert_eq!(
            actions[0].weight,
            Weight::Ghost,
            "a disabled leading verb was drawn as the pane's primary control"
        );
        assert_eq!(
            actions[1].weight,
            Weight::Ghost,
            "the second verb was promoted to primary because the first was disabled"
        );
    }

    /// **Status summarises the cache; it does not redraw the Cache tab's meter.**
    ///
    /// dig_ecosystem#2357's first duplication: the same meter was drawn byte-identically on two
    /// tabs, so either could be changed without the other and one screen would eventually contradict
    /// the other about one number.
    ///
    /// The absence half is asserted with a snapshot PRESENT, which is the only state in which a
    /// meter could be drawn — with none there is nothing to draw either way, and a test run against
    /// that would pass on any implementation. The unknown case is asserted separately, because the
    /// summary must not become a zero when nobody has reported: `0 B of 0 B` is the claim that this
    /// computer has a cache and it is empty.
    #[test]
    fn the_cache_is_summarised_here_and_metered_only_on_its_own_tab() {
        let snapshot = crate::cache::CacheSnapshot {
            cap_bytes: 10 * crate::cache::GIB,
            used_bytes: 407 * crate::cache::MIB,
        };
        let reading = cache_reading(Some(snapshot));
        assert!(
            reading.is_known(),
            "a reported cache came back as an absence: {reading:?}"
        );
        let shown = reading.shown().to_string();
        for figure in [
            crate::cache::format_cap(snapshot.used_bytes),
            crate::cache::format_cap(snapshot.cap_bytes),
        ] {
            assert!(
                shown.contains(&figure),
                "the summary does not carry {figure}, so it is not reporting the same disk the \
                 Cache tab meters: {shown}"
            );
        }

        let unread = cache_reading(None);
        assert!(
            !unread.is_known(),
            "an unreported cache was drawn as a figure, which claims a cache that is empty"
        );
        assert!(
            !unread.shown().chars().any(|c| c.is_ascii_digit()),
            "the unreported sentence carries a numeral where a person reads a size: {}",
            unread.shown()
        );
    }

    /// The live node's own status, so the figures under test are the ones a person actually sees.
    fn live_node_facts() -> crate::node_facts::NodeFacts {
        crate::node_facts::NodeFacts::of_status(&crate::test_support::node::fake_status_result())
    }

    /// The sharing readouts for a machine in `state`, keyed by their label.
    fn sharing(view: TrayView) -> Vec<Readout> {
        sharing_readouts(&PaneFacts::of_tray(&view))
    }

    /// **A node that has not been read leaves every sharing figure an explicit absence** — never a
    /// zero (dig_ecosystem#2397).
    ///
    /// The nearest wrong implementation reads `node_facts.unwrap_or_default()`, which draws
    /// "0 stores · 0 capsules · 0 pinned · up less than a minute" about a node nobody has spoken to.
    /// Every one of those figures is plausible and none of them is a reading.
    ///
    /// The absence's REASON is asserted too, and against the machine rather than against a constant:
    /// an agent that has not started and one that cannot find a node have different remedies, and the
    /// sentence that served both said neither.
    #[test]
    fn an_unread_node_leaves_every_sharing_figure_absent_with_its_own_reason() {
        let stopped = sharing(TrayView::default());
        assert_eq!(stopped.len(), copy::home::SHARING_LABELS.len());
        for item in &stopped {
            assert!(
                !item.value.is_known(),
                "{} was drawn as a figure on a computer whose node has said nothing: {:?}",
                item.label,
                item.value
            );
            assert!(
                !item.value.shown().chars().any(|c| c.is_ascii_digit()),
                "{} carries a numeral where a person reads a count: {}",
                item.label,
                item.value.shown()
            );
        }

        // One actor varied — the agent is now running — and the sentence must change with it.
        let searching = sharing(TrayView {
            running: true,
            ..TrayView::default()
        });
        assert_ne!(
            stopped[0].value.shown(),
            searching[0].value.shown(),
            "a stopped agent and one that cannot find a node are given the same sentence, so one \
             of the two readers is sent after the wrong remedy"
        );
    }

    /// **Every sharing figure is the node's own, and the four are not one number repeated.**
    ///
    /// The fixture's three counts all differ, so an implementation that read one field and reused it
    /// — or that swapped two of the three, which are all `u64` — cannot pass.
    #[test]
    fn every_sharing_figure_is_the_one_the_node_reported() {
        let node = live_node_facts();
        let items = sharing(TrayView {
            running: true,
            node_connected: true,
            node_facts: Some(node.clone()),
            ..TrayView::default()
        });

        let shown: Vec<&str> = items.iter().map(|item| item.value.shown()).collect();
        assert_eq!(
            shown,
            vec![
                node.hosted_store_count.to_string().as_str(),
                node.cached_capsule_count.to_string().as_str(),
                node.pinned_store_count.to_string().as_str(),
                node.uptime_phrase().as_str(),
            ],
            "the sharing card is not reporting the node's own figures, in the labels' order"
        );
        assert_ne!(
            node.hosted_store_count, node.cached_capsule_count,
            "the fixture's counts are indistinguishable, so this cannot see a swap"
        );
        for item in &items {
            assert!(item.value.is_known(), "{} came back absent", item.label);
        }
    }

    /// **The store count agrees with the sentence drawn above it on the same tab**
    /// (dig_ecosystem#2397).
    ///
    /// The defect this pane came closest to shipping. `node_card` renders
    /// [`PaneFacts::node_summary`], which `engine.rs` builds from `status.hosted_store_count` and
    /// which reads *"… · 3 store(s) hosted"*. Taking the card's figure from the hosted-store LIST
    /// instead — cached ∪ pinned, and legitimately longer — would put a 5 inches below that 3.
    ///
    /// The fixture is what makes this load-bearing: the store list carries MORE entries than the
    /// status count, exactly as the live node does, so a figure derived from the list disagrees with
    /// the summary and fails here. Against a list of equal length the two implementations are
    /// indistinguishable.
    #[test]
    fn the_store_count_agrees_with_the_summary_sentence_above_it() {
        use crate::hosted_stores::{HostedStore, HostedStoresReading};

        let node = live_node_facts();
        let listed: Vec<HostedStore> = (0..node.hosted_store_count + 2)
            .map(|n| HostedStore {
                store_id: format!("{n:064x}"),
                pinned: n >= node.hosted_store_count,
                capsule_count: 0,
                total_bytes: 0,
            })
            .collect();
        assert!(
            listed.len() as u64 > node.hosted_store_count,
            "the fixture's list is not longer than the status count, so this test cannot \
             distinguish the two sources"
        );

        let view = TrayView {
            running: true,
            node_connected: true,
            node: crate::engine::EngineState::Connected {
                endpoint: "http://127.0.0.1:9778".to_string(),
                status: Box::new(crate::test_support::node::fake_status_result()),
            }
            .summary(),
            node_facts: Some(node.clone()),
            hosted_stores: HostedStoresReading::Known(listed.clone()),
            ..TrayView::default()
        };
        let facts = PaneFacts::of_tray(&view);
        let shown = sharing_readouts(&facts)[0].value.shown().to_string();

        assert!(
            facts
                .node_summary
                .contains(&format!("{} store(s) hosted", node.hosted_store_count)),
            "the fixture's summary does not carry a store count, so this proves nothing: {}",
            facts.node_summary
        );
        assert_eq!(
            shown,
            node.hosted_store_count.to_string(),
            "the sharing card and the sentence above it report different store counts on one tab"
        );
        assert_ne!(
            shown,
            listed.len().to_string(),
            "the card took its figure from the hosted-store list, which counts cached ∪ pinned \
             stores and so contradicts the summary directly above it"
        );
    }

    /// **The store count's label says which set it counts.**
    ///
    /// The figure and the Content tab's list are both right and are different numbers, so the label
    /// is what keeps them from reading as a contradiction. A label of the bare word "hosted" is the
    /// one that names both sets at once, which is where this started.
    #[test]
    fn the_store_counts_label_names_the_set_it_counts() {
        let label = copy::home::SHARING_LABELS[0].to_lowercase();
        assert!(
            label.contains("cached"),
            "the store count's label does not say that it counts only stores with content cached, \
             so it reads as a count of the Content tab's rows: {label}"
        );
        let mut unique = copy::home::SHARING_LABELS.to_vec();
        unique.sort_unstable();
        unique.dedup();
        assert_eq!(
            unique.len(),
            copy::home::SHARING_LABELS.len(),
            "two sharing figures share a label"
        );
    }

    /// **A single store is reported in the singular.**
    ///
    /// Both sides, because a helper that always pluralised and one that never did each satisfy a
    /// one-case test — and "1 stores" beside three other figures is the kind of thing a reader
    /// notices and a suite does not.
    #[test]
    fn a_count_of_one_is_not_reported_in_the_plural() {
        assert_eq!(
            count(1, "store"),
            Value::Measure {
                amount: "1".to_string(),
                unit: "store".to_string()
            }
        );
        assert_eq!(
            count(0, "store"),
            Value::Measure {
                amount: "0".to_string(),
                unit: "stores".to_string()
            }
        );
        assert_eq!(
            count(5, "capsule"),
            Value::Measure {
                amount: "5".to_string(),
                unit: "capsules".to_string()
            }
        );
    }

    /// **A separator never becomes a button.**
    #[test]
    fn a_separator_is_not_rendered_as_a_verb() {
        let tab = Tab {
            id: crate::window_model::TabId::Home,
            label: "Home".to_string(),
            note: crate::window_model::PaneNote::Ready,
            sections: vec![crate::window_model::Section {
                heading: None,
                rows: vec![
                    MenuRow::Separator,
                    MenuRow::Action {
                        action: TrayAction::OpenLogs,
                        label: "Open the log folder".to_string(),
                        enabled: true,
                    },
                    MenuRow::Separator,
                ],
            }],
        };
        assert_eq!(actions_of(&tab).len(), 1);
    }
}
