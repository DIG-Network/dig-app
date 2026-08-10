//! The status strip the whole window carries, under the chrome and above every tab.
//!
//! # Why two facts follow the reader everywhere (dig_ecosystem#2358)
//!
//! Whether the agent is running and whether a node is reachable are the two facts that explain the
//! rest of the window. They used to live on one tab, which meant a person standing on Wallet had to
//! go and look somewhere else to learn the node was down — and a down node is frequently *why* the
//! balance in front of them reads "Not known". A fact that explains every other surface belongs on
//! every other surface.
//!
//! # It says only what it can say in two words
//!
//! One line, two badges, no prose. The strip is a GLANCE: it answers "is anything obviously wrong"
//! and nothing else. The reading behind each badge — the node's own sentence, the version, the
//! remedy — stays on the Home tab, because a strip that tried to carry a remedy would either
//! truncate it at 480 px or push the content pane down on every tab to make room for a sentence most
//! readers do not need.
//!
//! # Nothing here is a second derivation
//!
//! Both badges come from the same [`PaneFacts`] the panes read, through the same functions:
//! [`crate::confirm::gui::window::pane::copy::agent_state`] and [`PaneFacts::node_state`]. So the
//! strip and the Home tab cannot come to describe one machine differently — which is the failure the
//! duplicated cache meter was (one figure, two layouts, in two files).

use egui::{Rect, Ui, Vec2};

use super::super::paint;
use super::super::render::{regular, rgba, semibold, size, space};
use super::super::theme::Tokens;
use super::pane::{copy, data, facts::PaneFacts};

/// How tall the strip is.
///
/// Sized from what it holds rather than chosen: a badge is [`data::badge`]'s own height, and the
/// padding above and below it is one step of the 4 px rhythm.
pub(super) const HEADER_HEIGHT: f32 = 36.0;

/// Draw the strip across the top of `at`, and report the height it used.
///
/// It senses nothing. Every badge here is a READING, and a reading that responds to a click is a
/// control a person will press expecting something to happen.
///
/// # What it draws when there is not room for everything
///
/// The readings are laid out in priority order and the strip STOPS at the first one that will not
/// fit (see [`readings`]). It does not shrink them, wrap them, or truncate a word: a badge cut in
/// half is a reading a person has to guess at, and a strip that wrapped would push the content pane
/// down on every tab at every width.
///
/// Dropping is safe here in a way it would not be elsewhere, because nothing in the strip is a
/// CONTROL — every item is a glance-level reading, and the same facts are reachable in full on the
/// Home tab. The order is therefore the design: whether DIG is running, and whether it has a node,
/// come first because they explain every other reading on the screen.
pub(super) fn draw(ui: &mut Ui, at: Rect, t: &Tokens, facts: &PaneFacts) -> f32 {
    let bar = Rect::from_min_size(at.left_top(), Vec2::new(at.width(), HEADER_HEIGHT));
    ui.painter().rect_filled(bar, 0, rgba(t.surface));
    paint::rule(ui, bar, bar.bottom(), t);

    let mut x = bar.left() + space::S4;
    for item in readings(facts) {
        let width = reading_width(ui, t, &item);
        // The chip is wider than its word by half a step on each side (`data::badge`), so the fit
        // test has to allow for ink the galley's own width does not account for.
        if x + width + CHIP_OVERHANG > bar.right() {
            break;
        }
        reading(
            ui,
            egui::Pos2::new(x, bar.center().y),
            t,
            &item.label,
            &item.word,
            item.tone,
        );
        x += width + space::S4;
    }

    HEADER_HEIGHT
}

/// A badge's chip extends half a step past its text on each side — see [`data::badge`].
///
/// Measuring the text alone under-reports the strip's true extent by exactly this, and would let a
/// reading whose CHIP is clipped pass as fitting.
const CHIP_OVERHANG: f32 = space::S3 / 2.0;

/// One `label · badge` pair the strip may draw.
struct Reading {
    label: String,
    word: String,
    tone: data::Tone,
}

impl Reading {
    fn new(label: &str, word: &str, tone: data::Tone) -> Self {
        Self {
            label: label.to_owned(),
            word: word.to_owned(),
            tone,
        }
    }
}

/// Every reading the strip has to say, in priority order — most explanatory first.
///
/// A reading whose value is not KNOWN is absent from this list rather than present with a
/// placeholder. That is the honesty rule the whole [`crate::network`] module exists for: a peer
/// count nobody could take is not zero, and a `—` beside four badges carrying real facts costs a
/// glance and teaches nothing.
fn readings(facts: &PaneFacts) -> Vec<Reading> {
    let (node_word, node_tone) = facts.node_state();
    let mut items = vec![
        Reading::new(
            copy::header::AGENT_LABEL,
            copy::agent_state(facts.agent_running),
            agent_tone(facts.agent_running),
        ),
        Reading::new(copy::header::NODE_LABEL, node_word, node_tone),
    ];
    if let Some((word, severity)) = facts.network.sync.badge() {
        items.push(Reading::new(copy::header::CHAIN_LABEL, word, tone(severity)));
    }
    // Both networks, each named. Never one "peers" figure: a person told `1` cannot tell whether
    // their content network or their chain connection is the healthy one, and on a default install
    // those two answers differ (dig_ecosystem#2569).
    for (label, count) in [
        (crate::network::DIG_PEERS_LABEL, &facts.network.dig_peers),
        (crate::network::CHIA_PEERS_LABEL, &facts.network.chia_peers),
    ] {
        if let Some((word, severity)) = count.badge() {
            items.push(Reading::new(label, &word, tone(severity)));
        }
    }
    items
}

/// Translate a reading's severity into the pane layer's own [`data::Tone`].
///
/// The two enums are declared separately because [`crate::network`] sits above the GUI and must not
/// depend on it. This is the one place they meet, and `every_severity_has_a_tone` pins them to the
/// same shape.
fn tone(severity: crate::network::ChainSyncTone) -> data::Tone {
    use crate::network::ChainSyncTone;
    match severity {
        ChainSyncTone::Good => data::Tone::Good,
        ChainSyncTone::Neutral => data::Tone::Neutral,
        ChainSyncTone::Warn => data::Tone::Warn,
    }
}

/// How much horizontal room one reading needs, measured from the text it will actually draw.
fn reading_width(ui: &Ui, t: &Tokens, item: &Reading) -> f32 {
    let text = |s: &str, font: egui::FontId| {
        ui.painter()
            .layout_no_wrap(s.to_owned(), font, rgba(t.muted))
            .size()
            .x
    };
    // The word is measured in the badge's OWN font (`data::badge` uses semibold), not the label's:
    // semibold is the wider of the two, and measuring a badge with the label's font under-reports it.
    text(&item.label, regular(size::XS)) + space::S2 + text(&item.word, semibold(size::XS)) + space::S3
}

/// How worried to be about the agent's own state.
///
/// A starting agent is a WAIT, not a fault — `window_model` says so in the Home tab's banner, and a
/// strip painting it amber over that banner would be two surfaces disagreeing about one fact. It is
/// still not `Good`, because "Starting" is not a working machine yet.
fn agent_tone(running: bool) -> data::Tone {
    match running {
        true => data::Tone::Good,
        false => data::Tone::Neutral,
    }
}

/// One `label · badge` pair, left-aligned from `at`. Returns the x the next pair may start at.
fn reading(
    ui: &mut Ui,
    at: egui::Pos2,
    t: &Tokens,
    label: &str,
    word: &str,
    tone: data::Tone,
) -> f32 {
    let galley = ui
        .painter()
        .layout_no_wrap(label.to_owned(), regular(size::XS), rgba(t.muted));
    ui.painter().galley(
        egui::Pos2::new(at.x, at.y - galley.size().y / 2.0),
        galley.clone(),
        egui::Color32::PLACEHOLDER,
    );

    let badge_left = at.x + galley.size().x + space::S2;
    // `badge` measures itself from its own word, so the strip never has to guess a width — which is
    // what keeps a longer word (`Looking for a node`) from being drawn over the next reading.
    let drawn = data::badge(
        ui,
        egui::Pos2::new(badge_left, at.y - space::S3),
        t,
        word,
        tone,
    );
    drawn.right()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tray_menu::TrayView;

    /// Every string the strip painted for `view`, at `width`.
    fn painted(view: &TrayView, width: f32) -> Vec<String> {
        laid_out(view, width)
            .into_iter()
            .map(|(said, _where)| said)
            .collect()
    }

    /// Every string the strip painted for `view`, WITH the rectangle it occupies.
    ///
    /// Position is the half a string alone cannot carry: a reading drawn 400 px off the right edge
    /// is painted exactly as faithfully as one that fits, so a test that only collects text cannot
    /// tell a correct layout from an overflowing one.
    fn laid_out(view: &TrayView, width: f32) -> Vec<(String, Rect)> {
        let ctx = egui::Context::default();
        super::super::install_fonts(&ctx);
        let facts = PaneFacts::of_tray(view);
        let t = crate::confirm::gui::theme::Theme::Light.tokens();
        let screen = Rect::from_min_size(egui::Pos2::ZERO, Vec2::new(width, 200.0));

        let mut output = egui::FullOutput::default();
        // Two frames: the first builds the font atlas, the second lays out against it.
        for _ in 0..2 {
            output = ctx.run(
                egui::RawInput {
                    screen_rect: Some(screen),
                    ..Default::default()
                },
                |ctx| {
                    egui::Area::new(egui::Id::new("header-test"))
                        .fixed_pos(screen.left_top())
                        .show(ctx, |ui| {
                            draw(ui, screen, &t, &facts);
                        });
                },
            );
        }

        fn walk(shape: &egui::Shape, out: &mut Vec<(String, Rect)>) {
            match shape {
                egui::Shape::Text(text) => out.push((
                    text.galley.text().to_owned(),
                    Rect::from_min_size(text.pos, text.galley.size()),
                )),
                egui::Shape::Vec(shapes) => shapes.iter().for_each(|s| walk(s, out)),
                _ => {}
            }
        }
        let mut said = Vec::new();
        for clipped in &output.shapes {
            walk(&clipped.shape, &mut said);
        }
        said
    }

    /// **The strip reports the node's state, and it CHANGES with the node** (dig_ecosystem#2358).
    ///
    /// The point of the strip is that a person on any tab learns the node is down without moving, so
    /// the load-bearing half is that the two cases read differently. A strip that painted
    /// `Connected` unconditionally would satisfy any single-case check — which is why both are
    /// driven, and why each is asserted to say the other's word NOWHERE rather than merely to
    /// contain its own.
    #[test]
    fn the_strip_reports_the_node_and_says_something_different_when_it_is_down() {
        let up = painted(
            &TrayView {
                running: true,
                node_connected: true,
                ..TrayView::default()
            },
            960.0,
        );
        let down = painted(
            &TrayView {
                running: true,
                node_connected: false,
                ..TrayView::default()
            },
            960.0,
        );

        use super::super::pane::facts::{NODE_CONNECTED, NODE_SEARCHING};
        assert!(
            up.iter().any(|said| said == NODE_CONNECTED),
            "a connected node is not reported in the strip: {up:?}"
        );
        assert!(
            !up.iter().any(|said| said == NODE_SEARCHING),
            "a connected node was ALSO described as searching: {up:?}"
        );
        assert!(
            down.iter().any(|said| said == NODE_SEARCHING),
            "the strip does not say the node is unreachable, which is the whole reason it exists: \
             {down:?}"
        );
        assert!(
            !down.iter().any(|said| said == NODE_CONNECTED),
            "an unreachable node was reported as connected: {down:?}"
        );
    }

    /// **The strip reports the agent, and it changes with the agent.**
    ///
    /// The control for the test above: a strip that reported only the node would leave the reader
    /// unable to tell "no node" from "DIG is not running yet", which are different problems with
    /// different remedies.
    #[test]
    fn the_strip_reports_the_agent_separately_from_the_node() {
        let running = painted(
            &TrayView {
                running: true,
                ..TrayView::default()
            },
            960.0,
        );
        let starting = painted(&TrayView::default(), 960.0);

        assert!(running.iter().any(|said| said == copy::agent_state(true)));
        assert!(!running.iter().any(|said| said == copy::agent_state(false)));
        assert!(starting.iter().any(|said| said == copy::agent_state(false)));
        assert!(!starting.iter().any(|said| said == copy::agent_state(true)));
    }

    /// **Both readings survive the narrowest window a person can drag to.**
    ///
    /// The strip is one line and the node's longest word is `Looking for a node`, so 480 px is where
    /// the second reading either fits or is drawn over the first. Asserted by driving the WORST
    /// case — a searching node, whose word is the long one — rather than the connected case, which
    /// fits with room to spare and would prove nothing about the layout under pressure.
    ///
    /// Asserted on GEOMETRY, not on the presence of the strings. An earlier version of this test
    /// checked only that all four strings were painted, which overflow, overlap and a correct
    /// layout all satisfy identically: pushing the node reading 400 px off the right edge of a
    /// 480 px window left it green. What "fits" means is that the last reading's ink ends inside
    /// the bar and the two readings do not occupy the same pixels, so that is what is checked.
    /// Where `word` was painted, failing loudly if the strip never painted it at all.
    fn placed(laid_out: &[(String, Rect)], word: &str) -> Rect {
        laid_out
            .iter()
            .find(|(said, _)| said == word)
            .unwrap_or_else(|| panic!("the strip never painted {word:?}: {laid_out:?}"))
            .1
    }

    /// A view of a node reporting `sync`, `dig` DIG peers and `chia` Chia peers.
    fn on_the_networks(
        sync: crate::network::ChainSync,
        dig: crate::network::PeerCount,
        chia: crate::network::PeerCount,
    ) -> TrayView {
        TrayView {
            running: true,
            node_connected: true,
            network: crate::network::NetworkStanding {
                sync,
                dig_peers: dig,
                chia_peers: chia,
            },
            ..TrayView::default()
        }
    }

    /// **Both networks are counted, both are named, and the two counts stay apart**
    /// (dig_ecosystem#2569).
    ///
    /// The fixture is this machine's real reading: ZERO DIG peers and ONE Chia peer. The counts
    /// differ deliberately — a strip that read one number and drew it twice passes on any fixture
    /// where they agree, and would tell a person their content network is healthy on the strength of
    /// a chain connection.
    ///
    /// Asserted on the LABELS as well as the digits, because two bare numbers on one line are worse
    /// than one: the reader cannot tell which network either belongs to.
    #[test]
    fn the_strip_counts_both_networks_and_says_which_is_which() {
        use crate::network::{ChainSync, NoProgress, PeerCount, CHIA_PEERS_LABEL, DIG_PEERS_LABEL};
        let laid = laid_out(
            &on_the_networks(
                ChainSync::NoProgress(NoProgress::NoHeight),
                PeerCount::Known(0),
                PeerCount::Known(1),
            ),
            960.0,
        );

        let dig = placed(&laid, DIG_PEERS_LABEL);
        let chia = placed(&laid, CHIA_PEERS_LABEL);
        assert!(
            !dig.intersects(chia),
            "the two peer labels occupy the same pixels: {dig:?} / {chia:?}"
        );

        // Each count must be the one drawn NEXT TO its own label, not merely present somewhere on
        // the strip: a strip that painted `0` and `1` in the wrong order says the opposite of the
        // truth while containing both digits.
        let after = |label: Rect, digit: &str| {
            laid.iter()
                .filter(|(said, _)| said == digit)
                .any(|(_, at)| at.left() >= label.right() && at.left() - label.right() < 40.0)
        };
        assert!(after(dig, "0"), "the DIG label is not followed by its 0: {laid:?}");
        assert!(after(chia, "1"), "the Chia label is not followed by its 1: {laid:?}");

        // And the chain badge beside them, saying the honest thing about a replica at no height.
        assert!(
            laid.iter()
                .any(|(said, _)| said == crate::network::SYNC_NO_HEIGHT),
            "the chain reading is missing: {laid:?}"
        );
        assert!(
            !laid
                .iter()
                .any(|(said, _)| said == crate::network::SYNC_SYNCING),
            "a replica at no height was drawn as making progress: {laid:?}"
        );
    }

    /// **A count nobody could take is drawn as NOTHING, never as a zero** (dig_ecosystem#2569).
    ///
    /// The control for the test above, and the honesty rule at the surface it is actually seen on.
    /// The fixture varies one thing — whether the node answered — and holds the rest, so a strip
    /// that substituted a zero for an unread count fails here while still passing every test that
    /// drives a node which answered.
    #[test]
    fn an_unread_count_is_not_drawn_as_a_zero() {
        use crate::network::{ChainSync, PeerCount, SyncUnknown, CHIA_PEERS_LABEL, DIG_PEERS_LABEL};
        let said = painted(
            &on_the_networks(
                ChainSync::Unknown(SyncUnknown::NoNode),
                PeerCount::Unknown(SyncUnknown::NoNode),
                PeerCount::Unknown(SyncUnknown::NoNode),
            ),
            960.0,
        );

        for label in [DIG_PEERS_LABEL, CHIA_PEERS_LABEL] {
            assert!(
                !said.iter().any(|word| word == label),
                "{label} was drawn for a node nobody could ask: {said:?}"
            );
        }
        assert!(
            !said.iter().any(|word| word == "0"),
            "an unread peer count was drawn as an observed zero: {said:?}"
        );
        // The control: the two readings that ARE known are still there, so this is not passing
        // merely because the strip drew nothing at all.
        assert!(said.iter().any(|word| word == copy::agent_state(true)));
    }

    #[test]
    fn both_readings_fit_at_the_narrowest_width() {
        let width = super::super::shell::SHELL_MIN;
        let laid = laid_out(
            &TrayView {
                running: true,
                node_connected: false,
                ..TrayView::default()
            },
            width,
        );

        let agent =
            placed(&laid, copy::header::AGENT_LABEL).union(placed(&laid, copy::agent_state(true)));
        let node = placed(&laid, copy::header::NODE_LABEL)
            .union(placed(&laid, super::super::pane::facts::NODE_SEARCHING));

        // A badge's chip is wider than the word inside it: `data::badge` sizes itself to the galley
        // plus `space::S3`, centred, so the ink the reader sees extends half a step past the text on
        // each side. Measuring the text alone would under-report the strip's true extent by exactly
        // that, and let a reading whose CHIP is clipped pass as fitting.
        let chip_overhang = space::S3 / 2.0;
        assert!(
            node.right() + chip_overhang <= width,
            "the node reading ends at {} px in a {width} px window, so it is drawn off the right \
             edge: {laid:?}",
            node.right() + chip_overhang
        );
        assert!(
            !agent.intersects(node),
            "the two readings overlap — agent occupies {agent:?}, node {node:?}"
        );
    }

    /// **Nothing the strip draws ever runs off the edge, at any width it can be dragged to.**
    ///
    /// Five readings do not fit in 480 px, so the strip drops from the right rather than
    /// overflowing. This drives the WORST case — every reading present, each carrying its longest
    /// word — across the whole width range, and asserts on GEOMETRY: an overflowing strip paints
    /// every string just as faithfully as a correct one, so a test that collected text alone could
    /// not tell them apart. That exact false green was found here once already.
    ///
    /// The narrow end also asserts the two most explanatory readings SURVIVE, which is what makes
    /// the drop a priority order rather than a truncation: a strip that dropped everything at 480 px
    /// would satisfy the overflow half on its own.
    #[test]
    fn the_strip_never_overflows_and_keeps_the_two_facts_that_explain_the_rest() {
        use crate::network::{ChainSync, NoProgress, PeerCount};
        let view = on_the_networks(
            // The longest word each reading can carry, so the measurement is of the worst case.
            ChainSync::NoProgress(NoProgress::NoPeers),
            PeerCount::Unobservable,
            PeerCount::Unobservable,
        );
        let mut dropped_any = false;
        for width in [super::super::shell::SHELL_MIN, 640.0, 960.0, 1440.0] {
            let laid = laid_out(&view, width);
            for (said, at) in &laid {
                assert!(
                    at.right() + space::S3 / 2.0 <= width,
                    "{said:?} ends at {} px in a {width} px window, so it is drawn off the right \
                     edge: {laid:?}",
                    at.right()
                );
            }
            assert!(
                laid.iter().any(|(said, _)| said == copy::header::AGENT_LABEL),
                "the agent reading was dropped at {width} px, and it is the one that explains the \
                 rest of the window: {laid:?}"
            );
            assert!(
                laid.iter().any(|(said, _)| said == copy::header::NODE_LABEL),
                "the node reading was dropped at {width} px: {laid:?}"
            );
            dropped_any |= !laid
                .iter()
                .any(|(said, _)| said == crate::network::CHIA_PEERS_LABEL);
        }
        assert!(
            dropped_any,
            "every reading fit at every width, so this test never exercised the drop it exists to \
             pin — the fixture is too narrow to be a worst case"
        );
    }

    /// **Every severity a reading can carry maps to a tone**, so a new one cannot silently inherit
    /// another's colour.
    #[test]
    fn every_severity_has_its_own_tone() {
        use crate::network::ChainSyncTone;
        assert_eq!(tone(ChainSyncTone::Good), data::Tone::Good);
        assert_eq!(tone(ChainSyncTone::Neutral), data::Tone::Neutral);
        assert_eq!(tone(ChainSyncTone::Warn), data::Tone::Warn);
        let tones = [
            tone(ChainSyncTone::Good),
            tone(ChainSyncTone::Neutral),
            tone(ChainSyncTone::Warn),
        ];
        let mut unique = tones.to_vec();
        unique.sort_unstable_by_key(|t| format!("{t:?}"));
        unique.dedup();
        assert_eq!(unique.len(), tones.len(), "two severities share a tone");
    }
}
