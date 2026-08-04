//! What a prompt window SHOWS, as data — the layout model, separated from the drawing.
//!
//! # Why this layer exists
//!
//! [`ConfirmContent`] says what a prompt means; `paint` says how pixels get onto a screen. Between
//! them sits one question that is security-critical and that neither of those layers is a good place
//! to answer: *which strings reach the user, and in what role*.
//!
//! Keeping it here, as plain data, buys two things. A test can assert what a window WOULD show
//! without opening one — which matters because a consent window cannot be constructed inside
//! `cargo test` on this stack. And the set of roles a string may take is closed
//! ([`Block`]), so a caller cannot invent a new one that renders differently from the rest.
//!
//! # The text rule
//!
//! Every string in a [`Screen`] is drawn with [`egui::Painter::text`], which rasterises glyphs. It is
//! not parsed, not interpreted, and not templated into anything that is. A value containing
//! `<script>` produces the glyphs `<`, `s`, `c`, … — see this module's tests, which run the real
//! egui layout engine headlessly and read the glyphs back out.

use egui::{Align, Color32, FontFamily, FontId, RichText, TextFormat};

use super::theme::{Rgba, Tokens};
use crate::confirm::{ConfirmContent, InputContent, InputStyle, Presentation};

/// The logical width of the frameless launcher bar — wider than the titled [`Chrome::Dialog`] so a
/// full `dig://` link reads as a single generous field, the way a Spotlight bar does. A dialog is
/// sized for a wrapped `xch1…` address and a paragraph of body; a bar is sized for one line the user
/// is typing (dig_ecosystem#1839, restored in dig_ecosystem#2054).
pub const BAR_WIDTH: f32 = 720.0;

/// The fixed height of the launcher bar. Unlike a dialog — which grows to its content so a 24-word
/// recovery phrase is never clipped — a bar holds exactly one hint line and one field, so it is a
/// constant short height rather than content-sized.
pub const BAR_HEIGHT: f32 = 176.0;

/// Where a bar sits vertically: `monitor_height / BAR_TOP_DIVISOR` from the top, i.e. high on the
/// screen rather than centred. A launcher the eye expects near the top, not floating in the middle
/// of whatever is behind it.
pub const BAR_TOP_DIVISOR: f32 = 5.0;

/// The vertical position a bar is placed at on a monitor `monitor_h` tall.
///
/// A free function, and the reason [`Chrome`] carries no window state: the placement is pure
/// arithmetic a headless test can check, so "the bar sits high" is pinned without opening a window.
pub fn bar_top(monitor_h: f32) -> f32 {
    monitor_h / BAR_TOP_DIVISOR
}

/// How a prompt window is FRAMED — the presentation half of [`InputStyle`], resolved once at the
/// [`Screen`] seam so the paint layer and the window layer read one field instead of re-deriving it.
///
/// # Why this is a Screen-level enum and not a per-caller flag
///
/// [`Screen::confirm`] ALWAYS produces [`Chrome::Dialog`]; only [`Screen::input`] can produce
/// [`Chrome::Bar`], and only when its [`InputContent::style`] asks for it. So "a consent window is
/// never a bar" is a structural fact — a sign, connect, pair, notice, destroy or claim screen cannot
/// be constructed as a bar — rather than a rule the paint layer has to remember. The launcher's
/// dismiss-on-blur, which makes a window vanish when focus leaves it, is therefore unreachable for
/// any window asking the user to authorise something (dig_ecosystem#2054).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Chrome {
    /// A titled, framed card centred on the screen, sized to its content. Every confirm, and every
    /// account-journey input.
    Dialog,
    /// The frameless Spotlight-style launcher bar: wide, fixed-height, floating high, with an
    /// oversized field and a single hint line, dismissed by Esc OR by losing focus.
    Bar,
}

impl Chrome {
    /// Whether a window with this chrome dismisses itself the moment it loses focus.
    ///
    /// TRUE only for [`Chrome::Bar`]: a launcher the user has clicked away from has been abandoned.
    /// FALSE for [`Chrome::Dialog`] — a consent window must NEVER vanish because the user glanced at
    /// another window; it stays until it is answered.
    pub fn dismiss_on_blur(&self) -> bool {
        matches!(self, Chrome::Bar)
    }

    /// Whether this is the launcher bar, for the layout branches that differ between the two.
    pub fn is_bar(&self) -> bool {
        matches!(self, Chrome::Bar)
    }
}

/// The font family the brand's 600-weight face is registered under.
///
/// A named family rather than `FontFamily::Proportional` with a synthetic bold: hub's type is Space
/// Grotesk, whose 600 is a distinct cut, and faking it by smearing the 400 is exactly the kind of
/// detail that makes a port look like an imitation.
pub const SEMIBOLD: &str = "dig-semibold";

/// The font family identifiers are set in — Space Mono, the sanctioned second face.
///
/// `professional-ui` pairs Space Grotesk with Space Mono and reserves the mono cut for
/// identifiers, hex and code ("no third font, ever"). A monospace face is also materially more
/// legible for reading an `xch1…` address character by character and telling `1`/`l` and `0`/`O`
/// apart — which is exactly what a person does before authorising a spend.
pub const MONO: &str = "dig-mono";

/// Type sizes, mirroring hub's `--text-*` scale.
pub mod size {
    /// hub's `--text-xs` — the window-chrome title.
    pub const XS: f32 = 12.0;
    /// hub's `--text-sm` — the field label and the theme toggle.
    pub const SM: f32 = 13.0;
    /// hub's `--text-base` — body copy and the decoded transaction.
    pub const BASE: f32 = 15.0;
    /// Button labels. Between `--text-sm` and `--text-base`, as hub's `.btn` is.
    pub const BUTTON: f32 = 14.5;
    /// hub's `--text-xl` — the origin-bound heading.
    pub const HEADING: f32 = 22.0;
}

/// hub's `--space-*` scale, in logical pixels.
pub mod space {
    /// `--space-2`.
    pub const S2: f32 = 8.0;
    /// `--space-3`.
    pub const S3: f32 = 12.0;
    /// `--space-4`.
    pub const S4: f32 = 16.0;
    /// `--space-5`.
    pub const S5: f32 = 20.0;
    /// `--space-6`.
    pub const S6: f32 = 24.0;
}

/// hub's `--radius-*` scale.
pub mod radius {
    /// `--radius-sm` — chips and inputs.
    pub const SM: u8 = 8;
    /// `--radius` — cards.
    pub const BASE: u8 = 10;
    /// `--radius-lg` — the window card.
    pub const LG: u8 = 16;
    /// A pill. Not one of hub's tokens: hub writes `999px`, which is "half the height", and egui
    /// takes an absolute corner radius — so it is derived from the control height at the call site
    /// and this is only the cap.
    pub const PILL: u8 = 24;
}

/// One thing a prompt window shows, in the role it shows it as.
///
/// A closed set on purpose: adding a way to display a string means adding a variant here, in front of
/// the tests below, rather than reaching for a different draw call somewhere in the paint layer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Block {
    /// The origin-bound question, largest type. One per screen.
    Heading(String),
    /// Explanatory copy in the secondary colour.
    Body(String),
    /// The decoded transaction / detail, inside a recessed panel.
    ///
    /// Distinct from [`Block::Body`] because it is the part a user is meant to READ CAREFULLY before
    /// authorising, and because it is the field most likely to carry attacker-supplied text.
    Detail(String),
    /// A warning panel — the amber treatment. Used where the copy states an irreversible loss.
    Warning(String),
    /// A literal identifier — a DIG id, an `xch1…` address, a pairing ext-id, a TOTP secret — set in
    /// Space Mono for char-by-char legibility. Never prose: only a bare value the user reads or
    /// transcribes, split out of its surrounding copy so the mono treatment lands on the value alone.
    Identifier(String),
    /// A QR code, drawn beneath the body. Always accompanied by the same secret as text (see
    /// [`ClaimPrompt::scannable`](crate::confirm::ClaimPrompt::scannable)).
    ///
    /// Carries the art rather than a flag so the paint layer has everything it needs from the block
    /// alone — a variant that only SAYS "a QR goes here" is how the branded window ended up reserving
    /// space for a square it never drew.
    Qr(crate::confirm::QrArt),
}

/// A button's visual weight, which follows what the button DOES.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Weight {
    /// The accented affirmative — hub's `--dig-purple` fill.
    Primary,
    /// The destructive affirmative — hub's `--danger` fill. A destroy must not look like a save.
    Danger,
    /// The refusal — a bordered ghost.
    Ghost,
}

/// A labelled control in the action row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Button {
    /// The label, shown VERBATIM. A first-person claim label reaches the user unchanged; it is never
    /// slotted into a sentence (dig_ecosystem#1752).
    pub label: String,
    /// How it is drawn.
    pub weight: Weight,
    /// The answer clicking it produces.
    pub answer: Answer,
    /// Whether this control is focused when the window opens.
    ///
    /// Carries [`Presentation::Decide::refusal_is_default`]: a destroy or a security-weakening window
    /// pre-focuses its REFUSAL, so a bare Enter keeps the account (dig_ecosystem#1799).
    pub focused: bool,
}

/// What a control answers with.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Answer {
    /// The user took the affirmative action.
    Approve,
    /// The user refused, or dismissed the window.
    Deny,
}

/// Everything one prompt window shows and offers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Screen {
    /// The window-chrome title.
    pub title: String,
    /// The body, in order.
    pub blocks: Vec<Block>,
    /// The action row, in visual order (refusal first, affirmative last — the platform-conventional
    /// order on Windows and Linux, and the one the old backends already used).
    pub buttons: Vec<Button>,
    /// A text field, when this is an input prompt rather than a confirm.
    pub field: Option<Field>,
    /// How the window is framed. A confirm is always [`Chrome::Dialog`]; an input follows its
    /// [`InputContent::style`].
    pub chrome: Chrome,
}

/// A text-entry control.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Field {
    /// The label beside it.
    pub label: String,
    /// Whether typed characters start hidden. Secret material is masked by default (`SPEC.md` §3.1d).
    pub masked: bool,
    /// Whether a reveal-while-typing control is offered — §3.1d's own escape from the masking rule,
    /// for the phrase that cannot be checked if typed entirely blind.
    pub revealable: bool,
}

impl Screen {
    /// The screen for a confirm prompt.
    ///
    /// Reads its structure ENTIRELY off [`ConfirmContent`] — which is composed and unit-tested in the
    /// parent module — so this layer cannot reword a heading, drop an origin, or turn a notice into a
    /// question. It decides presentation, never content.
    pub fn confirm(content: &ConfirmContent, refusal_label: &str) -> Self {
        let destructive = content.action.eq_ignore_ascii_case("destroy");
        let blocks = {
            let mut blocks = vec![Block::Heading(content.heading.clone())];
            // A destroy states an irreversible loss, so its body takes the warning treatment rather
            // than reading like ordinary explanatory copy. An EMPTY body is dropped entirely — a
            // notice whose whole substance is an identifier (a copied DIG id) carries no prose, and an
            // empty paragraph would only add a stray gap above the value.
            if !content.body.is_empty() {
                blocks.push(match destructive {
                    true => Block::Warning(content.body.clone()),
                    false => Block::Body(content.body.clone()),
                });
            }
            // The one bare identifier this prompt shows, set apart from its prose so it reaches the
            // mono treatment alone. It sits directly under its explanatory copy, and — for two-factor
            // enrolment — just above the QR that encodes the same secret.
            if let Some(id) = content.identifier.clone() {
                blocks.push(Block::Identifier(id));
            }
            if let Some(detail) = content.detail.clone() {
                blocks.push(Block::Detail(detail));
            }
            if let Some(art) = content.qr.clone() {
                blocks.push(Block::Qr(art));
            }
            blocks
        };

        let buttons = match content.presentation {
            // A notice has ONE dismiss. Nothing downstream branches on how it was dismissed, so a
            // second button would invite a decision no code reads (dig_ecosystem#1773).
            Presentation::Acknowledge => vec![Button {
                label: content.action.to_owned(),
                weight: Weight::Primary,
                answer: Answer::Approve,
                focused: true,
            }],
            Presentation::Decide { refusal_is_default } => vec![
                Button {
                    // The CONTENT names the refusing control when the backend's own word for it
                    // would be a lie — on the first-run route fork, declining generates an account,
                    // and "Cancel" must never be the label on the control that does that
                    // (dig_ecosystem#2074).
                    label: content.decline.unwrap_or(refusal_label).to_owned(),
                    weight: Weight::Ghost,
                    answer: Answer::Deny,
                    focused: refusal_is_default,
                },
                Button {
                    label: content.action.to_owned(),
                    weight: match destructive {
                        true => Weight::Danger,
                        false => Weight::Primary,
                    },
                    answer: Answer::Approve,
                    focused: !refusal_is_default,
                },
            ],
        };

        Self {
            title: content.title.clone(),
            blocks,
            buttons,
            field: None,
            // A confirm is ALWAYS a dialog — this is what makes "consent is never a bar" structural
            // rather than a convention (see [`Chrome`]).
            chrome: Chrome::Dialog,
        }
    }

    /// The screen for an input prompt.
    ///
    /// Maps [`InputContent::style`] to the window's [`Chrome`]. A [`InputStyle::Bar`] launcher drops
    /// the heading and keeps at most a single hint line — a bar is one field, not a page of copy —
    /// while a [`InputStyle::Dialog`] keeps the titled heading-plus-body layout every account journey
    /// uses (dig_ecosystem#2054).
    pub fn input(content: &InputContent) -> Self {
        let (chrome, blocks) = match content.style {
            // The launcher: no heading, and the body only if it carries a hint worth one line.
            InputStyle::Bar => {
                let mut blocks = Vec::new();
                if !content.body.is_empty() {
                    blocks.push(Block::Body(content.body.clone()));
                }
                (Chrome::Bar, blocks)
            }
            InputStyle::Dialog => (
                Chrome::Dialog,
                vec![
                    Block::Heading(content.heading.clone()),
                    Block::Body(content.body.clone()),
                ],
            ),
        };
        Self {
            title: content.title.clone(),
            blocks,
            buttons: vec![
                Button {
                    label: "Cancel".to_owned(),
                    weight: Weight::Ghost,
                    answer: Answer::Deny,
                    focused: false,
                },
                Button {
                    // Pre-focused, so Enter SUBMITS what was typed.
                    //
                    // With nothing pre-focused the window fell back to its first control, and the
                    // first control is the refusal: typing a passphrase and pressing Enter — the
                    // single most likely thing a person does in a text field — cancelled the unlock
                    // (#2038, found in the screenshot gallery). Unlike a destroy, submitting a field
                    // is not destructive; the safe default here IS the affirmative.
                    label: content.submit.to_owned(),
                    weight: Weight::Primary,
                    answer: Answer::Approve,
                    focused: true,
                },
            ],
            field: Some(Field {
                label: content.field_label.clone(),
                masked: content.masked,
                revealable: content.revealable,
            }),
            chrome,
        }
    }

    /// Every string this screen puts in front of the user, in draw order.
    ///
    /// Exists for the tests: it is the list a hostile value must appear in VERBATIM, and the list an
    /// assistive technology walks. Not used by the paint layer, which walks the typed structure.
    #[cfg(test)]
    pub fn visible_text(&self) -> Vec<&str> {
        let blocks = self.blocks.iter().filter_map(|b| match b {
            Block::Heading(t)
            | Block::Body(t)
            | Block::Detail(t)
            | Block::Warning(t)
            | Block::Identifier(t) => Some(t.as_str()),
            Block::Qr(_) => None,
        });
        std::iter::once(self.title.as_str())
            .chain(blocks)
            .chain(self.field.iter().map(|f| f.label.as_str()))
            .chain(self.buttons.iter().map(|b| b.label.as_str()))
            .collect()
    }
}

/// The colour a [`Block`] draws its text in.
pub fn block_color(block: &Block, t: &Tokens) -> Rgba {
    match block {
        // Full-contrast `--text`, not `--muted`: an identifier is the value the user must read
        // exactly, so it takes the strongest text tier rather than the recessed one prose uses.
        Block::Heading(_) | Block::Identifier(_) => t.text,
        Block::Body(_) | Block::Detail(_) => t.muted,
        Block::Warning(_) => t.amber,
        Block::Qr(_) => t.text,
    }
}

/// Convert a token to egui's colour type.
pub fn rgba(c: Rgba) -> Color32 {
    Color32::from_rgba_unmultiplied(c.r, c.g, c.b, c.a)
}

/// The brand's 600-weight face at `size`.
pub fn semibold(size: f32) -> FontId {
    FontId::new(size, FontFamily::Name(SEMIBOLD.into()))
}

/// The brand's 400-weight face at `size`.
pub fn regular(size: f32) -> FontId {
    FontId::proportional(size)
}

/// Space Mono at `size` — the face every identifier, hex string and code is set in.
pub fn mono(size: f32) -> FontId {
    FontId::new(size, FontFamily::Name(MONO.into()))
}

/// A wrapping paragraph of PLAIN text, laid out at `width`.
///
/// The one place body-shaped text becomes a drawable. It takes a `&str` and produces a layout job
/// whose single section is that string — there is no parse step, no span splitting, and no way for a
/// substring to acquire different formatting from its neighbours.
pub fn paragraph(
    text: &str,
    font: FontId,
    color: Color32,
    width: f32,
    line: f32,
) -> egui::text::LayoutJob {
    let mut job = egui::text::LayoutJob::default();
    job.wrap.max_width = width;
    job.halign = Align::LEFT;
    job.append(
        text,
        0.0,
        TextFormat {
            font_id: font,
            color,
            line_height: Some(line),
            ..Default::default()
        },
    );
    job
}

/// A short, non-wrapping run of text.
pub fn label(text: &str, font: FontId, color: Color32) -> RichText {
    RichText::new(text).font(font).color(color)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::confirm::{ConnectPrompt, DestroyPrompt, NoticePrompt, SignPrompt};

    /// **The CONTENT names the refusing control when the backend's word for it would be a lie.**
    ///
    /// The backend passes its own generic label ("Cancel" on every platform today) and that is right
    /// almost everywhere. It is wrong on the first-run route fork, where declining does not back out
    /// of anything — it GENERATES AND SEALS A NEW MASTER SEED. A control that does that must not be
    /// called "Cancel" (dig_ecosystem#2074).
    ///
    /// Both directions are asserted: an override must WIN, and a prompt that supplies none must
    /// still get the backend's word — otherwise "override" quietly becomes "every window relabels
    /// itself".
    #[test]
    fn a_claim_can_name_its_own_refusing_control() {
        fn refusing_label(decline: Option<&'static str>) -> String {
            let content = ConfirmContent::claim(&crate::confirm::ClaimPrompt {
                title: "t",
                heading: "h",
                body: "b",
                affirm: "Import my recovery phrase",
                decline,
                refusal_is_default: false,
                scannable: None,
                identifier: None,
            });
            Screen::confirm(&content, "Cancel")
                .buttons
                .into_iter()
                .find(|button| button.answer == Answer::Deny)
                .expect("a claim offers a way out")
                .label
        }

        assert_eq!(
            refusing_label(Some("Create a new account")),
            "Create a new account",
            "the backend's generic label overrode the content's — so the control that creates a              brand-new account is drawn as \"Cancel\""
        );
        assert_eq!(
            refusing_label(None),
            "Cancel",
            "a claim that named no label should still get the backend's own word for refusing"
        );
    }

    /// A decoded transaction carrying markup AND a script tag — what a hostile dapp supplies.
    const HOSTILE: &str = "Send 0.001 XCH to xch1safe\u{2026}addr</div><div class=\"ok\">\
         <b>\u{2713} Verified by DIG</b><script>alert(1)</script>\
         <span style=\"color:#2ec27e\">safe to approve</span>&amp;<b>done</b>";

    fn sign_content(decoded: &'static str) -> ConfirmContent {
        ConfirmContent::sign(&SignPrompt {
            origin: "https://dapp.example",
            payload_type: "spend",
            decoded_tx: Some(decoded),
        })
        .expect("a decoded transaction yields content")
    }

    /// Run the REAL egui text pipeline, with no window, and report what it actually laid out.
    ///
    /// This is the point of these tests: they do not inspect our own structs and conclude we did the
    /// right thing — they drive the same `Fonts::layout_job` the window draws through and read the
    /// resulting galley back. A renderer that interpreted markup would swallow tags and show up here
    /// as missing text AND a lower glyph count.
    ///
    /// Returns the laid-out text and the number of GLYPHS the shaper emitted, because the text alone
    /// could be echoed by a galley that rendered nothing.
    fn laid_out(text: &str) -> (String, usize) {
        let ctx = egui::Context::default();
        // egui builds its font atlas on the first frame, so a bare `Context` has no fonts and
        // `Context::fonts` panics. One empty frame is the documented way to bring them up headlessly.
        let _ = ctx.run(egui::RawInput::default(), |_| {});
        let job = paragraph(
            text,
            regular(size::BASE),
            Color32::BLACK,
            10_000.0,
            size::BASE * 1.5,
        );
        let galley = ctx.fonts(|f| f.layout_job(job));
        let glyphs = galley.rows.iter().map(|r| r.glyphs.len()).sum();
        (galley.text().to_owned(), glyphs)
    }

    /// **The plain-text consent guarantee.** A hostile decoded transaction must reach the screen as
    /// LITERAL CHARACTERS — every angle bracket, every ampersand, every tag name — after passing
    /// through the real layout engine.
    ///
    /// This is the test the ticket requires to fail if the renderer ever starts interpreting markup.
    /// It asserts on the glyphs the text pipeline actually produced, not on a string we kept a copy
    /// of, so swapping in a markup-aware renderer breaks it.
    #[test]
    fn a_hostile_value_is_laid_out_as_literal_characters() {
        let (drawn, glyphs) = laid_out(HOSTILE);
        assert_eq!(
            drawn, HOSTILE,
            "the layout engine altered the text; markup must be drawn, not interpreted"
        );
        // Spelled out, so a failure names the specific thing that went missing.
        for fragment in [
            "<b>",
            "</b>",
            "<script>alert(1)</script>",
            "<div class=\"ok\">",
            "&amp;",
        ] {
            assert!(
                drawn.contains(fragment),
                "{fragment:?} did not survive layout; got {drawn:?}"
            );
        }
        // The text surviving is not enough on its own — a galley can carry text it never shaped.
        // Every non-newline character must have produced a glyph, so the angle brackets are not
        // merely present in the string but actually DRAWN.
        let expected = HOSTILE.chars().filter(|c| *c != '\n').count();
        assert_eq!(
            glyphs, expected,
            "the shaper emitted {glyphs} glyphs for {expected} characters — markup was consumed"
        );
    }

    /// …and the control that makes the test above meaningful: an HTML-ESCAPED value would ALSO
    /// survive a markup-interpreting renderer, so the assertion is specifically that NO escaping
    /// happened either. `&amp;` must stay `&amp;`, not become `&`.
    ///
    /// Without this, a future "let's just escape it to be safe" change would pass the test above
    /// while quietly showing the user a different string than the one that was signed.
    #[test]
    fn a_hostile_value_is_not_escaped_on_its_way_to_the_screen_either() {
        let (drawn, _) = laid_out("a &amp; b &lt;c&gt;");
        assert_eq!(
            drawn, "a &amp; b &lt;c&gt;",
            "the text must be neither interpreted NOR escaped — it is shown exactly as decoded"
        );
    }

    /// The same guarantee at the level the window is composed at: every string a screen puts on
    /// display is byte-identical to what the prompt supplied.
    #[test]
    fn every_string_a_screen_shows_is_verbatim() {
        let content = sign_content(HOSTILE);
        let screen = Screen::confirm(&content, "Cancel");
        let shown = screen.visible_text().join("\n");
        assert!(
            shown.contains(HOSTILE),
            "the hostile decoded transaction must reach the screen unchanged"
        );
    }

    /// The heading binds the origin, and it is the origin the prompt supplied — a window that
    /// dropped it would ask the user to authorise an unattributed request.
    #[test]
    fn the_heading_carries_the_vouched_origin() {
        let content = ConfirmContent::connect(&ConnectPrompt {
            origin: "https://dapp.example",
            dapp_name: Some("Cool Dapp"),
        });
        let screen = Screen::confirm(&content, "Cancel");
        let Some(Block::Heading(heading)) = screen.blocks.first() else {
            panic!("a confirm screen leads with its heading");
        };
        assert!(heading.contains("Cool Dapp"), "{heading}");
        assert!(heading.contains("dapp.example"), "{heading}");
    }

    // ---- Presentation: the two kinds of window stay distinguishable. ----

    /// A notice offers exactly one control, so the user is not asked to decide something no code
    /// reads (dig_ecosystem#1773).
    #[test]
    fn a_notice_offers_exactly_one_control() {
        let content = ConfirmContent::notice(&NoticePrompt {
            title: "DIG \u{2014} DIG ID copied",
            heading: "Your DIG ID is on the clipboard.",
            body: "abc123",
            acknowledge: "OK",
            identifier: None,
        });
        let screen = Screen::confirm(&content, "Cancel");
        assert_eq!(screen.buttons.len(), 1);
        assert_eq!(screen.buttons[0].answer, Answer::Approve);
        assert_eq!(screen.buttons[0].label, "OK");
    }

    /// …and the control: an authorisation offers two, one of which refuses.
    #[test]
    fn an_authorization_offers_a_real_refusal() {
        let screen = Screen::confirm(&sign_content("Send 1 XCH"), "Cancel");
        assert_eq!(screen.buttons.len(), 2);
        assert_eq!(screen.buttons[0].answer, Answer::Deny);
        assert_eq!(screen.buttons[1].answer, Answer::Approve);
    }

    /// **Regression (dig_ecosystem#1799).** A destroy pre-focuses its REFUSAL, so a bare Enter keeps
    /// the account. The affirmative being focused here would destroy a master seed on a keypress.
    #[test]
    fn a_destroy_pre_focuses_the_refusal_so_enter_keeps_the_account() {
        let content = ConfirmContent::destroy(&DestroyPrompt {
            subject: "the DIG Account on this computer",
            replacement: "",
            recoverable: false,
        });
        let screen = Screen::confirm(&content, "Cancel");
        let focused = screen
            .buttons
            .iter()
            .find(|b| b.focused)
            .expect("some control takes focus, or the window opens unfocusable");
        assert_eq!(
            focused.answer,
            Answer::Deny,
            "the safe answer must be pre-selected on a destroy"
        );
    }

    /// …and the control: an ordinary authorisation pre-focuses its AFFIRMATIVE, because the user
    /// just asked for it and refusing costs only a retry. Without this, a window that focused the
    /// refusal everywhere would pass the destroy test above.
    #[test]
    fn an_ordinary_authorization_pre_focuses_its_affirmative() {
        let screen = Screen::confirm(&sign_content("Send 1 XCH"), "Cancel");
        let focused = screen.buttons.iter().find(|b| b.focused).expect("focused");
        assert_eq!(focused.answer, Answer::Approve);
    }

    /// A destroy's affirmative is drawn DESTRUCTIVELY. The pre-focused refusal protects a keypress;
    /// the colour protects a glance — neither alone is the whole guard.
    #[test]
    fn a_destroy_draws_its_affirmative_as_destructive() {
        let content = ConfirmContent::destroy(&DestroyPrompt {
            subject: "the DIG Account on this computer",
            replacement: "",
            recoverable: true,
        });
        let screen = Screen::confirm(&content, "Cancel");
        let affirm = screen
            .buttons
            .iter()
            .find(|b| b.answer == Answer::Approve)
            .unwrap();
        assert_eq!(affirm.weight, Weight::Danger);
        assert_eq!(affirm.label, "Destroy");
    }

    /// …and the control: a sign's affirmative is the ordinary accent, so the destructive treatment
    /// still means something.
    #[test]
    fn a_sign_draws_its_affirmative_as_the_ordinary_accent() {
        let screen = Screen::confirm(&sign_content("Send 1 XCH"), "Cancel");
        let affirm = screen
            .buttons
            .iter()
            .find(|b| b.answer == Answer::Approve)
            .unwrap();
        assert_eq!(affirm.weight, Weight::Primary);
    }

    /// A destroy's body takes the WARNING treatment: it states an irreversible loss and must not
    /// read like ordinary explanatory copy.
    #[test]
    fn a_destroy_body_is_a_warning_not_ordinary_copy() {
        let content = ConfirmContent::destroy(&DestroyPrompt {
            subject: "the DIG Account on this computer",
            replacement: "",
            recoverable: false,
        });
        let screen = Screen::confirm(&content, "Cancel");
        assert!(
            screen.blocks.iter().any(|b| matches!(b, Block::Warning(_))),
            "a destroy states its loss as a warning: {:?}",
            screen.blocks
        );
    }

    /// A claim's first-person label reaches the button VERBATIM (dig_ecosystem#1752) — it is never
    /// slotted into an authorisation sentence.
    #[test]
    fn a_claim_label_reaches_the_button_unchanged() {
        let content = ConfirmContent::claim(&crate::confirm::ClaimPrompt {
            title: "DIG \u{2014} Your recovery phrase",
            heading: "Write these 24 words down.",
            body: " 1. abandon",
            affirm: "I have written these down",
            decline: None,
            refusal_is_default: true,
            scannable: None,
            identifier: None,
        });
        let screen = Screen::confirm(&content, "Not yet");
        assert_eq!(screen.buttons[1].label, "I have written these down");
        assert_eq!(screen.buttons[0].label, "Not yet");
    }

    // ---- Input screens. ----

    /// Secret material is masked by default and the mask survives into the screen (`SPEC.md` §3.1d).
    #[test]
    fn an_input_screen_carries_its_masking_and_reveal_affordance() {
        let content = InputContent {
            title: "DIG \u{2014} Restore".into(),
            heading: "Type your 24 words".into(),
            body: "Order matters.".into(),
            field_label: "Your 24 words:".into(),
            submit: "Restore",
            masked: true,
            revealable: true,
            style: crate::confirm::InputStyle::Dialog,
        };
        let screen = Screen::input(&content);
        let field = screen.field.expect("an input screen has a field");
        assert!(field.masked);
        assert!(field.revealable);
        assert_eq!(field.label, "Your 24 words:");
        assert_eq!(screen.buttons[1].label, "Restore");
    }

    /// An input screen always offers a way OUT that is not "submit" — never trap the user
    /// (`professional-ui`, HARD).
    #[test]
    fn an_input_screen_always_offers_a_refusal() {
        let content = InputContent {
            title: "t".into(),
            heading: "h".into(),
            body: "b".into(),
            field_label: "l".into(),
            submit: "Go",
            masked: false,
            revealable: false,
            style: crate::confirm::InputStyle::Dialog,
        };
        let screen = Screen::input(&content);
        assert!(screen.buttons.iter().any(|b| b.answer == Answer::Deny));
    }

    /// EVERY screen offers a refusal or a dismissal — there is no shape of prompt that leaves the
    /// user with no way out.
    #[test]
    fn every_screen_offers_at_least_one_control() {
        let screens = [
            Screen::confirm(&sign_content("Send 1 XCH"), "Cancel"),
            Screen::confirm(
                &ConfirmContent::notice(&NoticePrompt {
                    title: "t",
                    heading: "h",
                    body: "b",
                    acknowledge: "OK",
                    identifier: None,
                }),
                "Cancel",
            ),
        ];
        for screen in screens {
            assert!(!screen.buttons.is_empty(), "{:?}", screen.title);
        }
    }

    #[test]
    fn a_block_takes_its_colour_from_the_active_theme() {
        let warning = Block::Warning("gone for good".into());
        assert_eq!(block_color(&warning, &Tokens::LIGHT), Tokens::LIGHT.amber);
        assert_eq!(block_color(&warning, &Tokens::DARK), Tokens::DARK.amber);
        // …and the two themes genuinely differ, so the lookup is doing something.
        assert_ne!(Tokens::LIGHT.amber, Tokens::DARK.amber);
    }

    /// Build an input's content in the requested style. Every field but `style` is fixed, so a
    /// difference between two screens is a difference the style caused and nothing else.
    fn input_content(style: InputStyle) -> InputContent {
        InputContent {
            title: "DIG \u{2014} Open a dig:// link".into(),
            heading: "Open a dig:// link".into(),
            body: "Paste or type a dig:// address.".into(),
            field_label: "dig:// address".into(),
            submit: "Open",
            masked: false,
            revealable: false,
            style,
        }
    }

    /// A confirm content of each shape, so "consent is never a bar" is pinned against the WHOLE
    /// consent surface, not one example of it.
    fn every_confirm() -> Vec<Screen> {
        use crate::confirm::{ClaimPrompt, PairPrompt, RevealPrompt};
        vec![
            Screen::confirm(&sign_content("Send 1 XCH"), "Cancel"),
            Screen::confirm(
                &ConfirmContent::connect(&ConnectPrompt {
                    origin: "https://dapp.example",
                    dapp_name: Some("Example"),
                }),
                "Cancel",
            ),
            Screen::confirm(
                &ConfirmContent::pair(&PairPrompt {
                    ext_id: "mlibddmbhlgogepnjdienclhnkfpkfah",
                    ext_label: Some("DIG"),
                }),
                "Cancel",
            ),
            Screen::confirm(
                &ConfirmContent::notice(&NoticePrompt {
                    title: "t",
                    heading: "h",
                    body: "b",
                    acknowledge: "OK",
                    identifier: None,
                }),
                "Cancel",
            ),
            Screen::confirm(
                &ConfirmContent::destroy(&DestroyPrompt {
                    subject: "the account",
                    replacement: "",
                    recoverable: false,
                }),
                "Cancel",
            ),
            Screen::confirm(
                &ConfirmContent::claim(&ClaimPrompt {
                    title: "t",
                    heading: "h",
                    body: "b",
                    affirm: "Yes",
                    decline: None,
                    refusal_is_default: true,
                    scannable: None,
                    identifier: None,
                }),
                "Cancel",
            ),
            Screen::confirm(
                &ConfirmContent::reveal(&RevealPrompt {
                    secret: "your recovery phrase",
                }),
                "Cancel",
            ),
        ]
    }

    /// **`consent_is_never_a_bar`** — pinned in BOTH directions.
    ///
    /// EVERY confirm screen, whatever its shape, is a [`Chrome::Dialog`] and does not dismiss on
    /// blur — a window asking the user to authorise something must never vanish when they glance
    /// away. AND the launcher input IS a bar — so the property is a real structural distinction, not
    /// a constant that happens to read "Dialog" everywhere.
    #[test]
    fn consent_is_never_a_bar() {
        for screen in every_confirm() {
            assert_eq!(
                screen.chrome,
                Chrome::Dialog,
                "a confirm became a bar: {:?}",
                screen.title
            );
            assert!(
                !screen.chrome.dismiss_on_blur(),
                "a consent window would vanish on blur: {:?}",
                screen.title
            );
        }
        // The other direction: the launcher genuinely IS a bar, so the assertion above is a
        // distinction and not a tautology.
        let launcher = Screen::input(&input_content(InputStyle::Bar));
        assert_eq!(launcher.chrome, Chrome::Bar);
        assert!(launcher.chrome.dismiss_on_blur());
    }

    /// A `Bar` input dismisses on blur; a `Dialog` input does not. The one behaviour the bar carries
    /// beyond its looks (dig_ecosystem#2054).
    #[test]
    fn only_a_bar_dismisses_on_blur() {
        let bar = Screen::input(&input_content(InputStyle::Bar));
        let dialog = Screen::input(&input_content(InputStyle::Dialog));
        assert!(bar.chrome.dismiss_on_blur());
        assert!(!dialog.chrome.dismiss_on_blur());
    }

    /// A `Bar` drops the heading/body blocks down to at most one hint line and keeps the field; a
    /// `Dialog` keeps the full heading-plus-body layout. Asserts on the BLOCK SET, so a bar that
    /// quietly kept the heading fails here.
    #[test]
    fn a_bar_drops_the_heading_and_keeps_the_field() {
        let bar = Screen::input(&input_content(InputStyle::Bar));
        assert!(
            !bar.blocks.iter().any(|b| matches!(b, Block::Heading(_))),
            "the bar kept a heading: {:?}",
            bar.blocks
        );
        // At most one hint line, and it is body copy — never a heading.
        assert!(bar.blocks.len() <= 1, "the bar kept more than one line");
        assert!(bar.field.is_some(), "the bar lost its field");

        let dialog = Screen::input(&input_content(InputStyle::Dialog));
        assert!(
            dialog.blocks.iter().any(|b| matches!(b, Block::Heading(_))),
            "the dialog lost its heading"
        );
    }

    /// A bar with an empty body has no blocks at all — the hint line is dropped rather than left as
    /// an empty paragraph that would only add a stray gap above the field.
    #[test]
    fn a_bar_with_no_hint_has_no_blocks() {
        let mut content = input_content(InputStyle::Bar);
        content.body = String::new();
        let bar = Screen::input(&content);
        assert!(bar.blocks.is_empty());
        assert!(bar.field.is_some());
    }

    /// The bar sits HIGH: `bar_top` returns a y strictly above the vertical centre of the display,
    /// pinned from both sides of the divider so a regression to "centred" is caught.
    #[test]
    fn a_bar_is_placed_high_on_the_screen() {
        let monitor_h = 1080.0;
        let y = bar_top(monitor_h);
        assert!(y < monitor_h / 2.0, "the bar is not above centre");
        assert_eq!(y, monitor_h / BAR_TOP_DIVISOR);
        // And genuinely near the top, not merely a hair above centre.
        assert!(y < monitor_h / 3.0);
    }

    /// Guards the harness itself: if the headless text pipeline ever stops emitting glyphs, the
    /// tests above would pass while proving nothing, so the CONTROL fails first.
    #[test]
    fn the_headless_text_pipeline_emits_glyphs_at_all() {
        let (text, glyphs) = laid_out("abc");
        assert_eq!(text, "abc");
        assert_eq!(
            glyphs, 3,
            "no glyphs were shaped; the markup tests are vacuous"
        );
    }
}
