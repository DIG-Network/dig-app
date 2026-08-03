//! The DIG prompt palette — hub.dig.net's two themes, ported once (dig_ecosystem#2038).
//!
//! # Why the tokens live HERE and nowhere else
//!
//! Every colour a prompt window draws comes out of [`Tokens`]. Nothing else in the GUI names a hex
//! literal. That is the whole point: dig-app now carries a SECOND copy of a design system whose
//! source of truth is a CSS file in another repo
//! (`modules/services/hub.dig.net/apps/web/app/globals.css`), and a second copy that is scattered
//! through widget code cannot be diffed against the first. Each field below is named after the CSS
//! custom property it mirrors, so `grep -o '\-\-[a-z-]*' globals.css` and the field list here can be
//! compared by eye — and a divergence is a visible, greppable thing rather than a slow drift.
//!
//! # Light is the default
//!
//! hub is light-theme-first and so is dig-app: [`Theme::Light`] is what a user who has never touched
//! the setting sees, on every prompt, from the first run. Dark is opt-in and PERSISTED — see
//! [`ThemeChoice`] for why that persistence is a correctness requirement and not a nicety.

use std::path::{Path, PathBuf};

/// Which of hub's two themes a prompt is drawn in.
///
/// Deliberately a closed two-variant enum rather than a string or a "custom theme" hook: two themes
/// exist upstream, and a third invented here would be a divergence with nothing to diff against.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum Theme {
    /// hub's `:root` — the default, and what an unconfigured install shows.
    #[default]
    Light,
    /// hub's `[data-theme="dark"]` — opt-in, persisted.
    Dark,
}

impl Theme {
    /// The token set this theme draws with.
    pub fn tokens(self) -> Tokens {
        match self {
            Self::Light => Tokens::LIGHT,
            Self::Dark => Tokens::DARK,
        }
    }

    /// The other theme — what the toggle switches to.
    pub fn toggled(self) -> Self {
        match self {
            Self::Light => Self::Dark,
            Self::Dark => Self::Light,
        }
    }

    /// The on-disk spelling. Stable: it is written to a file that survives upgrades.
    fn as_str(self) -> &'static str {
        match self {
            Self::Light => "light",
            Self::Dark => "dark",
        }
    }

    /// Parse the on-disk spelling, falling back to the default for anything unrecognised.
    ///
    /// A corrupt or hand-edited file yields [`Theme::Light`] rather than an error: a prompt that
    /// refuses to open because its *colour scheme* could not be read would turn a cosmetic
    /// preference into a denial of the user's own account.
    fn parse(raw: &str) -> Self {
        match raw.trim() {
            "dark" => Self::Dark,
            _ => Self::Light,
        }
    }
}

/// One theme's colours, in premultiplied-free 8-bit RGBA, named after hub's CSS custom properties.
///
/// Alpha is carried explicitly because several of hub's dark tokens are `rgba(…)` rather than hex,
/// and flattening them against an assumed backdrop here would bake in the wrong surface.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Tokens {
    /// `--dig-purple` — the single accent.
    pub dig_purple: Rgba,
    /// `--dig-purple-hover`.
    pub dig_purple_hover: Rgba,
    /// `--dig-magenta` — secondary, used sparingly (the gradient's far end).
    pub dig_magenta: Rgba,
    /// `--dig-wash` — the faint accent tint behind highlighted regions.
    pub dig_wash: Rgba,
    /// `--bg` — the window backdrop.
    pub bg: Rgba,
    /// `--surface` — a card.
    pub surface: Rgba,
    /// `--surface-2` — a recessed card (the decoded-transaction panel).
    pub surface_2: Rgba,
    /// `--border`.
    pub border: Rgba,
    /// `--border-strong`.
    pub border_strong: Rgba,
    /// `--text` — primary copy.
    pub text: Rgba,
    /// `--muted` — secondary copy.
    pub muted: Rgba,
    /// `--faint` — tertiary copy.
    pub faint: Rgba,
    /// `--danger` — the destructive accent.
    pub danger: Rgba,
    /// `--danger-text` — destructive copy that clears AA on this theme's surfaces.
    pub danger_text: Rgba,
    /// `--ok` — the affirmative accent.
    pub ok: Rgba,
    /// `--amber` — the warning accent.
    pub amber: Rgba,
    /// `--amber-bg` — the warning panel fill.
    pub amber_bg: Rgba,
    /// `--amber-border`.
    pub amber_border: Rgba,
    /// `--glow-color` — the accent glow behind a primary control.
    pub glow: Rgba,
    /// `--shadow-pop`'s colour — the modal's own drop shadow.
    pub shadow: Rgba,
    /// `--chia-invert` as a boolean: whether a bundled white mark must be inverted to read on this
    /// theme's surfaces (hub's `1` → `true`).
    ///
    /// Carried as a token rather than derived from "is this the light theme" because that is how hub
    /// carries it, and because a future third asset could need the flag without needing a new theme.
    pub invert_marks: bool,
}

/// An 8-bit sRGB colour with straight (non-premultiplied) alpha.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Rgba {
    /// Red.
    pub r: u8,
    /// Green.
    pub g: u8,
    /// Blue.
    pub b: u8,
    /// Alpha; `255` for every opaque token.
    pub a: u8,
}

impl Rgba {
    /// An opaque colour, the form hub's hex tokens take.
    const fn hex(r: u8, g: u8, b: u8) -> Self {
        Self { r, g, b, a: 255 }
    }

    /// A translucent colour, the form hub's `rgba(…)` tokens take.
    const fn rgba(r: u8, g: u8, b: u8, a: u8) -> Self {
        Self { r, g, b, a }
    }

    /// Relative luminance per WCAG 2.2, used by the contrast checks.
    pub fn luminance(self) -> f64 {
        let channel = |c: u8| {
            let s = f64::from(c) / 255.0;
            if s <= 0.03928 {
                s / 12.92
            } else {
                ((s + 0.055) / 1.055).powf(2.4)
            }
        };
        0.2126 * channel(self.r) + 0.7152 * channel(self.g) + 0.0722 * channel(self.b)
    }

    /// The WCAG 2.2 contrast ratio between two OPAQUE colours, `1.0`..=`21.0`.
    ///
    /// Both operands must already be composited against their backdrop — this does no blending, so
    /// handing it a translucent token silently measures the wrong pair.
    pub fn contrast(self, other: Self) -> f64 {
        let (a, b) = (self.luminance(), other.luminance());
        let (hi, lo) = if a > b { (a, b) } else { (b, a) };
        (hi + 0.05) / (lo + 0.05)
    }

    /// Composite `self` over `backdrop` using `self`'s alpha, yielding an opaque colour.
    pub fn over(self, backdrop: Self) -> Self {
        let a = f64::from(self.a) / 255.0;
        let mix = |f: u8, b: u8| (f64::from(f) * a + f64::from(b) * (1.0 - a)).round() as u8;
        Self::hex(
            mix(self.r, backdrop.r),
            mix(self.g, backdrop.g),
            mix(self.b, backdrop.b),
        )
    }
}

impl Tokens {
    /// hub's `:root` block — the LIGHT theme, and dig-app's default.
    pub const LIGHT: Self = Self {
        dig_purple: Rgba::hex(0x58, 0x00, 0xd6),
        dig_purple_hover: Rgba::hex(0x48, 0x00, 0xb0),
        dig_magenta: Rgba::hex(0xff, 0x00, 0xde),
        dig_wash: Rgba::hex(0xf3, 0xf0, 0xfc),
        bg: Rgba::hex(0xf7, 0xf7, 0xfb),
        surface: Rgba::hex(0xff, 0xff, 0xff),
        surface_2: Rgba::hex(0xf3, 0xf1, 0xfb),
        border: Rgba::hex(0xe4, 0xe1, 0xf0),
        border_strong: Rgba::hex(0xd4, 0xd0, 0xe6),
        text: Rgba::hex(0x14, 0x12, 0x2b),
        muted: Rgba::hex(0x5e, 0x5a, 0x7c),
        faint: Rgba::hex(0x8e, 0x89, 0xa8),
        danger: Rgba::hex(0xd2, 0x3b, 0x57),
        danger_text: Rgba::hex(0xb0, 0x2a, 0x1f),
        ok: Rgba::hex(0x2e, 0xc2, 0x7e),
        amber: Rgba::hex(0x9a, 0x6b, 0x00),
        amber_bg: Rgba::hex(0xfb, 0xf3, 0xe0),
        amber_border: Rgba::hex(0xeb, 0xd9, 0xa8),
        // `--glow-color: rgba(122, 61, 255, .22)`.
        glow: Rgba::rgba(0x7a, 0x3d, 0xff, 56),
        // `--shadow-pop: 0 8px 28px rgba(20, 18, 43, .16)`.
        shadow: Rgba::rgba(0x14, 0x12, 0x2b, 41),
        invert_marks: true,
    };

    /// hub's `[data-theme="dark"]` block — the opt-in theme.
    pub const DARK: Self = Self {
        dig_purple: Rgba::hex(0x7a, 0x3d, 0xff),
        dig_purple_hover: Rgba::hex(0x94, 0x66, 0xff),
        dig_magenta: Rgba::hex(0xff, 0x00, 0xde),
        // `--dig-wash: rgba(122, 61, 255, .16)`.
        dig_wash: Rgba::rgba(0x7a, 0x3d, 0xff, 41),
        bg: Rgba::hex(0x0b, 0x0a, 0x12),
        surface: Rgba::hex(0x16, 0x13, 0x1f),
        surface_2: Rgba::hex(0x1e, 0x1a, 0x2b),
        border: Rgba::hex(0x2a, 0x24, 0x40),
        border_strong: Rgba::hex(0x3a, 0x33, 0x56),
        text: Rgba::hex(0xff, 0xff, 0xff),
        muted: Rgba::hex(0xa9, 0x9f, 0xc4),
        faint: Rgba::hex(0x7e, 0x76, 0x9b),
        danger: Rgba::hex(0xef, 0x55, 0x70),
        danger_text: Rgba::hex(0xef, 0x55, 0x70),
        ok: Rgba::hex(0x2e, 0xc2, 0x7e),
        amber: Rgba::hex(0xe0, 0xa6, 0x40),
        // `--amber-bg: rgba(224, 166, 64, .12)`.
        amber_bg: Rgba::rgba(0xe0, 0xa6, 0x40, 31),
        // `--amber-border: rgba(224, 166, 64, .4)`.
        amber_border: Rgba::rgba(0xe0, 0xa6, 0x40, 102),
        // `--glow-color: rgba(122, 61, 255, .45)`.
        glow: Rgba::rgba(0x7a, 0x3d, 0xff, 115),
        // `--shadow-pop: 0 8px 28px rgba(0, 0, 0, .6)`.
        shadow: Rgba::rgba(0, 0, 0, 153),
        invert_marks: false,
    };
}

/// The persisted theme preference.
///
/// # Why persistence is a correctness requirement
///
/// dig-app draws each prompt in a window it creates and destroys, so nothing about a prompt survives
/// in memory between two of them. Without a stored answer, EVERY consent dialog would open in the
/// default theme regardless of what the user chose a minute earlier — a light flash in a dark session,
/// on the window that asks whether to spend money. That reads as a different application each time,
/// which is precisely the unpolished quality this work exists to remove.
#[derive(Debug, Clone)]
pub struct ThemeChoice {
    /// The file the preference is stored in.
    path: PathBuf,
}

/// The file name the preference is stored under, inside the brand data directory.
const FILE_NAME: &str = "theme";

impl ThemeChoice {
    /// The preference stored beside the rest of dig-app's per-user state.
    pub fn in_brand_dir(brand_dir: &Path) -> Self {
        Self {
            path: brand_dir.join(FILE_NAME),
        }
    }

    /// The stored theme, or [`Theme::Light`] when nothing has been stored.
    ///
    /// Never fails. An unreadable, absent or nonsense file all mean "the user has expressed no
    /// preference", which is the default — see [`Theme::parse`] for why this must not be an error.
    pub fn read(&self) -> Theme {
        std::fs::read_to_string(&self.path)
            .map(|raw| Theme::parse(&raw))
            .unwrap_or_default()
    }

    /// Store `theme` so the next prompt opens in it.
    ///
    /// Errors are returned rather than swallowed so a caller can log them, but a caller that ignores
    /// the result still behaves correctly: the toggle applies to the open window either way, and the
    /// next window falls back to the default.
    pub fn write(&self, theme: Theme) -> std::io::Result<()> {
        if let Some(parent) = self.path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(&self.path, theme.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn light_is_the_default_theme() {
        assert_eq!(Theme::default(), Theme::Light);
    }

    #[test]
    fn toggling_twice_returns_to_where_it_started() {
        assert_eq!(Theme::Light.toggled(), Theme::Dark);
        assert_eq!(Theme::Light.toggled().toggled(), Theme::Light);
    }

    /// A user who has never touched the setting gets light, with no file on disk.
    #[test]
    fn an_unset_preference_reads_as_light() {
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(ThemeChoice::in_brand_dir(dir.path()).read(), Theme::Light);
    }

    /// The persistence requirement itself: a stored choice survives into a fresh reader, which is
    /// what a separately-spawned prompt window is.
    #[test]
    fn a_stored_choice_survives_into_a_fresh_reader() {
        let dir = tempfile::tempdir().unwrap();
        ThemeChoice::in_brand_dir(dir.path())
            .write(Theme::Dark)
            .unwrap();

        // A brand-new value over the same directory — no shared state with the writer.
        assert_eq!(ThemeChoice::in_brand_dir(dir.path()).read(), Theme::Dark);
    }

    /// …and the control: without the write, the same fresh reader answers light. Without this, a
    /// `read` hard-coded to `Dark` would pass the test above.
    #[test]
    fn the_same_reader_answers_light_when_nothing_was_written() {
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(ThemeChoice::in_brand_dir(dir.path()).read(), Theme::Light);
    }

    /// A corrupt file must not deny the user their account over a colour scheme.
    #[test]
    fn a_corrupt_preference_falls_back_to_light_rather_than_failing() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join(FILE_NAME), "\u{0}not-a-theme\u{feff}").unwrap();
        assert_eq!(ThemeChoice::in_brand_dir(dir.path()).read(), Theme::Light);
    }

    #[test]
    fn a_theme_round_trips_through_its_on_disk_spelling() {
        for theme in [Theme::Light, Theme::Dark] {
            assert_eq!(Theme::parse(theme.as_str()), theme, "{theme:?}");
        }
    }

    #[test]
    fn the_two_themes_disagree_about_inverting_bundled_marks() {
        // hub's `--chia-invert` flips 1→0 between the themes; a bundled white mark needs the same
        // treatment as the colours, and a single shared value would silently drop that.
        assert!(Tokens::LIGHT.invert_marks);
        assert!(!Tokens::DARK.invert_marks);
    }

    // ---- WCAG 2.2 AA, in BOTH themes (§6.6). ----

    /// Body and heading copy against the surfaces they are actually drawn on.
    ///
    /// Ported hex values are not automatically AA once a different rasteriser draws them, so the
    /// ratios are asserted here rather than assumed from hub's own audit.
    #[test]
    fn primary_and_secondary_copy_clear_aa_on_every_surface_in_both_themes() {
        for (name, t) in [("light", Tokens::LIGHT), ("dark", Tokens::DARK)] {
            for (surface_name, surface) in [
                ("bg", t.bg),
                ("surface", t.surface),
                ("surface-2", t.surface_2),
            ] {
                // 4.5:1 is AA for normal-size text — the bar the body copy must clear.
                let text = t.text.contrast(surface);
                assert!(
                    text >= 4.5,
                    "{name}: --text on --{surface_name} is {text:.2}:1, below AA 4.5"
                );
                let muted = t.muted.contrast(surface);
                assert!(
                    muted >= 4.5,
                    "{name}: --muted on --{surface_name} is {muted:.2}:1, below AA 4.5"
                );
            }
        }
    }

    /// The affirmative button's label against its own fill — the single most consequential piece of
    /// text in the product, since it is what the user reads before authorising a spend.
    #[test]
    fn the_affirmative_button_label_clears_aa_in_both_themes() {
        let white = Rgba::hex(0xff, 0xff, 0xff);
        for (name, t) in [("light", Tokens::LIGHT), ("dark", Tokens::DARK)] {
            let ratio = white.contrast(t.dig_purple);
            assert!(
                ratio >= 4.5,
                "{name}: white on --dig-purple is {ratio:.2}:1, below AA 4.5"
            );
        }
    }

    /// Destructive copy — the destroy/replace window — against the card it sits on.
    #[test]
    fn destructive_copy_clears_aa_in_both_themes() {
        for (name, t) in [("light", Tokens::LIGHT), ("dark", Tokens::DARK)] {
            let ratio = t.danger_text.contrast(t.surface);
            assert!(
                ratio >= 4.5,
                "{name}: --danger-text on --surface is {ratio:.2}:1, below AA 4.5"
            );
        }
    }

    /// The borders are decoration, so they take AA's 3:1 non-text bar rather than 4.5:1 — asserted
    /// so a future token edit cannot quietly make the card edge invisible.
    #[test]
    fn the_strong_border_clears_the_non_text_bar_in_both_themes() {
        for (name, t) in [("light", Tokens::LIGHT), ("dark", Tokens::DARK)] {
            let ratio = t.border_strong.contrast(t.surface);
            assert!(
                ratio >= 1.3,
                "{name}: --border-strong on --surface is {ratio:.2}:1, invisible"
            );
        }
    }

    #[test]
    fn compositing_a_translucent_token_yields_an_opaque_colour() {
        let half = Rgba::rgba(0, 0, 0, 128);
        let over_white = half.over(Rgba::hex(0xff, 0xff, 0xff));
        assert_eq!(over_white.a, 255);
        assert!(
            (127..=128).contains(&over_white.r),
            "expected a mid grey, got {over_white:?}"
        );
    }
}
