//! The global shortcut that opens the URN bar (dig_ecosystem#1839) — as data.
//!
//! # Why the shortcut is a model and not just a `RegisterHotKey` call
//!
//! Registering a system-wide shortcut is three lines of platform glue. Everything AROUND it is the part
//! that can be wrong: which chord the user asked for, whether that chord is even expressible, what the
//! app says when the OS refuses it, and how a person discovers the shortcut exists at all. None of that
//! can be tested from inside a Win32 message loop, so it lives here, pure, and the shell
//! ([`dig-app`'s `hotkey` module](../../dig_app/index.html)) does nothing but ask this module what to
//! register and report back what happened.
//!
//! # Alt+Space is TAKEN on Windows, and this claims it deliberately
//!
//! `Alt+Space` has opened the focused window's system menu (Move / Size / Minimize / Close) since
//! Windows 3.x, and is the keyboard route to moving a window without a mouse. A successful
//! `RegisterHotKey(NULL, id, MOD_ALT, VK_SPACE)` takes precedence and suppresses it **globally**, for
//! every application, for as long as dig-app runs.
//!
//! That is a real cost, taken on purpose and with precedent: PowerToys Run — Microsoft's own launcher —
//! ships Alt+Space as its default for exactly this reason. A launcher that needs a documented workaround
//! to bind its own shortcut is worse than one that claims a rarely-used chord, so DIG claims it, SAYS so
//! in `Status`, and lets the user change it ([`crate::config::AgentConfig::open_bar_shortcut`]).
//!
//! # Failing to register must never cost the user their app
//!
//! Another application may already hold the chord — `RegisterHotKey` then fails, and there is nothing
//! dig-app can do about it. That is a [`HotkeyState::Unavailable`], which is reported in `Status` with
//! the reason and leaves the tray's `Open URL…` row working exactly as before. A shortcut is a
//! convenience; the app's startup never depends on one.

use std::fmt;

/// The chord DIG claims unless the user configures another one.
///
/// `Alt+Space`, as asked for in dig_ecosystem#1839 — see the module docs for what it displaces and why
/// that is acceptable.
pub const DEFAULT_SHORTCUT: &str = "Alt+Space";

/// The non-modifier key of a shortcut.
///
/// A closed set rather than "any key": a shortcut is registered with a Win32 virtual-key code, and the
/// mapping from a name a user typed in a config file to that code is exactly the kind of thing that
/// should refuse what it does not understand rather than guess. Refusing produces a
/// [`HotkeyError::UnknownKey`] the user can read; guessing produces a shortcut that silently does
/// nothing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Key {
    /// The space bar.
    Space,
    /// A letter key, stored upper-case (its virtual-key code IS its ASCII upper-case value).
    Letter(char),
    /// A digit key `0`–`9` on the number row.
    Digit(u8),
    /// A function key `F1`–`F24`.
    Function(u8),
}

impl Key {
    /// The Win32 virtual-key code this key registers as.
    ///
    /// Pure integer arithmetic over the documented `VK_*` constants, so the mapping is unit-tested here
    /// rather than trusted inside the platform glue where nothing can reach it.
    pub fn virtual_key(self) -> u32 {
        /// `VK_SPACE`.
        const VK_SPACE: u32 = 0x20;
        /// `VK_F1`; F2..F24 follow contiguously.
        const VK_F1: u32 = 0x70;
        match self {
            // The `VK_0`–`VK_9` and `VK_A`–`VK_Z` codes ARE the ASCII values of the characters.
            Self::Space => VK_SPACE,
            Self::Letter(c) => c as u32,
            Self::Digit(d) => u32::from(b'0') + u32::from(d),
            Self::Function(n) => VK_F1 + u32::from(n) - 1,
        }
    }

    /// Parse one key name, case-insensitively. `None` if it names no key this module can register.
    fn parse(token: &str) -> Option<Self> {
        let upper = token.to_ascii_uppercase();
        if upper == "SPACE" {
            return Some(Self::Space);
        }
        if let Some(number) = upper.strip_prefix('F') {
            let n: u8 = number.parse().ok()?;
            return (1..=24).contains(&n).then_some(Self::Function(n));
        }
        let mut chars = upper.chars();
        let (first, rest) = (chars.next()?, chars.next());
        match (first, rest) {
            (c, None) if c.is_ascii_uppercase() => Some(Self::Letter(c)),
            (c, None) if c.is_ascii_digit() => Some(Self::Digit(c as u8 - b'0')),
            _ => None,
        }
    }
}

impl fmt::Display for Key {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Space => f.write_str("Space"),
            Self::Letter(c) => write!(f, "{c}"),
            Self::Digit(d) => write!(f, "{d}"),
            Self::Function(n) => write!(f, "F{n}"),
        }
    }
}

/// A global shortcut: at least one modifier plus one key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Hotkey {
    /// Whether `Ctrl` is held.
    pub ctrl: bool,
    /// Whether `Alt` is held.
    pub alt: bool,
    /// Whether `Shift` is held.
    pub shift: bool,
    /// Whether the Windows / Command key is held.
    pub win: bool,
    /// The non-modifier key.
    pub key: Key,
}

impl Hotkey {
    /// Parse a chord such as `"Alt+Space"` or `"Ctrl+Shift+D"`, case- and space-insensitively.
    ///
    /// # Why a modifier is REQUIRED
    ///
    /// A global hotkey is registered process-wide and suppresses the key for every application on the
    /// desktop. A bare `Space` would therefore make the space bar stop working everywhere the moment
    /// dig-app started — an unrecoverable state for anyone who could not guess the cause. So a chord
    /// without a modifier is refused at parse time ([`HotkeyError::NoModifier`]) and the user is told
    /// why, rather than being handed a keyboard that no longer types.
    pub fn parse(text: &str) -> Result<Self, HotkeyError> {
        let mut hotkey = Self {
            ctrl: false,
            alt: false,
            shift: false,
            win: false,
            key: Key::Space,
        };
        let mut key = None;
        let tokens: Vec<&str> = text
            .split('+')
            .map(str::trim)
            .filter(|t| !t.is_empty())
            .collect();
        if tokens.is_empty() {
            return Err(HotkeyError::Empty);
        }
        for token in tokens {
            match token.to_ascii_uppercase().as_str() {
                "CTRL" | "CONTROL" => hotkey.ctrl = true,
                "ALT" | "OPTION" => hotkey.alt = true,
                "SHIFT" => hotkey.shift = true,
                "WIN" | "SUPER" | "CMD" | "COMMAND" => hotkey.win = true,
                _ => match Key::parse(token) {
                    // Two keys is a typo ("Alt+Space+Space"), not a chord anything could register.
                    Some(_) if key.is_some() => return Err(HotkeyError::TwoKeys),
                    Some(parsed) => key = Some(parsed),
                    None => return Err(HotkeyError::UnknownKey(token.to_string())),
                },
            }
        }
        hotkey.key = key.ok_or(HotkeyError::NoKey)?;
        if !hotkey.has_modifier() {
            return Err(HotkeyError::NoModifier);
        }
        Ok(hotkey)
    }

    /// Whether any modifier is held. See [`Hotkey::parse`] for why this is not optional.
    fn has_modifier(&self) -> bool {
        self.ctrl || self.alt || self.shift || self.win
    }

    /// The Win32 `MOD_*` bit set this chord registers with, `MOD_NOREPEAT` included.
    ///
    /// `MOD_NOREPEAT` is not a detail: without it, holding the chord down repeats `WM_HOTKEY` at the
    /// keyboard's auto-repeat rate, and each one would open another bar.
    pub fn modifiers(&self) -> u32 {
        /// `MOD_ALT`.
        const MOD_ALT: u32 = 0x0001;
        /// `MOD_CONTROL`.
        const MOD_CONTROL: u32 = 0x0002;
        /// `MOD_SHIFT`.
        const MOD_SHIFT: u32 = 0x0004;
        /// `MOD_WIN`.
        const MOD_WIN: u32 = 0x0008;
        /// `MOD_NOREPEAT`.
        const MOD_NOREPEAT: u32 = 0x4000;

        let mut bits = MOD_NOREPEAT;
        for (held, bit) in [
            (self.alt, MOD_ALT),
            (self.ctrl, MOD_CONTROL),
            (self.shift, MOD_SHIFT),
            (self.win, MOD_WIN),
        ] {
            if held {
                bits |= bit;
            }
        }
        bits
    }

    /// The Win32 virtual-key code, for the same call.
    pub fn virtual_key(&self) -> u32 {
        self.key.virtual_key()
    }

    /// Whether this chord displaces the Windows system menu (`Alt+Space`, and only that).
    ///
    /// Read by [`HotkeyState::summary`] so the app says what it took rather than leaving the user to
    /// work out why their window menu stopped opening.
    pub fn displaces_window_menu(&self) -> bool {
        *self
            == Self {
                ctrl: false,
                alt: true,
                shift: false,
                win: false,
                key: Key::Space,
            }
    }
}

impl Default for Hotkey {
    /// [`DEFAULT_SHORTCUT`], parsed. Its own test pins that the constant and this agree.
    fn default() -> Self {
        Self {
            ctrl: false,
            alt: true,
            shift: false,
            win: false,
            key: Key::Space,
        }
    }
}

impl fmt::Display for Hotkey {
    /// Renders in the order a person reads a shortcut, which is also the order [`Hotkey::parse`]
    /// accepts — so every value round-trips through its own display form.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (held, name) in [
            (self.ctrl, "Ctrl"),
            (self.alt, "Alt"),
            (self.shift, "Shift"),
            (self.win, "Win"),
        ] {
            if held {
                write!(f, "{name}+")?;
            }
        }
        write!(f, "{}", self.key)
    }
}

/// Why a configured shortcut could not be understood.
///
/// Each variant carries what the user must change, because the only place these are seen is a log line
/// and the `Status` window — neither of which can ask a follow-up question.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum HotkeyError {
    /// The setting was blank.
    #[error("the shortcut is empty — write it as {DEFAULT_SHORTCUT}")]
    Empty,
    /// A token named nothing this module can register.
    #[error("\"{0}\" is not a key DIG can register — try a letter, a digit, F1–F24, or Space")]
    UnknownKey(String),
    /// Modifiers only, no key.
    #[error("the shortcut names no key — write it as {DEFAULT_SHORTCUT}")]
    NoKey,
    /// More than one non-modifier key.
    #[error("a shortcut may name only one key")]
    TwoKeys,
    /// No modifier — see [`Hotkey::parse`].
    #[error(
        "a global shortcut must include Ctrl, Alt, Shift or Win, or it would stop that key working \
         in every application"
    )]
    NoModifier,
}

/// What became of the shortcut, as the user needs to hear it.
///
/// Three states rather than `Option<Hotkey>`, because "this desktop cannot offer one" and "this desktop
/// could, but something else already holds the chord" call for different words and different remedies —
/// and collapsing them produces a `Status` window that says nothing useful in either case.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HotkeyState {
    /// The shortcut is live.
    Registered(Hotkey),
    /// The platform supports global shortcuts but refused this one — almost always because another
    /// application already registered it.
    Unavailable {
        /// The chord that was attempted.
        hotkey: Hotkey,
        /// What the OS (or the config parser) said, in the user's words.
        reason: String,
    },
    /// This build or desktop has no global-shortcut mechanism at all.
    Unsupported {
        /// Why, and what to use instead.
        reason: String,
    },
}

impl HotkeyState {
    /// The live chord, if there is one — what the tray appends to its `Open URL…` row so the shortcut
    /// is DISCOVERABLE rather than a secret only the release notes know.
    pub fn shortcut(&self) -> Option<Hotkey> {
        match self {
            Self::Registered(hotkey) => Some(*hotkey),
            _ => None,
        }
    }

    /// The `Status` window's line about the shortcut.
    ///
    /// Every state says something. A failure that produced silence would leave a user pressing a chord
    /// that does nothing with no way to find out why — which is the whole reason this is a three-state
    /// enum and not an `Option`.
    pub fn summary(&self) -> String {
        match self {
            Self::Registered(hotkey) if hotkey.displaces_window_menu() => format!(
                "{hotkey} opens the DIG bar from any application. While DIG is running this replaces \
                 the Windows window menu (Move / Size / Close) that {hotkey} normally opens."
            ),
            Self::Registered(hotkey) => {
                format!("{hotkey} opens the DIG bar from any application.")
            }
            Self::Unavailable { hotkey, reason } => format!(
                "{hotkey} could not be claimed ({reason}), so there is no keyboard shortcut. Open URL… \
                 in this menu still works."
            ),
            Self::Unsupported { reason } => format!(
                "No keyboard shortcut ({reason}). Open URL… in this menu still works."
            ),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every chord a user might reasonably write, and what it must parse to.
    #[test]
    fn parses_the_chords_a_person_writes() {
        assert_eq!(Hotkey::parse("Alt+Space").unwrap(), Hotkey::default());
        // Case and spacing are how a hand-edited config file actually looks.
        assert_eq!(Hotkey::parse("  alt + SPACE ").unwrap(), Hotkey::default());
        assert_eq!(
            Hotkey::parse("Ctrl+Shift+D").unwrap(),
            Hotkey {
                ctrl: true,
                alt: false,
                shift: true,
                win: false,
                key: Key::Letter('D'),
            }
        );
        assert_eq!(Hotkey::parse("Win+F5").unwrap().key, Key::Function(5));
        assert_eq!(Hotkey::parse("Ctrl+7").unwrap().key, Key::Digit(7));
        // The macOS/Linux spellings of the same modifiers.
        assert!(Hotkey::parse("Command+Space").unwrap().win);
        assert_eq!(Hotkey::parse("Option+Space").unwrap(), Hotkey::default());
    }

    /// The constant the docs and config quote must BE the default, not merely resemble it.
    #[test]
    fn the_documented_default_is_the_default() {
        assert_eq!(Hotkey::parse(DEFAULT_SHORTCUT).unwrap(), Hotkey::default());
        assert_eq!(Hotkey::default().to_string(), DEFAULT_SHORTCUT);
    }

    /// Display is the inverse of parse for every shape, so a chord shown in `Status` is one the user can
    /// paste straight back into the config file.
    #[test]
    fn every_chord_round_trips_through_its_own_display_form() {
        for text in [
            "Alt+Space",
            "Ctrl+Shift+D",
            "Ctrl+Alt+Shift+Win+F12",
            "Win+9",
            "Shift+A",
        ] {
            let parsed = Hotkey::parse(text).unwrap();
            assert_eq!(
                Hotkey::parse(&parsed.to_string()).unwrap(),
                parsed,
                "{text} did not round-trip"
            );
        }
    }

    /// A modifier-less chord would suppress that key in EVERY application on the desktop.
    #[test]
    fn a_shortcut_without_a_modifier_is_refused() {
        assert_eq!(Hotkey::parse("Space"), Err(HotkeyError::NoModifier));
        assert_eq!(Hotkey::parse("F1"), Err(HotkeyError::NoModifier));
    }

    #[test]
    fn malformed_shortcuts_name_what_is_wrong() {
        assert_eq!(Hotkey::parse(""), Err(HotkeyError::Empty));
        assert_eq!(Hotkey::parse("Alt"), Err(HotkeyError::NoKey));
        assert_eq!(Hotkey::parse("Alt+Space+D"), Err(HotkeyError::TwoKeys));
        assert_eq!(
            Hotkey::parse("Alt+Banana"),
            Err(HotkeyError::UnknownKey("Banana".to_string()))
        );
        // F0 and F25 are not keys, and must not silently become VK codes either side of the range.
        assert_eq!(
            Hotkey::parse("Alt+F0"),
            Err(HotkeyError::UnknownKey("F0".to_string()))
        );
        assert_eq!(
            Hotkey::parse("Alt+F25"),
            Err(HotkeyError::UnknownKey("F25".to_string()))
        );
    }

    /// The virtual-key codes, pinned against the documented `VK_*` values rather than against
    /// themselves — a mapping checked only by round-tripping through its own table cannot see an error.
    #[test]
    fn virtual_keys_match_the_documented_win32_codes() {
        assert_eq!(Key::Space.virtual_key(), 0x20);
        assert_eq!(Key::Letter('A').virtual_key(), 0x41);
        assert_eq!(Key::Letter('Z').virtual_key(), 0x5A);
        assert_eq!(Key::Digit(0).virtual_key(), 0x30);
        assert_eq!(Key::Digit(9).virtual_key(), 0x39);
        assert_eq!(Key::Function(1).virtual_key(), 0x70);
        assert_eq!(Key::Function(12).virtual_key(), 0x7B);
        assert_eq!(Key::Function(24).virtual_key(), 0x87);
    }

    /// The modifier bits, likewise pinned to the documented `MOD_*` values — and `MOD_NOREPEAT`
    /// asserted PRESENT on every chord, because without it holding the keys down opens a bar per
    /// auto-repeat tick.
    #[test]
    fn modifier_bits_match_the_documented_win32_values_and_never_repeat() {
        const NOREPEAT: u32 = 0x4000;
        assert_eq!(Hotkey::default().modifiers(), NOREPEAT | 0x0001);
        assert_eq!(
            Hotkey::parse("Ctrl+Shift+Win+A").unwrap().modifiers(),
            NOREPEAT | 0x0002 | 0x0004 | 0x0008
        );
        for text in ["Alt+Space", "Ctrl+D", "Shift+F1", "Win+9"] {
            assert_eq!(
                Hotkey::parse(text).unwrap().modifiers() & NOREPEAT,
                NOREPEAT,
                "{text} would auto-repeat"
            );
        }
    }

    /// Only Alt+Space displaces the window menu — a near-miss chord must not claim it does, or the
    /// warning becomes noise the user learns to ignore.
    #[test]
    fn only_alt_space_displaces_the_window_menu() {
        assert!(Hotkey::default().displaces_window_menu());
        for text in ["Ctrl+Alt+Space", "Alt+Shift+Space", "Alt+D", "Ctrl+Space"] {
            assert!(
                !Hotkey::parse(text).unwrap().displaces_window_menu(),
                "{text} is not the window-menu chord"
            );
        }
    }

    /// The live chord is offered for display ONLY when it is actually live — a failed registration that
    /// still advertised the shortcut would put a lie in the tray menu.
    #[test]
    fn only_a_registered_shortcut_is_advertised() {
        assert_eq!(
            HotkeyState::Registered(Hotkey::default()).shortcut(),
            Some(Hotkey::default())
        );
        assert_eq!(
            HotkeyState::Unavailable {
                hotkey: Hotkey::default(),
                reason: "another application already uses it".to_string(),
            }
            .shortcut(),
            None
        );
        assert_eq!(
            HotkeyState::Unsupported {
                reason: "not on this desktop".to_string()
            }
            .shortcut(),
            None
        );
    }

    /// Every state says something, and both failure states name the route that still works.
    #[test]
    fn every_state_explains_itself_and_failures_point_at_the_tray() {
        let registered = HotkeyState::Registered(Hotkey::default()).summary();
        assert!(registered.contains("Alt+Space"));
        // The displacement is DISCLOSED, per the module docs — a shortcut that silently breaks the
        // window menu is the failure mode this whole decision was weighed against.
        assert!(registered.contains("window menu"));

        // A chord that displaces nothing must NOT carry the warning.
        let other = HotkeyState::Registered(Hotkey::parse("Ctrl+Alt+D").unwrap()).summary();
        assert!(other.contains("Ctrl+Alt+D"));
        assert!(!other.contains("window menu"));

        for failed in [
            HotkeyState::Unavailable {
                hotkey: Hotkey::default(),
                reason: "another application already uses it".to_string(),
            },
            HotkeyState::Unsupported {
                reason: "this build has no global shortcut support".to_string(),
            },
        ] {
            let text = failed.summary();
            assert!(text.contains("Open URL…"), "{text} offers no way forward");
            assert!(!text.is_empty());
        }
    }
}
