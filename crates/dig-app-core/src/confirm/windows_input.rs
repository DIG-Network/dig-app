//! **Every** native DIG window on Windows: one registered window class, drawn with or without a typed field.
//!
//! # Why this exists at all
//!
//! It began (dig_ecosystem#1798) as the ONE window `MessageBoxW` could not draw. A message box cannot take
//! typed input — no control to type into and no API to add one — and that single limitation is why the tray
//! once shipped *"Restore from a recovery phrase (in a terminal)…"* and handed the user a command to run. A
//! tray menu having no text field is a fact about the tray API, not a reason to make a person open a console.
//!
//! It then absorbed the other four (dig_ecosystem#1832), because the same limitation shaped them too:
//! `MessageBoxW` cannot RELABEL its buttons, so every two-choice window had to spell its choice out in a
//! sentence — the retention claim explained in a paragraph what a button reading "Yes, I have them" says by
//! itself, and the destroy window's way out was labelled "Cancel", which names the dialog rather than the
//! outcome. Nor could it be scaled, styled, or given the DIG mark. The labels were in the content all along;
//! macOS and Linux put them on their buttons and only Windows discarded them.
//!
//! So there is now ONE window here, described by a [`WindowSpec`]: a heading, a body, an optional
//! [`FieldSpec`], and [`ButtonSpec`] buttons. That is deliberate rather than incidental — it means the DPI
//! scaling, the type hierarchy, the keyboard handling and (next) dark mode are implemented once and cannot
//! drift between "the message window" and "the input window".
//!
//! # Why it is not a subprocess helper
//!
//! The cheaper route — spawn a small `dig-ask-for-a-phrase.exe` and read its stdout — was **rejected on
//! security grounds**: it would need a "verify this helper is really ours" check, or a `PATH` impostor
//! harvests recovery phrases. This window is drawn IN THIS PROCESS, so there is no helper to impersonate.
//!
//! # Why not a `DLGTEMPLATE`
//!
//! A dialog template would have to be packed byte-by-byte at runtime (`DLGTEMPLATEEX` is an undocumented
//! variable-length layout with alignment rules), and a mistake there is a memory-safety bug rather than a
//! visible defect. Creating the same controls with `CreateWindowExW` is longer but every step is checked,
//! and [`IsDialogMessageW`] gives the window the keyboard behaviour a dialog would have anyway — Tab
//! between controls, Esc to cancel, Enter on the default button (§6.6: a native window must be usable
//! from the keyboard alone).
//!
//! # Secret handling
//!
//! The typed text is a recovery phrase. It is read once into a [`Zeroizing`] buffer, the `EDIT` control's
//! own buffer is overwritten before the window is destroyed, and nothing here logs, returns or stores the
//! text anywhere else.

use std::sync::OnceLock;

use windows::core::{HSTRING, PCWSTR};
use windows::Win32::Foundation::{E_FAIL, HINSTANCE, HWND, LPARAM, LRESULT, POINT, WPARAM};
use windows::Win32::Graphics::Gdi::{
    CreateFontW, DeleteObject, InvalidateRect, MonitorFromPoint, ANSI_CHARSET, CLEARTYPE_QUALITY,
    COLOR_WINDOW, DEFAULT_PITCH, FF_DONTCARE, FW_NORMAL, FW_SEMIBOLD, HBRUSH, HFONT,
    MONITOR_DEFAULTTONEAREST, OUT_TT_PRECIS,
};
use windows::Win32::System::LibraryLoader::GetModuleHandleW;
use windows::Win32::UI::HiDpi::{GetDpiForMonitor, MDT_EFFECTIVE_DPI};
use windows::Win32::UI::Input::KeyboardAndMouse::SetFocus;
// `BM_GETCHECK`/`BST_CHECKED`/`EM_SETPASSWORDCHAR` live in the Controls module, not WindowsAndMessaging.
use windows::Win32::UI::Controls::{BST_CHECKED, EM_SETPASSWORDCHAR};
use windows::Win32::UI::WindowsAndMessaging::{
    CreateWindowExW, DefWindowProcW, DestroyWindow, DispatchMessageW, GetCursorPos, GetDlgItem,
    GetMessageW, GetSystemMetrics, GetWindowLongPtrW, GetWindowTextLengthW, GetWindowTextW,
    IsDialogMessageW, LoadCursorW, PostQuitMessage, RegisterClassW, SendMessageW,
    SetForegroundWindow, SetWindowLongPtrW, SetWindowTextW, ShowWindow, TranslateMessage,
    BM_GETCHECK, BS_AUTOCHECKBOX, BS_DEFPUSHBUTTON, BS_PUSHBUTTON, CREATESTRUCTW, CW_USEDEFAULT,
    ES_AUTOHSCROLL, ES_PASSWORD, GWLP_USERDATA, HMENU, IDCANCEL, IDC_ARROW, IDOK, MSG, SM_CXSCREEN,
    SM_CYSCREEN, SW_SHOW, WA_INACTIVE, WINDOW_EX_STYLE, WINDOW_STYLE, WM_ACTIVATE, WM_CLOSE,
    WM_COMMAND, WM_DESTROY, WM_NCCREATE, WM_SETFONT, WNDCLASSW, WS_BORDER, WS_CAPTION, WS_CHILD,
    WS_EX_TOPMOST, WS_GROUP, WS_OVERLAPPED, WS_POPUP, WS_SYSMENU, WS_TABSTOP, WS_VISIBLE,
};
use zeroize::Zeroizing;

use super::{
    ConfirmContent, ForegroundInput, ForegroundWindow, InputContent, InputOutcome, InputStyle,
    Presentation, WindowIntent,
};

/// The window class this module registers. Namespaced so it can never collide with another component's.
const CLASS_NAME: PCWSTR = windows::core::w!("DigAppNativeInputWindow");

/// The window's geometry in DESIGN UNITS — pixels at 96 DPI, the reference scale.
///
/// Nothing here is used directly for drawing. [`Metrics::for_dpi`] scales every value by the DPI of the
/// monitor the window will appear on, and the drawing code reads only the scaled result. That indirection
/// is the whole point: this process is DPI-AWARE (tao calls `SetProcessDpiAwarenessContext` when it builds
/// the tray), so Windows does NOT scale it for us — a raw pixel written here would render at a fraction of
/// its intended physical size on any display above 100%, which is exactly how these windows came to read
/// as "too small" on a 3840x2400 panel (dig_ecosystem#1832).
///
/// Named constants rather than magic numbers inline, because the layout is arithmetic over them and a
/// stray literal is impossible to review.
mod layout {
    /// Outer width — wide enough that 24 words wrap into a readable block rather than a ribbon.
    pub const WIDTH: i32 = 660;
    /// Uniform margin around and between the controls.
    pub const MARGIN: i32 = 20;
    /// Height of a one-line body label.
    pub const LINE: i32 = 22;
    /// Height of the heading line, which uses a larger, semibold face.
    pub const HEADING_LINE: i32 = 30;
    /// Body text height for `CreateFontW` (negative = character height). The `CHAR_WIDTH` estimate below
    /// is calibrated to THIS size, so the two move together or the wrap maths stops protecting the text.
    pub const FONT_BODY: i32 = 15;
    /// Heading text height — larger and semibold, so the window has an actual type hierarchy instead of
    /// one size for everything.
    pub const FONT_HEADING: i32 = 21;
    /// Approximate width of one character at the window's font, in pixels.
    ///
    /// Used only to work out how many lines the body will wrap to. A `STATIC` control does not scroll and
    /// silently CLIPS text that does not fit, which a screenshot of the first build caught: the Sage
    /// warning — the most important sentence on the window — was cut off mid-phrase. So the body's height
    /// is computed from its text rather than fixed. 7 is a deliberate UNDER-estimate for Segoe UI at 15 px
    /// (whose average is nearer 8), because under-estimating the character width over-estimates the line
    /// count, and an extra blank line costs nothing while a missing one hides a warning.
    pub const CHAR_WIDTH: i32 = 7;

    /// The fewest body lines to reserve, so a one-line body still looks deliberate rather than cramped.
    pub const BODY_MIN_LINES: i32 = 2;

    /// The most body lines to reserve, bounding the window to something that fits a small display. Text
    /// past this is still clipped — but the body is caller-composed copy, and every real one fits well
    /// inside it (the longest is 6 lines).
    pub const BODY_MAX_LINES: i32 = 10;
    /// Height of the input field. One value, because the field can never be multiline: Win32 ignores
    /// `ES_PASSWORD` on a multiline `EDIT`, and §3.1d requires secret entry to be maskable.
    pub const FIELD_SINGLE: i32 = 30;
    /// Button size.
    pub const BUTTON_W: i32 = 124;
    /// Button height.
    pub const BUTTON_H: i32 = 34;
    /// Extra vertical space the caption and frame consume, so the CLIENT area fits the controls.
    pub const CHROME: i32 = 44;

    /// Outer width of the launcher BAR (dig_ecosystem#1839).
    ///
    /// Wider than the dialog because a DIG link is long — a store id alone is 64 hex characters — and a
    /// launcher whose field scrolls away from the start of what you pasted is one you cannot check.
    pub const BAR_WIDTH: i32 = 900;
    /// Height of the bar's field. Roughly half again the dialog's, which is what makes it read as a
    /// launcher rather than a small dialog with its title bar missing.
    pub const BAR_FIELD: i32 = 48;
    /// The bar field's text height. Deliberately large: this is the only text on the window that matters.
    pub const BAR_FONT_FIELD: i32 = 26;
    /// How far down the screen the bar's TOP sits, as a fraction of the screen height.
    ///
    /// A launcher belongs above the middle — dead centre puts it over whatever the user is reading, and
    /// every established launcher (Spotlight, PowerToys Run, Alfred) sits high for that reason.
    pub const BAR_TOP_DIVISOR: i32 = 4;
}

/// The reference DPI every value in [`layout`] is expressed at.
const BASE_DPI: u32 = 96;

/// [`layout`]'s design units scaled to one monitor's DPI. Every drawing call reads these, never `layout`.
///
/// `Copy` and tiny, so it is passed by value and the layout functions stay pure — which is what lets the
/// scaling itself be unit-tested at 96, 144 and 192 DPI without a display.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Metrics {
    dpi: u32,
    /// The factor every design unit was multiplied by, as a percentage. Carried so it can be asserted.
    scale_pct: i32,
    width: i32,
    margin: i32,
    line: i32,
    heading_line: i32,
    char_width: i32,
    field_single: i32,
    button_w: i32,
    button_h: i32,
    chrome: i32,
    font_body: i32,
    font_heading: i32,
    bar_width: i32,
    bar_field: i32,
    font_bar_field: i32,
}

impl Metrics {
    /// The reference display width the design units are drawn for.
    ///
    /// Not arbitrary: 1920 is the width at which a 660 px dialog occupies about a third of the screen, which
    /// is the proportion the layout was designed at.
    const REFERENCE_WIDTH: i32 = 1920;

    /// The most the RESOLUTION fallback alone may enlarge the layout.
    ///
    /// Bounds only the heuristic, never DPI: a real DPI of 250% must produce a 250% dialog, because every
    /// other window on that desktop is 250% and a capped one reads as the small thing among big ones. The
    /// fallback is capped because "the panel is wide" is a weaker signal than "the user set a scale", and an
    /// 8K panel should not get a 4x dialog on that basis alone.
    const MAX_SCALE_NUMERATOR: i32 = 2;

    /// Scale the design units for the display this window will appear on.
    ///
    /// # Why DPI alone is not enough
    ///
    /// DPI covers the case Windows knows about — a scaled display, where an aware process must scale itself
    /// or render at a fraction of its intended physical size. But a 3840x2400 panel run at **100%** reports
    /// 96 DPI, and there a 660 px dialog is genuinely tiny: about a sixth of the screen width. Windows says
    /// nothing is unusual, and DPI-only scaling would leave it exactly as small as before. That configuration
    /// is what "the GUI components appear too small" actually was (dig_ecosystem#1832).
    ///
    /// So the scale is the LARGER of the two signals — the monitor's DPI ratio, and the display's width
    /// against the reference the layout was drawn for. Taking the larger means neither configuration is
    /// missed, and a scaled 4K display (high DPI *and* wide) is not enlarged twice over.
    ///
    /// # Why one scalar, applied to everything
    ///
    /// `char_width` is the divisor the body-wrap estimate uses, and a `STATIC` control clips silently. If the
    /// font grew while that estimate did not, a bigger window would think more characters fit per line than
    /// really do and clip its own warning — the defect a screenshot caught once already. Deriving every
    /// metric from a single factor makes that class unrepresentable.
    fn for_display(dpi: u32, screen_width: i32) -> Self {
        // Both signals as a percentage, so the arithmetic stays in integers.
        let dpi_pct = (dpi.max(BASE_DPI) as i64 * 100) / BASE_DPI as i64;
        let width_pct = if screen_width > 0 {
            (screen_width as i64 * 100) / Self::REFERENCE_WIDTH as i64
        } else {
            100
        };
        // DPI is honoured EXACTLY and is NOT capped: on a 250% display every other application is 2.5x, and
        // a dialog capped at 2x is visibly smaller than the shell around it — which is the complaint, not the
        // fix. The cap belongs only on the resolution FALLBACK, which is a heuristic for the case Windows
        // does not describe (a high-resolution panel at 100%) and could otherwise enlarge without bound.
        let pct = dpi_pct
            .max(width_pct.min(Self::MAX_SCALE_NUMERATOR as i64 * 100))
            .max(100);

        let s = |v: i32| -> i32 { (((v as i64 * pct) + 50) / 100) as i32 };
        Self {
            dpi: dpi.max(BASE_DPI),
            scale_pct: pct as i32,
            width: s(layout::WIDTH),
            margin: s(layout::MARGIN),
            line: s(layout::LINE),
            heading_line: s(layout::HEADING_LINE),
            char_width: s(layout::CHAR_WIDTH).max(1),
            field_single: s(layout::FIELD_SINGLE),
            button_w: s(layout::BUTTON_W),
            button_h: s(layout::BUTTON_H),
            chrome: s(layout::CHROME),
            font_body: s(layout::FONT_BODY),
            font_heading: s(layout::FONT_HEADING),
            bar_width: s(layout::BAR_WIDTH),
            bar_field: s(layout::BAR_FIELD),
            font_bar_field: s(layout::BAR_FONT_FIELD),
        }
    }

    /// The DPI-only scale, for tests and for a caller with no display metrics.
    #[cfg(test)]
    fn for_dpi(dpi: u32) -> Self {
        Self::for_display(dpi, 0)
    }
}

/// What every control on this window is created against: its parent, the module, the font it wears, and
/// the scaled metrics it lays out in.
///
/// Grouped rather than passed as four positional arguments to each helper. Four identical arguments repeated
/// at every call site is where a transposition hides — and once the metrics joined them, the helpers crossed
/// clippy's argument-count threshold, which was the honest signal that they wanted a context rather than an
/// allow.
#[derive(Clone, Copy)]
struct ControlCtx {
    parent: HWND,
    instance: HINSTANCE,
    font: HFONT,
    m: Metrics,
}

/// The effective DPI of the monitor the window is about to appear on.
///
/// Taken from the monitor under the CURSOR rather than the primary display, because the user reached this
/// window by clicking the tray icon — the cursor is on the screen they are looking at, which on a
/// multi-monitor setup with mixed scaling is the only one whose DPI is correct for them.
///
/// Falls back to [`BASE_DPI`] if anything is unavailable (no cursor, no monitor, a session with no display),
/// which yields the 100% layout — undersized on a scaled display, but never zero-sized or off-screen.
///
/// # Safety
///
/// Calls documented Win32 entry points with valid out-params; every failure path falls back.
unsafe fn dpi_for_cursor_monitor() -> u32 {
    let mut pt = POINT::default();
    if GetCursorPos(&mut pt).is_err() {
        return BASE_DPI;
    }
    let monitor = MonitorFromPoint(pt, MONITOR_DEFAULTTONEAREST);
    if monitor.is_invalid() {
        return BASE_DPI;
    }
    let mut x: u32 = 0;
    let mut y: u32 = 0;
    match GetDpiForMonitor(monitor, MDT_EFFECTIVE_DPI, &mut x, &mut y) {
        // The horizontal value is the one Windows scales UI by; they are equal on every shipping display.
        Ok(()) if x > 0 => x,
        _ => BASE_DPI,
    }
}

/// What one DIG window draws, independent of what it is asking about.
///
/// # Why every window is described by ONE type
///
/// The typed-input window and the four consent windows differ in exactly two ways: whether there is a field,
/// and what the buttons say. Everything else — the heading, the body paragraph, the DPI-scaled metrics, the
/// type hierarchy, the message loop, the keyboard handling — is identical. Describing all five with one spec
/// means there is ONE layout path: dark mode, the DIG mark and text measurement get implemented once and
/// cannot drift between a "message window" and an "input window" (dig_ecosystem#1832).
struct WindowSpec<'a> {
    /// The caption bar text.
    title: &'a str,
    /// The primary line, drawn in the larger semibold face.
    heading: &'a str,
    /// The paragraph beneath it. `\n` is honoured; the block's height is derived from the text.
    body: &'a str,
    /// The typed field, or `None` for a window that only asks the user to choose.
    field: Option<FieldSpec<'a>>,
    /// What the buttons say and which one Enter activates.
    buttons: ButtonSpec<'a>,
    /// How the window is framed and placed. Six windows, one class, two presentations.
    chrome: Chrome,
}

/// The window's frame, placement and proportions — the ONLY axis on which the launcher bar differs from
/// the five dialogs.
///
/// Everything else about a bar is a dialog: the same class, the same field, the same message loop, the
/// same [`IsDialogMessageW`] keyboard handling, the same DPI scaling. Expressing the difference as a
/// two-variant enum read by [`Layout::compute`] keeps it that way — there is no second code path to drift.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Chrome {
    /// A titled, framed window centred on the display: the five consent/input dialogs.
    Dialog,
    /// A frameless bar floating high on the display, with an oversized field and no heading — the
    /// launcher (dig_ecosystem#1839).
    Bar,
}

impl Chrome {
    /// The window styles this presentation is created with.
    ///
    /// A bar is `WS_POPUP` — no caption, no system menu, no resize border — which is what "frameless"
    /// means in Win32 terms. `WS_BORDER` keeps a one-pixel edge so the bar reads as an object rather than
    /// bleeding into whatever is behind it.
    ///
    /// Pure and separate from the `CreateWindowExW` call so the property is unit-testable: a bar that
    /// silently regained a caption would otherwise be visible only in a screenshot.
    fn window_style(self) -> WINDOW_STYLE {
        match self {
            Self::Dialog => WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU,
            Self::Bar => WS_POPUP | WS_BORDER,
        }
    }

    /// The outer width of this presentation.
    fn width(self, m: Metrics) -> i32 {
        match self {
            Self::Dialog => m.width,
            Self::Bar => m.bar_width,
        }
    }

    /// Whether losing focus dismisses the window.
    ///
    /// TRUE for the bar and only the bar. A launcher the user has clicked away from has been abandoned,
    /// and an always-on-top frameless window with no close box that OUTLIVED that click would be one
    /// they cannot get rid of without answering it — the never-trap-the-user rule (§6.1), which the bar
    /// would otherwise break precisely because it has no frame to close.
    ///
    /// FALSE for the dialogs: a consent window that vanished when the user glanced at the transaction in
    /// their browser would be a consent window nobody can read.
    fn dismiss_on_blur(self) -> bool {
        matches!(self, Self::Bar)
    }
}

/// The typed field on a window that has one.
struct FieldSpec<'a> {
    /// The label above the field (`"DIG link:"`, `"Your 24 words:"`).
    label: &'a str,
    /// Whether characters are replaced by [`MASK_CHARACTER`]. Required for secret entry (`SPEC.md` §3.1d).
    masked: bool,
    /// Whether to offer the reveal-while-typing checkbox.
    revealable: bool,
}

/// The buttons a window offers.
///
/// This replaces the `MESSAGEBOX_STYLE` bit-fiddling that used to encode the same thing (`MB_OK` vs
/// `MB_OKCANCEL | MB_DEFBUTTON2`). Naming the buttons directly is what removes the workaround that shaped the
/// old windows: `MessageBoxW` could not relabel OK/Cancel, so a two-choice window had to spell its choice out
/// in a sentence — the retention claim explained in a paragraph what a button reading "Yes, I have them" says
/// by itself. The labels were always in the content; the message box just threw them away.
enum ButtonSpec<'a> {
    /// ONE dismiss button. Informational: nothing branches on the answer, so nothing is asked.
    Acknowledge {
        /// The dismiss label (`"OK"`).
        label: &'a str,
    },
    /// TWO labelled choices, because refusing genuinely changes what happens.
    Decide {
        /// The affirmative label — an imperative verb (`"Sign"`, `"Destroy"`) or a first-person claim
        /// (`"Yes, I have them"`).
        affirm: &'a str,
        /// The refusing label.
        refuse: &'a str,
        /// Whether REFUSING holds the focus, so a bare Enter refuses.
        ///
        /// The destroy window sets this: without it, a focused window would confirm irreversible key
        /// destruction on an accidental Enter (dig_ecosystem#1799).
        refusal_is_default: bool,
    },
}

/// What the user did, before it is interpreted as text or as consent.
enum Answer {
    /// The affirmative (or sole dismiss) button. `Some` carries the field's contents when there was a
    /// field and it could be read; `None` means either there was no field, or its text was unreadable —
    /// [`InputWindow::ask`] is what distinguishes those, because only it knows a field was asked for.
    Affirmed(Option<Zeroizing<String>>),
    /// Cancel, Escape, or the frame's close box. Nothing the caller may act on.
    Refused,
}

/// Per-window state, owned by the window for its lifetime and reached through `GWLP_USERDATA`.
///
/// Boxed and handed to `CreateWindowExW` rather than kept in a global, so two concurrent input windows
/// (a possibility the moment anything but the tray asks) cannot read each other's text.
struct WindowState {
    /// The `EDIT` control the user types into.
    edit: HWND,
    /// What the user submitted, moved out by [`InputWindow::ask`] after the loop ends.
    submitted: Option<Zeroizing<String>>,
    /// Whether Submit (rather than Cancel or the frame's close box) ended the window.
    accepted: bool,
    /// Whether losing the foreground dismisses this window — see [`Chrome::dismiss_on_blur`].
    dismiss_on_blur: bool,
}

/// A [`ForegroundInput`] that draws the Win32 window with a typed field.
pub(super) struct InputWindow;

impl ForegroundInput for InputWindow {
    fn ask(&self, content: &InputContent) -> InputOutcome {
        let result = show(&spec_for_input(content));
        if let Err(e) = &result {
            tracing::warn!(error = %e, "the native input window could not be shown");
        }
        input_outcome_from(result)
    }
}

/// Map a field window's result to the caller's outcome.
///
/// Pure and separate from [`InputWindow::ask`] so the FAIL-CLOSED property is unit-testable. It is the
/// distinction that matters here, and it is easy to lose: "the user declined" and "the window never appeared"
/// are different facts, and only the first is an answer. A caller that renders a cancel as *nothing happened*
/// would silently swallow a broken prompt if the two collapsed — which is precisely the regression that
/// reaching this module's error path as a refusal introduced, and that this function exists to pin.
fn input_outcome_from(result: Result<Answer, windows::core::Error>) -> InputOutcome {
    match result {
        Ok(Answer::Affirmed(Some(text))) => InputOutcome::Provided(text),
        // Submit with an unreadable field is not an empty answer — the caller must not act on it.
        Ok(Answer::Affirmed(None)) => InputOutcome::Unavailable,
        Ok(Answer::Refused) => InputOutcome::Cancelled,
        // Never asked, so never answered. Callers MUST fail closed rather than read a phantom empty string.
        Err(_) => InputOutcome::Unavailable,
    }
}

/// A [`ForegroundWindow`] that draws the same window WITHOUT a field, for the consent prompts.
///
/// This replaced `MessageBoxW` (dig_ecosystem#1832). The message box could not relabel its buttons, so every
/// two-choice window carried a sentence explaining which button meant what; here the labels come straight from
/// the content, which already held them for macOS and Linux.
pub(super) struct DialogWindow;

impl ForegroundWindow for DialogWindow {
    fn show(&self, content: &ConfirmContent) -> WindowIntent {
        let result = show(&spec_for_confirm(content));
        if let Err(e) = &result {
            tracing::warn!(error = %e, "the native confirm window could not be shown");
        }
        intent_from(result)
    }
}

/// Map a consent window's result to the user's intent. Only an affirmative approves; everything else — a
/// refusal, a closed frame, a window that could not be drawn at all — denies.
fn intent_from(result: Result<Answer, windows::core::Error>) -> WindowIntent {
    match result {
        Ok(Answer::Affirmed(_)) => WindowIntent::Approve,
        _ => WindowIntent::Deny,
    }
}

/// The window an [`InputContent`] draws.
///
/// Pure and separate from [`InputWindow::ask`] so the MAPPING is unit-testable. This is the seam where a
/// field's mask could be silently dropped — `masked` travelling from the content to the field is what
/// `SPEC.md` §3.1d actually requires, and a window cannot be constructed in a test process to check it any
/// other way.
fn spec_for_input(content: &InputContent) -> WindowSpec<'_> {
    WindowSpec {
        title: &content.title,
        heading: &content.heading,
        body: &content.body,
        field: Some(FieldSpec {
            label: &content.field_label,
            masked: content.masked,
            revealable: content.revealable,
        }),
        // A field window's affirmative is its own submit verb; refusing to type is a plain Cancel.
        buttons: ButtonSpec::Decide {
            affirm: content.submit,
            refuse: "Cancel",
            refusal_is_default: false,
        },
        chrome: match content.style {
            InputStyle::Dialog => Chrome::Dialog,
            InputStyle::Bar => Chrome::Bar,
        },
    }
}

/// The window a [`ConfirmContent`] draws.
///
/// Pure and separate from [`DialogWindow::show`] for the same reason, and it carries more weight: this is
/// where dig_ecosystem#1773 (a notice gets ONE button, not a Cancel nobody reads) and dig_ecosystem#1799 (a
/// destroy pre-selects its refusal) are decided. Both defects were originally invisible to every test and
/// visible only in a screenshot; expressing them as a value a test can read is what makes them checkable.
fn spec_for_confirm(content: &ConfirmContent) -> WindowSpec<'_> {
    let buttons = match &content.presentation {
        Presentation::Acknowledge => ButtonSpec::Acknowledge {
            label: content.action,
        },
        Presentation::Decide { refusal_is_default } => ButtonSpec::Decide {
            affirm: content.action,
            refuse: refusal_label(content.action),
            refusal_is_default: *refusal_is_default,
        },
    };
    WindowSpec {
        title: &content.title,
        heading: &content.heading,
        body: &content.body,
        field: None,
        buttons,
        // A consent window is never a launcher: it must keep its frame, its title and its place on the
        // screen, and it must NOT evaporate when the user looks at something else.
        chrome: Chrome::Dialog,
    }
}

/// What the refusing button says, given the affirmative label.
///
/// Plain "Cancel" is right for an authorization the user just asked for — refusing costs a retry, and the
/// word is unambiguous. It is WRONG for a destroy: next to a button reading "Destroy", "Cancel" names the
/// dialog rather than the outcome, and the outcome is what a person hesitating over an irreversible action is
/// looking for. So that one window says what keeping the account is.
fn refusal_label(affirm: &str) -> &'static str {
    match affirm {
        "Destroy" => "Keep my account",
        _ => "Cancel",
    }
}

/// Register the window class exactly once per process, returning whether it is available.
///
/// `RegisterClassW` returns 0 on failure; a second registration of the same name also fails, which is
/// why this is behind a [`OnceLock`] rather than called per window.
fn class_registered() -> bool {
    static REGISTERED: OnceLock<bool> = OnceLock::new();
    *REGISTERED.get_or_init(|| {
        // SAFETY: `GetModuleHandleW(None)` yields this process's own module handle, and the class struct
        // borrows only the 'static class name and a system cursor. `RegisterClassW` copies what it needs.
        unsafe {
            let instance: HINSTANCE = match GetModuleHandleW(None) {
                Ok(module) => module.into(),
                Err(_) => return false,
            };
            let class = WNDCLASSW {
                lpfnWndProc: Some(wnd_proc),
                hInstance: instance,
                lpszClassName: CLASS_NAME,
                hCursor: LoadCursorW(None, IDC_ARROW).unwrap_or_default(),
                // The window's face must be the system WINDOW colour, which is also what a `STATIC`
                // control paints behind its text. Without this the class has no background brush, the
                // frame is left unpainted, and every label reads as a grey box floating on it — visible
                // in the first screenshot of this window.
                hbrBackground: HBRUSH(COLOR_WINDOW.0 as isize as *mut _),
                ..Default::default()
            };
            RegisterClassW(&class) != 0
        }
    })
}

/// The window class, as a `Result` rather than a `bool`.
///
/// # Why this is not `if !class_registered() { ... }`
///
/// A class that will not register means the window was never drawn and the user was never asked — which is
/// NOT the same as them declining. While unifying these windows (dig_ecosystem#1832) that early return was
/// briefly written as a refusal, which reaches `InputOutcome::Cancelled`: a caller that renders a cancel as
/// *the user chose not to, show nothing* would then silently swallow a completely broken prompt.
///
/// Returning a `Result` and using `?` at the call site makes that mistake **unexpressible** rather than merely
/// tested against. A test cannot reach this branch — `RegisterClassW` succeeds in a test process, so the
/// failure is not forceable in-process — so the protection has to be structural: `?` on a `Result<(), _>`
/// cannot produce an `Answer`, and both callers already route every `Err` to their fail-closed outcome.
fn require_class() -> Result<(), windows::core::Error> {
    match class_registered() {
        true => Ok(()),
        false => Err(windows::core::Error::new(
            E_FAIL,
            "the DIG window class could not be registered",
        )),
    }
}

/// Create the window, pump its messages until the user answers, and report what they chose.
fn show(spec: &WindowSpec<'_>) -> Result<Answer, windows::core::Error> {
    require_class()?;
    // SAFETY: every call below is a documented Win32 entry point given valid handles; the boxed state is
    // adopted by the window on WM_NCCREATE and dropped exactly once, at the end of this function, after
    // the message loop has returned and the window has been destroyed.
    unsafe {
        let instance: HINSTANCE = GetModuleHandleW(None)?.into();
        // Scale to the display the user is actually looking at, BEFORE anything is sized (#1832).
        let m = Metrics::for_display(dpi_for_cursor_monitor(), GetSystemMetrics(SM_CXSCREEN));
        let font = gui_font(m.font_body, FW_NORMAL.0 as i32);
        let heading_font = gui_font(m.font_heading, FW_SEMIBOLD.0 as i32);
        // ONE walk of the layout: the drawing code below and the window's own height both read this, so a
        // control can never be placed outside the frame that was sized for it.
        let l = Layout::compute(spec, m);
        let height = l.total_height;
        let (x, y) = placed(spec.chrome, l.width, height);
        // The field wears its own face, which the bar enlarges; on a dialog it is the body font's size, so
        // this is the same face it always had.
        let field_font = gui_font(l.field_font, FW_NORMAL.0 as i32);

        let mut state = Box::new(WindowState {
            edit: HWND::default(),
            submitted: None,
            accepted: false,
            dismiss_on_blur: spec.chrome.dismiss_on_blur(),
        });
        let state_ptr: *mut WindowState = &mut *state;

        let window = CreateWindowExW(
            window_ex_style(),
            CLASS_NAME,
            &HSTRING::from(spec.title),
            spec.chrome.window_style(),
            x,
            y,
            l.width,
            height,
            HWND::default(),
            HMENU::default(),
            instance,
            Some(state_ptr.cast()),
        )?;

        // Two contexts over the same window: the heading wears the larger semibold face, everything else the
        // body face. Nothing else differs between them.
        let ctx = ControlCtx {
            parent: window,
            instance,
            font,
            m,
        };
        let heading_ctx = ControlCtx {
            font: heading_font,
            ..ctx
        };

        let inner = l.inner;
        if l.has_heading {
            add_static(
                &heading_ctx,
                spec.heading,
                l.heading_top,
                inner,
                m.heading_line,
            );
        }
        add_static(&ctx, spec.body, l.body_top, inner, l.body_height);

        if let Some(field) = &spec.field {
            if let Some(label_top) = l.field_label_top {
                add_static(&ctx, field.label, label_top, inner, m.line);
            }

            let edit = CreateWindowExW(
                WINDOW_EX_STYLE(0),
                windows::core::w!("EDIT"),
                PCWSTR::null(),
                edit_style(field),
                m.margin,
                l.field_top.unwrap_or(l.buttons_top),
                inner,
                l.field_height,
                window,
                HMENU::default(),
                instance,
                None,
            )?;
            set_font(edit, field_font);
            (*state_ptr).edit = edit;

            // §3.1d's reveal-while-typing affordance: masked by default, un-maskable on purpose. Without it
            // a person typing 24 words into a masked field cannot check their own work, which is how a
            // restore fails for a reason nobody can see.
            if let Some(reveal_top) = l.reveal_top {
                add_checkbox(
                    &ctx,
                    "Show the words while I type",
                    REVEAL_ID,
                    reveal_top,
                    inner,
                );
            }
        }
        let top = l.buttons_top;

        // Both windows right-align to the SAME edge — the text block's — so a notice's lone button sits
        // exactly where a decision's affirmative does. Derived once rather than per-arm: two arms computing
        // the same edge from different expressions is an alignment that drifts the first time one is edited.
        match &spec.buttons {
            ButtonSpec::Acknowledge { label } => {
                let w = button_width(label, m);
                add_button(
                    &ctx,
                    label,
                    IDOK.0,
                    affirm_button_left(w, m, inner),
                    top,
                    w,
                    BS_DEFPUSHBUTTON as u32,
                );
            }
            ButtonSpec::Decide {
                affirm,
                refuse,
                refusal_is_default,
            } => {
                // Refuse sits LEFT of affirm so the affirmative is never under the cursor's resting
                // position, and `refusal_is_default` decides which one a bare Enter activates.
                let (refuse_style, affirm_style) = match refusal_is_default {
                    true => (BS_DEFPUSHBUTTON, BS_PUSHBUTTON),
                    false => (BS_PUSHBUTTON, BS_DEFPUSHBUTTON),
                };
                let (affirm_w, refuse_w) = (button_width(affirm, m), button_width(refuse, m));
                let affirm_left = affirm_button_left(affirm_w, m, inner);
                add_button(
                    &ctx,
                    refuse,
                    IDCANCEL.0,
                    affirm_left - refuse_w - m.margin,
                    top,
                    refuse_w,
                    refuse_style as u32,
                );
                add_button(
                    &ctx,
                    affirm,
                    IDOK.0,
                    affirm_left,
                    top,
                    affirm_w,
                    affirm_style as u32,
                );
            }
        }

        let _ = ShowWindow(window, SW_SHOW);
        let _ = SetForegroundWindow(window);
        // Focus the field when there is one; otherwise let the default button hold it, so Enter and Space
        // both do what the window's default says — including refusing, on a destroy.
        focus_first(window, (*state_ptr).edit, &spec.buttons);

        pump(window);

        // The window is gone by now (WM_DESTROY ran), so the state is ours again.
        let _ = DeleteObject(font);
        let _ = DeleteObject(heading_font);
        let _ = DeleteObject(field_font);
        let answer = match state.accepted {
            true => Answer::Affirmed(state.submitted.take()),
            false => Answer::Refused,
        };
        Ok(answer)
    }
}

/// Give the keyboard to the field, or — when there is none — to whichever button the spec made default.
///
/// A window with no field that focuses nothing would leave Enter doing nothing at all, and Space landing
/// wherever Windows happened to put the focus. On the destroy window that difference is the whole point of
/// `refusal_is_default`, so the focus has to follow it.
///
/// # Safety
///
/// `window` must be live; `edit` is either a live `EDIT` control or the default (absent) handle.
unsafe fn focus_first(window: HWND, edit: HWND, buttons: &ButtonSpec<'_>) {
    if !edit.is_invalid() {
        let _ = SetFocus(edit);
        return;
    }
    let default_id = match buttons {
        ButtonSpec::Decide {
            refusal_is_default: true,
            ..
        } => IDCANCEL.0,
        _ => IDOK.0,
    };
    if let Ok(button) = GetDlgItem(window, default_id) {
        let _ = SetFocus(button);
    }
}

/// Where every control goes, and how tall the window must be to hold them.
///
/// # Why this exists
///
/// `window_height` and the drawing code used to walk the same vertical sequence SEPARATELY, and they
/// disagreed: the height reserved five margins because that suited the window WITH a field, while a fieldless
/// window consumed three — so every notice, claim and destroy shipped with a visible slab of dead space under
/// its buttons. That was invisible to the tests (the height was "big enough", which is all they asked) and
/// obvious the moment the windows were photographed.
///
/// One walk, used by both, is the fix: a position and the total height cannot disagree when they come from the
/// same arithmetic. Pure, so the whole layout is unit-testable without a display.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Layout {
    /// Top of the heading line.
    heading_top: i32,
    /// Top of the body block, and how tall it is.
    body_top: i32,
    body_height: i32,
    /// Top of the field's label, the field itself, and the reveal checkbox — `None` on a fieldless window.
    field_label_top: Option<i32>,
    field_top: Option<i32>,
    reveal_top: Option<i32>,
    /// Top of the button row.
    buttons_top: i32,
    /// The OUTER window height, caption and frame included.
    total_height: i32,
    /// The OUTER window width.
    width: i32,
    /// Width of the controls that span the window.
    inner: i32,
    /// Height of the input field, which the bar enlarges.
    field_height: i32,
    /// Text height of the input field's font, likewise.
    field_font: i32,
    /// Whether the heading line is drawn at all. The bar has no heading — a launcher that explained
    /// itself in a headline every time would be a dialog wearing a launcher's frame.
    has_heading: bool,
}

impl Layout {
    /// Walk `spec`'s controls top to bottom at `m`'s scale.
    fn compute(spec: &WindowSpec<'_>, m: Metrics) -> Self {
        match spec.chrome {
            Chrome::Dialog => Self::dialog(spec, m),
            Chrome::Bar => Self::bar(m),
        }
    }

    /// The launcher bar: field first and large, one hint line under it, then the buttons.
    ///
    /// Inverted from the dialog on purpose. A dialog explains and then asks; a launcher asks
    /// immediately, and anything it has to say sits UNDER the field where it does not stand between the
    /// user and the thing they pressed a shortcut to reach.
    ///
    /// The buttons stay. They are what makes Enter and Esc work: [`IsDialogMessageW`] maps Enter to the
    /// window's default push button, so a bar with no buttons would depend on the undefaulted fallback
    /// path instead of the same tested one every other DIG window uses — and a visible `Open` button also
    /// tells a first-time user what Enter is going to do.
    fn bar(m: Metrics) -> Self {
        let gap = m.margin / 2;
        let width = Chrome::Bar.width(m);
        let inner = width - m.margin * 2;

        let field_top = m.margin;
        let mut top = field_top + m.bar_field + gap;
        let body_top = top;
        let body_height = m.line;
        top += body_height + gap;

        let buttons_top = top;
        Self {
            // No heading is drawn, so its position is the field's — nothing reads it.
            heading_top: field_top,
            body_top,
            body_height,
            field_label_top: None,
            field_top: Some(field_top),
            // A URN is not a secret, so there is nothing to reveal.
            reveal_top: None,
            buttons_top,
            // No caption and no frame to account for: `WS_POPUP` client area IS the window.
            total_height: buttons_top + m.button_h + m.margin,
            width,
            inner,
            field_height: m.bar_field,
            field_font: m.font_bar_field,
            has_heading: false,
        }
    }

    /// The titled dialog: heading, body, optional field, buttons.
    fn dialog(spec: &WindowSpec<'_>, m: Metrics) -> Self {
        let gap = m.margin / 2;
        let inner = m.width - m.margin * 4;

        let heading_top = m.margin;
        let body_top = heading_top + m.heading_line + gap;
        let body_height = body_lines(spec.body, inner, m) * m.line;
        let mut top = body_top + body_height + gap;

        let (mut field_label_top, mut field_top, mut reveal_top) = (None, None, None);
        if let Some(field) = &spec.field {
            field_label_top = Some(top);
            top += m.line;
            field_top = Some(top);
            top += m.field_single + gap;
            if field.revealable {
                reveal_top = Some(top);
                top += m.line + gap;
            }
        }

        let buttons_top = top;
        // The client area ends a full margin below the buttons; the caption and frame sit outside it.
        let total_height = buttons_top + m.button_h + m.margin + m.chrome;

        Self {
            heading_top,
            body_top,
            body_height,
            field_label_top,
            field_top,
            reveal_top,
            buttons_top,
            total_height,
            width: Chrome::Dialog.width(m),
            inner,
            field_height: m.field_single,
            field_font: m.font_body,
            has_heading: true,
        }
    }
}

/// How tall the body paragraph's `STATIC` control must be to show all of `body`.
///
/// A `STATIC` control neither scrolls nor reports that it truncated — it just clips, silently. The first
/// build of this window fixed the body at 84 px and cut the Sage warning off mid-sentence, which only a
/// screenshot revealed. So the height is derived from the text: explicit newlines are counted, and each
/// paragraph is divided by how many characters fit on a line.
///
/// Pure, so the estimate is unit-tested against the real copy this window actually shows.
fn body_lines(body: &str, width: i32, m: Metrics) -> i32 {
    let per_line = ((width / m.char_width).max(1)) as usize;
    let wrapped: usize = body
        .split('\n')
        .map(|line| line.chars().count().div_ceil(per_line).max(1))
        .sum();
    (wrapped as i32).clamp(layout::BODY_MIN_LINES, layout::BODY_MAX_LINES)
}

/// The style bits for the input field.
///
/// **Always single-line.** Win32 silently IGNORES `ES_PASSWORD` on a multiline `EDIT`, so a field that can
/// be masked cannot be multiline — and `SPEC.md` §3.1d requires secret entry to be masked by default. The
/// field therefore scrolls horizontally, and the reveal checkbox ([`REVEAL_ID`]) is what makes 24 words
/// checkable rather than typed blind.
fn edit_style(field: &FieldSpec<'_>) -> WINDOW_STYLE {
    let mut style = WS_CHILD | WS_VISIBLE | WS_BORDER | WS_TABSTOP;
    style |= WINDOW_STYLE(ES_AUTOHSCROLL as u32);
    if field.masked {
        style |= WINDOW_STYLE(ES_PASSWORD as u32);
    }
    style
}

/// Where to place a `width`×`height` window of this presentation on the primary display.
///
/// Pure arithmetic behind one metrics call, so the placement is unit-tested; falls back to
/// `CW_USEDEFAULT` when the metrics are unreadable (a session with no display), which lets Windows place
/// it rather than putting it off-screen.
fn placed(chrome: Chrome, width: i32, height: i32) -> (i32, i32) {
    // SAFETY: `GetSystemMetrics` reads a global integer and cannot fail in a way that matters; a 0 result
    // means "unknown", handled below.
    let (screen_w, screen_h) =
        unsafe { (GetSystemMetrics(SM_CXSCREEN), GetSystemMetrics(SM_CYSCREEN)) };
    placed_in(chrome, width, height, screen_w, screen_h)
}

/// The placement arithmetic, separated from the metrics call so it is testable.
///
/// A dialog is centred both ways. A bar is centred horizontally and sits HIGH — one
/// [`layout::BAR_TOP_DIVISOR`] of the screen down — because a launcher dead-centre covers the thing the
/// user was looking at when they pressed the shortcut, and every established launcher sits high for that
/// reason.
fn placed_in(chrome: Chrome, width: i32, height: i32, screen_w: i32, screen_h: i32) -> (i32, i32) {
    if screen_w <= width || screen_h <= height {
        return (CW_USEDEFAULT, CW_USEDEFAULT);
    }
    let x = (screen_w - width) / 2;
    let y = match chrome {
        Chrome::Dialog => (screen_h - height) / 2,
        // Clamped to the centre line so a very tall bar on a very short screen still fits on it.
        Chrome::Bar => (screen_h / layout::BAR_TOP_DIVISOR).min((screen_h - height) / 2),
    };
    (x, y)
}

/// How wide a button must be to wear `label` without cramping it.
///
/// The buttons were a FIXED width, which was fine while every label was "OK" or "Cancel" and wrong the moment
/// they carried real words: "Keep my account" and "Yes, I have them" rendered with their text touching both
/// borders — legible, but visibly squeezed, and one longer label away from clipping.
///
/// Uses the same per-character estimate the body wrap does, deliberately: one estimate is reviewable, two
/// different ones drift. Both are replaced together when the window moves to real `DT_CALCRECT` measurement.
/// `BUTTON_W` becomes the MINIMUM rather than the size, so short labels keep the comfortable target they had.
fn button_width(label: &str, m: Metrics) -> i32 {
    let text = label.chars().count() as i32 * m.char_width;
    // A margin of padding each side: enough that a descender or an italic never meets the border.
    (text + m.margin * 2).max(m.button_w)
}

/// The left edge of the AFFIRMATIVE button — the rightmost control on every window.
///
/// It is flush with the right edge of the text block above it (`margin + inner`), so the buttons line up
/// with the heading, body and field rather than overhanging them. `inner` comes from the [`Layout`] rather
/// than being recomputed here, because the bar and the dialog span different widths and two expressions for
/// one edge is an alignment that drifts the first time either is edited.
/// A notice's single button and a decision's affirmative both sit here, which is what makes the two window
/// kinds read as one design.
fn affirm_button_left(affirm_width: i32, m: Metrics, inner: i32) -> i32 {
    let text_block_right = m.margin + inner;
    text_block_right - affirm_width
}

/// The extended style every DIG window carries.
///
/// **Topmost is load-bearing, not cosmetic.** A consent window the triggering browser or the tray can sit on
/// top of is a consent window the user never answers — and worse, one an attacker can cover while the user
/// clicks where they think a different button is. The `MessageBoxW` this window replaced got the same property
/// from `MB_TOPMOST | MB_SETFOREGROUND | MB_SYSTEMMODAL`; here it is `WS_EX_TOPMOST` plus the
/// `SetForegroundWindow` call in [`show`].
///
/// A function rather than a literal at the call site so the property is unit-testable — the equivalent
/// assertion existed for the message box and would otherwise have been lost with it (dig_ecosystem#1832).
fn window_ex_style() -> WINDOW_EX_STYLE {
    WS_EX_TOPMOST
}

/// The window's message loop, ending when the window posts a quit.
///
/// [`IsDialogMessageW`] runs FIRST so the window behaves like a dialog even though it is not one: Tab and
/// Shift+Tab move between the field and the buttons, Esc posts `IDCANCEL`, and Enter activates the default
/// button. Without it the window would be mouse-only, which fails the keyboard-accessibility baseline.
///
/// # Safety
///
/// `window` must be a live window created by [`show`].
unsafe fn pump(window: HWND) {
    let mut message = MSG::default();
    while GetMessageW(&mut message, HWND::default(), 0, 0).as_bool() {
        if IsDialogMessageW(window, &message).as_bool() {
            continue;
        }
        let _ = TranslateMessage(&message);
        DispatchMessageW(&message);
    }
}

/// The window procedure.
///
/// # Safety
///
/// Called by Windows with a valid `window` for this class. `WM_NCCREATE` adopts the boxed [`WindowState`]
/// the creator passed through `CREATESTRUCTW::lpCreateParams`; every later message reads it back through
/// `GWLP_USERDATA`, and the creator — not this procedure — owns the box, so nothing here frees it.
unsafe extern "system" fn wnd_proc(
    window: HWND,
    message: u32,
    wparam: WPARAM,
    lparam: LPARAM,
) -> LRESULT {
    match message {
        WM_NCCREATE => {
            let create = lparam.0 as *const CREATESTRUCTW;
            if !create.is_null() {
                SetWindowLongPtrW(window, GWLP_USERDATA, (*create).lpCreateParams as isize);
            }
            DefWindowProcW(window, message, wparam, lparam)
        }
        WM_COMMAND => {
            // The low word of wParam is the control id for a button click.
            let id = (wparam.0 & 0xFFFF) as i32;
            if id == IDOK.0 {
                if let Some(state) = state_of(window) {
                    state.accepted = true;
                    // A window with no field leaves `submitted` as `None`; only a FIELD window's caller
                    // treats that as unreadable, which is why the distinction lives in `InputWindow::ask`.
                    if !state.edit.is_invalid() {
                        state.submitted = read_edit(state.edit);
                        // Overwrite the control's OWN copy of the secret before the window goes away, so the
                        // phrase does not sit in an `EDIT` buffer until the heap happens to be reused.
                        let _ = SetWindowTextW(state.edit, windows::core::w!(""));
                    }
                }
                let _ = DestroyWindow(window);
                LRESULT(0)
            } else if id == REVEAL_ID {
                if let Some(state) = state_of(window) {
                    toggle_mask(state.edit, wparam.0 as isize, lparam.0);
                }
                LRESULT(0)
            } else if id == IDCANCEL.0 {
                let _ = DestroyWindow(window);
                LRESULT(0)
            } else {
                DefWindowProcW(window, message, wparam, lparam)
            }
        }
        // A launcher the user has clicked away from has been abandoned. The bar has no close box, so
        // without this it would be an always-on-top frameless window with no way out but answering it —
        // the never-trap-the-user rule (§6.1). Gated on the window's own flag so a CONSENT dialog, which
        // the user may legitimately look away from to read a transaction, is never dismissed for them.
        WM_ACTIVATE if wparam.0 as u32 & 0xFFFF == WA_INACTIVE => {
            let dismiss = state_of(window).is_some_and(|state| state.dismiss_on_blur);
            if dismiss {
                // `accepted` stays false, so nothing typed is acted on — this is a cancel, not a submit.
                let _ = DestroyWindow(window);
                return LRESULT(0);
            }
            DefWindowProcW(window, message, wparam, lparam)
        }
        WM_CLOSE => {
            // Closing by the frame is a cancel: `accepted` stays false, so no text is acted on.
            let _ = DestroyWindow(window);
            LRESULT(0)
        }
        WM_DESTROY => {
            PostQuitMessage(0);
            LRESULT(0)
        }
        _ => DefWindowProcW(window, message, wparam, lparam),
    }
}

/// Control id of the reveal-while-typing checkbox. Above `IDOK`/`IDCANCEL` so it cannot collide with the
/// standard dialog ids `IsDialogMessageW` posts for Enter and Esc.
const REVEAL_ID: i32 = 100;

/// The character a masked field shows in place of each typed one. `●` reads as a deliberate mask at the
/// window's font size, where the classic `*` reads as a typo.
const MASK_CHARACTER: u16 = 0x25CF;

/// Show or hide the field's characters, following the checkbox.
///
/// Repainting is REQUIRED after `EM_SETPASSWORDCHAR`: the control does not redraw already-typed text on its
/// own, so without the invalidate the setting appears to do nothing until the user types another character.
///
/// # Safety
///
/// `edit` must be a live `EDIT` control, and `lparam` the checkbox handle `WM_COMMAND` supplied.
unsafe fn toggle_mask(edit: HWND, _wparam: isize, lparam: isize) {
    let checkbox = HWND(lparam as *mut _);
    let checked =
        SendMessageW(checkbox, BM_GETCHECK, WPARAM(0), LPARAM(0)).0 == BST_CHECKED.0 as isize;
    let mask = match checked {
        true => 0,
        false => MASK_CHARACTER as usize,
    };
    SendMessageW(edit, EM_SETPASSWORDCHAR, WPARAM(mask), LPARAM(0));
    let _ = InvalidateRect(edit, None, true);
}

/// Add the reveal-while-typing checkbox.
///
/// # Safety
///
/// `parent` must be a live window.
unsafe fn add_checkbox(ctx: &ControlCtx, text: &str, id: i32, top: i32, width: i32) {
    let (parent, instance, font, m) = (ctx.parent, ctx.instance, ctx.font, ctx.m);
    let created = CreateWindowExW(
        WINDOW_EX_STYLE(0),
        windows::core::w!("BUTTON"),
        &HSTRING::from(text),
        WS_CHILD | WS_VISIBLE | WS_TABSTOP | WINDOW_STYLE(BS_AUTOCHECKBOX as u32),
        m.margin,
        top,
        width,
        m.line,
        parent,
        HMENU(id as isize as *mut _),
        instance,
        None,
    );
    match created {
        Ok(control) => set_font(control, font),
        // Losing the checkbox leaves a masked field with no way to check it — usable, but worse, so it is
        // logged rather than passed over.
        Err(e) => tracing::warn!(error = %e, "the reveal checkbox could not be created"),
    }
}

/// The window's state, or `None` before `WM_NCCREATE` has stored it.
///
/// # Safety
///
/// The pointer is the one [`show`] passed to `CreateWindowExW`, and the box it points at outlives every
/// message this window receives (it is dropped only after [`pump`] returns).
unsafe fn state_of(window: HWND) -> Option<&'static mut WindowState> {
    let raw = GetWindowLongPtrW(window, GWLP_USERDATA) as *mut WindowState;
    raw.as_mut()
}

/// Read the `EDIT` control's text into a zeroizing buffer, or `None` if it could not be read.
///
/// # Safety
///
/// `edit` must be a live `EDIT` control.
unsafe fn read_edit(edit: HWND) -> Option<Zeroizing<String>> {
    if edit.is_invalid() {
        return None;
    }
    let length = GetWindowTextLengthW(edit);
    if length <= 0 {
        // An empty field is not a failure to read — it is an empty answer, which the journey rejects with
        // a "that is not 24 words" message rather than treating as a cancel.
        return Some(Zeroizing::new(String::new()));
    }
    // +1 for the terminating NUL `GetWindowTextW` writes.
    let mut buffer: Zeroizing<Vec<u16>> = Zeroizing::new(vec![0u16; length as usize + 1]);
    let copied = GetWindowTextW(edit, &mut buffer);
    if copied <= 0 {
        return None;
    }
    Some(Zeroizing::new(String::from_utf16_lossy(
        &buffer[..copied as usize],
    )))
}

/// The UI font every control uses — Segoe UI at the shell's normal size.
///
/// Windows gives a freshly-created control the ancient bitmap system font unless told otherwise, which is
/// what makes a hand-built window look like it escaped from 1995 (§6.1: a surface a user reads as broken
/// is not done). The caller deletes the handle after the window closes.
///
/// # Safety
///
/// `CreateFontW` allocates a GDI object; the returned handle must be passed to `DeleteObject`.
unsafe fn gui_font(height: i32, weight: i32) -> HFONT {
    CreateFontW(
        // Negative height = character height, already DPI-scaled by the caller.
        -height,
        0,
        0,
        0,
        weight,
        0,
        0,
        0,
        ANSI_CHARSET.0 as u32,
        OUT_TT_PRECIS.0 as u32,
        0,
        CLEARTYPE_QUALITY.0 as u32,
        (DEFAULT_PITCH.0 | FF_DONTCARE.0) as u32,
        windows::core::w!("Segoe UI"),
    )
}

/// Apply `font` to `control`.
///
/// # Safety
///
/// `control` must be a live window and `font` a valid GDI font handle.
unsafe fn set_font(control: HWND, font: HFONT) {
    SendMessageW(control, WM_SETFONT, WPARAM(font.0 as usize), LPARAM(1));
}

/// Add a read-only text label. Static controls are the ONE place read-only text belongs — unlike a
/// disabled menu item, a `STATIC` control is what the platform means by "a label".
///
/// # Safety
///
/// `parent` must be a live window.
unsafe fn add_static(ctx: &ControlCtx, text: &str, top: i32, width: i32, height: i32) {
    let (parent, instance, font, m) = (ctx.parent, ctx.instance, ctx.font, ctx.m);
    let created = CreateWindowExW(
        WINDOW_EX_STYLE(0),
        windows::core::w!("STATIC"),
        &HSTRING::from(text),
        WS_CHILD | WS_VISIBLE,
        m.margin,
        top,
        width,
        height,
        parent,
        HMENU::default(),
        instance,
        None,
    );
    // A missing label costs the window a line of guidance, never the window itself — the field and its
    // buttons are what the user must have.
    match created {
        Ok(control) => set_font(control, font),
        Err(e) => tracing::warn!(error = %e, "an input-window label could not be created"),
    }
}

/// Add a push button carrying control id `id`.
///
/// # Safety
///
/// `parent` must be a live window.
#[allow(clippy::too_many_arguments)]
unsafe fn add_button(
    ctx: &ControlCtx,
    text: &str,
    id: i32,
    left: i32,
    top: i32,
    width: i32,
    button_style: u32,
) {
    let (parent, instance, font, m) = (ctx.parent, ctx.instance, ctx.font, ctx.m);
    let created = CreateWindowExW(
        WINDOW_EX_STYLE(0),
        windows::core::w!("BUTTON"),
        &HSTRING::from(text),
        WS_CHILD | WS_VISIBLE | WS_TABSTOP | WS_GROUP | WINDOW_STYLE(button_style),
        left,
        top,
        width,
        m.button_h,
        parent,
        HMENU(id as isize as *mut _),
        instance,
        None,
    );
    match created {
        Ok(control) => set_font(control, font),
        // Losing a button IS fatal to the window's usability, so it is logged loudly; the frame's close
        // box still cancels, so the user is not trapped.
        Err(e) => {
            tracing::error!(error = %e, button = text, "an input-window button could not be created")
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// **`SPEC.md` §3.1d.** A field asked to be masked MUST be masked, and one asked NOT to be must not be.
    ///
    /// Both directions, because a rule tested one way cannot tell "masked when asked" from "always masked" —
    /// and blanket masking would silently mask a non-secret field while blanket echoing would put a
    /// passphrase on the screen. The mask default is the SPEC's, not this window's preference.
    #[test]
    fn the_field_is_masked_exactly_when_the_prompt_asks() {
        assert_ne!(
            edit_style(field_spec(true, true).field.as_ref().unwrap()).0 & ES_PASSWORD as u32,
            0,
            "secret entry is masked by default (§3.1d)"
        );
        assert_eq!(
            edit_style(field_spec(false, false).field.as_ref().unwrap()).0 & ES_PASSWORD as u32,
            0,
            "a field that asked for no mask must not get one"
        );
    }

    /// The reveal checkbox costs the window a row ONLY when it is offered — the arithmetic that keeps a
    /// passphrase window from carrying a blank strip where a control it does not have would go.
    #[test]
    fn the_reveal_control_takes_space_only_when_it_is_offered() {
        let m = Metrics::for_dpi(BASE_DPI);
        assert!(Layout::compute(&field_spec(true, true), m)
            .reveal_top
            .is_some());
        assert!(Layout::compute(&field_spec(true, false), m)
            .reveal_top
            .is_none());
        assert!(
            Layout::compute(&field_spec(true, true), m).total_height
                > Layout::compute(&field_spec(true, false), m).total_height,
            "the window must grow to fit the checkbox"
        );
    }

    /// **The whole point of one window serving both roles.** A window with NO field must reserve no room for
    /// one — no label line, no field, no checkbox — so a notice is not a phrase window with a hole in it.
    ///
    /// Paired with the test above: together they pin that the field block is present exactly when a field is,
    /// which neither assertion could establish alone.
    #[test]
    fn a_window_with_no_field_reserves_no_room_for_one() {
        let m = Metrics::for_dpi(BASE_DPI);
        let message = message_spec(
            "Something happened.",
            ButtonSpec::Acknowledge { label: "OK" },
        );

        let l = Layout::compute(&message, m);
        assert!(l.field_label_top.is_none());
        assert!(l.field_top.is_none());
        assert!(l.reveal_top.is_none());
        assert!(
            l.total_height < Layout::compute(&field_spec(false, false), m).total_height,
            "a fieldless window must be shorter than the same window with a field"
        );
    }

    /// The reveal checkbox's control id must not collide with the standard dialog ids, or Enter and Escape —
    /// which `IsDialogMessageW` posts as `IDOK`/`IDCANCEL` — would toggle the mask instead of submitting or
    /// cancelling.
    #[test]
    fn the_reveal_control_id_cannot_collide_with_the_dialog_ids() {
        assert_ne!(REVEAL_ID, IDOK.0);
        assert_ne!(REVEAL_ID, IDCANCEL.0);
    }

    /// Every field, masked or not, must be reachable by keyboard — a window a keyboard user cannot enter is
    /// not accessible (§6.6). Both variants, so neither can lose the tab stop.
    #[test]
    fn every_field_is_a_tab_stop() {
        for masked in [true, false] {
            assert_ne!(
                edit_style(field_spec(masked, masked).field.as_ref().unwrap()).0 & WS_TABSTOP.0,
                0,
                "masked={masked}"
            );
        }
    }

    /// The window centres itself on a normal display, and defers to Windows when it would not fit — an
    /// off-screen input window is an input window the user never answers.
    #[test]
    fn the_window_centres_itself_and_defers_when_it_would_not_fit() {
        assert_eq!(placed_in(Chrome::Dialog, 600, 400, 1920, 1080), (660, 340));

        // A display smaller than the window (or unreadable metrics reported as 0) must not produce a
        // negative origin, which would put the title bar above the top of the screen.
        assert_eq!(
            placed_in(Chrome::Dialog, 600, 400, 0, 0),
            (CW_USEDEFAULT, CW_USEDEFAULT)
        );
        assert_eq!(
            placed_in(Chrome::Dialog, 600, 400, 640, 360),
            (CW_USEDEFAULT, CW_USEDEFAULT),
            "a display shorter than the window must not be centred into a negative Y"
        );
    }

    /// **Regression, found by screenshot.** A `STATIC` control clips silently, and the first build reserved
    /// a fixed 84 px for the body — which cut the Sage warning off mid-sentence on the ONE window where that
    /// warning is the difference between restoring an account and silently creating a different empty one.
    ///
    /// The fixture is the REAL body copy `ask_for_phrase` shows, not a synthetic string, because its actual
    /// length is what made this a defect. Asserted against the old fixed height, so an implementation that
    /// went back to a constant fails here.
    #[test]
    fn the_body_grows_to_fit_the_real_phrase_window_copy() {
        const REAL_BODY: &str = "Type or paste all 24 words in order, separated by spaces. Capitals \
             do not matter.\n\nUse the words DIG gave you. A recovery phrase from a Chia wallet such \
             as Sage is NOT a DIG recovery phrase — DIG would accept it and build a DIFFERENT, empty \
             account from it.";
        let spec = WindowSpec {
            body: REAL_BODY,
            ..field_spec(false, true)
        };

        let m = Metrics::for_dpi(BASE_DPI);
        const OLD_FIXED_HEIGHT: i32 = 84;
        assert!(
            Layout::compute(&spec, m).body_height > OLD_FIXED_HEIGHT,
            "the real copy does not fit the height that clipped it: {}",
            Layout::compute(&spec, m).body_height
        );
        // And every line of it must be accounted for: the estimate is per-character, so this is the check
        // that the arithmetic reaches the last sentence rather than merely being "bigger".
        let usable = m.width - m.margin * 4;
        let needed = REAL_BODY.chars().count() as i32 / (usable / m.char_width);
        assert!(
            body_lines(REAL_BODY, usable, m) >= needed,
            "the estimate must cover the whole paragraph"
        );
    }

    /// **The control.** A SHORT body must not reserve the tall block — otherwise "grows to fit" would be
    /// satisfied by a function that always returned the maximum, and every window would carry a slab of
    /// empty space. Both ends of the clamp are pinned here.
    #[test]
    fn a_short_body_stays_compact_and_a_huge_one_is_bounded() {
        let m = Metrics::for_dpi(BASE_DPI);
        let short = WindowSpec {
            body: "One line.",
            ..field_spec(false, false)
        };
        assert_eq!(
            Layout::compute(&short, m).body_height,
            layout::BODY_MIN_LINES * m.line,
            "a one-line body must not reserve the tall block"
        );

        let long_body = "word ".repeat(2000);
        let huge = WindowSpec {
            body: &long_body,
            ..field_spec(false, false)
        };
        assert_eq!(
            Layout::compute(&huge, m).body_height,
            layout::BODY_MAX_LINES * m.line,
            "the window must stay on a small display"
        );
    }

    /// Every metric scales with the monitor's DPI — the #1832 fix.
    ///
    /// This process is DPI-AWARE (tao sets per-monitor awareness for the tray), so Windows does not scale
    /// these windows for us. A layout that ignored DPI rendered at a fraction of its physical size on a
    /// scaled display, which is what "the GUI components appear too small" was.
    #[test]
    fn every_metric_scales_with_the_monitors_dpi() {
        let at96 = Metrics::for_dpi(96);
        let at192 = Metrics::for_dpi(192);
        for (name, lo, hi) in [
            ("width", at96.width, at192.width),
            ("margin", at96.margin, at192.margin),
            ("line", at96.line, at192.line),
            ("heading_line", at96.heading_line, at192.heading_line),
            ("char_width", at96.char_width, at192.char_width),
            ("field_single", at96.field_single, at192.field_single),
            ("button_w", at96.button_w, at192.button_w),
            ("button_h", at96.button_h, at192.button_h),
            ("chrome", at96.chrome, at192.chrome),
            ("font_body", at96.font_body, at192.font_body),
            ("font_heading", at96.font_heading, at192.font_heading),
        ] {
            assert_eq!(hi, lo * 2, "{name} must double from 96 to 192 DPI");
        }
    }

    /// ...and the whole window scales, not just the parts — the sum has to grow too, or a scaled window
    /// would clip its own controls.
    #[test]
    fn the_window_grows_with_dpi_for_the_same_content() {
        let c = field_spec(false, true);
        let h96 = Layout::compute(&c, Metrics::for_dpi(96)).total_height;
        let h150 = Layout::compute(&c, Metrics::for_dpi(144)).total_height;
        let h200 = Layout::compute(&c, Metrics::for_dpi(192)).total_height;
        assert!(h150 > h96, "150% must be taller than 100%: {h150} vs {h96}");
        assert!(
            h200 > h150,
            "200% must be taller than 150%: {h200} vs {h150}"
        );
    }

    /// The clip protection must survive scaling. `char_width` is the divisor the wrap estimate uses, so it
    /// scales with the font; if it did not, a high-DPI window would think more characters fit per line than
    /// really do and clip the tail — reintroducing the defect a screenshot caught once already.
    #[test]
    fn the_body_reserves_the_same_number_of_lines_at_every_scale() {
        const BODY: &str = "A sentence long enough to wrap more than once in the body block of this                             window, so the line count is a real measurement rather than the clamp floor.";
        let lines_at = |dpi: u32| {
            let m = Metrics::for_dpi(dpi);
            body_lines(BODY, m.width - m.margin * 4, m)
        };
        assert_eq!(
            lines_at(96),
            lines_at(192),
            "the same text must reserve the same LINE COUNT at any scale — only their pixel height changes"
        );
    }

    /// A HIGH-RESOLUTION display at 100% must still enlarge the window — the case DPI cannot see.
    ///
    /// This is the configuration that produced the complaint: 3840x2400 at 100% scaling reports 96 DPI, so a
    /// DPI-only layout stays at its reference size and occupies about a sixth of the screen. Windows reports
    /// nothing unusual, which is exactly why the width has to be consulted as well.
    #[test]
    fn a_high_resolution_display_at_100_percent_still_scales_up() {
        let unaware = Metrics::for_display(96, 1920);
        let panel_4k_at_100 = Metrics::for_display(96, 3840);
        assert_eq!(
            unaware.scale_pct, 100,
            "the reference display is the baseline"
        );
        assert_eq!(
            panel_4k_at_100.scale_pct, 200,
            "a 4K panel at 96 DPI must still be scaled — DPI alone reports nothing here"
        );
        assert!(panel_4k_at_100.width > unaware.width);
        assert!(panel_4k_at_100.font_body > unaware.font_body);
    }

    /// The two signals are the LARGER of, not the product — a scaled 4K display is high-DPI *and* wide, and
    /// multiplying them would enlarge it twice over into something absurd.
    #[test]
    fn dpi_and_resolution_do_not_compound() {
        let scaled_4k = Metrics::for_display(192, 3840);
        assert_eq!(
            scaled_4k.scale_pct, 200,
            "200% DPI on a 4K panel is 2x, never 4x"
        );
        assert_eq!(
            scaled_4k.width,
            Metrics::for_display(192, 1920).width,
            "whichever signal is larger wins; they do not stack"
        );
    }

    /// The RESOLUTION fallback is capped; DPI is not.
    ///
    /// The distinction matters and an earlier version of this got it wrong: capping DPI at 2x on this
    /// machine's 250% display produced a dialog visibly smaller than every other window on the desktop —
    /// the very complaint the change was meant to fix. A user-set scale is an instruction; a wide panel is
    /// only a hint.
    #[test]
    fn dpi_is_honoured_exactly_while_the_resolution_fallback_is_capped() {
        // A real 400% display gets a 400% dialog.
        assert_eq!(Metrics::for_display(384, 1920).scale_pct, 400);
        // An enormous panel at 100% gets the capped fallback, not 800%.
        assert_eq!(Metrics::for_display(96, 15360).scale_pct, 200);
        // This machine: 3840x2400 at 250%.
        assert_eq!(Metrics::for_display(240, 3840).scale_pct, 250);
    }

    /// A nonsense DPI must not shrink the window below the reference layout.
    #[test]
    fn a_dpi_below_the_reference_is_clamped_up() {
        assert_eq!(Metrics::for_dpi(0), Metrics::for_dpi(BASE_DPI));
        assert_eq!(Metrics::for_dpi(48), Metrics::for_dpi(BASE_DPI));
    }

    /// Explicit newlines must each cost a line: the body is two paragraphs separated by a blank line, and an
    /// estimate that only divided by the character count would lose both breaks and clip the tail.
    #[test]
    fn explicit_line_breaks_are_counted_not_just_wrapped_characters() {
        let m = Metrics::for_dpi(BASE_DPI);
        let usable = m.width - m.margin * 4;
        let one_paragraph = body_lines("short", usable, m);
        let three_lines = body_lines("short\n\nshort", usable, m);
        assert!(
            three_lines > one_paragraph,
            "blank lines take vertical space too: {three_lines} vs {one_paragraph}"
        );
    }

    fn content(masked: bool, revealable: bool) -> InputContent {
        InputContent {
            title: "DIG — Restore".to_string(),
            heading: "Type your 24-word recovery phrase.".to_string(),
            body: "Words in order, separated by spaces.".to_string(),
            field_label: "Your 24 words:".to_string(),
            submit: "Restore",
            masked,
            revealable,
            style: InputStyle::Dialog,
        }
    }

    // ──────────────── The presentation guarantees, carried over from the MessageBoxW window ────────────────
    //
    // These previously asserted on `MESSAGEBOX_STYLE` bits in `windows.rs`. That window is gone
    // (dig_ecosystem#1832), so the guarantees are re-pinned here on `ButtonSpec` — the value that replaced the
    // bits. Asserting on named buttons is STRONGER than asserting on flags: `MB_OKCANCEL` said only "two
    // buttons", while these say two buttons WITH THESE WORDS and THIS default.

    /// **Regression.** A window that could NOT BE DRAWN must not be reported as the user declining.
    ///
    /// Introduced while unifying the windows (dig_ecosystem#1832): the class-registration failure path started
    /// returning a refusal, which reaches `InputOutcome::Cancelled`. That is a different fact from
    /// `Unavailable` — a caller that treats a cancel as *the user chose not to, show nothing* would silently
    /// swallow a completely broken prompt. `Unavailable`'s own contract says callers MUST fail closed and never
    /// read it as an empty answer, so the two cannot be merged.
    ///
    /// Caught by review rather than by a test. Note what this test does and does not cover: it pins the
    /// MAPPING, not the call site where the mistake was actually made. That branch is unreachable from a test
    /// (`RegisterClassW` succeeds in a test process), so the call site is protected structurally instead —
    /// [`require_class`] returns a `Result` and `show` uses `?`, so "cannot draw" can no longer be spelled as
    /// an `Answer` at all. This test guards the other half: that an `Err`, however it arrives, stays
    /// fail-closed.
    #[test]
    fn a_window_that_could_not_be_drawn_is_unavailable_not_cancelled() {
        let failed = || Err(windows::core::Error::new(E_FAIL, "no window"));

        assert!(
            matches!(input_outcome_from(failed()), InputOutcome::Unavailable),
            "a window that never appeared was never answered"
        );
        // The control: a REAL cancel is still a cancel. Without this pair, mapping everything to
        // `Unavailable` would satisfy the assertion above while destroying the ordinary path.
        assert!(matches!(
            input_outcome_from(Ok(Answer::Refused)),
            InputOutcome::Cancelled
        ));
        assert!(matches!(
            input_outcome_from(Ok(Answer::Affirmed(Some(Zeroizing::new("x".to_string()))))),
            InputOutcome::Provided(_)
        ));
        // Submit with a field that could not be read is NOT an empty answer.
        assert!(matches!(
            input_outcome_from(Ok(Answer::Affirmed(None))),
            InputOutcome::Unavailable
        ));
    }

    /// The same property on the consent path: every non-affirmative, including an undrawable window, DENIES.
    #[test]
    fn a_consent_window_denies_unless_it_was_affirmed() {
        assert_eq!(
            intent_from(Err(windows::core::Error::new(E_FAIL, "no window"))),
            WindowIntent::Deny,
            "a consent window that never appeared cannot have consented"
        );
        assert_eq!(intent_from(Ok(Answer::Refused)), WindowIntent::Deny);
        assert_eq!(
            intent_from(Ok(Answer::Affirmed(None))),
            WindowIntent::Approve,
            "a fieldless window affirms with no text, which is not a failure"
        );
    }

    /// Every window's buttons align with its text block, and a notice's lone button sits exactly where a
    /// decision's affirmative does — so the two kinds are visibly one design rather than two dialogs.
    ///
    /// The real labels are used, not synthetic ones: a fixed-width button was legible with "OK" and visibly
    /// squeezed with "Keep my account", so a test on short labels would have passed through the defect.
    ///
    /// Pinned at several scales because the alignment is arithmetic over scaled metrics: a rounding change
    /// that broke it at 150% only would otherwise be invisible.
    #[test]
    fn the_buttons_align_with_the_text_block_at_every_scale() {
        for dpi in [96, 144, 192, 240] {
            let m = Metrics::for_dpi(dpi);
            let inner = Layout::compute(&field_spec(false, false), m).inner;
            let text_block_right = m.margin + inner;

            // Whatever the label, the affirmative's right edge meets the text block's.
            for label in ["OK", "Destroy", "Yes, I have them"] {
                let w = button_width(label, m);
                assert_eq!(
                    affirm_button_left(w, m, inner) + w,
                    text_block_right,
                    "'{label}' must right-align to the text block at {dpi} DPI"
                );
            }
            // ...and the widest real pair must still fit side by side inside the frame.
            let (affirm_w, refuse_w) = (
                button_width("Yes, I have them", m),
                button_width("Keep my account", m),
            );
            assert!(
                affirm_button_left(affirm_w, m, inner) - refuse_w - m.margin > m.margin,
                "two long-labelled buttons must fit beside each other at {dpi} DPI"
            );
        }
    }

    /// **Carried over from the message box.** EVERY window — notice or decision, with a field or without —
    /// must be forced above the windows that triggered it.
    ///
    /// The message-box version of this test asserted `MB_TOPMOST | MB_SETFOREGROUND | MB_SYSTEMMODAL`. Losing
    /// it silently with that window is exactly how a security property decays into a comment.
    #[test]
    fn every_window_is_topmost() {
        assert_ne!(
            window_ex_style().0 & WS_EX_TOPMOST.0,
            0,
            "a consent window the browser can cover is not a consent window"
        );
    }

    /// **Regression (#1773).** An informational window must not offer a Cancel that nothing reads. "Your DIG
    /// ID is on the clipboard" is not a question.
    #[test]
    fn a_notice_gets_exactly_one_button() {
        let content = ConfirmContent::notice(&crate::confirm::NoticePrompt {
            title: "DIG — DIG ID copied",
            heading: "Your DIG ID is on the clipboard.",
            body: "abc123",
            acknowledge: "OK",
        });
        let spec = spec_for_confirm(&content);

        assert!(
            matches!(spec.buttons, ButtonSpec::Acknowledge { label: "OK" }),
            "a notice has nothing to cancel, so it gets one dismiss button and no refusal"
        );
        assert!(spec.field.is_none(), "a notice asks for nothing typed");
    }

    /// **The control that makes the test above load-bearing.** A GENUINE either/or still gets two buttons.
    /// Without this pair, flattening every window to a single OK — destroying the reveal gate's and the
    /// retention claim's real way out — would pass just as happily.
    #[test]
    fn an_authorization_keeps_both_buttons() {
        let content = ConfirmContent::reveal(&crate::confirm::RevealPrompt {
            secret: "your recovery phrase",
        });
        let spec = spec_for_confirm(&content);

        assert!(
            matches!(
                spec.buttons,
                ButtonSpec::Decide {
                    affirm: "Reveal",
                    refuse: "Cancel",
                    refusal_is_default: false,
                }
            ),
            "declining a reveal must stay possible, on a button that says so"
        );
    }

    /// **Regression (#1799).** A destroy window must pre-select its REFUSAL, so a bare Enter on a focused
    /// window cannot confirm irreversible key destruction.
    ///
    /// It also checks the label, which the message-box window could not have: next to a button reading
    /// "Destroy", a way out labelled "Cancel" names the dialog rather than the outcome.
    #[test]
    fn a_destroy_window_pre_selects_its_refusal_and_names_it() {
        let content = ConfirmContent::destroy(&crate::confirm::DestroyPrompt {
            subject: "the DIG Account on this computer",
            replacement: "",
            recoverable: false,
        });
        let spec = spec_for_confirm(&content);

        match spec.buttons {
            ButtonSpec::Decide {
                affirm,
                refuse,
                refusal_is_default,
            } => {
                assert!(
                    refusal_is_default,
                    "Enter on a destroy window must not destroy an account"
                );
                assert_eq!(affirm, "Destroy");
                assert_eq!(
                    refuse, "Keep my account",
                    "the way out must name the outcome, not the dialog"
                );
            }
            ButtonSpec::Acknowledge { .. } => panic!("a destroy must keep a real way out"),
        }
    }

    /// **The control for #1799.** An ORDINARY authorization keeps its AFFIRMATIVE as the default: the user
    /// just asked for the action, and making every signature need a deliberate extra click would be its own
    /// defect. Without this pair, defaulting EVERY window to its refusal would satisfy the test above.
    #[test]
    fn an_ordinary_authorization_keeps_its_affirmative_as_the_default() {
        for content in [
            ConfirmContent::reveal(&crate::confirm::RevealPrompt {
                secret: "your recovery phrase",
            }),
            ConfirmContent::notice(&crate::confirm::NoticePrompt {
                title: "t",
                heading: "h",
                body: "b",
                acknowledge: "OK",
            }),
        ] {
            let refuses_by_default = matches!(
                spec_for_confirm(&content).buttons,
                ButtonSpec::Decide {
                    refusal_is_default: true,
                    ..
                }
            );
            assert!(
                !refuses_by_default,
                "only a destroy pre-selects its refusal: {}",
                content.title
            );
        }
    }

    /// **Regression (#1752), at the window seam.** A CLAIM's first-person label reaches the BUTTON verbatim.
    ///
    /// This is what replaced the choice sentence the message box needed. The old defect — *"Choose OK to I
    /// have written these down"* — is now structurally impossible, because there is no sentence to slot a
    /// label into; this pins that the label arrives unaltered.
    #[test]
    fn a_claim_puts_its_own_words_on_the_button() {
        let content = ConfirmContent::claim(&crate::confirm::ClaimPrompt {
            title: "DIG — Confirm you saved it",
            heading: "Do you have your 24 words written down?",
            body: "...",
            affirm: "Yes, I have them",
        });
        let spec = spec_for_confirm(&content);

        assert!(matches!(
            spec.buttons,
            ButtonSpec::Decide {
                affirm: "Yes, I have them",
                ..
            }
        ));
    }

    /// **`SPEC.md` §3.1d at the mapping seam.** The content's mask and reveal flags must REACH the field.
    ///
    /// `content` is the `InputContent` the tray actually builds, so this covers the one step the layout tests
    /// cannot: a mapping that dropped `masked` would put a recovery phrase on screen while every
    /// `edit_style` test still passed, because those test the field they are handed.
    #[test]
    fn the_input_mapping_carries_the_mask_and_reveal_flags_to_the_field() {
        for (masked, revealable) in [(true, true), (true, false), (false, true), (false, false)] {
            let c = content(masked, revealable);
            let spec = spec_for_input(&c);
            let field = spec
                .field
                .as_ref()
                .expect("an input window always has a field");

            assert_eq!(field.masked, masked, "masked={masked}");
            assert_eq!(field.revealable, revealable, "revealable={revealable}");
            assert_eq!(field.label, "Your 24 words:");
        }
        let c = content(true, true);
        assert!(matches!(
            spec_for_input(&c).buttons,
            ButtonSpec::Decide {
                affirm: "Restore",
                ..
            }
        ));
    }

    /// A field window's spec, the shape `InputWindow::ask` builds.
    fn field_spec(masked: bool, revealable: bool) -> WindowSpec<'static> {
        WindowSpec {
            title: "DIG — Restore",
            heading: "Type your 24-word recovery phrase.",
            body: "Words in order, separated by spaces.",
            field: Some(FieldSpec {
                label: "Your 24 words:",
                masked,
                revealable,
            }),
            buttons: ButtonSpec::Decide {
                affirm: "Restore",
                refuse: "Cancel",
                refusal_is_default: false,
            },
            chrome: Chrome::Dialog,
        }
    }

    /// The launcher bar's spec — the same field window, presented as a bar (dig_ecosystem#1839).
    ///
    /// Deliberately IDENTICAL to [`field_spec`] except for `chrome`, so every comparison below varies one
    /// thing. A bar fixture that also changed its copy or its buttons could not tell a presentation
    /// difference from a content difference.
    fn bar_spec() -> WindowSpec<'static> {
        WindowSpec {
            chrome: Chrome::Bar,
            ..field_spec(false, false)
        }
    }

    // ──────────────── The launcher bar (dig_ecosystem#1839) ────────────────

    /// The bar is FRAMELESS and the dialogs are not. Both arms asserted: a `window_style` that returned
    /// the popup style for everything would satisfy the bar half alone.
    #[test]
    fn the_bar_is_frameless_and_the_dialogs_keep_their_frame() {
        let bar = Chrome::Bar.window_style().0;
        assert_ne!(bar & WS_POPUP.0, 0, "the bar must be a popup");
        // `WS_CAPTION` is `WS_BORDER | WS_DLGFRAME`, and the bar deliberately KEEPS `WS_BORDER` for its
        // one-pixel edge — so the caption is only absent if the FULL mask is not set, not if the AND is
        // non-zero. Asserting the mask is what makes this test see a caption rather than a border.
        assert_ne!(
            bar & WS_CAPTION.0,
            WS_CAPTION.0,
            "the bar must have no caption"
        );
        assert_eq!(bar & WS_SYSMENU.0, 0, "the bar must have no system menu");

        let dialog = Chrome::Dialog.window_style().0;
        assert_eq!(dialog & WS_POPUP.0, 0);
        assert_eq!(dialog & WS_CAPTION.0, WS_CAPTION.0);
        assert_ne!(dialog & WS_SYSMENU.0, 0);
    }

    /// The bar sits HIGH; a dialog sits centred. Compared on the SAME size and the SAME screen, so the
    /// only thing that can move the window is the presentation — the nearest wrong implementation
    /// (centring both) is what this distinguishes.
    #[test]
    fn the_bar_sits_high_and_the_dialog_sits_centred() {
        let (w, h, screen_w, screen_h) = (900, 200, 1920, 1080);
        let (bar_x, bar_y) = placed_in(Chrome::Bar, w, h, screen_w, screen_h);
        let (dialog_x, dialog_y) = placed_in(Chrome::Dialog, w, h, screen_w, screen_h);

        // Horizontally identical — a launcher is centred left-to-right like anything else.
        assert_eq!(bar_x, dialog_x);
        assert_eq!(bar_y, screen_h / layout::BAR_TOP_DIVISOR);
        assert!(
            bar_y < dialog_y,
            "the bar must sit above the centre line: {bar_y} vs {dialog_y}"
        );

        // A bar taller than half a short screen must not be pushed BELOW the centre by the divisor.
        let (_, squeezed_y) = placed_in(Chrome::Bar, 600, 500, 1024, 768);
        assert!(squeezed_y <= (768 - 500) / 2);
        assert!(squeezed_y >= 0);
    }

    /// **The never-trap-the-user rule (§6.1), and the one property that must NOT generalise.**
    ///
    /// The bar has no close box, so losing focus has to dismiss it or it is a window with no way out. A
    /// CONSENT dialog must never inherit that: a user who glances at their browser to check the
    /// transaction they are approving would come back to a window that answered itself.
    #[test]
    fn only_the_bar_dismisses_itself_on_losing_focus() {
        assert!(Chrome::Bar.dismiss_on_blur());
        assert!(!Chrome::Dialog.dismiss_on_blur());
    }

    /// The bar is a LAUNCHER: no heading, no field label, no reveal control, and a field that fills it.
    ///
    /// Asserted against the dialog computed from the same spec, so each claim is a difference rather than
    /// a restatement of whatever the bar arm happens to return.
    #[test]
    fn the_bar_drops_the_dialogs_furniture_and_enlarges_its_field() {
        for dpi in [96, 144, 192, 240] {
            let m = Metrics::for_dpi(dpi);
            let bar = Layout::compute(&bar_spec(), m);
            let dialog = Layout::compute(&field_spec(false, true), m);

            assert!(!bar.has_heading, "a launcher explains nothing at {dpi} DPI");
            assert!(dialog.has_heading);
            assert_eq!(bar.field_label_top, None);
            assert_eq!(bar.reveal_top, None, "a DIG link is not a secret to reveal");

            assert!(
                bar.field_height > dialog.field_height,
                "the bar's field must be larger at {dpi} DPI"
            );
            assert!(
                bar.field_font > dialog.field_font,
                "the bar's type must be larger at {dpi} DPI"
            );
            assert!(
                bar.width > dialog.width && bar.inner > dialog.inner,
                "a 64-hex store id plus a 64-hex root needs the wider field at {dpi} DPI"
            );
        }
    }

    /// **The defect this file was reorganised to prevent, extended to the bar.** Every control must sit
    /// inside the window that was sized for it.
    ///
    /// The bar is where this could newly break: it is a DIFFERENT width from the dialog, so anything that
    /// still measured against the dialog's `Metrics::width` — as the button alignment did before it took
    /// the layout's `inner` — would place the buttons outside the bar entirely.
    #[test]
    fn every_control_fits_inside_the_window_it_was_sized_for() {
        for dpi in [96, 144, 192, 240] {
            let m = Metrics::for_dpi(dpi);
            for (name, spec) in [("bar", bar_spec()), ("dialog", field_spec(false, true))] {
                let l = Layout::compute(&spec, m);
                let field_bottom = l.field_top.unwrap() + l.field_height;
                assert!(
                    field_bottom <= l.buttons_top,
                    "{name}: the field overlaps the buttons at {dpi} DPI"
                );
                assert!(
                    l.buttons_top + m.button_h + m.margin <= l.total_height,
                    "{name}: the buttons fall outside the frame at {dpi} DPI"
                );
                // The affirmative's right edge, which is the rightmost pixel of any control.
                let w = button_width("Open", m);
                let right = affirm_button_left(w, m, l.inner) + w;
                assert!(
                    right <= l.width - m.margin,
                    "{name}: the buttons overhang the window at {dpi} DPI ({right} of {})",
                    l.width
                );
            }
        }
    }

    /// The style the CALLER asked for is the chrome the window gets — and a consent window can never
    /// become a bar.
    ///
    /// That second half is the load-bearing one. `Chrome::Bar` carries dismiss-on-blur, so a consent
    /// window drawn as a bar would silently deny itself the moment the user looked away — and it is the
    /// kind of thing a future refactor could plausibly "simplify" into one shared mapping.
    #[test]
    fn the_requested_style_reaches_the_window_and_consent_is_never_a_bar() {
        let mut c = content(false, false);
        c.style = InputStyle::Bar;
        assert_eq!(spec_for_input(&c).chrome, Chrome::Bar);
        c.style = InputStyle::Dialog;
        assert_eq!(spec_for_input(&c).chrome, Chrome::Dialog);

        for confirm in [
            ConfirmContent::notice(&crate::confirm::NoticePrompt {
                title: "DIG",
                heading: "Done.",
                body: "It worked.",
                acknowledge: "OK",
            }),
            ConfirmContent::destroy(&crate::confirm::DestroyPrompt {
                subject: "the DIG Account on this computer",
                replacement: "A new one will be created.",
                recoverable: true,
            }),
        ] {
            assert_eq!(spec_for_confirm(&confirm).chrome, Chrome::Dialog);
        }
    }

    /// A window with no field, the shape `DialogWindow::show` builds. `body` is borrowed so a test can
    /// measure how the block grows with real copy.
    fn message_spec<'a>(body: &'a str, buttons: ButtonSpec<'a>) -> WindowSpec<'a> {
        WindowSpec {
            title: "DIG — Notice",
            heading: "Something happened.",
            body,
            field: None,
            buttons,
            chrome: Chrome::Dialog,
        }
    }
}
