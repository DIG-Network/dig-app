//! The Windows native **input** window (dig_ecosystem#1798): a real Win32 window with an `EDIT` control.
//!
//! # Why this exists at all
//!
//! Every other DIG window on Windows is a `MessageBoxW`, which cannot take typed input — it has no
//! control to type into and no API to add one. That single API limitation is why the tray shipped
//! *"Restore from a recovery phrase (in a terminal)…"* and handed the user a command to run. A tray menu
//! having no text field is a fact about the tray API, not a reason to make a person open a console, so
//! this module builds the window `MessageBoxW` cannot: a registered window class with a heading, a body,
//! a label, an `EDIT` control, and Submit / Cancel buttons.
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
use windows::Win32::Foundation::{HINSTANCE, HWND, LPARAM, LRESULT, POINT, WPARAM};
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
    CreateWindowExW, DefWindowProcW, DestroyWindow, DispatchMessageW, GetCursorPos, GetMessageW,
    GetSystemMetrics, GetWindowLongPtrW, GetWindowTextLengthW, GetWindowTextW, IsDialogMessageW,
    LoadCursorW, PostQuitMessage, RegisterClassW, SendMessageW, SetForegroundWindow,
    SetWindowLongPtrW, SetWindowTextW, ShowWindow, TranslateMessage, BM_GETCHECK, BS_AUTOCHECKBOX,
    BS_DEFPUSHBUTTON, BS_PUSHBUTTON, CREATESTRUCTW, CW_USEDEFAULT, ES_AUTOHSCROLL, ES_PASSWORD,
    GWLP_USERDATA, HMENU, IDCANCEL, IDC_ARROW, IDOK, MSG, SM_CXSCREEN, SM_CYSCREEN, SW_SHOW,
    WINDOW_EX_STYLE, WINDOW_STYLE, WM_CLOSE, WM_COMMAND, WM_DESTROY, WM_NCCREATE, WM_SETFONT,
    WNDCLASSW, WS_BORDER, WS_CAPTION, WS_CHILD, WS_EX_TOPMOST, WS_GROUP, WS_OVERLAPPED, WS_SYSMENU,
    WS_TABSTOP, WS_VISIBLE,
};
use zeroize::Zeroizing;

use super::{ForegroundInput, InputContent, InputOutcome};

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
}

/// A [`ForegroundInput`] that draws the Win32 input window.
pub(super) struct InputWindow;

impl ForegroundInput for InputWindow {
    fn ask(&self, content: &InputContent) -> InputOutcome {
        match show(content) {
            Ok(outcome) => outcome,
            Err(e) => {
                // A window that could not be created means the user was never asked, which callers MUST
                // treat as fail-closed rather than as an empty answer.
                tracing::warn!(error = %e, "the native input window could not be shown");
                InputOutcome::Unavailable
            }
        }
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

/// Create the window, pump its messages until the user answers, and report what they typed.
fn show(content: &InputContent) -> Result<InputOutcome, windows::core::Error> {
    if !class_registered() {
        return Ok(InputOutcome::Unavailable);
    }
    // SAFETY: every call below is a documented Win32 entry point given valid handles; the boxed state is
    // adopted by the window on WM_NCCREATE and dropped exactly once, at the end of this function, after
    // the message loop has returned and the window has been destroyed.
    unsafe {
        let instance: HINSTANCE = GetModuleHandleW(None)?.into();
        // Scale to the display the user is actually looking at, BEFORE anything is sized (#1832).
        let m = Metrics::for_display(dpi_for_cursor_monitor(), GetSystemMetrics(SM_CXSCREEN));
        let font = gui_font(m.font_body, FW_NORMAL.0 as i32);
        let heading_font = gui_font(m.font_heading, FW_SEMIBOLD.0 as i32);
        let field_height = field_height(content, m);
        let body = body_height(content, m);
        let height = window_height(content, m);
        let (x, y) = centred(m.width, height);

        let mut state = Box::new(WindowState {
            edit: HWND::default(),
            submitted: None,
            accepted: false,
        });
        let state_ptr: *mut WindowState = &mut *state;

        let window = CreateWindowExW(
            // Topmost, because an input window the browser or the tray can hide is an input window the
            // user never answers.
            WS_EX_TOPMOST,
            CLASS_NAME,
            &HSTRING::from(content.title.as_str()),
            WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU | WINDOW_STYLE(0),
            x,
            y,
            m.width,
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

        let mut top = m.margin;
        let inner = m.width - m.margin * 4;
        add_static(&heading_ctx, &content.heading, top, inner, m.heading_line);
        top += m.heading_line + m.margin / 2;
        add_static(&ctx, &content.body, top, inner, body);
        top += body + m.margin / 2;
        add_static(&ctx, &content.field_label, top, inner, m.line);
        top += m.line;

        let edit = CreateWindowExW(
            WINDOW_EX_STYLE(0),
            windows::core::w!("EDIT"),
            PCWSTR::null(),
            edit_style(content),
            m.margin,
            top,
            inner,
            field_height,
            window,
            HMENU::default(),
            instance,
            None,
        )?;
        set_font(edit, font);
        (*state_ptr).edit = edit;
        top += field_height + m.margin / 2;

        // §3.1d's reveal-while-typing affordance: masked by default, un-maskable on purpose. Without it a
        // person typing 24 words into a masked field cannot check their own work, which is how a restore
        // fails for a reason nobody can see.
        if content.revealable {
            add_checkbox(&ctx, "Show the words while I type", REVEAL_ID, top, inner);
        }
        top += reveal_height(content, m) + m.margin / 2;

        // Submit is the DEFAULT button, so Enter on a single-line field submits; Cancel sits left of it so
        // the destructive-adjacent action is never under the cursor's resting position.
        let buttons_left = m.width - m.margin * 3 - m.button_w * 2;
        add_button(
            &ctx,
            "Cancel",
            IDCANCEL.0,
            buttons_left,
            top,
            BS_PUSHBUTTON as u32,
        );
        add_button(
            &ctx,
            content.submit,
            IDOK.0,
            buttons_left + m.button_w + m.margin,
            top,
            BS_DEFPUSHBUTTON as u32,
        );

        let _ = ShowWindow(window, SW_SHOW);
        let _ = SetForegroundWindow(window);
        let _ = SetFocus(edit);

        pump(window);

        // The window is gone by now (WM_DESTROY ran), so the state is ours again.
        let _ = DeleteObject(font);
        let outcome = match (state.accepted, state.submitted.take()) {
            (true, Some(text)) => InputOutcome::Provided(text),
            // Submit with an unreadable field is not an empty answer — the caller must not act on it.
            (true, None) => InputOutcome::Unavailable,
            _ => InputOutcome::Cancelled,
        };
        Ok(outcome)
    }
}

/// How tall the input field is. One line always — see [`edit_style`] for why it cannot be multiline.
fn field_height(_content: &InputContent, m: Metrics) -> i32 {
    m.field_single
}

/// The vertical space the reveal checkbox occupies, or zero when the window does not offer one.
fn reveal_height(content: &InputContent, m: Metrics) -> i32 {
    match content.revealable {
        true => m.line + m.margin / 2,
        false => 0,
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

/// The pixel height of the body block for `content`.
fn body_height(content: &InputContent, m: Metrics) -> i32 {
    body_lines(&content.body, m.width - m.margin * 4, m) * m.line
}

/// The outer window height that fits `content`'s controls, with the caption and frame accounted for.
///
/// A function rather than an expression inline in [`show`] so the layout arithmetic is unit-tested: a window
/// too short to show its own Submit button — or its own warning — is a defect no compiler catches.
fn window_height(content: &InputContent, m: Metrics) -> i32 {
    m.chrome
        + m.margin * 5
        // The heading is its own, taller line; the field label is an ordinary one.
        + m.heading_line
        + m.line
        + body_height(content, m)
        + field_height(content, m)
        + reveal_height(content, m)
        + m.button_h
}

/// The style bits for the input field.
///
/// **Always single-line.** Win32 silently IGNORES `ES_PASSWORD` on a multiline `EDIT`, so a field that can
/// be masked cannot be multiline — and `SPEC.md` §3.1d requires secret entry to be masked by default. The
/// field therefore scrolls horizontally, and the reveal checkbox ([`REVEAL_ID`]) is what makes 24 words
/// checkable rather than typed blind.
fn edit_style(content: &InputContent) -> WINDOW_STYLE {
    let mut style = WS_CHILD | WS_VISIBLE | WS_BORDER | WS_TABSTOP;
    style |= WINDOW_STYLE(ES_AUTOHSCROLL as u32);
    if content.masked {
        style |= WINDOW_STYLE(ES_PASSWORD as u32);
    }
    style
}

/// Where to place a `width`×`height` window so it sits centred on the primary display.
///
/// Pure so the arithmetic is unit-tested; falls back to `CW_USEDEFAULT` when the metrics are unreadable
/// (a session with no display), which lets Windows place it rather than putting it off-screen.
fn centred(width: i32, height: i32) -> (i32, i32) {
    // SAFETY: `GetSystemMetrics` reads a global integer and cannot fail in a way that matters; a 0 result
    // means "unknown", handled below.
    let (screen_w, screen_h) =
        unsafe { (GetSystemMetrics(SM_CXSCREEN), GetSystemMetrics(SM_CYSCREEN)) };
    centred_in(width, height, screen_w, screen_h)
}

/// The placement arithmetic, separated from the metrics call so it is testable.
fn centred_in(width: i32, height: i32, screen_w: i32, screen_h: i32) -> (i32, i32) {
    if screen_w <= width || screen_h <= height {
        return (CW_USEDEFAULT, CW_USEDEFAULT);
    }
    ((screen_w - width) / 2, (screen_h - height) / 2)
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
                    state.submitted = read_edit(state.edit);
                    state.accepted = true;
                    // Overwrite the control's OWN copy of the secret before the window goes away, so the
                    // phrase does not sit in an `EDIT` buffer until the heap happens to be reused.
                    let _ = SetWindowTextW(state.edit, windows::core::w!(""));
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
        m.button_w,
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
            edit_style(&content(true, true)).0 & ES_PASSWORD as u32,
            0,
            "secret entry is masked by default (§3.1d)"
        );
        assert_eq!(
            edit_style(&content(false, false)).0 & ES_PASSWORD as u32,
            0,
            "a field that asked for no mask must not get one"
        );
    }

    /// The reveal checkbox costs the window a row ONLY when it is offered — the arithmetic that keeps a
    /// passphrase window from carrying a blank strip where a control it does not have would go.
    #[test]
    fn the_reveal_control_takes_space_only_when_it_is_offered() {
        let m = Metrics::for_dpi(BASE_DPI);
        assert!(reveal_height(&content(true, true), m) > 0);
        assert_eq!(reveal_height(&content(true, false), m), 0);
        assert!(
            window_height(&content(true, true), m) > window_height(&content(true, false), m),
            "the window must grow to fit the checkbox"
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
                edit_style(&content(masked, masked)).0 & WS_TABSTOP.0,
                0,
                "masked={masked}"
            );
        }
    }

    /// The window centres itself on a normal display, and defers to Windows when it would not fit — an
    /// off-screen input window is an input window the user never answers.
    #[test]
    fn the_window_centres_itself_and_defers_when_it_would_not_fit() {
        assert_eq!(centred_in(600, 400, 1920, 1080), (660, 340));

        // A display smaller than the window (or unreadable metrics reported as 0) must not produce a
        // negative origin, which would put the title bar above the top of the screen.
        assert_eq!(centred_in(600, 400, 0, 0), (CW_USEDEFAULT, CW_USEDEFAULT));
        assert_eq!(
            centred_in(600, 400, 640, 360),
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
        let content = InputContent {
            body: REAL_BODY.to_string(),
            ..content(false, true)
        };

        let m = Metrics::for_dpi(BASE_DPI);
        const OLD_FIXED_HEIGHT: i32 = 84;
        assert!(
            body_height(&content, m) > OLD_FIXED_HEIGHT,
            "the real copy does not fit the height that clipped it: {}",
            body_height(&content, m)
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
        let short = InputContent {
            body: "One line.".to_string(),
            ..content(false, false)
        };
        assert_eq!(
            body_height(&short, m),
            layout::BODY_MIN_LINES * m.line,
            "a one-line body must not reserve the tall block"
        );

        let huge = InputContent {
            body: "word ".repeat(2000),
            ..content(false, false)
        };
        assert_eq!(
            body_height(&huge, m),
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
        let c = content(false, true);
        let h96 = window_height(&c, Metrics::for_dpi(96));
        let h150 = window_height(&c, Metrics::for_dpi(144));
        let h200 = window_height(&c, Metrics::for_dpi(192));
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
        }
    }
}
