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
use windows::Win32::Foundation::{HINSTANCE, HWND, LPARAM, LRESULT, WPARAM};
use windows::Win32::Graphics::Gdi::{
    CreateFontW, DeleteObject, InvalidateRect, ANSI_CHARSET, CLEARTYPE_QUALITY, COLOR_WINDOW,
    DEFAULT_PITCH, FF_DONTCARE, FW_NORMAL, HBRUSH, HFONT, OUT_TT_PRECIS,
};
use windows::Win32::System::LibraryLoader::GetModuleHandleW;
use windows::Win32::UI::Input::KeyboardAndMouse::SetFocus;
// `BM_GETCHECK`/`BST_CHECKED`/`EM_SETPASSWORDCHAR` live in the Controls module, not WindowsAndMessaging.
use windows::Win32::UI::Controls::{BST_CHECKED, EM_SETPASSWORDCHAR};
use windows::Win32::UI::WindowsAndMessaging::{
    CreateWindowExW, DefWindowProcW, DestroyWindow, DispatchMessageW, GetMessageW,
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

/// The pixel geometry of the window. Named constants rather than magic numbers inline, because the
/// layout is arithmetic over them and a stray literal is impossible to review.
mod layout {
    /// Outer width — wide enough that 24 words wrap into a readable block rather than a ribbon.
    pub const WIDTH: i32 = 620;
    /// Uniform margin around and between the controls.
    pub const MARGIN: i32 = 16;
    /// Height of a one-line label.
    pub const LINE: i32 = 20;
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
    pub const FIELD_SINGLE: i32 = 26;
    /// Button size.
    pub const BUTTON_W: i32 = 110;
    /// Button height.
    pub const BUTTON_H: i32 = 30;
    /// Extra vertical space the caption and frame consume, so the CLIENT area fits the controls.
    pub const CHROME: i32 = 44;
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
        let font = gui_font();
        let field_height = field_height(content);
        let body = body_height(content);
        let height = window_height(content);
        let (x, y) = centred(layout::WIDTH, height);

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
            layout::WIDTH,
            height,
            HWND::default(),
            HMENU::default(),
            instance,
            Some(state_ptr.cast()),
        )?;

        let mut top = layout::MARGIN;
        let inner = layout::WIDTH - layout::MARGIN * 4;
        add_static(
            window,
            instance,
            font,
            &content.heading,
            top,
            inner,
            layout::LINE,
        );
        top += layout::LINE + layout::MARGIN / 2;
        add_static(window, instance, font, &content.body, top, inner, body);
        top += body + layout::MARGIN / 2;
        add_static(
            window,
            instance,
            font,
            &content.field_label,
            top,
            inner,
            layout::LINE,
        );
        top += layout::LINE;

        let edit = CreateWindowExW(
            WINDOW_EX_STYLE(0),
            windows::core::w!("EDIT"),
            PCWSTR::null(),
            edit_style(content),
            layout::MARGIN,
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
        top += field_height + layout::MARGIN / 2;

        // §3.1d's reveal-while-typing affordance: masked by default, un-maskable on purpose. Without it a
        // person typing into a masked field cannot check their own work, which is how a restore fails for a
        // reason nobody can see. The label is the CALLER's, because only the caller knows whether the field
        // holds 24 words or a password.
        if let Some(label) = content.reveal_label {
            add_checkbox(window, instance, font, label, REVEAL_ID, top, inner);
        }
        top += reveal_height(content) + layout::MARGIN / 2;

        // Submit is the DEFAULT button, so Enter on a single-line field submits; Cancel sits left of it so
        // the destructive-adjacent action is never under the cursor's resting position.
        let buttons_left = layout::WIDTH - layout::MARGIN * 3 - layout::BUTTON_W * 2;
        add_button(
            window,
            instance,
            font,
            "Cancel",
            IDCANCEL.0,
            buttons_left,
            top,
            BS_PUSHBUTTON as u32,
        );
        add_button(
            window,
            instance,
            font,
            content.submit,
            IDOK.0,
            buttons_left + layout::BUTTON_W + layout::MARGIN,
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
fn field_height(_content: &InputContent) -> i32 {
    layout::FIELD_SINGLE
}

/// The vertical space the reveal checkbox occupies, or zero when the window does not offer one.
fn reveal_height(content: &InputContent) -> i32 {
    match content.revealable() {
        true => layout::LINE + layout::MARGIN / 2,
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
fn body_lines(body: &str, width: i32) -> i32 {
    let per_line = ((width / layout::CHAR_WIDTH).max(1)) as usize;
    let wrapped: usize = body
        .split('\n')
        .map(|line| line.chars().count().div_ceil(per_line).max(1))
        .sum();
    (wrapped as i32).clamp(layout::BODY_MIN_LINES, layout::BODY_MAX_LINES)
}

/// The pixel height of the body block for `content`.
fn body_height(content: &InputContent) -> i32 {
    body_lines(&content.body, layout::WIDTH - layout::MARGIN * 4) * layout::LINE
}

/// The outer window height that fits `content`'s controls, with the caption and frame accounted for.
///
/// A function rather than an expression inline in [`show`] so the layout arithmetic is unit-tested: a window
/// too short to show its own Submit button — or its own warning — is a defect no compiler catches.
fn window_height(content: &InputContent) -> i32 {
    layout::CHROME
        + layout::MARGIN * 5
        + layout::LINE * 2
        + body_height(content)
        + field_height(content)
        + reveal_height(content)
        + layout::BUTTON_H
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
unsafe fn add_checkbox(
    parent: HWND,
    instance: HINSTANCE,
    font: HFONT,
    text: &str,
    id: i32,
    top: i32,
    width: i32,
) {
    let created = CreateWindowExW(
        WINDOW_EX_STYLE(0),
        windows::core::w!("BUTTON"),
        &HSTRING::from(text),
        WS_CHILD | WS_VISIBLE | WS_TABSTOP | WINDOW_STYLE(BS_AUTOCHECKBOX as u32),
        layout::MARGIN,
        top,
        width,
        layout::LINE,
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
unsafe fn gui_font() -> HFONT {
    CreateFontW(
        // Negative height = character height in logical units, the convention for point-ish sizing.
        -15,
        0,
        0,
        0,
        FW_NORMAL.0 as i32,
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
unsafe fn add_static(
    parent: HWND,
    instance: HINSTANCE,
    font: HFONT,
    text: &str,
    top: i32,
    width: i32,
    height: i32,
) {
    let created = CreateWindowExW(
        WINDOW_EX_STYLE(0),
        windows::core::w!("STATIC"),
        &HSTRING::from(text),
        WS_CHILD | WS_VISIBLE,
        layout::MARGIN,
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
    parent: HWND,
    instance: HINSTANCE,
    font: HFONT,
    text: &str,
    id: i32,
    left: i32,
    top: i32,
    button_style: u32,
) {
    let created = CreateWindowExW(
        WINDOW_EX_STYLE(0),
        windows::core::w!("BUTTON"),
        &HSTRING::from(text),
        WS_CHILD | WS_VISIBLE | WS_TABSTOP | WS_GROUP | WINDOW_STYLE(button_style),
        left,
        top,
        layout::BUTTON_W,
        layout::BUTTON_H,
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
            edit_style(&content(true, REVEAL)).0 & ES_PASSWORD as u32,
            0,
            "secret entry is masked by default (§3.1d)"
        );
        assert_eq!(
            edit_style(&content(false, None)).0 & ES_PASSWORD as u32,
            0,
            "a field that asked for no mask must not get one"
        );
    }

    /// The reveal checkbox costs the window a row ONLY when it is offered — the arithmetic that keeps a
    /// passphrase window from carrying a blank strip where a control it does not have would go.
    #[test]
    fn the_reveal_control_takes_space_only_when_it_is_offered() {
        assert!(reveal_height(&content(true, REVEAL)) > 0);
        assert_eq!(reveal_height(&content(true, None)), 0);
        assert!(
            window_height(&content(true, REVEAL)) > window_height(&content(true, None)),
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
                edit_style(&content(masked, masked.then_some(REVEAL_TEXT))).0 & WS_TABSTOP.0,
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
            ..content(false, REVEAL)
        };

        const OLD_FIXED_HEIGHT: i32 = 84;
        assert!(
            body_height(&content) > OLD_FIXED_HEIGHT,
            "the real copy does not fit the height that clipped it: {}",
            body_height(&content)
        );
        // And every line of it must be accounted for: the estimate is per-character, so this is the check
        // that the arithmetic reaches the last sentence rather than merely being "bigger".
        let usable = layout::WIDTH - layout::MARGIN * 4;
        let needed = REAL_BODY.chars().count() as i32 / (usable / layout::CHAR_WIDTH);
        assert!(
            body_lines(REAL_BODY, usable) >= needed,
            "the estimate must cover the whole paragraph"
        );
    }

    /// **The control.** A SHORT body must not reserve the tall block — otherwise "grows to fit" would be
    /// satisfied by a function that always returned the maximum, and every window would carry a slab of
    /// empty space. Both ends of the clamp are pinned here.
    #[test]
    fn a_short_body_stays_compact_and_a_huge_one_is_bounded() {
        let short = InputContent {
            body: "One line.".to_string(),
            ..content(false, None)
        };
        assert_eq!(
            body_height(&short),
            layout::BODY_MIN_LINES * layout::LINE,
            "a one-line body must not reserve the tall block"
        );

        let huge = InputContent {
            body: "word ".repeat(2000),
            ..content(false, None)
        };
        assert_eq!(
            body_height(&huge),
            layout::BODY_MAX_LINES * layout::LINE,
            "the window must stay on a small display"
        );
    }

    /// Explicit newlines must each cost a line: the body is two paragraphs separated by a blank line, and an
    /// estimate that only divided by the character count would lose both breaks and clip the tail.
    #[test]
    fn explicit_line_breaks_are_counted_not_just_wrapped_characters() {
        let usable = layout::WIDTH - layout::MARGIN * 4;
        let one_paragraph = body_lines("short", usable);
        let three_lines = body_lines("short\n\nshort", usable);
        assert!(
            three_lines > one_paragraph,
            "blank lines take vertical space too: {three_lines} vs {one_paragraph}"
        );
    }

    /// The reveal label the fixtures use when they want a reveal control — named so a test reads as
    /// "with a reveal" rather than as an opaque `Some("…")`.
    const REVEAL_TEXT: &str = "Show the words while I type";
    const REVEAL: Option<&'static str> = Some(REVEAL_TEXT);

    fn content(masked: bool, reveal_label: Option<&'static str>) -> InputContent {
        InputContent {
            title: "DIG — Restore".to_string(),
            heading: "Type your 24-word recovery phrase.".to_string(),
            body: "Words in order, separated by spaces.".to_string(),
            field_label: "Your 24 words:".to_string(),
            submit: "Restore",
            masked,
            reveal_label,
        }
    }
}
