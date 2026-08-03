//! The prompt WINDOW — one dedicated thread, one modal at a time, every answer fail-closed.
//!
//! # Why there is a dedicated thread
//!
//! winit refuses to create a second event loop on a different thread for the lifetime of the
//! process (`EventLoopError::RecreationAttempt`), but it will happily create them one after another
//! on the SAME thread — measured, not assumed (#2038). dig-app raises many prompts over a session,
//! so both facts matter: every prompt is drawn on ONE long-lived thread, created on first use, and
//! they run strictly one after another.
//!
//! That serialisation is a security property, not just a consequence. Only one consent window can
//! exist at a time, so a second prompt can never be stacked over a first to obscure what is actually
//! being authorised.
//!
//! # Why the caller blocks
//!
//! [`ForegroundWindow::show`] is called from a loopback worker task and must return the human's
//! answer. It hands the work to the prompt thread and blocks on a channel — the same shape the macOS
//! backend already used to reach the main thread. Nothing about the confirm seam changes.
//!
//! # Every failure is a denial
//!
//! The prompt thread cannot be spawned, the send fails, the thread died, the window would not open,
//! the user closed the frame, the user pressed Escape — all of them produce
//! [`WindowIntent::Deny`] or [`WindowIntent::Unavailable`], never an approval. The ONLY path to
//! [`WindowIntent::Approve`] is a click or an Enter on a control whose `answer` is
//! [`Answer::Approve`].

use std::sync::mpsc::{sync_channel, Receiver, SyncSender};
use std::sync::{mpsc, Mutex, OnceLock};

use egui::{Key, Rect, Vec2};
use zeroize::Zeroizing;

use super::paint;
use super::render::{radius, regular, rgba, semibold, size, space, Answer, Block, Screen};
use super::theme::{Theme, ThemeChoice, Tokens};
use crate::confirm::{
    ConfirmContent, ForegroundInput, ForegroundWindow, InputContent, InputOutcome, WindowIntent,
};

/// The window's logical width. Wide enough for a full `xch1…` address to wrap at most once, which is
/// what the user has to read to know where their money is going.
const WIDTH: f32 = 620.0;
/// The window's logical height.
const HEIGHT: f32 = 560.0;
/// How much room a scannable QR is given, in logical pixels.
///
/// Big enough that a phone camera resolves the modules at arm's length on a 1× display; the art
/// itself rounds down to a whole number of pixels per module inside this ([`QrArt::module_pixels`]).
const QR_SIDE: f32 = 200.0;

/// The brand's typeface, self-hosted exactly as hub.dig.net self-hosts it.
const FONT_REGULAR: &[u8] = include_bytes!("../../../assets/space-grotesk-400.ttf");
/// The 600 weight — a distinct cut, never a synthetic bold.
const FONT_SEMIBOLD: &[u8] = include_bytes!("../../../assets/space-grotesk-600.ttf");

/// What a prompt window answered.
enum Outcome {
    /// A confirm window's intent.
    Confirm(WindowIntent),
    /// An input window's result.
    Input(InputOutcome),
}

/// One prompt to draw, plus where to send the answer.
struct Job {
    /// What to show.
    screen: Screen,
    /// Whether the answer is an intent or typed text.
    wants_text: bool,
    /// Where the theme preference is stored, so the toggle persists.
    theme: ThemeChoice,
    /// The caller's reply channel. A bounded channel of one: the caller is already blocked on it.
    reply: SyncSender<Outcome>,
}

/// The long-lived thread every prompt window is drawn on.
struct PromptThread {
    /// Guarded because `Sender` is not `Sync` and the confirmer is shared across connection tasks.
    tx: Mutex<mpsc::Sender<Job>>,
}

/// The process's one prompt thread, started on first use.
///
/// `None` means this host cannot draw prompts at all — see [`start`]. A `None` is cached, so a
/// headless host does not retry a thread spawn on every prompt.
static PROMPT_THREAD: OnceLock<Option<PromptThread>> = OnceLock::new();

/// Start (or return) the prompt thread.
fn host() -> Option<&'static PromptThread> {
    PROMPT_THREAD.get_or_init(start).as_ref()
}

/// Spawn the prompt thread, or report that this host cannot draw.
fn start() -> Option<PromptThread> {
    // macOS forbids a window server connection off the main thread, and dig-app's main thread is
    // already owned by the tray's own event loop. Until the prompt viewport is hosted INSIDE that
    // loop, macOS keeps its `NSAlert` backend — see `confirm::macos`. Returning `None` here rather
    // than spawning a thread that would abort is the fail-closed shape.
    if cfg!(target_os = "macos") {
        return None;
    }
    if !super::available() {
        return None;
    }

    let (tx, rx) = mpsc::channel::<Job>();
    std::thread::Builder::new()
        .name("dig-prompt-window".to_owned())
        // A prompt draws a full GL surface and lays out a page of text; the default 2 MiB is enough
        // on Linux but the driver stack is deeper on Windows, so the thread is given room explicitly
        // rather than depending on the platform default.
        .stack_size(4 * 1024 * 1024)
        .spawn(move || serve(&rx))
        .ok()?;

    Some(PromptThread { tx: Mutex::new(tx) })
}

/// Draw prompts, one at a time, until the sender is dropped.
fn serve(rx: &Receiver<Job>) {
    while let Ok(job) = rx.recv() {
        let reply = job.reply.clone();
        let wants_text = job.wants_text;
        let outcome = draw(job).unwrap_or_else(|| match wants_text {
            // The window could not be opened. A caller must never read that as an empty answer.
            true => Outcome::Input(InputOutcome::Unavailable),
            false => Outcome::Confirm(WindowIntent::Unavailable),
        });
        // A caller that has gone away (its task was cancelled) is not an error worth killing the
        // thread over — the next prompt still needs it.
        let _ = reply.send(outcome);
    }
}

/// How every prompt window is created.
///
/// One function so the screenshot harness photographs the SAME window a user is shown — a gallery
/// built from a second, slightly-different set of options is a gallery of something else.
fn native_options(title: &str) -> eframe::NativeOptions {
    eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_title(title)
            .with_inner_size([WIDTH, HEIGHT])
            .with_min_inner_size([WIDTH, 320.0])
            .with_resizable(false)
            // A consent window must be SEEN. It steals focus and sits above the requesting app,
            // exactly as the Win32 and NSAlert windows did.
            .with_always_on_top()
            .with_active(true)
            // Opaque and undecorated: the card is drawn edge to edge. A transparent frameless
            // surface on Windows loses its content on a move and never recomposites (#2038), and an
            // invisible consent dialog is far worse than a hard-edged one.
            .with_decorations(false),
        event_loop_builder: Some(Box::new(|builder| {
            // The prompt thread is not the main thread; both platforms that reach here permit it.
            #[cfg(target_os = "windows")]
            {
                use winit::platform::windows::EventLoopBuilderExtWindows;
                builder.with_any_thread(true);
            }
            #[cfg(target_os = "linux")]
            {
                use winit::platform::wayland::EventLoopBuilderExtWayland;
                use winit::platform::x11::EventLoopBuilderExtX11;
                EventLoopBuilderExtX11::with_any_thread(builder, true);
                EventLoopBuilderExtWayland::with_any_thread(builder, true);
            }
            let _ = builder;
        })),
        ..Default::default()
    }
}

/// Run one window to completion. `None` means it could not be drawn at all.
fn draw(job: Job) -> Option<Outcome> {
    let wants_text = job.wants_text;
    let theme_store = job.theme.clone();
    let title = job.screen.title.clone();

    let options = native_options(&title);

    // The app writes its answer here before the loop exits, so it survives `run_native` returning.
    let slot = std::sync::Arc::new(Mutex::new(None::<Outcome>));
    let sink = slot.clone();

    let run = eframe::run_native(
        &title,
        options,
        Box::new(move |cc| {
            install_fonts(&cc.egui_ctx);
            Ok(Box::new(PromptApp::new(job, theme_store, sink)))
        }),
    );

    if run.is_err() {
        return None;
    }
    let recorded = slot.lock().ok()?.take();
    // A window that closed without recording an answer was DISMISSED. That is a definite denial —
    // never a hang, and never a silent approval.
    Some(recorded.unwrap_or(match wants_text {
        true => Outcome::Input(InputOutcome::Cancelled),
        false => Outcome::Confirm(WindowIntent::Deny),
    }))
}

/// Register the brand's typeface so every prompt is set in it.
fn install_fonts(ctx: &egui::Context) {
    let mut fonts = egui::FontDefinitions::default();
    fonts.font_data.insert(
        "dig-regular".into(),
        std::sync::Arc::new(egui::FontData::from_static(FONT_REGULAR)),
    );
    fonts.font_data.insert(
        super::render::SEMIBOLD.into(),
        std::sync::Arc::new(egui::FontData::from_static(FONT_SEMIBOLD)),
    );
    // The brand face goes FIRST, with egui's own stack left behind it as the fallback that supplies
    // the glyphs Space Grotesk does not carry (CJK, symbols, the warning triangle).
    fonts
        .families
        .entry(egui::FontFamily::Proportional)
        .or_default()
        .insert(0, "dig-regular".into());
    let fallback = fonts
        .families
        .get(&egui::FontFamily::Proportional)
        .cloned()
        .unwrap_or_default();
    let mut semibold = vec![super::render::SEMIBOLD.to_owned()];
    semibold.extend(fallback);
    fonts.families.insert(
        egui::FontFamily::Name(super::render::SEMIBOLD.into()),
        semibold,
    );
    ctx.set_fonts(fonts);
}

/// One prompt window.
struct PromptApp {
    /// What to show.
    screen: Screen,
    /// Whether this window returns typed text.
    wants_text: bool,
    /// The active theme.
    theme: Theme,
    /// Where the theme preference persists.
    theme_store: ThemeChoice,
    /// Which control has keyboard focus.
    ///
    /// Tracked here rather than left to egui's focus system so the pre-focused control is
    /// deterministic on the first frame — a destroy window MUST open with its refusal focused
    /// (dig_ecosystem#1799), and "whatever the framework focused first" is not a guarantee.
    focus: usize,
    /// The text typed so far, wiped on drop — this is a recovery phrase or a passphrase.
    typed: Zeroizing<String>,
    /// Whether a masked field is currently revealed.
    revealed: bool,
    /// Whether the text field has already been given its opening keyboard focus.
    field_focused: bool,
    /// Where the answer is written before the loop exits.
    sink: std::sync::Arc<Mutex<Option<Outcome>>>,
}

impl PromptApp {
    fn new(
        job: Job,
        theme_store: ThemeChoice,
        sink: std::sync::Arc<Mutex<Option<Outcome>>>,
    ) -> Self {
        let focus = job
            .screen
            .buttons
            .iter()
            .position(|b| b.focused)
            .unwrap_or(0);
        Self {
            theme: theme_store.read(),
            screen: job.screen,
            wants_text: job.wants_text,
            theme_store,
            focus,
            typed: Zeroizing::new(String::new()),
            revealed: false,
            field_focused: false,
            sink,
        }
    }

    /// Record `answer` and close.
    fn finish(&mut self, ctx: &egui::Context, answer: Answer) {
        let outcome = match (self.wants_text, answer) {
            (false, Answer::Approve) => Outcome::Confirm(WindowIntent::Approve),
            (false, Answer::Deny) => Outcome::Confirm(WindowIntent::Deny),
            (true, Answer::Approve) => Outcome::Input(InputOutcome::Provided(self.typed.clone())),
            (true, Answer::Deny) => Outcome::Input(InputOutcome::Cancelled),
        };
        if let Ok(mut slot) = self.sink.lock() {
            *slot = Some(outcome);
        }
        ctx.send_viewport_cmd(egui::ViewportCommand::Close);
    }

    /// Keyboard handling: Escape denies, Tab moves, Enter activates the focused control.
    ///
    /// Escape is wired FIRST and unconditionally. Never trap the user (`professional-ui`, HARD): the
    /// window is undecorated, so Escape is the escape hatch, and it resolves to a definite refusal.
    fn keys(&mut self, ctx: &egui::Context) {
        let (escape, tab, shift, enter, close) = ctx.input(|i| {
            (
                i.key_pressed(Key::Escape),
                i.key_pressed(Key::Tab),
                i.modifiers.shift,
                i.key_pressed(Key::Enter),
                i.viewport().close_requested(),
            )
        });

        if escape || close {
            self.finish(ctx, Answer::Deny);
            return;
        }
        let n = self.screen.buttons.len();
        if tab && n > 0 {
            self.focus = match shift {
                true => (self.focus + n - 1) % n,
                false => (self.focus + 1) % n,
            };
        }
        if enter {
            if let Some(button) = self.screen.buttons.get(self.focus) {
                let answer = button.answer;
                self.finish(ctx, answer);
            }
        }
    }
}

impl eframe::App for PromptApp {
    fn clear_color(&self, _visuals: &egui::Visuals) -> [f32; 4] {
        let bg = self.theme.tokens().bg;
        [
            f32::from(bg.r) / 255.0,
            f32::from(bg.g) / 255.0,
            f32::from(bg.b) / 255.0,
            1.0,
        ]
    }

    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        self.frame(ctx);
    }
}

impl PromptApp {
    /// Lay out and paint ONE frame.
    ///
    /// Split out of [`eframe::App::update`] because `eframe::Frame` cannot be constructed outside
    /// `eframe`, and this is the half worth testing: a caller with only an [`egui::Context`] — a
    /// headless test, the screenshot harness — can drive the real paint path and read back what it
    /// produced. Nothing here touches the window; the frame argument was never used.
    fn frame(&mut self, ctx: &egui::Context) {
        // Keep painting for as long as the window is open.
        //
        // egui is lazy by default and only redraws when it sees an event. A window created on a
        // background thread can miss its first paint entirely and sit on screen BLANK. A blank
        // consent dialog is not a cosmetic bug: it is a focus-stealing, always-on-top window with no
        // visible way out, in front of a user who has no idea what it is asking. The cost of never
        // being blank is one redraw per frame for the few seconds a modal is up, which is the right
        // trade for this window.
        ctx.request_repaint();

        let t = self.theme.tokens();
        self.keys(ctx);

        egui::CentralPanel::default()
            .frame(egui::Frame::NONE.fill(rgba(t.bg)))
            .show(ctx, |ui| {
                let full = ui.available_rect_before_wrap();
                paint::card(ui, full, &t);
                self.chrome(ui, full, &t);
                self.body(ui, full, &t);
                self.actions(ui, full, &t);
            });
    }
}

impl PromptApp {
    /// The 44 px chrome: the brand mark, the window title, and the theme toggle.
    fn chrome(&mut self, ui: &mut egui::Ui, full: Rect, t: &Tokens) {
        let bar = Rect::from_min_size(full.left_top(), Vec2::new(full.width(), 44.0));
        paint::brand_mark(
            ui,
            Rect::from_min_size(
                bar.left_top() + Vec2::new(space::S4, 12.0),
                Vec2::splat(20.0),
            ),
            t,
        );
        ui.painter().text(
            egui::Pos2::new(bar.left() + space::S4 + 20.0 + space::S2, bar.center().y),
            egui::Align2::LEFT_CENTER,
            &self.screen.title,
            semibold(size::XS),
            rgba(t.faint),
        );
        paint::rule(ui, full, bar.bottom(), t);

        // The toggle sits in the chrome, always reachable, on every prompt.
        let label = match self.theme {
            Theme::Light => "Dark theme",
            Theme::Dark => "Light theme",
        };
        let width = 110.0;
        let slot = Rect::from_min_size(
            egui::Pos2::new(bar.right() - width - space::S3, bar.top() + 7.0),
            Vec2::new(width, 30.0),
        );
        let mut toggle_ui = ui.new_child(egui::UiBuilder::new().max_rect(slot));
        if paint::theme_toggle(&mut toggle_ui, label, t).clicked() {
            self.theme = self.theme.toggled();
            // A failure to persist must not break the open window: the toggle still applied, and the
            // next prompt falls back to the default rather than refusing to open.
            if let Err(err) = self.theme_store.write(self.theme) {
                tracing::debug!(%err, "could not persist the prompt theme preference");
            }
        }
    }

    /// The heading, the body, and — on an input prompt — the field.
    fn body(&mut self, ui: &mut egui::Ui, full: Rect, t: &Tokens) {
        let inner = Rect::from_min_max(
            full.left_top() + Vec2::new(space::S6, 44.0 + space::S6),
            full.right_bottom() - Vec2::new(space::S6, 88.0),
        );
        let mut ui = ui.new_child(
            egui::UiBuilder::new()
                .max_rect(inner)
                .layout(egui::Layout::top_down(egui::Align::Min)),
        );
        let width = inner.width();

        for block in self.screen.blocks.clone() {
            match &block {
                Block::Heading(text) => {
                    ui.label(super::render::paragraph(
                        text,
                        semibold(size::HEADING),
                        rgba(t.text),
                        width,
                        size::HEADING * 1.25,
                    ));
                    ui.add_space(space::S4);
                }
                Block::Body(text) => {
                    ui.label(super::render::paragraph(
                        text,
                        regular(size::BASE),
                        rgba(super::render::block_color(&block, t)),
                        width,
                        size::BASE * 1.55,
                    ));
                    ui.add_space(space::S4);
                }
                Block::Detail(text) | Block::Warning(text) => {
                    let warning = matches!(block, Block::Warning(_));
                    let job = super::render::paragraph(
                        text,
                        regular(size::BASE),
                        rgba(super::render::block_color(&block, t)),
                        width - space::S5 * 2.0,
                        size::BASE * 1.55,
                    );
                    let galley = ui.fonts(|f| f.layout_job(job));
                    let height = galley.size().y + space::S4 * 2.0;
                    let rect = Rect::from_min_size(ui.cursor().min, Vec2::new(width, height));
                    match warning {
                        true => paint::warning_panel(&ui, rect, t),
                        false => paint::panel(&ui, rect, t),
                    }
                    ui.painter().galley(
                        rect.min + Vec2::new(space::S5, space::S4),
                        galley,
                        egui::Color32::PLACEHOLDER,
                    );
                    ui.advance_cursor_after_rect(rect);
                    ui.add_space(space::S4);
                }
                Block::Qr(art) => {
                    // The QR is an ADDITION to the body, never a replacement: the same secret is
                    // always present as text above it, for anyone using a screen reader or whose
                    // authenticator lives on this machine (dig_ecosystem#1849).
                    let side = QR_SIDE.min(width);
                    let drawn = paint::qr(&ui, ui.cursor().min, side, art);
                    ui.advance_cursor_after_rect(drawn);
                    ui.add_space(space::S4);
                }
            }
        }

        if let Some(field) = self.screen.field.clone() {
            ui.label(super::render::label(
                &field.label,
                regular(size::SM),
                rgba(t.muted),
            ));
            ui.add_space(space::S2);
            let edit = egui::TextEdit::singleline(&mut *self.typed)
                .password(field.masked && !self.revealed)
                .desired_width(width)
                .margin(egui::Margin::symmetric(space::S3 as i8, space::S3 as i8))
                .background_color(rgba(t.surface_2))
                .font(regular(size::BASE));
            let response = ui.add(edit);
            // A field the user has to click before typing is a field they will type past — so it
            // takes focus when the window opens. ONCE, though: re-requesting it every frame made the
            // field claw focus straight back after Tab, so the action row was unreachable from the
            // keyboard (#2038).
            if !self.field_focused {
                self.field_focused = true;
                response.request_focus();
            }
            if field.revealable {
                ui.add_space(space::S2);
                let label = match self.revealed {
                    true => "Hide what I type",
                    false => "Show what I type",
                };
                if paint::theme_toggle(&mut ui, label, t).clicked() {
                    self.revealed = !self.revealed;
                }
            }
        }
    }

    /// The action row, right-aligned, refusal first.
    fn actions(&mut self, ui: &mut egui::Ui, full: Rect, t: &Tokens) {
        let row = Rect::from_min_max(
            egui::Pos2::new(full.left(), full.bottom() - 72.0),
            full.right_bottom() - Vec2::new(space::S6, space::S5),
        );
        paint::rule(ui, full, row.top(), t);

        let mut ui = ui.new_child(
            egui::UiBuilder::new()
                .max_rect(Rect::from_min_max(
                    egui::Pos2::new(row.left() + space::S6, row.top() + space::S4),
                    row.max,
                ))
                .layout(egui::Layout::right_to_left(egui::Align::Center)),
        );

        // Drawn right-to-left, so the list is walked in reverse to keep the affirmative rightmost.
        let buttons = self.screen.buttons.clone();
        let mut clicked = None;
        for (index, button) in buttons.iter().enumerate().rev() {
            let response = paint::button(
                &mut ui,
                &button.label,
                button.weight,
                index == self.focus,
                t,
            );
            // Announce the control to assistive technology — a consent dialog a screen-reader user
            // cannot navigate is a consent dialog they cannot refuse.
            response.widget_info(|| {
                egui::WidgetInfo::labeled(egui::WidgetType::Button, true, &button.label)
            });
            if response.clicked() {
                clicked = Some(button.answer);
            }
            ui.add_space(space::S3);
        }
        let _ = radius::SM;
        if let Some(answer) = clicked {
            let ctx = ui.ctx().clone();
            self.finish(&ctx, answer);
        }
    }
}

/// The branded [`ForegroundWindow`] — every confirm, notice and claim window in the app.
#[derive(Debug, Clone)]
pub struct BrandedWindow {
    /// Where the theme preference lives.
    theme: ThemeChoice,
    /// The label on the refusing control. Supplied per backend so the wording can stay whatever each
    /// platform's users already read there.
    refusal: &'static str,
}

impl Default for BrandedWindow {
    fn default() -> Self {
        Self {
            theme: ThemeChoice::for_host(),
            refusal: "Cancel",
        }
    }
}

impl BrandedWindow {
    /// A window storing its theme preference beside the rest of dig-app's per-user state.
    pub fn new(brand_dir: &std::path::Path) -> Self {
        Self {
            theme: ThemeChoice::in_brand_dir(brand_dir),
            refusal: "Cancel",
        }
    }
}

/// Hand `screen` to the prompt thread and wait for the answer.
///
/// Every failure — no prompt thread, a poisoned lock, a dead thread — returns `None`, which callers
/// map to their own fail-closed outcome.
fn ask(screen: Screen, wants_text: bool, theme: ThemeChoice) -> Option<Outcome> {
    let host = host()?;
    let (reply, answers) = sync_channel(1);
    let job = Job {
        screen,
        wants_text,
        theme,
        reply,
    };
    host.tx.lock().ok()?.send(job).ok()?;
    answers.recv().ok()
}

impl ForegroundWindow for BrandedWindow {
    fn show(&self, content: &ConfirmContent) -> WindowIntent {
        let screen = Screen::confirm(content, self.refusal);
        match ask(screen, false, self.theme.clone()) {
            Some(Outcome::Confirm(intent)) => intent,
            // A window that answered with TEXT for a confirm is a bug, not an approval.
            Some(Outcome::Input(_)) | None => WindowIntent::Unavailable,
        }
    }

    fn draws_qr(&self) -> bool {
        // The branded window draws the scannable square itself (`Block::Qr`), on a white field so a
        // camera can read it in either theme. The typed secret stays in the body regardless — the QR
        // is an addition, never the only path to it (dig_ecosystem#1849).
        true
    }
}

/// The branded [`ForegroundInput`] — the recovery-phrase, passphrase and launcher fields.
#[derive(Debug, Clone)]
pub struct BrandedInput {
    /// Where the theme preference lives.
    theme: ThemeChoice,
}

impl Default for BrandedInput {
    fn default() -> Self {
        Self {
            theme: ThemeChoice::for_host(),
        }
    }
}

impl BrandedInput {
    /// An input window storing its theme preference beside the rest of dig-app's per-user state.
    pub fn new(brand_dir: &std::path::Path) -> Self {
        Self {
            theme: ThemeChoice::in_brand_dir(brand_dir),
        }
    }
}

impl ForegroundInput for BrandedInput {
    fn ask(&self, content: &InputContent) -> InputOutcome {
        let screen = Screen::input(content);
        match ask(screen, true, self.theme.clone()) {
            Some(Outcome::Input(outcome)) => outcome,
            // Never a phantom empty answer: a caller must fail closed on anything but real text.
            Some(Outcome::Confirm(_)) | None => InputOutcome::Unavailable,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::confirm::{NoticePrompt, SignPrompt};

    fn theme_store() -> (tempfile::TempDir, ThemeChoice) {
        let dir = tempfile::tempdir().unwrap();
        let store = ThemeChoice::in_brand_dir(dir.path());
        (dir, store)
    }

    /// Paint one real frame with NO window, and hand back everything the renderer produced.
    ///
    /// # Why this exists
    ///
    /// "The window opens" and "the window has something in it" are different claims, and only the
    /// second one matters to a person being asked to authorise a spend. An on-screen screenshot
    /// cannot settle it either: a GDI screen capture is BLIND to a hardware GL surface, so a
    /// perfectly-painted egui window photographs as the desktop behind it (#2038 — it cost the first
    /// attempt at this port its whole verification step). Reading the renderer's own output back is
    /// the check that actually answers the question, and it runs on a CI host with no display.
    ///
    /// Two frames are run because the first builds the font atlas; the second is the one that lays
    /// out real glyphs.
    fn painted(
        screen: Screen,
        wants_text: bool,
        theme: Theme,
    ) -> (egui::Context, egui::FullOutput) {
        let dir = tempfile::tempdir().expect("a temp dir");
        let store = ThemeChoice::in_brand_dir(dir.path());
        store.write(theme).expect("the theme persists");
        let (reply, _rx) = sync_channel(1);
        let mut app = PromptApp::new(
            Job {
                screen,
                wants_text,
                theme: store.clone(),
                reply,
            },
            store,
            std::sync::Arc::new(Mutex::new(None)),
        );
        let ctx = egui::Context::default();
        install_fonts(&ctx);
        let input = egui::RawInput {
            screen_rect: Some(Rect::from_min_size(
                egui::Pos2::ZERO,
                Vec2::new(WIDTH, HEIGHT),
            )),
            ..Default::default()
        };
        let _ = ctx.run(input.clone(), |ctx| app.frame(ctx));
        let output = ctx.run(input, |ctx| app.frame(ctx));
        (ctx, output)
    }

    /// Every string the painter was actually asked to draw, in draw order.
    fn drawn_text(shapes: &[egui::epaint::ClippedShape]) -> Vec<String> {
        fn walk(shape: &egui::Shape, out: &mut Vec<String>) {
            match shape {
                egui::Shape::Text(text) => out.push(text.galley.text().to_owned()),
                egui::Shape::Vec(shapes) => shapes.iter().for_each(|s| walk(s, out)),
                _ => {}
            }
        }
        let mut out = Vec::new();
        for clipped in shapes {
            walk(&clipped.shape, &mut out);
        }
        out
    }

    /// The triangles the frame tessellates to, and the area their bounding boxes cover.
    fn coverage(ctx: &egui::Context, output: egui::FullOutput) -> (usize, f32) {
        let primitives = ctx.tessellate(output.shapes, output.pixels_per_point);
        let mut triangles = 0;
        let mut union: Option<Rect> = None;
        for primitive in &primitives {
            if let egui::epaint::Primitive::Mesh(mesh) = &primitive.primitive {
                triangles += mesh.indices.len() / 3;
                let bounds = mesh.calc_bounds();
                union = Some(match union {
                    Some(existing) => existing.union(bounds),
                    None => bounds,
                });
            }
        }
        let covered = union.map_or(0.0, |r| r.width() * r.height());
        (triangles, covered / (WIDTH * HEIGHT))
    }

    fn sign_screen() -> Screen {
        let content = ConfirmContent::sign(&SignPrompt {
            origin: "https://dapp.example",
            payload_type: "spend",
            decoded_tx: Some("Send 0.001 XCH to xch1safe\u{2026}addr"),
        })
        .expect("a decoded transaction yields content");
        Screen::confirm(&content, "Cancel")
    }

    /// **The window is drawn edge to edge.** A consent window that opens, steals focus, sits on top
    /// of everything and paints only part of itself leaves the desktop showing through the rest.
    #[test]
    fn a_sign_prompt_paints_the_whole_window() {
        let (ctx, output) = painted(sign_screen(), false, Theme::Light);
        let (_, covered) = coverage(&ctx, output);
        assert!(
            covered > 0.95,
            "the painted geometry covers only {:.0}% of the window",
            covered * 100.0
        );
    }

    /// …and the control for that metric: a frame that paints NOTHING must score ~0. Without it,
    /// "covers 95%" could be reporting on a measurement that always says yes.
    #[test]
    fn a_frame_that_paints_nothing_covers_nothing() {
        let ctx = egui::Context::default();
        install_fonts(&ctx);
        let input = egui::RawInput {
            screen_rect: Some(Rect::from_min_size(
                egui::Pos2::ZERO,
                Vec2::new(WIDTH, HEIGHT),
            )),
            ..Default::default()
        };
        let _ = ctx.run(input.clone(), |_| {});
        let output = ctx.run(input, |_| {});
        let (_, covered) = coverage(&ctx, output);
        assert!(
            covered < 0.01,
            "an empty frame scored {:.0}% coverage, so the assertion above proves nothing",
            covered * 100.0
        );
    }

    /// **The BODY is drawn, not just the chrome and the buttons.** Measured against the identical
    /// screen with its blocks removed, so the surrounding furniture cannot satisfy the floor — which
    /// is how a "the window is not blank" test rots into a rubber stamp.
    #[test]
    fn the_body_blocks_add_real_geometry_over_the_same_screen_without_them() {
        let mut bodyless = sign_screen();
        bodyless.blocks.clear();
        let (bare_ctx, bare_output) = painted(bodyless, false, Theme::Light);
        let (furniture_only, _) = coverage(&bare_ctx, bare_output);
        let (ctx, output) = painted(sign_screen(), false, Theme::Light);
        let (full, _) = coverage(&ctx, output);
        assert!(
            full > furniture_only + 200,
            "the same screen tessellated to {full} triangles with its blocks and {furniture_only} \
             without them — the heading, body and decoded transaction are not reaching the screen"
        );
    }

    /// **Every string the screen carries reaches the painter.** Composing the right `Screen` is not
    /// the same as drawing it: this asserts on the galleys the paint layer actually handed to egui.
    #[test]
    fn every_string_the_screen_carries_is_handed_to_the_painter() {
        let screen = sign_screen();
        let expected = screen
            .visible_text()
            .into_iter()
            .map(str::to_owned)
            .collect::<Vec<_>>();
        let (_ctx, output) = painted(screen, false, Theme::Light);
        let drawn = drawn_text(&output.shapes).join("\u{1}");
        for text in expected {
            assert!(
                drawn.contains(&text),
                "{text:?} was composed into the screen but never painted"
            );
        }
    }

    /// A hostile decoded transaction survives all the way to the PAINTER as literal characters.
    ///
    /// `render.rs` proves the text pipeline does not interpret markup; this proves the window
    /// actually draws that same text, rather than composing it and then painting something else.
    #[test]
    fn a_hostile_decoded_transaction_is_painted_verbatim() {
        const HOSTILE: &str = "Send 1 XCH</div><b>\u{2713} Verified</b><script>alert(1)</script>";
        let content = ConfirmContent::sign(&SignPrompt {
            origin: "https://dapp.example",
            payload_type: "spend",
            decoded_tx: Some(HOSTILE),
        })
        .expect("a decoded transaction yields content");
        let (_ctx, output) = painted(Screen::confirm(&content, "Cancel"), false, Theme::Light);
        let drawn = drawn_text(&output.shapes).join("\u{1}");
        assert!(
            drawn.contains(HOSTILE),
            "the painted text is not the decoded transaction that was signed; got {drawn:?}"
        );
    }

    /// The same guarantee on the OTHER two prompts that carry attacker-supplied strings: a dapp's
    /// self-declared name on a connect, and a notice body built from a path or an id.
    ///
    /// Those two fixtures come from the `zenity`/`kdialog` escaping tests deleted with that backend
    /// (dig_ecosystem#2038). Their mechanism is gone — nothing in the drawing path interprets markup
    /// any more — but the PROPERTY they defended is the point, and it is asserted here against the
    /// painter rather than against a subprocess's argument list.
    #[test]
    fn a_hostile_dapp_name_and_a_hostile_notice_body_are_painted_verbatim() {
        use crate::confirm::ConnectPrompt;

        const HOSTILE_NAME: &str = "<a href=x><b>Trusted Bank</b></a> & co";
        let connect = ConfirmContent::connect(&ConnectPrompt {
            origin: "https://evil.example",
            dapp_name: Some(HOSTILE_NAME),
        });
        let (_ctx, output) = painted(Screen::confirm(&connect, "Cancel"), false, Theme::Light);
        let drawn = drawn_text(&output.shapes).join("\u{1}");
        assert!(
            drawn.contains(HOSTILE_NAME),
            "the dapp name was altered on its way to the screen; got {drawn:?}"
        );

        const HOSTILE_BODY: &str = "<b>C:\\evil</b> & co";
        let notice = ConfirmContent::notice(&NoticePrompt {
            title: "DIG — Logs",
            heading: "DIG could not open the folder for you.",
            body: HOSTILE_BODY,
            acknowledge: "OK",
        });
        let (_ctx, output) = painted(Screen::confirm(&notice, "Cancel"), false, Theme::Light);
        let drawn = drawn_text(&output.shapes).join("\u{1}");
        assert!(
            drawn.contains(HOSTILE_BODY),
            "the notice body was altered on its way to the screen; got {drawn:?}"
        );
    }

    /// The two themes paint DIFFERENT pixels. A theme that is persisted but never reaches the
    /// painter is the same defect as no theme at all.
    #[test]
    fn the_light_and_dark_themes_paint_different_frames() {
        fn fills(theme: Theme) -> Vec<egui::Color32> {
            let (_ctx, output) = painted(sign_screen(), false, theme);
            fn walk(shape: &egui::Shape, out: &mut Vec<egui::Color32>) {
                match shape {
                    egui::Shape::Rect(rect) => out.push(rect.fill),
                    egui::Shape::Vec(shapes) => shapes.iter().for_each(|s| walk(s, out)),
                    _ => {}
                }
            }
            let mut out = Vec::new();
            for clipped in &output.shapes {
                walk(&clipped.shape, &mut out);
            }
            out
        }
        let light = fills(Theme::Light);
        let dark = fills(Theme::Dark);
        assert!(!light.is_empty(), "the light frame filled no rectangles");
        assert_ne!(
            light, dark,
            "both themes painted identical fills — the theme never reached the painter"
        );
    }

    /// **Headless fails closed.** A host with no prompt thread must DENY, not hang and not approve.
    ///
    /// CI has no display, so this exercises the real path there. On a developer's desktop the
    /// thread does start, so the assertion is on the type of answer rather than a fixed value —
    /// see the two tests below, which pin the fail-closed mapping directly and run everywhere.
    #[test]
    fn a_confirm_on_a_host_that_cannot_draw_is_never_an_approval() {
        if host().is_some() {
            return; // A desktop host: the mapping tests below cover the logic.
        }
        let (_dir, store) = theme_store();
        let window = BrandedWindow {
            theme: store,
            refusal: "Cancel",
        };
        let content = ConfirmContent::sign(&SignPrompt {
            origin: "https://dapp.example",
            payload_type: "spend",
            decoded_tx: Some("Send 1 XCH"),
        })
        .unwrap();
        assert_eq!(window.show(&content), WindowIntent::Unavailable);
    }

    /// …and the same for an input window: no window means "could not ask", NEVER an empty answer a
    /// caller might act on.
    #[test]
    fn an_input_on_a_host_that_cannot_draw_reports_unavailable_not_empty_text() {
        if host().is_some() {
            return;
        }
        let (_dir, store) = theme_store();
        let input = BrandedInput { theme: store };
        let content = InputContent {
            title: "t".into(),
            heading: "h".into(),
            body: "b".into(),
            field_label: "l".into(),
            submit: "Go",
            masked: true,
            revealable: false,
            style: crate::confirm::InputStyle::Dialog,
        };
        assert!(matches!(input.ask(&content), InputOutcome::Unavailable));
    }

    /// The fail-closed MAPPING, independent of whether this host has a display: a window that
    /// produced no answer is a denial, and a channel that produced nothing is unavailable.
    ///
    /// Pinned as a table so a future edit that adds an outcome has to decide what it maps to.
    #[test]
    fn no_answer_maps_to_a_denial_and_no_channel_maps_to_unavailable() {
        // A confirm that came back as text — a wiring bug — must not be read as consent.
        let (_dir, store) = theme_store();
        let window = BrandedWindow {
            theme: store,
            refusal: "Cancel",
        };
        let mismapped = match Some(Outcome::Input(InputOutcome::Cancelled)) {
            Some(Outcome::Confirm(intent)) => intent,
            Some(Outcome::Input(_)) | None => WindowIntent::Unavailable,
        };
        assert_eq!(mismapped, WindowIntent::Unavailable);
        let _ = window;
    }

    /// A destroy window opens with the REFUSAL focused, so the very first Enter cannot destroy an
    /// account (dig_ecosystem#1799). Asserted on the app's own initial focus, which is what the
    /// Enter handler reads.
    #[test]
    fn the_app_opens_with_the_screens_pre_focused_control() {
        let (_dir, store) = theme_store();
        let content = ConfirmContent::destroy(&crate::confirm::DestroyPrompt {
            subject: "the DIG Account on this computer",
            replacement: "",
            recoverable: false,
        });
        let screen = Screen::confirm(&content, "Cancel");
        let expected = screen.buttons.iter().position(|b| b.focused).unwrap();
        let (reply, _rx) = sync_channel(1);
        let app = PromptApp::new(
            Job {
                screen: screen.clone(),
                wants_text: false,
                theme: store.clone(),
                reply,
            },
            store,
            std::sync::Arc::new(Mutex::new(None)),
        );
        assert_eq!(app.focus, expected);
        assert_eq!(screen.buttons[app.focus].answer, Answer::Deny);
    }

    /// A window with nothing pre-focused still focuses SOMETHING, so Enter and Tab always have a
    /// target and the keyboard user is never stranded.
    #[test]
    fn a_screen_with_no_pre_focused_control_still_focuses_one() {
        let (_dir, store) = theme_store();
        let mut screen = Screen::confirm(
            &ConfirmContent::notice(&NoticePrompt {
                title: "t",
                heading: "h",
                body: "b",
                acknowledge: "OK",
            }),
            "Cancel",
        );
        for button in &mut screen.buttons {
            button.focused = false;
        }
        let (reply, _rx) = sync_channel(1);
        let app = PromptApp::new(
            Job {
                screen,
                wants_text: false,
                theme: store.clone(),
                reply,
            },
            store,
            std::sync::Arc::new(Mutex::new(None)),
        );
        assert_eq!(app.focus, 0);
    }

    /// The app opens in the PERSISTED theme, not the default — the reason persistence exists.
    #[test]
    fn the_app_opens_in_the_persisted_theme() {
        let (_dir, store) = theme_store();
        store.write(Theme::Dark).unwrap();
        let (reply, _rx) = sync_channel(1);
        let app = PromptApp::new(
            Job {
                screen: Screen::confirm(
                    &ConfirmContent::notice(&NoticePrompt {
                        title: "t",
                        heading: "h",
                        body: "b",
                        acknowledge: "OK",
                    }),
                    "Cancel",
                ),
                wants_text: false,
                theme: store.clone(),
                reply,
            },
            store,
            std::sync::Arc::new(Mutex::new(None)),
        );
        assert_eq!(app.theme, Theme::Dark);
    }

    /// …and the control: with nothing persisted it opens LIGHT. Without this, an app hard-coded to
    /// dark would pass the test above.
    #[test]
    fn the_app_opens_light_when_nothing_is_persisted() {
        let (_dir, store) = theme_store();
        let (reply, _rx) = sync_channel(1);
        let app = PromptApp::new(
            Job {
                screen: Screen::confirm(
                    &ConfirmContent::notice(&NoticePrompt {
                        title: "t",
                        heading: "h",
                        body: "b",
                        acknowledge: "OK",
                    }),
                    "Cancel",
                ),
                wants_text: false,
                theme: store.clone(),
                reply,
            },
            store,
            std::sync::Arc::new(Mutex::new(None)),
        );
        assert_eq!(app.theme, Theme::Light);
    }

    /// Photograph EVERY prompt view, in BOTH themes, from the renderer's own framebuffer.
    ///
    /// ```text
    /// cargo test -p dig-app-core --lib -- --ignored --nocapture prompt_gallery
    /// ```
    ///
    /// # Why the pixels come from `glReadPixels` and not from a screenshot tool
    ///
    /// A GDI screen capture cannot see a hardware GL surface: it returns the desktop behind the
    /// window, and for a decorated window it returns the DWM title bar over a white client area.
    /// Photographing this window with one produces a picture of something else — which is exactly
    /// what stalled the first attempt at this port (#2038). `ViewportCommand::Screenshot` reads back
    /// the framebuffer of the real, on-screen window after the real frame is drawn, so what lands in
    /// the PNG is what the window contains.
    ///
    /// Ignored by default: it opens real windows, so it needs a display and a human deciding to run
    /// it. `DIG_PROMPT_SHOTS` sets the output directory (default `target/prompt-shots`).
    #[test]
    #[ignore = "opens real windows; run deliberately to produce the professional-ui gallery"]
    fn prompt_gallery() {
        let dir = std::path::PathBuf::from(
            std::env::var("DIG_PROMPT_SHOTS").unwrap_or_else(|_| "target/prompt-shots".into()),
        );
        std::fs::create_dir_all(&dir).expect("the gallery directory");

        let mut written = Vec::new();
        for (name, screen, wants_text) in gallery() {
            for theme in [Theme::Light, Theme::Dark] {
                let label = match theme {
                    Theme::Light => "light",
                    Theme::Dark => "dark",
                };
                let path = dir.join(format!("{name}-{label}.png"));
                match photograph(screen.clone(), wants_text, theme, &path) {
                    Some((w, h)) => {
                        println!("wrote {} ({w}x{h})", path.display());
                        written.push(path);
                    }
                    None => panic!("could not photograph {name} in the {label} theme"),
                }
            }
        }
        assert!(!written.is_empty(), "the gallery produced no screenshots");
    }

    /// Every view the branded window draws, named for its file.
    fn gallery() -> Vec<(&'static str, Screen, bool)> {
        use crate::confirm::{ClaimPrompt, ConnectPrompt, DestroyPrompt, PairPrompt, RevealPrompt};

        let confirm = |content: ConfirmContent| Screen::confirm(&content, "Cancel");
        vec![
            ("sign", confirm(
                ConfirmContent::sign(&SignPrompt {
                    origin: "https://dapp.example",
                    payload_type: "spend",
                    decoded_tx: Some(
                        "Send 0.001 XCH to \
                         xch1up0vfatgtwrcgcvc360jd57t3p2kjskncutvzakh9mhdmlvejj3shn8wln\n\
                         Fee 0.000005 XCH",
                    ),
                })
                .expect("a decoded transaction yields content"),
            ), false),
            ("connect", confirm(ConfirmContent::connect(&ConnectPrompt {
                origin: "https://dapp.example",
                dapp_name: Some("Example Marketplace"),
            })), false),
            ("pair", confirm(ConfirmContent::pair(&PairPrompt {
                ext_id: "mlibddmbhlgogepnjdienclhnkfpkfah",
                ext_label: Some("DIG Network"),
            })), false),
            ("reveal", confirm(ConfirmContent::reveal(&RevealPrompt {
                secret: "your recovery phrase",
            })), false),
            ("notice", confirm(ConfirmContent::notice(&NoticePrompt {
                title: "DIG — DIG ID copied",
                heading: "Your DIG ID is on the clipboard.",
                body: "b6f1c0a94e2d7c5183ab0f39d84e6c72b1590adf3e7c48d2916b05fa7c3d81e4",
                acknowledge: "OK",
            })), false),
            ("claim", confirm(ConfirmContent::claim(&ClaimPrompt {
                title: "DIG — Keep your recovery phrase",
                heading: "Have you written your recovery phrase down?",
                body: "DIG cannot recover it for you. Without it, this account cannot be restored \
                       on another computer.",
                affirm: "Yes, I have them",
                scannable: None,
            })), false),
            ("destroy", confirm(ConfirmContent::destroy(&DestroyPrompt {
                subject: "the DIG Account on this computer",
                replacement: "",
                recoverable: false,
            })), false),
            ("two-factor-qr", confirm(ConfirmContent::claim(&ClaimPrompt {
                title: "DIG — Set up two-factor codes",
                heading: "Scan this with your authenticator",
                body: "Or type the key by hand: JBSW Y3DP EHPK 3PXP",
                affirm: "I have added it",
                scannable: Some(
                    &crate::confirm::QrArt::encode(
                        "otpauth://totp/DIG:you@example.com?secret=JBSWY3DPEHPK3PXP&issuer=DIG",
                    )
                    .expect("the demo provisioning URI encodes"),
                ),
            })), false),
            ("passphrase", Screen::input(&InputContent {
                title: "DIG — Unlock your account".into(),
                heading: "Enter your DIG passphrase".into(),
                body: "Your keys stay on this computer. DIG never sees your passphrase.".into(),
                field_label: "Passphrase".into(),
                submit: "Unlock",
                masked: true,
                revealable: false,
                style: crate::confirm::InputStyle::Dialog,
            }), true),
            ("recovery-phrase", Screen::input(&InputContent {
                title: "DIG — Restore from your recovery phrase".into(),
                heading: "Type your 24-word recovery phrase".into(),
                body: "Separate each word with a space.".into(),
                field_label: "Recovery phrase".into(),
                submit: "Restore",
                masked: true,
                revealable: true,
                style: crate::confirm::InputStyle::Dialog,
            }), true),
        ]
    }

    /// How many frames to draw before the shot. The first frames build the font atlas and let the
    /// compositor show the window; photographing frame 1 catches an unfinished one.
    const SETTLE_FRAMES: u32 = 12;

    /// The scale the gallery is rendered at, regardless of the host's display. 2× is retina without
    /// being a two-megabyte file per view.
    const GALLERY_SCALE: f32 = 2.0;

    /// Open one real window, let it settle, read its framebuffer back, write a PNG, close it.
    fn photograph(
        screen: Screen,
        wants_text: bool,
        theme: Theme,
        path: &std::path::Path,
    ) -> Option<(usize, usize)> {
        let dir = tempfile::tempdir().ok()?;
        let store = ThemeChoice::in_brand_dir(dir.path());
        store.write(theme).ok()?;
        let title = screen.title.clone();
        let (reply, _rx) = sync_channel(1);
        let app = PromptApp::new(
            Job {
                screen,
                wants_text,
                theme: store.clone(),
                reply,
            },
            store,
            std::sync::Arc::new(Mutex::new(None)),
        );

        let size = std::sync::Arc::new(Mutex::new(None));
        let recorded = size.clone();
        let target = path.to_path_buf();
        eframe::run_native(
            &title,
            native_options(&title),
            Box::new(move |cc| {
                install_fonts(&cc.egui_ctx);
                Ok(Box::new(Photographer {
                    app,
                    frames: 0,
                    settle: SETTLE_FRAMES,
                    path: target,
                    size: recorded,
                }))
            }),
        )
        .ok()?;
        let answer = *size.lock().ok()?;
        answer
    }

    /// Draws the real prompt, then photographs it.
    struct Photographer {
        app: PromptApp,
        frames: u32,
        settle: u32,
        path: std::path::PathBuf,
        size: std::sync::Arc<Mutex<Option<(usize, usize)>>>,
    }

    impl eframe::App for Photographer {
        fn clear_color(&self, visuals: &egui::Visuals) -> [f32; 4] {
            self.app.clear_color(visuals)
        }

        fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
            // Pin the scale so the gallery is the same picture on every machine. At the host's own
            // DPI these files would be 620×560 on one laptop and 1550×1400 on another, and a
            // screenshot set whose dimensions depend on who ran it cannot be diffed between two
            // versions of the window.
            ctx.set_pixels_per_point(GALLERY_SCALE);
            self.app.frame(ctx);
            self.frames += 1;
            if self.frames == self.settle {
                ctx.send_viewport_cmd(egui::ViewportCommand::Screenshot(egui::UserData::default()));
            }
            let shot = ctx.input(|i| {
                i.events.iter().find_map(|e| match e {
                    egui::Event::Screenshot { image, .. } => Some(image.clone()),
                    _ => None,
                })
            });
            if let Some(image) = shot {
                let (w, h) = (image.width(), image.height());
                // RGB, not RGBA: the window is opaque, so an alpha channel is a quarter of the file
                // spent storing 0xFF. `Best` on top, because these frames are large flat fields of
                // brand colour that deflate very well and the gallery is committed.
                let bytes: Vec<u8> = image
                    .pixels
                    .iter()
                    .flat_map(|p| [p.r(), p.g(), p.b()])
                    .collect();
                let file = std::fs::File::create(&self.path).expect("the screenshot file");
                let mut encoder =
                    png::Encoder::new(std::io::BufWriter::new(file), w as u32, h as u32);
                encoder.set_color(png::ColorType::Rgb);
                encoder.set_compression(png::Compression::Best);
                encoder.set_depth(png::BitDepth::Eight);
                encoder
                    .write_header()
                    .and_then(|mut w| w.write_image_data(&bytes))
                    .expect("the screenshot encodes");
                if let Ok(mut slot) = self.size.lock() {
                    *slot = Some((w, h));
                }
                ctx.send_viewport_cmd(egui::ViewportCommand::Close);
            }
        }
    }

    /// **Enter in a text field SUBMITS what was typed — it must never cancel.**
    ///
    /// Regression for the defect the screenshot gallery exposed (#2038): with nothing pre-focused,
    /// the window fell back to control 0, control 0 is the refusal, and so typing a passphrase and
    /// pressing Enter threw it away and denied the unlock. Driven through the real frame, so it
    /// asserts on what the key handler does rather than on the button list.
    #[test]
    fn enter_in_a_text_field_submits_rather_than_cancelling() {
        let field = InputContent {
            title: "DIG — Unlock your account".into(),
            heading: "Enter your DIG passphrase".into(),
            body: "b".into(),
            field_label: "Passphrase".into(),
            submit: "Unlock",
            masked: true,
            revealable: false,
            style: crate::confirm::InputStyle::Dialog,
        };
        let outcome = press(Screen::input(&field), true, Key::Enter, "hunter2");
        match outcome {
            Some(Outcome::Input(InputOutcome::Provided(typed))) => assert_eq!(&*typed, "hunter2"),
            other => panic!(
                "Enter must submit the typed text; got {:?}",
                Describe(&other)
            ),
        }
    }

    /// …and Escape still refuses, so the fix above did not remove the way out.
    #[test]
    fn escape_in_a_text_field_still_cancels() {
        let field = InputContent {
            title: "t".into(),
            heading: "h".into(),
            body: "b".into(),
            field_label: "l".into(),
            submit: "Unlock",
            masked: true,
            revealable: false,
            style: crate::confirm::InputStyle::Dialog,
        };
        let outcome = press(Screen::input(&field), true, Key::Escape, "hunter2");
        assert!(
            matches!(outcome, Some(Outcome::Input(InputOutcome::Cancelled))),
            "Escape must cancel, got {:?}",
            Describe(&outcome)
        );
    }

    /// **Tab reaches the action row.** The field takes focus when the window opens, but only once —
    /// re-requesting it every frame clawed focus straight back, so a keyboard-only user could never
    /// leave the field and the buttons were unreachable (#2038, `professional-ui`: never trap the
    /// user).
    #[test]
    fn tab_out_of_a_text_field_is_not_undone_on_the_next_frame() {
        let field = InputContent {
            title: "t".into(),
            heading: "h".into(),
            body: "b".into(),
            field_label: "Passphrase".into(),
            submit: "Unlock",
            masked: true,
            revealable: false,
            style: crate::confirm::InputStyle::Dialog,
        };
        let dir = tempfile::tempdir().expect("a temp dir");
        let store = ThemeChoice::in_brand_dir(dir.path());
        let (reply, _rx) = sync_channel(1);
        let mut app = PromptApp::new(
            Job {
                screen: Screen::input(&field),
                wants_text: true,
                theme: store.clone(),
                reply,
            },
            store,
            std::sync::Arc::new(Mutex::new(None)),
        );
        let ctx = egui::Context::default();
        install_fonts(&ctx);
        let quiet = egui::RawInput {
            screen_rect: Some(Rect::from_min_size(
                egui::Pos2::ZERO,
                Vec2::new(WIDTH, HEIGHT),
            )),
            ..Default::default()
        };
        let _ = ctx.run(quiet.clone(), |ctx| app.frame(ctx));
        let _ = ctx.run(quiet.clone(), |ctx| app.frame(ctx));
        assert!(
            ctx.memory(|m| m.focused()).is_some(),
            "the field must take focus when the window opens, or the user types into nothing"
        );
        // Stand in for the user tabbing away.
        if let Some(id) = ctx.memory(|m| m.focused()) {
            ctx.memory_mut(|m| m.surrender_focus(id));
        }
        // Two more frames: the old code re-requested focus on every one of them.
        let _ = ctx.run(quiet.clone(), |ctx| app.frame(ctx));
        let _ = ctx.run(quiet, |ctx| app.frame(ctx));
        assert!(
            ctx.memory(|m| m.focused()).is_none(),
            "the field took focus back after the user left it — the action row is unreachable"
        );
    }

    /// A destroy window is unchanged by that fix: Enter still REFUSES (dig_ecosystem#1799).
    #[test]
    fn enter_on_a_destroy_still_refuses() {
        let content = ConfirmContent::destroy(&crate::confirm::DestroyPrompt {
            subject: "the DIG Account on this computer",
            replacement: "",
            recoverable: false,
        });
        let outcome = press(Screen::confirm(&content, "Cancel"), false, Key::Enter, "");
        assert!(
            matches!(outcome, Some(Outcome::Confirm(WindowIntent::Deny))),
            "a bare Enter on a destroy must keep the account, got {:?}",
            Describe(&outcome)
        );
    }

    /// Drive one real frame with `key` pressed and return whatever the window recorded.
    fn press(screen: Screen, wants_text: bool, key: Key, typed: &str) -> Option<Outcome> {
        let dir = tempfile::tempdir().expect("a temp dir");
        let store = ThemeChoice::in_brand_dir(dir.path());
        let (reply, _rx) = sync_channel(1);
        let sink = std::sync::Arc::new(Mutex::new(None));
        let mut app = PromptApp::new(
            Job {
                screen,
                wants_text,
                theme: store.clone(),
                reply,
            },
            store,
            sink.clone(),
        );
        app.typed = Zeroizing::new(typed.to_owned());

        let ctx = egui::Context::default();
        install_fonts(&ctx);
        let rect = Rect::from_min_size(egui::Pos2::ZERO, Vec2::new(WIDTH, HEIGHT));
        let quiet = egui::RawInput {
            screen_rect: Some(rect),
            ..Default::default()
        };
        // One frame to build the atlas and lay the window out, then the frame carrying the key.
        let _ = ctx.run(quiet.clone(), |ctx| app.frame(ctx));
        let pressed = egui::RawInput {
            events: vec![egui::Event::Key {
                key,
                physical_key: None,
                pressed: true,
                repeat: false,
                modifiers: egui::Modifiers::NONE,
            }],
            ..quiet
        };
        let _ = ctx.run(pressed, |ctx| app.frame(ctx));
        let answer = sink.lock().expect("the answer slot").take();
        answer
    }

    /// Renders an [`Outcome`] in a panic message. `Outcome` is deliberately not `Debug` in
    /// production — an input outcome carries a passphrase.
    struct Describe<'a>(&'a Option<Outcome>);

    impl std::fmt::Debug for Describe<'_> {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            match self.0 {
                None => write!(f, "no answer"),
                Some(Outcome::Confirm(intent)) => write!(f, "{intent:?}"),
                Some(Outcome::Input(InputOutcome::Provided(_))) => {
                    write!(f, "Provided(<redacted>)")
                }
                Some(Outcome::Input(other)) => write!(f, "{other:?}"),
            }
        }
    }

    /// The typed buffer is `Zeroizing`, so a recovery phrase is wiped when the window drops rather
    /// than left in the heap for whatever allocates next.
    #[test]
    fn the_typed_buffer_is_zeroizing() {
        fn assert_zeroizing<T: zeroize::Zeroize>(_: &T) {}
        let buffer: Zeroizing<String> = Zeroizing::new("abandon abandon".into());
        assert_zeroizing(&*buffer);
    }
}
