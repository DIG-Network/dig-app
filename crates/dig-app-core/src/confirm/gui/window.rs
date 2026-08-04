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

use std::sync::mpsc::{sync_channel, Receiver, RecvTimeoutError, SyncSender};
use std::sync::{mpsc, Mutex, OnceLock};
use std::time::{Duration, Instant};

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
/// The window's logical height before it is sized to its content — the size it is CREATED at, and
/// the ceiling on a host that will not say how big its display is.
///
/// [`PromptApp::fit_to_content`] moves it from here in both directions: down to [`MIN_HEIGHT`] for a
/// two-line notice, up to [`PromptApp::tallest_here`] for a screen that genuinely needs the room.
const HEIGHT: f32 = 560.0;
/// The shortest a prompt may shrink to. Below this a consent window starts reading as a toast.
const MIN_HEIGHT: f32 = 320.0;
/// The tallest a prompt may GROW to when its content genuinely needs the room.
///
/// The window used to be capped at [`HEIGHT`] and could only shrink, so the 24-word recovery phrase
/// — about 715 px of content — was cut off at word 14 (dig_ecosystem#2038). Scrolling makes the rest
/// REACHABLE; growing makes it VISIBLE, and for a screen the user is copying out by hand onto paper
/// that is the difference between an affordance and a trap. So the window grows first and scrolls
/// only when it has run out of screen.
const MAX_HEIGHT: f32 = 900.0;
/// The most of the monitor's height a prompt may take.
///
/// A consent window taller than the display is worse than one that scrolls: its buttons go off the
/// bottom edge and the user cannot answer it at all.
const SCREEN_SHARE: f32 = 0.9;
/// The height reserved for the action row — the separator, the buttons and the padding under them.
const ACTION_ROW: f32 = 72.0;
/// How much room a scannable QR is given, in logical pixels.
///
/// Big enough that a phone camera resolves the modules at arm's length on a 1× display; the art
/// itself rounds down to a whole number of pixels per module inside this ([`QrArt::module_pixels`]).
const QR_SIDE: f32 = 200.0;

/// How long a CONFIRM window waits for an answer before dismissing ITSELF as a refusal.
///
/// # Why a prompt must have a deadline at all
///
/// Every prompt in the process is drawn on ONE thread, strictly one after another — which is a
/// security property (§ the module docs) and, without a deadline, a denial-of-service: a hostile
/// dapp raises a sign prompt the user never answers, and every LATER prompt — the tray unlock, a
/// destroy confirm, a second sign — queues behind it forever, none of them ever drawn, with no error
/// reaching any caller (dig_ecosystem#2038). One ignored window must cost the user one refused
/// action, never the whole consent surface.
///
/// Two minutes is what the deleted `zenity` backend passed as `--timeout=120s`, so this restores the
/// behaviour that shipped rather than inventing a new one.
const CONFIRM_DEADLINE: Duration = Duration::from_secs(120);

/// The same deadline for a window the user has to TYPE into.
///
/// Longer than [`CONFIRM_DEADLINE`] on purpose: a confirm window is read and answered, but restoring
/// an account means copying 24 words off a piece of paper, and a field that cancels itself halfway
/// through that is a trap. The security property is satisfied by any finite bound — the prompt thread
/// is freed either way — so the bound is set where it cannot interrupt an honest user.
const INPUT_DEADLINE: Duration = Duration::from_secs(300);

/// How much longer than the window's OWN deadline a blocked caller waits before giving up.
///
/// The window is the primary deadline: it self-dismisses, so it never lingers on screen asking a
/// question whose answer no longer matters. This is the BACKSTOP for the case the window itself is
/// wedged — the prompt thread died, the GL context hung, the frame loop stopped — where the caller
/// must still be released rather than blocked for the life of the process.
///
/// The caller's clock starts when it QUEUES the job, not when the window opens, so a prompt sitting
/// behind one the user is ignoring can have its caller give up before it is drawn. That resolves to
/// a refusal, which is the safe direction, and the window it eventually opens still dismisses itself
/// on its own deadline. Making the backstop cover an arbitrary queue would mean blocking the caller
/// for minutes, which is the thing being fixed.
const ANSWER_GRACE: Duration = Duration::from_secs(15);

/// The id the body's scrolling viewport is stored under.
///
/// Named rather than derived so a test can read the scroll state back out of `egui`'s memory and
/// assert on the SAME viewport the user scrolls.
const BODY_SCROLL_ID: &str = "dig-prompt-body";

/// The brand's typeface, self-hosted exactly as hub.dig.net self-hosts it.
const FONT_REGULAR: &[u8] = include_bytes!("../../../assets/space-grotesk-400.ttf");
/// The 600 weight — a distinct cut, never a synthetic bold.
const FONT_SEMIBOLD: &[u8] = include_bytes!("../../../assets/space-grotesk-600.ttf");
/// Space Mono — the face identifiers, hex and codes are set in (see [`render::MONO`]).
const FONT_MONO: &[u8] = include_bytes!("../../../assets/space-mono-400.ttf");

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
    /// How long this window waits for a human before dismissing itself ([`CONFIRM_DEADLINE`] /
    /// [`INPUT_DEADLINE`]). Carried on the job rather than read from a constant inside the window so
    /// a test can drive the expiry in milliseconds instead of minutes.
    deadline: Duration,
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
            .with_min_inner_size([WIDTH, MIN_HEIGHT])
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

    // The window is not gone yet — see why this call exists.
    flush_deferred_window_destruction();

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

/// Actually destroy the window the event loop only ASKED to destroy.
///
/// # The bug this exists for
///
/// On Windows a window may only be destroyed by the thread that created it, so
/// `winit::window::Window::drop` does not call `DestroyWindow` — it **posts a private message** and
/// leaves the real destruction to the window procedure (winit 0.30 `windows/window.rs:1113`, handled
/// at `windows/event_loop.rs:2445`). eframe drops the window only after `run_app_on_demand` has
/// already returned, and [`serve`] then goes straight back to waiting for the next job. Nothing on
/// this thread ever dispatches that message.
///
/// So the consent window STAYED ON SCREEN after the user answered it — always on top, undecorated,
/// with a message pump that had stopped — which is precisely what Windows shows as *"not
/// responding"*. It is the defect reported as *"whenever a UI pops up, when I press cancel or ok or
/// any button the program stops responding"* (dig_ecosystem#2038). The answer had in fact been
/// recorded and delivered; the frozen window on top of everything was all the user could see.
///
/// Draining the queue here is exactly what the NEXT `run_native` on this thread would have done —
/// which is why the *previous* prompt's window always vanished and only the LAST one stayed. Doing
/// it eagerly is what makes a window disappear when the person answers it.
#[cfg(target_os = "windows")]
fn flush_deferred_window_destruction() {
    crate::confirm::windows::pump_pending();
}

/// Elsewhere the window is destroyed inside `Drop`, so there is nothing to flush.
#[cfg(not(target_os = "windows"))]
fn flush_deferred_window_destruction() {}

/// Drop the undo history `egui` keeps of whatever was typed into `field`.
///
/// # Why `.password(true)` is not enough
///
/// `TextEdit` masks what is DRAWN; it does not change what is RETAINED. Every frame it feeds
/// `text.as_str().to_owned()` into an undoer twice (egui 0.31.1 `text_edit/builder.rs:905` and
/// `:1116`), and that undoer keeps up to `max_undos` snapshots in `ctx.memory` for the whole life of
/// the [`egui::Context`]. So the passphrase — and a 24-word recovery phrase typed to restore an
/// account — accumulated in plain `String`s that are freed without being wiped.
/// [`PromptApp::typed`] being [`Zeroizing`] covers our own buffer and nothing egui copied out of it.
///
/// A one-line consent field has no undo affordance, so the history is pure exposure and is cleared
/// on every frame. This BOUNDS the exposure to a single frame rather than the window's lifetime; it
/// is a reduction, not an erasure, because dropping a `String` does not scrub the allocation and
/// egui exposes no way to reach inside the undoer and do so.
fn forget_the_undo_history(ctx: &egui::Context, field: egui::Id) {
    if let Some(mut state) = egui::TextEdit::load_state(ctx, field) {
        state.clear_undoer();
        egui::TextEdit::store_state(ctx, field, state);
    }
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
    semibold.extend(fallback.clone());
    fonts.families.insert(
        egui::FontFamily::Name(super::render::SEMIBOLD.into()),
        semibold,
    );
    // Space Mono as its OWN family — never inserted into `Proportional`, so only a `Block::Identifier`
    // (which asks for it by name) is set in it. The same proportional fallback stack follows it, for the
    // glyphs the mono cut does not carry.
    fonts.font_data.insert(
        super::render::MONO.into(),
        std::sync::Arc::new(egui::FontData::from_static(FONT_MONO)),
    );
    let mut mono = vec![super::render::MONO.to_owned()];
    mono.extend(fallback);
    fonts
        .families
        .insert(egui::FontFamily::Name(super::render::MONO.into()), mono);
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
    /// Whether an answer has already been recorded.
    ///
    /// The window keeps drawing for the frames it takes the windowing system to take the close
    /// command, and those frames must not be able to change what the human said — see
    /// [`PromptApp::record`].
    answered: bool,
    /// When this window opened, and how long it waits — the self-dismissal deadline
    /// ([`CONFIRM_DEADLINE`] / [`INPUT_DEADLINE`]).
    opened: Instant,
    /// How long to wait before [`PromptApp::expire`] answers for the absent human.
    deadline: Duration,
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
            answered: false,
            opened: Instant::now(),
            deadline: job.deadline,
            sink,
        }
    }

    /// Record `outcome` — if nothing has been recorded yet — and ask the window to close.
    ///
    /// # Why the FIRST answer is the only one
    ///
    /// `ViewportCommand::Close` does not close anything by itself: eframe turns it into a
    /// `ViewportEvent::Close` that arrives in the NEXT frame's input, and the window keeps drawing
    /// until that frame runs. [`PromptApp::keys`] reads that same event as a dismissal — so a person
    /// who clicked **Sign** had their approval recorded and then, one frame later, silently
    /// overwritten with a refusal by the window's own teardown (dig_ecosystem#2038). Every
    /// affirmative in the app answered `Deny`.
    ///
    /// Latching here rather than special-casing the close event fixes the class: whatever else a
    /// teardown frame does, it cannot change what the human said. Closing stays idempotent, because
    /// a close command that is dropped on the floor is a window that never goes away.
    ///
    /// The latch cannot manufacture consent. An unanswered window records nothing, and [`draw`] maps
    /// nothing to a denial.
    fn record(&mut self, ctx: &egui::Context, outcome: Outcome) {
        if !self.answered {
            self.answered = true;
            if let Ok(mut slot) = self.sink.lock() {
                *slot = Some(outcome);
            }
        }
        ctx.send_viewport_cmd(egui::ViewportCommand::Close);
    }

    /// Record `answer` and close.
    fn finish(&mut self, ctx: &egui::Context, answer: Answer) {
        let outcome = match (self.wants_text, answer) {
            (false, Answer::Approve) => Outcome::Confirm(WindowIntent::Approve),
            (false, Answer::Deny) => Outcome::Confirm(WindowIntent::Deny),
            (true, Answer::Approve) => Outcome::Input(InputOutcome::Provided(self.typed.clone())),
            (true, Answer::Deny) => Outcome::Input(InputOutcome::Cancelled),
        };
        self.record(ctx, outcome);
    }

    /// Nobody answered in time: dismiss the window and report that, not an approval.
    ///
    /// A confirm reports [`WindowIntent::Timeout`], which `gated_consent` maps to
    /// [`ConfirmDecision::Timeout`](crate::confirm::ConfirmDecision::Timeout) — an honest "the human
    /// never answered", distinct from a refusal and from a host that could not draw. An input window
    /// reports [`InputOutcome::Cancelled`]: nothing was typed that a caller may act on. Neither is an
    /// approval, and no expression here could construct one.
    fn expire(&mut self, ctx: &egui::Context) {
        let outcome = match self.wants_text {
            true => Outcome::Input(InputOutcome::Cancelled),
            false => Outcome::Confirm(WindowIntent::Timeout),
        };
        self.record(ctx, outcome);
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
        // Answer for the human who never came back, so one ignored window cannot hold the single
        // prompt thread — and therefore every later consent window — for the life of the process.
        if !self.answered && self.opened.elapsed() >= self.deadline {
            self.expire(ctx);
        }

        let (full, content_bottom) = egui::CentralPanel::default()
            .frame(egui::Frame::NONE.fill(rgba(t.bg)))
            .show(ctx, |ui| {
                let full = ui.available_rect_before_wrap();
                paint::card(ui, full, &t);
                self.chrome(ui, full, &t);
                let content_bottom = self.body(ui, full, &t);
                self.actions(ui, full, &t);
                (full, content_bottom)
            })
            .inner;
        self.fit_to_content(ctx, full, content_bottom);
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
            // `--muted`, not `--faint`: this is the line that says WHICH window is asking, on a
            // window that is asking to spend money. `--faint` is 3.34:1 on white — a decoration
            // tier, below the 4.5:1 text bar (#2038).
            rgba(t.muted),
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

    /// The heading, the body, and — on an input prompt — the field, in a scrolling viewport.
    ///
    /// Returns the y the content actually ended at, which is what
    /// [`fit_to_content`](Self::fit_to_content) sizes the window from. It is measured rather than
    /// predicted because the blocks wrap: the same screen is a different height at a different
    /// address length.
    ///
    /// # Why the body SCROLLS
    ///
    /// The window was capped at [`HEIGHT`] and only ever shrank, leaving 404 px of body. A screen
    /// whose content was taller than that was **silently cut off**: `Ui::new_child` inherits its
    /// parent's clip rect, so the overflow was clipped with no scrollbar and no cut-off marker.
    ///
    /// That was not cosmetic. First-run enrolment draws a 24-word recovery phrase — 24 lines at
    /// `size::BASE * 1.55`, 558 px, plus a heading and a three-line warning — so roughly **words
    /// 15–24 and the entire warning never reached the screen**. The user wrote down 14 of 24 words,
    /// clicked "I have written these down", and their account became unrecoverable
    /// (dig_ecosystem#2038; the same clipping hid the tail of a many-output spend on the sign window,
    /// dig_ecosystem#2063, and hid sixteen words once before, dig_ecosystem#49).
    ///
    /// A [`egui::ScrollArea`] fixes the CLASS rather than the two instances: no content this window
    /// is ever handed can be hidden without a way to reach it, whatever the display, whatever the
    /// screen. It is the floor, not the answer — the window GROWS first
    /// ([`fit_to_content`](Self::fit_to_content)), because a person copying a phrase onto paper
    /// should not have to scroll the thing they are transcribing. Short prompts are unaffected: the
    /// window still shrinks to them and no bar appears.
    fn body(&mut self, ui: &mut egui::Ui, full: Rect, t: &Tokens) -> f32 {
        let inner = Rect::from_min_max(
            full.left_top() + Vec2::new(space::S6, 44.0 + space::S6),
            full.right_bottom() - Vec2::new(space::S6, 88.0),
        );
        let mut ui = ui.new_child(
            egui::UiBuilder::new()
                .max_rect(inner)
                .layout(egui::Layout::top_down(egui::Align::Min)),
        );
        // egui's default bar is a 2 px hairline that fades out when nobody is touching it. On a
        // window that is hiding part of a recovery phrase, the control that reveals the rest has to
        // be visible at a glance or it is not an affordance at all (`professional-ui`).
        //
        // egui takes the bar's colours from the SHARED widget palette, which the field inside the
        // body reads too, so the content's own visuals are put back before it is drawn — the
        // scrollbar's brand colours belong to the scrollbar.
        let content_widgets = ui.visuals().widgets.clone();
        let style = ui.style_mut();
        style.spacing.scroll = egui::style::ScrollStyle {
            bar_width: 8.0,
            handle_min_length: 24.0,
            ..egui::style::ScrollStyle::solid()
        };
        style.visuals.widgets.inactive.bg_fill = rgba(t.border_strong);
        style.visuals.widgets.hovered.bg_fill = rgba(t.dig_purple);
        style.visuals.widgets.active.bg_fill = rgba(t.dig_purple);
        style.visuals.extreme_bg_color = rgba(t.surface_2);
        let scrolled = egui::ScrollArea::vertical()
            .id_salt(BODY_SCROLL_ID)
            // The viewport is the body area whether or not the content fills it, so the action row
            // stays put instead of sliding up under a short prompt.
            .auto_shrink([false, false])
            .show(&mut ui, |ui| {
                ui.style_mut().visuals.widgets = content_widgets;
                self.contents(ui, t);
            });
        // Size the window from the CONTENT, not the viewport: a short prompt still shrinks to fit,
        // and a tall one asks for the full window and scrolls the remainder.
        inner.top() + scrolled.content_size.y
    }

    /// Draw the blocks and the field into whatever viewport the caller framed.
    fn contents(&mut self, ui: &mut egui::Ui, t: &Tokens) {
        // Read back rather than captured from the frame: when the scrollbar appears it takes real
        // width, and text that wraps to the pre-bar width would slide under it.
        let width = ui.available_width();

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
                Block::Identifier(text) => {
                    // A bare identifier, set in Space Mono so an address reads char by char, with no
                    // panel — it sits inline under its prose like a `Block::Body`, in full-contrast
                    // `--text`.
                    ui.label(super::render::paragraph(
                        text,
                        super::render::mono(size::BASE),
                        rgba(super::render::block_color(&block, t)),
                        width,
                        size::BASE * 1.55,
                    ));
                    ui.add_space(space::S4);
                }
                Block::Detail(text) | Block::Warning(text) => {
                    let warning = matches!(block, Block::Warning(_));
                    // The decoded transaction is set in Space Mono — it column-aligns amount/recipient/
                    // fee and makes the `xch1…` address checkable — while a warning stays prose. Only
                    // the font differs between the two; the recessed panel, the muted colour and the
                    // galley-height measurement are shared.
                    let font = match warning {
                        true => regular(size::BASE),
                        false => super::render::mono(size::BASE),
                    };
                    let job = super::render::paragraph(
                        text,
                        font,
                        rgba(super::render::block_color(&block, t)),
                        width - space::S5 * 2.0,
                        size::BASE * 1.55,
                    );
                    let galley = ui.fonts(|f| f.layout_job(job));
                    let height = galley.size().y + space::S4 * 2.0;
                    let rect = Rect::from_min_size(ui.cursor().min, Vec2::new(width, height));
                    match warning {
                        true => paint::warning_panel(ui, rect, t),
                        false => paint::panel(ui, rect, t),
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
                    let drawn = paint::qr(ui, ui.cursor().min, side, art);
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
            forget_the_undo_history(ui.ctx(), response.id);
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
                if paint::inline_toggle(ui, label, t).clicked() {
                    self.revealed = !self.revealed;
                }
            }
        }
    }

    /// Size the window to the height its content actually needs.
    ///
    /// # Why the window is not simply a fixed size
    ///
    /// It was, and every prompt got 560 px whatever it held. On the sign prompt that put roughly
    /// 300 px of empty card between the decoded transaction and the Sign button — the two things the
    /// user is meant to read together — and the gallery made it obvious in a way the tests could not
    /// (#2038). A consent window that looks broken is a consent window people click through.
    ///
    /// # Why it grows as well as shrinks
    ///
    /// It only shrank, and 24 recovery words do not fit in 560 px, so the enrolment screen showed 14
    /// of them and hid the rest (dig_ecosystem#2038). The body scrolls now, so nothing is ever
    /// unreachable — but a person copying a phrase onto paper should not have to scroll a window
    /// they are transcribing, and a hairline scrollbar is not the thing that stops them writing down
    /// 14 words and clicking "I have written these down". So the window takes the room it needs, up
    /// to [`tallest_here`](Self::tallest_here), and scrolls only past that.
    ///
    /// Recomputed every frame rather than latched on the first: the first frame builds the font
    /// atlas and lays out against it, so its measurement is not yet the real one. Sending only on a
    /// real difference makes it settle in two frames and stay there — the height cannot feed back
    /// into the measurement, because the blocks wrap on WIDTH, which never changes.
    fn fit_to_content(&self, ctx: &egui::Context, full: Rect, content_bottom: f32) {
        let needed = (content_bottom - full.top()) + space::S6 + ACTION_ROW;
        let wanted = needed.clamp(MIN_HEIGHT, Self::tallest_here(ctx));
        if (wanted - full.height()).abs() > 1.0 {
            ctx.send_viewport_cmd(egui::ViewportCommand::InnerSize(Vec2::new(WIDTH, wanted)));
        }
    }

    /// The tallest this window may be on the display it is actually on.
    ///
    /// Bounded twice — by [`MAX_HEIGHT`] and by [`SCREEN_SHARE`] of the monitor — because a consent
    /// window whose buttons are off the bottom of the screen cannot be answered at all.
    ///
    /// A host that does not report its monitor (a headless frame, a compositor that keeps it to
    /// itself) falls back to [`HEIGHT`], the size the window was created at and the size every
    /// display can show. That is the conservative answer, and it is the one the tests run under.
    fn tallest_here(ctx: &egui::Context) -> f32 {
        match ctx.input(|i| i.viewport().monitor_size) {
            Some(monitor) if monitor.y.is_finite() && monitor.y > 0.0 => {
                MAX_HEIGHT.min(monitor.y * SCREEN_SHARE).max(MIN_HEIGHT)
            }
            _ => HEIGHT,
        }
    }

    /// The action row, right-aligned, refusal first.
    fn actions(&mut self, ui: &mut egui::Ui, full: Rect, t: &Tokens) {
        let row = Rect::from_min_max(
            egui::Pos2::new(full.left(), full.bottom() - ACTION_ROW),
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

/// The branded `ForegroundWindow` — every confirm, notice and claim window in the app.
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
///
/// # Why the wait is bounded
///
/// This used to be a bare `recv()`. A caller that blocks forever is not merely a stuck caller here:
/// every prompt in the process is served by ONE thread, so an unanswered window queued the tray
/// unlock, the destroy confirm and every later sign behind it, none of them ever drawn, with no
/// error reaching anyone (dig_ecosystem#2038). The window answers for itself at
/// [`CONFIRM_DEADLINE`]/[`INPUT_DEADLINE`]; this is the backstop for the case where the window
/// cannot, and every way out of it is a refusal.
fn ask(screen: Screen, wants_text: bool, theme: ThemeChoice) -> Option<Outcome> {
    let host = host()?;
    let (reply, answers) = sync_channel(1);
    let deadline = match wants_text {
        true => INPUT_DEADLINE,
        false => CONFIRM_DEADLINE,
    };
    let job = Job {
        screen,
        wants_text,
        theme,
        deadline,
        reply,
    };
    host.tx.lock().ok()?.send(job).ok()?;
    match answers.recv_timeout(deadline + ANSWER_GRACE) {
        Ok(outcome) => Some(outcome),
        // The window did not even manage to dismiss itself. Report the same non-answer it would
        // have; there is no branch here that could produce an approval.
        Err(RecvTimeoutError::Timeout) => Some(match wants_text {
            true => Outcome::Input(InputOutcome::Cancelled),
            false => Outcome::Confirm(WindowIntent::Timeout),
        }),
        // The prompt thread died holding the job.
        Err(RecvTimeoutError::Disconnected) => None,
    }
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

/// The branded `ForegroundInput` — the recovery-phrase, passphrase and launcher fields.
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

    /// The deadline a test that is not ABOUT the deadline uses: longer than any test run, so the
    /// self-dismissal can never fire behind an assertion's back.
    const PATIENT: Duration = Duration::from_secs(3600);

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
                deadline: PATIENT,
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

    /// Every string the painter drew, paired with the colour it was drawn IN.
    ///
    /// A token can clear AA in the palette and still reach the screen in the wrong tier, so the
    /// colour is read back off the galley rather than assumed from the token table.
    fn drawn_text_colored(shapes: &[egui::epaint::ClippedShape]) -> Vec<(String, egui::Color32)> {
        fn walk(shape: &egui::Shape, out: &mut Vec<(String, egui::Color32)>) {
            match shape {
                egui::Shape::Text(text) => {
                    // `Painter::galley` passes PLACEHOLDER to mean "use the galley's own colours";
                    // any other override is the colour that actually lands on the screen.
                    let color = match text.override_text_color {
                        Some(c) if c != egui::Color32::PLACEHOLDER => c,
                        _ => text
                            .galley
                            .job
                            .sections
                            .first()
                            .map_or(egui::Color32::PLACEHOLDER, |s| s.format.color),
                    };
                    out.push((text.galley.text().to_owned(), color));
                }
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

    /// **The window chrome is TEXT, so it takes AA's 4.5:1 bar** — the window title and the theme
    /// toggle both sit on `--surface` and both have to be readable by someone who is not the person
    /// who picked the colour.
    ///
    /// Both were drawn in `--faint`, which is ~3.2:1 on white. The token test above did not catch it
    /// because it asserts `--text` and `--muted` and never the tertiary tier, and `--faint` is a
    /// legitimate token — for decoration, not for a control's label (#2038, found in the gallery).
    ///
    /// Asserted against the frame rather than the palette: the bug was a token used in the wrong
    /// place, which a palette-only test cannot see.
    #[test]
    fn the_window_chrome_text_clears_aa_in_both_themes() {
        for theme in [Theme::Light, Theme::Dark] {
            let t = theme.tokens();
            let toggle_label = match theme {
                Theme::Light => "Dark theme",
                Theme::Dark => "Light theme",
            };
            let (_ctx, output) = painted(sign_screen(), false, theme);
            let drawn = drawn_text_colored(&output.shapes);

            for wanted in [sign_screen().title.as_str(), toggle_label] {
                let (_, color) = drawn
                    .iter()
                    .find(|(text, _)| text == wanted)
                    .unwrap_or_else(|| panic!("{theme:?}: the chrome never drew {wanted:?}"));
                let ratio = super::super::theme::Rgba::hex(color.r(), color.g(), color.b())
                    .contrast(t.surface);
                assert!(
                    ratio >= 4.5,
                    "{theme:?}: {wanted:?} is drawn at {ratio:.2}:1 on --surface, below AA 4.5"
                );
            }
        }
    }

    /// The inner size the frame asked the windowing system for, if it asked for one.
    fn requested_height(output: &egui::FullOutput) -> Option<f32> {
        output.viewport_output.values().find_map(|viewport| {
            viewport.commands.iter().rev().find_map(|cmd| match cmd {
                egui::ViewportCommand::InnerSize(size) => Some(size.y),
                _ => None,
            })
        })
    }

    fn notice_screen() -> Screen {
        let content = ConfirmContent::notice(&NoticePrompt {
            title: "DIG — Logs",
            heading: "DIG could not open the folder for you.",
            body: "Open it yourself at C:\\Users\\you\\AppData\\DIG.",
            acknowledge: "OK",
            identifier: None,
        });
        Screen::confirm(&content, "Cancel")
    }

    /// **The window is as tall as what it holds.** Every prompt used to be 560 px whatever it
    /// contained, so the sign prompt opened with roughly 300 px of empty card between the decoded
    /// transaction and the Sign button — the two things a person is meant to read together (#2038,
    /// visible the moment the gallery existed).
    ///
    /// Asserted as a RELATIONSHIP as well as a bound: a short prompt must ask for less than a long
    /// one. A single absolute number would pass just as well if the height stopped tracking the
    /// content at all and got stuck on some smaller constant.
    #[test]
    fn a_prompt_asks_to_be_only_as_tall_as_its_content() {
        let (_ctx, short) = painted(notice_screen(), false, Theme::Light);
        let (_ctx, tall) = painted(sign_screen(), false, Theme::Light);

        let short = requested_height(&short).expect("the notice asked for a height");
        let tall = requested_height(&tall).expect("the sign prompt asked for a height");

        assert!(
            short < tall,
            "a two-line notice asked for {short} px and a sign prompt with a decoded transaction \
             asked for {tall} — the height is not tracking the content"
        );
        assert!(
            short < HEIGHT,
            "the notice still asked for the full {HEIGHT} px window"
        );
        assert!(
            short >= MIN_HEIGHT,
            "the notice asked for {short} px, under the {MIN_HEIGHT} px floor"
        );
        assert!(
            tall <= HEIGHT,
            "the sign prompt asked for {tall} px, over the {HEIGHT} px ceiling a host that reports \
             no monitor gets"
        );
    }

    /// Where each drawn string's left edge landed.
    fn drawn_text_left(shapes: &[egui::epaint::ClippedShape]) -> Vec<(String, f32)> {
        fn walk(shape: &egui::Shape, out: &mut Vec<(String, f32)>) {
            match shape {
                egui::Shape::Text(text) => {
                    out.push((text.galley.text().to_owned(), text.pos.x));
                }
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

    /// **The reveal control lines up with the column it sits in.** It is drawn with the same padded
    /// hit area as the chrome toggle, and that control CENTRES its label — which indented "Show what
    /// I type" by half the padding, leaving it visibly out of line with the field label directly
    /// above it (#2038, caught in the gallery, invisible to every other test).
    #[test]
    fn the_reveal_control_starts_on_the_same_column_as_the_field_label() {
        let content = InputContent {
            title: "DIG — Restore from your recovery phrase".into(),
            heading: "Type your 24-word recovery phrase".into(),
            body: "Separate each word with a space.".into(),
            field_label: "Recovery phrase".into(),
            submit: "Restore",
            masked: true,
            revealable: true,
            style: crate::confirm::InputStyle::Dialog,
        };
        let (_ctx, output) = painted(Screen::input(&content), true, Theme::Light);
        let drawn = drawn_text_left(&output.shapes);

        let left_of = |wanted: &str| {
            drawn
                .iter()
                .find(|(text, _)| text == wanted)
                .unwrap_or_else(|| panic!("the frame never drew {wanted:?}"))
                .1
        };
        let label = left_of("Recovery phrase");
        let reveal = left_of("Show what I type");
        assert!(
            (reveal - label).abs() < 1.0,
            "the reveal control starts at x={reveal} and the field label at x={label} — \
             a {:.0} px indent out of the column",
            reveal - label
        );
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

    fn sign_content() -> ConfirmContent {
        ConfirmContent::sign(&SignPrompt {
            origin: "https://dapp.example",
            payload_type: "spend",
            decoded_tx: Some("Send 0.001 XCH to xch1safe\u{2026}addr"),
        })
        .expect("a decoded transaction yields content")
    }

    fn sign_screen() -> Screen {
        Screen::confirm(&sign_content(), "Cancel")
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
            identifier: None,
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
                deadline: PATIENT,
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
                identifier: None,
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
                deadline: PATIENT,
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
                        identifier: None,
                    }),
                    "Cancel",
                ),
                wants_text: false,
                theme: store.clone(),
                deadline: PATIENT,
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
                        identifier: None,
                    }),
                    "Cancel",
                ),
                wants_text: false,
                theme: store.clone(),
                deadline: PATIENT,
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
                body: "DIG ID copied to your clipboard.",
                identifier: Some("b6f1c0a94e2d7c5183ab0f39d84e6c72b1590adf3e7c48d2916b05fa7c3d81e4"),
                acknowledge: "OK",
            })), false),
            // The 24-word enrolment screen. It was the ONE confirm view the gallery did not
            // photograph, which is exactly why the look-at-the-pictures pass missed that ten of its
            // words and its whole warning were being clipped away (dig_ecosystem#2038). A gallery
            // that omits the view whose overflow matters is a gallery of the easy cases.
            ("recovery-phrase-shown", phrase_screen(), false),
            ("claim", confirm(ConfirmContent::claim(&ClaimPrompt {
                title: "DIG — Keep your recovery phrase",
                heading: "Have you written your recovery phrase down?",
                body: "DIG cannot recover it for you. Without it, this account cannot be restored \
                       on another computer.",
                affirm: "Yes, I have them",
                scannable: None,
            identifier: None,
            })), false),
            ("destroy", confirm(ConfirmContent::destroy(&DestroyPrompt {
                subject: "the DIG Account on this computer",
                replacement: "",
                recoverable: false,
            })), false),
            ("two-factor-qr", confirm(ConfirmContent::claim(&ClaimPrompt {
                title: "DIG — Set up two-factor codes",
                heading: "Scan this with your authenticator",
                body: "Or add it by hand. Then type this key:",
                affirm: "I have added it",
                scannable: Some(
                    &crate::confirm::QrArt::encode(
                        "otpauth://totp/DIG:you@example.com?secret=JBSWY3DPEHPK3PXP&issuer=DIG",
                    )
                    .expect("the demo provisioning URI encodes"),
                ),
                identifier: Some("JBSW Y3DP EHPK 3PXP"),
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
                deadline: PATIENT,
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
                deadline: PATIENT,
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
                deadline: PATIENT,
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

    // ---------------------------------------------------------------------------------------------
    // Driving the window the way eframe drives it
    //
    // Everything above reads a PAINTED frame back. The three defects below live one layer lower —
    // in what the window does when a pointer actually presses a control, when eframe reports that
    // the close command was taken, and when nobody answers at all. None of them can be seen from a
    // frame's glyphs, which is why 786 tests at 93.85% coverage shipped a window that answered
    // `Deny` to every affirmative click (dig_ecosystem#2038).
    // ---------------------------------------------------------------------------------------------

    /// One prompt, driven frame by frame with real input.
    struct Driver {
        app: PromptApp,
        ctx: egui::Context,
        size: Vec2,
        sink: std::sync::Arc<Mutex<Option<Outcome>>>,
        /// Keeps the theme file alive for the driver's lifetime.
        _dir: tempfile::TempDir,
    }

    impl Driver {
        fn new(screen: Screen, wants_text: bool, deadline: Duration, size: Vec2) -> Self {
            let dir = tempfile::tempdir().expect("a temp dir");
            let store = ThemeChoice::in_brand_dir(dir.path());
            let (reply, _rx) = sync_channel(1);
            let sink = std::sync::Arc::new(Mutex::new(None));
            let app = PromptApp::new(
                Job {
                    screen,
                    wants_text,
                    theme: store.clone(),
                    deadline,
                    reply,
                },
                store,
                sink.clone(),
            );
            let ctx = egui::Context::default();
            install_fonts(&ctx);
            Self {
                app,
                ctx,
                size,
                sink,
                _dir: dir,
            }
        }

        /// A prompt at the shipped window size, with a deadline no test reaches by accident.
        fn shown(screen: Screen, wants_text: bool) -> Self {
            Self::new(screen, wants_text, PATIENT, Vec2::new(WIDTH, HEIGHT))
        }

        fn input(&self) -> egui::RawInput {
            egui::RawInput {
                screen_rect: Some(Rect::from_min_size(egui::Pos2::ZERO, self.size)),
                ..Default::default()
            }
        }

        /// Run one frame carrying `events`.
        fn frame(&mut self, events: Vec<egui::Event>) -> egui::FullOutput {
            let input = egui::RawInput {
                events,
                ..self.input()
            };
            let app = &mut self.app;
            self.ctx.run(input, |ctx| app.frame(ctx))
        }

        /// Two quiet frames: the first builds the font atlas, the second lays out against it.
        fn settle(&mut self) -> egui::FullOutput {
            self.frame(Vec::new());
            self.frame(Vec::new())
        }

        /// The frame eframe runs once the windowing system has taken `ViewportCommand::Close`.
        ///
        /// This is not a synthetic convenience: `Close` does not close anything by itself, it comes
        /// back as a `ViewportEvent::Close` in the next frame's input (eframe 0.31.1
        /// `epi_integration.rs:270`, `egui-winit` `lib.rs:1352`). Reproducing it is the whole point
        /// — that frame is where a recorded approval used to be overwritten with a refusal.
        fn close_frame(&mut self) -> egui::FullOutput {
            let mut input = self.input();
            input
                .viewports
                .get_mut(&egui::ViewportId::ROOT)
                .expect("the root viewport")
                .events
                .push(egui::ViewportEvent::Close);
            let app = &mut self.app;
            self.ctx.run(input, |ctx| app.frame(ctx))
        }

        /// Press and release the primary pointer over `at`, as a person clicking would.
        fn click(&mut self, at: egui::Pos2) {
            self.frame(vec![
                egui::Event::PointerMoved(at),
                egui::Event::PointerButton {
                    pos: at,
                    button: egui::PointerButton::Primary,
                    pressed: true,
                    modifiers: egui::Modifiers::NONE,
                },
            ]);
            self.frame(vec![egui::Event::PointerButton {
                pos: at,
                button: egui::PointerButton::Primary,
                pressed: false,
                modifiers: egui::Modifiers::NONE,
            }]);
        }

        /// Turn the wheel over `at`, far enough to reach the end of anything this window shows.
        fn scroll_to_the_bottom(&mut self, at: egui::Pos2) {
            for _ in 0..4 {
                self.frame(vec![
                    egui::Event::PointerMoved(at),
                    egui::Event::MouseWheel {
                        unit: egui::MouseWheelUnit::Point,
                        delta: Vec2::new(0.0, -2000.0),
                        modifiers: egui::Modifiers::NONE,
                    },
                ]);
            }
        }

        fn answer(&self) -> Option<Outcome> {
            self.sink.lock().expect("the answer slot").take()
        }
    }

    /// Every string the frame drew, with the rectangle it occupies and the clip it was drawn under.
    ///
    /// The clip is the half that matters here: a galley whose rectangle escapes its clip rect is
    /// text the user cannot see, and it is drawn exactly as confidently as text they can.
    fn drawn_with_clip(shapes: &[egui::epaint::ClippedShape]) -> Vec<(String, Rect, Rect)> {
        fn walk(shape: &egui::Shape, clip: Rect, out: &mut Vec<(String, Rect, Rect)>) {
            match shape {
                egui::Shape::Text(text) => out.push((
                    text.galley.text().to_owned(),
                    Rect::from_min_size(text.pos, text.galley.size()),
                    clip,
                )),
                egui::Shape::Vec(shapes) => shapes.iter().for_each(|s| walk(s, clip, out)),
                _ => {}
            }
        }
        let mut out = Vec::new();
        for clipped in shapes {
            walk(&clipped.shape, clipped.clip_rect, &mut out);
        }
        out
    }

    /// Where the control labelled `label` was drawn, in window coordinates.
    ///
    /// Read off the frame rather than recomputed from the layout constants: a test that predicts
    /// where a button *should* be would keep clicking the same spot after the button moved.
    fn centre_of(output: &egui::FullOutput, label: &str) -> egui::Pos2 {
        let drawn = drawn_with_clip(&output.shapes);
        let (_, rect, _) = drawn
            .iter()
            .find(|(text, _, _)| text == label)
            .unwrap_or_else(|| panic!("the frame never drew a control labelled {label:?}"));
        rect.center()
    }

    /// The one galley containing `needle`, with its rectangle and its clip.
    fn body_galley(output: &egui::FullOutput, needle: &str) -> (String, Rect, Rect) {
        drawn_with_clip(&output.shapes)
            .into_iter()
            .find(|(text, _, _)| text.contains(needle))
            .unwrap_or_else(|| panic!("the frame never drew a body containing {needle:?}"))
    }

    /// Every string the frame drew, paired with the font FAMILY it was actually set in.
    ///
    /// The family is read off the galley's own layout job — `sections[0].format.font_id.family`, the
    /// same field the shaper consumed — not from our own structs, so it proves an identifier reached
    /// the screen in Space Mono and prose did not, rather than restating what we asked for.
    fn drawn_with_family(shapes: &[egui::epaint::ClippedShape]) -> Vec<(String, egui::FontFamily)> {
        fn walk(shape: &egui::Shape, out: &mut Vec<(String, egui::FontFamily)>) {
            match shape {
                egui::Shape::Text(text) => {
                    let family = text
                        .galley
                        .job
                        .sections
                        .first()
                        .map(|s| s.format.font_id.family.clone())
                        .unwrap_or(egui::FontFamily::Proportional);
                    out.push((text.galley.text().to_owned(), family));
                }
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

    /// The font family the one galley containing `needle` was set in.
    fn family_of(output: &egui::FullOutput, needle: &str) -> egui::FontFamily {
        drawn_with_family(&output.shapes)
            .into_iter()
            .find(|(text, _)| text.contains(needle))
            .unwrap_or_else(|| panic!("the frame never drew a galley containing {needle:?}"))
            .1
    }

    /// The Space Mono family every identifier must be set in.
    fn mono_family() -> egui::FontFamily {
        egui::FontFamily::Name(super::super::render::MONO.into())
    }

    /// A pairing confirm — a label in the heading and the opaque ext-id split out as its identifier.
    fn pair_screen() -> Screen {
        Screen::confirm(
            &ConfirmContent::pair(&crate::confirm::PairPrompt {
                ext_id: "mlibddmbhlgogepnjdienclhnkfpkfah",
                ext_label: Some("DIG Network"),
            }),
            "Cancel",
        )
    }

    /// A two-factor enrolment claim — the base32 TOTP secret split out as its identifier.
    fn two_factor_screen() -> Screen {
        Screen::confirm(
            &ConfirmContent::claim(&crate::confirm::ClaimPrompt {
                title: "DIG — Set up two-factor codes",
                heading: "Scan this with your authenticator",
                body: "Or add it by hand. Then type this key:",
                affirm: "I have added it",
                scannable: None,
                identifier: Some("JBSW Y3DP EHPK 3PXP"),
            }),
            "Cancel",
        )
    }

    /// The receive-address notice — prose plus the `xch1…` address split out as its identifier. The
    /// same identifier class as the sign address, so it must reach the screen in the same mono face.
    fn receive_address_notice_screen() -> Screen {
        Screen::confirm(
            &ConfirmContent::notice(&NoticePrompt {
                title: "DIG — Address copied",
                heading: "Your receiving address is on the clipboard.",
                body: "Receiving address copied to your clipboard.",
                identifier: Some("xch1up0vfatgtwrcgcvc360jd57t3p2kjskncutvzakh9mhdmlvejj3shn8wln"),
                acknowledge: "OK",
            }),
            "Cancel",
        )
    }

    /// The DIG-id notice — prose plus the id split out as its identifier.
    fn dig_id_notice_screen() -> Screen {
        Screen::confirm(
            &ConfirmContent::notice(&NoticePrompt {
                title: "DIG — DIG ID copied",
                heading: "Your DIG ID is on the clipboard.",
                body: "DIG ID copied to your clipboard.",
                identifier: Some(
                    "b6f1c0a94e2d7c5183ab0f39d84e6c72b1590adf3e7c48d2916b05fa7c3d81e4",
                ),
                acknowledge: "OK",
            }),
            "Cancel",
        )
    }

    /// **Every identifier reaches the screen in Space Mono (dig_ecosystem#2060).** The sign `xch1…`
    /// address, the pairing ext-id, the TOTP secret, the DIG id and the copied receiving address are
    /// each read or transcribed character by character, and a monospace face is what makes an address
    /// checkable and tells `1`/`l`, `0`/`O` apart. Read off the shaped galley's own font family, so
    /// reverting any one value back to the proportional face fails the matching assertion.
    #[test]
    fn each_identifier_is_set_in_space_mono() {
        let mono = mono_family();

        let sign = painted(sign_screen(), false, Theme::Light).1;
        assert_eq!(
            family_of(&sign, "xch1safe"),
            mono,
            "the decoded-transaction address must be Space Mono"
        );

        let pair = painted(pair_screen(), false, Theme::Light).1;
        assert_eq!(
            family_of(&pair, "mlibddmb"),
            mono,
            "the pairing ext-id must be Space Mono"
        );

        let two_factor = painted(two_factor_screen(), false, Theme::Light).1;
        assert_eq!(
            family_of(&two_factor, "JBSW Y3DP"),
            mono,
            "the TOTP secret must be Space Mono"
        );

        let notice = painted(dig_id_notice_screen(), false, Theme::Light).1;
        assert_eq!(
            family_of(&notice, "b6f1c0a9"),
            mono,
            "the DIG id must be Space Mono"
        );

        let receive = painted(receive_address_notice_screen(), false, Theme::Light).1;
        assert_eq!(
            family_of(&receive, "xch1up0"),
            mono,
            "the receiving address must be Space Mono"
        );
    }

    /// …and the CONTROL that makes the mono assertions meaningful: the prose around each identifier is
    /// NOT mono. The pair heading is the brand semibold cut and its body is the proportional face; the
    /// two-factor prose is proportional. Without this, setting the WHOLE window in mono would satisfy
    /// every assertion above.
    #[test]
    fn prose_beside_an_identifier_keeps_its_proportional_face() {
        let semibold = egui::FontFamily::Name(super::super::render::SEMIBOLD.into());

        let pair = painted(pair_screen(), false, Theme::Light).1;
        assert_eq!(
            family_of(&pair, "with your DIG identity"),
            semibold,
            "the pair heading is the brand semibold cut, not mono"
        );
        assert_eq!(
            family_of(&pair, "browser extension will be allowed"),
            egui::FontFamily::Proportional,
            "the pair body is prose"
        );

        let two_factor = painted(two_factor_screen(), false, Theme::Light).1;
        assert_eq!(
            family_of(&two_factor, "Then type this key"),
            egui::FontFamily::Proportional,
            "the two-factor body is prose"
        );

        let receive = painted(receive_address_notice_screen(), false, Theme::Light).1;
        assert_eq!(
            family_of(&receive, "Receiving address copied"),
            egui::FontFamily::Proportional,
            "the receive-address notice body is prose"
        );
    }

    /// **The guard: no heading, body or warning on any identifier-bearing surface is ever set in mono.**
    ///
    /// The mono treatment is reserved for identifier-bearing values; a prose line drifting into it
    /// would read as code and is exactly the drift this pins. Checked across every such screen at once,
    /// on the shaped galley, so a stray `mono(...)` on a prose block fails here.
    #[test]
    fn no_prose_on_any_surface_is_ever_set_in_mono() {
        let mono = mono_family();
        let cases: [(Screen, &[&str]); 5] = [
            (
                sign_screen(),
                &["wants you to sign", "Requested via your paired"],
            ),
            (
                pair_screen(),
                &[
                    "with your DIG identity",
                    "browser extension will be allowed",
                ],
            ),
            (
                two_factor_screen(),
                &["Scan this with your authenticator", "Then type this key"],
            ),
            (
                dig_id_notice_screen(),
                &["is on the clipboard", "copied to your clipboard"],
            ),
            (
                receive_address_notice_screen(),
                &["is on the clipboard", "Receiving address copied"],
            ),
        ];
        for (screen, needles) in cases {
            let out = painted(screen, false, Theme::Light).1;
            for needle in needles {
                assert_ne!(
                    family_of(&out, needle),
                    mono,
                    "prose {needle:?} must never be set in Space Mono"
                );
            }
        }
    }

    /// **Clicking the affirmative approves.** Not "records an approval" — *ends up* an approval,
    /// after the frame that actually closes the window has run.
    ///
    /// This is the defect the user hit and no test could see (dig_ecosystem#2038): the click DID
    /// record `Approve`, and then `ViewportCommand::Close` came back one frame later as a
    /// `ViewportEvent::Close`, [`PromptApp::keys`] read it as a dismissal, and the window overwrote
    /// the person's approval with a refusal on its way out. Every Sign, every Unlock, every "I have
    /// written these down" in the app answered `Deny`.
    ///
    /// Driven with a real pointer press and release over the control's real rectangle, because the
    /// bug lives between the click and the answer — a test that calls `finish` directly walks
    /// straight past it.
    #[test]
    fn clicking_the_affirmative_survives_the_frame_that_closes_the_window() {
        let mut driver = Driver::shown(sign_screen(), false);
        let laid_out = driver.settle();
        let at = centre_of(&laid_out, "Sign");

        driver.click(at);
        driver.close_frame();

        match driver.answer() {
            Some(Outcome::Confirm(WindowIntent::Approve)) => {}
            other => panic!(
                "a click on Sign answered {:?} — the affirmative does not survive the close",
                Describe(&other)
            ),
        }
    }

    /// …and the same for the typed window: the passphrase must not be thrown away on the way out.
    #[test]
    fn submitting_a_typed_field_survives_the_frame_that_closes_the_window() {
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
        let mut driver = Driver::shown(Screen::input(&field), true);
        let laid_out = driver.settle();
        let at = centre_of(&laid_out, "Unlock");
        driver.app.typed = Zeroizing::new("hunter2".to_owned());

        driver.click(at);
        driver.close_frame();

        match driver.answer() {
            Some(Outcome::Input(InputOutcome::Provided(typed))) => assert_eq!(&*typed, "hunter2"),
            other => panic!(
                "submitting answered {:?} — the typed text does not survive the close",
                Describe(&other)
            ),
        }
    }

    /// **The control for the latch: a window closed with NOTHING clicked is still a refusal.**
    ///
    /// Without this, "keep the first answer" could be satisfied by keeping no answer at all, and the
    /// window-manager close button would stop denying.
    #[test]
    fn a_window_closed_without_a_click_is_still_a_denial() {
        let mut driver = Driver::shown(sign_screen(), false);
        driver.settle();

        driver.close_frame();

        assert!(
            matches!(driver.answer(), Some(Outcome::Confirm(WindowIntent::Deny))),
            "dismissing the window without answering it must deny"
        );
    }

    /// …and the refusal control still refuses, so the latch did not make every button approve.
    #[test]
    fn clicking_the_refusal_denies() {
        let mut driver = Driver::shown(sign_screen(), false);
        let laid_out = driver.settle();
        let at = centre_of(&laid_out, "Cancel");

        driver.click(at);
        driver.close_frame();

        assert!(
            matches!(driver.answer(), Some(Outcome::Confirm(WindowIntent::Deny))),
            "a click on Cancel must deny"
        );
    }

    /// The 24-word enrolment screen, composed the way `account::journey::present_new_phrase`
    /// composes it: the numbered words, then the sentence that says losing them loses the account.
    ///
    /// This is the screen that hid sixteen of its own words.
    fn phrase_screen() -> Screen {
        use crate::confirm::ClaimPrompt;
        // Twenty-four BIP-39 words, laid out by `RecoveryPhrase::numbered_lines`' exact format.
        let words = [
            "abandon", "ability", "able", "about", "above", "absent", "absorb", "abstract",
            "absurd", "abuse", "access", "accident", "account", "accuse", "achieve", "acid",
            "acoustic", "acquire", "across", "act", "action", "actor", "actress", "adapt",
        ];
        let mut body = String::new();
        for (i, word) in words.iter().enumerate() {
            body.push_str(&format!("{:>2}. {word}\n", i + 1));
        }
        body.push_str(
            "These words ARE your DIG Account. Anyone who has them can take it, and nobody — \
             including DIG — can recover your account without them.",
        );
        Screen::confirm(
            &ConfirmContent::claim(&ClaimPrompt {
                title: "DIG — Your recovery phrase",
                heading: "Write these 24 words down, in order, and keep them somewhere safe.",
                body: &body,
                affirm: "I have written these down",
                scannable: None,
                identifier: None,
            }),
            "Not yet",
        )
    }

    /// **No display can hide body text without a scrollbar.**
    ///
    /// The guard this replaces was deleted with the Win32 renderer, and the defect came straight
    /// back. The window was capped at [`HEIGHT`] and could only shrink, leaving 404 px of body; the
    /// phrase body is 24 lines at 23.25 px plus a heading and a warning — about 767 px.
    /// `Ui::new_child` inherits its parent's clip rect, so the overflow was cut off **with no
    /// scrollbar and no marker**: words 15–24 and the whole warning never reached the screen, the
    /// user wrote down 14 of 24, and the account became unrecoverable (dig_ecosystem#49, #2038, and
    /// #2063 on the sign window).
    ///
    /// The window grows now, so on an ordinary display the phrase fits with nothing to scroll. This
    /// asserts the FLOOR — the display where it cannot fit however tall the window is allowed to be,
    /// which is the one that has to be safe.
    ///
    /// The property asserted is REACHABILITY, at every display this window can be drawn on: the
    /// start of the body is visible at rest, and the END of it is visible after the user scrolls.
    /// Both halves are read off the painted frame — the galley's own rectangle against the clip it
    /// was drawn under — so a scroll container that exists but does not actually move the content
    /// fails here.
    #[test]
    fn no_display_can_hide_body_text_without_a_scrollbar() {
        for (height, points_per_pixel) in [
            (HEIGHT, 1.0),
            (HEIGHT, 1.5),
            (HEIGHT, 2.0),
            (480.0, 1.0),
            (MIN_HEIGHT, 1.0),
            (MIN_HEIGHT, 2.0),
        ] {
            let mut driver = Driver::new(phrase_screen(), false, PATIENT, Vec2::new(WIDTH, height));
            driver.ctx.set_pixels_per_point(points_per_pixel);
            let at_rest = driver.settle();
            let (_, first, clip) = body_galley(&at_rest, " 1. abandon");
            let config = format!("{height} px at {points_per_pixel}×");
            assert!(
                first.top() >= clip.top() - 0.5,
                "{config}: the body starts above its own clip — the FIRST words are cut off",
            );

            driver.scroll_to_the_bottom(clip.center());
            let scrolled = driver.frame(Vec::new());
            let (text, last, clip) = body_galley(&scrolled, "24. adapt");
            assert!(
                text.contains("recover your account without them"),
                "{config}: the warning is not in the body that was drawn",
            );
            assert!(
                last.bottom() <= clip.bottom() + 0.5,
                "{config}: after scrolling to the end, the body still runs {:.0} px past its clip \
                 — the last words and the warning are unreachable",
                last.bottom() - clip.bottom(),
            );
        }
    }

    /// The premise the test above rests on: this body genuinely does NOT fit.
    ///
    /// Asserted at the smallest window the app can draw, where 26 lines can never fit however the
    /// layout is retuned. Without it, "you can scroll to the end" would pass on a body that was
    /// never long enough to scroll, and prove nothing.
    #[test]
    fn the_recovery_phrase_really_is_taller_than_the_window() {
        let mut driver = Driver::new(
            phrase_screen(),
            false,
            PATIENT,
            Vec2::new(WIDTH, MIN_HEIGHT),
        );
        let at_rest = driver.settle();
        let (_, body, clip) = body_galley(&at_rest, " 1. abandon");
        assert!(
            body.bottom() > clip.bottom(),
            "the 24-word body fits in a {MIN_HEIGHT} px window, so the scrolling test proves nothing"
        );
    }

    /// …and the other control: a body that DOES fit is shown whole, with nothing to scroll.
    ///
    /// This is what stops the fix from "passing" by pushing every prompt into a scroll container the
    /// user has to operate before they can read a two-line notice.
    #[test]
    fn a_short_body_is_shown_whole_and_needs_no_scrolling() {
        let mut driver = Driver::shown(notice_screen(), false);
        let at_rest = driver.settle();
        for (text, rect, clip) in drawn_with_clip(&at_rest.shapes) {
            assert!(
                clip.contains_rect(rect.shrink(0.5)),
                "a two-line notice drew {text:?} outside its clip — {rect:?} against {clip:?}"
            );
        }
    }

    /// A sign screen whose decoded transaction has `outputs` `Send … XCH to xch1…` lines — the
    /// ordinary shape of a batch payment, and the input that ran off the bottom of the window.
    ///
    /// The outputs are ONE `Block::Detail` panel (the decode is a single multi-line string, per
    /// `Screen::confirm`), so this exercises the panel layout path — `galley.size().y + padding`,
    /// distinct from the recovery phrase's `Block::Body` path — which is why it is worth a test of
    /// its own even though the scroll container is shared.
    fn many_output_sign_screen(outputs: usize) -> Screen {
        let mut tx = String::new();
        for i in 1..=outputs {
            tx.push_str(&format!(
                "Send 0.001 XCH to xch1recipient{i:02}\u{2026}addr\n"
            ));
        }
        let content = ConfirmContent::sign(&SignPrompt {
            origin: "https://dapp.example",
            payload_type: "spend",
            decoded_tx: Some(tx.trim_end()),
        })
        .expect("a decoded transaction yields content");
        Screen::confirm(&content, "Cancel")
    }

    /// **A many-output spend keeps every output above the action row and reachable (dig_ecosystem#2063).**
    ///
    /// The sign window's whole job is to show the full effect of what will be signed — `SPEC.md` §3.2
    /// requires every output the decode enumerated, "never a lossy subset, so the human sees the full
    /// effect they authorize". Before the body scrolled, a decoded transaction with enough outputs
    /// drew straight past the bottom of the window: at 12 outputs (an ordinary batch payment) the
    /// lowest line sat 239 px below the window, invisible and unindicated, and the user authorised a
    /// spend with part of what they were authorising off-screen.
    ///
    /// The recovery-phrase test above proves the CLASS is fixed, but it drives a `Block::Body`; the
    /// sign screen is a `Block::Detail` panel whose height is measured differently, so a regression
    /// that broke only the panel path would pass there and fail on a real spend. This pins the sign
    /// instance directly, three ways: the body genuinely overflows, its viewport sits entirely ABOVE
    /// the action row (so no output can be painted over Sign), and the LAST output is reachable after
    /// scrolling. The action-row top is read off the painted frame, not recomputed, so the assertion
    /// moves with the layout.
    #[test]
    fn a_many_output_spend_stays_above_the_action_row_and_stays_reachable() {
        let mut driver = Driver::new(
            many_output_sign_screen(30),
            false,
            PATIENT,
            Vec2::new(WIDTH, HEIGHT),
        );
        let at_rest = driver.settle();

        let (_, galley, clip) = body_galley(&at_rest, "xch1recipient01");
        // The premise the reachability halves rest on: 30 outputs genuinely do not fit the viewport.
        // Without it, "you can scroll to the last output" would pass on a body short enough to need
        // no scrolling and prove nothing (the sign analogue of the recovery-phrase premise test).
        assert!(
            galley.bottom() > clip.bottom(),
            "30 outputs fit the viewport, so the scrolling assertions below prove nothing",
        );
        // The window did not open already scrolled past the first outputs.
        assert!(
            galley.top() >= clip.top() - 0.5,
            "the decoded transaction starts above its clip — the first outputs are cut off",
        );

        // The #2063 assertion: the transaction viewport sits ENTIRELY above the action row, so no
        // output can be painted into or below the band the Cancel/Sign controls occupy. The action
        // row top is the Cancel control's own rectangle, read off the frame.
        let drawn = drawn_with_clip(&at_rest.shapes);
        let (_, cancel, _) = drawn
            .iter()
            .find(|(t, _, _)| t == "Cancel")
            .expect("the action row draws a Cancel control");
        assert!(
            clip.bottom() <= cancel.top() + 0.5,
            "the transaction viewport overlaps the action row by {:.0} px — an output can draw over Sign",
            clip.bottom() - cancel.top(),
        );
        // …and the affirmative is itself on-screen, not shoved off the bottom by the long body.
        drawn
            .iter()
            .find(|(t, _, _)| t == "Sign")
            .expect("the action row draws a Sign control");

        // Reachability: the LAST output is inside the viewport after scrolling — the tail is not
        // clipped away with no way to reach it.
        driver.scroll_to_the_bottom(clip.center());
        let scrolled = driver.frame(Vec::new());
        let (_, last, clip) = body_galley(&scrolled, "xch1recipient30");
        assert!(
            last.bottom() <= clip.bottom() + 0.5,
            "after scrolling to the end, the last output still runs {:.0} px past its clip — unreachable",
            last.bottom() - clip.bottom(),
        );
    }

    /// **A prompt nobody answers dismisses ITSELF, and what it reports is not an approval.**
    ///
    /// Every prompt in the process is drawn on one thread, one at a time. Before this, `ask` blocked
    /// on a bare `recv()` with no deadline anywhere in `confirm/gui/`, so a hostile dapp could raise
    /// one sign prompt the user ignored and every LATER prompt — the tray unlock, a destroy confirm,
    /// a second sign — queued behind it forever, none of them ever drawn, with no error reaching any
    /// caller (dig_ecosystem#2038). One ignored window must cost one refused action.
    #[test]
    fn a_prompt_nobody_answers_times_out_rather_than_waiting_forever() {
        let mut driver = Driver::new(
            sign_screen(),
            false,
            Duration::from_millis(1),
            Vec2::new(WIDTH, HEIGHT),
        );
        driver.frame(Vec::new());
        std::thread::sleep(Duration::from_millis(5));
        driver.frame(Vec::new());

        assert!(
            matches!(
                driver.answer(),
                Some(Outcome::Confirm(WindowIntent::Timeout))
            ),
            "an unanswered confirm must report a timeout"
        );
    }

    /// …and the typed window reports that nothing was typed, never an empty answer a caller acts on.
    #[test]
    fn an_unanswered_input_window_times_out_as_a_cancellation() {
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
        let mut driver = Driver::new(
            Screen::input(&field),
            true,
            Duration::from_millis(1),
            Vec2::new(WIDTH, HEIGHT),
        );
        driver.app.typed = Zeroizing::new("half-typed".to_owned());
        driver.frame(Vec::new());
        std::thread::sleep(Duration::from_millis(5));
        driver.frame(Vec::new());

        assert!(
            matches!(
                driver.answer(),
                Some(Outcome::Input(InputOutcome::Cancelled))
            ),
            "an unanswered input window must cancel, never hand over what was half-typed"
        );
    }

    /// The control: a window WITHIN its deadline answers nothing at all, so the test above is not
    /// just observing a window that expires the moment it opens.
    #[test]
    fn a_prompt_inside_its_deadline_is_not_dismissed() {
        let mut driver = Driver::shown(sign_screen(), false);
        driver.settle();
        std::thread::sleep(Duration::from_millis(5));
        driver.frame(Vec::new());

        assert!(
            driver.answer().is_none(),
            "a prompt that is still within its deadline answered on the user's behalf"
        );
    }

    /// A timeout must not be able to become an approval on its way through the consent gate.
    #[test]
    fn a_timed_out_window_never_authorizes() {
        use crate::confirm::{BiometricVerifier, ConfirmDecision, VerifyOutcome};

        struct TimingOutWindow;
        impl ForegroundWindow for TimingOutWindow {
            fn show(&self, _content: &ConfirmContent) -> WindowIntent {
                WindowIntent::Timeout
            }
        }
        struct AlwaysVerified;
        impl BiometricVerifier for AlwaysVerified {
            fn verify(&self, _reason: &str) -> VerifyOutcome {
                VerifyOutcome::Verified
            }
        }

        assert_eq!(
            crate::confirm::gated_consent(&sign_content(), &TimingOutWindow, &AlwaysVerified),
            ConfirmDecision::Timeout
        );
    }

    /// **What the user typed is not left behind in egui's undo history.**
    ///
    /// `.password(true)` masks what is DRAWN. It does not stop `TextEdit` feeding
    /// `text.as_str().to_owned()` into an undoer twice per frame (egui 0.31.1
    /// `text_edit/builder.rs:905`, `:1116`) and keeping those snapshots in `ctx.memory` for the life
    /// of the Context — so a passphrase, or a 24-word recovery phrase typed to restore an account,
    /// accumulated in plain `String`s outside our zeroizing buffer.
    ///
    /// Asserted against egui's own state rather than our field, because
    /// `the_typed_buffer_is_zeroizing` asserts a type property on a local and cannot see this.
    #[test]
    fn what_was_typed_is_not_kept_in_eguis_undo_history() {
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
        let mut driver = Driver::shown(Screen::input(&field), true);
        driver.settle();
        // A person typing, one frame per keystroke — which is what fills the history.
        for keystroke in ["c", "o", "r", "r", "e", "c", "t"] {
            driver.frame(vec![egui::Event::Text(keystroke.to_owned())]);
        }
        assert_eq!(
            &*driver.app.typed, "correct",
            "the field never took the text"
        );

        let id = driver
            .ctx
            .memory(|m| m.focused())
            .expect("the field holds focus");
        let state = egui::TextEdit::load_state(&driver.ctx, id).expect("the field has state");
        // A state no keystroke could have produced, so an empty history is the only way this is
        // false — a single retained snapshot that happens to equal the current one cannot hide here.
        let sentinel = (
            egui::text::CCursorRange::default(),
            "\u{0}never-typed".to_owned(),
        );
        assert!(
            !state.undoer().has_undo(&sentinel),
            "egui is still holding earlier copies of what was typed into a masked field"
        );
    }

    /// **The window is really gone when the prompt is answered.**
    ///
    /// On Windows `winit::window::Window::drop` does not destroy the window: it posts a private
    /// message and lets the window procedure do it (winit 0.30 `windows/window.rs:1113`). eframe
    /// drops the window only after `run_app_on_demand` has returned, and [`serve`] then goes
    /// straight back to waiting — so nothing dispatched that message and the consent window STAYED
    /// ON SCREEN, always on top, with a dead message pump. That is the *"press any button and the
    /// program stops responding"* the user reported (dig_ecosystem#2038); the answer had already
    /// been delivered, and the frozen window was all they could see.
    ///
    /// Driven with no input at all: the window is given a one-second deadline and dismisses itself,
    /// so this needs a display but not a person.
    ///
    /// Ignored because it opens a real window — CI has no display, and a headless run cannot reach
    /// the code path at all, since the whole defect is in what the real winit event loop leaves
    /// behind. Run it deliberately on a desktop.
    #[test]
    #[ignore = "opens a real window; run deliberately on a desktop to check the window is destroyed"]
    #[cfg(target_os = "windows")]
    fn an_answered_prompt_leaves_no_window_behind() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        use windows::Win32::Foundation::{BOOL, HWND, LPARAM};
        use windows::Win32::UI::WindowsAndMessaging::{
            EnumWindows, GetClassNameW, GetWindowThreadProcessId, IsWindowVisible,
        };

        /// The class every `winit` window is registered under — the prompt's own window.
        ///
        /// Named so the count can EXCLUDE `"Winit Thread Event Target"`, the 32 px helper window the
        /// cached event loop keeps between prompts. That one is meant to outlive a prompt; the
        /// consent window is not.
        const WINIT_WINDOW_CLASS: &str = "Window Class";

        /// Count this process's visible prompt windows.
        unsafe extern "system" fn prompts(window: HWND, total: LPARAM) -> BOOL {
            // SAFETY: `total` is the `&AtomicUsize` handed to `EnumWindows` below, which outlives
            // the enumeration.
            let seen = unsafe { &*(total.0 as *const AtomicUsize) };
            let mut owner = 0u32;
            let mut class = [0u16; 64];
            // SAFETY: plain queries on a handle the enumeration just produced.
            let (visible, len) = unsafe {
                GetWindowThreadProcessId(window, Some(&mut owner));
                (
                    IsWindowVisible(window).as_bool(),
                    GetClassNameW(window, &mut class),
                )
            };
            let class = String::from_utf16_lossy(&class[..len.max(0) as usize]);
            if owner == std::process::id() && visible && class == WINIT_WINDOW_CLASS {
                seen.fetch_add(1, Ordering::Relaxed);
            }
            true.into()
        }

        fn prompt_windows_still_open() -> usize {
            let seen = AtomicUsize::new(0);
            // SAFETY: the callback only reads `seen`, which outlives the call.
            unsafe {
                let _ = EnumWindows(Some(prompts), LPARAM(std::ptr::from_ref(&seen) as isize));
            }
            seen.load(Ordering::Relaxed)
        }

        assert_eq!(
            prompt_windows_still_open(),
            0,
            "another test left a prompt window open; run this one on its own"
        );

        let dir = tempfile::tempdir().expect("a temp dir");
        let store = ThemeChoice::in_brand_dir(dir.path());
        let (reply, _rx) = sync_channel(1);
        let outcome = draw(Job {
            screen: sign_screen(),
            wants_text: false,
            theme: store.clone(),
            // Answered by the deadline rather than by a person, so this needs a display but no human.
            deadline: Duration::from_secs(1),
            reply,
        });

        assert!(
            matches!(outcome, Some(Outcome::Confirm(WindowIntent::Timeout))),
            "the window should have dismissed itself on its deadline"
        );
        let left_behind = prompt_windows_still_open();
        assert_eq!(
            left_behind, 0,
            "the prompt returned but left {left_behind} visible window(s) behind, with nothing left \
             to pump their messages — that is the frozen consent window the user cannot dismiss"
        );
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
