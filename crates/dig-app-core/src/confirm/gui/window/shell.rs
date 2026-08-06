//! The app shell — a window the person opened, hosted as a job on the one prompt thread.
//!
//! # Why the shell is a job that pumps the queue
//!
//! There is exactly one winit event loop in this process and there can never be a second
//! ([`super::start`]). So the shell cannot own a loop; it has to be drawn by the one that already
//! exists, which means it has to be a job on [`super::serve_with`]'s queue.
//!
//! But `serve_with` is `while let Ok(job) = rx.recv()` — strictly one job at a time. A persistent
//! window sitting in that slot would park every prompt raised while it was open until
//! [`super::Job::over_by`] elapsed, and each would then be refused **without ever being drawn**: a
//! dapp asks for a signature, nothing appears, the request is refused, and no surface explains why.
//! Opening the app window would silently disable consent for as long as it was up.
//!
//! So the shell is a job AND it owns the receiver for its lifetime. Every frame it draws itself,
//! takes at most one waiting prompt off the queue, and draws that prompt as an immediate child
//! viewport — a real, separate OS window on the same loop. When it closes, `serve_with` resumes
//! `recv` and nothing else has changed.
//!
//! # The one way to get this wrong
//!
//! **`ViewportCommand::Close` does not close a viewport.** It raises `close_requested()` on it and
//! nothing else; measured on Windows 11, the child's window handle after the command is the *same*
//! handle. Dismissal here therefore runs through [`ShellApp::prompt`] — the shell stops showing the
//! viewport, and ceasing to show it is what destroys it (25–45 ms, 15 of 15 cycles, with or without
//! the command). Wiring dismissal to the command alone would leave an undismissable consent prompt
//! on screen while `close_requested` reported success — the dig-app#86 class, on the consent path.
//!
//! # The shell never authors an answer
//!
//! [`super::PromptApp`]'s answer latch owns what the human said. A teardown frame that could change
//! it is dig_ecosystem#2038, where every approval in the app was silently overwritten with a
//! refusal. The shell only ever *reads* the outcome the prompt recorded ([`ActivePrompt::settle`]);
//! the single answer it may write is the fail-closed one, for a prompt nobody answered at all.

use std::sync::mpsc::{Receiver, SyncSender};
use std::sync::{Arc, Mutex};
use std::time::Instant;

use egui::{Key, Rect, Vec2};

use super::super::paint;
use super::super::render::{regular, rgba, semibold, size, space, Weight};
use super::super::theme::{Rgba, Theme, ThemeChoice, Tokens};
use super::{
    install_fonts, unavailable, Job, Outcome, PromptApp, Shell, Work, CHROME_HEIGHT, TOGGLE_WIDTH,
    WIDTH,
};

/// The shell's opening size. Wide enough for the content column this window is designed around.
const SHELL_WIDTH: f32 = 960.0;
/// The shell's opening height.
const SHELL_HEIGHT: f32 = 640.0;
/// The smallest the shell may be dragged to, on both axes.
///
/// Square rather than the prompt's wide-and-short minimum: the shell is a browsable window, and a
/// person who shrinks it to a sliver must still be able to find the way out of it.
const SHELL_MIN: f32 = 480.0;

/// How far in from an edge counts as a grab for a resize.
///
/// The window is undecorated, so the operating system draws no resize border and this is the only
/// one there is. Eight logical pixels is the Windows default frame sense; smaller reads as a window
/// that cannot be resized at all.
const RESIZE_GRAB: f32 = 8.0;

/// How opaque the scrim over the shell is while a prompt is up, per theme.
///
/// Two values because the surfaces differ, not for taste: dark `surface` under a half-alpha black is
/// barely distinguishable from `bg`, so a single alpha reads inert in one theme and as a smudge in
/// the other.
const SCRIM_ALPHA_LIGHT: u8 = 128;
/// See [`SCRIM_ALPHA_LIGHT`].
const SCRIM_ALPHA_DARK: u8 = 168;

/// The child viewport every prompt raised over the shell is drawn in.
///
/// One id, reused, because only one prompt may be up at a time ([`ShellApp::prompt`]).
fn prompt_viewport() -> egui::ViewportId {
    egui::ViewportId::from_hash_of("dig-prompt-over-the-app-window")
}

/// Draw the app shell to completion. Always `None` — a shell produces no [`Outcome`].
///
/// Signature matches [`super::draw_watched`] so both are reachable through `serve_with`'s one
/// injection point, which is what lets a test make either of them misbehave.
pub(super) fn draw(shell: Shell, queue: &Receiver<Work>) -> Option<Outcome> {
    let theme = shell.theme.read();
    let app = ShellApp::new(theme, shell.theme);
    let run = eframe::run_native(
        "DIG",
        native_options(),
        Box::new(|cc| {
            install_fonts(&cc.egui_ctx);
            Ok(Box::new(Host { app, queue }))
        }),
    );

    // The loop on this thread has now stopped, which is the precondition that makes this necessary —
    // see `super::flush_deferred_window_destruction`.
    super::flush_deferred_window_destruction();
    if let Err(err) = run {
        tracing::warn!(%err, "the DIG app window could not be opened");
    }
    None
}

/// How the shell window is created.
///
/// # Why this is a SECOND set of options and not the prompt's
///
/// [`super::native_options`] hardcodes the consent posture, and every flag in it is wrong here.
/// Editing it to suit the shell would change every consent prompt in the app, which is the exact
/// opposite of what is wanted.
///
/// | Flag | Prompt | Shell | Why |
/// |---|---|---|---|
/// | `decorations` | false | false | the window must read as the prompts do |
/// | `always_on_top` | **true** | **false** | the shell is not a consent window and must not float over the person's other work |
/// | `resizable` | false | **true** | a browsable window at one fixed size cannot fit every host |
/// | dismiss-on-blur | bar only | false | the shell must survive a glance elsewhere |
///
/// The prompt keeps `always_on_top` for a measured reason: a non-topmost prompt is *completely
/// buried* by one click on the shell — its own geometric centre resolves to the shell and it keeps
/// repainting into a window nobody can see, while [`super::Job::over_by`] counts down to a refusal
/// the person never saw. Being unmissable is the security property, and it does not weaken because
/// the prompt happened to be raised while a window was open.
fn native_options() -> eframe::NativeOptions {
    eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_title("DIG")
            .with_inner_size([SHELL_WIDTH, SHELL_HEIGHT])
            .with_min_inner_size([SHELL_MIN, SHELL_MIN])
            // No maximum. An infinite one was tried and it is a TRAP: winit converts the logical
            // size to physical before clamping, and the window came up ~23% wider than the size
            // asked for — caught in the gallery, invisible to every headless test, because the
            // wrongness is in what the operating system drew.
            .with_resizable(true)
            .with_active(true)
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

/// Binds [`ShellApp`] to the queue it pumps, for the life of one `run_native`.
///
/// The receiver is borrowed rather than owned because it belongs to [`super::serve_with`], which
/// takes it back the moment this window closes.
struct Host<'a> {
    app: ShellApp,
    queue: &'a Receiver<Work>,
}

impl eframe::App for Host<'_> {
    fn clear_color(&self, _visuals: &egui::Visuals) -> [f32; 4] {
        let bg = self.app.theme.tokens().bg;
        [
            f32::from(bg.r) / 255.0,
            f32::from(bg.g) / 255.0,
            f32::from(bg.b) / 255.0,
            1.0,
        ]
    }

    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        self.app.frame(ctx, self.queue);
    }
}

/// A prompt being drawn as a child viewport over the shell.
struct ActivePrompt {
    /// The real prompt, driven through the real paint path — [`super::PromptApp::frame`], unmodified.
    app: PromptApp,
    /// Where the prompt records its answer. Read by the shell, written only by the prompt.
    sink: Arc<Mutex<Option<Outcome>>>,
    /// The caller blocked on this prompt.
    reply: SyncSender<Outcome>,
    /// Whether this prompt returns typed text — decides the SHAPE of the fail-closed answer.
    wants_text: bool,
    /// The prompt's title, for the log.
    title: String,
}

impl ActivePrompt {
    /// Send whatever the PROMPT recorded, or the fail-closed answer if it recorded nothing.
    ///
    /// # Why the shell reads the outcome and never decides it
    ///
    /// [`super::PromptApp::record`] latches the first answer specifically so that no later frame —
    /// a teardown, a close event, anything — can change what the human said. That latch exists
    /// because it did not, once: a person clicked **Sign**, their approval was recorded, and the
    /// window's own teardown overwrote it with a refusal one frame later. Every affirmative in the
    /// app answered `Deny` (dig_ecosystem#2038).
    ///
    /// A shell that authored its own outcome would bypass that latch and reintroduce the same class
    /// on the same path. So the recorded answer always wins, and the fail-closed default below is
    /// reached only when there is nothing to win against.
    fn settle(self) {
        let recorded = self.sink.lock().ok().and_then(|mut slot| slot.take());
        if recorded.is_none() {
            tracing::debug!(
                prompt = %self.title,
                "a prompt over the DIG app window was never answered; refusing"
            );
        }
        let _ = self
            .reply
            .send(recorded.unwrap_or_else(|| unavailable(self.wants_text)));
    }
}

/// The app shell, and at most one prompt drawn over it.
///
/// # The re-entrancy rule
///
/// **`ShellApp` never blocks.** It renders the shell, and at most one prompt viewport, and returns
/// from every frame. In particular a control in this window may never call the blocking
/// [`super::ask`] inline: that would block the prompt thread inside its own frame, waiting on the
/// very queue this frame owns. Guaranteed deadlock. Anything the shell wants to ask is dispatched on
/// a worker exactly as a tray click is.
struct ShellApp {
    /// The active theme.
    theme: Theme,
    /// Where the theme preference persists.
    theme_store: ThemeChoice,
    /// The prompt on screen right now, if any.
    ///
    /// **This is the dismissal mechanism.** A prompt is on screen for exactly as long as this is
    /// `Some`; dropping it is what destroys the child window (see the module docs). It is also the
    /// one-modal-at-a-time rule: the queue is not polled while it is set, so a second prompt can
    /// never be stacked over a first to obscure what is actually being authorised.
    prompt: Option<ActivePrompt>,
    /// Whether this window has been asked to close.
    ///
    /// Explicit rather than read back off the viewport, so the frame that decides to close and the
    /// frame that acts on it cannot disagree.
    closing: bool,
}

impl ShellApp {
    fn new(theme: Theme, theme_store: ThemeChoice) -> Self {
        Self {
            theme,
            theme_store,
            prompt: None,
            closing: false,
        }
    }

    /// Lay out and paint ONE frame: the shell, then at most one prompt over it.
    ///
    /// Split out of [`eframe::App::update`] for the same reason [`super::PromptApp::frame`] is — a
    /// caller holding only an [`egui::Context`] can drive the real paint path and read back what it
    /// produced, which is how every rule in this module is tested on a host with no display.
    fn frame(&mut self, ctx: &egui::Context, queue: &Receiver<Work>) {
        // egui is lazy by default. The shell must keep painting regardless, because a prompt's own
        // self-dismissal deadline can only elapse on a frame that actually runs, and the prompt is
        // drawn from inside this one.
        ctx.request_repaint();

        self.keys(ctx);
        if self.closing {
            self.close(ctx);
            return;
        }

        // Admitted BEFORE the shell is drawn so that the scrim and the pane agree with each other
        // within a single frame: a prompt admitted afterwards would show for one frame over an
        // unscrimmed, live-looking shell.
        self.admit_one_prompt(queue);

        let t = self.theme.tokens();
        let prompt_is_up = self.prompt.is_some();
        self.paint_shell(ctx, &t, prompt_is_up);
        self.show_prompt(ctx);
    }

    /// Escape, and the window manager's own close.
    ///
    /// # Why the prompt's claim on Escape is an explicit flag
    ///
    /// While a prompt is up it owns Escape entirely, and that is decided HERE, by
    /// [`ShellApp::prompt`], rather than by trusting which viewport `ctx.input` reads inside a
    /// nested callback. That routing is a framework claim, and a wrong answer means one Escape both
    /// denies the prompt AND closes the shell in the same frame — on the window that authorises
    /// spending. [`super::PromptApp::focus`] already refuses this class of dependency for exactly
    /// this reason.
    ///
    /// # Why suppressing the escape hatch here is legitimate
    ///
    /// Never-trap-the-user is a hard rule, and suppression is only defensible because it is
    /// **bounded**: a prompt answers for itself at [`super::CONFIRM_DEADLINE`] /
    /// [`super::INPUT_DEADLINE`] via [`super::PromptApp::expire`] — with a timeout or a
    /// cancellation, never an approval — and the shell's Escape works again the moment it does.
    fn keys(&mut self, ctx: &egui::Context) {
        let (escape, close_requested) =
            ctx.input(|i| (i.key_pressed(Key::Escape), i.viewport().close_requested()));
        if close_requested {
            self.closing = true;
            return;
        }
        if escape && self.prompt.is_none() {
            self.closing = true;
        }
    }

    /// Close the shell, answering any prompt it was hosting.
    ///
    /// The order is load-bearing: [`ActivePrompt::settle`] sends what the prompt RECORDED if it
    /// recorded anything, and only falls back to the fail-closed answer otherwise. A shell that
    /// refused unconditionally here would throw away an approval the person had already given, and
    /// one that dropped the reply instead would strand the caller on `recv_timeout`.
    fn close(&mut self, ctx: &egui::Context) {
        if let Some(active) = self.prompt.take() {
            active.settle();
        }
        ctx.send_viewport_cmd(egui::ViewportCommand::Close);
    }

    /// Take at most one waiting prompt off the queue.
    ///
    /// Non-blocking by construction. `try_recv` is not called at all while a prompt is up, which is
    /// where one-modal-at-a-time is enforced.
    fn admit_one_prompt(&mut self, queue: &Receiver<Work>) {
        if self.prompt.is_some() {
            return;
        }
        match queue.try_recv() {
            Ok(Work::Prompt(job)) => self.open(job),
            // A second open-the-window request while the window is open. There is nobody blocked on
            // it and nothing to answer, so dropping it is the whole handling; raising the window is
            // the caller's job, not the queue's.
            Ok(Work::Shell(_)) => {
                tracing::debug!("the DIG app window is already open; a second request was ignored");
            }
            Err(_) => {}
        }
    }

    /// Begin drawing `job`, or refuse it without drawing it.
    ///
    /// The staleness rule is [`super::serve_with`]'s, applied here for the same reason: opening a
    /// real consent window — a real origin, a real payload — for an operation nobody is waiting on
    /// any more teaches precisely the click-through reflex the prompts are shaped to prevent
    /// (dig_ecosystem#2074).
    fn open(&mut self, job: Job) {
        if Instant::now() >= job.over_by {
            tracing::warn!(
                prompt = %job.screen.title,
                "a DIG prompt reached the app window after its caller had given up; refused \
                 without opening a window"
            );
            let _ = job.reply.send(unavailable(job.wants_text));
            return;
        }

        let sink = Arc::new(Mutex::new(None));
        let reply = job.reply.clone();
        let wants_text = job.wants_text;
        let title = job.screen.title.clone();
        let theme_store = job.theme.clone();
        tracing::debug!(prompt = %title, wants_text, "drawing a DIG prompt over the app window");
        self.prompt = Some(ActivePrompt {
            app: PromptApp::new(job, theme_store, Arc::clone(&sink)),
            sink,
            reply,
            wants_text,
            title,
        });
    }

    /// Draw the active prompt as a child viewport, and stop showing it once it has been answered.
    ///
    /// **Dropping [`ShellApp::prompt`] is what dismisses the window.** Nothing here sends
    /// `ViewportCommand::Close`, because that command does not close a viewport — see the module
    /// docs. The prompt's own `record` still sends one, harmlessly; the destruction is caused by the
    /// next frame not showing the viewport.
    fn show_prompt(&mut self, ctx: &egui::Context) {
        let Some(active) = self.prompt.as_mut() else {
            return;
        };
        let builder = egui::ViewportBuilder::default()
            .with_title(active.title.clone())
            .with_inner_size([WIDTH, super::HEIGHT])
            .with_min_inner_size([WIDTH, super::MIN_HEIGHT])
            .with_resizable(false)
            // A consent window must be SEEN. Measured: a non-topmost prompt is buried outright by
            // one click on the shell — see `native_options` above.
            .with_always_on_top()
            .with_active(true)
            .with_decorations(false);

        let prompt = &mut active.app;
        ctx.show_viewport_immediate(prompt_viewport(), builder, |child, _class| {
            prompt.frame(child);
        });

        if active.app.answered {
            // Taken out of the field FIRST: this is the dismissal.
            if let Some(answered) = self.prompt.take() {
                answered.settle();
            }
        }
    }

    /// Paint the shell itself: chrome, pane, and — while a prompt is up — the scrim and the pill.
    fn paint_shell(&mut self, ctx: &egui::Context, t: &Tokens, prompt_is_up: bool) {
        let screen = ctx.screen_rect();
        // An `Area` rather than a `CentralPanel` so the shell and the prompt it hosts never contend
        // for the one central-panel id on hosts where egui embeds an immediate viewport instead of
        // giving it a window of its own.
        egui::Area::new(egui::Id::new("dig-app-shell"))
            .fixed_pos(screen.left_top())
            .order(egui::Order::Background)
            .show(ctx, |ui| {
                ui.set_clip_rect(screen);
                ui.painter().rect_filled(screen, 0, rgba(t.bg));
                self.chrome(ui, screen, t, prompt_is_up);
                pane(ui, screen, t, prompt_is_up);
            });

        if prompt_is_up {
            self.scrim_and_pill(ctx, screen, t);
        } else {
            self.resize_edges(ctx, screen);
        }
    }

    /// The 44 px header: brand mark, title, theme toggle, Close — and the drag strip.
    fn chrome(&mut self, ui: &mut egui::Ui, full: Rect, t: &Tokens, prompt_is_up: bool) {
        let bar = Rect::from_min_size(full.left_top(), Vec2::new(full.width(), CHROME_HEIGHT));
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
            "DIG",
            semibold(size::XS),
            rgba(t.muted),
        );
        paint::rule(ui, full, bar.bottom(), t);

        // Every control in the chrome is inert while a prompt is up, and the scrim covers the chrome
        // too: sparing it would leave the toggle and Close looking live, which is exactly the wrong
        // signal over a window that cannot be interacted with.
        if prompt_is_up {
            return;
        }

        let close = Rect::from_min_size(
            egui::Pos2::new(bar.right() - CLOSE_WIDTH - space::S3, bar.top() + 7.0),
            Vec2::new(CLOSE_WIDTH, 30.0),
        );
        let mut close_ui = ui.new_child(egui::UiBuilder::new().max_rect(close));
        // A word, not a glyph: an unlabelled cross is one more thing to decode, and it is invisible
        // to a screen reader.
        if paint::theme_toggle(&mut close_ui, "Close", t).clicked() {
            self.closing = true;
        }

        let label = match self.theme {
            Theme::Light => "Dark theme",
            Theme::Dark => "Light theme",
        };
        let toggle = Rect::from_min_size(
            egui::Pos2::new(
                bar.right() - CLOSE_WIDTH - space::S3 - TOGGLE_WIDTH - space::S2,
                bar.top() + 7.0,
            ),
            Vec2::new(TOGGLE_WIDTH, 30.0),
        );
        let mut toggle_ui = ui.new_child(egui::UiBuilder::new().max_rect(toggle));
        if paint::theme_toggle(&mut toggle_ui, label, t).clicked() {
            self.theme = self.theme.toggled();
            if let Err(err) = self.theme_store.write(self.theme) {
                tracing::debug!(%err, "could not persist the app window theme preference");
            }
        }

        // The drag strip stops short of the controls so it cannot swallow their hit areas — an
        // undecorated window whose Close cannot be clicked is a window with no way out.
        let strip = Rect::from_min_max(
            bar.left_top(),
            egui::Pos2::new(toggle.left() - space::S2, bar.bottom()),
        );
        let dragged = ui
            .interact(
                strip,
                egui::Id::new("dig-app-shell-drag"),
                egui::Sense::drag(),
            )
            .dragged();
        if dragged {
            ui.ctx().send_viewport_cmd(egui::ViewportCommand::StartDrag);
        }
    }

    /// Dim the whole window and offer the one way back to the prompt.
    ///
    /// # Why the pill is a safety item and not decoration
    ///
    /// The prompt is its own OS window with its own focus, so it can be dragged behind the shell or
    /// onto another display. Without an affordance that brings it back, the shell is permanently
    /// inert with no visible cause — a trap. The pill sends `ViewportCommand::Focus`, which is the
    /// only mechanism that works: re-asserting `WindowLevel::AlwaysOnTop` was measured to lift
    /// z-order while leaving keyboard focus on the shell, so the person would read the prompt and
    /// type into the window behind it. That is worse than not raising it at all.
    ///
    /// The label names what it does, so it cannot be misread as a way to dismiss the prompt.
    fn scrim_and_pill(&self, ctx: &egui::Context, full: Rect, t: &Tokens) {
        egui::Area::new(egui::Id::new("dig-app-shell-scrim"))
            .fixed_pos(full.left_top())
            .order(egui::Order::Foreground)
            .show(ctx, |ui| {
                ui.set_clip_rect(full);
                ui.painter()
                    .rect_filled(full, 0, rgba(scrim(t, self.theme)));

                let size = Vec2::new(PILL_WIDTH, PILL_HEIGHT);
                let at = Rect::from_center_size(full.center(), size);
                let mut pill_ui = ui.new_child(egui::UiBuilder::new().max_rect(at));
                if paint::button(&mut pill_ui, RAISE_LABEL, Weight::Primary, false, t).clicked() {
                    ctx.send_viewport_cmd_to(prompt_viewport(), egui::ViewportCommand::Focus);
                }
            });
    }

    /// Hit-test the window's own edges, because an undecorated window has no frame to grab.
    ///
    /// Suppressed while a prompt is up along with everything else, so the scrimmed window cannot be
    /// resized out from under a consent prompt.
    fn resize_edges(&self, ctx: &egui::Context, full: Rect) {
        let Some(at) = ctx.input(|i| i.pointer.latest_pos()) else {
            return;
        };
        let Some(direction) = edge_at(full, at) else {
            return;
        };
        ctx.set_cursor_icon(resize_cursor(direction));
        if ctx.input(|i| i.pointer.primary_pressed()) {
            ctx.send_viewport_cmd(egui::ViewportCommand::BeginResize(direction));
        }
    }
}

/// The placeholder content pane.
///
/// The sidebar and the six tab panes are a separate change; this is the host, and the host is proven
/// on its own before anything is rendered into it.
///
/// Allocated with [`egui::Sense::hover`] rather than `Sense::click` while a prompt is up. That is
/// what keeps the pointer the default arrow over the scrimmed surface: a pointing-hand cursor says
/// *clickable* louder than any amount of dimming says *inert*. `egui`'s own `disable()` is not used
/// because its grey multipliers would fight the token palette.
fn pane(ui: &mut egui::Ui, full: Rect, t: &Tokens, prompt_is_up: bool) {
    let body = Rect::from_min_max(
        egui::Pos2::new(full.left(), full.top() + CHROME_HEIGHT),
        full.right_bottom(),
    );
    let sense = match prompt_is_up {
        true => egui::Sense::hover(),
        false => egui::Sense::click(),
    };
    ui.interact(body, egui::Id::new("dig-app-shell-pane"), sense);
    ui.painter().text(
        body.left_top() + Vec2::new(space::S6, space::S6),
        egui::Align2::LEFT_TOP,
        PANE_HEADING,
        semibold(size::HEADING),
        rgba(t.text),
    );
    ui.painter().text(
        body.left_top() + Vec2::new(space::S6, space::S6 + PANE_LINE),
        egui::Align2::LEFT_TOP,
        PANE_BODY,
        regular(size::SM),
        rgba(t.muted),
    );
}

/// The scrim colour: the theme's own shadow at the theme's own alpha.
///
/// Derived rather than added to [`Tokens`] on purpose — a token with no counterpart in hub's
/// `globals.css` breaks the by-eye diffability the token table exists for.
fn scrim(t: &Tokens, theme: Theme) -> Rgba {
    let a = match theme {
        Theme::Light => SCRIM_ALPHA_LIGHT,
        Theme::Dark => SCRIM_ALPHA_DARK,
    };
    Rgba { a, ..t.shadow }
}

/// Which window edge, if any, `at` is grabbing.
fn edge_at(full: Rect, at: egui::Pos2) -> Option<egui::viewport::ResizeDirection> {
    use egui::viewport::ResizeDirection as D;
    if !full.contains(at) {
        return None;
    }
    let west = at.x - full.left() <= RESIZE_GRAB;
    let east = full.right() - at.x <= RESIZE_GRAB;
    let north = at.y - full.top() <= RESIZE_GRAB;
    let south = full.bottom() - at.y <= RESIZE_GRAB;
    match (north, south, west, east) {
        (true, _, true, _) => Some(D::NorthWest),
        (true, _, _, true) => Some(D::NorthEast),
        (_, true, true, _) => Some(D::SouthWest),
        (_, true, _, true) => Some(D::SouthEast),
        (true, ..) => Some(D::North),
        (_, true, ..) => Some(D::South),
        (_, _, true, _) => Some(D::West),
        (_, _, _, true) => Some(D::East),
        _ => None,
    }
}

/// The pointer shape that names which way an edge will move.
fn resize_cursor(direction: egui::viewport::ResizeDirection) -> egui::CursorIcon {
    use egui::viewport::ResizeDirection as D;
    match direction {
        D::North | D::South => egui::CursorIcon::ResizeVertical,
        D::East | D::West => egui::CursorIcon::ResizeHorizontal,
        D::NorthEast | D::SouthWest => egui::CursorIcon::ResizeNeSw,
        D::NorthWest | D::SouthEast => egui::CursorIcon::ResizeNwSe,
    }
}

/// The width of the chrome's Close control.
const CLOSE_WIDTH: f32 = 72.0;
/// The raise pill's size.
const PILL_WIDTH: f32 = 220.0;
/// See [`PILL_WIDTH`].
const PILL_HEIGHT: f32 = 44.0;
/// The pill's label. Names the ACTION, so it cannot be read as a way to dismiss the prompt.
const RAISE_LABEL: &str = "Show the prompt";
/// The placeholder pane's heading.
const PANE_HEADING: &str = "DIG";
/// The placeholder pane's one line of body copy.
const PANE_BODY: &str = "This window is not finished yet.";
/// The gap between the placeholder heading and its body line.
const PANE_LINE: f32 = 34.0;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::confirm::gui::window::ANSWER_GRACE;
    use crate::confirm::{InputOutcome, SignPrompt, WindowIntent};
    use std::sync::mpsc::{self, sync_channel, Receiver, TryRecvError};
    use std::time::Duration;

    /// A deadline no test reaches by accident, so nothing here is timing-dependent.
    const PATIENT: Duration = Duration::from_secs(3600);

    /// The shell's test size. Real numbers, so the layout under test is the shipped one.
    fn shell_size() -> Vec2 {
        Vec2::new(SHELL_WIDTH, SHELL_HEIGHT)
    }

    fn sign_screen() -> super::super::Screen {
        let content = crate::confirm::ConfirmContent::sign(&SignPrompt {
            origin: "https://dapp.example",
            payload_type: "spend",
            decoded_tx: Some("Send 0.001 XCH to xch1safe\u{2026}addr"),
        })
        .expect("a decoded transaction yields content");
        super::super::Screen::confirm(&content, "Cancel")
    }

    /// A shell driven frame by frame, with a queue a test can put prompts on.
    struct Shelf {
        app: ShellApp,
        ctx: egui::Context,
        jobs: mpsc::Sender<Work>,
        queue: Receiver<Work>,
        store: ThemeChoice,
        _dir: tempfile::TempDir,
    }

    impl Shelf {
        fn open() -> Self {
            let dir = tempfile::tempdir().expect("a temp dir");
            let store = ThemeChoice::in_brand_dir(dir.path());
            let (jobs, queue) = mpsc::channel::<Work>();
            let ctx = egui::Context::default();
            install_fonts(&ctx);
            Self {
                app: ShellApp::new(Theme::Light, store.clone()),
                ctx,
                jobs,
                queue,
                store,
                _dir: dir,
            }
        }

        /// Queue a prompt whose caller gives up at `over_by`, and hand back its reply channel.
        fn queue_prompt(&self, over_by: Instant) -> Receiver<Outcome> {
            let (reply, answers) = sync_channel(1);
            self.jobs
                .send(Work::Prompt(Job {
                    screen: sign_screen(),
                    wants_text: false,
                    theme: self.store.clone(),
                    deadline: PATIENT,
                    over_by,
                    reply,
                }))
                .expect("the shell queue is open");
            answers
        }

        /// Queue a prompt the caller is still waiting on.
        fn queue_live_prompt(&self) -> Receiver<Outcome> {
            self.queue_prompt(Instant::now() + PATIENT + ANSWER_GRACE)
        }

        fn raw_input(&self, events: Vec<egui::Event>) -> egui::RawInput {
            egui::RawInput {
                screen_rect: Some(Rect::from_min_size(egui::Pos2::ZERO, shell_size())),
                events,
                ..Default::default()
            }
        }

        /// Run one frame carrying `events`.
        fn frame(&mut self, events: Vec<egui::Event>) -> egui::FullOutput {
            let input = self.raw_input(events);
            let (app, queue) = (&mut self.app, &self.queue);
            self.ctx.run(input, |ctx| app.frame(ctx, queue))
        }

        /// Two quiet frames: the first builds the font atlas, the second lays out against it.
        fn settle(&mut self) {
            self.frame(Vec::new());
            self.frame(Vec::new());
        }

        /// The frame the windowing system delivers when the shell itself is asked to close.
        fn close_frame(&mut self) -> egui::FullOutput {
            let mut input = self.raw_input(Vec::new());
            input
                .viewports
                .get_mut(&egui::ViewportId::ROOT)
                .expect("the root viewport")
                .events
                .push(egui::ViewportEvent::Close);
            let (app, queue) = (&mut self.app, &self.queue);
            self.ctx.run(input, |ctx| app.frame(ctx, queue))
        }
    }

    /// Every string the painter was actually asked to draw this frame.
    fn drawn_text(output: &egui::FullOutput) -> Vec<String> {
        fn walk(shape: &egui::Shape, out: &mut Vec<String>) {
            match shape {
                egui::Shape::Text(text) => out.push(text.galley.text().to_owned()),
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

    /// Whether the PROMPT's own copy — not the shell's — was laid out this frame.
    ///
    /// Keyed on the origin line, which only a consent prompt draws. The shell's placeholder never
    /// contains it, so this cannot read the shell back as a prompt.
    fn a_prompt_was_drawn(output: &egui::FullOutput) -> bool {
        drawn_text(output)
            .iter()
            .any(|line| line.contains("dapp.example"))
    }

    /// Whether the SHELL was laid out this frame.
    ///
    /// The truthful control for every assertion that a prompt is ABSENT: without it, a frame that
    /// drew nothing at all would read as a successful dismissal.
    fn the_shell_was_drawn(output: &egui::FullOutput) -> bool {
        drawn_text(output).iter().any(|line| line == PANE_BODY)
    }

    /// Press Escape.
    fn escape() -> Vec<egui::Event> {
        vec![egui::Event::Key {
            key: Key::Escape,
            physical_key: None,
            pressed: true,
            repeat: false,
            modifiers: egui::Modifiers::NONE,
        }]
    }

    /// Whether the shell asked its OWN window to close this frame.
    fn asked_to_close(output: &egui::FullOutput) -> bool {
        output
            .viewport_output
            .get(&egui::ViewportId::ROOT)
            .is_some_and(|v| {
                v.commands
                    .iter()
                    .any(|c| matches!(c, egui::ViewportCommand::Close))
            })
    }

    // ---------------------------------------------------------------------------------------------
    // A prompt raised while the window is open is DRAWN, not aged out behind it
    // ---------------------------------------------------------------------------------------------

    /// **A prompt raised while the app window is open is drawn, not parked behind it.**
    ///
    /// This is the reason the shell pumps the queue at all. `serve_with` serves one job at a time,
    /// so a shell that merely occupied that slot would leave every prompt raised over it unread
    /// until [`Job::over_by`] elapsed, then refused WITHOUT BEING DRAWN — a dapp asks for a
    /// signature, nothing appears, the request is refused, and no surface explains why.
    ///
    /// Asserted against `over_by` semantics rather than a sleep: this caller is still waiting (an
    /// hour out), so a refusal on this fixture could only mean the shell aged it out. The companion
    /// test below is the same fixture with the ONE field that decides staleness moved, which is what
    /// makes the pair able to tell drawing from ageing.
    #[test]
    fn a_prompt_raised_over_the_open_shell_is_drawn_rather_than_aged_out() {
        let mut shelf = Shelf::open();
        shelf.settle();
        let answers = shelf.queue_live_prompt();

        shelf.frame(Vec::new());
        let output = shelf.frame(Vec::new());

        assert!(
            a_prompt_was_drawn(&output),
            "the prompt was never laid out; a shell that does not pump the queue disables consent \
             for as long as it is open"
        );
        assert_eq!(
            answers.try_recv().err(),
            Some(TryRecvError::Empty),
            "the caller was answered without the prompt ever being drawn — the silent refusal this \
             design exists to prevent"
        );
    }

    /// …and the control: the SAME fixture whose caller has already given up is refused WITHOUT
    /// being drawn.
    ///
    /// Exactly one field differs from the test above — `over_by` — so the pair distinguishes "draws
    /// everything it is handed" from "draws what is still wanted". Opening a real consent window for
    /// an operation nobody is waiting on teaches the click-through reflex (dig_ecosystem#2074).
    #[test]
    fn a_prompt_whose_caller_gave_up_is_refused_by_the_shell_without_being_drawn() {
        let mut shelf = Shelf::open();
        shelf.settle();
        let answers = shelf.queue_prompt(Instant::now() - Duration::from_secs(1));

        shelf.frame(Vec::new());
        let output = shelf.frame(Vec::new());

        assert!(
            !a_prompt_was_drawn(&output),
            "a consent window was opened for a caller that had already given up"
        );
        assert!(
            the_shell_was_drawn(&output),
            "the shell itself must still be on screen — without this the assertion above would \
             also pass on a frame that drew nothing at all"
        );
        assert!(
            matches!(
                answers.recv_timeout(Duration::from_secs(1)),
                Ok(Outcome::Confirm(WindowIntent::Unavailable))
            ),
            "a stale prompt is refused fail-closed, never dropped and never approved"
        );
    }

    // ---------------------------------------------------------------------------------------------
    // A panicking shell costs the shell and nothing else
    // ---------------------------------------------------------------------------------------------

    /// **A panic in the shell refuses the shell and the loop takes the next job.**
    ///
    /// The prompt thread cannot be replaced, so a shell that took it down on the way out would be a
    /// silent, permanent consent lockout for the session — and it would look exactly like an app
    /// that had simply stopped showing prompts.
    ///
    /// Asserted on a prompt served AFTER the panic, because a loop that dies here still answers
    /// every question asked before it.
    #[test]
    fn a_panicking_shell_does_not_take_the_prompt_thread_down_with_it() {
        let lane = super::super::tests::Lane::serving_work(|work, _queue| match work {
            Work::Shell(_) => panic!("the app window panicked mid-draw"),
            Work::Prompt(_) => Some(Outcome::Confirm(WindowIntent::Deny)),
        });

        lane.open_shell();
        assert!(
            matches!(lane.ask(), Ok(Outcome::Confirm(WindowIntent::Deny))),
            "the prompt thread stopped serving after the app window panicked, which is a consent \
             lockout for the life of the process"
        );
    }

    /// **The shell is not a consent surface.**
    ///
    /// The tray disables its foreground claim while a consent surface is up (dig-app#91). Counting
    /// the shell would disable that claim for the whole life of a window somebody may leave open all
    /// day — and a disabled claim is indistinguishable from a working one.
    ///
    /// Read from INSIDE the draw, which is the only moment a wrongly-scoped `Raised` is observable.
    #[test]
    fn the_shell_alone_is_not_a_consent_surface() {
        use crate::confirm::surface::consent_surface_is_up;
        use std::sync::atomic::{AtomicBool, Ordering};

        let seen: &'static AtomicBool = Box::leak(Box::new(AtomicBool::new(true)));
        let lane = super::super::tests::Lane::serving_work(move |work, _queue| {
            if matches!(work, Work::Shell(_)) {
                seen.store(consent_surface_is_up(), Ordering::SeqCst);
            }
            Some(Outcome::Confirm(WindowIntent::Deny))
        });

        lane.open_shell();
        // Serialises against the draw above: the loop is strictly ordered, so an answered prompt
        // proves the shell's draw has already returned.
        lane.ask().expect("the lane answers");

        assert!(
            !seen.load(Ordering::SeqCst),
            "the app window reported itself as a consent surface; the tray's foreground claim \
             would be disabled for as long as the window stayed open"
        );
    }

    // ---------------------------------------------------------------------------------------------
    // One prompt at a time
    // ---------------------------------------------------------------------------------------------

    /// **A second prompt is not admitted while one is active.**
    ///
    /// One-modal-at-a-time is a security property, not a tidiness one: a second consent window
    /// stacked over a first can obscure what is actually being authorised. The shell enforces it by
    /// not polling the queue at all while [`ShellApp::prompt`] is set.
    ///
    /// Asserted on the SECOND caller still waiting AND on the job still being on the queue — not on
    /// a glyph count. A shell that admitted both and drew only one would pass a glyph assertion and
    /// still have taken the job somewhere nothing will ever answer it.
    #[test]
    fn a_second_prompt_is_not_admitted_while_one_is_active() {
        let mut shelf = Shelf::open();
        shelf.settle();
        let _first = shelf.queue_live_prompt();
        let second = shelf.queue_live_prompt();

        for _ in 0..4 {
            shelf.frame(Vec::new());
        }

        assert!(shelf.app.prompt.is_some(), "the first prompt is up");
        assert_eq!(
            second.try_recv().err(),
            Some(TryRecvError::Empty),
            "the second prompt was answered while the first was still up"
        );
        assert!(
            matches!(shelf.queue.try_recv(), Ok(Work::Prompt(_))),
            "the second prompt must still be ON the queue, waiting its turn — a shell that \
             consumed and dropped it would strand its caller on recv_timeout"
        );
    }

    /// **A second open-the-window request while the window is open is discarded, not left in front
    /// of the next real prompt.** Nobody is blocked on it, so there is nothing to answer.
    #[test]
    fn a_second_open_request_while_the_shell_is_open_is_discarded() {
        let mut shelf = Shelf::open();
        shelf.settle();
        shelf
            .jobs
            .send(Work::Shell(Shell {
                theme: shelf.store.clone(),
            }))
            .expect("the queue is open");
        let answers = shelf.queue_live_prompt();

        for _ in 0..4 {
            shelf.frame(Vec::new());
        }

        assert!(
            shelf.app.prompt.is_some(),
            "the duplicate open request blocked the prompt behind it"
        );
        assert_eq!(answers.try_recv().err(), Some(TryRecvError::Empty));
    }

    // ---------------------------------------------------------------------------------------------
    // Escape
    // ---------------------------------------------------------------------------------------------

    /// **Escape with a prompt up denies the prompt and leaves the shell open.**
    ///
    /// One Escape that both denied the prompt AND closed the shell would be a single keystroke
    /// tearing down the window that authorises spending. The prompt's claim on Escape is decided by
    /// [`ShellApp::prompt`], not by which viewport the framework happens to route input to.
    #[test]
    fn escape_with_a_prompt_up_denies_the_prompt_and_leaves_the_shell_open() {
        let mut shelf = Shelf::open();
        shelf.settle();
        let answers = shelf.queue_live_prompt();
        shelf.frame(Vec::new());
        shelf.frame(Vec::new());
        assert!(shelf.app.prompt.is_some(), "the prompt is up before Escape");

        shelf.frame(escape());

        // Asserted on the shell's OWN flag, not on a `Close` in the frame's viewport output.
        // `PromptApp::record` sends a close command of its own, and on a host that embeds an
        // immediate viewport rather than giving it a window both land on the same viewport id — so
        // the command is genuinely ambiguous here while the flag never is. The flag is also the
        // mechanism under test: it is what decides that the prompt owns Escape.
        assert!(
            !shelf.app.closing,
            "Escape closed the app window while a consent prompt was on top of it"
        );
        let after = shelf.frame(Vec::new());
        assert!(
            the_shell_was_drawn(&after),
            "the shell stopped drawing itself after an Escape aimed at the prompt"
        );
        assert!(
            matches!(
                answers.recv_timeout(Duration::from_secs(1)),
                Ok(Outcome::Confirm(WindowIntent::Deny))
            ),
            "Escape must reach the prompt and deny it"
        );
    }

    /// **Escape with no prompt up closes the shell.**
    ///
    /// The window is undecorated, so Escape is an escape hatch and never-trap-the-user (HARD) makes
    /// it mandatory. Paired with the test above, the two pin BOTH sides of the one condition.
    #[test]
    fn escape_with_no_prompt_up_closes_the_shell() {
        let mut shelf = Shelf::open();
        shelf.settle();

        let output = shelf.frame(escape());

        assert!(
            shelf.app.closing,
            "Escape did not close the app window; an undecorated window with no working Escape is \
             a trap"
        );
        assert!(
            asked_to_close(&output),
            "the shell decided to close and never told its window; a flag nobody acts on is not \
             an escape hatch"
        );
    }

    // ---------------------------------------------------------------------------------------------
    // Closing the shell over a prompt
    // ---------------------------------------------------------------------------------------------

    /// **Closing the shell over an unanswered prompt answers that prompt fail-closed.**
    ///
    /// The caller is blocked on `recv_timeout`. A dropped reply strands it for its whole deadline
    /// with no explanation; an approval here would be consent nobody gave. `Unavailable` is the only
    /// honest answer, and it must actually be SENT.
    #[test]
    fn closing_the_shell_over_an_unanswered_prompt_answers_fail_closed() {
        let mut shelf = Shelf::open();
        shelf.settle();
        let answers = shelf.queue_live_prompt();
        shelf.frame(Vec::new());
        assert!(
            shelf.app.prompt.is_some(),
            "the prompt is up before the close"
        );

        shelf.close_frame();

        assert!(
            matches!(
                answers.recv_timeout(Duration::from_secs(1)),
                Ok(Outcome::Confirm(WindowIntent::Unavailable))
            ),
            "the caller was left waiting, or was told something other than Unavailable"
        );
    }

    /// **An answer the person ALREADY gave survives the shell closing over it.**
    ///
    /// The fail-closed default above must never overwrite a recorded answer. This is
    /// dig_ecosystem#2038 at the shell boundary: there, a teardown frame turned every approval into
    /// a refusal, and the fix was [`PromptApp::record`]'s latch. A shell that authored the outcome
    /// itself would reach around that latch and reintroduce the same inversion — so this asserts on
    /// `Approve` specifically, the one value a fail-closed shell can never produce.
    #[test]
    fn an_answer_the_person_gave_survives_the_shell_closing_over_it() {
        let mut shelf = Shelf::open();
        shelf.settle();
        let answers = shelf.queue_live_prompt();
        shelf.frame(Vec::new());

        // The human answers, recorded through the prompt's OWN latch exactly as a click does.
        let ctx = shelf.ctx.clone();
        let prompt = shelf.app.prompt.as_mut().expect("the prompt is up");
        prompt
            .app
            .record(&ctx, Outcome::Confirm(WindowIntent::Approve));

        shelf.close_frame();

        assert!(
            matches!(
                answers.recv_timeout(Duration::from_secs(1)),
                Ok(Outcome::Confirm(WindowIntent::Approve))
            ),
            "the shell overwrote an approval the person had already given — dig_ecosystem#2038, \
             where every affirmative in the app answered Deny"
        );
    }

    /// **The fail-closed answer takes the shape the caller is waiting for.**
    ///
    /// An input prompt's caller matches on [`InputOutcome`]; handing it a `Confirm` would be an
    /// unhandled arm, not a refusal.
    #[test]
    fn the_fail_closed_answer_for_an_input_prompt_is_an_input_outcome() {
        let mut shelf = Shelf::open();
        shelf.settle();
        let (reply, answers) = sync_channel(1);
        shelf
            .jobs
            .send(Work::Prompt(Job {
                screen: sign_screen(),
                wants_text: true,
                theme: shelf.store.clone(),
                deadline: PATIENT,
                over_by: Instant::now() + PATIENT + ANSWER_GRACE,
                reply,
            }))
            .expect("the queue is open");
        shelf.frame(Vec::new());

        shelf.close_frame();

        assert!(
            matches!(
                answers.recv_timeout(Duration::from_secs(1)),
                Ok(Outcome::Input(InputOutcome::Unavailable))
            ),
            "an input prompt must be refused as an input outcome"
        );
    }

    // ---------------------------------------------------------------------------------------------
    // Dismissal — the measured hazard
    // ---------------------------------------------------------------------------------------------

    /// **A prompt is dismissed by the shell NO LONGER SHOWING IT.**
    ///
    /// `ViewportCommand::Close` does not close a viewport. Measured on Windows 11: it raises
    /// `close_requested()` and the child's window handle afterwards is the SAME handle. A shell that
    /// waited for the command to take effect would leave an undismissable consent prompt on screen
    /// while every signal it read said the dismissal had worked (the dig-app#86 class).
    ///
    /// So the assertion is placed where the two implementations differ: the frame AFTER the prompt
    /// records its answer must not lay the prompt out at all. A shell rewired to keep showing the
    /// viewport until it observes a close event never reaches that state, because nothing delivers
    /// that event — and this test goes red. Proven by doing exactly that; see the PR body.
    ///
    /// `the_shell_was_drawn` is the control: without it, a frame that painted nothing whatsoever
    /// would satisfy the absence assertion.
    #[test]
    fn a_prompt_is_dismissed_by_the_shell_ceasing_to_show_it() {
        let mut shelf = Shelf::open();
        shelf.settle();
        let _answers = shelf.queue_live_prompt();
        shelf.frame(Vec::new());
        let up = shelf.frame(Vec::new());
        assert!(
            a_prompt_was_drawn(&up),
            "the prompt is on screen to begin with"
        );

        let ctx = shelf.ctx.clone();
        let prompt = shelf.app.prompt.as_mut().expect("the prompt is up");
        prompt
            .app
            .record(&ctx, Outcome::Confirm(WindowIntent::Deny));
        // The frame that observes the answer still draws the prompt; the NEXT one must not.
        shelf.frame(Vec::new());
        let after = shelf.frame(Vec::new());

        assert!(
            !a_prompt_was_drawn(&after),
            "the prompt was still being shown after it was answered — a consent surface that \
             cannot be dismissed"
        );
        assert!(
            the_shell_was_drawn(&after),
            "the shell must still be on screen, or the assertion above would pass on a frame that \
             drew nothing"
        );
        assert!(
            shelf.app.prompt.is_none(),
            "the field IS the dismissal; a prompt left in it is a prompt left on screen"
        );
    }

    // ---------------------------------------------------------------------------------------------
    // The scrimmed shell must not look clickable
    // ---------------------------------------------------------------------------------------------

    /// **The pointer stays the default arrow over the scrimmed pane.**
    ///
    /// A pointing-hand cursor over a dimmed pane says *clickable* louder than any amount of dimming
    /// says *inert*. The pane allocates [`egui::Sense::hover`] while a prompt is up, which is what
    /// gets the cursor right; egui's own `disable()` would fight the token palette instead.
    #[test]
    fn the_cursor_stays_an_arrow_over_the_pane_while_a_prompt_is_up() {
        let mut shelf = Shelf::open();
        shelf.settle();
        let _answers = shelf.queue_live_prompt();
        shelf.frame(Vec::new());

        // Inside the pane and well away from the raise pill.
        let over_the_pane = egui::Pos2::new(space::S6, SHELL_HEIGHT - space::S6);
        shelf.frame(vec![egui::Event::PointerMoved(over_the_pane)]);
        let output = shelf.frame(Vec::new());

        assert_eq!(
            output.platform_output.cursor_icon,
            egui::CursorIcon::Default,
            "the scrimmed pane offered a clickable cursor over a window that takes no input"
        );
    }

    /// **The pane IS interactive when no prompt is up.**
    ///
    /// The control for the test above: an implementation that senses nothing at all, ever, would
    /// satisfy it while being permanently inert.
    #[test]
    fn the_pane_is_interactive_when_no_prompt_is_up() {
        let mut shelf = Shelf::open();
        shelf.settle();
        let at = egui::Pos2::new(space::S6, SHELL_HEIGHT - space::S6);
        shelf.frame(vec![egui::Event::PointerMoved(at)]);
        shelf.frame(Vec::new());

        let sensed = shelf.ctx.read_response(egui::Id::new("dig-app-shell-pane"));
        assert!(
            sensed.is_some_and(|r| r.sense.senses_click()),
            "the pane takes no clicks even with nothing over it"
        );
    }

    /// **The raise pill is offered above the scrim, and its label names its action.**
    ///
    /// The prompt is its own OS window and can be dragged behind the shell; without an affordance
    /// that brings it back, the shell is permanently inert with no visible cause. The label must not
    /// read as a way to dismiss the prompt.
    #[test]
    fn the_scrim_offers_a_way_back_to_the_prompt() {
        let mut shelf = Shelf::open();
        shelf.settle();
        let _answers = shelf.queue_live_prompt();
        shelf.frame(Vec::new());
        let output = shelf.frame(Vec::new());

        assert!(
            drawn_text(&output).iter().any(|line| line == RAISE_LABEL),
            "no way back to a prompt the person may have buried behind the window"
        );
    }

    // ---------------------------------------------------------------------------------------------
    // Window posture and geometry
    // ---------------------------------------------------------------------------------------------

    /// **The shell is resizable and never always-on-top; the prompt over it is the reverse.**
    ///
    /// Both halves are safety properties. A non-topmost prompt is buried outright by one click on
    /// the shell and keeps repainting into a window nobody can see, while its deadline runs down to
    /// a refusal the person never saw. A topmost, non-resizable, undecorated shell could be neither
    /// dismissed nor moved.
    #[test]
    fn the_shell_and_the_prompt_have_opposite_window_postures() {
        let shell = native_options().viewport;
        assert_eq!(shell.window_level, None, "the shell must never be topmost");
        assert_eq!(shell.resizable, Some(true), "the shell must be resizable");
        assert_eq!(
            shell.decorations,
            Some(false),
            "the shell must read as the prompts do"
        );
        assert_eq!(
            shell.min_inner_size,
            Some(Vec2::splat(SHELL_MIN)),
            "the shell keeps a floor a person cannot shrink the way out of"
        );
        assert_eq!(
            shell.inner_size,
            Some(Vec2::new(SHELL_WIDTH, SHELL_HEIGHT)),
            "the shell opens at the size it asks for"
        );
        assert_eq!(
            shell.max_inner_size, None,
            "an infinite maximum made the real window come up ~23% too wide; there must be none"
        );

        let prompt = super::super::native_options("t", super::super::Chrome::Dialog).viewport;
        assert_eq!(
            prompt.window_level,
            Some(egui::WindowLevel::AlwaysOnTop),
            "the consent prompt must stay unmissable — this is what the shell must NOT copy"
        );
    }

    /// **Every window edge is grabbable, and the interior is not.**
    ///
    /// An undecorated resizable window has no frame the operating system draws, so this hit test is
    /// the only resize affordance there is. Pinned from BOTH sides: at the grab distance it must
    /// answer, half a pixel further in it must not.
    #[test]
    fn each_window_edge_resizes_and_the_interior_does_not() {
        use egui::viewport::ResizeDirection as D;
        let full = Rect::from_min_size(egui::Pos2::ZERO, shell_size());
        let inside = RESIZE_GRAB - 0.5;
        let outside = RESIZE_GRAB + 0.5;
        let (mid_x, mid_y) = (full.center().x, full.center().y);

        assert_eq!(edge_at(full, egui::Pos2::new(inside, mid_y)), Some(D::West));
        assert_eq!(
            edge_at(full, egui::Pos2::new(full.right() - inside, mid_y)),
            Some(D::East)
        );
        assert_eq!(
            edge_at(full, egui::Pos2::new(mid_x, inside)),
            Some(D::North)
        );
        assert_eq!(
            edge_at(full, egui::Pos2::new(mid_x, full.bottom() - inside)),
            Some(D::South)
        );
        assert_eq!(
            edge_at(full, egui::Pos2::new(inside, inside)),
            Some(D::NorthWest)
        );
        assert_eq!(
            edge_at(full, egui::Pos2::new(full.right() - inside, inside)),
            Some(D::NorthEast)
        );
        assert_eq!(
            edge_at(full, egui::Pos2::new(inside, full.bottom() - inside)),
            Some(D::SouthWest)
        );
        assert_eq!(
            edge_at(
                full,
                egui::Pos2::new(full.right() - inside, full.bottom() - inside)
            ),
            Some(D::SouthEast)
        );

        assert_eq!(
            edge_at(full, egui::Pos2::new(outside, mid_y)),
            None,
            "half a pixel past the grab must be interior, or the whole window would resize"
        );
        assert_eq!(edge_at(full, full.center()), None);
        assert_eq!(
            edge_at(full, egui::Pos2::new(-1.0, mid_y)),
            None,
            "a pointer outside the window grabs nothing"
        );
    }

    /// **The scrim dims both themes without blacking either out, and the two alphas differ.**
    ///
    /// Dark `surface` under a light-theme alpha is barely distinguishable from `bg`, so one value
    /// for both reads as inert in one theme and as a smudge in the other.
    #[test]
    fn the_scrim_dims_both_themes_without_blacking_them_out() {
        for theme in [Theme::Light, Theme::Dark] {
            let a = scrim(&theme.tokens(), theme).a;
            assert!(
                (96..=200).contains(&a),
                "the {theme:?} scrim at alpha {a} either fails to read as inert or hides the \
                 window entirely"
            );
        }
        assert!(
            scrim(&Theme::Dark.tokens(), Theme::Dark).a
                > scrim(&Theme::Light.tokens(), Theme::Light).a,
            "dark surfaces need the heavier scrim"
        );
    }
}
