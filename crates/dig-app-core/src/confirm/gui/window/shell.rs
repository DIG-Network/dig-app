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
    install_fonts, unavailable, Job, Outcome, PromptApp, Shell, Work, CHROME_HEIGHT, MAX_HEIGHT,
    TOGGLE_WIDTH, WIDTH,
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
            .with_max_inner_size([f32::INFINITY, MAX_HEIGHT.max(SHELL_HEIGHT)])
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
        let (escape, close_requested) = ctx.input(|i| {
            (
                i.key_pressed(Key::Escape),
                i.viewport().close_requested(),
            )
        });
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
            Rect::from_min_size(bar.left_top() + Vec2::new(space::S4, 12.0), Vec2::splat(20.0)),
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
            .interact(strip, egui::Id::new("dig-app-shell-drag"), egui::Sense::drag())
            .dragged();
        if dragged {
            ui.ctx()
                .send_viewport_cmd(egui::ViewportCommand::StartDrag);
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
                ui.painter().rect_filled(full, 0, rgba(scrim(t, self.theme)));

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
