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
//! takes at most one waiting prompt off the queue, and draws that prompt **inside itself**, as a
//! modal layer over a scrimmed pane. When it closes, `serve_with` resumes `recv` and nothing else
//! has changed.
//!
//! # One window (dig_ecosystem#2270)
//!
//! A prompt raised while this window is open used to be a second, real OS window stacked on top of
//! it: clicking *Show my recovery phrase…* in the app opened another window in front of the one you
//! were already looking at. It is now painted into this one, through the same
//! [`super::PromptApp::paint_into`] the standalone window uses, so the surface a person reads before
//! approving anything is pixel-identical between the two hosts.
//!
//! **A prompt raised while this window is CLOSED still gets its own window** ([`super::draw_watched`]).
//! A dapp asking for a signature does not get to force the whole app open, and that standalone path
//! is the audited consent surface; nothing here changes it.
//!
//! # Why the modal is the only thing on screen that responds
//!
//! The old child window was `always_on_top` because a non-topmost prompt was buried outright by one
//! click on the shell, while it went on repainting invisibly with [`super::Job::over_by`] counting
//! down. An in-window modal cannot be buried by the shell — it *is* the shell — but it can be
//! clicked *through*, which is the same defect wearing different clothes. Three things prevent it,
//! and each is asserted:
//!
//! * The panes are drawn non-interactive while a prompt is up, and the chrome draws no controls at
//!   all ([`ShellApp::paint_shell`]).
//! * The scrim is a full-window widget that SENSES clicks and drags, so anything under it that was
//!   still listening gets nothing ([`ShellApp::scrim`]).
//! * The modal is painted in a layer strictly above the scrim, so it — and only it — is reachable.
//!
//! Resizing is suppressed for the same reason, so the window cannot be dragged out from under a
//! consent prompt.
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
use super::super::render::{rgba, semibold, size, space};
use super::super::theme::{Rgba, Theme, ThemeChoice, Tokens};
use super::panes::{self, Click};
use super::{
    install_fonts, unavailable, AppWindow, Job, Outcome, PromptApp, Work, CHROME_HEIGHT,
    TOGGLE_WIDTH, WIDTH,
};
use crate::tray_menu::TrayAction;
use crate::window_model::{self, TabId, WindowModel};

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

/// How much of the shell's height the modal may take before it stops growing and scrolls.
///
/// The prompt's own [`super::MAX_HEIGHT`] is a bound against the MONITOR; this is the bound against
/// the window, and it is the tighter one whenever the shell is not full-screen. A modal taller than
/// its host would put the buttons past the bottom edge, which is a consent surface that cannot be
/// answered — the failure [`super::SCREEN_SHARE`] exists to prevent, one level in.
const MODAL_SHARE: f32 = 0.9;

/// Draw the app shell to completion. Always `None` — a shell produces no [`Outcome`].
///
/// Signature matches [`super::draw_watched`] so both are reachable through `serve_with`'s one
/// injection point, which is what lets a test make either of them misbehave.
pub(super) fn draw(shell: AppWindow, queue: &Receiver<Work>) -> Option<Outcome> {
    let theme = shell.theme.read();
    let app = ShellApp::new(theme, shell.theme, shell.view, shell.act);
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
        // The tray trimmed itself on the promise that this window would open. It did not, so the
        // promise is withdrawn and the full menu comes back (`crate::window_host`). Without this a
        // person is left with four rows and no route to the escape hatches.
        crate::window_host::note_open_failure();
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

/// A prompt being drawn as a modal layer inside the shell.
struct ActivePrompt {
    /// The real prompt, driven through the real paint path — [`super::PromptApp::paint_into`], the
    /// same one the standalone window paints through.
    app: PromptApp,
    /// A consent surface is on screen for exactly as long as this prompt is.
    ///
    /// # Why the guard lives on the prompt and not around the draw
    ///
    /// The tray disables its foreground claim while a consent surface is up (dig-app#91), and an
    /// in-window prompt is a consent surface for its whole LIFE, not for the microseconds of one
    /// frame. Scoping this to a draw would leave `consent_surface_is_up()` false in the gaps between
    /// frames — which is every moment a tray click actually arrives — and a tray click that yanks the
    /// foreground away from somebody typing a recovery phrase is exactly the defect that rule exists
    /// to stop. The #2253 audit found the shell-hosted path missing this guard entirely (its N1
    /// finding); this is where it is fixed.
    ///
    /// Held by [`ActivePrompt`] rather than by [`ShellApp`] so the two can never disagree: the
    /// surface is raised by the same value that makes the prompt exist and lowered by the same drop
    /// that dismisses it, on every path out — answered, escaped, expired, or the shell closing.
    _on_screen: crate::confirm::surface::Raised,
    /// The height the modal is drawn at, remembered between frames.
    ///
    /// Sized from the content the way [`super::PromptApp::fit_to_content`] sizes a real window, and
    /// for the same reason: a two-line notice in a 560 px card is 400 px of empty space between what
    /// is being asked and the button that answers it. It settles in two frames — the first lays out
    /// against a freshly built font atlas — and cannot oscillate, because the blocks wrap on a width
    /// that never changes.
    height: f32,
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
    /// The live tray snapshot, read once per frame — see [`super::AppWindow::view`].
    view: Arc<dyn Fn() -> crate::tray_menu::TrayView + Send + Sync>,
    /// Where a clicked row's verb goes — see [`super::AppWindow::act`].
    act: Arc<dyn Fn(TrayAction) + Send + Sync>,
    /// Which tab is showing.
    ///
    /// Held here rather than derived per frame because the model is REBUILT every frame from a view
    /// the node poll rewrites every five seconds. A selection recomputed from that would jump back
    /// to the first tab under a person who was reading the fourth.
    selected: TabId,
}

impl ShellApp {
    fn new(
        theme: Theme,
        theme_store: ThemeChoice,
        view: Arc<dyn Fn() -> crate::tray_menu::TrayView + Send + Sync>,
        act: Arc<dyn Fn(TrayAction) + Send + Sync>,
    ) -> Self {
        Self {
            theme,
            theme_store,
            prompt: None,
            closing: false,
            view,
            act,
            selected: FIRST_TAB,
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
        self.admit_one_prompt(ctx, queue);

        let t = self.theme.tokens();
        let prompt_is_up = self.prompt.is_some();
        self.paint_shell(ctx, &t, prompt_is_up);
        self.show_prompt(ctx, ctx.screen_rect());
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
    fn admit_one_prompt(&mut self, ctx: &egui::Context, queue: &Receiver<Work>) {
        if self.prompt.is_some() {
            return;
        }
        match queue.try_recv() {
            Ok(Work::Prompt(job)) => self.open(job),
            // A second open-the-window request while the window is open. Nobody is blocked on it and
            // there is nothing to answer, so it is not queued behind anything — but it is not
            // discarded either: the person asked for this window, so the window comes forward.
            //
            // `Focus` rather than a `WindowLevel` re-assert, which was measured to lift z-order while
            // leaving keyboard focus behind — a window the person can see and cannot type into.
            Ok(Work::Shell(_)) => {
                tracing::debug!("the DIG app window is already open; raising it instead");
                ctx.send_viewport_cmd(egui::ViewportCommand::Focus);
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
        tracing::debug!(prompt = %title, wants_text, "drawing a DIG prompt inside the app window");
        self.prompt = Some(ActivePrompt {
            app: PromptApp::in_window(job, theme_store, Arc::clone(&sink)),
            _on_screen: crate::confirm::surface::Raised::now(),
            height: super::HEIGHT,
            sink,
            reply,
            wants_text,
            title,
        });
    }

    /// Draw the active prompt as a modal layer inside this window, and dismiss it once answered.
    ///
    /// **Dropping [`ShellApp::prompt`] is what dismisses the modal** — the next frame simply does not
    /// paint it. That was already true when the prompt was a child viewport (a
    /// `ViewportCommand::Close` never destroyed one; ceasing to show it did), and it is trivially
    /// true now. Nothing here authors an answer: the prompt's own latch owns that, and
    /// [`ActivePrompt::settle`] only reads it.
    fn show_prompt(&mut self, ctx: &egui::Context, full: Rect) {
        let Some(active) = self.prompt.as_mut() else {
            return;
        };
        let at = modal_rect(full, active.height);

        // Strictly above the scrim's layer, so the modal is the one thing under the pointer that
        // still answers to it. Two named orders rather than two areas at the same order, whose
        // relative z-order egui decides from interaction history — not something a consent surface
        // should depend on.
        let content_bottom = egui::Area::new(egui::Id::new("dig-app-shell-modal"))
            .order(egui::Order::Tooltip)
            .fixed_pos(at.left_top())
            .show(ctx, |ui| {
                ui.set_clip_rect(at);
                active.app.frame_in_window(ui, at)
            })
            .inner;
        active.height = modal_height(full, at, content_bottom);

        if active.app.answered {
            // Taken out of the field FIRST: this is the dismissal.
            if let Some(answered) = self.prompt.take() {
                answered.settle();
            }
        }
    }

    /// Paint the shell itself: chrome, panes, and — while a prompt is up — the scrim and the pill.
    fn paint_shell(&mut self, ctx: &egui::Context, t: &Tokens, prompt_is_up: bool) {
        let screen = ctx.screen_rect();
        let model = window_model::build(&(self.view)());
        self.keep_selection_valid(&model);
        // An `Area` rather than a `CentralPanel` so the shell and the prompt it hosts never contend
        // for the one central-panel id on hosts where egui embeds an immediate viewport instead of
        // giving it a window of its own.
        let mut clicked = None;
        egui::Area::new(egui::Id::new("dig-app-shell"))
            .fixed_pos(screen.left_top())
            .order(egui::Order::Background)
            .show(ctx, |ui| {
                ui.set_clip_rect(screen);
                ui.painter().rect_filled(screen, 0, rgba(t.bg));
                self.chrome(ui, screen, t, prompt_is_up);
                let body = Rect::from_min_max(
                    egui::Pos2::new(screen.left(), screen.top() + CHROME_HEIGHT),
                    screen.right_bottom(),
                );
                clicked = panes::draw(ui, body, t, &model, self.selected, !prompt_is_up);
            });
        if let Some(click) = clicked {
            self.handle(click);
        }

        if prompt_is_up {
            self.scrim(ctx, screen, t);
        } else {
            self.resize_edges(ctx, screen);
        }
    }

    /// Keep the selection on a tab that still exists.
    ///
    /// Tabs come and go with the account state — an account being removed can take a tab's whole
    /// reason to exist with it — and a selection pointing at a tab that is no longer emitted would
    /// render an empty pane with a sidebar that highlights nothing. Falling back to the first tab is
    /// the one choice that is always valid, and `Status` leads the sidebar precisely because it is
    /// the tab that makes sense to land on when the app cannot say what else to show.
    fn keep_selection_valid(&mut self, model: &WindowModel) {
        if model.tab(self.selected).is_some() {
            return;
        }
        if let Some(first) = model.tabs.first() {
            self.selected = first.id;
        }
    }

    /// Act on a click in the body.
    ///
    /// # Why a verb is handed off rather than run
    ///
    /// This runs inside the frame, on the prompt thread. Calling [`super::ask`] here — which is what
    /// running a verb inline would eventually do — would block that thread inside its own frame,
    /// waiting on the queue this very frame owns. That is not a slow path, it is a deadlock with no
    /// timeout. So the verb goes to the same worker a tray click goes to, and this returns.
    fn handle(&mut self, click: Click) {
        match click {
            Click::Tab(tab) => self.selected = tab,
            Click::Act(action) => {
                tracing::debug!(?action, "a DIG app window row was clicked");
                (self.act)(action);
            }
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

    /// Dim the whole window, and swallow every click that lands on it.
    ///
    /// # Why the scrim is a widget and not a rectangle of paint
    ///
    /// Dimming says the window is inert; `allocate_rect` with a click-and-drag sense MAKES it inert.
    /// Both halves are needed, and only the second is a security property: a pane control that
    /// stayed live under a wash of translucent black could be clicked through the appearance of a
    /// modal, which is a worse version of the burial the always-on-top child window was there to
    /// prevent. The panes are already drawn non-interactive and the chrome draws no controls
    /// ([`ShellApp::paint_shell`]); this is the backstop that does not depend on either remembering,
    /// and it is given a NAMED id so a test can assert the backstop is really there rather than only
    /// that today's controls happen not to need it.
    ///
    /// # Why there is no longer a pill
    ///
    /// A *Show the prompt* affordance existed because the prompt was a separate OS window that could
    /// be dragged behind the shell or onto another display, leaving the shell inert with no visible
    /// cause. An in-window modal cannot go anywhere: it is drawn in this window, centred, above the
    /// scrim, every frame. There is nothing to find, so there is nothing to offer.
    fn scrim(&self, ctx: &egui::Context, full: Rect, t: &Tokens) {
        egui::Area::new(egui::Id::new("dig-app-shell-scrim"))
            .fixed_pos(full.left_top())
            .order(egui::Order::Foreground)
            .show(ctx, |ui| {
                ui.set_clip_rect(full);
                ui.painter()
                    .rect_filled(full, 0, rgba(scrim(t, self.theme)));
                ui.interact(full, scrim_blocker(), egui::Sense::click_and_drag());
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

/// Where the modal is drawn: horizontally centred, and vertically centred within what is left.
///
/// # Why a function and not two lines inside the painter
///
/// So it can be ASSERTED. Every placement claim this surface makes — that the modal is inside the
/// window, that it is centred, that it never overhangs an edge a person would have to resize the
/// window to reach past — is a claim about a rectangle, and a pure function is the only form of it a
/// headless test can hold. Nothing here reads the [`egui::Context`] for that reason.
///
/// Clamped to the window on both axes. On a shell dragged to [`SHELL_MIN`] the prompt's natural
/// [`super::WIDTH`] is wider than the window itself, and a card whose action row runs off the right
/// edge is a consent surface that cannot be refused.
fn modal_rect(full: Rect, height: f32) -> Rect {
    let size = Vec2::new(WIDTH.min(full.width()), height.min(full.height()));
    Rect::from_center_size(full.center(), size)
}

/// How tall the modal should be NEXT frame, given the content this one produced.
///
/// The in-window twin of [`super::PromptApp::fit_to_content`], which cannot be used directly because
/// it resizes a window and there is no window here to resize. The arithmetic is the same, and so is
/// the reason for it: a prompt is as tall as what it has to say — a two-line notice must not open a
/// 560 px card, and 24 recovery words must not be cut off at word 14 (dig_ecosystem#2038).
///
/// The ceiling is the tighter of the prompt's own [`super::MAX_HEIGHT`] and [`MODAL_SHARE`] of the
/// host window, so the modal cannot grow past the frame it lives in; past that the body scrolls.
fn modal_height(full: Rect, at: Rect, content_bottom: f32) -> f32 {
    let needed = (content_bottom - at.top()) + space::S6 + super::ACTION_ROW;
    let ceiling = super::MAX_HEIGHT
        .min(full.height() * MODAL_SHARE)
        .max(super::MIN_HEIGHT.min(full.height()));
    needed.clamp(super::MIN_HEIGHT.min(ceiling), ceiling)
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
/// The id of the scrim's input blocker — the widget that eats every click aimed under the modal.
///
/// Named rather than auto-generated so [`ShellApp::scrim`]'s guarantee is a thing a test can read
/// back, instead of an inference from the controls that happen to exist today.
fn scrim_blocker() -> egui::Id {
    egui::Id::new("dig-app-shell-scrim-blocker")
}
/// The tab the window opens on, and the one it falls back to when a selected tab stops existing.
///
/// Status, because it is the tab that makes sense when the app cannot yet say what else to show —
/// and because it holds `Open the log folder`, the escape hatch for when nothing else works.
const FIRST_TAB: TabId = TabId::Status;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::confirm::gui::window::ANSWER_GRACE;
    use crate::confirm::{InputOutcome, SignPrompt, WindowIntent};
    use crate::tray_menu::MenuRow;
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

    /// The view every test opens on unless it says otherwise: an unlocked, working, connected app.
    ///
    /// Deliberately the RICHEST state rather than the default. A window built from
    /// `TrayView::default()` has an absent account, so half the rows a person would click are not
    /// emitted at all — and a layout test on that fixture would be checking a nearly-empty pane
    /// while claiming to check the window.
    fn busy_view() -> crate::tray_menu::TrayView {
        crate::tray_menu::TrayView {
            running: true,
            account: Some(crate::tray_menu::AccountState::Unlocked { recoverable: true }),
            window_host: crate::tray_menu::WindowHost::Available,
            profile_id: Some("dig1examplepublicidentity".to_string()),
            receive_address: Some("xch1exampleaddress".to_string()),
            cache: Some(crate::cache::CacheSnapshot {
                cap_bytes: crate::cache::CACHE_PRESETS[2],
                used_bytes: 1_234_567,
            }),
            ..crate::tray_menu::TrayView::default()
        }
    }

    /// A shell driven frame by frame, with a queue a test can put prompts on.
    struct Shelf {
        app: ShellApp,
        ctx: egui::Context,
        jobs: mpsc::Sender<Work>,
        queue: Receiver<Work>,
        store: ThemeChoice,
        /// Every verb the window handed to the worker, in order.
        dispatched: Arc<Mutex<Vec<TrayAction>>>,
        /// The window's size for the next frame, so a test can narrow it.
        size: Vec2,
        _dir: tempfile::TempDir,
        /// Excludes every other test that raises or reads the process-global consent count.
        ///
        /// Held by the HARNESS rather than by the handful of tests that assert on the count,
        /// because since dig_ecosystem#2270 any shelf showing a prompt RAISES it — so every shelf is
        /// a raiser, whether or not it looks like one. Scoping the guard to the assertions instead
        /// would leave the raisers unsynchronised, which is the shape of the flake it fixes: two
        /// tests failing together, each having read the other's legitimate surface.
        ///
        /// The mirror of [`super::super::tests::Lane`]'s own guard. A test must therefore not build
        /// a `Shelf` and a `Lane` at once — the mutex is not reentrant, and doing so hangs rather
        /// than fails.
        _exclusive: std::sync::MutexGuard<'static, ()>,
    }

    impl Shelf {
        fn open() -> Self {
            Self::showing(busy_view())
        }

        /// A shell built over one fixed view.
        fn showing(view: crate::tray_menu::TrayView) -> Self {
            let exclusive = crate::confirm::surface::one_surface_at_a_time();
            let dir = tempfile::tempdir().expect("a temp dir");
            let store = ThemeChoice::in_brand_dir(dir.path());
            let (jobs, queue) = mpsc::channel::<Work>();
            let ctx = egui::Context::default();
            // Headless egui EMBEDS child viewports into the root, so a `show_viewport_immediate`
            // leaves no trace in `viewport_output` and every "no second window" assertion is
            // unfalsifiable by default — measured: the regression that put the prompt back into a
            // child viewport survived until this line existed. `eframe` clears the same flag on
            // desktop, so this is the host posture the shipped window actually runs under.
            ctx.set_embed_viewports(false);
            install_fonts(&ctx);
            let dispatched: Arc<Mutex<Vec<TrayAction>>> = Arc::new(Mutex::new(Vec::new()));
            let sink = Arc::clone(&dispatched);
            Self {
                app: ShellApp::new(
                    Theme::Light,
                    store.clone(),
                    Arc::new(move || view.clone()),
                    Arc::new(move |action| {
                        sink.lock().expect("the sink is not poisoned").push(action)
                    }),
                ),
                ctx,
                jobs,
                queue,
                store,
                dispatched,
                size: shell_size(),
                _dir: dir,
                _exclusive: exclusive,
            }
        }

        /// The centre of a control the last frame drew, so a click can be aimed at the real thing
        /// rather than at a coordinate that only happens to be over it today.
        fn centre_of(&self, id: egui::Id) -> egui::Pos2 {
            self.ctx
                .read_response(id)
                .unwrap_or_else(|| panic!("{id:?} was not drawn"))
                .rect
                .center()
        }

        /// Click at `at`: press, then release, then one more frame for the click to be observed.
        fn click(&mut self, at: egui::Pos2) {
            self.frame(vec![egui::Event::PointerMoved(at)]);
            self.frame(vec![egui::Event::PointerButton {
                pos: at,
                button: egui::PointerButton::Primary,
                pressed: true,
                modifiers: egui::Modifiers::default(),
            }]);
            self.frame(vec![egui::Event::PointerButton {
                pos: at,
                button: egui::PointerButton::Primary,
                pressed: false,
                modifiers: egui::Modifiers::default(),
            }]);
            self.frame(Vec::new());
        }

        /// Whether the SHELL asked to be brought forward within the next `frames` frames.
        fn asked_for_focus(&mut self, frames: usize) -> bool {
            (0..frames).any(|_| {
                self.frame(Vec::new())
                    .viewport_output
                    .get(&egui::ViewportId::ROOT)
                    .is_some_and(|root| {
                        root.commands
                            .iter()
                            .any(|command| matches!(command, egui::ViewportCommand::Focus))
                    })
            })
        }

        /// Everything the window has dispatched so far.
        fn dispatched(&self) -> Vec<TrayAction> {
            self.dispatched
                .lock()
                .expect("the sink is not poisoned")
                .clone()
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
                screen_rect: Some(Rect::from_min_size(egui::Pos2::ZERO, self.size)),
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
    /// Keyed on the origin line, which only a consent prompt draws. No window row contains it, so
    /// this cannot read the shell back as a prompt.
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
        // Keyed on the sidebar's own labels, which only the shell draws. `Status` leads the
        // sidebar in every state the model can produce, so this stays true for any view.
        drawn_text(output).iter().any(|line| line == "Status")
    }

    /// The element id of one sidebar entry.
    fn sidebar_entry(tab: TabId) -> egui::Id {
        egui::Id::new(crate::window_model::tab_element_id(tab))
    }

    /// The element id of the FIRST row carrying `label`, from the pane's own id function rather than
    /// a copy of it.
    fn row_control(label: &str) -> egui::Id {
        super::super::panes::row_id(label, 0)
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

    /// **A second open-the-window request RAISES the window it already opened.**
    ///
    /// Split from the queueing claim below on purpose. A prompt raised over the shell also asks for
    /// focus, and on a headless host egui EMBEDS the child viewport into the root — so its request
    /// is recorded against the root and a test that queued a prompt alongside the duplicate would
    /// read the prompt's focus as the shell's. Measured: with the raise removed, that version still
    /// passed. So this queues nothing but the duplicate, and carries its own control.
    #[test]
    fn a_second_open_request_raises_the_window_rather_than_doing_nothing() {
        let mut shelf = Shelf::open();
        shelf.settle();

        // The control, FIRST: an idle shell asks for focus on no frame of its own accord. Without
        // this the assertion below would pass on any implementation that focused constantly.
        assert!(
            !shelf.asked_for_focus(4),
            "the shell asks for focus without being asked to, so raising cannot be observed"
        );

        shelf
            .jobs
            .send(Work::Shell(AppWindow {
                theme: shelf.store.clone(),
                view: Arc::new(busy_view),
                act: Arc::new(|_| {}),
            }))
            .expect("the queue is open");

        assert!(
            shelf.asked_for_focus(4),
            "the window was not brought forward, so a second Open App does nothing visible"
        );
    }

    /// **A second open-the-window request is not left in front of the next real prompt.**
    ///
    /// Nobody is blocked on it and there is nothing to answer, so it must be consumed rather than
    /// queued — a duplicate sitting in the queue would delay the next consent prompt behind it.
    #[test]
    fn a_second_open_request_does_not_delay_the_next_prompt() {
        let mut shelf = Shelf::open();
        shelf.settle();
        shelf
            .jobs
            .send(Work::Shell(AppWindow {
                theme: shelf.store.clone(),
                view: Arc::new(busy_view),
                act: Arc::new(|_| {}),
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
    // The tabbed body
    // ---------------------------------------------------------------------------------------------

    /// **Every tab the model emits gets a sidebar entry, and the first one is showing.**
    #[test]
    fn the_sidebar_lists_every_tab_and_opens_on_the_first() {
        let mut shelf = Shelf::open();
        shelf.settle();
        let output = shelf.frame(Vec::new());
        let drawn = drawn_text(&output);

        let model = window_model::build(&busy_view());
        assert!(
            model.tabs.len() > 1,
            "the fixture must have tabs to choose between"
        );
        for tab in &model.tabs {
            assert!(
                drawn.iter().any(|line| line == &tab.label),
                "{:?} has no sidebar entry",
                tab.id
            );
        }
        assert_eq!(shelf.app.selected, FIRST_TAB);
    }

    /// **Clicking a sidebar entry shows that tab, and the choice survives later frames.**
    ///
    /// The survival half is the point. The model is rebuilt every frame from a view the node poll
    /// rewrites every five seconds, so a selection recomputed per frame would snap back to Status
    /// under someone reading the Account tab — and would do it on a timer they cannot see
    /// (dig_ecosystem#2074's shape, in a different surface).
    #[test]
    fn choosing_a_tab_shows_it_and_the_choice_survives_a_repaint() {
        let mut shelf = Shelf::open();
        shelf.settle();
        let at = shelf.centre_of(sidebar_entry(TabId::Account));
        shelf.click(at);

        assert_eq!(
            shelf.app.selected,
            TabId::Account,
            "the click did not change tabs"
        );

        let account_rows: Vec<String> = window_model::build(&busy_view())
            .tab(TabId::Account)
            .expect("the Account tab renders")
            .sections
            .iter()
            .flat_map(|section| &section.rows)
            .filter_map(|row| match row {
                MenuRow::Action { label, .. } => Some(label.clone()),
                _ => None,
            })
            .collect();
        assert!(
            !account_rows.is_empty(),
            "the fixture must give Account some rows"
        );

        for _ in 0..10 {
            let output = shelf.frame(Vec::new());
            let drawn = drawn_text(&output);
            assert_eq!(
                shelf.app.selected,
                TabId::Account,
                "the selection was reset by a repaint"
            );
            assert!(
                account_rows.iter().any(|label| drawn.contains(label)),
                "the Account tab stopped rendering its own rows"
            );
        }
    }

    /// **A selection whose tab stops existing falls back to a tab that does, rather than to nothing.**
    ///
    /// Fixture chosen so the fallback is OBSERVABLE: the shell starts on a tab the second view does
    /// not emit. An account being removed really does take tabs with it, and a sidebar highlighting
    /// a tab that is gone would render an empty pane with no way to notice why.
    #[test]
    fn a_selection_whose_tab_disappears_falls_back_to_one_that_exists() {
        let mut shelf = Shelf::open();
        shelf.settle();

        // A tab that exists in one model and not another. `Advanced` is declared and never
        // constructed, so it is exactly a selection the model cannot honour.
        shelf.app.selected = TabId::Advanced;
        shelf.frame(Vec::new());

        let model = window_model::build(&busy_view());
        assert!(
            model.tab(TabId::Advanced).is_none(),
            "the fixture must not emit the tab being selected, or nothing is tested"
        );
        assert_eq!(
            shelf.app.selected, model.tabs[0].id,
            "a selection pointing at a tab that is not emitted must fall back to one that is"
        );
    }

    /// **Clicking a row hands its verb to the worker — and does not run it here.**
    ///
    /// The window must never call the blocking `ask` inline: that blocks the prompt thread inside
    /// its own frame, waiting on the queue the frame owns. A guaranteed deadlock. So the assertion is
    /// that the verb ARRIVED AT THE SINK, and that the frame returned — a shell that ran the verb
    /// itself would never reach the next line.
    #[test]
    fn clicking_a_row_dispatches_its_verb_to_the_worker() {
        let mut shelf = Shelf::open();
        shelf.settle();
        assert!(
            shelf.dispatched().is_empty(),
            "nothing is dispatched before a click"
        );

        let at = shelf.centre_of(row_control("Open the log folder"));
        shelf.click(at);

        assert_eq!(
            shelf.dispatched(),
            vec![TrayAction::OpenLogs],
            "the clicked row's verb did not reach the worker"
        );
    }

    /// **A disabled row is drawn, and is not clickable.**
    ///
    /// Both halves matter and they pull against each other. A disabled row must still SHOW, because
    /// its label carries the remedy — "Show my recovery phrase (unlock first)" is the only place a
    /// locked account is told what to do — and hiding it would take that away (dig_ecosystem#1800).
    /// It must also not dispatch, or the window offers a control guaranteed to fail.
    #[test]
    fn a_disabled_row_is_shown_and_takes_no_click() {
        let locked = crate::tray_menu::TrayView {
            account: Some(crate::tray_menu::AccountState::Locked),
            ..busy_view()
        };
        let disabled: Vec<String> = window_model::build(&locked)
            .tabs
            .iter()
            .flat_map(|tab| &tab.sections)
            .flat_map(|section| &section.rows)
            .filter_map(|row| match row {
                MenuRow::Action {
                    label,
                    enabled: false,
                    ..
                } => Some(label.clone()),
                _ => None,
            })
            .collect();
        assert!(
            !disabled.is_empty(),
            "the locked fixture must produce a disabled row, or this test proves nothing"
        );

        let mut shelf = Shelf::showing(locked);
        shelf.settle();
        // The disabled rows live on Account; the window opens on Status.
        let account = shelf.centre_of(sidebar_entry(TabId::Account));
        shelf.click(account);
        shelf.dispatched.lock().expect("the sink").clear();

        let output = shelf.frame(Vec::new());
        let drawn = drawn_text(&output);
        let shown: Vec<&String> = disabled.iter().filter(|l| drawn.contains(l)).collect();
        assert!(
            !shown.is_empty(),
            "no disabled row was drawn, so its remedy was never shown: {disabled:?}"
        );

        for label in shown {
            let sensed = shelf
                .ctx
                .read_response(row_control(label))
                .unwrap_or_else(|| panic!("{label:?} was drawn but allocated no control"));
            assert!(
                !sensed.sense.senses_click(),
                "the disabled row {label:?} still takes clicks"
            );
            let at = sensed.rect.center();
            shelf.click(at);
            assert!(
                shelf.dispatched().is_empty(),
                "clicking the disabled row {label:?} dispatched {:?}",
                shelf.dispatched()
            );
        }
    }

    /// **Below the narrow threshold the sidebar becomes a strip, and every tab is still reachable.**
    ///
    /// The window can legitimately be dragged to [`SHELL_MIN`], and a 208 px sidebar out of 480 px
    /// leaves a content column narrower than the sidebar. Asserted on the tabs still being drawn AND
    /// still being clickable, not on a width — a layout that reflowed into an unreachable strip
    /// would satisfy a width assertion.
    #[test]
    fn a_narrow_window_keeps_every_tab_reachable() {
        let mut shelf = Shelf::open();
        shelf.size = Vec2::new(SHELL_MIN, SHELL_MIN);
        shelf.settle();
        let output = shelf.frame(Vec::new());
        let drawn = drawn_text(&output);

        for tab in &window_model::build(&busy_view()).tabs {
            assert!(
                drawn.iter().any(|line| line == &tab.label),
                "{:?} vanished when the window was narrowed to {SHELL_MIN}",
                tab.id
            );
        }

        let at = shelf.centre_of(sidebar_entry(TabId::Cache));
        shelf.click(at);
        assert_eq!(
            shelf.app.selected,
            TabId::Cache,
            "a tab chip in the narrow strip could not be clicked"
        );
    }

    /// **Each of the four pane states is actually painted**, keyed on the sentence the model chose.
    ///
    /// Reading the sentence back off the painter rather than off the model: a note the model
    /// produces and the pane never draws is a state that exists only in the tests.
    #[test]
    fn every_pane_state_reaches_the_screen() {
        let cases = [
            (
                "loading",
                crate::tray_menu::TrayView {
                    running: false,
                    ..busy_view()
                },
                TabId::Status,
            ),
            (
                "error",
                crate::tray_menu::TrayView {
                    cache: None,
                    ..busy_view()
                },
                TabId::Cache,
            ),
            (
                "empty",
                crate::tray_menu::TrayView {
                    account: Some(crate::tray_menu::AccountState::Absent),
                    receive_address: None,
                    ..busy_view()
                },
                TabId::Wallet,
            ),
        ];

        for (name, view, tab) in cases {
            let expected = match window_model::build(&view)
                .tab(tab)
                .unwrap_or_else(|| panic!("{name}: {tab:?} must render"))
                .note
                .clone()
            {
                window_model::PaneNote::Ready => {
                    panic!("{name}: the fixture produced the success state, so nothing is tested")
                }
                window_model::PaneNote::Waiting(text)
                | window_model::PaneNote::Unreachable(text)
                | window_model::PaneNote::Empty(text) => text,
            };

            let mut shelf = Shelf::showing(view);
            shelf.settle();
            let at = shelf.centre_of(sidebar_entry(tab));
            shelf.click(at);
            let output = shelf.frame(Vec::new());
            assert!(
                drawn_text(&output).iter().any(|line| line == expected),
                "{name}: {tab:?} never painted its note {expected:?}"
            );
        }

        // The success state paints no note at all, which is what makes the three above meaningful.
        let mut shelf = Shelf::open();
        shelf.settle();
        let at = shelf.centre_of(sidebar_entry(TabId::Cache));
        shelf.click(at);
        let output = shelf.frame(Vec::new());
        assert_eq!(
            window_model::build(&busy_view())
                .tab(TabId::Cache)
                .map(|tab| tab.note.clone()),
            Some(window_model::PaneNote::Ready)
        );
        assert!(
            !drawn_text(&output)
                .iter()
                .any(|line| line.contains("No node is connected")),
            "a ready tab painted the error note anyway"
        );
    }

    /// **No two controls on a tab share an element id** — the defect the gallery found and no
    /// headless test was looking for.
    ///
    /// The Account tab draws `About on-chain DIDs…` twice, from two different group builders, and a
    /// label-only id gave both the same name. egui painted its duplicate-id warning across the pane
    /// and the second row could not be addressed at all. Every assertion in this file passed.
    ///
    /// Asserted by reading egui's OWN id-clash report rather than by re-deriving the ids here: a test
    /// that recomputed them would agree with any id function, including a broken one. The tab with
    /// the repeat is visited explicitly, and its repeat is proven present first — otherwise this
    /// passes on a fixture that never draws two rows with one label.
    #[test]
    fn no_two_rows_on_a_tab_are_given_the_same_element_id() {
        // The fixture must actually contain the hazard, or this passes without exercising anything.
        //
        // The hazard is two rows on ONE pane sharing an ACTION, because the element id derives from
        // the action. It used to be spelled as two rows sharing a LABEL, which was true of the Account
        // tab's repeated `AboutDid`; that repeat is now removed by `drop_repeats` (dig_ecosystem#2253),
        // so pinning to a label would leave this test guarding nothing.
        //
        // A shared ACTION is not a defect and is not removed: the Cache tab with no node connected
        // deliberately offers "Change the size limit (connect a node first)…" and "About the cache and
        // your privacy…", both `AboutCache`, because they open the same window. That is exactly the
        // case the occurrence counter in the id function exists for — so it is the right subject.
        let hazard_view = crate::tray_menu::TrayView {
            cache: None,
            ..busy_view()
        };
        let repeated: Vec<TrayAction> = {
            let mut actions: Vec<TrayAction> = window_model::build(&hazard_view)
                .tabs
                .iter()
                .flat_map(|tab| tab.sections.iter())
                .flat_map(|section| &section.rows)
                .filter_map(|row| match row {
                    MenuRow::Action { action, .. } => Some(*action),
                    _ => None,
                })
                .collect();
            let mut repeats = Vec::new();
            for (i, action) in actions.iter().enumerate() {
                if actions[..i].contains(action) && !repeats.contains(action) {
                    repeats.push(*action);
                }
            }
            actions.clear();
            repeats
        };
        assert!(
            !repeated.is_empty(),
            "no tab draws two rows sharing an action, so this test can no longer see the id collision it exists for — find a view that does, or delete it deliberately"
        );

        // Driven over the SAME view the hazard was proven in — walking `busy_view` here would click
        // through tabs that do not contain the shared action and report clean.
        let mut shelf = Shelf::showing(hazard_view.clone());
        shelf.settle();
        for tab in &window_model::build(&hazard_view).tabs {
            let at = shelf.centre_of(sidebar_entry(tab.id));
            shelf.click(at);
            let output = shelf.frame(Vec::new());
            let clashes: Vec<String> = drawn_text(&output)
                .into_iter()
                .filter(|line| line.contains("widget ID") || line.contains("First use of"))
                .collect();
            assert!(
                clashes.is_empty(),
                "{:?} drew two controls under one id: {clashes:?}",
                tab.id
            );
        }
    }

    /// **Every label the window can draw is covered by the fonts the window installs.**
    ///
    /// The other defect the gallery found. The cache label marked the active cap with a TICK, which
    /// the tray got from the operating system's own menu font — the window draws it in Space Grotesk
    /// with egui's stack behind, and neither carries it, so the one row a person is hunting for was
    /// marked with a tofu box. Nothing headless was looking, because a missing glyph still lays out
    /// and still reports the right text.
    ///
    /// Asked of egui's own font set rather than of a list of characters this test also writes: a
    /// hand-kept allowlist would go stale the first time a label gained a character nobody thought
    /// of, which is precisely what happened.
    #[test]
    fn every_label_the_window_can_draw_has_the_glyphs_to_draw_it() {
        let ctx = egui::Context::default();
        install_fonts(&ctx);
        // One frame, so the font set is built before it is asked anything.
        let _ = ctx.run(egui::RawInput::default(), |_| {});

        let mut checked = 0usize;
        for view in gallery_views() {
            for tab in &window_model::build(&view).tabs {
                let mut strings = vec![tab.label.clone()];
                if let window_model::PaneNote::Waiting(text)
                | window_model::PaneNote::Unreachable(text)
                | window_model::PaneNote::Empty(text) = &tab.note
                {
                    strings.push((*text).to_string());
                }
                for section in &tab.sections {
                    strings.extend(section.heading.clone());
                    strings.extend(section.rows.iter().filter_map(|row| match row {
                        MenuRow::Action { label, .. } => Some(label.clone()),
                        _ => None,
                    }));
                }
                for text in strings {
                    checked += 1;
                    // Both faces the pane uses: rows and notes are regular, headings semibold.
                    let covered = ctx.fonts(|fonts| {
                        fonts.has_glyphs(&crate::confirm::gui::render::regular(size::BASE), &text)
                            && fonts.has_glyphs(&semibold(size::SM), &text)
                    });
                    assert!(
                        covered,
                        "{:?} draws {text:?}, which this window has no glyph for — it will paint a \
                         tofu box",
                        tab.id
                    );
                }
            }
        }
        assert!(checked > 20, "only {checked} strings were checked");
    }

    /// The views the glyph sweep walks: every account state, with and without a node.
    ///
    /// Wider than `busy_view` alone because a label a person only sees in an unusual state is exactly
    /// the one nobody has looked at.
    fn gallery_views() -> Vec<crate::tray_menu::TrayView> {
        use crate::tray_menu::AccountState;
        let mut views = Vec::new();
        for account in [
            AccountState::Unsupported,
            AccountState::Absent,
            AccountState::Locked,
            AccountState::Unopenable,
            AccountState::NeedsPassword,
            AccountState::Unlocked { recoverable: true },
            AccountState::Unlocked { recoverable: false },
        ] {
            for cache in [None, busy_view().cache] {
                views.push(crate::tray_menu::TrayView {
                    account: Some(account.clone()),
                    cache,
                    ..busy_view()
                });
            }
        }
        views
    }

    // ---------------------------------------------------------------------------------------------
    // The scrimmed shell must not look clickable
    // ---------------------------------------------------------------------------------------------

    /// **The pointer stays the default arrow over the scrimmed body.**
    ///
    /// A pointing-hand cursor over a dimmed pane says *clickable* louder than any amount of dimming
    /// says *inert*. Every control in the body falls back to [`egui::Sense::hover`] while a prompt is
    /// up, which is what gets the cursor right; egui's own `disable()` would fight the token palette.
    ///
    /// Aimed at a REAL control — the Account sidebar entry — rather than at a bare coordinate. A
    /// coordinate that happened to land on no control at all would report the arrow cursor whatever
    /// the code did.
    #[test]
    fn the_cursor_stays_an_arrow_over_a_control_while_a_prompt_is_up() {
        let mut shelf = Shelf::open();
        shelf.settle();
        let over = shelf.centre_of(sidebar_entry(TabId::Account));

        let _answers = shelf.queue_live_prompt();
        shelf.frame(Vec::new());
        shelf.frame(vec![egui::Event::PointerMoved(over)]);
        let output = shelf.frame(Vec::new());

        assert_eq!(
            output.platform_output.cursor_icon,
            egui::CursorIcon::Default,
            "the scrimmed body offered a clickable cursor over a window that takes no input"
        );
        let sensed = shelf
            .ctx
            .read_response(sidebar_entry(TabId::Account))
            .expect("the sidebar entry is still drawn behind the scrim");
        assert!(
            !sensed.sense.senses_click(),
            "a sidebar entry still took clicks with a consent prompt over it"
        );
    }

    /// **The body IS interactive when no prompt is up.**
    ///
    /// The control for the test above: an implementation that senses nothing at all, ever, would
    /// satisfy it while being permanently inert.
    #[test]
    fn the_body_is_interactive_when_no_prompt_is_up() {
        let mut shelf = Shelf::open();
        shelf.settle();
        let over = shelf.centre_of(sidebar_entry(TabId::Account));
        shelf.frame(vec![egui::Event::PointerMoved(over)]);
        shelf.frame(Vec::new());

        let sensed = shelf.ctx.read_response(sidebar_entry(TabId::Account));
        assert!(
            sensed.is_some_and(|r| r.sense.senses_click()),
            "the sidebar takes no clicks even with nothing over it"
        );
    }

    /// **A prompt over the open shell opens no second window.**
    ///
    /// This is dig_ecosystem#2270 itself: clicking *Show my recovery phrase…* inside the app window
    /// used to put a second OS window in front of the one the person was already looking at.
    ///
    /// Asserted on `viewport_output`, which is the record of every viewport egui was asked to
    /// realise this frame — and on the prompt's own copy being drawn ANYWAY, in the same frame. Both
    /// halves are needed: "no second viewport" is also what a frame that failed to draw the prompt at
    /// all would report, and that would be a consent lockout rather than a fix.
    #[test]
    fn a_prompt_over_the_open_shell_opens_no_second_window() {
        let mut shelf = Shelf::open();
        shelf.settle();
        let _answers = shelf.queue_live_prompt();
        shelf.frame(Vec::new());
        let output = shelf.frame(Vec::new());

        assert!(
            a_prompt_was_drawn(&output),
            "the prompt was not drawn at all, so nothing here is evidence of anything"
        );
        let extra: Vec<_> = output
            .viewport_output
            .keys()
            .filter(|id| **id != egui::ViewportId::ROOT)
            .collect();
        assert!(
            extra.is_empty(),
            "the app window asked for {} more window(s) ({extra:?}) to show a prompt it is              already showing",
            extra.len()
        );
    }

    /// **The modal is a consent surface for as long as it is up — and the shell alone is not.**
    ///
    /// The tray suppresses its foreground claim while `consent_surface_is_up()` (dig-app#91). Without
    /// this, a tray click yanks the foreground off somebody part-way through typing a seed phrase.
    /// The #2253 audit found the shell-hosted path missing the guard entirely (N1).
    ///
    /// Read BETWEEN frames, never inside one, and that is the whole point: a guard scoped to a draw
    /// would read true from inside `frame` and false in every gap — and the gaps are when a tray
    /// click actually arrives. A test that sampled inside the draw would pass over that defect.
    ///
    /// Three samples, so the assertion is about the PROMPT and not about the process: before (the
    /// shell alone, the truthful control), during, and after it is answered.
    #[test]
    fn the_in_window_prompt_is_a_consent_surface_for_as_long_as_it_is_up() {
        use crate::confirm::surface::consent_surface_is_up;

        // `Shelf` already holds the exclusion — taking it again here would hang, not fail.
        let mut shelf = Shelf::open();
        shelf.settle();
        assert!(
            !consent_surface_is_up(),
            "the app window alone reported itself as a consent surface; the tray's foreground              claim would be suppressed for as long as somebody left the window open"
        );

        let answers = shelf.queue_live_prompt();
        shelf.frame(Vec::new());
        assert!(
            shelf.app.prompt.is_some(),
            "the prompt is not up, so the next assertion would prove nothing"
        );
        assert!(
            consent_surface_is_up(),
            "a consent prompt is on screen and the tray still believes it may take the foreground"
        );

        shelf.frame(escape());
        shelf.frame(Vec::new());
        assert!(shelf.app.prompt.is_none(), "Escape dismissed the prompt");
        let _ = answers.try_recv();
        assert!(
            !consent_surface_is_up(),
            "the surface stayed raised after the prompt was answered; the tray's claim would be              suppressed for the rest of the process"
        );
    }

    /// **A click on the shell beneath the modal does nothing at all.**
    ///
    /// The occlusion question, re-answered for a modal that shares its host's window. The prompt used
    /// to be `always_on_top` because a non-topmost one was buried by a single click on the shell
    /// while it went on repainting invisibly with its deadline running down. A modal inside the shell
    /// cannot be buried — but it can be clicked THROUGH, which fails the same way.
    ///
    /// The fixture is chosen to make a through-click OBSERVABLE rather than merely harmless: the
    /// pointer is aimed at a sidebar tab that is not the selected one, so the defect has a visible
    /// consequence (the pane changes under a live consent prompt) instead of being absorbed by a
    /// no-op. The first two assertions are the control — without them a target that was never
    /// clickable in the first place would satisfy the third.
    #[test]
    fn a_click_on_the_shell_beneath_the_modal_changes_nothing() {
        let mut shelf = Shelf::open();
        shelf.settle();
        let at = shelf.centre_of(sidebar_entry(TabId::Account));
        assert_ne!(
            shelf.app.selected,
            TabId::Account,
            "the target tab is already selected, so a through-click would be invisible"
        );

        let _answers = shelf.queue_live_prompt();
        shelf.frame(Vec::new());
        assert!(shelf.app.prompt.is_some(), "the prompt is up");

        shelf.click(at);

        assert_eq!(
            shelf.app.selected, FIRST_TAB,
            "a click landed on the sidebar through a live consent prompt and changed the pane"
        );
        assert!(
            shelf.dispatched().is_empty(),
            "a click through a live consent prompt reached the worker: {:?}",
            shelf.dispatched()
        );
        assert!(
            shelf.app.prompt.is_some(),
            "the click dismissed the prompt, which no click on the shell may do"
        );
    }

    /// **The scrim really is an input blocker, over the whole window.**
    ///
    /// The behavioural test above passes today without this widget, because every control the shell
    /// currently draws is ALREADY inert while a prompt is up. That is exactly why the backstop needs
    /// its own assertion: it is the thing that keeps a control added tomorrow from being clickable
    /// through a live consent prompt, and no test of today's controls can see it.
    ///
    /// Its extent is asserted too. A blocker that covered only the pane would leave the chrome — and
    /// therefore Close — live under the scrim that is drawn over it.
    #[test]
    fn the_scrim_blocks_input_across_the_whole_window() {
        let mut shelf = Shelf::open();
        shelf.settle();
        let _answers = shelf.queue_live_prompt();
        shelf.frame(Vec::new());
        shelf.frame(Vec::new());

        let blocker = shelf
            .ctx
            .read_response(scrim_blocker())
            .expect("nothing is swallowing input under the modal");
        assert!(
            blocker.sense.senses_click() && blocker.sense.senses_drag(),
            "the scrim is painted but takes no input, so it stops nothing"
        );
        assert!(
            blocker
                .rect
                .contains_rect(Rect::from_min_size(egui::Pos2::ZERO, shell_size())),
            "the blocker at {:?} leaves part of the window live under the scrim",
            blocker.rect
        );
    }

    /// **The modal stays inside the window, at every size the window can be.**
    ///
    /// Asserted against the placement function rather than a control read back off the context:
    /// `paint::button` generates its own id from the layout, so a test that guessed that id would
    /// find nothing and skip its assertions — passing while proving nothing. Both bounds are
    /// checked, because a modal pinned to the top-left would be "inside the window" too.
    ///
    /// [`SHELL_MIN`] is in the list on purpose: it is NARROWER than the prompt's natural
    /// [`super::WIDTH`], which is the one size where an unclamped rectangle escapes.
    #[test]
    fn the_modal_is_centred_and_never_leaves_the_window() {
        for size in [
            Vec2::new(SHELL_MIN, SHELL_MIN),
            shell_size(),
            Vec2::new(1400.0, 1000.0),
        ] {
            let window = Rect::from_min_size(egui::Pos2::new(0.0, 0.0), size);
            for height in [
                crate::confirm::gui::window::MIN_HEIGHT,
                crate::confirm::gui::window::HEIGHT,
                crate::confirm::gui::window::MAX_HEIGHT,
            ] {
                let at = modal_rect(window, height);
                assert!(
                    window.contains_rect(at),
                    "a {height}-tall modal at {at:?} left a {size:?} window"
                );
                assert_eq!(
                    at.center(),
                    window.center(),
                    "a {height}-tall modal in a {size:?} window is not centred"
                );
            }
        }
    }

    /// **The modal is sized to its content, and stops at the window.**
    ///
    /// Three points, because a clamp is only proved by the values on either side of it: a short
    /// notice must SHRINK (a fixed size would fail this), a tall one must GROW (a shrink-only rule
    /// would fail this — it is dig_ecosystem#2038, where 24 recovery words showed 14), and an
    /// enormous one must be held to the window rather than to the prompt's own monitor-scale ceiling.
    #[test]
    fn the_modal_grows_and_shrinks_to_its_content_within_the_window() {
        use crate::confirm::gui::window::{HEIGHT, MAX_HEIGHT, MIN_HEIGHT};

        let window = Rect::from_min_size(egui::Pos2::ZERO, shell_size());
        let at = modal_rect(window, HEIGHT);
        // The constant the arithmetic has to invert, so the expectations below are derived from the
        // contract rather than transcribed from a run.
        let chrome = space::S6 + crate::confirm::gui::window::ACTION_ROW;

        let short = modal_height(window, at, at.top() + 120.0);
        assert_eq!(
            short,
            (120.0 + chrome).max(MIN_HEIGHT),
            "a two-line notice is not shrinking to its content"
        );

        let tall = modal_height(window, at, at.top() + 715.0);
        assert!(
            tall > HEIGHT,
            "a 715 px screen — the recovery phrase — got {tall}, no more than the opening height;              the words below the fold are the #2038 defect"
        );

        let enormous = modal_height(window, at, at.top() + 5_000.0);
        assert!(
            enormous <= window.height() * MODAL_SHARE && enormous < MAX_HEIGHT,
            "a {enormous}-tall modal in a {}-tall window puts its buttons past the bottom edge",
            window.height()
        );
    }

    /// **A window too short for even the minimum still gets a modal that fits.**
    ///
    /// The lower clamp and the upper one can contradict each other: `clamp(MIN, ceiling)` panics
    /// outright when a window is shorter than [`super::MIN_HEIGHT`], which a person can produce by
    /// dragging the shell down — [`SHELL_MIN`] is 480 and the prompt minimum is 320, so the margin is
    /// small and a monitor-scaled `MODAL_SHARE` eats it.
    #[test]
    fn a_modal_in_a_window_shorter_than_the_minimum_still_fits() {
        let window = Rect::from_min_size(egui::Pos2::ZERO, Vec2::new(SHELL_MIN, 300.0));
        let at = modal_rect(window, crate::confirm::gui::window::HEIGHT);
        assert!(window.contains_rect(at), "the modal at {at:?} left the window");

        let height = modal_height(window, at, at.top() + 1_000.0);
        assert!(
            height <= window.height(),
            "a {height}-tall modal in a 300-tall window cannot be answered"
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
