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
use std::sync::{mpsc, Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

use egui::{Key, Rect, Vec2};
use zeroize::Zeroizing;

mod panes;
mod shell;

use super::paint;
use super::render::{
    bar_top, radius, regular, rgba, semibold, size, space, Answer, Block, Chrome, Screen,
    BAR_HEIGHT, BAR_WIDTH,
};
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
/// The height of the window's chrome bar — the brand mark, the title, the theme toggle, and the
/// strip the window is DRAGGED by ([`PromptApp::drag_region`]).
const CHROME_HEIGHT: f32 = 44.0;
/// The width of the theme toggle sitting at the right end of the chrome.
const TOGGLE_WIDTH: f32 = 110.0;
/// What the window's drag strip senses.
///
/// Two halves, each load-bearing, and NEITHER is what the obvious `Sense::click_and_drag()` or
/// `Sense::drag()` would give:
///
/// * **`CLICK` is kept** even though the handle's click is never read. It is what makes `egui`
///   withhold the drag until the gesture can no longer be a click, which is the whole reason a
///   finished move cannot press a consent button — see
///   [`drag_by_the_header`](PromptApp::drag_by_the_header). `Sense::drag()` alone reports the drag on
///   the press frame and silently removes that guarantee.
/// * **`FOCUSABLE` is dropped**, which `Sense::click_and_drag()` would include (egui 0.31.1
///   `sense.rs:77`). The strip is registered before every other widget, so a focusable one would be
///   the FIRST tab stop on a consent dialog — an invisible, unlabelled stop with no focus ring, on the
///   one surface whose keyboard navigation has to be unambiguous. It is decoration for the pointer,
///   not a control.
const DRAG_HANDLE_SENSE: egui::Sense = egui::Sense::CLICK.union(egui::Sense::DRAG);

/// The gap left between the end of the drag strip and the theme toggle.
///
/// A drag strip that runs right up to a control makes the control's own edge ambiguous: a press a
/// pixel out lands on the strip and the window moves instead of the theme changing. This is the
/// same reasoning as the action row's exclusion, at the scale the two things are actually apart.
const DRAG_DEAD_ZONE: f32 = space::S3;
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
    /// The instant past which this job's caller has certainly stopped waiting — the same
    /// `deadline + ANSWER_GRACE` [`ask`] gives up at, resolved to an absolute time when the job is
    /// QUEUED rather than when it is drawn.
    ///
    /// # Why a job can go stale before it is ever drawn
    ///
    /// Jobs are served one at a time, so a window that wedges parks every prompt behind it. Their
    /// callers time out and are refused, but the jobs stay in the queue — and once the thread is
    /// freed the loop would open each of them in turn: a real sign window, a real unlock, a real
    /// destroy confirm, each showing a genuine origin and payload for an operation that was refused
    /// minutes ago, and each holding the single renderer for another full deadline
    /// (dig_ecosystem#2074).
    ///
    /// That is fail-safe on consent — the reply channel is gone, so no answer can reach anybody —
    /// but a consent window nobody asked for is its own defect, and a stream of them teaches exactly
    /// the click-through reflex [`ConfirmContent::claim`](crate::confirm::ConfirmContent) pre-selects
    /// a refusal to prevent. So [`serve_with`] refuses a stale job WITHOUT DRAWING IT.
    over_by: Instant,
    /// The caller's reply channel. A bounded channel of one: the caller is already blocked on it.
    reply: SyncSender<Outcome>,
}

/// One piece of work for the prompt thread.
///
/// The queue carries two shapes because this thread hosts two kinds of window and there is only one
/// event loop in the process to host them on (see [`start`]). They are an enum rather than a flag on
/// [`Job`] because almost nothing [`serve_with`] does to a prompt is right for the shell:
///
/// * a [`Job`] is a CONSENT surface — a blocked caller, a deadline, a fail-closed answer, and a
///   [`Raised`](crate::confirm::surface::Raised) count the tray reads;
/// * a [`Shell`] is an ordinary application window the person opened, with none of those.
///
/// Keeping them apart is what lets the prompt arm of the loop stay exactly as it was.
enum Work {
    /// A consent prompt, drawn for a caller who is blocked waiting on the answer.
    Prompt(Job),
    /// The app shell, which pumps this same queue for prompts while it is up — see [`shell`].
    Shell(AppWindow),
}

/// A request to open the app shell, and everything the shell needs from the app around it.
///
/// The two callbacks are how the window stays a RENDERER. It reads the live view through one and
/// hands verbs back through the other, so it never learns what an action does — which is what keeps
/// [`crate::tray_menu::TrayAction`] a single enum with a single `dispatch`, and keeps the window and
/// the tray incapable of disagreeing about what a verb means.
pub struct AppWindow {
    /// Where the shell's theme preference persists.
    ///
    /// The same store every prompt uses, so the window and a prompt raised over it can never be in
    /// different themes.
    pub theme: ThemeChoice,
    /// The live tray snapshot, read once per frame.
    ///
    /// A closure rather than a value because the window outlives any one snapshot: the node poll
    /// rewrites the view every five seconds, an unlock changes the account state, and a window
    /// showing the state at the moment it opened would quietly become a lie.
    ///
    /// **It must not block.** It runs inside the frame on the one prompt thread.
    pub view: Arc<dyn Fn() -> crate::tray_menu::TrayView + Send + Sync>,
    /// Hand a verb to whatever runs verbs — for dig-app, the single action worker.
    ///
    /// **It must not block, and must never call the blocking `ask` itself.** Doing so would block the
    /// prompt thread inside its own frame, waiting on the queue that frame owns: a guaranteed
    /// deadlock. A window row dispatches exactly as a tray click does, on a worker, and this
    /// callback is the seam that makes that the only expressible option.
    pub act: Arc<dyn Fn(crate::tray_menu::TrayAction) + Send + Sync>,
}

/// The long-lived thread every prompt window is drawn on.
struct PromptThread {
    /// Guarded because `Sender` is not `Sync` and the confirmer is shared across connection tasks.
    tx: Mutex<mpsc::Sender<Work>>,
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
///
/// # Why the thread is never replaced
///
/// It would be natural to notice a dead prompt thread and spawn a fresh one. That cannot work.
/// `winit` guards event-loop creation with a PROCESS-GLOBAL one-shot — `EVENT_LOOP_CREATED`, an
/// `AtomicBool` swapped to `true` on the first `build()` and reset nowhere off the web
/// (winit 0.30.13 `src/event_loop.rs:69` and `:118`) — and `eframe` caches the loop it built in
/// THREAD-LOCAL storage (`eframe` 0.31.1 `src/native/run.rs:51`). A replacement thread therefore
/// starts with an empty cache, asks winit for a loop, and is told `RecreationAttempt` forever. A
/// respawn would look like a recovery and would in fact be a silent, permanent `Unavailable`.
///
/// So this thread is made UNKILLABLE instead ([`serve`] catches every panic), and the one thing a
/// caller can do about a thread that died anyway is say so loudly ([`ask`]).
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

    // Leaked rather than reference-counted: the prompt thread and the watchdog both hold it for the
    // life of the process, so there is no last owner for an `Arc` to free.
    let drawing: &'static Mutex<Option<Vigil>> = Box::leak(Box::new(Mutex::new(None)));

    let (tx, rx) = mpsc::channel::<Work>();
    std::thread::Builder::new()
        .name("dig-prompt-window".to_owned())
        // A prompt draws a full GL surface and lays out a page of text; the default 2 MiB is enough
        // on Linux but the driver stack is deeper on Windows, so the thread is given room explicitly
        // rather than depending on the platform default.
        .stack_size(4 * 1024 * 1024)
        .spawn(move || serve(&rx, drawing))
        .ok()?;

    // The watchdog is a second thread on purpose: it has to be able to act while the prompt thread
    // is inside a window that has stopped calling back (see `Vigil`).
    let _ = std::thread::Builder::new()
        .name("dig-prompt-watchdog".to_owned())
        .spawn(move || watch(drawing, WATCHDOG_TICK));

    Some(PromptThread { tx: Mutex::new(tx) })
}

/// The window on screen right now, and the moment it has outstayed its welcome.
///
/// # Why the window's own deadline is not enough
///
/// [`PromptApp::frame`] expires the window by comparing `opened.elapsed()` against its deadline —
/// which can only happen on a frame that actually RUNS. Every prompt in the process is drawn on one
/// thread, one at a time, so a window whose frame loop goes quiet does not merely fail to expire
/// itself: it holds the only prompt thread there is, and no later consent window — an unlock, a
/// destroy confirm, a sign — can ever be drawn again (dig_ecosystem#2074). An in-frame deadline
/// cannot bound a stalled frame loop, because it IS the frame loop.
///
/// So the deadline is enforced from OUTSIDE as well, with two requests the window already makes of
/// itself — neither can invent an answer, and the outcome is still whatever [`PromptApp::expire`]
/// records, never an approval.
///
/// # Which of the two actually saves the thread, and why the ORDER is load-bearing
///
/// `request_repaint` first, `ViewportCommand::Close` second — and NOT because a repaint is tidier.
/// In the worst failure mode the two are not interchangeable and only the first one works:
///
/// * When the frame loop is merely idle, either would do. `Close` comes back as a
///   `ViewportEvent::Close` in the next frame's input and eframe exits.
/// * When winit has LATCHED a panic (`EventLoopRunner::catch_unwind`, winit 0.30.13
///   `windows/event_loop/runner.rs:170`) the application handler is never invoked again, so
///   `Close` is queued into an [`egui::Context`] nobody will ever read. What recovers the thread is
///   a side effect of the wake: `request_repaint` posts through the `EventLoopProxy`, THAT message
///   is still dispatched, and the `take_panic_error()` / `resume_unwind` at winit
///   `event_loop.rs:423` then fires — so the stored panic finally escapes `run_native` into
///   [`serve_with`]'s guard.
///
/// So `request_repaint` is the mechanism and `send_viewport_cmd` is the fallback, not the other way
/// round. A refactor that drops the repaint because "Close implies a repaint" would silently remove
/// the only thing that works in the latched case.
struct Vigil {
    /// The live window's context, used only to wake it and ask it to close.
    ///
    /// `None` until the window is CONSTRUCTED. A `run_native` that hangs before it reaches the
    /// creator — GL context init, adapter enumeration, a driver that never returns — has no context
    /// to nudge, and the watchdog cannot free that thread. Registering the vigil before the call
    /// anyway is what lets it at least SAY SO, instead of the renderer disappearing with no record.
    wake: Option<egui::Context>,
    /// When the window has exceeded its own deadline by [`ANSWER_GRACE`] and must be forced shut.
    over_by: Instant,
    /// When to complain about this window again, once it has been forced and did not go.
    ///
    /// A latch was the first shape and it was wrong in the case that matters: a window that ignores
    /// the nudge is a PERMANENT consent lockout, and latching reported it exactly once and then went
    /// quiet forever — reintroducing, for the worst case specifically, the silence this module
    /// exists to remove. Backing off keeps the log honest about the difference between "forced, and
    /// it worked" and "forced, and the renderer is still gone".
    complain_again_at: Option<Instant>,
}

/// How often the watchdog looks at the window on screen.
///
/// Coarse on purpose. It is enforcing a two-to-five MINUTE deadline that the window has already
/// failed to enforce itself, so a second of slack costs nothing and a tighter tick would burn a
/// wakeup a frame for the entire life of the process.
const WATCHDOG_TICK: Duration = Duration::from_secs(1);

/// How long to wait before saying again that a forced window is STILL there.
///
/// Long enough not to fill the log, short enough that a permanent lockout is unmistakable in it.
const COMPLAIN_AGAIN_AFTER: Duration = Duration::from_secs(30);

/// Force any window that has outstayed [`Vigil::over_by`] to wake up and close.
///
/// Runs until the process ends. Takes the tick as an argument so a test can drive it in
/// milliseconds rather than waiting out a real prompt deadline.
fn watch(drawing: &'static Mutex<Option<Vigil>>, tick: Duration) {
    loop {
        std::thread::sleep(tick);
        // A poisoned slot means an earlier prompt panicked. `serve_with` catches that and carries
        // on, so the watchdog must too — a poisoning is not a reason to stop enforcing deadlines
        // for the rest of the session.
        let mut slot = poisonless(drawing);
        let Some(vigil) = slot.as_mut() else { continue };
        let now = Instant::now();
        if now < vigil.over_by {
            continue;
        }
        match vigil.complain_again_at {
            None => {
                tracing::error!(
                    "a DIG prompt window outlived its own deadline without answering; forcing it \
                     closed so later prompts can be shown"
                );
            }
            Some(due) if now >= due => {
                // Still here a full backoff after being forced. This is the permanent lockout, and
                // it must keep saying so rather than going quiet after one line.
                tracing::error!(
                    "a DIG prompt window is STILL open after being forced closed; no further DIG \
                     prompt can be shown until DIG is restarted"
                );
            }
            Some(_) => continue,
        }
        vigil.complain_again_at = Some(now + COMPLAIN_AGAIN_AFTER);
        let Some(wake) = vigil.wake.as_ref() else {
            // No context means `run_native` never reached the creator (GL init, adapter
            // enumeration, a driver hang). There is nothing to nudge; the log line above is the
            // whole of what the watchdog can do about it.
            continue;
        };
        // Wake the loop FIRST — see `Vigil`, this ordering is the mechanism, not a nicety.
        wake.request_repaint();
        wake.send_viewport_cmd(egui::ViewportCommand::Close);
    }
}

/// Draw prompts, one at a time, until the sender is dropped.
///
/// # Why one job can never take the thread with it
///
/// This loop is the whole consent surface. If it exits — or if it never comes back from one window
/// — the process keeps a [`PromptThread`] whose receiver is gone, and every later prompt returns
/// `Unavailable` for the life of the process: the user can no longer approve, deny, unlock or
/// destroy anything, with nothing written anywhere to say why (dig_ecosystem#2074). A prompt thread
/// cannot be replaced either ([`start`]), so surviving is the only available answer.
///
/// Hence the panic guard. It is the same shape `session_lock` uses around its own callback: catch
/// the unwind, put the platform back in a usable state, answer the caller the fail-closed way, say
/// so in the log, and take the next job.
fn serve(rx: &Receiver<Work>, drawing: &'static Mutex<Option<Vigil>>) {
    serve_with(rx, drawing, |work, queue| match work {
        Work::Prompt(job) => draw_watched(job, Some(drawing)),
        Work::Shell(shell) => shell::draw(shell, queue),
    });
}

/// [`serve`]'s loop over an arbitrary way of drawing a window.
///
/// Split out for ONE reason: the behaviour worth pinning here is what the loop does when a window
/// misbehaves — panics, or refuses to open — and a test cannot make a real GL window do either on
/// demand. With the drawing injected, the survival rules are exercised on a CI host with no display
/// and no window, against the same loop production runs.
fn serve_with(
    rx: &Receiver<Work>,
    drawing: &Mutex<Option<Vigil>>,
    draw: impl Fn(Work, &Receiver<Work>) -> Option<Outcome>,
) {
    while let Ok(work) = rx.recv() {
        // The shell is served on its own path ([`serve_shell`]) rather than through the arm below.
        // It raises no consent surface, has no deadline, and has nobody blocked on it, so not one of
        // the rules that follow applies to it — and keeping it out of them entirely is what leaves
        // the consent arm exactly as it was.
        let job = match work {
            Work::Shell(shell) => {
                serve_shell(shell, rx, &draw);
                continue;
            }
            Work::Prompt(job) => job,
        };

        let reply = job.reply.clone();
        let wants_text = job.wants_text;
        let title = job.screen.title.clone();

        // A job whose caller stopped waiting is REFUSED WITHOUT BEING DRAWN. Drawing it would open a
        // real consent window — a real origin, a real payload — for an operation nobody is waiting
        // on, and would hold the single renderer for another full deadline while doing it. See
        // `Job::over_by`.
        if Instant::now() >= job.over_by {
            tracing::warn!(
                prompt = %title,
                "a DIG prompt reached the renderer after its caller had given up; refused without \
                 opening a window"
            );
            let _ = reply.send(unavailable(wants_text));
            continue;
        }

        tracing::debug!(prompt = %title, wants_text, "drawing a DIG prompt");

        // A consent surface is on screen for exactly the span of the draw, and the tray's foreground
        // claim is disabled for exactly that span (dig-app#91). The guard is INSIDE `catch_unwind`
        // and around nothing else: a job refused above without being drawn raised no window, so
        // counting it would disable the claim over an empty screen.
        let drawn = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _on_screen = crate::confirm::surface::Raised::now();
            draw(Work::Prompt(job), rx)
        }));

        // Whatever happened in there, this window is over: stop the watchdog nudging a context
        // that no longer has a window, before anything else can go wrong.
        clear_vigil(drawing);

        let outcome = match drawn {
            Ok(Some(outcome)) => outcome,
            Ok(None) => {
                tracing::warn!(prompt = %title, "a DIG prompt window could not be opened");
                unavailable(wants_text)
            }
            Err(_) => {
                // A panic inside `run_native` leaves the window undestroyed on Windows, because the
                // flush at the end of `draw` was skipped on the way out.
                flush_deferred_window_destruction();
                tracing::error!(
                    prompt = %title,
                    "a DIG prompt window panicked; it was refused and the prompt thread kept alive"
                );
                unavailable(wants_text)
            }
        };
        // A caller that has gone away (its task was cancelled) is not an error worth killing the
        // thread over — the next prompt still needs it.
        let _ = reply.send(outcome);
    }
    // Only reachable once every `PromptThread` sender has been dropped, which outside a test means
    // the process is going away.
    tracing::debug!("the DIG prompt thread has no senders left and is stopping");
}

/// Draw the app shell, and survive it.
///
/// # What deliberately does NOT apply here
///
/// Four of [`serve_with`]'s rules are absent, and each absence is the point rather than an omission:
///
/// * **No [`Raised`](crate::confirm::surface::Raised).** The shell is not a consent surface. Counting
///   it would disable the tray's foreground claim (dig-app#91) for the whole life of a window a
///   person may leave open all day — and a disabled claim looks exactly like a working one.
/// * **No [`Vigil`].** A window somebody opened on purpose must never be forced shut by a watchdog.
///   The shell has no deadline and must never acquire one.
/// * **No staleness check.** Nobody is blocked on a shell, so there is no caller who can have given
///   up while it sat in the queue.
/// * **No reply.** There is no channel to answer, so there is nothing here to fail closed. The
///   prompts the shell hosts each keep their own reply, and the shell fails those closed itself
///   (see [`shell::ActivePrompt::settle`]).
///
/// # What does apply, and why
///
/// The panic guard, for exactly the reason the prompt arm has one. The prompt thread cannot be
/// replaced ([`start`]), so a shell that took it down on the way out would be a silent, permanent
/// consent lockout for the rest of the session. A panic costs the shell and only the shell; the loop
/// goes back to `recv` and takes the next job.
fn serve_shell(
    shell: AppWindow,
    rx: &Receiver<Work>,
    draw: &impl Fn(Work, &Receiver<Work>) -> Option<Outcome>,
) {
    let drawn = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        draw(Work::Shell(shell), rx)
    }));
    if drawn.is_err() {
        // A panic inside `run_native` skips the flush at the end of the draw, leaving the window
        // undestroyed on Windows — the same hole the prompt arm plugs here.
        flush_deferred_window_destruction();
        // An observed failure, not a suspicion: the tray goes back to its full form so the verbs the
        // trim moved into this window stay reachable (`crate::window_host`).
        crate::window_host::note_open_failure();
        tracing::error!(
            "the DIG app window panicked; it was closed and the prompt thread kept alive"
        );
    }
}

/// The fail-closed answer for a window that produced none. Never an approval, never empty text.
fn unavailable(wants_text: bool) -> Outcome {
    match wants_text {
        true => Outcome::Input(InputOutcome::Unavailable),
        false => Outcome::Confirm(WindowIntent::Unavailable),
    }
}

/// Put the window now being drawn under the watchdog's eye.
fn set_vigil(drawing: &Mutex<Option<Vigil>>, wake: Option<egui::Context>, over_by: Instant) {
    let mut slot = poisonless(drawing);
    // Upgrading the same window from "no context yet" to "here is the context" must not restart its
    // backoff, or a wedged window would re-announce itself as a fresh problem.
    let complain_again_at = slot
        .as_ref()
        .filter(|current| current.over_by == over_by)
        .and_then(|current| current.complain_again_at);
    *slot = Some(Vigil {
        wake,
        over_by,
        complain_again_at,
    });
}

/// Take the window off the watchdog's list, because it is gone.
fn clear_vigil(drawing: &Mutex<Option<Vigil>>) {
    *poisonless(drawing) = None;
}

/// Lock `slot`, recovering rather than propagating a poisoning.
///
/// A poisoned slot means an earlier prompt panicked. Refusing to draw every later prompt over that
/// — which is what propagating would do — is exactly the lockout this module exists to prevent, so
/// this cannot fail: the guard is taken out of the `PoisonError` and handed back.
fn poisonless<T>(slot: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    slot.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// How every prompt window is created.
///
/// One function so the screenshot harness photographs the SAME window a user is shown — a gallery
/// built from a second, slightly-different set of options is a gallery of something else.
fn native_options(title: &str, chrome: Chrome) -> eframe::NativeOptions {
    // A bar is a fixed-size frameless launcher; a dialog is created at [`HEIGHT`] and then sized to
    // its content ([`PromptApp::fit_to_content`]). Both are frameless and always-on-top — the bar
    // regains the width and placement the deleted Win32 renderer gave it (dig_ecosystem#2054).
    let (width, height, min_height) = match chrome {
        Chrome::Bar => (BAR_WIDTH, BAR_HEIGHT, BAR_HEIGHT),
        Chrome::Dialog => (WIDTH, HEIGHT, MIN_HEIGHT),
    };
    eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_title(title)
            .with_inner_size([width, height])
            .with_min_inner_size([width, min_height])
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
///
/// `watched` is where the window registers itself for the out-of-band deadline (see [`Vigil`]); a
/// caller that passes `None` — the screenshot harness, a test about one window — simply runs
/// without a watchdog.
fn draw_watched(job: Job, watched: Option<&Mutex<Option<Vigil>>>) -> Option<Outcome> {
    let wants_text = job.wants_text;
    let theme_store = job.theme.clone();
    let title = job.screen.title.clone();
    // Read off the job rather than recomputed, so the watchdog, the caller's own wait and the
    // staleness check in `serve_with` all enforce the SAME instant.
    let over_by = job.over_by;

    let options = native_options(&title, job.screen.chrome);

    // The app writes its answer here before the loop exits, so it survives `run_native` returning.
    let slot = std::sync::Arc::new(Mutex::new(None::<Outcome>));
    let sink = slot.clone();

    // Registered BEFORE the call, with no context yet. `run_native` can hang before it ever reaches
    // the creator below — GL context init, adapter enumeration, a driver that does not return — and
    // a vigil that only started existing inside the creator would never see that at all.
    if let Some(watched) = watched {
        set_vigil(watched, None, over_by);
    }

    let run = eframe::run_native(
        &title,
        options,
        Box::new(move |cc| {
            install_fonts(&cc.egui_ctx);
            if let Some(watched) = watched {
                set_vigil(watched, Some(cc.egui_ctx.clone()), over_by);
            }
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
///
/// # The precondition, which is the part a later change can silently break
///
/// The defect is **a loop that has stopped pumping**, not a window that will not close. Whenever
/// this thread's event loop is STILL RUNNING, it dispatches the private destroy message itself
/// within a frame or two and no drain is needed — measured on Windows 11 at 25–45 ms, 15 of 15
/// cycles, for a prompt viewport dismissed while [`shell::ShellApp`]'s loop kept running. That is
/// why the shell needs no call here for the prompts it hosts, and it is the whole difference between
/// this working and dig_ecosystem#2038.
///
/// So: **a refactor that stops the parent loop while a child viewport is still up re-opens #2038**,
/// and the call sites below — after `run_native` has returned, and after a panic skipped that return
/// — are the two places where the pump has genuinely stopped. Do not remove them, and do not assume
/// a new call site is unnecessary without checking whether a loop is still running on this thread.
#[cfg(target_os = "windows")]
fn flush_deferred_window_destruction() {
    // Drained, not budgeted: the destroy message is somewhere in the queue and a bound that ran out
    // first would leave the window on screen forever (dig_ecosystem#2074).
    crate::confirm::windows::drain_pending();
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

/// Where a prompt is being drawn, which decides what it may say to the windowing system.
///
/// Three of [`PromptApp`]'s behaviours address a *viewport* — focus it, close it, watch it lose
/// focus — and every one of them is either meaningless or actively wrong when the prompt is painted
/// inside the app window, because the viewport it would address is then the SHELL's. A prompt that
/// sent `ViewportCommand::Close` from inside the shell would close the shell.
///
/// An explicit two-state enum rather than a `bool` or a `cfg!`: the hosting is a runtime fact — the
/// same prompt content reaches both hosts on the same platform, depending only on whether the person
/// happened to have the app window open — and the call sites read as the question they are asking.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum PromptHost {
    /// Its own top-level OS window, drawn by its own `eframe` run. The audited consent surface.
    Standalone,
    /// A modal layer inside the app shell, sharing the shell's viewport and its event loop.
    InWindow,
}

/// One prompt window.
struct PromptApp {
    /// Whether this prompt owns a viewport or is a layer inside the shell's.
    host: PromptHost,
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
    /// Whether this window has EVER held focus. Latched so a launcher bar cannot dismiss itself on
    /// blur before it has ever been focused — the frame that reports `focused == Some(false)` on the
    /// way UP would otherwise close it the instant it opened (dig_ecosystem#2054).
    has_been_focused: bool,
    /// Whether the launcher bar has been placed high on its monitor yet. Placement waits for the
    /// first frame that reports a real `monitor_size`, then latches so the bar is positioned once and
    /// does not fight the compositor every frame.
    placed: bool,
    /// Whether the window has already been told to take the keyboard.
    ///
    /// Asked for ONCE, on the first frame, and never again — see [`PromptApp::claim_the_keyboard`].
    /// Repeating it every frame would fight the user for the foreground for the whole life of the
    /// window, which is a different and worse defect than the one it fixes.
    keyboard_claimed: bool,
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
    /// A prompt that owns its own window.
    fn new(
        job: Job,
        theme_store: ThemeChoice,
        sink: std::sync::Arc<Mutex<Option<Outcome>>>,
    ) -> Self {
        Self::hosted(job, theme_store, sink, PromptHost::Standalone)
    }

    /// A prompt drawn as a modal layer inside the app shell.
    pub(super) fn in_window(
        job: Job,
        theme_store: ThemeChoice,
        sink: std::sync::Arc<Mutex<Option<Outcome>>>,
    ) -> Self {
        Self::hosted(job, theme_store, sink, PromptHost::InWindow)
    }

    fn hosted(
        job: Job,
        theme_store: ThemeChoice,
        sink: std::sync::Arc<Mutex<Option<Outcome>>>,
        host: PromptHost,
    ) -> Self {
        let focus = job
            .screen
            .buttons
            .iter()
            .position(|b| b.focused)
            .unwrap_or(0);
        Self {
            host,
            theme: theme_store.read(),
            screen: job.screen,
            wants_text: job.wants_text,
            theme_store,
            focus,
            typed: Zeroizing::new(String::new()),
            revealed: false,
            keyboard_claimed: false,
            field_focused: false,
            has_been_focused: false,
            placed: false,
            answered: false,
            opened: Instant::now(),
            deadline: job.deadline,
            sink,
        }
    }

    /// Ask, once, for the keyboard this window's own body text promises the user.
    ///
    /// # The defect
    ///
    /// `with_active(true)` asks the windowing system to activate the window, and on Windows that is
    /// a REQUEST, not an instruction: the foreground lock refuses it for a process that is not
    /// already foreground and has not just received input. A tray agent raising a prompt is exactly
    /// that process, and the first prompt after a cold start was measured opening with the
    /// foreground window belonging to somebody else (dig_ecosystem#2079).
    ///
    /// A prompt in that state has NO way out. It is undecorated, so there is no close button; it is
    /// always-on-top, so it cannot be put behind anything; Escape does nothing because the keystroke
    /// goes to whichever window does hold the keyboard — while the body of the input window reads
    /// *"press Enter. Esc closes this."* Clicking it first activates it and everything then works,
    /// but nothing on screen says so. That is `professional-ui`'s never-trap-the-user rule broken on
    /// the one surface where being trapped means being unable to refuse.
    ///
    /// # Why here rather than in the window options
    ///
    /// [`egui::ViewportCommand::Focus`] is applied by `egui-winit` on a window that EXISTS, which is
    /// a strictly better moment to ask than window creation: by the first frame the process has a
    /// visible top-level window, which is one of the conditions the foreground lock tests.
    ///
    /// It is still a request. Windows can refuse it — a full-screen exclusive app, an active
    /// foreground lock timeout — and this makes no attempt to defeat the lock with the
    /// `AttachThreadInput` trick, which steals focus from whatever the user is typing into and is
    /// the reason that lock exists. What this guarantees is that DIG ASKS; it does not guarantee
    /// Windows agrees. The window remains answerable by mouse either way, and its own deadline still
    /// refuses on its behalf if it is never answered at all.
    ///
    /// # Why an in-window prompt does not ask
    ///
    /// There is nothing to ask for. The shell already holds the foreground — the person is looking
    /// at it — and the only viewport this could address is the shell's own, so the request would at
    /// best be a no-op and at worst re-raise a window the person had just moved behind something.
    fn claim_the_keyboard(&mut self, ctx: &egui::Context) {
        if self.host == PromptHost::InWindow || self.keyboard_claimed {
            return;
        }
        self.keyboard_claimed = true;
        ctx.send_viewport_cmd(egui::ViewportCommand::Focus);
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
    ///
    /// # Why only a standalone prompt asks to close
    ///
    /// In-window there is no window of this prompt's own to close; the only viewport this could
    /// address is the SHELL's, so sending the command would shut the app window out from under the
    /// person. Dismissal in that host is the shell dropping its `ActivePrompt` on the frame it sees
    /// [`PromptApp::answered`] — the same mechanism, one level up.
    ///
    /// **The latch itself is host-independent** and runs identically on both paths: the whole point
    /// of dig_ecosystem#2038 is that no later frame, whatever it is, may change what the human said.
    fn record(&mut self, ctx: &egui::Context, outcome: Outcome) {
        if !self.answered {
            self.answered = true;
            if let Ok(mut slot) = self.sink.lock() {
                *slot = Some(outcome);
            }
        }
        if self.host == PromptHost::Standalone {
            ctx.send_viewport_cmd(egui::ViewportCommand::Close);
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
                // Only a standalone prompt owns the viewport whose close this reads. In-window the
                // flag belongs to the SHELL, and a shell being closed over a live prompt is settled
                // fail-closed by `ShellApp::close` — reading it here would answer a definite `Deny`
                // for a person who was closing the app, not refusing the request.
                self.host == PromptHost::Standalone && i.viewport().close_requested(),
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
        self.claim_the_keyboard(ctx);

        let t = self.theme.tokens();
        self.keys(ctx);
        self.place_bar(ctx);
        self.dismiss_on_blur(ctx);
        // Answer for the human who never came back, so one ignored window cannot hold the single
        // prompt thread — and therefore every later consent window — for the life of the process.
        if !self.answered && self.opened.elapsed() >= self.deadline {
            self.expire(ctx);
        }

        let (full, content_bottom) = egui::CentralPanel::default()
            .frame(egui::Frame::NONE.fill(rgba(t.bg)))
            .show(ctx, |ui| {
                let full = ui.available_rect_before_wrap();
                (full, self.paint_into(ui, full, &t))
            })
            .inner;
        // A bar is a fixed short height; only a dialog grows to its content.
        if !self.screen.chrome.is_bar() {
            self.fit_to_content(ctx, full, content_bottom);
        }
    }

    /// Paint the whole prompt — card, chrome, body, actions — into `full`, and report the bottom of
    /// its content.
    ///
    /// This is the prompt, entire. Both hosts call it with a rectangle and neither has any other way
    /// to draw one, so a standalone window and an in-window modal cannot drift apart: what a person
    /// reads before approving a spend is the same pixels either way. The hosts differ only in where
    /// the rectangle comes from and in what they do with the returned height.
    ///
    /// The return value is the y of the last content pixel — see [`PromptApp::fit_to_content`] for
    /// the sizing it feeds.
    fn paint_into(&mut self, ui: &mut egui::Ui, full: Rect, t: &Tokens) -> f32 {
        paint::card(ui, full, t);
        self.chrome(ui, full, t);
        let content_bottom = self.body(ui, full, t);
        self.actions(ui, full, t);
        content_bottom
    }

    /// Lay out and paint ONE frame as a layer inside the app shell.
    ///
    /// The counterpart of [`PromptApp::frame`] for [`PromptHost::InWindow`], and deliberately
    /// smaller than it: everything [`frame`](Self::frame) does that this omits is a message to a
    /// viewport this prompt does not own. It does not repaint-request (the shell already does, every
    /// frame, so the deadline below can elapse), does not place, size, or focus a window, and does
    /// not watch one for blur.
    ///
    /// What it keeps is everything that decides an ANSWER: the keyboard, the deadline, and the paint.
    ///
    /// # Why blur-dismissal is dropped rather than re-pointed
    ///
    /// [`PromptApp::dismiss_on_blur`] exists for the launcher bar: a Spotlight-style bar is dismissed
    /// by clicking away from it, and "away" means the bar's own window lost focus. In-window the only
    /// focus there is belongs to the SHELL, so the same code would mean something else entirely —
    /// *the person switched to their browser* — and would silently cancel whatever they had opened
    /// the moment they looked something up. Clicking off the app window is not an answer, so nothing
    /// here treats it as one. Every in-window prompt therefore stays until it is answered, escaped,
    /// or expired, exactly as every dialog already does ([`Chrome::dismiss_on_blur`] is false for all
    /// of them), and it is never trapping: Escape resolves it and the deadline resolves it.
    pub(super) fn frame_in_window(&mut self, ui: &mut egui::Ui, full: Rect) -> f32 {
        let t = self.theme.tokens();
        let ctx = ui.ctx().clone();
        self.keys(&ctx);
        // Answer for the human who never came back. The shell keeps the frames coming, so this
        // elapses on the same schedule a standalone prompt's does.
        if !self.answered && self.opened.elapsed() >= self.deadline {
            self.expire(&ctx);
        }
        self.paint_into(ui, full, &t)
    }

    /// Place the launcher bar HIGH on the screen — centred horizontally, `bar_top` from the top.
    ///
    /// A dialog is left centred (the compositor's default); only a bar is moved, and only once, on
    /// the first frame that reports a real monitor size. A headless frame reports no monitor, so this
    /// is a no-op there — which is exactly what the tests run under.
    fn place_bar(&mut self, ctx: &egui::Context) {
        if self.placed || !self.screen.chrome.is_bar() {
            return;
        }
        let monitor = ctx.input(|i| i.viewport().monitor_size);
        if let Some(monitor) = monitor {
            if monitor.x.is_finite() && monitor.y.is_finite() && monitor.y > 0.0 {
                let x = ((monitor.x - BAR_WIDTH) / 2.0).max(0.0);
                let y = bar_top(monitor.y);
                ctx.send_viewport_cmd(egui::ViewportCommand::OuterPosition(egui::Pos2::new(x, y)));
                self.placed = true;
            }
        }
    }

    /// Close the launcher bar the moment it loses focus — Esc is not the only way out of it.
    ///
    /// # Why the has-been-focused latch
    ///
    /// A window reports `focused == Some(false)` on the frames BEFORE it is first raised, so acting
    /// on the first unfocused frame would close the bar before the user ever saw it. The latch waits
    /// for one focused frame, so only a REAL blur — focus that was held and then left — dismisses it.
    ///
    /// # Why this is safe for a dialog
    ///
    /// [`Chrome::dismiss_on_blur`] is FALSE for every dialog, so a consent window can never reach the
    /// close below. A window asking the user to authorise a spend must never vanish because they
    /// clicked another window; it stays until it is answered. The existing no-answer path in [`draw`]
    /// maps this close to [`InputOutcome::Cancelled`] — a definite non-answer, never an approval.
    fn dismiss_on_blur(&mut self, ctx: &egui::Context) {
        if !self.screen.chrome.dismiss_on_blur() {
            return;
        }
        let focused = ctx.input(|i| i.viewport().focused);
        if focused == Some(true) {
            self.has_been_focused = true;
        }
        if self.has_been_focused && focused == Some(false) {
            self.finish(ctx, Answer::Deny);
        }
    }
}

impl PromptApp {
    /// The strip of the chrome the window may be dragged by.
    ///
    /// The chrome bar, minus the theme toggle and a dead zone in front of it. Everything else — the
    /// body, the field, and above all the action row — is deliberately OUTSIDE it, and that
    /// exclusion is a consent property rather than a tidiness one. See
    /// [`drag_by_the_header`](Self::drag_by_the_header).
    ///
    /// # Why the bottom edge is clamped rather than just [`CHROME_HEIGHT`]
    ///
    /// [`actions`](Self::actions) puts the action row at `full.bottom() - ACTION_ROW`, so on a window
    /// shorter than `CHROME_HEIGHT + ACTION_ROW` the two would OVERLAP and a press on the strip would
    /// land on a consent button. Nothing produces such a window today — [`MIN_HEIGHT`] is 320, it is
    /// also the viewport's `min_inner_size`, and [`fit_to_content`](Self::fit_to_content) re-requests
    /// a taller window every frame — but that is three separate coincidences holding up a consent
    /// property. Taking the smaller of the two edges makes it fail closed by construction: at any
    /// height where the row would reach the chrome, the strip shrinks to nothing and the window
    /// simply stops being draggable, which is the safe direction.
    fn drag_region(full: Rect) -> Rect {
        let action_row_top = full.bottom() - ACTION_ROW;
        let height = CHROME_HEIGHT.min(action_row_top - full.top());
        let right = full.right() - TOGGLE_WIDTH - space::S3 - DRAG_DEAD_ZONE;
        // `Rect::NOTHING` rather than a flattened rect: a zero-height rect still CONTAINS the points
        // on its own edge, so it could still take a press. There is no such thing as a slightly-safe
        // drag strip — either there is room for one above the action row or there is none.
        if height <= 0.0 || right <= full.left() {
            return Rect::NOTHING;
        }
        Rect::from_min_max(full.left_top(), egui::Pos2::new(right, full.top() + height))
    }

    /// Let the user move the window by its header, the way every other window on their desktop moves.
    ///
    /// # Why the window manager does the move, and not this code
    ///
    /// [`egui::ViewportCommand::StartDrag`] hands the gesture straight to the platform — on Windows
    /// `ReleaseCapture` followed by `WM_NCLBUTTONDOWN`/`HTCAPTION`, which is literally what dragging
    /// a titlebar does. Aero Snap at the screen edges, multi-monitor boundaries, per-monitor DPI
    /// transitions and the drag shadow all come from that one message. Reading pointer deltas and
    /// pushing [`egui::ViewportCommand::OuterPosition`] every frame would reimplement each of those,
    /// badly, and would fight the compositor at exactly the moment the window is moving — the
    /// condition under which a frameless surface was previously measured losing its content
    /// (dig_ecosystem#2038). The surface stays OPAQUE for the same reason; this adds a gesture, it
    /// does not reopen transparency.
    ///
    /// # Why a finished move cannot press anything — the STRUCTURAL guarantee
    ///
    /// This is the primary reason, and it does not depend on where the strip is.
    ///
    /// [`DRAG_HANDLE_SENSE`] senses BOTH click and drag, and for such a widget `egui` will not report
    /// a drag until [`egui::PointerState::is_decidedly_dragging`] holds (egui 0.31.1
    /// `interaction.rs:196`), which requires `!could_any_button_be_click()` — the pointer has already
    /// travelled past `max_click_dist` or been held past `max_click_duration`. **By the time
    /// [`egui::ViewportCommand::StartDrag`] is sent, the gesture has already been disqualified from
    /// ever producing a click.** Whatever release arrives afterwards, and wherever it lands, it cannot
    /// resolve as one. That covers the awkward case geometry alone would not: press, hold still for a
    /// second and a half, and let go directly on **Sign**.
    ///
    /// The sense is therefore load-bearing, not incidental. A `Sense::drag()` handle marks itself
    /// dragged on the PRESS frame (`interaction.rs:202`) and removes the disqualification entirely,
    /// which is why [`DRAG_HANDLE_SENSE`] keeps `CLICK` and why a test pins it.
    ///
    /// # Why the strip ALSO stops short of the controls — the backstop
    ///
    /// An `egui` button senses CLICKS only. Hit testing resolves a click and a drag separately, so a
    /// drag-sensing region that merely sits UNDER the action row still wins the drag: pressing
    /// **Sign** and moving a few pixels would move the window instead of signing, and — worse — the
    /// affirmative control would travel under a cursor already committed to pressing it. Depth does
    /// not save this; only geometry does, so the strip is bounded to the chrome and stops a dead zone
    /// short of the theme toggle ([`drag_region`](Self::drag_region)).
    ///
    /// Nothing about the gesture can answer the prompt. It sends one viewport command and touches
    /// neither [`PromptApp::record`] nor the sink, so a moved window still has exactly the outcomes
    /// it had standing still — including Escape, which stays wired first and unconditionally in
    /// [`keys`](Self::keys).
    ///
    /// # Where the release at `(0, 0)` actually comes from
    ///
    /// Windows runs the move in a MODAL loop, so this application's frames stop while the window is
    /// being dragged and the real button-up is consumed by that loop. winit compensates on
    /// `WM_EXITSIZEMOVE` by posting a synthetic `WM_LBUTTONUP` — but that arm never reads the
    /// message's `lparam`; it emits a bare `MouseInput { Released }` with no position at all (winit
    /// 0.30.13 `windows/event_loop.rs:1797`), and `egui-winit` fills the position in from the LAST
    /// CACHED cursor position (`egui-winit` 0.31.1 `lib.rs:551`).
    ///
    /// The `(0, 0)` is real, and it arrives by a different route: the `WM_NCLBUTTONDOWN`/`HTCAPTION`
    /// arm posts a dummy `WM_MOUSEMOVE` with `lparam = 0` to stop Windows pausing the loop
    /// (`windows/event_loop.rs:1244`), and that move is what leaves the cached position at the
    /// client origin. So the synthetic release lands at either the origin or wherever the pointer
    /// last genuinely was — and both are inside the strip, because the gesture began there. Recorded
    /// precisely because this paragraph is what a maintainer reads before moving the strip.
    ///
    /// # Aero Snap, honestly
    ///
    /// Snapping to a screen edge is a feature of RESIZABLE windows. These are created
    /// `.with_resizable(false)` so they can be sized to their content, so edge-snap does not apply —
    /// stated rather than claimed. Everything else the platform gesture provides (monitor
    /// boundaries, per-display scale, the drag shadow) is unaffected by that.
    fn drag_by_the_header(&self, ui: &egui::Ui, full: Rect) {
        // A launcher bar places itself high on the monitor and dismisses itself on blur; whether an
        // OS-driven move keeps it focused is a claim that needs a real desktop to settle, and getting
        // it wrong makes the bar vanish mid-gesture. Dialogs are what the user asked to be able to
        // move, so dialogs are what this covers.
        if self.screen.chrome.is_bar() {
            return;
        }
        let handle = ui.interact(
            Self::drag_region(full),
            ui.id().with("dig-prompt-drag"),
            DRAG_HANDLE_SENSE,
        );
        if handle.hovered() {
            ui.ctx().set_cursor_icon(egui::CursorIcon::Grab);
        }
        // Primary button only: a right-drag on a titlebar is the system menu, never a move.
        if handle.drag_started_by(egui::PointerButton::Primary) {
            ui.ctx().send_viewport_cmd(egui::ViewportCommand::StartDrag);
        }
    }

    /// The 44 px chrome: the drag strip, the brand mark, the window title, and the theme toggle.
    fn chrome(&mut self, ui: &mut egui::Ui, full: Rect, t: &Tokens) {
        let bar = Rect::from_min_size(full.left_top(), Vec2::new(full.width(), CHROME_HEIGHT));
        self.drag_by_the_header(ui, full);
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
        let width = TOGGLE_WIDTH;
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
        // A bar has no action row, so its body runs to the bottom padding; a dialog reserves the
        // room the [`actions`](Self::actions) row occupies.
        let bottom_reserve = match self.screen.chrome.is_bar() {
            true => space::S6,
            false => 88.0,
        };
        let inner = Rect::from_min_max(
            full.left_top() + Vec2::new(space::S6, CHROME_HEIGHT + space::S6),
            full.right_bottom() - Vec2::new(space::S6, bottom_reserve),
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
            // The launcher's field is oversized — a Spotlight bar is one big field the user types a
            // link into, not a labelled form control — while a dialog's field keeps the form scale.
            let bar = self.screen.chrome.is_bar();
            let (field_size, field_pad) = match bar {
                true => (size::HEADING, space::S4),
                false => (size::BASE, space::S3),
            };
            ui.label(super::render::label(
                &field.label,
                regular(size::SM),
                rgba(t.muted),
            ));
            ui.add_space(space::S2);
            let edit = egui::TextEdit::singleline(&mut *self.typed)
                .password(field.masked && !self.revealed)
                .desired_width(width)
                .margin(egui::Margin::symmetric(space::S3 as i8, field_pad as i8))
                .background_color(rgba(t.surface_2))
                .font(regular(field_size));
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
    ///
    /// A bar draws NO buttons: it is a Spotlight-style launcher dismissed by Esc or by blur and
    /// submitted by Enter (the pre-focused submit button in the model still resolves Enter — see
    /// [`PromptApp::keys`]), so a visible action row would only be consent chrome the launcher does
    /// not have.
    fn actions(&mut self, ui: &mut egui::Ui, full: Rect, t: &Tokens) {
        if self.screen.chrome.is_bar() {
            return;
        }
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

/// Open the app shell, and return as soon as it has been QUEUED.
///
/// `true` means the request reached the prompt thread; `false` means this host cannot draw a window
/// at all (see `start`) or the thread is gone. The caller is deliberately NOT blocked for the life
/// of the window: the shell is a window a person leaves open, and a tray click that did not return
/// until they closed it would hold the dispatching worker — and therefore Quit — for as long as it
/// was up.
///
/// # Why there is no answer to wait for
///
/// A shell produces no `Outcome`. It hosts prompts, and each of those keeps and answers its own
/// reply channel; nothing about the shell itself is a consent decision.
pub fn open_app_window(window: AppWindow) -> bool {
    let Some(host) = host() else {
        tracing::debug!("this host cannot draw the DIG app window");
        crate::window_host::note_open_failure();
        return false;
    };
    let queued = poisonless(&host.tx).send(Work::Shell(window));
    if queued.is_err() {
        tracing::error!("the DIG prompt thread is gone; the DIG app window cannot be opened");
        crate::window_host::note_open_failure();
        return false;
    }
    true
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
    let title = screen.title.clone();
    let job = Job {
        screen,
        wants_text,
        theme,
        deadline,
        // Stamped when the job is QUEUED, because that is when this caller's clock starts: the wait
        // below gives up at exactly this instant, and the renderer must not draw a window for a
        // caller that is already gone (`Job::over_by`).
        over_by: Instant::now() + deadline + ANSWER_GRACE,
        reply,
    };

    // Every arm below is a NON-answer, and each one is logged. A prompt surface that has stopped
    // working used to do so in complete silence — the user found it, not the log
    // (dig_ecosystem#2074) — and silence is what made a five-minute wedge indistinguishable from a
    // permanent one.
    let queued = poisonless(&host.tx).send(Work::Prompt(job));
    if queued.is_err() {
        tracing::error!(
            prompt = %title,
            "the DIG prompt thread is gone; no consent window can be shown for the rest of this \
             session and every prompt will be refused. Restart DIG."
        );
        return None;
    }

    match answers.recv_timeout(deadline + ANSWER_GRACE) {
        Ok(outcome) => Some(outcome),
        // The window did not even manage to dismiss itself. Report the same non-answer it would
        // have; there is no branch here that could produce an approval.
        Err(RecvTimeoutError::Timeout) => {
            tracing::warn!(
                prompt = %title,
                ?deadline,
                "a DIG prompt was never answered and its window did not dismiss itself; refusing"
            );
            Some(match wants_text {
                true => Outcome::Input(InputOutcome::Cancelled),
                false => Outcome::Confirm(WindowIntent::Timeout),
            })
        }
        // The prompt thread died holding the job.
        Err(RecvTimeoutError::Disconnected) => {
            tracing::error!(
                prompt = %title,
                "the DIG prompt thread died while drawing this window; the prompt is refused"
            );
            None
        }
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
                over_by: Instant::now() + PATIENT + ANSWER_GRACE,
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
                over_by: Instant::now() + PATIENT + ANSWER_GRACE,
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
                over_by: Instant::now() + PATIENT + ANSWER_GRACE,
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
                over_by: Instant::now() + PATIENT + ANSWER_GRACE,
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
                over_by: Instant::now() + PATIENT + ANSWER_GRACE,
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
                decline: None,
                refusal_is_default: true,
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
                decline: None,
                refusal_is_default: true,
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
            // The frameless launcher bar — the ONE view that exercises `Chrome::Bar`, so the
            // reshoot covers the wide oversized field and the dropped heading (dig_ecosystem#2054).
            ("launcher-bar", Screen::input(&InputContent {
                title: "DIG — Open a dig:// link".into(),
                heading: "Open a dig:// link".into(),
                body: "Paste or type a dig:// address.".into(),
                field_label: "dig:// address".into(),
                submit: "Open",
                masked: false,
                revealable: false,
                style: crate::confirm::InputStyle::Bar,
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
        let chrome = screen.chrome;
        let (reply, _rx) = sync_channel(1);
        let app = PromptApp::new(
            Job {
                screen,
                wants_text,
                theme: store.clone(),
                deadline: PATIENT,
                over_by: Instant::now() + PATIENT + ANSWER_GRACE,
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
            native_options(&title, chrome),
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

    /// Open a REAL prompt window and photograph its framebuffer on a schedule while something
    /// outside drags it.
    ///
    /// # Why this cannot be a headless test
    ///
    /// The claim being checked is dig_ecosystem#2038's: that a frameless surface on Windows can lose
    /// its content when the window MOVES and never recomposite. There is no compositor in a headless
    /// frame, so the only way to find out is to move a real window on a real desktop and read the
    /// real framebuffer back — with [`egui::ViewportCommand::Screenshot`], never a screen capture,
    /// because a GDI capture is blind to a hardware GL surface and would photograph the desktop
    /// behind it.
    ///
    /// The schedule is wall-clock from window creation so an external driver can aim at it:
    /// `drag-1-before` at 1.5 s, `drag-2-during` at 4.0 s (a drag is expected to be IN PROGRESS),
    /// `drag-3-after` at 7.0 s, `drag-4-settled` at 9.0 s. Each shot's outer position is written
    /// beside it, so "the window actually moved" is evidence rather than an impression.
    ///
    /// Ignored: it needs a display and a driver. Run with
    /// `cargo test -p dig-app-core --lib --all-features -- --ignored --nocapture a_real_window_survives_being_dragged`.
    #[test]
    #[ignore = "opens a real window and needs an external drag driver; run deliberately on a desktop"]
    fn a_real_window_survives_being_dragged() {
        let dir = std::path::PathBuf::from(
            std::env::var("DIG_PROMPT_SHOTS").unwrap_or_else(|_| "target/prompt-shots".into()),
        );
        std::fs::create_dir_all(&dir).expect("the gallery directory");

        let store_dir = tempfile::tempdir().expect("a temp dir");
        let store = ThemeChoice::in_brand_dir(store_dir.path());
        store.write(Theme::Light).expect("the theme persists");
        let screen = sign_screen();
        let title = screen.title.clone();
        let chrome = screen.chrome;
        let (reply, _rx) = sync_channel(1);
        let app = PromptApp::new(
            Job {
                screen,
                wants_text: false,
                theme: store.clone(),
                deadline: PATIENT,
                over_by: Instant::now() + PATIENT + ANSWER_GRACE,
                reply,
            },
            store,
            std::sync::Arc::new(Mutex::new(None)),
        );

        let log = std::sync::Arc::new(Mutex::new(Vec::<String>::new()));
        let recorded = log.clone();
        eframe::run_native(
            &title,
            native_options(&title, chrome),
            Box::new(move |cc| {
                install_fonts(&cc.egui_ctx);
                Ok(Box::new(DragProbe {
                    app,
                    started: Instant::now(),
                    next: 0,
                    pending: false,
                    dir,
                    log: recorded,
                }))
            }),
        )
        .expect("the real window opens");

        let log = log.lock().expect("the log is not poisoned");
        for line in log.iter() {
            println!("{line}");
        }
        assert_eq!(
            log.len(),
            DragProbe::SHOTS.len(),
            "the probe did not complete its schedule"
        );
    }

    /// The real window under an external drag, photographing itself on a timetable.
    struct DragProbe {
        app: PromptApp,
        started: Instant,
        /// Which entry of [`SHOTS`](Self::SHOTS) is next.
        next: usize,
        /// Whether a screenshot has been asked for and not yet come back.
        ///
        /// A request per frame would queue four of them inside one 60th of a second and the whole
        /// schedule would be consumed in three frames — measured, and it made the first run of this
        /// probe report four identical positions.
        pending: bool,
        dir: std::path::PathBuf,
        /// One line per shot: the file, its pixel size, and where the window was.
        log: std::sync::Arc<Mutex<Vec<String>>>,
    }

    impl DragProbe {
        /// When to photograph, and what to call each one.
        const SHOTS: [(f32, &'static str); 4] = [
            (1.5, "drag-1-before"),
            (4.0, "drag-2-during"),
            (7.0, "drag-3-after"),
            (9.0, "drag-4-settled"),
        ];
    }

    impl eframe::App for DragProbe {
        fn clear_color(&self, visuals: &egui::Visuals) -> [f32; 4] {
            self.app.clear_color(visuals)
        }

        fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
            self.app.frame(ctx);
            let elapsed = self.started.elapsed().as_secs_f32();
            if let Some((due, _)) = Self::SHOTS.get(self.next) {
                if elapsed >= *due && !self.pending {
                    self.pending = true;
                    ctx.send_viewport_cmd(egui::ViewportCommand::Screenshot(
                        egui::UserData::default(),
                    ));
                }
            }
            let shot = ctx.input(|i| {
                i.events.iter().find_map(|e| match e {
                    egui::Event::Screenshot { image, .. } => Some(image.clone()),
                    _ => None,
                })
            });
            let Some(image) = shot else { return };
            let Some((_, name)) = Self::SHOTS.get(self.next) else {
                return;
            };
            let where_it_is = ctx.input(|i| i.viewport().outer_rect);
            let path = self.dir.join(format!("{name}.png"));
            let (w, h) = (image.width(), image.height());
            let bytes: Vec<u8> = image
                .pixels
                .iter()
                .flat_map(|p| [p.r(), p.g(), p.b()])
                .collect();
            let file = std::fs::File::create(&path).expect("the screenshot file");
            let mut encoder = png::Encoder::new(std::io::BufWriter::new(file), w as u32, h as u32);
            encoder.set_color(png::ColorType::Rgb);
            encoder.set_depth(png::BitDepth::Eight);
            encoder
                .write_header()
                .and_then(|mut w| w.write_image_data(&bytes))
                .expect("the screenshot encodes");
            if let Ok(mut log) = self.log.lock() {
                log.push(format!(
                    "{name}: {w}x{h} at {:?} (t+{elapsed:.1}s)",
                    where_it_is.map(|r| r.min)
                ));
            }
            self.pending = false;
            self.next += 1;
            if self.next == Self::SHOTS.len() {
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

    /// A launcher-bar input, every field fixed but the style, so the window under test differs from a
    /// dialog only by what the bar chrome changes.
    fn launcher_input() -> InputContent {
        InputContent {
            title: "DIG — Open a dig:// link".into(),
            heading: "Open a dig:// link".into(),
            body: "Paste or type a dig:// address.".into(),
            field_label: "dig:// address".into(),
            submit: "Open",
            masked: false,
            revealable: false,
            style: crate::confirm::InputStyle::Bar,
        }
    }

    /// The launcher bar is created at [`BAR_WIDTH`] × [`BAR_HEIGHT`], NOT the dialog's [`WIDTH`] ×
    /// [`HEIGHT`] — the geometric half of the presentation the branded window had dropped (#2054).
    #[test]
    fn a_bar_window_is_created_wider_and_shorter_than_a_dialog() {
        let bar = native_options("t", Chrome::Bar);
        assert_eq!(
            bar.viewport.inner_size,
            Some([BAR_WIDTH, BAR_HEIGHT].into())
        );
        let dialog = native_options("t", Chrome::Dialog);
        assert_eq!(dialog.viewport.inner_size, Some([WIDTH, HEIGHT].into()));
        // Compare the widths the two windows are actually created at, not the raw consts — the point
        // is that a launcher is a wider bar than the dialog it replaces.
        let bar_width = bar
            .viewport
            .inner_size
            .expect("the bar has an inner size")
            .x;
        let dialog_width = dialog
            .viewport
            .inner_size
            .expect("the dialog has an inner size")
            .x;
        assert!(
            bar_width > dialog_width,
            "the bar ({bar_width}) must be wider than the dialog ({dialog_width})"
        );
    }

    /// Both windows are frameless and always-on-top — the bar regains the launcher chrome without
    /// giving up the properties every prompt window has.
    #[test]
    fn a_bar_stays_frameless_and_on_top() {
        let bar = native_options("t", Chrome::Bar);
        assert_eq!(bar.viewport.decorations, Some(false));
        assert_eq!(
            bar.viewport.window_level,
            Some(egui::WindowLevel::AlwaysOnTop)
        );
    }

    /// **A launcher bar dismisses itself when it loses focus, and reports [`InputOutcome::Cancelled`]
    /// — never an approval.** The one behaviour beyond looks the bar carries (dig_ecosystem#2054).
    ///
    /// Driven through real focus frames: two focused frames set the has-been-focused latch, then one
    /// unfocused frame is the blur that closes it. The existing no-answer path is not exercised here
    /// because [`PromptApp::dismiss_on_blur`] records the cancellation directly.
    #[test]
    fn a_bar_dismisses_when_it_loses_focus() {
        let mut driver = Driver::shown(Screen::input(&launcher_input()), true);
        driver.focus_frame(true);
        driver.focus_frame(true);
        driver.focus_frame(false);
        assert!(
            matches!(
                driver.answer(),
                Some(Outcome::Input(InputOutcome::Cancelled))
            ),
            "a bar that lost focus must cancel, not approve"
        );
    }

    /// A bar does NOT dismiss on an unfocused frame it sees BEFORE it has ever been focused — the
    /// has-been-focused latch stops it closing the instant it opens, before the user sees it.
    #[test]
    fn a_bar_does_not_self_dismiss_before_it_is_ever_focused() {
        let mut driver = Driver::shown(Screen::input(&launcher_input()), true);
        driver.focus_frame(false);
        driver.focus_frame(false);
        assert!(
            driver.answer().is_none(),
            "the bar closed before it was ever focused"
        );
    }

    /// **A dialog NEVER dismisses on blur.** A consent-shaped input window (and every confirm) must
    /// stay put when the user glances at another window — the exact opposite of the bar. Pins the
    /// other direction of dismiss-on-blur through the real frame loop.
    #[test]
    fn a_dialog_input_does_not_dismiss_on_blur() {
        let dialog = InputContent {
            style: crate::confirm::InputStyle::Dialog,
            ..launcher_input()
        };
        let mut driver = Driver::shown(Screen::input(&dialog), true);
        driver.focus_frame(true);
        driver.focus_frame(false);
        driver.focus_frame(false);
        assert!(
            driver.answer().is_none(),
            "a dialog vanished on blur — a consent window must never do that"
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
                over_by: Instant::now() + PATIENT + ANSWER_GRACE,
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
                over_by: Instant::now() + PATIENT + ANSWER_GRACE,
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
                    over_by: Instant::now() + deadline + ANSWER_GRACE,
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

        /// Run one frame reporting the window's focus state, the way the compositor does.
        ///
        /// `focused` is a property of the viewport, not an event: egui reads it from
        /// `ViewportInfo::focused`, so it is set on the root viewport rather than pushed as an event.
        /// This is how a blur (`Some(false)` after a `Some(true)`) is reproduced headlessly.
        fn focus_frame(&mut self, focused: bool) -> egui::FullOutput {
            let mut input = self.input();
            input
                .viewports
                .get_mut(&egui::ViewportId::ROOT)
                .expect("the root viewport")
                .focused = Some(focused);
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
                decline: None,
                refusal_is_default: true,
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
                decline: None,
                refusal_is_default: true,
                scannable: None,
                identifier: None,
            }),
            "Not yet",
        )
    }

    /// The height a screen asks the windowing system for, on a display of `monitor` logical pixels.
    ///
    /// `None` for `monitor` is the host that will not say how big its display is. Everything else in
    /// the suite runs that way, which is why the GROWTH half of the sizing had no coverage at all:
    /// nothing supplied [`egui::ViewportInfo::monitor_size`], so `tallest_here` always took its
    /// fallback branch and a regression to a bare `HEIGHT` cap passed every test while clipping the
    /// recovery phrase (dig_ecosystem#2074).
    fn asked_height_on(screen: Screen, monitor: Option<f32>) -> f32 {
        let dir = tempfile::tempdir().expect("a temp dir");
        let store = ThemeChoice::in_brand_dir(dir.path());
        let (reply, _rx) = sync_channel(1);
        let mut app = PromptApp::new(
            Job {
                screen,
                wants_text: false,
                theme: store.clone(),
                deadline: PATIENT,
                over_by: Instant::now() + PATIENT + ANSWER_GRACE,
                reply,
            },
            store,
            std::sync::Arc::new(Mutex::new(None)),
        );
        let ctx = egui::Context::default();
        install_fonts(&ctx);
        let mut viewports = egui::ViewportIdMap::default();
        viewports.insert(
            egui::ViewportId::ROOT,
            egui::ViewportInfo {
                monitor_size: monitor.map(|height| Vec2::new(1920.0, height)),
                ..Default::default()
            },
        );
        let input = egui::RawInput {
            screen_rect: Some(Rect::from_min_size(
                egui::Pos2::ZERO,
                Vec2::new(WIDTH, HEIGHT),
            )),
            viewports,
            ..Default::default()
        };
        // Two frames: the first builds the font atlas, the second lays out real glyphs and is the
        // one whose measured content drives the size request.
        let _ = ctx.run(input.clone(), |ctx| app.frame(ctx));
        let output = ctx.run(input, |ctx| app.frame(ctx));
        requested_height(&output).unwrap_or(HEIGHT)
    }

    /// **On a display with room, the phrase window GROWS past the size it was created at.**
    ///
    /// Growing is the half of the sizing fix that makes the 24 words VISIBLE; scrolling only makes
    /// them reachable, and for a person copying a phrase onto paper that is the difference between
    /// an affordance and a trap (dig_ecosystem#2038). It had no test: with no
    /// [`egui::ViewportInfo::monitor_size`] anywhere in the suite, `tallest_here` always returned
    /// [`HEIGHT`], so reverting the cap to a bare `HEIGHT` stayed green (dig_ecosystem#2074).
    ///
    /// Asserted against a tall display, where the phrase genuinely fits, and compared to the
    /// created size rather than to a magic number.
    #[test]
    fn a_tall_display_lets_the_phrase_window_grow_past_its_created_height() {
        let grown = asked_height_on(phrase_screen(), Some(1440.0));
        assert!(
            grown > HEIGHT,
            "on a 1440 px display the phrase window asked for {grown} px — no more than the \
             {HEIGHT} px it was created at, so the words below the fold are only reachable by \
             scrolling"
        );
        assert!(
            grown <= MAX_HEIGHT,
            "the window asked for {grown} px, past the {MAX_HEIGHT} px ceiling"
        );
    }

    /// **On a SHORT display the same window is held to a share of the screen.**
    ///
    /// The other half, and the one that keeps the window answerable: a consent window taller than
    /// the display puts its buttons off the bottom edge, where no click can reach them. Asserted
    /// with the same screen on a 720 px display, so a cap that ignored the monitor — or applied
    /// only [`MAX_HEIGHT`] — fails here.
    #[test]
    fn a_short_display_keeps_the_window_within_the_screen() {
        let capped = asked_height_on(phrase_screen(), Some(720.0));
        let allowed = 720.0 * SCREEN_SHARE;
        assert!(
            capped <= allowed,
            "on a 720 px display the window asked for {capped} px, past the {allowed} px this \
             display can show — its buttons would be off the bottom edge and unanswerable"
        );
        assert!(
            capped >= MIN_HEIGHT,
            "the window shrank to {capped} px, below the {MIN_HEIGHT} px floor"
        );
    }

    /// **A host that will not name its display gets the conservative size.**
    ///
    /// The fallback every display can show, and the branch every other test in the suite runs on.
    #[test]
    fn a_display_of_unknown_size_falls_back_to_the_created_height() {
        assert!(
            asked_height_on(phrase_screen(), None) <= HEIGHT,
            "a host that reports no monitor size was given a window taller than the size every \
             display is known to be able to show"
        );
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
        // Unwatched: this test is about ONE window and has no prompt thread to register with.
        let outcome = draw_watched(
            Job {
                screen: sign_screen(),
                wants_text: false,
                theme: store.clone(),
                // Answered by the deadline rather than by a person, so this needs a display but no
                // human.
                deadline: Duration::from_secs(1),
                over_by: Instant::now() + Duration::from_secs(1) + ANSWER_GRACE,
                reply,
            },
            None,
        );

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

    // ---------------------------------------------------------------------------------------
    // The prompt thread has to survive its own windows (dig_ecosystem#2074).
    //
    // Every prompt in the process is drawn on ONE thread, and that thread cannot be replaced —
    // `winit` allows a process one event loop, and `eframe` caches it per-thread, so a fresh
    // prompt thread would be told `RecreationAttempt` forever (see `start`). So the whole consent
    // surface — approve, deny, unlock, destroy — lives or dies with this loop. The suite had 904
    // tests and not one of them put a SECOND prompt through it.
    // ---------------------------------------------------------------------------------------

    /// A prompt thread running `drawn`, plus a way to put jobs through it and read the answers.
    pub(super) struct Lane {
        jobs: mpsc::Sender<Work>,
        worker: Option<std::thread::JoinHandle<()>>,
        store: ThemeChoice,
        _dir: tempfile::TempDir,
        /// A drawing lane RAISES the process-global consent-surface count, so two lanes running at
        /// once make any assertion about that count read another lane's window. Held for the lane's
        /// whole life, which is exactly the span in which it may draw. See
        /// [`crate::confirm::surface::ONE_SURFACE_AT_A_TIME`].
        _exclusive: std::sync::MutexGuard<'static, ()>,
    }

    impl Lane {
        /// Start the REAL [`serve_with`] loop on its own thread, drawing with `drawn`.
        /// Start a lane whose PROMPTS are drawn by `drawn` and which never opens a shell.
        fn serving(drawn: impl Fn(Job) -> Option<Outcome> + Send + 'static) -> Self {
            Self::serving_work(move |work, _queue| match work {
                Work::Prompt(job) => drawn(job),
                Work::Shell(_) => None,
            })
        }

        /// Start a lane over the whole of [`Work`], for the rules that are about the SHELL.
        pub(super) fn serving_work(
            drawn: impl Fn(Work, &Receiver<Work>) -> Option<Outcome> + Send + 'static,
        ) -> Self {
            // Taken BEFORE the thread starts, so no window of this lane's can be drawn while
            // another lane's assertions are running.
            let exclusive = crate::confirm::surface::one_surface_at_a_time();
            let dir = tempfile::tempdir().expect("a temp dir");
            let store = ThemeChoice::in_brand_dir(dir.path());
            let (jobs, rx) = mpsc::channel::<Work>();
            // Leaked so the loop can hold it for its whole life without borrowing from this frame.
            let drawing: &'static Mutex<Option<Vigil>> = Box::leak(Box::new(Mutex::new(None)));
            let worker = std::thread::Builder::new()
                .name("test-prompt-window".to_owned())
                .spawn(move || serve_with(&rx, drawing, drawn))
                .expect("the prompt thread spawns");
            Self {
                jobs,
                worker: Some(worker),
                store,
                _dir: dir,
                _exclusive: exclusive,
            }
        }

        /// Put one confirm through the loop and wait for its answer.
        ///
        /// The wait is bounded so a loop that died reports as a FAILED ASSERTION rather than hanging
        /// the suite — a hung test says "something is wrong somewhere", a failed one names it.
        pub(super) fn ask(&self) -> Result<Outcome, RecvTimeoutError> {
            self.ask_expiring_at(Instant::now() + PATIENT + ANSWER_GRACE)
        }

        /// Ask the loop to open the app shell. Returns as soon as it is QUEUED — nothing is
        /// blocked on a shell, so there is no answer to wait for.
        pub(super) fn open_shell(&self) {
            self.jobs
                .send(Work::Shell(AppWindow {
                    theme: self.store.clone(),
                    view: Arc::new(crate::tray_menu::TrayView::default),
                    act: Arc::new(|_| {}),
                }))
                .expect("the prompt thread is still accepting jobs");
        }

        /// Queue a confirm whose caller gives up at `over_by`, and wait for the answer.
        ///
        /// An `over_by` already in the past is a job whose caller walked away while it sat in the
        /// queue — which is the ordinary consequence of one window wedging in front of it.
        fn ask_expiring_at(&self, over_by: Instant) -> Result<Outcome, RecvTimeoutError> {
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
                .expect("the prompt thread is still accepting jobs");
            answers.recv_timeout(Duration::from_secs(10))
        }
    }

    impl Drop for Lane {
        fn drop(&mut self) {
            // Dropping the sender is what ends `serve_with`; joining proves it ended cleanly.
            let (jobs, _) = mpsc::channel();
            drop(std::mem::replace(&mut self.jobs, jobs));
            if let Some(worker) = self.worker.take() {
                let _ = worker.join();
            }
        }
    }

    /// **A drawn prompt reports itself as a consent surface, for exactly as long as it is drawn.**
    ///
    /// The tray disables its foreground claim while this reads true (dig-app#91), so BOTH edges are
    /// load-bearing in opposite directions: a signal that never rises leaves a prompt fighting the
    /// tray for focus, and one that never falls silently disables the claim for the life of the
    /// process — which looks exactly like a claim that is working.
    ///
    /// The "after" assertion is made while `lane` is STILL ALIVE and still serving. That is the
    /// whole point of it: the neighbouring wrong implementation raises the guard for the span of
    /// `serve_with` — "the prompt thread is running, so a surface is up" — and that reads identical
    /// to this one at every moment except this one.
    #[test]
    fn a_prompt_is_a_consent_surface_only_while_it_is_being_drawn() {
        use crate::confirm::surface::consent_surface_is_up;
        use std::sync::atomic::{AtomicBool, Ordering};
        use std::sync::Arc;

        let seen_during_draw = Arc::new(AtomicBool::new(false));
        let recorder = Arc::clone(&seen_during_draw);
        let lane = Lane::serving(move |_job| {
            recorder.store(consent_surface_is_up(), Ordering::SeqCst);
            Some(Outcome::Confirm(WindowIntent::Deny))
        });

        lane.ask().expect("the prompt thread answers");

        assert!(
            seen_during_draw.load(Ordering::SeqCst),
            "a window being drawn IS a consent surface; with no signal the tray would keep \
             claiming the foreground over a prompt the user is reading"
        );
        assert!(
            !consent_surface_is_up(),
            "the surface is gone the moment the draw returns — and the lane is still serving, \
             which is what distinguishes this from a guard held for the thread's whole life"
        );
    }

    /// **A prompt that panicked mid-draw is not left reported as on screen.**
    ///
    /// `serve_with` catches the panic and keeps the thread alive, so a leaked signal would cost
    /// nothing visible: it would just disable the tray's foreground claim from then on, forever,
    /// indistinguishably from the claim working. That is why the signal is an RAII guard and why
    /// this drives a real panic through the real loop rather than trusting the guard's own unit test
    /// — the unwind here passes through `eframe`-shaped frames and `catch_unwind`.
    #[test]
    fn a_panicking_prompt_does_not_leave_a_consent_surface_reported() {
        use crate::confirm::surface::consent_surface_is_up;

        let lane = Lane::serving(|_job| panic!("a prompt window panicked mid-draw"));

        let outcome = lane
            .ask()
            .expect("the loop survives its window's panic and answers");
        assert!(
            matches!(outcome, Outcome::Confirm(WindowIntent::Unavailable)),
            "a panicked draw is fail-closed, as it already was"
        );
        assert!(
            !consent_surface_is_up(),
            "the unwind must lower the signal; a raise/lower pair leaks it here and silently \
             disables the tray's foreground claim for the rest of the process"
        );
    }

    /// **Two prompts in a row are BOTH answerable.**
    ///
    /// The defect that shipped in 5.14.0 was not that a prompt was wrong — it was that after one
    /// prompt there was never another (dig_ecosystem#2074). Nothing in the suite drove a second
    /// prompt through the real loop, so nothing could have caught it.
    ///
    /// Asserted on the SECOND and THIRD answers specifically: a loop that serves exactly one job
    /// and then stops passes any test that asks only once.
    #[test]
    fn a_second_prompt_is_answerable_after_a_first_one_closes() {
        let lane = Lane::serving(|_| Some(Outcome::Confirm(WindowIntent::Deny)));
        for nth in 1..=3 {
            let answer = lane.ask();
            assert!(
                matches!(answer, Ok(Outcome::Confirm(WindowIntent::Deny))),
                "prompt {nth} of 3 was never answered — the prompt thread stopped serving after \
                 {} prompt(s), which is a consent lockout for the life of the process",
                nth - 1
            );
        }
    }

    /// **The window ASKS for the keyboard, once, on its first frame.**
    ///
    /// A consent window that opens without keyboard focus has no way out at all: undecorated, so no
    /// close button; always-on-top, so it cannot be put behind anything; and Escape goes to whoever
    /// does hold the keyboard — while the input window's own body says *"press Enter. Esc closes
    /// this."* Measured on a cold start, twice (dig_ecosystem#2079).
    ///
    /// Both halves are asserted, because each alone permits a defect. Asking on the FIRST frame is
    /// the fix; asking on EVERY frame would fight the user for the foreground for the whole life of
    /// the window, which is worse than the bug.
    ///
    /// What this cannot assert is that Windows AGREES — the foreground lock may refuse, and this
    /// deliberately does not try to defeat it. The decision under test is that DIG asks.
    #[test]
    fn the_window_asks_for_the_keyboard_on_its_first_frame_and_only_then() {
        let (_dir, store) = theme_store();
        let (reply, _rx) = sync_channel(1);
        let mut app = PromptApp::new(
            Job {
                screen: sign_screen(),
                wants_text: false,
                theme: store.clone(),
                deadline: PATIENT,
                over_by: Instant::now() + PATIENT + ANSWER_GRACE,
                reply,
            },
            store,
            std::sync::Arc::new(Mutex::new(None)),
        );
        let ctx = egui::Context::default();
        install_fonts(&ctx);

        fn asked_for_focus(output: &egui::FullOutput) -> bool {
            output
                .viewport_output
                .values()
                .any(|viewport| viewport.commands.contains(&egui::ViewportCommand::Focus))
        }

        let first = ctx.run(egui::RawInput::default(), |ctx| app.frame(ctx));
        assert!(
            asked_for_focus(&first),
            "the window never asked for the keyboard, so on a cold start it can open with no \
             working escape: Escape goes elsewhere and it has no close button"
        );

        for nth in 2..=4 {
            let later = ctx.run(egui::RawInput::default(), |ctx| app.frame(ctx));
            assert!(
                !asked_for_focus(&later),
                "frame {nth} asked for the keyboard again — a window that re-claims the foreground \
                 every frame takes it back off whatever the user switched to"
            );
        }
    }

    /// **A prompt whose caller already gave up is never DRAWN.**
    ///
    /// Jobs are served one at a time, so a wedged window parks every later prompt in the queue. Each
    /// of those callers times out and is refused — but the jobs survive, and once the renderer is
    /// freed the loop would open every one of them in turn: a genuine sign window, a genuine unlock,
    /// a genuine destroy confirm, each with a real origin and payload, for operations refused
    /// minutes earlier, each holding the single renderer for another full deadline
    /// (dig_ecosystem#2074). One wedge would cost its own outage MULTIPLIED by the queue behind it.
    ///
    /// The assertion is on the PROPERTY, not the answer: it COUNTS DRAWS. "The stale job answered
    /// `Unavailable`" is satisfied identically by a loop that opens the window, holds the thread for
    /// five minutes and then fails to deliver the answer — which is the defect. Only "the draw never
    /// happened" distinguishes them.
    #[test]
    fn a_prompt_whose_caller_gave_up_is_refused_without_being_drawn() {
        let draws = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let counter = draws.clone();
        // The drawing answers `Unavailable` — the SAME answer skipping produces — so that the answer
        // cannot distinguish the two and the draw count is the only thing that can. A draw that
        // returned anything else would let the outcome assertions fail first and leave the counts
        // unreached, which is how "answered Unavailable" sneaks in as the real assertion.
        let lane = Lane::serving(move |_| {
            counter.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Some(Outcome::Confirm(WindowIntent::Unavailable))
        });

        // A live prompt first, so the count below cannot pass by the loop simply never drawing.
        assert!(
            matches!(lane.ask(), Ok(Outcome::Confirm(WindowIntent::Unavailable))),
            "the control prompt was not served"
        );
        assert_eq!(
            draws.load(std::sync::atomic::Ordering::SeqCst),
            1,
            "the control prompt was not drawn"
        );

        let stale = lane.ask_expiring_at(Instant::now() - Duration::from_secs(1));
        assert!(
            matches!(stale, Ok(Outcome::Confirm(WindowIntent::Unavailable))),
            "a stale prompt must still answer its (departed) caller, and never with an approval"
        );
        assert_eq!(
            draws.load(std::sync::atomic::Ordering::SeqCst),
            1,
            "a prompt whose caller had already given up was DRAWN — that is a real consent window, \
             with a real origin and payload, opened for an operation nobody is waiting on, holding \
             the one renderer for another full deadline"
        );

        // …and the loop is still serving afterwards: skipping must not be a way to stop.
        assert!(
            matches!(lane.ask(), Ok(Outcome::Confirm(WindowIntent::Unavailable))),
            "the prompt thread stopped after skipping a stale job"
        );
        assert_eq!(
            draws.load(std::sync::atomic::Ordering::SeqCst),
            2,
            "the prompt after a skipped one was not drawn"
        );
    }

    /// **A window that PANICS costs one prompt, not every later one.**
    ///
    /// Without the guard, a panic unwinds out of the loop and the process keeps a `PromptThread`
    /// whose receiver is gone: every later prompt is refused for the life of the process, with
    /// nothing logged and no window shown. The thread cannot be replaced either (`start`), so
    /// surviving the panic is the only recovery there is.
    ///
    /// Both halves are asserted, because either alone would pass a broken implementation: the
    /// panicking prompt must come back REFUSED (never an approval, never a hang), and the one after
    /// it must be answered normally.
    #[test]
    fn a_panicking_prompt_is_refused_and_the_next_prompt_still_works() {
        let first = std::sync::atomic::AtomicBool::new(true);
        let lane = Lane::serving(move |_| {
            if first.swap(false, std::sync::atomic::Ordering::SeqCst) {
                panic!("a prompt window blew up mid-frame (dig_ecosystem#2074)");
            }
            Some(Outcome::Confirm(WindowIntent::Approve))
        });

        // The panic must not become a hang, and must not become consent.
        let panicked = lane.ask();
        assert!(
            matches!(panicked, Ok(Outcome::Confirm(WindowIntent::Unavailable))),
            "a prompt whose window panicked must answer Unavailable, not hang and not approve"
        );

        let after = lane.ask();
        assert!(
            matches!(after, Ok(Outcome::Confirm(WindowIntent::Approve))),
            "the prompt after a panicking one was never answered — one bad window took the whole \
             consent surface down with it"
        );
    }

    /// **A window that cannot be opened is refused, and the next one is still tried.**
    ///
    /// The headless path, which is also what a display that goes away mid-session looks like. A
    /// `None` from the draw must be a refusal for THAT prompt only.
    #[test]
    fn a_window_that_will_not_open_refuses_only_its_own_prompt() {
        let opened = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let counter = opened.clone();
        let lane = Lane::serving(move |_| {
            match counter.fetch_add(1, std::sync::atomic::Ordering::SeqCst) {
                0 => None,
                _ => Some(Outcome::Confirm(WindowIntent::Deny)),
            }
        });
        assert!(
            matches!(lane.ask(), Ok(Outcome::Confirm(WindowIntent::Unavailable))),
            "a window that would not open must be Unavailable, never an approval"
        );
        assert!(
            matches!(lane.ask(), Ok(Outcome::Confirm(WindowIntent::Deny))),
            "the prompt thread stopped after a window failed to open"
        );
        assert_eq!(
            opened.load(std::sync::atomic::Ordering::SeqCst),
            2,
            "the second prompt was never even attempted"
        );
    }

    /// **A caller that walked away does not take the prompt thread with it.**
    ///
    /// The reply channel is dropped before the answer arrives — an ordinary cancelled task. The
    /// send fails, and the loop must treat that as this caller's business and take the next job.
    #[test]
    fn an_abandoned_caller_does_not_stop_the_prompt_thread() {
        let lane = Lane::serving(|_| Some(Outcome::Confirm(WindowIntent::Deny)));
        {
            let (reply, answers) = sync_channel(1);
            lane.jobs
                .send(Work::Prompt(Job {
                    screen: sign_screen(),
                    wants_text: false,
                    theme: lane.store.clone(),
                    deadline: PATIENT,
                    over_by: Instant::now() + PATIENT + ANSWER_GRACE,
                    reply,
                }))
                .expect("the job is queued");
            drop(answers);
        }
        assert!(
            matches!(lane.ask(), Ok(Outcome::Confirm(WindowIntent::Deny))),
            "the prompt thread stopped after a caller abandoned its prompt"
        );
    }

    /// **A window past its deadline is forced closed from OUTSIDE the frame loop.**
    ///
    /// [`PromptApp::frame`] expires a window by checking the clock on each frame, which is no bound
    /// at all if the frame loop stops running: the window then holds the only prompt thread there
    /// is, and no later consent window can ever be drawn (dig_ecosystem#2074).
    ///
    /// Driven against a real [`egui::Context`] with no window attached, in milliseconds: the
    /// watchdog must ask THAT context to close. Asserted on the command the context actually
    /// received, so a watchdog that wakes the loop without asking it to close — the earlier,
    /// insufficient shape — fails here.
    #[test]
    fn the_watchdog_closes_a_window_that_outlived_its_deadline() {
        let drawing: &'static Mutex<Option<Vigil>> = Box::leak(Box::new(Mutex::new(None)));
        let ctx = egui::Context::default();
        set_vigil(drawing, Some(ctx.clone()), Instant::now());
        std::thread::spawn(move || watch(drawing, Duration::from_millis(10)));

        let deadline = Instant::now() + Duration::from_secs(5);
        let closed = loop {
            if commands_of(&ctx).contains(&egui::ViewportCommand::Close) {
                break true;
            }
            if Instant::now() > deadline {
                break false;
            }
            std::thread::sleep(Duration::from_millis(20));
        };
        assert!(
            closed,
            "the watchdog never asked the overdue window to close; a stalled prompt would hold the \
             one prompt thread for the life of the process"
        );
    }

    /// **A window still inside its deadline is left alone.**
    ///
    /// The other half of the watchdog, and the one that matters for consent: a person reading a
    /// spend prompt must not have it shut in their face because a timer is coarse.
    #[test]
    fn the_watchdog_leaves_a_window_that_is_still_in_time_alone() {
        let drawing: &'static Mutex<Option<Vigil>> = Box::leak(Box::new(Mutex::new(None)));
        let ctx = egui::Context::default();
        set_vigil(
            drawing,
            Some(ctx.clone()),
            Instant::now() + Duration::from_secs(3600),
        );
        std::thread::spawn(move || watch(drawing, Duration::from_millis(10)));
        std::thread::sleep(Duration::from_millis(300));
        assert!(
            !commands_of(&ctx).contains(&egui::ViewportCommand::Close),
            "the watchdog closed a window that was still well inside its deadline"
        );
    }

    /// **A finished window is taken off the watchdog's list.**
    ///
    /// Otherwise the watchdog would eventually send `Close` to the context of a window that is long
    /// gone — harmless today, and exactly the kind of stale handle that becomes a cross-prompt bug
    /// the moment contexts are reused.
    #[test]
    fn a_finished_window_is_no_longer_watched() {
        let drawing = Mutex::new(None);
        set_vigil(&drawing, Some(egui::Context::default()), Instant::now());
        assert!(
            poisonless(&drawing).is_some(),
            "the window never registered with the watchdog"
        );
        clear_vigil(&drawing);
        assert!(
            poisonless(&drawing).is_none(),
            "a window that finished is still being watched"
        );
    }

    /// **A poisoned watchdog slot does not disable prompts.**
    ///
    /// The slot is touched by a thread that is expected to panic occasionally (that is what the
    /// guard in `serve_with` is for). If a poisoning made the slot unusable, the FIRST panicking
    /// prompt would silently switch the deadline enforcement off for the whole session.
    #[test]
    fn a_poisoned_watchdog_slot_is_recovered_rather_than_propagated() {
        let drawing: &'static Mutex<Option<Vigil>> = Box::leak(Box::new(Mutex::new(None)));
        let poisoner = std::thread::spawn(|| {
            let _held = drawing.lock().expect("the slot locks");
            panic!("poisoning the slot on purpose");
        });
        assert!(
            poisoner.join().is_err(),
            "the poisoning thread should panic"
        );

        set_vigil(drawing, Some(egui::Context::default()), Instant::now());
        assert!(
            poisonless(drawing).is_some(),
            "a poisoned slot stopped later windows from being watched at all"
        );
    }

    /// Every viewport command a context has been asked to run, from a frame with no window.
    fn commands_of(ctx: &egui::Context) -> Vec<egui::ViewportCommand> {
        let output = ctx.run(egui::RawInput::default(), |_| {});
        output
            .viewport_output
            .values()
            .flat_map(|viewport| viewport.commands.clone())
            .collect()
    }

    /// **THREE real prompts in a row, through the real window.**
    ///
    /// The headless tests above pin what the loop does with a window that misbehaves; this one pins
    /// that a real `eframe` window can be opened, closed and then opened AGAIN on the same thread —
    /// the claim the whole single-thread design rests on, and the one a mocked draw cannot make.
    ///
    /// Ignored because it opens real windows: CI has no display. Run it deliberately on a desktop.
    /// The exclusion below is what makes running it deliberately SAFE — see the comment on it.
    #[test]
    #[ignore = "opens three real windows; run deliberately on a desktop"]
    fn three_real_prompt_windows_in_a_row_are_all_answered() {
        // This drives the real `serve`, which raises the process-global consent-surface count around
        // each draw. Held before the thread starts, so no window of this test's can be on screen
        // while another test's count assertions run. Without it, un-ignoring this test measured 15
        // failures in 40 runs; with it, 0 in 40 (dig-app#99).
        let _exclusive = crate::confirm::surface::one_surface_at_a_time();
        let dir = tempfile::tempdir().expect("a temp dir");
        let store = ThemeChoice::in_brand_dir(dir.path());
        let (jobs, rx) = mpsc::channel::<Work>();
        let drawing: &'static Mutex<Option<Vigil>> = Box::leak(Box::new(Mutex::new(None)));
        let worker = std::thread::Builder::new()
            .name("dig-prompt-window".to_owned())
            .stack_size(4 * 1024 * 1024)
            .spawn(move || serve(&rx, drawing))
            .expect("the prompt thread spawns");

        for nth in 1..=3 {
            let (reply, answers) = sync_channel(1);
            jobs.send(Work::Prompt(Job {
                screen: sign_screen(),
                wants_text: false,
                theme: store.clone(),
                // Answered by the deadline rather than by a person, so this needs a display but no
                // human. Short enough that three of them fit in a test run.
                deadline: Duration::from_millis(900),
                over_by: Instant::now() + Duration::from_millis(900) + ANSWER_GRACE,
                reply,
            }))
            .expect("the job is queued");
            let answer = answers.recv_timeout(Duration::from_secs(30));
            assert!(
                matches!(answer, Ok(Outcome::Confirm(WindowIntent::Timeout))),
                "real prompt {nth} of 3 never answered — a window opened and the thread never came \
                 back from it"
            );
        }
        drop(jobs);
        worker.join().expect("the prompt thread exits cleanly");
    }

    /// The typed buffer is `Zeroizing`, so a recovery phrase is wiped when the window drops rather
    /// than left in the heap for whatever allocates next.
    #[test]
    fn the_typed_buffer_is_zeroizing() {
        fn assert_zeroizing<T: zeroize::Zeroize>(_: &T) {}
        let buffer: Zeroizing<String> = Zeroizing::new("abandon abandon".into());
        assert_zeroizing(&*buffer);
    }

    /// A real prompt, driven frame by frame with real pointer input.
    ///
    /// [`painted`] answers "what did one frame draw"; the drag gesture is a SEQUENCE — a press, then
    /// motion while held — and the thing under test is which of those frames asks the windowing
    /// system to take over. So this keeps the app alive across frames and accumulates every viewport
    /// command it issued, alongside the answer it recorded.
    struct Driven {
        app: PromptApp,
        ctx: egui::Context,
        sink: std::sync::Arc<Mutex<Option<Outcome>>>,
        commands: Vec<egui::ViewportCommand>,
        /// Kept alive: the theme store writes into it for the life of the app.
        _dir: tempfile::TempDir,
    }

    impl Driven {
        fn new(screen: Screen) -> Self {
            Self::with(screen, false)
        }

        fn with(screen: Screen, wants_text: bool) -> Self {
            let dir = tempfile::tempdir().expect("a temp dir");
            let store = ThemeChoice::in_brand_dir(dir.path());
            store.write(Theme::Light).expect("the theme persists");
            let (reply, _rx) = sync_channel(1);
            let sink = std::sync::Arc::new(Mutex::new(None));
            let app = PromptApp::new(
                Job {
                    screen,
                    wants_text,
                    theme: store.clone(),
                    deadline: PATIENT,
                    over_by: Instant::now() + PATIENT + ANSWER_GRACE,
                    reply,
                },
                store,
                sink.clone(),
            );
            let ctx = egui::Context::default();
            install_fonts(&ctx);
            let mut driven = Self {
                app,
                ctx,
                sink,
                commands: Vec::new(),
                _dir: dir,
            };
            // The first frame builds the font atlas and lays out against a provisional one, so it is
            // run and DISCARDED before anything is measured or asserted on.
            driven.frame(Vec::new());
            driven.commands.clear();
            driven
        }

        /// Run one frame with `events` delivered to it.
        fn frame(&mut self, events: Vec<egui::Event>) {
            self.frame_focused(events, None);
        }

        /// Run one frame with `events`, and with the windowing system reporting `focused`.
        ///
        /// Focus arrives as viewport INFO rather than as an event, so it cannot be expressed in
        /// `events` — and focus is what [`PromptApp::dismiss_on_blur`] reads.
        fn frame_focused(&mut self, events: Vec<egui::Event>, focused: Option<bool>) {
            let mut viewports = egui::ViewportIdMap::default();
            viewports.insert(
                egui::ViewportId::ROOT,
                egui::ViewportInfo {
                    focused,
                    ..Default::default()
                },
            );
            let input = egui::RawInput {
                screen_rect: Some(Rect::from_min_size(
                    egui::Pos2::ZERO,
                    Vec2::new(WIDTH, HEIGHT),
                )),
                events,
                viewports,
                ..Default::default()
            };
            let app = &mut self.app;
            let output = self.ctx.run(input, |ctx| app.frame(ctx));
            for viewport in output.viewport_output.values() {
                self.commands.extend(viewport.commands.iter().cloned());
            }
        }

        /// Press the primary button at `at` and run ONE frame. No movement, no release.
        fn press_only(&mut self, at: egui::Pos2) {
            self.press(at, egui::PointerButton::Primary);
        }

        fn press(&mut self, at: egui::Pos2, button: egui::PointerButton) {
            self.frame(vec![
                egui::Event::PointerMoved(at),
                egui::Event::PointerButton {
                    pos: at,
                    button,
                    pressed: true,
                    modifiers: Default::default(),
                },
            ]);
        }

        /// Press `button` at `at`, then move while still held.
        fn press_and_drag_with(&mut self, at: egui::Pos2, button: egui::PointerButton) {
            self.press(at, button);
            self.frame(vec![egui::Event::PointerMoved(at + Vec2::new(120.0, 90.0))]);
        }

        /// Press the primary button at `at`, then move while still held.
        ///
        /// Two frames on purpose. A press alone is a click; only motion past egui's threshold while
        /// the button is down is a DRAG, and it is the drag that must reach the window manager.
        fn press_and_drag(&mut self, at: egui::Pos2) {
            self.frame(vec![
                egui::Event::PointerMoved(at),
                egui::Event::PointerButton {
                    pos: at,
                    button: egui::PointerButton::Primary,
                    pressed: true,
                    modifiers: Default::default(),
                },
            ]);
            self.frame(vec![egui::Event::PointerMoved(at + Vec2::new(120.0, 90.0))]);
        }

        /// The whole gesture: press at `from`, move to `to`, and let go THERE.
        ///
        /// The release is the half a hit-region test cannot see. A drag that begins on the header
        /// ends wherever the user stopped moving, and that is very often over a control.
        fn drag_from_to(&mut self, from: egui::Pos2, to: egui::Pos2) {
            self.frame(vec![
                egui::Event::PointerMoved(from),
                egui::Event::PointerButton {
                    pos: from,
                    button: egui::PointerButton::Primary,
                    pressed: true,
                    modifiers: Default::default(),
                },
            ]);
            self.frame(vec![egui::Event::PointerMoved(to)]);
            self.frame(vec![egui::Event::PointerButton {
                pos: to,
                button: egui::PointerButton::Primary,
                pressed: false,
                modifiers: Default::default(),
            }]);
        }

        /// Press and release the primary button at `at`, which is a plain click.
        fn click(&mut self, at: egui::Pos2) {
            self.frame(vec![
                egui::Event::PointerMoved(at),
                egui::Event::PointerButton {
                    pos: at,
                    button: egui::PointerButton::Primary,
                    pressed: true,
                    modifiers: Default::default(),
                },
            ]);
            self.frame(vec![egui::Event::PointerButton {
                pos: at,
                button: egui::PointerButton::Primary,
                pressed: false,
                modifiers: Default::default(),
            }]);
        }

        fn press_key(&mut self, key: Key) {
            self.frame(vec![egui::Event::Key {
                key,
                physical_key: None,
                pressed: true,
                repeat: false,
                modifiers: Default::default(),
            }]);
        }

        /// Whether the window ever asked the platform to take over a move.
        fn asked_the_os_to_move_it(&self) -> bool {
            self.commands
                .iter()
                .any(|cmd| matches!(cmd, egui::ViewportCommand::StartDrag))
        }

        fn recorded(&self) -> Option<WindowIntent> {
            match &*self.sink.lock().expect("the sink is not poisoned") {
                Some(Outcome::Confirm(intent)) => Some(*intent),
                _ => None,
            }
        }
    }

    /// The frameless launcher bar — the one screen whose chrome is [`Chrome::Bar`].
    fn bar_screen() -> Screen {
        Screen::input(&InputContent {
            title: "DIG — Open a dig:// link".into(),
            heading: "Open a dig:// link".into(),
            body: "Paste or type a dig:// address.".into(),
            field_label: "dig:// address".into(),
            submit: "Open",
            masked: false,
            revealable: false,
            style: crate::confirm::InputStyle::Bar,
        })
    }

    /// The full window rect every driven frame is laid out in.
    fn full_rect() -> Rect {
        Rect::from_min_size(egui::Pos2::ZERO, Vec2::new(WIDTH, HEIGHT))
    }

    /// A point in the middle of the draggable header strip.
    fn on_the_header() -> egui::Pos2 {
        PromptApp::drag_region(full_rect()).center()
    }

    /// A point on the RIGHTMOST control of the action row — the affirmative one.
    ///
    /// Derived from the row geometry rather than eyeballed, and every test that uses it also proves
    /// the point really lands on the button (see
    /// [`the_action_row_is_not_a_drag_handle`]): a coordinate that quietly missed the control would
    /// make "no drag started here" true for the wrong reason.
    fn on_the_affirmative_button() -> egui::Pos2 {
        let full = full_rect();
        egui::Pos2::new(
            full.right() - space::S6 - 40.0,
            full.bottom() - ACTION_ROW / 2.0,
        )
    }

    /// A point on the theme toggle in the chrome.
    fn on_the_theme_toggle() -> egui::Pos2 {
        let full = full_rect();
        egui::Pos2::new(
            full.right() - space::S3 - TOGGLE_WIDTH / 2.0,
            CHROME_HEIGHT / 2.0,
        )
    }

    /// **A prompt can be moved by its header, and the platform does the moving.**
    ///
    /// Asserted as [`egui::ViewportCommand::StartDrag`] specifically, not merely "the window moved".
    /// That command is what becomes `WM_NCLBUTTONDOWN`/`HTCAPTION` on Windows, and it is where Aero
    /// Snap, monitor boundaries and DPI transitions come from. A hand-rolled
    /// [`egui::ViewportCommand::OuterPosition`] loop would also move the window and would have none
    /// of them, so the test pins the mechanism (dig_ecosystem#2096).
    #[test]
    fn a_prompt_is_dragged_by_its_header() {
        let mut window = Driven::new(sign_screen());
        window.press_and_drag(on_the_header());
        assert!(
            window.asked_the_os_to_move_it(),
            "a press-and-drag on the header never sent StartDrag, so the window cannot be moved"
        );
    }

    /// **The action row is not a drag handle.** Pressing **Sign** and twitching must sign, never move
    /// the window.
    ///
    /// This is a PLACEMENT property, and placement is what an outcome-only assertion cannot see, so
    /// the test is built in two halves against ONE varied coordinate:
    ///
    /// * the same gesture on the header DOES start a move — the honest control, without which
    ///   "no drag here" would also pass on a build where dragging is broken everywhere;
    /// * a click at the very same action-row point records an APPROVAL — which proves the coordinate
    ///   is genuinely on the affirmative control, rather than in some empty corner where nothing was
    ///   ever going to happen.
    ///
    /// The hazard is real rather than theoretical: an `egui` button senses clicks only, and hit
    /// testing resolves clicks and drags separately, so a drag region merely layered UNDERNEATH the
    /// action row still wins the drag. Only geometry excludes it.
    #[test]
    fn the_action_row_is_not_a_drag_handle() {
        let at = on_the_affirmative_button();

        let mut control = Driven::new(sign_screen());
        control.press_and_drag(on_the_header());
        assert!(
            control.asked_the_os_to_move_it(),
            "the control gesture did not start a move, so this test cannot tell a protected action \
             row from a window that simply never drags"
        );

        let mut aimed = Driven::new(sign_screen());
        aimed.click(at);
        assert_eq!(
            aimed.recorded(),
            Some(WindowIntent::Approve),
            "the action-row coordinate {at:?} is not on the affirmative control, so any assertion \
             about dragging it proves nothing"
        );

        let mut dragged = Driven::new(sign_screen());
        dragged.press_and_drag(at);
        assert!(
            !dragged.asked_the_os_to_move_it(),
            "pressing the affirmative control and moving started a WINDOW DRAG: the button travels \
             out from under a cursor already committed to pressing it"
        );
    }

    /// **The theme toggle is not a drag handle either**, and it still works.
    ///
    /// Same THREE-sided shape as the action row, and all three halves are needed. Without the
    /// header control this test passed on a build where `StartDrag` was never sent at all — measured,
    /// not supposed — because "the toggle did not start a drag" is trivially true when nothing does.
    /// Without the click, the coordinate could be sitting in empty chrome.
    #[test]
    fn the_theme_toggle_is_not_a_drag_handle() {
        let at = on_the_theme_toggle();

        let mut control = Driven::new(sign_screen());
        control.press_and_drag(on_the_header());
        assert!(
            control.asked_the_os_to_move_it(),
            "the control gesture did not start a move, so this test cannot tell a protected toggle \
             from a window that simply never drags"
        );

        let mut clicked = Driven::new(sign_screen());
        let before = clicked.app.theme;
        clicked.click(at);
        assert_ne!(
            clicked.app.theme, before,
            "the toggle coordinate {at:?} did not flip the theme, so it is not on the toggle"
        );

        let mut dragged = Driven::new(sign_screen());
        dragged.press_and_drag(at);
        assert!(
            !dragged.asked_the_os_to_move_it(),
            "dragging the theme toggle moved the window instead of leaving the control alone"
        );
    }

    /// **Escape still refuses after the window has been moved.**
    ///
    /// The window is undecorated, so Escape is the escape hatch (`professional-ui`, HARD RULE 1) and
    /// dig_ecosystem#2079 already established there is no titlebar X behind it. A gesture that left
    /// the app in a dragging state and swallowed the keystroke would take the only way out away.
    #[test]
    fn escape_still_refuses_after_a_drag() {
        let mut window = Driven::new(sign_screen());
        window.press_and_drag(on_the_header());
        assert!(window.asked_the_os_to_move_it(), "the window never moved");
        assert_eq!(
            window.recorded(),
            None,
            "the move answered the prompt by itself"
        );

        window.press_key(Key::Escape);
        assert_eq!(
            window.recorded(),
            Some(WindowIntent::Deny),
            "Escape did not refuse the prompt after it had been dragged"
        );
    }

    /// **Moving the window cannot answer it.** The gesture sends viewport commands and nothing else.
    ///
    /// Checked over the full set of drag targets, because the failure would be one region wiring a
    /// press into [`PromptApp::finish`] while the others stayed clean.
    ///
    /// The header iteration is also the control: at least one of these gestures must genuinely reach
    /// the window manager, or "no answer was recorded" is a statement about a window that did nothing
    /// at all.
    #[test]
    fn dragging_never_answers_the_prompt() {
        let mut control = Driven::new(sign_screen());
        control.press_and_drag(on_the_header());
        assert!(
            control.asked_the_os_to_move_it(),
            "no gesture in this test actually dragged anything"
        );

        for at in [
            on_the_header(),
            on_the_affirmative_button(),
            on_the_theme_toggle(),
        ] {
            let mut window = Driven::new(sign_screen());
            window.press_and_drag(at);
            assert_eq!(
                window.recorded(),
                None,
                "a drag beginning at {at:?} recorded an answer nobody gave"
            );
        }
    }

    /// **The launcher bar is deliberately NOT draggable**, and the same gesture on a dialog is.
    ///
    /// The bar places itself high on its monitor and dismisses itself the moment it loses focus. An
    /// OS-driven move that blurs it would make it disappear mid-gesture, and that is a claim about a
    /// real compositor rather than something this harness can settle — so the scope is dialogs, on
    /// purpose, and the pairing here is what stops that reading as an accident.
    #[test]
    fn only_a_dialog_is_draggable() {
        let mut dialog = Driven::new(sign_screen());
        dialog.press_and_drag(on_the_header());
        assert!(
            dialog.asked_the_os_to_move_it(),
            "a dialog must be draggable — that is the whole feature"
        );

        let mut bar = Driven::with(bar_screen(), true);
        bar.press_and_drag(on_the_header());
        assert!(
            !bar.asked_the_os_to_move_it(),
            "the launcher bar started an OS move; it dismisses itself on blur and this was scoped out"
        );
    }

    /// **A drag that ENDS on the affirmative control does not press it.**
    ///
    /// Sharper than "the action row is not a drag handle", and a genuinely different failure: the
    /// header strip can be perfectly bounded and the gesture still approve a transaction, because a
    /// drag finishes with a pointer-UP wherever the user stopped — very often over a button, since
    /// the buttons are where the eye is. A control that treats that release as a click turns "I moved
    /// the window aside to read what is underneath it" into "I signed".
    ///
    /// Both endings are checked, because only the pair distinguishes a safe release from a gesture
    /// that never reached the button at all: releasing on **Sign** must NOT approve, and a plain
    /// click at the very same point must.
    #[test]
    fn a_drag_that_ends_on_the_affirmative_control_does_not_press_it() {
        let on_sign = on_the_affirmative_button();

        let mut proof = Driven::new(sign_screen());
        proof.click(on_sign);
        assert_eq!(
            proof.recorded(),
            Some(WindowIntent::Approve),
            "the release point {on_sign:?} is not on the affirmative control, so ending a drag \
             there proves nothing"
        );

        let mut dragged = Driven::new(sign_screen());
        dragged.drag_from_to(on_the_header(), on_sign);
        assert!(
            dragged.asked_the_os_to_move_it(),
            "the gesture never became a window move, so this is not the case under test"
        );
        assert_eq!(
            dragged.recorded(),
            None,
            "letting go of a window drag over the affirmative control APPROVED the prompt — the \
             user moved a window and signed a transaction"
        );
    }

    /// **A consent dialog still cannot be dismissed by losing focus, dragged or not.**
    ///
    /// `dismiss_on_blur` is true for the launcher bar alone, and that asymmetry is what stops an
    /// attacker who can steal the foreground from making a consent window disappear. A drag
    /// implementation is exactly the kind of change that could weaken it by accident, since an
    /// OS-driven move plausibly blurs the window on the way.
    ///
    /// The bar is the control: the same blur MUST dismiss it, or this test would pass just as well on
    /// a build where blur handling had stopped working altogether.
    #[test]
    fn a_dragged_dialog_still_never_dismisses_on_blur() {
        let mut dialog = Driven::new(sign_screen());
        dialog.press_and_drag(on_the_header());
        dialog.frame_focused(Vec::new(), Some(true));
        dialog.frame_focused(Vec::new(), Some(false));
        assert_eq!(
            dialog.recorded(),
            None,
            "a consent dialog dismissed itself when it lost focus after being dragged"
        );

        let mut bar = Driven::with(bar_screen(), true);
        bar.frame_focused(Vec::new(), Some(true));
        bar.frame_focused(Vec::new(), Some(false));
        assert!(
            bar.sink.lock().expect("the sink is not poisoned").is_some(),
            "the launcher bar did not dismiss on blur either, so the dialog's silence above says \
             nothing about dismiss-on-blur"
        );
    }

    /// **Dragging never computes a position itself.**
    ///
    /// The move is delegated whole to the window manager, so the frame must emit `StartDrag` and NO
    /// [`egui::ViewportCommand::OuterPosition`]. This is not style. `egui` reports a window's
    /// `monitor_size` but not that monitor's ORIGIN, so any position arithmetic written here is
    /// implicitly about the primary display — and would drag a window that the user had just moved
    /// onto a second monitor straight back onto the first. Pinning the absence keeps a future
    /// "clamp it into view" from silently breaking the multi-monitor behaviour the OS gesture is
    /// being used FOR. See [`PromptApp::drag_by_the_header`].
    #[test]
    fn dragging_delegates_the_position_and_never_computes_one() {
        let mut window = Driven::new(sign_screen());
        window.drag_from_to(on_the_header(), on_the_affirmative_button());
        assert!(
            window.asked_the_os_to_move_it(),
            "the gesture never asked the platform to move the window"
        );
        let hand_rolled: Vec<_> = window
            .commands
            .iter()
            .filter(|cmd| matches!(cmd, egui::ViewportCommand::OuterPosition(_)))
            .collect();
        assert!(
            hand_rolled.is_empty(),
            "the drag positioned the window itself ({hand_rolled:?}); that arithmetic has no \
             monitor origin to work from and moves a second-monitor window back to the primary"
        );
    }

    /// **A move only begins once the gesture can no longer be a click.**
    ///
    /// This is the guarantee the whole feature rests on, and it is STRUCTURAL rather than
    /// geometric: because the handle senses click as well as drag, `egui` withholds the drag until
    /// `is_decidedly_dragging` holds, which requires the gesture to have already failed the click
    /// test. Whatever release arrives after `StartDrag`, wherever it lands, cannot resolve as a
    /// click — including the case geometry alone would not cover, of pressing the header, holding
    /// perfectly still, and letting go on **Sign**.
    ///
    /// The observable that distinguishes it: a plain PRESS, with no movement and no dwell, must not
    /// move the window, because that press could still become a click. A `Sense::drag()` handle
    /// reports itself dragged on the press frame and fails exactly here — which is the mutation this
    /// exists for, and which the whole rest of the suite survived.
    ///
    /// The second half is the control: once the pointer does move, the move must happen.
    #[test]
    fn a_move_only_begins_once_the_gesture_can_no_longer_be_a_click() {
        let mut window = Driven::new(sign_screen());

        window.press_only(on_the_header());
        assert!(
            !window.asked_the_os_to_move_it(),
            "a bare press on the header started a window move while the gesture could still \
             resolve to a click, so one gesture can be both a click and a move"
        );

        window.frame(vec![egui::Event::PointerMoved(
            on_the_header() + Vec2::new(120.0, 90.0),
        )]);
        assert!(
            window.asked_the_os_to_move_it(),
            "moving the pointer never started the drag, so the assertion above is about a handle \
             that does not work at all"
        );
    }

    /// **The drag strip senses click, and is not a tab stop.**
    ///
    /// Both halves of [`DRAG_HANDLE_SENSE`] are deliberate and neither is what the two obvious
    /// constructors give, so both are pinned:
    ///
    /// * `CLICK` is what makes `egui` withhold the drag until the gesture cannot be a click — the
    ///   structural guarantee above. `Sense::drag()` would drop it silently.
    /// * `FOCUSABLE` must be absent. The strip is registered before every other widget, so
    ///   `Sense::click_and_drag()` would make it the FIRST tab stop on a consent dialog: invisible,
    ///   unlabelled, no focus ring, on the surface whose keyboard navigation has to be unambiguous.
    #[test]
    fn the_drag_strip_senses_click_and_is_not_a_tab_stop() {
        assert!(
            DRAG_HANDLE_SENSE.senses_drag(),
            "the drag strip does not sense dragging"
        );
        assert!(
            DRAG_HANDLE_SENSE.senses_click(),
            "the drag strip stopped sensing clicks, which is what makes egui withhold the drag \
             until the gesture can no longer be a click; a finished move can now press a button"
        );
        assert!(
            !DRAG_HANDLE_SENSE.is_focusable(),
            "the drag strip became focusable, so it is an unlabelled ring-less first tab stop on a \
             consent dialog"
        );
    }

    /// **A drag with a non-primary button never moves the window.**
    ///
    /// A secondary press is the system-menu gesture, never a move. Letting it through would also set
    /// winit's dragging flag, which earns a synthetic LEFT release at the end of a gesture `egui`
    /// never saw a left press for — a release with no matching press is exactly the kind of unpaired
    /// input a consent surface should not be inventing.
    ///
    /// The primary button is the control, so this cannot pass on a handle that never drags.
    #[test]
    fn only_the_primary_button_moves_the_window() {
        let mut secondary = Driven::new(sign_screen());
        secondary.press_and_drag_with(on_the_header(), egui::PointerButton::Secondary);
        assert!(
            !secondary.asked_the_os_to_move_it(),
            "a secondary-button drag on the header moved the window"
        );

        let mut primary = Driven::new(sign_screen());
        primary.press_and_drag_with(on_the_header(), egui::PointerButton::Primary);
        assert!(
            primary.asked_the_os_to_move_it(),
            "the primary button did not move the window either, so the assertion above is about a \
             handle that never drags"
        );
    }

    /// **The drag strip can never reach the action row, at any window height.**
    ///
    /// The strip is chrome-height and the action row is measured up from the bottom, so on a short
    /// enough window the two would overlap and a press on the strip would land on a consent button.
    /// Nothing produces such a window today, but that rests on three separate coincidences
    /// ([`MIN_HEIGHT`], the viewport's `min_inner_size`, and `fit_to_content` asking to grow back),
    /// and a consent property should not.
    ///
    /// Pinned from BOTH sides of the bound, because a one-sided check confirms only itself:
    ///
    /// * at and above `CHROME_HEIGHT + ACTION_ROW` the strip must keep its FULL height, so the clamp
    ///   cannot be quietly stealing room from every real window;
    /// * below it the strip must not reach the row. It collapses to [`Rect::NOTHING`], which is the
    ///   safe direction: the window simply stops being draggable rather than becoming dangerous.
    ///   Emptiness is asserted as "cannot contain a press", not as a height of zero — a flattened
    ///   rect still contains the points along its own edge, and that was the first shape this took.
    #[test]
    fn the_drag_strip_never_reaches_the_action_row_at_any_height() {
        let at_bound = CHROME_HEIGHT + ACTION_ROW;
        for height in [at_bound, at_bound + 0.5, MIN_HEIGHT, HEIGHT, MAX_HEIGHT] {
            let full = Rect::from_min_size(egui::Pos2::ZERO, Vec2::new(WIDTH, height));
            let strip = PromptApp::drag_region(full);
            assert!(
                (strip.height() - CHROME_HEIGHT).abs() < 0.001,
                "at {height} px the strip is {} px tall, not the full {CHROME_HEIGHT}; the clamp is \
                 stealing room from a window that had none to spare",
                strip.height()
            );
        }

        for height in [at_bound - 0.5, 100.0, 60.0, CHROME_HEIGHT, 10.0, 0.0] {
            let full = Rect::from_min_size(egui::Pos2::ZERO, Vec2::new(WIDTH, height));
            let strip = PromptApp::drag_region(full);
            let action_row_top = full.bottom() - ACTION_ROW;
            let reaches_the_row = strip.bottom() > action_row_top + 0.001;
            // A press anywhere in the row must miss the strip. Asserted against `contains` rather
            // than against a height of zero, because a FLATTENED rect still contains its own edge.
            let takes_a_press_in_the_row = [
                full.center_bottom(),
                egui::Pos2::new(full.left() + 1.0, action_row_top.max(full.top()) + 1.0),
                egui::Pos2::new(full.left(), full.top()),
            ]
            .into_iter()
            .any(|p| strip.contains(p) && reaches_the_row);
            assert!(
                !takes_a_press_in_the_row,
                "at {height} px the strip {strip:?} reaches the action row at {action_row_top} and \
                 still takes a press: a press on the drag strip lands on a consent button"
            );
        }
    }

    /// **The window options a drag runs against stay exactly as they were.**
    ///
    /// Every one of these is load-bearing for a window that can now MOVE:
    ///
    /// * `transparent` unset — a transparent frameless surface on Windows was measured losing its
    ///   content on a move and never recompositing (dig_ecosystem#2038), and a move is now the
    ///   primary interaction;
    /// * `always_on_top` — a consent window that can be dragged behind another is one an attacker
    ///   can hide;
    /// * `active` — it must still take the foreground;
    /// * `decorations` off — the card is drawn edge to edge, and the header IS the titlebar now.
    ///
    /// Pinned here rather than trusted to review: each is one word in a builder chain, and the
    /// natural way to add "native window behaviour" is to reach for exactly these.
    #[test]
    fn a_draggable_prompt_is_still_opaque_focused_and_on_top() {
        let viewport = native_options("DIG", Chrome::Dialog).viewport;
        assert_ne!(
            viewport.transparent,
            Some(true),
            "the prompt surface became transparent; a frameless transparent window loses its \
             content on a move on Windows (#2038), and moving is now the point"
        );
        assert_eq!(
            viewport.window_level,
            Some(egui::WindowLevel::AlwaysOnTop),
            "a consent window that is not always-on-top can be dragged behind another"
        );
        assert_eq!(
            viewport.active,
            Some(true),
            "the prompt no longer takes focus"
        );
        assert_eq!(
            viewport.decorations,
            Some(false),
            "the prompt grew OS decorations; the card is drawn edge to edge"
        );
    }
}
