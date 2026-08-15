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
//! # Being SEEN, and being the only thing that responds — two rules, not one
//!
//! The old child window was `always_on_top` and asked for the keyboard on its first frame, and those
//! were claims against the **desktop**: a non-topmost prompt was buried outright, and one raised by a
//! background agent opened behind whatever the person was actually using (dig_ecosystem#2079). An
//! in-window modal cannot be buried by the shell — it *is* the shell — but the shell can be behind a
//! browser, so **[`ShellApp::raise_for_the_prompt`] brings the window forward on admission**. Without
//! it a dapp's signature request drew into a window nobody could see and refused itself on the
//! deadline.
//!
//! Being visible is not the same as being the only thing that answers. The modal can still be
//! clicked *through*, which is the burial defect wearing different clothes. Three things prevent it,
//! and each is asserted:
//!
//! * The panes are drawn non-interactive while a prompt is up, and the chrome draws no controls at
//!   all ([`ShellApp::paint_shell`]).
//! * The scrim is a full-window widget that SENSES clicks and drags, so anything under it that was
//!   still listening gets nothing ([`ShellApp::scrim`]).
//! * The modal is painted in a layer strictly above the scrim, so it — and only it — is reachable,
//!   which is asserted by CLICKING its action button rather than by reading a layer back: egui's
//!   `read_response` is layer-blind and cannot tell a blocker above the panes from one below them.
//!
//! The modal also has no drag handle ([`super::PromptApp::drag_by_the_header`]): the viewport a drag
//! would move is the app window, so grabbing a consent dialog's header would send the whole
//! application across the desktop — or snap it to an edge, since unlike a standalone prompt the shell
//! IS resizable.
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
use super::pane;
use super::panes::{self, Click};
use super::{
    install_fonts, set_vigil, unavailable, AppWindow, Chrome, Heartbeat, Job, Outcome, Overstay,
    PromptApp, Vigil, Work, CHROME_HEIGHT, FRAME_SILENCE,
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
pub(super) const SHELL_MIN: f32 = 480.0;

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
///
/// # What `watched` buys a window with no deadline
///
/// The shell is registered on [`super::Overstay::painting`], never on a deadline: it is forced shut
/// for having STOPPED PAINTING, and for nothing else. A person can leave it open all day. What it
/// cannot do is wedge — that would hold the one prompt thread and refuse every later consent prompt
/// for the life of the process (dig_ecosystem#2074).
///
/// Registered BEFORE `run_native` for the same reason [`super::draw_watched`] is: a loop that hangs
/// in GL context init never reaches the creator below, and a vigil that only began to exist there
/// would never see the hang at all.
///
/// `watched` is not optional — there is no way to ask for an unwatched window. See
/// [`super::serve_with`], which owns the slot and hands it to whatever draws.
pub(super) fn draw(
    shell: AppWindow,
    queue: &Receiver<Work>,
    watched: &Mutex<Option<Vigil>>,
) -> Option<Outcome> {
    let theme = shell.theme.read();
    let app = ShellApp::new(theme, shell.theme, shell.view, shell.act, shell.initial_tab);
    let run = watched_while_painting(watched, |beat| {
        let creator_beat = Arc::clone(&beat);
        eframe::run_native(
            "DIG",
            native_options(),
            Box::new(move |cc| {
                install_fonts(&cc.egui_ctx);
                // The SAME window, now with a context the watchdog can nudge — see
                // [`super::Overstay::is_the_same_window_as`], which is what keeps this from reading
                // as a fresh problem.
                set_vigil(
                    watched,
                    Some(cc.egui_ctx.clone()),
                    Overstay::painting(Arc::clone(&creator_beat), FRAME_SILENCE),
                );
                Ok(Box::new(Host {
                    app,
                    queue,
                    beat: Arc::clone(&beat),
                }))
            }),
        )
    });

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

/// Open the shell on `tab` at `size`, let it settle, read its framebuffer back into a PNG at `path`,
/// and close it. Returns the image's pixel dimensions.
///
/// # Why the gallery photographs itself
///
/// A screen capture cannot do this. GDI — `PrintWindow`, `BitBlt`, every screenshot tool built on
/// them — is blind to a hardware GL surface: it returns a black rectangle of exactly the right size,
/// which is worse than an error because the harness reports success and the file looks plausible
/// until somebody opens it. Reading the framebuffer with [`egui::ViewportCommand::Screenshot`] is
/// the only capture that sees what was actually drawn.
///
/// It is also the only capture that cannot photograph the wrong thing. Nothing is clicked, nothing
/// is dragged, and no window has to be in the foreground — so no capture can be of whatever happened
/// to be on top, which is how a committed screenshot labelled "Cache" turned out to be the Status
/// tab (dig_ecosystem#2326).
///
/// `view` is the snapshot the model and the facts are both built from, and `size` is in LOGICAL
/// pixels. The scale is PINNED rather than taken from the host, so the gallery is the same picture
/// on every machine: at the host's own DPI these files would differ in size between two laptops and
/// a screenshot set whose dimensions depend on who ran it cannot be diffed between two versions of
/// the window.
///
/// Returns an error string when this host cannot open a window at all.
pub fn photograph(
    theme: Theme,
    tab: TabId,
    size: Vec2,
    view: Arc<dyn Fn() -> crate::tray_menu::TrayView + Send + Sync>,
    path: &std::path::Path,
) -> Result<(usize, usize), String> {
    // The shell reads its theme from a store and its toggle writes back to one. A scratch store
    // keeps both away from the person's own preference — a gallery has no business changing settings
    // — and it is per-process, so two captures running at once cannot read each other's theme.
    let scratch = std::env::temp_dir().join(format!("dig-gallery-{}", std::process::id()));
    let store = ThemeChoice::in_brand_dir(&scratch);
    store
        .write(theme)
        .map_err(|e| format!("the gallery theme could not be stored: {e}"))?;

    // The shell hosts prompts from this queue. The gallery raises none, so it holds the only sender
    // and never sends: the receiver must simply stay open, because a disconnected queue is a
    // different state from an empty one.
    let (_keep_open, queue) = std::sync::mpsc::channel();
    let app = ShellApp::new(theme, store, view, Arc::new(|_| {}), Some(tab));

    let recorded = Arc::new(Mutex::new(None));
    let size_slot = Arc::clone(&recorded);
    let target = path.to_path_buf();
    let mut options = native_options();
    options.viewport = options.viewport.with_inner_size(size);
    // eframe restores the LAST run's geometry in preference to the size asked for, so without this
    // every capture after the first came out at the first one's size — two files claiming two widths
    // and holding one picture.
    options.persist_window = false;

    eframe::run_native(
        "DIG",
        options,
        Box::new(move |cc| {
            install_fonts(&cc.egui_ctx);
            Ok(Box::new(Photographer {
                app,
                queue,
                wanted: size,
                settled_for: None,
                frames: 0,
                path: target,
                size: size_slot,
            }))
        }),
    )
    .map_err(|e| format!("this host cannot open the DIG app window: {e}"))?;
    let _ = std::fs::remove_dir_all(&scratch);

    let answer = *recorded.lock().map_err(|_| "the size slot was poisoned")?;
    answer.ok_or_else(|| "the window closed before its framebuffer was read".to_string())
}

/// How pixel-dense a gallery capture is, independent of the display it was taken on.
const GALLERY_SCALE: f32 = 2.0;

/// How many frames to draw after the window has reached its asked-for size, before reading back.
///
/// egui lays out on the frame AFTER the one that measured, and fonts land a frame later still, so an
/// early read photographs a half-built window. Generous on purpose: the cost is milliseconds.
const SETTLE_FRAMES: u32 = 12;

/// How many frames to keep asking for a size before concluding the window manager will not grant it.
const GIVE_UP_FRAMES: u32 = 240;

/// Draws the real shell, then photographs it.
struct Photographer {
    app: ShellApp,
    queue: Receiver<Work>,
    /// The size the CAPTURE is of, in the points the shell lays itself out in.
    ///
    /// Not the display's points. Pinning `pixels_per_point` to [`GALLERY_SCALE`] decouples the two,
    /// and a viewport command speaks in the shell's — which is what makes the file name and the
    /// picture the same claim on every host. Asked for in DISPLAY points instead, a 480 file taken on
    /// a 2.5x screen would hold a 600-point layout, and every narrow-width judgement made from it
    /// would be about a layout no user sees.
    wanted: Vec2,
    /// Frames drawn since the window reached [`Self::wanted`]; `None` until it has.
    settled_for: Option<u32>,
    /// Frames drawn in total, so a size the window manager refuses ends the run instead of looping.
    frames: u32,
    path: std::path::PathBuf,
    size: Arc<Mutex<Option<(usize, usize)>>>,
}

impl eframe::App for Photographer {
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
        ctx.set_pixels_per_point(GALLERY_SCALE);
        // The SHIPPING paint path, not a re-creation of it. A gallery that drew its own approximation
        // of the shell would photograph the approximation.
        self.app.frame(ctx, &self.queue);

        // The window is asked for its size every frame until it HAS it, and the settle count only
        // starts once it does. A window manager clamps a request it cannot honour — to the work area,
        // or to the shell's own minimum — and counting frames from the request instead would
        // photograph whatever the window was mid-resize.
        let reached = ctx.screen_rect().size();
        let on_size = (reached - self.wanted).abs().max_elem() < 1.0;
        match (on_size, self.settled_for) {
            (false, _) => {
                self.settled_for = None;
                ctx.send_viewport_cmd(egui::ViewportCommand::InnerSize(self.wanted));
            }
            (true, Some(frames)) => self.settled_for = Some(frames + 1),
            (true, None) => self.settled_for = Some(0),
        }
        if self.settled_for == Some(SETTLE_FRAMES) {
            ctx.send_viewport_cmd(egui::ViewportCommand::Screenshot(egui::UserData::default()));
        }
        self.frames += 1;
        // A size the window manager will not grant — taller than the work area, narrower than the
        // shell's floor — would otherwise loop here forever asking for it. Leaving WITHOUT a file is
        // the honest outcome: `photograph` reports it, and the alternative is a picture whose name
        // describes a size it is not.
        if self.frames > GIVE_UP_FRAMES && self.settled_for.is_none() {
            tracing::error!(
                wanted = ?self.wanted,
                reached = ?reached,
                "the window manager would not grant the size this capture asked for"
            );
            ctx.send_viewport_cmd(egui::ViewportCommand::Close);
        }
        let shot = ctx.input(|i| {
            i.events.iter().find_map(|e| match e {
                egui::Event::Screenshot { image, .. } => Some(image.clone()),
                _ => None,
            })
        });
        let Some(image) = shot else {
            return;
        };
        let (width, height) = (image.width(), image.height());
        // RGB, not RGBA: the window is opaque, so an alpha channel is a quarter of the file spent
        // storing 0xFF. `Best` on top, because these frames are large flat fields of brand colour
        // that deflate very well and the gallery is committed.
        let bytes: Vec<u8> = image
            .pixels
            .iter()
            .flat_map(|p| [p.r(), p.g(), p.b()])
            .collect();
        if let Err(err) = write_png(&self.path, width, height, &bytes) {
            tracing::error!(%err, path = %self.path.display(), "the gallery capture was not written");
        } else if let Ok(mut slot) = self.size.lock() {
            *slot = Some((width, height));
        }
        ctx.send_viewport_cmd(egui::ViewportCommand::Close);
    }
}

/// Encode `bytes` — tightly packed RGB — as a PNG at `path`.
fn write_png(
    path: &std::path::Path,
    width: usize,
    height: usize,
    bytes: &[u8],
) -> std::io::Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let file = std::io::BufWriter::new(std::fs::File::create(path)?);
    let mut encoder = png::Encoder::new(file, width as u32, height as u32);
    encoder.set_color(png::ColorType::Rgb);
    encoder.set_compression(png::Compression::Best);
    encoder.set_depth(png::BitDepth::Eight);
    encoder
        .write_header()
        .and_then(|mut writer| writer.write_image_data(bytes))
        .map_err(std::io::Error::other)
}

/// Run `paint` with this window registered for wedge-watching, and hand it the heartbeat to stamp.
///
/// # Why the registration is a wrapper rather than two lines in [`draw`]
///
/// It keeps creating the heartbeat and registering it in ONE place, so the two cannot drift into a
/// window that stamps a heartbeat nobody watches.
///
/// **It is not what stops the watching being removed, and an earlier version of this comment claimed
/// it was.** The claim was that [`Host`] cannot be built without a heartbeat, so a deletion would not
/// compile — but the heartbeat arrives as this function's own closure parameter, minted here however
/// the caller is written, so deleting the registration compiled cleanly and left the whole suite
/// green. What actually holds it is upstream in [`super::serve_with`]: the watchdog slot is not
/// optional and is HANDED to the drawer rather than captured by it, so there is no "unwatched" value
/// to pass and ignoring the parameter fails the `-D warnings` gate.
///
/// Registered BEFORE `paint`, with no context, for [`super::draw_watched`]'s reason: a `run_native`
/// that hangs in GL context init never reaches the creator, and a vigil created there would never
/// see it.
///
/// **Unregistering is deliberately NOT done here.** [`super::serve_shell`] clears it, from outside
/// the panic guard, so a window that left by panicking is taken off the watchdog's list exactly as
/// one that closed normally.
pub(super) fn watched_while_painting<T>(
    watched: &Mutex<Option<Vigil>>,
    paint: impl FnOnce(Arc<Heartbeat>) -> T,
) -> T {
    let beat = Arc::new(Heartbeat::new());
    set_vigil(
        watched,
        None,
        Overstay::painting(Arc::clone(&beat), FRAME_SILENCE),
    );
    paint(beat)
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
/// The DIG mark, embedded so the window's own icon is the brand rather than the toolkit's default.
///
/// Without this eframe supplies its own placeholder — a letter "e" — which is what the window
/// actually showed in the corner and in the taskbar (dig_ecosystem#2340). The 64px source is the
/// same file the tray uses, so the two surfaces cannot drift into showing different marks.
const WINDOW_MARK: &[u8] = include_bytes!("../../../../assets/mark-64.png");

/// Decode [`WINDOW_MARK`] into the RGBA an icon wants, or `None` if it will not decode.
///
/// **Fallible on purpose, exactly as the tray's decode is.** A corrupt asset should cost the window
/// its picture and nothing else — never the user's whole consent surface — so every failure here
/// returns `None` and the window opens with the toolkit default instead of not opening.
fn window_icon() -> Option<egui::IconData> {
    let mut reader = png::Decoder::new(WINDOW_MARK).read_info().ok()?;
    let info = reader.info();
    // Only the one shape the checked-in asset has. A PNG in another colour type or bit depth would
    // need resampling, and silently mis-decoding a brand mark is worse than showing no mark.
    if info.color_type != png::ColorType::Rgba || info.bit_depth != png::BitDepth::Eight {
        return None;
    }
    let (width, height) = (info.width, info.height);
    let mut rgba = vec![0; reader.output_buffer_size()];
    let frame = reader.next_frame(&mut rgba).ok()?;
    rgba.truncate(frame.buffer_size());
    Some(egui::IconData {
        rgba,
        width,
        height,
    })
}

fn native_options() -> eframe::NativeOptions {
    let mut viewport = egui::ViewportBuilder::default();
    // Attached only if it decoded, for the reason `window_icon` states.
    if let Some(icon) = window_icon() {
        viewport = viewport.with_icon(icon);
    }
    eframe::NativeOptions {
        viewport: viewport
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
    /// Stamped at the top of every frame, so a watchdog on another thread can tell a window
    /// somebody is using from a loop that has died — see [`super::Overstay::Painting`].
    beat: Arc<Heartbeat>,
}

impl Host<'_> {
    /// Stamp the heartbeat, then draw one frame.
    ///
    /// Split out of [`eframe::App::update`] for the reason [`ShellApp::frame`] is split out of this
    /// one: an `eframe::Frame` cannot be built on a host with no window, so a rule stated only
    /// inside `update` is a rule no test can reach. The rule here is that a frame which ran always
    /// says so.
    ///
    /// The stamp goes FIRST and unconditionally. It is the evidence that this loop is alive, so it
    /// must not sit behind any part of the frame that could itself be the thing that wedges. Placed
    /// after the drawing it would report silence for a hang in the drawing — which is honest — and
    /// equally for a hang in a MODAL the person is reading, which is not the same thing at all.
    /// Stamped on entry it says exactly one thing: the platform called us.
    fn paint(&mut self, ctx: &egui::Context) {
        self.beat.beat();
        self.app.frame(ctx, self.queue);
    }
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
        self.paint(ctx);
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
    /// How this prompt is FRAMED — a consent dialog, or the Alt+Space URN launcher.
    ///
    /// Decides three things a bar and a dialog do not share: its size, where in the window it sits,
    /// and whether clicking away from it dismisses it. Copied off the [`Job`] rather than reached
    /// through [`ActivePrompt::app`] so the shell never has to reach into the prompt's own state to
    /// lay it out.
    chrome: Chrome,
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
        initial_tab: Option<TabId>,
    ) -> Self {
        Self {
            theme,
            theme_store,
            prompt: None,
            closing: false,
            view,
            act,
            // A caller that names no tab gets the shipping behaviour; only a gallery names one.
            selected: initial_tab.unwrap_or(FIRST_TAB),
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

        // The Settings pane operates the theme (dig_ecosystem#2997) and the shell owns it, so a
        // choice made on the last frame is applied at the top of this one — before anything reads
        // `self.theme` — and republished so the chooser shows what is actually being painted.
        self.apply_a_chosen_theme(ctx);

        // Admitted BEFORE the shell is drawn so that the scrim and the pane agree with each other
        // within a single frame: a prompt admitted afterwards would show for one frame over an
        // unscrimmed, live-looking shell.
        self.admit_one_prompt(ctx, queue);

        let t = self.theme.tokens();
        let prompt_is_up = self.prompt.is_some();
        self.paint_shell(ctx, &t, prompt_is_up);
        self.show_prompt(ctx, ctx.screen_rect());
        self.dismiss_a_bar_clicked_away_from(ctx);
    }

    /// Take up a theme the Settings pane recorded, persist it, and say which one is in force.
    ///
    /// # Why the shell writes and the pane does not
    ///
    /// There is one [`ThemeChoice`] and it belongs to the shell, which is what makes a stored theme
    /// and a painted theme incapable of disagreeing. A pane that wrote the file itself would be a
    /// second writer of the same preference, and the first divergence would be a window painting
    /// one theme while the file said the other — with the file winning at the next restart, so the
    /// person's choice would appear to take and then silently revert.
    ///
    /// A failed WRITE does not stop the switch: the person asked for this theme and the app can
    /// honour it for this session even when it cannot remember it. The failure is logged rather
    /// than surfaced because the loss is a preference, not a fact about their money.
    fn apply_a_chosen_theme(&mut self, ctx: &egui::Context) {
        if let Some(chosen) = pane::settings::appearance::Exchange::take_request(ctx) {
            if chosen != self.theme {
                self.theme = chosen;
                if let Err(err) = self.theme_store.write(self.theme) {
                    tracing::debug!(%err, "could not persist the app window theme preference");
                }
            }
        }
        pane::settings::appearance::Exchange::publish(ctx, self.theme);
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
            // A prompt that was really opened brings the window forward with it. See
            // [`ShellApp::raise_for`] — this is the consent surface's only claim on the desktop, and
            // it is why a stale job, which opens nothing, must not reach it.
            Ok(Work::Prompt(job)) => {
                if self.open(job) {
                    self.raise_for_the_prompt(ctx);
                }
            }
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
    ///
    /// Reports whether a prompt was actually opened, because a refused job raised no surface and
    /// must not bring the window forward for one ([`ShellApp::raise_for_the_prompt`]).
    fn open(&mut self, job: Job) -> bool {
        if Instant::now() >= job.over_by {
            tracing::warn!(
                prompt = %job.screen.title,
                "a DIG prompt reached the app window after its caller had given up; refused \
                 without opening a window"
            );
            let _ = job.reply.send(unavailable(job.wants_text));
            return false;
        }

        let sink = Arc::new(Mutex::new(None));
        let reply = job.reply.clone();
        let wants_text = job.wants_text;
        let title = job.screen.title.clone();
        let theme_store = job.theme.clone();
        let chrome = job.screen.chrome;
        tracing::debug!(prompt = %title, wants_text, "drawing a DIG prompt inside the app window");
        self.prompt = Some(ActivePrompt {
            app: PromptApp::in_window(job, theme_store, Arc::clone(&sink)),
            _on_screen: crate::confirm::surface::Raised::now(),
            chrome,
            height: super::opening_size(chrome).1,
            sink,
            reply,
            wants_text,
            title,
        });
        true
    }

    /// Bring the app window forward, because a consent prompt has just appeared inside it.
    ///
    /// # The defect this closes (dig_ecosystem#2270, gate finding A1)
    ///
    /// A standalone prompt is `always_on_top` and asks for the keyboard on its first frame
    /// ([`super::PromptApp::claim_the_keyboard`]) — both of which are claims against the DESKTOP,
    /// not against the shell. Moving the prompt inside the app window keeps it from being buried BY
    /// the shell and silently drops every guarantee about being seen at all: with the window open
    /// but behind a browser, a dapp's signature request drew into a window nobody could see, held
    /// the consent surface up for two minutes, and refused on the timeout. That is dig_ecosystem#2079
    /// re-created one layer in.
    ///
    /// # Why every admitted prompt raises, rather than only an externally-originated one
    ///
    /// Keying this on the request's ORIGIN was considered and is the weaker rule. It cannot be read
    /// where it would be needed — a row clicked in this window and a tray click go to the SAME
    /// worker (`dig-app`'s `WindowSeam`), which is what reaches [`super::ask`], so the two are
    /// indistinguishable at the point a [`Job`] is built without threading a new field across both
    /// crates. And it would buy a WORSE guarantee: a person who clicks *Show my recovery phrase…*
    /// and then switches to another window would get exactly the invisible prompt described above,
    /// with the reasoning saying that was fine.
    ///
    /// Raising unconditionally is also the honest parity with the surface this replaces: a
    /// standalone prompt asks for focus once, on its first frame, whoever asked for it. This asks
    /// once, on admission — never per frame, which would fight the user for the foreground for the
    /// life of the prompt.
    ///
    /// `Focus` rather than a `WindowLevel` re-assert: the latter was measured to lift z-order while
    /// leaving the keyboard behind, which is a consent surface the person can read and cannot answer.
    /// Like every focus request this is a REQUEST — Windows' foreground lock may refuse it — and the
    /// prompt's own deadline still answers for the absent human either way.
    fn raise_for_the_prompt(&self, ctx: &egui::Context) {
        ctx.send_viewport_cmd(egui::ViewportCommand::Focus);
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
        let at = modal_rect(full, active.chrome, active.height);

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
        // Only a dialog grows to its content; a bar is a fixed short height, exactly as
        // `PromptApp::frame` treats it.
        if !active.chrome.is_bar() {
            active.height = modal_height(full, at, content_bottom);
        }

        if active.app.answered {
            // Taken out of the field FIRST: this is the dismissal.
            if let Some(answered) = self.prompt.take() {
                answered.settle();
            }
        }
    }

    /// Clicking off the URN launcher, onto the dimmed window, closes it — and closes NOTHING else.
    ///
    /// # Why the scrim is what "away" means here
    ///
    /// A Spotlight-style launcher is dismissed by clicking away from it, which standalone means its
    /// own window lost focus ([`super::PromptApp::dismiss_on_blur`]). In-window the only focus there
    /// is belongs to the shell, so blur would mean *the person switched to their browser* — a
    /// different gesture with a different meaning. The scrim is the exact counterpart: it IS the rest
    /// of the window, and clicking it is clicking away.
    ///
    /// # Why no consent surface can reach this
    ///
    /// Gated on [`super::Chrome::dismiss_on_blur`], which is `false` for every dialog — the same flag
    /// that has always kept a consent window from vanishing because somebody clicked elsewhere. The
    /// answer it produces is [`super::PromptApp::finish`]'s refusal, so even if that flag were ever
    /// wrong the outcome would be a denial, never an approval.
    ///
    /// Read from the scrim's own blocker rather than from a bare coordinate, so this cannot fire on a
    /// click that landed on the modal itself.
    fn dismiss_a_bar_clicked_away_from(&mut self, ctx: &egui::Context) {
        let Some(active) = self.prompt.as_mut() else {
            return;
        };
        if !active.chrome.dismiss_on_blur() {
            return;
        }
        let clicked_away = ctx
            .read_response(scrim_blocker())
            .is_some_and(|scrim| scrim.clicked());
        if !clicked_away {
            return;
        }
        active.app.refuse_from_the_host(ctx);
        if active.app.answered {
            if let Some(answered) = self.prompt.take() {
                answered.settle();
            }
        }
    }

    /// Paint the shell itself: chrome, panes, and — while a prompt is up — the scrim and the pill.
    fn paint_shell(&mut self, ctx: &egui::Context, t: &Tokens, prompt_is_up: bool) {
        let screen = ctx.screen_rect();
        let view = (self.view)();
        let model = window_model::build(&view);
        // The same snapshot, projected twice: the model decides which verbs exist, and the facts are
        // the readings a pane displays beside them. One call, so the two cannot describe different
        // instants.
        let facts = super::pane::facts::PaneFacts::of_tray(&view);
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
                // The strip is drawn BEFORE the body and its height is subtracted from it, rather
                // than painted over the top: a band laid across a pane that still believes it owns
                // the full rectangle hides the pane's first card at every width.
                let under_chrome = Rect::from_min_max(
                    egui::Pos2::new(screen.left(), screen.top() + CHROME_HEIGHT),
                    screen.right_bottom(),
                );
                let strip = super::header::draw(ui, under_chrome, t, &facts);
                let body = Rect::from_min_max(
                    egui::Pos2::new(under_chrome.left(), under_chrome.top() + strip),
                    under_chrome.right_bottom(),
                );
                clicked = panes::draw(ui, body, t, &model, &facts, self.selected, !prompt_is_up);
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

    /// The 44 px header: brand mark, title, the three window controls, the theme toggle — and the
    /// drag strip.
    ///
    /// # Why this window draws its own Minimize and Maximize (dig_ecosystem#2569)
    ///
    /// The window is undecorated ([`native_options`]), so the operating system contributes no
    /// controls at all: everything a person can do to this window has to be drawn here or it does
    /// not exist. It shipped with only Close, which meant the window could not be minimised or
    /// maximised by any means — the most literal form of the trap `professional-ui` forbids.
    ///
    /// The alternative was to turn decorations back ON and take the platform's own controls, which
    /// would be free and correct per-platform. It was rejected because this chrome is not a
    /// titlebar substitute that happens to hold a Close: it carries the brand mark, the window's
    /// name and the theme toggle, and the panes are laid out from [`CHROME_HEIGHT`] downward. With
    /// decorations on, the OS bar sits ABOVE all of that, so the window grows a second title row and
    /// the same window shows its name twice. The comment on the PROMPT window's own
    /// `.with_decorations(false)` cites dig_ecosystem#2038 for a Windows compositing fault, but that
    /// citation is about a TRANSPARENT frameless surface losing its content on a move; neither
    /// window is transparent and the fault does not bear on this decision either way.
    ///
    /// So the three controls are drawn, and Maximize RESTORES: a control that can only go one way is
    /// the same trap in a smaller shape.
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

        let maximized = window_is_maximized(ui.ctx());
        let slots = ChromeSlots::lay_out(bar);

        // Glyphs, each carrying the same word it used to say — see [`paint::window_control`] for why
        // the name survives the switch to icons (dig_ecosystem#2997).
        if self.control(ui, slots.close, paint::WindowIcon::Close, "Close", t) {
            self.closing = true;
        }
        let (maximize_icon, maximize_name) = maximize_control(maximized);
        if self.control(ui, slots.maximize, maximize_icon, maximize_name, t) {
            ui.ctx()
                .send_viewport_cmd(egui::ViewportCommand::Maximized(!maximized));
        }
        if self.control(
            ui,
            slots.minimize,
            paint::WindowIcon::Minimize,
            "Minimize",
            t,
        ) {
            ui.ctx()
                .send_viewport_cmd(egui::ViewportCommand::Minimized(true));
        }

        // The strip senses clicks as well as drags so a double-click can toggle maximise, which is
        // the gesture every platform's titlebar answers to and the one a person tries before they
        // look for a control.
        let strip = ui.interact(
            slots.drag,
            egui::Id::new("dig-app-shell-drag"),
            egui::Sense::click_and_drag(),
        );
        if strip.double_clicked() {
            ui.ctx()
                .send_viewport_cmd(egui::ViewportCommand::Maximized(!maximized));
        } else if strip.dragged() {
            ui.ctx().send_viewport_cmd(egui::ViewportCommand::StartDrag);
        }
    }

    /// One chrome control, drawn in the slot [`ChromeSlots`] measured for it.
    fn control(
        &self,
        ui: &mut egui::Ui,
        slot: Rect,
        icon: paint::WindowIcon,
        name: &str,
        t: &Tokens,
    ) -> bool {
        paint::window_control(ui, slot, icon, name, t).clicked()
    }

    /// Dim the whole window, and swallow every click that lands on it.
    ///
    /// # Why the scrim is a widget and not a rectangle of paint
    ///
    /// Dimming says the window is inert; a full-window widget that senses clicks and drags MAKES it so.
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

/// Where the modal is drawn: centred in the window, clamped to it on both axes.
///
/// # Why a function and not two lines inside the painter
///
/// So it can be ASSERTED. Every placement claim this surface makes — that the modal is inside the
/// window, that it is centred, that it never overhangs an edge a person would have to resize the
/// window to reach past — is a claim about a rectangle, and a pure function is the only form of it a
/// headless test can hold. Nothing here reads the [`egui::Context`] for that reason.
///
/// Clamped to [`MODAL_SHARE`] of the window on both axes. On a shell dragged to [`SHELL_MIN`] the
/// prompt's natural [`super::WIDTH`] is wider than the window itself, and a card whose action row
/// runs off the right edge is a consent surface that cannot be refused. The share rather than the
/// full width, so a margin of scrim always shows: a modal drawn edge to edge is indistinguishable
/// from the window having simply become the prompt, which loses the one cue that says the app is
/// still there, waiting behind this.
fn modal_rect(full: Rect, chrome: Chrome, height: f32) -> Rect {
    let (natural_width, ..) = super::opening_size(chrome);
    let size = Vec2::new(
        natural_width.min(full.width() * MODAL_SHARE),
        height.min(full.height() * MODAL_SHARE),
    );
    // A launcher sits HIGH, where the standalone bar places itself on its monitor
    // (`PromptApp::place_bar`); a dialog is centred. Same arithmetic, against the window instead of
    // the display, so the two hosts put the bar in the same place relative to what it is inside of.
    let centre = match chrome.is_bar() {
        true => egui::Pos2::new(
            full.center().x,
            (full.top() + super::bar_top(full.height()) + size.y / 2.0)
                .min(full.bottom() - size.y / 2.0),
        ),
        false => full.center(),
    };
    Rect::from_center_size(centre, size)
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

/// How tall a chrome control is, and how far below the top of the bar it starts.
///
/// Sized so a 30 px control is centred in the 44 px bar: `(44 - 30) / 2` is 7.
const CONTROL_HEIGHT: f32 = 30.0;
/// The gap above a chrome control, which is what centres it in the bar.
const CONTROL_TOP: f32 = (CHROME_HEIGHT - CONTROL_HEIGHT) / 2.0;
/// How wide an icon control's hit area is.
///
/// Wider than it is tall, so the row reads as a titlebar rather than as three buttons, while the
/// target stays comfortably larger than the mark inside it (`professional-ui`). It is also wider
/// than the old `Minimize` text control was, so nothing lost reach in the switch to glyphs.
const CONTROL_WIDTH: f32 = 40.0;

/// Where every chrome control sits, and what is left over for the drag strip.
///
/// # Why the slots are measured rather than declared
///
/// Every slot is exactly as wide as [`paint::text_control_width`] says its label needs. The chrome
/// used to place Close and the theme toggle at two hardcoded widths, which works only while nobody
/// re-words a label: a control whose label outgrows its slot still draws and still senses, it simply
/// does so on top of its neighbour. With four controls in the row that stops being hypothetical.
///
/// The drag strip is DERIVED from the same measurement — everything left of the leftmost control —
/// so it cannot come to overlap a control's hit area. An undecorated window whose Close is swallowed
/// by a drag strip is a window with no way out.
#[derive(Debug, Clone, Copy, PartialEq)]
struct ChromeSlots {
    /// Minimize, first of the three window controls.
    minimize: Rect,
    /// Maximize — or Restore, when the window is already maximised.
    maximize: Rect,
    /// Close, rightmost, where every platform puts it.
    close: Rect,
    /// Everything to the left of the controls: drag here to move the window.
    drag: Rect,
}

impl ChromeSlots {
    /// Place the row's three square slots, right to left.
    ///
    /// No longer measured against a label: an icon control's mark is stroked to a fixed box, so its
    /// slot is a constant square and the whole row is decided by arithmetic that cannot be thrown
    /// off by a re-worded or translated label. The measured-width machinery this replaces existed
    /// because the labels were TEXT (dig_ecosystem#2569); the reason went with the words.
    ///
    /// A square that is [`CONTROL_HEIGHT`] on a side is a larger hit target than the old
    /// `Minimize` control had, so the switch to icons takes nothing away from a pointer either.
    fn lay_out(bar: Rect) -> Self {
        let mut right = bar.right() - space::S3;
        let mut slot = || {
            let rect = Rect::from_min_size(
                egui::Pos2::new(right - CONTROL_WIDTH, bar.top() + CONTROL_TOP),
                Vec2::new(CONTROL_WIDTH, CONTROL_HEIGHT),
            );
            right = rect.left() - space::S1;
            rect
        };
        let close = slot();
        let maximize = slot();
        let minimize = slot();
        Self {
            minimize,
            maximize,
            close,
            // `max` rather than a bare subtraction: on a window narrow enough that the controls fill
            // the bar the strip collapses to nothing, which is a window that cannot be dragged by
            // its header. That is recoverable; a strip laid OVER the controls is not.
            drag: Rect::from_min_max(
                bar.left_top(),
                egui::Pos2::new((minimize.left() - space::S2).max(bar.left()), bar.bottom()),
            ),
        }
    }

    /// Every control slot, for the tests that must hold all of them to the same rule.
    #[cfg(test)]
    fn controls(&self) -> [(&'static str, Rect); 3] {
        [
            ("minimize", self.minimize),
            ("maximize", self.maximize),
            ("close", self.close),
        ]
    }
}

/// The maximise control's glyph AND its name, which must always describe the same action.
///
/// Returned together so they cannot be chosen independently: a square glyph announced as *Restore*
/// tells a sighted person and a screen-reader user two different things about the same button.
fn maximize_control(maximized: bool) -> (paint::WindowIcon, &'static str) {
    match maximized {
        true => (paint::WindowIcon::Restore, "Restore"),
        false => (paint::WindowIcon::Maximize, "Maximize"),
    }
}

/// Whether the platform currently has this window maximised.
///
/// `None` — a host that does not report the flag at all — is read as NOT maximised, so the control
/// says *Maximize* and its click asks for `Maximized(true)`. That is the recoverable direction: a
/// host that cannot report the state can still be asked to restore by dragging the window, whereas
/// defaulting to *Restore* would leave a plainly un-maximised window offering to un-maximise itself.
fn window_is_maximized(ctx: &egui::Context) -> bool {
    ctx.input(|i| i.viewport().maximized).unwrap_or(false)
}
/// The id of the scrim's input blocker — the widget that eats every click aimed under the modal.
///
/// Named rather than auto-generated so [`ShellApp::scrim`]'s guarantee is a thing a test can read
/// back, instead of an inference from the controls that happen to exist today.
fn scrim_blocker() -> egui::Id {
    egui::Id::new("dig-app-shell-scrim-blocker")
}
/// The tab the window opens on, and the one it falls back to when a selected tab stops existing.
///
/// Home, because it is the tab that makes sense when the app cannot yet say what else to show —
/// and because it holds `Open the log folder`, the escape hatch for when nothing else works.
const FIRST_TAB: TabId = TabId::Home;

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
        /// What the platform reports about this window being maximised, for the next frame.
        ///
        /// `None` is a host that does not report the flag at all, which is a third case and not a
        /// synonym for `Some(false)` — see [`window_is_maximized`].
        maximized: Option<bool>,
        _dir: tempfile::TempDir,
        /// Excludes every other test that raises or reads the process-global consent count.
        ///
        /// Held by the HARNESS rather than by the handful of tests that assert on the count,
        /// because since dig_ecosystem#2270 any shelf showing a prompt RAISES it — so every shelf is
        /// a raiser, whether or not it looks like one. Scoping the guard to the assertions instead
        /// would leave the raisers unsynchronised, which is the shape of the flake it fixes: two
        /// tests failing together, each having read the other's legitimate surface.
        ///
        /// The mirror of [`super::super::tests::Lane`]'s own guard. A test must not build a `Shelf`
        /// and a `Lane` at once — the mutex is not reentrant — and
        /// [`ExclusiveSurface`](crate::confirm::surface::ExclusiveSurface) turns that mistake into a
        /// named panic on the spot rather than a suite that hangs with no output.
        _exclusive: crate::confirm::surface::ExclusiveSurface,
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
                    None,
                ),
                ctx,
                jobs,
                queue,
                store,
                dispatched,
                size: shell_size(),
                maximized: None,
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

        /// Queue the Alt+Space URN launcher — a `Chrome::Bar` prompt the caller is waiting on.
        fn queue_live_bar(&self) -> Receiver<Outcome> {
            let (reply, answers) = sync_channel(1);
            let content = crate::confirm::InputContent {
                title: "DIG — Open".to_owned(),
                heading: "Open a DIG link".to_owned(),
                body: "Paste a chia:// or urn:dig:chia: link and press Enter. Esc closes this."
                    .to_owned(),
                field_label: "DIG link:".to_owned(),
                submit: "Open",
                masked: false,
                revealable: false,
                style: crate::confirm::InputStyle::Bar,
            };
            let screen = super::super::Screen::input(&content);
            assert_eq!(
                screen.chrome,
                Chrome::Bar,
                "the fixture is not a bar, so every bar rule it is used for is vacuous"
            );
            self.jobs
                .send(Work::Prompt(Job {
                    screen,
                    wants_text: true,
                    theme: self.store.clone(),
                    deadline: PATIENT,
                    over_by: Instant::now() + PATIENT + ANSWER_GRACE,
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
            let mut viewports = egui::ViewportIdMap::default();
            viewports.insert(
                egui::ViewportId::ROOT,
                egui::ViewportInfo {
                    maximized: self.maximized,
                    ..Default::default()
                },
            );
            egui::RawInput {
                screen_rect: Some(Rect::from_min_size(egui::Pos2::ZERO, self.size)),
                events,
                viewports,
                ..Default::default()
            }
        }

        /// Every word the last frame painted, and the rectangle it occupies.
        ///
        /// Tests aim clicks at what was DRAWN rather than at a rectangle recomputed from the layout
        /// code under test: a slot function and a test that both got the arithmetic wrong the same
        /// way agree with each other perfectly.
        fn words(&mut self) -> Vec<(String, Rect)> {
            let output = self.frame(Vec::new());
            fn walk(shape: &egui::Shape, out: &mut Vec<(String, Rect)>) {
                match shape {
                    egui::Shape::Text(text) => out.push((
                        text.galley.text().to_owned(),
                        Rect::from_min_size(text.pos, text.galley.size()),
                    )),
                    egui::Shape::Vec(shapes) => shapes.iter().for_each(|s| walk(s, out)),
                    _ => {}
                }
            }
            let mut said = Vec::new();
            for clipped in &output.shapes {
                walk(&clipped.shape, &mut said);
            }
            said
        }

        /// Where the control NAMED `word` sensed, or `None` when the chrome offered no such control.
        ///
        /// Resolved through [`paint::window_control_id`] — the control's accessible name — rather
        /// than by hunting for painted text. Since dig_ecosystem#2997 the window controls paint no
        /// text at all, so a harness that searched for words would find nothing and every chrome
        /// test would stop reaching its control. Asking by name is also the only addressing that
        /// stays true to what a screen reader announces.
        fn control_rect(&mut self, word: &str) -> Option<Rect> {
            self.frame(Vec::new());
            self.ctx
                .read_response(paint::window_control_id(word))
                .map(|response| response.rect)
        }

        /// Where the chrome drew `word`, failing loudly when it drew no such control.
        fn control_at(&mut self, word: &str) -> egui::Pos2 {
            self.control_rect(word)
                .unwrap_or_else(|| panic!("the chrome drew no {word:?} control"))
                .center()
        }

        /// Click the chrome control labelled `word` and report every command that click produced.
        fn press_chrome(&mut self, word: &str) -> Vec<egui::ViewportCommand> {
            let at = self.control_at(word);
            self.frame(vec![egui::Event::PointerMoved(at)]);
            self.frame(vec![egui::Event::PointerButton {
                pos: at,
                button: egui::PointerButton::Primary,
                pressed: true,
                modifiers: egui::Modifiers::default(),
            }]);
            let released = self.frame(vec![egui::Event::PointerButton {
                pos: at,
                button: egui::PointerButton::Primary,
                pressed: false,
                modifiers: egui::Modifiers::default(),
            }]);
            released
                .viewport_output
                .get(&egui::ViewportId::ROOT)
                .map(|root| root.commands.clone())
                .unwrap_or_default()
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

    /// Whether THIS frame asked the windowing system to bring the app window forward.
    ///
    /// The free-function counterpart of [`Shelf::asked_for_focus`], which runs frames of its own. A
    /// raise that happens on admission has to be read from the admitting frame itself, and a helper
    /// that advances the clock would step straight past it.
    fn focus_requested(output: &egui::FullOutput) -> bool {
        output
            .viewport_output
            .get(&egui::ViewportId::ROOT)
            .is_some_and(|root| {
                root.commands
                    .iter()
                    .any(|command| matches!(command, egui::ViewportCommand::Focus))
            })
    }

    /// Where a painted line of text ended up, so a test can aim a real pointer at it.
    ///
    /// Read back from the SHAPES rather than from a widget id: `paint::button` derives its id from
    /// the layout, so a test that guessed the id would find nothing and skip its assertions —
    /// passing while proving nothing (the trap `the_raise_pill…` was written to avoid, applied to a
    /// control this time). Panics rather than returning an `Option`: every caller needs the control
    /// to exist, and a `None` silently satisfying a `?` is how a click test stops clicking.
    fn where_text_landed(output: &egui::FullOutput, needle: &str) -> Rect {
        fn walk(shape: &egui::Shape, needle: &str, out: &mut Vec<Rect>) {
            match shape {
                egui::Shape::Text(text) if text.galley.text() == needle => {
                    out.push(Rect::from_min_size(text.pos, text.galley.size()));
                }
                egui::Shape::Vec(shapes) => shapes.iter().for_each(|s| walk(s, needle, out)),
                _ => {}
            }
        }
        let mut found = Vec::new();
        for clipped in &output.shapes {
            walk(&clipped.shape, needle, &mut found);
        }
        match found.as_slice() {
            [one] => *one,
            [] => panic!("`{needle}` was never painted, so there is nothing to click"),
            many => panic!(
                "`{needle}` was painted {} times; the target is ambiguous",
                many.len()
            ),
        }
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
        // Keyed on the sidebar's own labels, which only the shell draws. `Home` leads the sidebar
        // in every state the model can produce, so this stays true for any view.
        drawn_text(output).iter().any(|line| line == "Home")
    }

    /// The element id of one sidebar entry.
    fn sidebar_entry(tab: TabId) -> egui::Id {
        egui::Id::new(crate::window_model::tab_element_id(tab))
    }

    /// The element id of the FIRST row carrying `label`, from the pane's own id function rather than
    /// a copy of it.
    fn row_control(label: &str) -> egui::Id {
        super::super::pane::row_element_id(label, 0)
    }

    /// Press Enter, and do not release it.
    ///
    /// The `repeat` field is left `false` because egui does not read it: it recomputes the flag from
    /// its own `keys_down` set on every pass (`input_state/mod.rs`). Whether a press counts as a
    /// repeat is therefore decided by whether a matching [`enter_up`] was sent, which is what makes
    /// `a_held_enter_cannot_answer_the_next_prompt` a real sequence rather than a claim about a flag.
    fn enter_down() -> Vec<egui::Event> {
        enter_key(true)
    }

    /// Release Enter.
    fn enter_up() -> Vec<egui::Event> {
        enter_key(false)
    }

    /// Press Enter and release it — one complete keystroke.
    fn enter() -> Vec<egui::Event> {
        let mut events = enter_down();
        events.extend(enter_up());
        events
    }

    fn enter_key(pressed: bool) -> Vec<egui::Event> {
        vec![egui::Event::Key {
            key: Key::Enter,
            physical_key: None,
            pressed,
            repeat: false,
            modifiers: egui::Modifiers::NONE,
        }]
    }

    /// A point inside the window but outside any modal: the scrim, and nothing else.
    ///
    /// A corner, so it cannot land on a centred dialog or on a launcher placed high.
    fn clicked_away() -> egui::Pos2 {
        egui::Pos2::new(4.0, SHELL_HEIGHT - 4.0)
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
        let lane = super::super::tests::Lane::serving_work(|work, _queue, _watching| match work {
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
        let lane = super::super::tests::Lane::serving_work(move |work, _queue, _watching| {
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
                initial_tab: None,
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
                initial_tab: None,
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

        // The human answers, recorded through the prompt's OWN latch. Note what this does NOT
        // exercise: it calls `record` directly, so it skips hit-testing entirely — which is the part
        // a click actually risks. The pointer path has its own tests
        // (`the_modal_answers_a_real_pointer_click_on_its_action_button` and its refusal twin); this
        // one is about what SURVIVES the shell closing over an answer, and reaching the latch by the
        // shortest route is what keeps it aimed at that.
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
    /// # Why this drives the function and not the shell (dig_ecosystem#2358)
    ///
    /// It used to select `TabId::Advanced` — a variant that was declared and never constructed, so
    /// it was exactly a selection the model could not honour. Advanced is gone with the five-tab
    /// reshape, and every remaining tab is emitted in every state, so no VIEW can now produce the
    /// condition: a shell-level fixture for it would have to be a tab that does not exist.
    ///
    /// The guard is still worth keeping — `build` filters empty tabs, and a future tab whose content
    /// is conditional would bring the state straight back, at which point a sidebar highlighting a
    /// tab that is gone renders an empty pane with no way to notice why. So the model is built by
    /// hand with the selection deliberately absent, which is the smallest fixture that exhibits the
    /// property, and the control asserts the selection is left ALONE when the tab does exist — a
    /// fallback that fired unconditionally would move a person off the tab they chose.
    #[test]
    fn a_selection_whose_tab_disappears_falls_back_to_one_that_exists() {
        let mut shelf = Shelf::open();
        shelf.settle();

        let full = window_model::build(&busy_view());
        let missing = WindowModel {
            tabs: full
                .tabs
                .iter()
                .filter(|tab| tab.id != TabId::Content)
                .cloned()
                .collect(),
        };
        assert!(
            missing.tab(TabId::Content).is_none() && !missing.tabs.is_empty(),
            "the fixture must drop the tab being selected and keep others, or nothing is tested"
        );

        shelf.app.selected = TabId::Content;
        shelf.app.keep_selection_valid(&missing);
        assert_eq!(
            shelf.app.selected, missing.tabs[0].id,
            "a selection pointing at a tab that is not emitted must fall back to one that is"
        );

        shelf.app.selected = TabId::Wallet;
        shelf.app.keep_selection_valid(&missing);
        assert_eq!(
            shelf.app.selected,
            TabId::Wallet,
            "a selection pointing at a tab that IS emitted was moved anyway"
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
        // Tall enough that the row under test is on screen without scrolling. The pane scrolls
        // (`panes.rs`), so a row below the fold is reachable in the product — but a synthetic click
        // aimed at a rect outside the clip lands on nothing, and this test is about DISPATCH, not
        // about what fits at one particular height.
        shelf.size = Vec2::new(shelf.size.x, 1_400.0);
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

    /// **Every tab the model emits can be clicked at every width the window can be dragged to.**
    ///
    /// The window can legitimately be dragged to [`SHELL_MIN`], and a 208 px sidebar out of 480 px
    /// leaves a content column narrower than the sidebar, so below the threshold the sidebar becomes
    /// a strip. Whichever it is, a tab that exists must be selectable.
    ///
    /// # What this deliberately does NOT assert
    ///
    /// Until dig_ecosystem#2309 this read the tab labels back out of the frame's shapes and checked
    /// each one appeared. That is not reachability, and it was green while the shipping window drew
    /// six of seven chips. Two reasons, both worth remembering:
    ///
    /// - Text is emitted into `FullOutput` before anything is culled, so a chip laid out past the
    ///   right edge — or under the chip beside it — reads back exactly like one a person can click.
    /// - It probed ONE width, with whatever tab set the fixture happened to produce, so it could
    ///   only fail if that set overflowed at exactly that width. Overflow was never exercised.
    ///
    /// So this asserts geometry and a real click instead, at several widths on both sides of
    /// [`panes::NARROW_AT`]. It still cannot MANUFACTURE overflow — the tab set is the model's, not
    /// the test's — which is why the strip's own behaviour when the chips do not fit is pinned by
    /// `panes::tests::every_tab_is_reachable_at_every_width_the_window_allows`, whose fixture
    /// refuses to run unless they genuinely overflow.
    /// **Proves:** the embedded mark decodes, so the window opens with the DIG brand rather than
    /// eframe's default placeholder — the letter "e" the window actually showed (#2340).
    /// **Catches:** a mark replaced with a PNG in another colour type or bit depth, which
    /// `window_icon` refuses rather than mis-decoding, and which would silently restore the default.
    #[test]
    fn the_window_opens_with_the_dig_mark_not_the_toolkits_default() {
        let icon = window_icon().expect("the embedded mark decodes");
        assert_eq!(
            icon.width, icon.height,
            "the mark is square; {}x{} means the wrong asset is embedded",
            icon.width, icon.height
        );
        assert_eq!(
            icon.rgba.len() as u32,
            icon.width * icon.height * 4,
            "RGBA is four bytes a pixel; a shorter buffer is a partial decode drawn as garbage"
        );
        assert!(
            icon.rgba.chunks_exact(4).any(|px| px[3] != 0),
            "every pixel is transparent, so the window would show an empty square"
        );
    }

    #[test]
    fn a_narrow_window_keeps_every_tab_reachable() {
        let tabs = window_model::build(&busy_view()).tabs;
        assert!(tabs.len() > 1, "one tab cannot show a strip overflowing");

        for width in [SHELL_MIN, SHELL_MIN + 70.0, 640.0, SHELL_WIDTH] {
            let mut shelf = Shelf::open();
            shelf.size = Vec2::new(width, SHELL_MIN);
            shelf.settle();
            let screen = Rect::from_min_size(egui::Pos2::ZERO, shelf.size);

            for tab in &tabs {
                let entry = shelf
                    .ctx
                    .read_response(sidebar_entry(tab.id))
                    .unwrap_or_else(|| panic!("at {width} px {:?} was never laid out", tab.id));
                assert!(
                    screen.contains_rect(entry.rect),
                    "at {width} px {:?} sits at {:?}, off the window",
                    tab.id,
                    entry.rect
                );
                shelf.click(entry.rect.center());
                assert_eq!(
                    shelf.app.selected, tab.id,
                    "at {width} px a click on {:?} did not select it",
                    tab.id
                );
            }
        }
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
                TabId::Home,
            ),
            (
                "error",
                crate::tray_menu::TrayView {
                    cache: None,
                    ..busy_view()
                },
                TabId::Content,
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
        let at = shelf.centre_of(sidebar_entry(TabId::Content));
        shelf.click(at);
        let output = shelf.frame(Vec::new());
        assert_eq!(
            window_model::build(&busy_view())
                .tab(TabId::Content)
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

    /// **No code path reachable while the app window is open opens a second window.**
    ///
    /// This is dig_ecosystem#2270 itself: clicking *Show my recovery phrase…* inside the app window
    /// used to put a second OS window in front of the one the person was already looking at.
    ///
    /// # Why this reads the source instead of the frame
    ///
    /// Because every runtime instrument here is blind, and that was MEASURED rather than assumed.
    /// `egui::Context::default()` sets `embed_viewports`, so a headless `show_viewport_immediate`
    /// runs its child inline and leaves the root's own shapes and `viewport_output` exactly as they
    /// were; clearing the flag does not help either — a bare `Context::run` has no integration to
    /// realise a viewport, so `viewport_output` came back holding ROOT alone with the child call
    /// restored. An assertion on either would pass over the regression it names, which is worse than
    /// no assertion at all.
    ///
    /// # What "the shell-open path" actually means here
    ///
    /// The WHOLE `confirm::gui` subtree — every file that can run while the window is up, which is
    /// all of them: the shell, the panes it draws, [`super::PromptApp`] which the modal drives every
    /// frame, and the painter, renderer and theme those call into. Scoping the scan to this module
    /// left most of the path unchecked, and the modal's own painter is the likeliest place for a
    /// viewport call to reappear.
    ///
    /// Listed by name rather than walked, because `include_str!` needs a literal path: a file added
    /// to this directory is NOT covered until it is added here, which the count assertion below is
    /// there to make somebody notice.
    ///
    /// Both viewport-opening APIs are covered, and the needle is `show_viewport` rather than a full
    /// method name so the deferred form and a UFCS call
    /// (`egui::Context::show_viewport_immediate(ctx, …)`) are caught by the same rule. Line
    /// comments are excluded so the prose above does not match itself; the doc comments elsewhere in
    /// these files that DISCUSS the call are excluded for the same reason.
    #[test]
    fn nothing_on_the_shell_open_path_opens_a_second_window() {
        // Assembled from halves so this test's own source does not match the needle it looks for.
        let needle = format!("show_{}", "viewport");
        let path = [
            ("window/shell.rs", include_str!("shell.rs")),
            ("window/panes.rs", include_str!("panes.rs")),
            ("window.rs", include_str!("../window.rs")),
            ("mod.rs", include_str!("../mod.rs")),
            ("paint.rs", include_str!("../paint.rs")),
            ("render.rs", include_str!("../render.rs")),
            ("theme.rs", include_str!("../theme.rs")),
        ];

        // The `gui` subtree is seven files. A new one is not scanned until it is listed above.
        assert_eq!(
            path.len(),
            7,
            "the file list changed; make sure every file in `confirm/gui` is still covered"
        );

        let mut calls: Vec<String> = Vec::new();
        for (file, source) in path {
            for (n, line) in source.lines().enumerate() {
                let code = line.trim_start();
                if !code.starts_with("//") && code.contains(&needle) {
                    calls.push(format!("{file}:{}: {code}", n + 1));
                }
            }
        }

        assert!(
            calls.is_empty(),
            "the shell-open path opens a child window again:
{}",
            calls.join(
                "
"
            )
        );
    }

    /// **A prompt raised over the open shell is drawn in the shell's own frame.**
    ///
    /// The runtime half of the rule above, and the reason that one is not vacuous: a shell that drew
    /// no prompt at all would also contain no viewport call, and would be a consent lockout rather
    /// than a fix.
    #[test]
    fn a_prompt_over_the_open_shell_is_drawn_in_the_shell_itself() {
        let mut shelf = Shelf::open();
        shelf.settle();
        let _answers = shelf.queue_live_prompt();
        shelf.frame(Vec::new());
        let output = shelf.frame(Vec::new());

        assert!(
            a_prompt_was_drawn(&output),
            "the prompt reached the app window and nothing was drawn for it"
        );
        assert!(
            the_shell_was_drawn(&output),
            "the shell stopped drawing itself, so the prompt is not IN it"
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
        // A second frame because the FIRST is the modal's sizing pass, which egui marks invisible:
        // the prompt cannot be answered until it has been presented (`frame_in_window`, F1). The
        // surface is raised from admission either way, which is what this test is about.
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

    /// **The modal answers a real pointer click on its action button.**
    ///
    /// The positive control the scrim tests had no counterpart for, and the highest-value assertion
    /// in this module. Everything else about the in-window prompt is answered by the KEYBOARD —
    /// Escape, Enter — so without this the modal could be completely unreachable by mouse and the
    /// whole suite would stay green. `read_response` cannot see the difference either: it is
    /// layer-blind, so it reports a blocker that sits UNDER the panes exactly as it reports one over
    /// them.
    ///
    /// Concretely: this is the test that dies when the modal's layer stops being strictly above the
    /// scrim's, which is a consent surface a person can read and cannot approve.
    ///
    /// Asserted on the OUTCOME the caller received, not on a field of the app — an approval that
    /// never reaches the blocked caller is not an approval.
    #[test]
    fn the_modal_answers_a_real_pointer_click_on_its_action_button() {
        let mut shelf = Shelf::open();
        shelf.settle();
        let answers = shelf.queue_live_prompt();
        shelf.frame(Vec::new());
        let output = shelf.frame(Vec::new());

        let sign = where_text_landed(&output, "Sign");
        shelf.click(sign.center());

        assert!(
            shelf.app.prompt.is_none(),
            "the click on Sign did not dismiss the modal, so it never landed"
        );
        assert!(
            matches!(
                answers.try_recv(),
                Ok(Outcome::Confirm(WindowIntent::Approve))
            ),
            "a click on the modal's Sign button did not reach the caller as an approval; the \
             consent surface is unanswerable by pointer"
        );
    }

    /// **A pointer click on the modal's REFUSAL reaches the caller too.**
    ///
    /// Both controls, because a modal wired so that every click resolves to the same answer would
    /// satisfy the test above perfectly. This is a consent surface: being able to refuse it by the
    /// obvious gesture is the half that matters most.
    #[test]
    fn the_modal_answers_a_real_pointer_click_on_its_refusal() {
        let mut shelf = Shelf::open();
        shelf.settle();
        let answers = shelf.queue_live_prompt();
        shelf.frame(Vec::new());
        let output = shelf.frame(Vec::new());

        let cancel = where_text_landed(&output, "Cancel");
        shelf.click(cancel.center());

        assert!(
            matches!(answers.try_recv(), Ok(Outcome::Confirm(WindowIntent::Deny))),
            "a click on the modal's Cancel button did not reach the caller as a refusal"
        );
    }

    /// **Admitting a prompt brings the app window forward.**
    ///
    /// Gate finding A1. A standalone prompt is always-on-top and claims the keyboard, and BOTH are
    /// claims against the desktop. Drawing the prompt inside the app window keeps it from being
    /// buried by the shell and, on its own, drops every guarantee that it is seen at all: with the
    /// window open behind a browser, a dapp's signature request drew where nobody could see it, held
    /// the consent surface up for its full deadline, and refused itself.
    ///
    /// Asserted alongside the prompt actually being up, so a shell that raised itself while failing
    /// to draw anything cannot pass.
    #[test]
    fn admitting_a_prompt_brings_the_window_forward() {
        let mut shelf = Shelf::open();
        shelf.settle();
        let _answers = shelf.queue_live_prompt();
        let output = shelf.frame(Vec::new());

        assert!(
            shelf.app.prompt.is_some(),
            "no prompt was admitted, so this frame says nothing about raising"
        );
        assert!(
            focus_requested(&output),
            "a consent prompt appeared inside the app window and the window was not brought \
             forward; behind another application it is invisible for its whole deadline (#2079)"
        );
    }

    /// **A prompt refused without being drawn does NOT bring the window forward.**
    ///
    /// The other side of the rule above, and not a nicety: a stale job raises no surface, so pulling
    /// the person's foreground for it is a bare interruption with nothing to show them. It is also
    /// what stops the raise from being unconditional-and-therefore-untested — a shell that always
    /// raised would pass the test above whatever it did with the job.
    #[test]
    fn a_stale_prompt_does_not_bring_the_window_forward() {
        let mut shelf = Shelf::open();
        shelf.settle();
        let answers = shelf.queue_prompt(Instant::now() - Duration::from_secs(1));
        let output = shelf.frame(Vec::new());

        assert!(
            matches!(
                answers.try_recv(),
                Ok(Outcome::Confirm(WindowIntent::Unavailable))
            ),
            "the stale job was not refused, so it is not the case under test"
        );
        assert!(
            !focus_requested(&output),
            "the app window took the foreground for a prompt it refused without drawing"
        );
    }

    // ---------------------------------------------------------------------------------------------
    // No answer from a pass the person was not shown (dig_ecosystem#2270, F1)
    // ---------------------------------------------------------------------------------------------

    /// **A prompt cannot be answered on the frame it first appears.**
    ///
    /// The regression test for the highest-severity defect this change introduced: a sign request
    /// answered `Approve`, delivered to a blocked caller, with the consent surface **never drawn**.
    ///
    /// Two facts met. The shell admits a prompt and paints it in the SAME frame, and in-window it
    /// shares the shell's input stream — so the prompt's first `keys()` read a keystroke aimed at the
    /// app window. And an [`egui::Area`] whose state does not exist yet runs a sizing pass that egui
    /// marks invisible and discards, so that first pass showed nothing by construction. The
    /// pre-focused control of a sign prompt is the AFFIRMATIVE, so the leftover Enter approved a
    /// spend nobody had seen.
    ///
    /// # Why this shape, and not the suite's usual one
    ///
    /// Every other in-window answer test runs `settle(); queue; frame(); frame(); frame(key)` — by
    /// which point the Area's state exists and the modal has been painted, so **none of them can
    /// observe this**. This is deliberately the ONE-frame case: the keystroke rides the very frame
    /// that admits the prompt.
    ///
    /// Asserted on what the CALLER received, never on what was drawn. "Nothing was painted" is a
    /// symptom; "the caller was told Approve" is the defect.
    #[test]
    fn a_prompt_cannot_be_answered_on_the_frame_it_first_appears() {
        let mut shelf = Shelf::open();
        shelf.settle();
        let answers = shelf.queue_live_prompt();

        // One frame that admits the prompt AND carries an Enter left over from the app window.
        shelf.frame(enter());

        assert!(
            shelf.app.prompt.is_some(),
            "the prompt was answered on the frame it was admitted, before anything of it had been \
             drawn"
        );
        assert!(
            matches!(answers.try_recv(), Err(TryRecvError::Empty)),
            "an answer reached the caller from a frame in which the consent surface was never \
             presented; for a sign prompt the pre-focused control is the AFFIRMATIVE, so this is an \
             approval the person never saw"
        );

        // And not on the NEXT frame either, which is the only frame the two halves of the guard
        // disagree about. That frame follows the invisible sizing pass, so a latch that counted the
        // sizing pass as a presentation would have the keyboard live here — while the person still
        // has not been shown anything. Measured: without this the sizing-pass check was
        // unfalsifiable and a mutant removing it survived.
        shelf.frame(enter());
        assert!(
            matches!(answers.try_recv(), Err(TryRecvError::Empty)),
            "an answer was taken on the frame after the modal's INVISIBLE sizing pass; nothing had \
             been drawn for the person to answer"
        );
    }

    /// **…and it CAN be answered once it has been presented.**
    ///
    /// The control. A prompt that simply never accepted Enter would satisfy the test above perfectly
    /// and would be a consent surface nobody can approve — which, since Escape and the deadline both
    /// resolve a confirm to `Deny`, silently refuses everything.
    #[test]
    fn a_presented_prompt_answers_a_fresh_enter() {
        let mut shelf = Shelf::open();
        shelf.settle();
        let answers = shelf.queue_live_prompt();
        shelf.frame(Vec::new());
        shelf.frame(Vec::new());

        shelf.frame(enter());

        assert!(
            matches!(
                answers.try_recv(),
                Ok(Outcome::Confirm(WindowIntent::Approve))
            ),
            "a presented prompt did not answer a real Enter on its focused affirmative"
        );
    }

    /// **A held Enter cannot answer the NEXT prompt.**
    ///
    /// The other half of F1, and the one that needs no attacker timing. Prompts chain in this app —
    /// an unlock, then the operation it unlocked — and Windows repeats a held key at roughly 31 ms
    /// against a ~16 ms frame. So a person who answers one prompt with Enter and holds the key a beat
    /// longer generates presses that land on whatever is drawn next, and the pre-focused control of a
    /// sign prompt is the AFFIRMATIVE. [`egui::InputState::key_pressed`] counts those repeats;
    /// [`super::PromptApp::pressed_afresh`] does not.
    ///
    /// # The fixture is the real chain, because a synthesised flag is not the thing under test
    ///
    /// Measured, and it invalidated the obvious fixture: egui **overwrites** the `repeat` field of
    /// every incoming key event, deriving it from its own `keys_down` set
    /// (`input_state/mod.rs`, `*repeat = !first_press`). A test that simply passed `repeat: true`
    /// would have that rewritten to `false` and would exercise a fresh press while claiming to
    /// exercise a repeat — passing whatever the production code did. So this drives the actual
    /// sequence: answer one prompt, never send the key-up, and let egui decide what the next press is.
    ///
    /// Both sides are kept truthful: the repeat must NOT answer, and the fresh press after a real
    /// key-up MUST — otherwise "the prompt ignores Enter entirely" would pass, which since Escape and
    /// the deadline both resolve to `Deny` is a surface that silently refuses everything.
    #[test]
    fn a_held_enter_cannot_answer_the_next_prompt() {
        let mut shelf = Shelf::open();
        shelf.settle();

        // The first prompt, answered with a genuine Enter — and the key is never released.
        let first = shelf.queue_live_prompt();
        shelf.frame(Vec::new());
        shelf.frame(Vec::new());
        shelf.frame(enter_down());
        assert!(
            matches!(
                first.try_recv(),
                Ok(Outcome::Confirm(WindowIntent::Approve))
            ),
            "the first prompt was not answered, so nothing here is a chain"
        );

        // The second arrives while the key is still down, and every press egui reports for it is a
        // repeat of the one aimed at the first.
        let second = shelf.queue_live_prompt();
        shelf.frame(Vec::new());
        shelf.frame(Vec::new());
        shelf.frame(enter_down());
        shelf.frame(enter_down());

        assert!(
            shelf.app.prompt.is_some(),
            "a key held over from the previous prompt answered this one; that is an approval for a              surface the person never read"
        );
        assert!(
            matches!(second.try_recv(), Err(TryRecvError::Empty)),
            "a key-repeat reached the caller as an answer"
        );

        // Released, then pressed again: this one is the person's.
        shelf.frame(enter_up());
        shelf.frame(enter_down());
        assert!(
            matches!(second.try_recv(), Ok(Outcome::Confirm(WindowIntent::Approve))),
            "a fresh Enter after the key was released did not answer; the rule is refusing every              keystroke rather than only the repeats"
        );
    }

    // ---------------------------------------------------------------------------------------------
    // The URN launcher, in-window (dig_ecosystem#2270, correctness finding 3)
    // ---------------------------------------------------------------------------------------------

    /// **A launcher bar gets a launcher's geometry, not a dialog's.**
    ///
    /// `Chrome::Bar` HAS a live production producer, which is worth stating because it was disputed:
    /// `dig-app`'s Alt+Space hotkey calls `open_dig_link(.., InputStyle::Bar)`, and `Screen::input`
    /// maps that to `Chrome::Bar`. So the URN launcher really can be raised over the app window.
    ///
    /// Sized from [`super::opening_size`], which is the SAME mapping the standalone window layer
    /// uses — the point of the shared function. Asserted against the raw constants rather than
    /// against that function, so a test written from the contract cannot be satisfied by a mapping
    /// that has quietly changed to agree with itself.
    #[test]
    fn a_launcher_bar_in_the_window_is_sized_as_a_bar() {
        use crate::confirm::gui::render::{BAR_HEIGHT, BAR_WIDTH};

        // A window with room for the bar at its natural size, so the clamp is not what is measured.
        let window = Rect::from_min_size(egui::Pos2::ZERO, Vec2::new(1400.0, 1000.0));

        let bar = modal_rect(window, Chrome::Bar, BAR_HEIGHT);
        assert_eq!(
            bar.size(),
            Vec2::new(BAR_WIDTH, BAR_HEIGHT),
            "the launcher was drawn at a dialog's size; 720x176 became something else"
        );

        let dialog = modal_rect(window, Chrome::Dialog, crate::confirm::gui::window::HEIGHT);
        assert_ne!(
            dialog.size(),
            bar.size(),
            "a bar and a dialog are drawn at the same size, so this test cannot tell them apart"
        );
    }

    /// **Every frame the app window draws stamps its heartbeat.**
    ///
    /// The other end of the wedge vigil (dig_ecosystem#2272), and the half that fails DANGEROUSLY.
    /// The watchdog reads silence as a dead loop, so a frame loop that stopped saying it had run
    /// would have a perfectly healthy window force-closed under the person about
    /// [`super::FRAME_SILENCE`] after they opened it. The vigil's own tests stamp the heartbeat
    /// themselves and so cannot see this at all.
    ///
    /// Driven through [`Host`] rather than [`ShellApp`], because [`Host`] is where the stamp lives
    /// and a test that called `ShellApp::frame` would be measuring the wrong object.
    ///
    /// Both sides come off one frame: silent before it, stamped after it. The "before" half is the
    /// control — without it an implementation that reported itself alive from birth, and therefore
    /// could never detect a `run_native` that hangs before its first frame, would pass.
    #[test]
    fn every_frame_the_app_window_draws_stamps_its_heartbeat() {
        let _exclusive = crate::confirm::surface::one_surface_at_a_time();
        let dir = tempfile::tempdir().expect("a temp dir");
        let store = ThemeChoice::in_brand_dir(dir.path());
        let (_jobs, queue) = mpsc::channel::<Work>();
        let ctx = egui::Context::default();
        install_fonts(&ctx);

        let beat = Arc::new(super::super::Heartbeat::new());
        // A measurable age BEFORE the first frame, so that "the window went quiet" and "the window
        // was only just created" are two different readings rather than one near-zero one.
        std::thread::sleep(Duration::from_millis(80));
        let silent_before = beat.silence(Instant::now());

        assert!(
            silent_before >= Duration::from_millis(80),
            "a window that has drawn nothing was already reporting itself alive; a run_native that \
             hangs before its first frame would then never be seen at all"
        );

        let mut host = Host {
            app: ShellApp::new(
                Theme::Light,
                store,
                Arc::new(crate::tray_menu::TrayView::default),
                Arc::new(|_| {}),
                None,
            ),
            queue: &queue,
            beat: Arc::clone(&beat),
        };
        let input = egui::RawInput {
            screen_rect: Some(Rect::from_min_size(
                egui::Pos2::ZERO,
                Vec2::new(SHELL_WIDTH, SHELL_HEIGHT),
            )),
            ..Default::default()
        };
        let _painted = ctx.run(input, |ctx| host.paint(ctx));

        // Compared against the reading from before the frame rather than against a fixed number:
        // silence only ever GROWS with time, so the one thing that can make it smaller is a stamp.
        // Nothing here depends on how long a frame actually takes.
        assert!(
            beat.silence(Instant::now()) < silent_before,
            "a frame ran and the app window never said so; the watchdog would force this perfectly \
             healthy window closed under the person"
        );
    }

    /// **The committed gallery is exactly the set the generator produces — no more, no fewer.**
    ///
    /// The gallery is the only record of what this window LOOKS like, and its whole value is that a
    /// reviewer can trust it to be current. Two ways it stops being current, both observed: a run
    /// under a second naming scheme leaves the superseded files sitting beside the new ones, so the
    /// directory shows two generations of the same view and nothing says which is which; and a view
    /// added to `examples/shell_gallery.rs` is photographed once and then quietly never again.
    ///
    /// Pinning the set here makes both a failing test rather than a thing somebody notices. It is a
    /// list that is MEANT to be edited — adding a view to the generator means adding it here, in the
    /// same change, which is the point.
    ///
    /// This says nothing about what is IN the images. Nothing can: they are photographs of what an
    /// operating system drew, and looking at them is the job (`professional-ui`).
    #[test]
    fn the_committed_gallery_is_exactly_what_the_generator_photographs() {
        const VIEWS: [&str; 9] = [
            // One per tab the sidebar offers...
            "status",
            "account",
            "security",
            "wallet",
            "apps",
            "cache",
            // ...plus the states that are about the WINDOW rather than about a tab.
            "narrow",
            "with-prompt",
            "narrow-with-prompt",
        ];

        let mut expected: Vec<String> = ["light", "dark"]
            .iter()
            .flat_map(|theme| {
                VIEWS
                    .iter()
                    .map(move |view| format!("shell-{theme}-{view}.png"))
            })
            .collect();
        expected.sort();

        let gallery = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("docs/shell-gallery");
        let mut found: Vec<String> = std::fs::read_dir(&gallery)
            .unwrap_or_else(|err| {
                panic!(
                    "the gallery directory {} is readable: {err}",
                    gallery.display()
                )
            })
            .map(|entry| entry.expect("a directory entry").file_name())
            .map(|name| name.to_string_lossy().into_owned())
            .collect();
        found.sort();

        assert_eq!(
            found, expected,
            "the committed gallery no longer matches the set the generator photographs — either a \
             view was added or renamed without being regenerated, or a superseded run left files \
             behind under another naming scheme"
        );
    }

    /// **A launcher bar keeps its height across frames; only a dialog grows to its content.**
    ///
    /// [`ShellApp::show_prompt`] feeds each frame's measured content back into the modal's height for
    /// the next one, and the bar is exempted from that loop — a launcher is a fixed short strip, and
    /// the feedback inflates it to [`super::MIN_HEIGHT`] on its second frame (measured: 176 becomes
    /// 320), turning a Spotlight-style bar into a small dialog.
    ///
    /// # Why the size tests below could not see this, and why the control here is not the bar
    ///
    /// Its siblings call [`modal_rect`] directly, which is a pure function of a height handed TO it —
    /// so they measure the mapping and never the loop that supplies its argument. Deleting the
    /// exemption left every one of them green.
    ///
    /// # Where this belongs (dig_ecosystem#2292, A3)
    ///
    /// It arrived with the fresh-keystroke fix (#118) and has nothing to do with it, so it is worth
    /// saying once that it is not filed here by accident: it is a SIZING rule, and it already sits
    /// between the two tests it belongs with — `a_launcher_bar_in_the_window_is_sized_as_a_bar`
    /// above and `a_launcher_bar_in_the_window_sits_high_and_a_dialog_does_not` below — which is
    /// exactly where the reasoning below needs it, since those are the siblings it names as blind.
    /// Moving it would separate the explanation from what it explains.
    ///
    /// The first control written here was just as blind, and it is worth naming: comparing the bar's
    /// settled height against the DIALOG's passes on a shell that has stopped feeding anything back
    /// at all, because the two open at different heights and simply stay there. So each surface is
    /// held against its OWN opening height instead — the bar must not have moved, the dialog must
    /// have (measured: 560 opening, 378 settled) — and the pair distinguishes the exemption from the
    /// loop's absence.
    #[test]
    fn only_a_dialog_grows_to_its_content_in_the_window() {
        use crate::confirm::gui::render::BAR_HEIGHT;
        use crate::confirm::gui::window::opening_size;

        fn height_after_a_few_frames(raise: impl Fn(&Shelf) -> Receiver<Outcome>) -> f32 {
            let mut shelf = Shelf::open();
            shelf.settle();
            let _held = raise(&shelf);
            // Enough that a frame runs on what the frame before it measured, which is where the
            // feedback lives.
            for _ in 0..4 {
                shelf.frame(Vec::new());
            }
            shelf
                .app
                .prompt
                .as_ref()
                .expect("the prompt is still up")
                .height
        }

        let bar = height_after_a_few_frames(Shelf::queue_live_bar);
        assert_eq!(
            bar,
            opening_size(Chrome::Bar).1,
            "the launcher bar grew to its content; the URN bar is a fixed strip, and the feedback              turns it into a small dialog on its second frame"
        );
        assert_eq!(
            bar, BAR_HEIGHT,
            "the bar no longer opens at a bar's height, so holding it to its opening height proves              nothing about what it is"
        );

        let dialog = height_after_a_few_frames(Shelf::queue_live_prompt);
        assert_ne!(
            dialog,
            opening_size(Chrome::Dialog).1,
            "a dialog's height never moved off the value it opened at, so the shell is measuring              nothing and 'the bar did not grow' is a statement about a loop that is not running"
        );
    }

    /// **A launcher bar sits HIGH in the window; a dialog is centred.**
    ///
    /// A launcher is placed above the vertical centre — `SPEC.md` §3.1c-i, and what
    /// [`super::PromptApp::place_bar`] does against the monitor. In-window the same arithmetic runs
    /// against the window, via the same [`super::bar_top`], so the bar lands in the same place
    /// relative to whatever it is inside of.
    ///
    /// Pinned to the shared function rather than to a number, and paired with the dialog control:
    /// "above the centre" is also true of a bar pinned to the top edge, which would read as a
    /// notification bar rather than a launcher.
    #[test]
    fn a_launcher_bar_in_the_window_sits_high_and_a_dialog_does_not() {
        use crate::confirm::gui::render::BAR_HEIGHT;

        let window = Rect::from_min_size(egui::Pos2::ZERO, Vec2::new(1400.0, 1000.0));
        let bar = modal_rect(window, Chrome::Bar, BAR_HEIGHT);

        assert!(
            bar.center().y < window.center().y,
            "the launcher at {bar:?} is at or below the middle of the window"
        );
        assert_eq!(
            bar.center().y,
            window.top() + crate::confirm::gui::render::bar_top(window.height()) + BAR_HEIGHT / 2.0,
            "the in-window launcher is not placed by the same `bar_top` the standalone one uses"
        );
        assert!(
            window.contains_rect(bar),
            "the launcher at {bar:?} left the window"
        );

        let dialog = modal_rect(window, Chrome::Dialog, crate::confirm::gui::window::HEIGHT);
        assert_eq!(
            dialog.center(),
            window.center(),
            "a dialog stopped being centred, so the bar's placement is not distinguishable"
        );
    }

    /// **A bar shorter than the window still fits when the window is tiny.**
    ///
    /// The clamp, from the side that can actually go wrong: at [`SHELL_MIN`] the window is 480 tall
    /// and `bar_top` plus the bar's own height can put its bottom edge past the frame, which is a
    /// launcher whose field is off-screen.
    #[test]
    fn a_launcher_bar_stays_inside_a_window_at_its_minimum() {
        use crate::confirm::gui::render::BAR_HEIGHT;

        let window = Rect::from_min_size(egui::Pos2::ZERO, Vec2::splat(SHELL_MIN));
        let bar = modal_rect(window, Chrome::Bar, BAR_HEIGHT);
        assert!(
            window.contains_rect(bar),
            "the launcher at {bar:?} left a {SHELL_MIN}-square window"
        );
    }

    /// **Clicking the dimmed window closes the launcher — and never a consent dialog.**
    ///
    /// A launcher is dismissed by clicking away from it. Standalone that means its own window lost
    /// focus; in-window the exact counterpart is the SCRIM, which IS the rest of the window. Without
    /// this the Alt+Space bar could only be closed with Escape, silently losing the gesture it is
    /// built around.
    ///
    /// The dialog half is the one that matters for safety and is asserted in the same test, on the
    /// same gesture: a consent surface must NOT vanish because somebody clicked elsewhere, and the
    /// flag that separates them ([`Chrome::dismiss_on_blur`]) is false for every dialog.
    #[test]
    fn clicking_away_closes_a_launcher_bar_but_never_a_consent_dialog() {
        let mut shelf = Shelf::open();
        shelf.settle();
        let bar = shelf.queue_live_bar();
        shelf.frame(Vec::new());
        shelf.frame(Vec::new());
        assert!(shelf.app.prompt.is_some(), "the launcher is up");

        shelf.click(clicked_away());
        assert!(
            shelf.app.prompt.is_none(),
            "clicking away from the launcher did not close it"
        );
        assert!(
            matches!(bar.try_recv(), Ok(Outcome::Input(InputOutcome::Cancelled))),
            "the dismissed launcher did not report a cancellation to its caller"
        );
    }

    /// **…and the same click never dismisses a consent dialog.**
    ///
    /// The half that matters for safety, and a SEPARATE test rather than a second act of the one
    /// above: a `Shelf` holds the consent-surface exclusion for its whole life, so two of them in one
    /// test can never make progress. (Measured — the exclusion says so by name now.)
    ///
    /// A consent surface must not vanish because somebody clicked elsewhere.
    /// [`Chrome::dismiss_on_blur`] is what separates the two, and it is `false` for every dialog.
    #[test]
    fn clicking_away_never_dismisses_a_consent_dialog() {
        let mut shelf = Shelf::open();
        shelf.settle();
        let dialog = shelf.queue_live_prompt();
        shelf.frame(Vec::new());
        shelf.frame(Vec::new());

        shelf.click(clicked_away());
        assert!(
            shelf.app.prompt.is_some(),
            "a click on the dimmed window dismissed a CONSENT prompt; a spend request must not \
             vanish because somebody clicked elsewhere"
        );
        assert!(
            matches!(dialog.try_recv(), Err(TryRecvError::Empty)),
            "the click answered the consent prompt on the person's behalf"
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

    /// **The three layers are stacked shell < scrim < modal, and that is asserted as DATA.**
    ///
    /// # Why data and not a consequence
    ///
    /// Because the consequence is not currently observable, which was MEASURED. Demoting the scrim
    /// to `Order::Background`, or the modal to `Order::Foreground`, changes no behaviour any other
    /// test in this module can see: within one `Order`, egui stacks areas by creation, and
    /// `paint_shell` runs before `show_prompt`, so the intended stacking survives the mutation by
    /// accident. `read_response` cannot help either — it is layer-blind and reports a blocker under
    /// the panes exactly as it reports one over them.
    ///
    /// Relying on creation order is not a guarantee worth resting a consent surface on: it is
    /// invisible at the call sites, one reordered statement from being wrong, and — see the test
    /// below — egui promotes an area within its own `Order` when it is interacted with. So the
    /// separation is declared in distinct `Order`s and pinned here, as the two values, plus the
    /// relation between them so a future pair that happened to compare equal cannot pass.
    #[test]
    fn the_modal_sits_in_a_layer_strictly_above_the_scrim() {
        let mut shelf = Shelf::open();
        shelf.settle();
        let _answers = shelf.queue_live_prompt();
        shelf.frame(Vec::new());
        shelf.frame(Vec::new());

        // egui has no "which order is this area in?" query, so each expected (order, id) PAIR is
        // asked for by name: a demoted area is simply not visible under the pair named here.
        let drawn = |order, id: &str| {
            shelf.ctx.memory(|m| {
                m.areas()
                    .is_visible(&egui::LayerId::new(order, egui::Id::new(id)))
            })
        };

        assert!(
            drawn(egui::Order::Background, "dig-app-shell"),
            "the shell is not in Background, so the two assertions below are measured against              something other than the shipped stack"
        );
        assert!(
            drawn(egui::Order::Foreground, "dig-app-shell-scrim"),
            "the scrim left Order::Foreground; it no longer sits above the shell it makes inert"
        );
        assert!(
            drawn(egui::Order::Tooltip, "dig-app-shell-modal"),
            "the modal left Order::Tooltip — it and the scrim would then be separated only by the              order the two are painted in, which is one reordered statement, or one click on the              scrim, from leaving the consent surface unanswerable"
        );
        assert!(
            egui::Order::Background < egui::Order::Foreground
                && egui::Order::Foreground < egui::Order::Tooltip,
            "the three orders named above no longer stack shell < scrim < modal"
        );
    }

    /// **A click on the scrim does not make the modal unclickable.**
    ///
    /// The behavioural consequence of the rule above, and the reason it is not merely tidy. egui
    /// promotes an area to the front OF ITS OWN `Order` when the pointer interacts with it — so if
    /// the scrim and the modal shared an `Order`, one click on the dimmed area would lift the
    /// full-window blocker over the modal and the consent surface would stop answering the mouse
    /// entirely, with every other test in this file still green.
    ///
    /// The gesture is an ordinary one: a person clicks the greyed-out window, nothing happens
    /// (correctly), and then they go to the button.
    #[test]
    fn clicking_the_scrim_first_leaves_the_modal_answerable() {
        let mut shelf = Shelf::open();
        shelf.settle();
        let answers = shelf.queue_live_prompt();
        shelf.frame(Vec::new());
        let output = shelf.frame(Vec::new());
        let sign = where_text_landed(&output, "Sign");

        // A corner: inside the window, outside the modal, so it lands on the scrim and nothing else.
        shelf.click(egui::Pos2::new(4.0, SHELL_HEIGHT - 4.0));
        assert!(
            shelf.app.prompt.is_some(),
            "the click on the scrim answered or dismissed the prompt, which no click outside the              modal may do"
        );

        shelf.click(sign.center());
        assert!(
            matches!(
                answers.try_recv(),
                Ok(Outcome::Confirm(WindowIntent::Approve))
            ),
            "after one click on the scrim, the modal's Sign button no longer answers; the consent              surface is unanswerable by pointer"
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
                let at = modal_rect(window, Chrome::Dialog, height);
                assert!(
                    window.contains_rect(at),
                    "a {height}-tall modal at {at:?} left a {size:?} window"
                );
                assert!(
                    at.width() < window.width() && at.height() < window.height(),
                    "a {height}-tall modal at {at:?} fills a {size:?} window edge to edge, so no                      scrim is visible around it"
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
        let at = modal_rect(window, Chrome::Dialog, HEIGHT);
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
        let at = modal_rect(
            window,
            super::Chrome::Dialog,
            crate::confirm::gui::window::HEIGHT,
        );
        assert!(
            window.contains_rect(at),
            "the modal at {at:?} left the window"
        );

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

    /// **All three window controls exist and each one does its own thing** (dig_ecosystem#2569).
    ///
    /// The window is undecorated, so a control that is not drawn here is a thing the person cannot
    /// do at all — and before this it could not be minimised or maximised by any means.
    ///
    /// Driven as real clicks on the pixels the chrome actually painted, and asserted on the
    /// VIEWPORT COMMANDS that leave the frame, because those are what the platform acts on. All
    /// three are exercised in one test on purpose: a per-control test passes for a chrome that
    /// sends the same command from every control, which is the nearest wrong implementation to a
    /// row of near-identical text controls.
    #[test]
    fn the_three_window_controls_each_send_their_own_command() {
        let mut shelf = Shelf::open();
        shelf.settle();

        assert!(
            shelf
                .press_chrome("Minimize")
                .contains(&egui::ViewportCommand::Minimized(true)),
            "the Minimize control did not ask the platform to minimise the window"
        );
        let maximize = shelf.press_chrome("Maximize");
        assert!(
            maximize.contains(&egui::ViewportCommand::Maximized(true)),
            "the Maximize control did not ask the platform to maximise the window: {maximize:?}"
        );
        assert!(
            !maximize.contains(&egui::ViewportCommand::Minimized(true)),
            "Maximize also minimised the window: {maximize:?}"
        );
        assert!(!shelf.app.closing, "nothing so far should have closed it");

        shelf.press_chrome("Close");
        assert!(shelf.app.closing, "the Close control no longer closes");
    }

    /// **A maximised window offers the way BACK, and pressing it un-maximises** (dig_ecosystem#2569).
    ///
    /// The load-bearing half of a maximise control is the second press. The fixture varies ONE
    /// thing — what the platform says about this window — and holds everything else, so a chrome
    /// that hardcoded `Maximized(true)` fails here while still passing the test above.
    ///
    /// `Restore` is asserted to be REACHABLE rather than merely returned by [`maximize_control`]: a
    /// name the chrome does not consult is not a name.
    #[test]
    fn a_maximised_window_offers_restore_and_restoring_un_maximises_it() {
        let mut shelf = Shelf::open();
        shelf.maximized = Some(true);
        shelf.settle();

        assert!(
            shelf.control_rect("Maximize").is_none(),
            "an already-maximised window still offers to maximise itself"
        );
        assert!(
            shelf.control_rect("Restore").is_some(),
            "a maximised window offers no way back"
        );

        let restore = shelf.press_chrome("Restore");
        assert!(
            restore.contains(&egui::ViewportCommand::Maximized(false)),
            "Restore did not un-maximise the window, so a maximised window has no way back: \
             {restore:?}"
        );
    }

    /// **Double-clicking the header toggles maximise, in both directions.**
    ///
    /// The gesture every platform's titlebar answers to, and the one a person tries before they go
    /// looking for a control. Both directions, for the reason the test above exists: a handler that
    /// only ever sends `Maximized(true)` satisfies the first half alone.
    #[test]
    fn double_clicking_the_header_toggles_maximise_both_ways() {
        for (reported, expected) in [(None, true), (Some(false), true), (Some(true), false)] {
            let mut shelf = Shelf::open();
            shelf.maximized = reported;
            shelf.settle();

            // Left of every control, on the drag strip, and clear of the brand mark.
            let at = egui::Pos2::new(shelf.size.x / 2.0, CHROME_HEIGHT / 2.0);
            shelf.frame(vec![egui::Event::PointerMoved(at)]);
            let mut commands = Vec::new();
            let mut collect = |output: egui::FullOutput| {
                if let Some(root) = output.viewport_output.get(&egui::ViewportId::ROOT) {
                    commands.extend(root.commands.clone());
                }
            };
            for _ in 0..2 {
                collect(shelf.frame(vec![egui::Event::PointerButton {
                    pos: at,
                    button: egui::PointerButton::Primary,
                    pressed: true,
                    modifiers: egui::Modifiers::default(),
                }]));
                collect(shelf.frame(vec![egui::Event::PointerButton {
                    pos: at,
                    button: egui::PointerButton::Primary,
                    pressed: false,
                    modifiers: egui::Modifiers::default(),
                }]));
            }
            collect(shelf.frame(Vec::new()));
            assert!(
                commands.contains(&egui::ViewportCommand::Maximized(expected)),
                "a double-click on the header of a window reported as maximized={reported:?} did \
                 not send Maximized({expected}): {commands:?}"
            );
        }
    }

    /// **Every chrome control keeps its own HIT AREA at the narrowest width the window allows.**
    ///
    /// Three icon controls in a 480 px bar. A control that overlaps its neighbour still draws and
    /// still senses; it simply answers for a click aimed at the other one, and the person aiming at
    /// Close presses Maximize.
    ///
    /// # Asserted on what SENSED, not on the slot rectangles and not on drawn ink
    ///
    /// An earlier version compared the rectangles [`ChromeSlots`] returns, and passed while the
    /// controls overlapped, because a text control allocated its OWN size from its label and merely
    /// STARTED at its slot. A later version measured painted words, which icons do not have. Both
    /// were proxies. What decides which control a click reaches is the rectangle each one
    /// interacted over, so that is what is read back here — through the same name a screen reader
    /// announces.
    #[test]
    fn no_two_chrome_controls_share_pixels_at_the_narrowest_width() {
        let mut shelf = Shelf::open();
        shelf.size = Vec2::new(SHELL_MIN, SHELL_HEIGHT);
        shelf.settle();

        let controls: Vec<(&str, Rect)> = ["Minimize", "Maximize", "Close"]
            .into_iter()
            .map(|name| {
                let at = shelf
                    .control_rect(name)
                    .unwrap_or_else(|| panic!("the chrome offered no {name:?} at {SHELL_MIN} px"));
                (name, at)
            })
            .collect();

        for (i, (name, rect)) in controls.iter().enumerate() {
            assert!(
                rect.right() <= SHELL_MIN && rect.left() >= 0.0,
                "the {name} control at {rect:?} is drawn outside the {SHELL_MIN} px bar"
            );
            assert!(
                rect.top() >= 0.0 && rect.bottom() <= CHROME_HEIGHT,
                "the {name} control at {rect:?} leaves the {CHROME_HEIGHT} px chrome band"
            );
            for (other, other_rect) in &controls[i + 1..] {
                assert!(
                    !rect.intersects(*other_rect),
                    "{name} at {rect:?} overlaps {other} at {other_rect:?}"
                );
            }
        }
    }

    /// **An icon control is at least as big a target as the words it replaced** (dig_ecosystem#2997).
    ///
    /// The rule this protects is `professional-ui`'s: turning a label into a glyph must not shrink
    /// what a person has to hit. The bound is taken from the control the change actually removed
    /// text from — a 30 px-tall slot — rather than from a number invented here, and BOTH dimensions
    /// are checked, because a 40x8 strip satisfies an area bound while being unhittable.
    #[test]
    fn every_icon_control_keeps_a_comfortable_hit_target() {
        let mut shelf = Shelf::open();
        shelf.size = Vec2::new(SHELL_MIN, SHELL_HEIGHT);
        shelf.settle();

        for name in ["Minimize", "Maximize", "Close"] {
            let at = shelf
                .control_rect(name)
                .unwrap_or_else(|| panic!("the chrome offered no {name:?} control"));
            assert!(
                at.width() >= CONTROL_HEIGHT && at.height() >= CONTROL_HEIGHT,
                "the {name} control is {}x{} px, under the {CONTROL_HEIGHT} px target it replaced",
                at.width(),
                at.height()
            );
        }
    }

    /// **The theme is no longer operated from the chrome, and the Settings pane operates it.**
    ///
    /// Two halves, and only together do they mean anything (dig_ecosystem#2997): a chrome that has
    /// dropped the toggle while nothing else offers one is a preference a person can no longer
    /// change, which is a worse outcome than the crowded header. So this asserts the control is
    /// GONE from the chrome and that the shell answers the Settings pane's request.
    #[test]
    fn the_theme_moved_out_of_the_chrome_and_into_settings() {
        let mut shelf = Shelf::open();
        shelf.settle();

        // Asserted on the PIXELS the chrome painted, not on whether a named control answers.
        // The toggle this replaced was a TEXT control and never carried a window-control name, so
        // asking for one by name would report it absent even when it was still there — a check that
        // passes against the very code it is supposed to reject.
        let in_chrome: Vec<String> = shelf
            .words()
            .into_iter()
            .filter(|(_, at)| at.top() < CHROME_HEIGHT)
            .map(|(said, _)| said)
            .collect();
        for gone in ["Dark theme", "Light theme"] {
            assert!(
                !in_chrome.iter().any(|said| said == gone),
                "the chrome still draws a {gone:?} control: {in_chrome:?}"
            );
        }

        let started = shelf.app.theme;
        pane::settings::appearance::Exchange::request(&shelf.ctx, started.toggled());
        shelf.settle();
        assert_eq!(
            shelf.app.theme,
            started.toggled(),
            "the shell ignored the theme the Settings pane recorded"
        );
        assert_eq!(
            pane::settings::appearance::Exchange::in_force_now(&shelf.ctx),
            Some(started.toggled()),
            "the shell did not republish the theme it is painting, so the chooser cannot show it"
        );
    }

    /// **Each slot is disjoint from the others and the drag strip clears them all.**
    ///
    /// Derived from the leftmost control rather than declared, so it cannot come to overlap one. On
    /// an undecorated window a strip laid over Close is how Close stops working — and the converse,
    /// a strip of zero width, is a window that cannot be moved.
    #[test]
    fn every_chrome_slot_is_disjoint_and_the_drag_strip_clears_them_all() {
        let bar = Rect::from_min_size(egui::Pos2::ZERO, Vec2::new(SHELL_MIN, CHROME_HEIGHT));
        let slots = ChromeSlots::lay_out(bar);

        let controls = slots.controls();
        for (i, (name, rect)) in controls.iter().enumerate() {
            assert!(
                bar.contains_rect(*rect),
                "the {name} slot {rect:?} is not inside the {bar:?} bar"
            );
            for (other, other_rect) in &controls[i + 1..] {
                assert!(
                    !rect.intersects(*other_rect),
                    "the {name} slot {rect:?} overlaps the {other} slot {other_rect:?}"
                );
            }
        }

        for (name, rect) in slots.controls() {
            assert!(
                !slots.drag.intersects(rect),
                "the drag strip {:?} swallows the {name} control's hit area at {rect:?}",
                slots.drag
            );
        }
        assert!(
            slots.drag.width() > 0.0,
            "there is nowhere left to drag the window by its header at {SHELL_MIN} px"
        );
    }

    /// **The maximise control is labelled with what it will DO, never with the state it is in.**
    ///
    /// A control that says `Maximize` on an already-maximised window offers no way back, which is
    /// the trap in a smaller shape. The unreported case defaults to the recoverable direction.
    #[test]
    fn the_maximise_label_names_the_action_and_not_the_state() {
        assert_eq!(maximize_control(false).1, "Maximize");
        assert_eq!(maximize_control(true).1, "Restore");
        assert_ne!(maximize_control(true), maximize_control(false));

        let ctx = egui::Context::default();
        let _ = ctx.run(egui::RawInput::default(), |_| {});
        assert!(
            !window_is_maximized(&ctx),
            "a host that reports nothing must read as not maximised, so its control offers the \
             direction a person can undo by dragging"
        );
    }
}
