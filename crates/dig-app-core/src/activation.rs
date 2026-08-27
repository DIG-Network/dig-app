//! The `dig-app:` activation URI — an ALLOWLIST, not a parser (dig-app#296).
//!
//! # What this is, and why it is written defensively out of proportion to its size
//!
//! The installer registers `dig-app` as an OS URL scheme, so `"C:\Program Files\DIG\bin\dig-app.exe"
//! "%1"` runs whenever anything on the machine navigates to `dig-app:<anything>`. A Windows toast
//! raised by this app uses that (`activationType="protocol"`), which is the right mechanism because
//! it survives a cold start — but the channel is **not private to the toast**. Any web page the user
//! visits can navigate to `dig-app:` with attacker-chosen text and the OS will hand that text to
//! this binary.
//!
//! So this module never *interprets* what arrives. It compares the whole thing, after the scheme,
//! against a fixed list of known route tokens, and answers `None` to everything else. There is no
//! query string, no fragment, no path segment and no percent-decoding, because a route that carried
//! a VALUE is the thing that turns a link into a one-click phishing primitive: the moment a URI can
//! name an amount or a destination, a page can pre-stage a transaction and the person only has to
//! press "yes". [`Route`] therefore names **views**, and only views.
//!
//! The consequence worth stating plainly: `dig-app:deposit?amount=5` is not "deposit with a
//! parameter", it is **unknown**, and unknown opens the ordinary first view. Rejecting by exact
//! comparison rather than by stripping the parts we dislike is what makes that true for inputs
//! nobody thought of, including percent-encoded spellings such as `dig-app:%64eposit` — nothing here
//! decodes `%64`, so it simply is not `deposit`.
//!
//! An unknown route is never an error on screen. The app opens normally, and the text is logged with
//! the `?` (Debug) sigil, which escapes control characters — see the call site in `dig-app.rs`.
//!
//! # This is NOT [`crate::link`]
//!
//! [`crate::link`] maps `chia://`/`urn:dig:chia:` CONTENT links to the node's serve URL, a contract
//! owned by dig-node. This module carries no content, addresses nothing on the network, and never
//! leaves the process except as a [`TabId`]. They share a shape and nothing else.
//!
//! # Two entry points, one allowlist
//!
//! A person clicking the toast is usually a person whose dig-app is **already running**, and a
//! second launch stands down on the single-instance lock before any window exists
//! ([`crate::single_instance`]). A cold-start-only route would therefore be inert in exactly the
//! case it was built for. So the standing-down process leaves the route in a one-shot file
//! ([`hand_off`]) and the live instance takes it ([`take`]).
//!
//! **Every launch hands off, including the one that goes on to BE the live instance.** That is why
//! there is only one place a route is ever consumed — the tray tick's [`take`] — and therefore only
//! one allowlist reading, rather than a cold-start path and a warm path that can drift apart. It
//! costs a cold start one tick before the window appears, and buys the guarantee outright.
//!
//! Both entry points end at [`Route::from_token`]. That is deliberate and is the property
//! `both_entry_points_admit_the_same_set` pins: a file dropped in the brand directory by anything
//! else on the machine can express **exactly** what a URI can express, and no more.

use std::io::Read;
use std::path::{Path, PathBuf};

use crate::window_model::TabId;

/// The URL scheme the installer registers, with its colon. Compared case-insensitively, because the
/// OS does not promise a spelling.
pub const SCHEME_PREFIX: &str = "dig-app:";

/// The file a standing-down duplicate launch leaves for the live instance, inside the brand
/// directory that already holds the single-instance lock.
pub const HANDOFF_FILE_NAME: &str = "activation";

/// The most bytes [`take`] will read. A hand-off holds one short token; anything larger is not one,
/// and reading it to find that out would let a local file decide how much memory this app allocates.
const MAX_HANDOFF_BYTES: u64 = 64;

/// How long a hand-off stays worth honouring.
///
/// A hand-off is a person's click, and a click is answered now or not at all. Without a bound, one
/// written while no tray was running — a headless instance, a tray that failed to mount — would sit
/// on disk and open a window at some unrelated later launch, which reads as the app doing something
/// nobody asked for. Generous enough to cover a cold start's own start-up, short enough that nothing
/// surprising survives to the next one.
pub const MAX_HANDOFF_AGE: std::time::Duration = std::time::Duration::from_secs(60);

/// A view the activation URI is allowed to open.
///
/// Every variant must be a *destination*. Nothing here may move money, start a send, pre-fill an
/// amount or choose a recipient — see the module docs for why that is the whole design and not a
/// caution.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Route {
    /// Where money arrives: the Wallet view, showing this account's receiving address.
    ///
    /// Safe to reach from a link precisely because it is read-only — it displays an address the
    /// account already owns, and accepts no amount and no destination from anywhere.
    Deposit,
}

impl Route {
    /// The one canonical spelling of this route, and the only text [`hand_off`] ever writes.
    pub const fn token(self) -> &'static str {
        match self {
            Self::Deposit => "deposit",
        }
    }

    /// The allowlist itself: the route this token names, or nothing.
    ///
    /// ASCII-case-insensitive and otherwise **exact**. This is the single gate both entry points
    /// pass through.
    pub fn from_token(token: &str) -> Option<Self> {
        [Self::Deposit]
            .into_iter()
            .find(|route| token.eq_ignore_ascii_case(route.token()))
    }

    /// The window tab this route opens on.
    pub fn tab(self) -> TabId {
        match self {
            Self::Deposit => TabId::Wallet,
        }
    }
}

/// The route `arg` asks for, if `arg` is a `dig-app:` URI naming a known one.
///
/// Answers `None` for a non-`dig-app:` argument, so ordinary flags fall through untouched, and for
/// every `dig-app:` URI that is not exactly a known route.
///
/// The only shapes tolerated beyond the bare token are the two the OS itself may produce: an
/// authority-style `//` after the colon, and a single trailing `/`. Both are removed by comparison
/// of a fixed prefix and suffix — never by scanning for delimiters, which is how a stripper starts
/// accepting the parts it was meant to reject.
pub fn route_of(arg: &str) -> Option<Route> {
    let rest = strip_prefix_ignore_ascii_case(arg, SCHEME_PREFIX)?;
    let rest = rest.strip_prefix("//").unwrap_or(rest);
    let rest = rest.strip_suffix('/').unwrap_or(rest);
    Route::from_token(rest)
}

/// The first route named anywhere in `args` (which excludes `argv[0]`).
///
/// First rather than last: a launcher that appends its own arguments cannot displace the one the OS
/// handed over, and two routes in one launch is not a shape any caller produces.
pub fn requested<S: AsRef<str>>(args: &[S]) -> Option<Route> {
    args.iter().find_map(|arg| route_of(arg.as_ref()))
}

/// Where the one-shot hand-off lives for `brand_dir`.
pub fn handoff_path(brand_dir: &Path) -> PathBuf {
    brand_dir.join(HANDOFF_FILE_NAME)
}

/// Leave `route` for the dig-app that already owns `brand_dir`, then let this process exit.
///
/// Only ever writes [`Route::token`] — a value this module produced, never text that arrived from
/// outside — so the file cannot carry anything the allowlist has not already accepted once.
pub fn hand_off(brand_dir: &Path, route: Route) -> std::io::Result<()> {
    std::fs::create_dir_all(brand_dir)?;
    std::fs::write(handoff_path(brand_dir), route.token())
}

/// Take the pending hand-off for `brand_dir`, if there is one.
///
/// **One shot.** The file is removed whatever it contained, before the content is judged, so a file
/// that is not a route cannot make the live instance re-read it on every tick, and a route is
/// honoured exactly once rather than on every tick until the app closes.
///
/// The content is **not** trimmed, and that is the point rather than an omission: [`hand_off`]
/// writes exactly [`Route::token`], so trimming could only ever widen this gate beyond the URI gate
/// — and the two admitting different sets is the one thing this design must not allow.
///
/// A hand-off older than [`MAX_HANDOFF_AGE`] is consumed and ignored — see [`take_within`].
///
/// Every failure is `None` and silent by design: no hand-off is the overwhelmingly common case,
/// this runs on the tray tick, and there is no user on the other end of a message about it.
pub fn take(brand_dir: &Path) -> Option<Route> {
    take_within(brand_dir, MAX_HANDOFF_AGE)
}

/// [`take`], with the staleness bound named, so a test can pin both sides of it.
pub fn take_within(brand_dir: &Path, max_age: std::time::Duration) -> Option<Route> {
    let path = handoff_path(brand_dir);
    let contents = read_bounded(&path).filter(|_| age_of(&path) < max_age);
    let _ = std::fs::remove_file(&path);
    Route::from_token(&contents?)
}

/// How long ago `path` was last written, or [`Duration::MAX`](std::time::Duration::MAX) when the
/// host cannot say — an unanswerable age is treated as stale, so an unreadable timestamp can only
/// ever refuse a window, never open one.
fn age_of(path: &Path) -> std::time::Duration {
    std::fs::metadata(path)
        .and_then(|meta| meta.modified())
        .map(|written| written.elapsed().unwrap_or_default())
        .unwrap_or(std::time::Duration::MAX)
}

/// Read at most [`MAX_HANDOFF_BYTES`] of `path` as UTF-8, or nothing.
fn read_bounded(path: &Path) -> Option<String> {
    let file = std::fs::File::open(path).ok()?;
    let mut text = String::new();
    file.take(MAX_HANDOFF_BYTES)
        .read_to_string(&mut text)
        .ok()?;
    Some(text)
}

/// `s` without `prefix`, comparing the prefix without ASCII case.
///
/// `str::strip_prefix` is case-sensitive, and the OS does not promise the case it hands the scheme
/// back in. The slicing goes through `str::get`, so a multi-byte character straddling the prefix's
/// length answers `None` instead of panicking — `arg` is arbitrary text from off the machine.
fn strip_prefix_ignore_ascii_case<'a>(s: &'a str, prefix: &str) -> Option<&'a str> {
    let head = s.get(..prefix.len())?;
    let rest = s.get(prefix.len()..)?;
    head.eq_ignore_ascii_case(prefix).then_some(rest)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every input a test may throw at the gate, kept in one place so both entry points can be
    /// driven over the SAME list — see [`both_entry_points_admit_the_same_set`].
    ///
    /// Each entry is hostile in a different way on purpose. A table of near-misses of one kind
    /// (say, only unknown words) would pass against a gate that strips query strings, which is
    /// precisely the wrong implementation this list exists to reject.
    const HOSTILE: &[&str] = &[
        // A known route carrying a VALUE. The one-click phishing shape, and the reason the gate
        // compares rather than parses.
        "deposit?amount=100&to=xch1attacker",
        "deposit#amount=100",
        "deposit/../send",
        "deposit send",
        // Percent-encoded spellings of the known route. Nothing decodes them, so none is `deposit`.
        "%64eposit",
        "deposit%00",
        "deposit%20",
        // Shell and command metacharacters, in case anything ever reaches a command line.
        "deposit; calc.exe",
        "deposit && calc.exe",
        "deposit | calc.exe",
        "$(calc.exe)",
        "`calc.exe`",
        "\"deposit\"",
        "'deposit'",
        // Log and terminal injection.
        "deposit\nINFO fake log line",
        "deposit\r\nSet-Cookie: x",
        "deposit\u{001b}[2J",
        // Paths, which must never reach a file open.
        "../../../../Windows/System32/calc.exe",
        "C:\\Windows\\System32\\calc.exe",
        "file:///etc/passwd",
        // Structured text, in case anything ever reaches a deserializer.
        "{\"route\":\"deposit\"}",
        // Unknown words, including one that merely starts with a known route.
        "send",
        "depositx",
        "",
    ];

    // -- the allowlist ------------------------------------------------------------------------

    #[test]
    fn the_known_route_opens_the_wallet_view() {
        assert_eq!(route_of("dig-app:deposit"), Some(Route::Deposit));
        assert_eq!(Route::Deposit.tab(), TabId::Wallet);
    }

    /// The OS does not promise a spelling, and may hand back an authority-style form or a trailing
    /// slash. All of these are the same launch.
    #[test]
    fn the_spellings_the_os_may_produce_are_the_same_route() {
        for spelling in [
            "dig-app:deposit",
            "dig-app://deposit",
            "dig-app://deposit/",
            "dig-app:deposit/",
            "DIG-APP:Deposit",
            "Dig-App://DEPOSIT/",
        ] {
            assert_eq!(
                route_of(spelling),
                Some(Route::Deposit),
                "{spelling:?} is the deposit launch"
            );
        }
    }

    /// An ordinary argument is not an activation and must fall through to the existing argv
    /// handling rather than being consumed here.
    #[test]
    fn a_non_activation_argument_is_not_a_route() {
        for arg in ["--service", "-x", "deposit", "dig-app", "digapp:deposit"] {
            assert_eq!(route_of(arg), None, "{arg:?} is not a dig-app: URI");
        }
    }

    /// The whole security claim, over the whole table: **nothing** but the bare known token is a
    /// route, whichever way it is dressed up.
    #[test]
    fn no_hostile_uri_names_a_route() {
        for hostile in HOSTILE {
            let uri = format!("dig-app:{hostile}");
            assert_eq!(route_of(&uri), None, "{uri:?} must not name a route");
        }
    }

    /// A very long argument is answered by a comparison, not by an allocation proportional to it.
    #[test]
    fn an_enormous_uri_is_merely_unknown() {
        let uri = format!("dig-app:deposit{}", "A".repeat(1_000_000));
        assert_eq!(route_of(&uri), None);
    }

    /// The route the OS hands over is the one honoured, even when a launcher appends its own flags.
    #[test]
    fn the_route_is_found_among_other_arguments() {
        assert_eq!(
            requested(&["--service", "dig-app:deposit"]),
            Some(Route::Deposit)
        );
        assert_eq!(requested(&["--service", "-x"]), None);
        assert_eq!(requested::<&str>(&[]), None);
    }

    // -- the hand-off -------------------------------------------------------------------------

    fn brand_dir() -> tempfile::TempDir {
        tempfile::tempdir().expect("a temp brand directory")
    }

    #[test]
    fn a_handed_off_route_is_taken_by_the_live_instance() {
        let dir = brand_dir();
        hand_off(dir.path(), Route::Deposit).expect("the hand-off is written");
        assert_eq!(take(dir.path()), Some(Route::Deposit));
    }

    /// One shot: a route opens one window, not one per tick for the life of the process.
    #[test]
    fn a_taken_route_is_gone() {
        let dir = brand_dir();
        hand_off(dir.path(), Route::Deposit).expect("the hand-off is written");
        assert_eq!(take(dir.path()), Some(Route::Deposit));
        assert_eq!(take(dir.path()), None);
        assert!(!handoff_path(dir.path()).exists());
    }

    /// Both sides of the staleness bound, from one fixture: the same freshly-written hand-off is
    /// honoured under a generous bound and refused under a zero one. A bound checked only from the
    /// fresh side would pass against an implementation that never checks the age at all.
    #[test]
    fn a_stale_hand_off_is_consumed_and_ignored() {
        let dir = brand_dir();

        hand_off(dir.path(), Route::Deposit).expect("the hand-off is written");
        assert_eq!(
            take_within(dir.path(), std::time::Duration::ZERO),
            None,
            "nothing is fresh enough for a zero bound"
        );
        assert!(
            !handoff_path(dir.path()).exists(),
            "a stale hand-off is still consumed, or it is re-read on every tick"
        );

        hand_off(dir.path(), Route::Deposit).expect("the hand-off is written");
        assert_eq!(
            take_within(dir.path(), MAX_HANDOFF_AGE),
            Some(Route::Deposit),
            "a hand-off written a moment ago is a person's click"
        );
    }

    #[test]
    fn no_hand_off_is_not_an_error() {
        let dir = brand_dir();
        assert_eq!(take(dir.path()), None);
    }

    /// A hand-off file the app did not write is removed on the FIRST look, whatever it held.
    /// Without this, a local file that is not a route is re-read on every tick forever.
    #[test]
    fn an_unreadable_hand_off_is_consumed_rather_than_re_read() {
        let dir = brand_dir();
        std::fs::write(handoff_path(dir.path()), [0xff, 0xfe, 0xff]).expect("a non-utf8 file");
        assert_eq!(take(dir.path()), None);
        assert!(!handoff_path(dir.path()).exists());

        std::fs::write(handoff_path(dir.path()), "x".repeat(10_000)).expect("an enormous file");
        assert_eq!(take(dir.path()), None);
        assert!(!handoff_path(dir.path()).exists());
    }

    /// The property the two-entry-point design rests on.
    ///
    /// A file dropped in the brand directory by anything else on the machine must express
    /// **exactly** what a URI can express. Asserting the two answers are EQUAL — rather than that
    /// each is `None` — is what makes this load-bearing: it fails if either gate is loosened,
    /// including a future route added to one path only, and it cannot be satisfied by a filter
    /// placed at the wrong layer, because both readings are taken end to end.
    #[test]
    fn both_entry_points_admit_the_same_set() {
        let dir = brand_dir();
        for text in HOSTILE
            .iter()
            .copied()
            .chain(["deposit", "DEPOSIT", " deposit "])
        {
            let by_uri = route_of(&format!("dig-app:{text}"));

            std::fs::write(handoff_path(dir.path()), text).expect("a hand-off file");
            let by_file = take(dir.path());

            assert_eq!(
                by_uri, by_file,
                "the URI gate and the file gate disagree about {text:?}"
            );
        }
    }
}
