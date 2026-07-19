//! Event-driven wallet UI seam (#1008) — dig-app consumes the dig-wallet-backend event stream.
//!
//! dig-app does not poll wallet state; it SUBSCRIBES to the engine's [`WalletEvent`] stream (a
//! FILTERED view chosen with an [`EnumSet<EventKind>`]) and drives its UI reactively, event by
//! event. On a transport gap (the subscriber fell behind, or reconnected) it backfills the missed
//! range with [`CatchUp::catch_up`] ONCE, then resumes the live stream — the "event-driven, poll
//! only on a gap" contract owned by [`dig_events_protocol`].
//!
//! # The three seams (transport-injected, like [`crate::wallet::engine::WalletEngine`])
//!
//! - [`EventFeed`] — the live stream the app reads. Over IPC this is the engine's server-push of
//!   the subscribed [`EmittedEvent`]s; the concrete transport is injected so this module compiles
//!   and tests standalone. It yields a [`FeedItem`] per read.
//! - [`CatchUp`] — the backfill half (the canonical [`dig_events_protocol`] trait), implemented by
//!   the engine over the same transport; called once after a gap.
//! - [`EventSink`] — where recognized events land: the reactive [`WalletView`] state and the #970
//!   notification pipeline are sinks. The [`driver`] fans one event out to every sink.
//!
//! # Why the contract types are imported, never re-declared
//!
//! [`WalletEvent`], [`EventKind`], [`Cursor`], [`EmittedEvent`], and [`CatchUp`] come from the
//! canonical [`dig_events_protocol`] crate. Re-declaring them here would drift the ecosystem
//! (#1008 design rule); this module only CONSUMES them and adds the app-side driver + sinks.

pub mod driver;
pub mod view;

pub use driver::{run, EventDriver};
pub use view::WalletView;

// The canonical event contract, re-exported at the paths app code imports from `crate::events`.
pub use dig_events_protocol::{
    filter_events, CatchUp, Cursor, EmittedEvent, EnumSet, EventKind, SyncLifecycle, SyncStatus,
    WalletEvent,
};

use async_trait::async_trait;

/// One read from the live [`EventFeed`].
///
/// The feed is created with the subscriber's kind filter, so every [`FeedItem::Event`] already
/// matches it. Gap detection is a TRANSPORT concern — the feed reports [`FeedItem::Lagged`] when
/// the subscriber fell behind and must [`CatchUp`], never something the app derives from cursor
/// arithmetic (kind-filtering makes live cursors legitimately non-contiguous).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FeedItem {
    /// A live, filter-matching event with its monotonic cursor.
    Event(EmittedEvent),
    /// The subscriber fell behind (broadcast lag) or (re)connected: the app must backfill the
    /// missed range from its last cursor with [`CatchUp::catch_up`], then resume reading.
    Lagged,
    /// The stream closed for good (the engine went away / the session ended): stop the driver.
    Closed,
}

/// The live event stream the app reads (transport-injected).
///
/// The production implementation is dig-app's IPC session server-push; tests use an in-memory
/// scripted feed. `Send` so the driver can own it on a background task.
#[async_trait]
pub trait EventFeed: Send {
    /// Await the next item from the live stream.
    async fn recv(&mut self) -> FeedItem;
}

/// A destination for recognized events + the resync signal.
///
/// The reactive [`WalletView`] and the #970 notification pipeline each implement this; the
/// [`driver`] fans every applied event out to every sink and broadcasts [`EventSink::resync`] when
/// an unrecoverable gap forces a full re-sync. `Send + Sync` because the driver shares the sink set
/// across its async loop.
pub trait EventSink: Send + Sync {
    /// Apply one delivered event (update reactive state, enqueue a notification, …).
    fn apply(&self, event: &EmittedEvent);

    /// The incremental state was lost (a gap older than the engine's bounded catch-up window): the
    /// sink MUST discard incremental state and reload authoritatively. Default: no-op, for sinks
    /// (like a pure notifier) that hold no reconstructable state.
    fn resync(&self) {}
}
