//! [`Live<T>`] — a value that is RE-READ at the moment it is used, rather than copied once
//! (dig_ecosystem#2398).
//!
//! # Why a type, and not a discipline
//!
//! [`AccountResidency`](crate::account::residency::AccountResidency) already re-reads the unlocked
//! account and the active profile index on every operation, which is what makes a stale index
//! unrepresentable there rather than merely detectable. But the APP-SIGN assembly is built ONCE at
//! boot and moved onto a serving thread for the life of the process, so any plain `String`/`PathBuf`
//! it captured is frozen at the profile that was active at boot — and no switching code can reach the
//! thread to correct it.
//!
//! A frozen profile DID is not a cosmetic staleness. It makes dig-app advertise profile A's DID and
//! signing key over a channel the LIVE signer signs for profile B — a false DID→key binding published
//! to every paired dApp — and it seals new pairing/whitelist grants under B's DEK, with A's DID as
//! AAD, into A's directory. The per-profile directory exists precisely to keep those apart
//! ([`crate::account::boot::active_profile_id`]).
//!
//! `Live<T>` is the seam that closes it. A handle holds the *source* of the value rather than the
//! value, so "the DID this store seals under" is answered at seal time rather than at boot, and a
//! switch that happened in between is reflected instead of ignored.
//!
//! # What this seam does NOT make impossible
//!
//! It removes the STALENESS, not the interleaving. The DID and the DEK remain two separate reads —
//! `seal_as` consults the live DID, and the sealer independently resolves the active profile index and
//! derives that profile's key — so a switch landing between them still seals under one profile's DEK
//! tagged with the other's DID. The window is the width of two reads rather than the life of the
//! process, and the sealer is addressed by a raw DEK that never sees a DID, so nothing downstream can
//! detect the mismatch. Closing it for good needs the pair handed out from ONE acquisition; until then
//! this is a narrowing, and the doc-comments here say so rather than claiming an invariant.
//!
//! # Fixed is not a loophole
//!
//! [`Live::fixed`] exists for values that genuinely cannot move: a test's single-profile fixture, and
//! a headless assembly with no residency behind it. A fixed value is honest about being fixed, which
//! a captured `String` never was.

use std::fmt;
use std::path::{Path, PathBuf};
use std::sync::Arc;

/// A `T` obtained at the moment of use. See the [module docs](self).
pub struct Live<T>(Source<T>);

/// Where a [`Live`] value comes from.
enum Source<T> {
    /// A value that cannot move.
    Fixed(T),
    /// A reader consulted on every [`Live::get`].
    Read(Arc<dyn Fn() -> T + Send + Sync>),
}

impl<T: Clone> Live<T> {
    /// A value that cannot move — a fixture, or a host with nothing to move underneath it.
    pub fn fixed(value: T) -> Self {
        Self(Source::Fixed(value))
    }

    /// A value read afresh on every [`get`](Self::get). `read` MUST consult the live source (the
    /// residency, the profile session) rather than close over a copy, or this is a `fixed` value
    /// wearing a disguise.
    pub fn read(read: impl Fn() -> T + Send + Sync + 'static) -> Self {
        Self(Source::Read(Arc::new(read)))
    }

    /// The value, right now.
    pub fn get(&self) -> T {
        match &self.0 {
            Source::Fixed(value) => value.clone(),
            Source::Read(read) => read(),
        }
    }
}

impl<T> Clone for Live<T>
where
    T: Clone,
{
    fn clone(&self) -> Self {
        match &self.0 {
            Source::Fixed(value) => Self(Source::Fixed(value.clone())),
            Source::Read(read) => Self(Source::Read(Arc::clone(read))),
        }
    }
}

impl<T: Clone + fmt::Debug> fmt::Debug for Live<T> {
    /// Renders the value as it reads NOW, tagged with whether it can move — so a debug line can never
    /// be mistaken for evidence that a handle is following the active profile.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let kind = match &self.0 {
            Source::Fixed(_) => "fixed",
            Source::Read(_) => "live",
        };
        write!(f, "Live::{kind}({:?})", self.get())
    }
}

/// A profile DID that reads as `Some` while an account is unlocked and `None` once it locks — the
/// shape every per-profile sealing seam wants, because a locked account has no DID to seal under and
/// answering with a placeholder would seal real records under a name no profile owns.
pub type LiveDid = Live<Option<String>>;

impl From<&str> for LiveDid {
    fn from(did: &str) -> Self {
        Self::fixed(Some(did.to_owned()))
    }
}

impl From<String> for LiveDid {
    fn from(did: String) -> Self {
        Self::fixed(Some(did))
    }
}

/// The active profile's directory, reading as `None` once the account locks — the same shape as
/// [`LiveDid`] and for the same reason: the directory is keyed by the DID, so no DID means no
/// directory, and a fallback would put one profile's records under another's name.
pub type LiveProfileDir = Live<Option<PathBuf>>;

impl From<&Path> for LiveProfileDir {
    fn from(path: &Path) -> Self {
        Self::fixed(Some(path.to_path_buf()))
    }
}

impl From<PathBuf> for LiveProfileDir {
    fn from(path: PathBuf) -> Self {
        Self::fixed(Some(path))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    /// A fixed value answers the same thing forever; a live one answers what its source says NOW.
    ///
    /// The moving source is the whole point, so it is what the assertions are built around: the same
    /// handle is asked twice with a mutation in between, exactly as a serving thread asks a store
    /// either side of a profile switch. A `get` that cached would satisfy the first assertion and
    /// fail the second, which is the mistake this type exists to prevent.
    #[test]
    fn a_live_value_follows_its_source_while_a_fixed_one_cannot() {
        let source = Arc::new(AtomicUsize::new(1));
        let reader = Arc::clone(&source);
        let live = Live::read(move || reader.load(Ordering::SeqCst));
        let fixed = Live::fixed(1usize);

        assert_eq!(1, live.get());
        assert_eq!(1, fixed.get());

        source.store(2, Ordering::SeqCst);

        assert_eq!(2, live.get(), "a live value must re-read its source");
        assert_eq!(1, fixed.get(), "a fixed value must not invent a new one");
    }

    /// A CLONE of a live handle shares the source rather than snapshotting it.
    ///
    /// This is not incidental: the sign assembly clones its DID source into the pairing store, the
    /// whitelist store and the connect handle. A clone that captured the value at clone time would
    /// leave three handles frozen at boot while the original followed — the exact half-landed switch,
    /// reintroduced by the one operation the assembly performs most.
    #[test]
    fn cloning_a_live_handle_shares_the_source_rather_than_freezing_it() {
        let source = Arc::new(AtomicUsize::new(1));
        let reader = Arc::clone(&source);
        let original = Live::read(move || reader.load(Ordering::SeqCst));
        let clone = original.clone();

        source.store(7, Ordering::SeqCst);

        assert_eq!(7, clone.get(), "the clone froze at its own creation");
        assert_eq!(original.get(), clone.get());
    }

    /// The `From` conversions the fixtures rely on produce FIXED values, and say so when printed.
    #[test]
    fn the_conversions_produce_fixed_values_that_render_as_fixed() {
        let did: LiveDid = "did:chia:example".into();
        assert_eq!(Some("did:chia:example".to_owned()), did.get());
        assert!(format!("{did:?}").starts_with("Live::fixed("), "{did:?}");

        let dir: LiveProfileDir = Path::new("/tmp/profile").into();
        assert_eq!(Some(PathBuf::from("/tmp/profile")), dir.get());

        let live: LiveDid = Live::read(|| Some("did:chia:moves".to_owned()));
        assert!(format!("{live:?}").starts_with("Live::live("), "{live:?}");
    }
}
