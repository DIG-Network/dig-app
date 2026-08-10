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

/// The profile a user's consent was given under, captured BEFORE the prompt that asks for it and
/// presented again when the durable authority it authorizes is written (dig_ecosystem#2398).
///
/// # Why the write needs a witness of its own
///
/// A native confirm names the origin and the app, never a profile ([`SignPrompt`](crate::sign_policy)),
/// so the person answering it is consenting about whichever profile is active as they read it. The
/// record is written afterwards, under whichever profile is active by then. Those are the same profile
/// almost always and not by construction: `SetActiveProfile` reads the registry from disk and needs no
/// unlock, so it can land in between. What is written then is DURABLE authority — a whitelist grant, or
/// a pairing minting a channel token — created under B from consent given under A, while A, whose owner
/// actually said yes, is granted nothing.
///
/// The sign path re-asks its gate after the equivalent gap
/// ([`FrameRouter::handle_sign`](crate::loopback::FrameRouter)); this is the same check on the creating
/// side, and it is a PARAMETER rather than a remembered line so a call site added later cannot omit it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConsentedProfile(Option<String>);

impl ConsentedProfile {
    /// Read the profile now active, to be presented to the write that follows. Take this BEFORE
    /// raising the confirm — taken after, it witnesses nothing.
    pub(crate) fn reading(did: &LiveDid) -> Self {
        Self(did.get())
    }

    /// Whether `writing_as` is still the profile the consent was given under. A consent captured while
    /// LOCKED (`None`) matches nothing: no profile was named, so none can be said to have agreed.
    pub(crate) fn still_holds(&self, writing_as: &str) -> bool {
        self.0.as_deref() == Some(writing_as)
    }
}

/// Why a durable grant was not recorded.
///
/// Kept distinct from a bare [`SealError`](crate::sealer::SealError) because the two mean opposite
/// things to a caller: sealing failed because there is no unlocked profile (retry after unlocking),
/// whereas the profile MOVED, so the consent that was given does not apply to whoever is here now
/// and must be asked for again.
#[derive(Debug, thiserror::Error)]
pub enum ConsentError {
    /// The active profile changed between the confirm and the write. See [`ConsentedProfile`].
    #[error("the active profile changed between consent and the record it authorizes")]
    ProfileMoved,
    /// The record could not be sealed — in practice, a locked profile.
    #[error(transparent)]
    Seal(#[from] crate::sealer::SealError),
}

/// Whether a stored record tagged `entry_did` is one the profile named by `active` may ACT ON — the
/// question every authorization read asks before honouring a grant.
///
/// The companion to [`LiveDid`] for state that is unavoidably a COPY. A live handle keeps a derivation
/// current, but an in-memory map of granted pairings and connected origins cannot be re-derived — it is
/// the record of what a person consented to. Tagging each entry with the DID it was granted under, and
/// asking this before every lookup, is what stops a consent given under one profile authorizing under
/// the next (dig_ecosystem#2398 ADV-A1).
///
/// # Why a LOCKED account (`active` is `None`) authorizes NOTHING
///
/// It is tempting to read a lock as "no DID to disagree with, so let the operation that needs a key
/// refuse on its own". That reasoning holds only where the key is reached from the SAME read — and on
/// the sign path it is not. `handle_sign` gates on this, then calls the re-auth gate, which RE-UNLOCKS
/// the account into whichever profile is now active, and only then signs. So a locked "yes" here is a
/// grant made under profile A being honoured by a key belonging to profile B: the dapp is told it is
/// still connected, and gets back B's signature and B's public key.
///
/// The lock is reachable with a foreign profile active because a switch does not require an unlock —
/// `SetActiveProfile` reads the registry from disk and works deliberately while locked
/// ([`ProfileSession`](crate::account::profile_session::ProfileSession)). A locked account is therefore
/// not "the same profile, briefly quiet"; it is an account whose active profile can change without
/// anyone authenticating. Answering `false` costs a locked caller nothing it was entitled to.
///
/// Use [`visible_under_active_profile`] where the answer only DISPLAYS a record.
pub(crate) fn belongs_to_active_profile(active: Option<&str>, entry_did: &str) -> bool {
    active == Some(entry_did)
}

/// Whether a record tagged `entry_did` should be SHOWN to whoever is at the machine, and offered to
/// them to manage.
///
/// Deliberately permissive where [`belongs_to_active_profile`] is closed: a locked account shows its
/// records rather than an empty list, because a person who locked their screen and came back should
/// see the apps they paired instead of being told there are none. Showing a row grants nothing — every
/// path that acts on it asks the authorization predicate above.
pub(crate) fn visible_under_active_profile(active: Option<&str>, entry_did: &str) -> bool {
    // `Option::is_none_or` would read better but is stable only since 1.82; this crate's MSRV is 1.75.
    active.map_or(true, |active| active == entry_did)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    /// A record authorizes for the profile that granted it and for nobody else — INCLUDING a locked
    /// account, whose active profile can be changed by anyone at the machine without authenticating.
    ///
    /// The locked case is the load-bearing one: it is the case the sign path reaches with a foreign
    /// profile about to be unlocked underneath it.
    #[test]
    fn a_record_authorizes_only_for_the_profile_that_granted_it() {
        assert!(belongs_to_active_profile(Some("did:chia:a"), "did:chia:a"));
        assert!(!belongs_to_active_profile(Some("did:chia:b"), "did:chia:a"));
        assert!(
            !belongs_to_active_profile(None, "did:chia:a"),
            "a locked account authorizes nothing: the re-auth gate unlocks into whichever profile is \
             active by then, so a `true` here is A's consent honoured by B's key"
        );
    }

    /// Displaying a record is a different question, and answers YES while locked — the one place the
    /// permissive reading is correct, because showing a row hands out no authority.
    #[test]
    fn a_locked_account_still_sees_its_own_records() {
        assert!(visible_under_active_profile(None, "did:chia:a"));
        assert!(visible_under_active_profile(
            Some("did:chia:a"),
            "did:chia:a"
        ));
        assert!(
            !visible_under_active_profile(Some("did:chia:b"), "did:chia:a"),
            "control: visibility is still SCOPED — another profile's records stay hidden"
        );
    }

    /// A consent is held by the profile that was active when it was read, and by nobody else — the
    /// predicate the creating side asks before writing durable authority.
    ///
    /// The LOCKED reading is the load-bearing one and is asserted from BOTH sides: a consent taken
    /// while locked names no profile, so it can never come to hold for the profile that unlocks next.
    #[test]
    fn a_consent_holds_only_for_the_profile_it_was_read_under() {
        let a: LiveDid = "did:chia:a".into();
        let consent = ConsentedProfile::reading(&a);
        assert!(consent.still_holds("did:chia:a"));
        assert!(
            !consent.still_holds("did:chia:b"),
            "a switch between the confirm and the write means nobody here agreed to it"
        );

        let locked: LiveDid = Live::fixed(None);
        let while_locked = ConsentedProfile::reading(&locked);
        assert!(
            !while_locked.still_holds("did:chia:a"),
            "no profile was named, so none can be said to have consented"
        );
    }

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
