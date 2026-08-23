//! What a live WalletConnect session IS, and where it is remembered.
//!
//! A session is the durable half of WalletConnect: the pairing string is used once and thrown away,
//! but the session it produces outlives it and — crucially — outlives a restart of the tray. A dapp
//! that reconnects expects the wallet to still know it. So sessions are persisted, and they are
//! persisted the same way every other custody-adjacent record in this app is: DIGOP1-sealed under the
//! active profile's DEK through the [`ProfileSealer`] seam (NC-2), never in plaintext.
//!
//! # Why the session key is sealed and the pairing key is not kept at all
//!
//! `sym_key` opens every future message on the session topic, so at rest it is exactly as sensitive
//! as a password and is sealed with the rest of the record. The PAIRING key is different: it is used
//! for one exchange and is then dead, so it is never written down. Keeping it would create a
//! long-lived secret with no remaining purpose, which is the definition of an unnecessary liability.
//!
//! # Cross-profile isolation
//!
//! A session belongs to the profile that approved it. The store seals under, and lists for, the
//! ACTIVE profile only — so switching profiles does not hand one identity's dapp connections to
//! another. That is the same rule [`crate::whitelist`] enforces for dapp origins, for the same reason.

use std::collections::HashMap;
use std::sync::Mutex;

use serde::{Deserialize, Serialize};

use crate::live::{ConsentError, ConsentedProfile, LiveDid};
use crate::sealer::{ProfileSealer, SealError};

/// How long a settled session lasts before the wallet stops honouring it, in seconds.
///
/// Seven days, which is what `@walletconnect/sign-client` proposes by default and what Sage settles
/// on. A wallet is free to settle SHORTER than the proposal, and a shorter default would be
/// defensible security — but a session that silently dies while the dapp believes it is live is a
/// worse experience than the extra days are worth, and the user can disconnect at any moment from
/// the tray. Extension is `wc_sessionExtend`, which a dapp asks for.
pub const SESSION_TTL_SECS: u64 = 7 * 24 * 60 * 60;

/// How a dapp described itself in its session proposal.
///
/// **Every field here is attacker-controlled**, which is why it is a distinct type rather than loose
/// strings on the session: anything drawn from it goes through the neutralising render in
/// [`super::journey`], never straight onto a consent window.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct DappMetadata {
    /// The dapp's self-declared name.
    pub name: String,
    /// Its self-declared description.
    pub description: String,
    /// Its self-declared URL. NOT a verified origin — WalletConnect has no channel that could
    /// verify one, which is precisely why the consent window must not present it as proof.
    pub url: String,
    /// Icon URLs it offered. Retained for completeness; nothing in the tray fetches them, because
    /// fetching a URL a stranger chose is a request this process should not be making.
    #[serde(default)]
    pub icons: Vec<String>,
}

/// One settled WalletConnect session, as persisted.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WcSession {
    /// The session topic — `sha256(sym_key)`, and the relay subscription this session lives on.
    pub topic: String,
    /// The symmetric key every message on `topic` is sealed under. Sealed at rest with the record.
    pub sym_key_hex: String,
    /// The profile DID that approved this session, and whose DEK seals it.
    pub profile_did: String,
    /// What the dapp said about itself. Attacker-controlled — see [`DappMetadata`].
    pub peer: DappMetadata,
    /// The CAIP-2 chains this session was settled for (e.g. `chia:mainnet`).
    pub chains: Vec<String>,
    /// The methods the wallet ADVERTISED at settle. A dapp is entitled to call these and nothing
    /// else; the list is stored rather than recomputed so a wallet upgrade cannot silently widen
    /// what an already-settled session may ask for.
    pub methods: Vec<String>,
    /// The account strings settled (CAIP-10, e.g. `chia:mainnet:xch1…`).
    pub accounts: Vec<String>,
    /// Unix seconds when the session was approved.
    pub connected_at: u64,
    /// Unix seconds after which the wallet stops honouring the session.
    pub expires_at: u64,
}

impl WcSession {
    /// Whether the session is still within its lifetime at `now`.
    ///
    /// Expiry is compared with `>=` rather than `>`: a session whose last valid second has arrived
    /// is over. The boundary is pinned from both sides by tests, because an off-by-one here silently
    /// extends every session by a second and nothing would ever notice.
    pub fn is_live_at(&self, now: u64) -> bool {
        now < self.expires_at
    }

    /// Whether the dapp is entitled to call `method` on this session.
    ///
    /// Read from the stored advertisement, never from the wallet's current capability list — see
    /// [`methods`](Self::methods).
    pub fn permits(&self, method: &str) -> bool {
        self.methods.iter().any(|m| m == method)
    }
}

/// The result of approving a session: the live record plus the sealed bytes the caller persists.
///
/// Same shape as [`GrantOutcome`](crate::whitelist::GrantOutcome), deliberately — the persistence
/// step is the caller's, so a store cannot half-write a record it has already gone live with.
pub struct SettleOutcome {
    /// The session now live in the store.
    pub session: WcSession,
    /// The DIGOP1-sealed [`WcSession`] bytes to write at rest.
    pub sealed_record: Vec<u8>,
}

/// Whether a disconnect reached disk.
///
/// The distinction is not pedantry: a locked profile cannot re-seal the remaining set, so the
/// session is gone for this run and BACK at the next start. A person told "disconnected" who then
/// finds the dapp reconnected has been lied to, so the caller is given the fact and says so.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DisconnectOutcome {
    /// Gone, and written down.
    Disconnected,
    /// Gone for this run only — the change could not be sealed.
    DisconnectedForThisRunOnly,
    /// There was no such session.
    NotFound,
}

impl DisconnectOutcome {
    /// Whether the dapp actually lost its session, durably or otherwise.
    pub fn lost_session(self) -> bool {
        matches!(self, Self::Disconnected | Self::DisconnectedForThisRunOnly)
    }
}

/// The per-profile store of settled WalletConnect sessions.
///
/// Interior-mutable behind a [`Mutex`] so the relay task and the tray journeys share one store
/// through an `Arc`, exactly as [`WhitelistStore`](crate::whitelist::WhitelistStore) is shared.
pub struct WcSessionStore<S: ProfileSealer> {
    sealer: S,
    /// Read at each operation rather than captured, so the store follows a profile switch instead of
    /// sealing new records under whoever was active when it was built.
    profile_did: LiveDid,
    live: Mutex<HashMap<String, WcSession>>,
}

impl<S: ProfileSealer> WcSessionStore<S> {
    /// Build a store sealing under `profile_did`'s DEK via `sealer`.
    pub fn new(sealer: S, profile_did: impl Into<LiveDid>) -> Self {
        Self {
            sealer,
            profile_did: profile_did.into(),
            live: Mutex::new(HashMap::new()),
        }
    }

    /// Read the profile a consent is about to be answered under. Taken BEFORE the approval window is
    /// raised and handed back to [`settle`](Self::settle).
    pub fn consent_now(&self) -> ConsentedProfile {
        ConsentedProfile::reading(&self.profile_did)
    }

    /// Record an APPROVED session. The caller has already obtained consent; this store never asks.
    ///
    /// `consent`, taken before the approval window, is what binds the session to the profile whose
    /// owner approved it — a profile switch landing mid-window is refused rather than recorded under
    /// whoever arrived.
    ///
    /// # Errors
    ///
    /// [`ConsentError::ProfileMoved`] if the active profile changed since `consent` was taken;
    /// [`ConsentError::Seal`] if the profile is locked. Nothing goes live on either error — sealing
    /// happens FIRST so a live session never exists without its durable counterpart.
    pub fn settle(
        &self,
        consent: &ConsentedProfile,
        session: WcSession,
    ) -> Result<SettleOutcome, ConsentError> {
        let profile_did = self.seal_as()?;
        if !consent.still_holds(&profile_did) {
            return Err(ConsentError::ProfileMoved);
        }
        let session = WcSession {
            profile_did: profile_did.clone(),
            ..session
        };
        let plaintext = serde_json::to_vec(&session).map_err(|e| SealError::Seal(e.to_string()))?;
        let sealed_record = self.sealer.seal(&profile_did, &plaintext)?;
        self.lock().insert(session.topic.clone(), session.clone());
        Ok(SettleOutcome {
            session,
            sealed_record,
        })
    }

    /// The session on `topic`, if it belongs to the active profile and has not expired at `now`.
    ///
    /// The expiry check lives HERE rather than at each call site on purpose: a lookup that returned
    /// expired sessions would put the burden of remembering to check on every future caller, and the
    /// one that forgot would be the one handling a signing request.
    pub fn live(&self, topic: &str, now: u64) -> Option<WcSession> {
        let active = self.profile_did.get()?;
        self.lock()
            .get(topic)
            .filter(|s| s.profile_did == active && s.is_live_at(now))
            .cloned()
    }

    /// Every live session of the active profile, oldest first.
    ///
    /// Ordered so the management list does not reshuffle between openings — a list whose rows move
    /// makes "remove number 2" mean different things a second apart.
    pub fn list(&self, now: u64) -> Vec<WcSession> {
        let Some(active) = self.profile_did.get() else {
            return Vec::new();
        };
        let mut all: Vec<WcSession> = self
            .lock()
            .values()
            .filter(|s| s.profile_did == active && s.is_live_at(now))
            .cloned()
            .collect();
        all.sort_by(|a, b| {
            a.connected_at
                .cmp(&b.connected_at)
                .then_with(|| a.topic.cmp(&b.topic))
        });
        all
    }

    /// Drop the session on `topic` and re-seal what remains.
    ///
    /// The live drop happens FIRST and unconditionally: a person who asked to disconnect must be
    /// disconnected even when the change cannot be written down. The return value tells the caller
    /// which of those two worlds it is in, so the confirmation can say the true thing.
    pub fn disconnect(&self, topic: &str) -> (DisconnectOutcome, Option<Vec<u8>>) {
        let removed = self.lock().remove(topic);
        if removed.is_none() {
            return (DisconnectOutcome::NotFound, None);
        }
        match self.seal_all() {
            Ok(sealed) => (DisconnectOutcome::Disconnected, Some(sealed)),
            Err(_) => (DisconnectOutcome::DisconnectedForThisRunOnly, None),
        }
    }

    /// Reinstate sessions read back from disk at start-up.
    ///
    /// Records belonging to another profile, and records already expired at `now`, are DROPPED rather
    /// than loaded: restoring an expired session would resurrect access the clock had already ended.
    pub fn restore(&self, sessions: Vec<WcSession>, now: u64) {
        let Some(active) = self.profile_did.get() else {
            return;
        };
        let mut live = self.lock();
        for session in sessions {
            if session.profile_did == active && session.is_live_at(now) {
                live.insert(session.topic.clone(), session);
            }
        }
    }

    /// Seal the whole remaining set for the caller to write.
    fn seal_all(&self) -> Result<Vec<u8>, ConsentError> {
        let profile_did = self.seal_as()?;
        let all: Vec<WcSession> = self.lock().values().cloned().collect();
        let plaintext = serde_json::to_vec(&all).map_err(|e| SealError::Seal(e.to_string()))?;
        Ok(self.sealer.seal(&profile_did, &plaintext)?)
    }

    /// The DID to seal under right now, or a fail-closed error when no profile is active.
    fn seal_as(&self) -> Result<String, SealError> {
        self.profile_did
            .get()
            .ok_or_else(|| SealError::Seal("no active profile — the account is locked".to_string()))
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<String, WcSession>> {
        self.live.lock().unwrap_or_else(|e| e.into_inner())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::FakeSealer;

    const MINE: &str = "did:chia:mine";
    const THEIRS: &str = "did:chia:theirs";

    /// A fixed instant every fixture is written against.
    ///
    /// Pinned rather than `now()`: a store keyed on wall-clock time reads every fixture expiry as
    /// long past, so a test written with small literals would exercise only the expired path while
    /// appearing to test establishment.
    const NOW: u64 = 1_800_000_000;

    fn store() -> WcSessionStore<FakeSealer> {
        WcSessionStore::new(FakeSealer::default(), MINE)
    }

    fn session(topic: &str, connected_at: u64) -> WcSession {
        WcSession {
            topic: topic.to_string(),
            sym_key_hex: "aa".repeat(32),
            profile_did: MINE.to_string(),
            peer: DappMetadata {
                name: format!("app-{topic}"),
                description: String::new(),
                url: format!("https://{topic}.example"),
                icons: Vec::new(),
            },
            chains: vec!["chia:mainnet".into()],
            methods: vec!["chip0002_connect".into()],
            accounts: vec!["chia:mainnet:xch1abc".into()],
            connected_at,
            expires_at: connected_at + SESSION_TTL_SECS,
        }
    }

    fn settle(store: &WcSessionStore<FakeSealer>, s: WcSession) {
        let consent = store.consent_now();
        store.settle(&consent, s).expect("settles");
    }

    #[test]
    fn a_settled_session_is_listed_and_findable() {
        let store = store();
        settle(&store, session("t1", NOW));
        assert_eq!(store.list(NOW).len(), 1);
        assert!(store.live("t1", NOW).is_some());
    }

    /// The expiry boundary, pinned from BOTH sides. A bound tested only from below can only confirm
    /// itself: `<=` and `<` agree everywhere except on the boundary second, so the at-bound case is
    /// the only fixture that can tell them apart.
    #[test]
    fn a_session_is_live_until_its_expiry_second_and_not_at_it() {
        let s = session("t1", NOW);
        let expiry = s.expires_at;
        assert!(s.is_live_at(expiry - 1), "one second before expiry is live");
        assert!(!s.is_live_at(expiry), "the expiry second itself is over");
        assert!(!s.is_live_at(expiry + 1));
    }

    #[test]
    fn an_expired_session_is_neither_listed_nor_found() {
        let store = store();
        let s = session("t1", NOW);
        let expiry = s.expires_at;
        settle(&store, s);
        assert!(store.list(expiry).is_empty());
        assert!(store.live("t1", expiry).is_none());
    }

    /// Cross-profile isolation, with a TRUTHFUL CONTROL beside the foreign record.
    ///
    /// A fixture holding only the foreign session would pass just as happily against a store that
    /// returns nothing at all, which is the nearest wrong implementation. Keeping one session that
    /// SHOULD be visible is what makes the filter's presence observable rather than its absence.
    #[test]
    fn another_profiles_session_is_invisible_while_this_profiles_is_not() {
        let store = store();
        settle(&store, session("mine", NOW));
        // Written directly through `restore`, because `settle` re-stamps the DID by design and so
        // cannot produce a foreign record — which is itself the property being relied on.
        let foreign = WcSession {
            profile_did: THEIRS.to_string(),
            ..session("theirs", NOW)
        };
        store.restore(vec![foreign], NOW);

        let listed: Vec<String> = store.list(NOW).into_iter().map(|s| s.topic).collect();
        assert_eq!(listed, vec!["mine".to_string()]);
        assert!(store.live("theirs", NOW).is_none());
        assert!(
            store.live("mine", NOW).is_some(),
            "the control must be visible"
        );
    }

    /// `settle` re-stamps the record with the ACTIVE profile, so a caller cannot smuggle a session
    /// in under someone else's identity by pre-filling the field.
    #[test]
    fn settling_records_the_active_profile_whatever_the_caller_supplied() {
        let store = store();
        let claimed = WcSession {
            profile_did: THEIRS.to_string(),
            ..session("t1", NOW)
        };
        let consent = store.consent_now();
        let out = store.settle(&consent, claimed).expect("settles");
        assert_eq!(out.session.profile_did, MINE);
    }

    /// Sealing happens FIRST, so a locked account leaves NOTHING live. The nearest wrong
    /// implementation inserts and then seals, which produces a session that works this run and
    /// vanishes at restart — the state a person cannot see and cannot revoke.
    #[test]
    fn a_locked_account_settles_nothing_at_all() {
        let sealer = FakeSealer::default();
        sealer.lock();
        let store = WcSessionStore::new(sealer, MINE);
        let consent = store.consent_now();
        assert!(store.settle(&consent, session("t1", NOW)).is_err());
        assert!(
            store.list(NOW).is_empty(),
            "nothing may be live without a sealed record"
        );
        assert!(store.live("t1", NOW).is_none());
    }

    #[test]
    fn disconnecting_a_session_removes_it_and_leaves_the_others() {
        let store = store();
        settle(&store, session("a", NOW));
        settle(&store, session("b", NOW + 1));
        let (outcome, sealed) = store.disconnect("a");
        assert_eq!(outcome, DisconnectOutcome::Disconnected);
        assert!(
            sealed.is_some(),
            "the remaining set is re-sealed for the caller to write"
        );
        let left: Vec<String> = store.list(NOW + 2).into_iter().map(|s| s.topic).collect();
        assert_eq!(left, vec!["b".to_string()]);
    }

    /// A locked account must still DROP the session — the person asked — while reporting that the
    /// change did not reach disk. Both halves matter: reporting durable would be a lie, and refusing
    /// to drop would leave a dapp connected after the person disconnected it.
    #[test]
    fn a_locked_account_disconnects_for_this_run_and_says_so() {
        let sealer = FakeSealer::default();
        let store = WcSessionStore::new(sealer, MINE);
        settle(&store, session("a", NOW));
        settle(&store, session("b", NOW + 1));
        // Lock only AFTER the sessions exist, which is the real sequence: connected, then idle-locked.
        store.sealer.lock();

        let (outcome, sealed) = store.disconnect("a");
        assert_eq!(outcome, DisconnectOutcome::DisconnectedForThisRunOnly);
        assert!(sealed.is_none());
        assert!(
            store.live("a", NOW).is_none(),
            "the person asked; it must be gone now"
        );
        assert!(
            store.live("b", NOW + 2).is_some(),
            "and only the one they named"
        );
    }

    #[test]
    fn disconnecting_something_that_was_never_connected_reports_not_found() {
        let store = store();
        let (outcome, sealed) = store.disconnect("nope");
        assert_eq!(outcome, DisconnectOutcome::NotFound);
        assert!(sealed.is_none());
        assert!(!outcome.lost_session());
    }

    /// Restore drops what the clock already ended and what belongs to somebody else, and keeps the
    /// one record that is neither — the control that makes the two filters observable.
    #[test]
    fn restore_reinstates_only_this_profiles_unexpired_sessions() {
        let store = store();
        let live_one = session("live", NOW);
        let expired = WcSession {
            expires_at: NOW - 1,
            ..session("expired", NOW - SESSION_TTL_SECS - 1)
        };
        let foreign = WcSession {
            profile_did: THEIRS.to_string(),
            ..session("foreign", NOW)
        };
        store.restore(vec![live_one, expired, foreign], NOW);

        let topics: Vec<String> = store.list(NOW).into_iter().map(|s| s.topic).collect();
        assert_eq!(topics, vec!["live".to_string()]);
    }

    /// The list is ordered oldest-first so rows do not reshuffle between openings — "disconnect
    /// number 2" must mean the same session a second apart. Inserted out of order so a store that
    /// simply returns its map's iteration order cannot pass.
    #[test]
    fn the_list_is_oldest_first_regardless_of_insertion_order() {
        let store = store();
        settle(&store, session("third", NOW + 200));
        settle(&store, session("first", NOW));
        settle(&store, session("second", NOW + 100));
        let topics: Vec<String> = store.list(NOW + 300).into_iter().map(|s| s.topic).collect();
        assert_eq!(topics, vec!["first", "second", "third"]);
    }

    /// `permits` reads what the SESSION settled, never today's capability list. The fixture is a
    /// session whose stored methods OMIT one the wallet globally supports: an implementation that
    /// consulted `SUPPORTED_METHODS` would allow it, and this is the only shape that can see that.
    #[test]
    fn a_session_permits_only_what_it_settled_not_what_the_wallet_can_do() {
        let s = session("t1", NOW);
        assert!(s.permits("chip0002_connect"), "the control it did settle");
        assert!(
            !s.permits(crate::walletconnect::request::METHOD_SIGN_MESSAGE),
            "a globally-supported method this session never settled must stay refused"
        );
        assert!(
            crate::walletconnect::SUPPORTED_METHODS
                .contains(&crate::walletconnect::request::METHOD_SIGN_MESSAGE),
            "the fixture is only meaningful while the wallet does support it globally"
        );
    }

    /// A session record must survive the round trip through the sealed store's own serialisation,
    /// including the key it needs to keep talking. A record that lost `sym_key_hex` at rest would
    /// restore into a session that cannot open a single message.
    #[test]
    fn a_session_round_trips_through_its_persisted_form() {
        let original = session("t1", NOW);
        let json = serde_json::to_vec(&original).unwrap();
        let back: WcSession = serde_json::from_slice(&json).unwrap();
        assert_eq!(back, original);
    }

    /// A locked profile yields no DID, and the store must fail closed rather than sealing under a
    /// placeholder or listing another profile's records.
    #[test]
    fn a_store_with_no_active_profile_lists_nothing_and_settles_nothing() {
        let store: WcSessionStore<FakeSealer> =
            WcSessionStore::new(FakeSealer::default(), LiveDid::from(String::new()));
        // An empty DID string still resolves, so drive the genuine no-profile case through `Live`.
        let absent = WcSessionStore::new(FakeSealer::default(), LiveDid::read(|| None));
        let consent = absent.consent_now();
        assert!(absent.settle(&consent, session("t1", NOW)).is_err());
        assert!(absent.list(NOW).is_empty());
        assert!(absent.live("t1", NOW).is_none());
        let _ = store;
    }
}
