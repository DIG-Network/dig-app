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
use std::fmt;
use std::sync::{Arc, Mutex};

use serde::{Deserialize, Serialize};

use crate::live::{ConsentError, ConsentedProfile, LiveDid};
use crate::loopback::persist::SealedRecordStore;
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
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
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

/// A [`Debug`] that REDACTS the session key.
///
/// `sym_key_hex` opens every message on the session topic, so a derived `Debug` would put it in the
/// output of any `{:?}` — a log line, a panic message, a test failure, an error chain. Nothing in
/// this module logs today, which is precisely why this is worth fixing now rather than after the
/// first `tracing::debug!(?session)` is added by someone who had no reason to suspect the field.
///
/// Everything else is shown, because the point of a `Debug` is to be usable: the topic identifies
/// the session, and the topic is a public value the relay already routes on.
impl fmt::Debug for WcSession {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("WcSession")
            .field("topic", &self.topic)
            .field("sym_key_hex", &"<redacted>")
            .field("profile_did", &self.profile_did)
            .field("peer", &self.peer)
            .field("chains", &self.chains)
            .field("methods", &self.methods)
            .field("accounts", &self.accounts)
            .field("connected_at", &self.connected_at)
            .field("expires_at", &self.expires_at)
            .finish()
    }
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
/// # It is wired (dig-app#262)
///
/// This type carried a "NOT YET WIRED" notice for as long as every constructor call was in a test:
/// the tray held its settled sessions in the [`WcClient`](super::client::WcClient) for the run of
/// the app and wrote nothing to disk, so sessions were not sealed at rest and did not survive a
/// restart. That is no longer true. The production assembly is
/// `sign_service::build_wc_sessions`, called at profile unlock beside
/// [`build_router`](crate::sign_service::build_router), and the client reaches it through the
/// [`WcSessions`](super::client::WcSessions) seam.
///
/// The old notice ended *"do not cite this type as evidence that sealing runs — cite the call site,
/// once there is one"*, and that instruction still stands: the call site is
/// `crates/dig-app/src/bin/dig-app.rs`'s profile-unlock path, and the seam it installs is what makes
/// the guarantee live rather than merely implemented.
///
/// The contract is unchanged: seal BEFORE going live so a live session never outlives its durable
/// record, scope every read to the active profile, and drop expired or foreign records on restore.
///
/// Interior-mutable behind a [`Mutex`] so the relay task and the tray journeys share one store
/// through an `Arc`, exactly as [`WhitelistStore`](crate::whitelist::WhitelistStore) is shared.
pub struct WcSessionStore<S: ProfileSealer> {
    sealer: S,
    /// Read at each operation rather than captured, so the store follows a profile switch instead of
    /// sealing new records under whoever was active when it was built.
    profile_did: LiveDid,
    live: Mutex<HashMap<String, WcSession>>,
    /// Where sealed records are written and read back. `None` on a store with no persistence —
    /// every existing unit test, and a headless host with no per-profile directory — in which case
    /// the store behaves exactly as it always did and sessions last one run.
    at_rest: Option<Arc<dyn SealedRecordStore>>,
}

impl<S: ProfileSealer> WcSessionStore<S> {
    /// Build a store sealing under `profile_did`'s DEK via `sealer`.
    pub fn new(sealer: S, profile_did: impl Into<LiveDid>) -> Self {
        Self {
            sealer,
            profile_did: profile_did.into(),
            live: Mutex::new(HashMap::new()),
            at_rest: None,
        }
    }

    /// Write sealed records through `store`, and read them back from it on
    /// [`restore_at_rest`](Self::restore_at_rest).
    ///
    /// Mirrors [`FrameRouter::with_persistence`](crate::loopback::FrameRouter::with_persistence) so
    /// the two custody-adjacent stores in this app are assembled the same way — one place to look
    /// for how a sealed record reaches disk.
    #[must_use]
    pub fn with_persistence(mut self, store: Arc<dyn SealedRecordStore>) -> Self {
        self.at_rest = Some(store);
        self
    }

    /// Reinstate the sessions on disk that belong to the ACTIVE profile and are live at `now`.
    ///
    /// # Three filters, and each drops a different thing for a different reason
    ///
    /// * **A record that will not OPEN is dropped.** [`ProfileSealer::open`] fails on ciphertext
    ///   sealed under a different DEK, which is what makes cross-profile isolation a property of
    ///   the cryptography rather than of a comparison somebody remembered to write. It fails the
    ///   same way on a corrupted or truncated record — so a damaged file yields no session rather
    ///   than a partly-trusted one. **There is no unsealed fallback and there must never be one.**
    /// * **A record that will not PARSE is dropped**, because a `WcSession` this app cannot read is
    ///   one it cannot honour, and inventing defaults for its missing fields would invent an expiry
    ///   or a method list.
    /// * **A foreign or expired record is dropped by [`restore`](Self::restore)**, which already
    ///   holds those two rules. They are applied there rather than repeated here so there is one
    ///   answer to *may this session be live*.
    ///
    /// The DID check is therefore belt AND braces: opening already proves the DEK, and `restore`
    /// re-checks the name. Both are kept because they fail independently — a record could in
    /// principle be sealed under the right DEK and carry the wrong name, which is exactly the
    /// mismatch `seal_bound` was introduced to make unexpressible (dig-app#255).
    ///
    /// A locked account restores NOTHING: with no active profile there is no DEK to open anything
    /// with, and that is the fail-closed direction.
    pub fn restore_at_rest(&self, now: u64) {
        let Some(store) = self.at_rest.as_ref() else {
            return;
        };
        let Some(active) = self.profile_did.get() else {
            return;
        };
        let sessions = store
            .load()
            .sessions
            .into_iter()
            .filter_map(|sealed| self.sealer.open(&active, &sealed).ok())
            .filter_map(|plaintext| serde_json::from_slice::<WcSession>(&plaintext).ok())
            .collect();
        self.restore(sessions, now);
    }

    /// Every live session of the active profile, for handing to the in-memory client.
    ///
    /// A named accessor rather than a second call to [`list`](Self::list) at the call site, so the
    /// restore path and the management list cannot come to disagree about what "live" means.
    pub fn live_sessions(&self, now: u64) -> Vec<WcSession> {
        self.list(now)
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
        // `seal_bound`, not `seal`: the DID and the sealer's DEK used to be two independent
        // reads, so a switch landing between them tagged one profile's key with the other's
        // name — undetectable downstream (dig-app#255). The sealer now re-resolves the DID
        // from the acquisition that yields the key and refuses when they disagree.
        let sealed_record = self.sealer.seal_bound(&profile_did, &plaintext)?;
        // Written BEFORE the session goes live, for the reason the sealing itself happens first: a
        // live session that has no durable record is one the dapp can use and the person cannot
        // find again after a restart. The write is best-effort by the store's contract — a failure
        // is logged and costs one session at the next boot — which is the direction that fails
        // closed (`SealedRecordStore`'s own docs state the asymmetry).
        if let Some(store) = self.at_rest.as_ref() {
            store.persist_session(&session.topic, &sealed_record);
        }
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
    /// # With persistence installed, the verdict comes from the DELETION and not from a re-seal
    ///
    /// Records are stored one file per session, so removing one is a file deletion and needs no
    /// key — where re-sealing the remaining set needs the DEK and therefore an unlocked profile.
    /// The two agree in both states that occur (unlocked: deleted and sealable; locked: neither),
    /// and where they could differ the DELETION is the fact that decides whether the dapp comes
    /// back at the next boot. So that is what the outcome is taken from.
    ///
    /// The re-seal still runs, because its `Err` is the honest signal on a store with NO
    /// persistence — there, nothing was ever written, and the outcome must not claim more than the
    /// old contract did.
    pub fn disconnect(&self, topic: &str) -> (DisconnectOutcome, Option<Vec<u8>>) {
        let removed = self.lock().remove(topic);
        if removed.is_none() {
            return (DisconnectOutcome::NotFound, None);
        }
        let sealed = self.seal_all();
        if let Some(store) = self.at_rest.as_ref() {
            return match store.remove_session(topic) {
                true => (DisconnectOutcome::Disconnected, sealed.ok()),
                // The sealed record is still on disk, so the dapp reconnects at the next boot. The
                // person has already been disconnected in this run and must be told exactly that
                // much and no more.
                false => (DisconnectOutcome::DisconnectedForThisRunOnly, None),
            };
        }
        match sealed {
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
        // `seal_bound`, not `seal`: the DID and the sealer's DEK used to be two independent
        // reads, so a switch landing between them tagged one profile's key with the other's
        // name — undetectable downstream (dig-app#255). The sealer now re-resolves the DID
        // from the acquisition that yields the key and refuses when they disagree.
        Ok(self.sealer.seal_bound(&profile_did, &plaintext)?)
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

    /// The session key must never reach a `Debug` rendering.
    ///
    /// The fixture uses a key that is DISTINCTIVE rather than the usual `aa`-repeat, so the
    /// assertion cannot pass by the value coincidentally not appearing; and it asserts the topic IS
    /// present, so a `Debug` that redacted everything — or one that had simply stopped working —
    /// could not pass either.
    #[test]
    fn the_session_key_is_redacted_from_debug_output() {
        let secret = "c0ffee".repeat(10) + "beef";
        let rendered = format!(
            "{:?}",
            WcSession {
                sym_key_hex: secret.clone(),
                ..session("t1", NOW)
            }
        );
        assert!(
            !rendered.contains(&secret),
            "the session key reached a Debug rendering: {rendered}"
        );
        assert!(rendered.contains("<redacted>"), "{rendered}");
        assert!(
            rendered.contains("t1"),
            "the topic must still be shown: {rendered}"
        );
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
    // ---------------------------------------------------------------------------------------
    // dig-app#262: the PRODUCTION path — sealed at rest, restored on start, scoped per profile.
    //
    // Every test above this line drives a store with no persistence, which is what the ticket was
    // filed about: a complete contract, fully tested, against code production never called. These
    // drive the assembly the app actually builds — `WcSessionStore::with_persistence` over a real
    // `FileSealedStore` on a real directory, opened by a real `AccountSealer` — so a regression in
    // the WIRING reddens them rather than passing under it.
    // ---------------------------------------------------------------------------------------

    use crate::loopback::persist::FileSealedStore;
    use crate::test_support::test_sealer;

    /// A store persisting into `dir`, sealing with `label`'s DEK under `did`.
    ///
    /// `test_sealer` is a REAL `AccountSealer` rather than [`FakeSealer`], deliberately: the
    /// isolation these tests assert is enforced by an AEAD tag, and a fake that compares a string
    /// prefix would prove a property the shipping code does not rely on.
    fn persisted(
        dir: &std::path::Path,
        label: &str,
        did: &str,
    ) -> WcSessionStore<crate::account::sealer::AccountSealer> {
        WcSessionStore::new(test_sealer(label), did)
            .with_persistence(Arc::new(FileSealedStore::new(dir.to_path_buf())))
    }

    fn settle_into<S: ProfileSealer>(store: &WcSessionStore<S>, s: WcSession) {
        let consent = store.consent_now();
        store.settle(&consent, s).expect("settles");
    }

    /// The topics a store lists, in its own order.
    fn topics<S: ProfileSealer>(store: &WcSessionStore<S>, now: u64) -> Vec<String> {
        store.list(now).iter().map(|s| s.topic.clone()).collect()
    }

    /// **A session created in one run is listed and usable after a restart.**
    ///
    /// The ticket's first acceptance criterion, driven through the production path: seal on settle,
    /// then build a SECOND store over the same directory and the same DEK — which is what a restart
    /// is — and restore from disk.
    ///
    /// The second store is a genuinely new object with an empty map, and that emptiness is asserted
    /// BEFORE the restore, so a pass cannot come from in-memory state surviving the test. Both
    /// `list` and `live` are checked, because they answer different questions: `list` is what a
    /// management window draws, `live` is what a signing request is validated against, and a
    /// restore that populated one without the other would show a person a row their dapp could not
    /// use.
    #[test]
    fn a_session_settled_in_one_run_is_listed_and_usable_after_a_restart() {
        let dir = tempfile::tempdir().unwrap();
        {
            let first_run = persisted(dir.path(), MINE, MINE);
            settle_into(&first_run, session("t1", NOW));
            assert_eq!(first_run.list(NOW).len(), 1);
        }

        let second_run = persisted(dir.path(), MINE, MINE);
        assert!(
            second_run.list(NOW).is_empty(),
            "a fresh store must start empty, or this test cannot tell a restore from a leak"
        );

        second_run.restore_at_rest(NOW);

        assert_eq!(
            topics(&second_run, NOW),
            vec!["t1".to_string()],
            "the session did not survive the restart"
        );
        assert!(
            second_run.live("t1", NOW).is_some(),
            "the session was listed but is not usable, so a dapp would be refused on a row the \
             person can see"
        );
    }

    /// **A session belonging to another profile is not listed, used, or restored.**
    ///
    /// Two profiles, two DEKs, ONE directory — which is the arrangement that actually needs a
    /// guard. Giving each profile its own directory would prove only that two directories are
    /// different, which no implementation can get wrong.
    ///
    /// All three verbs the ticket names are asserted, because they fail independently: `list` is
    /// the management window, `live` is the signing check, and `restore_at_rest` is the boot path.
    /// A store that filtered the first two and restored the foreign record anyway would hold a
    /// stranger's session key in memory behind two filters — which is one edit from being no
    /// filters.
    #[test]
    fn a_session_of_another_profile_is_not_listed_used_or_restored() {
        let dir = tempfile::tempdir().unwrap();
        {
            let theirs = persisted(dir.path(), THEIRS, THEIRS);
            settle_into(
                &theirs,
                WcSession {
                    profile_did: THEIRS.to_string(),
                    ..session("t1", NOW)
                },
            );
            assert_eq!(
                theirs.list(NOW).len(),
                1,
                "the fixture must have written a record, or the case below is vacuous"
            );
        }

        // The switch: same directory, a DIFFERENT profile's DEK and DID.
        let mine = persisted(dir.path(), MINE, MINE);
        mine.restore_at_rest(NOW);

        assert!(
            mine.list(NOW).is_empty(),
            "another profile's session was listed"
        );
        assert!(
            mine.live("t1", NOW).is_none(),
            "another profile's session was usable"
        );
    }

    /// **A record the app cannot open yields ZERO sessions, never an unsealed read.**
    ///
    /// The fail-closed rule, on a record that is genuinely undecryptable rather than merely
    /// mislabelled: the ciphertext is truncated, so the AEAD tag cannot verify however the DID
    /// compares. An implementation that fell back to reading the bytes would produce a session.
    ///
    /// The CONTROL matters as much as the case — the same directory with the record intact does
    /// restore — because a test that only asserts emptiness passes just as happily on a restore
    /// path that never works at all.
    ///
    /// The wrong-DEK case is asserted beside the corruption case rather than instead of it: they
    /// take different routes through `open`, and only one of them is about the tag.
    #[test]
    fn an_unopenable_record_yields_no_sessions_rather_than_an_unsealed_read() {
        let dir = tempfile::tempdir().unwrap();
        {
            let first_run = persisted(dir.path(), MINE, MINE);
            settle_into(&first_run, session("t1", NOW));
        }

        let sealed_dir = dir.path().join("app-sign").join("wc-sessions");
        let record = std::fs::read_dir(&sealed_dir)
            .expect("the sealed session directory exists")
            .map(|entry| entry.unwrap().path())
            .next()
            .expect("one sealed record was written");

        let control = persisted(dir.path(), MINE, MINE);
        control.restore_at_rest(NOW);
        assert_eq!(
            control.list(NOW).len(),
            1,
            "the control must restore, or the cases below prove nothing"
        );

        let bytes = std::fs::read(&record).unwrap();
        std::fs::write(&record, &bytes[..bytes.len() / 2]).unwrap();

        let corrupted = persisted(dir.path(), MINE, MINE);
        corrupted.restore_at_rest(NOW);
        assert!(
            corrupted.list(NOW).is_empty(),
            "a record that cannot be opened produced a session anyway"
        );

        let wrong_key = persisted(dir.path(), THEIRS, MINE);
        wrong_key.restore_at_rest(NOW);
        assert!(
            wrong_key.list(NOW).is_empty(),
            "a record was opened under the wrong DEK"
        );
    }

    /// **A disconnect reaches disk, so the dapp does not come back at the next start.**
    ///
    /// The half of persistence whose failure is invisible within a single run: a disconnect that
    /// removed the session from memory only would report success, satisfy every in-run assertion,
    /// and reconnect the dapp at the next boot.
    ///
    /// TWO sessions, and only one is disconnected, so the test distinguishes *the right record was
    /// removed* from *the directory was emptied* — which an implementation that deleted the whole
    /// subdirectory would satisfy identically.
    #[test]
    fn a_disconnect_removes_the_record_at_rest_and_leaves_its_neighbour() {
        let dir = tempfile::tempdir().unwrap();
        {
            let first_run = persisted(dir.path(), MINE, MINE);
            settle_into(&first_run, session("t1", NOW));
            settle_into(&first_run, session("t2", NOW));
            let (outcome, _) = first_run.disconnect("t1");
            assert_eq!(
                outcome,
                DisconnectOutcome::Disconnected,
                "a disconnect that reached disk must say so"
            );
        }

        let second_run = persisted(dir.path(), MINE, MINE);
        second_run.restore_at_rest(NOW);
        assert_eq!(
            topics(&second_run, NOW),
            vec!["t2".to_string()],
            "the disconnected session came back, or its neighbour did not survive"
        );
    }

    /// An expired record is dropped on restore rather than resurrected.
    ///
    /// The clock is pinned from BOTH sides: one second short of the expiry it restores, at the
    /// expiry second it does not. A test written only against the far future would pass on a
    /// restore path that dropped everything.
    #[test]
    fn an_expired_record_is_dropped_on_restore_and_the_boundary_is_pinned() {
        let dir = tempfile::tempdir().unwrap();
        let expires_at = NOW + SESSION_TTL_SECS;
        {
            let first_run = persisted(dir.path(), MINE, MINE);
            settle_into(&first_run, session("t1", NOW));
        }

        let live = persisted(dir.path(), MINE, MINE);
        live.restore_at_rest(expires_at - 1);
        assert_eq!(
            live.list(expires_at - 1).len(),
            1,
            "a session one second short of its expiry is still live"
        );

        let expired = persisted(dir.path(), MINE, MINE);
        expired.restore_at_rest(expires_at);
        assert!(
            expired.list(expires_at).is_empty(),
            "a session at its expiry second was restored"
        );
    }
}
