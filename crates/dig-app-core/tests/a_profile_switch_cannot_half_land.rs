//! **A profile switch cannot half-land** (dig_ecosystem#2398).
//!
//! # The failure this exists to catch
//!
//! Switching profiles changes three things at once: the identity signing key, the per-profile DEK,
//! and the profile-scoped directory. If any ONE of them keeps deriving at the old index, the app is
//! signing as one identity while sealing under another's key, or writing one profile's data into
//! another's directory. That is not a cosmetic inconsistency — it is two identities sharing a state
//! they each believe is private.
//!
//! # Why the handles are RETAINED across the switch
//!
//! The dangerous handles are the ones nothing can reach. `bin/dig-app.rs` builds a signer and a
//! sealer at boot and moves them onto the sign-service thread for the process lifetime, so the
//! switching code cannot find them to update. **Re-fetching a signer after the switch would prove
//! nothing about those**: a design that captured the index at construction would hand out a correct
//! NEW signer while the serving thread went on signing as the old identity. So every handle here is
//! taken out BEFORE the switch and asserted on AFTER it.
//!
//! # Each mechanism is separately falsifiable
//!
//! Measured, not assumed. Each mechanism was reverted on its own and exactly one test went red:
//!
//! | reverted | red |
//! |---|---|
//! | `ResidencySigner` reads a captured `ProfileIx::ROOT` | `a_retained_identity_signer_follows_the_switch` |
//! | `ResidencySealer` reads a captured `ProfileIx::ROOT` | `a_retained_sealer_follows_the_switch_and_can_no_longer_open_the_old_profiles_blob` |
//! | `active_profile_id` pinned back to ROOT | `the_profile_directory_moves_but_the_account_scoped_id_does_not` |
//! | `build_router` captures the DID/dir as `String`/`PathBuf` | `a_retained_sealed_store_writes_into_the_directory_of_the_profile_now_active` + `a_retained_whitelist_store_records_the_profile_now_active` |
//!
//! # Re-fetching is not retaining, and one test here used to do it
//!
//! `the_profile_directory_moves_but_the_account_scoped_id_does_not` calls `active_profile_id` afresh
//! on both sides of the switch and retains no directory, so it can only prove that the FUNCTION
//! follows the active slot. It cannot see the assembly that had already copied its answer into a
//! `PathBuf` on the serving thread — which is exactly what shipped. The two tests added below retain
//! the store handles themselves, which is the only way to observe that layer.
//! The fourth mechanism — the fail-closed re-check inside the confirm ceremony — lives with the money
//! path and is proved the same way by
//! `account::money::tests::a_profile_switch_during_the_ceremony_signs_nothing`.

use std::sync::Arc;

use chia_bls::SecretKey;
use dig_account::{AccountId, AccountSession, AccountStore, ProfileIx};
use dig_app_core::account::profile_session::test_support::registry_json;
use dig_app_core::account::profile_session::{MemoryRegistryStore, ProfileSession};
use dig_app_core::account::residency::AccountResidency;
use dig_app_core::account::{ActiveSlot, WalletSlot};
use dig_app_core::sealer::ProfileSealer;
use dig_app_core::session::SessionSigner;
use dig_keystore::{KdfParams, MemoryBackend};
use dig_session::{Password, ENTROPY_LEN};

/// One fixed entropy, so the only variable across every derivation here is the profile index.
const SEED: [u8; ENTROPY_LEN] = [0x5e; ENTROPY_LEN];

/// The account's first profile.
const FIRST: ProfileIx = ProfileIx::ROOT;
/// The profile switched TO. Adjacent to [`FIRST`], so an implementation that quietly stayed at index
/// 0 is the nearest wrong answer this fixture can distinguish.
const SECOND: ProfileIx = ProfileIx(1);

/// A DID the sealer's AAD is bound to. Constant across the switch on purpose: the isolation under
/// test is the DEK's, so holding the advisory DID fixed removes it as an explanation for a failed
/// open.
const DID: &str = "did:chia:seal-target";

/// A residency over [`SEED`] with two confirmed profiles, active on [`FIRST`], plus the session that
/// owns the active slot.
///
/// The account is opened at [`WalletSlot::from_active`] rather than the bootstrap, so it is genuinely
/// the registry that decides where the wallet lands.
fn two_profile_account() -> (AccountResidency, ProfileSession) {
    let session = ProfileSession::load(Arc::new(MemoryRegistryStore::seeded(registry_json(
        &[(FIRST, Some("home")), (SECOND, Some("work"))],
        FIRST,
    ))))
    .expect("the fixture registry loads");

    let store = Arc::new(AccountStore::new(Arc::new(MemoryBackend::new())));
    let unlocked = AccountSession::enroll(
        store,
        AccountId::new("switch-test"),
        Password::new("pw"),
        &SEED,
        session.wallet_slot().ix(),
    )
    .expect("a fresh in-memory account enrols");

    let residency =
        AccountResidency::with_profiles(unlocked, session.wallet_slot(), session.clone());
    (residency, session)
}

/// The identity signing public key for [`SEED`] at `ix`, derived HERE from `chia_bls` — so the
/// assertions compare two implementations rather than reading one value back from itself.
///
/// Recomputes the canonical dig-identity path from `chia_bls` primitives — BIP-39 expansion → the
/// FULLY HARDENED path `m/12381'/8444'/9'/{ix}'` → the compressed G1 public key. It touches neither
/// dig-identity nor dig-account, so agreement is agreement between two implementations.
///
/// The path components are written out here on purpose rather than imported. Importing the constant
/// dig-identity derives from would make this a restatement: a change to that constant would move both
/// sides together and the assertion would still pass, while every DIG identity key silently changed.
/// Note in particular that the application index is `9` and NOT Chia's wallet index `2` — an identity
/// key secures no coins, and confusing the two is the nearest wrong derivation.
fn independent_identity_key(ix: ProfileIx) -> Vec<u8> {
    const PURPOSE: u32 = 12381;
    const CHIA_COIN_TYPE: u32 = 8444;
    const DIG_IDENTITY_APPLICATION: u32 = 9;

    let expanded = bip39::Mnemonic::from_entropy_in(bip39::Language::English, &SEED)
        .expect("32 bytes is valid 24-word BIP-39 entropy")
        .to_seed("");
    let identity = [PURPOSE, CHIA_COIN_TYPE, DIG_IDENTITY_APPLICATION, ix.0]
        .iter()
        .fold(SecretKey::from_seed(&expanded), |sk, &index| {
            sk.derive_hardened(index)
        });
    identity.public_key().to_bytes().to_vec()
}

/// **The identity signer follows the switch — the RETAINED one, not a fresh one.**
///
/// The control comes first and is what makes the rest meaningful: before any switch, the retained
/// signer's public key must equal an independent out-of-tree derivation at [`FIRST`]. Without it this
/// test cannot tell "the signer followed the switch" from "the signer returns garbage that happens to
/// change".
#[test]
fn a_retained_identity_signer_follows_the_switch() {
    let (residency, session) = two_profile_account();
    let signer = residency.signer();

    let before = signer.signing_public_key().as_bytes().to_vec();
    assert_eq!(
        independent_identity_key(FIRST),
        before,
        "control: before any switch the signer must derive the canonical key for the FIRST profile"
    );

    let switched = session
        .switch_to(SECOND)
        .expect("the second profile is confirmed");
    assert_eq!(SECOND, switched.to_ix());

    let after = signer.signing_public_key().as_bytes().to_vec();
    assert_ne!(
        before, after,
        "a retained signer that kept signing as the old identity is the half-landed switch"
    );
    assert_eq!(
        independent_identity_key(SECOND),
        after,
        "merely different is not enough — it must be the RIGHT key for the profile now active"
    );
}

/// **The at-rest DEK follows the switch, proved cryptographically rather than by inspection.**
///
/// The load-bearing assertion is the third: a blob sealed under the FIRST profile's DEK must no
/// longer OPEN. That is the AEAD tag refusing, which no amount of field-reading could fake — and it
/// is the property the whole per-profile-directory model rests on, because it is what makes one
/// profile's sealed data genuinely unreadable to another.
///
/// A round-trip under the new profile comes first as a truthful control: a sealer that had simply
/// broken would also fail to open the old blob.
#[test]
fn a_retained_sealer_follows_the_switch_and_can_no_longer_open_the_old_profiles_blob() {
    let (residency, session) = two_profile_account();
    let sealer = residency.sealer(KdfParams::FAST_TEST);

    let sealed_under_first = sealer
        .seal(DID, b"the first profile's private note")
        .expect("an unlocked residency seals");
    assert_eq!(
        &sealer.open(DID, &sealed_under_first).expect("round-trips")[..],
        b"the first profile's private note",
        "control: the blob opens under the profile that sealed it"
    );

    let _switched = session
        .switch_to(SECOND)
        .expect("the second profile is confirmed");

    // Control: the sealer still WORKS, so the refusal below is isolation and not breakage.
    let sealed_under_second = sealer
        .seal(DID, b"the second profile's private note")
        .expect("the retained sealer still seals after the switch");
    assert_eq!(
        &sealer.open(DID, &sealed_under_second).expect("round-trips")[..],
        b"the second profile's private note"
    );

    assert!(
        sealer.open(DID, &sealed_under_first).is_err(),
        "the retained sealer must no longer open a blob sealed under the PREVIOUS profile's DEK — \
         if it can, both profiles share one at-rest key and the per-profile directory is theatre"
    );
    assert_ne!(
        sealed_under_first, sealed_under_second,
        "two profiles' ciphertexts of different plaintexts must differ (a sanity floor)"
    );
}

/// **The profile-scoped DIRECTORY moves with the switch** — the teardown half.
///
/// `profile_dir` is keyed by the active profile's id, and the app builds it once at boot. Sharing one
/// directory across profiles would put profile B's sealed stores beside A's under a DEK that cannot
/// open them, and would leak each profile's metadata into the other's listing.
///
/// The account-scoped id is asserted NOT to move in the same test, because the two are derived from
/// the same residency and a change that made everything follow the switch would break the recovery
/// phrase — that is the failure this pairing exists to catch, not a redundant assertion.
#[test]
fn the_profile_directory_moves_but_the_account_scoped_id_does_not() {
    use dig_app_core::account::boot::{account_scoped_id, active_profile_id};
    use dig_app_core::storage::profile_dir;

    let (residency, session) = two_profile_account();
    let brand = std::path::Path::new("brand");

    let account_before = account_scoped_id(&residency).expect("unlocked");
    let dir_before = profile_dir(brand, &active_profile_id(&residency).expect("unlocked"));

    let _switched = session
        .switch_to(SECOND)
        .expect("the second profile is confirmed");

    let dir_after = profile_dir(brand, &active_profile_id(&residency).expect("unlocked"));
    assert_ne!(
        dir_before, dir_after,
        "the profile directory must move with the active profile, or two identities share a DEK-\
         mismatched directory"
    );
    assert_eq!(
        account_before,
        account_scoped_id(&residency).expect("unlocked"),
        "the ACCOUNT id must NOT move: the recovery phrase and the second factor are sealed under it, \
         and a switch that moved it would make a user's own recovery words unreadable"
    );
}

/// **A RETAINED sealed-record store writes into the directory of the profile now active.**
///
/// The nearest wrong implementation is the one that shipped: `build_router` resolved the profile
/// directory to a `PathBuf` at boot and handed it to a store that was then moved onto the sign-service
/// thread. Every assertion about `profile_dir` the function elsewhere in this file makes stays green
/// under it, because that function is not what went stale — the copy of its answer was.
///
/// So the fixture uses TWO directories and one retained handle. A record persisted before the switch
/// must land under the first profile's directory and a record persisted after it under the second's,
/// with neither directory holding the other's file. A single-directory fixture could not tell a store
/// that followed from one that never moved, and asserting only "the new file exists" would pass on an
/// implementation that wrote to both.
#[test]
fn a_retained_sealed_store_writes_into_the_directory_of_the_profile_now_active() {
    use dig_app_core::account::boot::{active_profile_id, live_profile_dir};
    use dig_app_core::loopback::{FileSealedStore, SealedRecordStore};
    use dig_app_core::storage::{did_hash, profile_dir};

    let (residency, session) = two_profile_account();
    let brand = tempfile::tempdir().expect("a temp brand dir");
    let dir_of = |residency: &AccountResidency| {
        profile_dir(
            brand.path(),
            &did_hash(&active_profile_id(residency).expect("unlocked")),
        )
    };

    // Retained for the whole test, exactly as the serving thread retains it.
    let store = FileSealedStore::new(live_profile_dir(&residency, brand.path()));

    let first_dir = dir_of(&residency);
    store.persist_pairing("pairing-under-first", b"sealed-bytes-A");
    assert_eq!(
        1,
        store.load().pairings.len(),
        "control: the store persists and restores at all"
    );

    let _switched = session
        .switch_to(SECOND)
        .expect("the second profile is confirmed");
    let second_dir = dir_of(&residency);
    assert_ne!(
        first_dir, second_dir,
        "the fixture needs two distinct directories, or it cannot observe a move"
    );

    store.persist_pairing("pairing-under-second", b"sealed-bytes-B");

    let sealed_files = |dir: &std::path::Path| -> Vec<String> {
        let mut names: Vec<String> = std::fs::read_dir(dir.join("app-sign").join("pairings"))
            .into_iter()
            .flatten()
            .filter_map(|entry| Some(entry.ok()?.file_name().to_string_lossy().into_owned()))
            .collect();
        names.sort();
        names
    };

    assert_eq!(
        vec!["pairing-under-first.seal".to_owned()],
        sealed_files(&first_dir),
        "the record written AFTER the switch landed in the previous profile's directory"
    );
    assert_eq!(
        vec!["pairing-under-second.seal".to_owned()],
        sealed_files(&second_dir),
        "the retained store did not follow the switch — it is still writing where it was built"
    );
    assert_eq!(
        1,
        store.load().pairings.len(),
        "and the store must now RESTORE from the new directory, not the old one"
    );
}

/// **A RETAINED whitelist store records the grant against the profile now active.**
///
/// `WhitelistEntry::profile_did` names which profile a grant belongs to, and it is the one observable
/// that isolates the captured DID from the DEK that moves with it. Asserting instead that a
/// pre-switch record fails to reopen would prove nothing here: the DEK has already moved, so that
/// refusal happens with a stale DID too — the outcome is identical and the placement is what differs.
///
/// The control is the pre-switch grant: without it, a store that recorded an empty or garbage DID
/// would satisfy the "not the old one" half exactly as a correct one does.
#[test]
fn a_retained_whitelist_store_records_the_profile_now_active() {
    use dig_app_core::account::boot::live_profile_did;
    use dig_app_core::whitelist::WhitelistStore;

    let (residency, session) = two_profile_account();
    // One handle, built before the switch and never rebuilt.
    let whitelist = WhitelistStore::new(
        residency.sealer(KdfParams::FAST_TEST),
        live_profile_did(&residency),
    );

    let before = whitelist
        .grant(&whitelist.consent_now(), "https://dapp.example", vec![], 1)
        .expect("an unlocked profile grants")
        .entry
        .profile_did;
    assert_eq!(
        residency.signing_public_key_hex().expect("unlocked"),
        before,
        "control: before any switch the grant must name the profile actually in force"
    );

    let _switched = session
        .switch_to(SECOND)
        .expect("the second profile is confirmed");

    let after = whitelist
        .grant(&whitelist.consent_now(), "https://other.example", vec![], 2)
        .expect("the retained store still grants after the switch")
        .entry
        .profile_did;
    assert_ne!(
        before, after,
        "the retained store recorded the grant against the profile the user switched AWAY from"
    );
    assert_eq!(
        residency.signing_public_key_hex().expect("unlocked"),
        after,
        "merely different is not enough — the grant must name the profile now active"
    );

    // Tagging the NEW grant correctly is only half of it. The map is the authorization state the
    // connect gate reads, so the OLD profile's grant must stop answering for it: a consent given
    // under `FIRST` that still passes under `SECOND` skips the connect modal and hands the dapp
    // SECOND's DID, addresses and signing key (dig_ecosystem#2398 ADV-A1).
    assert!(
        !whitelist.is_whitelisted("https://dapp.example"),
        "the grant made under the previous profile must not authorize anything under this one"
    );
    assert!(
        whitelist.is_whitelisted("https://other.example"),
        "control: the grant made under THIS profile must still authorize — the map is scoped, not emptied"
    );
}

/// **A RETAINED pairing store stops authenticating the previous profile's pairings.**
///
/// The whitelist gates which origins may act; the pairing store gates which local app may speak at
/// all, and it is read by the same router on the same unreachable thread. An app paired under
/// `FIRST` that keeps authenticating under `SECOND` is a channel the second profile never approved —
/// and revoking it from the tray while on `SECOND` deletes `SECOND`'s sealed record, so the pairing
/// returns at the next boot into `FIRST`.
///
/// The control is the pairing made AFTER the switch: without it, a store that had simply dropped
/// every pairing on any read would satisfy the first assertion exactly as a correctly-scoped one does.
#[test]
fn a_retained_pairing_store_stops_authenticating_the_previous_profiles_pairings() {
    use dig_app_core::account::boot::live_profile_did;
    use dig_app_core::pairing::{NewPairing, PairingStore};

    let (residency, session) = two_profile_account();
    let pairings = PairingStore::new(
        residency.sealer(KdfParams::FAST_TEST),
        live_profile_did(&residency),
    );

    let under_first = pairings
        .pair(
            &pairings.consent_now(),
            &NewPairing::pinned("app.under.first", None),
            1,
        )
        .expect("an unlocked profile pairs")
        .pairing_id;
    assert!(
        pairings.is_paired(&under_first),
        "control: before any switch the pairing must authenticate"
    );

    let _switched = session
        .switch_to(SECOND)
        .expect("the second profile is confirmed");

    let under_second = pairings
        .pair(
            &pairings.consent_now(),
            &NewPairing::pinned("app.under.second", None),
            2,
        )
        .expect("the retained store still pairs after the switch")
        .pairing_id;

    assert!(
        !pairings.is_paired(&under_first),
        "the pairing made under the previous profile must not authenticate under this one"
    );
    assert!(
        pairings.is_paired(&under_second),
        "control: the pairing made under THIS profile must still authenticate"
    );
    assert_eq!(
        vec![under_second],
        pairings
            .list()
            .into_iter()
            .map(|app| app.pairing_id)
            .collect::<Vec<_>>(),
        "and the tray must not offer to revoke a pairing whose record lives in another profile's \
         directory — that revoke could only last until the next start"
    );
}

/// **The wallet seam fails CLOSED rather than answering for the profile the user just left.**
///
/// dig-account 0.8 fixes an unlock's wallet index at open time and exposes no `wallet_ops_at(ix)`
/// (dig_ecosystem#2496), so after a switch the wallet can only speak for the OLD profile. Returning
/// its address anyway would show one identity's receive address under another's name — money sent
/// there would land on a key the user believes belongs to a different profile.
///
/// The control is the pre-switch read: without it, a residency that never derived an address would
/// satisfy the refusal identically.
#[test]
fn the_wallet_refuses_to_answer_for_a_profile_it_was_not_opened_at() {
    let (residency, session) = two_profile_account();

    let before = residency
        .receiving_address()
        .expect("unlocked")
        .expect("control: an address derives while the wallet and the active profile agree");
    assert!(before.starts_with("xch1"), "{before}");

    let _switched = session
        .switch_to(SECOND)
        .expect("the second profile is confirmed");

    let after = residency.receiving_address().expect("still unlocked");
    assert!(
        after.is_err(),
        "the wallet must refuse rather than show the PREVIOUS profile's receive address: {after:?}"
    );
    assert!(
        residency
            .money_signer(dig_wallet_backend::types::Network::Mainnet)
            .is_none(),
        "and it must sign nothing, or a spend would leave the profile the user switched away from"
    );
}

/// **The ONE address accessor the tray reads refuses too, and says WHY.**
///
/// `observe_receiving_address` is the accessor `TrayView.receive_address` is filled from, and it was
/// the only one of the four money accessors with no agreement check. Its three siblings all had one,
/// so a test that asserted "some accessor refuses" would have passed on the broken version — this
/// names the accessor, and distinguishes the refusal from an ordinary lock, which is the outcome a
/// wrong fix would produce.
///
/// The control is the pre-switch read: a residency that never derived an address would satisfy the
/// refusal identically.
#[test]
fn the_tray_address_accessor_reports_the_wallet_is_behind_rather_than_the_old_address() {
    use dig_app_core::account::residency::AddressObservation;

    let (residency, session) = two_profile_account();

    let AddressObservation::Derived(before) = residency.observe_receiving_address() else {
        panic!("control: an unlocked residency on its own profile must derive an address");
    };
    assert!(before.starts_with("xch1"), "{before}");

    let _switched = session
        .switch_to(SECOND)
        .expect("the second profile is confirmed");

    let after = residency.observe_receiving_address();
    assert_ne!(
        AddressObservation::Derived(before),
        after,
        "the tray would have shown the PREVIOUS profile's address under the new profile's name, and          `Copy my receive address` would have handed it out"
    );
    assert_eq!(
        AddressObservation::WalletBehindActiveProfile,
        after,
        "and it must say the wallet is behind, not report an ordinary lock — a person told to          unlock an account that is already unlocked is told to do nothing"
    );
}

/// **What the user is TOLD about a switch matches what the code then does.**
///
/// The disclosure and the success notice both used to state that the receive address changes. It
/// does not: `wallet_ops_at` does not exist (dig_ecosystem#2496), so after a switch the wallet can
/// only answer for the profile just left and every accessor refuses — including the one the test
/// above pins. Promising a new address sends somebody looking for one that is not there, and invites
/// them to keep handing out the old one believing it belongs to the profile they are now on.
///
/// This asserts the two halves TOGETHER — the sentence and the behaviour — because either alone is
/// satisfiable by a lie: copy can promise anything, and a refusal proves nothing about what the user
/// was told.
#[test]
fn the_switch_disclosure_does_not_promise_an_address_that_will_not_move() {
    use dig_app_core::account::residency::AddressObservation;
    use dig_app_core::profiles::copy;

    let disclosure = copy::switching("home", "work");
    assert!(
        disclosure.contains("does NOT change yet"),
        "the disclosure must say the address does not move yet: {disclosure}"
    );
    assert!(
        disclosure.contains("signing key changes with it"),
        "and it must still disclose what DOES change: {disclosure}"
    );

    let (residency, session) = two_profile_account();
    let _switched = session
        .switch_to(SECOND)
        .expect("the second profile is confirmed");
    assert_eq!(
        AddressObservation::WalletBehindActiveProfile,
        residency.observe_receiving_address(),
        "the disclosure and the behaviour must describe the same app: if the wallet DOES follow a          switch, this sentence is the one that is now wrong"
    );
}

/// **The slot itself, read live, is what moved** — the floor the other three tests stand on.
#[test]
fn the_live_slot_reports_the_profile_switched_to() {
    let (residency, session) = two_profile_account();
    assert_eq!(FIRST, residency.slot().ix());

    let switched = session
        .switch_to(SECOND)
        .expect("the second profile is confirmed");

    assert_eq!(SECOND, residency.slot().ix());
    assert_eq!(Some(FIRST), switched.from_ix());
    assert!(matches!(residency.slot(), ActiveSlot::Profile { .. }));
    assert_eq!(
        residency.slot().did(),
        switched.slot().did(),
        "the residency and the switch value must name ONE profile, not two"
    );
}

/// **The address a user funds before minting is the address their first profile inherits.**
///
/// This holds by `ProfileRegistry::next_free_ix`'s arithmetic — `ROOT` on an empty registry — and is
/// asserted by nothing else. Without it, a change that started the first mint at index 1 would strand
/// every pre-mint deposit at an address the app stops watching, and every other test here would stay
/// green.
///
/// The second assertion is the one that makes it more than a restatement: a test naming only the
/// current address would pass on the broken version too, so the address is compared BETWEEN an empty
/// registry and a populated one whose active profile is ROOT.
#[test]
fn the_pre_mint_address_survives_the_first_mint() {
    let unprofiled = {
        let store = Arc::new(AccountStore::new(Arc::new(MemoryBackend::new())));
        let session = ProfileSession::unprofiled();
        assert_eq!(
            ProfileIx::ROOT,
            session.next_mint_target().ix(),
            "the first mint must target the index the pre-mint address was funded at"
        );
        let unlocked = AccountSession::enroll(
            store,
            AccountId::new("pre-mint"),
            Password::new("pw"),
            &SEED,
            session.wallet_slot().ix(),
        )
        .unwrap();
        AccountResidency::with_profiles(unlocked, WalletSlot::unprofiled(), session)
            .receiving_address()
            .expect("unlocked")
            .expect("an address encodes")
    };

    let (profiled, _session) = two_profile_account();
    assert_eq!(
        unprofiled,
        profiled
            .receiving_address()
            .expect("unlocked")
            .expect("an address encodes"),
        "the address must not move when the first profile is recorded at ROOT — funds sent before \
         the mint would otherwise be stranded at an address the app no longer watches"
    );
}
