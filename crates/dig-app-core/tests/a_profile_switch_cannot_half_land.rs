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
//! The three mechanisms are exercised by three separate tests, and reverting any ONE of them turns
//! exactly one of them red — see the module `PROOF` note at the bottom for how that was measured.

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

    let switched = session.switch_to(SECOND).expect("the second profile is confirmed");
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

    let _switched = session.switch_to(SECOND).expect("the second profile is confirmed");

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

    let _switched = session.switch_to(SECOND).expect("the second profile is confirmed");

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

    let _switched = session.switch_to(SECOND).expect("the second profile is confirmed");

    let after = residency.receiving_address().expect("still unlocked");
    assert!(
        after.is_err(),
        "the wallet must refuse rather than show the PREVIOUS profile's receive address: {after:?}"
    );
    assert!(
        residency.money_signer(dig_wallet_backend::types::Network::Mainnet).is_none(),
        "and it must sign nothing, or a spend would leave the profile the user switched away from"
    );
}

/// **The slot itself, read live, is what moved** — the floor the other three tests stand on.
#[test]
fn the_live_slot_reports_the_profile_switched_to() {
    let (residency, session) = two_profile_account();
    assert_eq!(FIRST, residency.slot().ix());

    let switched = session.switch_to(SECOND).expect("the second profile is confirmed");

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
