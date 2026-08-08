//! The shared unlocked-account RESIDENCY — the live, lockable home of the master seed the tray drives
//! and the sign path reads (#1547, custody switchover).
//!
//! # Why a residency, not a snapshot
//!
//! dig-account's [`UnlockedAccount::signer`](dig_account::UnlockedAccount::signer) returns a
//! [`ProfileSigner`](dig_account::ProfileSigner) that captures its OWN `Arc` of the master seed. If the
//! tray dropped the boot-time `UnlockedAccount`, that snapshot signer would keep signing — a lock that
//! does not lock. (dig-account itself defers wiring idle-relock onto the capability lifecycle; see its
//! `unlocked` docs / `SPEC.md` §4.1.)
//!
//! [`AccountResidency`] closes that gap on the harness side: it OWNS the sole `UnlockedAccount` behind a
//! shared lock, and hands out LIVE-VIEW capabilities ([`ResidencySigner`], [`ResidencySealer`]) that
//! re-read the account on every operation and FAIL CLOSED once it is locked. So a lock-now / idle
//! timeout / OS screen lock that drops the residency ([`SessionKeys::lock_all`]) immediately relocks
//! the running sign + seal paths over the master-HD account, without relying on dig-account's deferred
//! capability relock. The signer never forges when locked, and the sealer fails closed when locked.

use std::sync::{Arc, Mutex};

use chia_protocol::CoinSpend;
use dig_account::{
    CustodyPolicy, LocalMoneySigner, ProfileIx, Result as AccountResult, SpendSummary,
    UnlockedAccount,
};
use dig_ipc_protocol::domain::{Signature, SigningPublicKey};
use dig_ipc_protocol::signer::SessionSigner;
use dig_keystore::KdfParams;
use dig_wallet_backend::types::Network;
use zeroize::Zeroizing;

use crate::account::sealer::AccountSealer;
use crate::sealer::{ProfileSealer, SealError};
use crate::session_lock::SessionKeys;

/// The single unlocked account the app currently holds, behind a shared lock so the tray, the sign
/// path, and the seal path all see the SAME lock state. Cheap to clone (an `Arc`); locking any clone
/// locks them all.
#[derive(Clone)]
pub struct AccountResidency {
    inner: Arc<Mutex<Option<UnlockedAccount>>>,
}

/// The outcome of [`AccountResidency::observe_receiving_address`] — the residency's unlock state and
/// its receive-address derivation, read TOGETHER under one lock acquisition (dig_ecosystem#2059). See
/// that method's docs for why the two facts must come from a single observation rather than two calls.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AddressObservation {
    /// The residency held no unlocked account at the moment of observation — an ordinary lock, whether
    /// this account was never unlocked or has since been relocked.
    Locked,
    /// The residency was unlocked, and the address derived successfully.
    Derived(String),
    /// The residency was unlocked at the moment of observation, and address derivation itself failed —
    /// a genuine defect: unlocking is NOT the way back, because unlocking is not what is missing.
    DerivationFailed,
}

impl AccountResidency {
    /// House a freshly-unlocked `account`.
    pub fn new(account: UnlockedAccount) -> Self {
        Self {
            inner: Arc::new(Mutex::new(Some(account))),
        }
    }

    /// An empty (locked) residency — nothing unlocked yet.
    pub fn empty() -> Self {
        Self {
            inner: Arc::new(Mutex::new(None)),
        }
    }

    /// Install `account` as the current unlocked account, replacing any prior one. Used by the
    /// sign-path re-auth to refill the residency after a lock (a zero-prompt re-unlock on Windows/macOS).
    pub fn install(&self, account: UnlockedAccount) {
        *self.guard() = Some(account);
    }

    /// A live-view identity signer for profile `ix` — signs through the current account, or returns
    /// `None`/a non-verifying signature once the residency is locked (never a forgery).
    pub fn signer(&self, ix: ProfileIx) -> ResidencySigner {
        ResidencySigner {
            residency: self.clone(),
            ix,
        }
    }

    /// A live-view per-profile sealer for profile `ix` at the given KDF cost — seals/opens under the
    /// current account's DEK, or fails closed once the residency is locked. Production passes
    /// [`KdfParams::DEFAULT`]; tests pass [`KdfParams::FAST_TEST`].
    pub fn sealer(&self, ix: ProfileIx, kdf: KdfParams) -> ResidencySealer {
        ResidencySealer {
            residency: self.clone(),
            ix,
            kdf,
        }
    }

    /// The production live-view sealer for profile `ix` — [`sealer`](Self::sealer) at the default
    /// (production Argon2) KDF cost. A convenience so the tray shell need not name [`KdfParams`].
    pub fn production_sealer(&self, ix: ProfileIx) -> ResidencySealer {
        self.sealer(ix, KdfParams::DEFAULT)
    }

    /// Re-derive + tier a [`SpendSummary`] for `coin_spends` under `policy`, through the CURRENT
    /// account's money path — or `None` once the residency is locked (fail-closed: a locked account
    /// summarizes nothing, so the confirm ceremony can never run against a stale snapshot).
    ///
    /// The recipients + fee are re-derived from the coin spends by dig-account (never a caller's
    /// claim); the returned [`SpendSummary::tier`] is what the [authorize-before-sign
    /// gate](crate::account::money::MoneyPath) weighs. The inner `Result` is dig-account's — an
    /// undecodable coin-spend set fails closed there.
    pub fn summarize(
        &self,
        coin_spends: &[CoinSpend],
        policy: &CustodyPolicy,
    ) -> Option<AccountResult<SpendSummary>> {
        self.guard()
            .as_ref()
            .map(|acct| acct.wallet_ops().summarize(coin_spends, policy))
    }

    /// Build the LIVE money signer for the default profile on `network`, through the CURRENT account —
    /// or `None` once the residency is locked. Read on every call so a lock (lock-now / idle timeout /
    /// OS screen lock) that drops the account between the confirm ceremony and this call fails the
    /// sign closed rather than signing under a snapshot the user meant to relock.
    ///
    /// The returned [`LocalMoneySigner`] holds the master key inside dig-account's vetted signer and
    /// exposes signing only — the seed never crosses this boundary. Since `dig-account` 0.5.0 building
    /// the signer is infallible, so `None` means one thing and one thing only: the account is locked.
    pub fn money_signer(&self, network: Network) -> Option<LocalMoneySigner> {
        self.guard()
            .as_ref()
            .map(|acct| acct.wallet_ops().money_signer(network))
    }

    /// The account's receiving address, in `xch1…` form — where a user sends XCH or $DIG.
    ///
    /// Derived live from the unlocked account, so it fails closed to `None` the moment the residency
    /// locks: an address is public information, but reading it from a locked account would mean the
    /// residency was still holding key material after a lock, which is the invariant that matters here.
    /// The inner `Result` is dig-account's own (an address-encoding failure).
    pub fn receiving_address(&self) -> Option<AccountResult<String>> {
        self.guard()
            .as_ref()
            .map(|acct| acct.wallet_ops().address())
    }

    /// [`is_any_unlocked`](Self::is_any_unlocked) and [`receiving_address`](Self::receiving_address)
    /// TOGETHER, under a single lock acquisition (dig_ecosystem#2059).
    ///
    /// Calling those two methods separately reads the residency TWICE, so a lock landing between the
    /// calls — an idle timeout, `Lock now`, an OS screen lock — can make "was unlocked" and "no address"
    /// true of two DIFFERENT moments: an ordinary lock race, not a defect. A caller that then reasons
    /// "unlocked yet no address ⇒ derivation is broken" would alarm a user who merely locked their
    /// account. This method closes that gap by taking the lock exactly once, so
    /// [`AddressObservation::DerivationFailed`] can only ever mean a genuine defect.
    pub fn observe_receiving_address(&self) -> AddressObservation {
        match self.guard().as_ref() {
            None => AddressObservation::Locked,
            Some(acct) => match acct.wallet_ops().address() {
                Ok(address) => AddressObservation::Derived(address),
                Err(e) => {
                    tracing::warn!(
                        error = %e,
                        "the account's receive address could not be derived while unlocked"
                    );
                    AddressObservation::DerivationFailed
                }
            },
        }
    }

    /// The 48-byte identity signing public key of profile `ix`, as hex — for the connect-handle
    /// advertisement at assembly time (read while unlocked). `None` if the residency is locked.
    pub fn signing_public_key_hex(&self, ix: ProfileIx) -> Option<String> {
        self.guard()
            .as_ref()
            .map(|acct| hex::encode(acct.profile_signer(ix).signing_public_key().as_bytes()))
    }

    fn guard(&self) -> std::sync::MutexGuard<'_, Option<UnlockedAccount>> {
        // A poisoned mutex means another thread panicked mid-operation on the residency — an
        // unrecoverable custody-state bug, so fail loudly rather than sign/seal on half-updated state.
        self.inner.lock().expect("account-residency mutex poisoned")
    }
}

impl SessionKeys for AccountResidency {
    fn lock_all(&self) {
        // Dropping the `UnlockedAccount` drops its `Arc<UnlockedMasterSeed>`; with no live-view
        // capability holding a clone (they read through this residency), the seed is zeroized.
        *self.guard() = None;
    }

    fn is_any_unlocked(&self) -> bool {
        self.guard().is_some()
    }
}

/// A [`SessionSigner`] that reads the current account from an [`AccountResidency`] on every call, so a
/// lock immediately relocks it. Fail-closed: a locked residency yields `None` from
/// [`try_sign`](SessionSigner::try_sign) and a non-verifying zero signature from the infallible
/// [`sign`](SessionSigner::sign) — never a forgery.
pub struct ResidencySigner {
    residency: AccountResidency,
    ix: ProfileIx,
}

impl SessionSigner for ResidencySigner {
    fn signing_public_key(&self) -> SigningPublicKey {
        match self.residency.guard().as_ref() {
            Some(acct) => acct.profile_signer(self.ix).signing_public_key(),
            // Locked: advertise the all-zero key rather than panic (fail-closed, never a forgery).
            None => SigningPublicKey::new([0u8; 48]),
        }
    }

    fn sign(&self, message: &[u8]) -> Signature {
        self.try_sign(message).unwrap_or_else(|| {
            // Locked between service start and this infallible-sign call — fail safe with a
            // non-verifying zero signature rather than a forgery. Custody callers use `try_sign` and
            // surface LOCKED instead of ever framing this. (NEVER log the message.)
            tracing::warn!("sign requested on a locked account residency — returning a non-verifying signature");
            Signature::new([0u8; 96])
        })
    }

    fn try_sign(&self, message: &[u8]) -> Option<Signature> {
        self.residency
            .guard()
            .as_ref()
            .and_then(|acct| acct.profile_signer(self.ix).try_sign(message))
    }
}

/// A [`ProfileSealer`] that derives the current account's per-profile DEK from an [`AccountResidency`]
/// on every call, so a lock immediately relocks at-rest access. Fail-closed: a locked residency yields
/// [`SealError::Seal`] rather than sealing/opening.
#[derive(Clone)]
pub struct ResidencySealer {
    residency: AccountResidency,
    ix: ProfileIx,
    kdf: KdfParams,
}

impl ResidencySealer {
    /// Run `f` with a fresh [`AccountSealer`] over the current account's DEK, or fail closed when the
    /// residency is locked. The DEK lives only inside `f`'s scope (a scrubbing buffer).
    fn with_sealer<T>(
        &self,
        f: impl FnOnce(&AccountSealer) -> Result<T, SealError>,
    ) -> Result<T, SealError> {
        let guard = self.residency.guard();
        let Some(acct) = guard.as_ref() else {
            return Err(SealError::Seal("account residency is locked".to_string()));
        };
        let dek = Zeroizing::new(acct.dek(self.ix));
        f(&AccountSealer::with_kdf(*dek, self.kdf))
    }
}

impl ProfileSealer for ResidencySealer {
    fn seal(&self, profile_did: &str, plaintext: &[u8]) -> Result<Vec<u8>, SealError> {
        self.with_sealer(|s| s.seal(profile_did, plaintext))
    }

    fn open(&self, profile_did: &str, ciphertext: &[u8]) -> Result<Zeroizing<Vec<u8>>, SealError> {
        self.with_sealer(|s| s.open(profile_did, ciphertext))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use dig_account::{AccountId, AccountSession, AccountStore};
    use dig_keystore::MemoryBackend;
    use dig_session::{Password, ENTROPY_LEN};
    use std::sync::Arc as StdArc;

    const DID: &str = "did:chia:residency-test";

    /// Enrol a fresh account (synchronous keystore enrol) into a residency, so the tests exercise the
    /// real dig-account [`UnlockedAccount`] handle. Each call uses a distinct random seed so two
    /// residencies hold genuinely different key material.
    fn residency() -> AccountResidency {
        use rand_core::RngCore;
        let mut seed = [0u8; ENTROPY_LEN];
        rand_core::OsRng.fill_bytes(&mut seed);
        residency_from_seed(&seed)
    }

    /// Enrol a residency over an EXACT seed, so a test can pin what the account derives from.
    fn residency_from_seed(seed: &[u8; ENTROPY_LEN]) -> AccountResidency {
        let store = StdArc::new(AccountStore::new(StdArc::new(MemoryBackend::new())));
        let unlocked = AccountSession::enroll(
            store,
            AccountId::new("primary"),
            Password::new("residency-test-pw"),
            seed,
            ProfileIx::ROOT,
        )
        .unwrap();
        AccountResidency::new(unlocked)
    }

    /// The receiving address is a real derived `xch1…` address, differs per account, and fails closed
    /// once the residency locks.
    ///
    /// Two DIFFERENT residencies are compared because a fixed placeholder — or an address derived from
    /// something other than this account's key — would satisfy "it looks like an address" identically.
    /// The differing values are what prove it is derived from the seed in hand.
    #[test]
    fn the_receiving_address_is_derived_per_account_and_locks_with_it() {
        let mine_residency = residency();
        let mine = mine_residency
            .receiving_address()
            .expect("unlocked")
            .expect("an address encodes");
        assert!(mine.starts_with("xch1"), "{mine}");

        let other = residency()
            .receiving_address()
            .expect("unlocked")
            .expect("an address encodes");
        assert_ne!(mine, other, "each account has its own address");

        mine_residency.lock_all();
        assert!(
            mine_residency.receiving_address().is_none(),
            "a locked residency must not derive an address from key material it no longer holds"
        );
    }

    /// [`AccountResidency::observe_receiving_address`] reports the same two everyday outcomes the
    /// separate calls already prove — unlocked-and-derived, and locked — through the ONE atomic call
    /// (dig_ecosystem#2059). `DerivationFailed` is exercised at the `wallet::overview` mapping layer
    /// instead of here: dig-account's real address derivation has no seam that fails for a validly
    /// enrolled account, so forcing that outcome from a genuine residency would mean faking a defect
    /// that cannot occur — the honest test of "does the fault route correctly" lives where the app can
    /// inject the observation directly (`TrayView::address_derivation_failed`).
    #[test]
    fn the_atomic_observation_agrees_with_the_two_separate_reads() {
        let residency = residency();

        let observed = residency.observe_receiving_address();
        let AddressObservation::Derived(address) = observed else {
            panic!("a freshly unlocked residency must derive: {observed:?}");
        };
        assert_eq!(
            address,
            residency
                .receiving_address()
                .expect("still unlocked")
                .expect("an address encodes"),
            "the atomic read must agree with the separate call"
        );
        assert!(address.starts_with("xch1"), "{address}");

        residency.lock_all();
        assert_eq!(
            AddressObservation::Locked,
            residency.observe_receiving_address(),
            "a locked residency has no address to observe"
        );
    }

    /// The address the tray hands out is the address that actually RECEIVES — pinned against a SECOND,
    /// independent derivation of the same seed.
    ///
    /// "It starts with `xch1`" proves nothing: money sent to a well-formed address for the wrong key is
    /// gone. So this recomputes the whole chain here — canonical synthetic wallet key → standard p2
    /// puzzle hash → bech32m — using chia-bls / chia-puzzle-types and a local bech32m encoder, touching
    /// none of dig-account's code, and requires the residency to agree with it. A drifted profile index,
    /// a dropped `derive_synthetic()`, or a swapped HRP all break this and only this.
    ///
    /// The literal is belt-and-braces on top: independently reproduced with an out-of-tree bech32m
    /// implementation, and identical to dig-account's own frozen `GOLDEN_ADDRESS` for this seed. A
    /// derivation change that moved BOTH implementations together would still have to move the literal.
    /// The independent derivation now BIP-39-expands the entropy before key derivation, matching
    /// dig-account 0.3's seed expansion via the `bip39` crate.
    #[test]
    fn the_receiving_address_matches_an_independent_derivation_of_the_same_seed() {
        const SEED: [u8; ENTROPY_LEN] = [0x42; ENTROPY_LEN];
        const GOLDEN: &str = "xch14vlj35vktk9uyhuau3fv2dj4gw6c9kfxex44gvmzqa4rmvluqe7qrapt26";

        let derived = residency_from_seed(&SEED)
            .receiving_address()
            .expect("unlocked")
            .expect("an address encodes");

        assert_eq!(derived, independent_address(&SEED), "second implementation");
        assert_eq!(derived, GOLDEN, "frozen cross-checked vector");

        // Non-vacuity: the comparison above must be able to FAIL. An address derived from a seed one
        // BIT away is well-formed, `xch1`-prefixed, indistinguishable by eye, and wrong — precisely
        // the class of mistake that sends funds nowhere.
        let mut near_miss = SEED;
        near_miss[0] ^= 0x01;
        assert_ne!(derived, independent_address(&near_miss));
    }

    /// Derive the canonical Chia receive address for `seed` at the root profile WITHOUT dig-account:
    /// BIP-39-expand the entropy → `master_to_wallet_unhardened(master, 0).derive_synthetic()` →
    /// `StandardArgs::curry_tree_hash` → bech32m under the `xch` HRP.
    fn independent_address(seed: &[u8]) -> String {
        use chia_bls::{master_to_wallet_unhardened, SecretKey};
        use chia_puzzle_types::{standard::StandardArgs, DeriveSynthetic};

        let expanded = bip39::Mnemonic::from_entropy_in(bip39::Language::English, seed)
            .expect("32 bytes is valid 24-word BIP-39 entropy")
            .to_seed("");
        let master = SecretKey::from_seed(&expanded);
        let synthetic = master_to_wallet_unhardened(&master, ProfileIx::ROOT.0).derive_synthetic();
        let puzzle_hash = StandardArgs::curry_tree_hash(synthetic.public_key());
        bech32m("xch", puzzle_hash.to_bytes().as_ref())
    }

    /// A self-contained BIP-350 bech32m encoder, so the encoding half of the address is checked by
    /// something other than the encoder under test.
    fn bech32m(hrp: &str, data: &[u8]) -> String {
        const CHARSET: &[u8] = b"qpzry9x8gf2tvdw0s3jn54khce6mua7l";
        const BECH32M_CONST: u32 = 0x2bc8_30a3;

        fn polymod(values: &[u8]) -> u32 {
            const GEN: [u32; 5] = [
                0x3b6a_57b2,
                0x2650_8e6d,
                0x1ea1_19fa,
                0x3d42_33dd,
                0x2a14_62b3,
            ];
            let mut chk: u32 = 1;
            for &v in values {
                let top = chk >> 25;
                chk = ((chk & 0x1ff_ffff) << 5) ^ u32::from(v);
                for (i, g) in GEN.iter().enumerate() {
                    if (top >> i) & 1 == 1 {
                        chk ^= g;
                    }
                }
            }
            chk
        }

        // 8-bit bytes → 5-bit groups, zero-padded to a whole group (the payload is 32 bytes = 52
        // groups + 4 padding bits, exactly as an address carries it).
        let mut five_bit = Vec::new();
        let (mut acc, mut bits) = (0u32, 0u32);
        for &byte in data {
            acc = (acc << 8) | u32::from(byte);
            bits += 8;
            while bits >= 5 {
                bits -= 5;
                five_bit.push(((acc >> bits) & 31) as u8);
            }
        }
        if bits > 0 {
            five_bit.push(((acc << (5 - bits)) & 31) as u8);
        }

        let mut values: Vec<u8> = hrp.bytes().map(|c| c >> 5).collect();
        values.push(0);
        values.extend(hrp.bytes().map(|c| c & 31));
        values.extend_from_slice(&five_bit);
        values.extend_from_slice(&[0; 6]);
        let checksum = polymod(&values) ^ BECH32M_CONST;

        let mut out = format!("{hrp}1");
        for group in five_bit
            .iter()
            .copied()
            .chain((0..6).map(|i| ((checksum >> (5 * (5 - i))) & 31) as u8))
        {
            out.push(CHARSET[group as usize] as char);
        }
        out
    }

    #[test]
    fn an_unlocked_residency_signs_and_a_lock_relocks_the_live_signer() {
        let residency = residency();
        let signer = residency.signer(ProfileIx::ROOT);

        assert!(
            signer.try_sign(b"challenge").is_some(),
            "an unlocked residency signs"
        );

        // Locking the residency must immediately relock the SAME live-view signer — the custody
        // property a snapshot signer could not provide.
        residency.lock_all();
        assert!(!residency.is_any_unlocked());
        assert!(
            signer.try_sign(b"challenge").is_none(),
            "a locked residency must relock the running signer (no snapshot escape)"
        );
    }

    #[test]
    fn a_locked_signer_never_forges_via_the_infallible_path() {
        use crate::session::verify_signature;
        let residency = residency();
        let signer = residency.signer(ProfileIx::ROOT);
        residency.lock_all();

        let pubkey = signer.signing_public_key();
        let fallback = signer.sign(b"anything");
        assert!(
            !verify_signature(&pubkey, b"anything", &fallback),
            "the locked fail-safe signature must not verify"
        );
    }

    #[test]
    fn the_sealer_round_trips_while_unlocked_and_fails_closed_once_locked() {
        let residency = residency();
        let sealer = residency.sealer(ProfileIx::ROOT, KdfParams::FAST_TEST);

        let blob = sealer.seal(DID, b"subscriptions").unwrap();
        assert_eq!(&sealer.open(DID, &blob).unwrap()[..], b"subscriptions");

        residency.lock_all();
        assert!(
            matches!(sealer.seal(DID, b"x"), Err(SealError::Seal(_))),
            "a locked residency must fail closed on seal"
        );
        assert!(
            matches!(sealer.open(DID, &blob), Err(SealError::Seal(_))),
            "a locked residency must fail closed on open"
        );
    }

    #[test]
    fn re_installing_an_account_re_unlocks_the_live_capabilities() {
        // Models the sign-path re-auth: after a lock, refilling the residency makes the live signer
        // work again (a zero-prompt re-unlock on Windows/macOS).
        let resident = residency();
        let signer = resident.signer(ProfileIx::ROOT);
        resident.lock_all();
        assert!(signer.try_sign(b"m").is_none());

        // Enrol/unlock a second handle over the same fixture and re-install it.
        let refill = residency();
        if let Some(acct) = refill.take_for_test() {
            resident.install(acct);
        }
        assert!(
            signer.try_sign(b"m").is_some(),
            "re-installing an unlocked account re-unlocks the live signer"
        );
    }

    #[test]
    fn the_money_signer_is_live_while_unlocked_and_fails_closed_once_locked() {
        use dig_wallet_backend::types::Network;
        let residency = residency();

        assert!(
            residency.money_signer(Network::Mainnet).is_some(),
            "an unlocked residency yields a live money signer"
        );

        residency.lock_all();
        assert!(
            residency.money_signer(Network::Mainnet).is_none(),
            "a locked residency yields NO money signer (fail-closed — never signs money)"
        );
    }

    #[test]
    fn summarize_reads_the_live_account_and_fails_closed_once_locked() {
        use dig_account::{CustodyPolicy, HotWallet};
        let residency = residency();
        let policy = CustodyPolicy::Hot(HotWallet::default());

        // Unlocked: the summary derivation runs (an empty coin-spend set is an undecodable spend, so
        // dig-account fails it closed as `Err` — but the accessor itself is `Some`, i.e. the account
        // was consulted).
        assert!(
            matches!(residency.summarize(&[], &policy), Some(Err(_))),
            "an unlocked residency consults the account (and fails an empty spend closed)"
        );

        residency.lock_all();
        assert!(
            residency.summarize(&[], &policy).is_none(),
            "a locked residency summarizes nothing (fail-closed)"
        );
    }

    #[test]
    fn signing_public_key_hex_is_present_while_unlocked_and_absent_once_locked() {
        let residency = residency();
        assert!(residency.signing_public_key_hex(ProfileIx::ROOT).is_some());
        residency.lock_all();
        assert!(residency.signing_public_key_hex(ProfileIx::ROOT).is_none());
    }

    impl AccountResidency {
        /// Test-only: take the current account out of the residency (to move it into another).
        fn take_for_test(&self) -> Option<UnlockedAccount> {
            self.guard().take()
        }
    }
}
