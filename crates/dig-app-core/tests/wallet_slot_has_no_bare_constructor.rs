//! There is no way to name a wallet index the profile registry has not vouched for.
//!
//! # Why a compile-fail test rather than a runtime one
//!
//! The property is the ABSENCE of a constructor, and absence has no runtime witness — no call can be
//! made to observe that it fails. A test that asserted something about `WalletSlot::unprofiled()`
//! would pass identically in a build where `WalletSlot(ProfileIx(7))` had also become legal, which is
//! precisely the regression this exists to catch.
//!
//! It replaces #2236's `!is_active(DEACTIVATED)` clause, and is strictly stronger: that assertion
//! could only observe that ONE named index was refused, while this observes that no index can be
//! named at all.

/// Both bare-index constructions must fail to compile.
#[test]
fn a_wallet_slot_cannot_be_built_from_a_bare_profile_index() {
    trybuild::TestCases::new().compile_fail("tests/compile_fail/wallet_slot_from_a_bare_index.rs");
}
