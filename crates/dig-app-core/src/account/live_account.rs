//! [`LiveAccount`] — the one place the running app publishes its unlocked
//! [`AccountResidency`](crate::account::residency::AccountResidency), so a background lane can
//! consult it PER OPERATION instead of being handed a copy it can only hold (dig-app#270).
//!
//! # Why a slot exists at all
//!
//! The `diga` CLI lane starts BEFORE any unlock. It has to: dig-app leaves the account locked on
//! almost every start-up path (dig_ecosystem#1817), and a lane bound only after an unlock would tell
//! a person their running app is not running. So the lane comes up first and the account arrives
//! later — which means the lane cannot be *given* a residency, and must be given somewhere to LOOK.
//!
//! This is that somewhere. The shell publishes each residency it opens; the lane reads the slot on
//! every operation and answers from whatever is there at that instant.
//!
//! # Reading, never holding
//!
//! [`read`](LiveAccount::read) returns *a reading, valid for the instant it was taken* — the same
//! discipline [`ActiveSlot`](crate::account::active_profile::ActiveSlot) holds for the active profile
//! index. A caller that stored the returned residency in a field would be back to the copy this type
//! exists to avoid, so every consumer calls `read` again rather than remembering.
//!
//! # It needs no lock operation, and that is the point
//!
//! Locking is the residency's own business: [`AccountResidency`] drops its unlocked account under
//! `SessionKeys::lock_all`, and every capability it issued observes that immediately. A published
//! residency that has since locked therefore reads back as locked WITHOUT anything touching this
//! slot — so there is no window in which the slot says "unlocked" while the account behind it is
//! not, and no second lock path that could be forgotten.
//!
//! [`withdraw`](LiveAccount::withdraw) exists for the ONE thing locking cannot express: an account
//! being replaced or deleted, where the residency should stop being reachable at all rather than
//! merely stop answering.

use std::sync::{Arc, RwLock, RwLockWriteGuard};

use crate::account::residency::AccountResidency;

/// The shared slot holding the app's current unlocked-account residency, if it has one.
///
/// Cheap to clone (one `Arc`) and `Send + Sync`, so the shell keeps one while the CLI lane thread
/// holds another and both see the same publication. See the [module docs](self).
#[derive(Clone, Default)]
pub struct LiveAccount {
    slot: Arc<RwLock<Option<AccountResidency>>>,
}

impl LiveAccount {
    /// A slot with nothing in it — the state every process starts in, and the state a headless build
    /// stays in for its whole life.
    pub fn empty() -> Self {
        Self::default()
    }

    /// Publish `residency` as the app's current account, replacing any previous one.
    ///
    /// Called once per unlock. Replacing rather than merging is deliberate: a re-unlock produces a
    /// genuinely new [`AccountResidency`] over a fresh unlocked account, and leaving the previous one
    /// reachable would leave a locked husk answering for an account that has since reopened.
    pub fn publish(&self, residency: AccountResidency) {
        *self.write() = Some(residency);
    }

    /// Make the slot empty again — for an account being replaced or deleted, where "locked" is the
    /// wrong answer because there is no longer an account to unlock.
    pub fn withdraw(&self) {
        *self.write() = None;
    }

    /// The residency published at this instant, if any.
    ///
    /// **A reading, never a field.** See the [module docs](self): callers re-read rather than store.
    /// A `Some` here does NOT mean unlocked — ask the residency, which is the only thing that knows.
    pub fn read(&self) -> Option<AccountResidency> {
        match self.slot.read() {
            Ok(slot) => slot.clone(),
            Err(poisoned) => poisoned.into_inner().clone(),
        }
    }

    /// The one slot belonging to THIS process, created on first use.
    ///
    /// # Why a process-wide slot is the right shape here, and not a shortcut
    ///
    /// A process has exactly one unlocked account, by construction — `TraySession` is built at a
    /// single site in `dig-app`, and every unlock path (setup, restore, replace, the DID wizard, the
    /// tray's `Unlock…`) reaches it by calling that one function. So the slot is not a global standing
    /// in for state that is really plural; it is a global describing something genuinely singular.
    ///
    /// The alternative — threading a [`LiveAccount`] from `main` through the form-factor dispatch, the
    /// tray event loop and each account action — would add the handle to roughly eight signatures whose
    /// business is not the account, and would still end at this same single publish site.
    ///
    /// **It holds no key material and grants no authority.** The slot stores an
    /// [`AccountResidency`] handle; the residency owns the unlocked account and answers every
    /// capability request itself, so reaching this slot gets a caller exactly what asking the tray
    /// would: an account that may well be locked. Locking remains the residency's own business, so a
    /// residency parked here that has since locked reads back locked with nothing touching the slot.
    ///
    /// Tests use [`empty`](Self::empty) and never this, so no test can observe another's publication.
    pub fn of_this_process() -> Self {
        static SLOT: std::sync::OnceLock<LiveAccount> = std::sync::OnceLock::new();
        SLOT.get_or_init(Self::empty).clone()
    }

    /// The write guard, recovering from a poisoned lock rather than propagating the panic.
    ///
    /// A panic elsewhere must not leave the app permanently unable to publish an unlock: the slot
    /// holds one `Option` and no invariant spanning two writes, so there is nothing here a poisoned
    /// lock could have left half-updated.
    fn write(&self) -> RwLockWriteGuard<'_, Option<AccountResidency>> {
        self.slot
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::account::residency::test_support::residency;
    use crate::session_lock::SessionKeys;

    /// An unpublished slot reads empty — the state the lane serves in from start-up until an unlock.
    #[test]
    fn an_empty_slot_holds_no_account() {
        assert!(LiveAccount::empty().read().is_none());
    }

    /// A published residency is readable, and reads back as UNLOCKED — the control every locked-case
    /// assertion below needs, because a slot that could never produce an unlocked account would make
    /// each "it refuses when locked" test pass for the wrong reason.
    #[test]
    fn a_published_residency_reads_back_unlocked() {
        let live = LiveAccount::empty();
        live.publish(residency());

        let read = live.read().expect("the published residency is readable");
        assert!(
            read.receiving_address().is_some(),
            "a freshly published residency must be unlocked, or every locked-case test is vacuous"
        );
    }

    /// Locking the residency is observed through the slot WITHOUT the slot being told — the property
    /// that makes a second lock path unnecessary, and therefore unforgettable.
    #[test]
    fn locking_the_residency_is_visible_through_the_slot_with_no_second_write() {
        let live = LiveAccount::empty();
        let published = residency();
        live.publish(published.clone());
        assert!(
            live.read()
                .expect("published")
                .receiving_address()
                .is_some(),
            "control: unlocked before the lock"
        );

        published.lock_all();

        let read = live
            .read()
            .expect("the residency is still PRESENT, just locked");
        assert!(
            read.receiving_address().is_none(),
            "a lock applied to the residency must be visible through the slot"
        );
    }

    /// Withdrawing is distinguishable from locking: locked leaves a residency in place, withdrawn
    /// leaves none. The two states mean different things to a caller, so they must not collapse.
    #[test]
    fn withdrawing_empties_the_slot_where_locking_does_not() {
        let live = LiveAccount::empty();
        let published = residency();
        live.publish(published.clone());

        published.lock_all();
        assert!(
            live.read().is_some(),
            "a locked account is still an account"
        );

        live.withdraw();
        assert!(live.read().is_none(), "a withdrawn account is not");
    }

    /// A second publication replaces the first, so a re-unlock is not shadowed by the locked husk of
    /// the unlock it replaced.
    #[test]
    fn republishing_replaces_the_previous_residency() {
        let live = LiveAccount::empty();
        let first = residency();
        live.publish(first.clone());
        let first_address = live
            .read()
            .expect("published")
            .receiving_address()
            .expect("unlocked")
            .expect("derived");

        first.lock_all();
        live.publish(residency());

        let second_address = live
            .read()
            .expect("republished")
            .receiving_address()
            .expect("the replacement is unlocked, not the locked husk")
            .expect("derived");
        assert_ne!(
            first_address, second_address,
            "each test residency enrols its own seed, so a replacement must derive elsewhere"
        );
    }
}
