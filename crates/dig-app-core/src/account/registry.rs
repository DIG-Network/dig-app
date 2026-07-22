//! The Accounts registry (#1509 Phase 1, harness) — which accounts exist, which ONE is the default,
//! and which is currently active.
//!
//! # Invariants (upheld at every mutation, enforced by tests)
//!
//! 1. **Exactly one default when non-empty.** An empty registry has no default. The first account
//!    registered becomes the default. Removing the default promotes another remaining account (the
//!    next in insertion order); removing the last account clears the default. There is never zero
//!    defaults over a non-empty registry, and never two.
//! 2. **At most one active.** Zero or one account is "active" (the one whose UI/session is foreground).
//!    Removing the active account clears the active slot; it does NOT auto-promote (activation is a
//!    deliberate user action, unlike the always-present default).
//!
//! The registry is generic over the loaded-account handle `A` so it carries no `dig-account` type — on
//! adoption it is used as `AccountRegistry<dig_account::AccountSession>` (or `UnlockedAccount`),
//! unchanged. It owns bookkeeping only; it never touches key material.

use super::AccountId;
use dig_account::AccountSession;

/// The registry specialized to the production loaded-account handle: `dig-account`'s locked
/// [`AccountSession`]. This is the concrete type the harness holds — one locked session per registered
/// account, with the single default + active slot tracked on top. Unlocking a session yields a
/// transient `UnlockedAccount` the caller owns for the duration of a signing ceremony; the registry
/// itself only ever holds the safe, always-holdable locked handle.
pub type SessionRegistry = AccountRegistry<AccountSession>;

/// One registered account: its stable id plus the loaded handle of type `A`.
struct Entry<A> {
    id: AccountId,
    handle: A,
}

/// Tracks the set of accounts, the single default, and the active slot. Insertion order is preserved
/// (the order [`ids`](Self::ids) returns and default-promotion follows).
pub struct AccountRegistry<A> {
    entries: Vec<Entry<A>>,
    default: Option<AccountId>,
    active: Option<AccountId>,
}

impl<A> Default for AccountRegistry<A> {
    fn default() -> Self {
        Self::new()
    }
}

impl<A> AccountRegistry<A> {
    /// An empty registry — no accounts, no default, no active.
    pub fn new() -> Self {
        Self {
            entries: Vec::new(),
            default: None,
            active: None,
        }
    }

    /// The number of registered accounts.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the registry has no accounts.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// The registered account ids in insertion order.
    pub fn ids(&self) -> impl Iterator<Item = &AccountId> {
        self.entries.iter().map(|e| &e.id)
    }

    fn position(&self, id: &AccountId) -> Option<usize> {
        self.entries.iter().position(|e| &e.id == id)
    }

    /// Register `id` with its loaded `handle`.
    ///
    /// If `id` is already registered its handle is REPLACED (a re-load), and the default/active slots
    /// are left unchanged. The FIRST account ever registered becomes the default (invariant 1).
    /// Returns `true` if this was a new registration, `false` if it replaced an existing handle.
    pub fn register(&mut self, id: AccountId, handle: A) -> bool {
        if let Some(pos) = self.position(&id) {
            self.entries[pos].handle = handle;
            return false;
        }
        if self.default.is_none() {
            self.default = Some(id.clone());
        }
        self.entries.push(Entry { id, handle });
        true
    }

    /// Remove `id`. Maintains both invariants: if it was the default, the next remaining account (in
    /// insertion order) is promoted to default (or the default is cleared when none remain); if it was
    /// active, the active slot is cleared. Returns the removed handle, or `None` if `id` was unknown.
    pub fn remove(&mut self, id: &AccountId) -> Option<A> {
        let pos = self.position(id)?;
        let removed = self.entries.remove(pos);

        if self.active.as_ref() == Some(id) {
            self.active = None;
        }
        if self.default.as_ref() == Some(id) {
            // Promote the first remaining account (insertion order), or clear when empty.
            self.default = self.entries.first().map(|e| e.id.clone());
        }
        Some(removed.handle)
    }

    /// The default account's id, or `None` when the registry is empty.
    pub fn default_id(&self) -> Option<&AccountId> {
        self.default.as_ref()
    }

    /// Make `id` the default. Returns `false` (no change) if `id` is not registered.
    pub fn set_default(&mut self, id: &AccountId) -> bool {
        if self.position(id).is_some() {
            self.default = Some(id.clone());
            true
        } else {
            false
        }
    }

    /// The active account's id, or `None` when nothing is active.
    pub fn active_id(&self) -> Option<&AccountId> {
        self.active.as_ref()
    }

    /// Make `id` the active account. Returns `false` (no change) if `id` is not registered.
    pub fn set_active(&mut self, id: &AccountId) -> bool {
        if self.position(id).is_some() {
            self.active = Some(id.clone());
            true
        } else {
            false
        }
    }

    /// Clear the active slot (e.g. on relock / sign-out) without removing the account.
    pub fn clear_active(&mut self) {
        self.active = None;
    }

    /// The loaded handle for `id`, if registered.
    pub fn get(&self, id: &AccountId) -> Option<&A> {
        self.position(id).map(|pos| &self.entries[pos].handle)
    }

    /// A mutable reference to `id`'s handle, if registered.
    pub fn get_mut(&mut self, id: &AccountId) -> Option<&mut A> {
        self.position(id).map(|pos| &mut self.entries[pos].handle)
    }

    /// The active account's handle, if one is active.
    pub fn active(&self) -> Option<&A> {
        let id = self.active.as_ref()?;
        self.get(id)
    }

    /// A mutable reference to the active account's handle, if one is active.
    pub fn active_mut(&mut self) -> Option<&mut A> {
        let id = self.active.clone()?;
        self.get_mut(&id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn id(s: &str) -> AccountId {
        AccountId::new(s)
    }

    /// A stand-in loaded-account handle. In production `A` is `dig_account::AccountSession`.
    #[derive(Debug, PartialEq)]
    struct FakeHandle(u32);

    #[test]
    fn a_new_registry_is_empty_with_no_default_or_active() {
        let reg: AccountRegistry<FakeHandle> = AccountRegistry::new();
        assert!(reg.is_empty());
        assert_eq!(reg.len(), 0);
        assert!(reg.default_id().is_none());
        assert!(reg.active_id().is_none());
    }

    #[test]
    fn the_first_registered_account_becomes_the_default() {
        let mut reg = AccountRegistry::new();
        assert!(reg.register(id("a"), FakeHandle(1)));
        assert_eq!(reg.default_id(), Some(&id("a")));

        // A second account does NOT steal the default.
        assert!(reg.register(id("b"), FakeHandle(2)));
        assert_eq!(reg.default_id(), Some(&id("a")));
        assert_eq!(reg.len(), 2);
    }

    #[test]
    fn re_registering_replaces_the_handle_without_disturbing_slots() {
        let mut reg = AccountRegistry::new();
        reg.register(id("a"), FakeHandle(1));
        reg.set_active(&id("a"));

        assert!(!reg.register(id("a"), FakeHandle(9)), "replace ⇒ not new");
        assert_eq!(reg.get(&id("a")), Some(&FakeHandle(9)));
        assert_eq!(reg.len(), 1);
        assert_eq!(reg.default_id(), Some(&id("a")));
        assert_eq!(reg.active_id(), Some(&id("a")));
    }

    #[test]
    fn set_default_and_set_active_require_a_registered_account() {
        let mut reg = AccountRegistry::new();
        reg.register(id("a"), FakeHandle(1));

        assert!(!reg.set_default(&id("ghost")));
        assert!(!reg.set_active(&id("ghost")));
        assert_eq!(reg.default_id(), Some(&id("a")));
        assert!(reg.active_id().is_none());

        assert!(reg.set_active(&id("a")));
        assert_eq!(reg.active_id(), Some(&id("a")));
    }

    #[test]
    fn removing_the_default_promotes_the_next_in_insertion_order() {
        let mut reg = AccountRegistry::new();
        reg.register(id("a"), FakeHandle(1)); // default
        reg.register(id("b"), FakeHandle(2));
        reg.register(id("c"), FakeHandle(3));

        assert_eq!(reg.remove(&id("a")), Some(FakeHandle(1)));
        assert_eq!(
            reg.default_id(),
            Some(&id("b")),
            "next-in-order is promoted to default"
        );
        assert_eq!(reg.len(), 2);
    }

    #[test]
    fn removing_the_active_clears_the_active_slot_without_promotion() {
        let mut reg = AccountRegistry::new();
        reg.register(id("a"), FakeHandle(1));
        reg.register(id("b"), FakeHandle(2));
        reg.set_active(&id("b"));

        reg.remove(&id("b"));
        assert!(reg.active_id().is_none(), "no auto-promote for active");
        // Default (a) is untouched since b was not the default.
        assert_eq!(reg.default_id(), Some(&id("a")));
    }

    #[test]
    fn removing_the_last_account_clears_the_default() {
        let mut reg = AccountRegistry::new();
        reg.register(id("only"), FakeHandle(1));
        reg.remove(&id("only"));
        assert!(reg.is_empty());
        assert!(reg.default_id().is_none(), "empty ⇒ no default");
    }

    #[test]
    fn remove_of_an_unknown_account_is_a_noop_none() {
        let mut reg = AccountRegistry::new();
        reg.register(id("a"), FakeHandle(1));
        assert!(reg.remove(&id("ghost")).is_none());
        assert_eq!(reg.len(), 1);
        assert_eq!(reg.default_id(), Some(&id("a")));
    }

    #[test]
    fn active_handle_accessors_follow_the_active_slot() {
        let mut reg = AccountRegistry::new();
        reg.register(id("a"), FakeHandle(1));
        reg.register(id("b"), FakeHandle(2));

        assert!(reg.active().is_none());
        reg.set_active(&id("b"));
        assert_eq!(reg.active(), Some(&FakeHandle(2)));

        if let Some(h) = reg.active_mut() {
            h.0 = 42;
        }
        assert_eq!(reg.get(&id("b")), Some(&FakeHandle(42)));

        reg.clear_active();
        assert!(reg.active().is_none());
    }
}
