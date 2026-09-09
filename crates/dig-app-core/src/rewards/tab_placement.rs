//! DECISIONS-3253 Q2 guards: this pane adds NO new tab, and does not turn Activity into a tab with
//! verbs.
//!
//! These are tests only — there is no production code here. The Rewards section itself is not
//! wired into the Content tab in this commit (see [`crate::rewards`]'s module doc for what is and
//! is not attempted); this file exists so the placement CONSTRAINT is checked from the first
//! commit, before any pane code could violate it.

#[cfg(test)]
mod tests {
    use crate::window_model::TabId;

    /// DECISIONS-3253 Q2: no 7th "Rewards" tab. `TabId::all()` must still be exactly the six
    /// labels, in order, that existed before this ticket.
    #[test]
    fn tab_id_all_is_still_the_six_labels() {
        let labels: Vec<&'static str> = TabId::all().into_iter().map(|id| id.label()).collect();
        assert_eq!(
            labels,
            vec![
                "Home",
                "Account",
                "Wallet",
                "Automatic spends",
                "Content",
                "Settings"
            ],
            "a 7th tab (or a relabelled/reordered one) appeared -- DECISIONS-3253 Q2 forbids a \
             Rewards tab; being paid as a mirror belongs in Automatic spends as a read-only record"
        );
    }
}
