//! DECISIONS-3253 Q2 guards: this pane adds NO new tab, and does not turn Activity into a tab with
//! verbs.
//!
//! These are tests only — there is no production code here. The Rewards section itself is not
//! wired into the Content tab in this commit (see [`crate::rewards`]'s module doc for what is and
//! is not attempted); this file exists so the placement CONSTRAINT is checked from the first
//! commit, before any pane code could violate it.

#[cfg(test)]
mod tests {
    use crate::window_model::{build, TabId, TrayView};

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

    /// DECISIONS-3253 Q2: being paid as a mirror is a read-only record, never a verb. The Activity
    /// tab must keep emitting zero action rows regardless of view state -- this pane must never be
    /// the lane that adds the first one.
    #[test]
    fn activity_tab_emits_zero_action_rows() {
        let view = TrayView::default();
        let model = build(&view);
        let activity = model
            .tabs
            .iter()
            .find(|tab| tab.id == TabId::Activity)
            .expect("Activity tab must exist");
        for section in &activity.sections {
            assert!(
                section.rows.is_empty(),
                "Activity tab emitted an action row: {:?} -- it must stay verb-free, including for \
                 any future reward-claim record",
                section.rows
            );
        }
    }
}
