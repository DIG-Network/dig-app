# reviewed
language-name = English
catalog-review-state = reviewed
balance-known = Balance: { $dig } $DIG · { $xch } XCH
rewards-create-warning-summary = PROVISIONAL: Rewards are distributed only while this node's prover runs. Funds are not lost when it stops -- they stay in the reserve. While stopped, the entry set is frozen: peers that stopped mirroring keep earning, and new mirrors cannot join. At your current commitment, a dead prover can pay a frozen set for at most { $max_epochs } more epochs.
rewards-refill-cadence = At this funding rate a mirror clears the claim threshold every { $days } days.
rewards-clawback-confirm-summary = PROVISIONAL: Clawing back this commitment returns { $recoverable } to you and leaves { $retained_percent }% in the reserve for the mirrors. This applies only to the funder's own key for this commitment slot.
rewards-status-not-distributing = Not distributing
rewards-status-never-ran = Never ran
rewards-status-entry-count-unknown = Entry count unknown -- no write recorded yet
