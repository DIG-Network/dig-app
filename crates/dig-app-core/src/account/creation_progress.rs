//! Turning a profile creation's progress into something a window can draw (dig_ecosystem#2995).
//!
//! [`create_profile`](super::profile_creation::create_profile) already reports every step it
//! reaches — it always did, and nothing was listening, because the only caller was blocking the
//! painting thread for the whole ceremony. This module is the listener: it translates dig-account's
//! ladder into the [`Transaction`] the app's status sheet reads.
//!
//! # It translates and it decides nothing
//!
//! Every fact here comes from the step it is given. Nothing infers a confirmation, nothing invents a
//! height, and the two phases are named apart so a person can see WHICH half of a two-bundle
//! ceremony they are watching. The one judgement made is [`Transaction::more_to_come`] — whether a
//! confirmed bundle ends the ceremony — and it is made from the step's own position in the ladder.

use crate::transaction::{Money, Stage, Transaction};

use super::profile_creation::{Creation, CreationStep, Spent, Stopped};

/// What the whole ceremony is, in the person's words.
pub const CREATING: &str = "Creating your profile";

/// The second half, once the identity is on chain.
pub const LAUNCHING: &str = "Creating your profile — launching your store";

/// The advice that belongs on every stopped creation.
///
/// It is the same promise `first_profile`'s copy makes and for the same reason: this build cannot
/// resume an interrupted ceremony, so quitting is the one action that turns a recoverable pause into
/// a permanent loss.
pub const KEEP_DIG_RUNNING: &str =
    "Leave DIG running. Do not quit it — an interrupted creation cannot be picked back up, and any \
     money already committed is on chain either way.";

/// The transaction a creation starts as: nothing built, nothing sent, and the cost stated.
pub fn starting(cost_mojos: u64) -> Transaction {
    Transaction::starting(
        CREATING,
        Some(Money {
            amount_mojos: cost_mojos,
            // The offer this ceremony was approved from quotes ONE number — what the creation
            // costs — and does not break out a fee. Passing a zero here would invent a claim the
            // caller never made.
            fee_mojos: None,
        }),
    )
}

/// Where `step` puts the ceremony.
///
/// # The DID's confirmation is REAL and is not the end
///
/// `DidConfirmed` carries a height the chain reported, so it is drawn as the confirmation it is —
/// but the store has not been launched yet, so it is marked mid-ceremony. Drawing it as a finished
/// transaction would offer to clear a ceremony that is still spending.
pub fn of_step(base: &Transaction, step: &CreationStep) -> Transaction {
    match step {
        CreationStep::DidSubmitted { did_coin_id } => base.mid_ceremony(
            CREATING,
            Stage::Pushed {
                id: format!("Identity coin {did_coin_id}"),
            },
        ),
        CreationStep::DidConfirmed {
            did,
            confirmed_height,
            ..
        } => base.mid_ceremony(
            LAUNCHING,
            Stage::Confirmed {
                height: *confirmed_height,
                made: format!("Your identity exists: {did}. DIG is now launching your store."),
            },
        ),
        CreationStep::StoreSubmitted {
            store_launcher_id, ..
        } => base.mid_ceremony(
            LAUNCHING,
            Stage::Pushed {
                id: format!("Store launcher {store_launcher_id}"),
            },
        ),
        CreationStep::Confirmed(profile) => base.at(Stage::Confirmed {
            height: profile.store_confirmed_height,
            made: format!(
                "Your profile is on chain.\n\n{}\nStore {}",
                profile.did, profile.store_launcher_id
            ),
        }),
        // A stage this build cannot read. It is neither progress nor a fault, so it claims neither:
        // the ceremony is still under way and the surface keeps saying so.
        CreationStep::Unrecognised => base.mid_ceremony(CREATING, base.stage.clone()),
    }
}

/// Where `outcome` leaves the ceremony — the last thing the sheet will say about it.
pub fn of_outcome(base: &Transaction, outcome: &Creation) -> Transaction {
    match outcome {
        Creation::Created { profile, .. } => base.at(Stage::Confirmed {
            height: profile.store_confirmed_height,
            made: super::profile_creation::copy::created_body(profile),
        }),
        Creation::Stopped(stopped) => base.at(Stage::Failed {
            why: stopped_why(stopped),
            next: KEEP_DIG_RUNNING.to_string(),
        }),
    }
}

/// Why a creation stopped, said in the words the app already uses for it.
///
/// Deliberately dig-account's own account of the money — [`Spent`] distinguishes *nothing left your
/// wallet* from *it cannot be known* — because collapsing those two is how a person is either
/// invited to pay twice or told their funds are gone on no evidence.
fn stopped_why(stopped: &Stopped) -> String {
    let money = match &stopped.spent {
        Spent::Nothing => "No money left your wallet.",
        Spent::Unknown { .. } => {
            "DIG cannot tell whether money left your wallet — a transaction may be waiting in the \
             mempool right now."
        }
        Spent::Committed => {
            "Money has left your wallet: a coin this creation paid for is on chain."
        }
    };
    format!("{}\n\n{money}", stopped.why)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::account::profile_creation::ConfirmedProfile;
    use dig_account::ProfileIx;

    /// The profile the chain confirmed in the incident this ticket came from.
    fn confirmed() -> ConfirmedProfile {
        ConfirmedProfile {
            did: "did:chia:1mhdr5h6pyzqerp6h3cdkqjl24he8aatja24rz68chl7c9lqlluaspqwc6r".to_string(),
            did_coin_id: "0xe4e2b74f915e7f4a739b305aa086aa657a09a8a4df231d9307bb265c528ecc12"
                .to_string(),
            did_confirmed_height: 9_154_450,
            store_launcher_id: "0x111eb8bce53a9b46bedc6a8883b50b6e503ee333384930e93ef3054b25e992be"
                .to_string(),
            store_confirmed_height: 9_154_458,
        }
    }

    /// **No step short of the last one settles the transaction.**
    ///
    /// The trap this guards is `DidConfirmed`: a genuine, chain-proved confirmation that arrives
    /// with a whole second bundle still to pay for and to wait on. Every earlier step is included so
    /// that a mapping which settled everything, or nothing, fails here.
    #[test]
    fn only_the_finished_ceremony_settles() {
        let base = starting(20_002);
        let steps = [
            CreationStep::DidSubmitted {
                did_coin_id: confirmed().did_coin_id,
            },
            CreationStep::DidConfirmed {
                did: confirmed().did,
                did_coin_id: confirmed().did_coin_id,
                confirmed_height: confirmed().did_confirmed_height,
            },
            CreationStep::StoreSubmitted {
                did: confirmed().did,
                store_launcher_id: confirmed().store_launcher_id,
            },
            CreationStep::Unrecognised,
        ];
        for step in steps {
            assert!(
                !of_step(&base, &step).is_settled(),
                "{step:?} settled the transaction while the ceremony was still going"
            );
        }

        let finished = of_step(&base, &CreationStep::Confirmed(confirmed()));
        assert!(
            finished.is_settled(),
            "the finished ceremony never settles, so its sheet can never be cleared"
        );
    }

    /// **The DID's confirmation is drawn as the confirmation it is, at the height the chain gave.**
    ///
    /// Honesty runs in both directions: understating a chain-proved fact would have the app deny
    /// something the person has already paid for and could see on a block explorer.
    #[test]
    fn a_confirmed_identity_is_reported_at_its_real_height() {
        let base = starting(20_002);
        let at = of_step(
            &base,
            &CreationStep::DidConfirmed {
                did: confirmed().did,
                did_coin_id: confirmed().did_coin_id,
                confirmed_height: 9_154_450,
            },
        );
        assert_eq!(
            at.stage,
            Stage::Confirmed {
                height: 9_154_450,
                made: format!(
                    "Your identity exists: {}. DIG is now launching your store.",
                    confirmed().did
                ),
            }
        );
        assert_eq!(
            at.what, LAUNCHING,
            "the sheet does not say which half of the ceremony is running"
        );
    }

    /// **A submitted bundle is a push, carrying an id, and never a confirmation.**
    #[test]
    fn a_submitted_bundle_is_never_confirmed_and_carries_its_id() {
        let base = starting(20_002);
        for (step, id) in [
            (
                CreationStep::DidSubmitted {
                    did_coin_id: confirmed().did_coin_id,
                },
                confirmed().did_coin_id,
            ),
            (
                CreationStep::StoreSubmitted {
                    did: confirmed().did,
                    store_launcher_id: confirmed().store_launcher_id,
                },
                confirmed().store_launcher_id,
            ),
        ] {
            let at = of_step(&base, &step);
            assert!(
                !at.stage.is_confirmed(),
                "{step:?} was drawn as confirmed on nothing but a broadcast"
            );
            assert!(
                at.stage.detail().contains(&id),
                "{step:?} dropped the id a person would look it up by"
            );
        }
    }

    /// **A stopped creation says what is known about the money, and never invents certainty.**
    ///
    /// The three `Spent` verdicts must reach the person as three different sentences: collapsing
    /// `Unknown` into either certainty is how somebody is invited to pay twice, or told their money
    /// is gone on no evidence at all.
    #[test]
    fn a_stop_reports_the_money_verdict_it_was_given() {
        let base = starting(20_002);
        let sentences: Vec<String> = [
            Spent::Nothing,
            Spent::Unknown {
                detail: "the node stopped answering".to_string(),
            },
            Spent::Committed,
        ]
        .into_iter()
        .map(|spent| {
            let stopped = Stopped {
                reached: None,
                spent,
                why: "DIG lost the node.".to_string(),
                may_be_forgotten: false,
            };
            match of_outcome(&base, &Creation::Stopped(stopped)).stage {
                Stage::Failed { why, next } => {
                    assert!(next.contains("Leave DIG running"), "no next action: {next}");
                    why
                }
                other => panic!("a stopped creation was not a failure: {other:?}"),
            }
        })
        .collect();

        for (i, said) in sentences.iter().enumerate() {
            for other in &sentences[i + 1..] {
                assert_ne!(
                    said, other,
                    "two different money verdicts reached the person as the same sentence"
                );
            }
        }
    }

    /// **The cost is carried from the first frame to the last.**
    ///
    /// A person watching a spend asks what it costs at every stage, not only at the offer.
    #[test]
    fn the_cost_survives_every_stage() {
        let base = starting(20_002);
        let steps = [
            CreationStep::DidSubmitted {
                did_coin_id: confirmed().did_coin_id,
            },
            CreationStep::Confirmed(confirmed()),
        ];
        for step in steps {
            assert_eq!(
                of_step(&base, &step).money,
                base.money,
                "{step:?} lost the cost"
            );
        }
        assert_eq!(
            of_outcome(
                &base,
                &Creation::Created {
                    ix: ProfileIx::ROOT,
                    profile: confirmed(),
                }
            )
            .money,
            base.money
        );
    }
}
