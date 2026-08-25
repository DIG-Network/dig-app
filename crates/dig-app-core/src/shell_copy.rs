//! The tray shell's own notices, where a guard test can see them (dig-app#260).
//!
//! # Why these had to leave `dig-app/src/bin`
//!
//! The copy guards enumerate user-facing bodies **by name**. A literal that lives inside
//! `crates/dig-app/src/bin/dig-app.rs` is structurally invisible to them, so nothing could tell that
//! one of these sentences had drifted from the code it describes — and that is not hypothetical. A
//! false promise (*"You will see the exact cost, and approve it, before anything is spent"*) survived
//! three releases in that file, found eventually by hand.
//!
//! **The "test-free zone" half of that argument has since expired, and the rest has not.** The binary
//! now carries eleven tests of its own and they do run. But being *able* to write a test somewhere is
//! not the same as anything enumerating what is there: the guard has to be able to walk the whole set
//! and refuse an addition it has not been told about, and it can only do that where the set is
//! declared. Hence [`ALL`].
//!
//! # What the guard actually catches
//!
//! Naming a control the reader cannot find — the dead end dig_ecosystem#1800 was opened for. Every
//! notice that sends someone to a menu row DECLARES which row in [`ShellNotice::points_at`], and the
//! test checks two things the prose alone cannot: that the body really does name it, and that the row
//! really does exist, by comparing against the same constants `tray_menu` builds the menu from.
//!
//! This is not a theoretical guard. Enumerating these notices is what turned up three notices and two
//! test assertions telling people to choose *"Manage my DIG Account"*, a row that has never existed —
//! the menu has always built *"Manage Account"*. One of those assertions sat directly beside a sibling
//! demanding *"the remedy must be named by the label the user will see"*.
//!
//! # The shape is an allow-list, deliberately
//!
//! A banned-phrase list only catches wording that has already been wrong once. An allow-list refuses a
//! NEW notice until its author says where it points, which is the part that rots.

use crate::tray_menu::{MANAGE_ACCOUNT_LABEL, SECURITY_LABEL};

/// One plain informational window the shell draws: what it is called, what it says, and where — if
/// anywhere — it sends the reader.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ShellNotice {
    /// The window title.
    pub title: &'static str,
    /// The one-line claim.
    pub heading: &'static str,
    /// The explanation beneath it.
    pub body: &'static str,
    /// The menu rows this notice tells the reader to go to, named as the menu names them.
    ///
    /// Empty for a notice that reports an outcome and asks nothing. A non-empty entry is a promise
    /// that the row exists AND that the body spells it exactly, and [`ALL`]'s guard holds both.
    pub points_at: &'static [&'static str],
}

/// Changing the password on an existing account.
pub mod password_change {
    use super::{ShellNotice, MANAGE_ACCOUNT_LABEL};

    /// The prompt shown when choosing the password.
    ///
    /// Says what does NOT change, because the question "will this lose my money?" is the one a person
    /// actually has at this moment and the answer is no.
    pub const CHOOSE_PROMPT: &str =
        "Choose a password for your DIG Account. Your account, address and recovery phrase all stay \
         exactly as they are — only the lock on them changes.";

    /// No window could be opened to ask for a password.
    pub const COULD_NOT_ASK: ShellNotice = ShellNotice {
        title: "DIG — Could not ask for a password",
        heading: "DIG could not open a window to ask for a password.",
        body: "Nothing was changed. The log folder, in this menu, has the details.",
        points_at: &[],
    };

    /// The password was adopted.
    pub const PASSWORD_SET: ShellNotice = ShellNotice {
        title: "DIG — Password set",
        heading: "Your DIG Account now has your password on it.",
        body:
            "It is the same account, with the same address and the same 24 words. From now on DIG \
               will ask for this password whenever it needs to unlock your account, and nothing on \
               this computer can open it without you.",
        points_at: &[],
    };

    /// The one arm that cannot be fixed in place: with no stored recovery phrase the seed cannot be
    /// read back out, so there is nothing to re-seal.
    ///
    /// The remedy is NAMED rather than gestured at, because advice pointing at a control the user
    /// cannot find is a dead end (dig_ecosystem#1800) — which is exactly why `points_at` is checked.
    pub const CANNOT_TAKE_PASSWORD: ShellNotice = ShellNotice {
        title: "DIG — This account cannot take a password",
        heading: "This account has no recovery phrase, so its password cannot be changed.",
        body: "It was created before DIG had recovery phrases. Nothing has changed and your account \
               still works exactly as before.\n\n\
               To get an account with a password of your own, replace this one: in the DIG menu \
               choose \"Manage Account\" then \"Replace this account with a NEW one…\". You will be \
               shown 24 words to write down, and you will get a NEW identity and address — this \
               account's data stays sealed to its old key and becomes unreadable.",
        points_at: &[MANAGE_ACCOUNT_LABEL],
    };

    /// The change was attempted and failed. Says the account is untouched, because that is the thing
    /// the reader is frightened about.
    pub const NOT_CHANGED: ShellNotice = ShellNotice {
        title: "DIG — Password not changed",
        heading: "Your DIG Account password could not be changed.",
        body: "Your account was left exactly as it was and still works. The log folder, in this \
               menu, has the details.",
        points_at: &[],
    };
}

/// Restoring an account from its recovery phrase.
pub mod restore_phrase {
    use super::ShellNotice;

    /// The prompt above the phrase field.
    pub const ASK_PROMPT: &str = "Restore your DIG Account from its recovery phrase.";

    /// The restore completed and a live session came up behind it.
    pub const ACCOUNT_RESTORED: ShellNotice = ShellNotice {
        title: "DIG — Account restored",
        heading: "Your DIG Account is back on this computer.",
        body: "You can view your recovery phrase again at any time from the DIG menu.",
        points_at: &[],
    };
}

/// Two-factor codes: the challenge, and turning them on or off.
pub mod twofa {
    use super::{ShellNotice, SECURITY_LABEL};

    /// A code is required but the account is locked, so no code can be checked.
    pub const NEEDS_UNLOCK: ShellNotice = ShellNotice {
        title: "DIG — Two-factor code needed",
        heading: "Unlock your DIG Account first.",
        body: "This account has two-factor codes turned on, so DIG needs a code from your \
               authenticator before it can do this — and it can only check one while the account is \
               unlocked.\n\n\
               Use Unlock in this menu and try again. If you no longer have your authenticator or \
               your recovery codes, turn two-factor off from the Security menu first.",
        points_at: &[SECURITY_LABEL],
    };

    /// The code did not verify.
    pub const WRONG_CODE: ShellNotice = ShellNotice {
        title: "DIG — Two-factor code needed",
        heading: "That code was not right, so nothing was changed.",
        body: "Codes change every 30 seconds — open your authenticator, wait for a fresh one, and \
               try again. A recovery code works too, and each of those works once.",
        points_at: &[],
    };

    /// A factor is enrolled and could not be judged. Fails closed, and says the account is unchanged.
    pub const COULD_NOT_CHECK: ShellNotice = ShellNotice {
        title: "DIG — Two-factor code needed",
        heading: "DIG could not check your code, so nothing changed.",
        body: "Your account is unchanged. The log folder (in this menu) has the details.",
        points_at: &[],
    };

    /// The title over the rate-limit notice. Its body is computed from the wait, so only the fixed
    /// part lives here.
    pub const TOO_MANY_TITLE: &str = "DIG — Too many attempts";
    /// Its heading.
    pub const TOO_MANY_HEADING: &str =
        "Too many codes were entered incorrectly, so nothing was changed.";

    /// Enrolment succeeded. The recovery-code count is filled in by the caller.
    pub const TURNED_ON_TITLE: &str = "DIG — Two-factor codes are on";
    /// Its heading.
    pub const TURNED_ON_HEADING: &str = "Two-factor codes are on for this account.";

    /// The shared title for the three enrolment outcomes that are not success.
    pub const ENROLMENT_TITLE: &str = "DIG — Two-factor codes";

    /// The key was never verified, so nothing was enabled.
    pub const NOT_VERIFIED: ShellNotice = ShellNotice {
        title: ENROLMENT_TITLE,
        heading: "Nothing was turned on — no code was accepted.",
        body: "Your account is exactly as it was. This usually means the key was not copied into \
               the authenticator correctly, or your phone's clock is off — check the phone's \
               automatic time setting and start again from the Security menu.",
        points_at: &[SECURITY_LABEL],
    };

    /// Already on. DIG will not quietly replace codes the user is already holding.
    pub const ALREADY_ON: ShellNotice = ShellNotice {
        title: ENROLMENT_TITLE,
        heading: "Two-factor codes are already on.",
        body: "To issue a new key and a fresh set of recovery codes, turn two-factor off from the \
               Security menu first, then set it up again. DIG will not quietly replace the codes \
               you are already holding.",
        points_at: &[SECURITY_LABEL],
    };

    /// Turned off. Says plainly that the old recovery codes are dead, because a person who kept them
    /// would otherwise believe they still have a way in.
    pub const TURNED_OFF: ShellNotice = ShellNotice {
        title: "DIG — Two-factor codes are off",
        heading: "Two-factor codes are off for this account.",
        body: "Replacing or removing this account will no longer ask for a code, and your old \
               recovery codes no longer work. You can set it up again at any time from the \
               Security menu — that issues a new key and a new set of codes.",
        points_at: &[SECURITY_LABEL],
    };

    /// Disabling failed; they are still on.
    pub const COULD_NOT_TURN_OFF: ShellNotice = ShellNotice {
        title: ENROLMENT_TITLE,
        heading: "Two-factor codes could not be turned off.",
        body: "They are still on and your account is unchanged. The log folder (in this menu) \
               has the details.",
        points_at: &[],
    };

    /// Enrolment failed outright.
    pub const COULD_NOT_TURN_ON: ShellNotice = ShellNotice {
        title: ENROLMENT_TITLE,
        heading: "Two-factor codes could not be turned on.",
        body: "Your account is unchanged and still works. The log folder (in this menu) has the \
               details.",
        points_at: &[],
    };
}

/// Every notice declared above, by name.
///
/// The enumeration IS the guard: a notice that is not here is not checked, so adding one and leaving
/// it out is the mistake the tests below are written to make loud.
pub const ALL: &[(&str, ShellNotice)] = &[
    (
        "password_change::COULD_NOT_ASK",
        password_change::COULD_NOT_ASK,
    ),
    (
        "password_change::PASSWORD_SET",
        password_change::PASSWORD_SET,
    ),
    (
        "password_change::CANNOT_TAKE_PASSWORD",
        password_change::CANNOT_TAKE_PASSWORD,
    ),
    ("password_change::NOT_CHANGED", password_change::NOT_CHANGED),
    (
        "restore_phrase::ACCOUNT_RESTORED",
        restore_phrase::ACCOUNT_RESTORED,
    ),
    ("twofa::NEEDS_UNLOCK", twofa::NEEDS_UNLOCK),
    ("twofa::WRONG_CODE", twofa::WRONG_CODE),
    ("twofa::COULD_NOT_CHECK", twofa::COULD_NOT_CHECK),
    ("twofa::NOT_VERIFIED", twofa::NOT_VERIFIED),
    ("twofa::ALREADY_ON", twofa::ALREADY_ON),
    ("twofa::COULD_NOT_TURN_ON", twofa::COULD_NOT_TURN_ON),
    ("twofa::TURNED_OFF", twofa::TURNED_OFF),
    ("twofa::COULD_NOT_TURN_OFF", twofa::COULD_NOT_TURN_OFF),
];

#[cfg(test)]
mod tests {
    use super::*;

    /// Every top-level row the menu builds. The guard compares against THIS rather than a list
    /// written here, so a renamed row breaks the notices that point at it.
    const REAL_MENU_ROWS: &[&str] = &[
        crate::tray_menu::VIEW_ACCOUNT_LABEL,
        crate::tray_menu::MANAGE_ACCOUNT_LABEL,
        crate::tray_menu::WALLET_LABEL,
        crate::tray_menu::SECURITY_LABEL,
        crate::tray_menu::CACHE_LABEL,
        crate::tray_menu::APPS_LABEL,
    ];

    /// **A notice may only send someone to a row that exists.**
    ///
    /// Makes impossible: the dead end of dig_ecosystem#1800 — advice naming a control the reader
    /// cannot find. This is the assertion that fails on the real defect this module was written after:
    /// three notices said *"Manage my DIG Account"* while the menu builds *"Manage Account"*.
    #[test]
    fn a_notice_only_points_at_menu_rows_that_exist() {
        for (name, notice) in ALL {
            for row in notice.points_at {
                assert!(
                    REAL_MENU_ROWS.contains(row),
                    "{name} sends the reader to a row the menu does not build: {row:?}"
                );
            }
        }
    }

    /// **A notice that declares a destination must actually NAME it.**
    ///
    /// The other half, and the half that catches drift rather than invention: `points_at` staying
    /// correct while the body is reworded into naming something else would satisfy the test above on
    /// its own. Together they pin the body to a row that exists.
    #[test]
    fn a_notice_names_every_row_it_claims_to_point_at() {
        for (name, notice) in ALL {
            for row in notice.points_at {
                assert!(
                    notice.body.contains(*row),
                    "{name} declares it points at {row:?} but its body never names it: {}",
                    notice.body
                );
            }
        }
    }

    /// **Every notice is fully written.**
    ///
    /// The cheapest possible drift — a constant added with a field left as `""` — reads on screen as
    /// a blank window rather than as a mistake.
    #[test]
    fn every_notice_has_a_title_a_heading_and_a_body() {
        for (name, notice) in ALL {
            assert!(!notice.title.trim().is_empty(), "{name} has no title");
            assert!(!notice.heading.trim().is_empty(), "{name} has no heading");
            assert!(!notice.body.trim().is_empty(), "{name} has no body");
        }
    }

    /// **Titles are branded one way.**
    ///
    /// The shell had both `DIG — Two-factor code needed` (em dash) and `DIG - Two-factor codes are on`
    /// (hyphen) in the SAME flow, a difference invisible in review and obvious on screen. Pinning the
    /// separator is the kind of rule that is only enforceable once the set can be walked.
    #[test]
    fn every_title_uses_the_one_brand_separator() {
        for (name, notice) in ALL {
            assert!(
                notice.title.starts_with("DIG — "),
                "{name} does not use the `DIG — ` title form: {:?}",
                notice.title
            );
        }
    }

    /// **No notice contains a run of whitespace.**
    ///
    /// Makes impossible: the corrupted literal this module produced ON ITS WAY IN. A Rust string
    /// continued with a trailing backslash swallows the next line's indentation; drop the backslash
    /// and `cargo fmt` folds the lines together, leaving sixteen spaces INSIDE the sentence. It still
    /// compiles, every other test still passes, and the user reads
    /// *"your old                recovery codes"*.
    ///
    /// Two of the notices above shipped that way for the length of one commit and were caught by
    /// diffing runtime values against the pre-move file — not by review, which had read straight past
    /// them twice. This is the cheap mechanical check that makes the expensive one unnecessary.
    #[test]
    fn no_notice_contains_a_run_of_whitespace() {
        for (name, notice) in ALL {
            for (field, text) in [
                ("title", notice.title),
                ("heading", notice.heading),
                ("body", notice.body),
            ] {
                assert!(
                    !text.contains("  "),
                    "{name}'s {field} carries a run of spaces, which reads as a hole on screen: {text:?}"
                );
            }
        }
    }

    /// **No notice claims a capability is missing from THIS BUILD.**
    ///
    /// A sentence of the *"not available in this version"* family is a claim about the build rather
    /// than about the user's machine, and it goes stale the moment the capability lands — silently,
    /// because nothing recompiles prose (dig_ecosystem#2940).
    #[test]
    fn no_notice_asserts_a_capability_is_absent_from_this_version() {
        for (name, notice) in ALL {
            for phrase in [
                "not available in this version",
                "not yet available",
                "coming soon",
            ] {
                assert!(
                    !notice.body.to_lowercase().contains(phrase),
                    "{name} makes a claim about the build rather than the machine: {phrase:?}"
                );
            }
        }
    }
}
