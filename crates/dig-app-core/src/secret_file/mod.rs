//! Putting a secret on disk: where it goes, and who can read it once it is there.
//!
//! The recovery-phrase backup (SPEC §3.1a) is the one flow in dig-app that deliberately writes an
//! account's custody root out in the clear, at the user's explicit and twice-confirmed request.
//! Everything in this module exists because of what that implies: whoever can read the resulting
//! file holds the funds.
//!
//! Two decisions have to be right, and they are coupled:
//!
//! * **Where the file goes** — [`picker`] asks the user, through the platform's own save dialog,
//!   instead of dropping the seed at a fixed and therefore predictable path (dig_ecosystem#1966).
//! * **Who can read it** — [`write_owner_only`] restricts the file to its owner AT CREATION on
//!   every platform, including Windows, where mode bits mean nothing (dig_ecosystem#1965).
//!
//! Letting the user choose the destination is what makes the second half load-bearing rather than
//! belt-and-braces: a chosen folder is far more likely to be a shared or cloud-synced one — a
//! Desktop, a Documents folder, a OneDrive tree — than the profile root ever was.

mod owner_only;
#[cfg(windows)]
mod windows_acl;

pub use owner_only::write_owner_only;
