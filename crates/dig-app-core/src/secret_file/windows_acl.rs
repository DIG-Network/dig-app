//! The Windows half of [`super::write_owner_only`]: an explicit, protected, owner-only DACL.
//!
//! # Why this file exists at all
//!
//! Windows does not honour Unix mode bits. `std::fs::set_permissions` there can only toggle the
//! read-only ATTRIBUTE — there is no expression in the std API for "readable by me alone". So a
//! `chmod 0600` ported to Windows as a plain `fs::write` is not a weaker version of the Unix rule,
//! it is the ABSENCE of the rule: the file simply takes whatever the parent directory hands down.
//! Under the user profile that is the user, plus Administrators, plus SYSTEM.
//!
//! For most files that is the correct posture. For a recovery phrase it is not — whoever can read
//! that file holds the funds — and, worse, the code READS as though it were handled, because the
//! Unix arm right next to it is meticulous about mode `0600` (dig_ecosystem#1965).
//!
//! The genuine equivalent of `0600` on Windows is a discretionary access-control list holding
//! exactly ONE access-allowed entry, for the calling user's own SID, marked **protected** so the
//! parent directory's inheritable entries are not merged into it. That list, the SID lookup and the
//! descriptor around them are the same primitive the `dign` CLI pipe needs, so they live in
//! [`crate::windows_security`]; this module is only the FILE-specific half.
//!
//! # Why the DACL is applied twice
//!
//! `CreateFileW` takes a security descriptor, but Windows applies it **only when it actually
//! creates the file**: for a path that already exists, `CREATE_ALWAYS` truncates the file and
//! silently ignores the descriptor, leaving the old — possibly wide — ACL in place. A single
//! create call therefore protects a new file and quietly fails to protect a replaced one.
//!
//! So the descriptor is supplied at creation (a new file is never on disk unprotected, not even
//! for an instant), and the same DACL is then applied to the open handle with `SetSecurityInfo`,
//! which does not care whether the file is new. That second call happens while the file is
//! truncated to zero length — before a single secret byte is written — which is the same ordering
//! guarantee the Unix arm gets from `open(2)` plus `fchmod`.
//!
//! # What is deliberately NOT granted
//!
//! Administrators and SYSTEM get nothing. An administrator can still take ownership and read the
//! file, exactly as `root` can read a `0600` file on Unix; the point of the single ACE is not to
//! stop them but to stop everything that is merely *running* on the machine — backup agents,
//! indexers, sync clients, and any other process holding those groups' tokens — from reading a
//! recovery phrase in passing.

use std::fs::File;
use std::io::{self, Write};
use std::os::windows::ffi::OsStrExt;
use std::os::windows::io::AsRawHandle;
use std::path::Path;

use windows::core::PCWSTR;
use windows::Win32::Foundation::{GENERIC_WRITE, HANDLE};
use windows::Win32::Security::Authorization::{SetSecurityInfo, SE_FILE_OBJECT};
use windows::Win32::Security::{
    DACL_SECURITY_INFORMATION, OBJECT_SECURITY_INFORMATION, PROTECTED_DACL_SECURITY_INFORMATION,
    PSID,
};
use windows::Win32::Storage::FileSystem::GetVolumeInformationByHandleW;
use windows::Win32::Storage::FileSystem::{
    CreateFileW, CREATE_ALWAYS, FILE_ALL_ACCESS, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_MODE, WRITE_DAC,
};
use windows::Win32::System::SystemServices::FILE_PERSISTENT_ACLS;

use crate::windows_security::{check, to_io, OwnerOnlyDacl, ProtectedSecurity};

/// Create-or-truncate `path` under an owner-only DACL and write `bytes` into it.
///
/// See the module docs for why the DACL is applied both at creation and to the open handle, and
/// [`stores_acls`] for the one volume where there is no DACL to apply.
pub(super) fn write_owner_only(path: &Path, bytes: &[u8]) -> io::Result<()> {
    write_under_dacl(path, bytes, stores_acls)
}

/// [`write_owner_only`], with the volume-capability question injected.
///
/// The seam exists so a test can drive the `false` branch on an ordinary NTFS disk — there is no
/// FAT volume on a CI runner to reach it with otherwise, and an untested fail-open branch in
/// custody code is exactly the kind that rots quietly. Driving it `false` also isolates the
/// creation descriptor: with `SetSecurityInfo` skipped, a new file is protected by `CreateFileW`'s
/// descriptor ALONE, so a test in that mode fails if the descriptor is ever dropped.
fn write_under_dacl(
    path: &Path,
    bytes: &[u8],
    volume_stores_acls: impl Fn(&File) -> io::Result<bool>,
) -> io::Result<()> {
    // A file object's full-access mask, as distinct from the pipe mask its sibling call site uses.
    let security = ProtectedSecurity::owner_only(FILE_ALL_ACCESS.0)?;
    let mut file = create_truncated(path, &security)?;
    if volume_stores_acls(&file)? {
        apply_dacl_to(security.dacl(), &file)?;
    }
    file.write_all(bytes)
}

/// Whether the volume `file` lives on can persist access-control lists at all.
///
/// # Why this question has to be asked
///
/// The reason a user is offered a destination at all (dig_ecosystem#1966) is so they can put their
/// recovery phrase on a removable or encrypted volume of their own — and removable volumes are
/// routinely exFAT or FAT32, which have **no access control whatsoever**. There is no owner-only
/// DACL to write there, so insisting on one would fail the backup on precisely the destination the
/// picker exists to enable.
///
/// Skipping it there is not a downgrade, because there was never anything to downgrade FROM: a FAT
/// volume grants everyone everything by design, and the user reached this point through a stark
/// warning that the file is plaintext and anyone who can read it can take the account — which the
/// confirmation window repeats, naming the path. What the user is NOT told, and what this must
/// therefore never do, is skip the DACL on a volume that could have held one: on any filesystem
/// with access control the restriction stays mandatory and a failure to apply it is a failed backup.
fn stores_acls(file: &File) -> io::Result<bool> {
    let mut flags = 0u32;
    unsafe {
        GetVolumeInformationByHandleW(
            HANDLE(file.as_raw_handle()),
            None,
            None,
            None,
            Some(&mut flags),
            None,
        )
    }
    .map_err(to_io)?;
    Ok(flags & FILE_PERSISTENT_ACLS != 0)
}

/// Replace `file`'s DACL with `dacl`, and mark the result protected.
///
/// `PROTECTED_DACL_SECURITY_INFORMATION` is what severs inheritance: without it the parent
/// directory's inheritable entries are merged back in and the single-ACE list stops being a
/// single-ACE list. The handle must have been opened with `WRITE_DAC` for this to be permitted.
fn apply_dacl_to(dacl: &OwnerOnlyDacl, file: &File) -> io::Result<()> {
    check(unsafe {
        SetSecurityInfo(
            HANDLE(file.as_raw_handle()),
            SE_FILE_OBJECT,
            OBJECT_SECURITY_INFORMATION(
                DACL_SECURITY_INFORMATION.0 | PROTECTED_DACL_SECURITY_INFORMATION.0,
            ),
            PSID::default(),
            PSID::default(),
            Some(dacl.as_ptr()),
            None,
        )
    })
}

/// Put `dacl` on `path` WITHOUT protecting it, so the parent's inheritable entries stay.
///
/// Test-only, and deliberately the loose counterpart of [`apply_dacl_to`]: it is how a test
/// manufactures the wide-open starting condition that [`write_owner_only`] then has to close.
#[cfg(test)]
fn apply_unprotected_to(dacl: &OwnerOnlyDacl, path: &Path) -> io::Result<()> {
    use windows::Win32::Security::Authorization::SetNamedSecurityInfoW;

    let wide: Vec<u16> = path
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();
    check(unsafe {
        SetNamedSecurityInfoW(
            PCWSTR(wide.as_ptr()),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION,
            PSID::default(),
            PSID::default(),
            Some(dacl.as_ptr()),
            None,
        )
    })
}

/// Open `path` for writing, truncated, with `security` as the descriptor a NEW file is created under.
///
/// `WRITE_DAC` is requested alongside `GENERIC_WRITE` so the caller can re-apply the DACL to the
/// handle afterwards, which is the half that covers a path that already existed.
fn create_truncated(path: &Path, security: &ProtectedSecurity) -> io::Result<File> {
    use std::os::windows::io::FromRawHandle;

    let wide: Vec<u16> = path
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();
    let attributes = security.attributes();

    // Share mode 0: nothing else may open the file while the secret is being written.
    let handle = unsafe {
        CreateFileW(
            PCWSTR(wide.as_ptr()),
            GENERIC_WRITE.0 | WRITE_DAC.0,
            FILE_SHARE_MODE(0),
            Some(&attributes),
            CREATE_ALWAYS,
            FILE_ATTRIBUTE_NORMAL,
            None,
        )
    }
    .map_err(to_io)?;
    Ok(unsafe { File::from_raw_handle(handle.0) })
}

/// Read back what the OS actually recorded on a FILE, so a test can check the ACL that EXISTS.
///
/// The object-agnostic half of this — effective-rights queries, well-known SIDs, ACE counting —
/// lives in [`crate::windows_security::inspect`]; only the by-path lookup and the impersonation
/// probe are file-specific and stay here.
#[cfg(test)]
pub(super) mod inspect {
    use super::{apply_unprotected_to, check, to_io};
    use crate::windows_security::inspect::{well_known, ObjectSecurity};
    use crate::windows_security::{OwnerOnlyDacl, Sid};
    use std::io;
    use std::os::windows::ffi::OsStrExt;
    use std::path::Path;

    use windows::core::PCWSTR;
    use windows::Win32::Security::Authorization::{GetNamedSecurityInfoW, SE_FILE_OBJECT};
    use windows::Win32::Security::{
        WinWorldSid, ACL, DACL_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR,
    };
    use windows::Win32::Storage::FileSystem::FILE_ALL_ACCESS;

    pub(in crate::secret_file) use crate::windows_security::inspect::{
        administrators, everyone, me, system,
    };

    /// A file's security, looked up by path.
    pub(in crate::secret_file) struct FileSecurity;

    impl FileSecurity {
        pub(in crate::secret_file) fn of(path: &Path) -> io::Result<ObjectSecurity> {
            let wide: Vec<u16> = path
                .as_os_str()
                .encode_wide()
                .chain(std::iter::once(0))
                .collect();
            let mut acl: *mut ACL = std::ptr::null_mut();
            let mut descriptor = PSECURITY_DESCRIPTOR::default();
            check(unsafe {
                GetNamedSecurityInfoW(
                    PCWSTR(wide.as_ptr()),
                    SE_FILE_OBJECT,
                    DACL_SECURITY_INFORMATION,
                    None,
                    None,
                    Some(&mut acl),
                    None,
                    &mut descriptor,
                )
            })?;
            Ok(ObjectSecurity::from_parts(descriptor, acl))
        }
    }

    /// Open `path` up to Everyone, so a test can prove the write CLOSES a pre-existing wide ACL
    /// rather than merely being applied to a file that happened to be narrow already.
    pub(in crate::secret_file) fn open_to_everyone(path: &Path) -> io::Result<()> {
        let everyone: Sid = well_known(WinWorldSid)?;
        let dacl = OwnerOnlyDacl::granting(&everyone, FILE_ALL_ACCESS.0)?;
        apply_unprotected_to(&dacl, path)
    }

    /// Run the real volume probe against an open file, so a test can check what it reports.
    pub(in crate::secret_file) fn probe_volume_of(file: &std::fs::File) -> io::Result<bool> {
        super::stores_acls(file)
    }

    /// Try to OPEN `path` as a principal that is not the file's owner, and report whether it worked.
    ///
    /// # Why an effective-rights query was not enough
    ///
    /// An effective-rights query asks the OS to evaluate an ACL. This performs the actual syscall a
    /// second user would — the kernel's own access check, against a thread token in which the owner's
    /// SID is **deny-only**, so an allow-ACE naming that SID grants nothing. It is as close to
    /// "another account tries to read the recovery phrase" as a single-account test process can get,
    /// and it is the check that catches a permission bug an owner-run test cannot see.
    ///
    /// Impersonation is per-THREAD and is reverted by [`Impersonation`]'s `Drop`, including on panic.
    pub(in crate::secret_file) fn readable_without_owner_sid(path: &Path) -> io::Result<bool> {
        let _acting_as_someone_else = Impersonation::denying_our_own_sid()?;
        match std::fs::File::open(path) {
            Ok(_) => Ok(true),
            Err(e) if e.kind() == io::ErrorKind::PermissionDenied => Ok(false),
            Err(e) => Err(e),
        }
    }

    /// A thread impersonating a restricted token, reverted when it drops.
    struct Impersonation;

    impl Impersonation {
        /// Impersonate a copy of this process's token with our own SID marked deny-only.
        fn denying_our_own_sid() -> io::Result<Self> {
            use std::os::windows::io::{FromRawHandle, OwnedHandle};
            use windows::Win32::Foundation::HANDLE;
            use windows::Win32::Security::{
                CreateRestrictedToken, ImpersonateLoggedOnUser, DISABLE_MAX_PRIVILEGE,
                SID_AND_ATTRIBUTES, TOKEN_DUPLICATE, TOKEN_QUERY,
            };
            use windows::Win32::System::SystemServices::SE_GROUP_USE_FOR_DENY_ONLY;
            use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

            let mut ours = HANDLE::default();
            unsafe {
                OpenProcessToken(
                    GetCurrentProcess(),
                    TOKEN_DUPLICATE | TOKEN_QUERY,
                    &mut ours,
                )
            }
            .map_err(to_io)?;
            let ours_owned = unsafe { OwnedHandle::from_raw_handle(ours.0) };

            // Marking a SID deny-only leaves it in the token for DENY entries but strips its power to
            // GRANT — so the one allow-ACE naming this user stops applying, which is precisely the
            // difference between "the owner" and "somebody else" for this file.
            let me = crate::windows_security::current_user_sid()?;
            let disable = [SID_AND_ATTRIBUTES {
                Sid: me.as_psid(),
                Attributes: SE_GROUP_USE_FOR_DENY_ONLY as u32,
            }];

            let mut restricted = HANDLE::default();
            unsafe {
                CreateRestrictedToken(
                    ours,
                    DISABLE_MAX_PRIVILEGE,
                    Some(&disable),
                    None,
                    None,
                    &mut restricted,
                )
            }
            .map_err(to_io)?;
            let restricted_owned = unsafe { OwnedHandle::from_raw_handle(restricted.0) };

            unsafe { ImpersonateLoggedOnUser(restricted) }.map_err(to_io)?;
            drop(ours_owned);
            drop(restricted_owned);
            Ok(Self)
        }
    }

    impl Drop for Impersonation {
        fn drop(&mut self) {
            // If this ever failed the thread would keep the restricted token, so it is not ignored
            // quietly — a test thread that silently stayed impersonated would corrupt later tests.
            unsafe { windows::Win32::Security::RevertToSelf() }
                .expect("the test thread must stop impersonating");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::inspect::{everyone, probe_volume_of, FileSecurity};
    use super::write_under_dacl;

    /// On a volume that CANNOT hold an ACL the write still succeeds — refusing would fail the backup
    /// on a FAT/exFAT USB stick, which is the destination the save picker exists to enable.
    ///
    /// It also isolates the creation descriptor. With `SetSecurityInfo` skipped, the only thing that
    /// can protect a NEW file is `CreateFileW`'s own security descriptor, so this test goes red if
    /// that descriptor is ever dropped — which no other test here notices.
    #[test]
    fn a_volume_without_acls_still_gets_the_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("secret.txt");

        write_under_dacl(&path, b"redacted\n", |_| Ok(false)).unwrap();

        assert_eq!(std::fs::read(&path).unwrap(), b"redacted\n");
        // This directory is NTFS, so the creation descriptor really did apply, and it must have been
        // the owner-only one. On a true FAT volume there would be no ACL here to read at all.
        let security = FileSecurity::of(&path).unwrap();
        assert_eq!(
            security.rights_of(&everyone().unwrap()).unwrap(),
            0,
            "the creation descriptor alone must already exclude Everyone"
        );
        assert!(security.dacl().unwrap().protected);
    }

    /// The probe tells the truth about the volume these tests run on — so the fail-open branch above
    /// is genuinely NOT the path production takes here, and the permission tests mean what they say.
    #[test]
    fn an_ordinary_disk_reports_that_it_stores_acls() {
        let dir = tempfile::tempdir().unwrap();
        let probe = std::fs::File::create(dir.path().join("probe")).unwrap();

        assert!(
            probe_volume_of(&probe).unwrap(),
            "the test volume must support ACLs, or the permission tests prove nothing"
        );
    }
}
