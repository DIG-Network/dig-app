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
//! parent directory's inheritable entries are not merged into it.
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

use std::ffi::c_void;
use std::fs::File;
use std::io::{self, Write};
use std::mem::size_of;
use std::os::windows::ffi::OsStrExt;
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
use std::path::Path;

use windows::core::{PCWSTR, PWSTR};
use windows::Win32::Foundation::{
    LocalFree, ERROR_SUCCESS, GENERIC_WRITE, HANDLE, HLOCAL, WIN32_ERROR,
};
use windows::Win32::Security::Authorization::{
    SetEntriesInAclW, SetSecurityInfo, EXPLICIT_ACCESS_W, NO_MULTIPLE_TRUSTEE, SET_ACCESS,
    SE_FILE_OBJECT, TRUSTEE_IS_SID, TRUSTEE_IS_USER, TRUSTEE_W,
};
use windows::Win32::Security::{
    CopySid, GetLengthSid, GetTokenInformation, InitializeSecurityDescriptor,
    SetSecurityDescriptorControl, SetSecurityDescriptorDacl, TokenUser, ACL,
    DACL_SECURITY_INFORMATION, NO_INHERITANCE, OBJECT_SECURITY_INFORMATION,
    PROTECTED_DACL_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, PSID, SECURITY_ATTRIBUTES,
    SECURITY_DESCRIPTOR, SE_DACL_PROTECTED, TOKEN_QUERY, TOKEN_USER,
};
use windows::Win32::Storage::FileSystem::GetVolumeInformationByHandleW;
use windows::Win32::Storage::FileSystem::{
    CreateFileW, CREATE_ALWAYS, FILE_ALL_ACCESS, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_MODE, WRITE_DAC,
};
use windows::Win32::System::SystemServices::{FILE_PERSISTENT_ACLS, SECURITY_DESCRIPTOR_REVISION};
use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

/// Create-or-truncate `path` under an owner-only DACL and write `bytes` into it.
///
/// See the module docs for why the DACL is applied both at creation and to the open handle, and
/// [`stores_acls`] for the one volume where there is no DACL to apply.
pub(super) fn write_owner_only(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let dacl = OwnerOnlyDacl::for_current_user()?;
    let mut file = create_truncated(path, &dacl)?;
    if stores_acls(&file)? {
        dacl.apply_to(&file)?;
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

/// A DACL granting full access to exactly one trustee and to nobody else.
///
/// Owns the list allocated by `SetEntriesInAclW`, which is `LocalAlloc`-ed memory the caller is
/// responsible for releasing — hence the [`Drop`] rather than a bare pointer at the call site.
struct OwnerOnlyDacl {
    acl: *mut ACL,
}

impl OwnerOnlyDacl {
    /// Build the list for whoever this process is running as.
    fn for_current_user() -> io::Result<Self> {
        Self::granting(&current_user_sid()?)
    }

    /// Build a list whose sole entry grants `owner` full access.
    fn granting(owner: &Sid) -> io::Result<Self> {
        let entry = EXPLICIT_ACCESS_W {
            grfAccessPermissions: FILE_ALL_ACCESS.0,
            grfAccessMode: SET_ACCESS,
            // The file grants nothing to anything it might one day contain, and nothing is
            // inherited INTO it either — that is what SE_DACL_PROTECTED below enforces.
            grfInheritance: NO_INHERITANCE,
            Trustee: TRUSTEE_W {
                pMultipleTrustee: std::ptr::null_mut(),
                MultipleTrusteeOperation: NO_MULTIPLE_TRUSTEE,
                TrusteeForm: TRUSTEE_IS_SID,
                TrusteeType: TRUSTEE_IS_USER,
                // With TRUSTEE_IS_SID this field carries the SID pointer rather than a name. It is
                // a union the Win32 headers express as a string pointer, not a cast mistake here.
                ptstrName: PWSTR(owner.as_psid().0.cast()),
            },
        };

        // No old ACL to merge with, so the result holds this single entry and nothing else.
        let mut acl: *mut ACL = std::ptr::null_mut();
        check(unsafe { SetEntriesInAclW(Some(&[entry]), None, &mut acl) })?;
        Ok(Self { acl })
    }

    fn as_ptr(&self) -> *const ACL {
        self.acl
    }

    /// Replace `file`'s DACL with this one, and mark the result protected.
    ///
    /// `PROTECTED_DACL_SECURITY_INFORMATION` is what severs inheritance: without it the parent
    /// directory's inheritable entries are merged back in and the single-ACE list stops being a
    /// single-ACE list. The handle must have been opened with `WRITE_DAC` for this to be permitted.
    fn apply_to(&self, file: &File) -> io::Result<()> {
        check(unsafe {
            SetSecurityInfo(
                HANDLE(file.as_raw_handle()),
                SE_FILE_OBJECT,
                OBJECT_SECURITY_INFORMATION(
                    DACL_SECURITY_INFORMATION.0 | PROTECTED_DACL_SECURITY_INFORMATION.0,
                ),
                PSID::default(),
                PSID::default(),
                Some(self.acl),
                None,
            )
        })
    }

    /// Put this DACL on `path` WITHOUT protecting it, so the parent's inheritable entries stay.
    ///
    /// Test-only, and deliberately the loose counterpart of [`Self::apply_to`]: it is how a test
    /// manufactures the wide-open starting condition that [`write_owner_only`] then has to close.
    #[cfg(test)]
    fn apply_unprotected_to(&self, path: &Path) -> io::Result<()> {
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
                Some(self.acl),
                None,
            )
        })
    }
}

impl Drop for OwnerOnlyDacl {
    fn drop(&mut self) {
        unsafe {
            let _ = LocalFree(HLOCAL(self.acl.cast()));
        }
    }
}

/// Open `path` for writing, truncated, with `dacl` as the descriptor a NEW file is created under.
///
/// `WRITE_DAC` is requested alongside `GENERIC_WRITE` so the caller can re-apply the DACL to the
/// handle afterwards, which is the half that covers a path that already existed.
fn create_truncated(path: &Path, dacl: &OwnerOnlyDacl) -> io::Result<File> {
    let wide: Vec<u16> = path
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();

    let mut descriptor = SECURITY_DESCRIPTOR::default();
    let security = PSECURITY_DESCRIPTOR(std::ptr::addr_of_mut!(descriptor).cast());
    unsafe {
        InitializeSecurityDescriptor(security, SECURITY_DESCRIPTOR_REVISION).map_err(to_io)?;
        SetSecurityDescriptorDacl(security, true, Some(dacl.as_ptr()), false).map_err(to_io)?;
        SetSecurityDescriptorControl(security, SE_DACL_PROTECTED, SE_DACL_PROTECTED)
            .map_err(to_io)?;
    }

    let attributes = SECURITY_ATTRIBUTES {
        nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: security.0,
        bInheritHandle: false.into(),
    };

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

/// The SID of the account this process is running as.
fn current_user_sid() -> io::Result<Sid> {
    let mut raw = HANDLE::default();
    unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut raw) }.map_err(to_io)?;
    let token = unsafe { OwnedHandle::from_raw_handle(raw.0) };

    // TOKEN_USER is variable length (the SID inside it is), so the first call only measures. It is
    // EXPECTED to fail with ERROR_INSUFFICIENT_BUFFER, which is why its result is discarded rather
    // than checked — `needed` staying zero is what the second call would fail on.
    let mut needed = 0u32;
    let _ = unsafe {
        GetTokenInformation(
            HANDLE(token.as_raw_handle()),
            TokenUser,
            None,
            0,
            &mut needed,
        )
    };

    // u64 elements rather than u8: TOKEN_USER holds a pointer, so the buffer must be aligned for one.
    let mut buffer = vec![0u64; (needed as usize).div_ceil(8).max(1)];
    unsafe {
        GetTokenInformation(
            HANDLE(token.as_raw_handle()),
            TokenUser,
            Some(buffer.as_mut_ptr().cast()),
            needed,
            &mut needed,
        )
    }
    .map_err(to_io)?;

    let user = buffer.as_ptr() as *const TOKEN_USER;
    Sid::copy_of(unsafe { (*user).User.Sid })
}

/// An owned, correctly-aligned copy of a security identifier.
///
/// SIDs are variable-length and must be DWORD-aligned, so they are held as `u32` words rather than
/// bytes — a `Vec<u8>` carries no such alignment guarantee and Win32 may read it as `u32`s.
pub(in crate::secret_file) struct Sid(Vec<u32>);

impl Sid {
    /// Copy the SID at `source`, which is only valid for as long as its own buffer is.
    fn copy_of(source: PSID) -> io::Result<Self> {
        let length = unsafe { GetLengthSid(source) };
        let mut words = vec![0u32; (length as usize).div_ceil(4).max(1)];
        let destination = PSID(words.as_mut_ptr().cast());
        unsafe { CopySid(length, destination, source) }.map_err(to_io)?;
        Ok(Self(words))
    }

    fn as_psid(&self) -> PSID {
        PSID(self.0.as_ptr() as *mut c_void)
    }
}

/// Turn a Win32 status code into the `Ok`/`Err` the rest of the module speaks.
fn check(status: WIN32_ERROR) -> io::Result<()> {
    if status == ERROR_SUCCESS {
        Ok(())
    } else {
        Err(io::Error::from_raw_os_error(status.0 as i32))
    }
}

/// Convert a `windows` error into an `io::Error`, preserving the OS code where there is one.
///
/// A Win32 code surfaced as an `HRESULT` keeps its original value in the low word (`
/// HRESULT_FROM_WIN32`), so unwrapping it there gives callers the same `raw_os_error` they would
/// have got from a std call — e.g. `ERROR_ACCESS_DENIED` stays recognisable as `5`.
fn to_io(error: windows::core::Error) -> io::Error {
    let hresult = error.code().0 as u32;
    if hresult & 0xFFFF_0000 == 0x8007_0000 {
        io::Error::from_raw_os_error((hresult & 0xFFFF) as i32)
    } else {
        io::Error::other(error)
    }
}

/// Read back what the OS actually recorded on a file, so a test can check the ACL that EXISTS
/// rather than that the call to set it returned `Ok`.
#[cfg(test)]
pub(super) mod inspect {
    use super::{check, to_io, Sid};
    use std::ffi::c_void;
    use std::io;
    use std::mem::size_of;
    use std::os::windows::ffi::OsStrExt;
    use std::path::Path;

    use windows::core::{PCWSTR, PWSTR};
    use windows::Win32::Foundation::{LocalFree, HLOCAL};
    use windows::Win32::Security::Authorization::{
        GetEffectiveRightsFromAclW, GetNamedSecurityInfoW, NO_MULTIPLE_TRUSTEE, SE_FILE_OBJECT,
        TRUSTEE_IS_SID, TRUSTEE_IS_USER, TRUSTEE_W,
    };
    use windows::Win32::Security::{
        AclSizeInformation, CreateWellKnownSid, GetAclInformation, GetSecurityDescriptorControl,
        WinBuiltinAdministratorsSid, WinLocalSystemSid, WinWorldSid, ACL, ACL_SIZE_INFORMATION,
        DACL_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, PSID, SECURITY_MAX_SID_SIZE,
        SE_DACL_PROTECTED, WELL_KNOWN_SID_TYPE,
    };

    /// What a file's DACL says about itself, independently of who wrote it.
    pub(in crate::secret_file) struct Dacl {
        /// True when inheritance is severed — the parent directory's entries are NOT merged in.
        pub protected: bool,
        /// How many entries the list holds. Owner-only means exactly one.
        pub entries: u32,
    }

    /// A file's DACL, plus the effective rights it grants to any trustee you care to ask about.
    ///
    /// Holds the security descriptor alive because the ACL pointer borrows from it.
    pub(in crate::secret_file) struct FileSecurity {
        descriptor: PSECURITY_DESCRIPTOR,
        acl: *mut ACL,
    }

    impl FileSecurity {
        pub(in crate::secret_file) fn of(path: &Path) -> io::Result<Self> {
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
            Ok(Self { descriptor, acl })
        }

        pub(in crate::secret_file) fn dacl(&self) -> io::Result<Dacl> {
            let mut control = 0u16;
            let mut revision = 0u32;
            unsafe { GetSecurityDescriptorControl(self.descriptor, &mut control, &mut revision) }
                .map_err(to_io)?;

            let mut size = ACL_SIZE_INFORMATION::default();
            unsafe {
                GetAclInformation(
                    self.acl,
                    std::ptr::addr_of_mut!(size).cast(),
                    size_of::<ACL_SIZE_INFORMATION>() as u32,
                    AclSizeInformation,
                )
            }
            .map_err(to_io)?;

            Ok(Dacl {
                protected: control & SE_DACL_PROTECTED.0 != 0,
                entries: size.AceCount,
            })
        }

        /// The access mask the OS itself computes for `who` against this file's real ACL.
        ///
        /// This is the question that matters — "could that principal read this?" — answered by the
        /// same evaluation the security reference monitor performs, not by re-reading our own ACEs.
        pub(in crate::secret_file) fn rights_of(&self, who: &Sid) -> io::Result<u32> {
            let trustee = TRUSTEE_W {
                pMultipleTrustee: std::ptr::null_mut(),
                MultipleTrusteeOperation: NO_MULTIPLE_TRUSTEE,
                TrusteeForm: TRUSTEE_IS_SID,
                TrusteeType: TRUSTEE_IS_USER,
                ptstrName: PWSTR(who.as_psid().0.cast()),
            };
            let mut rights = 0u32;
            check(unsafe { GetEffectiveRightsFromAclW(self.acl, &trustee, &mut rights) })?;
            Ok(rights)
        }
    }

    impl Drop for FileSecurity {
        fn drop(&mut self) {
            unsafe {
                let _ = LocalFree(HLOCAL(self.descriptor.0));
            }
        }
    }

    /// The SID of a well-known principal — `WinWorldSid` (Everyone), `WinBuiltinAdministratorsSid`.
    pub(in crate::secret_file) fn well_known(kind: WELL_KNOWN_SID_TYPE) -> io::Result<Sid> {
        let mut words = vec![0u32; (SECURITY_MAX_SID_SIZE as usize).div_ceil(4)];
        let mut length = SECURITY_MAX_SID_SIZE;
        let sid = PSID(words.as_mut_ptr().cast::<c_void>());
        unsafe { CreateWellKnownSid(kind, None, sid, &mut length) }.map_err(to_io)?;
        Sid::copy_of(sid)
    }

    /// The SID this test process is running as.
    pub(in crate::secret_file) fn me() -> io::Result<Sid> {
        super::current_user_sid()
    }

    /// Open `path` up to Everyone, so a test can prove the write CLOSES a pre-existing wide ACL
    /// rather than merely being applied to a file that happened to be narrow already.
    pub(in crate::secret_file) fn open_to_everyone(path: &Path) -> io::Result<()> {
        let everyone = well_known(WinWorldSid)?;
        super::OwnerOnlyDacl::granting(&everyone)?.apply_unprotected_to(path)
    }

    /// Everyone — the principal that must end up with nothing.
    pub(in crate::secret_file) fn everyone() -> io::Result<Sid> {
        well_known(WinWorldSid)
    }

    /// The local Administrators group: present in the inherited profile ACL, absent from ours.
    pub(in crate::secret_file) fn administrators() -> io::Result<Sid> {
        well_known(WinBuiltinAdministratorsSid)
    }

    /// SYSTEM — the other principal an inherited profile ACL hands the file to.
    pub(in crate::secret_file) fn system() -> io::Result<Sid> {
        well_known(WinLocalSystemSid)
    }
}
