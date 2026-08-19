//! Owner-only Windows access control, shared by every kernel object that needs a `0600` equivalent.
//!
//! # Why this exists once, and centrally
//!
//! Windows honours no mode bits, so "reachable by me and nobody else" has to be spelled as a
//! discretionary access-control list holding exactly ONE access-allowed entry — for the calling
//! user's own SID — marked **protected** so the container's inheritable entries are not merged back
//! into it. That is several hundred lines of `unsafe` FFI, and it is a security primitive: a second
//! copy of it is a byte-drift bug waiting to happen (CLAUDE.md Appendix B).
//!
//! Two objects in this crate need it, for the same reason and with different access masks:
//!
//! * the recovery-phrase backup file ([`crate::secret_file`]) — whoever reads it holds the funds;
//! * the `dign` CLI named pipe ([`crate::cli_session`]) — whoever connects to it is handed the
//!   session token in cleartext, and whoever *creates* it first can impersonate dig-app.
//!
//! # What a DEFAULT descriptor actually grants, which is the trap
//!
//! Passing no security descriptor reads as "the process token's own DACL, so this user and SYSTEM".
//! For a **named pipe** that is measurably false: `CreateNamedPipe`'s documented default descriptor
//! grants read access to **Everyone** and to the **anonymous** account, and that is what this host
//! measured. The only honest way to state a per-user boundary on a kernel object is to build one.
//!
//! # What is deliberately NOT granted
//!
//! Administrators and SYSTEM get nothing. An administrator can still take ownership, exactly as
//! `root` can read a `0600` file; the point of the single ACE is not to stop them but to stop
//! everything merely *running* on the machine — backup agents, indexers, sync clients — from
//! reaching the object in passing.

use std::ffi::c_void;
use std::io;
use std::mem::size_of;
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};

use windows::core::PWSTR;
use windows::Win32::Foundation::{LocalFree, ERROR_SUCCESS, HANDLE, HLOCAL, WIN32_ERROR};
use windows::Win32::Security::Authorization::{
    SetEntriesInAclW, EXPLICIT_ACCESS_W, NO_MULTIPLE_TRUSTEE, SET_ACCESS, TRUSTEE_IS_SID,
    TRUSTEE_IS_USER, TRUSTEE_W,
};
use windows::Win32::Security::{
    CopySid, GetLengthSid, GetTokenInformation, InitializeSecurityDescriptor,
    SetSecurityDescriptorControl, SetSecurityDescriptorDacl, TokenUser, ACL, NO_INHERITANCE,
    PSECURITY_DESCRIPTOR, PSID, SECURITY_ATTRIBUTES, SECURITY_DESCRIPTOR, SE_DACL_PROTECTED,
    TOKEN_QUERY, TOKEN_USER,
};
use windows::Win32::Storage::FileSystem::FILE_ALL_ACCESS;
use windows::Win32::System::SystemServices::SECURITY_DESCRIPTOR_REVISION;
use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

/// Full access to a **named pipe**, for the sole ACE of an owner-only pipe DACL.
///
/// `FILE_ALL_ACCESS` is every object-specific right in the file-object bit range, and for a pipe
/// that range is read as the PIPE rights: bit `0x0004` is `FILE_CREATE_PIPE_INSTANCE`, which a pipe
/// SERVER needs in order to mint each further instance of a name it already owns. Without it the
/// successor instance in [`crate::cli_session::transport`] would be refused and the lane would serve
/// exactly one client.
///
/// # Why the whole constant, and not the rights this crate can name
///
/// The first version of this enumerated the bits it believed were needed — standard rights,
/// `SYNCHRONIZE`, read/write of data and attributes, `FILE_CREATE_PIPE_INSTANCE` — on the reasoning
/// that spelling them out kept the pipe-instance right visible. It omitted `FILE_READ_EA` and
/// `FILE_WRITE_EA`, and that was not a cosmetic gap: a CLIENT opens the pipe with `GENERIC_READ |
/// GENERIC_WRITE`, which the OS expands to include both EA bits, so every real `dign` connection was
/// refused with `ERROR_ACCESS_DENIED` while the server sat in an untimed `ConnectNamedPipe` waiting
/// for a client that could never attach.
///
/// A hand-enumerated mask on a DENY-by-default ACL fails exactly that way — closed, silently, and
/// only against the caller you forgot to model. The canonical constant cannot omit a bit, so it is
/// the safer spelling even though it names the pipe-instance right less loudly.
pub(crate) const PIPE_ALL_ACCESS: u32 = FILE_ALL_ACCESS.0;

/// A DACL granting `access` to exactly one trustee and to nobody else.
///
/// Owns the list allocated by `SetEntriesInAclW`, which is `LocalAlloc`-ed memory the caller is
/// responsible for releasing — hence the [`Drop`] rather than a bare pointer at the call site.
pub(crate) struct OwnerOnlyDacl {
    acl: *mut ACL,
}

// SAFETY: the only non-`Send` member is a pointer into `LocalAlloc` heap that this value owns
// exclusively and frees on drop. It has no thread affinity, and nothing mutates it after
// construction, so both moving it between threads and sharing `&` across them are sound. The pipe
// listener needs this: it is built on the caller's thread and served on a background one.
unsafe impl Send for OwnerOnlyDacl {}
unsafe impl Sync for OwnerOnlyDacl {}

impl OwnerOnlyDacl {
    /// Build the list for whoever this process is running as.
    pub(crate) fn for_current_user(access: u32) -> io::Result<Self> {
        Self::granting(&current_user_sid()?, access)
    }

    /// Build a list whose sole entry grants `owner` the rights in `access`.
    pub(crate) fn granting(owner: &Sid, access: u32) -> io::Result<Self> {
        let entry = EXPLICIT_ACCESS_W {
            grfAccessPermissions: access,
            grfAccessMode: SET_ACCESS,
            // The object grants nothing to anything it might one day contain, and nothing is
            // inherited INTO it either — that is what SE_DACL_PROTECTED enforces.
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

        // A NULL DACL does not mean "no access", it means "access to EVERYONE" — so a success that
        // somehow handed back nothing would turn this whole type into the opposite of itself.
        // Unreachable with a fixed one-entry list, and checked anyway, because the fail-closed
        // property should hold structurally rather than rest on an undocumented guarantee.
        if acl.is_null() {
            return Err(io::Error::other(
                "the access-control list could not be built",
            ));
        }
        Ok(Self { acl })
    }

    /// The raw list, for a call that applies it to an object after creation.
    pub(crate) fn as_ptr(&self) -> *const ACL {
        self.acl
    }
}

impl Drop for OwnerOnlyDacl {
    fn drop(&mut self) {
        unsafe {
            let _ = LocalFree(HLOCAL(self.acl.cast()));
        }
    }
}

/// A protected, owner-only security descriptor ready to hand to a creating call.
///
/// Holds the DACL alongside the descriptor because the descriptor stores a bare pointer INTO it:
/// separating the two is how a creating call ends up reading freed memory.
pub(crate) struct ProtectedSecurity {
    descriptor: SECURITY_DESCRIPTOR,
    dacl: OwnerOnlyDacl,
}

// SAFETY: `SECURITY_DESCRIPTOR` here is a plain struct of pointers into the `dacl` this value owns.
// There is no thread affinity and no interior mutation; see the identical note on `OwnerOnlyDacl`.
unsafe impl Send for ProtectedSecurity {}
unsafe impl Sync for ProtectedSecurity {}

impl ProtectedSecurity {
    /// A descriptor granting `access` to the calling user alone, with inheritance severed.
    pub(crate) fn owner_only(access: u32) -> io::Result<Self> {
        let dacl = OwnerOnlyDacl::for_current_user(access)?;
        let mut descriptor = SECURITY_DESCRIPTOR::default();
        let raw = PSECURITY_DESCRIPTOR(std::ptr::addr_of_mut!(descriptor).cast());
        unsafe {
            InitializeSecurityDescriptor(raw, SECURITY_DESCRIPTOR_REVISION).map_err(to_io)?;
            SetSecurityDescriptorDacl(raw, true, Some(dacl.as_ptr()), false).map_err(to_io)?;
            SetSecurityDescriptorControl(raw, SE_DACL_PROTECTED, SE_DACL_PROTECTED)
                .map_err(to_io)?;
        }
        // The descriptor is in ABSOLUTE format: it holds pointers outward and none back to itself,
        // so returning it by value does not invalidate it.
        Ok(Self { descriptor, dacl })
    }

    /// The `SECURITY_ATTRIBUTES` a creating call takes, borrowing this descriptor.
    ///
    /// The Win32 field is `*mut` because some APIs may write through it; the creating calls used
    /// here only read it, which is why handing them the address of a shared borrow is sound.
    pub(crate) fn attributes(&self) -> SECURITY_ATTRIBUTES {
        SECURITY_ATTRIBUTES {
            nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: std::ptr::addr_of!(self.descriptor) as *mut c_void,
            bInheritHandle: false.into(),
        }
    }

    /// The single-entry list inside this descriptor, for a call that re-applies it after creation.
    pub(crate) fn dacl(&self) -> &OwnerOnlyDacl {
        &self.dacl
    }
}

/// An owned, correctly-aligned copy of a security identifier.
///
/// SIDs are variable-length and must be DWORD-aligned, so they are held as `u32` words rather than
/// bytes — a `Vec<u8>` carries no such alignment guarantee and Win32 may read it as `u32`s.
pub(crate) struct Sid(Vec<u32>);

impl Sid {
    /// Copy the SID at `source`, which is only valid for as long as its own buffer is.
    pub(crate) fn copy_of(source: PSID) -> io::Result<Self> {
        let length = unsafe { GetLengthSid(source) };
        let mut words = vec![0u32; (length as usize).div_ceil(4).max(1)];
        let destination = PSID(words.as_mut_ptr().cast());
        unsafe { CopySid(length, destination, source) }.map_err(to_io)?;
        Ok(Self(words))
    }

    pub(crate) fn as_psid(&self) -> PSID {
        PSID(self.0.as_ptr() as *mut c_void)
    }
}

/// The SID of the account this process is running as.
pub(crate) fn current_user_sid() -> io::Result<Sid> {
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

/// Turn a Win32 status code into the `Ok`/`Err` the rest of the crate speaks.
pub(crate) fn check(status: WIN32_ERROR) -> io::Result<()> {
    if status == ERROR_SUCCESS {
        Ok(())
    } else {
        Err(io::Error::from_raw_os_error(status.0 as i32))
    }
}

/// Convert a `windows` error into an `io::Error`, preserving the OS code where there is one.
///
/// A Win32 code surfaced as an `HRESULT` keeps its original value in the low word
/// (`HRESULT_FROM_WIN32`), so unwrapping it there gives callers the same `raw_os_error` they would
/// have got from a std call — e.g. `ERROR_ACCESS_DENIED` stays recognisable as `5`.
pub(crate) fn to_io(error: windows::core::Error) -> io::Error {
    let hresult = error.code().0 as u32;
    if hresult & 0xFFFF_0000 == 0x8007_0000 {
        io::Error::from_raw_os_error((hresult & 0xFFFF) as i32)
    } else {
        io::Error::other(error)
    }
}

/// Read back what the OS actually recorded on an object, so a test can check the ACL that EXISTS
/// rather than that the call to set it returned `Ok`.
#[cfg(test)]
pub(crate) mod inspect {
    use super::{check, to_io, Sid};
    use std::ffi::c_void;
    use std::io;
    use std::mem::size_of;

    use windows::core::PWSTR;
    use windows::Win32::Foundation::{LocalFree, HANDLE, HLOCAL};
    use windows::Win32::Security::Authorization::{
        GetEffectiveRightsFromAclW, GetSecurityInfo, NO_MULTIPLE_TRUSTEE, SE_KERNEL_OBJECT,
        TRUSTEE_IS_SID, TRUSTEE_IS_USER, TRUSTEE_W,
    };
    use windows::Win32::Security::{
        AclSizeInformation, CreateWellKnownSid, GetAclInformation, GetSecurityDescriptorControl,
        WinAnonymousSid, WinBuiltinAdministratorsSid, WinLocalSystemSid, WinWorldSid, ACL,
        ACL_SIZE_INFORMATION, DACL_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, PSID,
        SECURITY_MAX_SID_SIZE, SE_DACL_PROTECTED, WELL_KNOWN_SID_TYPE,
    };

    /// What an object's DACL says about itself, independently of who wrote it.
    pub(crate) struct Dacl {
        /// True when inheritance is severed — the container's entries are NOT merged in.
        pub protected: bool,
        /// How many entries the list holds. Owner-only means exactly one.
        pub entries: u32,
    }

    /// An object's DACL, plus the effective rights it grants to any trustee you care to ask about.
    ///
    /// Holds the security descriptor alive because the ACL pointer borrows from it.
    pub(crate) struct ObjectSecurity {
        descriptor: PSECURITY_DESCRIPTOR,
        acl: *mut ACL,
    }

    impl ObjectSecurity {
        /// Read the DACL of any kernel object — a pipe instance, a file, a mutex — by handle.
        ///
        /// A named pipe has no path a name-based query can reach, so the handle form is the only
        /// way to ask the OS what a live pipe instance actually grants.
        pub(crate) fn of_kernel_object(handle: HANDLE) -> io::Result<Self> {
            let mut acl: *mut ACL = std::ptr::null_mut();
            let mut descriptor = PSECURITY_DESCRIPTOR::default();
            check(unsafe {
                GetSecurityInfo(
                    handle,
                    SE_KERNEL_OBJECT,
                    DACL_SECURITY_INFORMATION,
                    None,
                    None,
                    Some(&mut acl),
                    None,
                    Some(&mut descriptor),
                )
            })?;
            Ok(Self { descriptor, acl })
        }

        /// Adopt a descriptor and ACL some other query already produced.
        pub(crate) fn from_parts(descriptor: PSECURITY_DESCRIPTOR, acl: *mut ACL) -> Self {
            Self { descriptor, acl }
        }

        pub(crate) fn dacl(&self) -> io::Result<Dacl> {
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

        /// The access mask the OS itself computes for `who` against this object's real ACL.
        ///
        /// This is the question that matters — "could that principal reach this?" — answered by the
        /// same evaluation the security reference monitor performs, not by re-reading our own ACEs.
        pub(crate) fn rights_of(&self, who: &Sid) -> io::Result<u32> {
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

    impl Drop for ObjectSecurity {
        fn drop(&mut self) {
            unsafe {
                let _ = LocalFree(HLOCAL(self.descriptor.0));
            }
        }
    }

    /// The SID of a well-known principal — `WinWorldSid` (Everyone), `WinAnonymousSid`.
    pub(crate) fn well_known(kind: WELL_KNOWN_SID_TYPE) -> io::Result<Sid> {
        let mut words = vec![0u32; (SECURITY_MAX_SID_SIZE as usize).div_ceil(4)];
        let mut length = SECURITY_MAX_SID_SIZE;
        let sid = PSID(words.as_mut_ptr().cast::<c_void>());
        unsafe { CreateWellKnownSid(kind, None, sid, &mut length) }.map_err(to_io)?;
        Sid::copy_of(sid)
    }

    /// The SID this test process is running as.
    pub(crate) fn me() -> io::Result<Sid> {
        super::current_user_sid()
    }

    /// Everyone — the principal that must end up with nothing.
    pub(crate) fn everyone() -> io::Result<Sid> {
        well_known(WinWorldSid)
    }

    /// ANONYMOUS LOGON — the other principal a DEFAULT pipe descriptor hands read access to.
    pub(crate) fn anonymous() -> io::Result<Sid> {
        well_known(WinAnonymousSid)
    }

    /// The local Administrators group: present in an inherited profile ACL, absent from ours.
    pub(crate) fn administrators() -> io::Result<Sid> {
        well_known(WinBuiltinAdministratorsSid)
    }

    /// SYSTEM — the other principal an inherited profile ACL hands the object to.
    pub(crate) fn system() -> io::Result<Sid> {
        well_known(WinLocalSystemSid)
    }
}
