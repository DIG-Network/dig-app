//! The Windows save dialog: `GetSaveFileNameW`.

use std::ffi::OsString;
use std::os::windows::ffi::{OsStrExt, OsStringExt};
use std::path::PathBuf;

use windows::core::{PCWSTR, PWSTR};
use windows::Win32::UI::Controls::Dialogs::{
    CommDlgExtendedError, GetSaveFileNameW, COMMON_DLG_ERRORS, OFN_NOCHANGEDIR,
    OFN_OVERWRITEPROMPT, OFN_PATHMUSTEXIST, OPENFILENAMEW,
};

use super::{PickedPath, SaveFileRequest};

/// Long enough for any path Windows will hand back, including the extended forms.
///
/// `MAX_PATH` is not the limit here — the dialog can return a longer path on a system with long
/// paths enabled — and the buffer length is what the dialog truncates against, so it is generous.
const PATH_BUFFER: usize = 32_768;

/// Raise the save dialog and block until the user answers.
pub(super) fn ask(request: &SaveFileRequest<'_>) -> PickedPath {
    let title = wide(request.title);
    let filter = filter();
    let default_extension = wide("txt");
    let starting_dir = request.starting_dir.map(|dir| wide_os(dir.as_os_str()));

    // The dialog reads the pre-filled name out of this buffer and writes the answer back into it.
    let mut chosen = vec![0u16; PATH_BUFFER];
    for (slot, unit) in chosen.iter_mut().zip(request.file_name.encode_utf16()) {
        *slot = unit;
    }

    let mut dialog = OPENFILENAMEW {
        lStructSize: std::mem::size_of::<OPENFILENAMEW>() as u32,
        lpstrFilter: PCWSTR(filter.as_ptr()),
        lpstrFile: PWSTR(chosen.as_mut_ptr()),
        nMaxFile: chosen.len() as u32,
        lpstrTitle: PCWSTR(title.as_ptr()),
        lpstrInitialDir: starting_dir
            .as_ref()
            .map_or(PCWSTR::null(), |dir| PCWSTR(dir.as_ptr())),
        lpstrDefExt: PCWSTR(default_extension.as_ptr()),
        // OVERWRITEPROMPT so replacing an existing file is the user's decision, not a surprise;
        // PATHMUSTEXIST so a typo'd folder is rejected in the dialog rather than as a failed write;
        // NOCHANGEDIR so the dialog does not move this process's working directory out from under it.
        Flags: OFN_OVERWRITEPROMPT | OFN_PATHMUSTEXIST | OFN_NOCHANGEDIR,
        ..Default::default()
    };

    if unsafe { GetSaveFileNameW(&mut dialog) }.as_bool() {
        return match decode(&chosen) {
            Some(path) => PickedPath::Chosen(path),
            // A dialog that reports success and hands back nothing is not a cancel — the user did
            // choose. Falling back is the safe reading; refusing would lose their file.
            None => PickedPath::Unavailable,
        };
    }

    // A `false` return is BOTH "the user cancelled" and "the dialog could not run", and only the
    // extended error tells them apart: it is zero exactly when the user dismissed it.
    if unsafe { CommDlgExtendedError() } == COMMON_DLG_ERRORS(0) {
        PickedPath::Cancelled
    } else {
        PickedPath::Unavailable
    }
}

/// The dialog's type filter, in the double-NUL-terminated pair form the Win32 API expects.
///
/// `.txt` leads because that is what a recovery-phrase backup is; "all files" follows so a user who
/// wants a different extension — on a removable volume, say — is not prevented from choosing one.
fn filter() -> Vec<u16> {
    let mut filter = Vec::new();
    for part in ["Text file (*.txt)", "*.txt", "All files (*.*)", "*.*"] {
        filter.extend(part.encode_utf16());
        filter.push(0);
    }
    filter.push(0);
    filter
}

/// Read the answer back out of the dialog's buffer, up to its NUL terminator.
fn decode(buffer: &[u16]) -> Option<PathBuf> {
    let end = buffer.iter().position(|&unit| unit == 0)?;
    if end == 0 {
        return None;
    }
    Some(PathBuf::from(OsString::from_wide(&buffer[..end])))
}

fn wide(text: &str) -> Vec<u16> {
    text.encode_utf16().chain(std::iter::once(0)).collect()
}

fn wide_os(text: &std::ffi::OsStr) -> Vec<u16> {
    text.encode_wide().chain(std::iter::once(0)).collect()
}

#[cfg(test)]
mod tests {
    use super::{decode, filter};

    /// The filter is a run of NUL-separated pairs closed by a second NUL — the shape `OPENFILENAMEW`
    /// parses. Getting it wrong shows up as a dialog with no file types, not as an error.
    #[test]
    fn the_filter_is_a_double_nul_terminated_pair_list() {
        let filter = filter();

        assert_eq!(
            &filter[filter.len() - 2..],
            &[0, 0],
            "the list must be closed by an empty entry"
        );
        assert_eq!(
            filter.iter().filter(|&&unit| unit == 0).count(),
            5,
            "four entries, each NUL-terminated, plus the closing NUL"
        );
        let text: String = String::from_utf16(&filter).unwrap();
        assert!(text.starts_with("Text file (*.txt)\0*.txt\0"));
    }

    #[test]
    fn the_answer_is_read_up_to_its_terminator() {
        let mut buffer: Vec<u16> = "C:\\Users\\dig\\words.txt".encode_utf16().collect();
        buffer.resize(512, 0);

        assert_eq!(
            decode(&buffer).unwrap(),
            std::path::Path::new("C:\\Users\\dig\\words.txt")
        );
    }

    /// An empty or unterminated buffer yields no path, so the caller falls back instead of trying
    /// to write a secret to `""`.
    #[test]
    fn an_empty_answer_is_no_path() {
        assert!(decode(&[0u16; 16]).is_none());
        assert!(decode(&[]).is_none());
    }
}
