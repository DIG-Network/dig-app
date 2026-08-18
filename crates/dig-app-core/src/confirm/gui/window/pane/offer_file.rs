//! Turning a file somebody dragged onto the Offers card into the text the paste path already reads
//! (dig_ecosystem#3120).
//!
//! # Why this module produces TEXT and never a verdict about the offer
//!
//! A drop must load exactly what a paste would load, and be judged by exactly the same parser. So
//! everything here answers one question — *can this file's contents be handed to the field at all?*
//! — and hands the bytes on verbatim when they can. Nothing here inspects whether the text IS an
//! offer. That judgement stays with [`crate::wallet::offer::ReviewedOffer::read`], which is what the
//! paste path uses, and a second opinion living here is how a drop path becomes more permissive than
//! the paste path it is meant to mirror.
//!
//! The refusals it does make are all NARROWER than paste, never wider: a folder, an unreadable file,
//! a file that is not text, an empty one, and one far too large to be an offer. Each is answered in
//! words naming the file and what was wrong with it, because a drop that does nothing is
//! indistinguishable from a drop the app never noticed.
//!
//! # Why a size is refused before the file is opened
//!
//! [`MOST_BYTES`] is a thousand times the size of a large offer and is checked against the file's
//! own length. Reading an arbitrary dragged file into memory unbounded is how a dropped disk image
//! becomes a frozen window, and a person cannot tell that apart from a crash.

use super::copy;

/// The largest file this will read, in bytes.
///
/// One mebibyte. A Chia offer with many NFT legs is a few tens of kilobytes, so this leaves three
/// orders of magnitude of headroom while still refusing anything that is plainly not an offer.
pub(crate) const MOST_BYTES: u64 = 1 << 20;

/// The text a drop should load into the offer field, or the sentence saying why it cannot.
pub(crate) fn from_drop(files: &[egui::DroppedFile]) -> Result<String, String> {
    match files {
        [] => Err(copy::offer::DROP_UNNAMED.to_string()),
        [one] => from_one(one),
        several => Err(copy::offer::drop_several(several.len())),
    }
}

/// One dropped file's contents, or why they could not be had.
///
/// Bytes carried on the drop itself are preferred over the path when both are present: they are what
/// the person actually let go of, and on the platforms that supply them the path may not exist.
fn from_one(file: &egui::DroppedFile) -> Result<String, String> {
    let name = name_of(file);
    if let Some(bytes) = &file.bytes {
        return text_of(&name, bytes);
    }
    let Some(path) = &file.path else {
        return Err(copy::offer::DROP_UNNAMED.to_string());
    };
    if path.is_dir() {
        return Err(copy::offer::drop_folder(&name));
    }
    match std::fs::metadata(path) {
        Ok(about) if about.len() > MOST_BYTES => {
            return Err(copy::offer::drop_too_big(&name, kib(about.len())))
        }
        Ok(_) => {}
        Err(why) => return Err(copy::offer::drop_unreadable(&name, &why.to_string())),
    }
    match std::fs::read(path) {
        Ok(bytes) => text_of(&name, &bytes),
        Err(why) => Err(copy::offer::drop_unreadable(&name, &why.to_string())),
    }
}

/// The bytes as the text to load, or why they are not text this card can use.
///
/// The text is passed on UNTRIMMED. `ReviewedOffer::read` trims its input, so a file's trailing
/// newline is already accounted for there; trimming again here would be a second, divergent copy of
/// a rule that belongs to the parser.
fn text_of(name: &str, bytes: &[u8]) -> Result<String, String> {
    if bytes.len() as u64 > MOST_BYTES {
        return Err(copy::offer::drop_too_big(name, kib(bytes.len() as u64)));
    }
    match std::str::from_utf8(bytes) {
        Err(_) => Err(copy::offer::drop_binary(name)),
        Ok(text) if text.trim().is_empty() => Err(copy::offer::drop_empty(name)),
        Ok(text) => Ok(text.to_string()),
    }
}

/// What to call the file in a sentence: its own name, or a plain noun when it has none.
fn name_of(file: &egui::DroppedFile) -> String {
    file.name
        .rsplit(['/', '\\'])
        .next()
        .filter(|part| !part.is_empty())
        .map(str::to_string)
        .or_else(|| {
            file.path
                .as_deref()
                .and_then(std::path::Path::file_name)
                .map(|name| name.to_string_lossy().into_owned())
        })
        .unwrap_or_else(|| "That file".to_string())
}

/// A byte count in whole kilobytes, for a sentence about how oversized something is.
fn kib(bytes: u64) -> usize {
    usize::try_from(bytes / 1024).unwrap_or(usize::MAX)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    /// A dropped file naming `path`, as the backend delivers one.
    fn dropped(path: &std::path::Path) -> egui::DroppedFile {
        egui::DroppedFile {
            path: Some(path.to_path_buf()),
            name: path
                .file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_default(),
            ..Default::default()
        }
    }

    /// A file of `bytes` under a fresh directory, and the directory itself so it outlives the test.
    fn a_file_of(name: &str, bytes: &[u8]) -> (tempfile::TempDir, std::path::PathBuf) {
        let dir = tempfile::tempdir().expect("a temporary directory");
        let path = dir.path().join(name);
        let mut file = std::fs::File::create(&path).expect("the fixture file is created");
        file.write_all(bytes).expect("the fixture file is written");
        (dir, path)
    }

    /// **A dropped text file loads its contents byte for byte, with no interpretation on the way.**
    ///
    /// The fixture is NOT an offer, deliberately. That is what makes this test see the property: a
    /// drop path that recognised offers itself would have to refuse this file, and the whole point is
    /// that recognising an offer is the parser's job downstream. A fixture holding a real offer could
    /// not tell a verbatim loader from a validating one.
    ///
    /// The trailing newline is asserted for the same reason — a `trim` here would be a second copy of
    /// a rule `ReviewedOffer::read` already owns, and the two copies would eventually disagree.
    #[test]
    fn a_text_file_loads_verbatim_without_being_judged_as_an_offer() {
        let (_dir, path) = a_file_of("swap.offer", b"not an offer at all\n");

        assert_eq!(
            from_drop(&[dropped(&path)]),
            Ok("not an offer at all\n".to_string())
        );
    }

    /// **Every file-level refusal names the file and says a DIFFERENT thing about it.**
    ///
    /// Each case varies exactly one property of an otherwise loadable drop, and the sentences are
    /// asserted pairwise distinct: an implementation that answered every bad drop with one generic
    /// failure would satisfy "it refused" on any single case and fails here. The honest control is
    /// the loadable file above, which must still succeed.
    #[test]
    fn each_refusal_names_the_file_and_answers_a_different_fault() {
        let (dir, text) = a_file_of("swap.offer", b"offer1abc");
        let folder = dir.path().join("holder");
        std::fs::create_dir(&folder).expect("the fixture folder is created");
        let (_binary_dir, binary) = a_file_of("swap.png", &[0x89, b'P', b'N', b'G', 0xff, 0xfe]);
        let (_empty_dir, empty) = a_file_of("blank.txt", b"   \n\t ");
        let missing = dir.path().join("gone.offer");

        let of_folder = from_drop(&[dropped(&folder)]).expect_err("a folder is not an offer file");
        let of_binary = from_drop(&[dropped(&binary)]).expect_err("a binary file holds no offer");
        let of_empty = from_drop(&[dropped(&empty)]).expect_err("an empty file holds no offer");
        let of_missing =
            from_drop(&[dropped(&missing)]).expect_err("a file that is not there cannot be read");
        let of_several = from_drop(&[dropped(&text), dropped(&text)])
            .expect_err("two files at once is not one offer");

        for (what, said) in [
            ("folder", &of_folder),
            ("binary", &of_binary),
            ("empty", &of_empty),
            ("missing", &of_missing),
        ] {
            let named = match what {
                "folder" => "holder",
                "binary" => "swap.png",
                "empty" => "blank.txt",
                _ => "gone.offer",
            };
            assert!(
                said.contains(named),
                "the {what} refusal does not name the file: {said}"
            );
        }
        assert!(
            of_several.contains('2'),
            "the several-files refusal does not say how many: {of_several}"
        );

        let all = [&of_folder, &of_binary, &of_empty, &of_missing, &of_several];
        for (ix, one) in all.iter().enumerate() {
            for other in all.iter().skip(ix + 1) {
                assert_ne!(one, other, "two different faults gave the same answer");
            }
        }

        assert!(
            from_drop(&[dropped(&text)]).is_ok(),
            "the control file stopped loading"
        );
    }

    /// **A file one byte over the cap is refused and a file exactly at the cap is loaded.**
    ///
    /// The bound is pinned from BOTH sides. A cap tested only from above confirms itself: an
    /// implementation that refused everything would pass it, and so would one whose real limit sits
    /// anywhere below the published one. The at-bound case is what fixes the number.
    #[test]
    fn the_size_cap_refuses_one_byte_over_and_accepts_exactly_the_cap() {
        let at_cap = vec![b'a'; usize::try_from(MOST_BYTES).expect("the cap fits in memory")];
        let mut over_cap = at_cap.clone();
        over_cap.push(b'a');
        let (_at_dir, at) = a_file_of("at.offer", &at_cap);
        let (_over_dir, over) = a_file_of("over.offer", &over_cap);

        assert!(
            from_drop(&[dropped(&at)]).is_ok(),
            "a file exactly at the cap was refused"
        );
        let refused = from_drop(&[dropped(&over)]).expect_err("a file over the cap is refused");
        assert!(
            refused.contains("over.offer"),
            "the oversize refusal does not name the file: {refused}"
        );
    }

    /// **Bytes carried on the drop are read the same way a file's are, and are preferred over the
    /// path.**
    ///
    /// The two sources must not diverge, so the same three answers are asserted through the bytes
    /// route. Preference is proved with a drop whose path points at DIFFERENT contents — a reader
    /// that quietly favoured the path would return the path's text and fails here, which a drop
    /// carrying only bytes could never show.
    #[test]
    fn bytes_on_the_drop_are_read_like_a_file_and_win_over_the_path() {
        let (_dir, path) = a_file_of("swap.offer", b"from the path");
        let mut carried = dropped(&path);
        carried.bytes = Some(std::sync::Arc::from(&b"from the bytes"[..]));

        assert_eq!(from_drop(&[carried]), Ok("from the bytes".to_string()));

        let mut binary = dropped(&path);
        binary.bytes = Some(std::sync::Arc::from(&[0xff_u8, 0xfe][..]));
        assert!(
            from_drop(&[binary])
                .expect_err("carried bytes that are not text are refused")
                .contains("swap.offer"),
            "the carried-bytes refusal does not name the file"
        );
    }
}
