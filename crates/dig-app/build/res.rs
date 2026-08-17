//! Turn an `.ico` file into the Windows `.res` object the MSVC linker embeds as a binary's icon.
//!
//! # Why this is written out rather than delegated
//!
//! `winresource` shells out to `rc.exe`, which exists only inside a Visual Studio developer
//! environment, and drags a build-dependency tree into a consent-bearing app (see `build.rs` for the
//! same reasoning applied to the manifest). The `.res` container is a handful of fixed-width headers
//! around image bytes that are copied through untouched, so writing it costs less than depending on
//! a tool that may not be on PATH.
//!
//! # The format
//!
//! A `.res` file is a null resource entry followed by one entry per resource. Each entry is a header
//! — sizes, an ordinal type, an ordinal name, flags — then its data, with both the header and the
//! data padded out to a DWORD boundary. Windows resolves an icon in two hops: `RT_GROUP_ICON`
//! holds a directory of available sizes, each naming an `RT_ICON` that holds the image itself.
//!
//! Mounted by `build.rs`, and by `tests/icon_resource.rs` so the byte layout is actually checked.

/// Resource type for one icon image.
pub const RT_ICON: u16 = 3;
/// Resource type for the directory that lists the images and their sizes.
pub const RT_GROUP_ICON: u16 = 14;

/// The application icon's group id.
///
/// Explorer, the taskbar and the Start Menu all take a binary's *lowest-numbered* icon group as its
/// application icon, so this stays 1.
pub const ICON_GROUP_ID: u16 = 1;

/// `MOVEABLE | DISCARDABLE` — the memory flags the resource compiler gives an icon image.
const MEMORY_FLAGS_ICON: u16 = 0x1010;
/// `MOVEABLE | PURE | DISCARDABLE` — as above for the directory, which is never written to.
const MEMORY_FLAGS_GROUP: u16 = 0x1030;

/// US English. An icon carries no text, but a resource still needs a language to be found.
const LANGUAGE_EN_US: u16 = 0x0409;

/// Bytes of one `.ico` directory entry.
const ICO_ENTRY: usize = 16;
/// Bytes of one `RT_GROUP_ICON` directory entry: the `.ico` entry with its 4-byte file offset
/// replaced by the 2-byte id of the `RT_ICON` carrying the image.
const GROUP_ENTRY: usize = 14;

/// Encode `ico` as a `.res` file whose lowest icon group is the application icon.
///
/// Returns an error rather than a partial file when the input is not a well-formed icon: a `.res`
/// describing images that are not there links successfully and renders as nothing at all.
pub fn ico_to_res(ico: &[u8]) -> Result<Vec<u8>, String> {
    let images = read_ico_directory(ico)?;

    let mut res = Vec::new();
    // The null entry that opens every .res file.
    push_resource(&mut res, 0, 0, 0, &[]);

    let mut group = Vec::with_capacity(6 + GROUP_ENTRY * images.len());
    group.extend_from_slice(&0u16.to_le_bytes()); // reserved
    group.extend_from_slice(&1u16.to_le_bytes()); // 1 = icon, 2 = cursor
    group.extend_from_slice(&(images.len() as u16).to_le_bytes());

    for (index, image) in images.iter().enumerate() {
        let id = index as u16 + 1;
        // The first 12 bytes — width, height, colours, reserved, planes, bit count, byte count —
        // are copied verbatim. Width and height are single bytes in which a 256px image is stored
        // as 0, so copying rather than recomputing is what keeps that image addressable.
        group.extend_from_slice(&ico[image.entry..image.entry + 12]);
        group.extend_from_slice(&id.to_le_bytes());
        push_resource(&mut res, RT_ICON, id, MEMORY_FLAGS_ICON, image.bytes(ico));
    }

    push_resource(
        &mut res,
        RT_GROUP_ICON,
        ICON_GROUP_ID,
        MEMORY_FLAGS_GROUP,
        &group,
    );
    Ok(res)
}

/// Where one image sits inside the `.ico` file.
struct IcoImage {
    /// Offset of this image's 16-byte directory entry.
    entry: usize,
    offset: usize,
    size: usize,
}

impl IcoImage {
    fn bytes<'a>(&self, ico: &'a [u8]) -> &'a [u8] {
        &ico[self.offset..self.offset + self.size]
    }
}

/// Read the `.ico` header and directory, checking every image it claims is actually present.
fn read_ico_directory(ico: &[u8]) -> Result<Vec<IcoImage>, String> {
    if ico.len() < 6 {
        return Err("the icon file is too short to hold a directory header".into());
    }
    let reserved = u16::from_le_bytes([ico[0], ico[1]]);
    let kind = u16::from_le_bytes([ico[2], ico[3]]);
    if reserved != 0 || kind != 1 {
        return Err(format!(
            "this is not an icon file (reserved {reserved}, type {kind}; an icon is 0 and 1)"
        ));
    }
    let count = u16::from_le_bytes([ico[4], ico[5]]) as usize;
    if count == 0 {
        return Err("the icon file contains no images".into());
    }
    if ico.len() < 6 + ICO_ENTRY * count {
        return Err("the icon file's directory is truncated".into());
    }

    (0..count)
        .map(|index| {
            let entry = 6 + ICO_ENTRY * index;
            let read_u32 = |at: usize| {
                u32::from_le_bytes(ico[at..at + 4].try_into().expect("bounds checked above"))
                    as usize
            };
            let size = read_u32(entry + 8);
            let offset = read_u32(entry + 12);
            match offset.checked_add(size) {
                Some(end) if end <= ico.len() => Ok(IcoImage {
                    entry,
                    offset,
                    size,
                }),
                _ => Err(format!(
                    "image {index} claims {size} bytes at offset {offset}, past the end of the file"
                )),
            }
        })
        .collect()
}

/// Append one resource entry — header, then data, each padded to a DWORD boundary.
///
/// `HeaderSize` counts the padding after the name, so a misreported one leaves the linker reading
/// the rest of the file at the wrong offset.
fn push_resource(res: &mut Vec<u8>, kind: u16, name: u16, memory_flags: u16, data: &[u8]) {
    const FIXED_HEADER: usize = 4 + 4 + 4 + 4 + 4 + 2 + 2 + 4 + 4;
    let header_size = FIXED_HEADER.next_multiple_of(4);

    res.extend_from_slice(&(data.len() as u32).to_le_bytes());
    res.extend_from_slice(&(header_size as u32).to_le_bytes());
    // 0xFFFF marks an ordinal rather than a wide string name.
    res.extend_from_slice(&0xFFFFu16.to_le_bytes());
    res.extend_from_slice(&kind.to_le_bytes());
    res.extend_from_slice(&0xFFFFu16.to_le_bytes());
    res.extend_from_slice(&name.to_le_bytes());
    res.extend_from_slice(&0u32.to_le_bytes()); // data version
    res.extend_from_slice(&memory_flags.to_le_bytes());
    res.extend_from_slice(&LANGUAGE_EN_US.to_le_bytes());
    res.extend_from_slice(&0u32.to_le_bytes()); // version
    res.extend_from_slice(&0u32.to_le_bytes()); // characteristics
    res.resize(res.len() + header_size - FIXED_HEADER, 0);

    res.extend_from_slice(data);
    res.resize(res.len().next_multiple_of(4), 0);
}
