//! The `.ico` → Windows `.res` encoder the build script uses to give the binary an icon.
//!
//! The encoder lives in `build/res.rs` because it runs at build time, and is included here so it is
//! covered like ordinary code: a resource file the linker accepts but Windows renders wrongly fails
//! silently, and the only cheap way to see that is to parse the bytes back.

#![cfg(windows)]

#[path = "../build/res.rs"]
mod res;

use res::{ico_to_res, ICON_GROUP_ID, RT_GROUP_ICON, RT_ICON};

const ICO: &[u8] = include_bytes!("../icons/mark.ico");

/// One resource as it appears in a `.res` file, decoded far enough to check it.
struct Resource {
    kind: u16,
    name: u16,
    data: Vec<u8>,
    /// Where this resource's header began, so alignment can be asserted.
    offset: usize,
}

/// Parse a `.res` file back into its resources, skipping the leading null entry.
///
/// Deliberately strict: the point of the round trip is to fail on the padding and header-size
/// mistakes that a linker tolerates and a shell renders as a blank icon.
fn parse_res(bytes: &[u8]) -> Vec<Resource> {
    let mut out = Vec::new();
    let mut at = 0usize;
    while at + 32 <= bytes.len() {
        let start = at;
        let read_u32 = |o: usize| u32::from_le_bytes(bytes[o..o + 4].try_into().unwrap()) as usize;
        let read_u16 = |o: usize| u16::from_le_bytes(bytes[o..o + 2].try_into().unwrap());

        let data_size = read_u32(at);
        let header_size = read_u32(at + 4);
        assert_eq!(header_size % 4, 0, "header size must stay DWORD-aligned");

        let kind = {
            assert_eq!(read_u16(at + 8), 0xFFFF, "types are written as ordinals");
            read_u16(at + 10)
        };
        let name = {
            assert_eq!(read_u16(at + 12), 0xFFFF, "names are written as ordinals");
            read_u16(at + 14)
        };

        let data_at = at + header_size;
        let data = bytes[data_at..data_at + data_size].to_vec();
        at = data_at + data_size.next_multiple_of(4);

        // The null entry (type 0, name 0, no data) is the file's header, not a resource.
        if !(kind == 0 && name == 0 && data_size == 0) {
            out.push(Resource {
                kind,
                name,
                data,
                offset: start,
            });
        }
    }
    assert_eq!(at, bytes.len(), "the file must end on a resource boundary");
    out
}

/// The `.ico` directory entries, as (width byte, height byte, bytes, offset).
fn ico_entries(ico: &[u8]) -> Vec<(u8, u8, usize, usize)> {
    let count = u16::from_le_bytes(ico[4..6].try_into().unwrap()) as usize;
    (0..count)
        .map(|i| {
            let e = 6 + 16 * i;
            let size = u32::from_le_bytes(ico[e + 8..e + 12].try_into().unwrap()) as usize;
            let offset = u32::from_le_bytes(ico[e + 12..e + 16].try_into().unwrap()) as usize;
            (ico[e], ico[e + 1], size, offset)
        })
        .collect()
}

#[test]
fn every_image_in_the_ico_becomes_its_own_icon_resource() {
    let res = ico_to_res(ICO).expect("the brand mark is a well-formed .ico");
    let parsed = parse_res(&res);
    let entries = ico_entries(ICO);

    let icons: Vec<&Resource> = parsed.iter().filter(|r| r.kind == RT_ICON).collect();
    assert_eq!(
        icons.len(),
        entries.len(),
        "dropping an image silently costs the size the shell wanted to sample"
    );

    for (index, (icon, entry)) in icons.iter().zip(&entries).enumerate() {
        assert_eq!(
            icon.name,
            index as u16 + 1,
            "icon ids are 1-based and in directory order"
        );
        assert_eq!(
            icon.data,
            &ICO[entry.3..entry.3 + entry.2],
            "the image bytes are carried through unmodified"
        );
    }
}

#[test]
fn the_group_directory_points_at_the_icons_it_ships() {
    let res = ico_to_res(ICO).unwrap();
    let parsed = parse_res(&res);
    let entries = ico_entries(ICO);

    let group = parsed
        .iter()
        .find(|r| r.kind == RT_GROUP_ICON)
        .expect("without a group directory the shell has no icon to resolve");
    assert_eq!(
        group.name, ICON_GROUP_ID,
        "the group is the binary's lowest-numbered icon, which is the one Explorer picks"
    );

    assert_eq!(u16::from_le_bytes(group.data[0..2].try_into().unwrap()), 0);
    assert_eq!(
        u16::from_le_bytes(group.data[2..4].try_into().unwrap()),
        1,
        "type 1 is an icon, not a cursor"
    );
    let count = u16::from_le_bytes(group.data[4..6].try_into().unwrap()) as usize;
    assert_eq!(count, entries.len());
    assert_eq!(group.data.len(), 6 + 14 * count, "no trailing slack");

    for (index, entry) in entries.iter().enumerate() {
        let e = 6 + 14 * index;
        assert_eq!(group.data[e], entry.0, "width byte survives the copy");
        assert_eq!(group.data[e + 1], entry.1, "height byte survives the copy");
        assert_eq!(
            u32::from_le_bytes(group.data[e + 8..e + 12].try_into().unwrap()) as usize,
            entry.2,
            "a wrong byte count truncates the image the shell decodes"
        );
        assert_eq!(
            u16::from_le_bytes(group.data[e + 12..e + 14].try_into().unwrap()),
            index as u16 + 1,
            "each directory slot names its own RT_ICON, not the first one"
        );
    }
}

/// The 256px image is the one modern toasts and the Start Menu actually sample, and it is also the
/// one an encoder gets wrong: 256 does not fit the `.ico` format's single width byte, which stores
/// it as 0. An encoder that clamps or truncates instead of copying the byte produces a group entry
/// claiming a 255px or 0-byte image, and the shell then falls back to a smaller one.
#[test]
fn the_256px_image_keeps_its_zero_width_encoding() {
    let entries = ico_entries(ICO);
    let big = entries
        .iter()
        .position(|e| e.0 == 0 && e.1 == 0)
        .expect("the brand .ico must carry a 256px image for the Start Menu to sample");
    assert!(
        entries[big].2 > 20_000,
        "a 256px image this small would be an upscale of a tiny source"
    );

    let res = ico_to_res(ICO).unwrap();
    let group = parse_res(&res)
        .into_iter()
        .find(|r| r.kind == RT_GROUP_ICON)
        .unwrap();
    let e = 6 + 14 * big;
    assert_eq!(group.data[e], 0);
    assert_eq!(group.data[e + 1], 0);
}

/// A resource whose data does not end on a DWORD boundary leaves the next header misaligned, and
/// the brand mark's 16px image has an odd length, so this is reachable with the real asset.
#[test]
fn resources_stay_dword_aligned() {
    assert!(
        ico_entries(ICO).iter().any(|e| e.2 % 4 != 0),
        "the fixture must contain an unaligned image or this test cannot fail"
    );

    let res = ico_to_res(ICO).unwrap();
    assert_eq!(res.len() % 4, 0);
    for resource in parse_res(&res) {
        assert_eq!(
            resource.offset % 4,
            0,
            "a misaligned header makes the linker read the rest of the file as garbage"
        );
    }
}

#[test]
fn a_file_that_is_not_an_icon_is_refused() {
    assert!(ico_to_res(b"not an icon at all").is_err());
    assert!(
        ico_to_res(&ICO[..20]).is_err(),
        "a truncated directory must not be encoded as if the images were there"
    );
}
