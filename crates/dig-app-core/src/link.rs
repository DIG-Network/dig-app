//! Mapping a DIG link to the local node's serve URL, for the tray's "Open…" action.
//!
//! # This MIRRORS a contract owned by dig-node — it does not define one
//!
//! The authority is `dig-node`'s `crates/dig-node-service/src/open.rs`, which is the OS
//! scheme-handler target the installer registers for `chia://` and `urn:dig:chia:`. It documents the
//! serve URL as:
//!
//! - `http://dig.local/s/<storeId>[:<root>]/<path>`
//! - `http://localhost:9778/s/<storeId>[:<root>]/<path>`
//!
//! and the node's own request parser (`dig-node-service/src/content.rs::parse_store_path`) accepts
//! `/s/<storeId>[:<root>]/<resource>` with the store id and root each **64 hex characters**.
//!
//! Duplicating a cross-repo contract is a future drift bug, so two things bound the duplication:
//! [`serve_url`] is the ONLY place in dig-app that builds this URL, and its tests pin the exact
//! shapes quoted above rather than merely round-tripping through this module — a round-trip through
//! one implementation's own code cannot see a divergence from the other. Converging on a shared
//! crate or a node control method is tracked separately; until then, a change to the node's route is
//! expected to break the tests here, which is the point.
//!
//! # What this module is NOT
//!
//! It does not decide whether a link is allowed — that is
//! [`validate_open_link`](crate::gateway::validate_open_link), the security boundary, and it runs
//! FIRST. Store content is attacker-controlled (#745), so nothing here opens a file by a
//! content-chosen name, invokes a shell, or follows a redirect; it produces an `http://` URL under
//! the node's own origin and nothing else.

/// A DIG link split into the parts the `/s/` route needs.
#[derive(Debug, PartialEq, Eq)]
struct DigLink {
    /// 64-hex store id.
    store_id: String,
    /// Optional 64-hex generation root.
    root: Option<String>,
    /// The resource path within the store, without a leading slash. Empty means the store root.
    path: String,
}

impl DigLink {
    /// The `<storeId>[:<root>]` reference the `/s/<ref>/…` route expects.
    fn store_ref(&self) -> String {
        match &self.root {
            Some(root) => format!("{}:{}", self.store_id, root),
            None => self.store_id.clone(),
        }
    }
}

/// 64 lowercase-or-uppercase hex characters, the shape the node's own parser requires.
///
/// `pub(crate)` because the Cache pane validates a typed store id against the SAME rule before
/// offering to mirror it. A second copy of "64 hex" would be a second answer the moment either
/// moved.
pub(crate) fn is_64_hex(s: &str) -> bool {
    s.len() == 64 && s.chars().all(|c| c.is_ascii_hexdigit())
}

/// Split `<storeId>[:<root>][/<path>]` — the part after either scheme prefix.
///
/// Rejects anything whose store id (or root, when present) is not 64 hex, so a typo fails here with
/// a message naming the problem rather than as an opaque 404 from the node.
fn parse_after_scheme(rest: &str) -> Result<DigLink, String> {
    let (store_part, path) = match rest.split_once('/') {
        Some((store_part, path)) => (store_part, path.to_string()),
        None => (rest, String::new()),
    };

    let (store_id, root) = match store_part.split_once(':') {
        Some((id, root)) => (id, Some(root.to_string())),
        None => (store_part, None),
    };

    if !is_64_hex(store_id) {
        return Err(format!(
            "the store id must be 64 hex characters, but this link has {} character(s): {store_id}",
            store_id.len()
        ));
    }
    if let Some(root) = root.as_deref() {
        if !is_64_hex(root) {
            return Err(format!(
                "the generation root must be 64 hex characters, but this link has {} character(s): {root}",
                root.len()
            ));
        }
    }

    Ok(DigLink {
        store_id: store_id.to_string(),
        root,
        path,
    })
}

/// Parse a `chia://` or `urn:dig:chia:` link.
///
/// The caller MUST have run [`validate_open_link`](crate::gateway::validate_open_link) first; this
/// re-checks the prefixes anyway, because a parser that trusts its caller becomes wrong the moment a
/// second caller appears.
fn parse(link: &str) -> Result<DigLink, String> {
    if let Some(rest) = link.strip_prefix("chia://") {
        return parse_after_scheme(rest);
    }
    if let Some(rest) = link.strip_prefix("urn:dig:chia:") {
        return parse_after_scheme(rest);
    }
    Err(format!(
        "not a DIG link — expected chia:// or urn:dig:chia:, got: {link}"
    ))
}

/// Build the node serve URL for `link` against the node at `endpoint`.
///
/// `endpoint` is the base the engine actually connected on (the §5.3 ladder's answer — `dig.local`,
/// `localhost:9778`, or an explicitly configured node), so this never hardcodes a tier and never
/// falls back to the public gateway on its own.
pub fn serve_url(endpoint: &str, link: &str) -> Result<String, String> {
    let parsed = parse(link)?;
    let base = endpoint.trim_end_matches('/');
    let store_ref = parsed.store_ref();
    if parsed.path.is_empty() {
        Ok(format!("{base}/s/{store_ref}/"))
    } else {
        Ok(format!("{base}/s/{store_ref}/{}", parsed.path))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const STORE: &str = "21092da4f2ea44459d237e9f533a3a9285acbce292dcd5e3de0e7e46abe5b668";
    const ROOT: &str = "ef69982150e71c7727d7c6279f22ecac023bf230cfa26d548f0b357dcc759b0d";

    /// The two URL shapes dig-node's `open.rs` documents, pinned as LITERALS.
    ///
    /// Literal expectations rather than values computed from this module's own parts: if the node's
    /// route changes, this test must fail. A round-trip through `serve_url` alone would keep passing
    /// while dig-app and dig-node had diverged, which is the whole failure mode being guarded.
    #[test]
    fn the_serve_url_matches_the_shape_dig_node_documents() {
        assert_eq!(
            serve_url(
                "http://dig.local",
                &format!("urn:dig:chia:{STORE}:{ROOT}/README.txt")
            )
            .unwrap(),
            format!("http://dig.local/s/{STORE}:{ROOT}/README.txt")
        );
        assert_eq!(
            serve_url(
                "http://localhost:9778",
                &format!("chia://{STORE}/index.html")
            )
            .unwrap(),
            format!("http://localhost:9778/s/{STORE}/index.html")
        );
    }

    /// A link with no resource opens the store root, and the trailing slash is not optional: the node
    /// injects `<base href="/s/<store>[:<root>]/">` so a store's RELATIVE links resolve, and a
    /// missing trailing slash makes the browser resolve them one level too high.
    #[test]
    fn a_link_with_no_path_opens_the_store_root_with_a_trailing_slash() {
        assert_eq!(
            serve_url("http://dig.local", &format!("urn:dig:chia:{STORE}")).unwrap(),
            format!("http://dig.local/s/{STORE}/")
        );
        assert_eq!(
            serve_url("http://dig.local", &format!("chia://{STORE}:{ROOT}")).unwrap(),
            format!("http://dig.local/s/{STORE}:{ROOT}/")
        );
    }

    /// Both schemes must reach the SAME URL for the same content, or the tray and the OS
    /// scheme-handler would disagree about where a link points.
    #[test]
    fn both_schemes_resolve_to_the_same_url() {
        let from_urn =
            serve_url("http://dig.local", &format!("urn:dig:chia:{STORE}/a/b.txt")).unwrap();
        let from_chia = serve_url("http://dig.local", &format!("chia://{STORE}/a/b.txt")).unwrap();
        assert_eq!(from_urn, from_chia);
    }

    /// A trailing slash on the configured endpoint must not produce `//s/`.
    #[test]
    fn a_trailing_slash_on_the_endpoint_is_not_doubled() {
        assert_eq!(
            serve_url("http://dig.local/", &format!("chia://{STORE}/x")).unwrap(),
            format!("http://dig.local/s/{STORE}/x")
        );
    }

    /// A store id that is not 64 hex is refused HERE, with a message naming the actual length, rather
    /// than being sent to the node to come back as an opaque failure.
    #[test]
    fn a_store_id_that_is_not_64_hex_is_refused_with_its_length() {
        let err = serve_url("http://dig.local", "chia://not-hex/index.html").unwrap_err();
        assert!(err.contains("64 hex"), "got: {err}");
        assert!(
            err.contains('7'),
            "the message should name the length: {err}"
        );

        let short = "a".repeat(63);
        assert!(serve_url("http://dig.local", &format!("chia://{short}/x")).is_err());
        let long = "a".repeat(65);
        assert!(serve_url("http://dig.local", &format!("chia://{long}/x")).is_err());
    }

    /// A malformed ROOT is refused too — it is half the identity of a capsule, so accepting it and
    /// letting the node 404 would report "not found" for what is really a typo.
    #[test]
    fn a_root_that_is_not_64_hex_is_refused() {
        let err = serve_url("http://dig.local", &format!("chia://{STORE}:deadbeef/x")).unwrap_err();
        assert!(err.contains("generation root"), "got: {err}");
    }

    /// Anything outside the two schemes is refused by the parser as well as by the gateway
    /// validator, so this module is not safe only by virtue of its caller.
    #[test]
    fn a_foreign_scheme_is_refused_even_though_the_gateway_also_refuses_it() {
        for link in [
            "file:///etc/passwd",
            "http://evil.example/x",
            "javascript:alert(1)",
            "urn:dig:other:abc",
            STORE, // bare, no scheme
        ] {
            assert!(
                serve_url("http://dig.local", link).is_err(),
                "must refuse: {link}"
            );
        }
    }
}
