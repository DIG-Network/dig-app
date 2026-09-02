//! The one cursor walk every paged control read uses (dig-app#323).
//!
//! # Why paging is centralised rather than written per read
//!
//! Every paged `control.*` read has the same three ways to go wrong, and they are all silent:
//! stopping on a short page and calling it complete, resuming a node that never paged and reading
//! page one forever, and following a cursor a node keeps repeating. Each read that hand-rolls the
//! loop gets its own chance to miss one, and the failure is a **short answer that reads as a
//! complete one** — the worst shape available on a surface about somebody's money, because nothing
//! about it looks wrong.
//!
//! Two implementations of it already existed: [`crate::wallet::coin_list`]'s, which had the
//! scrutiny, and a hand-rolled copy inside `coin_records_by_parent` serving the mint's lineage read,
//! which kept only the **immediately previous** cursor and so burned its whole page budget against a
//! node answering `A → B → A → B` where a set stops at the first repeat. Both refused rather than
//! returning a prefix, so they agreed in failure DIRECTION and the copy was weaker rather than
//! wrong. This module removes the second copy before a third read produces a third.
//!
//! # What this module does NOT decide
//!
//! It never decides what a stop MEANS to a caller. [`walk`] reports how the walk ended and hands
//! back what it collected; whether [`Stop::PageBudget`] is a value to render with a warning or an
//! error to refuse is the caller's judgement, because the two callers here genuinely differ — a
//! coin list can honestly show a truncated list labelled as truncated, while a lineage walk cannot
//! hand a partial child set to a spend.
//!
//! # A contract without an unpaged case cannot construct one
//!
//! [`PageEnd::Unpaged`] exists because `control.wallet.coins` has a three-state `complete`, where a
//! missing key means a pre-0.25 node that never paged. `control.wallet.coinsByParent` has a plain
//! `bool` and no such case. Rather than a second helper, the difference is expressed by which
//! constructor a caller uses: [`PageEnd::of_optional_complete`] can produce
//! [`Unpaged`](PageEnd::Unpaged) and [`PageEnd::of_complete`] cannot.

use std::collections::BTreeSet;

/// How ONE page ended — the whole of what a `complete` flag and a `cursor` say.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PageEnd {
    /// `complete: true`. Everything the node knows of was in this page.
    Complete,
    /// `complete: false` with a cursor. More rows exist; resume strictly after this id.
    More {
        /// The cursor to send for the next page.
        cursor: String,
    },
    /// `complete` absent. A node that served this read unpaged, so its answer is already the whole
    /// set — and one that will ignore the cursor parameter, so it must never be resumed.
    Unpaged,
    /// `complete: false` with no cursor. The node says the list is partial and gave no way to
    /// finish it. Distinct from [`Complete`](Self::Complete) because it is the opposite claim.
    TruncatedWithoutCursor,
}

impl PageEnd {
    /// Read a contract whose `complete` has THREE states, the third being "this node does not page".
    ///
    /// The `None` arm is FIRST so no cursor value can route around it.
    pub fn of_optional_complete(complete: Option<bool>, cursor: Option<&str>) -> Self {
        match (complete, cursor) {
            (None, _) => Self::Unpaged,
            (Some(true), _) => Self::Complete,
            (Some(false), Some(cursor)) => Self::More {
                cursor: cursor.to_owned(),
            },
            (Some(false), None) => Self::TruncatedWithoutCursor,
        }
    }

    /// Read a contract whose `complete` is a plain `bool`, so "does not page" is not expressible.
    ///
    /// **This constructor cannot return [`Unpaged`](Self::Unpaged)**, which is how a caller whose
    /// contract has no unpaged case says so — by construction rather than by a comment or by an
    /// arm it hopes never fires.
    pub fn of_complete(complete: bool, cursor: Option<&str>) -> Self {
        Self::of_optional_complete(Some(complete), cursor)
    }

    /// The id to resume from, or `None` when this page must not be resumed.
    ///
    /// Every non-[`More`](Self::More) end returns `None`, including [`Unpaged`](Self::Unpaged) —
    /// which is exactly the guard that keeps an older node's answer from being walked forever.
    pub fn cursor(&self) -> Option<&str> {
        match self {
            Self::More { cursor } => Some(cursor),
            _ => None,
        }
    }
}

/// One page of rows and how it ended.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Page<T> {
    /// The rows in this page, in the order the node delivered them.
    pub items: Vec<T>,
    /// What the node said about what lies beyond it.
    pub end: PageEnd,
}

/// Why a walk stopped. Each is a different fault and none of them is "there were no more".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Stop {
    /// The node said it was done. Everything it knows of was collected.
    Complete,
    /// The node does not page. Its one answer is the whole set it knows of.
    Unpaged,
    /// The node reported more rows and handed back no cursor to resume from.
    NoCursor,
    /// The node handed back a cursor it had ALREADY handed back, which would loop forever.
    RepeatedCursor,
    /// The page budget was spent and the node still had not said it was done.
    PageBudget,
}

impl Stop {
    /// Whether everything the node knows of was collected.
    ///
    /// The two `true` arms are the two ways a walk finishes honestly. Every other arm means the
    /// collected rows are a PREFIX, and a caller that cannot use a prefix keys off this.
    pub fn is_whole(&self) -> bool {
        matches!(self, Self::Complete | Self::Unpaged)
    }
}

/// Everything a walk collected, and how it ended.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Walk<T> {
    /// Every row seen, in the order the pages delivered them.
    pub items: Vec<T>,
    /// Why the walk stopped.
    pub stop: Stop,
}

/// Walk every page by following the cursor the node hands back.
///
/// `fetch` is given the cursor for the page it should read — `None` for the first — and returns that
/// page. It is a closure rather than a trait so the paging RULE can be tested against a scripted
/// node with no transport, which is where all three failure modes live.
///
/// # What stops the walk, and why each stop is its own answer
///
/// A [`PageEnd::Unpaged`] stops it after ONE page. That is load-bearing: a node that does not page
/// ignores the cursor, so resuming would re-serve page one until the budget ran out and then report
/// a duplicate-filled list as truncated.
///
/// A REPEATED cursor stops it, tracked against every cursor already seen rather than only the
/// previous one. The contract says the cursor advances, but a caller walking a stranger's answer
/// cannot assume it: a node alternating `A → B → A → B` never repeats consecutively, so a
/// previous-only check does not fire and the walk spends its entire budget before refusing. Both
/// checks refuse in the end, so this is a strength difference rather than a correctness one — but
/// the weaker one lets an untrusted node choose how much work it costs.
///
/// `budget` bounds the walk for liveness, never by policy: the walk follows a cursor the NODE chose,
/// so its length is not this app's to bound by trust.
pub fn walk<T, E>(
    budget: usize,
    mut fetch: impl FnMut(Option<&str>) -> Result<Page<T>, E>,
) -> Result<Walk<T>, E> {
    let mut items = Vec::new();
    let mut seen_cursors: BTreeSet<String> = BTreeSet::new();
    let mut cursor: Option<String> = None;

    for _ in 0..budget {
        let page = fetch(cursor.as_deref())?;
        items.extend(page.items);
        let next = match page.end {
            PageEnd::Complete => {
                return Ok(Walk {
                    items,
                    stop: Stop::Complete,
                })
            }
            PageEnd::Unpaged => {
                return Ok(Walk {
                    items,
                    stop: Stop::Unpaged,
                })
            }
            PageEnd::TruncatedWithoutCursor => {
                return Ok(Walk {
                    items,
                    stop: Stop::NoCursor,
                })
            }
            PageEnd::More { cursor } => cursor,
        };
        if !seen_cursors.insert(next.clone()) {
            return Ok(Walk {
                items,
                stop: Stop::RepeatedCursor,
            });
        }
        cursor = Some(next);
    }

    Ok(Walk {
        items,
        stop: Stop::PageBudget,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A node that alternates between two cursors, never repeating one CONSECUTIVELY.
    ///
    /// This is the fixture that distinguishes a seen-set from a previous-only check, and it is the
    /// whole reason the by-parent copy was weaker. A node answering `A → B → A → B` defeats a
    /// previous-only comparison on every step; only a set notices on the third page.
    ///
    /// The control that makes it meaningful is the page COUNT: both implementations eventually
    /// refuse, so an assertion on the stop alone passes against the weaker one too.
    #[test]
    fn an_alternating_cursor_stops_on_the_third_page_not_at_the_budget() {
        let cursors = ["a", "b", "a", "b"];
        let mut reads = 0usize;
        let walked: Walk<u8> = walk(64, |_| {
            let end = PageEnd::More {
                cursor: cursors[reads % cursors.len()].to_string(),
            };
            reads += 1;
            Ok::<_, ()>(Page {
                items: vec![reads as u8],
                end,
            })
        })
        .expect("the scripted node never errors");

        assert_eq!(walked.stop, Stop::RepeatedCursor);
        assert_eq!(
            reads, 3,
            "a previous-only cursor check never fires on an alternating node and would spend the \
             whole 64-page budget here; the seen-set must stop on the page that repeats `a`"
        );
        assert!(!walked.stop.is_whole());
    }

    /// A node that never says it is done is stopped by the budget, and the walk says so.
    ///
    /// The budget is set to 3 rather than [`crate::wallet::coin_list::MAX_PAGES`] so the assertion
    /// is on the walk honouring the budget it was GIVEN, not on a constant that could change.
    #[test]
    fn an_endless_node_stops_at_the_budget_and_reports_a_prefix() {
        let mut reads = 0usize;
        let walked: Walk<u8> = walk(3, |_| {
            reads += 1;
            Ok::<_, ()>(Page {
                items: vec![reads as u8],
                end: PageEnd::More {
                    cursor: format!("cursor-{reads}"),
                },
            })
        })
        .expect("the scripted node never errors");

        assert_eq!(walked.stop, Stop::PageBudget);
        assert_eq!(
            reads, 3,
            "the budget bounds the reads, not merely the result"
        );
        assert_eq!(walked.items, vec![1, 2, 3]);
        assert!(
            !walked.stop.is_whole(),
            "a budget stop is a PREFIX; reporting it as whole is the fail-open this bound exists \
             to make impossible"
        );
    }

    /// An unpaged node is read ONCE, even though its cursor field is populated.
    ///
    /// The fixture deliberately carries a cursor value, because the nearest wrong implementation
    /// resumes whenever a cursor is present. A fixture with no cursor could not tell the two apart.
    #[test]
    fn an_unpaged_node_is_read_once_even_when_it_hands_back_a_cursor() {
        let mut reads = 0usize;
        let walked: Walk<u8> = walk(64, |_| {
            reads += 1;
            Ok::<_, ()>(Page {
                items: vec![reads as u8],
                end: PageEnd::of_optional_complete(None, Some("looks-resumable")),
            })
        })
        .expect("the scripted node never errors");

        assert_eq!(walked.stop, Stop::Unpaged);
        assert_eq!(
            reads, 1,
            "resuming an unpaged node re-serves page one forever"
        );
        assert!(walked.stop.is_whole());
    }

    /// The two-state constructor cannot produce [`PageEnd::Unpaged`], for either value.
    ///
    /// This is the whole of how a contract without an unpaged case says so, so it is asserted
    /// rather than left to the type's shape — and asserted for BOTH booleans and with and without a
    /// cursor, because a constructor that only avoided `Unpaged` on the arm a test happened to
    /// exercise would be no guarantee at all.
    #[test]
    fn the_two_state_constructor_can_never_say_unpaged() {
        for complete in [true, false] {
            for cursor in [None, Some("c")] {
                assert_ne!(
                    PageEnd::of_complete(complete, cursor),
                    PageEnd::Unpaged,
                    "a contract with a plain `bool` complete has no unpaged case to express"
                );
            }
        }
    }

    /// A cursor is offered for exactly one end, so no other end can be resumed.
    #[test]
    fn only_a_more_page_offers_a_cursor_to_resume_from() {
        assert_eq!(PageEnd::More { cursor: "c".into() }.cursor(), Some("c"));
        assert_eq!(PageEnd::Complete.cursor(), None);
        assert_eq!(PageEnd::Unpaged.cursor(), None);
        assert_eq!(PageEnd::TruncatedWithoutCursor.cursor(), None);
    }

    /// A page claiming more rows with no cursor is a stop of its own, not a completion.
    #[test]
    fn a_truncated_page_without_a_cursor_is_not_whole() {
        let walked: Walk<u8> = walk(64, |_| {
            Ok::<_, ()>(Page {
                items: vec![1],
                end: PageEnd::of_complete(false, None),
            })
        })
        .expect("the scripted node never errors");

        assert_eq!(walked.stop, Stop::NoCursor);
        assert!(
            !walked.stop.is_whole(),
            "folding a partial list into a complete one reads as missing funds"
        );
    }

    /// Only the two honest finishes are whole; every fault arm is a prefix.
    #[test]
    fn exactly_the_two_finishing_stops_are_whole() {
        assert!(Stop::Complete.is_whole());
        assert!(Stop::Unpaged.is_whole());
        assert!(!Stop::NoCursor.is_whole());
        assert!(!Stop::RepeatedCursor.is_whole());
        assert!(!Stop::PageBudget.is_whole());
    }
}
