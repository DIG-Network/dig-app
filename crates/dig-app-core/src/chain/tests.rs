//! What this module's fixtures make IMPOSSIBLE.
//!
//! Every test here runs against a real loopback HTTP server speaking the real wire bytes (the
//! [`FakeNode`] the arrivals watch already uses), because the code under test is a transport: a
//! double sharing a helper with the client could pass while the bytes were wrong.
//!
//! Each test names, in its own doc comment, the property it holds and the NEAREST WRONG
//! IMPLEMENTATION it rules out. That second half is the load-bearing one — most of these properties
//! are also satisfied by a client that is wrong in a way the fixture cannot see, so the fixture is
//! chosen to make the wrong version fail rather than merely to make the right version pass.

use chia_bls::Signature;
use chia_protocol::{Bytes32, SpendBundle};
use dig_account::mint::{PushOutcome, SpendPublisher};
use dig_chainsource_interface::ChainSource;
use dig_node_control_interface::results::WalletReadSource;
use std::time::Duration;

use crate::chain::{
    ChainReadError, ControlChainSource, ControlSpendPublisher, PublishFailure, MAX_CHILD_PAGES,
};
use crate::test_support::node::{Behaviour, ChainReply, FakeChain, FakeCoin, FakeNode, FakeSpend};

/// The peak the scripted chain reports.
const PEAK: u32 = 9_104_152;

/// A budget short enough to keep the suite quick, long enough that a loopback exchange is never the
/// thing that fails.
const TEST_TIMEOUT: Duration = Duration::from_secs(5);

/// A distinct 32-byte id per `n`, so a client that read one field where it meant another cannot pass.
fn id(n: u64) -> Bytes32 {
    Bytes32::new(
        <[u8; 32]>::try_from(hex::decode(format!("{n:064x}")).unwrap().as_slice()).unwrap(),
    )
}

/// The hex spelling of [`id`], as it travels.
fn id_hex(n: u64) -> String {
    format!("{n:064x}")
}

/// A source reading from `node`.
fn source(node: &FakeNode) -> ControlChainSource {
    ControlChainSource::with_timeout(node.endpoint(), TEST_TIMEOUT)
}

// --------------------------------------------------------------------------------------------
// PAGING — a partial child set must never be presented as a whole one
// --------------------------------------------------------------------------------------------

/// **A truncated page can never be read as the whole child set.**
///
/// The nearest wrong implementation issues ONE `coinsByParent` call and returns what came back —
/// which the contract explicitly forbids, because a short page is not evidence of completeness. A
/// caller walking a lineage reads a child list as *these are all the children*, so a prefix returned
/// as a whole set says a spend created less than it did, and the walk ends on the wrong coin.
///
/// The fixture is chosen so that wrong version FAILS rather than merely being unproven: five
/// children served two at a time, while the client asks for the contract's 1000-row maximum. So the
/// first page is short (2 < 1000) and *still* not complete — exactly the case a length heuristic
/// gets wrong. The request COUNT is asserted at the server, not inferred from the result, because a
/// client could return five children having asked once against a more generous fixture.
#[test]
fn a_truncated_page_can_never_be_read_as_the_whole_child_set() {
    let kids: Vec<FakeCoin> = (1..=5).map(|n| FakeCoin::confirmed("xch", n)).collect();
    let node = FakeNode::serving_chain(ChainReply::of(FakeChain::synced_at(PEAK).with_children(
        &id_hex(70),
        kids,
        2,
    )));

    let children = source(&node)
        .coin_records_by_parent(id(70))
        .expect("the node answered every page");

    assert_eq!(
        children.len(),
        5,
        "every child must be collected: {children:?}"
    );
    assert_eq!(
        node.request_count(),
        3,
        "5 children at 2 per page is 3 pages; a client that asked once inferred completeness"
    );
}

/// **A COMPLETE final page that still carries a cursor is not mistaken for "there is more".**
///
/// This is the shape a real dig-node 0.110.0 answers with — `complete: true` beside a non-null
/// `cursor`, because a full final page still has a last child. The nearest wrong implementation
/// keeps paging while a cursor is present, which against a node whose last page always names one
/// would either loop until the client's own bound fired (turning a good answer into an error) or
/// duplicate rows.
///
/// The fixture puts the whole child set in ONE complete page, and the assertion is the request
/// COUNT: a client that paged on cursor-presence asks twice, and no assertion about the returned
/// coins alone would notice.
#[test]
fn a_complete_page_carrying_a_cursor_is_not_mistaken_for_more() {
    let kids = vec![
        FakeCoin::confirmed("xch", 11),
        FakeCoin::confirmed("xch", 12),
    ];
    let node = FakeNode::serving_chain(ChainReply::of(FakeChain::synced_at(PEAK).with_children(
        &id_hex(70),
        kids,
        0,
    )));

    let children = source(&node)
        .coin_records_by_parent(id(70))
        .expect("answered");

    assert_eq!(children.len(), 2);
    assert_eq!(
        node.request_count(),
        1,
        "`complete` alone ends the walk; a present cursor is not evidence of another page"
    );
}

/// **A node that never says `complete` cannot hold the client forever, and never yields a prefix.**
///
/// There is no rate limiter anywhere behind this path, so an unbounded page loop is a caller's
/// thread held indefinitely by somebody else's reply. The fixture hands back an ADVANCING cursor
/// every time, so the only thing that can stop the walk is the client's own bound — a client that
/// detected the loop by a repeated cursor would not be exercised at all.
///
/// The second half is the money half, and rules out the tempting wrong fix: giving up must be an
/// ERROR, never the rows collected so far. A prefix returned as a child set is the same fail-open
/// the truncation test forbids, arrived at from the client's side instead of the node's.
#[test]
fn an_endless_node_is_bounded_and_yields_an_error_rather_than_a_prefix() {
    let node = FakeNode::serving_chain(ChainReply::of(FakeChain {
        endless_children: true,
        ..FakeChain::synced_at(PEAK)
    }));

    let outcome = source(&node).coin_records_by_parent(id(70));

    match outcome {
        Err(ChainReadError::Transport { .. }) => {}
        other => panic!("an unbounded page loop must be an unknown answer, got {other:?}"),
    }
    assert!(
        node.request_count() <= 16,
        "the client must stop at its own page bound, asked {} times",
        node.request_count()
    );
}

/// **An incomplete page with nothing to resume from is refused, not re-asked forever.**
///
/// `{complete: false, cursor: null}` is a self-contradiction the wire shape cannot forbid. The
/// nearest wrong implementation re-asks with the same (absent) cursor and spins on an identical
/// page until the page bound fires — burning sixteen round trips to reach a worse-labelled error.
/// Refusing it as unbelievable on the FIRST page is both faster and the honest classification, and
/// the request count is what distinguishes the two.
#[test]
fn an_incomplete_page_with_no_cursor_is_refused_on_the_first_page() {
    let kids = vec![FakeCoin::confirmed("xch", 21)];
    let node = FakeNode::serving_chain(ChainReply::of(FakeChain {
        incomplete_without_cursor: true,
        ..FakeChain::synced_at(PEAK).with_children(&id_hex(70), kids, 1)
    }));

    let outcome = source(&node).coin_records_by_parent(id(70));

    assert!(
        matches!(outcome, Err(ChainReadError::Malformed { .. })),
        "a self-contradicting page is unbelievable, got {outcome:?}"
    );
    assert_eq!(
        node.request_count(),
        1,
        "there is nothing to gain by re-asking"
    );
}

/// **The page bound is pinned from BOTH sides: at the bound the walk succeeds, one over it fails.**
///
/// A published bound tested only from one side can only confirm itself — an off-by-one, or a bound
/// silently lowered by a later edit, would keep a one-sided test green. So the fixture serves one
/// child per page and varies ONE thing: whether the child set needs exactly [`MAX_CHILD_PAGES`]
/// pages or one more.
///
/// The at-bound half is the more valuable of the two, because the nearest wrong implementation is a
/// loop that runs `MAX_CHILD_PAGES - 1` times and errors on a walk that was about to finish — which
/// turns a good answer into an unknown, and every other test here would stay green.
#[test]
fn the_page_bound_admits_exactly_max_child_pages_and_refuses_one_more() {
    let at_bound: Vec<FakeCoin> = (1..=MAX_CHILD_PAGES as u64)
        .map(|n| FakeCoin::confirmed("xch", n))
        .collect();
    let node = FakeNode::serving_chain(ChainReply::of(FakeChain::synced_at(PEAK).with_children(
        &id_hex(70),
        at_bound,
        1,
    )));
    let children = source(&node)
        .coin_records_by_parent(id(70))
        .expect("a child set needing exactly the bound must be readable");
    assert_eq!(children.len(), MAX_CHILD_PAGES);
    assert_eq!(node.request_count(), MAX_CHILD_PAGES);

    let one_over: Vec<FakeCoin> = (1..=MAX_CHILD_PAGES as u64 + 1)
        .map(|n| FakeCoin::confirmed("xch", n))
        .collect();
    let node = FakeNode::serving_chain(ChainReply::of(FakeChain::synced_at(PEAK).with_children(
        &id_hex(70),
        one_over,
        1,
    )));
    let outcome = source(&node).coin_records_by_parent(id(70));
    assert!(
        matches!(outcome, Err(ChainReadError::Transport { .. })),
        "one child past the bound is an unknown child set, never a prefix: {outcome:?}"
    );
}

// --------------------------------------------------------------------------------------------
// THE THREE REMEDIES — a failure must never wear another failure's remedy
// --------------------------------------------------------------------------------------------

/// **`-32601 METHOD_NOT_FOUND` can never be read as "no such coin".**
///
/// `Ok(None)` from `coin_record` is a VERDICT: it says the chain holds no such coin, so stop
/// waiting. The nearest wrong implementation maps any refusal to that verdict, and it would report
/// a mint that DID happen as never having happened — with the money already gone.
///
/// The fixture varies ONE thing against the truthful control below: the node refuses rather than
/// answers. Both `coin_record` and `coin_spend` are asked, because they are the two reads whose
/// `None` a caller acts on.
#[test]
fn a_method_not_found_can_never_be_read_as_an_absent_coin() {
    let node = FakeNode::serving_chain(ChainReply::rejected(-32601, "METHOD_NOT_FOUND"));
    let source = source(&node);

    for outcome in [
        format!("{:?}", source.coin_record(id(1))),
        format!("{:?}", source.coin_spend(id(1))),
    ] {
        assert!(
            outcome.starts_with("Err(Unsupported"),
            "a node that does not serve the read must not report an absence, got {outcome}"
        );
    }
}

/// **An `UNAUTHORIZED` on an OPEN read is reported as *upgrade the node*, never as *get a token*.**
///
/// dig-node authorizes before it resolves a method name, so a token-less probe of an unknown method
/// answers `-32030 UNAUTHORIZED` rather than `-32601`. Every read here is contractually OPEN, so a
/// refusal cannot be about a credential the method does not take — the only honest reading is that
/// the node is too old. The nearest wrong implementation reports the code at face value and sends
/// somebody to provision a token that would change nothing.
///
/// This travels the real wire, unlike the unit test on the mapping itself, so it also proves the
/// code survives the envelope round trip. The assertion is on the SENTENCE as well as the arm: an
/// arm alone would still let the message say the wrong thing.
#[test]
fn an_unauthorized_on_an_open_read_says_upgrade_and_never_mentions_a_token() {
    let node = FakeNode::serving_chain(ChainReply::rejected(-32030, "UNAUTHORIZED"));

    let outcome = source(&node).coin_spend(id(1));

    let Err(error) = outcome else {
        panic!("a refusal is never an answer: {outcome:?}");
    };
    assert!(
        matches!(error, ChainReadError::Unsupported { .. }),
        "{error:?}"
    );
    let sentence = error.to_string();
    assert!(sentence.contains("upgrade dig-node"), "said: {sentence}");
    assert!(
        !sentence.to_lowercase().contains("token"),
        "an open read needs no token, so nothing may send anybody after one: {sentence}"
    );
}

/// **A transport failure can never surface as an absence or an empty list — on ANY of the reads.**
///
/// This is the rule the whole module exists for. On `coin_spend`, `Ok(None)` means *unspent or
/// unknown*, which a caller reads as **safe to spend** and as *this is the singleton's tip*: a
/// dropped connection rendered as an absence is a double-spend enabler. dig-node's own
/// `ChiaQueryLineage::parent_spend` makes exactly this mistake (dig_ecosystem#2594), so it is a live
/// pattern rather than a hypothetical one.
///
/// The fixture is a node that ACCEPTS the connection and then closes it without replying, which is
/// the shape most likely to decode into an empty default. Every read is swept, including
/// `parent_spend` — which is the trait default and therefore easy to assume is covered by the two
/// reads it composes, when what is actually being checked is that neither composes into a `None`.
#[test]
fn no_read_turns_a_transport_failure_into_an_absence() {
    let node = FakeNode::with_behaviour(Behaviour::Silent);
    let source = source(&node);

    let outcomes = [
        ("coin_record", format!("{:?}", source.coin_record(id(1)))),
        ("coin_spend", format!("{:?}", source.coin_spend(id(1)))),
        ("parent_spend", format!("{:?}", source.parent_spend(id(1)))),
        (
            "coin_records_by_parent",
            format!("{:?}", source.coin_records_by_parent(id(1))),
        ),
        (
            "coin_records_by_puzzle_hash",
            format!("{:?}", source.coin_records_by_puzzle_hash(id(2), false)),
        ),
        ("peak_height", format!("{:?}", source.peak_height())),
    ];

    for (read, outcome) in outcomes {
        assert!(
            outcome.starts_with("Err("),
            "{read} turned an unanswered read into {outcome}"
        );
    }
}

/// **The truthful control: a healthy node's absences and answers both come through.**
///
/// Without this, every test above is satisfiable by a client that returns `Err` unconditionally —
/// the classic blind-fixture false green. So one node answers three questions: a coin it holds, a
/// coin it does not, and a spend it does not. The first proves the client can succeed; the second
/// and third prove `Ok(None)` is still reachable, which is what makes "never an absence" a
/// constraint rather than a tautology.
#[test]
fn a_healthy_node_still_answers_and_still_reports_genuine_absences() {
    let known = FakeCoin::confirmed("xch", 4242);
    let known_id = known.coin_id.clone();
    let node = FakeNode::serving_chain(ChainReply::of(
        FakeChain::synced_at(PEAK).with_coin(known.clone()),
    ));
    let source = source(&node);

    let found = source
        .coin_record(bytes32(&known_id))
        .expect("a healthy node answers")
        .expect("the coin it holds is found");
    assert_eq!(found.coin.amount, 4242);
    assert_eq!(found.confirmed_height, Some(5_412_000));
    assert!(!found.is_spent());

    assert_eq!(
        source
            .coin_record(id(9999))
            .expect("a healthy node answers"),
        None,
        "a coin the chain does not hold is a genuine absence"
    );
    assert_eq!(
        source.coin_spend(bytes32(&known_id)).expect("answered"),
        None,
        "an unspent coin has no spend, and that is an answer"
    );
}

// --------------------------------------------------------------------------------------------
// FRESHNESS — the tier that answered is a signal, not decoration
// --------------------------------------------------------------------------------------------

/// **The freshness of the answering tier is carried through, not dropped.**
///
/// Every wallet result carries `source` / `synced` / `peak_height` describing THE TIER THAT
/// ANSWERED, and the `ChainSource` trait has nowhere to put them — so the nearest wrong
/// implementation discards them, silently removing the only signal a caller has for *is this coin
/// really unspent, or is that just what a stale replica thinks?*
///
/// The fixture is the state the target machine is actually in: an unsynced replica answering from
/// the third-party coinset tier, reporting `source: fallback`, `synced: false`, `peak_height: null`.
/// A `db`/`synced: true` fixture would be the blinder choice — it cannot distinguish a client that
/// carries the fields from one that hardcodes the optimistic values.
#[test]
fn the_answering_tier_is_disclosed_rather_than_discarded() {
    let coin = FakeCoin::confirmed("xch", 77);
    let coin_id = coin.coin_id.clone();
    let node = FakeNode::serving_chain(ChainReply::of(FakeChain {
        source: "fallback",
        synced: false,
        peak_height: None,
        ..FakeChain::synced_at(PEAK).with_coin(coin)
    }));
    let source = source(&node);

    assert_eq!(
        source.last_freshness(),
        None,
        "nothing is claimed before a read"
    );
    source.coin_record(bytes32(&coin_id)).expect("answered");

    let freshness = source
        .last_freshness()
        .expect("a successful read discloses its tier");
    assert_eq!(freshness.source, Some(WalletReadSource::Fallback));
    assert!(!freshness.synced, "a fallback answer is never a synced one");
    assert_eq!(
        freshness.peak_height, None,
        "a null peak is unknown, never a stand-in zero"
    );
}

// --------------------------------------------------------------------------------------------
// ANSWERS THAT CANNOT BE BELIEVED, AND CAPABILITIES THAT ARE NOT THERE
// --------------------------------------------------------------------------------------------

/// **A spend whose coin reports no spent height is refused rather than read past.**
///
/// The contract forbids the pair — a spend exists only because a coin was spent — and the wire shape
/// cannot enforce it, which is why the client must. The nearest wrong implementation trusts the two
/// programs and ignores the contradiction, walking a lineage through a spend that may not exist.
#[test]
fn a_spend_reporting_an_unspent_coin_is_unbelievable() {
    let mut unspent = FakeCoin::confirmed("xch", 31);
    unspent.spent_height = None;
    let coin_id = unspent.coin_id.clone();
    let node = FakeNode::serving_chain(ChainReply::of(FakeChain::synced_at(PEAK).with_spend(
        FakeSpend {
            coin: unspent,
            puzzle_reveal: "ff01ff8080".into(),
            solution: "ff8203e880".into(),
        },
    )));

    let outcome = source(&node).coin_spend(bytes32(&coin_id));

    assert!(
        matches!(outcome, Err(ChainReadError::Malformed { .. })),
        "got {outcome:?}"
    );
}

/// **A well-formed spend decodes into a real `CoinSpend`, reveal and solution the right way round.**
///
/// The control test for the one above, and it makes a specific transposition impossible: the reveal
/// and the solution are distinct byte strings, so a client that swapped them fails. A fixture using
/// the same bytes for both would satisfy the property while proving nothing about which is which.
#[test]
fn a_well_formed_spend_decodes_with_its_programs_in_the_right_places() {
    let coin = FakeCoin::confirmed("xch", 55);
    let coin_id = coin.coin_id.clone();
    let node = FakeNode::serving_chain(ChainReply::of(
        FakeChain::synced_at(PEAK).with_spend(FakeSpend::of(coin, PEAK)),
    ));

    let spend = source(&node)
        .coin_spend(bytes32(&coin_id))
        .expect("answered")
        .expect("the node holds that spend");

    assert_eq!(spend.coin.amount, 55);
    assert_eq!(hex::encode(spend.puzzle_reveal.as_ref()), "ff01ff8080");
    assert_eq!(hex::encode(spend.solution.as_ref()), "ff8203e880");
}

/// **`include_spent: true` is refused, never answered with the unspent set.**
///
/// `control.wallet.coins` lists UNSPENT coins only and takes no widening parameter. The nearest
/// wrong implementation ignores the flag and answers anyway, so a caller looking for a SPENT coin —
/// a mint's funding coin, say — is told it does not exist. That is a wrong answer wearing the shape
/// of a right one, and no assertion about the returned list could catch it, which is why the flag's
/// refusal is asserted directly.
///
/// The `false` half is asserted against a node that DOES hold coins, so the refusal cannot be a
/// blanket one and cannot be satisfied by a client that returns an empty list for both.
#[test]
fn include_spent_is_refused_rather_than_answered_with_the_unspent_set() {
    let node = FakeNode::serving_chain(ChainReply::of(FakeChain {
        address_coins: vec![FakeCoin::confirmed("xch", 900)],
        ..FakeChain::synced_at(PEAK)
    }));
    let source = source(&node);

    let refused = source.coin_records_by_puzzle_hash(id(3), true);
    assert!(
        matches!(refused, Err(ChainReadError::Unsupported { .. })),
        "the unspent set is not an answer to an include-spent question, got {refused:?}"
    );

    let unspent = source
        .coin_records_by_puzzle_hash(id(3), false)
        .expect("the unspent question IS serviceable");
    assert_eq!(unspent.len(), 1, "{unspent:?}");
    assert_eq!(unspent[0].coin.amount, 900);
}

/// **A launcher the chain does not have is a genuine `Ok(None)` — proving the walk is SERVED.**
///
/// Through 10.3.0 this method was a stated `Unsupported` placeholder, so the nearest wrong
/// implementation is the one that was actually here: a client that never looks. That version fails
/// this test, because it cannot produce `Ok(None)` at all.
///
/// `Ok(None)` is the walk's own documented answer for *no such launcher* — the node was asked, it
/// answered that the coin does not exist, and the walk stopped there. The companion test below is
/// what keeps this from licensing the opposite error: an absence may be reached ONLY from an answer,
/// never from a failure.
#[test]
fn a_launcher_the_chain_does_not_have_is_a_genuine_absence() {
    let node = FakeNode::serving_chain(ChainReply::of(FakeChain::synced_at(PEAK)));

    let answered = source(&node)
        .resolve_singleton_lineage(id(1))
        .expect("a node that answers must not produce an error");

    assert_eq!(
        answered, None,
        "a launcher no coin record names resolves to no lineage"
    );
}

/// **A lineage walk against an unanswerable node is an `Err`, and NEVER `Ok(None)`.**
///
/// This is the money-critical half, and it is the reason the walk is delegated rather than written
/// here. `Ok(None)` on this method means *the launcher never existed, or the singleton was melted* —
/// a verdict about an identity. Delivered because a socket dropped, it is a fail-OPEN answer about
/// somebody's DID, and on the mint path *the lineage ends here* reads as **safe to spend**.
///
/// The nearest wrong implementation is a `map_err` that collapses a walk failure into an absence, or
/// a `.ok()` anywhere on this path. The fixture is a node that accepts the connection and never
/// replies — the shape most likely to decode into an empty default — and the control leg is the test
/// above, on a node that DOES answer, so this cannot pass by the client erroring unconditionally.
#[test]
fn a_lineage_walk_that_could_not_be_completed_is_never_reported_as_an_absent_singleton() {
    let node = FakeNode::with_behaviour(Behaviour::Silent);

    let outcome = source(&node).resolve_singleton_lineage(id(1));

    let Err(error) = outcome else {
        panic!("an unanswered walk must not become a verdict about an identity: {outcome:?}");
    };
    // A dropped socket is a retry, not an accusation and not an upgrade prompt.
    assert!(
        matches!(error, ChainReadError::Transport { .. }),
        "an unanswered read is a transport fault: {error:?}"
    );
}

/// **Each walk failure keeps its OWN remedy: retry, report, or upgrade.**
///
/// `ChainReadError`'s three original arms encode remedies, not causes, and the walk can fail in six
/// ways. The nearest wrong implementation flattens them — most temptingly into `Malformed`, which
/// says *the node's answer could not be believed*. Saying that about a node whose only sin was being
/// slow, or serving a singleton with a large puzzle reveal, accuses an honest party of lying; the
/// walk crate keeps `RevealTooLarge` and `LineageTooDeep` as distinct variants for exactly that
/// reason, which is why `ChainReadError::Unusable` now exists to receive them.
///
/// Asserted over the mapping function directly, because several of these variants cannot be provoked
/// from a fixture node at all — a 100,000-hop lineage is not something a test builds. Every arm is
/// listed, so a future variant added to the match without a remedy shows up here.
#[test]
fn every_lineage_walk_failure_keeps_its_own_remedy() {
    use dig_chainsource_interface::LineageWalkError;

    let source_fault = ChainReadError::transport("control.wallet.coinById", "socket closed");

    let cases: Vec<(&str, LineageWalkError<ChainReadError>, ChainReadError)> = vec![
        (
            "a failed read passes through UNMODIFIED, keeping its own arm",
            LineageWalkError::Source(source_fault.clone()),
            source_fault,
        ),
        (
            "inconsistent chain data is unbelievable",
            LineageWalkError::Malformed("a spend of the wrong coin".into()),
            ChainReadError::malformed("resolve_singleton_lineage", "a spend of the wrong coin"),
        ),
        (
            "a coin that is not this launcher's singleton is unbelievable",
            LineageWalkError::NotASingleton { coin_id: id(9) },
            ChainReadError::malformed(
                "resolve_singleton_lineage",
                format!("coin {} is not a genuine singleton of this launcher", id(9)),
            ),
        ),
        (
            "an oversized reveal is refused for SIZE, not accused of corruption",
            LineageWalkError::RevealTooLarge {
                coin_id: id(9),
                limit: 4096,
            },
            ChainReadError::unusable(
                "resolve_singleton_lineage",
                format!(
                    "the puzzle reveal of coin {} expands beyond the 4096-byte bound",
                    id(9)
                ),
            ),
        ),
        (
            "a too-deep lineage is refused for DEPTH, and is not a retry",
            LineageWalkError::TooDeep { limit: 100_000 },
            ChainReadError::unusable(
                "resolve_singleton_lineage",
                "this singleton's lineage is longer than the 100000-hop bound DIG will walk",
            ),
        ),
        (
            "a budget overrun is a retry, never an accusation",
            LineageWalkError::DeadlineExceeded {
                budget: Duration::from_secs(45),
            },
            ChainReadError::transport(
                "resolve_singleton_lineage",
                "the lineage walk outlasted its 45s budget",
            ),
        ),
    ];

    for (property, failure, expected) in cases {
        assert_eq!(super::source::walk_failure(failure), expected, "{property}");
    }
}

/// **`peak_height` reports the node's height, and a null peak stays unknown.**
///
/// The contract is explicit that `null` is "this node tracks no height yet", not zero — every block
/// is trivially above zero, so a stand-in would license a confirmation that never happened. The
/// fixture asserts both directions, because a client that returned `Ok(None)` unconditionally would
/// satisfy the null half alone.
#[test]
fn a_null_peak_stays_unknown_and_a_real_peak_comes_through() {
    let known = FakeNode::serving_chain(ChainReply::of(FakeChain::synced_at(PEAK)));
    assert_eq!(source(&known).peak_height().expect("answered"), Some(PEAK));

    let unknown = FakeNode::serving_chain(ChainReply::of(FakeChain {
        peak_height: None,
        ..FakeChain::synced_at(PEAK)
    }));
    assert_eq!(source(&unknown).peak_height().expect("answered"), None);
}

/// **`block_timestamp` is an honest `Ok(None)`, matching chia-peer's light-client precedent.**
///
/// The control plane exposes no height-to-timestamp read, so this source genuinely does not resolve
/// timestamps — which is what `None` means on this method. Asserted so a later reader does not
/// mistake it for an oversight and wire something speculative into a money path.
#[test]
fn block_timestamp_is_an_honest_absence() {
    let node = FakeNode::serving_chain(ChainReply::of(FakeChain::synced_at(PEAK)));
    assert_eq!(source(&node).block_timestamp(PEAK).expect("answered"), None);
}

// --------------------------------------------------------------------------------------------
// THE PUSH — §908, and the one method that needs a token
// --------------------------------------------------------------------------------------------

/// A minimal already-signed bundle. Empty of spends and carrying the infinity signature: this
/// module never inspects a bundle's contents, only serializes it, so a heavier fixture would test
/// chia's encoder rather than this client.
fn a_bundle() -> SpendBundle {
    SpendBundle::new(vec![], Signature::default())
}

/// A token reader for a machine that holds no control token.
fn no_token() -> Option<String> {
    None
}

/// A token reader presenting the token [`FakeNode`] authorizes.
fn good_token() -> Option<String> {
    Some(FakeNode::TOKEN.to_string())
}

/// **A token-less push is a LOCAL refusal, and can never look like an absent node.**
///
/// The two have opposite remedies — read the node's token, versus start a node — and dig-node runs
/// as a service whose master token this user may simply not be able to read, so a healthy node plus
/// no token is an ordinary state rather than an exotic one. The nearest wrong implementation sends
/// the push anyway and reports whatever refusal comes back, which is indistinguishable from the
/// shape an absent node produces.
///
/// The request COUNT is asserted at the server, and it is the load-bearing half: the property "a
/// token-less push fails" is satisfied by a client that sends it and gets a 401. Only the count
/// shows the refusal happened BEFORE a signed bundle went anywhere.
#[test]
fn a_tokenless_push_is_refused_locally_and_never_reads_as_an_absent_node() {
    let node = FakeNode::serving_broadcast(crate::test_support::node::BroadcastReply::Accepted {
        transaction_id: "ab".repeat(32),
    });
    let publisher =
        ControlSpendPublisher::with_token_reader(node.endpoint(), no_token, TEST_TIMEOUT);

    let outcome = publisher.push_detailed(&a_bundle());

    assert_eq!(
        outcome,
        Err(PublishFailure::NoToken),
        "a missing token is its own fault, not an unreachable node"
    );
    assert_eq!(
        node.request_count(),
        0,
        "a push that cannot be authorized must not put a signed bundle on the wire at all"
    );
}

/// **A token-less push never becomes a mempool rejection at the trait boundary either.**
///
/// `SpendPublisher::push` has two positions, and which one a failure lands in decides what the
/// caller does next: a `PushOutcome::Rejected` means the mempool judged the bundle, so REBUILD it,
/// while a `ChainUnavailable` means it was never asked, so RETRY it. The nearest wrong
/// implementation reaches for `Rejected` because it is the arm that carries a reason string — and
/// would have dig-account discard a perfectly good signed bundle over a missing file permission.
#[test]
fn a_tokenless_push_is_unavailable_rather_than_a_mempool_verdict() {
    let node = FakeNode::serving_broadcast(crate::test_support::node::BroadcastReply::Accepted {
        transaction_id: "ab".repeat(32),
    });
    let publisher =
        ControlSpendPublisher::with_token_reader(node.endpoint(), no_token, TEST_TIMEOUT);

    let outcome = SpendPublisher::push(&publisher, &a_bundle());

    let Err(unavailable) = outcome else {
        panic!("an unsent push is never an outcome: {outcome:?}");
    };
    assert!(
        unavailable.to_string().contains("control token"),
        "the sentence must name the real remedy: {unavailable}"
    );
}

/// **A mempool that judged the bundle is a VALUE; a node that could not be reached is an ERROR.**
///
/// The truthful control for the two tests above, and the one that makes them non-vacuous: with a
/// token, the same publisher reaches the same node and gets a real answer. Both mempool verdicts are
/// exercised — acceptance and rejection — because a client that returned `Err` for every non-accepted
/// push would satisfy "acceptance works" while destroying the distinction the type exists for.
#[test]
fn a_mempool_verdict_is_a_value_and_only_an_unasked_push_is_an_error() {
    use crate::test_support::node::BroadcastReply;

    let accepted = FakeNode::serving_broadcast(BroadcastReply::Accepted {
        transaction_id: "cd".repeat(32),
    });
    let publisher =
        ControlSpendPublisher::with_token_reader(accepted.endpoint(), good_token, TEST_TIMEOUT);
    assert_eq!(
        publisher.push_detailed(&a_bundle()),
        Ok(PushOutcome::Accepted)
    );

    let refused = FakeNode::serving_broadcast(BroadcastReply::RefusedByMempool {
        reason: "ASSERT_HEIGHT_ABSOLUTE_FAILED".into(),
    });
    let publisher =
        ControlSpendPublisher::with_token_reader(refused.endpoint(), good_token, TEST_TIMEOUT);
    assert_eq!(
        publisher.push_detailed(&a_bundle()),
        Ok(PushOutcome::Rejected {
            reason: "ASSERT_HEIGHT_ABSOLUTE_FAILED".into()
        }),
        "a judged bundle is a successful call carrying a verdict"
    );

    let mute = FakeNode::with_behaviour(Behaviour::Silent);
    let publisher =
        ControlSpendPublisher::with_token_reader(mute.endpoint(), good_token, TEST_TIMEOUT);
    assert!(
        matches!(
            publisher.push_detailed(&a_bundle()),
            Err(PublishFailure::Unreachable { .. })
        ),
        "an unanswered push is an unknown outcome"
    );
}

/// **A duplicate is the same success arrived at twice, not a rejection.**
///
/// The mempool's `ALREADY_INCLUDING_TRANSACTION` means the bundle IS in flight. The nearest wrong
/// implementation reports it as `Rejected`, and a caller following the rebuild-on-rejection rule
/// would build a second spend of coins already committed — a double spend produced by mislabelling
/// a success.
#[test]
fn a_duplicate_in_the_mempool_is_a_success_not_a_rejection() {
    let node = FakeNode::serving_broadcast(
        crate::test_support::node::BroadcastReply::RefusedByMempool {
            reason: "ALREADY_INCLUDING_TRANSACTION".into(),
        },
    );
    let publisher =
        ControlSpendPublisher::with_token_reader(node.endpoint(), good_token, TEST_TIMEOUT);

    assert_eq!(
        publisher.push_detailed(&a_bundle()),
        Ok(PushOutcome::AlreadyInMempool)
    );
}

/// **An `UNAUTHORIZED` on the PUSH means *get a token* — the opposite reading to an open read.**
///
/// This is the other half of requirement 3, and the pair is the point: the SAME wire code demands
/// opposite remedies on the two paths, because the push genuinely takes a token and the reads
/// genuinely do not. A client with one mapping for both sends somebody to fix the wrong thing on one
/// of them, whichever way it chose.
#[test]
fn an_unauthorized_on_the_push_is_a_credential_fault_not_an_old_node() {
    let node = FakeNode::serving_broadcast(crate::test_support::node::BroadcastReply::rejected(
        -32030,
        "UNAUTHORIZED",
    ));
    let publisher =
        ControlSpendPublisher::with_token_reader(node.endpoint(), good_token, TEST_TIMEOUT);

    let outcome = publisher.push_detailed(&a_bundle());

    assert!(
        matches!(outcome, Err(PublishFailure::Unauthorized { .. })),
        "got {outcome:?}"
    );
    assert!(
        !format!("{outcome:?}").contains("upgrade"),
        "the push's refusal is about the credential, not the node's age: {outcome:?}"
    );
}

/// A [`Bytes32`] from its hex spelling, for ids the fixture generated.
fn bytes32(hex_text: &str) -> Bytes32 {
    Bytes32::new(<[u8; 32]>::try_from(hex::decode(hex_text).unwrap().as_slice()).unwrap())
}

/// A token reader presenting a token the node does not know.
fn wrong_token() -> Option<String> {
    Some("not-the-nodes-token".into())
}

/// **The push's four remaining failures each keep their own remedy.**
///
/// Grouped because they share one shape and differ only in which remedy they name, and the point is
/// precisely that they stay APART: the nearest wrong implementation collapses them into one
/// "broadcast failed", after which nobody can tell an old node from a wrong token from a node that
/// declined to explain itself. Each assertion therefore checks the ARM and the sentence's remedy
/// word, since an arm alone would still let the message mislead.
///
/// The reasonless refusal is the subtle one. `accepted: false` with no reason asserts the bundle is
/// not in a mempool while supplying nothing that judged it, and the tempting reading is
/// `PushOutcome::Rejected` — which would send dig-account to rebuild a bundle that may be perfectly
/// good and is possibly already in flight.
#[test]
fn each_push_failure_keeps_its_own_remedy() {
    use crate::test_support::node::BroadcastReply;

    let old_node =
        FakeNode::serving_broadcast(BroadcastReply::rejected(-32601, "METHOD_NOT_FOUND"));
    let outcome =
        ControlSpendPublisher::with_token_reader(old_node.endpoint(), good_token, TEST_TIMEOUT)
            .push_detailed(&a_bundle());
    let Err(error) = outcome else {
        panic!("{outcome:?}")
    };
    assert!(
        matches!(error, PublishFailure::Unsupported { .. }),
        "{error:?}"
    );
    assert!(error.to_string().contains("upgrade it"), "{error}");

    // A token the node does not know draws an HTTP 401, before any JSON-RPC body exists. That is a
    // CREDENTIAL fault here, unlike the identical status on an open read.
    let node = FakeNode::serving_broadcast(BroadcastReply::Accepted {
        transaction_id: "ef".repeat(32),
    });
    let outcome =
        ControlSpendPublisher::with_token_reader(node.endpoint(), wrong_token, TEST_TIMEOUT)
            .push_detailed(&a_bundle());
    let Err(error) = outcome else {
        panic!("{outcome:?}")
    };
    assert!(
        matches!(error, PublishFailure::Unauthorized { .. }),
        "{error:?}"
    );
    assert!(error.to_string().contains("control token"), "{error}");
    assert!(!error.to_string().contains("upgrade"), "{error}");

    let mute = FakeNode::serving_broadcast(BroadcastReply::NeitherAcceptedNorRejected);
    let outcome =
        ControlSpendPublisher::with_token_reader(mute.endpoint(), good_token, TEST_TIMEOUT)
            .push_detailed(&a_bundle());
    assert!(
        matches!(outcome, Err(PublishFailure::NodeCouldNotAnswer { .. })),
        "an unexplained non-acceptance is not a mempool verdict: {outcome:?}"
    );

    let broken =
        FakeNode::serving_broadcast(BroadcastReply::rejected(-32042, "WALLET_READ_FAILED"));
    let outcome =
        ControlSpendPublisher::with_token_reader(broken.endpoint(), good_token, TEST_TIMEOUT)
            .push_detailed(&a_bundle());
    let Err(error) = outcome else {
        panic!("{outcome:?}")
    };
    assert!(
        matches!(error, PublishFailure::NodeCouldNotAnswer { .. }),
        "{error:?}"
    );
    assert!(!error.to_string().contains("upgrade"), "{error}");
}

/// **A coin field that is not 32 bytes of hex is refused, on every read that decodes one.**
///
/// The node's ids are attacker-influenced in the sense that matters here: they come off a wire this
/// client does not control, and a `Coin` built from a truncated or over-long parent id is a coin
/// that does not exist. The nearest wrong implementation pads or truncates to 32 bytes, silently
/// fabricating an id — which downstream becomes a lineage hop to a coin nobody ever created.
///
/// The fixture varies ONE field on an otherwise well-formed coin, so the failure cannot be blamed on
/// the rest of the reply.
#[test]
fn a_coin_field_that_is_not_thirty_two_bytes_is_refused_rather_than_padded() {
    let mut bad = FakeCoin::confirmed("xch", 61);
    let coin_id = bad.coin_id.clone();
    bad.parent_coin_info = "deadbeef".into();
    let node = FakeNode::serving_chain(ChainReply::of(FakeChain::synced_at(PEAK).with_coin(bad)));

    let outcome = source(&node).coin_record(bytes32(&coin_id));

    assert!(
        matches!(outcome, Err(ChainReadError::Malformed { .. })),
        "a short parent id must never be padded into a coin that does not exist: {outcome:?}"
    );
}

/// **A spend whose programs are not hex is refused rather than decoded to empty CLVM.**
///
/// An empty `Program` is a valid value, so the nearest wrong implementation — `unwrap_or_default()`
/// on the hex decode — produces a structurally fine `CoinSpend` carrying a puzzle that is not the
/// one that ran. Nothing downstream could detect it, which is why it is refused here.
#[test]
fn a_spend_whose_programs_are_not_hex_is_refused_rather_than_emptied() {
    let coin = FakeCoin::confirmed("xch", 62);
    let coin_id = coin.coin_id.clone();
    let node = FakeNode::serving_chain(ChainReply::of(FakeChain::synced_at(PEAK).with_spend(
        FakeSpend {
            coin: FakeCoin {
                spent_height: Some(PEAK),
                ..coin
            },
            puzzle_reveal: "not-hex".into(),
            solution: "ff8203e880".into(),
        },
    )));

    let outcome = source(&node).coin_spend(bytes32(&coin_id));

    assert!(
        matches!(outcome, Err(ChainReadError::Malformed { .. })),
        "got {outcome:?}"
    );
}
