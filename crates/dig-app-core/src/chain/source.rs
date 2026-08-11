//! [`ControlChainSource`] — the canonical chain-READ seam, served by the local dig-node.
//!
//! dig-account's profile minter is generic over
//! [`ChainSource`] and does not know or care which chain
//! answers it. This is the provider that makes the user's OWN node the answer: every read is one
//! `control.wallet.*` call over the loopback control plane, and nothing here consults a third party
//! directly (the node may fall back to one, and says so — see [`Freshness`]).
//!
//! # The custody boundary (§908)
//!
//! Everything in this file is a READ. No key, seed, phrase, address-derivation secret or signature
//! appears anywhere on this path, and the trait it implements is structurally incapable of pushing
//! — there is no broadcast method on it, by design. The push half is [`crate::chain::publish`], and
//! it takes an already-signed bundle.
//!
//! # Which control method answers which trait method
//!
//! | trait method | control method | token |
//! |---|---|---|
//! | [`coin_record`](ChainSource::coin_record) | `control.wallet.coinById` | open |
//! | [`coin_records_by_puzzle_hash`](ChainSource::coin_records_by_puzzle_hash) | `control.wallet.coins` | open |
//! | [`coin_records_by_parent`](ChainSource::coin_records_by_parent) | `control.wallet.coinsByParent` | open |
//! | [`coin_spend`](ChainSource::coin_spend) | `control.wallet.coinSpend` | open |
//! | [`peak_height`](ChainSource::peak_height) | `control.wallet.peak` | open |
//! | [`parent_spend`](ChainSource::parent_spend) | *(the trait default)* | — |
//! | [`block_timestamp`](ChainSource::block_timestamp) | *(none exists)* | — |
//! | [`resolve_singleton_lineage`](ChainSource::resolve_singleton_lineage) | *(the shared walk, over the four reads above)* | — |
//!
//! `parent_spend` is deliberately NOT overridden: the trait's default composes `coin_record` with
//! `coin_spend`, which is exactly the two calls a direct implementation would make, and a second
//! spelling of a money-critical walk is a second thing to keep correct.
//!
//! # Reads only, and reads that never lie by omission
//!
//! `Ok(None)` and `vec![]` are answers here, reachable only from a node that consulted a chain. Every
//! failure is a [`ChainReadError`]; see that type for why the distinction is money-critical.

use chia_protocol::{Bytes32, Coin, CoinSpend, Program};
use chia_sdk_utils::Address;
use dig_chainsource_interface::{walk_singleton_lineage, LineageWalkError};
use dig_chainsource_interface::{ChainSource, CoinRecord, SingletonLineage};
use dig_node_control_interface::params::{
    Asset, WalletCoinByIdParams, WalletCoinSpendParams, WalletCoinsByParentParams,
    WalletCoinsParams, WalletPeakParams, COINS_BY_PARENT_MAX_LIMIT,
};
use dig_node_control_interface::results::{
    WalletCoinRecord, WalletCoinsByParentResult, WalletReadSource,
};
use dig_node_control_interface::traits::ControlCall;
use std::sync::Mutex;
use std::time::Duration;

use crate::chain::error::ChainReadError;
use crate::control;

/// How long ONE chain read may take before it is abandoned.
///
/// Generous compared to [`crate::control::DEFAULT_PROBE_TIMEOUT`], and for a reason the liveness
/// probe does not share: this read can go to CHAIN. On the fallback tier the node forwards it to a
/// public HTTPS oracle, so a budget tuned for a loopback round trip would abandon a read that was
/// merely being answered honestly — and an abandoned read is an unknown, which fails a mint closed.
pub const READ_TIMEOUT: Duration = Duration::from_secs(20);

/// The page size asked of `control.wallet.coinsByParent`.
///
/// The contract's own maximum, taken from the contract rather than restated, so a raised ceiling
/// needs no edit here and a lowered one cannot leave this asking for a value the node refuses
/// outright (an over-max limit is `INVALID_PARAMS`, never a clamp).
pub const CHILD_PAGE_SIZE: u32 = COINS_BY_PARENT_MAX_LIMIT;

/// How many pages of one coin's children this client will draw before giving up.
///
/// # Why a bound exists at all
///
/// The node paginates but does not rate-limit (the contract records that there is no limiter behind
/// this path at all), and a hostile or broken node can answer `complete: false` forever. Without a
/// ceiling a single `coin_records_by_parent` call is an unbounded loop against a remote party's
/// answer — the caller's thread held indefinitely by somebody else's reply.
///
/// # Why exceeding it is an ERROR and not a short list
///
/// Returning what was collected so far would be the exact fail-open this whole module exists to
/// prevent: a caller reads a child list as *these are all the children*, so a truncated one says a
/// spend created less than it did. Hitting the bound means the answer is UNKNOWN, so it is a
/// [`ChainReadError::Transport`].
///
/// 16 pages of the contract's 1000-row maximum is 16,000 children — far above any real spend, whose
/// output count is bounded by block cost, and far below a loop that never ends.
pub const MAX_CHILD_PAGES: usize = 16;

/// The `control.*` method names, as they appear in a [`ChainReadError`]. Taken from the contract's
/// own name table so an error can never name a method the client did not actually call.
mod method {
    use dig_node_control_interface::method::ControlMethod;

    /// `control.wallet.coinById`.
    pub const COIN_BY_ID: &str = ControlMethod::WalletCoinById.name();
    /// `control.wallet.coins`.
    pub const COINS: &str = ControlMethod::WalletCoins.name();
    /// `control.wallet.coinsByParent`.
    pub const COINS_BY_PARENT: &str = ControlMethod::WalletCoinsByParent.name();
    /// `control.wallet.coinSpend`.
    pub const COIN_SPEND: &str = ControlMethod::WalletCoinSpend.name();
    /// `control.wallet.peak`.
    pub const PEAK: &str = ControlMethod::WalletPeak.name();
}

/// Which tier of the node answered a read, and how current that tier claims to be.
///
/// # Why this is kept rather than dropped
///
/// Every wallet result carries `source` / `synced` / `peak_height`, describing THE TIER THAT
/// ANSWERED — and the trait it feeds has nowhere to put them. Dropping them on the floor would
/// discard the only signal a caller has for the question that decides a spend: *is this coin really
/// unspent, or is that just what a stale replica thinks?* On the machine this was built against
/// every read answers `"source": "fallback"` because the node's own replica is behind, so this is
/// not a hypothetical field.
///
/// It is recorded out-of-band, on [`ControlChainSource::last_freshness`], rather than folded into
/// the return value, because the trait's shape is fixed by the contract crate and a wrapper type
/// would not survive erasure behind `dyn ChainSource`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Freshness {
    /// Which tier produced the answer, or `None` from a node too old to disclose it.
    ///
    /// [`WalletReadSource::Fallback`] means a third-party HTTPS oracle was consulted and the queried
    /// value was disclosed off-machine.
    pub source: Option<WalletReadSource>,
    /// Whether the answering tier claims to reflect a caught-up view. Always `false` for a fallback
    /// answer, however caught-up the node's own replica is.
    pub synced: bool,
    /// The peak height the answer reflects, or `None` when none applies. Never a stand-in zero.
    pub peak_height: Option<u32>,
}

/// A [`ChainSource`] served by the local dig-node's control plane.
pub struct ControlChainSource {
    /// The `http://…` control endpoint, already resolved off the §5.3 ladder.
    endpoint: String,
    /// How long one read may take.
    timeout: Duration,
    /// The freshness the most recent successful read reported. See [`Freshness`].
    last_freshness: Mutex<Option<Freshness>>,
}

impl ControlChainSource {
    /// A chain source reading from the node at `endpoint`, with the default [`READ_TIMEOUT`].
    ///
    /// There is no `token` parameter, and that is a statement rather than an omission: all five
    /// reads are OPEN in the 0.10 contract, so presenting a token would neither be required nor
    /// change any answer. The token belongs to the PUSH half alone
    /// ([`crate::chain::ControlSpendPublisher`]), which keeps the credential on the one path that
    /// actually needs it.
    pub fn new(endpoint: impl Into<String>) -> Self {
        Self::with_timeout(endpoint, READ_TIMEOUT)
    }

    /// [`new`](Self::new) with an explicit per-read budget.
    pub fn with_timeout(endpoint: impl Into<String>, timeout: Duration) -> Self {
        Self {
            endpoint: endpoint.into(),
            timeout,
            last_freshness: Mutex::new(None),
        }
    }

    /// What the most recent successful read said about the tier that answered it.
    ///
    /// `None` before any read has succeeded. See [`Freshness`] for why this is not discarded.
    pub fn last_freshness(&self) -> Option<Freshness> {
        *self.last_freshness.lock().expect("freshness mutex")
    }

    /// Record the freshness an answer disclosed.
    ///
    /// # Called only once the reply has been BELIEVED
    ///
    /// Every caller of this runs after the reply it came with has passed validation — after the
    /// coin fields decoded, after the asset was checked, after the walk completed. That ordering
    /// is the whole meaning of the field: it answers *is this coin really unspent, or is that a
    /// stale replica*, so freshness taken from a reply the client went on to refuse would answer a
    /// spend question out of an error. A read that returns `Err` leaves the previous value alone.
    fn note_freshness(&self, freshness: Freshness) {
        *self.last_freshness.lock().expect("freshness mutex") = Some(freshness);
    }

    /// One OPEN control read, with every failure mapped onto the arm whose remedy is correct.
    ///
    /// The single door to the wire, so no read can accidentally acquire a different error mapping
    /// — which is how one read comes to report an absence the others would have refused.
    fn read<C>(&self, method: &'static str, call: &C) -> Result<C::Output, ChainReadError>
    where
        C: ControlCall,
    {
        control::call_control_result(&self.endpoint, call, None, self.timeout)
            .map_err(|failure| ChainReadError::from_open_read_failure(method, failure))
    }
}

impl ChainSource for ControlChainSource {
    type Error = ChainReadError;

    fn coin_record(&self, coin_id: Bytes32) -> Result<Option<CoinRecord>, Self::Error> {
        let answer = self.read(
            method::COIN_BY_ID,
            &WalletCoinByIdParams {
                coin_id: hex::encode(coin_id),
            },
        )?;
        let record = answer
            .coin
            .as_ref()
            .map(|c| coin_record_from(method::COIN_BY_ID, c))
            .transpose()?;
        self.note_freshness(Freshness {
            source: answer.source,
            synced: answer.synced,
            peak_height: answer.peak_height,
        });
        Ok(record)
    }

    /// # `include_spent` is REFUSED, not quietly ignored
    ///
    /// `control.wallet.coins` answers by ADDRESS and lists UNSPENT coins only; the contract states
    /// so and there is no parameter that widens it. Answering an `include_spent: true` request with
    /// the unspent set would be a wrong answer wearing the shape of a right one — a caller looking
    /// for a spent coin would be told it does not exist. So the unserviceable half of the method is
    /// [`ChainReadError::Unsupported`], and the caller can see which capability it needs.
    ///
    /// # This read is narrowed to XCH, and that narrowing is a KNOWN divergence
    ///
    /// The trait says this answers ALL coins paying to `puzzle_hash`. `control.wallet.coins` is
    /// scoped to exactly one asset, so this asks for [`Asset::Xch`] and can only ever answer XCH.
    /// A puzzle hash holding only $DIG CAT coins therefore answers `vec![]`, which on this trait
    /// means *no matching coins* — the same wrong-answer-in-the-shape-of-a-right-one this method
    /// refuses `include_spent` for. It is tolerated (and NOT refused) only because the one caller
    /// on the mint path selects XCH funding coins, so the narrowing costs no capability today;
    /// widening it needs either a per-asset loop or a control method that is not scoped.
    ///
    /// The `"xch"` address HRP is likewise a mainnet-only assumption. There is no testnet build of
    /// this app, and the control plane names no network, so `"txch"` has nowhere to come from.
    ///
    /// Both facts are recorded in [`crate::chain`]'s absence rule and in `SPEC.md` §3.1b.
    fn coin_records_by_puzzle_hash(
        &self,
        puzzle_hash: Bytes32,
        include_spent: bool,
    ) -> Result<Vec<CoinRecord>, Self::Error> {
        if include_spent {
            return Err(ChainReadError::unsupported(
                method::COINS,
                "control.wallet.coins lists UNSPENT coins only and takes no include-spent \
                 parameter; a spent coin must be read by its own id via control.wallet.coinById",
            ));
        }
        // bech32m over a fixed 32-byte payload and a fixed HRP cannot fail, so this arm is
        // unreachable in practice. It is kept rather than unwrapped because the alternative on a
        // money path is a panic, and an error the caller can read costs one line.
        let address = Address::new(puzzle_hash, "xch".to_string())
            .encode()
            .map_err(|e| {
                ChainReadError::malformed(
                    method::COINS,
                    format!("that puzzle hash has no xch address: {e}"),
                )
            })?;
        let answer = self.read(
            method::COINS,
            &WalletCoinsParams {
                address,
                asset: Asset::Xch,
            },
        )?;
        let records: Vec<CoinRecord> = answer
            .coins
            .iter()
            .map(|c| {
                // The contract makes this the ONE read that must echo the concrete asset it was
                // scoped to. Since the caller will treat these as XCH funding coins, a record
                // labelled anything else -- or labelled nothing -- is a node widening or
                // mislabelling a scoped answer, and believing it would spend a CAT coin as if it
                // were XCH. An unbelievable answer, not an answer.
                if c.asset != Some(Asset::Xch) {
                    return Err(ChainReadError::malformed(
                        method::COINS,
                        format!(
                            "control.wallet.coins was scoped to xch and answered a coin labelled \
                             {:?}",
                            c.asset
                        ),
                    ));
                }
                coin_record_from(method::COINS, c)
            })
            .collect::<Result<_, _>>()?;
        self.note_freshness(Freshness {
            source: answer.source,
            synced: answer.synced,
            peak_height: answer.peak_height,
        });
        Ok(records)
    }

    /// # Paged to exhaustion, or refused
    ///
    /// See [`MAX_CHILD_PAGES`]. The loop resumes only from the `cursor` the previous page HANDED
    /// BACK, never from a value invented here, and it stops only on `complete: true` — never on a
    /// short page, which the contract states is not evidence of completeness.
    fn coin_records_by_parent(
        &self,
        parent_coin_id: Bytes32,
    ) -> Result<Vec<CoinRecord>, Self::Error> {
        let mut children = Vec::new();
        let mut after_coin_id: Option<String> = None;

        for _ in 0..MAX_CHILD_PAGES {
            let page: WalletCoinsByParentResult = self.read(
                method::COINS_BY_PARENT,
                &WalletCoinsByParentParams {
                    parent_coin_id: hex::encode(parent_coin_id),
                    after_coin_id: after_coin_id.clone(),
                    limit: Some(CHILD_PAGE_SIZE),
                },
            )?;
            // [`MAX_CHILD_PAGES`] bounds this walk by reasoning about pages of at most
            // [`CHILD_PAGE_SIZE`] rows -- but that is the limit ASKED for, and nothing on the way
            // back enforces it. An over-long page makes the stated bound arithmetic false, so the
            // page is refused rather than absorbed.
            if page.coins.len() > CHILD_PAGE_SIZE as usize {
                return Err(ChainReadError::malformed(
                    method::COINS_BY_PARENT,
                    format!(
                        "the node answered {} children to a page limit of {CHILD_PAGE_SIZE}",
                        page.coins.len()
                    ),
                ));
            }
            for record in &page.coins {
                children.push(coin_record_from(method::COINS_BY_PARENT, record)?);
            }
            if page.complete {
                // Recorded HERE and nowhere else in the walk: freshness answers "is this coin
                // really unspent, or is that a stale replica", so a value left behind by a walk
                // that then failed on a later page would answer it from a read that returned
                // `Err`. Only a completed walk has a freshness to report.
                self.note_freshness(Freshness {
                    source: page.source,
                    synced: page.synced,
                    peak_height: page.peak_height,
                });
                return Ok(children);
            }
            // An incomplete page with nothing to resume from is a contradiction the wire shape
            // cannot forbid, and re-asking with the same cursor would spin forever against a node
            // that keeps saying it. Refuse it as an unbelievable answer rather than loop or
            // truncate.
            let Some(cursor) = page.cursor else {
                return Err(ChainReadError::malformed(
                    method::COINS_BY_PARENT,
                    "the node reported an incomplete page with no cursor to resume from",
                ));
            };
            if after_coin_id.as_deref() == Some(cursor.as_str()) {
                return Err(ChainReadError::malformed(
                    method::COINS_BY_PARENT,
                    format!(
                        "the node handed back the same cursor twice ({cursor}), so the walk \
                             cannot advance"
                    ),
                ));
            }
            after_coin_id = Some(cursor);
        }

        // The bound was reached with the node still claiming more. What was collected is a PREFIX,
        // and a prefix returned as a child set is the fail-open this bound exists to make
        // impossible. The honest answer is that the child set is unknown.
        Err(ChainReadError::transport(
            method::COINS_BY_PARENT,
            format!(
                "the node was still reporting more children after {MAX_CHILD_PAGES} pages of \
                 {CHILD_PAGE_SIZE}, so the child set of that coin could not be established"
            ),
        ))
    }

    fn coin_spend(&self, coin_id: Bytes32) -> Result<Option<CoinSpend>, Self::Error> {
        let answer = self.read(
            method::COIN_SPEND,
            &WalletCoinSpendParams {
                coin_id: hex::encode(coin_id),
            },
        )?;
        let freshness = Freshness {
            source: answer.source,
            synced: answer.synced,
            peak_height: answer.peak_height,
        };
        let Some(spend) = answer.spend else {
            // An absence IS a believed answer here, so it carries freshness like any other.
            self.note_freshness(freshness);
            return Ok(None);
        };
        // The contract requires a spend's coin to carry a spent height — a spend reporting an
        // unspent coin is a contradiction — so a reply that breaks it is refused rather than read
        // past. Believing it would mean walking a lineage through a spend that may not exist.
        if spend.coin.spent_height.is_none() {
            return Err(ChainReadError::malformed(
                method::COIN_SPEND,
                "the node returned a spend whose coin reports no spent height",
            ));
        }
        let decoded = CoinSpend::new(
            coin_from(method::COIN_SPEND, &spend.coin)?,
            program_from(method::COIN_SPEND, "puzzle_reveal", &spend.puzzle_reveal)?,
            program_from(method::COIN_SPEND, "solution", &spend.solution)?,
        );
        self.note_freshness(freshness);
        Ok(Some(decoded))
    }

    /// Delegates to the ecosystem's ONE hardened singleton walk (dig_ecosystem#2572).
    ///
    /// An authenticated launcher-to-tip walk is the most money-critical read in the trait: a coin's
    /// puzzle hash is attacker-chosen, so lineage membership may only be established by walking real
    /// recreation spends, and a walk that gets this subtly wrong authenticates a forgery.
    /// `dig_chainsource_interface::walk_singleton_lineage` is that walk, built once and hardened
    /// over four rounds of security review. **Never hand-roll it here.**
    ///
    /// # Why the PLAIN variant, and not `_bounded` or `_within`
    ///
    /// All three exist; the plain one is the only correct choice for a provider. Its default
    /// [`WalkBounds`](dig_chainsource_interface::WalkBounds) already carry BOTH denial-of-
    /// service guards — the canonical `MAX_LINEAGE_DEPTH` hop cap and the `DEFAULT_WALK_BUDGET`
    /// wall-clock budget — and the crate's own documentation says a one-line delegation is how a
    /// provider INHERITS them rather than having to remember them. The other two exist so a test can
    /// exercise a guard over a short chain with a tiny value.
    ///
    /// Passing bounds of my own would either narrow the ecosystem's shared bound on a guess, or
    /// attempt to widen it — and `WalkBounds::hops` clamps to `MAX_LINEAGE_DEPTH`, so widening is not
    /// even expressible. Inheriting the shared numbers is the whole point: an unbounded walk against
    /// a hostile or very long lineage is a liveness problem, and these two bounds are the ecosystem's
    /// agreed answer to it.
    ///
    /// This is not recursive. The walk reads `coin_record`, `coin_spend` and `coin_records_by_parent`
    /// only; it never calls back into this method.
    ///
    /// # Every failure stays a failure
    ///
    /// `Ok(None)` is returned ONLY for the walk's own genuine absences — no such launcher, not a
    /// launcher coin, never spent, or fully melted. All six `LineageWalkError` variants become an
    /// `Err`, because on a mint path *the lineage ends here* reads as **safe to spend**. The mapping
    /// preserves the crate's own remedy taxonomy rather than flattening it.
    fn resolve_singleton_lineage(
        &self,
        launcher_id: Bytes32,
    ) -> Result<Option<SingletonLineage>, Self::Error> {
        walk_singleton_lineage(self, launcher_id).map_err(walk_failure)
    }

    fn peak_height(&self) -> Result<Option<u32>, Self::Error> {
        let answer = self.read(method::PEAK, &WalletPeakParams {})?;
        self.note_freshness(Freshness {
            source: None,
            synced: answer.synced,
            peak_height: answer.peak_height,
        });
        Ok(answer.peak_height)
    }

    /// # Always `Ok(None)`, and that is an honest answer rather than a stub
    ///
    /// The control plane exposes no height-to-timestamp read, so this source genuinely does not
    /// resolve timestamps — which is exactly what `Ok(None)` means on this method ("no such block
    /// or no timestamp index"), not "the read failed". chia-peer's provider answers the same way
    /// for the same reason: a light client sees coin states, not block records.
    ///
    /// Nothing on the mint path calls it (checked across dig-account, dig-did, dig-store,
    /// dig-capsule and dig-social-profile), so this costs no capability today.
    fn block_timestamp(&self, _height: u32) -> Result<Option<u64>, Self::Error> {
        Ok(None)
    }
}

/// The trait method name a lineage failure is reported under.
///
/// Not a `control.*` method: the walk is composed from four of them, so naming any single one would
/// point a diagnosis at the wrong read.
const LINEAGE_WALK: &str = "resolve_singleton_lineage";

/// Project a [`LineageWalkError`] onto this client's error, PRESERVING the remedy.
///
/// Every arm produces an `Err`. That is the whole contract: on a mint path an `Ok(None)` means *this
/// singleton does not exist*, which reads as safe to spend, so a walk that could not complete must
/// never become one.
///
/// The mapping mirrors `dig-chainsource-interface`'s own projection rather than inventing a second
/// judgement of which failure means what — including the two places that judgement is counter-
/// intuitive:
///
/// - a [`Source`](LineageWalkError::Source) failure passes through **unmodified**, so an
///   `Unsupported` node stays distinguishable from bad data. Flattening it would erase exactly the
///   distinction the fail-closed contract depends on.
/// - a deadline overrun is a [`Transport`](ChainReadError::Transport), not a `Malformed`: nothing
///   about the chain was necessarily wrong, the walk merely ran out of time, and the remedy is to
///   retry. Calling it malformed accuses an honest node of lying for the crime of being slow.
pub(super) fn walk_failure(error: LineageWalkError<ChainReadError>) -> ChainReadError {
    match error {
        // Already classified by the read that failed; re-wrapping it would only blur it.
        LineageWalkError::Source(inner) => inner,
        LineageWalkError::Malformed(detail) => ChainReadError::malformed(LINEAGE_WALK, detail),
        LineageWalkError::NotASingleton { coin_id } => ChainReadError::malformed(
            LINEAGE_WALK,
            format!("coin {coin_id} is not a genuine singleton of this launcher"),
        ),
        // Size, not corruption — see [`ChainReadError::Unusable`].
        LineageWalkError::RevealTooLarge { coin_id, limit } => ChainReadError::unusable(
            LINEAGE_WALK,
            format!("the puzzle reveal of coin {coin_id} expands beyond the {limit}-byte bound"),
        ),
        // Depth, not corruption, and deterministic — so it is not a retry either.
        LineageWalkError::TooDeep { limit } => ChainReadError::unusable(
            LINEAGE_WALK,
            format!("this singleton's lineage is longer than the {limit}-hop bound DIG will walk"),
        ),
        LineageWalkError::DeadlineExceeded { budget } => ChainReadError::transport(
            LINEAGE_WALK,
            format!("the lineage walk outlasted its {budget:?} budget"),
        ),
        // `LineageWalkError` is `#[non_exhaustive]`, so the walk may grow a failure this build has
        // never heard of. That is precisely a case for failing CLOSED: an unrecognised failure is
        // still a failure, and the one thing it may never become is `Ok(None)`.
        //
        // `Unsupported` — remedy *upgrade* — is the honest arm, because a variant this code cannot
        // name means the walk knows something this code does not. Its own `Display` is carried
        // verbatim so a diagnosis is not lost to the wildcard.
        other => ChainReadError::unsupported(
            LINEAGE_WALK,
            format!(
                "the lineage walk failed in a way this version of DIG does not recognise \
                 ({other}) — upgrade dig-app"
            ),
        ),
    }
}

/// One wire record as the canonical [`CoinRecord`].
fn coin_record_from(
    method: &'static str,
    record: &WalletCoinRecord,
) -> Result<CoinRecord, ChainReadError> {
    Ok(CoinRecord {
        coin: coin_from(method, record)?,
        confirmed_height: record.created_height,
        spent_height: record.spent_height,
        // The control plane carries no block timestamp and no coinbase flag on any wallet read.
        // `None`/`false` are the record's documented "not known by this source" values, so this
        // asserts nothing the read did not establish.
        timestamp: None,
        coinbase: false,
    })
}

/// The `Coin` a wire record describes: parent, puzzle hash, amount.
fn coin_from(method: &'static str, record: &WalletCoinRecord) -> Result<Coin, ChainReadError> {
    Ok(Coin::new(
        bytes32_from(method, "parent_coin_info", &record.parent_coin_info)?,
        bytes32_from(method, "puzzle_hash", &record.puzzle_hash)?,
        record.amount,
    ))
}

/// A 32-byte field from its lowercase-hex wire form.
///
/// A `0x` prefix is tolerated on the way IN because the contract tolerates one on its own
/// parameters and a block explorer prints them; the length check then applies to the real digits.
fn bytes32_from(
    method: &'static str,
    field: &'static str,
    hex_text: &str,
) -> Result<Bytes32, ChainReadError> {
    let digits = hex_text.strip_prefix("0x").unwrap_or(hex_text);
    let bytes: [u8; 32] = hex::decode(digits)
        .ok()
        .and_then(|b| <[u8; 32]>::try_from(b.as_slice()).ok())
        .ok_or_else(|| {
            ChainReadError::malformed(
                method,
                format!("{field} is not 32 bytes of hex: {hex_text:?}"),
            )
        })?;
    Ok(Bytes32::new(bytes))
}

/// A serialized CLVM program from its lowercase-hex wire form.
fn program_from(
    method: &'static str,
    field: &'static str,
    hex_text: &str,
) -> Result<Program, ChainReadError> {
    let digits = hex_text.strip_prefix("0x").unwrap_or(hex_text);
    hex::decode(digits)
        .map(Program::from)
        .map_err(|e| ChainReadError::malformed(method, format!("{field} is not hex: {e}")))
}
