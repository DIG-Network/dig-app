//! Open ONE content pane, at a chosen tab, size and theme, so it can be photographed.
//!
//! # Why this exists beside `shell_gallery`
//!
//! The shell gallery opens the real window, which opens on `Status`; reaching any other tab means
//! clicking a chip. A committed screenshot must not be taken after synthetic input
//! (dig_ecosystem#2309 records what that costs — the click stole foreground and the capture was of
//! the window behind), so photographing the Apps or Settings tab needed a way to open ON that tab.
//!
//! This is that way. It draws the same pane the shell draws, from the same model and facts, with the
//! tab as a parameter instead of as state.
//!
//! ```text
//! cargo run -p dig-app-core --example pane_preview -- settings light 960 640
//! cargo run -p dig-app-core --example pane_preview -- wallet light 960 900 live healthy 1 machine
//! cargo run -p dig-app-core --example pane_preview -- wallet light 960 900 live healthy 1 machine-funded
//! cargo run -p dig-app-core --example pane_preview -- apps dark 480 480
//! cargo run -p dig-app-core --example pane_preview -- settings light 960 900 margin-priced
//! cargo run -p dig-app-core --example pane_preview -- settings light 960 900 margin-no-requirement
//! cargo run -p dig-app-core --example pane_preview -- settings light 960 900 margin-unread
//! cargo run -p dig-app-core --example pane_preview -- settings light 960 900 funding-short-now
//! cargo run -p dig-app-core --example pane_preview -- settings light 960 900 funding-dangerously-low
//! cargo run -p dig-app-core --example pane_preview -- settings light 960 900 funding-below-buffer
//! cargo run -p dig-app-core --example pane_preview -- settings light 960 900 funding-pending
//! cargo run -p dig-app-core --example pane_preview -- settings light 960 900 funding-node-cannot-say
//! ```
//!
//! Sizes are LOGICAL pixels; the display's scaling is applied by the windowing system, so a capture
//! on a 2.5× display is 2.5× larger and must be labelled with both figures.
//!
//! This example only ever DRAWS. A click is read and discarded — a verb dispatched from a gallery
//! would run against the machine it is previewing on.

#[path = "shared/offer.rs"]
mod shared_offer;

use std::sync::Arc;

use dig_app_core::cache::{CacheSnapshot, GIB, MIB};
use dig_app_core::confirm::gui::{
    open_pane_preview, preview_theme, CollateralPreview, PreviewSeeds,
};
use dig_app_core::profile_edit::{
    BodyRead, BodyStore, BodyStoreError, CommitOutcome, EditSeams, EditService, PendingBodies,
    PendingBody, PendingError, ProfileEditError, ProfileEditSeam, ProfileEditing, ProfileField,
    ProfileSnapshot, SlotChange,
};
use dig_app_core::profiles::{ProfileRow, ProfilesReading, RootReading};
use dig_app_core::transaction::Feed;
use dig_app_core::tray_menu::{AccountState, TrayView, WindowHost};
use dig_app_core::window_model::TabId;

/// The view every pane is photographed against: the richest state, so nothing reads as empty by
/// accident.
///
/// The beacon is deliberately present and HEALTHY here; the other beacon states are photographed by
/// the `--beacon` argument below, because "what this looks like when the updater cannot be asked" is
/// exactly the picture worth having.
fn preview_view(beacon: Beacon) -> TrayView {
    TrayView {
        running: true,
        node_connected: true,
        node: "Node v0.65.0 · 3 capsule(s) cached · 1 store(s) hosted".to_string(),
        account: Some(AccountState::Unlocked { recoverable: true }),
        receive_address: Some(
            "xch1up0vfatgtwrcgcvc360jd57t3p2kjskncutvzakh9mhdmlvejj3shn8wln".to_string(),
        ),
        second_factor: true,
        window_host: WindowHost::Available,
        cache: Some(CacheSnapshot {
            cap_bytes: GIB,
            used_bytes: 350 * MIB,
        }),
        update: beacon.status(),
        // STATED rather than defaulted: `ProfileCreation::default()` is `Unknown` — *nobody has
        // asked the node yet* (dig_ecosystem#2690) — while the shipped binary answers this from a
        // constant and renders the unreachable-chain sentence. On the default this capture would
        // show a *still checking* card no build a user runs can produce.
        profile_creation: dig_app_core::profiles::ProfileCreation::of(
            dig_app_core::account::chain_mint::MintAvailability::NoChainTransport,
        ),
        // A fixture takes no reading (dig_ecosystem#2398).
        mint_chain: None,
        ..TrayView::default()
    }
}

/// The root from the machine this defect was measured on, so a capture shows a real one.
const LOST_ROOT: &str = "371a39b04742cd4d4b45bdf61a99f3838b700587fad093330dddb4766feba454";

/// The store that root belongs to, in the `0x…` form the card prints.
const STORE_ID: &str = "0x111eb8bce53a9b46bedc6a8883b50b6e503ee333384930e93ef3054b25e992be";

/// The DID that store is anchored to.
const DID: &str = "did:chia:1mhdr5h6pyzqerp6h3cdkqjl24he8aatja24rz68chl7c9lqlluaspqwc6r";

/// One listed profile, before anything has read it from the chain.
///
/// The identifiers are the ones from the report this row was built for (dig-app#212), so a capture
/// shows the three values side by side at the lengths a person actually sees them.
fn listed_profile() -> ProfilesReading {
    ProfilesReading::Known(vec![ProfileRow {
        ix: dig_account::ProfileIx::ROOT,
        did: DID.to_string(),
        store_id: STORE_ID.to_string(),
        label: None,
        hidden: false,
        active: true,
        root: RootReading::Pending,
    }])
}

/// Install an editor whose profile READ fails the way an unrecoverable body fails.
///
/// # Why a seam and not a fabricated reading
///
/// The card asks the process-wide [`EditService`] for its reading, and the reading is DERIVED from
/// what the seam answers. Installing a `BodyLost` reading directly would photograph a value this
/// example made up; installing a seam that fails the way the user's node fails photographs the value
/// the app computes. The difference matters exactly here, because the defect being captured was the
/// app computing the right value and drawing the wrong thing.
///
/// It reads and commits nothing: there is no chain, no node and no key behind it.
fn install_a_profile_whose_content_is_gone() {
    struct ContentIsGone;

    impl ProfileEditSeam for ContentIsGone {
        /// Never routed here: this double stands for a DELTA edit, and a fresh publish
        /// replaces the whole profile. Refusing rather than delegating means a test that
        /// took the wrong route fails instead of quietly passing on the other one.
        fn publish_fresh(
            &self,
            _: &[(ProfileField, SlotChange)],
        ) -> Result<CommitOutcome, ProfileEditError> {
            Err(ProfileEditError::Refused(
                "this double publishes deltas only".into(),
            ))
        }
        fn store_id(&self) -> String {
            "111e8bce53a9b46bedc6a8883b50b6e503ee333384930e93ef3054b25e992be0".to_string()
        }
        fn read(&self) -> Result<ProfileSnapshot, ProfileEditError> {
            Err(ProfileEditError::BodyLost {
                root: LOST_ROOT.to_string(),
            })
        }
        fn commit(
            &self,
            _: &[(ProfileField, SlotChange)],
        ) -> Result<CommitOutcome, ProfileEditError> {
            // A preview never spends. Reaching here means somebody pressed publish while
            // photographing, and the honest answer is the one the shipped build gives today.
            Err(ProfileEditError::BodyLost {
                root: LOST_ROOT.to_string(),
            })
        }
        fn confirmation(&self, _: &str) -> Result<Option<u32>, ProfileEditError> {
            Ok(None)
        }
    }

    /// Never reached: the read fails first, so nothing is ever stored or read back.
    struct NoBodies;
    impl BodyStore for NoBodies {
        fn put(&self, _: &str, _: &str, _: &[u8]) -> Result<(), BodyStoreError> {
            Ok(())
        }
        fn get(&self, _: &str, _: &str) -> Result<BodyRead, BodyStoreError> {
            Ok(BodyRead::Nothing)
        }
    }

    /// Likewise: a preview writes nothing to this machine.
    struct NoPending;
    impl PendingBodies for NoPending {
        fn remember(&self, _: &PendingBody) -> Result<(), PendingError> {
            Ok(())
        }
        fn forget(&self, _: &str, _: &str) -> Result<(), PendingError> {
            Ok(())
        }
        fn all(&self) -> Result<Vec<PendingBody>, PendingError> {
            Ok(Vec::new())
        }
    }

    EditService::install(Arc::new(EditService::new(
        EditSeams::Wired {
            seam: Arc::new(ContentIsGone),
            bodies: Arc::new(NoBodies),
            pending: Arc::new(NoPending),
        },
        Feed::app(),
    )));
}

/// Which beacon state to photograph.
#[derive(Clone, Copy)]
enum Beacon {
    /// Updates running, on the stable feed.
    Live,
    /// The daily schedule was removed: updates are OFF even though nothing is paused.
    OptedOut,
    /// The updater could not be asked at all — the state where the controls must disappear.
    Absent,
}

impl Beacon {
    fn status(self) -> Option<dig_app_core::auto_update::BeaconStatus> {
        use dig_app_core::auto_update::{BeaconStatus, UpdateChannel};
        match self {
            Self::Live => Some(BeaconStatus {
                paused: false,
                schedule_opted_out: false,
                channel: UpdateChannel::Stable,
            }),
            Self::OptedOut => Some(BeaconStatus {
                paused: false,
                schedule_opted_out: true,
                channel: UpdateChannel::Nightly,
            }),
            Self::Absent => None,
        }
    }

    fn parse(name: &str) -> Option<Self> {
        match name {
            "live" => Some(Self::Live),
            "opted-out" => Some(Self::OptedOut),
            "absent" => Some(Self::Absent),
            _ => None,
        }
    }
}

/// Every tab the preview can open, by the name given on the command line — its label, lowercased.
///
/// Derived from [`TabId::all`] rather than listed, so this cannot come to disagree with the window
/// about which tabs exist. The hand-written version still accepted `status`, `security`, `apps` and
/// `cache` after those tabs were merged away (dig_ecosystem#2358), which is how a capture lands
/// under a name that describes a picture nobody can take.
fn tab(name: &str) -> Option<TabId> {
    TabId::all()
        .into_iter()
        .find(|tab| format!("{tab:?}").to_lowercase() == name)
}

/// A departure from the healthy view, for the states worth photographing.
///
/// The beacon argument above varies the UPDATER; this varies the machine the pane is reporting on.
/// Both are parameters for the same reason: a state a capture cannot be opened directly into is a
/// state somebody eventually reaches by clicking, and a committed screenshot must not depend on a
/// click landing (dig_ecosystem#2309).
#[derive(Clone, Copy)]
enum Case {
    /// Node up, account unlocked, balance read: the state the whole-pane captures use.
    Healthy,
    /// A balance read in flight — on screen for the seconds a chain lookup takes.
    BalancePending,
    /// A node that connected and did not answer in time. Deliberately not "no node is running":
    /// that is the wrong sentence a live user was shown (dig_ecosystem#2325).
    BalanceTimedOut,
    /// A sealed account: no address to derive, so no code and no figure.
    Locked,
    /// Nothing answered the §5.3 ladder, so no cache snapshot and no balance.
    NoNode,
    /// A profile whose content is anchored on chain and is not on this computer (dig_ecosystem#3041).
    ///
    /// The state a person is actually stuck in, and the one worth photographing: the card must say
    /// the details are not here AND draw the form to type them in again, with no sentence anywhere under
    /// it claiming nothing has gone wrong. Two separate defects on this card rendered correctly at
    /// the model and wrongly on screen, so it gets a capture of its own.
    ProfileBodyLost,
    /// A profile listed before any chain read has answered for it (dig-app#212).
    ///
    /// The state EVERY row is in on the first frame, and the one a wrong implementation renders as a
    /// blank identifier or a zero hash. Worth its own capture because the failure it guards against
    /// looks like a working card in every other respect.
    ProfileRootUnread,
}

impl Case {
    /// Apply this case to the healthy view.
    fn apply(self, view: TrayView) -> TrayView {
        use dig_app_core::wallet::overview::{BalanceReading, BalanceUnknown};
        match self {
            Self::Healthy => TrayView {
                balance: BalanceReading::Known {
                    balances: held(),
                    as_of: dig_app_core::wallet::engine::BalanceAsOf::Replica {
                        height: 7_000_000,
                        caught_up: true,
                    },
                },
                ..view
            },
            Self::BalancePending => TrayView {
                balance: BalanceReading::Pending,
                ..view
            },
            Self::BalanceTimedOut => TrayView {
                balance: BalanceReading::Unknown(BalanceUnknown::NodeTimedOut),
                ..view
            },
            Self::Locked => TrayView {
                account: Some(AccountState::Locked),
                receive_address: None,
                ..view
            },
            Self::NoNode => TrayView {
                running: false,
                node_connected: false,
                node: "No DIG node answered on this computer".to_string(),
                cache: None,
                ..view
            },
            Self::ProfileBodyLost => {
                install_a_profile_whose_content_is_gone();
                TrayView {
                    profile_editing: ProfileEditing::Possible,
                    // The root is DERIVED from the same failure the seam above returns, through the
                    // same function the app calls, so the capture shows the value production
                    // computes rather than a string this example typed out.
                    profiles: listed_profile().with_active_root(RootReading::of_read(Err(
                        &ProfileEditError::BodyLost {
                            root: LOST_ROOT.to_string(),
                        },
                    ))),
                    ..view
                }
            }
            Self::ProfileRootUnread => TrayView {
                profiles: listed_profile(),
                ..view
            },
        }
    }

    fn parse(name: &str) -> Option<Self> {
        match name {
            "healthy" => Some(Self::Healthy),
            "pending" => Some(Self::BalancePending),
            "timedout" => Some(Self::BalanceTimedOut),
            "locked" => Some(Self::Locked),
            "no-node" => Some(Self::NoNode),
            "body-lost" => Some(Self::ProfileBodyLost),
            "root-unread" => Some(Self::ProfileRootUnread),
            _ => None,
        }
    }
}

/// The balance the healthy captures show: 12.5 $DIG and 0.25 XCH, in each asset's own base unit.
///
/// Written in base units rather than as decimals, because that is what the type holds and what the
/// pane's one formatter divides — a preview that pre-divided would photograph a figure the
/// application does not produce.
fn held() -> dig_app_core::wallet::overview::Balances {
    use dig_app_core::wallet::overview::Holding;
    use dig_app_core::wallet::state::{Asset, AssetId};

    let mut balances =
        dig_app_core::wallet::overview::Balances::of_xch_and_dig(250_000_000_000, 12_500);
    // A THIRD token, and one this app knows nothing about but its id — so the capture shows the row
    // an unfamiliar CAT actually produces: labelled by its shortened id, and stated in BASE UNITS
    // rather than as a whole-coin figure nobody measured (dig_ecosystem#3077). A preview holding
    // only the two known assets would photograph the one case that was never in doubt.
    balances.holdings.push(Holding {
        asset: Asset::Cat(
            AssetId::from_hex("a628c1c2c6fcb74d53746157e438e108eab5c0bb3e5c80ff9b1910b3e4832913")
                .expect("a 64-hex asset id"),
        ),
        base_units: 4_200,
    });
    balances
}

/// Seed the coin listing the Coins card reads, so the table can be PHOTOGRAPHED rather than
/// described (dig_ecosystem#334).
///
/// Held process-wide for the same reason the activity log is, so a preview that does not seed it
/// draws the card's Pending sentence — an honest state, and not the one the table lives in.
///
/// The fixture varies one field at a time across the four rows, because a capture of four identical
/// coins cannot show that the columns hold DIFFERENT facts: a confirmed free coin, a held one, one
/// whose hold status was never read, and one still in the mempool. Those are exactly the four cells
/// whose renderings must not collapse into each other.
///
/// The XCH section is then filled to the full `VISIBLE_STEP` of ten, because the card's layout
/// budget is a claim about TEN rows under the new heading line and a four-row fixture could only
/// support it by extrapolation from a measured row pitch. The eight filler coins carry no case of
/// their own; they exist so the budget is photographed rather than predicted.
fn seed_coins() {
    use dig_app_core::wallet::coin_list::{
        CoinListing, CoinsReading, ListedCoin, Reservation, WalkEnd,
    };
    use dig_app_core::wallet::state::Asset;

    let coin = |coin_id: &str, asset, amount, confirmed_height, reservation| ListedCoin {
        coin_id: coin_id.to_owned(),
        asset,
        amount,
        confirmed_height,
        reservation,
    };
    dig_app_core::wallet::coin_list::remember(CoinListing {
        xch: CoinsReading::Known {
            coins: vec![
                coin(
                    &"9f2c".repeat(16),
                    Asset::Xch,
                    2_500_000_000_000,
                    Some(5_400_096),
                    Reservation::Free,
                ),
                coin(
                    &"1ab4".repeat(16),
                    Asset::Xch,
                    750_000_000_000,
                    Some(5_400_112),
                    Reservation::Held,
                ),
                // Eight ordinary coins after the four varied ones, filling the section to the
                // full `VISIBLE_STEP`. They carry no case of their own -- their whole job is to let
                // the LAYOUT claim be photographed rather than predicted: ten rows, each two lines,
                // under the new heading line, in a 480 px window.
                coin(
                    &"2d81".repeat(16),
                    Asset::Xch,
                    125_000_000_000,
                    Some(5_400_128),
                    Reservation::Free,
                ),
                coin(
                    &"3e92".repeat(16),
                    Asset::Xch,
                    250_000_000_000,
                    Some(5_400_135),
                    Reservation::Free,
                ),
                coin(
                    &"4fa3".repeat(16),
                    Asset::Xch,
                    375_000_000_000,
                    Some(5_400_142),
                    Reservation::Free,
                ),
                coin(
                    &"50b4".repeat(16),
                    Asset::Xch,
                    500_000_000_000,
                    Some(5_400_149),
                    Reservation::Free,
                ),
                coin(
                    &"61c5".repeat(16),
                    Asset::Xch,
                    625_000_000_000,
                    Some(5_400_156),
                    Reservation::Free,
                ),
                coin(
                    &"72d6".repeat(16),
                    Asset::Xch,
                    750_000_000_000,
                    Some(5_400_163),
                    Reservation::Free,
                ),
                coin(
                    &"83e7".repeat(16),
                    Asset::Xch,
                    875_000_000_000,
                    Some(5_400_170),
                    Reservation::Free,
                ),
                coin(
                    &"94f8".repeat(16),
                    Asset::Xch,
                    1_000_000_000_000,
                    Some(5_400_177),
                    Reservation::Free,
                ),
            ],
            end: WalkEnd::Complete,
        },
        dig: CoinsReading::Known {
            coins: vec![
                coin(
                    &"c0ff".repeat(16),
                    Asset::DIG,
                    12_500,
                    Some(5_400_130),
                    Reservation::Unknown,
                ),
                coin(
                    &"7e3d".repeat(16),
                    Asset::DIG,
                    1_234,
                    None,
                    Reservation::Free,
                ),
            ],
            end: WalkEnd::Unpaged,
        },
    });
}

/// Put a plausible two-way activity list in front of the Wallet tab's Activity card.
///
/// The card reads a PROCESS-WIDE log rather than the tray view, because its two writers (the arrival
/// sweep and the send path) run on their own threads — so seeding it is how this gallery photographs
/// it populated, in the same spirit as the rich `preview_view` above.
///
/// The fixture deliberately mixes the two directions and two assets, because the picture worth
/// having is the one where an arrival cites a height and a send does not: that asymmetry is the
/// feature, and a capture of one direction alone cannot show it.
fn seed_activity() {
    use dig_app_core::arrivals::Arrival;
    use dig_app_core::wallet::activity;
    use dig_app_core::wallet::state::{Asset, SpendRecord};

    activity::remember_arrivals(&[
        Arrival {
            seq: 41,
            coin_id: "9f2c".repeat(16),
            asset_id: None,
            amount: 2_500_000_000_000,
            confirmed_height: 5_400_096,
        },
        Arrival {
            seq: 42,
            coin_id: "1ab4".repeat(16),
            asset_id: Some(dig_app_core::notify::dig_asset_id()),
            amount: 12_500,
            confirmed_height: 5_400_112,
        },
    ]);
    activity::remember_spend(SpendRecord {
        recipient: "xch1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq".into(),
        asset: Asset::Xch,
        amount: 750_000_000_000,
        broadcast_at: 1_770_000_000,
        transaction_id: "c0ffee".repeat(10),
    });
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let usage = "usage: pane_preview <tab> <light|dark> [width] [height] [live|opted-out|absent] \
                 [healthy|pending|timedout|locked|no-node|body-lost|root-unread] [zoom]";

    let Some(tab) = args.first().and_then(|name| tab(name)) else {
        eprintln!("{usage}");
        std::process::exit(2);
    };
    let Some(theme) = args.get(1).map(String::as_str).and_then(preview_theme) else {
        eprintln!("{usage}");
        std::process::exit(2);
    };
    let size = (
        args.get(2).and_then(|w| w.parse().ok()).unwrap_or(960.0),
        args.get(3).and_then(|h| h.parse().ok()).unwrap_or(640.0),
    );
    let Some(beacon) = Beacon::parse(args.get(4).map(String::as_str).unwrap_or("live")) else {
        eprintln!("{usage}");
        std::process::exit(2);
    };

    let Some(case) = Case::parse(args.get(5).map(String::as_str).unwrap_or("healthy")) else {
        eprintln!("{usage}");
        std::process::exit(2);
    };

    // A pane taller than the display is clamped by the window manager, not by the size asked for,
    // so a whole-pane capture of a long pane needs this rather than a bigger number.
    let zoom: f32 = args.get(6).and_then(|z| z.parse().ok()).unwrap_or(1.0);

    seed_activity();
    seed_coins();

    // A REAL offer, built by the canonical crate rather than pasted as a literal, so the picture is
    // of what `dig_offers::summarize` actually reports today. Passing `offer` on the command line
    // seeds the Wallet tab's field before the first frame — the honest way to photograph a filled
    // card, since a committed screenshot must never be taken after synthetic input.
    let offer = args
        .iter()
        .any(|arg| arg == "offer")
        .then(shared_offer::gallery_offer);

    // Which collateral answers the Settings funding and margin cards are drawn from. Named on the
    // command line rather than left to whatever node happens to run on this machine: a picture of
    // the unknown state taken because no node was running proves only that no node was running.
    let collateral = args.iter().find_map(|arg| match arg.as_str() {
        "margin-priced" => Some(CollateralPreview::Priced),
        "margin-no-requirement" => Some(CollateralPreview::MarginWithoutRequirement),
        "margin-unread" => Some(CollateralPreview::Unread),
        "funding-short-now" => Some(CollateralPreview::FundingShortNow),
        "funding-dangerously-low" => Some(CollateralPreview::FundingDangerouslyLow),
        "funding-below-buffer" => Some(CollateralPreview::FundingBelowBuffer),
        "funding-pending" => Some(CollateralPreview::FundingPending),
        "funding-node-cannot-say" => Some(CollateralPreview::FundingNodeCannotSay),
        _ => None,
    });

    // Which machine wallet the Wallet tab is drawn from. `machine` is the state
    // every node is in today — no control method publishes the operator address — and
    // `machine-funded` is the state adopting that method reaches, so both can be photographed
    // before either can be reached on a real host.
    // Which wallet the switcher opens on. A parameter rather than a click, so a capture of the
    // machine wallet is a capture of what the window draws for that selection.
    let wallet = match args.iter().any(|arg| arg.starts_with("machine")) {
        true => dig_app_core::window_model::SelectedWallet::Machine,
        false => dig_app_core::window_model::SelectedWallet::User,
    };

    let machine = args.iter().find_map(|arg| match arg.as_str() {
        "machine" => Some(dig_app_core::wallet::machine::MachineWalletReading::not_published()),
        "machine-funded" => Some(dig_app_core::wallet::machine::MachineWalletReading {
            address: dig_app_core::wallet::machine::MachineAddressReading::Known(
                "xch1q9m6l5vm0tsp0hqe3wrdzhqe6rqf3nrxs4tqz9v0dpk6lz0rr8jsq0v7xj".to_owned(),
            ),
            balance: dig_app_core::wallet::overview::BalanceReading::Known {
                balances: dig_app_core::wallet::overview::Balances::of_xch_and_dig(0, 0),
                as_of: dig_app_core::wallet::engine::BalanceAsOf::Undisclosed,
            },
            ..Default::default()
        }),
        _ => None,
    });

    println!("previewing {tab:?} at {size:?} logical px, zoom {zoom}; close the window when done");
    if let Err(why) = open_pane_preview(
        theme,
        tab,
        size,
        zoom,
        case.apply(preview_view(beacon)),
        wallet,
        PreviewSeeds {
            offer,
            collateral,
            machine,
        },
    ) {
        eprintln!("{why}");
        std::process::exit(1);
    }
}
