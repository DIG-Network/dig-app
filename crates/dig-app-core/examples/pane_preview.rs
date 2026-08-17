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
//! cargo run -p dig-app-core --example pane_preview -- apps dark 480 480
//! ```
//!
//! Sizes are LOGICAL pixels; the display's scaling is applied by the windowing system, so a capture
//! on a 2.5× display is 2.5× larger and must be labelled with both figures.
//!
//! This example only ever DRAWS. A click is read and discarded — a verb dispatched from a gallery
//! would run against the machine it is previewing on.

use std::sync::Arc;

use dig_app_core::cache::{CacheSnapshot, GIB, MIB};
use dig_app_core::confirm::gui::{open_pane_preview, preview_theme};
use dig_app_core::profile_edit::{
    BodyRead, BodyStore, BodyStoreError, CommitOutcome, EditSeams, EditService, PendingBodies,
    PendingBody, PendingError, ProfileEditError, ProfileEditSeam, ProfileEditing, ProfileField,
    ProfileSnapshot, SlotChange,
};
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
    /// The root from the machine this defect was measured on, so the capture shows a real one.
    const LOST_ROOT: &str = "371a39b04742cd4d4b45bdf61a99f3838b700587fad093330dddb4766feba454";

    struct ContentIsGone;

    impl ProfileEditSeam for ContentIsGone {
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
    /// A profile whose content is anchored on chain and exists nowhere (dig_ecosystem#3041).
    ///
    /// The state a person is actually stuck in, and the one worth photographing: the card must say
    /// the details are gone AND draw the form to type them in again, with no sentence anywhere under
    /// it claiming nothing has gone wrong. Two separate defects on this card rendered correctly at
    /// the model and wrongly on screen, so it gets a capture of its own.
    ProfileBodyLost,
}

impl Case {
    /// Apply this case to the healthy view.
    fn apply(self, view: TrayView) -> TrayView {
        use dig_app_core::wallet::overview::{BalanceReading, BalanceUnknown};
        match self {
            Self::Healthy => TrayView {
                balance: BalanceReading::Known {
                    balances: HELD,
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
                    ..view
                }
            }
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
            _ => None,
        }
    }
}

/// The balance the healthy captures show: 12.5 $DIG and 0.25 XCH, in each asset's own base unit.
///
/// Written in base units rather than as decimals, because that is what the type holds and what the
/// pane's one formatter divides — a preview that pre-divided would photograph a figure the
/// application does not produce.
const HELD: dig_app_core::wallet::overview::Balances = dig_app_core::wallet::overview::Balances {
    dig_units: 12_500,
    xch_mojos: 250_000_000_000,
};

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
                 [healthy|pending|timedout|locked|no-node|body-lost] [zoom]";

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

    // A REAL offer, built by the canonical crate rather than pasted as a literal, so the picture is
    // of what `dig_offers::summarize` actually reports today. Passing `offer` on the command line
    // seeds the Wallet tab's field before the first frame — the honest way to photograph a filled
    // card, since a committed screenshot must never be taken after synthetic input.
    let offer = args.iter().any(|arg| arg == "offer").then(preview_offer);

    println!("previewing {tab:?} at {size:?} logical px, zoom {zoom}; close the window when done");
    if let Err(why) = open_pane_preview(
        theme,
        tab,
        size,
        zoom,
        case.apply(preview_view(beacon)),
        offer,
    ) {
        eprintln!("{why}");
        std::process::exit(1);
    }
}

/// A real `offer1…` string for the Wallet tab's offer card: 400 mojos offered for 1,000 requested,
/// so the two sides are visibly different rather than a symmetric pair that would look the same
/// under a swapped mapping.
///
/// Built here rather than imported from `wallet::offer_fixture`, which is `#[cfg(test)]` and reaches
/// for `chia-sdk-test`; an example cannot see a test-only module. The SHAPE is deliberately the same
/// as that fixture's so the picture and the tests describe one offer — if the two ever diverge, the
/// tested one is authoritative and this is what should move.
fn preview_offer() -> String {
    use chia_protocol::{Bytes32, Coin, SpendBundle};
    use chia_sdk_driver::SpendContext;
    use chia_sdk_test::BlsPair;
    use chia_wallet_sdk::prelude::Signature;
    use dig_offers::{OfferedSide, RequestedSide};

    let maker = BlsPair::new(1);
    let mut keys = indexmap::IndexMap::new();
    keys.insert(maker.puzzle_hash, maker.pk);
    let mut ctx = SpendContext::new();

    let unsigned = dig_offers::make_build(
        &mut ctx,
        OfferedSide {
            change_puzzle_hash: maker.puzzle_hash,
            owner_keys: keys,
            xch_coins: vec![Coin::new(
                Bytes32::new([0xA1; 32]),
                maker.puzzle_hash,
                1_500,
            )],
            cat_coins: Vec::new(),
            nfts: Vec::new(),
            offer_xch: 400,
            offer_cats: Vec::new(),
            _pd: std::marker::PhantomData,
        },
        RequestedSide {
            payee_puzzle_hash: maker.puzzle_hash,
            xch: 1_000,
            cats: Vec::new(),
            nfts: Vec::new(),
        },
        0,
    )
    .expect("the preview offer must build");

    dig_offers::make_assemble(
        &mut ctx,
        SpendBundle::new(unsigned.coin_spends, Signature::default()),
        unsigned.requested_payments,
        unsigned.requested_asset_info,
    )
    .expect("the preview offer must encode")
}
