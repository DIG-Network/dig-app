//! What the connected node says about ITSELF, distilled for a surface to render
//! (dig_ecosystem#2330).
//!
//! # Why this is a distillation and not `StatusResult` itself
//!
//! The node's own `control.status` snapshot ([`StatusResult`]) is rich, and the Status pane wants most
//! of it. Carrying it verbatim in [`TrayView`](crate::tray_menu::TrayView) would be two mistakes at
//! once:
//!
//! - **The repaint gate compares the view field by field on every tick.** Anything that moves every
//!   second makes the whole window redraw every second. `StatusResult::uptime_secs` is exactly that.
//! - **It would bind the repaint gate to a schema dig-app does not own.** A field added upstream would
//!   silently join the comparison, and a field renamed upstream would change what dig-app repaints on,
//!   with no decision taken here. The same argument
//!   [`BeaconStatus`](crate::auto_update::BeaconStatus) makes for its own subset.
//!
//! So the app names the facts it renders, converts once at the seam ([`NodeFacts::of_status`]), and
//! everything downstream reads a type this crate controls.
//!
//! # Uptime is bucketed to the minute, deliberately
//!
//! `uptime_secs` is the one field that changes on every single tick. Bucketed to whole minutes it
//! changes 60× less often, and nothing is lost: [`NodeFacts::uptime_phrase`] renders
//! `up 4 hours 47 minutes`, never `17257`, so the seconds were never going to reach a person's eyes.
//! `a_second_of_uptime_does_not_change_the_facts` pins that, and
//! `a_full_minute_of_uptime_does_change_the_facts` is its control — without the second test a
//! constant would pass the first.

use dig_node_control_interface::results::StatusResult;

/// Everything a surface renders about the connected node, as facts this crate owns.
///
/// Absent from a view means no node answered — never "a node with nothing to say". The reason a node
/// is absent is [`TrayView::node`](crate::tray_menu::TrayView::node)'s, which already carries the
/// engine's actionable diagnosis.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NodeFacts {
    /// The node binary's semantic version.
    pub version: String,
    /// The git commit it was built from, or `"unknown"` when the build did not record one.
    pub commit: String,
    /// The DIG read-protocol version the node speaks.
    pub protocol: String,
    /// The loopback `host:port` the node is bound to — the tier of the §5.3 ladder that answered.
    pub addr: String,
    /// The upstream DIG RPC the node proxies and syncs to.
    pub upstream: String,
    /// Process uptime in whole MINUTES. See the module docs for why this is not seconds.
    pub uptime_minutes: u64,
    /// Whether authenticated §21 whole-store sync is available on this node.
    pub sync_available: bool,
    /// Distinct stores with content CACHED — **not** every store this node holds.
    ///
    /// The node derives it from its cached capsules alone, so a store that is pinned with nothing
    /// cached yet is absent from this count while being present, by dig-node's `SPEC.md` §7.6 MUST,
    /// in `control.hostedStores.list`. On a real node those two numbers differ, which is why the
    /// surface reading this renders it as "Stores with cached content" rather than "Stores hosted"
    /// (dig_ecosystem#2397). Do not describe it as "stores held" — that phrasing is what put one
    /// number under a different one on the same screen.
    pub hosted_store_count: u64,
    /// Capsules currently in its content cache.
    pub cached_capsule_count: u64,
    /// Stores the operator has pinned.
    pub pinned_store_count: u64,
}

impl NodeFacts {
    /// Distil the node's own status snapshot into the facts a surface renders.
    pub fn of_status(status: &StatusResult) -> Self {
        Self {
            version: status.version.clone(),
            commit: status.commit.clone(),
            protocol: status.protocol.clone(),
            addr: status.addr.clone(),
            upstream: status.upstream.clone(),
            uptime_minutes: status.uptime_secs / SECONDS_PER_MINUTE,
            sync_available: status.sync.available,
            hosted_store_count: status.hosted_store_count,
            cached_capsule_count: status.cached_capsule_count,
            pinned_store_count: status.pinned_store_count,
        }
    }

    /// How long the node has been up, as a person would say it.
    ///
    /// The two most significant non-zero units and no more: `up 6 days 3 hours` rather than
    /// `up 6 days 3 hours 12 minutes`, because the third unit is noise at that scale and it is the
    /// unit that keeps changing. A node up for less than a minute says so rather than reporting
    /// `up 0 minutes`, which reads like a fault.
    pub fn uptime_phrase(&self) -> String {
        let days = self.uptime_minutes / MINUTES_PER_DAY;
        let hours = (self.uptime_minutes % MINUTES_PER_DAY) / MINUTES_PER_HOUR;
        let minutes = self.uptime_minutes % MINUTES_PER_HOUR;
        let parts = match (days, hours, minutes) {
            (0, 0, 0) => return "up less than a minute".to_string(),
            (0, 0, m) => vec![plural(m, "minute")],
            (0, h, m) => vec![plural(h, "hour"), plural(m, "minute")],
            (d, h, _) => vec![plural(d, "day"), plural(h, "hour")],
        };
        // A zero trailing unit is dropped rather than printed: "up 3 hours" beats "up 3 hours 0
        // minutes", which reads as a machine talking.
        let said: Vec<String> = parts.into_iter().flatten().collect();
        format!("up {}", said.join(" "))
    }
}

/// `n unit(s)`, or `None` when `n` is zero and the unit is therefore not worth saying.
fn plural(n: u64, unit: &str) -> Option<String> {
    match n {
        0 => None,
        1 => Some(format!("1 {unit}")),
        n => Some(format!("{n} {unit}s")),
    }
}

const SECONDS_PER_MINUTE: u64 = 60;
const MINUTES_PER_HOUR: u64 = 60;
const MINUTES_PER_DAY: u64 = 24 * MINUTES_PER_HOUR;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::node::fake_status_result;

    /// The fixture's status snapshot with `uptime_secs` replaced — the ONE actor varied, so a test
    /// below cannot pass because something else moved.
    fn status_up_for(uptime_secs: u64) -> StatusResult {
        StatusResult {
            uptime_secs,
            ..fake_status_result()
        }
    }

    /// **Every field the pane renders travels**, from the node's real wire shape through to the
    /// facts. Asserted against the fake node's own snapshot rather than a hand-built struct, so a
    /// field read from the wrong source fails here.
    #[test]
    fn the_facts_carry_what_the_node_actually_reported() {
        let status = fake_status_result();
        let facts = NodeFacts::of_status(&status);

        assert_eq!(facts.version, status.version);
        assert_eq!(facts.commit, status.commit);
        assert_eq!(facts.protocol, status.protocol);
        assert_eq!(facts.addr, status.addr);
        assert_eq!(facts.upstream, status.upstream);
        assert_eq!(facts.sync_available, status.sync.available);
        assert_eq!(facts.hosted_store_count, status.hosted_store_count);
        assert_eq!(facts.cached_capsule_count, status.cached_capsule_count);
        assert_eq!(facts.pinned_store_count, status.pinned_store_count);
        // The three counts differ in the fixture, so an implementation that read one and reused it
        // for the others cannot pass.
        assert_ne!(facts.hosted_store_count, facts.cached_capsule_count);
        assert_ne!(facts.hosted_store_count, facts.pinned_store_count);
    }

    /// **The repaint property.** A second of uptime must not change the facts, because the facts are
    /// compared on every tick and a value that moves every second repaints the whole window every
    /// second.
    ///
    /// The nearest wrong implementation carries `uptime_secs` through unchanged; this fixture is the
    /// only shape that can see it, because the two snapshots are identical in every other field.
    #[test]
    fn a_second_of_uptime_does_not_change_the_facts() {
        assert_eq!(
            NodeFacts::of_status(&status_up_for(4_200)),
            NodeFacts::of_status(&status_up_for(4_259)),
            "59 further seconds is still the same minute, so nothing a person reads has changed"
        );
    }

    /// The control for the test above: without it, a `uptime_minutes` hardcoded to `0` would pass.
    #[test]
    fn a_full_minute_of_uptime_does_change_the_facts() {
        assert_ne!(
            NodeFacts::of_status(&status_up_for(4_200)),
            NodeFacts::of_status(&status_up_for(4_260)),
            "a whole minute later is a different phrase, so the view must repaint"
        );
    }

    /// The phrase is what a person reads, and it never contains a raw second count.
    #[test]
    fn uptime_reads_as_a_sentence_and_never_as_a_second_count() {
        // 4 h 47 m — the example the ticket names, in seconds, so the arithmetic is pinned end to end.
        let facts = NodeFacts::of_status(&status_up_for(17_257));
        assert_eq!(facts.uptime_phrase(), "up 4 hours 47 minutes");
        assert!(!facts.uptime_phrase().contains("17257"));

        assert_eq!(
            NodeFacts::of_status(&status_up_for(0)).uptime_phrase(),
            "up less than a minute"
        );
        assert_eq!(
            NodeFacts::of_status(&status_up_for(59)).uptime_phrase(),
            "up less than a minute",
            "under a minute must not round up into a claim of a whole one"
        );
        assert_eq!(
            NodeFacts::of_status(&status_up_for(60)).uptime_phrase(),
            "up 1 minute"
        );
        // Exactly on the hour: the trailing zero unit is dropped rather than printed.
        assert_eq!(
            NodeFacts::of_status(&status_up_for(3 * 3_600)).uptime_phrase(),
            "up 3 hours"
        );
        // Past a day the minutes are dropped — two units, most significant first.
        assert_eq!(
            NodeFacts::of_status(&status_up_for(6 * 86_400 + 3 * 3_600 + 12 * 60)).uptime_phrase(),
            "up 6 days 3 hours"
        );
        assert_eq!(
            NodeFacts::of_status(&status_up_for(86_400)).uptime_phrase(),
            "up 1 day"
        );
    }
}
