"""Apply one named mutation, so a revert proof can be run against a committed tree."""
import io, sys

MUTATIONS = {
    # 1. cost() goes back to counting a store list: emulate it by using a plausible list length.
    "pairs_to_list_length": (
        "crates/dig-app-core/src/collateral/mod.rs",
        "        BufferReading::Known(known) => known.pairs_served_by_this_node,",
        "        BufferReading::Known(_) => 4,",
    ),
    # 2. an unknown funding reading becomes a confident zero.
    "unknown_becomes_zero": (
        "crates/dig-app-core/src/confirm/gui/window/pane/settings/mod.rs",
        "        BufferReading::Pending => {\n            return vec![unknown_funding(copy::settings::FUNDING_PENDING)];\n        }",
        "        BufferReading::Pending => {\n            return vec![dig_row(copy::settings::FUNDING_RECOMMENDED, 0)];\n        }",
    ),
    # 3. the Add row is drawn unconditionally.
    "add_row_always": (
        "crates/dig-app-core/src/confirm/gui/window/pane/settings/mod.rs",
        "    if buffer.add_dig_base_units() > 0 {",
        "    if true {",
    ),
    # 4. the horizon comes from a constant here instead of from the payload.
    "horizon_from_constant": (
        "crates/dig-app-core/src/confirm/gui/window/pane/settings/mod.rs",
        "        Value::Word(horizon_phrase(buffer.horizon_epochs)),",
        "        Value::Word(horizon_phrase(3)),",
    ),
    # 5. the three unknown reasons collapse into one.
    "reasons_collapse": (
        "crates/dig-app-core/src/confirm/gui/window/pane/settings/mod.rs",
        "        BufferReading::Unknown(BufferUnknown::NodeCannotSay(_)) => {\n            return vec![unknown_funding(copy::settings::FUNDING_NODE_CANNOT_SAY)];\n        }",
        "        BufferReading::Unknown(BufferUnknown::NodeCannotSay(_)) => {\n            return vec![unknown_funding(copy::settings::FUNDING_UNREAD)];\n        }",
    ),
}

name = sys.argv[1]
path, old, new = MUTATIONS[name]
s = io.open(path, encoding="utf-8", newline="").read()
if s.count(old) != 1:
    sys.exit("MUTATION %s DID NOT APPLY: %d matches" % (name, s.count(old)))
io.open(path, "w", encoding="utf-8", newline="").write(s.replace(old, new))
print("mutated:", name, "in", path)
