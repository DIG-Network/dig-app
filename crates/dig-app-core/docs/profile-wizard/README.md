# The profile creation wizard (dig_ecosystem#3038)

Real captures of the shipping shell, taken with `examples/window_gallery.rs`:

```text
cargo run -p dig-app-core --features gui --example window_gallery -- \
    account light 700 1400 unlocked --can-create-profile \
    docs/profile-wizard/create-wizard-light-700x1400.png
```

Each file is 2x the logical size in its name, because `window_gallery` pins the scale rather than
taking it from the display.

## What each file shows

| File | Shows |
|---|---|
| `create-wizard-light-960x900.png` | The Account tab with the profiles card, and the *Creating a profile* panel beneath it. |
| `create-wizard-light-700x1400.png` | The wizard's form itself: every field the profile can hold, each with its label, its "not set" placeholder and the sentence saying who can read it. |

`--can-create-profile` is what puts the fixture on a node that could complete a whole-profile mint.
Without it the panel explains why creation is unavailable and draws no form — which is the state a
gallery host genuinely is in, and the reason the flag exists rather than the form being drawn
unconditionally.

## What these captures do NOT evidence

They are fixtures. Nothing here reached a chain, nothing was spent, and no profile was minted. What
they show is the form a person fills in before the ceremony starts; that the values it collects are
committed by the store's first root is held by the tests in `profile_edit::seed`, and an end-to-end
mainnet creation is the separate evidence #3039 asks for.
