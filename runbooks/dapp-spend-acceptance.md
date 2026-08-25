# Runbook — seeing `spend.request` work end to end (WU5)

The acceptance for the `spend.request` money boundary (`SPEC.md` §5.6.10, dig_ecosystem#1552) is **a
person watching the confirm window name a real recipient and a real amount, approving it, and the
signed bundle reaching a mempool.** A green test suite is not the acceptance and never will be: the
suite cannot see what the window said.

This runbook makes that a single command plus the human step that has to stay human.

## Prerequisites

| What | Check | Expected |
|---|---|---|
| dig-node running and synced | `dign wallet sync-status` | `"phase":"synced"`, `chia_peer_peak_height` equal to `peak_height` |
| A funded address | `dign wallet watched` then `dign wallet balance <addr>` | a coin covering amount + fee |
| dig-app running **from this branch** | see below | the installed build answers `-32601`; `spend.request` is new |

**The installed dig-app will NOT work.** `spend.request` does not exist in any released build, so it
answers JSON-RPC `-32601`. That is the correct before-state, and it is worth seeing once — it is how
you know the run afterwards proved something. Run the branch build instead:

```bash
cargo run --features tray --bin dig-app
```

## Finding the sender key and an address

Public data only. **Never** print, paste or pass a seed, mnemonic or private key — nothing in this
flow needs one, and the harness is structurally unable to use one.

```bash
dign wallet watched          # 48-byte G1 public keys, hex
dign wallet balance <xch1…>  # confirm the address holds enough
```

## The run

1. In the DIG App: **Paired apps → Pair an app**. Copy the 8-character pairing code.
2. Run the harness. **Start without `--broadcast`** — the app signs and pushes nothing, so you see
   the entire path including the window, with no money moving:

```bash
cargo run --example live_dapp_spend -- \
    <PAIRING_CODE> <SENDER_PUBKEY_HEX> <RECIPIENT_xch1…> <AMOUNT_MOJOS> <FEE_MOJOS>
```

3. Two windows appear, in this order, and both matter:
   - the **pairing** confirm, which must say **PAYMENTS** are being granted and that each payment is
     still confirmed separately;
   - the **spend** confirm, which must name the recipient address and the amount, and which must
     promise a broadcast ONLY if a node is actually reachable (see step 6).
4. **Read the recipient in the window and compare it to what you typed.** That comparison is the
   security property this whole feature exists to provide; approving without doing it proves nothing.
5. Approve. The harness prints `bundle_id` and `push: not_broadcast`.
6. Re-run with `--broadcast` to let it actually leave.

   **The window's wording changes, and that change is the thing to check.** With a node reachable it
   reads *"Approve and SEND this payment?"* and carries *"a broadcast payment cannot be recalled"*.
   With no node reachable it must NOT say either — DIG will sign and hand the bundle back, and
   whether it is ever sent is not settled here. If the window promises a broadcast and you then see
   `push: not_broadcast`, that is the defect this step exists to catch: **stop and report it.**

   `push: pending` means a mempool **accepted** it — an acceptance, not a confirmation. Watch the
   coin settle:

```bash
dign wallet coin-by-id <PAYMENT_COIN_ID>
```

   The harness prints the coin it spent; the payment coin is the child of that spend:

```bash
dign wallet coins-by-parent <SPENT_COIN_ID>
```

## Reading the result honestly

| `push` | What it means | What you may do |
|---|---|---|
| `not_broadcast` | no mempool holds it — either you did not ask, or the push provably never left | retry safely |
| `pending` | a mempool accepted it | wait; do not resend |
| `unknown` | the push was unanswered and it **may** be in a mempool | **do not resend** — a rebuild over fresh inputs can pay the recipient twice |

There is deliberately no `sent` and no `confirmed`. Money is settled when the chain says so.

## Capturing the screenshot

The screenshot of the **spend confirm window** is the deliverable. Two rules:

- **Do not drive synthetic input.** A committed screenshot must show a real window a real person
  looked at; a synthesised one documents the harness, not the product.
- **Public addresses only in the image.** `xch1…` values are public and fine. Nothing else from the
  wallet belongs in a screenshot.

## What to do when it refuses

Every refusal is a stable wire symbol (`SPEC.md` §5.6.7), and they mean different things:

| Symbol | Cause |
|---|---|
| `CAP_NOT_GRANTED` | the pairing does not hold `spend.request` — re-pair; the harness asserts the grant and stops early |
| `CONNECT_REQUIRED` | the origin is not connected for the **active** profile; also fires if the profile switched during the re-auth, which is correct |
| `SIGN_DENIED` | you declined. Asking again is reasonable |
| `SPEND_REFUSED` | the app refused structurally. An identical retry cannot change it |
| `SIGN_NO_CONFIRMER` | no wallet is wired, or no window could be raised — never a decline on your behalf |
| `LOCKED` | the account is locked; unlocking helps |
| `-32601` | you are running a build without `spend.request` (almost always the installed app) |
