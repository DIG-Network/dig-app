# Lane 3077 — offers in the wallet tab (slices O1 + O2)

O1: paste/scan an `offer1…` string and see honest terms, derived from
`dig_offers::summarize` on the SAME bytes that would be broadcast.

O2: take an offer — summarize -> take_build -> sign locally -> take_combine ->
`control.wallet.broadcast`.

Working notes live here until the PR is ready; deleted before merge.
