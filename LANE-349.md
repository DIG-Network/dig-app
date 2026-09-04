# Lane 349 -- second-factor disable: close the biometric-alone bypass

Ticket: https://github.com/DIG-Network/dig-app/issues/349

## Resume-ready state

- Branch: `loop/349-disable-second-factor`
- Base: `origin/main` @ cc815d4 (v13.33.4 on disk)
- Status: stub pushed, work starting.

## What this lane ships

1. `journey::disable` splits into `disable_unlocked` (Hello AND (code OR recovery code))
   and `disable_locked` (refuses -- the biometric alone may DESTROY, never DE-GATE).
2. The advertised walk-around is closed: `Lock now` -> Security -> Turn off two-factor
   no longer removes the enrolment.
3. A break-glass "remove this account from this computer" discard keeps the refusal from
   becoming a lockout: it destroys the seed vault AND the enrolment together.

## Next action

Read `journey.rs`, `vault.rs`, `dig-app.rs` disable seams; write the red tests first
(locked refusal + the end-to-end walk-around) before touching production code.
