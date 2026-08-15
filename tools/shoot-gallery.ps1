<#
.SYNOPSIS
Re-shoot the complete DIG app gallery into `docs/gallery/`.

.DESCRIPTION
The one command that produces a true picture of this application: every tab in both themes at both
widths, every account state the Account pane can be in, and every screen of the first-run DID
wizard.

Two harnesses, one discipline. `window_gallery` draws the shipping shell at a tab, theme, size and
account state given as ARGUMENTS, and the `did_wizard_gallery` test draws each wizard screen from
the journey's own builders. Both read the framebuffer back with `ViewportCommand::Screenshot`.

Nothing is clicked, nothing is dragged, and no window has to be in the foreground. That matters
twice over:

* A capture set up by driving input photographs whatever the pointer landed on -- which is how a
  committed screenshot labelled "Cache" turned out to be the Status tab (dig_ecosystem#2326).
* A GDI screen capture (`PrintWindow`, `BitBlt`, most screenshot tools) is blind to a hardware GL
  surface. It hands back a black rectangle of exactly the right size, so the harness reports success
  and the file looks plausible until somebody opens it.

Prints the pixel size of every PNG written. Every image is 2x the logical size in its name, on every
host, because the scale is pinned rather than taken from the display.

The `-Live` switch additionally shoots the four `*-live-*` captures, which read the two node-backed
cards from the RUNNING local dig-node instead of the fixture (dig_ecosystem#2397). They are opt-in
because they need a node: `window_gallery --live` refuses rather than falling back to fixture data,
so on a machine with no node running this switch fails the script instead of writing a picture that
would be labelled live and be synthetic.

.EXAMPLE
tools/shoot-gallery.ps1 -Live
#>
[CmdletBinding()]
param(
    [string]$OutDir = "docs/gallery",
    [switch]$Live
)

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
Set-Location $root

# 480 is the shell's own minimum (`SHELL_MIN`) -- the narrowest a person can drag the window to, and
# where the layout is under the most pressure. 900 tall is the most this display's work area grants.
$WIDE = 960
$NARROW = 480
$TALL = 900
# The live captures alone are shot taller -- see the `-Live` block below for why.
$LIVE_TALL = 1400
# The profiles captures are shot to the pane's full height, at each width, so the card's controls and
# its create explainer are both in frame -- see the profiles block below.
$PROFILES_TALL = 2000
$NARROW_PROFILES_TALL = 2400

$shots = @()

# Every tab, both themes, both widths: the app as it stands.
foreach ($tab in @('home', 'account', 'wallet', 'content', 'settings')) {
    foreach ($theme in @('light', 'dark')) {
        foreach ($width in @($WIDE, $NARROW)) {
            $shots += @{
                file = "$tab-$theme-$width.png"
                args = @($tab, $theme, "$width", "$TALL", 'unlocked')
            }
        }
    }
}

# The account states that are NOT the happy path. dig_ecosystem#2059 was a defect in three states at
# once, invisible from a screenshot of the sixth -- so each one is photographed, not reasoned about.
foreach ($state in @('unsupported', 'absent', 'locked', 'unopenable', 'needs-password', 'unlocked-no-phrase')) {
    $shots += @{
        file = "account-$state.png"
        args = @('account', 'light', "$WIDE", "$TALL", $state)
    }
}

# The Wallet tab with nothing to show. Every control on it is refused in this state, so it is the one
# picture that proves the never-trap rule holds there: the balance says WHY there is no figure rather
# than showing a zero, each greyed verb states its own condition in place, and the menu's copy row
# survives because no disclosed card is drawing one (dig_ecosystem#2967).
$shots += @{
    file = 'wallet-locked.png'
    args = @('wallet', 'light', "$WIDE", "$TALL", 'locked')
}

# The second-factor row is the one control on the Account tab that appears and disappears with a
# setting rather than with the account's state, so both sides of it are photographed rather than
# described. It lives on Account since dig_ecosystem#2358 merged the Security tab into it.
$shots += @{
    file = 'account-second-factor-on.png'
    args = @('account', 'light', "$WIDE", "$TALL", 'unlocked', '--second-factor')
}

# The profiles card's three interesting states (dig_ecosystem#2403). Every REAL account holds no
# profiles, so the empty state is already covered by every `account-*` shot above; these three are
# the states a list can only be in once minting exists, built from registry fixtures that go through
# `ProfileRegistry::from_json` -- the same loader production uses, with all four of dig-account's
# invariants re-checked on the way in.
#
# Taller than $TALL for the same reason the live shots are: the card sits below two others, and a
# capture that cannot show the controls it is evidence for is not evidence.
foreach ($fixture in @('two', 'hidden', 'switched')) {
    $shots += @{
        file = "profiles-$fixture-$WIDE.png"
        args = @('account', 'light', "$WIDE", "$PROFILES_TALL", 'unlocked', '--profiles', $fixture)
    }
    $shots += @{
        file = "profiles-$fixture-$NARROW.png"
        args = @('account', 'light', "$NARROW", "$NARROW_PROFILES_TALL", 'unlocked', '--profiles', $fixture)
    }
}

# The two cards that read the node (dig_ecosystem#2397): the Home tab's sharing card and the Content
# tab's hosted-store list. `--live` fills them from the RUNNING node, so these are the only images in
# the set whose contents depend on the machine that shot them -- and the only ones that cannot be
# taken at all without a node, which is why they are opt-in.
#
# Taller than $TALL because both cards are the LAST thing on their tab, and at 900 the sharing card
# is below the fold: a capture that cannot show the card it is evidence for is not evidence.
if ($Live) {
    foreach ($tab in @('home', 'content')) {
        foreach ($width in @($WIDE, $NARROW)) {
            $shots += @{
                file = "$tab-live-$width.png"
                args = @($tab, 'light', "$width", "$LIVE_TALL", 'unlocked', '--live')
            }
        }
    }
}

cargo build -p dig-app-core --features gui --example window_gallery | Out-Null

# Honoured because a lane building in a worktree points cargo somewhere other than ./target, and a
# script that assumed otherwise would silently photograph a stale binary.
$targetRoot = if ($env:CARGO_TARGET_DIR) { $env:CARGO_TARGET_DIR } else { Join-Path $root 'target' }
$exe = Join-Path $targetRoot 'debug/examples/window_gallery.exe'
if (-not (Test-Path $exe)) { throw "window_gallery was not built at $exe" }

New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
foreach ($shot in $shots) {
    $out = Join-Path $OutDir $shot.file
    & $exe @($shot.args + $out)
    if ($LASTEXITCODE -ne 0) { throw "$($shot.file) was not written" }
}

# The wizard's eight screens, in both themes. A test rather than an example because each screen is
# built by the journey's own builder, which is where they are reachable from.
$env:DIG_WIZARD_SHOTS = (Resolve-Path $OutDir).Path
cargo test -p dig-app-core --features gui --lib -- --ignored --nocapture did_wizard_gallery
