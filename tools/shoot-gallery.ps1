<#
.SYNOPSIS
Re-shoot the complete DIG app gallery into `docs/gallery/`.

.DESCRIPTION
The one command that produces a true picture of this application: every tab in both themes at both
widths, every account state the Account and Security panes can be in, and every screen of the
first-run DID wizard.

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
#>
[CmdletBinding()]
param(
    [string]$OutDir = "docs/gallery"
)

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
Set-Location $root

# 480 is the shell's own minimum (`SHELL_MIN`) -- the narrowest a person can drag the window to, and
# where the layout is under the most pressure. 900 tall is the most this display's work area grants.
$WIDE = 960
$NARROW = 480
$TALL = 900

$shots = @()

# Every tab, both themes, both widths: the app as it stands.
foreach ($tab in @('status', 'account', 'security', 'wallet', 'apps', 'cache', 'settings')) {
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

# Security answers the account state too, and its second-factor row is the one control that appears
# and disappears -- so both sides of that are photographed rather than described.
$shots += @{ file = 'security-locked.png'; args = @('security', 'light', "$WIDE", "$TALL", 'locked') }
$shots += @{
    file = 'security-second-factor-on.png'
    args = @('security', 'light', "$WIDE", "$TALL", 'unlocked', '--second-factor')
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
