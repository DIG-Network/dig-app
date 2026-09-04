<#
.SYNOPSIS
Re-shoot the Coins table captures in `crates/dig-app-core/docs/wallet-cache/` (dig_ecosystem#334).

.DESCRIPTION
Two pairs, both at zoom 0.36, differing only in the WINDOW they ask for -- and that difference is the
whole point of having two.

`coins-<theme>-480.png` opens a 480 logical-px window, which is the width being claimed, but zoom
multiplies every logical unit: at 0.36 the pane is laid out at roughly 1333 logical px, so an id that
fits there proves nothing about the window a person actually has.

`coins-<theme>-480-layout.png` asks for `480 x 0.36 ~= 173` logical px at the same zoom, which lays the
pane out at exactly 480 -- the width being claimed -- while keeping the photograph small enough to hold
the whole ten-row card in frame. That pair is the one that can settle whether a 64-character id fits.

Prints the physical size of every PNG written, so a claimed logical width can be checked against the
pixels rather than against the command that was meant to produce them.
#>
[CmdletBinding()]
param(
    [string]$OutDir = "crates/dig-app-core/docs/wallet-cache"
)

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
Set-Location $root

# 480 x 0.36. Kept as the arithmetic rather than the rounded literal, so the relationship to the width
# being claimed survives a later change to either number.
$LAYOUT_WIDTH = [int][math]::Round(480 * 0.36)

$shots = @(
    @{ file = 'coins-light-480.png'; args = @('wallet', 'light', '480', '900', 'live', 'healthy', '0.36') }
    @{ file = 'coins-dark-480.png';  args = @('wallet', 'dark',  '480', '900', 'live', 'healthy', '0.36') }
    @{ file = 'coins-light-480-layout.png'; args = @('wallet', 'light', "$LAYOUT_WIDTH", '900', 'live', 'healthy', '0.36') }
    @{ file = 'coins-dark-480-layout.png';  args = @('wallet', 'dark',  "$LAYOUT_WIDTH", '900', 'live', 'healthy', '0.36') }
)

cargo build -p dig-app-core --features gui --example pane_preview | Out-Null

# Honoured because a lane building in a worktree points cargo somewhere other than ./target, and a
# script that assumed otherwise would silently photograph a stale binary.
$targetRoot = if ($env:CARGO_TARGET_DIR) { $env:CARGO_TARGET_DIR } else { Join-Path $root 'target' }
$exe = Join-Path $targetRoot 'debug/examples/pane_preview.exe'
if (-not (Test-Path $exe)) { throw "pane_preview was not built at $exe" }
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null

foreach ($shot in $shots) {
    $proc = Start-Process -FilePath $exe -ArgumentList $shot.args -PassThru
    try {
        # Long enough for eframe to create the window, install the fonts and paint a settled frame.
        Start-Sleep -Seconds 6
        $out = Join-Path $OutDir $shot.file
        # The PID is what makes this a picture of THIS run. Without it a leftover preview that has
        # already painted is indistinguishable from the process just launched.
        $result = & (Join-Path $PSScriptRoot 'capture-window.ps1') -ProcessName 'pane_preview' -ProcessId $proc.Id -Out $out
        Write-Output ("{0,-30} {1}" -f $shot.file, $result)
    }
    finally {
        Stop-Process -Id $proc.Id -Force -ErrorAction SilentlyContinue
        Start-Sleep -Milliseconds 700
    }
}
