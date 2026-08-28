<#
.SYNOPSIS
Re-shoot every collateral safety-margin capture in `crates/dig-app-core/docs/collateral/`.

.DESCRIPTION
Drives `pane_preview` (which takes the tab, size, theme and the COLLATERAL ANSWER as arguments) and
`capture-window.ps1`. No synthetic input anywhere: nothing is clicked, so no capture can be of a tab
other than the one asked for.

The margin state is named on the command line rather than left to whatever node happens to be
running on the machine taking the picture. That matters here more than elsewhere: the node side of
`control.collateral.*` ships separately, so a machine taking these pictures today would produce the
UNREAD state for all three shots and they would look like proof that the other two render correctly.

Prints the physical size of every PNG written, so a claimed logical width can be checked against the
pixels rather than against the command that was meant to produce them.
#>
[CmdletBinding()]
param(
    [string]$OutDir = "crates/dig-app-core/docs/collateral"
)

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
Set-Location $root

$shots = @(
    # The margin AND a priced requirement: the card with real figures in it.
    @{ file = 'margin-light-960-priced.png'; args = @('settings', 'light', '960', '1180', 'live', 'healthy', '0.8', 'margin-priced') }
    @{ file = 'margin-dark-960-priced.png';  args = @('settings', 'dark',  '960', '1180', 'live', 'healthy', '0.8', 'margin-priced') }
    @{ file = 'margin-light-480-priced.png'; args = @('settings', 'light', '480', '900',  'live', 'healthy', '0.7', 'margin-priced') }
    # The margin read, the requirement not: the ordinary state of every node today, and the one the
    # honest-unknown rule exists for. The copy still promises the choice IS saved and applied.
    @{ file = 'margin-light-960-no-requirement.png'; args = @('settings', 'light', '960', '1180', 'live', 'healthy', '0.8', 'margin-no-requirement') }
    @{ file = 'margin-light-480-no-requirement.png'; args = @('settings', 'light', '480', '900',  'live', 'healthy', '0.7', 'margin-no-requirement') }
    # Neither served: the margin itself is unread, so the chooser shows no percentage and the copy
    # must NOT promise the choice is saved.
    @{ file = 'margin-light-960-unread.png'; args = @('settings', 'light', '960', '1180', 'live', 'healthy', '0.8', 'margin-unread') }
    @{ file = 'margin-light-480-unread.png'; args = @('settings', 'light', '480', '900',  'live', 'healthy', '0.7', 'margin-unread') }
)

cargo build -p dig-app-core --example pane_preview | Out-Null
$exe = Join-Path $root 'target/debug/examples/pane_preview.exe'
if (-not (Test-Path $exe)) { throw "pane_preview was not built at $exe" }
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null

foreach ($shot in $shots) {
    $proc = Start-Process -FilePath $exe -ArgumentList $shot.args -PassThru
    try {
        # Long enough for eframe to create the window, install the fonts and paint a settled frame.
        Start-Sleep -Seconds 5
        $out = Join-Path $OutDir $shot.file
        $result = & (Join-Path $PSScriptRoot 'capture-window.ps1') -ProcessName 'pane_preview' -Out $out
        Write-Output ("{0,-40} {1}" -f $shot.file, $result)
    }
    finally {
        Stop-Process -Id $proc.Id -Force -ErrorAction SilentlyContinue
        Start-Sleep -Milliseconds 700
    }
}
