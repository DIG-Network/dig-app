<#
.SYNOPSIS
Re-shoot every Wallet and Cache capture in `crates/dig-app-core/docs/wallet-cache/`.

.DESCRIPTION
Drives `pane_preview` (which takes the tab, size, theme and machine state as ARGUMENTS) and
`capture-window.ps1`. No synthetic input anywhere: nothing is clicked, so no capture can be of a tab
other than the one asked for -- which is the defect this replaced (dig_ecosystem#2326, a capture of
the Status tab committed as the Cache pane).

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

$shots = @(
    @{ file = 'wallet-light-960.png'; args = @('wallet', 'light', '960', '1180', 'live', 'healthy') }
    @{ file = 'wallet-dark-960.png';  args = @('wallet', 'dark',  '960', '1180', 'live', 'healthy') }
    @{ file = 'wallet-light-480.png';  args = @('wallet', 'light', '480', '900',  'live', 'healthy') }
    # The three balance states carry the QR AND the full Sending card, which together are taller than
    # this display allows a window to be -- so they are drawn at 0.8 to keep the whole pane in frame
    # rather than photographed cut off (see open_pane_preview's `zoom`).
    @{ file = 'wallet-light-pending.png';  args = @('wallet', 'light', '960', '1180', 'live', 'pending',  '0.8') }
    @{ file = 'wallet-light-timedout.png'; args = @('wallet', 'light', '960', '1180', 'live', 'timedout', '0.8') }
    @{ file = 'wallet-light-locked.png';   args = @('wallet', 'light', '960', '1180', 'live', 'locked') }
    # The offer card, in the two states worth a picture: an offer read and ready to take, and the
    # same card on a locked account, where the take control is refused WITH its reason rather than
    # greyed in silence. Drawn at 0.8 because the wallet pane plus a filled offer card is taller
    # than this display grants a window.
    @{ file = 'wallet-light-offer.png'; args = @('wallet', 'light', '960', '1180', 'live', 'healthy', '0.8', 'offer') }
    @{ file = 'wallet-dark-offer.png';  args = @('wallet', 'dark',  '960', '1180', 'live', 'healthy', '0.8', 'offer') }
    @{ file = 'wallet-light-offer-480.png'; args = @('wallet', 'light', '480', '900', 'live', 'healthy', '0.7', 'offer') }
    @{ file = 'wallet-light-offer-locked.png'; args = @('wallet', 'light', '960', '1180', 'live', 'locked', '0.8', 'offer') }
    # The Wallet tab's SECOND sub-tab (dig-app#339). Shot at zoom 1 so the claimed logical width IS
    # the pixel width -- a reduced-zoom capture lays the pane out wider and proves nothing about fit.
    # Both machine states are shot because only one of them is reachable on a real host today: no
    # control method publishes the node's operator address, so `machine` is what every user sees now
    # and `machine-funded` is what adopting that method looks like.
    @{ file = 'machine-light-960.png'; args = @('wallet', 'light', '960', '1180', 'live', 'healthy', '1', 'machine') }
    @{ file = 'machine-dark-960.png';  args = @('wallet', 'dark',  '960', '1180', 'live', 'healthy', '1', 'machine') }
    @{ file = 'machine-light-480.png'; args = @('wallet', 'light', '480', '900',  'live', 'healthy', '1', 'machine') }
    @{ file = 'machine-funded-light-960.png'; args = @('wallet', 'light', '960', '1180', 'live', 'healthy', '1', 'machine-funded') }
    @{ file = 'machine-funded-dark-960.png';  args = @('wallet', 'dark',  '960', '1180', 'live', 'healthy', '1', 'machine-funded') }
    @{ file = 'cache-light-960.png';  args = @('cache',  'light', '960', '1180', 'live', 'healthy') }
    @{ file = 'cache-dark-960.png';   args = @('cache',  'dark',  '960', '1180', 'live', 'healthy') }
    @{ file = 'cache-light-480.png';   args = @('cache',  'light', '480', '900',  'live', 'healthy') }
    @{ file = 'cache-light-no-node.png';   args = @('cache',  'light', '960', '1180', 'live', 'no-node') }
)

cargo build -p dig-app-core --features gui --example pane_preview | Out-Null
$exe = Join-Path $root 'target/debug/examples/pane_preview.exe'
if (-not (Test-Path $exe)) { throw "pane_preview was not built at $exe" }

foreach ($shot in $shots) {
    $proc = Start-Process -FilePath $exe -ArgumentList $shot.args -PassThru
    try {
        # Long enough for eframe to create the window, install the fonts and paint a settled frame.
        Start-Sleep -Seconds 5
        $out = Join-Path $OutDir $shot.file
        $result = & (Join-Path $PSScriptRoot 'capture-window.ps1') -ProcessName 'pane_preview' -ProcessId $proc.Id -Out $out
        Write-Output ("{0,-32} {1}" -f $shot.file, $result)
    }
    finally {
        Stop-Process -Id $proc.Id -Force -ErrorAction SilentlyContinue
        Start-Sleep -Milliseconds 700
    }
}
