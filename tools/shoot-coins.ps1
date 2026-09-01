# Photograph the Coins table at 480 px logical (dig_ecosystem#334), in both themes and at two zooms.
#
# 0.36 brings the WHOLE card into frame, so the ten-row layout budget can be counted. 1.0 is true
# scale, which is the only capture that can settle whether a 64-character id fits the column width a
# person actually sees -- a reduced zoom gives the pane proportionally more logical width and would
# make a clipped id look fine.
$ErrorActionPreference = 'Stop'
$root = 'C:/tmp/worktrees/da-table'
Set-Location $root
$exe = Join-Path $root 'target/debug/examples/pane_preview.exe'
if (-not (Test-Path $exe)) { throw "pane_preview was not built at $exe" }

$shots = @(
    @{ file = 'coins-light-480.png';      args = @('wallet', 'light', '480', '900',  'live', 'healthy', '0.36') }
    @{ file = 'coins-dark-480.png';       args = @('wallet', 'dark',  '480', '900',  'live', 'healthy', '0.36') }
    @{ file = 'coins-light-480-true.png'; args = @('wallet', 'light', '480', '1180', 'live', 'healthy', '1.0') }
    @{ file = 'coins-dark-480-true.png';  args = @('wallet', 'dark',  '480', '1180', 'live', 'healthy', '1.0') }
)
foreach ($shot in $shots) {
    # Any leftover from an earlier shot answers to the same process name; capture-window.ps1 now
    # refuses rather than guessing, so clear the field before launching.
    Get-Process -Name 'pane_preview' -ErrorAction SilentlyContinue | Stop-Process -Force
    Start-Sleep -Milliseconds 700
    $proc = Start-Process -FilePath $exe -ArgumentList $shot.args -PassThru
    try {
        Start-Sleep -Seconds 6
        $result = & (Join-Path $root 'tools/capture-window.ps1') -ProcessName 'pane_preview' -Out (Join-Path "$root/crates/dig-app-core/docs/wallet-cache" $shot.file)
        Write-Output ("{0,-28} {1}" -f $shot.file, $result)
    } finally {
        Stop-Process -Id $proc.Id -Force -ErrorAction SilentlyContinue
        Start-Sleep -Milliseconds 700
    }
}
