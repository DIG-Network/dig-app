<#
.SYNOPSIS
Audit every committed capture for the three ways one can be silently wrong (dig-app#337).

.DESCRIPTION
A screenshot is the acceptance evidence for every visual change in this repo, and the ways a capture
goes wrong are all silent: nothing errors, and the file looks plausible until somebody opens it. Three
of those ways leave a mark in the PIXELS, which means they can be measured instead of trusted.

Run with:

    pwsh -NoProfile -File tools/audit-captures.ps1

Each check exists because it caught a real committed defect on the run that introduced it, so none of
them is hypothetical:

1. DEGENERATE -- a capture of nothing. `offer-light-960.png` was 13 x 13 pixels of a single colour,
   named as a 960 logical-px capture that should have been 2432 px wide, referenced by no script and
   no README. This is the failure `shoot-gallery.ps1` warns about in its own docstring: a capture path
   that hands back a uniform rectangle and reports success.

2. THEME -- a file named for one theme showing the other. This is the defect that opened the ticket:
   a capture labelled `dark` that showed the light theme. Measured across the whole committed set the
   two populations do not overlap remotely -- dark-named images run 13.8 to 43.7 mean luminance and
   light-named ones run 200.6 to 248.9 -- so the boundary below sits in a gap of about 157 units with
   more than 75 units of margin on EITHER side. A threshold pinned from only one side could only ever
   confirm itself; this one is placed from both.

3. TWIN -- two different names holding byte-identical pixels. Three byte-identical PNGs under three
   names is what exposed the original bug. The same scan found `account-second-factor-on.png` equal to
   `account-unlocked-no-phrase.png`, which turned out to be a capture too short to contain the control
   it was named for.

Same base name in two directories is NOT flagged: the wizard screens are deliberately copied into two
galleries, and a rule that cannot tell a deliberate copy from a collision would be ignored within a
week.

.PARAMETER Root
Directory to scan. Defaults to the repository root.
#>
[CmdletBinding()]
param(
    [string]$Root = (Split-Path -Parent $PSScriptRoot)
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
Add-Type -AssemblyName System.Drawing

# Measured, not chosen: the nearest real dark image sits at 43.7 and the nearest real light one at
# 200.6, so anything within 75 units of this line is already unlike every capture in the repo.
$THEME_BOUNDARY = 120.0

# Brand marks are legitimately tiny and legitimately duplicated across crates. They are artwork, not
# evidence, and including them would produce a permanent pair of false findings.
$ARTWORK = '[\\/](icons|assets)[\\/]'

function Get-Thumbnail {
    param([Parameter(Mandatory = $true)][string]$Path)
    $source = [System.Drawing.Image]::FromFile($Path)
    try {
        $thumb = New-Object System.Drawing.Bitmap 64, 64
        $g = [System.Drawing.Graphics]::FromImage($thumb)
        try { $g.DrawImage($source, 0, 0, 64, 64) } finally { $g.Dispose() }
        return @{ Thumb = $thumb; Width = $source.Width; Height = $source.Height }
    } finally { $source.Dispose() }
}

$images = @(Get-ChildItem -Path $Root -Filter '*.png' -Recurse -File |
    Where-Object { $_.FullName -notmatch '[\\/](target|\.git|node_modules)[\\/]' } |
    Where-Object { $_.FullName -notmatch $ARTWORK })

$findings = @()
$byHash = @{}

foreach ($image in $images) {
    $measured = Get-Thumbnail -Path $image.FullName
    $thumb = $measured.Thumb
    try {
        $total = 0.0
        $colours = @{}
        for ($x = 0; $x -lt 64; $x++) {
            for ($y = 0; $y -lt 64; $y++) {
                $p = $thumb.GetPixel($x, $y)
                # Rec. 601 luma, which is what "does this look like the dark theme" actually means.
                $total += (0.299 * $p.R) + (0.587 * $p.G) + (0.114 * $p.B)
                $colours[$p.ToArgb()] = $true
            }
        }
        $luma = $total / 4096.0
    } finally { $thumb.Dispose() }

    $relative = $image.FullName.Substring($Root.Length).TrimStart('\', '/')

    # A real capture of a real window is never one flat colour, at any scale.
    if ($colours.Count -eq 1) {
        $findings += "DEGENERATE $relative is a single flat colour at $($measured.Width) x $($measured.Height) - it shows nothing"
    } elseif ($measured.Width -lt 100 -or $measured.Height -lt 100) {
        $findings += "DEGENERATE $relative is only $($measured.Width) x $($measured.Height) - too small to be a window"
    }

    $name = $image.Name.ToLowerInvariant()
    if ($name -match 'dark' -and $luma -ge $THEME_BOUNDARY) {
        $findings += ("THEME $relative is named dark but measures {0:N1} mean luma - that is the light theme" -f $luma)
    } elseif ($name -match 'light' -and $luma -lt $THEME_BOUNDARY) {
        $findings += ("THEME $relative is named light but measures {0:N1} mean luma - that is the dark theme" -f $luma)
    }

    $hash = (Get-FileHash -Path $image.FullName -Algorithm SHA256).Hash
    if (-not $byHash.ContainsKey($hash)) { $byHash[$hash] = @() }
    $byHash[$hash] += $image
}

foreach ($hash in $byHash.Keys) {
    $group = @($byHash[$hash])
    if ($group.Count -lt 2) { continue }
    $distinctNames = @($group | ForEach-Object { $_.Name } | Sort-Object -Unique)
    # Identical pixels under the SAME name in two galleries is a deliberate copy. Under DIFFERENT
    # names it is two claims resting on one picture, and at most one of them can be true.
    if ($distinctNames.Count -lt 2) { continue }
    $findings += "TWIN $($distinctNames -join ' == ') hold byte-identical pixels under different names"
}

foreach ($finding in ($findings | Sort-Object)) { Write-Host $finding }

Write-Host ''
Write-Host "$($images.Count) captures audited, $($findings.Count) findings"

# A glob that matched nothing exits zero and prints a reassuring zero, which is the same shape as every
# other instrument failure this repo has been bitten by. Assert the sample instead of trusting it.
if ($images.Count -lt 100) {
    Write-Host "AUDITED TOO FEW CAPTURES - expected the committed gallery set, got $($images.Count)"
    exit 2
}
if ($findings.Count -ne 0) { exit 1 }
Write-Host 'PASS'
