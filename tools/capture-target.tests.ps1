<#
.SYNOPSIS
Prove the capture refuses to photograph a window it did not identify (dig-app#337).

.DESCRIPTION
Run with:

    pwsh -NoProfile -File tools/capture-target.tests.ps1

Deliberately not Pester. This repo's CI runs on Ubuntu and never invokes PowerShell, so a Pester
suite would advertise a gate that does not exist; a self-contained runner at least runs anywhere
`pwsh` does, and says how many assertions actually executed rather than only whether it exited zero.

## Why the fixtures are shaped the way they are

The rule being tested replaced a HEADCOUNT ("exactly one window answers to the name") with an
IDENTITY check ("the window belongs to the process the caller started"). The nearest wrong
implementation is therefore the headcount, and most obvious fixtures cannot tell the two apart:

* Two windowed strangers is the case the headcount ALREADY refuses. A suite built only from it passes
  against the defect, which is exactly how a stale-window bug survives a green run.
* One windowed process that IS the target is the case the headcount already gets right.

The case that separates them is `one_stranger_windowed_target_still_painting`: exactly one window
exists, so the headcount is satisfied, and it belongs to the wrong process. That is also the failure
that actually happens -- a leftover preview has painted and the process just launched has not.

`two_windows_target_identified` separates them in the other direction: identity ACCEPTS a run the
headcount refuses, so the fix is not merely "throw more often".
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

Import-Module (Join-Path $PSScriptRoot 'capture-target.psm1') -Force

$script:Ran = 0
$script:Failed = 0

function Candidate {
    param([int]$Id, [int]$Handle)
    return [pscustomobject]@{ Id = $Id; MainWindowHandle = [IntPtr]$Handle }
}

function Assert {
    param([string]$Name, [scriptblock]$Body)
    $script:Ran++
    try {
        & $Body
        Write-Host "  ok   $Name"
    } catch {
        $script:Failed++
        Write-Host "  FAIL $Name"
        Write-Host "       $($_.Exception.Message)"
    }
}

function Should-Throw {
    param([scriptblock]$Body, [string[]]$Naming)
    try {
        & $Body
    } catch {
        foreach ($needle in $Naming) {
            if ($_.Exception.Message -notlike "*$needle*") {
                throw "refusal did not name '$needle'. It said: $($_.Exception.Message)"
            }
        }
        return
    }
    throw 'expected a refusal, but the call returned'
}

Write-Host 'Select-CaptureTarget'

# THE LOAD-BEARING CASE. One window exists, so a headcount is satisfied, and it is the wrong process.
# A version that counts instead of identifying returns 4242 here and the caller writes that window to
# the target's filename -- a picture of the previous shot, committed as evidence for this one.
Assert 'one_stranger_windowed_target_still_painting refuses and names the stranger' {
    Should-Throw -Naming @('1111', '4242') -Body {
        Select-CaptureTarget -ProcessName 'pane_preview' -ProcessId 1111 -Candidates @(
            (Candidate -Id 1111 -Handle 0),
            (Candidate -Id 4242 -Handle 987)
        )
    }
}

# The same shape with the target absent entirely rather than merely unpainted: a caller whose process
# died still must not be handed a leftover's window.
Assert 'target_not_running refuses even though exactly one window exists' {
    Should-Throw -Naming @('1111', '4242') -Body {
        Select-CaptureTarget -ProcessName 'pane_preview' -ProcessId 1111 -Candidates @(
            (Candidate -Id 4242 -Handle 987)
        )
    }
}

# THE TRUTHFUL CONTROL. Without this the suite is satisfied by a rule that refuses unconditionally,
# and an always-refusing capture would pass every case above while photographing nothing ever again.
Assert 'target_windowed_alone is captured' {
    $chosen = Select-CaptureTarget -ProcessName 'pane_preview' -ProcessId 1111 -Candidates @(
        (Candidate -Id 1111 -Handle 555)
    )
    if ($chosen.Id -ne 1111) { throw "chose $($chosen.Id), wanted 1111" }
}

# Identity ACCEPTS what the headcount refused. A leftover on the machine no longer fails a run whose
# target is unambiguous -- which is why the fix is an identity check rather than a stricter count.
Assert 'two_windows_target_identified is captured, stranger ignored' {
    $chosen = Select-CaptureTarget -ProcessName 'pane_preview' -ProcessId 1111 -Candidates @(
        (Candidate -Id 4242 -Handle 987),
        (Candidate -Id 1111 -Handle 555)
    )
    if ($chosen.Id -ne 1111) { throw "chose $($chosen.Id), wanted 1111" }
    if ($chosen.MainWindowHandle -ne [IntPtr]555) { throw 'chose the stranger handle' }
}

# The by-hand path from the docs READMEs, where no PID is available. With no identity to check the
# headcount is all there is, so ambiguity must still refuse -- and name both PIDs, or the reader has
# no way to find the leftover.
Assert 'no_process_id_two_windows refuses and names both' {
    Should-Throw -Naming @('4242', '1111') -Body {
        Select-CaptureTarget -ProcessName 'pane_preview' -Candidates @(
            (Candidate -Id 4242 -Handle 987),
            (Candidate -Id 1111 -Handle 555)
        )
    }
}

Assert 'no_process_id_one_window is captured' {
    $chosen = Select-CaptureTarget -ProcessName 'pane_preview' -Candidates @(
        (Candidate -Id 4242 -Handle 987)
    )
    if ($chosen.Id -ne 4242) { throw "chose $($chosen.Id), wanted 4242" }
}

Assert 'nothing_running refuses' {
    Should-Throw -Naming @('pane_preview') -Body {
        Select-CaptureTarget -ProcessName 'pane_preview' -Candidates @()
    }
}

# A run that matched no assertions exits zero and prints nothing alarming, so the count is asserted
# rather than eyeballed -- the same reason a filtered `cargo test` that matches nothing is not a green.
$expected = 7
Write-Host ''
Write-Host "$($script:Ran) assertions, $($script:Failed) failed"
if ($script:Ran -ne $expected) {
    Write-Host "EXPECTED $expected assertions to run; a suite that ran fewer proves less than it claims."
    exit 2
}
if ($script:Failed -ne 0) { exit 1 }
Write-Host 'PASS'
