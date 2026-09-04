<#
.SYNOPSIS
Decide WHICH window a capture is allowed to photograph, or refuse.

.DESCRIPTION
Separated from `capture-window.ps1` so the decision can be exercised against fabricated candidate
lists, without a display, a GPU or a running gallery. The Win32 call is not the interesting part; the
choice is, and a choice that only runs when a real window is on screen is a choice nobody tests.

The rule is IDENTITY, not headcount. A caller that started a process knows which one it wants, so it
says so, and this returns that process's window or nothing at all.
#>

Set-StrictMode -Version Latest

<#
.SYNOPSIS
Return the one candidate a capture may photograph, or throw naming what was found instead.

.DESCRIPTION
Counting is not identifying. An earlier version of this rule accepted any single windowed process
answering to the name, which is silently wrong in the one case that actually happens: a stale preview
from an earlier shot has painted, the process just launched has not, and exactly ONE window therefore
answers to the name -- the wrong one. A headcount cannot tell those apart, because it never asks which
process the caller meant.

So when the caller names a `ProcessId`, that process's window is the only acceptable answer. A target
that has not painted yet is a refusal rather than a fallback, and the refusal names the strangers that
were standing where the target should have been.

`ProcessId` is optional only so a person can still run the capture by hand from the two lines in a
docs README. Without it there is no identity to check, so the headcount rule is all that remains and
any ambiguity refuses.

.PARAMETER ProcessName
The process name the caller asked for, used only to word the refusals.

.PARAMETER ProcessId
The process the caller started, when it knows. When supplied, only this process may be photographed.

.PARAMETER Candidates
Objects carrying an `Id` and a `MainWindowHandle`, as `Get-Process` returns them.

.OUTPUTS
The single candidate whose window may be photographed.
#>
function Select-CaptureTarget {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$ProcessName,
        [int]$ProcessId = 0,
        [Parameter(Mandatory = $true)][AllowEmptyCollection()][object[]]$Candidates
    )

    $windowed = @($Candidates | Where-Object { $_.MainWindowHandle -ne 0 })

    if ($ProcessId -ne 0) {
        $target = @($Candidates | Where-Object { $_.Id -eq $ProcessId })

        if ($target.Count -eq 0) {
            throw ("process $ProcessId is not running, so there is no window of it to photograph. " +
                (Format-Foundling -ProcessName $ProcessName -Windowed $windowed))
        }

        if ($target[0].MainWindowHandle -eq 0) {
            throw ("process $ProcessId has not opened its window yet, so a capture now would " +
                "photograph something else or nothing. " +
                (Format-Foundling -ProcessName $ProcessName -Windowed $windowed))
        }

        # Strangers are IGNORED once the target is identified. Refusing here would make an unrelated
        # leftover on the machine able to fail an otherwise-correct run, which is what a headcount did.
        return $target[0]
    }

    if ($windowed.Count -eq 0) {
        throw ("no window found for process $ProcessName - is the gallery still starting?")
    }

    if ($windowed.Count -gt 1) {
        throw ("$($windowed.Count) windows answer to '$ProcessName' (PIDs $(Format-Pids $windowed)); " +
            "a capture cannot say which one it photographed. Pass -ProcessId, or close the leftovers.")
    }

    return $windowed[0]
}

<#
.SYNOPSIS
Name the windows that were standing where the target should have been.

.DESCRIPTION
A refusal that only says "no" sends the reader to Task Manager. Naming the PIDs that DID have a window
is what turns the refusal into the diagnosis, and it is the part worth asserting in a test: it is the
difference between "the capture stopped" and "a leftover from the previous shot is still open".
#>
function Format-Foundling {
    param(
        [Parameter(Mandatory = $true)][string]$ProcessName,
        [Parameter(Mandatory = $true)][AllowEmptyCollection()][object[]]$Windowed
    )

    if ($Windowed.Count -eq 0) {
        return "Nothing else answering to '$ProcessName' has a window either."
    }

    return ("$($Windowed.Count) other window(s) answer to '$ProcessName' (PIDs " +
        "$(Format-Pids $Windowed)) - photographing one of those would be a picture of the wrong run.")
}

<#
.SYNOPSIS
Render candidate PIDs as a stable, comma-separated list.
#>
function Format-Pids {
    param([Parameter(Mandatory = $true)][AllowEmptyCollection()][object[]]$Candidates)
    return (($Candidates | ForEach-Object { $_.Id }) -join ', ')
}

Export-ModuleMember -Function Select-CaptureTarget
