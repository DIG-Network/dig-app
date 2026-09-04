<#
.SYNOPSIS
Photograph a window this repo's galleries opened, without touching the mouse or keyboard.

.DESCRIPTION
`PrintWindow` with `PW_RENDERFULLCONTENT`, after the capturing process has declared itself
per-monitor DPI aware -- the posture dig-app itself runs in, so the pixels here are the pixels a
person sees rather than a DPI-virtualised approximation.

No synthetic input is used, deliberately. A committed screenshot is a claim about what the
application draws; driving a click to reach the thing being photographed can steal foreground and
capture whatever was behind the window (dig_ecosystem#2309). The galleries take what to show as an
argument instead, so nothing has to be clicked.

WHICH window gets photographed is decided by `capture-target.psm1` and tested without a display; see
`capture-target.tests.ps1` for why the rule is an identity check rather than a headcount.

.PARAMETER ProcessName
The process whose main window to photograph, e.g. `pane_preview`.

.PARAMETER ProcessId
The process the caller started. Supply it whenever it is known -- it is the only thing that makes the
capture a picture of THIS run rather than of whatever else answers to the same name. A script that
launched the process always knows it; the by-hand form below does not, and falls back to refusing on
ambiguity.

.PARAMETER Out
Where to write the PNG.

.EXAMPLE
  cargo run -p dig-app-core --features gui --example pane_preview -- settings light 960 640
  pwsh tools/capture-window.ps1 -ProcessName pane_preview -Out settings-light-960x640.png

.EXAMPLE
  $proc = Start-Process -FilePath $exe -ArgumentList $args -PassThru
  pwsh tools/capture-window.ps1 -ProcessName pane_preview -ProcessId $proc.Id -Out shot.png
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$ProcessName,
    [int]$ProcessId = 0,
    [Parameter(Mandatory = $true)][string]$Out
)

$ErrorActionPreference = 'Stop'

Import-Module (Join-Path $PSScriptRoot 'capture-target.psm1') -Force

Add-Type -AssemblyName System.Drawing

Add-Type @'
using System;
using System.Drawing;
using System.Runtime.InteropServices;

public static class WindowShot
{
    [DllImport("user32.dll")]
    private static extern bool PrintWindow(IntPtr hwnd, IntPtr hdc, uint flags);

    [DllImport("user32.dll")]
    private static extern bool GetWindowRect(IntPtr hwnd, out RECT rect);

    [DllImport("user32.dll")]
    private static extern bool SetProcessDpiAwarenessContext(IntPtr context);

    [StructLayout(LayoutKind.Sequential)]
    private struct RECT { public int Left, Top, Right, Bottom; }

    // DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2, the context the tray sets for dig-app.
    private static readonly IntPtr PerMonitorV2 = new IntPtr(-4);
    // PW_RENDERFULLCONTENT: ask the window to render its whole client area, including the parts a
    // compositor would otherwise leave out.
    private const uint RenderFullContent = 0x00000002;

    public static Bitmap Capture(IntPtr hwnd)
    {
        SetProcessDpiAwarenessContext(PerMonitorV2);
        RECT r;
        if (!GetWindowRect(hwnd, out r)) { throw new Exception("the window has no rectangle"); }
        int width = r.Right - r.Left;
        int height = r.Bottom - r.Top;
        Bitmap shot = new Bitmap(width, height);
        using (Graphics g = Graphics.FromImage(shot))
        {
            IntPtr hdc = g.GetHdc();
            try
            {
                if (!PrintWindow(hwnd, hdc, RenderFullContent))
                {
                    throw new Exception("PrintWindow refused this window");
                }
            }
            finally { g.ReleaseHdc(hdc); }
        }
        return shot;
    }
}
'@ -ReferencedAssemblies System.Drawing, System.Drawing.Primitives

# Unfiltered on purpose: the selection rule needs to see a target that is RUNNING BUT NOT YET PAINTED,
# and a `MainWindowHandle -ne 0` filter here would erase exactly that case -- leaving a stale window as
# the only candidate and making it indistinguishable from the one the caller asked for.
$candidates = @(Get-Process -Name $ProcessName -ErrorAction SilentlyContinue)

$process = Select-CaptureTarget -ProcessName $ProcessName -ProcessId $ProcessId -Candidates $candidates

$shot = [WindowShot]::Capture($process.MainWindowHandle)
$size = "" + $shot.Width + " x " + $shot.Height
$full = [System.IO.Path]::GetFullPath($Out)
[System.IO.Directory]::CreateDirectory([System.IO.Path]::GetDirectoryName($full)) | Out-Null
$shot.Save($full, [System.Drawing.Imaging.ImageFormat]::Png)
$shot.Dispose()

Write-Output ($full + " -- " + $size + " physical px")
