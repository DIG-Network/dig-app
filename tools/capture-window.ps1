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

.PARAMETER ProcessName
The process whose main window to photograph, e.g. `pane_preview`.

.PARAMETER Out
Where to write the PNG.

.EXAMPLE
  cargo run -p dig-app-core --features gui --example pane_preview -- settings light 960 640
  pwsh tools/capture-window.ps1 -ProcessName pane_preview -Out settings-light-960x640.png
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$ProcessName,
    [Parameter(Mandatory = $true)][string]$Out
)

$ErrorActionPreference = 'Stop'

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

$process = Get-Process -Name $ProcessName -ErrorAction SilentlyContinue |
    Where-Object { $_.MainWindowHandle -ne 0 } |
    Select-Object -First 1

if (-not $process) {
    throw ("no window found for process " + $ProcessName + " - is the gallery still starting?")
}

$shot = [WindowShot]::Capture($process.MainWindowHandle)
$size = "" + $shot.Width + " x " + $shot.Height
$full = [System.IO.Path]::GetFullPath($Out)
[System.IO.Directory]::CreateDirectory([System.IO.Path]::GetDirectoryName($full)) | Out-Null
$shot.Save($full, [System.Drawing.Imaging.ImageFormat]::Png)
$shot.Dispose()

Write-Output ($full + " -- " + $size + " physical px")
