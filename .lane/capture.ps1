# Photograph one dialog-gallery window with PrintWindow(PW_RENDERFULLCONTENT). No input is driven at
# the window: it is launched, found by owning process, rendered to a bitmap, and the process is killed.
param(
  [Parameter(Mandatory = $true)][string]$Screen,
  [Parameter(Mandatory = $true)][string]$Out,
  [string]$Arg = ""
)

Add-Type -AssemblyName System.Drawing
Add-Type @"
using System;
using System.Runtime.InteropServices;
public class Cap {
  [DllImport("user32.dll")] public static extern bool PrintWindow(IntPtr h, IntPtr dc, uint flags);
  [DllImport("user32.dll")] public static extern bool GetWindowRect(IntPtr h, out RECT r);
  [DllImport("user32.dll")] public static extern bool IsWindowVisible(IntPtr h);
  [DllImport("user32.dll")] public static extern int GetWindowThreadProcessId(IntPtr h, out uint pid);
  [DllImport("user32.dll")] public static extern bool EnumWindows(EnumProc cb, IntPtr p);
  [DllImport("user32.dll")] public static extern int SetProcessDpiAwarenessContext(IntPtr c);
  public delegate bool EnumProc(IntPtr h, IntPtr p);
  [StructLayout(LayoutKind.Sequential)] public struct RECT { public int L, T, R, B; }
}
"@

# -4 = DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2. Without it this process is DPI-virtualised and
# photographs the wrong rectangle at the wrong scale.
[void][Cap]::SetProcessDpiAwarenessContext([IntPtr](-4))

# The already-built example, run directly: a `cargo run` wrapper would own the process the window is
# NOT on, and the search below keys on the owning pid.
$exe = Join-Path $PSScriptRoot '../target/debug/examples/dialog_gallery.exe'
$proc = Start-Process -PassThru -FilePath $exe -ArgumentList @($Screen, $Arg)
Start-Sleep -Seconds 6

$script:found = [IntPtr]::Zero
$script:pids = @($proc.Id)
$cb = [Cap+EnumProc] {
  param($h, $p)
  $owner = 0
  [void][Cap]::GetWindowThreadProcessId($h, [ref]$owner)
  if ($script:pids -contains $owner -and [Cap]::IsWindowVisible($h)) {
    $r = New-Object Cap+RECT
    [void][Cap]::GetWindowRect($h, [ref]$r)
    if (($r.R - $r.L) -gt 200 -and ($r.B - $r.T) -gt 120) { $script:found = $h; return $false }
  }
  return $true
}
[void][Cap]::EnumWindows($cb, [IntPtr]::Zero)

if ($script:found -eq [IntPtr]::Zero) {
  Write-Error "no window found for $Screen $Arg"
  Stop-Process -Id $proc.Id -Force -ErrorAction SilentlyContinue
  exit 1
}

$r = New-Object Cap+RECT
[void][Cap]::GetWindowRect($script:found, [ref]$r)
$w = $r.R - $r.L; $h = $r.B - $r.T
$bmp = New-Object System.Drawing.Bitmap($w, $h)
$g = [System.Drawing.Graphics]::FromImage($bmp)
$dc = $g.GetHdc()
# 2 = PW_RENDERFULLCONTENT, which renders a composited/GL window that a plain PrintWindow leaves blank.
[void][Cap]::PrintWindow($script:found, $dc, 2)
$g.ReleaseHdc($dc)
$bmp.Save($Out, [System.Drawing.Imaging.ImageFormat]::Png)
$g.Dispose(); $bmp.Dispose()
Stop-Process -Id $proc.Id -Force -ErrorAction SilentlyContinue
Get-Process dialog_gallery -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
Write-Output "$Out ${w}x${h}"
