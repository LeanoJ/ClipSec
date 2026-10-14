# Erzeugt Assets\clipsec.ico (Zwischenablage mit Schloss) in mehreren Größen.
param([string]$Out = (Join-Path $PSScriptRoot '..\ClipSec\Assets\clipsec.ico'))

Add-Type -AssemblyName System.Drawing

function New-RoundedPath([float]$x, [float]$y, [float]$w, [float]$h, [float]$r) {
    $p = New-Object System.Drawing.Drawing2D.GraphicsPath
    $d = 2 * $r
    $p.AddArc($x, $y, $d, $d, 180, 90)
    $p.AddArc($x + $w - $d, $y, $d, $d, 270, 90)
    $p.AddArc($x + $w - $d, $y + $h - $d, $d, $d, 0, 90)
    $p.AddArc($x, $y + $h - $d, $d, $d, 90, 90)
    $p.CloseFigure()
    return $p
}

function New-IconPng([int]$s) {
    $bmp = New-Object System.Drawing.Bitmap $s, $s, ([System.Drawing.Imaging.PixelFormat]::Format32bppArgb)
    $g = [System.Drawing.Graphics]::FromImage($bmp)
    $g.SmoothingMode = 'AntiAlias'
    $g.PixelOffsetMode = 'HighQuality'
    $g.Clear([System.Drawing.Color]::Transparent)
    $u = $s / 32.0

    # Hintergrund: abgerundetes Quadrat mit Verlauf
    $bg = New-RoundedPath (1*$u) (1*$u) (30*$u) (30*$u) (7*$u)
    $rect = New-Object System.Drawing.RectangleF 0, 0, $s, $s
    $grad = New-Object System.Drawing.Drawing2D.LinearGradientBrush $rect, ([System.Drawing.Color]::FromArgb(255, 59, 130, 246)), ([System.Drawing.Color]::FromArgb(255, 29, 78, 216)), 90
    $g.FillPath($grad, $bg)

    # Klemmbrett
    $white = New-Object System.Drawing.SolidBrush ([System.Drawing.Color]::White)
    $board = New-RoundedPath (8*$u) (6.5*$u) (16*$u) (20*$u) (2.5*$u)
    $g.FillPath($white, $board)
    $clip = New-RoundedPath (12*$u) (4.5*$u) (8*$u) (4.5*$u) (1.5*$u)
    $dark = New-Object System.Drawing.SolidBrush ([System.Drawing.Color]::FromArgb(255, 30, 58, 138))
    $g.FillPath($dark, $clip)

    # Schloss
    $blue = New-Object System.Drawing.SolidBrush ([System.Drawing.Color]::FromArgb(255, 37, 99, 235))
    $penW = [Math]::Max(1.0, 2.0*$u)
    $pen = New-Object System.Drawing.Pen ([System.Drawing.Color]::FromArgb(255, 37, 99, 235)), $penW
    $g.DrawArc($pen, (12.5*$u), (11.5*$u), (7*$u), (8*$u), 180, 180)
    $g.DrawLine($pen, (12.5*$u), (15.5*$u), (12.5*$u), (17*$u))
    $g.DrawLine($pen, (19.5*$u), (15.5*$u), (19.5*$u), (17*$u))
    $body = New-RoundedPath (11*$u) (16.5*$u) (10*$u) (7.5*$u) (1.5*$u)
    $g.FillPath($blue, $body)
    if ($s -ge 24) {
        $g.FillEllipse($white, (15*$u), (18.5*$u), (2*$u), (2*$u))
        $g.FillRectangle($white, (15.6*$u), (19.5*$u), (0.8*$u), (2.5*$u))
    }

    $g.Dispose()
    $ms = New-Object System.IO.MemoryStream
    $bmp.Save($ms, [System.Drawing.Imaging.ImageFormat]::Png)
    $bmp.Dispose()
    return ,$ms.ToArray()
}

$sizes = 16, 20, 24, 32, 40, 48, 64, 256
$images = foreach ($s in $sizes) { ,(New-IconPng $s) }

New-Item -ItemType Directory -Force (Split-Path $Out) | Out-Null
$fs = [System.IO.File]::Create($Out)
$bw = New-Object System.IO.BinaryWriter $fs
$bw.Write([UInt16]0); $bw.Write([UInt16]1); $bw.Write([UInt16]$sizes.Count)
$offset = 6 + 16 * $sizes.Count
for ($i = 0; $i -lt $sizes.Count; $i++) {
    $s = $sizes[$i]; $data = $images[$i]
    $dim = if ($s -ge 256) { 0 } else { $s }
    $bw.Write([byte]$dim); $bw.Write([byte]$dim); $bw.Write([byte]0); $bw.Write([byte]0)
    $bw.Write([UInt16]1); $bw.Write([UInt16]32)
    $bw.Write([UInt32]$data.Length); $bw.Write([UInt32]$offset)
    $offset += $data.Length
}
foreach ($data in $images) { $bw.Write([byte[]]$data) }
$bw.Dispose()
Write-Host "Icon geschrieben: $Out"
