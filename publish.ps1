# Baut dist\ClipSec-Setup.exe – eine einzige EXE:
#  • Doppelklick → Installationsassistent (pro Benutzer, keine Adminrechte)
#  • "Ohne Installation starten" → portable Nutzung
# Zusätzlich: dist\SHA256SUMS.txt und dist\latest.json (für Webseite & Releases).
param(
    [string]$Version,              # Standard: <Version> aus ClipSec.csproj (CI übergibt die Tag-Version)
    [switch]$FrameworkDependent
)

$ErrorActionPreference = 'Stop'
$project = Join-Path $PSScriptRoot 'ClipSec\ClipSec.csproj'
$out = Join-Path $PSScriptRoot 'dist'
$tmp = Join-Path $out '_publish'

if (-not $Version) { $Version = ([xml](Get-Content $project)).Project.PropertyGroup.Version | Where-Object { $_ } | Select-Object -First 1 }
$Version = $Version.TrimStart('v')

$common = @('-c', 'Release', '-r', 'win-x64', '-p:PublishSingleFile=true', '-p:DebugType=none', "-p:Version=$Version", '-o', $tmp)
if ($FrameworkDependent) {
    # ~1 MB, benötigt die ".NET 8 Desktop Runtime" auf dem Zielrechner
    dotnet publish $project --self-contained false @common
} else {
    # Läuft ohne installiertes .NET, dafür größer
    dotnet publish $project --self-contained true -p:IncludeNativeLibrariesForSelfExtract=true `
        -p:EnableCompressionInSingleFile=true @common
}
if ($LASTEXITCODE -ne 0) { throw "Build fehlgeschlagen." }

# Der Dateiname schaltet den Installer-Modus ein.
$setup = Join-Path $out 'ClipSec-Setup.exe'
Move-Item (Join-Path $tmp 'ClipSec.exe') $setup -Force
Remove-Item $tmp -Recurse -Force

# Alte portable EXE aus Version 1.0 aufräumen (falls sie gerade läuft, bleibt sie liegen).
$old = Join-Path $out 'ClipSec.exe'
if (Test-Path $old) {
    try { Remove-Item $old -Force } catch { Write-Warning "dist\ClipSec.exe läuft noch und wurde nicht gelöscht." }
}

# Prüfsummen + Manifest für die Webseite
$hash = (Get-FileHash $setup -Algorithm SHA256).Hash.ToLowerInvariant()
$size = (Get-Item $setup).Length
"$hash  ClipSec-Setup.exe" | Set-Content (Join-Path $out 'SHA256SUMS.txt') -Encoding ascii
[ordered]@{
    version = $Version
    tag     = "v$Version"
    file    = 'ClipSec-Setup.exe'
    url     = 'ClipSec-Setup.exe'
    size    = $size
    sha256  = $hash
    date    = (Get-Date -Format 'yyyy-MM-dd')
} | ConvertTo-Json | Set-Content (Join-Path $out 'latest.json') -Encoding utf8

Write-Host "`nFertig: $setup"
Write-Host "Version $Version · $([math]::Round($size / 1MB, 1)) MB · SHA-256 $hash"
