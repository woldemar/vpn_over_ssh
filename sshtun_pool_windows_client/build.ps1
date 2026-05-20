param(
    [string]$WintunVersion = "0.14.1",
    [string]$OutDir = "dist",
    [ValidateSet("amd64", "arm64", "386")]
    [string]$Arch = "amd64"
)

$ErrorActionPreference = "Stop"

function Require-Command($Name) {
    if (-not (Get-Command $Name -ErrorAction SilentlyContinue)) {
        throw "Required command not found: $Name"
    }
}

Require-Command go

$Root = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $Root

$Dist = Join-Path $Root $OutDir
$Deps = Join-Path $Root ".deps"
$WintunZip = Join-Path $Deps "wintun-$WintunVersion.zip"
$WintunExtract = Join-Path $Deps "wintun-$WintunVersion"

New-Item -ItemType Directory -Force -Path $Dist | Out-Null
New-Item -ItemType Directory -Force -Path $Deps | Out-Null

$WintunUrl = "https://www.wintun.net/builds/wintun-$WintunVersion.zip"

if (-not (Test-Path $WintunZip)) {
    Write-Host "Downloading Wintun from $WintunUrl"
    Invoke-WebRequest -Uri $WintunUrl -OutFile $WintunZip
}

if (Test-Path $WintunExtract) {
    Remove-Item -Recurse -Force $WintunExtract
}
New-Item -ItemType Directory -Force -Path $WintunExtract | Out-Null
Expand-Archive -Force -Path $WintunZip -DestinationPath $WintunExtract

$DllArch = switch ($Arch) {
    "amd64" { "amd64" }
    "arm64" { "arm64" }
    "386"   { "x86" }
}

$Dll = Get-ChildItem -Path $WintunExtract -Recurse -Filter "wintun.dll" |
    Where-Object { $_.FullName -match "\\bin\\$DllArch\\wintun\.dll$" } |
    Select-Object -First 1

if (-not $Dll) {
    throw "Cannot find wintun.dll for arch $DllArch in downloaded archive"
}

Copy-Item -Force $Dll.FullName (Join-Path $Dist "wintun.dll")

Write-Host "Resolving Go modules"
go mod tidy

$env:GOOS = "windows"
$env:GOARCH = $Arch
$env:CGO_ENABLED = "0"

$OutExe = Join-Path $Dist "sshtun_pool_client.exe"
Write-Host "Building $OutExe"
go build -trimpath -ldflags "-s -w" -o $OutExe .\cmd\sshtun_pool_client

Write-Host ""
Write-Host "OK"
Write-Host "  $OutExe"
Write-Host "  $(Join-Path $Dist 'wintun.dll')"
Write-Host ""
Write-Host "Run PowerShell as Administrator, then:"
Write-Host "  .\dist\sshtun_pool_client.exe start --host SERVER_IP --key .\id_ed25519"
