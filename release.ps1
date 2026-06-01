$ErrorActionPreference = "Stop"

& "$PSScriptRoot\build.ps1"

$Dist = Join-Path $PSScriptRoot "dist"
$PackageDir = Join-Path $Dist "release-package"
$ZipPath = Join-Path $Dist "moz-cloudflare-scanner-windows-amd64.zip"

if (Test-Path $PackageDir) {
    Remove-Item -Recurse -Force $PackageDir
}
New-Item -ItemType Directory -Force -Path $PackageDir | Out-Null

Copy-Item -Path (Join-Path $Dist "moz-cloudflare-scanner.exe") -Destination $PackageDir
Copy-Item -Path (Join-Path $PSScriptRoot "README.md") -Destination $PackageDir
Copy-Item -Path (Join-Path $PSScriptRoot "LICENSE") -Destination $PackageDir

if (Test-Path $ZipPath) {
    Remove-Item -Force $ZipPath
}
Compress-Archive -Path (Join-Path $PackageDir "*") -DestinationPath $ZipPath
Remove-Item -Recurse -Force $PackageDir

Write-Host "Created $ZipPath"
