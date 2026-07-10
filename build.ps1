$ErrorActionPreference = "Stop"

$Binary = "moz-cloudflare-scanner"
$Module = "github.com/moz/moz-cloudflare-scanner"
$Cmd = "./cmd/moz-cloudflare-scanner"
$Version = "1.1"
$Commit = "none"
$BuildDate = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")

if (Get-Command git -ErrorAction SilentlyContinue) {
    $gitCommit = git rev-parse --short HEAD 2>$null
    if ($LASTEXITCODE -eq 0 -and $gitCommit) {
        $Commit = $gitCommit
    }
}

New-Item -ItemType Directory -Force -Path "dist" | Out-Null

$ldflags = @(
    "-s -w",
    "-X $Module/pkg/version.Version=$Version",
    "-X $Module/pkg/version.Commit=$Commit",
    "-X $Module/pkg/version.BuildDate=$BuildDate",
    "-X $Module/pkg/version.BuiltBy=build.ps1"
) -join " "

go build -trimpath -ldflags $ldflags -o "dist/$Binary.exe" $Cmd

Write-Host "Built dist/$Binary.exe"
