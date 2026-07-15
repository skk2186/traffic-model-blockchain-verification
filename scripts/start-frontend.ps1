param(
    [string]$FrontendRoot = ''
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$scriptDirectory = Split-Path -Parent $MyInvocation.MyCommand.Path
$backendRoot = Resolve-Path -LiteralPath (Join-Path $scriptDirectory '..')

if ([string]::IsNullOrWhiteSpace($FrontendRoot)) {
    $trafficRoot = Split-Path -Parent $backendRoot
    $FrontendRoot = Join-Path $trafficRoot 'traffic-model-blockchain-web'
}

if (-not (Test-Path -LiteralPath $FrontendRoot)) {
    throw "Frontend project directory does not exist: $FrontendRoot"
}

$packageJson = Join-Path $FrontendRoot 'package.json'
if (-not (Test-Path -LiteralPath $packageJson)) {
    throw "package.json not found: $packageJson"
}

$npm = Get-Command npm -ErrorAction SilentlyContinue
if ($null -eq $npm) {
    throw "npm command was not found. Please install Node.js/npm or add it to PATH."
}

Write-Host "Backend root: $backendRoot"
Write-Host "Frontend root: $FrontendRoot"
Write-Host "Starting frontend dev server ..."

Push-Location -LiteralPath $FrontendRoot
try {
    & npm run dev
    if ($LASTEXITCODE -ne 0) {
        throw "Frontend exited with code $LASTEXITCODE"
    }
} finally {
    Pop-Location
}
