[CmdletBinding()]
param(
    [string]$ProofPath,
    [string]$VerificationKeyPath,
    [string]$ZokratesPath
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$circuitRoot = Split-Path -Parent $PSScriptRoot
$projectRoot = (Resolve-Path -LiteralPath (Join-Path $circuitRoot '..\..\..')).Path
if ([string]::IsNullOrWhiteSpace($ZokratesPath)) {
    $modelRoot = Split-Path -Parent (Split-Path -Parent $projectRoot)
    $ZokratesPath = Join-Path $modelRoot 'ZoKrates\target\release\zokrates.exe'
}
if ([string]::IsNullOrWhiteSpace($ProofPath)) {
    $ProofPath = Join-Path $circuitRoot 'fixtures\valid\proof.json'
}
if ([string]::IsNullOrWhiteSpace($VerificationKeyPath)) {
    $VerificationKeyPath = Join-Path $circuitRoot 'keys\verification.key'
}

foreach ($requiredPath in @($ZokratesPath, $ProofPath, $VerificationKeyPath)) {
    if (-not (Test-Path -LiteralPath $requiredPath -PathType Leaf)) {
        throw "Required file not found: $requiredPath"
    }
}

$verificationOutput = @(& $ZokratesPath verify `
    --proof-path $ProofPath `
    --verification-key-path $VerificationKeyPath `
    --backend ark 2>&1)
$exitCode = $LASTEXITCODE
$verificationOutput | ForEach-Object { Write-Host $_.ToString() }
if ($exitCode -ne 0) {
    throw "ZoKrates verify failed with exit code $exitCode"
}
$passed = @($verificationOutput | Where-Object { $_.ToString().Trim() -eq 'PASSED' }).Count -gt 0
if (-not $passed) {
    throw 'ZoKrates completed but reported that the proof is invalid.'
}

Write-Host 'ZoKrates proof verification passed.'
