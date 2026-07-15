[CmdletBinding()]
param(
    [string]$ZokratesPath,
    [switch]$Force
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$circuitRoot = Split-Path -Parent $PSScriptRoot
$projectRoot = (Resolve-Path -LiteralPath (Join-Path $circuitRoot '..\..\..')).Path
if ([string]::IsNullOrWhiteSpace($ZokratesPath)) {
    $modelRoot = Split-Path -Parent (Split-Path -Parent $projectRoot)
    $ZokratesPath = Join-Path $modelRoot 'ZoKrates\target\release\zokrates.exe'
}
$zokratesRoot = (Resolve-Path -LiteralPath (Join-Path (Split-Path -Parent $ZokratesPath) '..\..')).Path
$standardLibraryPath = Join-Path $zokratesRoot 'zokrates_stdlib\stdlib'
$sourcePath = Join-Path $circuitRoot 'src\main.zok'
$runtimeDirectory = Join-Path $projectRoot 'runtime\zkp\traffic-speed-range-v1'
$outPath = Join-Path $runtimeDirectory 'out'
$r1csPath = Join-Path $runtimeDirectory 'out.r1cs'
$abiPath = Join-Path $runtimeDirectory 'abi.json'
$provingKeyPath = Join-Path $runtimeDirectory 'proving.key'
$verificationKeyPath = Join-Path $runtimeDirectory 'verification.key'
$publicKeyDirectory = Join-Path $circuitRoot 'keys'
$publicVerificationKeyPath = Join-Path $publicKeyDirectory 'verification.key'

if (-not (Test-Path -LiteralPath $ZokratesPath -PathType Leaf)) {
    throw "ZoKrates executable not found: $ZokratesPath"
}
if (-not (Test-Path -LiteralPath $sourcePath -PathType Leaf)) {
    throw "ZoKrates source file not found: $sourcePath"
}
if (-not (Test-Path -LiteralPath $standardLibraryPath -PathType Container)) {
    throw "ZoKrates standard library directory not found: $standardLibraryPath"
}
if ((Test-Path -LiteralPath $provingKeyPath -PathType Leaf) -or
    (Test-Path -LiteralPath $verificationKeyPath -PathType Leaf)) {
    if (-not $Force) {
        throw "Setup keys already exist in $runtimeDirectory. Re-run with -Force to replace them explicitly."
    }
}

New-Item -ItemType Directory -Path $runtimeDirectory -Force | Out-Null

Write-Host "Compiling circuit: $sourcePath"
& $ZokratesPath compile `
    --input $sourcePath `
    --output $outPath `
    --r1cs $r1csPath `
    --abi-spec $abiPath `
    --curve bn128 `
    --stdlib-path $standardLibraryPath
if ($LASTEXITCODE -ne 0) {
    throw "ZoKrates compile failed with exit code $LASTEXITCODE"
}

Write-Host 'Generating Groth16 setup keys (scheme=g16, backend=ark)...'
& $ZokratesPath setup `
    --input $outPath `
    --proving-scheme g16 `
    --backend ark `
    --proving-key-path $provingKeyPath `
    --verification-key-path $verificationKeyPath
if ($LASTEXITCODE -ne 0) {
    throw "ZoKrates setup failed with exit code $LASTEXITCODE"
}

foreach ($requiredPath in @($outPath, $abiPath, $provingKeyPath, $verificationKeyPath)) {
    if (-not (Test-Path -LiteralPath $requiredPath -PathType Leaf)) {
        throw "Expected build artifact was not generated: $requiredPath"
    }
}

New-Item -ItemType Directory -Path $publicKeyDirectory -Force | Out-Null
Copy-Item -LiteralPath $verificationKeyPath -Destination $publicVerificationKeyPath -Force
if (-not (Test-Path -LiteralPath $publicVerificationKeyPath -PathType Leaf)) {
    throw "Public verification key was not provisioned: $publicVerificationKeyPath"
}

Write-Host "ZoKrates build completed: $runtimeDirectory"
Write-Host "Public verification key provisioned: $publicVerificationKeyPath"
