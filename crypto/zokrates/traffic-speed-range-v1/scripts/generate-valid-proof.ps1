[CmdletBinding()]
param(
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
$runtimeDirectory = Join-Path $projectRoot 'runtime\zkp\traffic-speed-range-v1'
$validFixtureDirectory = Join-Path $circuitRoot 'fixtures\valid'
$invalidFixtureDirectory = Join-Path $circuitRoot 'fixtures\invalid-public-input'
$outPath = Join-Path $runtimeDirectory 'out'
$abiPath = Join-Path $runtimeDirectory 'abi.json'
$provingKeyPath = Join-Path $runtimeDirectory 'proving.key'
$witnessPath = Join-Path $runtimeDirectory 'witness'
$circomWitnessPath = Join-Path $runtimeDirectory 'out.wtns'
$proofPath = Join-Path $runtimeDirectory 'proof.json'

foreach ($requiredPath in @($ZokratesPath, $outPath, $abiPath, $provingKeyPath)) {
    if (-not (Test-Path -LiteralPath $requiredPath -PathType Leaf)) {
        throw "Required file not found: $requiredPath"
    }
}

New-Item -ItemType Directory -Path $validFixtureDirectory -Force | Out-Null
New-Item -ItemType Directory -Path $invalidFixtureDirectory -Force | Out-Null

Write-Host 'Computing witness for speed=60, minSpeed=30, maxSpeed=80...'
& $ZokratesPath compute-witness `
    --input $outPath `
    --output $witnessPath `
    --circom-witness $circomWitnessPath `
    --abi-spec $abiPath `
    --arguments 60 30 80
if ($LASTEXITCODE -ne 0) {
    throw "ZoKrates compute-witness failed with exit code $LASTEXITCODE"
}

Write-Host 'Generating Groth16 proof...'
& $ZokratesPath generate-proof `
    --input $outPath `
    --witness $witnessPath `
    --proving-key-path $provingKeyPath `
    --proof-path $proofPath `
    --proving-scheme g16 `
    --backend ark
if ($LASTEXITCODE -ne 0) {
    throw "ZoKrates generate-proof failed with exit code $LASTEXITCODE"
}
if (-not (Test-Path -LiteralPath $proofPath -PathType Leaf)) {
    throw "Expected proof file was not generated: $proofPath"
}

$validProofPath = Join-Path $validFixtureDirectory 'proof.json'
$validSignalsPath = Join-Path $validFixtureDirectory 'public-signals.json'
$invalidProofPath = Join-Path $invalidFixtureDirectory 'proof.json'
$invalidSignalsPath = Join-Path $invalidFixtureDirectory 'public-signals.json'

Copy-Item -LiteralPath $proofPath -Destination $validProofPath -Force
$proofDocument = Get-Content -LiteralPath $proofPath -Raw -Encoding UTF8 | ConvertFrom-Json
if ($null -eq $proofDocument.inputs -or @($proofDocument.inputs).Count -eq 0) {
    throw 'Generated proof does not contain public inputs.'
}
$validSignalsJson = ConvertTo-Json -InputObject @($proofDocument.inputs) -Depth 10
[System.IO.File]::WriteAllText($validSignalsPath, $validSignalsJson, [System.Text.UTF8Encoding]::new($false))

$invalidDocument = Get-Content -LiteralPath $proofPath -Raw -Encoding UTF8 | ConvertFrom-Json
$originalInput = [string]@($invalidDocument.inputs)[0]
if ($originalInput.Length -lt 1) {
    throw 'Generated proof contains an empty public input.'
}
$replacement = if ($originalInput.EndsWith('0')) { '1' } else { '0' }
$invalidDocument.inputs[0] = $originalInput.Substring(0, $originalInput.Length - 1) + $replacement
$invalidProofJson = ConvertTo-Json -InputObject $invalidDocument -Depth 20
[System.IO.File]::WriteAllText($invalidProofPath, $invalidProofJson, [System.Text.UTF8Encoding]::new($false))
$invalidSignalsJson = ConvertTo-Json -InputObject @($invalidDocument.inputs) -Depth 10
[System.IO.File]::WriteAllText($invalidSignalsPath, $invalidSignalsJson, [System.Text.UTF8Encoding]::new($false))

foreach ($fixturePath in @($validProofPath, $validSignalsPath, $invalidProofPath, $invalidSignalsPath)) {
    if (-not (Test-Path -LiteralPath $fixturePath -PathType Leaf)) {
        throw "Expected fixture was not generated: $fixturePath"
    }
}

Write-Host "Valid and invalid-public-input fixtures generated under: $($circuitRoot)"
