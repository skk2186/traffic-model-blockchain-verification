param(
    [string]$ZokratesPath = '',
    [ValidateSet('real', 'mock')]
    [string]$ZkpMode = 'real',
    [ValidateSet('real', 'mock')]
    [string]$ThresholdSignatureMode = 'real',
    [ValidateSet('memory', 'mysql')]
    [string]$RecordStorage = 'mysql',
    [string]$MysqlUrl = '',
    [string]$MysqlUsername = '',
    [string]$MysqlPassword = '1085134460Sk',
    [ValidateSet('true', 'false')]
    [string]$MysqlInitializeSchema = 'true',
    [string]$MavenLocalRepository = ''
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$scriptDirectory = Split-Path -Parent $MyInvocation.MyCommand.Path
$repoRoot = Resolve-Path -LiteralPath (Join-Path $scriptDirectory '..')
$pomPath = Join-Path $repoRoot 'pom.xml'

if (-not (Test-Path -LiteralPath $pomPath)) {
    throw "pom.xml not found: $pomPath"
}

if ([string]::IsNullOrWhiteSpace($ZokratesPath)) {
    if (-not [string]::IsNullOrWhiteSpace($env:ZOKRATES_EXECUTABLE)) {
        $ZokratesPath = $env:ZOKRATES_EXECUTABLE
    } else {
        $trafficRoot = Split-Path -Parent $repoRoot
        $projectRoot = Split-Path -Parent $trafficRoot
        $ZokratesPath = Join-Path $projectRoot 'ZoKrates\target\release\zokrates.exe'
    }
}

if (-not (Test-Path -LiteralPath $ZokratesPath)) {
    throw "ZoKrates executable does not exist: $ZokratesPath"
}

$mvn = Get-Command mvn -ErrorAction SilentlyContinue
if ($null -eq $mvn) {
    throw "mvn command was not found. Please install Maven or add it to PATH."
}

if ([string]::IsNullOrWhiteSpace($MavenLocalRepository)) {
    $MavenLocalRepository = Join-Path $repoRoot '.m2\repository'
}

if ($RecordStorage -eq 'mysql') {
    if ([string]::IsNullOrWhiteSpace($MysqlUrl)) {
        if (-not [string]::IsNullOrWhiteSpace($env:VERIFICATION_RECORDS_MYSQL_URL)) {
            $MysqlUrl = $env:VERIFICATION_RECORDS_MYSQL_URL
        } else {
            $MysqlUrl = 'jdbc:mysql://127.0.0.1:3306/traffic_verification?useUnicode=true&characterEncoding=utf8&serverTimezone=Asia/Shanghai&useSSL=false&allowPublicKeyRetrieval=true'
        }
    }
    if ([string]::IsNullOrWhiteSpace($MysqlUsername)) {
        if (-not [string]::IsNullOrWhiteSpace($env:VERIFICATION_RECORDS_MYSQL_USERNAME)) {
            $MysqlUsername = $env:VERIFICATION_RECORDS_MYSQL_USERNAME
        } else {
            $MysqlUsername = 'root'
        }
    }
    if ([string]::IsNullOrWhiteSpace($MysqlPassword) -and -not [string]::IsNullOrWhiteSpace($env:VERIFICATION_RECORDS_MYSQL_PASSWORD)) {
        $MysqlPassword = $env:VERIFICATION_RECORDS_MYSQL_PASSWORD
    }
    if ([string]::IsNullOrWhiteSpace($MysqlPassword)) {
        Write-Warning "MySQL password is empty. If this MySQL account requires a password, pass -MysqlPassword or set VERIFICATION_RECORDS_MYSQL_PASSWORD. For a temporary local startup without record persistence, pass -RecordStorage memory."
    }
}

$env:ZOKRATES_EXECUTABLE = $ZokratesPath
$env:ZKP_MODE = $ZkpMode
$env:ZKP_ALLOW_LEGACY_MOCK = 'false'
$env:THRESHOLD_SIGNATURE_MODE = $ThresholdSignatureMode
$env:THRESHOLD_SIGNATURE_ALLOW_LEGACY_MOCK = 'false'
$env:VERIFICATION_RECORDS_STORAGE = $RecordStorage
$env:VERIFICATION_RECORDS_MYSQL_INITIALIZE_SCHEMA = $MysqlInitializeSchema
if ($RecordStorage -eq 'mysql') {
    $env:VERIFICATION_RECORDS_MYSQL_URL = $MysqlUrl
    $env:VERIFICATION_RECORDS_MYSQL_USERNAME = $MysqlUsername
    $env:VERIFICATION_RECORDS_MYSQL_PASSWORD = $MysqlPassword
}

Write-Host "Backend root: $repoRoot"
Write-Host "ZoKrates: $env:ZOKRATES_EXECUTABLE"
Write-Host "ZKP mode: $env:ZKP_MODE"
Write-Host "Threshold signature mode: $env:THRESHOLD_SIGNATURE_MODE"
Write-Host "Verification record storage: $env:VERIFICATION_RECORDS_STORAGE"
if ($RecordStorage -eq 'mysql') {
    Write-Host "Verification record MySQL URL: $env:VERIFICATION_RECORDS_MYSQL_URL"
    Write-Host "Verification record MySQL username: $env:VERIFICATION_RECORDS_MYSQL_USERNAME"
    Write-Host "Verification record MySQL initialize schema: $env:VERIFICATION_RECORDS_MYSQL_INITIALIZE_SCHEMA"
}
Write-Host "Maven local repository: $MavenLocalRepository"
Write-Host "Starting backend on http://127.0.0.1:8088 ..."

Push-Location -LiteralPath $repoRoot
try {
    & mvn -q "-Dmaven.repo.local=$MavenLocalRepository" spring-boot:run
    if ($LASTEXITCODE -ne 0) {
        if ($RecordStorage -eq 'mysql') {
            Write-Host ""
            Write-Host "Backend failed while MySQL record storage was enabled."
            Write-Host "Check that MySQL is running, database traffic_verification exists, and the username/password are correct."
            Write-Host "Examples:"
            Write-Host '  .\scripts\start-backend.ps1 -MysqlUsername root -MysqlPassword "<password>"'
            Write-Host '  .\scripts\start-backend.ps1 -RecordStorage memory'
        }
        throw "Backend exited with code $LASTEXITCODE"
    }
} finally {
    Pop-Location
}
