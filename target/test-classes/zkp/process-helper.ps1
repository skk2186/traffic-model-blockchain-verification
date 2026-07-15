param(
    [Parameter(Mandatory = $true)]
    [string]$Mode
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

switch ($Mode) {
    'echo' {
        [Console]::Out.WriteLine('standard-output')
        [Console]::Error.WriteLine('standard-error')
        exit 0
    }
    'nonzero' {
        [Console]::Error.WriteLine('intentional-nonzero')
        exit 7
    }
    'timeout' {
        Start-Sleep -Seconds 10
        exit 0
    }
    'flood' {
        [Console]::Out.WriteLine(('O' * 4096))
        [Console]::Error.WriteLine(('E' * 4096))
        exit 0
    }
    'working-directory' {
        [Console]::Out.WriteLine((Get-Location).Path)
        Set-Content -LiteralPath (Join-Path (Get-Location).Path 'temporary-proof.json') -Value '{}'
        exit 0
    }
    default {
        [Console]::Error.WriteLine("unsupported mode: $Mode")
        exit 9
    }
}
