# scripts/setup-dev-environment.ps1
[CmdletBinding()]
param ()
begin { Set-StrictMode -Version Latest; $ErrorActionPreference = 'Stop' }
process {
    Write-Host "Setting up ZenithSec Dev Environment..." -ForegroundColor Cyan
    $Modules = @('Pester', 'PSScriptAnalyzer', 'Az.Accounts', 'Az.Resources')
    foreach ($mod in $Modules) {
        if (-not (Get-Module -ListAvailable -Name $mod)) {
            Install-Module -Name $mod -Scope CurrentUser -Force -AllowClobber
        }
        Import-Module $mod -Force
    }
    Write-Host "Environment ready. All security modules loaded." -ForegroundColor Green
}
