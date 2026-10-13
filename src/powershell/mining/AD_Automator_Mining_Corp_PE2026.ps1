# src/powershell/mining/AD_Automator_Mining_Corp_PE2026.ps1
<#
.SYNOPSIS
    Framework Maestro de Automatización AD para CI/CD - Sector Minería Perú 2026.
.DESCRIPTION
    Automatiza la creación masiva de cuentas para contratistas, asignación a OUs por campamento,
    y optimización de replicación hacia zonas remotas (RODC). Cumplimiento OSINERGMIN y SUNAFIL.
.NOTES
    Autor: Joaquin Ocampo | CyberZenithAI
    Versión: 3.0.0-Enterprise
#>
#Requires -Version 5.1
#Requires -Modules ActiveDirectory
#Requires -RunAsAdministrator

[CmdletBinding()]
param (
    [Parameter(Mandatory=$false)][string]$CsvPath = ".\contractors_batch.csv",
    [Parameter(Mandatory=$false)][string]$SiemWebhookUrl = $env:SIEM_WEBHOOK_URL,
    [Parameter(Mandatory=$false)][switch]$LaunchGUI,
    [Parameter(Mandatory=$false)][switch]$CICDMode
)

$ErrorActionPreference = 'Stop'
. "$PSScriptRoot\..\shared\functions\Send-SIEMAuditLog.ps1"

function Invoke-ADContractorAutomation {
    param([string]$InputCsv)
    if (-not (Test-Path $InputCsv)) { throw "El archivo CSV de entrada no existe: $InputCsv" }
    
    $contractors = Import-Csv -Path $InputCsv -Encoding UTF8
    $validRoles = @("Operador", "Supervisor", "Ingeniero", "Seguridad", "Logistica", "Administrativo")
    
    foreach ($user in $contractors) {
        try {
            if ($user.Rol -notin $validRoles) { continue }
            
            $startDate = [datetime]::ParseExact($user.FechaInicio, "dd/MM/yyyy", $null)
            $endDate = [datetime]::ParseExact($user.FechaFin, "dd/MM/yyyy", $null)
            if ($endDate -le $startDate) { continue }

            $mineSite = $user.UnidadMinera -replace '\s', ''
            $targetOU = "OU=Contractors,OU=$mineSite,OU=MiningOps,DC=corp,DC=pe"
            
            if (-not (Get-ADOrganizationalUnit -Filter {DistinguishedName -eq $targetOU} -ErrorAction SilentlyContinue)) {
                New-ADOrganizationalUnit -Name $mineSite -Path "OU=MiningOps,DC=corp,DC=pe" -ProtectedFromAccidentalDeletion $true
                New-ADOrganizationalUnit -Name "Contractors" -Path "OU=$mineSite,OU=MiningOps,DC=corp,DC=pe" -ProtectedFromAccidentalDeletion $true
            }

            $samName = ($user.Nombres.Substring(0,1) + $user.Apellidos + $user.DNI.Substring($user.DNI.Length-2)).ToLower()
            if ($samName.Length -gt 20) { $samName = $samName.Substring(0,20) }
            
            if (-not (Get-ADUser -Filter {SamAccountName -eq $samName} -ErrorAction SilentlyContinue)) {
                $securePass = ConvertTo-SecureString -String $user.PasswordTemporal -AsPlainText -Force
                New-ADUser -Name "$($user.Nombres) $($user.Apellidos)" -SamAccountName $samName -Path $targetOU `
                           -AccountPassword $securePass -Enabled $true -ChangePasswordAtLogon $true -AccountExpirationDate $endDate `
                           -Replace @{extensionAttribute1=$user.DNI; extensionAttribute2=$user.EmpresaContratista}
                
                Send-SIEMAuditLog -Event "CONTRACTOR_CREATED" -Level "Success" -Target $samName -Metadata @{DNI=$user.DNI; Site=$mineSite}
            }
        } catch {
            Send-SIEMAuditLog -Event "CONTRACTOR_ERROR" -Level "Error" -Target $user.DNI -ErrorMessage $_.Exception.Message
        }
    }
}

function Optimize-RemoteReplication {
    $remoteSites = Get-ADReplicationSite -Filter {Name -like "Site_Camp_*"}
    foreach ($site in $remoteSites) {
        $siteLinks = Get-ADReplicationSiteLink -Filter "Sites -eq '$($site.Name)'"
        foreach ($link in $siteLinks) {
            Set-ADReplicationSiteLink -Identity $link.Name -ReplicationFrequencyInMinutes 180 -Cost 500 -ErrorAction SilentlyContinue
        }
    }
    Send-SIEMAuditLog -Event "REPLICATION_OPTIMIZED" -Level "Success" -Target "RemoteSites"
}

try {
    if ($CICDMode) {
        Invoke-ADContractorAutomation -InputCsv $CsvPath
        Optimize-RemoteReplication
    } else {
        Write-Host "Ejecución interactiva no soportada en este modo. Use -CICDMode o -LaunchGUI." -ForegroundColor Yellow
    }
} catch {
    Send-SIEMAuditLog -Event "FRAMEWORK_FAILURE" -Level "Critical" -ErrorMessage $_.Exception.Message
    exit 1
}
exit 0
