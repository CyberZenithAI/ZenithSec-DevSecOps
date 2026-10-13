# src/powershell/financial/Invoke-NAIF_AD_Automation.ps1
<#
.SYNOPSIS
    Núcleo de Automatización de Identidades Financieras (NAIF-PE) para Active Directory.
.DESCRIPTION
    Motor avanzado para la gestión del ciclo de vida de identidades en el sector financiero peruano.
    Cumple con normativas SBS, SMV, ISO 27001, ISO 27701.
.NOTES
    Autor: Joaquin Ocampo | CyberZenithAI
    Versión: 2026.1.0-PROD
#>
#Requires -Version 5.1
#Requires -Modules ActiveDirectory

[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)]
    [ValidateSet('Offboard', 'PrivilegeAudit', 'PasswordExpiry', 'BranchLogonControl')]
    [string]$Action,

    [Parameter(Mandatory=$false)][string]$InputFilePath,
    [Parameter(Mandatory=$false)][string]$TargetOU,
    [Parameter(Mandatory=$false)][ValidateRange(0,23)][int]$LogonStartHour = 8,
    [Parameter(Mandatory=$false)][ValidateRange(0,23)][int]$LogonEndHour = 18
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 -bor [Net.SecurityProtocolType]::Tls13

. "$PSScriptRoot\..\shared\functions\Send-SIEMAuditLog.ps1"

function Invoke-Offboarding {
    param([string]$File)
    if (-not (Test-Path $File)) { throw "Archivo de entrada no encontrado: $File" }
    $cesados = Import-Csv -Path $File -Encoding UTF8
    foreach ($user in $cesados) {
        $adUser = Get-ADUser -Filter "EmployeeID -eq '$($user.ID_Empleado)'" -Properties DistinguishedName
        if ($adUser) {
            Disable-ADAccount -Identity $adUser.SamAccountName
            $newPass = -join ((65..90) + (97..122) + (48..57) | Get-Random -Count 32 | ForEach-Object {[char]$_})
            Set-ADAccountPassword -Identity $adUser.SamAccountName -NewPassword (ConvertTo-SecureString $newPass -AsPlainText -Force) -Reset
            Move-ADObject -Identity $adUser.DistinguishedName -TargetPath "OU=Cesados,OU=Usuarios,DC=empresa,DC=com,DC=pe"
            Send-SIEMAuditLog -Event "Offboarding" -Level "Success" -Target $adUser.SamAccountName
        }
    }
}

function Invoke-PrivilegeAudit {
    $privGroups = @("Domain Admins", "Enterprise Admins", "Schema Admins")
    $currentMembers = foreach ($group in $privGroups) {
        Get-ADGroupMember -Identity $group -Recursive | Select-Object SamAccountName
    }
    $currentHash = ($currentMembers | ConvertTo-Json | Get-FileHash -Algorithm SHA256).Hash
    Send-SIEMAuditLog -Event "PrivilegeAudit" -Level "Information" -Metadata @{Hash = $currentHash}
    return @{ Status = "Success"; Hash = $currentHash }
}

$executionResult = @{ Timestamp = (Get-Date).ToUniversalTime().ToString("o"); Action = $Action; Status = "Success"; Details = $null }

try {
    switch ($Action) {
        'Offboard'          { $executionResult.Details = Invoke-Offboarding -File $InputFilePath }
        'PrivilegeAudit'    { $executionResult.Details = Invoke-PrivilegeAudit }
        'BranchLogonControl'{ 
            $bytes = New-Object byte[] 21
            for ($day = 0; $day -lt 7; $day++) {
                for ($hour = $LogonStartHour; $hour -lt $LogonEndHour; $hour++) {
                    $bitIndex = ($day * 24) + $hour
                    $bytes[[math]::Floor($bitIndex / 8)] = $bytes[[math]::Floor($bitIndex / 8)] -bor (1 -shl ($bitIndex % 8))
                }
            }
            Get-ADUser -SearchBase $TargetOU -Filter {Enabled -eq $true} | ForEach-Object {
                Set-ADUser -Identity $_.SamAccountName -Replace @{logonHours=$bytes}
            }
            $executionResult.Details = @{ Status = "Success"; OU = $TargetOU }
        }
    }
} catch {
    $executionResult.Status = "Failed"
    $executionResult.Details = $_.Exception.Message
    Send-SIEMAuditLog -Event "PipelineFailure" -Level "Critical" -ErrorMessage $_.Exception.Message
    Write-Output ($executionResult | ConvertTo-Json -Depth 5)
    exit 1
}

Write-Output ($executionResult | ConvertTo-Json -Depth 5)
exit 0
