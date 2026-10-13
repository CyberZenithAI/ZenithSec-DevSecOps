# src/powershell/government/Invoke-ADMasterFramework.ps1
<#
.SYNOPSIS
    Framework Maestro de Automatización CI/CD para Active Directory (Gobierno Digital & Sector Financiero PE 2026).
.DESCRIPTION
    Orquestador avanzado para el ciclo de vida de identidades, depuración de locadores (CAS), 
    creación estandarizada PCM, y auditoría de sistemas críticos (SIAF/SIGA).
.NOTES
    Autor: Joaquin Ocampo | CyberZenithAI
    Versión: 2026.1.0-RC
    Compatibilidad: Windows Server 2022/2025, PowerShell 7.4+
#>
#Requires -Version 7.4
#Requires -Modules ActiveDirectory

[CmdletBinding(SupportsShouldProcess=$true, ConfirmImpact='High')]
param (
    [Parameter(Mandatory=$true)]
    [ValidateSet('CleanupCAS', 'CreatePCMUser', 'AuditSIAFSIGA', 'All')]
    [string[]]$PipelineTask,

    [Parameter(Mandatory=$false)]
    [string]$TargetOU = "OU=Usuarios,OU=Ministerio_Estado,DC=gob,DC=pe",
    
    [Parameter(Mandatory=$false)]
    [string]$AuditLogPath = "C:\ZenithSec\Logs\AD_Automation"
)

$ErrorActionPreference = "Stop"
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 -bor [Net.SecurityProtocolType]::Tls13

. "$PSScriptRoot\..\shared\functions\Send-SIEMAuditLog.ps1"
. "$PSScriptRoot\modules\Module-GobiernoAD.psm1"

function Initialize-SecureEnvironment {
    if (-not (Test-Path $AuditLogPath)) {
        New-Item -Path $AuditLogPath -ItemType Directory -Force | Out-Null
        $acl = Get-Acl $AuditLogPath
        $acl.SetAccessRuleProtection($true, $false)
        $rule = New-Object System.Security.AccessControl.FileSystemAccessRule("BUILTIN\Administrators","FullControl","Allow")
        $acl.AddAccessRule($rule)
        Set-Acl $AuditLogPath $acl
    }
    Start-Transcript -Path "$AuditLogPath\Execution_Transcript_$(Get-Date -Format 'yyyyMMdd_HHmmss').log" -IncludeInvocationHeader
}

function Get-SIAFSIGAAccessAudit {
    $criticalGroups = @("GRP_SIAF_Aprobador_Maximo", "GRP_SIAF_Ejecutor_Gasto", "GRP_SIGA_Administrador")
    $auditResults = @()
    foreach ($group in $criticalGroups) {
        $members = Get-ADGroupMember -Identity $group -Recursive | Where-Object { $_.objectClass -eq 'user' }
        foreach ($member in $members) {
            $userDetails = Get-ADUser -Identity $member.SamAccountName -Properties LastLogonDate, ExtensionAttribute10, ExtensionAttribute11
            $auditResults += [PSCustomObject]@{
                FechaAuditoria = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
                SistemaCritico = $group
                Usuario        = $member.SamAccountName
                DNI            = $userDetails.ExtensionAttribute10
                Cargo          = $userDetails.ExtensionAttribute11
                UltimoLogon    = $userDetails.LastLogonDate
                EstadoCuenta   = if ($userDetails.Enabled) { "Activo" } else { "Deshabilitado" }
            }
        }
    }
    $reportPath = "$AuditLogPath\Auditoria_Contraloria_$(Get-Date -Format 'yyyyMMdd').csv"
    $auditResults | Export-Csv -Path $reportPath -NoTypeInformation -Encoding UTF8
    Send-SIEMAuditLog -Event "SIAF_SIGA_AUDIT" -Level "Success" -Metadata @{ReportPath = $reportPath; Count = $auditResults.Count}
    return $auditResults
}

try {
    Initialize-SecureEnvironment
    Send-SIEMAuditLog -Event "FRAMEWORK_START" -Level "Information" -Target "GovernmentAD"

    foreach ($task in $PipelineTask) {
        switch ($task) {
            'CleanupCAS'    { Invoke-ADUserLifecycleCleanup -QuarantineOU "OU=Cuarentena_CAS,$TargetOU" }
            'AuditSIAFSIGA' { Get-SIAFSIGAAccessAudit }
            'All' {
                Invoke-ADUserLifecycleCleanup -QuarantineOU "OU=Cuarentena_CAS,$TargetOU"
                Get-SIAFSIGAAccessAudit
            }
        }
    }
    
    Send-SIEMAuditLog -Event "FRAMEWORK_SUCCESS" -Level "Success" -Target "GovernmentAD"
    exit 0
} catch {
    Send-SIEMAuditLog -Event "FRAMEWORK_FAILURE" -Level "Critical" -ErrorMessage $_.Exception.Message
    exit 1
} finally {
    Stop-Transcript
}
