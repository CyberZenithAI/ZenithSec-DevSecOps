# src/powershell/functions/Invoke-ZenithSecSIEMLog.ps1
<#
.SYNOPSIS
    Función universal de telemetría y logging para SIEM (Wazuh/Splunk/Sentinel).
.DESCRIPTION
    Reemplaza los loggers locales de cada script para estandarizar el payload JSON 
    y garantizar el cumplimiento de trazabilidad (ISO 27001 A.12.4).
#>
function Invoke-ZenithSecSIEMLog {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)][string]$Sector,       # 'Financial', 'Mining', 'Government'
        [Parameter(Mandatory=$true)][string]$Action,       # 'Offboard', 'CreateUser', etc.
        [Parameter(Mandatory=$true)][string]$Status,       # 'Success', 'Failed', 'Warning'
        [string]$Message = "",
        [hashtable]$AuditData = @{},
        [string]$WebhookUrl = $env:ZENITHSEC_SIEM_WEBHOOK
    )
    
    $payload = @{
        timestamp   = (Get-Date).ToUniversalTime().ToString("o")
        source      = "ZenithSec-AD-Automation"
        sector      = $Sector
        action      = $Action
        status      = $Status
        message     = $Message
        host        = $env:COMPUTERNAME
        actor       = $env:USERNAME
        audit_data  = $AuditData
    } | ConvertTo-Json -Depth 5 -Compress

    try {
        if ([string]::IsNullOrWhiteSpace($WebhookUrl)) {
            Write-Warning "ZENITHSEC: SIEM Webhook no configurado. Logging solo en consola/archivo."
            return
        }
        Invoke-RestMethod -Uri $WebhookUrl -Method Post -Body $payload -ContentType "application/json" -TimeoutSec 5 -ErrorAction Stop
    }
    catch {
        # Fallback a EventLog de Windows si el SIEM no responde (Continuidad del Negocio)
        $logName = "ZenithSec_Automation"
        if (-not [System.Diagnostics.EventLog]::SourceExists($logName)) {
            New-EventLog -LogName Application -Source $logName -ErrorAction SilentlyContinue
        }
        Write-EventLog -LogName Application -Source $logName -EventId 5000 -EntryType Warning -Message "Fallo envío SIEM: $Message"
    }
}
