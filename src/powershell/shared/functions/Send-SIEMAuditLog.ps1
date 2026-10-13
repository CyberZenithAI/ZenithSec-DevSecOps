# src/powershell/shared/functions/Send-SIEMAuditLog.ps1
<#
.SYNOPSIS
    Envía logs de auditoría estructurados en formato JSON a un SIEM externo o Event Log local.
.DESCRIPTION
    Función centralizada para garantizar la trazabilidad inmutable de todas las operaciones de AD.
    Cumple con ISO 27001 A.8.15 (Logging) y normativas SBS/PCM.
#>
function Send-SIEMAuditLog {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)][string]$Event,
        [Parameter(Mandatory=$true)][ValidateSet('Information','Warning','Error','Critical','Success')][string]$Level,
        [string]$Target,
        [string]$ErrorMessage,
        [int]$DurationMs,
        [hashtable]$Metadata
    )
    process {
        $Payload = @{
            timestamp = (Get-Date).ToUniversalTime().ToString("o")
            source    = "ZenithSec-AD-Automation"
            actor     = $env:USERNAME
            event     = $Event
            level     = $Level
            target    = $Target
            error     = $ErrorMessage
            duration_ms = $DurationMs
            metadata  = $Metadata
        } | ConvertTo-Json -Depth 5 -Compress

        try {
            # Intento de envío a Webhook SIEM (Wazuh/Splunk/Sentinel)
            $Uri = $env:ZENITHSEC_SIEM_WEBHOOK
            if ([string]::IsNullOrWhiteSpace($Uri)) {
                # Fallback a Event Log de Windows si no hay webhook configurado
                $LogName = "ZenithSec_Audit"
                if (-not [System.Diagnostics.EventLog]::SourceExists($LogName)) {
                    New-EventLog -LogName Application -Source $LogName -ErrorAction SilentlyContinue
                }
                Write-EventLog -LogName Application -Source $LogName -EventId 1001 -EntryType $Level -Message $Payload
            } else {
                Invoke-RestMethod -Uri $Uri -Method Post -Body $Payload -ContentType "application/json" -TimeoutSec 5 -SkipCertificateCheck:$false
            }
        } catch {
            Write-Warning "Fallo al enviar log a SIEM: $($_.Exception.Message). Datos perdidos: $Payload"
        }
    }
}
