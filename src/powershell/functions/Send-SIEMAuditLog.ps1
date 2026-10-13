# src/powershell/functions/Send-SIEMAuditLog.ps1
function Send-SIEMAuditLog {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)][string]$Event,
        [Parameter(Mandatory)][string]$Status,
        [string]$Target, [string]$Error, [int]$DurationMs, [hashtable]$Metadata
    )
    process {
        $Payload = @{
            timestamp = (Get-Date).ToUniversalTime().ToString("o")
            source = "ZenithSec-DevSecOps"
            actor = $env:USERNAME
            event = $Event; status = $Status; target = $Target
            error = $Error; duration_ms = $DurationMs; metadata = $Metadata
        } | ConvertTo-Json -Depth 5 -Compress
        
        try {
            $Uri = $env:ZENITHSEC_SIEM_WEBHOOK
            if (-not $Uri) { Write-Warning "SIEM Webhook not configured."; return }
            Invoke-RestMethod -Uri $Uri -Method Post -Body $Payload -ContentType "application/json" -TimeoutSec 5
        } catch {
            Write-Error "Failed to send audit log to SIEM: $_"
        }
    }
}
