# src/powershell/functions/Invoke-SecureADOperation.ps1
function Invoke-SecureADOperation {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)][scriptblock]$Action,
        [Parameter(Mandatory)][string]$OperationName
    )
    begin {
        $Stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
        Write-Verbose "Starting secure operation: $OperationName"
    }
    process {
        try {
            $Result = & $Action
            $Status = "SUCCESS"
        } catch {
            $Status = "FAILED"
            Send-SIEMAuditLog -Event $OperationName -Status $Status -Error $_.Exception.Message
            throw
        }
    }
    end {
        $Stopwatch.Stop()
        Send-SIEMAuditLog -Event $OperationName -Status $Status -DurationMs $Stopwatch.ElapsedMilliseconds
        return $Result
    }
}
