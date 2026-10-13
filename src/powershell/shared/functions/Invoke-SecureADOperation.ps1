# src/powershell/shared/functions/Invoke-SecureADOperation.ps1
<#
.SYNOPSIS
    Wrapper de ejecución segura con manejo de errores, cronometraje y logging automático.
.DESCRIPTION
    Garantiza que cualquier operación de AD se ejecute dentro de un bloque Try/Catch estandarizado,
    registrando el éxito o fallo automáticamente en el SIEM.
#>
function Invoke-SecureADOperation {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)][scriptblock]$Action,
        [Parameter(Mandatory=$true)][string]$OperationName,
        [string]$TargetName
    )
    begin {
        $Stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
        Send-SIEMAuditLog -Event "$OperationName-Start" -Level "Information" -Target $TargetName
    }
    process {
        try {
            $Result = & $Action
            $Status = "Success"
            return $Result
        } catch {
            $Status = "Failed"
            Send-SIEMAuditLog -Event "$OperationName-Failed" -Level "Error" -Target $TargetName -ErrorMessage $_.Exception.Message
            throw
        }
    }
    end {
        $Stopwatch.Stop()
        Send-SIEMAuditLog -Event "$OperationName-End" -Level "Success" -Target $TargetName -DurationMs $Stopwatch.ElapsedMilliseconds
    }
}
