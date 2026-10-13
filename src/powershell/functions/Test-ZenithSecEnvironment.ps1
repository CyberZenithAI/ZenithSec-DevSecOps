# src/powershell/functions/Test-ZenithSecEnvironment.ps1
<#
.SYNOPSIS
    Valida el entorno de ejecución antes de permitir la automatización.
#>
function Test-ZenithSecEnvironment {
    [CmdletBinding()]
    param()
    
    # 1. Validar Sistema Operativo
    $os = Get-CimInstance Win32_OperatingSystem
    if ($os.Caption -notmatch "Server") {
        throw "[FATAL] ZenithSec Framework requiere ejecución en Windows Server."
    }

    # 2. Forzar TLS 1.2/1.3 (Cumplimiento SBS/PCM)
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 -bor [Net.SecurityProtocolType]::Tls13

    # 3. Validar Módulo AD
    if (-not (Get-Module -ListAvailable -Name ActiveDirectory)) {
        throw "[FATAL] El módulo RSAT-AD-PowerShell no está instalado."
    }

    Write-Host "[ZENITHSEC] Validación de entorno completada exitosamente." -ForegroundColor Green
}
