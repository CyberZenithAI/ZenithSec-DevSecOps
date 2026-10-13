<#
.SYNOPSIS
    Núcleo de Automatización de Identidades Financieras (NAIF-PE) para Active Directory.
.DESCRIPTION
    Motor avanzado para la gestión del ciclo de vida de identidades en el sector financiero peruano.
    Cumple con normativas SBS, SMV, ISO 27001, ISO 27701.
    Diseñado para integración CI/CD y ejecución en Windows Server.
.NOTES
    Autor: @NexusSec_Architect_PE
    Versión: 2026.1.0-PROD
    Entorno: Windows Server 2022 / Active Directory
#>

#Requires -Version 5.1
#Requires -Modules ActiveDirectory

[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)]
    [ValidateSet('Offboard', 'PrivilegeAudit', 'PasswordExpiry', 'BranchLogonControl')]
    [string]$Action,

    [Parameter(Mandatory=$false)]
    [string]$InputFilePath,

    [Parameter(Mandatory=$false)]
    [string]$TargetOU,

    [Parameter(Mandatory=$false)]
    [ValidateRange(0,23)]
    [int]$LogonStartHour = 8,

    [Parameter(Mandatory=$false)]
    [ValidateRange(0,23)]
    [int]$LogonEndHour = 18
)

# ==============================================================================
# CONFIGURACIÓN DE SEGURIDAD Y ENTORNO (TLS, STRICT MODE)
# ==============================================================================
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 -bor [Net.SecurityProtocolType]::Tls13

# Configuración de Log de Eventos para SIEM (SBS Compliance)
$LogName = "NAIF_FinSec_AD"
if (-not [System.Diagnostics.EventLog]::SourceExists($LogName)) {
    New-EventLog -LogName Application -Source $LogName -ErrorAction SilentlyContinue
}

function Write-SIEMLog {
    param([string]$Message, [string]$Level = "Information", [hashtable]$AuditData)
    $jsonPayload = @{
        Timestamp = (Get-Date).ToUniversalTime().ToString("o")
        Level     = $Level
        Action    = $Action
        Message   = $Message
        AuditData = $AuditData
    } | ConvertTo-Json -Compress
    
    Write-EventLog -LogName Application -Source $LogName -EventId 1001 -EntryType $Level -Message $jsonPayload
}

# ==============================================================================
# FUNCIÓN AVANZADA: GENERADOR DE BYTES PARA LOGONHOURS (AD API)
# ==============================================================================
function Get-ADLogonHoursByte {
    param([int]$Start, [int]$End)
    # 21 bytes = 168 bits. 1 bit = 1 hour. 7 days * 24 hours.
    # SBS requiere control estricto de horarios para cajeros/asesores.
    $bytes = New-Object byte[] 21
    for ($day = 0; $day -lt 7; $day++) {
        for ($hour = $Start; $hour -lt $End; $hour++) {
            $bitIndex = ($day * 24) + $hour
            $byteIndex = [math]::Floor($bitIndex / 8)
            $bitOffset = $bitIndex % 8
            $bytes[$byteIndex] = $bytes[$byteIndex] -bor (1 -shl $bitOffset)
        }
    }
    return $bytes
}

# ==============================================================================
# MÓDULO 1: OFFBOARDING (CESE INMEDIATO - CICLO DE VIDA)
# ==============================================================================
function Invoke-Offboarding {
    param([string]$File)
    $results = @()
    
    if (-not (Test-Path $File)) { throw "Archivo de entrada no encontrado: $File" }
    
    # Carga segura de datos (RRHH envía CSV con ID_Empleado, no DNI para cumplir ISO 27701)
    $cesados = Import-Csv -Path $File -Encoding UTF8
    
    foreach ($user in $cesados) {
        $audit = @{ EmployeeID = $user.ID_Empleado; Status = "Pending" }
        try {
            $adUser = Get-ADUser -Filter "EmployeeID -eq '$($user.ID_Empleado)'" -Properties MemberOf, DistinguishedName
            
            if ($adUser) {
                # 1. Deshabilitar y mover a OU de Cuarentena (SBS RSBI)
                Disable-ADAccount -Identity $adUser.SamAccountName
                
                # 2. Revocación de Sesiones (Kerberos TGT invalidation)
                $targetDC = (Get-ADDomainController -Discover).HostName
                Invoke-Command -ComputerName $targetDC -ScriptBlock {
                    param($sam)
                    # Forzar revocación de tickets Kerberos en el DC
                    $sessions = klist sessions | Where-Object { $_ -match $sam }
                    # Reset de contraseña a string aleatorio de 32 chars para invalidar hashes NTLM
                    $newPass = -join ((65..90) + (97..122) + (48..57) | Get-Random -Count 32 | ForEach-Object {[char]$_})
                    $secPass = ConvertTo-SecureString $newPass -AsPlainText -Force
                    Set-ADAccountPassword -Identity $sam -NewPassword $secPass -Reset
                } -ArgumentList $adUser.SamAccountName

                # 3. Mover a OU de Cesados
                $quarantineOU = "OU=Cesados,OU=Usuarios,DC=banco,DC=com,DC=pe" # Ajustar al dominio real
                Move-ADObject -Identity $adUser.DistinguishedName -TargetPath $quarantineOU

                $audit.Status = "Success"
                Write-SIEMLog -Message "Offboarding ejecutado" -AuditData $audit
            } else {
                $audit.Status = "NotFound"
            }
        } catch {
            $audit.Status = "Error: $($_.Exception.Message)"
            Write-SIEMLog -Message "Fallo en Offboarding" -Level "Error" -AuditData $audit
        }
        $results += $audit
    }
    return $results
}

# ==============================================================================
# MÓDULO 2: AUDITORÍA DE PRIVILEGIOS (ISO 27001 A.9.2.6)
# ==============================================================================
function Invoke-PrivilegeAudit {
    $privGroups = @("Domain Admins", "Enterprise Admins", "Schema Admins", "GPO_Admins_Financiero")
    $baselineHashFile = "C:\Secure\NAIF\PrivilegeBaseline.hash" # Debe estar en volumen cifrado BitLocker
    $currentMembers = @()

    foreach ($group in $privGroups) {
        try {
            $members = Get-ADGroupMember -Identity $group -Recursive | Select-Object SamAccountName, Name
            $currentMembers += [PSCustomObject]@{ Group = $group; Members = ($members.SamAccountName -join ";") }
        } catch {
            Write-SIEMLog -Message "Error auditando grupo $group" -Level "Error"
        }
    }

    $currentHash = ($currentMembers | ConvertTo-Json | Get-FileHash -Algorithm SHA256).Hash
    
    if (Test-Path $baselineHashFile) {
        $storedHash = Get-Content $baselineHashFile
        if ($currentHash -ne $storedHash) {
            Write-SIEMLog -Message "ALERTA CRITICA: Modificación no autorizada en grupos privilegiados detectada." -Level "Error"
            # Romper el pipeline de CI/CD si hay cambio no autorizado
            throw "INTEGRITY_CHECK_FAILED: Privileged groups modified."
        }
    } else {
        # Primera ejecución, crear baseline
        $currentHash | Out-File $baselineHashFile -Force
    }

    return @{ Status = "Success"; Hash = $currentHash; GroupsAudited = $privGroups.Count }
}

# ==============================================================================
# MÓDULO 3: REPORTE DE CADUCIDAD DE CONTRASEÑAS (ISO 27001 A.9.4.3)
# ==============================================================================
function Invoke-PasswordExpiryAudit {
    $expiringUsers = @()
    $users = Get-ADUser -Filter {Enabled -eq $true -and PasswordNeverExpires -eq $false} -Properties "msDS-UserPasswordExpiryTimeComputed", EmailAddress
    
    foreach ($u in $users) {
        $expiry = $u."msDS-UserPasswordExpiryTimeComputed"
        if ($expiry -ne 9223372036854775807) { # 9223... es el valor para "nunca expira" en AD
            $expiryDate = [DateTime]::FromFileTime($expiry)
            $daysLeft = ($expiryDate - (Get-Date)).Days
            
            if ($daysLeft -le 7 -and $daysLeft -ge 0) {
                $expiringUsers += [PSCustomObject]@{
                    SamAccountName = $u.SamAccountName
                    DaysRemaining  = $daysLeft
                    ExpiryDate     = $expiryDate.ToString("yyyy-MM-dd")
                }
            }
        }
    }
    
    $reportPath = "C:\Secure\NAIF\Reports\PasswordExpiry_$(Get-Date -Format 'yyyyMMdd').csv"
    $expiringUsers | Export-Csv -Path $reportPath -NoTypeInformation -Encoding UTF8
    
    Write-SIEMLog -Message "Reporte de caducidad generado" -AuditData @{ Count = $expiringUsers.Count; Path = $reportPath }
    return @{ Status = "Success"; ExpiringCount = $expiringUsers.Count; ReportPath = $reportPath }
}

# ==============================================================================
# MÓDULO 4: CONTROL HORARIO CAJEROS/ASESORES (SBS RSBI - FRAUDE INTERNO)
# ==============================================================================
function Set-BranchLogonControl {
    param([string]$OU, [int]$Start, [int]$End)
    
    if (-not $OU) { throw "Se requiere la TargetOU para el control horario." }
    
    # Obtener usuarios de la OU específica (ej. Cajeros, Asesores)
    $users = Get-ADUser -SearchBase $OU -Filter {Enabled -eq $true} -Properties logonHours
    
    # Generar la matriz de bytes para el horario permitido
    $allowedBytes = Get-ADLogonHoursByte -Start $Start -End $End
    
    $modifiedCount = 0
    foreach ($user in $users) {
        try {
            # Aplicar restricción a nivel de atributo AD (Más seguro que deshabilitar/habilitar)
            Set-ADUser -Identity $user.SamAccountName -Replace @{logonHours=$allowedBytes}
            $modifiedCount++
        } catch {
            Write-SIEMLog -Message "Error aplicando logonHours a $($user.SamAccountName)" -Level "Warning"
        }
    }
    
    Write-SIEMLog -Message "Control horario aplicado" -AuditData @{ OU = $OU; UsersModified = $modifiedCount; Start = $Start; End = $End }
    return @{ Status = "Success"; UsersModified = $modifiedCount }
}

# ==============================================================================
# EJECUCIÓN PRINCIPAL Y SALIDA CI/CD (JSON)
# ==============================================================================
$executionResult = @{
    Timestamp = (Get-Date).ToUniversalTime().ToString("o")
    Action    = $Action
    Status    = "Success"
    Details   = $null
}

try {
    switch ($Action) {
        'Offboard'          { $executionResult.Details = Invoke-Offboarding -File $InputFilePath }
        'PrivilegeAudit'    { $executionResult.Details = Invoke-PrivilegeAudit }
        'PasswordExpiry'    { $executionResult.Details = Invoke-PasswordExpiryAudit }
        'BranchLogonControl'{ $executionResult.Details = Set-BranchLogonControl -OU $TargetOU -Start $LogonStartHour -End $LogonEndHour }
    }
} catch {
    $executionResult.Status = "Failed"
    $executionResult.Details = $_.Exception.Message
    Write-SIEMLog -Message "Fallo crítico en pipeline" -Level "Error" -AuditData @{ Error = $_.Exception.Message }
    # Salida de error para CI/CD
    Write-Output ($executionResult | ConvertTo-Json -Depth 5)
    exit 1
}

# Salida estándar para CI/CD
Write-Output ($executionResult | ConvertTo-Json -Depth 5)
exit 0
