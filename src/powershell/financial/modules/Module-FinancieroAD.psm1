# src/powershell/financial/modules/Module-FinancieroAD.psm1
#Requires -Version 5.1
#Requires -Modules ActiveDirectory
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

. "$PSScriptRoot\..\..\shared\functions\Send-SIEMAuditLog.ps1"
. "$PSScriptRoot\..\..\shared\functions\Invoke-SecureADOperation.ps1"

function New-SecureFinancialADUser {
    [CmdletBinding(SupportsShouldProcess)]
    param (
        [Parameter(Mandatory)][ValidatePattern('^[a-z0-9]{6,12}$')][string]$SamAccountName,
        [Parameter(Mandatory)][ValidateSet('Banca','Seguros','TPRM','Auditoria')][string]$Sector,
        [Parameter(Mandatory)][System.Management.Automation.PSCredential]$AdminCred
    )
    process {
        Invoke-SecureADOperation -Action {
            $SecurePass = [System.Web.Security.Membership]::GeneratePassword(24, 5) | ConvertTo-SecureString -AsPlainText -Force
            $Params = @{
                SamAccountName       = $SamAccountName
                Path                 = "OU=$Sector,OU=Financial,DC=empresa,DC=com,DC=pe"
                AccountPassword      = $SecurePass
                Enabled              = $true
                ChangePasswordAtLogon= $true
                PasswordNeverExpires = $false
            }
            New-ADUser @Params -Credential $AdminCred
        } -OperationName "CreateFinancialUser" -TargetName $SamAccountName
    }
}

function Invoke-StrictLogonHours {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)][string]$TargetOU,
        [Parameter(Mandatory)][int]$StartHour,
        [Parameter(Mandatory)][int]$EndHour
    )
    process {
        Invoke-SecureADOperation -Action {
            $bytes = New-Object byte[] 21
            for ($day = 0; $day -lt 7; $day++) {
                for ($hour = $StartHour; $hour -lt $EndHour; $hour++) {
                    $bitIndex = ($day * 24) + $hour
                    $byteIndex = [math]::Floor($bitIndex / 8)
                    $bitOffset = $bitIndex % 8
                    $bytes[$byteIndex] = $bytes[$byteIndex] -bor (1 -shl $bitOffset)
                }
            }
            Get-ADUser -SearchBase $TargetOU -Filter {Enabled -eq $true} | ForEach-Object {
                Set-ADUser -Identity $_.SamAccountName -Replace @{logonHours=$bytes}
            }
        } -OperationName "ApplyLogonHours" -TargetName $TargetOU
    }
}
