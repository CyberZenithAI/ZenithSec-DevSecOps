# src/powershell/government/modules/Module-GobiernoAD.psm1
#Requires -Version 7.4
#Requires -Modules ActiveDirectory
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

. "$PSScriptRoot\..\..\shared\functions\Send-SIEMAuditLog.ps1"
. "$PSScriptRoot\..\..\shared\functions\Invoke-SecureADOperation.ps1"

function Set-GovernmentDataClassification {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)][string]$TargetOU,
        [Parameter(Mandatory)][ValidateSet('Publico','Confidencial','Reservado','Secreto')][string]$Classification
    )
    process {
        Invoke-SecureADOperation -Action {
            Set-ADOrganizationalUnit -Identity $TargetOU -ProtectedFromAccidentalDeletion $true
            $Desc = "Data Classification: $Classification | Ley 29733 Compliant"
            Set-ADObject -Identity $TargetOU -Replace @{description=$Desc}
        } -OperationName "ClassifyOU" -TargetName $TargetOU
    }
}

function Invoke-ADUserLifecycleCleanup {
    [CmdletBinding()]
    param([string]$QuarantineOU)
    process {
        Invoke-SecureADOperation -Action {
            $filter = "(&(objectCategory=person)(objectClass=user)(!userAccountControl:1.2.840.113556.1.4.803:=2)(extensionAttribute15=CAS*))"
            $expiredUsers = Get-ADUser -LDAPFilter $filter -Properties AccountExpirationDate | Where-Object { $_.AccountExpirationDate -lt (Get-Date) }
            
            foreach ($user in $expiredUsers) {
                Disable-ADAccount -Identity $user.SamAccountName
                Move-ADObject -Identity $user.DistinguishedName -TargetPath $QuarantineOU
                $newPass = -join ((33..126) | Get-Random -Count 32 | ForEach-Object {[char]$_})
                Set-ADAccountPassword -Identity $user.SamAccountName -NewPassword (ConvertTo-SecureString $newPass -AsPlainText -Force) -Reset
            }
            return @{ CleanedCount = $expiredUsers.Count }
        } -OperationName "CAS_Cleanup" -TargetName $QuarantineOU
    }
}
