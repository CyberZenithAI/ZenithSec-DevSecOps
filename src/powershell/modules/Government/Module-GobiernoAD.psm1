# src/powershell/modules/Government/Module-GobiernoAD.psm1
#Requires -Version 5.1 -Modules ActiveDirectory
Set-StrictMode -Version Latest

function Set-GovernmentDataClassification {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)][string]$TargetOU,
        [Parameter(Mandatory)][ValidateSet('Publico','Confidencial','Reservado','Secreto')][string]$Classification,
        [Parameter(Mandatory)][System.Management.Automation.PSCredential]$AdminCred
    )
    process {
        Set-ADOrganizationalUnit -Identity $TargetOU -ProtectedFromAccidentalDeletion $true -Credential $AdminCred
        $Desc = "Data Classification: $Classification | Ley 29733 Compliant"
        Set-ADObject -Identity $TargetOU -Replace @{description=$Desc} -Credential $AdminCred
        Send-SIEMAuditLog -Event "OU_CLASSIFIED" -Target $TargetOU -Status "SUCCESS" -Metadata @{Level=$Classification}
    }
}
