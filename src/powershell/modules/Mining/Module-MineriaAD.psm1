# src/powershell/modules/Mining/Module-MineriaAD.psm1
#Requires -Version 5.1 -Modules ActiveDirectory
Set-StrictMode -Version Latest

function Update-MiningServiceAccountSecurity {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)][string]$ServiceAccount,
        [Parameter(Mandatory)][System.Management.Automation.PSCredential]$AdminCred
    )
    process {
        $User = Get-ADUser -Identity $ServiceAccount -Properties ServicePrincipalNames -Credential $AdminCred
        if ($User.ServicePrincipalNames.Count -eq 0) { throw "No SPN found. Risk of misconfiguration." }
        
        $NewPass = [System.Web.Security.Membership]::GeneratePassword(32, 6) | ConvertTo-SecureString -AsPlainText -Force
        Set-ADAccountPassword -Identity $ServiceAccount -NewPassword $NewPass -Reset -Credential $AdminCred
        Set-ADUser -Identity $ServiceAccount -ChangePasswordAtLogon $false -Credential $AdminCred
        
        Send-SIEMAuditLog -Event "SVC_ACCOUNT_ROTATED" -Target $ServiceAccount -Status "SUCCESS"
    }
}
