# src/powershell/mining/modules/Module-MineriaAD.psm1
#Requires -Version 5.1
#Requires -Modules ActiveDirectory
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

. "$PSScriptRoot\..\..\shared\functions\Send-SIEMAuditLog.ps1"

function Update-MiningServiceAccountSecurity {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)][string]$ServiceAccount,
        [Parameter(Mandatory)][System.Management.Automation.PSCredential]$AdminCred
    )
    process {
        $User = Get-ADUser -Identity $ServiceAccount -Properties ServicePrincipalNames -Credential $AdminCred
        if ($User.ServicePrincipalNames.Count -eq 0) { throw "No SPN found. Riesgo de configuración incorrecta." }
        
        $NewPass = [System.Web.Security.Membership]::GeneratePassword(32, 6) | ConvertTo-SecureString -AsPlainText -Force
        Set-ADAccountPassword -Identity $ServiceAccount -NewPassword $NewPass -Reset -Credential $AdminCred
        Set-ADUser -Identity $ServiceAccount -ChangePasswordAtLogon $false -Credential $AdminCred
        
        Send-SIEMAuditLog -Event "SVC_ACCOUNT_ROTATED" -Level "Success" -Target $ServiceAccount
    }
}

function New-MiningContractorUser {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)][string]$SamAccountName,
        [Parameter(Mandatory)][string]$MineSite,
        [Parameter(Mandatory)][datetime]$ExpirationDate,
        [Parameter(Mandatory)][System.Management.Automation.PSCredential]$AdminCred
    )
    process {
        $targetOU = "OU=Contractors,OU=$MineSite,OU=MiningOps,DC=corp,DC=pe"
        $SecurePass = [System.Web.Security.Membership]::GeneratePassword(16, 4) | ConvertTo-SecureString -AsPlainText -Force
        
        New-ADUser -SamAccountName $SamAccountName -Path $targetOU -AccountPassword $SecurePass `
                   -Enabled $true -AccountExpirationDate $ExpirationDate -ChangePasswordAtLogon $true -Credential $AdminCred
        
        Send-SIEMAuditLog -Event "CONTRACTOR_CREATED" -Level "Success" -Target $SamAccountName -Metadata @{Site=$MineSite; Expiration=$ExpirationDate}
    }
}
