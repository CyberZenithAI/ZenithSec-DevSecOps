# src/powershell/modules/Financial/Module-FinancieroAD.psm1
#Requires -Version 5.1 -Modules ActiveDirectory
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function New-SecureFinancialADUser {
    [CmdletBinding(SupportsShouldProcess)]
    param (
        [Parameter(Mandatory)][ValidatePattern('^[a-z0-9]{6,12}$')][string]$SamAccountName,
        [Parameter(Mandatory)][ValidateSet('Banca','Seguros','TPRM')][string]$Sector,
        [Parameter(Mandatory)][System.Management.Automation.PSCredential]$AdminCred
    )
    process {
        try {
            $SecurePass = [System.Web.Security.Membership]::GeneratePassword(24, 5) | ConvertTo-SecureString -AsPlainText -Force
            $Params = @{
                SamAccountName = $SamAccountName; Path = "OU=$Sector,OU=Financial,DC=zenith,DC=local"
                AccountPassword = $SecurePass; Enabled = $true; ChangePasswordAtLogon = $true
                SmartcardLogonRequired = $false; PasswordNeverExpires = $false
            }
            if ($PSCmdlet.ShouldProcess($SamAccountName, "Create Financial AD User")) {
                New-ADUser @Params -Credential $AdminCred
                Send-SIEMAuditLog -Event "USER_CREATED" -Target $SamAccountName -Status "SUCCESS"
            }
        } catch {
            Send-SIEMAuditLog -Event "USER_CREATION_FAILED" -Target $SamAccountName -Status "FAILED" -Error $_.Exception.Message
            throw
        }
    }
}
