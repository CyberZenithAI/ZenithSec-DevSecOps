# tests/unit/Mining.Tests.ps1
BeforeAll { Import-Module ./src/powershell/modules/Mining/Module-MineriaAD.psd1 -Force }
Describe "Mining AD Module Unit Tests" {
    Context "Update-MiningServiceAccountSecurity" {
        It "Should throw if no SPN is found" {
            Mock Get-ADUser { return [PSCustomObject]@{ServicePrincipalNames=@()} }
            { Update-MiningServiceAccountSecurity -ServiceAccount "svc_no_spn" -AdminCred (New-Object System.Management.Automation.PSCredential ("a", (ConvertTo-SecureString "b" -AsPlainText -Force))) } | Should -Throw "No SPN found*"
        }
    }
}
