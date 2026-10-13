# tests/unit/Government.Tests.ps1
BeforeAll { Import-Module ./src/powershell/modules/Government/Module-GobiernoAD.psd1 -Force }
Describe "Government AD Module Unit Tests" {
    Context "Set-GovernmentDataClassification" {
        It "Should reject invalid classification levels" {
            { Set-GovernmentDataClassification -TargetOU "OU=Test" -Classification "TopSecret" -AdminCred (New-Object System.Management.Automation.PSCredential ("a", (ConvertTo-SecureString "b" -AsPlainText -Force))) } | Should -Throw
        }
    }
}
