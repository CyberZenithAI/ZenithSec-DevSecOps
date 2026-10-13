# tests/unit/Financial.Tests.ps1
BeforeAll { Import-Module ./src/powershell/modules/Financial/Module-FinancieroAD.psd1 -Force }
Describe "Financial AD Module Unit Tests" {
    Context "New-SecureFinancialADUser" {
        It "Should reject invalid SamAccountName" {
            { New-SecureFinancialADUser -SamAccountName "INVALID_NAME!" -Sector "Banca" -AdminCred (New-Object System.Management.Automation.PSCredential ("a", (ConvertTo-SecureString "b" -AsPlainText -Force))) } | Should -Throw
        }
        It "Should accept valid parameters" {
            Mock New-ADUser { return $true }
            Mock Send-SIEMAuditLog { return $true }
            { New-SecureFinancialADUser -SamAccountName "testuser01" -Sector "Banca" -AdminCred (New-Object System.Management.Automation.PSCredential ("a", (ConvertTo-SecureString "b" -AsPlainText -Force))) } | Should -Not -Throw
        }
    }
}
