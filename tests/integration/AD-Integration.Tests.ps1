# tests/integration/AD-Integration.Tests.ps1
Describe "AD Integration Tests" -Tag "Integration" {
    BeforeAll {
        # Mock AD environment or use test tenant
        $env:ZENITHSEC_SIEM_WEBHOOK = "http://localhost:8080/mock"
    }
    It "Should successfully send audit logs to SIEM" {
        Mock Invoke-RestMethod { return $true }
        Send-SIEMAuditLog -Event "TEST" -Status "SUCCESS"
        Should -Invoke Invoke-RestMethod -Times 1
    }
}
