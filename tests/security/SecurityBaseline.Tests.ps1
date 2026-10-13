# tests/security/SecurityBaseline.Tests.ps1
Describe "Security Baseline Tests" -Tag "Security" {
    It "No plain text passwords in source code" {
        $files = Get-ChildItem -Path ./src -Recurse -Include *.ps1,*.psm1
        $violations = $files | Select-String -Pattern "ConvertTo-SecureString.*-AsPlainText.*-Force" -Context 0,0 | Where-Object { $_.Line -notmatch "GeneratePassword" }
        $violations.Count | Should -Be 0
    }
    It "All scripts use StrictMode" {
        $files = Get-ChildItem -Path ./src -Recurse -Include *.ps1,*.psm1
        foreach ($file in $files) {
            $content = Get-Content $file.FullName -Raw
            $content | Should -Match "Set-StrictMode"
        }
    }
}
