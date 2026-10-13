# src/powershell/modules/Financial/Module-FinancieroAD.psd1
@{
    RootModule = 'Module-FinancieroAD.psm1'
    ModuleVersion = '2.1.0'
    GUID = 'a1b2c3d4-e5f6-7890-abcd-ef1234567890'
    Author = 'Joaquin Ocampo (CyberZenithAI)'
    CompanyName = 'ZenithSec'
    Copyright = '(c) 2026 ZenithSec. All rights reserved.'
    Description = 'Secure AD Automation for Financial Sector (SBS Compliant)'
    PowerShellVersion = '5.1'
    RequiredModules = @('ActiveDirectory')
    FunctionsToExport = @('New-SecureFinancialADUser')
    CmdletsToExport = @()
    VariablesToExport = @()
    AliasesToExport = @()
    PrivateData = @{ PSData = @{ Tags = @('Security','ActiveDirectory','Finance','SBS') } }
}
