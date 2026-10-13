# src/powershell/financial/modules/Module-FinancieroAD.psd1
@{
    RootModule           = 'Module-FinancieroAD.psm1'
    ModuleVersion        = '2026.1.0'
    GUID                 = 'a1b2c3d4-e5f6-7890-abcd-ef1234567890'
    Author               = 'Joaquin Ocampo | CyberZenithAI'
    CompanyName          = 'ZenithSec'
    Copyright            = '(c) 2026 ZenithSec. Cumplimiento SBS/SMV.'
    Description          = 'Módulo de automatización segura de Active Directory para el Sector Financiero Peruano.'
    PowerShellVersion    = '5.1'
    RequiredModules      = @('ActiveDirectory')
    FunctionsToExport    = @('New-SecureFinancialADUser', 'Invoke-StrictLogonHours')
    CmdletsToExport      = @()
    VariablesToExport    = @()
    AliasesToExport      = @()
    PrivateData          = @{
        PSData = @{
            Tags = @('Security', 'ActiveDirectory', 'Finance', 'SBS', 'ISO27001')
        }
    }
}
