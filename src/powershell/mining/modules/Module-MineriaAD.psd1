# src/powershell/mining/modules/Module-MineriaAD.psd1
@{
    RootModule           = 'Module-MineriaAD.psm1'
    ModuleVersion        = '2026.1.0'
    GUID                 = 'b2c3d4e5-f6a7-8901-bcde-f12345678901'
    Author               = 'Joaquin Ocampo | CyberZenithAI'
    Description          = 'Módulo de automatización segura de Active Directory para el Sector Minero (OSINERGMIN/SUNAFIL).'
    PowerShellVersion    = '5.1'
    RequiredModules      = @('ActiveDirectory')
    FunctionsToExport    = @('Update-MiningServiceAccountSecurity', 'New-MiningContractorUser')
}
