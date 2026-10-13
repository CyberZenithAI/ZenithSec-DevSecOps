# src/powershell/modules/Mining/Module-MineriaAD.psd1
@{
    RootModule = 'Module-MineriaAD.psm1'
    ModuleVersion = '2.1.0'
    GUID = 'b2c3d4e5-f6a7-8901-bcde-f12345678901'
    Author = 'Joaquin Ocampo (CyberZenithAI)'
    Description = 'Secure AD Automation for Mining Sector (OSINERGMIN IT/OT Compliant)'
    PowerShellVersion = '5.1'
    RequiredModules = @('ActiveDirectory')
    FunctionsToExport = @('Update-MiningServiceAccountSecurity')
}
