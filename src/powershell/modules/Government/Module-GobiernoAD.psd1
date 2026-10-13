# src/powershell/modules/Government/Module-GobiernoAD.psd1
@{
    RootModule = 'Module-GobiernoAD.psm1'
    ModuleVersion = '2.1.0'
    GUID = 'c3d4e5f6-a7b8-9012-cdef-123456789012'
    Author = 'Joaquin Ocampo (CyberZenithAI)'
    Description = 'Secure AD Automation for Government Sector (PCM & Ley 29733 Compliant)'
    PowerShellVersion = '5.1'
    RequiredModules = @('ActiveDirectory')
    FunctionsToExport = @('Set-GovernmentDataClassification')
}
