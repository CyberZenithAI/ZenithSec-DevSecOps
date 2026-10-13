# src/powershell/government/modules/Module-GobiernoAD.psd1
@{
    RootModule           = 'Module-GobiernoAD.psm1'
    ModuleVersion        = '2026.1.0'
    GUID                 = 'c3d4e5f6-a7b8-9012-cdef-123456789012'
    Author               = 'Joaquin Ocampo | CyberZenithAI'
    Description          = 'Módulo de automatización segura de Active Directory para el Sector Gobierno (PCM/INAI/Ley 29733).'
    PowerShellVersion    = '7.4'
    RequiredModules      = @('ActiveDirectory')
    FunctionsToExport    = @('Set-GovernmentDataClassification', 'Invoke-ADUserLifecycleCleanup')
}
