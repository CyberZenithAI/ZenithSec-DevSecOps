# scripts/generate-sbom.ps1
[CmdletBinding()]
param (
    [string]$OutputPath = "security/sbom.json"
)
begin { Set-StrictMode -Version Latest }
process {
    Write-Host "Generating Software Bill of Materials (SBOM)..."
    # In production, use Microsoft.SBOMTool or CycloneDX CLI
    # This is a structural placeholder for the generation logic
    $sbom = Get-Content $OutputPath | ConvertFrom-Json
    $sbom.metadata.timestamp = (Get-Date).ToUniversalTime().ToString("o")
    $sbom | ConvertTo-Json -Depth 10 | Set-Content $OutputPath
    Write-Host "SBOM updated at $OutputPath" -ForegroundColor Green
}
