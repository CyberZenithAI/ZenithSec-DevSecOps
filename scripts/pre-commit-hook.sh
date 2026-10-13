# scripts/pre-commit-hook.sh
#!/usr/bin/env bash
set -euo pipefail

echo "🛡️ [ZenithSec] Ejecutando Hooks de Pre-Commit de Nivel Empresarial..."

# 1. Validar que no haya secretos (Gitleaks)
echo "🔍 Escaneando secretos con Gitleaks..."
gitleaks detect --config security/gitleaks-config.json --source . -v --redact
if [ $? -ne 0 ]; then
    echo "❌ FALLO: Gitleaks detectó posibles secretos. Commit abortado."
    exit 1
fi

# 2. Validar sintaxis y seguridad de PowerShell (PSScriptAnalyzer)
echo "🔍 Analizando seguridad de PowerShell (PSScriptAnalyzer)..."
pwsh -Command "
    \$errors = Invoke-ScriptAnalyzer -Path ./src/powershell -Settings ./security/PSScriptAnalyzerSettings.psd1 -Recurse -Severity Error
    if (\$errors) {
        Write-Host '❌ FALLO: Se encontraron violaciones de seguridad en los scripts:' -ForegroundColor Red
        \$errors | Format-Table
        exit 1
    }
"
if [ $? -ne 0 ]; then
    echo "❌ FALLO: PSScriptAnalyzer detectó código inseguro. Commit abortado."
    exit 1
fi

# 3. Validar que los scripts principales existan y sean ejecutables
echo "🔍 Validando integridad de los frameworks principales..."
FILES=(
    "src/powershell/financial/Invoke-NAIF_AD_Automation.ps1"
    "src/powershell/mining/AD_Automator_Mining_Corp_PE2026.ps1"
    "src/powershell/government/Invoke-ADMasterFramework.ps1"
)
for f in "${FILES[@]}"; do
    if [ ! -f "$f" ]; then
        echo "❌ FALLO: El archivo crítico $f no existe."
        exit 1
    fi
done

echo "✅ [ZenithSec] Todos los controles de seguridad pasaron. Commit permitido."
exit 0
