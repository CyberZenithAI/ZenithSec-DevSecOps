# scripts/pre-commit-hook.sh
#!/usr/bin/env bash
set -euo pipefail

echo "Running ZenithSec Pre-Commit Hooks..."

# Run PSScriptAnalyzer
pwsh -Command "Invoke-ScriptAnalyzer -Path ./src -Settings ./security/PSScriptAnalyzerSettings.psd1 -Recurse -Severity Error"
if [ $? -ne 0 ]; then
    echo "PSScriptAnalyzer failed. Commit aborted."
    exit 1
fi

# Run Gitleaks
gitleaks detect --config security/gitleaks-config.json --source . -v
if [ $? -ne 0 ]; then
    echo "Gitleaks detected secrets. Commit aborted."
    exit 1
fi

echo "Pre-commit hooks passed successfully."
exit 0
