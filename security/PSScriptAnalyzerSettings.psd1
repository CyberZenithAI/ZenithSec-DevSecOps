# security/PSScriptAnalyzerSettings.psd1
@{
    Severity = @('Error', 'Warning')
    ExcludeRules = @(
        'PSUseShouldProcessForStateChangingFunctions' # Disabled for internal automation functions
    )
    IncludeRules = @(
        'PSAvoidUsingPlainTextForPassword',
        'PSAvoidUsingInvokeExpression',
        'PSUseApprovedVerbs',
        'PSAvoidUsingWriteHost',
        'PSUseConsistentIndentation',
        'PSUseDeclaredVarsMoreThanAssignments'
    )
    Rules = @{
        PSAvoidUsingPlainTextForPassword = @{ Enable = $true }
        PSAvoidUsingInvokeExpression = @{ Enable = $true }
    }
}
