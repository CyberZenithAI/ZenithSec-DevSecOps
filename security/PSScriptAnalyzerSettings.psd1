@{
    Severity = @('Error')
    IncludeRules = @(
        'PSAvoidUsingInvokeExpression',
        'PSUseApprovedVerbs',
        'PSUseDeclaredVarsMoreThanAssignments',
        'PSUseConsistentIndentation',
        'PSAvoidGlobalVars',
        'PSAvoidUsingPlainTextForPassword'
    )
    ExcludeRules = @(
        'PSAvoidUsingConvertToSecureStringWithPlainText',
        'PSUseShouldProcessForStateChangingFunctions',
        'PSAvoidUsingWriteHost',
        'PSUseSingularNouns',
        'PSAvoidUsingEmptyCatchBlock',
        'PSUsePSCredentialType'
    )
    Rules = @{
        PSAvoidUsingInvokeExpression = @{
            Enable = $true
        }
        PSAvoidUsingPlainTextForPassword = @{
            Enable = $false
        }
        PSAvoidUsingConvertToSecureStringWithPlainText = @{
            Enable = $false
        }
        PSUseConsistentIndentation = @{
            Enable = $true
            IndentationSize = 4
            PipelineIndentation = 'IncreaseIndentationForFirstPipeline'
            Kind = 'space'
        }
        PSAvoidGlobalVars = @{
            Enable = $false
        }
    }
}
