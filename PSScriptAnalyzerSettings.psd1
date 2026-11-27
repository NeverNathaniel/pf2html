@{
    # The CI gate fails on Error, ParseError, and Warning severities. These intentional
    # stylistic choices (custom verb names, Write-Host status output, plural nouns)
    # are excluded so the analyzer output stays signal, not noise.
    ExcludeRules = @(
        'PSUseApprovedVerbs',
        'PSUseSingularNouns',
        'PSAvoidUsingWriteHost',
        'PSUseShouldProcessForStateChangingFunctions',
        'PSAvoidUsingPositionalParameters'
    )
}
