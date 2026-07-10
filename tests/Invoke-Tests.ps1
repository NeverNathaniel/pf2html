<#
.SYNOPSIS
    Functional + security smoke tests for pfsense_report.ps1.

.DESCRIPTION
    Runs the report generator against the sanitized fixture (tests/fixtures/sample-config.xml)
    and asserts: clean parse, exit codes, all sections rendered, context-aware risk flags,
    certificate parsing/usage, no secret leakage, and that -Redact tokenizes sensitive values.

    The script under test is invoked in a CHILD process (so its `exit` calls do not terminate
    this runner) using whichever PowerShell engine is currently running this file. CI runs this
    once under Windows PowerShell 5.1 and once under PowerShell 7 to prove cross-version support.

.EXAMPLE
    pwsh ./tests/Invoke-Tests.ps1
    powershell -File ./tests/Invoke-Tests.ps1
#>
[CmdletBinding()]
param(
    [string]$ScriptPath,
    [string]$Fixture
)

$ErrorActionPreference = 'Stop'
$script:Failures = 0

# Resolve defaults in the body: $PSScriptRoot is not reliably populated inside the
# param() default block under Windows PowerShell 5.1.
if (-not $ScriptPath) { $ScriptPath = Join-Path $PSScriptRoot '..\pfsense_report.ps1' }
if (-not $Fixture)    { $Fixture    = Join-Path $PSScriptRoot 'fixtures\sample-config.xml' }

function Check {
    param([string]$Name, [bool]$Condition)
    if ($Condition) { Write-Host ("  PASS  " + $Name) -ForegroundColor Green }
    else { Write-Host ("  FAIL  " + $Name) -ForegroundColor Red; $script:Failures++ }
}

# Use the same engine that is running this test file, in a child process.
$exe = if ($PSVersionTable.PSVersion.Major -ge 6) { 'pwsh' } else { 'powershell' }
$ScriptPath = (Resolve-Path $ScriptPath).Path
$Fixture    = (Resolve-Path $Fixture).Path
$tmp        = [System.IO.Path]::GetTempPath()
$outNormal  = Join-Path $tmp 'pfreport-test.html'
$outRedact  = Join-Path $tmp 'pfreport-test-redacted.html'

Write-Host ("Testing {0} with {1} ({2})" -f (Split-Path $ScriptPath -Leaf), $exe, $PSVersionTable.PSVersion)

# 1. Static parse check
$perr = $null
[System.Management.Automation.Language.Parser]::ParseFile($ScriptPath, [ref]$null, [ref]$perr) | Out-Null
Check "script parses with no syntax errors" (-not $perr)

# 2. Normal run against the fixture
& $exe -NoProfile -ExecutionPolicy Bypass -File $ScriptPath -ConfigPath $Fixture -OutputPath $outNormal | Out-Null
$exit = $LASTEXITCODE
Check "normal run exits 0" ($exit -eq 0)
Check "output HTML created" (Test-Path $outNormal)

$h = if (Test-Path $outNormal) { Get-Content $outNormal -Raw } else { '' }
Check "self-contained (no external http/https refs)" (-not ($h -match 'src="https?://' -or $h -match 'href="https?://' -or $h -match '@import'))
Check "renders all 17 sections" (([regex]::Matches($h, '<section class="report-section" id=')).Count -ge 17)
Check "WAN TCP any->any flagged HIGH RISK" ($h -match 'HIGH RISK')
Check "WAN ICMP treated as low risk (WAN ICMP)" ($h -match 'WAN ICMP')
Check "LAN/internal interface marked TRUSTED" ($h -match 'TRUSTED / INTERNAL')
Check "certificate parsed (subject CN present)" ($h -match 'demo-fw\.example\.com')
Check "certificate usage context resolved" ($h -match 'WebGUI HTTPS certificate')
Check "port forward rendered" ($h -match 'HTTPS to web server')
Check "1:1 NAT rendered" ($h -match '1:1 mapping')

# 3. Secret-leakage checks (must never appear in output).
#    Case-sensitive PEM header match so the "Private key material is never exported"
#    disclaimer text is not mistaken for an actual leaked key block.
Check "no PEM PRIVATE KEY block leaked" (-not ($h -cmatch 'BEGIN [A-Z ]*PRIVATE KEY'))
Check "no bcrypt hash leaked" (-not ($h -match '\$2y\$'))
Check "no private-key placeholder leaked" (-not ($h -match 'NOT-A-REAL-PRIVATE-KEY'))
Check "PSK shown when NOT redacted" ($h -match 'EXAMPLEPSKdonotuse')

# 4. Redacted run
& $exe -NoProfile -ExecutionPolicy Bypass -File $ScriptPath -ConfigPath $Fixture -OutputPath $outRedact -Redact | Out-Null
Check "redacted run exits 0" ($LASTEXITCODE -eq 0)
$r = if (Test-Path $outRedact) { Get-Content $outRedact -Raw } else { '' }
Check "redacted: PSK removed" (-not ($r -match 'EXAMPLEPSKdonotuse'))
Check "redacted: documentation IP 192.0.2.1 masked" (-not ($r -match '192\.0\.2\.1\b'))
Check "redacted: stable IP tokens present (IP-NNN)" ($r -match 'IP-\d{3}')

# 5. Error handling: missing config => exit 1.
#    The child writes to stderr; relax EAP locally so 5.1 does not promote that
#    native-stderr output to a terminating error before we read the exit code.
$prevEAP = $ErrorActionPreference
$ErrorActionPreference = 'Continue'
& $exe -NoProfile -ExecutionPolicy Bypass -File $ScriptPath -ConfigPath (Join-Path $tmp 'does-not-exist-xyz.xml') -OutputPath $outNormal 2>$null | Out-Null
$missingExit = $LASTEXITCODE
$ErrorActionPreference = $prevEAP
Check "missing config file exits 1" ($missingExit -eq 1)

# Cleanup temp artifacts
Remove-Item $outNormal, $outRedact -ErrorAction SilentlyContinue

Write-Host ''
if ($script:Failures -gt 0) {
    Write-Host ("{0} test(s) FAILED." -f $script:Failures) -ForegroundColor Red
    exit 1
}
Write-Host "All tests passed." -ForegroundColor Green
exit 0
