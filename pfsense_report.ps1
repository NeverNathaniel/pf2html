<#
.SYNOPSIS
    Generate a professional, self-contained HTML report from a pfSense config.xml.

.DESCRIPTION
    pfsense_report.ps1 parses a pfSense configuration backup (config.xml) entirely
    locally using PowerShell's built-in XML reader and the .NET base class library.
    It produces a single, self-contained .html file (all CSS / JS embedded) that can be
    opened in any modern browser on an air-gapped machine and printed to PDF.

    No AI, no external API, no internet connection, and no third-party modules are used.
    Compatible with Windows PowerShell 5.1 and PowerShell 7+ (Windows, Linux, macOS).

.PARAMETER ConfigPath
    Path to the pfSense config.xml file to parse. (Required unless dot-sourced for tests.)

.PARAMETER OutputPath
    Path of the .html report to write. Defaults to "<configname>-report.html"
    in the current directory.

.PARAMETER Redact
    Replace sensitive values (PSKs, SNMP communities) with [REDACTED] and mask IP
    addresses, MAC addresses, hostnames, domains, usernames, and certificate org
    attributes using stable correlation tokens so the report can be shared safely.
    Password hashes, private keys, WireGuard keys, LDAP/RADIUS secrets, HA sync
    passwords, DynDNS passwords, and OpenVPN TLS static keys are NEVER emitted
    regardless of this switch.

.PARAMETER Title
    Custom title shown in the report header. Defaults to "pfSense Configuration Report".

.PARAMETER LogoPath
    Optional path to a logo image (png/jpg/gif/svg/webp). Embedded as inline base64.

.PARAMETER WanInterfaces
    Optional list of interface keys (e.g. 'opt2','opt3') to force as untrusted / WAN
    for firewall risk scoring.

.PARAMETER InternalInterfaces
    Optional list of interface keys (e.g. 'opt1') to force as trusted / internal
    for firewall risk scoring (useful for internal transit interfaces with gateways).

.PARAMETER ExpiryWarnDays
    Number of days before certificate expiration to flag EXPIRING SOON. Defaults to 90.

.PARAMETER JsonPath
    Optional path to also export a structured JSON summary of metadata, counts, and
    security findings (respects -Redact).

.PARAMETER PassThru
    Emit a summary object containing output path, counts, and findings to the pipeline.

.PARAMETER Quiet
    Suppress status console output (errors and warnings are still written).

.EXAMPLE
    .\pfsense_report.ps1 -ConfigPath "config.xml" -OutputPath "report.html"

.EXAMPLE
    .\pfsense_report.ps1 -ConfigPath "config.xml" -OutputPath "shared.html" -Redact -Title "Acme Firewall"

.EXAMPLE
    .\pfsense_report.ps1 -ConfigPath "config.xml" -JsonPath "findings.json" -PassThru -Quiet
#>

[CmdletBinding()]
param(
    [Parameter(Position = 0)]
    [string]$ConfigPath,

    [Parameter(Position = 1)]
    [string]$OutputPath,

    [switch]$Redact,

    [string]$Title = "pfSense Configuration Report",

    [string]$LogoPath,

    [string[]]$WanInterfaces,

    [string[]]$InternalInterfaces,

    [ValidateRange(1, 3650)]
    [int]$ExpiryWarnDays = 90,

    [string]$JsonPath,

    [switch]$PassThru,

    [switch]$Quiet
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# ----------------------------------------------------------------------------------
#  Script-scoped state & constants
# ----------------------------------------------------------------------------------
$script:ToolVersion = '1.1.0'

function Initialize-ReportContext {
    param(
        [bool]$RedactMode = $false,
        [int]$ExpiryWarnDaysValue = 90,
        [datetime]$NowValue = (Get-Date)
    )
    $script:IsRedacted             = $RedactMode
    $script:RedactHost         = $null
    $script:RedactDomain       = $null
    $script:ExpiryWarnDays     = $ExpiryWarnDaysValue
    $script:Now                = $NowValue
    $script:Findings           = New-Object 'System.Collections.Generic.List[object]'
    $script:RedactMaps         = @{ IP = @{}; MAC = @{}; HOST = @{}; DOMAIN = @{}; USER = @{}; ORG = @{} }
    $script:HasPlaintextSecret = $false
    $script:AliasMap           = @{}
    $script:GatewayMap         = @{}
    $script:VlanMap            = @{}
    $script:CertRefMap         = @{}
    $script:RefUsageMap        = @{}
    $script:IfMap              = @{}
    $script:TrustMap           = @{}
    $script:InternalNoLogCount = 0
}

Initialize-ReportContext -RedactMode ([bool]$Redact) -ExpiryWarnDaysValue $ExpiryWarnDays

# ==================================================================================
#  HELPER FUNCTIONS
# ==================================================================================

function Resolve-FullPath {
    param([string]$PathValue)
    if ([string]::IsNullOrWhiteSpace($PathValue)) { return '' }
    return $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($PathValue)
}

function Read-PfSenseXml {
    param([string]$PathValue)
    $full = Resolve-FullPath $PathValue
    if (-not (Test-Path -LiteralPath $full -PathType Leaf)) {
        if (Test-Path -LiteralPath $full -PathType Container) {
            throw "Config path is a directory, not a file: $PathValue"
        }
        throw "Config file not found: $PathValue"
    }
    $settings = New-Object System.Xml.XmlReaderSettings
    $settings.DtdProcessing = [System.Xml.DtdProcessing]::Prohibit
    $settings.XmlResolver = $null
    $settings.IgnoreComments = $true
    $xml = New-Object System.Xml.XmlDocument
    $xml.XmlResolver = $null
    $reader = $null
    try {
        $reader = [System.Xml.XmlReader]::Create($full, $settings)
        $xml.Load($reader)
    }
    finally {
        if ($null -ne $reader) { $reader.Dispose() }
    }
    return $xml
}

function Format-Slug {
    param([string]$Value)
    if ([string]::IsNullOrWhiteSpace($Value)) { return 'item' }
    $s = [regex]::Replace($Value.Trim().ToLowerInvariant(), '[^a-z0-9_-]+', '-').Trim('-')
    if ([string]::IsNullOrEmpty($s)) { return 'item' }
    return $s
}

function Get-RedactToken {
    param([string]$value, [string]$kind)
    if ([string]::IsNullOrWhiteSpace($value)) { return $value }
    $key = $value.Trim()
    if (-not $script:RedactMaps.ContainsKey($kind)) { $kind = 'HOST' }
    $map = $script:RedactMaps[$kind]
    if (-not $map.ContainsKey($key)) {
        $map[$key] = ('{0}-{1:000}' -f $kind, ($map.Count + 1))
    }
    return $map[$key]
}

function Test-IsRedactToken {
    param([string]$value)
    return ($value -match '^(?:IP|MAC|HOST|DOMAIN|USER|ORG)-\d{3}(?:\.(?:IP|MAC|HOST|DOMAIN|USER|ORG)-\d{3})*$')
}

function Apply-Redaction {
    param([string]$text)
    if (-not $script:IsRedacted) { return $text }
    if ([string]::IsNullOrEmpty($text)) { return $text }
    $t = $text

    # 1. MAC addresses (colon or hyphen delimited, consistent separator) -> MAC-NNN
    $t = [regex]::Replace($t, '(?i)(?<![0-9a-f:-])([0-9a-f]{2})([:-])(?:[0-9a-f]{2}\2){4}[0-9a-f]{2}(?![0-9a-f:-])',
        [System.Text.RegularExpressions.MatchEvaluator] {
            param($m)
            $norm = ($m.Value -replace '-', ':').ToLowerInvariant()
            return (Get-RedactToken $norm 'MAC')
        })

    # 2. IPv4 addresses (valid 0-255 octets, not part of longer dotted OID/version) -> IP-NNN
    $t = [regex]::Replace($t, '(?<![.\d])(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})(?![.\d])',
        [System.Text.RegularExpressions.MatchEvaluator] {
            param($m)
            for ($i = 1; $i -le 4; $i++) {
                $oct = [int]$m.Groups[$i].Value
                if ($oct -gt 255) { return $m.Value }
            }
            return (Get-RedactToken $m.Value 'IP')
        })

    # 3. IPv6 addresses (full 8-group or compressed '::', validated by IPAddress.TryParse;
    #    never touches HH:MM:SS timestamps because they lack '::' and have only 2 colons)
    $t = [regex]::Replace($t, '(?i)(?<![0-9a-f:])(?:[0-9a-f]{0,4}:){2,7}[0-9a-f]{0,4}(?![0-9a-f:])',
        [System.Text.RegularExpressions.MatchEvaluator] {
            param($m)
            $cand = $m.Value
            $hasDouble = $cand.Contains('::')
            $colonCount = @($cand.ToCharArray() | Where-Object { $_ -eq ':' }).Count
            if (-not $hasDouble -and $colonCount -lt 7) { return $cand }
            if ($cand -eq '::') { return $cand }
            $ipObj = $null
            if ([System.Net.IPAddress]::TryParse($cand, [ref]$ipObj) -and
                $ipObj.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetworkV6) {
                return (Get-RedactToken $ipObj.ToString() 'IP')
            }
            return $cand
        })

    # 4. Email addresses (mask local-part as USER-NNN and domain consistently)
    $t = [regex]::Replace($t, '(?i)\b([a-z0-9._%+-]+)@([a-z0-9-]+(?:\.[a-z0-9-]+)+|IP-\d{3})\b',
        [System.Text.RegularExpressions.MatchEvaluator] {
            param($m)
            $uTok = Get-RedactToken $m.Groups[1].Value.ToLowerInvariant() 'USER'
            $domPart = $m.Groups[2].Value
            if (Test-IsRedactToken $domPart) { return ($uTok + '@' + $domPart) }
            if ($script:RedactDomain -and $domPart -ieq $script:RedactDomain) {
                return ($uTok + '@' + (Get-RedactToken $script:RedactDomain 'DOMAIN'))
            }
            return ($uTok + '@' + (Get-RedactToken $domPart.ToLowerInvariant() 'DOMAIN'))
        })

    # 5. FQDNs (preserve HOST-NNN.DOMAIN-NNN correlation with system domain; skip generated tokens & filenames)
    $skipExts = @('ps1','xml','html','htm','php','sh','conf','cfg','pem','crt','cer','key','log','json','csv','txt','zip','tar','gz','exe','dll','png','jpg','jpeg','gif','svg','webp','pdf','md')
    $t = [regex]::Replace($t, '(?i)\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{1,62}\b',
        [System.Text.RegularExpressions.MatchEvaluator] {
            param($m)
            $val = $m.Value
            if (Test-IsRedactToken $val) { return $val }
            $lastDot = $val.LastIndexOf('.')
            if ($lastDot -gt 0) {
                $ext = $val.Substring($lastDot + 1).ToLowerInvariant()
                if ($skipExts -contains $ext) { return $val }
            }
            if ($script:RedactDomain) {
                if ($val -ieq $script:RedactDomain) {
                    return (Get-RedactToken $script:RedactDomain 'DOMAIN')
                }
                $suffix = '.' + $script:RedactDomain
                if ($val.Length -gt $suffix.Length -and $val.EndsWith($suffix, [System.StringComparison]::OrdinalIgnoreCase)) {
                    $hostPart = $val.Substring(0, $val.Length - $suffix.Length)
                    return ((Get-RedactToken $hostPart.ToLowerInvariant() 'HOST') + '.' + (Get-RedactToken $script:RedactDomain 'DOMAIN'))
                }
            }
            return (Get-RedactToken $val.ToLowerInvariant() 'HOST')
        })

    # 6. Specific system domain / bare hostname with strict word boundaries (no substring mangling)
    if ($script:RedactDomain) {
        $domTok = Get-RedactToken $script:RedactDomain 'DOMAIN'
        $pat = '(?i)(?<![a-z0-9_-])' + [regex]::Escape($script:RedactDomain) + '(?![a-z0-9_-])'
        $t = [regex]::Replace($t, $pat, [System.Text.RegularExpressions.MatchEvaluator] { param($m) $null = $m; return $domTok })
    }
    if ($script:RedactHost) {
        $hostTok = Get-RedactToken $script:RedactHost 'HOST'
        $pat = '(?i)(?<![a-z0-9_-])' + [regex]::Escape($script:RedactHost) + '(?![a-z0-9_-])'
        $t = [regex]::Replace($t, $pat, [System.Text.RegularExpressions.MatchEvaluator] { param($m) $null = $m; return $hostTok })
    }

    return $t
}

function E {
    # Encode a raw data value for safe HTML output (applies redaction first).
    param([object]$s)
    if ($null -eq $s) { return '' }
    $str = [string]$s
    if ($script:IsRedacted) { $str = Apply-Redaction $str }
    return [System.Net.WebUtility]::HtmlEncode($str)
}

function E-Host {
    # Encode a hostname field: under -Redact, even single-label hostnames become HOST-NNN.
    param([object]$s)
    if ($null -eq $s) { return '' }
    $str = ([string]$s).Trim()
    if ([string]::IsNullOrWhiteSpace($str)) { return '<span class="muted">&mdash;</span>' }
    if ($script:IsRedacted) {
        if ($str.Contains('.') -or $str.Contains(':')) {
            return (E $str)
        }
        return [System.Net.WebUtility]::HtmlEncode((Get-RedactToken $str.ToLowerInvariant() 'HOST'))
    }
    return [System.Net.WebUtility]::HtmlEncode($str)
}

function E-User {
    # Encode a username field: under -Redact, local usernames become USER-NNN.
    param([object]$s)
    if ($null -eq $s) { return '' }
    $str = ([string]$s).Trim()
    if ([string]::IsNullOrWhiteSpace($str)) { return '<span class="muted">&mdash;</span>' }
    if ($script:IsRedacted) {
        if ($str -match '@') { return (E $str) }
        return [System.Net.WebUtility]::HtmlEncode((Get-RedactToken $str.ToLowerInvariant() 'USER'))
    }
    return [System.Net.WebUtility]::HtmlEncode($str)
}

function E-CertDn {
    # Encode an X.509 Distinguished Name; under -Redact also masks O/OU/L/ST/email attributes.
    param([object]$s)
    if ($null -eq $s) { return '<span class="muted">&mdash;</span>' }
    $str = ([string]$s).Trim()
    if ([string]::IsNullOrWhiteSpace($str)) { return '<span class="muted">&mdash;</span>' }
    if ($script:IsRedacted) {
        $str = [regex]::Replace($str, '(?i)\b(O|OU|L|ST|S|STREET)=([^,]+)',
            [System.Text.RegularExpressions.MatchEvaluator] {
                param($m)
                $attr = $m.Groups[1].Value
                $val  = $m.Groups[2].Value.Trim()
                return ($attr + '=' + (Get-RedactToken $val 'ORG'))
            })
        $str = [regex]::Replace($str, '(?i)\b(CN)=([^,]+)',
            [System.Text.RegularExpressions.MatchEvaluator] {
                param($m)
                $val = $m.Groups[2].Value.Trim()
                $red = Apply-Redaction $val
                if ($red -eq $val -and -not (Test-IsRedactToken $val)) {
                    $red = Get-RedactToken $val 'HOST'
                }
                return ($m.Groups[1].Value + '=' + $red)
            })
        $str = Apply-Redaction $str
    }
    return [System.Net.WebUtility]::HtmlEncode($str)
}

function Dash {
    # Encode a value; show an em-dash placeholder when empty.
    param([object]$s)
    if ($null -eq $s) { return '<span class="muted">&mdash;</span>' }
    $str = [string]$s
    if ([string]::IsNullOrWhiteSpace($str)) { return '<span class="muted">&mdash;</span>' }
    return (E $str)
}

function DashMono {
    # Encode a technical value (IP, MAC, CIDR, port, device) in monospace.
    param([object]$s)
    if ($null -eq $s) { return '<span class="muted">&mdash;</span>' }
    $str = [string]$s
    if ([string]::IsNullOrWhiteSpace($str)) { return '<span class="muted">&mdash;</span>' }
    return '<code class="mono">' + (E $str) + '</code>'
}

function Secret {
    # PSKs / SNMP communities: click-to-reveal masked on screen when not redacted,
    # completely replaced with [REDACTED] under -Redact.
    param([object]$s)
    if ($null -eq $s) { return '<span class="muted">&mdash;</span>' }
    $str = [string]$s
    if ([string]::IsNullOrWhiteSpace($str)) { return '<span class="muted">&mdash;</span>' }
    if ($script:IsRedacted) { return '<span class="redacted">[REDACTED]</span>' }
    $script:HasPlaintextSecret = $true
    return '<span class="secret-wrap"><code class="mono secret-val is-masked">' +
           [System.Net.WebUtility]::HtmlEncode($str) +
           '</code><button type="button" class="secret-btn" aria-label="Toggle secret visibility">Show</button></span>'
}

function XText {
    param($node, [string]$path)
    if ($null -eq $node) { return '' }
    $n = $node.SelectSingleNode($path)
    if ($null -eq $n) { return '' }
    return ([string]$n.InnerText).Trim()
}

function XHas {
    param($node, [string]$path)
    if ($null -eq $node) { return $false }
    return ($null -ne $node.SelectSingleNode($path))
}

function XNodes {
    # Always returns a real array (never collapses to a scalar). Windows PowerShell 5.1
    # unwraps single-element collections returned from functions, and .Count on the
    # resulting scalar throws under StrictMode or returns $null. The ',$arr' return
    # guarantees array semantics on both 5.1 and 7.
    param($node, [string]$path)
    $list = New-Object 'System.Collections.Generic.List[object]'
    if ($null -ne $node) {
        $r = $node.SelectNodes($path)
        if ($null -ne $r) {
            foreach ($n in $r) { [void]$list.Add($n) }
        }
    }
    $arr = $list.ToArray()
    return , $arr
}

function YesNo {
    param([bool]$b)
    if ($b) { return '<span class="badge badge-ok">Yes</span>' }
    return '<span class="badge badge-muted">No</span>'
}

function Add-Finding {
    param(
        [string]$Sev,
        [string]$Label,
        [string]$Where,
        [string]$Detail,
        [string]$TargetId = ''
    )
    [void]$script:Findings.Add([pscustomobject]@{
        Sev      = $Sev
        Label    = $Label
        Where    = $Where
        Detail   = $Detail
        TargetId = $TargetId
    })
}

function ConvertFrom-Epoch {
    param([string]$s)
    if ([string]::IsNullOrWhiteSpace($s)) { return '' }
    $n = [int64]0
    if ([int64]::TryParse($s, [ref]$n)) {
        try {
            return ([DateTimeOffset]::FromUnixTimeSeconds($n)).ToLocalTime().ToString('yyyy-MM-dd HH:mm:ss zzz')
        }
        catch {
            Write-Verbose ("Could not parse Unix timestamp '{0}': {1}" -f $s, $_.Exception.Message)
            return $s
        }
    }
    return $s
}

function Get-Ipv4Mask {
    param([string]$bits)
    $b = 0
    if (-not [int]::TryParse($bits, [ref]$b)) { return '' }
    if ($b -lt 0 -or $b -gt 32) { return '' }
    $octets = @(0, 0, 0, 0)
    for ($i = 0; $i -lt 4; $i++) {
        $take = [math]::Min(8, [math]::Max(0, $b - ($i * 8)))
        if ($take -le 0)     { $octets[$i] = 0 }
        elseif ($take -ge 8) { $octets[$i] = 255 }
        else                 { $octets[$i] = [int](256 - [math]::Pow(2, 8 - $take)) }
    }
    return ($octets -join '.')
}

function Test-IsPrivateIpv4 {
    param([string]$ip)
    if ([string]::IsNullOrWhiteSpace($ip)) { return $false }
    $ipObj = $null
    if (-not [System.Net.IPAddress]::TryParse($ip.Trim(), [ref]$ipObj)) { return $false }
    if ($ipObj.AddressFamily -ne [System.Net.Sockets.AddressFamily]::InterNetwork) { return $false }
    $b = $ipObj.GetAddressBytes()
    if ($b[0] -eq 10) { return $true }
    if ($b[0] -eq 172 -and $b[1] -ge 16 -and $b[1] -le 31) { return $true }
    if ($b[0] -eq 192 -and $b[1] -eq 168) { return $true }
    if ($b[0] -eq 100 -and $b[1] -ge 64 -and $b[1] -le 127) { return $true }
    if ($b[0] -eq 169 -and $b[1] -eq 254) { return $true }
    return $false
}

function Get-WeakCryptoHits {
    param([string[]]$values)
    $high = New-Object 'System.Collections.Generic.List[string]'
    $warn = New-Object 'System.Collections.Generic.List[string]'
    foreach ($v in $values) {
        if ([string]::IsNullOrWhiteSpace($v)) { continue }
        if ($v -match '(?i)(3des|des-ede|tripledes)')               { [void]$high.Add('3DES') }
        elseif ($v -match '(?i)(^|[^a-z0-9])des([^a-z0-9]|$)')      { [void]$high.Add('DES') }
        if ($v -match '(?i)md5')                                    { [void]$high.Add('MD5') }
        if ($v -match '(?i)(^|[^a-z0-9])rc4([^a-z0-9]|$)')          { [void]$high.Add('RC4') }
        if ($v -match '(?i)(blowfish|(^|[^a-z0-9])bf-)')            { [void]$high.Add('Blowfish') }
        if ($v -match '(?i)(cast128|(^|[^a-z0-9])cast-)')           { [void]$high.Add('CAST128') }
        if ($v -match '(?i)(^|[^a-z0-9])(null|none)([^a-z0-9]|$)')  { [void]$high.Add('NULL') }
        if ($v -match '(?i)(^|[^a-z0-9])(hmac_)?sha1([^0-9]|$)')    { [void]$warn.Add('SHA-1') }
    }
    return [pscustomobject]@{
        High = @($high | Select-Object -Unique)
        Warn = @($warn | Select-Object -Unique)
    }
}

function Get-WeakDhFinding {
    param([string]$group, [bool]$isPfs = $false)
    if ([string]::IsNullOrWhiteSpace($group)) { return $null }
    $g = $group.Trim()
    if ($isPfs -and ($g -eq '0' -or $g -ieq 'off')) {
        return [pscustomobject]@{ Sev = 'warn'; Label = 'NO PFS'; Detail = 'Perfect Forward Secrecy (PFS) is disabled.' }
    }
    if ($g -in @('1', '2')) {
        return [pscustomobject]@{ Sev = 'high'; Label = 'WEAK CRYPTO'; Detail = "Uses weak DH group $g (<2048-bit MODP)." }
    }
    if ($g -in @('5', '22', '23', '24')) {
        return [pscustomobject]@{ Sev = 'warn'; Label = 'LEGACY CRYPTO'; Detail = "Uses legacy/deprecated DH group $g." }
    }
    return $null
}

function Get-CertInfo {
    param([string]$CrtField)
    $r = [pscustomobject]@{
        Subject    = ''
        Issuer     = ''
        NotBefore  = $null
        NotAfter   = $null
        SigAlg     = ''
        KeyAlg     = ''
        KeySize    = 0
        SelfSigned = $false
        Error      = $null
    }
    if ([string]::IsNullOrWhiteSpace($CrtField)) { $r.Error = 'No certificate data'; return $r }
    $cert = $null
    try {
        $pem = $CrtField.Trim()
        if ($pem -notmatch 'BEGIN CERTIFICATE') {
            try {
                $pem = [System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String(($CrtField -replace '\s', '')))
            }
            catch {
                Write-Verbose ("Outer base64 decode failed for certificate: {0}" -f $_.Exception.Message)
            }
        }
        if ($pem -notmatch 'BEGIN CERTIFICATE') { $r.Error = 'Unrecognized certificate format'; return $r }
        $m = [regex]::Match($pem, '-----BEGIN CERTIFICATE-----(.*?)-----END CERTIFICATE-----', [System.Text.RegularExpressions.RegexOptions]::Singleline)
        if (-not $m.Success) { $r.Error = 'Could not extract certificate body'; return $r }
        $der  = [Convert]::FromBase64String(($m.Groups[1].Value -replace '\s', ''))
        $cert = New-Object 'System.Security.Cryptography.X509Certificates.X509Certificate2' -ArgumentList (, $der)
        $r.Subject    = $cert.Subject
        $r.Issuer     = $cert.Issuer
        $r.NotBefore  = $cert.NotBefore
        $r.NotAfter   = $cert.NotAfter
        $r.SigAlg     = $cert.SignatureAlgorithm.FriendlyName
        $r.SelfSigned = ($cert.Subject -eq $cert.Issuer)
        try {
            $rsa = [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPublicKey($cert)
            if ($null -ne $rsa) {
                $r.KeyAlg  = 'RSA'
                $r.KeySize = $rsa.get_KeySize()
                $rsa.Dispose()
            }
            else {
                $ecdsa = [System.Security.Cryptography.X509Certificates.ECDsaCertificateExtensions]::GetECDsaPublicKey($cert)
                if ($null -ne $ecdsa) {
                    $r.KeyAlg  = 'ECDSA'
                    $r.KeySize = $ecdsa.get_KeySize()
                    $ecdsa.Dispose()
                }
            }
        }
        catch {
            Write-Verbose ("Could not inspect certificate public key: {0}" -f $_.Exception.Message)
        }
    }
    catch {
        $r.Error = $_.Exception.Message
    }
    finally {
        if ($null -ne $cert) { $cert.Dispose() }
    }
    return $r
}

function Format-CertStatus {
    # Returns an HTML badge describing certificate validity, and records findings.
    param($info, [string]$where, [string]$targetId = '')
    if ($info.Error) { return '<span class="badge badge-info">PARSE ERROR</span>' }
    $badges = New-Object System.Text.StringBuilder
    if ($null -ne $info.NotBefore -and $info.NotBefore -gt $script:Now) {
        Add-Finding 'warn' 'NOT YET VALID' $where ("Certificate is not valid until " + $info.NotBefore.ToString('yyyy-MM-dd')) $targetId
        [void]$badges.Append('<span class="badge badge-warn">NOT YET VALID</span> ')
    }
    if ($null -eq $info.NotAfter) {
        [void]$badges.Append('<span class="badge badge-muted">Unknown</span>')
    }
    else {
        $days = ($info.NotAfter - $script:Now).TotalDays
        if ($days -lt 0) {
            Add-Finding 'high' 'EXPIRED' $where ("Certificate expired " + $info.NotAfter.ToString('yyyy-MM-dd')) $targetId
            [void]$badges.Append('<span class="badge badge-high">EXPIRED</span>')
        }
        elseif ($days -lt $script:ExpiryWarnDays) {
            Add-Finding 'warn' 'EXPIRING SOON' $where ("Certificate expires " + $info.NotAfter.ToString('yyyy-MM-dd') + " (" + [int]$days + " days)") $targetId
            [void]$badges.Append('<span class="badge badge-warn">EXPIRING SOON</span>')
        }
        elseif ($badges.Length -eq 0) {
            [void]$badges.Append('<span class="badge badge-ok">Valid</span>')
        }
    }
    # Check signature algorithm and RSA key length
    if ($info.SigAlg -match '(?i)md5') {
        Add-Finding 'high' 'WEAK CERT' $where ("Certificate uses weak signature algorithm: " + $info.SigAlg) $targetId
        [void]$badges.Append(' <span class="badge badge-high">MD5 SIG</span>')
    }
    elseif ($info.SigAlg -match '(?i)sha1') {
        Add-Finding 'warn' 'WEAK CERT' $where ("Certificate uses deprecated SHA-1 signature algorithm: " + $info.SigAlg) $targetId
        [void]$badges.Append(' <span class="badge badge-warn">SHA-1 SIG</span>')
    }
    if ($info.KeyAlg -eq 'RSA' -and $info.KeySize -gt 0 -and $info.KeySize -lt 2048) {
        Add-Finding 'high' 'WEAK CERT' $where ("Certificate uses short RSA key (" + $info.KeySize + "-bit; <2048-bit).") $targetId
        [void]$badges.Append(' <span class="badge badge-high">WEAK KEY</span>')
    }
    return $badges.ToString().Trim()
}

function Tbl {
    param([string[]]$headers, [string]$bodyHtml, [string]$tableClass = '')
    $sb = New-Object System.Text.StringBuilder
    $cls = if ($tableClass) { ' class="' + $tableClass + '"' } else { '' }
    [void]$sb.Append('<div class="table-wrap"><table' + $cls + '><thead><tr>')
    foreach ($x in $headers) {
        [void]$sb.Append('<th>').Append($x).Append('</th>')
    }
    [void]$sb.Append('</tr></thead><tbody>').Append($bodyHtml).Append('</tbody></table></div>')
    return $sb.ToString()
}

function Wrap-Section {
    param(
        [string]$id,
        [string]$title,
        [string]$summary,
        [string]$body,
        [string]$headerBadge = ''
    )
    $isEmpty = [string]::IsNullOrWhiteSpace($body)
    $b = if ($isEmpty) { '<p class="not-configured">Not configured.</p>' } else { $body }
    $secCls = if ($isEmpty) { 'report-section section-empty' } else { 'report-section' }
    $sb = New-Object System.Text.StringBuilder
    [void]$sb.Append('<section class="' + $secCls + '" id="' + $id + '">')
    [void]$sb.Append('<h2 class="section-heading"><button type="button" class="section-header" aria-expanded="true">')
    [void]$sb.Append('<span class="toggle-icon" aria-hidden="true">&#9662;</span>')
    [void]$sb.Append('<span class="sh-title">' + $title + '</span>' + $headerBadge + '</button></h2>')
    [void]$sb.Append('<div class="section-body"><p class="section-summary">' + $summary + '</p>' + $b + '</div></section>')
    return $sb.ToString()
}

function Format-Endpoint {
    # Returns a small object describing a firewall/NAT source or destination node.
    param($epNode)
    $o = [pscustomobject]@{ Addr = 'any'; Port = ''; Negated = $false; RawAddr = 'any' }
    if ($null -eq $epNode) { return $o }
    $neg = ''
    if (XHas $epNode 'not') { $neg = '! '; $o.Negated = $true }
    $raw = 'any'
    if (XHas $epNode 'any')           { $raw = 'any' }
    elseif (XText $epNode 'network') { $raw = (XText $epNode 'network') }
    elseif (XText $epNode 'address') { $raw = (XText $epNode 'address') }
    $o.RawAddr = $raw
    $o.Addr = $neg + $raw
    $o.Port = (XText $epNode 'port')
    return $o
}

function Format-RefCell {
    # Format an address/port token with optional Alias cross-link & preview tooltip or friendly interface label.
    param([string]$val, [bool]$negated = $false)
    if ([string]::IsNullOrWhiteSpace($val)) { return '<span class="muted">&mdash;</span>' }
    $clean = $val
    $prefix = ''
    if ($negated -and $clean.StartsWith('! ')) {
        $prefix = '<span class="badge badge-warn">!</span> '
        $clean = $clean.Substring(2)
    }
    elseif ($clean.StartsWith('! ')) {
        $prefix = '<span class="badge badge-warn">!</span> '
        $clean = $clean.Substring(2)
    }
    if ($script:AliasMap.ContainsKey($clean)) {
        $alInfo = $script:AliasMap[$clean]
        $tip = if ($alInfo.Preview) { ' title="' + (E $alInfo.Preview) + '"' } else { '' }
        return $prefix + '<a class="xref alias-ref" href="#' + $alInfo.Id + '"' + $tip + '><code class="mono">' + (E $clean) + '</code></a>'
    }
    if ($clean -eq '(self)') {
        return $prefix + '<code class="mono">This Firewall (self)</code>'
    }
    if ($clean -match '^(.+)ip$') {
        $ifKey = $Matches[1]
        if ($script:IfMap.ContainsKey($ifKey)) {
            return $prefix + '<code class="mono">' + (E $clean) + '</code> <span class="muted">(' + (E $script:IfMap[$ifKey]) + ' addr)</span>'
        }
    }
    if ($script:IfMap.ContainsKey($clean)) {
        return $prefix + '<code class="mono">' + (E $clean) + '</code> <span class="muted">(' + (E $script:IfMap[$clean]) + ' net)</span>'
    }
    return $prefix + '<code class="mono">' + (E $clean) + '</code>'
}

function Format-GatewayRef {
    param([string]$gwName)
    if ([string]::IsNullOrWhiteSpace($gwName)) { return '<span class="muted">&mdash;</span>' }
    if ($script:GatewayMap.ContainsKey($gwName)) {
        return '<a class="xref" href="#' + $script:GatewayMap[$gwName] + '"><code class="mono">' + (E $gwName) + '</code></a>'
    }
    return '<code class="mono">' + (E $gwName) + '</code>'
}

function Format-CertRef {
    param([string]$refid)
    if ([string]::IsNullOrWhiteSpace($refid)) { return '<span class="muted">&mdash;</span>' }
    if ($script:CertRefMap.ContainsKey($refid)) {
        $cInfo = $script:CertRefMap[$refid]
        $label = if ($cInfo.Name) { $cInfo.Name } else { $refid }
        return '<a class="xref" href="#' + $cInfo.Id + '">' + (E $label) + '</a>'
    }
    return '<code class="mono">' + (E $refid) + '</code>'
}

function Get-LogoTag {
    param([string]$path)
    if ([string]::IsNullOrWhiteSpace($path)) { return '' }
    $full = Resolve-FullPath $path
    if (-not (Test-Path -LiteralPath $full -PathType Leaf)) {
        Write-Warning "Logo not found: $path"
        return ''
    }
    try {
        $ext = ([System.IO.Path]::GetExtension($full)).ToLowerInvariant()
        switch ($ext) {
            '.png'  { $mime = 'image/png' }
            '.jpg'  { $mime = 'image/jpeg' }
            '.jpeg' { $mime = 'image/jpeg' }
            '.gif'  { $mime = 'image/gif' }
            '.svg'  { $mime = 'image/svg+xml' }
            '.webp' { $mime = 'image/webp' }
            default {
                Write-Warning "Unsupported logo format '$ext' (expected png/jpg/gif/svg/webp). Skipping logo."
                return ''
            }
        }
        $fi = Get-Item -LiteralPath $full
        if ($fi.Length -gt 2MB) {
            Write-Warning ("Logo file is large ({0:N1} MB); embedding as base64 will increase report size." -f ($fi.Length / 1MB))
        }
        $bytes = [System.IO.File]::ReadAllBytes($full)
        $b64   = [Convert]::ToBase64String($bytes)
        return '<img class="cover-logo" alt="Logo" src="data:' + $mime + ';base64,' + $b64 + '" />'
    }
    catch {
        Write-Warning "Could not embed logo: $($_.Exception.Message)"
        return ''
    }
}

function Build-RefUsageMap {
    # Single-pass O(N) DOM traversal indexing every refid reference (no XPath string interpolation).
    param($root)
    $map = @{}
    if ($null -eq $root) { return $map }
    $stack = New-Object 'System.Collections.Generic.Stack[System.Xml.XmlNode]'
    $stack.Push($root)
    while ($stack.Count -gt 0) {
        $n = $stack.Pop()
        foreach ($child in $n.ChildNodes) {
            if ($child.NodeType -eq [System.Xml.XmlNodeType]::Element) {
                $stack.Push($child)
            }
        }
        $name = $n.LocalName
        if ($name -eq 'refid') { continue }
        # Only leaf text elements that look like reference pointers
        $hasElementChild = $false
        foreach ($child in $n.ChildNodes) {
            if ($child.NodeType -eq [System.Xml.XmlNodeType]::Element) { $hasElementChild = $true; break }
        }
        if ($hasElementChild) { continue }
        $val = ([string]$n.InnerText).Trim()
        if ([string]::IsNullOrWhiteSpace($val)) { continue }
        if (-not $script:CertRefMap.ContainsKey($val)) { continue }

        $parent = if ($null -ne $n.ParentNode) { $n.ParentNode.LocalName } else { '' }
        $label = switch -regex ("$parent/$name") {
            '^webgui/ssl-certref$'     { 'WebGUI HTTPS certificate'; break }
            '^openvpn-server/certref$' { 'OpenVPN server certificate'; break }
            '^openvpn-server/caref$'   { 'OpenVPN server CA'; break }
            '^openvpn-client/certref$' { 'OpenVPN client certificate'; break }
            '^openvpn-client/caref$'   { 'OpenVPN client CA'; break }
            '^phase1/certref$'         { 'IPsec Phase 1 certificate'; break }
            '^phase1/caref$'           { 'IPsec Phase 1 CA'; break }
            '^cert/caref$'             { 'Issues certificate(s)'; break }
            '^ca/caref$'               { 'Issues intermediate CA(s)'; break }
            '^crl/caref$'              { 'CRL issuer'; break }
            '^user/cert$'              { 'User certificate'; break }
            '^syslog/.*certref$'       { 'Remote Syslog TLS'; break }
            'captiveportal'            { 'Captive Portal HTTPS'; break }
            default                    { "$parent ($name)" }
        }
        if (-not $map.ContainsKey($val)) {
            $map[$val] = New-Object 'System.Collections.Generic.List[string]'
        }
        if (-not $map[$val].Contains($label)) {
            [void]$map[$val].Add($label)
        }
    }
    return $map
}

function Build-LookupMaps {
    param($root, [string[]]$ForceWan, [string[]]$ForceInternal)

    # Interfaces friendly names
    $ifsNode = $root.SelectSingleNode('interfaces')
    if ($null -ne $ifsNode) {
        foreach ($c in $ifsNode.ChildNodes) {
            if ($c.NodeType -eq [System.Xml.XmlNodeType]::Element) {
                $d = XText $c 'descr'
                $script:IfMap[$c.Name] = if ($d) { $d } else { $c.Name.ToUpperInvariant() }
            }
        }
    }
    # Interface groups
    foreach ($ig in (XNodes $root 'ifgroups/ifgroupentry')) {
        $gn = XText $ig 'ifname'
        if ($gn) {
            $gd = XText $ig 'descr'
            $script:IfMap[$gn] = if ($gd) { "Group: $gd" } else { "Interface Group ($gn)" }
        }
    }
    # WireGuard pseudo-interface
    $script:IfMap['WireGuard']  = 'WireGuard'
    $script:IfMap['openvpn']    = 'OpenVPN'
    $script:IfMap['enc0']       = 'IPsec'
    $script:IfMap['ipsec']      = 'IPsec'
    $script:IfMap['l2tp']       = 'L2TP'
    $script:IfMap['(floating)'] = 'Floating rules'

    # Gateways map + default gateway identification
    $gwNode = $root.SelectSingleNode('gateways')
    $defaultGws = @{}
    if ($null -ne $gwNode) {
        $d4 = XText $gwNode 'defaultgw4'
        $d6 = XText $gwNode 'defaultgw6'
        if ($d4 -and $d4 -ne 'automatic' -and $d4 -ne '-') { $defaultGws[$d4] = $true }
        if ($d6 -and $d6 -ne 'automatic' -and $d6 -ne '-') { $defaultGws[$d6] = $true }
    }
    $wanGwIfaces = @{}
    $allGwIfaces = @{}
    foreach ($g in (XNodes $root 'gateways/gateway_item')) {
        $gname = XText $g 'name'
        $gi    = XText $g 'interface'
        $gip   = XText $g 'gateway'
        if ($gname) { $script:GatewayMap[$gname] = 'gw-' + (Format-Slug $gname) }
        if ($gi) {
            $allGwIfaces[$gi] = $true
            $isDefaultGw = ($gname -and $defaultGws.ContainsKey($gname))
            $isPublicGw  = ($gip -and $gip -ne 'dynamic' -and -not (Test-IsPrivateIpv4 $gip))
            if ($isDefaultGw -or $isPublicGw -or $gip -eq 'dynamic') {
                $wanGwIfaces[$gi] = $true
            }
        }
    }
    foreach ($gg in (XNodes $root 'gateways/gateway_group')) {
        $ggname = XText $gg 'name'
        if ($ggname) { $script:GatewayMap[$ggname] = 'gwg-' + (Format-Slug $ggname) }
    }

    $forceWanSet = @{}
    if ($null -ne $ForceWan) { foreach ($x in $ForceWan) { if ($x) { $forceWanSet[$x.Trim().ToLowerInvariant()] = $true } } }
    $forceIntSet = @{}
    if ($null -ne $ForceInternal) { foreach ($x in $ForceInternal) { if ($x) { $forceIntSet[$x.Trim().ToLowerInvariant()] = $true } } }

    # Interface trust classification
    if ($null -ne $ifsNode) {
        foreach ($c in $ifsNode.ChildNodes) {
            if ($c.NodeType -ne [System.Xml.XmlNodeType]::Element) { continue }
            $k = $c.Name
            $kl = $k.ToLowerInvariant()
            if ($forceIntSet.ContainsKey($kl)) { $script:TrustMap[$k] = 'internal'; continue }
            if ($forceWanSet.ContainsKey($kl)) { $script:TrustMap[$k] = 'wan'; continue }

            $dev  = XText $c 'if'
            $dscr = XText $c 'descr'
            if ($dev -match '^(tun_wg|wg|ovpn|ipsec|enc)\d*' -or $dscr -match '(?i)\b(wireguard|wg|vpn|openvpn|ipsec)\b') {
                $script:TrustMap[$k] = 'vpn'
                continue
            }

            $isWan = $false
            if ($kl -eq 'wan') { $isWan = $true }
            if ($wanGwIfaces.ContainsKey($k)) { $isWan = $true }
            $gwv = XText $c 'gateway'
            if ($gwv -and $gwv -ne 'none' -and ($defaultGws.ContainsKey($gwv) -or $wanGwIfaces.ContainsKey($k) -or $kl -ne 'lan')) {
                $isWan = $true
            }
            $ipv = (XText $c 'ipaddr').ToLowerInvariant()
            if ($ipv -in @('dhcp', 'pppoe', 'pptp', 'l2tp')) { $isWan = $true }
            if ($kl -match 'wan' -or $dscr -match '(?i)\b(wan|internet|isp|untrust|external)\b') { $isWan = $true }
            $script:TrustMap[$k] = if ($isWan) { 'wan' } else { 'internal' }
        }
    }
    $script:TrustMap['openvpn']    = 'vpn'
    $script:TrustMap['enc0']       = 'vpn'
    $script:TrustMap['ipsec']      = 'vpn'
    $script:TrustMap['l2tp']       = 'vpn'
    $script:TrustMap['WireGuard']  = 'vpn'
    $script:TrustMap['(floating)'] = 'floating'

    # VLANs
    foreach ($v in (XNodes $root 'vlans/vlan')) {
        $vif = XText $v 'vlanif'
        $tag = XText $v 'tag'
        if ($vif) { $script:VlanMap[$vif] = [pscustomobject]@{ Tag = $tag; Id = 'vlan-' + (Format-Slug $vif) } }
    }

    # Aliases (for cross-links & hover previews)
    foreach ($a in (XNodes $root 'aliases/alias')) {
        $an = XText $a 'name'
        if ($an) {
            $addr = XText $a 'address'
            if (-not $addr) { $addr = XText $a 'url' }
            $items = @($addr -split '\s+' | Where-Object { $_ })
            $preview = if ($items.Count -gt 6) {
                (($items[0..5]) -join ', ') + " (+$($items.Count - 6) more)"
            }
            else {
                $items -join ', '
            }
            $script:AliasMap[$an] = [pscustomobject]@{
                Id      = 'alias-' + (Format-Slug $an)
                Type    = XText $a 'type'
                Preview = $preview
            }
        }
    }

    # Certs & CAs
    foreach ($c in (XNodes $root 'ca')) {
        $rid = XText $c 'refid'
        if ($rid) {
            $script:CertRefMap[$rid] = [pscustomobject]@{
                Name = XText $c 'descr'
                Id   = 'ca-' + (Format-Slug $rid)
            }
        }
    }
    foreach ($c in (XNodes $root 'cert')) {
        $rid = XText $c 'refid'
        if ($rid) {
            $script:CertRefMap[$rid] = [pscustomobject]@{
                Name = XText $c 'descr'
                Id   = 'cert-' + (Format-Slug $rid)
            }
        }
    }

    $script:RefUsageMap = Build-RefUsageMap $root
}

# ==================================================================================
#  SECTION BUILDERS
# ==================================================================================

function Build-System {
    param($root)
    $sys = $root.SelectSingleNode('system')
    if ($null -eq $sys) { return '' }

    $dns = New-Object 'System.Collections.Generic.List[string]'
    foreach ($d in (XNodes $sys 'dnsserver')) {
        $dv = $d.InnerText.Trim()
        if ($dv) { [void]$dns.Add($dv) }
    }
    $ntp = @((XText $sys 'timeservers') -split '\s+' | Where-Object { $_ })
    $tz  = XText $sys 'timezone'
    $gui = $sys.SelectSingleNode('webgui')
    $proto = XText $gui 'protocol'
    if (-not $proto) { $proto = 'https' }
    $port  = XText $gui 'port'
    $portDisp = if ($port) { $port } elseif ($proto -eq 'http') { '80 (default)' } else { '443 (default)' }
    $guiCert = XText $gui 'ssl-certref'
    $noAntiLockout = XHas $gui 'noantilockout'
    $noDnsRebind   = XHas $gui 'nodnsrebindcheck'
    $noReferer     = XHas $gui 'nohttpreferercheck'

    if ($proto -ieq 'http') {
        Add-Finding 'high' 'INSECURE WEBGUI' 'System / WebGUI' 'WebGUI is configured to use unencrypted HTTP instead of HTTPS.' 'row-sys-webgui'
    }
    if ($noDnsRebind) {
        Add-Finding 'warn' 'DNS REBIND OFF' 'System / WebGUI' 'DNS Rebind Attack protection is disabled.' 'row-sys-rebind'
    }
    if ($noReferer) {
        Add-Finding 'warn' 'REFERER CHECK OFF' 'System / WebGUI' 'HTTP_REFERER enforcement check is disabled.' 'row-sys-referer'
    }

    $sshNode = $sys.SelectSingleNode('ssh')
    $sshEnabled = $false
    $sshPort = ''
    $sshKeyOnly = ''
    if ($null -ne $sshNode) {
        if (XHas $sshNode 'enable') {
            $sv = XText $sshNode 'enable'
            if ($sv -eq '' -or $sv -match '(?i)^(enabled|on|yes|true|1)$') { $sshEnabled = $true }
        }
        elseif (XHas $sshNode 'enabled') {
            $sv = XText $sshNode 'enabled'
            if ($sv -eq '' -or $sv -match '(?i)^(enabled|on|yes|true|1)$') { $sshEnabled = $true }
        }
        $sshPort = XText $sshNode 'port'
        $sshKeyOnly = XText $sshNode 'sshdkeyonly'
    }
    if ($sshEnabled -and ($sshKeyOnly -notin @('enabled', 'both'))) {
        Add-Finding 'warn' 'SSH PASSWORD AUTH' 'System / SSH' 'SSH is enabled and permits password authentication (Public Key Only is not enforced).' 'row-sys-ssh'
    }

    $consoleProtected = XHas $sys 'disableconsolemenu'
    if (-not $consoleProtected) {
        Add-Finding 'info' 'UNPROTECTED CONSOLE' 'System / Console' 'Console menu password protection is not enabled.' 'row-sys-console'
    }

    $sb = New-Object System.Text.StringBuilder
    [void]$sb.Append('<div class="table-wrap"><table class="kv">')
    [void]$sb.Append('<tr><th>Hostname</th><td>' + (E-Host (XText $sys 'hostname')) + '</td></tr>')
    [void]$sb.Append('<tr><th>Domain</th><td>' + (Dash (XText $sys 'domain')) + '</td></tr>')
    if ($dns.Count -gt 0) {
        [void]$sb.Append('<tr><th>DNS servers</th><td>' + (($dns | ForEach-Object { DashMono $_ }) -join '<br>') + '</td></tr>')
    }
    else {
        [void]$sb.Append('<tr><th>DNS servers</th><td><span class="muted">&mdash;</span></td></tr>')
    }
    if ($ntp.Count -gt 0) {
        [void]$sb.Append('<tr><th>NTP servers</th><td>' + (($ntp | ForEach-Object { DashMono $_ }) -join '<br>') + '</td></tr>')
    }
    else {
        [void]$sb.Append('<tr><th>NTP servers</th><td><span class="muted">&mdash;</span></td></tr>')
    }
    [void]$sb.Append('<tr><th>Time zone</th><td>' + (Dash $tz) + '</td></tr>')

    $guiBadges = if ($proto -ieq 'http') { ' <span class="badge badge-high">INSECURE HTTP</span>' } else { '' }
    $guiExtra = if ($guiCert) { ' &mdash; Cert: ' + (Format-CertRef $guiCert) } else { '' }
    [void]$sb.Append('<tr id="row-sys-webgui"><th>WebGUI</th><td><code class="mono">' + (E $proto) + '</code> on port <code class="mono">' + (E $portDisp) + '</code>' + $guiExtra + $guiBadges + '</td></tr>')
    [void]$sb.Append('<tr><th>WebGUI anti-lockout</th><td>' + (YesNo (-not $noAntiLockout)) + '</td></tr>')
    [void]$sb.Append('<tr id="row-sys-rebind"><th>DNS rebind check</th><td>' + (YesNo (-not $noDnsRebind)) + '</td></tr>')
    [void]$sb.Append('<tr id="row-sys-referer"><th>HTTP Referer check</th><td>' + (YesNo (-not $noReferer)) + '</td></tr>')

    $sshInfo = YesNo $sshEnabled
    if ($sshEnabled) {
        $sp = if ($sshPort) { $sshPort } else { '22 (default)' }
        $sk = switch ($sshKeyOnly) {
            'enabled' { 'Public key only' }
            'both'    { 'Key + password' }
            default   { 'Password or key' }
        }
        $sshInfo += ' &mdash; Port <code class="mono">' + (E $sp) + '</code> (' + (E $sk) + ')'
    }
    [void]$sb.Append('<tr id="row-sys-ssh"><th>SSH access</th><td>' + $sshInfo + '</td></tr>')
    [void]$sb.Append('<tr id="row-sys-console"><th>Console password protection</th><td>' + (YesNo $consoleProtected) + '</td></tr>')
    [void]$sb.Append('<tr><th>Tuning / optimization</th><td>' + (Dash (XText $sys 'optimization')) + '</td></tr>')
    $crypto = XText $sys 'crypto_hardware'
    if ($crypto) { [void]$sb.Append('<tr><th>Hardware crypto</th><td>' + (E $crypto) + '</td></tr>') }
    $dhcpBackend = XText $root 'dhcpbackend'
    if ($dhcpBackend) { [void]$sb.Append('<tr><th>DHCP backend</th><td>' + (E $dhcpBackend.ToUpperInvariant()) + '</td></tr>') }
    [void]$sb.Append('</table></div>')
    return $sb.ToString()
}

function Build-Interfaces {
    param($root)
    $ifs = $root.SelectSingleNode('interfaces')
    if ($null -eq $ifs) { return '' }
    $sb = New-Object System.Text.StringBuilder
    $any = $false
    foreach ($c in $ifs.ChildNodes) {
        if ($c.NodeType -ne [System.Xml.XmlNodeType]::Element) { continue }
        $any = $true
        $key   = $c.Name
        $rowId = 'row-if-' + (Format-Slug $key)
        $descr = XText $c 'descr'
        $dev   = XText $c 'if'
        $en    = XHas $c 'enable'
        $ipv4  = XText $c 'ipaddr'
        $method = switch -regex ($ipv4) {
            '^dhcp$'   { 'DHCP'; break }
            '^pppoe$'  { 'PPPoE'; break }
            '^pptp$'   { 'PPTP'; break }
            '^l2tp$'   { 'L2TP'; break }
            '^carp$'   { 'CARP'; break }
            '^none$'   { 'None'; break }
            '^\d+\.'   { 'Static'; break }
            '^$'       { 'None'; break }
            default    { $ipv4 }
        }
        $ipv4disp = if ($ipv4 -match '^(dhcp|pppoe|pptp|l2tp|dhcp6|carp|none|)$') { '' } else { $ipv4 }
        $subnet = XText $c 'subnet'
        $mask   = Get-Ipv4Mask $subnet
        $subnetDisp = ''
        if ($ipv4disp -and $subnet) {
            $subnetDisp = '/' + $subnet
            if ($mask) { $subnetDisp += ' (' + $mask + ')' }
        }

        $v6 = XText $c 'ipaddrv6'
        $v6Static = $false
        $v6disp = switch -regex ($v6) {
            '^track6$' {
                $t6if = XText $c 'track6-interface'
                $t6id = XText $c 'track6-prefix-id'
                $lbl = if ($t6if) { 'Track IPv6 (' + $t6if.ToUpperInvariant() + $(if ($t6id -ne '') { ", prefix $t6id" } else { '' }) + ')' } else { 'Track IPv6' }
                $lbl; break
            }
            '^dhcp6$'  { 'DHCP6'; break }
            '^slaac$'  { 'SLAAC'; break }
            '^6rd$'    { '6rd Tunnel'; break }
            '^6to4$'   { '6to4 Tunnel'; break }
            '^none$'   { ''; break }
            '^$'       { ''; break }
            default    { $v6Static = $true; $v6 }
        }
        $sv6 = XText $c 'subnetv6'
        if ($v6Static -and $sv6) { $v6disp += '/' + $sv6 }

        $mac = XText $c 'spoofmac'
        $mtu = XText $c 'mtu'
        $mss = XText $c 'mss'
        $vlanCell = '<span class="muted">&mdash;</span>'
        if ($script:VlanMap.ContainsKey($dev)) {
            $vi = $script:VlanMap[$dev]
            $vlanCell = '<a class="xref" href="#' + $vi.Id + '"><code class="mono">' + (E $vi.Tag) + '</code></a>'
        }
        elseif ($dev -match '\.(\d+)$') {
            $vlanCell = '<code class="mono">' + (E $Matches[1]) + '</code>'
        }
        $gw   = XText $c 'gateway'
        $brfc = XHas $c 'blockpriv'
        $bbog = XHas $c 'blockbogons'

        if ($en -and $script:TrustMap.ContainsKey($key) -and $script:TrustMap[$key] -eq 'wan') {
            if (-not $bbog) {
                Add-Finding 'info' 'BOGONS NOT BLOCKED' "Interface / $key" "WAN interface '$key' does not have 'Block bogon networks' enabled." $rowId
            }
        }

        $cls = if (-not $en) { ' class="row-disabled"' } else { '' }
        [void]$sb.Append('<tr id="' + $rowId + '"' + $cls + '>')
        [void]$sb.Append('<td><code class="mono">' + (E $key) + '</code></td>')
        [void]$sb.Append('<td>' + (Dash $descr) + '</td>')
        [void]$sb.Append('<td>' + (DashMono $dev) + '</td>')
        [void]$sb.Append('<td>' + (YesNo $en) + '</td>')
        [void]$sb.Append('<td>' + (Dash $method) + '</td>')
        [void]$sb.Append('<td>' + (DashMono $ipv4disp) + '</td>')
        [void]$sb.Append('<td>' + (DashMono $subnetDisp) + '</td>')
        [void]$sb.Append('<td>' + (DashMono $v6disp) + '</td>')
        [void]$sb.Append('<td>' + (DashMono $mac) + '</td>')
        [void]$sb.Append('<td>' + (DashMono $mtu) + '</td>')
        [void]$sb.Append('<td>' + (DashMono $mss) + '</td>')
        [void]$sb.Append('<td>' + $vlanCell + '</td>')
        [void]$sb.Append('<td>' + (Format-GatewayRef $gw) + '</td>')
        [void]$sb.Append('<td>' + (YesNo $brfc) + '</td>')
        [void]$sb.Append('<td>' + (YesNo $bbog) + '</td>')
        [void]$sb.Append('</tr>')
    }
    if (-not $any) { return '' }
    return (Tbl @('Key','Description','Device','Enabled','IPv4 Method','IPv4 Address','Subnet','IPv6','MAC (spoof)','MTU','MSS','VLAN','Gateway','Block RFC1918','Block bogons') $sb.ToString())
}

function Build-IfGroupsAndL2 {
    param($root)
    $out = New-Object System.Text.StringBuilder
    $igNodes = XNodes $root 'ifgroups/ifgroupentry'
    if ($igNodes.Count -gt 0) {
        $sb = New-Object System.Text.StringBuilder
        foreach ($g in $igNodes) {
            [void]$sb.Append('<tr>')
            [void]$sb.Append('<td><code class="mono">' + (E (XText $g 'ifname')) + '</code></td>')
            [void]$sb.Append('<td>' + (DashMono (XText $g 'members')) + '</td>')
            [void]$sb.Append('<td>' + (Dash (XText $g 'descr')) + '</td>')
            [void]$sb.Append('</tr>')
        }
        [void]$out.Append('<h3>Interface Groups</h3>')
        [void]$out.Append((Tbl @('Group Name','Members','Description') $sb.ToString()))
    }

    $laggs = XNodes $root 'laggs/lagg'
    if ($laggs.Count -gt 0) {
        $sb = New-Object System.Text.StringBuilder
        foreach ($l in $laggs) {
            [void]$sb.Append('<tr>')
            [void]$sb.Append('<td>' + (DashMono (XText $l 'laggif')) + '</td>')
            [void]$sb.Append('<td>' + (Dash (XText $l 'proto')) + '</td>')
            [void]$sb.Append('<td>' + (DashMono (XText $l 'members')) + '</td>')
            [void]$sb.Append('<td>' + (Dash (XText $l 'descr')) + '</td>')
            [void]$sb.Append('</tr>')
        }
        [void]$out.Append('<h3>Link Aggregations (LAGG)</h3>')
        [void]$out.Append((Tbl @('LAGG Interface','Protocol','Member Interfaces','Description') $sb.ToString()))
    }

    $bridges = XNodes $root 'bridges/bridged'
    if ($bridges.Count -gt 0) {
        $sb = New-Object System.Text.StringBuilder
        foreach ($b in $bridges) {
            [void]$sb.Append('<tr>')
            [void]$sb.Append('<td>' + (DashMono (XText $b 'bridgeif')) + '</td>')
            [void]$sb.Append('<td>' + (DashMono (XText $b 'members')) + '</td>')
            [void]$sb.Append('<td>' + (Dash (XText $b 'descr')) + '</td>')
            [void]$sb.Append('</tr>')
        }
        [void]$out.Append('<h3>Bridges</h3>')
        [void]$out.Append((Tbl @('Bridge Interface','Member Interfaces','Description') $sb.ToString()))
    }

    return $out.ToString()
}

function Build-Vlans {
    param($root)
    $vl = $root.SelectSingleNode('vlans')
    if ($null -eq $vl) { return '' }
    $nodes = XNodes $vl 'vlan'
    if ($nodes.Count -eq 0) { return '' }
    $sb = New-Object System.Text.StringBuilder
    foreach ($v in $nodes) {
        $vif = XText $v 'vlanif'
        $rowId = if ($vif) { ' id="vlan-' + (Format-Slug $vif) + '"' } else { '' }
        [void]$sb.Append('<tr' + $rowId + '>')
        [void]$sb.Append('<td>' + (DashMono (XText $v 'if')) + '</td>')
        [void]$sb.Append('<td>' + (DashMono (XText $v 'tag')) + '</td>')
        [void]$sb.Append('<td>' + (DashMono (XText $v 'pcp')) + '</td>')
        [void]$sb.Append('<td>' + (DashMono $vif) + '</td>')
        [void]$sb.Append('<td>' + (Dash (XText $v 'descr')) + '</td>')
        [void]$sb.Append('</tr>')
    }
    return (Tbl @('Parent interface','VLAN tag','Priority (PCP)','VLAN interface','Description') $sb.ToString())
}

function Build-VirtualIps {
    param($root)
    $vips = XNodes $root 'virtualip/vip'
    if ($vips.Count -eq 0) { return '' }
    $sb = New-Object System.Text.StringBuilder
    foreach ($v in $vips) {
        $subnet = XText $v 'subnet'
        $bits   = XText $v 'subnet_bits'
        $addr   = if ($subnet -and $bits) { $subnet + '/' + $bits } else { $subnet }
        $mode   = XText $v 'mode'
        $vhid   = XText $v 'vhid'
        $adv    = XText $v 'advskew'
        $carpInfo = ''
        if ($vhid) { $carpInfo = 'VHID ' + $vhid; if ($adv -ne '') { $carpInfo += ', skew ' + $adv } }
        [void]$sb.Append('<tr>')
        [void]$sb.Append('<td>' + (Dash $mode.ToUpperInvariant()) + '</td>')
        [void]$sb.Append('<td>' + (DashMono (XText $v 'interface')) + '</td>')
        [void]$sb.Append('<td>' + (DashMono $addr) + '</td>')
        [void]$sb.Append('<td>' + (DashMono $carpInfo) + '</td>')
        [void]$sb.Append('<td>' + (Dash (XText $v 'descr')) + '</td>')
        [void]$sb.Append('</tr>')
    }
    return (Tbl @('Type','Interface','Address / Subnet','CARP (VHID / Skew)','Description') $sb.ToString())
}

function Build-Gateways {
    param($root)
    $gws = $root.SelectSingleNode('gateways')
    if ($null -eq $gws) { return '' }
    $def4 = XText $gws 'defaultgw4'
    $def6 = XText $gws 'defaultgw6'
    $items  = XNodes $gws 'gateway_item'
    $groups = XNodes $gws 'gateway_group'
    if ($items.Count -eq 0 -and $groups.Count -eq 0 -and -not $def4 -and -not $def6) { return '' }

    $out = New-Object System.Text.StringBuilder
    if ($def4 -or $def6) {
        [void]$out.Append('<p class="note">Default IPv4 gateway: <strong>' + (Dash $def4) + '</strong> &nbsp;|&nbsp; Default IPv6 gateway: <strong>' + (Dash $def6) + '</strong></p>')
    }
    if ($items.Count -gt 0) {
        $sb = New-Object System.Text.StringBuilder
        foreach ($g in $items) {
            $name = XText $g 'name'
            $disabled = XHas $g 'disabled'
            $monDis   = XHas $g 'monitor_disable'
            $isDef    = ($name -and (($name -eq $def4) -or ($name -eq $def6)))
            $rowId    = if ($name) { ' id="gw-' + (Format-Slug $name) + '"' } else { '' }
            $cls      = if ($disabled) { ' class="row-disabled"' } else { '' }
            $monDisp  = if ($monDis) { '<span class="badge badge-muted">Disabled</span>' } else { DashMono (XText $g 'monitor') }
            [void]$sb.Append('<tr' + $rowId + $cls + '>')
            [void]$sb.Append('<td>' + (DashMono $name) + '</td>')
            [void]$sb.Append('<td>' + (YesNo (-not $disabled)) + '</td>')
            [void]$sb.Append('<td>' + (DashMono (XText $g 'interface')) + '</td>')
            [void]$sb.Append('<td>' + (DashMono (XText $g 'gateway')) + '</td>')
            [void]$sb.Append('<td>' + $monDisp + '</td>')
            [void]$sb.Append('<td>' + (Dash (XText $g 'ipprotocol')) + '</td>')
            [void]$sb.Append('<td>' + $(if ($isDef) { '<span class="badge badge-info">DEFAULT</span>' } else { '<span class="muted">&mdash;</span>' }) + '</td>')
            [void]$sb.Append('<td>' + (Dash (XText $g 'descr')) + '</td>')
            [void]$sb.Append('</tr>')
        }
        [void]$out.Append((Tbl @('Name','Enabled','Interface','Gateway IP','Monitor IP','Protocol','Default','Description') $sb.ToString()))
    }
    if ($groups.Count -gt 0) {
        $sb = New-Object System.Text.StringBuilder
        foreach ($gg in $groups) {
            $gn = XText $gg 'name'
            $rowId = if ($gn) { ' id="gwg-' + (Format-Slug $gn) + '"' } else { '' }
            $members = New-Object 'System.Collections.Generic.List[string]'
            foreach ($m in (XNodes $gg 'item')) {
                $parts = $m.InnerText.Trim() -split '\|'
                if ($parts.Count -ge 2) { [void]$members.Add(($parts[0] + ' (Tier ' + $parts[1] + ')')) }
                elseif ($m.InnerText.Trim()) { [void]$members.Add($m.InnerText.Trim()) }
            }
            [void]$sb.Append('<tr' + $rowId + '>')
            [void]$sb.Append('<td>' + (DashMono $gn) + '</td>')
            [void]$sb.Append('<td>' + $(if ($members.Count) { ($members | ForEach-Object { '<code class="mono">' + (E $_) + '</code>' }) -join '<br>' } else { '<span class="muted">&mdash;</span>' }) + '</td>')
            [void]$sb.Append('<td>' + (Dash (XText $gg 'trigger')) + '</td>')
            [void]$sb.Append('<td>' + (Dash (XText $gg 'descr')) + '</td>')
            [void]$sb.Append('</tr>')
        }
        [void]$out.Append('<h3>Gateway Groups</h3>')
        [void]$out.Append((Tbl @('Group Name','Members &amp; Tiers','Trigger Level','Description') $sb.ToString()))
    }
    return $out.ToString()
}

function Build-Routes {
    param($root)
    $sr = $root.SelectSingleNode('staticroutes')
    if ($null -eq $sr) { return '' }
    $routes = XNodes $sr 'route'
    if ($routes.Count -eq 0) { return '' }
    $sb = New-Object System.Text.StringBuilder
    foreach ($r in $routes) {
        $disabled = XHas $r 'disabled'
        $cls = if ($disabled) { ' class="row-disabled"' } else { '' }
        [void]$sb.Append('<tr' + $cls + '>')
        [void]$sb.Append('<td>' + (DashMono (XText $r 'network')) + '</td>')
        [void]$sb.Append('<td>' + (Format-GatewayRef (XText $r 'gateway')) + '</td>')
        [void]$sb.Append('<td>' + (YesNo (-not $disabled)) + '</td>')
        [void]$sb.Append('<td>' + (Dash (XText $r 'descr')) + '</td>')
        [void]$sb.Append('</tr>')
    }
    return (Tbl @('Destination network','Gateway','Enabled','Description') $sb.ToString())
}

function Test-Broad {
    # True when an endpoint address is effectively "everything" (any / negated / default route).
    param([string]$addr)
    if ([string]::IsNullOrWhiteSpace($addr)) { return $true }
    $a = $addr.Trim()
    if ($a -eq 'any') { return $true }
    if ($a -like '! *') { return $true }
    if ($a -eq '0.0.0.0/0' -or $a -eq '::/0') { return $true }
    return $false
}

function Get-ProtoClass {
    # Classify a rule protocol into a risk tier.
    param([string]$proto)
    $p = (($proto -replace '/.*$', '')).ToLowerInvariant().Trim()
    if ($p -in @('icmp', 'icmp6', 'ipv6-icmp', 'igmp')) { return 'icmp' }
    if ($p -in @('esp', 'ah', 'gre', 'pim', 'ospf', 'carp', 'pfsync', 'l2tp')) { return 'infra' }
    if ($p -in @('tcp', 'udp', 'tcp/udp')) { return 'tcpudp' }
    if ($p -in @('', 'any')) { return 'any' }
    return 'other'
}

function Get-RuleExposure {
    # Context-aware risk for a single PASS rule, scaled by interface trust + protocol + management exposure.
    param(
        [string]$trust,
        [string]$type,
        [string]$dir,
        [string]$protoClass,
        [bool]$srcBroad,
        [bool]$dstBroad,
        [bool]$dstPortSet,
        [string]$protoDisp,
        [string]$dstSvc,
        [bool]$isFirewallMgmt = $false,
        [bool]$floatingTouchesWan = $false
    )
    if ($type -ne 'pass') { return $null }   # block/reject/match rules are not exposures
    if ($dir -eq 'out')   { return $null }   # outbound allows are not inbound exposure

    $effectiveTrust = $trust
    if ($trust -eq 'floating' -and $floatingTouchesWan) { $effectiveTrust = 'wan' }

    switch ($effectiveTrust) {
        'wan' {
            if ($isFirewallMgmt -and $protoClass -in @('tcpudp', 'any')) {
                return @{ Sev = 'high'; Label = 'WAN MGMT EXPOSED'; Detail = "inbound WAN rule permits access to firewall management ($dstSvc)."; Row = 'row-high' }
            }
            if ($srcBroad) {
                if ($protoClass -eq 'icmp')  { return @{ Sev = 'info'; Label = 'WAN ICMP'; Detail = 'inbound ICMP from any source (diagnostic, low risk).'; Row = '' } }
                if ($protoClass -eq 'infra') { return @{ Sev = 'info'; Label = 'WAN VPN'; Detail = "inbound $protoDisp from any source (typical for VPN/tunnel endpoints)."; Row = '' } }
                if ($dstBroad -and -not $dstPortSet) {
                    $pd = if ($protoClass -eq 'any') { 'all protocols / all ports' } else { $protoDisp }
                    return @{ Sev = 'high'; Label = 'HIGH RISK'; Detail = "inbound $pd from ANY source to ANY destination (no port restriction) on a WAN (Internet-facing) interface."; Row = 'row-high' }
                }
                return @{ Sev = 'warn'; Label = 'WAN EXPOSED'; Detail = "inbound $protoDisp service published to the Internet (any source -> $dstSvc)."; Row = 'row-warn' }
            }
            else {
                if ($protoClass -in @('tcpudp', 'any', 'other')) {
                    return @{ Sev = 'info'; Label = 'WAN (restricted)'; Detail = 'inbound WAN allow limited to specific source(s) - lower risk.'; Row = '' }
                }
                return $null
            }
        }
        'vpn' {
            if ($srcBroad -and $dstBroad -and ($protoClass -in @('tcpudp', 'any', 'other'))) {
                return @{ Sev = 'info'; Label = 'VPN ANY'; Detail = 'VPN interface permits any-to-any (common for full-tunnel remote access).'; Row = '' }
            }
            return $null
        }
        'floating' {
            if ($srcBroad -and $dstBroad -and ($protoClass -in @('tcpudp', 'any'))) {
                return @{ Sev = 'warn'; Label = 'FLOATING ANY'; Detail = 'floating rule permits any-to-any; verify the intended scope.'; Row = 'row-warn' }
            }
            return $null
        }
        default { return $null }   # internal / trusted interfaces: any-to-any is expected
    }
    return $null
}

function Build-Firewall {
    param($root)
    $rules = XNodes $root 'filter/rule'
    if ($rules.Count -eq 0) { return '' }

    # Detect management ports for WAN management exposure check
    $sysNode  = $root.SelectSingleNode('system')
    $guiNode  = if ($null -ne $sysNode) { $sysNode.SelectSingleNode('webgui') } else { $null }
    $guiProto = XText $guiNode 'protocol'; if (-not $guiProto) { $guiProto = 'https' }
    $guiPort  = XText $guiNode 'port'; if (-not $guiPort) { $guiPort = if ($guiProto -eq 'http') { '80' } else { '443' } }
    $sshNode  = if ($null -ne $sysNode) { $sysNode.SelectSingleNode('ssh') } else { $null }
    $sshPort  = XText $sshNode 'port'; if (-not $sshPort) { $sshPort = '22' }
    $mgmtPorts = @($guiPort, $sshPort)

    # Floating rules first (matches pfSense evaluation order)
    $groups = [ordered]@{}
    $floatingList = New-Object 'System.Collections.Generic.List[object]'
    foreach ($r in $rules) {
        if (XHas $r 'floating') {
            [void]$floatingList.Add($r)
            continue
        }
        $ifKey = XText $r 'interface'
        if (-not $ifKey) {
            [void]$floatingList.Add($r)
            continue
        }
        if (-not $groups.Contains($ifKey)) { $groups[$ifKey] = New-Object 'System.Collections.Generic.List[object]' }
        [void]$groups[$ifKey].Add($r)
    }
    if ($floatingList.Count -gt 0) {
        $orderedGroups = [ordered]@{ '(floating)' = $floatingList }
        foreach ($k in $groups.Keys) { $orderedGroups[$k] = $groups[$k] }
        $groups = $orderedGroups
    }

    $out = New-Object System.Text.StringBuilder
    [void]$out.Append('<div class="section-controls"><p class="note">Risk is assessed from <strong>interface trust</strong> (WAN = Internet-facing / untrusted; LAN / OPT = internal / trusted; VPN = remote-access; Floating = evaluated before interface tabs) combined with <strong>protocol</strong> and management-plane exposure.</p>')
    [void]$out.Append('<label class="toggle-check"><input type="checkbox" class="hide-disabled-toggle" data-target="firewall" /> Hide disabled rules</label></div>')

    foreach ($key in $groups.Keys) {
        $trust = if ($script:TrustMap.ContainsKey($key)) { $script:TrustMap[$key] } else { 'other' }
        $trustBadge = switch ($trust) {
            'wan'      { ' <span class="badge badge-high">UNTRUSTED / WAN</span>' }
            'vpn'      { ' <span class="badge badge-info">VPN</span>' }
            'floating' { ' <span class="badge badge-muted">FLOATING</span>' }
            'internal' { ' <span class="badge badge-ok">TRUSTED / INTERNAL</span>' }
            default    { '' }
        }
        $label = '<code class="mono">' + (E $key) + '</code>'
        if ($script:IfMap.ContainsKey($key) -and $script:IfMap[$key]) {
            $label += ' <span class="muted">&mdash; ' + (E $script:IfMap[$key]) + '</span>'
        }
        $sb = New-Object System.Text.StringBuilder
        $seq = 0
        $isFloatingGroup = ($key -eq '(floating)')
        foreach ($r in $groups[$key]) {
            $seq++
            $rowId    = 'row-fw-' + (Format-Slug $key) + '-' + $seq
            $disabled = XHas $r 'disabled'
            $type     = XText $r 'type'
            $ipproto  = XText $r 'ipprotocol'
            $ipDisp   = switch ($ipproto) {
                'inet'   { 'IPv4' }
                'inet6'  { 'IPv6' }
                'inet46' { 'IPv4+6' }
                default  { if ($ipproto) { $ipproto } else { 'IPv4' } }
            }
            $rawProto   = XText $r 'protocol'
            $protoClass = Get-ProtoClass $rawProto
            $proto      = if ($rawProto) { $rawProto } else { 'any' }
            if ($rawProto -in @('icmp', 'icmp6', 'ipv6-icmp')) {
                $it = XText $r 'icmptype'
                if ($it) { $proto = $rawProto + '/' + $it }
            }
            $src   = Format-Endpoint $r.SelectSingleNode('source')
            $dst   = Format-Endpoint $r.SelectSingleNode('destination')
            $dir   = XText $r 'direction'; if (-not $dir) { $dir = 'in' }
            $quick = XHas $r 'quick'
            $log   = XHas $r 'log'
            $gw    = XText $r 'gateway'
            $sched = XText $r 'sched'
            $descr = XText $r 'descr'
            $floatIfs = if ($isFloatingGroup) { XText $r 'interface' } else { '' }
            $floatingTouchesWan = $false
            if ($isFloatingGroup) {
                if (-not $floatIfs) {
                    $floatingTouchesWan = $true
                }
                else {
                    foreach ($fi in ($floatIfs -split ',')) {
                        $fk = $fi.Trim()
                        if ($fk -and $script:TrustMap.ContainsKey($fk) -and $script:TrustMap[$fk] -eq 'wan') {
                            $floatingTouchesWan = $true; break
                        }
                    }
                }
            }

            $srcBroad = Test-Broad $src.Addr
            $dstBroad = Test-Broad $dst.Addr
            $dstIsSelf = ($dst.RawAddr -eq '(self)' -or $dst.RawAddr -match '^wanip$' -or ($key -ne '(floating)' -and $dst.RawAddr -eq ($key + 'ip')))
            $isMgmt = $dstIsSelf -and (($dst.Port -in $mgmtPorts) -or (-not $dst.Port -and $protoClass -in @('tcpudp', 'any')))

            $where  = "Firewall / $key rule #$seq"
            $badges = New-Object System.Text.StringBuilder
            $rowCls = ''
            if ($disabled) {
                $rowCls = 'row-disabled'
                [void]$badges.Append('<span class="badge badge-muted">DISABLED</span> ')
            }
            if ($isFloatingGroup) {
                if ($floatIfs) { [void]$badges.Append('<span class="badge badge-muted">IF: ' + (E $floatIfs) + '</span> ') }
                if ($quick)    { [void]$badges.Append('<span class="badge badge-info">QUICK</span> ') }
            }
            if ($sched) { [void]$badges.Append('<span class="badge badge-muted">SCHED: ' + (E $sched) + '</span> ') }

            if (-not $disabled) {
                $dstSvc = $dst.Addr; if ($dst.Port) { $dstSvc += ':' + $dst.Port }
                $exp = Get-RuleExposure -trust $trust -type $type -dir $dir -protoClass $protoClass -srcBroad $srcBroad -dstBroad $dstBroad -dstPortSet ([bool]$dst.Port) -protoDisp $proto -dstSvc $dstSvc -isFirewallMgmt $isMgmt -floatingTouchesWan $floatingTouchesWan
                if ($null -ne $exp) {
                    $bcls = switch ($exp.Sev) { 'high' { 'badge-high' } 'warn' { 'badge-warn' } default { 'badge-info' } }
                    [void]$badges.Append('<span class="badge ' + $bcls + '">' + (E $exp.Label) + '</span> ')
                    if ($exp.Row -and $rowCls -eq '') { $rowCls = $exp.Row }
                    Add-Finding $exp.Sev $exp.Label $where ($(if ($descr) { $descr } else { '(no description)' }) + ' - ' + $exp.Detail) $rowId
                }
                if (-not $log) {
                    [void]$badges.Append('<span class="badge badge-muted">NO LOG</span> ')
                    # De-noise Findings: report individual NO LOG findings for WAN/floating/block/reject rules;
                    # aggregate internal pass rules into one clean summary finding.
                    if ($trust -in @('wan', 'floating') -or $type -in @('block', 'reject')) {
                        Add-Finding 'info' 'NO LOG' $where ($(if ($descr) { $descr } else { '(no description)' }) + ' - logging is disabled on this rule.') $rowId
                    }
                    else {
                        $script:InternalNoLogCount++
                    }
                }
            }

            $actBadge = switch ($type) {
                'pass'   { '<span class="badge badge-ok">PASS</span>' }
                'block'  { '<span class="badge badge-muted">BLOCK</span>' }
                'reject' { '<span class="badge badge-warn">REJECT</span>' }
                'match'  { '<span class="badge badge-info">MATCH</span>' }
                default  { (E $type) }
            }

            $trAttr = ' id="' + $rowId + '"'
            if ($rowCls) { $trAttr += ' class="' + $rowCls + '"' }
            if ($disabled) { $trAttr += ' data-disabled="1"' }
            [void]$sb.Append('<tr' + $trAttr + '>')
            [void]$sb.Append('<td>' + $seq + '</td>')
            [void]$sb.Append('<td>' + (YesNo (-not $disabled)) + '</td>')
            [void]$sb.Append('<td>' + $actBadge + '</td>')
            [void]$sb.Append('<td>' + (E $ipDisp) + '</td>')
            [void]$sb.Append('<td><code class="mono">' + (E $proto) + '</code></td>')
            [void]$sb.Append('<td>' + (Format-RefCell $src.Addr $src.Negated) + '</td>')
            [void]$sb.Append('<td>' + (Format-RefCell $src.Port) + '</td>')
            [void]$sb.Append('<td>' + (Format-RefCell $dst.Addr $dst.Negated) + '</td>')
            [void]$sb.Append('<td>' + (Format-RefCell $dst.Port) + '</td>')
            [void]$sb.Append('<td>' + (Format-GatewayRef $gw) + '</td>')
            [void]$sb.Append('<td>' + (E $dir) + '</td>')
            [void]$sb.Append('<td>' + (YesNo $log) + '</td>')
            $flagHtml = if ($badges.Length -gt 0) { '<div class="flagcell">' + $badges.ToString().Trim() + '</div>' } else { '' }
            [void]$sb.Append('<td>' + (Dash $descr) + $flagHtml + '</td>')
            [void]$sb.Append('</tr>')
        }
        $tbl = Tbl @('#','Enabled','Action','IP','Protocol','Source','Src Port','Destination','Dst Port','Gateway','Dir','Log','Description / Flags') $sb.ToString() 'filterable-table'
        $cnt = $groups[$key].Count
        [void]$out.Append('<h3 class="iface-head">' + $label + $trustBadge + ' <span class="count">(' + $cnt + ' rule' + $(if ($cnt -ne 1) { 's' } else { '' }) + ')</span></h3>' + $tbl)
    }

    if ($script:InternalNoLogCount -gt 0) {
        Add-Finding 'info' 'NO LOG (INTERNAL)' 'Firewall / Internal interfaces' ("$($script:InternalNoLogCount) enabled internal/VPN pass rule(s) have logging disabled (see NO LOG row badges).") 'firewall'
    }
    return $out.ToString()
}

function Build-Nat {
    param($root)
    $nat = $root.SelectSingleNode('nat')
    if ($null -eq $nat) { return '' }
    $out = New-Object System.Text.StringBuilder
    [void]$out.Append('<div class="section-controls"><span></span><label class="toggle-check"><input type="checkbox" class="hide-disabled-toggle" data-target="nat" /> Hide disabled rules</label></div>')

    # Outbound NAT
    $mode = XText $nat 'outbound/mode'
    if (-not $mode) { $mode = 'automatic' }
    [void]$out.Append('<h3>Outbound NAT</h3><p>Mode: <span class="badge badge-info">' + (E $mode.ToUpperInvariant()) + '</span></p>')
    $obRules = XNodes $nat 'outbound/rule'
    if ($obRules.Count -gt 0) {
        $sb = New-Object System.Text.StringBuilder
        foreach ($r in $obRules) {
            $disabled = XHas $r 'disabled'
            $noNat    = XHas $r 'nonat'
            $statPort = XHas $r 'staticnatport'
            $trAttr   = if ($disabled) { ' class="row-disabled" data-disabled="1"' } else { '' }
            $src = Format-Endpoint $r.SelectSingleNode('source')
            $srcPort = XText $r 'sourceport'
            $dst = Format-Endpoint $r.SelectSingleNode('destination')
            $dstPort = if ($dst.Port) { $dst.Port } else { XText $r 'dstport' }
            $proto   = XText $r 'protocol'; if (-not $proto) { $proto = 'any' }

            $tgtCell = ''
            if ($noNat) {
                $tgtCell = '<span class="badge badge-warn">DO NOT NAT</span>'
            }
            else {
                $tgt = XText $r 'targetip'
                if ($tgt) {
                    $tsub = XText $r 'targetip_subnet'
                    if ($tsub) { $tgt += '/' + $tsub }
                }
                else {
                    $tgt = XText $r 'target'
                }
                if (-not $tgt -or $tgt -eq 'other-subnet') { $tgt = 'Interface address' }
                $tgtCell = DashMono $tgt
                if ($statPort) { $tgtCell += ' <span class="badge badge-info">STATIC PORT</span>' }
            }
            $srcCell = Format-RefCell $src.Addr $src.Negated
            if ($srcPort) { $srcCell += ':<code class="mono">' + (E $srcPort) + '</code>' }
            $dstCell = Format-RefCell $dst.Addr $dst.Negated
            if ($dstPort) { $dstCell += ':<code class="mono">' + (E $dstPort) + '</code>' }

            [void]$sb.Append('<tr' + $trAttr + '>')
            [void]$sb.Append('<td>' + (DashMono (XText $r 'interface')) + '</td>')
            [void]$sb.Append('<td><code class="mono">' + (E $proto) + '</code></td>')
            [void]$sb.Append('<td>' + $srcCell + '</td>')
            [void]$sb.Append('<td>' + $dstCell + '</td>')
            [void]$sb.Append('<td>' + $tgtCell + '</td>')
            [void]$sb.Append('<td>' + (YesNo (-not $disabled)) + '</td>')
            [void]$sb.Append('<td>' + (Dash (XText $r 'descr')) + '</td>')
            [void]$sb.Append('</tr>')
        }
        [void]$out.Append((Tbl @('Interface','Proto','Source','Destination','Translation target','Enabled','Description') $sb.ToString() 'filterable-table'))
    }
    elseif ($mode -match '(?i)advanced|hybrid|manual') {
        [void]$out.Append('<p class="not-configured">No manual outbound rules defined.</p>')
    }

    # Port forwards
    $pf = XNodes $nat 'rule'
    [void]$out.Append('<h3>Port Forwards</h3>')
    if ($pf.Count -gt 0) {
        $sb = New-Object System.Text.StringBuilder
        $pfSeq = 0
        foreach ($r in $pf) {
            $pfSeq++
            $rowId    = 'row-nat-pf-' + $pfSeq
            $disabled = XHas $r 'disabled'
            $noRdr    = XHas $r 'nordr'
            $assoc    = XText $r 'associated-rule-id'
            $iface    = XText $r 'interface'
            $proto    = XText $r 'protocol'
            $src      = Format-Endpoint $r.SelectSingleNode('source')
            $dst      = Format-Endpoint $r.SelectSingleNode('destination')
            $extPort  = if ($dst.Port) { $dst.Port } else { XText $r 'dstport' }
            $target   = XText $r 'target'
            $locPort  = XText $r 'local-port'
            $descr    = XText $r 'descr'

            $flags = New-Object System.Text.StringBuilder
            $rowCls = if ($disabled) { 'row-disabled' } else { '' }
            if ($noRdr) { [void]$flags.Append('<span class="badge badge-warn">NO RDR</span> ') }
            if (-not $disabled -and -not $noRdr -and $assoc -ieq 'pass') {
                $isWan = $script:TrustMap.ContainsKey($iface) -and $script:TrustMap[$iface] -eq 'wan'
                $sev = if ($isWan -and (Test-Broad $src.Addr)) { 'warn' } else { 'info' }
                $bcls = if ($sev -eq 'warn') { 'badge-warn' } else { 'badge-info' }
                [void]$flags.Append('<span class="badge ' + $bcls + '">INLINE PASS</span> ')
                if ($sev -eq 'warn' -and -not $rowCls) { $rowCls = 'row-warn' }
                Add-Finding $sev 'NAT INLINE PASS' "NAT / Port Forward #$pfSeq" ("$(if ($descr) { $descr } else { '(no description)' }) - uses implicit 'pass' (bypasses explicit firewall rules) forwarding $($proto):$($extPort) -> $($target):$($locPort).") $rowId
            }

            $trAttr = ' id="' + $rowId + '"'
            if ($rowCls) { $trAttr += ' class="' + $rowCls + '"' }
            if ($disabled) { $trAttr += ' data-disabled="1"' }
            [void]$sb.Append('<tr' + $trAttr + '>')
            [void]$sb.Append('<td>' + (DashMono $iface) + '</td>')
            [void]$sb.Append('<td>' + (DashMono $proto) + '</td>')
            [void]$sb.Append('<td>' + (Format-RefCell $src.Addr $src.Negated) + '</td>')
            [void]$sb.Append('<td>' + (Format-RefCell $dst.Addr $dst.Negated) + '</td>')
            [void]$sb.Append('<td>' + (Format-RefCell $extPort) + '</td>')
            [void]$sb.Append('<td>' + (Format-RefCell $target) + '</td>')
            [void]$sb.Append('<td>' + (Format-RefCell $locPort) + '</td>')
            [void]$sb.Append('<td>' + (YesNo (-not $disabled)) + '</td>')
            $flagHtml = if ($flags.Length -gt 0) { '<div class="flagcell">' + $flags.ToString().Trim() + '</div>' } else { '' }
            [void]$sb.Append('<td>' + (Dash $descr) + $flagHtml + '</td>')
            [void]$sb.Append('</tr>')
        }
        [void]$out.Append((Tbl @('Interface','Protocol','Source','External addr','External port','Redirect target','Target port','Enabled','Description / Flags') $sb.ToString() 'filterable-table'))
    }
    else {
        [void]$out.Append('<p class="not-configured">No port forwards defined.</p>')
    }

    # 1:1 NAT
    $oto = XNodes $nat 'onetoone'
    if ($oto.Count -gt 0) {
        [void]$out.Append('<h3>1:1 NAT</h3>')
        $sb = New-Object System.Text.StringBuilder
        foreach ($r in $oto) {
            $disabled = XHas $r 'disabled'
            $noBinat  = XHas $r 'nobinat'
            $trAttr   = if ($disabled) { ' class="row-disabled" data-disabled="1"' } else { '' }
            $src = Format-Endpoint $r.SelectSingleNode('source')
            $dst = Format-Endpoint $r.SelectSingleNode('destination')
            $extCell = DashMono (XText $r 'external')
            if ($noBinat) { $extCell += ' <span class="badge badge-warn">DO NOT BINAT</span>' }
            [void]$sb.Append('<tr' + $trAttr + '>')
            [void]$sb.Append('<td>' + (DashMono (XText $r 'interface')) + '</td>')
            [void]$sb.Append('<td>' + $extCell + '</td>')
            [void]$sb.Append('<td>' + (Format-RefCell $src.Addr $src.Negated) + '</td>')
            [void]$sb.Append('<td>' + (Format-RefCell $dst.Addr $dst.Negated) + '</td>')
            [void]$sb.Append('<td>' + (YesNo (-not $disabled)) + '</td>')
            [void]$sb.Append('<td>' + (Dash (XText $r 'descr')) + '</td>')
            [void]$sb.Append('</tr>')
        }
        [void]$out.Append((Tbl @('Interface','External IP','Internal (source)','Destination','Enabled','Description') $sb.ToString() 'filterable-table'))
    }

    return $out.ToString()
}

function Build-Ipsec {
    param($root)
    $ipsec = $root.SelectSingleNode('ipsec')
    if ($null -eq $ipsec) { return '' }
    $p1 = XNodes $ipsec 'phase1'
    $p2 = XNodes $ipsec 'phase2'
    if ($p1.Count -eq 0 -and $p2.Count -eq 0) { return '' }

    $out = New-Object System.Text.StringBuilder

    # Phase 1
    if ($p1.Count -gt 0) {
        [void]$out.Append('<h3>Phase 1 (IKE)</h3>')
        $sb = New-Object System.Text.StringBuilder
        $p1Seq = 0
        foreach ($p in $p1) {
            $p1Seq++
            $ikeid    = XText $p 'ikeid'
            $rowId    = 'row-ipsec-p1-' + $(if ($ikeid) { Format-Slug $ikeid } else { $p1Seq })
            $disabled = XHas $p 'disabled'
            $iketype  = XText $p 'iketype'
            $mode     = XText $p 'mode'

            # Inspect ALL Phase 1 encryption proposals (and legacy pre-2.4 flat nodes)
            $items = XNodes $p 'encryption/item'
            $encDisplays  = New-Object 'System.Collections.Generic.List[string]'
            $hashDisplays = New-Object 'System.Collections.Generic.List[string]'
            $dhDisplays   = New-Object 'System.Collections.Generic.List[string]'
            $allCryptoVals = New-Object 'System.Collections.Generic.List[string]'

            if ($items.Count -gt 0) {
                foreach ($item in $items) {
                    $ea = XText $item 'encryption-algorithm/name'
                    $kl = XText $item 'encryption-algorithm/keylen'
                    $ha = XText $item 'hash-algorithm'
                    $dh = XText $item 'dhgroup'
                    $ed = $ea; if ($kl) { $ed += '-' + $kl }
                    if ($ed) { [void]$encDisplays.Add($ed); [void]$allCryptoVals.Add($ea) }
                    if ($ha) { [void]$hashDisplays.Add($ha); [void]$allCryptoVals.Add($ha) }
                    if ($dh) { [void]$dhDisplays.Add($dh) }
                }
            }
            else {
                $ea = XText $p 'encryption-algorithm/name'
                $kl = XText $p 'encryption-algorithm/keylen'
                $ha = XText $p 'hash-algorithm'
                $dh = XText $p 'dhgroup'
                $ed = $ea; if ($kl) { $ed += '-' + $kl }
                if ($ed) { [void]$encDisplays.Add($ed); [void]$allCryptoVals.Add($ea) }
                if ($ha) { [void]$hashDisplays.Add($ha); [void]$allCryptoVals.Add($ha) }
                if ($dh) { [void]$dhDisplays.Add($dh) }
            }

            $where = "IPsec P1 (IKE id $ikeid)"
            $flags = New-Object System.Text.StringBuilder
            $rowCls = if ($disabled) { 'row-disabled' } else { '' }

            if (-not $disabled) {
                $weak = Get-WeakCryptoHits $allCryptoVals.ToArray()
                if ($weak.High.Count -gt 0) {
                    [void]$flags.Append('<span class="badge badge-high">WEAK CRYPTO</span> ')
                    $rowCls = 'row-high'
                    Add-Finding 'high' 'WEAK CRYPTO' $where ('Uses ' + ($weak.High -join ', ')) $rowId
                }
                if ($weak.Warn.Count -gt 0) {
                    [void]$flags.Append('<span class="badge badge-warn">LEGACY CRYPTO</span> ')
                    if (-not $rowCls) { $rowCls = 'row-warn' }
                    Add-Finding 'warn' 'LEGACY CRYPTO' $where ('Uses ' + ($weak.Warn -join ', ')) $rowId
                }
                foreach ($dhg in ($dhDisplays | Select-Object -Unique)) {
                    $dhf = Get-WeakDhFinding $dhg $false
                    if ($null -ne $dhf) {
                        $bcls = if ($dhf.Sev -eq 'high') { 'badge-high' } else { 'badge-warn' }
                        [void]$flags.Append('<span class="badge ' + $bcls + '">' + (E $dhf.Label) + '</span> ')
                        if ($dhf.Sev -eq 'high') { $rowCls = 'row-high' } elseif (-not $rowCls) { $rowCls = 'row-warn' }
                        Add-Finding $dhf.Sev $dhf.Label $where $dhf.Detail $rowId
                    }
                }
                if ($iketype -match '(?i)^(ikev1|auto)$') {
                    [void]$flags.Append('<span class="badge badge-warn">IKEV1</span> ')
                    if (-not $rowCls) { $rowCls = 'row-warn' }
                    Add-Finding 'warn' 'LEGACY IKEV1' $where ("Uses $iketype instead of IKEv2.") $rowId
                }
                if ($mode -ieq 'aggressive') {
                    [void]$flags.Append('<span class="badge badge-high">AGGRESSIVE MODE</span> ')
                    $rowCls = 'row-high'
                    Add-Finding 'high' 'AGGRESSIVE MODE' $where 'IKEv1 Aggressive Mode exposes PSK hashes to offline cracking.' $rowId
                }
            }

            $authMethod = XText $p 'authentication_method'
            $certRef    = XText $p 'certref'
            $authCell   = Dash $authMethod
            if ($certRef) { $authCell += '<br><span class="muted">Cert:</span> ' + (Format-CertRef $certRef) }

            $trAttr = ' id="' + $rowId + '"'
            if ($rowCls) { $trAttr += ' class="' + $rowCls + '"' }
            [void]$sb.Append('<tr' + $trAttr + '>')
            [void]$sb.Append('<td>' + (DashMono $ikeid) + '</td>')
            $flagHtml = if ($flags.Length -gt 0) { '<div class="flagcell">' + $flags.ToString().Trim() + '</div>' } else { '' }
            [void]$sb.Append('<td>' + (Dash (XText $p 'descr')) + $flagHtml + '</td>')
            [void]$sb.Append('<td>' + (YesNo (-not $disabled)) + '</td>')
            [void]$sb.Append('<td>' + (Dash $iketype) + '</td>')
            [void]$sb.Append('<td>' + (DashMono (XText $p 'interface')) + '</td>')
            [void]$sb.Append('<td>' + (DashMono (XText $p 'remote-gateway')) + '</td>')
            [void]$sb.Append('<td>' + (DashMono (($encDisplays | Select-Object -Unique) -join ', ')) + '</td>')
            [void]$sb.Append('<td>' + (DashMono (($hashDisplays | Select-Object -Unique) -join ', ')) + '</td>')
            [void]$sb.Append('<td>' + (DashMono (($dhDisplays | Select-Object -Unique) -join ', ')) + '</td>')
            [void]$sb.Append('<td>' + (DashMono (XText $p 'lifetime')) + '</td>')
            [void]$sb.Append('<td>' + $authCell + '</td>')
            [void]$sb.Append('<td>' + (Secret (XText $p 'pre-shared-key')) + '</td>')
            [void]$sb.Append('</tr>')
        }
        [void]$out.Append((Tbl @('IKE id','Description','Enabled','IKE','Interface','Peer / Remote GW','Encryption','Hash','DH group','Lifetime','Auth','Pre-shared key') $sb.ToString()))
    }

    # Phase 2
    if ($p2.Count -gt 0) {
        [void]$out.Append('<h3>Phase 2 (IPsec SA)</h3>')
        $sb = New-Object System.Text.StringBuilder
        $p2Seq = 0
        foreach ($p in $p2) {
            $p2Seq++
            $ikeid    = XText $p 'ikeid'
            $rowId    = 'row-ipsec-p2-' + $p2Seq
            $disabled = XHas $p 'disabled'
            $lid = $p.SelectSingleNode('localid')
            $local = XText $lid 'type'
            if (XText $lid 'address') { $local = (XText $lid 'address'); $nb = XText $lid 'netbits'; if ($nb) { $local += '/' + $nb } }
            $rid = $p.SelectSingleNode('remoteid')
            $remote = XText $rid 'type'
            if (XText $rid 'address') { $remote = (XText $rid 'address'); $nb = XText $rid 'netbits'; if ($nb) { $remote += '/' + $nb } }

            $encList  = New-Object 'System.Collections.Generic.List[string]'
            $encNames = New-Object 'System.Collections.Generic.List[string]'
            foreach ($e in (XNodes $p 'encryption-algorithm-option')) {
                $n = XText $e 'name'; $kl = XText $e 'keylen'
                if ($n) { [void]$encNames.Add($n) }
                $d = $n; if ($kl) { $d += '-' + $kl }
                if ($d) { [void]$encList.Add($d) }
            }
            $hashList = New-Object 'System.Collections.Generic.List[string]'
            foreach ($h in (XNodes $p 'hash-algorithm-option')) {
                $hv = $h.InnerText.Trim()
                if ($hv) { [void]$hashList.Add($hv) }
            }
            $pfs = XText $p 'pfsgroup'

            $where = "IPsec P2 (IKE id $ikeid)"
            $flags = New-Object System.Text.StringBuilder
            $rowCls = if ($disabled) { 'row-disabled' } else { '' }
            if (-not $disabled) {
                $allVals = @($encNames.ToArray()) + @($hashList.ToArray())
                $weak = Get-WeakCryptoHits $allVals
                if ($weak.High.Count -gt 0) {
                    [void]$flags.Append('<span class="badge badge-high">WEAK CRYPTO</span> ')
                    $rowCls = 'row-high'
                    Add-Finding 'high' 'WEAK CRYPTO' $where ('Uses ' + ($weak.High -join ', ')) $rowId
                }
                if ($weak.Warn.Count -gt 0) {
                    [void]$flags.Append('<span class="badge badge-warn">LEGACY CRYPTO</span> ')
                    if (-not $rowCls) { $rowCls = 'row-warn' }
                    Add-Finding 'warn' 'LEGACY CRYPTO' $where ('Uses ' + ($weak.Warn -join ', ')) $rowId
                }
                $pfsf = Get-WeakDhFinding $pfs $true
                if ($null -ne $pfsf) {
                    $bcls = if ($pfsf.Sev -eq 'high') { 'badge-high' } else { 'badge-warn' }
                    [void]$flags.Append('<span class="badge ' + $bcls + '">' + (E $pfsf.Label) + '</span> ')
                    if ($pfsf.Sev -eq 'high') { $rowCls = 'row-high' } elseif (-not $rowCls) { $rowCls = 'row-warn' }
                    Add-Finding $pfsf.Sev $pfsf.Label $where $pfsf.Detail $rowId
                }
            }

            $trAttr = ' id="' + $rowId + '"'
            if ($rowCls) { $trAttr += ' class="' + $rowCls + '"' }
            [void]$sb.Append('<tr' + $trAttr + '>')
            [void]$sb.Append('<td>' + (DashMono $ikeid) + '</td>')
            $flagHtml = if ($flags.Length -gt 0) { '<div class="flagcell">' + $flags.ToString().Trim() + '</div>' } else { '' }
            [void]$sb.Append('<td>' + (Dash (XText $p 'descr')) + $flagHtml + '</td>')
            [void]$sb.Append('<td>' + (YesNo (-not $disabled)) + '</td>')
            [void]$sb.Append('<td>' + (Dash (XText $p 'mode')) + '</td>')
            [void]$sb.Append('<td>' + (DashMono (XText $p 'protocol')) + '</td>')
            [void]$sb.Append('<td>' + (DashMono $local) + '</td>')
            [void]$sb.Append('<td>' + (DashMono $remote) + '</td>')
            [void]$sb.Append('<td>' + (DashMono ($encList -join ', ')) + '</td>')
            [void]$sb.Append('<td>' + (DashMono ($hashList -join ', ')) + '</td>')
            [void]$sb.Append('<td>' + (DashMono $pfs) + '</td>')
            [void]$sb.Append('<td>' + (DashMono (XText $p 'lifetime')) + '</td>')
            [void]$sb.Append('</tr>')
        }
        [void]$out.Append((Tbl @('IKE id','Description','Enabled','Mode','Protocol','Local network','Remote network','Encryption','Hash','PFS group','Lifetime') $sb.ToString()))
    }

    return $out.ToString()
}

function Format-OpenVpnRows {
    param($list, [bool]$isServer)
    $sb = New-Object System.Text.StringBuilder
    $seq = 0
    foreach ($s in $list) {
        $seq++
        $kind     = if ($isServer) { 'server' } else { 'client' }
        $rowId    = "row-ovpn-$kind-$seq"
        $disabled = (XHas $s 'disable') -or (XHas $s 'disabled')
        $desc     = XText $s 'description'
        $mode     = XText $s 'mode'
        $devMode  = XText $s 'dev_mode'
        $proto    = XText $s 'protocol'
        $endpoint = ''
        if ($isServer) {
            $endpoint = XText $s 'local_port'
        }
        else {
            $sa = XText $s 'server_addr'
            $sp = XText $s 'server_port'
            if ($sa -and $sp) { $endpoint = $sa + ':' + $sp }
            elseif ($sa) { $endpoint = $sa }
            elseif ($sp) { $endpoint = ':' + $sp }
        }
        $tnet   = XText $s 'tunnel_network'
        $lnet   = XText $s 'local_network'
        $rnet   = XText $s 'remote_network'
        $auth   = XText $s 'authmode'
        $dc     = XText $s 'data_ciphers'
        $dcf    = XText $s 'data_ciphers_fallback'
        $legacy = XText $s 'crypto'
        $digest = XText $s 'digest'
        $comp   = XText $s 'compression'
        $tlsUse = if (XText $s 'tls') { $tm = XText $s 'tls_type'; if ($tm) { $tm } else { 'tls-auth' } } else { '' }
        $cipherDisp = $dc
        if (-not $cipherDisp -and $legacy) { $cipherDisp = $legacy }
        if ($dcf) {
            if ($cipherDisp) { $cipherDisp += ' (fallback ' + $dcf + ')' } else { $cipherDisp = $dcf }
        }
        $caref   = XText $s 'caref'
        $certref = XText $s 'certref'

        $where = "OpenVPN $kind '" + $(if ($desc) { $desc } else { '(unnamed)' }) + "'"
        $flags = New-Object System.Text.StringBuilder
        $rowCls = if ($disabled) { 'row-disabled' } else { '' }
        if ($tlsUse) { [void]$flags.Append('<span class="badge badge-info">' + (E $tlsUse.ToUpperInvariant()) + '</span> ') }

        if (-not $disabled) {
            $weak = Get-WeakCryptoHits @($dc, $dcf, $legacy, $digest)
            if ($weak.High.Count -gt 0) {
                [void]$flags.Append('<span class="badge badge-high">WEAK CRYPTO</span> ')
                $rowCls = 'row-high'
                Add-Finding 'high' 'WEAK CRYPTO' $where ('Uses ' + ($weak.High -join ', ')) $rowId
            }
            if ($weak.Warn.Count -gt 0) {
                [void]$flags.Append('<span class="badge badge-warn">LEGACY CRYPTO</span> ')
                if (-not $rowCls) { $rowCls = 'row-warn' }
                Add-Finding 'warn' 'LEGACY CRYPTO' $where ('Uses ' + ($weak.Warn -join ', ')) $rowId
            }
            if ($comp -and $comp -notmatch '(?i)^(no|none|stub)$') {
                [void]$flags.Append('<span class="badge badge-warn">COMPRESSION</span> ')
                if (-not $rowCls) { $rowCls = 'row-warn' }
                Add-Finding 'warn' 'VPN COMPRESSION' $where ("Compression '$comp' is enabled (potential VORACLE side-channel risk).") $rowId
            }
        }

        $trAttr = ' id="' + $rowId + '"'
        if ($rowCls) { $trAttr += ' class="' + $rowCls + '"' }
        $caCell = Format-CertRef $caref
        if ($certref) { $caCell += '<br><span class="muted">Cert:</span> ' + (Format-CertRef $certref) }
        $modeDisp = if ($devMode) { "$mode ($devMode)" } else { $mode }

        [void]$sb.Append('<tr' + $trAttr + '>')
        $flagHtml = if ($flags.Length -gt 0) { '<div class="flagcell">' + $flags.ToString().Trim() + '</div>' } else { '' }
        [void]$sb.Append('<td>' + (Dash $desc) + $flagHtml + '</td>')
        [void]$sb.Append('<td>' + (YesNo (-not $disabled)) + '</td>')
        [void]$sb.Append('<td>' + (Dash $modeDisp) + '</td>')
        [void]$sb.Append('<td>' + (DashMono $proto) + '</td>')
        [void]$sb.Append('<td>' + (DashMono $endpoint) + '</td>')
        [void]$sb.Append('<td>' + (DashMono $tnet) + '</td>')
        [void]$sb.Append('<td>' + (DashMono $lnet) + '</td>')
        [void]$sb.Append('<td>' + (DashMono $rnet) + '</td>')
        [void]$sb.Append('<td>' + (Dash $auth) + '</td>')
        [void]$sb.Append('<td>' + (DashMono $cipherDisp) + '</td>')
        [void]$sb.Append('<td>' + (DashMono $digest) + '</td>')
        [void]$sb.Append('<td>' + $caCell + '</td>')
        [void]$sb.Append('</tr>')
    }
    return $sb.ToString()
}

function Build-OpenVpn {
    param($root)
    $ovpn = $root.SelectSingleNode('openvpn')
    if ($null -eq $ovpn) { return '' }
    $servers = XNodes $ovpn 'openvpn-server'
    $clients = XNodes $ovpn 'openvpn-client'
    if ($servers.Count -eq 0 -and $clients.Count -eq 0) { return '' }

    $out = New-Object System.Text.StringBuilder
    if ($servers.Count -gt 0) {
        [void]$out.Append('<h3>OpenVPN Servers</h3>')
        [void]$out.Append((Tbl @('Description','Enabled','Mode','Protocol','Port','Tunnel network','Local network','Remote network','Auth','Cipher','Digest','CA / Cert') (Format-OpenVpnRows $servers $true)))
    }
    if ($clients.Count -gt 0) {
        [void]$out.Append('<h3>OpenVPN Clients</h3>')
        [void]$out.Append((Tbl @('Description','Enabled','Mode','Protocol','Server','Tunnel network','Local network','Remote network','Auth','Cipher','Digest','CA / Cert') (Format-OpenVpnRows $clients $false)))
    }
    [void]$out.Append('<p class="note">OpenVPN TLS static keys are never exported by this report, regardless of options.</p>')
    return $out.ToString()
}

function Build-WireGuard {
    param($root)
    $wg = $root.SelectSingleNode('installedpackages/wireguard')
    if ($null -eq $wg) { $wg = $root.SelectSingleNode('wireguard') }
    if ($null -eq $wg) { return '' }
    $tunnels = XNodes $wg 'tunnels/item'
    $peers   = XNodes $wg 'peers/item'
    if ($tunnels.Count -eq 0 -and $peers.Count -eq 0) { return '' }

    $out = New-Object System.Text.StringBuilder
    if ($tunnels.Count -gt 0) {
        $sb = New-Object System.Text.StringBuilder
        foreach ($t in $tunnels) {
            $en = (XText $t 'enabled') -match '(?i)^(yes|on|enabled|true|1)$'
            $addrs = New-Object 'System.Collections.Generic.List[string]'
            foreach ($a in (XNodes $t 'addresses/row')) {
                $ad = XText $a 'address'; $mk = XText $a 'mask'
                if ($ad) { [void]$addrs.Add($(if ($mk) { "$ad/$mk" } else { $ad })) }
            }
            $cls = if (-not $en) { ' class="row-disabled"' } else { '' }
            [void]$sb.Append('<tr' + $cls + '>')
            [void]$sb.Append('<td>' + (DashMono (XText $t 'name')) + '</td>')
            [void]$sb.Append('<td>' + (YesNo $en) + '</td>')
            [void]$sb.Append('<td>' + (DashMono (XText $t 'listenport')) + '</td>')
            [void]$sb.Append('<td>' + $(if ($addrs.Count) { ($addrs | ForEach-Object { DashMono $_ }) -join '<br>' } else { '<span class="muted">&mdash;</span>' }) + '</td>')
            [void]$sb.Append('<td>' + (Dash (XText $t 'descr')) + '</td>')
            [void]$sb.Append('</tr>')
        }
        [void]$out.Append('<h3>WireGuard Tunnels</h3>')
        [void]$out.Append((Tbl @('Tunnel','Enabled','Listen Port','Addresses','Description') $sb.ToString()))
    }
    if ($peers.Count -gt 0) {
        $sb = New-Object System.Text.StringBuilder
        foreach ($p in $peers) {
            $en = (XText $p 'enabled') -match '(?i)^(yes|on|enabled|true|1)$'
            $ep = XText $p 'endpoint'
            $pt = XText $p 'port'
            if ($ep -and $pt) { $ep = $ep + ':' + $pt }
            $allowed = New-Object 'System.Collections.Generic.List[string]'
            foreach ($a in (XNodes $p 'allowedips/row')) {
                $ad = XText $a 'address'; $mk = XText $a 'mask'
                if ($ad) { [void]$allowed.Add($(if ($mk) { "$ad/$mk" } else { $ad })) }
            }
            $hasPsk = -not [string]::IsNullOrWhiteSpace((XText $p 'presharedkey'))
            $cls = if (-not $en) { ' class="row-disabled"' } else { '' }
            [void]$sb.Append('<tr' + $cls + '>')
            [void]$sb.Append('<td>' + (DashMono (XText $p 'tun')) + '</td>')
            [void]$sb.Append('<td>' + (YesNo $en) + '</td>')
            [void]$sb.Append('<td>' + (DashMono $ep) + '</td>')
            [void]$sb.Append('<td>' + $(if ($allowed.Count) { ($allowed | ForEach-Object { DashMono $_ }) -join '<br>' } else { '<span class="muted">&mdash;</span>' }) + '</td>')
            [void]$sb.Append('<td>' + (YesNo $hasPsk) + '</td>')
            [void]$sb.Append('<td>' + (Dash (XText $p 'descr')) + '</td>')
            [void]$sb.Append('</tr>')
        }
        [void]$out.Append('<h3>WireGuard Peers</h3>')
        [void]$out.Append((Tbl @('Tunnel','Enabled','Endpoint','Allowed IPs','PSK Set','Description') $sb.ToString()))
    }
    [void]$out.Append('<p class="note">WireGuard private keys and preshared keys are never exported by this report, regardless of options.</p>')
    return $out.ToString()
}

function Build-HighAvailability {
    param($root)
    $ha = $root.SelectSingleNode('hasync')
    if ($null -eq $ha) { return '' }
    $pfsync  = XHas $ha 'pfsyncenabled'
    $pfIf    = XText $ha 'pfsyncinterface'
    $pfPeer  = XText $ha 'pfsyncpeerip'
    $syncTo  = XText $ha 'synchronizetoip'
    $syncUsr = XText $ha 'username'
    if (-not $pfsync -and -not $syncTo -and -not $pfIf) { return '' }

    $synced = New-Object 'System.Collections.Generic.List[string]'
    foreach ($child in $ha.ChildNodes) {
        if ($child.NodeType -eq [System.Xml.XmlNodeType]::Element -and $child.Name -like 'synchronize*') {
            if ($child.Name -notin @('synchronizetoip')) {
                [void]$synced.Add(($child.Name -replace '^synchronize', ''))
            }
        }
    }

    $sb = New-Object System.Text.StringBuilder
    [void]$sb.Append('<div class="table-wrap"><table class="kv">')
    [void]$sb.Append('<tr><th>pfsync State Sync</th><td>' + (YesNo $pfsync) + '</td></tr>')
    [void]$sb.Append('<tr><th>pfsync Interface</th><td>' + (DashMono $pfIf) + '</td></tr>')
    [void]$sb.Append('<tr><th>pfsync Peer IP</th><td>' + (DashMono $pfPeer) + '</td></tr>')
    [void]$sb.Append('<tr><th>XMLRPC Sync Target IP</th><td>' + (DashMono $syncTo) + '</td></tr>')
    [void]$sb.Append('<tr><th>XMLRPC Username</th><td>' + (E-User $syncUsr) + '</td></tr>')
    [void]$sb.Append('<tr><th>XMLRPC Password</th><td><span class="muted">' + $(if (XText $ha 'password') { '[password not shown]' } else { '[none]' }) + '</span></td></tr>')
    [void]$sb.Append('<tr><th>Synced Sections</th><td>' + $(if ($synced.Count) { E ($synced -join ', ') } else { '<span class="muted">&mdash;</span>' }) + '</td></tr>')
    [void]$sb.Append('</table></div>')
    return $sb.ToString()
}

function Build-Dhcp {
    param($root)
    $out = New-Object System.Text.StringBuilder
    $any = $false

    foreach ($spec in @(@{ Tag = 'dhcpd'; Label = 'DHCPv4' }, @{ Tag = 'dhcpdv6'; Label = 'DHCPv6' })) {
        $node = $root.SelectSingleNode($spec.Tag)
        if ($null -eq $node) { continue }
        foreach ($ifNode in $node.ChildNodes) {
            if ($ifNode.NodeType -ne [System.Xml.XmlNodeType]::Element) { continue }
            $any = $true
            $key     = $ifNode.Name
            $friendly = if ($script:IfMap.ContainsKey($key)) { $key + ' &mdash; ' + $script:IfMap[$key] } else { $key }
            $enabled = XHas $ifNode 'enable'
            $from    = XText $ifNode 'range/from'
            $to      = XText $ifNode 'range/to'
            $ranges  = New-Object 'System.Collections.Generic.List[string]'
            if ($from -or $to) { [void]$ranges.Add("$from - $to") }
            foreach ($pool in (XNodes $ifNode 'pool')) {
                $pf = XText $pool 'range/from'; $pt = XText $pool 'range/to'
                if ($pf -or $pt) { [void]$ranges.Add("$pf - $pt (pool)") }
            }
            $dns = New-Object 'System.Collections.Generic.List[string]'
            foreach ($d in (XNodes $ifNode 'dnsserver')) { if ($d.InnerText.Trim()) { [void]$dns.Add($d.InnerText.Trim()) } }
            $gw  = XText $ifNode 'gateway'
            $dom = XText $ifNode 'domain'
            $dlt = XText $ifNode 'defaultleasetime'
            $mlt = XText $ifNode 'maxleasetime'
            $denyUnk = XHas $ifNode 'denyunknown'

            $kv = New-Object System.Text.StringBuilder
            [void]$kv.Append('<table class="kv">')
            [void]$kv.Append('<tr><th>Enabled</th><td>' + (YesNo $enabled) + '</td></tr>')
            [void]$kv.Append('<tr><th>Pool range(s)</th><td>' + $(if ($ranges.Count) { ($ranges | ForEach-Object { DashMono $_ }) -join '<br>' } else { '<span class="muted">&mdash;</span>' }) + '</td></tr>')
            [void]$kv.Append('<tr><th>DNS servers</th><td>' + $(if ($dns.Count) { ($dns | ForEach-Object { DashMono $_ }) -join '<br>' } else { '<span class="muted">&mdash;</span>' }) + '</td></tr>')
            [void]$kv.Append('<tr><th>Gateway</th><td>' + (DashMono $gw) + '</td></tr>')
            [void]$kv.Append('<tr><th>Domain</th><td>' + (Dash $dom) + '</td></tr>')
            [void]$kv.Append('<tr><th>Deny unknown clients</th><td>' + (YesNo $denyUnk) + '</td></tr>')
            [void]$kv.Append('<tr><th>Default / Max lease</th><td>' + (DashMono $(if ($dlt -or $mlt) { "$dlt / $mlt" } else { '' })) + '</td></tr>')
            [void]$kv.Append('</table>')

            [void]$out.Append('<h3 class="iface-head">' + (E $friendly) + ' <span class="badge badge-info">' + $spec.Label + '</span></h3><div class="table-wrap">' + $kv.ToString() + '</div>')

            $smaps = XNodes $ifNode 'staticmap'
            if ($smaps.Count -gt 0) {
                $sb = New-Object System.Text.StringBuilder
                foreach ($m in $smaps) {
                    $idVal = if ($spec.Tag -eq 'dhcpdv6') { XText $m 'duid' } else { XText $m 'mac' }
                    $ipVal = if ($spec.Tag -eq 'dhcpdv6') { XText $m 'ipaddrv6' } else { XText $m 'ipaddr' }
                    [void]$sb.Append('<tr>')
                    [void]$sb.Append('<td>' + (DashMono $idVal) + '</td>')
                    [void]$sb.Append('<td>' + (DashMono $ipVal) + '</td>')
                    [void]$sb.Append('<td>' + (E-Host (XText $m 'hostname')) + '</td>')
                    [void]$sb.Append('<td>' + (DashMono (XText $m 'cid')) + '</td>')
                    [void]$sb.Append('<td>' + (Dash (XText $m 'descr')) + '</td>')
                    [void]$sb.Append('</tr>')
                }
                $idHdr = if ($spec.Tag -eq 'dhcpdv6') { 'DUID' } else { 'MAC' }
                [void]$out.Append('<p class="subtitle">Static mappings (' + $smaps.Count + ')</p>' + (Tbl @($idHdr,'IP address','Hostname','Client ID','Description') $sb.ToString() 'filterable-table'))
            }
        }
    }

    # DHCP Relay (v4 & v6)
    foreach ($rSpec in @(@{ Tag = 'dhcrelay'; Label = 'DHCPv4 Relay' }, @{ Tag = 'dhcrelay6'; Label = 'DHCPv6 Relay' })) {
        $rel = $root.SelectSingleNode($rSpec.Tag)
        if ($null -ne $rel -and (XHas $rel 'enable')) {
            $any = $true
            $kv = '<table class="kv">' +
                  '<tr><th>Enabled</th><td>' + (YesNo $true) + '</td></tr>' +
                  '<tr><th>Interfaces</th><td>' + (DashMono (XText $rel 'interface')) + '</td></tr>' +
                  '<tr><th>Destination Server(s)</th><td>' + (DashMono (XText $rel 'server')) + '</td></tr>' +
                  '</table>'
            [void]$out.Append('<h3>' + $rSpec.Label + '</h3><div class="table-wrap">' + $kv + '</div>')
        }
    }

    if (-not $any) { return '' }
    return $out.ToString()
}

function Build-Dns {
    param($root)
    $out = New-Object System.Text.StringBuilder

    # Resolver (Unbound)
    $unbound = $root.SelectSingleNode('unbound')
    [void]$out.Append('<h3>DNS Resolver (Unbound)</h3>')
    if ($null -eq $unbound) {
        [void]$out.Append('<p class="not-configured">Not configured.</p>')
    }
    else {
        $enabled = XHas $unbound 'enable'
        $ai = XText $unbound 'active_interface'; if (-not $ai) { $ai = 'All' }
        $oi = XText $unbound 'outgoing_interface'; if (-not $oi) { $oi = 'All' }
        $fwd = XHas $unbound 'forwarding'
        $kv = New-Object System.Text.StringBuilder
        [void]$kv.Append('<table class="kv">')
        [void]$kv.Append('<tr><th>Enabled</th><td>' + (YesNo $enabled) + '</td></tr>')
        [void]$kv.Append('<tr><th>Listening interfaces</th><td>' + (DashMono $ai) + '</td></tr>')
        [void]$kv.Append('<tr><th>Outgoing interfaces</th><td>' + (DashMono $oi) + '</td></tr>')
        [void]$kv.Append('<tr><th>DNSSEC</th><td>' + (YesNo (XHas $unbound 'dnssec')) + '</td></tr>')
        [void]$kv.Append('<tr><th>Forwarding mode</th><td>' + (YesNo $fwd) + '</td></tr>')
        [void]$kv.Append('<tr><th>Register DHCP leases / static</th><td>' + (YesNo (XHas $unbound 'regdhcp')) + ' / ' + (YesNo (XHas $unbound 'regdhcpstatic')) + '</td></tr>')
        [void]$kv.Append('</table>')
        [void]$out.Append('<div class="table-wrap">' + $kv.ToString() + '</div>')

        $hosts = XNodes $unbound 'hosts'
        if ($hosts.Count -gt 0) {
            $sb = New-Object System.Text.StringBuilder
            foreach ($h in $hosts) {
                $alItems = New-Object 'System.Collections.Generic.List[string]'
                foreach ($al in (XNodes $h 'aliases/item')) {
                    $ah = XText $al 'host'; $ad = XText $al 'domain'
                    if ($ah -and $ad) { [void]$alItems.Add("$ah.$ad") } elseif ($ah) { [void]$alItems.Add($ah) }
                }
                [void]$sb.Append('<tr><td>' + (E-Host (XText $h 'host')) + '</td><td>' + (Dash (XText $h 'domain')) + '</td><td>' + (DashMono (XText $h 'ip')) + '</td><td>' + $(if ($alItems.Count) { ($alItems | ForEach-Object { E-Host $_ }) -join '<br>' } else { '<span class="muted">&mdash;</span>' }) + '</td><td>' + (Dash (XText $h 'descr')) + '</td></tr>')
            }
            [void]$out.Append('<p class="subtitle">Host overrides (' + $hosts.Count + ')</p>' + (Tbl @('Host','Domain','IP','Aliases','Description') $sb.ToString() 'filterable-table'))
        }
        $doms = XNodes $unbound 'domainoverrides'
        if ($doms.Count -gt 0) {
            $sb = New-Object System.Text.StringBuilder
            foreach ($d in $doms) {
                [void]$sb.Append('<tr><td>' + (Dash (XText $d 'domain')) + '</td><td>' + (DashMono (XText $d 'ip')) + '</td><td>' + (Dash (XText $d 'descr')) + '</td></tr>')
            }
            [void]$out.Append('<p class="subtitle">Domain overrides (' + $doms.Count + ')</p>' + (Tbl @('Domain','Forward-to IP','Description') $sb.ToString() 'filterable-table'))
        }
    }

    # Forwarder (dnsmasq)
    $dnsmasq = $root.SelectSingleNode('dnsmasq')
    [void]$out.Append('<h3>DNS Forwarder (dnsmasq)</h3>')
    if ($null -eq $dnsmasq -or -not (XHas $dnsmasq 'enable')) {
        [void]$out.Append('<p class="not-configured">Not enabled.</p>')
    }
    else {
        $dmIf = XText $dnsmasq 'interface'; if (-not $dmIf) { $dmIf = 'All' }
        $kv = '<table class="kv"><tr><th>Enabled</th><td>' + (YesNo $true) + '</td></tr><tr><th>Interfaces</th><td>' + (DashMono $dmIf) + '</td></tr></table>'
        [void]$out.Append('<div class="table-wrap">' + $kv + '</div>')
        $hosts = XNodes $dnsmasq 'hosts'
        if ($hosts.Count -gt 0) {
            $sb = New-Object System.Text.StringBuilder
            foreach ($h in $hosts) {
                [void]$sb.Append('<tr><td>' + (E-Host (XText $h 'host')) + '</td><td>' + (Dash (XText $h 'domain')) + '</td><td>' + (DashMono (XText $h 'ip')) + '</td><td>' + (Dash (XText $h 'descr')) + '</td></tr>')
            }
            [void]$out.Append('<p class="subtitle">Host overrides (' + $hosts.Count + ')</p>' + (Tbl @('Host','Domain','IP','Description') $sb.ToString() 'filterable-table'))
        }
        $doms = XNodes $dnsmasq 'domainoverrides'
        if ($doms.Count -gt 0) {
            $sb = New-Object System.Text.StringBuilder
            foreach ($d in $doms) {
                [void]$sb.Append('<tr><td>' + (Dash (XText $d 'domain')) + '</td><td>' + (DashMono (XText $d 'ip')) + '</td><td>' + (Dash (XText $d 'descr')) + '</td></tr>')
            }
            [void]$out.Append('<p class="subtitle">Domain overrides (' + $doms.Count + ')</p>' + (Tbl @('Domain','Forward-to IP','Description') $sb.ToString() 'filterable-table'))
        }
    }
    return $out.ToString()
}

function Build-Certs {
    param($root)
    $cas   = XNodes $root 'ca'
    $certs = XNodes $root 'cert'
    $crls  = XNodes $root 'crl'
    if ($cas.Count -eq 0 -and $certs.Count -eq 0 -and $crls.Count -eq 0) { return '' }
    $out = New-Object System.Text.StringBuilder

    if ($cas.Count -gt 0) {
        [void]$out.Append('<h3>Certificate Authorities</h3>')
        $sb = New-Object System.Text.StringBuilder
        foreach ($c in $cas) {
            $rid   = XText $c 'refid'
            $rowId = 'ca-' + (Format-Slug $rid)
            $descr = XText $c 'descr'
            $info  = Get-CertInfo (XText $c 'crt')
            $status = Format-CertStatus $info ("CA '" + $(if ($descr) { $descr } else { $rid }) + "'") $rowId
            $nb    = if ($info.NotBefore) { $info.NotBefore.ToString('yyyy-MM-dd') } else { '' }
            $na    = if ($info.NotAfter)  { $info.NotAfter.ToString('yyyy-MM-dd') }  else { '' }
            $keyInfo = if ($info.KeyAlg -and $info.KeySize) { "$($info.KeyAlg) $($info.KeySize)b" } else { '' }
            $algDisp = if ($info.SigAlg -and $keyInfo) { "$($info.SigAlg) / $keyInfo" } elseif ($info.SigAlg) { $info.SigAlg } else { $keyInfo }
            $uses  = @()
            if ($rid -and $script:RefUsageMap.ContainsKey($rid)) { $uses = @($script:RefUsageMap[$rid]) }
            $usedBy = if ($uses.Count -gt 0) { ($uses | ForEach-Object { E $_ }) -join '<br>' } else { '<span class="muted">Not referenced</span>' }
            [void]$sb.Append('<tr id="' + $rowId + '">')
            [void]$sb.Append('<td>' + (Dash $descr) + '</td>')
            [void]$sb.Append('<td>Certificate Authority</td>')
            [void]$sb.Append('<td class="wrapcell">' + (E-CertDn $info.Subject) + '</td>')
            [void]$sb.Append('<td>' + (DashMono $algDisp) + '</td>')
            $valCell = if ($nb -or $na) { '<code class="mono">' + (E $nb) + '</code> &rarr; <code class="mono">' + (E $na) + '</code>' } else { '<span class="muted">&mdash;</span>' }
            [void]$sb.Append('<td>' + $valCell + '</td>')
            [void]$sb.Append('<td>' + $status + '</td>')
            [void]$sb.Append('<td>' + $usedBy + '</td>')
            [void]$sb.Append('</tr>')
        }
        [void]$out.Append((Tbl @('Name','Type','Subject','Sig / Key','Validity','Status','Used by') $sb.ToString()))
    }

    if ($certs.Count -gt 0) {
        [void]$out.Append('<h3>Certificates</h3>')
        $sb = New-Object System.Text.StringBuilder
        foreach ($c in $certs) {
            $rid   = XText $c 'refid'
            $rowId = 'cert-' + (Format-Slug $rid)
            $descr = XText $c 'descr'
            $type  = XText $c 'type'
            $info  = Get-CertInfo (XText $c 'crt')
            $status = Format-CertStatus $info ("Certificate '" + $(if ($descr) { $descr } else { $rid }) + "'") $rowId
            $nb    = if ($info.NotBefore) { $info.NotBefore.ToString('yyyy-MM-dd') } else { '' }
            $na    = if ($info.NotAfter)  { $info.NotAfter.ToString('yyyy-MM-dd') }  else { '' }
            $keyInfo = if ($info.KeyAlg -and $info.KeySize) { "$($info.KeyAlg) $($info.KeySize)b" } else { '' }
            $algDisp = if ($info.SigAlg -and $keyInfo) { "$($info.SigAlg) / $keyInfo" } elseif ($info.SigAlg) { $info.SigAlg } else { $keyInfo }
            $typeDisp = switch ($type) {
                'server' { 'Server' }
                'user'   { 'User' }
                default  { if ($type) { $type } else { 'Unknown' } }
            }
            if ($info.SelfSigned) { $typeDisp += ' (Self-signed)' }
            $uses  = @()
            if ($rid -and $script:RefUsageMap.ContainsKey($rid)) { $uses = @($script:RefUsageMap[$rid]) }
            $usedBy = if ($uses.Count -gt 0) { ($uses | ForEach-Object { E $_ }) -join '<br>' } else { '<span class="muted">Not referenced</span>' }
            [void]$sb.Append('<tr id="' + $rowId + '">')
            [void]$sb.Append('<td>' + (Dash $descr) + '</td>')
            [void]$sb.Append('<td>' + (E $typeDisp) + '</td>')
            [void]$sb.Append('<td class="wrapcell">' + (E-CertDn $info.Subject) + '</td>')
            [void]$sb.Append('<td>' + (DashMono $algDisp) + '</td>')
            $valCell = if ($nb -or $na) { '<code class="mono">' + (E $nb) + '</code> &rarr; <code class="mono">' + (E $na) + '</code>' } else { '<span class="muted">&mdash;</span>' }
            [void]$sb.Append('<td>' + $valCell + '</td>')
            [void]$sb.Append('<td>' + $status + '</td>')
            [void]$sb.Append('<td>' + $usedBy + '</td>')
            [void]$sb.Append('</tr>')
        }
        [void]$out.Append((Tbl @('Name','Type','Subject','Sig / Key','Validity','Status','Used by') $sb.ToString()))
    }

    if ($crls.Count -gt 0) {
        [void]$out.Append('<h3>Certificate Revocation Lists (CRLs)</h3>')
        $sb = New-Object System.Text.StringBuilder
        foreach ($crl in $crls) {
            $revCount = (XNodes $crl 'cert').Count
            [void]$sb.Append('<tr>')
            [void]$sb.Append('<td>' + (Dash (XText $crl 'descr')) + '</td>')
            [void]$sb.Append('<td>' + (Format-CertRef (XText $crl 'caref')) + '</td>')
            [void]$sb.Append('<td>' + (Dash (XText $crl 'method')) + '</td>')
            [void]$sb.Append('<td>' + $revCount + '</td>')
            [void]$sb.Append('</tr>')
        }
        [void]$out.Append((Tbl @('Name','CA','Method','Revoked Certs') $sb.ToString()))
    }

    [void]$out.Append('<p class="note">Private key material is never exported by this report, regardless of options.</p>')
    return $out.ToString()
}

function Build-Users {
    param($root)
    $sys = $root.SelectSingleNode('system')
    if ($null -eq $sys) { return '' }
    $users  = XNodes $sys 'user'
    $groups = XNodes $sys 'group'
    $auths  = XNodes $sys 'authserver'
    if ($users.Count -eq 0 -and $groups.Count -eq 0 -and $auths.Count -eq 0) { return '' }

    # uid -> name map & uid -> groups reverse map
    $uidMap = @{}
    foreach ($u in $users) {
        $uid = XText $u 'uid'
        if ($uid -ne '') { $uidMap[$uid] = (XText $u 'name') }
    }
    $uidGroups = @{}
    foreach ($g in $groups) {
        $gn = XText $g 'name'
        foreach ($m in (XNodes $g 'member')) {
            $mv = $m.InnerText.Trim()
            if ($mv -ne '' -and $gn) {
                if (-not $uidGroups.ContainsKey($mv)) { $uidGroups[$mv] = New-Object 'System.Collections.Generic.List[string]' }
                if (-not $uidGroups[$mv].Contains($gn)) { [void]$uidGroups[$mv].Add($gn) }
            }
        }
    }

    $out = New-Object System.Text.StringBuilder
    if ($users.Count -gt 0) {
        [void]$out.Append('<h3>Users</h3>')
        $sb = New-Object System.Text.StringBuilder
        foreach ($u in $users) {
            $uname    = XText $u 'name'
            $uid      = XText $u 'uid'
            $rowId    = 'row-user-' + (Format-Slug $(if ($uname) { $uname } else { $uid }))
            $disabled = XHas $u 'disabled'
            $expires  = XText $u 'expires'
            $authKeys = XText $u 'authorizedkeys'
            $keyCount = 0
            if ($authKeys) {
                try {
                    $decoded = [System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String(($authKeys -replace '\s', '')))
                    $keyCount = @($decoded -split "`r?`n" | Where-Object { $_.Trim() -and -not $_.Trim().StartsWith('#') }).Count
                }
                catch {
                    Write-Verbose ("Could not decode authorizedkeys for user '{0}': {1}" -f $uname, $_.Exception.Message)
                    $keyCount = 1
                }
            }
            $privs = New-Object 'System.Collections.Generic.List[string]'
            foreach ($p in (XNodes $u 'priv')) { if ($p.InnerText.Trim()) { [void]$privs.Add($p.InnerText.Trim()) } }

            $gList = New-Object 'System.Collections.Generic.List[string]'
            $gProp = XText $u 'groupname'
            if ($gProp) { [void]$gList.Add($gProp) }
            if ($uid -ne '' -and $uidGroups.ContainsKey($uid)) {
                foreach ($gn in $uidGroups[$uid]) { if (-not $gList.Contains($gn)) { [void]$gList.Add($gn) } }
            }

            $hashType = ''
            if (XHas $u 'bcrypt-hash')      { $hashType = 'bcrypt' }
            elseif (XHas $u 'sha512-hash')  { $hashType = 'sha512' }
            elseif (XHas $u 'md5-hash')     { $hashType = 'md5' }

            $hashBadge = ''
            if ($hashType -eq 'md5' -and -not $disabled) {
                $hashBadge = ' <span class="badge badge-high">WEAK HASH</span>'
                Add-Finding 'high' 'WEAK PASSWORD HASH' ("User '$uname'") 'Account uses legacy MD5 password hash instead of bcrypt.' $rowId
            }

            $cls = if ($disabled) { ' class="row-disabled"' } else { '' }
            [void]$sb.Append('<tr id="' + $rowId + '"' + $cls + '>')
            [void]$sb.Append('<td>' + (E-User $uname) + '</td>')
            [void]$sb.Append('<td>' + (YesNo (-not $disabled)) + '</td>')
            [void]$sb.Append('<td>' + (Dash (XText $u 'descr')) + '</td>')
            [void]$sb.Append('<td>' + (Dash (XText $u 'scope')) + '</td>')
            [void]$sb.Append('<td>' + $(if ($gList.Count) { ($gList | ForEach-Object { E $_ }) -join ', ' } else { '<span class="muted">&mdash;</span>' }) + '</td>')
            [void]$sb.Append('<td>' + $(if ($privs.Count) { ($privs | ForEach-Object { E $_ }) -join '<br>' } else { '<span class="muted">&mdash;</span>' }) + '</td>')
            [void]$sb.Append('<td>' + $(if ($keyCount -gt 0) { '<span class="badge badge-info">' + $keyCount + ' key(s)</span>' } else { '<span class="muted">&mdash;</span>' }) + '</td>')
            [void]$sb.Append('<td>' + (Dash $expires) + '</td>')
            [void]$sb.Append('<td><span class="muted">' + $(if ($hashType) { '[' + $hashType + ' hash not shown]' } else { '[none]' }) + '</span>' + $hashBadge + '</td>')
            [void]$sb.Append('</tr>')
        }
        [void]$out.Append((Tbl @('Username','Enabled','Full name','Scope','Groups','Privileges','SSH Keys','Expires','Password') $sb.ToString()))
        [void]$out.Append('<p class="note">Password hashes and SSH key bodies are never exported by this report, regardless of options.</p>')
    }

    if ($groups.Count -gt 0) {
        [void]$out.Append('<h3>Groups</h3>')
        $sb = New-Object System.Text.StringBuilder
        foreach ($g in $groups) {
            $privs = New-Object 'System.Collections.Generic.List[string]'
            foreach ($p in (XNodes $g 'priv')) { if ($p.InnerText.Trim()) { [void]$privs.Add($p.InnerText.Trim()) } }
            $members = New-Object 'System.Collections.Generic.List[string]'
            foreach ($m in (XNodes $g 'member')) {
                $mv = $m.InnerText.Trim()
                if ($uidMap.ContainsKey($mv)) { [void]$members.Add($uidMap[$mv]) } elseif ($mv) { [void]$members.Add("uid:$mv") }
            }
            [void]$sb.Append('<tr>')
            [void]$sb.Append('<td>' + (Dash (XText $g 'name')) + '</td>')
            [void]$sb.Append('<td>' + (Dash (XText $g 'description')) + '</td>')
            [void]$sb.Append('<td>' + (Dash (XText $g 'scope')) + '</td>')
            [void]$sb.Append('<td>' + $(if ($members.Count) { ($members | ForEach-Object { E-User $_ }) -join '<br>' } else { '<span class="muted">&mdash;</span>' }) + '</td>')
            [void]$sb.Append('<td>' + $(if ($privs.Count) { ($privs | ForEach-Object { E $_ }) -join '<br>' } else { '<span class="muted">&mdash;</span>' }) + '</td>')
            [void]$sb.Append('</tr>')
        }
        [void]$out.Append((Tbl @('Group','Description','Scope','Members','Privileges') $sb.ToString()))
    }

    if ($auths.Count -gt 0) {
        [void]$out.Append('<h3>Authentication Servers (LDAP / RADIUS)</h3>')
        $sb = New-Object System.Text.StringBuilder
        $aSeq = 0
        foreach ($a in $auths) {
            $aSeq++
            $rowId = 'row-auth-' + $aSeq
            $aname = XText $a 'name'
            $atype = XText $a 'type'
            $ahost = XText $a 'host'
            $port  = if ($atype -ieq 'ldap') { XText $a 'ldap_port' } else { XText $a 'radius_auth_port' }
            $trans = if ($atype -ieq 'ldap') { XText $a 'ldap_urltype' } else { 'RADIUS' }
            $badge = ''
            $cls   = ''
            if ($atype -ieq 'ldap' -and $trans -match '(?i)standard\s*tcp') {
                $badge = ' <span class="badge badge-high">PLAINTEXT LDAP</span>'
                $cls = ' class="row-high"'
                Add-Finding 'high' 'PLAINTEXT LDAP' ("Auth server '$aname'") 'LDAP server uses unencrypted Standard TCP instead of SSL/TLS or STARTTLS.' $rowId
            }
            [void]$sb.Append('<tr id="' + $rowId + '"' + $cls + '>')
            [void]$sb.Append('<td>' + (Dash $aname) + $badge + '</td>')
            [void]$sb.Append('<td>' + (Dash $atype.ToUpperInvariant()) + '</td>')
            [void]$sb.Append('<td>' + (DashMono $ahost) + '</td>')
            [void]$sb.Append('<td>' + (DashMono $port) + '</td>')
            [void]$sb.Append('<td>' + (Dash $trans) + '</td>')
            [void]$sb.Append('<td><span class="muted">[credentials not shown]</span></td>')
            [void]$sb.Append('</tr>')
        }
        [void]$out.Append((Tbl @('Name','Type','Host','Port','Transport','Secrets') $sb.ToString()))
    }
    return $out.ToString()
}

function Build-Aliases {
    param($root)
    $al = $root.SelectSingleNode('aliases')
    if ($null -eq $al) { return '' }
    $aliases = XNodes $al 'alias'
    if ($aliases.Count -eq 0) { return '' }
    $sb = New-Object System.Text.StringBuilder
    foreach ($a in $aliases) {
        $name   = XText $a 'name'
        $rowId  = if ($name) { ' id="alias-' + (Format-Slug $name) + '"' } else { '' }
        $type   = XText $a 'type'
        $addr   = XText $a 'address'
        $url    = XText $a 'url'
        $freq   = XText $a 'updatefreq'
        $detail = XText $a 'detail'
        $detArr = @()
        if ($detail) { $detArr = @($detail -split '\|\|') }

        $addrDisp = '<span class="muted">&mdash;</span>'
        if ($addr) {
            $entries = @($addr -split '\s+' | Where-Object { $_ })
            $lines = New-Object 'System.Collections.Generic.List[string]'
            for ($i = 0; $i -lt $entries.Count; $i++) {
                $line = '<code class="mono">' + (E $entries[$i]) + '</code>'
                if ($i -lt $detArr.Count -and -not [string]::IsNullOrWhiteSpace($detArr[$i])) {
                    $line += ' <span class="muted">&mdash; ' + (E $detArr[$i].Trim()) + '</span>'
                }
                [void]$lines.Add($line)
            }
            $addrDisp = $lines -join '<br>'
        }
        elseif ($url) {
            $addrDisp = '<code class="mono">' + (E $url) + '</code>'
            if ($freq) { $addrDisp += ' <span class="muted">(every ' + (E $freq) + 'd)</span>' }
        }

        [void]$sb.Append('<tr' + $rowId + '>')
        [void]$sb.Append('<td><code class="mono">' + (E $name) + '</code></td>')
        [void]$sb.Append('<td>' + (Dash $type) + '</td>')
        [void]$sb.Append('<td class="wrapcell">' + $addrDisp + '</td>')
        [void]$sb.Append('<td>' + (Dash (XText $a 'descr')) + '</td>')
        [void]$sb.Append('</tr>')
    }
    return (Tbl @('Name','Type','Contents','Description') $sb.ToString() 'filterable-table')
}

function Build-Services {
    param($root)
    $out = New-Object System.Text.StringBuilder

    # SNMP
    $snmp = $root.SelectSingleNode('snmpd')
    if ($null -ne $snmp -and ((XHas $snmp 'enable') -or (XText $snmp 'rocommunity'))) {
        $en   = XHas $snmp 'enable'
        $comm = XText $snmp 'rocommunity'
        $bind = XText $snmp 'bindip'; if (-not $bind) { $bind = 'All' }
        $port = XText $snmp 'pollport'; if (-not $port) { $port = '161 (default)' }
        $trap = XText $snmp 'trapserver'
        $commBadge = ''
        if ($en -and $comm -match '(?i)^(public|private)$') {
            $commBadge = ' <span class="badge badge-high">DEFAULT COMMUNITY</span>'
            Add-Finding 'high' 'DEFAULT SNMP COMMUNITY' 'Services / SNMP' 'SNMP is enabled with a default community string (public/private).' 'row-svc-snmp'
        }
        $kv = New-Object System.Text.StringBuilder
        [void]$kv.Append('<table class="kv">')
        [void]$kv.Append('<tr id="row-svc-snmp"><th>Enabled</th><td>' + (YesNo $en) + '</td></tr>')
        [void]$kv.Append('<tr><th>Bind interface / IP</th><td>' + (DashMono $bind) + '</td></tr>')
        [void]$kv.Append('<tr><th>Polling port</th><td>' + (DashMono $port) + '</td></tr>')
        [void]$kv.Append('<tr><th>Read-only community</th><td>' + (Secret $comm) + $commBadge + '</td></tr>')
        if ($trap) { [void]$kv.Append('<tr><th>Trap server</th><td>' + (DashMono $trap) + '</td></tr>') }
        [void]$kv.Append('</table>')
        [void]$out.Append('<h3>SNMP</h3><div class="table-wrap">' + $kv.ToString() + '</div>')
    }

    # Syslog
    $syslog = $root.SelectSingleNode('syslog')
    if ($null -ne $syslog -and ((XHas $syslog 'enable') -or (XText $syslog 'remoteserver'))) {
        $remEn = XHas $syslog 'enable'
        $svrs  = @((XText $syslog 'remoteserver'), (XText $syslog 'remoteserver2'), (XText $syslog 'remoteserver3') | Where-Object { $_ })
        $kv = '<table class="kv">' +
              '<tr><th>Remote logging enabled</th><td>' + (YesNo $remEn) + '</td></tr>' +
              '<tr><th>Remote server(s)</th><td>' + $(if ($svrs.Count) { ($svrs | ForEach-Object { DashMono $_ }) -join '<br>' } else { '<span class="muted">&mdash;</span>' }) + '</td></tr>' +
              '<tr><th>Source interface</th><td>' + (DashMono (XText $syslog 'sourceip')) + '</td></tr>' +
              '<tr><th>Log default blocks</th><td>' + (YesNo (-not (XHas $syslog 'nologdefaultblock'))) + '</td></tr>' +
              '</table>'
        [void]$out.Append('<h3>Syslog</h3><div class="table-wrap">' + $kv + '</div>')
    }

    # Dynamic DNS
    $ddns = XNodes $root 'dyndnses/dyndns'
    if ($ddns.Count -gt 0) {
        $sb = New-Object System.Text.StringBuilder
        foreach ($d in $ddns) {
            $en = XHas $d 'enable'
            $cls = if (-not $en) { ' class="row-disabled"' } else { '' }
            [void]$sb.Append('<tr' + $cls + '>')
            [void]$sb.Append('<td>' + (Dash (XText $d 'type')) + '</td>')
            [void]$sb.Append('<td>' + (DashMono (XText $d 'interface')) + '</td>')
            [void]$sb.Append('<td>' + (DashMono (XText $d 'host')) + '</td>')
            [void]$sb.Append('<td>' + (YesNo $en) + '</td>')
            [void]$sb.Append('<td>' + (Dash (XText $d 'descr')) + '</td>')
            [void]$sb.Append('</tr>')
        }
        [void]$out.Append('<h3>Dynamic DNS</h3>' + (Tbl @('Service','Interface','Hostname','Enabled','Description') $sb.ToString()))
        [void]$out.Append('<p class="note">Dynamic DNS passwords and API tokens are never exported.</p>')
    }

    # Schedules
    $scheds = XNodes $root 'schedules/schedule'
    if ($scheds.Count -gt 0) {
        $sb = New-Object System.Text.StringBuilder
        foreach ($s in $scheds) {
            [void]$sb.Append('<tr>')
            [void]$sb.Append('<td>' + (DashMono (XText $s 'name')) + '</td>')
            [void]$sb.Append('<td>' + (Dash (XText $s 'descr')) + '</td>')
            [void]$sb.Append('</tr>')
        }
        [void]$out.Append('<h3>Schedules</h3>' + (Tbl @('Name','Description') $sb.ToString()))
    }

    return $out.ToString()
}

function Build-Packages {
    param($root)
    $ip = $root.SelectSingleNode('installedpackages')
    if ($null -eq $ip) { return '' }
    $pkgs = XNodes $ip 'package'
    if ($pkgs.Count -eq 0) { return '' }
    $sb = New-Object System.Text.StringBuilder
    foreach ($p in $pkgs) {
        [void]$sb.Append('<tr>')
        [void]$sb.Append('<td>' + (Dash (XText $p 'name')) + '</td>')
        [void]$sb.Append('<td>' + (DashMono (XText $p 'version')) + '</td>')
        [void]$sb.Append('<td>' + (Dash (XText $p 'descr')) + '</td>')
        [void]$sb.Append('</tr>')
    }
    return (Tbl @('Package','Version','Description') $sb.ToString() 'filterable-table')
}

function Build-Revision {
    param($root)
    $rev = $root.SelectSingleNode('revision')
    $lc  = XText $root 'lastchange'
    if ($null -eq $rev -and -not $lc) { return '' }
    $sb = New-Object System.Text.StringBuilder
    [void]$sb.Append('<div class="table-wrap"><table class="kv">')
    if ($null -ne $rev) {
        [void]$sb.Append('<tr><th>Last change time</th><td>' + (DashMono (ConvertFrom-Epoch (XText $rev 'time'))) + '</td></tr>')
        [void]$sb.Append('<tr><th>Description</th><td>' + (Dash (XText $rev 'description')) + '</td></tr>')
        [void]$sb.Append('<tr><th>Changed by</th><td>' + (E-User (XText $rev 'username')) + '</td></tr>')
    }
    if ($lc) {
        [void]$sb.Append('<tr><th>lastchange</th><td>' + (DashMono (ConvertFrom-Epoch $lc)) + '</td></tr>')
    }
    [void]$sb.Append('</table></div>')
    return $sb.ToString()
}

function Build-Findings {
    if ($script:Findings.Count -eq 0) {
        return '<p class="all-clear">No automated risk flags were raised. (This is a heuristic scan, not a substitute for a full security review.)</p>'
    }
    # Severity ordering: high first, then warn, then info.
    $sevRank = @{ 'high' = 0; 'warn' = 1; 'info' = 2 }
    $ordered = @($script:Findings | Sort-Object @{ Expression = { $sevRank[$_.Sev] } }, Label, Where)

    # Counts (explicitly sorted by severity rank, then label)
    $byKey = @($ordered | Group-Object { $_.Sev + '|' + $_.Label } | Sort-Object @{ Expression = { $sevRank[$_.Group[0].Sev] } }, { $_.Group[0].Label })
    $cards = New-Object System.Text.StringBuilder
    [void]$cards.Append('<div class="finding-cards" role="group" aria-label="Filter findings by type">')
    [void]$cards.Append('<button type="button" class="fcard fcard-all is-active" data-sev="all" data-label="all"><div class="fnum">' + $ordered.Count + '</div><div class="flbl">ALL FLAGS</div></button>')
    foreach ($g in $byKey) {
        $sev = ($g.Group[0]).Sev
        $lbl = ($g.Group[0]).Label
        [void]$cards.Append('<button type="button" class="fcard fcard-' + $sev + '" data-sev="' + $sev + '" data-label="' + [System.Net.WebUtility]::HtmlEncode($lbl) + '"><div class="fnum">' + $g.Count + '</div><div class="flbl">' + (E $lbl) + '</div></button>')
    }
    [void]$cards.Append('</div>')

    $sb = New-Object System.Text.StringBuilder
    foreach ($f in $ordered) {
        $cls = switch ($f.Sev) { 'high' { 'badge-high' } 'warn' { 'badge-warn' } default { 'badge-info' } }
        $locCell = if ($f.TargetId) {
            '<a class="xref finding-jump" href="#' + $f.TargetId + '">' + (E $f.Where) + '</a>'
        }
        else {
            E $f.Where
        }
        [void]$sb.Append('<tr data-sev="' + $f.Sev + '" data-label="' + [System.Net.WebUtility]::HtmlEncode($f.Label) + '">')
        [void]$sb.Append('<td><span class="badge ' + $cls + '">' + (E $f.Label) + '</span></td>')
        [void]$sb.Append('<td>' + $locCell + '</td>')
        [void]$sb.Append('<td>' + (E $f.Detail) + '</td>')
        [void]$sb.Append('</tr>')
    }
    return $cards.ToString() + (Tbl @('Flag','Location','Detail') $sb.ToString() 'findings-table filterable-table')
}

# ==================================================================================
#  CSS / JS (single-quoted here-strings: no interpolation, pure ASCII)
# ==================================================================================

$script:ReportCss = @'
:root{
  --bg:#f4f6f9; --panel:#ffffff; --panel-alt:#fbfcfe; --ink:#1f2933; --muted:#5a6573; --line:#dce3ec;
  --brand:#1e3f75; --brand2:#2b5ea8; --accent:#3b82f6; --row-alt:#f7f9fc; --row-hover:#eef3fb;
  --kv-bg:#eef2f8; --code-bg:#f0f3f8;
  --high:#c0392b; --high-bg:#fdecea; --high-bd:#f0b4ac;
  --warn:#9a5d05; --warn-bg:#fef6e7; --warn-bd:#f0d9a8;
  --ok:#167a41; --ok-bg:#e8f6ee; --ok-bd:#b7e0c6;
  --info:#20549b; --info-bg:#e8eef8; --info-bd:#b6c8e8;
  --mutedb:#4a5462; --muted-bg:#eceff3; --muted-bd:#d6dce4;
}
:root[data-theme="dark"]{
  --bg:#0f1722; --panel:#16202e; --panel-alt:#1b2738; --ink:#e6edf5; --muted:#9aa8ba; --line:#29374b;
  --brand:#132a4f; --brand2:#5b94eb; --accent:#60a5fa; --row-alt:#192536; --row-hover:#203047;
  --kv-bg:#1c293b; --code-bg:#1e2c3f;
  --high:#f87171; --high-bg:#381a1c; --high-bd:#6e2a2e;
  --warn:#fbbf24; --warn-bg:#362812; --warn-bd:#6b4e1b;
  --ok:#4ade80; --ok-bg:#123121; --ok-bd:#215b3b;
  --info:#60a5fa; --info-bg:#152842; --info-bd:#284a78;
  --mutedb:#b4c0cf; --muted-bg:#212f42; --muted-bd:#33455e;
}
*{box-sizing:border-box}
html{scroll-behavior:smooth}
body{margin:0;font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif;
  background:var(--bg);color:var(--ink);font-size:14px;line-height:1.5}
a{color:var(--brand2);text-decoration:none}
a:hover{text-decoration:underline}
:focus-visible{outline:2px solid var(--accent);outline-offset:2px}
.sr-only{position:absolute;width:1px;height:1px;padding:0;margin:-1px;overflow:hidden;clip:rect(0,0,0,0);border:0}
.skip-link{position:fixed;top:-40px;left:8px;z-index:100;background:var(--brand);color:#fff;padding:8px 12px;border-radius:6px;font-size:13px}
.skip-link:focus{top:8px}

/* Sidebar */
.sidebar{position:fixed;top:0;left:0;width:268px;height:100vh;overflow-y:auto;background:var(--brand);
  color:#dce6f5;padding:18px 0 24px;border-right:1px solid #163259}
.sidebar .brand{font-size:15px;font-weight:700;color:#fff;padding:0 18px 12px;letter-spacing:.3px}
.sidebar .brand small{display:block;font-weight:400;font-size:11px;color:#b8cde8;margin-top:3px;word-break:break-all}
.sidebar .navfilter{margin:0 16px 10px;width:calc(100% - 32px);padding:7px 10px;border-radius:6px;border:1px solid #2b5089;
  background:#163259;color:#fff;font-size:12px}
.sidebar .navfilter::placeholder{color:#a8bfe0}
.sidebar nav a{display:flex;align-items:center;justify-content:space-between;gap:8px;padding:7px 18px;color:#d0def2;
  font-size:13px;border-left:3px solid transparent}
.sidebar nav a:hover{background:#1a3868;text-decoration:none;color:#fff}
.sidebar nav a.active{background:#15315c;border-left-color:var(--accent);color:#fff;font-weight:600}
.sidebar nav a.nav-empty{opacity:.6}
.sidebar nav a .nav-cnt{font-size:11px;padding:1px 6px;border-radius:10px;background:rgba(255,255,255,.12);color:#d7e5f8}
.sidebar .navtools{padding:4px 16px 10px;display:grid;grid-template-columns:1fr 1fr;gap:6px}
.sidebar .navtools button{padding:6px 8px;border:1px solid #2b5089;background:#163259;color:#e4eefb;
  border-radius:6px;cursor:pointer;font-size:12px}
.sidebar .navtools button:hover{background:#1e447e}

/* Main */
.main{margin-left:268px;padding:24px 32px 80px;max-width:1360px}

/* Global search bar */
.search-bar{display:flex;align-items:center;gap:10px;background:var(--panel);border:1px solid var(--line);
  border-radius:10px;padding:10px 14px;margin-bottom:20px}
.search-bar input{flex:1;border:none;background:transparent;color:var(--ink);font-size:13px;outline:none}
.search-bar .search-status{font-size:12px;color:var(--muted);white-space:nowrap}
.search-bar button{padding:4px 10px;border:1px solid var(--line);background:var(--panel-alt);color:var(--ink);
  border-radius:6px;cursor:pointer;font-size:12px}
.search-bar button:hover{background:var(--row-hover)}

/* Cover */
.cover{background:linear-gradient(135deg,#1e3f75,#2b5ea8);color:#fff;border-radius:14px;
  padding:28px 32px;margin-bottom:20px;box-shadow:0 6px 20px rgba(30,63,117,.18)}
.cover .cover-top{display:flex;align-items:center;gap:20px}
.cover-logo{max-height:64px;max-width:200px;background:#fff;border-radius:8px;padding:6px}
.cover h1{margin:0;font-size:25px;font-weight:700}
.cover .sub{color:#dbe8fa;font-size:13px;margin-top:4px}
.cover .meta{display:flex;flex-wrap:wrap;gap:26px;margin-top:18px}
.cover .meta div span{display:block;font-size:11px;text-transform:uppercase;letter-spacing:.6px;color:#d0e2fb}
.cover .meta div strong{font-size:14px;font-weight:600}

/* Stat cards */
.cards{display:flex;flex-wrap:wrap;gap:12px;margin-bottom:20px}
.card{background:var(--panel);border:1px solid var(--line);border-radius:10px;padding:13px 16px;min-width:118px;flex:1}
.card .n{font-size:23px;font-weight:700;color:var(--brand2)}
.card .n.sev-high{color:var(--high)}
.card .n.sev-warn{color:var(--warn)}
.card .n.sev-info{color:var(--info)}
.card .n.sev-ok{color:var(--ok)}
.card .l{font-size:11px;color:var(--muted);text-transform:uppercase;letter-spacing:.4px;margin-top:2px}

/* Sections */
.report-section{background:var(--panel);border:1px solid var(--line);border-radius:10px;margin-bottom:18px}
.section-heading{margin:0}
.section-header{width:100%;text-align:left;border:none;cursor:pointer;margin:0;padding:14px 18px;font-size:16px;
  font-weight:600;color:var(--ink);background:var(--panel-alt);border-bottom:1px solid var(--line);
  border-radius:10px 10px 0 0;display:flex;align-items:center;gap:10px;font-family:inherit}
.section-header:hover{background:var(--row-hover)}
.report-section.collapsed .section-header{border-bottom:none;border-radius:10px}
.toggle-icon{display:inline-block;transition:transform .15s;font-size:13px;color:var(--muted)}
.report-section.collapsed .toggle-icon{transform:rotate(-90deg)}
.report-section.collapsed .section-body{display:none}
.sh-title{flex:0 0 auto}
.section-body{padding:16px 18px}
.section-summary{margin:0 0 12px;color:var(--muted);font-size:13px;font-style:italic}
.section-controls{display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:10px;margin-bottom:8px}
.toggle-check{font-size:12px;color:var(--muted);display:inline-flex;align-items:center;gap:6px;cursor:pointer;user-select:none}
.report-section h3{font-size:14px;color:var(--brand2);margin:18px 0 8px;border-bottom:1px dashed var(--line);padding-bottom:5px}
.report-section h3:first-of-type{margin-top:2px}
.iface-head{font-size:14px}
.iface-head .count{color:var(--muted);font-weight:400;font-size:12px}
.subtitle{font-size:12px;color:var(--muted);margin:14px 0 6px;font-weight:600;text-transform:uppercase;letter-spacing:.4px}

/* Tables */
.table-wrap{overflow-x:auto;max-height:72vh;overflow-y:auto;border:1px solid var(--line);border-radius:8px;margin-bottom:10px}
table{border-collapse:collapse;width:100%;font-size:13px}
thead th{position:sticky;top:0;background:var(--brand);color:#fff;text-align:left;padding:8px 10px;font-weight:600;
  white-space:nowrap;z-index:2}
tbody td{padding:7px 10px;border-top:1px solid var(--line);vertical-align:top}
tbody tr:nth-child(even){background:var(--row-alt)}
tbody tr:hover{background:var(--row-hover)}
table.kv th{position:static;background:var(--kv-bg);color:var(--ink);width:240px;font-weight:600;border-top:1px solid var(--line);text-align:left;padding:8px 10px}
table.kv td{border-top:1px solid var(--line);padding:8px 10px}
.wrapcell{max-width:360px;word-break:break-word}
.flagcell{margin-top:4px;display:flex;flex-wrap:wrap;gap:4px}
.mono{font-family:ui-monospace,SFMono-Regular,Menlo,Monaco,Consolas,"Liberation Mono",monospace;font-size:12px;
  background:var(--code-bg);padding:1px 4px;border-radius:4px}
a.xref{border-bottom:1px dotted var(--brand2)}
a.xref:hover{text-decoration:none;border-bottom-style:solid}

/* Secret reveal */
.secret-wrap{display:inline-flex;align-items:center;gap:6px;flex-wrap:wrap}
.secret-val.is-masked{filter:blur(5px);user-select:none}
.secret-btn{font-size:11px;padding:1px 7px;border-radius:5px;border:1px solid var(--line);background:var(--panel-alt);
  color:var(--ink);cursor:pointer}
.secret-btn:hover{background:var(--row-hover)}

/* States */
.row-disabled{opacity:.62}
.row-disabled td{background:var(--panel-alt)}
.row-high td{background:var(--high-bg) !important}
.row-warn td{background:var(--warn-bg) !important}
.row-hidden{display:none !important}
.row-flash td{animation:flashRow 1.8s ease-out}
@keyframes flashRow{0%{outline:2px solid var(--accent);background:var(--info-bg)}100%{outline:none}}
.muted{color:var(--muted)}
.redacted{color:var(--high);font-weight:600;font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;font-size:12px}
.note{font-size:12px;color:var(--muted);margin:6px 0 0}
.not-configured{color:var(--muted);font-style:italic;background:var(--panel-alt);border:1px dashed var(--line);
  padding:10px 14px;border-radius:8px;margin:0}
.all-clear{color:var(--ok);background:var(--ok-bg);border:1px solid var(--ok-bd);padding:12px 16px;border-radius:8px}

/* Badges */
.badge{display:inline-block;padding:1px 7px;border-radius:11px;font-size:11px;font-weight:700;letter-spacing:.3px;
  white-space:nowrap;line-height:1.6}
.badge-high{background:var(--high-bg);color:var(--high);border:1px solid var(--high-bd)}
.badge-warn{background:var(--warn-bg);color:var(--warn);border:1px solid var(--warn-bd)}
.badge-ok{background:var(--ok-bg);color:var(--ok);border:1px solid var(--ok-bd)}
.badge-info{background:var(--info-bg);color:var(--info);border:1px solid var(--info-bd)}
.badge-muted{background:var(--muted-bg);color:var(--mutedb);border:1px solid var(--muted-bd)}

/* Findings cards */
.finding-cards{display:flex;flex-wrap:wrap;gap:10px;margin-bottom:14px}
.fcard{border-radius:10px;padding:10px 14px;min-width:118px;border:1px solid var(--line);background:var(--panel-alt);
  text-align:left;cursor:pointer;font-family:inherit;color:var(--ink)}
.fcard:hover{filter:brightness(.97)}
.fcard.is-active{box-shadow:0 0 0 2px var(--accent)}
.fcard-high{background:var(--high-bg);border-color:var(--high-bd)}
.fcard-warn{background:var(--warn-bg);border-color:var(--warn-bd)}
.fcard-info{background:var(--info-bg);border-color:var(--info-bd)}
.fcard .fnum{font-size:21px;font-weight:700}
.fcard-high .fnum{color:var(--high)} .fcard-warn .fnum{color:var(--warn)} .fcard-info .fnum{color:var(--info)}
.fcard .flbl{font-size:11px;font-weight:600;text-transform:uppercase;letter-spacing:.3px;margin-top:2px}

/* Banners */
.warn-banner{background:var(--warn-bg);border:1px solid var(--warn-bd);color:var(--warn);padding:12px 16px;border-radius:10px;
  margin-bottom:16px;font-size:13px}
.warn-banner strong{color:var(--warn)}

.footer{margin-top:28px;color:var(--muted);font-size:11px;text-align:center}

@media (max-width:940px){
  .sidebar{position:static;width:auto;height:auto;max-height:280px;border-right:none;border-bottom:1px solid #163259}
  .main{margin-left:0;padding:16px}
  .cards .card{min-width:96px}
}

@page{size:landscape;margin:12mm}
@media print{
  :root,:root[data-theme="dark"]{
    --bg:#fff; --panel:#fff; --panel-alt:#fff; --ink:#000; --muted:#444; --line:#bbb;
    --brand:#1e3f75; --brand2:#1e3f75; --row-alt:#f5f7fa; --kv-bg:#eef2f8; --code-bg:transparent;
    --high:#b02a1d; --high-bg:#fdecea; --warn:#8a5200; --warn-bg:#fef6e7;
    --ok:#167a41; --ok-bg:#e8f6ee; --info:#20549b; --info-bg:#e8eef8;
  }
  body{background:#fff;font-size:10px;color:#000}
  .sidebar,.search-bar,.section-controls .toggle-check,.secret-btn,.skip-link{display:none !important}
  .main{margin-left:0 !important;max-width:none;padding:0}
  .cover{background:#1e3f75 !important;-webkit-print-color-adjust:exact;print-color-adjust:exact;color:#fff;box-shadow:none}
  .report-section{break-before:auto;border:1px solid #ccc;box-shadow:none;margin-bottom:12px}
  .report-section.section-empty{break-inside:avoid}
  .report-section.collapsed .section-body{display:block !important}
  .toggle-icon{display:none}
  .section-header{cursor:default;padding:8px 12px;font-size:13px}
  .table-wrap{overflow:visible !important;max-height:none !important;border:1px solid #999}
  table{font-size:9.5px;table-layout:auto}
  thead{display:table-header-group}
  thead th{position:static;white-space:normal}
  tbody td{overflow-wrap:anywhere;padding:4px 6px}
  tr,.fcard,.card{break-inside:avoid;page-break-inside:avoid}
  .badge,.fcard,thead th{-webkit-print-color-adjust:exact;print-color-adjust:exact}
  a{color:#000;border-bottom:none !important}
}
'@

$script:ReportJs = @'
(function(){
  "use strict";
  function setSectionCollapsed(sec, collapsed){
    if(!sec){ return; }
    sec.classList.toggle("collapsed", collapsed);
    var btn = sec.querySelector(".section-header");
    if(btn){ btn.setAttribute("aria-expanded", collapsed ? "false" : "true"); }
  }
  function setAll(collapsed){
    var secs = document.querySelectorAll(".report-section");
    for(var i = 0; i < secs.length; i++){ setSectionCollapsed(secs[i], collapsed); }
  }
  function openAndJump(targetId){
    if(!targetId){ return; }
    var el = document.getElementById(targetId);
    if(!el){ return; }
    var sec = el.classList.contains("report-section") ? el : el.closest(".report-section");
    if(sec){ setSectionCollapsed(sec, false); }
    el.scrollIntoView({ behavior: "smooth", block: "center" });
    el.classList.remove("row-flash");
    void el.offsetWidth;
    el.classList.add("row-flash");
  }

  document.addEventListener("DOMContentLoaded", function(){
    // Section collapse/expand
    var headers = document.querySelectorAll(".section-header");
    for(var i = 0; i < headers.length; i++){
      headers[i].addEventListener("click", function(){
        var sec = this.closest(".report-section");
        setSectionCollapsed(sec, !sec.classList.contains("collapsed"));
      });
    }

    // Sidebar tool buttons
    var btnExp = document.getElementById("btn-expand-all");
    if(btnExp){ btnExp.addEventListener("click", function(){ setAll(false); }); }
    var btnCol = document.getElementById("btn-collapse-all");
    if(btnCol){ btnCol.addEventListener("click", function(){ setAll(true); }); }
    var btnPrt = document.getElementById("btn-print");
    if(btnPrt){ btnPrt.addEventListener("click", function(){ window.print(); }); }
    var btnTheme = document.getElementById("btn-theme");
    if(btnTheme){
      var rootEl = document.documentElement;
      if(window.matchMedia && window.matchMedia("(prefers-color-scheme: dark)").matches){
        rootEl.setAttribute("data-theme", "dark");
        btnTheme.textContent = "Light theme";
      }
      btnTheme.addEventListener("click", function(){
        var isDark = rootEl.getAttribute("data-theme") === "dark";
        if(isDark){ rootEl.removeAttribute("data-theme"); this.textContent = "Dark theme"; }
        else { rootEl.setAttribute("data-theme", "dark"); this.textContent = "Light theme"; }
      });
    }

    // Secret click-to-reveal buttons
    var sBtns = document.querySelectorAll(".secret-btn");
    for(var s = 0; s < sBtns.length; s++){
      sBtns[s].addEventListener("click", function(){
        var val = this.previousElementSibling;
        if(!val){ return; }
        var masked = val.classList.toggle("is-masked");
        this.textContent = masked ? "Show" : "Hide";
      });
    }

    // Hide-disabled toggles
    var hdToggles = document.querySelectorAll(".hide-disabled-toggle");
    for(var d = 0; d < hdToggles.length; d++){
      hdToggles[d].addEventListener("change", function(){
        var sec = document.getElementById(this.getAttribute("data-target"));
        if(!sec){ return; }
        var rows = sec.querySelectorAll('tr[data-disabled="1"]');
        for(var r = 0; r < rows.length; r++){
          rows[r].classList.toggle("row-hidden", this.checked);
        }
      });
    }

    // Findings card filter
    var fCards = document.querySelectorAll(".finding-cards .fcard");
    var fRows  = document.querySelectorAll(".findings-table tbody tr");
    for(var c = 0; c < fCards.length; c++){
      fCards[c].addEventListener("click", function(){
        for(var j = 0; j < fCards.length; j++){ fCards[j].classList.remove("is-active"); }
        this.classList.add("is-active");
        var wantSev = this.getAttribute("data-sev");
        var wantLbl = this.getAttribute("data-label");
        for(var r = 0; r < fRows.length; r++){
          var ok = (wantSev === "all") || (fRows[r].getAttribute("data-sev") === wantSev && fRows[r].getAttribute("data-label") === wantLbl);
          fRows[r].classList.toggle("row-hidden", !ok);
        }
      });
    }

    // Auto-expand collapsed sections on sidebar/cross-link clicks
    var xLinks = document.querySelectorAll('.sidebar nav a[href^="#"], a.xref[href^="#"]');
    for(var x = 0; x < xLinks.length; x++){
      xLinks[x].addEventListener("click", function(ev){
        var href = this.getAttribute("href");
        if(href && href.length > 1){
          ev.preventDefault();
          openAndJump(href.substring(1));
        }
      });
    }

    // Sidebar section filter
    var navLinks = [].slice.call(document.querySelectorAll(".sidebar nav a"));
    var nf = document.getElementById("navfilter");
    if(nf){
      nf.addEventListener("input", function(){
        var q = this.value.toLowerCase();
        for(var i = 0; i < navLinks.length; i++){
          navLinks[i].style.display = navLinks[i].textContent.toLowerCase().indexOf(q) > -1 ? "" : "none";
        }
      });
    }

    // Global table row search
    var gInput  = document.getElementById("global-search");
    var gStatus = document.getElementById("global-search-status");
    var gClear  = document.getElementById("global-search-clear");
    var allRows = [].slice.call(document.querySelectorAll("table.filterable-table tbody tr"));
    function runSearch(){
      if(!gInput){ return; }
      var q = gInput.value.trim().toLowerCase();
      var shown = 0;
      for(var i = 0; i < allRows.length; i++){
        if(!q){
          allRows[i].classList.remove("row-hidden");
          shown++;
        }
        else {
          var match = allRows[i].textContent.toLowerCase().indexOf(q) > -1;
          allRows[i].classList.toggle("row-hidden", !match);
          if(match){ shown++; }
        }
      }
      if(gStatus){ gStatus.textContent = q ? (shown + " matching row" + (shown === 1 ? "" : "s")) : ""; }
    }
    if(gInput){ gInput.addEventListener("input", runSearch); }
    if(gClear){ gClear.addEventListener("click", function(){ if(gInput){ gInput.value = ""; runSearch(); gInput.focus(); } }); }

    // Scroll-spy with rAF + passive listener + bottom-of-page handling
    var secs = [];
    for(var k = 0; k < navLinks.length; k++){
      var el = document.querySelector(navLinks[k].getAttribute("href"));
      if(el){ secs.push(el); }
    }
    var ticking = false;
    function updateActiveNav(){
      ticking = false;
      var pos = window.pageYOffset + 130;
      var atBottom = (window.innerHeight + window.pageYOffset) >= (document.documentElement.scrollHeight - 20);
      var cur = null;
      if(atBottom && secs.length > 0){ cur = secs[secs.length - 1]; }
      else {
        for(var i = 0; i < secs.length; i++){ if(secs[i].offsetTop <= pos){ cur = secs[i]; } }
      }
      for(var j = 0; j < navLinks.length; j++){
        var on = cur && navLinks[j].getAttribute("href") === ("#" + cur.id);
        navLinks[j].classList.toggle("active", !!on);
      }
    }
    window.addEventListener("scroll", function(){
      if(!ticking){ ticking = true; window.requestAnimationFrame(updateActiveNav); }
    }, { passive: true });
    updateActiveNav();
  });

  window.addEventListener("beforeprint", function(){ setAll(false); });
})();
'@

# ==================================================================================
#  MAIN ENTRYPOINT
# ==================================================================================

function Invoke-PfSenseReport {
    param(
        [string]$ConfigPathValue,
        [string]$OutputPathValue,
        [bool]$RedactValue,
        [string]$TitleValue,
        [string]$LogoPathValue,
        [string[]]$WanInterfacesValue,
        [string[]]$InternalInterfacesValue,
        [int]$ExpiryWarnDaysValue,
        [string]$JsonPathValue,
        [bool]$QuietValue
    )

    Initialize-ReportContext -RedactMode $RedactValue -ExpiryWarnDaysValue $ExpiryWarnDaysValue

    if ([string]::IsNullOrWhiteSpace($ConfigPathValue)) {
        throw "ConfigPath is required. Example: .\pfsense_report.ps1 -ConfigPath config.xml"
    }

    # ---- Load and validate XML -----------------------------------------------
    $resolvedConfig = Resolve-FullPath $ConfigPathValue
    $xml = Read-PfSenseXml $ConfigPathValue
    $root = $xml.DocumentElement
    if ($null -eq $root -or $root.Name -ne 'pfsense') {
        throw "This does not appear to be a pfSense configuration (missing <pfsense> root element)."
    }

    # ---- Default output path -------------------------------------------------
    if ([string]::IsNullOrWhiteSpace($OutputPathValue)) {
        $base = [System.IO.Path]::GetFileNameWithoutExtension($resolvedConfig)
        $OutputPathValue = Join-Path (Get-Location).Path ($base + '-report.html')
    }
    $resolvedOutput = Resolve-FullPath $OutputPathValue

    # ---- Gather metadata -----------------------------------------------------
    $sysNode  = $root.SelectSingleNode('system')
    $hostname = XText $sysNode 'hostname'
    $domain   = XText $sysNode 'domain'
    $version  = XText $root 'version'
    $script:RedactHost   = $hostname
    $script:RedactDomain = $domain

    # ---- Build lookup maps ---------------------------------------------------
    Build-LookupMaps -root $root -ForceWan $WanInterfacesValue -ForceInternal $InternalInterfacesValue

    # ---- Build sections (risk-bearing sections first to populate findings) ---
    $sysHtml      = Build-System           $root
    $ifHtml       = Build-Interfaces       $root
    $ifGrpHtml    = Build-IfGroupsAndL2    $root
    $vlanHtml     = Build-Vlans            $root
    $vipHtml      = Build-VirtualIps       $root
    $gwHtml       = Build-Gateways         $root
    $routeHtml    = Build-Routes           $root
    $fwHtml       = Build-Firewall         $root
    $natHtml      = Build-Nat              $root
    $ipsecHtml    = Build-Ipsec            $root
    $ovpnHtml     = Build-OpenVpn          $root
    $wgHtml       = Build-WireGuard        $root
    $haHtml       = Build-HighAvailability $root
    $dhcpHtml     = Build-Dhcp             $root
    $dnsHtml      = Build-Dns              $root
    $certHtml     = Build-Certs            $root
    $userHtml     = Build-Users            $root
    $aliasHtml    = Build-Aliases          $root
    $svcHtml      = Build-Services         $root
    $pkgHtml      = Build-Packages         $root
    $revHtml      = Build-Revision         $root
    $findHtml     = Build-Findings

    # ---- Counts for cover & sidebar ------------------------------------------
    $ifsNode = $root.SelectSingleNode('interfaces')
    $cIf     = (XNodes $ifsNode '*').Count
    $cVlan   = (XNodes $root 'vlans/vlan').Count
    $cVip    = (XNodes $root 'virtualip/vip').Count
    $cGw     = (XNodes $root 'gateways/gateway_item').Count + (XNodes $root 'gateways/gateway_group').Count
    $cRoute  = (XNodes $root 'staticroutes/route').Count
    $cFw     = (XNodes $root 'filter/rule').Count
    $cPf     = (XNodes $root 'nat/rule').Count
    $cNat    = $cPf + (XNodes $root 'nat/outbound/rule').Count + (XNodes $root 'nat/onetoone').Count
    $cP1     = (XNodes $root 'ipsec/phase1').Count
    $cOv     = (XNodes $root 'openvpn/openvpn-server').Count + (XNodes $root 'openvpn/openvpn-client').Count
    $cWg     = (XNodes $root 'installedpackages/wireguard/tunnels/item').Count + (XNodes $root 'wireguard/tunnels/item').Count
    $cCert   = (XNodes $root 'cert').Count + (XNodes $root 'ca').Count
    $cUser   = (XNodes $root 'system/user').Count
    $cAlias  = (XNodes $root 'aliases/alias').Count
    $cPkg    = (XNodes $root 'installedpackages/package').Count
    $cFind   = $script:Findings.Count
    $highCount = @($script:Findings | Where-Object { $_.Sev -eq 'high' }).Count
    $warnCount = @($script:Findings | Where-Object { $_.Sev -eq 'warn' }).Count
    $infoCount = @($script:Findings | Where-Object { $_.Sev -eq 'info' }).Count

    # ---- Assemble sections ---------------------------------------------------
    $sectionDefs = @(
        @{ Id='findings';   Nav='Security Findings';        Title='Security Findings';        Summary='Heuristic risk flags raised while parsing this configuration.'; Body=$findHtml; Count=$cFind },
        @{ Id='system';     Nav='System Overview';          Title='System Overview';          Summary='Core system services: DNS, NTP, time zone, WebGUI security, SSH and console protection.'; Body=$sysHtml; Count=$null },
        @{ Id='interfaces'; Nav='Interfaces';               Title='Interfaces';               Summary='Every configured interface and its addressing, VLAN and filtering options.'; Body=$ifHtml; Count=$cIf },
        @{ Id='ifgroups';   Nav='Groups / LAGGs / Bridges'; Title='Interface Groups, LAGGs &amp; Bridges'; Summary='Logical interface groups, link aggregations (LAGG), and Layer-2 bridges.'; Body=$ifGrpHtml; Count=$null },
        @{ Id='vlans';      Nav='VLANs';                    Title='VLANs';                    Summary='IEEE 802.1Q VLANs defined on physical interfaces.'; Body=$vlanHtml; Count=$cVlan },
        @{ Id='vips';       Nav='Virtual IPs';              Title='Virtual IPs';              Summary='CARP, IP Alias, Proxy ARP and other virtual IP addresses.'; Body=$vipHtml; Count=$cVip },
        @{ Id='gateways';   Nav='Gateways';                 Title='Gateways &amp; Groups';    Summary='Upstream gateways, default route selections, and multi-WAN gateway groups.'; Body=$gwHtml; Count=$cGw },
        @{ Id='routes';     Nav='Static Routes';            Title='Static Routes';            Summary='Manually configured static routes to remote networks.'; Body=$routeHtml; Count=$cRoute },
        @{ Id='firewall';   Nav='Firewall Rules';           Title='Firewall Rules';           Summary='Packet-filter rules grouped by interface (floating first), with risk flags highlighted.'; Body=$fwHtml; Count=$cFw },
        @{ Id='nat';        Nav='NAT';                      Title='NAT';                      Summary='Outbound NAT mode and rules, port forwards, and 1:1 NAT mappings.'; Body=$natHtml; Count=$cNat },
        @{ Id='ipsec';      Nav='VPN - IPsec';              Title='VPN &mdash; IPsec';        Summary='IPsec tunnels: Phase 1 (IKE) peers and Phase 2 (child SA) tunnel networks.'; Body=$ipsecHtml; Count=$cP1 },
        @{ Id='openvpn';    Nav='VPN - OpenVPN';            Title='VPN &mdash; OpenVPN';      Summary='OpenVPN server and client instances and their cryptographic settings.'; Body=$ovpnHtml; Count=$cOv },
        @{ Id='wireguard';  Nav='VPN - WireGuard';          Title='VPN &mdash; WireGuard';    Summary='WireGuard tunnels and peers. Private and preshared keys are never exported.'; Body=$wgHtml; Count=$cWg },
        @{ Id='ha';         Nav='High Availability';        Title='High Availability (CARP / Sync)'; Summary='pfsync state synchronization and XMLRPC configuration sync settings.'; Body=$haHtml; Count=$null },
        @{ Id='dhcp';       Nav='DHCP Servers';             Title='DHCP Servers &amp; Relay'; Summary='Per-interface DHCPv4/DHCPv6 scopes, pools, static reservations, and relay settings.'; Body=$dhcpHtml; Count=$null },
        @{ Id='dns';        Nav='DNS Resolver / Forwarder'; Title='DNS Resolver / Forwarder'; Summary='Unbound resolver and dnsmasq forwarder settings and overrides.'; Body=$dnsHtml; Count=$null },
        @{ Id='certs';      Nav='Certificates & CAs';       Title='Certificates, CAs &amp; CRLs'; Summary='Certificate authorities, certificates, and CRLs with expiry, key/signature analysis, and usage context.'; Body=$certHtml; Count=$cCert },
        @{ Id='users';      Nav='Users & Groups';           Title='Users, Groups &amp; Auth'; Summary='Local user accounts, groups, and external LDAP/RADIUS servers. Hashes and secrets are never exported.'; Body=$userHtml; Count=$cUser },
        @{ Id='aliases';    Nav='Aliases';                  Title='Aliases';                  Summary='Reusable host, network, port and URL aliases referenced by rules.'; Body=$aliasHtml; Count=$cAlias },
        @{ Id='services';   Nav='Services (SNMP / Syslog)'; Title='System Services';          Summary='SNMP, remote Syslog, Dynamic DNS, and firewall schedules.'; Body=$svcHtml; Count=$null },
        @{ Id='packages';   Nav='Installed Packages';       Title='Installed Packages';       Summary='Add-on packages installed on this firewall.'; Body=$pkgHtml; Count=$cPkg },
        @{ Id='revision';   Nav='Revision / Notes';         Title='Revision / Notes';         Summary='Metadata about the most recent configuration change.'; Body=$revHtml; Count=$null }
    )

    $sectionsSb = New-Object System.Text.StringBuilder
    $navSb      = New-Object System.Text.StringBuilder
    foreach ($sd in $sectionDefs) {
        [void]$sectionsSb.Append((Wrap-Section $sd.Id $sd.Title $sd.Summary $sd.Body))
        $emptyCls = if ([string]::IsNullOrWhiteSpace($sd.Body)) { ' class="nav-empty"' } else { '' }
        $cntBadge = if ($null -ne $sd.Count -and $sd.Count -gt 0) { '<span class="nav-cnt">' + $sd.Count + '</span>' } else { '' }
        [void]$navSb.Append('<a href="#' + $sd.Id + '"' + $emptyCls + '><span>' + [System.Net.WebUtility]::HtmlEncode($sd.Nav) + '</span>' + $cntBadge + '</a>')
    }

    # ---- Banners (Version & Plaintext Secrets) -------------------------------
    $banners = New-Object System.Text.StringBuilder
    $verMajor = 0.0
    $verOk = [double]::TryParse($version, [System.Globalization.NumberStyles]::Float, [System.Globalization.CultureInfo]::InvariantCulture, [ref]$verMajor)
    if (-not $version) {
        [void]$banners.Append('<div class="warn-banner"><strong>Warning:</strong> No pfSense configuration version was found in this file. The report may be incomplete or this may not be a standard pfSense backup.</div>')
    }
    elseif (-not $verOk -or $verMajor -lt 15.0 -or $verMajor -gt 30.0) {
        [void]$banners.Append('<div class="warn-banner"><strong>Warning:</strong> Configuration version &quot;' + (E $version) + '&quot; is outside the validated range (pfSense config versions 15.x&ndash;30.x). Some sections may not parse as expected.</div>')
    }
    if ($script:HasPlaintextSecret -and -not $script:IsRedacted) {
        [void]$banners.Append('<div class="warn-banner"><strong>Confidentiality Notice:</strong> This report contains unredacted secrets (such as IPsec pre-shared keys or SNMP communities, hidden behind click-to-reveal). Treat this file as sensitive, or re-run with <code class="mono">-Redact</code> before sharing externally.</div>')
    }

    # ---- Stat cards ----------------------------------------------------------
    $riskCls = if ($highCount -gt 0) { 'sev-high' } elseif ($warnCount -gt 0) { 'sev-warn' } elseif ($infoCount -gt 0) { 'sev-info' } else { 'sev-ok' }
    $cardsSb = New-Object System.Text.StringBuilder
    [void]$cardsSb.Append('<div class="cards">')
    [void]$cardsSb.Append('<div class="card"><div class="n">' + $cIf + '</div><div class="l">Interfaces</div></div>')
    [void]$cardsSb.Append('<div class="card"><div class="n">' + $cFw + '</div><div class="l">Firewall rules</div></div>')
    [void]$cardsSb.Append('<div class="card"><div class="n">' + $cPf + '</div><div class="l">Port forwards</div></div>')
    [void]$cardsSb.Append('<div class="card"><div class="n">' + $cP1 + '</div><div class="l">IPsec tunnels</div></div>')
    [void]$cardsSb.Append('<div class="card"><div class="n">' + $cOv + '</div><div class="l">OpenVPN</div></div>')
    if ($cWg -gt 0) {
        [void]$cardsSb.Append('<div class="card"><div class="n">' + $cWg + '</div><div class="l">WireGuard</div></div>')
    }
    [void]$cardsSb.Append('<div class="card"><div class="n">' + $cCert + '</div><div class="l">Certs / CAs</div></div>')
    [void]$cardsSb.Append('<div class="card"><div class="n ' + $riskCls + '">' + $cFind + '</div><div class="l">Risk flags</div></div>')
    [void]$cardsSb.Append('</div>')

    # ---- Cover ---------------------------------------------------------------
    $logoTag = Get-LogoTag $LogoPathValue
    $genTime = $script:Now.ToString('yyyy-MM-dd HH:mm:ss zzz')
    $hostDisp = if ($script:IsRedacted) {
        if ($hostname) { Get-RedactToken $hostname.ToLowerInvariant() 'HOST' } else { 'unknown' }
    } else {
        if ($hostname) { $hostname } else { 'unknown' }
    }
    $domDisp = if ($script:IsRedacted) {
        if ($domain) { Get-RedactToken $domain.ToLowerInvariant() 'DOMAIN' } else { '' }
    } else {
        if ($domain) { $domain } else { '' }
    }
    $fqdn = if ($domDisp) { $hostDisp + '.' + $domDisp } else { $hostDisp }

    $cover = '<div class="cover"><div class="cover-top">' + $logoTag +
             '<div><h1>' + (E $TitleValue) + '</h1><div class="sub">Generated by pfsense_report.ps1 v' + $script:ToolVersion + $(if ($script:IsRedacted) { ' &mdash; REDACTED COPY' } else { '' }) + '</div></div></div>' +
             '<div class="meta">' +
             '<div><span>Hostname</span><strong>' + [System.Net.WebUtility]::HtmlEncode($fqdn) + '</strong></div>' +
             '<div><span>pfSense config version</span><strong>' + $(if ($version) { [System.Net.WebUtility]::HtmlEncode($version) } else { 'unknown' }) + '</strong></div>' +
             '<div><span>Report generated</span><strong>' + [System.Net.WebUtility]::HtmlEncode($genTime) + '</strong></div>' +
             '<div><span>Source file</span><strong>' + $(if ($script:IsRedacted) { '[redacted]' } else { [System.Net.WebUtility]::HtmlEncode([System.IO.Path]::GetFileName($resolvedConfig)) }) + '</strong></div>' +
             '</div></div>'

    # ---- Sidebar & Search Bar ------------------------------------------------
    $sidebarBrand = if ($script:IsRedacted) {
        if ($hostname) { [System.Net.WebUtility]::HtmlEncode((Get-RedactToken $hostname.ToLowerInvariant() 'HOST')) } else { '' }
    } else {
        [System.Net.WebUtility]::HtmlEncode($hostname)
    }
    $sidebar = '<aside class="sidebar"><div class="brand">pfSense Report<small>' + $sidebarBrand + '</small></div>' +
               '<label for="navfilter" class="sr-only">Filter sections</label>' +
               '<input id="navfilter" class="navfilter" type="search" placeholder="Filter sections..." aria-label="Filter sections" />' +
               '<div class="navtools">' +
               '<button type="button" id="btn-expand-all">Expand all</button>' +
               '<button type="button" id="btn-collapse-all">Collapse all</button>' +
               '<button type="button" id="btn-print">Print / PDF</button>' +
               '<button type="button" id="btn-theme">Dark theme</button>' +
               '</div><nav aria-label="Report sections">' + $navSb.ToString() + '</nav></aside>'

    $searchBar = '<div class="search-bar"><label for="global-search" class="sr-only">Search report tables</label>' +
                 '<input id="global-search" type="search" placeholder="Search rules, IPs, ports, aliases, hosts, packages..." aria-label="Search report tables" />' +
                 '<span id="global-search-status" class="search-status" aria-live="polite"></span>' +
                 '<button type="button" id="global-search-clear">Clear</button></div>'

    $footer = '<div class="footer">Generated locally by pfsense_report.ps1 v' + $script:ToolVersion + ' &mdash; no data left this machine. Heuristic risk flags are informational and do not replace a manual security review.</div>'

    # ---- Final HTML document -------------------------------------------------
    $csp = "default-src 'none'; img-src data:; style-src 'unsafe-inline'; script-src 'unsafe-inline';"
    $docSb = New-Object System.Text.StringBuilder
    [void]$docSb.Append('<!DOCTYPE html><html lang="en"><head><meta charset="utf-8">')
    [void]$docSb.Append('<meta name="viewport" content="width=device-width, initial-scale=1">')
    [void]$docSb.Append('<meta name="color-scheme" content="light dark">')
    [void]$docSb.Append('<meta http-equiv="Content-Security-Policy" content="' + $csp + '">')
    [void]$docSb.Append('<title>' + (E $TitleValue) + '</title><style>' + $script:ReportCss + '</style></head><body>')
    [void]$docSb.Append('<a class="skip-link" href="#main-content">Skip to report content</a>')
    [void]$docSb.Append($sidebar)
    [void]$docSb.Append('<main id="main-content" class="main">')
    [void]$docSb.Append($cover).Append($banners.ToString()).Append($cardsSb.ToString()).Append($searchBar).Append($sectionsSb.ToString()).Append($footer)
    [void]$docSb.Append('</main><script>' + $script:ReportJs + '</script></body></html>')

    # ---- Write HTML ----------------------------------------------------------
    $outDir = [System.IO.Path]::GetDirectoryName($resolvedOutput)
    if (-not [string]::IsNullOrWhiteSpace($outDir) -and -not (Test-Path -LiteralPath $outDir)) {
        [void](New-Item -ItemType Directory -Path $outDir -Force)
    }
    $utf8 = New-Object System.Text.UTF8Encoding($false)
    [System.IO.File]::WriteAllText($resolvedOutput, $docSb.ToString(), $utf8)

    # ---- Build structured summary (for -JsonPath / -PassThru) ----------------
    $findingsSummary = @(foreach ($f in $script:Findings) {
        [pscustomobject]@{
            severity = $f.Sev
            label    = $f.Label
            location = if ($script:IsRedacted) { Apply-Redaction $f.Where } else { $f.Where }
            detail   = if ($script:IsRedacted) { Apply-Redaction $f.Detail } else { $f.Detail }
        }
    })
    $summaryObj = [pscustomobject]@{
        toolVersion   = $script:ToolVersion
        generatedAt   = $genTime
        redacted      = $script:IsRedacted
        hostname      = $fqdn
        configVersion = $version
        outputPath    = $resolvedOutput
        counts        = [pscustomobject]@{
            interfaces   = $cIf
            vlans        = $cVlan
            virtualIps   = $cVip
            gateways     = $cGw
            staticRoutes = $cRoute
            firewallRules = $cFw
            portForwards = $cPf
            ipsecTunnels = $cP1
            openVpn      = $cOv
            wireGuard    = $cWg
            certsAndCas  = $cCert
            users        = $cUser
            aliases      = $cAlias
            packages     = $cPkg
            findings     = [pscustomobject]@{
                total = $cFind
                high  = $highCount
                warn  = $warnCount
                info  = $infoCount
            }
        }
        findings      = $findingsSummary
    }

    if (-not [string]::IsNullOrWhiteSpace($JsonPathValue)) {
        $resolvedJson = Resolve-FullPath $JsonPathValue
        $jsonDir = [System.IO.Path]::GetDirectoryName($resolvedJson)
        if (-not [string]::IsNullOrWhiteSpace($jsonDir) -and -not (Test-Path -LiteralPath $jsonDir)) {
            [void](New-Item -ItemType Directory -Path $jsonDir -Force)
        }
        [System.IO.File]::WriteAllText($resolvedJson, ($summaryObj | ConvertTo-Json -Depth 6), $utf8)
    }

    if (-not $QuietValue) {
        Write-Host "pfSense report written to: $resolvedOutput" -ForegroundColor Green
        Write-Host ("{0} sections rendered, {1} risk flag(s) raised ({2} high, {3} warn, {4} info)." -f $sectionDefs.Count, $cFind, $highCount, $warnCount, $infoCount)
    }

    return $summaryObj
}

# Execute only when run directly (not when dot-sourced for unit tests)
if ($MyInvocation.InvocationName -ne '.') {
    try {
        $result = Invoke-PfSenseReport `
            -ConfigPathValue $ConfigPath `
            -OutputPathValue $OutputPath `
            -RedactValue ([bool]$Redact) `
            -TitleValue $Title `
            -LogoPathValue $LogoPath `
            -WanInterfacesValue $WanInterfaces `
            -InternalInterfacesValue $InternalInterfaces `
            -ExpiryWarnDaysValue $ExpiryWarnDays `
            -JsonPathValue $JsonPath `
            -QuietValue ([bool]$Quiet)
        if ($PassThru) { $result }
        exit 0
    }
    catch {
        Write-Error ("Error (line {0}): {1}" -f $_.InvocationInfo.ScriptLineNumber, $_.Exception.Message)
        exit 1
    }
}
