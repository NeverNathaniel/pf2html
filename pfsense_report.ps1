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

.PARAMETER Hudu
    Generate a simplified, paste-ready operational summary for Hudu (or other IT
    documentation/KB platforms) containing only the essential setup details, with empty
    sections omitted, no <style>/<script> boilerplate, and secrets omitted for vault storage.

.PARAMETER HuduFormat
    Output format when -Hudu is specified: 'Html' (inline-styled embeddable HTML fragment
    for TinyMCE/Hudu Source Code or copy-paste, default) or 'Markdown' (GFM Markdown; also
    auto-selected when -OutputPath ends in .md or .markdown).

.PARAMETER PassThru
    Emit a summary object containing output path, counts, and findings to the pipeline.

.PARAMETER Quiet
    Suppress status console output (errors and warnings are still written).

.EXAMPLE
    .\pfsense_report.ps1 -ConfigPath "config.xml" -OutputPath "report.html"

.EXAMPLE
    .\pfsense_report.ps1 -ConfigPath "config.xml" -OutputPath "shared.html" -Redact -Title "Acme Firewall"

.EXAMPLE
    .\pfsense_report.ps1 -ConfigPath "config.xml" -Hudu -OutputPath "client-fw-hudu.html"

.EXAMPLE
    .\pfsense_report.ps1 -ConfigPath "config.xml" -Hudu -HuduFormat Markdown -OutputPath "client-fw.md"
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

    [switch]$Hudu,

    [ValidateSet('Html', 'Markdown', 'Md')]
    [string]$HuduFormat = 'Html',

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
    $script:IsRedacted         = $RedactMode
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
#  CORE I/O, XML & REDACTION HELPERS
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
    $settings.DtdProcessing  = [System.Xml.DtdProcessing]::Prohibit
    $settings.XmlResolver    = $null
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
    if (-not $script:IsRedacted -or [string]::IsNullOrEmpty($text)) { return $text }
    $t = $text

    # 1. MAC addresses (colon or hyphen delimited, consistent separator) -> MAC-NNN
    $t = [regex]::Replace($t, '(?i)(?<![0-9a-f:-])([0-9a-f]{2})([:-])(?:[0-9a-f]{2}\2){4}[0-9a-f]{2}(?![0-9a-f:-])',
        [System.Text.RegularExpressions.MatchEvaluator] {
            param($m)
            return (Get-RedactToken ($m.Value -replace '-', ':').ToLowerInvariant() 'MAC')
        })

    # 2. IPv4 addresses (valid 0-255 octets, not part of longer dotted OID/version) -> IP-NNN
    $t = [regex]::Replace($t, '(?<![.\d])(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})(?![.\d])',
        [System.Text.RegularExpressions.MatchEvaluator] {
            param($m)
            for ($i = 1; $i -le 4; $i++) { if ([int]$m.Groups[$i].Value -gt 255) { return $m.Value } }
            return (Get-RedactToken $m.Value 'IP')
        })

    # 3. IPv6 addresses (full 8-group or compressed '::', validated by IPAddress.TryParse;
    #    never touches HH:MM:SS timestamps because they lack '::' and have only 2 colons)
    $t = [regex]::Replace($t, '(?i)(?<![0-9a-f:])(?:[0-9a-f]{0,4}:){2,7}[0-9a-f]{0,4}(?![0-9a-f:])',
        [System.Text.RegularExpressions.MatchEvaluator] {
            param($m)
            $cand = $m.Value
            $colonCount = @($cand.ToCharArray() | Where-Object { $_ -eq ':' }).Count
            if (-not $cand.Contains('::') -and $colonCount -lt 7) { return $cand }
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
            $domKey = if ($script:RedactDomain -and $domPart -ieq $script:RedactDomain) { $script:RedactDomain } else { $domPart.ToLowerInvariant() }
            return ($uTok + '@' + (Get-RedactToken $domKey 'DOMAIN'))
        })

    # 5. FQDNs (preserve HOST-NNN.DOMAIN-NNN correlation; skip generated tokens & filenames)
    $skipExts = @('ps1','xml','html','htm','php','sh','conf','cfg','pem','crt','cer','key','log','json','csv','txt','zip','tar','gz','exe','dll','png','jpg','jpeg','gif','svg','webp','pdf','md')
    $t = [regex]::Replace($t, '(?i)\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{1,62}\b',
        [System.Text.RegularExpressions.MatchEvaluator] {
            param($m)
            $val = $m.Value
            if (Test-IsRedactToken $val) { return $val }
            $lastDot = $val.LastIndexOf('.')
            if ($lastDot -gt 0 -and ($skipExts -contains $val.Substring($lastDot + 1).ToLowerInvariant())) { return $val }
            if ($script:RedactDomain) {
                if ($val -ieq $script:RedactDomain) { return (Get-RedactToken $script:RedactDomain 'DOMAIN') }
                $suffix = '.' + $script:RedactDomain
                if ($val.Length -gt $suffix.Length -and $val.EndsWith($suffix, [System.StringComparison]::OrdinalIgnoreCase)) {
                    $hostPart = $val.Substring(0, $val.Length - $suffix.Length)
                    return ((Get-RedactToken $hostPart.ToLowerInvariant() 'HOST') + '.' + (Get-RedactToken $script:RedactDomain 'DOMAIN'))
                }
            }
            return (Get-RedactToken $val.ToLowerInvariant() 'HOST')
        })

    # 6. Specific system domain / bare hostname with strict word boundaries
    foreach ($pair in @(@($script:RedactDomain, 'DOMAIN'), @($script:RedactHost, 'HOST'))) {
        if ($pair[0]) {
            $tok = Get-RedactToken $pair[0] $pair[1]
            $pat = '(?i)(?<![a-z0-9_-])' + [regex]::Escape($pair[0]) + '(?![a-z0-9_-])'
            $t = [regex]::Replace($t, $pat, [System.Text.RegularExpressions.MatchEvaluator] { param($m) $null = $m; return $tok })
        }
    }
    return $t
}

# ==================================================================================
#  HTML ENCODING & DECLARATIVE TABLE HELPERS
# ==================================================================================

function E {
    param([object]$s)
    if ($null -eq $s) { return '' }
    $str = [string]$s
    if ($script:IsRedacted) { $str = Apply-Redaction $str }
    return [System.Net.WebUtility]::HtmlEncode($str)
}

function E-Host {
    param([object]$s)
    $str = if ($null -eq $s) { '' } else { ([string]$s).Trim() }
    if ([string]::IsNullOrWhiteSpace($str)) { return '<span class="muted">&mdash;</span>' }
    if ($script:IsRedacted) {
        if ($str.Contains('.') -or $str.Contains(':')) { return (E $str) }
        return [System.Net.WebUtility]::HtmlEncode((Get-RedactToken $str.ToLowerInvariant() 'HOST'))
    }
    return [System.Net.WebUtility]::HtmlEncode($str)
}

function E-User {
    param([object]$s)
    $str = if ($null -eq $s) { '' } else { ([string]$s).Trim() }
    if ([string]::IsNullOrWhiteSpace($str)) { return '<span class="muted">&mdash;</span>' }
    if ($script:IsRedacted) {
        if ($str -match '@') { return (E $str) }
        return [System.Net.WebUtility]::HtmlEncode((Get-RedactToken $str.ToLowerInvariant() 'USER'))
    }
    return [System.Net.WebUtility]::HtmlEncode($str)
}

function E-CertDn {
    param([object]$s)
    $str = if ($null -eq $s) { '' } else { ([string]$s).Trim() }
    if ([string]::IsNullOrWhiteSpace($str)) { return '<span class="muted">&mdash;</span>' }
    if ($script:IsRedacted) {
        $str = [regex]::Replace($str, '(?i)\b(O|OU|L|ST|S|STREET)=([^,]+)',
            [System.Text.RegularExpressions.MatchEvaluator] {
                param($m)
                return ($m.Groups[1].Value + '=' + (Get-RedactToken $m.Groups[2].Value.Trim() 'ORG'))
            })
        $str = [regex]::Replace($str, '(?i)\b(CN)=([^,]+)',
            [System.Text.RegularExpressions.MatchEvaluator] {
                param($m)
                $val = $m.Groups[2].Value.Trim()
                $red = Apply-Redaction $val
                if ($red -eq $val -and -not (Test-IsRedactToken $val)) { $red = Get-RedactToken $val 'HOST' }
                return ($m.Groups[1].Value + '=' + $red)
            })
        $str = Apply-Redaction $str
    }
    return [System.Net.WebUtility]::HtmlEncode($str)
}

function Dash {
    param([object]$s)
    if ($null -eq $s -or [string]::IsNullOrWhiteSpace([string]$s)) { return '<span class="muted">&mdash;</span>' }
    return (E $s)
}

function DashMono {
    param([object]$s)
    if ($null -eq $s -or [string]::IsNullOrWhiteSpace([string]$s)) { return '<span class="muted">&mdash;</span>' }
    return '<code class="mono">' + (E $s) + '</code>'
}

function Badge {
    param([string]$Text, [string]$Kind = 'muted', [bool]$Raw = $false)
    $body = if ($Raw) { $Text } else { E $Text }
    return '<span class="badge badge-' + $Kind + '">' + $body + '</span>'
}

function YesNo {
    param([bool]$b)
    if ($b) { return (Badge 'Yes' 'ok' $true) }
    return (Badge 'No' 'muted' $true)
}

function Secret {
    param([object]$s)
    if ($null -eq $s -or [string]::IsNullOrWhiteSpace([string]$s)) { return '<span class="muted">&mdash;</span>' }
    if ($script:IsRedacted) { return '<span class="redacted">[REDACTED]</span>' }
    $script:HasPlaintextSecret = $true
    return '<span class="secret-wrap"><code class="mono secret-val is-masked">' +
           [System.Net.WebUtility]::HtmlEncode([string]$s) +
           '</code><button type="button" class="secret-btn" aria-label="Toggle secret visibility">Show</button></span>'
}

function Format-ListCell {
    param(
        [object[]]$Items,
        [ValidateSet('text', 'mono', 'host', 'user')]
        [string]$Mode = 'text',
        [string]$Separator = '<br>'
    )
    $arr = @($Items | Where-Object { $null -ne $_ -and -not [string]::IsNullOrWhiteSpace([string]$_) })
    if ($arr.Count -eq 0) { return '<span class="muted">&mdash;</span>' }
    $formatted = @(foreach ($item in $arr) {
        switch ($Mode) {
            'mono' { DashMono $item }
            'host' { E-Host $item }
            'user' { E-User $item }
            default { E $item }
        }
    })
    return ($formatted -join $Separator)
}

function Add-Row {
    param(
        [System.Text.StringBuilder]$Sb,
        [string[]]$Cells,
        [string]$Id = '',
        [string]$Class = '',
        [bool]$Disabled = $false,
        [string]$ExtraAttr = ''
    )
    [void]$Sb.Append('<tr')
    if ($Id) { [void]$Sb.Append(' id="').Append($Id).Append('"') }
    $cls = if ($Class) { $Class } elseif ($Disabled) { 'row-disabled' } else { '' }
    if ($cls) { [void]$Sb.Append(' class="').Append($cls).Append('"') }
    if ($Disabled) { [void]$Sb.Append(' data-disabled="1"') }
    if ($ExtraAttr) { [void]$Sb.Append(' ').Append($ExtraAttr) }
    [void]$Sb.Append('>')
    foreach ($c in $Cells) {
        if ($c.StartsWith('<td')) { [void]$Sb.Append($c) }
        else { [void]$Sb.Append('<td>').Append($c).Append('</td>') }
    }
    [void]$Sb.Append('</tr>')
}

function Format-KvTable {
    param([object[]]$Rows)
    $sb = New-Object System.Text.StringBuilder
    [void]$sb.Append('<div class="table-wrap"><table class="kv">')
    foreach ($r in $Rows) {
        $idAttr = if ($r.Count -ge 3 -and $r[2]) { ' id="' + $r[2] + '"' } else { '' }
        [void]$sb.Append('<tr').Append($idAttr).Append('><th>').Append($r[0]).Append('</th><td>').Append($r[1]).Append('</td></tr>')
    }
    [void]$sb.Append('</table></div>')
    return $sb.ToString()
}

function Tbl {
    param([string[]]$headers, [string]$bodyHtml, [string]$tableClass = '')
    $sb = New-Object System.Text.StringBuilder
    $cls = if ($tableClass) { ' class="' + $tableClass + '"' } else { '' }
    [void]$sb.Append('<div class="table-wrap"><table').Append($cls).Append('><thead><tr>')
    foreach ($x in $headers) { [void]$sb.Append('<th>').Append($x).Append('</th>') }
    [void]$sb.Append('</tr></thead><tbody>').Append($bodyHtml).Append('</tbody></table></div>')
    return $sb.ToString()
}

function Wrap-Section {
    param([string]$id, [string]$title, [string]$summary, [string]$body, [string]$headerBadge = '')
    $isEmpty = [string]::IsNullOrWhiteSpace($body)
    $b = if ($isEmpty) { '<p class="not-configured">Not configured.</p>' } else { $body }
    $secCls = if ($isEmpty) { 'report-section section-empty' } else { 'report-section' }
    return '<section class="' + $secCls + '" id="' + $id + '">' +
           '<h2 class="section-heading"><button type="button" class="section-header" aria-expanded="true">' +
           '<span class="toggle-icon" aria-hidden="true">&#9662;</span>' +
           '<span class="sh-title">' + $title + '</span>' + $headerBadge + '</button></h2>' +
           '<div class="section-body"><p class="section-summary">' + $summary + '</p>' + $b + '</div></section>'
}

# ==================================================================================
#  XML, NETWORK, CRYPTO, CERT & CROSS-REFERENCE HELPERS
# ==================================================================================

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
    # Always returns a real array (never collapses to a scalar on Windows PowerShell 5.1).
    param($node, [string]$path)
    $list = New-Object 'System.Collections.Generic.List[object]'
    if ($null -ne $node) {
        $r = $node.SelectNodes($path)
        if ($null -ne $r) { foreach ($n in $r) { [void]$list.Add($n) } }
    }
    $arr = $list.ToArray()
    return , $arr
}

function Test-XmlEnabled {
    param($node, [string[]]$TagNames = @('enable'))
    if ($null -eq $node) { return $false }
    foreach ($tag in $TagNames) {
        if (XHas $node $tag) {
            $v = XText $node $tag
            if ($v -eq '' -or $v -match '(?i)^(enabled|on|yes|true|1)$') { return $true }
        }
    }
    return $false
}

function Add-Finding {
    param([string]$Sev, [string]$Label, [string]$Where, [string]$Detail, [string]$TargetId = '')
    [void]$script:Findings.Add([pscustomobject]@{
        Sev = $Sev; Label = $Label; Where = $Where; Detail = $Detail; TargetId = $TargetId
    })
}

function ConvertFrom-Epoch {
    param([string]$s)
    if ([string]::IsNullOrWhiteSpace($s)) { return '' }
    $n = [int64]0
    if ([int64]::TryParse($s, [ref]$n)) {
        try { return ([DateTimeOffset]::FromUnixTimeSeconds($n)).ToLocalTime().ToString('yyyy-MM-dd HH:mm:ss zzz') }
        catch { Write-Verbose ("Could not parse Unix timestamp '{0}': {1}" -f $s, $_.Exception.Message); return $s }
    }
    return $s
}

function Get-Ipv4Mask {
    param([string]$bits)
    $b = 0
    if (-not [int]::TryParse($bits, [ref]$b) -or $b -lt 0 -or $b -gt 32) { return '' }
    $octets = @(0, 0, 0, 0)
    for ($i = 0; $i -lt 4; $i++) {
        $take = [math]::Min(8, [math]::Max(0, $b - ($i * 8)))
        $octets[$i] = if ($take -le 0) { 0 } elseif ($take -ge 8) { 255 } else { [int](256 - [math]::Pow(2, 8 - $take)) }
    }
    return ($octets -join '.')
}

function Test-IsPrivateIpv4 {
    param([string]$ip)
    if ([string]::IsNullOrWhiteSpace($ip)) { return $false }
    $ipObj = $null
    if (-not [System.Net.IPAddress]::TryParse($ip.Trim(), [ref]$ipObj) -or
        $ipObj.AddressFamily -ne [System.Net.Sockets.AddressFamily]::InterNetwork) { return $false }
    $b = $ipObj.GetAddressBytes()
    return ($b[0] -eq 10) -or
           ($b[0] -eq 172 -and $b[1] -ge 16 -and $b[1] -le 31) -or
           ($b[0] -eq 192 -and $b[1] -eq 168) -or
           ($b[0] -eq 100 -and $b[1] -ge 64 -and $b[1] -le 127) -or
           ($b[0] -eq 169 -and $b[1] -eq 254)
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

function Add-CryptoFindings {
    param(
        [string[]]$CryptoValues,
        [string[]]$DhGroups = @(),
        [bool]$IsPfs = $false,
        [string]$Where,
        [string]$RowId,
        [System.Text.StringBuilder]$Flags
    )
    $rowCls = ''
    $weak = Get-WeakCryptoHits $CryptoValues
    if ($weak.High.Count -gt 0) {
        [void]$Flags.Append((Badge 'WEAK CRYPTO' 'high' $true)).Append(' ')
        $rowCls = 'row-high'
        Add-Finding 'high' 'WEAK CRYPTO' $Where ('Uses ' + ($weak.High -join ', ')) $RowId
    }
    if ($weak.Warn.Count -gt 0) {
        [void]$Flags.Append((Badge 'LEGACY CRYPTO' 'warn' $true)).Append(' ')
        if (-not $rowCls) { $rowCls = 'row-warn' }
        Add-Finding 'warn' 'LEGACY CRYPTO' $Where ('Uses ' + ($weak.Warn -join ', ')) $RowId
    }
    foreach ($dhg in @($DhGroups | Where-Object { $_ } | Select-Object -Unique)) {
        $dhf = Get-WeakDhFinding $dhg $IsPfs
        if ($null -ne $dhf) {
            $kind = if ($dhf.Sev -eq 'high') { 'high' } else { 'warn' }
            [void]$Flags.Append((Badge $dhf.Label $kind)).Append(' ')
            if ($dhf.Sev -eq 'high') { $rowCls = 'row-high' } elseif (-not $rowCls) { $rowCls = 'row-warn' }
            Add-Finding $dhf.Sev $dhf.Label $Where $dhf.Detail $RowId
        }
    }
    return $rowCls
}

function Get-CertInfo {
    param([string]$CrtField)
    $r = [pscustomobject]@{
        Subject = ''; Issuer = ''; NotBefore = $null; NotAfter = $null
        SigAlg = ''; KeyAlg = ''; KeySize = 0; SelfSigned = $false; Error = $null
    }
    if ([string]::IsNullOrWhiteSpace($CrtField)) { $r.Error = 'No certificate data'; return $r }
    $cert = $null
    try {
        $pem = $CrtField.Trim()
        if ($pem -notmatch 'BEGIN CERTIFICATE') {
            try { $pem = [System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String(($CrtField -replace '\s', ''))) }
            catch { Write-Verbose ("Outer base64 decode failed: {0}" -f $_.Exception.Message) }
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
        catch { Write-Verbose ("Could not inspect certificate public key: {0}" -f $_.Exception.Message) }
    }
    catch { $r.Error = $_.Exception.Message }
    finally { if ($null -ne $cert) { $cert.Dispose() } }
    return $r
}

function Format-CertStatus {
    param($info, [string]$where, [string]$targetId = '')
    if ($info.Error) { return (Badge 'PARSE ERROR' 'info' $true) }
    $badges = New-Object System.Text.StringBuilder
    if ($null -ne $info.NotBefore -and $info.NotBefore -gt $script:Now) {
        Add-Finding 'warn' 'NOT YET VALID' $where ("Certificate is not valid until " + $info.NotBefore.ToString('yyyy-MM-dd')) $targetId
        [void]$badges.Append((Badge 'NOT YET VALID' 'warn' $true)).Append(' ')
    }
    if ($null -eq $info.NotAfter) {
        [void]$badges.Append((Badge 'Unknown' 'muted' $true))
    }
    else {
        $days = ($info.NotAfter - $script:Now).TotalDays
        if ($days -lt 0) {
            Add-Finding 'high' 'EXPIRED' $where ("Certificate expired " + $info.NotAfter.ToString('yyyy-MM-dd')) $targetId
            [void]$badges.Append((Badge 'EXPIRED' 'high' $true))
        }
        elseif ($days -lt $script:ExpiryWarnDays) {
            Add-Finding 'warn' 'EXPIRING SOON' $where ("Certificate expires " + $info.NotAfter.ToString('yyyy-MM-dd') + " (" + [int]$days + " days)") $targetId
            [void]$badges.Append((Badge 'EXPIRING SOON' 'warn' $true))
        }
        elseif ($badges.Length -eq 0) {
            [void]$badges.Append((Badge 'Valid' 'ok' $true))
        }
    }
    if ($info.SigAlg -match '(?i)md5') {
        Add-Finding 'high' 'WEAK CERT' $where ("Certificate uses weak signature algorithm: " + $info.SigAlg) $targetId
        [void]$badges.Append(' ').Append((Badge 'MD5 SIG' 'high' $true))
    }
    elseif ($info.SigAlg -match '(?i)sha1') {
        Add-Finding 'warn' 'WEAK CERT' $where ("Certificate uses deprecated SHA-1 signature algorithm: " + $info.SigAlg) $targetId
        [void]$badges.Append(' ').Append((Badge 'SHA-1 SIG' 'warn' $true))
    }
    if ($info.KeyAlg -eq 'RSA' -and $info.KeySize -gt 0 -and $info.KeySize -lt 2048) {
        Add-Finding 'high' 'WEAK CERT' $where ("Certificate uses short RSA key (" + $info.KeySize + "-bit; <2048-bit).") $targetId
        [void]$badges.Append(' ').Append((Badge 'WEAK KEY' 'high' $true))
    }
    return $badges.ToString().Trim()
}

function Format-Endpoint {
    param($epNode)
    $o = [pscustomobject]@{ Addr = 'any'; Port = ''; Negated = $false; RawAddr = 'any' }
    if ($null -eq $epNode) { return $o }
    $neg = ''
    if (XHas $epNode 'not') { $neg = '! '; $o.Negated = $true }
    $raw = if (XHas $epNode 'any') { 'any' } elseif (XText $epNode 'network') { XText $epNode 'network' } elseif (XText $epNode 'address') { XText $epNode 'address' } else { 'any' }
    $o.RawAddr = $raw
    $o.Addr    = $neg + $raw
    $o.Port    = XText $epNode 'port'
    return $o
}

function Format-RefCell {
    param([string]$val, [bool]$negated = $false)
    if ([string]::IsNullOrWhiteSpace($val)) { return '<span class="muted">&mdash;</span>' }
    $clean = $val
    $prefix = ''
    if ($clean.StartsWith('! ')) {
        $prefix = (Badge '!' 'warn' $true) + ' '
        $clean = $clean.Substring(2)
    }
    elseif ($negated) {
        $prefix = (Badge '!' 'warn' $true) + ' '
    }
    if ($script:AliasMap.ContainsKey($clean)) {
        $alInfo = $script:AliasMap[$clean]
        $tip = if ($alInfo.Preview) { ' title="' + (E $alInfo.Preview) + '"' } else { '' }
        return $prefix + '<a class="xref alias-ref" href="#' + $alInfo.Id + '"' + $tip + '><code class="mono">' + (E $clean) + '</code></a>'
    }
    if ($clean -eq '(self)') { return $prefix + '<code class="mono">This Firewall (self)</code>' }
    if ($clean -match '^(.+)ip$' -and $script:IfMap.ContainsKey($Matches[1])) {
        return $prefix + '<code class="mono">' + (E $clean) + '</code> <span class="muted">(' + (E $script:IfMap[$Matches[1]]) + ' addr)</span>'
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
    if (-not (Test-Path -LiteralPath $full -PathType Leaf)) { Write-Warning "Logo not found: $path"; return '' }
    try {
        $mimeMap = @{ '.png'='image/png'; '.jpg'='image/jpeg'; '.jpeg'='image/jpeg'; '.gif'='image/gif'; '.svg'='image/svg+xml'; '.webp'='image/webp' }
        $ext = ([System.IO.Path]::GetExtension($full)).ToLowerInvariant()
        if (-not $mimeMap.ContainsKey($ext)) {
            Write-Warning "Unsupported logo format '$ext' (expected png/jpg/gif/svg/webp). Skipping logo."
            return ''
        }
        $fi = Get-Item -LiteralPath $full
        if ($fi.Length -gt 2MB) { Write-Warning ("Logo file is large ({0:N1} MB)." -f ($fi.Length / 1MB)) }
        $b64 = [Convert]::ToBase64String([System.IO.File]::ReadAllBytes($full))
        return '<img class="cover-logo" alt="Logo" src="data:' + $mimeMap[$ext] + ';base64,' + $b64 + '" />'
    }
    catch { Write-Warning "Could not embed logo: $($_.Exception.Message)"; return '' }
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
        $hasElementChild = $false
        foreach ($child in $n.ChildNodes) {
            if ($child.NodeType -eq [System.Xml.XmlNodeType]::Element) {
                $hasElementChild = $true
                $stack.Push($child)
            }
        }
        if ($hasElementChild -or $n.LocalName -eq 'refid') { continue }
        $val = ([string]$n.InnerText).Trim()
        if ([string]::IsNullOrWhiteSpace($val) -or -not $script:CertRefMap.ContainsKey($val)) { continue }

        $parent = if ($null -ne $n.ParentNode) { $n.ParentNode.LocalName } else { '' }
        $label = switch -regex ("$parent/$($n.LocalName)") {
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
            default                    { "$parent ($($n.LocalName))" }
        }
        if (-not $map.ContainsKey($val)) { $map[$val] = New-Object 'System.Collections.Generic.List[string]' }
        if (-not $map[$val].Contains($label)) { [void]$map[$val].Add($label) }
    }
    return $map
}

function Build-LookupMaps {
    param($root, [string[]]$ForceWan, [string[]]$ForceInternal)

    $ifsNode = $root.SelectSingleNode('interfaces')
    if ($null -ne $ifsNode) {
        foreach ($c in $ifsNode.ChildNodes) {
            if ($c.NodeType -eq [System.Xml.XmlNodeType]::Element) {
                $d = XText $c 'descr'
                $script:IfMap[$c.Name] = if ($d) { $d } else { $c.Name.ToUpperInvariant() }
            }
        }
    }
    foreach ($ig in (XNodes $root 'ifgroups/ifgroupentry')) {
        $gn = XText $ig 'ifname'
        if ($gn) { $gd = XText $ig 'descr'; $script:IfMap[$gn] = if ($gd) { "Group: $gd" } else { "Interface Group ($gn)" } }
    }
    foreach ($kv in @{ WireGuard='WireGuard'; openvpn='OpenVPN'; enc0='IPsec'; ipsec='IPsec'; l2tp='L2TP'; '(floating)'='Floating rules' }.GetEnumerator()) {
        $script:IfMap[$kv.Key] = $kv.Value
    }

    # Gateways & default gateway identification
    $gwNode = $root.SelectSingleNode('gateways')
    $defaultGws = @{}
    if ($null -ne $gwNode) {
        foreach ($d in @((XText $gwNode 'defaultgw4'), (XText $gwNode 'defaultgw6'))) {
            if ($d -and $d -ne 'automatic' -and $d -ne '-') { $defaultGws[$d] = $true }
        }
    }
    $wanGwIfaces = @{}
    foreach ($g in (XNodes $root 'gateways/gateway_item')) {
        $gname = XText $g 'name'; $gi = XText $g 'interface'; $gip = XText $g 'gateway'
        if ($gname) { $script:GatewayMap[$gname] = 'gw-' + (Format-Slug $gname) }
        if ($gi -and (($gname -and $defaultGws.ContainsKey($gname)) -or $gip -eq 'dynamic' -or ($gip -and -not (Test-IsPrivateIpv4 $gip)))) {
            $wanGwIfaces[$gi] = $true
        }
    }
    foreach ($gg in (XNodes $root 'gateways/gateway_group')) {
        $ggname = XText $gg 'name'
        if ($ggname) { $script:GatewayMap[$ggname] = 'gwg-' + (Format-Slug $ggname) }
    }

    $forceWanSet = @{}; if ($null -ne $ForceWan)      { foreach ($x in $ForceWan)      { if ($x) { $forceWanSet[$x.Trim().ToLowerInvariant()] = $true } } }
    $forceIntSet = @{}; if ($null -ne $ForceInternal) { foreach ($x in $ForceInternal) { if ($x) { $forceIntSet[$x.Trim().ToLowerInvariant()] = $true } } }

    if ($null -ne $ifsNode) {
        foreach ($c in $ifsNode.ChildNodes) {
            if ($c.NodeType -ne [System.Xml.XmlNodeType]::Element) { continue }
            $k = $c.Name; $kl = $k.ToLowerInvariant()
            if ($forceIntSet.ContainsKey($kl)) { $script:TrustMap[$k] = 'internal'; continue }
            if ($forceWanSet.ContainsKey($kl)) { $script:TrustMap[$k] = 'wan'; continue }
            $dev = XText $c 'if'; $dscr = XText $c 'descr'
            if ($dev -match '^(tun_wg|wg|ovpn|ipsec|enc)\d*' -or $dscr -match '(?i)\b(wireguard|wg|vpn|openvpn|ipsec)\b') {
                $script:TrustMap[$k] = 'vpn'; continue
            }
            $gwv = XText $c 'gateway'
            $ipv = (XText $c 'ipaddr').ToLowerInvariant()
            $isWan = ($kl -eq 'wan') -or $wanGwIfaces.ContainsKey($k) -or
                     ($gwv -and $gwv -ne 'none' -and ($defaultGws.ContainsKey($gwv) -or $kl -ne 'lan')) -or
                     ($ipv -in @('dhcp', 'pppoe', 'pptp', 'l2tp')) -or
                     ($kl -match 'wan' -or $dscr -match '(?i)\b(wan|internet|isp|untrust|external)\b')
            $script:TrustMap[$k] = if ($isWan) { 'wan' } else { 'internal' }
        }
    }
    foreach ($k in @('openvpn','enc0','ipsec','l2tp','WireGuard')) { $script:TrustMap[$k] = 'vpn' }
    $script:TrustMap['(floating)'] = 'floating'

    foreach ($v in (XNodes $root 'vlans/vlan')) {
        $vif = XText $v 'vlanif'
        if ($vif) { $script:VlanMap[$vif] = [pscustomobject]@{ Tag = XText $v 'tag'; Id = 'vlan-' + (Format-Slug $vif) } }
    }
    foreach ($a in (XNodes $root 'aliases/alias')) {
        $an = XText $a 'name'
        if (-not $an) { continue }
        $addr = XText $a 'address'; if (-not $addr) { $addr = XText $a 'url' }
        $items = @($addr -split '\s+' | Where-Object { $_ })
        $preview = if ($items.Count -gt 6) { (($items[0..5]) -join ', ') + " (+$($items.Count - 6) more)" } else { $items -join ', ' }
        $script:AliasMap[$an] = [pscustomobject]@{ Id = 'alias-' + (Format-Slug $an); Type = XText $a 'type'; Preview = $preview }
    }
    foreach ($pair in @(@('ca','ca-'), @('cert','cert-'))) {
        foreach ($c in (XNodes $root $pair[0])) {
            $rid = XText $c 'refid'
            if ($rid) { $script:CertRefMap[$rid] = [pscustomobject]@{ Name = XText $c 'descr'; Id = $pair[1] + (Format-Slug $rid) } }
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

    $dns = @(foreach ($d in (XNodes $sys 'dnsserver')) { $d.InnerText.Trim() })
    $ntp = @((XText $sys 'timeservers') -split '\s+' | Where-Object { $_ })
    $gui = $sys.SelectSingleNode('webgui')
    $proto = XText $gui 'protocol'; if (-not $proto) { $proto = 'https' }
    $port  = XText $gui 'port'
    $portDisp = if ($port) { $port } elseif ($proto -eq 'http') { '80 (default)' } else { '443 (default)' }
    $guiCert       = XText $gui 'ssl-certref'
    $noAntiLockout = XHas $gui 'noantilockout'
    $noDnsRebind   = XHas $gui 'nodnsrebindcheck'
    $noReferer     = XHas $gui 'nohttpreferercheck'

    if ($proto -ieq 'http') { Add-Finding 'high' 'INSECURE WEBGUI'   'System / WebGUI' 'WebGUI is configured to use unencrypted HTTP instead of HTTPS.' 'row-sys-webgui' }
    if ($noDnsRebind)       { Add-Finding 'warn' 'DNS REBIND OFF'    'System / WebGUI' 'DNS Rebind Attack protection is disabled.' 'row-sys-rebind' }
    if ($noReferer)         { Add-Finding 'warn' 'REFERER CHECK OFF' 'System / WebGUI' 'HTTP_REFERER enforcement check is disabled.' 'row-sys-referer' }

    $sshNode    = $sys.SelectSingleNode('ssh')
    $sshEnabled = Test-XmlEnabled $sshNode @('enable', 'enabled')
    $sshPort    = XText $sshNode 'port'
    $sshKeyOnly = XText $sshNode 'sshdkeyonly'
    if ($sshEnabled -and ($sshKeyOnly -notin @('enabled', 'both'))) {
        Add-Finding 'warn' 'SSH PASSWORD AUTH' 'System / SSH' 'SSH is enabled and permits password authentication (Public Key Only is not enforced).' 'row-sys-ssh'
    }

    $consoleProtected = XHas $sys 'disableconsolemenu'
    if (-not $consoleProtected) {
        Add-Finding 'info' 'UNPROTECTED CONSOLE' 'System / Console' 'Console menu password protection is not enabled.' 'row-sys-console'
    }

    $guiHtml = '<code class="mono">' + (E $proto) + '</code> on port <code class="mono">' + (E $portDisp) + '</code>'
    if ($guiCert) { $guiHtml += ' &mdash; Cert: ' + (Format-CertRef $guiCert) }
    if ($proto -ieq 'http') { $guiHtml += ' ' + (Badge 'INSECURE HTTP' 'high' $true) }

    $sshHtml = YesNo $sshEnabled
    if ($sshEnabled) {
        $sp = if ($sshPort) { $sshPort } else { '22 (default)' }
        $sk = switch ($sshKeyOnly) { 'enabled' { 'Public key only' } 'both' { 'Key + password' } default { 'Password or key' } }
        $sshHtml += ' &mdash; Port <code class="mono">' + (E $sp) + '</code> (' + (E $sk) + ')'
    }

    $rows = New-Object 'System.Collections.Generic.List[object]'
    foreach ($r in @(
        @('Hostname',                    (E-Host (XText $sys 'hostname'))),
        @('Domain',                      (Dash (XText $sys 'domain'))),
        @('DNS servers',                 (Format-ListCell $dns -Mode 'mono')),
        @('NTP servers',                 (Format-ListCell $ntp -Mode 'mono')),
        @('Time zone',                   (Dash (XText $sys 'timezone'))),
        @('WebGUI',                      $guiHtml, 'row-sys-webgui'),
        @('WebGUI anti-lockout',         (YesNo (-not $noAntiLockout))),
        @('DNS rebind check',            (YesNo (-not $noDnsRebind)), 'row-sys-rebind'),
        @('HTTP Referer check',          (YesNo (-not $noReferer)), 'row-sys-referer'),
        @('SSH access',                  $sshHtml, 'row-sys-ssh'),
        @('Console password protection', (YesNo $consoleProtected), 'row-sys-console'),
        @('Tuning / optimization',       (Dash (XText $sys 'optimization')))
    )) { [void]$rows.Add($r) }
    $crypto = XText $sys 'crypto_hardware'
    if ($crypto) { [void]$rows.Add(@('Hardware crypto', (E $crypto))) }
    $dhcpBackend = XText $root 'dhcpbackend'
    if ($dhcpBackend) { [void]$rows.Add(@('DHCP backend', (E $dhcpBackend.ToUpperInvariant()))) }
    return (Format-KvTable $rows.ToArray())
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
        $key = $c.Name; $rowId = 'row-if-' + (Format-Slug $key)
        $dev = XText $c 'if'; $en = XHas $c 'enable'; $ipv4 = XText $c 'ipaddr'
        $method = switch -regex ($ipv4) {
            '^dhcp$'  { 'DHCP'; break }  '^pppoe$' { 'PPPoE'; break } '^pptp$' { 'PPTP'; break }
            '^l2tp$'  { 'L2TP'; break }  '^carp$'  { 'CARP'; break }  '^none$|^$' { 'None'; break }
            '^\d+\.'  { 'Static'; break } default  { $ipv4 }
        }
        $ipv4disp = if ($ipv4 -match '^(dhcp|pppoe|pptp|l2tp|dhcp6|carp|none|)$') { '' } else { $ipv4 }
        $subnet = XText $c 'subnet'; $mask = Get-Ipv4Mask $subnet
        $subnetDisp = if ($ipv4disp -and $subnet) { '/' + $subnet + $(if ($mask) { ' (' + $mask + ')' } else { '' }) } else { '' }

        $v6 = XText $c 'ipaddrv6'; $v6Static = $false
        $v6disp = switch -regex ($v6) {
            '^track6$' {
                $t6if = XText $c 'track6-interface'; $t6id = XText $c 'track6-prefix-id'
                if ($t6if) { 'Track IPv6 (' + $t6if.ToUpperInvariant() + $(if ($t6id -ne '') { ", prefix $t6id" } else { '' }) + ')' } else { 'Track IPv6' }
                break
            }
            '^dhcp6$' { 'DHCP6'; break } '^slaac$' { 'SLAAC'; break } '^6rd$' { '6rd Tunnel'; break }
            '^6to4$'  { '6to4 Tunnel'; break } '^none$|^$' { ''; break }
            default   { $v6Static = $true; $v6 }
        }
        $sv6 = XText $c 'subnetv6'; if ($v6Static -and $sv6) { $v6disp += '/' + $sv6 }

        $vlanCell = '<span class="muted">&mdash;</span>'
        if ($script:VlanMap.ContainsKey($dev)) {
            $vi = $script:VlanMap[$dev]
            $vlanCell = '<a class="xref" href="#' + $vi.Id + '"><code class="mono">' + (E $vi.Tag) + '</code></a>'
        }
        elseif ($dev -match '\.(\d+)$') { $vlanCell = '<code class="mono">' + (E $Matches[1]) + '</code>' }

        $bbog = XHas $c 'blockbogons'
        if ($en -and $script:TrustMap.ContainsKey($key) -and $script:TrustMap[$key] -eq 'wan' -and -not $bbog) {
            Add-Finding 'info' 'BOGONS NOT BLOCKED' "Interface / $key" "WAN interface '$key' does not have 'Block bogon networks' enabled." $rowId
        }

        Add-Row $sb -Id $rowId -Disabled (-not $en) -Cells @(
            (DashMono $key), (Dash (XText $c 'descr')), (DashMono $dev), (YesNo $en),
            (Dash $method), (DashMono $ipv4disp), (DashMono $subnetDisp), (DashMono $v6disp),
            (DashMono (XText $c 'spoofmac')), (DashMono (XText $c 'mtu')), (DashMono (XText $c 'mss')),
            $vlanCell, (Format-GatewayRef (XText $c 'gateway')), (YesNo (XHas $c 'blockpriv')), (YesNo $bbog)
        )
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
        foreach ($g in $igNodes) { Add-Row $sb @((DashMono (XText $g 'ifname')), (DashMono (XText $g 'members')), (Dash (XText $g 'descr'))) }
        [void]$out.Append('<h3>Interface Groups</h3>').Append((Tbl @('Group Name','Members','Description') $sb.ToString()))
    }
    $laggs = XNodes $root 'laggs/lagg'
    if ($laggs.Count -gt 0) {
        $sb = New-Object System.Text.StringBuilder
        foreach ($l in $laggs) { Add-Row $sb @((DashMono (XText $l 'laggif')), (Dash (XText $l 'proto')), (DashMono (XText $l 'members')), (Dash (XText $l 'descr'))) }
        [void]$out.Append('<h3>Link Aggregations (LAGG)</h3>').Append((Tbl @('LAGG Interface','Protocol','Member Interfaces','Description') $sb.ToString()))
    }
    $bridges = XNodes $root 'bridges/bridged'
    if ($bridges.Count -gt 0) {
        $sb = New-Object System.Text.StringBuilder
        foreach ($b in $bridges) { Add-Row $sb @((DashMono (XText $b 'bridgeif')), (DashMono (XText $b 'members')), (Dash (XText $b 'descr'))) }
        [void]$out.Append('<h3>Bridges</h3>').Append((Tbl @('Bridge Interface','Member Interfaces','Description') $sb.ToString()))
    }
    return $out.ToString()
}

function Build-Vlans {
    param($root)
    $nodes = XNodes $root 'vlans/vlan'
    if ($nodes.Count -eq 0) { return '' }
    $sb = New-Object System.Text.StringBuilder
    foreach ($v in $nodes) {
        $vif = XText $v 'vlanif'
        Add-Row $sb -Id $(if ($vif) { 'vlan-' + (Format-Slug $vif) } else { '' }) -Cells @(
            (DashMono (XText $v 'if')), (DashMono (XText $v 'tag')), (DashMono (XText $v 'pcp')), (DashMono $vif), (Dash (XText $v 'descr'))
        )
    }
    return (Tbl @('Parent interface','VLAN tag','Priority (PCP)','VLAN interface','Description') $sb.ToString())
}

function Build-VirtualIps {
    param($root)
    $vips = XNodes $root 'virtualip/vip'
    if ($vips.Count -eq 0) { return '' }
    $sb = New-Object System.Text.StringBuilder
    foreach ($v in $vips) {
        $subnet = XText $v 'subnet'; $bits = XText $v 'subnet_bits'
        $addr = if ($subnet -and $bits) { "$subnet/$bits" } else { $subnet }
        $vhid = XText $v 'vhid'; $adv = XText $v 'advskew'
        $carpInfo = if ($vhid) { "VHID $vhid" + $(if ($adv -ne '') { ", skew $adv" } else { '' }) } else { '' }
        Add-Row $sb @((Dash (XText $v 'mode').ToUpperInvariant()), (DashMono (XText $v 'interface')), (DashMono $addr), (DashMono $carpInfo), (Dash (XText $v 'descr')))
    }
    return (Tbl @('Type','Interface','Address / Subnet','CARP (VHID / Skew)','Description') $sb.ToString())
}

function Build-Gateways {
    param($root)
    $gws = $root.SelectSingleNode('gateways')
    if ($null -eq $gws) { return '' }
    $def4 = XText $gws 'defaultgw4'; $def6 = XText $gws 'defaultgw6'
    $items = XNodes $gws 'gateway_item'; $groups = XNodes $gws 'gateway_group'
    if ($items.Count -eq 0 -and $groups.Count -eq 0 -and -not $def4 -and -not $def6) { return '' }

    $out = New-Object System.Text.StringBuilder
    if ($def4 -or $def6) {
        [void]$out.Append('<p class="note">Default IPv4 gateway: <strong>' + (Dash $def4) + '</strong> &nbsp;|&nbsp; Default IPv6 gateway: <strong>' + (Dash $def6) + '</strong></p>')
    }
    if ($items.Count -gt 0) {
        $sb = New-Object System.Text.StringBuilder
        foreach ($g in $items) {
            $name = XText $g 'name'; $disabled = XHas $g 'disabled'
            $isDef = ($name -and ($name -eq $def4 -or $name -eq $def6))
            $monDisp = if (XHas $g 'monitor_disable') { Badge 'Disabled' 'muted' $true } else { DashMono (XText $g 'monitor') }
            Add-Row $sb -Id $(if ($name) { 'gw-' + (Format-Slug $name) } else { '' }) -Disabled $disabled -Cells @(
                (DashMono $name), (YesNo (-not $disabled)), (DashMono (XText $g 'interface')), (DashMono (XText $g 'gateway')),
                $monDisp, (Dash (XText $g 'ipprotocol')), $(if ($isDef) { Badge 'DEFAULT' 'info' $true } else { '<span class="muted">&mdash;</span>' }), (Dash (XText $g 'descr'))
            )
        }
        [void]$out.Append((Tbl @('Name','Enabled','Interface','Gateway IP','Monitor IP','Protocol','Default','Description') $sb.ToString()))
    }
    if ($groups.Count -gt 0) {
        $sb = New-Object System.Text.StringBuilder
        foreach ($gg in $groups) {
            $gn = XText $gg 'name'
            $members = @(foreach ($m in (XNodes $gg 'item')) {
                $parts = @($m.InnerText.Trim() -split '\|')
                if ($parts.Count -ge 2) { $parts[0] + ' (Tier ' + $parts[1] + ')' } elseif ($m.InnerText.Trim()) { $m.InnerText.Trim() }
            })
            Add-Row $sb -Id $(if ($gn) { 'gwg-' + (Format-Slug $gn) } else { '' }) -Cells @(
                (DashMono $gn), (Format-ListCell $members -Mode 'mono'), (Dash (XText $gg 'trigger')), (Dash (XText $gg 'descr'))
            )
        }
        [void]$out.Append('<h3>Gateway Groups</h3>').Append((Tbl @('Group Name','Members &amp; Tiers','Trigger Level','Description') $sb.ToString()))
    }
    return $out.ToString()
}

function Build-Routes {
    param($root)
    $routes = XNodes $root 'staticroutes/route'
    if ($routes.Count -eq 0) { return '' }
    $sb = New-Object System.Text.StringBuilder
    foreach ($r in $routes) {
        $disabled = XHas $r 'disabled'
        Add-Row $sb -Disabled $disabled -Cells @(
            (DashMono (XText $r 'network')), (Format-GatewayRef (XText $r 'gateway')), (YesNo (-not $disabled)), (Dash (XText $r 'descr'))
        )
    }
    return (Tbl @('Destination network','Gateway','Enabled','Description') $sb.ToString())
}

function Test-Broad {
    param([string]$addr)
    if ([string]::IsNullOrWhiteSpace($addr)) { return $true }
    $a = $addr.Trim()
    return ($a -eq 'any' -or $a -like '! *' -or $a -eq '0.0.0.0/0' -or $a -eq '::/0')
}

function Get-ProtoClass {
    param([string]$proto)
    $p = (($proto -replace '/.*$', '')).ToLowerInvariant().Trim()
    if ($p -in @('icmp', 'icmp6', 'ipv6-icmp', 'igmp')) { return 'icmp' }
    if ($p -in @('esp', 'ah', 'gre', 'pim', 'ospf', 'carp', 'pfsync', 'l2tp')) { return 'infra' }
    if ($p -in @('tcp', 'udp', 'tcp/udp')) { return 'tcpudp' }
    if ($p -in @('', 'any')) { return 'any' }
    return 'other'
}

function Get-RuleExposure {
    param(
        [string]$trust, [string]$type, [string]$dir, [string]$protoClass,
        [bool]$srcBroad, [bool]$dstBroad, [bool]$dstPortSet, [string]$protoDisp, [string]$dstSvc,
        [bool]$isFirewallMgmt = $false, [bool]$floatingTouchesWan = $false
    )
    if ($type -ne 'pass' -or $dir -eq 'out') { return $null }
    $effectiveTrust = if ($trust -eq 'floating' -and $floatingTouchesWan) { 'wan' } else { $trust }

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
            if ($protoClass -in @('tcpudp', 'any', 'other')) {
                return @{ Sev = 'info'; Label = 'WAN (restricted)'; Detail = 'inbound WAN allow limited to specific source(s) - lower risk.'; Row = '' }
            }
        }
        'vpn' {
            if ($srcBroad -and $dstBroad -and ($protoClass -in @('tcpudp', 'any', 'other'))) {
                return @{ Sev = 'info'; Label = 'VPN ANY'; Detail = 'VPN interface permits any-to-any (common for full-tunnel remote access).'; Row = '' }
            }
        }
        'floating' {
            if ($srcBroad -and $dstBroad -and ($protoClass -in @('tcpudp', 'any'))) {
                return @{ Sev = 'warn'; Label = 'FLOATING ANY'; Detail = 'floating rule permits any-to-any; verify the intended scope.'; Row = 'row-warn' }
            }
        }
    }
    return $null
}

function Build-Firewall {
    param($root)
    $rules = XNodes $root 'filter/rule'
    if ($rules.Count -eq 0) { return '' }

    $sysNode  = $root.SelectSingleNode('system')
    $guiNode  = if ($null -ne $sysNode) { $sysNode.SelectSingleNode('webgui') } else { $null }
    $guiProto = XText $guiNode 'protocol'; if (-not $guiProto) { $guiProto = 'https' }
    $guiPort  = XText $guiNode 'port'; if (-not $guiPort) { $guiPort = if ($guiProto -eq 'http') { '80' } else { '443' } }
    $sshNode  = if ($null -ne $sysNode) { $sysNode.SelectSingleNode('ssh') } else { $null }
    $sshPort  = XText $sshNode 'port'; if (-not $sshPort) { $sshPort = '22' }
    $mgmtPorts = @($guiPort, $sshPort)

    # Group floating rules first (pfSense evaluation order)
    $groups = [ordered]@{}
    $floatingList = New-Object 'System.Collections.Generic.List[object]'
    foreach ($r in $rules) {
        $ifKey = if (XHas $r 'floating') { '' } else { XText $r 'interface' }
        if (-not $ifKey) { [void]$floatingList.Add($r); continue }
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
            'wan'      { ' ' + (Badge 'UNTRUSTED / WAN' 'high' $true) }
            'vpn'      { ' ' + (Badge 'VPN' 'info' $true) }
            'floating' { ' ' + (Badge 'FLOATING' 'muted' $true) }
            'internal' { ' ' + (Badge 'TRUSTED / INTERNAL' 'ok' $true) }
            default    { '' }
        }
        $label = '<code class="mono">' + (E $key) + '</code>'
        if ($script:IfMap.ContainsKey($key) -and $script:IfMap[$key]) { $label += ' <span class="muted">&mdash; ' + (E $script:IfMap[$key]) + '</span>' }

        $sb = New-Object System.Text.StringBuilder
        $seq = 0
        $isFloatingGroup = ($key -eq '(floating)')
        foreach ($r in $groups[$key]) {
            $seq++
            $rowId    = 'row-fw-' + (Format-Slug $key) + '-' + $seq
            $disabled = XHas $r 'disabled'
            $type     = XText $r 'type'
            $ipDisp   = switch (XText $r 'ipprotocol') { 'inet' { 'IPv4' } 'inet6' { 'IPv6' } 'inet46' { 'IPv4+6' } default { if ($_) { $_ } else { 'IPv4' } } }
            $rawProto = XText $r 'protocol'; $protoClass = Get-ProtoClass $rawProto
            $proto    = if ($rawProto) { $rawProto } else { 'any' }
            if ($rawProto -in @('icmp', 'icmp6', 'ipv6-icmp')) { $it = XText $r 'icmptype'; if ($it) { $proto = "$rawProto/$it" } }

            $src = Format-Endpoint $r.SelectSingleNode('source')
            $dst = Format-Endpoint $r.SelectSingleNode('destination')
            $dir = XText $r 'direction'; if (-not $dir) { $dir = 'in' }
            $log = XHas $r 'log'; $descr = XText $r 'descr'; $sched = XText $r 'sched'

            $floatIfs = if ($isFloatingGroup) { XText $r 'interface' } else { '' }
            $floatingTouchesWan = $false
            if ($isFloatingGroup) {
                $floatingTouchesWan = (-not $floatIfs) -or (@($floatIfs -split ',' | Where-Object {
                    $fk = $_.Trim(); $fk -and $script:TrustMap.ContainsKey($fk) -and $script:TrustMap[$fk] -eq 'wan'
                }).Count -gt 0)
            }

            $dstIsSelf = ($dst.RawAddr -eq '(self)' -or $dst.RawAddr -eq 'wanip' -or (-not $isFloatingGroup -and $dst.RawAddr -eq ($key + 'ip')))
            $isMgmt    = $dstIsSelf -and (($dst.Port -in $mgmtPorts) -or (-not $dst.Port -and $protoClass -in @('tcpudp', 'any')))
            $where     = "Firewall / $key rule #$seq"
            $badges    = New-Object System.Text.StringBuilder
            $rowCls    = if ($disabled) { 'row-disabled' } else { '' }

            if ($disabled) { [void]$badges.Append((Badge 'DISABLED' 'muted' $true)).Append(' ') }
            if ($isFloatingGroup -and $floatIfs) { [void]$badges.Append((Badge ("IF: $floatIfs") 'muted')).Append(' ') }
            if ($isFloatingGroup -and (XHas $r 'quick')) { [void]$badges.Append((Badge 'QUICK' 'info' $true)).Append(' ') }
            if ($sched) { [void]$badges.Append((Badge ("SCHED: $sched") 'muted')).Append(' ') }

            if (-not $disabled) {
                $dstSvc = $dst.Addr + $(if ($dst.Port) { ':' + $dst.Port } else { '' })
                $exp = Get-RuleExposure -trust $trust -type $type -dir $dir -protoClass $protoClass `
                    -srcBroad (Test-Broad $src.Addr) -dstBroad (Test-Broad $dst.Addr) -dstPortSet ([bool]$dst.Port) `
                    -protoDisp $proto -dstSvc $dstSvc -isFirewallMgmt $isMgmt -floatingTouchesWan $floatingTouchesWan
                if ($null -ne $exp) {
                    $kind = switch ($exp.Sev) { 'high' { 'high' } 'warn' { 'warn' } default { 'info' } }
                    [void]$badges.Append((Badge $exp.Label $kind)).Append(' ')
                    if ($exp.Row -and -not $rowCls) { $rowCls = $exp.Row }
                    Add-Finding $exp.Sev $exp.Label $where ($(if ($descr) { $descr } else { '(no description)' }) + ' - ' + $exp.Detail) $rowId
                }
                if (-not $log) {
                    [void]$badges.Append((Badge 'NO LOG' 'muted' $true)).Append(' ')
                    if ($trust -in @('wan', 'floating') -or $type -in @('block', 'reject')) {
                        Add-Finding 'info' 'NO LOG' $where ($(if ($descr) { $descr } else { '(no description)' }) + ' - logging is disabled on this rule.') $rowId
                    }
                    else { $script:InternalNoLogCount++ }
                }
            }

            $actBadge = switch ($type) {
                'pass' { Badge 'PASS' 'ok' $true } 'block' { Badge 'BLOCK' 'muted' $true }
                'reject' { Badge 'REJECT' 'warn' $true } 'match' { Badge 'MATCH' 'info' $true }
                default { E $type }
            }
            $flagHtml = if ($badges.Length -gt 0) { '<div class="flagcell">' + $badges.ToString().Trim() + '</div>' } else { '' }
            Add-Row $sb -Id $rowId -Class $rowCls -Disabled $disabled -Cells @(
                [string]$seq, (YesNo (-not $disabled)), $actBadge, (E $ipDisp), (DashMono $proto),
                (Format-RefCell $src.Addr $src.Negated), (Format-RefCell $src.Port),
                (Format-RefCell $dst.Addr $dst.Negated), (Format-RefCell $dst.Port),
                (Format-GatewayRef (XText $r 'gateway')), (E $dir), (YesNo $log), ((Dash $descr) + $flagHtml)
            )
        }
        $cnt = $groups[$key].Count
        $tbl = Tbl @('#','Enabled','Action','IP','Protocol','Source','Src Port','Destination','Dst Port','Gateway','Dir','Log','Description / Flags') $sb.ToString() 'filterable-table'
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
    $mode = XText $nat 'outbound/mode'; if (-not $mode) { $mode = 'automatic' }
    [void]$out.Append('<h3>Outbound NAT</h3><p>Mode: ' + (Badge $mode.ToUpperInvariant() 'info') + '</p>')
    $obRules = XNodes $nat 'outbound/rule'
    if ($obRules.Count -gt 0) {
        $sb = New-Object System.Text.StringBuilder
        foreach ($r in $obRules) {
            $disabled = XHas $r 'disabled'
            $src = Format-Endpoint $r.SelectSingleNode('source'); $srcPort = XText $r 'sourceport'
            $dst = Format-Endpoint $r.SelectSingleNode('destination'); $dstPort = if ($dst.Port) { $dst.Port } else { XText $r 'dstport' }
            $proto = XText $r 'protocol'; if (-not $proto) { $proto = 'any' }
            if (XHas $r 'nonat') {
                $tgtCell = Badge 'DO NOT NAT' 'warn' $true
            }
            else {
                $tgt = XText $r 'targetip'
                if ($tgt) { $tsub = XText $r 'targetip_subnet'; if ($tsub) { $tgt += '/' + $tsub } } else { $tgt = XText $r 'target' }
                if (-not $tgt -or $tgt -eq 'other-subnet') { $tgt = 'Interface address' }
                $tgtCell = (DashMono $tgt) + $(if (XHas $r 'staticnatport') { ' ' + (Badge 'STATIC PORT' 'info' $true) } else { '' })
            }
            $srcCell = (Format-RefCell $src.Addr $src.Negated) + $(if ($srcPort) { ':<code class="mono">' + (E $srcPort) + '</code>' } else { '' })
            $dstCell = (Format-RefCell $dst.Addr $dst.Negated) + $(if ($dstPort) { ':<code class="mono">' + (E $dstPort) + '</code>' } else { '' })
            Add-Row $sb -Disabled $disabled -Cells @(
                (DashMono (XText $r 'interface')), (DashMono $proto), $srcCell, $dstCell, $tgtCell, (YesNo (-not $disabled)), (Dash (XText $r 'descr'))
            )
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
        $sb = New-Object System.Text.StringBuilder; $pfSeq = 0
        foreach ($r in $pf) {
            $pfSeq++; $rowId = "row-nat-pf-$pfSeq"
            $disabled = XHas $r 'disabled'; $noRdr = XHas $r 'nordr'
            $iface = XText $r 'interface'; $proto = XText $r 'protocol'; $target = XText $r 'target'; $locPort = XText $r 'local-port'; $descr = XText $r 'descr'
            $src = Format-Endpoint $r.SelectSingleNode('source'); $dst = Format-Endpoint $r.SelectSingleNode('destination')
            $extPort = if ($dst.Port) { $dst.Port } else { XText $r 'dstport' }

            $flags = New-Object System.Text.StringBuilder
            $rowCls = if ($disabled) { 'row-disabled' } else { '' }
            if ($noRdr) { [void]$flags.Append((Badge 'NO RDR' 'warn' $true)).Append(' ') }
            if (-not $disabled -and -not $noRdr -and (XText $r 'associated-rule-id') -ieq 'pass') {
                $isWan = $script:TrustMap.ContainsKey($iface) -and $script:TrustMap[$iface] -eq 'wan'
                $sev = if ($isWan -and (Test-Broad $src.Addr)) { 'warn' } else { 'info' }
                [void]$flags.Append((Badge 'INLINE PASS' $sev $true)).Append(' ')
                if ($sev -eq 'warn' -and -not $rowCls) { $rowCls = 'row-warn' }
                Add-Finding $sev 'NAT INLINE PASS' "NAT / Port Forward #$pfSeq" ("$(if ($descr) { $descr } else { '(no description)' }) - uses implicit 'pass' (bypasses explicit firewall rules) forwarding $($proto):$($extPort) -> $($target):$($locPort).") $rowId
            }
            $flagHtml = if ($flags.Length -gt 0) { '<div class="flagcell">' + $flags.ToString().Trim() + '</div>' } else { '' }
            Add-Row $sb -Id $rowId -Class $rowCls -Disabled $disabled -Cells @(
                (DashMono $iface), (DashMono $proto), (Format-RefCell $src.Addr $src.Negated),
                (Format-RefCell $dst.Addr $dst.Negated), (Format-RefCell $extPort), (Format-RefCell $target),
                (Format-RefCell $locPort), (YesNo (-not $disabled)), ((Dash $descr) + $flagHtml)
            )
        }
        [void]$out.Append((Tbl @('Interface','Protocol','Source','External addr','External port','Redirect target','Target port','Enabled','Description / Flags') $sb.ToString() 'filterable-table'))
    }
    else { [void]$out.Append('<p class="not-configured">No port forwards defined.</p>') }

    # 1:1 NAT
    $oto = XNodes $nat 'onetoone'
    if ($oto.Count -gt 0) {
        [void]$out.Append('<h3>1:1 NAT</h3>')
        $sb = New-Object System.Text.StringBuilder
        foreach ($r in $oto) {
            $disabled = XHas $r 'disabled'
            $src = Format-Endpoint $r.SelectSingleNode('source'); $dst = Format-Endpoint $r.SelectSingleNode('destination')
            $extCell = (DashMono (XText $r 'external')) + $(if (XHas $r 'nobinat') { ' ' + (Badge 'DO NOT BINAT' 'warn' $true) } else { '' })
            Add-Row $sb -Disabled $disabled -Cells @(
                (DashMono (XText $r 'interface')), $extCell, (Format-RefCell $src.Addr $src.Negated),
                (Format-RefCell $dst.Addr $dst.Negated), (YesNo (-not $disabled)), (Dash (XText $r 'descr'))
            )
        }
        [void]$out.Append((Tbl @('Interface','External IP','Internal (source)','Destination','Enabled','Description') $sb.ToString() 'filterable-table'))
    }
    return $out.ToString()
}

function Build-Ipsec {
    param($root)
    $ipsec = $root.SelectSingleNode('ipsec')
    if ($null -eq $ipsec) { return '' }
    $p1 = XNodes $ipsec 'phase1'; $p2 = XNodes $ipsec 'phase2'
    if ($p1.Count -eq 0 -and $p2.Count -eq 0) { return '' }
    $out = New-Object System.Text.StringBuilder

    if ($p1.Count -gt 0) {
        $sb = New-Object System.Text.StringBuilder; $p1Seq = 0
        foreach ($p in $p1) {
            $p1Seq++
            $ikeid = XText $p 'ikeid'; $rowId = 'row-ipsec-p1-' + $(if ($ikeid) { Format-Slug $ikeid } else { $p1Seq })
            $disabled = XHas $p 'disabled'; $iketype = XText $p 'iketype'; $mode = XText $p 'mode'
            $items = XNodes $p 'encryption/item'
            $proposals = if ($items.Count -gt 0) { $items } else { @($p) }
            $encDisplays = New-Object 'System.Collections.Generic.List[string]'
            $hashDisplays = New-Object 'System.Collections.Generic.List[string]'
            $dhDisplays = New-Object 'System.Collections.Generic.List[string]'
            $cryptoVals = New-Object 'System.Collections.Generic.List[string]'
            foreach ($prop in $proposals) {
                $ea = XText $prop 'encryption-algorithm/name'; $kl = XText $prop 'encryption-algorithm/keylen'
                $ha = XText $prop 'hash-algorithm'; $dh = XText $prop 'dhgroup'
                if ($ea) { [void]$encDisplays.Add($(if ($kl) { "$ea-$kl" } else { $ea })); [void]$cryptoVals.Add($ea) }
                if ($ha) { [void]$hashDisplays.Add($ha); [void]$cryptoVals.Add($ha) }
                if ($dh) { [void]$dhDisplays.Add($dh) }
            }

            $where = "IPsec P1 (IKE id $ikeid)"; $flags = New-Object System.Text.StringBuilder
            $rowCls = if ($disabled) { 'row-disabled' } else { '' }
            if (-not $disabled) {
                $rowCls = Add-CryptoFindings -CryptoValues $cryptoVals.ToArray() -DhGroups $dhDisplays.ToArray() -Where $where -RowId $rowId -Flags $flags
                if ($iketype -match '(?i)^(ikev1|auto)$') {
                    [void]$flags.Append((Badge 'IKEV1' 'warn' $true)).Append(' ')
                    if (-not $rowCls) { $rowCls = 'row-warn' }
                    Add-Finding 'warn' 'LEGACY IKEV1' $where ("Uses $iketype instead of IKEv2.") $rowId
                }
                if ($mode -ieq 'aggressive') {
                    [void]$flags.Append((Badge 'AGGRESSIVE MODE' 'high' $true)).Append(' ')
                    $rowCls = 'row-high'
                    Add-Finding 'high' 'AGGRESSIVE MODE' $where 'IKEv1 Aggressive Mode exposes PSK hashes to offline cracking.' $rowId
                }
            }

            $certRef = XText $p 'certref'
            $authCell = (Dash (XText $p 'authentication_method')) + $(if ($certRef) { '<br><span class="muted">Cert:</span> ' + (Format-CertRef $certRef) } else { '' })
            $flagHtml = if ($flags.Length -gt 0) { '<div class="flagcell">' + $flags.ToString().Trim() + '</div>' } else { '' }
            Add-Row $sb -Id $rowId -Class $rowCls -Disabled $disabled -Cells @(
                (DashMono $ikeid), ((Dash (XText $p 'descr')) + $flagHtml), (YesNo (-not $disabled)), (Dash $iketype),
                (DashMono (XText $p 'interface')), (DashMono (XText $p 'remote-gateway')),
                (DashMono (($encDisplays | Select-Object -Unique) -join ', ')), (DashMono (($hashDisplays | Select-Object -Unique) -join ', ')),
                (DashMono (($dhDisplays | Select-Object -Unique) -join ', ')), (DashMono (XText $p 'lifetime')),
                $authCell, (Secret (XText $p 'pre-shared-key'))
            )
        }
        [void]$out.Append('<h3>Phase 1 (IKE)</h3>').Append((Tbl @('IKE id','Description','Enabled','IKE','Interface','Peer / Remote GW','Encryption','Hash','DH group','Lifetime','Auth','Pre-shared key') $sb.ToString()))
    }

    if ($p2.Count -gt 0) {
        $sb = New-Object System.Text.StringBuilder; $p2Seq = 0
        foreach ($p in $p2) {
            $p2Seq++; $ikeid = XText $p 'ikeid'; $rowId = "row-ipsec-p2-$p2Seq"; $disabled = XHas $p 'disabled'
            $lid = $p.SelectSingleNode('localid'); $rid = $p.SelectSingleNode('remoteid')
            $local  = if (XText $lid 'address') { (XText $lid 'address') + $(if (XText $lid 'netbits') { '/' + (XText $lid 'netbits') } else { '' }) } else { XText $lid 'type' }
            $remote = if (XText $rid 'address') { (XText $rid 'address') + $(if (XText $rid 'netbits') { '/' + (XText $rid 'netbits') } else { '' }) } else { XText $rid 'type' }

            $encList = New-Object 'System.Collections.Generic.List[string]'
            $encNames = New-Object 'System.Collections.Generic.List[string]'
            foreach ($e in (XNodes $p 'encryption-algorithm-option')) {
                $n = XText $e 'name'; $kl = XText $e 'keylen'
                if ($n) { [void]$encNames.Add($n); [void]$encList.Add($(if ($kl) { "$n-$kl" } else { $n })) }
            }
            $hashList = @(foreach ($h in (XNodes $p 'hash-algorithm-option')) { if ($h.InnerText.Trim()) { $h.InnerText.Trim() } })
            $pfs = XText $p 'pfsgroup'

            $flags = New-Object System.Text.StringBuilder
            $rowCls = if ($disabled) { 'row-disabled' } else { '' }
            if (-not $disabled) {
                $rowCls = Add-CryptoFindings -CryptoValues (@($encNames.ToArray()) + $hashList) -DhGroups @($pfs) -IsPfs $true -Where "IPsec P2 (IKE id $ikeid)" -RowId $rowId -Flags $flags
            }
            $flagHtml = if ($flags.Length -gt 0) { '<div class="flagcell">' + $flags.ToString().Trim() + '</div>' } else { '' }
            Add-Row $sb -Id $rowId -Class $rowCls -Disabled $disabled -Cells @(
                (DashMono $ikeid), ((Dash (XText $p 'descr')) + $flagHtml), (YesNo (-not $disabled)), (Dash (XText $p 'mode')),
                (DashMono (XText $p 'protocol')), (DashMono $local), (DashMono $remote),
                (DashMono ($encList -join ', ')), (DashMono ($hashList -join ', ')), (DashMono $pfs), (DashMono (XText $p 'lifetime'))
            )
        }
        [void]$out.Append('<h3>Phase 2 (IPsec SA)</h3>').Append((Tbl @('IKE id','Description','Enabled','Mode','Protocol','Local network','Remote network','Encryption','Hash','PFS group','Lifetime') $sb.ToString()))
    }
    return $out.ToString()
}

function Format-OpenVpnRows {
    param($list, [bool]$isServer)
    $sb = New-Object System.Text.StringBuilder; $seq = 0
    $kind = if ($isServer) { 'server' } else { 'client' }
    foreach ($s in $list) {
        $seq++; $rowId = "row-ovpn-$kind-$seq"
        $disabled = (XHas $s 'disable') -or (XHas $s 'disabled')
        $desc = XText $s 'description'; $mode = XText $s 'mode'; $devMode = XText $s 'dev_mode'
        $endpoint = if ($isServer) { XText $s 'local_port' } else {
            $sa = XText $s 'server_addr'; $sp = XText $s 'server_port'
            if ($sa -and $sp) { "$sa`:$sp" } elseif ($sa) { $sa } elseif ($sp) { ":$sp" } else { '' }
        }
        $dc = XText $s 'data_ciphers'; $dcf = XText $s 'data_ciphers_fallback'; $legacy = XText $s 'crypto'; $digest = XText $s 'digest'; $comp = XText $s 'compression'
        $cipherDisp = if ($dc) { $dc } else { $legacy }
        if ($dcf) { $cipherDisp = if ($cipherDisp) { "$cipherDisp (fallback $dcf)" } else { $dcf } }

        $where = "OpenVPN $kind '" + $(if ($desc) { $desc } else { '(unnamed)' }) + "'"
        $flags = New-Object System.Text.StringBuilder
        $rowCls = if ($disabled) { 'row-disabled' } else { '' }
        if (XText $s 'tls') {
            $tm = XText $s 'tls_type'; if (-not $tm) { $tm = 'tls-auth' }
            [void]$flags.Append((Badge $tm.ToUpperInvariant() 'info')).Append(' ')
        }
        if (-not $disabled) {
            $rowCls = Add-CryptoFindings -CryptoValues @($dc, $dcf, $legacy, $digest) -Where $where -RowId $rowId -Flags $flags
            if ($comp -and $comp -notmatch '(?i)^(no|none|stub)$') {
                [void]$flags.Append((Badge 'COMPRESSION' 'warn' $true)).Append(' ')
                if (-not $rowCls) { $rowCls = 'row-warn' }
                Add-Finding 'warn' 'VPN COMPRESSION' $where ("Compression '$comp' is enabled (potential VORACLE side-channel risk).") $rowId
            }
        }

        $certref = XText $s 'certref'
        $caCell = (Format-CertRef (XText $s 'caref')) + $(if ($certref) { '<br><span class="muted">Cert:</span> ' + (Format-CertRef $certref) } else { '' })
        $flagHtml = if ($flags.Length -gt 0) { '<div class="flagcell">' + $flags.ToString().Trim() + '</div>' } else { '' }
        Add-Row $sb -Id $rowId -Class $rowCls -Disabled $disabled -Cells @(
            ((Dash $desc) + $flagHtml), (YesNo (-not $disabled)), (Dash $(if ($devMode) { "$mode ($devMode)" } else { $mode })),
            (DashMono (XText $s 'protocol')), (DashMono $endpoint), (DashMono (XText $s 'tunnel_network')),
            (DashMono (XText $s 'local_network')), (DashMono (XText $s 'remote_network')),
            (Dash (XText $s 'authmode')), (DashMono $cipherDisp), (DashMono $digest), $caCell
        )
    }
    return $sb.ToString()
}

function Build-OpenVpn {
    param($root)
    $ovpn = $root.SelectSingleNode('openvpn')
    if ($null -eq $ovpn) { return '' }
    $servers = XNodes $ovpn 'openvpn-server'; $clients = XNodes $ovpn 'openvpn-client'
    if ($servers.Count -eq 0 -and $clients.Count -eq 0) { return '' }
    $out = New-Object System.Text.StringBuilder
    if ($servers.Count -gt 0) {
        [void]$out.Append('<h3>OpenVPN Servers</h3>').Append((Tbl @('Description','Enabled','Mode','Protocol','Port','Tunnel network','Local network','Remote network','Auth','Cipher','Digest','CA / Cert') (Format-OpenVpnRows $servers $true)))
    }
    if ($clients.Count -gt 0) {
        [void]$out.Append('<h3>OpenVPN Clients</h3>').Append((Tbl @('Description','Enabled','Mode','Protocol','Server','Tunnel network','Local network','Remote network','Auth','Cipher','Digest','CA / Cert') (Format-OpenVpnRows $clients $false)))
    }
    [void]$out.Append('<p class="note">OpenVPN TLS static keys are never exported by this report, regardless of options.</p>')
    return $out.ToString()
}

function Build-WireGuard {
    param($root)
    $wg = $root.SelectSingleNode('installedpackages/wireguard')
    if ($null -eq $wg) { $wg = $root.SelectSingleNode('wireguard') }
    if ($null -eq $wg) { return '' }
    $tunnels = XNodes $wg 'tunnels/item'; $peers = XNodes $wg 'peers/item'
    if ($tunnels.Count -eq 0 -and $peers.Count -eq 0) { return '' }

    $out = New-Object System.Text.StringBuilder
    if ($tunnels.Count -gt 0) {
        $sb = New-Object System.Text.StringBuilder
        foreach ($t in $tunnels) {
            $en = Test-XmlEnabled $t @('enabled')
            $addrs = @(foreach ($a in (XNodes $t 'addresses/row')) {
                $ad = XText $a 'address'; $mk = XText $a 'mask'; if ($ad) { if ($mk) { "$ad/$mk" } else { $ad } }
            })
            Add-Row $sb -Disabled (-not $en) -Cells @(
                (DashMono (XText $t 'name')), (YesNo $en), (DashMono (XText $t 'listenport')), (Format-ListCell $addrs -Mode 'mono'), (Dash (XText $t 'descr'))
            )
        }
        [void]$out.Append('<h3>WireGuard Tunnels</h3>').Append((Tbl @('Tunnel','Enabled','Listen Port','Addresses','Description') $sb.ToString()))
    }
    if ($peers.Count -gt 0) {
        $sb = New-Object System.Text.StringBuilder
        foreach ($p in $peers) {
            $en = Test-XmlEnabled $p @('enabled')
            $ep = XText $p 'endpoint'; $pt = XText $p 'port'; if ($ep -and $pt) { $ep = "$ep`:$pt" }
            $allowed = @(foreach ($a in (XNodes $p 'allowedips/row')) {
                $ad = XText $a 'address'; $mk = XText $a 'mask'; if ($ad) { if ($mk) { "$ad/$mk" } else { $ad } }
            })
            Add-Row $sb -Disabled (-not $en) -Cells @(
                (DashMono (XText $p 'tun')), (YesNo $en), (DashMono $ep), (Format-ListCell $allowed -Mode 'mono'),
                (YesNo (-not [string]::IsNullOrWhiteSpace((XText $p 'presharedkey')))), (Dash (XText $p 'descr'))
            )
        }
        [void]$out.Append('<h3>WireGuard Peers</h3>').Append((Tbl @('Tunnel','Enabled','Endpoint','Allowed IPs','PSK Set','Description') $sb.ToString()))
    }
    [void]$out.Append('<p class="note">WireGuard private keys and preshared keys are never exported by this report, regardless of options.</p>')
    return $out.ToString()
}

function Build-HighAvailability {
    param($root)
    $ha = $root.SelectSingleNode('hasync')
    if ($null -eq $ha) { return '' }
    $pfsync = XHas $ha 'pfsyncenabled'; $pfIf = XText $ha 'pfsyncinterface'; $syncTo = XText $ha 'synchronizetoip'
    if (-not $pfsync -and -not $syncTo -and -not $pfIf) { return '' }
    $synced = @(foreach ($child in $ha.ChildNodes) {
        if ($child.NodeType -eq [System.Xml.XmlNodeType]::Element -and $child.Name -like 'synchronize*' -and $child.Name -ne 'synchronizetoip') {
            $child.Name -replace '^synchronize', ''
        }
    })
    return (Format-KvTable @(
        @('pfsync State Sync',     (YesNo $pfsync)),
        @('pfsync Interface',      (DashMono $pfIf)),
        @('pfsync Peer IP',        (DashMono (XText $ha 'pfsyncpeerip'))),
        @('XMLRPC Sync Target IP', (DashMono $syncTo)),
        @('XMLRPC Username',       (E-User (XText $ha 'username'))),
        @('XMLRPC Password',       ('<span class="muted">' + $(if (XText $ha 'password') { '[password not shown]' } else { '[none]' }) + '</span>')),
        @('Synced Sections',       (Format-ListCell $synced -Separator ', '))
    ))
}

function Build-Dhcp {
    param($root)
    $out = New-Object System.Text.StringBuilder; $any = $false
    foreach ($spec in @(@{ Tag = 'dhcpd'; Label = 'DHCPv4' }, @{ Tag = 'dhcpdv6'; Label = 'DHCPv6' })) {
        $node = $root.SelectSingleNode($spec.Tag)
        if ($null -eq $node) { continue }
        foreach ($ifNode in $node.ChildNodes) {
            if ($ifNode.NodeType -ne [System.Xml.XmlNodeType]::Element) { continue }
            $any = $true; $key = $ifNode.Name
            $friendly = if ($script:IfMap.ContainsKey($key)) { "$key &mdash; $($script:IfMap[$key])" } else { $key }
            $ranges = New-Object 'System.Collections.Generic.List[string]'
            $from = XText $ifNode 'range/from'; $to = XText $ifNode 'range/to'
            if ($from -or $to) { [void]$ranges.Add("$from - $to") }
            foreach ($pool in (XNodes $ifNode 'pool')) {
                $pf = XText $pool 'range/from'; $pt = XText $pool 'range/to'
                if ($pf -or $pt) { [void]$ranges.Add("$pf - $pt (pool)") }
            }
            $dns = @(foreach ($d in (XNodes $ifNode 'dnsserver')) { $d.InnerText.Trim() })
            $dlt = XText $ifNode 'defaultleasetime'; $mlt = XText $ifNode 'maxleasetime'
            $kvHtml = Format-KvTable @(
                @('Enabled',              (YesNo (XHas $ifNode 'enable'))),
                @('Pool range(s)',        (Format-ListCell $ranges.ToArray() -Mode 'mono')),
                @('DNS servers',          (Format-ListCell $dns -Mode 'mono')),
                @('Gateway',              (DashMono (XText $ifNode 'gateway'))),
                @('Domain',               (Dash (XText $ifNode 'domain'))),
                @('Deny unknown clients', (YesNo (XHas $ifNode 'denyunknown'))),
                @('Default / Max lease',  (DashMono $(if ($dlt -or $mlt) { "$dlt / $mlt" } else { '' })))
            )
            [void]$out.Append('<h3 class="iface-head">' + (E $friendly) + ' ' + (Badge $spec.Label 'info' $true) + '</h3>' + $kvHtml)

            $smaps = XNodes $ifNode 'staticmap'
            if ($smaps.Count -gt 0) {
                $sb = New-Object System.Text.StringBuilder
                $isV6 = ($spec.Tag -eq 'dhcpdv6')
                foreach ($m in $smaps) {
                    Add-Row $sb @(
                        (DashMono (XText $m $(if ($isV6) { 'duid' } else { 'mac' }))),
                        (DashMono (XText $m $(if ($isV6) { 'ipaddrv6' } else { 'ipaddr' }))),
                        (E-Host (XText $m 'hostname')), (DashMono (XText $m 'cid')), (Dash (XText $m 'descr'))
                    )
                }
                $idHdr = if ($isV6) { 'DUID' } else { 'MAC' }
                [void]$out.Append('<p class="subtitle">Static mappings (' + $smaps.Count + ')</p>' + (Tbl @($idHdr,'IP address','Hostname','Client ID','Description') $sb.ToString() 'filterable-table'))
            }
        }
    }
    foreach ($rSpec in @(@{ Tag = 'dhcrelay'; Label = 'DHCPv4 Relay' }, @{ Tag = 'dhcrelay6'; Label = 'DHCPv6 Relay' })) {
        $rel = $root.SelectSingleNode($rSpec.Tag)
        if ($null -ne $rel -and (XHas $rel 'enable')) {
            $any = $true
            [void]$out.Append('<h3>' + $rSpec.Label + '</h3>' + (Format-KvTable @(
                @('Enabled', (YesNo $true)), @('Interfaces', (DashMono (XText $rel 'interface'))), @('Destination Server(s)', (DashMono (XText $rel 'server')))
            )))
        }
    }
    if (-not $any) { return '' }
    return $out.ToString()
}

function Build-DnsOverrides {
    param($parentNode, [bool]$IncludeAliases = $false)
    $out = New-Object System.Text.StringBuilder
    $hosts = XNodes $parentNode 'hosts'
    if ($hosts.Count -gt 0) {
        $sb = New-Object System.Text.StringBuilder
        foreach ($h in $hosts) {
            if ($IncludeAliases) {
                $alItems = @(foreach ($al in (XNodes $h 'aliases/item')) {
                    $ah = XText $al 'host'; $ad = XText $al 'domain'
                    if ($ah -and $ad) { "$ah.$ad" } elseif ($ah) { $ah }
                })
                Add-Row $sb @((E-Host (XText $h 'host')), (Dash (XText $h 'domain')), (DashMono (XText $h 'ip')), (Format-ListCell $alItems -Mode 'host'), (Dash (XText $h 'descr')))
            }
            else {
                Add-Row $sb @((E-Host (XText $h 'host')), (Dash (XText $h 'domain')), (DashMono (XText $h 'ip')), (Dash (XText $h 'descr')))
            }
        }
        $hdrs = if ($IncludeAliases) { @('Host','Domain','IP','Aliases','Description') } else { @('Host','Domain','IP','Description') }
        [void]$out.Append('<p class="subtitle">Host overrides (' + $hosts.Count + ')</p>' + (Tbl $hdrs $sb.ToString() 'filterable-table'))
    }
    $doms = XNodes $parentNode 'domainoverrides'
    if ($doms.Count -gt 0) {
        $sb = New-Object System.Text.StringBuilder
        foreach ($d in $doms) { Add-Row $sb @((Dash (XText $d 'domain')), (DashMono (XText $d 'ip')), (Dash (XText $d 'descr'))) }
        [void]$out.Append('<p class="subtitle">Domain overrides (' + $doms.Count + ')</p>' + (Tbl @('Domain','Forward-to IP','Description') $sb.ToString() 'filterable-table'))
    }
    return $out.ToString()
}

function Build-Dns {
    param($root)
    $out = New-Object System.Text.StringBuilder
    $unbound = $root.SelectSingleNode('unbound')
    [void]$out.Append('<h3>DNS Resolver (Unbound)</h3>')
    if ($null -eq $unbound) {
        [void]$out.Append('<p class="not-configured">Not configured.</p>')
    }
    else {
        $ai = XText $unbound 'active_interface';   if (-not $ai) { $ai = 'All' }
        $oi = XText $unbound 'outgoing_interface'; if (-not $oi) { $oi = 'All' }
        [void]$out.Append((Format-KvTable @(
            @('Enabled',                       (YesNo (XHas $unbound 'enable'))),
            @('Listening interfaces',          (DashMono $ai)),
            @('Outgoing interfaces',           (DashMono $oi)),
            @('DNSSEC',                        (YesNo (XHas $unbound 'dnssec'))),
            @('Forwarding mode',               (YesNo (XHas $unbound 'forwarding'))),
            @('Register DHCP leases / static', ((YesNo (XHas $unbound 'regdhcp')) + ' / ' + (YesNo (XHas $unbound 'regdhcpstatic'))))
        )))
        [void]$out.Append((Build-DnsOverrides $unbound $true))
    }

    $dnsmasq = $root.SelectSingleNode('dnsmasq')
    [void]$out.Append('<h3>DNS Forwarder (dnsmasq)</h3>')
    if ($null -eq $dnsmasq -or -not (XHas $dnsmasq 'enable')) {
        [void]$out.Append('<p class="not-configured">Not enabled.</p>')
    }
    else {
        $dmIf = XText $dnsmasq 'interface'; if (-not $dmIf) { $dmIf = 'All' }
        [void]$out.Append((Format-KvTable @(@('Enabled', (YesNo $true)), @('Interfaces', (DashMono $dmIf)))))
        [void]$out.Append((Build-DnsOverrides $dnsmasq $false))
    }
    return $out.ToString()
}

function Build-CertRows {
    param($nodes, [bool]$IsCa)
    $sb = New-Object System.Text.StringBuilder
    $prefix = if ($IsCa) { 'ca-' } else { 'cert-' }
    $kindLabel = if ($IsCa) { 'CA' } else { 'Certificate' }
    foreach ($c in $nodes) {
        $rid = XText $c 'refid'; $rowId = $prefix + (Format-Slug $rid); $descr = XText $c 'descr'
        $info = Get-CertInfo (XText $c 'crt')
        $status = Format-CertStatus $info ("$kindLabel '" + $(if ($descr) { $descr } else { $rid }) + "'") $rowId
        $nb = if ($info.NotBefore) { $info.NotBefore.ToString('yyyy-MM-dd') } else { '' }
        $na = if ($info.NotAfter)  { $info.NotAfter.ToString('yyyy-MM-dd') }  else { '' }
        $keyInfo = if ($info.KeyAlg -and $info.KeySize) { "$($info.KeyAlg) $($info.KeySize)b" } else { '' }
        $algDisp = if ($info.SigAlg -and $keyInfo) { "$($info.SigAlg) / $keyInfo" } elseif ($info.SigAlg) { $info.SigAlg } else { $keyInfo }
        $valCell = if ($nb -or $na) { '<code class="mono">' + (E $nb) + '</code> &rarr; <code class="mono">' + (E $na) + '</code>' } else { '<span class="muted">&mdash;</span>' }
        $typeDisp = if ($IsCa) { 'Certificate Authority' } else {
            $t = XText $c 'type'
            $td = switch ($t) { 'server' { 'Server' } 'user' { 'User' } default { if ($t) { $t } else { 'Unknown' } } }
            if ($info.SelfSigned) { "$td (Self-signed)" } else { $td }
        }
        $uses = @()
        if ($rid -and $script:RefUsageMap.ContainsKey($rid)) { $uses = @($script:RefUsageMap[$rid]) }
        $usedBy = if ($uses.Count -gt 0) { ($uses | ForEach-Object { E $_ }) -join '<br>' } else { '<span class="muted">Not referenced</span>' }
        Add-Row $sb -Id $rowId -Cells @(
            (Dash $descr), (E $typeDisp), ('<td class="wrapcell">' + (E-CertDn $info.Subject) + '</td>'),
            (DashMono $algDisp), $valCell, $status, $usedBy
        )
    }
    return (Tbl @('Name','Type','Subject','Sig / Key','Validity','Status','Used by') $sb.ToString())
}

function Build-Certs {
    param($root)
    $cas = XNodes $root 'ca'; $certs = XNodes $root 'cert'; $crls = XNodes $root 'crl'
    if ($cas.Count -eq 0 -and $certs.Count -eq 0 -and $crls.Count -eq 0) { return '' }
    $out = New-Object System.Text.StringBuilder
    if ($cas.Count -gt 0)   { [void]$out.Append('<h3>Certificate Authorities</h3>').Append((Build-CertRows $cas $true)) }
    if ($certs.Count -gt 0) { [void]$out.Append('<h3>Certificates</h3>').Append((Build-CertRows $certs $false)) }
    if ($crls.Count -gt 0) {
        $sb = New-Object System.Text.StringBuilder
        foreach ($crl in $crls) {
            Add-Row $sb @((Dash (XText $crl 'descr')), (Format-CertRef (XText $crl 'caref')), (Dash (XText $crl 'method')), [string](XNodes $crl 'cert').Count)
        }
        [void]$out.Append('<h3>Certificate Revocation Lists (CRLs)</h3>').Append((Tbl @('Name','CA','Method','Revoked Certs') $sb.ToString()))
    }
    [void]$out.Append('<p class="note">Private key material is never exported by this report, regardless of options.</p>')
    return $out.ToString()
}

function Build-Users {
    param($root)
    $sys = $root.SelectSingleNode('system')
    if ($null -eq $sys) { return '' }
    $users = XNodes $sys 'user'; $groups = XNodes $sys 'group'; $auths = XNodes $sys 'authserver'
    if ($users.Count -eq 0 -and $groups.Count -eq 0 -and $auths.Count -eq 0) { return '' }

    $uidMap = @{}; $uidGroups = @{}
    foreach ($u in $users) { $uid = XText $u 'uid'; if ($uid -ne '') { $uidMap[$uid] = XText $u 'name' } }
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
        $sb = New-Object System.Text.StringBuilder
        foreach ($u in $users) {
            $uname = XText $u 'name'; $uid = XText $u 'uid'
            $rowId = 'row-user-' + (Format-Slug $(if ($uname) { $uname } else { $uid }))
            $disabled = XHas $u 'disabled'; $authKeys = XText $u 'authorizedkeys'; $keyCount = 0
            if ($authKeys) {
                try {
                    $decoded = [System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String(($authKeys -replace '\s', '')))
                    $keyCount = @($decoded -split "`r?`n" | Where-Object { $_.Trim() -and -not $_.Trim().StartsWith('#') }).Count
                }
                catch { Write-Verbose ("Could not decode authorizedkeys for '{0}': {1}" -f $uname, $_.Exception.Message); $keyCount = 1 }
            }
            $privs = @(foreach ($p in (XNodes $u 'priv')) { $p.InnerText.Trim() })
            $gList = New-Object 'System.Collections.Generic.List[string]'
            $gProp = XText $u 'groupname'; if ($gProp) { [void]$gList.Add($gProp) }
            if ($uid -ne '' -and $uidGroups.ContainsKey($uid)) {
                foreach ($gn in $uidGroups[$uid]) { if (-not $gList.Contains($gn)) { [void]$gList.Add($gn) } }
            }
            $hashType = if (XHas $u 'bcrypt-hash') { 'bcrypt' } elseif (XHas $u 'sha512-hash') { 'sha512' } elseif (XHas $u 'md5-hash') { 'md5' } else { '' }
            $hashBadge = ''
            if ($hashType -eq 'md5' -and -not $disabled) {
                $hashBadge = ' ' + (Badge 'WEAK HASH' 'high' $true)
                Add-Finding 'high' 'WEAK PASSWORD HASH' ("User '$uname'") 'Account uses legacy MD5 password hash instead of bcrypt.' $rowId
            }
            Add-Row $sb -Id $rowId -Disabled $disabled -Cells @(
                (E-User $uname), (YesNo (-not $disabled)), (Dash (XText $u 'descr')), (Dash (XText $u 'scope')),
                (Format-ListCell $gList.ToArray() -Separator ', '), (Format-ListCell $privs),
                $(if ($keyCount -gt 0) { Badge "$keyCount key(s)" 'info' $true } else { '<span class="muted">&mdash;</span>' }),
                (Dash (XText $u 'expires')),
                ('<span class="muted">' + $(if ($hashType) { "[$hashType hash not shown]" } else { '[none]' }) + '</span>' + $hashBadge)
            )
        }
        [void]$out.Append('<h3>Users</h3>').Append((Tbl @('Username','Enabled','Full name','Scope','Groups','Privileges','SSH Keys','Expires','Password') $sb.ToString()))
        [void]$out.Append('<p class="note">Password hashes and SSH key bodies are never exported by this report, regardless of options.</p>')
    }

    if ($groups.Count -gt 0) {
        $sb = New-Object System.Text.StringBuilder
        foreach ($g in $groups) {
            $privs = @(foreach ($p in (XNodes $g 'priv')) { $p.InnerText.Trim() })
            $members = @(foreach ($m in (XNodes $g 'member')) {
                $mv = $m.InnerText.Trim()
                if ($uidMap.ContainsKey($mv)) { $uidMap[$mv] } elseif ($mv) { "uid:$mv" }
            })
            Add-Row $sb @((Dash (XText $g 'name')), (Dash (XText $g 'description')), (Dash (XText $g 'scope')), (Format-ListCell $members -Mode 'user'), (Format-ListCell $privs))
        }
        [void]$out.Append('<h3>Groups</h3>').Append((Tbl @('Group','Description','Scope','Members','Privileges') $sb.ToString()))
    }

    if ($auths.Count -gt 0) {
        $sb = New-Object System.Text.StringBuilder; $aSeq = 0
        foreach ($a in $auths) {
            $aSeq++; $rowId = "row-auth-$aSeq"
            $aname = XText $a 'name'; $atype = XText $a 'type'
            $port  = if ($atype -ieq 'ldap') { XText $a 'ldap_port' } else { XText $a 'radius_auth_port' }
            $trans = if ($atype -ieq 'ldap') { XText $a 'ldap_urltype' } else { 'RADIUS' }
            $badge = ''; $rowCls = ''
            if ($atype -ieq 'ldap' -and $trans -match '(?i)standard\s*tcp') {
                $badge = ' ' + (Badge 'PLAINTEXT LDAP' 'high' $true); $rowCls = 'row-high'
                Add-Finding 'high' 'PLAINTEXT LDAP' ("Auth server '$aname'") 'LDAP server uses unencrypted Standard TCP instead of SSL/TLS or STARTTLS.' $rowId
            }
            Add-Row $sb -Id $rowId -Class $rowCls -Cells @(
                ((Dash $aname) + $badge), (Dash $atype.ToUpperInvariant()), (DashMono (XText $a 'host')),
                (DashMono $port), (Dash $trans), '<span class="muted">[credentials not shown]</span>'
            )
        }
        [void]$out.Append('<h3>Authentication Servers (LDAP / RADIUS)</h3>').Append((Tbl @('Name','Type','Host','Port','Transport','Secrets') $sb.ToString()))
    }
    return $out.ToString()
}

function Build-Aliases {
    param($root)
    $aliases = XNodes $root 'aliases/alias'
    if ($aliases.Count -eq 0) { return '' }
    $sb = New-Object System.Text.StringBuilder
    foreach ($a in $aliases) {
        $name = XText $a 'name'; $addr = XText $a 'address'; $url = XText $a 'url'; $freq = XText $a 'updatefreq'
        $detail = XText $a 'detail'
        $detArr = @(); if ($detail) { $detArr = @($detail -split '\|\|') }
        $addrDisp = '<span class="muted">&mdash;</span>'
        if ($addr) {
            $entries = @($addr -split '\s+' | Where-Object { $_ })
            $lines = @(for ($i = 0; $i -lt $entries.Count; $i++) {
                (DashMono $entries[$i]) + $(if ($i -lt $detArr.Count -and -not [string]::IsNullOrWhiteSpace($detArr[$i])) { ' <span class="muted">&mdash; ' + (E $detArr[$i].Trim()) + '</span>' } else { '' })
            })
            $addrDisp = $lines -join '<br>'
        }
        elseif ($url) {
            $addrDisp = (DashMono $url) + $(if ($freq) { ' <span class="muted">(every ' + (E $freq) + 'd)</span>' } else { '' })
        }
        Add-Row $sb -Id $(if ($name) { 'alias-' + (Format-Slug $name) } else { '' }) -Cells @(
            (DashMono $name), (Dash (XText $a 'type')), ('<td class="wrapcell">' + $addrDisp + '</td>'), (Dash (XText $a 'descr'))
        )
    }
    return (Tbl @('Name','Type','Contents','Description') $sb.ToString() 'filterable-table')
}

function Build-Services {
    param($root)
    $out = New-Object System.Text.StringBuilder

    $snmp = $root.SelectSingleNode('snmpd')
    if ($null -ne $snmp -and ((XHas $snmp 'enable') -or (XText $snmp 'rocommunity'))) {
        $en = XHas $snmp 'enable'; $comm = XText $snmp 'rocommunity'
        $bind = XText $snmp 'bindip';   if (-not $bind) { $bind = 'All' }
        $port = XText $snmp 'pollport'; if (-not $port) { $port = '161 (default)' }
        $commBadge = ''
        if ($en -and $comm -match '(?i)^(public|private)$') {
            $commBadge = ' ' + (Badge 'DEFAULT COMMUNITY' 'high' $true)
            Add-Finding 'high' 'DEFAULT SNMP COMMUNITY' 'Services / SNMP' 'SNMP is enabled with a default community string (public/private).' 'row-svc-snmp'
        }
        $rows = New-Object 'System.Collections.Generic.List[object]'
        foreach ($r in @(
            @('Enabled',             (YesNo $en), 'row-svc-snmp'),
            @('Bind interface / IP', (DashMono $bind)),
            @('Polling port',        (DashMono $port)),
            @('Read-only community', ((Secret $comm) + $commBadge))
        )) { [void]$rows.Add($r) }
        $trap = XText $snmp 'trapserver'; if ($trap) { [void]$rows.Add(@('Trap server', (DashMono $trap))) }
        [void]$out.Append('<h3>SNMP</h3>').Append((Format-KvTable $rows.ToArray()))
    }

    $syslog = $root.SelectSingleNode('syslog')
    if ($null -ne $syslog -and ((XHas $syslog 'enable') -or (XText $syslog 'remoteserver'))) {
        $svrs = @((XText $syslog 'remoteserver'), (XText $syslog 'remoteserver2'), (XText $syslog 'remoteserver3'))
        [void]$out.Append('<h3>Syslog</h3>').Append((Format-KvTable @(
            @('Remote logging enabled', (YesNo (XHas $syslog 'enable'))),
            @('Remote server(s)',       (Format-ListCell $svrs -Mode 'mono')),
            @('Source interface',       (DashMono (XText $syslog 'sourceip'))),
            @('Log default blocks',     (YesNo (-not (XHas $syslog 'nologdefaultblock'))))
        )))
    }

    $ddns = XNodes $root 'dyndnses/dyndns'
    if ($ddns.Count -gt 0) {
        $sb = New-Object System.Text.StringBuilder
        foreach ($d in $ddns) {
            $en = XHas $d 'enable'
            Add-Row $sb -Disabled (-not $en) -Cells @((Dash (XText $d 'type')), (DashMono (XText $d 'interface')), (DashMono (XText $d 'host')), (YesNo $en), (Dash (XText $d 'descr')))
        }
        [void]$out.Append('<h3>Dynamic DNS</h3>').Append((Tbl @('Service','Interface','Hostname','Enabled','Description') $sb.ToString()))
        [void]$out.Append('<p class="note">Dynamic DNS passwords and API tokens are never exported.</p>')
    }

    $scheds = XNodes $root 'schedules/schedule'
    if ($scheds.Count -gt 0) {
        $sb = New-Object System.Text.StringBuilder
        foreach ($s in $scheds) { Add-Row $sb @((DashMono (XText $s 'name')), (Dash (XText $s 'descr'))) }
        [void]$out.Append('<h3>Schedules</h3>').Append((Tbl @('Name','Description') $sb.ToString()))
    }
    return $out.ToString()
}

function Build-Packages {
    param($root)
    $pkgs = XNodes $root 'installedpackages/package'
    if ($pkgs.Count -eq 0) { return '' }
    $sb = New-Object System.Text.StringBuilder
    foreach ($p in $pkgs) { Add-Row $sb @((Dash (XText $p 'name')), (DashMono (XText $p 'version')), (Dash (XText $p 'descr'))) }
    return (Tbl @('Package','Version','Description') $sb.ToString() 'filterable-table')
}

function Build-Revision {
    param($root)
    $rev = $root.SelectSingleNode('revision'); $lc = XText $root 'lastchange'
    if ($null -eq $rev -and -not $lc) { return '' }
    $rows = New-Object 'System.Collections.Generic.List[object]'
    if ($null -ne $rev) {
        [void]$rows.Add(@('Last change time', (DashMono (ConvertFrom-Epoch (XText $rev 'time')))))
        [void]$rows.Add(@('Description',      (Dash (XText $rev 'description'))))
        [void]$rows.Add(@('Changed by',       (E-User (XText $rev 'username'))))
    }
    if ($lc) { [void]$rows.Add(@('lastchange', (DashMono (ConvertFrom-Epoch $lc)))) }
    return (Format-KvTable $rows.ToArray())
}

function Build-Findings {
    if ($script:Findings.Count -eq 0) {
        return '<p class="all-clear">No automated risk flags were raised. (This is a heuristic scan, not a substitute for a full security review.)</p>'
    }
    $sevRank = @{ 'high' = 0; 'warn' = 1; 'info' = 2 }
    $ordered = @($script:Findings | Sort-Object @{ Expression = { $sevRank[$_.Sev] } }, Label, Where)
    $byKey   = @($ordered | Group-Object { $_.Sev + '|' + $_.Label } | Sort-Object @{ Expression = { $sevRank[$_.Group[0].Sev] } }, { $_.Group[0].Label })

    $cards = New-Object System.Text.StringBuilder
    [void]$cards.Append('<div class="finding-cards" role="group" aria-label="Filter findings by type">')
    [void]$cards.Append('<button type="button" class="fcard fcard-all is-active" data-sev="all" data-label="all"><div class="fnum">' + $ordered.Count + '</div><div class="flbl">ALL FLAGS</div></button>')
    foreach ($g in $byKey) {
        $sev = ($g.Group[0]).Sev; $lbl = ($g.Group[0]).Label
        [void]$cards.Append('<button type="button" class="fcard fcard-' + $sev + '" data-sev="' + $sev + '" data-label="' + [System.Net.WebUtility]::HtmlEncode($lbl) + '"><div class="fnum">' + $g.Count + '</div><div class="flbl">' + (E $lbl) + '</div></button>')
    }
    [void]$cards.Append('</div>')

    $sb = New-Object System.Text.StringBuilder
    foreach ($f in $ordered) {
        $kind = switch ($f.Sev) { 'high' { 'high' } 'warn' { 'warn' } default { 'info' } }
        $locCell = if ($f.TargetId) { '<a class="xref finding-jump" href="#' + $f.TargetId + '">' + (E $f.Where) + '</a>' } else { E $f.Where }
        $extra = 'data-sev="' + $f.Sev + '" data-label="' + [System.Net.WebUtility]::HtmlEncode($f.Label) + '"'
        Add-Row $sb -ExtraAttr $extra -Cells @((Badge $f.Label $kind), $locCell, (E $f.Detail))
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
.card .n.sev-high{color:var(--high)} .card .n.sev-warn{color:var(--warn)}
.card .n.sev-info{color:var(--info)} .card .n.sev-ok{color:var(--ok)}
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
thead th{position:sticky;top:0;background:var(--brand);color:#fff;text-align:left;padding:8px 10px;font-weight:600;white-space:nowrap;z-index:2}
tbody td{padding:7px 10px;border-top:1px solid var(--line);vertical-align:top}
tbody tr:nth-child(even){background:var(--row-alt)}
tbody tr:hover{background:var(--row-hover)}
table.kv th{position:static;background:var(--kv-bg);color:var(--ink);width:240px;font-weight:600;border-top:1px solid var(--line);text-align:left;padding:8px 10px}
table.kv td{border-top:1px solid var(--line);padding:8px 10px}
.wrapcell{max-width:360px;word-break:break-word}
.flagcell{margin-top:4px;display:flex;flex-wrap:wrap;gap:4px}
.mono{font-family:ui-monospace,SFMono-Regular,Menlo,Monaco,Consolas,"Liberation Mono",monospace;font-size:12px;background:var(--code-bg);padding:1px 4px;border-radius:4px}
a.xref{border-bottom:1px dotted var(--brand2)}
a.xref:hover{text-decoration:none;border-bottom-style:solid}

/* Secret reveal */
.secret-wrap{display:inline-flex;align-items:center;gap:6px;flex-wrap:wrap}
.secret-val.is-masked{filter:blur(5px);user-select:none}
.secret-btn{font-size:11px;padding:1px 7px;border-radius:5px;border:1px solid var(--line);background:var(--panel-alt);color:var(--ink);cursor:pointer}
.secret-btn:hover{background:var(--row-hover)}

/* States & Badges */
.row-disabled{opacity:.62} .row-disabled td{background:var(--panel-alt)}
.row-high td{background:var(--high-bg) !important} .row-warn td{background:var(--warn-bg) !important}
.row-hidden{display:none !important}
.row-flash td{animation:flashRow 1.8s ease-out}
@keyframes flashRow{0%{outline:2px solid var(--accent);background:var(--info-bg)}100%{outline:none}}
.muted{color:var(--muted)}
.redacted{color:var(--high);font-weight:600;font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;font-size:12px}
.note{font-size:12px;color:var(--muted);margin:6px 0 0}
.not-configured{color:var(--muted);font-style:italic;background:var(--panel-alt);border:1px dashed var(--line);padding:10px 14px;border-radius:8px;margin:0}
.all-clear{color:var(--ok);background:var(--ok-bg);border:1px solid var(--ok-bd);padding:12px 16px;border-radius:8px}
.badge{display:inline-block;padding:1px 7px;border-radius:11px;font-size:11px;font-weight:700;letter-spacing:.3px;white-space:nowrap;line-height:1.6}
.badge-high{background:var(--high-bg);color:var(--high);border:1px solid var(--high-bd)}
.badge-warn{background:var(--warn-bg);color:var(--warn);border:1px solid var(--warn-bd)}
.badge-ok{background:var(--ok-bg);color:var(--ok);border:1px solid var(--ok-bd)}
.badge-info{background:var(--info-bg);color:var(--info);border:1px solid var(--info-bd)}
.badge-muted{background:var(--muted-bg);color:var(--mutedb);border:1px solid var(--muted-bd)}

/* Findings cards & Banners */
.finding-cards{display:flex;flex-wrap:wrap;gap:10px;margin-bottom:14px}
.fcard{border-radius:10px;padding:10px 14px;min-width:118px;border:1px solid var(--line);background:var(--panel-alt);text-align:left;cursor:pointer;font-family:inherit;color:var(--ink)}
.fcard:hover{filter:brightness(.97)} .fcard.is-active{box-shadow:0 0 0 2px var(--accent)}
.fcard-high{background:var(--high-bg);border-color:var(--high-bd)}
.fcard-warn{background:var(--warn-bg);border-color:var(--warn-bd)}
.fcard-info{background:var(--info-bg);border-color:var(--info-bd)}
.fcard .fnum{font-size:21px;font-weight:700}
.fcard-high .fnum{color:var(--high)} .fcard-warn .fnum{color:var(--warn)} .fcard-info .fnum{color:var(--info)}
.fcard .flbl{font-size:11px;font-weight:600;text-transform:uppercase;letter-spacing:.3px;margin-top:2px}
.warn-banner{background:var(--warn-bg);border:1px solid var(--warn-bd);color:var(--warn);padding:12px 16px;border-radius:10px;margin-bottom:16px;font-size:13px}
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
(() => {
  "use strict";
  const setCollapsed = (sec, collapsed) => {
    if (!sec) return;
    sec.classList.toggle("collapsed", collapsed);
    const btn = sec.querySelector(".section-header");
    if (btn) btn.setAttribute("aria-expanded", collapsed ? "false" : "true");
  };
  const setAll = (collapsed) => document.querySelectorAll(".report-section").forEach((s) => setCollapsed(s, collapsed));
  const openAndJump = (id) => {
    const el = id ? document.getElementById(id) : null;
    if (!el) return;
    setCollapsed(el.classList.contains("report-section") ? el : el.closest(".report-section"), false);
    el.scrollIntoView({ behavior: "smooth", block: "center" });
    el.classList.remove("row-flash");
    void el.offsetWidth;
    el.classList.add("row-flash");
  };

  document.addEventListener("DOMContentLoaded", () => {
    const rootEl   = document.documentElement;
    const navLinks = [...document.querySelectorAll(".sidebar nav a")];
    const allRows  = [...document.querySelectorAll("table.filterable-table tbody tr")];
    const fRows    = [...document.querySelectorAll(".findings-table tbody tr")];
    const btnTheme = document.getElementById("btn-theme");

    if (btnTheme && window.matchMedia && window.matchMedia("(prefers-color-scheme: dark)").matches) {
      rootEl.setAttribute("data-theme", "dark");
      btnTheme.textContent = "Light theme";
    }

    // Delegated click handler for sections, secrets, findings filter cards, cross-links & toolbar
    document.addEventListener("click", (ev) => {
      const hdr = ev.target.closest(".section-header");
      if (hdr) { const sec = hdr.closest(".report-section"); setCollapsed(sec, !sec.classList.contains("collapsed")); return; }

      const sBtn = ev.target.closest(".secret-btn");
      if (sBtn && sBtn.previousElementSibling) {
        const masked = sBtn.previousElementSibling.classList.toggle("is-masked");
        sBtn.textContent = masked ? "Show" : "Hide";
        return;
      }

      const card = ev.target.closest(".finding-cards .fcard");
      if (card) {
        document.querySelectorAll(".finding-cards .fcard").forEach((c) => c.classList.toggle("is-active", c === card));
        const sev = card.getAttribute("data-sev");
        const lbl = card.getAttribute("data-label");
        fRows.forEach((r) => r.classList.toggle("row-hidden", sev !== "all" && (r.getAttribute("data-sev") !== sev || r.getAttribute("data-label") !== lbl)));
        return;
      }

      const link = ev.target.closest('.sidebar nav a[href^="#"], a.xref[href^="#"]');
      if (link) {
        const href = link.getAttribute("href");
        if (href && href.length > 1) { ev.preventDefault(); openAndJump(href.slice(1)); }
        return;
      }

      const id = ev.target.id;
      if (id === "btn-expand-all")   { setAll(false); }
      else if (id === "btn-collapse-all") { setAll(true); }
      else if (id === "btn-print")   { window.print(); }
      else if (id === "btn-theme")   {
        const isDark = rootEl.getAttribute("data-theme") === "dark";
        if (isDark) { rootEl.removeAttribute("data-theme"); ev.target.textContent = "Dark theme"; }
        else        { rootEl.setAttribute("data-theme", "dark"); ev.target.textContent = "Light theme"; }
      }
      else if (id === "global-search-clear" && gInput) { gInput.value = ""; runSearch(); gInput.focus(); }
    });

    // Delegated change handler for hide-disabled toggles
    document.addEventListener("change", (ev) => {
      if (!ev.target.classList.contains("hide-disabled-toggle")) return;
      const sec = document.getElementById(ev.target.getAttribute("data-target"));
      if (sec) sec.querySelectorAll('tr[data-disabled="1"]').forEach((r) => r.classList.toggle("row-hidden", ev.target.checked));
    });

    // Sidebar section filter
    const nf = document.getElementById("navfilter");
    if (nf) nf.addEventListener("input", () => {
      const q = nf.value.toLowerCase();
      navLinks.forEach((a) => { a.style.display = a.textContent.toLowerCase().includes(q) ? "" : "none"; });
    });

    // Global table row search
    const gInput  = document.getElementById("global-search");
    const gStatus = document.getElementById("global-search-status");
    const runSearch = () => {
      if (!gInput) return;
      const q = gInput.value.trim().toLowerCase();
      let shown = 0;
      allRows.forEach((r) => {
        const match = !q || r.textContent.toLowerCase().includes(q);
        r.classList.toggle("row-hidden", !match);
        if (match) shown++;
      });
      if (gStatus) gStatus.textContent = q ? `${shown} matching row${shown === 1 ? "" : "s"}` : "";
    };
    if (gInput) gInput.addEventListener("input", runSearch);

    // Scroll-spy with rAF + passive listener + bottom-of-page handling
    const secs = navLinks.map((a) => document.querySelector(a.getAttribute("href"))).filter(Boolean);
    let ticking = false;
    const updateActiveNav = () => {
      ticking = false;
      const pos = window.pageYOffset + 130;
      const atBottom = (window.innerHeight + window.pageYOffset) >= (document.documentElement.scrollHeight - 20);
      let cur = atBottom && secs.length ? secs[secs.length - 1] : null;
      if (!cur) secs.forEach((s) => { if (s.offsetTop <= pos) cur = s; });
      navLinks.forEach((a) => a.classList.toggle("active", Boolean(cur && a.getAttribute("href") === `#${cur.id}`)));
    };
    window.addEventListener("scroll", () => { if (!ticking) { ticking = true; requestAnimationFrame(updateActiveNav); } }, { passive: true });
    updateActiveNav();
  });

  window.addEventListener("beforeprint", () => setAll(false));
})();
'@

# ==================================================================================
#  HUDU / COMPACT OPERATIONAL EXPORT (HTML FRAGMENT OR MARKDOWN)
# ==================================================================================

function Format-HuduCell {
    param([object]$Value, [string]$Format, [ValidateSet('text', 'host', 'user', 'dn')][string]$Kind = 'text')
    $raw = if ($null -eq $Value) { '' } else { ([string]$Value).Trim() }
    if ([string]::IsNullOrWhiteSpace($raw)) {
        if ($Format -eq 'Html') { return '<span style="color:#6c757d;">&mdash;</span>' }
        return '-'
    }
    if ($script:IsRedacted) {
        $raw = switch ($Kind) {
            'host' { if ($raw.Contains('.') -or $raw.Contains(':')) { Apply-Redaction $raw } else { Get-RedactToken $raw.ToLowerInvariant() 'HOST' } }
            'user' { if ($raw -match '@') { Apply-Redaction $raw } else { Get-RedactToken $raw.ToLowerInvariant() 'USER' } }
            'dn'   {
                $dn = [regex]::Replace($raw, '(?i)\b(O|OU|L|ST|S|STREET)=([^,]+)',
                    [System.Text.RegularExpressions.MatchEvaluator] { param($m) $m.Groups[1].Value + '=' + (Get-RedactToken $m.Groups[2].Value.Trim() 'ORG') })
                $dn = [regex]::Replace($dn, '(?i)\b(CN)=([^,]+)',
                    [System.Text.RegularExpressions.MatchEvaluator] {
                        param($m)
                        $v = $m.Groups[2].Value.Trim(); $r = Apply-Redaction $v
                        if ($r -eq $v -and -not (Test-IsRedactToken $v)) { $r = Get-RedactToken $v 'HOST' }
                        return ($m.Groups[1].Value + '=' + $r)
                    })
                Apply-Redaction $dn
            }
            default { Apply-Redaction $raw }
        }
    }
    if ($Format -eq 'Html') {
        return [System.Net.WebUtility]::HtmlEncode($raw)
    }
    return (($raw -replace '\r?\n', ' ') -replace '\|', '\|')
}

function Add-HuduHeading {
    param([System.Text.StringBuilder]$Sb, [string]$Text, [string]$Format, [int]$Level = 2)
    if ($Format -eq 'Html') {
        if ($Level -eq 2) {
            [void]$Sb.Append('<h2 style="color:#1e3f75;border-bottom:2px solid #d0d7de;padding-bottom:4px;margin:20px 0 8px;font-size:16px;">').Append([System.Net.WebUtility]::HtmlEncode($Text)).Append("</h2>`n")
        }
        else {
            [void]$Sb.Append('<h3 style="color:#2b5ea8;margin:14px 0 6px;font-size:14px;">').Append([System.Net.WebUtility]::HtmlEncode($Text)).Append("</h3>`n")
        }
    }
    else {
        $hashes = if ($Level -eq 2) { '##' } else { '###' }
        [void]$Sb.Append("`n$hashes $Text`n`n")
    }
}

function Add-HuduTable {
    param([System.Text.StringBuilder]$Sb, [string[]]$Headers, [object[]]$Rows, [string]$Format)
    if ($Rows.Count -eq 0) { return }
    if ($Format -eq 'Html') {
        [void]$Sb.Append('<table style="border-collapse:collapse;width:100%;margin:6px 0 14px;font-size:13px;border:1px solid #d0d7de;"><thead><tr>')
        foreach ($h in $Headers) {
            [void]$Sb.Append('<th style="background:#1e3f75;color:#ffffff;padding:6px 10px;text-align:left;border:1px solid #d0d7de;white-space:nowrap;">').Append([System.Net.WebUtility]::HtmlEncode($h)).Append('</th>')
        }
        [void]$Sb.Append('</tr></thead><tbody>')
        $i = 0
        foreach ($r in $Rows) {
            $bg = if (($i % 2) -eq 1) { 'background:#f7f9fc;' } else { '' }
            [void]$Sb.Append('<tr>')
            foreach ($c in $r) {
                [void]$Sb.Append('<td style="' + $bg + 'padding:6px 10px;border:1px solid #d0d7de;vertical-align:top;">').Append($c).Append('</td>')
            }
            [void]$Sb.Append('</tr>')
            $i++
        }
        [void]$Sb.Append("</tbody></table>`n")
    }
    else {
        [void]$Sb.Append('| ' + ($Headers -join ' | ') + " |`n")
        [void]$Sb.Append('| ' + (($Headers | ForEach-Object { '---' }) -join ' | ') + " |`n")
        foreach ($r in $Rows) {
            [void]$Sb.Append('| ' + ($r -join ' | ') + " |`n")
        }
        [void]$Sb.Append("`n")
    }
}

function Add-HuduKv {
    param([System.Text.StringBuilder]$Sb, [object[]]$Pairs, [string]$Format)
    if ($Pairs.Count -eq 0) { return }
    if ($Format -eq 'Html') {
        [void]$Sb.Append('<table style="border-collapse:collapse;width:100%;margin:6px 0 14px;font-size:13px;border:1px solid #d0d7de;"><tbody>')
        foreach ($p in $Pairs) {
            [void]$Sb.Append('<tr><th style="background:#eef2f8;color:#1f2933;padding:6px 10px;text-align:left;border:1px solid #d0d7de;width:210px;white-space:nowrap;">')
            [void]$Sb.Append([System.Net.WebUtility]::HtmlEncode($p[0])).Append('</th><td style="padding:6px 10px;border:1px solid #d0d7de;">').Append($p[1]).Append('</td></tr>')
        }
        [void]$Sb.Append("</tbody></table>`n")
    }
    else {
        Add-HuduTable $Sb @('Setting', 'Value') $Pairs 'Markdown'
    }
}

function Build-HuduReport {
    param($Root, [string]$Format, [string]$TitleValue, [string]$Fqdn, [string]$Version, [string]$GenTime)
    $sb = New-Object System.Text.StringBuilder
    $c  = { param($v, $k = 'text') Format-HuduCell $v $Format $k }

    # Header & Metadata
    $rev = $Root.SelectSingleNode('revision')
    $lastChg = if ($null -ne $rev) { ConvertFrom-Epoch (XText $rev 'time') } else { ConvertFrom-Epoch (XText $Root 'lastchange') }
    $titleStr = if ($script:IsRedacted) { (Apply-Redaction $TitleValue) + ' (Redacted)' } else { $TitleValue }
    $verDisp  = if ($Version) { $Version } else { 'unknown' }

    if ($Format -eq 'Html') {
        [void]$sb.Append('<div style="font-family:-apple-system,BlinkMacSystemFont,''Segoe UI'',Roboto,Helvetica,Arial,sans-serif;color:#1f2933;line-height:1.45;">' + "`n")
        [void]$sb.Append('<h1 style="color:#1e3f75;margin:0 0 6px;font-size:21px;">' + [System.Net.WebUtility]::HtmlEncode($titleStr) + "</h1>`n")
        $meta = '<strong>Host:</strong> ' + [System.Net.WebUtility]::HtmlEncode($Fqdn) +
                ' &nbsp;|&nbsp; <strong>pfSense Config:</strong> ' + [System.Net.WebUtility]::HtmlEncode($verDisp) +
                ' &nbsp;|&nbsp; <strong>Generated:</strong> ' + [System.Net.WebUtility]::HtmlEncode($GenTime)
        if ($lastChg) { $meta += ' &nbsp;|&nbsp; <strong>Last Change:</strong> ' + [System.Net.WebUtility]::HtmlEncode($lastChg) }
        [void]$sb.Append('<p style="color:#5a6573;font-size:12px;margin:0 0 14px;">' + $meta + "</p>`n")
    }
    else {
        [void]$sb.Append("# $titleStr`n`n")
        $meta = "**Host:** ``$Fqdn`` | **pfSense Config:** ``$verDisp`` | **Generated:** $GenTime"
        if ($lastChg) { $meta += " | **Last Change:** $lastChg" }
        [void]$sb.Append("$meta`n`n")
    }

    # Key Security Alerts (HIGH and WARN only - skip info/NO LOG noise)
    $alerts = @($script:Findings | Where-Object { $_.Sev -in @('high', 'warn') } | Sort-Object @{ Expression = { if ($_.Sev -eq 'high') { 0 } else { 1 } } }, Label, Where)
    if ($alerts.Count -gt 0) {
        if ($Format -eq 'Html') {
            [void]$sb.Append('<div style="background:#fef6e7;border:1px solid #f0d9a8;border-left:4px solid #c0392b;padding:10px 14px;border-radius:4px;margin:0 0 16px;">')
            [void]$sb.Append('<strong style="color:#c0392b;">Key Security Alerts (' + $alerts.Count + '):</strong><ul style="margin:6px 0 0;padding-left:18px;font-size:13px;">')
            foreach ($a in $alerts) {
                $clr = if ($a.Sev -eq 'high') { '#c0392b' } else { '#9a5d05' }
                [void]$sb.Append('<li><strong style="color:' + $clr + ';">[' + (& $c $a.Label) + ']</strong> ' + (& $c $a.Where) + ' &mdash; ' + (& $c $a.Detail) + '</li>')
            }
            [void]$sb.Append("</ul></div>`n")
        }
        else {
            [void]$sb.Append("> **Key Security Alerts ($($alerts.Count)):**`n")
            foreach ($a in $alerts) {
                [void]$sb.Append("> - **[$(& $c $a.Label)]** $(& $c $a.Where) - $(& $c $a.Detail)`n")
            }
            [void]$sb.Append("`n")
        }
    }

    # 1. System Overview
    $sys = $Root.SelectSingleNode('system')
    if ($null -ne $sys) {
        Add-HuduHeading $sb 'System Overview' $Format
        $gui = $sys.SelectSingleNode('webgui')
        $gProto = XText $gui 'protocol'; if (-not $gProto) { $gProto = 'https' }
        $gPort  = XText $gui 'port';     if (-not $gPort)  { $gPort = if ($gProto -eq 'http') { '80' } else { '443' } }
        $sshNode = $sys.SelectSingleNode('ssh')
        $sshEn = Test-XmlEnabled $sshNode @('enable', 'enabled')
        $sshDisp = if ($sshEn) { 'Enabled (port ' + $(if (XText $sshNode 'port') { XText $sshNode 'port' } else { '22' }) + ')' } else { 'Disabled' }
        $dnsList = @((XNodes $sys 'dnsserver') | ForEach-Object { $_.InnerText.Trim() } | Where-Object { $_ })
        $ntpList = @((XText $sys 'timeservers') -split '\s+' | Where-Object { $_ })
        $sysPairs = New-Object 'System.Collections.Generic.List[object]'
        foreach ($p in @(
            @('Hostname / Domain', ((& $c (XText $sys 'hostname') 'host') + ' / ' + (& $c (XText $sys 'domain')))),
            @('WebGUI',            (& $c "$gProto on port $gPort")),
            @('SSH',               (& $c $sshDisp)),
            @('DNS Servers',       (& $c ($dnsList -join ', '))),
            @('NTP / Timezone',    ((& $c ($ntpList -join ', ')) + ' (' + (& $c (XText $sys 'timezone')) + ')'))
        )) { [void]$sysPairs.Add($p) }
        $dhcpBe = XText $Root 'dhcpbackend'
        if ($dhcpBe) { [void]$sysPairs.Add(@('DHCP Backend', (& $c $dhcpBe.ToUpperInvariant()))) }
        Add-HuduKv $sb $sysPairs.ToArray() $Format
    }

    # 2. Interfaces
    $ifs = $Root.SelectSingleNode('interfaces')
    if ($null -ne $ifs) {
        $ifRows = New-Object 'System.Collections.Generic.List[object]'
        foreach ($n in $ifs.ChildNodes) {
            if ($n.NodeType -ne [System.Xml.XmlNodeType]::Element) { continue }
            $key = $n.Name; $dev = XText $n 'if'; $en = XHas $n 'enable'
            $ip4 = XText $n 'ipaddr'; $sub = XText $n 'subnet'
            $ip4Disp = if ($ip4 -match '^\d+\.' -and $sub) { "$ip4/$sub" } elseif ($ip4) { $ip4.ToUpperInvariant() } else { '' }
            $v6 = XText $n 'ipaddrv6'
            $v6Disp = if ($v6 -eq 'track6') { 'Track IPv6 (' + (XText $n 'track6-interface').ToUpperInvariant() + ')' } elseif ($v6 -and $v6 -ne 'none') { $v6 + $(if ((XText $n 'subnetv6') -and $v6 -notmatch '^(dhcp6|slaac)$') { '/' + (XText $n 'subnetv6') } else { '' }) } else { '' }
            $vlan = if ($script:VlanMap.ContainsKey($dev)) { $script:VlanMap[$dev].Tag } elseif ($dev -match '\.(\d+)$') { $Matches[1] } else { '' }
            [void]$ifRows.Add(@((& $c $key), (& $c (XText $n 'descr')), (& $c $dev), $(if ($en) { 'Yes' } else { 'No' }), (& $c $ip4Disp), (& $c $v6Disp), (& $c $vlan), (& $c (XText $n 'gateway'))))
        }
        if ($ifRows.Count -gt 0) {
            Add-HuduHeading $sb 'Interfaces' $Format
            Add-HuduTable $sb @('Key','Description','Device','Enabled','IPv4','IPv6','VLAN','Gateway') $ifRows.ToArray() $Format
        }
    }

    # 3. VLANs, Virtual IPs & High Availability (only if configured)
    $vlans = XNodes $Root 'vlans/vlan'
    if ($vlans.Count -gt 0) {
        Add-HuduHeading $sb 'VLANs' $Format
        $rows = @(foreach ($v in $vlans) { ,@((& $c (XText $v 'if')), (& $c (XText $v 'tag')), (& $c (XText $v 'vlanif')), (& $c (XText $v 'descr'))) })
        Add-HuduTable $sb @('Parent','Tag','Interface','Description') $rows $Format
    }

    $vips = XNodes $Root 'virtualip/vip'
    if ($vips.Count -gt 0) {
        Add-HuduHeading $sb 'Virtual IPs' $Format
        $rows = @(foreach ($v in $vips) {
            $sn = XText $v 'subnet'; $bits = XText $v 'subnet_bits'
            ,@((& $c (XText $v 'mode').ToUpperInvariant()), (& $c (XText $v 'interface')), (& $c $(if ($sn -and $bits) { "$sn/$bits" } else { $sn })), (& $c (XText $v 'vhid')), (& $c (XText $v 'descr')))
        })
        Add-HuduTable $sb @('Type','Interface','Address','VHID','Description') $rows $Format
    }

    $ha = $Root.SelectSingleNode('hasync')
    if ($null -ne $ha -and ((XHas $ha 'pfsyncenabled') -or (XText $ha 'synchronizetoip'))) {
        Add-HuduHeading $sb 'High Availability (CARP / Sync)' $Format
        Add-HuduKv $sb @(
            @('pfsync',        $(if (XHas $ha 'pfsyncenabled') { 'Enabled' } else { 'Disabled' }) + ' on ' + (& $c (XText $ha 'pfsyncinterface')) + ' (peer ' + (& $c (XText $ha 'pfsyncpeerip')) + ')'),
            @('XMLRPC Target', (& $c (XText $ha 'synchronizetoip')) + ' (user: ' + (& $c (XText $ha 'username') 'user') + ', password in vault)')
        ) $Format
    }

    # 4. Gateways & Static Routes
    $gws = XNodes $Root 'gateways/gateway_item'; $gwGroups = XNodes $Root 'gateways/gateway_group'; $routes = XNodes $Root 'staticroutes/route'
    if ($gws.Count -gt 0 -or $gwGroups.Count -gt 0 -or $routes.Count -gt 0) {
        Add-HuduHeading $sb 'Gateways & Routing' $Format
        $gwNode = $Root.SelectSingleNode('gateways'); $d4 = XText $gwNode 'defaultgw4'; $d6 = XText $gwNode 'defaultgw6'
        if ($gws.Count -gt 0) {
            $rows = @(foreach ($g in $gws) {
                $gn = XText $g 'name'; $isDef = if ($gn -and ($gn -eq $d4 -or $gn -eq $d6)) { 'DEFAULT' } else { '' }
                ,@((& $c $gn), (& $c (XText $g 'interface')), (& $c (XText $g 'gateway')), (& $c (XText $g 'monitor')), (& $c $isDef), (& $c (XText $g 'descr')))
            })
            Add-HuduTable $sb @('Gateway','Interface','IP','Monitor','Default','Description') $rows $Format
        }
        if ($gwGroups.Count -gt 0) {
            Add-HuduHeading $sb 'Gateway Groups' $Format 3
            $rows = @(foreach ($gg in $gwGroups) {
                $mem = @((XNodes $gg 'item') | ForEach-Object { $_.InnerText.Trim() -replace '\|', ' T' }) -join ', '
                ,@((& $c (XText $gg 'name')), (& $c $mem), (& $c (XText $gg 'trigger')), (& $c (XText $gg 'descr')))
            })
            Add-HuduTable $sb @('Group','Members','Trigger','Description') $rows $Format
        }
        if ($routes.Count -gt 0) {
            Add-HuduHeading $sb 'Static Routes' $Format 3
            $rows = @(foreach ($r in $routes) {
                ,@((& $c (XText $r 'network')), (& $c (XText $r 'gateway')), $(if (XHas $r 'disabled') { 'Disabled' } else { 'Enabled' }), (& $c (XText $r 'descr')))
            })
            Add-HuduTable $sb @('Destination','Gateway','Status','Description') $rows $Format
        }
    }

    # 5. DHCP & DNS
    $dhcpRows = New-Object 'System.Collections.Generic.List[object]'
    $smapRows = New-Object 'System.Collections.Generic.List[object]'
    foreach ($spec in @(@{ Tag='dhcpd'; Label='v4' }, @{ Tag='dhcpdv6'; Label='v6' })) {
        $dn = $Root.SelectSingleNode($spec.Tag); if ($null -eq $dn) { continue }
        foreach ($in in $dn.ChildNodes) {
            if ($in.NodeType -ne [System.Xml.XmlNodeType]::Element) { continue }
            $ifName = if ($script:IfMap.ContainsKey($in.Name)) { "$($in.Name) ($($script:IfMap[$in.Name]))" } else { $in.Name }
            $rng = (XText $in 'range/from') + ' - ' + (XText $in 'range/to')
            if ($rng -eq ' - ') { $rng = '' }
            $dns = @((XNodes $in 'dnsserver') | ForEach-Object { $_.InnerText.Trim() } | Where-Object { $_ }) -join ', '
            [void]$dhcpRows.Add(@((& $c "$ifName [$($spec.Label)]"), $(if (XHas $in 'enable') { 'Yes' } else { 'No' }), (& $c $rng), (& $c (XText $in 'gateway')), (& $c $dns), (& $c (XText $in 'domain'))))
            foreach ($m in (XNodes $in 'staticmap')) {
                $idv = if ($spec.Tag -eq 'dhcpdv6') { XText $m 'duid' } else { XText $m 'mac' }
                $ipv = if ($spec.Tag -eq 'dhcpdv6') { XText $m 'ipaddrv6' } else { XText $m 'ipaddr' }
                [void]$smapRows.Add(@((& $c $in.Name), (& $c $ipv), (& $c $idv), (& $c (XText $m 'hostname') 'host'), (& $c (XText $m 'descr'))))
            }
        }
    }
    if ($dhcpRows.Count -gt 0) {
        Add-HuduHeading $sb 'DHCP' $Format
        Add-HuduTable $sb @('Interface','Enabled','Range','Gateway','DNS','Domain') $dhcpRows.ToArray() $Format
        if ($smapRows.Count -gt 0) {
            Add-HuduHeading $sb "DHCP Static Mappings ($($smapRows.Count))" $Format 3
            Add-HuduTable $sb @('Interface','IP','MAC / DUID','Hostname','Description') $smapRows.ToArray() $Format
        }
    }

    $unbound = $Root.SelectSingleNode('unbound'); $dnsmasq = $Root.SelectSingleNode('dnsmasq')
    $dnsActive = if ($null -ne $unbound -and (XHas $unbound 'enable')) { $unbound } elseif ($null -ne $dnsmasq -and (XHas $dnsmasq 'enable')) { $dnsmasq } else { $null }
    if ($null -ne $dnsActive) {
        $dnsKind = if ($dnsActive.Name -eq 'unbound') { 'DNS Resolver (Unbound)' } else { 'DNS Forwarder (dnsmasq)' }
        Add-HuduHeading $sb $dnsKind $Format
        $listen = if ($dnsActive.Name -eq 'unbound') { XText $dnsActive 'active_interface' } else { XText $dnsActive 'interface' }
        if (-not $listen) { $listen = 'All' }
        $dnsPairs = @(@('Listening Interfaces', (& $c $listen)))
        if ($dnsActive.Name -eq 'unbound') { $dnsPairs += ,@('Forwarding / DNSSEC', ($(if (XHas $dnsActive 'forwarding') { 'Forwarding' } else { 'Recursive' }) + ' / DNSSEC: ' + $(if (XHas $dnsActive 'dnssec') { 'On' } else { 'Off' }))) }
        Add-HuduKv $sb $dnsPairs $Format
        $hOvr = XNodes $dnsActive 'hosts'
        if ($hOvr.Count -gt 0) {
            Add-HuduHeading $sb 'DNS Host Overrides' $Format 3
            $rows = @(foreach ($h in $hOvr) { ,@((& $c (XText $h 'host') 'host'), (& $c (XText $h 'domain')), (& $c (XText $h 'ip')), (& $c (XText $h 'descr'))) })
            Add-HuduTable $sb @('Host','Domain','IP','Description') $rows $Format
        }
        $dOvr = XNodes $dnsActive 'domainoverrides'
        if ($dOvr.Count -gt 0) {
            Add-HuduHeading $sb 'DNS Domain Overrides' $Format 3
            $rows = @(foreach ($d in $dOvr) { ,@((& $c (XText $d 'domain')), (& $c (XText $d 'ip')), (& $c (XText $d 'descr'))) })
            Add-HuduTable $sb @('Domain','Forward-to IP','Description') $rows $Format
        }
    }

    # 6. NAT & Port Forwards
    $nat = $Root.SelectSingleNode('nat')
    if ($null -ne $nat) {
        $obMode = XText $nat 'outbound/mode'; if (-not $obMode) { $obMode = 'automatic' }
        $pfNodes = XNodes $nat 'rule'; $otoNodes = XNodes $nat 'onetoone'; $obNodes = XNodes $nat 'outbound/rule'
        if ($pfNodes.Count -gt 0 -or $otoNodes.Count -gt 0 -or $obNodes.Count -gt 0 -or $obMode -ne 'automatic') {
            Add-HuduHeading $sb "NAT (Outbound Mode: $($obMode.ToUpperInvariant()))" $Format
            if ($pfNodes.Count -gt 0) {
                Add-HuduHeading $sb 'Port Forwards' $Format 3
                $rows = @(foreach ($r in $pfNodes) {
                    $src = Format-Endpoint $r.SelectSingleNode('source'); $dst = Format-Endpoint $r.SelectSingleNode('destination')
                    $ep = if ($dst.Port) { $dst.Port } else { XText $r 'dstport' }
                    $ext = $dst.Addr + $(if ($ep) { ":$ep" } else { '' })
                    $tgt = (XText $r 'target') + $(if (XText $r 'local-port') { ':' + (XText $r 'local-port') } else { '' })
                    $st  = if (XHas $r 'disabled') { 'Disabled' } elseif (XHas $r 'nordr') { 'NO RDR' } else { 'Active' }
                    ,@((& $c (XText $r 'interface')), (& $c (XText $r 'protocol')), (& $c $src.Addr), (& $c $ext), (& $c $tgt), $st, (& $c (XText $r 'descr')))
                })
                Add-HuduTable $sb @('Interface','Proto','Source','External','Redirect Target','Status','Description') $rows $Format
            }
            if ($otoNodes.Count -gt 0) {
                Add-HuduHeading $sb '1:1 NAT' $Format 3
                $rows = @(foreach ($r in $otoNodes) {
                    $src = Format-Endpoint $r.SelectSingleNode('source')
                    $st  = if (XHas $r 'disabled') { 'Disabled' } elseif (XHas $r 'nobinat') { 'DO NOT BINAT' } else { 'Active' }
                    ,@((& $c (XText $r 'interface')), (& $c (XText $r 'external')), (& $c $src.Addr), $st, (& $c (XText $r 'descr')))
                })
                Add-HuduTable $sb @('Interface','External IP','Internal','Status','Description') $rows $Format
            }
            if ($obNodes.Count -gt 0) {
                Add-HuduHeading $sb 'Outbound NAT Rules' $Format 3
                $rows = @(foreach ($r in $obNodes) {
                    $src = Format-Endpoint $r.SelectSingleNode('source'); $dst = Format-Endpoint $r.SelectSingleNode('destination')
                    $tgt = if (XHas $r 'nonat') { 'DO NOT NAT' } elseif (XText $r 'targetip') { XText $r 'targetip' } elseif (XText $r 'target') { XText $r 'target' } else { 'Interface address' }
                    ,@((& $c (XText $r 'interface')), (& $c $src.Addr), (& $c $dst.Addr), (& $c $tgt), $(if (XHas $r 'disabled') { 'Disabled' } else { 'Active' }), (& $c (XText $r 'descr')))
                })
                Add-HuduTable $sb @('Interface','Source','Destination','Translation','Status','Description') $rows $Format
            }
        }
    }

    # 7. VPN (IPsec combined P1+P2, OpenVPN, WireGuard - never emit PSKs/keys)
    $p1 = XNodes $Root 'ipsec/phase1'; $p2 = XNodes $Root 'ipsec/phase2'
    $ovS = XNodes $Root 'openvpn/openvpn-server'; $ovC = XNodes $Root 'openvpn/openvpn-client'
    $wgT = (XNodes $Root 'installedpackages/wireguard/tunnels/item') + (XNodes $Root 'wireguard/tunnels/item')
    $wgP = (XNodes $Root 'installedpackages/wireguard/peers/item')   + (XNodes $Root 'wireguard/peers/item')
    if ($p1.Count -gt 0 -or $ovS.Count -gt 0 -or $ovC.Count -gt 0 -or $wgT.Count -gt 0) {
        Add-HuduHeading $sb 'VPN Configuration' $Format
        if ($p1.Count -gt 0) {
            Add-HuduHeading $sb 'IPsec Tunnels' $Format 3
            $p2ByIke = @{}
            foreach ($s2 in $p2) {
                $id = XText $s2 'ikeid'
                $lid = $s2.SelectSingleNode('localid'); $rid = $s2.SelectSingleNode('remoteid')
                $loc = if (XText $lid 'address') { (XText $lid 'address') + $(if (XText $lid 'netbits') { '/' + (XText $lid 'netbits') } else { '' }) } else { XText $lid 'type' }
                $rem = if (XText $rid 'address') { (XText $rid 'address') + $(if (XText $rid 'netbits') { '/' + (XText $rid 'netbits') } else { '' }) } else { XText $rid 'type' }
                if (-not $p2ByIke.ContainsKey($id)) { $p2ByIke[$id] = New-Object 'System.Collections.Generic.List[string]' }
                [void]$p2ByIke[$id].Add("$loc -> $rem")
            }
            $rows = @(foreach ($s1 in $p1) {
                $id = XText $s1 'ikeid'
                $nets = if ($p2ByIke.ContainsKey($id)) { ($p2ByIke[$id].ToArray()) -join '; ' } else { '' }
                $auth = (XText $s1 'authentication_method') + $(if (XText $s1 'pre-shared-key') { ' (PSK in vault)' } else { '' })
                ,@((& $c (XText $s1 'descr')), $(if (XHas $s1 'disabled') { 'Disabled' } else { 'Active' }), (& $c (XText $s1 'iketype')), (& $c (XText $s1 'remote-gateway')), (& $c $nets), (& $c $auth))
            })
            Add-HuduTable $sb @('Tunnel','Status','IKE','Remote Peer','Subnets (Local -> Remote)','Auth') $rows $Format
        }
        if ($ovS.Count -gt 0 -or $ovC.Count -gt 0) {
            Add-HuduHeading $sb 'OpenVPN' $Format 3
            $rows = New-Object 'System.Collections.Generic.List[object]'
            foreach ($s in $ovS) {
                $ep = (XText $s 'protocol') + '/' + (XText $s 'local_port')
                [void]$rows.Add(@('Server', (& $c (XText $s 'description')), $(if ((XHas $s 'disable') -or (XHas $s 'disabled')) { 'Disabled' } else { 'Active' }), (& $c $ep), (& $c (XText $s 'tunnel_network')), (& $c (XText $s 'local_network')), (& $c (XText $s 'authmode'))))
            }
            foreach ($s in $ovC) {
                $ep = (XText $s 'protocol') + ' ' + (XText $s 'server_addr') + ':' + (XText $s 'server_port')
                [void]$rows.Add(@('Client', (& $c (XText $s 'description')), $(if ((XHas $s 'disable') -or (XHas $s 'disabled')) { 'Disabled' } else { 'Active' }), (& $c $ep), (& $c (XText $s 'tunnel_network')), (& $c (XText $s 'remote_network')), (& $c (XText $s 'authmode'))))
            }
            Add-HuduTable $sb @('Role','Description','Status','Proto / Endpoint','Tunnel Net','Local / Remote Net','Auth') $rows.ToArray() $Format
        }
        if ($wgT.Count -gt 0) {
            Add-HuduHeading $sb 'WireGuard' $Format 3
            $rows = @(foreach ($t in $wgT) {
                $tn = XText $t 'name'
                $ad = @((XNodes $t 'addresses/row') | ForEach-Object { (XText $_ 'address') + '/' + (XText $_ 'mask') }) -join ', '
                $pr = @($wgP | Where-Object { (XText $_ 'tun') -eq $tn } | ForEach-Object { (XText $_ 'descr') + ' (' + (XText $_ 'endpoint') + ')' }) -join '; '
                ,@((& $c $tn), $(if (Test-XmlEnabled $t @('enabled')) { 'Active' } else { 'Disabled' }), (& $c (XText $t 'listenport')), (& $c $ad), (& $c $pr), (& $c (XText $t 'descr')))
            })
            Add-HuduTable $sb @('Tunnel','Status','Port','Addresses','Peers','Description') $rows $Format
        }
    }

    # 8. Firewall Rules (enabled rules only, grouped by interface)
    $fwRules = XNodes $Root 'filter/rule'
    if ($fwRules.Count -gt 0) {
        Add-HuduHeading $sb 'Firewall Rules (Active)' $Format
        $fwGroups = [ordered]@{}
        $disabledCnt = 0
        foreach ($r in $fwRules) {
            if (XHas $r 'disabled') { $disabledCnt++; continue }
            $k = if (XHas $r 'floating') { '(floating)' } else { XText $r 'interface' }
            if (-not $k) { $k = '(floating)' }
            if (-not $fwGroups.Contains($k)) { $fwGroups[$k] = New-Object 'System.Collections.Generic.List[object]' }
            [void]$fwGroups[$k].Add($r)
        }
        foreach ($k in $fwGroups.Keys) {
            $ifLbl = if ($script:IfMap.ContainsKey($k)) { "$k - $($script:IfMap[$k])" } else { $k }
            Add-HuduHeading $sb $ifLbl $Format 3
            $rows = @(foreach ($r in $fwGroups[$k]) {
                $src = Format-Endpoint $r.SelectSingleNode('source'); $dst = Format-Endpoint $r.SelectSingleNode('destination')
                $pr = XText $r 'protocol'; if (-not $pr) { $pr = 'any' }
                ,@((& $c (XText $r 'type').ToUpperInvariant()), (& $c $pr), (& $c $src.Addr), (& $c $dst.Addr), (& $c $dst.Port), (& $c (XText $r 'gateway')), (& $c (XText $r 'descr')))
            })
            Add-HuduTable $sb @('Action','Proto','Source','Destination','Dst Port','Gateway','Description') $rows $Format
        }
        if ($disabledCnt -gt 0) {
            if ($Format -eq 'Html') { [void]$sb.Append('<p style="color:#5a6573;font-size:12px;"><em>' + $disabledCnt + " disabled rule(s) omitted.</em></p>`n") }
            else { [void]$sb.Append("_$disabledCnt disabled rule(s) omitted._`n`n") }
        }
    }

    # 9. Aliases
    $aliases = XNodes $Root 'aliases/alias'
    if ($aliases.Count -gt 0) {
        Add-HuduHeading $sb 'Aliases' $Format
        $rows = @(foreach ($a in $aliases) {
            $val = XText $a 'address'; if (-not $val) { $val = XText $a 'url' }
            $val = (@($val -split '\s+' | Where-Object { $_ }) -join ', ')
            ,@((& $c (XText $a 'name')), (& $c (XText $a 'type')), (& $c $val), (& $c (XText $a 'descr')))
        })
        Add-HuduTable $sb @('Name','Type','Contents','Description') $rows $Format
    }

    # 10. Certificates & Packages / Services Summary
    $certs = XNodes $Root 'cert'
    if ($certs.Count -gt 0) {
        Add-HuduHeading $sb 'Certificates' $Format
        $rows = @(foreach ($ct in $certs) {
            $rid = XText $ct 'refid'; $info = Get-CertInfo (XText $ct 'crt')
            $exp = if ($info.NotAfter) { $info.NotAfter.ToString('yyyy-MM-dd') } else { '' }
            $uses = @(); if ($rid -and $script:RefUsageMap.ContainsKey($rid)) { $uses = @($script:RefUsageMap[$rid]) }
            ,@((& $c (XText $ct 'descr')), (& $c $info.Subject 'dn'), (& $c $exp), (& $c ($uses -join ', ')))
        })
        Add-HuduTable $sb @('Name','Subject','Expires','Used By') $rows $Format
    }

    $pkgs = XNodes $Root 'installedpackages/package'
    $snmp = $Root.SelectSingleNode('snmpd'); $syslog = $Root.SelectSingleNode('syslog'); $ddns = XNodes $Root 'dyndnses/dyndns'
    $svcPairs = New-Object 'System.Collections.Generic.List[object]'
    if ($null -ne $snmp -and (XHas $snmp 'enable')) { [void]$svcPairs.Add(@('SNMP', 'Enabled on ' + (& $c $(if (XText $snmp 'bindip') { XText $snmp 'bindip' } else { 'All' })) + ' (community in vault)')) }
    if ($null -ne $syslog -and (XHas $syslog 'enable')) {
        $svrs = @((XText $syslog 'remoteserver'), (XText $syslog 'remoteserver2'), (XText $syslog 'remoteserver3') | Where-Object { $_ }) -join ', '
        [void]$svcPairs.Add(@('Remote Syslog', (& $c $svrs)))
    }
    if ($ddns.Count -gt 0) {
        $dh = @(foreach ($d in $ddns) { if (XHas $d 'enable') { (XText $d 'host') + ' (' + (XText $d 'type') + ')' } }) -join ', '
        if ($dh) { [void]$svcPairs.Add(@('Dynamic DNS', (& $c $dh))) }
    }
    if ($pkgs.Count -gt 0) {
        $pl = @(foreach ($p in $pkgs) { (XText $p 'name') + ' ' + (XText $p 'version') }) -join ', '
        [void]$svcPairs.Add(@('Installed Packages', (& $c $pl)))
    }
    if ($svcPairs.Count -gt 0) {
        Add-HuduHeading $sb 'Services & Packages' $Format
        Add-HuduKv $sb $svcPairs.ToArray() $Format
    }

    if ($Format -eq 'Html') {
        [void]$sb.Append('<p style="color:#6c757d;font-size:11px;margin-top:16px;">Generated by pfsense_report.ps1 v' + $script:ToolVersion + ' (-Hudu). Passwords, PSKs, and private keys are omitted &mdash; store them in your Hudu Password Vault.</p></div>')
    }
    else {
        [void]$sb.Append("---`n*Generated by pfsense_report.ps1 v$($script:ToolVersion) (-Hudu). Passwords, PSKs, and private keys are omitted - store them in your Hudu Password Vault.*`n")
    }
    return $sb.ToString()
}

# ==================================================================================
#  MAIN ENTRYPOINT
# ==================================================================================

function Invoke-PfSenseReport {
    param(
        [string]$ConfigPathValue, [string]$OutputPathValue, [bool]$RedactValue,
        [string]$TitleValue, [string]$LogoPathValue,
        [string[]]$WanInterfacesValue, [string[]]$InternalInterfacesValue,
        [int]$ExpiryWarnDaysValue, [string]$JsonPathValue,
        [bool]$HuduValue = $false, [string]$HuduFormatValue = 'Html',
        [bool]$QuietValue = $false
    )

    Initialize-ReportContext -RedactMode $RedactValue -ExpiryWarnDaysValue $ExpiryWarnDaysValue
    if ([string]::IsNullOrWhiteSpace($ConfigPathValue)) {
        throw "ConfigPath is required. Example: .\pfsense_report.ps1 -ConfigPath config.xml"
    }

    $resolvedConfig = Resolve-FullPath $ConfigPathValue
    $xml  = Read-PfSenseXml $ConfigPathValue
    $root = $xml.DocumentElement
    if ($null -eq $root -or $root.Name -ne 'pfsense') {
        throw "This does not appear to be a pfSense configuration (missing <pfsense> root element)."
    }

    $normHuduFmt = if ($HuduFormatValue -match '(?i)^(markdown|md)$') { 'Markdown' } else { 'Html' }
    if ([string]::IsNullOrWhiteSpace($OutputPathValue)) {
        $baseName = [System.IO.Path]::GetFileNameWithoutExtension($resolvedConfig)
        $suffix = if ($HuduValue) { if ($normHuduFmt -eq 'Markdown') { '-hudu.md' } else { '-hudu.html' } } else { '-report.html' }
        $OutputPathValue = Join-Path (Get-Location).Path ($baseName + $suffix)
    }
    $resolvedOutput = Resolve-FullPath $OutputPathValue

    $sysNode = $root.SelectSingleNode('system')
    $hostname = XText $sysNode 'hostname'; $domain = XText $sysNode 'domain'; $version = XText $root 'version'
    $script:RedactHost = $hostname; $script:RedactDomain = $domain

    Build-LookupMaps -root $root -ForceWan $WanInterfacesValue -ForceInternal $InternalInterfacesValue

    # ---- Inventory counts ----------------------------------------------------
    $ifsNode = $root.SelectSingleNode('interfaces')
    $counts = @{
        interfaces    = (XNodes $ifsNode '*').Count
        vlans         = (XNodes $root 'vlans/vlan').Count
        virtualIps    = (XNodes $root 'virtualip/vip').Count
        gateways      = (XNodes $root 'gateways/gateway_item').Count + (XNodes $root 'gateways/gateway_group').Count
        staticRoutes  = (XNodes $root 'staticroutes/route').Count
        firewallRules = (XNodes $root 'filter/rule').Count
        portForwards  = (XNodes $root 'nat/rule').Count
        natTotal      = (XNodes $root 'nat/rule').Count + (XNodes $root 'nat/outbound/rule').Count + (XNodes $root 'nat/onetoone').Count
        ipsecTunnels  = (XNodes $root 'ipsec/phase1').Count
        openVpn       = (XNodes $root 'openvpn/openvpn-server').Count + (XNodes $root 'openvpn/openvpn-client').Count
        wireGuard     = (XNodes $root 'installedpackages/wireguard/tunnels/item').Count + (XNodes $root 'wireguard/tunnels/item').Count
        certsAndCas   = (XNodes $root 'cert').Count + (XNodes $root 'ca').Count
        users         = (XNodes $root 'system/user').Count
        aliases       = (XNodes $root 'aliases/alias').Count
        packages      = (XNodes $root 'installedpackages/package').Count
    }

    # ---- Data-driven section registry (non-findings built first to populate findings)
    $sectionDefs = @(
        @{ Id='findings';   Nav='Security Findings';        Title='Security Findings';                     Summary='Heuristic risk flags raised while parsing this configuration.';                                                                  CountKey='findings';      Builder=$null },
        @{ Id='system';     Nav='System Overview';          Title='System Overview';                       Summary='Core system services: DNS, NTP, time zone, WebGUI security, SSH and console protection.';                                        CountKey=$null;           Builder={ param($r) Build-System $r } },
        @{ Id='interfaces'; Nav='Interfaces';               Title='Interfaces';                            Summary='Every configured interface and its addressing, VLAN and filtering options.';                                                     CountKey='interfaces';    Builder={ param($r) Build-Interfaces $r } },
        @{ Id='ifgroups';   Nav='Groups / LAGGs / Bridges'; Title='Interface Groups, LAGGs &amp; Bridges'; Summary='Logical interface groups, link aggregations (LAGG), and Layer-2 bridges.';                                                       CountKey=$null;           Builder={ param($r) Build-IfGroupsAndL2 $r } },
        @{ Id='vlans';      Nav='VLANs';                    Title='VLANs';                                 Summary='IEEE 802.1Q VLANs defined on physical interfaces.';                                                                              CountKey='vlans';         Builder={ param($r) Build-Vlans $r } },
        @{ Id='vips';       Nav='Virtual IPs';              Title='Virtual IPs';                           Summary='CARP, IP Alias, Proxy ARP and other virtual IP addresses.';                                                                      CountKey='virtualIps';    Builder={ param($r) Build-VirtualIps $r } },
        @{ Id='gateways';   Nav='Gateways';                 Title='Gateways &amp; Groups';                 Summary='Upstream gateways, default route selections, and multi-WAN gateway groups.';                                                     CountKey='gateways';      Builder={ param($r) Build-Gateways $r } },
        @{ Id='routes';     Nav='Static Routes';            Title='Static Routes';                         Summary='Manually configured static routes to remote networks.';                                                                          CountKey='staticRoutes';  Builder={ param($r) Build-Routes $r } },
        @{ Id='firewall';   Nav='Firewall Rules';           Title='Firewall Rules';                        Summary='Packet-filter rules grouped by interface (floating first), with risk flags highlighted.';                                        CountKey='firewallRules'; Builder={ param($r) Build-Firewall $r } },
        @{ Id='nat';        Nav='NAT';                      Title='NAT';                                   Summary='Outbound NAT mode and rules, port forwards, and 1:1 NAT mappings.';                                                              CountKey='natTotal';      Builder={ param($r) Build-Nat $r } },
        @{ Id='ipsec';      Nav='VPN - IPsec';              Title='VPN &mdash; IPsec';                     Summary='IPsec tunnels: Phase 1 (IKE) peers and Phase 2 (child SA) tunnel networks.';                                                     CountKey='ipsecTunnels';  Builder={ param($r) Build-Ipsec $r } },
        @{ Id='openvpn';    Nav='VPN - OpenVPN';            Title='VPN &mdash; OpenVPN';                   Summary='OpenVPN server and client instances and their cryptographic settings.';                                                          CountKey='openVpn';       Builder={ param($r) Build-OpenVpn $r } },
        @{ Id='wireguard';  Nav='VPN - WireGuard';          Title='VPN &mdash; WireGuard';                 Summary='WireGuard tunnels and peers. Private and preshared keys are never exported.';                                                    CountKey='wireGuard';     Builder={ param($r) Build-WireGuard $r } },
        @{ Id='ha';         Nav='High Availability';        Title='High Availability (CARP / Sync)';       Summary='pfsync state synchronization and XMLRPC configuration sync settings.';                                                           CountKey=$null;           Builder={ param($r) Build-HighAvailability $r } },
        @{ Id='dhcp';       Nav='DHCP Servers';             Title='DHCP Servers &amp; Relay';              Summary='Per-interface DHCPv4/DHCPv6 scopes, pools, static reservations, and relay settings.';                                            CountKey=$null;           Builder={ param($r) Build-Dhcp $r } },
        @{ Id='dns';        Nav='DNS Resolver / Forwarder'; Title='DNS Resolver / Forwarder';              Summary='Unbound resolver and dnsmasq forwarder settings and overrides.';                                                                 CountKey=$null;           Builder={ param($r) Build-Dns $r } },
        @{ Id='certs';      Nav='Certificates & CAs';       Title='Certificates, CAs &amp; CRLs';          Summary='Certificate authorities, certificates, and CRLs with expiry, key/signature analysis, and usage context.';                        CountKey='certsAndCas';   Builder={ param($r) Build-Certs $r } },
        @{ Id='users';      Nav='Users & Groups';           Title='Users, Groups &amp; Auth';              Summary='Local user accounts, groups, and external LDAP/RADIUS servers. Hashes and secrets are never exported.';                          CountKey='users';         Builder={ param($r) Build-Users $r } },
        @{ Id='aliases';    Nav='Aliases';                  Title='Aliases';                               Summary='Reusable host, network, port and URL aliases referenced by rules.';                                                              CountKey='aliases';       Builder={ param($r) Build-Aliases $r } },
        @{ Id='services';   Nav='Services (SNMP / Syslog)'; Title='System Services';                       Summary='SNMP, remote Syslog, Dynamic DNS, and firewall schedules.';                                                                      CountKey=$null;           Builder={ param($r) Build-Services $r } },
        @{ Id='packages';   Nav='Installed Packages';       Title='Installed Packages';                    Summary='Add-on packages installed on this firewall.';                                                                                    CountKey='packages';      Builder={ param($r) Build-Packages $r } },
        @{ Id='revision';   Nav='Revision / Notes';         Title='Revision / Notes';                      Summary='Metadata about the most recent configuration change.';                                                                           CountKey=$null;           Builder={ param($r) Build-Revision $r } }
    )

    foreach ($sd in $sectionDefs) {
        if ($null -ne $sd.Builder) { $sd.Body = & $sd.Builder $root }
    }
    $sectionDefs[0].Body = Build-Findings

    $cFind     = $script:Findings.Count
    $highCount = @($script:Findings | Where-Object { $_.Sev -eq 'high' }).Count
    $warnCount = @($script:Findings | Where-Object { $_.Sev -eq 'warn' }).Count
    $infoCount = @($script:Findings | Where-Object { $_.Sev -eq 'info' }).Count
    $counts['findings'] = $cFind

    $genTime  = $script:Now.ToString('yyyy-MM-dd HH:mm:ss zzz')
    $hostDisp = if (-not $hostname) { 'unknown' } elseif ($script:IsRedacted) { Get-RedactToken $hostname.ToLowerInvariant() 'HOST' } else { $hostname }
    $domDisp  = if (-not $domain)   { '' }        elseif ($script:IsRedacted) { Get-RedactToken $domain.ToLowerInvariant() 'DOMAIN' } else { $domain }
    $fqdn     = if ($domDisp) { "$hostDisp.$domDisp" } else { $hostDisp }

    $outContent = ''
    if ($HuduValue) {
        $outContent = Build-HuduReport -Root $root -Format $normHuduFmt -TitleValue $TitleValue -Fqdn $fqdn -Version $version -GenTime $genTime
    }
    else {
        $sectionsSb = New-Object System.Text.StringBuilder
        $navSb      = New-Object System.Text.StringBuilder
        foreach ($sd in $sectionDefs) {
            [void]$sectionsSb.Append((Wrap-Section $sd.Id $sd.Title $sd.Summary $sd.Body))
            $emptyCls = if ([string]::IsNullOrWhiteSpace($sd.Body)) { ' class="nav-empty"' } else { '' }
            $cntVal   = if ($sd.CountKey) { $counts[$sd.CountKey] } else { 0 }
            $cntBadge = if ($cntVal -gt 0) { '<span class="nav-cnt">' + $cntVal + '</span>' } else { '' }
            [void]$navSb.Append('<a href="#' + $sd.Id + '"' + $emptyCls + '><span>' + [System.Net.WebUtility]::HtmlEncode($sd.Nav) + '</span>' + $cntBadge + '</a>')
        }

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

        $riskCls = if ($highCount -gt 0) { 'sev-high' } elseif ($warnCount -gt 0) { 'sev-warn' } elseif ($infoCount -gt 0) { 'sev-info' } else { 'sev-ok' }
        $statItems = New-Object 'System.Collections.Generic.List[object]'
        foreach ($st in @(
            @($counts.interfaces,    'Interfaces',     ''),
            @($counts.firewallRules, 'Firewall rules', ''),
            @($counts.portForwards,  'Port forwards',  ''),
            @($counts.ipsecTunnels,  'IPsec tunnels',  ''),
            @($counts.openVpn,       'OpenVPN',        '')
        )) { [void]$statItems.Add($st) }
        if ($counts.wireGuard -gt 0) { [void]$statItems.Add(@($counts.wireGuard, 'WireGuard', '')) }
        [void]$statItems.Add(@($counts.certsAndCas, 'Certs / CAs', ''))
        [void]$statItems.Add(@($cFind,              'Risk flags',  $riskCls))

        $cardsSb = New-Object System.Text.StringBuilder
        [void]$cardsSb.Append('<div class="cards">')
        foreach ($st in $statItems) {
            $nCls = if ($st[2]) { 'n ' + $st[2] } else { 'n' }
            [void]$cardsSb.Append('<div class="card"><div class="' + $nCls + '">' + $st[0] + '</div><div class="l">' + $st[1] + '</div></div>')
        }
        [void]$cardsSb.Append('</div>')

        $cover = '<div class="cover"><div class="cover-top">' + (Get-LogoTag $LogoPathValue) +
                 '<div><h1>' + (E $TitleValue) + '</h1><div class="sub">Generated by pfsense_report.ps1 v' + $script:ToolVersion + $(if ($script:IsRedacted) { ' &mdash; REDACTED COPY' } else { '' }) + '</div></div></div>' +
                 '<div class="meta">' +
                 '<div><span>Hostname</span><strong>' + [System.Net.WebUtility]::HtmlEncode($fqdn) + '</strong></div>' +
                 '<div><span>pfSense config version</span><strong>' + $(if ($version) { [System.Net.WebUtility]::HtmlEncode($version) } else { 'unknown' }) + '</strong></div>' +
                 '<div><span>Report generated</span><strong>' + [System.Net.WebUtility]::HtmlEncode($genTime) + '</strong></div>' +
                 '<div><span>Source file</span><strong>' + $(if ($script:IsRedacted) { '[redacted]' } else { [System.Net.WebUtility]::HtmlEncode([System.IO.Path]::GetFileName($resolvedConfig)) }) + '</strong></div>' +
                 '</div></div>'

        $sidebarBrand = if (-not $hostname) { '' } elseif ($script:IsRedacted) { [System.Net.WebUtility]::HtmlEncode((Get-RedactToken $hostname.ToLowerInvariant() 'HOST')) } else { [System.Net.WebUtility]::HtmlEncode($hostname) }
        $sidebar = '<aside class="sidebar"><div class="brand">pfSense Report<small>' + $sidebarBrand + '</small></div>' +
                   '<label for="navfilter" class="sr-only">Filter sections</label>' +
                   '<input id="navfilter" class="navfilter" type="search" placeholder="Filter sections..." aria-label="Filter sections" />' +
                   '<div class="navtools"><button type="button" id="btn-expand-all">Expand all</button><button type="button" id="btn-collapse-all">Collapse all</button>' +
                   '<button type="button" id="btn-print">Print / PDF</button><button type="button" id="btn-theme">Dark theme</button></div>' +
                   '<nav aria-label="Report sections">' + $navSb.ToString() + '</nav></aside>'

        $searchBar = '<div class="search-bar"><label for="global-search" class="sr-only">Search report tables</label>' +
                     '<input id="global-search" type="search" placeholder="Search rules, IPs, ports, aliases, hosts, packages..." aria-label="Search report tables" />' +
                     '<span id="global-search-status" class="search-status" aria-live="polite"></span>' +
                     '<button type="button" id="global-search-clear">Clear</button></div>'

        $footer = '<div class="footer">Generated locally by pfsense_report.ps1 v' + $script:ToolVersion + ' &mdash; no data left this machine. Heuristic risk flags are informational and do not replace a manual security review.</div>'
        $csp    = "default-src 'none'; img-src data:; style-src 'unsafe-inline'; script-src 'unsafe-inline';"

        $docSb = New-Object System.Text.StringBuilder
        [void]$docSb.Append('<!DOCTYPE html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">')
        [void]$docSb.Append('<meta name="color-scheme" content="light dark"><meta http-equiv="Content-Security-Policy" content="' + $csp + '">')
        [void]$docSb.Append('<title>' + (E $TitleValue) + '</title><style>' + $script:ReportCss + '</style></head><body>')
        [void]$docSb.Append('<a class="skip-link" href="#main-content">Skip to report content</a>').Append($sidebar)
        [void]$docSb.Append('<main id="main-content" class="main">').Append($cover).Append($banners.ToString()).Append($cardsSb.ToString()).Append($searchBar).Append($sectionsSb.ToString()).Append($footer)
        [void]$docSb.Append('</main><script>' + $script:ReportJs + '</script></body></html>')
        $outContent = $docSb.ToString()
    }

    $outDir = [System.IO.Path]::GetDirectoryName($resolvedOutput)
    if (-not [string]::IsNullOrWhiteSpace($outDir) -and -not (Test-Path -LiteralPath $outDir)) { [void](New-Item -ItemType Directory -Path $outDir -Force) }
    $utf8 = New-Object System.Text.UTF8Encoding($false)
    [System.IO.File]::WriteAllText($resolvedOutput, $outContent, $utf8)

    $summaryObj = [pscustomobject]@{
        toolVersion   = $script:ToolVersion
        generatedAt   = $genTime
        redacted      = $script:IsRedacted
        mode          = if ($HuduValue) { "Hudu-$normHuduFmt" } else { 'Full-Html' }
        hostname      = $fqdn
        configVersion = $version
        outputPath    = $resolvedOutput
        counts        = [pscustomobject]@{
            interfaces    = $counts.interfaces;    vlans         = $counts.vlans;        virtualIps   = $counts.virtualIps
            gateways      = $counts.gateways;      staticRoutes  = $counts.staticRoutes; firewallRules = $counts.firewallRules
            portForwards  = $counts.portForwards;  ipsecTunnels  = $counts.ipsecTunnels; openVpn      = $counts.openVpn
            wireGuard     = $counts.wireGuard;     certsAndCas   = $counts.certsAndCas;  users        = $counts.users
            aliases       = $counts.aliases;       packages      = $counts.packages
            findings      = [pscustomobject]@{ total = $cFind; high = $highCount; warn = $warnCount; info = $infoCount }
        }
        findings      = @(foreach ($f in $script:Findings) {
            [pscustomobject]@{
                severity = $f.Sev
                label    = $f.Label
                location = if ($script:IsRedacted) { Apply-Redaction $f.Where } else { $f.Where }
                detail   = if ($script:IsRedacted) { Apply-Redaction $f.Detail } else { $f.Detail }
            }
        })
    }

    if (-not [string]::IsNullOrWhiteSpace($JsonPathValue)) {
        $resolvedJson = Resolve-FullPath $JsonPathValue
        $jsonDir = [System.IO.Path]::GetDirectoryName($resolvedJson)
        if (-not [string]::IsNullOrWhiteSpace($jsonDir) -and -not (Test-Path -LiteralPath $jsonDir)) { [void](New-Item -ItemType Directory -Path $jsonDir -Force) }
        [System.IO.File]::WriteAllText($resolvedJson, ($summaryObj | ConvertTo-Json -Depth 6), $utf8)
    }

    if (-not $QuietValue) {
        Write-Host "pfSense report written to: $resolvedOutput" -ForegroundColor Green
        if ($HuduValue) {
            Write-Host ("Hudu {0} summary rendered ({1} high, {2} warn alert(s))." -f $normHuduFmt, $highCount, $warnCount)
        }
        else {
            Write-Host ("{0} sections rendered, {1} risk flag(s) raised ({2} high, {3} warn, {4} info)." -f $sectionDefs.Count, $cFind, $highCount, $warnCount, $infoCount)
        }
    }
    return $summaryObj
}

if ($MyInvocation.InvocationName -ne '.') {
    try {
        $useHudu = [bool]$Hudu -or $PSBoundParameters.ContainsKey('HuduFormat')
        $effHuduFmt = $HuduFormat
        if ($useHudu -and -not $PSBoundParameters.ContainsKey('HuduFormat') -and $OutputPath -match '\.(md|markdown)$') {
            $effHuduFmt = 'Markdown'
        }
        $result = Invoke-PfSenseReport `
            -ConfigPathValue $ConfigPath -OutputPathValue $OutputPath -RedactValue ([bool]$Redact) `
            -TitleValue $Title -LogoPathValue $LogoPath `
            -WanInterfacesValue $WanInterfaces -InternalInterfacesValue $InternalInterfaces `
            -ExpiryWarnDaysValue $ExpiryWarnDays -JsonPathValue $JsonPath `
            -HuduValue $useHudu -HuduFormatValue $effHuduFmt -QuietValue ([bool]$Quiet)
        if ($PassThru) { $result }
        exit 0
    }
    catch {
        Write-Error ("Error (line {0}): {1}" -f $_.InvocationInfo.ScriptLineNumber, $_.Exception.Message)
        exit 1
    }
}
