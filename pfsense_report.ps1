<#
.SYNOPSIS
    Generate a professional, self-contained HTML report from a pfSense config.xml.

.DESCRIPTION
    pfsense_report.ps1 parses a pfSense configuration backup (config.xml) entirely
    locally using PowerShell's built-in [xml] parser and the .NET base class library.
    It produces a single, self-contained .html file (all CSS / JS embedded) that can be
    opened in any modern browser on an air-gapped machine and printed to PDF.

    No AI, no external API, no internet connection, and no third-party modules are used.
    Compatible with Windows PowerShell 5.1 and PowerShell 7+.

.PARAMETER ConfigPath
    Path to the pfSense config.xml file to parse. (Required)

.PARAMETER OutputPath
    Path of the .html report to write. Defaults to "<configname>-report.html"
    in the current directory.

.PARAMETER Redact
    Replace sensitive values (PSKs, passwords, SNMP communities) with [REDACTED] and
    mask IP addresses, MAC addresses, hostnames and domains so the report can be shared.
    Password hashes, private keys and other key material are NEVER emitted regardless
    of this switch.

.PARAMETER Title
    Custom title shown in the report header. Defaults to "pfSense Configuration Report".

.PARAMETER LogoPath
    Optional path to a logo image (png/jpg/gif/svg). Embedded as inline base64.

.EXAMPLE
    .\pfsense_report.ps1 -ConfigPath "config.xml" -OutputPath "report.html"

.EXAMPLE
    .\pfsense_report.ps1 -ConfigPath "config.xml" -OutputPath "shared.html" -Redact -Title "Acme Firewall"
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true, Position = 0)]
    [string]$ConfigPath,

    [Parameter(Position = 1)]
    [string]$OutputPath,

    [switch]$Redact,

    [string]$Title = "pfSense Configuration Report",

    [string]$LogoPath
)

# ----------------------------------------------------------------------------------
#  Script-scoped state
# ----------------------------------------------------------------------------------
$script:Redact        = [bool]$Redact
$script:RedactHost    = $null
$script:RedactDomain  = $null
$script:Findings      = New-Object System.Collections.Generic.List[object]
$script:Now           = Get-Date
# Stable redaction maps: each distinct value gets a consistent token (IP-001, HOST-002, ...)
# so a sanitized report still preserves correlation between rules without exposing real values.
$script:RedactMaps    = @{ IP = @{}; MAC = @{}; HOST = @{}; DOMAIN = @{} }

# ==================================================================================
#  HELPER FUNCTIONS
# ==================================================================================

function Get-RedactToken {
    param([string]$value, [string]$kind)
    if ([string]::IsNullOrWhiteSpace($value)) { return $value }
    $map = $script:RedactMaps[$kind]
    if ($null -eq $map) { $map = $script:RedactMaps['HOST'] }
    if (-not $map.ContainsKey($value)) { $map[$value] = ('{0}-{1:000}' -f $kind, ($map.Count + 1)) }
    return $map[$value]
}

function Apply-Redaction {
    param([string]$text)
    if (-not $script:Redact) { return $text }
    if ([string]::IsNullOrEmpty($text)) { return $text }
    $t = $text
    # MAC addresses first (so the IPv6 pass cannot touch them) -> stable MAC-NNN token
    $t = [regex]::Replace($t, '(?i)\b([0-9a-f]{2}:){5}[0-9a-f]{2}\b',
        [System.Text.RegularExpressions.MatchEvaluator] { param($m) Get-RedactToken $m.Value 'MAC' })
    # IPv4 addresses (CIDR suffix preserved so network sizes stay visible) -> IP-NNN
    $t = [regex]::Replace($t, '\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b',
        [System.Text.RegularExpressions.MatchEvaluator] { param($m) Get-RedactToken $m.Value 'IP' })
    # IPv6 addresses (conservative: at least two ':' groups) -> IP-NNN
    $t = [regex]::Replace($t, '(?i)\b(?:[0-9a-f]{1,4}:){2,7}[0-9a-f]{0,4}\b',
        [System.Text.RegularExpressions.MatchEvaluator] { param($m) Get-RedactToken $m.Value 'IP' })
    # Specific system domain / hostname (bare, single-label) -> stable tokens
    if ($script:RedactDomain) { $t = $t -replace [regex]::Escape($script:RedactDomain), (Get-RedactToken $script:RedactDomain 'DOMAIN') }
    if ($script:RedactHost)   { $t = $t -replace [regex]::Escape($script:RedactHost),   (Get-RedactToken $script:RedactHost 'HOST') }
    # Remaining FQDN-style hostnames -> HOST-NNN
    $t = [regex]::Replace($t, '(?i)\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{1,62}\b',
        [System.Text.RegularExpressions.MatchEvaluator] { param($m) Get-RedactToken $m.Value 'HOST' })
    return $t
}

function E {
    # Encode a raw data value for safe HTML output (applies redaction first).
    param([object]$s)
    if ($null -eq $s) { return '' }
    $str = [string]$s
    if ($script:Redact) { $str = Apply-Redaction $str }
    return [System.Net.WebUtility]::HtmlEncode($str)
}

function Dash {
    # Encode a value; show an em-dash placeholder when empty.
    param([object]$s)
    $str = [string]$s
    if ([string]::IsNullOrWhiteSpace($str)) { return '<span class="muted">&mdash;</span>' }
    return (E $str)
}

function Secret {
    # PSKs / passwords / community strings: shown by default, [REDACTED] under -Redact.
    param([object]$s)
    $str = [string]$s
    if ([string]::IsNullOrWhiteSpace($str)) { return '<span class="muted">&mdash;</span>' }
    if ($script:Redact) { return '<span class="redacted">[REDACTED]</span>' }
    return [System.Net.WebUtility]::HtmlEncode($str)
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
    # resulting scalar is $null -- which silently skips single-item sections. The
    # ',$arr' return guarantees array semantics on both 5.1 and 7.
    param($node, [string]$path)
    $arr = @()
    if ($null -ne $node) {
        $r = $node.SelectNodes($path)
        if ($null -ne $r) { foreach ($n in $r) { $arr += $n } }
    }
    return , $arr
}

function YesNo {
    param([bool]$b)
    if ($b) { return '<span class="badge badge-ok">Yes</span>' }
    return '<span class="badge badge-muted">No</span>'
}

function Add-Finding {
    param([string]$Sev, [string]$Label, [string]$Where, [string]$Detail)
    $script:Findings.Add([pscustomobject]@{ Sev = $Sev; Label = $Label; Where = $Where; Detail = $Detail })
}

function ConvertFrom-Epoch {
    param([string]$s)
    if ([string]::IsNullOrWhiteSpace($s)) { return '' }
    $n = [int64]0
    if ([int64]::TryParse($s, [ref]$n)) {
        try { return ([DateTimeOffset]::FromUnixTimeSeconds($n)).LocalDateTime.ToString('yyyy-MM-dd HH:mm:ss') }
        catch { return $s }
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
        if ($take -le 0)    { $octets[$i] = 0 }
        elseif ($take -ge 8){ $octets[$i] = 255 }
        else                { $octets[$i] = [int](256 - [math]::Pow(2, 8 - $take)) }
    }
    return ($octets -join '.')
}

function Get-WeakCryptoHits {
    param([string[]]$values)
    $hits = New-Object System.Collections.Generic.List[string]
    foreach ($v in $values) {
        if ([string]::IsNullOrWhiteSpace($v)) { continue }
        if ($v -match '(?i)(3des|des-ede|tripledes)') { $hits.Add('3DES') }
        elseif ($v -match '(?i)(^|[^a-z0-9])des([^a-z0-9]|$)') { $hits.Add('DES') }
        if ($v -match '(?i)md5') { $hits.Add('MD5') }
    }
    $uniq = @($hits | Select-Object -Unique)
    return , $uniq
}

function Get-CertInfo {
    param([string]$CrtField)
    $r = [pscustomobject]@{ Subject=''; Issuer=''; NotBefore=$null; NotAfter=$null; SigAlg=''; SelfSigned=$false; Error=$null }
    if ([string]::IsNullOrWhiteSpace($CrtField)) { $r.Error = 'No certificate data'; return $r }
    try {
        $pem = $CrtField.Trim()
        if ($pem -notmatch 'BEGIN CERTIFICATE') {
            # Field is base64-of-PEM (pfSense default); decode the outer layer.
            try { $pem = [System.Text.Encoding]::ASCII.GetString([Convert]::FromBase64String(($CrtField -replace '\s', ''))) } catch { }
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
        $cert.Dispose()
    }
    catch { $r.Error = $_.Exception.Message }
    return $r
}

function Format-CertStatus {
    # Returns an HTML badge describing the certificate validity, and records findings.
    param($info, [string]$where)
    if ($info.Error) { return '<span class="badge badge-info">PARSE ERROR</span>' }
    if ($null -eq $info.NotAfter) { return '<span class="badge badge-muted">Unknown</span>' }
    $days = ($info.NotAfter - $script:Now).TotalDays
    if ($days -lt 0) {
        Add-Finding 'high' 'EXPIRED' $where ("Certificate expired " + $info.NotAfter.ToString('yyyy-MM-dd'))
        return '<span class="badge badge-high">EXPIRED</span>'
    }
    elseif ($days -lt 90) {
        Add-Finding 'warn' 'EXPIRING SOON' $where ("Certificate expires " + $info.NotAfter.ToString('yyyy-MM-dd') + " (" + [int]$days + " days)")
        return '<span class="badge badge-warn">EXPIRING SOON</span>'
    }
    return '<span class="badge badge-ok">Valid</span>'
}

function Tbl {
    param([string[]]$headers, [string]$bodyHtml)
    $h = ''
    foreach ($x in $headers) { $h += '<th>' + $x + '</th>' }
    return '<div class="table-wrap"><table><thead><tr>' + $h + '</tr></thead><tbody>' + $bodyHtml + '</tbody></table></div>'
}

function Wrap-Section {
    param([string]$id, [string]$title, [string]$summary, [string]$body, [string]$headerBadge = '')
    $b = $body
    if ([string]::IsNullOrWhiteSpace($b)) { $b = '<p class="not-configured">Not configured.</p>' }
    return '<section class="report-section" id="' + $id + '">' +
           '<h2 class="section-header" role="button" tabindex="0" aria-expanded="true" onclick="toggleSection(this)" onkeydown="sectionKey(event,this)">' +
           '<span class="toggle-icon">&#9662;</span><span class="sh-title">' + $title + '</span>' + $headerBadge + '</h2>' +
           '<div class="section-body"><p class="section-summary">' + $summary + '</p>' + $b + '</div></section>'
}

function Format-Endpoint {
    # Returns a small object describing a firewall/NAT source or destination node.
    param($epNode)
    $o = [pscustomobject]@{ Addr = 'any'; Port = '' }
    if ($null -eq $epNode) { return $o }
    $neg = ''
    if (XHas $epNode 'not') { $neg = '! ' }
    if (XHas $epNode 'any')              { $o.Addr = 'any' }
    elseif (XText $epNode 'network')     { $o.Addr = (XText $epNode 'network') }
    elseif (XText $epNode 'address')     { $o.Addr = (XText $epNode 'address') }
    else                                 { $o.Addr = 'any' }
    $o.Addr = $neg + $o.Addr
    $o.Port = (XText $epNode 'port')
    return $o
}

function Get-LogoTag {
    param([string]$path)
    if ([string]::IsNullOrWhiteSpace($path)) { return '' }
    if (-not (Test-Path -LiteralPath $path)) { Write-Warning "Logo not found: $path"; return '' }
    try {
        $bytes = [System.IO.File]::ReadAllBytes($path)
        $b64   = [Convert]::ToBase64String($bytes)
        $ext   = ([System.IO.Path]::GetExtension($path)).ToLower()
        switch ($ext) {
            '.png'  { $mime = 'image/png' }
            '.jpg'  { $mime = 'image/jpeg' }
            '.jpeg' { $mime = 'image/jpeg' }
            '.gif'  { $mime = 'image/gif' }
            '.svg'  { $mime = 'image/svg+xml' }
            '.webp' { $mime = 'image/webp' }
            default { $mime = 'image/png' }
        }
        return '<img class="cover-logo" alt="Logo" src="data:' + $mime + ';base64,' + $b64 + '" />'
    }
    catch { Write-Warning "Could not embed logo: $($_.Exception.Message)"; return '' }
}

# ==================================================================================
#  SECTION BUILDERS
# ==================================================================================

function Build-System {
    param($root)
    $sys = $root.SelectSingleNode('system')
    if ($null -eq $sys) { return '' }

    $dns = @(); foreach ($d in (XNodes $sys 'dnsserver')) { if ($d.InnerText.Trim()) { $dns += $d.InnerText.Trim() } }
    $ntp = @((XText $sys 'timeservers') -split '\s+' | Where-Object { $_ })
    $tz  = XText $sys 'timezone'
    $gui = $sys.SelectSingleNode('webgui')
    $proto = XText $gui 'protocol'; if (-not $proto) { $proto = 'https' }
    $port  = XText $gui 'port'
    if (-not $port) { if ($proto -eq 'http') { $port = '80 (default)' } else { $port = '443 (default)' } }
    $sshNode = $sys.SelectSingleNode('ssh')
    $sshEnabled = $false
    if ($sshNode) {
        $sv = (XText $sshNode 'enable')
        if ($sv -or (XHas $sshNode 'enabled')) { $sshEnabled = $true }
        if ($sv -match '(?i)enabled|on|yes') { $sshEnabled = $true }
    }
    $consoleProtected = (XHas $sys 'disableconsolemenu')

    $rows = ''
    $rows += '<tr><th>Hostname</th><td>' + (Dash (XText $sys 'hostname')) + '</td></tr>'
    $rows += '<tr><th>Domain</th><td>' + (Dash (XText $sys 'domain')) + '</td></tr>'
    if ($dns.Count) { $rows += '<tr><th>DNS servers</th><td>' + (($dns | ForEach-Object { E $_ }) -join '<br>') + '</td></tr>' }
    else { $rows += '<tr><th>DNS servers</th><td><span class="muted">&mdash;</span></td></tr>' }
    if ($ntp.Count) { $rows += '<tr><th>NTP servers</th><td>' + (($ntp | ForEach-Object { E $_ }) -join '<br>') + '</td></tr>' }
    else { $rows += '<tr><th>NTP servers</th><td><span class="muted">&mdash;</span></td></tr>' }
    $rows += '<tr><th>Time zone</th><td>' + (Dash $tz) + '</td></tr>'
    $rows += '<tr><th>WebGUI</th><td>' + (E $proto) + ' on port ' + (E $port) + '</td></tr>'
    $rows += '<tr><th>SSH access</th><td>' + (YesNo $sshEnabled) + '</td></tr>'
    $rows += '<tr><th>Console password protection</th><td>' + (YesNo $consoleProtected) + '</td></tr>'
    $rows += '<tr><th>Tuning / optimization</th><td>' + (Dash (XText $sys 'optimization')) + '</td></tr>'

    return '<div class="table-wrap"><table class="kv">' + $rows + '</table></div>'
}

function Build-Interfaces {
    param($root, $vlanTagMap)
    $ifs = $root.SelectSingleNode('interfaces')
    if ($null -eq $ifs) { return '' }
    $body = ''
    $any = $false
    foreach ($c in $ifs.ChildNodes) {
        if ($c.NodeType -ne [System.Xml.XmlNodeType]::Element) { continue }
        $any = $true
        $key   = $c.Name
        $descr = XText $c 'descr'
        $dev   = XText $c 'if'
        $en    = (XHas $c 'enable')
        $ipv4  = XText $c 'ipaddr'
        $method = switch -regex ($ipv4) {
            '^dhcp$'   { 'DHCP' ; break }
            '^pppoe$'  { 'PPPoE'; break }
            '^dhcp6$'  { 'DHCP6'; break }
            '^\d+\.'   { 'Static'; break }
            '^$'       { 'None'; break }
            default    { $ipv4 }
        }
        $ipv4disp = $ipv4
        if ($ipv4 -match '^(dhcp|pppoe|dhcp6|)$') { $ipv4disp = '' }
        $subnet = XText $c 'subnet'
        $mask   = Get-Ipv4Mask $subnet
        $subnetDisp = ''
        if ($subnet) { $subnetDisp = '/' + $subnet; if ($mask) { $subnetDisp += ' (' + $mask + ')' } }
        $v6 = XText $c 'ipaddrv6'
        $v6disp = switch -regex ($v6) {
            '^track6$' { 'Track IPv6 (WAN)'; break }
            '^dhcp6$'  { 'DHCP6'; break }
            '^slaac$'  { 'SLAAC'; break }
            '^$'       { ''; break }
            default    { $v6 }
        }
        $sv6 = XText $c 'subnetv6'; if ($sv6 -and $v6disp) { $v6disp += '/' + $sv6 }
        $mac = XText $c 'spoofmac'
        $mtu = XText $c 'mtu'
        $mss = XText $c 'mss'
        $vlan = ''
        if ($dev -match '\.(\d+)$') { $vlan = $Matches[1] }
        elseif ($vlanTagMap.ContainsKey($dev)) { $vlan = $vlanTagMap[$dev] }
        $gw  = XText $c 'gateway'
        $brfc = (XHas $c 'blockpriv')
        $bbog = (XHas $c 'blockbogons')

        $cls = ''; if (-not $en) { $cls = ' class="row-disabled"' }
        $body += '<tr' + $cls + '>'
        $body += '<td>' + (E $key) + '</td>'
        $body += '<td>' + (Dash $descr) + '</td>'
        $body += '<td>' + (Dash $dev) + '</td>'
        $body += '<td>' + (YesNo $en) + '</td>'
        $body += '<td>' + (Dash $method) + '</td>'
        $body += '<td>' + (Dash $ipv4disp) + '</td>'
        $body += '<td>' + (Dash $subnetDisp) + '</td>'
        $body += '<td>' + (Dash $v6disp) + '</td>'
        $body += '<td>' + (Dash $mac) + '</td>'
        $body += '<td>' + (Dash $mtu) + '</td>'
        $body += '<td>' + (Dash $mss) + '</td>'
        $body += '<td>' + (Dash $vlan) + '</td>'
        $body += '<td>' + (Dash $gw) + '</td>'
        $body += '<td>' + (YesNo $brfc) + '</td>'
        $body += '<td>' + (YesNo $bbog) + '</td>'
        $body += '</tr>'
    }
    if (-not $any) { return '' }
    return (Tbl @('Key','Description','Device','Enabled','IPv4 Method','IPv4 Address','Subnet','IPv6','MAC (spoof)','MTU','MSS','VLAN','Gateway','Block RFC1918','Block bogons') $body)
}

function Build-Vlans {
    param($root)
    $vl = $root.SelectSingleNode('vlans')
    if ($null -eq $vl) { return '' }
    $body = ''
    foreach ($v in (XNodes $vl 'vlan')) {
        $body += '<tr>'
        $body += '<td>' + (Dash (XText $v 'if')) + '</td>'
        $body += '<td>' + (Dash (XText $v 'tag')) + '</td>'
        $body += '<td>' + (Dash (XText $v 'pcp')) + '</td>'
        $body += '<td>' + (Dash (XText $v 'vlanif')) + '</td>'
        $body += '<td>' + (Dash (XText $v 'descr')) + '</td>'
        $body += '</tr>'
    }
    if (-not $body) { return '' }
    return (Tbl @('Parent interface','VLAN tag','Priority (PCP)','VLAN interface','Description') $body)
}

function Build-Gateways {
    param($root)
    $gws = $root.SelectSingleNode('gateways')
    if ($null -eq $gws) { return '' }
    $def4 = XText $gws 'defaultgw4'
    $def6 = XText $gws 'defaultgw6'
    $body = ''
    foreach ($g in (XNodes $gws 'gateway_item')) {
        $name = XText $g 'name'
        $isDef = ($name -and (($name -eq $def4) -or ($name -eq $def6)))
        $body += '<tr>'
        $body += '<td>' + (Dash $name) + '</td>'
        $body += '<td>' + (Dash (XText $g 'interface')) + '</td>'
        $body += '<td>' + (Dash (XText $g 'gateway')) + '</td>'
        $body += '<td>' + (Dash (XText $g 'monitor')) + '</td>'
        $body += '<td>' + (Dash (XText $g 'ipprotocol')) + '</td>'
        if ($isDef) { $body += '<td><span class="badge badge-info">DEFAULT</span></td>' } else { $body += '<td><span class="muted">&mdash;</span></td>' }
        $body += '<td>' + (Dash (XText $g 'descr')) + '</td>'
        $body += '</tr>'
    }
    if (-not $body) { return '' }
    return (Tbl @('Name','Interface','Gateway IP','Monitor IP','Protocol','Default','Description') $body)
}

function Build-Routes {
    param($root)
    $sr = $root.SelectSingleNode('staticroutes')
    if ($null -eq $sr) { return '' }
    $body = ''
    foreach ($r in (XNodes $sr 'route')) {
        $disabled = (XHas $r 'disabled')
        $cls = ''; if ($disabled) { $cls = ' class="row-disabled"' }
        $body += '<tr' + $cls + '>'
        $body += '<td>' + (Dash (XText $r 'network')) + '</td>'
        $body += '<td>' + (Dash (XText $r 'gateway')) + '</td>'
        $body += '<td>' + (YesNo (-not $disabled)) + '</td>'
        $body += '<td>' + (Dash (XText $r 'descr')) + '</td>'
        $body += '</tr>'
    }
    if (-not $body) { return '' }
    return (Tbl @('Destination network','Gateway','Enabled','Description') $body)
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
    $p = (($proto -replace '/.*$', '')).ToLower().Trim()
    if ($p -in @('icmp', 'icmp6', 'ipv6-icmp', 'igmp')) { return 'icmp' }
    if ($p -in @('esp', 'ah', 'gre', 'pim', 'ospf', 'carp', 'pfsync', 'l2tp')) { return 'infra' }
    if ($p -in @('tcp', 'udp', 'tcp/udp')) { return 'tcpudp' }
    if ($p -in @('', 'any')) { return 'any' }
    return 'other'
}

function Get-RuleExposure {
    # Context-aware risk for a single PASS rule, scaled by interface trust + protocol.
    # Returns $null (no concern) or a hashtable: Sev / Label / Detail / Row.
    param(
        [string]$trust, [string]$type, [string]$dir, [string]$protoClass,
        [bool]$srcBroad, [bool]$dstBroad, [bool]$dstPortSet, [string]$protoDisp, [string]$dstSvc
    )
    if ($type -ne 'pass') { return $null }   # block/reject rules are not exposures
    if ($dir -eq 'out')   { return $null }   # outbound allows are not inbound exposure
    switch ($trust) {
        'wan' {
            if ($srcBroad) {
                if ($protoClass -eq 'icmp')  { return @{ Sev='info'; Label='WAN ICMP'; Detail='inbound ICMP from any source (diagnostic, low risk).'; Row='' } }
                if ($protoClass -eq 'infra') { return @{ Sev='info'; Label='WAN VPN'; Detail="inbound $protoDisp from any source (typical for VPN/tunnel endpoints)."; Row='' } }
                if ($dstBroad -and -not $dstPortSet) {
                    $pd = $protoDisp; if ($protoClass -eq 'any') { $pd = 'all protocols / all ports' }
                    return @{ Sev='high'; Label='HIGH RISK'; Detail="inbound $pd from ANY source to ANY destination (no port restriction) on a WAN (Internet-facing) interface."; Row=' row-high' }
                }
                return @{ Sev='warn'; Label='WAN EXPOSED'; Detail="inbound $protoDisp service published to the Internet (any source -> $dstSvc)."; Row=' row-warn' }
            }
            else {
                if ($protoClass -in @('tcpudp', 'any', 'other')) {
                    return @{ Sev='info'; Label='WAN (restricted)'; Detail='inbound WAN allow limited to specific source(s) - lower risk.'; Row='' }
                }
                return $null
            }
        }
        'vpn' {
            if ($srcBroad -and $dstBroad -and ($protoClass -in @('tcpudp', 'any', 'other'))) {
                return @{ Sev='info'; Label='VPN ANY'; Detail='VPN interface permits any-to-any (common for full-tunnel remote access).'; Row='' }
            }
            return $null
        }
        'floating' {
            if ($srcBroad -and $dstBroad -and ($protoClass -in @('tcpudp', 'any'))) {
                return @{ Sev='warn'; Label='FLOATING ANY'; Detail='floating rule permits any-to-any; verify the intended scope.'; Row=' row-warn' }
            }
            return $null
        }
        default { return $null }   # internal / trusted interfaces: any-to-any is expected
    }
    return $null
}

function Build-Firewall {
    param($root, $ifMap, $trustMap)
    $rules = XNodes $root 'filter/rule'
    if (-not $rules -or $rules.Count -eq 0) { return '' }

    $groups = [ordered]@{}
    foreach ($r in $rules) {
        $if = XText $r 'interface'; if (-not $if) { $if = '(floating)' }
        if (-not $groups.Contains($if)) { $groups[$if] = New-Object System.Collections.Generic.List[object] }
        $groups[$if].Add($r)
    }

    $out = '<p class="note">Risk is assessed from <strong>interface trust</strong> (WAN = Internet-facing / untrusted; LAN / OPT = internal / trusted; VPN = remote-access) combined with the <strong>protocol</strong>. An any-to-any rule on a trusted interface is normal and is not flagged; the same rule inbound on a WAN is, and TCP/UDP or all-protocol rules weigh heavier than ICMP.</p>'
    foreach ($key in $groups.Keys) {
        $trust = 'other'
        if ($trustMap.ContainsKey($key)) { $trust = $trustMap[$key] }
        $trustBadge = switch ($trust) {
            'wan'      { ' <span class="badge badge-high">UNTRUSTED / WAN</span>' }
            'vpn'      { ' <span class="badge badge-info">VPN</span>' }
            'floating' { ' <span class="badge badge-muted">FLOATING</span>' }
            'internal' { ' <span class="badge badge-ok">TRUSTED / INTERNAL</span>' }
            default    { '' }
        }
        $label = (E $key)
        if ($ifMap.ContainsKey($key) -and $ifMap[$key]) { $label += ' <span class="muted">&mdash; ' + (E $ifMap[$key]) + '</span>' }
        $body = ''
        $seq = 0
        foreach ($r in $groups[$key]) {
            $seq++
            $disabled = (XHas $r 'disabled')
            $type = XText $r 'type'
            $rawProto = XText $r 'protocol'
            $protoClass = Get-ProtoClass $rawProto
            $proto = $rawProto; if (-not $proto) { $proto = 'any' }
            if ($rawProto -eq 'icmp') { $it = XText $r 'icmptype'; if ($it) { $proto = 'icmp/' + $it } }
            $src = Format-Endpoint $r.SelectSingleNode('source')
            $dst = Format-Endpoint $r.SelectSingleNode('destination')
            $dir = XText $r 'direction'; if (-not $dir) { $dir = 'in' }
            $log = (XHas $r 'log')
            $descr = XText $r 'descr'
            $srcBroad = Test-Broad $src.Addr
            $dstBroad = Test-Broad $dst.Addr

            $where = "Firewall / $key rule #$seq"
            $badges = ''
            $rowCls = ''
            if ($disabled) { $rowCls = ' row-disabled'; $badges += '<span class="badge badge-muted">DISABLED</span> ' }

            if (-not $disabled) {
                $dstSvc = $dst.Addr; if ($dst.Port) { $dstSvc += ':' + $dst.Port }
                $exp = Get-RuleExposure -trust $trust -type $type -dir $dir -protoClass $protoClass -srcBroad $srcBroad -dstBroad $dstBroad -dstPortSet ([bool]$dst.Port) -protoDisp $proto -dstSvc $dstSvc
                if ($exp) {
                    $bcls = switch ($exp.Sev) { 'high' { 'badge-high' } 'warn' { 'badge-warn' } default { 'badge-info' } }
                    $badges += '<span class="badge ' + $bcls + '">' + (E $exp.Label) + '</span> '
                    if ($exp.Row -and $rowCls -eq '') { $rowCls = $exp.Row }
                    Add-Finding $exp.Sev $exp.Label $where ($(if($descr){$descr}else{'(no description)'}) + ' - ' + $exp.Detail)
                }
                if (-not $log) {
                    $badges += '<span class="badge badge-muted">NO LOG</span> '
                    Add-Finding 'info' 'NO LOG' $where ($(if($descr){$descr}else{'(no description)'}) + ' - logging is disabled on this rule.')
                }
            }

            $actBadge = switch ($type) {
                'pass'   { '<span class="badge badge-ok">PASS</span>' }
                'block'  { '<span class="badge badge-muted">BLOCK</span>' }
                'reject' { '<span class="badge badge-warn">REJECT</span>' }
                default  { (E $type) }
            }

            $body += '<tr class="' + $rowCls.Trim() + '">'
            $body += '<td>' + $seq + '</td>'
            $body += '<td>' + (YesNo (-not $disabled)) + '</td>'
            $body += '<td>' + $actBadge + '</td>'
            $body += '<td>' + (E $proto) + '</td>'
            $body += '<td>' + (Dash $src.Addr) + '</td>'
            $body += '<td>' + (Dash $src.Port) + '</td>'
            $body += '<td>' + (Dash $dst.Addr) + '</td>'
            $body += '<td>' + (Dash $dst.Port) + '</td>'
            $body += '<td>' + (E $dir) + '</td>'
            $body += '<td>' + (YesNo $log) + '</td>'
            $body += '<td>' + (Dash $descr) + '<div class="flagcell">' + $badges + '</div></td>'
            $body += '</tr>'
        }
        $tbl = Tbl @('#','Enabled','Action','Protocol','Source','Src Port','Destination','Dst Port','Direction','Log','Description / Flags') $body
        $out += '<h3 class="iface-head">' + $label + $trustBadge + ' <span class="count">(' + $groups[$key].Count + ' rule' + $(if($groups[$key].Count -ne 1){'s'}else{''}) + ')</span></h3>' + $tbl
    }
    return $out
}

function Build-Nat {
    param($root)
    $nat = $root.SelectSingleNode('nat')
    if ($null -eq $nat) { return '' }
    $out = ''

    # Outbound NAT
    $mode = XText $nat 'outbound/mode'
    if (-not $mode) { $mode = 'automatic' }
    $out += '<h3>Outbound NAT</h3><p>Mode: <span class="badge badge-info">' + (E $mode.ToUpper()) + '</span></p>'
    $obRules = XNodes $nat 'outbound/rule'
    if ($obRules.Count) {
        $body = ''
        foreach ($r in $obRules) {
            $disabled = (XHas $r 'disabled')
            $cls = ''; if ($disabled) { $cls = ' class="row-disabled"' }
            $src = Format-Endpoint $r.SelectSingleNode('source')
            $dst = Format-Endpoint $r.SelectSingleNode('destination')
            $tgt = XText $r 'targetip'
            if ($tgt) { $tsub = XText $r 'targetip_subnet'; if ($tsub) { $tgt += '/' + $tsub } }
            else { $tgt = XText $r 'target' }
            if (-not $tgt) { $tgt = 'Interface address' }
            $body += '<tr' + $cls + '>'
            $body += '<td>' + (Dash (XText $r 'interface')) + '</td>'
            $body += '<td>' + (Dash $src.Addr) + '</td>'
            $body += '<td>' + (Dash $dst.Addr) + '</td>'
            $body += '<td>' + (Dash $tgt) + '</td>'
            $body += '<td>' + (YesNo (-not $disabled)) + '</td>'
            $body += '<td>' + (Dash (XText $r 'descr')) + '</td>'
            $body += '</tr>'
        }
        $out += (Tbl @('Interface','Source','Destination','Translation target','Enabled','Description') $body)
    }
    elseif ($mode -match '(?i)advanced|hybrid|manual') {
        $out += '<p class="not-configured">No manual outbound rules defined.</p>'
    }

    # Port forwards
    $pf = XNodes $nat 'rule'
    $out += '<h3>Port Forwards</h3>'
    if ($pf.Count) {
        $body = ''
        foreach ($r in $pf) {
            $disabled = (XHas $r 'disabled')
            $cls = ''; if ($disabled) { $cls = ' class="row-disabled"' }
            $dst = Format-Endpoint $r.SelectSingleNode('destination')
            $extPort = $dst.Port; if (-not $extPort) { $extPort = XText $r 'dstport' }
            $body += '<tr' + $cls + '>'
            $body += '<td>' + (Dash (XText $r 'interface')) + '</td>'
            $body += '<td>' + (Dash (XText $r 'protocol')) + '</td>'
            $body += '<td>' + (Dash $dst.Addr) + '</td>'
            $body += '<td>' + (Dash $extPort) + '</td>'
            $body += '<td>' + (Dash (XText $r 'target')) + '</td>'
            $body += '<td>' + (Dash (XText $r 'local-port')) + '</td>'
            $body += '<td>' + (YesNo (-not $disabled)) + '</td>'
            $body += '<td>' + (Dash (XText $r 'descr')) + '</td>'
            $body += '</tr>'
        }
        $out += (Tbl @('Interface','Protocol','External addr','External port','Redirect target','Target port','Enabled','Description') $body)
    }
    else { $out += '<p class="not-configured">No port forwards defined.</p>' }

    # 1:1 NAT
    $oto = XNodes $nat 'onetoone'
    if ($oto.Count) {
        $out += '<h3>1:1 NAT</h3>'
        $body = ''
        foreach ($r in $oto) {
            $disabled = (XHas $r 'disabled')
            $cls = ''; if ($disabled) { $cls = ' class="row-disabled"' }
            $src = Format-Endpoint $r.SelectSingleNode('source')
            $dst = Format-Endpoint $r.SelectSingleNode('destination')
            $body += '<tr' + $cls + '>'
            $body += '<td>' + (Dash (XText $r 'interface')) + '</td>'
            $body += '<td>' + (Dash (XText $r 'external')) + '</td>'
            $body += '<td>' + (Dash $src.Addr) + '</td>'
            $body += '<td>' + (Dash $dst.Addr) + '</td>'
            $body += '<td>' + (YesNo (-not $disabled)) + '</td>'
            $body += '<td>' + (Dash (XText $r 'descr')) + '</td>'
            $body += '</tr>'
        }
        $out += (Tbl @('Interface','External IP','Internal (source)','Destination','Enabled','Description') $body)
    }

    return $out
}

function Build-Ipsec {
    param($root)
    $ipsec = $root.SelectSingleNode('ipsec')
    if ($null -eq $ipsec) { return '' }
    $p1 = XNodes $ipsec 'phase1'
    $p2 = XNodes $ipsec 'phase2'
    if ($p1.Count -eq 0 -and $p2.Count -eq 0) { return '' }

    $out = ''

    # Phase 1
    if ($p1.Count) {
        $out += '<h3>Phase 1 (IKE)</h3>'
        $body = ''
        foreach ($p in $p1) {
            $ikeid = XText $p 'ikeid'
            $disabled = (XHas $p 'disabled')
            $cls = ''; if ($disabled) { $cls = ' class="row-disabled"' }
            $item = $p.SelectSingleNode('encryption/item')
            $ealg = XText $item 'encryption-algorithm/name'
            $eklen = XText $item 'encryption-algorithm/keylen'
            $ealgDisp = $ealg; if ($eklen) { $ealgDisp += '-' + $eklen }
            $hash = XText $item 'hash-algorithm'
            $dh = XText $item 'dhgroup'
            $weak = Get-WeakCryptoHits @($ealg, $hash)
            $wb = ''
            if ($weak.Count) {
                $wb = ' <span class="badge badge-high">WEAK CRYPTO</span>'
                Add-Finding 'high' 'WEAK CRYPTO' ("IPsec P1 (IKE id $ikeid)") ('Uses ' + ($weak -join ', '))
            }
            $where = "IPsec Phase 1 (id $ikeid)"
            $body += '<tr' + $cls + '>'
            $body += '<td>' + (Dash $ikeid) + '</td>'
            $body += '<td>' + (Dash (XText $p 'descr')) + $wb + '</td>'
            $body += '<td>' + (YesNo (-not $disabled)) + '</td>'
            $body += '<td>' + (Dash (XText $p 'iketype')) + '</td>'
            $body += '<td>' + (Dash (XText $p 'interface')) + '</td>'
            $body += '<td>' + (Dash (XText $p 'remote-gateway')) + '</td>'
            $body += '<td>' + (Dash $ealgDisp) + '</td>'
            $body += '<td>' + (Dash $hash) + '</td>'
            $body += '<td>' + (Dash $dh) + '</td>'
            $body += '<td>' + (Dash (XText $p 'lifetime')) + '</td>'
            $body += '<td>' + (Dash (XText $p 'authentication_method')) + '</td>'
            $body += '<td>' + (Secret (XText $p 'pre-shared-key')) + '</td>'
            $body += '</tr>'
        }
        $out += (Tbl @('IKE id','Description','Enabled','IKE','Interface','Peer / Remote GW','Encryption','Hash','DH group','Lifetime','Auth','Pre-shared key') $body)
    }

    # Phase 2
    if ($p2.Count) {
        $out += '<h3>Phase 2 (IPsec SA)</h3>'
        $body = ''
        foreach ($p in $p2) {
            $ikeid = XText $p 'ikeid'
            $disabled = (XHas $p 'disabled')
            $cls = ''; if ($disabled) { $cls = ' class="row-disabled"' }
            $lid = $p.SelectSingleNode('localid')
            $local = XText $lid 'type'
            if ((XText $lid 'address')) { $local = (XText $lid 'address'); $nb = XText $lid 'netbits'; if ($nb) { $local += '/' + $nb } }
            $rid = $p.SelectSingleNode('remoteid')
            $remote = XText $rid 'type'
            if ((XText $rid 'address')) { $remote = (XText $rid 'address'); $nb = XText $rid 'netbits'; if ($nb) { $remote += '/' + $nb } }
            $encList = New-Object System.Collections.Generic.List[string]
            $encNames = @()
            foreach ($e in (XNodes $p 'encryption-algorithm-option')) {
                $n = XText $e 'name'; $kl = XText $e 'keylen'; $encNames += $n
                $d = $n; if ($kl) { $d += '-' + $kl }; $encList.Add($d)
            }
            $hashList = @()
            foreach ($h in (XNodes $p 'hash-algorithm-option')) { $hashList += $h.InnerText.Trim() }
            $weak = Get-WeakCryptoHits ($encNames + $hashList)
            $wb = ''
            if ($weak.Count) {
                $wb = ' <span class="badge badge-high">WEAK CRYPTO</span>'
                Add-Finding 'high' 'WEAK CRYPTO' ("IPsec P2 (IKE id $ikeid)") ('Uses ' + ($weak -join ', '))
            }
            $body += '<tr' + $cls + '>'
            $body += '<td>' + (Dash $ikeid) + '</td>'
            $body += '<td>' + (Dash (XText $p 'descr')) + $wb + '</td>'
            $body += '<td>' + (YesNo (-not $disabled)) + '</td>'
            $body += '<td>' + (Dash (XText $p 'mode')) + '</td>'
            $body += '<td>' + (Dash (XText $p 'protocol')) + '</td>'
            $body += '<td>' + (Dash $local) + '</td>'
            $body += '<td>' + (Dash $remote) + '</td>'
            $body += '<td>' + (Dash (($encList) -join ', ')) + '</td>'
            $body += '<td>' + (Dash (($hashList | ForEach-Object { $_ }) -join ', ')) + '</td>'
            $body += '<td>' + (Dash (XText $p 'pfsgroup')) + '</td>'
            $body += '<td>' + (Dash (XText $p 'lifetime')) + '</td>'
            $body += '</tr>'
        }
        $out += (Tbl @('IKE id','Description','Enabled','Mode','Protocol','Local network','Remote network','Encryption','Hash','PFS group','Lifetime') $body)
    }

    return $out
}

function Build-OpenVpn {
    param($root, $refMap)
    $ovpn = $root.SelectSingleNode('openvpn')
    if ($null -eq $ovpn) { return '' }
    $servers = XNodes $ovpn 'openvpn-server'
    $clients = XNodes $ovpn 'openvpn-client'
    if ($servers.Count -eq 0 -and $clients.Count -eq 0) { return '' }

    $out = ''
    $renderRows = {
        param($list, $isServer)
        $body = ''
        foreach ($s in $list) {
            $desc = XText $s 'description'
            $mode = XText $s 'mode'
            $proto = XText $s 'protocol'
            $port  = if ($isServer) { XText $s 'local_port' } else { (XText $s 'server_addr') + ':' + (XText $s 'server_port') }
            $tnet  = XText $s 'tunnel_network'
            $lnet  = XText $s 'local_network'
            $rnet  = XText $s 'remote_network'
            $auth  = XText $s 'authmode'
            $dc    = XText $s 'data_ciphers'
            $dcf   = XText $s 'data_ciphers_fallback'
            $digest= XText $s 'digest'
            $cipherDisp = $dc; if ($dcf) { if ($cipherDisp) { $cipherDisp += ' (fallback ' + $dcf + ')' } else { $cipherDisp = $dcf } }
            $caref = XText $s 'caref'; $caN = if ($refMap.ContainsKey($caref)) { $refMap[$caref] } else { $caref }
            $weak = Get-WeakCryptoHits @($dc, $dcf, $digest)
            $wb = ''
            $where = "OpenVPN " + $(if($isServer){'server'}else{'client'}) + " '" + $(if($desc){$desc}else{'(unnamed)'}) + "'"
            if ($weak.Count) {
                $wb = ' <span class="badge badge-high">WEAK CRYPTO</span>'
                Add-Finding 'high' 'WEAK CRYPTO' $where ('Uses ' + ($weak -join ', '))
            }
            $body += '<tr>'
            $body += '<td>' + (Dash $desc) + $wb + '</td>'
            $body += '<td>' + (Dash $mode) + '</td>'
            $body += '<td>' + (Dash $proto) + '</td>'
            $body += '<td>' + (Dash $port) + '</td>'
            $body += '<td>' + (Dash $tnet) + '</td>'
            $body += '<td>' + (Dash $lnet) + '</td>'
            $body += '<td>' + (Dash $rnet) + '</td>'
            $body += '<td>' + (Dash $auth) + '</td>'
            $body += '<td>' + (Dash $cipherDisp) + '</td>'
            $body += '<td>' + (Dash $digest) + '</td>'
            $body += '<td>' + (Dash $caN) + '</td>'
            $body += '</tr>'
        }
        return $body
    }

    if ($servers.Count) {
        $out += '<h3>OpenVPN Servers</h3>'
        $out += (Tbl @('Description','Mode','Protocol','Port','Tunnel network','Local network','Remote network','Auth','Cipher','Digest','CA') (& $renderRows $servers $true))
    }
    if ($clients.Count) {
        $out += '<h3>OpenVPN Clients</h3>'
        $out += (Tbl @('Description','Mode','Protocol','Server','Tunnel network','Local network','Remote network','Auth','Cipher','Digest','CA') (& $renderRows $clients $false))
    }
    return $out
}

function Build-Dhcp {
    param($root)
    $dhcpd = $root.SelectSingleNode('dhcpd')
    if ($null -eq $dhcpd) { return '' }
    $out = ''
    $any = $false
    foreach ($ifNode in $dhcpd.ChildNodes) {
        if ($ifNode.NodeType -ne [System.Xml.XmlNodeType]::Element) { continue }
        $any = $true
        $key = $ifNode.Name
        $enabled = (XHas $ifNode 'enable')
        $from = XText $ifNode 'range/from'
        $to   = XText $ifNode 'range/to'
        $range = ''; if ($from -or $to) { $range = $from + ' - ' + $to }
        $dns = @(); foreach ($d in (XNodes $ifNode 'dnsserver')) { if ($d.InnerText.Trim()) { $dns += $d.InnerText.Trim() } }
        $gw  = XText $ifNode 'gateway'
        $dom = XText $ifNode 'domain'
        $dlt = XText $ifNode 'defaultleasetime'
        $mlt = XText $ifNode 'maxleasetime'

        $kv = '<table class="kv">'
        $kv += '<tr><th>Enabled</th><td>' + (YesNo $enabled) + '</td></tr>'
        $kv += '<tr><th>Range</th><td>' + (Dash $range) + '</td></tr>'
        $kv += '<tr><th>DNS servers</th><td>' + $(if($dns.Count){ ($dns | ForEach-Object { E $_ }) -join '<br>' }else{'<span class="muted">&mdash;</span>'}) + '</td></tr>'
        $kv += '<tr><th>Gateway</th><td>' + (Dash $gw) + '</td></tr>'
        $kv += '<tr><th>Domain</th><td>' + (Dash $dom) + '</td></tr>'
        $kv += '<tr><th>Default lease</th><td>' + (Dash $dlt) + '</td></tr>'
        $kv += '<tr><th>Max lease</th><td>' + (Dash $mlt) + '</td></tr>'
        $kv += '</table>'

        $out += '<h3 class="iface-head">' + (E $key) + ' DHCP server</h3><div class="table-wrap">' + $kv + '</div>'

        $smaps = XNodes $ifNode 'staticmap'
        if ($smaps.Count) {
            $sb = ''
            foreach ($m in $smaps) {
                $sb += '<tr>'
                $sb += '<td>' + (Dash (XText $m 'mac')) + '</td>'
                $sb += '<td>' + (Dash (XText $m 'ipaddr')) + '</td>'
                $sb += '<td>' + (Dash (XText $m 'hostname')) + '</td>'
                $sb += '<td>' + (Dash (XText $m 'cid')) + '</td>'
                $sb += '<td>' + (Dash (XText $m 'descr')) + '</td>'
                $sb += '</tr>'
            }
            $out += '<p class="subtitle">Static mappings (' + $smaps.Count + ')</p>' + (Tbl @('MAC','IP address','Hostname','Client ID','Description') $sb)
        }
    }
    if (-not $any) { return '' }
    return $out
}

function Build-Dns {
    param($root)
    $out = ''

    # Resolver (unbound)
    $unbound = $root.SelectSingleNode('unbound')
    $out += '<h3>DNS Resolver (Unbound)</h3>'
    if ($null -eq $unbound) {
        $out += '<p class="not-configured">Not configured.</p>'
    }
    else {
        $enabled = (XHas $unbound 'enable')
        $ai = XText $unbound 'active_interface'; if (-not $ai) { $ai = 'All' }
        $kv = '<table class="kv">'
        $kv += '<tr><th>Enabled</th><td>' + (YesNo $enabled) + '</td></tr>'
        $kv += '<tr><th>Listening interfaces</th><td>' + (Dash $ai) + '</td></tr>'
        $kv += '<tr><th>DNSSEC</th><td>' + (YesNo (XHas $unbound 'dnssec')) + '</td></tr>'
        $kv += '</table>'
        $out += '<div class="table-wrap">' + $kv + '</div>'

        $hosts = XNodes $unbound 'hosts'
        if ($hosts.Count) {
            $hb = ''
            foreach ($h in $hosts) {
                $hb += '<tr><td>' + (Dash (XText $h 'host')) + '</td><td>' + (Dash (XText $h 'domain')) + '</td><td>' + (Dash (XText $h 'ip')) + '</td><td>' + (Dash (XText $h 'descr')) + '</td></tr>'
            }
            $out += '<p class="subtitle">Host overrides (' + $hosts.Count + ')</p>' + (Tbl @('Host','Domain','IP','Description') $hb)
        }
        $doms = XNodes $unbound 'domainoverrides'
        if ($doms.Count) {
            $db = ''
            foreach ($d in $doms) {
                $db += '<tr><td>' + (Dash (XText $d 'domain')) + '</td><td>' + (Dash (XText $d 'ip')) + '</td><td>' + (Dash (XText $d 'descr')) + '</td></tr>'
            }
            $out += '<p class="subtitle">Domain overrides (' + $doms.Count + ')</p>' + (Tbl @('Domain','Forward-to IP','Description') $db)
        }
    }

    # Forwarder (dnsmasq)
    $dnsmasq = $root.SelectSingleNode('dnsmasq')
    $out += '<h3>DNS Forwarder (dnsmasq)</h3>'
    if ($null -eq $dnsmasq -or -not (XHas $dnsmasq 'enable')) {
        $out += '<p class="not-configured">Not enabled.</p>'
    }
    else {
        $kv = '<table class="kv">'
        $kv += '<tr><th>Enabled</th><td>' + (YesNo $true) + '</td></tr>'
        $kv += '<tr><th>Interfaces</th><td>' + (Dash (XText $dnsmasq 'interface')) + '</td></tr>'
        $kv += '</table>'
        $out += '<div class="table-wrap">' + $kv + '</div>'
        $hosts = XNodes $dnsmasq 'hosts'
        if ($hosts.Count) {
            $hb = ''
            foreach ($h in $hosts) {
                $hb += '<tr><td>' + (Dash (XText $h 'host')) + '</td><td>' + (Dash (XText $h 'domain')) + '</td><td>' + (Dash (XText $h 'ip')) + '</td><td>' + (Dash (XText $h 'descr')) + '</td></tr>'
            }
            $out += '<p class="subtitle">Host overrides (' + $hosts.Count + ')</p>' + (Tbl @('Host','Domain','IP','Description') $hb)
        }
        $doms = XNodes $dnsmasq 'domainoverrides'
        if ($doms.Count) {
            $db = ''
            foreach ($d in $doms) {
                $db += '<tr><td>' + (Dash (XText $d 'domain')) + '</td><td>' + (Dash (XText $d 'ip')) + '</td><td>' + (Dash (XText $d 'descr')) + '</td></tr>'
            }
            $out += '<p class="subtitle">Domain overrides (' + $doms.Count + ')</p>' + (Tbl @('Domain','Forward-to IP','Description') $db)
        }
    }
    return $out
}

function Get-CertUsage {
    # Resolve where a cert/CA refid is referenced elsewhere in the config (usage context).
    param($root, [string]$refid)
    $result = New-Object System.Collections.Generic.List[string]
    if ([string]::IsNullOrWhiteSpace($refid)) { return $result }
    $nodes = $root.SelectNodes("//*[text()='" + $refid + "']")
    if ($null -eq $nodes) { return $result }
    foreach ($n in $nodes) {
        $name = $n.LocalName
        if ($name -eq 'refid') { continue }   # the definition itself, not a usage
        $parent = ''
        if ($n.ParentNode) { $parent = $n.ParentNode.LocalName }
        $label = switch -regex ("$parent/$name") {
            'webgui/ssl-certref'     { 'WebGUI HTTPS certificate'; break }
            'openvpn-server/certref' { 'OpenVPN server certificate'; break }
            'openvpn-server/caref'   { 'OpenVPN server CA'; break }
            'openvpn-client/certref' { 'OpenVPN client certificate'; break }
            'openvpn-client/caref'   { 'OpenVPN client CA'; break }
            'phase1/certref'         { 'IPsec Phase 1 certificate'; break }
            'phase1/caref'           { 'IPsec Phase 1 CA'; break }
            'cert/caref'             { 'Issues certificate(s)'; break }
            'ca/caref'               { 'Issues intermediate CA(s)'; break }
            default                  { "$parent ($name)" }
        }
        if (-not $result.Contains($label)) { $result.Add($label) }
    }
    return $result
}

function Build-Certs {
    param($root)
    $cas   = XNodes $root 'ca'
    $certs = XNodes $root 'cert'
    if ($cas.Count -eq 0 -and $certs.Count -eq 0) { return '' }
    $out = ''

    if ($cas.Count) {
        $out += '<h3>Certificate Authorities</h3>'
        $body = ''
        foreach ($c in $cas) {
            $descr = XText $c 'descr'
            $info = Get-CertInfo (XText $c 'crt')
            $status = Format-CertStatus $info ("CA '" + $(if($descr){$descr}else{XText $c 'refid'}) + "'")
            $na = if ($info.NotAfter) { $info.NotAfter.ToString('yyyy-MM-dd') } else { '' }
            $uses = @(Get-CertUsage $root (XText $c 'refid'))
            $usedBy = if ($uses.Count) { ($uses | ForEach-Object { E $_ }) -join '<br>' } else { '<span class="muted">Not referenced</span>' }
            $body += '<tr>'
            $body += '<td>' + (Dash $descr) + '</td>'
            $body += '<td>Certificate Authority</td>'
            $body += '<td>' + (Dash $info.Subject) + '</td>'
            $body += '<td>' + (Dash $na) + '</td>'
            $body += '<td>' + $status + '</td>'
            $body += '<td>' + $usedBy + '</td>'
            $body += '</tr>'
        }
        $out += (Tbl @('Name','Type','Subject','Expires','Status','Used by') $body)
    }

    if ($certs.Count) {
        $out += '<h3>Certificates</h3>'
        $body = ''
        foreach ($c in $certs) {
            $descr = XText $c 'descr'
            $type  = XText $c 'type'
            $info = Get-CertInfo (XText $c 'crt')
            $status = Format-CertStatus $info ("Certificate '" + $(if($descr){$descr}else{XText $c 'refid'}) + "'")
            $na = if ($info.NotAfter) { $info.NotAfter.ToString('yyyy-MM-dd') } else { '' }
            $typeDisp = switch ($type) {
                'server' { 'Server' }
                'user'   { 'User' }
                default  { if ($type) { $type } else { 'Unknown' } }
            }
            $uses = @(Get-CertUsage $root (XText $c 'refid'))
            $usedBy = if ($uses.Count) { ($uses | ForEach-Object { E $_ }) -join '<br>' } else { '<span class="muted">Not referenced</span>' }
            $body += '<tr>'
            $body += '<td>' + (Dash $descr) + '</td>'
            $body += '<td>' + (E $typeDisp) + '</td>'
            $body += '<td>' + (Dash $info.Subject) + '</td>'
            $body += '<td>' + (Dash $na) + '</td>'
            $body += '<td>' + $status + '</td>'
            $body += '<td>' + $usedBy + '</td>'
            $body += '</tr>'
        }
        $out += (Tbl @('Name','Type','Subject','Expires','Status','Used by') $body)
        $out += '<p class="note">Private key material is never exported by this report, regardless of options.</p>'
    }
    return $out
}

function Build-Users {
    param($root)
    $sys = $root.SelectSingleNode('system')
    if ($null -eq $sys) { return '' }
    $users  = XNodes $sys 'user'
    $groups = XNodes $sys 'group'
    if ($users.Count -eq 0 -and $groups.Count -eq 0) { return '' }

    # uid -> name map
    $uidMap = @{}
    foreach ($u in $users) { $uid = XText $u 'uid'; if ($uid -ne '') { $uidMap[$uid] = (XText $u 'name') } }

    $out = ''
    if ($users.Count) {
        $out += '<h3>Users</h3>'
        $body = ''
        foreach ($u in $users) {
            $privs = @(); foreach ($p in (XNodes $u 'priv')) { if ($p.InnerText.Trim()) { $privs += $p.InnerText.Trim() } }
            $hashType = ''
            if (XHas $u 'bcrypt-hash')  { $hashType = 'bcrypt' }
            elseif (XHas $u 'sha512-hash') { $hashType = 'sha512' }
            elseif (XHas $u 'md5-hash')    { $hashType = 'md5' }
            $body += '<tr>'
            $body += '<td>' + (Dash (XText $u 'name')) + '</td>'
            $body += '<td>' + (Dash (XText $u 'descr')) + '</td>'
            $body += '<td>' + (Dash (XText $u 'scope')) + '</td>'
            $body += '<td>' + (Dash (XText $u 'groupname')) + '</td>'
            $body += '<td>' + $(if($privs.Count){ ($privs | ForEach-Object { E $_ }) -join '<br>' }else{'<span class="muted">&mdash;</span>'}) + '</td>'
            $body += '<td><span class="muted">' + $(if($hashType){'['+$hashType+' hash not shown]'}else{'[none]'}) + '</span></td>'
            $body += '</tr>'
        }
        $out += (Tbl @('Username','Full name','Scope','Group','Privileges','Password') $body)
        $out += '<p class="note">Password hashes are never exported by this report, regardless of options.</p>'
    }

    if ($groups.Count) {
        $out += '<h3>Groups</h3>'
        $body = ''
        foreach ($g in $groups) {
            $privs = @(); foreach ($p in (XNodes $g 'priv')) { if ($p.InnerText.Trim()) { $privs += $p.InnerText.Trim() } }
            $members = @()
            foreach ($m in (XNodes $g 'member')) {
                $mv = $m.InnerText.Trim()
                if ($uidMap.ContainsKey($mv)) { $members += $uidMap[$mv] } elseif ($mv) { $members += "uid:$mv" }
            }
            $body += '<tr>'
            $body += '<td>' + (Dash (XText $g 'name')) + '</td>'
            $body += '<td>' + (Dash (XText $g 'description')) + '</td>'
            $body += '<td>' + (Dash (XText $g 'scope')) + '</td>'
            $body += '<td>' + $(if($members.Count){ ($members | ForEach-Object { E $_ }) -join '<br>' }else{'<span class="muted">&mdash;</span>'}) + '</td>'
            $body += '<td>' + $(if($privs.Count){ ($privs | ForEach-Object { E $_ }) -join '<br>' }else{'<span class="muted">&mdash;</span>'}) + '</td>'
            $body += '</tr>'
        }
        $out += (Tbl @('Group','Description','Scope','Members','Privileges') $body)
    }
    return $out
}

function Build-Aliases {
    param($root)
    $al = $root.SelectSingleNode('aliases')
    if ($null -eq $al) { return '' }
    $aliases = XNodes $al 'alias'
    if ($aliases.Count -eq 0) { return '' }
    $body = ''
    foreach ($a in $aliases) {
        $addr = XText $a 'address'
        $addrDisp = '<span class="muted">&mdash;</span>'
        if ($addr) { $addrDisp = (($addr -split '\s+' | Where-Object { $_ } | ForEach-Object { E $_ }) -join '<br>') }
        $body += '<tr>'
        $body += '<td>' + (Dash (XText $a 'name')) + '</td>'
        $body += '<td>' + (Dash (XText $a 'type')) + '</td>'
        $body += '<td class="wrapcell">' + $addrDisp + '</td>'
        $body += '<td>' + (Dash (XText $a 'descr')) + '</td>'
        $body += '</tr>'
    }
    return (Tbl @('Name','Type','Contents','Description') $body)
}

function Build-Packages {
    param($root)
    $ip = $root.SelectSingleNode('installedpackages')
    if ($null -eq $ip) { return '' }
    $pkgs = XNodes $ip 'package'
    if ($pkgs.Count -eq 0) { return '' }
    $body = ''
    foreach ($p in $pkgs) {
        $body += '<tr>'
        $body += '<td>' + (Dash (XText $p 'name')) + '</td>'
        $body += '<td>' + (Dash (XText $p 'version')) + '</td>'
        $body += '<td>' + (Dash (XText $p 'descr')) + '</td>'
        $body += '</tr>'
    }
    return (Tbl @('Package','Version','Description') $body)
}

function Build-Revision {
    param($root)
    $rev = $root.SelectSingleNode('revision')
    $lc  = XText $root 'lastchange'
    if ($null -eq $rev -and -not $lc) { return '' }
    $kv = '<table class="kv">'
    if ($rev) {
        $kv += '<tr><th>Last change time</th><td>' + (Dash (ConvertFrom-Epoch (XText $rev 'time'))) + '</td></tr>'
        $kv += '<tr><th>Description</th><td>' + (Dash (XText $rev 'description')) + '</td></tr>'
        $kv += '<tr><th>Changed by</th><td>' + (Dash (XText $rev 'username')) + '</td></tr>'
    }
    if ($lc) { $kv += '<tr><th>lastchange</th><td>' + (Dash (ConvertFrom-Epoch $lc)) + '</td></tr>' }
    $kv += '</table>'
    return '<div class="table-wrap">' + $kv + '</div>'
}

function Build-Findings {
    if ($script:Findings.Count -eq 0) {
        return '<p class="all-clear">No automated risk flags were raised. (This is a heuristic scan, not a substitute for a full security review.)</p>'
    }
    # Severity ordering: high first, then warn, then info.
    $sevRank = @{ 'high' = 0; 'warn' = 1; 'info' = 2 }
    $ordered = $script:Findings | Sort-Object @{ Expression = { $sevRank[$_.Sev] } }, Label

    # Counts (cards sorted by severity, then label)
    $byLabel = $ordered | Group-Object Label
    $cards = '<div class="finding-cards">'
    foreach ($g in $byLabel) {
        $sev = ($g.Group[0]).Sev
        $cards += '<div class="fcard fcard-' + $sev + '"><div class="fnum">' + $g.Count + '</div><div class="flbl">' + (E $g.Name) + '</div></div>'
    }
    $cards += '</div>'

    $body = ''
    foreach ($f in $ordered) {
        $cls = 'badge-info'
        if ($f.Sev -eq 'high') { $cls = 'badge-high' } elseif ($f.Sev -eq 'warn') { $cls = 'badge-warn' }
        $body += '<tr>'
        $body += '<td><span class="badge ' + $cls + '">' + (E $f.Label) + '</span></td>'
        $body += '<td>' + (E $f.Where) + '</td>'
        $body += '<td>' + (E $f.Detail) + '</td>'
        $body += '</tr>'
    }
    return $cards + (Tbl @('Flag','Location','Detail') $body)
}

# ==================================================================================
#  CSS / JS (single-quoted here-strings: no interpolation)
# ==================================================================================

$css = @'
:root{
  --bg:#f4f6f9; --panel:#ffffff; --ink:#1f2933; --muted:#7b8794; --line:#e1e6ec;
  --brand:#1e3f75; --brand2:#2b5ea8; --accent:#3b82f6;
  --high:#c0392b; --high-bg:#fdecea; --warn:#b9770e; --warn-bg:#fef6e7;
  --ok:#1e8e4e; --ok-bg:#e8f6ee; --info:#2b5ea8; --info-bg:#e8eef8; --mutedb:#5b6573;
}
*{box-sizing:border-box}
html{scroll-behavior:smooth}
body{margin:0;font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif;
  background:var(--bg);color:var(--ink);font-size:14px;line-height:1.5;}
a{color:var(--brand2);text-decoration:none}
a:hover{text-decoration:underline}

/* Sidebar */
.sidebar{position:fixed;top:0;left:0;width:258px;height:100vh;overflow-y:auto;background:var(--brand);
  color:#dce6f5;padding:18px 0;border-right:1px solid #163259;}
.sidebar .brand{font-size:15px;font-weight:700;color:#fff;padding:0 20px 12px;letter-spacing:.3px}
.sidebar .brand small{display:block;font-weight:400;font-size:11px;color:#9bb4d6;margin-top:3px}
.sidebar .navfilter{margin:0 16px 10px;width:calc(100% - 32px);padding:7px 10px;border-radius:6px;border:1px solid #2b5089;
  background:#163259;color:#fff;font-size:12px}
.sidebar .navfilter::placeholder{color:#8fa7cd}
.sidebar nav a{display:block;padding:8px 20px;color:#c5d4ec;font-size:13px;border-left:3px solid transparent}
.sidebar nav a:hover{background:#1a3868;text-decoration:none;color:#fff}
.sidebar nav a.active{background:#15315c;border-left-color:var(--accent);color:#fff;font-weight:600}
.sidebar .navtools{padding:10px 20px 0}
.sidebar .navtools button{width:100%;margin-bottom:6px;padding:6px;border:1px solid #2b5089;background:#163259;color:#dbe6f7;
  border-radius:6px;cursor:pointer;font-size:12px}
.sidebar .navtools button:hover{background:#1e447e}

/* Main */
.main{margin-left:258px;padding:26px 34px 80px;max-width:1280px}

/* Cover */
.cover{background:linear-gradient(135deg,var(--brand),var(--brand2));color:#fff;border-radius:14px;
  padding:30px 34px;margin-bottom:24px;box-shadow:0 6px 20px rgba(30,63,117,.18)}
.cover .cover-top{display:flex;align-items:center;gap:20px}
.cover-logo{max-height:64px;max-width:200px;background:#fff;border-radius:8px;padding:6px}
.cover h1{margin:0;font-size:26px;font-weight:700}
.cover .sub{color:#cfe0f7;font-size:14px;margin-top:4px}
.cover .meta{display:flex;flex-wrap:wrap;gap:26px;margin-top:20px}
.cover .meta div span{display:block;font-size:11px;text-transform:uppercase;letter-spacing:.6px;color:#a8c2e8}
.cover .meta div strong{font-size:15px;font-weight:600}

/* Stat cards */
.cards{display:flex;flex-wrap:wrap;gap:14px;margin-bottom:24px}
.card{background:var(--panel);border:1px solid var(--line);border-radius:10px;padding:14px 18px;min-width:120px;flex:1}
.card .n{font-size:24px;font-weight:700;color:var(--brand)}
.card .l{font-size:12px;color:var(--muted);text-transform:uppercase;letter-spacing:.4px;margin-top:2px}

/* Sections */
.report-section{background:var(--panel);border:1px solid var(--line);border-radius:10px;margin-bottom:18px;overflow:hidden}
.section-header{cursor:pointer;margin:0;padding:15px 20px;font-size:17px;font-weight:600;color:var(--brand);
  background:#fbfcfe;border-bottom:1px solid var(--line);display:flex;align-items:center;gap:10px;user-select:none}
.section-header:hover{background:#f3f6fb}
.toggle-icon{display:inline-block;transition:transform .15s;font-size:13px;color:var(--muted)}
.report-section.collapsed .toggle-icon{transform:rotate(-90deg)}
.report-section.collapsed .section-body{display:none}
.sh-title{flex:0 0 auto}
.section-body{padding:18px 20px}
.section-summary{margin:0 0 14px;color:var(--mutedb);font-size:13px;font-style:italic}
.report-section h3{font-size:14px;color:var(--brand2);margin:20px 0 8px;border-bottom:1px dashed var(--line);padding-bottom:5px}
.report-section h3:first-of-type{margin-top:2px}
.iface-head{font-size:14px}
.iface-head .count{color:var(--muted);font-weight:400;font-size:12px}
.subtitle{font-size:12px;color:var(--muted);margin:14px 0 6px;font-weight:600;text-transform:uppercase;letter-spacing:.4px}

/* Tables */
.table-wrap{overflow-x:auto;border:1px solid var(--line);border-radius:8px;margin-bottom:10px}
table{border-collapse:collapse;width:100%;font-size:13px}
thead th{position:sticky;top:0;background:var(--brand);color:#fff;text-align:left;padding:9px 11px;font-weight:600;
  white-space:nowrap;z-index:1}
tbody td{padding:8px 11px;border-top:1px solid var(--line);vertical-align:top}
tbody tr:nth-child(even){background:#f7f9fc}
tbody tr:hover{background:#eef3fb}
table.kv th{position:static;background:#eef2f8;color:var(--ink);width:230px;font-weight:600;border-top:1px solid var(--line)}
table.kv td{border-top:1px solid var(--line)}
.wrapcell{max-width:360px;word-break:break-word}
.flagcell{margin-top:4px}

/* States */
.row-disabled{opacity:.6}
.row-disabled td{background:#fafafa}
.row-high td{background:var(--high-bg) !important}
.row-warn td{background:var(--warn-bg) !important}
.muted{color:var(--muted)}
.redacted{color:var(--high);font-weight:600;font-family:monospace}
.note{font-size:12px;color:var(--muted);margin:6px 0 0}
.not-configured{color:var(--muted);font-style:italic;background:#fafbfd;border:1px dashed var(--line);
  padding:10px 14px;border-radius:8px;margin:0}
.all-clear{color:var(--ok);background:var(--ok-bg);border:1px solid #b7e0c6;padding:12px 16px;border-radius:8px}

/* Badges */
.badge{display:inline-block;padding:2px 8px;border-radius:11px;font-size:11px;font-weight:700;letter-spacing:.3px;
  white-space:nowrap;line-height:1.6}
.badge-high{background:var(--high-bg);color:var(--high);border:1px solid #f0b4ac}
.badge-warn{background:var(--warn-bg);color:var(--warn);border:1px solid #f0d9a8}
.badge-ok{background:var(--ok-bg);color:var(--ok);border:1px solid #b7e0c6}
.badge-info{background:var(--info-bg);color:var(--info);border:1px solid #b6c8e8}
.badge-muted{background:#eceff3;color:var(--mutedb);border:1px solid #d6dce4}

/* Findings cards */
.finding-cards{display:flex;flex-wrap:wrap;gap:12px;margin-bottom:16px}
.fcard{border-radius:10px;padding:12px 16px;min-width:130px;border:1px solid}
.fcard-high{background:var(--high-bg);border-color:#f0b4ac}
.fcard-warn{background:var(--warn-bg);border-color:#f0d9a8}
.fcard-info{background:var(--info-bg);border-color:#b6c8e8}
.fcard .fnum{font-size:22px;font-weight:700}
.fcard-high .fnum{color:var(--high)} .fcard-warn .fnum{color:var(--warn)} .fcard-info .fnum{color:var(--info)}
.fcard .flbl{font-size:11px;font-weight:600;text-transform:uppercase;letter-spacing:.3px;margin-top:2px}

/* Warning banner */
.warn-banner{background:var(--warn-bg);border:1px solid #f0d9a8;color:#8a5a08;padding:13px 18px;border-radius:10px;
  margin-bottom:20px;font-size:13px}
.warn-banner strong{color:var(--warn)}

.footer{margin-top:30px;color:var(--muted);font-size:11px;text-align:center}

/* Narrow screens: drop the fixed sidebar to a normal block at the top */
@media (max-width:900px){
  .sidebar{position:static;width:auto;height:auto;max-height:260px;border-right:none;border-bottom:1px solid #163259}
  .main{margin-left:0;padding:18px}
  .cards .card{min-width:96px}
}

/* Print */
@media print{
  body{background:#fff;font-size:11px;color:#000}
  .sidebar{display:none !important}
  .main{margin-left:0 !important;max-width:none;padding:0}
  .cover{background:#1e3f75 !important;-webkit-print-color-adjust:exact;print-color-adjust:exact;color:#fff;box-shadow:none}
  .report-section{page-break-before:always;border:none;box-shadow:none;margin-bottom:0}
  .report-section:first-of-type{page-break-before:avoid}
  .report-section.collapsed .section-body{display:block !important}
  .toggle-icon{display:none}
  .section-header{cursor:default}
  thead th{position:static}
  .table-wrap{overflow:visible !important;border:1px solid #999}
  table,tr,td,th{page-break-inside:avoid}
  .badge,.fcard,thead th{-webkit-print-color-adjust:exact;print-color-adjust:exact}
  a{color:#000}
}
'@

$js = @'
function toggleSection(h){ var c=h.parentElement.classList.toggle("collapsed"); h.setAttribute("aria-expanded", c?"false":"true"); }
function sectionKey(e,h){ if(e.key==="Enter"||e.key===" "||e.key==="Spacebar"){ e.preventDefault(); toggleSection(h); } }
function setAll(collapsed){ var s=document.querySelectorAll(".report-section"); for(var i=0;i<s.length;i++){ if(collapsed){s[i].classList.add("collapsed");}else{s[i].classList.remove("collapsed");} var h=s[i].querySelector(".section-header"); if(h){h.setAttribute("aria-expanded", collapsed?"false":"true");} } }
function expandAll(){ setAll(false); }
function collapseAll(){ setAll(true); }
document.addEventListener("DOMContentLoaded",function(){
  var links=[].slice.call(document.querySelectorAll(".sidebar nav a"));
  var secs=[];
  for(var i=0;i<links.length;i++){ var el=document.querySelector(links[i].getAttribute("href")); if(el){secs.push(el);} }
  function onScroll(){
    var pos=window.pageYOffset+130; var cur=null;
    for(var i=0;i<secs.length;i++){ if(secs[i].offsetTop<=pos){cur=secs[i];} }
    for(var j=0;j<links.length;j++){
      var on = cur && links[j].getAttribute("href")==="#"+cur.id;
      if(on){ links[j].classList.add("active"); } else { links[j].classList.remove("active"); }
    }
  }
  window.addEventListener("scroll",onScroll); onScroll();
  var f=document.getElementById("navfilter");
  if(f){ f.addEventListener("input",function(){
    var q=this.value.toLowerCase();
    for(var i=0;i<links.length;i++){
      links[i].style.display = links[i].textContent.toLowerCase().indexOf(q)>-1 ? "" : "none";
    }
  }); }
});
window.addEventListener("beforeprint",function(){ expandAll(); });
'@

# ==================================================================================
#  MAIN
# ==================================================================================

try {
    # ---- Validate input ------------------------------------------------------
    if (-not (Test-Path -LiteralPath $ConfigPath)) {
        Write-Error "Config file not found: $ConfigPath"
        exit 1
    }
    try {
        $rawXml = Get-Content -LiteralPath $ConfigPath -Raw -ErrorAction Stop
        [xml]$xml = $rawXml
    }
    catch {
        Write-Error "The file is not valid XML: $($_.Exception.Message)"
        exit 1
    }
    $root = $xml.DocumentElement
    if ($null -eq $root -or $root.Name -ne 'pfsense') {
        Write-Error "This does not appear to be a pfSense configuration (missing <pfsense> root element)."
        exit 1
    }

    # ---- Default output path -------------------------------------------------
    if ([string]::IsNullOrWhiteSpace($OutputPath)) {
        $base = [System.IO.Path]::GetFileNameWithoutExtension($ConfigPath)
        $OutputPath = Join-Path (Get-Location).Path ($base + '-report.html')
    }

    # ---- Gather metadata -----------------------------------------------------
    $sysNode  = $root.SelectSingleNode('system')
    $hostname = XText $sysNode 'hostname'
    $domain   = XText $sysNode 'domain'
    $version  = XText $root 'version'
    $script:RedactHost   = $hostname
    $script:RedactDomain = $domain

    # ---- Build lookup maps ---------------------------------------------------
    $ifMap = @{}
    $ifsNode = $root.SelectSingleNode('interfaces')
    if ($ifsNode) {
        foreach ($c in $ifsNode.ChildNodes) {
            if ($c.NodeType -eq [System.Xml.XmlNodeType]::Element) {
                $d = XText $c 'descr'
                if ($d) { $ifMap[$c.Name] = $d } else { $ifMap[$c.Name] = $c.Name.ToUpper() }
            }
        }
    }
    $ifMap['openvpn'] = 'OpenVPN'; $ifMap['enc0'] = 'IPsec'; $ifMap['l2tp'] = 'L2TP'; $ifMap['(floating)'] = 'Floating rules'

    # Interface trust classification used to scale firewall-rule risk.
    # WAN-type = key 'wan', any interface with an upstream <gateway>, a dhcp/pppoe address,
    # a /wan/i name or description, or an interface that backs a system gateway_item.
    $gwIfaces = @{}
    foreach ($g in (XNodes $root 'gateways/gateway_item')) { $gi = XText $g 'interface'; if ($gi) { $gwIfaces[$gi] = $true } }
    $trustMap = @{}
    if ($ifsNode) {
        foreach ($c in $ifsNode.ChildNodes) {
            if ($c.NodeType -ne [System.Xml.XmlNodeType]::Element) { continue }
            $k = $c.Name
            $isWan = $false
            if ($k -eq 'wan') { $isWan = $true }
            if ($gwIfaces.ContainsKey($k)) { $isWan = $true }
            $gwv = XText $c 'gateway'
            if ($gwv -and $gwv -ne 'none') { $isWan = $true }
            $ipv = (XText $c 'ipaddr').ToLower()
            if ($ipv -in @('dhcp', 'pppoe', 'pptp', 'l2tp')) { $isWan = $true }
            $dscr = XText $c 'descr'
            if ($k -match '(?i)wan' -or $dscr -match '(?i)\bwan\b') { $isWan = $true }
            if ($isWan) { $trustMap[$k] = 'wan' } else { $trustMap[$k] = 'internal' }
        }
    }
    $trustMap['openvpn'] = 'vpn'; $trustMap['enc0'] = 'vpn'; $trustMap['ipsec'] = 'vpn'; $trustMap['l2tp'] = 'vpn'
    $trustMap['(floating)'] = 'floating'

    $vlanTagMap = @{}
    $vlNode = $root.SelectSingleNode('vlans')
    if ($vlNode) {
        foreach ($v in (XNodes $vlNode 'vlan')) {
            $vif = XText $v 'vlanif'; $tag = XText $v 'tag'
            if ($vif) { $vlanTagMap[$vif] = $tag }
        }
    }

    $refMap = @{}
    foreach ($c in (XNodes $root 'ca'))   { $rid = XText $c 'refid'; if ($rid) { $refMap[$rid] = (XText $c 'descr') } }
    foreach ($c in (XNodes $root 'cert')) { $rid = XText $c 'refid'; if ($rid) { $refMap[$rid] = (XText $c 'descr') } }

    # ---- Build sections (order matters: risk-bearing first to populate findings)
    $sysHtml      = Build-System     $root
    $ifHtml       = Build-Interfaces $root $vlanTagMap
    $vlanHtml     = Build-Vlans      $root
    $gwHtml       = Build-Gateways   $root
    $routeHtml    = Build-Routes     $root
    $fwHtml       = Build-Firewall   $root $ifMap $trustMap
    $natHtml      = Build-Nat        $root
    $ipsecHtml    = Build-Ipsec      $root
    $ovpnHtml     = Build-OpenVpn    $root $refMap
    $dhcpHtml     = Build-Dhcp       $root
    $dnsHtml      = Build-Dns        $root
    $certHtml     = Build-Certs      $root
    $userHtml     = Build-Users      $root
    $aliasHtml    = Build-Aliases    $root
    $pkgHtml      = Build-Packages   $root
    $revHtml      = Build-Revision   $root
    $findHtml     = Build-Findings

    # ---- Assemble sections ---------------------------------------------------
    $sections = ''
    $sections += Wrap-Section 'findings'  'Security Findings'         'Heuristic risk flags raised while parsing this configuration.' $findHtml
    $sections += Wrap-Section 'system'    'System Overview'           'Core system services: DNS, NTP, time zone, management access and console protection.' $sysHtml
    $sections += Wrap-Section 'interfaces' 'Interfaces'               'Every configured interface and its addressing, VLAN and filtering options.' $ifHtml
    $sections += Wrap-Section 'vlans'     'VLANs'                     'IEEE 802.1Q VLANs defined on physical interfaces.' $vlanHtml
    $sections += Wrap-Section 'gateways'  'Gateways'                  'Upstream gateways and the default route selections.' $gwHtml
    $sections += Wrap-Section 'routes'    'Static Routes'             'Manually configured static routes to remote networks.' $routeHtml
    $sections += Wrap-Section 'firewall'  'Firewall Rules'            'Packet-filter rules grouped by interface, with risk flags highlighted.' $fwHtml
    $sections += Wrap-Section 'nat'       'NAT'                       'Outbound NAT mode and rules, port forwards, and 1:1 NAT mappings.' $natHtml
    $sections += Wrap-Section 'ipsec'     'VPN &mdash; IPsec'         'IPsec tunnels: Phase 1 (IKE) peers and Phase 2 (child SA) tunnel networks.' $ipsecHtml
    $sections += Wrap-Section 'openvpn'   'VPN &mdash; OpenVPN'       'OpenVPN server and client instances and their cryptographic settings.' $ovpnHtml
    $sections += Wrap-Section 'dhcp'      'DHCP Servers'              'Per-interface DHCP scopes, options and static address reservations.' $dhcpHtml
    $sections += Wrap-Section 'dns'       'DNS Resolver / Forwarder'  'Unbound resolver and dnsmasq forwarder settings and overrides.' $dnsHtml
    $sections += Wrap-Section 'certs'     'Certificates &amp; CAs'    'Certificate authorities and certificates, with expiry status. Keys are never exported.' $certHtml
    $sections += Wrap-Section 'users'     'Users &amp; Groups'        'Local user accounts and groups with their privileges. Hashes are never exported.' $userHtml
    $sections += Wrap-Section 'aliases'   'Aliases'                   'Reusable host, network, port and URL aliases referenced by rules.' $aliasHtml
    $sections += Wrap-Section 'packages'  'Installed Packages'        'Add-on packages installed on this firewall.' $pkgHtml
    $sections += Wrap-Section 'revision'  'Revision / Notes'          'Metadata about the most recent configuration change.' $revHtml

    # ---- Version banner ------------------------------------------------------
    $banner = ''
    $verMajor = 0.0
    $verOk = [double]::TryParse($version, [ref]$verMajor)
    if (-not $version) {
        $banner = '<div class="warn-banner"><strong>Warning:</strong> No pfSense configuration version was found in this file. The report may be incomplete or this may not be a standard pfSense backup.</div>'
    }
    elseif (-not $verOk -or $verMajor -lt 15.0 -or $verMajor -gt 30.0) {
        $banner = '<div class="warn-banner"><strong>Warning:</strong> Configuration version &quot;' + (E $version) + '&quot; is outside the range this tool was validated against (pfSense config versions 15.x&ndash;24.x). Some sections may not parse as expected.</div>'
    }

    # ---- Counts for cover ----------------------------------------------------
    $cIf   = @(XNodes $ifsNode '*' | Where-Object { $_.NodeType -eq [System.Xml.XmlNodeType]::Element }).Count
    if ($null -eq $ifsNode) { $cIf = 0 }
    $cFw   = (XNodes $root 'filter/rule').Count
    $cPf   = (XNodes $root 'nat/rule').Count
    $cP1   = (XNodes $root 'ipsec/phase1').Count
    $cOv   = (XNodes $root 'openvpn/openvpn-server').Count + (XNodes $root 'openvpn/openvpn-client').Count
    $cCert = (XNodes $root 'cert').Count + (XNodes $root 'ca').Count
    $cFind = $script:Findings.Count
    $highCount = @($script:Findings | Where-Object { $_.Sev -eq 'high' }).Count

    $cards = '<div class="cards">'
    $cards += '<div class="card"><div class="n">' + $cIf  + '</div><div class="l">Interfaces</div></div>'
    $cards += '<div class="card"><div class="n">' + $cFw  + '</div><div class="l">Firewall rules</div></div>'
    $cards += '<div class="card"><div class="n">' + $cPf  + '</div><div class="l">Port forwards</div></div>'
    $cards += '<div class="card"><div class="n">' + $cP1  + '</div><div class="l">IPsec tunnels</div></div>'
    $cards += '<div class="card"><div class="n">' + $cOv  + '</div><div class="l">OpenVPN instances</div></div>'
    $cards += '<div class="card"><div class="n">' + $cCert + '</div><div class="l">Certs / CAs</div></div>'
    $cards += '<div class="card"><div class="n" style="color:' + $(if($highCount){'#c0392b'}else{'#1e8e4e'}) + '">' + $cFind + '</div><div class="l">Risk flags</div></div>'
    $cards += '</div>'

    # ---- Cover ---------------------------------------------------------------
    $logoTag = Get-LogoTag $LogoPath
    $genTime = $script:Now.ToString('yyyy-MM-dd HH:mm:ss zzz')
    $hostDisp = if ($script:Redact) { if ($hostname) { Get-RedactToken $hostname 'HOST' } else { 'unknown' } } else { if ($hostname) { $hostname } else { 'unknown' } }
    $domDisp  = if ($script:Redact) { if ($domain) { Get-RedactToken $domain 'DOMAIN' } else { '' } } else { if ($domain) { $domain } else { '' } }
    $fqdn = $hostDisp; if ($domDisp) { $fqdn = $hostDisp + '.' + $domDisp }

    $cover = '<div class="cover"><div class="cover-top">' + $logoTag +
             '<div><h1>' + (E $Title) + '</h1><div class="sub">Generated by pfsense_report.ps1' + $(if($script:Redact){' &mdash; REDACTED COPY'}else{''}) + '</div></div></div>' +
             '<div class="meta">' +
             '<div><span>Hostname</span><strong>' + ([System.Net.WebUtility]::HtmlEncode($fqdn)) + '</strong></div>' +
             '<div><span>pfSense config version</span><strong>' + $(if($version){[System.Net.WebUtility]::HtmlEncode($version)}else{'unknown'}) + '</strong></div>' +
             '<div><span>Report generated</span><strong>' + ([System.Net.WebUtility]::HtmlEncode($genTime)) + '</strong></div>' +
             '<div><span>Source file</span><strong>' + $(if($script:Redact){'[redacted]'}else{[System.Net.WebUtility]::HtmlEncode([System.IO.Path]::GetFileName($ConfigPath))}) + '</strong></div>' +
             '</div></div>'

    # ---- Sidebar -------------------------------------------------------------
    $navItems = @(
        @('findings','Security Findings'), @('system','System Overview'), @('interfaces','Interfaces'),
        @('vlans','VLANs'), @('gateways','Gateways'), @('routes','Static Routes'),
        @('firewall','Firewall Rules'), @('nat','NAT'), @('ipsec','VPN - IPsec'),
        @('openvpn','VPN - OpenVPN'), @('dhcp','DHCP Servers'), @('dns','DNS Resolver / Forwarder'),
        @('certs','Certificates & CAs'), @('users','Users & Groups'), @('aliases','Aliases'),
        @('packages','Installed Packages'), @('revision','Revision / Notes')
    )
    $nav = ''
    foreach ($n in $navItems) { $nav += '<a href="#' + $n[0] + '">' + [System.Net.WebUtility]::HtmlEncode($n[1]) + '</a>' }
    $sidebarBrand = if ($script:Redact) { [System.Net.WebUtility]::HtmlEncode((Get-RedactToken $hostname 'HOST')) } else { [System.Net.WebUtility]::HtmlEncode($hostname) }
    $sidebar = '<aside class="sidebar"><div class="brand">pfSense Report<small>' + $sidebarBrand + '</small></div>' +
               '<input id="navfilter" class="navfilter" type="text" placeholder="Filter sections..." />' +
               '<div class="navtools"><button onclick="expandAll()">Expand all</button><button onclick="collapseAll()">Collapse all</button></div>' +
               '<nav>' + $nav + '</nav></aside>'

    $footer = '<div class="footer">Generated locally by pfsense_report.ps1 &mdash; no data left this machine. Heuristic risk flags are informational and do not replace a manual security review.</div>'

    # ---- Final document ------------------------------------------------------
    $doc = '<!DOCTYPE html><html lang="en"><head><meta charset="utf-8">' +
           '<meta name="viewport" content="width=device-width, initial-scale=1">' +
           '<title>' + (E $Title) + '</title><style>' + $css + '</style></head><body>' +
           $sidebar +
           '<main class="main">' + $cover + $banner + $cards + $sections + $footer + '</main>' +
           '<script>' + $js + '</script></body></html>'

    # ---- Write ---------------------------------------------------------------
    $outDir = [System.IO.Path]::GetDirectoryName([System.IO.Path]::GetFullPath($OutputPath))
    if (-not [string]::IsNullOrWhiteSpace($outDir) -and -not (Test-Path -LiteralPath $outDir)) {
        [void](New-Item -ItemType Directory -Path $outDir -Force)
    }
    $utf8 = New-Object System.Text.UTF8Encoding($false)
    [System.IO.File]::WriteAllText($OutputPath, $doc, $utf8)

    Write-Host "pfSense report written to: $OutputPath" -ForegroundColor Green
    Write-Host ("Sections rendered, {0} risk flag(s) raised ({1} high)." -f $cFind, $highCount)
    exit 0
}
catch {
    Write-Error ("Unexpected error on line {0}: {1}`nPlease verify the structure of the XML config file." -f $_.InvocationInfo.ScriptLineNumber, $_.Exception.Message)
    exit 1
}
