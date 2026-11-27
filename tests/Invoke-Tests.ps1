<#
.SYNOPSIS
    Comprehensive unit, functional, and security test suite for pfsense_report.ps1.

.DESCRIPTION
    Exercises pfsense_report.ps1 via both direct unit tests (dot-sourcing helpers) and
    child-process integration runs against tests/fixtures/sample-config.xml plus
    synthetic edge-case and negative-security XML configs.

    Designed with zero external module dependencies so it runs offline on Windows
    PowerShell 5.1 and PowerShell 7+ (Windows, Linux, macOS).

.EXAMPLE
    pwsh ./tests/Invoke-Tests.ps1
    powershell -File ./tests/Invoke-Tests.ps1
#>
[CmdletBinding()]
param(
    [string]$ScriptPath,
    [string]$Fixture
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$script:Failures = 0
$script:Passed   = 0

# Resolve defaults in the body (PS 5.1 compatibility) with cross-platform Join-Path
if (-not $ScriptPath) {
    $repoRoot   = Split-Path -Path $PSScriptRoot -Parent
    $ScriptPath = Join-Path $repoRoot 'pfsense_report.ps1'
}
if (-not $Fixture) {
    $fixDir  = Join-Path $PSScriptRoot 'fixtures'
    $Fixture = Join-Path $fixDir 'sample-config.xml'
}

function Check {
    param([string]$Name, [bool]$Condition)
    if ($Condition) {
        Write-Host ("  PASS  " + $Name) -ForegroundColor Green
        $script:Passed++
    }
    else {
        Write-Host ("  FAIL  " + $Name) -ForegroundColor Red
        $script:Failures++
    }
}

$exe = if ($PSVersionTable.PSVersion.Major -ge 6) { 'pwsh' } else { 'powershell' }
$ScriptPath = (Resolve-Path -LiteralPath $ScriptPath).Path
$Fixture    = (Resolve-Path -LiteralPath $Fixture).Path
$tmpRoot    = Join-Path ([System.IO.Path]::GetTempPath()) ('pf2html-tests-' + [guid]::NewGuid().ToString('N').Substring(0, 8))
[void](New-Item -ItemType Directory -Path $tmpRoot -Force)
$utf8NoBom  = New-Object System.Text.UTF8Encoding($false)

Write-Host ("Testing {0} with {1} ({2})" -f (Split-Path $ScriptPath -Leaf), $exe, $PSVersionTable.PSVersion)

try {
    # ==============================================================================
    # 1. Static parse & encoding checks
    # ==============================================================================
    Write-Host "`n[1/5] Static parse & encoding" -ForegroundColor Cyan
    $perr = $null
    [System.Management.Automation.Language.Parser]::ParseFile($ScriptPath, [ref]$null, [ref]$perr) | Out-Null
    Check "script parses with no syntax errors" (-not $perr)

    $rawBytes = [System.IO.File]::ReadAllBytes($ScriptPath)
    $hasBom   = ($rawBytes.Length -ge 3 -and $rawBytes[0] -eq 0xEF -and $rawBytes[1] -eq 0xBB -and $rawBytes[2] -eq 0xBF)
    Check "pfsense_report.ps1 has UTF-8 BOM (PS 5.1 compatibility)" $hasBom
    $nonAscii = $false
    for ($i = 3; $i -lt $rawBytes.Length; $i++) {
        if ($rawBytes[$i] -gt 127) { $nonAscii = $true; break }
    }
    Check "pfsense_report.ps1 body is pure ASCII" (-not $nonAscii)

    # ==============================================================================
    # 2. Unit tests (dot-source helpers directly)
    # ==============================================================================
    Write-Host "`n[2/5] Unit tests (helpers, redaction, crypto, exposure)" -ForegroundColor Cyan
    . $ScriptPath
    Initialize-ReportContext -RedactMode $true -ExpiryWarnDaysValue 90
    $script:RedactHost   = 'fw'
    $script:RedactDomain = 'example.com'

    Check "Get-Ipv4Mask /0 -> 0.0.0.0"   ((Get-Ipv4Mask '0') -eq '0.0.0.0')
    Check "Get-Ipv4Mask /24 -> 255.255.255.0" ((Get-Ipv4Mask '24') -eq '255.255.255.0')
    Check "Get-Ipv4Mask /32 -> 255.255.255.255" ((Get-Ipv4Mask '32') -eq '255.255.255.255')
    Check "Get-Ipv4Mask invalid -> empty" ((Get-Ipv4Mask '99') -eq '')

    # Redaction: MAC normalization
    $m1 = Apply-Redaction '00:11:22:33:44:55'
    $m2 = Apply-Redaction '00-11-22-33-44-55'
    Check "redaction: colon and hyphen MAC normalize to same MAC-NNN" ($m1 -match '^MAC-\d{3}$' -and $m1 -eq $m2)

    # Redaction: IPv4 validation & OID protection
    $ip4 = Apply-Redaction 'Server 192.0.2.10/24 oid 1.3.6.1.4.1 invalid 999.0.0.1'
    Check "redaction: valid IPv4 masked with CIDR preserved" ($ip4 -match 'IP-\d{3}/24' -and $ip4 -notmatch '192\.0\.2\.10')
    Check "redaction: OID and invalid octets not corrupted" ($ip4 -match '1\.3\.6\.1\.4\.1' -and $ip4 -match '999\.0\.0\.1')

    # Redaction: IPv6 compressed + full + timestamp protection
    $v6a = Apply-Redaction 'fe80::1'
    $v6b = Apply-Redaction '2001:0db8::1'
    $v6c = Apply-Redaction '2001:db8::1'
    $ts  = Apply-Redaction '2023-11-14 22:13:20 -07:00'
    Check "redaction: compressed IPv6 (fe80::1) masked" ($v6a -match '^IP-\d{3}$')
    Check "redaction: IPv6 canonical forms map to same token" ($v6b -match '^IP-\d{3}$' -and $v6b -eq $v6c)
    Check "redaction: HH:MM:SS timestamps NOT corrupted to IP-NNN" ($ts -eq '2023-11-14 22:13:20 -07:00')

    # Redaction: Short hostname word boundaries & FQDN correlation (no double-redaction)
    $prose = Apply-Redaction 'software on fw and fw.example.com and fw01 using pfsense_report.ps1'
    Check "redaction: short hostname 'fw' does not mangle 'software' or 'fw01'" ($prose -match '\bsoftware\b' -and $prose -match '\bfw01\b')
    Check "redaction: filename pfsense_report.ps1 not treated as FQDN" ($prose -match 'pfsense_report\.ps1')
    Check "redaction: bare 'fw' and 'fw.example.com' share consistent HOST/DOMAIN tokens" ($prose -match 'on (HOST-\d{3}) and \1\.(DOMAIN-\d{3})')

    # Redaction: Email & Cert DN
    $em = Apply-Redaction 'Contact alice@example.com'
    Check "redaction: email masks local-part and domain" ($em -notmatch 'alice' -and $em -match 'USER-\d{3}@DOMAIN-\d{3}')
    $dn = E-CertDn 'CN=fw.example.com, O=Acme Corp, OU=Security, L=Seattle, ST=WA, C=US'
    Check "redaction: cert DN masks O/OU/L/ST and CN" ($dn -notmatch 'Acme' -and $dn -notmatch 'Seattle' -and $dn -match 'O=ORG-\d{3}')

    # Weak crypto & DH
    $wk1 = Get-WeakCryptoHits @('3des', 'hmac_sha1', 'md5')
    Check "weak crypto: 3DES/MD5 in High, SHA-1 in Warn" (($wk1.High -contains '3DES') -and ($wk1.High -contains 'MD5') -and ($wk1.Warn -contains 'SHA-1'))
    $wk2 = Get-WeakCryptoHits @('aes-256-gcm', 'sha256')
    Check "weak crypto: AES-256-GCM / SHA256 clean" ($wk2.High.Count -eq 0 -and $wk2.Warn.Count -eq 0)
    Check "weak DH: group 2 -> high" ((Get-WeakDhFinding '2' $false).Sev -eq 'high')
    Check "weak DH: PFS 0 -> warn NO PFS" ((Get-WeakDhFinding '0' $true).Label -eq 'NO PFS')
    Check "weak DH: group 14 -> clean" ($null -eq (Get-WeakDhFinding '14' $false))

    # Exposure model
    $expMgmt = Get-RuleExposure -trust 'wan' -type 'pass' -dir 'in' -protoClass 'tcpudp' -srcBroad $true -dstBroad $false -dstPortSet $true -protoDisp 'tcp' -dstSvc 'wanip:443' -isFirewallMgmt $true
    Check "exposure: WAN management access flagged HIGH (WAN MGMT EXPOSED)" ($null -ne $expMgmt -and $expMgmt.Sev -eq 'high' -and $expMgmt.Label -eq 'WAN MGMT EXPOSED')
    $expFloat = Get-RuleExposure -trust 'floating' -type 'pass' -dir 'in' -protoClass 'tcpudp' -srcBroad $true -dstBroad $true -dstPortSet $false -protoDisp 'tcp' -dstSvc 'any' -floatingTouchesWan $true
    Check "exposure: floating WAN any->any flagged HIGH RISK" ($null -ne $expFloat -and $expFloat.Sev -eq 'high' -and $expFloat.Label -eq 'HIGH RISK')

    # ==============================================================================
    # 3. Normal + Redacted + JSON integration runs on sample-config.xml
    # ==============================================================================
    Write-Host "`n[3/5] Integration tests (sample-config.xml)" -ForegroundColor Cyan
    $outNormal = Join-Path $tmpRoot 'pfreport-normal.html'
    $outRedact = Join-Path $tmpRoot 'pfreport-redacted.html'
    $outJson   = Join-Path $tmpRoot 'pfreport-redacted.json'

    & $exe -NoProfile -ExecutionPolicy Bypass -File $ScriptPath -ConfigPath $Fixture -OutputPath $outNormal -Quiet | Out-Null
    Check "normal run exits 0" ($LASTEXITCODE -eq 0)
    Check "output HTML created" (Test-Path -LiteralPath $outNormal)

    $h = if (Test-Path -LiteralPath $outNormal) { [System.IO.File]::ReadAllText($outNormal) } else { '' }
    Check "self-contained (no external http/https refs)" (-not ($h -match 'src="https?://' -or $h -match 'href="https?://' -or $h -match '@import'))
    Check "strict CSP meta tag present" ($h -match 'http-equiv="Content-Security-Policy"')
    Check "no inline onclick/onkeydown event handlers" (-not ($h -match '\sonclick=' -or $h -match '\sonkeydown='))
    Check "renders all 22 sections" (([regex]::Matches($h, '<section class="report-section[^"]*" id=')).Count -eq 22)
    Check "cover Interfaces stat card accurately shows 3 (regression check)" ($h -match '<div class="n">3</div><div class="l">Interfaces</div>')
    Check "WAN TCP any->any flagged HIGH RISK" ($h -match 'HIGH RISK')
    Check "WAN ICMP treated as low risk (WAN ICMP)" ($h -match 'WAN ICMP')
    Check "LAN/internal interface marked TRUSTED" ($h -match 'TRUSTED / INTERNAL')
    Check "SSH password auth flagged" ($h -match 'SSH PASSWORD AUTH')
    Check "internal NO LOG aggregated (not flooded)" ($h -match 'NO LOG \(INTERNAL\)')
    Check "certificate parsed (subject CN + key info present)" ($h -match 'demo-fw\.example\.com' -and $h -match 'RSA 2048b')
    Check "certificate usage context resolved" ($h -match 'WebGUI HTTPS certificate')
    Check "port forward rendered" ($h -match 'HTTPS to web server')
    Check "1:1 NAT rendered" ($h -match '1:1 mapping')
    Check "Confidentiality Notice banner shown when secrets present" ($h -match 'Confidentiality Notice')

    # Secret-leakage checks
    Check "no PEM PRIVATE KEY block leaked" (-not ($h -cmatch 'BEGIN [A-Z ]*PRIVATE KEY'))
    Check "no bcrypt hash leaked" (-not ($h -match '\$2y\$'))
    Check "no private-key placeholder leaked" (-not ($h -match 'NOT-A-REAL-PRIVATE-KEY'))
    Check "PSK shown (behind click-to-reveal) when NOT redacted" ($h -match 'secret-val is-masked[^>]*>EXAMPLEPSKdonotuse<')

    # Redacted + JSON run
    & $exe -NoProfile -ExecutionPolicy Bypass -File $ScriptPath -ConfigPath $Fixture -OutputPath $outRedact -JsonPath $outJson -Redact -Quiet | Out-Null
    Check "redacted + JSON run exits 0" ($LASTEXITCODE -eq 0)
    $r = if (Test-Path -LiteralPath $outRedact) { [System.IO.File]::ReadAllText($outRedact) } else { '' }
    Check "redacted: PSK removed" (-not ($r -match 'EXAMPLEPSKdonotuse'))
    Check "redacted: Confidentiality Notice omitted" (-not ($r -match 'Confidentiality Notice'))
    Check "redacted: documentation IP 192.0.2.1 masked" (-not ($r -match '192\.0\.2\.1\b'))
    Check "redacted: MAC 00:11:22:33:44:55 masked" (-not ($r -match '00:11:22:33:44:55') -and $r -match 'MAC-\d{3}')
    Check "redacted: bare DHCP/DNS hostnames (printer, nas) masked" (-not ($r -cmatch '>printer<') -and -not ($r -cmatch '>nas<'))
    Check "redacted: FQDN demo-fw.example.com removed" (-not ($r -match 'demo-fw\.example\.com'))
    Check "redacted: stable IP tokens present (IP-NNN)" ($r -match 'IP-\d{3}')
    Check "redacted: revision timestamp HH:MM:SS NOT mangled to IP-NNN" ($r -match '\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}')

    Check "JSON export file created" (Test-Path -LiteralPath $outJson)
    $jText = if (Test-Path -LiteralPath $outJson) { [System.IO.File]::ReadAllText($outJson) } else { '{}' }
    $jObj  = $jText | ConvertFrom-Json
    Check "JSON counts.interfaces == 3" ($jObj.counts.interfaces -eq 3)
    Check "JSON counts.firewallRules == 3" ($jObj.counts.firewallRules -eq 3)
    Check "JSON redacted flag true and no raw IP/PSK" ($jObj.redacted -eq $true -and $jText -notmatch '192\.0\.2\.' -and $jText -notmatch 'EXAMPLEPSKdonotuse')

    # ==============================================================================
    # 4. Advanced pfSense scenarios, new sections & security edge cases
    # ==============================================================================
    Write-Host "`n[4/5] Advanced scenarios & negative security tests" -ForegroundColor Cyan

    $advXml = @'
<?xml version="1.0" encoding="UTF-8"?>
<pfsense>
  <version>23.3</version>
  <system>
    <hostname>edge-fw</hostname>
    <domain>corp.example</domain>
    <webgui><protocol>http</protocol><port>8080</port><nodnsrebindcheck/><nohttpreferercheck/></webgui>
    <ssh><enable/></ssh>
    <user><name>legacyadmin</name><descr><![CDATA[Legacy Account - UTF8 Cafe]]></descr><scope>user</scope><uid>2001</uid><md5-hash>$1$FAKEHASHVALUE</md5-hash></user>
    <user><name>olduser</name><disabled/><uid>2002</uid><md5-hash>$1$DISABLEDMD5</md5-hash></user>
    <group><name>netops</name><description>Network Ops</description><scope>local</scope><member>2001</member><priv>page-all</priv></group>
    <authserver><name>CorpLDAP</name><type>ldap</type><host>198.51.100.20</host><ldap_port>389</ldap_port><ldap_urltype>Standard TCP</ldap_urltype><ldap_bindpw>SUPERSECRETLDAPBINDPW</ldap_bindpw></authserver>
  </system>
  <interfaces>
    <wan><enable/><if>igb0</if><descr>WAN</descr><ipaddr>pppoe</ipaddr><gateway>WANGW</gateway></wan>
    <lan><enable/><if>lagg0</if><descr>LAN</descr><ipaddr>10.10.0.1</ipaddr><subnet>24</subnet><ipaddrv6>track6</ipaddrv6><track6-interface>wan</track6-interface><track6-prefix-id>0</track6-prefix-id><subnetv6>64</subnetv6></lan>
    <opt1><enable/><if>tun_wg0</if><descr>WG_SITE</descr><ipaddr>10.200.0.1</ipaddr><subnet>24</subnet></opt1>
  </interfaces>
  <ifgroups><ifgroupentry><ifname>CorpGroup</ifname><members>lan opt1</members><descr>Internal Group</descr></ifgroupentry></ifgroups>
  <laggs><lagg><laggif>lagg0</laggif><proto>lacp</proto><members>igb1,igb2</members><descr>Core LACP</descr></lagg></laggs>
  <bridges><bridged><bridgeif>bridge0</bridgeif><members>igb3,igb4</members><descr>DMZ Bridge</descr></bridged></bridges>
  <virtualip><vip><mode>carp</mode><interface>wan</interface><subnet>203.0.113.5</subnet><subnet_bits>29</subnet_bits><vhid>10</vhid><advskew>0</advskew><descr>WAN CARP VIP</descr></vip></virtualip>
  <gateways>
    <gateway_item><interface>wan</interface><gateway>203.0.113.1</gateway><name>WANGW</name><ipprotocol>inet</ipprotocol></gateway_item>
    <gateway_group><name>WAN_FAILOVER</name><item>WANGW|1</item><trigger>down</trigger><descr>Primary failover</descr></gateway_group>
    <defaultgw4>WANGW</defaultgw4>
  </gateways>
  <hasync><pfsyncenabled/><pfsyncinterface>lan</pfsyncinterface><pfsyncpeerip>10.10.0.2</pfsyncpeerip><synchronizetoip>10.10.0.2</synchronizetoip><username>syncadmin</username><password>SUPERSECRETHAPASS</password><synchronizerules/></hasync>
  <filter>
    <rule><floating>yes</floating><quick>yes</quick><type>pass</type><interface>wan,lan</interface><ipprotocol>inet</ipprotocol><protocol>tcp</protocol><source><any/></source><destination><any/></destination><descr>Floating WAN wide open</descr></rule>
    <rule><type>pass</type><interface>wan</interface><ipprotocol>inet</ipprotocol><protocol>tcp</protocol><source><any/></source><destination><network>wanip</network><port>8080</port></destination><descr>Exposed WebGUI</descr></rule>
    <rule><type>pass</type><interface>lan</interface><disabled/><protocol>tcp</protocol><source><any/></source><destination><any/></destination><descr>Disabled rule</descr></rule>
  </filter>
  <nat>
    <outbound><mode>manual</mode><rule><interface>wan</interface><nonat/><source><network>10.10.0.0/24</network></source><destination><any/></destination><descr>Bypass NAT</descr></rule></outbound>
    <rule><interface>wan</interface><protocol>tcp</protocol><source><any/></source><destination><network>wanip</network><port>8443</port></destination><target>10.10.0.50</target><local-port>443</local-port><associated-rule-id>pass</associated-rule-id><descr>Inline pass PF</descr></rule>
    <rule><interface>wan</interface><protocol>tcp</protocol><nordr/><destination><network>wanip</network><port>80</port></destination><descr>No RDR rule</descr></rule>
    <onetoone><interface>wan</interface><nobinat/><external>203.0.113.9</external><source><address>10.10.0.9</address></source><destination><any/></destination><descr>No BINAT</descr></onetoone>
  </nat>
  <ipsec>
    <phase1><ikeid>10</ikeid><iketype>ikev1</iketype><mode>aggressive</mode><interface>wan</interface><remote-gateway>198.51.100.99</remote-gateway><encryption><item><encryption-algorithm><name>aes</name><keylen>256</keylen></encryption-algorithm><hash-algorithm>sha256</hash-algorithm><dhgroup>14</dhgroup></item><item><encryption-algorithm><name>3des</name></encryption-algorithm><hash-algorithm>md5</hash-algorithm><dhgroup>2</dhgroup></item></encryption><authentication_method>pre_shared_key</authentication_method><pre-shared-key>ADVIPSECPSK999</pre-shared-key><descr>Multi-proposal P1</descr></phase1>
    <phase1><ikeid>11</ikeid><disabled/><iketype>ikev1</iketype><interface>wan</interface><remote-gateway>198.51.100.98</remote-gateway><encryption><item><encryption-algorithm><name>des</name></encryption-algorithm><hash-algorithm>md5</hash-algorithm><dhgroup>1</dhgroup></item></encryption><descr>Disabled Weak P1</descr></phase1>
    <phase2><ikeid>10</ikeid><mode>tunnel</mode><protocol>esp</protocol><pfsgroup>0</pfsgroup><encryption-algorithm-option><name>aes</name><keylen>256</keylen></encryption-algorithm-option><hash-algorithm-option>hmac_sha256</hash-algorithm-option><descr>No PFS P2</descr></phase2>
  </ipsec>
  <openvpn>
    <openvpn-client><disable/><description>Disabled OVPN</description><mode>p2p_tls</mode><protocol>UDP4</protocol><crypto>BF-CBC</crypto><digest>MD5</digest></openvpn-client>
  </openvpn>
  <installedpackages>
    <wireguard>
      <tunnels><item><name>tun_wg0</name><enabled>yes</enabled><listenport>51820</listenport><privatekey>WG_SUPER_SECRET_PRIVATE_KEY</privatekey><addresses><row><address>10.200.0.1</address><mask>24</mask></row></addresses><descr>Site WG</descr></item></tunnels>
      <peers><item><tun>tun_wg0</tun><enabled>yes</enabled><endpoint>198.51.100.77</endpoint><port>51820</port><presharedkey>WG_SUPER_SECRET_PSK</presharedkey><allowedips><row><address>10.200.0.2</address><mask>32</mask></row></allowedips><descr>Branch Peer</descr></item></peers>
    </wireguard>
  </installedpackages>
  <dhcpdv6><lan><enable/><range><from>2001:db8::100</from><to>2001:db8::200</to></range></lan></dhcpdv6>
  <dhcrelay><enable/><interface>opt1</interface><server>10.10.0.5</server></dhcrelay>
  <snmpd><enable/><rocommunity>public</rocommunity><bindip>lan</bindip></snmpd>
  <syslog><enable/><remoteserver>10.10.0.60:514</remoteserver></syslog>
  <dyndnses><dyndns><enable/><type>cloudflare</type><interface>wan</interface><host>fw.corp.example</host><password>SUPERSECRETDYNTOKEN</password><descr>CF DDNS</descr></dyndns></dyndnses>
  <schedules><schedule><name>BusinessHours</name><descr>Mon-Fri 8-6</descr></schedule></schedules>
  <aliases><alias><name>ExternalBlock</name><type>urltable</type><url>https://lists.example/block.txt</url><updatefreq>7</updatefreq><descr>Blocklist</descr></alias></aliases>
  <cert><refid>bad'refid</refid><descr>Quote Refid Cert</descr><type>server</type><crt>INVALID</crt></cert>
  <crl><descr>Revoked Users</descr><caref>testca1</caref><method>internal</method><cert><serial>1</serial></cert></crl>
</pfsense>
'@
    $advPath = Join-Path $tmpRoot 'advanced-config.xml'
    $advOut  = Join-Path $tmpRoot 'advanced-report.html'
    [System.IO.File]::WriteAllText($advPath, $advXml, $utf8NoBom)

    & $exe -NoProfile -ExecutionPolicy Bypass -File $ScriptPath -ConfigPath $advPath -OutputPath $advOut -Title '<script>alert(1)</script>' -Quiet | Out-Null
    Check "advanced config (including quote in refid) exits 0" ($LASTEXITCODE -eq 0)
    $ah = if (Test-Path -LiteralPath $advOut) { [System.IO.File]::ReadAllText($advOut) } else { '' }

    Check "XSS in -Title is HTML-encoded" (-not ($ah -match '<script>alert\(1\)</script>') -and $ah -match '&lt;script&gt;alert\(1\)&lt;/script&gt;')
    Check "HTTP WebGUI flagged INSECURE WEBGUI" ($ah -match 'INSECURE WEBGUI')
    Check "DNS Rebind / Referer disabled flagged" ($ah -match 'DNS REBIND OFF' -and $ah -match 'REFERER CHECK OFF')
    Check "empty <ssh><enable/></ssh> detected as enabled" ($ah -match 'SSH PASSWORD AUTH')
    Check "floating WAN,LAN rule grouped under (floating) and flagged HIGH RISK" ($ah -match '\(floating\)' -and $ah -match 'Floating WAN wide open')
    Check "WAN management exposure flagged WAN MGMT EXPOSED" ($ah -match 'WAN MGMT EXPOSED')
    Check "NAT inversion flags rendered (DO NOT NAT, NO RDR, DO NOT BINAT)" ($ah -match 'DO NOT NAT' -and $ah -match 'NO RDR' -and $ah -match 'DO NOT BINAT')
    Check "NAT implicit pass flagged NAT INLINE PASS" ($ah -match 'NAT INLINE PASS')
    Check "IPsec multi-proposal #2 weak crypto + aggressive + NO PFS flagged" ($ah -match 'WEAK CRYPTO' -and $ah -match 'AGGRESSIVE MODE' -and $ah -match 'NO PFS')
    Check "disabled IPsec P1 & OpenVPN do not trigger WEAK CRYPTO" (-not ($ah -match 'Disabled Weak P1.*WEAK CRYPTO') -and -not ($ah -match 'Disabled OVPN.*WEAK CRYPTO'))
    Check "md5-hash active user flagged WEAK PASSWORD HASH" ($ah -match 'WEAK PASSWORD HASH')
    Check "user group derived from <group><member>" ($ah -match 'netops')
    Check "plaintext LDAP flagged PLAINTEXT LDAP" ($ah -match 'PLAINTEXT LDAP')
    Check "default SNMP community flagged DEFAULT SNMP COMMUNITY" ($ah -match 'DEFAULT SNMP COMMUNITY')
    Check "new sections populated (VIPs, WireGuard, HA, LAGG, Bridge, DHCPv6, Relay, Syslog, DDNS, CRL)" (
        $ah -match 'WAN CARP VIP' -and $ah -match '51820' -and $ah -match 'pfsync State Sync' -and
        $ah -match 'Core LACP' -and $ah -match 'DMZ Bridge' -and $ah -match 'DHCPv6' -and
        $ah -match 'DHCPv4 Relay' -and $ah -match '10\.10\.0\.60:514' -and $ah -match 'CF DDNS' -and $ah -match 'Revoked Users'
    )
    Check "urltable alias URL rendered" ($ah -match 'https://lists\.example/block\.txt')
    Check "track6 interface rendered without stale /64" ($ah -match 'Track IPv6 \(WAN, prefix 0\)' -and -not ($ah -match 'Track IPv6 \(WAN, prefix 0\)/64'))
    Check "zero secret leakage (WireGuard keys, HA pass, LDAP bindpw, DynDNS token)" (
        -not ($ah -match 'WG_SUPER_SECRET_PRIVATE_KEY') -and
        -not ($ah -match 'WG_SUPER_SECRET_PSK') -and
        -not ($ah -match 'SUPERSECRETHAPASS') -and
        -not ($ah -match 'SUPERSECRETLDAPBINDPW') -and
        -not ($ah -match 'SUPERSECRETDYNTOKEN')
    )

    # Minimal empty <pfsense/> config
    $minPath = Join-Path $tmpRoot 'minimal.xml'
    $minOut  = Join-Path $tmpRoot 'minimal-report.html'
    [System.IO.File]::WriteAllText($minPath, '<?xml version="1.0"?><pfsense></pfsense>', $utf8NoBom)
    & $exe -NoProfile -ExecutionPolicy Bypass -File $ScriptPath -ConfigPath $minPath -OutputPath $minOut -Quiet | Out-Null
    $mh = if (Test-Path -LiteralPath $minOut) { [System.IO.File]::ReadAllText($minOut) } else { '' }
    Check "minimal <pfsense/> exits 0 with version warning" ($LASTEXITCODE -eq 0 -and $mh -match 'No pfSense configuration version')

    # Relative OutputPath after Set-Location (regression for .NET CWD bug)
    $relDir = Join-Path $tmpRoot 'rel-cwd-test'
    [void](New-Item -ItemType Directory -Path $relDir -Force)
    $relCmd = "Set-Location -LiteralPath '$relDir'; & '$ScriptPath' -ConfigPath '$Fixture' -OutputPath 'relative-out.html' -Quiet"
    & $exe -NoProfile -ExecutionPolicy Bypass -Command $relCmd | Out-Null
    Check "relative -OutputPath respects PowerShell Set-Location CWD" (Test-Path -LiteralPath (Join-Path $relDir 'relative-out.html'))

    # ==============================================================================
    # 5. Negative error handling (missing file, directory, XXE, invalid XML, wrong root)
    # ==============================================================================
    Write-Host "`n[5/5] Error handling & XXE rejection" -ForegroundColor Cyan
    $prevEAP = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'

    & $exe -NoProfile -ExecutionPolicy Bypass -File $ScriptPath -ConfigPath (Join-Path $tmpRoot 'does-not-exist.xml') -OutputPath $outNormal 2>$null | Out-Null
    Check "missing config file exits 1" ($LASTEXITCODE -eq 1)

    & $exe -NoProfile -ExecutionPolicy Bypass -File $ScriptPath -ConfigPath $tmpRoot -OutputPath $outNormal 2>$null | Out-Null
    Check "directory passed as -ConfigPath exits 1" ($LASTEXITCODE -eq 1)

    $xxePath = Join-Path $tmpRoot 'xxe.xml'
    [System.IO.File]::WriteAllText($xxePath, '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe "pwn">]><pfsense><version>22.5</version><system><hostname>&xxe;</hostname></system></pfsense>', $utf8NoBom)
    & $exe -NoProfile -ExecutionPolicy Bypass -File $ScriptPath -ConfigPath $xxePath -OutputPath $outNormal 2>$null | Out-Null
    Check "XXE / DTD payload rejected with exit 1" ($LASTEXITCODE -eq 1)

    $badXmlPath = Join-Path $tmpRoot 'bad.xml'
    [System.IO.File]::WriteAllText($badXmlPath, '<pfsense><unclosed>', $utf8NoBom)
    & $exe -NoProfile -ExecutionPolicy Bypass -File $ScriptPath -ConfigPath $badXmlPath -OutputPath $outNormal 2>$null | Out-Null
    Check "malformed XML exits 1" ($LASTEXITCODE -eq 1)

    $wrongRootPath = Join-Path $tmpRoot 'wrong-root.xml'
    [System.IO.File]::WriteAllText($wrongRootPath, '<?xml version="1.0"?><notpfsense/>', $utf8NoBom)
    & $exe -NoProfile -ExecutionPolicy Bypass -File $ScriptPath -ConfigPath $wrongRootPath -OutputPath $outNormal 2>$null | Out-Null
    Check "non-pfSense XML root exits 1" ($LASTEXITCODE -eq 1)

    $ErrorActionPreference = $prevEAP
}
finally {
    Remove-Item -LiteralPath $tmpRoot -Recurse -Force -ErrorAction SilentlyContinue
}

Write-Host ''
if ($script:Failures -gt 0) {
    Write-Host ("{0} passed, {1} test(s) FAILED." -f $script:Passed, $script:Failures) -ForegroundColor Red
    exit 1
}
Write-Host ("All {0} tests passed." -f $script:Passed) -ForegroundColor Green
exit 0
