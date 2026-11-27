# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and this project adheres
to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [1.2.0] - 2026-11-27
### Added
- Compact **Hudu / KB export mode** (`-Hudu`, `-HuduFormat Html|Markdown`): produces a clean, paste-ready inline-styled HTML fragment or GFM Markdown summary with only the essential setup details (empty sections omitted, disabled firewall rules omitted with a count note, IPsec Phase 1+2 combined, high/warn alerts highlighted, and all PSKs/secrets omitted for password-vault storage). Auto-selects Markdown when `-OutputPath` ends in `.md` or `.markdown`.

## [1.1.0] - 2026-11-26
### Security
- Hardened XML loading with `XmlReaderSettings` (`DtdProcessing = Prohibit`, `XmlResolver = $null`) to prevent XXE and DTD entity expansion (Billion Laughs), and fixed UTF-8 decoding on Windows PowerShell 5.1.
- Replaced XPath string interpolation in certificate usage lookup with a single-pass $O(N)$ DOM index (eliminates XPath injection / crash on quotes in `refid`).
- Overhauled `-Redact` engine: fixed IPv6 matching (handles compressed `::` addresses while never corrupting `HH:MM:SS` timestamps), validated IPv4 octets (ignores OIDs/versions), normalized hyphenated MACs, added word boundaries on short hostnames, eliminated FQDN double-redaction, and added field-aware redaction for bare DHCP/DNS hostnames, usernames, emails, and certificate Distinguished Name attributes (`O`/`OU`/`L`/`ST`/`CN`).
- Added click-to-reveal masking and a Confidentiality Notice banner when unredacted secrets are present in the report.
- Removed inline `onclick`/`onkeydown` handlers in favor of `addEventListener` and added a strict `Content-Security-Policy` meta header.
- Fixed workflow script injection in `release.yml` by passing tag inputs via environment variables and validating semver format.

### Fixed
- Fixed cover **Interfaces** stat card always displaying `1` when ≥1 interfaces existed (caused by piping comma-wrapped `XNodes` output into `Where-Object`).
- Fixed relative `-OutputPath` and `-LogoPath` resolving against `.NET`'s `CurrentDirectory` instead of PowerShell's `Set-Location` working directory.
- Fixed culture-dependent `[double]::TryParse` version banner false positives on non-English locales.
- Fixed floating firewall rules (`<floating>yes</floating>`) with multi-interface lists being misgrouped and bypassing WAN risk analysis.
- Fixed SSH `<enable/>` empty-tag detection, IPsec Phase 1 multi-proposal inspection (no longer ignores proposals #2+), OpenVPN `<disable/>` / legacy `<crypto>` / empty endpoint handling, NAT inversion flags (`<nonat/>`, `<nordr/>`, `<nobinat/>`), implicit `pass` port-forward auditing, and `track6` / `subnetv6` interface rendering.
- Fixed sticky table headers, print page-break / multi-page table layout, WCAG AA color contrast, and `<h2 role="button">` ARIA heading semantics.
- Fixed cross-platform path separators in `tests/Invoke-Tests.ps1` for Linux/macOS PowerShell 7.

### Added
- **New pfSense sections** (22 total): Virtual IPs (CARP/IP Alias/Proxy ARP), WireGuard VPN (tunnels & peers, never exports keys), High Availability (pfsync & XMLRPC sync, never exports sync password), Interface Groups / LAGGs / Bridges, Gateway Groups, DHCPv6 & DHCP Relay, External Authentication Servers (LDAP/RADIUS, never exports secrets), and System Services (SNMP, remote Syslog, Dynamic DNS, Schedules), plus CRLs.
- **Expanded security heuristics**: HTTP WebGUI (`INSECURE WEBGUI`), WAN management exposure (`WAN MGMT EXPOSED`), NAT implicit `pass` (`NAT INLINE PASS`), SSH password auth, DNS rebind / HTTP Referer disabled, SHA-1 / Blowfish / CAST128 / RC4 / NULL / weak DH / IKEv1 / Aggressive Mode / No-PFS / OpenVPN compression, weak cert signatures & short RSA keys, not-yet-valid certs, `md5-hash` users, plaintext LDAP, default SNMP communities, and aggregated internal `NO LOG` reporting.
- **Interactive report UX**: global table search bar, clickable finding filter cards, deep links from findings to rows, alias/gateway/cert/VLAN cross-links with alias hover previews, hide-disabled toggles, dark mode toggle, print button, and sidebar section counts.
- **CLI & performance**: `-WanInterfaces`, `-InternalInterfaces`, `-ExpiryWarnDays`, `-JsonPath`, `-PassThru`, and `-Quiet`; `StringBuilder`/`List` rendering; `Set-StrictMode -Version Latest`; dot-sourceable helpers for unit testing.
- **CI & tests**: expanded to 75+ unit, integration, and security checks; added Ubuntu PowerShell 7 + encoding + `node --check` JS syntax CI job; enforced zero PSScriptAnalyzer warnings.

## [1.0.0] - 2026-07-10
### Added
- Standalone `pfsense_report.ps1` that renders a self-contained HTML report from a
  pfSense `config.xml` backup — no AI, no external API, no internet, no modules.
- Coverage of all 17 configuration areas: metadata, system, interfaces, VLANs,
  gateways, static routes, firewall rules, NAT, IPsec, OpenVPN, DHCP, DNS
  resolver/forwarder, certificates & CAs, users & groups, aliases, packages, revision.
- Context-aware firewall risk model that scores rules by **interface trust**
  (WAN/untrusted vs internal/trusted vs VPN) combined with **protocol**
  (e.g. WAN TCP any→any = HIGH RISK; WAN ICMP = low; LAN any→any = not flagged).
- Risk badges: HIGH RISK, WAN EXPOSED, WEAK CRYPTO, EXPIRED, EXPIRING SOON, plus a
  severity-sorted Security Findings summary.
- Certificate parsing via `X509Certificate2` with expiry status and a "Used by"
  usage-context column resolved from `refid` references.
- `-Redact` mode with **stable tokenization** (IP-001, HOST-002, …) so sanitized
  reports remain analyzable while exposing no real values. Private keys, password
  hashes and TLS static keys are never emitted, with or without `-Redact`.
- Fixed left navigation, collapsible sections, print stylesheet (File → Print → PDF),
  responsive layout, and keyboard/ARIA support.
- Pure-ASCII source + UTF-8 BOM for Windows PowerShell 5.1 and PowerShell 7 compatibility.

[Unreleased]: https://github.com/NeverNathaniel/pf2html/compare/v1.2.0...HEAD
[1.2.0]: https://github.com/NeverNathaniel/pf2html/compare/v1.1.0...v1.2.0
[1.1.0]: https://github.com/NeverNathaniel/pf2html/releases/tag/v1.1.0
[1.0.0]: https://github.com/NeverNathaniel/pf2html/commit/58df6c8d748278e701456c64590e003ec28a9aa8
