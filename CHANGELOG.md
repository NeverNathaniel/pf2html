# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and this project adheres
to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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

<!-- Link targets can be added once the GitHub remote exists:
[Unreleased]: https://github.com/OWNER/pf2html/compare/v1.0.0...HEAD
[1.0.0]: https://github.com/OWNER/pf2html/releases/tag/v1.0.0
-->
