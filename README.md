# pf2html — pfSense Config Report

Turn a pfSense `config.xml` backup into a professional, **self-contained HTML report** —
entirely offline. No AI, no external API, no internet connection, and no third-party
PowerShell modules. The output is a single `.html` file you can open in any modern browser
on an air-gapped machine and print to PDF (File → Print → Save as PDF).

<!-- After the GitHub remote exists, uncomment and set OWNER:
[![CI](https://github.com/OWNER/pf2html/actions/workflows/ci.yml/badge.svg)](https://github.com/OWNER/pf2html/actions/workflows/ci.yml)
-->

![Report overview — cover, stat cards and severity-sorted Security Findings](docs/screenshot.png)

## Features

- **Every section parsed** (17 areas): report metadata, system overview, interfaces,
  VLANs, gateways, static routes, firewall rules, NAT (outbound / port forwards / 1:1),
  IPsec (Phase 1 & 2), OpenVPN (servers & clients), DHCP servers + static mappings,
  DNS resolver/forwarder, certificates & CAs, users & groups, aliases, installed
  packages, and revision notes. Absent sections render **"Not configured"** rather than
  being silently skipped.

- **Context-aware risk model.** Firewall rules are scored by *interface trust*
  (WAN = Internet-facing / untrusted; LAN / OPT = internal / trusted; VPN) combined with
  *protocol* — so a LAN any→any rule isn't a false alarm, while the same rule on a WAN is:

  | Rule | Flag |
  |------|------|
  | WAN, TCP/UDP or all-protocol, any→any, no port | 🔴 **HIGH RISK** |
  | WAN, any source → a specific port/host | 🟠 **WAN EXPOSED** (published service) |
  | WAN, ICMP from any | 🔵 WAN ICMP (low) |
  | WAN, restricted source (alias / specific IP) | 🔵 WAN (restricted) |
  | LAN / internal, any→any | *not flagged — normal* |

  Each interface group is labeled with its trust level, and every flag is a colored badge
  **with a text label** so it survives black-and-white printing:

  ![Firewall rules grouped by interface with trust badges and per-rule risk flags](docs/screenshot-firewall.png)

- **Security Findings summary.** All flags — including **WEAK CRYPTO** (DES/3DES/MD5 in
  IPsec or OpenVPN), **EXPIRED** / **EXPIRING SOON** certificates, and per-rule **NO LOG**
  indicators — are collected into one severity-sorted table at the top of the report
  (high → warn → info), with count cards per flag type.

- **Certificate intelligence.** Expiry parsed from the embedded base64 via .NET
  `X509Certificate2`, plus a *Used by* column resolving where each cert/CA is referenced
  (WebGUI HTTPS, OpenVPN server/client, IPsec, signing). Private key material is
  **never** exported.

- **Redaction for safe sharing** (`-Redact`). Replaces PSKs with `[REDACTED]` and masks
  IPs, MACs, hostnames and domains using **stable tokens** (`IP-001`, `HOST-002`, …) so a
  sanitized report stays *analyzable* — the same host is still recognizable across
  firewall rules, NAT entries and DHCP reservations. Password hashes, private keys and
  OpenVPN TLS static keys are never emitted, redacted or not.

- **Readable, printable layout.** Fixed sidebar navigation with section filter,
  collapsible sections (keyboard/ARIA accessible), sticky table headers, alternating row
  shading, horizontal scroll on overflow, a responsive breakpoint for narrow screens, and
  a print stylesheet that opens all sections and page-breaks per section — all CSS/JS
  embedded inline, zero external resources.

- **Cross-version PowerShell.** Works on Windows PowerShell 5.1 and PowerShell 7+ —
  both engines are exercised in CI on every push.

## Usage

```powershell
.\pfsense_report.ps1 -ConfigPath "config.xml" -OutputPath "report.html"
```

### Parameters

| Parameter | Description |
|-----------|-------------|
| `-ConfigPath` | **(required)** Path to the pfSense `config.xml` backup. |
| `-OutputPath` | Output `.html` path. Defaults to `<configname>-report.html`; parent folders are created if missing. |
| `-Redact` | Sanitize for sharing: `[REDACTED]` PSKs, stable-token masking of IPs / MACs / hostnames / domains. |
| `-Title "..."` | Custom title shown in the report header. |
| `-LogoPath "logo.png"` | Optional logo embedded inline as base64 (png/jpg/gif/svg/webp). |

### Examples

```powershell
# Internal report
.\pfsense_report.ps1 -ConfigPath ".\config-fw01.xml" -OutputPath ".\fw01.html"

# Sanitized copy to share with a third party
.\pfsense_report.ps1 -ConfigPath ".\config-fw01.xml" -OutputPath ".\fw01-shared.html" -Redact -Title "FW01 (Sanitized)"

# With a branded logo
.\pfsense_report.ps1 -ConfigPath ".\config-fw01.xml" -OutputPath ".\fw01.html" -LogoPath ".\logo.png"
```

Exit codes: `0` on success; `1` if the config is missing, not valid XML, or not a pfSense
backup (a clear message is written to stderr). Configs from versions outside the
validated range get a visible warning banner in the report instead of a hard failure.

## Security notes

- The tool runs **fully offline** and writes a single local `.html` file. Nothing leaves the machine.
- Generated reports (without `-Redact`) contain real IPs, hostnames and IPsec PSKs.
  Treat them as sensitive. The included [`.gitignore`](.gitignore) excludes `reports/`,
  `*.html` and `config-*.xml` so real backups and reports are never committed.
- Private keys, TLS static keys and password hashes are never written to the report.
- The screenshots above were generated from the **synthetic test fixture**
  ([`tests/fixtures/sample-config.xml`](tests/fixtures/sample-config.xml)) — documentation
  IPs (RFC 5737), fake hashes, and a throwaway self-signed certificate only.

## Requirements

Windows with Windows PowerShell 5.1 **or** PowerShell 7+. No modules, no internet.

## Repository layout

```
pfsense_report.ps1              The tool — single file, no dependencies
tests/Invoke-Tests.ps1          Functional + security smoke tests (21 checks)
tests/fixtures/sample-config.xml Synthetic pfSense config used by tests & screenshots
.github/workflows/ci.yml        Lint (PSScriptAnalyzer) + tests on PS 5.1 and PS 7
.github/workflows/release.yml   Tag-triggered release: validate, zip, checksum, publish
docs/                           README screenshots
```

## Development

Run the test suite locally — it generates a report from the sanitized fixture and asserts
section rendering, context-aware risk flags, certificate parsing, redaction tokenization,
exit codes, and that no secret material ever reaches the output:

```powershell
pwsh ./tests/Invoke-Tests.ps1               # PowerShell 7
powershell -File ./tests/Invoke-Tests.ps1   # Windows PowerShell 5.1
```

CI ([`ci.yml`](.github/workflows/ci.yml)) runs PSScriptAnalyzer plus the suite on **both**
engines for every push and pull request. Running on real 5.1 matters: it has already
caught engine-specific bugs (single-element collection collapse, BOM-less encoding) that
PowerShell 7 silently tolerates.

## Releases

Releases are produced automatically by pushing a semver tag:

```bash
git tag v1.0.0
git push origin v1.0.0
```

The [release workflow](.github/workflows/release.yml) re-validates on both PowerShell
engines, packages `pfsense_report.ps1` (plus README / LICENSE / CHANGELOG) into a
versioned `.zip` with SHA-256 checksums, and publishes a GitHub Release with
auto-generated notes. See [CHANGELOG.md](CHANGELOG.md) for version history.

## License

[MIT](LICENSE)
