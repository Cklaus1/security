# WSL2 Security Hardening Toolkit

A defense-in-depth security toolkit for WSL2 (Ubuntu 24.04 LTS) covering hardening, monitoring, DNS-level threat blocking, and secrets management.

## What's Included

| Component | Description |
|-----------|-------------|
| [wsl2-security-hardening.md](wsl2-security-hardening.md) | Comprehensive hardening guide — firewall, AppArmor, process accounting, command logging, Pi-hole DNS, file integrity, and more |
| [scripts/security-monitor.sh](scripts/security-monitor.sh) | Automated security log checker with color-coded findings across 9 audit categories |
| [kms-integration.md](kms-integration.md) | Secrets management architecture — dotenvx + AWS KMS + OpenBao integration |
| [pi-hole/](pi-hole/) | Pi-hole v6 DNS sinkhole (git submodule) for network-level ad/tracker/malware blocking |
| [wazuh-install.sh](wazuh-install.sh) | Wazuh 4.11.2 security agent installer for endpoint detection and response |

## Quick Start

### Hardening Guide

The main guide (`wsl2-security-hardening.md`) is organized in tiers:

| Tier | Time | RAM Overhead | Scope |
|------|------|-------------|-------|
| **Baseline** | 15 min | Negligible | Firewall, AppArmor, process accounting, command logging, auto-updates |
| **Recommended** | 30 min | 200-500 MB | Pi-hole DNS blocking (1M+ blocked domains), monitoring script |
| **Advanced** | 60 min | 2-4 GB+ | Wazuh EDR, container hardening, file integrity monitoring |

A quick install script is included at the bottom of the guide for automated setup.

### Security Monitor

```bash
# Check all logs from the last 24 hours
./scripts/security-monitor.sh

# Check last hour only
./scripts/security-monitor.sh --hours 1

# Cron-friendly (no color output)
./scripts/security-monitor.sh --quiet
```

Checks performed:

- **Authentication** — failed logins, brute force detection, unauthorized sudo
- **Command Audit** — reconnaissance, exfiltration, persistence, evasion patterns
- **AppArmor** — MAC policy violations
- **Firewall (UFW)** — blocked connections, port scan detection
- **DNS (Pi-hole)** — DGA detection, C2 beaconing, DNS tunneling, query anomalies
- **Packages** — suspicious installs (nmap, hydra, netcat, etc.), auto-update failures
- **Cron** — jobs from /tmp or /dev/shm, unexpected cron file modifications
- **System Health** — failed services, journal errors, listening ports
- **File Integrity** — resolv.conf tampering, world-writable files in /etc, SUID binaries

### Pi-hole on WSL2

The hardening guide documents a working Pi-hole setup that solves the WSL2 port 53 conflict (kernel DNS proxy on `10.255.255.254`). Key details:

- Uses `listeningMode = "NONE"` with custom `bind-interfaces` to avoid the WSL DNS proxy
- Static IP (`172.31.95.250/20`) on eth0 for stable Windows DNS resolution
- Windows DNS: primary `172.31.95.250` (Pi-hole), secondary `1.1.1.1` (fallback when WSL is off)
- 1,038,531 unique blocked domains across 3 blocklists (StevenBlack, Hagezi Pro, Hagezi TIF)

## Requirements

- WSL2 with Ubuntu 24.04 LTS (Noble)
- Kernel 6.6.x+
- `systemd=true` in `/etc/wsl.conf`
- Apple Silicon / x86_64

## Repository Structure

```
.
├── README.md
├── LICENSE
├── wsl2-security-hardening.md    # Main hardening guide (13 sections + quick install script)
├── kms-integration.md            # Secrets management architecture
├── wazuh-install.sh              # Wazuh EDR agent installer
├── wazuh-install-files.tar       # Wazuh supporting files
├── scripts/
│   └── security-monitor.sh       # Automated security log checker
└── pi-hole/                      # Pi-hole v6 (git submodule)
```

## License

This work is licensed under [CC BY-NC 4.0](LICENSE). See LICENSE for details.
