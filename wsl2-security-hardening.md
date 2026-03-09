# WSL2 Security Hardening Guide

Tested on Ubuntu 24.04 LTS (Noble) running on WSL2 kernel 6.6.x.

This guide documents every step to harden a fresh WSL2 instance. Run all commands as root or prefix with `sudo`.

---

## Table of Contents

1. [Prerequisites](#1-prerequisites)
2. [Firewall (ufw)](#2-firewall-ufw)
3. [AppArmor (Mandatory Access Control)](#3-apparmor-mandatory-access-control)
4. [Process Accounting (acct)](#4-process-accounting-acct)
5. [Shell Command Logging (PROMPT_COMMAND)](#5-shell-command-logging-prompt_command)
6. [Unattended Security Updates](#6-unattended-security-updates)
7. [User Account Hardening](#7-user-account-hardening)
8. [SSH Hardening](#8-ssh-hardening)
9. [Kernel and Network Hardening (sysctl)](#9-kernel-and-network-hardening-sysctl)
10. [File Integrity Monitoring](#10-file-integrity-monitoring)
11. [Secrets and Credential Protection](#11-secrets-and-credential-protection)
12. [Container / Docker Hardening](#12-container--docker-hardening)
13. [Cron and Systemd Timer Auditing](#13-cron-and-systemd-timer-auditing)
14. [Backup and Recovery](#14-backup-and-recovery)
15. [Lynis (Security Auditing)](#15-lynis-security-auditing)
16. [Rootkit Detection (rkhunter / chkrootkit)](#16-rootkit-detection-rkhunter--chkrootkit)
17. [CrowdSec (Intrusion Prevention)](#17-crowdsec-intrusion-prevention)
18. [Falco (Runtime Threat Detection)](#18-falco-runtime-threat-detection)
19. [Trivy (Container Vulnerability Scanning)](#19-trivy-container-vulnerability-scanning)
20. [Microsoft Defender for Endpoint (EDR)](#20-microsoft-defender-for-endpoint-edr)
21. [ClamAV (Antivirus Scanning)](#21-clamav-antivirus-scanning)
22. [OpenCanary (Honeypot / Deception)](#22-opencanary-honeypot--deception)
23. [Pi-hole (Network-Level Ad/Tracker Blocking)](#23-pi-hole-network-level-adtracker-blocking)
24. [WSL-Specific Hardening](#24-wsl-specific-hardening)
25. [Verification Checklist](#25-verification-checklist)
26. [Known WSL2 Limitations](#26-known-wsl2-limitations)
27. [Log Sources Reference](#27-log-sources-reference)
28. [Security Monitoring Script](#28-security-monitoring-script)
29. [Useful Monitoring Commands](#29-useful-monitoring-commands)

---

## 1. Prerequisites

Update the package index first:

```bash
apt update
```

---

## 2. Firewall (ufw)

WSL2 has no firewall by default. While WSL2 runs behind a Windows NAT, there is no filtering within the Linux instance itself.

### Install and enable

```bash
apt install -y ufw
ufw default deny incoming
ufw default allow outgoing
ufw --force enable
```

### Verify

```bash
ufw status verbose
```

Expected output:

```
Status: active
Logging: on (low)
Default: deny (incoming), allow (outgoing), disabled (routed)
```

### Common operations

```bash
# Allow a dev server port from WSL NAT range only
ufw allow from 172.16.0.0/12 to any port 3000

# Allow SSH (if you ever enable sshd)
ufw allow 22/tcp

# Remove a rule
ufw delete allow 3000

# Check app profiles
ufw app list
```

### Persistence

ufw rules persist across reboots automatically. The service is enabled via systemd.

---

## 3. AppArmor (Mandatory Access Control)

The WSL2 kernel ships with AppArmor compiled in but disabled. It must be enabled via kernel boot parameters.

### Install packages

```bash
apt install -y apparmor apparmor-utils apparmor-profiles apparmor-profiles-extra
apt install -y ubuntu-advantage-tools   # provides AppArmor profiles for ubuntu_pro_apt_news and ubuntu_pro_esm_cache
systemctl enable apparmor.service
```

> **Note:** Without `ubuntu-advantage-tools`, Ubuntu Pro background processes (`apt_news`, `esm_cache`) will trigger AppArmor DENIED errors in syslog because their profiles are missing. These are harmless but noisy — installing the package adds the missing profiles and silences the warnings.

### Enable via kernel boot parameter

Create or edit `C:\Users\<USERNAME>\.wslconfig` on the **Windows side**:

```ini
[wsl2]
kernelCommandLine = apparmor=1 security=apparmor
```

From within WSL, you can write this file directly:

```bash
cat > /mnt/c/Users/$(ls /mnt/c/Users/ | grep -v -E "Public|Default|desktop.ini|All Users|Default User")/.wslconfig << 'EOF'
[wsl2]
kernelCommandLine = apparmor=1 security=apparmor
EOF
```

> **Note:** `.wslconfig` is per-Windows-user and applies to ALL WSL2 distros on that machine.

### Load profiles on boot

Edit `/etc/wsl.conf` inside the WSL instance:

```ini
[boot]
systemd=true
command="apparmor_parser -r /etc/apparmor.d/ 2>/dev/null || true"
```

### Activate

From PowerShell on Windows:

```powershell
wsl --shutdown
```

Reopen the WSL terminal.

### Verify

```bash
# Should print "Y"
cat /sys/module/apparmor/parameters/enabled

# Should list loaded profiles
aa-status

# Should include "apparmor"
cat /sys/kernel/security/lsm
```

### Enforce all profiles

```bash
aa-enforce /etc/apparmor.d/*
```

### Useful commands

```bash
aa-status                    # list profiles and their enforcement mode
aa-complain /etc/apparmor.d/<profile>  # switch a profile to log-only
aa-enforce /etc/apparmor.d/<profile>   # switch a profile to enforcing
aa-logprof                   # interactive tool to review denials and update profiles
```

---

## 4. Process Accounting (acct)

Records every process executed on the system at the kernel level. This is the WSL2 alternative to `auditd` (which cannot run on WSL2 — see Limitations).

### Install and enable

```bash
apt install -y acct
accton on
systemctl enable acct.service
```

### Verify

```bash
# Show recent commands by all users
lastcomm --forwards | tail -20
```

### Log location

```
/var/log/account/pacct
```

### Useful commands

```bash
lastcomm              # show recent commands with user, TTY, timestamps
lastcomm --user root  # filter by user
sa -u                 # per-user summary
sa -m                 # summary by command name
ac -p                 # connect time per user
```

---

## 5. Shell Command Logging (PROMPT_COMMAND)

Logs every interactive bash command to syslog with the user, TTY, working directory, and full command text.

### Create the logger script

```bash
cat > /etc/profile.d/cmd-logger.sh << 'SCRIPT'
# Log all interactive bash commands to syslog for audit trail
# Commands are logged with the user, TTY, PWD, and the command itself
if [ -n "$BASH_VERSION" ] && [[ $- == *i* ]]; then
    _CMD_LOG_LAST=""
    PROMPT_COMMAND='_cmd="$(history 1 | sed "s/^[ ]*[0-9]*[ ]*//")"
        if [ "$_cmd" != "$_CMD_LOG_LAST" ] && [ -n "$_cmd" ]; then
            logger -p local6.info -t "cmd-audit" "user=$USER tty=$(tty) pwd=$PWD cmd=$_cmd"
            _CMD_LOG_LAST="$_cmd"
        fi'
fi
SCRIPT
```

### Route logs to a dedicated file

```bash
cat > /etc/rsyslog.d/30-cmd-audit.conf << 'EOF'
# Route command audit logs to dedicated file
local6.*    /var/log/cmd-audit.log
EOF

systemctl restart rsyslog
```

### Add log rotation

```bash
cat > /etc/logrotate.d/cmd-audit << 'EOF'
/var/log/cmd-audit.log {
    weekly
    rotate 4
    compress
    delaycompress
    missingok
    notifempty
    postrotate
        /usr/lib/rsyslog/rsyslog-rotate
    endscript
}
EOF
```

### Verify

```bash
# Test manually
logger -p local6.info -t "cmd-audit" "user=root tty=/dev/pts/0 pwd=/root cmd=INSTALL_TEST"
cat /var/log/cmd-audit.log
```

### Log location

```
/var/log/cmd-audit.log
```

> **Note:** This only activates for new shell sessions. Existing sessions need
> `source /etc/profile.d/cmd-logger.sh` to start logging.

---

## 6. Unattended Security Updates

Ubuntu 24.04 ships with `unattended-upgrades` installed and enabled by default. Verify it is active and optionally tighten the configuration.

### Verify current config

```bash
cat /etc/apt/apt.conf.d/20auto-upgrades
```

Expected:

```
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
```

### If not installed

```bash
apt install -y unattended-upgrades
dpkg-reconfigure -plow unattended-upgrades
```

### Optional: auto-remove unused dependencies

Edit `/etc/apt/apt.conf.d/50unattended-upgrades` and uncomment:

```
Unattended-Upgrade::Remove-Unused-Dependencies "true";
```

### Verify it runs

```bash
systemctl status unattended-upgrades
cat /var/log/unattended-upgrades/unattended-upgrades.log
```

---

## 7. User Account Hardening

Running everything as root is the single biggest risk on any Linux system. An attacker who compromises a non-root process gets limited access; an attacker who compromises root owns everything.

### Create a non-root user for daily use

```bash
# Create user with home directory and bash shell
useradd -m -s /bin/bash <username>
passwd <username>

# Add to sudo group
usermod -aG sudo <username>
```

Set as the default WSL user in `/etc/wsl.conf`:

```ini
[user]
default=<username>
```

### Restrict sudo access

Edit `/etc/sudoers` via `visudo` (never edit directly):

```bash
visudo
```

Ensure only the `sudo` group has access:

```
# Allow members of group sudo to execute any command
%sudo   ALL=(ALL:ALL) ALL

# Remove any NOPASSWD entries unless absolutely required
# NOPASSWD lets any process running as that user sudo without interaction
```

### Password policy

```bash
apt install -y libpam-pwquality

# Configure password complexity
cat > /etc/security/pwquality.conf << 'EOF'
minlen = 12
minclass = 3
maxrepeat = 3
reject_username = true
enforce_for_root = true
EOF
```

### Account lockout after failed attempts

```bash
apt install -y libpam-faillock
```

Edit `/etc/security/faillock.conf`:

```ini
deny = 5
unlock_time = 900
fail_interval = 900
```

This locks an account for 15 minutes after 5 failed login attempts within 15 minutes.

### Useful commands

```bash
faillock --user <username>    # check lockout status
faillock --user <username> --reset  # manually unlock
passwd -S <username>          # check password status (locked, expired, etc.)
chage -l <username>           # check password aging
```

---

## 8. SSH Hardening

If you ever enable `sshd` (even for local access from Windows), lock it down immediately. An open SSH with password auth is the #1 way Linux systems get compromised.

### Install and enable

```bash
apt install -y openssh-server
systemctl enable ssh
```

### Harden the config

Edit `/etc/ssh/sshd_config`:

```bash
cat > /etc/ssh/sshd_config.d/hardening.conf << 'EOF'
# Authentication
PermitRootLogin no
PasswordAuthentication no
PubkeyAuthentication yes
AuthenticationMethods publickey
MaxAuthTries 3
MaxSessions 3

# Disable unused auth methods
KbdInteractiveAuthentication no
ChallengeResponseAuthentication no
UsePAM yes

# Disable forwarding (unless you need it)
X11Forwarding no
AllowTcpForwarding no
AllowAgentForwarding no

# Session timeout (5 min idle)
ClientAliveInterval 300
ClientAliveCountMax 2

# Restrict to specific users (optional)
# AllowUsers <username>

# Logging
LogLevel VERBOSE
EOF

systemctl restart ssh
```

### Set up key-only auth

```bash
# On the client (Windows PowerShell or another machine):
ssh-keygen -t ed25519 -C "wsl2-access"

# Copy the public key to WSL:
# From Windows, if WSL is local:
cat ~/.ssh/id_ed25519.pub | wsl -u <username> sh -c 'mkdir -p ~/.ssh && chmod 700 ~/.ssh && cat >> ~/.ssh/authorized_keys && chmod 600 ~/.ssh/authorized_keys'
```

### Install fail2ban for brute force protection

```bash
apt install -y fail2ban

cat > /etc/fail2ban/jail.local << 'EOF'
[sshd]
enabled = true
port = 22
filter = sshd
maxretry = 3
bantime = 3600
findtime = 600
EOF

systemctl enable fail2ban
systemctl start fail2ban
```

### Verify

```bash
sshd -t                       # test config for errors
ss -tlnp | grep 22            # confirm listening
fail2ban-client status sshd   # check ban status
```

---

## 9. Kernel and Network Hardening (sysctl)

The WSL2 kernel shares with Windows, so not all sysctls work. The ones below have been tested on WSL2 kernel 6.6.x.

### Apply hardening sysctls

```bash
cat > /etc/sysctl.d/99-hardening.conf << 'EOF'
# --- Memory ---
kernel.randomize_va_space = 2              # full ASLR
fs.suid_dumpable = 0                       # no core dumps from SUID binaries

# --- Kernel info leaks ---
kernel.kptr_restrict = 2                   # hide kernel pointers from non-root
kernel.dmesg_restrict = 1                  # non-root can't read dmesg

# --- Network: IP spoofing ---
net.ipv4.conf.all.rp_filter = 1            # strict reverse path filtering
net.ipv4.conf.default.rp_filter = 1

# --- Network: ICMP ---
net.ipv4.icmp_echo_ignore_broadcasts = 1   # ignore broadcast pings (smurf attack)
net.ipv4.icmp_ignore_bogus_error_responses = 1

# --- Network: redirects (MITM prevention) ---
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0

# --- Network: SYN flood protection ---
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_max_syn_backlog = 2048
net.ipv4.tcp_synack_retries = 2

# --- Network: logging ---
net.ipv4.conf.all.log_martians = 1         # log packets with impossible addresses
net.ipv4.conf.default.log_martians = 1

# --- Network: source routing (disable) ---
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv6.conf.all.accept_source_route = 0
net.ipv6.conf.default.accept_source_route = 0
EOF

sysctl --system
```

### Restrict outbound traffic

The default `ufw allow outgoing` lets any process reach any external host. Tighten this if your WSL instance doesn't need wide outbound access:

```bash
# Switch to deny-by-default outbound
ufw default deny outgoing

# Allow only what's needed
ufw allow out 53        # DNS
ufw allow out 80/tcp    # HTTP
ufw allow out 443/tcp   # HTTPS
ufw allow out 22/tcp    # SSH (git, scp)
ufw allow out 123/udp   # NTP (time sync)

# If you need Docker Hub, npm, apt, etc. — these all use 443
# If you need SMTP: ufw allow out 587/tcp
```

> **Warning:** Restricting outbound will break anything that uses non-standard ports (database connections on 5432/3306, Redis on 6379, etc.). Only do this if you understand your outbound traffic patterns. For most dev environments, `allow outgoing` with Pi-hole DNS filtering is a better balance.

### Verify

```bash
sysctl -a | grep rp_filter
sysctl kernel.kptr_restrict
sysctl kernel.dmesg_restrict
ufw status verbose
```

> **Note:** Some sysctls may return `permission denied` or have no effect on WSL2 because the kernel is shared with Windows. If `sysctl --system` prints errors for specific keys, comment them out — they're not supported on your kernel version.

---

## 10. File Integrity Monitoring

Detects unauthorized changes to system binaries, config files, and libraries. If an attacker modifies `/usr/bin/sudo` or `/etc/pam.d/`, you want to know.

### AIDE (Advanced Intrusion Detection Environment)

```bash
apt install -y aide

# Initialize the database (takes a few minutes — checksums every monitored file)
aideinit
cp /var/lib/aide/aide.db.new /var/lib/aide/aide.db
```

### Run a check

```bash
aide --check
```

This compares current file state against the stored database. Any changes (modified, added, removed) are reported.

### Automate daily checks

```bash
cat > /etc/cron.daily/aide-check << 'SCRIPT'
#!/bin/bash
aide --check 2>&1 | mail -s "AIDE report $(hostname) $(date +%F)" root || \
aide --check >> /var/log/aide-check.log 2>&1
SCRIPT
chmod +x /etc/cron.daily/aide-check
```

If `mail` isn't configured, results go to `/var/log/aide-check.log`.

### Update the database after legitimate changes

After installing packages or making intentional config changes:

```bash
aide --update
cp /var/lib/aide/aide.db.new /var/lib/aide/aide.db
```

### Quick check with debsums

Verify installed packages haven't been tampered with:

```bash
apt install -y debsums

# Check all packages — only shows modified files
debsums --changed 2>/dev/null
```

If this reports changes to binaries in `/usr/bin/` or `/usr/sbin/` that you didn't make, investigate immediately.

### Log location

```
/var/log/aide-check.log     # daily AIDE reports (if configured)
/var/lib/aide/aide.db       # baseline database
```

---

## 11. Secrets and Credential Protection

Protect private keys, API tokens, `.env.keys`, and other credentials stored on the WSL2 filesystem.

### File permissions

```bash
# SSH keys — owner read-only
chmod 700 ~/.ssh
chmod 600 ~/.ssh/id_*
chmod 644 ~/.ssh/id_*.pub
chmod 600 ~/.ssh/authorized_keys

# Any .env.keys or credential files
chmod 600 ~/.env.keys
chmod 600 ~/projects/*/.env.keys

# GPG keys
chmod 700 ~/.gnupg
chmod 600 ~/.gnupg/private-keys-v1.d/*
```

### Prevent credentials from leaking into shell history

```bash
cat >> /etc/profile.d/history-hardening.sh << 'EOF'
# Don't log commands that start with a space (allows hiding sensitive one-liners)
HISTCONTROL=ignorespace:ignoredups:erasedups

# Don't log common secret-handling commands
HISTIGNORE="export *KEY*:export *SECRET*:export *TOKEN*:export *PASSWORD*:*dotenvx*private*"

# Set history file permissions
umask 077
EOF
```

### Credential storage options

| Tool | Use case | Notes |
|------|----------|-------|
| `pass` (password-store) | GPG-encrypted file-based password manager | Works well in WSL2, git-backed |
| `git-credential-store` | Git HTTPS credentials | Stores plaintext in `~/.git-credentials` — use `git-credential-cache` instead (in-memory, time-limited) |
| Windows Credential Manager | Cross-WSL/Windows credential sharing | Use `git-credential-manager` from Windows side |

```bash
# Use in-memory git credential cache (15 min default)
git config --global credential.helper 'cache --timeout=900'

# Or use pass for a more secure GPG-backed store
apt install -y pass
gpg --gen-key
pass init <gpg-key-id>
pass insert project/api-key
```

### Scan for accidentally committed secrets

```bash
# Quick grep for common patterns in a repo
grep -rn --include="*.env" --include="*.json" --include="*.yml" \
  -E '(api_key|secret|password|token|private_key)\s*[:=]' . 2>/dev/null

# For a more thorough scan, use gitleaks (if installed)
# gitleaks detect --source .
```

---

## 12. Container / Docker Hardening

Docker is commonly installed in WSL2. The Docker socket grants root-equivalent access to anyone who can reach it.

### Docker socket permissions

```bash
# Check who can access the Docker socket
ls -la /var/run/docker.sock
# Default: srw-rw---- root docker

# Only add users to the docker group who genuinely need it
# Being in the docker group = root access to the host
```

### Restrict Docker capabilities

When running containers, drop unnecessary capabilities:

```bash
# Run with minimal privileges
docker run --rm \
  --security-opt no-new-privileges \
  --cap-drop ALL \
  --cap-add NET_BIND_SERVICE \
  --read-only \
  <image>

# Never run with --privileged unless absolutely necessary
```

### Docker daemon hardening

```bash
mkdir -p /etc/docker
cat > /etc/docker/daemon.json << 'EOF'
{
  "no-new-privileges": true,
  "live-restore": true,
  "userns-remap": "default",
  "log-driver": "json-file",
  "log-opts": {
    "max-size": "10m",
    "max-file": "3"
  }
}
EOF

systemctl restart docker
```

Key settings:

| Setting | What it does |
|---------|-------------|
| `no-new-privileges` | Prevents processes in containers from gaining additional privileges via SUID/SGID |
| `userns-remap` | Maps container root to a non-root user on the host |
| `live-restore` | Keeps containers running during daemon restarts |
| `log-opts` | Prevents container logs from filling disk |

### Scan images for vulnerabilities

```bash
# Docker Scout (built into Docker Desktop)
docker scout cves <image>

# Or use Trivy (standalone, open source)
# apt install -y trivy
# trivy image <image>
```

### Audit Docker usage

```bash
# List all running containers
docker ps

# Check what's listening
docker ps --format '{{.Names}}: {{.Ports}}'

# Review container capabilities
docker inspect --format '{{.HostConfig.CapAdd}}' <container>
```

---

## 13. Cron and Systemd Timer Auditing

Cron jobs and systemd timers are common persistence mechanisms for attackers. Lock them down and monitor them.

### Restrict who can create cron jobs

```bash
# Only allow specific users to use cron
echo root > /etc/cron.allow
echo <username> >> /etc/cron.allow

# If cron.allow exists, only listed users can use crontab
# Everyone else is denied (cron.deny is ignored when cron.allow exists)
```

### Lock down cron directories

```bash
chmod 700 /etc/cron.d
chmod 700 /etc/cron.daily
chmod 700 /etc/cron.hourly
chmod 700 /etc/cron.weekly
chmod 700 /etc/cron.monthly
chmod 600 /etc/crontab
```

### Audit existing cron jobs and timers

```bash
# List all user crontabs
for user in $(cut -f1 -d: /etc/passwd); do
  crontab -l -u "$user" 2>/dev/null | grep -v '^#' | grep -v '^$' && echo "  ↑ $user"
done

# List system cron
ls -la /etc/cron.d/
cat /etc/crontab

# List all systemd timers
systemctl list-timers --all

# Check for unexpected .timer units
find /etc/systemd /usr/lib/systemd /run/systemd -name "*.timer" 2>/dev/null
```

### Monitor for new cron entries

Add to the security monitoring script or run periodically:

```bash
# Snapshot current cron state
find /etc/cron* /var/spool/cron -type f -exec md5sum {} \; > /var/log/cron-baseline.md5

# Compare against baseline
md5sum --check /var/log/cron-baseline.md5 --quiet 2>/dev/null || echo "ALERT: cron files changed"
```

---

## 14. Backup and Recovery

If the WSL2 instance is compromised, you need a clean recovery path.

### Export WSL2 instance (full backup)

From **PowerShell** on Windows:

```powershell
# Create a full backup (tar archive of the entire filesystem)
wsl --export Ubuntu "D:\Backups\wsl2-ubuntu-$(Get-Date -Format yyyy-MM-dd).tar"

# Restore from backup
wsl --import Ubuntu-Restored "D:\WSL\Ubuntu-Restored" "D:\Backups\wsl2-ubuntu-2026-03-08.tar"
```

### Automate weekly backups

Create a Windows scheduled task or PowerShell script:

```powershell
# backup-wsl.ps1
$date = Get-Date -Format "yyyy-MM-dd"
$backupDir = "D:\Backups\WSL2"
if (!(Test-Path $backupDir)) { New-Item -ItemType Directory -Path $backupDir }

# Keep last 4 backups
Get-ChildItem "$backupDir\wsl2-ubuntu-*.tar" | Sort-Object LastWriteTime -Descending | Select-Object -Skip 4 | Remove-Item

wsl --export Ubuntu "$backupDir\wsl2-ubuntu-$date.tar"
Write-Host "WSL2 backup complete: $backupDir\wsl2-ubuntu-$date.tar"
```

### Recovery procedure if compromised

1. **Stop the instance immediately**: `wsl --shutdown` from PowerShell
2. **Do NOT restart it** — the attacker may have persistence (cron, systemd, bashrc)
3. **Export the compromised instance for forensics**: `wsl --export Ubuntu D:\forensics\compromised.tar`
4. **Restore from last known-good backup**: `wsl --import Ubuntu C:\WSL\Ubuntu D:\Backups\wsl2-ubuntu-<date>.tar`
5. **Rotate all credentials** — SSH keys, API tokens, `.env.keys`, git credentials, anything the compromised instance had access to
6. **Review logs from the compromised export** — mount the tar and check `/var/log/cmd-audit.log`, `/var/log/auth.log`, and cron entries for indicators of compromise

### Critical files to back up separately

Beyond the full WSL export, keep copies of these outside WSL:

```bash
# From within WSL, copy critical configs to Windows
cp /etc/wsl.conf /mnt/c/Users/<username>/wsl-backup/
cp /etc/pihole/pihole.toml /mnt/c/Users/<username>/wsl-backup/
cp /etc/ufw/user.rules /mnt/c/Users/<username>/wsl-backup/

# SSH keys (if not already backed up elsewhere)
cp -r ~/.ssh /mnt/c/Users/<username>/wsl-backup/ssh-keys/
chmod 600 /mnt/c/Users/<username>/wsl-backup/ssh-keys/*
```

---

## 15. Lynis (Security Auditing)

Lynis is a security auditing tool that scans your system and produces a hardening index (0-100) with specific recommendations. It checks file permissions, kernel parameters, authentication settings, network configuration, installed software, and more. Think of it as a security report card.

### Install

```bash
apt install -y lynis
```

### Run a full audit

```bash
lynis audit system
```

The audit takes 1-2 minutes and produces a report with:
- **Hardening index** — a score from 0 to 100
- **Warnings** — issues that need immediate attention
- **Suggestions** — improvements ranked by severity
- **Tests performed** — every check that was run

### Automate weekly audits

```bash
# Lynis installs a systemd timer by default
systemctl enable lynis.timer
systemctl start lynis.timer

# Check when it's scheduled
systemctl list-timers | grep lynis
```

Or run manually via cron with report logging:

```bash
echo '0 3 * * 0 root lynis audit system --quiet --logfile /var/log/lynis-report.log' > /etc/cron.d/lynis-weekly
```

### Review results

```bash
# View the last report
cat /var/log/lynis.log

# View just warnings and suggestions
grep -E "warning|suggestion" /var/log/lynis-report.dat

# Compare hardening index over time
grep "hardening_index" /var/log/lynis-report.dat
```

### Log locations

```
/var/log/lynis.log              # detailed audit log
/var/log/lynis-report.dat       # machine-readable report data
```

---

## 16. Rootkit Detection (rkhunter / chkrootkit)

Two complementary tools that scan for known rootkits, backdoors, and suspicious binaries. Running both gives a second opinion — they use different detection methods.

### Install

```bash
apt install -y rkhunter chkrootkit
```

### Fix rkhunter default config

The default Ubuntu config has a broken `WEB_CMD` setting:

```bash
sed -i 's|WEB_CMD="/bin/false"|WEB_CMD=""|' /etc/rkhunter.conf
```

### Initialize rkhunter baseline

```bash
# Create a baseline of current file properties (run after a clean install)
rkhunter --propupd
```

### Run scans

```bash
# rkhunter — full scan (non-interactive)
rkhunter --check --skip-keypress

# chkrootkit — quick scan
chkrootkit
```

### What they check

| Check | rkhunter | chkrootkit |
|-------|----------|------------|
| Known rootkits (signatures) | Yes (370+) | Yes (70+) |
| Modified system binaries | Yes | Yes |
| Hidden files/processes | Yes | Yes (unhide) |
| Network interfaces in promiscuous mode | Yes | Yes |
| Suspicious kernel modules | Yes | No |
| Suspicious startup files | Yes | No |
| File property changes (permissions, size) | Yes | No |

### Automate daily scans

chkrootkit installs a systemd timer automatically. For rkhunter:

```bash
# Enable daily rkhunter check via cron
echo 'CRON_DAILY_RUN="true"' >> /etc/default/rkhunter
```

### Update rkhunter signatures after system changes

After installing or updating packages, update the baseline so rkhunter doesn't flag legitimate changes:

```bash
rkhunter --propupd
```

### Log locations

```
/var/log/rkhunter.log           # rkhunter scan results
/var/log/chkrootkit/log.today   # chkrootkit daily results (if timer enabled)
```

---

## 17. CrowdSec (Intrusion Prevention)

CrowdSec is a modern, community-powered intrusion prevention system. It parses logs, detects attacks (brute force, port scanning, etc.), and blocks offending IPs. Unlike fail2ban, it shares threat intelligence across all CrowdSec users — if an IP is attacking someone else, it gets preemptively blocked on your machine.

### Install

```bash
# Add the CrowdSec repository
curl -s https://install.crowdsec.net | bash

# Install CrowdSec + firewall bouncer (auto-blocks via iptables)
apt install -y crowdsec crowdsec-firewall-bouncer-iptables
```

### How it works

```
Log sources (auth.log, syslog, etc.)
    ↓
CrowdSec agent (parses logs, detects patterns)
    ↓
Local API (stores decisions: "ban IP X for Y minutes")
    ↓
Firewall bouncer (applies bans to iptables)
    ↓
Community API (shares/receives threat intelligence)
```

### Auto-configured log sources

CrowdSec auto-detects installed services during setup. On this system it monitors:

| Source | What it detects |
|--------|----------------|
| SSH (auth.log) | Brute force, slow brute force, CVE-2024-6387, refused connections |
| Linux (syslog) | General system attack patterns |
| Postfix (mail.log) | Spam, relay abuse, HELO rejected |
| Audit | Post-exploitation (rm, pkill, exec from network, SUID crash) |

### Useful commands

```bash
# View active decisions (banned IPs)
cscli decisions list

# View alerts (detected attacks)
cscli alerts list

# View metrics (parsed lines, active scenarios)
cscli metrics

# View installed collections (detection rules)
cscli collections list

# Manually ban an IP
cscli decisions add --ip 1.2.3.4 --duration 24h --reason "manual ban"

# Unban an IP
cscli decisions delete --ip 1.2.3.4

# View bouncer status
cscli bouncers list

# Update threat intelligence and hub content
cscli hub update
cscli hub upgrade
```

### Add more detection scenarios

```bash
# Browse available collections
cscli collections list -a

# Install additional collections (example: nginx, if you run it)
cscli collections install crowdsecurity/nginx

# Install community blocklists
cscli console enroll <your-key>   # register at https://app.crowdsec.net
```

### Configuration files

```
/etc/crowdsec/config.yaml                    # main config
/etc/crowdsec/acquis.d/                      # log source configurations
/etc/crowdsec/scenarios/                     # detection rules
/etc/crowdsec/parsers/                       # log parsers
/etc/crowdsec/local_api_credentials.yaml     # local API auth
/var/log/crowdsec.log                        # CrowdSec agent log
/var/log/crowdsec_api.log                    # local API log
```

### Verify

```bash
systemctl is-active crowdsec
systemctl is-active crowdsec-firewall-bouncer
cscli metrics
```

---

## 18. Falco (Runtime Threat Detection)

Falco monitors every syscall (system call) in real-time using eBPF and alerts when something suspicious happens. Unlike log-based tools that detect attacks after the fact, Falco catches them as they happen — including activity inside Docker containers.

### Install

```bash
# Add Falco repository
curl -s https://falco.org/repo/falcosecurity-packages.asc | gpg --dearmor -o /etc/apt/trusted.gpg.d/falco.gpg
echo "deb https://download.falco.org/packages/deb stable main" | tee /etc/apt/sources.list.d/falcosecurity.list
apt update

# Install with modern eBPF driver (no kernel headers needed)
FALCO_DRIVER_CHOICE=modern_ebpf apt install -y falco
```

During installation, choose `Yes` for automatic ruleset updates and select the `modern_ebpf` driver.

### How it works

```
Any process does anything (open file, network connect, exec, etc.)
    ↓
Kernel syscall
    ↓
Falco eBPF probe (hooks into kernel, zero overhead when no match)
    ↓
Rule engine (matches against ~100 default rules)
    ↓
Alert (syslog, stdout, file, webhook, gRPC)
```

### What it detects (default rules)

| Category | Example rules |
|----------|--------------|
| **Container escape** | Shell spawned in container, write below /etc in container |
| **Privilege escalation** | Non-sudo setuid, unexpected privilege gain |
| **Sensitive file access** | Read of /etc/shadow, /etc/passwd, SSH keys |
| **Suspicious processes** | Known mining binaries, shells from unexpected parents |
| **Network** | Unexpected outbound connections, port scanning |
| **Persistence** | Modified system binaries, new cron entries, systemd unit changes |
| **Data exfiltration** | Bulk data reads, base64 encoding of files |

### Useful commands

```bash
# Check if Falco is running
systemctl status falco-modern-bpf

# View Falco alerts live
journalctl -u falco-modern-bpf -f

# Test Falco detection (triggers "Read sensitive file" alert)
cat /etc/shadow > /dev/null

# Check Falco alerts in the log
journalctl -u falco-modern-bpf --since "1 hour ago" --no-pager

# List loaded rules
falco --list

# Validate rule syntax
falco --validate /etc/falco/falco_rules.yaml
```

### Custom rules

Add custom rules in `/etc/falco/falco_rules.local.yaml` (never edit the default rules file — it gets overwritten on updates):

```yaml
# Example: alert when anyone runs docker exec
- rule: Docker Exec Detected
  desc: Detect docker exec into a running container
  condition: >
    spawned_process and container and
    proc.pname = "runc:[2:INIT]"
  output: >
    Docker exec detected (user=%user.name container=%container.name
    command=%proc.cmdline)
  priority: NOTICE
  tags: [container, docker]
```

```bash
# Reload rules after editing
systemctl restart falco-modern-bpf
```

### Configuration

```
/etc/falco/falco.yaml                # main config (output destinations, log level)
/etc/falco/falco_rules.yaml          # default rules (auto-updated, don't edit)
/etc/falco/falco_rules.local.yaml    # custom rules (your overrides go here)
/etc/falco/config.d/                 # additional config fragments
```

### WSL2 notes

Falco uses the modern eBPF driver on WSL2, which works with the Microsoft-managed kernel (6.6.x). If Falco fails to start, check:

```bash
# Verify eBPF support
journalctl -u falco-modern-bpf | grep -i error
ls /sys/kernel/btf/vmlinux   # must exist for CO-RE eBPF
```

---

## 19. Trivy (Container Vulnerability Scanning)

Trivy scans Docker images, filesystems, and git repos for known vulnerabilities (CVEs), misconfigurations, and embedded secrets. If you're running Docker containers, this tells you which ones have known security holes.

### Install

```bash
curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin
```

### Scan Docker images

```bash
# Scan an image for CVEs
trivy image postgres:latest

# Scan with only HIGH and CRITICAL severity
trivy image --severity HIGH,CRITICAL postgres:latest

# Scan all running container images
docker ps --format '{{.Image}}' | sort -u | while read img; do
  echo "=== Scanning: $img ==="
  trivy image --severity HIGH,CRITICAL "$img"
done
```

### Scan the local filesystem

```bash
# Scan current directory for vulnerabilities and secrets
trivy fs .

# Scan for embedded secrets (API keys, passwords)
trivy fs --scanners secret /root/projects/
```

### Scan a git repo

```bash
trivy repo https://github.com/Cklaus1/security
```

### Output formats

```bash
# JSON output (for processing)
trivy image --format json -o results.json postgres:latest

# Table output (default, human-readable)
trivy image --format table postgres:latest

# SARIF output (for GitHub Security tab integration)
trivy image --format sarif -o results.sarif postgres:latest
```

### Automate regular scans

```bash
# Weekly scan of all running Docker images
cat > /etc/cron.d/trivy-scan << 'EOF'
0 4 * * 0 root docker ps --format '{{.Image}}' | sort -u | xargs -I{} trivy image --severity HIGH,CRITICAL --quiet {} >> /var/log/trivy-scan.log 2>&1
EOF
```

### Update vulnerability database

Trivy auto-downloads the vulnerability database on first run. To update manually:

```bash
trivy image --download-db-only
```

### Log location

```
/var/log/trivy-scan.log         # weekly scan results (if cron configured)
```

---

## 20. Microsoft Defender for Endpoint (EDR)

Microsoft Defender for Endpoint (MDE) is the enterprise EDR (Endpoint Detection & Response) layer for WSL2. It installs on the **Windows side** as an MSI package and hooks into WSL2 to provide real-time antimalware scanning, behavioral threat detection, and centralized alerting — the main gap in the open-source-only stack.

### What it adds

The open-source tools in this guide (Falco, CrowdSec, AIDE, rkhunter) cover detection and prevention, but they all run locally with no centralized management. MDE adds:

| Capability | Open-source stack | MDE adds |
|-----------|------------------|----------|
| File scanning | AIDE (periodic), rkhunter (rootkit signatures) | Real-time antimalware with cloud-delivered protection |
| Runtime detection | Falco (syscall monitoring) | EDR behavioral detection backed by Microsoft's threat intelligence |
| Network monitoring | Pi-hole (DNS), UFW (firewall) | Network traffic analysis, C2 detection |
| Alerting | Local logs, security-monitor.sh | Centralized portal with cross-machine correlation |
| Response | Manual investigation | Remote live response, process isolation, automated remediation |
| Threat intelligence | CrowdSec community blocklists | Microsoft's global threat intelligence feed |

### Requirements

- **Microsoft Defender for Endpoint license** — requires Microsoft 365 E5, E5 Security, or Microsoft Defender for Business. **This is not free.**
- Windows 10/11 with WSL2
- WSL updated to latest version: `wsl --update` (from PowerShell)
- Not supported on ARM64 processors

### Install (Windows side)

1. Open the [Microsoft Defender portal](https://security.microsoft.com)
2. Navigate to **Settings** → **Endpoints** → **Onboarding**
3. Select **"Windows Subsystem for Linux 2 (plug-in)"** as the deployment method
4. Download the MSI installer
5. Run the MSI on Windows (not inside WSL)

Or via **PowerShell** (elevated):

```powershell
# Download from the Defender portal first, then:
msiexec /i "path\to\wsl-mde-plugin.msi" /qn
```

### Verify

After installation, it takes a few minutes for the plugin to instantiate and up to 30 minutes for the WSL2 instance to onboard.

From **PowerShell**:

```powershell
# Check if the plugin is running
Get-Service -Name "MDE-WSL" -ErrorAction SilentlyContinue
```

From **WSL2**:

```bash
# Test EDR detection (downloads a safe EICAR test file)
# Download the test script from Microsoft:
curl -o mde_linux_edr_diy.sh https://aka.ms/MDE-Linux-EDR-DIY
chmod +x mde_linux_edr_diy.sh
./mde_linux_edr_diy.sh
```

Check the [Microsoft Defender portal](https://security.microsoft.com) → **Incidents & alerts** to confirm the test alert appears.

### Automatic updates

Version 1.24.522.2 and later supports automatic updates through Windows Update. Earlier versions require manual MSI reinstallation.

### If you don't have a license

For personal machines without E5/Business licensing, the open-source stack provides comparable coverage:

| MDE capability | Open-source equivalent |
|---------------|----------------------|
| Real-time file scanning | ClamAV (open-source antivirus, not covered in this guide) |
| Behavioral EDR | Falco (syscall monitoring via eBPF) |
| Threat intelligence | CrowdSec (community IP reputation) |
| Rootkit detection | rkhunter + chkrootkit |
| File integrity | AIDE |
| Network monitoring | Pi-hole (DNS) + UFW (firewall) |

The main gaps without MDE: no centralized alerting portal, no cross-machine correlation, and no Microsoft-backed threat intelligence. For a single developer WSL2 instance, the open-source stack is sufficient. For enterprise machines, MDE is the recommended addition.

---

## 21. ClamAV (Antivirus Scanning)

ClamAV is the standard open-source antivirus engine for Linux. It detects trojans, viruses, malware, and other threats using signature-based scanning. While Linux malware is less common than Windows malware, ClamAV catches cross-platform threats (malicious attachments, infected downloads) and satisfies compliance requirements.

### Installation

```bash
sudo apt install -y clamav clamav-daemon
```

### Initial Setup

```bash
# Stop the freshclam daemon to do an initial update
sudo systemctl stop clamav-freshclam

# Update virus definitions
sudo freshclam

# Restart the update daemon (auto-updates signatures)
sudo systemctl start clamav-freshclam
sudo systemctl enable clamav-freshclam

# Start the scanning daemon
sudo systemctl start clamav-daemon
sudo systemctl enable clamav-daemon
```

### Usage

```bash
# Scan a specific directory
clamscan -r /home

# Scan and remove infected files
clamscan -r --remove /tmp

# Scan with the daemon (faster, uses in-memory signatures)
clamdscan /home

# Full system scan (skip /proc, /sys, /dev)
clamscan -r --exclude-dir="^/proc|^/sys|^/dev|^/run" /
```

### Scheduled Scanning

```bash
# Add a daily scan via cron
cat >> /etc/cron.daily/clamav-scan << 'CRON'
#!/bin/bash
LOG=/var/log/clamav/daily-scan.log
clamscan -r --exclude-dir="^/proc|^/sys|^/dev|^/run" / -l "$LOG" 2>&1
# Alert on findings
FOUND=$(grep "Infected files:" "$LOG" | awk '{print $NF}')
if [ "$FOUND" -gt 0 ]; then
    echo "ClamAV found $FOUND infected file(s). Check $LOG" | logger -t clamav-alert
fi
CRON
chmod +x /etc/cron.daily/clamav-scan
```

### Key Files

| File | Purpose |
|------|---------|
| `/etc/clamav/clamd.conf` | Daemon configuration |
| `/etc/clamav/freshclam.conf` | Signature update configuration |
| `/var/log/clamav/freshclam.log` | Update log |
| `/var/lib/clamav/` | Virus signature database |

### Verification

```bash
# Check daemon status
systemctl status clamav-daemon

# Check signature freshness
freshclam --version
clamscan --version

# Test with EICAR test file (harmless test signature)
curl -o /tmp/eicar.com https://secure.eicar.org/eicar.com
clamscan /tmp/eicar.com   # Should detect "Win.Test.EICAR_HDB-1"
rm /tmp/eicar.com
```

---

## 22. OpenCanary (Honeypot / Deception)

OpenCanary is a lightweight honeypot daemon that creates fake services (SSH, FTP, MySQL, HTTP, Redis, Telnet, etc.) to detect unauthorized access attempts. Any connection to these decoy services is an immediate indicator of compromise — legitimate users have no reason to touch them.

### How It Works

```
Attacker scans network → finds open ports (2222, 3306, 6379...)
         ↓
Connects to fake SSH/MySQL/Redis
         ↓
OpenCanary logs: source IP, credentials tried, service targeted
         ↓
Alert: someone is probing your network
```

The key insight: **zero false positives**. Real users never connect to honeypot services, so any activity is suspicious by definition.

### Installation

```bash
# Create isolated Python environment
python3 -m venv /opt/opencanary
/opt/opencanary/bin/pip install opencanary

# Generate default config
mkdir -p /etc/opencanaryd
cp /opt/opencanary/lib/python3.*/site-packages/opencanary/data/settings.json \
   /etc/opencanaryd/opencanary.conf
```

### Configuration

Edit `/etc/opencanaryd/opencanary.conf` to enable fake services on **non-conflicting ports**:

```json
{
    "device.node_id": "wsl2-honeypot",
    "ssh.enabled": true,
    "ssh.port": 2222,
    "ssh.version": "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6",
    "ftp.enabled": true,
    "ftp.port": 2121,
    "http.enabled": true,
    "http.port": 8888,
    "http.skin": "nasLogin",
    "mysql.enabled": true,
    "mysql.port": 3306,
    "mysql.banner": "5.7.99-0ubuntu0.22.04.1",
    "redis.enabled": true,
    "redis.port": 6379,
    "telnet.enabled": true,
    "telnet.port": 2323,
    "portscan.enabled": true,
    "portscan.ignore_localhost": true,
    "logger": {
        "class": "PyLogger",
        "kwargs": {
            "handlers": {
                "file": {
                    "class": "logging.FileHandler",
                    "filename": "/var/log/opencanary.log"
                }
            }
        }
    }
}
```

> **Port selection:** Use ports that don't conflict with real services. If you run a real MySQL on 3306, move the honeypot MySQL to 13306. The goal is to present attractive-looking services an attacker would probe.

### Systemd Service

```bash
cat > /etc/systemd/system/opencanary.service << 'EOF'
[Unit]
Description=OpenCanary Honeypot
After=network.target

[Service]
Type=forking
PIDFile=/opt/opencanary/bin/opencanaryd.pid
User=root
ExecStart=/opt/opencanary/bin/opencanaryd --start
ExecStop=/opt/opencanary/bin/opencanaryd --stop
Restart=on-failure
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable opencanary
systemctl start opencanary
```

### Log Format

OpenCanary logs JSON to `/var/log/opencanary.log`. Each event includes:

```json
{
    "dst_host": "10.0.0.5",
    "dst_port": 2222,
    "logtype": 4002,
    "node_id": "wsl2-honeypot",
    "src_host": "10.0.0.99",
    "src_port": 48230,
    "logdata": {
        "USERNAME": "admin",
        "PASSWORD": "password123",
        "REMOTEVERSION": "SSH-2.0-OpenSSH_8.2"
    },
    "utc_time": "2026-03-09 05:18:31.369347"
}
```

Key log types:

| logtype | Meaning |
|---------|---------|
| 4000 | SSH session opened |
| 4002 | SSH login attempt |
| 5001 | FTP login attempt |
| 7001 | HTTP login attempt |
| 8001 | MySQL login attempt |
| 10001 | Redis command |
| 6001 | Telnet login attempt |

### Monitoring OpenCanary Alerts

```bash
# View recent honeypot triggers
cat /var/log/opencanary.log | python3 -m json.tool

# Watch for live alerts
tail -f /var/log/opencanary.log | jq '.'

# Count attacks by source IP
cat /var/log/opencanary.log | jq -r '.src_host' | sort | uniq -c | sort -rn

# Show all login attempts
cat /var/log/opencanary.log | jq 'select(.logdata.USERNAME) | {time: .utc_time, src: .src_host, user: .logdata.USERNAME, service: .dst_port}'
```

### Verification

```bash
# Check service is running
systemctl status opencanary

# Verify listening ports
ss -tlnp | grep twistd

# Test (from the same machine or another machine)
ssh -p 2222 admin@localhost        # Triggers SSH alert
curl http://localhost:8888          # Triggers HTTP alert
redis-cli -p 6379 PING             # Triggers Redis alert

# Check alerts were logged
tail -5 /var/log/opencanary.log | jq '.'
```

### Best Practices

- **Don't expose honeypot ports to the internet** unless you specifically want to collect external attack data
- **Alert on any activity** — all honeypot triggers are suspicious by definition
- **Use realistic banners** — outdated-looking SSH/MySQL versions attract attackers
- **Don't run on the same ports as real services** — honeypots complement, not replace, real services
- **Review logs daily** — honeypot alerts are high-signal and require investigation

---

## 23. Pi-hole (Network-Level Ad/Tracker Blocking)

Pi-hole acts as a DNS sinkhole, blocking ads, trackers, and malicious domains at the network level before they reach any application. It also provides a query log and web dashboard for DNS visibility.

### The WSL2 port 53 problem

WSL2 runs a **kernel-level DNS proxy** on `10.255.255.254:53` (bound to the `lo` interface). This process has no PID — it's built into the WSL init layer and cannot be stopped or disabled. It will block any attempt by Pi-hole/dnsmasq to bind port 53 on:

- `0.0.0.0` (wildcard) — fails because `10.255.255.254:53` already exists
- `10.255.255.254` — directly conflicts with the WSL proxy

The solution is to configure Pi-hole to bind **only** to specific addresses — `172.31.87.23` (eth0 dynamic), `172.31.95.250` (eth0 static), and `127.0.0.1` (loopback) — avoiding the WSL-owned address entirely. This requires using dnsmasq's `bind-interfaces` option with explicit `listen-address` directives.

A **static IP** (`172.31.95.250`) is added to eth0 at boot within the WSL2 subnet (`172.31.80.0/20`) so that Windows can route to it. This gives Windows a fixed DNS address that survives WSL restarts (the DHCP-assigned eth0 IP changes each time). The IP is chosen near the top of the subnet range to avoid DHCP conflicts.

Additionally, `systemd-resolved` runs a stub listener on `127.0.0.53:53` by default, which must also be disabled.

### Prerequisites: Configure DNS plumbing

**1. Disable the systemd-resolved stub listener and point it at Pi-hole:**

Edit `/etc/systemd/resolved.conf`:

```ini
[Resolve]
DNS=172.31.87.23
DNSStubListener=no
```

```bash
systemctl restart systemd-resolved
```

**2. Disable WSL auto-generated DNS:**

Add to `/etc/wsl.conf`:

```ini
[network]
generateResolvConf = false
```

**3. Create a static resolv.conf pointing to Pi-hole on loopback:**

```bash
rm -f /etc/resolv.conf
echo 'nameserver 127.0.0.1' > /etc/resolv.conf
chattr +i /etc/resolv.conf  # immutable flag prevents WSL from overwriting
```

> **Note:** The `chattr +i` immutable flag prevents **anything** from modifying `/etc/resolv.conf`, including `apt` and `systemd-resolved`. If you need to edit it later, remove the flag first with `chattr -i /etc/resolv.conf`, make your changes, then re-apply `chattr +i`.

> **Important:** Do NOT add a fallback like `1.1.1.1` — that would bypass Pi-hole for all queries when it's slow, defeating the purpose. If Pi-hole is down, fix Pi-hole.

### Install Pi-hole

Clone the repository and run the installer:

```bash
git clone --depth 1 https://github.com/pi-hole/pi-hole.git /opt/pi-hole
```

Create the unattended config before running the installer:

```bash
mkdir -p /etc/pihole
cat > /etc/pihole/setupVars.conf << 'EOF'
PIHOLE_INTERFACE=eth0
QUERY_LOGGING=true
INSTALL_WEB_SERVER=true
INSTALL_WEB_INTERFACE=true
LIGHTTPD_ENABLED=true
CACHE_SIZE=10000
DNS_FQDN_REQUIRED=true
DNS_BOGUS_PRIV=true
DNSMASQ_LISTENING=local
WEBPASSWORD=                  # blank for unattended install — set with 'pihole setpassword' after install
BLOCKING_ENABLED=true
PIHOLE_DNS_1=1.1.1.1
PIHOLE_DNS_2=1.0.0.1
DNSSEC=false
REV_SERVER=false
EOF
```

> **Upstream DNS options:** Replace `1.1.1.1`/`1.0.0.1` (Cloudflare) with your preferred provider:
> - Google: `8.8.8.8` / `8.8.4.4`
> - Quad9: `9.9.9.9` / `149.112.112.112`
> - OpenDNS: `208.67.222.222` / `208.67.220.220`

Run the installer:

```bash
bash /opt/pi-hole/"automated install/basic-install.sh" --unattended
```

### Post-install: Fix port 53 binding for WSL2

This is the critical step. Pi-hole v6 uses `pihole.toml` for configuration. The following settings make dnsmasq bind only to eth0 and loopback, avoiding the WSL DNS proxy on `10.255.255.254`:

```bash
# Set listening mode to NONE (disables Pi-hole's automatic dnsmasq listen config)
pihole-FTL --config dns.listeningMode NONE

# Bind to eth0
pihole-FTL --config dns.interface eth0

# Inject custom dnsmasq lines to bind only specific addresses
pihole-FTL --config misc.dnsmasq_lines '["bind-interfaces", "listen-address=172.31.87.23", "listen-address=127.0.0.1", "listen-address=172.31.95.250"]'
```

Or edit `/etc/pihole/pihole.toml` directly:

```toml
[dns]
  interface = "eth0"
  listeningMode = "NONE"

[misc]
  dnsmasq_lines = [
    "bind-interfaces",
    "listen-address=172.31.87.23",
    "listen-address=127.0.0.1",
    "listen-address=172.31.95.250"
  ]
```

Key settings explained:

| Setting | Value | Why |
|---------|-------|-----|
| `listeningMode` | `"NONE"` | Prevents Pi-hole from auto-generating dnsmasq listen directives (which would try `0.0.0.0` and fail) |
| `interface` | `"eth0"` | Tells Pi-hole which interface to use for replies |
| `bind-interfaces` | dnsmasq line | Forces dnsmasq to bind only the specified addresses instead of wildcard |
| `listen-address=172.31.87.23` | dnsmasq line | Bind to eth0's DHCP IP (changes on restart) |
| `listen-address=127.0.0.1` | dnsmasq line | Bind to loopback for local WSL queries |
| `listen-address=172.31.95.250` | dnsmasq line | Bind to static IP for Windows DNS queries |

> **Note:** The DHCP-assigned eth0 IP (`172.31.87.x`) can change on restart. Update that `listen-address` in `pihole.toml` if needed. The static IP `172.31.95.250` stays fixed as long as the WSL2 subnet doesn't change.

### Restart and verify

```bash
systemctl restart pihole-FTL
```

Check the FTL log — you should see successful bind lines with **no CRIT errors**:

```bash
grep -E 'CRIT|listening' /var/log/pihole/FTL.log | tail -5
```

Expected output:

```
INFO: listening on eth0(#2): 172.31.95.250 port 53
INFO: listening on 172.31.87.23 port 53
INFO: listening on eth0(#2): 172.31.87.23 port 53
INFO: listening on 127.0.0.1 port 53
INFO: listening on lo(#1): 127.0.0.1 port 53
```

If you see `CRIT: Error in dnsmasq configuration: failed to create listening socket for port 53: Address in use`, dnsmasq is still trying to bind an address owned by the WSL proxy. Double-check that `listeningMode = "NONE"` and the `dnsmasq_lines` are set correctly.

### Test DNS resolution and blocking

```bash
# Should resolve normally
dig @127.0.0.1 google.com +short

# Should return 0.0.0.0 (blocked)
dig @127.0.0.1 doubleclick.net +short

# Should show queries in the log
tail /var/log/pihole/pihole.log
```

### Static IP for Windows DNS

WSL2's eth0 IP changes on every restart, which makes it unusable as a stable DNS server for Windows. The fix is to assign a **static secondary IP** to eth0 at boot.

**Add to the boot command in `/etc/wsl.conf`:**

```ini
[boot]
command="apparmor_parser -r /etc/apparmor.d/ 2>/dev/null || true; ip addr add 172.31.95.250/20 dev eth0 2>/dev/null || true"
```

This adds `172.31.95.250` as a secondary IP on eth0 at boot. The `/20` mask must match the WSL2 subnet so Windows can route to it. The `2>/dev/null || true` prevents errors if the address already exists.

> **Note:** The WSL2 subnet is typically `172.31.80.0/20` but can change after a WSL reinstall or Hyper-V network reset. If Windows can no longer reach Pi-hole, check the subnet with `ip addr show eth0` and pick a new high IP within that range.

### Windows DNS configuration

On the **Windows host**, configure DNS to use Pi-hole with a fallback for when WSL isn't running:

| Setting | Value | Purpose |
|---------|-------|---------|
| Primary DNS | `172.31.95.250` | Pi-hole (via WSL2 static IP) |
| Secondary DNS | `1.1.1.1` | Cloudflare fallback when WSL is down |

**Via Windows Settings:**

Settings → Network & Internet → Wi-Fi (or Ethernet) → your connection → DNS server assignment → Edit → Manual

**Via elevated PowerShell:**

```powershell
# Replace "Wi-Fi" with your adapter name (use Get-NetAdapter to list)
Set-DnsClientServerAddress -InterfaceAlias "Wi-Fi" -ServerAddresses 172.31.95.250, 1.1.1.1
```

**Behavior:**
- WSL running → all DNS goes through Pi-hole (ad blocking, query logging, threat blocking)
- WSL not running → Windows falls back to Cloudflare `1.1.1.1`, everything works normally without blocking

### Open firewall ports

```bash
ufw allow 53 comment "Pi-hole DNS"
ufw allow 80/tcp comment "Pi-hole web UI"
ufw allow 443/tcp comment "Pi-hole web UI HTTPS"
```

### Set a web admin password

```bash
pihole setpassword
```

Leave blank to disable password (not recommended if the web UI is exposed).

### Web admin UI

Access in your browser at `https://172.31.95.250/admin` or `http://172.31.95.250/admin` (uses the static IP, so this URL never changes).

### Useful commands

```bash
pihole status              # check if running and blocking
pihole -t                  # tail the query log live
pihole -g                  # update gravity (blocklists)
pihole -up                 # update Pi-hole itself
pihole setpassword         # set/change web UI password
pihole -q example.com      # check if a domain is blocked
pihole disable 5m          # temporarily disable blocking for 5 minutes
pihole enable              # re-enable blocking
```

### Adding more blocklists

The default blocklist (StevenBlack/hosts) blocks ~77,000 domains. Add more via the web UI under **Adlists** or via the API. Then update gravity:

```bash
pihole -g
```

Current blocklists configured:

| List | Domains | Focus |
|------|---------|-------|
| [StevenBlack/hosts](https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts) | ~78k | Ads, trackers |
| [Hagezi Pro](https://raw.githubusercontent.com/hagezi/dns-blocklists/main/hosts/pro.txt) | ~370k | Ads, trackers, analytics |
| [Hagezi Threat Intelligence](https://raw.githubusercontent.com/hagezi/dns-blocklists/main/hosts/tif.txt) | ~689k | Malware, phishing, C2 |

Total: **~1,038,531 unique blocked domains**.

### Log locations

```
/var/log/pihole/FTL.log       # FTL engine log (startup, errors, gravity)
/var/log/pihole/pihole.log    # DNS query log (if queryLogging = true)
/etc/pihole/pihole.toml       # main configuration (v6)
/etc/pihole/gravity.db        # blocklist database
```

---

## 24. WSL-Specific Hardening

### Tighten Windows drive mount permissions

By default, `/mnt/c` is mounted `rwxrwxrwx` — any Linux process can read/write your entire Windows filesystem.

Edit `/etc/wsl.conf`:

```ini
[automount]
options = "metadata,umask=077"
```

After this change, only root can access `/mnt/c` contents. Adjust `umask=027` if you want group read access.

### Reduce PATH pollution

Windows PATH entries are appended to Linux PATH by default. This allows malicious Windows executables to be called from Linux.

Edit `/etc/wsl.conf`:

```ini
[interop]
enabled = true
appendWindowsPath = false
```

Set `enabled = false` if you never need to call Windows executables from Linux.

### Complete recommended /etc/wsl.conf

```ini
[boot]
systemd=true
command="apparmor_parser -r /etc/apparmor.d/ 2>/dev/null || true; ip addr add 172.31.95.250/20 dev eth0 2>/dev/null || true"

[network]
generateResolvConf = false

[user]
default=<your-username>

[automount]
options = "metadata,umask=077"

[interop]
enabled = true
appendWindowsPath = false
```

### Complete recommended C:\Users\<USERNAME>\.wslconfig

```ini
[wsl2]
kernelCommandLine = apparmor=1 security=apparmor
```

> After editing either file, run `wsl --shutdown` from PowerShell and reopen.

---

## 25. Verification Checklist

Run these after a fresh `wsl --shutdown` and reopen to confirm everything is working:

```bash
echo "=== Firewall ==="
ufw status verbose

echo "=== AppArmor ==="
cat /sys/module/apparmor/parameters/enabled
aa-status | head -5

echo "=== Process Accounting ==="
systemctl is-active acct

echo "=== Command Logging ==="
test -f /etc/profile.d/cmd-logger.sh && echo "cmd-logger: installed"
test -f /etc/rsyslog.d/30-cmd-audit.conf && echo "rsyslog route: configured"

echo "=== Unattended Upgrades ==="
systemctl is-active unattended-upgrades

echo "=== User Account ==="
whoami  # should NOT be root
sudo -l 2>/dev/null | head -3

echo "=== SSH ==="
if systemctl is-active ssh 2>/dev/null; then
  sshd -t && echo "sshd config: OK"
  grep "PermitRootLogin" /etc/ssh/sshd_config.d/*.conf 2>/dev/null
  grep "PasswordAuthentication" /etc/ssh/sshd_config.d/*.conf 2>/dev/null
  systemctl is-active fail2ban 2>/dev/null && echo "fail2ban: active"
else
  echo "sshd: not running (OK if not needed)"
fi

echo "=== Kernel Hardening ==="
sysctl kernel.randomize_va_space kernel.kptr_restrict kernel.dmesg_restrict 2>/dev/null
sysctl net.ipv4.conf.all.rp_filter 2>/dev/null

echo "=== File Integrity ==="
test -f /var/lib/aide/aide.db && echo "AIDE database: initialized" || echo "AIDE database: MISSING — run aideinit"
command -v debsums >/dev/null && echo "debsums: installed" || echo "debsums: not installed"

echo "=== Credential Permissions ==="
test -d ~/.ssh && stat -c "%a %n" ~/.ssh ~/.ssh/id_* 2>/dev/null
find ~/projects -name ".env.keys" -exec stat -c "%a %n" {} \; 2>/dev/null

echo "=== Docker ==="
if command -v docker >/dev/null 2>&1; then
  docker info --format '{{.SecurityOptions}}' 2>/dev/null
  ls -la /var/run/docker.sock
else
  echo "Docker: not installed"
fi

echo "=== Cron Access ==="
test -f /etc/cron.allow && echo "cron.allow: $(cat /etc/cron.allow)" || echo "cron.allow: NOT SET (any user can create cron jobs)"

echo "=== Lynis ==="
command -v lynis >/dev/null && lynis --version || echo "lynis: not installed"

echo "=== Rootkit Detection ==="
command -v rkhunter >/dev/null && echo "rkhunter: installed" || echo "rkhunter: not installed"
command -v chkrootkit >/dev/null && echo "chkrootkit: installed" || echo "chkrootkit: not installed"

echo "=== CrowdSec ==="
systemctl is-active crowdsec 2>/dev/null && echo "crowdsec: active" || echo "crowdsec: not running"
systemctl is-active crowdsec-firewall-bouncer 2>/dev/null && echo "bouncer: active" || echo "bouncer: not running"
cscli decisions list 2>/dev/null | head -5

echo "=== Falco ==="
systemctl is-active falco-modern-bpf 2>/dev/null && echo "falco: active (modern eBPF)" || echo "falco: not running"

echo "=== Trivy ==="
command -v trivy >/dev/null && trivy --version 2>/dev/null | head -1 || echo "trivy: not installed"

echo "=== ClamAV ==="
systemctl is-active clamav-daemon 2>/dev/null && echo "clamav-daemon: active" || echo "clamav-daemon: not running"
systemctl is-active clamav-freshclam 2>/dev/null && echo "freshclam: active" || echo "freshclam: not running"
clamscan --version 2>/dev/null | head -1

echo "=== OpenCanary ==="
systemctl is-active opencanary 2>/dev/null && echo "opencanary: active" || echo "opencanary: not running"
ss -tlnp | grep twistd 2>/dev/null | awk '{print "  listening:", $4}'

echo "=== Pi-hole ==="
pihole status 2>/dev/null || echo "Pi-hole not installed"
dig @127.0.0.1 ads.doubleclick.net +short 2>/dev/null | head -1

echo "=== Mount Permissions ==="
ls -ld /mnt/c

echo "=== Listening Ports ==="
ss -tlnp
```

---

## 26. Known WSL2 Limitations

### auditd does not work

The WSL2 kernel has `CONFIG_AUDIT=y` but Microsoft blocks the `audit_set_enabled` netlink operation. The auditd daemon starts, fails `op=set-enable`, and aborts. Setting `local_events = no` in `/etc/audit/auditd.conf` lets the daemon run but it collects nothing.

**Workaround:** Use `acct` (process accounting) and `PROMPT_COMMAND` logging as described in this guide.

### AppArmor requires kernel boot parameter

Unlike a standard Ubuntu install, WSL2 does not enable AppArmor by default. The `.wslconfig` kernel command line parameter is required.

### No systemd-journald persistent storage by default

Journal files may be corrupted on hard WSL shutdowns. Use `wsl --shutdown` for clean shutdowns. Logs written via rsyslog to `/var/log/` are more reliable.

### Some sysctl settings may not work

The WSL2 kernel is shared with Windows. Certain sysctl keys may return `permission denied` or silently have no effect. Test each one and comment out any that fail. The settings in Section 9 have been tested on kernel 6.6.x but may vary across versions.

### Time sync

`systemd-timesyncd` works in WSL2 and syncs to NTP automatically. Chrony is not needed unless you are running an NTP server.

### Docker user namespace remapping

`userns-remap` in Docker daemon config may not work correctly on all WSL2 configurations. Test after enabling and check `docker info` for warnings.

---

## 27. Log Sources Reference

Complete inventory of log sources on this WSL2 system and what to look for in each.

### Authentication & Access

| Log | Format | What to check |
|-----|--------|--------------|
| `/var/log/auth.log` | text | Failed logins (`authentication failure`), brute force patterns, unauthorized `sudo`, `su` attempts, SSH activity, PAM errors |
| `/var/log/btmp` | binary | Failed login attempts — read with `lastb` |
| `/var/log/wtmp` | binary | Login/logout sessions — read with `last` |
| `/var/log/lastlog` | binary | Last login time per user — read with `lastlog` |
| `/var/log/faillog` | binary | Failed login counters — read with `faillog` |

**Suspicious indicators:** logins at unusual hours, sudo from unexpected users, repeated auth failures from the same source, `su` to root from non-admin accounts.

### Command Auditing

| Log | Format | What to check |
|-----|--------|--------------|
| `/var/log/cmd-audit.log` | text | Every interactive shell command via PROMPT_COMMAND logger |
| `/var/log/account/pacct` | binary | Kernel-level process accounting — every binary executed. Read with `lastcomm` / `sa` |

**Suspicious indicators:**
- Reconnaissance: `whoami`, `id`, `uname -a`, `cat /etc/passwd`, `cat /etc/shadow`, `ifconfig`/`ip addr`, `netstat`/`ss`, `ps aux`, `env`, `find / -perm -4000` (SUID hunting)
- Data exfiltration: `curl`, `wget`, `scp`, `rsync`, `nc`/`ncat` to external IPs, base64 encoding of files
- Persistence: `crontab -e`, `systemctl enable`, writing to `/etc/profile.d/`, modifying `.bashrc`, creating systemd units
- Privilege escalation: `chmod +s`, `chown root`, writing to `/etc/sudoers`
- Defense evasion: `history -c`, `unset HISTFILE`, deleting logs, stopping services (`systemctl stop`)

### System & Kernel

| Log | Format | What to check |
|-----|--------|--------------|
| `/var/log/syslog` | text | Catch-all — service crashes, cron runs, UFW blocks, AppArmor denials, unexpected restarts |
| `/var/log/kern.log` | text | Kernel messages — segfaults, OOM kills, module loading, capability errors |
| `/var/log/dmesg` | text | Boot-time kernel ring buffer (also: `dmesg -T` for timestamped output) |

**Suspicious indicators:** unexpected kernel module loads, repeated segfaults in the same binary (exploitation attempts), OOM kills on processes that shouldn't use much memory.

### Mandatory Access Control (AppArmor)

| Log | Format | What to check |
|-----|--------|--------------|
| `/var/log/apparmor/` | text | Profile load/reload events |
| `grep 'apparmor.*DENIED' /var/log/syslog` | text | Policy violations — processes accessing files or capabilities they shouldn't |

**Suspicious indicators:** DENIED entries for unexpected binaries, repeated denials suggesting an attacker probing boundaries, denials on `/etc/shadow`, `/etc/passwd`, or credential files.

### Firewall (UFW)

| Log | Format | What to check |
|-----|--------|--------------|
| `grep 'UFW BLOCK' /var/log/syslog` | text | Blocked inbound/outbound connections |
| `grep 'UFW ALLOW' /var/log/syslog` | text | Allowed connections (audit trail) |

**Suspicious indicators:** port scans (many blocked connections from one source to sequential ports), outbound blocks to unusual ports (C2 channels), blocked connections to internal services.

### DNS / Pi-hole

| Log | Format | What to check |
|-----|--------|--------------|
| `/var/log/pihole/pihole.log` | text | Every DNS query and response |
| `/var/log/pihole/FTL.log` | text | Pi-hole engine health — startup errors, database issues, gravity failures |
| `/var/log/pihole/webserver.log` | text | Web admin UI access — unauthorized access attempts |

**Suspicious indicators:**
- C2 beaconing: repeated queries to the same unusual domain at regular intervals
- DGA (Domain Generation Algorithm): queries to random-looking domains (`xkr7d2.com`, `a8f3k2.net`)
- DNS tunneling: very long subdomain labels (data encoded in DNS queries)
- High query volume from a single client
- Queries to known-bad TLDs (`.tk`, `.top`, `.xyz` — in unusual volume)
- Blocked queries that keep retrying aggressively

### Package Management

| Log | Format | What to check |
|-----|--------|--------------|
| `/var/log/apt/history.log` | text | Package installs, removes, upgrades with timestamps |
| `/var/log/apt/term.log` | text | Full terminal output of apt operations |
| `/var/log/dpkg.log` | text | Low-level package state changes |
| `/var/log/unattended-upgrades/unattended-upgrades.log` | text | Auto-update status and failures |

**Suspicious indicators:** unexpected package installations (especially: `nmap`, `netcat`, `socat`, `proxychains`, `tor`, `john`, `hydra`), packages installed outside of normal maintenance windows, auto-update failures (could indicate tampering with apt sources).

### File Integrity

| Log | Format | What to check |
|-----|--------|--------------|
| `/var/log/aide-check.log` | text | Daily AIDE integrity reports — modified system binaries, config changes |
| `debsums --changed` | command | Tampered package files — binaries that don't match their installed checksums |

**Suspicious indicators:** modified binaries in `/usr/bin/`, `/usr/sbin/`, changed PAM configs in `/etc/pam.d/`, modified SSH configs, unexpected changes to `/etc/sudoers`.

### SSH / fail2ban

| Log | Format | What to check |
|-----|--------|--------------|
| `/var/log/auth.log` (SSH entries) | text | Failed SSH logins, accepted keys, brute force patterns |
| `/var/log/fail2ban.log` | text | Banned IPs, unban events, jail status |

**Suspicious indicators:** SSH logins from unexpected IPs, brute force patterns (many failed attempts), logins outside normal hours, use of unknown SSH keys.

### Docker

| Log | Format | What to check |
|-----|--------|--------------|
| `journalctl -u docker` | structured | Docker daemon events — container starts, stops, errors |
| `docker events` | stream | Real-time container lifecycle events |
| `docker logs <container>` | text | Per-container application logs |

**Suspicious indicators:** containers started by unexpected users, `--privileged` containers, containers mounting sensitive host paths (`/etc`, `/root`, `/var/run/docker.sock`), unusual images pulled.

### Cron / Scheduled Tasks

| Log | Format | What to check |
|-----|--------|--------------|
| `grep 'CRON' /var/log/syslog` | text | Every cron job execution with user and command |

**Suspicious indicators:** cron jobs running as root that weren't configured by you, jobs executing scripts from `/tmp` or `/dev/shm`, new entries appearing in `/etc/cron.d/` or user crontabs.

### Security Tools

| Log | Format | What to check |
|-----|--------|--------------|
| `/var/log/lynis.log` | text | Security audit results — hardening index, warnings, suggestions |
| `/var/log/lynis-report.dat` | text | Machine-readable audit data for trend analysis |
| `/var/log/rkhunter.log` | text | Rootkit scan results — modified binaries, suspicious files |
| `/var/log/chkrootkit/log.today` | text | chkrootkit daily scan results |
| `/var/log/crowdsec.log` | text | CrowdSec agent — parsed logs, detected scenarios, decisions |
| `/var/log/crowdsec_api.log` | text | CrowdSec local API — bouncer connections, alerts |
| `journalctl -u falco-modern-bpf` | structured | Falco runtime alerts — syscall violations, container events |
| `/var/log/trivy-scan.log` | text | Container vulnerability scan results (if cron configured) |
| `/var/log/clamav/freshclam.log` | text | ClamAV signature update status |
| `/var/log/clamav/daily-scan.log` | text | ClamAV daily scan results (if cron configured) |
| `/var/log/opencanary.log` | JSON | Honeypot triggers — any activity here is suspicious |

**Suspicious indicators:**
- **Lynis**: Hardening index dropping between scans (something was weakened)
- **rkhunter/chkrootkit**: Any rootkit detection (always investigate, may be false positive)
- **CrowdSec**: Repeated alerts from same IP range, alerts on unusual ports
- **Falco**: Shell in container, sensitive file reads, unexpected outbound connections, privilege escalation
- **Trivy**: CRITICAL CVEs in running container images
- **ClamAV**: Any "Infected files" count > 0 in scan results
- **OpenCanary**: ALL entries are suspicious — any connection to honeypot services means someone is probing

### Systemd Journal (structured)

| Command | What to check |
|---------|--------------|
| `journalctl -p err -b` | All errors since last boot |
| `journalctl -u <service> --since "1 hour ago"` | Recent activity for a specific service |
| `systemctl --failed` | Services that failed to start — could indicate tampering or crashes |

---

## 28. Security Monitoring Script

An automated monitoring script is installed at `/root/projects/security/scripts/security-monitor.sh`. It checks all log sources from Section 11 and produces a color-coded summary.

### Install and run

```bash
# Run manually
/root/projects/security/scripts/security-monitor.sh

# Run for a specific time window (default: 24h)
/root/projects/security/scripts/security-monitor.sh --hours 1

# Run as a daily cron job (reports to /var/log/security-monitor.log)
echo "0 8 * * * root /root/projects/security/scripts/security-monitor.sh --quiet >> /var/log/security-monitor.log 2>&1" > /etc/cron.d/security-monitor
```

See the script source for details on all checks performed.

---

## 29. Useful Monitoring Commands

### Daily checks

```bash
# Failed login attempts
grep "authentication failure" /var/log/auth.log

# All sudo usage today
grep "sudo" /var/log/auth.log | grep "$(date +%Y-%m-%d)"

# Commands run as root today
lastcomm --user root | head -20

# Shell commands logged today
grep "$(date +%Y-%m-%d)" /var/log/cmd-audit.log | tail -20

# Blocked firewall connections
grep "UFW BLOCK" /var/log/syslog

# AppArmor denials (after enabling)
grep "apparmor.*DENIED" /var/log/syslog

# Check for failed services
systemctl --failed

# Pi-hole: top blocked domains today
pihole -c -e 2>/dev/null | head -20

# Pi-hole: query log (live tail)
# pihole -t
```

### Listening ports audit

```bash
# TCP
ss -tlnp

# UDP
ss -ulnp
```

### Package security

```bash
# Check for available security updates
apt list --upgradable 2>/dev/null | grep -i security

# Review unattended-upgrades log
cat /var/log/unattended-upgrades/unattended-upgrades.log
```

### Security tool checks

```bash
# Lynis — run a full audit and check hardening score
lynis audit system
grep "hardening_index" /var/log/lynis-report.dat

# Rootkit scans
rkhunter --check --skip-keypress
chkrootkit

# CrowdSec — check for active bans and recent alerts
cscli decisions list
cscli alerts list --since 24h
cscli metrics

# Falco — check for runtime alerts
journalctl -u falco-modern-bpf --since "24 hours ago" --no-pager | grep -i "notice\|warning\|error"

# Trivy — scan all running container images
docker ps --format '{{.Image}}' | sort -u | while read img; do
  echo "=== $img ==="
  trivy image --severity HIGH,CRITICAL --quiet "$img"
done

# ClamAV — scan home directory
clamscan -r /home --infected --bell
freshclam --version  # check signature freshness

# OpenCanary — check honeypot alerts
cat /var/log/opencanary.log | jq 'select(.logdata.USERNAME) | {time: .utc_time, src: .src_host, user: .logdata.USERNAME, port: .dst_port}'
cat /var/log/opencanary.log | jq -r '.src_host' | sort | uniq -c | sort -rn  # attacks by source IP
```

---

## Quick Install Script

Copy and run this to apply all settings to a fresh WSL2 Ubuntu instance. Review before running.

```bash
#!/usr/bin/env bash
set -euo pipefail

# --- Must run as root ---
if [ "$EUID" -ne 0 ]; then echo "Run as root"; exit 1; fi

echo "[1/6] Updating packages..."
apt update -qq

echo "[2/6] Installing ufw..."
apt install -y -qq ufw
ufw default deny incoming
ufw default allow outgoing
ufw --force enable

echo "[3/6] Installing AppArmor tools..."
apt install -y -qq apparmor apparmor-utils apparmor-profiles apparmor-profiles-extra
apt install -y -qq ubuntu-advantage-tools   # AppArmor profiles for Ubuntu Pro processes
systemctl enable apparmor.service

echo "[4/6] Installing process accounting..."
apt install -y -qq acct
accton on
systemctl enable acct.service

echo "[5/6] Configuring shell command logging..."
cat > /etc/profile.d/cmd-logger.sh << 'SCRIPT'
if [ -n "$BASH_VERSION" ] && [[ $- == *i* ]]; then
    _CMD_LOG_LAST=""
    PROMPT_COMMAND='_cmd="$(history 1 | sed "s/^[ ]*[0-9]*[ ]*//")"
        if [ "$_cmd" != "$_CMD_LOG_LAST" ] && [ -n "$_cmd" ]; then
            logger -p local6.info -t "cmd-audit" "user=$USER tty=$(tty) pwd=$PWD cmd=$_cmd"
            _CMD_LOG_LAST="$_cmd"
        fi'
fi
SCRIPT

cat > /etc/rsyslog.d/30-cmd-audit.conf << 'EOF'
local6.*    /var/log/cmd-audit.log
EOF

cat > /etc/logrotate.d/cmd-audit << 'EOF'
/var/log/cmd-audit.log {
    weekly
    rotate 4
    compress
    delaycompress
    missingok
    notifempty
    postrotate
        /usr/lib/rsyslog/rsyslog-rotate
    endscript
}
EOF

systemctl restart rsyslog

echo "[6/10] Configuring wsl.conf..."
STATIC_IP="172.31.95.250"
cat > /etc/wsl.conf << EOF
[boot]
systemd=true
command="apparmor_parser -r /etc/apparmor.d/ 2>/dev/null || true; ip addr add ${STATIC_IP}/20 dev eth0 2>/dev/null || true"

[network]
generateResolvConf = false

[automount]
options = "metadata,umask=077"

[interop]
enabled = true
appendWindowsPath = false
EOF

echo "[7/10] Configuring DNS for Pi-hole..."
# Add static IP to eth0 now (wsl.conf boot command handles future boots)
ip addr add ${STATIC_IP}/20 dev eth0 2>/dev/null || true

# Disable systemd-resolved stub listener, point at Pi-hole
ETH0_IP=$(ip -4 addr show eth0 | grep -oP '(?<=inet\s)\d+(\.\d+){3}' | head -1)
sed -i "s/#DNS=/DNS=${ETH0_IP}/" /etc/systemd/resolved.conf
sed -i 's/#DNSStubListener=yes/DNSStubListener=no/' /etc/systemd/resolved.conf
systemctl restart systemd-resolved

# Create static resolv.conf pointing to Pi-hole on loopback
rm -f /etc/resolv.conf
echo 'nameserver 127.0.0.1' > /etc/resolv.conf
chattr +i /etc/resolv.conf  # prevent WSL from overwriting

echo "[8/10] Installing Pi-hole..."
mkdir -p /etc/pihole
cat > /etc/pihole/setupVars.conf << 'EOF'
PIHOLE_INTERFACE=eth0
QUERY_LOGGING=true
INSTALL_WEB_SERVER=true
INSTALL_WEB_INTERFACE=true
LIGHTTPD_ENABLED=true
CACHE_SIZE=10000
DNS_FQDN_REQUIRED=true
DNS_BOGUS_PRIV=true
DNSMASQ_LISTENING=local
WEBPASSWORD=                  # blank for unattended install — set with 'pihole setpassword' after install
BLOCKING_ENABLED=true
PIHOLE_DNS_1=1.1.1.1
PIHOLE_DNS_2=1.0.0.1
DNSSEC=false
REV_SERVER=false
EOF

git clone --depth 1 https://github.com/pi-hole/pi-hole.git /opt/pi-hole
bash /opt/pi-hole/"automated install/basic-install.sh" --unattended

# Configure FTL to avoid WSL2 port 53 conflict on 10.255.255.254
# NONE mode disables auto listen config; bind-interfaces + explicit addresses
# avoid the WSL kernel DNS proxy
pihole-FTL --config dns.listeningMode NONE
pihole-FTL --config dns.interface eth0
pihole-FTL --config misc.dnsmasq_lines "[\"bind-interfaces\", \"listen-address=${ETH0_IP}\", \"listen-address=127.0.0.1\", \"listen-address=${STATIC_IP}\"]"

# Open firewall ports for Pi-hole
ufw allow 53 comment "Pi-hole DNS"
ufw allow 80/tcp comment "Pi-hole web UI"
ufw allow 443/tcp comment "Pi-hole web UI HTTPS"

# Restart to apply
systemctl restart pihole-FTL

echo "[9/10] Applying kernel hardening sysctls..."
cat > /etc/sysctl.d/99-hardening.conf << 'SYSCTL'
kernel.randomize_va_space = 2
fs.suid_dumpable = 0
kernel.kptr_restrict = 2
kernel.dmesg_restrict = 1
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.icmp_ignore_bogus_error_responses = 1
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0
net.ipv4.tcp_syncookies = 1
net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.default.log_martians = 1
net.ipv4.conf.all.accept_source_route = 0
net.ipv6.conf.all.accept_source_route = 0
SYSCTL
sysctl --system 2>/dev/null || true

echo "[10/10] Installing file integrity monitoring..."
apt install -y -qq aide debsums
aideinit 2>/dev/null || true
test -f /var/lib/aide/aide.db.new && cp /var/lib/aide/aide.db.new /var/lib/aide/aide.db

echo ""
echo "============================================"
echo " DONE — Linux-side configuration complete"
echo "============================================"
echo ""
echo "MANUAL STEPS REMAINING:"
echo ""
echo "1. Create C:\\Users\\<USERNAME>\\.wslconfig with:"
echo ""
echo "   [wsl2]"
echo "   kernelCommandLine = apparmor=1 security=apparmor"
echo ""
echo "2. From PowerShell, run:  wsl --shutdown"
echo "3. Reopen WSL and verify:"
echo "     aa-status && ufw status && pihole status"
echo ""
echo "4. Set a Pi-hole web admin password:"
echo "     pihole setpassword"
echo ""
echo "5. Configure Windows DNS (elevated PowerShell):"
echo "     Set-DnsClientServerAddress -InterfaceAlias \"Wi-Fi\" -ServerAddresses ${STATIC_IP}, 1.1.1.1"
echo ""
echo "6. Access Pi-hole admin at:"
echo "     http://${STATIC_IP}/admin"
echo ""
```

> **Important:** The `.wslconfig` file must be created on the Windows side manually or via `/mnt/c/Users/<username>/.wslconfig`. It cannot be included in the script reliably because the Windows username must be known. The script prints the manual steps at the end. A `wsl --shutdown` and reopen is required for Pi-hole DNS and AppArmor to fully activate.
