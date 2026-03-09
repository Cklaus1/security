#!/usr/bin/env bash
# security-monitor.sh — WSL2 security log checker
# Checks all system log sources for suspicious activity and produces a summary.
# Usage:
#   ./security-monitor.sh              # check last 24 hours (default)
#   ./security-monitor.sh --hours 1    # check last 1 hour
#   ./security-monitor.sh --quiet      # no color, suitable for cron/logging

set -euo pipefail

# --- Defaults ---
HOURS=24
QUIET=false

while [[ $# -gt 0 ]]; do
    case "$1" in
        --hours) HOURS="$2"; shift 2 ;;
        --quiet) QUIET=true; shift ;;
        -h|--help)
            echo "Usage: $0 [--hours N] [--quiet]"
            exit 0 ;;
        *) echo "Unknown option: $1"; exit 1 ;;
    esac
done

SINCE=$(date -d "${HOURS} hours ago" '+%Y-%m-%d %H:%M:%S' 2>/dev/null || date '+%Y-%m-%d %H:%M:%S')
FINDINGS=0

# --- Colors ---
if [[ "$QUIET" == "true" ]]; then
    RED="" YEL="" GRN="" CYN="" RST="" BLD=""
else
    RED='\033[0;31m' YEL='\033[0;33m' GRN='\033[0;32m'
    CYN='\033[0;36m' RST='\033[0m' BLD='\033[1m'
fi

header()  { echo -e "\n${BLD}${CYN}=== $1 ===${RST}"; }
ok()      { echo -e "  ${GRN}[OK]${RST} $1"; }
warn()    { echo -e "  ${YEL}[!]${RST} $1"; FINDINGS=$((FINDINGS + 1)); }
alert()   { echo -e "  ${RED}[ALERT]${RST} $1"; FINDINGS=$((FINDINGS + 1)); }
info()    { echo -e "  ${CYN}[i]${RST} $1"; }

# Safe grep -c that always returns a single integer
count_grep() {
    local pattern="$1" file="$2"
    local n
    n=$(grep -cE "$pattern" "$file" 2>/dev/null || true)
    # grep -c on a single file returns one number, but ensure it's valid
    echo "${n:-0}"
}

echo -e "${BLD}Security Monitor — $(date '+%Y-%m-%d %H:%M:%S')${RST}"
echo -e "Checking logs from the last ${HOURS} hour(s) (since ${SINCE})"

# =========================================================================
# 1. Authentication & Access
# =========================================================================
header "Authentication & Access"

if [[ -f /var/log/auth.log ]]; then
    # Failed logins
    FAIL_COUNT=$(count_grep "authentication failure" /var/log/auth.log)
    if [[ "$FAIL_COUNT" -gt 10 ]]; then
        alert "auth.log: ${FAIL_COUNT} authentication failures (possible brute force)"
        grep "authentication failure" /var/log/auth.log | tail -5 | while read -r line; do
            echo -e "    $line"
        done
    elif [[ "$FAIL_COUNT" -gt 0 ]]; then
        warn "auth.log: ${FAIL_COUNT} authentication failure(s)"
    else
        ok "No authentication failures"
    fi

    # Sudo usage
    SUDO_COUNT=$(count_grep "sudo:" /var/log/auth.log)
    SUDO_FAIL=$(grep "sudo:" /var/log/auth.log 2>/dev/null | grep -cE "NOT in sudoers|authentication failure|incorrect password" || true)
    SUDO_FAIL="${SUDO_FAIL:-0}"
    if [[ "$SUDO_FAIL" -gt 0 ]]; then
        alert "auth.log: ${SUDO_FAIL} failed sudo attempt(s)"
        grep "sudo:" /var/log/auth.log | grep -E "NOT in sudoers|authentication failure|incorrect password" | tail -5 | while read -r line; do
            echo -e "    $line"
        done
    else
        info "auth.log: ${SUDO_COUNT} sudo entries (no failures)"
    fi

    # su attempts
    SU_COUNT=$(count_grep "su:" /var/log/auth.log)
    if [[ "$SU_COUNT" -gt 0 ]]; then
        warn "auth.log: ${SU_COUNT} su session event(s)"
    fi
else
    warn "auth.log not found"
fi

# Failed login binary log
LASTB_COUNT=$(lastb 2>/dev/null | grep -vcE "^$|^btmp" || true)
LASTB_COUNT="${LASTB_COUNT:-0}"
if [[ "$LASTB_COUNT" -gt 0 ]]; then
    warn "btmp: ${LASTB_COUNT} failed login record(s)"
else
    ok "No failed login records in btmp"
fi

# =========================================================================
# 2. Command Auditing
# =========================================================================
header "Command Auditing"

if [[ -f /var/log/cmd-audit.log ]]; then
    # Suspicious command patterns
    RECON_PATTERNS='cat /etc/shadow|cat /etc/passwd|find.*-perm.*4000|find.*-perm.*2000|whoami|/etc/sudoers'
    EXFIL_PATTERNS='curl.*\|.*base64|wget.*-O -|nc -|ncat |socat |scp .*:|rsync.*:'
    PERSIST_PATTERNS='crontab -e|crontab -l|systemctl enable|systemctl daemon-reload|/etc/profile\.d/|\.bashrc'
    EVASION_PATTERNS='history -c|unset HISTFILE|shred.*log|rm.*/var/log|systemctl stop.*rsyslog|systemctl stop.*acct|systemctl stop.*apparmor|systemctl stop.*ufw'

    RECON_COUNT=$(count_grep "$RECON_PATTERNS" /var/log/cmd-audit.log)
    EXFIL_COUNT=$(count_grep "$EXFIL_PATTERNS" /var/log/cmd-audit.log)
    PERSIST_COUNT=$(count_grep "$PERSIST_PATTERNS" /var/log/cmd-audit.log)
    EVASION_COUNT=$(count_grep "$EVASION_PATTERNS" /var/log/cmd-audit.log)

    if [[ "$RECON_COUNT" -gt 0 ]]; then
        warn "cmd-audit: ${RECON_COUNT} reconnaissance command(s)"
        grep -E "$RECON_PATTERNS" /var/log/cmd-audit.log | tail -3 | while read -r line; do echo -e "    $line"; done
    fi
    if [[ "$EXFIL_COUNT" -gt 0 ]]; then
        alert "cmd-audit: ${EXFIL_COUNT} potential exfiltration command(s)"
        grep -E "$EXFIL_PATTERNS" /var/log/cmd-audit.log | tail -3 | while read -r line; do echo -e "    $line"; done
    fi
    if [[ "$PERSIST_COUNT" -gt 0 ]]; then
        warn "cmd-audit: ${PERSIST_COUNT} persistence-related command(s)"
        grep -E "$PERSIST_PATTERNS" /var/log/cmd-audit.log | tail -3 | while read -r line; do echo -e "    $line"; done
    fi
    if [[ "$EVASION_COUNT" -gt 0 ]]; then
        alert "cmd-audit: ${EVASION_COUNT} defense evasion command(s)"
        grep -E "$EVASION_PATTERNS" /var/log/cmd-audit.log | tail -3 | while read -r line; do echo -e "    $line"; done
    fi

    TOTAL_CMDS=$(wc -l < /var/log/cmd-audit.log 2>/dev/null || echo 0)
    if [[ "$RECON_COUNT" -eq 0 && "$EXFIL_COUNT" -eq 0 && "$PERSIST_COUNT" -eq 0 && "$EVASION_COUNT" -eq 0 ]]; then
        ok "No suspicious commands detected (${TOTAL_CMDS} total entries)"
    fi
else
    warn "cmd-audit.log not found — shell command logging may not be configured"
fi

# Process accounting
if command -v lastcomm &>/dev/null; then
    ROOT_CMDS=$(lastcomm --user root 2>/dev/null | wc -l || echo 0)
    info "Process accounting: ${ROOT_CMDS} commands run as root"
else
    warn "lastcomm not available — install acct"
fi

# =========================================================================
# 3. AppArmor
# =========================================================================
header "AppArmor"

if [[ -f /sys/module/apparmor/parameters/enabled ]]; then
    AA_ENABLED=$(cat /sys/module/apparmor/parameters/enabled)
    if [[ "$AA_ENABLED" == "Y" ]]; then
        ok "AppArmor is enabled"
        AA_DENIALS=$(count_grep "apparmor.*DENIED" /var/log/syslog)
        if [[ "$AA_DENIALS" -gt 0 ]]; then
            warn "AppArmor: ${AA_DENIALS} DENIED event(s) in syslog"
            grep 'apparmor.*DENIED' /var/log/syslog | tail -5 | while read -r line; do
                echo -e "    $line"
            done
        else
            ok "No AppArmor denials"
        fi
    else
        warn "AppArmor module present but disabled"
    fi
else
    warn "AppArmor not available on this kernel"
fi

# =========================================================================
# 4. Firewall (UFW)
# =========================================================================
header "Firewall (UFW)"

if command -v ufw &>/dev/null; then
    UFW_STATUS=$(ufw status 2>/dev/null | head -1)
    if echo "$UFW_STATUS" | grep -q "active"; then
        ok "UFW is active"
    else
        alert "UFW is NOT active"
    fi

    UFW_BLOCKS=$(count_grep "UFW BLOCK" /var/log/syslog)
    if [[ "$UFW_BLOCKS" -gt 50 ]]; then
        alert "UFW: ${UFW_BLOCKS} blocked connection(s) — possible port scan"
        grep 'UFW BLOCK' /var/log/syslog | tail -5 | while read -r line; do
            echo -e "    $line"
        done
    elif [[ "$UFW_BLOCKS" -gt 0 ]]; then
        info "UFW: ${UFW_BLOCKS} blocked connection(s)"
    else
        ok "No blocked connections"
    fi
else
    warn "UFW not installed"
fi

# =========================================================================
# 5. DNS / Pi-hole
# =========================================================================
header "DNS / Pi-hole"

if systemctl is-active pihole-FTL &>/dev/null; then
    ok "Pi-hole FTL is running"

    # Check for dnsmasq bind errors
    BIND_ERRORS=$(count_grep "CRIT.*dnsmasq|CRIT.*port 53" /var/log/pihole/FTL.log)
    if [[ "$BIND_ERRORS" -gt 0 ]]; then
        warn "FTL.log: ${BIND_ERRORS} dnsmasq bind error(s) — DNS may not be fully functional"
    fi

    if [[ -f /var/log/pihole/pihole.log ]]; then
        TOTAL_QUERIES=$(wc -l < /var/log/pihole/pihole.log 2>/dev/null || echo 0)
        BLOCKED_QUERIES=$(count_grep " is 0\.0\.0\.0$| is ::$| is NXDOMAIN" /var/log/pihole/pihole.log)
        info "Pi-hole: ${TOTAL_QUERIES} log lines, ${BLOCKED_QUERIES} blocked responses"

        # DGA detection: domains with high entropy (long random-looking names)
        DGA_SUSPECTS=$(grep 'query\[' /var/log/pihole/pihole.log 2>/dev/null | \
            awk '{print $NF}' | \
            grep -E '^[a-z0-9]{15,}\.' 2>/dev/null | sort -u | head -10 || true)
        if [[ -n "$DGA_SUSPECTS" ]]; then
            warn "Pi-hole: Possible DGA domains detected"
            echo "$DGA_SUSPECTS" | while read -r line; do echo -e "    $line"; done
        fi

        # High-frequency single domain queries (beaconing)
        TOP_DOMAIN=$(grep 'query\[' /var/log/pihole/pihole.log 2>/dev/null | \
            awk '{print $NF}' | sort | uniq -c | sort -rn | head -1 || true)
        if [[ -n "$TOP_DOMAIN" ]]; then
            TOP_COUNT=$(echo "$TOP_DOMAIN" | awk '{print $1}')
            TOP_NAME=$(echo "$TOP_DOMAIN" | awk '{print $2}')
            if [[ -n "$TOP_COUNT" && "$TOP_COUNT" -gt 500 ]]; then
                warn "Pi-hole: High-frequency queries — ${TOP_COUNT}x to ${TOP_NAME} (possible beaconing)"
            fi
        fi

        # DNS tunneling: very long query names
        TUNNEL_SUSPECTS=$(grep 'query\[' /var/log/pihole/pihole.log 2>/dev/null | \
            awk '{print $NF}' | awk 'length > 60' | sort -u | head -5 || true)
        if [[ -n "$TUNNEL_SUSPECTS" ]]; then
            warn "Pi-hole: Unusually long domain queries (possible DNS tunneling)"
            echo "$TUNNEL_SUSPECTS" | while read -r line; do echo -e "    $line"; done
        fi
    else
        warn "Pi-hole query log not found (pihole.log)"
    fi

    # Web UI access
    if [[ -f /var/log/pihole/webserver.log ]]; then
        WEB_ERRORS=$(count_grep " 401 | 403 " /var/log/pihole/webserver.log)
        if [[ "$WEB_ERRORS" -gt 10 ]]; then
            warn "Pi-hole web: ${WEB_ERRORS} unauthorized/forbidden requests"
        fi
    fi
else
    warn "Pi-hole FTL is not running"
fi

# =========================================================================
# 6. Package Management
# =========================================================================
header "Package Management"

if [[ -f /var/log/apt/history.log ]]; then
    # Check for suspicious package installs
    SUSPICIOUS_PKGS='nmap|netcat|ncat|socat|proxychains|tor |hydra|john|hashcat|aircrack|metasploit|mimikatz|responder|bloodhound|impacket|crackmapexec'
    SUS_INSTALLS=$(grep -i "Install:" /var/log/apt/history.log 2>/dev/null | grep -ciE "$SUSPICIOUS_PKGS" || true)
    SUS_INSTALLS="${SUS_INSTALLS:-0}"
    if [[ "$SUS_INSTALLS" -gt 0 ]]; then
        alert "apt: ${SUS_INSTALLS} potentially suspicious package install(s)"
        grep -i "Install:" /var/log/apt/history.log | grep -iE "$SUSPICIOUS_PKGS" | tail -5 | while read -r line; do
            echo -e "    $line"
        done
    else
        ok "No suspicious package installations detected"
    fi

    RECENT_INSTALLS=$(grep -c "Install:" /var/log/apt/history.log 2>/dev/null || true)
    RECENT_INSTALLS="${RECENT_INSTALLS:-0}"
    info "apt: ${RECENT_INSTALLS} install operations in history"
fi

# Auto-updates
if [[ -f /var/log/unattended-upgrades/unattended-upgrades.log ]]; then
    UU_ERRORS=$(count_grep "error|fail|warning" /var/log/unattended-upgrades/unattended-upgrades.log)
    if [[ "$UU_ERRORS" -gt 0 ]]; then
        warn "Unattended-upgrades: ${UU_ERRORS} error/warning(s) — security patches may not be applied"
    else
        ok "Unattended-upgrades: no errors"
    fi
else
    warn "Unattended-upgrades log not found"
fi

# =========================================================================
# 7. Cron / Scheduled Tasks
# =========================================================================
header "Cron / Scheduled Tasks"

CRON_ENTRIES=$(count_grep "CRON" /var/log/syslog)
info "syslog: ${CRON_ENTRIES} CRON entries"

# Check for cron jobs running from suspicious locations
SUS_CRON=$(grep 'CRON' /var/log/syslog 2>/dev/null | grep -E '/tmp/|/dev/shm/|/var/tmp/' || true)
if [[ -n "$SUS_CRON" ]]; then
    alert "Cron jobs executing from suspicious locations (/tmp, /dev/shm)"
    echo "$SUS_CRON" | tail -5 | while read -r line; do echo -e "    $line"; done
fi

# Check for unexpected cron files
CRON_FILES=$(find /etc/cron.d/ /etc/cron.daily/ /etc/cron.hourly/ /etc/cron.weekly/ /etc/cron.monthly/ \
    -type f -newer /var/log/wtmp 2>/dev/null || true)
if [[ -n "$CRON_FILES" ]]; then
    warn "Recently modified cron files"
    echo "$CRON_FILES" | while read -r line; do echo -e "    $line"; done
fi

# =========================================================================
# 8. System Health
# =========================================================================
header "System Health"

# Failed services
FAILED=$(systemctl --failed --no-legend 2>/dev/null | wc -l || echo 0)
if [[ "$FAILED" -gt 0 ]]; then
    warn "${FAILED} failed systemd service(s)"
    systemctl --failed --no-legend 2>/dev/null | while read -r line; do
        echo -e "    $line"
    done
else
    ok "No failed services"
fi

# Journal errors since window
JERRORS=$(journalctl -p err --since "${HOURS} hours ago" --no-pager -q 2>/dev/null | wc -l || echo 0)
if [[ "$JERRORS" -gt 20 ]]; then
    warn "Journal: ${JERRORS} error-level entries in the last ${HOURS}h"
    journalctl -p err --since "${HOURS} hours ago" --no-pager -q 2>/dev/null | tail -5 | while read -r line; do
        echo -e "    $line"
    done
elif [[ "$JERRORS" -gt 0 ]]; then
    info "Journal: ${JERRORS} error-level entries in the last ${HOURS}h"
else
    ok "No journal errors"
fi

# Listening ports check
header "Listening Ports"
echo -e "  TCP:"
ss -tlnp 2>/dev/null | grep -v "^State" | while read -r line; do
    echo -e "    $line"
done
echo -e "  UDP:"
ss -ulnp 2>/dev/null | grep -v "^State" | while read -r line; do
    echo -e "    $line"
done

# =========================================================================
# 9. File Integrity Spot Checks
# =========================================================================
header "File Integrity Spot Checks"

# Check resolv.conf
RESOLV_NS=$(grep '^nameserver' /etc/resolv.conf 2>/dev/null | awk '{print $2}' | tr '\n' ' ')
if echo "$RESOLV_NS" | grep -q '127.0.0.1'; then
    ok "resolv.conf points to Pi-hole (${RESOLV_NS})"
else
    warn "resolv.conf points to ${RESOLV_NS}(expected 127.0.0.1 for Pi-hole)"
fi

# Check resolv.conf immutable flag
if lsattr /etc/resolv.conf 2>/dev/null | grep -q 'i'; then
    ok "resolv.conf has immutable flag set"
else
    warn "resolv.conf is NOT immutable — WSL may overwrite it"
fi

# Check for world-writable files in /etc
WORLD_WRITABLE=$(find /etc -maxdepth 2 -type f -perm -002 2>/dev/null | head -10 || true)
if [[ -n "$WORLD_WRITABLE" ]]; then
    warn "World-writable files in /etc"
    echo "$WORLD_WRITABLE" | while read -r line; do echo -e "    $line"; done
else
    ok "No world-writable files in /etc"
fi

# Check for SUID binaries outside expected set
SUID_COUNT=$(find /usr -type f -perm -4000 2>/dev/null | wc -l || echo 0)
info "SUID binaries in /usr: ${SUID_COUNT}"

# =========================================================================
# Summary
# =========================================================================
echo ""
echo -e "${BLD}============================================${RST}"
if [[ "$FINDINGS" -eq 0 ]]; then
    echo -e "${BLD}${GRN}  No findings. All checks passed.${RST}"
else
    echo -e "${BLD}${YEL}  ${FINDINGS} finding(s) detected. Review above.${RST}"
fi
echo -e "${BLD}============================================${RST}"
exit 0
