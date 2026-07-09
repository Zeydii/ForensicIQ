#!/bin/bash
#
# LINUX FORENSIC ARTIFACT COLLECTION SCRIPT
# Comprehensive collection for compromise assessment
#

set -euo pipefail

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Configuration
COLLECTION_DIR="/tmp/linux_forensics"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
OUTPUT_DIR="${COLLECTION_DIR}/Collection_${TIMESTAMP}"
HOSTNAME=$(hostname)

echo -e "${GREEN}════════════════════════════════════════════════════════════════${NC}"
echo -e "${GREEN}LINUX FORENSIC ARTIFACT COLLECTION${NC}"
echo -e "${GREEN}════════════════════════════════════════════════════════════════${NC}"
echo -e "Timestamp: ${TIMESTAMP}"
echo -e "Hostname: ${HOSTNAME}"
echo -e "Output: ${OUTPUT_DIR}"
echo -e "${GREEN}════════════════════════════════════════════════════════════════${NC}\n"

# Create output directory
mkdir -p "${OUTPUT_DIR}"/{logs,memory,network,processes,users,files,system,persistence}

# ═══════════════════════════════════════════════════════════════
# SYSTEM INFORMATION
# ═══════════════════════════════════════════════════════════════
echo -e "${YELLOW}[1/12] Collecting System Information...${NC}"

# OS Information
uname -a > "${OUTPUT_DIR}/system/uname.txt" 2>&1
cat /etc/os-release > "${OUTPUT_DIR}/system/os-release.txt" 2>&1
hostnamectl > "${OUTPUT_DIR}/system/hostnamectl.txt" 2>&1
uptime > "${OUTPUT_DIR}/system/uptime.txt" 2>&1
date > "${OUTPUT_DIR}/system/current_time.txt" 2>&1

# Kernel information
cat /proc/version > "${OUTPUT_DIR}/system/kernel_version.txt" 2>&1
cat /proc/cmdline > "${OUTPUT_DIR}/system/kernel_cmdline.txt" 2>&1

echo -e "  ${GREEN}✓${NC} System information collected\n"

# ═══════════════════════════════════════════════════════════════
# PROCESS INFORMATION
# ═══════════════════════════════════════════════════════════════
echo -e "${YELLOW}[2/12] Collecting Process Information...${NC}"

# Running processes
ps auxf > "${OUTPUT_DIR}/processes/ps_auxf.txt" 2>&1
ps -eo pid,ppid,user,cmd,etime,lstart > "${OUTPUT_DIR}/processes/ps_detailed.txt" 2>&1

# Process tree
pstree -apnh > "${OUTPUT_DIR}/processes/pstree.txt" 2>&1

# Top processes
top -b -n 1 > "${OUTPUT_DIR}/processes/top.txt" 2>&1

# Open files
lsof > "${OUTPUT_DIR}/processes/lsof.txt" 2>&1 || true

echo -e "  ${GREEN}✓${NC} Process information collected\n"

# ═══════════════════════════════════════════════════════════════
# NETWORK INFORMATION
# ═══════════════════════════════════════════════════════════════
echo -e "${YELLOW}[3/12] Collecting Network Information...${NC}"

# Network connections
netstat -antp > "${OUTPUT_DIR}/network/netstat_tcp.txt" 2>&1 || ss -antp > "${OUTPUT_DIR}/network/ss_tcp.txt" 2>&1
netstat -anup > "${OUTPUT_DIR}/network/netstat_udp.txt" 2>&1 || ss -anup > "${OUTPUT_DIR}/network/ss_udp.txt" 2>&1

# Listening ports
netstat -tulpn > "${OUTPUT_DIR}/network/listening_ports.txt" 2>&1 || ss -tulpn > "${OUTPUT_DIR}/network/listening_ports.txt" 2>&1

# Network interfaces
ip addr > "${OUTPUT_DIR}/network/ip_addr.txt" 2>&1
ifconfig -a > "${OUTPUT_DIR}/network/ifconfig.txt" 2>&1 || true

# Routing table
ip route > "${OUTPUT_DIR}/network/routing_table.txt" 2>&1
route -n > "${OUTPUT_DIR}/network/route.txt" 2>&1 || true

# ARP cache
ip neigh > "${OUTPUT_DIR}/network/arp_cache.txt" 2>&1
arp -a > "${OUTPUT_DIR}/network/arp.txt" 2>&1 || true

# Firewall rules
iptables -L -n -v > "${OUTPUT_DIR}/network/iptables.txt" 2>&1 || true
ufw status verbose > "${OUTPUT_DIR}/network/ufw_status.txt" 2>&1 || true

# DNS configuration
cat /etc/resolv.conf > "${OUTPUT_DIR}/network/resolv.conf" 2>&1
cat /etc/hosts > "${OUTPUT_DIR}/network/hosts.txt" 2>&1

echo -e "  ${GREEN}✓${NC} Network information collected\n"

# ═══════════════════════════════════════════════════════════════
# USER INFORMATION
# ═══════════════════════════════════════════════════════════════
echo -e "${YELLOW}[4/12] Collecting User Information...${NC}"

# User accounts
cat /etc/passwd > "${OUTPUT_DIR}/users/passwd.txt" 2>&1
cat /etc/shadow > "${OUTPUT_DIR}/users/shadow.txt" 2>&1 || echo "Permission denied" > "${OUTPUT_DIR}/users/shadow.txt"
cat /etc/group > "${OUTPUT_DIR}/users/group.txt" 2>&1
cat /etc/sudoers > "${OUTPUT_DIR}/users/sudoers.txt" 2>&1 || echo "Permission denied" > "${OUTPUT_DIR}/users/sudoers.txt"

# Currently logged in users
w > "${OUTPUT_DIR}/users/logged_in_w.txt" 2>&1
who > "${OUTPUT_DIR}/users/logged_in_who.txt" 2>&1
last -a > "${OUTPUT_DIR}/users/last_logins.txt" 2>&1
lastlog > "${OUTPUT_DIR}/users/lastlog.txt" 2>&1

# Failed logins
lastb > "${OUTPUT_DIR}/users/failed_logins.txt" 2>&1 || echo "No failed logins" > "${OUTPUT_DIR}/users/failed_logins.txt"

# SSH keys
find /home -name "authorized_keys" -type f 2>/dev/null | while read keyfile; do
    echo "=== $keyfile ===" >> "${OUTPUT_DIR}/users/ssh_authorized_keys.txt"
    cat "$keyfile" >> "${OUTPUT_DIR}/users/ssh_authorized_keys.txt" 2>&1
    echo "" >> "${OUTPUT_DIR}/users/ssh_authorized_keys.txt"
done

# User directories
ls -laR /home > "${OUTPUT_DIR}/users/home_directories.txt" 2>&1

echo -e "  ${GREEN}✓${NC} User information collected\n"

# ═══════════════════════════════════════════════════════════════
# PERSISTENCE MECHANISMS
# ═══════════════════════════════════════════════════════════════
echo -e "${YELLOW}[5/12] Collecting Persistence Mechanisms...${NC}"

# Cron jobs
crontab -l > "${OUTPUT_DIR}/persistence/root_crontab.txt" 2>&1 || echo "No root crontab" > "${OUTPUT_DIR}/persistence/root_crontab.txt"
cat /etc/crontab > "${OUTPUT_DIR}/persistence/etc_crontab.txt" 2>&1

# System-wide cron
ls -laR /etc/cron.* > "${OUTPUT_DIR}/persistence/cron_directories.txt" 2>&1
tar czf "${OUTPUT_DIR}/persistence/cron_files.tar.gz" /etc/cron.d /etc/cron.daily /etc/cron.hourly /etc/cron.monthly /etc/cron.weekly /var/spool/cron 2>/dev/null || true

# Systemd services
systemctl list-units --type=service --all > "${OUTPUT_DIR}/persistence/systemd_services.txt" 2>&1
systemctl list-unit-files > "${OUTPUT_DIR}/persistence/systemd_unit_files.txt" 2>&1

# Startup scripts
ls -la /etc/init.d/ > "${OUTPUT_DIR}/persistence/init_d.txt" 2>&1
ls -la /etc/rc*.d/ > "${OUTPUT_DIR}/persistence/rc_directories.txt" 2>&1

# Systemd service files
tar czf "${OUTPUT_DIR}/persistence/systemd_services.tar.gz" /etc/systemd/system /usr/lib/systemd/system 2>/dev/null || true

# Profile scripts
tar czf "${OUTPUT_DIR}/persistence/profile_scripts.tar.gz" /etc/profile /etc/profile.d /etc/bash.bashrc /etc/environment 2>/dev/null || true

echo -e "  ${GREEN}✓${NC} Persistence mechanisms collected\n"

# ═══════════════════════════════════════════════════════════════
# LOGS
# ═══════════════════════════════════════════════════════════════
echo -e "${YELLOW}[6/12] Collecting System Logs...${NC}"

# System logs
tar czf "${OUTPUT_DIR}/logs/var_log.tar.gz" /var/log/*.log /var/log/syslog* /var/log/auth.log* /var/log/kern.log* /var/log/dmesg* 2>/dev/null || true

# Audit logs
if [ -d /var/log/audit ]; then
    tar czf "${OUTPUT_DIR}/logs/audit_logs.tar.gz" /var/log/audit/ 2>/dev/null || true
fi

# Journal logs (systemd)
journalctl --no-pager > "${OUTPUT_DIR}/logs/journalctl.txt" 2>&1 || true
journalctl --no-pager --since "7 days ago" > "${OUTPUT_DIR}/logs/journalctl_7days.txt" 2>&1 || true

# Wazuh agent logs
if [ -d /var/ossec/logs ]; then
    tar czf "${OUTPUT_DIR}/logs/wazuh_agent_logs.tar.gz" /var/ossec/logs/ 2>/dev/null || true
fi

echo -e "  ${GREEN}✓${NC} Logs collected\n"

# ═══════════════════════════════════════════════════════════════
# KERNEL MODULES
# ═══════════════════════════════════════════════════════════════
echo -e "${YELLOW}[7/12] Collecting Kernel Module Information...${NC}"

# Loaded kernel modules
lsmod > "${OUTPUT_DIR}/system/lsmod.txt" 2>&1
cat /proc/modules > "${OUTPUT_DIR}/system/proc_modules.txt" 2>&1

# Kernel module details
modinfo $(lsmod | awk 'NR>1 {print $1}') > "${OUTPUT_DIR}/system/modinfo.txt" 2>&1 || true

echo -e "  ${GREEN}✓${NC} Kernel module information collected\n"

# ═══════════════════════════════════════════════════════════════
# FILE SYSTEM
# ═══════════════════════════════════════════════════════════════
echo -e "${YELLOW}[8/12] Collecting File System Information...${NC}"

# Mounted file systems
mount > "${OUTPUT_DIR}/files/mount.txt" 2>&1
df -h > "${OUTPUT_DIR}/files/df.txt" 2>&1
cat /etc/fstab > "${OUTPUT_DIR}/files/fstab.txt" 2>&1

# Recently modified files (last 7 days)
find / -type f -mtime -7 -ls 2>/dev/null > "${OUTPUT_DIR}/files/recently_modified_7days.txt" &
FIND_PID=$!

# SUID/SGID files
find / -type f \( -perm -4000 -o -perm -2000 \) -ls 2>/dev/null > "${OUTPUT_DIR}/files/suid_sgid_files.txt" &

# Hidden files in common locations
find /tmp /var/tmp /dev/shm -name ".*" -ls 2>/dev/null > "${OUTPUT_DIR}/files/hidden_files_tmp.txt" &

# Wait for background jobs
wait $FIND_PID 2>/dev/null || true
wait

echo -e "  ${GREEN}✓${NC} File system information collected\n"

# ═══════════════════════════════════════════════════════════════
# BASH HISTORY
# ═══════════════════════════════════════════════════════════════
echo -e "${YELLOW}[9/12] Collecting Bash History...${NC}"

# Root bash history
cat /root/.bash_history > "${OUTPUT_DIR}/users/root_bash_history.txt" 2>&1 || echo "Permission denied" > "${OUTPUT_DIR}/users/root_bash_history.txt"

# User bash histories
find /home -name ".bash_history" -type f 2>/dev/null | while read histfile; do
    username=$(echo "$histfile" | cut -d'/' -f3)
    cat "$histfile" > "${OUTPUT_DIR}/users/${username}_bash_history.txt" 2>&1
done

echo -e "  ${GREEN}✓${NC} Bash history collected\n"

# ═══════════════════════════════════════════════════════════════
# INSTALLED PACKAGES
# ═══════════════════════════════════════════════════════════════
echo -e "${YELLOW}[10/12] Collecting Installed Packages...${NC}"

# Debian/Ubuntu
if command -v dpkg &> /dev/null; then
    dpkg -l > "${OUTPUT_DIR}/system/installed_packages_dpkg.txt" 2>&1
    apt list --installed > "${OUTPUT_DIR}/system/installed_packages_apt.txt" 2>&1
fi

# RedHat/CentOS
if command -v rpm &> /dev/null; then
    rpm -qa > "${OUTPUT_DIR}/system/installed_packages_rpm.txt" 2>&1
    yum list installed > "${OUTPUT_DIR}/system/installed_packages_yum.txt" 2>&1 || true
fi

echo -e "  ${GREEN}✓${NC} Installed packages collected\n"

# ═══════════════════════════════════════════════════════════════
# MEMORY DUMP (if available)
# ═══════════════════════════════════════════════════════════════
echo -e "${YELLOW}[11/12] Attempting Memory Dump...${NC}"

if command -v avml &> /dev/null; then
    avml "${OUTPUT_DIR}/memory/memory.lime" > "${OUTPUT_DIR}/memory/avml.log" 2>&1 || true
    echo -e "  ${GREEN}✓${NC} Memory dump created with AVML\n"
elif [ -e /proc/kcore ]; then
    echo -e "  ${YELLOW}⚠${NC} Memory dump requires tools like AVML or LiME"
    echo -e "    Install: wget https://github.com/microsoft/avml/releases/download/v0.11.0/avml -O /usr/local/bin/avml"
    echo -e "    SKIPPING\n"
else
    echo -e "  ${YELLOW}⚠${NC} Memory dump not available\n"
fi

# ═══════════════════════════════════════════════════════════════
# CREATE MANIFEST
# ═══════════════════════════════════════════════════════════════
echo -e "${YELLOW}[12/12] Creating Manifest...${NC}"

cat > "${OUTPUT_DIR}/MANIFEST.json" << EOF
{
    "collection_timestamp": "${TIMESTAMP}",
    "hostname": "${HOSTNAME}",
    "collector": "linux_forensic_collector.sh",
    "collector_version": "2.0",
    "operating_system": "$(cat /etc/os-release | grep PRETTY_NAME | cut -d'=' -f2 | tr -d '\"')",
    "kernel_version": "$(uname -r)",
    "collection_user": "$(whoami)",
    "collection_complete": true
}
EOF

echo -e "  ${GREEN}✓${NC} Manifest created\n"

# ═══════════════════════════════════════════════════════════════
# COMPRESS COLLECTION
# ═══════════════════════════════════════════════════════════════
echo -e "${YELLOW}Compressing Collection...${NC}"

ARCHIVE_NAME="LinuxCollection_${HOSTNAME}_${TIMESTAMP}.tar.gz"
ARCHIVE_PATH="${COLLECTION_DIR}/${ARCHIVE_NAME}"

cd "${COLLECTION_DIR}"
tar czf "${ARCHIVE_PATH}" "Collection_${TIMESTAMP}/"

# Generate hash
sha256sum "${ARCHIVE_PATH}" > "${ARCHIVE_PATH}.sha256"

# Get size
SIZE=$(du -h "${ARCHIVE_PATH}" | cut -f1)

echo -e "\n${GREEN}════════════════════════════════════════════════════════════════${NC}"
echo -e "${GREEN}COLLECTION COMPLETE${NC}"
echo -e "${GREEN}════════════════════════════════════════════════════════════════${NC}"
echo -e "Archive: ${ARCHIVE_PATH}"
echo -e "Size: ${SIZE}"
echo -e "SHA256: $(cat ${ARCHIVE_PATH}.sha256 | cut -d' ' -f1)"
echo -e "\nTransfer to forensic server:"
echo -e "  scp ${ARCHIVE_PATH} user@192.168.56.40:/incoming/"
echo -e "${GREEN}════════════════════════════════════════════════════════════════${NC}\n"

# Cleanup uncompressed directory
rm -rf "${OUTPUT_DIR}"

exit 0
