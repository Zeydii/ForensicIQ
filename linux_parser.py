#!/usr/bin/env python3
"""
Linux Forensic Artifact Parser v1

Parses collections from the Linux collector.

Expected structure:
  Collection_YYYYMMDD_HHMMSS/
    MANIFEST.json
    files/       -- df, fstab, mount, suid, hidden, recently_modified
    logs/        -- audit, journalctl, var_log (tarballs + txt)
    memory/      -- memory image if present
    network/     -- arp, netstat, ss, iptables, routes
    persistence/ -- cron, systemd, rc, profile_scripts
    processes/   -- ps_auxf, lsof, pstree, top
    system/      -- os-release, uname, modules, packages
    users/       -- passwd, shadow, sudoers, bash_history, logins

Tools used:
  - log2timeline.py + psort.py  (Plaso)
  - vol.py                       (Volatility3, only if memory image found)
  - bulk_extractor               (only if memory image found, else scans dir)
  - yara / yara-python           (scans extracted text artifacts)

Usage:
  python3 linux_parser.py <collection_dir> <case_id> [options]
  python3 linux_parser.py Collection_20260317_130045 CASE-2026-001
  python3 linux_parser.py Collection_20260317_130045 CASE-2026-001 --memory /tmp/mem.lime
  python3 linux_parser.py Collection_20260317_130045 CASE-2026-001 --yara /opt/rules/malware.yar
"""

import argparse
import csv
import json
import logging
import os
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
from datetime import datetime
from pathlib import Path
from typing import List, Optional, Tuple

# ======================================================================
# LOGGING
# ======================================================================

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('linux_parser.log', encoding='utf-8'),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)

# ======================================================================
# CONFIG
# ======================================================================

CONFIG = {
    'tools': {
        'log2timeline': 'log2timeline.py',
        'psort':        'psort.py',
        'vol':          '/root/forensic_tools/volatility3/vol.py',
        'bulk_extractor': 'bulk_extractor',
        'yara':         'yara',
    },
    'timeouts': {
        'log2timeline':  7200,
        'psort':          600,
        'vol':           1800,
        'bulk_extractor': 3600,
        'yara':           300,
    },
    'output_base': Path('/cases/parsed/linux'),

    # Volatility3 linux plugins to run when a memory image is found
    'vol_plugins': [
        ('linux.pslist.PsList',                         'pslist.csv'),
        ('linux.pstree.PsTree',                         'pstree.csv'),
        ('linux.psaux.PsAux',                           'psaux.csv'),
        ('linux.lsmod.Lsmod',                           'lsmod.csv'),
        ('linux.sockstat.Sockstat',                     'sockstat.csv'),
        ('linux.lsof.Lsof',                             'lsof.csv'),
        ('linux.bash.Bash',                             'bash_memory.csv'),
        ('linux.envars.Envars',                         'envars.csv'),
        ('linux.capabilities.Capabilities',             'capabilities.csv'),
        ('linux.ebpf.EBPF',                             'ebpf.csv'),
        ('linux.malware.malfind.Malfind',               'malfind.csv'),
        ('linux.malware.hidden_modules.Hidden_modules', 'hidden_modules.csv'),
        ('linux.malware.check_syscall.Check_syscall',   'syscall_hooks.csv'),
        ('linux.malware.check_modules.Check_modules',   'module_check.csv'),
        ('linux.malware.netfilter.Netfilter',           'netfilter.csv'),
        ('linux.malware.check_creds.Check_creds',       'cred_sharing.csv'),
        ('timeliner.Timeliner',                         'vol_timeline.csv'),
    ],

    # Inline YARA rules used when no --yara file is provided
    'yara_inline': r"""
rule ReverseshellPatterns {
    strings:
        $nc1 = "nc -e /bin/sh" nocase
        $nc2 = "nc -e /bin/bash" nocase
        $py  = "python -c 'import socket" nocase
        $tcp = "/dev/tcp/" nocase
        $mkf = "mkfifo" nocase
    condition:
        any of them
}
rule SuspiciousDownloadExecute {
    strings:
        $a = "curl" nocase
        $b = "wget" nocase
        $c = "bash -i" nocase
        $d = "chmod +x /tmp" nocase
        $e = "base64 -d" nocase
    condition:
        2 of them
}
rule CredentialPatterns {
    strings:
        $pw  = "password=" nocase
        $tok = "Bearer " nocase
        $aws = "AKIA"
        $key = "-----BEGIN" nocase
    condition:
        any of them
}
rule CronPersistence {
    strings:
        $cron = "* * * * *"
        $sudo = "NOPASSWD" nocase
        $dl   = "curl" nocase
    condition:
        2 of them
}
""",
}

# Known-suspicious process names
SUSPICIOUS_PROCS = {
    'mimikatz', 'meterpreter', 'empire', 'metasploit', 'nmap', 'masscan',
    'hydra', 'john', 'hashcat', 'aircrack', 'socat', 'ngrok', 'chisel',
    'ligolo', 'frp', 'pwncat', 'backdoor', 'rootkit', 'keylogger',
    'cryptominer', 'xmrig', 'kworker_', 'sshd_',
}

# Ports commonly used for reverse shells / C2
SUSPICIOUS_PORTS = {4444, 4445, 5555, 6666, 7777, 8888, 9999, 1337, 31337, 2222}

# Timeline merge sources (glob relative to output_dir, ts_col, label, extra_cols)
TIMELINE_SOURCES = [
    ('05_plaso/linux_timeline.csv', 'datetime',   'plaso',
     ['timestamp_desc', 'source', 'source_long', 'message', 'filename']),
    ('06_memory/pslist.csv',        'CreateTime', 'vol_ps',
     ['PID', 'PPID', 'Name']),
    ('06_memory/bash_memory.csv',   'Time',       'vol_bash',
     ['PID', 'Process', 'Command']),
    ('06_memory/malfind.csv',       'Start',      'vol_malfind',
     ['PID', 'Name', 'Protection']),
]

# ======================================================================
# HELPERS
# ======================================================================

def find_tool(name: str, override: Optional[str] = None) -> Optional[str]:
    p = override or CONFIG['tools'].get(name, name)
    if Path(p).exists():
        return p
    found = shutil.which(p)
    if found:
        return found
    logger.warning(f'[SKIP] {name} not found: {p}')
    return None


def run(label: str, cmd: List[str], timeout: Optional[int] = None,
        stdout_file=None) -> bool:
    t = timeout or CONFIG['timeouts'].get(label, 300)
    try:
        result = subprocess.run(
            cmd,
            stdout=stdout_file,
            stderr=subprocess.PIPE,
            timeout=t,
        )
        stderr = result.stderr.decode(errors='replace').strip()
        if result.returncode != 0:
            logger.error(f'[{label}] FAILED (rc={result.returncode})')
            if stderr:
                logger.error(stderr[:500])
            return False
        logger.info(f'[{label}] OK')
        return True
    except subprocess.TimeoutExpired:
        logger.error(f'[{label}] TIMEOUT after {t}s')
        return False
    except Exception as e:
        logger.error(f'[{label}] ERROR: {e}')
        return False


def extract_tar(tar_path: Path, dest: Path) -> bool:
    try:
        dest.mkdir(parents=True, exist_ok=True)
        with tarfile.open(tar_path) as tf:
            tf.extractall(dest)
        return True
    except Exception as e:
        logger.warning(f'tar extract failed ({tar_path.name}): {e}')
        return False


def read_text(path: Path, max_bytes: int = 10 * 1024 * 1024) -> str:
    try:
        with open(path, 'r', encoding='utf-8', errors='replace') as f:
            return f.read(max_bytes)
    except Exception:
        return ''


def write_csv(path: Path, rows: List[dict], fieldnames: Optional[List[str]] = None):
    if not rows:
        return
    fn = fieldnames or list(rows[0].keys())
    with open(path, 'w', newline='', encoding='utf-8') as f:
        w = csv.DictWriter(f, fieldnames=fn, extrasaction='ignore')
        w.writeheader()
        w.writerows(rows)


def save_findings(path: Path, findings: List[str]):
    if not findings:
        return
    with open(path, 'w', encoding='utf-8') as f:
        for line in findings:
            f.write(line + '\n')

# ======================================================================
# PLASO VERSION HELPER
# ======================================================================

def _get_plaso_version(l2t_path: str) -> int:
    """Return plaso version as integer YYYYMMDD. Falls back to 0."""
    try:
        # plaso prints version to both stdout and stderr depending on invocation
        result = subprocess.run(
            [l2t_path, '--version'],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=15,
        )
        output = (result.stdout + result.stderr).decode(errors='replace')
        m = re.search(r'(\d{8})', output)
        if m:
            v = int(m.group(1))
            if 20200101 <= v <= 20991231:   # sanity check it looks like a date
                return v
    except Exception:
        pass
    return 0


def _get_valid_parsers(l2t_path: str) -> set:
    """Query log2timeline for all valid parser names on this installation.

    The --parsers list output mixes description lines and comma-separated
    name lists. We extract every token that looks like a parser name
    (only word chars, digits, underscore, and forward-slash).
    """
    try:
        result = subprocess.run(
            [l2t_path, '--parsers', 'list'],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30,
        )
        output = (result.stdout + result.stderr).decode(errors='replace')
        parsers = set()
        # Parser names are word characters optionally separated by /
        # e.g.  text/bash_history   systemd_journal   utmp
        for token in re.findall(r'\b([a-z][a-z0-9_]*/[a-z][a-z0-9_]+|[a-z][a-z0-9_]{2,})\b', output):
            # Filter out English prose words that sneak through
            if '_' in token or '/' in token or token in (
                'linux', 'utmp', 'utmpx', 'webhist', 'bencode',
                'filestat', 'msiecf', 'olecf',
            ):
                parsers.add(token)
        return parsers
    except Exception:
        return set()


# ======================================================================
# PARSER CLASS
# ======================================================================

class LinuxParser:

    def __init__(self, collection_dir: Path, case_id: str,
                 memory_path: Optional[Path] = None,
                 vol_override: Optional[str] = None,
                 yara_rules: Optional[Path] = None):

        self.collection_dir = collection_dir.resolve()
        self.case_id        = case_id
        self.timestamp      = datetime.now().strftime('%Y%m%d_%H%M%S')
        self.memory_path    = memory_path
        self.vol_override   = vol_override
        self.yara_rules     = yara_rules

        self.output_dir = CONFIG['output_base'] / f'{case_id}_{self.timestamp}'
        self.output_dir.mkdir(parents=True, exist_ok=True)

        self.dirs = {
            'extracted':   self.output_dir / '00_extracted',
            'users':       self.output_dir / '01_users',
            'processes':   self.output_dir / '02_processes',
            'network':     self.output_dir / '03_network',
            'persistence': self.output_dir / '04_persistence',
            'plaso':       self.output_dir / '05_plaso',
            'memory':      self.output_dir / '06_memory',
            'yara':        self.output_dir / '07_yara',
            'system':      self.output_dir / '08_system',
            'files':       self.output_dir / '09_files',
        }
        for d in self.dirs.values():
            d.mkdir(exist_ok=True)

        self.notes: List[str] = []
        self.results: dict = {}

    # ------------------------------------------------------------------
    # [1] UNPACK TARBALLS
    # ------------------------------------------------------------------

    def unpack_archives(self):
        logger.info('\n[1] UNPACKING ARCHIVES')
        count = 0
        for tar_path in sorted(self.collection_dir.rglob('*.tar.gz')):
            dest = self.dirs['extracted'] / tar_path.stem.replace('.tar', '')
            if extract_tar(tar_path, dest):
                logger.info(f'  -> {tar_path.name} -> {dest.name}/')
                count += 1
        logger.info(f'[unpack] {count} archives extracted')
        self.results['archives_extracted'] = count

    # ------------------------------------------------------------------
    # [2] USERS & CREDENTIALS
    # ------------------------------------------------------------------

    def parse_users(self):
        logger.info('\n[2] USERS & CREDENTIALS')
        src = self.collection_dir / 'users'
        if not src.exists():
            logger.warning('[SKIP] users/ not found')
            return

        findings = []

        # passwd
        passwd_file = src / 'passwd.txt'
        passwd_rows = []
        if passwd_file.exists():
            for line in read_text(passwd_file).splitlines():
                parts = line.strip().split(':')
                if len(parts) < 7:
                    continue
                uid = int(parts[2]) if parts[2].isdigit() else -1
                row = {'Username': parts[0], 'UID': uid, 'GID': parts[3],
                       'Home': parts[5], 'Shell': parts[6]}
                passwd_rows.append(row)
                if uid == 0 and parts[0] != 'root':
                    findings.append(f'PASSWD: Non-root user with UID=0: {parts[0]}')
                if uid >= 1000 and '/nologin' not in parts[6] and '/false' not in parts[6]:
                    if '/tmp' in parts[5] or '/dev' in parts[5]:
                        findings.append(f'PASSWD: User home in suspicious path: {parts[0]} -> {parts[5]}')
            write_csv(self.dirs['users'] / 'passwd.csv', passwd_rows)
            logger.info(f'  -> passwd: {len(passwd_rows)} entries')

        # sudoers
        sudoers_file = src / 'sudoers.txt'
        if sudoers_file.exists():
            sudo_rows = []
            for line in read_text(sudoers_file).splitlines():
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                sudo_rows.append({'Rule': line})
                if 'NOPASSWD' in line and 'ALL' in line:
                    findings.append(f'SUDOERS: Unrestricted passwordless sudo: {line}')
            write_csv(self.dirs['users'] / 'sudoers.csv', sudo_rows, ['Rule'])
            logger.info(f'  -> sudoers: {len(sudo_rows)} active rules')

        # bash history files
        history_rows = []
        for hist_file in sorted(src.glob('*bash_history*.txt')):
            username = hist_file.stem.replace('_bash_history', '').replace('bash_history', 'unknown')
            for i, line in enumerate(read_text(hist_file).splitlines(), 1):
                line = line.strip()
                if not line:
                    continue
                history_rows.append({'User': username, 'LineNo': i, 'Command': line})
                lc = line.lower()
                # Flag dangerous patterns
                if any(p in lc for p in ['base64 -d', 'bash -i', '/dev/tcp', 'curl|sh',
                                          'wget -q -O-', 'chmod +x /tmp', 'nc -e', 'nohup',
                                          'python -c', 'perl -e']):
                    findings.append(f'BASH_HISTORY [{username}]: {line}')
                for sp in SUSPICIOUS_PROCS:
                    if sp in lc:
                        findings.append(f'BASH_HISTORY [{username}] suspicious tool: {line}')
                        break
        write_csv(self.dirs['users'] / 'bash_history.csv', history_rows,
                  ['User', 'LineNo', 'Command'])
        logger.info(f'  -> bash_history: {len(history_rows)} commands across all users')

        # shadow: empty password detection
        shadow_file = src / 'shadow.txt'
        if shadow_file.exists():
            for line in read_text(shadow_file).splitlines():
                parts = line.strip().split(':')
                if len(parts) >= 2:
                    user, pw = parts[0], parts[1]
                    if pw == '':
                        findings.append(f'SHADOW: Empty (no) password for user: {user}')

        # login records -- pass through as CSV rows
        for fname, dest in [('last_logins.txt', 'last_logins.csv'),
                             ('failed_logins.txt', 'failed_logins.csv'),
                             ('lastlog.txt', 'lastlog.csv'),
                             ('logged_in_who.txt', 'logged_in_who.csv'),
                             ('logged_in_w.txt', 'logged_in_w.csv')]:
            f = src / fname
            if f.exists():
                rows = [{'Line': l.strip()} for l in read_text(f).splitlines() if l.strip()]
                write_csv(self.dirs['users'] / dest, rows, ['Line'])
                logger.info(f'  -> {fname}: {len(rows)} lines')

        # group
        group_file = src / 'group.txt'
        if group_file.exists():
            shutil.copy2(group_file, self.dirs['users'] / 'group.txt')

        self.notes.extend(findings)
        save_findings(self.dirs['users'] / 'findings_users.txt', findings)
        logger.info(f'  -> {len(findings)} findings')

    # ------------------------------------------------------------------
    # [3] PROCESSES
    # ------------------------------------------------------------------

    def parse_processes(self):
        logger.info('\n[3] PROCESSES')
        src = self.collection_dir / 'processes'
        if not src.exists():
            logger.warning('[SKIP] processes/ not found')
            return

        findings = []

        # ps_auxf -> structured CSV
        ps_file = src / 'ps_auxf.txt'
        if ps_file.exists():
            lines = read_text(ps_file).splitlines()
            ps_rows = []
            header = None
            for line in lines:
                line_stripped = line.strip()
                if not line_stripped:
                    continue
                if header is None:
                    header = re.split(r'\s+', line_stripped, maxsplit=10)
                    continue
                parts = re.split(r'\s+', line_stripped, maxsplit=len(header) - 1)
                if len(parts) < 2:
                    continue
                row = dict(zip(header, parts + [''] * max(0, len(header) - len(parts))))
                ps_rows.append(row)
                cmd = ' '.join([row.get('COMMAND', ''), row.get('CMD', '')]).lower()
                for sp in SUSPICIOUS_PROCS:
                    if sp in cmd:
                        findings.append(f'PROCESS: Suspicious binary: {cmd.strip()}')
                        break
                if any(p in cmd for p in ['/tmp/', '/dev/shm/', '/var/tmp/']):
                    findings.append(f'PROCESS: Executing from temp dir: {cmd.strip()}')
            write_csv(self.dirs['processes'] / 'ps_auxf.csv', ps_rows)
            logger.info(f'  -> ps_auxf: {len(ps_rows)} processes')

        # lsof -> structured CSV
        lsof_file = src / 'lsof.txt'
        if lsof_file.exists():
            lines = read_text(lsof_file).splitlines()
            lsof_rows = []
            header = None
            for line in lines:
                line = line.strip()
                if not line:
                    continue
                if header is None:
                    header = re.split(r'\s+', line, maxsplit=8)
                    continue
                parts = re.split(r'\s+', line, maxsplit=len(header) - 1)
                if len(parts) >= 4:
                    row = dict(zip(header, parts + [''] * max(0, len(header) - len(parts))))
                    lsof_rows.append(row)
            write_csv(self.dirs['processes'] / 'lsof.csv', lsof_rows)
            logger.info(f'  -> lsof: {len(lsof_rows)} open files')

        # pass-through remaining process files
        for fname in ['pstree.txt', 'ps_detailed.txt', 'top.txt']:
            f = src / fname
            if f.exists():
                shutil.copy2(f, self.dirs['processes'] / fname)

        self.notes.extend(findings)
        save_findings(self.dirs['processes'] / 'findings_processes.txt', findings)
        logger.info(f'  -> {len(findings)} findings')

    # ------------------------------------------------------------------
    # [4] NETWORK
    # ------------------------------------------------------------------

    def parse_network(self):
        logger.info('\n[4] NETWORK')
        src = self.collection_dir / 'network'
        if not src.exists():
            logger.warning('[SKIP] network/ not found')
            return

        findings = []

        # parse netstat / ss files into CSV
        for fname, dest in [('netstat_tcp.txt', 'netstat_tcp.csv'),
                             ('netstat_udp.txt', 'netstat_udp.csv'),
                             ('ss_tcp.txt',      'ss_tcp.csv'),
                             ('ss_udp.txt',      'ss_udp.csv')]:
            f = src / fname
            if not f.exists():
                continue
            lines = read_text(f).splitlines()
            rows = []
            header = None
            for line in lines:
                line = line.strip()
                if not line or 'Active Internet' in line:
                    continue
                if 'Recv-Q' in line or 'State' in line or 'Netid' in line:
                    header = re.split(r'\s+', line)
                    continue
                parts = re.split(r'\s+', line)
                row = (dict(zip(header, parts + [''] * max(0, len(header) - len(parts))))
                       if header else {'Line': line})
                rows.append(row)
                for port in SUSPICIOUS_PORTS:
                    if f':{port}' in line or f' {port} ' in line:
                        findings.append(f'NETWORK [{fname}]: Suspicious port {port} -> {line}')
            write_csv(self.dirs['network'] / dest, rows)
            logger.info(f'  -> {fname}: {len(rows)} connections')

        # iptables / ufw
        for fname in ['iptables.txt', 'ufw_status.txt']:
            f = src / fname
            if f.exists():
                content = read_text(f)
                shutil.copy2(f, self.dirs['network'] / fname)
                if 'ufw' in fname and 'inactive' in content.lower():
                    findings.append('NETWORK: UFW firewall is INACTIVE')

        # copy remaining files
        for fname in ['arp.txt', 'arp_cache.txt', 'hosts.txt', 'resolv.conf',
                       'route.txt', 'routing_table.txt', 'ifconfig.txt',
                       'ip_addr.txt', 'listening_ports.txt']:
            f = src / fname
            if f.exists():
                shutil.copy2(f, self.dirs['network'] / fname)

        self.notes.extend(findings)
        save_findings(self.dirs['network'] / 'findings_network.txt', findings)
        logger.info(f'  -> {len(findings)} findings')

    # ------------------------------------------------------------------
    # [5] PERSISTENCE
    # ------------------------------------------------------------------

    def parse_persistence(self):
        logger.info('\n[5] PERSISTENCE')
        src = self.collection_dir / 'persistence'
        if not src.exists():
            logger.warning('[SKIP] persistence/ not found')
            return

        findings = []
        all_rows = []

        # plain cron files
        for fname in ['etc_crontab.txt', 'root_crontab.txt', 'cron_directories.txt']:
            f = src / fname
            if f.exists():
                for line in read_text(f).splitlines():
                    line = line.strip()
                    if not line or line.startswith('#'):
                        continue
                    all_rows.append({'Source': fname, 'Entry': line})
                    lc = line.lower()
                    if any(s in lc for s in ['curl', 'wget', 'bash -i', '/tmp/', 'python -c', 'nc ']):
                        findings.append(f'CRON [{fname}]: Suspicious entry: {line}')

        # cron_files tarball
        cron_tar = src / 'cron_files.tar.gz'
        if cron_tar.exists():
            cron_dest = self.dirs['extracted'] / 'cron_files'
            extract_tar(cron_tar, cron_dest)
            for f in sorted(cron_dest.rglob('*')):
                if not f.is_file():
                    continue
                for line in read_text(f).splitlines():
                    lc = line.lower().strip()
                    if lc and not lc.startswith('#'):
                        if any(s in lc for s in ['curl', 'wget', '/tmp/', 'bash -i', 'nc ']):
                            findings.append(f'CRON_FILE [{f.name}]: {line.strip()}')

        # systemd services list
        svc_file = src / 'systemd_services.txt'
        if svc_file.exists():
            rows = [{'Service': l.strip()} for l in read_text(svc_file).splitlines() if l.strip()]
            write_csv(self.dirs['persistence'] / 'systemd_services.csv', rows, ['Service'])
            logger.info(f'  -> systemd_services: {len(rows)} entries')

        # systemd unit files tarball -- scan ExecStart lines
        svc_tar = src / 'systemd_services.tar.gz'
        if svc_tar.exists():
            svc_dest = self.dirs['extracted'] / 'systemd_units'
            extract_tar(svc_tar, svc_dest)
            for f in sorted(svc_dest.rglob('*.service')):
                for line in read_text(f).splitlines():
                    lc = line.lower()
                    if 'execstart' in lc:
                        all_rows.append({'Source': f'systemd/{f.name}', 'Entry': line.strip()})
                        if any(s in lc for s in ['/tmp/', '/dev/shm', 'curl', 'wget', 'bash -i']):
                            findings.append(f'SYSTEMD [{f.name}]: Suspicious ExecStart: {line.strip()}')

        # profile scripts tarball
        prof_tar = src / 'profile_scripts.tar.gz'
        if prof_tar.exists():
            prof_dest = self.dirs['extracted'] / 'profile_scripts'
            extract_tar(prof_tar, prof_dest)
            for f in sorted(prof_dest.rglob('*')):
                if not f.is_file():
                    continue
                for line in read_text(f).splitlines():
                    lc = line.lower().strip()
                    if lc and not lc.startswith('#'):
                        all_rows.append({'Source': f'profile/{f.name}', 'Entry': line.strip()})
                        if any(s in lc for s in ['curl', 'wget', '/tmp/', 'bash -i', 'nc -e', 'base64']):
                            findings.append(f'PROFILE [{f.name}]: Suspicious line: {line.strip()}')

        # init.d and rc directories
        for fname, dest in [('init_d.txt', 'init_d.csv'), ('rc_directories.txt', 'rc_directories.csv')]:
            f = src / fname
            if f.exists():
                rows = [{'Entry': l.strip()} for l in read_text(f).splitlines() if l.strip()]
                write_csv(self.dirs['persistence'] / dest, rows, ['Entry'])

        write_csv(self.dirs['persistence'] / 'all_persistence.csv', all_rows, ['Source', 'Entry'])
        self.notes.extend(findings)
        save_findings(self.dirs['persistence'] / 'findings_persistence.txt', findings)
        logger.info(f'  -> {len(findings)} findings, {len(all_rows)} total persistence entries')

    # ------------------------------------------------------------------
    # [6] FILES (suid, hidden, recently modified)
    # ------------------------------------------------------------------

    def parse_files(self):
        logger.info('\n[6] FILES')
        src = self.collection_dir / 'files'
        if not src.exists():
            logger.warning('[SKIP] files/ not found')
            return

        findings = []

        # SUID/SGID files -- anything unexpected is notable
        suid_file = src / 'suid_sgid_files.txt'
        if suid_file.exists():
            rows = []
            for line in read_text(suid_file).splitlines():
                line = line.strip()
                if not line:
                    continue
                rows.append({'Path': line})
                # Flag SUID binaries in unusual locations
                if any(p in line for p in ['/tmp/', '/home/', '/var/', '/dev/']):
                    findings.append(f'SUID: SUID/SGID in unusual location: {line}')
            write_csv(self.dirs['files'] / 'suid_sgid.csv', rows, ['Path'])
            logger.info(f'  -> suid_sgid: {len(rows)} entries')

        # Hidden files
        hidden_file = src / 'hidden_files_tmp.txt'
        if hidden_file.exists():
            rows = [{'Path': l.strip()} for l in read_text(hidden_file).splitlines() if l.strip()]
            write_csv(self.dirs['files'] / 'hidden_files.csv', rows, ['Path'])
            if rows:
                findings.append(f'FILES: {len(rows)} hidden files found in /tmp and similar dirs')
            logger.info(f'  -> hidden_files: {len(rows)} entries')

        # Recently modified files (7 days)
        recent_file = src / 'recently_modified_7days.txt'
        if recent_file.exists():
            rows = [{'Path': l.strip()} for l in read_text(recent_file).splitlines() if l.strip()]
            write_csv(self.dirs['files'] / 'recently_modified.csv', rows, ['Path'])
            logger.info(f'  -> recently_modified: {len(rows)} files')

        # Copy mount and fstab info
        for fname in ['df.txt', 'fstab.txt', 'mount.txt']:
            f = src / fname
            if f.exists():
                shutil.copy2(f, self.dirs['files'] / fname)

        self.notes.extend(findings)
        save_findings(self.dirs['files'] / 'findings_files.txt', findings)
        logger.info(f'  -> {len(findings)} findings')

    # ------------------------------------------------------------------
    # [7] SYSTEM INFO
    # ------------------------------------------------------------------

    def parse_system(self):
        logger.info('\n[7] SYSTEM INFO')
        src = self.collection_dir / 'system'
        if not src.exists():
            logger.warning('[SKIP] system/ not found')
            return

        findings = []

        # Copy all .txt files
        for f in sorted(src.glob('*.txt')):
            shutil.copy2(f, self.dirs['system'] / f.name)

        # lsmod -> structured CSV
        lsmod_file = src / 'lsmod.txt'
        if lsmod_file.exists():
            rows = []
            for line in read_text(lsmod_file).splitlines()[1:]:
                parts = re.split(r'\s+', line.strip(), maxsplit=4)
                if len(parts) >= 3:
                    rows.append({'Module': parts[0], 'Size': parts[1],
                                 'Used': parts[2], 'UsedBy': parts[3] if len(parts) > 3 else ''})
            write_csv(self.dirs['system'] / 'lsmod.csv', rows)
            logger.info(f'  -> lsmod: {len(rows)} modules')

        # Cross-reference lsmod vs proc/modules for hidden module detection
        proc_mod_file = src / 'proc_modules.txt'
        if proc_mod_file.exists() and lsmod_file.exists():
            proc_mods = {l.split()[0] for l in read_text(proc_mod_file).splitlines() if l.split()}
            lsmod_mods = {l.split()[0] for l in read_text(lsmod_file).splitlines()[1:] if l.split()}
            hidden = proc_mods - lsmod_mods
            if hidden:
                findings.append(f'MODULES: In /proc/modules but NOT in lsmod (possible rootkit): {", ".join(sorted(hidden))}')

        # installed packages
        for fname in ['installed_packages_apt.txt', 'installed_packages_dpkg.txt']:
            f = src / fname
            if f.exists():
                rows = [{'Package': l.strip()} for l in read_text(f).splitlines() if l.strip()]
                write_csv(self.dirs['system'] / fname.replace('.txt', '.csv'), rows, ['Package'])
                logger.info(f'  -> {fname}: {len(rows)} packages')

        self.notes.extend(findings)
        save_findings(self.dirs['system'] / 'findings_system.txt', findings)
        logger.info(f'  -> {len(findings)} findings')

    # ------------------------------------------------------------------
    # [8] PLASO TIMELINE
    # ------------------------------------------------------------------

    def run_plaso(self):
        logger.info('\n[8] PLASO TIMELINE')

        l2t   = find_tool('log2timeline')
        psort = find_tool('psort')
        if not l2t or not psort:
            logger.warning('[SKIP] log2timeline or psort not available')
            return

        plaso_file = self.dirs['plaso'] / 'linux.plaso'
        log_file   = self.dirs['plaso'] / 'log2timeline.log'
        out_csv    = self.dirs['plaso'] / 'linux_timeline.csv'

        # ----------------------------------------------------------------
        # Step 1: detect version and query valid parser names dynamically
        # ----------------------------------------------------------------
        plaso_version = _get_plaso_version(l2t)
        logger.info(f'  [plaso] version detected: {plaso_version}')

        valid_parsers = _get_valid_parsers(l2t)
        logger.info(f'  [plaso] {len(valid_parsers)} valid parsers found on this install')

        # Candidate parsers we want -- pick only those actually installed
        wanted = [
            'linux',              # preset covering utmp, syslog, dpkg, etc.
            'systemd_journal',    # journald binary logs
            'text/bash_history',  # bash_history files
            'text/apt_history',   # /var/log/apt/history.log
            'text/dpkg',          # /var/log/dpkg.log
            'text/syslog',        # /var/log/syslog
            'text/syslog_traditional',
            'text/zsh_extended_history',
            'utmp',               # login records
        ]

        # Always include 'linux' preset (it is always valid)
        # For extras, only add if found in the valid parsers list
        confirmed = ['linux']
        skipped   = []
        for p in wanted[1:]:   # skip 'linux' -- already added
            if not valid_parsers or p in valid_parsers:
                # If we could not query the list, include all and let plaso warn
                confirmed.append(p)
            else:
                skipped.append(p)

        if skipped:
            logger.info(f'  [plaso] Skipping parsers not in this install: {", ".join(skipped)}')

        parser_filter = ','.join(confirmed)
        logger.info(f'  [plaso] Using parsers: {parser_filter}')

        # ----------------------------------------------------------------
        # Step 2: run log2timeline
        # ----------------------------------------------------------------
        cmd_l2t = [
            l2t,
            '--parsers', parser_filter,
            '--hashers', 'md5,sha256',
            '--status_view', 'none',
            '--unattended',
            '-q',
            '--logfile', str(log_file),
            '--storage_file', str(plaso_file),
            str(self.collection_dir),
        ]
        ok = run('log2timeline', cmd_l2t, timeout=CONFIG['timeouts']['log2timeline'])

        # Fallback: linux preset only (guaranteed safe on all plaso versions)
        if not ok or not plaso_file.exists():
            logger.warning('[plaso] Attempt 1 failed -- retrying with linux preset only')
            plaso_file.unlink(missing_ok=True)
            ok = run('log2timeline_fallback', [
                l2t,
                '--parsers', 'linux',
                '--status_view', 'none',
                '--unattended',
                '-q',
                '--logfile', str(log_file),
                '--storage_file', str(plaso_file),
                str(self.collection_dir),
            ], timeout=CONFIG['timeouts']['log2timeline'])

        if not ok or not plaso_file.exists():
            logger.error('[plaso] Both attempts failed. Check: ' + str(log_file))
            return

        # ----------------------------------------------------------------
        # Step 3: export .plaso -> CSV via psort
        # ----------------------------------------------------------------
        cmd_psort = [
            psort,
            '-o', 'dynamic',
            '-w', str(out_csv),
            '--fields', 'datetime,timestamp_desc,source,source_long,message,filename,inode,hostname',
            '--status_view', 'none',
            '--unattended',
            '-q',
            str(plaso_file),
        ]
        run('psort', cmd_psort, timeout=CONFIG['timeouts']['psort'])

        if out_csv.exists():
            size_kb = out_csv.stat().st_size // 1024
            try:
                with open(out_csv, 'r', encoding='utf-8', errors='replace') as f:
                    row_count = sum(1 for _ in f) - 1
            except Exception:
                row_count = 0
            logger.info(f'[plaso] {row_count:,} events -> linux_timeline.csv ({size_kb} KB)')
            self.results['plaso_rows'] = row_count
        else:
            logger.warning('[plaso] psort produced no CSV output')
    # ------------------------------------------------------------------
    # [9] VOLATILITY3
    # ------------------------------------------------------------------

    def run_volatility(self):
        logger.info('\n[9] VOLATILITY3')

        # Find memory image
        mem_img = self.memory_path
        if not mem_img:
            mem_src = self.collection_dir / 'memory'
            for ext in ['*.lime', '*.mem', '*.raw', '*.dump', '*.img']:
                candidates = list(mem_src.glob(ext))
                if candidates:
                    mem_img = candidates[0]
                    break

        if not mem_img or not mem_img.exists():
            logger.warning('[SKIP] No memory image found. Use --memory /path/to/image.lime')
            return

        vol = find_tool('vol', self.vol_override)
        if not vol:
            return

        logger.info(f'  Image: {mem_img}')
        ok_count = 0

        for plugin, out_name in CONFIG['vol_plugins']:
            out_file = self.dirs['memory'] / out_name
            cmd = [
                sys.executable, vol,
                '-q',
                '-r', 'csv',
                '-f', str(mem_img),
                plugin,
            ]
            try:
                with open(out_file, 'w', encoding='utf-8') as fout:
                    result = subprocess.run(
                        cmd,
                        stdout=fout,
                        stderr=subprocess.PIPE,
                        timeout=CONFIG['timeouts']['vol'],
                    )
                if result.returncode == 0 and out_file.stat().st_size > 20:
                    logger.info(f'  [vol] {plugin} -> {out_name}')
                    ok_count += 1
                else:
                    out_file.unlink(missing_ok=True)
                    err = result.stderr.decode(errors='replace').strip()
                    if err:
                        logger.warning(f'  [vol] {plugin}: {err[:150]}')
            except subprocess.TimeoutExpired:
                logger.warning(f'  [vol] {plugin}: TIMEOUT')
                out_file.unlink(missing_ok=True)
            except Exception as e:
                logger.warning(f'  [vol] {plugin}: ERROR {e}')
                out_file.unlink(missing_ok=True)

        logger.info(f'[vol] {ok_count}/{len(CONFIG["vol_plugins"])} plugins succeeded')
        self.results['vol_plugins_ok'] = ok_count

        # Flag malfind hits
        malfind_csv = self.dirs['memory'] / 'malfind.csv'
        if malfind_csv.exists():
            try:
                with open(malfind_csv, 'r', encoding='utf-8', errors='replace') as f:
                    rows = list(csv.DictReader(f))
                if rows:
                    self.notes.append(f'MEMORY: malfind found {len(rows)} suspicious memory regions')
                    for r in rows[:10]:
                        self.notes.append(
                            f'  MALFIND PID={r.get("PID","?")} Name={r.get("Name","?")} Prot={r.get("Protection","")}')
            except Exception:
                pass

        # Flag hidden modules from vol
        hmod_csv = self.dirs['memory'] / 'hidden_modules.csv'
        if hmod_csv.exists() and hmod_csv.stat().st_size > 50:
            self.notes.append('MEMORY: Volatility detected hidden kernel modules -- review hidden_modules.csv')

        # Flag syscall hooks
        hook_csv = self.dirs['memory'] / 'syscall_hooks.csv'
        if hook_csv.exists() and hook_csv.stat().st_size > 50:
            self.notes.append('MEMORY: Volatility detected syscall hooks -- review syscall_hooks.csv')

    # ------------------------------------------------------------------
    # [10] BULK_EXTRACTOR
    # ------------------------------------------------------------------

    def run_bulk_extractor(self):
        logger.info('\n[10] BULK_EXTRACTOR')

        be = find_tool('bulk_extractor')
        if not be:
            return

        # Prefer memory image, fall back to collection dir (recursive scan)
        target = self.memory_path
        if not target:
            mem_src = self.collection_dir / 'memory'
            for ext in ['*.lime', '*.mem', '*.raw', '*.dump']:
                candidates = list(mem_src.glob(ext))
                if candidates:
                    target = candidates[0]
                    break

        be_out = self.dirs['yara'] / 'bulk_extractor'
        be_out.mkdir(exist_ok=True)

        if target and target.exists():
            logger.info(f'  [be] Scanning memory image: {target.name}')
            cmd = [be, '-o', str(be_out), '-j', '4', '-q', '-0', str(target)]
        else:
            logger.info('  [be] No memory image -- scanning collection directory recursively')
            cmd = [be, '-o', str(be_out), '-R', '-j', '4', '-q', '-0', str(self.collection_dir)]

        be_log = be_out / 'bulk_extractor.log'
        try:
            with open(be_log, 'w', encoding='utf-8') as blog:
                result = subprocess.run(
                    cmd,
                    stdout=blog,
                    stderr=blog,
                    timeout=CONFIG['timeouts']['bulk_extractor'],
                )
            if result.returncode == 0:
                logger.info('[bulk_extractor] OK')
            else:
                logger.error(f'[bulk_extractor] FAILED (rc={result.returncode}) -- see {be_log}')
        except subprocess.TimeoutExpired:
            logger.error('[bulk_extractor] TIMEOUT')
        except Exception as e:
            logger.error(f'[bulk_extractor] ERROR: {e}')

        # Summarise output files
        for report in sorted(be_out.glob('*.txt')):
            lines = [l for l in read_text(report).splitlines()
                     if l.strip() and not l.startswith('#')]
            if lines:
                logger.info(f'  [be] {report.name}: {len(lines)} hits')
                # Add first few IPs / domains / URLs to notes
                if report.stem in ('ip', 'domain', 'email', 'url'):
                    for hit in lines[:5]:
                        self.notes.append(f'BULK_EXTRACTOR [{report.stem}]: {hit.split(chr(9))[0]}')

    # ------------------------------------------------------------------
    # [11] YARA
    # ------------------------------------------------------------------

    def run_yara(self):
        logger.info('\n[11] YARA SCAN')

        yara_bin = find_tool('yara')

        # Write inline rules to temp file if no external rules provided
        rules_file = self.yara_rules
        temp_rules_path = None
        if not rules_file or not rules_file.exists():
            tmp = tempfile.NamedTemporaryFile(
                mode='w', suffix='.yar', delete=False, encoding='utf-8')
            tmp.write(CONFIG['yara_inline'])
            tmp.flush()
            tmp.close()
            rules_file = Path(tmp.name)
            temp_rules_path = tmp.name
            logger.info('  [yara] Using built-in inline rules')

        # Targets: text CSVs from users + persistence + extracted archives
        targets = (
            list(self.dirs['users'].glob('*.csv')) +
            list(self.dirs['persistence'].glob('*.csv')) +
            list(self.dirs['extracted'].rglob('*'))
        )
        targets = [t for t in targets if t.is_file() and t.stat().st_size < 20 * 1024 * 1024]

        yara_hits = []

        if yara_bin:
            for target in targets:
                try:
                    result = subprocess.run(
                        [yara_bin, str(rules_file), str(target)],
                        stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                        timeout=30,
                    )
                    out = result.stdout.decode(errors='replace').strip()
                    for line in out.splitlines():
                        parts = line.split()
                        rule = parts[0] if parts else ''
                        yara_hits.append({'Rule': rule, 'File': str(target), 'Match': line})
                        self.notes.append(f'YARA [{rule}]: {target.name}')
                except Exception:
                    pass
        else:
            # Fallback: try yara-python
            try:
                import yara as yara_py
                compiled = yara_py.compile(str(rules_file))
                for target in targets:
                    try:
                        for m in compiled.match(str(target)):
                            yara_hits.append({'Rule': m.rule, 'File': str(target), 'Match': str(m)})
                            self.notes.append(f'YARA [{m.rule}]: {target.name}')
                    except Exception:
                        pass
                logger.info('[yara] Used yara-python library (no yara binary)')
            except ImportError:
                logger.warning('[SKIP] Neither yara binary nor yara-python found')

        if temp_rules_path:
            try:
                os.unlink(temp_rules_path)
            except Exception:
                pass

        if yara_hits:
            write_csv(self.dirs['yara'] / 'yara_hits.csv', yara_hits, ['Rule', 'File', 'Match'])
            logger.info(f'[yara] {len(yara_hits)} hits -> yara_hits.csv')
        else:
            logger.info('[yara] No hits')

    # ------------------------------------------------------------------
    # [12] MASTER TIMELINE
    # ------------------------------------------------------------------

    def build_master_timeline(self):
        logger.info('\n[TIMELINE] Building master timeline')
        timeline_rows = []

        for glob_pat, ts_col, source_label, extra_cols in TIMELINE_SOURCES:
            for csv_path in sorted(self.output_dir.glob(glob_pat)):
                try:
                    with open(csv_path, 'r', encoding='utf-8-sig', errors='replace') as f:
                        reader = csv.DictReader(f)
                        if ts_col not in (reader.fieldnames or []):
                            continue
                        for row in reader:
                            ts = row.get(ts_col, '').strip()
                            if not ts:
                                continue
                            entry = {'Timestamp': ts, 'Source': source_label,
                                     'SourceFile': csv_path.name}
                            for col in extra_cols:
                                entry[col] = row.get(col, '')
                            timeline_rows.append(entry)
                except Exception as e:
                    logger.warning(f'Timeline read error ({csv_path.name}): {e}')

        if not timeline_rows:
            logger.warning('[TIMELINE] No events -- Plaso must succeed for a timeline')
            return

        timeline_rows.sort(key=lambda r: r.get('Timestamp', ''))
        out_path = self.output_dir / 'MASTER_TIMELINE.csv'
        fieldnames = ['Timestamp', 'Source', 'SourceFile'] + sorted(
            {k for r in timeline_rows for k in r
             if k not in ('Timestamp', 'Source', 'SourceFile')}
        )
        with open(out_path, 'w', newline='', encoding='utf-8') as f:
            w = csv.DictWriter(f, fieldnames=fieldnames, extrasaction='ignore')
            w.writeheader()
            w.writerows(timeline_rows)

        logger.info(f'[TIMELINE] {len(timeline_rows):,} events -> MASTER_TIMELINE.csv')
        self.results['timeline_rows'] = len(timeline_rows)

    # ------------------------------------------------------------------
    # [13] PARSE SUMMARY
    # ------------------------------------------------------------------

    def write_summary(self):
        counts = {}
        for name, d in self.dirs.items():
            csv_files = list(d.rglob('*.csv'))
            rows = 0
            for f in csv_files:
                try:
                    rows += max(0, sum(1 for _ in open(f, encoding='utf-8', errors='replace')) - 1)
                except Exception:
                    pass
            counts[name] = {'csv_files': len(csv_files), 'rows': rows}

        summary = {
            'schema':          'LinuxParseSummary/v1',
            'case_id':         self.case_id,
            'parsed_at':       datetime.now().isoformat(),
            'collection_dir':  str(self.collection_dir),
            'output_dir':      str(self.output_dir),
            'artifact_counts': counts,
            'timeline_rows':   self.results.get('timeline_rows', 0),
            'plaso_rows':      self.results.get('plaso_rows', 0),
            'vol_plugins_ok':  self.results.get('vol_plugins_ok', 0),
            'total_findings':  len(self.notes),
            'findings':        self.notes[:300],
        }

        out_path = self.output_dir / 'PARSE_SUMMARY.json'
        with open(out_path, 'w', encoding='utf-8') as f:
            json.dump(summary, f, indent=2)

        logger.info(f'[SUMMARY] Written -> PARSE_SUMMARY.json')
        logger.info(f'[SUMMARY] Total findings: {len(self.notes)}')
        # Surface highest-priority notes
        for note in self.notes:
            if any(k in note for k in ['UID=0', 'NOPASSWD', 'malfind', 'YARA',
                                        'BASH_HISTORY', 'hidden_modules', 'syscall_hooks']):
                logger.warning(f'  * {note}')

    # ------------------------------------------------------------------
    # RUN ALL
    # ------------------------------------------------------------------

    def run_all(self):
        self.unpack_archives()
        self.parse_users()
        self.parse_processes()
        self.parse_network()
        self.parse_persistence()
        self.parse_files()
        self.parse_system()
        self.run_plaso()
        self.run_volatility()
        self.run_bulk_extractor()
        self.run_yara()
        self.build_master_timeline()
        self.write_summary()

# ======================================================================
# MAIN
# ======================================================================

def main():
    ap = argparse.ArgumentParser(
        description='Linux Forensic Artifact Parser v1',
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    ap.add_argument('collection_dir',
                    help='Path to Collection_YYYYMMDD_HHMMSS/ directory')
    ap.add_argument('case_id',
                    help='Case identifier, e.g. CASE-2026-001')
    ap.add_argument('--memory', metavar='PATH',
                    help='Path to a memory image (.lime / .raw / .mem)')
    ap.add_argument('--vol', metavar='PATH',
                    help='Override path to vol.py (default: from CONFIG)')
    ap.add_argument('--yara', metavar='PATH',
                    help='Path to a YARA rules file (.yar)')
    ap.add_argument('--outdir', metavar='PATH',
                    help='Override output base directory (default: /cases/parsed/linux)')
    args = ap.parse_args()

    collection_dir = Path(args.collection_dir)
    if not collection_dir.exists():
        print(f'ERROR: not found: {collection_dir}')
        sys.exit(1)

    if args.outdir:
        CONFIG['output_base'] = Path(args.outdir)

    parser = LinuxParser(
        collection_dir = collection_dir,
        case_id        = args.case_id,
        memory_path    = Path(args.memory) if args.memory else None,
        vol_override   = args.vol,
        yara_rules     = Path(args.yara) if args.yara else None,
    )
    parser.run_all()
    logger.info(f'\nPARSING COMPLETE: {parser.output_dir}')

if __name__ == '__main__':
    main()
