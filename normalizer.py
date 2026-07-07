#!/usr/bin/env python3
"""
Forensic Artifact Normalizer v1
Merges Windows (windows_parser.py) and Linux (linux_parser.py) outputs
into a single unified schema ready for the dashboard and AI layer.

Usage:
  python3 normalizer.py --windows  /cases/parsed/windows/CASE-2026-001_TIMESTAMP \
                        --linux    /cases/parsed/linux/CASE-2026-001_TIMESTAMP \
                        --case_id  CASE-2026-001 \
                        --outdir   /cases/normalized

Output structure:
  /cases/normalized/CASE-2026-001_TIMESTAMP/
    UNIFIED_TIMELINE.csv      -- all events from both OS, same columns
    UNIFIED_SUMMARY.json      -- merged stats + all findings
    artifacts/
      processes.csv           -- processes from both OS
      network.csv             -- network connections from both OS
      users.csv               -- user accounts from both OS
      persistence.csv         -- persistence entries from both OS
      iocs.csv                -- all IOC findings in one place
      bulk_extractor.csv      -- domains/IPs/emails/URLs from bulk_extractor
"""

import argparse
import csv
import json
import logging
import re
import shutil
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

# ======================================================================
# LOGGING
# ======================================================================

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('normalizer.log', encoding='utf-8'),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)

# ======================================================================
# UNIFIED SCHEMA
# Every row in UNIFIED_TIMELINE.csv has exactly these columns.
# ======================================================================

TIMELINE_FIELDS = [
    'timestamp_utc',      # ISO-8601 UTC  2026-03-17T13:00:00Z
    'timestamp_raw',      # original string from source
    'os',                 # 'windows' | 'linux'
    'source',             # evtx | prefetch | shimcache | plaso | vol_ps | ...
    'source_file',        # original CSV filename
    'event_type',         # process | network | logon | file | registry | ...
    'hostname',           # machine name
    'username',           # user involved (if known)
    'process_name',       # executable name (if applicable)
    'pid',                # process ID (if applicable)
    'path',               # file/registry/network path
    'description',        # human-readable summary of the event
    'severity',           # critical | high | medium | low | info
    'ioc_flag',           # True/False -- flagged as suspicious
    'raw_fields',         # JSON blob of all original fields
]

ARTIFACT_PROCESS_FIELDS = [
    'os', 'hostname', 'pid', 'ppid', 'name', 'path', 'cmdline',
    'user', 'start_time', 'hash_sha256', 'ioc_flag', 'ioc_reason',
]

ARTIFACT_NETWORK_FIELDS = [
    'os', 'hostname', 'protocol', 'local_address', 'local_port',
    'remote_address', 'remote_port', 'state', 'pid', 'process_name',
    'ioc_flag', 'ioc_reason',
]

ARTIFACT_USER_FIELDS = [
    'os', 'hostname', 'username', 'uid', 'gid', 'home', 'shell',
    'groups', 'has_sudo', 'ioc_flag', 'ioc_reason',
]

ARTIFACT_PERSISTENCE_FIELDS = [
    'os', 'hostname', 'source', 'entry', 'ioc_flag', 'ioc_reason',
]

IOC_FIELDS = [
    'os', 'hostname', 'category', 'severity', 'description', 'raw_value',
]

BULK_FIELDS = [
    'os', 'hostname', 'type', 'value', 'context',
]

# Suspicious port set (shared between Windows and Linux normalization)
SUSPICIOUS_PORTS = {4444, 4445, 5555, 6666, 7777, 8888, 9999, 1337, 31337, 2222, 3333}

SUSPICIOUS_PROC_NAMES = {
    'mimikatz', 'mimikatz_test', 'meterpreter', 'empire', 'metasploit',
    'cobalt', 'psexec', 'wce', 'fgdump', 'procdump', 'dumpert',
    'ngrok', 'chisel', 'ligolo', 'frp', 'pwncat', 'xmrig',
    'socat', 'ncat', 'netcat',
}

# ======================================================================
# HELPERS
# ======================================================================

def read_csv(path: Path) -> List[Dict[str, str]]:
    if not path.exists():
        return []
    try:
        with open(path, 'r', encoding='utf-8-sig', errors='replace') as f:
            return list(csv.DictReader(f))
    except Exception as e:
        logger.warning(f'read_csv failed ({path.name}): {e}')
        return []


def write_csv(path: Path, rows: List[Dict], fields: List[str]):
    """Write CSV with QUOTE_ALL to prevent unescaped commas/newlines in text fields."""
    if not rows:
        with open(path, 'w', newline='', encoding='utf-8') as f:
            w = csv.DictWriter(f, fieldnames=fields, quoting=csv.QUOTE_ALL)
            w.writeheader()
        return
    # Sanitize: strip literal newlines from all string values to keep one event per line
    clean_rows = []
    for row in rows:
        clean = {}
        for k, v in row.items():
            if isinstance(v, str):
                # Replace newlines/carriage returns with space, strip null bytes
                v = v.replace('\r\n', ' ').replace('\n', ' ').replace('\r', ' ').replace('\x00', '')
            clean[k] = v
        clean_rows.append(clean)
    with open(path, 'w', newline='', encoding='utf-8') as f:
        w = csv.DictWriter(f, fieldnames=fields, extrasaction='ignore',
                           quoting=csv.QUOTE_ALL)
        w.writeheader()
        w.writerows(clean_rows)


def normalize_timestamp(raw: str) -> str:
    """
    Convert any timestamp string to ISO-8601 UTC.
    Handles the formats produced by EvtxECmd, PECmd, psort, Volatility.
    Returns the raw string unchanged if parsing fails.
    """
    if not raw or not raw.strip():
        return ''
    raw = raw.strip()

    # Already ISO-8601
    if re.match(r'\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}', raw):
        if not raw.endswith('Z') and '+' not in raw[-6:]:
            raw = raw.split('.')[0] + 'Z'
        return raw

    # plaso dynamic format: 2026-03-17 13:00:00 UTC
    m = re.match(r'(\d{4}-\d{2}-\d{2})\s+(\d{2}:\d{2}:\d{2})', raw)
    if m:
        return f'{m.group(1)}T{m.group(2)}Z'

    # Windows FILETIME decimal (100ns intervals since 1601-01-01) -- skip
    # EvtxECmd: 2026-03-17 13:00:00.0000000
    m = re.match(r'(\d{4}-\d{2}-\d{2})\s+(\d{2}:\d{2}:\d{2})\.\d+', raw)
    if m:
        return f'{m.group(1)}T{m.group(2)}Z'

    return raw   # return as-is if we cannot parse


def flag_process(name: str, path: str) -> tuple:
    """Return (is_ioc, reason)."""
    name_lower = name.lower()
    path_lower = path.lower()
    for s in SUSPICIOUS_PROC_NAMES:
        if s in name_lower:
            return True, f'Suspicious process name: {name}'
    for tmp in ['/tmp/', '/dev/shm/', r'c:\users\public\\',
                r'c:\windows\temp\\', r'c:\programdata\\']:
        if tmp in path_lower:
            return True, f'Process running from suspicious path: {path}'
    return False, ''


def flag_port(port_str: str) -> tuple:
    try:
        port = int(port_str)
        if port in SUSPICIOUS_PORTS:
            return True, f'Suspicious port: {port}'
    except Exception:
        pass
    return False, ''


def get_hostname(summary: dict, os_name: str) -> str:
    try:
        if os_name == 'windows':
            return summary.get('Hostname', summary.get('hostname', 'unknown-win'))
        else:
            return summary.get('hostname', summary.get('Hostname', 'unknown-linux'))
    except Exception:
        return 'unknown'


def empty_timeline_row() -> Dict[str, Any]:
    return {f: '' for f in TIMELINE_FIELDS}

# ======================================================================
# WINDOWS NORMALIZER
# ======================================================================

class WindowsNormalizer:

    def __init__(self, parsed_dir: Path, summary: dict):
        self.d       = parsed_dir
        self.summary = summary
        self.hostname = get_hostname(summary, 'windows')
        self.rows_timeline: List[Dict]    = []
        self.rows_processes: List[Dict]   = []
        self.rows_network: List[Dict]     = []
        self.rows_users: List[Dict]       = []
        self.rows_persistence: List[Dict] = []
        self.iocs: List[Dict]             = []

    def run(self):
        self._evtx()
        self._prefetch()
        self._shimcache()
        self._hayabusa()
        self._processes()
        self._network()
        self._persistence()
        self._users_from_summary()
        logger.info(f'[windows] {len(self.rows_timeline):,} timeline events')

    # -- EVTX ---------------------------------------------------------

    def _evtx(self):
        evtx_dir = self.d / '01_evtx'
        for csv_path in sorted(evtx_dir.glob('*.csv')):
            for row in read_csv(csv_path):
                ts = normalize_timestamp(row.get('TimeCreated', ''))
                if not ts:
                    continue
                desc = (row.get('MapDescription', '') or
                        row.get('PayloadData1', '') or
                        row.get('Description', ''))[:300]

                # Classify event type by EventId
                eid = row.get('EventId', '')
                event_type = _classify_windows_event(eid)

                # Logon events -- flag suspicious logon types
                ioc = False
                if eid in ('4624', '4625', '4648', '4672'):
                    lt = row.get('PayloadData2', '')
                    if 'Type 10' in lt or 'Type 3' in lt:
                        ioc = True

                r = empty_timeline_row()
                r.update({
                    'timestamp_utc':  ts,
                    'timestamp_raw':  row.get('TimeCreated', ''),
                    'os':             'windows',
                    'source':         'evtx',
                    'source_file':    csv_path.name,
                    'event_type':     event_type,
                    'hostname':       row.get('Computer', self.hostname),
                    'username':       row.get('UserName', ''),
                    'description':    desc,
                    'severity':       _evtx_severity(eid),
                    'ioc_flag':       str(ioc),
                    'raw_fields':     json.dumps({
                        'EventId': eid,
                        'Channel': row.get('Channel', ''),
                        'PayloadData1': row.get('PayloadData1', '')[:200],
                    }),
                })
                self.rows_timeline.append(r)

    # -- PREFETCH -----------------------------------------------------

    def _prefetch(self):
        pf_csv = self.d / '02_prefetch' / 'prefetch.csv'
        for row in read_csv(pf_csv):
            exe = row.get('ExecutableName', '')
            ioc, reason = flag_process(exe, exe)
            if ioc:
                self.iocs.append({
                    'os': 'windows', 'hostname': self.hostname,
                    'category': 'prefetch', 'severity': 'high',
                    'description': reason, 'raw_value': exe,
                })

            r = empty_timeline_row()
            r.update({
                'timestamp_utc':  normalize_timestamp(row.get('LastRun', '')),
                'timestamp_raw':  row.get('LastRun', ''),
                'os':             'windows',
                'source':         'prefetch',
                'source_file':    'prefetch.csv',
                'event_type':     'process_execution',
                'hostname':       self.hostname,
                'process_name':   exe,
                'description':    f'Executed: {exe} (run count: {row.get("RunCount", "?")})',
                'severity':       'high' if ioc else 'info',
                'ioc_flag':       str(ioc),
                'raw_fields':     json.dumps({'RunCount': row.get('RunCount', '')}),
            })
            if r['timestamp_utc']:
                self.rows_timeline.append(r)

    # -- SHIMCACHE ----------------------------------------------------

    def _shimcache(self):
        sh_csv = self.d / '05_shimcache' / 'shimcache.csv'
        for row in read_csv(sh_csv):
            name = row.get('Name', '')
            path = row.get('Path', '')
            ioc, reason = flag_process(name, path)
            r = empty_timeline_row()
            r.update({
                'timestamp_utc':  normalize_timestamp(row.get('LastModifiedTimeUTC', '')),
                'timestamp_raw':  row.get('LastModifiedTimeUTC', ''),
                'os':             'windows',
                'source':         'shimcache',
                'source_file':    'shimcache.csv',
                'event_type':     'process_execution',
                'hostname':       self.hostname,
                'process_name':   name,
                'path':           path,
                'description':    f'Shimcache entry: {name}',
                'severity':       'high' if ioc else 'info',
                'ioc_flag':       str(ioc),
                'raw_fields':     json.dumps({'Path': path}),
            })
            if r['timestamp_utc']:
                self.rows_timeline.append(r)

    # -- HAYABUSA -----------------------------------------------------

    def _hayabusa(self):
        hay_csv = self.d / '08_hayabusa' / 'hayabusa.csv'
        for row in read_csv(hay_csv):
            level = row.get('Level', 'info').lower()
            sev   = {'critical': 'critical', 'high': 'high',
                     'medium': 'medium', 'low': 'low'}.get(level, 'info')
            ioc   = level in ('critical', 'high')
            r = empty_timeline_row()
            r.update({
                'timestamp_utc':  normalize_timestamp(row.get('Timestamp', '')),
                'timestamp_raw':  row.get('Timestamp', ''),
                'os':             'windows',
                'source':         'hayabusa',
                'source_file':    'hayabusa.csv',
                'event_type':     'detection_rule',
                'hostname':       row.get('Computer', self.hostname),
                'description':    row.get('RuleTitle', '') + ' -- ' + row.get('Details', '')[:200],
                'severity':       sev,
                'ioc_flag':       str(ioc),
                'raw_fields':     json.dumps({'RuleTitle': row.get('RuleTitle', '')}),
            })
            if r['timestamp_utc']:
                self.rows_timeline.append(r)
            if ioc:
                self.iocs.append({
                    'os': 'windows', 'hostname': self.hostname,
                    'category': 'hayabusa', 'severity': sev,
                    'description': row.get('RuleTitle', ''),
                    'raw_value': row.get('Details', '')[:300],
                })

    # -- PROCESSES (volatile) -----------------------------------------

    def _processes(self):
        proc_dir = self.d / '11_process'
        for csv_path in proc_dir.glob('running_processes.csv'):
            for row in read_csv(csv_path):
                name = row.get('ProcessName', '')
                path = row.get('Path', '')
                ioc, reason = flag_process(name, path)
                p = {
                    'os': 'windows', 'hostname': self.hostname,
                    'pid': row.get('Id', ''), 'ppid': '',
                    'name': name, 'path': path, 'cmdline': '',
                    'user': row.get('Owner', ''),
                    'start_time': normalize_timestamp(row.get('StartTime', '')),
                    'hash_sha256': row.get('Hash', ''),
                    'ioc_flag': str(ioc), 'ioc_reason': reason,
                }
                self.rows_processes.append(p)
                if ioc:
                    self.iocs.append({
                        'os': 'windows', 'hostname': self.hostname,
                        'category': 'process', 'severity': 'high',
                        'description': reason, 'raw_value': f'{name} ({path})',
                    })

    # -- NETWORK ------------------------------------------------------

    def _network(self):
        net_dir = self.d / '11_network'
        for csv_path in net_dir.glob('tcp_connections.csv'):
            for row in read_csv(csv_path):
                rport = row.get('RemotePort', '')
                ioc, reason = flag_port(rport)
                n = {
                    'os': 'windows', 'hostname': self.hostname,
                    'protocol': 'TCP',
                    'local_address':  row.get('LocalAddress', ''),
                    'local_port':     row.get('LocalPort', ''),
                    'remote_address': row.get('RemoteAddress', ''),
                    'remote_port':    rport,
                    'state':          row.get('State', ''),
                    'pid':            row.get('OwningProcess', ''),
                    'process_name':   row.get('ProcessName', ''),
                    'ioc_flag': str(ioc), 'ioc_reason': reason,
                }
                self.rows_network.append(n)
                if ioc:
                    self.iocs.append({
                        'os': 'windows', 'hostname': self.hostname,
                        'category': 'network', 'severity': 'high',
                        'description': reason,
                        'raw_value': f"{row.get('RemoteAddress','')}:{rport}",
                    })

    # -- PERSISTENCE --------------------------------------------------

    def _persistence(self):
        proc_dir = self.d / '11_process'
        for csv_path in proc_dir.glob('scheduled_tasks.csv'):
            for row in read_csv(csv_path):
                actions = row.get('Actions', '')
                ioc = any(s in actions.lower() for s in
                          ['powershell', 'cmd', 'wscript', 'cscript', 'regsvr32',
                           'rundll32', 'mshta', 'certutil', '/tmp', 'http'])
                self.rows_persistence.append({
                    'os': 'windows', 'hostname': self.hostname,
                    'source': 'scheduled_tasks',
                    'entry': f"{row.get('TaskName', '')} | {actions}",
                    'ioc_flag': str(ioc),
                    'ioc_reason': 'Suspicious scheduled task action' if ioc else '',
                })
        for csv_path in proc_dir.glob('services.csv'):
            for row in read_csv(csv_path):
                path = row.get('PathName', '')
                ioc = any(s in path.lower() for s in [r'\temp\\', r'\users\public\\', 'http', 'cmd.exe /c'])
                self.rows_persistence.append({
                    'os': 'windows', 'hostname': self.hostname,
                    'source': 'services',
                    'entry': f"{row.get('Name', '')} | {path}",
                    'ioc_flag': str(ioc),
                    'ioc_reason': 'Suspicious service path' if ioc else '',
                })

    # -- USERS (from summary) -----------------------------------------

    def _users_from_summary(self):
        # Windows parser doesn't produce a users CSV but summary has IOC notes
        for note in self.summary.get('notes', []):
            if 'SUSPICIOUS' in note or 'WMI' in note:
                self.iocs.append({
                    'os': 'windows', 'hostname': self.hostname,
                    'category': 'summary_flag', 'severity': 'high',
                    'description': note, 'raw_value': '',
                })

# ======================================================================
# LINUX NORMALIZER
# ======================================================================

class LinuxNormalizer:

    def __init__(self, parsed_dir: Path, summary: dict):
        self.d        = parsed_dir
        self.summary  = summary
        self.hostname = get_hostname(summary, 'linux')
        self.rows_timeline: List[Dict]    = []
        self.rows_processes: List[Dict]   = []
        self.rows_network: List[Dict]     = []
        self.rows_users: List[Dict]       = []
        self.rows_persistence: List[Dict] = []
        self.iocs: List[Dict]             = []
        self.bulk_rows: List[Dict]        = []

    def run(self):
        self._plaso()
        self._processes()
        self._network()
        self._users()
        self._persistence()
        self._bulk_extractor()
        self._iocs_from_summary()
        logger.info(f'[linux] {len(self.rows_timeline):,} timeline events')

    # -- PLASO --------------------------------------------------------

    def _plaso(self):
        tl_csv = self.d / '05_plaso' / 'linux_timeline.csv'
        for row in read_csv(tl_csv):
            ts = normalize_timestamp(row.get('datetime', ''))
            if not ts:
                continue
            msg   = row.get('message', '')[:300]
            src   = row.get('source', '')
            etype = _classify_plaso_source(src)
            r = empty_timeline_row()
            r.update({
                'timestamp_utc':  ts,
                'timestamp_raw':  row.get('datetime', ''),
                'os':             'linux',
                'source':         f'plaso/{src}',
                'source_file':    'linux_timeline.csv',
                'event_type':     etype,
                'hostname':       row.get('hostname', self.hostname),
                'username':       _extract_user_from_message(msg),
                'path':           row.get('filename', ''),
                'description':    msg,
                'severity':       'info',
                'ioc_flag':       'False',
                'raw_fields':     json.dumps({
                    'timestamp_desc': row.get('timestamp_desc', ''),
                    'source_long':    row.get('source_long', ''),
                }),
            })
            self.rows_timeline.append(r)

    # -- PROCESSES ----------------------------------------------------

    def _processes(self):
        ps_csv = self.d / '02_processes' / 'ps_auxf.csv'
        for row in read_csv(ps_csv):
            cmd = row.get('COMMAND', row.get('CMD', ''))
            name = cmd.split()[0].split('/')[-1] if cmd.split() else ''
            ioc, reason = flag_process(name, cmd)
            p = {
                'os': 'linux', 'hostname': self.hostname,
                'pid':  row.get('PID', ''), 'ppid': '',
                'name': name, 'path': cmd.split()[0] if cmd.split() else '',
                'cmdline': cmd[:300],
                'user': row.get('USER', ''),
                'start_time': normalize_timestamp(row.get('START', '')),
                'hash_sha256': '',
                'ioc_flag': str(ioc), 'ioc_reason': reason,
            }
            self.rows_processes.append(p)
            if ioc:
                self.iocs.append({
                    'os': 'linux', 'hostname': self.hostname,
                    'category': 'process', 'severity': 'high',
                    'description': reason, 'raw_value': cmd[:200],
                })

    # -- NETWORK ------------------------------------------------------

    def _network(self):
        for fname in ['ss_tcp.csv', 'netstat_tcp.csv']:
            tcp_csv = self.d / '03_network' / fname
            for row in read_csv(tcp_csv):
                # ss output: Local Address:Port  Peer Address:Port
                local  = row.get('Local Address:Port', row.get('LocalAddress', ''))
                remote = row.get('Peer Address:Port',  row.get('RemoteAddress', ''))
                rport  = remote.split(':')[-1] if ':' in remote else ''
                ioc, reason = flag_port(rport)
                n = {
                    'os': 'linux', 'hostname': self.hostname,
                    'protocol': 'TCP',
                    'local_address':  local.rsplit(':', 1)[0] if ':' in local else local,
                    'local_port':     local.split(':')[-1] if ':' in local else '',
                    'remote_address': remote.rsplit(':', 1)[0] if ':' in remote else remote,
                    'remote_port':    rport,
                    'state':          row.get('State', row.get('Status', '')),
                    'pid':            row.get('Process', ''),
                    'process_name':   '',
                    'ioc_flag': str(ioc), 'ioc_reason': reason,
                }
                self.rows_network.append(n)
                if ioc:
                    self.iocs.append({
                        'os': 'linux', 'hostname': self.hostname,
                        'category': 'network', 'severity': 'high',
                        'description': reason, 'raw_value': remote,
                    })

    # -- USERS --------------------------------------------------------

    def _users(self):
        passwd_csv = self.d / '01_users' / 'passwd.csv'
        sudo_set = set()
        sudoers_csv = self.d / '01_users' / 'sudoers.csv'
        for row in read_csv(sudoers_csv):
            rule = row.get('Rule', '')
            m = re.match(r'^(\S+)\s+', rule)
            if m:
                sudo_set.add(m.group(1))

        for row in read_csv(passwd_csv):
            user = row.get('Username', '')
            uid  = row.get('UID', '')
            ioc  = False
            reason = ''
            if uid == '0' and user != 'root':
                ioc    = True
                reason = f'Non-root user with UID=0: {user}'
            u = {
                'os': 'linux', 'hostname': self.hostname,
                'username': user, 'uid': uid,
                'gid':  row.get('GID', ''),
                'home': row.get('Home', ''),
                'shell': row.get('Shell', ''),
                'groups': '',
                'has_sudo': str(user in sudo_set or '%' + user in sudo_set),
                'ioc_flag': str(ioc), 'ioc_reason': reason,
            }
            self.rows_users.append(u)
            if ioc:
                self.iocs.append({
                    'os': 'linux', 'hostname': self.hostname,
                    'category': 'user', 'severity': 'critical',
                    'description': reason, 'raw_value': user,
                })

    # -- PERSISTENCE --------------------------------------------------

    def _persistence(self):
        pers_csv = self.d / '04_persistence' / 'all_persistence.csv'
        for row in read_csv(pers_csv):
            entry = row.get('Entry', '')
            lc    = entry.lower()
            ioc   = any(s in lc for s in ['curl', 'wget', 'bash -i', 'nc -e',
                                           '/tmp/', 'base64', 'python -c'])
            self.rows_persistence.append({
                'os': 'linux', 'hostname': self.hostname,
                'source': row.get('Source', ''),
                'entry':  entry[:300],
                'ioc_flag': str(ioc),
                'ioc_reason': 'Suspicious persistence entry' if ioc else '',
            })

    # -- BULK EXTRACTOR -----------------------------------------------

    def _bulk_extractor(self):
        be_dir = self.d / '07_yara' / 'bulk_extractor'
        if not be_dir.exists():
            return
        for fname in ['domain.txt', 'email.txt', 'url.txt', 'ip.txt']:
            f = be_dir / fname
            if not f.exists():
                continue
            ftype = fname.replace('.txt', '')
            try:
                with open(f, 'r', encoding='utf-8', errors='replace') as fh:
                    for line in fh:
                        line = line.strip()
                        if not line or line.startswith('#'):
                            continue
                        parts = line.split('\t')
                        value = parts[1] if len(parts) > 1 else parts[0]
                        self.bulk_rows.append({
                            'os': 'linux', 'hostname': self.hostname,
                            'type': ftype, 'value': value[:300],
                            'context': parts[2][:200] if len(parts) > 2 else '',
                        })
            except Exception:
                pass

    # -- IOCS FROM SUMMARY --------------------------------------------

    def _iocs_from_summary(self):
        for note in self.summary.get('findings', []):
            if note.strip():
                cat   = note.split(':')[0].strip() if ':' in note else 'general'
                sev   = ('critical' if any(k in note for k in ['UID=0', 'NOPASSWD', 'malfind', 'syscall_hooks'])
                         else 'high' if any(k in note for k in ['YARA', 'BASH_HISTORY', 'CRON', 'hidden_modules'])
                         else 'medium')
                self.iocs.append({
                    'os': 'linux', 'hostname': self.hostname,
                    'category': cat.lower(), 'severity': sev,
                    'description': note[:300], 'raw_value': '',
                })

# ======================================================================
# CLASSIFIERS
# ======================================================================

def _classify_windows_event(eid: str) -> str:
    mapping = {
        '4624': 'logon', '4625': 'logon_failed', '4634': 'logoff',
        '4648': 'logon_explicit', '4672': 'privilege_use',
        '4688': 'process_creation', '4689': 'process_exit',
        '4698': 'scheduled_task', '4702': 'scheduled_task',
        '4719': 'audit_policy', '4720': 'user_created', '4726': 'user_deleted',
        '4732': 'group_change', '4776': 'credential_validation',
        '5140': 'network_share', '5156': 'network_connection',
        '7045': 'service_installed', '7036': 'service_state',
        '1': 'process_creation',   # Sysmon
        '3': 'network_connection', # Sysmon
        '11': 'file_created',      # Sysmon
        '13': 'registry_value',    # Sysmon
    }
    return mapping.get(str(eid), 'windows_event')


def _evtx_severity(eid: str) -> str:
    critical = {'4625', '4648', '4672', '4719', '4720', '4726', '7045'}
    high     = {'4624', '4688', '4698', '4702', '5156', '1', '3'}
    if eid in critical:
        return 'critical'
    if eid in high:
        return 'high'
    return 'info'


def _classify_plaso_source(src: str) -> str:
    src = src.lower()
    if 'log' in src or 'syslog' in src or 'auth' in src:
        return 'log_entry'
    if 'bash' in src or 'shell' in src:
        return 'shell_command'
    if 'dpkg' in src or 'apt' in src:
        return 'package_install'
    if 'systemd' in src or 'journal' in src:
        return 'service_event'
    if 'utmp' in src or 'wtmp' in src:
        return 'logon'
    return 'file_event'


def _extract_user_from_message(msg: str) -> str:
    m = re.search(r'user[=:\s]+([a-zA-Z0-9_-]+)', msg, re.IGNORECASE)
    if m:
        return m.group(1)
    m = re.search(r'for\s+([a-zA-Z0-9_-]+)\s+from', msg)
    if m:
        return m.group(1)
    return ''

# ======================================================================
# MERGER
# ======================================================================

class Normalizer:

    def __init__(self, windows_dir: Optional[Path], linux_dir: Optional[Path],
                 case_id: str, outdir: Path):
        self.windows_dir = windows_dir
        self.linux_dir   = linux_dir
        self.case_id     = case_id
        self.timestamp   = datetime.now().strftime('%Y%m%d_%H%M%S')
        self.outdir      = outdir / f'{case_id}_{self.timestamp}'
        (self.outdir / 'artifacts').mkdir(parents=True, exist_ok=True)

    def _load_summary(self, parsed_dir: Path) -> dict:
        for name in ['PARSE_SUMMARY.json', 'MANIFEST.json']:
            f = parsed_dir / name
            if f.exists():
                try:
                    return json.loads(f.read_text(encoding='utf-8'))
                except Exception:
                    pass
        return {}

    def run(self):
        all_timeline:    List[Dict] = []
        all_processes:   List[Dict] = []
        all_network:     List[Dict] = []
        all_users:       List[Dict] = []
        all_persistence: List[Dict] = []
        all_iocs:        List[Dict] = []
        all_bulk:        List[Dict] = []
        summaries = []

        # -- Windows --
        if self.windows_dir and self.windows_dir.exists():
            logger.info(f'\n[1] NORMALIZING WINDOWS: {self.windows_dir.name}')
            win_summary = self._load_summary(self.windows_dir)
            summaries.append({'os': 'windows', 'summary': win_summary})
            wn = WindowsNormalizer(self.windows_dir, win_summary)
            wn.run()
            all_timeline    += wn.rows_timeline
            all_processes   += wn.rows_processes
            all_network     += wn.rows_network
            all_users       += wn.rows_users
            all_persistence += wn.rows_persistence
            all_iocs        += wn.iocs
        else:
            logger.warning('[SKIP] No Windows parsed directory provided or found')

        # -- Linux --
        if self.linux_dir and self.linux_dir.exists():
            logger.info(f'\n[2] NORMALIZING LINUX: {self.linux_dir.name}')
            lin_summary = self._load_summary(self.linux_dir)
            summaries.append({'os': 'linux', 'summary': lin_summary})
            ln = LinuxNormalizer(self.linux_dir, lin_summary)
            ln.run()
            all_timeline    += ln.rows_timeline
            all_processes   += ln.rows_processes
            all_network     += ln.rows_network
            all_users       += ln.rows_users
            all_persistence += ln.rows_persistence
            all_iocs        += ln.iocs
            all_bulk        += ln.bulk_rows
        else:
            logger.warning('[SKIP] No Linux parsed directory provided or found')

        # -- Sort timeline by timestamp --
        logger.info('\n[3] MERGING AND SORTING')
        all_timeline.sort(key=lambda r: r.get('timestamp_utc', ''))
        logger.info(f'  -> {len(all_timeline):,} total timeline events')

        # -- Write outputs --
        logger.info('\n[4] WRITING UNIFIED OUTPUT')

        write_csv(self.outdir / 'UNIFIED_TIMELINE.csv',    all_timeline,    TIMELINE_FIELDS)
        write_csv(self.outdir / 'artifacts' / 'processes.csv',   all_processes,   ARTIFACT_PROCESS_FIELDS)
        write_csv(self.outdir / 'artifacts' / 'network.csv',     all_network,     ARTIFACT_NETWORK_FIELDS)
        write_csv(self.outdir / 'artifacts' / 'users.csv',       all_users,       ARTIFACT_USER_FIELDS)
        write_csv(self.outdir / 'artifacts' / 'persistence.csv', all_persistence, ARTIFACT_PERSISTENCE_FIELDS)
        write_csv(self.outdir / 'artifacts' / 'iocs.csv',        all_iocs,        IOC_FIELDS)
        write_csv(self.outdir / 'artifacts' / 'bulk_extractor.csv', all_bulk,     BULK_FIELDS)

        logger.info(f'  -> UNIFIED_TIMELINE.csv      ({len(all_timeline):,} rows)')
        logger.info(f'  -> artifacts/processes.csv   ({len(all_processes):,} rows)')
        logger.info(f'  -> artifacts/network.csv     ({len(all_network):,} rows)')
        logger.info(f'  -> artifacts/users.csv       ({len(all_users):,} rows)')
        logger.info(f'  -> artifacts/persistence.csv ({len(all_persistence):,} rows)')
        logger.info(f'  -> artifacts/iocs.csv        ({len(all_iocs):,} rows)')
        logger.info(f'  -> artifacts/bulk_extractor.csv ({len(all_bulk):,} rows)')

        # -- Unified summary --
        unified_summary = {
            'schema':        'UnifiedSummary/v1',
            'case_id':       self.case_id,
            'normalized_at': datetime.now(timezone.utc).isoformat(),
            'output_dir':    str(self.outdir),
            'os_sources':    [s['os'] for s in summaries],
            'counts': {
                'timeline_events': len(all_timeline),
                'processes':       len(all_processes),
                'network_conns':   len(all_network),
                'users':           len(all_users),
                'persistence':     len(all_persistence),
                'iocs':            len(all_iocs),
                'bulk_extractor':  len(all_bulk),
            },
            'ioc_breakdown': {
                'critical': sum(1 for i in all_iocs if i.get('severity') == 'critical'),
                'high':     sum(1 for i in all_iocs if i.get('severity') == 'high'),
                'medium':   sum(1 for i in all_iocs if i.get('severity') == 'medium'),
            },
            'timeline_range': {
                'earliest': all_timeline[0]['timestamp_utc']  if all_timeline else '',
                'latest':   all_timeline[-1]['timestamp_utc'] if all_timeline else '',
            },
            'source_summaries': summaries,
        }
        summary_path = self.outdir / 'UNIFIED_SUMMARY.json'
        summary_path.write_text(json.dumps(unified_summary, indent=2), encoding='utf-8')
        logger.info(f'  -> UNIFIED_SUMMARY.json')

        # -- Print IOC summary to console --
        logger.info(f'\n[IOC SUMMARY]')
        logger.info(f'  Critical : {unified_summary["ioc_breakdown"]["critical"]}')
        logger.info(f'  High     : {unified_summary["ioc_breakdown"]["high"]}')
        logger.info(f'  Medium   : {unified_summary["ioc_breakdown"]["medium"]}')
        for ioc in all_iocs:
            if ioc.get('severity') in ('critical', 'high'):
                logger.warning(f'  * [{ioc["os"].upper()}] [{ioc["severity"].upper()}] '
                               f'[{ioc["category"]}] {ioc["description"][:120]}')

        logger.info(f'\nNORMALIZATION COMPLETE: {self.outdir}')
        return self.outdir

# ======================================================================
# MAIN
# ======================================================================

def main():
    ap = argparse.ArgumentParser(
        description='Forensic Artifact Normalizer v1 -- merges Windows + Linux parser outputs',
    )
    ap.add_argument('--windows', metavar='PATH',
                    help='Path to Windows parsed directory (CASE-ID_TIMESTAMP)')
    ap.add_argument('--linux',   metavar='PATH',
                    help='Path to Linux parsed directory (CASE-ID_TIMESTAMP)')
    ap.add_argument('--case_id', required=True,
                    help='Case identifier, e.g. CASE-2026-001')
    ap.add_argument('--outdir',  default='/cases/normalized',
                    help='Output base directory (default: /cases/normalized)')
    args = ap.parse_args()

    if not args.windows and not args.linux:
        print('ERROR: provide at least one of --windows or --linux')
        sys.exit(1)

    windows_dir = Path(args.windows) if args.windows else None
    linux_dir   = Path(args.linux)   if args.linux   else None
    outdir      = Path(args.outdir)
    outdir.mkdir(parents=True, exist_ok=True)

    n = Normalizer(windows_dir, linux_dir, args.case_id, outdir)
    n.run()


if __name__ == '__main__':
    main()
