#!/usr/bin/env python3
"""
Windows Forensic Artifact Parser v2
Improvements:
  - Fixed Hayabusa command (adds --rules auto-detect)
  - Added browser parsing via hindsight
  - Added RECmd registry batch parsing
  - Added network/process CSV pass-through
  - Master timeline builder that merges all timestamped CSVs
  - Structured PARSE_SUMMARY.json
"""

import subprocess
import shutil
import json
import csv
import logging
import sys
from pathlib import Path
from datetime import datetime
from typing import List, Optional

# ==================================================================
# LOGGING
# ==================================================================

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('windows_parser.log', encoding='utf-8'),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)

# ==================================================================
# CONFIG  -- edit paths to match your forensic server layout
# ==================================================================

TOOLS_BASE = Path(r"C:\ForensicServer\Tools")

CONFIG = {
    'tools': {
        'evtxecmd':  str(TOOLS_BASE / r"EZTools\net9\EvtxeCmd\EvtxECmd.exe"),
        'pecmd':     str(TOOLS_BASE / r"EZTools\net9\PECmd.exe"),
        'jlecmd':    str(TOOLS_BASE / r"EZTools\net9\JLECmd.exe"),
        'amcache':   str(TOOLS_BASE / r"EZTools\net9\AmcacheParser.exe"),
        'appcompat': str(TOOLS_BASE / r"EZTools\net9\AppCompatCacheParser.exe"),
        'lecmd':     str(TOOLS_BASE / r"EZTools\net9\LECmd.exe"),
        'mftecmd':   str(TOOLS_BASE / r"EZTools\net9\MFTECmd.exe"),
        'recmd':     str(TOOLS_BASE / r"EZTools\net9\RECmd\RECmd.exe"),
        'hayabusa':  str(TOOLS_BASE / r"Hayabusa\hayabusa.exe"),
        # hayabusa rules dir -- auto-detected below, override if needed
        'hayabusa_rules': str(TOOLS_BASE / r"Hayabusa\rules"),
        # hindsight for browser history (pip install hindsight or standalone exe)
        'hindsight': str(TOOLS_BASE / r"Hindsight\hindsight.exe"),
        # RECmd batch files
        'recmd_batch': str(TOOLS_BASE / r"EZTools\net9\RECmd\BatchExamples\Kroll_Batch.reb"),
    },
    'timeouts': {
        'evtxecmd': 600, 'pecmd': 300, 'jlecmd': 300,
        'amcache': 300, 'appcompat': 300, 'lecmd': 300,
        'mftecmd': 900, 'recmd': 600,
        'hayabusa': 1200, 'hindsight': 300,
    },
    'output_base': Path(r"C:\ParsedData\windows"),
}

# Timeline field mappings: (csv_glob, timestamp_col, source_label, extra_cols)
TIMELINE_SOURCES = [
    # evtx
    ("01_evtx/*.csv",         "TimeCreated",         "evtx",      ["EventId", "Channel", "Computer", "UserName", "MapDescription", "PayloadData1", "PayloadData2"]),
    # prefetch
    ("02_prefetch/prefetch_Timeline.csv", "RunTime",  "prefetch",  ["ExecutableName", "RunCount", "VolumeSerialNumbers"]),
    # jumplists
    ("03_jumplists/jumplists.csv",        "SourceModified", "jumplist", ["AppIdDescription", "LocalPath", "TargetCreated"]),
    # amcache
    ("04_amcache/*.csv",      "FileKeyLastWriteTimestamp", "amcache", ["Name", "FullPath", "SHA1"]),
    # shimcache
    ("05_shimcache/shimcache.csv", "LastModifiedTimeUTC", "shimcache", ["Name", "Path"]),
    # lnk
    ("06_lnk/lnk.csv",        "SourceModified",      "lnk",       ["Name", "LocalPath", "NetworkPath"]),
    # mft
    ("07_mft/mft.csv",        "Created0x10",         "mft",       ["FileName", "Extension", "ParentPath", "FileSize"]),
    # hayabusa
    ("08_hayabusa/hayabusa.csv", "Timestamp",         "hayabusa",  ["RuleTitle", "Level", "Computer", "Details"]),
    # registry
    ("10_registry/*.csv",     "LastWriteTimestamp",  "registry",  ["Description", "ValueName", "ValueData"]),
]

# ==================================================================
# HELPERS
# ==================================================================

def tool_exists(name: str) -> bool:
    path = CONFIG['tools'].get(name, '')
    if not path or not Path(path).exists():
        logger.warning(f"[SKIP] {name} not found: {path}")
        return False
    return True


def run(name: str, cmd: List[str], timeout: Optional[int] = None) -> bool:
    """Run a subprocess, return True on success."""
    t = timeout or CONFIG['timeouts'].get(name, 300)
    try:
        result = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=False,
            timeout=t,
            creationflags=subprocess.CREATE_NO_WINDOW,
        )
        if result.returncode != 0:
            stderr = result.stderr.decode(errors='ignore').strip()
            logger.error(f"[{name}] FAILED (rc={result.returncode})")
            if stderr:
                logger.error(stderr[:500])
            return False
        logger.info(f"[{name}] OK")
        return True
    except subprocess.TimeoutExpired:
        logger.error(f"[{name}] TIMEOUT after {t}s")
        return False
    except Exception as e:
        logger.error(f"[{name}] ERROR: {e}")
        return False

# ==================================================================
# PARSER CLASS
# ==================================================================

class WindowsParser:

    def __init__(self, artifacts_dir: Path, case_id: str):
        self.artifacts_dir = artifacts_dir.resolve()
        self.case_id = case_id
        self.timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        self.output_dir = CONFIG['output_base'] / f"{case_id}_{self.timestamp}"
        self.output_dir.mkdir(parents=True, exist_ok=True)

        self.dirs = {
            'evtx':      self.output_dir / '01_evtx',
            'prefetch':  self.output_dir / '02_prefetch',
            'jumplists': self.output_dir / '03_jumplists',
            'amcache':   self.output_dir / '04_amcache',
            'shimcache': self.output_dir / '05_shimcache',
            'lnk':       self.output_dir / '06_lnk',
            'mft':       self.output_dir / '07_mft',
            'hayabusa':  self.output_dir / '08_hayabusa',
            'browser':   self.output_dir / '09_browser',
            'registry':  self.output_dir / '10_registry',
            'network':   self.output_dir / '11_network',
            'process':   self.output_dir / '11_process',
        }
        for d in self.dirs.values():
            d.mkdir(exist_ok=True)

        self.results: dict = {}   # populated per step, used in summary

    # -- EVTX ----------------------------------------------------

    def parse_event_logs(self):
        logger.info("\n[1] EVTX")
        if not tool_exists('evtxecmd'):
            return

        evtx_dir = self.artifacts_dir / 'EventLogs'
        if not evtx_dir.exists():
            logger.warning("[SKIP] EventLogs not found")
            return

        ok = 0
        for f in sorted(evtx_dir.rglob('*.evtx')):
            logger.info(f" -> {f.name}")
            if run('evtxecmd', [
                CONFIG['tools']['evtxecmd'],
                '-f', str(f),
                '--csv', str(self.dirs['evtx']),
                '--csvf', f"{f.stem}.csv",
            ]):
                ok += 1
        self.results['evtx'] = ok

    # -- PREFETCH -------------------------------------------------

    def parse_prefetch(self):
        logger.info("\n[2] PREFETCH")
        if not tool_exists('pecmd'):
            return

        pf_dir = self.artifacts_dir / 'Prefetch'
        if not pf_dir.exists() or not any(pf_dir.glob('*.pf')):
            logger.warning("[SKIP] Prefetch not found / empty")
            return

        run('pecmd', [
            CONFIG['tools']['pecmd'],
            '-d', str(pf_dir),
            '--csv', str(self.dirs['prefetch']),
            '--csvf', 'prefetch.csv',
        ])

    # -- JUMPLISTS ------------------------------------------------

    def parse_jumplists(self):
        logger.info("\n[3] JUMPLISTS")
        if not tool_exists('jlecmd'):
            return

        jl_dir = self.artifacts_dir / 'JumpLists'
        if not jl_dir.exists() or not any(jl_dir.iterdir()):
            logger.warning("[SKIP] JumpLists empty")
            return

        run('jlecmd', [
            CONFIG['tools']['jlecmd'],
            '-d', str(jl_dir),
            '--csv', str(self.dirs['jumplists']),
            '--csvf', 'jumplists.csv',
        ])

    # -- AMCACHE --------------------------------------------------

    def parse_amcache(self):
        logger.info("\n[4] AMCACHE")
        if not tool_exists('amcache'):
            return

        f = self.artifacts_dir / 'AmCache' / 'Amcache.hve'
        if not f.exists():
            logger.warning("[SKIP] Amcache not found")
            return

        run('amcache', [
            CONFIG['tools']['amcache'],
            '-f', str(f),
            '--csv', str(self.dirs['amcache']),
        ])

    # -- SHIMCACHE ------------------------------------------------

    def parse_shimcache(self):
        logger.info("\n[5] SHIMCACHE")
        if not tool_exists('appcompat'):
            return

        hive = self.artifacts_dir / 'Registry' / 'SYSTEM.hiv'
        if not hive.exists():
            logger.warning("[SKIP] SYSTEM hive not found")
            return

        run('appcompat', [
            CONFIG['tools']['appcompat'],
            '-f', str(hive),
            '--csv', str(self.dirs['shimcache']),
            '--csvf', 'shimcache.csv',
        ])

    # -- LNK ------------------------------------------------------

    def parse_lnk(self):
        logger.info("\n[6] LNK")
        if not tool_exists('lecmd'):
            return

        lnk_dir = self.artifacts_dir / 'LNK'
        if not lnk_dir.exists() or not any(lnk_dir.glob('*.lnk')):
            logger.warning("[SKIP] LNK empty")
            return

        run('lecmd', [
            CONFIG['tools']['lecmd'],
            '-d', str(lnk_dir),
            '--csv', str(self.dirs['lnk']),
            '--csvf', 'lnk.csv',
        ])

    # -- MFT ------------------------------------------------------

    def parse_mft(self):
        logger.info("\n[7] MFT")
        if not tool_exists('mftecmd'):
            return

        mft_file = self.artifacts_dir / 'MFT' / '$MFT'
        if not mft_file.exists():
            logger.warning("[SKIP] $MFT not found -- was RawCopy64 present during collection?")
            return

        run('mftecmd', [
            CONFIG['tools']['mftecmd'],
            '-f', str(mft_file),
            '--csv', str(self.dirs['mft']),
            '--csvf', 'mft.csv',
        ], timeout=CONFIG['timeouts']['mftecmd'])

    # -- HAYABUSA (FIXED) -----------------------------------------

    def run_hayabusa(self):
        logger.info("\n[8] HAYABUSA")
        if not tool_exists('hayabusa'):
            return

        evtx_dir = self.artifacts_dir / 'EventLogs'
        if not evtx_dir.exists():
            logger.warning("[SKIP] EventLogs not found")
            return

        # Auto-detect rules dir
        rules_dir = Path(CONFIG['tools']['hayabusa_rules'])
        if not rules_dir.exists():
            # Try sibling 'rules' dir next to the hayabusa exe
            exe_parent = Path(CONFIG['tools']['hayabusa']).parent
            candidate = exe_parent / 'rules'
            if candidate.exists():
                rules_dir = candidate
            else:
                logger.error(
                    "[hayabusa] FAILED -- no rules directory found.\n"
                    f"  Tried: {rules_dir}\n"
                    f"  Tried: {candidate}\n"
                    "  Run: hayabusa.exe update-rules  OR  set hayabusa_rules in CONFIG"
                )
                return

        output_file = self.dirs['hayabusa'] / 'hayabusa.csv'

        run('hayabusa', [
            CONFIG['tools']['hayabusa'],
            'csv-timeline',
            '--no-wizard',               # required by hayabusa >= 2.10
            '-d', str(evtx_dir),
            '-r', str(rules_dir),
            '-o', str(output_file),
            '-p', 'verbose',
            '--no-summary',
        ], timeout=CONFIG['timeouts']['hayabusa'])

    # -- BROWSER HISTORY ------------------------------------------

    def parse_browser(self):
        logger.info("\n[9] BROWSER HISTORY")
        browser_dir = self.artifacts_dir / 'BrowserHistory'
        if not browser_dir.exists():
            logger.warning("[SKIP] BrowserHistory dir not found")
            return

        if tool_exists('hindsight'):
            for profile_dir in browser_dir.rglob('History'):
                if profile_dir.is_file():
                    out_prefix = self.dirs['browser'] / profile_dir.parent.name
                    run('hindsight', [
                        CONFIG['tools']['hindsight'],
                        '-i', str(profile_dir.parent),
                        '-o', str(out_prefix),
                        '-f', 'csv',
                    ])
        else:
            # Fallback: copy SQLite databases directly so the AI layer can query them
            logger.warning("[hindsight] not found -- copying browser SQLite files as-is")
            for f in browser_dir.rglob('*'):
                if f.is_file():
                    dest = self.dirs['browser'] / f.relative_to(browser_dir)
                    dest.parent.mkdir(parents=True, exist_ok=True)
                    shutil.copy2(f, dest)
            logger.info("[browser] SQLite files copied (no parsing)")

    # -- REGISTRY (RECmd batch) ------------------------------------

    def parse_registry(self):
        logger.info("\n[10] REGISTRY (RECmd batch)")
        if not tool_exists('recmd'):
            logger.warning("[SKIP] RECmd not found -- skipping batch registry parse")
            return

        reg_dir = self.artifacts_dir / 'Registry'
        if not reg_dir.exists():
            logger.warning("[SKIP] Registry dir not found")
            return

        batch_file = Path(CONFIG['tools']['recmd_batch'])
        if not batch_file.exists():
            logger.warning(f"[SKIP] RECmd batch file not found: {batch_file}")
            logger.warning("       Download from: https://github.com/EricZimmermann/RECmd")
            return

        run('recmd', [
            CONFIG['tools']['recmd'],
            '--bn', str(batch_file),
            '-d', str(reg_dir),
            '--nl',
            '--csv', str(self.dirs['registry']),
        ], timeout=CONFIG['timeouts']['recmd'])

    # -- NETWORK / PROCESS PASS-THROUGH ---------------------------

    def copy_volatile_artifacts(self):
        logger.info("\n[11] NETWORK & PROCESS (pass-through)")

        for src_subdir, dst_dir in [
            ('NetworkConnections', self.dirs['network']),
            ('ProcessList',        self.dirs['process']),
            ('ScheduledTasks',     self.dirs['process']),
            ('Services',           self.dirs['process']),
            ('WMI',                self.dirs['process']),
            ('Startup',            self.dirs['process']),
        ]:
            src = self.artifacts_dir / src_subdir
            if src.exists():
                for f in src.glob('*.csv'):
                    shutil.copy2(f, dst_dir / f.name)
                    logger.info(f" -> {f.name}")

    # -- MASTER TIMELINE ------------------------------------------

    def build_master_timeline(self):
        logger.info("\n[TIMELINE] Building master timeline")

        timeline_rows = []

        for glob_pat, ts_col, source_label, extra_cols in TIMELINE_SOURCES:
            for csv_path in sorted(self.output_dir.glob(glob_pat)):
                try:
                    with open(csv_path, 'r', encoding='utf-8-sig', errors='replace') as fh:
                        reader = csv.DictReader(fh)
                        if ts_col not in (reader.fieldnames or []):
                            continue
                        for row in reader:
                            ts_raw = row.get(ts_col, '').strip()
                            if not ts_raw:
                                continue
                            entry = {
                                'Timestamp': ts_raw,
                                'Source': source_label,
                                'SourceFile': csv_path.name,
                            }
                            for col in extra_cols:
                                entry[col] = row.get(col, '')
                            timeline_rows.append(entry)
                except Exception as e:
                    logger.warning(f"Timeline read error ({csv_path.name}): {e}")

        if not timeline_rows:
            logger.warning("[TIMELINE] No rows collected -- check that parsing produced CSVs")
            return

        # Sort by timestamp string (ISO-ish strings sort lexicographically)
        timeline_rows.sort(key=lambda r: r.get('Timestamp', ''))

        out_path = self.output_dir / 'MASTER_TIMELINE.csv'
        fieldnames = ['Timestamp', 'Source', 'SourceFile'] + sorted(
            {k for row in timeline_rows for k in row if k not in ('Timestamp', 'Source', 'SourceFile')}
        )
        with open(out_path, 'w', newline='', encoding='utf-8') as fh:
            writer = csv.DictWriter(fh, fieldnames=fieldnames, extrasaction='ignore')
            writer.writeheader()
            writer.writerows(timeline_rows)

        logger.info(f"[TIMELINE] {len(timeline_rows):,} events -> {out_path.name}")
        self.results['timeline_rows'] = len(timeline_rows)

    # -- PARSE SUMMARY --------------------------------------------

    def write_summary(self):
        # Count output rows per dir
        counts = {}
        for name, d in self.dirs.items():
            rows = 0
            for f in d.glob('*.csv'):
                try:
                    with open(f, 'r', encoding='utf-8-sig', errors='replace') as fh:
                        rows += sum(1 for _ in fh) - 1  # subtract header
                except Exception:
                    pass
            counts[name] = {'files': len(list(d.glob('*.csv'))), 'rows': max(rows, 0)}

        summary = {
            'schema': 'ParseSummary/v2',
            'case_id': self.case_id,
            'parsed_at': datetime.now().isoformat(),
            'artifacts_dir': str(self.artifacts_dir),
            'output_dir': str(self.output_dir),
            'artifact_counts': counts,
            'timeline_rows': self.results.get('timeline_rows', 0),
            'notes': []
        }

        # Auto-flag interesting prefetch entries
        pf_csv = self.dirs['prefetch'] / 'prefetch.csv'
        ioc_prefetch = []
        if pf_csv.exists():
            suspicious_names = {
                'mimikatz', 'psexec', 'wce', 'fgdump', 'meterpreter',
                'cobalt', 'metasploit', 'procdump', 'dumpert', 'wce', 'lsass',
            }
            try:
                with open(pf_csv, 'r', encoding='utf-8-sig', errors='replace') as fh:
                    for row in csv.DictReader(fh):
                        exe = row.get('ExecutableName', '').lower()
                        if any(s in exe for s in suspicious_names):
                            ioc_prefetch.append(exe)
            except Exception:
                pass
        if ioc_prefetch:
            summary['notes'].append(f"SUSPICIOUS PREFETCH: {', '.join(ioc_prefetch)}")

        # Flag WMI subscriptions
        wmi_csv = self.dirs['process'] / 'wmi_consumers.csv'
        if wmi_csv.exists():
            try:
                with open(wmi_csv, 'r', encoding='utf-8-sig', errors='replace') as fh:
                    wmi_rows = list(csv.DictReader(fh))
                if wmi_rows:
                    summary['notes'].append(f"WMI CONSUMERS PRESENT: {len(wmi_rows)} consumer(s) -- review manually")
            except Exception:
                pass

        out_path = self.output_dir / 'PARSE_SUMMARY.json'
        with open(out_path, 'w', encoding='utf-8') as fh:
            json.dump(summary, fh, indent=2)
        logger.info(f"[SUMMARY] Written -> {out_path.name}")
        if summary['notes']:
            for note in summary['notes']:
                logger.warning(f"  * {note}")

    # -- RUN ALL --------------------------------------------------

    def run_all(self):
        self.parse_event_logs()
        self.parse_prefetch()
        self.parse_jumplists()
        self.parse_amcache()
        self.parse_shimcache()
        self.parse_lnk()
        self.parse_mft()
        self.run_hayabusa()
        self.parse_browser()
        self.parse_registry()
        self.copy_volatile_artifacts()
        self.build_master_timeline()
        self.write_summary()

# ==================================================================
# MAIN
# ==================================================================

def main():
    if len(sys.argv) != 3:
        print("Usage: python windows_parser.py <artifacts_dir> <case_id>")
        print("  artifacts_dir: path to the unzipped WindowsCollection_* folder")
        print("  case_id:       e.g. CASE-2026-001")
        sys.exit(1)

    artifacts_dir = Path(sys.argv[1])
    case_id       = sys.argv[2]

    if not artifacts_dir.exists():
        logger.error(f"Artifacts directory not found: {artifacts_dir}")
        sys.exit(1)

    parser = WindowsParser(artifacts_dir, case_id)
    parser.run_all()
    logger.info(f"\nPARSING COMPLETE: {parser.output_dir}")

if __name__ == "__main__":
    main()
