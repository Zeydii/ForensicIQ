#!/usr/bin/env python3
"""
ForensicIQ — Baseline Database
================================
Accumulates knowledge across multiple investigations so each new case
benefits from previous ones. Uses SQLite — no server required.

Stores:
  - Per-case feature statistics (mean/std per feature)
  - Cross-case known-benign processes (confirmed in >= N cases)
  - Cross-case IOC hits (IPs, domains, hashes seen in multiple cases)
  - MITRE technique frequency across all cases

Usage:
  from baseline_db import init_db, record_case_baseline, get_cross_case_benign

  # After each case completes (called automatically by ai_model_v9.py):
  init_db()
  record_case_baseline(case_id, feature_stats, env_type='windows_workstation')

  # Get benign process list enriched from past cases:
  extra_benign = get_cross_case_benign(min_cases=3)

  # Get IOCs confirmed across multiple cases (high-confidence threats):
  repeat_iocs = get_repeat_iocs(min_cases=2)
"""

import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

# Database path — shared across all cases on this analysis machine
_DEFAULT_DB = Path("/cases/forensiciq_baseline.db")


def _get_db_path() -> Path:
    """Use /cases/ if writable, otherwise fall back to home directory."""
    if _DEFAULT_DB.parent.exists() and _DEFAULT_DB.parent.is_dir():
        try:
            _DEFAULT_DB.parent.mkdir(parents=True, exist_ok=True)
            return _DEFAULT_DB
        except PermissionError:
            pass
    fallback = Path.home() / '.forensiciq' / 'baseline.db'
    fallback.parent.mkdir(parents=True, exist_ok=True)
    return fallback


DB_PATH = _get_db_path()


def init_db():
    """Create tables if they don't exist. Safe to call multiple times."""
    with sqlite3.connect(DB_PATH) as conn:
        conn.executescript("""
        PRAGMA journal_mode=WAL;

        CREATE TABLE IF NOT EXISTS baseline_stats (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            case_id     TEXT NOT NULL,
            env_type    TEXT DEFAULT 'unknown',
            recorded_at TEXT NOT NULL,
            n_events    INTEGER DEFAULT 0,
            features    TEXT NOT NULL   -- JSON: {feature: {mean, std}}
        );

        CREATE TABLE IF NOT EXISTS known_benign (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            process     TEXT NOT NULL,
            env_type    TEXT DEFAULT 'any',
            seen_cases  INTEGER DEFAULT 1,
            first_seen  TEXT,
            last_seen   TEXT,
            UNIQUE(process, env_type)
        );

        CREATE TABLE IF NOT EXISTS known_iocs (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            ioc_value   TEXT NOT NULL UNIQUE,
            ioc_type    TEXT,
            severity    TEXT DEFAULT 'medium',
            first_seen  TEXT,
            last_seen   TEXT,
            case_count  INTEGER DEFAULT 1,
            case_ids    TEXT DEFAULT ''   -- comma-separated list
        );

        CREATE TABLE IF NOT EXISTS mitre_freq (
            technique   TEXT PRIMARY KEY,
            description TEXT DEFAULT '',
            seen_count  INTEGER DEFAULT 1,
            last_seen   TEXT
        );

        CREATE TABLE IF NOT EXISTS case_registry (
            case_id     TEXT PRIMARY KEY,
            processed_at TEXT,
            n_events    INTEGER,
            n_anomalies INTEGER,
            top_techniques TEXT,  -- JSON list
            env_type    TEXT
        );
        """)
    return DB_PATH


def record_case_baseline(
    case_id:       str,
    feature_stats: Dict[str, Dict[str, float]],
    env_type:      str = 'unknown',
    n_events:      int = 0,
    n_anomalies:   int = 0,
    top_techniques: Optional[List[str]] = None,
):
    """
    Record feature statistics for a completed case.
    Called automatically by ai_model_v9.py after run_pipeline().

    Args:
        case_id:        Case identifier (e.g. 'CASE-2026-001')
        feature_stats:  Dict of {feature_name: {'mean': float, 'std': float}}
        env_type:       Environment type hint ('windows_workstation', 'linux_server', etc.)
        n_events:       Total real events processed
        n_anomalies:    Total anomalies confirmed
        top_techniques: List of top MITRE techniques found
    """
    now = datetime.now(timezone.utc).isoformat()
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute(
            """INSERT OR REPLACE INTO baseline_stats
               (case_id, env_type, recorded_at, n_events, features)
               VALUES (?, ?, ?, ?, ?)""",
            (case_id, env_type, now, n_events, json.dumps(feature_stats))
        )
        conn.execute(
            """INSERT OR REPLACE INTO case_registry
               (case_id, processed_at, n_events, n_anomalies, top_techniques, env_type)
               VALUES (?, ?, ?, ?, ?, ?)""",
            (case_id, now, n_events, n_anomalies,
             json.dumps(top_techniques or []), env_type)
        )
        # Record MITRE frequencies
        for tech in (top_techniques or []):
            if tech:
                conn.execute(
                    """INSERT INTO mitre_freq (technique, last_seen, seen_count)
                       VALUES (?, ?, 1)
                       ON CONFLICT(technique) DO UPDATE SET
                           seen_count = seen_count + 1,
                           last_seen  = excluded.last_seen""",
                    (tech, now)
                )


def record_benign_processes(processes: List[str], env_type: str = 'any'):
    """
    Record processes confirmed benign in this case.
    After 3+ cases confirm a process as benign, get_cross_case_benign()
    will return it for automatic inclusion in the suppression list.
    """
    now = datetime.now(timezone.utc).isoformat()
    with sqlite3.connect(DB_PATH) as conn:
        for proc in processes:
            proc = proc.strip()
            if not proc:
                continue
            conn.execute(
                """INSERT INTO known_benign (process, env_type, seen_cases, first_seen, last_seen)
                   VALUES (?, ?, 1, ?, ?)
                   ON CONFLICT(process, env_type) DO UPDATE SET
                       seen_cases = seen_cases + 1,
                       last_seen  = excluded.last_seen""",
                (proc.lower(), env_type, now, now)
            )


def get_cross_case_benign(
    env_type:  Optional[str] = None,
    min_cases: int = 3,
) -> List[str]:
    """
    Return processes confirmed benign across >= min_cases investigations.
    Use to dynamically extend CFG['benign_suppress'] without hardcoding.

    Example:
        extra_benign = get_cross_case_benign(min_cases=3)
        CFG['benign_suppress'].extend(extra_benign)
    """
    with sqlite3.connect(DB_PATH) as conn:
        if env_type and env_type != 'any':
            rows = conn.execute(
                """SELECT process FROM known_benign
                   WHERE seen_cases >= ?
                   AND (env_type = ? OR env_type = 'any')
                   ORDER BY seen_cases DESC""",
                (min_cases, env_type)
            ).fetchall()
        else:
            rows = conn.execute(
                """SELECT process FROM known_benign
                   WHERE seen_cases >= ?
                   ORDER BY seen_cases DESC""",
                (min_cases,)
            ).fetchall()
    return [r[0] for r in rows]


def record_ioc(
    value:    str,
    ioc_type: str,
    severity: str,
    case_id:  str,
):
    """
    Record an IOC hit. If same IOC appears in multiple cases,
    get_repeat_iocs() will surface it as a persistent/recurring threat.
    """
    now = datetime.now(timezone.utc).isoformat()
    with sqlite3.connect(DB_PATH) as conn:
        existing = conn.execute(
            "SELECT case_ids, case_count FROM known_iocs WHERE ioc_value = ?",
            (value,)
        ).fetchone()

        if existing:
            old_ids   = existing[0] or ''
            cases_set = set(old_ids.split(',')) if old_ids else set()
            cases_set.add(case_id)
            conn.execute(
                """UPDATE known_iocs SET
                       last_seen  = ?,
                       case_count = ?,
                       case_ids   = ?
                   WHERE ioc_value = ?""",
                (now, len(cases_set), ','.join(sorted(cases_set)), value)
            )
        else:
            conn.execute(
                """INSERT INTO known_iocs
                   (ioc_value, ioc_type, severity, first_seen, last_seen, case_count, case_ids)
                   VALUES (?, ?, ?, ?, ?, 1, ?)""",
                (value, ioc_type, severity, now, now, case_id)
            )


def get_repeat_iocs(min_cases: int = 2) -> List[Dict[str, Any]]:
    """
    Return IOCs seen in >= min_cases.
    These are high-confidence persistent threats — same infrastructure
    reused across multiple victims or investigations.
    """
    with sqlite3.connect(DB_PATH) as conn:
        rows = conn.execute(
            """SELECT ioc_value, ioc_type, severity, case_count, case_ids,
                      first_seen, last_seen
               FROM known_iocs
               WHERE case_count >= ?
               ORDER BY case_count DESC""",
            (min_cases,)
        ).fetchall()
    return [
        {
            'value':      r[0],
            'type':       r[1],
            'severity':   r[2],
            'case_count': r[3],
            'cases':      r[4].split(',') if r[4] else [],
            'first_seen': r[5],
            'last_seen':  r[6],
        }
        for r in rows
    ]


def get_baseline_feature_stats(
    env_type:   Optional[str] = None,
    last_n:     int = 10,
) -> Dict[str, Dict[str, float]]:
    """
    Return averaged feature statistics across recent cases.
    Useful for computing drift score on a new case:
      drift = |new_mean - baseline_mean| / baseline_std

    Args:
        env_type: Filter to matching environment type.
        last_n:   Only average the most recent N cases.

    Returns:
        {feature_name: {'mean': float, 'std': float, 'baseline_mean': float}}
    """
    with sqlite3.connect(DB_PATH) as conn:
        if env_type and env_type != 'unknown':
            rows = conn.execute(
                """SELECT features FROM baseline_stats
                   WHERE env_type = ? OR env_type = 'unknown'
                   ORDER BY recorded_at DESC LIMIT ?""",
                (env_type, last_n)
            ).fetchall()
        else:
            rows = conn.execute(
                """SELECT features FROM baseline_stats
                   ORDER BY recorded_at DESC LIMIT ?""",
                (last_n,)
            ).fetchall()

    if not rows:
        return {}

    import numpy as np
    all_stats: Dict[str, List[float]] = {}
    for (feat_json,) in rows:
        try:
            stats = json.loads(feat_json)
            for feat, vals in stats.items():
                if feat not in all_stats:
                    all_stats[feat] = []
                all_stats[feat].append(float(vals.get('mean', 0)))
        except Exception:
            continue

    return {
        feat: {
            'baseline_mean': float(np.mean(means)),
            'baseline_std':  float(np.std(means)) + 1e-9,
        }
        for feat, means in all_stats.items()
        if means
    }


def compute_drift_score(
    current_stats: Dict[str, Dict[str, float]],
    env_type:      Optional[str] = None,
) -> Dict[str, Any]:
    """
    Compute how much a new case drifts from the stored baseline.
    High drift means the new environment is unlike anything seen before
    — scores should be interpreted with caution.

    Returns:
        {'drift_score': float 0-1, 'drifted_features': list,
         'interpretation': str}
    """
    import numpy as np
    baseline = get_baseline_feature_stats(env_type=env_type)
    if not baseline or not current_stats:
        return {
            'drift_score':     0.0,
            'drifted_features': [],
            'interpretation':  'No baseline available — first case on this system',
            'n_baseline_cases': 0,
        }

    drifts: List[float] = []
    drifted: List[str]  = []

    for feat, cur in current_stats.items():
        if feat not in baseline:
            continue
        base = baseline[feat]
        cur_mean  = float(cur.get('mean', 0))
        base_mean = base['baseline_mean']
        base_std  = base['baseline_std']
        z = abs(cur_mean - base_mean) / base_std
        drifts.append(min(z / 3.0, 1.0))   # normalize: z=3 = drift=1.0
        if z > 2.0:
            drifted.append(feat)

    if not drifts:
        return {'drift_score': 0.0, 'drifted_features': [], 'interpretation': 'No overlap'}

    drift_score = float(np.mean(drifts))

    if drift_score >= 0.70:
        interpretation = (
            "HIGH DRIFT: This environment is very different from the baseline. "
            "Scores may be less reliable. Consider this an exploratory run."
        )
    elif drift_score >= 0.35:
        interpretation = (
            "MODERATE DRIFT: Some behavioral differences from baseline. "
            "Scores are informative but verify critical findings manually."
        )
    else:
        interpretation = (
            "LOW DRIFT: Environment matches baseline well. "
            "Scores are well-calibrated."
        )

    return {
        'drift_score':      round(drift_score, 3),
        'drifted_features': drifted[:10],
        'interpretation':   interpretation,
    }


def get_case_registry() -> List[Dict[str, Any]]:
    """Return all processed cases as a list of dicts."""
    with sqlite3.connect(DB_PATH) as conn:
        rows = conn.execute(
            """SELECT case_id, processed_at, n_events, n_anomalies,
                      top_techniques, env_type
               FROM case_registry
               ORDER BY processed_at DESC"""
        ).fetchall()
    return [
        {
            'case_id':        r[0],
            'processed_at':   r[1],
            'n_events':       r[2],
            'n_anomalies':    r[3],
            'top_techniques': json.loads(r[4] or '[]'),
            'env_type':       r[5],
        }
        for r in rows
    ]


def print_summary():
    """Print a human-readable summary of the baseline database."""
    with sqlite3.connect(DB_PATH) as conn:
        n_cases   = conn.execute("SELECT COUNT(*) FROM case_registry").fetchone()[0]
        n_benign  = conn.execute("SELECT COUNT(*) FROM known_benign WHERE seen_cases >= 2").fetchone()[0]
        n_iocs    = conn.execute("SELECT COUNT(*) FROM known_iocs WHERE case_count >= 2").fetchone()[0]
        n_mitre   = conn.execute("SELECT COUNT(*) FROM mitre_freq").fetchone()[0]
        top_mitre = conn.execute(
            "SELECT technique, seen_count FROM mitre_freq ORDER BY seen_count DESC LIMIT 5"
        ).fetchall()

    print(f"\n{'='*50}")
    print(f"  ForensicIQ Baseline Database: {DB_PATH}")
    print(f"{'='*50}")
    print(f"  Cases processed:          {n_cases}")
    print(f"  Cross-case benign procs:  {n_benign} (confirmed in >= 2 cases)")
    print(f"  Repeat IOCs:              {n_iocs} (seen in >= 2 cases)")
    print(f"  MITRE techniques tracked: {n_mitre}")
    if top_mitre:
        print(f"  Top techniques across all cases:")
        for tech, cnt in top_mitre:
            print(f"    {tech}: {cnt} cases")
    print(f"{'='*50}\n")


if __name__ == '__main__':
    import argparse
    ap = argparse.ArgumentParser(description='ForensicIQ Baseline DB CLI')
    ap.add_argument('--summary', action='store_true')
    ap.add_argument('--cases',   action='store_true')
    ap.add_argument('--iocs',    action='store_true', help='Show repeat IOCs')
    ap.add_argument('--benign',  action='store_true', help='Show cross-case benign processes')
    args = ap.parse_args()

    init_db()
    if args.summary or not any([args.cases, args.iocs, args.benign]):
        print_summary()
    if args.cases:
        for c in get_case_registry():
            print(f"  {c['case_id']} | {c['processed_at'][:10]} | "
                  f"{c['n_events']:,} events | {c['n_anomalies']} anomalies | {c['env_type']}")
    if args.iocs:
        for ioc in get_repeat_iocs(min_cases=2):
            print(f"  [{ioc['severity'].upper()}] {ioc['type']}: {ioc['value']} "
                  f"(seen in {ioc['case_count']} cases)")
    if args.benign:
        for proc in get_cross_case_benign(min_cases=2):
            print(f"  {proc}")
