#!/usr/bin/env python3
"""
false_positive_filter.py — ForensicIQ False Positive Suppression
=================================================================
Provides:
  FALSE_POSITIVE_PATTERNS  — list of known-benign description substrings
  filter_anomalies(df)     — removes rows whose description matches any pattern
"""

from __future__ import annotations
import re
from typing import Tuple
import pandas as pd


# ── Known false-positive patterns ─────────────────────────────────────────
# These descriptions appear in nearly every Windows/Linux environment and
# have a very high false-positive rate when flagged as anomalies.
# They are filtered OUT from the top_anomalies / ai_only_findings lists
# returned by the AI summary endpoint.
FALSE_POSITIVE_PATTERNS: list[str] = [
    # Windows startup / shutdown noise
    "OS was started",
    "The system time was changed",

    # Windows shell / UI host processes (always running, never malicious by themselves)
    "BackgroundTaskHost",
    "ShellExperienceHost",
    "SearchApp.exe",
    "sihost.exe",
    "dashost.exe",
    "LOGONUI.EXE",
    "WINLOGON.EXE",

    # .NET JIT compilation (triggers on every .NET app install / first run)
    "mscorsvw.exe",
    "ngen.exe",

    # Windows Update worker (very noisy, legitimate)
    "TiWorker.exe",

    # Windows Error Reporting (fires after any crash — noisy but benign)
    "WERMGR.EXE",
    "WERFAULT.EXE",

    # Windows compatibility telemetry
    "compattelrunner.exe",
]

# Pre-compile a single regex for fast vectorised matching
_FP_REGEX = re.compile(
    "|".join(re.escape(p) for p in FALSE_POSITIVE_PATTERNS),
    re.IGNORECASE,
)


# ── Public API ─────────────────────────────────────────────────────────────

def filter_anomalies(df: pd.DataFrame) -> Tuple[pd.DataFrame, int]:
    """
    Remove rows from *df* whose 'description' column matches any pattern
    in FALSE_POSITIVE_PATTERNS.

    Works on any DataFrame that has a 'description' column (the standard
    column name in anomaly_results.csv).  If the column is absent, the
    original DataFrame is returned unchanged.

    Returns:
        (filtered_df, n_filtered)  — filtered DataFrame and count removed.
    """
    if df.empty or "description" not in df.columns:
        return df, 0

    desc    = df["description"].fillna("").astype(str)
    is_fp   = desc.str.contains(_FP_REGEX, regex=True)
    n_fp    = int(is_fp.sum())
    return df[~is_fp].copy(), n_fp


def is_false_positive(description: str) -> bool:
    """
    Return True if a single description string matches any FP pattern.
    Useful for per-row checks in loops.
    """
    return bool(_FP_REGEX.search(description or ""))
