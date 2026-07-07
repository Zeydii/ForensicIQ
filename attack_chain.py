#!/usr/bin/env python3
"""
ForensicIQ -- Attack Chain Reconstruction v2
=============================================
Transforms isolated correlated events into structured attack narratives
by grouping temporally-adjacent, host-correlated COMPROMISED/SUSPICIOUS
events into labelled chains.

NO external dependencies. NO API calls. Works fully offline.
Import into api.py or call standalone.

Key design decisions:
  - Pure rule-based: deterministic, reproducible, no rate limits
  - Greedy O(n) clustering: temporal sort + single-pass scan
  - Score formula uses log2 scaling to prevent large low-quality
    clusters from dominating high-confidence small chains
  - Cross-platform detection: flags chains spanning Windows + Linux
  - Narrative is 100% factual -- built only from observed fields

Usage (standalone):
  python3 attack_chain.py \\
      --input  /cases/CASE-XXX/artifacts/correlation_results.json \\
      --outdir /cases/CASE-XXX/artifacts

  python3 attack_chain.py --input corr.json --window 20 --min-events 2
  python3 attack_chain.py --input corr.json --no-host-check

Usage (library):
  from attack_chain import build_attack_chains, chain_summary
  chains  = build_attack_chains(corr_results)
  summary = chain_summary(chains)
"""

import argparse
import json
import math
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

# ======================================================================
# CONFIG
# ======================================================================

CHAIN_CFG: Dict[str, Any] = {
    # Max gap in minutes between consecutive events to stay in same chain.
    # 10 min: tight enough to separate distinct attack sessions,
    # loose enough to capture multi-step techniques.
    "time_window_minutes":  10,

    # Require host/IP/user overlap between adjacent events.
    # True  = fewer false merges between unrelated concurrent events.
    # False = time-only clustering (more aggressive merging).
    "require_host_overlap": True,

    # Minimum events in a chain before emitting. 1 = emit all.
    "min_events": 1,

    # Which verdict values to include.
    "include_verdicts": {"COMPROMISED", "SUSPICIOUS"},

    # Score = max(scores) + bonus * log2(n_events + 1).
    # log2(2)=1, log2(10)=3.32, log2(50)=5.64.
    # Prevents large low-quality clusters from outscoring
    # small high-confidence ones.
    "score_log_bonus": 0.08,

    # Severity thresholds on chain_score (0-1 range).
    "severity_high":   0.70,
    "severity_medium": 0.40,

    # Flag chains that span both Windows and Linux.
    "flag_cross_platform": True,
}

# ======================================================================
# MITRE TECHNIQUE -> TACTIC (ATT&CK v14 common techniques)
# ======================================================================
_TECH_TO_TACTIC: Dict[str, str] = {
    "T1190":"Initial Access",    "T1566":"Initial Access",
    "T1133":"Initial Access",    "T1078":"Initial Access",
    "T1195":"Initial Access",    "T1091":"Initial Access",
    "T1059":"Execution",         "T1203":"Execution",
    "T1072":"Execution",         "T1569":"Execution",
    "T1204":"Execution",         "T1086":"Execution",
    "T1053":"Persistence",       "T1547":"Persistence",
    "T1543":"Persistence",       "T1136":"Persistence",
    "T1505":"Persistence",       "T1176":"Persistence",
    "T1548":"Privilege Escalation","T1134":"Privilege Escalation",
    "T1574":"Privilege Escalation","T1055":"Privilege Escalation",
    "T1068":"Privilege Escalation",
    "T1027":"Defense Evasion",   "T1070":"Defense Evasion",
    "T1036":"Defense Evasion",   "T1218":"Defense Evasion",
    "T1562":"Defense Evasion",   "T1112":"Defense Evasion",
    "T1003":"Credential Access", "T1110":"Credential Access",
    "T1555":"Credential Access", "T1552":"Credential Access",
    "T1558":"Credential Access",
    "T1082":"Discovery",         "T1083":"Discovery",
    "T1069":"Discovery",         "T1087":"Discovery",
    "T1135":"Discovery",         "T1057":"Discovery",
    "T1021":"Lateral Movement",  "T1210":"Lateral Movement",
    "T1534":"Lateral Movement",  "T1570":"Lateral Movement",
    "T1005":"Collection",        "T1074":"Collection",
    "T1114":"Collection",        "T1560":"Collection",
    "T1071":"C2",                "T1095":"C2",
    "T1572":"C2",                "T1573":"C2",
    "T1041":"Exfiltration",      "T1048":"Exfiltration",
    "T1567":"Exfiltration",
    "T1486":"Impact",            "T1490":"Impact",
    "T1485":"Impact",            "T1499":"Impact",
}

_PHASE_ORDER = [
    "Initial Access","Execution","Persistence","Privilege Escalation",
    "Defense Evasion","Credential Access","Discovery",
    "Lateral Movement","Collection","C2","Exfiltration","Impact",
]

_PATTERN_LABELS: Dict[str, str] = {
    "rare_process":         "Offensive tool detected",
    "lateral_movement":     "Lateral movement",
    "potential_exfil":      "Data exfiltration attempt",
    "persistence":          "Persistence mechanism",
    "privilege_escalation": "Privilege escalation",
    "burst_events":         "Event burst (attack pattern)",
}


# ======================================================================
# HELPERS
# ======================================================================

def _parse_ts(ts_str: str) -> Optional[float]:
    """Parse any common timestamp to POSIX epoch. Returns None on failure."""
    if not ts_str or not ts_str.strip():
        return None
    s = ts_str.strip().replace("Z", "").replace("+00:00", "")
    for n_chars, fmt in _TS_FMTS:
        if len(s) < n_chars:
            continue
        try:
            return datetime.strptime(s[:n_chars], fmt).replace(
                tzinfo=timezone.utc).timestamp()
        except ValueError:
            continue
    return None


def _epoch_to_iso(epoch: float) -> str:
    try:
        return datetime.fromtimestamp(epoch, tz=timezone.utc).strftime(
            "%Y-%m-%dT%H:%M:%SZ")
    except Exception:
        return ""


_IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_IP_SKIP = ("127.", "169.254.", "0.0.0.0", "255.")

# Actual lengths of datestrings, not format strings
_TS_FMTS = [
    (26, "%Y-%m-%dT%H:%M:%S.%f"),
    (19, "%Y-%m-%dT%H:%M:%S"),
    (26, "%Y-%m-%d %H:%M:%S.%f"),
    (19, "%Y-%m-%d %H:%M:%S"),
    (16, "%Y-%m-%dT%H:%M"),
    (16, "%Y-%m-%d %H:%M"),
]

def _extract_hosts(ev: Dict) -> Set[str]:
    skip = {"", "none", "unknown", "-", "n/a"}
    out: Set[str] = set()
    for k in ("hostname", "host", "computer", "agent_name"):
        v = str(ev.get(k, "")).strip().lower()
        if v not in skip:
            out.add(v)
    return out

def _extract_users(ev: Dict) -> Set[str]:
    skip = {"", "none", "unknown", "-", "n/a", "system",
            "nt authority\\system", "nt authority\\local service",
            "nt authority\\network service", "root"}
    out: Set[str] = set()
    for k in ("username", "user", "subject_user", "dest_user"):
        v = str(ev.get(k, "")).strip().lower()
        if v not in skip:
            out.add(v)
    return out

def _extract_ips(ev: Dict) -> Set[str]:
    out: Set[str] = set()
    for k in ("description", "path", "raw_fields",
              "remote_address", "source_ip", "dest_ip"):
        for ip in _IP_RE.findall(str(ev.get(k, ""))):
            if not any(ip.startswith(p) for p in _IP_SKIP):
                out.add(ip)
    return out

def _extract_mitre(ev: Dict) -> List[str]:
    seen: Set[str] = set()
    result: List[str] = []
    for t in str(ev.get("mitre_technique", "")).split(","):
        t = t.strip()
        if t.startswith("T") and t not in seen:
            seen.add(t)
            result.append(t)
    return result

def _extract_patterns(ev: Dict) -> Set[str]:
    pf = ev.get("pattern_flags", [])
    if isinstance(pf, list):
        return {str(f).strip() for f in pf if f}
    if isinstance(pf, str) and pf:
        return {f.strip() for f in pf.split(",") if f.strip()}
    return set()

def _techniques_to_tactics(techniques: List[str]) -> List[str]:
    """Map technique IDs -> ordered kill chain phases."""
    seen: Set[str] = set()
    out: List[str] = []
    for t in techniques:
        tactic = _TECH_TO_TACTIC.get(t, _TECH_TO_TACTIC.get(t[:5], ""))
        if tactic and tactic not in seen:
            seen.add(tactic)
            out.append(tactic)
    return sorted(out, key=lambda x: _PHASE_ORDER.index(x)
                  if x in _PHASE_ORDER else 99)


# ======================================================================
# SCORE AND SEVERITY
# ======================================================================

def _compute_chain_score(events: List[Dict]) -> float:
    """
    Score = max(compromise_scores) + score_log_bonus * log2(n + 1)

    WHY LOG2 SCALING:
    Without scaling, a chain with 50 events at 0.50 scores
    0.50 + 50*0.08 = 4.50 (capped to 1.0) -- trivially wins over
    a chain with 1 event at 0.90. With log2 scaling:
      1-event chain:  0.90 + 0.08 * log2(2)  = 0.98
      50-event chain: 0.50 + 0.08 * log2(51) = 0.95
    The 1-event high-confidence chain correctly ranks first.
    A 100-event chain at 0.90 scores: 0.90 + 0.08 * 6.66 = 1.0 (max).
    """
    if not events:
        return 0.0
    scores    = [float(e.get("compromise_score", 0) or 0) for e in events]
    max_score = max(scores)
    bonus     = CHAIN_CFG["score_log_bonus"] * math.log2(len(events) + 1)
    return round(min(1.0, max_score + bonus), 4)

def _assign_severity(score: float) -> str:
    if score >= CHAIN_CFG["severity_high"]:   return "HIGH"
    if score >= CHAIN_CFG["severity_medium"]: return "MEDIUM"
    return "LOW"


# ======================================================================
# NARRATIVE BUILDER
# ======================================================================

def _build_narrative(chain: Dict) -> str:
    """
    Factual narrative from observed event data only.
    No inference or fabrication -- every sentence cites a real field.
    """
    parts: List[str] = []

    # 1. Time span
    t0   = str(chain["time_start"])[:16].replace("T", " ").rstrip("Z")
    t1   = str(chain["time_end"])[:16].replace("T", " ").rstrip("Z")
    span = chain["span_minutes"]
    if span == 0:
        parts.append(f"Activity observed at {t0} UTC.")
    else:
        parts.append(f"Activity from {t0} to {t1} UTC ({span} min duration).")

    # 2. Cross-platform flag
    os_list = chain.get("os", [])
    if len(os_list) > 1:
        parts.append(
            f"Cross-platform: {' and '.join(os_list)} -- uncommon and high-risk."
        )
    elif os_list:
        parts.append(f"Platform: {os_list[0].title()}.")

    # 3. Hosts and users
    hosts = chain.get("hosts", [])
    users = chain.get("users", [])
    if hosts:
        hs = ", ".join(sorted(hosts)[:3])
        if len(hosts) > 3:
            hs += f" (+{len(hosts)-3} more)"
        parts.append(f"Endpoint(s): {hs}.")
    if users:
        us = ", ".join(sorted(users)[:3])
        parts.append(f"Account(s): {us}.")

    # 4. IPs
    ips = chain.get("ips", [])
    if ips:
        parts.append(f"Network: {', '.join(sorted(ips)[:4])}.")

    # 5. Kill chain phases
    phases     = chain.get("kill_chain_phases", [])
    techniques = chain.get("mitre_tactics", [])
    if phases:
        parts.append(f"Kill chain: {' -> '.join(phases)}.")
    if techniques:
        tech_str = ", ".join(techniques[:5])
        if len(techniques) > 5:
            tech_str += f" (+{len(techniques)-5} more)"
        parts.append(f"MITRE: {tech_str}.")

    # 6. Pattern flags
    flags = chain.get("pattern_flags", [])
    if flags:
        readable = [_PATTERN_LABELS.get(f, f) for f in sorted(flags)]
        parts.append(f"Behaviours: {', '.join(readable)}.")

    # 7. Anchor event
    anchor = str(chain.get("anchor_event", "")).strip()
    if anchor:
        short = anchor[:200] + ("..." if len(anchor) > 200 else "")
        parts.append(f"Key event: {short}")

    # 8. Closing
    sev   = chain["severity"]
    score = chain["chain_score"]
    if sev == "HIGH":
        action = "Immediate investigation required."
    elif sev == "MEDIUM":
        action = "Analyst review recommended."
    else:
        action = "Monitor for escalation."
    parts.append(f"Severity: {sev} (score {score:.3f}). {action}")

    return " ".join(parts)


def _build_headline(chain: Dict) -> str:
    """Single-line summary for table display."""
    n       = chain["event_count"]
    span    = chain["span_minutes"]
    verdict = chain["verdict"]
    hosts   = chain.get("hosts", [])
    phases  = chain.get("kill_chain_phases", [])
    hs      = ", ".join(sorted(hosts)[:2]) if hosts else "unknown host"
    ps      = " -> ".join(phases[:2]) if phases else "unknown phase"
    return (f"{verdict} -- {n} event{'s' if n!=1 else ''} "
            f"over {span} min on {hs} [{ps}]")


# ======================================================================
# CLUSTERING
# ======================================================================

def _events_share_context(a: Dict, b: Dict) -> bool:
    """
    True if events share host, IP, user, or same OS (weakest signal).
    OS-only overlap is kept because plaso/Linux events often lack
    hostname, so we cannot split same-machine events into separate chains
    just because hostname is empty.
    """
    if not CHAIN_CFG["require_host_overlap"]:
        return True
    if _extract_hosts(a) & _extract_hosts(b):
        return True
    if _extract_ips(a) & _extract_ips(b):
        return True
    if _extract_users(a) & _extract_users(b):
        return True
    os_a = str(a.get("os", "")).lower()
    os_b = str(b.get("os", "")).lower()
    if os_a and os_b and os_a == os_b:
        return True
    return False


def _cluster_events(events: List[Dict], window_minutes: int) -> List[List[Dict]]:
    """
    Greedy O(n log n) temporal + context clustering.

    Step 1: parse + sort by timestamp.
    Step 2: single pass -- extend current chain if gap <= window
            AND events share context, else start new chain.

    Greedy is the right choice here because:
      - Forensic timelines can have 100k+ events
      - O(n^2) graph-based approaches (DBSCAN) would take minutes
      - Attack sequences are inherently temporal, so a greedy
        time-ordered scan captures chains naturally
    """
    if not events:
        return []

    window_secs = window_minutes * 60.0

    # Tag with parsed timestamps, drop unparseable
    tagged: List[Tuple[float, Dict]] = []
    for ev in events:
        ts = _parse_ts(str(ev.get("timestamp_utc", ev.get("timestamp", ""))))
        if ts is not None:
            tagged.append((ts, ev))

    if not tagged:
        return []

    tagged.sort(key=lambda x: x[0])

    chains: List[List[Dict]]  = []
    current: List[Dict]        = []
    last_ts: float             = 0.0

    for ts, ev in tagged:
        if not current:
            current = [ev]
            last_ts  = ts
            continue

        gap = ts - last_ts
        if gap <= window_secs and _events_share_context(current[-1], ev):
            current.append(ev)
            last_ts = ts
        else:
            chains.append(current)
            current = [ev]
            last_ts  = ts

    if current:
        chains.append(current)

    return chains


# ======================================================================
# CHAIN BUILDER
# ======================================================================

def _build_chain(cluster: List[Dict], chain_index: int) -> Dict:
    """Aggregate all event fields into a single chain dict."""

    all_mitre:    List[str] = []
    all_patterns: Set[str]  = set()
    all_hosts:    Set[str]  = set()
    all_users:    Set[str]  = set()
    all_ips:      Set[str]  = set()
    all_os:       Set[str]  = set()

    for ev in cluster:
        all_mitre.extend(_extract_mitre(ev))
        all_patterns.update(_extract_patterns(ev))
        all_hosts.update(_extract_hosts(ev))
        all_users.update(_extract_users(ev))
        all_ips.update(_extract_ips(ev))
        os_v = str(ev.get("os", "")).lower().strip()
        if os_v:
            all_os.add(os_v)

    # Dedup MITRE preserving order
    seen_m: Set[str] = set()
    unique_mitre: List[str] = []
    for t in all_mitre:
        if t not in seen_m:
            seen_m.add(t)
            unique_mitre.append(t)

    # Timestamps
    ts_vals = [_parse_ts(str(e.get("timestamp_utc", e.get("timestamp", ""))))
               for e in cluster]
    ts_vals = [t for t in ts_vals if t is not None]
    t_start  = min(ts_vals) if ts_vals else 0.0
    t_end    = max(ts_vals) if ts_vals else 0.0
    span_min = int((t_end - t_start) / 60)

    verdict = (
        "COMPROMISED"
        if any(str(e.get("verdict", "")).upper() == "COMPROMISED" for e in cluster)
        else "SUSPICIOUS"
    )
    anchor      = max(cluster, key=lambda e: float(e.get("compromise_score", 0) or 0))
    chain_score = _compute_chain_score(cluster)
    severity    = _assign_severity(chain_score)
    phases      = _techniques_to_tactics(unique_mitre)
    cross_plat  = len(all_os) > 1 and CHAIN_CFG.get("flag_cross_platform", True)

    chain: Dict = {
        "chain_id":          f"Attack Chain {chain_index}",
        "chain_index":       chain_index,
        "verdict":           verdict,
        "severity":          severity,
        "chain_score":       chain_score,
        "event_count":       len(cluster),
        "time_start":        _epoch_to_iso(t_start),
        "time_end":          _epoch_to_iso(t_end),
        "span_minutes":      span_min,
        "os":                sorted(all_os),
        "cross_platform":    cross_plat,
        "hosts":             sorted(all_hosts),
        "users":             sorted(all_users),
        "ips":               sorted(all_ips),
        "mitre_tactics":     unique_mitre,
        "kill_chain_phases": phases,
        "tactic_summary":    " -> ".join(phases[:4]) if phases else "Unknown",
        "pattern_flags":     sorted(all_patterns),
        "anchor_event":      str(anchor.get("description", ""))[:300],
        "anchor_ts":         str(anchor.get("timestamp_utc", "")),
        "anchor_score":      float(anchor.get("compromise_score", 0) or 0),
        "events":            [{k: v for k, v in e.items() if not k.startswith("_")}
                              for e in cluster],
    }
    chain["headline"]  = _build_headline(chain)
    chain["narrative"] = _build_narrative(chain)
    return chain


# ======================================================================
# PUBLIC API
# ======================================================================

def build_attack_chains(
    corr_results:   List[Dict],
    window_minutes: int = CHAIN_CFG["time_window_minutes"],
    min_events:     int = CHAIN_CFG["min_events"],
) -> List[Dict]:
    """
    Build and return attack chains from correlated events.

    Args:
        corr_results:   Output of correlation_engine.batch_correlate().
                        Required fields per event: timestamp_utc,
                        compromise_score, verdict.
                        Optional: hostname, username, os, mitre_technique,
                        pattern_flags, description.
        window_minutes: Max time gap between events in the same chain.
        min_events:     Minimum chain size to emit.

    Returns:
        List of chain dicts sorted HIGH -> MEDIUM -> LOW then by score.
        Each chain has a full 'events' list for drill-down.
    """
    include  = CHAIN_CFG["include_verdicts"]
    filtered = [e for e in corr_results
                if str(e.get("verdict", "")).upper() in include]

    if not filtered:
        return []

    clusters = _cluster_events(filtered, window_minutes)

    raw: List[Dict] = []
    for idx, cluster in enumerate(clusters, 1):
        if len(cluster) >= min_events:
            raw.append(_build_chain(cluster, idx))

    sev_order = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}
    raw.sort(key=lambda c: (sev_order.get(c["severity"], 3), -c["chain_score"]))

    # Renumber after sort so index matches display order
    for i, c in enumerate(raw, 1):
        c["chain_index"] = i
        c["chain_id"]    = f"Attack Chain {i}"

    return raw


def chain_summary(chains: List[Dict]) -> Dict:
    """
    Compact summary for API responses (/api/chains/summary).
    Strips the heavy events list from each chain.
    """
    if not chains:
        return {
            "total_chains": 0, "high_chains": 0, "medium_chains": 0,
            "low_chains": 0, "total_events": 0, "compromised_chains": 0,
            "cross_platform_chains": 0, "chains": [],
        }

    def _strip(c: Dict) -> Dict:
        return {k: v for k, v in c.items() if k != "events"}

    return {
        "total_chains":          len(chains),
        "high_chains":           sum(1 for c in chains if c["severity"] == "HIGH"),
        "medium_chains":         sum(1 for c in chains if c["severity"] == "MEDIUM"),
        "low_chains":            sum(1 for c in chains if c["severity"] == "LOW"),
        "total_events":          sum(c["event_count"] for c in chains),
        "compromised_chains":    sum(1 for c in chains if c["verdict"] == "COMPROMISED"),
        "cross_platform_chains": sum(1 for c in chains if c.get("cross_platform")),
        "chains":                [_strip(c) for c in chains],
    }


# ======================================================================
# CLI
# ======================================================================

def main():
    ap = argparse.ArgumentParser(
        description="ForensicIQ Attack Chain Reconstruction v2",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 attack_chain.py --input artifacts/correlation_results.json --outdir artifacts/
  python3 attack_chain.py --input corr.json --window 20 --min-events 2
  python3 attack_chain.py --input corr.json --no-host-check
""",
    )
    ap.add_argument("--input",         required=True)
    ap.add_argument("--outdir",        default=".")
    ap.add_argument("--window",        type=int, default=CHAIN_CFG["time_window_minutes"])
    ap.add_argument("--min-events",    type=int, default=CHAIN_CFG["min_events"])
    ap.add_argument("--no-host-check", action="store_true",
                    help="Time-only clustering, ignore host/user overlap")
    ap.add_argument("--verdicts",      default="COMPROMISED,SUSPICIOUS")
    args = ap.parse_args()

    CHAIN_CFG["time_window_minutes"] = args.window
    CHAIN_CFG["min_events"]          = args.min_events
    CHAIN_CFG["require_host_overlap"]= not args.no_host_check
    CHAIN_CFG["include_verdicts"]    = {v.strip().upper() for v in args.verdicts.split(",")}

    in_path = Path(args.input)
    if not in_path.exists():
        print(f"[ERROR] Not found: {in_path}"); return

    print(f"\n{'='*60}")
    print(f"  ForensicIQ -- Attack Chain Reconstruction v2")
    print(f"  Input  : {in_path}")
    print(f"  Window : {args.window} min | Min: {args.min_events} events")
    print(f"  Host check: {'off' if args.no_host_check else 'on'}")
    print(f"  Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"{'='*60}")

    data    = json.loads(in_path.read_text(encoding="utf-8"))
    results = data.get("results", data) if isinstance(data, dict) else data
    print(f"  Loaded {len(results):,} correlated events")

    chains = build_attack_chains(results, window_minutes=args.window,
                                 min_events=args.min_events)
    summ   = chain_summary(chains)

    print(f"\n  Chains       : {summ['total_chains']}")
    print(f"    HIGH       : {summ['high_chains']}")
    print(f"    MEDIUM     : {summ['medium_chains']}")
    print(f"    LOW        : {summ['low_chains']}")
    print(f"  Events       : {summ['total_events']:,}")
    print(f"  Compromised  : {summ['compromised_chains']}")
    print(f"  Cross-platform: {summ['cross_platform_chains']}")

    print(f"\n{'='*60}")
    for c in chains:
        icon = {"HIGH":"HIGH","MEDIUM":"MEDIUM","LOW":"LOW"}.get(c["severity"],"⚪")
        xp   = " [CROSS-PLATFORM]" if c.get("cross_platform") else ""
        print(f"\n  {icon} {c['chain_id']}{xp} [{c['verdict']}] score={c['chain_score']:.3f}")
        print(f"     {c['headline']}")
        print(f"     {c['time_start'][:19]} -> {c['time_end'][:19]}")
        if c["kill_chain_phases"]:
            print(f"     Phases : {' -> '.join(c['kill_chain_phases'])}")
        if c["mitre_tactics"]:
            print(f"     MITRE  : {', '.join(c['mitre_tactics'][:6])}")
        if c["pattern_flags"]:
            print(f"     Flags  : {', '.join(c['pattern_flags'])}")
        print(f"     Anchor : {c['anchor_event'][:100]}")

    out_dir = Path(args.outdir)
    out_dir.mkdir(parents=True, exist_ok=True)

    full_out = {
        "generated_at":   datetime.now(timezone.utc).isoformat(),
        "window_minutes": args.window,
        "min_events":     args.min_events,
        "stats":          {k: v for k, v in summ.items() if k != "chains"},
        "chains":         chains,
    }
    fp = out_dir / "attack_chains.json"
    fp.write_text(json.dumps(full_out, indent=2, default=str), encoding="utf-8")
    print(f"\n  Saved -> {fp}")

    cp = out_dir / "attack_chains_summary.json"
    compact = {k: v for k, v in full_out.items() if k != "chains"}
    compact["chains"] = summ["chains"]
    cp.write_text(json.dumps(compact, indent=2, default=str), encoding="utf-8")
    print(f"  Saved -> {cp}")
    print(f"\n{'='*60}\n")


if __name__ == "__main__":
    main()
