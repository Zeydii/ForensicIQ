#!/usr/bin/env python3
"""
ForensicIQ — Correlation Engine
=================================
Computes a unified compromise_score (0–1) for each event by combining
signals from the AI anomaly model, Wazuh alerts, IOC flags, MITRE
techniques, and enrichment data (IP/domain risk scores).

This module has NO API logic — it is imported into api.py or called
standalone on the anomaly_results.csv produced by ai_model_v8.py.

Usage (standalone):
  python3 correlation_engine.py \\
      --ai-results  /cases/normalized/CASE-XXX/artifacts/anomaly_results.csv \\
      --iocs        /cases/normalized/CASE-XXX/artifacts/iocs.csv \\
      --enriched-ips     /cases/normalized/CASE-XXX/artifacts/enriched_ips.json \\
      --enriched-domains /cases/normalized/CASE-XXX/artifacts/enriched_domains.json \\
      --outdir      /cases/normalized/CASE-XXX/artifacts

Usage (as a library inside api.py):
  from correlation_engine import correlate_event, batch_correlate, WEIGHTS

Output columns added to each event:
  compromise_score  float 0–1
  verdict           NORMAL | SUSPICIOUS | COMPROMISED
  explanation       short human-readable reason string
  pattern_flags     list of triggered pattern names
"""

import argparse
import csv
import json
import math
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

# ======================================================================
# WEIGHTS — edit these to tune sensitivity
# ======================================================================

WEIGHTS: Dict[str, float] = {
    # Primary signals (sum should be ~1.0 before pattern multipliers)
    "ai_anomaly_score":   0.35,   # raw 0–1 anomaly score from model
    "ioc_flag":           0.25,   # event is flagged in IOC list
    "wazuh_alert":        0.20,   # corroborating Wazuh detection
    "enrichment_risk":    0.10,   # IP or domain risk from enrichment
    "mitre_technique":    0.10,   # presence of a MITRE technique mapping

    # Pattern bonuses (additive, applied after base score)
    "pattern_burst":         0.10,  # many events in short window
    "pattern_rare_process":  0.08,  # rarely-seen process name
    "pattern_lateral":       0.12,  # lateral movement indicators
    "pattern_exfil":         0.10,  # potential exfiltration
    "pattern_persistence":   0.08,  # persistence mechanism
    "pattern_priv_esc":      0.10,  # privilege escalation

    # IOC severity multipliers (applied to ioc_flag weight)
    "ioc_severity_critical": 1.0,
    "ioc_severity_high":     0.75,
    "ioc_severity_medium":   0.40,
    "ioc_severity_low":      0.15,

    # Wazuh level multipliers
    "wazuh_level_critical":  1.0,   # level >= 12
    "wazuh_level_high":      0.70,  # level 10-11
    "wazuh_level_medium":    0.40,  # level 7-9
    "wazuh_level_low":       0.15,  # level < 7

    # MITRE high-impact technique categories
    "mitre_high_impact_bonus": 0.08,
}

# Verdict thresholds
THRESHOLDS = {
    "COMPROMISED":  0.55,   # Lowered from 0.65: Linux audit-only cases max ~0.68
                            # without IOC/Wazuh; 0.55 lets dual-model AI+syscall reach COMPROMISED
    "SUSPICIOUS":   0.35,
    # below SUSPICIOUS = NORMAL
}

# MITRE techniques considered high-impact (process injection, cred dump, etc.)
HIGH_IMPACT_MITRE = {
    "T1055", "T1059", "T1003", "T1078", "T1021", "T1053",
    "T1574", "T1543", "T1547", "T1548", "T1134", "T1070",
    "T1027", "T1562", "T1190", "T1210", "T1486", "T1490",
}


# ======================================================================
# LINUX AUDIT SYSCALL → MITRE MAPPING
# Linux audit events use raw syscall numbers in descriptions.
# These have no MITRE field unless we map them here.
# syscall=59 = execve (T1059), syscall=41 = socket (T1071),
# syscall=42 = connect (C2/T1071), syscall=2 = open (T1083),
# syscall=62 = kill (T1057), syscall=105 = setuid (T1548)
# ======================================================================

LINUX_SYSCALL_MITRE: Dict[str, str] = {
    "syscall=59":  "T1059",    # execve - command execution
    "syscall=322": "T1059",    # execveat
    "syscall=41":  "T1071",    # socket - network comm
    "syscall=42":  "T1071",    # connect - C2 comm
    "syscall=49":  "T1071",    # bind
    "syscall=2":   "T1083",    # open - file discovery
    "syscall=257": "T1083",    # openat
    "syscall=87":  "T1070",    # unlink - indicator removal
    "syscall=263": "T1070",    # unlinkat
    "syscall=62":  "T1057",    # kill - process discovery
    "syscall=105": "T1548",    # setuid - priv escalation
    "syscall=106": "T1548",    # setgid
    "syscall=117": "T1548",    # setresuid
    "syscall=90":  "T1055",    # mmap - process injection
    "syscall=9":   "T1055",    # mmap2
    "syscall=56":  "T1136",    # clone - fork/create process
    "syscall=57":  "T1136",    # fork
    "syscall=58":  "T1136",    # vfork
    "proctitle=rm": "T1070",   # rm command - cleanup
    "proctitle=gpg":"T1553",   # gpg - subvert trust controls
    "proctitle=wget":"T1105",  # wget - ingress tool transfer
    "proctitle=curl":"T1105",  # curl - ingress tool transfer
    "proctitle=chmod":"T1222", # chmod - file permissions
    "proctitle=chown":"T1222", # chown
    "proctitle=nc":  "T1059",  # netcat
    "proctitle=bash":"T1059",  # bash
    "proctitle=python":"T1059",# python
    "/tmp/":         "T1036",  # /tmp execution - masquerading
    "apt-key":       "T1195",  # supply chain / apt manipulation
}

# Syscall numbers that indicate high-impact activity (lower threshold needed)
LINUX_HIGH_IMPACT_SYSCALLS = {
    "syscall=59", "syscall=322",  # execve
    "syscall=41", "syscall=42",   # socket/connect
    "syscall=105","syscall=117",  # setuid
    "syscall=90",                  # mmap
}

# Process names associated with specific attack patterns
LATERAL_MOVEMENT_PROCS = {
    "psexec", "psexesvc", "wmic", "winrm", "mstsc", "schtasks",
    "at.exe", "sc.exe", "reg.exe",
}
EXFIL_PROCS = {
    "curl", "wget", "certutil", "bitsadmin", "powershell",
    "ftp", "sftp", "scp", "rclone", "megasync",
}
RARE_PROCS = {
    "mimikatz", "procdump", "wce", "fgdump", "meterpreter",
    "cobalt", "empire", "metasploit", "netcat", "ncat", "socat",
    "chisel", "ligolo", "frp", "ngrok", "xmrig",
}
PERSISTENCE_PROCS = {
    "regsvr32", "mshta", "wscript", "cscript", "rundll32",
    "svchost", "lsass", "taskmgr",
}
PRIV_ESC_PROCS = {
    "runas", "sudo", "pkexec", "doas", "su",
}

# ======================================================================
# SINGLE EVENT CORRELATION
# ======================================================================

def correlate_event(event: Dict[str, Any]) -> Dict[str, Any]:
    """
    Compute compromise_score for a single event dict.

    Expected keys (all optional — missing fields score 0):
      anomaly_score     float  0–1  (from AI model)
      anomaly           int    0/1  (1 = flagged by AI model)
      ioc_flag          str    True/False or 1/0
      ioc_severity      str    critical/high/medium/low
      wazuh_alert       bool   True if a Wazuh alert corroborates
      wazuh_level       int    Wazuh rule level (0–16)
      mitre_technique   str    comma-separated MITRE IDs
      description       str    free-text event description
      process_name      str    executable name
      event_type        str    e.g. process_creation, logon, network_connection
      ip_risk_score     float  0–1 from enrichment_engine (optional)
      domain_risk_score float  0–1 from enrichment_engine (optional)
      confidence        int    0–100 confidence from AI tier
    Returns the event dict with added keys:
      compromise_score, verdict, explanation, pattern_flags
    """
    score   = 0.0
    reasons = []
    patterns: List[str] = []

    # ── 1. AI anomaly score ──────────────────────────────────────────
    raw_ai = _to_float(event.get("anomaly_score", 0))
    ai_flagged = str(event.get("anomaly", "0")) in ("1", "True", "true")
    if ai_flagged and raw_ai > 0:
        ai_contrib = WEIGHTS["ai_anomaly_score"] * min(1.0, raw_ai)
        score += ai_contrib
        reasons.append(f"AI anomaly score {raw_ai:.3f}")

    # ── 2. IOC flag ──────────────────────────────────────────────────
    ioc_present = str(event.get("ioc_flag", "")).lower() in ("true", "1")
    if ioc_present:
        sev = str(event.get("ioc_severity", "medium")).lower()
        mult = WEIGHTS.get(f"ioc_severity_{sev}", WEIGHTS["ioc_severity_medium"])
        ioc_contrib = WEIGHTS["ioc_flag"] * mult
        score += ioc_contrib
        reasons.append(f"IOC flagged ({sev} severity)")

    # ── 3. Wazuh alert ───────────────────────────────────────────────
    wazuh_present = bool(event.get("wazuh_alert", False))
    wazuh_level   = _to_int(event.get("wazuh_level", 0))
    if wazuh_present or wazuh_level >= 7:
        if wazuh_level >= 12:
            mult = WEIGHTS["wazuh_level_critical"]
        elif wazuh_level >= 10:
            mult = WEIGHTS["wazuh_level_high"]
        elif wazuh_level >= 7:
            mult = WEIGHTS["wazuh_level_medium"]
        else:
            mult = WEIGHTS["wazuh_level_low"]
        waz_contrib = WEIGHTS["wazuh_alert"] * mult
        score += waz_contrib
        reasons.append(f"Wazuh alert level {wazuh_level}")

    # ── 4. Enrichment risk score ─────────────────────────────────────
    ip_risk  = _to_float(event.get("ip_risk_score",     0))
    dom_risk = _to_float(event.get("domain_risk_score", 0))
    enrich_risk = max(ip_risk, dom_risk)
    if enrich_risk > 0:
        enrich_contrib = WEIGHTS["enrichment_risk"] * enrich_risk
        score += enrich_contrib
        src = "IP" if ip_risk >= dom_risk else "domain"
        reasons.append(f"Enrichment risk ({src}): {enrich_risk:.2f}")

    # ── 5. MITRE technique ───────────────────────────────────────────
    mitre_str   = str(event.get("mitre_technique", ""))
    mitre_techs = {t.strip() for t in mitre_str.split(",") if t.strip()}

    # For Linux audit events: map syscall numbers to MITRE techniques
    # Audit events have no MITRE field — infer from description
    if not mitre_techs:
        desc_check = str(event.get("description", "")).lower()
        for pattern, tech in LINUX_SYSCALL_MITRE.items():
            if pattern.lower() in desc_check:
                mitre_techs.add(tech)

    if mitre_techs:
        score += WEIGHTS["mitre_technique"]
        reasons.append(f"MITRE: {', '.join(sorted(mitre_techs)[:3])}")
        # Bonus for high-impact techniques
        hi = mitre_techs & HIGH_IMPACT_MITRE
        if hi:
            score += WEIGHTS["mitre_high_impact_bonus"]
            reasons.append(f"High-impact technique: {next(iter(hi))}")
        # Extra bonus for Linux high-impact syscalls
        desc_lo = str(event.get("description","")).lower()
        if any(s in desc_lo for s in LINUX_HIGH_IMPACT_SYSCALLS):
            score += 0.05
            reasons.append("Linux high-impact syscall detected")

    # ── 6. Pattern detection ─────────────────────────────────────────
    desc  = str(event.get("description", "")).lower()
    proc  = str(event.get("process_name", event.get("source", ""))).lower()
    etype = str(event.get("event_type",  "")).lower()

    # Rare / known-bad process
    if any(r in proc or r in desc for r in RARE_PROCS):
        score += WEIGHTS["pattern_rare_process"]
        patterns.append("rare_process")
        reasons.append("Known offensive tool detected")

    # Lateral movement
    if (etype in ("logon", "network_connection") and
            any(p in proc or p in desc for p in LATERAL_MOVEMENT_PROCS)):
        score += WEIGHTS["pattern_lateral"]
        patterns.append("lateral_movement")
        reasons.append("Lateral movement indicator")

    # Exfiltration
    if (etype == "network_connection" and
            any(p in proc or p in desc for p in EXFIL_PROCS)):
        score += WEIGHTS["pattern_exfil"]
        patterns.append("potential_exfil")
        reasons.append("Potential data exfiltration tool")

    # Persistence
    if (etype in ("process_execution", "process_creation", "scheduled_task") and
            any(p in proc or p in desc for p in PERSISTENCE_PROCS)):
        score += WEIGHTS["pattern_persistence"]
        patterns.append("persistence")
        reasons.append("Persistence mechanism activity")

    # Privilege escalation
    if (etype in ("privilege_use", "logon") and
            any(p in proc or p in desc for p in PRIV_ESC_PROCS)):
        score += WEIGHTS["pattern_priv_esc"]
        patterns.append("privilege_escalation")
        reasons.append("Privilege escalation indicator")

    # Burst detection marker (set by batch_correlate)
    if event.get("_burst_flag"):
        score += WEIGHTS["pattern_burst"]
        patterns.append("burst_events")
        reasons.append("Part of event burst (possible attack chain)")

    # ── Finalise ─────────────────────────────────────────────────────
    final_score = round(min(1.0, score), 4)

    if final_score >= THRESHOLDS["COMPROMISED"]:
        verdict = "COMPROMISED"
    elif final_score >= THRESHOLDS["SUSPICIOUS"]:
        verdict = "SUSPICIOUS"
    else:
        verdict = "NORMAL"

    explanation = "; ".join(reasons[:4]) if reasons else "No significant signals"

    # Store inferred MITRE techniques back so downstream tools see them
    # (Linux audit events have no mitre_technique field until correlation)
    existing_mitre = str(event.get("mitre_technique","")).strip()
    inferred_mitre = ",".join(sorted(mitre_techs)) if mitre_techs else ""
    final_mitre    = existing_mitre if existing_mitre else inferred_mitre

    return {
        **event,
        "compromise_score":  final_score,
        "verdict":           verdict,
        "explanation":       explanation,
        "pattern_flags":     patterns,
        "mitre_technique":   final_mitre,
    }


# ======================================================================
# BATCH CORRELATION WITH BURST DETECTION
# ======================================================================

def batch_correlate(
    events:        List[Dict[str, Any]],
    burst_window:  int = 120,   # seconds
    burst_min:     int = 5,     # events in window to trigger burst flag
) -> List[Dict[str, Any]]:
    """
    Correlate a list of events in bulk.

    Extra step: burst detection — if >= burst_min events share the same
    timestamp window and at least one is suspicious, all get _burst_flag=True.

    Returns list of events with compromise_score / verdict / explanation added.
    """
    if not events:
        return []

    # ── Parse timestamps and detect bursts ───────────────────────────
    import bisect
    timestamps: List[float] = []
    for ev in events:
        ts = _parse_ts(str(ev.get("timestamp_utc", "")))
        ev["_ts_epoch"] = ts
        timestamps.append(ts)

    timestamps_sorted = sorted(timestamps)
    burst_flags: set = set()

    for i, ts in enumerate(timestamps):
        if ts <= 0:
            continue
        lo = bisect.bisect_left(timestamps_sorted,  ts)
        hi = bisect.bisect_right(timestamps_sorted, ts + burst_window)
        if hi - lo >= burst_min:
            burst_flags.add(i)

    for i, ev in enumerate(events):
        ev["_burst_flag"] = i in burst_flags

    # ── Correlate each event ─────────────────────────────────────────
    results = []
    for ev in events:
        corr = correlate_event(ev)
        # clean internal keys
        corr.pop("_ts_epoch",    None)
        corr.pop("_burst_flag",  None)
        results.append(corr)

    # Sort: COMPROMISED first, then by score desc
    verdict_order = {"COMPROMISED": 0, "SUSPICIOUS": 1, "NORMAL": 2}
    results.sort(
        key=lambda x: (verdict_order.get(x["verdict"], 3), -x["compromise_score"])
    )
    return results


# ======================================================================
# ENRICHMENT INTEGRATION — attach enriched IP/domain risk to events
# ======================================================================

def attach_enrichment(
    events:          List[Dict[str, Any]],
    enriched_ips:    List[Dict[str, Any]],
    enriched_domains:List[Dict[str, Any]],
) -> List[Dict[str, Any]]:
    """
    For each event, look up the IP/domain mentioned in its description
    against the enrichment results and attach risk_score fields.
    """
    ip_risk_map:  Dict[str, float] = {e["ip"]:     e["risk_score"] for e in enriched_ips}
    dom_risk_map: Dict[str, float] = {e["domain"]: e["risk_score"] for e in enriched_domains}

    ip_re  = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
    dom_re = re.compile(r'\b(?:[a-zA-Z0-9\-]+\.)+(?:com|net|org|io|edu|gov|ru|cn)\b', re.I)

    for ev in events:
        text = str(ev.get("description", "")) + " " + str(ev.get("path", ""))

        best_ip_risk  = 0.0
        best_dom_risk = 0.0

        for ip in ip_re.findall(text):
            best_ip_risk = max(best_ip_risk, ip_risk_map.get(ip, 0.0))

        for dom in dom_re.findall(text):
            best_dom_risk = max(best_dom_risk, dom_risk_map.get(dom.lower(), 0.0))

        ev["ip_risk_score"]     = round(best_ip_risk,  3)
        ev["domain_risk_score"] = round(best_dom_risk, 3)

    return events


# ======================================================================
# HELPERS
# ======================================================================

def _to_float(v: Any) -> float:
    try:
        return float(v)
    except (TypeError, ValueError):
        return 0.0


def _to_int(v: Any) -> int:
    try:
        return int(float(v))
    except (TypeError, ValueError):
        return 0


def _parse_ts(ts_str: str) -> float:
    """Parse ISO-8601 timestamp to POSIX epoch float. Returns 0 on failure."""
    if not ts_str:
        return 0.0
    for fmt in ("%Y-%m-%dT%H:%M:%SZ", "%Y-%m-%dT%H:%M:%S+00:00",
                "%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S"):
        try:
            from datetime import datetime as _dt
            dt = _dt.strptime(ts_str[:19], fmt)
            return dt.replace(tzinfo=timezone.utc).timestamp()
        except ValueError:
            continue
    return 0.0


# ======================================================================
# STANDALONE USAGE
# ======================================================================

def main():
    ap = argparse.ArgumentParser(
        description="ForensicIQ Correlation Engine — unified compromise scoring",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Example:
  python3 correlation_engine.py \\
      --ai-results  /cases/normalized/CASE-XXX/artifacts/anomaly_results.csv \\
      --iocs        /cases/normalized/CASE-XXX/artifacts/iocs.csv \\
      --enriched-ips     /cases/normalized/CASE-XXX/artifacts/enriched_ips.json \\
      --enriched-domains /cases/normalized/CASE-XXX/artifacts/enriched_domains.json \\
      --outdir      /cases/normalized/CASE-XXX/artifacts
"""
    )
    ap.add_argument("--ai-results",        required=True)
    ap.add_argument("--iocs",              default="")
    ap.add_argument("--enriched-ips",      default="")
    ap.add_argument("--enriched-domains",  default="")
    ap.add_argument("--outdir",            default=".")
    args = ap.parse_args()

    print(f"\n{'='*60}")
    print(f"  ForensicIQ Correlation Engine")
    print(f"  Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"{'='*60}")

    # Load AI results
    ai_path = Path(args.ai_results)
    if not ai_path.exists():
        print(f"[ERROR] AI results not found: {ai_path}"); return

    events: List[Dict[str, Any]] = []
    with open(ai_path, encoding="utf-8", errors="replace") as f:
        for row in csv.DictReader(f):
            if str(row.get("anomaly", "0")) == "1":
                events.append(dict(row))
    print(f"[LOAD] {len(events):,} anomalous events loaded")

    # Load enrichment results
    enriched_ips:     List[Dict] = []
    enriched_domains: List[Dict] = []

    if args.enriched_ips and Path(args.enriched_ips).exists():
        data = json.loads(Path(args.enriched_ips).read_text())
        enriched_ips = data.get("ips", [])
        print(f"[LOAD] {len(enriched_ips)} enriched IPs")

    if args.enriched_domains and Path(args.enriched_domains).exists():
        data = json.loads(Path(args.enriched_domains).read_text())
        enriched_domains = data.get("domains", [])
        print(f"[LOAD] {len(enriched_domains)} enriched domains")

    # Attach enrichment risk scores to events
    if enriched_ips or enriched_domains:
        events = attach_enrichment(events, enriched_ips, enriched_domains)

    # Load IOC severity into events if available
    if args.iocs and Path(args.iocs).exists():
        ioc_sev_map: Dict[str, str] = {}
        with open(args.iocs, encoding="utf-8", errors="replace") as f:
            for row in csv.DictReader(f):
                val = str(row.get("raw_value","")).lower().strip()
                if val:
                    ioc_sev_map[val] = str(row.get("severity","medium")).lower()
        # Attach severity to events that are IOC-flagged
        for ev in events:
            if str(ev.get("ioc_flag","")).lower() in ("true","1"):
                desc = str(ev.get("description","")).lower()
                for val, sev in ioc_sev_map.items():
                    if val and val in desc:
                        ev["ioc_severity"] = sev
                        break

    # Run correlation
    print(f"\n[CORRELATE] Processing {len(events):,} events")
    results = batch_correlate(events)

    # Stats
    compromised = sum(1 for r in results if r["verdict"] == "COMPROMISED")
    suspicious  = sum(1 for r in results if r["verdict"] == "SUSPICIOUS")
    normal      = sum(1 for r in results if r["verdict"] == "NORMAL")

    print(f"\n  COMPROMISED : {compromised}")
    print(f"  SUSPICIOUS  : {suspicious}")
    print(f"  NORMAL      : {normal}")

    # Top 10
    print(f"\n{'='*60}")
    print("  TOP 10 CORRELATED EVENTS")
    print(f"{'='*60}")
    for r in results[:10]:
        ts  = str(r.get("timestamp_utc",""))[:19].replace("T"," ")
        sc  = r["compromise_score"]
        verd= r["verdict"]
        exp = r["explanation"][:80]
        print(f"  [{ts}] [{verd:<11}] score={sc:.3f}")
        print(f"    {exp}")

    # Write output
    outdir = Path(args.outdir)
    outdir.mkdir(parents=True, exist_ok=True)
    out_path = outdir / "correlation_results.json"
    # Compute MITRE breakdown from results (inferred from Linux syscalls)
    mitre_breakdown: Dict[str, int] = {}
    for r in results:
        for t in str(r.get("mitre_technique","")).split(","):
            t = t.strip()
            if t.startswith("T"):
                mitre_breakdown[t] = mitre_breakdown.get(t, 0) + 1
    mitre_breakdown = dict(sorted(mitre_breakdown.items(), key=lambda x:-x[1])[:15])

    output = {
        "generated_at":    datetime.now(timezone.utc).isoformat(),
        "stats": {
            "total":       len(results),
            "compromised": compromised,
            "suspicious":  suspicious,
            "normal":      normal,
        },
        "mitre_breakdown": mitre_breakdown,
        "weights":         WEIGHTS,
        "thresholds":      THRESHOLDS,
        "results":         results,   # save ALL results, no truncation
    }
    out_path.write_text(json.dumps(output, indent=2, default=str))
    print(f"\n[OUTPUT] {out_path}  ({len(results):,} events)")
    if mitre_breakdown:
        print(f"  Top MITRE: {list(mitre_breakdown.items())[:5]}")
    print(f"{'='*60}\n")


if __name__ == "__main__":
    main()
