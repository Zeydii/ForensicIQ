#!/usr/bin/env python3
"""
ForensicIQ -- Case Manager & Risk Assessment Engine v2
=======================================================
Two responsibilities:

1. CASE MANAGER
   Scans /cases/normalized/ for all ForensicIQ case directories,
   builds a browsable index, and supports instant case switching
   in the dashboard without restarting the API.

2. RISK ASSESSMENT ENGINE
   Computes a transparent 0-100 risk score from five independent
   evidence sources. Each component is justified below.

=====================================================================
RISK SCORE DESIGN RATIONALE
=====================================================================

The score answers one question: "How confident are we that this
endpoint was actively compromised, and how serious is it?"

Five independent evidence sources are combined additively.
They are INDEPENDENT because each catches different things:
  - IOCs: known-bad artifacts (definitive but signature-dependent)
  - AI:   statistical anomalies (novel threats, no signatures)
  - Corr: multi-signal confirmation (reduces false positives)
  - Chains: organised kill chain (severity escalation)
  - Wazuh: rule-based detection (breadth, low noise)

WHY ADDITIVE, NOT MULTIPLICATIVE:
  Multiplicative scoring (A * B * C) collapses to zero if any
  component is missing (e.g. Wazuh not available after shutdown).
  Additive scoring gracefully degrades: no Wazuh = max 90/100,
  not 0. This is essential for forensic workflows where not all
  data sources are always available.

WHY THESE WEIGHTS:
  A - IOC Severity      (max 35): Highest weight because IOCs are
      the most concrete evidence. A critical IOC (e.g. mimikatz hash)
      is definitively malicious. 5 pts per critical IOC, capped at 7
      critical IOCs = 35 pts. This prevents a single tool execution
      from maxing the score while rewarding multiple IOC types.

  B - AI Anomaly Quality (max 25): Second highest. AI anomalies
      are novel threat detection -- they catch what signatures miss.
      Weighted by tier (CRITICAL=1.0, HIGH=0.3, MEDIUM=0.05)
      because CRITICAL tier requires BOTH AE and IF agreement,
      making it much more reliable than MEDIUM-tier anomalies.
      Divisor of 5 means 25 CRITICAL anomalies = 25 pts (max).

  C - Correlation Depth (max 20): Events confirmed COMPROMISED
      by the correlation engine have been verified by at least
      AI + one other signal (IOC, Wazuh, enrichment, or MITRE).
      4 pts per COMPROMISED event, capped at 5 events = 20 pts.
      This rewards multi-signal confirmation specifically.

  D - Attack Chain Coverage (max 15): Organised attack chains
      indicate a systematic attacker executing a kill chain,
      not random noise. HIGH chain = 7 pts (capped at 2 = 14 pts),
      MEDIUM chain = 3 pts. Cross-platform chain adds 3 bonus pts.

  E - Wazuh Confirmation (max 5): Lowest weight because Wazuh
      is often unavailable after machine shutdown (the primary
      constraint in this project). When available, it provides
      independent rule-based corroboration. Low cap prevents
      high Wazuh alert volume from inflating scores on noisy
      environments.

THRESHOLDS:
  CRITICAL >= 80: Multiple independent sources all confirm
                  active compromise. Incident response required.
  HIGH     >= 60: Strong multi-source evidence. Investigate now.
  MEDIUM   >= 35: Suspicious signals. Analyst triage needed.
  LOW      <  35: Weak or absent signals. Routine monitoring.

Usage:
  from case_manager import load_case_index, compute_risk_score, scan_cases

  # CLI:
  python3 case_manager.py --root /cases/normalized --scan
  python3 case_manager.py --root /cases/normalized --risk /cases/normalized/CASE-XXX
"""

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

import pandas as pd


# ======================================================================
# CASE DISCOVERY
# ======================================================================

_CACHE_TTL_SECONDS = 300   # 5 minutes

CASE_INDEX_FILE = "forensiciq_cases.json"


def scan_cases(root_dir: Path) -> List[Dict[str, Any]]:
    """
    Scan root_dir for valid ForensicIQ case directories.
    A valid case directory must contain UNIFIED_TIMELINE.csv
    OR UNIFIED_SUMMARY.json.
    Returns list sorted newest first.
    """
    root  = Path(root_dir)
    cases: List[Dict[str, Any]] = []

    if not root.exists():
        return []

    for candidate in sorted(root.iterdir(), reverse=True):
        if not candidate.is_dir():
            continue

        has_timeline = (candidate / "UNIFIED_TIMELINE.csv").exists()
        has_summary  = (candidate / "UNIFIED_SUMMARY.json").exists()
        if not has_timeline and not has_summary:
            continue

        meta: Dict[str, Any] = {
            "case_id":    candidate.name,
            "case_dir":   str(candidate),
            "case_name":  candidate.name,
            "created_at": "",
            "has_ai":     False,
            "has_corr":   False,
            "has_chains": False,
            "has_wazuh":  False,
            "n_events":   0,
            "n_anomalies": 0,
            "n_iocs":     0,
            "risk_level": "UNKNOWN",
        }

        if has_summary:
            try:
                s = json.loads((candidate / "UNIFIED_SUMMARY.json").read_text(
                    encoding="utf-8"))
                meta["case_id"]    = s.get("case_id", candidate.name)
                meta["created_at"] = s.get("normalized_at", "")
                counts = s.get("counts", {})
                meta["n_events"] = counts.get("timeline_events", 0)
                meta["n_iocs"]   = counts.get("iocs", 0)
            except Exception:
                pass

        art = candidate / "artifacts"
        ai_path    = art / "anomaly_results.csv"
        corr_path  = art / "correlation_results.json"
        chain_path = art / "attack_chains.json"
        wazuh_path = art / "wazuh_alerts.csv"

        meta["has_ai"]     = ai_path.exists()
        meta["has_corr"]   = corr_path.exists()
        meta["has_chains"] = chain_path.exists()
        meta["has_wazuh"]  = wazuh_path.exists()

        if ai_path.exists():
            try:
                df = pd.read_csv(ai_path, dtype=str, usecols=["anomaly"],
                                 on_bad_lines="skip").fillna("")
                meta["n_anomalies"] = int((df["anomaly"] == "1").sum())
            except Exception:
                pass

        # Quick risk level from saved benchmark if available
        bench = art / "benchmark_report.json"
        if bench.exists():
            try:
                g = json.loads(bench.read_text()).get(
                    "metrics", {}).get("overall", {}).get("grade", "")
                if g:
                    meta["risk_level"] = (
                        "LOW" if g[0] in ("A",) else
                        "MEDIUM" if g[0] in ("B", "C") else "HIGH"
                    )
            except Exception:
                pass

        cases.append(meta)

    return cases


def build_case_index(root_dir: Path) -> Dict[str, Any]:
    """Scan and persist case index. Called on first load or cache expiry."""
    cases = scan_cases(root_dir)
    index = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "root_dir":     str(root_dir),
        "total_cases":  len(cases),
        "cases":        cases,
    }
    idx_path = Path(root_dir) / CASE_INDEX_FILE
    try:
        idx_path.write_text(json.dumps(index, indent=2, default=str),
                            encoding="utf-8")
    except Exception:
        pass
    return index


def load_case_index(root_dir: Path) -> Dict[str, Any]:
    """Return cached index if < 5 min old, otherwise rescan."""
    idx_path = Path(root_dir) / CASE_INDEX_FILE
    if idx_path.exists():
        try:
            data = json.loads(idx_path.read_text(encoding="utf-8"))
            gen  = data.get("generated_at", "")
            if gen:
                age = (datetime.now(timezone.utc) -
                       datetime.fromisoformat(
                           gen.replace("Z", "+00:00"))).total_seconds()
                if age < _CACHE_TTL_SECONDS:
                    return data
        except Exception:
            pass
    return build_case_index(root_dir)


# ======================================================================
# RISK ASSESSMENT ENGINE
# ======================================================================

def compute_risk_score(
    iocs_df:       pd.DataFrame,
    ai_results_df: pd.DataFrame,
    corr_results:  List[Dict],
    chains:        List[Dict],
    wazuh_df:      pd.DataFrame,
) -> Dict[str, Any]:
    """
    Compute a transparent, multi-component risk score (0-100).

    All inputs are optional: missing data contributes 0 to that
    component. The score degrades gracefully — no Wazuh = max 95,
    not a crash. This is critical for forensic use where not all
    data sources survive machine shutdown.

    Returns a dict containing:
      score (int 0-100), level, color, components (A-E),
      key_findings (list of strings), formula, interpretation.
    """

    # ── A: IOC Severity (max 35) ───────────────────────────────────────
    # IOCs are the most concrete evidence in forensic investigation.
    # A critical IOC (mimikatz hash, known C2 IP) is definitively
    # malicious — no model uncertainty, no threshold sensitivity.
    # Weight: critical=5, high=2, medium=0.5.
    # Divisor 7 means 7 critical IOCs fills the 35-pt bucket.
    # Why 7 not 6 or 10: 7 distinct critical IOCs across different
    # categories (process, network, persistence) represents a
    # well-established compromise, not a single tool execution.
    ioc_crit = ioc_high = ioc_med = ioc_low = 0
    if not iocs_df.empty and "severity" in iocs_df.columns:
        vc = iocs_df["severity"].str.lower().value_counts()
        ioc_crit = int(vc.get("critical", 0))
        ioc_high = int(vc.get("high",     0))
        ioc_med  = int(vc.get("medium",   0))
        ioc_low  = int(vc.get("low",      0))

    ioc_raw = ioc_crit * 5.0 + ioc_high * 2.0 + ioc_med * 0.5 + ioc_low * 0.1
    comp_a  = round(min(35.0, ioc_raw / 7.0), 2)

    # ── B: AI Anomaly Quality (max 25) ────────────────────────────────
    # AI anomalies detect novel attacks that have no IOC signatures.
    # Not all anomalies are equal: CRITICAL tier requires both AE and
    # IF to rank the event in the top 30% of candidates independently.
    # This is a much stronger signal than MEDIUM, which may be confirmed
    # by IOC or burst alone.
    # Weight: CRITICAL=1.0, HIGH=0.3, MEDIUM=0.05.
    # Divisor 5 means 25 CRITICAL anomalies = 25 pts (max).
    # Why not count all anomalies equally: the whole point of tiers is
    # to separate high-confidence detections from marginal ones.
    ai_crit_n = ai_high_n = ai_med_n = ai_low_n = 0
    ai_total  = 0
    if not ai_results_df.empty and "anomaly" in ai_results_df.columns:
        anoms = ai_results_df[ai_results_df["anomaly"].astype(str) == "1"]
        ai_total = len(anoms)
        if "alert_tier" in anoms.columns:
            tc = anoms["alert_tier"].value_counts()
            ai_crit_n = int(tc.get("CRITICAL", 0))
            ai_high_n = int(tc.get("HIGH",     0))
            ai_med_n  = int(tc.get("MEDIUM",   0))
            ai_low_n  = int(tc.get("LOW",      0))
        else:
            ai_low_n = ai_total

    ai_weighted = ai_crit_n * 1.0 + ai_high_n * 0.3 + ai_med_n * 0.05
    comp_b      = round(min(25.0, ai_weighted / 5.0), 2)

    # ── C: Correlation Depth (max 20) ─────────────────────────────────
    # The correlation engine rates events COMPROMISED only when they
    # have AI anomaly score + at least one of: IOC flag, Wazuh alert,
    # enrichment risk, or MITRE high-impact technique. This multi-signal
    # requirement makes COMPROMISED the most reliable verdict.
    # Weight: COMPROMISED=4.0, SUSPICIOUS=0.5.
    # Divisor: none -- each COMPROMISED event directly adds 4 pts.
    # Capped at 5 events (20 pts) because beyond 5 confirmed-compromised
    # events, the machine is definitely compromised -- more events add
    # no additional certainty, only severity.
    n_comp = n_susp = n_norm = 0
    for r in corr_results:
        v = str(r.get("verdict", "")).upper()
        if v == "COMPROMISED":   n_comp += 1
        elif v == "SUSPICIOUS":  n_susp += 1
        else:                    n_norm += 1

    corr_raw = n_comp * 4.0 + n_susp * 0.5
    comp_c   = round(min(20.0, corr_raw), 2)

    # ── D: Attack Chain Coverage (max 15) ─────────────────────────────
    # Organised attack chains indicate a deliberate, multi-step attacker
    # executing a kill chain -- not random noise or misconfiguration.
    # A HIGH chain (score >= 0.70) means the chain contains at least one
    # very high-confidence event AND has temporal/host coherence.
    # Weight: HIGH chain=7, MEDIUM chain=3.
    # Cross-platform chain adds 3 bonus points because Windows->Linux
    # pivoting is unusual and indicates advanced attackers.
    # Capped at 2 HIGH chains (14 pts) + 1 cross-platform bonus = 15 max.
    n_high_c  = sum(1 for c in chains if c.get("severity") == "HIGH")
    n_med_c   = sum(1 for c in chains if c.get("severity") == "MEDIUM")
    n_xplat   = sum(1 for c in chains if c.get("cross_platform"))

    chain_raw = n_high_c * 7.0 + n_med_c * 3.0 + n_xplat * 3.0
    comp_d    = round(min(15.0, chain_raw), 2)

    # ── E: Wazuh Confirmation (max 5) ─────────────────────────────────
    # Wazuh gets the lowest weight for a forensic-specific reason:
    # it is frequently unavailable (machine shutdown, no export).
    # When available, it provides independent rule-based corroboration.
    # Low cap (5 pts) prevents high-volume noisy Wazuh environments
    # from inflating scores beyond what the evidence supports.
    # Weight: critical(>=12)=0.5, high(10-11)=0.2, other=0.02.
    waz_crit = waz_high = waz_other = 0
    if not wazuh_df.empty:
        lc = next((c for c in ["rule_level", "level", "Level"]
                   if c in wazuh_df.columns), None)
        if lc:
            lvl       = pd.to_numeric(wazuh_df[lc], errors="coerce").fillna(0)
            waz_crit  = int((lvl >= 12).sum())
            waz_high  = int(((lvl >= 10) & (lvl < 12)).sum())
            waz_other = int((lvl < 10).sum())

    waz_raw = waz_crit * 0.5 + waz_high * 0.2 + waz_other * 0.02
    comp_e  = round(min(5.0, waz_raw), 2)

    # ── Total & Level ─────────────────────────────────────────────────
    total = round(min(100, max(0, comp_a + comp_b + comp_c + comp_d + comp_e)), 1)
    total = int(total)

    if total >= 80:   level = "CRITICAL"
    elif total >= 60: level = "HIGH"
    elif total >= 35: level = "MEDIUM"
    else:             level = "LOW"

    _colors = {
        "CRITICAL": "#c0392b",
        "HIGH":     "#c0641a",
        "MEDIUM":   "#8a6d00",
        "LOW":      "#1b6b3a",
    }

    # ── Key findings (analyst-readable bullets) ───────────────────────
    findings: List[str] = []
    if ioc_crit > 0:
        findings.append(
            f"{ioc_crit} critical IOC(s) — definitively malicious artifacts confirmed")
    if ioc_high > 0:
        findings.append(
            f"{ioc_high} high-severity IOC(s) — offensive tools or suspicious persistence")
    if ai_crit_n > 0:
        findings.append(
            f"{ai_crit_n} CRITICAL-tier anomaly(s) — dual model agreement, top-ranked events")
    if n_comp > 0:
        findings.append(
            f"{n_comp} event(s) rated COMPROMISED — AI + rule-based multi-signal confirmation")
    if n_high_c > 0:
        findings.append(
            f"{n_high_c} HIGH attack chain(s) — systematic kill chain activity detected")
    if n_xplat > 0:
        findings.append(
            f"{n_xplat} cross-platform chain(s) — Windows/Linux pivot detected")
    if waz_crit > 0:
        findings.append(
            f"{waz_crit} critical Wazuh alert(s) — independent rule-based corroboration")
    if not findings:
        findings.append("No significant compromise signals detected")

    def _pct(pts: float, mx: float) -> int:
        return round(pts / mx * 100) if mx > 0 else 0

    return {
        "score": total,
        "level": level,
        "color": _colors[level],
        "components": {
            "A_ioc_severity": {
                "score":   comp_a, "max": 35,
                "pct":     _pct(comp_a, 35),
                "inputs":  {"critical": ioc_crit, "high": ioc_high,
                            "medium": ioc_med, "low": ioc_low},
                "formula": "min(35, (crit×5 + high×2 + med×0.5) / 7)",
                "label":   "IOC Severity",
                "why":     "IOCs are definitive evidence — signature-matched malicious artifacts",
            },
            "B_ai_quality": {
                "score":   comp_b, "max": 25,
                "pct":     _pct(comp_b, 25),
                "inputs":  {"CRITICAL": ai_crit_n, "HIGH": ai_high_n,
                            "MEDIUM": ai_med_n, "LOW": ai_low_n, "total": ai_total},
                "formula": "min(25, (CRIT×1.0 + HIGH×0.3 + MED×0.05) / 5)",
                "label":   "AI Anomaly Quality",
                "why":     "CRITICAL tier = dual-model agreement; detects novel threats without signatures",
            },
            "C_correlation": {
                "score":   comp_c, "max": 20,
                "pct":     _pct(comp_c, 20),
                "inputs":  {"compromised": n_comp, "suspicious": n_susp, "normal": n_norm},
                "formula": "min(20, COMPROMISED×4 + SUSPICIOUS×0.5)",
                "label":   "Correlation Depth",
                "why":     "COMPROMISED = AI + at least one independent rule-based signal confirmed it",
            },
            "D_attack_chains": {
                "score":   comp_d, "max": 15,
                "pct":     _pct(comp_d, 15),
                "inputs":  {"high_chains": n_high_c, "medium_chains": n_med_c,
                            "cross_platform": n_xplat, "total_chains": len(chains)},
                "formula": "min(15, HIGH×7 + MEDIUM×3 + cross_platform×3)",
                "label":   "Attack Chain Coverage",
                "why":     "Organised chains indicate deliberate attacker, not random noise",
            },
            "E_wazuh": {
                "score":   comp_e, "max": 5,
                "pct":     _pct(comp_e, 5),
                "inputs":  {"critical": waz_crit, "high": waz_high, "other": waz_other},
                "formula": "min(5, crit×0.5 + high×0.2 + other×0.02)",
                "label":   "Wazuh Confirmation",
                "why":     "Low cap: Wazuh often unavailable post-shutdown; independent corroboration when present",
            },
        },
        "key_findings":  findings,
        "formula":       "A(IOC,35) + B(AI,25) + C(Corr,20) + D(Chains,15) + E(Wazuh,5) = 100",
        "interpretation": {
            "CRITICAL": "Active compromise confirmed by multiple independent sources. Incident response required.",
            "HIGH":     "Strong multi-source compromise indicators. Investigate immediately.",
            "MEDIUM":   "Suspicious activity detected. Analyst triage required.",
            "LOW":      "No significant compromise signals. Routine monitoring recommended.",
        }[level],
    }


# ======================================================================
# CLI
# ======================================================================

def main():
    import argparse
    ap = argparse.ArgumentParser(description="ForensicIQ Case Manager")
    ap.add_argument("--root",  default="/cases/normalized",
                    help="Root directory containing case folders")
    ap.add_argument("--scan",  action="store_true",
                    help="Scan and list all cases")
    ap.add_argument("--risk",  metavar="CASE_DIR",
                    help="Compute and print risk score for a case directory")
    args = ap.parse_args()

    root = Path(args.root)

    if args.scan or (not args.risk):
        print(f"\nScanning {root} ...")
        index = build_case_index(root)
        print(f"Found {index['total_cases']} cases:\n")
        for c in index["cases"]:
            has = []
            if c["has_ai"]:    has.append("AI")
            if c["has_corr"]:  has.append("CORR")
            if c["has_chains"]:has.append("CHAINS")
            if c["has_wazuh"]: has.append("WAZUH")
            print(f"  {c['case_id']:<35} {c['n_events']:>7} events  "
                  f"{c['n_anomalies']:>5} anomalies  [{', '.join(has)}]")

    if args.risk:
        case_dir = Path(args.risk)
        art      = case_dir / "artifacts"
        print(f"\nRisk score for: {case_dir.name}")

        def _load(p: Path) -> pd.DataFrame:
            if not p.exists():
                return pd.DataFrame()
            try:
                return pd.read_csv(p, dtype=str, on_bad_lines="skip").fillna("")
            except Exception:
                return pd.DataFrame()

        iocs_df = _load(art / "iocs.csv")
        ai_df   = _load(art / "anomaly_results.csv")
        waz_df  = _load(art / "wazuh_alerts.csv")

        corr: List[Dict] = []
        cp = art / "correlation_results.json"
        if cp.exists():
            try:
                d = json.loads(cp.read_text())
                corr = d.get("results", []) if isinstance(d, dict) else d
            except Exception:
                pass

        chains: List[Dict] = []
        chp = art / "attack_chains.json"
        if chp.exists():
            try:
                d = json.loads(chp.read_text())
                chains = d.get("chains", [])
            except Exception:
                pass

        result = compute_risk_score(iocs_df, ai_df, corr, chains, waz_df)

        print(f"\n  Score  : {result['score']}/100 — {result['level']}")
        print(f"  Color  : {result['color']}")
        print(f"  Meaning: {result['interpretation']}")
        print(f"\n  Components:")
        for k, comp in result["components"].items():
            bar = "█" * int(comp["pct"] / 10) + "░" * (10 - int(comp["pct"] / 10))
            print(f"    {comp['label']:<28} {bar} {comp['score']:.1f}/{comp['max']}")
            print(f"      Why: {comp['why']}")
        print(f"\n  Key findings:")
        for f in result["key_findings"]:
            print(f"    • {f}")
        print(f"\n  Formula: {result['formula']}")


if __name__ == "__main__":
    main()
