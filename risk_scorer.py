#!/usr/bin/env python3
"""
risk_scorer.py — ForensicIQ AI Risk Scorer
============================================
Single entry point: calculate_risk_score(perf_json_path, corr_json_path)

Scoring formula (0-100):
  A. Anomaly rate        (0-25 pts) — how many events are anomalous
  B. IOC correlation     (0-25 pts) — how many anomalies have IOC corroboration
  C. Temporal clustering (0-25 pts) — are anomalies concentrated in time (attack pattern)
  D. Model agreement     (0-25 pts) — dual-model and IOC-confirmed percentages
"""

from __future__ import annotations
import json
from pathlib import Path
from typing import Any, Dict, Optional


# ── helpers ────────────────────────────────────────────────────────────────

def _load_json(path) -> Optional[Dict]:
    """Return parsed JSON or None if file missing/broken."""
    try:
        p = Path(path)
        if p.exists():
            return json.loads(p.read_text(encoding="utf-8"))
    except Exception:
        pass
    return None


def _clamp(value: float, lo: float = 0.0, hi: float = 25.0) -> float:
    return max(lo, min(hi, value))


# ── component scorers ──────────────────────────────────────────────────────

def _score_anomaly_rate(perf: Dict) -> tuple[float, str]:
    """
    A: Anomaly rate — 25 pts max.
    Healthy baseline is < 1%.  > 10% is maximum suspicion.
    Scoring curve: linear from 0% → 1 pt,  5% → 15 pts,  10%+ → 25 pts.
    """
    rate = float((perf.get("detection") or {}).get("anomaly_rate_pct") or 0)
    if rate <= 0:
        pts = 0.0
        note = "No anomalies detected."
    elif rate >= 10:
        pts = 25.0
        note = f"Anomaly rate {rate:.1f}% — extremely elevated."
    else:
        # Piecewise linear: 0→0, 5→15, 10→25
        if rate <= 5:
            pts = rate * 3.0      # 0-15 pts
        else:
            pts = 15 + (rate - 5) * 2.0   # 15-25 pts
        note = f"Anomaly rate {rate:.1f}% — {'elevated' if rate > 2 else 'moderate'}."
    return _clamp(pts), note


def _score_ioc_correlation(perf: Dict, corr: Optional[Dict]) -> tuple[float, str]:
    """
    B: IOC correlation — 25 pts max.
    We look at:
      - model_agreement.ioc_confirmed_pct from model_performance.json
      - fraction COMPROMISED in correlation_results.json if available
    """
    pts = 0.0
    parts = []

    # Source 1: model_performance.json model_agreement
    ma = perf.get("model_agreement") or {}
    ioc_pct = float(ma.get("ioc_confirmed_pct") or 0)
    if ioc_pct > 0:
        # Up to 15 pts from IOC confirmation
        ioc_pts = _clamp(ioc_pct * 0.3, 0, 15)
        pts += ioc_pts
        parts.append(f"{ioc_pct:.0f}% IOC-confirmed anomalies (+{ioc_pts:.0f}pts)")

    # Source 2: correlation_results.json compromised fraction
    if corr:
        results = corr.get("results", corr) if isinstance(corr, dict) else corr
        if isinstance(results, list) and results:
            n_comp = sum(1 for r in results if str(r.get("verdict","")).upper() == "COMPROMISED")
            comp_pct = n_comp / len(results) * 100
            corr_pts = _clamp(comp_pct * 0.2, 0, 10)
            pts += corr_pts
            parts.append(f"{comp_pct:.0f}% correlation-compromised (+{corr_pts:.0f}pts)")

    note = "; ".join(parts) if parts else "No IOC/correlation data."
    return _clamp(pts), note


def _score_temporal_clustering(perf: Dict) -> tuple[float, str]:
    """
    C: Temporal clustering — 25 pts max.
    Attack events cluster in time.  We measure:
      - ratio of anomalies on the primary attack day vs total anomalies
      - number of distinct attack dates
    High concentration on 1 day = high score.
    Spread over many days = lower score (could be noisy data or persistent APT).
    """
    attack_dates = perf.get("attack_dates") or {}
    n_anom = int((perf.get("detection") or {}).get("n_anomalies") or 0)
    if not attack_dates or n_anom == 0:
        return 0.0, "No attack date data."

    primary_day   = perf.get("primary_attack_day", "")
    primary_count = int(attack_dates.get(primary_day, 0)) if primary_day else 0
    n_days        = len(attack_dates)

    # Concentration ratio: how much of the activity is on the primary day
    concentration = primary_count / n_anom if n_anom > 0 else 0

    # More concentration → higher score (tight burst = ransomware / lateral movement)
    # More unique dates → slightly penalise (could be noise OR persistent APT)
    cluster_pts = concentration * 20         # 0-20 pts
    day_pts     = max(0, 5 - (n_days - 1))  # 5 pts for 1 day, 0 for ≥6 days

    pts  = _clamp(cluster_pts + day_pts)
    note = (f"Primary attack day {primary_day} has {primary_count}/{n_anom} anomalies "
            f"({concentration*100:.0f}% concentration, {n_days} attack date(s)).")
    return pts, note


def _score_model_agreement(perf: Dict) -> tuple[float, str]:
    """
    D: Model agreement — 25 pts max.
    When multiple models agree (AE + IF both flag the same event) and when IOC
    data corroborates, confidence is high.
      - dual_model_pct:     up to 15 pts
      - ioc_confirmed_pct:  up to 10 pts (additional dimension from agreement)
    """
    ma  = perf.get("model_agreement") or {}
    dual_pct = float(ma.get("dual_model_pct") or 0)
    ioc_pct  = float(ma.get("ioc_confirmed_pct") or 0)

    dual_pts = _clamp(dual_pct * 0.3, 0, 15)
    ioc_pts  = _clamp(ioc_pct  * 0.1, 0, 10)
    pts      = _clamp(dual_pts + ioc_pts)
    note     = (f"Dual-model agreement: {dual_pct:.0f}% (+{dual_pts:.0f}pts), "
                f"IOC confirmed: {ioc_pct:.0f}% (+{ioc_pts:.0f}pts).")
    return pts, note


# ── interpretation ─────────────────────────────────────────────────────────

def _interpret(score: float) -> tuple[str, str, str]:
    """Return (level, color, text) for the overall score."""
    if score >= 80:
        return ("CRITICAL",
                "#c0392b",
                "Strong indicators of active compromise. Immediate escalation recommended.")
    if score >= 60:
        return ("HIGH",
                "#c0641a",
                "Significant anomalies with corroboration. Detailed investigation required.")
    if score >= 35:
        return ("MEDIUM",
                "#8a6d00",
                "Moderate anomaly signal. Review top findings and cross-reference IOCs.")
    return ("LOW",
            "#1b6b3a",
            "Low anomaly signal. May be benign or insufficient data for firm conclusions.")


# ── public API ─────────────────────────────────────────────────────────────

def calculate_risk_score(
    perf_json_path,
    corr_json_path=None,
) -> Dict[str, Any]:
    """
    Calculate a 0-100 risk score from model_performance.json and
    (optionally) correlation_results.json.

    Returns:
        {
          "overall_score": int,       # 0-100
          "level":         str,       # CRITICAL / HIGH / MEDIUM / LOW
          "color":         str,       # hex colour for UI
          "interpretation": str,      # human-readable conclusion
          "components": {
            "anomaly_rate":        {"score": float, "max": 25, "note": str},
            "ioc_correlation":     {"score": float, "max": 25, "note": str},
            "temporal_clustering": {"score": float, "max": 25, "note": str},
            "model_agreement":     {"score": float, "max": 25, "note": str},
          },
          "formula": str,
        }
    """
    perf = _load_json(perf_json_path) or {}
    corr = _load_json(corr_json_path)  # may be None

    a_pts, a_note = _score_anomaly_rate(perf)
    b_pts, b_note = _score_ioc_correlation(perf, corr)
    c_pts, c_note = _score_temporal_clustering(perf)
    d_pts, d_note = _score_model_agreement(perf)

    total = int(round(a_pts + b_pts + c_pts + d_pts))
    total = max(0, min(100, total))

    level, color, interp = _interpret(total)

    return {
        "overall_score":  total,
        "level":          level,
        "color":          color,
        "interpretation": interp,
        "components": {
            "anomaly_rate":        {"score": round(a_pts, 1), "max": 25, "note": a_note},
            "ioc_correlation":     {"score": round(b_pts, 1), "max": 25, "note": b_note},
            "temporal_clustering": {"score": round(c_pts, 1), "max": 25, "note": c_note},
            "model_agreement":     {"score": round(d_pts, 1), "max": 25, "note": d_note},
        },
        "formula": "A(anomaly_rate,25)+B(ioc_corr,25)+C(temporal,25)+D(model_agree,25)",
    }
