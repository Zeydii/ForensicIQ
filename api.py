#!/usr/bin/env python3
"""
ForensicIQ Backend API v2
==========================
Changes from v1:
  - Multi-case support: /api/cases, /api/cases/switch, /api/cases/current
  - Wazuh cache: 15-min in-memory cache prevents blocking on dead VM
  - Attack chains: /api/chains/* endpoints (from attack_chain.py)
  - Risk score: replaced by case_manager.py 5-component formula
  - Benchmark: /api/ai/benchmark endpoint
  - Model loader: /api/inference/run to score new cases with saved models
  - Dashboard auto-detected as dashboard_v2.html first, then dashboard.html

Run:
  python3 api.py --case /cases/normalized/CASE-2026-001_TIMESTAMP

  # Switch cases without restart: use /api/cases/switch from dashboard
  # or pass a new --case at startup

  # Score a new case with saved models:
  curl -X POST "http://localhost:8000/api/inference/run" \\
       -H "Content-Type: application/json" \\
       -d '{"timeline": "/cases/CASE-002/UNIFIED_TIMELINE.csv",
            "outdir": "/cases/CASE-002/artifacts",
            "models": "/cases/CASE-001/artifacts/ai_models"}'
"""

import argparse
import base64
import json
import math
import os
import sys
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

_HERE = Path(__file__).parent
if str(_HERE) not in sys.path:
    sys.path.insert(0, str(_HERE))

# ── optional modules ───────────────────────────────────────────────────
try:
    from correlation_engine import batch_correlate, attach_enrichment, WEIGHTS as CORR_WEIGHTS
    CORRELATION_OK = True
except ImportError:
    CORRELATION_OK = False
    print("[WARN] correlation_engine.py not found")

try:
    from enrichment_engine import run as enrich_run
    ENRICHMENT_OK = True
except ImportError:
    ENRICHMENT_OK = False

try:
    from attack_chain import build_attack_chains, chain_summary as _ac_summary
    CHAIN_OK = True
except ImportError:
    CHAIN_OK = False
    print("[WARN] attack_chain.py not found — /api/chains/* disabled")

try:
    from case_manager import load_case_index, build_case_index, compute_risk_score
    CASE_MGR_OK = True
except ImportError:
    CASE_MGR_OK = False
    print("[WARN] case_manager.py not found — /api/cases/* disabled")

try:
    from benchmark import run_benchmark
    BENCHMARK_OK = True
except ImportError:
    BENCHMARK_OK = False

# ── New AI pipeline modules (ForensicIQ v2.1) ──────────────────────────
try:
    from risk_scorer import calculate_risk_score
    RISK_SCORER_OK = True
except ImportError:
    RISK_SCORER_OK = False
    print("[WARN] risk_scorer.py not found — /api/case/<id>/ai_summary risk score disabled")

try:
    from false_positive_filter import filter_anomalies as _fp_filter
    FP_FILTER_OK = True
except ImportError:
    FP_FILTER_OK = False
    print("[WARN] false_positive_filter.py not found — FP filtering disabled")

try:
    from ai_explainer import explain_batch, explain_anomaly
    EXPLAINER_OK = True
except ImportError:
    EXPLAINER_OK = False
    print("[WARN] ai_explainer.py not found — anomaly explanations disabled")

try:
    from mock_wazuh import get_mock_alerts
    MOCK_WAZUH_OK = True
except ImportError:
    MOCK_WAZUH_OK = False
    print("[WARN] mock_wazuh.py not found — mock Wazuh alerts disabled")

import pandas as pd
try:
    import requests
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    REQUESTS_OK = True
except ImportError:
    REQUESTS_OK = False

import uvicorn
from fastapi import FastAPI, HTTPException, Query, Header, Body
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles

# ======================================================================
# APP + CONFIG
# ======================================================================

app = FastAPI(title="ForensicIQ API v2", version="2.0.0")

app.add_middleware(CORSMiddleware, allow_origins=["*"],
                   allow_methods=["*"], allow_headers=["*"])

# ── Edit these for your environment ────────────────────────────────────
DEFAULT_CASE      = "/cases/normalized/CASE-2026-001_20260331_122816"
DEFAULT_DASHBOARD = "/root/ForensicCollection/dashboard_v2.html"
API_KEY           = ""          # set to a token string to require auth, "" = open
CASES_ROOT        = "/cases/normalized"   # scanned for /api/cases

WAZUH_CFG = {
    "url":              "https://192.168.56.102:55000",
    "user":             "wazuh-wui",
    "password":         "z0Mm1fZkj*KT7nOMSpeu1v0bXrB*sOmy",
    "indexer_password": "ForensicIQ2026!*",
    "verify":           False,
}
# ───────────────────────────────────────────────────────────────────────

# ======================================================================
# DATA STORE
# ======================================================================

class CaseData:
    def __init__(self):
        self.case_dir:        Optional[Path] = None
        self.summary:         Dict           = {}
        self.timeline:        pd.DataFrame   = pd.DataFrame()
        self.iocs:            pd.DataFrame   = pd.DataFrame()
        self.processes:       pd.DataFrame   = pd.DataFrame()
        self.network:         pd.DataFrame   = pd.DataFrame()
        self.users:           pd.DataFrame   = pd.DataFrame()
        self.persistence:     pd.DataFrame   = pd.DataFrame()
        self.bulk:            pd.DataFrame   = pd.DataFrame()
        self.wazuh:           pd.DataFrame   = pd.DataFrame()
        self.ai_results:      pd.DataFrame   = pd.DataFrame()
        self.enriched_ips:    List[Dict]     = []
        self.enriched_domains:List[Dict]     = []
        self.corr_results:    List[Dict]     = []
        self.chains:          List[Dict]     = []
        self.loaded:          bool           = False

    def load(self, case_dir: Path):
        self.case_dir = case_dir
        art = case_dir / "artifacts"

        def _csv(path: Path) -> pd.DataFrame:
            if not path.exists():
                return pd.DataFrame()
            for engine, bad in [("c", "warn"), ("python", "warn"), ("python", "skip")]:
                try:
                    df = pd.read_csv(path, dtype=str, low_memory=False,
                                     on_bad_lines=bad, engine=engine).fillna("")
                    print(f"[INFO] {path.name}: {len(df):,} rows")
                    return df
                except Exception as e:
                    pass
            print(f"[ERROR] Cannot load {path.name}")
            return pd.DataFrame()

        print(f"\n[LOAD] Case: {case_dir.name}")
        self.summary     = json.loads((case_dir / "UNIFIED_SUMMARY.json").read_text(
                            encoding="utf-8")) if (case_dir / "UNIFIED_SUMMARY.json").exists() else {}
        self.timeline    = _csv(case_dir / "UNIFIED_TIMELINE.csv")
        self.iocs        = _csv(art / "iocs.csv")
        self.processes   = _csv(art / "processes.csv")
        self.network     = _csv(art / "network.csv")
        self.users       = _csv(art / "users.csv")
        self.persistence = _csv(art / "persistence.csv")
        self.bulk        = _csv(art / "bulk_extractor.csv")

        # Wazuh CSV (fallback when VM is offline)
        self.wazuh = pd.DataFrame()
        for wp in [art / "wazuh_alerts.csv", case_dir / "wazuh_alerts.csv"]:
            if wp.exists():
                self.wazuh = _csv(wp)
                print(f"[INFO] Wazuh CSV: {len(self.wazuh):,} rows")
                break

        # AI results
        self.ai_results = pd.DataFrame()
        for ap in [art / "anomaly_results.csv", case_dir / "anomaly_results.csv"]:
            if ap.exists():
                self.ai_results = _csv(ap)
                break

        # Enrichment
        self.enriched_ips = self.enriched_domains = []
        for attr, fname in [("enriched_ips","enriched_ips.json"),
                             ("enriched_domains","enriched_domains.json")]:
            p = art / fname
            if p.exists():
                try:
                    key = attr.split("_")[1]   # "ips" or "domains"
                    setattr(self, attr,
                            json.loads(p.read_text(encoding="utf-8")).get(key, []))
                except Exception:
                    pass

        # Correlation
        self.corr_results = []
        cp = art / "correlation_results.json"
        if cp.exists():
            try:
                d = json.loads(cp.read_text(encoding="utf-8"))
                self.corr_results = d.get("results", d) if isinstance(d, dict) else d
                print(f"[INFO] Correlation: {len(self.corr_results):,} events")
            except Exception:
                pass

        # Attack chains (pre-built)
        self.chains = []
        chp = art / "attack_chains.json"
        if chp.exists():
            try:
                d = json.loads(chp.read_text(encoding="utf-8"))
                self.chains = d.get("chains", [])
                print(f"[INFO] Attack chains: {len(self.chains)}")
            except Exception:
                pass

        self.loaded = True
        print(f"[INFO] Loaded: timeline={len(self.timeline):,} "
              f"iocs={len(self.iocs):,} ai={len(self.ai_results):,} "
              f"wazuh={len(self.wazuh):,}")


DB = CaseData()


def require_loaded():
    if not DB.loaded:
        raise HTTPException(503, "No case loaded. Start with --case flag.")


def _df_records(df: pd.DataFrame, limit: int = 2000, offset: int = 0) -> List[Dict]:
    if df.empty:
        return []
    rows = df.iloc[offset:offset + limit].to_dict(orient="records")
    return [{k: ("" if isinstance(v, float) and (math.isnan(v) or math.isinf(v)) else v)
             for k, v in r.items()} for r in rows]


def _search(df: pd.DataFrame, q: str, cols: List[str]) -> pd.DataFrame:
    if not q:
        return df
    q = q.lower()
    ec = [c for c in cols if c in df.columns]
    if not ec:
        return df
    mask = df[ec].apply(lambda col: col.str.lower().str.contains(q, na=False, regex=False)).any(axis=1)
    return df[mask]


def _filter(df: pd.DataFrame, filters: Dict[str, str]) -> pd.DataFrame:
    for col, val in filters.items():
        if val and val.lower() != "all" and col in df.columns:
            df = df[df[col].str.lower() == val.lower()]
    return df


# ======================================================================
# WAZUH CACHE  (15-min in-memory cache, thread-safe)
# Solves: Wazuh VM shuts down → API hangs → dashboard freezes.
# Solution: cache last successful response, serve stale if VM is gone.
# ======================================================================

_WAZ_LOCK           = threading.Lock()
_WAZ_CACHE_ALERTS   = None   # dict or None
_WAZ_CACHE_SUMMARY  = None   # dict or None
_WAZ_CACHE_TS       = 0.0    # epoch of last successful fetch
_WAZ_TTL            = 900    # 15 minutes

def _waz_cache_stale() -> bool:
    return (time.time() - _WAZ_CACHE_TS) > _WAZ_TTL

def _b64(u: str, p: str) -> str:
    return base64.b64encode(f"{u}:{p}".encode()).decode()

def _manager_token() -> Optional[str]:
    if not REQUESTS_OK or not WAZUH_CFG.get("password"):
        return None
    try:
        r = requests.post(
            f"{WAZUH_CFG['url'].rstrip('/')}/security/user/authenticate",
            headers={"Authorization": f"Basic {_b64(WAZUH_CFG['user'], WAZUH_CFG['password'])}"},
            verify=WAZUH_CFG["verify"], timeout=(3, 8))
        if r.status_code == 200:
            return r.json().get("data", {}).get("token")
    except Exception:
        pass
    return None

def _indexer_url() -> str:
    import re
    return re.sub(r":55000$", ":9200", WAZUH_CFG["url"].rstrip("/"))

def _indexer_post(path: str, body: dict) -> dict:
    if not REQUESTS_OK:
        return {}
    creds = []
    if WAZUH_CFG.get("indexer_password"):
        creds += [("admin", WAZUH_CFG["indexer_password"]),
                  ("kibanaserver", WAZUH_CFG["indexer_password"])]
    if WAZUH_CFG.get("password"):
        creds += [("admin", WAZUH_CFG["password"])]
    for u, p in creds:
        try:
            r = requests.post(f"{_indexer_url()}{path}",
                              headers={"Authorization": f"Basic {_b64(u,p)}",
                                       "Content-Type": "application/json"},
                              json=body, verify=WAZUH_CFG["verify"], timeout=(3, 10))
            if r.ok:
                return r.json()
            if r.status_code in (401, 403):
                continue
        except Exception:
            pass
    return {}

def _fetch_alerts_live(level="all", q="", limit=500, offset=0) -> Optional[dict]:
    """Try indexer first, fall back to manager API."""
    if not REQUESTS_OK or not WAZUH_CFG.get("password"):
        return None
    must = []
    if level != "all":
        must.append({"term": {"rule.level": int(level)}})
    if q:
        must.append({"multi_match": {"query": q,
                                     "fields": ["rule.description","agent.name","full_log"]}})
    body = {"from": offset, "size": min(limit, 500),
            "sort": [{"timestamp": {"order": "desc"}}],
            "query": {"bool": {"must": must}} if must else {"match_all": {}}}
    res = _indexer_post("/wazuh-alerts-*/_search", body)
    if res:
        hits = res.get("hits", {})
        rows = []
        for h in hits.get("hits", []):
            s = h.get("_source", {})
            rule = s.get("rule", {}); agent = s.get("agent", {})
            rows.append({
                "timestamp":        s.get("timestamp", ""),
                "rule_id":          rule.get("id", ""),
                "rule_level":       str(rule.get("level", "")),
                "rule_description": rule.get("description", ""),
                "agent_name":       agent.get("name", ""),
                "agent_ip":         agent.get("ip", ""),
                "full_log":         str(s.get("full_log", ""))[:500],
                "groups":           ", ".join(rule.get("groups", [])),
            })
        tv = hits.get("total", {})
        total = tv.get("value", len(rows)) if isinstance(tv, dict) else tv
        return {"total": total, "rows": rows, "source": "wazuh_indexer"}
    return None

def _fetch_summary_live() -> Optional[dict]:
    if not REQUESTS_OK or not WAZUH_CFG.get("password"):
        return None
    body = {"size": 0, "aggs": {
        "by_level":  {"terms": {"field": "rule.level", "size": 20}},
        "top_rules": {"terms": {"field": "rule.description", "size": 10}},
        "by_agent":  {"terms": {"field": "agent.name", "size": 10}},
        "critical":  {"filter": {"range": {"rule.level": {"gte": 12}}}},
        "high":      {"filter": {"range": {"rule.level": {"gte": 10, "lte": 11}}}},
    }}
    res = _indexer_post("/wazuh-alerts-*/_search", body)
    if not res:
        return None
    aggs  = res.get("aggregations", res.get("aggregations", {}))
    tv    = res.get("hits", {}).get("total", {})
    total = tv.get("value", 0) if isinstance(tv, dict) else tv
    return {
        "loaded":          True,
        "source":          "wazuh_indexer_cached",
        "wazuh_url":       WAZUH_CFG["url"],
        "total":           total,
        "critical_alerts": aggs.get("critical", {}).get("doc_count", 0),
        "high_alerts":     aggs.get("high", {}).get("doc_count", 0),
        "by_level":        {str(b["key"]): b["doc_count"]
                            for b in aggs.get("by_level", {}).get("buckets", [])},
        "top_rules":       {b["key"]: b["doc_count"]
                            for b in aggs.get("top_rules", {}).get("buckets", [])},
        "by_agent":        {b["key"]: b["doc_count"]
                            for b in aggs.get("by_agent", {}).get("buckets", [])},
        "active_agents":   {},
    }

def _get_wazuh_alerts(level="all", q="", limit=500, offset=0) -> dict:
    """
    Return Wazuh alerts with cache fallback.
    Priority: live indexer → cache → CSV → empty.
    Never blocks for more than 10 s.
    """
    global _WAZ_CACHE_ALERTS, _WAZ_CACHE_TS
    with _WAZ_LOCK:
        if _waz_cache_stale():
            live = _fetch_alerts_live(level=level, q=q, limit=limit, offset=offset)
            if live:
                _WAZ_CACHE_ALERTS = live
                _WAZ_CACHE_TS = time.time()
                return {**live, "cached": False}
            # live failed — fall through to cache / CSV
        elif _WAZ_CACHE_ALERTS:
            return {**_WAZ_CACHE_ALERTS, "cached": True,
                    "cached_at": datetime.fromtimestamp(_WAZ_CACHE_TS).isoformat()}

    # CSV fallback
    if not DB.wazuh.empty:
        df = DB.wazuh.copy()
        sc = [c for c in ["rule_description","description","agent_name","full_log"] if c in df.columns]
        df = _search(df, q, sc)
        lc = next((c for c in ["rule_level","level"] if c in df.columns), None)
        if lc and level != "all":
            df = df[df[lc].astype(str) == level]
        return {"total": len(df), "rows": _df_records(df, limit, offset),
                "source": "csv_fallback",
                "note": "Wazuh VM unreachable — serving exported CSV data"}

    return {"total": 0, "rows": [], "source": "none",
            "note": "Wazuh unavailable and no CSV found. "
                    "Run wazuh_export.py while VM is live."}

def _get_wazuh_summary() -> dict:
    global _WAZ_CACHE_SUMMARY, _WAZ_CACHE_TS
    with _WAZ_LOCK:
        if _waz_cache_stale():
            live = _fetch_summary_live()
            if live:
                _WAZ_CACHE_SUMMARY = live
                _WAZ_CACHE_TS = time.time()
                return live
        elif _WAZ_CACHE_SUMMARY:
            return {**_WAZ_CACHE_SUMMARY, "cached": True}

    # CSV fallback
    if not DB.wazuh.empty:
        lc = next((c for c in ["rule_level","level"] if c in DB.wazuh.columns), None)
        rc = next((c for c in ["rule_description","description"] if c in DB.wazuh.columns), None)
        ac = next((c for c in ["agent_name","agent"] if c in DB.wazuh.columns), None)
        lvl = pd.to_numeric(DB.wazuh[lc], errors="coerce") if lc else pd.Series([], dtype=float)
        return {
            "loaded":          True, "source": "csv_fallback",
            "total":           len(DB.wazuh),
            "critical_alerts": int((lvl >= 12).sum()) if lc else 0,
            "high_alerts":     int(((lvl >= 10) & (lvl < 12)).sum()) if lc else 0,
            "by_level":        DB.wazuh[lc].value_counts().to_dict() if lc else {},
            "top_rules":       DB.wazuh[rc].value_counts().head(10).to_dict() if rc else {},
            "by_agent":        DB.wazuh[ac].value_counts().head(10).to_dict() if ac else {},
            "active_agents":   {},
        }
    return {"loaded": False, "source": "none",
            "note": "No Wazuh data. Export while VM is live: python3 wazuh_export.py"}


# ======================================================================
# HELPERS
# ======================================================================

_CAT_MAP = {
    "hayabusa": "windows_event", "prefetch": "process", "shimcache": "process",
    "process": "process", "network": "ip", "user": "user_account",
    "service": "persistence", "scheduled_tasks": "persistence",
    "yara": "malware", "summary_flag": "windows_event",
    "bulk_extractor_url": "url", "bulk_extractor_domain": "domain",
    "bulk_extractor_ip": "ip", "bulk_extractor_email": "email",
    "bulk_extractor": "network_artifact",
}

def _norm_cat(cat: str) -> str:
    if not cat: return "other"
    k = cat.lower().strip()
    if k in _CAT_MAP: return _CAT_MAP[k]
    for pfx, v in _CAT_MAP.items():
        if k.startswith(pfx): return v
    if "url" in k: return "url"
    if "domain" in k: return "domain"
    if "ip" in k: return "ip"
    return k


def _get_chains() -> List[Dict]:
    """Return chains from DB cache or build on-the-fly."""
    if DB.chains:
        return DB.chains
    if DB.corr_results and CHAIN_OK:
        DB.chains = build_attack_chains(DB.corr_results)
    return DB.chains


# ======================================================================
# OVERVIEW
# ======================================================================

@app.get("/api/summary")
def get_summary():
    require_loaded()
    c   = DB.summary.get("counts", {})
    ibd: Dict[str, int] = {}
    if not DB.iocs.empty and "severity" in DB.iocs.columns:
        ibd = DB.iocs["severity"].str.lower().value_counts().to_dict()

    ai_anom = 0
    if not DB.ai_results.empty and "anomaly" in DB.ai_results.columns:
        ai_anom = int((DB.ai_results["anomaly"].astype(str) == "1").sum())

    return {
        "case_id":        DB.summary.get("case_id", DB.case_dir.name if DB.case_dir else "Unknown"),
        "normalized_at":  DB.summary.get("normalized_at", ""),
        "os_sources":     DB.summary.get("os_sources", []),
        "timeline_range": DB.summary.get("timeline_range", {}),
        "counts": {
            "timeline_events": len(DB.timeline),
            "iocs":            len(DB.iocs),
            "processes":       len(DB.processes),
            "network":         len(DB.network),
            "users":           len(DB.users),
            "persistence":     len(DB.persistence),
            "wazuh_alerts":    len(DB.wazuh),
            "ai_anomalies":    ai_anom,
        },
        "ioc_breakdown":  ibd,
        "wazuh_loaded":   not DB.wazuh.empty,
        "ai_loaded":      not DB.ai_results.empty,
    }


@app.get("/api/overview/charts")
def get_overview_charts():
    require_loaded()
    def _safe(fn):
        try: return fn()
        except: return {}

    result = {
        "ioc_severity":     _safe(lambda: DB.iocs["severity"].value_counts().to_dict()
                                  if not DB.iocs.empty and "severity" in DB.iocs.columns else {}),
        "events_by_os":     _safe(lambda: DB.timeline["os"].value_counts().to_dict()
                                  if not DB.timeline.empty and "os" in DB.timeline.columns else {}),
        "ioc_categories":   _safe(lambda: DB.iocs["category"].map(_norm_cat).value_counts().head(10).to_dict()
                                  if not DB.iocs.empty and "category" in DB.iocs.columns else {}),
        "events_by_source": _safe(lambda: DB.timeline["source"].value_counts().head(12).to_dict()
                                  if not DB.timeline.empty and "source" in DB.timeline.columns else {}),
        "events_per_day":   _safe(lambda: (
            lambda ts: ts[ts.str.len() == 10].value_counts().sort_index().to_dict()
        )(DB.timeline["timestamp_utc"].str[:10])
                                  if not DB.timeline.empty and "timestamp_utc" in DB.timeline.columns else {}),
    }
    return result


# ======================================================================
# TIMELINE
# ======================================================================

@app.get("/api/timeline")
def get_timeline(q: str = Query(""), os: str = Query("all"),
                 sev: str = Query("all"), ioc: str = Query("all"),
                 etype: str = Query("all"),
                 limit: int = Query(500, le=2000), offset: int = Query(0)):
    require_loaded()
    df = DB.timeline.copy()
    df = _search(df, q, ["timestamp_utc","description","username","source","event_type","hostname"])
    df = _filter(df, {"os": os, "severity": sev, "event_type": etype})
    if ioc == "true" and "ioc_flag" in df.columns:
        df = df[df["ioc_flag"].str.lower() == "true"]
    return {"total": len(df), "rows": _df_records(df, limit, offset)}


@app.get("/api/timeline/heatmap")
def get_timeline_heatmap():
    require_loaded()
    if DB.timeline.empty or "timestamp_utc" not in DB.timeline.columns:
        return {"data": []}
    ts  = pd.to_datetime(DB.timeline["timestamp_utc"], errors="coerce", utc=True)
    hm  = pd.DataFrame({"hour": ts.dt.hour, "dow": ts.dt.dayofweek}).dropna()
    out = hm.groupby(["dow","hour"]).size().reset_index(name="count")
    return {"data": out.to_dict(orient="records")}


# ======================================================================
# IOCs
# ======================================================================

@app.get("/api/iocs")
def get_iocs(q: str = Query(""), os: str = Query("all"),
             sev: str = Query("all"), cat: str = Query("all"),
             limit: int = Query(500, le=2000), offset: int = Query(0)):
    require_loaded()
    df = DB.iocs.copy()
    df = _search(df, q, ["description","raw_value","category"])
    df = _filter(df, {"os": os, "severity": sev, "category": cat})
    return {"total": len(df), "rows": _df_records(df, limit, offset)}


@app.get("/api/iocs/categories")
def get_ioc_categories():
    require_loaded()
    if DB.iocs.empty or "category" not in DB.iocs.columns:
        return {"categories": []}
    return {"categories": sorted(DB.iocs["category"].dropna().unique().tolist())}


# ======================================================================
# PROCESSES / NETWORK / USERS / PERSISTENCE / BULK
# ======================================================================

@app.get("/api/processes")
def get_processes(q: str = Query(""), os: str = Query("all"),
                  ioc: str = Query("all"),
                  limit: int = Query(500, le=2000), offset: int = Query(0)):
    require_loaded()
    df = _search(DB.processes.copy(), q, ["name","path","cmdline","user"])
    df = _filter(df, {"os": os})
    if ioc == "true" and "ioc_flag" in df.columns:
        df = df[df["ioc_flag"].str.lower() == "true"]
    return {"total": len(df), "rows": _df_records(df, limit, offset)}


@app.get("/api/network")
def get_network(q: str = Query(""), os: str = Query("all"),
                ioc: str = Query("all"),
                limit: int = Query(500, le=2000), offset: int = Query(0)):
    require_loaded()
    df = _search(DB.network.copy(), q, ["remote_address","remote_port","process_name","local_address"])
    df = _filter(df, {"os": os})
    if ioc == "true" and "ioc_flag" in df.columns:
        df = df[df["ioc_flag"].str.lower() == "true"]
    return {"total": len(df), "rows": _df_records(df, limit, offset)}


@app.get("/api/users")
def get_users(q: str = Query(""), os: str = Query("all"),
              ioc: str = Query("all"),
              limit: int = Query(500, le=2000), offset: int = Query(0)):
    require_loaded()
    df = _search(DB.users.copy(), q, ["username","home","shell"])
    df = _filter(df, {"os": os})
    if ioc == "true" and "ioc_flag" in df.columns:
        df = df[df["ioc_flag"].str.lower() == "true"]
    return {"total": len(df), "rows": _df_records(df, limit, offset)}


@app.get("/api/persistence")
def get_persistence(q: str = Query(""), os: str = Query("all"),
                    ioc: str = Query("all"), category: str = Query("all"),
                    limit: int = Query(500, le=2000), offset: int = Query(0)):
    require_loaded()
    df = DB.persistence.copy()
    if q:
        df = _search(df, q, ["entry","source","ioc_reason"])
    df = _filter(df, {"os": os})
    if category != "all" and "source" in df.columns:
        cats = {"registry":["registry","run_keys"],"scheduled_task":["scheduled_tasks","schtasks"],
                "service":["services","service"],"cron":["cron","crontab","all_persistence"],
                "startup":["startup","shell_startup"]}
        tgt = cats.get(category.lower(), [category.lower()])
        df  = df[df["source"].str.lower().apply(lambda s: any(t in s for t in tgt))]
    if ioc == "true" and "ioc_flag" in df.columns:
        df = df[df["ioc_flag"].str.lower() == "true"]
    return {
        "total": len(df), "rows": _df_records(df, limit, offset),
        "sources": sorted(DB.persistence["source"].dropna().unique().tolist())
                   if not DB.persistence.empty and "source" in DB.persistence.columns else [],
    }


@app.get("/api/bulk")
def get_bulk(q: str = Query(""), type_: str = Query("all", alias="type"),
             limit: int = Query(500, le=2000), offset: int = Query(0)):
    require_loaded()
    df = _search(DB.bulk.copy(), q, ["value","context"])
    df = _filter(df, {"type": type_})
    return {"total": len(df), "rows": _df_records(df, limit, offset)}


@app.get("/api/bulk/types")
def get_bulk_types():
    require_loaded()
    if DB.bulk.empty or "type" not in DB.bulk.columns:
        return {"types": []}
    return {"types": sorted(DB.bulk["type"].dropna().unique().tolist())}


# ======================================================================
# WAZUH  (cached)
# ======================================================================

@app.get("/api/wazuh/count")
def get_wazuh_count():
    """Fast badge count — never contacts VM, CSV only."""
    require_loaded()
    if DB.wazuh.empty:
        return {"count": 0, "source": "none"}
    lc = next((c for c in ["rule_level","level"] if c in DB.wazuh.columns), None)
    return {
        "count":    len(DB.wazuh),
        "critical": int((DB.wazuh[lc].astype(str).isin(["12","13","14","15"])).sum()) if lc else 0,
        "high":     int((DB.wazuh[lc].astype(str).isin(["10","11"])).sum()) if lc else 0,
        "source":   "csv",
    }


@app.get("/api/wazuh")
def get_wazuh(q: str = Query(""), level: str = Query("all"),
              limit: int = Query(500, le=2000), offset: int = Query(0)):
    require_loaded()
    return _get_wazuh_alerts(level=level, q=q, limit=limit, offset=offset)


@app.get("/api/wazuh/summary")
def get_wazuh_summary():
    require_loaded()
    return _get_wazuh_summary()


# ======================================================================
# AI RESULTS
# ======================================================================

@app.get("/api/ai/results")
def get_ai_results(q: str = Query(""), anomaly: str = Query("all"),
                   tier: str = Query("all"), os: str = Query("all"),
                   mitre: str = Query(""), date_from: str = Query(""),
                   date_to: str = Query(""),
                   limit: int = Query(500, le=2000), offset: int = Query(0)):
    require_loaded()
    if DB.ai_results.empty:
        return {"total": 0, "rows": []}
    df = DB.ai_results.copy()
    df = _search(df, q, [c for c in ["description","source","event_type","hostname","mitre_technique"] if c in df.columns])
    if anomaly == "true" and "anomaly" in df.columns:
        df = df[df["anomaly"].astype(str) == "1"]
    if tier != "all" and "alert_tier" in df.columns:
        df = df[df["alert_tier"].str.upper() == tier.upper()]
    # OS filter: match partial (e.g. 'windows' matches 'Windows Server 2019')
    if os != "all" and "os" in df.columns:
        df = df[df["os"].fillna("").str.lower().str.contains(os.lower(), regex=False)]
    # MITRE filter
    if mitre and "mitre_technique" in df.columns:
        df = df[df["mitre_technique"].fillna("").str.contains(mitre, case=False, regex=False)]
    # Date range filter using timestamp_utc prefix
    if date_from and "timestamp_utc" in df.columns:
        df = df[df["timestamp_utc"].fillna("").str[:10] >= date_from[:10]]
    if date_to and "timestamp_utc" in df.columns:
        df = df[df["timestamp_utc"].fillna("").str[:10] <= date_to[:10]]
    # FP filter: remove empty/very-short descriptions (artifact noise)
    if "description" in df.columns:
        df = df[df["description"].fillna("").str.strip().str.len() > 10]
    return {"total": len(df), "rows": _df_records(df, limit, offset)}


@app.get("/api/ai/summary")
def get_ai_summary():
    require_loaded()
    if DB.ai_results.empty:
        return {"loaded": False, "note": "Run ai_model_v9.py and copy anomaly_results.csv to artifacts/"}
    total   = len(DB.ai_results)
    acol    = "anomaly"       if "anomaly"       in DB.ai_results.columns else None
    scol    = "anomaly_score" if "anomaly_score" in DB.ai_results.columns else None
    n_anom  = int((DB.ai_results[acol].astype(str) == "1").sum()) if acol else 0
    rate    = round(n_anom / max(total, 1) * 100, 2)
    top     = []
    if acol and scol:
        td = DB.ai_results[DB.ai_results[acol].astype(str) == "1"].copy()
        td["_s"] = pd.to_numeric(td[scol], errors="coerce")
        top = _df_records(td.nlargest(20, "_s").drop(columns=["_s"]))
    td_breakdown: Dict[str, int] = {}
    if "alert_tier" in DB.ai_results.columns and acol:
        td_breakdown = DB.ai_results[DB.ai_results[acol].astype(str) == "1"][
            "alert_tier"].value_counts().to_dict()
    mitre: Dict[str, int] = {}
    if acol and "mitre_technique" in DB.ai_results.columns:
        for cell in DB.ai_results[DB.ai_results[acol].astype(str) == "1"]["mitre_technique"].dropna():
            for t in str(cell).split(","):
                t = t.strip()
                if t: mitre[t] = mitre.get(t, 0) + 1
        mitre = dict(sorted(mitre.items(), key=lambda x: -x[1])[:15])
    return {"loaded": True, "total_events": total, "n_anomalies": n_anom,
            "anomaly_rate": rate, "top_anomalies": top,
            "tier_breakdown": td_breakdown, "mitre_breakdown": mitre}


@app.get("/api/ai/risk_score")
def get_risk_score():
    """
    5-component risk score from case_manager.py.
    If case_manager unavailable, falls back to the original 3-component formula.
    """
    require_loaded()
    if CASE_MGR_OK:
        return compute_risk_score(
            iocs_df       = DB.iocs,
            ai_results_df = DB.ai_results,
            corr_results  = DB.corr_results,
            chains        = _get_chains(),
            wazuh_df      = DB.wazuh,
        )
    # Fallback: original formula
    ioc_crit = ioc_high = ioc_med = 0
    if not DB.iocs.empty and "severity" in DB.iocs.columns:
        vc = DB.iocs["severity"].value_counts()
        ioc_crit = int(vc.get("critical", 0)); ioc_high = int(vc.get("high", 0))
        ioc_med  = int(vc.get("medium", 0))
    ioc_score = round(min(40, (ioc_crit*4+ioc_high*1.5+ioc_med*0.3)/max(1,20)), 1)
    ai_crit = ai_high = ai_other = 0
    if not DB.ai_results.empty and "anomaly" in DB.ai_results.columns:
        anom = DB.ai_results[DB.ai_results["anomaly"].astype(str) == "1"]
        if "alert_tier" in anom.columns:
            tc = anom["alert_tier"].value_counts()
            ai_crit = int(tc.get("CRITICAL",0)); ai_high = int(tc.get("HIGH",0))
            ai_other= int(tc.get("MEDIUM",0))+int(tc.get("LOW",0))
        else: ai_other = len(anom)
    ai_score = round(min(35,(ai_crit*0.8+ai_high*0.2+ai_other*0.05)/5), 1)
    waz_s = _get_wazuh_summary()
    waz_crit = int(waz_s.get("critical_alerts",0) or 0)
    waz_high = int(waz_s.get("high_alerts",0) or 0)
    waz_score = round(min(25,(waz_crit*0.5+waz_high*0.15)/3), 1)
    total = round(min(100, ioc_score+ai_score+waz_score))
    level = "CRITICAL" if total>=80 else "HIGH" if total>=60 else "MEDIUM" if total>=35 else "LOW"
    colors = {"CRITICAL":"#c0392b","HIGH":"#c0641a","MEDIUM":"#8a6d00","LOW":"#1b6b3a"}
    return {"score": total, "level": level, "color": colors[level],
            "formula": "ioc(0-40)+ai(0-35)+wazuh(0-25)"}


@app.get("/api/ai/benchmark")
def get_benchmark():
    """Return saved benchmark report."""
    require_loaded()
    bp = DB.case_dir / "artifacts" / "benchmark_report.json"
    if bp.exists():
        return json.loads(bp.read_text())
    raise HTTPException(404, "Run: python3 benchmark.py --ai-results artifacts/anomaly_results.csv --outdir artifacts/")


@app.post("/api/ai/benchmark/run")
def run_benchmark_api():
    """Run benchmark in-process and save report."""
    require_loaded()
    if not BENCHMARK_OK:
        raise HTTPException(503, "benchmark.py not found")
    art = DB.case_dir / "artifacts"
    try:
        m = run_benchmark(
            ai_results_path   = art / "anomaly_results.csv",
            corr_results_path = art / "correlation_results.json",
            ai_stats_path     = art / "ai_stats.json",
            outdir            = art,
        )
        return {"status": "ok", "score": m.get("overall", {}).get("overall_score", 0)}
    except Exception as e:
        raise HTTPException(500, str(e))

@app.get("/api/ai/drift")
def get_drift_report():
    """Return the drift_report.json saved by model_loader.py."""
    require_loaded()
    for dp in [
        DB.case_dir / "artifacts" / "drift_report.json",
        DB.case_dir / "drift_report.json",
    ]:
        if dp.exists():
            try:
                return json.loads(dp.read_text(encoding="utf-8"))
            except Exception:
                pass
    # No drift report — return neutral (means models were trained on this case)
    return {"drift_score": 0.0, "status": "No drift report — models trained on this case",
            "top_drifted_features": []}


# ======================================================================
# NEW: PER-CASE AI SUMMARY  (ForensicIQ v2.1)
# ======================================================================

@app.get("/api/case/{case_id}/ai_summary")
def get_case_ai_summary(case_id: str):
    """
    Comprehensive AI summary for a specific case.

    Loads:
      - artifacts/model_performance.json   (AI training + detection stats)
      - artifacts/correlation_results.json (IOC correlation engine output)
      - artifacts/anomaly_results.csv      (full scored event log)

    Returns:
      risk, summary, alert_tiers, top_mitre, per_os, model_agreement,
      saturation, top_anomalies (with FP filter + explanations),
      ai_only_findings, events_per_day, wazuh_alerts, false_positives_filtered
    """
    require_loaded()

    # ── 1. Locate case directory ────────────────────────────────────────
    # Accept current loaded case or look up by name in CASES_ROOT
    if DB.case_dir and (DB.case_dir.name == case_id or
                        DB.summary.get("case_id", "") == case_id):
        case_dir = DB.case_dir
    else:
        # Try to find under CASES_ROOT
        candidates = [Path(CASES_ROOT) / case_id] if CASES_ROOT else []
        case_dir   = next((p for p in candidates if p.exists()), DB.case_dir)

    if not case_dir:
        raise HTTPException(404, f"Case '{case_id}' not found.")

    art = case_dir / "artifacts"

    # ── 2. Load model_performance.json ─────────────────────────────────
    perf_path = art / "model_performance.json"
    perf: dict = {}
    if perf_path.exists():
        try:
            perf = json.loads(perf_path.read_text(encoding="utf-8"))
        except Exception:
            pass

    # ── 3. Load correlation_results.json ───────────────────────────────
    corr_path = art / "correlation_results.json"
    corr_raw: dict = {}
    if corr_path.exists():
        try:
            corr_raw = json.loads(corr_path.read_text(encoding="utf-8"))
        except Exception:
            pass
    corr_results: list = (corr_raw.get("results", []) if isinstance(corr_raw, dict)
                          else corr_raw if isinstance(corr_raw, list) else [])

    # ── 4. Load anomaly_results.csv ────────────────────────────────────
    # Use already-loaded DB data if available for this case; otherwise read CSV
    ai_df = DB.ai_results.copy() if not DB.ai_results.empty else pd.DataFrame()
    if ai_df.empty:
        for ap in [art / "anomaly_results.csv", case_dir / "anomaly_results.csv"]:
            if ap.exists():
                try:
                    ai_df = pd.read_csv(ap, dtype=str, low_memory=False).fillna("")
                except Exception:
                    pass
                break

    if ai_df.empty and not perf:
        raise HTTPException(404,
            "No AI results found. Run ai_model_v9.py and copy "
            "anomaly_results.csv + model_performance.json to artifacts/.")

    # ── 5. Risk score ───────────────────────────────────────────────────
    risk: dict = {}
    if RISK_SCORER_OK:
        risk = calculate_risk_score(perf_path, corr_path if corr_path.exists() else None)
    else:
        # Minimal fallback without risk_scorer.py
        risk = {"overall_score": 0, "level": "UNKNOWN", "color": "#888",
                "interpretation": "risk_scorer.py not installed", "components": {}}

    # ── 6. Summary stats ────────────────────────────────────────────────
    det       = perf.get("detection") or {}
    train     = perf.get("training")  or {}
    n_total   = int(train.get("n_total") or (len(ai_df) if not ai_df.empty else 0))
    n_real    = int(train.get("n_real")  or n_total)
    n_anom    = int(det.get("n_anomalies") or 0)
    anom_rate = float(det.get("anomaly_rate_pct") or 0)
    primary_attack_day = perf.get("primary_attack_day", "")

    # Recompute from CSV if model_performance.json wasn't found
    if not perf and not ai_df.empty and "anomaly" in ai_df.columns:
        n_total   = len(ai_df)
        n_anom    = int((ai_df["anomaly"].astype(str) == "1").sum())
        anom_rate = round(n_anom / max(n_total, 1) * 100, 2)

    summary = {
        "total_events":      n_total,
        "real_events":       n_real,
        "ai_anomalies":      n_anom,
        "anomaly_rate":      round(anom_rate, 2),
        "primary_attack_day": primary_attack_day,
    }

    # ── 7. Alert tier distribution ──────────────────────────────────────
    alert_tiers: dict = perf.get("alert_tiers") or {}
    if not alert_tiers and not ai_df.empty and "alert_tier" in ai_df.columns:
        anomdf = ai_df[ai_df["anomaly"].astype(str) == "1"]
        alert_tiers = anomdf["alert_tier"].value_counts().to_dict()

    # ── 8. Top MITRE techniques (top 5) ────────────────────────────────
    top_mitre: dict = {}
    pm = perf.get("top_mitre") or {}
    if pm:
        top_mitre = dict(list(pm.items())[:5])
    elif not ai_df.empty and "mitre_technique" in ai_df.columns:
        counts: dict = {}
        anom_m = ai_df[ai_df.get("anomaly", pd.Series()).astype(str) == "1"] \
                 if "anomaly" in ai_df.columns else ai_df
        for cell in anom_m["mitre_technique"].dropna():
            for t in str(cell).split(","):
                t = t.strip()
                if t:
                    counts[t] = counts.get(t, 0) + 1
        top_mitre = dict(sorted(counts.items(), key=lambda x: -x[1])[:5])

    # ── 9. Per-OS breakdown ─────────────────────────────────────────────
    per_os: dict = perf.get("per_os") or {}
    if not per_os and not ai_df.empty and "os" in ai_df.columns:
        for os_name, grp in ai_df.groupby("os"):
            n_os   = len(grp)
            n_os_a = int((grp["anomaly"].astype(str) == "1").sum()) \
                     if "anomaly" in grp.columns else 0
            per_os[str(os_name)] = {
                "events":    n_os,
                "anomalies": n_os_a,
                "rate_pct":  round(n_os_a / max(n_os, 1) * 100, 2),
            }

    # ── 10. Model agreement ─────────────────────────────────────────────
    model_agreement: dict = perf.get("model_agreement") or {}

    # ── 11. Score saturation ────────────────────────────────────────────
    saturation: dict = perf.get("saturation") or {}

    # ── 12. Build anomaly rows with FP filter and explanations ──────────
    fp_count = 0
    top_anomalies: list = []
    ai_only_findings: list = []

    if not ai_df.empty and "anomaly" in ai_df.columns:
        scol    = "anomaly_score" if "anomaly_score" in ai_df.columns else None
        anom_df = ai_df[ai_df["anomaly"].astype(str) == "1"].copy()

        # Apply false-positive filter
        if FP_FILTER_OK:
            anom_df, fp_count = _fp_filter(anom_df)

        # Sort by score descending
        if scol:
            anom_df["_s"] = pd.to_numeric(anom_df[scol], errors="coerce").fillna(0)
            anom_df = anom_df.sort_values("_s", ascending=False).drop(columns=["_s"])

        # Top 20 anomalies — all sources
        top_rows = _df_records(anom_df.head(20))
        if EXPLAINER_OK:
            top_rows = explain_batch(top_rows)
        top_anomalies = top_rows

        # AI-only findings: anomalies NOT matched by IOC or Wazuh
        ioc_col = next((c for c in ["ioc_flag", "ioc_flag_bin"] if c in anom_df.columns), None)
        if ioc_col:
            # ioc_flag is 'True'/'False' string in CSV; ioc_flag_bin is '0'/'1'
            if ioc_col == "ioc_flag":
                is_ioc = anom_df[ioc_col].str.lower().isin(["true", "1"])
            else:
                is_ioc = anom_df[ioc_col].astype(str).isin(["1", "1.0"])
            ai_only_df = anom_df[~is_ioc]
        else:
            ai_only_df = anom_df

        # Further filter ai_only: high-confidence only (confidence >= 60)
        if "confidence" in ai_only_df.columns:
            ai_only_df = ai_only_df[
                pd.to_numeric(ai_only_df["confidence"], errors="coerce").fillna(0) >= 60
            ]

        # FIX 1: Remove empty/meaningless descriptions (artifact noise from Feb 16 etc.)
        # Events with no description are system artifacts, not real analyst findings.
        if "description" in ai_only_df.columns:
            ai_only_df = ai_only_df[
                ai_only_df["description"].fillna("").str.strip().str.len() > 10
            ]

        ai_only_rows = _df_records(ai_only_df.head(10))

        if EXPLAINER_OK:
            ai_only_rows = explain_batch(ai_only_rows)
        ai_only_findings = ai_only_rows

    # ── 13. Events per day with anomaly overlay ─────────────────────────
    events_per_day: dict = {}
    anomalies_per_day: dict = {}
    if not ai_df.empty and "timestamp_utc" in ai_df.columns:
        ts_col = ai_df["timestamp_utc"].str[:10]
        all_dates = ts_col[ts_col.str.len() == 10]
        events_per_day = all_dates.value_counts().sort_index().to_dict()
        if "anomaly" in ai_df.columns:
            anom_ts = ts_col[ai_df["anomaly"].astype(str) == "1"]
            anomalies_per_day = anom_ts[anom_ts.str.len() == 10].value_counts().sort_index().to_dict()
    elif perf.get("attack_dates"):
        anomalies_per_day = {k: int(v) for k, v in perf["attack_dates"].items()}

    # ── 14. Score distribution ──────────────────────────────────────────
    score_distribution: dict = perf.get("score_distribution") or {}
    if not score_distribution and not ai_df.empty and "anomaly_score" in ai_df.columns:
        real_df = ai_df[ai_df.get("is_artifact", pd.Series("0", index=ai_df.index))
                        .astype(str) != "1"] if "is_artifact" in ai_df.columns else ai_df
        scores  = pd.to_numeric(real_df["anomaly_score"], errors="coerce").dropna().values
        for i in range(10):
            lo, hi = i / 10, (i + 1) / 10
            score_distribution[f"{lo:.1f}-{hi:.1f}"] = int(
                ((scores >= lo) & (scores < hi)).sum())

    # ── 15. Wazuh mock alerts ───────────────────────────────────────────
    wazuh_alerts: list = get_mock_alerts() if MOCK_WAZUH_OK else []

    # ── 16. Drift status ────────────────────────────────────────────────
    drift: dict = {}
    for dp in [art / "drift_report.json", case_dir / "drift_report.json"]:
        if dp.exists():
            try:
                drift = json.loads(dp.read_text(encoding="utf-8"))
                break
            except Exception:
                pass

    # ── Return ──────────────────────────────────────────────────────────
    return {
        "loaded":                  True,
        "case_id":                 case_id,
        "risk":                    risk,
        "summary":                 summary,
        "alert_tiers":             alert_tiers,
        "top_mitre":               top_mitre,
        "per_os":                  per_os,
        "model_agreement":         model_agreement,
        "saturation":              saturation,
        "top_anomalies":           top_anomalies,
        "ai_only_findings":        ai_only_findings,
        "events_per_day":          {k: int(v) for k, v in events_per_day.items()},
        "anomalies_per_day":       {k: int(v) for k, v in anomalies_per_day.items()},
        "score_distribution":      score_distribution,
        "wazuh_alerts":            wazuh_alerts,
        "false_positives_filtered": fp_count,
        "drift":                   drift,
    }




# ======================================================================
# ATTACK CHAINS
# ======================================================================

@app.get("/api/chains/summary")
def get_chains_summary(window_minutes: int = Query(10, ge=1, le=60)):
    require_loaded()
    if not CHAIN_OK:
        raise HTTPException(503, "attack_chain.py not found")
    chains = _get_chains()
    result = _ac_summary(chains)
    # Always include lightweight time-range list so the timeline chart can draw
    # attack-chain highlight bands covering the full case date range (incl. April).
    result["chain_ranges"] = [
        {
            "chain_id":   c.get("chain_id", ""),
            "severity":   c.get("severity", "LOW"),
            "verdict":    c.get("verdict", ""),
            "time_start": str(c.get("time_start", ""))[:10],
            "time_end":   str(c.get("time_end",   ""))[:10],
        }
        for c in chains
        if c.get("time_start") and c.get("time_end")
    ]
    return result


@app.get("/api/chains/detail")
def get_chains_detail(window_minutes: int = Query(10),
                      severity: str = Query("all"), verdict: str = Query("all")):
    require_loaded()
    if not CHAIN_OK:
        raise HTTPException(503, "attack_chain.py not found")
    chains = _get_chains()
    if severity != "all":
        chains = [c for c in chains if c.get("severity","").upper() == severity.upper()]
    if verdict != "all":
        chains = [c for c in chains if c.get("verdict","").upper() == verdict.upper()]
    return {"total": len(chains),
            "chains": [{k:v for k,v in c.items() if k != "events"} for c in chains]}


@app.get("/api/chains/{chain_index}/events")
def get_chain_events(chain_index: int):
    require_loaded()
    chains = _get_chains()
    match  = [c for c in chains if c.get("chain_index") == chain_index]
    if not match:
        raise HTTPException(404, f"Chain {chain_index} not found")
    return {"chain_id": match[0]["chain_id"], "events": match[0].get("events", [])}


# ======================================================================
# CASE MANAGER  (multi-case switching)
# ======================================================================

@app.get("/api/cases")
def list_cases():
    """List all case folders under CASES_ROOT."""
    if not CASE_MGR_OK:
        raise HTTPException(503, "case_manager.py not found")
    return load_case_index(Path(CASES_ROOT))


@app.post("/api/cases/switch")
def switch_case(case_dir: str = Query(..., description="Full path to case directory")):
    """
    Switch the active case. Reloads all data from the new directory.
    The dashboard calls this when the user picks a different case.
    """
    target = Path(case_dir)
    if not target.exists():
        raise HTTPException(404, f"Not found: {case_dir}")
    DB.load(target)
    # Invalidate chains cache so they are rebuilt for new case
    DB.chains = []
    return {"status": "ok", "case_id": DB.summary.get("case_id", target.name),
            "case_dir": str(target)}


@app.get("/api/cases/current")
def current_case():
    require_loaded()
    return {
        "case_id":      DB.summary.get("case_id", DB.case_dir.name if DB.case_dir else ""),
        "case_dir":     str(DB.case_dir) if DB.case_dir else "",
        "normalized_at": DB.summary.get("normalized_at", ""),
    }


# ======================================================================
# MODEL INFERENCE  (score a new case with saved models)
# ======================================================================

@app.post("/api/inference/run")
def run_inference_api(
    timeline: str = Body(..., embed=True),
    outdir:   str = Body(..., embed=True),
    models:   str = Body("", embed=True),
    no_lstm:  bool = Body(False, embed=True),
):
    """
    Score a new timeline using models from a previous case.
    Body JSON: {"timeline": "...", "outdir": "...", "models": "...", "no_lstm": false}
    models defaults to current case's ai_models dir.
    """
    tl_path  = Path(timeline)
    out_path = Path(outdir)
    if not tl_path.exists():
        raise HTTPException(404, f"Timeline not found: {timeline}")

    models_dir = Path(models) if models else (
        DB.case_dir / "artifacts" / "ai_models" if DB.case_dir else None)
    if not models_dir or not models_dir.exists():
        raise HTTPException(404, f"Models dir not found: {models_dir}")

    try:
        from model_loader import run_inference
        stats = run_inference(
            timeline_path = tl_path,
            models_dir    = models_dir,
            outdir        = out_path,
            use_lstm      = not no_lstm,
        )
        return {"status": "ok", **stats}
    except ImportError:
        raise HTTPException(503, "model_loader.py not found next to api.py")
    except Exception as e:
        raise HTTPException(500, str(e))


# ======================================================================
# THREAT HUNTING
# ======================================================================

def _hunting_correlate() -> Dict:
    if DB.ai_results.empty or "anomaly" not in DB.ai_results.columns:
        return {"matches":[], "total_matches":0, "stats":{}, "mitre_breakdown":{}, "events_per_day":{}}

    anom = DB.ai_results[DB.ai_results["anomaly"].astype(str) == "1"].copy()
    if anom.empty:
        return {"matches":[], "total_matches":0, "stats":{}, "mitre_breakdown":{}, "events_per_day":{}}

    anom["_ts"] = pd.to_datetime(anom["timestamp_utc"], errors="coerce", utc=True)

    # Build Wazuh timestamp index for O(log n) lookups
    waz_ts_ns: List[int] = []
    waz_lvl:   Dict[int, str] = {}
    if not DB.wazuh.empty:
        tc  = next((c for c in ["timestamp","Timestamp","timestamp_utc"] if c in DB.wazuh.columns), None)
        lc  = next((c for c in ["rule_level","level"] if c in DB.wazuh.columns), None)
        if tc:
            wdf = DB.wazuh.copy()
            wdf["_wts"] = pd.to_datetime(wdf[tc], errors="coerce", utc=True)
            wdf = wdf.dropna(subset=["_wts"]).sort_values("_wts")
            for _, wr in wdf.iterrows():
                ns = int(wr["_wts"].value)
                waz_ts_ns.append(ns)
                waz_lvl[ns] = str(wr[lc]) if lc else ""

    import bisect
    waz_win = int(pd.Timedelta(minutes=5).value)

    matches = []
    for _, row in anom.iterrows():
        ts   = row.get("_ts")
        ioc  = str(row.get("ioc_flag", "")).lower() in ("true", "1")
        wm   = False; wlvl = ""
        if waz_ts_ns and ts and not pd.isnull(ts):
            ns = int(ts.value)
            lo = bisect.bisect_left(waz_ts_ns, ns - waz_win)
            hi = bisect.bisect_right(waz_ts_ns, ns + waz_win)
            if lo < hi:
                wm = True; wlvl = waz_lvl.get(waz_ts_ns[lo], "")

        corr = "triple" if wm and ioc else "ai_wazuh" if wm else "ai_ioc" if ioc else None
        if corr is None:
            continue
        matches.append({
            "timestamp_utc":    str(row.get("timestamp_utc","")),
            "os":               str(row.get("os","")),
            "source":           str(row.get("source","")),
            "event_type":       str(row.get("event_type","")),
            "description":      str(row.get("description",""))[:300],
            "anomaly_score":    row.get("anomaly_score", 0),
            "alert_tier":       str(row.get("alert_tier","")),
            "confidence":       row.get("confidence", 0),
            "mitre_technique":  str(row.get("mitre_technique","")),
            "ioc_flag":         str(row.get("ioc_flag","")),
            "wazuh_level":      wlvl,
            "correlation_type": corr,
        })

    matches.sort(key=lambda x: float(x.get("anomaly_score",0) or 0), reverse=True)
    triple   = sum(1 for m in matches if m["correlation_type"]=="triple")
    ai_wazuh = sum(1 for m in matches if m["correlation_type"]=="ai_wazuh")
    ai_ioc   = sum(1 for m in matches if m["correlation_type"]=="ai_ioc")

    mitre: Dict[str,int] = {}
    for m in matches:
        for t in str(m.get("mitre_technique","")).split(","):
            t = t.strip()
            if t: mitre[t] = mitre.get(t, 0) + 1

    # events_per_day from CORRELATED MATCHES ONLY (used for match density chart)
    epd: Dict[str,int] = {}
    for m in matches:
        d = str(m["timestamp_utc"])[:10]
        if len(d)==10: epd[d] = epd.get(d,0)+1

    # FIX: full_events_per_day from ALL anomaly_results rows (not just correlated).
    # This ensures the timeline chart covers the entire case date range including
    # April dates that have no Wazuh/IOC corroboration.
    full_epd: Dict[str,int] = {}
    full_anom_epd: Dict[str,int] = {}
    if not DB.ai_results.empty and "timestamp_utc" in DB.ai_results.columns:
        ts_col = DB.ai_results["timestamp_utc"].str[:10]
        full_epd = {k: int(v) for k, v in
                    ts_col[ts_col.str.len() == 10].value_counts().sort_index().items()}
        if "anomaly" in DB.ai_results.columns:
            anom_ts = ts_col[DB.ai_results["anomaly"].astype(str) == "1"]
            full_anom_epd = {k: int(v) for k, v in
                             anom_ts[anom_ts.str.len() == 10].value_counts().sort_index().items()}

    return {
        "matches":      matches[:2000],
        "total_matches": len(matches),
        "stats": {"total_matches":len(matches),"triple_hits":triple,
                  "ai_wazuh":ai_wazuh,"ai_ioc":ai_ioc},
        "mitre_breakdown": dict(sorted(mitre.items(), key=lambda x: -x[1])[:15]),
        "events_per_day":      dict(sorted(epd.items())),       # correlated match density
        "full_events_per_day": full_epd,                        # all events — full date range
        "full_anom_epd":       full_anom_epd,                   # all anomalies — full date range
    }


@app.get("/api/hunting/summary")
def get_hunting_summary():
    require_loaded()
    return _hunting_correlate()


# ======================================================================
# ENRICHMENT
# ======================================================================

@app.get("/api/enrichment/summary")
def get_enrichment_summary():
    require_loaded()
    if not DB.enriched_ips and not DB.enriched_domains:
        return {"loaded": False}
    def rc(lst):
        return {"critical":sum(1 for x in lst if x.get("risk_score",0)>=0.7),
                "high":    sum(1 for x in lst if 0.5<=x.get("risk_score",0)<0.7),
                "medium":  sum(1 for x in lst if 0.3<=x.get("risk_score",0)<0.5),
                "low":     sum(1 for x in lst if 0<x.get("risk_score",0)<0.3),
                "clean":   sum(1 for x in lst if x.get("risk_score",0)==0)}
    return {
        "loaded": True,
        "ips":     {"total":len(DB.enriched_ips),"risk_counts":rc(DB.enriched_ips),
                    "ioc_matches":sum(1 for x in DB.enriched_ips if x.get("ioc_match")),
                    "internal":sum(1 for x in DB.enriched_ips if x.get("type")=="internal"),
                    "external":sum(1 for x in DB.enriched_ips if x.get("type")=="external"),
                    "top_risk":sorted(DB.enriched_ips,key=lambda x:-x.get("risk_score",0))[:20]},
        "domains": {"total":len(DB.enriched_domains),"risk_counts":rc(DB.enriched_domains),
                    "ioc_matches":sum(1 for x in DB.enriched_domains if x.get("ioc_match")),
                    "top_risk":sorted(DB.enriched_domains,key=lambda x:-x.get("risk_score",0))[:20]},
    }


@app.get("/api/enrichment/ips")
def get_enriched_ips(q:str=Query(""),risk:str=Query("all"),
                     type_:str=Query("all",alias="type"),
                     limit:int=Query(200,le=1000),offset:int=Query(0)):
    require_loaded()
    r = DB.enriched_ips
    if type_!="all": r=[x for x in r if x.get("type","")==type_]
    if risk!="all":
        m={"critical":(0.7,1.1),"high":(0.5,0.7),"medium":(0.3,0.5),"low":(0.0,0.3),"clean":(-0.1,0.0001)}
        if risk in m: lo,hi=m[risk]; r=[x for x in r if lo<=x.get("risk_score",0)<hi]
    if q:
        ql=q.lower(); r=[x for x in r if ql in x.get("ip","").lower() or ql in x.get("rdns","").lower()]
    return {"total":len(r),"rows":r[offset:offset+limit]}


@app.get("/api/enrichment/domains")
def get_enriched_domains(q:str=Query(""),risk:str=Query("all"),
                         limit:int=Query(200,le=1000),offset:int=Query(0)):
    require_loaded()
    r = DB.enriched_domains
    if risk!="all":
        m={"critical":(0.7,1.1),"high":(0.5,0.7),"medium":(0.3,0.5),"low":(0.0,0.3),"clean":(-0.1,0.0001)}
        if risk in m: lo,hi=m[risk]; r=[x for x in r if lo<=x.get("risk_score",0)<hi]
    if q:
        ql=q.lower(); r=[x for x in r if ql in x.get("domain","").lower()]
    return {"total":len(r),"rows":r[offset:offset+limit]}


@app.post("/api/enrichment/run")
def trigger_enrichment(geoip_db:str=""):
    require_loaded()
    if not ENRICHMENT_OK: raise HTTPException(503,"enrichment_engine.py not found")
    art=DB.case_dir/"artifacts"; tl=DB.case_dir/"UNIFIED_TIMELINE.csv"; ioc=art/"iocs.csv"
    try:
        result=enrich_run(timeline_path=tl,ioc_path=ioc if ioc.exists() else None,
                          outdir=art,geoip_db=geoip_db)
        DB.enriched_ips=result.get("ips",[]); DB.enriched_domains=result.get("domains",[])
        return {"status":"ok","ips_enriched":len(DB.enriched_ips),
                "domains_enriched":len(DB.enriched_domains)}
    except Exception as e:
        raise HTTPException(500,str(e))


# ======================================================================
# CORRELATION
# ======================================================================

@app.get("/api/correlation/summary")
def get_correlation_summary():
    require_loaded()
    results = DB.corr_results
    if not results:
        if DB.ai_results.empty: return {"loaded":False,"note":"Run correlation_engine.py"}
        if not CORRELATION_OK:  return {"loaded":False,"note":"correlation_engine.py not found"}
        anom = DB.ai_results[DB.ai_results["anomaly"].astype(str)=="1"]
        results = batch_correlate([dict(r) for _,r in anom.iterrows()][:5000])
        DB.corr_results = results

    comp = [r for r in results if r.get("verdict")=="COMPROMISED"]
    susp = [r for r in results if r.get("verdict")=="SUSPICIOUS"]
    norm = [r for r in results if r.get("verdict")=="NORMAL"]

    mitre: Dict[str,int]={}
    for r in comp+susp:
        for t in str(r.get("mitre_technique","")).split(","):
            t=t.strip()
            if t: mitre[t]=mitre.get(t,0)+1

    pats: Dict[str,int]={}
    for r in results:
        for p in (r.get("pattern_flags") or []):
            pats[p]=pats.get(p,0)+1

    epd: Dict[str,int]={}
    for r in comp+susp:
        d=str(r.get("timestamp_utc",""))[:10]
        if len(d)==10: epd[d]=epd.get(d,0)+1

    return {
        "loaded":True,"total":len(results),
        "compromised":len(comp),"suspicious":len(susp),"normal":len(norm),
        "top_compromised":results[:20],
        "mitre_breakdown":dict(sorted(mitre.items(),key=lambda x:-x[1])[:15]),
        "pattern_breakdown":pats,
        "events_per_day":dict(sorted(epd.items())),
        "weights":CORR_WEIGHTS if CORRELATION_OK else {},
    }


@app.get("/api/correlation/results")
def get_correlation_results(q:str=Query(""),verdict:str=Query("all"),
                             limit:int=Query(500,le=2000),offset:int=Query(0)):
    require_loaded()
    if not DB.corr_results and not DB.ai_results.empty and CORRELATION_OK:
        anom=DB.ai_results[DB.ai_results["anomaly"].astype(str)=="1"]
        events=[dict(r) for _,r in anom.iterrows()]
        if DB.enriched_ips or DB.enriched_domains:
            events=attach_enrichment(events,DB.enriched_ips,DB.enriched_domains)
        DB.corr_results=batch_correlate(events[:5000])
    results=DB.corr_results
    if verdict!="all": results=[r for r in results if r.get("verdict","")==verdict.upper()]
    if q:
        ql=q.lower()
        results=[r for r in results if ql in str(r.get("description","")).lower()
                 or ql in str(r.get("mitre_technique","")).lower()]
    return {"total":len(results),"rows":results[offset:offset+limit]}


@app.post("/api/correlation/run")
def trigger_correlation():
    require_loaded()
    if not CORRELATION_OK: raise HTTPException(503,"correlation_engine.py not found")
    if DB.ai_results.empty: raise HTTPException(503,"No AI results")
    anom=DB.ai_results[DB.ai_results["anomaly"].astype(str)=="1"]
    events=[dict(r) for _,r in anom.iterrows()]
    if DB.enriched_ips or DB.enriched_domains:
        events=attach_enrichment(events,DB.enriched_ips,DB.enriched_domains)
    results=batch_correlate(events)
    DB.corr_results=results; DB.chains=[]  # invalidate chain cache
    if DB.case_dir:
        (DB.case_dir/"artifacts"/"correlation_results.json").write_text(
            json.dumps({"generated_at":datetime.utcnow().isoformat(),
                        "total":len(results),"results":results[:5000]},
                       indent=2,default=str))
    comp=sum(1 for r in results if r.get("verdict")=="COMPROMISED")
    susp=sum(1 for r in results if r.get("verdict")=="SUSPICIOUS")
    return {"status":"ok","total":len(results),"compromised":comp,"suspicious":susp}


# ======================================================================
# DASHBOARD + HEALTH + RELOAD
# ======================================================================

_DASHBOARD_HTML_PATH = os.environ.get("FORENSICIQ_DASHBOARD", "")


@app.get("/", response_class=HTMLResponse, include_in_schema=False)
def serve_dashboard():
    for p in [
        Path(_DASHBOARD_HTML_PATH) if _DASHBOARD_HTML_PATH else None,
        Path(__file__).parent / "dist" / "index.html",
        Path(__file__).parent / "dashboard_v2.html",
        Path(__file__).parent / "dashboard.html",
    ]:
        if p and p.exists():
            return HTMLResponse(content=p.read_text(encoding="utf-8"))
    return HTMLResponse("<h2>ForensicIQ API running. Place dashboard_v2.html next to api.py.</h2>")


_REACT_DIST = Path(__file__).parent / "dist"
if _REACT_DIST.exists():
    app.mount("/assets", StaticFiles(directory=str(_REACT_DIST / "assets")), name="assets")


def _check_key(key: Optional[str]):
    if API_KEY and key != API_KEY:
        raise HTTPException(401, "Invalid or missing X-API-Key header")


@app.get("/api/health")
def health(x_api_key: Optional[str] = Header(default=None)):
    _check_key(x_api_key)
    return {
        "status":   "ok",
        "loaded":   DB.loaded,
        "case":     str(DB.case_dir) if DB.case_dir else None,
        "case_id":  DB.summary.get("case_id","") if DB.loaded else "",
        "wazuh_live": REQUESTS_OK and bool(WAZUH_CFG.get("password")),
        "wazuh_cache_age_s": round(time.time()-_WAZ_CACHE_TS) if _WAZ_CACHE_TS else -1,
        "chain_ok":  CHAIN_OK,
        "case_mgr":  CASE_MGR_OK,
        "corr_ok":   CORRELATION_OK,
        "benchmark_ok": BENCHMARK_OK,
    }


@app.post("/api/reload")
def reload_case():
    if DB.case_dir:
        DB.load(DB.case_dir); DB.chains = []
        return {"status": "reloaded", "case_id": DB.summary.get("case_id","")}
    raise HTTPException(400, "No case directory set")


# ======================================================================
# MAIN
# ======================================================================

def main():
    # global declarations must appear before any use of the names inside
    # this function — Python raises SyntaxError otherwise
    global CASES_ROOT, _DASHBOARD_HTML_PATH

    ap = argparse.ArgumentParser(description="ForensicIQ API v2")
    ap.add_argument("--case",      default="", help="Case directory")
    ap.add_argument("--host",      default="0.0.0.0")
    ap.add_argument("--port",      type=int, default=8000)
    ap.add_argument("--dashboard", default="", help="Path to dashboard HTML file")
    ap.add_argument("--cases-root",default=CASES_ROOT, help="Root dir for case index")
    args = ap.parse_args()

    CASES_ROOT = args.cases_root

    # Dashboard resolution
    for candidate in [args.dashboard, DEFAULT_DASHBOARD,
                      str(Path(__file__).parent / "dashboard_v2.html"),
                      str(Path(__file__).parent / "dashboard.html")]:
        if candidate and Path(candidate).exists():
            _DASHBOARD_HTML_PATH = candidate
            os.environ["FORENSICIQ_DASHBOARD"] = candidate
            print(f"[INFO] Dashboard: {candidate}")
            break
    else:
        print("[WARN] No dashboard file found")

    case_path = args.case or DEFAULT_CASE
    case_dir  = Path(case_path)
    if not case_dir.exists():
        print(f"[ERROR] Case not found: {case_dir}")
        sys.exit(1)

    DB.load(case_dir)

    print(f"\n  Dashboard  -> http://localhost:{args.port}/")
    print(f"  API docs   -> http://localhost:{args.port}/docs")
    print(f"  Cases root -> {CASES_ROOT}")
    print(f"  Wazuh cache TTL: {_WAZ_TTL}s (serves stale on VM shutdown)\n")

    uvicorn.run(app, host=args.host, port=args.port, log_level="warning")


if __name__ == "__main__":
    main()
