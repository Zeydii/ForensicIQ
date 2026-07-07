#!/usr/bin/env python3
"""
ForensicIQ — Enrichment Engine
================================
Enriches IPs and domains extracted from the normalized timeline.

Stages:
  1. Extract  — pull IPs / domains from UNIFIED_TIMELINE.csv
  2. Clean    — validate, deduplicate, remove private/noise
  3. Classify — internal vs external, suspicious patterns
  4. Enrich   — GeoIP (offline db), DNS resolution, IOC matching
  5. Scan     — Nmap (internal IPs only, opt-in)
  6. Output   — structured JSON written to artifacts/enriched_ips.json
                                              artifacts/enriched_domains.json

Usage:
  # Basic (no Nmap):
  python3 enrichment_engine.py \
      --timeline /cases/normalized/CASE-2026-001_TIMESTAMP/UNIFIED_TIMELINE.csv \
      --iocs     /cases/normalized/CASE-2026-001_TIMESTAMP/artifacts/iocs.csv \
      --outdir   /cases/normalized/CASE-2026-001_TIMESTAMP/artifacts

  # With Nmap scan of internal IPs:
  python3 enrichment_engine.py --timeline ... --outdir ... --nmap

  # With offline GeoIP database:
  python3 enrichment_engine.py --timeline ... --outdir ... \
      --geoip-db /opt/GeoLite2-City.mmdb

Install (optional extras):
  pip3 install geoip2 dnspython --break-system-packages
"""

import argparse
import csv
import ipaddress
import json
import os
import re
import socket
import subprocess
import sys
import warnings
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

warnings.filterwarnings("ignore")

# ── optional imports ────────────────────────────────────────────────────────
try:
    import geoip2.database
    GEOIP2_OK = True
except ImportError:
    GEOIP2_OK = False

try:
    import dns.resolver
    DNSPYTHON_OK = True
except ImportError:
    DNSPYTHON_OK = False

# ======================================================================
# CONFIGURATION  — adjust weights and thresholds here
# ======================================================================

CFG = {
    # Risk score weights (sum = 1.0 recommended)
    "w_ioc_match":       0.40,   # IP/domain found in IOC list
    "w_suspicious_port": 0.25,   # open port in known-bad list
    "w_pattern":         0.20,   # suspicious naming / pattern
    "w_external":        0.10,   # external IPs are higher risk than internal
    "w_no_rdns":         0.05,   # no reverse DNS = slightly suspicious

    # Nmap: only scan IPs in these private ranges (never scan external)
    "nmap_internal_only": True,
    "nmap_timeout_sec":   120,
    "nmap_flags":         "-sV --open -T4 --max-retries 1 --host-timeout 10s",
    "nmap_always":        True,   # always run nmap on internal IPs

    # Ports considered high-risk if found open
    "suspicious_ports": {
        4444, 4445, 5555, 6666, 7777, 8888, 9999, 1337, 31337,
        2222, 3333, 12345, 6379, 27017, 9200, 5601,   # common pentest/DB ports
    },

    # Domain patterns that raise risk score
    "suspicious_domain_patterns": [
        r"\d{4,}",             # long numeric strings (DGA indicator)
        r"[a-z]{20,}",         # very long random-looking TLD-less strings
        r"\.tk$|\.ml$|\.ga$|\.cf$|\.gq$",   # free TLDs often used by malware
        r"\.onion$",           # Tor
        r"bit\.ly|t\.co|goo\.gl|tinyurl",   # URL shorteners
        r"pastebin\.com|paste\.ee|hastebin", # paste sites
        r"ngrok\.io|serveo\.net|pagekite",   # tunneling services
        r"duckdns\.org|no-ip\.|ddns\.",      # dynamic DNS
    ],

    # DNS: seconds to wait per resolution
    "dns_timeout": 2,

    # Output limits
    "max_ips":      500,
    "max_domains":  500,
}

# ======================================================================
# PRIVATE NETWORK DETECTION
# ======================================================================

_PRIVATE_RANGES = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),
]


def is_private(ip_str: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip_str)
        return any(addr in net for net in _PRIVATE_RANGES)
    except ValueError:
        return False


def is_valid_ip(ip_str: str) -> bool:
    try:
        ipaddress.ip_address(ip_str)
        return True
    except ValueError:
        return False


# ======================================================================
# STEP 1 — EXTRACT IPs AND DOMAINS FROM TIMELINE
# ======================================================================

_IP_RE     = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
_DOMAIN_RE = re.compile(
    r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)'
    r'+(?:com|net|org|io|edu|gov|mil|info|biz|xyz|tk|ml|ga|cf|gq|'
    r'onion|local|internal|corp|lan|ru|cn|de|fr|uk|br|au|nl|pl|se|no)\b',
    re.IGNORECASE,
)
_URL_RE = re.compile(r'https?://([^\s/\'\"<>]+)', re.IGNORECASE)

# Columns most likely to contain IPs / domains
_SEARCH_COLS = [
    "description", "path", "raw_fields", "hostname",
    "remote_address", "local_address", "username",
]


def extract_from_timeline(timeline_path: Path) -> Tuple[Set[str], Set[str]]:
    """
    Extract unique IPs and domains from UNIFIED_TIMELINE.csv.
    Returns (ip_set, domain_set).
    """
    ips:     Set[str] = set()
    domains: Set[str] = set()

    noise_ips = {"0.0.0.0", "255.255.255.255", "127.0.0.1", "::1"}

    print(f"[EXTRACT] Reading {timeline_path.name}")
    with open(timeline_path, encoding="utf-8", errors="replace") as f:
        reader = csv.DictReader(f)
        for row in reader:
            text = " ".join(
                row.get(c, "") for c in _SEARCH_COLS if row.get(c)
            )

            for ip in _IP_RE.findall(text):
                if ip not in noise_ips and is_valid_ip(ip):
                    ips.add(ip)

            # Extract domains from URLs first (more reliable)
            for url_host in _URL_RE.findall(text):
                host = url_host.split(":")[0].split("/")[0].lower()
                if not is_valid_ip(host) and "." in host:
                    domains.add(host)

            for dom in _DOMAIN_RE.findall(text):
                dom = dom.lower().rstrip(".")
                if not is_valid_ip(dom):
                    domains.add(dom)

    # Remove IPs that look like version numbers (e.g. 1.2.3 in "v1.2.3.4")
    valid_ips = {ip for ip in ips if all(0 <= int(o) <= 255 for o in ip.split("."))}

    print(f"[EXTRACT] Found {len(valid_ips)} unique IPs, {len(domains)} unique domains")
    return valid_ips, domains


# ======================================================================
# STEP 2 — LOAD IOC LIST FOR MATCHING
# ======================================================================

def load_ioc_set(ioc_path: Optional[Path]) -> Dict[str, str]:
    """
    Returns {value_lower: severity} for all IOC entries.
    """
    ioc_map: Dict[str, str] = {}
    if not ioc_path or not ioc_path.exists():
        return ioc_map
    with open(ioc_path, encoding="utf-8", errors="replace") as f:
        for row in csv.DictReader(f):
            val = str(row.get("raw_value", "")).lower().strip()
            sev = str(row.get("severity", "medium")).lower()
            if val:
                ioc_map[val] = sev
    print(f"[IOC] Loaded {len(ioc_map)} IOC entries for matching")
    return ioc_map


# ======================================================================
# STEP 3 — GeoIP ENRICHMENT
# ======================================================================

def geoip_lookup(ip: str, reader) -> Dict[str, str]:
    """Return {'country': ..., 'city': ..., 'org': ...} using geoip2 reader."""
    if reader is None:
        return {}
    try:
        resp = reader.city(ip)
        return {
            "country": resp.country.name or "",
            "country_iso": resp.country.iso_code or "",
            "city":    resp.city.name or "",
            "lat":     str(resp.location.latitude or ""),
            "lon":     str(resp.location.longitude or ""),
        }
    except Exception:
        return {}


def open_geoip_reader(db_path: str):
    if not GEOIP2_OK or not db_path or not Path(db_path).exists():
        return None
    try:
        import geoip2.database
        reader = geoip2.database.Reader(db_path)
        print(f"[GEOIP] Loaded database: {db_path}")
        return reader
    except Exception as e:
        print(f"[WARN] GeoIP load failed: {e}")
        return None


# ======================================================================
# STEP 4 — DNS RESOLUTION
# ======================================================================

def resolve_domain(domain: str) -> List[str]:
    """Return list of resolved IPs for a domain. Uses dnspython if available."""
    results: List[str] = []
    if DNSPYTHON_OK:
        try:
            resolver = dns.resolver.Resolver()
            resolver.timeout    = CFG["dns_timeout"]
            resolver.lifetime   = CFG["dns_timeout"]
            for rdata in resolver.resolve(domain, "A"):
                results.append(str(rdata))
        except Exception:
            pass
        if not results:
            try:
                for rdata in dns.resolver.resolve(domain, "AAAA"):
                    results.append(str(rdata))
            except Exception:
                pass
    else:
        # Fallback: stdlib socket
        try:
            socket.setdefaulttimeout(CFG["dns_timeout"])
            for _, _, _, _, sockaddr in socket.getaddrinfo(domain, None):
                results.append(sockaddr[0])
        except Exception:
            pass
    return list(set(results))


def reverse_dns(ip: str) -> str:
    """Attempt reverse DNS lookup."""
    try:
        socket.setdefaulttimeout(CFG["dns_timeout"])
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return ""


# ======================================================================
# STEP 5 — NMAP SCAN (internal IPs only)
# ======================================================================

def nmap_available() -> bool:
    try:
        subprocess.run(["nmap", "--version"], capture_output=True, timeout=5)
        return True
    except Exception:
        return False


def nmap_scan(ip: str) -> Dict[str, Any]:
    """
    Run Nmap against a single internal IP.
    Returns {'ports': [...], 'services': [...], 'status': 'up/down/unknown'}.
    """
    result: Dict[str, Any] = {"ports": [], "services": [], "status": "unknown"}

    if not nmap_available():
        return result

    cmd = ["nmap"] + CFG["nmap_flags"].split() + ["-oX", "-", ip]
    try:
        proc = subprocess.run(
            cmd, capture_output=True, text=True,
            timeout=CFG["nmap_timeout_sec"]
        )
        output = proc.stdout

        # Parse XML output
        status_match = re.search(r'<status state="(\w+)"', output)
        if status_match:
            result["status"] = status_match.group(1)

        for port_match in re.finditer(
            r'<port protocol="\w+" portid="(\d+)">'
            r'.*?<state state="(\w+)".*?/>'
            r'(?:.*?<service name="([^"]*)"[^/]*/?>)?',
            output, re.DOTALL
        ):
            port_num  = int(port_match.group(1))
            state     = port_match.group(2)
            service   = port_match.group(3) or ""
            if state == "open":
                result["ports"].append(port_num)
                if service:
                    result["services"].append(f"{port_num}/{service}")
    except subprocess.TimeoutExpired:
        result["status"] = "timeout"
    except Exception as e:
        result["status"] = f"error: {e}"

    return result


# ======================================================================
# STEP 6 — RISK SCORING
# ======================================================================

def compute_ip_risk(
    ip: str,
    ioc_match: Optional[str],
    open_ports: List[int],
    rdns: str,
    is_ext: bool,
) -> Tuple[float, List[str]]:
    """Returns (risk_score 0–1, [reason strings])."""
    score   = 0.0
    reasons = []

    if ioc_match:
        weight = {"critical": 1.0, "high": 0.8, "medium": 0.5, "low": 0.2}.get(ioc_match, 0.4)
        score += CFG["w_ioc_match"] * weight
        reasons.append(f"IOC match ({ioc_match} severity)")

    bad_ports = [p for p in open_ports if p in CFG["suspicious_ports"]]
    if bad_ports:
        score += CFG["w_suspicious_port"]
        reasons.append(f"Suspicious open port(s): {bad_ports}")

    if is_ext:
        score += CFG["w_external"]
        reasons.append("External IP")

    if not rdns and is_ext:
        score += CFG["w_no_rdns"]
        reasons.append("No reverse DNS")

    return round(min(1.0, score), 3), reasons


def compute_domain_risk(
    domain: str,
    ioc_match: Optional[str],
    resolved_ips: List[str],
) -> Tuple[float, List[str]]:
    """Returns (risk_score 0–1, [reason strings])."""
    score   = 0.0
    reasons = []

    if ioc_match:
        weight = {"critical": 1.0, "high": 0.8, "medium": 0.5, "low": 0.2}.get(ioc_match, 0.4)
        score += CFG["w_ioc_match"] * weight
        reasons.append(f"IOC match ({ioc_match} severity)")

    for pattern in CFG["suspicious_domain_patterns"]:
        if re.search(pattern, domain, re.IGNORECASE):
            score += CFG["w_pattern"]
            reasons.append(f"Suspicious domain pattern: {pattern}")
            break

    if not resolved_ips:
        score += CFG["w_no_rdns"] * 0.5
        reasons.append("Does not resolve (possible sinkhole or inactive C2)")

    # Check if resolved IPs are themselves suspicious (external only)
    ext_ips = [ip for ip in resolved_ips if not is_private(ip)]
    if ext_ips:
        score += CFG["w_external"] * 0.5
        reasons.append(f"Resolves to external IP: {ext_ips[0]}")

    return round(min(1.0, score), 3), reasons


def risk_label(score: float) -> str:
    if score >= 0.7:   return "CRITICAL"
    if score >= 0.5:   return "HIGH"
    if score >= 0.3:   return "MEDIUM"
    if score > 0.0:    return "LOW"
    return "CLEAN"


# ======================================================================
# MAIN PIPELINE
# ======================================================================

def enrich_ips(
    ip_set:    Set[str],
    ioc_map:   Dict[str, str],
    geoip_rdr,
    do_nmap:   bool = True,
) -> List[Dict[str, Any]]:
    """Enrich a set of IP addresses. Returns list of enriched dicts.
    Nmap runs automatically on all internal IPs.
    """
    results = []
    ips = list(ip_set)[:CFG["max_ips"]]
    total = len(ips)
    print(f"\n[IP ENRICHMENT] Processing {total} IPs")

    for idx, ip in enumerate(ips, 1):
        if idx % 50 == 0 or idx == total:
            print(f"  {idx}/{total}")

        internal = is_private(ip)
        ip_type  = "internal" if internal else "external"

        # GeoIP (external only — internal IPs won't resolve)
        geo = geoip_lookup(ip, geoip_rdr) if not internal else {}

        # Reverse DNS
        rdns = reverse_dns(ip)

        # IOC match
        ioc_sev = ioc_map.get(ip.lower())

        # Nmap — always run on internal IPs
        nmap_result: Dict[str, Any] = {"ports": [], "services": [], "status": "skipped"}
        if internal:
            if nmap_available():
                print(f"    [NMAP] scanning {ip}")
                nmap_result = nmap_scan(ip)
            else:
                nmap_result["status"] = "nmap_not_installed"

        # Risk score
        risk_score, reasons = compute_ip_risk(
            ip, ioc_sev,
            nmap_result.get("ports", []),
            rdns, not internal
        )

        results.append({
            "ip":         ip,
            "type":       ip_type,
            "geo":        geo,
            "rdns":       rdns,
            "ioc_match":  ioc_sev or None,
            "ports":      nmap_result.get("ports", []),
            "services":   nmap_result.get("services", []),
            "host_status":nmap_result.get("status", "skipped"),
            "risk_score": risk_score,
            "risk_label": risk_label(risk_score),
            "reasons":    reasons,
        })

    results.sort(key=lambda x: x["risk_score"], reverse=True)
    return results


def enrich_domains(
    domain_set: Set[str],
    ioc_map:    Dict[str, str],
) -> List[Dict[str, Any]]:
    """Enrich a set of domain names. Returns list of enriched dicts."""
    results = []
    domains = list(domain_set)[:CFG["max_domains"]]
    total   = len(domains)
    print(f"\n[DOMAIN ENRICHMENT] Processing {total} domains")

    for idx, domain in enumerate(domains, 1):
        if idx % 50 == 0 or idx == total:
            print(f"  {idx}/{total}")

        # Resolve
        resolved_ips = resolve_domain(domain)

        # IOC match (full domain and parent domain)
        parent = ".".join(domain.split(".")[-2:]) if domain.count(".") >= 1 else domain
        ioc_sev = ioc_map.get(domain.lower()) or ioc_map.get(parent.lower())

        # Risk score
        risk_score, reasons = compute_domain_risk(domain, ioc_sev, resolved_ips)

        results.append({
            "domain":       domain,
            "resolved_ips": resolved_ips,
            "ioc_match":    ioc_sev or None,
            "risk_score":   risk_score,
            "risk_label":   risk_label(risk_score),
            "reasons":      reasons,
        })

    results.sort(key=lambda x: x["risk_score"], reverse=True)
    return results


def run(
    timeline_path:  Path,
    ioc_path:       Optional[Path],
    outdir:         Path,
    geoip_db:       str = "",
) -> Dict[str, Any]:
    """
    Full enrichment pipeline. Nmap runs automatically on internal IPs.
    Returns dict with 'ips' and 'domains' lists.
    """
    print(f"\n{'='*60}")
    print(f"  ForensicIQ Enrichment Engine")
    print(f"  Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"{'='*60}")

    outdir.mkdir(parents=True, exist_ok=True)

    # 1. Extract
    ip_set, domain_set = extract_from_timeline(timeline_path)

    # 2. Load IOCs
    ioc_map = load_ioc_set(ioc_path)

    # 3. Open GeoIP reader
    geoip_rdr = open_geoip_reader(geoip_db)

    # 4. Enrich IPs
    enriched_ips = enrich_ips(ip_set, ioc_map, geoip_rdr, do_nmap=True)

    # 5. Enrich domains
    enriched_domains = enrich_domains(domain_set, ioc_map)

    # 6. Write outputs
    ip_path  = outdir / "enriched_ips.json"
    dom_path = outdir / "enriched_domains.json"

    summary = {
        "generated_at":    datetime.now(timezone.utc).isoformat(),
        "timeline":        str(timeline_path),
        "total_ips":       len(enriched_ips),
        "total_domains":   len(enriched_domains),
        "high_risk_ips":   sum(1 for x in enriched_ips     if x["risk_score"] >= 0.5),
        "high_risk_domains": sum(1 for x in enriched_domains if x["risk_score"] >= 0.5),
        "ioc_matched_ips":     sum(1 for x in enriched_ips     if x["ioc_match"]),
        "ioc_matched_domains": sum(1 for x in enriched_domains if x["ioc_match"]),
    }

    ip_output = {"summary": summary, "ips": enriched_ips}
    dom_output = {"summary": summary, "domains": enriched_domains}

    ip_path.write_text(json.dumps(ip_output, indent=2))
    dom_path.write_text(json.dumps(dom_output, indent=2))

    print(f"\n{'='*60}")
    print(f"  ENRICHMENT COMPLETE")
    print(f"  IPs enriched:     {len(enriched_ips):,}  "
          f"(high risk: {summary['high_risk_ips']})")
    print(f"  Domains enriched: {len(enriched_domains):,}  "
          f"(high risk: {summary['high_risk_domains']})")
    print(f"   {ip_path}")
    print(f"   {dom_path}")
    print(f"{'='*60}\n")

    if geoip_rdr:
        geoip_rdr.close()

    return {"ips": enriched_ips, "domains": enriched_domains, "summary": summary}


# ======================================================================
# CLI
# ======================================================================

def main():
    ap = argparse.ArgumentParser(
        description="ForensicIQ Enrichment Engine — IP and domain enrichment",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Basic (DNS only, no Nmap):
  python3 enrichment_engine.py \\
      --timeline /cases/normalized/CASE-2026-001_TIMESTAMP/UNIFIED_TIMELINE.csv \\
      --iocs     /cases/normalized/CASE-2026-001_TIMESTAMP/artifacts/iocs.csv \\
      --outdir   /cases/normalized/CASE-2026-001_TIMESTAMP/artifacts

  # With GeoIP and Nmap:
  python3 enrichment_engine.py --timeline ... --outdir ... \\
      --geoip-db /opt/GeoLite2-City.mmdb --nmap

GeoIP database (free):
  Register at https://www.maxmind.com and download GeoLite2-City.mmdb
"""
    )
    ap.add_argument("--timeline", required=True)
    ap.add_argument("--iocs",     default="")
    ap.add_argument("--outdir",   default=".")
    ap.add_argument("--geoip-db", default="", help="Path to GeoLite2-City.mmdb")
    args = ap.parse_args()
    print("[INFO] Nmap: enabled for all internal IPs (install nmap if not present)")

    if not GEOIP2_OK:
        print("[INFO] geoip2 not installed — GeoIP lookup disabled")
        print("       pip3 install geoip2 --break-system-packages")
    if not DNSPYTHON_OK:
        print("[INFO] dnspython not installed — using stdlib DNS fallback")
        print("       pip3 install dnspython --break-system-packages")

    run(
        timeline_path = Path(args.timeline),
        ioc_path      = Path(args.iocs) if args.iocs else None,
        outdir        = Path(args.outdir),
        geoip_db      = args.geoip_db,
    )


if __name__ == "__main__":
    main()
