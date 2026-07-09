# ForensicIQ — AI-Powered Compromise Assessment Platform

> **Graduation Internship Project** · ENET'COM Sfax × EY Advanced Cyber Security Team  
> Automates digital forensics investigation across Windows and Linux environments using an unsupervised AI ensemble, unified event correlation, and an interactive real-time dashboard.

---

## Table of Contents

1. [Overview](#overview)
2. [Architecture](#architecture)
3. [Lab Environment](#lab-environment)
4. [Project Structure](#project-structure)
5. [Pipeline — Step by Step](#pipeline--step-by-step)
   - [Phase 1 · Data Collection (Windows)](#phase-1--data-collection-windows)
   - [Phase 2 · Data Collection (Linux)](#phase-2--data-collection-linux)
   - [Phase 3 · Normalization (Analysis Server)](#phase-3--normalization-analysis-server)
   - [Phase 4 · AI Anomaly Detection](#phase-4--ai-anomaly-detection)
   - [Phase 5 · Enrichment Engine](#phase-5--enrichment-engine)
   - [Phase 6 · Correlation Engine](#phase-6--correlation-engine)
   - [Phase 7 · Dashboard & API](#phase-7--dashboard--api)
6. [Module Reference](#module-reference)
7. [Unified Schema](#unified-schema)
8. [AI Model — Technical Details](#ai-model--technical-details)
9. [Installation](#installation)
10. [Configuration](#configuration)
11. [Running a Full Case](#running-a-full-case)
12. [Security Notes](#security-notes)
13. [Dependencies](#dependencies)

---

## Overview

ForensicIQ is a modular compromise assessment platform built for the EY Advanced Cyber Security Team. It ingests raw forensic artifacts from live Windows and Linux endpoints, normalizes them into a unified timeline, runs a three-model unsupervised AI ensemble to detect anomalies without requiring labelled training data, and surfaces findings through a FastAPI backend and a single-file HTML dashboard.

**Key capabilities:**

- Cross-platform artifact collection — dedicated scripts per OS, no agent required on endpoints
- Unified timeline merging events from both OS into a single normalized schema
- Unsupervised anomaly detection: Autoencoder + LSTM + Isolation Forest ensemble
- Temporal training split — model trains only on pre-attack data, then scores the full timeline
- IOC detection: rule-based flagging of suspicious processes, ports, persistence entries
- IP/domain enrichment: Nmap, reverse DNS, GeoIP, IOC matching
- Event correlation: cross-source verdict (COMPROMISED / SUSPICIOUS / NORMAL)
- Threat hunting: triple-source confirmation (AI anomaly + Wazuh alert + IOC flag)
- Live Wazuh integration via Manager REST API and OpenSearch Indexer
- Interactive dashboard: timeline, IOC explorer, AI results, correlation, network enrichment

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                        COLLECTION PHASE                             │
│                                                                     │
│  Windows Endpoint (192.168.56.10)    Linux Endpoint (192.168.56.11) │
│  ┌──────────────────────────────┐    ┌──────────────────────────┐  │
│  │  windows_collector.ps1/.py   │    │  linux_collector.sh/.py  │  │
│  │  EvtxECmd · PECmd · AppCmd   │    │  ps · ss · Plaso         │  │
│  │  Shimcache · Hayabusa        │    │  bulk_extractor · YARA   │  │
│  │  Volatility (memory)         │    │  auditd logs             │  │
│  └──────────────┬───────────────┘    └────────────┬─────────────┘  │
└─────────────────┼────────────────────────────────┼─────────────────┘
                  │  Transfer parsed CSVs           │
                  ▼                                 ▼
┌─────────────────────────────────────────────────────────────────────┐
│                    ANALYSIS SERVER (192.168.56.103)                 │
│                                                                     │
│  normalizer.py                                                      │
│  ├── WindowsNormalizer  (evtx, prefetch, shimcache, hayabusa, …)   │
│  └── LinuxNormalizer    (plaso, processes, network, users, …)      │
│              │                                                      │
│              ▼                                                      │
│       UNIFIED_TIMELINE.csv  +  artifacts/                          │
│              │                                                      │
│              ├──▶  ai_model.py         (Autoencoder + LSTM + IF)   │
│              ├──▶  enrichment_engine.py (Nmap, DNS, GeoIP, IOC)    │
│              └──▶  correlation_engine.py (verdict scoring)         │
│                           │                                         │
│                           ▼                                         │
│                       api.py  (FastAPI, port 8000)                 │
│                           │                                         │
│                           ▼                                         │
│                    dashboard.html  (browser UI)                    │
└─────────────────────────────────────────────────────────────────────┘
                          ▲
          ┌───────────────┘
          │
┌─────────────────────────────┐
│  Wazuh Server (56.102)      │
│  Manager API  :55000        │
│  OpenSearch   :9200         │
│  QRadar SIEM  (integration) │
└─────────────────────────────┘
```

---

## Lab Environment

| VM | IP | Role | OS |
|---|---|---|---|
| Windows Endpoint | 192.168.56.10 | Target machine — Windows artifacts collected here | Windows 10 |
| Linux Endpoint | 192.168.56.11 | Target machine — Linux artifacts collected here | Ubuntu |
| Wazuh Server | 192.168.56.102 | SIEM — Manager API + OpenSearch Indexer | Ubuntu |
| Analysis Server | 192.168.56.103 | Runs normalizer, AI model, API, dashboard | Ubuntu |
| Windows Forensic Server | 192.168.56.104 | Runs EvtxECmd, PECmd, AppCompatCacheParser | Windows Server |

All VMs are connected on a VirtualBox host-only network. No internet access from endpoints during investigation.

---

## Project Structure

```
ForensicIQ/
│
├── README.md
│
├── collection/
│   ├── windows/
│   │   ├── windows_collector.ps1       # PowerShell: runs EvtxECmd, PECmd, AppCmd, Hayabusa
│   │   └── windows_parser.py           # Parses raw tool output → structured CSVs
│   └── linux/
│       ├── linux_collector.sh          # Bash: ps, ss, crontab, /etc/passwd, auditd
│       └── linux_parser.py             # Parses raw output → structured CSVs
│
├── normalizer.py                       # Merges Windows + Linux parsed output → unified schema
├── ai_model.py                         # Autoencoder + LSTM + Isolation Forest ensemble
├── enrichment_engine.py                # IP/domain enrichment (Nmap, DNS, GeoIP, IOC)
├── correlation_engine.py               # Cross-source event scoring and verdict engine
├── api.py                              # FastAPI backend (serves all data to dashboard)
├── dashboard.html                      # Single-file browser UI
│
├── cases/                              # ← .gitignored — never commit case data
│   ├── parsed/
│   │   ├── windows/CASE-XXX_TIMESTAMP/
│   │   └── linux/CASE-XXX_TIMESTAMP/
│   └── normalized/CASE-XXX_TIMESTAMP/
│       ├── UNIFIED_TIMELINE.csv
│       ├── UNIFIED_SUMMARY.json
│       └── artifacts/
│           ├── iocs.csv
│           ├── processes.csv
│           ├── network.csv
│           ├── users.csv
│           ├── persistence.csv
│           ├── bulk_extractor.csv
│           ├── anomaly_results.csv     # AI model output
│           ├── enriched_ips.json
│           ├── enriched_domains.json
│           └── correlation_results.json
│
└── requirements.txt
```

---

## Pipeline — Step by Step

### Phase 1 · Data Collection (Windows)

Run on the **Windows Forensic Server (192.168.56.104)** against the Windows Endpoint image.

**Tools used:**

| Tool | What it collects | Output location |
|---|---|---|
| EvtxECmd | Windows Event Logs (Security, System, Application, Sysmon) | `01_evtx/*.csv` |
| PECmd | Prefetch files — program execution history with timestamps and run counts | `02_prefetch/prefetch.csv` |
| AppCompatCacheParser | Shimcache — EXE paths from the Application Compatibility Cache | `05_shimcache/shimcache.csv` |
| Hayabusa | Sigma rule–based threat detection over EVTX files | `08_hayabusa/hayabusa.csv` |
| Volatility | Running processes, network connections from memory image | `11_process/`, `11_network/` |
| Task Scheduler / SC | Scheduled tasks, services | `11_process/scheduled_tasks.csv`, `services.csv` |

**Important note on Shimcache:** Shimcache stores the last-modified time of the EXE, not the actual execution time. On a freshly installed OS all entries cluster at the install date. The AI model excludes Shimcache from LSTM training for this reason — it is still parsed and scored by the Autoencoder and Isolation Forest.

```powershell
# Example — run on Windows Forensic Server
.\windows_collector.ps1 -CaseId "CASE-2026-001" -TargetDrive "E:\" -OutDir "D:\cases\collected"
```

The collector script runs each tool and saves structured CSV output under a timestamped case folder. Then transfer the folder to the Analysis Server.

---

### Phase 2 · Data Collection (Linux)

Run on the **Linux Endpoint (192.168.56.11)** directly or from a live boot.

**Tools used:**

| Tool | What it collects | Output location |
|---|---|---|
| Plaso / log2timeline | Full filesystem timeline (auth logs, bash history, syslog, dpkg, systemd) | `05_plaso/linux_timeline.csv` |
| ps auxf | Running processes with full command lines | `02_processes/ps_auxf.csv` |
| ss / netstat | Active TCP connections | `03_network/ss_tcp.csv` |
| /etc/passwd, sudoers | User accounts, sudo rights | `01_users/passwd.csv`, `sudoers.csv` |
| crontab, systemd units | Persistence mechanisms | `04_persistence/all_persistence.csv` |
| bulk_extractor | Domains, IPs, URLs, email addresses from disk image | `07_yara/bulk_extractor/` |
| YARA | Pattern-based malware signature scanning | `07_yara/` |

```bash
# Example — run on Linux Endpoint
sudo bash linux_collector.sh --case CASE-2026-001 --outdir /tmp/forensic_out
# Then transfer to Analysis Server
scp -r /tmp/forensic_out analyst@192.168.56.103:/cases/collected/linux/
```

---

### Phase 3 · Normalization (Analysis Server)

`normalizer.py` reads both parsed directories and produces a single unified timeline and artifact set. Every event — regardless of OS or source tool — is mapped to the same 15-column schema.

```bash
python3 normalizer.py \
    --windows /cases/parsed/windows/CASE-2026-001_20260331 \
    --linux   /cases/parsed/linux/CASE-2026-001_20260331 \
    --case_id CASE-2026-001 \
    --outdir  /cases/normalized
```

**What the normalizer does for Windows:**
- Parses all EVTX CSVs from `01_evtx/`, classifies each event by EventId (logon, process creation, network, scheduled task, etc.), and flags suspicious logon types (Type 3 remote, Type 10 RDP)
- Parses Prefetch for execution history and flags known offensive tool names
- Parses Shimcache and marks all entries as `is_artifact` (no real execution timestamp)
- Parses Hayabusa detections and promotes critical/high findings directly to IOC list
- Parses Volatility process and network output; flags processes running from temp paths or with offensive names
- Parses scheduled tasks and services for suspicious command patterns (PowerShell, certutil, rundll32 from unusual paths)

**What the normalizer does for Linux:**
- Converts the full Plaso timeline, classifying each source (auth log → logon, bash history → shell_command, dpkg → package_install, utmp/wtmp → logon)
- Parses `ps_auxf.csv` and flags processes matching `SUSPICIOUS_PROC_NAMES` or running from `/tmp`, `/dev/shm`
- Parses TCP connections and flags connections to known attacker ports (4444, 1337, 31337, etc.)
- Checks `/etc/passwd` for non-root users with UID=0 — marked critical IOC
- Parses sudoers to identify privilege escalation paths
- Parses all persistence entries (cron, systemd, shell startup files) and flags encoded commands, reverse shells, wget/curl chains
- Extracts domains, IPs, URLs and email addresses from bulk_extractor output

**Output:**
```
/cases/normalized/CASE-2026-001_TIMESTAMP/
├── UNIFIED_TIMELINE.csv      # all events, unified schema
├── UNIFIED_SUMMARY.json      # counts, IOC breakdown, date range
└── artifacts/
    ├── iocs.csv              # all IOCs from both OS
    ├── processes.csv
    ├── network.csv
    ├── users.csv
    ├── persistence.csv
    └── bulk_extractor.csv
```

---

### Phase 4 · AI Anomaly Detection

`ai_model.py` runs the three-model ensemble on `UNIFIED_TIMELINE.csv`.

```bash
python3 ai_model.py \
    --timeline /cases/normalized/CASE-2026-001_TIMESTAMP/UNIFIED_TIMELINE.csv \
    --outdir   /cases/normalized/CASE-2026-001_TIMESTAMP/artifacts
```

**Temporal split:** The model trains only on events before `temporal_train_cutoff` (default: `2026-03-01`). This gives the model a clean pre-attack baseline so that events from the actual attack window score as anomalous.

**Artifact exclusion:** Shimcache, Plaso file-stat metadata, and events with timestamps before `historic_cutoff_year` are excluded from LSTM training and zeroed in the final ensemble score — they cannot be flagged as anomalies.

**Post-processing:**
- Known-benign processes (Windows Defender, Edge updater, .NET JIT, etc.) receive a 40% score reduction
- Events confirmed by the IOC list receive a 30% score boost, capped at 1.0

**Output:** `artifacts/anomaly_results.csv` with columns `anomaly_score`, `ae_score`, `lstm_score`, `if_score`, `anomaly` (0/1), `anomaly_pct_rank`, `alert_tier`, `confidence`, `mitre_technique`.

Inference mode (new data, saved models):
```bash
python3 ai_model.py --timeline new_timeline.csv --outdir ./results --inference
```

---

### Phase 5 · Enrichment Engine

`enrichment_engine.py` extracts all IPs and domains from the timeline and IOC list, then enriches them.

```bash
python3 enrichment_engine.py \
    --timeline /cases/normalized/CASE-2026-001_TIMESTAMP/UNIFIED_TIMELINE.csv \
    --iocs     /cases/normalized/CASE-2026-001_TIMESTAMP/artifacts/iocs.csv \
    --outdir   /cases/normalized/CASE-2026-001_TIMESTAMP/artifacts/
```

**Per IP:**
- Classifies as internal (RFC 1918) or external
- Reverse DNS lookup
- Nmap port scan on internal IPs
- GeoIP lookup for external IPs
- Cross-reference against IOC list
- Risk score 0.0–1.0, risk label CRITICAL / HIGH / MEDIUM / LOW / CLEAN

**Per domain:**
- Forward DNS resolution
- Cross-reference against IOC list

**Output:** `artifacts/enriched_ips.json`, `artifacts/enriched_domains.json`

Can also be triggered live from the dashboard via `POST /api/enrichment/run`.

---

### Phase 6 · Correlation Engine

`correlation_engine.py` takes all AI-confirmed anomalies and scores each one with a unified compromise score using weighted evidence from multiple sources.

```bash
python3 correlation_engine.py \
    --anomalies /cases/normalized/CASE-2026-001_TIMESTAMP/artifacts/anomaly_results.csv \
    --outdir    /cases/normalized/CASE-2026-001_TIMESTAMP/artifacts/
```

**Evidence weights (WEIGHTS dict):**
- AI anomaly score, alert tier, confidence
- IOC flag presence
- Enrichment risk score (IP/domain reputation)
- Pattern flags: rare process, lateral movement, privilege escalation, persistence, potential exfiltration, burst events

**Verdicts:**
- `COMPROMISED` — compromise score ≥ 0.65
- `SUSPICIOUS` — score ≥ 0.35
- `NORMAL` — score < 0.35

**Output:** `artifacts/correlation_results.json`

Can also be triggered live from the dashboard via `POST /api/correlation/run`.

---

### Phase 7 · Dashboard & API

Start the FastAPI backend on the Analysis Server:

```bash
pip3 install fastapi uvicorn pandas python-multipart requests --break-system-packages

python3 api.py \
    --case /cases/normalized/CASE-2026-001_TIMESTAMP \
    --port 8000 \
    --wazuh-url https://192.168.56.102:55000 \
    --wazuh-password YOUR_WAZUH_PASSWORD \
    --wazuh-indexer-password YOUR_INDEXER_ADMIN_PASSWORD
```

Open `dashboard.html` in a browser (or navigate to `http://192.168.56.103:8000/`).

**Wazuh integration modes:**

| Mode | Port | Auth | When to use |
|---|---|---|---|
| Manager REST API | 55000 | JWT (wazuh-wui user) | Agent status, live auth |
| OpenSearch Indexer | 9200 | Basic (admin user) | Full alert history, aggregations |

If no live Wazuh connection, place a `wazuh_alerts.csv` export in `artifacts/` as a fallback.

**API endpoints summary:**

| Endpoint | Description |
|---|---|
| `GET /api/summary` | Case overview counts and IOC breakdown |
| `GET /api/timeline` | Paginated unified event timeline with filters |
| `GET /api/iocs` | IOC explorer with category/severity filters |
| `GET /api/processes` | Process list from both OS |
| `GET /api/network` | Network connections from both OS |
| `GET /api/users` | User accounts with sudo flag |
| `GET /api/persistence` | Persistence mechanisms (registry, cron, services, tasks) |
| `GET /api/wazuh` | Live or CSV Wazuh alerts |
| `GET /api/wazuh/summary` | Alert counts by level, top rules, active agents |
| `GET /api/ai/results` | Full AI anomaly results table |
| `GET /api/ai/summary` | Anomaly counts by tier with top events |
| `GET /api/ai/risk_score` | Composite risk score 0–100 with component breakdown |
| `GET /api/hunting/summary` | Threat hunting: AI × Wazuh × IOC triple correlation |
| `GET /api/enrichment/summary` | IP and domain enrichment results |
| `POST /api/enrichment/run` | Trigger enrichment engine in-process |
| `GET /api/correlation/summary` | Correlation verdicts and MITRE coverage |
| `POST /api/correlation/run` | Re-run correlation engine in-process |
| `GET /api/health` | Health check (requires X-API-Key header) |

---

## Module Reference

| File | Runs on | Description |
|---|---|---|
| `windows_collector.ps1` | Windows Forensic Server | Orchestrates EvtxECmd, PECmd, AppCmd, Hayabusa, Volatility |
| `windows_parser.py` | Windows Forensic Server | Converts raw tool output to structured CSVs |
| `linux_collector.sh` | Linux Endpoint | Collects ps, ss, crontab, passwd, auditd, runs Plaso |
| `linux_parser.py` | Linux Endpoint | Converts raw output to structured CSVs |
| `normalizer.py` | Analysis Server | Merges both OS parsed outputs into unified schema |
| `ai_model.py` | Analysis Server | Autoencoder + LSTM + Isolation Forest ensemble |
| `enrichment_engine.py` | Analysis Server | IP/domain enrichment with Nmap, DNS, GeoIP |
| `correlation_engine.py` | Analysis Server | Cross-source event scoring and verdict engine |
| `api.py` | Analysis Server | FastAPI backend serving dashboard and external tools |
| `dashboard.html` | Browser | Single-file interactive investigation dashboard |

---

## Unified Schema

Every row in `UNIFIED_TIMELINE.csv` has exactly these columns regardless of source OS or tool:

| Column | Description | Example |
|---|---|---|
| `timestamp_utc` | ISO-8601 UTC timestamp | `2026-03-26T13:45:00Z` |
| `timestamp_raw` | Original timestamp string from source tool | `2026-03-26 13:45:00.0000000` |
| `os` | Source operating system | `windows` / `linux` |
| `source` | Source tool/artifact | `evtx` / `prefetch` / `shimcache` / `plaso/AUTH` |
| `source_file` | Original CSV filename | `Security.csv` |
| `event_type` | Logical event category | `logon` / `process_creation` / `network_connection` |
| `hostname` | Machine name | `DESKTOP-ABC123` |
| `username` | User involved if known | `administrator` |
| `process_name` | Executable name if applicable | `mimikatz.exe` |
| `pid` | Process ID if applicable | `1234` |
| `path` | File, registry, or network path | `C:\Users\Public\evil.exe` |
| `description` | Human-readable event summary | `Executed: MIMIKATZ.EXE (run count: 3)` |
| `severity` | `critical` / `high` / `medium` / `low` / `info` | `critical` |
| `ioc_flag` | Rule-based IOC detection | `True` / `False` |
| `raw_fields` | JSON blob of all original fields | `{"EventId": "4624", …}` |

---

## AI Model — Technical Details

### Feature Engineering (27 features)

**Time features (7):** Cyclical sine/cosine encoding of hour-of-day and day-of-week, weekend flag, night flag (22:00–06:00), work-hours flag (08:00–18:00 Mon–Fri).

**Rolling window features (5):** Over a 60-minute sliding window: event count, IOC-flagged event count, user diversity (std of user codes), source diversity (std of source codes), event velocity (events/min).

**IOC features (2):** Binary IOC flag, IOC boost flag (event matches a high/critical IOC from the IOC list).

**Frequency-encoded categoricals (12):** For each of `os`, `source`, `event_type`, `username`, `hostname`, `severity` — both frequency value (how common this value is) and rarity score (1 − frequency, so rare values score high).

### Models

**Autoencoder** (`ae_weight = 0.50`)
- Architecture: Dense [128 → 64 → 32] → bottleneck [10] → Dense [32 → 64 → 128] → output
- BatchNorm + LeakyReLU(0.1) + Dropout(0.35) per layer
- Adam optimizer, lr=5e-4, early stopping on val_loss (patience=18)
- Scores events by mean squared reconstruction error

**LSTM Sequence Detector** (`lstm_weight = 0.20`)
- Architecture: LSTM [48] → LSTM [24] → Dense [16 latent] → RepeatVector → LSTM [24] → LSTM [48] → TimeDistributed Dense
- Sequence length: 24 events (sliding window)
- Trained only on real forensic events (Shimcache and Plaso file-stat excluded)
- Scores by mean squared error across sequence and feature dimensions

**Isolation Forest** (`if_weight = 0.30`)
- 300 trees, contamination=0.05, max_features=0.8, bootstrap=True
- Scores normalized to [0,1] (1 = most anomalous)

### Ensemble
```
final_score = (ae_score × 0.50 + lstm_score × 0.20 + if_score × 0.30)
```
Normalized per-model using non-artifact events only (prevents artifact outliers from compressing real event scores). Artifacts zeroed. Benign patterns suppressed (×0.6). Confirmed IOCs boosted (×1.3, capped at 1.0). Threshold at 95th percentile of real event scores.

---

## Installation

### Analysis Server (Ubuntu)

```bash
# Python dependencies
pip3 install \
    fastapi uvicorn pandas numpy scikit-learn joblib \
    tensorflow requests python-multipart \
    --break-system-packages

# Optional: for enrichment engine
pip3 install python-nmap dnspython geoip2 --break-system-packages
```

### Windows Forensic Server

Download and place in `C:\Tools\`:
- [EvtxECmd](https://github.com/EricZimmerman/evtx) — Event log parser
- [PECmd](https://github.com/EricZimmerman/PECmd) — Prefetch parser
- [AppCompatCacheParser](https://github.com/EricZimmerman/AppCompatCacheParser) — Shimcache parser
- [Hayabusa](https://github.com/Yamato-Security/hayabusa) — Sigma-based EVTX threat detection

### Linux Endpoint

```bash
# Plaso
sudo apt install plaso-tools -y

# bulk_extractor
sudo apt install bulk-extractor -y

# YARA
sudo apt install yara -y
```

---

## Configuration

Before running, edit these values in `api.py`:

```python
# Default case path
DEFAULT_CASE = "/cases/normalized/CASE-2026-001_TIMESTAMP"

# API key for /api/health (set "" to disable)
API_KEY = "your-secret-key-here"

# Wazuh connection
WAZUH_CFG = {
    "url":              "https://192.168.56.102:55000",
    "user":             "wazuh-wui",
    "password":         "",          # ← fill in, or pass via --wazuh-password
    "indexer_password": "",          # ← admin indexer password for OpenSearch
    "verify":           False,
}
```

> **Never commit real credentials.** Use environment variables or CLI flags instead of hardcoding passwords.

To use environment variables:
```bash
export WAZUH_PASSWORD="your_password"
export WAZUH_INDEXER_PASSWORD="your_indexer_password"
```

In `ai_model.py`, set the temporal training cutoff to a date before your known attack window:
```python
'temporal_train_cutoff': '2026-03-01',  # train on Jan–Feb, score all
'historic_cutoff_year':  2024,           # ignore shimcache/OS install artifacts
```

---

## Running a Full Case

```bash
# 1. Collect on Windows (run on Forensic Server 192.168.56.104)
.\windows_collector.ps1 -CaseId CASE-2026-001 -OutDir D:\cases\

# 2. Collect on Linux (run on Linux Endpoint 192.168.56.11)
sudo bash linux_collector.sh --case CASE-2026-001 --outdir /tmp/forensic_out

# 3. Transfer to Analysis Server (192.168.56.103)
scp -r windows_output analyst@192.168.56.103:/cases/parsed/windows/
scp -r linux_output   analyst@192.168.56.103:/cases/parsed/linux/

# 4. Normalize
python3 normalizer.py \
    --windows /cases/parsed/windows/CASE-2026-001_20260331 \
    --linux   /cases/parsed/linux/CASE-2026-001_20260331 \
    --case_id CASE-2026-001 \
    --outdir  /cases/normalized

# 5. Run AI model
python3 ai_model.py \
    --timeline /cases/normalized/CASE-2026-001_TIMESTAMP/UNIFIED_TIMELINE.csv \
    --outdir   /cases/normalized/CASE-2026-001_TIMESTAMP/artifacts

# 6. Run enrichment
python3 enrichment_engine.py \
    --timeline /cases/normalized/CASE-2026-001_TIMESTAMP/UNIFIED_TIMELINE.csv \
    --iocs     /cases/normalized/CASE-2026-001_TIMESTAMP/artifacts/iocs.csv \
    --outdir   /cases/normalized/CASE-2026-001_TIMESTAMP/artifacts/

# 7. Run correlation
python3 correlation_engine.py \
    --anomalies /cases/normalized/CASE-2026-001_TIMESTAMP/artifacts/anomaly_results.csv \
    --outdir    /cases/normalized/CASE-2026-001_TIMESTAMP/artifacts/

# 8. Start API and dashboard
python3 api.py \
    --case /cases/normalized/CASE-2026-001_TIMESTAMP \
    --port 8000 \
    --wazuh-password YOUR_PASSWORD \
    --wazuh-indexer-password YOUR_INDEXER_PASSWORD
```

Then open `http://192.168.56.103:8000/` in your browser.

---

## Security Notes

- **Never commit case data.** The `cases/` directory is in `.gitignore`. Raw timelines, IOC lists, and anomaly results may contain real endpoint data.
- **Scrub `api.py` before pushing.** The `WAZUH_CFG` block and `API_KEY` contain credentials — replace with empty strings or environment variables.
- **Keep the repo private.** Even without case data, the codebase reveals your detection logic, IOC rules, and lab IP addresses.
- **Restrict API access.** Set a strong `API_KEY` in `api.py` and restrict access to the analysis server network interface if exposing port 8000 outside the lab.

---

## Dependencies

| Package | Used by | Purpose |
|---|---|---|
| `fastapi` | api.py | REST API framework |
| `uvicorn` | api.py | ASGI server |
| `pandas` | all Python modules | Data loading, filtering, aggregation |
| `numpy` | ai_model.py | Numerical operations |
| `scikit-learn` | ai_model.py | Isolation Forest, StandardScaler |
| `tensorflow` | ai_model.py | Autoencoder and LSTM models |
| `joblib` | ai_model.py | Model serialization |
| `requests` | api.py | Wazuh REST API calls |
| `urllib3` | api.py | HTTP with SSL warning suppression |
| `python-multipart` | api.py | FastAPI file upload support |

---

*ForensicIQ · Meyssa · ENET'COM Sfax × EY Advanced Cyber Security Team · 2026*
