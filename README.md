# ForensicIQ — AI-Powered Compromise Assessment Platform

> Graduation Internship Project · ENET'COM Sfax × EY Advanced Cyber Security Team

ForensicIQ automates digital forensics investigation across Windows and Linux environments. It collects forensic artifacts from live endpoints, normalizes them into a unified timeline, runs an unsupervised AI ensemble to detect anomalies, and surfaces findings through an interactive dashboard.

---

## Table of Contents

1. [Overview](#overview)
2. [Architecture](#architecture)
3. [Pipeline](#pipeline)
4. [Modules](#modules)
5. [AI Model](#ai-model)
6. [Installation](#installation)
7. [Usage](#usage)
8. [API Endpoints](#api-endpoints)

---

## Overview

Traditional compromise assessment is manual, slow, and siloed per operating system. ForensicIQ solves this by:

- Collecting artifacts from both Windows and Linux endpoints using dedicated scripts
- Merging all sources into one unified timeline with a consistent schema
- Detecting anomalies without labelled data using a three-model AI ensemble
- Correlating AI detections with Wazuh alerts and IOC flags for high-confidence verdicts
- Presenting everything in a single interactive dashboard

---

## Architecture

```
<img width="763" height="645" alt="image" src="https://github.com/user-attachments/assets/6ccfea2c-9c07-4031-8349-8317d0044f20" />

```

---

## Pipeline

| Phase | Script | Description |
|---|---|---|
| 1 | `windows_collector` | Runs EvtxECmd, PECmd, AppCompatCacheParser, Hayabusa on the Windows endpoint |
| 2 | `linux_collector` | Runs Plaso, ps, ss, bulk_extractor, YARA on the Linux endpoint |
| 3 | `normalizer.py` | Merges both OS outputs into a single unified timeline |
| 4 | `ai_model.py` | Detects anomalies using Autoencoder + LSTM + Isolation Forest |
| 5 | `enrichment_engine.py` | Enriches IPs and domains with Nmap, DNS, GeoIP, and IOC matching |
| 6 | `correlation_engine.py` | Scores events across all sources and assigns COMPROMISED / SUSPICIOUS / NORMAL verdict |
| 7 | `api.py` + `dashboard.html` | Serves all results through a FastAPI backend and browser dashboard |

---

## Modules

### Windows Collection
Uses **EvtxECmd** to parse Security, System, and Sysmon event logs; **PECmd** for Prefetch execution history; **AppCompatCacheParser** for Shimcache; and **Hayabusa** for Sigma-based threat detection. Output is structured CSVs transferred to the Analysis Server.

### Linux Collection
Uses **Plaso** for a full filesystem timeline covering auth logs, bash history, syslog, dpkg, and systemd journals. Supplements with live `ps`, `ss`, `/etc/passwd`, crontab, and **bulk_extractor** for network artifacts. Output is structured CSVs transferred to the Analysis Server.

### Normalizer
Maps every event from both OS into a unified 15-column schema (`timestamp_utc`, `os`, `source`, `event_type`, `hostname`, `username`, `process_name`, `severity`, `ioc_flag`, ...). Applies rule-based IOC detection: flags suspicious process names, attacker ports, UID=0 non-root users, encoded persistence commands, and suspicious logon types.

### AI Model
Three-model unsupervised ensemble — no labelled training data required. Uses a **temporal split**: the model trains only on events before the known attack window, then scores the full timeline so attack-period events appear anomalous by contrast. See [AI Model](#ai-model) section for details.

### Enrichment Engine
For every IP extracted from the timeline: classifies internal vs. external, reverse DNS, Nmap port scan (internal only), GeoIP (external), IOC cross-reference, risk score 0–1. For every domain: forward DNS resolution and IOC matching.

### Correlation Engine
Takes all AI-confirmed anomalies and assigns a weighted compromise score using: AI anomaly score, alert tier, IOC flag, enrichment risk, and pattern flags (lateral movement, privilege escalation, persistence, potential exfiltration, event burst). Verdicts: **COMPROMISED** ≥ 0.65 · **SUSPICIOUS** ≥ 0.35 · **NORMAL** < 0.35.

### API & Dashboard
FastAPI backend exposing all data. Integrates live with Wazuh via Manager REST API (port 55000) and OpenSearch Indexer (port 9200), with CSV fallback. Single-file HTML dashboard with: unified timeline, IOC explorer, AI anomaly viewer, threat hunting (triple-source correlation), enrichment, correlation, Wazuh alerts, and a composite risk score.

---

## AI Model

### Feature Engineering — 27 features

| Group | Features |
|---|---|
| Time (7) | Hour sin/cos, day-of-week sin/cos, weekend flag, night flag (22:00–06:00), work-hours flag (08:00–18:00 Mon–Fri) |
| Rolling window 60 min (5) | Event count, IOC-flagged count, user diversity, source diversity, event velocity |
| IOC (2) | Binary IOC flag, IOC boost flag |
| Frequency-encoded categoricals (12) | Frequency + rarity score for: os, source, event_type, username, hostname, severity |

### Ensemble

| Model | Weight | Role |
|---|---|---|
| Autoencoder | 0.50 | Dense [128→64→32→bottleneck 10→32→64→128], BatchNorm + LeakyReLU + Dropout(0.35), reconstruction MSE |
| LSTM | 0.20 | Sequence autoencoder over 24-event sliding windows, trained on real events only (Shimcache excluded) |
| Isolation Forest | 0.30 | 300 trees, contamination=0.05, scores normalized to [0,1] |

```
final_score = (ae × 0.50) + (lstm × 0.20) + (if × 0.30)
```

Post-processing: artifacts zeroed · benign patterns suppressed ×0.6 · confirmed IOCs boosted ×1.3 · threshold at 95th percentile.

---

## Installation

### Analysis Server (Ubuntu)

```bash
pip3 install fastapi uvicorn pandas numpy scikit-learn \
             joblib tensorflow requests python-multipart \
             --break-system-packages
```

### Windows Forensic Tools

Download and place in your tools directory:
- [EvtxECmd](https://github.com/EricZimmerman/evtx)
- [PECmd](https://github.com/EricZimmerman/PECmd)
- [AppCompatCacheParser](https://github.com/EricZimmerman/AppCompatCacheParser)
- [Hayabusa](https://github.com/Yamato-Security/hayabusa)

### Linux Tools

```bash
sudo apt install plaso-tools bulk-extractor yara -y
```

---

## Usage

```bash
# 1. Normalize both OS outputs
python3 normalizer.py \
    --windows /cases/parsed/windows/CASE-XXX \
    --linux   /cases/parsed/linux/CASE-XXX \
    --case_id CASE-2026-001 \
    --outdir  /cases/normalized

# 2. Run AI detection
python3 ai_model.py \
    --timeline /cases/normalized/CASE-2026-001_TIMESTAMP/UNIFIED_TIMELINE.csv \
    --outdir   /cases/normalized/CASE-2026-001_TIMESTAMP/artifacts

# 3. Enrich IPs and domains
python3 enrichment_engine.py \
    --timeline /cases/normalized/CASE-2026-001_TIMESTAMP/UNIFIED_TIMELINE.csv \
    --iocs     /cases/normalized/CASE-2026-001_TIMESTAMP/artifacts/iocs.csv \
    --outdir   /cases/normalized/CASE-2026-001_TIMESTAMP/artifacts/

# 4. Run correlation
python3 correlation_engine.py \
    --anomalies /cases/normalized/CASE-2026-001_TIMESTAMP/artifacts/anomaly_results.csv \
    --outdir    /cases/normalized/CASE-2026-001_TIMESTAMP/artifacts/

# 5. Start the dashboard
python3 api.py --case /cases/normalized/CASE-2026-001_TIMESTAMP --port 8000
```

Open `http://localhost:8000` in your browser.

---

## API Endpoints

| Endpoint | Description |
|---|---|
| `GET /api/summary` | Case overview and IOC counts |
| `GET /api/timeline` | Unified event timeline with filters |
| `GET /api/iocs` | IOC explorer |
| `GET /api/processes` | Processes from both OS |
| `GET /api/network` | Network connections |
| `GET /api/users` | User accounts |
| `GET /api/persistence` | Persistence mechanisms |
| `GET /api/wazuh` | Live or CSV Wazuh alerts |
| `GET /api/ai/results` | AI anomaly results |
| `GET /api/ai/risk_score` | Composite risk score 0–100 |
| `GET /api/hunting/summary` | Triple-source threat hunting |
| `GET /api/enrichment/summary` | IP and domain enrichment |
| `POST /api/enrichment/run` | Trigger enrichment in-process |
| `GET /api/correlation/summary` | Correlation verdicts |
| `POST /api/correlation/run` | Re-run correlation engine |
| `GET /api/health` | Health check |

---

*ForensicIQ · ENET'COM Sfax × EY Advanced Cyber Security Team · 2026*
