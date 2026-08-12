# sih1451-graded-firewall
AI/ML tool for non-IoC compromise detection — a graded-response firewall with honeypot deception and selective DLP blocking, built for SIH1451 (NTRO).
# 🛡️ Sentinel — Graded-Response Firewall for Non-IoC Compromise Detection

**Smart India Hackathon 2025 — Problem Statement SIH1451**
**Organization:** National Technical Research Organisation (NTRO)
**Category:** Software · **Domain:** Blockchain & Cybersecurity

---

## The Problem

Most security tools detect compromise using **IoCs (Indicators of Compromise)** — known malware hashes, known bad IPs, known signatures. This fails against **zero-day attacks**: novel techniques that have never been catalogued slip straight through.

**NTRO's ask:** detect compromise on a system, firewall, router, or network — **without relying on known IoCs at all.**

## Our Approach

Instead of a binary block/allow, every session gets a **0–100 suspicion score** from an ML model trained *only* on normal traffic (no attack labels used, ever). The response escalates gradually:

| Score | Tier | Action |
|---|---|---|
| < 25 | **MONITOR** | Silent logging only |
| 25–45 | **SUPERVISE** | Quietly routed toward honeytokens, deep logging begins |
| 45+ | **HIGH ALERT** | Sandbox restricted, strict inline DLP armed |

**The differentiator:** regardless of tier, the moment anyone touches a honeytoken (a decoy file/record with zero legitimate use) or tries to send out real sensitive data, we **block only that specific transfer** — not the whole connection. The attacker stays in, unaware, while a full evidence case is captured automatically.

## Results

Tested on CICIDS2017 (trained on Monday's benign traffic, tested against Friday's PortScan attack traffic):

- **89.2%** of attacks caught
- **20.3%** false positive rate (honestly reported, not cherry-picked)
- **0** attack labels used in training — fully non-IoC by construction

## Architecture

```
Traffic Ingress → Feature Extraction → Anomaly Scoring Engine
   → Tiered Decision Engine → Action & Evidence Layer
```

## Project Structure

```
sih1451-graded-firewall/
├── data/
│   ├── raw/                    # CICIDS2017 CSVs (not committed — see Setup)
│   └── honeytokens/             # Generated decoy files
├── models/                      # Trained model, scaler, feature list
├── src/
│   ├── train_baseline_model.py  # Trains Isolation Forest on benign traffic
│   ├── test_baseline_model.py   # Validates against attack traffic
│   ├── decision_engine.py       # Tiered scoring + explainability
│   ├── honeytoken_generator.py  # Generates decoy files/records
│   └── dlp_matcher.py           # Sensitive-data pattern matching + blocking
├── dashboard/
│   └── app.py                   # Live Streamlit dashboard
└── docs/
```

## Setup

```bash
python -m venv venv
venv\Scripts\activate          # Windows
pip install scikit-learn pandas numpy scapy streamlit fastapi uvicorn joblib matplotlib
```

Download **CICIDS2017** (MachineLearningCVE CSVs) from the official CIC source or Kaggle, and place the CSVs in `data/raw/MachineLearningCVE/`.

## Running It

```bash
python src/honeytoken_generator.py       # generate decoys (run once)
python src/train_baseline_model.py       # train the model
python src/test_baseline_model.py        # validate against attack data
python src/decision_engine.py            # see the tiered engine in action
streamlit run dashboard/app.py           # launch the live dashboard
```

## Why This Approach

- **(a) Innovation:** graded, deception-based response instead of binary block/allow — mirrors real enterprise honeypot + DLP practice, applied to a hackathon-scale system
- **(b) Cross-device utility:** the same scoring pipeline generalizes to any device type emitting flow-level telemetry — network, firewall, or router
- **(c) Ease of deployment:** software-only, no special hardware, runs on a single machine
- **(d) False-alarm minimization:** suspicion alone never triggers a block — only certain, deterministic proof (a honeytoken touch or a real sensitive-data match) does, so legitimate users are never punished for looking unusual

## Team

Team Sentinel — Smart India Hackathon 2025

---

*Built for SIH1451. Not a production security product — a hackathon prototype demonstrating a non-IoC, deception-based detection approach.*
