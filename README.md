# SHAKE CHECK — Web Safety Scanner

A Chrome extension + Flask backend that detects phishing and malicious websites in real time using a hybrid **Machine Learning + rule-based heuristic engine**.

---

## Features

- **Automatic scanning** — every page you visit is checked in the background, no manual action needed.
- **Hybrid detection engine**
  - Random Forest ML model trained on URL-based features (length, dots, hyphens, HTTPS, IP usage, etc.)
  - Rule-based heuristics for IP-based URLs, `@` symbol tricks, suspicious TLDs (`.xyz`, `.tk`, `.ml`, …), brand impersonation, URL shorteners, deep subdomains, high-entropy domains, and piracy/copyright-infringing sites.
  - Domain age lookup (WHOIS) — newly registered domains are flagged as higher risk.
- **Risk scoring** — combines ML confidence and rule score into a single 0–100 risk score, mapped to **SAFE / SUSPICIOUS / DANGEROUS**.
- **In-page overlay** (`content.js`) — a floating panel shows the verdict, safety score, and triggered flags directly on the page.
- **Popup dashboard** (`popup.html` / `popup.js`) — manual scan button, score breakdown, ML confidence, rule score, domain age, and scan history.
- **Browser badge & notifications** — colored badge (OK / !! / !!!) on the extension icon, with a desktop notification for dangerous sites.
- **Local scan history** — stored via `chrome.storage.local`, viewable and clearable from the popup.

---

## Architecture

```
┌─────────────────┐        ┌──────────────────┐
│ Chrome Extension │  HTTP  │   Flask Backend   │
│  (Manifest V3)   │ ─────► │  app.py / server.py│
│                   │ POST   │                    │
│ background.js     │ /check │  feature_extractor │
│ content.js        │◄────── │  + ML model.pkl    │
│ popup.html/js     │  JSON  │  + WHOIS lookup     │
└─────────────────┘        └──────────────────┘
```

1. **background.js** intercepts every navigated tab and sends the URL to the Flask `/check` endpoint.
2. **feature_extractor.py** parses the URL into ~25 structural, security, and statistical features (HTTPS usage, IP detection, entropy, brand impersonation, suspicious keywords, etc.).
3. A **Random Forest classifier** (`train_model.py` → `model.pkl`) scores the feature vector.
4. A parallel **rule engine** assigns weighted penalty scores for known phishing patterns.
5. **Domain age** is fetched via a WHOIS API to flag newly registered domains.
6. The combined risk score and explanation flags are returned and rendered in the **popup** and the **in-page overlay**.

---

## Project Structure

| File | Purpose |
|---|---|
| `manifest.json` | Chrome Extension (MV3) configuration |
| `background.js` | Service worker — auto-scans tabs, sets badge, manages history |
| `content.js` | Injects the floating result panel into every page |
| `popup.html` / `popup.js` | Extension popup UI — scan button, results, history tab |
| `app.py` / `server.py` | Flask backend exposing `/check`, `/predict`, `/health` |
| `feature_extractor.py` | URL feature engineering (used by both backend and training) |
| `train_model.py` | Trains the Random Forest model and saves `model.pkl` |

---

## Getting Started

### 1. Backend (Python)

```bash
pip install flask flask-cors pandas scikit-learn joblib
python train_model.py   # generates model.pkl from your dataset
python app.py            # starts the API on http://localhost:5000
```

### 2. Chrome Extension

1. Open `chrome://extensions`
2. Enable **Developer mode**
3. Click **Load unpacked** and select the extension folder
4. Make sure the Flask server is running on `http://127.0.0.1:5000`

---

## API

**POST** `/check`
```json
{ "url": "https://example.com" }
```

**Response**
```json
{
  "result": "SAFE",
  "risk": 12,
  "safety_score": 88,
  "flags": [{ "icon": "🔒", "text": "HTTPS encrypted", "bad": false }],
  "ml_prediction": 0,
  "ml_confidence": 0.04,
  "rule_score": 5,
  "domain_age_days": 3650
}
```

---

## Disclaimer

This project is a personal/educational cybersecurity tool. It is **not** a substitute for enterprise-grade threat intelligence and may produce false positives/negatives. Use it as one signal among several when evaluating site safety.

---
