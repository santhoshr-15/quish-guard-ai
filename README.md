# 🛡️ Quish-Guard AI

A Zero-Click QR Phishing Detection System built with Python.

## Features
- **Zero-Click Scanning:** Detects QR codes on screen automatically.
- **4-Layer Defense:** Checks TLS, DNS, Redirects, and Global Threat Intel.
- **Real-Time Analysis:** Multi-threaded engine.

## How to Run
1. Clone the repo.
2. Install dependencies: `pip install -r requirements.txt`
3. Add your VirusTotal API Key in `layers/global_intel_layer.py`.
4. Run: `python gui.py`