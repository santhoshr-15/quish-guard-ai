# 🛡️ Quish-Guard AI: Zero-Click QR Phishing Defense

![Python](https://img.shields.io/badge/Python-3.10%2B-blue?style=for-the-badge&logo=python)
![Security](https://img.shields.io/badge/Security-Heuristic%20Analysis-red?style=for-the-badge)
![Status](https://img.shields.io/badge/Status-Active-success?style=for-the-badge)
![License](https://img.shields.io/badge/License-MIT-green?style=for-the-badge)

Quish-Guard AI is a real-time, zero-click security tool designed to detect and block QR code phishing (Quishing) attempts. Unlike traditional scanners that only check the URL text, Quish-Guard employs a 4-Layer Defense-in-Depth Engine to analyze the infrastructure, encryption, and behavior behind the link before the user visits it.

---

## 🚀 Key Features

### 🖥️ Zero-Click "Look-to-Scan"
- Automatic detection using Computer Vision (OpenCV) to find QR codes visible anywhere on the screen.
- No screenshots needed: click one button and the app captures, decodes, and analyzes the QR instantly.
- Real-time protection: scans, analyzes, and notifies the user within seconds.

### 🧠 4-Layer Defense Engine
The core intelligence runs 4 distinct analysis layers in parallel:

1. Global Intel Layer
   - Checks URL against VirusTotal and Google Safe Browsing databases.
2. TLS Forensic Layer
   - Detects "fresh" SSL certificates (< 14 days old).
   - Identifies weak encryption and free CA abuse (e.g., Let's Encrypt on banking sites).
3. DNS Physics Layer
   - Analyzes domain age (detects "burner domains" < 6 months old).
   - Checks for missing MX records on sensitive domains (e.g., a "bank" with no email server).
4. Redirect & Behavior Layer
   - Unravels shortened links (`bit.ly`, etc.) to find the final destination.
   - Calculates HTML entropy to detect obfuscated phishing kits.

### 🔔 Smart Notifications
- Instant Windows desktop notifications (Safe / Suspicious / Malicious).
- Dark Mode GUI built with CustomTkinter for a modern security tool aesthetic.
- Auto-logging: saves detailed forensic reports to `logs.txt` for audit trails.

---

## 🛠️ Installation & Setup

### Prerequisites
- Python 3.10 or higher
- Windows 10/11 (required for desktop notifications)

### 1. Clone the repository
```bash
git clone https://github.com/YOUR_USERNAME/quish-guard-ai.git
cd quish-guard-ai
```

### 2. Install dependencies
```bash
pip install -r requirements.txt
```

### 3. Configure API Keys
To enable the Global Intel Layer, add your API keys to `layers/global_intel_layer.py`. Example:
```python
# layers/global_intel_layer.py
VT_API_KEY  = "YOUR_VIRUSTOTAL_KEY"
GSB_API_KEY = "YOUR_GOOGLE_SAFE_BROWSING_KEY"
```
Note: The app runs without keys but will skip global intelligence checks.

---

## 🖥️ Usage

### Running from source
```bash
python gui.py
```

### Running as an executable
If you build the .exe using PyInstaller, double-click `QuishGuard_AI.exe`.

How to use:
1. Open the suspicious QR code on your screen (e.g., in a browser or email).
2. Click "SCAN SCREEN FOR QR" in the Quish-Guard app.
3. Wait 2–3 seconds for the notification verdict.

---

## 📂 Project Structure
```
quish-guard-ai/
│
├── gui.py                   # Main Desktop Application (GUI)
├── main.py                  # Core Engine Logic & Threading
├── requirements.txt         # Dependency List
├── logs.txt                 # Audit Logs (Auto-generated)
│
└── layers/                  # The 4-Layer Security Engine
    ├── __init__.py
    ├── dns_layer.py         # Infrastructure analysis
    ├── tls_layer.py         # Certificate forensics
    ├── redirect_layer.py    # URL expansion & HTML analysis
    └── global_intel_layer.py# API integrations (VT/GSB)
```

---

## 🛡️ Detection Logic (Heuristics)

Risk Factor         | Weight | Explanation
------------------- | ------ | -----------
VirusTotal Flag     | High   | Confirmed malware by external engines.
Fresh Domain        | High   | Domain registered < 6 months ago.
Fresh SSL Cert      | High   | Certificate created < 14 days ago.
Deep Redirects      | Med    | URL redirects more than 3 times.
Suspicious HTML     | Med    | High entropy (obfuscated code) detected.

--- 

## 📸 Screenshots
![Quish-Guard AI Demo](<img width="1359" height="638" alt="image" src="https://github.com/user-attachments/assets/691e2cbf-af78-43d5-901a-49da29365f37" />)



⚠️ Disclaimer
This tool is intended for educational and defensive purposes only. It is designed to protect users from phishing attacks. The author is not responsible for any misuse of the information or code provided herein.

---

👨‍💻 Author
Santhosh Kumar R  
Cyber Security Student | Saveetha Engineering College  
