import sys
from datetime import datetime
from layers.global_intel_layer import vt_check, gsb_check
from layers.tls_layer import run_tls_scan
from layers.dns_layer import run_dns_scan
from layers.redirect_layer import run_redirect_scan



def scan_url(url):

    TOTAL_RISK = 0
    REPORT = []
    DETAILS = []

    # ─────────────────────────────────────────────
    # ① GLOBAL THREAT INTEL (FAST BLOCK)
    # ─────────────────────────────────────────────
    vt_mal, vt_sus = vt_check(url)

    if vt_mal >= 3:
        TOTAL_RISK += 60
        REPORT.append(f"Global Intel: VirusTotal flagged ({vt_mal} engines)")
        DETAILS.append(f"VirusTotal malicious engines = {vt_mal}")

    if gsb_check(url):
        TOTAL_RISK += 60
        REPORT.append("Global Intel: Google Safe Browsing listed threat")
        DETAILS.append("Google Safe Browsing: LISTED")

    if TOTAL_RISK < 60:

        # ─────────────────────────────────────────────
        # ② TLS
        # ─────────────────────────────────────────────
        tls_risk, tls_flags = run_tls_scan(url)
        if tls_risk > 0:
            TOTAL_RISK += tls_risk
            REPORT.append("TLS Layer: " + ", ".join(tls_flags))
            DETAILS.append("TLS → " + ", ".join(tls_flags))

        # ─────────────────────────────────────────────
        # ③ DNS
        # ─────────────────────────────────────────────
        dns_risk, dns_flags = run_dns_scan(url)
        if dns_risk > 0:
            TOTAL_RISK += dns_risk
            REPORT.append("DNS Layer: " + ", ".join(dns_flags))
            DETAILS.append("DNS → " + ", ".join(dns_flags))

        # ─────────────────────────────────────────────
        # ④ REDIRECT
        # ─────────────────────────────────────────────
        redir_risk, redir_flags = run_redirect_scan(url)
        if redir_risk > 0:
            TOTAL_RISK += redir_risk
            REPORT.append("Redirect Layer: " + ", ".join(redir_flags))
            DETAILS.append("Redirect → " + ", ".join(redir_flags))


    # ─────────────────────────────────────────────
    # FINAL VERDICT
    # ─────────────────────────────────────────────
    if TOTAL_RISK >= 100:
        verdict = "🚨 PHISHING / MALWARE"
    elif TOTAL_RISK >= 60:
        verdict = "⚠️ SUSPICIOUS"
    else:
        verdict = "✅ SAFE"


    # ─────────────────────────────────────────────
    # OUTPUT
    # ─────────────────────────────────────────────
    print("\nFINAL SECURITY REPORT")
    print("---------------------")
    print("Total Risk Score:", TOTAL_RISK)
    print("VERDICT:", verdict)
    print("\nDETECTION DETAILS:")
    for r in REPORT:
        print("•", r)

    # ─────────────────────────────────────────────
    # LOGGING
    # ─────────────────────────────────────────────
    stamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    with open("logs.txt", "a", encoding="utf-8") as f:
        f.write("\n" + "="*60 + "\n")
        f.write(f"[{stamp}]\n")
        f.write(f"URL: {url}\n")
        f.write(f"Verdict: {verdict}\n")
        f.write(f"Risk Score: {TOTAL_RISK}\n")
        f.write("Details:\n")
        for d in DETAILS:
            f.write(" - " + d + "\n")

    with open("last_result.txt", "w", encoding="utf-8") as f:
        f.write(f"{verdict}|{TOTAL_RISK}|{' | '.join(REPORT)}")

    return verdict, TOTAL_RISK, REPORT



# ─────────────────────────────────────────────
# MANUAL MODE ENTRY POINT
# ─────────────────────────────────────────────
if __name__ == "__main__":
    # This block ONLY runs if you type "python main.py" in terminal.
    # It will NOT run when the GUI imports the scan_url function.
    print("\n🛡️  QUISH-GUARD AI ZERO-CLICK DEFENSE  🛡️")
    print("-----------------------------------------")
    u = input("Paste QR URL: ").strip()
    if u:
        scan_url(u)
