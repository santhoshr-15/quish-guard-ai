import base64
import requests

VT_API_KEY  = ""
GSB_API_KEY = ""

# ---------------- VIRUSTOTAL ----------------
def vt_check(url):
    try:
        uid = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
        h = {"x-apikey": VT_API_KEY}
        r = requests.get(
            f"https://www.virustotal.com/api/v3/urls/{uid}",
            headers=h,
            timeout=8
        )
        if r.status_code == 200:
            stats = r.json()["data"]["attributes"]["last_analysis_stats"]
            return stats.get("malicious",0), stats.get("suspicious",0)
    except:
        pass
    return 0, 0


# ---------------- GOOGLE SAFE BROWSING ----------------
def gsb_check(url):
    try:
        endpoint = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={GSB_API_KEY}"
        payload = {
            "client":{"clientId":"quishguard","clientVersion":"1.0"},
            "threatInfo":{
                "threatTypes":["MALWARE","SOCIAL_ENGINEERING","UNWANTED_SOFTWARE"],
                "platformTypes":["ANY_PLATFORM"],
                "threatEntryTypes":["URL"],
                "threatEntries":[{"url":url}]
            }
        }
        r = requests.post(endpoint, json=payload, timeout=8)
        return bool(r.json())
    except:
        pass
    return False
