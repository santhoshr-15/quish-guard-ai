import httpx, math, re
from bs4 import BeautifulSoup


def entropy(s):
    freq = {}
    for c in s:
        freq[c] = freq.get(c,0)+1
    H = 0
    for v in freq.values():
        p = v/len(s)
        H -= p * math.log2(p)
    return H


def run_redirect_scan(url):
    if not url.startswith("http"):
        url = "https://" + url

    risk = 0
    flags = []
    r = None
    chain = []

    with httpx.Client(follow_redirects=True, timeout=10) as client:
        try:
            r = client.get(url)
            chain = [str(h.url) for h in r.history] + [str(r.url)]
        except:
            risk += 40
            flags.append("Navigation failure")

    # Redirect depth
    if len(chain) >= 4:
        risk += 30
        flags.append("Deep redirect chain")

    # Header fingerprint
    if r:
        server = r.headers.get("server","").lower()
        powered = r.headers.get("x-powered-by","").lower()

        if any(x in server+powered for x in ["php","cgi","perl"]):
            risk += 25
            flags.append("Legacy phishing backend")

    # Content inspection
    if r:
        html = r.text[:5000]
        soup = BeautifulSoup(html, "html.parser")

        # Credential harvesting
        input_types = [i.get("type","") for i in soup.find_all("input")]
        if "password" in input_types:
            risk += 50
            flags.append("Credential harvesting form")

        # JS redirect abuse
        if re.search(r'window\.location|location\.href', html, re.I):
            risk += 20
            flags.append("JavaScript redirect")

        # Obfuscated loader
        H = entropy(html)
        if H > 4.8 and risk >= 40:
            risk += 20
            flags.append("Obfuscated phishing loader")

    return risk, flags
