import dns.resolver, socket, re
from ipwhois import IPWhois
from datetime import datetime


def run_dns_scan(url):
    domain = url.replace("https://","").replace("http://","").replace("www.","").split("/")[0]

    risk = 0
    flags = []

    # Sensitive target detection
    SENSITIVE_HINTS = re.compile(r"(login|secure|bank|pay|verify|kyc|account|wallet|update|reset)", re.I)
    looks_sensitive = bool(SENSITIVE_HINTS.search(domain))

    # ---------------- A Records ----------------
    try:
        answers = dns.resolver.resolve(domain, "A")
        ips = [r.address for r in answers]
        ttl = answers.rrset.ttl
    except:
        ips = []
        ttl = 0
        risk += 60
        flags.append("No A record")

    # ---------------- MX Records ----------------
    mx_found = True
    try:
        dns.resolver.resolve(domain, "MX")
    except:
        mx_found = False

    if looks_sensitive and not mx_found:
        risk += 40
        flags.append("No MX on sensitive domain")

    # ---------------- ASN Physics ----------------
    for ip in ips:
        try:
            data = IPWhois(ip).lookup_rdap()
            net = data["network"]
            asn = data["asn"]
            org = net.get("name","")
            start = net.get("start_address")
            end = net.get("end_address")
            created = data.get("asn_date")

            # Single IP burner infra
            if start == end:
                risk += 40
                flags.append("Single-IP netblock")

            # New ASN burner infra
            if created:
                age = (datetime.now() - datetime.strptime(created, "%Y-%m-%d")).days
                if age < 180:
                    risk += 30
                    flags.append("New ASN (<6 months)")

            # Fast-flux rDNS physics
            try:
                rdns = socket.gethostbyaddr(ip)[0]
                looks_random = any(c.isdigit() for c in rdns[:6])
                if looks_random and start == end and ttl < 180:
                    risk += 20
                    flags.append("Fast-flux rDNS on small netblock")
            except:
                pass

        except:
            pass

    return risk, flags
