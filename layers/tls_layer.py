import ssl, socket, idna, datetime
from urllib.parse import urlparse
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend


# -------------------- Domain Extract --------------------
def extract_domain(url):
    if not url.startswith("http"):
        url = "https://" + url
    return urlparse(url).netloc.replace("www.", "")


# -------------------- TLS Fetch --------------------
def fetch_tls_cert(domain):
    try:
        domain = idna.encode(domain).decode()
        ctx = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=7) as sock:
            with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                der = ssock.getpeercert(binary_form=True)
        return x509.load_der_x509_certificate(der, default_backend())
    except:
        return None


# -------------------- Modern Cloud-Edge Detection --------------------
def is_modern_protected_edge(domain):
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((domain,443),timeout=5) as sock:
            with ctx.wrap_socket(sock,server_hostname=domain) as s:
                cipher = s.cipher()[0].lower()

        edge_fp = ["cloudflare","akamai","fastly","imperva",
                   "google","azure","amazon","frontdoor","cloudfront"]
        return any(e in cipher for e in edge_fp)
    except:
        return False


# -------------------- TLS Forensic Engine --------------------
def run_tls_scan(url):
    domain = extract_domain(url)
    risk = 0
    flags = []

    cert = fetch_tls_cert(domain)
    if not cert:
        if is_modern_protected_edge(domain):
            return 0, ["Modern cloud-edge protected TLS"]
        return 80, ["TLS certificate missing"]

    now = datetime.datetime.now(datetime.UTC)
    start = cert.not_valid_before_utc
    end   = cert.not_valid_after_utc
    validity_days = (end - start).days

    # Fresh burner cert
    if (now - start).days < 14:
        risk += 50
        flags.append("Fresh certificate (<14 days)")

    # Short validity infra
    if validity_days < 90:
        risk += 30
        flags.append("Short validity certificate")

    # CA Trust Physics
    issuer = cert.issuer.rfc4514_string()
    trusted_ca = ["Google Trust Services","DigiCert","GlobalSign","Entrust"]
    free_ca = ["Let's Encrypt","ZeroSSL"]

    if any(ca in issuer for ca in trusted_ca):
        risk -= 20
    elif any(ca in issuer for ca in free_ca):
        risk += 15
        flags.append("Free certificate authority")

    # SAN cluster phishing
    try:
        sans = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
        if len(sans) > 8:
            risk += 40
            flags.append("Mass SAN phishing cluster")
    except:
        pass

    # Weak crypto
    pubkey = cert.public_key()
    if isinstance(pubkey, rsa.RSAPublicKey) and pubkey.key_size < 2048:
        risk += 40
        flags.append("Weak RSA key (<2048 bits)")

    return max(risk,0), flags
