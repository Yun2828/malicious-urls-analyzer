from urllib.parse import urlparse, parse_qs
import math
import re
import ipaddress
import tldextract

SUSPICIOUS_KEYWORDS = [
    "login", "verify", "update", "secure", "account", "password", "free",
    "download", "gift", "winner", "confirm", "token", "session", "bank"
]

BRAND_WORDS = ["microsoft", "apple", "google", "paypal", "amazon", "facebook", "office"]

RISKY_TLDS = [".xyz", ".top", ".click", ".ru", ".biz", ".info"]


def shannon_entropy(text: str) -> float:
    """Measure randomness. Higher entropy can suggest generated-looking domains."""
    if not text:
        return 0.0
    freq = {char: text.count(char) for char in set(text)}
    return -sum((count / len(text)) * math.log2(count / len(text)) for count in freq.values())

def has_ip_address(hostname: str) -> int:
    if not hostname:
        return 0

    try:
        ipaddress.ip_address(hostname)
        return 1
    except ValueError:
        return 0

from urllib.parse import urlparse, parse_qs


def parse_url(url: str) -> dict:
    parsed = urlparse(url)
    hostname = parsed.hostname or ""
    path = parsed.path or ""
    query = parsed.query or ""
    query_params = parse_qs(query)

    parts = tldextract.extract(url)
    subdomain = parts.subdomain
    domain = parts.domain
    suffix = parts.suffix

    domain_name = ""
    if domain and suffix:
        domain_name = f"{domain}.{suffix}"
    elif domain:
        domain_name = domain

    components = {
        "protocol": parsed.scheme,
        "subdomain": subdomain,
        "hostname": hostname,
        "domain_name": domain_name,
        "path": path,
        "query": query,
        "query_params": query_params,
        "fragment": parsed.fragment or "",
    }

    return {key: value for key, value in components.items() if value}


def extract_features(url: str) -> dict:
    parts = parse_url(url)

    protocol = parts.get("protocol", "")
    hostname = parts.get("hostname", "")
    path = parts.get("path", "")
    query = parts.get("query", "")
    query_params = parts.get("query_params", {})
    fragment = parts.get("fragment", "")

    full_lower = url.lower()
    host_lower = hostname.lower()
    path_lower = path.lower()

    return {
        "url_length": len(url),
        "domain_length": len(hostname),
        "path_length": len(path),
        "query_length": len(query),
        "num_dots": url.count("."),
        "num_hyphens": url.count("-"),
        "num_slashes": url.count("/"),
        "num_digits": sum(char.isdigit() for char in url),
        "uses_https": int(protocol == "https"),
        "uses_http": int(protocol == "http"),
        "uses_ftp_smtp_ldap": int(protocol in ["ftp", "smtp", "ldap"]),
        "has_ip_address": has_ip_address(hostname),
        "has_query": int(bool(query)),
        "num_query_params": len(query_params),
        "has_percent_encoding": int("%" in url),
        "has_fragment": int(bool(fragment)),
        "suspicious_keyword_count": sum(
            word in full_lower for word in SUSPICIOUS_KEYWORDS
        ),
        "brand_keyword_count": sum(word in full_lower for word in BRAND_WORDS),
        "risky_tld": int(any(host_lower.endswith(tld) for tld in RISKY_TLDS)),
        "domain_entropy": shannon_entropy(host_lower),
        "deep_path": int(path.count("/") >= 3),
        "executable_in_path": int(
            any(
                path_lower.endswith(ext)
                for ext in [".exe", ".zip", ".scr", ".dll", ".js"]
            )
        ),
    }


"""
scheme    = protocol, like https, http, ftp, smtp, ldap
netloc    = network location, usually hostname plus optional port
hostname  = domain name or IP address without the port
port      = port number, like 443, 80, 8080
path      = page or file path after the domain
params    = path parameters after ;
query     = query string after ?
fragment  = page section after #

scheme: https
netloc: login.example.com:443
hostname: login.example.com
port: 443
path: /account/reset
params: type=user
query: user=abc&token=123%20xyz
fragment: section1

subdomain = "login"
domain_name = "example.com"

%20 = space
%2F = /
%3F = ?
%3D = =
%26 = &
%23 = #

? starts the query string
& separates query parameters
# starts a fragment
/ separates paths

https%3A%2F%2Fgoogle.com = https://google.com
"""
