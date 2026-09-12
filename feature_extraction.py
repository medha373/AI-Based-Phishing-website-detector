import re
from urllib.parse import urlparse

SUSPICIOUS_WORDS = {
    "login", "verify", "verification", "secure", "account",
    "update", "confirm", "password", "signin", "bank",
    "wallet", "unlock", "bonus", "free", "security"
}

def extract_features(url: str) -> dict:
    original = url.strip()
    normalized = original if re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", original) else "http://" + original
    parsed = urlparse(normalized)
    host = parsed.netloc.lower().split("@")[-1].split(":")[0]
    path = parsed.path or ""
    query = parsed.query or ""
    full = normalized.lower()

    host_parts = [p for p in host.split(".") if p]
    suspicious_count = sum(1 for word in SUSPICIOUS_WORDS if word in full)
    has_ip = int(bool(re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", host)))

    return {
        "url_length": len(original),
        "hostname_length": len(host),
        "path_length": len(path),
        "num_dots": original.count("."),
        "num_hyphens": original.count("-"),
        "num_slashes": original.count("/"),
        "num_at": original.count("@"),
        "num_digits": sum(c.isdigit() for c in original),
        "has_ip": has_ip,
        "uses_https": int(parsed.scheme.lower() == "https"),
        "num_subdomains": max(0, len(host_parts) - 2),
        "num_query_params": 0 if not query else query.count("&") + 1,
        "has_suspicious_word": int(suspicious_count > 0),
        "suspicious_word_count": suspicious_count,
        "has_port": int(parsed.port is not None) if parsed.hostname else 0,
        "has_double_slash_path": int("//" in path),
    }

FEATURE_NAMES = [
    "url_length", "hostname_length", "path_length", "num_dots",
    "num_hyphens", "num_slashes", "num_at", "num_digits", "has_ip",
    "uses_https", "num_subdomains", "num_query_params",
    "has_suspicious_word", "suspicious_word_count", "has_port",
    "has_double_slash_path"
]
