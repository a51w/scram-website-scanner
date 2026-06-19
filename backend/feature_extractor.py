import re
import math
from collections import Counter
from urllib.parse import urlparse


# ── Known legitimate domains (whitelist) ──────────────────────────────────────
TRUSTED_DOMAINS = {
    "google.com", "youtube.com", "facebook.com", "instagram.com",
    "twitter.com", "x.com", "tiktok.com", "wikipedia.org",
    "amazon.com", "apple.com", "microsoft.com", "github.com",
    "netflix.com", "linkedin.com", "reddit.com", "yahoo.com",
    "paypal.com", "ebay.com", "twitch.tv", "discord.com",
    "spotify.com", "dropbox.com", "adobe.com", "salesforce.com",
    "zoom.us", "slack.com", "notion.so", "canva.com",
    "shopify.com", "wordpress.com", "medium.com", "stackoverflow.com",
}

SUSPICIOUS_TLDS = {
    ".xyz", ".top", ".club", ".online", ".site",
    ".tk",  ".ml",  ".ga",  ".cf",  ".gq",
    ".win", ".loan", ".work", ".click", ".download",
    ".zip", ".review", ".country", ".stream", ".gdn",
    ".racing", ".party", ".trade", ".bid", ".webcam",
}

SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly",
    "is.gd", "buff.ly", "short.link", "rebrand.ly", "tiny.cc",
    "bl.ink", "cutt.ly", "shorturl.at",
}

BRANDS = [
    "paypal", "google", "facebook", "apple", "amazon",
    "microsoft", "netflix", "instagram", "twitter", "tiktok",
    "ebay", "bank", "chase", "wellsfargo", "citibank",
    "dhl", "fedex", "ups", "usps", "steam",
]

# คำที่อันตรายเสมอ
SUSPICIOUS_WORDS = [
    "verify", "suspend", "urgent", "winner", "lucky",
    "limited-offer", "free-bonus", "recover", "wallet",
    "confirm-account", "update-billing", "secure-login",
    "signin-verify", "account-suspend",
]

# คำที่น่าสงสัยแต่ต้องดูบริบท
CONTEXT_WORDS = [
    "login", "signin", "secure", "account", "update",
    "bank", "billing", "password", "confirm", "support",
]


def _get_root_domain(hostname):
    parts = hostname.split(".")
    if len(parts) >= 2:
        return ".".join(parts[-2:])
    return hostname


def _entropy(s):
    if not s:
        return 0.0
    freq = Counter(s)
    length = len(s)
    return -sum((c / length) * math.log2(c / length) for c in freq.values())


def extract_features(url):
    features = {}

    parsed   = urlparse(url)
    domain   = parsed.netloc.lower()
    path     = parsed.path.lower()
    query    = parsed.query.lower()
    url_low  = url.lower()
    hostname = (parsed.hostname or "").lower()
    root     = _get_root_domain(hostname)

    # Trusted domain check
    features["is_trusted"] = root in TRUSTED_DOMAINS

    # GROUP 1: URL Structure
    features["has_ip"]          = bool(re.match(r"^\d{1,3}(\.\d{1,3}){3}$", hostname))
    features["has_at"]          = "@" in url
    features["url_length"]      = len(url)
    features["long_url"]        = len(url) > 75
    features["many_dots"]       = domain.count(".") > 3
    features["subdomain_depth"] = max(0, len(hostname.split(".")) - 2)
    features["deep_subdomain"]  = features["subdomain_depth"] >= 3
    features["hyphen_count"]    = hostname.count("-")
    features["has_many_hyphens"]  = hostname.count("-") > 2
    features["has_double_slash"]  = "//" in path
    features["has_port"]          = parsed.port is not None
    features["query_param_count"] = len([p for p in query.split("&") if p]) if query else 0

    # GROUP 2: Security
    features["use_https"]   = parsed.scheme == "https"
    features["is_shortened"] = any(s in hostname for s in SHORTENERS)

    # GROUP 3: Domain Analysis
    features["suspicious_tld"]  = any(hostname.endswith(tld) for tld in SUSPICIOUS_TLDS)
    features["digit_in_domain"] = bool(re.search(r"\d", hostname))
    features["hostname_length"] = len(hostname)
    features["long_hostname"]   = len(hostname) > 30

    # Brand impersonation — ถ้า root domain ตรงกับแบรนด์ใน trusted = ของจริง
    brand_in_hostname = any(b in hostname for b in BRANDS)
    brand_is_legit    = any(b in root for b in BRANDS) and root in TRUSTED_DOMAINS
    features["brand_in_domain"] = brand_in_hostname and not brand_is_legit

    # GROUP 4: Statistical
    ent = _entropy(hostname)
    features["hostname_entropy"] = round(ent, 4)
    features["high_entropy"]     = ent > 3.8

    digit_ratio = sum(c.isdigit() for c in url) / max(len(url), 1)
    features["digit_ratio"]      = round(digit_ratio, 4)
    features["high_digit_ratio"] = digit_ratio > 0.15

    special_chars = sum(url.count(c) for c in ["%", "=", "&", "?", "#", "@"])
    features["special_char_count"] = special_chars
    features["high_special_chars"] = special_chars > 4

    # GROUP 5: Suspicious Keywords (context-aware)
    has_hard_suspicious = any(w in url_low for w in SUSPICIOUS_WORDS)
    has_context_word    = any(w in url_low for w in CONTEXT_WORDS)

    features["suspicious_word"] = (
        has_hard_suspicious or
        (has_context_word and not features["use_https"]) or
        (has_context_word and features["suspicious_tld"]) or
        (has_context_word and features["brand_in_domain"])
    )

    # Rule-based Risk Score (weighted)
    weighted_flags = [
        (features["has_ip"],                                               1.0),
        (features["has_at"],                                               0.9),
        (features["suspicious_tld"],                                       0.8),
        (features["brand_in_domain"] and not features["use_https"],        0.9),
        (features["brand_in_domain"],                                      0.6),
        (features["is_shortened"],                                         0.5),
        (features["deep_subdomain"],                                       0.5),
        (features["high_entropy"] and not features["is_trusted"],         0.5),
        (features["has_many_hyphens"],                                     0.5),
        (features["suspicious_word"],                                      0.6),
        (not features["use_https"] and has_context_word,                   0.7),
        (not features["use_https"] and features["long_url"],               0.4),
        (features["high_digit_ratio"],                                     0.3),
        (features["high_special_chars"],                                   0.3),
        (features["long_hostname"],                                        0.3),
        (features["digit_in_domain"] and features["brand_in_domain"],     0.5),
    ]

    raw_score    = sum(w for flag, w in weighted_flags if flag)
    max_possible = sum(w for _, w in weighted_flags)
    normalized   = raw_score / max_possible if max_possible > 0 else 0

    # Trusted domain → ลด risk เหลือ 25%
    if features["is_trusted"]:
        normalized *= 0.25

    features["rule_risk_score"] = round(min(normalized, 1.0), 4)

    # Feature vector for ML model
    feature_vector = [
        int(features["has_ip"]),
        int(features["has_at"]),
        int(features["long_url"]),
        int(features["many_dots"]),
        int(features["suspicious_word"]),
        int(features["use_https"]),
        features["url_length"],
        features["hostname_length"],
        features["hyphen_count"],
        int(features["has_many_hyphens"]),
        int(features["has_double_slash"]),
        int(features["has_port"]),
        features["query_param_count"],
        int(features["suspicious_tld"]),
        int(features["is_shortened"]),
        features["subdomain_depth"],
        int(features["deep_subdomain"]),
        int(features["digit_in_domain"]),
        int(features["brand_in_domain"]),
        features["hostname_entropy"],
        int(features["high_entropy"]),
        features["digit_ratio"],
        int(features["high_digit_ratio"]),
        features["special_char_count"],
        int(features["high_special_chars"]),
    ]

    return features, feature_vector


FEATURE_NAMES = [
    "has_ip", "has_at", "long_url", "many_dots", "suspicious_word",
    "use_https", "url_length", "hostname_length", "hyphen_count",
    "has_many_hyphens", "has_double_slash", "has_port",
    "query_param_count", "suspicious_tld", "is_shortened",
    "subdomain_depth", "deep_subdomain", "digit_in_domain",
    "brand_in_domain", "hostname_entropy", "high_entropy",
    "digit_ratio", "high_digit_ratio", "special_char_count",
    "high_special_chars",
]


if __name__ == "__main__":
    test_urls = [
        ("https://www.google.com",                                      "SAFE"),
        ("https://mail.google.com/mail/u/0/#inbox",                     "SAFE"),
        ("https://github.com/user/repo",                                "SAFE"),
        ("http://paypal-secure-login.xyz/confirm?user=test@gmail.com",  "DANGEROUS"),
        ("http://192.168.1.1/secure/login?verify=account",              "DANGEROUS"),
        ("https://bit.ly/3xFreeBonus",                                  "SUSPICIOUS"),
        ("http://google-account-verify.tk/signin",                      "DANGEROUS"),
        ("http://apple-id-suspend.online/update-billing",               "DANGEROUS"),
        ("https://zapz88.me/?prefix=zapz88&action=register&refer_code=SRTd2qn9Co", "DANGEROUS"),
    ]

    print(f"\n{'URL':<55} {'Expected':<12} {'Risk':>6}")
    print("─" * 80)
    for url, expected in test_urls:
        feat, _ = extract_features(url)
        risk  = feat["rule_risk_score"]
        label = "DANGEROUS" if risk > 0.5 else "SUSPICIOUS" if risk > 0.25 else "SAFE"
        match = "✅" if label == expected or (label == "DANGEROUS" and expected == "SUSPICIOUS") else "❌"
        print(f"{match} {url[:53]:<53} {expected:<12} {risk:>6.3f}")