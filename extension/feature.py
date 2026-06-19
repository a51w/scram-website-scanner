import re
from urllib.parse import urlparse

def extract_features(url):

    features = []

    url_lower = url.lower()

    # URL length
    features.append(len(url))

    # number of dots
    features.append(url.count('.'))

    # number of hyphens
    features.append(url.count('-'))

    # contains @
    features.append(1 if '@' in url else 0)

    # contains https
    features.append(1 if url.startswith("https") else 0)

    # contains IP address
    ip_pattern = r'(\d{1,3}\.){3}\d{1,3}'
    features.append(1 if re.search(ip_pattern, url) else 0)

    # 🚨 ตรวจเว็บหนังเถื่อน
    pirate_keywords = [
        "123movie",
        "fmovies",
        "putlocker",
        "soap2day",
        "gomovies",
        "kissasian",
        "dramacool"
    ]

    pirate_flag = 0
    for word in pirate_keywords:
        if word in url_lower:
            pirate_flag = 1

    features.append(pirate_flag)

    return features