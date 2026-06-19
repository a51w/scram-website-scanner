from flask import Flask, request, jsonify
from flask_cors import CORS
import joblib
import json
import urllib.request
import pandas as pd
from datetime import datetime
from feature_extractor import extract_features
from urllib.parse import urlparse

app = Flask(__name__)
CORS(app)

_data         = joblib.load("model.pkl")
model         = _data["model"]
FEATURE_NAMES = _data["feature_names"]
print(f"Model loaded | Features: {FEATURE_NAMES}")


# ══════════════════════════════════════════════════════════════════════════════
# SECTION 1 : DOMAIN AGE
# ══════════════════════════════════════════════════════════════════════════════

def get_domain_age_days(hostname):
    try:
        parts = hostname.split(".")
        root  = ".".join(parts[-2:]) if len(parts) >= 2 else hostname
        url   = f"https://www.whoisxmlapi.com/whoisserver/WhoisService?apiKey=at_free&domainName={root}&outputFormat=JSON"
        req   = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
        with urllib.request.urlopen(req, timeout=4) as resp:
            data = json.loads(resp.read().decode())
        created_str = (
            data.get("WhoisRecord", {}).get("createdDate") or
            data.get("WhoisRecord", {}).get("registryData", {}).get("createdDate")
        )
        if not created_str:
            return None
        for fmt in ("%Y-%m-%dT%H:%M:%SZ", "%Y-%m-%dT%H:%M:%S+00:00", "%Y-%m-%d"):
            try:
                created = datetime.strptime(created_str[:19], fmt[:len(created_str[:19])])
                return max((datetime.utcnow() - created).days, 0)
            except Exception:
                continue
        return None
    except Exception:
        return None


# ══════════════════════════════════════════════════════════════════════════════
# SECTION 2 : RULE-BASED
# ══════════════════════════════════════════════════════════════════════════════

RULES = [
    {"id":"has_ip",         "check": lambda f,u: f.get("has_ip"),                                          "score":50, "icon":"🖥️", "text":"IP address used instead of domain"},
    {"id":"has_at",         "check": lambda f,u: f.get("has_at"),                                          "score":45, "icon":"⚠️", "text":"@ symbol in URL (hostname hidden)"},
    {"id":"suspicious_tld", "check": lambda f,u: f.get("suspicious_tld"),                                  "score":35, "icon":"🌐", "text":"Suspicious TLD (.xyz .tk .ml etc.)"},
    {"id":"brand_no_https", "check": lambda f,u: f.get("brand_in_domain") and not f.get("use_https"),      "score":40, "icon":"🎭", "text":"Brand impersonation + no HTTPS"},
    {"id":"brand_https",    "check": lambda f,u: f.get("brand_in_domain") and f.get("use_https"),          "score":25, "icon":"🎭", "text":"Brand impersonation detected (has HTTPS)"},
    {"id":"is_shortened",   "check": lambda f,u: f.get("is_shortened"),                                    "score":25, "icon":"🔗", "text":"URL shortener detected"},
    {"id":"no_https_sus",   "check": lambda f,u: not f.get("use_https") and f.get("suspicious_word"),      "score":30, "icon":"🔓", "text":"HTTP + suspicious keywords"},
    {"id":"no_https",       "check": lambda f,u: not f.get("use_https") and not f.get("suspicious_word"),  "score":15, "icon":"🔓", "text":"No HTTPS encryption"},
    {"id":"deep_subdomain", "check": lambda f,u: f.get("subdomain_depth", 0) >= 3,                         "score":20, "icon":"📂", "text":"Abnormally deep subdomain structure"},
    {"id":"high_entropy",   "check": lambda f,u: f.get("high_entropy") and not f.get("is_trusted"),        "score":20, "icon":"🔀", "text":"Random-looking domain characters"},
    {"id":"many_hyphens",   "check": lambda f,u: f.get("has_many_hyphens"),                                "score":20, "icon":"➖", "text":"Excessive hyphens in domain"},
    {"id":"piracy",         "check": lambda f,u: any(w in u.lower() for w in ["123movies","fmovies","putlocker","torrent","pirate","cracked"]), "score":30, "icon":"🏴‍☠️", "text":"Piracy / copyright infringement site"},
    {"id":"suspicious_word","check": lambda f,u: f.get("suspicious_word"),                                 "score":20, "icon":"🚨", "text":"Suspicious keywords in URL"},
    {"id":"long_url",       "check": lambda f,u: f.get("url_length", 0) > 100,                            "score":10, "icon":"📏", "text":"Unusually long URL"},
    {"id":"digit_brand",    "check": lambda f,u: f.get("digit_in_domain") and f.get("brand_in_domain"),   "score":15, "icon":"🔢", "text":"Digits in domain + brand impersonation"},
    {"id":"double_slash",   "check": lambda f,u: f.get("has_double_slash"),                                "score":15, "icon":"↩️", "text":"Double slash in path (redirect trick)"},
    {"id":"long_hostname",  "check": lambda f,u: f.get("long_hostname") and not f.get("is_trusted"),      "score":10, "icon":"🔤", "text":"Unusually long hostname"},
]

def rule_based_score(features_dict, url):
    score, triggered = 0, []
    for rule in RULES:
        try:
            if rule["check"](features_dict, url):
                score += rule["score"]
                triggered.append({"icon": rule["icon"], "text": rule["text"], "bad": True})
        except Exception:
            pass
    return score, triggered


# ══════════════════════════════════════════════════════════════════════════════
# SECTION 3 : FEATURE VECTOR
# ══════════════════════════════════════════════════════════════════════════════

def build_feature_vector(features_dict):
    alias = {"has_https": "use_https", "num_dots": "many_dots"}
    row = {}
    for name in FEATURE_NAMES:
        key = alias.get(name, name)
        val = features_dict.get(key, 0)
        row[name] = int(bool(val)) if isinstance(val, bool) else val
    return pd.DataFrame([row])[FEATURE_NAMES]


# ══════════════════════════════════════════════════════════════════════════════
# SECTION 4 : ROUTES
# ══════════════════════════════════════════════════════════════════════════════

@app.route("/check", methods=["POST"])
def check():
    data = request.get_json()
    if not data or "url" not in data:
        return jsonify({"error": "Missing url"}), 400

    url = data["url"].strip()
    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    # ── Feature extraction + ML ───────────────────────────────────────────────
    features_dict, _ = extract_features(url)
    feature_df       = build_feature_vector(features_dict)
    prediction       = model.predict(feature_df)[0]
    try:
        ml_proba = model.predict_proba(feature_df)[0][1]
    except Exception:
        ml_proba = float(prediction)

    # ── Rule-based ────────────────────────────────────────────────────────────
    rule_score, triggered_rules = rule_based_score(features_dict, url)

    # ── Domain age ────────────────────────────────────────────────────────────
    hostname = urlparse(url).hostname or ""
    age_days = get_domain_age_days(hostname)
    age_flag = None
    if age_days is not None:
        if age_days < 30:
            rule_score += 40
            age_flag = {"icon":"🆕", "text":f"Very new domain! ({age_days} days old)", "bad":True}
        elif age_days < 180:
            rule_score += 20
            age_flag = {"icon":"📅", "text":f"Young domain ({age_days} days old)", "bad":True}
        elif age_days < 365:
            rule_score += 10
            age_flag = {"icon":"📅", "text":f"Domain age: {age_days} days", "bad":False}
        else:
            age_flag = {"icon":"✅", "text":f"Established domain ({age_days//365} year(s) old)", "bad":False}
    else:
        rule_score += 5
        age_flag = {"icon":"❓", "text":"Domain age unknown", "bad":True}

    # ══════════════════════════════════════════════════════════════════════════
    # SCORING — แก้ใหม่ทั้งหมด
    # ══════════════════════════════════════════════════════════════════════════

    # Rule score ไม่ cap ที่ 100 แล้ว ใช้ค่าจริงหาร max ที่เป็นไปได้
    MAX_RULE = 350  # ผลรวมสูงสุดถ้า trigger ทุก rule
    rule_pct  = min(rule_score / MAX_RULE, 1.0)  # 0.0 – 1.0

    # ML เทรนน้อย → ใช้เป็น tie-breaker เท่านั้น ไม่ใช่ตัวหลัก
    # ถ้า model ไม่น่าเชื่อถือ ให้ rule-based ทำงานแทน
    if ml_proba >= 0.5:
        # model บอก phishing → บวกเพิ่ม
        ml_bonus = int(ml_proba * 20)
    else:
        ml_bonus = 0

    # คะแนนหลักมาจาก rule-based 100%
    risk = int(rule_pct * 100) + ml_bonus

    # Trusted domain → กดคะแนนลง
    if features_dict.get("is_trusted"):
        risk = int(risk * 0.3)

    risk = min(risk, 100)

    # ── Label ─────────────────────────────────────────────────────────────────
    if   risk >= 65: result = "DANGEROUS"
    elif risk >= 35: result = "SUSPICIOUS"
    else:            result = "SAFE"

    # ── Flags ─────────────────────────────────────────────────────────────────
    flags = []
    if features_dict.get("use_https"):
        flags.append({"icon":"🔒", "text":"HTTPS encrypted", "bad":False})
    if age_flag:
        flags.append(age_flag)
    for r in triggered_rules:
        if r["text"] not in [f["text"] for f in flags]:
            flags.append(r)

    return jsonify({
        "result":          result,
        "risk":            risk,
        "safety_score":    100 - risk,
        "flags":           flags[:7],
        "ml_prediction":   int(prediction),
        "ml_confidence":   round(float(ml_proba), 3),
        "rule_score":      rule_score,
        "domain_age_days": age_days,
    })


@app.route("/health", methods=["GET"])
def health():
    return jsonify({"status": "ok"})


if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=5000)