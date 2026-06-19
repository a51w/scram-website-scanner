"""
server.py — Flask API for Phishing Detection
Endpoint: POST /predict  { "url": "https://example.com" }
"""

from flask import Flask, request, jsonify
from flask_cors import CORS
import joblib
import os
import time
from feature_extractor import extract_features

app = Flask(__name__)
CORS(app)  # Allow Chrome Extension to call this API

# ── Load Model ────────────────────────────────────────────────────────────────

MODEL_PATH = os.path.join(os.path.dirname(__file__), "model.pkl")

model_data = None
model = None
feature_names = []

try:
    model_data = joblib.load(MODEL_PATH)
    model = model_data["model"]
    feature_names = model_data.get("feature_names", [])
    accuracy = model_data.get("accuracy", 0)
    print(f"✅ Model loaded | Accuracy: {accuracy*100:.2f}%")
except FileNotFoundError:
    print("⚠️  model.pkl not found. Run train_model.py first.")
except Exception as e:
    print(f"❌ Error loading model: {e}")


# ── Helper ────────────────────────────────────────────────────────────────────

def rule_based_check(url, features_dict):
    """
    Fast rule-based checks as fallback or pre-filter.
    Returns (is_phishing: bool, reason: str, confidence: float)
    """
    url_lower = url.lower()

    if features_dict.get("has_ip"):
        return True, "ใช้ IP Address แทนชื่อโดเมน", 0.92

    if features_dict.get("is_shortened"):
        return True, "ใช้ URL Shortener ที่น่าสงสัย", 0.75

    if not features_dict.get("use_https"):
        if features_dict.get("suspicious_word_count", 0) >= 2:
            return True, "HTTP (ไม่เข้ารหัส) + คำน่าสงสัย", 0.80

    if features_dict.get("suspicious_tld"):
        return True, f"TLD น่าสงสัย (.xyz, .tk, .ml, ฯลฯ)", 0.85

    if features_dict.get("num_at", 0) > 0:
        return True, "มี @ ใน URL (ซ่อน hostname)", 0.95

    if features_dict.get("url_length", 0) > 200:
        return True, "URL ยาวผิดปกติ", 0.70

    return False, "", 0.0


# ── Routes ────────────────────────────────────────────────────────────────────

@app.route("/", methods=["GET"])
def home():
    return jsonify({
        "status": "running",
        "service": "SHAKE CHECK - Phishing Detection API",
        "model_loaded": model is not None,
        "endpoints": {
            "POST /predict": "Analyze a URL for phishing",
            "GET /health": "Health check"
        }
    })


@app.route("/health", methods=["GET"])
def health():
    return jsonify({
        "status": "ok",
        "model_loaded": model is not None,
        "timestamp": time.time()
    })


@app.route("/predict", methods=["POST"])
def predict():
    start_time = time.time()

    # ── Validate Input ──
    data = request.get_json(silent=True)
    if not data or "url" not in data:
        return jsonify({
            "error": "Missing 'url' field",
            "example": {"url": "https://example.com"}
        }), 400

    url = str(data["url"]).strip()
    if not url:
        return jsonify({"error": "URL cannot be empty"}), 400

    # Add scheme if missing
    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    # ── Extract Features ──
    try:
        features_dict, feature_vector = extract_features(url)
    except Exception as e:
        return jsonify({"error": f"Feature extraction failed: {str(e)}"}), 500

    # ── Rule-based Check ──
    rule_phishing, rule_reason, rule_conf = rule_based_check(url, features_dict)

    # ── ML Prediction ──
    ml_result = None
    ml_confidence = None
    final_label = None
    final_confidence = None
    reasons = []

    if model is not None:
        try:
            X = [feature_vector]
            prediction = model.predict(X)[0]
            probabilities = model.predict_proba(X)[0]
            ml_confidence = float(probabilities[1])  # prob of phishing
            ml_label = bool(prediction == 1)
            ml_result = ml_label

            # Combine ML + rules
            if rule_phishing and ml_label:
                final_label = True
                final_confidence = max(rule_conf, ml_confidence)
            elif rule_phishing and not ml_label:
                final_label = rule_conf > 0.85
                final_confidence = rule_conf
            elif not rule_phishing and ml_label:
                final_label = ml_confidence > 0.65
                final_confidence = ml_confidence
            else:
                final_label = False
                final_confidence = 1.0 - ml_confidence

            if rule_phishing and rule_reason:
                reasons.append(rule_reason)

        except Exception as e:
            print(f"ML prediction error: {e}")
            final_label = rule_phishing
            final_confidence = rule_conf if rule_phishing else 0.1
    else:
        # Fallback: rule-based only
        final_label = rule_phishing
        final_confidence = rule_conf if rule_phishing else 0.1

    # ── Build Response ──
    if final_label is None:
        final_label = False
    if final_confidence is None:
        final_confidence = 0.5

    safety_score = round((1.0 - final_confidence) * 100) if final_label else round(final_confidence * 100)

    # Risk level
    if final_label:
        if final_confidence >= 0.85:
            risk_level = "HIGH"
            risk_th = "ความเสี่ยงสูงมาก"
        elif final_confidence >= 0.60:
            risk_level = "MEDIUM"
            risk_th = "ความเสี่ยงปานกลาง"
        else:
            risk_level = "LOW"
            risk_th = "ความเสี่ยงต่ำ"
    else:
        risk_level = "SAFE"
        risk_th = "ปลอดภัย"

    # Notable features for UI display
    notable = []
    if not features_dict.get("use_https"):
        notable.append({"icon": "🔓", "text": "ไม่ใช้ HTTPS", "bad": True})
    else:
        notable.append({"icon": "🔒", "text": "ใช้ HTTPS", "bad": False})

    if features_dict.get("has_ip"):
        notable.append({"icon": "🖥️", "text": "IP Address แทนโดเมน", "bad": True})

    if features_dict.get("suspicious_tld"):
        notable.append({"icon": "⚠️", "text": "TLD น่าสงสัย", "bad": True})

    if features_dict.get("suspicious_word_count", 0) > 0:
        notable.append({"icon": "🚨", "text": f"คำน่าสงสัย {features_dict['suspicious_word_count']} คำ", "bad": True})

    if features_dict.get("is_shortened"):
        notable.append({"icon": "🔗", "text": "URL Shortener", "bad": True})

    if features_dict.get("subdomain_depth", 0) > 2:
        notable.append({"icon": "📂", "text": f"Subdomain ลึก ({features_dict['subdomain_depth']} ชั้น)", "bad": True})

    elapsed = round((time.time() - start_time) * 1000, 1)

    return jsonify({
        "url": url,
        "is_phishing": bool(final_label),
        "is_safe": not bool(final_label),
        "confidence": round(final_confidence, 4),
        "safety_score": safety_score,
        "risk_level": risk_level,
        "risk_level_th": risk_th,
        "reasons": reasons,
        "notable_features": notable,
        "features": features_dict,
        "ml_confidence": round(ml_confidence, 4) if ml_confidence is not None else None,
        "scan_time_ms": elapsed
    })


# ── /check route (same as /predict but returns extension-compatible format) ───

@app.route("/check", methods=["POST"])
def check():
    data = request.get_json(silent=True)
    if not data or "url" not in data:
        return jsonify({"error": "Missing url"}), 400

    url = str(data["url"]).strip()
    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    try:
        features_dict, feature_vector = extract_features(url)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

    risk = 10

    # Rule-based
    suspicious_words = [
        "login", "verify", "secure", "update", "bank", "account",
        "password", "signin", "confirm", "billing", "suspend",
        "recover", "wallet", "urgent", "winner", "free-bonus"
    ]
    piracy_words = [
        "123movies", "fmovies", "putlocker", "watchfree",
        "freemovie", "hdmovie", "torrent", "pirate"
    ]
    url_low = url.lower()
    for word in suspicious_words:
        if word in url_low:
            risk += 40
            break
    for word in piracy_words:
        if word in url_low:
            risk += 30
            break
    if url.startswith("http://"):
        risk += 15

    # ML
    if model is not None:
        try:
            alias = {"has_https": "use_https", "num_dots": "many_dots"}
            vector = []
            for name in feature_names:
                key = alias.get(name, name)
                val = features_dict.get(key, 0)
                vector.append(int(bool(val)) if isinstance(val, bool) else val)
            prediction = model.predict([vector])[0]
            if prediction == 1:
                risk += 30
        except Exception as e:
            print(f"ML error: {e}")

    # Additional rules
    if features_dict.get("has_ip"):         risk += 25
    if features_dict.get("has_at"):         risk += 20
    if features_dict.get("suspicious_tld"): risk += 20
    if features_dict.get("is_shortened"):   risk += 15
    if features_dict.get("brand_in_domain") and not features_dict.get("use_https"):
        risk += 20

    risk = min(risk, 100)

    if risk >= 70:
        result = "DANGEROUS"
    elif risk >= 40:
        result = "SUSPICIOUS"
    else:
        result = "SAFE"

    flags = []
    if features_dict.get("use_https"):
        flags.append({"icon": "🔒", "text": "HTTPS encrypted", "bad": False})
    else:
        flags.append({"icon": "🔓", "text": "No HTTPS encryption", "bad": True})
    if features_dict.get("has_ip"):
        flags.append({"icon": "🖥️", "text": "IP address used instead of domain", "bad": True})
    if features_dict.get("suspicious_tld"):
        flags.append({"icon": "⚠️", "text": "Suspicious TLD (.xyz .tk .ml etc.)", "bad": True})
    if features_dict.get("is_shortened"):
        flags.append({"icon": "🔗", "text": "URL shortener detected", "bad": True})
    if features_dict.get("brand_in_domain"):
        flags.append({"icon": "🎭", "text": "Brand impersonation detected", "bad": True})
    if features_dict.get("suspicious_word"):
        flags.append({"icon": "🚨", "text": "Suspicious keywords in URL", "bad": True})

    return jsonify({
        "result":        result,
        "risk":          risk,
        "safety_score":  100 - risk,
        "flags":         flags,
        "ml_prediction": int(prediction) if model is not None else None,
    })


# ── Run ───────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    print("=" * 50)
    print("  SHAKE CHECK — Phishing Detection Server")
    print("  http://localhost:5000")
    print("=" * 50)
    app.run(debug=True, host="0.0.0.0", port=5000)