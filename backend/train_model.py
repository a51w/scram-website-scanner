import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, accuracy_score
import joblib
import os

# ── โหลด Dataset ──────────────────────────────────────────────────────────────
CSV_PATH = r"C:\Users\lamoooose\Documents\lamooose\stuff\study\cpe 3\sem 2\cyber security\shake checkkk\dataset\phishing_dataset.csv"

print(f"Loading: {CSV_PATH}")
data = pd.read_csv(CSV_PATH)
print(f"Rows: {len(data)}  |  Columns: {data.columns.tolist()}")

# ── Features ที่ dataset มี (ตรงกับ feature_extractor.py) ─────────────────────
# dataset columns: url_length, num_dots, num_hyphens, has_at, has_https, has_ip, label
FEATURE_COLS = [
    "url_length",
    "num_dots",
    "num_hyphens",
    "has_at",
    "has_https",
    "has_ip",
]

# ตรวจสอบว่า columns ครบ
missing = [c for c in FEATURE_COLS + ["label"] if c not in data.columns]
if missing:
    raise ValueError(f"ไม่พบ columns: {missing}\nมีแค่: {data.columns.tolist()}")

X = data[FEATURE_COLS]
y = data["label"]

print(f"\nLabel distribution:\n{y.value_counts().to_string()}")
print(f"  0 = Safe, 1 = Phishing")

# ── Train / Test split ────────────────────────────────────────────────────────
# ถ้า dataset เล็ก (<50 rows) ไม่ split — train ทั้งหมด
if len(data) >= 50:
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )
    do_eval = True
else:
    print(f"\n⚠️  Dataset เล็กมาก ({len(data)} rows) — train ทั้งหมดโดยไม่แบ่ง test")
    X_train, y_train = X, y
    do_eval = False

# ── Train Model ───────────────────────────────────────────────────────────────
print("\nTraining Random Forest...")
model = RandomForestClassifier(
    n_estimators=100,
    max_depth=10,
    class_weight="balanced",   # รับมือ imbalanced data
    random_state=42,
)
model.fit(X_train, y_train)
print("Training done ✓")

# ── Evaluate ──────────────────────────────────────────────────────────────────
if do_eval:
    y_pred = model.predict(X_test)
    acc = accuracy_score(y_test, y_pred)
    print(f"\nAccuracy: {acc*100:.1f}%")
    print(classification_report(y_test, y_pred, target_names=["Safe","Phishing"]))

# ── บันทึก model พร้อม feature names ─────────────────────────────────────────
# สำคัญมาก: ต้องเซฟ feature_names ไปด้วย
# เพื่อให้ app.py รู้ว่าต้องส่ง features ลำดับไหนเข้า model
joblib.dump({
    "model": model,
    "feature_names": FEATURE_COLS,
}, "model.pkl")

print(f"\n✅ Saved model.pkl")
print(f"   Features ({len(FEATURE_COLS)}): {FEATURE_COLS}")