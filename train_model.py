from pathlib import Path
import pandas as pd
import joblib
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, classification_report
from src.feature_extraction import extract_features, FEATURE_NAMES

ROOT = Path(__file__).resolve().parents[1]
DATASET = ROOT / "dataset" / "phishing_dataset.csv"
MODEL_DIR = ROOT / "model"
MODEL_DIR.mkdir(exist_ok=True)
MODEL_PATH = MODEL_DIR / "phishing_model.pkl"

df = pd.read_csv(DATASET)
X = pd.DataFrame([extract_features(url) for url in df["url"]])[FEATURE_NAMES]
y = df["label"].astype(int)

X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.25, random_state=42, stratify=y
)

model = RandomForestClassifier(
    n_estimators=200,
    random_state=42,
    class_weight="balanced"
)
model.fit(X_train, y_train)

pred = model.predict(X_test)
print("Accuracy:", round(accuracy_score(y_test, pred), 4))
print(classification_report(y_test, pred, target_names=["Legitimate", "Phishing"]))

joblib.dump({"model": model, "features": FEATURE_NAMES}, MODEL_PATH)
print(f"Saved model to: {MODEL_PATH}")
