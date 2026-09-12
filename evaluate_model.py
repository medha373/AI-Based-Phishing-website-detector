from pathlib import Path
import pandas as pd
import joblib
import matplotlib.pyplot as plt
from sklearn.model_selection import train_test_split
from sklearn.metrics import confusion_matrix, ConfusionMatrixDisplay, classification_report
from src.feature_extraction import extract_features, FEATURE_NAMES

ROOT = Path(__file__).resolve().parents[1]
df = pd.read_csv(ROOT / "dataset" / "phishing_dataset.csv")
X = pd.DataFrame([extract_features(url) for url in df["url"]])[FEATURE_NAMES]
y = df["label"].astype(int)

_, X_test, _, y_test = train_test_split(
    X, y, test_size=0.25, random_state=42, stratify=y
)

bundle = joblib.load(ROOT / "model" / "phishing_model.pkl")
model = bundle["model"]
pred = model.predict(X_test)

print(classification_report(y_test, pred, target_names=["Legitimate", "Phishing"]))

cm = confusion_matrix(y_test, pred)
disp = ConfusionMatrixDisplay(cm, display_labels=["Legitimate", "Phishing"])
disp.plot()
plt.title("Phishing URL Detector - Confusion Matrix")
plt.tight_layout()
out = ROOT / "results" / "confusion_matrix.png"
plt.savefig(out)
plt.close()
print("Saved:", out)
