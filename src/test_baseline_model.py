import pandas as pd
import numpy as np
import joblib

model = joblib.load("models/baseline_isolation_forest.pkl")
scaler = joblib.load("models/scaler.pkl")
FEATURES = joblib.load("models/feature_list.pkl")

DATA_PATH = "data/raw/MachineLearningCVE/Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv"
df = pd.read_csv(DATA_PATH)
df.columns = df.columns.str.strip()
df = df[FEATURES + ["Label"]].copy()
df = df.replace([np.inf, -np.inf], np.nan).dropna()

LOG_COLS = ["Flow Duration", "Flow Bytes/s", "Flow Packets/s",
            "Total Length of Fwd Packets", "Total Length of Bwd Packets"]

for col in LOG_COLS:
    df[col] = np.log1p(df[col].clip(lower=0))

df = df.replace([np.inf, -np.inf], np.nan).dropna()

X_scaled = scaler.transform(df[FEATURES])
scores = model.decision_function(X_scaled)
df["sus_score"] = 100 * (scores.max() - scores) / (scores.max() - scores.min())

print("Average sus_score by label:")
print(df.groupby("Label")["sus_score"].mean())

print("\nScore percentiles by label:")
print(df.groupby("Label")["sus_score"].describe(percentiles=[.5, .75, .9, .95, .99]))

print("\n--- Trying different thresholds ---")
for threshold in [25, 30, 35, 40, 45, 50]:
    df["flagged"] = df["sus_score"] > threshold
    attack_rows = df[df["Label"] != "BENIGN"]
    benign_rows = df[df["Label"] == "BENIGN"]
    caught = attack_rows["flagged"].sum()
    total_attacks = len(attack_rows)
    fp = benign_rows["flagged"].sum()
    total_benign = len(benign_rows)
    print(f"threshold={threshold:>3} | caught {caught}/{total_attacks} ({caught/total_attacks*100:.1f}%) "
          f"| false positives {fp}/{total_benign} ({fp/total_benign*100:.1f}%)")