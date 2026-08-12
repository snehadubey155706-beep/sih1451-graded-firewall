import pandas as pd
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
import joblib
import os

DATA_PATH = "data/raw/MachineLearningCVE/Monday-WorkingHours.pcap_ISCX.csv"
df = pd.read_csv(DATA_PATH)
df.columns = df.columns.str.strip()

FEATURES = [
    "Destination Port",
    "Flow Duration", "Total Fwd Packets", "Total Backward Packets",
    "Total Length of Fwd Packets", "Total Length of Bwd Packets",
    "Flow Bytes/s", "Flow Packets/s",
    "Fwd Packet Length Mean", "Bwd Packet Length Mean",
    "SYN Flag Count", "ACK Flag Count", "FIN Flag Count", "RST Flag Count",
]
df = df[FEATURES + ["Label"]].copy()
df = df.replace([np.inf, -np.inf], np.nan).dropna()

LOG_COLS = ["Flow Duration", "Flow Bytes/s", "Flow Packets/s",
            "Total Length of Fwd Packets", "Total Length of Bwd Packets"]

for col in LOG_COLS:
    df[col] = np.log1p(df[col].clip(lower=0))

df = df.replace([np.inf, -np.inf], np.nan).dropna()

X_normal = df[df["Label"] == "BENIGN"][FEATURES]

scaler = StandardScaler()
X_scaled = scaler.fit_transform(X_normal)

model = IsolationForest(n_estimators=150, contamination=0.02, random_state=42)
model.fit(X_scaled)

os.makedirs("models", exist_ok=True)
joblib.dump(model, "models/baseline_isolation_forest.pkl")
joblib.dump(scaler, "models/scaler.pkl")
joblib.dump(FEATURES, "models/feature_list.pkl")
print("Model and scaler trained and saved")