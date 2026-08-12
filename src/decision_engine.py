import pandas as pd
import numpy as np
import joblib

# ---- Load your trained pieces ----
model = joblib.load("models/baseline_isolation_forest.pkl")
scaler = joblib.load("models/scaler.pkl")
FEATURES = joblib.load("models/feature_list.pkl")

LOG_COLS = ["Flow Duration", "Flow Bytes/s", "Flow Packets/s",
            "Total Length of Fwd Packets", "Total Length of Bwd Packets"]

# ---- Tier thresholds, calibrated from your actual test results ----
# (BENIGN median ~22, PortScan median ~38 — these thresholds sit
#  between the two distributions based on your threshold sweep)
TIER_1_MONITOR = 25
TIER_2_SUPERVISE = 45


def preprocess(df):
    """Same cleaning + log-transform used in training/testing."""
    df = df[FEATURES].copy()
    for col in LOG_COLS:
        if col in df.columns:
            df[col] = np.log1p(df[col].clip(lower=0))
    df = df.replace([np.inf, -np.inf], np.nan).dropna()
    return df


def compute_sus_score(df, score_min, score_max):
    """Turn model output into a 0-100 suspicion score."""
    X_scaled = scaler.transform(df[FEATURES])
    raw_scores = model.decision_function(X_scaled)
    sus_score = 100 * (score_max - raw_scores) / (score_max - score_min)
    return sus_score, X_scaled, raw_scores


def assign_tier(score):
    if score < TIER_1_MONITOR:
        return "MONITOR"
    elif score < TIER_2_SUPERVISE:
        return "SUPERVISE"
    else:
        return "HIGH_ALERT"


def explain_flagged_session(x_scaled_row, feature_names):
    """
    Return the top 3 features that pushed this session's score up.
    After StandardScaler, 'normal' sits near 0 — so the features with
    the biggest absolute value are the ones that look most unusual.
    """
    deviations = np.abs(x_scaled_row)
    top_idx = np.argsort(deviations)[::-1][:3]
    reasons = [(feature_names[i], round(x_scaled_row[i], 2)) for i in top_idx]
    return reasons


def run_decision_engine(csv_path, label_col="Label"):
    df_raw = pd.read_csv(csv_path)
    df_raw.columns = df_raw.columns.str.strip()

    keep_cols = FEATURES + ([label_col] if label_col in df_raw.columns else [])
    df_raw = df_raw[keep_cols].copy()
    df_raw = df_raw.replace([np.inf, -np.inf], np.nan).dropna()

    df = preprocess(df_raw)
    df_raw = df_raw.loc[df.index]  # keep labels aligned after dropna

    # Use the same score range as your test run for consistent calibration
    X_scaled_all = scaler.transform(df[FEATURES])
    raw_scores_all = model.decision_function(X_scaled_all)
    score_min, score_max = raw_scores_all.min(), raw_scores_all.max()

    sus_scores, X_scaled, raw_scores = compute_sus_score(df, score_min, score_max)
    df_raw["sus_score"] = sus_scores
    df_raw["tier"] = [assign_tier(s) for s in sus_scores]

    print("\n--- Tier distribution ---")
    print(df_raw["tier"].value_counts())

    if label_col in df_raw.columns:
        print("\n--- Tier breakdown by true label ---")
        print(pd.crosstab(df_raw[label_col], df_raw["tier"]))

    # Show a worked example: explain the first HIGH_ALERT session found
    high_alert_rows = df_raw[df_raw["tier"] == "HIGH_ALERT"]
    if len(high_alert_rows) > 0:
        idx = high_alert_rows.index[0]
        row_position = df.index.get_loc(idx)
        reasons = explain_flagged_session(X_scaled[row_position], FEATURES)
        print(f"\n--- Example HIGH_ALERT session (sus_score={sus_scores[row_position]:.1f}) ---")
        print("Top contributing factors (feature, standardized deviation):")
        for feat, dev in reasons:
            direction = "higher than normal" if dev > 0 else "lower than normal"
            print(f"  - {feat}: {direction} (z={dev})")

    return df_raw


if __name__ == "__main__":
    TEST_FILE = "data/raw/MachineLearningCVE/Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv"
    result_df = run_decision_engine(TEST_FILE)