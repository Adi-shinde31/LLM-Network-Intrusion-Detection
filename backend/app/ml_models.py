# app/ml_models.py

import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
from .schema import ParsedTask

# ==========================================================
# MAIN ENTRY FUNCTION
# ==========================================================

def run_anomaly_detection(task: ParsedTask, network_data):

    # Convert list → DataFrame
    if isinstance(network_data, list):
        network_data = pd.DataFrame(network_data)

    if not isinstance(network_data, pd.DataFrame):
        raise ValueError("Network data must be DataFrame or list")

    if network_data.empty:
        raise ValueError("Network data is empty")

    df = pd.DataFrame(network_data)

    # Apply row limit
    if task.row_limit:
        df = df.head(task.row_limit)

    # 🔥 LIVE DATA → Only anomaly detection allowed
    if task.data_source == "live":

        if task.analysis_type != "anomaly_detection":
            return {
                "error": "Live capture supports only basic anomaly_detection.",
                "suggestion": "Use uploaded CSV for MITM, DoS, or brute-force detection."
            }

        return _anomaly_detection(df)

    # 🔥 UPLOADED DATA → Allow all detections
    if task.analysis_type == "anomaly_detection":
        return _anomaly_detection(df)

    elif task.analysis_type == "brute_force_detection":
        return _brute_force_detection(df)

    elif task.analysis_type == "mitm_detection":
        return _mitm_detection(df)

    elif task.analysis_type == "dos_detection":
        return _dos_detection(df)

    else:
        return {"error": f"Unsupported analysis type: {task.analysis_type}"}


# ==========================================================
# 1️⃣ ADAPTIVE ANOMALY DETECTION
# Works for BOTH:
# - CICIDS CSV
# - Live Flow Data
# ==========================================================

def _anomaly_detection(df: pd.DataFrame):

    cicids_features = [
        "Flow Byts/s",
        "Flow Pkts/s",
        "Flow Duration",
        "Tot Fwd Pkts",
        "Tot Bwd Pkts"
    ]

    live_features = [
        "total_packets",
        "total_bytes",
        "avg_packet_size",
        "flow_duration"
    ]

    # Determine feature set automatically
    if all(col in df.columns for col in cicids_features):
        feature_cols = cicids_features
        data_type = "uploaded"

    elif all(col in df.columns for col in live_features):
        feature_cols = live_features
        data_type = "live"

    else:
        return {
            "error": "Required columns not found",
            "available_columns": df.columns.tolist()
        }

    # Prepare features
    X = df[feature_cols].apply(pd.to_numeric, errors="coerce")
    X = X.replace([np.inf, -np.inf], np.nan)
    X = X.fillna(0)

    # Train Isolation Forest
    clf = IsolationForest(
        contamination=0.05,
        random_state=42
    )

    clf.fit(X)
    preds = clf.predict(X)

    df["prediction"] = preds

    anomaly_indices = df[df["prediction"] == -1].index.tolist()

    return {
        "analysis_type": "adaptive_anomaly_detection",
        "data_type": data_type,
        "total_records": len(df),
        "anomaly_count": len(anomaly_indices),
        "anomaly_indices": anomaly_indices
    }


# ==========================================================
# 2️⃣ BRUTE FORCE DETECTION (Uploaded Only)
# ==========================================================

def _brute_force_detection(df: pd.DataFrame):

    required_columns = [
        "Src IP",
        "Flow Duration",
        "Tot Fwd Pkts",
        "TotLen Fwd Pkts",
        "Flow Pkts/s",
        "SYN Flag Cnt",
        "RST Flag Cnt",
        "ACK Flag Cnt",
        "Dst Port"
    ]

    for col in required_columns:
        if col not in df.columns:
            return {
                "error": f"Missing column: {col}",
                "available_columns": df.columns.tolist()
            }

    X = df[required_columns].copy()
    X = X.apply(pd.to_numeric, errors="coerce")
    X = X.replace([np.inf, -np.inf], np.nan)
    X = X.fillna(0)

    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)

    model = IsolationForest(
        n_estimators=150,
        contamination=0.02,
        random_state=42,
        n_jobs=-1
    )

    model.fit(X_scaled)

    df["prediction"] = model.predict(X_scaled)

    suspicious = df[df["prediction"] == -1]

    attacker_summary = (
        suspicious.groupby("Src IP")
        .size()
        .reset_index(name="attempt_count")
        .sort_values(by="attempt_count", ascending=False)
    )

    return {
        "analysis_type": "ml_brute_force_detection",
        "total_records": len(df),
        "suspicious_flow_count": len(suspicious),
        "unique_attackers": attacker_summary.shape[0],
        "top_attackers": attacker_summary.head(5).to_dict(orient="records")
    }


# ==========================================================
# 3️⃣ MITM DETECTION (Uploaded Only)
# ==========================================================

def _mitm_detection(df: pd.DataFrame):

    required_columns = [
        "Src IP",
        "Flow Duration",
        "Tot Fwd Pkts",
        "Tot Bwd Pkts",
        "Flow IAT Mean",
        "Flow IAT Std",
        "SYN Flag Cnt",
        "RST Flag Cnt",
        "ACK Flag Cnt"
    ]

    for col in required_columns:
        if col not in df.columns:
            return {
                "error": f"Missing column: {col}",
                "available_columns": df.columns.tolist()
            }

    X = df[required_columns].copy()
    X = X.apply(pd.to_numeric, errors="coerce")
    X = X.replace([np.inf, -np.inf], np.nan)
    X = X.fillna(0)

    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)

    model = IsolationForest(
        n_estimators=200,
        contamination=0.02,
        random_state=42,
        n_jobs=-1
    )

    model.fit(X_scaled)

    df["prediction"] = model.predict(X_scaled)

    suspicious = df[df["prediction"] == -1]

    mitm_summary = (
        suspicious.groupby("Src IP")
        .size()
        .reset_index(name="suspicious_flow_count")
        .sort_values(by="suspicious_flow_count", ascending=False)
    )

    return {
        "analysis_type": "ml_mitm_detection",
        "total_records": len(df),
        "suspicious_flow_count": len(suspicious),
        "unique_suspected_ips": mitm_summary.shape[0],
        "top_suspects": mitm_summary.head(5).to_dict(orient="records")
    }


# ==========================================================
# 4️⃣ DOS DETECTION (Uploaded Only)
# ==========================================================

def _dos_detection(df: pd.DataFrame):

    required_columns = [
        "Src IP",
        "Flow Duration",
        "Flow Pkts/s",
        "Flow Byts/s",
        "SYN Flag Cnt",
        "ACK Flag Cnt"
    ]

    for col in required_columns:
        if col not in df.columns:
            return {
                "error": f"Missing column: {col}",
                "available_columns": df.columns.tolist()
            }

    X = df[required_columns].copy()
    X = X.apply(pd.to_numeric, errors="coerce")
    X = X.replace([np.inf, -np.inf], np.nan)
    X = X.fillna(0)

    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)

    model = IsolationForest(
        n_estimators=200,
        contamination=0.03,
        random_state=42,
        n_jobs=-1
    )

    model.fit(X_scaled)

    df["prediction"] = model.predict(X_scaled)

    suspicious = df[df["prediction"] == -1]

    dos_summary = (
        suspicious.groupby("Src IP")
        .size()
        .reset_index(name="suspicious_flow_count")
        .sort_values(by="suspicious_flow_count", ascending=False)
    )

    return {
        "analysis_type": "ml_dos_detection",
        "total_records": len(df),
        "suspicious_flow_count": len(suspicious),
        "unique_suspected_attackers": dos_summary.shape[0],
        "top_attackers": dos_summary.head(5).to_dict(orient="records")
    }