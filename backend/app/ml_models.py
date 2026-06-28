import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
from sklearn.decomposition import PCA
from .schema import ParsedTask

# ==========================================================
# MAIN ENTRY FUNCTION
# ==========================================================

def run_anomaly_detection(task: ParsedTask, network_data):

    if isinstance(network_data, list):
        network_data = pd.DataFrame(network_data)

    if not isinstance(network_data, pd.DataFrame):
        raise ValueError("Network data must be DataFrame or list")

    if network_data.empty:
        raise ValueError("Network data is empty")

    df = pd.DataFrame(network_data)

    if task.row_limit:
        df = df.head(task.row_limit)

    # Default fallback
    if task.analysis_type is None:
        task.analysis_type = "anomaly_detection"

    if task.data_source == "live":
        return _anomaly_detection(df)

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
# PCA FUNCTION (COMMON)
# ==========================================================

def compute_pca_visualization(df, feature_cols, preds):

    X = df[feature_cols].apply(pd.to_numeric, errors="coerce")
    X = X.replace([np.inf, -np.inf], np.nan).fillna(0)

    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)

    pca = PCA(n_components=2)
    components = pca.fit_transform(X_scaled)

    normal_points = []
    anomaly_points = []

    for i in range(len(components)):
        x, y = components[i]

        if np.isnan(x) or np.isnan(y):
            continue

        point = {
            "x": float(x),
            "y": float(y)
        }

        if preds[i] == -1:
            anomaly_points.append(point)
        else:
            normal_points.append(point)

    return {
        "explained_variance": pca.explained_variance_ratio_.tolist(),
        "normal": normal_points[:1000],
        "anomaly": anomaly_points[:1000]
    }

# ==========================================================
# 1️⃣ ANOMALY DETECTION
# ==========================================================

def _anomaly_detection(df):

    cicids_features = [
        "Flow Byts/s", "Flow Pkts/s", "Flow Duration",
        "Tot Fwd Pkts", "Tot Bwd Pkts"
    ]

    live_features = [
        "total_packets", "total_bytes",
        "avg_packet_size", "flow_duration"
    ]

    if all(col in df.columns for col in cicids_features):
        feature_cols = cicids_features

    elif all(col in df.columns for col in live_features):
        feature_cols = live_features

    else:
        return {
            "error": "Required columns not found",
            "available_columns": df.columns.tolist()
        }

    X = df[feature_cols].apply(pd.to_numeric, errors="coerce")
    X = X.replace([np.inf, -np.inf], np.nan).fillna(0)

    model = IsolationForest(contamination=0.05, random_state=42)
    model.fit(X)

    preds = model.predict(X)
    df["prediction"] = preds
    anomaly_indices = df[df["prediction"] == -1].index.tolist()
    suspicious_df = df[df["prediction"] == -1]

    # 🔥 Extract top suspicious IPs (if available)
    ip_col = "src_ip" if "src_ip" in df.columns else ("Src IP" if "Src IP" in df.columns else None)

    top_ips = []
    unique_attackers = 0

    if ip_col:
        top_ips = (
            suspicious_df.groupby(ip_col)
            .size()
            .reset_index(name="count")
            .rename(columns={ip_col: "src_ip"})
            .sort_values(by="count", ascending=False)
            .head(5)
            .to_dict(orient="records")
        )
        unique_attackers = suspicious_df[ip_col].nunique()

    pca_result = compute_pca_visualization(df, feature_cols, preds)

    # 🔥 ADD THIS ABOVE RETURN
    risk_score = len(anomaly_indices) / len(df) if len(df) > 0 else 0

    if risk_score > 0.1:
        risk_level = "HIGH"
    elif risk_score > 0.05:
        risk_level = "MEDIUM"
    else:
        risk_level = "LOW"

    return {
        "analysis_type": "adaptive_anomaly_detection",
        "total_records": len(df),
        "suspicious_flow_count": len(anomaly_indices),
        "anomaly_indices": anomaly_indices,
        "unique_suspected_attackers": unique_attackers,
        "risk_score": round(risk_score, 4),
        "risk_level": risk_level,

        "top_suspicious_ips": top_ips,   # 🔥 NEW

        "pca": pca_result
    }


# ==========================================================
# 2️⃣ BRUTE FORCE
# ==========================================================

def _brute_force_detection(df):

    cols = [
        "Src IP", "Flow Duration", "Tot Fwd Pkts",
        "TotLen Fwd Pkts", "Flow Pkts/s",
        "SYN Flag Cnt", "RST Flag Cnt",
        "ACK Flag Cnt", "Dst Port"
    ]

    for col in cols:
        if col not in df.columns:
            return {"error": f"Missing column: {col}"}

    X = df[cols].apply(pd.to_numeric, errors="coerce")

    # 🔥 CRITICAL FIX
    X = X.replace([np.inf, -np.inf], np.nan)
    X = X.fillna(0)

    # 🔥 EXTRA SAFETY (IMPORTANT)
    X = X.clip(-1e10, 1e10)

    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)

    model = IsolationForest(n_estimators=150, contamination=0.02, random_state=42)
    model.fit(X_scaled)

    preds = model.predict(X_scaled)
    df["prediction"] = preds

    suspicious = df[df["prediction"] == -1]
    risk_score = len(suspicious) / len(df) if len(df) > 0 else 0

    if risk_score > 0.1:
        risk_level = "HIGH"
    elif risk_score > 0.05:
        risk_level = "MEDIUM"
    else:
        risk_level = "LOW"
        
    pca_result = compute_pca_visualization(df, cols, preds)

    return {
        "analysis_type": "ml_brute_force_detection",
        "total_records": len(df),
        "suspicious_flow_count": len(suspicious),
        "unique_suspected_attackers": suspicious["Src IP"].nunique(),
        "risk_score": risk_score,
        "risk_level": risk_level,
        "pca": pca_result
    }


# ==========================================================
# 3️⃣ MITM
# ==========================================================

def _mitm_detection(df):

    cols = [
        "Src IP", "Flow Duration", "Tot Fwd Pkts",
        "Tot Bwd Pkts", "Flow IAT Mean",
        "Flow IAT Std", "SYN Flag Cnt",
        "RST Flag Cnt", "ACK Flag Cnt"
    ]

    for col in cols:
        if col not in df.columns:
            return {"error": f"Missing column: {col}"}

    X = df[cols].apply(pd.to_numeric, errors="coerce")

    # 🔥 CRITICAL FIX
    X = X.replace([np.inf, -np.inf], np.nan)
    X = X.fillna(0)

    # 🔥 EXTRA SAFETY (IMPORTANT)
    X = X.clip(-1e10, 1e10)

    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)

    model = IsolationForest(n_estimators=200, contamination=0.02, random_state=42)
    model.fit(X_scaled)

    preds = model.predict(X_scaled)
    df["prediction"] = preds

    suspicious = df[df["prediction"] == -1]
    risk_score = len(suspicious) / len(df) if len(df) > 0 else 0

    if risk_score > 0.1:
        risk_level = "HIGH"
    elif risk_score > 0.05:
        risk_level = "MEDIUM"
    else:
        risk_level = "LOW"
        
        
    pca_result = compute_pca_visualization(df, cols, preds)

    return {
        "analysis_type": "ml_mitm_detection",
        "total_records": len(df),
        "suspicious_flow_count": len(suspicious),
        "unique_suspected_attackers": suspicious["Src IP"].nunique(),
        "risk_score": risk_score,
        "risk_level": risk_level,
        "pca": pca_result
    }


# ==========================================================
# 4️⃣ DOS
# ==========================================================

def _dos_detection(df):

    cols = [
        "Src IP", "Flow Duration",
        "Flow Pkts/s", "Flow Byts/s",
        "SYN Flag Cnt", "ACK Flag Cnt"
    ]

    for col in cols:
        if col not in df.columns:
            return {"error": f"Missing column: {col}"}

    X = df[cols].apply(pd.to_numeric, errors="coerce")

    # 🔥 CRITICAL FIX
    X = X.replace([np.inf, -np.inf], np.nan)
    X = X.fillna(0)

    # 🔥 EXTRA SAFETY (IMPORTANT)
    X = X.clip(-1e10, 1e10)

    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)

    model = IsolationForest(n_estimators=200, contamination=0.03, random_state=42)
    model.fit(X_scaled)

    preds = model.predict(X_scaled)
    df["prediction"] = preds

    suspicious = df[df["prediction"] == -1]
    risk_score = len(suspicious) / len(df) if len(df) > 0 else 0

    if risk_score > 0.1:
        risk_level = "HIGH"
    elif risk_score > 0.05:
        risk_level = "MEDIUM"
    else:
        risk_level = "LOW"
        
    pca_result = compute_pca_visualization(df, cols, preds)

    return {
        "analysis_type": "ml_dos_detection",
        "total_records": len(df),
        "suspicious_flow_count": len(suspicious),
        "unique_suspected_attackers": suspicious["Src IP"].nunique(),
        "risk_score": risk_score,
        "risk_level": risk_level,
        "pca": pca_result
    }