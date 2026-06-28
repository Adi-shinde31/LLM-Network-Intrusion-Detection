# app/mcp.py

import os
import json
import logging
from typing import Dict, Any
from dotenv import load_dotenv
from openai import OpenAI
import pandas as pd

from .schema import ParsedTask
from .ml_models import run_anomaly_detection
from .data_handler import fetch_network_data, validate_and_store_data
from app.db import files_collection
from bson import ObjectId
from app.db import uploads_collection
from app.db import fs

load_dotenv()

API_KEY = os.getenv("OPENAI_API_KEY")
if not API_KEY:
    raise EnvironmentError("❌ OPENAI_API_KEY not found in environment.")

client = OpenAI(api_key=API_KEY)

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

EXPLAIN_SYSTEM_PROMPT = """
You are a cybersecurity analyst.

Explain the results in simple, clear language for a dashboard user.

Rules:
- Do NOT mention PCA, models, or algorithms
- Focus on what is happening in the network
- Be concise and actionable

Return ONLY valid JSON:
{
  "explanation": string,
  "confidence": float,
  "recommendations": [string]
}
"""

def clear_previous_output():
    output_file = "output/network_data.json"
    try:
        if os.path.exists(output_file):
            os.remove(output_file)
    except:
        pass

# =========================
# FILE LOADER (FIXED)
# =========================
def load_file_data(file_id: str, file_type: str, row_limit: int = None):

    file_data = fs.get(ObjectId(file_id))
    content = file_data.read()

    if file_type == "csv":
        import io

        df = pd.read_csv(
            io.BytesIO(content),
            low_memory=False,
            on_bad_lines="skip"
        )

        print("Raw rows from CSV:", len(df))

        df = df.dropna(how="all")
        df.columns = df.columns.str.strip()
        df = df.reset_index(drop=True)

        # ✅ IMPORTANT FIX: apply row limit HERE
        if row_limit:
            df = df.head(row_limit)

        print("FINAL STORED ROWS:", len(df))

        return df

    elif file_type == "pcap":
        import tempfile
        temp_path = tempfile.mktemp(suffix=".pcap")
        with open(temp_path, "wb") as f:
            f.write(content)

        import pyshark
        capture = pyshark.FileCapture(temp_path, keep_packets=False)

        records = []
        try:
            for pkt in capture:
                try:
                    records.append({
                        "timestamp": str(pkt.sniff_time),
                        "src_ip": pkt.ip.src if hasattr(pkt, "ip") else None,
                        "dst_ip": pkt.ip.dst if hasattr(pkt, "ip") else None,
                        "protocol": pkt.highest_layer
                    })
                except:
                    continue
        finally:
            capture.close()
            os.remove(temp_path)

        return records

# =========================
# MAIN EXECUTION PIPELINE
# =========================
def execute_task(task: ParsedTask) -> Dict[str, Any]:

    clear_previous_output()
    logger.info(f"Task received: {task.model_dump()}")

    try:
        filepath = None
        network_data = None

        # =========================
        # FILE INPUT (CSV / PCAP)
        # =========================
        if getattr(task, "file_path", None):

            logger.info("Using uploaded file")

            filepath = task.file_path

            network_data = load_file_data(
                task.file_path,
                task.file_type,
                task.row_limit
            )

            if task.file_type == "pcap":
                from app.data_handler import build_flows
                network_data = build_flows(network_data)

            if isinstance(network_data, pd.DataFrame):
                row_count = len(network_data)
                print("row_count: ", row_count)
            else:
                row_count = 0

            try:
                uploads_collection.update_one(
                    {"_id": ObjectId(task.file_path)},
                    {"$set": {"row_count": row_count}}
                )
            except Exception as e:
                logger.warning(f"MongoDB update failed: {e}")

        # =========================
        # LIVE DATA INPUT
        # =========================
        else:
            logger.info("Using live network data")

            network_data = fetch_network_data(task)
            filepath = validate_and_store_data(task, network_data)

        logger.info("Data ready")

        # =========================
        # ML MODEL
        # =========================
        ml_results = run_anomaly_detection(task, network_data)

    except Exception as e:
        logger.exception("Pipeline failed")
        return {
            "status": "error",
            "stage": "pipeline",
            "message": str(e)
        }

    # =========================
    # 🔥 BUILD COMPACT SUMMARY (CRITICAL FIX)
    # =========================
    try:
        ml_summary = {
            "analysis_type": ml_results.get("analysis_type"),
            "total_records": ml_results.get("total_records"),
            "suspicious_flow_count": ml_results.get("suspicious_flow_count"),
            "unique_attackers": ml_results.get("unique_suspected_attackers", 0),
            "risk_score": ml_results.get("risk_score"),
            "top_anomaly_indices": ml_results.get("anomaly_indices", [])[:5]
        }

    except Exception as e:
        logger.warning(f"Failed to build ML summary: {e}")
        ml_summary = {}

    # =========================
    # 🤖 LLM EXPLANATION (SAFE)
    # =========================
    try:
        user_message = f"""
        Task:
        {json.dumps(task.model_dump(), indent=2)}

        ML Summary:
        {json.dumps(ml_summary, indent=2)}
        """

        response = client.chat.completions.create(
            model="gpt-4.1",
            messages=[
                {"role": "system", "content": EXPLAIN_SYSTEM_PROMPT},
                {"role": "user", "content": user_message}
            ],
            temperature=0,
        )

        raw = response.choices[0].message.content.strip()
        explanation = json.loads(raw)

    except Exception as e:
        logger.exception("LLM failed")

        # 🔥 FALLBACK (IMPORTANT FOR DEMO STABILITY)
        explanation = {
            "explanation": f"{ml_summary.get('suspicious_flow_count', 0)} anomalous flows detected out of {ml_summary.get('total_records', 0)} records. These flows deviate from normal traffic patterns and may indicate potential threats or unusual behavior.",
            "confidence": 0.75,
            "recommendations": [
                "Inspect anomalous flows in detail",
                "Check source/destination IPs",
                "Correlate with firewall/IDS logs",
                "Monitor suspicious traffic patterns"
            ]
        }
        
    print("PCA DEBUG:", ml_results.get("pca"))

    # =========================
    # ✅ FINAL RESPONSE
    # =========================
    return {
        "status": "success",
        "task": task.model_dump(),
        "data_path": filepath,
        "ml_results": ml_results,   # full data (for charts)
        "ml_summary": ml_summary,   # 🔥 NEW (for UI)
        "explanation": explanation
    }


# =========================
# CONFIDENCE BLENDING
# =========================
def blend_confidence(ml_results: Dict[str, Any], llm_confidence: float) -> float:

    ml_score = ml_results.get("risk_score", 0.0)

    ml_score = max(0.0, min(1.0, ml_score))
    llm_confidence = max(0.0, min(1.0, llm_confidence))

    return round((0.7 * ml_score) + (0.3 * llm_confidence), 3)