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
You are an AI assistant for network security analysis.

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
def load_file_data(file_id: str, file_type: str):

    file_data = fs.get(ObjectId(file_id))
    content = file_data.read()

    if file_type == "csv":
        import io
        return pd.read_csv(io.BytesIO(content))

    elif file_type == "pcap":
        import tempfile
        temp_path = tempfile.mktemp(suffix=".pcap")
        with open(temp_path, "wb") as f:
            f.write(content)

        import pyshark
        capture = pyshark.FileCapture(temp_path, keep_packets=False)

        records = []
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

        capture.close()
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

            network_data = load_file_data(task.file_path, task.file_type)
            if isinstance(network_data, pd.DataFrame):
                row_count = len(network_data)
            elif isinstance(network_data, list):
                row_count = len(network_data)
            else:
                row_count = 0
                
            # 🔥 FIX: correct row count stored in MongoDB
            try:
                uploads_collection.insert_one({
                    "file_path": task.file_path,
                    "file_type": task.file_type,
                    "row_count": row_count,
                })
            except Exception as e:
                logger.warning(f"MongoDB insert failed: {e}")

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
    # LLM EXPLANATION
    # =========================
    try:
        user_message = f"""
        Task:
        {json.dumps(task.model_dump(), indent=2)}

        ML Results:
        {json.dumps(ml_results, indent=2)}
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
        return {
            "status": "error",
            "stage": "llm",
            "message": str(e)
        }

    return {
        "status": "success",
        "task": task.model_dump(),
        "data_path": filepath,
        "ml_results": ml_results,
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