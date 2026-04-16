# app/data_handler.py

import os
import json
from .schema import ParsedTask
from .file_parsers import (
    parse_pcap,
    parse_csv,
    capture_live_traffic,
    get_active_interface
)
import pandas as pd

DATASET_DIR = "dataset"
OUTPUT_DIR = "output"

# ==========================================================
#  Convert packets → flows
# ==========================================================
def build_flows(packet_records):

    df = pd.DataFrame(packet_records)

    if df.empty:
        print("❌ No packets captured.")
        return pd.DataFrame()

    print(df.head(5))

    # Convert timestamp
    df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce")

    # Remove invalid rows
    df = df.dropna(subset=["src_ip", "dst_ip", "timestamp"])


    if df.empty:
        print("❌ No valid packet data after cleaning.")
        return pd.DataFrame()

    # Group into flows
    flows = df.groupby(["src_ip", "dst_ip", "protocol"]).agg(
        total_packets=("length", "count"),
        total_bytes=("length", "sum"),
        avg_packet_size=("length", "mean"),
        flow_duration=("timestamp", lambda x: (x.max() - x.min()).total_seconds())
    ).reset_index()

    print(flows.head(5))

    return flows


# ==========================================================
# MAIN FETCH FUNCTION
# ==========================================================
def fetch_network_data(task: ParsedTask):

    # LIVE DATA
    if task.data_source == "live":

        print("\n📡 LIVE DATA MODE")

        try:
            interface = get_active_interface()
        except Exception as e:
            print("❌ Failed to get interface:", str(e))
            raise

        try:
            packets = capture_live_traffic(
                interface=interface,
                capture_duration=task.time_window_minutes * 60 if task.time_window_minutes else 5
            )
        except Exception as e:
            print("❌ Capture failed:", str(e))
            raise

        if not packets:
            print("⚠ WARNING: No packets captured!")

        flows = build_flows(packets)

        return flows


    else:
        raise ValueError("Invalid data_source. Use 'live' or 'uploaded'")


# ==========================================================
#  STORE DATA
# ==========================================================
def validate_and_store_data(task: ParsedTask, network_data):

    if isinstance(network_data, pd.DataFrame):
        df = network_data
    elif isinstance(network_data, list):
        df = pd.DataFrame(network_data)
    else:
        raise ValueError("Network data must be list or DataFrame")

    if df.empty:
        print("⚠ WARNING: DataFrame is empty before saving")

    json_data = df.to_dict(orient="records")

    os.makedirs(OUTPUT_DIR, exist_ok=True)
    filepath = os.path.join(OUTPUT_DIR, "network_data.json")

    with open(filepath, "w") as f:
        json.dump(json_data, f, indent=2, default=str)

    return filepath