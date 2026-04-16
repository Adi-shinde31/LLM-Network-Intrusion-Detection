# app/file_parser.py

import pandas as pd
import subprocess
import json


# ==========================================================
# 📂 PCAP PARSER (OFFLINE - PYSHARK)
# ==========================================================
def parse_pcap(filepath: str):
    import pyshark

    capture = pyshark.FileCapture(filepath, keep_packets=False)
    records = []

    for pkt in capture:
        try:
            record = {
                "Timestamp": str(pkt.sniff_time),
                "Src IP": pkt.ip.src if hasattr(pkt, "ip") else None,
                "Dst IP": pkt.ip.dst if hasattr(pkt, "ip") else None,
                "Protocol": pkt.highest_layer,
                "TotLen Fwd Pkts": int(pkt.length) if hasattr(pkt, "length") else 0
            }
            records.append(record)
        except Exception:
            continue

    capture.close()
    return pd.DataFrame(records)


# ==========================================================
# 📊 CSV PARSER
# ==========================================================
def parse_csv(filepath: str):
    df = pd.read_csv(filepath)

    df.columns = df.columns.str.strip()
    df = df.loc[:, ~df.columns.duplicated()]

    if df.empty:
        raise ValueError("CSV file is empty")

    return df


# ==========================================================
# 🔥 HELPER: SAFE VALUE EXTRACTION (CRITICAL FIX)
# ==========================================================
def safe_get(layer, key):
    val = layer.get(key)

    if isinstance(val, list):
        return val[0]

    return val


# ==========================================================
# 🔥 LIVE TRAFFIC CAPTURE (FIXED)
# ==========================================================
def capture_live_traffic(interface=None, capture_duration=5):

    if not interface:
        interface = get_active_interface()

    print(f"🚀 Using interface: {interface}")
    print(f"📡 Capturing live traffic for {capture_duration} seconds...")

    cmd = [
        "tshark",
        "-i", interface,
        "-a", f"duration:{capture_duration}",
        "-T", "json"
    ]

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True
        )

        if result.returncode != 0:
            print("❌ Tshark error:", result.stderr)
            return []

        if not result.stdout.strip():
            print("⚠ No output from Tshark")
            return []

        packets_json = json.loads(result.stdout)

    except Exception as e:
        print("❌ Tshark failed:", str(e))
        return []

    records = []

    for pkt in packets_json:
        try:
            layers = pkt["_source"]["layers"]

            ip_layer = layers.get("ip", {})
            frame_layer = layers.get("frame", {})

            timestamp = safe_get(frame_layer, "frame.time")
            src_ip = safe_get(ip_layer, "ip.src")
            dst_ip = safe_get(ip_layer, "ip.dst")
            protocol = safe_get(frame_layer, "frame.protocols")
            length = safe_get(frame_layer, "frame.len")

            record = {
                "timestamp": timestamp,
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "protocol": protocol,
                "length": int(length) if length else 0
            }

            # Only keep valid packets
            if src_ip and dst_ip:
                records.append(record)

        except Exception:
            continue

    print(f"✅ Captured {len(records)} valid packets")

    if len(records) < 10:
        print("⚠ Very low traffic — generate traffic (ping google.com)")

    return records


# ==========================================================
# 🔍 INTERFACE DETECTION (FIXED)
# ==========================================================
def get_active_interface():

    print("🔍 Detecting interfaces using tshark...")

    try:
        result = subprocess.run(
            ["tshark", "-D"],
            capture_output=True,
            text=True
        )

        output = result.stdout.strip().split("\n")

        print("📡 Available Interfaces:")
        for line in output:
            print(line)

        # Prefer Wi-Fi or Ethernet
        for line in output:
            if "Wi-Fi" in line or "Ethernet" in line:
                raw_interface = line.split(". ", 1)[1]

                # ✅ FIX: remove "(Wi-Fi)" part
                interface = raw_interface.split(" (")[0]

                print(f"✅ Selected interface: {interface}")
                return interface

        # fallback
        fallback = output[0].split(". ", 1)[1]
        interface = fallback.split(" (")[0]

        print(f"⚠ Fallback interface: {interface}")
        return interface

    except Exception as e:
        print("❌ Failed to detect interface:", str(e))

        # last fallback
        return None