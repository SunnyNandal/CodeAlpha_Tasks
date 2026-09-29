"""
main.py
Network Intrusion Detection System
Monitors network traffic continuously, detects threats,
and triggers responses.

Run in VS Code terminal:
    sudo python main.py        (Linux/macOS)
    python main.py             (Windows - run VS Code as Administrator)
"""

import os
import threading
import time
import webbrowser

from scapy.all import sniff, TCP, UDP, ICMP, IP

from detector import DetectionEngine
from responder import Responder
from server import app as dashboard_app


# ==== CONFIGURATION ====
INTERFACE = None      # None = default interface. Set e.g. "eth0" or "Wi-Fi"
PACKET_LIMIT = 0      # 0 = run forever. Set e.g. 100 for a test run.


def extract_packet_info(packet):
    """Turn a Scapy packet into a simple dict the detector can use."""
    info = {
        "src_ip": None,
        "dst_ip": None,
        "dst_port": None,
        "protocol": None,
        "payload": "",
    }

    if IP in packet:
        info["src_ip"] = packet[IP].src
        info["dst_ip"] = packet[IP].dst

    if TCP in packet:
        info["protocol"] = "TCP"
        info["dst_port"] = int(packet[TCP].dport)
        info["payload"] = str(bytes(packet[TCP].payload))
    elif UDP in packet:
        info["protocol"] = "UDP"
        info["dst_port"] = int(packet[UDP].dport)
        info["payload"] = str(bytes(packet[UDP].payload))
    elif ICMP in packet:
        info["protocol"] = "ICMP"
    else:
        return None

    if info.get("dst_port") == 80 and info["payload"]:
        info["protocol"] = "HTTP"

    return info


def process_packet(packet):
    """Callback for every captured packet."""
    info = extract_packet_info(packet)
    if info is None:
        return

    alerts = engine.check_rules(info)

    for alert in alerts:
        print(f"\n[ALERT] {alert['severity']} | {alert['name']}")
        print(f"        Source: {alert['src_ip']} -> Dest: {alert['dst_ip']}")
        print(f"        Detail: {alert['detail']}")
        responder.respond(alert)


def start_dashboard():
    """Start the Flask dashboard server."""
    try:
        dashboard_app.run(host="0.0.0.0", port=5000, debug=False, use_reloader=False)
    except OSError as exc:
        print(f"\n[WEB] Dashboard already running on port 5000: {exc}")


if __name__ == "__main__":
    alerts_log = os.path.join(os.path.dirname(__file__), "alerts.log")

    engine = DetectionEngine()
    responder = Responder(block_enabled=True)

    print("=" * 50)
    print("  NETWORK INTRUSION DETECTION SYSTEM")
    print("=" * 50)
    print(f"  Interface : {INTERFACE or 'default'}")
    print(f"  Rules     : {len(engine.rules)} loaded")
    print(f"  Alerts log: {alerts_log}")
    print("=" * 50)

    dashboard_thread = threading.Thread(target=start_dashboard, daemon=True)
    dashboard_thread.start()
    time.sleep(1)

    try:
        webbrowser.open("http://127.0.0.1:5000")
        print("[*] Dashboard: http://127.0.0.1:5000")
    except Exception as exc:
        print(f"[WEB] Could not open browser automatically: {exc}")

    print("[*] Monitoring network traffic... (Ctrl+C to stop)\n")

    try:
        sniff(
            iface=INTERFACE,
            prn=process_packet,
            count=PACKET_LIMIT if PACKET_LIMIT > 0 else 0,
            store=False,
        )
    except KeyboardInterrupt:
        print("\n[*] Stopped by user.")
    except PermissionError:
        print("\n[!] Permission denied. Run as Administrator/root.")
