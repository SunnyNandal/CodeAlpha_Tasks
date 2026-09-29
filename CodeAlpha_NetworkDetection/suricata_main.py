"""Run Suricata IDS and serve its alerts on the project dashboard."""

import json
import os
import socket
import subprocess
import threading
import time
import webbrowser
from pathlib import Path

PROJECT_DIR = Path(__file__).resolve().parent
LOG_DIR = PROJECT_DIR / "suricata-logs"
ALERT_LOG = LOG_DIR / "alerts-live.jsonl"
PORT_SCAN_STATUS_FILE = LOG_DIR / "port-scan.json"
LOG_DIR.mkdir(exist_ok=True)
os.environ["NIDS_ALERT_LOG"] = str(ALERT_LOG)
os.environ["NIDS_PORT_SCAN_STATUS"] = str(PORT_SCAN_STATUS_FILE)

import server as dashboard_server
from port_scanner import run_scan_loop

dashboard_app = dashboard_server.app
SURICATA_EXE = Path(os.environ.get("SURICATA_PATH", r"C:\Program Files\Suricata\suricata.exe"))
SURICATA_CONFIG = Path(os.environ.get("SURICATA_CONFIG", r"C:\Program Files\Suricata\suricata.yaml"))
SURICATA_RULES = PROJECT_DIR / "suricata.rules"
NMAP_EXE = Path(os.environ.get("NMAP_PATH", r"C:\Program Files (x86)\Nmap\nmap.exe"))
INTERFACE = os.environ.get("NIDS_INTERFACE")


def get_capture_interface():
    """Use a configured interface or resolve the default routed IPv4 address."""
    if INTERFACE:
        return INTERFACE

    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as route_socket:
        route_socket.connect(("1.1.1.1", 53))
        return route_socket.getsockname()[0]


def normalize_alert(event):
    """Convert a Suricata EVE alert into the dashboard's alert schema."""
    details = event.get("alert", {})
    priority = details.get("severity", 4)
    severity = {1: "HIGH", 2: "MEDIUM", 3: "LOW"}.get(priority, "LOW")
    signature = details.get("signature", "Suricata alert")
    category = details.get("category")

    return {
        "timestamp": event.get("timestamp", time.strftime("%Y-%m-%d %H:%M:%S")),
        "rule_id": details.get("signature_id"),
        "name": signature,
        "severity": severity,
        "src_ip": event.get("src_ip"),
        "dst_ip": event.get("dest_ip"),
        "dst_port": event.get("dest_port"),
        "detail": f"{category}: {signature}" if category else signature,
    }


def monitor_eve_log(eve_path, initial_offset):
    """Forward new Suricata alert events to the dashboard's JSON-lines log."""
    offset = initial_offset
    while True:
        try:
            with eve_path.open("r", encoding="utf-8") as eve_file:
                if eve_path.stat().st_size < offset:
                    offset = 0
                eve_file.seek(offset)
                while line := eve_file.readline():
                    offset = eve_file.tell()
                    try:
                        event = json.loads(line)
                    except json.JSONDecodeError:
                        continue
                    if event.get("event_type") != "alert":
                        continue

                    alert = normalize_alert(event)
                    with ALERT_LOG.open("a", encoding="utf-8") as alert_file:
                        alert_file.write(json.dumps(alert) + "\n")
                    print(f"\n[ALERT] {alert['severity']} | {alert['name']}")
                    print(f"        Source: {alert['src_ip']} -> Dest: {alert['dst_ip']}")
        except FileNotFoundError:
            pass
        time.sleep(0.25)


def find_dashboard_port():
    """Choose the first available local dashboard port."""
    configured_port = os.environ.get("NIDS_DASHBOARD_PORT")
    if configured_port:
        return int(configured_port)

    for port in range(5000, 5010):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
            try:
                probe.bind(("127.0.0.1", port))
                return port
            except OSError:
                continue
    raise RuntimeError("No free dashboard port found between 5000 and 5009.")


def start_dashboard(port):
    """Start the Flask dashboard server."""
    try:
        dashboard_app.run(host="0.0.0.0", port=port, debug=False, use_reloader=False)
    except OSError as exc:
        print(f"\n[WEB] Dashboard already running on port 5000: {exc}")


def main():
    if not SURICATA_EXE.is_file():
        raise SystemExit(f"Suricata was not found at {SURICATA_EXE}. Set SURICATA_PATH to suricata.exe.")
    if not SURICATA_CONFIG.is_file():
        raise SystemExit(f"Suricata config was not found at {SURICATA_CONFIG}. Set SURICATA_CONFIG to suricata.yaml.")
    if not SURICATA_RULES.is_file():
        raise SystemExit(f"Local signatures were not found at {SURICATA_RULES}.")
    if not NMAP_EXE.is_file():
        raise SystemExit(f"Nmap was not found at {NMAP_EXE}. Set NMAP_PATH to nmap.exe.")

    LOG_DIR.mkdir(exist_ok=True)
    ALERT_LOG.write_text("", encoding="utf-8")
    eve_path = LOG_DIR / "eve.json"
    initial_offset = eve_path.stat().st_size if eve_path.exists() else 0
    capture_interface = get_capture_interface()
    dashboard_port = find_dashboard_port()

    print("=" * 50)
    print("  NETWORK INTRUSION DETECTION SYSTEM")
    print("=" * 50)
    print("  Sensor    : Suricata IDS")
    print(f"  Interface : {capture_interface}")
    print(f"  Rules     : {SURICATA_RULES}")
    print(f"  Alerts log: {ALERT_LOG}")
    print("  Port scan : continuous TCP+UDP 1-65535 scans of 127.0.0.1")
    print("=" * 50)

    threading.Thread(target=start_dashboard, args=(dashboard_port,), daemon=True).start()
    threading.Thread(
        target=run_scan_loop,
        args=(NMAP_EXE, PORT_SCAN_STATUS_FILE),
        daemon=True,
    ).start()
    threading.Thread(
        target=monitor_eve_log,
        args=(eve_path, initial_offset),
        daemon=True,
    ).start()
    time.sleep(1)

    try:
        dashboard_url = f"http://127.0.0.1:{dashboard_port}"
        webbrowser.open(dashboard_url)
        print(f"[*] Dashboard: {dashboard_url}")
    except Exception as exc:
        print(f"[WEB] Could not open browser automatically: {exc}")

    command = [
        str(SURICATA_EXE),
        "-c", str(SURICATA_CONFIG),
        "-S", str(SURICATA_RULES),
        "-i", capture_interface,
        "-l", str(LOG_DIR),
    ]
    process = None
    try:
        with (LOG_DIR / "suricata.log").open("a", encoding="utf-8") as engine_log:
            process = subprocess.Popen(command, stdout=engine_log, stderr=subprocess.STDOUT)
            print("[*] Monitoring network traffic with Suricata... (Ctrl+C to stop)\n")
            exit_code = process.wait()
            if exit_code:
                print(f"[!] Suricata exited with code {exit_code}. Review suricata-logs/suricata.log.")
    except KeyboardInterrupt:
        if process is not None and process.poll() is None:
            process.terminate()
            process.wait()
        print("\n[*] Stopped by user.")
    except OSError as exc:
        print(f"\n[!] Could not start Suricata: {exc}")
        print("[!] Check Npcap, run PowerShell as Administrator, and review suricata-logs/suricata.log.")


if __name__ == "__main__":
    main()
