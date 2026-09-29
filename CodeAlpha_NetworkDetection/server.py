import json
import os
from collections import Counter

from flask import Flask, jsonify, send_file

app = Flask(__name__)
ALERT_LOG = os.environ.get(
    "NIDS_ALERT_LOG",
    os.path.join(os.path.dirname(__file__), "alerts.log"),
)
PORT_SCAN_STATUS_FILE = os.environ.get(
    "NIDS_PORT_SCAN_STATUS",
    os.path.join(os.path.dirname(__file__), "suricata-logs", "port-scan.json"),
)

os.makedirs(os.path.dirname(ALERT_LOG), exist_ok=True)

if not os.path.exists(ALERT_LOG):
    with open(ALERT_LOG, "w", encoding="utf-8") as file:
        file.write("")


def read_alerts():
    alerts = []
    if not os.path.exists(ALERT_LOG):
        return alerts

    with open(ALERT_LOG, "r", encoding="utf-8") as file:
        for line in file:
            line = line.strip()
            if not line:
                continue
            try:
                alerts.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    return alerts


@app.route("/")
def index():
    return send_file(os.path.join(os.path.dirname(__file__), "index.html"))


@app.route("/api/alerts")
def api_alerts():
    alerts = read_alerts()
    alerts = sorted(alerts, key=lambda item: item.get("timestamp", ""), reverse=True)

    severities = Counter(alert.get("severity", "UNKNOWN") for alert in alerts)
    sources = Counter(alert.get("src_ip", "Unknown") for alert in alerts)

    summary = {
        "total_alerts": len(alerts),
        "high": severities.get("HIGH", 0),
        "medium": severities.get("MEDIUM", 0),
        "low": severities.get("LOW", 0),
        "alert_sources": len({alert.get("src_ip") for alert in alerts if alert.get("src_ip")}),
        "latest": alerts[0] if alerts else None,
        "source_breakdown": dict(sources.most_common(5)),
        "alerts": alerts[:20],
    }

    return jsonify(summary)


@app.route("/api/port-scan")
def api_port_scan():
    try:
        with open(PORT_SCAN_STATUS_FILE, "r", encoding="utf-8") as file:
            scan_status = json.load(file)
    except (FileNotFoundError, json.JSONDecodeError):
        scan_status = {
            "state": "waiting",
            "target": "127.0.0.1",
            "protocol": "tcp+udp",
            "ports_scanned": 0,
            "ports_total": 131070,
            "open_ports": [],
            "started_at": None,
            "completed_at": None,
            "error": None,
        }
    return jsonify(scan_status)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
