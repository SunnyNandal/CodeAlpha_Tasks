"""
detector.py
Detection engine: analyzes packets and matches them against rules.
"""

import time
import json
import os
from collections import defaultdict, deque

RULES_FILE = os.path.join(os.path.dirname(__file__), "rules.json")
ALERT_LOG = os.path.join(os.path.dirname(__file__), "alerts.log")


def load_rules():
    """Load detection rules from rules.json"""
    with open(RULES_FILE, "r") as f:
        data = json.load(f)
    return data["rules"]


class DetectionEngine:
    def __init__(self):
        self.rules = load_rules()
        # Track connection attempts per source IP (for port scan detection)
        self.tcp_tracker = defaultdict(deque)
        # Track ICMP destinations per source IP (for ping sweep detection)
        self.icmp_tracker = defaultdict(set)

    def check_rules(self, packet_info):
        """Run all rules against a packet. Returns list of alerts."""
        alerts = []

        for rule in self.rules:
            rule_protocol = rule["protocol"].upper()
            packet_protocol = packet_info["protocol"].upper()
            condition = rule["condition"]

            if rule_protocol != packet_protocol:
                continue

            # ---- Rule 1: Port Scan Detection ----
            if condition == "port_scan":
                src = packet_info["src_ip"]
                dst_port = packet_info.get("dst_port")
                now = time.time()
                window = rule["window_seconds"]

                if src and dst_port is not None:
                    self.tcp_tracker[src].append((now, dst_port))
                    # Remove entries older than the time window
                    while self.tcp_tracker[src] and self.tcp_tracker[src][0][0] < now - window:
                        self.tcp_tracker[src].popleft()

                    unique_ports = {port for _, port in self.tcp_tracker[src]}
                    if len(unique_ports) >= rule["threshold"]:
                        alerts.append(self._make_alert(
                            rule, packet_info,
                            f"{len(unique_ports)} unique ports hit in {window}s"
                        ))
                        self.tcp_tracker[src].clear()

            # ---- Rule 2: Ping Sweep Detection ----
            elif condition == "ping_sweep":
                src = packet_info["src_ip"]
                dst = packet_info.get("dst_ip")
                now = time.time()
                window = rule["window_seconds"]

                if src and dst:
                    self.icmp_tracker[src].add((now, dst))
                    recent = {d for t, d in self.icmp_tracker[src] if t >= now - window}
                    if len(recent) >= rule["threshold"]:
                        alerts.append(self._make_alert(
                            rule, packet_info,
                            f"pinged {len(recent)} hosts in {window}s"
                        ))
                        self.icmp_tracker[src].clear()

            # ---- Rule 3: Suspicious Port Access ----
            elif condition == "suspicious_port":
                dst_port = packet_info.get("dst_port")
                if dst_port in rule.get("ports", []):
                    alerts.append(self._make_alert(
                        rule, packet_info,
                        f"traffic to suspicious port {dst_port}"
                    ))

            # ---- Rule 4: HTTP Keyword Match ----
            elif condition == "http_keyword":
                payload = packet_info.get("payload", "").lower()
                for keyword in rule.get("keywords", []):
                    if keyword.lower() in payload:
                        alerts.append(self._make_alert(
                            rule, packet_info,
                            f"HTTP payload contains '{keyword}'"
                        ))
                        break

        return alerts

    def _make_alert(self, rule, packet_info, detail):
        alert = {
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            "rule_id": rule["id"],
            "name": rule["name"],
            "severity": rule["severity"],
            "src_ip": packet_info["src_ip"],
            "dst_ip": packet_info["dst_ip"],
            "dst_port": packet_info.get("dst_port"),
            "detail": detail,
        }
        self._log_alert(alert)
        return alert

    def _log_alert(self, alert):
        """Write alert to alerts.log"""
        with open(ALERT_LOG, "a") as f:
            f.write(json.dumps(alert) + "\n")