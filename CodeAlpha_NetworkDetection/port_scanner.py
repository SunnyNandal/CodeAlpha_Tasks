"""Run real Nmap TCP and UDP scans against the local host."""

import json
import subprocess
import time
import xml.etree.ElementTree as ET
from datetime import datetime
from pathlib import Path

TARGET = "127.0.0.1"
PORT_COUNT = 65535
TOTAL_CHECKS = PORT_COUNT * 2


def _timestamp():
    return datetime.now().astimezone().isoformat(timespec="seconds")


def _write_status(status_path, status):
    temporary_path = status_path.with_suffix(".json.tmp")
    temporary_path.write_text(json.dumps(status), encoding="utf-8")
    temporary_path.replace(status_path)


def scan_local_ports(nmap_path, timeout_seconds=900):
    """Scan every TCP and UDP port on loopback and return actual open ports."""
    started_at = time.monotonic()
    result = subprocess.run(
        [
            str(nmap_path),
            "-n",
            "-Pn",
            "-sT",
            "-sU",
            "-T4",
            "--max-retries",
            "1",
            "-p",
            "T:1-65535,U:1-65535",
            "--open",
            "-oX",
            "-",
            TARGET,
        ],
        check=True,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=timeout_seconds,
    )
    document = ET.fromstring(result.stdout)
    open_ports = []

    for port_element in document.findall(".//ports/port"):
        state_element = port_element.find("state")
        if state_element is None or state_element.get("state") != "open":
            continue

        service_element = port_element.find("service")
        open_ports.append({
            "port": int(port_element.get("portid", "0")),
            "protocol": port_element.get("protocol", "tcp"),
            "service": service_element.get("name", "unknown") if service_element is not None else "unknown",
        })

    return {
        "state": "complete",
        "target": TARGET,
        "protocol": "tcp+udp",
        "ports_scanned": TOTAL_CHECKS,
        "ports_total": TOTAL_CHECKS,
        "open_ports": open_ports,
        "started_at": _timestamp(),
        "duration_seconds": round(time.monotonic() - started_at, 2),
        "error": None,
    }


def run_scan_loop(nmap_path, status_path):
    """Continuously repeat full localhost scans and publish their results."""
    while True:
        started_at = _timestamp()
        try:
            previous_status = json.loads(status_path.read_text(encoding="utf-8"))
        except (FileNotFoundError, json.JSONDecodeError):
            previous_status = {}
        if previous_status.get("state") != "complete":
            previous_status = {}

        _write_status(status_path, {
            "state": "scanning",
            "target": TARGET,
            "protocol": "tcp+udp",
            "ports_scanned": 0,
            "ports_total": TOTAL_CHECKS,
            "open_ports": previous_status.get("open_ports", []),
            "started_at": started_at,
            "completed_at": previous_status.get("completed_at"),
            "duration_seconds": previous_status.get("duration_seconds"),
            "error": None,
        })

        try:
            status = scan_local_ports(nmap_path)
            status["started_at"] = started_at
        except (OSError, subprocess.SubprocessError, ET.ParseError) as exc:
            status = {
                "state": "error",
                "target": TARGET,
                "protocol": "tcp+udp",
                "ports_scanned": TOTAL_CHECKS,
                "ports_total": TOTAL_CHECKS,
                "open_ports": [],
                "started_at": started_at,
                "duration_seconds": None,
                "error": str(exc),
            }

        status["completed_at"] = _timestamp()
        _write_status(status_path, status)

