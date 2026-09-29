# 🛡️ Network Intrusion Detection System (NIDS)

### CodeAlpha Internship — Alpha Task 2

A Windows-oriented **Network Intrusion Detection System (NIDS)** built using **Python, Suricata, Nmap, Flask, and Npcap**.

The system monitors network traffic for suspicious activity, processes Suricata intrusion alerts, performs local port scanning, and displays security information through a live web dashboard.

---

## 🚀 Project Status

**Alpha Task 2 — COMPLETE ✅**

Current version: **IDS / Monitoring Only**

> The current launcher detects and reports suspicious activity but does **not automatically block network traffic**.

---

## 🔍 Features

### 🐊 Suricata Intrusion Detection

* Monitors traffic on the selected network interface.
* Uses custom Suricata signatures from `suricata.rules`.
* Generates intrusion detection events.
* Stores raw events in `suricata-logs/eve.json`.

### 🚨 Live Security Alerts

* Monitors new Suricata alert events.
* Converts alerts into a dashboard-friendly format.
* Stores normalized alerts in:
  `suricata-logs/alerts-live.jsonl`

### 🔎 Local Port Scanning

* Uses Nmap to scan the local computer.
* Scans TCP and UDP ports from `1-65535`.
* Target is restricted to:
  `127.0.0.1`
* Results are stored in:
  `suricata-logs/port-scan.json`

### 🌐 Web Dashboard

The Flask dashboard provides:

* Live security alerts
* Port scan information
* Monitoring status
* Security event information
* API endpoints for dashboard data

Default dashboard:

```text
http://127.0.0.1:5000
```

If port `5000` is unavailable, the launcher attempts ports `5001` through `5009`.

---

## 🏗️ Architecture

```text
                    ┌─────────────────────┐
                    │   suricata_main.py  │
                    └──────────┬──────────┘
                               │
             ┌─────────────────┴─────────────────┐
             │                                   │
             ▼                                   ▼
     ┌───────────────┐                   ┌───────────────┐
     │   Suricata    │                   │     Nmap      │
     │ Traffic IDS   │                   │ Local Scanner │
     └───────┬───────┘                   └───────┬───────┘
             │                                   │
             ▼                                   ▼
     ┌───────────────┐                   ┌───────────────┐
     │   eve.json    │                   │ port-scan.json│
     └───────┬───────┘                   └───────┬───────┘
             │                                   │
             ▼                                   │
     ┌─────────────────┐                         │
     │ Alert Processor │                         │
     └────────┬────────┘                         │
              │                                  │
              ▼                                  ▼
     ┌──────────────────────────────────────────────┐
     │              Flask Dashboard                 │
     │                                                │
     │       Alerts API + Port Scan API              │
     └──────────────────────┬───────────────────────┘
                            │
                            ▼
                     🌐 Web Dashboard
```

---

## 🧰 Technologies Used

| Technology    | Purpose                             |
| ------------- | ----------------------------------- |
| 🐍 Python     | Main application and automation     |
| 🐊 Suricata   | Network intrusion detection         |
| 🔎 Nmap       | Local TCP/UDP port scanning         |
| 🌐 Flask      | Web dashboard and APIs              |
| 🖥️ Npcap     | Windows packet capture              |
| 📄 JSON/JSONL | Security event storage              |
| ⚙️ PowerShell | Windows configuration and execution |

---

## 📁 Project Structure

```text
Network-Intrusion-Detection-System/
│
├── suricata_main.py
├── suricata.rules
├── server.py
├── index.html
├── port_scanner.py
├── detector.py
├── responder.py
├── rules.json
├── requirements.txt
│
└── suricata-logs/
    ├── eve.json
    ├── alerts-live.jsonl
    ├── port-scan.json
    └── suricata.log
```

---

## ⚙️ Requirements

### Operating System

```text
Windows 10 or later
```

### Software

* Python 3.8+
* Suricata
* Npcap
* Nmap
* Administrator privileges may be required for packet capture.

### Python Packages

The required Python packages are listed in:

```text
requirements.txt
```

Install them with:

```powershell
python -m pip install -r requirements.txt
```

---

## 🛠️ Installation

### 1. Clone or Download the Project

Open the project directory in VS Code.

### 2. Create a Virtual Environment

```powershell
py -m venv .venv
```

### 3. Activate the Environment

```powershell
.\.venv\Scripts\Activate.ps1
```

### 4. Install Dependencies

```powershell
python -m pip install -r requirements.txt
```

### 5. Install Suricata

Install Suricata and Npcap on Windows.

Make sure the Suricata executable and configuration file are available.

### 6. Install Nmap

Install Nmap and ensure the Nmap executable is accessible.

---

## ▶️ Running the Project

Open **PowerShell as Administrator** if required by your Npcap/packet-capture configuration.

Run:

```powershell
python suricata_main.py
```

The launcher will:

1. Check Suricata.
2. Check Nmap.
3. Select the network interface.
4. Start Suricata.
5. Start the local Nmap scanner.
6. Process Suricata alerts.
7. Start the Flask dashboard.
8. Display the dashboard URL.

Open:

```text
http://127.0.0.1:5000
```

---

## ⚙️ Configuration

### Custom Suricata Path

```powershell
$env:SURICATA_PATH = "D:\Suricata\suricata.exe"
```

### Custom Suricata Configuration

```powershell
$env:SURICATA_CONFIG = "D:\Suricata\suricata.yaml"
```

### Custom Nmap Path

```powershell
$env:NMAP_PATH = "D:\Nmap\nmap.exe"
```

Then run:

```powershell
python suricata_main.py
```

---

## 🌐 Network Interface

By default, the launcher attempts to select the IPv4 address associated with the default route.

You can specify an interface/address manually:

```powershell
$env:NIDS_INTERFACE = "192.168.1.20"
python suricata_main.py
```

Suricata only receives traffic delivered to the selected host interface.

Monitoring traffic between other devices may require appropriate network visibility such as a switch mirror port or network TAP.

---

## 🔌 Dashboard Port

The default dashboard port is:

```text
5000
```

To use another port:

```powershell
$env:NIDS_DASHBOARD_PORT = "5005"
python suricata_main.py
```

---

## 🧪 Detection Rules

The project includes custom Suricata rules in:

```text
suricata.rules
```

The rules include detection for examples such as:

* TCP SYN port-scan patterns
* Telnet traffic
* SMB connections
* RDP connections
* Connections involving port `4444`
* HTTP requests targeting `/admin.php`

---

## ✅ Testing Suricata Rules

You can validate the rule configuration using:

```powershell
& "C:\Program Files\Suricata\suricata.exe" -T `
  -c "C:\Program Files\Suricata\suricata.yaml" `
  -S ".\suricata.rules" `
  -l ".\suricata-logs"
```

A successful configuration test should indicate that the rules and configuration can be loaded.

---

## 📊 Data Flow

```text
Network Traffic
       │
       ▼
   Suricata
       │
       ▼
  Detection Rules
       │
       ▼
    eve.json
       │
       ▼
 Alert Processor
       │
       ▼
alerts-live.jsonl
       │
       ▼
 Flask API
       │
       ▼
 Web Dashboard
```

At the same time:

```text
Local Computer
      │
      ▼
     Nmap
      │
      ▼
TCP/UDP Port Scan
      │
      ▼
port-scan.json
      │
      ▼
 Flask API
      │
      ▼
 Web Dashboard
```

---

## ⚠️ Current Limitations

The current Alpha version has some limitations:

* ❌ No automatic firewall blocking.
* ❌ `detector.py` is not connected to the main launcher.
* ❌ `responder.py` is not connected to the main launcher.
* ❌ The system is primarily designed for Windows.
* ❌ Suricata visibility depends on the selected network interface.
* ❌ Monitoring other devices requires appropriate network visibility.
* ❌ Local port scanning only targets `127.0.0.1`.

---

## 🔮 Future Improvements

Possible future development:

* 🛡️ Automated response and blocking
* 🔥 Windows Firewall integration
* 🤖 AI-assisted alert analysis
* 📈 Advanced security analytics
* 🔔 Real-time notifications
* 👤 User/device identification
* 📊 Historical security reports
* 🧠 Behavioral anomaly detection
* 🔐 Threat intelligence integration
* 📡 Network-wide monitoring
* 📝 Automated incident reports

---

## 🔐 Security & Ethical Use

This project is intended for **authorized cybersecurity monitoring, learning, research, and defensive security purposes**.

Only capture or analyze network traffic on systems and networks that you **own or have explicit authorization to monitor**.

The included Nmap scanner is restricted to the local machine:

```text
127.0.0.1
```

Do not use this project to monitor or scan systems without permission.

---

## 👨‍💻 Project Information

**Program:** CodeAlpha Internship
**Task:** Alpha Task 2
**Project:** Network Intrusion Detection System
**Domain:** Cybersecurity / Network Security
**Status:** ✅ Completed

---

## 🏆 Learning Outcomes

Through this project, I gained practical experience with:

* Network traffic monitoring
* Intrusion detection systems
* Suricata rule configuration
* Nmap scanning
* Python automation
* Flask web applications
* Security event logging
* Network security fundamentals
* Windows-based cybersecurity tooling

---

### ⭐ CodeAlpha

This project was developed as part of my **CodeAlpha cybersecurity internship journey**.

**Alpha Task 2 — Completed ✅**

#CodeAlpha #CodeAlphaInternship #CyberSecurity #NetworkSecurity #NIDS #Suricata #Nmap #Python #Flask #EthicalHacking

