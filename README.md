📡 Scapy Network Packet Sniffer & Analyzer
An interactive Python-based network packet sniffer and protocol analyzer built with Scapy. Designed for educational purposes, security analysis, and network debugging, this tool captures live traffic and dissects packets layer-by-layer—from Ethernet frames up to application payloads.

⚡ Key Features
🔍 Deep Layer-by-Layer Packet Dissection

Link Layer: Ethernet II, ARP

Network Layer: IPv4, IPv6, ICMP

Transport Layer: TCP (with flags & port parsing), UDP

🧠 Smart Protocol Analyzers

DNS: Decodes live DNS queries and responses.

HTTP: Extracts plain-text HTTP requests, including Host:, User-Agent:, and sensitive headers like Authorization:.

Payload Dump: Renders raw payloads as Hex + ASCII dumps (similar to tcpdump -X).

📊 Live Traffic Statistics

Real-time metrics on total packets and bandwidth usage.

Protocol distribution breakdowns.

Identifies Top Talkers and heavy network flows.

⚙️ Advanced Capture Controls

Native Kernel-level BPF Filters (e.g., tcp port 80 or udp port 53).

Configurable capture counts and multi-interface support.

📋 Prerequisites
[!CAUTION]
Raw packet capturing requires elevated permissions. Always run this tool with administrative/root privileges.

Python: 3.8+

Root / Administrator privileges

🚀 Getting Started
1. Install Dependencies
Bash
pip install scapy
2. Run the Sniffer
Bash
# On Linux / macOS
sudo python3 sniffer.py

# On Windows (Run Command Prompt as Administrator)
python sniffer.py
📄 License
This project is licensed under the MIT License - see the LICENSE file for details.

⚠️ Disclaimer
This tool is intended strictly for educational purposes and authorized network testing. Intercepting network traffic without prior consent may violate local and international laws.
