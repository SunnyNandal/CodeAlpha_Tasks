# Suricata IDS Setup

The project uses Suricata for live packet capture and signature detection. On this Windows machine, Suricata 7.0.10 and the Npcap driver are installed. The launcher opens the dashboard on the first available port starting at 5000.

## Run

Open PowerShell as Administrator in the project folder and run:

```powershell
python suricata_main.py
```

The app starts Suricata on the default routed IPv4 interface, opens the dashboard, and forwards only new Suricata alert events to `suricata-logs/alerts-live.jsonl`. That session feed starts empty each run; older `alerts.log` history is preserved and is not shown as current data. Raw Suricata events are written to `suricata-logs/eve.json`. This is IDS-only; it does not block traffic.

Nmap continuously repeats real TCP connect and UDP scans of ports `1-65535` on `127.0.0.1`, starting another pass as soon as the previous pass completes. A complete pass checks 65,535 ports for each protocol and may take longer for UDP. The dashboard's port chart and open-port table use Nmap's XML results and retain the previous results during each pass. Only loopback is scanned; no other computer is probed. Set `NMAP_PATH` if `nmap.exe` is installed elsewhere.

To choose a different interface, set Suricata's interface IP or device name before starting:

```powershell
$env:NIDS_INTERFACE = "192.168.1.20"
python main.py
```

To use a non-default Suricata installation or configuration:

```powershell
$env:SURICATA_PATH = "D:\Suricata\suricata.exe"
$env:SURICATA_CONFIG = "D:\Suricata\suricata.yaml"
python main.py
```

## Local Signatures

The project loads only `suricata.rules` for detection. It includes signatures for TCP SYN port scans, Telnet/SMB/RDP/high-risk service access, and `/admin.php` HTTP requests. Update and validate the rules with:

```powershell
& "C:\Program Files\Suricata\suricata.exe" -T `
  -c "C:\Program Files\Suricata\suricata.yaml" `
  -S ".\suricata.rules" `
  -l ".\suricata-logs"
```

Capture sees traffic delivered to the selected host interface. To monitor other devices on a network, configure a switch mirror port or network TAP and attach a supported capture interface.
