

import argparse
import sys
from datetime import datetime
from collections import Counter
from threading import Lock

try:
    from scapy.all import (
        sniff, IP, IPv6, TCP, UDP, ICMP,
        DNS, DNSQR, Raw, ARP, conf
    )
except ImportError:
    sys.exit("[!] Scapy not installed. Run: pip install scapy")


stats_lock = Lock()
stats = {
    "total": 0,
    "protocols": Counter(),   
    "hosts": Counter(),       
    "bytes": 0,
}


def update_stats(proto, src, dst, size):
    with stats_lock:
        stats["total"] += 1
        stats["protocols"][proto] += 1
        stats["hosts"][(src, dst)] += 1
        stats["bytes"] += size


def print_stats():
    with stats_lock:
        print("\n" + "=" * 60)
        print(f" PACKETS CAPTURED: {stats['total']}  |  BYTES: {stats['bytes']}")
        print(f" Protocols: {dict(stats['protocols'])}")
        top = stats["hosts"].most_common(5)
        print(" Top flows:")
        for (src, dst), count in top:
            print(f"   {src} -> {dst}: {count} packets")
        print("=" * 60 + "\n")


def ascii_dump(data: bytes, width: int = 16) -> str:
    """Hex + ASCII dump of raw payload."""
    lines = []
    for i in range(0, len(data), width):
        chunk = data[i:i + width]
        hex_part = " ".join(f"{b:02x}" for b in chunk)
        ascii_part = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        lines.append(f"    {i:04x}  {hex_part:<{width * 3}} {ascii_part}")
    return "\n".join(lines)


def get_payload(packet) -> bytes:
    if packet.haslayer(Raw):
        return bytes(packet[Raw].load)
    return b""


def decode_payload(payload: bytes) -> str:
    """Try to decode common application-layer payloads."""
    try:
        text = payload.decode("utf-8", errors="replace")
    except Exception:
        return "<binary>"
    return text


def analyze_layers(packet):
    """Extract deep info for interesting protocols."""
    info = []

    
    if packet.haslayer(DNS):
        dns = packet[DNS]
        qr = "Response" if dns.qr == 1 else "Query"
        if packet.haslayer(DNSQR):
            qname = packet[DNSQR].qname.decode(errors="replace").rstrip(".")
            info.append(f"DNS {qr}: {qname} (type={dns.qd.qtype})")

    
    if packet.haslayer(TCP) and get_payload(packet):
        payload = get_payload(packet)
        if payload.startswith((b"GET ", b"POST ", b"HTTP/", b"PUT ", b"DELETE ")):
            first_line = payload.split(b"\r\n", 1)[0].decode(errors="replace")
            info.append(f"HTTP: {first_line}")
        # Basic auth or interesting HTTP headers
        for keyword in (b"Authorization:", b"User-Agent:", b"Host:"):
            if keyword.lower() in payload.lower():
                for line in payload.split(b"\r\n"):
                    if line.lower().startswith(keyword.lower()):
                        info.append(f"HTTP Header: {line.decode(errors='replace')}")
                        break

    # ---- ICMP ----
    if packet.haslayer(ICMP):
        info.append(f"ICMP type={packet[ICMP].type} code={packet[ICMP].code}")

    # ---- TCP flags ----
    if packet.haslayer(TCP):
        flags = str(packet[TCP].flags)
        info.append(f"TCP flags=[{flags}] seq={packet[TCP].seq} win={packet[TCP].window}")

    # ---- Raw payload ----
    payload = get_payload(packet)
    if payload:
        printable = decode_payload(payload[:200]).replace("\n", " | ").replace("\r", "")
        info.append(f"Payload ({len(payload)} bytes): {printable}")
        if args.hexdump and len(payload) <= args.hexdump:
            info.append("Hex dump:\n" + ascii_dump(payload))

    return info


def process_packet(packet):
    """Callback for every captured packet."""
    timestamp = datetime.now().strftime("%H:%M:%S.%f")[:-3]

    # ---- Link layer: ARP ----
    if packet.haslayer(ARP):
        arp = packet[ARP]
        op = "request" if arp.op == 1 else "reply"
        print(f"[{timestamp}] ARP  {op}: who-has/tell {arp.psrc} -> {arp.pdst}")
        update_stats("ARP", arp.psrc, arp.pdst, len(packet))
        return

    # ---- IPv4 ----
    if packet.haslayer(IP):
        ip = packet[IP]
        src, dst = ip.src, ip.dst
    # ---- IPv6 ----
    elif packet.haslayer(IPv6):
        ip = packet[IPv6]
        src, dst = ip.src, ip.dst
    else:
        return

    # ---- Transport layer ----
    if packet.haslayer(TCP):
        proto = "TCP"
        details = f"{src}:{packet[TCP].sport} -> {dst}:{packet[TCP].dport}"
    elif packet.haslayer(UDP):
        proto = "UDP"
        details = f"{src}:{packet[UDP].sport} -> {dst}:{packet[UDP].dport}"
    elif packet.haslayer(ICMP) or packet.haslayer("ICMPv6"):
        proto = "ICMP"
        details = f"{src} -> {dst}"
    else:
        proto = "IP-OTHER"
        details = f"{src} -> {dst}"

    update_stats(proto, src, dst, len(packet))

    print(f"[{timestamp}] {proto:<5} {details} len={len(packet)}")

    # ---- Deep analysis ----
    for line in analyze_layers(packet):
        print(f"           └─ {line}")


def main():
    global args
    parser = argparse.ArgumentParser(description="Scapy Packet Sniffer & Analyzer")
    parser.add_argument("-i", "--interface", default=None,
                        help="Interface to sniff on (default: all/active)")
    parser.add_argument("-c", "--count", type=int, default=0,
                        help="Number of packets to capture (0 = infinite)")
    parser.add_argument("-f", "--filter", default="ip or arp",
                        help="BPF filter, e.g. 'tcp port 80' or 'udp'")
    parser.add_argument("--hexdump", type=int, default=0, metavar="N",
                        help="Hex-dump payloads up to N bytes")
    parser.add_argument("-s", "--stats", type=int, default=50, metavar="N",
                        help="Print stats every N packets (default 50)")
    args = parser.parse_args()

    # --- List interfaces if none given ---
    if args.interface is None:
        print("[*] Available interfaces:")
        for i, iface in enumerate(conf.ifaces.values()):
            print(f"    [{i}] {iface.name}  ({getattr(iface, 'ip', '?')})")
        args.interface = None  # sniff on default

    print(f"[*] Sniffing on {args.interface or 'default interface'} "
          f"with filter '{args.filter}' — Ctrl+C to stop\n")

    packets_seen = [0]

    def counter_hook(packet):
        packets_seen[0] += 1
        process_packet(packet)
        if args.stats and packets_seen[0] % args.stats == 0:
            print_stats()

    try:
        sniff(
            iface=args.interface,
            filter=args.filter,
            prn=counter_hook,
            count=args.count or 0,
            store=False,
        )
    except KeyboardInterrupt:
        pass
    except PermissionError:
        sys.exit("[!] Root privileges required. Try: sudo python3 sniffer.py")

    print_stats()
    print("[*] Capture stopped.")


if __name__ == "__main__":
    main()