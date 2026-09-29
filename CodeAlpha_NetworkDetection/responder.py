"""
responder.py
Response mechanisms for detected intrusions.

NOTE: On Windows, firewall blocking requires admin rights.
Run VS Code as Administrator for full functionality.
"""

import platform
import subprocess


class Responder:
    def __init__(self, block_enabled=True):
        self.block_enabled = block_enabled
        self.blocked_ips = set()

    def respond(self, alert):
        """Decide and execute a response based on severity."""
        severity = alert["severity"]
        src_ip = alert["src_ip"]

        if severity == "HIGH" and self.block_enabled and src_ip:
            self._block_ip(src_ip)
        elif severity == "MEDIUM":
            print(f"[RESPONSE] WARNING issued for {src_ip} — {alert['name']}")
        else:
            print(f"[RESPONSE] Logged only — {alert['name']}")

    def _block_ip(self, ip):
        """Block attacker IP using the OS firewall."""
        if ip in self.blocked_ips:
            return  

        os_type = platform.system()
        try:
            if os_type == "Linux":
            
                subprocess.run(["sudo", "ufw", "deny", "from", ip], check=False)
            elif os_type == "Windows":
             
                subprocess.run(
                    ["netsh", "advfirewall", "firewall", "add", "rule",
                     f"name=Block {ip}", "dir=in", "action=block", f"remoteip={ip}"],
                    check=False
                )
            else:
                print(f"[RESPONSE] Auto-block not supported on {os_type}. Manual block needed.")
                return

            self.blocked_ips.add(ip)
            print(f"[RESPONSE] BLOCKED attacker IP: {ip}")
        except Exception as e:
            print(f"[RESPONSE] Failed to block {ip}: {e}")