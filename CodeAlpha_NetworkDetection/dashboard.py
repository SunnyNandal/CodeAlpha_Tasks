import json
import os
import time
from collections import Counter

import matplotlib.pyplot as plt

ALERT_LOG = os.path.join(os.path.dirname(__file__), "alerts.log")


def load_alerts():
    alerts = []
    if os.path.exists(ALERT_LOG):
        with open(ALERT_LOG, "r") as f:
            for line in f:
                try:
                    alerts.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
    return alerts


def show_dashboard():
    plt.ion() 
    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(12, 5))
    fig.suptitle("NIDS Attack Dashboard")

    while True:
        alerts = load_alerts()
        ax1.clear()
        ax2.clear()

        if alerts:
            
            names = Counter(a["name"] for a in alerts)
            ax1.bar(names.keys(), names.values(), color="crimson")
            ax1.set_title("Attacks by Type")
            ax1.tick_params(axis="x", rotation=30)

            
            ips = Counter(a["src_ip"] for a in alerts)
            ax2.bar(ips.keys(), ips.values(), color="orange")
            ax2.set_title("Attacks by Source IP")
            ax2.tick_params(axis="x", rotation=30)
        else:
            ax1.text(0.5, 0.5, "No alerts yet...", ha="center")
            ax2.text(0.5, 0.5, "No alerts yet...", ha="center")

        plt.tight_layout()
        plt.pause(5)  


if __name__ == "__main__":
    show_dashboard()