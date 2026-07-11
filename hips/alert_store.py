#!/usr/bin/env python3
"""
HIPS - Stockage structuré des alertes (JSON Lines)
Chaque ligne = un événement JSON, facile à lire pour le dashboard web plus tard.
"""

import json
import os
from datetime import datetime

ALERTS_FILE = os.path.join(os.path.dirname(__file__), "alerts.jsonl")


def save_alert(alert_type, severity, details):
    """
    alert_type : 'file_access', 'exec_suspicious', 'ssh_bruteforce'
    severity   : 'low', 'medium', 'high'
    details    : dict avec les infos spécifiques (ip, comm, file, pid, etc.)
    """
    alert = {
        "timestamp": datetime.now().isoformat(),
        "type": alert_type,
        "severity": severity,
        "details": details,
    }
    with open(ALERTS_FILE, "a") as f:
        f.write(json.dumps(alert) + "\n")
    return alert
