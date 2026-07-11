#!/usr/bin/env python3
"""
HIPS - Dashboard web
Sert une interface de visualisation des alertes stockées dans alerts.jsonl.
Lecture seule : ce script ne modifie jamais alerts.jsonl, il se contente
de le relire à chaque requête (le fichier est déjà géré par hips.py / alert_store.py).
"""

import json
import os
from datetime import datetime

from flask import Flask, jsonify, render_template

app = Flask(__name__)

# alerts.jsonl est attendu au même endroit que hips.py (racine du projet).
# Si tu ranges ce dashboard dans un sous-dossier, ajuste ce chemin.
PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))
ALERTS_FILE = os.path.join(PROJECT_ROOT, "..", "alerts.jsonl")

MAX_ALERTS_RETURNED = 200


def load_alerts(limit=MAX_ALERTS_RETURNED):
    """Lit alerts.jsonl et retourne les N dernières alertes, la plus récente en premier.
    Une ligne JSON invalide (écriture en cours, corruption) est ignorée silencieusement
    plutôt que de faire planter le dashboard.
    """
    if not os.path.exists(ALERTS_FILE):
        return []

    alerts = []
    with open(ALERTS_FILE, "r") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                alerts.append(json.loads(line))
            except json.JSONDecodeError:
                continue

    return list(reversed(alerts[-limit:]))


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/alerts")
def api_alerts():
    alerts = load_alerts()

    stats = {
        "total": len(alerts),
        "high": sum(1 for a in alerts if a.get("severity") == "high"),
        "medium": sum(1 for a in alerts if a.get("severity") == "medium"),
        "low": sum(1 for a in alerts if a.get("severity") == "low"),
    }

    by_type = {}
    for a in alerts:
        t = a.get("type", "inconnu")
        by_type[t] = by_type.get(t, 0) + 1

    return jsonify({
        "alerts": alerts,
        "stats": stats,
        "by_type": by_type,
        "server_time": datetime.now().isoformat(),
    })


if __name__ == "__main__":
    # host=0.0.0.0 pour pouvoir consulter le dashboard depuis Kali si besoin
    # (192.168.174.130 -> http://192.168.174.129:5000)
    app.run(host="0.0.0.0", port=5000, debug=True)
