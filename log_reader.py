#!/usr/bin/env python3
"""
HIPS - Module de collecte de logs (v2 - avec corrélation d'événements)
"""

import subprocess
import re
from datetime import datetime
from collections import defaultdict

AUDIT_LOG = "/var/log/audit/audit.log"
WATCHED_KEYS = {"access_shadow", "access_passwd", "access_sudoers", "exec_suspicious"}

def get_event_id(line):
    """Extrait l'ID unique de l'événement, ex: 1783511071.438:399"""
    m = re.search(r'audit\(([\d.]+:\d+)\)', line)
    return m.group(1) if m else None

def parse_line(line):
    event = {}
    for field, pattern in [
        ('key', r'key="([^"]+)"'),
        ('comm', r'comm="([^"]+)"'),
        ('file', r'name="([^"]+)"'),
        ('exe', r'exe="([^"]+)"'),
        ('auid', r'auid=(\d+)'),
        ('pid', r'\bpid=(\d+)'),
    ]:
        m = re.search(pattern, line)
        if m:
            event[field] = m.group(1)
    return event

def follow_log():
    process = subprocess.Popen(
        ["sudo", "tail", "-F", "-n", "0", AUDIT_LOG],
        stdout=subprocess.PIPE,
        text=True
    )

    print(f"[{datetime.now()}] Surveillance de {AUDIT_LOG} démarrée...\n")

    buffer = defaultdict(dict)  # regroupe les lignes par event_id

    for line in process.stdout:
        line = line.strip()
        if not line:
            continue

        eid = get_event_id(line)
        if not eid:
            continue

        parsed = parse_line(line)
        buffer[eid].update(parsed)

        # Une fois qu'on a une clé pertinente ET assez d'infos, on émet l'alerte
        event = buffer[eid]
        if event.get('key') in WATCHED_KEYS and event.get('comm'):
            timestamp = datetime.now().strftime("%H:%M:%S")
            print(f"[{timestamp}] ALERTE -> "
                  f"key={event.get('key')} "
                  f"comm={event.get('comm', '?')} "
                  f"file={event.get('file', '-')} "
                  f"auid={event.get('auid', '?')} "
                  f"pid={event.get('pid', '?')}")
            del buffer[eid]  # évite de ré-alerter sur le même événement

        # Nettoyage mémoire basique : évite que le buffer grossisse indéfiniment
        if len(buffer) > 500:
            oldest = next(iter(buffer))
            del buffer[oldest]


if __name__ == "__main__":
    try:
        follow_log()
    except KeyboardInterrupt:
        print("\nArrêt de la surveillance.")
