#!/usr/bin/env python3
"""
HIPS - Moteur principal
Lance en parallèle :
- la surveillance auditd (fichiers sensibles, exécutions suspectes, malware simulé)
- la surveillance SSH (brute force)
Toutes les alertes sont écrites dans alerts.jsonl via alert_store.
"""

import subprocess
import re
import time
import threading
from datetime import datetime
from collections import defaultdict, deque

from alert_store import save_alert
from actions import block_ip, kill_process

AUDIT_LOG = "/var/log/audit/audit.log"
AUTH_LOG = "/var/log/auth.log"
WATCHED_KEYS = {
    "access_shadow", "access_passwd", "access_sudoers",
    "exec_suspicious", "exec_from_tmp",
}

MAX_ATTEMPTS = 5
TIME_WINDOW = 60

# Processus système légitimes qui accèdent normalement à /etc/passwd et /etc/shadow
# (bruit normal du système, pas une menace)
TRUSTED_COMMS = {
    "cron", "sudo", "sshd", "systemd-tmpfile", "systemd", "apport",
    "polkitd", "accounts-daemon", "gdm3", "login", "su", "passwd",
    "unattended-upgr", "update-notifier", "packagekit", "cupsd", "NetworkManager",
    "gdm-session-wor", "gdm-password", "gnome-shell", "unix_chkpwd",
    "nano", "gpgv", "pkexec", "pool-org.gnome.", "gnome-session-b",
    "package-data-do", "apt", "apt-get", "dpkg", "dpkg-preconfigu",
    "tar", "perl", "mandb", "http",
}

# Liste dédiée et plus stricte pour /etc/sudoers : c'est le fichier qui définit
# qui a les droits root, donc on ne fait confiance qu'à sudo/visudo eux-mêmes.
TRUSTED_COMMS_SUDOERS = {"sudo", "visudo"}

# Signatures de "malware" simulé : noms de comm considérés comme confirmés
# malveillants si on les voit s'exécuter. À adapter si tu renommes le script
# de test (fake_malware.sh -> comm tronqué à 15 caractères par le kernel).
MALWARE_SIGNATURES = {"fake_malware.sh", "fake_malware"}

# ---------- MODULE 1 : fichiers sensibles + exécutions suspectes ----------

def get_event_id(line):
    m = re.search(r'audit\(([\d.]+:\d+)\)', line)
    return m.group(1) if m else None


def parse_audit_line(line):
    event = {}
    for field, pattern in [
        ('key', r'key="([^"]+)"'),
        ('comm', r'comm="([^"]+)"'),
        ('file', r'name="([^"]+)"'),
        ('auid', r'auid=(\d+)'),
        ('pid', r'\bpid=(\d+)'),
    ]:
        m = re.search(pattern, line)
        if m:
            event[field] = m.group(1)
    return event


def watch_auditd():
    process = subprocess.Popen(
        ["sudo", "tail", "-F", "-n", "0", AUDIT_LOG],
        stdout=subprocess.PIPE, text=True
    )
    print(f"[HIPS] Surveillance auditd démarrée ({AUDIT_LOG})")

    buffer = defaultdict(dict)

    for line in process.stdout:
        line = line.strip()
        if not line:
            continue

        # Ignore les événements CONFIG_CHANGE : ce sont des accusés de
        # rechargement de règles (auditctl -R / augenrules / restart auditd),
        # pas de vraies exécutions ni de vrais accès fichiers. Sans ce filtre,
        # chaque rechargement génère une fausse alerte par règle définie.
        if 'type=CONFIG_CHANGE' in line:
            continue

        eid = get_event_id(line)
        if not eid:
            continue

        buffer[eid].update(parse_audit_line(line))
        event = buffer[eid]

        if event.get('key') in WATCHED_KEYS and event.get('comm'):
            key = event['key']
            comm = event.get('comm', '?')
            pid = event.get('pid')

            # Filtre anti-bruit spécifique à sudoers (liste plus stricte)
            if key == "access_sudoers" and comm in TRUSTED_COMMS_SUDOERS:
                del buffer[eid]
                continue

            # Filtre anti-bruit générique passwd/shadow
            if key in ("access_passwd", "access_shadow") and comm in TRUSTED_COMMS:
                del buffer[eid]
                continue

            # Détection prioritaire : signature de malware simulé connue
            if comm in MALWARE_SIGNATURES:
                alert = save_alert(
                    alert_type="malware_detected",
                    severity="high",
                    details={
                        "comm": comm,
                        "file": event.get("file", "-"),
                        "auid": event.get("auid", "?"),
                        "pid": pid or "?",
                        "trigger_key": key,
                    }
                )
                print(f"[{alert['timestamp'][11:19]}] 🚨 MALWARE DÉTECTÉ -> "
                      f"comm={comm} pid={pid}")
                if pid:
                    kill_process(pid, reason=f"exécution détectée : {comm} "
                                              f"(signature malware simulé)")
                del buffer[eid]
                continue

            # Exécution générique depuis /tmp, sans signature connue :
            # suspect (emplacement classique pour du code malveillant) mais
            # pas confirmé -> alerte informative, pas d'action automatique
            # (évite de tuer un script légitime par excès de zèle).
            if key == "exec_from_tmp":
                alert = save_alert(
                    alert_type="exec_from_tmp",
                    severity="medium",
                    details={
                        "comm": comm,
                        "file": event.get("file", "-"),
                        "auid": event.get("auid", "?"),
                        "pid": pid or "?",
                    }
                )
                print(f"[{alert['timestamp'][11:19]}] ALERTE [exec_from_tmp] comm={comm}")
                del buffer[eid]
                continue

            severity = "high" if key == "access_shadow" else "medium"

            alert = save_alert(
                alert_type=key,
                severity=severity,
                details={
                    "comm": event.get("comm", "?"),
                    "file": event.get("file", "-"),
                    "auid": event.get("auid", "?"),
                    "pid": event.get("pid", "?"),
                }
            )
            print(f"[{alert['timestamp'][11:19]}] ALERTE [{key}] "
                  f"comm={event.get('comm')} file={event.get('file', '-')}")

            del buffer[eid]

        if len(buffer) > 500:
            del buffer[next(iter(buffer))]

# ---------- MODULE 2 : brute force SSH ----------

FAILED_PATTERN = re.compile(
    r'sshd\[(\d+)\]:\s+Failed password for (invalid user )?(\S+) from (\d+\.\d+\.\d+\.\d+) port (\d+)'
)


def watch_ssh():
    process = subprocess.Popen(
        ["sudo", "tail", "-F", "-n", "0", AUTH_LOG],
        stdout=subprocess.PIPE, text=True
    )
    print(f"[HIPS] Surveillance SSH démarrée ({AUTH_LOG})")

    attempts_by_ip = defaultdict(deque)
    # dict IP -> timestamp de la dernière alerte, au lieu d'un set() permanent :
    # une IP peut redéclencher une alerte après expiration du cooldown, plutôt
    # que d'être "immunisée" à vie pour la durée du process hips.py.
    last_alerted_at = {}

    for line in process.stdout:
        line = line.strip()
        match = FAILED_PATTERN.search(line)
        if not match:
            continue

        sshd_pid = match.group(1)
        user = match.group(3)
        ip = match.group(4)

        now = time.time()
        dq = attempts_by_ip[ip]
        dq.append(now)
        while dq and now - dq[0] > TIME_WINDOW:
            dq.popleft()

        nb_attempts = len(dq)
        print(f"[{datetime.now().strftime('%H:%M:%S')}] Échec SSH -> "
              f"user={user} ip={ip} (tentative {nb_attempts})")

        if nb_attempts >= MAX_ATTEMPTS and (
            ip not in last_alerted_at or now - last_alerted_at[ip] > TIME_WINDOW
        ):
            last_alerted_at[ip] = now

            alert = save_alert(
                alert_type="ssh_bruteforce",
                severity="high",
                details={"ip": ip, "user": user, "attempts": nb_attempts, "pid": sshd_pid}
            )
            print(f"[{alert['timestamp'][11:19]}] 🚨 BRUTE FORCE DÉTECTÉ -> IP={ip}")

            block_ip(ip)
            kill_process(sshd_pid, reason=f"brute force SSH depuis {ip}")


# ---------- LANCEMENT ----------

if __name__ == "__main__":
    print(f"[{datetime.now()}] Démarrage du moteur HIPS\n")

    t1 = threading.Thread(target=watch_auditd, daemon=True)
    t2 = threading.Thread(target=watch_ssh, daemon=True)
    t1.start()
    t2.start()

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\nArrêt du HIPS.")
