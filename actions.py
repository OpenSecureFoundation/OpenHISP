#!/usr/bin/env python3
"""
HIPS - Module d'actions automatiques
- block_ip() : blocage RÉEL via iptables (règle DROP sur l'IP source)
- kill_process() : kill réel du PID donné
"""
import os
import signal
import socket
import subprocess
from datetime import datetime

ACTIONS_LOG = "actions.log"

# IPs qu'on ne bloquera jamais, quoi qu'il arrive, pour éviter de se couper
# soi-même du réseau ou de la machine (auto-DoS).
NEVER_BLOCK = {"127.0.0.1", "0.0.0.0", "::1"}


def log_action(message):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    line = f"[{timestamp}] {message}"
    print(line)
    with open(ACTIONS_LOG, "a") as f:
        f.write(line + "\n")


def get_local_ips():
    """Retourne l'ensemble des IPs locales de la machine, pour éviter de se bloquer soi-même."""
    ips = set(NEVER_BLOCK)
    try:
        hostname = socket.gethostname()
        ips.add(socket.gethostbyname(hostname))
    except Exception:
        pass
    try:
        # Astuce classique : ouvrir un socket UDP "à blanc" vers l'extérieur
        # révèle l'IP locale utilisée pour sortir, sans envoyer de vrai paquet.
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ips.add(s.getsockname()[0])
        s.close()
    except Exception:
        pass
    return ips


def _rule_exists(ip):
    """Vérifie si une règle DROP existe déjà pour cette IP (-C = check, ne modifie rien)."""
    result = subprocess.run(
        ["sudo", "iptables", "-C", "INPUT", "-s", ip, "-j", "DROP"],
        capture_output=True, text=True
    )
    return result.returncode == 0


def block_ip(ip):
    """Blocage RÉEL : ajoute une règle iptables DROP pour l'IP donnée.
    Ne bloque jamais une IP locale/de la machine elle-même, et évite les doublons.
    """
    if ip in get_local_ips():
        log_action(f"⛔ Blocage IP {ip} REFUSÉ — c'est une IP locale de cette machine "
                    f"(protection anti auto-DoS)")
        return False

    if _rule_exists(ip):
        log_action(f"ℹ️  IP {ip} déjà bloquée (règle iptables existante), rien à faire")
        return True

    result = subprocess.run(
        ["sudo", "iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"],
        capture_output=True, text=True
    )

    if result.returncode == 0:
        log_action(f"🛡️  IP {ip} bloquée avec succès (règle iptables DROP ajoutée)")
        return True
    else:
        log_action(f"❌ Échec du blocage de l'IP {ip} — {result.stderr.strip()}")
        return False


def unblock_ip(ip):
    """Retire la règle DROP pour une IP donnée (utile pour les tests, ou lever un blocage manuel)."""
    result = subprocess.run(
        ["sudo", "iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"],
        capture_output=True, text=True
    )
    if result.returncode == 0:
        log_action(f"✅ IP {ip} débloquée (règle iptables retirée)")
        return True
    else:
        log_action(f"❌ Échec du déblocage de l'IP {ip} — {result.stderr.strip()}")
        return False


def kill_process(pid, reason=""):
    """Kill RÉEL du processus donné par son PID."""
    try:
        pid = int(pid)
        os.kill(pid, signal.SIGKILL)
        log_action(f"💀 Processus PID={pid} tué avec succès ({reason})")
        return True
    except ProcessLookupError:
        log_action(f"⚠️  PID={pid} déjà terminé (processus non trouvé) ({reason})")
        return False
    except PermissionError:
        log_action(f"❌ Permission refusée pour tuer PID={pid} — lance le script avec sudo")
        return False
    except Exception as e:
        log_action(f"❌ Erreur lors du kill de PID={pid}: {e}")
        return False
