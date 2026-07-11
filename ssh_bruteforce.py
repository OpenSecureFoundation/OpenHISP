#!/usr/bin/env python3
"""
HIPS - Module de détection brute force SSH + actions automatiques
"""

import subprocess
import re
import time
from datetime import datetime
from collections import defaultdict, deque
from actions import block_ip, kill_process

AUTH_LOG = "/var/log/auth.log"

MAX_ATTEMPTS = 5
TIME_WINDOW = 60

attempts_by_ip = defaultdict(deque)
already_alerted = set()

# Capture aussi le PID du processus sshd responsable de la tentative
FAILED_PATTERN = re.compile(
    r'sshd\[(\d+)\]:\s+Failed password for (invalid user )?(\S+) from (\d+\.\d+\.\d+\.\d+) port (\d+)'
)


def check_bruteforce(ip):
    now = time.time()
    dq = attempts_by_ip[ip]
    dq.append(now)
    while dq and now - dq[0] > TIME_WINDOW:
        dq.popleft()
    return len(dq) >= MAX_ATTEMPTS


def follow_log():
    process = subprocess.Popen(
        ["sudo", "tail", "-F", "-n", "0", AUTH_LOG],
        stdout=subprocess.PIPE,
        text=True
    )

    print(f"[{datetime.now()}] Surveillance brute force SSH démarrée...")
    print(f"Seuil : {MAX_ATTEMPTS} échecs en {TIME_WINDOW}s\n")

    for line in process.stdout:
        line = line.strip()
        match = FAILED_PATTERN.search(line)
        if not match:
            continue

        sshd_pid = match.group(1)
        user = match.group(3)
        ip = match.group(4)
        timestamp = datetime.now().strftime("%H:%M:%S")

        nb_attempts = len(attempts_by_ip[ip]) + 1
        print(f"[{timestamp}] Échec SSH -> user={user} ip={ip} pid={sshd_pid} (tentative {nb_attempts})")

        if check_bruteforce(ip):
            if ip not in already_alerted:
                print(f"\n[{timestamp}] 🚨 BRUTE FORCE DÉTECTÉ -> IP={ip} "
                      f"({MAX_ATTEMPTS}+ échecs en {TIME_WINDOW}s)")
                already_alerted.add(ip)

                # Actions automatiques
                block_ip(ip)
                kill_process(sshd_pid, reason=f"brute force SSH depuis {ip}")
                print()


if __name__ == "__main__":
    try:
        follow_log()
    except KeyboardInterrupt:
        print("\nArrêt de la surveillance.")
