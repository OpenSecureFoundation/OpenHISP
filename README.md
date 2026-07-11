# HIPS — Host Intrusion Prevention System

Système de détection et de prévention d'intrusion développé sur Linux (Ubuntu),
avec surveillance en temps réel, dashboard web, et actions automatiques de
réponse (blocage IP, kill process).

## Architecture

Deux VMs sur un réseau isolé (VMware, `192.168.174.0/24`) :
- **Ubuntu Desktop** (victime + HIPS) : `192.168.174.129`
- **Kali Linux** (attaquant, tests) : `192.168.174.130`

```
hips-project/
├── hips.py              # Moteur principal (2 threads de surveillance)
├── alert_store.py       # Stockage structuré des alertes (JSON Lines)
├── actions.py           # Actions automatiques (blocage IP, kill process)
├── fake_malware.sh      # Script factice pour tester la détection malware
└── dashboard/
    ├── app.py            # Backend Flask (API + rendu)
    ├── templates/
    │   └── index.html
    └── static/
        ├── style.css
        └── script.js
```

## Fonctionnalités

### Détection (via auditd + logs SSH)
- Accès à `/etc/passwd`, `/etc/shadow`, `/etc/sudoers`
- Exécution de binaires suspects (`nc`, `wget`, `curl`, `python3`)
- Exécution de scripts depuis `/tmp` (emplacement classique pour du code
  malveillant)
- Détection par signature d'un "malware" simulé (`fake_malware.sh`), à des
  fins pédagogiques — aucun payload réel
- Brute force SSH (5 échecs / 60s par IP)

### Filtrage anti-bruit
Une liste de processus de confiance (`TRUSTED_COMMS`) évite les faux positifs
liés à l'activité système normale (sessions GNOME, gestion de paquets APT,
rechargement des règles auditd, etc.), tout en gardant une liste séparée et
plus stricte pour l'accès à `/etc/sudoers`.

### Actions automatiques
- **Blocage IP** : ajout d'une règle `iptables DROP` réelle sur l'IP source
  d'un brute force, avec garde-fous anti auto-DoS (jamais l'IP de la machine
  elle-même) et anti-doublon (vérifie si la règle existe déjà)
- **Kill process** : termine le processus responsable (`SIGKILL`)

### Dashboard web
Interface de visualisation en temps réel (polling 2.5s) : flux d'alertes,
statistiques par sévérité et par type, détails dépliables au clic.

## Installation

```bash
# Dépendances
sudo apt install auditd flask
pip3 install flask --break-system-packages

# Règles auditd — copier dans /etc/audit/rules.d/hips.rules :
-w /etc/passwd -p rwa -k access_passwd
-w /etc/shadow -p rwa -k access_shadow
-w /etc/sudoers -p rwa -k access_sudoers
-w /usr/bin/wget -p x -k exec_suspicious
-w /usr/bin/curl -p x -k exec_suspicious
-w /usr/bin/python3 -p x -k exec_suspicious
-w /bin/nc.openbsd -p x -k exec_suspicious
-w /bin/nc.traditional -p x -k exec_suspicious
-w /usr/bin/ncat -p x -k exec_suspicious
-a always,exit -F arch=b64 -S execve -F dir=/tmp -F key=exec_from_tmp

sudo augenrules --load
sudo systemctl restart auditd
```

## Utilisation

```bash
# Terminal 1 — moteur de détection (doit tourner en permanence)
cd hips-project
sudo python3 hips.py

# Terminal 2 — dashboard web
cd hips-project/dashboard
python3 app.py
# puis ouvrir http://<IP-machine>:5000
```

## Tests

```bash
# Brute force SSH (depuis Kali)
hydra -l test -P password.txt ssh://<IP-victime>

# Détection malware simulé
cp fake_malware.sh /tmp/ && chmod +x /tmp/fake_malware.sh
cd /tmp && ./fake_malware.sh

# Accès fichier sensible
sudo cat /etc/shadow
```

## Limites connues

- `TRUSTED_COMMS` doit être calibrée par machine (les noms de processus
  système varient selon l'environnement) — voir commentaires dans `hips.py`
- `comm=bash` n'est volontairement pas mis en liste de confiance : trop
  générique, blanchir ce nom masquerait l'activité d'un vrai payload lancé
  en shell
- Le blocage iptables agit sur les nouvelles connexions ; des connexions
  déjà établies avant la règle peuvent persister brièvement (non traité par
  `conntrack` dans la version actuelle)
