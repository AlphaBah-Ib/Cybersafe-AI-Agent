# Cybersafe-AI Agent

Agent multi-plateforme (**Linux** + **Windows**) qui collecte les événements de sécurité système et les envoie au backend Cybersafe-AI pour détection, analyse et réponse SOC.

[![Build Windows](https://github.com/AlphaBah-Ib/Cybersafe-AI-Agent/actions/workflows/build-windows.yml/badge.svg)](https://github.com/AlphaBah-Ib/Cybersafe-AI-Agent/actions/workflows/build-windows.yml)

---

## Plateformes supportées

| OS | Source de logs | Statut | Documentation |
|---|---|---|---|
| **Linux** (Ubuntu, Debian, RHEL, Rocky, etc.) | `/var/log/*.log` (auth.log, syslog, nginx, ...) | Production | Voir ci-dessous |
| **Windows** (10, 11, Server 2019, 2022) | Windows Event Log (Security, System, PowerShell, Defender, ...) | Phase 2 SOC-200 | [`packaging/windows/README-Windows.md`](packaging/windows/README-Windows.md) |
| **macOS** | (extension future possible) | Non livré | — |

---

## Architecture multi-plateforme
                       main.py (orchestrateur)
                              |
          +-------------------+-------------------+
          |                                       |
   parser.py (facade)                    tailer.py (facade)
          |                                       |
 +--------+--------+                     +--------+--------+
 |                 |                     |                 |
parsers/linux.py  parsers/windows.py   platforms/linux.py  platforms/windows.py
(syslog)         (Event Log JSON,        (tail -f         (EvtSubscribe
36 EventIDs MITRE)      /var/log/*.log)  + pywin32)
|
|
buffer.py -> sender.py -> Backend Cybersafe-AI
|
+-> spool.py (résilience disque si réseau down)

**95% du code est partagé** entre Linux et Windows. Seuls `platforms/{linux,windows}.py` (lecture des sources) et `parsers/{linux,windows}.py` (normalisation) sont OS-spécifiques. Le reste (buffer, sender, spool, config, main) est commun.

Voir [`docs/adr/ADR-001-windows-agent-stack.md`](docs/adr/ADR-001-windows-agent-stack.md) pour les décisions architecturales.

---

## Fonctionnalités

### Collection
- **Linux** : tail multi-fichiers, détection rotation logrotate, 1 thread par fichier
- **Windows** : subscription PUSH via `EvtSubscribe` (API moderne, CPU-efficient), filtrage XPath natif
- Bookmarks Windows persistés sur disque (continuité après reboot)

### Normalisation
- 8 patterns Linux (SSH, sudo, sessions, erreurs système)
- **36 EventIDs Windows mappés MITRE ATT&CK** (Authentication, Privilege Escalation, Execution, Defense Evasion, etc.)
- Extraction structurée (IP, user, port, PID, commande, EventID, computer, provider)

### Robustesse
- Buffer mémoire (flush par taille OU temps)
- Spool disque (FIFO, taille bornée) → aucun event perdu en cas de coupure réseau prolongée
- Retry exponentiel sur l'envoi HTTPS (jusqu'à 6 tentatives, backoff configurable)
- Reprise après redémarrage (bookmarks Windows + rejeu spool Linux)

### Sécurité
- Service systemd hardened (Linux) : `ProtectSystem=strict`, `MemoryDenyWriteExecute`, `CapabilityBoundingSet` vide, syscall filter
- Service Windows en `LocalSystem` (requis pour Event Log Security)
- Token agent en YAML 0640 (Linux) / ACL restreint (Windows)

---

## Installation — Linux

### Installation rapide

```bash
git clone https://github.com/AlphaBah-Ib/Cybersafe-AI-Agent.git
cd Cybersafe-AI-Agent

# Installeur automatisé (root requis)
sudo ./install.sh
```

L'installeur :
- Crée l'utilisateur système `cybersafe` (no shell, no login)
- Crée les dossiers `/opt/cybersafe-agent`, `/etc/cybersafe`, `/var/lib/cybersafe`, `/var/spool/cybersafe`
- Installe l'agent dans `/opt/cybersafe-agent/` avec son propre venv Python
- Installe le service systemd (sans le démarrer)

Puis :

```bash
# 1. Mettre votre token dans la config
sudo nano /etc/cybersafe/config.yaml

# 2. Démarrer le service
sudo systemctl start cybersafe-agent

# 3. Vérifier
systemctl status cybersafe-agent
journalctl -u cybersafe-agent -f
sudo tail -f /var/lib/cybersafe/agent.log
```

### Désinstallation

```bash
sudo ./uninstall.sh           # Interactive (demande pour les données)
sudo ./uninstall.sh --purge   # Tout supprimer sans demander
```

---

## Installation — Windows

Voir la documentation dédiée : [`packaging/windows/README-Windows.md`](packaging/windows/README-Windows.md).

**TL;DR** :

```powershell
# 1. Télécharger depuis Releases
# https://github.com/AlphaBah-Ib/Cybersafe-AI-Agent/releases

# 2. Extraire le zip et lancer (PowerShell Administrateur)
.\install.ps1
```

---

## Configuration

Voir [`config.example.yaml`](config.example.yaml) pour la configuration complète. Champs principaux :

```yaml
token: csa_xxxxxxxxxxxxxxx                  # Token agent (dashboard Cybersafe)
api_url: https://cybersafe-ai-...           # URL API backend

# Linux uniquement (ignoré sur Windows)
sources:
  - /var/log/auth.log
  - /var/log/syslog

# Windows uniquement (ignoré sur Linux)
windows:
  channels:
    - Security
    - System
    - Microsoft-Windows-PowerShell/Operational
    # ... voir config.example.yaml
  security_event_ids:
    - 4624
    - 4625
    # ... 20 EventIDs MITRE ATT&CK
  bookmarks_dir: C:\ProgramData\Cybersafe\bookmarks
```

---

## Modules

| Module | Rôle | OS |
|---|---|---|
| `cybersafe_agent/main.py` | Orchestrateur principal | Tous |
| `cybersafe_agent/config.py` | Chargement YAML + validation | Tous |
| `cybersafe_agent/buffer.py` | Buffer mémoire (flush taille/temps) | Tous |
| `cybersafe_agent/spool.py` | Spool disque (résilience réseau) | Tous |
| `cybersafe_agent/sender.py` | Envoi HTTPS + retry exponentiel | Tous |
| `cybersafe_agent/tailer.py` | Façade tailer (détection OS au runtime) | Tous |
| `cybersafe_agent/parser.py` | Façade parser (détection format ligne) | Tous |
| `cybersafe_agent/platforms/linux.py` | Tail multi-fichiers `/var/log/*.log` | Linux/macOS |
| `cybersafe_agent/platforms/windows.py` | Subscription Event Log via pywin32 | Windows |
| `cybersafe_agent/parsers/linux.py` | Patterns regex syslog | Linux/macOS |
| `cybersafe_agent/parsers/windows.py` | Mapping EventID → severity (MITRE) | Windows |

---

## Développement

### Lancer en mode dev (sans installer)

```bash
# Linux
pip install -r requirements.txt
CYBERSAFE_CONFIG=./config.yaml python -m cybersafe_agent

# Windows
pip install -r requirements.txt
$env:CYBERSAFE_CONFIG = ".\config.yaml"
python -m cybersafe_agent
```

### Build du .exe Windows

```powershell
.\packaging\windows\build.ps1
```

Le build se fait automatiquement via GitHub Actions à chaque tag `v*.*.*`.

### Tests de non-régression

```bash
# Vérifier que la façade tailer importe la bonne implémentation
python3 -c "from cybersafe_agent.tailer import LogTailer; print(LogTailer.__name__)"
# Linux: LinuxLogTailer
# Windows: WindowsLogTailer

# Vérifier le mapping Windows MITRE
python3 -c "from cybersafe_agent.parsers.windows import WINDOWS_EVENT_MAPPING; print(f'{len(WINDOWS_EVENT_MAPPING)} EventIDs mapped')"
# Sortie attendue: 36 EventIDs mapped
```

---

## Structure du repo
.
├── cybersafe_agent/           # Code Python de l'agent
│   ├── platforms/             # Code OS-spécifique (tailer)
│   └── parsers/               # Code OS-spécifique (normalisation)
├── docs/
│   └── adr/                   # Architecture Decision Records
├── packaging/
│   ├── linux/
│   │   └── systemd/           # Unit file systemd
│   └── windows/
│       ├── cybersafe-agent.spec   # PyInstaller config
│       ├── build.ps1              # Script de build local
│       ├── install.ps1            # Installeur client
│       ├── uninstall.ps1          # Désinstalleur
│       └── README-Windows.md      # Doc client Windows
├── .github/workflows/
│   └── build-windows.yml      # CI build automatique Windows
├── install.sh                 # Installeur Linux
├── uninstall.sh               # Désinstalleur Linux
├── config.example.yaml        # Template de config
├── requirements.txt           # Deps Python (pywin32 marker Windows-only)
└── README.md                  # Ce fichier

---

## Licence

Propriétaire — Cybersafe-AI © 2026

---

## Liens

- **Backend** : https://github.com/AlphaBah-Ib/Cybersafe-AI
- **Dashboard** : https://cybersafe-ai-e1u6.vercel.app
- **Releases** : https://github.com/AlphaBah-Ib/Cybersafe-AI-Agent/releases
- **Documentation ADR** : [`docs/adr/`](docs/adr/)
