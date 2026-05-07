# Cybersafe Agent

Agent Linux qui surveille des fichiers de log et envoie les événements de sécurité au backend Cybersafe-AI.

## Installation rapide

```bash
# 1. Cloner
git clone https://github.com/AlphaBah-Ib/Cybersafe-AI-Agent.git
cd Cybersafe-AI-Agent

# 2. Installer les dépendances
pip3 install -r requirements.txt --break-system-packages

# 3. Créer le fichier de config
sudo mkdir -p /etc/cybersafe
sudo cp config.example.yaml /etc/cybersafe/config.yaml
sudo chmod 600 /etc/cybersafe/config.yaml

# 4. Éditer la config (remplacer le token)
sudo nano /etc/cybersafe/config.yaml

# 5. Lancer en avant-plan (test)
sudo python3 -m cybersafe_agent
```

## Configuration

Voir `config.example.yaml` pour la config complète. Champs obligatoires :
- `token` : token agent (commence par `csa_`)
- `api_url` : URL API Cybersafe
- `sources` : liste de fichiers à surveiller

## Architecture

```
[Tailer] → [Parser] → [Buffer] → [Sender] → Backend Cybersafe
   ↓          ↓          ↓          ↓
multi-     extract    flush      retry
file       severity   max_size   exponential
threads    + parsed   OR time
```

## Modules

- `cybersafe_agent/config.py` — Chargement YAML + validation
- `cybersafe_agent/tailer.py` — Tail multi-fichiers (1 thread/fichier)
- `cybersafe_agent/parser.py` — Détection severity + extraction
- `cybersafe_agent/buffer.py` — Buffer flush taille/temps
- `cybersafe_agent/sender.py` — POST avec retry exponentiel
- `cybersafe_agent/main.py` — Orchestrateur

## Test rapide

```bash
# 1. Installer et configurer
pip3 install -r requirements.txt
cp config.example.yaml /tmp/cybersafe-test.yaml
nano /tmp/cybersafe-test.yaml  # mettre ton token

# 2. Lancer en mode test
CYBERSAFE_CONFIG=/tmp/cybersafe-test.yaml sudo -E python3 -m cybersafe_agent

# 3. Dans un autre terminal, générer du trafic
sudo whoami  # tape un mauvais mdp puis le bon
```

## Logs

L'agent écrit dans `/var/log/cybersafe-agent.log` (rotation automatique 10 Mo × 3 backups).

## Service systemd (à venir SOC-021)

Pas encore implémenté. Pour l'instant, lance-le manuellement avec `sudo`.

## Licence

Propriétaire — Cybersafe-AI © 2026
