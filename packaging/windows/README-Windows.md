# Cybersafe-AI Agent — Windows

Agent Windows qui surveille les **Windows Event Log** et envoie les événements de sécurité au backend Cybersafe-AI.

Cette version Windows partage 95% de son code avec l'agent Linux (cf. ADR-001 dans `docs/adr/`), garantissant cohérence et maintenance unifiée.

---

## Prérequis

| Composant | Version minimale |
|---|---|
| **OS** | Windows 10, Windows 11, Windows Server 2019, Windows Server 2022 |
| **Architecture** | x64 (64-bit) |
| **PowerShell** | 5.1+ (intégré à Windows 10+) |
| **Privilèges** | Administrateur local (requis pour Event Log Security) |
| **Réseau** | Sortie HTTPS vers l'API Cybersafe (TCP/443) |

> **Pourquoi LocalSystem ?** Le channel `Security` du Windows Event Log nécessite le privilège `SeSecurityPrivilege`, accordé par défaut au compte `LocalSystem`. Tourner en compte utilisateur restreindrait drastiquement la visibilité SOC.

---

## Installation rapide

### 1. Télécharger la distribution

Depuis [github.com/AlphaBah-Ib/Cybersafe-AI-Agent/releases](https://github.com/AlphaBah-Ib/Cybersafe-AI-Agent/releases) :

- `cybersafe-agent-windows-vX.Y.Z.zip`

### 2. Extraire le zip

Décompresser dans un dossier temporaire (ex: `C:\Users\<vous>\Downloads\cybersafe-agent\`).

### 3. Lancer l'installeur (PowerShell Administrateur)

```powershell

### Suivre les logs en temps réel

```powershell
Get-Content "C:\ProgramData\Cybersafe\logs\agent.log" -Wait -Tail 50
```

Vous devriez voir des lignes du type :
2026-05-16 19:30:01 [INFO] cybersafe -- Cybersafe Agent v1.0 -- demarrage
2026-05-16 19:30:01 [INFO] cybersafe.tailer.windows --   Watching channel: Security
2026-05-16 19:30:01 [INFO] cybersafe.tailer.windows --   Watching channel: System

### Vérifier la connectivité backend

```powershell
$config = Get-Content "C:\ProgramData\Cybersafe\config\config.yaml" -Raw
$apiUrl = ($config | Select-String 'api_url:\s*(.+)').Matches[0].Groups[1].Value.Trim()
Invoke-WebRequest -Uri "$apiUrl/health/" -UseBasicParsing
```

---

## Troubleshooting

### Le service ne démarre pas

```powershell
# Voir le dernier code d'erreur du service
Get-EventLog -LogName System -Source 'Service Control Manager' -Newest 5 |
    Where-Object { $_.Message -like '*CybersafeAgent*' }

# Voir stderr du service
Get-Content "C:\ProgramData\Cybersafe\logs\service-stderr.log" -Tail 100
```

### Access denied sur le channel Security

Le service doit tourner en `LocalSystem`. Vérifier :

```powershell
sc.exe qc CybersafeAgent
```

Chercher la ligne `SERVICE_START_NAME` -- doit être `LocalSystem`.

Si autre chose, reconfigurer :

```powershell
& "C:\ProgramData\Cybersafe\nssm\nssm.exe" set CybersafeAgent ObjectName LocalSystem
Restart-Service CybersafeAgent
```

### Un channel n'existe pas (ex: Sysmon non installé)

C'est normal et géré. L'agent log un warning et skip ce channel :
[WARN] cybersafe.tailer.windows --  Channel 'Microsoft-Windows-Sysmon/Operational'
not found on this system (skip -- install missing component if needed)

Si vous voulez vraiment Sysmon, installez-le : [learn.microsoft.com/en-us/sysinternals/downloads/sysmon](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon).

### Antivirus bloque l'installation

L'agent est un binaire Python packagé via PyInstaller, ce qui peut déclencher des False Positives sur certains antivirus (signature heuristique).

Solutions :

1. Ajouter `C:\Program Files\Cybersafe Agent\` aux exclusions
2. Soumettre le binaire pour analyse :
   - Microsoft Defender : https://www.microsoft.com/wdsi/filesubmission
   - Autres AV : voir leur portail respectif

Une version signée avec certificat EV est prévue en v2 (Q3 2026).

---

## Désinstallation

### Désinstallation interactive

```powershell
cd C:\Users\<vous>\Downloads\cybersafe-agent
.\uninstall.ps1
```

L'uninstaller demande pour chaque dossier de données si vous voulez le supprimer (config, logs, bookmarks, spool).

### Désinstallation totale (sans questions)

```powershell
.\uninstall.ps1 -Purge
```

> **Attention** : `-Purge` supprime tout, y compris votre token agent et les logs. À utiliser uniquement pour réinstaller from scratch ou décommissionner définitivement la machine.

---

## Build from source

Si vous voulez builder le `.exe` vous-même au lieu d'utiliser le zip pré-built :

```powershell
git clone https://github.com/AlphaBah-Ib/Cybersafe-AI-Agent.git
cd Cybersafe-AI-Agent
.\packaging\windows\build.ps1
```

Le build prend 2-5 minutes. Output dans `dist\cybersafe-agent\`.

---

## Architecture
[Windows Event Log]
|
v
[WindowsLogTailer]      (1 thread / channel, EvtSubscribe PUSH)
| JSON
v
[Parser Windows]        (36 EventIDs MITRE -> severity + type)
|
v
[Buffer]             (flush taille OU temps)
|
v
[Sender]             (HTTPS + retry exponentiel)
|
v
[Backend Cybersafe-AI]
^
|
[Spool]              (resilience disque si reseau down)

Tous les modules sauf `WindowsLogTailer` et `parsers/windows.py` sont partagés avec l'agent Linux, garantissant cohérence comportementale entre les 2 OS.

---

## Support

- Documentation : `docs/adr/ADR-001-windows-agent-stack.md`
- Issues : https://github.com/AlphaBah-Ib/Cybersafe-AI-Agent/issues
- Dashboard Cybersafe : https://cybersafe-ai-e1u6.vercel.app

---

(c) 2026 Cybersafe-AI — Tous droits réservés.
