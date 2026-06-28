# Cybersafe-AI Agent — Guide d'installation Windows


Documentation complète pour déployer l'agent Cybersafe-AI sur Windows.

**Version** : v1.1.0-beta.7  
**Dernière mise à jour** : 17 mai 2026  
**Plateformes supportées** : Windows 10, Windows 11, Windows Server 2019, Windows Server 2022

---

## Table des matières

1. [Vue d'ensemble](#1-vue-densemble)
2. [Prérequis](#2-prérequis)
3. [Installation rapide](#3-installation-rapide)
   - 3.1 [Méthode 1 — Installation via MSI installer (recommandée)](#31-méthode-1--installation-via-msi-installer-recommandée)
   - 3.2 [Méthode 2 — Script PowerShell + NSSM (alternative)](#32-méthode-2--installation-via-script-powershell--nssm-alternative)
4. [Configuration](#4-configuration)
5. [Démarrage et gestion du service](#5-démarrage-et-gestion-du-service)
6. [Vérification post-installation](#6-vérification-post-installation)
7. [Configuration avancée](#7-configuration-avancée)
8. [Sécurité](#8-sécurité)
9. [Déploiement à grande échelle](#9-déploiement-à-grande-échelle)
10. [Monitoring](#10-monitoring)
11. [Désinstallation](#11-désinstallation)
12. [Mise à jour](#12-mise-à-jour)
13. [Troubleshooting](#13-troubleshooting)
14. [FAQ](#14-faq)
15. [Annexes](#15-annexes)

---

## 1. Vue d'ensemble

### 1.1 Qu'est-ce que Cybersafe-AI Agent Windows

Cybersafe-AI Agent est un collecteur d'événements de sécurité qui surveille en temps réel les **Windows Event Log** (Security, System, PowerShell, Defender, etc.) et envoie les événements détectés au backend Cybersafe-AI pour analyse et corrélation.

L'agent fonctionne comme un **service Windows** (similaire à un antivirus), avec auto-démarrage au boot et résilience aux coupures réseau.

### 1.2 Architecture

    [Windows Event Log]
            |
            v
    [WindowsLogTailer]      (1 thread / channel, EvtSubscribe push-based)
            |  JSON
            v
    [Parser Windows]        (33 EventIDs MITRE ATT&CK)
            |
            v
    [Buffer]                (flush par taille OU temps)
            |
            v
    [Sender]                (HTTPS + retry exponentiel)
            |
            v
    [Backend Cybersafe-AI]  (https://app.cybersafe-ai.com)
            ^
            |
    [Spool]                 (résilience disque si réseau down)

### 1.3 Différences avec l'agent Linux

| Aspect | Linux | Windows |
|---|---|---|
| **Source des logs** | `/var/log/*.log` (auth, syslog) | Windows Event Log (Security, System, PowerShell, etc.) |
| **Méthode lecture** | `tail -f` multi-fichiers | `EvtSubscribe` API push-based |
| **Service** | systemd | Windows Installer ServiceInstall (MSI) ou NSSM (legacy) |
| **Privilèges** | utilisateur `cybersafe` (no-shell) | `LocalSystem` (requis pour Security channel) |
| **Configuration** | `/etc/cybersafe/config.yaml` | `C:\ProgramData\Cybersafe\config\config.yaml` |
| **Logs** | `/var/lib/cybersafe/agent.log` | `C:\ProgramData\Cybersafe\logs\agent.log` |
| **Bookmark** | offset fichier | EventLog bookmark XML natif |

**95% du code Python est partagé** entre les 2 OS (cf. ADR-001).

---

## 2. Prérequis

### 2.1 Système d'exploitation

| OS | Version | Status |
|---|---|---|
| **Windows 10** | 1809 ou supérieur (x64) | Supporté |
| **Windows 11** | Toutes versions (x64) | Supporté |
| **Windows Server 2019** | Toutes éditions | Supporté |
| **Windows Server 2022** | Toutes éditions | Supporté |
| **Windows 7 / 8 / 8.1** | — | Non supporté (EOL) |
| **Windows Server 2016** | — | Non supporté |

### 2.2 Matériel minimum

| Ressource | Minimum | Recommandé |
|---|---|---|
| **CPU** | 1 vCPU | 2 vCPU |
| **RAM** | 100 MB libre | 200 MB libre |
| **Disque** | 50 MB libre (binaires) + 500 MB libre (spool/logs) | 1 GB libre |
| **Réseau** | Connexion HTTPS sortante | — |

### 2.3 Permissions

- **Compte Administrateur local** requis pour l'installation
- Le service tourne en `LocalSystem` (privilège `SeSecurityPrivilege` requis pour le channel Security)
- **Windows Installer 5.0+** (intégré à Windows 10/11 et Windows Server 2016+ par défaut)
- **PowerShell 5.1+** (requis uniquement pour la méthode alternative NSSM, intégré à Windows par défaut)

### 2.4 Réseau et firewall

L'agent doit pouvoir établir une connexion **HTTPS sortante** (TCP/443) vers :

    https://app.cybersafe-ai.com

Aucun port entrant n'est requis. Si vous avez un proxy d'entreprise, configurez-le via les variables d'environnement Windows (cf. section 7.4).

### 2.5 Token agent

Avant l'installation, créez un token agent depuis votre dashboard Cybersafe-AI :

1. Connectez-vous à : `https://cybersafe-ai-e1u6.vercel.app`
2. Allez dans **SOC → Agents**
3. Cliquez sur **Créer un agent**
4. Donnez un nom à la machine (ex: `pc-comptabilite-01`)
5. Copiez le token généré (format `csa_xxxxxxxxxxxxxxx`)
6. **Conservez ce token précieusement** — il est nécessaire pour l'installation

---

## 3. Installation rapide

L'agent Cybersafe-AI Windows peut être installé selon **deux méthodes**, au choix selon votre contexte :

| Méthode | Cas d'usage | Effort |
|---|---|---|
| **3.1 MSI installer** ⭐ | Sysadmins, GPO, Intune, déploiement de masse | 2 min |
| **3.2 Script PowerShell + NSSM** | Anciennes versions, environnements custom, debug | 5 min |

→ **La méthode MSI (3.1) est recommandée** pour la majorité des cas. Elle suit le standard industrie (Wazuh, Datadog, SentinelOne) et permet une intégration directe avec GPO / SCCM / Intune / MDM.

---

### 3.1 Méthode 1 — Installation via MSI installer (recommandée)

L'installer MSI Windows est le format standard industrie pour le déploiement d'applications sur Windows. Il offre :

- ✅ **Wizard graphique** d'installation (mode interactif)
- ✅ **Installation silencieuse** scriptable (mode unattended pour MDM)
- ✅ **Add/Remove Programs** : visible dans le Panneau de configuration
- ✅ **Rollback transactional** : si l'install échoue, la machine reste propre
- ✅ **Déploiement GPO / Intune / SCCM** : compatible nativement
- ✅ **Désinstallation propre** : un clic depuis Programmes et fonctionnalités
- ✅ **Mise à jour automatique** : majeure upgrade géré nativement par Windows Installer

#### 3.1.1 Téléchargement du MSI

Téléchargez la dernière version stable depuis GitHub Releases :

- **Page Releases** : https://github.com/AlphaBah-Ib/Cybersafe-AI-Agent/releases/latest
- **Fichier** : `cybersafe-agent-windows-vX.Y.Z.msi` (~12-13 MB)

Vérification d'intégrité (recommandée pour environnements de production) :

```powershell
# Vérifier la signature SHA256 (visible sur la page Release GitHub)
Get-FileHash -Algorithm SHA256 cybersafe-agent-windows-vX.Y.Z.msi
```

Comparez le hash avec celui affiché à côté du fichier sur GitHub.

#### 3.1.2 Installation interactive (mode wizard graphique)

**Pré-requis** : Droits administrateur local (UAC).

1. **Double-cliquez** sur `cybersafe-agent-windows-vX.Y.Z.msi`
2. **SmartScreen Windows** peut afficher un avertissement (MSI non signé Authenticode en V1) :
   - Cliquer sur "Plus d'infos" puis "Exécuter quand même"
3. **Wizard d'installation** :
   - **Welcome** → Next
   - **License Agreement** → Accept → Next
   - **Destination Folder** : par défaut `C:\Program Files\Cybersafe Agent\` → Next
   - **Ready to Install** → Install
4. **UAC popup** → Oui (élévation de privilèges)
5. **Progress bar** → installation en ~10-30 secondes
6. **Complete** → Finish

**Important** : Le service `CybersafeAgent` est **registered en autostart**, mais **NE démarre PAS automatiquement** après l'install. Cette décision design (alignée Datadog/Wazuh) permet de configurer le token AVANT le premier démarrage du service.

→ Procédez à la configuration (section 4) avant de démarrer le service.

#### 3.1.3 Installation silencieuse (mode unattended pour MDM/GPO/Intune)

Pour déploiement de masse via GPO Active Directory, Microsoft Intune, SCCM ou tout autre MDM :

```powershell
msiexec /i cybersafe-agent-windows-vX.Y.Z.msi /qn TOKEN=csa_VOTRE_TOKEN_ICI
```

Paramètres MSI standards :

| Paramètre | Description |
|---|---|
| `/i` | Install |
| `/qn` | Quiet, No UI (totalement silencieux) |
| `/qb` | Quiet, Basic UI (juste la barre de progression) |
| `/L*V install.log` | Logs verbeux dans `install.log` (pour debug) |
| `INSTALLFOLDER="D:\Cybersafe\"` | Override du dossier d'install |
| `TOKEN=csa_xxx` | Token agent (sera écrit dans config.yaml) |

**Exemple Intune** : Importez le `.msi` directement dans l'app Microsoft Intune, puis poussez sur le groupe de machines cible. Le MSI sera installé silencieusement au prochain check-in de l'agent Intune.

**Exemple GPO** : Computer Configuration → Policies → Software Settings → Software Installation → New Package → sélectionner le MSI partagé en SMB.

#### 3.1.4 Visibilité Add/Remove Programs

Après installation, l'agent apparaît dans :

- **Windows 10/11** : Paramètres → Applications → Applications installées
- **Windows Server** : Panneau de configuration → Programmes et fonctionnalités

Vous y verrez :

    Cybersafe-AI Agent
      Éditeur     : Cybersafe-AI
      Version     : 1.1.0
      Taille      : ~30 MB
      Date install: <date du jour>
      Support     : support@cybersafe-ai.com
      Aide        : https://github.com/AlphaBah-Ib/Cybersafe-AI-Agent/issues

#### 3.1.5 Configuration post-installation

Une fois le MSI installé, **deux options** pour configurer le token :

**Option A** — Token fourni à l'install via cmdline (recommandé pour MDM) :
Le token est déjà écrit dans `config.yaml` automatiquement.

**Option B** — Éditer manuellement `config.yaml` (install interactive sans token) :

1. Ouvrir **Notepad en administrateur** (clic droit → Exécuter en tant qu'administrateur)
2. Ouvrir `C:\ProgramData\Cybersafe\config\config.yaml`
3. Remplir les valeurs :

```yaml
agent:
  token: csa_VOTRE_TOKEN_ICI
  backend_url: https://app.cybersafe-ai.com/api/soc/ingest/
  hostname: VOTRE_NOM_MACHINE

channels:
  - Security
  - System
  - Application
```

4. Sauvegarder (Ctrl+S)

#### 3.1.6 Démarrage du service après configuration

```powershell
Start-Service CybersafeAgent
```

OU via l'interface graphique : `services.msc` → Cybersafe-AI Agent → clic droit → Démarrer.

→ Voir section 6 pour les vérifications post-démarrage.

---

### 3.2 Méthode 2 — Installation via script PowerShell + NSSM (alternative)

Méthode legacy pour environnements custom ou debugging avancé.

Temps estimé : **5 minutes**.

#### 3.2.1 Télécharger l'agent

Téléchargez la dernière version depuis :

    https://github.com/AlphaBah-Ib/Cybersafe-AI-Agent/releases/latest

Fichier : `cybersafe-agent-windows-vX.Y.Z.zip` (~12 MB)

#### 3.2.2 Vérifier l'intégrité (SHA256)

Sur la page Release, copiez le SHA256 affiché à côté du zip. Puis dans PowerShell :

```powershell
Get-FileHash -Algorithm SHA256 "C:\Users\\Downloads\cybersafe-agent-windows-vX.Y.Z.zip"
```

Comparez la valeur avec celle de GitHub. **Si les hashs diffèrent → arrêtez l'installation** et signalez le problème.

#### 3.2.3 Extraire le zip

Clic droit sur le zip → **Extraire tout...** → Choisissez un dossier (ex: `C:\Users\<vous>\Downloads\cybersafe-agent\`).

#### 3.2.4 Lancer install.ps1 en tant qu'Administrateur

1. Touche **Windows** → tapez `PowerShell`
2. **Clic droit sur "Windows PowerShell"** → **Exécuter en tant qu'administrateur**
3. Confirmer le UAC

Dans PowerShell admin :

```powershell
cd C:\Users\\Downloads\cybersafe-agent
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass -Force
.\install.ps1
```

> **Note** : `Set-ExecutionPolicy` est requis car le script n'est pas (encore) signé numériquement. Cela autorise uniquement la session courante, votre policy globale reste inchangée.

#### 3.2.5 Suivre les prompts de l'installeur

L'installeur va :

1. ✓ Vérifier les prérequis (Windows version, PowerShell, droits admin)
2. ✓ Créer les dossiers d'installation
3. ✓ Copier les binaires dans `C:\Program Files\Cybersafe Agent\`
4. ⚙ **Vous demander votre token agent** (collez-le)
5. ✓ Générer `C:\ProgramData\Cybersafe\config\config.yaml`
6. ✓ Télécharger et vérifier NSSM (gestionnaire de service)
7. ✓ Enregistrer le service Windows `CybersafeAgent`
8. ⚙ Vous demander si vous voulez démarrer le service (recommandé : Y)

L'installation est terminée. Passez à la **section 6** pour vérifier.

---

## 4. Configuration

### 4.1 Localisation des fichiers

| Chemin | Contenu | Permissions |
|---|---|---|
| `C:\Program Files\Cybersafe Agent\` | Binaires (read-only après install) | Admin: Full, Users: Read |
| `C:\Program Files\Cybersafe Agent\cybersafe-agent.exe` | Exécutable principal | — |
| `C:\Program Files\Cybersafe Agent\_internal\` | Bibliothèques Python embarquées (PyInstaller onedir) | — |
| `C:\ProgramData\Cybersafe\config\config.yaml` | Configuration agent | LocalSystem: Full |
| `C:\ProgramData\Cybersafe\logs\agent.log` | Logs applicatifs (rotation 10 MB × 3) | LocalSystem: Full |
| `C:\ProgramData\Cybersafe\logs\service-stdout.log` | stdout du service (méthode NSSM uniquement) | LocalSystem: Full |
| `C:\ProgramData\Cybersafe\logs\service-stderr.log` | stderr du service (méthode NSSM uniquement) | LocalSystem: Full |
| `C:\ProgramData\Cybersafe\bookmarks\` | Bookmarks Event Log (persistance) | LocalSystem: Full |
| `C:\ProgramData\Cybersafe\spool\` | Events en queue (résilience réseau) | LocalSystem: Full |
| `C:\ProgramData\Cybersafe\nssm\nssm.exe` | Service manager NSSM (méthode NSSM uniquement) | — |

### 4.2 Fichier config.yaml — Structure

```yaml
# Token agent (obtenu depuis le dashboard)
agent:
  token: csa_xxxxxxxxxxxxxxx
  backend_url: https://app.cybersafe-ai.com/api/soc/ingest/
  hostname: VOTRE_NOM_MACHINE

# Fichier de log local
log_file: C:\ProgramData\Cybersafe\logs\agent.log
log_level: INFO

# Configuration Windows (section dédiée)
channels:
  # Tier 1 - Sécurité critique
  - Security
  - System
  - Application
  # Tier 2 - Attaques modernes
  - Microsoft-Windows-PowerShell/Operational
  - Microsoft-Windows-Windows Defender/Operational
  # Tier 3 - Persistence & lateral movement
  - Microsoft-Windows-TaskScheduler/Operational
  - Microsoft-Windows-WinRM/Operational
  - Microsoft-Windows-TerminalServices-LocalSessionManager/Operational
  # Bonus - si Sysmon installé
  - Microsoft-Windows-Sysmon/Operational

security_event_ids:
  # Authentification
  - 4624   # Successful logon
  - 4625   # Failed logon
  - 4647   # User-initiated logoff
  - 4648   # Logon with explicit credentials
  - 4672   # Special privileges assigned
  - 4673   # Privileged service called

  # Process & Service
  - 4688   # New process created
  - 4697   # Service installed via Sec audit
  - 7045   # Service installed via SCM (System channel) - SOC-203

  # Object access
  - 4663   # Object accessed

  # Audit policy (CRITIQUE - attaquants effacent les logs)
  - 4719   # Audit policy changed
  - 1102   # Audit log cleared

  # Account management
  - 4720   # User account created
  - 4722   # User account enabled
  - 4724   # Password reset attempt
  - 4725   # User account disabled
  - 4728   # User added to security-enabled group
  - 4732   # User added to security-enabled local group
  - 4738   # User account changed

  # Kerberos (Active Directory)
  - 4768   # Kerberos TGT requested
  - 4769   # Kerberos service ticket requested

bookmarks_dir: C:\ProgramData\Cybersafe\bookmarks

# Buffer (flush par taille OU temps)
batch_size: 50            # Events avant flush
flush_interval_seconds: 10

# Spool disque (résilience réseau)
spool:
  enabled: true
  path: C:\ProgramData\Cybersafe\spool
  max_size_mb: 500        # Taille max disque

# Réseau
http:
  timeout: 30             # Secondes
  retries: 6              # Nombre de tentatives
  backoff: 2.0            # Multiplicateur exponentiel
```

### 4.3 Modifier la configuration

Après modification, redémarrez le service pour appliquer :

```powershell
Restart-Service CybersafeAgent
```

---

## 5. Démarrage et gestion du service

### 5.1 Commandes essentielles

```powershell
# Voir le status
Get-Service CybersafeAgent

# Démarrer
Start-Service CybersafeAgent

# Arrêter
Stop-Service CybersafeAgent

# Redémarrer (après config change)
Restart-Service CybersafeAgent

# Voir les détails complets
sc.exe qc CybersafeAgent
```

### 5.2 Auto-démarrage au boot

Par défaut (méthodes MSI et NSSM), le service est configuré en **automatic** (démarre avec Windows). Pour vérifier :

```powershell
Get-Service CybersafeAgent | Select-Object Name, Status, StartType
```

Pour modifier :

```powershell
Set-Service CybersafeAgent -StartupType Automatic       # auto
Set-Service CybersafeAgent -StartupType Manual          # manuel
Set-Service CybersafeAgent -StartupType Disabled        # désactivé
```

### 5.3 Recovery policy (auto-restart en cas de crash)

Le MSI configure automatiquement une **recovery policy** :
- 1ère tentative : redémarrage après 5 secondes
- 2ème tentative : redémarrage après 10 secondes
- 3ème tentative : redémarrage après 30 secondes
- Reset du compteur après 1 jour sans crash

Pour vérifier la configuration :

```powershell
sc.exe qfailure CybersafeAgent
```

Pour modifier (exemple : redémarrer indéfiniment toutes les 5 secondes) :

```powershell
sc.exe failure CybersafeAgent reset= 86400 actions= restart/5000/restart/5000/restart/5000
```

### 5.4 Configuration NSSM (méthode alternative uniquement)

```powershell
# Voir toute la config NSSM
& "C:\ProgramData\Cybersafe\nssm\nssm.exe" dump CybersafeAgent

# Modifier la commande de démarrage
& "C:\ProgramData\Cybersafe\nssm\nssm.exe" set CybersafeAgent Application "C:\Program Files\Cybersafe Agent\cybersafe-agent.exe"

# Voir le restart policy (par défaut : restart sur crash)
& "C:\ProgramData\Cybersafe\nssm\nssm.exe" get CybersafeAgent AppExit
```

---

## 6. Vérification post-installation

### 6.1 Status du service

```powershell
Get-Service CybersafeAgent
```

Sortie attendue :

    Status   Name               DisplayName
    ------   ----               -----------
    Running  CybersafeAgent     Cybersafe-AI Agent

### 6.2 Logs en temps réel

```powershell
Get-Content "C:\ProgramData\Cybersafe\logs\agent.log" -Wait -Tail 50
```

Vous devriez voir :

    2026-05-17 22:30:01 [INFO] cybersafe -- Cybersafe Agent v1.1 -- demarrage
    2026-05-17 22:30:01 [INFO] cybersafe.config -- Loaded config from C:\ProgramData\Cybersafe\config\config.yaml
    2026-05-17 22:30:01 [INFO] cybersafe.tailer.windows -- Watching channel: Security
    2026-05-17 22:30:01 [INFO] cybersafe.tailer.windows -- Watching channel: System
    2026-05-17 22:30:01 [INFO] cybersafe.tailer.windows -- Watching channel: Application
    2026-05-17 22:30:02 [INFO] cybersafe.sender -- Connected to backend

### 6.3 Test de connectivité

```powershell
# Test ping HTTPS du backend
Invoke-WebRequest -Uri "https://app.cybersafe-ai.com/api/health/" -UseBasicParsing

# Doit retourner StatusCode 200
```

### 6.4 Vérifier l'agent dans le dashboard

1. Connectez-vous à `https://cybersafe-ai-e1u6.vercel.app`
2. Allez dans **SOC → Agents**
3. Votre nouvelle machine Windows doit apparaître :
   - **Status** : `online` (vert)
   - **Last heartbeat** : il y a quelques secondes
   - **OS** : `Windows`

### 6.5 Premiers events reçus

Pour générer un event de test, essayez de vous connecter avec un mauvais mot de passe :

```powershell
# Dans une nouvelle fenêtre PowerShell (pas admin)
runas /user:utilisateur-inexistant cmd.exe
# Tapez n'importe quel mot de passe -> échec
```

Dans les **2-3 secondes**, vous devriez voir dans le dashboard SOC un nouvel event :

- **EventID** : 4625 (Failed logon)
- **Severity** : high
- **failure_reason** : user_does_not_exist
- **Source** : votre machine Windows

---

## 7. Configuration avancée

### 7.1 Filtrage par EventID (MITRE ATT&CK)

L'agent ne capture **par défaut** que 22 EventIDs critiques sur les channels `Security`, `System` et `Application` (sinon volume trop important). Pour ajouter un EventID spécifique, éditez `config.yaml` :

```yaml
security_event_ids:
  - 4624
  - 4625
  # ... defaults ...
  - 4670   # Permissions on an object changed (votre ajout)
  - 4717   # System security access granted (votre ajout)
```

**Référence complète des EventIDs Windows** :

    https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/audit-policy-recommendations

### 7.2 Gestion mémoire

Le service par défaut consomme **30-150 MB RAM** selon l'activité. Pour limiter strictement (méthode NSSM uniquement) :

```powershell
# Augmenter à 512 MB
& "C:\ProgramData\Cybersafe\nssm\nssm.exe" set CybersafeAgent AppRotateBytes 524288000
Restart-Service CybersafeAgent
```

### 7.3 Buffer et spool tuning

Pour des environnements **très haut débit** (>1000 events/seconde), augmentez le buffer dans `config.yaml` :

```yaml
batch_size: 500            # défaut: 50
flush_interval_seconds: 5  # défaut: 10

spool:
  max_size_mb: 2000        # défaut: 500
```

### 7.4 Proxy d'entreprise

Si votre réseau utilise un proxy HTTPS, configurez-le via les variables d'environnement du système.

**Pour la méthode MSI** : Définissez les variables d'environnement au niveau système (Panneau de configuration → Système → Variables d'environnement → Variables système) :

    HTTPS_PROXY = http://proxy.entreprise.local:8080
    HTTP_PROXY = http://proxy.entreprise.local:8080

Puis redémarrez le service :

```powershell
Restart-Service CybersafeAgent
```

**Pour la méthode NSSM** :

```powershell
& "C:\ProgramData\Cybersafe\nssm\nssm.exe" set CybersafeAgent AppEnvironmentExtra "HTTPS_PROXY=http://proxy.entreprise.local:8080" "HTTP_PROXY=http://proxy.entreprise.local:8080"
Restart-Service CybersafeAgent
```

### 7.5 Log rotation

Les logs sont déjà en rotation automatique (10 MB × 3 fichiers maximum). Pour modifier :

```yaml
log:
  max_bytes: 10485760    # 10 MB par fichier
  backup_count: 3        # 3 fichiers d'historique
```

---

## 8. Sécurité

### 8.1 Pourquoi LocalSystem

Le channel `Security` du Windows Event Log nécessite le privilège **SeSecurityPrivilege**, accordé par défaut au compte `LocalSystem`. Tourner en compte utilisateur restreindrait drastiquement la visibilité SOC (pas d'accès aux logs critiques).

C'est le même modèle que Microsoft Defender, Wazuh Agent, Splunk Universal Forwarder.

### 8.2 ACL sur les dossiers sensibles

Pendant l'installation (MSI ou PowerShell), les ACL suivantes sont appliquées :

| Dossier | LocalSystem | Administrators | Users |
|---|---|---|---|
| `C:\Program Files\Cybersafe Agent\` | Full | Full | Read |
| `C:\ProgramData\Cybersafe\config\` | Full | Full | **Aucun accès** |
| `C:\ProgramData\Cybersafe\logs\` | Full | Read | **Aucun accès** |

Le fichier `config.yaml` (qui contient votre token) **n'est lisible que par LocalSystem et Administrators**.

### 8.3 Protection du token

- Le token est stocké en clair dans `config.yaml` (limitation actuelle, planifiée DPAPI Windows en v2)
- L'ACL restrictive sur le dossier `config\` empêche les utilisateurs standard de le lire
- **Ne jamais commiter le token dans Git, partager par email non-chiffré, ou laisser en clair dans des scripts**
- En cas de compromission suspectée : régénérez le token depuis le dashboard et redémarrez l'agent

### 8.4 Vérification SHA256 (supply-chain)

Toujours vérifier l'intégrité du MSI ou du zip avant installation (cf. sections 3.1.1 et 3.2.2). Le SHA256 attendu est affiché publiquement sur la page Release GitHub, signé cryptographiquement par GitHub Actions.

### 8.5 Roadmap signing

L'agent **n'est pas encore signé numériquement** avec un certificat EV (Extended Validation). Conséquences :

- ✗ Windows affiche un warning "Unknown publisher" au premier lancement
- ✗ Certains antivirus peuvent flagger comme False Positive
- ✗ SmartScreen Defender peut bloquer

**Planifié en v2 (Q3 2026)** : achat certificat EV + signature automatisée du MSI dans le CI GitHub Actions.

---

## 9. Déploiement à grande échelle

Pour déployer l'agent sur **plusieurs dizaines/centaines de machines**, plusieurs options.

### 9.1 Installation silencieuse via MSI (recommandé)

```powershell
msiexec /i cybersafe-agent-windows-vX.Y.Z.msi /qn TOKEN=csa_xxx
```

Paramètres MSI standards (cf. section 3.1.3).

### 9.2 Installation silencieuse via PowerShell (méthode NSSM)

```powershell
.\install.ps1 -Token csa_xxxxxxxxxxxxxxx -Unattended
```

Paramètres disponibles :

| Paramètre | Valeur | Description |
|---|---|---|
| `-Token <string>` | `csa_xxx...` | Token agent (obligatoire en mode unattended) |
| `-Unattended` | switch | Pas de prompts, démarre le service automatiquement |
| `-SkipServiceStart` | switch | Installe sans démarrer (utile pour MDM) |
| `-InstallDir <path>` | path | Override le chemin d'installation |

### 9.3 Déploiement via Microsoft Intune

**Méthode MSI (recommandé)** :

1. Connectez-vous à Microsoft Intune Admin Center
2. Apps → Windows → Add → **Line-of-business app**
3. Sélectionnez le fichier `.msi`
4. Configurez les paramètres :
   - **App information** : Cybersafe-AI Agent
   - **Command-line arguments** : `TOKEN=csa_xxx /qn`
5. Assignez au groupe de machines cible

**Méthode PowerShell (legacy)** :

1. Préparez le package :
```powershell
   # Sur une machine de référence
   IntuneWinAppUtil.exe -c "C:\Sources\cybersafe-agent" -s "install.ps1" -o "C:\Output"
```

2. Importez le `.intunewin` dans Intune Admin Center
3. Configurez la commande d'installation :

       powershell.exe -ExecutionPolicy Bypass -File install.ps1 -Token csa_xxx -Unattended

4. Configurez la commande de désinstallation :

       powershell.exe -ExecutionPolicy Bypass -File uninstall.ps1 -Purge

5. Définissez la **detection rule** :
   - Type : Registry
   - Path : `HKLM\SYSTEM\CurrentControlSet\Services\CybersafeAgent`
   - Detection : Key exists

### 9.4 Déploiement via GPO (Group Policy)

**Méthode MSI (recommandé)** :

1. Copiez le `.msi` sur un share réseau (ex: `\\dc01\deploy\cybersafe.msi`)
2. Group Policy Management → New GPO → Edit
3. Computer Configuration → Policies → Software Settings → **Software Installation**
4. Right-click → New → Package → sélectionnez le MSI (chemin UNC `\\dc01\deploy\cybersafe.msi`)
5. Choisissez **Assigned** (installation au prochain boot)
6. Liez la GPO à l'OU contenant les machines cibles

**Méthode PowerShell (legacy)** :

1. Copiez les fichiers d'install sur un share réseau accessible (ex: `\\dc01\deploy\cybersafe\`)
2. Créez un script PowerShell de déploiement :
```powershell
   # \\dc01\deploy\cybersafe\deploy.ps1
   if (-not (Get-Service CybersafeAgent -ErrorAction SilentlyContinue)) {
       & "\\dc01\deploy\cybersafe\install.ps1" -Token "csa_xxx" -Unattended
   }
```
3. Dans GPO Editor : **Computer Configuration → Scripts → Startup**
4. Ajoutez le script `deploy.ps1`
5. Liez la GPO à l'OU contenant les machines cibles

### 9.5 Déploiement via Ansible (mixed environments)

**Méthode MSI** :

```yaml
- name: Deploy Cybersafe Agent on Windows
  hosts: windows_machines
  tasks:
    - name: Copy MSI
      win_copy:
        src: files/cybersafe-agent-windows-v1.1.0.msi
        dest: C:\Temp\cybersafe.msi

    - name: Install MSI
      win_package:
        path: C:\Temp\cybersafe.msi
        arguments: TOKEN={{ cybersafe_token }} /qn
        state: present
```

**Méthode PowerShell (legacy)** :

```yaml
- name: Deploy Cybersafe Agent on Windows
  hosts: windows_machines
  tasks:
    - name: Copy installer
      win_copy:
        src: files/cybersafe-agent/
        dest: C:\Temp\cybersafe-agent\

    - name: Run installer
      win_shell: |
        Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass -Force
        C:\Temp\cybersafe-agent\install.ps1 -Token {{ cybersafe_token }} -Unattended
      args:
        chdir: C:\Temp\cybersafe-agent\
```

### 9.6 Vérification de déploiement en masse

Depuis un serveur d'admin :

```powershell
# Liste des machines avec l'agent installé et leur status
$machines = Get-ADComputer -Filter * | Select-Object -ExpandProperty Name
foreach ($m in $machines) {
    try {
        $svc = Get-Service -ComputerName $m -Name CybersafeAgent -ErrorAction Stop
        Write-Host "$m : $($svc.Status)" -ForegroundColor Green
    } catch {
        Write-Host "$m : NOT INSTALLED" -ForegroundColor Red
    }
}
```

---

## 10. Monitoring

### 10.1 Logs locaux

```powershell
# Logs applicatifs
Get-Content "C:\ProgramData\Cybersafe\logs\agent.log" -Tail 100

# stdout du service NSSM (méthode alternative)
Get-Content "C:\ProgramData\Cybersafe\logs\service-stdout.log" -Tail 100

# stderr du service NSSM (erreurs - méthode alternative)
Get-Content "C:\ProgramData\Cybersafe\logs\service-stderr.log" -Tail 100
```

### 10.2 Event Viewer Windows

Les événements de démarrage/arrêt du service sont visibles dans :

    Event Viewer → Windows Logs → System
    Filter : Source = "Service Control Manager", Keyword = "CybersafeAgent"

### 10.3 Détection "agent silencieux" (côté backend)

Si l'agent ne communique plus avec le backend pendant **plus de 10 minutes**, un **finding automatique** est créé dans le dashboard SOC :

- **Severity** : high
- **Title** : `Agent silencieux : <hostname>`
- **Auteur** : `cybersafe_system` (compte technique)

Vous recevez une notification immédiate dans l'UI.

---

## 11. Désinstallation

### 11.1 Désinstallation via MSI (méthode recommandée)

**Option A — Interface graphique** :

1. Panneau de configuration → Programmes et fonctionnalités
2. Sélectionner "Cybersafe-AI Agent"
3. Cliquer "Désinstaller"
4. UAC → Oui
5. Wizard désinstallation → Finish

**Option B — Ligne de commande (silencieuse)** :

```powershell
# Avec le fichier MSI :
msiexec /x cybersafe-agent-windows-vX.Y.Z.msi /qn

# Sans le fichier (via ProductCode) :
Get-WmiObject -Class Win32_Product | Where-Object { $_.Name -like "*Cybersafe*" } | ForEach-Object { $_.Uninstall() }
```

La désinstallation MSI :

- ✅ Arrête le service Windows
- ✅ Supprime le service du SCM
- ✅ Supprime les fichiers de `C:\Program Files\Cybersafe Agent\`
- ⚠️ **Préserve** les données et logs dans `C:\ProgramData\Cybersafe\` (pour réinstall futur)

Pour un nettoyage complet :

```powershell
Remove-Item -Recurse -Force "C:\ProgramData\Cybersafe\"
```

### 11.2 Désinstallation via PowerShell (méthode NSSM)

```powershell
cd C:\Users\\Downloads\cybersafe-agent
.\uninstall.ps1
```

L'uninstaller demande pour chaque dossier de données si vous voulez le supprimer (config, logs, bookmarks, spool). Utile si vous voulez conserver les logs/bookmarks pour audit forensique ultérieur.

**Désinstallation silencieuse (purge totale)** :

```powershell
.\uninstall.ps1 -Purge
```

> **Attention** : `-Purge` supprime tout, y compris votre token agent et les logs. À utiliser uniquement pour réinstaller from scratch ou décommissionner définitivement la machine.

### 11.3 Nettoyage manuel (si uninstall échoue)

```powershell
# 1. Arrêter et supprimer le service
Stop-Service CybersafeAgent -Force -ErrorAction SilentlyContinue
sc.exe delete CybersafeAgent

# 2. Supprimer la clé registre (si zombie)
Remove-Item "HKLM:\SYSTEM\CurrentControlSet\Services\CybersafeAgent" -Recurse -Force -ErrorAction SilentlyContinue

# 3. Supprimer les binaires
Remove-Item "C:\Program Files\Cybersafe Agent\" -Recurse -Force -ErrorAction SilentlyContinue

# 4. Supprimer les données
Remove-Item "C:\ProgramData\Cybersafe\" -Recurse -Force -ErrorAction SilentlyContinue
```

### 11.4 Conserver les bookmarks pour une réinstallation

Si vous prévoyez de réinstaller l'agent et voulez **éviter la duplication d'events**, sauvegardez le dossier bookmarks AVANT la désinstallation :

```powershell
Copy-Item "C:\ProgramData\Cybersafe\bookmarks\" "C:\Temp\bookmarks-backup\" -Recurse
```

Puis après réinstallation, restaurez-le :

```powershell
Copy-Item "C:\Temp\bookmarks-backup\*" "C:\ProgramData\Cybersafe\bookmarks\" -Force
Restart-Service CybersafeAgent
```

L'agent reprendra exactement là où il s'était arrêté.

---

## 12. Mise à jour

### 12.1 Stratégie de versioning

L'agent suit [Semantic Versioning](https://semver.org/) :

- **vMAJOR.MINOR.PATCH** (ex: v1.2.3)
- **MAJOR** : breaking changes (config incompatible)
- **MINOR** : nouvelles features (compatibles)
- **PATCH** : bugfixes seulement

### 12.2 Upgrade via MSI (méthode recommandée)

Le MSI gère nativement les **major upgrades** : installer une nouvelle version désinstalle automatiquement l'ancienne, **en préservant `config.yaml`** dans `C:\ProgramData\Cybersafe\`.

```powershell
# Télécharger la nouvelle version
# Page : https://github.com/AlphaBah-Ib/Cybersafe-AI-Agent/releases/latest

# Installation directe (silencieuse) :
msiexec /i cybersafe-agent-windows-v2.0.0.msi /qn

# OU interactive : double-click sur le nouveau MSI
```

Le service est arrêté pendant l'upgrade puis redémarré automatiquement (si configuré).

### 12.3 Upgrade via PowerShell (méthode NSSM)

```powershell
# 1. Télécharger la nouvelle version
# https://github.com/AlphaBah-Ib/Cybersafe-AI-Agent/releases/latest

# 2. Arrêter le service
Stop-Service CybersafeAgent

# 3. Extraire la nouvelle version (par-dessus l'ancienne)
Expand-Archive cybersafe-agent-windows-vX.Y.Z.zip -DestinationPath C:\Temp\cybersafe-update -Force

# 4. Backup de la config actuelle
Copy-Item "C:\ProgramData\Cybersafe\config\config.yaml" "C:\Temp\config-backup.yaml"

# 5. Lancer install.ps1 en mode upgrade (détecte l'installation existante)
cd C:\Temp\cybersafe-update
.\install.ps1 -Upgrade

# 6. Vérifier
Get-Service CybersafeAgent
Get-Content "C:\ProgramData\Cybersafe\logs\agent.log" -Tail 30
```

### 12.4 Rollback

Si la nouvelle version pose problème :

```powershell
# 1. Arrêter le service
Stop-Service CybersafeAgent

# 2. Désinstaller la nouvelle version (MSI)
msiexec /x cybersafe-agent-windows-vNEW.msi /qn

# 3. Réinstaller l'ancienne version
msiexec /i cybersafe-agent-windows-vOLD.msi /qn TOKEN=csa_xxx
```

---

## 13. Troubleshooting

### 13.1 Le service ne démarre pas

```powershell
# Voir le dernier code d'erreur du service
Get-EventLog -LogName System -Source 'Service Control Manager' -Newest 5 | 
    Where-Object { $_.Message -like '*CybersafeAgent*' }

# Voir stderr du service (méthode NSSM)
Get-Content "C:\ProgramData\Cybersafe\logs\service-stderr.log" -Tail 100

# Lancer l'agent en mode console pour voir les erreurs en direct
cd "C:\Program Files\Cybersafe Agent\"
.\cybersafe-agent.exe
```

**Causes les plus fréquentes** :

1. `config.yaml` introuvable ou mal formaté → vérifier la syntaxe YAML
2. Token agent invalide → régénérer depuis le dashboard
3. Backend inaccessible → tester avec `Invoke-WebRequest` (cf. section 6.3)
4. Channel Event Log inexistant → cf. 13.5
5. **Service zombie d'un précédent test** → cf. 13.9 (spécifique MSI)

### 13.2 "Access denied" sur le channel Security

Le service doit tourner en `LocalSystem`. Vérifier :

```powershell
sc.exe qc CybersafeAgent
```

Chercher la ligne `SERVICE_START_NAME` → doit être `LocalSystem`.

Si autre chose (ex: un compte utilisateur), reconfigurer :

```powershell
sc.exe config CybersafeAgent obj= LocalSystem
Restart-Service CybersafeAgent
```

### 13.3 Antivirus False Positive

L'agent est un binaire Python packagé via PyInstaller, ce qui peut déclencher des False Positives sur certains antivirus (signature heuristique).

**Solutions** :

1. Ajouter `C:\Program Files\Cybersafe Agent\` aux **exclusions de l'antivirus**
2. Ajouter le hash SHA256 du `.exe` à la whitelist
3. Soumettre le binaire pour analyse :
   - **Microsoft Defender** : https://www.microsoft.com/wdsi/filesubmission
   - **Autres AV** : voir leur portail respectif

Une version signée avec certificat EV est prévue en v2 (cf. section 8.5).

### 13.4 Backend inaccessible

```powershell
# Test 1 : DNS resolve
Resolve-DnsName app.cybersafe-ai.com

# Test 2 : Ping TCP/443
Test-NetConnection -ComputerName app.cybersafe-ai.com -Port 443

# Test 3 : HTTPS health endpoint
Invoke-WebRequest -Uri "https://app.cybersafe-ai.com/api/health/" -UseBasicParsing
```

**Causes possibles** :

- Firewall d'entreprise bloque la sortie HTTPS → contacter votre admin réseau
- Proxy d'entreprise non configuré → cf. section 7.4
- DNS bloqué → vérifier la résolution
- Backend Cybersafe-AI temporairement down → vérifier le statut sur le dashboard

### 13.5 Channel inexistant (ex: Sysmon non installé)

C'est **normal et géré**. L'agent log un warning et skip ce channel :

    [WARN] cybersafe.tailer.windows -- Channel 'Microsoft-Windows-Sysmon/Operational'
    not found on this system (skip -- install missing component if needed)

Si vous voulez vraiment Sysmon, installez-le : 

    https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon

### 13.6 Bookmark corrompu

Si après un crash système l'agent ne démarre plus à cause d'un bookmark corrompu :

```powershell
# 1. Arrêter le service
Stop-Service CybersafeAgent

# 2. Supprimer tous les bookmarks (l'agent reprendra depuis "now")
Remove-Item "C:\ProgramData\Cybersafe\bookmarks\*" -Force

# 3. Redémarrer
Start-Service CybersafeAgent
```

> **Note** : Vous perdrez les events de la période non-collectée (généralement quelques minutes).

### 13.7 Logs vides

Si `agent.log` est vide alors que le service est `Running` :

```powershell
# Voir si le service écrit ailleurs (stdout/stderr, méthode NSSM)
Get-Content "C:\ProgramData\Cybersafe\logs\service-stdout.log" -Tail 50
Get-Content "C:\ProgramData\Cybersafe\logs\service-stderr.log" -Tail 50

# Vérifier les permissions
Get-Acl "C:\ProgramData\Cybersafe\logs\" | Format-List
```

LocalSystem doit avoir **Full Control** sur le dossier `logs\`.

### 13.8 Memory leak suspecté

Si l'agent consomme >500 MB RAM :

```powershell
# Voir la consommation
Get-Process -Name cybersafe-agent | Format-Table Name, WS, PM

# Capturer un dump pour analyse
Get-Process cybersafe-agent | Out-File "C:\Temp\agent-process.txt"
Stop-Service CybersafeAgent
Start-Service CybersafeAgent
```

Signaler le problème sur : https://github.com/AlphaBah-Ib/Cybersafe-AI-Agent/issues

### 13.9 Service zombie après désinstallation/rollback MSI

Si une installation MSI a échoué (rollback) ou si une désinstallation a partiellement réussi, il peut rester un **"service zombie"** dans le SCM Windows. Symptôme : un nouvelle installation MSI échoue avec :

    Service 'Cybersafe-AI Agent' (CybersafeAgent) could not be installed.
    Verify that you have sufficient privileges to install system services.

**Nettoyage manuel** (PowerShell admin) :

```powershell
# 1. Vérifier la présence du zombie
Get-Service -Name "CybersafeAgent" -ErrorAction SilentlyContinue

# 2. Forcer la suppression
Stop-Service -Name "CybersafeAgent" -Force -ErrorAction SilentlyContinue
sc.exe delete CybersafeAgent

# 3. Supprimer la clé registre orpheline
Remove-Item "HKLM:\SYSTEM\CurrentControlSet\Services\CybersafeAgent" -Recurse -Force -ErrorAction SilentlyContinue

# 4. Vérifier (rien ne doit s'afficher)
Get-Service -Name "CybersafeAgent" -ErrorAction SilentlyContinue
```

Si l'erreur "1072 : Le service est marqué pour suppression" apparaît :

- Fermer toutes les fenêtres `services.msc` ouvertes
- Redémarrer Windows
- Le service zombie sera complètement supprimé au prochain boot

---

## 14. FAQ

### 14.1 Performance & footprint

**Q : Combien de CPU/RAM l'agent consomme-t-il ?**  
R : Typiquement 30-80 MB RAM, <1% CPU en charge normale. Sur des serveurs très actifs (>1000 events/sec), peut monter à 150-200 MB.

**Q : L'agent ralentit-il le système ?**  
R : Non. Il utilise l'API `EvtSubscribe` qui est push-based (notifications kernel) sans polling. Impact CPU négligeable.

**Q : Combien d'events l'agent peut-il gérer ?**  
R : Testé jusqu'à 5000 events/seconde sustained. Au-delà, ajustez le buffer (cf. section 7.3).

### 14.2 Compatibilité

**Q : L'agent fonctionne-t-il avec mon EDR (CrowdStrike, SentinelOne, etc.) ?**  
R : Oui, mais ajoutez l'agent aux **exclusions** de votre EDR pour éviter les false positives. L'agent ne fait que lire les Event Log (pas d'injection mémoire, pas de hooks).

**Q : Compatible avec un Active Directory ?**  
R : Oui. Sur un Domain Controller, l'agent capturera les events Kerberos (4768, 4769, etc.) très utiles pour détecter du Pass-the-Ticket ou Kerberoasting.

**Q : Fonctionne-t-il sur Windows Server Core (sans GUI) ?**  
R : Oui. PowerShell ou msiexec suffit pour l'installation.

**Q : Fonctionne-t-il sur Windows ARM64 ?**  
R : Pas encore. v1.1.0-beta = x64 uniquement. ARM64 sur la roadmap v2.

**Q : Différence entre MSI et PowerShell ?**  
R : Le MSI est le format standard industrie (Wazuh, Datadog, etc.) avec wizard graphique, intégration Add/Remove Programs, et compatibilité GPO/Intune native. Le PowerShell + NSSM est une méthode alternative pour environnements custom. **Préférez toujours le MSI quand possible**.

### 14.3 Sécurité

**Q : Que se passe-t-il si quelqu'un vole le token ?**  
R : Ils pourraient envoyer de fausses données depuis votre nom de machine. Régénérez immédiatement le token depuis le dashboard. Bonne pratique : **rotation annuelle des tokens**.

**Q : L'agent peut-il être désactivé par un attaquant ?**  
R : Oui, s'il a les privilèges Administrator local. C'est pourquoi le backend détecte les **agents silencieux** (cf. section 10.3) et crée un finding immédiat. Vous pouvez aussi protéger le service via GPO "Service permissions".

**Q : Les données envoyées sont-elles chiffrées ?**  
R : Oui, TLS 1.2+ obligatoire. Le backend rejette les connexions non-HTTPS.

### 14.4 Licence et support

**Q : Quelle est la licence de l'agent ?**  
R : Propriétaire — Cybersafe-AI © 2026. Code source consultable mais pas redistribuable.

**Q : Y a-t-il un support payant ?**  
R : Le support fait partie de votre abonnement Cybersafe-AI. Contact via le dashboard.

**Q : Puis-je modifier le code de l'agent ?**  
R : Pour usage interne, oui (analyse, debug). Pas de redistribution sans accord écrit.

---

## 15. Annexes

### A. Cheatsheet PowerShell

```powershell
# Service
Get-Service CybersafeAgent
Start-Service CybersafeAgent
Stop-Service CybersafeAgent
Restart-Service CybersafeAgent

# Logs
Get-Content "C:\ProgramData\Cybersafe\logs\agent.log" -Wait -Tail 50

# Config
notepad "C:\ProgramData\Cybersafe\config\config.yaml"

# Désinstallation MSI silencieuse
Get-WmiObject -Class Win32_Product | Where-Object { $_.Name -like "*Cybersafe*" } | ForEach-Object { $_.Uninstall() }

# Health check backend
Invoke-WebRequest -Uri "https://app.cybersafe-ai.com/api/health/" -UseBasicParsing

# Service zombie cleanup
sc.exe delete CybersafeAgent
Remove-Item "HKLM:\SYSTEM\CurrentControlSet\Services\CybersafeAgent" -Recurse -Force
```

### B. Glossaire

| Terme | Définition |
|---|---|
| **SOC** | Security Operations Center — centre opérationnel de cybersécurité |
| **SIEM** | Security Information and Event Management — agrégation et corrélation d'événements |
| **MITRE ATT&CK** | Framework de référence des tactiques et techniques d'attaque |
| **EventID** | Identifiant unique d'un type d'événement Windows |
| **EvtSubscribe** | API Windows pour s'abonner aux Event Log (push-based) |
| **MSI** | Microsoft Installer — format standard d'installation Windows |
| **NSSM** | Non-Sucking Service Manager — outil pour exécuter des programmes comme services Windows |
| **WiX** | Windows Installer XML Toolset — toolchain pour builder des MSI |
| **LocalSystem** | Compte système Windows avec privilèges élevés (équivalent root) |
| **Bookmark** | Marqueur de position dans un Event Log pour reprise après crash |
| **Finding** | Alerte de sécurité générée automatiquement par le backend Cybersafe-AI |
| **GPO** | Group Policy Object — mécanisme de déploiement Active Directory |
| **Intune** | Solution MDM (Mobile Device Management) Microsoft |

### C. Liens utiles

- **Repo GitHub** : https://github.com/AlphaBah-Ib/Cybersafe-AI-Agent
- **Releases** : https://github.com/AlphaBah-Ib/Cybersafe-AI-Agent/releases
- **Issues** : https://github.com/AlphaBah-Ib/Cybersafe-AI-Agent/issues
- **Dashboard Cybersafe** : https://cybersafe-ai-e1u6.vercel.app
- **ADR-001 (architecture)** : [docs/adr/ADR-001-windows-agent-stack.md](adr/ADR-001-windows-agent-stack.md)
- **README agent** : [README.md](../README.md)
- **MITRE ATT&CK** : https://attack.mitre.org/
- **Microsoft Event Log reference** : https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/
- **WiX Toolset** : https://wixtoolset.org/

---

## Support

Pour toute question :

- **Issues GitHub** : https://github.com/AlphaBah-Ib/Cybersafe-AI-Agent/issues
- **Dashboard support** : https://cybersafe-ai-e1u6.vercel.app/support
- **Email** : support@cybersafe-ai.com

---

(c) 2026 Cybersafe-AI — Tous droits réservés.
