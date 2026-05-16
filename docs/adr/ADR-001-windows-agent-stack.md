# ADR-001 — Stack technologique pour l'agent Windows

| Métadonnée | Valeur |
|---|---|
| **Statut** | Accepté |
| **Date** | 2026-05-16 |
| **Auteurs** | Alpha Bah |
| **Décideurs** | Lead Tech |
| **Contexte produit** | SOC-200 — Phase 2 Agent Windows |

---

## 1. Contexte

Cybersafe-AI démarre la **Phase 2** de son agent : le portage sur Windows.
L'agent Linux existant (Python, déployé sur Ubuntu/Debian via `systemd`) est
en production et envoie ~18 000 events/24h depuis une machine de test
(`bah-alpha`). Le code est modulaire :
cybersafe_agent/
├── config.py     — chargement YAML + validation
├── buffer.py     — accumulation in-memory
├── spool.py      — persistence disque pour resilience
├── parser.py     — normalisation des events
├── sender.py     — envoi HTTPS avec retry/backoff
├── tailer.py     — lecture continue des sources de logs
└── main.py       — orchestrateur

Sur les 7 modules, **6 sont OS-agnostiques** (config, buffer, spool, parser,
sender, main). Seul `tailer.py` lit des fichiers spécifiques à Linux
(`/var/log/auth.log`, `/var/log/syslog`, etc.). Pour Windows, il faudra
lire l'**Event Log** via une API différente.

La question stratégique : **quelle stack technologique pour la version
Windows de l'agent ?**

---

## 2. Options envisagées

### Option A — Python + PyInstaller (RETENUE)

Réutiliser le code Python existant à 95% et compiler en `.exe` standalone
via PyInstaller. Adapter uniquement `tailer.py` pour lire l'Event Log
Windows via le package `pywin32`.

**Pros :**
- ✅ Réutilisation maximale du code existant (6 modules sur 7 inchangés)
- ✅ Une seule codebase à maintenir (bugfix Linux = bugfix Windows automatique)
- ✅ Compétences déjà acquises (équipe maîtrise Python)
- ✅ Cohérence du comportement entre les 2 OS (mêmes config, mêmes retries,
  même format d'envoi backend)
- ✅ Vélocité de développement : ~1 jour pour la v1
- ✅ Écosystème mature : `pywin32` est une lib stable depuis 2002,
  utilisée par des outils SOC pros (Wazuh, ElasticBeats, etc.)

**Cons :**
- ⚠️ Binaire plus lourd (~30-50 MB vs 5-10 MB en Go)
- ⚠️ Startup time ~1-3s (vs <100ms en Go)
- ⚠️ Cross-compilation impossible : il faut un runner Windows pour builder
  le `.exe` (résolu via GitHub Actions `windows-latest`)
- ⚠️ Distribution : `.exe` non-signé déclenchera SmartScreen Windows
  (résolu plus tard avec un certificat EV)

### Option B — Réécrire en Go

Réécrire totalement l'agent en Go pour bénéficier d'un binaire compact
et d'un startup quasi-instantané, avec cross-compilation native.

**Pros :**
- ⚡ Binaire compact (5-10 MB)
- ⚡ Startup <100ms
- ⚡ Footprint mémoire minimal (10-20 MB)
- ⚡ Cross-compilation native Linux → Windows depuis n'importe quel OS

**Cons :**
- ❌ Réécriture complète : 0% de réutilisation
- ❌ 5-7 jours de dev minimum (contre 1 jour pour Option A)
- ❌ Apprentissage Go par l'équipe
- ❌ Maintenance long terme : 2 codebases Python (backend) + Go (agent)
- ❌ Risque de divergence comportementale entre Linux et Windows
- ❌ Surcoût de tests pour rattraper la maturité de l'agent Python

### Option C — Réécrire en C# .NET

Écrire un agent natif Windows en C# .NET, packagé en MSI signable.

**Pros :**
- ✅ Intégration native Windows (services, registry, Event Log)
- ✅ Signing MSI via Authenticode standard
- ✅ Performances natives

**Cons :**
- ❌ Pas portable Linux : il faudrait maintenir 2 agents totalement distincts
- ❌ Réécriture complète : 0% de réutilisation
- ❌ Apprentissage .NET par l'équipe
- ❌ 4-6 jours de dev minimum
- ❌ Maintenance double : code Linux + code Windows à faire évoluer en parallèle

### Tableau récapitulatif

| Critère | Python + PyInstaller | Go | C# .NET |
|---|---|---|---|
| Réutilisation code Linux | **95%** | 0% | 0% |
| Cross-plateforme | Linux + Windows + macOS | Linux + Windows + macOS | Windows uniquement |
| Taille binaire | 30-50 MB | 5-10 MB | 20-40 MB |
| Startup time | 1-3s | <100ms | 200-500ms |
| Footprint mémoire | 50-80 MB | 10-20 MB | 30-50 MB |
| Effort dev v1 | **1 jour** | 5-7 jours | 4-6 jours |
| Codebases à maintenir | **1** | 2 (Python backend + Go) | 2 (Python backend + C#) |
| Signing MSI/EXE | Possible | Possible | Natif |
| Compétences requises | **Python (déjà OK)** | Apprendre Go | Apprendre C# |

---

## 3. Décision

**Nous retenons l'Option A : Python + PyInstaller.**

### Justification

Le facteur décisif est la **maintenabilité long terme**. Avec une seule
codebase Python :

- Tout bugfix s'applique automatiquement aux 2 OS
- Tout nouveau feature (ex: chiffrement TLS-pinning, support gRPC futur)
  ne se code qu'une fois
- Les comportements sont garantis identiques (mêmes retries, mêmes
  formats, mêmes timeouts)
- L'équipe reste focalisée sur la valeur produit, pas sur l'apprentissage
  de stacks parallèles

Les inconvénients (binaire 30-50 MB, startup 1-3s) sont **acceptables**
pour un agent qui :
- Est installé une seule fois sur la machine cliente
- Démarre une seule fois au boot
- N'est jamais relancé en condition normale
- Tourne en tâche de fond avec un footprint mémoire borné (256 MB max
  via `MemoryMax` côté systemd, équivalent attendu sur Windows)

En 2026, un binaire de 50 MB sur une machine PME avec 500 GB de disque
représente 0.01% du stockage. Ce n'est plus un critère discriminant.

---

## 4. Architecture cible

### 4.1 Refactor du module `tailer.py`

Le module `tailer.py` actuel devient une **façade** qui détecte l'OS et
délègue à une implémentation spécifique :
cybersafe_agent/
├── tailer.py                    ← façade publique (compatibilité)
└── platform/                    ← code OS-spécifique
├── init.py
├── base.py                  ← Protocol Tailer + dataclass RawEvent
├── linux.py                 ← LinuxTailer (lit /var/log/*.log)
└── windows.py               ← WindowsTailer (lit Event Log via pywin32)

**Garantie : zéro régression Linux.** L'agent Linux existant en
production continue de fonctionner exactement comme aujourd'hui après
le refactor.

### 4.2 Interface commune (Protocol)

```python
# platform/base.py
from typing import Protocol, Iterator
from dataclasses import dataclass

@dataclass
class RawEvent:
    source: str        # ex: "/var/log/auth.log" ou "Security"
    timestamp: float
    raw: str
    meta: dict         # OS-specific metadata

class Tailer(Protocol):
    def start(self) -> None: ...
    def stop(self) -> None: ...
    def events(self) -> Iterator[RawEvent]: ...
```

### 4.3 Channels Windows Event Log surveillés (v1)

Sélection ciblée sécurité, alignée sur les recommandations MITRE
ATT&CK, Microsoft Security Baselines et CIS Benchmarks :

| Channel | Catégorie | Justification |
|---|---|---|
| `Security` | Tier 1 | Auth, logons, modifications ACL, élévations de privilèges |
| `System` | Tier 1 | Services, drivers, kernel events, redémarrages |
| `Microsoft-Windows-PowerShell/Operational` | Tier 2 | Scripts PowerShell exécutés (vecteur d'attaque moderne) |
| `Microsoft-Windows-Windows Defender/Operational` | Tier 2 | Malwares détectés, scans, quarantaines |
| `Microsoft-Windows-TaskScheduler/Operational` | Tier 3 | Tâches planifiées (persistance d'attaquant classique) |
| `Microsoft-Windows-WinRM/Operational` | Tier 3 | Connexions remote admin |
| `Microsoft-Windows-TerminalServices-LocalSessionManager/Operational` | Tier 3 | Sessions RDP entrantes |
| `Microsoft-Windows-Sysmon/Operational` | Bonus | EDR-like events (si Sysmon installé sur la machine) |

**Channels exclus volontairement** : `Application` (trop bruyant, 50%
d'erreurs d'apps non-sécu), `Setup` (logs Windows Update sans valeur SOC).

### 4.4 Filtrage par EventID sur `Security`

Le channel `Security` génère des milliers d'events/jour dont 90% sont
du bruit. On filtre sur 20 EventIDs critiques alignés MITRE ATT&CK :

| EventID | Description | Tactique MITRE |
|---|---|---|
| 4624 | Successful logon | TA0001 Initial Access |
| 4625 | Failed logon | TA0006 Credential Access |
| 4648 | Logon with explicit credentials | TA0008 Lateral Movement |
| 4672 | Special privileges assigned (admin) | TA0004 Privilege Escalation |
| 4673 | Sensitive privilege use | TA0004 |
| 4688 | Process created | TA0002 Execution |
| 4697 | Service installed | TA0003 Persistence |
| 4663 | Object access | TA0009 Collection |
| 4719 | Audit policy changed | TA0005 Defense Evasion |
| 1102 | Audit log cleared | TA0005 Defense Evasion |
| 4720 | User account created | TA0003 Persistence |
| 4722 | User account enabled | TA0003 |
| 4724 | Password reset attempt | TA0006 |
| 4725 | User account disabled | TA0003 |
| 4728 | User added to security group | TA0004 |
| 4732 | Member added to local group | TA0004 |
| 4738 | User account changed | TA0003 |
| 4647 | User initiated logoff | TA0001 |
| 4634 | Logoff (exclu : trop fréquent) | — |
| 4768/4769 | Kerberos TGT/Service ticket (Active Directory) | TA0006 |

Cette liste est **configurable via `config.yaml`** pour permettre aux
clients d'ajuster selon leurs besoins.

---

## 5. Implications opérationnelles

### 5.1 CI/CD

- **GitHub Actions workflow** `windows-latest` runner pour builder
  le `.exe` à chaque release tag
- **Coût** : gratuit (2000 min/mois sur tier gratuit GitHub, le build
  prend ~3-5 min)
- **Artifact** : `cybersafe-agent-vX.Y.Z-windows.exe` attaché à la
  Release GitHub

### 5.2 Distribution

- **v1** : `.exe` standalone téléchargeable depuis la page agents de
  l'app Cybersafe (page d'installation Windows à créer)
- **v2** (post-démo) : installeur NSIS qui :
  - Place le `.exe` dans `C:\Program Files\Cybersafe Agent\`
  - Installe le service Windows via `NSSM`
  - Demande le token agent (paste depuis l'UI)
  - Démarre le service automatiquement

### 5.3 Service Windows

Pour wrapper le `.exe` Python en service Windows (équivalent
`systemd` sous Linux), on utilise **NSSM** (Non-Sucking Service
Manager) :
- Gestion automatique du restart (équivalent `Restart=on-failure`)
- Logs vers Windows Event Viewer
- Configuration via registry, modifiable via `nssm edit`

Alternative considérée : `pywin32` `win32service`. Rejetée car plus
complexe à débugger et nécessite des privilèges de dev pour tester.

### 5.4 Sécurité

- **Pas de signing** en v1 (déclenchera SmartScreen → docs claire pour
  l'utilisateur)
- **v2 (Q3 2026)** : certificat code-signing EV (cost ~400€/an)
  élimine SmartScreen
- **Permissions** : le service tourne sous `LocalSystem` (accès Event
  Log complet, requis pour le channel `Security`)

---

## 6. Risques et mitigations

| Risque | Impact | Mitigation |
|---|---|---|
| PyInstaller produit un binaire détecté comme malware | Élevé (FAUX POSITIF AV) | Soumettre le `.exe` à Microsoft Defender via le portail Submission for analysis ; ajouter une "Trusted Publisher" via cert EV en v2 |
| `pywin32` plante sur une version Windows non-testée | Moyen | Tester sur Windows 10, 11, Server 2019, Server 2022 dans la CI |
| Le channel `Sysmon` n'existe pas sur la machine | Faible | Détecter l'absence et logger un warning sans crash ; channel optionnel |
| Volume d'events `Security` trop élevé (>10k/min) | Moyen | Filtrage EventIDs en amont ; rate-limiting côté `sender.py` (déjà en place) |
| Le client refuse d'installer en `LocalSystem` | Faible | Documenter qu'un compte de service dédié avec `SeSecurityPrivilege` fonctionne aussi |

---

## 7. Statut

**Accepté** le 2026-05-16.

Cette décision sera révisée si :
- Le footprint mémoire dépasse 256 MB en condition normale
- Les faux-positifs antivirus deviennent un blocker commercial
- Un client major demande explicitement un agent natif (alors envisager
  une réécriture Go ciblée pour ce client)

---

## 8. Références

- [PyInstaller documentation](https://pyinstaller.org/)
- [pywin32 documentation](https://github.com/mhammond/pywin32)
- [MITRE ATT&CK Tactics](https://attack.mitre.org/tactics/enterprise/)
- [Microsoft Security Baselines](https://learn.microsoft.com/en-us/windows/security/threat-protection/windows-security-configuration-framework/windows-security-baselines)
- [CIS Microsoft Windows Benchmarks](https://www.cisecurity.org/benchmark/microsoft_windows_desktop)
- [Windows Event Forwarding (WEF) guidance from MITRE](https://github.com/palantir/windows-event-forwarding)
- [NSSM — Non-Sucking Service Manager](https://nssm.cc/)
