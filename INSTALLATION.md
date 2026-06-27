# Cybersafe-AI Agent — Guide d'installation et de configuration de A a Z

Guide unifie pour deployer l'agent Cybersafe-AI sur **Linux** et **Windows**, et le
configurer pour collecter les logs systeme **et** les logs de serveurs web (nginx,
Apache, IIS).

**Derniere mise a jour** : 22 mai 2026
**Version agent** : v1.5.0 (tag Git `aa1d6fe`)
**Repo** : https://github.com/AlphaBah-Ib/Cybersafe-AI-Agent

---

## Table des matieres

1. [Vue d'ensemble : OS vs sources de logs](#1-vue-densemble--os-vs-sources-de-logs)
2. [Etape 0 — Creer l'agent et recuperer le token](#2-etape-0--creer-lagent-et-recuperer-le-token)
3. [Installation Linux](#3-installation-linux)
4. [Configuration Linux](#4-configuration-linux)
5. [Surveiller un serveur web (nginx / Apache)](#5-surveiller-un-serveur-web-nginx--apache)
6. [Installation et configuration Windows](#6-installation-et-configuration-windows)
7. [Surveiller IIS sur Windows](#7-surveiller-iis-sur-windows)
8. [Verification end-to-end](#8-verification-end-to-end)
9. [Gestion du service](#9-gestion-du-service)
10. [Desinstallation](#10-desinstallation)
11. [Troubleshooting](#11-troubleshooting)

---

## 1. Vue d'ensemble : OS vs sources de logs

Point essentiel a comprendre avant toute installation : il n'existe **que deux
plateformes d'installation** de l'agent.

| Plateforme | Mode d'installation | Service |
|---|---|---|
| **Linux** (Ubuntu, Debian, RHEL, Rocky, AlmaLinux) | Script `install.sh` | systemd |
| **Windows** (10, 11, Server 2019/2022) | Installeur MSI (ou NSSM legacy) | Service Windows |

Le **serveur web n'est PAS une troisieme plateforme**. C'est un **type de source de
logs** que l'agent sait parser, quel que soit l'OS sur lequel il tourne :

| OS qui heberge l'agent | Sources de logs collectees | Parsers utilises |
|---|---|---|
| **Linux** | syslog / auth.log, **nginx**, **Apache** | `syslog`, `nginx_*`, `apache_*` |
| **Windows** | Event Log (jusqu'a 9 channels), **IIS** | `windows_*`, `iis_*` |

Concretement :
- Un serveur web **nginx ou Apache** tourne sur Linux. C'est donc l'agent **Linux**
  qui surveille ses logs (`/var/log/nginx/access.log`, etc.).
- Un serveur web **IIS** tourne sur Windows. C'est donc l'agent **Windows** qui
  surveille ses logs (`C:\inetpub\logs\LogFiles\...`).

Le dashboard "Web Traffic" cote plateforme agrege ensuite TOUS les events web
(`nginx_*`, `apache_*`, `iis_*`) ensemble, independamment de l'OS d'origine.

**95 % du code de l'agent est partage** entre Linux et Windows. Seuls les modules de
lecture des sources (`platforms/{linux,windows}.py`) et de normalisation
(`parsers/{linux,windows}.py`) sont specifiques a l'OS.

---

## 2. Etape 0 — Creer l'agent et recuperer le token

Cette etape est commune aux deux OS et se fait depuis le dashboard web.

1. Connecte-toi a la plateforme Cybersafe-AI en tant qu'**Admin Entreprise**.
2. Va dans la section de gestion des agents (page d'installation des agents).
3. Cree un nouvel agent : donne-lui un **nom** (ex. `web-prod-01`) et renseigne son
   **hostname**.
4. La plateforme genere un **token d'authentification unique** de la forme
   `csa_xxxxxxxxxxxxxxxxxxxxxxxx`.

> **Important** : le token n'est **affiche qu'une seule fois**, puis il est hashe en
> base. Copie-le immediatement. Si tu le perds, il faudra regenerer un token.

Ce token relie chaque event remonte par l'agent a la bonne **company**
(multi-tenant). Garde-le confidentiel : il vaut une cle d'API.

---

## 3. Installation Linux

### 3.1 Prerequis

- Une distribution Linux avec **systemd** (Ubuntu, Debian, RHEL, Rocky, AlmaLinux...).
- **Python 3.10 ou superieur** + le module `venv`.
- Acces **root** (via `sudo`) pour l'installation.

Sur Debian / Ubuntu, si Python ou venv manquent :

```bash
sudo apt-get update
sudo apt-get install -y python3 python3-venv git
```

Sur RHEL / Rocky / AlmaLinux :

```bash
sudo dnf install -y python3 git
```

### 3.2 Recuperer le code de l'agent

```bash
cd ~
git clone https://github.com/AlphaBah-Ib/Cybersafe-AI-Agent.git cybersafe-agent
cd cybersafe-agent
```

### 3.3 Lancer l'installeur

Le script doit etre lance **en root, depuis la racine du repo** :

```bash
sudo ./install.sh
```

Le script est **idempotent** (le relancer est sans risque). Voici exactement ce
qu'il fait :

1. Cree le groupe et l'utilisateur systeme **`cybersafe`** (sans shell,
   `/usr/sbin/nologin`, pas de home login).
2. Ajoute `cybersafe` aux groupes **`adm`** et **`syslog`** pour lui donner le droit
   de lire `/var/log/auth.log` et consorts **sans etre root**. Si l'un de ces
   groupes n'existe pas (Debian minimal sans rsyslog), il est **cree
   automatiquement** (sinon le service systemd echouerait en `216/GROUP`).
   L'installeur verifie aussi la presence d'une **source de logs** : si ni
   `/var/log/auth.log` (Debian/Ubuntu) ni `/var/log/secure` (RHEL) n'existe,
   il **installe et active `rsyslog`** pour creer ces fichiers — sinon l'agent
   attendrait indefiniment (`File not found: /var/log/auth.log (waiting...)`).
   Si l'install auto echoue (pas de reseau/`apt-get`), installez un demon
   syslog manuellement ou ajustez `log_files` dans `config.yaml`.
3. Cree les repertoires :
   - `/opt/cybersafe-agent` — code de l'agent + virtualenv
   - `/etc/cybersafe` — configuration (lecture seule au runtime)
   - `/var/lib/cybersafe` — etat + log local de l'agent
   - `/var/spool/cybersafe` — spool disque (resilience reseau)
4. Copie le code dans `/opt/cybersafe-agent` et cree un **virtualenv dedie** avec les
   dependances (`requests`, `PyYAML`).
5. Installe la configuration par defaut dans **`/etc/cybersafe/config.yaml`** (a
   partir de `config.example.yaml`) et **reecrit automatiquement** la ligne
   `log_file:` vers `/var/lib/cybersafe/agent.log` (car `/var/log` est en lecture
   seule sous le hardening systemd `ProtectSystem=strict`).
6. Installe et **active** le service systemd `cybersafe-agent` (demarrage au boot)
   mais **ne le demarre PAS** : il faut d'abord renseigner le token.

A la fin, le script affiche les "Next steps" (renseigner le token, demarrer le
service, verifier les logs).

> Le service tourne sous l'utilisateur `cybersafe` avec un **hardening systemd
> strict** : `NoNewPrivileges`, `ProtectSystem=strict`, `ProtectHome`, aucune
> capability Linux, `MemoryMax=256M`, `CPUQuota=50%`. Les seuls chemins inscriptibles
> sont `/var/lib/cybersafe` et `/var/spool/cybersafe`.

---

## 4. Configuration Linux

La configuration vit dans **`/etc/cybersafe/config.yaml`** (proprietaire
`root:cybersafe`, permissions `0640`).

### 4.1 Renseigner le token et l'URL

Edite le fichier :

```bash
sudo nano /etc/cybersafe/config.yaml
```

Remplace le token placeholder par ton vrai token :

```yaml
token: csa_REMPLACE_PAR_TON_TOKEN_ICI      # <- colle ton token ici
api_url: https://cybersafe-ai-production.up.railway.app/api
```

- `token` : le token recupere a l'etape 0.
- `api_url` : l'URL du backend. En production c'est l'URL Railway ci-dessus. En
  test local sur le meme reseau, ce serait par exemple
  `http://192.168.1.133:8000/api`.

### 4.2 Choisir les sources a surveiller

La section `sources:` accepte **deux syntaxes**, mixables dans la meme liste :

**Syntaxe simple** — juste un chemin. Le parser est detecte automatiquement
(syslog Linux). Convient pour `auth.log`, `syslog`, `secure`.

```yaml
sources:
  - /var/log/auth.log        # SSH, sudo, login (Ubuntu/Debian)
  # - /var/log/secure        # equivalent RHEL / Rocky / AlmaLinux
  # - /var/log/syslog        # systeme general
```

**Syntaxe avancee** — un objet avec `type` et `format` explicites, pour router vers
un parser dedie (web). Voir la section suivante.

### 4.3 Demarrer le service

Une fois le token renseigne :

```bash
sudo systemctl start cybersafe-agent
```

Verifie immediatement que tout est OK :

```bash
systemctl status cybersafe-agent
journalctl -u cybersafe-agent -f
sudo tail -f /var/lib/cybersafe/agent.log
```

Le service redemarrera automatiquement en cas d'echec (`Restart=on-failure`) et au
boot de la machine (il est `enable`).

---

## 5. Surveiller un serveur web (nginx / Apache)

C'est ici que l'agent Linux collecte les logs web. On utilise la **syntaxe avancee**
dans `sources:`.

### 5.1 nginx

```yaml
sources:
  - /var/log/auth.log
  - path: /var/log/nginx/access.log
    type: nginx_access
    format: combined          # combined = format nginx par defaut
  - path: /var/log/nginx/error.log
    type: nginx_error
```

### 5.2 Apache

Le format Apache `combined` est identique au `combined` nginx. Le format `common`
(CLF, sans Referer ni User-Agent) est aussi gere. `format: auto` detecte
automatiquement lequel des deux.

Sur Debian / Ubuntu :

```yaml
sources:
  - path: /var/log/apache2/access.log
    type: apache_access
    format: auto              # auto (defaut) | combined | common
```

Sur RHEL / Rocky / AlmaLinux :

```yaml
sources:
  - path: /var/log/httpd/access_log
    type: apache_access
    format: auto
```

### 5.3 Donner a l'agent le droit de lire les logs web

L'utilisateur `cybersafe` doit pouvoir lire les fichiers de log nginx/Apache.
Verifie le proprietaire et le groupe de ces fichiers :

```bash
ls -l /var/log/nginx/
ls -l /var/log/apache2/   # ou /var/log/httpd/
```

Generalement les logs nginx/Apache sont lisibles par le groupe `adm` (auquel
`cybersafe` appartient deja). Si ce n'est pas le cas, ajoute `cybersafe` au groupe
proprietaire des logs (ex. `adm` ou `www-data`) :

```bash
sudo usermod -aG adm cybersafe
# puis redemarre le service pour prendre en compte le nouveau groupe
sudo systemctl restart cybersafe-agent
```

> Note : sous le hardening systemd, `/var/log` est accessible en **lecture** ; seuls
> `/var/lib/cybersafe` et `/var/spool/cybersafe` sont inscriptibles. Lire les logs
> web ne pose donc pas de probleme tant que les permissions de groupe sont bonnes.

Apres toute modification de `config.yaml`, redemarre le service :

```bash
sudo systemctl restart cybersafe-agent
```

---

## 6. Installation et configuration Windows

Sur Windows, l'agent s'installe via un **MSI** et tourne comme **service Windows**
sous le compte `LocalSystem` (requis pour lire le channel Security de l'Event Log).

La procedure complete et detaillee est documentee dans le repo :
**`docs/INSTALLATION-WINDOWS.md`** (couvre MSI, NSSM legacy, GPO/Intune/Ansible,
troubleshooting). Voici le resume.

### 6.1 Prerequis

- Windows 10/11 ou Windows Server 2019/2022.
- Droits administrateur sur la machine.

### 6.2 Installation via MSI (recommande)

1. Telecharge le MSI de l'agent (depuis la page d'installation des agents du
   dashboard, ou les artefacts de build GitHub).
2. Lance l'installeur (double-clic pour l'install interactive, ou en ligne de
   commande pour une install silencieuse).
3. Le MSI installe le service Windows, cree l'arborescence sous
   `C:\ProgramData\Cybersafe\` (config + logs + bookmarks).

### 6.3 Configuration Windows

La config se trouve dans **`C:\ProgramData\Cybersafe\config\config.yaml`**.
Renseigne le `token` et `api_url` comme sur Linux. La section `windows:` permet de
choisir les channels Event Log a surveiller ; si elle est absente, l'agent utilise
des valeurs par defaut alignees MITRE ATT&CK (Security, System, PowerShell,
Defender, Task Scheduler, WinRM, RDP, Sysmon si present).

### 6.4 Demarrer le service

```powershell
Start-Service CybersafeAgent
Get-Service CybersafeAgent
```

Logs de l'agent : `C:\ProgramData\Cybersafe\logs\agent.log`.

---

## 7. Surveiller IIS sur Windows

IIS ecrit ses logs au format **W3C Extended** (auto-descriptif via l'en-tete
`#Fields:`). L'agent Windows sait les tailer, y compris la rotation par date.

Dans `C:\ProgramData\Cybersafe\config\config.yaml`, ajoute une source de type
`iis_access` :

```yaml
sources:
  - path: C:\inetpub\logs\LogFiles\W3SVC1\u_ex*.log   # PATTERN recommande
    type: iis_access
```

> **Pourquoi un pattern `u_ex*.log` et pas un chemin fixe ?** IIS effectue sa
> rotation **par date de nom de fichier** : `u_ex260522.log` devient
> `u_ex260523.log` a minuit (pas une troncature). Un chemin fixe "mourrait" a
> minuit. Le pattern `u_ex*.log` suit automatiquement le fichier actif (le plus
> recent par date de modification) et bascule a minuit **sans perte de donnees**
> (l'ancien fichier est draine avant la bascule).

Le parser `iis_access` extrait l'IP client (`c-ip`), la methode, le path, la query,
le status, le sous-status, le User-Agent, le Referer et le temps de reponse.

> A noter : `iis_access` fonctionne aussi sur Linux si tu recois des logs W3C via un
> reverse proxy ou un CDN.

Redemarre le service apres modification :

```powershell
Restart-Service CybersafeAgent
```

---

## 8. Verification end-to-end

Objectif : confirmer que les events remontent bien jusqu'au dashboard.

### 8.1 Cote agent

- **Linux** : `journalctl -u cybersafe-agent -f` doit montrer l'agent qui lit les
  fichiers et envoie les batches. `sudo tail -f /var/lib/cybersafe/agent.log`.
- **Windows** : consulter `C:\ProgramData\Cybersafe\logs\agent.log`.

### 8.2 Generer du trafic de test

Pour un serveur web, genere quelques requetes (dont une qui declenche une regle) :

```bash
# requete legitime (200)
curl http://localhost/

# 404 -> alimente la regle "Mass 404" si repete
curl http://localhost/page-qui-nexiste-pas

# tentative type path traversal (declenche la regle Path traversal)
curl "http://localhost/../../etc/passwd"
```

### 8.3 Cote dashboard

1. Va sur le dashboard **Web Traffic** de la plateforme.
2. Verifie que les compteurs ne sont plus a 0 : total des events web, top IPs / paths
   / user-agents, breakdown des codes HTTP (2xx/3xx/4xx/5xx), repartition par pays.
3. Si une regle a matche (ex. path traversal, mass 404), un **finding** doit
   apparaitre dans le dashboard SOC.

> Si le dashboard Web Traffic affiche encore 0, c'est presque toujours soit (a) le
> service agent pas demarre, soit (b) un mauvais token / mauvaise `api_url`, soit
> (c) l'agent n'a pas les droits de lecture sur les logs web (voir section 5.3).

---

## 9. Gestion du service

### Linux (systemd)

```bash
sudo systemctl start cybersafe-agent      # demarrer
sudo systemctl stop cybersafe-agent       # arreter
sudo systemctl restart cybersafe-agent    # redemarrer (apres edit config)
systemctl status cybersafe-agent          # statut
journalctl -u cybersafe-agent -f          # logs en direct (journald)
sudo tail -f /var/lib/cybersafe/agent.log # log local de l'agent
```

### Windows

```powershell
Start-Service CybersafeAgent
Stop-Service CybersafeAgent
Restart-Service CybersafeAgent
Get-Service CybersafeAgent
```

---

## 10. Desinstallation

### Linux

```bash
cd ~/cybersafe-agent
sudo ./uninstall.sh
```

### Windows

Via le Panneau de configuration (Add/Remove Programs) ou
`msiexec /x` (voir `docs/INSTALLATION-WINDOWS.md`, section desinstallation).

---

## 11. Troubleshooting

**Le service ne demarre pas (Linux).**
Verifie le statut et les logs : `systemctl status cybersafe-agent` puis
`journalctl -u cybersafe-agent -n 50`. Cause frequente : token encore au placeholder
`csa_REMPLACE_PAR_TON_TOKEN_ICI`.

**Erreur d'ecriture sur le log (Linux).**
Si `log_file:` pointe vers `/var/log/...` dans `config.yaml`, l'agent echouera a
cause de `ProtectSystem=strict`. La ligne doit pointer vers
`/var/lib/cybersafe/agent.log` (l'installeur le fait automatiquement, mais une config
preexistante peut etre restee sur `/var/log`).

**L'agent ne lit pas les logs web (Linux).**
L'utilisateur `cybersafe` n'a pas les droits de lecture. Verifie le groupe
proprietaire des logs (`ls -l /var/log/nginx/`) et ajoute `cybersafe` au bon groupe,
puis `sudo systemctl restart cybersafe-agent` (voir section 5.3).

**Les logs IIS ne sont pas suivis apres minuit (Windows).**
Tu as probablement utilise un chemin fixe au lieu d'un pattern. Utilise
`u_ex*.log` (voir section 7).

**Le dashboard Web Traffic affiche 0.**
Service pas demarre, mauvais token/URL, ou pas de droit de lecture sur les logs.
Verifie d'abord les logs de l'agent (section 8.1).

---

*Document genere pour Cybersafe-AI — agent v1.5.0. Pour les details Windows
avances, se referer a `docs/INSTALLATION-WINDOWS.md` dans le repo agent.*
