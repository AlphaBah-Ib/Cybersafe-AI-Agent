"""
Tail des Windows Event Log via pywin32 (SOC-200 / Phase 2).

Cette implémentation lit en continu les channels Event Log Windows
configurés (Security, System, PowerShell, etc.) et émet chaque event
sous forme de JSON sérialisé via le callback fourni.

Architecture :
  - 1 thread par channel (parallèle à LinuxLogTailer)
  - Subscription PUSH-based via EvtSubscribe (API moderne, CPU-efficient)
  - Filtrage XPath natif (sélection des EventIDs côté kernel Windows)
  - Bookmarks Windows natifs (xml) persistés sur disque pour continuité
    après redémarrage de l'agent (résilience SOC critique)

Le format JSON émis est consommé par cybersafe_agent.parsers.windows.line_to_event()
qui le normalise en dict standard backend.

Requiert : pywin32 (>= 305 recommandé).
Installation : pip install pywin32

Documentation Microsoft EventLog API :
  https://learn.microsoft.com/en-us/windows/win32/wes/windows-event-log

Historique :
  - SOC-200 : implémentation initiale Phase 2 Windows
"""
import json
import logging
import glob
import os
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, List, Optional


logger = logging.getLogger("cybersafe.tailer.windows")


# =============================================================================
# Fail-fast : pywin32 absent
# =============================================================================
# Cet import lèvera ImportError clair au démarrage si l'agent tourne
# sans pywin32 installé. Mieux qu'un crash mystérieux 30s plus tard.

try:
    import win32evtlog  # noqa: F401
    import win32event   # noqa: F401
    import winerror     # noqa: F401
    import pywintypes   # noqa: F401
except ImportError as exc:  # pragma: no cover
    raise ImportError(
        "Le module pywin32 est requis pour l'agent Windows. "
        "Installation : pip install pywin32"
    ) from exc


# =============================================================================
# Constantes : channels par défaut + EventIDs critiques (alignés ADR-001)
# =============================================================================
# Ces valeurs sont les DÉFAUTS si l'utilisateur n'a rien configuré dans
# config.yaml. Voir docs/adr/ADR-001-windows-agent-stack.md pour la
# justification de chaque channel et EventID.

DEFAULT_WINDOWS_CHANNELS = [
    "Security",                                          # Tier 1
    "System",                                            # Tier 1
    "Application",                                       # Tier 1 (legacy apps)
    "Microsoft-Windows-PowerShell/Operational",          # Tier 2 (scripts)
    "Microsoft-Windows-Windows Defender/Operational",    # Tier 2 (AV)
    "Microsoft-Windows-TaskScheduler/Operational",       # Tier 3 (persist)
    "Microsoft-Windows-WinRM/Operational",               # Tier 3 (remote)
    "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational",  # RDP
    "Microsoft-Windows-Sysmon/Operational",              # Bonus (EDR-like)
]

# EventIDs filtrés sur le channel Security (XPath natif).
# Pour les autres channels, on prend TOUS les events (déjà filtrés
# par la sélection des channels eux-mêmes).
DEFAULT_SECURITY_EVENT_IDS = [
    # Authentication
    4624, 4625, 4647, 4648, 4672, 4673,
    # Process & Service
    4688, 4697,
    # Object access
    4663,
    # Audit policy (CRITIQUE - attaquant efface ses traces)
    4719, 1102,
    # Account management
    4720, 4722, 4724, 4725, 4728, 4732, 4738,
    # Kerberos (AD)
    4768, 4769,
]

# Subscription flags (cf. win32evtlog SubscribeFlag constants)
# StartAtOldestRecord = remonter dans l'historique au démarrage
# StartAfterBookmark = continuer après le dernier bookmark sauvé
_EvtSubscribeToFutureEvents = 1
_EvtSubscribeStartAtOldestRecord = 2
_EvtSubscribeStartAfterBookmark = 3

# Timeout en ms pour attendre un event lors du polling de la subscription.
# 1000 ms = check toutes les 1s si on doit s'arrêter (stop_event).
_SUBSCRIPTION_WAIT_TIMEOUT_MS = 1000  # kept for backward compat, unused since pull refactor
_POLL_INTERVAL_SECONDS = 2.0  # polling interval for EvtNext (pull mode)


# =============================================================================
# Helpers : XPath query & XML -> dict parsing
# =============================================================================

def _build_xpath_query(channel: str, security_event_ids: List[int]) -> str:
    """
    Construit le XPath query pour filtrer côté kernel Windows.

    Pour le channel 'Security', on filtre sur les EventIDs configurés
    (économise massivement de CPU côté agent vs filtrage Python).
    Pour les autres channels, on prend tous les events (le filtrage
    est déjà fait par le choix des channels).

    Référence XPath WEvtApi:
      https://learn.microsoft.com/en-us/windows/win32/wes/consuming-events
    """
    if channel == "Security" and security_event_ids:
        # Build "EventID=X or EventID=Y or ..." pour les IDs configurés
        eid_clauses = " or ".join(
            f"EventID={int(eid)}" for eid in security_event_ids
        )
        return f"*[System[({eid_clauses})]]"

    # Pour les autres channels : tous les events
    return "*"


def _parse_event_xml(xml_str: str) -> dict:
    """
    Parse l'XML d'un event Windows en dict Python compact.

    Format Windows XML (simplifié) :
        <Event>
          <System>
            <Provider Name="..."/>
            <EventID>4625</EventID>
            <Level>4</Level>
            <TimeCreated SystemTime="..."/>
            <Computer>DESKTOP-ABC</Computer>
            <Channel>Security</Channel>
          </System>
          <EventData>
            <Data Name="TargetUserName">admin</Data>
            <Data Name="IpAddress">192.168.1.100</Data>
            ...
          </EventData>
        </Event>

    Sortie dict :
        {
            "channel": "Security",
            "event_id": 4625,
            "level": "Information",
            "time_created": "ISO 8601 UTC",
            "computer": "DESKTOP-ABC",
            "provider": "Microsoft-Windows-Security-Auditing",
            "event_data": {
                "TargetUserName": "admin",
                "IpAddress": "192.168.1.100",
                ...
            }
        }

    Robustesse : si une clé manque, on dégrade gracieusement (chaîne vide
    ou dict vide), pas de crash.
    """
    import xml.etree.ElementTree as ET

    try:
        root = ET.fromstring(xml_str)
    except ET.ParseError as exc:
        logger.warning(f"Failed to parse event XML: {exc}")
        return {
            "channel": "Unknown",
            "event_id": 0,
            "level": "Information",
            "time_created": datetime.now(timezone.utc).isoformat(),
            "computer": "",
            "provider": "",
            "event_data": {},
        }

    # Namespace par défaut Windows Event XML
    ns = {"e": "http://schemas.microsoft.com/win/2004/08/events/event"}

    def _findtext(path: str, default: str = "") -> str:
        el = root.find(path, ns)
        return (el.text or default) if el is not None else default

    def _getattr(path: str, attr: str, default: str = "") -> str:
        el = root.find(path, ns)
        if el is None:
            return default
        return el.attrib.get(attr, default)

    # === Section System ===
    channel = _findtext("e:System/e:Channel", "Unknown")
    event_id_str = _findtext("e:System/e:EventID", "0")
    try:
        event_id = int(event_id_str)
    except (ValueError, TypeError):
        event_id = 0

    level_str = _findtext("e:System/e:Level", "4")
    level_map = {"1": "Critical", "2": "Error", "3": "Warning",
                 "4": "Information", "5": "Verbose"}
    level = level_map.get(level_str, "Information")

    time_created = _getattr("e:System/e:TimeCreated", "SystemTime",
                            datetime.now(timezone.utc).isoformat())
    computer = _findtext("e:System/e:Computer", "")
    provider = _getattr("e:System/e:Provider", "Name", "")

    # === Section EventData ===
    event_data = {}
    event_data_el = root.find("e:EventData", ns)
    if event_data_el is not None:
        for data_el in event_data_el.findall("e:Data", ns):
            name = data_el.attrib.get("Name", "").strip()
            value = (data_el.text or "").strip()
            if name and value not in ("", "-"):
                event_data[name] = value

    return {
        "channel": channel,
        "event_id": event_id,
        "level": level,
        "time_created": time_created,
        "computer": computer,
        "provider": provider,
        "event_data": event_data,
    }


# =============================================================================
# Bookmark management (persistance disque)
# =============================================================================
# Les bookmarks Windows permettent de reprendre la lecture des events là
# où on s'était arrêté après un redémarrage de l'agent. Critique pour ne
# perdre aucun event de sécurité pendant les Windows Updates ou reboots.

def _bookmark_path(bookmarks_dir: str, channel: str) -> str:
    """Chemin disque où sauvegarder le bookmark XML d'un channel donné."""
    # Sanitize channel name pour usage filesystem (slashes, espaces interdits)
    safe_name = channel.replace("/", "_").replace(" ", "_").replace("\\", "_")
    return os.path.join(bookmarks_dir, f"{safe_name}.xml")


def _load_bookmark(bookmarks_dir: str, channel: str) -> Optional[str]:
    """
    Charge le bookmark XML depuis le disque s'il existe.

    Retourne None si pas de bookmark (premier démarrage) ou si lecture
    échoue (corruption). Dans ce dernier cas l'agent démarrera depuis
    le record le plus ancien (option de fallback safe).
    """
    path = _bookmark_path(bookmarks_dir, channel)
    if not os.path.exists(path):
        return None

    try:
        with open(path, "r", encoding="utf-8") as f:
            content = f.read().strip()
            return content if content else None
    except OSError as exc:
        logger.warning(
            f"Could not load bookmark for channel '{channel}': {exc}. "
            f"Will start from oldest record (may re-process old events)."
        )
        return None


def _save_bookmark(bookmarks_dir: str, channel: str, bookmark_xml: str) -> None:
    """
    Sauvegarde le bookmark XML sur disque (atomic write).

    Atomic write : on écrit dans un fichier temporaire puis os.replace()
    pour éviter de corrompre le bookmark en cas de crash en cours d'écriture.
    """
    if not bookmark_xml:
        return

    path = _bookmark_path(bookmarks_dir, channel)
    tmp_path = path + ".tmp"

    try:
        Path(bookmarks_dir).mkdir(parents=True, exist_ok=True)
        with open(tmp_path, "w", encoding="utf-8") as f:
            f.write(bookmark_xml)
        os.replace(tmp_path, path)  # atomic on POSIX & Windows
    except OSError as exc:
        logger.error(
            f"Could not save bookmark for channel '{channel}': {exc}"
        )
        # On ne crash pas : au pire on re-process quelques events au prochain
        # démarrage. L'erreur est loggée pour investigation.


# =============================================================================
# Classe principale : WindowsLogTailer
# =============================================================================

def _is_file_path(source: str) -> bool:
    """
    Distingue un chemin de fichier (a tailer, ex: logs IIS) d'un nom de
    channel Windows Event Log.

    Regle 0 risque : dans le doute -> channel (False), pour ne JAMAIS casser
    le comportement Event Log historique (SOC-200).

    Fichier si la source : contient ":\\" (lettre de lecteur), commence par
    "\\\\" (UNC), ou se termine par ".log". Les channels Event Log
    (ex: "Microsoft-Windows-PowerShell/Operational") n'ont aucun de ces marqueurs.
    """
    if not source:
        return False
    s = source.strip()
    if len(s) >= 3 and s[1] == ":" and s[2] == "\\":
        return True
    if s.startswith("\\\\"):
        return True
    if s.lower().endswith(".log"):
        return True
    return False


class WindowsFileTailer:
    """
    Tail de fichiers texte sur Windows (logs IIS W3C). SOC-303.

    Deux modes selon la forme du path :
      - PATTERN (le path contient '*' ou '?') : suit le fichier le plus
        recemment modifie matchant le glob, et bascule automatiquement quand
        un nouveau fichier apparait (rotation IIS par date a minuit).
      - FIXE : tail un fichier a nom stable, detecte la troncature.

    Pas d'os.fstat().st_ino (non expose sur NTFS) : la rotation est detectee
    via le glob (mode pattern) ou la taille (mode fixe).
    """

    def __init__(self, paths, callback, poll_interval: float = 1.0,
                 rescan_interval: float = 30.0):
        self.paths = paths
        self.callback = callback
        self.poll_interval = poll_interval
        self.rescan_interval = rescan_interval
        self._stop_event = threading.Event()
        self._threads = []

    def start(self):
        if self._threads:
            logger.warning("WindowsFileTailer.start() called twice; ignoring")
            return
        if not self.paths:
            return
        for path in self.paths:
            t = threading.Thread(
                target=self._watch, args=(path,), daemon=True,
                name=f"filetailer-{os.path.basename(path)}",
            )
            t.start()
            self._threads.append(t)

    def stop(self):
        self._stop_event.set()
        if getattr(self, "_file_tailer", None) is not None:
            self._file_tailer.stop()
        for t in self._threads:
            t.join(timeout=3.0)

    def _safe_callback(self, line, path):
        try:
            self.callback(line, path)
        except Exception as exc:
            logger.error(f"Error in callback for {path}: {exc}")

    def _watch(self, path):
        if "*" in path or "?" in path:
            self._watch_pattern(path)
        else:
            self._watch_fixed(path)

    def _resolve_active(self, pattern):
        """Fichier le plus recemment modifie matchant le glob (None si aucun)."""
        matches = glob.glob(pattern)
        if not matches:
            return None
        return max(matches, key=lambda fp: os.path.getmtime(fp))

    def _drain(self, f, path):
        """Lit toutes les lignes restantes jusqu'a EOF (avant bascule)."""
        while True:
            line = f.readline()
            if not line:
                break
            line = line.rstrip("\n").rstrip("\r")
            if line:
                self._safe_callback(line, path)

    def _watch_pattern(self, pattern):
        current = None
        f = None
        last_rescan = 0.0
        first_open = True
        while not self._stop_event.is_set():
            now = time.monotonic()
            if current is None or (now - last_rescan) >= self.rescan_interval:
                last_rescan = now
                active = self._resolve_active(pattern)
                if active and active != current:
                    if f is not None:
                        # Rotation : finir l'ancien fichier avant de basculer
                        self._drain(f, current)
                        f.close()
                    try:
                        f = open(active, "r", encoding="utf-8", errors="replace")
                    except (FileNotFoundError, PermissionError) as exc:
                        logger.warning(f"  [WARN] cannot open {active}: {exc}")
                        f = None
                        self._stop_event.wait(self.poll_interval)
                        continue
                    if first_open:
                        # 1er demarrage : tail -f depuis la fin
                        f.seek(0, os.SEEK_END)
                        first_open = False
                        logger.info(f"  [WATCH] {active} (active, from end)")
                    else:
                        # Rotation : lire le nouveau fichier depuis le debut
                        logger.info(f"  [ROTATE] {active} (new file, from start)")
                    current = active
            if f is None:
                self._stop_event.wait(self.poll_interval)
                continue
            line = f.readline()
            if line:
                line = line.rstrip("\n").rstrip("\r")
                if line:
                    self._safe_callback(line, current)
                continue
            self._stop_event.wait(self.poll_interval)
        if f is not None:
            f.close()

    def _watch_fixed(self, path):
        while not self._stop_event.is_set():
            try:
                with open(path, "r", encoding="utf-8", errors="replace") as f:
                    f.seek(0, os.SEEK_END)
                    last_pos = f.tell()
                    logger.info(f"  [WATCH] {path}")
                    while not self._stop_event.is_set():
                        line = f.readline()
                        if line:
                            last_pos = f.tell()
                            line = line.rstrip("\n").rstrip("\r")
                            if line:
                                self._safe_callback(line, path)
                            continue
                        self._stop_event.wait(self.poll_interval)
                        try:
                            if os.path.getsize(path) < last_pos:
                                logger.info(f"  [ROTATE] {path} (truncated)")
                                break
                        except FileNotFoundError:
                            logger.warning(f"  [WARN] File disappeared: {path}")
                            self._stop_event.wait(2.0)
                            break
            except PermissionError:
                logger.error(f"  [ERROR] Permission denied: {path}")
                return
            except FileNotFoundError:
                logger.warning(f"  [WARN] File not found: {path} (waiting...)")
                self._stop_event.wait(5.0)
            except Exception as exc:
                logger.error(f"  [ERROR] Unexpected error on {path}: {exc}")
                self._stop_event.wait(5.0)


class WindowsLogTailer:
    """
    Surveille plusieurs channels Windows Event Log et appelle un callback
    pour chaque event détecté.

    L'API publique est identique à LinuxLogTailer pour permettre l'usage
    via la façade cybersafe_agent.tailer.LogTailer (qui détecte l'OS).

    Args:
        paths: Liste de noms de channels Windows à surveiller
            (ex: ["Security", "System", "Microsoft-Windows-PowerShell/Operational"])
        callback: Fonction(line, source_channel) appelée pour chaque event.
            `line` est une chaîne JSON sérialisée, `source_channel` est
            le nom du channel.
        poll_interval: Non utilisé (l'API Windows est push-based via
            EvtSubscribe). Conservé pour compatibilité de signature avec
            LinuxLogTailer.
        bookmarks_dir: Dossier où persister les bookmarks XML
            (default: C:\\ProgramData\\Cybersafe\\bookmarks)
        security_event_ids: Liste des EventIDs à filtrer sur le channel
            Security (XPath natif). Si None, utilise DEFAULT_SECURITY_EVENT_IDS.
    """

    def __init__(
        self,
        paths: List[str],
        callback: Callable[[str, str], None],
        poll_interval: float = 1.0,  # ignoré (compat signature)
        bookmarks_dir: Optional[str] = None,
        security_event_ids: Optional[List[int]] = None,
    ):
        # SOC-303 : separer les sources en channels Event Log et fichiers.
        raw_sources = paths or list(DEFAULT_WINDOWS_CHANNELS)
        self.channels = [s for s in raw_sources if not _is_file_path(s)]
        self._file_paths = [s for s in raw_sources if _is_file_path(s)]
        self.callback = callback
        self._file_tailer = None
        if self._file_paths:
            self._file_tailer = WindowsFileTailer(
                paths=self._file_paths,
                callback=callback,
                poll_interval=poll_interval,
            )
        # poll_interval ignoré : push-based via EvtSubscribe

        self.bookmarks_dir = bookmarks_dir or os.environ.get(
            "PROGRAMDATA",
            r"C:\ProgramData"
        ) + r"\Cybersafe\bookmarks"

        self.security_event_ids = (
            security_event_ids
            if security_event_ids is not None
            else list(DEFAULT_SECURITY_EVENT_IDS)
        )

        self._stop_event = threading.Event()
        self._threads: List[threading.Thread] = []

    def start(self):
        """Démarre un thread par channel (idempotent)."""
        if self._threads:
            logger.warning("WindowsLogTailer.start() called twice; ignoring")
            return
        # SOC-303 : demarrer le sous-tailer fichiers (IIS) s'il existe.
        if self._file_tailer is not None:
            logger.info(
                f"  Starting file tailer for {len(self._file_paths)} file source(s)"
            )
            self._file_tailer.start()

        if not self.channels:
            if self._file_tailer is None:
                logger.warning("No Windows channels configured - tailer is idle")
            return

        # S'assurer que le dossier des bookmarks existe (peut faillir si
        # permissions insuffisantes — on log et continue sans persistance)
        try:
            Path(self.bookmarks_dir).mkdir(parents=True, exist_ok=True)
            logger.info(f"  Bookmarks dir: {self.bookmarks_dir}")
        except OSError as exc:
            logger.warning(
                f"  [WARN] Bookmarks directory not writable ({exc}). "
                f"Events may be re-processed after restart."
            )

        for channel in self.channels:
            t = threading.Thread(
                target=self._subscribe_loop,
                args=(channel,),
                daemon=True,
                name=f"win-tailer-{channel.replace('/', '_')[:30]}",
            )
            t.start()
            self._threads.append(t)
            logger.info(f"  [WATCH] channel: {channel}")

    def stop(self):
        """Arrête proprement tous les threads (timeout 3s par thread)."""
        self._stop_event.set()
        for t in self._threads:
            t.join(timeout=3.0)

    def _subscribe_loop(self, channel: str) -> None:
        """
        Boucle de reception d'events Windows en mode PULL (polling EvtNext).

        Refacto v1.1.0-beta.14 : remplacement du push-based (EvtSubscribe +
        WaitForSingleObject + signal_event) qui se montrait non fiable selon
        les versions Windows (signal_event ne se declenche pas sur Win10/Win11
        avec certains flags). Le mode pull est :
          - Predictible (depend uniquement de l'API Windows native, stable
            depuis Vista)
          - Pattern industrie (Splunk UF, Wazuh, Elastic Beats)
          - Surcout CPU negligeable (8 channels x poll 2s = 4 calls/s)

        Resilience identique :
          - Channel inexistant -> warning + abandon ce channel
          - Acces refuse -> error + abandon ce channel
          - Event XML malforme -> warning + skip cet event
          - 5 EvtNext errors consecutives -> abandon thread (anti-boucle infinie)
        """
        try:
            xpath_query = _build_xpath_query(channel, self.security_event_ids)
            existing_bookmark = _load_bookmark(self.bookmarks_dir, channel)

            # Bookmark : reprise depuis disque OU nouveau vide
            if existing_bookmark:
                try:
                    bookmark_handle = win32evtlog.EvtCreateBookmark(existing_bookmark)
                    flags = _EvtSubscribeStartAfterBookmark
                    logger.info(
                        f"  resuming '{channel}' from saved bookmark"
                    )
                except pywintypes.error as exc:
                    logger.warning(
                        f"  bookmark for '{channel}' invalid ({exc}); "
                        f"starting from current position"
                    )
                    # Bookmark MUST be None when using ToFutureEvents
                    # (Microsoft EvtSubscribe API contract: Bookmark only with StartAfterBookmark)
                    bookmark_handle = None
                    flags = _EvtSubscribeToFutureEvents
            else:
                # Bookmark MUST be None when using ToFutureEvents
                bookmark_handle = None
                flags = _EvtSubscribeToFutureEvents
                logger.info(
                    f"  starting '{channel}' from current position (no bookmark)"
                )

            # Microsoft EvtSubscribe API : SignalEvent OR Callback must be non-NULL.
            # En mode pull on cree un SignalEvent handle mais on n'attend jamais
            # dessus - on poll EvtNext directement avec sleep entre les calls.
            # Reference : pywin32 issue #2377 confirmed pattern.
            signal_event = win32event.CreateEvent(None, False, False, None)
            subscription = win32evtlog.EvtSubscribe(
                channel,
                flags,
                SignalEvent=signal_event,
                Query=xpath_query,
                Bookmark=bookmark_handle,
            )
        except pywintypes.error as exc:
            error_code = exc.winerror if hasattr(exc, "winerror") else 0
            if error_code == winerror.ERROR_EVT_CHANNEL_NOT_FOUND:
                logger.warning(
                    f"  Channel '{channel}' not found on this system "
                    f"(skip - install missing component if needed, e.g. Sysmon)"
                )
            elif error_code == winerror.ERROR_ACCESS_DENIED:
                logger.error(
                    f"  Access denied to channel '{channel}'. "
                    f"Run agent as LocalSystem or with SeSecurityPrivilege."
                )
            else:
                logger.error(
                    f"  Could not subscribe to '{channel}': {exc}"
                )
            return

        # === Boucle de polling pull-based ===
        events_since_last_save = 0
        consecutive_errors = 0
        BOOKMARK_SAVE_INTERVAL = 50

        while not self._stop_event.is_set():
            # Tenter de recuperer un batch d'events
            try:
                events = win32evtlog.EvtNext(subscription, 100, -1, 0)
            except pywintypes.error as exc:
                error_code = exc.winerror if hasattr(exc, "winerror") else 0
                if error_code == winerror.ERROR_NO_MORE_ITEMS:
                    # File vide, normal - sleep 2s puis re-poll
                    self._stop_event.wait(timeout=_POLL_INTERVAL_SECONDS)
                    continue
                consecutive_errors += 1
                logger.error(
                    f"  EvtNext failed on '{channel}' "
                    f"(err {consecutive_errors}/5): {exc}"
                )
                if consecutive_errors >= 5:
                    logger.error(
                        f"  Too many EvtNext errors on '{channel}', "
                        f"stopping thread"
                    )
                    break
                self._stop_event.wait(timeout=_POLL_INTERVAL_SECONDS)
                continue

            consecutive_errors = 0

            if not events:
                # Cas rare : EvtNext retourne [] sans exception
                self._stop_event.wait(timeout=_POLL_INTERVAL_SECONDS)
                continue

            # Traiter chaque event recu
            for event_handle in events:
                if self._stop_event.is_set():
                    break
                try:
                    xml_str = win32evtlog.EvtFormatMessage(
                        None,
                        event_handle,
                        win32evtlog.EvtFormatMessageXml,
                    )
                    event_dict = _parse_event_xml(xml_str)
                    json_line = json.dumps(event_dict, separators=(",", ":"))
                    # Bookmark may be None on cold start (ToFutureEvents)
                    # Create it lazily on first event so we can persist progress
                    if bookmark_handle is None:
                        bookmark_handle = win32evtlog.EvtCreateBookmark(
                            "<BookmarkList></BookmarkList>"
                        )
                    win32evtlog.EvtUpdateBookmark(bookmark_handle, event_handle)
                    try:
                        self.callback(json_line, channel)
                    except Exception as cb_exc:
                        logger.error(
                            f"Error in callback for channel '{channel}': {cb_exc}"
                        )
                    events_since_last_save += 1
                except Exception as exc:
                    logger.warning(
                        f"  Failed to process event on '{channel}': {exc}"
                    )

            # Persistance bookmark periodique
            if events_since_last_save >= BOOKMARK_SAVE_INTERVAL and bookmark_handle is not None:
                self._persist_bookmark(bookmark_handle, channel)
                events_since_last_save = 0

            # Reboucle direct sur EvtNext (peut-etre plus d'events a fetch).
            # Si la queue est vide, on dormira dans la branche
            # except ERROR_NO_MORE_ITEMS ci-dessus.

        # === Sauvegarde finale du bookmark au stop ===
        try:
            if bookmark_handle is not None:
                self._persist_bookmark(bookmark_handle, channel)
                logger.info(f"  bookmark saved on stop for '{channel}'")
            else:
                logger.info(f"  no events received on '{channel}', skip bookmark save")
        except Exception as exc:
            logger.warning(
                f"  could not save final bookmark for '{channel}': {exc}"
            )


    def _persist_bookmark(self, bookmark_handle, channel: str) -> None:
        """Sérialise le bookmark courant en XML et le persiste sur disque."""
        try:
            bookmark_xml = win32evtlog.EvtRender(
                bookmark_handle,
                win32evtlog.EvtRenderBookmark,
            )
            _save_bookmark(self.bookmarks_dir, channel, bookmark_xml)
        except pywintypes.error as exc:
            logger.warning(
                f"  [WARN] EvtRender bookmark failed for '{channel}': {exc}"
            )
