# -*- coding: utf-8 -*-
"""
US-SOC-R15 (agent 2.5.0) — releve et action sur un processus Linux, a partir de /proc.

Utilise UNIQUEMENT par l'unite root cybersafe-process-apply (process_apply.py) ;
aucune commande externe (ni ps, ni ss) : tout est lu dans /proc.

Releve (preuve) : PID, PID parent, utilisateur, nom, executable et son hash,
ligne de commande et son hash, dossier courant, cgroup, heure de demarrage,
boot_id, etat, connexions reseau. JAMAIS l'environnement du processus (secrets).

Action (gel, liberation, arret) :
  1. un pidfd est ouvert sur le PID : il designe CE processus et aucun autre ;
  2. le processus est releve de nouveau et compare a l'empreinte SIGNEE par le
     serveur (PID, heure de demarrage, boot_id, executable, hash de l'executable,
     hash de la ligne de commande, uid) : au moindre ecart, rien n'est envoye ;
  3. le signal part PAR LE PIDFD : un PID reutilise entre-temps ne peut pas etre
     touche ;
  4. le resultat est constate (etat T, sortie du processus).
Les processus « core » (systeme, SSH principal, agent Cybersafe-AI) sont refuses
ici aussi, quel que soit l'ordre recu.
"""
import hashlib
import ipaddress
import os
import pwd
import re
import select
import signal
import time
from datetime import datetime, timezone

PROC = "/proc"
MAX_PID = 4194304
MAX_HASH_BYTES = 256 * 1024 * 1024   # au-dela : hash non calcule (vide), compare tel quel
MAX_CONNECTIONS = 50
MAX_EXE = 1024
MAX_CMDLINE = 4096
MAX_CWD = 1024
MAX_CGROUP = 512
STOP_WAIT = 3.0
KILL_WAIT = 5.0

# Memes listes que le serveur (apps/soc/response/process.py) : defense en profondeur.
CORE_NAMES = frozenset({
    "init", "systemd", "kthreadd", "systemd-journald", "systemd-logind", "systemd-udevd",
    "systemd-networkd", "systemd-resolved", "systemd-timesyncd", "dbus-daemon", "dbus-broker",
    "containerd", "dockerd", "kubelet", "agetty", "polkitd",
})
CRITICAL_NAMES = frozenset({
    "postgres", "postmaster", "mysqld", "mariadbd", "mongod", "redis-server", "nginx",
    "apache2", "httpd", "haproxy", "keycloak", "slapd", "ns-slapd", "named", "chronyd",
    "cron", "crond", "rsyslogd", "java",
})
_CRITICAL_PREFIXES = ("php-fpm",)
_AGENT_MARKERS = ("/opt/cybersafe-agent", "cybersafe_agent")
FINGERPRINT_KEYS = ("pid", "start_ticks", "boot_id", "exe", "exe_sha256", "cmdline_sha256", "uid")

_TCP_STATES = {"01": "ESTABLISHED", "02": "SYN_SENT", "03": "SYN_RECV", "04": "FIN_WAIT1",
               "05": "FIN_WAIT2", "06": "TIME_WAIT", "07": "CLOSE", "08": "CLOSE_WAIT",
               "09": "LAST_ACK", "0A": "LISTEN", "0B": "CLOSING"}
_SOCKET_RE = re.compile(r"^socket:\[([0-9]+)\]$")


class ProcessError(Exception):
    """Releve ou action impossible ; le message est remonte tel quel au serveur."""


def _path(pid, *parts):
    return os.path.join(PROC, str(pid), *parts)


def _read_bytes(path, limit=65536):
    with open(path, "rb") as fh:
        return fh.read(limit)


def boot_id():
    with open(os.path.join(PROC, "sys/kernel/random/boot_id"), "r", encoding="ascii") as fh:
        return fh.read().strip()


def read_stat(pid):
    """(nom, etat, ppid, start_ticks) depuis /proc/<pid>/stat. ProcessError si absent."""
    try:
        raw = _read_bytes(_path(pid, "stat")).decode("utf-8", "replace")
    except (FileNotFoundError, ProcessLookupError):
        raise ProcessError("processus %d introuvable (deja termine)" % pid) from None
    except OSError as exc:
        raise ProcessError("processus %d illisible (%s)" % (pid, exc.strerror or exc)) from None
    left, right = raw.find("("), raw.rfind(")")  # le nom peut contenir espaces et parentheses
    if left < 0 or right < left:
        raise ProcessError("processus %d : /proc/<pid>/stat illisible" % pid)
    fields = raw[right + 2:].split()
    if len(fields) < 20:
        raise ProcessError("processus %d : /proc/<pid>/stat incomplet" % pid)
    return raw[left + 1:right], fields[0], int(fields[1]), fields[19]


def read_uid(pid):
    try:
        for line in _read_bytes(_path(pid, "status")).decode("utf-8", "replace").splitlines():
            if line.startswith("Uid:"):
                return int(line.split()[1])  # uid reel
    except (OSError, ValueError, IndexError):
        pass
    raise ProcessError("processus %d : utilisateur illisible" % pid)


def _readlink(pid, name):
    try:
        return os.readlink(_path(pid, name))
    except OSError:
        return ""


def exe_sha256(pid):
    """Hash du binaire reellement execute (lien /proc/<pid>/exe : valable meme supprime)."""
    digest = hashlib.sha256()
    total = 0
    try:
        with open(_path(pid, "exe"), "rb") as fh:
            while True:
                chunk = fh.read(1024 * 1024)
                if not chunk:
                    break
                total += len(chunk)
                if total > MAX_HASH_BYTES:
                    return ""
                digest.update(chunk)
    except OSError:
        return ""
    return digest.hexdigest()


def _cmdline(pid):
    try:
        raw = _read_bytes(_path(pid, "cmdline"), 1024 * 1024)
    except OSError:
        raw = b""
    text = raw.rstrip(b"\0").replace(b"\0", b" ").decode("utf-8", "replace")
    return text[:MAX_CMDLINE], hashlib.sha256(raw).hexdigest()


def _cgroup(pid):
    try:
        text = _read_bytes(_path(pid, "cgroup"), 8192).decode("utf-8", "replace")
    except OSError:
        return ""
    return ";".join(line.strip() for line in text.splitlines() if line.strip())[:MAX_CGROUP]


def _username(uid):
    try:
        return pwd.getpwuid(uid).pw_name[:64]
    except (KeyError, OSError):
        return ""


def socket_inodes(pid):
    inodes = set()
    try:
        names = os.listdir(_path(pid, "fd"))
    except OSError:
        return inodes
    for name in names:
        try:
            m = _SOCKET_RE.match(os.readlink(_path(pid, "fd", name)))
        except OSError:
            continue
        if m:
            inodes.add(m.group(1))
    return inodes


def _decode_addr(hexaddr):
    host, port = hexaddr.split(":")
    raw = bytes.fromhex(host)
    if len(raw) == 4:
        ip = ".".join(str(b) for b in raw[::-1])
        return "%s:%d" % (ip, int(port, 16))
    words = b"".join(raw[i:i + 4][::-1] for i in range(0, 16, 4))
    return "[%s]:%d" % (ipaddress.IPv6Address(words), int(port, 16))


def _net_rows(base, proto):
    """Lignes de /proc/.../net/<proto> : (local, distant, etat, inode)."""
    try:
        with open(os.path.join(base, "net", proto), "r", encoding="ascii", errors="replace") as fh:
            lines = fh.read().splitlines()[1:]
    except OSError:
        return []
    rows = []
    for line in lines:
        parts = line.split()
        if len(parts) < 10:
            continue
        rows.append((parts[1], parts[2], parts[3], parts[9]))
    return rows


def connections(pid, inodes=None):
    """Connexions du processus, vues depuis SON espace reseau (conteneurs compris)."""
    inodes = socket_inodes(pid) if inodes is None else inodes
    out = []
    if not inodes:
        return out
    for proto in ("tcp", "tcp6", "udp", "udp6"):
        for local, remote, st, inode in _net_rows(_path(pid), proto):
            if inode not in inodes:
                continue
            try:
                entry = {"proto": proto, "local": _decode_addr(local), "remote": _decode_addr(remote),
                         "state": (_TCP_STATES.get(st, st) if proto.startswith("tcp")
                                   else ("UNCONN" if st == "07" else st))}
            except ValueError:
                continue
            out.append(entry)
            if len(out) >= MAX_CONNECTIONS:
                return out
    return out


def classify(ev):
    """(« core » | « critical » | « », motif) — meme logique que le serveur."""
    pid, ppid, name = ev["pid"], ev["ppid"], ev["name"]
    exe, cmd = ev["exe"], ev["cmdline"]
    base = exe.replace(" (deleted)", "").rsplit("/", 1)[-1] or name
    if pid in (1, 2) or ppid == 2:
        return "core", "processus systeme (PID 1 ou thread du noyau)"
    if not exe:
        return "core", "thread du noyau ou executable illisible"
    if base in CORE_NAMES or name in CORE_NAMES:
        return "core", "service systeme indispensable (%s)" % base
    if (base == "sshd" or name == "sshd") and ppid == 1:
        return "core", "service SSH principal"
    if any(m in exe or m in cmd for m in _AGENT_MARKERS):
        return "core", "agent Cybersafe-AI"
    if pid in (os.getpid(), os.getppid()):
        return "core", "agent Cybersafe-AI"
    if base in CRITICAL_NAMES or name in CRITICAL_NAMES or base.startswith(_CRITICAL_PREFIXES):
        return "critical", "service metier critique (%s)" % base
    return "", ""


def capture(pid, listen_port=None):
    """Preuve complete du processus (format attendu par le serveur). ProcessError sinon."""
    if isinstance(pid, bool) or not isinstance(pid, int) or not 1 <= pid <= MAX_PID:
        raise ProcessError("PID invalide : %r" % (pid,))
    name, state, ppid, start = read_stat(pid)
    uid = read_uid(pid)
    exe = _readlink(pid, "exe")
    if len(exe) > MAX_EXE:
        raise ProcessError("processus %d : chemin d'executable trop long" % pid)
    cmdline, cmd_hash = _cmdline(pid)
    ev = {
        "pid": pid, "ppid": ppid, "uid": uid, "username": _username(uid),
        "name": (name or "?")[:64], "exe": exe, "exe_sha256": exe_sha256(pid) if exe else "",
        "cmdline": cmdline, "cmdline_sha256": cmd_hash, "cwd": _readlink(pid, "cwd")[:MAX_CWD],
        "cgroup": _cgroup(pid), "start_ticks": start, "boot_id": boot_id(), "state": state[:1],
        "listen_port": listen_port, "connections": connections(pid),
        "captured_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    }
    # Le processus a-t-il change pendant le releve (PID reutilise) ? Alors rien n'est fiable.
    if read_stat(pid)[3] != start:
        raise ProcessError("processus %d remplace pendant le releve : recommencer" % pid)
    ev["protection"] = classify(ev)[0]
    return ev


def children(pid):
    """PID des enfants directs (informatif : ils ne sont jamais touches)."""
    out = []
    try:
        names = os.listdir(PROC)
    except OSError:
        return out
    for name in names:
        if not name.isdigit():
            continue
        try:
            if read_stat(int(name))[2] == pid:
                out.append(int(name))
        except (ProcessError, ValueError):
            continue
    return sorted(out)


def find_listener(port):
    """PID du processus en ecoute sur ce port (TCP, sinon UDP). ProcessError si aucun."""
    if isinstance(port, bool) or not isinstance(port, int) or not 1 <= port <= 65535:
        raise ProcessError("port invalide : %r" % (port,))
    suffix = ":%04X" % port
    wanted = set()
    for proto, state in (("tcp", "0A"), ("tcp6", "0A")):
        for local, _, st, inode in _net_rows(PROC, proto):
            if st == state and local.endswith(suffix) and inode != "0":
                wanted.add(inode)
    if not wanted:
        for proto in ("udp", "udp6"):
            for local, _, st, inode in _net_rows(PROC, proto):
                if st == "07" and local.endswith(suffix) and inode != "0":
                    wanted.add(inode)
    if not wanted:
        raise ProcessError("aucun processus en ecoute sur le port %d (vu depuis l'hote)" % port)
    owners = []
    for name in os.listdir(PROC):
        if not name.isdigit():
            continue
        pid = int(name)
        if socket_inodes(pid) & wanted:
            try:
                owners.append((int(read_stat(pid)[3]), pid))
            except ProcessError:
                continue
    if not owners:
        raise ProcessError("port %d en ecoute mais processus proprietaire introuvable "
                           "(conteneur ou droits insuffisants)" % port)
    owners.sort()
    return owners[0][1], len(owners)   # le plus ancien (processus maitre), nombre de partageurs


def server_text(value):
    """Texte tel que le serveur le conserve (caracteres de controle -> « ? »)."""
    return "".join("?" if (ord(c) < 32 or ord(c) == 127) else c for c in str(value or ""))


def check_fingerprint(fp, ev):
    """Liste des ecarts entre l'empreinte signee et le processus releve (vide : identique).
    Le chemin est compare tel que le serveur l'a conserve : un nom d'executable piege
    (retour a la ligne...) ne permet pas d'echapper a l'action."""
    live = dict(ev, exe=server_text(ev.get("exe")))
    return [k for k in FINGERPRINT_KEYS if fp.get(k) != live.get(k)]


def _state(pid):
    try:
        return read_stat(pid)[1]
    except ProcessError:
        return None


def _wait_state(pid, start, predicate, timeout):
    deadline = time.monotonic() + timeout
    while True:
        try:
            _, st, _, current = read_stat(pid)
        except ProcessError:
            return None
        if current != start:
            return None
        if predicate(st):
            return st
        if time.monotonic() >= deadline:
            return st
        time.sleep(0.05)


def _wait_exit(pidfd, timeout):
    poller = select.poll()
    poller.register(pidfd, select.POLLIN)
    return bool(poller.poll(int(timeout * 1000)))


def act(action, fp):
    """
    Gel (quarantine_process), liberation (release_process) ou arret (kill_process) du
    processus designe par l'empreinte signee. Renvoie (ok, detail, preuve avant action).
    """
    if not hasattr(os, "pidfd_open") or not hasattr(signal, "pidfd_send_signal"):
        return False, "noyau ou Python sans pidfd : action refusee (securite)", None
    pid = fp.get("pid")
    if isinstance(pid, bool) or not isinstance(pid, int) or not 2 <= pid <= MAX_PID:
        return False, "empreinte invalide (PID)", None
    try:
        pidfd = os.pidfd_open(pid)
    except ProcessLookupError:
        return False, "processus %d introuvable : deja termine (rien n'a ete fait)" % pid, None
    except OSError as exc:
        return False, "pidfd impossible sur %d (%s) : action refusee" % (pid, exc.strerror or exc), None
    try:
        try:
            ev = capture(pid)
        except ProcessError as exc:
            return False, "%s : rien n'a ete fait" % exc, None
        diff = check_fingerprint(fp, ev)
        if diff:
            return (False, "processus %d different de celui inspecte (%s) : PID reutilise, binaire "
                    "remplace ou redemarrage. Rien n'a ete fait ; inspecter de nouveau."
                    % (pid, ", ".join(diff)), ev)
        level, why = classify(ev)
        if level == "core":
            return False, "processus protege (%s) : jamais cible. Rien n'a ete fait." % why, ev
        kids = children(pid)
        note = (" %d processus enfant(s) non touche(s) : %s." % (len(kids), ", ".join(map(str, kids[:10])))
                if kids else "")
        start = ev["start_ticks"]
        try:
            if action == "quarantine_process":
                if ev["state"] == "Z":
                    return False, "processus %d deja termine (zombie)." % pid, ev
                if ev["state"] in ("T", "t"):
                    return True, "processus %d deja gele (etat %s)." % (pid, ev["state"]) + note, ev
                signal.pidfd_send_signal(pidfd, signal.SIGSTOP)
                st = _wait_state(pid, start, lambda s: s in ("T", "t"), STOP_WAIT)
                if st in ("T", "t"):
                    return True, ("processus %s (PID %d) gele (SIGSTOP), etat T constate."
                                  % (ev["name"], pid)) + note, ev
                return False, "SIGSTOP envoye mais etat constate : %s" % (st or "processus disparu"), ev
            if action == "release_process":
                if ev["state"] not in ("T", "t"):
                    return True, "processus %d n'etait pas gele (etat %s) : rien a liberer." % (pid, ev["state"]), ev
                signal.pidfd_send_signal(pidfd, signal.SIGCONT)
                st = _wait_state(pid, start, lambda s: s not in ("T", "t"), STOP_WAIT)
                if st is not None and st not in ("T", "t"):
                    return True, "processus %s (PID %d) libere (SIGCONT), etat %s." % (ev["name"], pid, st), ev
                return False, "SIGCONT envoye mais etat constate : %s" % (st or "processus disparu"), ev
            if action == "kill_process":
                if ev["state"] == "Z":
                    return True, "processus %d deja termine (zombie)." % pid, ev
                signal.pidfd_send_signal(pidfd, signal.SIGKILL)
                if _wait_exit(pidfd, KILL_WAIT):
                    return True, ("processus %s (PID %d) termine (SIGKILL), sortie constatee."
                                  % (ev["name"], pid)) + note, ev
                return False, "SIGKILL envoye mais processus toujours present apres %ds" % KILL_WAIT, ev
        except ProcessLookupError:
            return False, "processus %d termine avant le signal : rien n'a ete fait." % pid, ev
        except PermissionError as exc:
            return False, "signal refuse par le systeme (%s)" % (exc.strerror or exc), ev
        return False, "action inconnue : %s" % action, ev
    finally:
        os.close(pidfd)


def inspect(target):
    """INSPECT_PROCESS : « port:<n> » ou « pid:<n> » -> (ok, detail, preuve)."""
    m = re.match(r"^(port|pid):([1-9][0-9]{0,6})$", str(target or ""))
    if not m:
        return False, "cible d'inspection invalide : %r" % (target,), None
    kind, num = m.group(1), int(m.group(2))
    try:
        if kind == "port":
            pid, sharing = find_listener(num)
            ev = capture(pid, listen_port=num)
            extra = (" %d processus partagent ce port (le plus ancien est releve)." % sharing
                     if sharing > 1 else "")
        else:
            ev = capture(num)
            extra = ""
    except ProcessError as exc:
        return False, str(exc), None
    except OSError as exc:
        return False, "releve impossible (%s)" % (exc.strerror or exc), None
    kids = children(ev["pid"])
    if kids:
        extra += " %d processus enfant(s)." % len(kids)
    return True, ("releve de %s (PID %d) : %s.%s" % (ev["name"], ev["pid"], ev["exe"] or "?", extra)), ev
