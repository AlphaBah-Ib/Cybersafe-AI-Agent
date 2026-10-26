# -*- coding: utf-8 -*-
"""
US-SOC-R12 porte 3 (AGENT 2.1.0) — blocage de plage d'adresses.

- order_guard : block_ip_range / unblock_ip_range ; plage CIDR exacte, /24 minimum
  (IPv4) ou /48 (IPv6) ; refus si la plage touche un reseau reserve ou interne ;
  justification obligatoire (texte signe v2, sans caractere de controle) ;
- remediation : regle iptables / ip6tables reperee par « cybersafe-range:<plage> » ;
  anti-lockout : refus si une session SSH active vient de la plage.

    cd ~/Projects/Cybersafe-AI-Agent
    python patch_agent_210.py --check
    python patch_agent_210.py --apply
"""
import os
import shutil
import sys

EDITS = {
    "cybersafe_agent/__init__.py": ('__version__ = "2.1.0"', [
        ('__version__ = "2.0.0"', '__version__ = "2.1.0"'),
    ]),
    "cybersafe_agent/order_guard.py": ("[R12-P3]", [
        ('ALLOWED_ACTIONS = frozenset({"ban_ip", "unban_ip", "rate_limit_ip", "remove_rate_limit"})\n',
         'ALLOWED_ACTIONS = frozenset({"ban_ip", "unban_ip", "rate_limit_ip", "remove_rate_limit",\n'
         '                             "block_ip_range", "unblock_ip_range"})  # [R12-P3]\n'
         '# [R12-P3] plages : taille maximale, reseaux jamais bloquables par plage.\n'
         'RANGE_ACTIONS = frozenset({"block_ip_range", "unblock_ip_range"})\n'
         'RANGE_MIN_PREFIX = {4: 24, 6: 48}\n'
         '_FORBIDDEN_RANGES = tuple(ipaddress.ip_network(n) for n in (\n'
         '    "0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16",\n'
         '    "172.16.0.0/12", "192.168.0.0/16", "224.0.0.0/4", "240.0.0.0/4",\n'
         '    "::/128", "::1/128", "::ffff:0:0/96", "fc00::/7", "fe80::/10", "ff00::/8",\n'
         '))\n'),
        ('    "rate_limit_ip": {"rate_per_minute": (1, 600), "burst": (1, 100)},\n',
         '    "rate_limit_ip": {"rate_per_minute": (1, 600), "burst": (1, 100)},\n'
         '    "block_ip_range": {"justification": ("str", 10, 500)},\n'),
        ('    for name, (lo, hi) in spec.items():\n'
         '        value = params.get(name)\n',
         '    for name, bounds in spec.items():\n'
         '        value = params.get(name)\n'
         '        if len(bounds) == 3:  # texte : ("str", longueur min, longueur max)\n'
         '            _, lo, hi = bounds\n'
         '            if not isinstance(value, str):\n'
         '                raise OrderRejected("parametre %s : texte attendu" % name)\n'
         '            if any(ord(c) < 32 or ord(c) == 127 for c in value):\n'
         '                raise OrderRejected("parametre %s : caracteres de controle interdits" % name)\n'
         '            if not lo <= len(value.strip()) <= hi:\n'
         '                raise OrderRejected("parametre %s : longueur hors bornes (%s a %s)" % (name, lo, hi))\n'
         '            continue\n'
         '        lo, hi = bounds\n'),
        ('def check_ip(order):\n'
         '    raw = order.get("target_ip")\n',
         'def check_range(order):\n'
         '    """[R12-P3] Plage CIDR exacte, taille bornee, jamais un reseau reserve ou interne."""\n'
         '    raw = order.get("target_ip")\n'
         '    if not isinstance(raw, str) or "/" not in raw:\n'
         '        raise OrderRejected("plage invalide (notation CIDR attendue): %r" % (raw,))\n'
         '    try:\n'
         '        net = ipaddress.ip_network(raw.strip(), strict=True)\n'
         '    except ValueError:\n'
         '        raise OrderRejected("plage invalide: %r" % (raw,)) from None\n'
         '    if net.prefixlen < RANGE_MIN_PREFIX[net.version]:\n'
         '        raise OrderRejected("plage trop large: %s (/%d minimum)" % (net, RANGE_MIN_PREFIX[net.version]))\n'
         '    if order.get("action") == "unblock_ip_range":\n'
         '        return  # une levee est toujours permise\n'
         '    for forbidden in _FORBIDDEN_RANGES:\n'
         '        if forbidden.version == net.version and net.overlaps(forbidden):\n'
         '            raise OrderRejected("plage %s refusee (reseau reserve ou interne)" % net)\n'
         '\n'
         '\n'
         'def check_ip(order):\n'
         '    if order.get("action") in RANGE_ACTIONS:  # [R12-P3]\n'
         '        return check_range(order)\n'
         '    raw = order.get("target_ip")\n'),
    ]),
    "cybersafe_agent/remediation.py": ("[R12-P3]", [
        ('import hashlib\n', 'import hashlib\nimport ipaddress\n'),
        ('    if action in ("ban_ip", "rate_limit_ip"):\n'
         '        active = _active_ssh_source_ips()\n'
         '        if ip in active:\n',
         '    if action in ("ban_ip", "rate_limit_ip", "block_ip_range"):  # [R12-P3] plage comprise\n'
         '        active = _active_ssh_source_ips()\n'
         '        if ip in active or _range_contains_any(ip, active):\n'),
        ('    elif action == "remove_rate_limit":\n'
         '        ok, detail = _remove_rate_limit(ip)\n',
         '    elif action == "remove_rate_limit":\n'
         '        ok, detail = _remove_rate_limit(ip)\n'
         '    elif action == "block_ip_range":\n'
         '        ok, detail = _apply_range_block(ip)\n'
         '    elif action == "unblock_ip_range":\n'
         '        ok, detail = _remove_range_block(ip)\n'),
        ('def _report(api_url, token, order_id, success, detail, rule_present=None):\n',
         '''# [R12-P3] ---------------------------------------------------------------------
# Blocage de plage : regle DROP sur la plage, reperee par « cybersafe-range:<plage> ».

def _range_comment(net):
    return "cybersafe-range:%s" % net


def _range_contains_any(net, ips):
    """La plage contient-elle une des adresses donnees ? (faux si ce n'est pas une plage)"""
    if "/" not in str(net):
        return False
    try:
        network = ipaddress.ip_network(str(net), strict=False)
    except ValueError:
        return False
    for ip in ips:
        try:
            if ipaddress.ip_address(ip) in network:
                return True
        except ValueError:
            continue
    return False


def _rules_with_comment(tool, comment):
    rc, out, _ = _run([tool, "-S", "INPUT"])
    if rc != 0:
        return []
    found = []
    for line in out.splitlines():
        try:
            args = shlex.split(line)
        except ValueError:
            continue
        if args[:2] != ["-A", "INPUT"]:
            continue
        for i, arg in enumerate(args[:-1]):
            if arg == "--comment" and args[i + 1] == comment:
                found.append(args)
                break
    return found


def _remove_range_block(net):
    tool = _ipt(net)
    if not shutil.which(tool):
        return False, "%s introuvable" % tool
    removed = 0
    for args in _rules_with_comment(tool, _range_comment(net)):
        rc, _, err = _run([tool, "-D"] + args[1:])
        if rc != 0:
            return False, "%s rc=%s err=%s" % (tool, rc, err)
        removed += 1
    return True, "%s: %d regle(s) de plage retiree(s)" % (tool, removed)


def _apply_range_block(net):
    tool = _ipt(net)
    if not shutil.which(tool):
        return False, "%s introuvable" % tool
    ok, detail = _remove_range_block(net)  # idempotent
    if not ok:
        return False, detail
    rc, _, err = _run([tool, "-I", "INPUT", "-s", net,
                       "-m", "comment", "--comment", _range_comment(net), "-j", "DROP"])
    if rc != 0:
        return False, "%s rc=%s err=%s" % (tool, rc, err)
    return True, "%s: plage %s bloquee" % (tool, net)


def _report(api_url, token, order_id, success, detail, rule_present=None):
'''),
    ]),
}

TESTS = "tests/test_ip_range.py"
TESTS_TEXT = '''# -*- coding: utf-8 -*-
"""
US-SOC-R12 porte 3 (agent 2.1.0) — blocage de plage d'adresses.

    python -m pytest tests/test_ip_range.py -v
"""
import base64
import types
import uuid
from datetime import datetime, timedelta, timezone

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from cybersafe_agent import order_guard as g
from cybersafe_agent import remediation as r

NET = "45.148.10.0/24"
WHY = "Campagne de force brute depuis ce bloc"
_FMT = "%Y-%m-%dT%H:%M:%SZ"


@pytest.fixture
def key(monkeypatch):
    priv = Ed25519PrivateKey.generate()
    raw = priv.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    monkeypatch.setattr(g, "_ORDER_PUBLIC_KEY_B64", base64.b64encode(raw).decode("ascii"))
    return priv


@pytest.fixture
def journal(tmp_path):
    return g.ReplayJournal(str(tmp_path))


def make(priv, **fields):
    now = datetime.now(timezone.utc)
    order = {"id": 7, "action": "block_ip_range", "target_ip": NET, "ttl_seconds": 3600, "agent_id": 7,
             "issued_at": now.strftime(_FMT), "expires_at": (now + timedelta(minutes=5)).strftime(_FMT),
             "nonce": uuid.uuid4().hex, "params": {"justification": WHY}}
    order.update(fields)
    order["sig_alg"] = "ed25519-v2"
    order["signature"] = base64.b64encode(priv.sign(g.canonical(order, g.SIGNED_FIELDS_V2))).decode("ascii")
    return order


class TestGarde:
    def test_plage_valide(self, key, journal):
        g.guard_order(make(key), journal)

    def test_plage_ipv6(self, key, journal):
        g.guard_order(make(key, target_ip="2001:db8:1::/48"), journal)

    @pytest.mark.parametrize("target,motif", [
        ("45.148.0.0/16", "trop large"),
        ("2001:db8::/32", "trop large"),
        ("45.148.10.7/24", "invalide"),
        ("45.148.10.7", "invalide"),
        ("192.168.1.0/24", "interne"),
        ("10.1.2.0/24", "interne"),
        ("127.0.0.0/24", "interne"),
        ("fe80::/64", "interne"),
    ])
    def test_plages_refusees(self, key, journal, target, motif):
        with pytest.raises(g.OrderRejected, match=motif):
            g.guard_order(make(key, target_ip=target), journal)

    def test_justification_obligatoire(self, key, journal):
        with pytest.raises(g.OrderRejected, match="texte attendu"):
            g.guard_order(make(key, params={}), journal)
        with pytest.raises(g.OrderRejected, match="longueur"):
            g.guard_order(make(key, params={"justification": "court"}), journal)
        with pytest.raises(g.OrderRejected, match="controle"):
            g.guard_order(make(key, params={"justification": WHY + "\\nDROP"}), journal)

    def test_levee_toujours_permise(self, key, journal):
        g.guard_order(make(key, action="unblock_ip_range", params={}), journal)

    def test_ban_ip_inchange(self, key, journal):
        g.guard_order(make(key, action="ban_ip", target_ip="45.148.10.9", params={}), journal)


@pytest.fixture
def ipt(monkeypatch):
    calls, state = [], {"rules": ""}

    def fake_run(cmd, **kw):
        calls.append(cmd)
        out = state["rules"] if cmd[1:3] == ["-S", "INPUT"] else ""
        return types.SimpleNamespace(returncode=0, stdout=out, stderr="")

    monkeypatch.setattr(r.shutil, "which", lambda name: "/usr/sbin/" + name)
    monkeypatch.setattr(r.subprocess, "run", fake_run)
    return types.SimpleNamespace(calls=calls, state=state)


class TestIptables:
    def test_regle_de_plage(self, ipt):
        ok, detail = r._apply_range_block(NET)
        assert ok, detail
        cmd = ipt.calls[-1]
        assert cmd[:5] == ["iptables", "-I", "INPUT", "-s", NET]
        assert cmd[cmd.index("--comment") + 1] == "cybersafe-range:" + NET
        assert cmd[-2:] == ["-j", "DROP"]

    def test_plage_ipv6(self, ipt):
        r._apply_range_block("2001:db8:1::/48")
        assert ipt.calls[-1][0] == "ip6tables"

    def test_retrait_par_commentaire(self, ipt):
        ipt.state["rules"] = (
            "-A INPUT -s 45.148.10.0/24 -m comment --comment \\"cybersafe-range:45.148.10.0/24\\" -j DROP\\n"
            "-A INPUT -s 45.148.10.9/32 -j DROP\\n")
        ok, detail = r._remove_range_block(NET)
        assert ok and "1 regle" in detail
        assert len([c for c in ipt.calls if c[1] == "-D"]) == 1


class TestAntiLockout:
    def test_contient(self):
        assert r._range_contains_any(NET, {"45.148.10.77"})
        assert not r._range_contains_any(NET, {"45.148.11.1"})
        assert not r._range_contains_any("45.148.10.77", {"45.148.10.77"})

    def test_session_ssh_dans_la_plage_refusee(self, monkeypatch):
        reports, applied = [], []
        monkeypatch.setattr(r, "_guard_order", lambda order: None)
        monkeypatch.setattr(r, "_active_ssh_source_ips", lambda: {"45.148.10.77"})
        monkeypatch.setattr(r, "_apply_range_block", lambda net: (applied.append(net), (True, "ok"))[1])
        monkeypatch.setattr(r, "_report", lambda api, tok, oid, ok, detail, rule_present=None: reports.append((ok, detail)))
        r._process_order({"id": 1, "action": "block_ip_range", "target_ip": NET,
                          "params": {"justification": WHY}}, "https://x", "t")
        assert applied == []
        assert reports[-1][0] is False and "anti-lockout" in reports[-1][1]

    def test_plage_executee_sans_session(self, monkeypatch):
        applied = []
        monkeypatch.setattr(r, "_guard_order", lambda order: None)
        monkeypatch.setattr(r, "_active_ssh_source_ips", lambda: {"203.0.113.5"})
        monkeypatch.setattr(r, "_apply_range_block", lambda net: (applied.append(net), (True, "ok"))[1])
        monkeypatch.setattr(r, "_report", lambda *a, **k: None)
        r._process_order({"id": 2, "action": "block_ip_range", "target_ip": NET,
                          "params": {"justification": WHY}}, "https://x", "t")
        assert applied == [NET]
'''


def read(path):
    with open(path, "r", encoding="utf-8") as fh:
        return fh.read()


def main():
    if len(sys.argv) != 2 or sys.argv[1] not in ("--check", "--apply"):
        print(__doc__)
        return 2
    apply = sys.argv[1] == "--apply"
    if not os.path.isfile("cybersafe_agent/remediation.py"):
        print("ERREUR : lancer depuis ~/Projects/Cybersafe-AI-Agent")
        return 2
    errors, pending, new_files = [], {}, []
    for path, (mark, pairs) in EDITS.items():
        content = read(path)
        if mark in content:
            print("  deja fait   %s" % path)
            continue
        ok = True
        for old, new in pairs:
            n = content.count(old)
            if n != 1:
                errors.append("%s : ancre trouvee %d fois : %r" % (path, n, old[:70]))
                ok = False
                break
            content = content.replace(old, new, 1)
        if ok:
            pending[path] = content
            print("  a modifier  %s" % path)
    if os.path.exists(TESTS):
        if read(TESTS) != TESTS_TEXT:
            errors.append("%s existe avec un autre contenu" % TESTS)
        else:
            print("  deja fait   %s" % TESTS)
    else:
        new_files.append((TESTS, TESTS_TEXT))
        print("  a creer     %s" % TESTS)
    if errors:
        print("\nAUCUNE modification (erreurs) :")
        for e in errors:
            print("  - " + e)
        return 1
    if not apply:
        print("\n--check : rien n'a ete modifie.")
        return 0
    for path, content in pending.items():
        if not os.path.exists(path + ".bak"):
            shutil.copy2(path, path + ".bak")
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(content)
    for path, text in new_files:
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(text)
    print("\nApplique. Sauvegardes : *.bak")
    return 0


if __name__ == "__main__":
    sys.exit(main())
