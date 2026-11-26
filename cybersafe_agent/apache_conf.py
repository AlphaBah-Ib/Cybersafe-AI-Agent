# -*- coding: utf-8 -*-
"""
[CERT04-P3B] Lecteur de configuration Apache httpd, en LECTURE SEULE.

Ecrit pour l'agent (aucune dependance externe) d'apres la syntaxe d'Apache 2.4 :
  - une directive par ligne ; '\\' en fin de ligne prolonge la directive ;
  - '#' en debut de ligne : commentaire (Apache n'a pas de commentaire en fin de ligne) ;
  - sections <Nom arguments> ... </Nom>, imbriquees, noms insensibles a la casse ;
  - Include / IncludeOptional : relatifs a ServerRoot, glob et dossier autorises ;
    IncludeOptional ignore ce qui n'existe pas ; un chemin contenant ${VAR} est refuse ;
  - sections conditionnelles (<IfModule>, <IfDefine>, <IfVersion>...) traitees comme
    transparentes : l'agent n'intervient que sur des vhosts explicites et teste
    toujours le resultat avec `apachectl configtest`.

Chaque directive garde son fichier et ses lignes (ouverture, fermeture des sections).
"""
import glob
import os
import shlex

MAX_FILE_BYTES = 2 * 1024 * 1024
MAX_FILES = 500
MAX_DEPTH = 20


class ApacheConfError(Exception):
    pass


class AStmt:
    __slots__ = ("directive", "name", "args", "file", "line", "close_line", "block", "includes")

    def __init__(self, directive, args, file, line):
        self.directive = directive          # tel qu'ecrit
        self.name = directive.lower()       # pour les comparaisons
        self.args = args
        self.file = file
        self.line = line
        self.close_line = None
        self.block = None
        self.includes = None

    def __repr__(self):
        return "<%s %s %s:%s>" % (self.directive, " ".join(self.args), self.file, self.line)


def _logical_lines(text):
    """(numero de premiere ligne, contenu) avec les prolongements '\\' recolles."""
    out, buf, start = [], [], None
    for no, raw in enumerate(text.split("\n"), start=1):
        line = raw.rstrip("\r")
        if start is None:
            start = no
        if line.endswith("\\"):
            buf.append(line[:-1])
            continue
        buf.append(line)
        out.append((start, " ".join(buf)))
        buf, start = [], None
    if buf:
        out.append((start, " ".join(buf)))
    return out


def _split_args(text, fname, line):
    try:
        lex = shlex.shlex(text, posix=True)
        lex.whitespace_split = True
        lex.commenters = ""
        return list(lex)
    except ValueError:
        raise ApacheConfError("%s:%d : guillemet non ferme" % (fname, line)) from None


def parse_text(text, fname):
    """Arbre d'AStmt (sans resolution des Include)."""
    root = []
    stack = [(None, root)]
    for line, content in _logical_lines(text):
        s = content.strip()
        if not s or s.startswith("#"):
            continue
        if s.startswith("</"):
            if not s.endswith(">"):
                raise ApacheConfError("%s:%d : fermeture de section invalide" % (fname, line))
            name = s[2:-1].strip().lower()
            sect, _children = stack[-1]
            if sect is None or sect.name != name:
                raise ApacheConfError("%s:%d : </%s> inattendu" % (fname, line, name))
            sect.close_line = line
            stack.pop()
            continue
        if s.startswith("<"):
            if not s.endswith(">"):
                raise ApacheConfError("%s:%d : ouverture de section invalide" % (fname, line))
            inner = s[1:-1].strip()
            if not inner:
                raise ApacheConfError("%s:%d : section sans nom" % (fname, line))
            parts = inner.split(None, 1)
            st = AStmt(parts[0], _split_args(parts[1], fname, line) if len(parts) > 1 else [],
                       fname, line)
            st.block = []
            stack[-1][1].append(st)
            stack.append((st, st.block))
            continue
        parts = s.split(None, 1)
        st = AStmt(parts[0], _split_args(parts[1], fname, line) if len(parts) > 1 else [],
                   fname, line)
        stack[-1][1].append(st)
    if len(stack) > 1:
        raise ApacheConfError("%s : section <%s> non fermee" % (fname, stack[-1][0].directive))
    return root


class ApacheConfig:
    def __init__(self, main_path, server_root=None):
        self.main = os.path.abspath(main_path)
        self.texts = {}
        first = self._read(self.main)
        sr = server_root
        if sr is None:
            for st in parse_text(first, self.main):
                if st.name == "serverroot" and st.args:
                    sr = st.args[0]
        self.server_root = os.path.abspath(sr or os.path.dirname(self.main))
        self.root = self._load(self.main, ())

    def _read(self, path):
        if path not in self.texts:
            if len(self.texts) >= MAX_FILES:
                raise ApacheConfError("trop de fichiers de configuration")
            try:
                st = os.stat(path)
            except OSError as exc:
                raise ApacheConfError("%s illisible (%s)" % (path, exc.strerror or exc)) from None
            if st.st_size > MAX_FILE_BYTES:
                raise ApacheConfError("%s trop volumineux" % path)
            with open(path, "r", encoding="utf-8", errors="replace") as fh:
                self.texts[path] = fh.read()
        return self.texts[path]

    def _load(self, path, stack):
        if path in stack:
            raise ApacheConfError("inclusion circulaire : %s" % path)
        if len(stack) > MAX_DEPTH:
            raise ApacheConfError("inclusions trop profondes")
        stmts = parse_text(self._read(path), path)
        self._resolve(stmts, stack + (path,))
        return stmts

    def _resolve(self, stmts, stack):
        for st in stmts:
            if st.name in ("include", "includeoptional") and st.block is None:
                if len(st.args) != 1:
                    raise ApacheConfError("%s:%d : Include invalide" % (st.file, st.line))
                pattern = st.args[0]
                if "${" in pattern:
                    raise ApacheConfError("%s:%d : Include avec variable non pris en charge"
                                          % (st.file, st.line))
                if not os.path.isabs(pattern):
                    pattern = os.path.join(self.server_root, pattern)
                if os.path.isdir(pattern):
                    pattern = os.path.join(pattern, "*")
                if glob.has_magic(pattern):
                    files = sorted(f for f in glob.glob(pattern) if os.path.isfile(f))
                elif os.path.isfile(pattern):
                    files = [pattern]
                elif st.name == "includeoptional":
                    files = []
                else:
                    raise ApacheConfError("%s:%d : fichier inclus introuvable : %s"
                                          % (st.file, st.line, pattern))
                st.includes = [(os.path.abspath(f), self._load(os.path.abspath(f), stack))
                               for f in files]
            elif st.block is not None:
                self._resolve(st.block, stack)

    @staticmethod
    def children(stmts):
        """Directives effectives : Include remplaces par leur contenu, sections
        conditionnelles traversees."""
        for st in stmts:
            yield st
            if st.includes:
                for _f, sub in st.includes:
                    yield from ApacheConfig.children(sub)
            elif st.block is not None and st.name.startswith("if"):
                yield from ApacheConfig.children(st.block)

    def vhosts(self):
        for st in self._walk(self.root):
            if st.name == "virtualhost" and st.block is not None:
                yield st

    def _walk(self, stmts):
        for st in self.children(stmts):
            yield st
            if st.block is not None and st.name != "virtualhost" and not st.name.startswith("if"):
                yield from self._walk(st.block)
