# -*- coding: utf-8 -*-
"""
[CERT04-P3] Lecteur de configuration Nginx, en LECTURE SEULE.

Ecrit pour l'agent (aucune dependance externe) d'apres la grammaire de Nginx :
  - jetons separes par des espaces ; { } ; sont des jetons a part entiere ;
  - '#' en debut de jeton : commentaire jusqu'a la fin de ligne ;
  - chaines entre guillemets simples ou doubles, avec echappement par '\\' ;
  - '${' a l'interieur d'un jeton n'ouvre pas de bloc (variable ${nom}) ;
  - include : chemin relatif au dossier du fichier principal, glob autorise,
    fichiers tries (comme Nginx).

Chaque directive garde son fichier et ses numeros de ligne (debut, accolade
ouvrante, accolade fermante) : l'agent modifie ensuite les fichiers ligne par
ligne, sans jamais les reecrire entierement.

Garde-fous : taille des fichiers, nombre de fichiers et profondeur d'inclusion
bornes ; inclusion circulaire detectee ; toute erreur de syntaxe leve
NginxConfError (l'agent refuse alors d'intervenir).
"""
import glob
import os

MAX_FILE_BYTES = 2 * 1024 * 1024
MAX_FILES = 500
MAX_DEPTH = 20


class NginxConfError(Exception):
    pass


class Stmt:
    """Directive Nginx. block est None pour une directive simple."""

    __slots__ = ("directive", "args", "file", "line", "open_line", "close_line", "block",
                 "includes", "parent")

    def __init__(self, directive, args, file, line):
        self.directive = directive
        self.args = args
        self.file = file
        self.line = line
        self.open_line = None
        self.close_line = None
        self.block = None
        self.includes = None  # pour include : liste des fichiers resolus
        self.parent = None

    def __repr__(self):
        return "<%s %s %s:%s>" % (self.directive, " ".join(self.args), self.file, self.line)


def tokenize(text, fname="<config>"):
    """Renvoie une liste de (jeton, ligne, entre_guillemets)."""
    tokens = []
    i, n, line = 0, len(text), 1
    while i < n:
        c = text[i]
        if c == "\n":
            line += 1
            i += 1
            continue
        if c.isspace():
            i += 1
            continue
        if c == "#":
            while i < n and text[i] != "\n":
                i += 1
            continue
        if c in "{};":
            tokens.append((c, line, False))
            i += 1
            continue
        if c in "\"'":
            quote, start_line, buf = c, line, []
            i += 1
            while True:
                if i >= n:
                    raise NginxConfError("%s:%d : guillemet non ferme" % (fname, start_line))
                c = text[i]
                if c == "\\" and i + 1 < n:
                    buf.append(text[i + 1])
                    if text[i + 1] == "\n":
                        line += 1
                    i += 2
                    continue
                if c == quote:
                    i += 1
                    break
                if c == "\n":
                    line += 1
                buf.append(c)
                i += 1
            tokens.append(("".join(buf), start_line, True))
            continue
        start_line, buf = line, []
        while i < n:
            c = text[i]
            if c.isspace() or c in ";}":
                break
            if c == "{":
                if buf and buf[-1] == "$":  # variable ${nom}
                    j = text.find("}", i)
                    if j == -1:
                        raise NginxConfError("%s:%d : variable non fermee" % (fname, line))
                    buf.append(text[i:j + 1])
                    i = j + 1
                    continue
                break
            if c == "\\" and i + 1 < n:
                buf.append(text[i:i + 2])
                i += 2
                continue
            buf.append(c)
            i += 1
        tokens.append(("".join(buf), start_line, False))
    return tokens


def _parse_tokens(tokens, fname):
    """Arbre de Stmt (sans resolution des include)."""
    pos = 0

    def block(depth, parent):
        nonlocal pos
        out = []
        while pos < len(tokens):
            tok, line, quoted = tokens[pos]
            if tok == "}" and not quoted:
                if depth == 0:
                    raise NginxConfError("%s:%d : '}' inattendue" % (fname, line))
                return out, line
            if tok in ("{", ";") and not quoted:
                raise NginxConfError("%s:%d : '%s' inattendu" % (fname, line, tok))
            st = Stmt(tok, [], fname, line)
            st.parent = parent
            pos += 1
            while True:
                if pos >= len(tokens):
                    raise NginxConfError("%s:%d : directive '%s' non terminee" % (fname, line, tok))
                t, tl, q = tokens[pos]
                pos += 1
                if t == ";" and not q:
                    break
                if t == "{" and not q:
                    st.open_line = tl
                    st.block, st.close_line = block(depth + 1, st)
                    pos += 1  # '}'
                    break
                if t == "}" and not q:
                    raise NginxConfError("%s:%d : ';' manquant avant '}'" % (fname, tl))
                st.args.append(t)
            out.append(st)
        if depth:
            raise NginxConfError("%s : fin de fichier, '}' manquante" % fname)
        return out, None

    stmts, _ = block(0, None)
    return stmts


def _read(path):
    try:
        st = os.stat(path)
    except OSError as exc:
        raise NginxConfError("%s illisible (%s)" % (path, exc.strerror or exc)) from None
    if st.st_size > MAX_FILE_BYTES:
        raise NginxConfError("%s trop volumineux" % path)
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        return fh.read()


class NginxConfig:
    """Configuration chargee : arbre racine + texte de chaque fichier."""

    def __init__(self, main_path):
        self.main = os.path.abspath(main_path)
        self.base = os.path.dirname(self.main)
        self.texts = {}
        self.root = self._load(self.main, (), None)

    def _load(self, path, stack, parent):
        if path in stack:
            raise NginxConfError("inclusion circulaire : %s" % path)
        if len(stack) > MAX_DEPTH:
            raise NginxConfError("inclusions trop profondes")
        if path not in self.texts:
            if len(self.texts) >= MAX_FILES:
                raise NginxConfError("trop de fichiers de configuration")
            self.texts[path] = _read(path)
        stmts = _parse_tokens(tokenize(self.texts[path], path), path)
        for st in stmts:
            if parent is not None and st.parent is None:
                st.parent = parent
        self._resolve(stmts, stack + (path,))
        return stmts

    def _resolve(self, stmts, stack):
        for st in stmts:
            if st.directive == "include" and st.block is None:
                if len(st.args) != 1:
                    raise NginxConfError("%s:%d : include invalide" % (st.file, st.line))
                pattern = st.args[0]
                if not os.path.isabs(pattern):
                    pattern = os.path.join(self.base, pattern)
                if glob.has_magic(pattern):
                    files = sorted(glob.glob(pattern))
                else:
                    if not os.path.isfile(pattern):
                        raise NginxConfError("%s:%d : fichier inclus introuvable : %s"
                                             % (st.file, st.line, pattern))
                    files = [pattern]
                st.includes = []
                for f in files:
                    f = os.path.abspath(f)
                    st.includes.append((f, self._load(f, stack, st.parent)))
            elif st.block is not None:
                self._resolve(st.block, stack)

    @staticmethod
    def children(stmts):
        """Directives effectives d'un bloc : les include sont remplaces par leur contenu
        (l'include lui-meme reste visible, en premier)."""
        for st in stmts:
            yield st
            if st.includes:
                for _f, sub in st.includes:
                    yield from NginxConfig.children(sub)

    def walk(self, stmts=None):
        """Parcours complet en profondeur (include compris)."""
        for st in self.children(self.root if stmts is None else stmts):
            yield st
            if st.block is not None:
                yield from self.walk(st.block)

    def servers(self):
        """Blocs server du contexte http (y compris venant d'include)."""
        for http in self.children(self.root):
            if http.directive == "http" and http.block is not None:
                for st in self.children(http.block):
                    if st.directive == "server" and st.block is not None:
                        yield st
