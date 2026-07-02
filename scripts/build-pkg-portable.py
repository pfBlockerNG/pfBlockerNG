#!/usr/bin/env python3
# build-pkg-portable.py — build a pfSense-installable FreeBSD .pkg for the
# pfBlockerNG port WITHOUT a FreeBSD host or the ports framework.
#
# pfBlockerNG is a NO_BUILD port: nothing is compiled. "Building" the package is
# just (a) laying the production files out at their install paths, (b) doing the
# port's textual substitutions, and (c) emitting a libpkg-format archive with the
# right manifest. This tool replicates exactly that, portably (Linux + macOS),
# by *executing the port's own do-extract/post-extract/do-install recipe* and
# *reading its pkg-plist* — never a hardcoded, pfBlockerNG-specific file list. So
# when the port gains files or changes dependencies, this tool keeps up: it reads
# the same Makefile/plist the real `make package` reads.
#
# It supports BOTH port layouts:
#   * USE_GITHUB  (FreeBSD-ports branch pfblockerng/use-github): source fetched
#     from GitHub into ${WRKSRC} (= <project>-<ver>/src); do-install copies thence.
#   * classic     (FreeBSD-ports branch devel, pre-src/ move): source embedded in
#     the port's files/ dir (${FILESDIR}); do-install copies thence.
# It picks the right one from the Makefile (USE_GITHUB present or not). For the
# USE_GITHUB variant you can pass --local-src to build from a local pfBlockerNG
# working tree instead of fetching the GitHub tag — handy for iterating on code
# under test, the way scripts/build-pkg.sh pins GH_TAGNAME on a FreeBSD VM.
#
# The result is a real libpkg archive: zstd-compressed tar with +COMPACT_MANIFEST
# and +MANIFEST first, then payload files at their absolute paths. `pkg add` on
# pfSense registers it and runs the POST-INSTALL hook (rc.packages), same as a
# port-built .pkg. Dependencies are RUN_DEPENDS/LIB_DEPENDS plus the ones USES
# injects (USES=php + USE_PHP -> php<XY>[-ext]; USES=python -> python<XY>), which
# `make package` also records; their exact versions can be pinned from a repo
# catalogue (--repo-catalogue).
#
# Fidelity: the output was diffed field-by-field against a real `make package`
# build for the same commit and matches it (metadata, files+checksums+perms,
# directories, scripts, dep names/origins). The only values not derivable from
# the port files are file mtime (the install clock) and a few dep versions that
# make package reads from the build host's installed packages.
#
# Requires: python3 (stdlib only) + a zstd encoder (the `zstd` binary, or the
# python `zstandard` module). `--compression xz` needs neither (stdlib lzma).
#
# This is a developer tool (not shipped in release archives). See --help.

from __future__ import annotations

import argparse
import hashlib
import io
import json
import os
import re
import shlex
import shutil
import subprocess
import sys
import tarfile
import tempfile
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path

# --------------------------------------------------------------------------- #
# Small FreeBSD-ports Makefile evaluator
#
# Just enough of bsd.port.mk's variable semantics to read a pfSense pkg port:
# =/?=/+=/:= assignments, line continuations, # comments, ${VAR}/$(VAR) and a
# couple of :modifiers. .include lines are ignored — we seed the framework
# variables the port relies on (PREFIX, DATADIR, PYTHON_*, install macros, …).
# Target recipes (do-install, post-extract, …) are captured verbatim, joined on
# backslash-continuation, and run later by the recipe interpreter.
# --------------------------------------------------------------------------- #


class Makefile:
    _ASSIGN = re.compile(r"^([A-Za-z_][A-Za-z0-9_]*)\s*(\?=|\+=|:=|=)\s*(.*)$")

    def __init__(self, path: Path, seed: dict[str, str]):
        self.vars: dict[str, str] = dict(seed)
        # Assignment order matters for ?= (only set if unset). Keep raw values;
        # expand lazily so later-defined vars are visible (ports are order-tolerant
        # for our reads because we expand at access time).
        self.recipes: dict[str, list[str]] = {}
        self._raw: dict[str, tuple[str, str]] = {}  # name -> (op, value) last write
        self._parse(path)

    def _parse(self, path: Path) -> None:
        lines = path.read_text().splitlines()
        # Join backslash continuations into logical lines, but keep recipe lines
        # (TAB-indented) separate from assignments.
        i = 0
        cur_target: str | None = None
        logical: list[tuple[bool, str]] = []  # (is_recipe, text)
        while i < len(lines):
            raw = lines[i]
            # Recipe line: starts with a literal TAB.
            is_recipe = raw.startswith("\t")
            text = raw
            # Gather continuations (backslash-newline collapses to a single space,
            # like make: drop the trailing space before the backslash too).
            while text.rstrip().endswith("\\"):
                text = text.rstrip()[:-1].rstrip()
                i += 1
                if i < len(lines):
                    text += " " + lines[i].strip() if not is_recipe else " " + lines[i].lstrip("\t")
            logical.append((is_recipe, text))
            i += 1

        for is_recipe, text in logical:
            if is_recipe:
                if cur_target is not None:
                    body = text[1:] if text.startswith("\t") else text
                    if body.strip():
                        self.recipes.setdefault(cur_target, []).append(body)
                continue
            stripped = text.strip()
            if not stripped or stripped.startswith("#"):
                cur_target = None
                continue
            if stripped.startswith(".include") or stripped.startswith("."):
                cur_target = None
                continue
            # Target header:  name:  (possibly with deps after the colon)
            m_t = re.match(r"^([A-Za-z0-9_\-./]+):(?!=)\s*(.*)$", stripped)
            m_a = self._ASSIGN.match(stripped)
            if m_a:
                cur_target = None
                name, op, val = m_a.group(1), m_a.group(2), m_a.group(3)
                val = self._strip_comment(val).strip()
                self._assign(name, op, val)
            elif m_t:
                cur_target = m_t.group(1)
                self.recipes.setdefault(cur_target, [])
            else:
                cur_target = None

    @staticmethod
    def _strip_comment(val: str) -> str:
        # Strip an unescaped trailing # comment (e.g. `DISTFILES= # empty`).
        out = []
        prev = ""
        for ch in val:
            if ch == "#" and prev != "\\":
                break
            out.append(ch)
            prev = ch
        return "".join(out)

    def _assign(self, name: str, op: str, val: str) -> None:
        if op == "?=":
            if name not in self._raw and name not in self.vars:
                self._raw[name] = ("=", val)
        elif op == "+=":
            old = self._raw.get(name, ("=", self.vars.get(name, "")))[1]
            self._raw[name] = ("=", (old + " " + val).strip())
        else:  # = or :=
            self._raw[name] = ("=", val)

    def _lookup(self, name: str) -> str | None:
        if name in self._raw:
            return self._raw[name][1]
        return self.vars.get(name)

    def expand(self, s: str, _depth: int = 0) -> str:
        if _depth > 40 or "$" not in s:
            return s
        out = []
        i = 0
        while i < len(s):
            ch = s[i]
            if ch == "$" and i + 1 < len(s) and s[i + 1] in "{(":
                close = "}" if s[i + 1] == "{" else ")"
                depth = 1
                j = i + 2
                while j < len(s) and depth:
                    if s[j] == s[i + 1]:
                        depth += 1
                    elif s[j] == close:
                        depth -= 1
                    if depth:
                        j += 1
                inner = s[i + 2 : j]
                out.append(self._expand_ref(inner, _depth))
                i = j + 1
            else:
                out.append(ch)
                i += 1
        return "".join(out)

    def _expand_ref(self, inner: str, depth: int) -> str:
        # Support  NAME  and  NAME:modifier...  (only the modifiers ports here use).
        inner = self.expand(inner, depth + 1)
        if ":" in inner:
            name, _, mods = inner.partition(":")
            val = self._lookup(name)
            val = self.expand(val, depth + 1) if val is not None else ""
            return self._apply_mods(val, mods)
        val = self._lookup(inner)
        if val is None:
            return ""
        return self.expand(val, depth + 1)

    @staticmethod
    def _apply_mods(val: str, mods: str) -> str:
        # Minimal :H (dirname), :T (basename), :R (root), :E (ext), and :S/old/new/[g]
        # (string substitution — used to strip the pfSense-pkg- prefix for the info.xml
        # registration <name>). Enough for the recipes we run; extend if a port needs more.
        # Split on ':' but keep an :S/.../.../ group intact (its body has no ':').
        for mod in mods.split(":"):
            if mod == "H":
                val = os.path.dirname(val)
            elif mod == "T":
                val = os.path.basename(val)
            elif mod == "R":
                val = os.path.splitext(val)[0]
            elif mod == "E":
                val = os.path.splitext(val)[1].lstrip(".")
            elif mod.startswith("S") and len(mod) >= 4:
                # :S<delim>old<delim>new<delim>[1g]  (make string substitution). Supports
                # a leading ^ / trailing $ anchor in <old> and the g (global) flag.
                delim = mod[1]
                parts = mod[2:].split(delim)
                if len(parts) >= 2:
                    old, new = parts[0], parts[1]
                    flags = parts[2] if len(parts) > 2 else ""
                    anchor_start, anchor_end = old.startswith("^"), old.endswith("$")
                    pat = old[1:] if anchor_start else old
                    pat = pat[:-1] if anchor_end else pat
                    if not pat:
                        pass
                    elif "g" in flags and not (anchor_start or anchor_end):
                        val = val.replace(pat, new)
                    elif anchor_start and val.startswith(pat):
                        val = new + val[len(pat) :]
                    elif anchor_end and val.endswith(pat):
                        val = val[: -len(pat)] + new
                    elif not (anchor_start or anchor_end):
                        val = val.replace(pat, new, 1)
        return val

    def get(self, name: str, default: str = "") -> str:
        v = self._lookup(name)
        return self.expand(v) if v is not None else default


# --------------------------------------------------------------------------- #
# Data model
# --------------------------------------------------------------------------- #


@dataclass
class Dep:
    name: str
    origin: str
    version: str


@dataclass
class StagedFile:
    install_path: str  # absolute, e.g. /usr/local/pkg/pfblockerng/pfblockerng.inc
    src_in_stage: Path  # actual file under STAGEDIR
    perm: str  # "0644" (INSTALL_DATA) / "0555" (INSTALL_SCRIPT)


@dataclass
class Build:
    portname: str
    pkgversion: str
    origin: str
    comment: str
    maintainer: str
    categories: list[str]
    licenses: list[str]
    www: str
    desc: str
    prefix: str
    abi: str
    arch: str
    deps: list[Dep] = field(default_factory=list)
    files: list[StagedFile] = field(default_factory=list)
    directories: list[str] = field(default_factory=list)
    scripts: dict[str, str] = field(default_factory=dict)
    annotations: dict[str, str] = field(default_factory=dict)

    @property
    def pkgname(self) -> str:
        return f"{self.portname}-{self.pkgversion}"


# --------------------------------------------------------------------------- #
# Recipe interpreter
#
# Runs the port's do-extract/post-extract/do-install recipe with a tiny command
# vocabulary. Every command maps to a real filesystem effect into a controlled
# WRKDIR/STAGEDIR — exactly what `make` would do, minus the shell. An unknown
# command is a hard error (rather than a silently broken package): that is the
# signal that the port changed in a way the tool must be taught.
# --------------------------------------------------------------------------- #


class Recipe:
    SED_S = re.compile(r"^s(.)(.*)$")

    def __init__(self, mk: Makefile):
        self.mk = mk
        # Record (install_path -> perm) as INSTALL_DATA/INSTALL_SCRIPT run, so the
        # manifest knows each file's mode (the plist does not encode it).
        self.modes: dict[str, str] = {}
        self.stagedir = Path(mk.get("STAGEDIR"))

    def run(self, target: str) -> None:
        for line in self.mk.recipes.get(target, []):
            self._exec(line)

    def _exec(self, line: str) -> None:
        line = line.strip()
        while line[:1] in ("@", "-"):
            line = line[1:].lstrip()
        if not line:
            return
        # A recipe command is either a ${MACRO} (e.g. ${INSTALL_DATA}) or a bare
        # command word (e.g. post-extract's literal `mv`). Both map to _cmd_<name>.
        m = re.match(r"^\$[{(]([A-Za-z_][A-Za-z0-9_]*)[})]\s*(.*)$", line)
        if m:
            cmd, rest = m.group(1), m.group(2)
        else:
            parts = line.split(None, 1)
            cmd = parts[0]
            rest = parts[1] if len(parts) > 1 else ""
            if not re.match(r"^[A-Za-z_][A-Za-z0-9_]*$", cmd):
                raise BuildError(f"recipe line is neither a ${{MACRO}} nor a bare command: {line!r}")
        rest = self.mk.expand(rest)
        args = shlex.split(rest)
        handler = getattr(self, f"_cmd_{cmd.lower()}", None)
        if handler is None:
            raise BuildError(
                f"unsupported recipe command ${{{cmd}}} — teach build-pkg-portable.py this command (line: {line!r})"
            )
        handler(args)

    # --- commands ---------------------------------------------------------- #

    def _cmd_mkdir(self, args: list[str]) -> None:
        for a in args:
            if a == "-p":
                continue
            Path(a).mkdir(parents=True, exist_ok=True)

    def _install(self, args: list[str], default_perm: str) -> None:
        perm = default_perm
        i = 0
        positional: list[str] = []
        while i < len(args):
            a = args[i]
            if a == "-m":
                perm = self._normperm(args[i + 1])
                i += 2
                continue
            if a in ("-o", "-g"):  # owner/group flags: irrelevant, files go in as root
                i += 2
                continue
            if a.startswith("-"):
                i += 1
                continue
            positional.append(a)
            i += 1
        if len(positional) < 2:
            raise BuildError(f"INSTALL with too few paths: {args!r}")
        dest = positional[-1]
        srcs = positional[:-1]
        dest_p = Path(dest)
        dest_is_dir = dest_p.is_dir() or dest.endswith("/") or len(srcs) > 1
        for s in srcs:
            sp = Path(s)
            if not sp.exists():
                raise BuildError(f"install source missing: {s}")
            target = dest_p / sp.name if dest_is_dir else dest_p
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(sp, target)
            os.chmod(target, int(perm, 8))
            self.modes[self._install_path(target)] = perm

    def _cmd_install_data(self, args: list[str]) -> None:
        self._install(args, "0644")

    def _cmd_install_script(self, args: list[str]) -> None:
        # INSTALL_SCRIPT installs with ${BINMODE}, which is 0555 on FreeBSD
        # (installed scripts/binaries are not writable) — NOT 0755.
        self._install(args, "0555")

    def _cmd_mv(self, args: list[str]) -> None:
        # Drop flags (e.g. -f), then split into (sources, dest).
        paths = [a for a in args if not a.startswith("-")]
        if len(paths) < 2:
            raise BuildError(f"mv with too few paths: {args!r}")
        for s in paths[:-1]:
            shutil.move(s, paths[-1])

    # NB: cp / ln / rm / install_program are intentionally NOT implemented. The
    # three pfBlockerNG port Makefiles drive only MKDIR / INSTALL_DATA /
    # INSTALL_SCRIPT / SED / REINPLACE_CMD (plus MV, handled above); an unknown
    # ${MACRO} is a hard error (see _exec), so re-add a command the day a port
    # actually needs it.

    def _cmd_reinplace_cmd(self, args: list[str]) -> None:
        self._sed_inplace(args)

    def _cmd_sed(self, args: list[str]) -> None:
        self._sed_inplace(args)

    def _sed_inplace(self, args: list[str]) -> None:
        # REINPLACE_CMD == `sed -i ''`. Parse: -i [suffix], -e EXPR (repeatable) or
        # a bare leading EXPR, then file(s). Only the `s` command is implemented —
        # which is all the pfSense pkg ports use (placeholder substitution).
        exprs: list[str] = []
        files: list[str] = []
        i = 0
        seen_expr = False
        while i < len(args):
            a = args[i]
            if a == "-i":
                # FreeBSD sed: -i takes a (possibly empty) backup suffix argument.
                if i + 1 < len(args) and (args[i + 1] == "" or not args[i + 1].startswith("-")) and not seen_expr:
                    # Treat next as the (empty) suffix only when it looks like one.
                    if args[i + 1] == "":
                        i += 2
                        continue
                i += 1
                continue
            if a == "-e":
                exprs.append(args[i + 1])
                seen_expr = True
                i += 2
                continue
            if a.startswith("-"):
                i += 1
                continue
            if not seen_expr and not exprs:
                exprs.append(a)
                seen_expr = True
                i += 1
                continue
            files.append(a)
            i += 1
        for f in files:
            self._apply_sed(Path(f), exprs)

    def _apply_sed(self, path: Path, exprs: list[str]) -> None:
        if not path.exists():
            raise BuildError(f"sed target missing: {path}")
        text = path.read_text()
        for expr in exprs:
            text = self._sed_s(text, expr)
        path.write_text(text)

    def _sed_s(self, text: str, expr: str) -> str:
        m = self.SED_S.match(expr)
        if not m:
            raise BuildError(f"unsupported sed expression (only s/// is handled): {expr!r}")
        delim = m.group(1)
        body = m.group(2)
        parts = _split_unescaped(body, delim)
        if len(parts) < 2:
            raise BuildError(f"malformed sed s expression: {expr!r}")
        pattern, repl = parts[0], parts[1]
        flags = parts[2] if len(parts) > 2 else ""
        # The pfSense ports only substitute literal %%TOKEN%% placeholders, so a
        # literal replace is faithful and avoids BRE/ERE ambiguity. 'g' => all.
        if "g" in flags:
            return text.replace(pattern, repl)
        out = []
        for ln in text.splitlines(keepends=True):
            out.append(ln.replace(pattern, repl, 1))
        return "".join(out)

    # --- helpers ----------------------------------------------------------- #

    def _install_path(self, staged: Path) -> str:
        rel = os.path.relpath(staged, self.stagedir)
        return "/" + rel

    @staticmethod
    def _normperm(p: str) -> str:
        p = p.strip()
        if not p.startswith("0"):
            p = "0" + p
        return p


def _split_unescaped(s: str, delim: str) -> list[str]:
    out, cur, esc = [], [], False
    for ch in s:
        if esc:
            cur.append(ch)
            esc = False
        elif ch == "\\":
            esc = True
            cur.append(ch)
        elif ch == delim:
            out.append("".join(cur))
            cur = []
        else:
            cur.append(ch)
    out.append("".join(cur))
    return out


class BuildError(Exception):
    pass


# --------------------------------------------------------------------------- #
# pkg-plist + pkg-descr parsing
# --------------------------------------------------------------------------- #


def parse_plist(text: str, plist_sub: dict[str, str], prefix: str) -> tuple[list[str], list[str]]:
    """Return (file install paths absolute, directory paths absolute) from a plist.

    Entries are PREFIX-relative unless they start with '/'. %%TOKEN%% are PLIST_SUB
    substitutions; @dir gives an explicit owned directory. An unknown @keyword
    (@mode, @sample, @owner, …) aborts the build — like an unknown recipe command,
    silently dropping it would emit a subtly wrong package instead of forcing the
    tool to be taught the keyword.
    """
    files: list[str] = []
    dirs: list[str] = []
    for raw in text.splitlines():
        line = raw.strip()
        if not line:
            continue
        line = _sub_tokens(line, plist_sub)
        if "%%" in line:
            raise BuildError(f"unresolved %%token%% in pkg-plist: {raw!r}")
        if line.startswith("@"):
            kw, _, arg = line[1:].partition(" ")
            arg = arg.strip()
            if kw == "dir":
                dirs.append(_abspath(arg, prefix))
            elif kw == "comment":
                continue
            else:
                raise BuildError(f"unsupported pkg-plist keyword @{kw} (teach the tool to handle it): {raw!r}")
            continue
        files.append(_abspath(line, prefix))
    return files, dirs


def _abspath(p: str, prefix: str) -> str:
    if p.startswith("/"):
        return os.path.normpath(p)
    return os.path.normpath(prefix.rstrip("/") + "/" + p)


def _sub_tokens(s: str, sub: dict[str, str]) -> str:
    def repl(m: re.Match) -> str:
        key = m.group(1)
        return sub.get(key, m.group(0))

    return re.sub(r"%%([A-Za-z0-9_]+)%%", repl, s)


def parse_descr(text: str) -> tuple[str, str]:
    """Return (desc, www_from_descr). Modern `make package` records the pkg-descr
    VERBATIM as `desc` (trailing whitespace trimmed) — it no longer strips the
    `WWW:` line. The `WWW:` line is parsed only as a *fallback* www source (the
    Makefile WWW / USE_GITHUB default takes precedence; see resolve_www)."""
    www = ""
    for line in text.splitlines():
        m = re.match(r"^WWW:\s*(\S+)", line.strip())
        if m:
            www = m.group(1)
    return text.rstrip(), www


# --------------------------------------------------------------------------- #
# Dependency resolution (offline, from the ports tree)
# --------------------------------------------------------------------------- #

_VEROP = re.compile(r"(>=|<=|>|<|=|!=)")


def resolve_deps(mk: Makefile, ports_root: Path, seed: dict[str, str]) -> list[Dep]:
    entries: list[str] = []
    for var in ("LIB_DEPENDS", "RUN_DEPENDS"):
        raw = mk.get(var)
        if raw.strip():
            entries.extend(raw.split())
    deps: dict[str, Dep] = {}
    for ent in entries:
        lhs, _, origin_spec = ent.partition(":")
        if not origin_spec:
            continue
        # A dep spec is origin[@flavor]; the flavor (already var-expanded, e.g.
        # net/rsync@python or databases/py-sqlite3@py311) selects which flavored
        # package name to record. No @flavor => the port's default flavor.
        origin, _, flavor = origin_spec.partition("@")
        name, ver = _dep_name_version(lhs, origin, flavor, ports_root, seed)
        if name and name not in deps:
            deps[name] = Dep(name=name, origin=origin, version=ver or "0")
    return list(deps.values())


def _dep_name_version(lhs: str, origin: str, flavor: str, ports_root: Path, seed: dict[str, str]) -> tuple[str, str]:
    # If the LHS carries a version operator it is a package-name dependency
    # (e.g. py311-sqlite3>0); the name is the part before the operator.
    op = _VEROP.search(lhs)
    name_from_lhs = ""
    if op and not lhs.startswith("/") and "${" not in lhs[: op.start()]:
        name_from_lhs = lhs[: op.start()].strip()
    # Resolve the dep port's PKGBASE + PORTVERSION from the ports tree when present;
    # that yields the real recorded version and the canonical name for file-exists
    # dependencies (e.g. ${LOCALBASE}/bin/ggrep -> gnugrep, not the path basename),
    # honouring the selected flavor (net/rsync default -> rsync, @python -> rsync-python).
    pkgbase, portver = _read_dep_port(ports_root / origin / "Makefile", flavor, seed)
    name = name_from_lhs or pkgbase
    if not name:
        # Last resort: basename of origin (rarely correct, but better than empty).
        name = origin.split("/")[-1]
    return name, portver


def _read_dep_port(makefile: Path, flavor: str, seed: dict[str, str]) -> tuple[str, str]:
    if not makefile.is_file():
        return "", ""
    try:
        mk = Makefile(makefile, seed)
    except Exception:
        return "", ""
    portname = mk.get("PORTNAME")
    if not portname:
        return "", ""
    # Flavored ports build PKGBASE from per-flavor name parts (FLAVORS_SUB): the
    # chosen flavor's ${flavor}_PKGNAMEPREFIX is prepended and ${flavor}_PKGNAMESUFFIX
    # appended to the base prefix/suffix. Default flavor = first in FLAVORS.
    flavors = mk.get("FLAVORS").split()
    fl = flavor or (flavors[0] if flavors else "")
    prefix = mk.get("PKGNAMEPREFIX")
    suffix = mk.get("PKGNAMESUFFIX")
    if fl:
        prefix = mk.get(f"{fl}_PKGNAMEPREFIX") + prefix
        suffix = suffix + mk.get(f"{fl}_PKGNAMESUFFIX")
    pkgbase = prefix + portname + suffix
    # PKGVERSION = PORTVERSION[_PORTREVISION][,PORTEPOCH] — same as the package
    # records (e.g. grepcidr 2.0_1). Note: the version make package ACTUALLY
    # records is the installed BINARY package's, which tracks the build host's
    # repo and can be newer than the ports tree (e.g. rsync 3.4.3 vs tree 3.4.1_6);
    # this is the best the port files alone can give. Use a repo catalogue for exact.
    ver = compute_pkgversion(mk) if (mk.get("PORTVERSION") or mk.get("DISTVERSION")) else ""
    return pkgbase, ver


def resolve_www(mk: Makefile, descr_www: str) -> str:
    """Manifest www: the Makefile's WWW, else the USE_GITHUB default
    (https://github.com/<acct>/<proj>/), else the pkg-descr WWW: line."""
    w = mk.get("WWW")
    if w:
        return w
    if _truthy(mk.get("USE_GITHUB")):
        return f"https://github.com/{mk.get('GH_ACCOUNT')}/{mk.get('GH_PROJECT')}/"
    return descr_www


def synthesize_uses_deps(
    mk: Makefile, ports_root: Path, php_ver: str, py_flavor: str, seed: dict[str, str]
) -> list[Dep]:
    """Dependencies injected by USES that `make package` records but that are not
    in RUN_DEPENDS: USES=python -> python<XY>; USES=php (+USE_PHP=<exts>) ->
    php<XY> and php<XY>-<ext>. Versions are best-effort from the ports tree."""
    bases = {u.split(":")[0] for u in mk.get("USES").split()}
    out: list[Dep] = []
    if "python" in bases:
        pyv = py_flavor[2:] if py_flavor.startswith("py") else py_flavor
        origin = f"lang/python{pyv}"
        _, ver = _read_dep_port(ports_root / origin / "Makefile", "", seed)
        out.append(Dep(f"python{pyv}", origin, ver or "0"))
    if "php" in bases:
        phpv = php_ver.replace(".", "")
        php_origin = f"lang/php{phpv}"
        _, phpver = _read_dep_port(ports_root / php_origin / "Makefile", "", seed)
        phpver = phpver or "0"
        out.append(Dep(f"php{phpv}", php_origin, phpver))
        for tok in mk.get("USE_PHP").split():
            ext = tok.split(":")[0]
            name = f"php{phpv}-{ext}"
            origin = _glob_origin(ports_root, name)
            ver = ""
            if origin:
                _, ver = _read_dep_port(ports_root / origin / "Makefile", "", seed)
            # A php extension's version tracks the php base port — fall back to it.
            out.append(Dep(name, origin or f"lang/{name}", ver or phpver))
    return out


def _glob_origin(ports_root: Path, pkgdir: str) -> str:
    """Find a port's <category>/<pkgdir> origin by globbing the ports tree (php
    extensions live in assorted categories, e.g. devel/php83-intl).

    Falls back to ``git ls-files`` when the filesystem glob finds nothing AND the
    ports_root is a git working tree — this works on a blobless/sparse clone where
    only some Makefiles are checked out but git still knows all paths from the trees.
    """
    for p in ports_root.glob(f"*/{pkgdir}/Makefile"):
        return f"{p.parent.parent.name}/{p.parent.name}"
    # Blobless+sparse clone: filesystem glob yields nothing, but git knows all paths.
    if (ports_root / ".git").exists():
        try:
            r = subprocess.run(
                ["git", "-C", str(ports_root), "ls-files", f"*/{pkgdir}/Makefile"],
                capture_output=True,
                text=True,
                check=True,
            )
            for line in r.stdout.splitlines():
                parts = line.strip().split("/")
                if len(parts) >= 3:
                    return f"{parts[0]}/{parts[1]}"
        except subprocess.CalledProcessError:
            pass
    return ""


def _resolve_variant_deps(php_version: str, py_flavor: str) -> list[tuple[str, str]]:
    """Return the variant guard RUN_DEPENDS as ``(name, origin)`` pairs.

    Derives the PHP dep from ``php_version`` (``"8.3"`` → ``php83`` / ``lang/php83``)
    and the Python dep from ``py_flavor`` (``"py311"`` → ``python311`` /
    ``lang/python311``) — the SAME names + origins ``make package`` records for a
    ``USES=php``/``USES=python`` port, so when the port already synthesises them the
    guard de-dups cleanly (it never introduces a second, conflicting dep). Both are
    needed because the exact PHP version differs between CE and Plus — this is the
    variant guard that prevents a wrong-variant package from silently installing.

    A non-empty ``origin`` is REQUIRED: libpkg's ``pkg repo`` asserts every dep has
    one (``pkg_adddep_chain``), so an empty origin aborts a real FreeBSD catalog build.

    Each side is emitted only when its source value is non-empty, so a build that
    supplies only one of ``--php`` / ``--py-flavor`` still yields a well-formed list.

    Pure function: no I/O, no side effects.  Testable without a ports tree.
    """
    deps: list[tuple[str, str]] = []
    if php_version:
        phpv = php_version.replace(".", "")
        deps.append((f"php{phpv}", f"lang/php{phpv}"))
    if py_flavor:
        pyv = py_flavor[2:] if py_flavor.startswith("py") else py_flavor
        deps.append((f"python{pyv}", f"lang/python{pyv}"))
    return deps


def apply_repo_catalogue(deps: list[Dep], source: str, abi: str) -> None:
    """Pin each dep's version/origin to the binary repo's — the exact source
    `make package` records (the INSTALLED package versions). `source` is a path to
    a packagesite.yaml or packagesite.pkg/.txz, a URL to one, or 'auto' to fetch
    FreeBSD.org's repo for the ABI. Mutates `deps` in place."""
    wanted = {d.name for d in deps}
    cat = load_catalogue(source, abi, wanted)
    for d in deps:
        hit = cat.get(d.name)
        if not hit:
            sys.stderr.write(f"warning: dep {d.name} not in repo catalogue; keeping version {d.version!r}\n")
            continue
        origin, version = hit
        if version:
            d.version = version
        if origin and origin != d.origin:
            sys.stderr.write(f"warning: catalogue origin {origin} != {d.origin} for {d.name}; keeping {d.origin}\n")


def load_catalogue(source: str, abi: str, wanted: set[str]) -> dict[str, tuple[str, str]]:
    if source == "auto":
        source = f"https://pkg.freebsd.org/{abi}/latest/packagesite.pkg"
    if source.startswith(("http://", "https://")):
        try:
            with _urlopen(source) as r:
                raw = r.read()
        except OSError as e:
            raise BuildError(f"failed to fetch repo catalogue {source}: {e}") from None
    else:
        if not Path(source).is_file():
            raise BuildError(f"--repo-catalogue file not found: {source}")
        raw = Path(source).read_bytes()
    text = _catalogue_text(raw, source)
    out: dict[str, tuple[str, str]] = {}
    for line in text.splitlines():
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            obj = json.loads(line)
        except ValueError:
            continue
        name = obj.get("name")
        if name in wanted:
            out[name] = (obj.get("origin", ""), obj.get("version", ""))
            if len(out) == len(wanted):
                break
    return out


def _catalogue_text(raw: bytes, source: str) -> str:
    # A bare packagesite.yaml (newline-delimited JSON), else a tar (packagesite.pkg
    # = tar.zst, .txz = tar.xz, .tgz = tar.gz) containing packagesite.yaml.
    if source.endswith((".yaml", ".json")) or raw[:1] in (b"{", b"["):
        return raw.decode("utf-8", "replace")
    tar_bytes = _decompress(raw)
    with tarfile.open(fileobj=io.BytesIO(tar_bytes)) as tf:
        # extractfile() returns None for a non-regular member (dir/symlink) and
        # raises KeyError for a missing name — fall back to the first regular file.
        try:
            fobj = tf.extractfile("packagesite.yaml")
        except KeyError:
            fobj = None
        if fobj is None:
            for m in tf.getmembers():
                if m.isfile():
                    fobj = tf.extractfile(m)
                    if fobj is not None:
                        break
        if fobj is None:
            raise BuildError("no readable packagesite file in the repo catalogue archive")
        data = fobj.read()
    return data.decode("utf-8", "replace")


def _decompress(data: bytes) -> bytes:
    if data[:4] == b"\x28\xb5\x2f\xfd":  # zstd
        try:
            import zstandard

            return zstandard.ZstdDecompressor().stream_reader(io.BytesIO(data)).read()
        except ImportError:
            zstd = shutil.which("zstd")
            if not zstd:
                raise BuildError("repo catalogue is zstd; install `zstd` or the python `zstandard` module") from None
            return subprocess.run([zstd, "-dc"], input=data, stdout=subprocess.PIPE, check=True).stdout
    if data[:6] == b"\xfd7zXZ\x00":  # xz
        import lzma

        return lzma.decompress(data)
    if data[:2] == b"\x1f\x8b":  # gzip
        import gzip

        return gzip.decompress(data)
    return data  # already an uncompressed tar


# --------------------------------------------------------------------------- #
# Source acquisition
# --------------------------------------------------------------------------- #


def acquire_source(mk: Makefile, workdir: Path, args: argparse.Namespace) -> Path | None:
    """Populate ${WRKSRC} for a USE_GITHUB port; return the WRKSRC path, or None
    for a classic port (which installs from ${FILESDIR}, nothing to fetch)."""
    if not _truthy(mk.get("USE_GITHUB")):
        return None

    wrksrc = Path(mk.get("WRKSRC"))
    wrksrc.parent.mkdir(parents=True, exist_ok=True)

    if args.local_src:
        local = Path(args.local_src).resolve()
        src_root = local / "src" if (local / "src").is_dir() else local
        if not (src_root / "usr").is_dir():
            raise BuildError(
                f"--local-src {local} does not look like a pfBlockerNG checkout (expected a src/ tree containing usr/)"
            )
        # Copy into WRKSRC so post-extract's sed/mv never mutate the working tree.
        shutil.copytree(src_root, wrksrc, dirs_exist_ok=True)
        sys.stderr.write(f"==> source: local working tree {src_root}\n")
        return wrksrc

    account = mk.get("GH_ACCOUNT")
    project = mk.get("GH_PROJECT")
    tagname = args.gh_tagname or mk.get("GH_TAGNAME")
    url = f"https://codeload.github.com/{account}/{project}/tar.gz/{tagname}"
    sys.stderr.write(f"==> source: fetching {url}\n")
    tgz = workdir / "src.tar.gz"
    _download(url, tgz)
    extract_root = workdir / "gh-extract"
    extract_root.mkdir(parents=True, exist_ok=True)
    with tarfile.open(tgz, "r:gz") as tf:
        _safe_extract(tf, extract_root)
    tops = [p for p in extract_root.iterdir() if p.is_dir()]
    if len(tops) != 1:
        raise BuildError(f"unexpected GitHub tarball layout: {[p.name for p in tops]}")
    fetched_src = tops[0] / "src"
    if not fetched_src.is_dir():
        raise BuildError(f"fetched tarball has no src/ dir under {tops[0].name}")
    shutil.copytree(fetched_src, wrksrc, dirs_exist_ok=True)
    return wrksrc


def _download(url: str, dest: Path) -> None:
    try:
        with _urlopen(url) as r, open(dest, "wb") as f:
            shutil.copyfileobj(r, f)
    except OSError as e:
        raise BuildError(f"failed to fetch {url}: {e}") from None


def _urlopen(url: str):
    req = urllib.request.Request(url, headers={"User-Agent": "build-pkg-portable"})
    return urllib.request.urlopen(req)


def _safe_extract(tf: tarfile.TarFile, dest: Path) -> None:
    # Use the stdlib 'data' filter (PEP 706, Python 3.11.4+): it rejects absolute
    # paths, parent-dir traversal, AND symlinks/hardlinks that escape dest — the
    # link-based escapes a manual path-prefix check (str.startswith) silently lets
    # through.
    try:
        tf.extractall(dest, filter="data")
    except tarfile.FilterError as e:
        raise BuildError(f"unsafe member in fetched tarball: {e}") from None


# --------------------------------------------------------------------------- #
# Scripts (pkg-install / pkg-deinstall -> manifest scripts)
# --------------------------------------------------------------------------- #

# How ports' SUB_FILES script names map to libpkg manifest script keys. pfSense's
# pkg-install checks $2 (PRE-INSTALL/POST-INSTALL) -> the combined `install`
# script libpkg runs at both phases; likewise pkg-deinstall -> `deinstall`.
_SCRIPT_KEYS = {
    "pkg-install": "install",
    "pkg-deinstall": "deinstall",
    "pkg-pre-install": "pre-install",
    "pkg-post-install": "post-install",
    "pkg-pre-deinstall": "pre-deinstall",
    "pkg-post-deinstall": "post-deinstall",
}


def build_scripts(mk: Makefile, filesdir: Path) -> dict[str, str]:
    sub_files = mk.get("SUB_FILES").split()
    sub_list = _parse_sub_list(mk)
    scripts: dict[str, str] = {}
    for name in sub_files:
        key = _SCRIPT_KEYS.get(name)
        if key is None:
            continue
        src = filesdir / f"{name}.in"
        if not src.is_file():
            raise BuildError(f"SUB_FILES references {name} but {src} is missing")
        body = src.read_text()
        body = _sub_tokens(body, sub_list)
        # pkg create embeds the script without its trailing newline.
        scripts[key] = body.rstrip("\n")
    return scripts


def _parse_sub_list(mk: Makefile) -> dict[str, str]:
    sub: dict[str, str] = {
        "PREFIX": mk.get("PREFIX"),
        "LOCALBASE": mk.get("LOCALBASE"),
        "DATADIR": mk.get("DATADIR"),
        "PORTNAME": mk.get("PORTNAME"),
        "PORTVERSION": mk.get("PORTVERSION"),
    }
    for tok in mk.get("SUB_LIST").split():
        if "=" in tok:
            k, _, v = tok.partition("=")
            sub[k] = mk.expand(v)
    return sub


# --------------------------------------------------------------------------- #
# Manifest + archive emission
# --------------------------------------------------------------------------- #


def make_manifest(b: Build, *, compact: bool) -> dict:
    m: dict = {
        "name": b.portname,
        "origin": b.origin,
        "version": b.pkgversion,
        "comment": b.comment,
        "maintainer": b.maintainer,
        "www": b.www,
        "abi": b.abi,
        "arch": b.arch,
        "prefix": b.prefix,
        "flatsize": sum(f.src_in_stage.stat().st_size for f in b.files),
        "licenselogic": "single" if len(b.licenses) <= 1 else "and",
        "licenses": b.licenses,
        "desc": b.desc,
        "categories": b.categories,
    }
    if b.deps:
        m["deps"] = {d.name: {"origin": d.origin, "version": d.version} for d in sorted(b.deps, key=lambda d: d.name)}
    # annotations appear in BOTH manifests (real `make package` emits at least
    # {"FreeBSD_version": <__FreeBSD_version of the build host>}).
    if b.annotations:
        m["annotations"] = b.annotations
    if compact:
        return m
    # `fflags: 0` matches `pkg create` (no file flags set). mtime is the staged
    # file's install time in real pkg — inherently per-build, so we record 0
    # (deterministic; install-irrelevant).
    m["files"] = {}
    for f in sorted(b.files, key=lambda x: x.install_path):
        digest = _sha256(f.src_in_stage)
        m["files"][f.install_path] = {
            "sum": f"1${digest}",
            "uname": "root",
            "gname": "wheel",
            "perm": f.perm,
            "fflags": 0,
            "mtime": 0,
        }
    if b.directories:
        m["directories"] = {
            d: {"uname": "root", "gname": "wheel", "perm": "0755", "fflags": 0}
            for d in sorted(b.directories, key=len, reverse=True)
        }
    if b.scripts:
        m["scripts"] = b.scripts
    return m


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 16), b""):
            h.update(chunk)
    return h.hexdigest()


def _ucl_dump(manifest: dict) -> bytes:
    # libpkg reads UCL; JSON is valid UCL. Compact, stable key order.
    return json.dumps(manifest, separators=(",", ":"), ensure_ascii=False).encode() + b"\n"


def write_pkg(b: Build, out_path: Path, compression: str) -> None:
    compact = _ucl_dump(make_manifest(b, compact=True))
    full = _ucl_dump(make_manifest(b, compact=False))

    raw = io.BytesIO()
    with tarfile.open(fileobj=raw, mode="w", format=tarfile.USTAR_FORMAT) as tf:
        _add_meta(tf, "+COMPACT_MANIFEST", compact)
        _add_meta(tf, "+MANIFEST", full)
        for f in sorted(b.files, key=lambda x: x.install_path):
            ti = tarfile.TarInfo(name=f.install_path)  # leading-slash, as libpkg stores
            data = f.src_in_stage.read_bytes()
            ti.size = len(data)
            ti.mode = int(f.perm, 8)
            ti.uid = ti.gid = 0
            ti.uname, ti.gname = "root", "wheel"
            ti.mtime = 0
            ti.type = tarfile.REGTYPE
            tf.addfile(ti, io.BytesIO(data))
    tar_bytes = raw.getvalue()

    if compression == "xz":
        import lzma

        out_path.write_bytes(lzma.compress(tar_bytes, preset=6))
    else:
        out_path.write_bytes(_zstd_compress(tar_bytes))


def _add_meta(tf: tarfile.TarFile, name: str, data: bytes) -> None:
    ti = tarfile.TarInfo(name=name)
    ti.size = len(data)
    ti.mode = 0o644
    ti.uid = ti.gid = 0
    ti.uname, ti.gname = "root", "wheel"
    ti.mtime = 0
    tf.addfile(ti, io.BytesIO(data))


def _zstd_compress(data: bytes) -> bytes:
    try:
        import zstandard

        return zstandard.ZstdCompressor(level=19).compress(data)
    except ImportError:
        pass
    zstd = shutil.which("zstd")
    if not zstd:
        raise BuildError(
            "zstd compression needs the `zstd` binary or the python `zstandard` "
            "module (brew install zstd / apt install zstd), or pass --compression xz"
        )
    p = subprocess.run([zstd, "-q", "-19", "-c"], input=data, stdout=subprocess.PIPE, check=True)
    return p.stdout


# --------------------------------------------------------------------------- #
# Orchestration
# --------------------------------------------------------------------------- #


def _truthy(v: str) -> bool:
    return v.strip().lower() in ("yes", "true", "1", "on")


def _ask_or_die(flag: str, question: str, examples: str) -> str:
    """Honour 'if not provided, ask': prompt on a TTY, else fail telling the user
    to pass the flag. Never guesses a version."""
    if sys.stdin.isatty() and sys.stderr.isatty():
        sys.stderr.write(f"{question}\n  ({examples})\n{flag} = ")
        sys.stderr.flush()
        ans = sys.stdin.readline().strip()
        if ans:
            return ans
    raise BuildError(f"{flag} not provided and no value to ask for — pass {flag}. {examples}")


def abi_to_arch(abi: str) -> str:
    # FreeBSD:15:amd64 -> freebsd:15:x86:64  (the manifest's `arch` triplet).
    cpu_map = {
        "amd64": "x86:64",
        "i386": "x86:32",
        "aarch64": "aarch64:64",
        "armv7": "armv7:32",
        "powerpc64": "powerpc:64:eb",
        "powerpc64le": "powerpc:64:el",
    }
    parts = abi.split(":")
    if len(parts) != 3:
        raise BuildError(f"--abi must look like FreeBSD:15:amd64, got {abi!r}")
    _os, major, cpu = parts
    return f"{_os.lower()}:{major}:{cpu_map.get(cpu, cpu)}"


def compute_pkgversion(mk: Makefile) -> str:
    ver = mk.get("PORTVERSION") or mk.get("DISTVERSION")
    rev = mk.get("PORTREVISION").strip()
    epoch = mk.get("PORTEPOCH").strip()
    if rev and rev != "0":
        ver += f"_{rev}"
    if epoch and epoch != "0":
        ver += f",{epoch}"
    return ver


def validate_pkgversion(ver: str) -> str:
    """Validate a `--pkgversion` override (the nightly's comparable version).

    `pkg` orders versions component-wise on `.`/`_`/`,`. The nightly carries a
    pkg-safe `<target>.YYYYMMDD.N` (e.g. `3.2.16.20260606.1`), compared only
    nightly-to-nightly (separate package name) so a later build always supersedes.
    A `-` is the pkg name/version separator (`<name>-<version>.pkg`), so it MUST NOT
    appear in the version — the commit / pretty string rides the annotation + comment.
    """
    ver = ver.strip()
    if not ver:
        raise BuildError("--pkgversion was empty")
    if "-" in ver:
        raise BuildError(f"--pkgversion must not contain '-' (the pkg name/version separator): {ver!r}")
    return ver


def parse_annotations(items: list[str]) -> dict[str, str]:
    """Parse repeatable `--annotate K=V` items into an ordered {K: V} dict.

    Each item is `K=V` (V may itself contain `=`); a later K wins. Used to MERGE
    into the manifest `annotations` and to append `K=V` tokens to `comment`.
    """
    out: dict[str, str] = {}
    for item in items:
        key, sep, value = item.partition("=")
        key = key.strip()
        if not sep or not key:
            raise BuildError(f"--annotate must be K=V (got {item!r})")
        out[key] = value.strip()
    return out


def seed_vars(portdir: Path, workdir: Path, py_flavor: str) -> dict[str, str]:
    prefix = "/usr/local"
    stagedir = str(workdir / "stage")
    py_prefix = f"{py_flavor}-" if py_flavor else ""
    return {
        "PREFIX": prefix,
        "LOCALBASE": prefix,
        "DATADIR": "${PREFIX}/share/${PORTNAME}",
        "FILESDIR": str(portdir / "files"),
        "WRKDIR": str(workdir / "work"),
        "WRKSRC": "${WRKDIR}/${DISTNAME}",
        "DISTNAME": "${PORTNAME}-${DISTVERSION}",
        "DISTVERSION": "${PORTVERSION}",
        "STAGEDIR": stagedir,
        "PORTREVISION": "0",
        "PORTEPOCH": "0",
        "PYTHON_PKGNAMEPREFIX": py_prefix,
        "PY_FLAVOR": py_flavor,
        "PYTHON_CMD": "python3",
    }


_CHANNEL_PORT_SUB = {
    "stable": "pfSense-pkg-pfBlockerNG",
    "devel": "pfSense-pkg-pfBlockerNG-devel",
    "nightly": "pfSense-pkg-pfBlockerNG-nightly",
}


def print_build_origins(args: argparse.Namespace) -> int:
    """Print (one per line) every ports-tree origin dir the build will read for
    the given --channel / --php / --py-flavor, then exit 0.  Does NOT build.

    The set is: the pfBlockerNG port's own origin; every DEPENDS origin from its
    Makefile; ``lang/python{pyv}`` and ``lang/php{phpv}``; and each php extension's
    origin resolved via ``_glob_origin`` (filesystem first, git ls-files fallback
    for blobless/sparse clones).

    Requires only the pfBlockerNG port Makefile to be present — dep dirs need not
    be checked out.
    """
    ports_root = Path(args.ports).resolve()
    if args.port_dir:
        portdir = Path(args.port_dir).resolve()
    else:
        portdir = ports_root / "net" / _CHANNEL_PORT_SUB[args.channel]
    makefile = portdir / "Makefile"
    if not makefile.is_file():
        sys.stderr.write(f"build-pkg-portable: port Makefile not found: {makefile}\n")
        return 1

    # Minimal seed — no workdir, no stage, no WRKSRC expansion needed.
    seed: dict[str, str] = {
        "PREFIX": "/usr/local",
        "LOCALBASE": "/usr/local",
        "DATADIR": "${PREFIX}/share/${PORTNAME}",
        "FILESDIR": str(portdir / "files"),
        "PORTREVISION": "0",
        "PORTEPOCH": "0",
    }
    py_flavor = args.py_flavor or ""
    if py_flavor:
        seed["PYTHON_PKGNAMEPREFIX"] = f"{py_flavor}-"
        seed["PY_FLAVOR"] = py_flavor
    mk = Makefile(makefile, seed)

    origins: set[str] = set()

    # 1. The pfBlockerNG port's own origin.
    categories = mk.get("CATEGORIES").split()
    portname = mk.get("PORTNAME")
    if categories and portname:
        origins.add(f"{categories[0]}/{portname}")

    # 2. Every RUN_DEPENDS / LIB_DEPENDS origin (strip @flavor).
    for var in ("LIB_DEPENDS", "RUN_DEPENDS"):
        for ent in mk.get(var).split():
            _, _, origin_spec = ent.partition(":")
            if origin_spec:
                origin, _, _ = origin_spec.partition("@")
                if origin:
                    origins.add(origin)

    # 3. USES-injected lang ports.
    uses_bases = {u.split(":")[0] for u in mk.get("USES").split()}
    if "python" in uses_bases and py_flavor:
        pyv = py_flavor[2:] if py_flavor.startswith("py") else py_flavor
        origins.add(f"lang/python{pyv}")
    if "php" in uses_bases:
        php_ver = args.php or ""
        if php_ver:
            phpv = php_ver.replace(".", "")
            origins.add(f"lang/php{phpv}")
            # 4. Each php extension's category-qualified origin.
            for tok in mk.get("USE_PHP").split():
                ext = tok.split(":")[0]
                origin = _glob_origin(ports_root, f"php{phpv}-{ext}")
                origins.add(origin if origin else f"lang/php{phpv}-{ext}")

    for o in sorted(origins):
        print(o)
    return 0


def run_build(args: argparse.Namespace) -> Build:
    ports_root = Path(args.ports).resolve()
    if args.port_dir:
        portdir = Path(args.port_dir).resolve()
    else:
        portdir = ports_root / "net" / _CHANNEL_PORT_SUB[args.channel]
    makefile = portdir / "Makefile"
    if not makefile.is_file():
        raise BuildError(f"port Makefile not found: {makefile}")

    # Version-dependent TARGET facts. These are properties of the target pfSense
    # edition+version, NOT of the --ports checkout: that fork tree is a single
    # snapshot whose default versions (e.g. PHP 8.4) need not match what a given
    # pfSense release ships (CE 2.8 = PHP 8.3, Python 3.11). So never derive them
    # from the tree — take them explicitly and ask if missing. The repo's
    # docs/misc/pfSense_versions.md is the authoritative per-version mirror.
    #
    # Three such facts affect this tool's output: the ABI (manifest abi/arch), the
    # Python flavor, and the PHP version. `make package` records 12 deps for
    # pfBlockerNG, not just the 9 RUN_DEPENDS: USES=php + USE_PHP=intl inject
    # php<XY> + php<XY>-intl, and USES=python injects python<XY> (verified against a
    # real make-package .pkg). Those carry the TARGET's php/python version, which is
    # NOT the ports tree default (build-pkg.sh pins php=8.3 though the fork tree
    # defaults to 8.4) — so php is asked for too (only when USES=php).
    abi = args.abi or _ask_or_die(
        "--abi",
        "Which target ABI? (FreeBSD major differs per pfSense edition/version)",
        "e.g. FreeBSD:15:amd64 (CE 2.8) or FreeBSD:16:amd64 (Plus) — see docs/misc/pfSense_versions.md",
    )
    arch = args.arch or abi_to_arch(abi)
    py_flavor = args.py_flavor or _ask_or_die(
        "--py-flavor",
        "Which Python flavor? (sets the py3xx- dep names; tracks the target's base Python, not the ports tree)",
        "e.g. py311 for pfSense CE 2.8 (Python 3.11) — see docs/misc/pfSense_versions.md",
    )

    workdir = Path(tempfile.mkdtemp(prefix="pfbng-pkg-"))
    args._workdir = workdir
    seed = seed_vars(portdir, workdir, py_flavor)
    mk = Makefile(makefile, seed)

    prefix = mk.get("PREFIX")
    portname = mk.get("PORTNAME")
    # The version is computed from the Makefile by default; a nightly build overrides
    # it with `--pkgversion <target>.YYYYMMDD.N` (CI passes it). Must be pkg-safe (no
    # '-'); the commit / pretty string rides the annotation + comment, not the version.
    pkgversion = validate_pkgversion(args.pkgversion) if args.pkgversion else compute_pkgversion(mk)
    # PKGVERSION/PKGNAME are framework-derived, not assigned in the Makefile, but
    # the recipe references them (e.g. the info.xml %%PKGVERSION%% reinplace). Seed
    # them so they expand to real values instead of empty.
    mk.vars["PKGVERSION"] = pkgversion
    mk.vars["PKGNAME"] = f"{portname}-{pkgversion}"
    categories = mk.get("CATEGORIES").split()
    origin = f"{categories[0]}/{portname}" if categories else portname

    # PHP version is a target fact, asked only when the port USES php.
    uses_bases = {u.split(":")[0] for u in mk.get("USES").split()}
    php_ver = ""
    if "php" in uses_bases:
        php_ver = args.php or _ask_or_die(
            "--php",
            "Which target PHP version? (USES=php injects a php<XY>[-ext] dep)",
            "e.g. 8.3 for pfSense CE 2.8 — see docs/misc/pfSense_versions.md",
        )

    descr_path = portdir / "pkg-descr"
    desc, descr_www = parse_descr(descr_path.read_text()) if descr_path.is_file() else ("", "")
    www = resolve_www(mk, descr_www)

    # Nightly provenance: `--annotate K=V` merges into the manifest `annotations`
    # AND appends `(K=V, …)` to the comment, so both `pkg info` and `pkg info -A`
    # surface it (e.g. commit=<sha>). Default empty -> release build unchanged.
    extra_annotations = parse_annotations(args.annotate)
    comment = mk.get("COMMENT")
    if extra_annotations:
        comment += " (" + ", ".join(f"{k}={v}" for k, v in extra_annotations.items()) + ")"

    b = Build(
        portname=portname,
        pkgversion=pkgversion,
        origin=origin,
        comment=comment,
        maintainer=mk.get("MAINTAINER"),
        categories=categories,
        licenses=mk.get("LICENSE").split() or [],
        www=www,
        desc=desc,
        prefix=prefix,
        abi=abi,
        arch=arch,
    )

    # --- source + recipe -------------------------------------------------- #
    Path(seed["STAGEDIR"]).mkdir(parents=True, exist_ok=True)
    Path(mk.get("WRKDIR")).mkdir(parents=True, exist_ok=True)
    acquire_source(mk, workdir, args)

    recipe = Recipe(mk)
    # do-extract only matters for the classic port (mkdir WRKSRC); harmless for GH.
    if "do-extract" in mk.recipes and not _truthy(mk.get("USE_GITHUB")):
        recipe.run("do-extract")
    if "post-extract" in mk.recipes:
        recipe.run("post-extract")
    if "do-install" not in mk.recipes:
        raise BuildError("port has no do-install target — unexpected for a pfSense pkg port")
    recipe.run("do-install")
    if "post-install" in mk.recipes:
        recipe.run("post-install")

    # --- collect staged files, validate against the plist ----------------- #
    stagedir = Path(seed["STAGEDIR"])
    staged_paths = {"/" + os.path.relpath(p, stagedir): p for p in stagedir.rglob("*") if p.is_file()}

    plist_path = portdir / "pkg-plist"
    plist_sub = {"DATADIR": "share/" + portname, "PORTNAME": portname, "PORTVERSION": mk.get("PORTVERSION")}
    plist_files, plist_dirs = parse_plist(plist_path.read_text(), plist_sub, prefix)

    plist_set = set(plist_files)
    staged_set = set(staged_paths)
    missing = plist_set - staged_set
    extra = staged_set - plist_set
    if missing:
        raise BuildError("plist lists files the recipe did not stage:\n  " + "\n  ".join(sorted(missing)))
    if extra:
        raise BuildError("recipe staged files not in the plist:\n  " + "\n  ".join(sorted(extra)))

    for ip in sorted(plist_set):
        perm = recipe.modes.get(ip, "0644")
        if ip not in recipe.modes:
            sys.stderr.write(f"warning: no mode recorded for {ip}; defaulting 0644\n")
        b.files.append(StagedFile(install_path=ip, src_in_stage=staged_paths[ip], perm=perm))

    b.directories = plist_dirs
    b.scripts = build_scripts(mk, portdir / "files")
    # Declared RUN_DEPENDS/LIB_DEPENDS + the deps USES injects (php/python), as
    # `make package` records them. Dedup by name (declared win).
    deps: dict[str, Dep] = {}
    for d in resolve_deps(mk, ports_root, seed) + synthesize_uses_deps(mk, ports_root, php_ver, py_flavor, seed):
        deps.setdefault(d.name, d)
    # Inject the variant guard RUN_DEPENDS derived from --php and --py-flavor
    # whenever --php is supplied. These ensure `pkg add` rejects a wrong-variant
    # .pkg (CE php83 won't satisfy a Plus php85 dep). The dep names are derived —
    # not hardcoded — so a CE/Plus PHP or Python bump is just a ci-metadata edit.
    # (ADR-20: the builder is dumb — it stamps no variant; the guard is purely the
    # versioned php/py deps the requested --php/--py-flavor imply.) Keyed on the CLI
    # args, NOT the USES-derived php_ver: the guard is independent of whether the port
    # itself USES=php (php_ver is "" for a non-php port, but the guard must still land).
    if args.php:
        # Use the RESOLVED py_flavor (prompt-filled when --py-flavor is omitted), not the
        # raw arg — otherwise an interactive build would silently drop the Python guard.
        for dep_name, dep_origin in _resolve_variant_deps(args.php, py_flavor):
            # Variant guard deps augment (never override) USES-synthesised deps. A real
            # origin is mandatory — libpkg's `pkg repo` aborts on an empty dep origin.
            deps.setdefault(dep_name, Dep(name=dep_name, origin=dep_origin, version="0"))
    b.deps = list(deps.values())
    # Best-effort dep versions come from the ports tree; the version make package
    # actually records is the INSTALLED binary package's. Pin those exactly from
    # the target repo catalogue when asked.
    if args.repo_catalogue:
        sys.stderr.write(f"==> pinning dep versions from repo catalogue ({args.repo_catalogue})\n")
        apply_repo_catalogue(b.deps, args.repo_catalogue, abi)
    if args.freebsd_version:
        b.annotations = {"FreeBSD_version": args.freebsd_version}
    # `--annotate K=V` merges on top (e.g. commit=<sha>); release build adds nothing.
    b.annotations.update(extra_annotations)
    return b


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(
        prog="build-pkg-portable.py",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description="Build a pfSense-installable pfBlockerNG .pkg off-FreeBSD, from the FreeBSD ports files.",
        epilog=(
            "examples:\n"
            "  # build from a local working tree, targeting pfSense CE 2.8\n"
            "  build-pkg-portable.py --ports ../FreeBSD-ports --local-src . \\\n"
            "      --abi FreeBSD:15:amd64 --py-flavor py311 --php 8.3 --out /tmp\n\n"
            "  # build a specific commit (with a src/ tree) and pin exact dep versions\n"
            "  build-pkg-portable.py --ports ../FreeBSD-ports --gh-tagname <sha> \\\n"
            "      --abi FreeBSD:15:amd64 --py-flavor py311 --php 8.3 --repo-catalogue auto\n\n"
            "  # inspect the plan without writing a .pkg\n"
            "  build-pkg-portable.py --ports ../FreeBSD-ports --local-src . \\\n"
            "      --abi FreeBSD:15:amd64 --py-flavor py311 --php 8.3 --dry-run\n\n"
            "See docs/build-pkg-portable.md for the full reference."
        ),
    )
    ap.add_argument(
        "--ports",
        default=None,
        help=(
            "FreeBSD-ports checkout (contains net/pfSense-pkg-pfBlockerNG[-devel]); "
            "not required for --print-port-origin"
        ),
    )

    g_port = ap.add_argument_group("port selection")
    g_port.add_argument(
        "--channel",
        choices=("devel", "stable", "nightly"),
        default="devel",
        help="which port: devel/stable release, or nightly (default: devel)",
    )
    g_port.add_argument("--port-dir", help="explicit port directory (overrides --channel)")

    g_target = ap.add_argument_group(
        "target facts (version-dependent; asked if omitted — never read from the ports tree)"
    )
    g_target.add_argument(
        "--abi", default="", help="target ABI, e.g. FreeBSD:15:amd64 (CE 2.8) or FreeBSD:16:amd64 (Plus)"
    )
    g_target.add_argument("--arch", default="", help="manifest arch triplet (default: derived from --abi)")
    g_target.add_argument("--py-flavor", default="", help="py3xx- flavor for dep names, e.g. py311 (CE 2.8)")
    g_target.add_argument(
        "--php", default="", help="PHP version for the USES=php dep, e.g. 8.3 (asked only if USES php)"
    )
    g_target.add_argument(
        "--freebsd-version", default="", help="build host __FreeBSD_version for annotations, e.g. 1500068 (optional)"
    )

    g_snap = ap.add_argument_group("nightly overrides (ADR-18; default off — release build byte-identical)")
    g_snap.add_argument(
        "--pkgversion",
        default="",
        help=(
            "override the computed package version with the nightly's pkg-safe comparable "
            "version, e.g. 3.2.16.20260606.1 (must not contain '-')."
        ),
    )
    g_snap.add_argument(
        "--annotate",
        action="append",
        default=[],
        metavar="K=V",
        help=(
            "add a manifest annotation K=V (repeatable; e.g. --annotate commit=<sha>). "
            "Merged into `annotations` and appended to `comment` (surfaced by pkg info -A)."
        ),
    )

    g_src = ap.add_argument_group("source (USE_GITHUB ports)")
    g_src.add_argument(
        "--local-src", help="build from this local pfBlockerNG checkout instead of fetching the GitHub tag"
    )
    g_src.add_argument(
        "--gh-tagname", help="override GH_TAGNAME (commit/tag) when fetching (default: the Makefile's v${PORTVERSION})"
    )

    g_deps = ap.add_argument_group("dependency versions")
    g_deps.add_argument(
        "--repo-catalogue",
        default="",
        help="pin exact dep versions from a repo packagesite (.yaml/.pkg path/URL, or 'auto')",
    )

    g_out = ap.add_argument_group("output")
    g_out.add_argument("--out", default=".", help="output directory for the .pkg (default: cwd)")
    g_out.add_argument(
        "--compression", choices=("zstd", "xz"), default="zstd", help="output compression (default: zstd)"
    )
    g_out.add_argument("--keep-work", action="store_true", help="keep the temporary work/staging dir")
    g_out.add_argument("--dry-run", action="store_true", help="print the build plan; do not write a .pkg")
    g_out.add_argument(
        "--print-build-origins",
        action="store_true",
        help=(
            "print (one per line) every ports-tree origin dir the build will read "
            "for the given --channel/--php/--py-flavor, then exit 0 without building. "
            "Used by scripts/sparse-clone-ports.sh to derive the sparse-checkout set."
        ),
    )
    g_out.add_argument(
        "--print-port-origin",
        action="store_true",
        help=(
            "print the port origin dir (e.g. net/pfSense-pkg-pfBlockerNG-devel) for "
            "--channel, then exit 0.  No --ports tree required.  Single source of truth "
            "for the channel→origin mapping; used by scripts/sparse-clone-ports.sh."
        ),
    )

    args = ap.parse_args(argv)

    if args.print_port_origin:
        channel = args.channel
        if channel not in _CHANNEL_PORT_SUB:
            sys.stderr.write(f"build-pkg-portable: unknown channel: {channel!r}\n")
            return 1
        print(f"net/{_CHANNEL_PORT_SUB[channel]}")
        return 0

    if not args.ports:
        ap.error("--ports is required")

    if args.print_build_origins:
        return print_build_origins(args)

    try:
        b = run_build(args)
    except BuildError as e:
        sys.stderr.write(f"build-pkg-portable: {e}\n")
        return 1

    workdir = getattr(args, "_workdir", None)
    try:
        if args.dry_run:
            _print_plan(b)
            return 0
        out_dir = Path(args.out).resolve()
        out_dir.mkdir(parents=True, exist_ok=True)
        out_path = out_dir / f"{b.pkgname}.pkg"
        write_pkg(b, out_path, args.compression)
        sys.stderr.write(f"==> wrote {out_path}  ({out_path.stat().st_size} bytes, {len(b.files)} files)\n")
        print(out_path)
        return 0
    finally:
        if workdir and not args.keep_work:
            shutil.rmtree(workdir, ignore_errors=True)
        elif workdir:
            sys.stderr.write(f"==> kept work dir {workdir}\n")


def _print_plan(b: Build) -> None:
    print(f"name        {b.portname}")
    print(f"version     {b.pkgversion}")
    print(f"origin      {b.origin}")
    print(f"abi/arch    {b.abi}  /  {b.arch}")
    print(f"comment     {b.comment}")
    print(f"www         {b.www}")
    print(f"licenses    {b.licenses} ({'single' if len(b.licenses) <= 1 else 'and'})")
    print(f"files       {len(b.files)}")
    print(f"directories {b.directories}")
    print(f"scripts     {sorted(b.scripts)}")
    print(f"flatsize    {sum(f.src_in_stage.stat().st_size for f in b.files)} bytes")
    print(f"deps        {len(b.deps)}")
    for d in sorted(b.deps, key=lambda x: x.name):
        print(f"  - {d.name:24s} {d.origin:28s} {d.version}")
    print("sample files (path  perm):")
    for f in sorted(b.files, key=lambda x: x.install_path)[:8]:
        print(f"  {f.perm}  {f.install_path}")


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
