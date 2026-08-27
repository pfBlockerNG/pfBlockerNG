"""Tests for scripts/build-pkg-portable.py.

All fixtures here are SYNTHETIC and authored in this repository — a tiny made-up
"port" and ports tree — so the suite vendors no FreeBSD ports/pkg source, no real
`packagesite`, and no compiled artifacts. That keeps the test data unambiguously
Apache-2.0 (this repo's licence) and lets the tests run with no network and no
FreeBSD host.

The tool is a hyphen-named CLI script, so it is loaded by path via importlib.
"""

from __future__ import annotations

import gzip
import importlib.util
import io
import json
import lzma
import os
import shutil
import subprocess
import sys
import tarfile
import tempfile
import time
from pathlib import Path
from typing import Any

import pfb_pkg
import pytest

from tests.gitenv import scrubbed_git_env

# --------------------------------------------------------------------------- #
# Load the hyphen-named tool as a module.
# --------------------------------------------------------------------------- #

_TOOL = Path(__file__).resolve().parent.parent / "scripts" / "build-pkg-portable.py"
_spec = importlib.util.spec_from_file_location("build_pkg_portable", _TOOL)
assert _spec is not None and _spec.loader is not None
bpp = importlib.util.module_from_spec(_spec)
sys.modules[_spec.name] = bpp
_spec.loader.exec_module(bpp)


def make_mk(
    tmp_path: Path, text: str, seed: dict | None = None
) -> Any:  # -> bpp.Makefile (runtime-loaded; not statically importable)
    p = tmp_path / "Makefile"
    p.write_text(text)
    return bpp.Makefile(p, seed or {})


# --------------------------------------------------------------------------- #
# Makefile evaluator
# --------------------------------------------------------------------------- #


def test_makefile_assignment_ops(tmp_path: Path) -> None:
    mk = make_mk(
        tmp_path,
        "A=\t1\n"
        "A?=\t2\n"  # ignored: A already set
        "B?=\t3\n"  # set: B unset
        "C=\tx\n"
        "C+=\ty\n"  # append
        "D:=\tz\n",
    )
    assert mk.get("A") == "1"
    assert mk.get("B") == "3"
    assert mk.get("C") == "x y"
    assert mk.get("D") == "z"


def test_makefile_seed_default_and_override(tmp_path: Path) -> None:
    mk = make_mk(tmp_path, "PREFIX=\t/somewhere\n", seed={"PREFIX": "/usr/local", "LOCALBASE": "/usr/local"})
    assert mk.get("PREFIX") == "/somewhere"  # Makefile overrides seed
    assert mk.get("LOCALBASE") == "/usr/local"  # seed default survives


def test_makefile_expansion_and_modifiers(tmp_path: Path) -> None:
    mk = make_mk(
        tmp_path,
        "PORTNAME=\tfoo\nPORTVERSION=\t1.2\nDISTNAME=\t${PORTNAME}-${PORTVERSION}\nWRKSRC=\t/w/${DISTNAME}/src\n",
    )
    assert mk.get("DISTNAME") == "foo-1.2"
    assert mk.get("WRKSRC") == "/w/foo-1.2/src"
    # :H (dirname) and :T (basename) modifiers
    mk2 = make_mk(tmp_path, "P=\t/a/b/c\nH=\t${P:H}\nT=\t${P:T}\n")
    assert mk2.get("H") == "/a/b"
    assert mk2.get("T") == "c"


def test_makefile_comment_stripping(tmp_path: Path) -> None:
    mk = make_mk(tmp_path, "DISTFILES=\t# empty\nX=\tvalue # trailing\n")
    assert mk.get("DISTFILES") == ""
    assert mk.get("X") == "value"


@pytest.mark.parametrize(
    "directive",
    [".if defined(X)", ".ifdef X", ".for f in a b", ".else", ".elif ${X}", ".endif", ".endfor"],
)
def test_makefile_conditional_directive_is_a_hard_error(tmp_path: Path, directive: str) -> None:
    # The evaluator has no branch logic: silently skipping a conditional/loop
    # would silently drop the port logic it guards (issue #727 finding 3a).
    with pytest.raises(bpp.BuildError, match="directive"):
        make_mk(tmp_path, f"A=\t1\n{directive}\n")


def test_makefile_include_stays_ignored(tmp_path: Path) -> None:
    # .include <bsd.port.mk> is the one dot-directive every port legitimately
    # carries — it must keep parsing cleanly (the framework vars are seeded).
    mk = make_mk(tmp_path, "A=\t1\n.include <bsd.port.mk>\n")
    assert mk.get("A") == "1"


def test_read_dep_port_tolerates_conditionals(tmp_path: Path) -> None:
    # Behaviour-preserving pin: dep-port mining is best-effort over REAL ports
    # tree Makefiles (php83, jq, …), which routinely carry .if blocks — the
    # directive hard-error must NOT apply there or every real build would break.
    ports = tmp_path / "ports"
    write_port(ports, "misc/dep", "PORTNAME=\tdep\nPORTVERSION=\t2.5\n.if defined(NEVER)\n.endif\n")
    seed = {"PORTREVISION": "0", "PORTEPOCH": "0"}
    assert bpp._read_dep_port(ports / "misc/dep/Makefile", "", seed) == ("dep", "2.5")


def test_makefile_line_continuation_and_recipe_capture(tmp_path: Path) -> None:
    mk = make_mk(
        tmp_path,
        "RUN_DEPENDS=\ta:cat/a \\\n\t\tb:cat/b\n"
        "do-install:\n"
        "\t${MKDIR} ${STAGEDIR}/x\n"
        "\t${INSTALL_DATA} a b\n"
        ".include <bsd.port.mk>\n",
        seed={"STAGEDIR": "/stage"},
    )
    assert mk.get("RUN_DEPENDS") == "a:cat/a b:cat/b"
    assert "do-install" in mk.recipes
    assert mk.recipes["do-install"] == ["${MKDIR} ${STAGEDIR}/x", "${INSTALL_DATA} a b"]


# --------------------------------------------------------------------------- #
# Pure helpers
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    "ver,rev,epoch,expected",
    [
        ("1.0", "", "", "1.0"),
        ("1.0", "2", "", "1.0_2"),
        ("1.0", "0", "", "1.0"),
        ("1.0", "2", "3", "1.0_2,3"),
        # bsd.port.mk: PKGVERSION = ${PORTVERSION:C/[-_,]/./g}… — '-'/'_'/',' in
        # PORTVERSION become '.' BEFORE the _REV/,EPOCH suffixes are appended
        # (else a '4.0.0-r1' edit would break the <name>-<version>.pkg split).
        ("4.0.0-r1", "", "", "4.0.0.r1"),
        ("4.0.0-r1", "2", "", "4.0.0.r1_2"),
        ("1_0,x", "", "", "1.0.x"),
    ],
)
def test_compute_pkgversion(tmp_path: Path, ver: str, rev: str, epoch: str, expected: str) -> None:
    text = f"PORTVERSION=\t{ver}\n"
    if rev:
        text += f"PORTREVISION=\t{rev}\n"
    if epoch:
        text += f"PORTEPOCH=\t{epoch}\n"
    mk = make_mk(tmp_path, text, seed={"PORTREVISION": "0", "PORTEPOCH": "0"})
    assert bpp.compute_pkgversion(mk) == expected


@pytest.mark.parametrize(
    "abi,arch",
    [
        ("FreeBSD:15:amd64", "freebsd:15:x86:64"),
        ("FreeBSD:16:amd64", "freebsd:16:x86:64"),
        ("FreeBSD:14:aarch64", "freebsd:14:aarch64:64"),
        ("FreeBSD:13:i386", "freebsd:13:x86:32"),
        # FreeBSD pkg ALTABI tags PowerPC with an explicit endian token:
        # big-endian "eb", little-endian "el".
        ("FreeBSD:15:powerpc64le", "freebsd:15:powerpc:64:el"),
        ("FreeBSD:15:powerpc64", "freebsd:15:powerpc:64:eb"),
        # armv7 carries the full endian/eabi/float triplet — per pkg's own
        # machine_arch_translation[] (libpkg/pkg_abi.c), not a bare armv7:32.
        ("FreeBSD:15:armv7", "freebsd:15:armv7:32:el:eabi:hardfp"),
    ],
)
def test_abi_to_arch(abi: str, arch: str) -> None:
    assert bpp.abi_to_arch(abi) == arch


def test_abi_to_arch_malformed() -> None:
    with pytest.raises(bpp.BuildError):
        bpp.abi_to_arch("nonsense")


def test_parse_descr_keeps_www_line_verbatim() -> None:
    descr = "Line one.\nLine two.\n\nWWW: https://example.org/p\n"
    desc, www = bpp.parse_descr(descr)
    assert www == "https://example.org/p"
    # desc is the whole file (incl. the WWW line), trailing whitespace trimmed.
    assert desc == "Line one.\nLine two.\n\nWWW: https://example.org/p"


def test_resolve_www_precedence(tmp_path: Path) -> None:
    explicit = make_mk(tmp_path, "WWW=\thttps://explicit/\n")
    assert bpp.resolve_www(explicit, "https://descr/") == "https://explicit/"

    gh = make_mk(tmp_path, "USE_GITHUB=\tyes\nGH_ACCOUNT=\tacc\nGH_PROJECT=\tProj\n")
    assert bpp.resolve_www(gh, "https://descr/") == "https://github.com/acc/Proj/"

    plain = make_mk(tmp_path, "PORTNAME=\tx\n")
    assert bpp.resolve_www(plain, "https://descr/") == "https://descr/"


def test_parse_plist_files_dirs_and_datadir() -> None:
    plist = "/etc/inc/priv/x.inc\nbin/y.sh\n%%DATADIR%%/info.xml\n@dir /etc/inc/priv\n@dir /etc/inc\n"
    sub = {"DATADIR": "share/portx"}
    files, dirs = bpp.parse_plist(plist, sub, "/usr/local")
    assert files == ["/etc/inc/priv/x.inc", "/usr/local/bin/y.sh", "/usr/local/share/portx/info.xml"]
    assert dirs == ["/etc/inc/priv", "/etc/inc"]


def test_parse_plist_unresolved_token_raises() -> None:
    with pytest.raises(bpp.BuildError):
        bpp.parse_plist("%%NOPE%%/x\n", {}, "/usr/local")


def test_parse_plist_unknown_keyword_raises() -> None:
    # Fail closed on an unhandled @keyword (don't silently emit a wrong package).
    with pytest.raises(bpp.BuildError, match="@sample"):
        bpp.parse_plist("@sample foo.conf.sample\nbin/x\n", {}, "/usr/local")


@pytest.mark.parametrize(
    "expr,text,expected",
    [
        ("s|A|B|", "A A\nA", "B A\nB"),  # first per line (no g)
        ("s|A|B|g", "A A\nA", "B B\nB"),  # all (g)
        ("s/x/y/", "x", "y"),  # slash delimiter
    ],
)
def test_sed_s(expr: str, text: str, expected: str) -> None:
    r = bpp.Recipe.__new__(bpp.Recipe)
    assert r._sed_s(text, expr) == expected


def test_sed_s_unsupported() -> None:
    r = bpp.Recipe.__new__(bpp.Recipe)
    with pytest.raises(bpp.BuildError):
        r._sed_s("text", "y|a|b|")  # only the s command is supported


@pytest.mark.parametrize(
    "expr",
    [
        "s|a.b|Z|",  # '.' would match any char in real sed; literal replace would miss
        "s|x[0-9]|Z|",  # character class
        "s|^a|Z|",  # anchor
        "s|a\\+|Z|",  # escaped metachar — still not literal-safe
    ],
)
def test_sed_s_rejects_non_literal_pattern(expr: str) -> None:
    # The emulation is a literal str.replace; a regex pattern would be applied
    # wrongly with no error (issue #727 finding 3b) — it must fail loud instead.
    r = bpp.Recipe.__new__(bpp.Recipe)
    with pytest.raises(bpp.BuildError, match="literal"):
        r._sed_s("aXb", expr)


@pytest.mark.parametrize("expr", ["s|A|B&C|", "s|A|\\1|"])
def test_sed_s_rejects_ampersand_and_backref_replacement(expr: str) -> None:
    # sed's & (whole match) and \N (group) have no literal-replace equivalent.
    r = bpp.Recipe.__new__(bpp.Recipe)
    with pytest.raises(bpp.BuildError, match="literal"):
        r._sed_s("A", expr)


# --------------------------------------------------------------------------- #
# Recipe interpreter (modes, mv, sed) on a synthetic source tree
# --------------------------------------------------------------------------- #


def test_recipe_install_modes_mv_sed(tmp_path: Path) -> None:
    src = tmp_path / "src"
    (src).mkdir()
    (src / "data.txt").write_text("data")
    (src / "script.sh").write_text("#!/bin/sh\necho hi\n")
    (src / "tpl.xml").write_text("v=%%PKGVERSION%%\n")
    stage = tmp_path / "stage"
    stage.mkdir()

    text = (
        f"SRC=\t{src}\nSTAGEDIR=\t{stage}\nPREFIX=\t/usr/local\nPKGVERSION=\t9.9\n"
        "do-install:\n"
        "\t${MKDIR} ${STAGEDIR}${PREFIX}/bin\n"
        "\t${MKDIR} ${STAGEDIR}${PREFIX}/etc\n"
        "\t${INSTALL_DATA} ${SRC}/data.txt ${STAGEDIR}${PREFIX}/etc\n"
        "\t${INSTALL_SCRIPT} ${SRC}/script.sh ${STAGEDIR}${PREFIX}/bin\n"
        "\t${INSTALL_DATA} ${SRC}/tpl.xml ${STAGEDIR}${PREFIX}/etc\n"
        "\t@${REINPLACE_CMD} -i '' -e \"s|%%PKGVERSION%%|${PKGVERSION}|\" ${STAGEDIR}${PREFIX}/etc/tpl.xml\n"
    )
    mk = make_mk(tmp_path, text)
    r = bpp.Recipe(mk)
    r.run("do-install")

    assert (stage / "usr/local/etc/data.txt").read_text() == "data"
    assert r.modes["/usr/local/etc/data.txt"] == "0644"
    assert r.modes["/usr/local/bin/script.sh"] == "0555"  # INSTALL_SCRIPT == BINMODE 0555
    assert (stage / "usr/local/etc/tpl.xml").read_text() == "v=9.9\n"  # reinplace applied to staged file


def test_recipe_copytree_share_then_script_glob_preserves_payload_and_modes(tmp_path: Path) -> None:
    src = tmp_path / "src"
    (src / "usr/local/pkg/app").mkdir(parents=True)
    (src / "usr/local/pkg/app/app.inc").write_text("<?php\n")
    (src / "usr/local/pkg/app/helper.sh").write_text("#!/bin/sh\n")
    stage = tmp_path / "stage"
    stage.mkdir()

    mk = make_mk(
        tmp_path,
        (
            f"WRKSRC=\t{src}\nSTAGEDIR=\t{stage}\nPREFIX=\t/usr/local\n"
            "do-install:\n"
            "\t(cd ${WRKSRC} && ${COPYTREE_SHARE} . ${STAGEDIR})\n"
            "\t${INSTALL_SCRIPT} ${WRKSRC}${PREFIX}/pkg/app/*.sh ${STAGEDIR}${PREFIX}/pkg/app\n"
        ),
    )
    recipe = bpp.Recipe(mk)
    recipe.run("do-install")

    assert (stage / "usr/local/pkg/app/app.inc").read_text() == "<?php\n"
    assert (stage / "usr/local/pkg/app/helper.sh").read_text() == "#!/bin/sh\n"
    assert recipe.modes["/usr/local/pkg/app/app.inc"] == "0644"
    assert recipe.modes["/usr/local/pkg/app/helper.sh"] == "0555"


def test_recipe_install_can_overwrite_a_readonly_staged_file(tmp_path: Path) -> None:
    src = tmp_path / "src"
    src.mkdir()
    (src / "helper.sh").write_text("#!/bin/sh\necho first\n")
    stage = tmp_path / "stage"
    (stage / "usr/local/bin").mkdir(parents=True)

    mk = make_mk(
        tmp_path,
        (
            f"SRC=\t{src}\nSTAGEDIR=\t{stage}\nPREFIX=\t/usr/local\n"
            "do-install:\n"
            "\t${INSTALL_SCRIPT} ${SRC}/helper.sh ${STAGEDIR}${PREFIX}/bin\n"
            "\t${INSTALL_SCRIPT} ${SRC}/helper.sh ${STAGEDIR}${PREFIX}/bin\n"
        ),
    )

    recipe = bpp.Recipe(mk)
    recipe.run("do-install")

    assert (stage / "usr/local/bin/helper.sh").read_text() == "#!/bin/sh\necho first\n"
    assert recipe.modes["/usr/local/bin/helper.sh"] == "0555"


def test_recipe_bare_mv_and_unknown_command(tmp_path: Path) -> None:
    src = tmp_path / "w"
    (src / "a").mkdir(parents=True)
    (src / "a" / "f").write_text("x")
    mk = make_mk(
        tmp_path,
        f"WRKSRC=\t{src}\npost-extract:\n\t@mv ${{WRKSRC}}/a ${{WRKSRC}}/b\n",
    )
    bpp.Recipe(mk).run("post-extract")
    assert (src / "b" / "f").read_text() == "x"

    bad = make_mk(tmp_path, "do-install:\n\t${FROBNICATE} a b\n")
    with pytest.raises(bpp.BuildError, match="unsupported recipe command"):
        bpp.Recipe(bad).run("do-install")


def test_recipe_unused_commands_are_unsupported(tmp_path: Path) -> None:
    # cp / ln / rm / install_program were removed (#502 B4): the port Makefiles
    # never emit them, so they must now fail as hard errors rather than silently
    # carrying a maintenance burden. mv stays (exercised above), so it is NOT here.
    for cmd in ("CP", "LN", "RM", "INSTALL_PROGRAM"):
        mk = make_mk(tmp_path, f"do-install:\n\t${{{cmd}}} a b\n")
        with pytest.raises(bpp.BuildError, match="unsupported recipe command"):
            bpp.Recipe(mk).run("do-install")


def test_safe_extract_rejects_traversal(tmp_path: Path) -> None:
    # A path-traversal member must be rejected (the stdlib 'data' filter).
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as tf:
        for name in ("ok.txt", "../escape.txt"):
            data = b"x"
            ti = tarfile.TarInfo(name)
            ti.size = len(data)
            tf.addfile(ti, io.BytesIO(data))
    buf.seek(0)
    with tarfile.open(fileobj=buf) as tf2, pytest.raises(bpp.BuildError):
        bpp._safe_extract(tf2, tmp_path / "dest")


def test_local_source_acquisition_excludes_untracked_artifacts(tmp_path: Path) -> None:
    checkout = tmp_path / "checkout"
    source = checkout / "src/usr/local/pkg/app"
    (source / "__pycache__").mkdir(parents=True)
    (source / "app.inc").write_text("<?php\n")
    (source / ".DS_Store").write_text("finder")
    (source / "__pycache__/app.pyc").write_bytes(b"cache")
    workdir = tmp_path / "work"
    wrksrc = workdir / "source/src"
    mk = make_mk(tmp_path, f"USE_GITHUB=\tyes\nWRKSRC=\t{wrksrc}\n")

    result = bpp.acquire_source(
        mk,
        workdir,
        bpp.argparse.Namespace(local_src=str(checkout), gh_tagname=None),
    )

    assert result == wrksrc
    assert (wrksrc / "usr/local/pkg/app/app.inc").is_file()
    assert not (wrksrc / "usr/local/pkg/app/.DS_Store").exists()
    assert not (wrksrc / "usr/local/pkg/app/__pycache__").exists()


# --------------------------------------------------------------------------- #
# Scripts (SUB_FILES -> manifest scripts) — fail-loud guards (issue #727 f.1)
# --------------------------------------------------------------------------- #


def test_build_scripts_unknown_sub_files_name_raises(tmp_path: Path) -> None:
    # A SUB_FILES entry the tool does not model (pkg-message, pkg-*.lua, …) is
    # picked up by a real `make package`; skipping it ships an incomplete
    # package. It must be a hard error naming the file, not a silent continue.
    files = tmp_path / "files"
    files.mkdir()
    (files / "pkg-message.in").write_text("hello\n")
    mk = make_mk(tmp_path, "PORTNAME=\tx\nSUB_FILES=\tpkg-message\n")
    with pytest.raises(bpp.BuildError, match="pkg-message"):
        bpp.build_scripts(mk, files)


def test_build_scripts_unresolved_token_raises(tmp_path: Path) -> None:
    # Mirror parse_plist: a %%TOKEN%% still present after SUB_LIST substitution
    # would ship literally inside the install script — fail loud instead.
    files = tmp_path / "files"
    files.mkdir()
    (files / "pkg-install.in").write_text("#!/bin/sh\necho %%UNKNOWN%%\n")
    mk = make_mk(tmp_path, "PORTNAME=\tx\nSUB_FILES=\tpkg-install\n")
    with pytest.raises(bpp.BuildError, match="UNKNOWN"):
        bpp.build_scripts(mk, files)


def test_build_scripts_framework_sub_list_defaults(tmp_path: Path) -> None:
    # The framework seeds SUB_LIST with DOCSDIR/EXAMPLESDIR/WWWDIR/ETCDIR too
    # (bsd.port.mk) — a script using one must get the framework default value,
    # and the pfSense scripts' %%PORTNAME%% must keep substituting.
    files = tmp_path / "files"
    files.mkdir()
    (files / "pkg-install.in").write_text("d=%%DOCSDIR%% e=%%EXAMPLESDIR%% w=%%WWWDIR%% c=%%ETCDIR%% n=%%PORTNAME%%\n")
    seed = bpp.seed_vars(tmp_path, tmp_path / "work", "py311")
    mk = make_mk(tmp_path, "PORTNAME=\ttestpkg\nSUB_FILES=\tpkg-install\n", seed=seed)
    scripts = bpp.build_scripts(mk, files)
    assert scripts["install"] == (
        "d=/usr/local/share/doc/testpkg e=/usr/local/share/examples/testpkg"
        " w=/usr/local/www/testpkg c=/usr/local/etc/testpkg n=testpkg"
    )


# --------------------------------------------------------------------------- #
# Dependency resolution (synthetic ports tree)
# --------------------------------------------------------------------------- #


def write_port(ports: Path, origin: str, body: str) -> None:
    d = ports / origin
    d.mkdir(parents=True, exist_ok=True)
    (d / "Makefile").write_text(body)


def test_read_dep_port_flavor(tmp_path: Path) -> None:
    ports = tmp_path / "ports"
    write_port(
        ports,
        "net/rsync",
        "PORTNAME=\trsync\nPORTVERSION=\t3.4.1\nPORTREVISION=\t6\n"
        "FLAVORS=\tdefault python\npython_PKGNAMESUFFIX=\t-python\n",
    )
    seed = {"PORTREVISION": "0", "PORTEPOCH": "0"}
    mkf = ports / "net/rsync/Makefile"
    assert bpp._read_dep_port(mkf, "", seed) == ("rsync", "3.4.1_6")  # default flavor
    assert bpp._read_dep_port(mkf, "python", seed) == ("rsync-python", "3.4.1_6")
    assert bpp._read_dep_port(mkf, "default", seed) == ("rsync", "3.4.1_6")


def test_resolve_deps_name_and_file_forms(tmp_path: Path) -> None:
    ports = tmp_path / "ports"
    write_port(ports, "textproc/gnugrep", "PORTNAME=\tgrep\nPKGNAMEPREFIX=\tgnu\nPORTVERSION=\t3.12\n")
    write_port(ports, "databases/py-sqlite3", "PORTNAME=\tsqlite3\nPKGNAMEPREFIX=\t${PYTHON_PKGNAMEPREFIX}\n")
    seed = {
        "LOCALBASE": "/usr/local",
        "PYTHON_PKGNAMEPREFIX": "py311-",
        "PY_FLAVOR": "py311",
        "PORTREVISION": "0",
        "PORTEPOCH": "0",
    }
    mk = make_mk(
        tmp_path,
        "RUN_DEPENDS=\t${LOCALBASE}/bin/ggrep:textproc/gnugrep \\\n"
        "\t\t${PYTHON_PKGNAMEPREFIX}sqlite3>0:databases/py-sqlite3@${PY_FLAVOR}\n",
        seed=seed,
    )
    deps = {d.name: d for d in bpp.resolve_deps(mk, ports, seed)}
    assert deps["gnugrep"].origin == "textproc/gnugrep"
    assert deps["gnugrep"].version == "3.12"  # file-form name resolved via ports tree
    assert "py311-sqlite3" in deps  # name-form (left side) wins
    assert deps["py311-sqlite3"].origin == "databases/py-sqlite3"


def test_synthesize_uses_deps(tmp_path: Path) -> None:
    ports = tmp_path / "ports"
    write_port(ports, "lang/php83", "PORTNAME=\tphp83\nPORTVERSION=\t8.3.30\n")
    write_port(ports, "devel/php83-intl", "PORTNAME=\tphp83-intl\n")  # version inherited; falls back to php base
    write_port(ports, "lang/python311", "PORTNAME=\tpython311\nPORTVERSION=\t3.11.15\n")
    seed = {"PORTREVISION": "0", "PORTEPOCH": "0"}
    mk = make_mk(tmp_path, "USES=\tphp python\nUSE_PHP=\tintl\n", seed=seed)
    deps = {d.name: d for d in bpp.synthesize_uses_deps(mk, ports, "8.3", "py311", seed)}
    assert deps["php83"].origin == "lang/php83"
    assert deps["php83"].version == "8.3.30"
    assert deps["php83-intl"].origin == "devel/php83-intl"  # origin found by globbing the tree
    assert deps["php83-intl"].version == "8.3.30"  # falls back to the php base version
    assert deps["python311"].origin == "lang/python311"


# --------------------------------------------------------------------------- #
# Repo catalogue
# --------------------------------------------------------------------------- #

_CATALOGUE = (
    '{"name":"rsync","origin":"net/rsync","version":"3.4.3"}\n'
    '{"name":"jq","origin":"textproc/jq","version":"1.8.1"}\n'
    '{"name":"other","origin":"x/other","version":"9"}\n'
)


def test_load_catalogue_plain_yaml(tmp_path: Path) -> None:
    f = tmp_path / "packagesite.yaml"
    f.write_text(_CATALOGUE)
    cat = bpp.load_catalogue(str(f), "FreeBSD:15:amd64", {"rsync", "jq"})
    assert cat == {"rsync": ("net/rsync", "3.4.3"), "jq": ("textproc/jq", "1.8.1")}


def test_load_catalogue_gzipped_tar(tmp_path: Path) -> None:
    # A packagesite.pkg-like archive: a gzip-compressed tar holding packagesite.yaml
    # (gzip via stdlib, so no zstd needed in the test environment).
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as tf:
        data = _CATALOGUE.encode()
        ti = tarfile.TarInfo("packagesite.yaml")
        ti.size = len(data)
        tf.addfile(ti, io.BytesIO(data))
    archive = tmp_path / "packagesite.pkg"
    archive.write_bytes(gzip.compress(buf.getvalue()))
    cat = bpp.load_catalogue(str(archive), "FreeBSD:15:amd64", {"rsync"})
    assert cat["rsync"] == ("net/rsync", "3.4.3")


def test_apply_repo_catalogue_overrides_versions(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    f = tmp_path / "packagesite.yaml"
    f.write_text(_CATALOGUE)
    deps = [bpp.Dep("rsync", "net/rsync", "0"), bpp.Dep("missing", "x/missing", "1.0")]
    bpp.apply_repo_catalogue(deps, str(f), "FreeBSD:15:amd64")
    by_name = {d.name: d for d in deps}
    assert by_name["rsync"].version == "3.4.3"
    assert by_name["missing"].version == "1.0"  # kept; warned
    assert "not in repo catalogue" in capsys.readouterr().err


# --------------------------------------------------------------------------- #
# End-to-end: build a real .pkg from a synthetic classic port, then inspect it
# --------------------------------------------------------------------------- #


def _make_classic_port(tmp_path: Path) -> tuple[Path, Path]:
    """A minimal classic (embedded-files) port + a one-entry ports tree."""
    ports = tmp_path / "ports"
    portdir = ports / "net" / "testpkg"
    files = portdir / "files"
    # embedded source tree (mirrors the install filesystem under files/)
    (files / "etc/inc/priv").mkdir(parents=True)
    (files / "etc/inc/priv/test.priv.inc").write_text("<?php // priv\n")
    (files / "usr/local/bin").mkdir(parents=True)
    (files / "usr/local/bin/hello.sh").write_text("#!/bin/sh\necho hi\n")
    (files / "usr/local/etc").mkdir(parents=True)
    (files / "usr/local/etc/testpkg.conf").write_text("key = value\n")
    (files / "usr/local/share/testpkg").mkdir(parents=True)
    (files / "usr/local/share/testpkg/info.xml").write_text("<version>%%PKGVERSION%%</version>\n")
    # SUB_FILES install scripts
    (files / "pkg-install.in").write_text(
        '#!/bin/sh\nif [ "${2}" != "POST-INSTALL" ]; then\n\texit 0\nfi\n'
        "/usr/local/bin/php -f /etc/rc.packages %%PORTNAME%% ${2}\n"
    )
    (files / "pkg-deinstall.in").write_text("#!/bin/sh\n/usr/local/bin/php -f /etc/rc.packages %%PORTNAME%% ${2}\n")

    portdir.joinpath("pkg-descr").write_text("A tiny test port.\n\nWWW: https://example.org/testpkg\n")
    portdir.joinpath("pkg-plist").write_text(
        "/etc/inc/priv/test.priv.inc\n"
        "bin/hello.sh\n"
        "etc/testpkg.conf\n"
        "%%DATADIR%%/info.xml\n"
        "@dir /etc/inc/priv\n"
        "@dir /etc/inc\n"
    )
    portdir.joinpath("Makefile").write_text(
        "PORTNAME=\ttestpkg\nPORTVERSION=\t1.0\nPORTREVISION=\t2\nCATEGORIES=\tnet\n"
        "MAINTAINER=\tdev@example.org\nCOMMENT=\tTest port\nLICENSE=\tAPACHE20\n"
        "RUN_DEPENDS=\t${LOCALBASE}/bin/foo:misc/foo\n"
        "NO_BUILD=\tyes\nSUB_FILES=\tpkg-install pkg-deinstall\nSUB_LIST=\tPORTNAME=${PORTNAME}\n"
        "do-extract:\n\t${MKDIR} ${WRKSRC}\n"
        "do-install:\n"
        "\t${MKDIR} ${STAGEDIR}/etc/inc/priv\n"
        "\t${MKDIR} ${STAGEDIR}${PREFIX}/bin\n"
        "\t${MKDIR} ${STAGEDIR}${PREFIX}/etc\n"
        "\t${MKDIR} ${STAGEDIR}${DATADIR}\n"
        "\t${INSTALL_DATA} ${FILESDIR}/etc/inc/priv/test.priv.inc ${STAGEDIR}/etc/inc/priv\n"
        "\t${INSTALL_SCRIPT} ${FILESDIR}${PREFIX}/bin/hello.sh ${STAGEDIR}${PREFIX}/bin\n"
        "\t${INSTALL_DATA} ${FILESDIR}${PREFIX}/etc/testpkg.conf ${STAGEDIR}${PREFIX}/etc\n"
        "\t${INSTALL_DATA} ${FILESDIR}${DATADIR}/info.xml ${STAGEDIR}${DATADIR}\n"
        "\t@${REINPLACE_CMD} -i '' -e \"s|%%PKGVERSION%%|${PKGVERSION}|\" ${STAGEDIR}${DATADIR}/info.xml\n"
        ".include <bsd.port.mk>\n"
    )
    write_port(ports, "misc/foo", "PORTNAME=\tfoo\nPORTVERSION=\t1.2\nPORTREVISION=\t3\n")
    return ports, portdir


def _extract(tf: tarfile.TarFile, name: str) -> bytes:
    member = tf.extractfile(name)
    assert member is not None, name
    return member.read()


def _read_pkg(path: Path) -> tuple[dict, dict, tarfile.TarFile]:
    raw = lzma.decompress(path.read_bytes())  # built with --compression xz (stdlib)
    tf = tarfile.open(fileobj=io.BytesIO(raw))
    full = json.loads(_extract(tf, "+MANIFEST"))
    compact = json.loads(_extract(tf, "+COMPACT_MANIFEST"))
    return full, compact, tf


def test_end_to_end_classic_build(tmp_path: Path) -> None:
    ports, portdir = _make_classic_port(tmp_path)
    out = tmp_path / "out"
    rc = bpp.main(
        [
            "--ports",
            str(ports),
            "--port-dir",
            str(portdir),
            "--abi",
            "FreeBSD:15:amd64",
            "--py-flavor",
            "py311",
            "--compression",
            "xz",
            "--freebsd-version",
            "1500068",
            "--out",
            str(out),
        ]
    )
    assert rc == 0
    pkg = out / "testpkg-1.0_2.pkg"
    assert pkg.is_file()

    full, compact, tf = _read_pkg(pkg)
    names = tf.getnames()
    # archive layout
    assert names[:2] == ["+COMPACT_MANIFEST", "+MANIFEST"]
    assert all(n.startswith("/") for n in names[2:])
    # metadata
    assert full["name"] == "testpkg"
    assert full["version"] == "1.0_2"
    assert full["origin"] == "net/testpkg"
    assert full["www"] == "https://example.org/testpkg"  # classic -> pkg-descr WWW line
    assert full["desc"].endswith("WWW: https://example.org/testpkg")  # verbatim
    assert full["abi"] == "FreeBSD:15:amd64" and full["arch"] == "freebsd:15:x86:64"
    assert full["licenselogic"] == "single" and full["licenses"] == ["APACHE20"]
    assert full["annotations"] == {"FreeBSD_version": "1500068"}
    assert "files" not in compact and "scripts" not in compact  # compact is metadata-only
    # files + perms
    perms = {p: e["perm"] for p, e in full["files"].items()}
    assert perms["/usr/local/bin/hello.sh"] == "0555"  # INSTALL_SCRIPT
    assert perms["/usr/local/etc/testpkg.conf"] == "0644"  # INSTALL_DATA
    assert perms["/usr/local/share/testpkg/info.xml"] == "0644"
    assert set(perms) == set(p for p in names if not p.startswith("+"))
    for p, e in full["files"].items():
        assert e["sum"].startswith("1$") and e["uname"] == "root" and e["gname"] == "wheel"
    # directories from @dir
    assert set(full["directories"]) == {"/etc/inc/priv", "/etc/inc"}
    # scripts: install/deinstall, %%PORTNAME%% substituted, trailing newline stripped
    assert set(full["scripts"]) == {"install", "deinstall"}
    assert "testpkg" in full["scripts"]["install"]
    assert not full["scripts"]["install"].endswith("\n")
    # dep resolved + PKGVERSION-with-revision from the ports tree
    assert full["deps"] == {"foo": {"origin": "misc/foo", "version": "1.2_3"}}
    # info.xml %%PKGVERSION%% substituted in the staged payload
    info = _extract(tf, "/usr/local/share/testpkg/info.xml").decode()
    assert info == "<version>1.0_2</version>\n"


def _make_no_arch_port(tmp_path: Path) -> tuple[Path, Path]:
    """The same minimal classic port as _make_classic_port, with NO_ARCH=yes set —
    simulates the FreeBSD-ports fork's staged NO_ARCH Makefile change (issue #1806;
    not visible to this repo — this fixture simulates it)."""
    ports, portdir = _make_classic_port(tmp_path)
    makefile = portdir / "Makefile"
    makefile.write_text(makefile.read_text().replace("NO_BUILD=\tyes\n", "NO_BUILD=\tyes\nNO_ARCH=\tyes\n"))
    return ports, portdir


def test_end_to_end_no_arch_port_stamps_wildcard_abi_and_arch(tmp_path: Path) -> None:
    """A NO_ARCH port's manifest stamps a CPU-wildcarded abi/arch (issue #1806 B1).

    Scenario: NO_ARCH port, concrete --abi input, no --arch override
      Given a port Makefile with NO_ARCH=yes
       When build-pkg-portable.py runs with --abi FreeBSD:15:amd64 (no --arch)
      Then the manifest abi is "FreeBSD:15:*" (major derived from --abi, CPU wildcarded)
       And the manifest arch is "freebsd:15:*" (same wildcard, lowercase per the
           existing arch triplet convention)
    """
    ports, portdir = _make_no_arch_port(tmp_path)
    out = tmp_path / "out"
    rc = bpp.main(
        [
            "--ports", str(ports),
            "--port-dir", str(portdir),
            "--abi", "FreeBSD:15:amd64",
            "--py-flavor", "py311",
            "--compression", "xz",
            "--freebsd-version", "1500068",
            "--out", str(out),
        ]
    )  # fmt: skip
    assert rc == 0
    full, _, _ = _read_pkg(out / "testpkg-1.0_2.pkg")
    assert full["abi"] == "FreeBSD:15:*"
    assert full["arch"] == "freebsd:15:*"


def test_end_to_end_no_arch_port_explicit_arch_override_wins(tmp_path: Path) -> None:
    """An explicit --arch still wins over the NO_ARCH wildcard default (issue #1806 B1).

    The manifest ABI is ALWAYS wildcarded for a NO_ARCH port (it is a fact about the
    package, probed live against a real Netgate build) — but --arch's existing
    override precedence (``args.arch or abi_to_arch(abi)``) is preserved: when the
    caller passes --arch explicitly, that concrete value is used verbatim, never
    wildcarded.

    Scenario: NO_ARCH port, explicit --arch override
      When build-pkg-portable.py runs with --abi FreeBSD:15:amd64 --arch freebsd:99:custom
      Then the manifest abi is STILL "FreeBSD:15:*" (unconditional NO_ARCH fact)
       And the manifest arch is the EXPLICIT "freebsd:99:custom" (not wildcarded)
    """
    ports, portdir = _make_no_arch_port(tmp_path)
    out = tmp_path / "out"
    rc = bpp.main(
        [
            "--ports", str(ports),
            "--port-dir", str(portdir),
            "--abi", "FreeBSD:15:amd64",
            "--arch", "freebsd:99:custom",
            "--py-flavor", "py311",
            "--compression", "xz",
            "--freebsd-version", "1500068",
            "--out", str(out),
        ]
    )  # fmt: skip
    assert rc == 0
    full, _, _ = _read_pkg(out / "testpkg-1.0_2.pkg")
    assert full["abi"] == "FreeBSD:15:*"
    assert full["arch"] == "freebsd:99:custom"


def test_end_to_end_no_arch_flag_forces_wildcard_on_a_port_without_no_arch(tmp_path: Path) -> None:
    """--no-arch forces the NO_ARCH manifest wildcard even without NO_ARCH=yes (issue #1676).

    Scenario: classic port (no NO_ARCH), --no-arch passed on the CLI
      Given a port Makefile WITHOUT NO_ARCH=yes (the frozen v3.2 ports Makefile shape)
       When build-pkg-portable.py runs with --abi FreeBSD:15:amd64 --no-arch (no --arch)
      Then the manifest abi is "FreeBSD:15:*" and arch is "freebsd:15:*" — same wildcard
           the port would get if it had declared NO_ARCH=yes.
    """
    ports, portdir = _make_classic_port(tmp_path)
    out = tmp_path / "out"
    rc = bpp.main(
        [
            "--ports", str(ports),
            "--port-dir", str(portdir),
            "--abi", "FreeBSD:15:amd64",
            "--py-flavor", "py311",
            "--compression", "xz",
            "--freebsd-version", "1500068",
            "--no-arch",
            "--out", str(out),
        ]
    )  # fmt: skip
    assert rc == 0
    full, _, _ = _read_pkg(out / "testpkg-1.0_2.pkg")
    assert full["abi"] == "FreeBSD:15:*"
    assert full["arch"] == "freebsd:15:*"


def test_end_to_end_no_arch_flag_on_a_no_arch_port_is_idempotent(tmp_path: Path) -> None:
    """--no-arch on a port that already declares NO_ARCH=yes double-applies harmlessly.

    Given a port Makefile WITH NO_ARCH=yes AND --no-arch also passed
     Then the manifest is still cleanly wildcarded (no double-mangled "FreeBSD:15:**").
    """
    ports, portdir = _make_no_arch_port(tmp_path)
    out = tmp_path / "out"
    rc = bpp.main(
        [
            "--ports", str(ports),
            "--port-dir", str(portdir),
            "--abi", "FreeBSD:15:amd64",
            "--py-flavor", "py311",
            "--compression", "xz",
            "--freebsd-version", "1500068",
            "--no-arch",
            "--out", str(out),
        ]
    )  # fmt: skip
    assert rc == 0
    full, _, _ = _read_pkg(out / "testpkg-1.0_2.pkg")
    assert full["abi"] == "FreeBSD:15:*"
    assert full["arch"] == "freebsd:15:*"


def test_end_to_end_no_arch_flag_explicit_arch_override_wins(tmp_path: Path) -> None:
    """--no-arch's abi wildcard still yields to an explicit --arch (issue #1676).

    Mirrors test_end_to_end_no_arch_port_explicit_arch_override_wins but drives the
    wildcard via --no-arch instead of a Makefile NO_ARCH=yes — same precedence rule.
    """
    ports, portdir = _make_classic_port(tmp_path)
    out = tmp_path / "out"
    rc = bpp.main(
        [
            "--ports", str(ports),
            "--port-dir", str(portdir),
            "--abi", "FreeBSD:15:amd64",
            "--arch", "freebsd:99:custom",
            "--py-flavor", "py311",
            "--compression", "xz",
            "--freebsd-version", "1500068",
            "--no-arch",
            "--out", str(out),
        ]
    )  # fmt: skip
    assert rc == 0
    full, _, _ = _read_pkg(out / "testpkg-1.0_2.pkg")
    assert full["abi"] == "FreeBSD:15:*"
    assert full["arch"] == "freebsd:99:custom"


def test_dry_run_no_arch_flag_prints_wildcarded_abi(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    """--dry-run + --no-arch: the printed plan reports the wildcarded manifest abi/arch."""
    ports, portdir = _make_classic_port(tmp_path)
    rc = bpp.main(
        [
            "--ports", str(ports),
            "--port-dir", str(portdir),
            "--abi", "FreeBSD:15:amd64",
            "--py-flavor", "py311",
            "--freebsd-version", "1500068",
            "--no-arch",
            "--dry-run",
        ]
    )  # fmt: skip
    assert rc == 0
    out = capsys.readouterr().out
    assert "abi/arch    FreeBSD:15:*  /  freebsd:15:*" in out


def test_end_to_end_dynamic_plist_uses_the_staged_payload(tmp_path: Path) -> None:
    ports, portdir = _make_classic_port(tmp_path)
    portdir.joinpath("pkg-plist").unlink()
    makefile = portdir / "Makefile"
    makefile.write_text(
        makefile.read_text().replace(
            "NO_BUILD=\tyes\n",
            "NO_BUILD=\tyes\nPLIST_DIRS=\t/etc/inc/priv /etc/inc\n",
        )
        + "post-install:\n"
        + "\t@${FIND} -s ${STAGEDIR}${PREFIX} -type f -print | "
        + '${SED} -e "s#${STAGEDIR}${PREFIX}/##g" >> ${TMPPLIST}\n'
    )
    out = tmp_path / "out"

    rc = bpp.main(
        [
            "--ports",
            str(ports),
            "--port-dir",
            str(portdir),
            "--abi",
            "FreeBSD:15:amd64",
            "--py-flavor",
            "py311",
            "--compression",
            "xz",
            "--freebsd-version",
            "1500068",
            "--out",
            str(out),
        ]
    )

    assert rc == 0
    full, _, _ = _read_pkg(out / "testpkg-1.0_2.pkg")
    assert set(full["files"]) == {
        "/etc/inc/priv/test.priv.inc",
        "/usr/local/bin/hello.sh",
        "/usr/local/etc/testpkg.conf",
        "/usr/local/share/testpkg/info.xml",
    }
    assert set(full["directories"]) == {"/etc/inc/priv", "/etc/inc"}


def test_end_to_end_plist_drift_aborts(tmp_path: Path) -> None:
    ports, portdir = _make_classic_port(tmp_path)
    # Add a plist entry with no corresponding staged file -> must abort.
    plist = portdir / "pkg-plist"
    plist.write_text(plist.read_text() + "bin/ghost\n")
    out = tmp_path / "out"
    rc = bpp.main(
        [
            "--ports",
            str(ports),
            "--port-dir",
            str(portdir),
            "--abi",
            "FreeBSD:15:amd64",
            "--py-flavor",
            "py311",
            "--compression",
            "xz",
            "--out",
            str(out),
        ]
    )
    assert rc == 1
    assert not list(out.glob("*.pkg")) if out.exists() else True


@pytest.mark.parametrize(
    "val, mods, expected",
    [
        # :S/old/new/ — the post-extract recipe uses ${PORTNAME:S/pfSense-pkg-//} to
        # template info.xml's <name> to the SHORT (prefix-stripped) registration name.
        # That is the name rc.packages (install_package_xml -> get_package_id) looks up;
        # the FULL ${PORTNAME} aborts the install hook (live-VM proven — Netgate ships the
        # short name; our fork had regressed to the full one). The builder must evaluate
        # :S so it reproduces the make-package recipe faithfully.
        ("pfSense-pkg-pfBlockerNG-devel", "S/pfSense-pkg-//", "pfBlockerNG-devel"),
        ("pfSense-pkg-pfBlockerNG", "S/pfSense-pkg-//", "pfBlockerNG"),
        ("pfSense-pkg-pfBlockerNG-devel", "S/^pfSense-pkg-//", "pfBlockerNG-devel"),  # ^ anchor
        ("aXbXc", "S/X/-/g", "a-b-c"),  # g (global) flag
        ("no-match", "S/zzz/q/", "no-match"),  # no occurrence → unchanged
        ("/usr/local/share/x.txt", "T", "x.txt"),  # pre-existing :T still works
        # An :S body containing ':' must survive the modifier split intact —
        # a blind split(':') silently no-ops it (issue #727 finding 3c).
        ("http://old.example/x", "S|http://old.example|https://new.example|", "https://new.example/x"),
        ("x a:b y", "S/a:b/c/", "x c y"),
        # …and the split must resume correctly after the :S group.
        ("dir/pfSense-pkg-x", "T:S/pfSense-pkg-//", "x"),
        ("a:b-c", "S/a:b/z/:S/-/./", "z.c"),
    ],
)
def test_makefile_apply_mods_substitution(val: str, mods: str, expected: str) -> None:
    assert bpp.Makefile._apply_mods(val, mods) == expected


@pytest.mark.parametrize(
    "mods",
    [
        "S/a\\/b/c/",  # escaped delimiter in the body — the old/new split can't interpret it
        "S/foo",  # unterminated group (no second delimiter)
    ],
)
def test_makefile_apply_mods_rejects_uninterpretable_s_body(mods: str) -> None:
    # Both shapes previously no-opped SILENTLY (returned the input unchanged) —
    # worse than a loud failure for a substitution the recipe relies on.
    with pytest.raises(bpp.BuildError, match=":S modifier"):
        bpp.Makefile._apply_mods("xxa/bxx", mods)


# --------------------------------------------------------------------------- #
# Explicit version and annotation overrides: --pkgversion / --annotate.
# The pair below is the branch contrast — OFF (release build, default flags) vs
# ON (explicit overrides) — proving the overrides are a real branch, not an
# always-on path. Neither ever emits a `conflicts` key (the portable builder
# never does — mutual exclusion with the release builds is by file overlap).
# --------------------------------------------------------------------------- #


def test_overrides_off_release_build_is_plain(tmp_path: Path) -> None:
    """OFF: with no --pkgversion/--annotate the manifest is the plain release shape.

    Given the synthetic port built with default flags,
    When no explicit override is passed,
    Then version comes from PORTVERSION(_PORTREVISION), the comment is verbatim, the
      only annotation is the FreeBSD_version, and there is no `conflicts` key.
    """
    ports, portdir = _make_classic_port(tmp_path)
    out = tmp_path / "out"
    rc = bpp.main(
        ["--ports", str(ports), "--port-dir", str(portdir), "--abi", "FreeBSD:15:amd64",
         "--py-flavor", "py311", "--compression", "xz", "--freebsd-version", "1500068", "--out", str(out)]
    )  # fmt: skip
    assert rc == 0
    full, compact, _ = _read_pkg(out / "testpkg-1.0_2.pkg")
    assert full["version"] == "1.0_2"  # from PORTVERSION(_PORTREVISION), not an override
    assert full["comment"] == "Test port"  # verbatim
    assert full["annotations"] == {"FreeBSD_version": "1500068"}  # no commit
    assert "conflicts" not in full and "conflicts" not in compact


def test_explicit_version_and_annotation_overrides(tmp_path: Path) -> None:
    """ON: --pkgversion sets the version; --annotate rides annotations + comment.

    Given the SAME synthetic port,
    When --pkgversion 4.0.0.a24 and repeatable --annotate K=V are passed,
    Then the manifest version is the override (NOT PORTVERSION), each K=V merges into
      `annotations` (on top of FreeBSD_version) AND appends to `comment` (so both
      `pkg info` and `pkg info -A` surface the provenance) — still NO `conflicts` key.
    """
    ports, portdir = _make_classic_port(tmp_path)
    out = tmp_path / "out"
    rc = bpp.main(
        ["--ports", str(ports), "--port-dir", str(portdir), "--abi", "FreeBSD:15:amd64",
         "--py-flavor", "py311", "--compression", "xz", "--freebsd-version", "1500068",
         "--pkgversion", "4.0.0.a24", "--annotate", "commit=deadbeef", "--annotate", "build=ci",
         "--out", str(out)]
    )  # fmt: skip
    assert rc == 0
    full, compact, _ = _read_pkg(out / "testpkg-4.0.0.a24.pkg")
    assert full["version"] == "4.0.0.a24"  # the override, NOT 1.0_2
    assert full["annotations"] == {"FreeBSD_version": "1500068", "commit": "deadbeef", "build": "ci"}
    assert full["comment"] == "Test port (commit=deadbeef, build=ci)"
    assert "conflicts" not in full and "conflicts" not in compact


@pytest.mark.parametrize("ver", ["20260606", "20260606_2", "4.0.0.a24", "4.0.0.r1"])
def test_validate_pkgversion_accepts_pkg_safe_versions(ver: str) -> None:
    assert bpp.validate_pkgversion(ver) == ver


@pytest.mark.parametrize("bad", ["", "   ", "3.2-nightly", "3.2.16-20260606"])
def test_validate_pkgversion_rejects_empty_or_dash(bad: str) -> None:
    # '-' is the pkg name/version delimiter (<name>-<version>.pkg); empty is meaningless.
    with pytest.raises(bpp.BuildError):
        bpp.validate_pkgversion(bad)


@pytest.mark.parametrize(
    "items, expected",
    [
        ([], {}),
        (["commit=abc"], {"commit": "abc"}),
        (["a=1", "b=2"], {"a": "1", "b": "2"}),
        (["k=v=w"], {"k": "v=w"}),  # value may itself contain '='
        (["k=1", "k=2"], {"k": "2"}),  # a later key wins
    ],
)
def test_parse_annotations(items: list[str], expected: dict[str, str]) -> None:
    assert bpp.parse_annotations(items) == expected


@pytest.mark.parametrize("bad", ["noequals", "=v", "  =v"])
def test_parse_annotations_rejects_malformed(bad: str) -> None:
    with pytest.raises(bpp.BuildError):
        bpp.parse_annotations([bad])


# --------------------------------------------------------------------------- #
# Variant-aware manifest deps (ADR-20) — _resolve_variant_deps
#
# This is a pure DERIVATION, not a record of today's matrix: php "X.Y" → phpXY /
# lang/phpXY; py "pyNNN" → pythonNNN / lang/pythonNNN. The tests therefore pin the
# RULE (expected computed from the input), not the specific CE=php83 / Plus=php85
# values — those are matrix-driven and will drift. 8.3/8.5 are just two of several
# inputs; 8.4/8.10 prove it is the transform, not a hardcode.
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("php_version", ["8.3", "8.5", "8.4", "8.10"])
def test_php_guard_is_derived_from_php_version(php_version: str) -> None:
    """The PHP guard is DERIVED from --php (strip the dot → phpXY / lang/phpXY).

    Whatever the matrix carries, exactly ONE php* dep appears and it is the derived
    one — so no php other than the one this build was asked for can leak in.
    """
    expected = "php" + php_version.replace(".", "")
    deps = dict(bpp._resolve_variant_deps(php_version=php_version, py_flavor="py311"))
    # The derived php dep is present with its real origin (libpkg requires a non-empty one).
    assert deps.get(expected) == f"lang/{expected}"
    # Exactly one php* dep, and it IS the derived one (no other php leaks in).
    assert [n for n in deps if n.startswith("php")] == [expected]


@pytest.mark.parametrize(
    "py_flavor,expected",
    [("py311", "python311"), ("py39", "python39"), ("py312", "python312")],
)
def test_python_guard_is_derived_from_py_flavor(py_flavor: str, expected: str) -> None:
    """The Python guard is DERIVED from --py-flavor (pyNNN → pythonNNN / lang/pythonNNN).

    Symmetric with the PHP guard, and asserted for BOTH editions: Python does not differ
    by edition today, but the guard is still emitted + derived, and uses the real package
    name (pythonNNN), never the bare flavor token (pyNNN — which is not installable).
    """
    # Asserted with a CE php (8.3) and a Plus php (8.5) so the Python guard is covered
    # on both editions, not just one.
    for php_version in ("8.3", "8.5"):
        deps = dict(bpp._resolve_variant_deps(php_version=php_version, py_flavor=py_flavor))
        assert deps.get(expected) == f"lang/{expected}"
        # Exactly one python* dep, and the bare flavor token is never a dep name.
        assert [n for n in deps if n.startswith("python")] == [expected]
        assert py_flavor not in deps


def test_variant_dep_origin_is_non_empty() -> None:
    """Every guard dep carries a non-empty <category>/<port> origin.

    Regression guard: an empty origin reached real FreeBSD `pkg repo` and tripped
    `Assertion failed: origin != NULL && origin[0] != '\\0'` (pkg_adddep_chain).
    """
    for name, origin in bpp._resolve_variant_deps(php_version="8.3", py_flavor="py311"):
        assert origin, f"guard dep {name!r} has an empty origin"
        assert "/" in origin, f"guard dep {name!r} origin {origin!r} is not a <category>/<port>"


def test_no_php_no_guard_injected(tmp_path: Path) -> None:
    """Without --php, no variant guard dep is injected (ADR-20: guard is gated on --php).

    Given the synthetic classic port (no USES=php / USES=python),
    When built with --py-flavor but NO --php,
    Then the deps dict contains only the RUN_DEPENDS from the Makefile
    and none of the versioned php*/py* variant guards.
    """
    ports, portdir = _make_classic_port(tmp_path)
    out = tmp_path / "out"
    rc = bpp.main(
        [
            "--ports", str(ports),
            "--port-dir", str(portdir),
            "--abi", "FreeBSD:15:amd64",
            "--py-flavor", "py311",
            "--compression", "xz",
            "--out", str(out),
        ]
    )  # fmt: skip
    assert rc == 0
    full, _compact, _tf = _read_pkg(out / "testpkg-1.0_2.pkg")
    dep_names = set(full.get("deps", {}).keys())
    # foo comes from RUN_DEPENDS; no variant guard is injected without --php. Exclude
    # both shapes a guard could take: the real Python guard dep is the interpreter
    # package pythonNNN (e.g. python311 — which does NOT start with "py3"), and the bare
    # flavor token py311 must never become a dep name either (the --php companion test
    # asserts that directly). Checking both means an accidental guard of either form
    # fails this test rather than slipping through.
    assert "foo" in dep_names
    assert not any(n.startswith("php8") for n in dep_names)
    assert not any(n.startswith("python3") for n in dep_names)
    assert not any(n.startswith("py3") for n in dep_names)


def test_php_injects_variant_guard_via_cli(tmp_path: Path) -> None:
    """With --php, the versioned php*/py* guard deps ARE injected (the on branch).

    Paired with test_no_php_no_guard_injected (the off branch) this proves the guard
    is a real branch keyed on --php, not an always-present or always-absent dep.

    Given the synthetic classic port,
    When built with --php 8.3 + --py-flavor py311 (CE values),
    Then deps gain php83 + python311 (alongside the Makefile RUN_DEPENDS), each with a
    real origin, and the Plus discriminator php85 is absent.
    """
    ports, portdir = _make_classic_port(tmp_path)
    out = tmp_path / "out"
    rc = bpp.main(
        [
            "--ports", str(ports),
            "--port-dir", str(portdir),
            "--abi", "FreeBSD:15:amd64",
            "--py-flavor", "py311",
            "--php", "8.3",
            "--compression", "xz",
            "--out", str(out),
        ]
    )  # fmt: skip
    assert rc == 0
    full, _compact, _tf = _read_pkg(out / "testpkg-1.0_2.pkg")
    deps = full.get("deps", {})
    assert "foo" in deps  # Makefile RUN_DEPENDS still present
    assert deps.get("php83", {}).get("origin") == "lang/php83"  # the requested PHP guard, real origin
    assert deps.get("python311", {}).get("origin") == "lang/python311"  # Python guard, real origin
    assert "php85" not in deps  # no php but the requested one (php85 is not an edition marker)
    assert "py311" not in deps  # the flavor token is NOT a dep name (would be unsatisfiable)


def test_packaged_files_carry_the_source_mtime_not_epoch_zero(tmp_path: Path) -> None:
    """Payload entries carry the SOURCE file's mtime, in the manifest and the archive.

    Scenario: an installed asset must be able to invalidate a browser cache
      Given a package whose payload files are recorded with mtime 0
      Then every installed file reports 1970 on the appliance
      And `filemtime()`-based cache-busting renders a constant `?v=0` for every release,
          while nginx answers with `Last-Modified: Thu, 01 Jan 1970` -- which browsers
          turn into a multi-year heuristic freshness window
      So a pre-upgrade copy of a shipped script survives the upgrade indefinitely and
          runs against the new markup (issue #1845)

    The mtime travels from the source tree rather than the build clock, so the same
    inputs still produce a byte-identical archive.
    """
    ports, portdir = _make_classic_port(tmp_path)
    # Distinct, in-the-past mtimes: a build-clock read (or any single constant) would
    # collapse them to one value, so this also pins that each file keeps its OWN mtime.
    sources = sorted((portdir / "files").rglob("*"))
    source_mtimes = {}
    for offset, src in enumerate(f for f in sources if f.is_file()):
        stamp = 1700000000 + offset
        os.utime(src, (stamp, stamp))
        source_mtimes[src.name] = stamp
    assert source_mtimes, "no source files staged -- nothing to assert on"

    out = tmp_path / "out"
    rc = bpp.main(
        [
            "--ports", str(ports),
            "--port-dir", str(portdir),
            "--abi", "FreeBSD:15:amd64",
            "--py-flavor", "py311",
            "--compression", "xz",
            "--out", str(out),
        ]
    )  # fmt: skip
    assert rc == 0

    full, _compact, tf = _read_pkg(out / "testpkg-1.0_2.pkg")
    payload = [m for m in tf.getmembers() if m.name.startswith("/")]
    assert payload, "no payload members in the archive -- nothing to assert on"

    wrong = [
        (m.name, m.mtime, source_mtimes[m.name.rsplit("/", 1)[-1]])
        for m in payload
        if m.name.rsplit("/", 1)[-1] in source_mtimes and m.mtime != source_mtimes[m.name.rsplit("/", 1)[-1]]
    ]
    assert not wrong, f"archive entries lost the source mtime (name, archive, source): {wrong}"

    manifest_mtimes = {path: entry["mtime"] for path, entry in full["files"].items()}
    mismatched = [
        (m.name, m.mtime, manifest_mtimes.get(m.name)) for m in payload if manifest_mtimes.get(m.name) != m.mtime
    ]
    assert not mismatched, f"+MANIFEST mtime disagrees with the archive entry (name, archive, manifest): {mismatched}"


def test_two_builds_of_the_same_inputs_are_byte_identical(tmp_path: Path) -> None:
    """The same source tree builds to the same bytes, whatever the clock says.

    The mtime fix must not reintroduce a per-build value: a build-clock read would make
    two runs over identical inputs differ, which the sparse-checkout equivalence check
    (tests/test_build_pkg_origins.py) relies on being false.
    """
    ports, portdir = _make_classic_port(tmp_path)
    built = []
    for run in ("one", "two"):
        out = tmp_path / f"out-{run}"
        rc = bpp.main(
            [
                "--ports", str(ports),
                "--port-dir", str(portdir),
                "--abi", "FreeBSD:15:amd64",
                "--py-flavor", "py311",
                "--compression", "xz",
                "--out", str(out),
            ]
        )  # fmt: skip
        assert rc == 0
        built.append((out / "testpkg-1.0_2.pkg").read_bytes())
        # A build-clock mtime differs between runs only if the clock moved; force it.
        time.sleep(1.1)

    assert built[0] == built[1], "two builds of identical inputs produced different .pkg bytes"


@pytest.mark.parametrize("bad", ["-1", "99999999999999", "not-a-number"])
def test_unusable_source_date_epoch_fails_the_build_cleanly(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, bad: str
) -> None:
    """A SOURCE_DATE_EPOCH the archive format cannot carry is rejected, not half-written.

    The ustar mtime field holds 8 octal digits and no sign, so a negative or oversized
    value would otherwise surface as tarfile's "overflow in number field" from deep
    inside the writer, after the manifest was already built.
    """
    monkeypatch.setenv("SOURCE_DATE_EPOCH", bad)
    ports, portdir = _make_classic_port(tmp_path)
    out = tmp_path / "out"
    with pytest.raises(bpp.BuildError, match="SOURCE_DATE_EPOCH"):
        bpp.main(
            [
                "--ports", str(ports),
                "--port-dir", str(portdir),
                "--abi", "FreeBSD:15:amd64",
                "--py-flavor", "py311",
                "--compression", "xz",
                "--out", str(out),
            ]
        )  # fmt: skip


def test_source_date_epoch_pins_every_packaged_mtime(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """SOURCE_DATE_EPOCH pins the recorded mtimes, so a build can still be reproducible.

    The default (the staged file's own mtime) moves with the build clock, which is what
    makes an upgraded asset look new to a browser. A caller that needs byte-identical
    rebuilds sets the standard reproducible-builds variable and gets a fixed value in
    both +MANIFEST and the archive.
    """
    pinned = 1700000000  # 2023-11-14, safely in the past
    monkeypatch.setenv("SOURCE_DATE_EPOCH", str(pinned))
    ports, portdir = _make_classic_port(tmp_path)
    out = tmp_path / "out"
    rc = bpp.main(
        [
            "--ports", str(ports),
            "--port-dir", str(portdir),
            "--abi", "FreeBSD:15:amd64",
            "--py-flavor", "py311",
            "--compression", "xz",
            "--out", str(out),
        ]
    )  # fmt: skip
    assert rc == 0

    full, _compact, tf = _read_pkg(out / "testpkg-1.0_2.pkg")
    payload = [m for m in tf.getmembers() if m.name.startswith("/")]
    assert payload, "no payload members in the archive -- nothing to assert on"

    assert [m.mtime for m in payload] == [pinned] * len(payload), (
        f"archive entries ignore SOURCE_DATE_EPOCH={pinned}: {[(m.name, m.mtime) for m in payload]}"
    )
    assert [entry["mtime"] for entry in full["files"].values()] == [pinned] * len(payload), (
        f"+MANIFEST entries ignore SOURCE_DATE_EPOCH={pinned}: {full['files']}"
    )


def test_source_file_mtime_the_archive_cannot_carry_fails_cleanly(tmp_path: Path) -> None:
    """An out-of-range mtime on a SOURCE file is rejected the same way the env var is.

    The archive format bounds the value whatever its origin, so the default path needs
    the same guard as SOURCE_DATE_EPOCH -- otherwise it surfaces as tarfile's "overflow
    in number field" from inside the writer, after the manifest is already built.
    """
    ports, portdir = _make_classic_port(tmp_path)
    victim = portdir / "files/usr/local/etc/testpkg.conf"
    beyond = 0o77777777777 + 1
    os.utime(victim, (beyond, beyond))
    out = tmp_path / "out"
    with pytest.raises(bpp.BuildError, match="mtime"):
        bpp.main(
            [
                "--ports", str(ports),
                "--port-dir", str(portdir),
                "--abi", "FreeBSD:15:amd64",
                "--py-flavor", "py311",
                "--compression", "xz",
                "--out", str(out),
            ]
        )  # fmt: skip


# --------------------------------------------------------------------------- #
# Channel/provenance records (issue #2142).
# --------------------------------------------------------------------------- #


_CHANNEL_IDENTITIES = {
    "stable": "pfSense-pkg-pfBlockerNG",
    "testing": "pfSense-pkg-pfBlockerNG-testing",
    "edge": "pfSense-pkg-pfBlockerNG-edge",
    "nightly": "pfSense-pkg-pfBlockerNG-nightly",
}


def _git(repo: Path, *args: str) -> str:
    result = subprocess.run(
        ["git", *args], cwd=repo, env=scrubbed_git_env(drop_git_vars=True), capture_output=True, text=True, check=True
    )
    return result.stdout.strip()


def _git_init(repo: Path) -> str:
    _git(repo, "init", "-q", "-b", "main")
    _git(repo, "config", "user.name", "test")
    _git(repo, "config", "user.email", "test@example.org")
    _git(repo, "add", "-A")
    _git(repo, "-c", "commit.gpgsign=false", "commit", "-qm", "fixture")
    return _git(repo, "rev-parse", "HEAD")


def _live_build_rows() -> tuple[dict[str, object], ...]:
    matrix_script = Path(__file__).resolve().parent.parent / "scripts" / "read-version-matrix.sh"
    try:
        result = subprocess.run(
            ["sh", str(matrix_script), "--print-build"],
            cwd=matrix_script.parent.parent,
            capture_output=True,
            text=True,
            timeout=30.0,
            check=False,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise RuntimeError(f"build matrix reader failed: {exc}") from exc
    if result.returncode != 0 or not result.stdout.strip():
        raise RuntimeError(f"build matrix reader failed with exit {result.returncode}")
    try:
        rows = json.loads(result.stdout)
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"build matrix reader returned invalid JSON: {exc}") from exc
    if not isinstance(rows, list) or not rows:
        raise RuntimeError("build matrix reader returned no rows")
    return tuple(rows)


_LIVE_BUILD_ROWS = _live_build_rows()


@pytest.mark.parametrize("failure", ["missing", "reader", "invalid", "empty"])
def test_live_build_matrix_reader_fails_closed(monkeypatch: pytest.MonkeyPatch, failure: str) -> None:
    def fake_run(*args: object, **kwargs: object) -> subprocess.CompletedProcess[str]:
        if failure == "missing":
            raise FileNotFoundError("sh")
        if failure == "reader":
            return subprocess.CompletedProcess("sh", 1, "", "reader failed")
        if failure == "invalid":
            return subprocess.CompletedProcess("sh", 0, "not-json\n", "")
        return subprocess.CompletedProcess("sh", 0, "\n", "")

    monkeypatch.setattr(bpp.subprocess, "run", fake_run)
    try:
        _live_build_rows()
    except RuntimeError as exc:
        assert "build matrix" in str(exc)
    except pytest.skip.Exception as exc:
        pytest.fail(f"matrix reader must fail, not skip: {exc}", pytrace=False)
    else:
        pytest.fail("matrix reader unexpectedly accepted failing output", pytrace=False)


def _record(
    channel: str,
    ports_sha: str,
    *,
    source_sha: str = "a" * 40,
    version: str | None = None,
    row: dict[str, object] | None = None,
) -> dict:
    if version is None:
        version = {
            "stable": "4.0.0",
            "testing": "4.0.1.a1",
            "edge": "4.0.0.b1",
            "nightly": f"20260804153045.{source_sha[:7]}",
        }[channel]
    row = dict(row or _LIVE_BUILD_ROWS[0])
    version_parts = str(row["pfsense_version"]).split(".")
    route = f"{channel}/{str(row['variant']).lower()}-{version_parts[0]}.{version_parts[1]}"
    record = {
        "schema": 1,
        "channel": channel,
        "release_line": "release/4.0",
        "classification": "nightly"
        if channel == "nightly"
        else {"stable": "final", "testing": "alpha", "edge": "beta"}[channel],
        "source_tag": None
        if channel == "nightly"
        else {"stable": "v4.0.0", "testing": "v4.0.1.a1", "edge": "v4.0.0.b1"}[channel],
        "source_sha": source_sha,
        "canonical_package_version": version,
        "native_recipe_identity": _CHANNEL_IDENTITIES[channel],
        "emitted_identity": "pfSense-pkg-pfBlockerNG",
        "matrix_row": row,
        "freebsd_ports_sha": ports_sha,
        "route": route,
        "source_date_epoch": 1700000000,
        "dependency_builder": {
            "python": "3.11.15",
            "pip": "26.2.1",
            "setuptools": "75.6.0",
            "wheel": "0.45.1",
            "zstandard": "0.25.0",
            "uv": "0.12.6",
            "uv_lock_sha256": "d" * 64,
        },
        "build_input_digest": "",
    }
    record["build_input_digest"] = pfb_pkg.build_input_digest(record)
    return record


def _make_channel_port(
    tmp_path: Path, channel: str, *, github: bool = False, php_version: str = "8.3"
) -> tuple[Path, Path, str, str]:
    ports = tmp_path / "ports"
    portname = _CHANNEL_IDENTITIES[channel]
    portdir = ports / "net" / portname
    files = portdir / "files"
    canonical_share = "pfSense-pkg-pfBlockerNG"
    (files / "usr/local/share" / canonical_share).mkdir(parents=True)
    (files / "usr/local/share" / canonical_share / "info.xml").write_text(
        "<package><name>%%PKGNAME%%</name><version>%%PKGVERSION%%</version></package>\n"
    )
    (files / "pkg-install.in").write_text("#!/bin/sh\n/usr/local/bin/php -f /etc/rc.packages %%PORTNAME%% ${2}\n")
    (files / "pkg-deinstall.in").write_text("#!/bin/sh\n/usr/local/bin/php -f /etc/rc.packages %%PORTNAME%% ${2}\n")
    portdir.joinpath("pkg-descr").write_text("Channel fixture.\n\nWWW: https://example.org/pfblockerng\n")
    portdir.joinpath("pkg-plist").write_text("%%DATADIR%%/info.xml\n")
    version = {"stable": "4.0.0", "testing": "4.0.1.a1", "edge": "4.0.0.b1", "nightly": "4.0.0"}[channel]
    gh_block = "USE_GITHUB=\tyes\nGH_ACCOUNT=\tfixture\nGH_PROJECT=\tpfsense\nGH_TAGNAME=\tstatic\n" if github else ""
    source_expr = (
        "${WRKSRC}/usr/local/share/pfSense-pkg-pfBlockerNG/info.xml"
        if github
        else ("${FILESDIR}${PREFIX}/share/pfSense-pkg-pfBlockerNG/info.xml")
    )
    portdir.joinpath("Makefile").write_text(
        f"PORTNAME=\t{portname}\nPORTVERSION=\t{version}\nCATEGORIES=\tnet\n"
        "MAINTAINER=\tdev@example.org\nCOMMENT=\tChannel fixture\nLICENSE=\tAPACHE20\n"
        "USES=\tphp python\nUSE_PHP=\tintl\n"
        f"{gh_block}SUB_FILES=\tpkg-install pkg-deinstall\n"
        "do-install:\n"
        "\t${MKDIR} ${STAGEDIR}${DATADIR}\n"
        f"\t${{INSTALL_DATA}} {source_expr} ${{STAGEDIR}}${{DATADIR}}\n"
        "\t@${REINPLACE_CMD} -i '' -e \"s|%%PKGVERSION%%|${PKGVERSION}|\" ${STAGEDIR}${DATADIR}/info.xml\n"
        "\t@${REINPLACE_CMD} -i '' -e \"s|%%PKGNAME%%|${PORTNAME:S/pfSense-pkg-//}|\" ${STAGEDIR}${DATADIR}/info.xml\n"
        ".include <bsd.port.mk>\n"
    )
    php_token = php_version.replace(".", "")
    write_port(ports, f"lang/php{php_token}", f"PORTNAME=\tphp{php_token}\nPORTVERSION=\t{php_version}.30\n")
    write_port(ports, f"devel/php{php_token}-intl", f"PORTNAME=\tphp{php_token}-intl\n")
    write_port(ports, "lang/python311", "PORTNAME=\tpython311\nPORTVERSION=\t3.11.15\n")
    ports_sha = _git_init(ports)
    source_sha = "a" * 40
    source = tmp_path / "source"
    if github:
        (source / "src/usr/local/share" / "pfSense-pkg-pfBlockerNG").mkdir(parents=True)
        (source / "src/usr/local/share" / "pfSense-pkg-pfBlockerNG" / "info.xml").write_text(
            "<package><name>%%PKGNAME%%</name><version>%%PKGVERSION%%</version></package>\n"
        )
        source_sha = _git_init(source)
        source_tag = {"stable": "v4.0.0", "testing": "v4.0.1.a1", "edge": "v4.0.0.b1", "nightly": "v4.0.0"}[channel]
        _git(source, "tag", source_tag)
    return ports, portdir, ports_sha, source_sha


def _project_args(
    ports: Path,
    portdir: Path,
    record: dict,
    *,
    source: Path | None = None,
    extra: list[str] | None = None,
    dry_run: bool = True,
    out: Path | None = None,
) -> list[str]:
    args = [
        "--ports",
        str(ports),
        "--port-dir",
        str(portdir),
        "--channel",
        record["channel"],
        "--variant",
        "CE",
        "--abi",
        "FreeBSD:15:amd64",
        "--arch",
        "freebsd:15:*",
        "--py-flavor",
        "py311",
        "--php",
        "8.3",
        "--pkgversion",
        record["canonical_package_version"],
        "--build-record",
        json.dumps(record),
        "--compression",
        "xz",
    ]
    if dry_run:
        args.append("--dry-run")
    if out is not None:
        args += ["--out", str(out)]
    if source is not None:
        args += ["--local-src", str(source)]
    if extra:
        args += extra
    return args


@pytest.mark.parametrize("channel", ["stable", "testing", "edge", "nightly"])
def test_native_channel_identities_remain_distinct(tmp_path: Path, channel: str) -> None:
    ports, portdir, _ports_sha, source_sha = _make_channel_port(tmp_path, channel)
    out = tmp_path / "native-out"
    args = [
        "--ports",
        str(ports),
        "--port-dir",
        str(portdir),
        "--channel",
        channel,
        "--abi",
        "FreeBSD:15:amd64",
        "--py-flavor",
        "py311",
        "--php",
        "8.3",
        "--compression",
        "xz",
        "--out",
        str(out),
    ]
    expected_version = {
        "stable": "4.0.0",
        "testing": "4.0.1.a1",
        "edge": "4.0.0.b1",
        "nightly": f"20260804153045.{source_sha[:7]}",
    }[channel]
    if channel == "nightly":
        args += ["--pkgversion", expected_version]
    assert bpp.main(args) == 0
    pkg = out / f"{_CHANNEL_IDENTITIES[channel]}-{expected_version}.pkg"
    full, _compact, _tf = _read_pkg(pkg)
    assert full["name"] == _CHANNEL_IDENTITIES[channel]
    assert full["origin"] == f"net/{_CHANNEL_IDENTITIES[channel]}"


@pytest.mark.parametrize("channel", ["stable", "testing", "edge", "nightly"])
def test_project_record_normalizes_complete_identity_cascade(tmp_path: Path, channel: str) -> None:
    ports, portdir, ports_sha, source_sha = _make_channel_port(tmp_path, channel, github=True)
    record = _record(channel, ports_sha, source_sha=source_sha)
    out = tmp_path / "project-out"
    args = [
        "--ports",
        str(ports),
        "--port-dir",
        str(portdir),
        "--channel",
        channel,
        "--variant",
        "CE",
        "--abi",
        "FreeBSD:15:amd64",
        "--arch",
        "freebsd:15:*",
        "--py-flavor",
        "py311",
        "--php",
        "8.3",
        "--pkgversion",
        record["canonical_package_version"],
        "--build-record",
        json.dumps(record),
        "--local-src",
        str(tmp_path / "source"),
        "--compression",
        "xz",
        "--out",
        str(out),
    ]
    assert bpp.main(args) == 0
    pkg = out / f"pfSense-pkg-pfBlockerNG-{record['canonical_package_version']}.pkg"
    result = bpp.validate_project_pkg(pkg, record)
    full = result["inspection"]["manifest"]
    assert full["name"] == "pfSense-pkg-pfBlockerNG"
    assert full["origin"] == "net/pfSense-pkg-pfBlockerNG"
    assert full["abi"] == "FreeBSD:15:*" and full["arch"] == "freebsd:15:*"
    info = result["inspection"]["payload"]["/usr/local/share/pfSense-pkg-pfBlockerNG/info.xml"].decode()
    assert "<name>pfBlockerNG</name>" in info
    assert f"<version>{record['canonical_package_version']}</version>" in info
    assert full["annotations"]["pfb_build_record"] == json.dumps(
        record, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    )
    assert "pfSense-pkg-pfBlockerNG-testing" not in full["scripts"]["install"]


def test_project_build_uses_canonical_channel_recipe_not_moved_substitute(tmp_path: Path) -> None:
    ports, canonical, _ports_sha, source_sha = _make_channel_port(tmp_path, "stable", github=True)
    substitute = ports / "net" / "moved-pfblockerng"
    shutil.copytree(canonical, substitute)
    substitute_makefile = substitute / "Makefile"
    substitute_makefile.write_text(
        substitute_makefile.read_text().replace("COMMENT=\tChannel fixture", "COMMENT=\tSubstitute")
    )
    _git(ports, "add", "-A")
    _git(ports, "-c", "commit.gpgsign=false", "commit", "-qm", "moved-substitute")
    ports_sha = _git(ports, "rev-parse", "HEAD")
    record = _record("stable", ports_sha, source_sha=source_sha)
    out = tmp_path / "out"
    args = _project_args(ports, substitute, record, source=tmp_path / "source", dry_run=False, out=out)
    assert bpp.main(args) == 0
    full, _, _ = _read_pkg(out / "pfSense-pkg-pfBlockerNG-4.0.0.pkg")
    assert full["comment"] == "Channel fixture"


@pytest.mark.parametrize("pkgversion", [None, "20260804", f"20261304153045.{'a' * 7}", f"20260804153045.{'a' * 40}"])
def test_nightly_requires_valid_explicit_pkgversion(tmp_path: Path, pkgversion: str | None) -> None:
    ports, portdir, _ports_sha, _source_sha = _make_channel_port(tmp_path, "nightly")
    out = tmp_path / "out"
    args = [
        "--ports",
        str(ports),
        "--port-dir",
        str(portdir),
        "--channel",
        "nightly",
        "--abi",
        "FreeBSD:15:amd64",
        "--py-flavor",
        "py311",
        "--php",
        "8.3",
        "--compression",
        "xz",
        "--out",
        str(out),
    ]
    if pkgversion is not None:
        args += ["--pkgversion", pkgversion]
    assert bpp.main(args) == 1
    assert not out.exists() or not list(out.glob("*.pkg"))


def test_project_rejects_recipe_identity_and_record_mismatches(tmp_path: Path) -> None:
    ports, portdir, ports_sha, _source_sha = _make_channel_port(tmp_path, "testing")
    record = _record("testing", ports_sha)
    (portdir / "Makefile").write_text(
        (portdir / "Makefile")
        .read_text()
        .replace("PORTNAME=\tpfSense-pkg-pfBlockerNG-testing", "PORTNAME=\tpfSense-pkg-pfBlockerNG-edge")
    )
    args = [
        "--ports",
        str(ports),
        "--port-dir",
        str(portdir),
        "--channel",
        "testing",
        "--variant",
        "CE",
        "--abi",
        "FreeBSD:15:amd64",
        "--py-flavor",
        "py311",
        "--php",
        "8.3",
        "--pkgversion",
        record["canonical_package_version"],
        "--build-record",
        json.dumps(record),
        "--dry-run",
    ]
    assert bpp.main(args) == 1


def test_project_rejects_reserved_annotation_and_wrong_matrix_facts(tmp_path: Path) -> None:
    ports, portdir, ports_sha, _source_sha = _make_channel_port(tmp_path, "stable")
    record = _record("stable", ports_sha)
    base = [
        "--ports",
        str(ports),
        "--port-dir",
        str(portdir),
        "--channel",
        "stable",
        "--variant",
        "CE",
        "--abi",
        "FreeBSD:15:amd64",
        "--py-flavor",
        "py311",
        "--php",
        "8.3",
        "--pkgversion",
        record["canonical_package_version"],
        "--build-record",
        json.dumps(record),
        "--dry-run",
    ]
    assert bpp.main(base + ["--annotate", "pfb_build_record=forged"]) == 1
    wrong = dict(record)
    wrong["matrix_row"] = dict(record["matrix_row"], php_version="8.5")
    wrong["build_input_digest"] = pfb_pkg.build_input_digest(wrong)
    wrong_args = list(base)
    wrong_args[wrong_args.index(json.dumps(record))] = json.dumps(wrong)
    assert bpp.main(wrong_args) == 1


def test_project_git_source_attestation_and_deterministic_mtime(tmp_path: Path) -> None:
    ports, portdir, ports_sha, source_sha = _make_channel_port(tmp_path, "stable", github=True)
    record = _record("stable", ports_sha, source_sha=source_sha)
    out1, out2 = tmp_path / "one", tmp_path / "two"
    common = [
        "--ports",
        str(ports),
        "--port-dir",
        str(portdir),
        "--channel",
        "stable",
        "--variant",
        "CE",
        "--abi",
        "FreeBSD:15:amd64",
        "--py-flavor",
        "py311",
        "--php",
        "8.3",
        "--pkgversion",
        record["canonical_package_version"],
        "--build-record",
        json.dumps(record),
        "--local-src",
        str(tmp_path / "source"),
        "--compression",
        "xz",
    ]
    assert bpp.main(common + ["--out", str(out1)]) == 0
    assert bpp.main(common + ["--out", str(out2)]) == 0
    pkg1 = out1 / "pfSense-pkg-pfBlockerNG-4.0.0.pkg"
    pkg2 = out2 / "pfSense-pkg-pfBlockerNG-4.0.0.pkg"
    assert pkg1.read_bytes() == pkg2.read_bytes()
    full, _compact, _tf = _read_pkg(pkg1)
    assert {entry["mtime"] for entry in full["files"].values()} == {1700000000}
    wrong = dict(record, source_sha="b" * 40)
    wrong["build_input_digest"] = pfb_pkg.build_input_digest(wrong)
    wrong_args = list(common)
    wrong_args[wrong_args.index(json.dumps(record))] = json.dumps(wrong)
    assert bpp.main(wrong_args + ["--out", str(tmp_path / "sha-mismatch-out")]) == 1
    # Keep each dirty-check probe on a clean counterpart. The old sequence dirtied
    # ports first, so the later source assertion never reached source attestation.
    ports_dirty, portdir_dirty, ports_sha_dirty, source_sha_dirty = _make_channel_port(
        tmp_path / "ports-dirty", "stable", github=True
    )
    dirty_record = _record("stable", ports_sha_dirty, source_sha=source_sha_dirty)
    dirty_common = [
        "--ports",
        str(ports_dirty),
        "--port-dir",
        str(portdir_dirty),
        "--channel",
        "stable",
        "--variant",
        "CE",
        "--abi",
        "FreeBSD:15:amd64",
        "--py-flavor",
        "py311",
        "--php",
        "8.3",
        "--pkgversion",
        dirty_record["canonical_package_version"],
        "--build-record",
        json.dumps(dirty_record),
        "--local-src",
        str(tmp_path / "ports-dirty" / "source"),
        "--compression",
        "xz",
    ]
    (ports_dirty / "dirty.txt").write_text("dirty")
    assert bpp.main(dirty_common + ["--out", str(tmp_path / "ports-dirty-out")]) == 1

    source_dirty_ports, source_dirty_portdir, source_dirty_ports_sha, source_dirty_sha = _make_channel_port(
        tmp_path / "source-dirty", "stable", github=True
    )
    source_dirty_record = _record("stable", source_dirty_ports_sha, source_sha=source_dirty_sha)
    source_dirty_common = [
        "--ports",
        str(source_dirty_ports),
        "--port-dir",
        str(source_dirty_portdir),
        "--channel",
        "stable",
        "--variant",
        "CE",
        "--abi",
        "FreeBSD:15:amd64",
        "--py-flavor",
        "py311",
        "--php",
        "8.3",
        "--pkgversion",
        source_dirty_record["canonical_package_version"],
        "--build-record",
        json.dumps(source_dirty_record),
        "--local-src",
        str(tmp_path / "source-dirty" / "source"),
        "--compression",
        "xz",
    ]
    (tmp_path / "source-dirty" / "source" / "dirty.txt").write_text("dirty")
    assert bpp.main(source_dirty_common + ["--out", str(tmp_path / "dirty-out")]) == 1


def test_project_post_write_validation_removes_output_on_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    ports, portdir, ports_sha, _source_sha = _make_channel_port(tmp_path, "stable")
    record = _record("stable", ports_sha)
    monkeypatch.setattr(bpp, "validate_project_pkg", lambda *a, **k: (_ for _ in ()).throw(bpp.PkgError("bad package")))
    out = tmp_path / "out"
    assert (
        bpp.main(
            [
                "--ports",
                str(ports),
                "--port-dir",
                str(portdir),
                "--channel",
                "stable",
                "--variant",
                "CE",
                "--abi",
                "FreeBSD:15:amd64",
                "--py-flavor",
                "py311",
                "--php",
                "8.3",
                "--pkgversion",
                record["canonical_package_version"],
                "--build-record",
                json.dumps(record),
                "--compression",
                "xz",
                "--out",
                str(out),
            ]
        )
        == 1
    )
    assert not list(out.glob("*.pkg"))


def test_inline_channel_spelling_enforces_native_recipe_identity(tmp_path: Path) -> None:
    ports, stable_portdir, _ports_sha, _source_sha = _make_channel_port(tmp_path, "stable")
    out = tmp_path / "out"
    assert (
        bpp.main(
            [
                "--ports",
                str(ports),
                "--port-dir",
                str(stable_portdir),
                "--channel=testing",
                "--abi",
                "FreeBSD:15:amd64",
                "--py-flavor",
                "py311",
                "--php",
                "8.3",
                "--compression",
                "xz",
                "--dry-run",
                "--out",
                str(out),
            ]
        )
        == 1
    )
    assert not out.exists() or not list(out.glob("*.pkg"))


@pytest.mark.parametrize("ambient", ["1700000001", "not-a-number"])
def test_project_record_rejects_conflicting_source_date_epoch(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, ambient: str
) -> None:
    ports, portdir, ports_sha, _source_sha = _make_channel_port(tmp_path, "stable")
    record = _record("stable", ports_sha)
    monkeypatch.setenv("SOURCE_DATE_EPOCH", ambient)
    out = tmp_path / "out"
    assert (
        bpp.main(
            [
                "--ports",
                str(ports),
                "--port-dir",
                str(portdir),
                "--channel",
                "stable",
                "--variant",
                "CE",
                "--abi",
                "FreeBSD:15:amd64",
                "--py-flavor",
                "py311",
                "--php",
                "8.3",
                "--pkgversion",
                record["canonical_package_version"],
                "--build-record",
                json.dumps(record),
                "--compression",
                "xz",
                "--out",
                str(out),
            ]
        )
        == 1
    )
    assert not out.exists() or not list(out.glob("*.pkg"))


@pytest.mark.parametrize("ambient", [None, "1700000000"])
def test_project_record_source_date_epoch_controls_package_mtime(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, ambient: str | None
) -> None:
    ports, portdir, ports_sha, source_sha = _make_channel_port(tmp_path, "stable", github=True)
    record = _record("stable", ports_sha, source_sha=source_sha)
    if ambient is None:
        monkeypatch.delenv("SOURCE_DATE_EPOCH", raising=False)
    else:
        monkeypatch.setenv("SOURCE_DATE_EPOCH", ambient)
    out = tmp_path / "out"
    assert (
        bpp.main(
            [
                "--ports",
                str(ports),
                "--port-dir",
                str(portdir),
                "--channel",
                "stable",
                "--variant",
                "CE",
                "--abi",
                "FreeBSD:15:amd64",
                "--py-flavor",
                "py311",
                "--php",
                "8.3",
                "--pkgversion",
                record["canonical_package_version"],
                "--build-record",
                json.dumps(record),
                "--local-src",
                str(tmp_path / "source"),
                "--compression",
                "xz",
                "--out",
                str(out),
            ]
        )
        == 0
    )
    pkg = out / "pfSense-pkg-pfBlockerNG-4.0.0.pkg"
    full, _compact, _tf = _read_pkg(pkg)
    assert {entry["mtime"] for entry in full["files"].values()} == {record["source_date_epoch"]}


def test_output_existing_regular_file_is_no_clobber(tmp_path: Path) -> None:
    ports, portdir = _make_classic_port(tmp_path)
    out = tmp_path / "out"
    out.mkdir()
    final = out / "testpkg-1.0_2.pkg"
    final.write_bytes(b"do not overwrite")
    before = final.read_bytes()
    assert (
        bpp.main(
            [
                "--ports",
                str(ports),
                "--port-dir",
                str(portdir),
                "--abi",
                "FreeBSD:15:amd64",
                "--py-flavor",
                "py311",
                "--compression",
                "xz",
                "--out",
                str(out),
            ]
        )
        == 1
    )
    assert final.read_bytes() == before


def test_output_existing_identical_regular_file_is_accepted(tmp_path: Path) -> None:
    ports, portdir = _make_classic_port(tmp_path)
    out = tmp_path / "out"
    args = [
        "--ports",
        str(ports),
        "--port-dir",
        str(portdir),
        "--abi",
        "FreeBSD:15:amd64",
        "--py-flavor",
        "py311",
        "--compression",
        "xz",
        "--out",
        str(out),
    ]
    assert bpp.main(args) == 0
    before = (out / "testpkg-1.0_2.pkg").read_bytes()
    assert bpp.main(args) == 0
    assert (out / "testpkg-1.0_2.pkg").read_bytes() == before


def test_output_final_symlink_is_rejected_without_following(tmp_path: Path) -> None:
    ports, portdir = _make_classic_port(tmp_path)
    out = tmp_path / "out"
    out.mkdir()
    victim = tmp_path / "victim"
    victim.write_bytes(b"safe")
    final = out / "testpkg-1.0_2.pkg"
    final.symlink_to(victim)
    assert (
        bpp.main(
            [
                "--ports",
                str(ports),
                "--port-dir",
                str(portdir),
                "--abi",
                "FreeBSD:15:amd64",
                "--py-flavor",
                "py311",
                "--compression",
                "xz",
                "--out",
                str(out),
            ]
        )
        == 1
    )
    assert final.is_symlink() and victim.read_bytes() == b"safe"


def test_output_directory_symlink_returns_failure_without_writing_target(tmp_path: Path) -> None:
    ports, portdir = _make_classic_port(tmp_path)
    target = tmp_path / "real-out"
    target.mkdir()
    sentinel = target / "sentinel"
    sentinel.write_bytes(b"safe")
    link = tmp_path / "out-link"
    link.symlink_to(target, target_is_directory=True)
    assert (
        bpp.main(
            [
                "--ports",
                str(ports),
                "--port-dir",
                str(portdir),
                "--abi",
                "FreeBSD:15:amd64",
                "--py-flavor",
                "py311",
                "--compression",
                "xz",
                "--out",
                str(link),
            ]
        )
        == 1
    )
    assert sentinel.read_bytes() == b"safe" and not list(target.glob("*.pkg"))


def test_output_parent_symlink_returns_failure_without_following(tmp_path: Path) -> None:
    ports, portdir = _make_classic_port(tmp_path)
    target = tmp_path / "real-parent"
    target.mkdir()
    link = tmp_path / "out-link"
    link.symlink_to(target, target_is_directory=True)
    nested = link / "nested"
    assert (
        bpp.main(
            [
                "--ports",
                str(ports),
                "--port-dir",
                str(portdir),
                "--abi",
                "FreeBSD:15:amd64",
                "--py-flavor",
                "py311",
                "--compression",
                "xz",
                "--out",
                str(nested),
            ]
        )
        == 1
    )
    assert not (target / "nested").exists()


@pytest.mark.parametrize("alias,canonical", [("/tmp", "/private/tmp"), ("/var", "/private/var")])
def test_output_macos_os_alias_is_allowed(tmp_path: Path, alias: str, canonical: str) -> None:
    if not Path(alias).is_symlink() or Path(alias).resolve() != Path(canonical):
        pytest.skip(f"{alias} is not the documented macOS alias")
    ports, portdir = _make_classic_port(tmp_path)
    if alias == "/tmp":
        canonical_out = Path(tempfile.mkdtemp(prefix="pfbng-portable-", dir="/private/tmp"))
        out = Path(alias) / canonical_out.relative_to("/private/tmp")
    else:
        canonical_out = Path(tempfile.mkdtemp(prefix="pfbng-portable-", dir=tmp_path))
        out = Path(alias) / canonical_out.relative_to("/private/var")
    try:
        assert (
            bpp.main(
                [
                    "--ports",
                    str(ports),
                    "--port-dir",
                    str(portdir),
                    "--abi",
                    "FreeBSD:15:amd64",
                    "--py-flavor",
                    "py311",
                    "--compression",
                    "xz",
                    "--out",
                    str(out),
                ]
            )
            == 0
        )
        assert list(out.glob("*.pkg"))
    finally:
        shutil.rmtree(out)


@pytest.mark.parametrize(
    "flag",
    [
        ["--annotate", "build=ci"],
        ["--freebsd-version", "1500068"],
        ["--repo-catalogue", "missing.yaml"],
    ],
)
def test_project_rejects_native_only_overrides(tmp_path: Path, flag: list[str]) -> None:
    ports, portdir, ports_sha, source_sha = _make_channel_port(tmp_path, "stable", github=True)
    record = _record("stable", ports_sha, source_sha=source_sha)
    assert bpp.main(_project_args(ports, portdir, record, source=tmp_path / "source", extra=flag)) == 1


def test_project_rejects_embedded_recipe(tmp_path: Path) -> None:
    ports, portdir, ports_sha, _source_sha = _make_channel_port(tmp_path, "stable", github=False)
    record = _record("stable", ports_sha)
    assert bpp.main(_project_args(ports, portdir, record)) == 1


def test_project_source_tag_must_resolve_to_source_sha(tmp_path: Path) -> None:
    ports, portdir, ports_sha, source_sha = _make_channel_port(tmp_path, "stable", github=True)
    record = _record("stable", ports_sha, source_sha=source_sha)
    bad = dict(record, source_tag="v4.0.0.missing")
    bad["build_input_digest"] = pfb_pkg.build_input_digest(bad)
    assert bpp.main(_project_args(ports, portdir, bad, source=tmp_path / "source")) == 1


def test_project_requires_local_checkout_for_source_attestation(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    ports, portdir, ports_sha, source_sha = _make_channel_port(tmp_path, "stable", github=True)
    record = _record("stable", ports_sha, source_sha=source_sha)
    assert bpp.main(_project_args(ports, portdir, record, extra=["--gh-tagname", record["source_tag"]])) == 1
    assert "requires --local-src" in capsys.readouterr().err


@pytest.mark.parametrize("channel", ["stable", "testing", "edge", "nightly"])
@pytest.mark.parametrize(
    "row",
    _LIVE_BUILD_ROWS,
    ids=[f"{str(row['variant']).lower()}-{row['pfsense_version']}" for row in _LIVE_BUILD_ROWS],
)
def test_project_matrix_rows_cover_all_channels(tmp_path: Path, channel: str, row: dict[str, object]) -> None:
    ports, portdir, ports_sha, source_sha = _make_channel_port(
        tmp_path, channel, github=True, php_version=str(row["php_version"])
    )
    record = _record(channel, ports_sha, source_sha=source_sha, row=row)
    out = tmp_path / "out"
    args = _project_args(ports, portdir, record, source=tmp_path / "source", dry_run=False, out=out)
    args[args.index("--variant") + 1] = str(row["variant"])
    args[args.index("--abi") + 1] = f"FreeBSD:{row['freebsd_major']}:amd64"
    args[args.index("--arch") + 1] = f"freebsd:{row['freebsd_major']}:*"
    args[args.index("--py-flavor") + 1] = str(row["py_flavor"])
    args[args.index("--php") + 1] = str(row["php_version"])
    assert bpp.main(args) == 0
    pkg = out / f"pfSense-pkg-pfBlockerNG-{record['canonical_package_version']}.pkg"
    result = bpp.validate_project_pkg(pkg, record)
    manifest = result["inspection"]["manifest"]
    assert manifest["name"] == "pfSense-pkg-pfBlockerNG"
    assert manifest["origin"] == "net/pfSense-pkg-pfBlockerNG"
    assert manifest["abi"] == f"FreeBSD:{row['freebsd_major']}:*"
    assert manifest["arch"] == f"freebsd:{row['freebsd_major']}:*"
    assert manifest["annotations"]["pfb_build_record"] == json.dumps(
        record, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    )


@pytest.mark.parametrize("index_flag", ["--assume-unchanged", "--skip-worktree"])
def test_project_checkout_attestation_rejects_materialized_index_flags(tmp_path: Path, index_flag: str) -> None:
    ports, portdir, ports_sha, source_sha = _make_channel_port(tmp_path, "stable", github=True)
    record = _record("stable", ports_sha, source_sha=source_sha)
    tracked = portdir / "Makefile"
    _git(ports, "update-index", index_flag, str(tracked.relative_to(ports)))
    assert bpp.main(_project_args(ports, portdir, record, source=tmp_path / "source")) == 1


def test_checkout_attestation_rejects_every_lowercase_index_marker(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(bpp, "_git_probe", lambda *_args: "m tracked\0")

    with pytest.raises(bpp.BuildError, match="assume-unchanged path: tracked"):
        bpp._reject_index_overrides(tmp_path, "source")


@pytest.mark.parametrize(
    "link_name,ignored",
    [("ignored-external.txt", True), ("tracked-trailing-space ", False)],
)
def test_project_rejects_external_source_symlinks_in_payload(tmp_path: Path, link_name: str, ignored: bool) -> None:
    ports, portdir, ports_sha, source_sha = _make_channel_port(tmp_path, "stable", github=True)
    source = tmp_path / "source"
    outside = tmp_path / "outside.txt"
    outside.write_text("mutable")
    if ignored:
        (source / ".gitignore").write_text(f"src/usr/local/share/pfSense-pkg-pfBlockerNG/{link_name}\n")
        _git(source, "add", ".gitignore")
        _git(source, "-c", "commit.gpgsign=false", "commit", "-qm", "ignore-external-link")
    link = source / "src/usr/local/share/pfSense-pkg-pfBlockerNG" / link_name
    link.symlink_to(outside)
    if not ignored:
        _git(source, "add", "-A")
        _git(source, "-c", "commit.gpgsign=false", "commit", "-qm", "external-link")
    assert _git(source, "status", "--porcelain", "--untracked-files=all") == ""
    source_sha = _git(source, "rev-parse", "HEAD")
    _git(source, "tag", "-f", "v4.0.0")
    record = _record("stable", ports_sha, source_sha=source_sha)
    record["build_input_digest"] = pfb_pkg.build_input_digest(record)
    assert bpp.main(_project_args(ports, portdir, record, source=source)) == 1


def test_project_rejects_source_payload_symlink_loop(tmp_path: Path) -> None:
    ports, portdir, ports_sha, _source_sha = _make_channel_port(tmp_path, "stable", github=True)
    source = tmp_path / "source"
    link = source / "src/usr/local/share/pfSense-pkg-pfBlockerNG/loop"
    link.symlink_to("loop")
    _git(source, "add", "-A")
    _git(source, "-c", "commit.gpgsign=false", "commit", "-qm", "symlink-loop")
    source_sha = _git(source, "rev-parse", "HEAD")
    _git(source, "tag", "-f", "v4.0.0")
    record = _record("stable", ports_sha, source_sha=source_sha)

    assert bpp.main(_project_args(ports, portdir, record, source=source)) == 1


def test_project_rejects_tracked_source_root_symlink(tmp_path: Path) -> None:
    ports, portdir, ports_sha, _source_sha = _make_channel_port(tmp_path, "stable", github=True)
    source = tmp_path / "source"
    outside = tmp_path / "outside-src"
    (source / "src").rename(outside)
    (source / "src").symlink_to(outside, target_is_directory=True)
    _git(source, "add", "-A")
    _git(source, "-c", "commit.gpgsign=false", "commit", "-qm", "source-root-link")
    source_sha = _git(source, "rev-parse", "HEAD")
    _git(source, "tag", "-f", "v4.0.0")
    record = _record("stable", ports_sha, source_sha=source_sha)
    assert bpp.main(_project_args(ports, portdir, record, source=source)) == 1


def test_project_rejects_in_tree_source_payload_symlink(tmp_path: Path) -> None:
    ports, portdir, ports_sha, _source_sha = _make_channel_port(tmp_path, "stable", github=True)
    source = tmp_path / "source"
    payload = source / "src/usr/local/share/pfSense-pkg-pfBlockerNG"
    (payload / "alias.xml").symlink_to("info.xml")
    _git(source, "add", "-A")
    _git(source, "-c", "commit.gpgsign=false", "commit", "-qm", "in-tree-link")
    source_sha = _git(source, "rev-parse", "HEAD")
    _git(source, "tag", "-f", "v4.0.0")
    record = _record("stable", ports_sha, source_sha=source_sha)
    record["build_input_digest"] = pfb_pkg.build_input_digest(record)

    assert bpp.main(_project_args(ports, portdir, record, source=source)) == 1


def test_project_source_snapshot_ignores_post_attestation_mutation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    ports, portdir, ports_sha, source_sha = _make_channel_port(tmp_path, "stable", github=True)
    source = tmp_path / "source"
    record = _record("stable", ports_sha, source_sha=source_sha)
    original = (source / "src/usr/local/share/pfSense-pkg-pfBlockerNG/info.xml").read_bytes()
    real_attest = bpp._attest_checkout

    def attest_then_mutate(*args: Any, **kwargs: Any) -> None:
        real_attest(*args, **kwargs)
        if args[2] == "source":
            (source / "src/usr/local/share/pfSense-pkg-pfBlockerNG/info.xml").write_bytes(b"tampered\n")

    monkeypatch.setattr(bpp, "_attest_checkout", attest_then_mutate)
    out = tmp_path / "out"
    args = _project_args(ports, portdir, record, source=source, dry_run=False, out=out)
    assert bpp.main(args) == 0
    pkg = out / f"pfSense-pkg-pfBlockerNG-{record['canonical_package_version']}.pkg"
    result = bpp.validate_project_pkg(pkg, record)
    payload = result["inspection"]["payload"]["/usr/local/share/pfSense-pkg-pfBlockerNG/info.xml"]
    assert payload == original.replace(b"%%PKGNAME%%", b"pfBlockerNG").replace(
        b"%%PKGVERSION%%", record["canonical_package_version"].encode()
    )


def test_project_ignores_tracked_symlink_outside_source_payload(tmp_path: Path) -> None:
    ports, portdir, ports_sha, _source_sha = _make_channel_port(tmp_path, "stable", github=True)
    source = tmp_path / "source"
    outside = tmp_path / "outside-config"
    outside.write_text("editor config")
    (source / ".claude").symlink_to(outside)
    _git(source, "add", "-A")
    _git(source, "-c", "commit.gpgsign=false", "commit", "-qm", "external-config-link")
    source_sha = _git(source, "rev-parse", "HEAD")
    _git(source, "tag", "-f", "v4.0.0")
    record = _record("stable", ports_sha, source_sha=source_sha)
    assert bpp.main(_project_args(ports, portdir, record, source=source)) == 0


def test_project_rejects_ignored_ports_symlink_outside_checkout(tmp_path: Path) -> None:
    ports, portdir, _ports_sha, source_sha = _make_channel_port(tmp_path, "stable", github=True)
    outside = tmp_path / "outside-port"
    outside.write_text("not in ports")
    (ports / ".gitignore").write_text("ignored-port-link\n")
    _git(ports, "add", ".gitignore")
    _git(ports, "-c", "commit.gpgsign=false", "commit", "-qm", "ignore-port-link")
    (ports / "ignored-port-link").symlink_to(outside)
    assert _git(ports, "status", "--porcelain", "--untracked-files=all") == ""
    ports_sha = _git(ports, "rev-parse", "HEAD")
    record = _record("stable", ports_sha, source_sha=source_sha)
    assert bpp.main(_project_args(ports, portdir, record, source=tmp_path / "source")) == 1


def test_project_rejects_tracked_ports_symlink_outside_checkout(tmp_path: Path) -> None:
    ports, portdir, _ports_sha, source_sha = _make_channel_port(tmp_path, "stable", github=True)
    outside = tmp_path / "outside-port"
    outside.write_text("not in ports")
    (ports / "external-port-link").symlink_to(outside)
    _git(ports, "add", "-A")
    _git(ports, "-c", "commit.gpgsign=false", "commit", "-qm", "ports-external-link")
    ports_sha = _git(ports, "rev-parse", "HEAD")
    record = _record("stable", ports_sha, source_sha=source_sha)
    assert bpp.main(_project_args(ports, portdir, record, source=tmp_path / "source")) == 1


def test_manifest_omits_recipe_conflicts(tmp_path: Path) -> None:
    """A recipe CONFLICTS line must NOT surface in either manifest (issue #2259).

    Real `make package`/`pkg repo` never embed CONFLICTS in a package: Netgate's
    own 2.8.1 catalog carries zero `conflicts` keys even though the
    pfSense-pkg-pfBlockerNG(-devel) ports declare CONFLICTS. Shipping the key
    makes guest libpkg register a conflict row against a package that is not
    installed and die with `NOT NULL constraint failed: pkg_conflicts.conflict_id`
    on every `pkg add` (observed on CE 2.8.1 pkg 1.21 and Plus 26.03/26.07 pkg 2.x
    alike). Channel exclusivity still holds via pkg's file-path conflict
    detection — the channel packages ship the same file set.
    """
    ports, portdir = _make_classic_port(tmp_path)
    makefile = portdir / "Makefile"
    makefile.write_text("CONFLICTS=\tfoo-* bar-*\n" + makefile.read_text())
    out = tmp_path / "out"
    assert (
        bpp.main(
            [
                "--ports",
                str(ports),
                "--port-dir",
                str(portdir),
                "--abi",
                "FreeBSD:15:amd64",
                "--py-flavor",
                "py311",
                "--compression",
                "xz",
                "--out",
                str(out),
            ]
        )
        == 0
    )
    full, compact, _ = _read_pkg(out / "testpkg-1.0_2.pkg")
    assert "conflicts" not in full, f"full +MANIFEST must omit conflicts, got {full.get('conflicts')!r}"
    assert "conflicts" not in compact, f"+COMPACT_MANIFEST must omit conflicts, got {compact.get('conflicts')!r}"
