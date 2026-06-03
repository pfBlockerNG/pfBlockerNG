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
import sys
import tarfile
from pathlib import Path

import pytest

# --------------------------------------------------------------------------- #
# Load the hyphen-named tool as a module.
# --------------------------------------------------------------------------- #

_TOOL = Path(__file__).resolve().parent.parent / "scripts" / "build-pkg-portable.py"
_spec = importlib.util.spec_from_file_location("build_pkg_portable", _TOOL)
bpp = importlib.util.module_from_spec(_spec)
sys.modules[_spec.name] = bpp
_spec.loader.exec_module(bpp)


def make_mk(tmp_path: Path, text: str, seed: dict | None = None) -> "bpp.Makefile":
    p = tmp_path / "Makefile"
    p.write_text(text)
    return bpp.Makefile(p, seed or {})


# --------------------------------------------------------------------------- #
# Makefile evaluator
# --------------------------------------------------------------------------- #


def test_makefile_assignment_ops(tmp_path):
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


def test_makefile_seed_default_and_override(tmp_path):
    mk = make_mk(tmp_path, "PREFIX=\t/somewhere\n", seed={"PREFIX": "/usr/local", "LOCALBASE": "/usr/local"})
    assert mk.get("PREFIX") == "/somewhere"  # Makefile overrides seed
    assert mk.get("LOCALBASE") == "/usr/local"  # seed default survives


def test_makefile_expansion_and_modifiers(tmp_path):
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


def test_makefile_comment_stripping(tmp_path):
    mk = make_mk(tmp_path, "DISTFILES=\t# empty\nX=\tvalue # trailing\n")
    assert mk.get("DISTFILES") == ""
    assert mk.get("X") == "value"


def test_makefile_line_continuation_and_recipe_capture(tmp_path):
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
    [("1.0", "", "", "1.0"), ("1.0", "2", "", "1.0_2"), ("1.0", "0", "", "1.0"), ("1.0", "2", "3", "1.0_2,3")],
)
def test_compute_pkgversion(tmp_path, ver, rev, epoch, expected):
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
    ],
)
def test_abi_to_arch(abi, arch):
    assert bpp.abi_to_arch(abi) == arch


def test_abi_to_arch_malformed():
    with pytest.raises(bpp.BuildError):
        bpp.abi_to_arch("nonsense")


def test_parse_descr_keeps_www_line_verbatim():
    descr = "Line one.\nLine two.\n\nWWW: https://example.org/p\n"
    desc, www = bpp.parse_descr(descr)
    assert www == "https://example.org/p"
    # desc is the whole file (incl. the WWW line), trailing whitespace trimmed.
    assert desc == "Line one.\nLine two.\n\nWWW: https://example.org/p"


def test_resolve_www_precedence(tmp_path):
    explicit = make_mk(tmp_path, "WWW=\thttps://explicit/\n")
    assert bpp.resolve_www(explicit, "https://descr/") == "https://explicit/"

    gh = make_mk(tmp_path, "USE_GITHUB=\tyes\nGH_ACCOUNT=\tacc\nGH_PROJECT=\tProj\n")
    assert bpp.resolve_www(gh, "https://descr/") == "https://github.com/acc/Proj/"

    plain = make_mk(tmp_path, "PORTNAME=\tx\n")
    assert bpp.resolve_www(plain, "https://descr/") == "https://descr/"


def test_parse_plist_files_dirs_and_datadir():
    plist = "/etc/inc/priv/x.inc\nbin/y.sh\n%%DATADIR%%/info.xml\n@dir /etc/inc/priv\n@dir /etc/inc\n"
    sub = {"DATADIR": "share/portx"}
    files, dirs = bpp.parse_plist(plist, sub, "/usr/local")
    assert files == ["/etc/inc/priv/x.inc", "/usr/local/bin/y.sh", "/usr/local/share/portx/info.xml"]
    assert dirs == ["/etc/inc/priv", "/etc/inc"]


def test_parse_plist_unresolved_token_raises():
    with pytest.raises(bpp.BuildError):
        bpp.parse_plist("%%NOPE%%/x\n", {}, "/usr/local")


def test_parse_plist_unknown_keyword_warns(capsys):
    files, dirs = bpp.parse_plist("@sample foo.conf.sample\nbin/x\n", {}, "/usr/local")
    assert files == ["/usr/local/bin/x"]
    assert dirs == []
    assert "@sample" in capsys.readouterr().err


@pytest.mark.parametrize(
    "expr,text,expected",
    [
        ("s|A|B|", "A A\nA", "B A\nB"),  # first per line (no g)
        ("s|A|B|g", "A A\nA", "B B\nB"),  # all (g)
        ("s/x/y/", "x", "y"),  # slash delimiter
    ],
)
def test_sed_s(expr, text, expected):
    r = bpp.Recipe.__new__(bpp.Recipe)
    assert r._sed_s(text, expr) == expected


def test_sed_s_unsupported():
    r = bpp.Recipe.__new__(bpp.Recipe)
    with pytest.raises(bpp.BuildError):
        r._sed_s("text", "y|a|b|")  # only the s command is supported


# --------------------------------------------------------------------------- #
# Recipe interpreter (modes, mv, sed) on a synthetic source tree
# --------------------------------------------------------------------------- #


def test_recipe_install_modes_mv_sed(tmp_path):
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


def test_recipe_bare_mv_and_unknown_command(tmp_path):
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


# --------------------------------------------------------------------------- #
# Dependency resolution (synthetic ports tree)
# --------------------------------------------------------------------------- #


def write_port(ports: Path, origin: str, body: str) -> None:
    d = ports / origin
    d.mkdir(parents=True, exist_ok=True)
    (d / "Makefile").write_text(body)


def test_read_dep_port_flavor(tmp_path):
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


def test_resolve_deps_name_and_file_forms(tmp_path):
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


def test_synthesize_uses_deps(tmp_path):
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


def test_load_catalogue_plain_yaml(tmp_path):
    f = tmp_path / "packagesite.yaml"
    f.write_text(_CATALOGUE)
    cat = bpp.load_catalogue(str(f), "FreeBSD:15:amd64", {"rsync", "jq"})
    assert cat == {"rsync": ("net/rsync", "3.4.3"), "jq": ("textproc/jq", "1.8.1")}


def test_load_catalogue_gzipped_tar(tmp_path):
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


def test_apply_repo_catalogue_overrides_versions(tmp_path, capsys):
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


def _read_pkg(path: Path) -> tuple[dict, dict, tarfile.TarFile]:
    raw = lzma.decompress(path.read_bytes())  # built with --compression xz (stdlib)
    tf = tarfile.open(fileobj=io.BytesIO(raw))
    full = json.loads(tf.extractfile("+MANIFEST").read())
    compact = json.loads(tf.extractfile("+COMPACT_MANIFEST").read())
    return full, compact, tf


def test_end_to_end_classic_build(tmp_path):
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
    info = tf.extractfile("/usr/local/share/testpkg/info.xml").read().decode()
    assert info == "<version>1.0_2</version>\n"


def test_end_to_end_plist_drift_aborts(tmp_path):
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
