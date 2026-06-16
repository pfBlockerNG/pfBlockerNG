#!/usr/bin/env python3
# gen_landing.py — generate the human-navigable landing page + per-directory
# indexes for the self-hosted pkg repository (ADR-17). Run by pfBlockerNG/pkg's
# publish.yml AFTER the per-ABI catalog trees are built under <site>/.
#
# It is the human-facing sibling of build-repo-portable.py: that tool emits the
# machine catalog pkg(8) fetches; this one renders a styled index over it —
# channel install cards (stable / devel / nightly), a Version x ABI table read
# from each .pkg's own manifest, and a clean per-directory listing that shows the
# package(s) but not the pkg(8) catalog plumbing (meta.conf/packagesite.pkg/...).
#
# Stdlib only + the `zstd` binary (to read a .pkg's +COMPACT_MANIFEST). Dev-only
# tooling — not shipped in release archives (those contain only src/).
#
# Usage: gen_landing.py <site-dir> <pages-base-url> <add-repo.sh path>
from __future__ import annotations

import argparse
import html
import io
import json
import os
import re
import shutil
import subprocess
import tarfile
from collections.abc import Callable, Iterable
from datetime import datetime, timezone

# Display order for the published-packages table (newest per channel). The channel of a
# package is read from its name suffix (channel_of); the install CARDS are rendered
# separately (release vs nightly) since stable + devel share one repo.
CH_ORDER: list[str] = ["stable", "devel", "nightly"]
RAW_ADDREPO = "https://raw.githubusercontent.com/pfBlockerNG/pfBlockerNG/devel/scripts/add-repo.sh"
# The source repo a .pkg is built from — base for the per-artifact commit link.
SOURCE_REPO_URL = "https://github.com/pfBlockerNG/pfBlockerNG"

# pkg(8) catalog files that live in a catalog dir but are NOT packages — excluded
# from the human listing and the package table.
CATALOG_META = ("packagesite.pkg", "data.pkg")


def channel_of(name: str) -> str:
    """Map a package NAME to its channel by suffix (-nightly / -devel / stable)."""
    if name.endswith("-nightly"):
        return "nightly"
    if name.endswith("-devel"):
        return "devel"
    return "stable"


def is_package_file(fname: str) -> bool:
    """True for a real package .pkg, False for catalog plumbing / non-.pkg."""
    return fname.endswith(".pkg") and fname not in CATALOG_META


def human_size(n: int) -> str:
    f = float(n)
    for unit in ("B", "KiB", "MiB", "GiB"):
        if f < 1024 or unit == "GiB":
            return f"{f:.0f} {unit}" if unit == "B" else f"{f:.1f} {unit}"
        f /= 1024
    return f"{f:.1f} GiB"


def ver_key(v: str) -> list[int]:
    """A coarse version sort key (numeric runs) — enough to pick the newest build."""
    return [int(x) for x in re.findall(r"\d+", v)]


def artifact_datetime(epoch: float) -> str:
    """Format a Unix epoch as a UTC, minute-precision datetime string."""
    return datetime.fromtimestamp(epoch, tz=timezone.utc).strftime("%Y-%m-%d %H:%M UTC")


def published_datetime(manifest: dict, mtime_epoch: float) -> str:
    """The artifact's creation datetime (UTC, minute precision).

    Prefer the ``created`` build annotation — the source commit's committer epoch,
    baked into the .pkg at build time, so it reflects when the artifact's CODE was
    created and survives every daily republish/re-download (devel is rebuilt and a
    release asset re-downloaded each run, which would otherwise reset the mtime to
    'today'). Fall back to the .pkg's mtime only when the annotation is absent.
    """
    created = (manifest.get("annotations") or {}).get("created")
    if created is not None:
        try:
            return artifact_datetime(float(created))
        except (TypeError, ValueError, OverflowError, OSError):
            pass  # malformed or out-of-range annotation — fall back to mtime
    return artifact_datetime(mtime_epoch)


def commit_cell(sha: str) -> str:
    """Render the source-commit cell: a short SHA linking to the commit on GitHub.

    The full SHA rides the .pkg's `commit` build annotation (stamped per channel at
    build time). A missing annotation — e.g. an older release asset built before
    commit stamping — or a non-hex value renders an em dash, never a broken/unsafe
    link (the hex guard also keeps untrusted annotation text out of the URL/markup).
    """
    sha = (sha or "").strip()
    if not re.fullmatch(r"[0-9a-fA-F]{7,40}", sha):
        return '<span class="empty">&mdash;</span>'
    return f'<a href="{SOURCE_REPO_URL}/commit/{_esc(sha)}"><code>{_esc(sha[:7])}</code></a>'


# pfSense edition display order + labels (the matrix `variant` field: CE / Plus).
# A build whose ABI the matrix doesn't cover lands in a trailing "Other" section.
EDITION_ORDER: list[str] = ["CE", "Plus"]
EDITION_LABELS: dict[str, str] = {"CE": "pfSense CE", "Plus": "pfSense Plus", "Other": "Other builds"}


def _dotted_ver(token: str) -> str:
    """A php/python flavor token -> dotted version: php85->8.5, py311/python311->3.11.

    Returns "" when the token carries no trailing digit run.
    """
    m = re.search(r"(\d+)$", token or "")
    if not m:
        return ""
    d = m.group(1)
    return f"{d[0]}.{d[1:]}" if len(d) > 1 else d


def _dep_flavor(deps: Iterable[str], names: tuple[str, ...]) -> str:
    """Dotted version of the first dep named exactly <name><digits> (e.g. php85, py311).

    Matches the runtime flavor package, not its sub-packages (php85-intl, py311-sqlite3),
    so the manifest yields the PHP/Python a build targets when no matrix row is joined.
    """
    for dep in deps:
        for nm in names:
            if re.fullmatch(rf"{nm}\d+", dep):
                return _dotted_ver(dep)
    return ""


def _or_dash(value: str) -> str:
    """An escaped cell value, or an em dash when it's empty (keeps columns aligned)."""
    return _esc(value) if value else '<span class="empty">&mdash;</span>'


def read_manifest_zstd(path: str) -> dict:
    """Read a .pkg's +COMPACT_MANIFEST (a libpkg .pkg is a zstd-compressed tar)."""
    if shutil.which("zstd") is None:
        raise RuntimeError("gen_landing.py needs the zstd binary to read .pkg manifests (e.g. pkg/apt install zstd)")
    raw = subprocess.run(["zstd", "-dc", path], capture_output=True, check=True).stdout
    with tarfile.open(fileobj=io.BytesIO(raw), mode="r:") as tar:
        member = tar.extractfile("+COMPACT_MANIFEST")
        if member is None:
            raise ValueError(f"{path}: no +COMPACT_MANIFEST member")
        return json.loads(member.read())


def collect_packages(site: str, read_manifest: Callable[[str], dict] | None = None) -> list[dict]:
    """Walk <site>/, returning one row per published package (channel/name/version/abi/size/rel)."""
    if read_manifest is None:
        read_manifest = read_manifest_zstd
    pkgs: list[dict] = []
    for dirpath, _dirs, files in os.walk(site):
        for fname in sorted(files):
            if not is_package_file(fname):
                continue
            path = os.path.join(dirpath, fname)
            man = read_manifest(path)
            name, ver, abi = man.get("name", ""), man.get("version", ""), man.get("abi", "")
            deps = man.get("deps") or {}
            pkgs.append(
                {
                    "channel": channel_of(name),
                    "name": name,
                    "version": ver,
                    "abi": abi,
                    "size": os.path.getsize(path),
                    "published": published_datetime(man, os.path.getmtime(path)),
                    "commit": (man.get("annotations") or {}).get("commit", ""),
                    # PHP/Python the build targets, read from its RUN_DEPENDS — the fallback
                    # for an ABI the matrix doesn't cover (the matrix value wins when joined).
                    "php": _dep_flavor(deps, ("php",)),
                    "py": _dep_flavor(deps, ("py", "python")),
                    "rel": os.path.relpath(path, site),
                }
            )
    return pkgs


def latest_versions(pkgs: Iterable[dict]) -> dict[str, str]:
    """Newest version present per channel (by numeric key)."""
    latest: dict[str, str] = {}
    for p in pkgs:
        ch = p["channel"]
        if ch not in latest or ver_key(p["version"]) > ver_key(latest[ch]):
            latest[ch] = p["version"]
    return latest


def build_table(pkgs: list[dict]) -> list[dict]:
    """The table rows: the newest version's package per (channel, ABI), display-sorted.

    Older nightly builds stay reachable via the catalog-tree links — the table
    surfaces only what a human would install right now.
    """
    latest = latest_versions(pkgs)
    rows = [p for p in pkgs if p["version"] == latest.get(p["channel"])]
    rows.sort(key=lambda p: (CH_ORDER.index(p["channel"]), p["abi"], p["name"]))
    return rows


def catalog_dirs(site: str) -> list[str]:
    """Relative paths of dirs holding a real package (a catalog tree)."""
    return sorted(os.path.relpath(d, site) for d, _x, files in os.walk(site) if any(is_package_file(f) for f in files))


def _esc(s: object) -> str:
    return html.escape(str(s))


_CSS = """
:root{--bg:#0d1117;--card:#161b22;--bd:#30363d;--fg:#e6edf3;--mut:#8b949e;--acc:#2f81f7;--warn:#d29922;--code:#0b0f14}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--fg);
  font:16px/1.6 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif}
a{color:var(--acc);text-decoration:none}a:hover{text-decoration:underline}
.wrap{max-width:980px;margin:0 auto;padding:2rem 1.25rem 4rem}
header h1{margin:0 0 .25rem;font-size:2rem}
header p{margin:0;color:var(--mut)}
h2{margin:2.5rem 0 1rem;font-size:1.3rem;border-bottom:1px solid var(--bd);padding-bottom:.4rem}
h3{margin:1.6rem 0 .5rem;font-size:1.05rem}
.cards{display:grid;gap:1rem;grid-template-columns:repeat(auto-fit,minmax(260px,1fr))}
.card{background:var(--card);border:1px solid var(--bd);border-radius:10px;padding:1rem 1.1rem}
.card h3{margin:0 0 .15rem;font-size:1.1rem}
.card .ver{color:var(--mut);font-size:.9rem;margin:0 0 .6rem}
.card .blurb{color:var(--mut);font-size:.92rem;margin:.15rem 0 .8rem}
pre{background:var(--code);border:1px solid var(--bd);border-radius:8px;padding:.7rem .8rem;overflow:auto;
  font:13px/1.5 ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;color:var(--fg)}
code{font:13px ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;
  background:#1f2630;padding:.1em .35em;border-radius:5px}
table{width:100%;border-collapse:collapse;font-size:.92rem}
.tablewrap{overflow-x:auto;-webkit-overflow-scrolling:touch}
th,td{text-align:left;padding:.5rem .6rem;border-bottom:1px solid var(--bd);white-space:nowrap}
th{color:var(--mut);font-weight:600}
td.num{font-variant-numeric:tabular-nums;color:var(--mut)}
.badge{display:inline-block;font-size:.72rem;padding:.05rem .45rem;border-radius:20px;
  border:1px solid var(--bd);color:var(--mut)}
details summary{cursor:pointer;color:var(--mut);font-size:.85rem;margin-top:.5rem}
ul.trees{display:grid;grid-template-columns:repeat(auto-fill,minmax(15rem,1fr));
  gap:.15rem 1rem;list-style:none;padding:0;margin:0}
ul.trees li{margin:.15rem 0;overflow-wrap:anywhere}
footer{margin-top:3rem;color:var(--mut);font-size:.85rem;border-top:1px solid var(--bd);padding-top:1rem}
.empty{color:var(--mut);font-style:italic}
.card ul.pkgs{margin:.3rem 0 .7rem;padding-left:0;list-style:none}
.card ul.pkgs li{margin:.45rem 0}
.card ul.pkgs .lbl{font-weight:600}
.card.release{border-color:var(--acc)}
.card.nightly{border-color:var(--warn)}
.card.nightly .badge{border-color:var(--warn);color:var(--warn)}
.warn{color:var(--warn)}
"""

# The release repo carries both packages (the channel picks the package, not the repo).
_PKG_STABLE = "pfSense-pkg-pfBlockerNG"
_PKG_DEVEL = "pfSense-pkg-pfBlockerNG-devel"
_PKG_NIGHTLY = "pfSense-pkg-pfBlockerNG-nightly"


def _ver_or_empty(latest: dict[str, str], channel: str) -> str:
    """The `Latest: <ver>` fragment for a channel, or an italic 'not yet published'."""
    lv = latest.get(channel)
    return f"Latest <code>{_esc(lv)}</code>" if lv else '<span class="empty">not yet published</span>'


def _release_card(base: str, latest: dict[str, str], conf_fn: Callable[[str], str]) -> str:
    """The unified stable+devel card: ONE bootstrap (the shared `pfblockerng` repo), then
    install whichever package you want — the channels differ only in the package name."""
    setup = f"fetch -qo - {RAW_ADDREPO} \\\n  | sh -s -- --base-url {base}"
    items = (
        f'<li><span class="lbl">Stable</span> — {_ver_or_empty(latest, "stable")}'
        f"<pre>pkg install {_esc(_PKG_STABLE)}</pre></li>"
        f'<li><span class="lbl">Development</span> — {_ver_or_empty(latest, "devel")}'
        f"<pre>pkg install {_esc(_PKG_DEVEL)}</pre></li>"
    )
    return (
        '<div class="card release"><h3>Stable &amp; development</h3>'
        '<p class="blurb">One bootstrap adds the shared <code>pfblockerng</code> repo, which carries '
        "both packages (they conflict &mdash; install one):</p>"
        f"<pre>{_esc(setup)}</pre>"
        f'<ul class="pkgs">{items}</ul>'
        "<details><summary>Manual conf (drop in /usr/local/etc/pkg/repos/)</summary>"
        f"<pre>{_esc(conf_fn('release'))}</pre></details></div>"
    )


def _nightly_card(base: str, latest: dict[str, str], conf_fn: Callable[[str], str]) -> str:
    """The nightly card — deliberately set apart: its own repo + a stability caveat."""
    one_liner = f"fetch -qo - {RAW_ADDREPO} \\\n  | sh -s -- --base-url {base} --nightly\npkg install {_PKG_NIGHTLY}"
    return (
        '<div class="card nightly"><h3>Nightly <span class="badge">not for daily use</span></h3>'
        f'<p class="ver">{_ver_or_empty(latest, "nightly")}</p>'
        '<p class="blurb">The <code>devel</code> tip rebuilt every night on its own separate '
        '<code>pfblockerng-nightly</code> repo. <span class="warn">Bleeding edge</span> &mdash; the only '
        "guarantee is that CI passed; unlike <code>devel</code> it carries no stability target. Use it to "
        "track the very latest, not on a production firewall.</p>"
        f"<pre>{_esc(one_liner)}</pre>"
        "<details><summary>Manual conf (drop in /usr/local/etc/pkg/repos/)</summary>"
        f"<pre>{_esc(conf_fn('nightly'))}</pre></details></div>"
    )


def matrix_index(matrix: list[dict] | None) -> dict[str, list[dict]]:
    """Map each ABI to its matrix entries (edition / pfSense version / php / py).

    An ABI shared by two pfSense versions maps to BOTH — the same .pkg installs on
    each (pkg resolves on ABI alone), so it is shown under each. The join is needed
    because the manifest itself names no pfSense edition/version, only its ABI.
    """
    idx: dict[str, list[dict]] = {}
    for e in matrix or []:
        abi = e.get("abi", "")
        if abi:
            idx.setdefault(abi, []).append(e)
    return idx


def _edition_key(variant: str) -> str:
    """Normalise the matrix `variant` to an edition key (CE / Plus / passthrough)."""
    low = (variant or "").strip().lower()
    if low == "ce":
        return "CE"
    if low == "plus":
        return "Plus"
    return variant.strip() or "Other"


def _join_matrix(rows: list[dict], matrix: list[dict] | None) -> list[tuple[str, dict]]:
    """Enrich each row with the pfSense version + PHP/Python from the matrix join.

    Returns ``(edition_key, row)`` pairs. An ABI shared by two pfSense versions yields
    one row per match (the same .pkg installs on each); an ABI with no matrix entry
    yields a single ("Other") row with a blank pfSense version + manifest-derived
    php/py, so nothing published is ever hidden. Input order is preserved.
    """
    idx = matrix_index(matrix)
    out: list[tuple[str, dict]] = []
    for r in rows:
        entries = idx.get(r["abi"], [])
        if entries:
            for e in entries:
                row = dict(r)
                row["pfsense_version"] = e.get("pfsense_version", "")
                row["php"] = e.get("php_version") or e.get("php") or r.get("php", "")
                row["py"] = _dotted_ver(e.get("py_flavor", "")) or r.get("py", "")
                out.append((_edition_key(e.get("variant", "")), row))
        else:
            row = dict(r)
            row["pfsense_version"] = ""
            out.append(("Other", row))
    return out


def build_edition_sections(pkgs: list[dict], matrix: list[dict] | None) -> list[tuple[str, list[dict]]]:
    """Group the current installables into per-edition row lists, display-ordered.

    Each row is the newest version per (channel, ABI) (build_table), enriched with the
    pfSense version + PHP/Python from the matrix join. A build whose ABI has no matrix
    entry falls into a trailing "Other" section using its manifest-derived php/py, so
    nothing published is ever hidden. Editions sort CE, then Plus, then the rest.
    """
    sections: dict[str, list[dict]] = {}
    for ekey, row in _join_matrix(build_table(pkgs), matrix):
        sections.setdefault(ekey, []).append(row)
    keys = [k for k in EDITION_ORDER if k in sections]
    keys += [k for k in sorted(sections) if k not in EDITION_ORDER and k != "Other"]
    if "Other" in sections:
        keys.append("Other")
    out: list[tuple[str, list[dict]]] = []
    for k in keys:
        rows = sections[k]
        rows.sort(key=lambda p: (ver_key(p.get("pfsense_version", "")), CH_ORDER.index(p["channel"]), p["abi"]))
        out.append((k, rows))
    return out


def _edition_table_html(rows: list[dict]) -> str:
    body = "".join(
        f"<tr><td>{_or_dash(r.get('pfsense_version', ''))}</td>"
        f"<td>{_esc(r['channel'])}</td>"
        f'<td><a href="./{_esc(r["rel"])}">{_esc(r["version"])}</a></td>'
        f"<td><code>{_esc(r['abi'])}</code></td>"
        f'<td class="num">{_or_dash(r.get("php", ""))}</td>'
        f'<td class="num">{_or_dash(r.get("py", ""))}</td>'
        f'<td class="num">{_esc(r.get("published", ""))}</td>'
        f"<td>{commit_cell(r.get('commit', ''))}</td>"
        f'<td class="num">{_esc(human_size(r["size"]))}</td></tr>'
        for r in rows
    )
    # overflow-x wrapper: a narrow (mobile) viewport scrolls the table, not the page.
    return (
        '<div class="tablewrap"><table><thead><tr>'
        "<th>pfSense</th><th>Channel</th><th>Version</th><th>ABI</th>"
        "<th>PHP</th><th>Python</th><th>Published</th><th>Commit</th><th>Size</th>"
        f"</tr></thead><tbody>{body}</tbody></table></div>"
    )


def _packages_html(pkgs: list[dict], matrix: list[dict] | None) -> str:
    """The Published-packages block: one titled table per pfSense edition."""
    sections = [(k, rows) for k, rows in build_edition_sections(pkgs, matrix) if rows]
    if not sections:
        return '<p class="empty">No packages published yet.</p>'
    return "".join(f"<h3>{_esc(EDITION_LABELS.get(k, k))}</h3>{_edition_table_html(rows)}" for k, rows in sections)


def older_nightlies(pkgs: list[dict]) -> list[dict]:
    """The retained nightly builds OTHER than the newest (newest-first, ABI-grouped).

    The per-edition tables surface only the latest nightly (the "install now" view);
    retention (ADR-18) keeps several older nightlies in the catalog, reachable here
    rather than only via the raw catalog-tree links. Empty when none are retained.
    """
    latest = latest_versions(pkgs).get("nightly")
    rows = [p for p in pkgs if p["channel"] == "nightly" and p["version"] != latest]
    rows.sort(key=lambda p: p["abi"])
    rows.sort(key=lambda p: ver_key(p["version"]), reverse=True)
    return rows


def _older_nightlies_html(pkgs: list[dict], matrix: list[dict] | None = None) -> str:
    """A collapsed disclosure listing the retained older nightlies; "" when there are none.

    Carries the same columns as the per-edition tables (matrix-joined pfSense version +
    PHP/Python), minus Channel — every row here is, by construction, a nightly.
    """
    older = older_nightlies(pkgs)
    if not older:
        return ""
    rows = [row for _ekey, row in _join_matrix(older, matrix)]
    body = "".join(
        f"<tr><td>{_or_dash(r.get('pfsense_version', ''))}</td>"
        f'<td><a href="./{_esc(r["rel"])}">{_esc(r["version"])}</a></td>'
        f"<td><code>{_esc(r['abi'])}</code></td>"
        f'<td class="num">{_or_dash(r.get("php", ""))}</td>'
        f'<td class="num">{_or_dash(r.get("py", ""))}</td>'
        f'<td class="num">{_esc(r.get("published", ""))}</td>'
        f"<td>{commit_cell(r.get('commit', ''))}</td>"
        f'<td class="num">{_esc(human_size(r["size"]))}</td></tr>'
        for r in rows
    )
    return (
        f"<details><summary>Older nightlies ({len(older)})</summary>"
        '<div class="tablewrap"><table><thead><tr>'
        "<th>pfSense</th><th>Version</th><th>ABI</th>"
        "<th>PHP</th><th>Python</th><th>Published</th><th>Commit</th><th>Size</th>"
        f"</tr></thead><tbody>{body}</tbody></table></div></details>"
    )


def render_page(
    base: str,
    pkgs: list[dict],
    trees: list[str],
    conf_fn: Callable[[str], str],
    matrix: list[dict] | None = None,
) -> str:
    """Render the root landing page."""
    latest = latest_versions(pkgs)
    cards = _release_card(base, latest, conf_fn) + _nightly_card(base, latest, conf_fn)
    tree_items = "".join(f'<li><a href="./{_esc(d)}/">{_esc(d)}</a></li>' for d in trees)
    return (
        '<!doctype html><html lang="en"><head><meta charset="utf-8">'
        '<meta name="viewport" content="width=device-width, initial-scale=1">'
        "<title>pfBlockerNG — self-hosted pkg repository</title>"
        f'<style>{_CSS}</style></head><body><div class="wrap">'
        "<header><h1>pfBlockerNG</h1>"
        "<p>Self-hosted FreeBSD <code>pkg</code> repository for pfSense&nbsp;CE &amp; pfSense&nbsp;Plus.</p></header>"
        "<p>Install pfBlockerNG straight from this repository: run the bootstrap on your firewall "
        "(as <code>root</code>), then <code>pkg install</code>. <strong>Stable</strong> and "
        "<strong>devel</strong> share one repo &mdash; pick the package; <strong>nightly</strong> is a "
        "separate, opt-in repo.</p>"
        f'<h2>Channels</h2><div class="cards">{cards}</div>'
        f"<h2>Published packages</h2>{_packages_html(pkgs, matrix)}{_older_nightlies_html(pkgs, matrix)}"
        "<h2>Catalog trees</h2>"
        '<p class="blurb">The raw pkg(8) catalogs (what your firewall fetches). <code>${ABI}</code> is filled '
        "in by pkg automatically, e.g. <code>FreeBSD:16:aarch64</code> on a Netgate ARM box.</p>"
        f'<ul class="trees">{tree_items}</ul>'
        '<footer><a href="https://github.com/pfBlockerNG/pfBlockerNG">Source</a> &middot; '
        '<a href="https://github.com/pfBlockerNG/pfBlockerNG/releases">Releases</a> &middot; '
        '<a href="https://github.com/pfBlockerNG/pkg">This repository</a></footer>'
        "</div></body></html>\n"
    )


def render_dir_index(rel: str, files: Iterable[str]) -> str:
    """Render a per-catalog-dir index listing only the real package file(s)."""
    items = sorted(f for f in files if is_package_file(f))
    li = "".join(f'<li><a href="{_esc(f)}">{_esc(f)}</a></li>' for f in items)
    back = "../" * (rel.count("/") + 1)
    return (
        '<!doctype html><html lang="en"><head><meta charset="utf-8">'
        '<meta name="viewport" content="width=device-width, initial-scale=1">'
        f"<title>pfBlockerNG pkg — {_esc(rel)}</title><style>{_CSS}</style></head>"
        f'<body><div class="wrap"><header><h1>{_esc(rel)}</h1>'
        f'<p><a href="{_esc(back)}">&larr; back to the repository</a></p></header>'
        f"<ul>{li}</ul>"
        "<footer>pkg(8) catalog metadata (<code>meta.conf</code>, <code>packagesite.pkg</code>, …) "
        "is served from this directory too.</footer></div></body></html>\n"
    )


def _conf_via_addrepo(addrepo: str, base: str, channel: str) -> str:
    # add-repo.sh selects the channel by FLAG: the release repo is the default (no arg),
    # --nightly picks the nightly repo. Anything other than "nightly" => the release conf.
    extra = ["--nightly"] if channel == "nightly" else []
    out = subprocess.run(
        ["sh", addrepo, "--print-conf", "--base-url", base, *extra],
        capture_output=True,
        text=True,
        check=True,
    )
    return out.stdout.rstrip("\n")


def write_site(site: str, base: str, addrepo: str, matrix: list[dict] | None = None) -> int:
    """Generate index.html at the root and in every catalog dir. Returns package count."""
    base = base.rstrip("/")
    pkgs = collect_packages(site)
    trees = catalog_dirs(site)

    def conf_fn(channel: str) -> str:
        return _conf_via_addrepo(addrepo, base, channel)

    with open(os.path.join(site, "index.html"), "w") as fh:
        fh.write(render_page(base, pkgs, trees, conf_fn, matrix))
    for rel in trees:
        d = os.path.join(site, rel)
        with open(os.path.join(d, "index.html"), "w") as fh:
            fh.write(render_dir_index(rel, os.listdir(d)))
    return len(pkgs)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Generate the pkg-repo landing page + per-dir indexes.")
    ap.add_argument("site", help="the built catalog tree (output of build-repo-portable.py)")
    ap.add_argument("base_url", help="the Pages base URL, e.g. https://pfblockerng.github.io/pkg")
    ap.add_argument("add_repo", help="path to add-repo.sh (for the per-channel conf snippets)")
    ap.add_argument(
        "--matrix",
        help="supported-versions build matrix JSON (list of {abi, pfsense_version, variant, "
        "php_version, py_flavor}) — splits the packages table by pfSense edition. Omitted -> "
        "a single 'Other builds' table from manifest data.",
    )
    args = ap.parse_args(argv)
    matrix = None
    if args.matrix:
        with open(args.matrix) as fh:
            matrix = json.load(fh)
    n = write_site(args.site, args.base_url, args.add_repo, matrix)
    print(f"landing page + {len(catalog_dirs(args.site))} dir index(es) written; {n} package(s) indexed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
