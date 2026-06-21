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
# Embed markers in add-repo.sh that delimit the hook placeholder body.
_HOOK_EMBED_BEGIN = "# PFB_EMBED_HOOK_BEGIN"
_HOOK_EMBED_END = "# PFB_EMBED_HOOK_END"
_HOOK_HEREDOC = "PFB_HOOK_HEREDOC"
# The source repo a .pkg is built from — base for the per-artifact commit link.
SOURCE_REPO_URL = "https://github.com/pfBlockerNG/pfBlockerNG"

# pkg(8) catalog files that live in a catalog dir but are NOT packages — excluded
# from the human listing and the package table.
CATALOG_META = ("packagesite.pkg", "data.pkg")

# Placeholder catalog-path passed to add-repo.sh --print-conf for the manual-conf
# snippet on the landing page.  The rc.d hook resolves the box's real varver/arch
# at boot; a hand-written conf must substitute a concrete value (e.g. ce-2.8/amd64).
_CONF_PLACEHOLDER_PATH = "<varver>/<arch>"


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

    Older builds stay reachable via the directory-browse page — the table surfaces
    only what a human would install right now.
    """
    latest = latest_versions(pkgs)
    rows = [p for p in pkgs if p["version"] == latest.get(p["channel"])]
    rows.sort(key=lambda p: (CH_ORDER.index(p["channel"]), p["abi"], p["name"]))
    return rows


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
.cards{display:grid;gap:1rem;grid-template-columns:minmax(0,1fr)}
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
a.browse{display:inline-block;padding:.5rem .9rem;border:1px solid var(--acc);border-radius:8px;font-weight:600}
table.autoindex td:first-child{white-space:normal;overflow-wrap:anywhere}
table.autoindex td.num{white-space:nowrap}
footer{margin-top:3rem;color:var(--mut);font-size:.85rem;border-top:1px solid var(--bd);padding-top:1rem}
.empty{color:var(--mut);font-style:italic}
.card ul.pkgs{margin:.3rem 0 .7rem;padding-left:0;list-style:none}
.card ul.pkgs li{margin:.45rem 0}
.card ul.pkgs .lbl{font-weight:600}
.card.release{border-color:var(--acc)}
.card.nightly{border-color:var(--warn)}
.card.nightly .badge{border-color:var(--warn);color:var(--warn)}
.warn{color:var(--warn)}
.snip{position:relative}
.snip>pre{padding-right:3.6rem}
.copy{position:absolute;top:.45rem;right:.45rem;z-index:1;
  font:600 11px/1 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif;
  color:var(--mut);background:#1f2630;border:1px solid var(--bd);border-radius:6px;
  padding:.3rem .5rem;cursor:pointer}
.copy:hover{color:var(--fg);border-color:var(--acc)}
.copy.copied{color:#3fb950;border-color:#3fb950}
"""

# The release repo carries both packages (the channel picks the package, not the repo).
_PKG_STABLE = "pfSense-pkg-pfBlockerNG"
_PKG_DEVEL = "pfSense-pkg-pfBlockerNG-devel"
_PKG_NIGHTLY = "pfSense-pkg-pfBlockerNG-nightly"

# Minimal, dependency-free clipboard handler for the snippet copy buttons. Delegated
# (one listener), reads the adjacent <pre> textContent (entities decoded), and falls
# back to execCommand('copy') where the async Clipboard API is unavailable.
_COPY_JS = (
    "(function(){"
    "function fb(t,cb){var a=document.createElement('textarea');a.value=t;"
    "a.setAttribute('readonly','');a.style.position='fixed';a.style.top='-1000px';"
    "a.style.opacity='0';document.body.appendChild(a);a.select();"
    "var ok=false;try{ok=document.execCommand('copy');}catch(e){ok=false;}"
    "document.body.removeChild(a);if(ok)cb();}"
    "function flash(b){b.textContent='Copied';b.classList.add('copied');"
    "setTimeout(function(){b.textContent='Copy';b.classList.remove('copied');},1500);}"
    "document.addEventListener('click',function(e){"
    "var b=e.target.closest&&e.target.closest('.copy');if(!b)return;"
    "var p=b.parentNode.querySelector('pre');if(!p)return;"
    "var t=p.textContent,done=function(){flash(b);};"
    "if(navigator.clipboard&&navigator.clipboard.writeText){"
    "navigator.clipboard.writeText(t).then(done).catch(function(){fb(t,done);});}"
    "else{fb(t,done);}});})();"
)


def _copyable(inner: str) -> str:
    """Wrap already-escaped snippet text in a <pre> with a corner 'Copy' button.

    The button is a sibling of (not inside) the <pre>, so the copied textContent never
    includes the button label; the <pre> content is emitted unchanged.
    """
    return (
        '<div class="snip">'
        '<button class="copy" type="button" aria-label="Copy to clipboard">Copy</button>'
        f"<pre>{inner}</pre></div>"
    )


def _ver_or_empty(latest: dict[str, str], channel: str) -> str:
    """The `Latest: <ver>` fragment for a channel, or an italic 'not yet published'."""
    lv = latest.get(channel)
    return f"Latest <code>{_esc(lv)}</code>" if lv else '<span class="empty">not yet published</span>'


def _release_card(base: str, latest: dict[str, str], conf_fn: Callable[[str], str]) -> str:
    """The unified stable+devel card: ONE bootstrap (the shared `pfblockerng` repo), then
    install whichever package you want — the channels differ only in the package name."""
    setup = f"fetch -qo - {base}/add-repo.sh \\\n  | sh -s -- --base-url {base}"
    items = (
        f'<li><span class="lbl">Stable</span> — {_ver_or_empty(latest, "stable")}'
        f"{_copyable('pkg install ' + _esc(_PKG_STABLE))}</li>"
        f'<li><span class="lbl">Development</span> — {_ver_or_empty(latest, "devel")}'
        f"{_copyable('pkg install ' + _esc(_PKG_DEVEL))}</li>"
    )
    return (
        '<div class="card release"><h3>Stable &amp; development</h3>'
        '<p class="blurb">One bootstrap adds the shared <code>pfblockerng</code> repo, which carries '
        "both packages (they conflict &mdash; install one):</p>"
        f"{_copyable(_esc(setup))}"
        f'<ul class="pkgs">{items}</ul>'
        "<details><summary>Manual conf (advanced)</summary>"
        '<p class="blurb">The bootstrap auto-detects these; in a hand-written conf, replace '
        "<code>&lt;varver&gt;</code> (the edition-version: <code>ce-2.8</code>, <code>plus-26.03</code>, &hellip;) and "
        "<code>&lt;arch&gt;</code> (the CPU architecture: <code>amd64</code> or <code>aarch64</code>) "
        "with your box's values.</p>"
        f"{_copyable(_esc(conf_fn('release')))}</details></div>"
    )


def _nightly_card(base: str, latest: dict[str, str], conf_fn: Callable[[str], str]) -> str:
    """The nightly card — deliberately set apart: its own repo + a stability caveat."""
    one_liner = (
        f"fetch -qo - {base}/add-repo.sh \\\n  | sh -s -- --base-url {base} --nightly\npkg install {_PKG_NIGHTLY}"
    )
    return (
        '<div class="card nightly"><h3>Nightly <span class="badge">not for daily use</span></h3>'
        f'<p class="ver">{_ver_or_empty(latest, "nightly")}</p>'
        '<p class="blurb">The <code>devel</code> tip rebuilt every night on its own separate '
        '<code>pfblockerng-nightly</code> repo. <span class="warn">Bleeding edge</span> &mdash; the only '
        "guarantee is that CI passed; unlike <code>devel</code> it carries no stability target. Use it to "
        "track the very latest, not on a production firewall.</p>"
        f"{_copyable(_esc(one_liner))}"
        "<details><summary>Manual conf (advanced)</summary>"
        '<p class="blurb">The bootstrap auto-detects these; in a hand-written conf, replace '
        "<code>&lt;varver&gt;</code> (the edition-version: <code>ce-2.8</code>, <code>plus-26.03</code>, &hellip;) and "
        "<code>&lt;arch&gt;</code> (the CPU architecture: <code>amd64</code> or <code>aarch64</code>) "
        "with your box's values.</p>"
        f"{_copyable(_esc(conf_fn('nightly')))}</details></div>"
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


def _order_edition_keys(sections: dict[str, list[dict]]) -> list[str]:
    """Edition display order: CE, then Plus, then any other variant alphabetically,
    with "Other" (unmatched ABIs) always last."""
    keys = [k for k in EDITION_ORDER if k in sections]
    keys += [k for k in sorted(sections) if k not in EDITION_ORDER and k != "Other"]
    if "Other" in sections:
        keys.append("Other")
    return keys


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
    out: list[tuple[str, list[dict]]] = []
    for k in _order_edition_keys(sections):
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
    """The Published-packages block: one titled table per pfSense edition, each followed by
    that edition's retained older releases and older nightlies, each folded into a collapsed
    disclosure."""
    sections = [(k, rows) for k, rows in build_edition_sections(pkgs, matrix) if rows]
    if not sections:
        return '<p class="empty">No packages published yet.</p>'
    older_releases_by_edition = _older_releases_by_edition(pkgs, matrix)
    older_nightlies_by_edition = _older_nightlies_by_edition(pkgs, matrix)
    return "".join(
        f"<h3>{_esc(EDITION_LABELS.get(k, k))}</h3>"
        f"{_edition_table_html(rows)}"
        f"{_older_releases_details(older_releases_by_edition.get(k, []))}"
        f"{_older_nightlies_details(older_nightlies_by_edition.get(k, []))}"
        for k, rows in sections
    )


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


def _older_nightlies_table_html(rows: list[dict]) -> str:
    """One older-nightlies table for a single edition: the same columns as the per-edition
    tables (matrix-joined pfSense version + PHP/Python), minus Channel — every row here is,
    by construction, a nightly."""
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
        '<div class="tablewrap"><table><thead><tr>'
        "<th>pfSense</th><th>Version</th><th>ABI</th>"
        "<th>PHP</th><th>Python</th><th>Published</th><th>Commit</th><th>Size</th>"
        f"</tr></thead><tbody>{body}</tbody></table></div>"
    )


def _older_nightlies_by_edition(pkgs: list[dict], matrix: list[dict] | None) -> dict[str, list[dict]]:
    """The retained older nightlies grouped by edition key (matrix-joined by ABI), so each
    edition's disclosure folds in directly under that edition's table. Empty when none."""
    by_edition: dict[str, list[dict]] = {}
    for ekey, row in _join_matrix(older_nightlies(pkgs), matrix):
        by_edition.setdefault(ekey, []).append(row)
    return by_edition


def _older_nightlies_details(rows: list[dict]) -> str:
    """One edition's retained older nightlies, folded into a collapsed disclosure; "" when
    that edition has none. Same columns as the edition table, minus Channel (all nightlies)."""
    if not rows:
        return ""
    return f"<details><summary>Older nightlies ({len(rows)})</summary>{_older_nightlies_table_html(rows)}</details>"


def older_releases(pkgs: list[dict]) -> list[dict]:
    """The retained stable/devel release builds OTHER than the newest per channel.

    The per-edition tables surface only the latest devel and stable versions (the
    "install now" view); release retention (ADR-27) keeps several older releases in the
    catalog, reachable here so a human can find a rollback target. Sorted newest-first
    within each channel, then by ABI. Empty when no older versions are retained.
    """
    latest = latest_versions(pkgs)
    rows = [p for p in pkgs if p["channel"] in ("devel", "stable") and p["version"] != latest.get(p["channel"])]
    rows.sort(key=lambda p: p["abi"])
    rows.sort(key=lambda p: (CH_ORDER.index(p["channel"]), ver_key(p["version"])), reverse=True)
    return rows


def _older_releases_table_html(rows: list[dict]) -> str:
    """One older-releases table for a single edition: same columns as the per-edition
    tables (matrix-joined pfSense version + PHP/Python), WITH Channel — devel and stable
    can both appear, so the channel column distinguishes them."""
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
    return (
        '<div class="tablewrap"><table><thead><tr>'
        "<th>pfSense</th><th>Channel</th><th>Version</th><th>ABI</th>"
        "<th>PHP</th><th>Python</th><th>Published</th><th>Commit</th><th>Size</th>"
        f"</tr></thead><tbody>{body}</tbody></table></div>"
    )


def _older_releases_by_edition(pkgs: list[dict], matrix: list[dict] | None) -> dict[str, list[dict]]:
    """The retained older releases grouped by edition key (matrix-joined by ABI), so each
    edition's disclosure folds in directly under that edition's table. Empty when none."""
    by_edition: dict[str, list[dict]] = {}
    for ekey, row in _join_matrix(older_releases(pkgs), matrix):
        by_edition.setdefault(ekey, []).append(row)
    return by_edition


def _older_releases_details(rows: list[dict]) -> str:
    """One edition's retained older releases, folded into a collapsed disclosure; "" when
    that edition has none. Includes Channel column (devel and stable can both appear)."""
    if not rows:
        return ""
    return f"<details><summary>Older releases ({len(rows)})</summary>{_older_releases_table_html(rows)}</details>"


def _eol_varver(pfsense_version: str, variant: str) -> str:
    """The catalog dir name (varver) for a route-only matrix entry.

    Mirrors build-repo-portable.py's catalog_name_from_version (major.minor only):
      "2.7" + "CE"   -> "ce-2.7"
      "25.03"+ "Plus" -> "plus-25.03"
    """
    major_minor = ".".join(pfsense_version.split(".")[:2])
    return f"{variant.lower()}-{major_minor}"


def eol_versions(pkgs: list[dict], matrix: list[dict] | None) -> list[tuple[str, str, dict]]:
    """The last-served .pkg for each EOL (route-only) pfSense version.

    A matrix entry is EOL iff ``role == "route-only"``. For each such entry, this function
    finds the newest .pkg version (by ver_key) served for that varver's path prefix
    (``release/<varver>/``), enriched with the matrix-provided pfSense version + PHP/Python.

    Returns ``(edition_key, pfsense_version, row)`` triples — one per (EOL pfSense version,
    ABI) combination — in deterministic order: CE before Plus, older pfSense version before
    newer within each edition, ABI alphabetically within each version.
    """
    eol_entries = [e for e in (matrix or []) if e.get("role") == "route-only"]
    if not eol_entries:
        return []

    # Group pkgs by path prefix release/<varver>/, so each EOL varver's pool is isolated.
    varver_pkgs: dict[str, list[dict]] = {}
    for p in pkgs:
        # rel format: release/<varver>/<arch>/name.pkg (always forward-slash, os.path.relpath
        # normalises to the OS separator, so normalise here too).
        rel = p["rel"].replace(os.sep, "/")
        parts = rel.split("/")
        if len(parts) >= 2 and parts[0] == "release":
            vv = parts[1]
            varver_pkgs.setdefault(vv, []).append(p)

    # For each EOL matrix entry, find the newest pkg per ABI in its varver pool.
    # One matrix entry = one (pfsense_version, variant, abi) combination.
    out: list[tuple[str, str, dict]] = []
    seen: set[tuple[str, str]] = set()  # (varver, abi) already emitted — dedup multi-arch entries
    for e in eol_entries:
        version = e.get("pfsense_version", "")
        variant = e.get("variant", "")
        abi = e.get("abi", "")
        php = e.get("php_version") or e.get("php", "")
        py = _dotted_ver(e.get("py_flavor", "")) or e.get("py", "")
        ekey = _edition_key(variant)
        varver = _eol_varver(version, variant)
        dedup_key = (varver, abi)
        if dedup_key in seen:
            continue
        seen.add(dedup_key)

        pool = [p for p in varver_pkgs.get(varver, []) if p["abi"] == abi]
        if not pool:
            continue  # no .pkg served for this (varver, abi) — skip silently

        # Newest served version = highest ver_key.
        best = max(pool, key=lambda p: ver_key(p["version"]))
        row = dict(best)
        row["pfsense_version"] = version
        row["php"] = php
        row["py"] = py
        out.append((ekey, version, row))

    # Sort: edition order (CE < Plus < Other), then pfSense version newest-first, then ABI.
    edition_rank = {k: i for i, k in enumerate(EDITION_ORDER)}

    def _sort_key(t: tuple[str, str, dict]) -> tuple[int, list[int], str]:
        ekey, ver, row = t
        return (edition_rank.get(ekey, len(EDITION_ORDER)), ver_key(ver), row["abi"])

    out.sort(key=_sort_key)
    return out


def _eol_table_html(rows: list[dict]) -> str:
    """One EOL-versions table for a single edition.

    Columns mirror the older-nightlies table shape (no Channel — irrelevant for EOL):
    pfSense | Version | ABI | PHP | Python | Published | Commit | Size.
    """
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
        '<div class="tablewrap"><table><thead><tr>'
        "<th>pfSense</th><th>Version</th><th>ABI</th>"
        "<th>PHP</th><th>Python</th><th>Published</th><th>Commit</th><th>Size</th>"
        f"</tr></thead><tbody>{body}</tbody></table></div>"
    )


def _eol_versions_html(pkgs: list[dict], matrix: list[dict] | None) -> str:
    """The EOL pfSense versions block: one table per edition (CE, Plus), each listing every
    route-only pfSense version and the last/highest .pkg still served for it.

    Returns "" when no matrix route-only entries exist — the section is entirely absent
    (no empty heading emitted).
    """
    triples = eol_versions(pkgs, matrix)
    if not triples:
        return ""

    # Group into per-edition lists, preserving the sorted order.
    by_edition: dict[str, list[dict]] = {}
    for ekey, _ver, row in triples:
        by_edition.setdefault(ekey, []).append(row)

    ordered_keys = [k for k in EDITION_ORDER if k in by_edition]
    ordered_keys += [k for k in sorted(by_edition) if k not in EDITION_ORDER and k != "Other"]
    if "Other" in by_edition:
        ordered_keys.append("Other")

    body = "".join(f"<h3>{_esc(EDITION_LABELS.get(k, k))}</h3>{_eol_table_html(by_edition[k])}" for k in ordered_keys)
    return (
        "<h2>EOL pfSense versions</h2>"
        "<p>These pfSense versions have reached end-of-life. The last build we served for "
        "each is still available below &mdash; pkg(8) on an EOL firewall continues to "
        "receive it automatically.</p>"
        f"{body}"
    )


def render_page(
    base: str,
    pkgs: list[dict],
    conf_fn: Callable[[str], str],
    matrix: list[dict] | None = None,
) -> str:
    """Render the root landing page."""
    latest = latest_versions(pkgs)
    cards = _release_card(base, latest, conf_fn) + _nightly_card(base, latest, conf_fn)
    eol_block = _eol_versions_html(pkgs, matrix)
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
        f"<h2>Published packages</h2>{_packages_html(pkgs, matrix)}"
        f"{eol_block}"
        "<h2>Repository files</h2>"
        '<p class="blurb">Browse every channel, version and ABI &mdash; and the raw pkg(8) catalogs your '
        "firewall fetches &mdash; in a directory-style listing.</p>"
        '<p><a class="browse" href="./browse.html">&#128193; Browse the repository &rarr;</a></p>'
        '<footer><a href="https://github.com/pfBlockerNG/pfBlockerNG">Source</a> &middot; '
        '<a href="https://github.com/pfBlockerNG/pfBlockerNG/releases">Releases</a> &middot; '
        '<a href="https://github.com/pfBlockerNG/pkg">This repository</a></footer>'
        "</div>"
        f"<script>{_COPY_JS}</script>"
        "</body></html>\n"
    )


def all_dirs(site: str) -> list[str]:
    """Every directory under ``site`` (relative path, "/"-separated), excluding the site root,
    sorted. Used to emit a browsable autoindex at EVERY level (GitHub Pages has no autoindex)."""
    out = [os.path.relpath(d, site) for d, _x, _f in os.walk(site) if os.path.relpath(d, site) != "."]
    return sorted(out)


# Generated HTML + Pages plumbing that an autoindex listing hides (it is not repository content).
_INDEX_HIDDEN = frozenset({"index.html", "browse.html", ".nojekyll"})


def _dir_entries(site: str, rel: str) -> tuple[list[str], list[tuple[str, int, float]]]:
    """The immediate children of ``site/rel``: (subdir names, file (name, size, mtime) tuples),
    each sorted, with the generated index pages + Pages plumbing hidden."""
    d = os.path.join(site, rel) if rel else site
    subdirs: list[str] = []
    files: list[tuple[str, int, float]] = []
    for name in sorted(os.listdir(d)):
        if name in _INDEX_HIDDEN:
            continue
        p = os.path.join(d, name)
        if os.path.isdir(p):
            subdirs.append(name)
        else:
            st = os.stat(p)
            files.append((name, st.st_size, st.st_mtime))
    return subdirs, files


def render_autoindex(
    rel: str, subdirs: list[str], files: list[tuple[str, int, float]], *, is_root: bool = False
) -> str:
    """A FreeBSD/Debian-style directory listing for ``rel`` (the browse root when ``is_root``).

    Subdirs link to ``./<name>/`` and files to ``./<name>`` (the ``./`` prefix keeps a colon-bearing
    ABI segment like ``FreeBSD:15:amd64`` a relative path, not a URI scheme — RFC 3986 §4.2). A
    "Parent Directory" row (``../``) is shown except at the browse root."""
    title = f"/{rel}" if rel else "/"
    rows = []
    if not is_root:
        rows.append(
            '<tr><td><a href="../">../</a></td><td class="num">&mdash;</td><td class="num">Parent Directory</td></tr>'
        )
    for name in subdirs:
        rows.append(
            f'<tr><td><a href="./{_esc(name)}/">{_esc(name)}/</a></td>'
            '<td class="num">&mdash;</td><td class="num">&mdash;</td></tr>'
        )
    for name, size, mtime in files:
        rows.append(
            f'<tr><td><a href="./{_esc(name)}">{_esc(name)}</a></td>'
            f'<td class="num">{_esc(artifact_datetime(mtime))}</td>'
            f'<td class="num">{_esc(human_size(size))}</td></tr>'
        )
    # "repository home" climbs to the site root (which serves the human landing page).
    home = "./" if is_root else "../" * (rel.count("/") + 1)
    return (
        '<!doctype html><html lang="en"><head><meta charset="utf-8">'
        '<meta name="viewport" content="width=device-width, initial-scale=1">'
        f"<title>pfBlockerNG pkg — Index of {_esc(title)}</title><style>{_CSS}</style></head>"
        f'<body><div class="wrap"><header><h1>Index of {_esc(title)}</h1>'
        f'<p><a href="{_esc(home)}">&larr; pfBlockerNG repository home</a></p></header>'
        '<div class="tablewrap"><table class="autoindex"><thead><tr>'
        "<th>Name</th><th>Last modified</th><th>Size</th></tr></thead>"
        f"<tbody>{''.join(rows)}</tbody></table></div>"
        "<footer>Directory listing of the self-hosted pfBlockerNG pkg repository. "
        "pkg(8) fetches the catalog files (<code>meta.conf</code>, <code>packagesite.pkg</code>, …) directly.</footer>"
        "</div></body></html>\n"
    )


def _embed_hook(add_repo_text: str, hook_text: str) -> str:
    """Splice *hook_text* into *add_repo_text* between the PFB_EMBED markers.

    The stub body (everything between the BEGIN and END marker lines, inclusive) is
    replaced with a single-quoted heredoc that prints the hook verbatim — no variable
    or command expansion in the emitted content, regardless of what the hook contains.
    The resulting add-repo.sh is self-contained and safe to pipe into ``sh``.
    """
    lines = add_repo_text.splitlines(keepends=True)
    begin_idx = next(
        (i for i, ln in enumerate(lines) if _HOOK_EMBED_BEGIN in ln),
        None,
    )
    end_idx = next(
        (i for i, ln in enumerate(lines) if _HOOK_EMBED_END in ln),
        None,
    )
    if begin_idx is None or end_idx is None or begin_idx >= end_idx:
        raise ValueError(f"add-repo.sh is missing the embed markers ({_HOOK_EMBED_BEGIN!r} / {_HOOK_EMBED_END!r})")
    if _HOOK_HEREDOC in hook_text:
        raise ValueError(
            f"hook text contains the heredoc delimiter {_HOOK_HEREDOC!r} — choose a different delimiter or fix the hook"
        )
    # Build the replacement: keep the BEGIN marker line, inject the heredoc, keep END.
    heredoc_lines = [
        lines[begin_idx],
        f"    cat <<'{_HOOK_HEREDOC}'\n",
        hook_text if hook_text.endswith("\n") else hook_text + "\n",
        f"{_HOOK_HEREDOC}\n",
        lines[end_idx],
    ]
    return "".join(lines[:begin_idx] + heredoc_lines + lines[end_idx + 1 :])


def write_add_repo(site: str, addrepo: str) -> None:
    """Write a self-contained ``add-repo.sh`` to *site*/add-repo.sh.

    *addrepo* is the path to the repository copy of ``scripts/add-repo.sh`` (which
    contains the stub placeholder body between the embed markers).  The hook is
    resolved as ``rc.d/pfblockerng_repo_generate.sh`` relative to the same ``scripts/``
    directory.  The published file embeds the hook via a single-quoted heredoc so it
    works correctly when piped into ``sh`` (where ``$0`` is ``sh`` and sibling-file
    resolution via ``dirname "$0"`` fails).
    """
    scripts_dir = os.path.dirname(os.path.abspath(addrepo))
    hook = os.path.join(scripts_dir, "rc.d", "pfblockerng_repo_generate.sh")
    with open(addrepo) as fh:
        add_repo_text = fh.read()
    with open(hook) as fh:
        hook_text = fh.read()
    out_text = _embed_hook(add_repo_text, hook_text)
    out_path = os.path.join(site, "add-repo.sh")
    with open(out_path, "w") as fh:
        fh.write(out_text)
    os.chmod(out_path, 0o755)


def _conf_via_addrepo(addrepo: str, base: str, channel: str) -> str:
    # add-repo.sh selects the channel by FLAG: the release repo is the default (no arg),
    # --nightly picks the nightly repo. Anything other than "nightly" => the release conf.
    # --catalog-path is required by --print-conf; we pass a literal placeholder here
    # because the landing page shows a generic snippet — the rc.d hook resolves the
    # box's real varver/arch at boot (see _CONF_PLACEHOLDER_PATH).
    extra = ["--nightly"] if channel == "nightly" else []
    out = subprocess.run(
        ["sh", addrepo, "--print-conf", "--base-url", base, "--catalog-path", _CONF_PLACEHOLDER_PATH, *extra],
        capture_output=True,
        text=True,
        check=True,
    )
    return out.stdout.rstrip("\n")


def write_site(site: str, base: str, addrepo: str, matrix: list[dict] | None = None) -> int:
    """Generate the human landing page (root index.html), a browsable autoindex at EVERY
    directory level (so the whole tree is folder-navigable on GitHub Pages, which has no
    autoindex), and a root ``browse.html`` entry point the landing page links to. Returns the
    package count."""
    base = base.rstrip("/")
    pkgs = collect_packages(site)

    def conf_fn(channel: str) -> str:
        return _conf_via_addrepo(addrepo, base, channel)

    # The human landing page stays the site root; browse.html is the directory-style entry.
    with open(os.path.join(site, "index.html"), "w") as fh:
        fh.write(render_page(base, pkgs, conf_fn, matrix))
    root_subdirs, root_files = _dir_entries(site, "")
    with open(os.path.join(site, "browse.html"), "w") as fh:
        fh.write(render_autoindex("", root_subdirs, root_files, is_root=True))
    # An autoindex index.html in every directory (intermediate + leaf), so each level is browsable.
    for rel in all_dirs(site):
        subdirs, files = _dir_entries(site, rel)
        with open(os.path.join(site, rel, "index.html"), "w") as fh:
            fh.write(render_autoindex(rel, subdirs, files))
    # Publish a self-contained add-repo.sh with the hook embedded for `fetch | sh`.
    write_add_repo(site, addrepo)
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
    print(f"landing page + browse.html + {len(all_dirs(args.site))} dir index(es) written; {n} package(s) indexed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
