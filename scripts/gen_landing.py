#!/usr/bin/env python3
# gen_landing.py — the pkg-site renderer (issue #2450). Builds the declared site
# tree (this repo's pkg-site/: install.sh, per-channel recipes, .nojekyll, …),
# renders the dynamic pages (landing index.html, browse.html, and a browse/<ch>/…
# view of every catalogue tree), and mirrors the result into the pkg repo's docs/ —
# write every desired file, delete everything extraneous outside the catalogue
# trees, touch nothing inside them. Run by pfBlockerNG/pkg's
# publish.yml AFTER the per-channel catalog trees are built under <site>/.
#
# It is the human-facing sibling of build-repo-portable.py: that tool emits the
# machine catalog pkg(8) fetches; this one renders a styled index over it —
# channel install cards (stable / testing / edge / nightly), a Version x ABI table
# read from each .pkg's own manifest, and a browse view that shows the package(s)
# without writing anything inside the publisher-owned catalogue trees.
#
# Four-channel catalogue model (issue #2147): every channel serves the ONE canonical
# package (pfb_pkg.CANONICAL_EMITTED_IDENTITY) from its own <channel>/<varver>/
# catalogue subtree. Channel is catalogue PLACEMENT, never a package-name suffix —
# the legacy two-repo / suffixed-package model (release/nightly repos,
# -devel/-nightly identities) is retired from this generator.
#
# Deterministic: rendering never reads a file's mtime. An artifact's Published/Last
# modified cell is its manifest `created` annotation, else the embedded build
# record's `source_date_epoch`, else an em dash — never a filesystem timestamp — so
# a second render of the same inputs is byte-identical (a NOOP republish never
# manufactures a commit).
#
# Stdlib only + the `zstd` binary (to read a .pkg's +COMPACT_MANIFEST). Dev-only
# tooling — not shipped in release archives (those contain only src/).
#
# Usage: gen_landing.py <docs-dir> <pages-base-url> --site-tree <pkg-site-dir> [--matrix <file>]
from __future__ import annotations

import argparse
import html
import json
import os
import re
import stat
import subprocess
import sys
from collections.abc import Callable, Iterable
from datetime import datetime, timezone

from pfb_pkg import CANONICAL_EMITTED_IDENTITY, pkg_version_sort_key, read_compact_manifest

# Display order for the published-packages table + the channel cards. Every channel
# owns its own <channel>/<varver>/ catalogue subtree and serves the SAME canonical
# package (issue #2147) — a package's channel is read from its catalogue PATH
# (channel_of_path), never from its name.
CH_ORDER: list[str] = ["stable", "testing", "edge", "nightly"]
_CHANNELS: frozenset[str] = frozenset(CH_ORDER)
# publish-pkg-repo.sh's PUBLISH_STAGE=stage relocates a not-yet-gated publish under
# this top-level dir (issue #2389) -- files there stay served, but this generator
# never indexes, browses, or writes it (CATALOGUE_DIRS below).
STAGING_TOP_DIR = "staging"
# Publisher-owned top-level prefixes: the renderer may never add, modify, or
# delete anything under one of these — no exceptions (issue #2450; a stray legacy
# autoindex `index.html` under one of these is an operator's one-time cleanup after
# the first publish with this script, never logic this script performs). Derived
# from CH_ORDER + STAGING_TOP_DIR so the two never drift apart.
CATALOGUE_DIRS: tuple[str, ...] = (*CH_ORDER, STAGING_TOP_DIR)
# Embed markers in a site-tree .sh file that delimit the hook placeholder body.
_HOOK_EMBED_BEGIN = "# PFB_EMBED_HOOK_BEGIN"
_HOOK_EMBED_END = "# PFB_EMBED_HOOK_END"
_HOOK_HEREDOC = "PFB_HOOK_HEREDOC"
# The source repo a .pkg is built from — base for the per-artifact commit link.
SOURCE_REPO_URL = "https://github.com/pfBlockerNG/pfBlockerNG"
MAIN_SITE_URL = "https://pfblockerng.com"
PKG_SITE_URL = "https://pkg.pfblockerng.com"

# pkg(8) catalog files that live in a catalog dir but are NOT packages — excluded
# from the human listing and the package table.
CATALOG_META = ("packagesite.pkg", "data.pkg")

# Placeholder catalog-path passed to build-repo-portable.py --print-conf for the
# manual-conf snippet on the landing page. The rc.d hook resolves the box's real
# varver at boot (arch-less; issue #1806 NO_ARCH); a hand-written conf must
# substitute a concrete value (e.g. ce-2.8).
_CONF_PLACEHOLDER_PATH = "<varver>"


def channel_of_path(rel: str) -> str | None:
    """Channel from a package's catalogue PLACEMENT: the first path segment under the
    site root, validated against the four known channels (issue #2147). The retired
    channel_of() read the package NAME's suffix instead; that model is gone — every
    channel now serves the one canonical identity, so the catalogue directory a
    package sits in IS its channel.

    Returns None for an unrecognized top-level segment (a stray future dir, or the
    retired legacy ``release/`` path) — the caller drops that package from every
    channel-scoped view. It stays reachable via the raw directory autoindex, which
    walks the tree directly and never consults this function.
    """
    seg = rel.replace(os.sep, "/").split("/", 1)[0]
    return seg if seg in _CHANNELS else None


def is_package_file(fname: str) -> bool:
    """True for a real package .pkg, False for catalog plumbing / non-.pkg."""
    return fname.endswith(".pkg") and fname not in CATALOG_META


def is_pfblockerng_package(name: str) -> bool:
    """True for the ONE canonical pfBlockerNG package identity, False for anything else.

    Every channel serves the same canonical package (issue #2147) — channel is
    catalogue placement, not a name suffix; the legacy suffixed identities
    (-devel/-nightly) no longer qualify even if found on disk (a retired-model
    leftover). Dependency packages we publish alongside it (the CE-only
    ``py311-charset-normalizer``, issue #1806) share the catalog dirs but are not
    pfBlockerNG builds — they stay browsable, never a channel row (issue #1863).
    """
    return name == CANONICAL_EMITTED_IDENTITY


def human_size(n: int) -> str:
    f = float(n)
    for unit in ("B", "KiB", "MiB", "GiB"):
        if f < 1024 or unit == "GiB":
            return f"{f:.0f} {unit}" if unit == "B" else f"{f:.1f} {unit}"
        f /= 1024
    return f"{f:.1f} GiB"


def ver_key(v: str) -> tuple[list[int], int, int]:
    """The newest-build sort key — see ``pfb_pkg.pkg_version_sort_key``.

    Must order the alpha/beta/rc prerelease stages correctly (not just fold them
    away), since testing/edge-channel rows compared here can be release-tag-shaped
    (``4.0.0.alpha.1`` etc.) as well as nightly-dated or bare edition versions.
    """
    return pkg_version_sort_key(v)


def artifact_datetime(epoch: float) -> str:
    """Format a Unix epoch as a UTC, minute-precision datetime string."""
    return datetime.fromtimestamp(epoch, tz=timezone.utc).strftime("%Y-%m-%d %H:%M UTC")


def _time_html(epoch: float) -> str:
    """Semantic UTC instant with deterministic fallback text for browser localization."""
    instant = datetime.fromtimestamp(epoch, tz=timezone.utc)
    return f'<time datetime="{instant:%Y-%m-%dT%H:%M:%SZ}">{instant:%Y-%m-%d %H:%M UTC}</time>'


def _build_record(manifest: dict) -> dict:
    """The embedded ``pfb_build_record`` annotation, parsed — ``{}`` when absent/bad.

    Release and nightly builders stamp the provenance record but nothing stamps the
    bare ``created``/``commit`` annotations (issue #2375), so the record is the one
    place a published .pkg actually carries its source epoch and SHA.
    """
    annotations = manifest.get("annotations")
    if not isinstance(annotations, dict):
        return {}
    raw = annotations.get("pfb_build_record")
    if not raw:
        return {}
    try:
        record = json.loads(raw)
    except (TypeError, ValueError):
        return {}
    return record if isinstance(record, dict) else {}


def artifact_epoch(manifest: dict) -> float | None:
    """Resolve the display epoch: ``created``, then ``source_date_epoch``, else None.

    Never a file mtime (issue #2450): a rendered page must not depend on when a
    file happened to be (re)written, or a NOOP republish would still change bytes.
    Shared by the landing table (``published_datetime``) and the browse view
    (``_display_epoch``) so the two surfaces cannot drift (issue #2401).
    """
    annotations = manifest.get("annotations")
    if not isinstance(annotations, dict):
        annotations = {}
    for epoch in (annotations.get("created"), _build_record(manifest).get("source_date_epoch")):
        if epoch is None:
            continue
        try:
            value = float(epoch)
            artifact_datetime(value)  # reject out-of-range epochs the renderer would choke on
            return value
        except (TypeError, ValueError, OverflowError, OSError):
            continue  # malformed or out-of-range — try the next source
    return None


def published_datetime(manifest: dict) -> str:
    """The artifact's creation datetime (UTC, minute precision), or "" when unknown.

    Prefer the ``created`` build annotation — the source commit's committer epoch,
    baked into the .pkg at build time — then the embedded build record's
    ``source_date_epoch``. Never a file mtime (issue #2450): the caller renders ""
    through ``_or_dash`` as an em dash, keeping the cell deterministic across every
    republish instead of showing "today".
    """
    epoch = artifact_epoch(manifest)
    return artifact_datetime(epoch) if epoch is not None else ""


def _display_epoch(path: str) -> float | None:
    """The epoch a browse-view row shows: a package's embedded creation epoch, else
    None (issue #2450: never a file mtime). Catalog plumbing and every non-package
    file always resolve to None (``is_package_file`` is the gate). An unreadable or
    unannotated package also resolves to None rather than crashing the render.
    """
    if not is_package_file(os.path.basename(path)):
        return None
    try:
        manifest = read_compact_manifest(path)
    except Exception:  # corrupt/foreign .pkg — a listing must never crash the publish
        return None
    return artifact_epoch(manifest)


def commit_sha(manifest: dict) -> str:
    """The source SHA for the Commit column — ``commit`` annotation, else the
    build record's ``source_sha``, else "" (rendered as an em dash downstream)."""
    sha = (manifest.get("annotations") or {}).get("commit", "")
    if sha:
        return sha
    record_sha = _build_record(manifest).get("source_sha", "")
    return record_sha if isinstance(record_sha, str) else ""


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


def collect_packages(site: str, read_manifest: Callable[[str], dict] | None = None) -> list[dict]:
    """Walk <site>/, returning one row per published package (channel/name/version/abi/size/rel).

    A package's channel is read from its catalogue placement — the top-level directory
    under <site> (issue #2147) — never from its name. A package sitting under an
    unrecognized top-level dir (a legacy release/nightly-suffixed tree, a stray future
    dir, ``staging/``) is not attributed to any channel and is dropped from this list
    entirely; it stays reachable via the raw catalogue tree, which this generator never
    autoindexes but never removes either.
    """
    if read_manifest is None:
        read_manifest = read_compact_manifest
    pkgs: list[dict] = []
    for dirpath, _dirs, files in os.walk(site):
        for fname in sorted(files):
            if not is_package_file(fname):
                continue
            path = os.path.join(dirpath, fname)
            rel = os.path.relpath(path, site)
            channel = channel_of_path(rel)
            if channel is None:
                continue  # unrecognized top-level dir — not a channel; browsable only
            man = read_manifest(path)
            name, ver, abi = man.get("name", ""), man.get("version", ""), man.get("abi", "")
            if not is_pfblockerng_package(name):
                continue  # a published dependency (issue #1806) — browsable, never a channel row
            deps = man.get("deps") or {}
            published_epoch = artifact_epoch(man)
            pkgs.append(
                {
                    "channel": channel,
                    "name": name,
                    "version": ver,
                    "abi": abi,
                    "size": os.path.getsize(path),
                    "published": artifact_datetime(published_epoch) if published_epoch is not None else "",
                    "published_epoch": published_epoch,
                    "commit": commit_sha(man),
                    # PHP/Python the build targets, read from its RUN_DEPENDS — the fallback
                    # for an ABI the matrix doesn't cover (the matrix value wins when joined).
                    "php": _dep_flavor(deps, ("php",)),
                    "py": _dep_flavor(deps, ("py", "python")),
                    "rel": rel,
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
:root{--stable:#2f81f7;--testing:#d29922;--edge:#a371f7;--nightly:#f85149}
.header-nav a[aria-current="page"]{color:var(--accent)}
.pkg-shell{max-width:1200px;margin:0 auto;padding:0 clamp(1rem,4vw,3rem) 6rem}
.pkg-hero{padding:clamp(3.5rem,8vw,6.5rem) 0 clamp(2.5rem,5vw,4rem);border-bottom:1px solid var(--line)}
.pkg-hero h1{max-width:900px;margin:0;font-size:clamp(2.8rem,7vw,6rem);font-weight:690;
  letter-spacing:-.055em;line-height:1}
.pkg-hero .hero-lede{max-width:720px;margin:1.35rem 0 0;color:var(--muted);font-size:clamp(1.05rem,1.5vw,1.25rem)}
.pkg-section{padding-top:clamp(2.8rem,6vw,5rem)}
.pkg-section>h2{margin:0 0 1.6rem;font-size:clamp(1.9rem,4vw,3.2rem);letter-spacing:-.04em;line-height:1.05}
.pkg-section h3{margin:2rem 0 .6rem;font-size:1.25rem}
.pkg-section h4{margin:1.4rem 0 .45rem;color:var(--muted);font-size:.82rem;letter-spacing:.1em;text-transform:uppercase}
.cards{display:grid;gap:1rem;grid-template-columns:1fr}
.card{--channel:var(--line);min-width:0;padding:clamp(1.25rem,3vw,2rem);border:1px solid var(--line);
  border-top:4px solid var(--channel);border-radius:var(--radius);background:var(--bg-elevated);
  box-shadow:0 1px 0 rgb(255 255 255 / 70%) inset}
.card h3{margin:0 0 .15rem;color:var(--ink);font-size:1.4rem;letter-spacing:-.025em}
.card .ver{margin:0 0 .75rem;color:var(--muted);font-size:.9rem}
.card .blurb,.blurb{color:var(--muted);font-size:.94rem}
.card .blurb{margin:.2rem 0 .9rem}
pre{border:1px solid var(--line);font-size:13px;line-height:1.5}
table{width:100%;border-collapse:collapse;font-size:.92rem}
.tablewrap{overflow-x:auto;-webkit-overflow-scrolling:touch}
th,td{text-align:left;padding:.65rem .75rem;border-bottom:1px solid var(--line);white-space:nowrap}
th{background:var(--bg-elevated);color:var(--muted);font-weight:720}
td.num{color:var(--muted);font-variant-numeric:tabular-nums}
.badge{display:inline-block;font-size:.72rem;padding:.05rem .45rem;border-radius:20px;
  border:1px solid;border-color:var(--channel);color:var(--ink)}
details summary{margin-top:.6rem;color:var(--muted);font-size:.87rem;cursor:pointer}
a.browse{display:inline-flex;align-items:center;min-height:46px;padding:.65rem 1rem;border:1px solid var(--ink);
  border-radius:999px;font-weight:740;text-decoration:none}
a.browse:hover{border-color:var(--accent);background:var(--accent-soft);color:var(--accent)}
table.autoindex td:first-child{white-space:normal;overflow-wrap:anywhere}
table.autoindex td.num{white-space:nowrap}
.entry-icon{display:inline-block;width:1.5em;margin-right:.25em;text-align:center}
.listing-page .pkg-shell{min-height:calc(100vh - 68px)}
.listing-hero{padding-bottom:2rem}
.listing-hero h1{font-size:clamp(2.4rem,6vw,4.8rem)}
.listing-hero p,.listing-note{color:var(--muted)}
.listing-note{margin-top:2rem;font-size:.88rem}
.empty{color:var(--muted);font-style:italic}
.card.stable{--channel:var(--stable)}
.card.testing{--channel:var(--testing)}
.card.edge{--channel:var(--edge)}
.card.nightly{--channel:var(--nightly)}
.warn{color:var(--ink);font-weight:700}
.snip{position:relative}
.snip>pre{padding-right:3.6rem}
.copy{position:absolute;top:.45rem;right:.45rem;z-index:1;
  font:600 11px/1 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif;
  color:#d2ccc7;background:#201f23;border:1px solid #575159;border-radius:6px;
  padding:.3rem .5rem;cursor:pointer}
.copy:hover{color:white;border-color:white}
.copy.copied{color:#56d364;border-color:#56d364}
@media(max-width:820px){.pkg-shell{padding-bottom:4rem}}
@media(prefers-color-scheme:dark){.card{background:rgb(27 26 30 / 72%);box-shadow:none}}
"""

_SITE_HEADER = (
    '<a class="skip-link" href="#main-content">Skip to content</a>'
    '<header class="site-header">'
    f'<a class="brand" href="{MAIN_SITE_URL}/" aria-label="pfBlockerNG home">'
    f'<img src="{MAIN_SITE_URL}/assets/logo.svg" alt="" width="34" height="34"><span>pfBlockerNG</span></a>'
    '<nav class="header-nav" aria-label="Primary">'
    f'<a href="{MAIN_SITE_URL}/guide/introduction/">Documentation</a>'
    f'<a href="{PKG_SITE_URL}/" aria-current="page">Packages</a>'
    '<a href="https://github.com/pfBlockerNG/pfBlockerNG">GitHub</a>'
    '<a href="https://github.com/pfBlockerNG">Organization</a></nav>'
    '<details class="mobile-nav"><summary aria-label="Open navigation">Menu</summary>'
    f'<nav aria-label="Mobile"><a href="{MAIN_SITE_URL}/guide/introduction/">Documentation</a>'
    f'<a href="{PKG_SITE_URL}/" aria-current="page">Packages</a>'
    '<a href="https://github.com/pfBlockerNG/pfBlockerNG">GitHub</a>'
    '<a href="https://github.com/pfBlockerNG">Organization</a></nav></details></header>'
)

_SITE_FOOTER = (
    '<footer class="site-footer"><div><strong>pfBlockerNG</strong>'
    '<span>IP and DNS blocking for pfSense</span></div><nav aria-label="Footer">'
    '<a href="https://www.reddit.com/r/pfBlockerNG/">Community</a>'
    '<a href="https://github.com/pfBlockerNG/pfBlockerNG">Repository</a>'
    '<a href="https://github.com/pfBlockerNG/pfBlockerNG/releases">Releases</a>'
    '<a href="https://github.com/pfBlockerNG/pfBlockerNG/blob/devel/LICENSE">Apache 2.0</a>'
    "</nav></footer>"
)


def _head(title: str) -> str:
    return (
        '<head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">'
        '<meta name="color-scheme" content="light dark"><meta name="theme-color" content="#151518">'
        f'<title>{_esc(title)}</title><link rel="icon" href="{MAIN_SITE_URL}/assets/logo.svg" type="image/svg+xml">'
        f'<link rel="stylesheet" href="{MAIN_SITE_URL}/assets/site.css"><style>{_CSS}</style></head>'
    )


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

_LOCAL_TIME_JS = (
    "(function(){function p(n){return String(n).padStart(2,'0');}"
    "document.querySelectorAll('time[datetime]').forEach(function(t){"
    "var d=new Date(t.dateTime);if(Number.isNaN(d.getTime()))return;"
    "t.textContent=d.getFullYear()+'-'+p(d.getMonth()+1)+'-'+p(d.getDate())+' '+p(d.getHours())+':'+p(d.getMinutes());"
    "});})();"
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


def _manual_conf_details(conf_fn: Callable[[str], str], channel: str) -> str:
    """The collapsed 'Manual conf (advanced)' disclosure shared by every channel card.

    ``channel`` is the catalogue channel (stable/testing/edge/nightly, issue #2147) —
    each owns its own repo/conf (``pfblockerng-<channel>``), unlike the legacy shared
    release repo.
    """
    return (
        "<details><summary>Manual conf (advanced)</summary>"
        '<p class="blurb">The bootstrap auto-detects this; in a hand-written conf, replace '
        "<code>&lt;varver&gt;</code> (the edition-version: <code>ce-2.8</code>, <code>plus-26.03</code>, &hellip;) "
        "with your box's value.</p>"
        f"{_copyable(_esc(conf_fn(channel)))}</details>"
    )


# Per-channel card copy: title, optional badge, and the audience/cadence prose. Fixed
# content decisions for the four-channel model, issue #2147 step A (the landing page):
# Stable = final tagged releases; Testing = nonzero-patch prereleases validating the
# next Stable; Edge = patch-zero prereleases opening the next release family; Nightly =
# untagged pinned-SHA snapshots.
_CARD_META: dict[str, dict[str, str]] = {
    "stable": {
        "title": "Stable",
        "badge": "",
        "blurb": ("Final tagged releases (<code>X.Y.Z</code>) from a maintained release line. Production use."),
    },
    "testing": {
        "title": "Testing",
        "badge": "",
        "blurb": (
            "Nonzero-patch prereleases (<code>X.Y.Z.aN</code>/<code>bN</code>/<code>rN</code>, "
            "Z &ne; 0) validating the next Stable of the current line. For users verifying an "
            "upcoming fix."
        ),
    },
    "edge": {
        "title": "Edge",
        "badge": "",
        "blurb": (
            "Patch-zero prereleases (<code>X.Y.0.aN</code>/<code>bN</code>/<code>rN</code>) opening "
            "the next release family. Earliest adopters."
        ),
    },
    "nightly": {
        "title": "Nightly",
        "badge": '<span class="badge">not for daily use</span>',
        "blurb": (
            "Untagged snapshot builds (<code>YYYYMMDDHHMMSS.&lt;7-character source SHA&gt;</code>) "
            "from a pinned source SHA. "
            'Every invocation builds. <span class="warn">Bleeding edge</span> &mdash; the '
            "only guarantee is that CI passed. Nightly versions intentionally sort above semantic "
            "versions: moving off Nightly is an explicit repository-qualified downgrade."
        ),
    },
}


def _recipe_text(site_tree: dict[str, tuple[bytes, int]], channel: str) -> str:
    """The stripped, already-{base}-substituted recipe for *channel* — the ONE-line
    piped install command a published card's copyable block shows verbatim (issue
    #2450). Raises when a PUBLISHED channel has no ``recipes/<channel>.sh`` in the
    built site tree: a missing recipe must fail the build loudly, never render a
    card with no install command.
    """
    key = f"recipes/{channel}.sh"
    entry = site_tree.get(key)
    if entry is None:
        raise ValueError(f"missing site-tree recipe for a published channel: {key}")
    data, _mode = entry
    return data.decode("utf-8").strip()


def _channel_card(
    channel: str,
    latest: dict[str, str],
    conf_fn: Callable[[str], str],
    site_tree: dict[str, tuple[bytes, int]],
) -> str:
    """One channel's install card: audience prose, and — only when published —
    the ONE-line piped installer recipe (read verbatim from the built site tree's
    ``recipes/<channel>.sh``) and a collapsed manual-conf snippet. An unpublished
    channel keeps title/badge/blurb/"not yet published" and ships no install recipe
    or conf snippet (issue #2382).
    """
    meta = _CARD_META[channel]
    badge = f" {meta['badge']}" if meta["badge"] else ""
    body = (
        f'<div class="card {channel}"><h3>{meta["title"]}{badge}</h3>'
        f'<p class="ver">{_ver_or_empty(latest, channel)}</p>'
        f'<p class="blurb">{meta["blurb"]}</p>'
    )
    if latest.get(channel):
        body += (
            '<p class="blurb">Install, upgrade, or switch to this channel (any starting state):</p>'
            f"{_copyable(_esc(_recipe_text(site_tree, channel)))}"
            f"{_manual_conf_details(conf_fn, channel)}"
        )
    return f"{body}</div>"


def _is_wildcard_abi(abi: str) -> bool:
    """True if ``abi`` is a NO_ARCH package's CPU-wildcarded ABI (e.g. "FreeBSD:16:*",
    issue #1806) — probed live against a real Netgate noarch package."""
    return isinstance(abi, str) and abi.endswith(":*")


def _abi_matches(a: str, b: str) -> bool:
    """True if two ABI strings denote the same catalog placement: exact string
    equality, OR either side is a NO_ARCH package's wildcarded ABI sharing the
    other's OS+major (the CPU/arch segment is never compared in that case;
    issue #1806 — mirrors build-repo-portable.py's ``_pkg_matches_abi``)."""
    if a == b:
        return True
    if not (_is_wildcard_abi(a) or _is_wildcard_abi(b)):
        return False
    return a.split(":")[:2] == b.split(":")[:2]


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


def _matrix_varver(pfsense_version: str, variant: str) -> str:
    """The catalog dir name (varver) a matrix entry's packages are published under.

    Mirrors build-repo-portable.py's catalog_name_from_version (major.minor only,
    pre-release suffix stripped first — it sits inside the minor field, so a bare
    split would keep it and pin the row to a varver nothing publishes, issue #1965):
      "2.7" + "CE"           -> "ce-2.7"
      "25.03"+ "Plus"        -> "plus-25.03"
      "26.07-BETA" + "Plus"  -> "plus-26.07"
    """
    major_minor = ".".join(pfsense_version.split("-")[0].split(".")[:2])
    return f"{variant.lower()}-{major_minor}"


def _row_varver(rel: str) -> str:
    """The varver dir a published package sits in, read from its site-relative path.

    ``release/plus-26.03/x.pkg`` -> ``plus-26.03`` (arch-less since issue #1806: one varver
    dir per FreeBSD major). A legacy per-ABI path yields that dir name instead, which
    matches no matrix varver — callers treat that as "no varver pin".
    """
    parts = rel.replace(os.sep, "/").split("/")
    return parts[-2] if len(parts) >= 2 else ""


def _join_matrix(rows: list[dict], matrix: list[dict] | None) -> list[tuple[str, dict]]:
    """Enrich each row with the pfSense version + PHP/Python from the matrix join.

    Returns ``(edition_key, row)`` pairs. An ABI shared by two pfSense versions yields
    one row per match (the same .pkg installs on each); an ABI with no matrix entry
    yields a single ("Other") row with a blank pfSense version + manifest-derived
    php/py, so nothing published is ever hidden. Input order is preserved.

    A NO_ARCH package's manifest ABI is CPU-wildcarded (issue #1806, e.g.
    "FreeBSD:16:*"). The matrix row's own ABI is wildcarded too (pfBlockerNG/pkg
    emits ``FreeBSD:<major>:*`` since `arch` was retired), so the exact-string
    index normally hits; a row it misses — a legacy concrete-ABI asset, or a
    matrix that still records one — falls back to an OS+major scan across every
    matrix entry (``_abi_matches``), joining EVERY row of that major instead of
    dropping to "Other". Both paths yield the same rows.

    An ABI match alone over-joins when two pfSense versions share it: the catalog is
    published per varver, so each varver dir holds its OWN copy of the .pkg, and
    broadcasting every copy to every matching entry cross-products them (issue #1863 —
    a 26.03 row linking the plus-26.07 file and vice versa). When the row's path names a
    varver that some matched entry is published under, that entry wins; a path naming no
    known varver (a legacy per-ABI dir) keeps the broadcast, so nothing is ever hidden.

    A pfSense minor is then listed ONCE per channel and package version, however many
    matrix entries it has: those entries enumerate build flavors (arch, FreeBSD, PHP,
    Python), while the arch-less catalog (issue #1806) serves one file per minor. The
    first entry of a minor supplies the displayed flavors. The dedup is per published
    FILE, so a legacy per-ABI layout — which publishes one file per arch and pins to no
    varver — still lists each of them; only flavor duplicates of one file collapse.
    """
    idx = matrix_index(matrix)
    out: list[tuple[str, dict]] = []
    seen: set[tuple[str, str, str, str, str]] = set()  # (edition, minor, channel, version, file)
    for r in rows:
        entries = idx.get(r["abi"], [])
        if not entries and _is_wildcard_abi(r["abi"]):
            entries = [e for e in (matrix or []) if _abi_matches(e.get("abi", ""), r["abi"])]
        vv = _row_varver(r["rel"])
        pinned = [e for e in entries if _matrix_varver(e.get("pfsense_version", ""), e.get("variant", "")) == vv]
        entries = pinned or entries
        if entries:
            for e in entries:
                ekey = _edition_key(e.get("variant", ""))
                key = (ekey, e.get("pfsense_version", ""), r["channel"], r["version"], r["rel"])
                if key in seen:
                    continue
                seen.add(key)
                row = dict(r)
                row["pfsense_version"] = e.get("pfsense_version", "")
                row["php"] = e.get("php_version") or e.get("php") or r.get("php", "")
                row["py"] = _dotted_ver(e.get("py_flavor", "")) or r.get("py", "")
                out.append((ekey, row))
        else:
            row = dict(r)
            row["pfsense_version"] = ""
            out.append(("Other", row))
    return out


def sort_table_rows(rows: list[dict]) -> None:
    """Order one table's rows in place: the display rule every packages table follows.

    pfBlockerNG version desc, then pfSense version desc, then channel (issue #1863). Both
    versions compare number-aware (``ver_key``), never as strings. Editions are already
    separate tables ordered CE before Plus (``_order_edition_keys``), which is where the
    edition rank of the rule lives. Written as stable passes, least significant first.
    """
    rows.sort(key=lambda p: CH_ORDER.index(p["channel"]))
    rows.sort(key=lambda p: ver_key(p.get("pfsense_version", "")), reverse=True)
    rows.sort(key=lambda p: ver_key(p["version"]), reverse=True)


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
    nothing published is ever hidden. Editions sort CE, then Plus, then the rest; rows
    within each follow the shared table order (``sort_table_rows``).
    """
    sections: dict[str, list[dict]] = {}
    for ekey, row in _join_matrix(build_table(pkgs), matrix):
        sections.setdefault(ekey, []).append(row)
    out: list[tuple[str, list[dict]]] = []
    for k in _order_edition_keys(sections):
        rows = sections[k]
        sort_table_rows(rows)
        out.append((k, rows))
    return out


def _versions_table_html(rows: list[dict], *, with_channel: bool) -> str:
    """One versions table for a single edition. Columns:
    pfSense [| Channel] | Version | ABI | PHP | Python | Published | Commit | Size.

    The Channel column appears only where several channels can occur in one table (the
    per-edition and older-releases tables); nightlies and EOL omit it (every row
    there is, by construction, the same channel)."""
    channel_th = "<th>Channel</th>" if with_channel else ""
    body = "".join(_row_html(r, with_channel=with_channel) for r in rows)
    # overflow-x wrapper: a narrow (mobile) viewport scrolls the table, not the page.
    return (
        '<div class="tablewrap"><table><thead><tr>'
        f"<th>pfSense</th>{channel_th}<th>Version</th><th>ABI</th>"
        "<th>PHP</th><th>Python</th><th>Published</th><th>Commit</th><th>Size</th>"
        f"</tr></thead><tbody>{body}</tbody></table></div>"
    )


def _row_html(r: dict, *, with_channel: bool) -> str:
    channel_td = f"<td>{_esc(r['channel'])}</td>" if with_channel else ""
    published_epoch = r.get("published_epoch")
    published = _time_html(published_epoch) if published_epoch is not None else _or_dash(r.get("published", ""))
    return (
        f"<tr><td>{_or_dash(r.get('pfsense_version', ''))}</td>{channel_td}"
        f'<td><a href="./{_esc(r["rel"])}">{_esc(r["version"])}</a></td>'
        f"<td><code>{_esc(r['abi'])}</code></td>"
        f'<td class="num">{_or_dash(r.get("php", ""))}</td>'
        f'<td class="num">{_or_dash(r.get("py", ""))}</td>'
        f'<td class="num">{published}</td>'
        f"<td>{commit_cell(r.get('commit', ''))}</td>"
        f'<td class="num">{_esc(human_size(r["size"]))}</td></tr>'
    )


def _packages_html(pkgs: list[dict], matrix: list[dict] | None) -> str:
    """Published packages by Stable/Testing/Edge/Nightly, then pfSense edition."""
    sections = [(k, rows) for k, rows in build_edition_sections(pkgs, matrix) if rows]
    if not sections:
        return '<p class="empty">No packages published yet.</p>'
    older_releases_by_edition = _older_releases_by_edition(pkgs, matrix)
    older_nightlies_by_edition = _older_nightlies_by_edition(pkgs, matrix)
    out: list[str] = []
    for channel in CH_ORDER:
        channel_body: list[str] = []
        for edition, rows in sections:
            current = [row for row in rows if row["channel"] == channel]
            older_rows = (
                older_nightlies_by_edition.get(edition, [])
                if channel == "nightly"
                else older_releases_by_edition.get(edition, [])
            )
            older = [row for row in older_rows if row["channel"] == channel]
            if not current and not older:
                continue
            channel_body.append(f"<h4>{_esc(EDITION_LABELS.get(edition, edition))}</h4>")
            if current:
                channel_body.append(_versions_table_html(current, with_channel=False))
            channel_body.append(
                _older_nightlies_details(older) if channel == "nightly" else _older_releases_details(older)
            )
        if channel_body:
            out.append(f"<h3>{_esc(channel.capitalize())}</h3>{''.join(channel_body)}")
    return "".join(out)


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


def _older_nightlies_by_edition(pkgs: list[dict], matrix: list[dict] | None) -> dict[str, list[dict]]:
    """The retained older nightlies grouped by edition key (matrix-joined by ABI), so each
    edition's disclosure folds in directly under that edition's table. Empty when none.

    Retention keeps several nightly versions, so an edition lists one row per retained
    version per pfSense version it was built for, in the shared table order (issue #1863).
    """
    by_edition: dict[str, list[dict]] = {}
    for ekey, row in _join_matrix(older_nightlies(pkgs), matrix):
        by_edition.setdefault(ekey, []).append(row)
    for rows in by_edition.values():
        sort_table_rows(rows)
    return by_edition


def _older_nightlies_details(rows: list[dict]) -> str:
    """One edition's retained older nightlies, folded into a collapsed disclosure; "" when
    that edition has none. Same columns as the edition table, minus Channel (all nightlies)."""
    if not rows:
        return ""
    return (
        f"<details><summary>Older nightlies ({len(rows)})</summary>"
        f"{_versions_table_html(rows, with_channel=False)}</details>"
    )


def older_releases(pkgs: list[dict]) -> list[dict]:
    """The retained release-channel builds (every channel but nightly) OTHER than the
    newest per channel.

    The per-edition tables surface only the latest version of each channel (the
    "install now" view); release retention (ADR-27, catalogue_assembly.DEFAULT_RETENTION_KEEP)
    keeps several older releases in the catalog, surfaced here for diagnostics and
    reproducibility. Nightly has its own retention/disclosure (older_nightlies) — its
    dated versions aren't "releases". Sorted newest-first within each channel, then by
    ABI. Empty when no older versions are retained.
    """
    latest = latest_versions(pkgs)
    rows = [p for p in pkgs if p["channel"] != "nightly" and p["version"] != latest.get(p["channel"])]
    rows.sort(key=lambda p: p["abi"])
    rows.sort(key=lambda p: (CH_ORDER.index(p["channel"]), ver_key(p["version"])), reverse=True)
    return rows


def _older_releases_by_edition(pkgs: list[dict], matrix: list[dict] | None) -> dict[str, list[dict]]:
    """The retained older releases grouped by edition key (matrix-joined by ABI), so each
    edition's disclosure folds in directly under that edition's table. Empty when none.

    Rows follow the shared table order (issue #1863): pfBlockerNG version desc, then
    pfSense version desc, then channel.
    """
    by_edition: dict[str, list[dict]] = {}
    for ekey, row in _join_matrix(older_releases(pkgs), matrix):
        by_edition.setdefault(ekey, []).append(row)
    for rows in by_edition.values():
        sort_table_rows(rows)
    return by_edition


def _older_releases_details(rows: list[dict]) -> str:
    """One edition's retained older releases, folded into a collapsed disclosure; "" when
    that channel has none. The surrounding heading identifies the channel."""
    if not rows:
        return ""
    return (
        f"<details><summary>Older releases ({len(rows)})</summary>"
        f"{_versions_table_html(rows, with_channel=False)}</details>"
    )


def eol_versions(pkgs: list[dict], matrix: list[dict] | None) -> list[tuple[str, str, dict]]:
    """The last-served .pkg for each EOL (route-only) pfSense version.

    A matrix entry is EOL iff ``role == "route-only"``. For each such entry, this function
    finds the newest .pkg version (by ver_key) served for that varver, enriched with the
    matrix-provided pfSense version + PHP/Python.

    Four-channel model (issue #2147): a varver's pool spans EVERY channel that still
    serves it — e.g. Stable and Testing can both retain a build for a now-EOL pfSense
    line — so the newest served build wins across the whole combined pool, not just one
    channel's slice. This also naturally dedupes: the EOL table is edition-keyed, not
    channel-keyed, and was always meant to show one "last served" row per pfSense
    version regardless of which channel(s) still carry it.

    Returns ``(edition_key, pfsense_version, row)`` triples — one per (EOL pfSense version,
    ABI) combination — in deterministic order: CE before Plus, older pfSense version before
    newer within each edition, ABI alphabetically within each version.
    """
    eol_entries = [e for e in (matrix or []) if e.get("role") == "route-only"]
    if not eol_entries:
        return []

    # Group pkgs by varver (the second path segment: <channel>/<varver>/...), so each EOL
    # varver's pool is isolated across every channel that still serves it. Arch-less
    # (issue #1806: NO_ARCH packages, one varver directory serves every arch of its
    # FreeBSD major). Always forward-slash; os.path.relpath normalises to the OS
    # separator, so normalise here too. A path whose top segment isn't a known channel
    # (the retired ``release/`` prefix, a stray dir) contributes nothing — it was never
    # attributed to a channel in the first place (collect_packages already drops it).
    varver_pkgs: dict[str, list[dict]] = {}
    for p in pkgs:
        rel = p["rel"].replace(os.sep, "/")
        parts = rel.split("/")
        if len(parts) >= 2 and parts[0] in _CHANNELS:
            vv = parts[1]
            varver_pkgs.setdefault(vv, []).append(p)

    # Group the entries by varver: a varver is emitted at most ONCE (issue #1863), since its
    # several matrix entries enumerate build flavors (arch, FreeBSD, PHP, Python) of ONE
    # frozen catalog. They therefore share one pool — taking the newest from a single
    # entry's slice would report a stale last-served version.
    by_varver: dict[str, list[dict]] = {}
    for e in eol_entries:
        by_varver.setdefault(_matrix_varver(e.get("pfsense_version", ""), e.get("variant", "")), []).append(e)

    out: list[tuple[str, str, dict]] = []
    for varver, entries in by_varver.items():
        # Matched via _abi_matches (OS+major, issue #1806) rather than string equality:
        # the served .pkg and the matrix entry may disagree on the CPU segment (a legacy
        # concrete-ABI asset against today's wildcarded matrix, or the reverse).
        served = varver_pkgs.get(varver, [])
        pool = [p for p in served if any(_abi_matches(p["abi"], e.get("abi", "")) for e in entries)]
        if not pool:
            continue  # nothing served for this varver — skip silently

        # The displayed flavors come from an entry that actually matches a served file, so
        # an unserved flavor never speaks for the varver.
        entry = next(e for e in entries if any(_abi_matches(p["abi"], e.get("abi", "")) for p in pool))
        version = entry.get("pfsense_version", "")

        # Newest served version = highest ver_key.
        best = max(pool, key=lambda p: ver_key(p["version"]))
        row = dict(best)
        row["pfsense_version"] = version
        row["php"] = entry.get("php_version") or entry.get("php", "")
        row["py"] = _dotted_ver(entry.get("py_flavor", "")) or entry.get("py", "")
        out.append((_edition_key(entry.get("variant", "")), version, row))

    # Sort: edition order (CE < Plus < Other) — each edition is its own table — then the
    # shared table order within it: pfBlockerNG version desc, then pfSense version desc
    # (issue #1863). Stable passes, least significant first.
    edition_rank = {k: i for i, k in enumerate(EDITION_ORDER)}
    out.sort(key=lambda t: ver_key(t[1]), reverse=True)
    out.sort(key=lambda t: ver_key(t[2]["version"]), reverse=True)
    out.sort(key=lambda t: edition_rank.get(t[0], len(EDITION_ORDER)))
    return out


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

    body = "".join(
        f"<h3>{_esc(EDITION_LABELS.get(k, k))}</h3>{_versions_table_html(by_edition[k], with_channel=False)}"
        for k in ordered_keys
    )
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
    site_tree: dict[str, tuple[bytes, int]],
    matrix: list[dict] | None = None,
) -> str:
    """Render the root landing page. ``site_tree`` is the BUILT site tree (issue
    #2450) — the source of each published channel's recipe text."""
    latest = latest_versions(pkgs)
    cards = "".join(_channel_card(ch, latest, conf_fn, site_tree) for ch in CH_ORDER)
    eol_block = _eol_versions_html(pkgs, matrix)
    eol_section = f'<section class="pkg-section">{eol_block}</section>' if eol_block else ""
    return (
        f'<!doctype html><html lang="en">{_head("pfBlockerNG — self-hosted pkg repository")}<body>'
        f'{_SITE_HEADER}<main id="main-content" class="pkg-shell">'
        '<section class="pkg-hero"><p class="eyebrow">Official package repository</p>'
        '<h1>Install pfBlockerNG.</h1><p class="hero-lede">Self-hosted FreeBSD <code>pkg</code> '
        "repository for pfSense&nbsp;CE &amp; pfSense&nbsp;Plus. Pick a channel and run its command "
        "on your firewall as <code>root</code>.</p></section>"
        f'<section class="pkg-section"><h2>Channels</h2><div class="cards">{cards}</div></section>'
        f'<section class="pkg-section"><h2>Published packages</h2>{_packages_html(pkgs, matrix)}</section>'
        f"{eol_section}"
        '<section class="pkg-section"><h2>Repository files</h2>'
        '<p class="blurb">Browse every channel, version and ABI &mdash; and the raw pkg(8) catalogs your '
        "firewall fetches &mdash; in a directory-style listing.</p>"
        '<p><a class="browse" href="./browse.html">&#128193; Browse the repository &rarr;</a></p></section>'
        f"</main>{_SITE_FOOTER}<script>{_LOCAL_TIME_JS}{_COPY_JS}</script></body></html>\n"
    )


def _epoch_cell(epoch: float | None) -> str:
    """The Last-modified cell for an optional epoch — an em dash when absent (issue
    #2450: never a file mtime)."""
    return _time_html(epoch) if epoch is not None else _or_dash("")


def _render_listing_html(title: str, home_href: str, rows: list[str]) -> str:
    """The shared directory-listing page shell — the landing/browse chrome around a
    Name | Last modified | Size table, used by both browse.html and every
    browse/<ch>/… page."""
    return (
        f'<!doctype html><html lang="en">{_head(f"pfBlockerNG pkg — Index of {title}")}<body class="listing-page">'
        f'{_SITE_HEADER}<main id="main-content" class="pkg-shell">'
        f'<section class="pkg-hero listing-hero"><p class="eyebrow">Repository files</p>'
        f'<h1>Index of {_esc(title)}</h1><p><a href="{_esc(home_href)}">'
        "&larr; pfBlockerNG repository home</a></p></section>"
        '<section class="pkg-section"><div class="tablewrap"><table class="autoindex"><thead><tr>'
        "<th>Name</th><th>Last modified</th><th>Size</th></tr></thead>"
        f"<tbody>{''.join(rows)}</tbody></table></div>"
        '<p class="listing-note">Directory listing of the self-hosted pfBlockerNG pkg repository. '
        "pkg(8) fetches the catalog files (<code>meta.conf</code>, <code>packagesite.pkg</code>, …) directly.</p>"
        f"</section></main>{_SITE_FOOTER}<script>{_LOCAL_TIME_JS}</script></body></html>\n"
    )


def _entry_link(href: str, label: str, *, directory: bool) -> str:
    icon = "&#128193;" if directory else "&#128196;"
    return f'<a href="{_esc(href)}"><span class="entry-icon" aria-hidden="true">{icon}</span>{_esc(label)}</a>'


def _root_files(built: dict[str, tuple[bytes, int]]) -> list[str]:
    """The site-tree's own root-level file names, sorted; the generated pages are
    hidden (not repository content). Sourced from ``built`` — never a disk listing
    — since sync_site's own contract makes the site tree's root files the ONLY
    things that can ever survive at the docs root besides a catalogue dir (issue
    #2450): reading disk here would see this run's write only after it happens,
    an ordering hazard that broke determinism (a rendered page must reflect the
    tree being written THIS run, not whatever a previous run left behind).
    """
    hidden = {"index.html", "browse.html", ".nojekyll", "CNAME"}
    return sorted(name for name in built if "/" not in name and name not in hidden)


def render_browse_root(docs: str, built: dict[str, tuple[bytes, int]]) -> str:
    """docs/browse.html — the top-level entry point: one row per present catalogue
    channel (CH_ORDER order; ``staging`` is never listed, issue #2389) linking into
    its own browse/<ch>/ page, then every root-level site-tree file linking directly.
    """
    rows: list[str] = []
    for ch in CH_ORDER:
        if os.path.isdir(os.path.join(docs, ch)):
            rows.append(
                f"<tr><td>{_entry_link(f'./browse/{ch}/', f'{ch}/', directory=True)}</td>"
                '<td class="num">&mdash;</td><td class="num">&mdash;</td></tr>'
            )
    for name in _root_files(built):
        data, _mode = built[name]
        rows.append(
            f"<tr><td>{_entry_link(f'./{name}', name, directory=False)}</td>"
            f'<td class="num">{_epoch_cell(None)}</td>'
            f'<td class="num">{_esc(human_size(len(data)))}</td></tr>'
        )
    return _render_listing_html("/", "./", rows)


def _catalogue_subdirs(docs: str, channel: str) -> list[str]:
    """Every docs-relative dir at or below <docs>/<channel> — the channel root
    itself plus each directory nested under it, sorted, "/"-separated."""
    root = os.path.join(docs, channel)
    out = [channel]
    for dirpath, dirs, _files in os.walk(root):
        for d in dirs:
            rel = os.path.relpath(os.path.join(dirpath, d), docs).replace(os.sep, "/")
            out.append(rel)
    return sorted(out)


def _render_catalogue_browse_page(docs: str, full_rel: str) -> str:
    """One ``browse/<full_rel>/index.html`` page — ``full_rel`` is ``"<channel>"``
    or ``"<channel>/<sub>/…"``, a real directory under docs/. Subdirs link within
    the browse mirror (``./<name>/``); files link OUT into the real catalogue tree
    via a climb-to-root-then-descend relative path, since the browse tree and the
    catalogue tree are siblings under docs/, not the same directory (issue #2450).
    """
    src_dir = os.path.join(docs, *full_rel.split("/"))
    depth = full_rel.count("/") + 2  # hops from browse/<full_rel>/ up to the docs root
    climb = "../" * depth
    is_channel_root = "/" not in full_rel

    rows: list[str] = []
    parent_href = f"{climb}browse.html" if is_channel_root else "../"
    rows.append(
        f"<tr><td>{_entry_link(parent_href, '../', directory=True)}</td>"
        '<td class="num">&mdash;</td><td class="num">Parent Directory</td></tr>'
    )

    subdirs: list[str] = []
    files: list[str] = []
    for name in sorted(os.listdir(src_dir)):
        if name == "index.html":
            continue  # a leftover autoindex is never repository content (issue #2450)
        (subdirs if os.path.isdir(os.path.join(src_dir, name)) else files).append(name)

    for name in subdirs:
        rows.append(
            f"<tr><td>{_entry_link(f'./{name}/', f'{name}/', directory=True)}</td>"
            '<td class="num">&mdash;</td><td class="num">&mdash;</td></tr>'
        )
    for name in files:
        path = os.path.join(src_dir, name)
        target = f"{climb}{full_rel}/{name}"
        rows.append(
            f"<tr><td>{_entry_link(target, name, directory=False)}</td>"
            f'<td class="num">{_epoch_cell(_display_epoch(path))}</td>'
            f'<td class="num">{_esc(human_size(os.path.getsize(path)))}</td></tr>'
        )
    return _render_listing_html(f"/{full_rel}", climb, rows)


# The exact hardcoded PFB_BASE_URL default line install.sh's repository copy
# carries — replaced with the SITE's own base at render time (issues #2416 /
# B3/F3) so a fork or staged prefix ships an installer that resolves against
# itself without requiring every user to override PFB_BASE_URL by hand.
_BASE_URL_DEFAULT_LINE = 'PFB_BASE_URL="${PFB_BASE_URL:-http://${PFB_REPO_HOST}}"'
_REPO_HOST_DEFAULT_LINE = 'PFB_REPO_HOST="${PFB_REPO_HOST:-pkg.pfblockerng.com}"'


def _shell_single_quote(value: str) -> str:
    """POSIX single-quote *value* as inert shell DATA: ``'`` becomes ``'\\''``.

    A single-quoted literal undergoes no expansion at all — the one safe way to
    land an externally-configured string (a base URL) inside a shell script's own
    source text without risking it being read back as executable syntax.
    """
    return "'" + value.replace("'", "'\\''") + "'"


# The site is browsed over HTTPS; the CATALOGUE is fetched over plain HTTP, because pkg
# on pfSense Plus runs against a Netgate-pinned CA bundle nothing we ship can widen
# (issue #2675). The published installer therefore carries the base its confs should
# name — no generator and no box rewrites a scheme — while the host it prints for the
# bootstrap `fetch | sh` stays HTTPS: a script piped to a root shell has no signature.
def _catalogue_base(base: str) -> str:
    return "http://" + base[len("https://") :] if base.startswith("https://") else base


def _repo_host(base: str) -> str:
    """The bare host of *base*, for the installer's own published-at URL."""
    without_scheme = base.split("://", 1)[-1]
    return without_scheme.split("/", 1)[0]


def _bake_base_url(script_text: str, base: str) -> str:
    """Replace install.sh's hardcoded ``PFB_BASE_URL`` default with *base*.

    Only called by ``build_site_tree`` when the default-URL line occurs at least
    once; raises if it occurs MORE than once, so a doubled line still fails the
    site build loudly. A script carrying ZERO occurrences is never routed here at
    all — ``build_site_tree`` leaves it unbaked, silently — so the invariant that
    the repository's own ``scripts/install.sh`` always carries this line EXACTLY
    once is pinned by the test suite
    (``test_scripts_install_sh_carries_the_bake_line_and_both_embed_markers``),
    not enforced by this function.

    *base* is baked in as a single-quoted ``PFB_DEFAULT_BASE_URL`` literal, then
    referenced through a second, unquoted ``${PFB_BASE_URL:-${PFB_DEFAULT_BASE_URL}}``
    line — never interpolated directly inside the ``${:-...}`` word: dash keeps a
    quote character embedded THERE literal instead of removing it (``x=; echo
    "${x:-'a b'}"`` prints ``'a b'``, quotes and all), so quoting inline would not
    stop expansion of a base containing ``$(...)`` or backticks. Splitting the
    literal into its own single-quoted assignment first closes that: single quotes
    suppress all expansion at assignment time, and the ``${VAR:-...}`` reference
    that follows just copies the already-safe value, never re-parsing it.
    """
    count = script_text.count(_BASE_URL_DEFAULT_LINE)
    if count != 1:
        raise ValueError(
            f"expected exactly one PFB_BASE_URL default line in install.sh, found {count}: {_BASE_URL_DEFAULT_LINE!r}"
        )
    host_count = script_text.count(_REPO_HOST_DEFAULT_LINE)
    if host_count != 1:
        raise ValueError(f"expected exactly one PFB_REPO_HOST default line in install.sh, found {host_count}")
    script_text = script_text.replace(
        _REPO_HOST_DEFAULT_LINE,
        f'PFB_REPO_HOST="${{PFB_REPO_HOST:-{_repo_host(base)}}}"',
        1,
    )
    base = _catalogue_base(base)
    replacement = (
        f'PFB_DEFAULT_BASE_URL={_shell_single_quote(base)}\nPFB_BASE_URL="${{PFB_BASE_URL:-${{PFB_DEFAULT_BASE_URL}}}}"'
    )
    return script_text.replace(_BASE_URL_DEFAULT_LINE, replacement, 1)


def _embed_hook(script_text: str, hook_text: str) -> str:
    """Splice *hook_text* into *script_text* between the PFB_EMBED_HOOK markers.

    The stub body (everything between the BEGIN and END marker lines, inclusive) is
    replaced with a single-quoted heredoc that prints the hook verbatim — no variable
    or command expansion in the emitted content, regardless of what the hook contains.
    The resulting script is self-contained and safe to pipe into ``sh``. Used by
    ``build_site_tree`` on every ``.sh`` site-tree file carrying the markers (today,
    only install.sh) — the PFB_EMBED_HOOK markers live in the script's own text.
    """
    lines = script_text.splitlines(keepends=True)
    begin_idx = next(
        (i for i, ln in enumerate(lines) if _HOOK_EMBED_BEGIN in ln),
        None,
    )
    end_idx = next(
        (i for i, ln in enumerate(lines) if _HOOK_EMBED_END in ln),
        None,
    )
    if begin_idx is None or end_idx is None or begin_idx >= end_idx:
        raise ValueError(f"script is missing the embed markers ({_HOOK_EMBED_BEGIN!r} / {_HOOK_EMBED_END!r})")
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


def build_site_tree(tree: str, base: str) -> dict[str, tuple[bytes, int]]:
    """Build the desired site-tree files from the declared source ``tree`` (this
    repo's ``pkg-site/``, issue #2450): every regular file under it (symlinks
    followed, dotfiles included), keyed by its "/"-relative path.

    A ``.sh`` file gets ``_bake_base_url`` applied when install.sh's default-URL
    line occurs (raising on more than one occurrence — a drifted script), then
    ``_embed_hook`` applied when the hook markers occur — today only ``install.sh``
    matches either. Every file whose bytes decode as UTF-8 then gets its literal
    ``{base}`` token substituted with *base* (the site's channel recipes use it;
    nothing else in the tree carries the token, so this is a no-op elsewhere).
    The source file's permission bits (the exec bit) are preserved.
    """
    repo_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    hook_path = os.path.join(repo_root, "src", "usr", "local", "etc", "rc.d", "pfblockerng_repo_generate.sh")
    out: dict[str, tuple[bytes, int]] = {}
    for dirpath, _dirs, files in os.walk(tree, followlinks=True):
        for fname in files:
            path = os.path.join(dirpath, fname)
            rel = os.path.relpath(path, tree).replace(os.sep, "/")
            with open(path, "rb") as fh:
                data = fh.read()
            mode = stat.S_IMODE(os.stat(path).st_mode)
            if fname.endswith(".sh"):
                text = data.decode("utf-8")
                if text.count(_BASE_URL_DEFAULT_LINE) >= 1:
                    text = _bake_base_url(text, base)
                if _HOOK_EMBED_BEGIN in text or _HOOK_EMBED_END in text:
                    with open(hook_path) as hf:
                        hook_text = hf.read()
                    text = _embed_hook(text, hook_text)
                data = text.encode("utf-8")
            try:
                text = data.decode("utf-8")
            except UnicodeDecodeError:
                pass  # binary file — copied verbatim, no {base} substitution possible
            else:
                data = text.replace("{base}", base).encode("utf-8")
            out[rel] = (data, mode)
    return out


def _catalogue_prefix(rel: str) -> str | None:
    """The ``CATALOGUE_DIRS`` entry *rel* sits under, or None."""
    seg = rel.split("/", 1)[0]
    return seg if seg in CATALOGUE_DIRS else None


def _prune_empty_dirs(root: str) -> None:
    """Remove every directory under *root* left empty by ``sync_site``'s deletions
    (never *root* itself, never a catalogue-owned tree). Bottom-up, re-checking
    live directory contents at each step so a cascade (a leaf's removal emptying
    its parent) prunes fully."""
    for dirpath, _dirs, _files in os.walk(root, topdown=False):
        if dirpath == root:
            continue
        rel = os.path.relpath(dirpath, root).replace(os.sep, "/")
        if _catalogue_prefix(rel) is not None:
            continue  # catalogue-owned — never touched, no exceptions
        if not os.listdir(dirpath):
            os.rmdir(dirpath)


def _symlinked_component(docs: str, rel: str) -> str | None:
    """The first path, walking from *docs* down to ``docs/<rel>`` inclusive, that is
    a symlink — or None if none is. Used by ``sync_site`` to refuse writing THROUGH
    a symlink (a directory component or the leaf itself) planted inside docs/, which
    would otherwise let a write escape the tree entirely."""
    current = docs
    for part in rel.split("/"):
        current = os.path.join(current, part)
        if os.path.islink(current):
            return current
    return None


def sync_site(docs: str, desired: dict[str, tuple[bytes, int]]) -> tuple[list[str], list[str]]:
    """Mirror *desired* into *docs*: write every desired file, then delete whatever
    under docs is neither under a ``CATALOGUE_DIRS`` prefix nor in *desired* (issue
    #2450). A catalogue-prefixed path is never added, modified, or deleted here —
    strictly, with no exception: the assert below makes the renderer unable to even
    WRITE one from *desired* in the first place. A one-time cleanup of a legacy
    autoindex leftover under a catalogue dir (from the generator this replaces) is
    an operator task run once after the first successful publish with this script,
    never logic this script carries forward. Every desired path is also validated
    BEFORE the first write — a `..` segment or a leading `/`, or a symlink sitting
    anywhere between docs/ and the write target (leaf or intermediate directory) —
    so no partial write can ever land, and none can escape docs/.
    Returns ``(written, deleted)``, each the sorted "/"-relative paths.
    """
    for rel in desired:
        if _catalogue_prefix(rel) is not None:
            raise ValueError(f"desired site path {rel!r} sits under a catalogue-owned prefix — refusing to write")
        if rel.startswith("/") or any(segment == ".." for segment in rel.split("/")):
            raise ValueError(f"desired site path {rel!r} is not a safe relative path — refusing to write")
        symlinked = _symlinked_component(docs, rel)
        if symlinked is not None:
            raise ValueError(
                f"desired site path {rel!r} resolves through a symlink at {symlinked!r} — refusing to write"
            )

    for rel, (data, mode) in desired.items():
        out_path = os.path.join(docs, *rel.split("/"))
        os.makedirs(os.path.dirname(out_path), exist_ok=True)
        with open(out_path, "wb") as fh:
            fh.write(data)
        os.chmod(out_path, mode)

    deleted: list[str] = []
    for dirpath, _dirs, files in os.walk(docs, followlinks=False):
        rel_dir = os.path.relpath(dirpath, docs).replace(os.sep, "/")
        rel_dir = "" if rel_dir == "." else rel_dir
        for fname in files:
            full = os.path.join(dirpath, fname)
            if os.path.islink(full):
                continue  # never follow/touch a symlink inside docs
            rel = f"{rel_dir}/{fname}" if rel_dir else fname
            if _catalogue_prefix(rel) is not None:
                continue  # catalogue-owned — never touched, no exceptions
            if rel not in desired:
                os.remove(full)
                deleted.append(rel)

    _prune_empty_dirs(docs)
    return sorted(desired), sorted(deleted)


def _conf_via_portable(base: str, channel: str) -> str:
    """The manual-conf snippet the landing page shows: build-repo-portable.py's own
    ``--print-conf`` (it supports ``--channel`` — every one of the four channels
    has its own repo/conf, ``pfblockerng-<channel>``). ``--catalog-path`` takes a
    literal placeholder because the landing page shows a generic snippet — the
    rc.d hook resolves the box's real varver at boot (see _CONF_PLACEHOLDER_PATH).
    """
    scripts_dir = os.path.dirname(os.path.abspath(__file__))
    build_repo_portable = os.path.join(scripts_dir, "build-repo-portable.py")
    out = subprocess.run(
        [
            sys.executable,
            build_repo_portable,
            "--print-conf",
            "--base-url",
            base,
            "--catalog-path",
            _CONF_PLACEHOLDER_PATH,
            "--channel",
            channel,
        ],
        capture_output=True,
        text=True,
        check=True,
    )
    return out.stdout.rstrip("\n")


def write_site(site: str, base: str, site_tree: str, matrix: list[dict] | None = None) -> int:
    """Render the pkg-site tree onto *site* (docs/) and mirror it there (issue
    #2450): build the site tree from *site_tree*, collect the published packages,
    render the landing page + the browse view (root + every catalogue dir, never
    writing inside a catalogue tree), then ``sync_site``. Returns the count of
    pfBlockerNG packages indexed — published dependencies are browsable but not
    ours to count (issue #1863).
    """
    base = base.rstrip("/")
    pkgs = collect_packages(site)
    built = build_site_tree(site_tree, base)

    def conf_fn(channel: str) -> str:
        return _conf_via_portable(base, channel)

    desired = dict(built)
    # A rendered page always wins over a same-named site-tree file (H4, issue #2450).
    desired["index.html"] = (render_page(base, pkgs, conf_fn, built, matrix).encode(), 0o644)
    desired["browse.html"] = (render_browse_root(site, built).encode(), 0o644)
    for ch in CH_ORDER:
        if not os.path.isdir(os.path.join(site, ch)):
            continue
        for full_rel in _catalogue_subdirs(site, ch):
            page = _render_catalogue_browse_page(site, full_rel)
            desired[f"browse/{full_rel}/index.html"] = (page.encode(), 0o644)

    written, deleted = sync_site(site, desired)
    print(
        f"pkg-site: {len(written)} file(s) written, {len(deleted)} removed; {len(pkgs)} pfBlockerNG package(s) indexed"
    )
    return len(pkgs)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Render the pkg-site tree onto the pkg repo's docs/ and mirror it there.")
    ap.add_argument("site", help="the docs/ tree to render into (the built catalog trees already live there)")
    ap.add_argument("base_url", help="the package repository base URL, e.g. https://pkg.pfblockerng.com")
    ap.add_argument("--site-tree", required=True, help="the pkg-site/ source tree to render (this repo's pkg-site/)")
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
    write_site(args.site, args.base_url, args.site_tree, matrix)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
