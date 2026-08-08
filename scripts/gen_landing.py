#!/usr/bin/env python3
# gen_landing.py — generate the human-navigable landing page + per-directory
# indexes for the self-hosted pkg repository (ADR-17). Run by pfBlockerNG/pkg's
# publish.yml AFTER the per-channel catalog trees are built under <site>/.
#
# It is the human-facing sibling of build-repo-portable.py: that tool emits the
# machine catalog pkg(8) fetches; this one renders a styled index over it —
# channel install cards (stable / testing / edge / nightly), a Version x ABI table
# read from each .pkg's own manifest, and a clean per-directory listing that shows
# the package(s) but not the pkg(8) catalog plumbing (meta.conf/packagesite.pkg/...).
#
# Four-channel catalogue model (issue #2147): every channel serves the ONE canonical
# package (pfb_pkg.CANONICAL_EMITTED_IDENTITY) from its own <channel>/<varver>/
# catalogue subtree. Channel is catalogue PLACEMENT, never a package-name suffix —
# the legacy two-repo / suffixed-package model (release/nightly repos,
# -devel/-nightly identities) is retired from this generator.
#
# Stdlib only + the `zstd` binary (to read a .pkg's +COMPACT_MANIFEST). Dev-only
# tooling — not shipped in release archives (those contain only src/).
#
# Usage: gen_landing.py <site-dir> <pages-base-url> <add-repo.sh path>
from __future__ import annotations

import argparse
import html
import json
import os
import re
import subprocess
from collections.abc import Callable, Iterable
from datetime import datetime, timezone

from pfb_pkg import CANONICAL_EMITTED_IDENTITY, pkg_version_sort_key, read_compact_manifest

# Display order for the published-packages table + the channel cards. Every channel
# owns its own <channel>/<varver>/ catalogue subtree and serves the SAME canonical
# package (issue #2147) — a package's channel is read from its catalogue PATH
# (channel_of_path), never from its name.
CH_ORDER: list[str] = ["stable", "testing", "edge", "nightly"]
_CHANNELS: frozenset[str] = frozenset(CH_ORDER)
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
# snippet on the landing page.  The rc.d hook resolves the box's real varver at
# boot (arch-less; issue #1806 NO_ARCH); a hand-written conf must substitute a
# concrete value (e.g. ce-2.8).
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


def published_datetime(manifest: dict, mtime_epoch: float) -> str:
    """The artifact's creation datetime (UTC, minute precision).

    Prefer the ``created`` build annotation — the source commit's committer epoch,
    baked into the .pkg at build time, so it reflects when the artifact's CODE was
    created and survives every daily republish/re-download (a nightly is rebuilt and a
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


def collect_packages(site: str, read_manifest: Callable[[str], dict] | None = None) -> list[dict]:
    """Walk <site>/, returning one row per published package (channel/name/version/abi/size/rel).

    A package's channel is read from its catalogue placement — the top-level directory
    under <site> (issue #2147) — never from its name. A package sitting under an
    unrecognized top-level dir (a legacy release/nightly-suffixed tree, a stray future
    dir) is not attributed to any channel and is dropped from this list entirely; it
    stays reachable via the raw directory autoindex, which walks disk directly and
    never calls this function.
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
            pkgs.append(
                {
                    "channel": channel,
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
:root{--bg:#0d1117;--card:#161b22;--bd:#30363d;--fg:#e6edf3;--mut:#8b949e;--acc:#2f81f7;--warn:#d29922;--edge:#a371f7;--red:#f85149;--code:#0b0f14}
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
.card.stable{border-color:var(--acc)}
.card.testing{border-color:var(--warn)}
.card.edge{border-color:var(--edge)}
.card.nightly{border-color:var(--red)}
.card.nightly .badge{border-color:var(--red);color:var(--red)}
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


def _bootstrap_install(base: str, channel: str) -> str:
    """A channel's unified command: the bootstrap one-liner + its `pkg install`.

    All four channels install the SAME canonical package (issue #2147) — `--channel
    <ch>` selects the catalogue, uniformly across every card (not a nightly-only flag).
    """
    return (
        f"fetch -qo - {base}/add-repo.sh \\\n"
        f"  | sh -s -- --base-url {base} --channel {channel}\n"
        f"pkg install {CANONICAL_EMITTED_IDENTITY}"
    )


def _channel_switch_commands(base: str) -> str:
    """The copyable two-step channel switch: move the subscription, then move the
    installed package. Adding the target repository alone is a documented silent
    no-op (`pkg` never leaves a package's origin repository), so both lines ship
    together (issue #2148)."""
    return (
        f"fetch -qo - {base}/add-repo.sh \\\n"
        f"  | sh -s -- --base-url {base} --channel <ch>\n"
        f"fetch -qo - {base}/migrate-channel.sh \\\n"
        "  | sh -s -- --channel <ch>"
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
            "Untagged snapshot builds (<code>YYYYMMDD[_N]</code>) from a pinned source SHA, "
            'rebuilt only when inputs change. <span class="warn">Bleeding edge</span> &mdash; the '
            "only guarantee is that CI passed. Bare date versions intentionally sort above semantic "
            "versions: moving off Nightly is an explicit repository-qualified downgrade."
        ),
    },
}


def _channel_card(channel: str, base: str, latest: dict[str, str], conf_fn: Callable[[str], str]) -> str:
    """One channel's install card: audience prose + the unified bootstrap/install command
    + a collapsed manual-conf snippet. Every channel installs the ONE canonical package
    (issue #2147) — channel is catalogue placement, never a name suffix."""
    meta = _CARD_META[channel]
    badge = f" {meta['badge']}" if meta["badge"] else ""
    return (
        f'<div class="card {channel}"><h3>{meta["title"]}{badge}</h3>'
        f'<p class="ver">{_ver_or_empty(latest, channel)}</p>'
        f'<p class="blurb">{meta["blurb"]}</p>'
        f"{_copyable(_esc(_bootstrap_install(base, channel)))}"
        f"{_manual_conf_details(conf_fn, channel)}</div>"
    )


def _trust_section_html(base: str) -> str:
    """The trust/provenance section: what 'installing from this repo' actually means
    under the four-channel model (issue #2147). No catalogue-signing claim anywhere;
    the NONE-signed trust anchor is HTTPS/TLS to the Pages host (mirrors add-repo.sh's
    own conf comment). *base* is woven into the channel-switching subsection, whose
    two client scripts are both served from it (issue #2148).
    """
    return (
        "<h2>Trust &amp; channel model</h2>"
        "<h3>One tagged artifact, several catalogues</h3>"
        '<p class="blurb">Stable, Testing, and Edge may intentionally serve the exact same canonical '
        "package &mdash; same name, same version, same bytes &mdash; because a single tagged release "
        "always fans out to every channel its tag kind reaches: a Stable final lands in Stable, Testing, "
        "and Edge; a Testing prerelease lands in Testing and Edge; an Edge patch-zero prerelease lands "
        "in Edge alone. Edge's own latest simply moves ahead numerically once a new release family "
        "opens there &mdash; the fan-out itself never depends on what else has been published. This is "
        "catalogue placement, not separate builds, and not a repository-priority policy.</p>"
        "<h3>Trust model</h3>"
        '<p class="blurb">Every repository conf sets <code>signature_type: none</code> &mdash; there is '
        "no catalogue-signing key. The trust anchor is HTTPS/TLS to this Pages host.</p>"
        "<h3>Single-repository subscription</h3>"
        '<p class="blurb">A box subscribes to exactly one channel repository at a time. The four '
        "channel repos share one equal priority (<code>100</code>), above the base Netgate "
        "<code>pfSense</code> repo (priority <code>0</code>); live <code>pkg</code> resolution at equal "
        "priority ignores version ordering between repos, and upgrades of an installed package never "
        "leave its origin repository &mdash; so enabling a second project channel repo is not how "
        "channel selection works. This is safe because each channel catalogue strictly contains "
        "everything its slower channels carry: Edge holds every package Testing does, and Testing holds "
        "every package Stable does, so a Stable final always lands in Stable, Testing, and Edge; a "
        "Testing prerelease always lands in Testing and Edge; an Edge patch-zero prerelease lands in "
        "Edge alone. One subscription therefore already has every package a box could need, because "
        "<code>pkg</code> orders versions numerically, component-wise &mdash; never by release date: if "
        "Edge holds <code>4.0.0.a2</code> and a later <code>3.2.16.a3</code> or <code>3.2.17</code> is "
        "published into it, the latest in Edge stays <code>4.0.0.a2</code>, and the older build stays in "
        "the Edge catalogue as in-repo rollback material. Switching forward (to a higher version) is "
        "replacing the enabled conf with the faster channel's and upgrading normally. Rolling back is an "
        "explicit repository-qualified downgrade/reinstall &mdash; available within the same repo on a "
        "faster channel (containment keeps the older build around), or after switching the conf to a "
        "slower channel. Removing a channel means removing its conf. Identical name/version across "
        "catalogues remains valid only because the bytes and provenance are identical.</p>"
        "<h3>Retention</h3>"
        '<p class="blurb">Each <code>&lt;channel&gt;/&lt;varver&gt;/</code> catalogue retains the newest '
        "5 canonical packages; a faster channel additionally retains any canonical package one of "
        "its slower channels still retains, so containment (Edge &supe; Testing &supe; Stable) "
        "survives retention, not only fan-out. Dependency packages are not pruned.</p>"
        "<h3>Netgate identity</h3>"
        '<p class="blurb">The canonical package shares its name with the pfBlockerNG package Netgate '
        "ships in its own <code>pfSense</code> repo &mdash; provenance differs. Every build published "
        "here carries <code>commit</code>/<code>created</code> annotations linking it to the source "
        "commit that produced it; repository priority decides which build <code>pkg</code> selects when "
        "both are enabled.</p>"
        "<h3>Channel switching</h3>"
        '<p class="blurb">Switching channels is two steps, and the second one is not optional. '
        f"<code>{_esc(base)}/add-repo.sh</code> run with <code>--channel &lt;ch&gt;</code> moves the "
        "<em>subscription</em>: it writes that channel's conf and retires every other project conf. "
        "It does not move the <em>installed package</em> &mdash; <code>pkg</code> keeps an installed "
        "package pinned to its origin repository and offers no upgrade across repositories, so a box "
        "that only gains a conf silently keeps running its old build. "
        f"<code>{_esc(base)}/migrate-channel.sh</code> run with the same "
        "<code>--channel &lt;ch&gt;</code> performs the repository-qualified operation that actually "
        "moves it, replaces a legacy suffixed identity "
        "(<code>-devel</code>, <code>-nightly</code>) with the canonical package, and verifies the "
        "result before reporting success. There is no in-UI channel switcher by design.</p>"
        f"{_copyable(_esc(_channel_switch_commands(base)))}"
    )


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
    return (
        f"<tr><td>{_or_dash(r.get('pfsense_version', ''))}</td>{channel_td}"
        f'<td><a href="./{_esc(r["rel"])}">{_esc(r["version"])}</a></td>'
        f"<td><code>{_esc(r['abi'])}</code></td>"
        f'<td class="num">{_or_dash(r.get("php", ""))}</td>'
        f'<td class="num">{_or_dash(r.get("py", ""))}</td>'
        f'<td class="num">{_esc(r.get("published", ""))}</td>'
        f"<td>{commit_cell(r.get('commit', ''))}</td>"
        f'<td class="num">{_esc(human_size(r["size"]))}</td></tr>'
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
        f"{_versions_table_html(rows, with_channel=True)}"
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
    that edition has none. Includes Channel column (stable/testing/edge can all appear)."""
    if not rows:
        return ""
    return (
        f"<details><summary>Older releases ({len(rows)})</summary>"
        f"{_versions_table_html(rows, with_channel=True)}</details>"
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
    matrix: list[dict] | None = None,
) -> str:
    """Render the root landing page."""
    latest = latest_versions(pkgs)
    cards = "".join(_channel_card(ch, base, latest, conf_fn) for ch in CH_ORDER)
    eol_block = _eol_versions_html(pkgs, matrix)
    return (
        '<!doctype html><html lang="en"><head><meta charset="utf-8">'
        '<meta name="viewport" content="width=device-width, initial-scale=1">'
        "<title>pfBlockerNG — self-hosted pkg repository</title>"
        f'<style>{_CSS}</style></head><body><div class="wrap">'
        "<header><h1>pfBlockerNG</h1>"
        "<p>Self-hosted FreeBSD <code>pkg</code> repository for pfSense&nbsp;CE &amp; pfSense&nbsp;Plus.</p></header>"
        "<p>Install pfBlockerNG straight from this repository: pick a channel below and run its "
        f"commands on your firewall (as <code>root</code>). Every channel installs the same canonical "
        f"package (<code>{CANONICAL_EMITTED_IDENTITY}</code>) from its own repository &mdash; see "
        "Trust &amp; channel model below for how the four relate.</p>"
        f'<h2>Channels</h2><div class="cards">{cards}</div>'
        f"{_trust_section_html(base)}"
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


def write_migrate_channel(site: str, addrepo: str) -> None:
    """Publish ``migrate-channel.sh`` verbatim to *site*/migrate-channel.sh.

    Resolved as a sibling of *addrepo* in the repository ``scripts/`` directory. Unlike
    ``add-repo.sh`` it has nothing to embed — it depends on no sibling file — so the
    published copy is byte-identical to the tested repository copy, which is what keeps
    the served script from drifting away from its shellspec (issue #2148).
    """
    scripts_dir = os.path.dirname(os.path.abspath(addrepo))
    with open(os.path.join(scripts_dir, "migrate-channel.sh")) as fh:
        text = fh.read()
    out_path = os.path.join(site, "migrate-channel.sh")
    with open(out_path, "w") as fh:
        fh.write(text)
    os.chmod(out_path, 0o755)


def _conf_via_addrepo(addrepo: str, base: str, channel: str) -> str:
    # add-repo.sh selects the channel EXPLICITLY via --channel <ch> (issue #2147) — every
    # one of the four channels now has its own repo/conf (pfblockerng-<channel>), unlike
    # the legacy shared release repo. --catalog-path is required by --print-conf; we pass
    # a literal placeholder here because the landing page shows a generic snippet — the
    # rc.d hook resolves the box's real varver at boot (see _CONF_PLACEHOLDER_PATH).
    out = subprocess.run(
        [
            "sh",
            addrepo,
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


def write_site(site: str, base: str, addrepo: str, matrix: list[dict] | None = None) -> int:
    """Generate the human landing page (root index.html), a browsable autoindex at EVERY
    directory level (so the whole tree is folder-navigable on GitHub Pages, which has no
    autoindex), and a root ``browse.html`` entry point the landing page links to. Returns the
    count of pfBlockerNG packages indexed — published dependencies are browsable but not
    ours to count (issue #1863)."""
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
    # Publish a self-contained add-repo.sh with the hook embedded for `fetch | sh`,
    # and its sibling migrate-channel.sh — both halves of a channel switch (issue #2148).
    write_add_repo(site, addrepo)
    write_migrate_channel(site, addrepo)
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
    print(
        f"landing page + browse.html + {len(all_dirs(args.site))} dir index(es) written; "
        f"{n} pfBlockerNG package(s) indexed"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
