"""`.claude/hooks/vendored-plugin-hook.sh` -- vendored plugin hooks for managed sessions.

The script runs a vendored plugin hook (node) ONLY when the real marketplace
plugin is absent, falling silent otherwise -- so locally the plugin injects
(no double-injection) and in managed/cloud sessions the vendored copy takes
over. Pinned here through the real production surface (the sh script run as
a subprocess with a controlled env), one test per resolution rung:

  - real plugin installed  -> silent no-op (rung 1)
  - node missing from PATH -> silent no-op (rung 2)
  - vendored script absent -> silent no-op (rung 3)
  - otherwise              -> node runs the vendored script with
                              CLAUDE_PLUGIN_ROOT at the vendored root and the
                              hook's stdin JSON passed through (rung 4)
"""

from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path

_HOOK = Path(__file__).resolve().parent.parent / ".claude" / "hooks" / "vendored-plugin-hook.sh"


def _run(
    tmp_path: Path,
    *,
    plugin_installed: bool,
    with_node: bool,
    vendored_js: bool,
    stdin: str = "",
) -> subprocess.CompletedProcess[str]:
    cfg = tmp_path / "cfg"
    project = tmp_path / "project"
    if plugin_installed:
        (cfg / "plugins" / "marketplaces" / "myplugin").mkdir(parents=True)
    if vendored_js:
        js = project / ".claude" / "skills" / "myplugin" / "hooks" / "activate.js"
        js.parent.mkdir(parents=True)
        # The stub proves three things at once: it ran, it saw
        # CLAUDE_PLUGIN_ROOT, and stdin reached it.
        js.write_text(
            "const data = require('fs').readFileSync(0, 'utf8');\n"
            "console.log(JSON.stringify({root: process.env.CLAUDE_PLUGIN_ROOT, stdin: data.trim()}));\n",
            encoding="utf-8",
        )
    path_dir = tmp_path / "bin"
    path_dir.mkdir()
    for tool in ("sh", "dirname", "env"):  # minimal POSIX the script itself needs
        real = subprocess.run(["/usr/bin/which", tool], capture_output=True, text=True).stdout.strip()
        if real:
            (path_dir / tool).symlink_to(real)
    if with_node:
        real_node = subprocess.run(["/usr/bin/which", "node"], capture_output=True, text=True).stdout.strip()
        assert real_node, "these tests need node on the dev host (CI installs it for the widget JS tests)"
        (path_dir / "node").symlink_to(real_node)

    env = {
        "PATH": str(path_dir),
        "HOME": str(tmp_path),
        "CLAUDE_CONFIG_DIR": str(cfg),
        "CLAUDE_PROJECT_DIR": str(project),
    }
    return subprocess.run(
        ["/bin/sh", str(_HOOK), "myplugin", "hooks/activate.js"],
        capture_output=True,
        text=True,
        env=env,
        input=stdin,
        timeout=30,
    )


def test_installed_plugin_wins_and_the_hook_stays_silent(tmp_path: Path) -> None:
    result = _run(tmp_path, plugin_installed=True, with_node=True, vendored_js=True)

    assert result.returncode == 0, f"expected silent success, got rc={result.returncode}: {result.stderr!r}"
    assert result.stdout == "", f"installed plugin must mean NO vendored injection, got: {result.stdout!r}"


def test_missing_node_is_a_silent_noop(tmp_path: Path) -> None:
    result = _run(tmp_path, plugin_installed=False, with_node=False, vendored_js=True)

    assert result.returncode == 0, f"expected silent success, got rc={result.returncode}: {result.stderr!r}"
    assert result.stdout == "", f"no node must mean no output (static hooks are the fallback), got: {result.stdout!r}"


def test_missing_vendored_script_is_a_silent_noop(tmp_path: Path) -> None:
    result = _run(tmp_path, plugin_installed=False, with_node=True, vendored_js=False)

    assert result.returncode == 0, f"expected silent success, got rc={result.returncode}: {result.stderr!r}"
    assert result.stdout == "", f"missing vendored script must be a no-op, got: {result.stdout!r}"


def test_vendored_script_runs_with_plugin_root_and_stdin_passthrough(tmp_path: Path) -> None:
    payload = '{"hook_event_name": "SessionStart"}'

    result = _run(tmp_path, plugin_installed=False, with_node=True, vendored_js=True, stdin=payload)

    assert result.returncode == 0, f"expected the vendored hook to run, got rc={result.returncode}: {result.stderr!r}"
    out = json.loads(result.stdout)
    expected_root = os.path.join(str(tmp_path / "project"), ".claude", "skills", "myplugin")
    assert out["root"] == expected_root, f"CLAUDE_PLUGIN_ROOT must point at the vendored root, got: {out['root']!r}"
    assert out["stdin"] == payload, f"the hook's stdin JSON must reach the vendored script, got: {out['stdin']!r}"
