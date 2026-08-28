#shellcheck shell=sh
# Real Ports parity examples. This file intentionally does not match *_spec.sh:
# the build workflow selects it explicitly with --fail-no-examples.
# The direct leg reuses the package job's shallow sparse checkout. The routed
# leg clones that bounded checkout through build-leg.sh.

Describe 'build-leg.sh real Ports parity'
  native_parity() {
    [ -n "${REAL_PORTS_DIR:-}" ] || { echo 'REAL_PORTS_DIR is required' >&2; return 1; }
    [ -n "${PARITY_CHANNEL:-}" ] || { echo 'PARITY_CHANNEL is required' >&2; return 1; }
    [ -n "${PARITY_VARIANT:-}" ] || { echo 'PARITY_VARIANT is required' >&2; return 1; }
    [ -n "${PARITY_ABI:-}" ] || { echo 'PARITY_ABI is required' >&2; return 1; }
    [ -n "${PARITY_PY_FLAVOR:-}" ] || { echo 'PARITY_PY_FLAVOR is required' >&2; return 1; }
    [ -n "${PARITY_PHP:-}" ] || { echo 'PARITY_PHP is required' >&2; return 1; }
    command -v git >/dev/null 2>&1 || { echo 'git is required' >&2; return 1; }
    command -v python3 >/dev/null 2>&1 || { echo 'python3 is required' >&2; return 1; }
    command -v zstd >/dev/null 2>&1 || { echo 'zstd is required' >&2; return 1; }
    DASH="${DASH:-$(command -v dash 2>/dev/null || true)}"
    [ -n "$DASH" ] || { echo 'dash is required' >&2; return 1; }
    git -C "$REAL_PORTS_DIR" rev-parse --verify HEAD >/dev/null 2>&1 || {
      echo 'REAL_PORTS_DIR must be a Git checkout' >&2; return 1; }
    work="$(mktemp -d "${SHELLSPEC_TMPBASE:-/tmp}/buildlegports.XXXXXX")" || return 1
    trap 'rm -rf "$work"' EXIT INT TERM || return 1
    ports_sha="$(git -C "$REAL_PORTS_DIR" rev-parse HEAD)" || return 1
    ports_url="$(git -C "$REAL_PORTS_DIR" remote get-url origin)" || return 1
    export SOURCE_DATE_EPOCH=1780000000 PFB_RUN_ROOT="${work}/runs" RUN_ID=native-parity || return 1
    if [ "$PARITY_CHANNEL" = nightly ]; then
      source_sha="$(git -C "$PFB_ROOT" rev-parse HEAD)" || return 1
      nightly_version="20260813153045.$(printf '%.7s' "$source_sha")" || return 1
      direct="$(python3 "${PFB_ROOT}/scripts/build-pkg-portable.py" \
        --ports "$REAL_PORTS_DIR" --channel "$PARITY_CHANNEL" --variant "$PARITY_VARIANT" \
        --abi "$PARITY_ABI" --py-flavor "$PARITY_PY_FLAVOR" --php "$PARITY_PHP" \
        --local-src "$PFB_ROOT" --pkgversion "$nightly_version" --out "${work}/direct")" || return 1
      routed="$(sh "${PFB_ROOT}/scripts/build-leg.sh" \
        --ports-repo "$ports_url" --ports-ref "$ports_sha" \
        --channel "$PARITY_CHANNEL" --variant "$PARITY_VARIANT" --abi "$PARITY_ABI" \
        --py-flavor "$PARITY_PY_FLAVOR" --php "$PARITY_PHP" \
        --pkgversion "$nightly_version" --out-dir "${work}/routed")" || return 1
    else
      direct="$(python3 "${PFB_ROOT}/scripts/build-pkg-portable.py" \
        --ports "$REAL_PORTS_DIR" --channel "$PARITY_CHANNEL" --variant "$PARITY_VARIANT" \
        --abi "$PARITY_ABI" --py-flavor "$PARITY_PY_FLAVOR" --php "$PARITY_PHP" \
        --local-src "$PFB_ROOT" --out "${work}/direct")" || return 1
      routed="$(sh "${PFB_ROOT}/scripts/build-leg.sh" \
        --ports-repo "$ports_url" --ports-ref "$ports_sha" \
        --channel "$PARITY_CHANNEL" --variant "$PARITY_VARIANT" --abi "$PARITY_ABI" \
        --py-flavor "$PARITY_PY_FLAVOR" --php "$PARITY_PHP" --out-dir "${work}/routed")" || return 1
    fi
    cmp -s "$direct" "$routed" || {
      echo "native parity mismatch: direct=$direct routed=$routed" >&2; return 1; }
  }

  It 'native package bytes match a direct portable-builder invocation' env:ports
    When call native_parity
    The status should be success
    The stderr should include '==> wrote'
  End

  project_parity() {
    [ -n "${REAL_PORTS_DIR:-}" ] || { echo 'REAL_PORTS_DIR is required' >&2; return 1; }
    for name in PARITY_VARIANT PARITY_ABI PARITY_PY_FLAVOR PARITY_PHP; do
      eval "value=\${$name:-}" || return 1
      [ -n "$value" ] || { echo "$name is required" >&2; return 1; }
    done
    for tool in git python3 zstd; do
      command -v "$tool" >/dev/null 2>&1 || { echo "$tool is required" >&2; return 1; }
    done
    DASH="${DASH:-$(command -v dash 2>/dev/null || true)}"
    [ -n "$DASH" ] || { echo 'dash is required' >&2; return 1; }
    work="$(mktemp -d "${SHELLSPEC_TMPBASE:-/tmp}/buildlegrecord.XXXXXX")" || return 1
    trap 'rm -rf "$work"' EXIT INT TERM || return 1
    ports_sha="$(git -C "$REAL_PORTS_DIR" rev-parse HEAD)" || return 1
    source_sha="$(git -C "$PFB_ROOT" rev-parse HEAD)" || return 1
    nightly_version="20260813153045.$(printf '%.7s' "$source_sha")" || return 1
    source_checkout="${work}/source"
    git clone -q --shared "$PFB_ROOT" "$source_checkout" || return 1
    git -C "$source_checkout" checkout -q "$source_sha" || return 1
    # Project records intentionally use the current nightly recipe: unlike release
    # channels it needs no historical source tag, while the target facts remain the
    # caller's resolved variant/ABI/PHP/Python inputs.
    ports_url="$(git -C "$REAL_PORTS_DIR" remote get-url origin)" || return 1
    sh "${PFB_ROOT}/scripts/sparse-clone-ports.sh" \
      "$ports_url" "$ports_sha" "$REAL_PORTS_DIR" \
      nightly "$PARITY_PHP" "$PARITY_PY_FLAVOR" || return 1
    python3 - "$work/record.json" "$ports_sha" "$source_sha" "$nightly_version" <<'PY' || return 1
import json
import os
import sys
from pathlib import Path
from scripts.pfb_pkg import build_input_digest

path, ports_sha, source_sha, nightly_version = sys.argv[1:]
abi = os.environ["PARITY_ABI"]
variant = os.environ["PARITY_VARIANT"]
php = os.environ["PARITY_PHP"]
py_flavor = os.environ["PARITY_PY_FLAVOR"]
major = abi.split(":")[1]
# A project record needs a valid pfSense version solely to derive its route. Take it
# from the caller, else look up a REAL matrix row for this (variant, major) — never a
# major -> version table (issue #2464): "15 means 2.8, anything else means 2.9"
# fabricated {Plus, 2.9}, a row that exists in no matrix, on every Plus leg.
pfsense_version = os.environ.get("PARITY_PFSENSE_VERSION", "")
if not pfsense_version:
    import subprocess

    proc = subprocess.run(
        ["sh", str(Path(os.environ["PFB_ROOT"]) / "scripts" / "read-version-matrix.sh"), "--print-ci"],
        capture_output=True,
        text=True,
        check=False,
    )
    if proc.returncode != 0:
        # capture_output swallows the reader's own ::error:: line; re-emit it or the failure
        # reads as an empty traceback.
        raise SystemExit(f"read-version-matrix.sh --print-ci failed (rc={proc.returncode}): {proc.stderr.strip()}")
    rows = json.loads(proc.stdout)
    matches = [
        r
        for r in rows
        if str(r.get("freebsd_major")) == major and str(r.get("variant", "")).lower() == variant.lower()
    ]
    if not matches:
        raise SystemExit(
            f"no matrix row for variant={variant} freebsd_major={major}; "
            f"set PARITY_PFSENSE_VERSION to name this leg's row"
        )
    # Several rows can share (variant, major) — Plus 26.03 and 26.07 do. Any REAL row gives a
    # valid route for this parity comparison (both sides of it use the same record), so pick
    # the lowest version deterministically rather than by matrix order. Naming the leg exactly
    # is the caller's job via PARITY_PFSENSE_VERSION.
    pfsense_version = min(str(m["pfsense_version"]) for m in matches)
row = {
    "pfsense_version": pfsense_version,
    "channel": variant,
    "freebsd_version": f"{major}.0-RELEASE",
    "freebsd_major": major,
    "php_version": php,
    "py_flavor": py_flavor,
    "variant": variant,
    "status": "active",
    "extra_pkgs": [],
}
parts = pfsense_version.split(".")
record = {
    "schema": 1,
    "channel": "nightly",
    "release_line": "nightly",
    "classification": "nightly",
    "source_tag": None,
    "source_sha": source_sha,
    "canonical_package_version": nightly_version,
    "native_recipe_identity": "pfSense-pkg-pfBlockerNG-nightly",
    "emitted_identity": "pfSense-pkg-pfBlockerNG",
    "matrix_row": row,
    "freebsd_ports_sha": ports_sha,
    "route": f"nightly/{variant.lower()}-{parts[0]}.{parts[1]}",
    "source_date_epoch": 1780000000,
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
record["build_input_digest"] = build_input_digest(record)
Path(path).write_text(json.dumps(record, sort_keys=True, separators=(",", ":")) + "\n", encoding="utf-8")
PY
    export SOURCE_DATE_EPOCH=1780000000 PFB_RUN_ROOT="${work}/runs" RUN_ID=record-parity || return 1
    direct="$(python3 "${PFB_ROOT}/scripts/build-pkg-portable.py" \
      --ports "$REAL_PORTS_DIR" --channel nightly --variant "$PARITY_VARIANT" \
      --abi "$PARITY_ABI" --py-flavor "$PARITY_PY_FLAVOR" --php "$PARITY_PHP" \
      --local-src "$source_checkout" --pkgversion "$nightly_version" \
      --build-record "$work/record.json" --out "${work}/direct")" || return 1
    routed="$(sh "${PFB_ROOT}/scripts/build-leg.sh" \
      --ports-repo "$ports_url" --ports-ref "$ports_sha" \
      --channel nightly --variant "$PARITY_VARIANT" --abi "$PARITY_ABI" \
      --py-flavor "$PARITY_PY_FLAVOR" --php "$PARITY_PHP" --pkgversion "$nightly_version" \
      --local-src "$source_checkout" --build-record "$work/record.json" \
      --out-dir "${work}/routed")" || return 1
    cmp -s "$direct" "$routed" || {
      echo "project parity mismatch: direct=$direct routed=$routed" >&2; return 1; }
  }

  It 'project build-record package bytes match a direct portable-builder invocation' env:ports
    When call project_parity
    The status should be success
    The stderr should include '==> wrote'
  End
End
