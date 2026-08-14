#shellcheck shell=sh
# Real Ports parity examples. This file intentionally does not match *_spec.sh:
# the build workflow selects it explicitly with --fail-no-examples.
# The direct leg reuses the package job's shallow sparse checkout. The routed
# leg clones that bounded checkout through build-leg.sh.

Describe 'build-leg.sh real Ports parity'
  It 'native package bytes match a direct portable-builder invocation' env:ports
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
    work="$(mktemp -d "${SHELLSPEC_TMPBASE:-/tmp}/buildlegports.XXXXXX")"
    trap 'rm -rf "$work"' EXIT INT TERM
    ports_sha="$(git -C "$REAL_PORTS_DIR" rev-parse HEAD)"
    ports_url="$(git -C "$REAL_PORTS_DIR" remote get-url origin)"
    export SOURCE_DATE_EPOCH=1780000000 PFB_RUN_ROOT="${work}/runs" RUN_ID=native-parity
    if [ "$PARITY_CHANNEL" = nightly ]; then
      nightly_version="20260813153045.$(git -C "$PFB_ROOT" rev-parse HEAD)"
      direct="$(python3 "${PFB_ROOT}/scripts/build-pkg-portable.py" \
        --ports "$REAL_PORTS_DIR" --channel "$PARITY_CHANNEL" --variant "$PARITY_VARIANT" \
        --abi "$PARITY_ABI" --py-flavor "$PARITY_PY_FLAVOR" --php "$PARITY_PHP" \
        --local-src "$PFB_ROOT" --pkgversion "$nightly_version" --out "${work}/direct")"
      routed="$(sh "${PFB_ROOT}/scripts/build-leg.sh" \
        --ports-repo "$ports_url" --ports-ref "$ports_sha" \
        --channel "$PARITY_CHANNEL" --variant "$PARITY_VARIANT" --abi "$PARITY_ABI" \
        --py-flavor "$PARITY_PY_FLAVOR" --php "$PARITY_PHP" \
        --pkgversion "$nightly_version" --out-dir "${work}/routed")"
    else
      direct="$(python3 "${PFB_ROOT}/scripts/build-pkg-portable.py" \
        --ports "$REAL_PORTS_DIR" --channel "$PARITY_CHANNEL" --variant "$PARITY_VARIANT" \
        --abi "$PARITY_ABI" --py-flavor "$PARITY_PY_FLAVOR" --php "$PARITY_PHP" \
        --local-src "$PFB_ROOT" --out "${work}/direct")"
      routed="$(sh "${PFB_ROOT}/scripts/build-leg.sh" \
        --ports-repo "$ports_url" --ports-ref "$ports_sha" \
        --channel "$PARITY_CHANNEL" --variant "$PARITY_VARIANT" --abi "$PARITY_ABI" \
        --py-flavor "$PARITY_PY_FLAVOR" --php "$PARITY_PHP" --out-dir "${work}/routed")"
    fi
    cmp -s "$direct" "$routed" || {
      echo "native parity mismatch: direct=$direct routed=$routed" >&2; return 1; }
  End

  It 'project build-record package bytes match a direct portable-builder invocation' env:ports
    [ -n "${REAL_PORTS_DIR:-}" ] || { echo 'REAL_PORTS_DIR is required' >&2; return 1; }
    for name in PARITY_VARIANT PARITY_ABI PARITY_PY_FLAVOR PARITY_PHP; do
      eval "value=\${$name:-}"
      [ -n "$value" ] || { echo "$name is required" >&2; return 1; }
    done
    for tool in git python3 zstd; do
      command -v "$tool" >/dev/null 2>&1 || { echo "$tool is required" >&2; return 1; }
    done
    DASH="${DASH:-$(command -v dash 2>/dev/null || true)}"
    [ -n "$DASH" ] || { echo 'dash is required' >&2; return 1; }
    work="$(mktemp -d "${SHELLSPEC_TMPBASE:-/tmp}/buildlegrecord.XXXXXX")"
    trap 'rm -rf "$work"' EXIT INT TERM
    ports_sha="$(git -C "$REAL_PORTS_DIR" rev-parse HEAD)"
    source_sha="$(git -C "$PFB_ROOT" rev-parse HEAD)"
    nightly_version="20260813153045.${source_sha}"
    source_checkout="${work}/source"
    git clone -q --shared "$PFB_ROOT" "$source_checkout"
    git -C "$source_checkout" checkout -q "$source_sha"
    # Project records intentionally use the current nightly recipe: unlike release
    # channels it needs no historical source tag, while the target facts remain the
    # caller's resolved variant/ABI/PHP/Python inputs.
    ports_url="$(git -C "$REAL_PORTS_DIR" remote get-url origin)"
    sh "${PFB_ROOT}/scripts/sparse-clone-ports.sh" \
      "$ports_url" "$ports_sha" "$REAL_PORTS_DIR" \
      nightly "$PARITY_PHP" "$PARITY_PY_FLAVOR"
    python3 - "$work/record.json" "$ports_sha" "$source_sha" "$nightly_version" <<'PY'
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
# A project record needs a valid pfSense version solely to derive its route. Keep
# it deterministic while deriving the target ABI facts from the caller.
pfsense_version = os.environ.get("PARITY_PFSENSE_VERSION", "2.8" if major == "15" else "2.9")
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
    "build_input_digest": "",
}
record["build_input_digest"] = build_input_digest(record)
Path(path).write_text(json.dumps(record, sort_keys=True, separators=(",", ":")) + "\n", encoding="utf-8")
PY
    export SOURCE_DATE_EPOCH=1780000000 PFB_RUN_ROOT="${work}/runs" RUN_ID=record-parity
    direct="$(python3 "${PFB_ROOT}/scripts/build-pkg-portable.py" \
      --ports "$REAL_PORTS_DIR" --channel nightly --variant "$PARITY_VARIANT" \
      --abi "$PARITY_ABI" --py-flavor "$PARITY_PY_FLAVOR" --php "$PARITY_PHP" \
      --local-src "$source_checkout" --pkgversion "$nightly_version" \
      --build-record "$work/record.json" --out "${work}/direct")"
    routed="$(sh "${PFB_ROOT}/scripts/build-leg.sh" \
      --ports-repo "$ports_url" --ports-ref "$ports_sha" \
      --channel nightly --variant "$PARITY_VARIANT" --abi "$PARITY_ABI" \
      --py-flavor "$PARITY_PY_FLAVOR" --php "$PARITY_PHP" --pkgversion "$nightly_version" \
      --local-src "$source_checkout" --build-record "$work/record.json" \
      --out-dir "${work}/routed")"
    cmp -s "$direct" "$routed" || {
      echo "project parity mismatch: direct=$direct routed=$routed" >&2; return 1; }
  End
End
