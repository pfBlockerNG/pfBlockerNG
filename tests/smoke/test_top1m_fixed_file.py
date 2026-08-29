"""Issue #1542 — live TOP1M fixed-file publication and lifecycle contract.

The provider body is staged directly on the pfSense box.  Both
``top-1m.csv`` and its detector baseline exist before each update, so the
production update/publisher path runs without contacting a public provider.
"""

from __future__ import annotations

import json
import os
import uuid
from collections.abc import Iterator

import pytest

from . import helpers as h
from .conftest import SmokeVM, _StubDnsServer

pytestmark = pytest.mark.smoke

TOP1M_CSV = f"{h.PFB_DBDIR}/top-1m.csv"
TOP1M_WHITELIST = f"{h.PFB_DBDIR}/pfbalexawhitelist.txt"
TOP1M_BASE = f"{h.PFB_DBDIR}/top-1m.csv.zip"
TOP1M_UPDATE = f"{h.PFB_DBDIR}/top-1m.update"
TOP1M_FIXED = "/var/unbound/pfb_py_top1m.txt"
MANIFEST = "/var/unbound/pfb_py_sources.json"
CACHE_BASE = "/usr/local/etc/pfb_dnsbl_cache.tar"
LOCAL_FEED = f"{h.PFB_DBDIR}/top1m_fixed_file_feed.txt"
TEMP_PATHS = (
    f"{h.PFB_DBDIR}/.pfbtop1m_smoke_file",
    f"{h.PFB_DBDIR}/.pfbtop1m_smoke_dir",
    "/var/unbound/.pfbtop1m_smoke_file",
    "/var/unbound/.pfbtop1m_smoke_dir",
)
SIDECAR_SUFFIXES = ("orig", "xxhash128", "md5", "source", "orig.etag", "orig.lastmod")
SIDECARS = tuple(f"{TOP1M_BASE}.{suffix}" for suffix in SIDECAR_SUFFIXES)
NEIGHBOR = f"{TOP1M_BASE}.orig.neighbor"

_SNAPSHOT_TARGETS = (
    TOP1M_CSV,
    f"{TOP1M_BASE}",
    TOP1M_WHITELIST,
    TOP1M_FIXED,
    *SIDECARS,
    NEIGHBOR,
    f"{CACHE_BASE}.zst",
    f"{CACHE_BASE}.bz2",
    LOCAL_FEED,
    TOP1M_UPDATE,
    *TEMP_PATHS,
)


def _require_ok(result: object, operation: str) -> None:
    if getattr(result, "returncode", 1) != 0:
        raise RuntimeError(
            f"{operation} failed: rc={getattr(result, 'returncode', '?')} "
            f"stdout={getattr(result, 'stdout', '')!r} stderr={getattr(result, 'stderr', '')!r}"
        )


def _archive_if_present(vm: SmokeVM, source: str, archive: str) -> None:
    relative = source.removeprefix("/")
    result = vm.ssh(f"if [ -e {source} ] || [ -L {source} ]; then /usr/bin/tar -cpf {archive} -C / {relative}; fi")
    _require_ok(result, f"snapshot {source}")


def _snapshot_box(vm: SmokeVM, root: str) -> None:
    _require_ok(vm.ssh("/bin/mkdir", "-p", f"{root}/files"), "create TOP1M smoke snapshot")
    _require_ok(vm.ssh("/bin/cp", "-p", "/conf/config.xml", f"{root}/config.xml"), "snapshot config.xml")
    for index, target in enumerate(_SNAPSHOT_TARGETS):
        _archive_if_present(vm, target, f"{root}/files/{index}.tar")
    runtime_snapshot = vm.ssh(
        "cd / && set --; "
        "for _path in var/unbound/pfb_unbound* var/unbound/pfb_py_*; do "
        '  if [ -e "${_path}" ] || [ -L "${_path}" ]; then set -- "$@" "${_path}"; fi; '
        "done; "
        f'if [ "$#" -gt 0 ]; then /usr/bin/tar -cpf {root}/runtime.tar "$@"; fi'
    )
    _require_ok(runtime_snapshot, "snapshot pfBlockerNG Unbound runtime")
    runtime_expected = vm.ssh(
        f"if [ -f {root}/runtime.tar ]; then /bin/mkdir -p {root}/expected && "
        f"/usr/bin/tar -xpf {root}/runtime.tar -C {root}/expected; fi"
    )
    _require_ok(runtime_expected, "materialize expected pfBlockerNG Unbound runtime")


def _remove_runtime_artifacts(vm: SmokeVM) -> None:
    result = h.php_eval(
        vm,
        "require_once('/usr/local/pkg/pfblockerng/pfblockerng.inc');\n"
        "$paths = array_merge(\n"
        "  glob('/var/unbound/pfb_unbound*') ?: array(),\n"
        "  glob('/var/unbound/pfb_py_*') ?: array()\n"
        ");\n"
        "$ok = TRUE;\n"
        "foreach (array_unique($paths) as $path) { $ok = pfb_unbound_py_remove_raw_artifact($path) && $ok; }\n"
        "echo $ok ? 'OK' : 'FAILED';",
    )
    _require_ok(result, "remove current pfBlockerNG Unbound runtime")
    if "OK" not in result.stdout:
        raise RuntimeError(f"remove current pfBlockerNG Unbound runtime failed: {result.stdout!r}")


def _remove_snapshot_root(vm: SmokeVM, root: str) -> None:
    result = h.php_eval(
        vm, f"rmdir_recursive({h._php_str(root)}); echo file_exists({h._php_str(root)}) ? 'FAILED' : 'OK';"
    )
    _require_ok(result, "remove TOP1M smoke snapshot")
    if "OK" not in result.stdout:
        raise RuntimeError(f"remove TOP1M smoke snapshot failed: {result.stdout!r}")


def _remove_exact_paths(vm: SmokeVM, paths: tuple[str, ...], operation: str) -> None:
    php_paths = "array(" + ",".join(h._php_str(path) for path in paths) + ")"
    result = h.php_eval(
        vm,
        f"$ok = TRUE; foreach ({php_paths} as $path) {{\n"
        "  if (is_link($path) || is_file($path)) { $ok = @unlink($path) && $ok; }\n"
        "  elseif (is_dir($path)) { rmdir_recursive($path); $ok = !file_exists($path) && $ok; }\n"
        "}\n"
        "echo $ok ? 'OK' : 'FAILED';",
    )
    _require_ok(result, operation)
    if "OK" not in result.stdout:
        raise RuntimeError(f"{operation} failed: {result.stdout!r}")


def _restore_box(vm: SmokeVM, root: str) -> tuple[dict, dict, dict]:
    """Restore config and every persistent file this module can replace."""
    errors: list[Exception] = []
    try:
        h.restore_pfb_config_baseline(vm, snapshot_path=f"{root}/config.xml")
    except Exception as exc:  # noqa: BLE001 -- keep restoring every owned path, then fail loudly
        errors.append(exc)
    try:
        _remove_runtime_artifacts(vm)
        runtime = vm.ssh(f"if [ -f {root}/runtime.tar ]; then /usr/bin/tar -xpf {root}/runtime.tar -C /; fi")
        _require_ok(runtime, "restore pfBlockerNG Unbound runtime")
    except Exception as exc:  # noqa: BLE001 -- continue the remaining cleanup, then fail loudly
        errors.append(exc)
    for index, target in enumerate(_SNAPSHOT_TARGETS):
        try:
            _remove_exact_paths(vm, (target,), f"remove test-owned {target}")
            archive = f"{root}/files/{index}.tar"
            result = vm.ssh(f"if [ -f {archive} ]; then /usr/bin/tar -xpf {archive} -C /; fi")
            _require_ok(result, f"restore {target}")
        except Exception as exc:  # noqa: BLE001 -- continue the remaining cleanup, then fail loudly
            errors.append(exc)
    try:
        config = vm.ssh(f"/bin/cp -p {root}/config.xml /conf/config.xml && /bin/rm -f /tmp/config.cache")
        _require_ok(config, "restore final config.xml bytes")
    except Exception as exc:  # noqa: BLE001 -- aggregate cleanup failure below
        errors.append(exc)
    restored_runtime: dict = {}
    restored_files: dict = {}
    restored_config: dict = {}
    try:
        # Observe restoration before restarting Unbound: daemon-owned counters/cache
        # may legitimately rewrite themselves after start, but every archived byte and
        # path must be identical at the restoration boundary.
        restored_runtime = _runtime_state(vm)
        restored_files = _file_state(vm, _SNAPSHOT_TARGETS)
        restored_config = _file_state(vm, ("/conf/config.xml",))
    except Exception as exc:  # noqa: BLE001 -- aggregate cleanup failure below
        errors.append(exc)
    try:
        configured = h.php_eval(vm, "services_unbound_configure(); echo 'OK';")
        _require_ok(configured, "reconfigure Unbound after TOP1M smoke restore")
        if "OK" not in configured.stdout:
            raise RuntimeError(f"reconfigure Unbound after TOP1M smoke restore failed: {configured.stdout!r}")
        h.wait_unbound_ready(vm)
    except Exception as exc:  # noqa: BLE001 -- aggregate cleanup failure below
        errors.append(exc)
    try:
        _remove_snapshot_root(vm, root)
    except Exception as exc:  # noqa: BLE001 -- aggregate cleanup failure below
        errors.append(exc)
    if errors:
        raise RuntimeError("TOP1M smoke cleanup failed: " + "; ".join(str(error) for error in errors)) from errors[0]
    return restored_runtime, restored_files, restored_config


@pytest.fixture(scope="module")
def top1m_fixed_file_vm(smoke_vm: SmokeVM, stub_dns: _StubDnsServer) -> Iterator[SmokeVM]:  # noqa: ARG001
    if not os.environ.get("SMOKE_PKG"):
        pytest.skip("SMOKE_PKG not set — no built .pkg to deploy")

    snapshot = f"/tmp/pfb-smoke-top1m-fixed-{uuid.uuid4().hex}"
    h.deploy(smoke_vm)
    _snapshot_box(smoke_vm, snapshot)
    runtime_before = _runtime_state(smoke_vm, root=f"{snapshot}/expected")
    files_before = _file_state(smoke_vm, _SNAPSHOT_TARGETS)
    saved_config = f"{snapshot}/config.xml"
    config_before = {"/conf/config.xml": _file_state(smoke_vm, (saved_config,))[saved_config]}
    try:
        h.ensure_dnsbl_vip(smoke_vm)
        h.use_system_dns_upstream(smoke_vm)
        yield smoke_vm
    finally:
        h.unblock_egress()
        diagnostic_error: Exception | None = None
        try:
            h.collect_host_diagnostics(smoke_vm)
        except Exception as exc:  # noqa: BLE001 -- restoration must still run
            diagnostic_error = exc
        runtime_after, files_after, config_after = _restore_box(smoke_vm, snapshot)
        files_post_service = _file_state(smoke_vm, _SNAPSHOT_TARGETS)
        config_post_service = _file_state(smoke_vm, ("/conf/config.xml",))
        if (
            runtime_after != runtime_before
            or files_after != files_before
            or config_after != config_before
            or files_post_service != files_before
            or config_post_service != config_before
        ):
            raise RuntimeError(
                "TOP1M smoke restore did not reproduce its post-deploy file baseline: "
                f"runtime_before={runtime_before!r} runtime_after={runtime_after!r} "
                f"files_before={files_before!r} files_after={files_after!r} "
                f"files_post_service={files_post_service!r} "
                f"config_before={config_before!r} config_after={config_after!r} "
                f"config_post_service={config_post_service!r}"
            )
        if diagnostic_error is not None:
            raise RuntimeError(f"TOP1M smoke diagnostics failed: {diagnostic_error}") from diagnostic_error


def _json_eval(vm: SmokeVM, snippet: str, tag: str = "PFB1542") -> dict:
    result = h.php_eval(vm, snippet + f"\necho '<<{tag}>>' . json_encode($out) . '<<END{tag}>>';")
    _require_ok(result, f"PHP JSON probe {tag}")
    try:
        encoded = result.stdout.split(f"<<{tag}>>", 1)[1].split(f"<<END{tag}>>", 1)[0]
        value = json.loads(encoded)
    except (IndexError, json.JSONDecodeError) as exc:
        raise RuntimeError(f"PHP JSON probe {tag} returned no valid payload: {result.stdout!r}") from exc
    if not isinstance(value, dict):
        raise RuntimeError(f"PHP JSON probe {tag} returned non-object payload: {value!r}")
    return value


def _publication_state(vm: SmokeVM) -> dict:
    return _json_eval(
        vm,
        "require_once('/usr/local/pkg/pfblockerng/pfblockerng.inc');\n"
        "pfb_global();\n"
        f"$manifest_raw = @file_get_contents('{MANIFEST}');\n"
        "$manifest = is_string($manifest_raw) ? json_decode($manifest_raw, TRUE) : NULL;\n"
        "$feed = is_array($manifest) ? ($manifest['feeds'][0] ?? array()) : array();\n"
        "$raw_rel = is_array($feed) ? ($feed['raw'] ?? '') : '';\n"
        "$raw_path = is_string($raw_rel) && $raw_rel !== '' ? '/var/unbound/' . $raw_rel : '';\n"
        "$raw_stat = $raw_path !== '' ? @stat($raw_path) : FALSE;\n"
        "$raw_dir = $raw_path !== '' ? dirname($raw_path) : '';\n"
        "$dir_stat = $raw_dir !== '' ? @stat($raw_dir) : FALSE;\n"
        "$top1m_keys = array();\n"
        "foreach ((array) ($manifest['config'] ?? array()) as $key => $_value) {\n"
        "  if (stripos((string) $key, 'top1m') !== FALSE) { $top1m_keys[] = (string) $key; }\n"
        "}\n"
        "$out = array(\n"
        f"  'fixed_regular' => is_file('{TOP1M_FIXED}') && !is_link('{TOP1M_FIXED}'),\n"
        f"  'fixed_bytes' => @file_get_contents('{TOP1M_FIXED}'),\n"
        f"  'whitelist_bytes' => @file_get_contents('{TOP1M_WHITELIST}'),\n"
        "  'top1m_enabled' => $manifest['config']['top1m_enabled'] ?? NULL,\n"
        "  'top1m_keys' => $top1m_keys,\n"
        "  'manifest_raw' => $manifest_raw,\n"
        "  'raw_rel' => $raw_rel,\n"
        "  'raw_identity' => $raw_stat === FALSE ? NULL : array(\n"
        "    'dev' => $raw_stat['dev'], 'ino' => $raw_stat['ino'], 'mtime' => $raw_stat['mtime'],\n"
        "    'ctime' => $raw_stat['ctime'], 'size' => $raw_stat['size'], 'sha256' => hash_file('sha256', $raw_path)),\n"
        "  'raw_dir_identity' => $dir_stat === FALSE ? NULL : array(\n"
        "    'dev' => $dir_stat['dev'], 'ino' => $dir_stat['ino'], 'mtime' => $dir_stat['mtime'],\n"
        "    'ctime' => $dir_stat['ctime']),\n"
        "  'fingerprint' => pfb_dnsbl_reload_fingerprint($pfb),\n"
        "  'reload_generation' => pfb_unbound_py_marker_generation('/var/unbound/pfb_py_reload'),\n"
        "  'applied_generation' => pfb_unbound_py_marker_generation('/var/unbound/pfb_py_reload.applied'),\n"
        ");",
    )


def _file_state(vm: SmokeVM, paths: tuple[str, ...]) -> dict:
    php_paths = "array(" + ",".join(h._php_str(path) for path in paths) + ")"
    return _json_eval(
        vm,
        "$describe = static function ($path) {\n"
        "  if (is_link($path)) { return array('type' => 'link', 'target' => readlink($path)); }\n"
        "  if (is_file($path)) { return array('type' => 'file',\n"
        "    'sha256' => hash_file('sha256', $path), 'size' => filesize($path)); }\n"
        "  if (is_dir($path)) { return array('type' => 'dir'); }\n"
        "  return NULL;\n"
        "};\n"
        f"$out = array(); foreach ({php_paths} as $path) {{\n"
        "  $out[$path] = $describe($path);\n"
        "  if (is_dir($path) && !is_link($path)) {\n"
        "    $entries = array();\n"
        "    $iterator = new RecursiveIteratorIterator(\n"
        "      new RecursiveDirectoryIterator($path, FilesystemIterator::SKIP_DOTS),\n"
        "      RecursiveIteratorIterator::SELF_FIRST);\n"
        "    foreach ($iterator as $entry) {\n"
        "      $relative = substr($entry->getPathname(), strlen($path) + 1);\n"
        "      $entries[$relative] = $describe($entry->getPathname());\n"
        "    }\n"
        "    ksort($entries, SORT_STRING);\n"
        "    $out[$path]['entries'] = $entries;\n"
        "  }\n"
        "}",
        "PFB1542FILES",
    )


def _runtime_state(vm: SmokeVM, *, root: str = "") -> dict:
    """Inventory every pfBlockerNG-owned Unbound path and nested generation member."""
    prefix = root.rstrip("/")
    unbound = f"{prefix}/var/unbound"
    return _json_eval(
        vm,
        f"$prefix = {h._php_str(prefix)};\n"
        "$roots = array_merge(\n"
        f"  glob({h._php_str(unbound + '/pfb_unbound*')}) ?: array(),\n"
        f"  glob({h._php_str(unbound + '/pfb_py_*')}) ?: array()\n"
        ");\n"
        "$out = array();\n"
        "$record = static function ($path) use (&$out, $prefix) {\n"
        "  $key = $prefix !== '' ? substr($path, strlen($prefix)) : $path;\n"
        "  if (is_link($path)) { $out[$key] = array('type' => 'link', 'target' => readlink($path)); }\n"
        "  elseif (is_file($path)) {\n"
        "    $out[$key] = array('type' => 'file',\n"
        "      'sha256' => hash_file('sha256', $path), 'size' => filesize($path));\n"
        "  } elseif (is_dir($path)) { $out[$key] = array('type' => 'dir'); }\n"
        "};\n"
        "foreach (array_unique($roots) as $root) {\n"
        "  if (!file_exists($root) && !is_link($root)) { continue; }\n"
        "  $record($root);\n"
        "  if (is_dir($root) && !is_link($root)) {\n"
        "    $iterator = new RecursiveIteratorIterator(\n"
        "      new RecursiveDirectoryIterator($root, FilesystemIterator::SKIP_DOTS),\n"
        "      RecursiveIteratorIterator::SELF_FIRST);\n"
        "    foreach ($iterator as $entry) { $record($entry->getPathname()); }\n"
        "  }\n"
        "}\n"
        "ksort($out, SORT_STRING);",
        "PFB1542RUNTIME",
    )


def _configure_top1m(vm: SmokeVM) -> None:
    """Configure TOP1M via pfSsh.php -- a no-session CLI caller, hence PfbConfig::writeSystem()
    (the gateway's system-context entry point) rather than the page-authorized
    PfbConfig::writeSection() the DNSBL UI save uses (issue #2071)."""
    result = h.php_eval(
        vm,
        "require_once('/usr/local/pkg/pfblockerng/pfblockerng_extra.inc');\n"
        "PfbConfig::writeSystem('dnsbl/top1m_enable', 'on');\n"
        "PfbConfig::writeSystem('dnsbl/top1m_source', PfbTop1mSource::Tranco);\n"
        "PfbConfig::writeSystem('dnsbl/top1m_count', '1');\n"
        "PfbConfig::writeSystem('dnsbl/top1m_inclusion', 'com');\n"
        "write_config('pfBlockerNG #1542 smoke: enable deterministic TOP1M fixture');\n"
        "echo 'OK';",
    )
    _require_ok(result, "configure TOP1M")
    if "OK" not in result.stdout:
        raise RuntimeError(f"configure TOP1M returned no success sentinel: {result.stdout!r}")


def _stage_top1m_source(vm: SmokeVM, body: str) -> None:
    """Stage provider-shaped CSV with a hash/source-consistent detector baseline."""
    h.write_local_feed(vm, "top-1m.csv", body)
    state = _json_eval(
        vm,
        "require_once('/usr/local/pkg/pfblockerng/pfblockerng.inc');\n"
        "pfb_global();\n"
        f"$base = '{TOP1M_BASE}';\n"
        f"$persisted = pfb_top1m_persist_baseline($base, '{TOP1M_CSV}');\n"
        "$provider = pfb_top1m_active_provider();\n"
        "$source = $pfb['dnsbl_top1m_type'];\n"
        "$source_key = $source instanceof PfbTop1mSource ? $source->value : (string) $source;\n"
        "$headers = pfb_top1m_auth_headers($provider, (string) PfbConfig::read('dnsbl/top1m_token'));\n"
        "$identity = pfb_top1m_source_identity($source_key, $provider['url'], $headers);\n"
        "$source_written = @file_put_contents($base . '.source', $identity, LOCK_EX) !== FALSE;\n"
        "$hash = pfb_hash_read($base);\n"
        "$out = array(\n"
        "  'persisted' => $persisted, 'source_written' => $source_written,\n"
        "  'hash_valid' => ($hash['algo'] ?? '') === 'xxh128'\n"
        "    && ($hash['digest'] ?? '') === pfb_content_hash($base . '.orig', TRUE),\n"
        "  'source_valid' => @file_get_contents($base . '.source') === $identity,\n"
        ");",
        "PFB1542BASELINE",
    )
    assert state == {"persisted": True, "source_written": True, "hash_valid": True, "source_valid": True}, state


def _complete_detector_sidecars(vm: SmokeVM) -> dict:
    """Create valid legacy-hash/validator siblings and verify all six sidecars."""
    return _json_eval(
        vm,
        "require_once('/usr/local/pkg/pfblockerng/pfblockerng.inc');\n"
        "pfb_global();\n"
        f"$base = '{TOP1M_BASE}';\n"
        "$md5 = md5_file($base . '.orig');\n"
        "$md5_written = is_string($md5) && @file_put_contents($base . '.md5', $md5, LOCK_EX) !== FALSE;\n"
        "pfb_validator_write($base . '.orig', '\"pfb-smoke-1542\"', 1700000000);\n"
        "$validators_written = is_file($base . '.orig.etag') && is_file($base . '.orig.lastmod');\n"
        "$provider = pfb_top1m_active_provider();\n"
        "$source = $pfb['dnsbl_top1m_type'];\n"
        "$source_key = $source instanceof PfbTop1mSource ? $source->value : (string) $source;\n"
        "$headers = pfb_top1m_auth_headers($provider, (string) PfbConfig::read('dnsbl/top1m_token'));\n"
        "$identity = pfb_top1m_source_identity($source_key, $provider['url'], $headers);\n"
        "$hash = pfb_hash_read($base);\n"
        "$validators = pfb_validator_read($base . '.orig');\n"
        "$out = array(\n"
        "  'md5_written' => $md5_written, 'validators_written' => $validators_written,\n"
        "  'hash_valid' => ($hash['algo'] ?? '') === 'xxh128'\n"
        "    && ($hash['digest'] ?? '') === pfb_content_hash($base . '.orig', TRUE),\n"
        "  'legacy_hash_valid' => trim((string) @file_get_contents($base . '.md5')) === md5_file($base . '.orig'),\n"
        "  'source_valid' => @file_get_contents($base . '.source') === $identity,\n"
        "  'etag_valid' => ($validators['etag'] ?? FALSE) === '\"pfb-smoke-1542\"',\n"
        "  'lastmod_valid' => ($validators['lastmod'] ?? FALSE) === 1700000000,\n"
        ");",
        "PFB1542SIDECARS",
    )


def _assert_vip(vm: SmokeVM, domain: str, stage: str) -> None:
    answer = h.dns_probe(vm, domain, "A")
    assert h.is_vip(answer), f"{stage}: {domain} should resolve to DNSBL VIP; got {answer}"


def _assert_stub_once(vm: SmokeVM, domain: str, stage: str) -> None:
    answer = h.dns_probe(vm, domain, "A")
    assert h.resolves_to(answer, h.STUB_DNS_A), f"{stage}: {domain} should pass to stub upstream; got {answer}"


@pytest.mark.timeout(600)
def test_top1m_fixed_file_publish_reload_cache_and_teardown(top1m_fixed_file_vm: SmokeVM) -> None:
    vm = top1m_fixed_file_vm
    allowed = h.unique_domain("top1m-fixed-allow")
    sibling = h.unique_domain("top1m-fixed-sibling")
    replacement = h.unique_domain("top1m-fixed-replacement")

    # Start from this test's own TOP1M state; the module fixture restores every path later.
    _remove_exact_paths(
        vm,
        (
            TOP1M_CSV,
            TOP1M_WHITELIST,
            TOP1M_FIXED,
            *SIDECARS,
            NEIGHBOR,
            LOCAL_FEED,
            TOP1M_UPDATE,
            *TEMP_PATHS,
        ),
        "clear TOP1M fixture paths",
    )
    feed = h.write_local_feed(vm, os.path.basename(LOCAL_FEED), f"{allowed}\n{sibling}\n{replacement}\n")
    h.inject(
        vm,
        h.DnsblCase(
            aliasname="Top1mFixedFile", feed_url=feed, header="top1mFixedFile", mode=h.DnsblMode.VIP, hsts=False
        ),
    )
    h.reload(vm, "updatednsbl")

    # Before-state: all three names are genuinely blocked before TOP1M can allow one.
    _assert_vip(vm, allowed, "before TOP1M")
    _assert_vip(vm, sibling, "before TOP1M")
    _assert_vip(vm, replacement, "before TOP1M")

    # Seed a provider-shaped local source plus the required detector baseline.  Their
    # presence makes pfb_top1m_refresh_needed() false, so no provider network runs.
    _configure_top1m(vm)
    _stage_top1m_source(vm, f"1,{allowed}\n2,{sibling}\n")
    h.reload(vm, "update", data_path=True)

    first = _publication_state(vm)
    assert first["fixed_regular"], f"publisher did not create regular {TOP1M_FIXED}: {first!r}"
    assert first["fixed_bytes"] == first["whitelist_bytes"], "fixed file did not preserve publisher bytes"
    assert first["fixed_bytes"] == f"{allowed}\n", f"TOP1M publisher did not emit canonical bytes: {first!r}"
    assert first["top1m_enabled"] is True
    assert first["top1m_keys"] == ["top1m_enabled"], f"manifest embeds retired TOP1M fields: {first!r}"
    assert allowed not in first["manifest_raw"], "manifest embeds TOP1M domain data instead of naming the fixed file"
    assert first["raw_identity"] is not None and first["raw_dir_identity"] is not None

    reader_first_generation = first["reload_generation"]
    assert isinstance(reader_first_generation, int) and reader_first_generation > 0

    h.flush_unbound_name(vm, allowed)
    _assert_stub_once(vm, allowed, "TOP1M allow")
    _assert_vip(vm, sibling, "TOP1M sibling")

    # A TOP1M-only source transition must replace fixed bytes and advance the
    # data reload while leaving the unrelated content-addressed feed generation intact.
    pid_before = h.unbound_pid(vm)
    _stage_top1m_source(vm, f"1,{replacement}\n2,{sibling}\n")
    _require_ok(vm.ssh("/usr/bin/touch", TOP1M_UPDATE), "mark TOP1M source changed")
    h.reload(vm, "update", data_path=True)
    second = _publication_state(vm)

    assert second["fixed_regular"]
    assert second["fixed_bytes"] == second["whitelist_bytes"]
    assert second["fixed_bytes"] != first["fixed_bytes"], "TOP1M-only update retained old fixed-file bytes"
    assert second["fingerprint"] != first["fingerprint"], (
        "TOP1M fixed-file replacement did not change reload fingerprint"
    )
    assert second["reload_generation"] > reader_first_generation, "TOP1M-only update did not advance reload generation"
    assert second["applied_generation"] == second["reload_generation"], "TOP1M reload was not applied before return"
    assert second["raw_rel"] == first["raw_rel"]
    assert second["raw_identity"] == first["raw_identity"], "TOP1M-only update regenerated unrelated feed raw"
    assert second["raw_dir_identity"] == first["raw_dir_identity"], "TOP1M-only update replaced unrelated generation"
    assert h.unbound_pid(vm) == pid_before, "TOP1M-only data change restarted Unbound instead of swapping"

    assert second["fixed_bytes"] == f"{replacement}\n", f"replacement TOP1M bytes not canonical: {second!r}"
    reader_second_generation = second["reload_generation"]
    assert isinstance(reader_second_generation, int)
    assert reader_second_generation > reader_first_generation

    h.flush_unbound_name(vm, allowed)
    h.flush_unbound_name(vm, replacement)
    _assert_vip(vm, allowed, "replaced TOP1M allow")
    _assert_stub_once(vm, replacement, "replacement TOP1M allow")
    _assert_vip(vm, sibling, "replacement TOP1M sibling")

    # Cache preserves the fixed file and exactly six detector sidecars.  A prefix
    # neighbor is deliberately deleted before restore and must not come back.
    assert len(SIDECARS) == 6
    detector_state = _complete_detector_sidecars(vm)
    assert detector_state and all(detector_state.values()), detector_state
    h.write_local_feed(vm, os.path.basename(NEIGHBOR), "not part of exact cache set\n")
    cached_paths = (TOP1M_FIXED, *SIDECARS)
    before_cache = _file_state(vm, cached_paths)
    assert all(value is not None for value in before_cache.values()), before_cache

    _require_ok(
        vm.ssh("/usr/local/pkg/pfblockerng/pfblockerng.sh", "dnsbl_cache", "save", timeout=180.0), "save DNSBL cache"
    )
    archives = _file_state(vm, (f"{CACHE_BASE}.zst", f"{CACHE_BASE}.bz2"))
    assert any(value is not None for value in archives.values()), f"dnsbl_cache save produced no archive: {archives!r}"
    _remove_exact_paths(vm, (TOP1M_FIXED, *SIDECARS, NEIGHBOR), "delete cached TOP1M artifacts")
    _require_ok(
        vm.ssh("/usr/local/pkg/pfblockerng/pfblockerng.sh", "dnsbl_cache", "restore", timeout=180.0),
        "restore DNSBL cache",
    )
    assert _file_state(vm, cached_paths) == before_cache, "cache restore changed TOP1M fixed/sidecar bytes"
    assert _file_state(vm, (NEIGHBOR,))[NEIGHBOR] is None, "cache restored a non-exact TOP1M sidecar neighbor"

    # Keep-on teardown is exercised through the callable production seam: active
    # provider/derived whitelist data remains, runtime derived files and narrow
    # TOP1M detector/staging artifacts disappear.  No destructive pkg uninstall.
    h.write_local_feed(vm, os.path.basename(NEIGHBOR), "preserve-neighbor\n")
    _remove_exact_paths(vm, TEMP_PATHS, "clear TOP1M temp fixture paths")
    _require_ok(vm.ssh("/usr/bin/touch", TEMP_PATHS[0], TEMP_PATHS[2]), "seed TOP1M temp files")
    _require_ok(
        vm.ssh("/bin/mkdir", "-p", f"{TEMP_PATHS[1]}/nested", f"{TEMP_PATHS[3]}/nested"),
        "seed TOP1M temp directories",
    )
    active_before = _file_state(vm, (TOP1M_CSV, TOP1M_WHITELIST, NEIGHBOR))
    raw_path = f"/var/unbound/{second['raw_rel']}"

    teardown = _json_eval(
        vm,
        "require_once('/usr/local/pkg/pfblockerng/pfblockerng.inc');\n"
        "PfbConfig::writeSystem('gen/pfb_keep', PfbToggle::On);\n"
        "write_config('pfBlockerNG #1542 smoke: keep-on callable teardown');\n"
        "pfb_global();\n"
        "$ok = pfb_unbound_py_teardown_raw_set();\n"
        "$keep = PfbConfig::read('gen/pfb_keep');\n"
        "$out = array('ok' => $ok, 'keep' => $keep instanceof PfbToggle ? $keep->value : (string) $keep);",
        "PFB1542TEARDOWN",
    )
    assert teardown == {"ok": True, "keep": "on"}, teardown

    removed = (TOP1M_FIXED, *SIDECARS, MANIFEST, raw_path, *TEMP_PATHS)
    assert all(value is None for value in _file_state(vm, removed).values()), "teardown left derived TOP1M artifacts"
    assert _file_state(vm, (TOP1M_CSV, TOP1M_WHITELIST, NEIGHBOR)) == active_before, (
        "keep-on teardown changed active provider/whitelist data or an unrelated sidecar neighbor"
    )
