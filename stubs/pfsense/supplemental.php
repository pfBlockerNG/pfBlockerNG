<?php
/**
 * pfSense supplemental stubs — IDE/PHPStan static analysis only.
 *
 * Hand-maintained. Holds pfSense functions AND classes that pfBlockerNG calls
 * on its supported target (CE 2.8) but which are ABSENT from the pinned
 * stub-source version used by scripts/update-pfsense-stubs.py (currently
 * 2.7.2 — the newest public pfSense source; Netgate's GitHub mirror has no
 * RELENG_2_8_0 ref) — plus symbols the generator can never cover: a bundled
 * third-party library pfSense's core requires (Net_IPv6) and a native PHP
 * extension function with no PHP source at all (pfSense_get_pf_rules).
 *
 * The generator never overwrites this file (it is not a STUB_MODULES output),
 * and its symbols seed the generator's cross-file dedup set. Drop an entry once
 * the stub-source version catches up and the generator provides the function.
 *
 * Not shipped in release archives (stubs/ is dev-only).
 */

// @codingStandardsIgnoreFile

/** Read and parse the pfSense configuration (config.lib.inc; pfSense CE 2.8+). */
function config_read_file(bool $use_backup = false, bool $use_cache = true): array {}

/** Return true if the current logged-in user may access $page, per their privilege match list (priv.inc). */
function isAllowedPage($page) {}

/**
 * HA/XMLRPC config-sync client (etc/inc/xmlrpc_client.inc; stable CE 2.8.0..master,
 * dated commit ed6c2eb8 2025-05-28 — mirror carries no RELENG_2_8_0 ref). Upstream
 * has more members (xmlrpc_exec_php/get_error/getUrl); only what pfBlockerNG
 * calls is declared.
 */
class pfsense_xmlrpc_client
{
    public function __construct() {}

    public function setConnectionData(mixed $syncip, mixed $port, mixed $username, mixed $password, mixed $scheme = ''): void {}

    public function xmlrpc_method(string $method, mixed $parameter = '', int $timeout = 240): mixed {}
}

/**
 * PEAR Net_IPv6 (etc/inc/util.inc: require_once('Net/IPv6.php')) — a bundled
 * third-party library, not pfSense-authored; https://github.com/pear/Net_IPv6.
 * Only the member pfBlockerNG calls is declared.
 */
class Net_IPv6
{
    public static function isInNetmask(string $ip, string $netmask, mixed $bits = null): bool {}
}

/**
 * Begin/end a buffered PHP session (etc/inc/phpsessionmanager.inc; stable
 * CE 2.8.0..master, dated commit ed6c2eb8 2025-05-28).
 */
function phpsession_begin(): void {}

function phpsession_end(bool $write = false): void {}

/**
 * Native PHP extension function (pfSense-utils; no PHP source to cite) —
 * returns the live pf ruleset with packet/byte counters, one row per rule.
 * Shape inferred from its sole call site in pfblockerng.widget.php.
 */
function pfSense_get_pf_rules(mixed ...$args): array {}
