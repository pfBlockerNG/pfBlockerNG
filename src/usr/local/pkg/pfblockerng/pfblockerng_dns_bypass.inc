<?php

declare(strict_types=1);

// [ ADR-36 / ADR-37 ] DNS-bypass containment — firewall controls that keep
// clients on the pfSense resolver:
//   * ADR-36: optional NAT redirect of plaintext port-53 DNS to the resolver.
//   * ADR-37: optional filter BLOCK of DoT (TCP 853) / DoQ (UDP 853).
//
// Pure builder helpers — no shell/exec, no write_config calls.
// write_config() is always the CALLER'S responsibility.
//
// The sections handled here (nat/rule, filter/rule) are pfSense-core foreign
// sections (ADR-29 exclusion list) — direct config_get_path/config_set_path
// is correct; the RequireConfigGateway sniff does NOT flag pfSense-core paths.
//
// The three registered config keys (dnsbl_redir, dnsbl_redir_int,
// dnsbl_redir_exclude) live in installedpackages/pfblockerngdnsblsettings/
// config/0 and are read exclusively via PfbConfig::read() (ADR-29).

// ---------------------------------------------------------------------------
// Description / marker constants
// ---------------------------------------------------------------------------

/**
 * NAT rdr rule descr prefix for inet (IPv4) DNS-redirect rules.
 * Pattern: pfB_DNS_Redirect_<iface>_v4
 * Must start with 'pfB_' so pfb_fwobj_is_owned() recognises it.
 * Must NOT contain 'pfB DNSBL' (space) — pfb_create_dnsbl() would
 * incorrectly bucket the rule as a DNSBL rule and attempt to remove it.
 */
define('PFB_DNS_REDIR_DESCR_V4_PFX', 'pfB_DNS_Redirect_');

/**
 * Suffix for inet (IPv4) DNS-redirect descr markers.
 * Full descr: PFB_DNS_REDIR_DESCR_V4_PFX . $iface . PFB_DNS_REDIR_DESCR_V4_SFX
 */
define('PFB_DNS_REDIR_DESCR_V4_SFX', '_v4');

/**
 * Suffix for inet6 (IPv6) DNS-redirect descr markers.
 * Full descr: PFB_DNS_REDIR_DESCR_V4_PFX . $iface . PFB_DNS_REDIR_DESCR_V6_SFX
 */
define('PFB_DNS_REDIR_DESCR_V6_SFX', '_v6');

// ---------------------------------------------------------------------------
// pfb_build_dns_redirect_rules — per-interface, per-family rule-set builder
// ---------------------------------------------------------------------------

/**
 * Build the NAT rdr rule + associated filter PASS rule for one interface/family.
 *
 * Ground-truth rule shape (from maintainer's working config.xml — ADR-36 §2.2):
 *
 *   <rule>                                        <!-- nat/rule -->
 *     <!-- source: negated exception alias; <any> when alias is empty -->
 *     <source><address>EXCEPTION_ALIAS</address><not></not></source>
 *     <!-- destination: negated (self) = firewall-self-exempt; port 53 -->
 *     <destination><network>(self)</network><not></not><port>53</port></destination>
 *     <ipprotocol>inet</ipprotocol>
 *     <protocol>tcp/udp</protocol>
 *     <target>127.0.0.1</target>                  <!-- inet; inet6 => ::1 -->
 *     <local-port>53</local-port>
 *     <interface>lan</interface>
 *     <descr><![CDATA[pfB_DNS_Redirect_lan_v4]]></descr>
 *     <associated-rule-id>nat_...</associated-rule-id>
 *     <natreflection>disable</natreflection>
 *   </rule>
 *
 * Invariants (all asserted by PHPUnit golden tests in DnsRedirectBuilderTest.php):
 *   • destination is always negated (self) + port 53 — firewall-self-exempt is
 *     structurally present in every generated rule.
 *   • source is negated-alias when $exception is non-empty; <any> when empty.
 *   • target is '127.0.0.1' for inet; '::1' for inet6.
 *   • natreflection is 'disable' on every rule.
 *   • protocol is 'tcp/udp' on every rule.
 *   • local-port is '53' on every rule.
 *   • descr carries the pfBlockerNG marker (pfB_DNS_Redirect_<iface>_v4/v6) in
 *     BOTH the NAT entry [0] and the associated filter PASS entry [1].
 *
 * @param  string $iface       pfSense interface name (e.g. 'lan', 'opt1').
 * @param  string $ipprotocol  IP family: 'inet' (IPv4) or 'inet6' (IPv6).
 * @param  string $exception   Exception alias/IP string. Empty string = no exception.
 *
 * @return array{0: array<string,mixed>, 1: array<string,mixed>}
 *   [0] => NAT rdr rule config array (for nat/rule).
 *   [1] => Associated filter PASS rule config array (for filter/rule).
 *
 * @throws \InvalidArgumentException if $ipprotocol is not 'inet' or 'inet6'.
 */
function pfb_build_dns_redirect_rules(string $iface, string $ipprotocol, string $exception): array
{
	if ($ipprotocol !== 'inet' && $ipprotocol !== 'inet6') {
		throw new \InvalidArgumentException(
			"pfb_build_dns_redirect_rules: ipprotocol must be 'inet' or 'inet6', got '{$ipprotocol}'"
		);
	}

	$is_v4  = ($ipprotocol === 'inet');
	$target = $is_v4 ? '127.0.0.1' : '::1';
	$suffix = $is_v4 ? PFB_DNS_REDIR_DESCR_V4_SFX : PFB_DNS_REDIR_DESCR_V6_SFX;
	$descr  = PFB_DNS_REDIR_DESCR_V4_PFX . $iface . $suffix;

	// -----------------------------------------------------------------------
	// Source element:
	//   When $exception is set: <source><address>$exception</address><not/></source>
	//   When $exception is empty: <source><any/></source>
	// -----------------------------------------------------------------------
	if ($exception !== '') {
		$source = [
			'address' => $exception,
			'not'     => '',
		];
	} else {
		$source = [
			'any' => '',
		];
	}

	// -----------------------------------------------------------------------
	// Destination element (always negated (self) + port 53):
	//   <destination><network>(self)</network><not/><port>53</port></destination>
	// -----------------------------------------------------------------------
	$destination = [
		'network' => '(self)',
		'not'     => '',
		'port'    => '53',
	];

	// -----------------------------------------------------------------------
	// NAT rdr rule [0]
	// -----------------------------------------------------------------------
	$nat_rule = [
		'source'          => $source,
		'destination'     => $destination,
		'ipprotocol'      => $ipprotocol,
		'protocol'        => 'tcp/udp',
		'target'          => $target,
		'local-port'      => '53',
		'interface'       => $iface,
		'descr'           => $descr,
		'natreflection'   => 'disable',
	];

	// -----------------------------------------------------------------------
	// Associated filter PASS rule [1]
	// The associated-rule-id wiring is pfSense's responsibility at apply time;
	// the builder populates the fields that pfSense writes when creating an
	// associated filter rule for a NAT rdr entry.
	// -----------------------------------------------------------------------
	$filter_rule = [
		'source'      => $source,
		'destination' => [
			'address' => $target,
			'port'    => '53',
		],
		'ipprotocol'  => $ipprotocol,
		'protocol'    => 'tcp/udp',
		'interface'   => $iface,
		'descr'       => $descr,
		'type'        => 'pass',
	];

	return [$nat_rule, $filter_rule];
}

// ---------------------------------------------------------------------------
// pfb_fwobj_init_dns_redirect_registrations — register DNS-redirect spec
// ---------------------------------------------------------------------------

/**
 * Registers the DNS-redirect NAT and filter objects into the ADR-35 registry.
 *
 * Two registrations — one per pfSense-core section — both keyed on the shared
 * PFB_DNS_REDIR_DESCR_V4_PFX prefix. Because pfb_fwobj_remove() / pfb_fwobj_sweep()
 * use str_starts_with() for pfB_-prefixed markers, a single prefix registration
 * covers every per-interface / per-family descr variant:
 *   pfB_DNS_Redirect_lan_v4, pfB_DNS_Redirect_lan_v6,
 *   pfB_DNS_Redirect_opt1_v4, pfB_DNS_Redirect_opt1_v6, …
 *
 * Call at any point after pfblockerng_dns_bypass.inc is loaded — before
 * pfb_fwobj_sweep() or pfb_fwobj_remove() targets DNS-redirect objects.
 * Idempotent (pfb_fwobj_register replaces the prior entry by key).
 *
 * write_config() is NEVER called here — callers own the flush.
 */
function pfb_fwobj_init_dns_redirect_registrations(): void
{
	// NAT rdr rules — one per interface/family, marker prefix covers all variants.
	pfb_fwobj_register([
		'type'    => 'nat',
		'section' => 'nat/rule',
		'marker'  => PFB_DNS_REDIR_DESCR_V4_PFX,
		'builder' => NULL,	// rules built by pfb_sync_dns_redirect_rules(); NULL = seam-only
		'guard'   => NULL,
	]);

	// Associated filter PASS rules — same prefix covers all variants.
	pfb_fwobj_register([
		'type'    => 'filter',
		'section' => 'filter/rule',
		'marker'  => PFB_DNS_REDIR_DESCR_V4_PFX,
		'builder' => NULL,	// rules built by pfb_sync_dns_redirect_rules(); NULL = seam-only
		'guard'   => NULL,
	]);
}

// ---------------------------------------------------------------------------
// pfb_validate_dns_redirect_post — server-side validator (PFBL-01 surface)
// ---------------------------------------------------------------------------

/**
 * Validate the DNS-redirect fields submitted via the DNSBL settings POST form.
 *
 * Called by the POST handler in pfblockerng_dnsbl.php before any PfbConfig::write()
 * call. Performs the PFBL-01 semantic validation that escapeshellarg() alone cannot
 * provide: each interface name is checked against the allow-list returned by
 * pfb_build_if_list(); the exception alias name is validated by is_validaliasname()
 * when non-empty.
 *
 * @param  array  $posted_ifaces    Array of interface names from the POST multi-select
 *                                  (may be empty when no interfaces selected).
 * @param  array  $valid_iface_list Flat array of valid interface keys (keys of the array
 *                                  returned by pfb_build_if_list(FALSE, FALSE)).
 * @param  string $posted_alias     Exception alias name from the POST text input.
 *                                  Empty string is accepted.
 *
 * @return string[]  Validation error messages. Empty array = all inputs valid.
 */
function pfb_validate_dns_redirect_post(
	array $posted_ifaces,
	array $valid_iface_list,
	string $posted_alias
): array {
	$errors = [];

	// Validate each selected interface against the allow-list.
	foreach ($posted_ifaces as $iface) {
		if (!in_array($iface, $valid_iface_list, TRUE)) {
			$errors[] = 'DNS Redirect: Invalid interface selection: ' .
				htmlspecialchars((string) $iface, ENT_QUOTES);
		}
	}

	// Validate the exception alias name when non-empty.
	if ($posted_alias !== '') {
		if (!is_validaliasname($posted_alias)) {
			$errors[] = 'DNS Redirect: Invalid exception alias name: ' .
				htmlspecialchars($posted_alias, ENT_QUOTES);
		}
	}

	return $errors;
}

// ---------------------------------------------------------------------------
// pfb_sync_dns_redirect_rules — lifecycle: create / reconcile / prune / remove
// ---------------------------------------------------------------------------

/**
 * Create, reconcile, prune-stale, or remove all pfB_DNS_Redirect_* NAT + filter rules.
 *
 * Called from sync_package_pfblockerng() after pfb_create_dnsbl(). Reads the three
 * registered PfbConfig fields and manages nat/rule + filter/rule via direct
 * config_*_path (pfSense-core foreign sections — ADR-29 exclusion list).
 *
 * Lifecycle:
 *   ENABLED + interfaces selected:
 *     1. For each validated interface, call pfb_build_dns_redirect_rules() for inet
 *        and inet6.  Upsert each rule set: if the rule already exists (idempotent
 *        reconcile), skip; otherwise append.
 *     2. Stale-interface prune: remove rules for interfaces that are no longer in the
 *        selected set (marker scan with guard on current iface set).
 *
 *   DISABLED or no interfaces:
 *     Remove ALL pfB_DNS_Redirect_* rules via pfb_fwobj_remove() on both sections.
 *
 * Returns TRUE iff config was mutated (caller may choose to write_config).
 * write_config() is NEVER called here — caller decides when to flush.
 *
 * Validation: each interface name is pfb_filter(PFB_FILTER_WORD) -validated before
 * use. Invalid names are logged and skipped (defence-in-depth; the UI also validates).
 *
 * @return bool  TRUE if nat/rule or filter/rule was changed.
 */
function pfb_sync_dns_redirect_rules(): bool
{
	$changed = FALSE;

	// [ ADR-29 ] Read registered fields through the PfbConfig gateway.
	$redir_toggle = PfbConfig::read('dnsbl_redir');

	// PfbToggle::On means 'on' stored value; anything else is off.
	// The toggle adapter returns a PfbToggle enum; compare .value to the stored string.
	$enabled = ($redir_toggle instanceof PfbToggle && $redir_toggle === PfbToggle::On);

	if (!$enabled) {
		// DISABLED: remove all pfB_DNS_Redirect_* NAT rules.
		if (pfb_fwobj_remove('nat/rule', PFB_DNS_REDIR_DESCR_V4_PFX)) {
			$changed = TRUE;
		}
		// Remove all pfB_DNS_Redirect_* filter rules.
		if (pfb_fwobj_remove('filter/rule', PFB_DNS_REDIR_DESCR_V4_PFX)) {
			$changed = TRUE;
		}
		return $changed;
	}

	// ENABLED: read interfaces (comma-separated) and exception alias.
	$iface_raw = (string) PfbConfig::read('dnsbl_redir_int');
	$exception  = trim((string) PfbConfig::read('dnsbl_redir_exclude'));

	// Split, trim, filter empty entries.
	$ifaces_raw = array_filter(array_map('trim', explode(',', $iface_raw)), 'strlen');

	// Validate and collect known-good interfaces via PFB_FILTER_WORD.
	$ifaces = [];
	foreach ($ifaces_raw as $iface_entry) {
		$validated = pfb_filter($iface_entry, PFB_FILTER_WORD, 'pfb_sync_dns_redirect_rules');
		if (empty($validated)) {
			// Interface name failed validation — skip with a log entry.
			pfb_logger(
				"\npfb_sync_dns_redirect_rules: interface failed validation [ " .
				substr(htmlspecialchars((string) $iface_entry), 0, 100) . " ] *skipping*", 2
			);
			continue;
		}
		$ifaces[] = $validated;
	}

	// If no valid interfaces remain, remove all rules and return.
	if (empty($ifaces)) {
		if (pfb_fwobj_remove('nat/rule', PFB_DNS_REDIR_DESCR_V4_PFX)) {
			$changed = TRUE;
		}
		if (pfb_fwobj_remove('filter/rule', PFB_DNS_REDIR_DESCR_V4_PFX)) {
			$changed = TRUE;
		}
		return $changed;
	}

	// -----------------------------------------------------------------------
	// Build the expected marker set for the current iface × family grid.
	// -----------------------------------------------------------------------
	$expected_descrs = [];
	foreach ($ifaces as $iface) {
		$expected_descrs[] = PFB_DNS_REDIR_DESCR_V4_PFX . $iface . PFB_DNS_REDIR_DESCR_V4_SFX;
		$expected_descrs[] = PFB_DNS_REDIR_DESCR_V4_PFX . $iface . PFB_DNS_REDIR_DESCR_V6_SFX;
	}

	// -----------------------------------------------------------------------
	// Stale-interface prune: remove pfB_DNS_Redirect_* rows whose descr is NOT
	// in the expected set (i.e. they belong to a previously-selected interface).
	// -----------------------------------------------------------------------
	$stale_guard = static function (array $row) use ($expected_descrs): bool {
		$descr = $row['descr'] ?? '';
		// Remove if it is a DNS-redirect marker not in the current expected set.
		return str_starts_with($descr, PFB_DNS_REDIR_DESCR_V4_PFX)
			&& !in_array($descr, $expected_descrs, TRUE);
	};

	if (pfb_fwobj_remove('nat/rule', PFB_DNS_REDIR_DESCR_V4_PFX, $stale_guard)) {
		$changed = TRUE;
	}
	if (pfb_fwobj_remove('filter/rule', PFB_DNS_REDIR_DESCR_V4_PFX, $stale_guard)) {
		$changed = TRUE;
	}

	// -----------------------------------------------------------------------
	// Idempotent upsert: for each interface × family, write the rule set if
	// the marker is not already present in the config section.
	// -----------------------------------------------------------------------
	foreach ($ifaces as $iface) {
		foreach (['inet', 'inet6'] as $family) {
			$suffix = ($family === 'inet') ? PFB_DNS_REDIR_DESCR_V4_SFX : PFB_DNS_REDIR_DESCR_V6_SFX;
			$marker = PFB_DNS_REDIR_DESCR_V4_PFX . $iface . $suffix;

			// Check existence in nat/rule.
			$nat_exists = (pfb_fwobj_find('nat/rule', $marker) !== FALSE);
			// Check existence in filter/rule.
			$filter_exists = (pfb_fwobj_find('filter/rule', $marker) !== FALSE);

			if ($nat_exists && $filter_exists) {
				// Both present — idempotent; skip.
				continue;
			}

			// Build the rule pair.
			[$nat_rule, $filter_rule] = pfb_build_dns_redirect_rules($iface, $family, $exception);

			if (!$nat_exists) {
				$nat_rows   = config_get_path('nat/rule', []);
				$nat_rows[] = $nat_rule;
				config_set_path('nat/rule', $nat_rows);
				$changed = TRUE;
			}

			if (!$filter_exists) {
				$filter_rows   = config_get_path('filter/rule', []);
				$filter_rows[] = $filter_rule;
				config_set_path('filter/rule', $filter_rows);
				$changed = TRUE;
			}
		}
	}

	return $changed;
}

// ---------------------------------------------------------------------------
// ADR-37 — DoT/DoQ BLOCK rule builder (skeleton; Phase 2 implements)
//
// pfb_build_dot_block_rule — build one filter/rule BLOCK entry for a single
// interface, blocking TCP+UDP port 853 (DoT/DoQ) on both IPv4 and IPv6.
//
// The rule shape (ground truth from §2.2 of ADR.md):
//   type         => 'block'
//   interface    => $iface
//   ipprotocol   => 'inet46'
//   protocol     => 'tcp/udp'
//   source       => <any/> when $exclude_alias is empty;
//                   <address>ALIAS</address><not/> when non-empty.
//   destination  => <network>(self)</network><not/><port>853</port>
//                   (self-exempt always on — cannot be disabled)
//   statetype    => 'keep state'
//   descr        => 'pfB_DoT_Block_' . $iface  (ADR-35 ownership marker)
//
// Phase 2 replaces this stub with the full implementation.
//
// @param string $iface          Interface name (e.g. 'lan', 'opt1').
// @param string $exclude_alias  Optional exception alias name (or '').
//                               When non-empty, the source is negated
//                               (exception hosts bypass the block rule).
// @return array{}               Phase 2: returns the filter/rule array.
//                               Phase 1 skeleton: throws LogicException.
// ---------------------------------------------------------------------------
function pfb_build_dot_block_rule(string $iface, string $exclude_alias): array
{
	// Phase 1 skeleton — replaced in Phase 2.
	// Returns an empty array so callers do not crash; the golden tests in
	// DotDoQBlockRuleTest FAIL (not error) against this stub, which is the
	// oracle-first discipline: tests specify the contract, not the implementation.
	return [];
}
