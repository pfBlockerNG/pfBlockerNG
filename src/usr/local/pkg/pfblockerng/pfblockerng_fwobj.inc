<?php

declare(strict_types=1);

// [ ADR-35 ] Managed firewall objects — ownership / marker layer.
//
// This file is a PURE helper include: no shell/exec, no write_config calls.
// write_config() is always the CALLER'S responsibility (mirrors PfbConfig contract).
//
// The sections handled here (virtualip/vip, nat/rule, filter/rule) are pfSense-core
// foreign sections (ADR-29 exclusion list) — direct config_get_path/config_set_path
// is correct; the RequireConfigGateway sniff does NOT flag pfSense-core paths.

// ---------------------------------------------------------------------------
// Recognised-marker constants
//
// NOTE: PFB_AUTO_VIP_DESCR_V4 ('pfB_AUTO_VIP_v4') and PFB_AUTO_VIP_DESCR_V6
// ('pfB_AUTO_VIP_v6') are defined in pfblockerng.inc — do NOT redefine them here.
// The str_starts_with($descr, PFB_FWOBJ_FILTER_PFX) check in pfb_fwobj_is_owned()
// already subsumes them (both start with 'pfB_'), but they are called out explicitly
// in comments below for clarity.
// ---------------------------------------------------------------------------

/** Full NAT rule description written by pfBlockerNG (the canonical new form). */
define('PFB_FWOBJ_NAT_DESCR', 'pfB DNSBL - DO NOT EDIT');

/** Legacy NAT prefix: any descr CONTAINING this prefix is owned (covers bare 'pfB DNSBL'
 *  and any variant suffixed with extra text, e.g. the ' - DO NOT EDIT' form above). */
define('PFB_FWOBJ_NAT_LEGACY_PFX', 'pfB DNSBL');

/** Filter-rule prefix: any rule descr that STARTS WITH this prefix is owned. */
define('PFB_FWOBJ_FILTER_PFX', 'pfB_');

// ---------------------------------------------------------------------------
// Internal registry (static state; populated by pfb_fwobj_register()).
// ---------------------------------------------------------------------------

/**
 * Return a reference to the internal registry array (static singleton).
 *
 * @return array<string,array{type:string,section:string,marker:string,builder:callable,guard:callable|null}>
 */
function &pfb_fwobj_registry(): array
{
	static $registry = [];
	return $registry;
}

// ---------------------------------------------------------------------------
// pfb_fwobj_is_owned — ownership predicate
// ---------------------------------------------------------------------------

/**
 * Returns TRUE iff $descr indicates pfBlockerNG ownership.
 *
 * Recognised patterns (UNION — any one match → owned):
 *   • str_starts_with($descr, 'pfB_')    — new prefix (covers PFB_AUTO_VIP_DESCR_V4/V6)
 *   • str_contains($descr, 'pfB DNSBL') — legacy NAT marker (bare AND ' - DO NOT EDIT' form)
 *
 * An empty descr or a user-owned description ('My rule', 'WAN', …) returns FALSE.
 */
function pfb_fwobj_is_owned(string $descr): bool
{
	if ($descr === '') {
		return FALSE;
	}
	// New prefix — also subsumes PFB_AUTO_VIP_DESCR_V4 ('pfB_AUTO_VIP_v4')
	//              and PFB_AUTO_VIP_DESCR_V6 ('pfB_AUTO_VIP_v6').
	if (str_starts_with($descr, PFB_FWOBJ_FILTER_PFX)) {
		return TRUE;
	}
	// Legacy NAT marker: covers 'pfB DNSBL' (bare) and 'pfB DNSBL - DO NOT EDIT'.
	if (str_contains($descr, PFB_FWOBJ_NAT_LEGACY_PFX)) {
		return TRUE;
	}
	return FALSE;
}

// ---------------------------------------------------------------------------
// pfb_fwobj_find — locate the first owned row matching $marker
// ---------------------------------------------------------------------------

/**
 * Reads config_get_path($section, []) and returns the FIRST row whose 'descr'
 * satisfies pfb_fwobj_is_owned() AND matches $marker:
 *   • If $marker starts with PFB_FWOBJ_FILTER_PFX ('pfB_'): str_starts_with match.
 *   • Otherwise: exact string equality (covers legacy 'pfB DNSBL' variants and
 *     the full 'pfB DNSBL - DO NOT EDIT' marker; caller passes the exact token).
 *
 * If $guard is provided it is called with the candidate row and must return TRUE to
 * accept the row (FALSE skips it — e.g. to filter by interface or subnet).
 *
 * Returns the matching row array, or FALSE if no row matches.
 *
 * $section: config path string, e.g. 'virtualip/vip', 'nat/rule', 'filter/rule'.
 *
 * @param string        $section  Config path string.
 * @param string        $marker   Descr marker to match (exact, or pfB_ prefix match).
 * @param callable|null $guard    Optional row-level predicate; TRUE = accept.
 * @return array<string,mixed>|false  First matching row, or FALSE.
 */
function pfb_fwobj_find(string $section, string $marker, ?callable $guard = NULL): array|false
{
	$use_prefix = str_starts_with($marker, PFB_FWOBJ_FILTER_PFX);

	foreach (config_get_path($section, []) as $row) {
		$descr = $row['descr'] ?? '';

		if (!pfb_fwobj_is_owned($descr)) {
			continue;
		}

		// Marker match: prefix or exact.
		if ($use_prefix) {
			if (!str_starts_with($descr, $marker)) {
				continue;
			}
		} else {
			if ($descr !== $marker) {
				continue;
			}
		}

		// Optional guard: skip when the guard rejects.
		if ($guard !== NULL && !$guard($row)) {
			continue;
		}

		return $row;
	}

	return FALSE;
}

// ---------------------------------------------------------------------------
// pfb_fwobj_remove — strip owned rows matching $marker from a section
// ---------------------------------------------------------------------------

/**
 * Reads config_get_path($section, []), filters OUT every row where:
 *   (a) pfb_fwobj_is_owned($row['descr']) is TRUE, AND
 *   (b) the descr matches $marker (same prefix/exact logic as pfb_fwobj_find), AND
 *   (c) when $guard is provided, $guard($row) returns TRUE.
 *
 * Any row that fails the ownership check (a) is NEVER removed — user-safety invariant.
 *
 * When at least one row was removed the filtered array is written back via
 * config_set_path(). No write is performed when nothing matched (caller decides when
 * to flush; write_config() is NEVER called here).
 *
 * Returns TRUE if at least one row was removed, FALSE if nothing matched.
 *
 * @param string        $section  Config path string.
 * @param string        $marker   Descr marker to remove (exact, or pfB_ prefix match).
 * @param callable|null $guard    Optional row-level predicate; TRUE = also remove.
 */
function pfb_fwobj_remove(string $section, string $marker, ?callable $guard = NULL): bool
{
	$use_prefix = str_starts_with($marker, PFB_FWOBJ_FILTER_PFX);
	$rows       = config_get_path($section, []);
	$filtered   = [];
	$removed    = FALSE;

	foreach ($rows as $row) {
		$descr = $row['descr'] ?? '';

		// Ownership check: user rows are NEVER removed regardless of $marker.
		if (!pfb_fwobj_is_owned($descr)) {
			$filtered[] = $row;
			continue;
		}

		// Marker match: prefix or exact.
		$marker_match = $use_prefix
			? str_starts_with($descr, $marker)
			: ($descr === $marker);

		if (!$marker_match) {
			$filtered[] = $row;
			continue;
		}

		// Guard check: when guard rejects, keep the row.
		if ($guard !== NULL && !$guard($row)) {
			$filtered[] = $row;
			continue;
		}

		// Row matches all criteria — remove it.
		$removed = TRUE;
	}

	if ($removed) {
		config_set_path($section, $filtered);
	}

	return $removed;
}

// ---------------------------------------------------------------------------
// pfb_fwobj_sweep — remove ALL owned rows from a set of sections (deinstall)
// ---------------------------------------------------------------------------

/**
 * Iterates each section in $sections. For each, removes every row where
 * pfb_fwobj_is_owned($row['descr']) is TRUE.
 *
 * Idempotent: if no owned rows exist, nothing is written and FALSE is returned.
 * write_config() is NEVER called here — caller flushes when done.
 *
 * Returns TRUE if anything was removed across any section, FALSE otherwise.
 *
 * @param list<string> $sections  Config path strings to sweep.
 */
function pfb_fwobj_sweep(array $sections): bool
{
	$any_removed = FALSE;

	foreach ($sections as $section) {
		$rows     = config_get_path($section, []);
		$filtered = [];
		$removed  = FALSE;

		foreach ($rows as $row) {
			if (pfb_fwobj_is_owned($row['descr'] ?? '')) {
				$removed = TRUE;
			} else {
				$filtered[] = $row;
			}
		}

		if ($removed) {
			config_set_path($section, $filtered);
			$any_removed = TRUE;
		}
	}

	return $any_removed;
}

// ---------------------------------------------------------------------------
// pfb_fwobj_register — register a firewall-object spec
// ---------------------------------------------------------------------------

/**
 * Registers a firewall-object spec into the internal static registry.
 *
 * $spec shape:
 *   ['type'    => 'vip'|'nat'|'filter',
 *    'section' => string,          // config path, e.g. 'virtualip/vip'
 *    'marker'  => string,          // descr marker (pfB_ prefix or exact legacy)
 *    'builder' => callable,        // called by pfb_fwobj_reconcile when absent; no args
 *    'guard'   => callable|null]   // optional find predicate (same as pfb_fwobj_find)
 *
 * Keyed by $spec['marker']. Replaces any prior registration for the same marker.
 * Does NOT immediately create anything — call pfb_fwobj_reconcile() to ensure presence.
 *
 * @param array{type:string,section:string,marker:string,builder:callable,guard:callable|null} $spec
 */
function pfb_fwobj_register(array $spec): void
{
	$registry          = &pfb_fwobj_registry();
	$registry[$spec['marker']] = $spec;
}

// ---------------------------------------------------------------------------
// pfb_fwobj_reconcile — ensure a registered object exists (idempotent)
// ---------------------------------------------------------------------------

/**
 * Finds the registration for $marker; if the object is not yet present in config,
 * calls $spec['builder']() to create it and writes the result via config_set_path.
 *
 * Idempotent: when the object already exists (pfb_fwobj_find returns a row) the
 * builder is NOT called and config is NOT written.
 *
 * write_config() is NEVER called here — caller flushes.
 *
 * @param string $marker  The marker key as registered via pfb_fwobj_register().
 * @throws \InvalidArgumentException  When $marker is not registered.
 */
function pfb_fwobj_reconcile(string $marker): void
{
	$registry = &pfb_fwobj_registry();

	if (!isset($registry[$marker])) {
		throw new \InvalidArgumentException(
			"pfb_fwobj_reconcile: marker '" . $marker . "' is not registered"
		);
	}

	$spec = $registry[$marker];

	// If the object already exists, nothing to do.
	$existing = pfb_fwobj_find($spec['section'], $marker, $spec['guard'] ?? NULL);
	if ($existing !== FALSE) {
		return;
	}

	// Object absent — call the builder to create the row and insert it.
	$new_row = ($spec['builder'])();
	$rows    = config_get_path($spec['section'], []);
	$rows[]  = $new_row;
	config_set_path($spec['section'], $rows);
}
