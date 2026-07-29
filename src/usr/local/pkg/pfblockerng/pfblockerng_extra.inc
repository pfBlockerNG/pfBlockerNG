<?php
/*
 * pfblockerng_extra.inc
 *
 * part of pfSense (https://www.pfsense.org)
 * Copyright (c) 2015-2026 Rubicon Communications, LLC (Netgate)
 * Copyright (c) 2015-2024 BBcan177@gmail.com
 * All rights reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

// This file is used to 'include functions' not yet merged into pfSense

// ---------------------------------------------------------------------------
// ADR-28 — config field enums (PfbStoredEnum contract): read = EnumClass::fromStored($raw)
// (registry default applied first; '' / legacy / junk resolved by the enum), write =
// $enum->toStored(). Goal: preserve forward-upgrade behaviour while keeping current
// canonical storage; an unknown token falls through to the safe default.
// Tests: tests/php/CfgAdaptersTest.php.
// ---------------------------------------------------------------------------

// PfbStoredEnum — the contract every config-backed enum implements. Keeps the
// reader/writer dumb: read = EnumClass::fromStored($raw), write = $enum->toStored().
interface PfbStoredEnum
{
	// Parse-fallback for unknown/non-scalar input. NOT the per-field absent default
	// (that is the registry's $entry['default'], applied by PfbConfig::read()).
	public static function default(): static;

	// Stored config value (string, NULL, or non-scalar) -> enum. The enum owns its
	// '' (EMPTY), legacy-alias, and junk handling.
	public static function fromStored(mixed $stored): static;

	// Enum -> the canonical token persisted to config.xml / py_unbound.ini.
	public function toStored(): string;
}

// PfbStoredEnumAdapter — shared fromStored/toStored mechanics. An enum customises
// its semantics by setting default() (fallback) and overriding fromLegacy() (aliases).
trait PfbStoredEnumAdapter
{
	public static function fromStored(mixed $stored): static
	{
		// Idempotency: a value already adapted to this enum (e.g. a PfbConfig::read()
		// result fed back through the read adapter) returns itself. Without this, the
		// non-scalar guard below would collapse a valid enum to default() — a double-apply
		// footgun that silently mis-rendered toggle checkboxes (always-unchecked) on the
		// settings pages.
		if ($stored instanceof static) {
			return $stored;
		}
		if (!is_scalar($stored) && $stored !== NULL) {
			return static::default();		// subtree / non-scalar guard
		}
		// NULL collapses to '' here — a gateway read has already applied the registry
		// per-field default, so NULL only reaches this path from direct callers.
		$raw = (string) ($stored ?? '');
		return self::tryFrom($raw) ?? static::fromLegacy($raw);
	}

	// '' (EMPTY) and any non-canonical token. Override per enum for legacy aliases.
	protected static function fromLegacy(string $raw): static
	{
		return static::default();
	}

	public function toStored(): string
	{
		return $this->value;
	}
}

// PfbToggle — checkbox fields stored as 'on' (checked) or '' (unchecked).
//   Stored vocabulary: 'on' | '' (missing/unchecked = ''). '' is the Off case, so
//   tryFrom('') resolves it directly; the per-field absent default is the registry's.
enum PfbToggle: string implements PfbStoredEnum
{
	use PfbStoredEnumAdapter;

	case On  = 'on';
	case Off = '';

	// Parse-fallback ONLY (unknown/non-scalar -> "not On"). NOT the absent default.
	public static function default(): static
	{
		return self::Off;
	}
}

// PfbLenient — tri-state {on, off, legacy ''} flag; explicit 'off' survives the config
// round-trip where a toggle's '' off-value would not. Used by pfb_dnsbl_lenient (ADR-22
// scheme-parsing leniency) and pfb_keep (#484, default-on keep storing 'off' explicitly).
// Stored vocabulary: 'on' | 'off' | '' (legacy missing key -> Off, NOT PfbToggle's '').
enum PfbLenient: string implements PfbStoredEnum
{
	use PfbStoredEnumAdapter;

	case On  = 'on';
	case Off = 'off';

	// NULL/absent -> registry default; '' (legacy missing) and junk -> Off (via fromLegacy).
	public static function default(): static
	{
		return self::Off;
	}
}

// PfbIdnMode — ADR-08 IDN-feature mode selector, adopted into the PfbConfig gateway.
// Used by pfb_idn / $pfb['dnsbl_idn']. Canonical tokens (config.xml, py_unbound.ini, and
// the Python IdnMode enum share one vocabulary): 'on' (=All), 'confusable', 'off'; '' /
// unknown -> Off. Reusing 'on' for All keeps existing installs migration-free and
// preserves the established block-all-IDN behaviour.
enum PfbIdnMode: string implements PfbStoredEnum
{
	use PfbStoredEnumAdapter;

	// All reuses the original 'on' token (pre-ADR-08 block-all-IDN) as its backing value:
	// it round-trips with ZERO migration and preserves the established block-all-IDN
	// behaviour. Only Confusable is a genuinely new token (unknown values are
	// treated as off, which is acceptable). The SAME token feeds config.xml, py_unbound.ini,
	// and the Python IdnMode enum — one canonical vocabulary, no per-consumer serialisation.
	case All        = 'on';
	case Confusable = 'confusable';
	case Off        = 'off';

	// Parse-fallback (unknown / '' -> Off via the trait); the per-field absent default is
	// the registry's. No legacy alias: the only other historical token was the 4.0.0-alpha
	// 'all', and breaking alpha-only compatibility is acceptable.
	public static function default(): static
	{
		return self::Off;
	}
}

// PfbAliasDeltaMode — ADR-40 alias-table apply mechanism selector.
//   Auto    ('auto')    — default; delta for small churn (< ~5%), full replace for
//                         initial load / boot / large churn.
//   Delta   ('delta')   — ALWAYS forward delta, no large-churn replace fallback.
//   Replace ('replace') — always full -T replace (pre-ADR-40 behaviour).
// Absent-default 'auto' reaches only brand-new installs; an existing install is
// grandfathered to 'replace' at install/upgrade (pfb_alias_delta_mode_install_default()).
enum PfbAliasDeltaMode: string implements PfbStoredEnum
{
	use PfbStoredEnumAdapter;

	case Auto    = 'auto';
	case Delta   = 'delta';
	case Replace = 'replace';

	public static function default(): static
	{
		return self::Auto;
	}
}

// PfbTop1mSource — TOP1M source selector (alexa_type, issue #877).
// Used by alexa_type (config key) / $pfb['dnsbl_top1m_type'] (runtime). Canonical tokens:
// 'tranco' (default), 'cisco', 'openpagerank' (#928, replacing ADR-59's 'domcop'),
// 'majestic' (ADR-59), 'cloudflare' (ADR-59, token-authenticated). 'alexa' (#872) and
// 'domcop' (#928) are READ-ONLY legacy tokens, coalesced to their replacement on read — the
// write vocabulary only ever emits live canonical tokens.
enum PfbTop1mSource: string implements PfbStoredEnum
{
	use PfbStoredEnumAdapter;

	case Tranco       = 'tranco';
	case Cisco        = 'cisco';
	case OpenPageRank = 'openpagerank';
	case Majestic     = 'majestic';
	case Cloudflare   = 'cloudflare';

	// Legacy 'alexa' (dead service, #872) -> Tranco; legacy 'domcop' (list moved
	// hosting to OpenPageRank, #928) -> OpenPageRank; any other unknown/'' token -> Tranco.
	protected static function fromLegacy(string $raw): static
	{
		return match ($raw) {
			'domcop' => self::OpenPageRank,
			default  => self::Tranco,
		};
	}

	// Parse-fallback ONLY (unknown/non-scalar -> Tranco). NOT the absent default
	// (that is the registry's $entry['default'], also 'tranco').
	public static function default(): static
	{
		return self::Tranco;
	}
}

// TOP1M provider descriptor table (ADR-59). Keyed by PfbTop1mSource::value.
// pfblockerng.php's TOP1M URL selection and pfblockerng_top1m() read
// 'parse'/'header'/'domain_col' to drive the builder; 'container' is INFORMATIONAL ONLY —
// pfb_download() branches on the actually-detected MIME type, not this field, so a mismatch
// (e.g. a zip provider serving an HTML error page) is caught by pfblockerng_top1m()'s
// domain-validity guard instead (#892). 'domain_col' is 0-indexed (str_getcsv() array
// index): Tranco/Cisco/OpenPageRank -> 1, Majestic -> 2, Cloudflare's single 'domain'
// column (no rank) -> 0. 'auth' is read by pfb_download()'s header-auth path via
// pfb_top1m_auth_headers() below: 'none' or {header, scheme} (Cloudflare's Bearer token).
//
// @return array<string, array{url: string, container: string, parse: string, header: bool, domain_col: int, columns: int, auth: string|array{header: string, scheme: string}, label: string, licence: string}>
function pfb_top1m_providers(): array
{
	return array(
		PfbTop1mSource::Tranco->value	=> array(
			'url'		=> 'https://tranco-list.eu/top-1m.csv.zip',
			'container'	=> 'zip',
			'parse'		=> 'rank_domain',
			'header'	=> FALSE,
			'domain_col'	=> 1,
			'columns'	=> 2,
			'auth'		=> 'none',
			'label'		=> 'Tranco',
			'licence'	=> '',
		),
		PfbTop1mSource::Cisco->value	=> array(
			'url'		=> 'https://s3-us-west-1.amazonaws.com/umbrella-static/top-1m.csv.zip',
			'container'	=> 'zip',
			'parse'		=> 'rank_domain',
			'header'	=> FALSE,
			'domain_col'	=> 1,
			'columns'	=> 2,
			'auth'		=> 'none',
			'label'		=> 'Cisco Umbrella',
			'licence'	=> '',
		),
		// OpenPageRank top-10M (registered-domain breadth; formerly hosted by
		// DomCop, #928 -- the DomCop URL froze 2026-03-29 when the list's hosting
		// moved): zipped CSV, unquoted 5-col header
		// (Rank,Domain,Extension,Open Page Rank,Referring Domains), Domain at
		// str_getcsv() index 1.
		PfbTop1mSource::OpenPageRank->value	=> array(
			'url'		=> 'https://openpagerank.keywordseverywhere.com/downloads/top10milliondomains.csv.zip',
			'container'	=> 'zip',
			'parse'		=> 'csv',
			'header'	=> TRUE,
			'domain_col'	=> 1,
			'columns'	=> 5,
			'auth'		=> 'none',
			'label'		=> 'OpenPageRank',
			'licence'	=> '',
		),
		// Majestic Million: PLAIN (uncompressed) CSV, unquoted 12-col header
		// (GlobalRank,TldRank,Domain,TLD,...), Domain at str_getcsv() index 2.
		PfbTop1mSource::Majestic->value	=> array(
			'url'		=> 'https://downloads.majestic.com/majestic_million.csv',
			'container'	=> 'plain',
			'parse'		=> 'csv',
			'header'	=> TRUE,
			'domain_col'	=> 2,
			'columns'	=> 12,
			'auth'		=> 'none',
			'label'		=> 'Majestic Million',
			'licence'	=> 'CC BY 3.0 — attribution required',
		),
		// Cloudflare Radar ranking bucket (ADR-59). VERIFIED against Cloudflare's own
		// current docs (developers.cloudflare.com/radar/investigate/domain-ranking-datasets/,
		// developers.cloudflare.com/api/resources/radar/subresources/datasets/) rather than
		// the ADR's original 2-column guess:
		//   - GET /radar/datasets/{alias} streams the dataset's CSV content directly given a
		//     STABLE alias ('ranking_top_1000000' for the 1,000,000-domain bucket -- id 213,
		//     tags ['GLOBAL','top_1000000']) -- a single request, exactly like every other
		//     provider here, NOT the two/three-call discover-id -> POST /datasets/download ->
		//     fetch-signed-URL flow the ADR worried might be disproportionately complex (§7).
		//   - The body is PLAIN (uncompressed) CSV with a header row reading literally
		//     'domain' and ONE column per row (no rank) -- domain_col is 0, not 1 (the ADR's
		//     guess assumed a 2-column rank,domain shape like Tranco/Cisco).
		//   - Auth: 'Authorization: Bearer <token>' (confirmed on every Radar API page), fed
		//     via pfb_top1m_auth_headers() below + the $feed['headers'] plumbing.
		//   - Licence: CC BY-NC 4.0 (developers.cloudflare.com/radar/ "About" -- confirmed by
		//     web search, non-commercial use, attribution required).
		// Residual verification gap (disclosed, not hidden): no live authenticated request was
		// made (no Cloudflare token available in this environment) to prove the alias/URL end
		// to end -- confirmed via two independent official Cloudflare doc pages instead. A real
		// token on a live box (ADR §7 definition-of-done manual smoke) is the final proof.
		PfbTop1mSource::Cloudflare->value	=> array(
			'url'		=> 'https://api.cloudflare.com/client/v4/radar/datasets/ranking_top_1000000',
			'container'	=> 'plain',
			'parse'		=> 'csv',
			'header'	=> TRUE,
			'domain_col'	=> 0,
			'columns'	=> 1,
			'auth'		=> array('header' => 'Authorization', 'scheme' => 'Bearer'),
			'label'		=> 'Cloudflare Radar',
			'licence'	=> 'CC BY-NC 4.0 — non-commercial use, attribution required',
		),
	);
}

// ADR-59: build the caller header(s) a provider's 'auth' descriptor needs. Pure / no I/O,
// so it is unit-testable and -- because it never logs -- the token only ever reaches
// pfb_download()'s CURLOPT_HTTPHEADER, never a log line. 'auth' is 'none' (keyless) or
// {header, scheme} (Cloudflare's Bearer token); an empty token/keyless provider yields
// array() so pfb_download() sends no Authorization header -- the #886 preserve+warn path
// keeps the previous TOP1M whitelist and warns on a resulting failure.
//
// @return string[] zero or one header line, e.g. ['Authorization: Bearer <token>'].
function pfb_top1m_auth_headers(array $provider, string $token): array
{
	$auth = $provider['auth'] ?? 'none';
	if (!is_array($auth) || empty($auth['header']) || $token === '') {
		return array();
	}
	// Defense-in-depth (#892 review): a token stored via a non-UI path (hand-edited
	// config.xml, HA sync, a restored backup) is not re-validated by PFB_FILTER_TOKEN --
	// strip CR/LF here so it can never inject an extra header/split the request.
	$token  = str_replace(["\r", "\n"], '', $token);
	$scheme = $auth['scheme'] ?? '';
	$value  = ($scheme !== '') ? "{$scheme} {$token}" : $token;
	return array("{$auth['header']}: {$value}");
}

/** Read a PfbAliasDeltaMode from a raw stored value. */
function pfb_cfg_alias_delta_mode_read(mixed $stored): PfbAliasDeltaMode
{
	return PfbAliasDeltaMode::fromStored($stored);
}

/** Write a PfbAliasDeltaMode back to its canonical stored token. */
function pfb_cfg_alias_delta_mode_write(PfbAliasDeltaMode|string $mode): string
{
	return ($mode instanceof PfbAliasDeltaMode ? $mode : PfbAliasDeltaMode::fromStored($mode))->toStored();
}

// Thin delegations to the enum adapters (PfbStoredEnum::fromStored / toStored).
// Kept so the registry callables + the direct www/ callers have a free-function
// handle; all semantics live on the enums.

/** Read a PfbToggle from a raw stored value. */
function pfb_cfg_toggle_read(mixed $stored): PfbToggle
{
	return PfbToggle::fromStored($stored);
}

/** Write a PfbToggle (enum or legacy string) back to its stored string. */
function pfb_cfg_toggle_write(PfbToggle|string $toggle): string
{
	return ($toggle instanceof PfbToggle ? $toggle : PfbToggle::fromStored($toggle))->toStored();
}

/** Read a PfbLenient from a raw stored value. */
function pfb_cfg_lenient_read(mixed $stored): PfbLenient
{
	return PfbLenient::fromStored($stored);
}

/** Write a PfbLenient (enum or legacy string) back to its stored string. */
function pfb_cfg_lenient_write(PfbLenient|string $lenient): string
{
	return ($lenient instanceof PfbLenient ? $lenient : PfbLenient::fromStored($lenient))->toStored();
}

/** Read a PfbIdnMode from a raw stored value (legacy 'on' -> All). */
function pfb_cfg_idn_mode_read(mixed $stored): PfbIdnMode
{
	return PfbIdnMode::fromStored($stored);
}

/**
 * Write a PfbIdnMode (enum or legacy string) back to its canonical stored token
 * ('on' | 'confusable' | 'off'). All persists as the legacy 'on' token (reproduces
 * the prior block-all-IDN behaviour); the 4.0.0-alpha 'all' token is dropped to 'off'.
 */
function pfb_cfg_idn_mode_write(PfbIdnMode|string $mode): string
{
	return ($mode instanceof PfbIdnMode ? $mode : PfbIdnMode::fromStored($mode))->toStored();
}

/** Read a PfbTop1mSource from a raw stored value (legacy 'alexa' -> Tranco, 'domcop' -> OpenPageRank). */
function pfb_cfg_top1m_source_read(mixed $stored): PfbTop1mSource
{
	return PfbTop1mSource::fromStored($stored);
}

/**
 * Write a PfbTop1mSource (enum or legacy string) back to its canonical stored
 * token ('tranco' | 'cisco' | 'openpagerank' | 'majestic' | 'cloudflare'). The
 * dead legacy 'alexa' token (#872) and the moved legacy 'domcop' token (#928)
 * are never re-emitted — fromStored() already coalesced them to Tranco /
 * OpenPageRank respectively before this runs.
 */
function pfb_cfg_top1m_source_write(PfbTop1mSource|string $source): string
{
	return ($source instanceof PfbTop1mSource ? $source : PfbTop1mSource::fromStored($source))->toStored();
}

// ---------------------------------------------------------------------------
// ADR-29 — PfbConfig gateway: the single sanctioned gateway for config.xml reads/writes of
// registered installedpackages/pfblockerng* keys, wrapping config_get/set/del_path with the
// registered default + field adapter (ADR-28) at the boundary.
// CONSTRAINTS (ADR-29 §5, ADR-28 §2.2 + 2026-07-20 amendments): registry keys are the EXACT
// existing config.xml keys (no renames); adapters accept supported forward-upgrade legacy
// tokens and write the current canonical string; write(read(v)) == v for every canonical value.
// Tests: tests/php/CfgGatewayTest.php (round-trip, default, inventory).
// ---------------------------------------------------------------------------

/**
 * pfb_cfg_registry — the declarative field registry for all registered
 * installedpackages/pfblockerng* scalar keys.
 *
 * Returns a flat map of config-key => descriptor. Keys are the exact strings
 * used in config.xml, grouped loosely by config section.
 *
 * Read adapter: callable(mixed $stored): <enum|string>  — stored string -> runtime value.
 * Write adapter: callable(<enum|string> $value): string — runtime value -> stored string.
 * null adapter = plain string (identity; no conversion).
 *
 * @return array<string,array{section:string,default:string,read_adapter:callable|null,write_adapter:callable|null}>
 */
function pfb_cfg_registry(): array
{
	static $registry = NULL;
	if ($registry !== NULL) {
		return $registry;
	}

	// -----------------------------------------------------------------------
	// Section: installedpackages/pfblockerng/config/0  (general settings)
	// -----------------------------------------------------------------------
	$gen = 'installedpackages/pfblockerng/config/0';

	// -----------------------------------------------------------------------
	// Section: installedpackages/pfblockerngdnsblsettings/config/0
	// -----------------------------------------------------------------------
	$dnsbl = 'installedpackages/pfblockerngdnsblsettings/config/0';

	// -----------------------------------------------------------------------
	// Section: installedpackages/pfblockerngsafesearch  (flat, no /config/0)
	// -----------------------------------------------------------------------
	$ss = 'installedpackages/pfblockerngsafesearch';

	// -----------------------------------------------------------------------
	// Section: installedpackages/pfblockerngipsettings/config/0
	// -----------------------------------------------------------------------
	$ip = 'installedpackages/pfblockerngipsettings/config/0';

	$registry = [

		// -------------------------------------------------------------------
		// General section (pfblockerng/config/0)
		// -------------------------------------------------------------------

		// Settings snapshot schema marker. Missing installs are the legacy 3.2 family.
		'settings_family' => [
			'section'       => $gen,
			'default'       => '3.2',
			'read_adapter'  => NULL,
			'write_adapter' => NULL,
		],

		// Master enable/disable: 'on' | '' (checkbox).
		'enable_cb' => [
			'section'       => $gen,
			'default'       => '',
			'read_adapter'  => 'pfb_cfg_toggle_read',
			'write_adapter' => 'pfb_cfg_toggle_write',
		],

		// Keep blocklists when pfBlockerNG is disabled: 'on' | 'off' | ''.
		// Default ON — the #281 canonical default; GUI and pfb_global() agree.
		// Uses the lenient adapter so an unchecked-save (off) is stored as the
		// explicit 'off' token, distinguishable from a never-configured install
		// (key absent) which the registry default returns as 'on'. The empty-string
		// '' is a LEGACY READ token for installs written before this fix; it maps
		// to Off on read, same as 'off'. Write always emits canonical 'off'.
		'pfb_keep' => [
			'section'       => $gen,
			'default'       => 'on',
			'read_adapter'  => 'pfb_cfg_lenient_read',
			'write_adapter' => 'pfb_cfg_lenient_write',
		],

		// Update interval: numeric hour string | 'Disabled'. Default '1'.
		'pfb_interval' => [
			'section'       => $gen,
			'default'       => '1',
			'read_adapter'  => NULL,
			'write_adapter' => NULL,
		],

		// Cron start minute ('0'|'15'|'30'|'45'). Default '0'.
		'pfb_min' => [
			'section'       => $gen,
			'default'       => '0',
			'read_adapter'  => NULL,
			'write_adapter' => NULL,
		],

		// Cron start hour (0-23 as string). Default '0'.
		'pfb_hour' => [
			'section'       => $gen,
			'default'       => '0',
			'read_adapter'  => NULL,
			'write_adapter' => NULL,
		],

		// Once-a-day start hour (0-23 as string). Default '0'.
		'pfb_dailystart' => [
			'section'       => $gen,
			'default'       => '0',
			'read_adapter'  => NULL,
			'write_adapter' => NULL,
		],

		// Max daily download failure threshold ('0' = unlimited). Default '0'.
		'skipfeed' => [
			'section'       => $gen,
			'default'       => '0',
			'read_adapter'  => NULL,
			'write_adapter' => NULL,
		],

		// ADR-11: CSV of active aggregate alias types (e.g. 'Deny,Permit'). Default ''.
		'pfb_agg_types' => [
			'section'       => $gen,
			'default'       => '',
			'read_adapter'  => NULL,
			'write_adapter' => NULL,
		],

		// Log rotation limits (all numeric strings; default '20000').
		'log_max_log' => [
			'section'       => $gen,
			'default'       => '20000',
			'read_adapter'  => NULL,
			'write_adapter' => NULL,
		],
		'log_max_errlog' => [
			'section'       => $gen,
			'default'       => '20000',
			'read_adapter'  => NULL,
			'write_adapter' => NULL,
		],
		'log_max_extraslog' => [
			'section'       => $gen,
			'default'       => '20000',
			'read_adapter'  => NULL,
			'write_adapter' => NULL,
		],
		'log_max_ip_blocklog' => [
			'section'       => $gen,
			'default'       => '20000',
			'read_adapter'  => NULL,
			'write_adapter' => NULL,
		],
		'log_max_ip_permitlog' => [
			'section'       => $gen,
			'default'       => '20000',
			'read_adapter'  => NULL,
			'write_adapter' => NULL,
		],
		'log_max_ip_matchlog' => [
			'section'       => $gen,
			'default'       => '20000',
			'read_adapter'  => NULL,
			'write_adapter' => NULL,
		],
		'log_max_ip_parse_err' => [
			'section'       => $gen,
			'default'       => '20000',
			'read_adapter'  => NULL,
			'write_adapter' => NULL,
		],
		'log_max_dnslog' => [
			'section'       => $gen,
			'default'       => '20000',
			'read_adapter'  => NULL,
			'write_adapter' => NULL,
		],
		'log_max_dnsbl_parse_err' => [
			'section'       => $gen,
			'default'       => '20000',
			'read_adapter'  => NULL,
			'write_adapter' => NULL,
		],
		'log_max_dnsreplylog' => [
			'section'       => $gen,
			'default'       => '20000',
			'read_adapter'  => NULL,
			'write_adapter' => NULL,
		],
		'log_max_unilog' => [
			'section'       => $gen,
			'default'       => '20000',
			'read_adapter'  => NULL,
			'write_adapter' => NULL,
		],
	];

	$log_types = [
		'log', 'errlog', 'extraslog', 'ip_blocklog', 'ip_permitlog',
		'ip_matchlog', 'ip_parse_err', 'dnslog', 'dnsbl_parse_err', 'dnsreplylog', 'unilog',
	];

	// ADR-60: per-log age-based retention cap (days; '0' = off), independent of
	// log_max_<type>'s line-count cap and its 'nolimit' opt-out (S2.2/S2.3 item 3).
	foreach ($log_types as $log_type) {
		$registry['log_max_days_' . $log_type] = [
			'section'       => $gen,
			'default'       => '0',
			'read_adapter'  => NULL,
			'write_adapter' => NULL,
		];
	}

	$registry = $registry + [

		// issue #1109: log-retention trim hysteresis margin percent (global,
		// applies uniformly to both the line-count and age caps). Default '0'.
		'pfb_log_trim_margin_pct' => [
			'section'       => $gen,
			'default'       => '0',
			'read_adapter'  => NULL,
			'write_adapter' => NULL,
		],

		// Software update check last-seen version (string or null). Default ''.
		'pfb_software_check' => [
			'section'       => $gen,
			'default'       => '',
			'read_adapter'  => NULL,
			'write_adapter' => NULL,
		],

		// Internal-address feed-host filter toggle: 'on'|'off'. Default 'on' (new install).
		'pfb_feed_internal_filter' => [
			'section'       => $gen,
			'default'       => 'on',
			'read_adapter'  => NULL,
			'write_adapter' => NULL,
		],

		// Allowlist for internal-feed hosts (base64-encoded). Default ''.
		'pfb_feed_internal_allowlist' => [
			'section'       => $gen,
			'default'       => '',
			'read_adapter'  => NULL,
			'write_adapter' => NULL,
		],

		// ADR-49: opt-in plain-text feed sanity scan. Checkbox 'on'|''(off).
		// Default off (absent = off = today's behaviour: the scan never runs).
		'pfb_feed_sanity' => [
			'section'       => $gen,
			'default'       => '',                       // absent -> Off (new-install default too)
			'read_adapter'  => 'pfb_cfg_toggle_read',
			'write_adapter' => 'pfb_cfg_toggle_write',
		],

		// Reuse blocklists across updates: 'on' | '' (checkbox). Default ''.
		'pfb_reuse' => [
			'section'       => $gen,
			'default'       => '',
			'read_adapter'  => 'pfb_cfg_toggle_read',
			'write_adapter' => 'pfb_cfg_toggle_write',
		],

		// ADR-40: alias-table apply mode: 'auto' | 'delta' | 'replace'. New-install default 'auto'.
		// 'auto' = delta for small churn (< ~5%), full replace for initial load / large churn;
		// 'delta' = ALWAYS forward delta, NO large-churn replace fallback (power-user override);
		// 'replace' = always full -T replace (pre-ADR-40 behaviour).
		// Existing installs are grandfather-seeded to 'replace' at install/upgrade
		// (pfb_alias_delta_mode_install_default); only brand-new installs take the 'auto' default.
		'pfb_alias_delta_mode' => [
			'section'       => $gen,
			'default'       => 'auto',
			'read_adapter'  => 'pfb_cfg_alias_delta_mode_read',
			'write_adapter' => 'pfb_cfg_alias_delta_mode_write',
		],

		// ADR-40: alias-table delta batch size (integer as string). Default '512'.
		// Clamped to [64, 4096] on read. Batch=512 is optimal for sub-1M tables
		// (zero ICMP stalls at 100k/1k-churn); batch=1024+ for 1M+ tables.
		'pfb_alias_delta_batch' => [
			'section'       => $gen,
			'default'       => '512',
			'read_adapter'  => NULL,
			'write_adapter' => NULL,
		],

		// ADR-43: tick-cron dispatch interval in minutes (1–60). Default '15'.
		// One cron tick fires every */pfb_tick_interval; jobs run only when due
		// per the due-ledger. Default 15 matches the tightest existing job (ss_refresh).
		'pfb_tick_interval' => [
			'section'       => $gen,
			'default'       => '15',
			'read_adapter'  => NULL,
			'write_adapter' => NULL,
		],

		// ADR-43: optional apply-on-change maintenance window ("HH:MM-HH:MM", local time).
		// When set: detected changes outside the window are deferred (pending); the first tick
		// inside the window applies them. Empty string (default) = apply immediately (no deferral).
		// Wrapping windows (e.g. "23:00-03:00") span midnight. Malformed = fail-safe (apply now).
		'pfb_quiet_hours' => [
			'section'       => $gen,
			'default'       => '',
			'read_adapter'  => NULL,
			'write_adapter' => NULL,
		],

		// issue #1669 slice C: client-side syntax highlighting for regex list fields
		// (CodeMirror 6), gating asset emission on pfblockerng_dnsbl.php. NEW feature --
		// no prior behaviour to preserve, so both fresh installs and upgraders take the
		// same 'on' absent-default; no grandfather seed is needed (config-gateway.md's
		// two-case forward-compat rule). Uses the LENIENT adapter, not PfbToggle -- a
		// TOGGLE field's '' off-value cannot survive the live config round-trip when the
		// default is 'on' (absent collapses back to the default, silently re-enabling a
		// deliberate off; the #484 pfb_keep bug class, enforced by
		// CfgGatewayTest::testNoToggleFieldDefaultsToOn). Mirrors pfb_keep exactly.
		'pfb_syntax_highlight' => [
			'section'       => $gen,
			'default'       => 'on',
			'read_adapter'  => 'pfb_cfg_lenient_read',
			'write_adapter' => 'pfb_cfg_lenient_write',
		],

		// -------------------------------------------------------------------
		// DNSBL settings section (pfblockerngdnsblsettings/config/0)
		// -------------------------------------------------------------------

		// DNSBL master enable: 'on' | '' (checkbox).
		'pfb_dnsbl' => [
			'section'       => $dnsbl,
			'default'       => '',
			'read_adapter'  => 'pfb_cfg_toggle_read',
			'write_adapter' => 'pfb_cfg_toggle_write',
		],

		// ADR-13: auto-create/remove DNSBL sinkhole VIPs: 'on' | '' (checkbox).
		'pfb_dnsvip_auto' => [
			'section'       => $dnsbl,
			'default'       => '',
			'read_adapter'  => 'pfb_cfg_toggle_read',
			'write_adapter' => 'pfb_cfg_toggle_write',
		],

		// [ #381 ] Opt out of automatic DNSBL sinkhole NAT rule generation: 'on' | '' (checkbox).
		// Default '' = NAT generated (current behaviour); 'on' = user manages NAT manually.
		'pfb_dnsbl_nonat' => [
			'section'       => $dnsbl,
			'default'       => '',
			'read_adapter'  => 'pfb_cfg_toggle_read',
			'write_adapter' => 'pfb_cfg_toggle_write',
		],

		// VIP interface for DNSBL sinkhole. Default 'lo0'.
		'dnsbl_interface' => [
			'section'       => $dnsbl,
			'default'       => 'lo0',
			'read_adapter'  => NULL,
			'write_adapter' => NULL,
		],

		// DNSBL IPv4 sinkhole VIP id string. Default ''.
		'pfb_dnsvip4' => [
			'section'       => $dnsbl,
			'default'       => '',
			'read_adapter'  => NULL,
			'write_adapter' => NULL,
		],

		// DNSBL IPv6 sinkhole VIP id string. Default ''.
		'pfb_dnsvip6' => [
			'section'       => $dnsbl,
			'default'       => '',
			'read_adapter'  => NULL,
			'write_adapter' => NULL,
		],

		// DNSBL lighttpd HTTP port. Default '' (system default).
		'pfb_dnsport' => [
			'section'       => $dnsbl,
			'default'       => '',
			'read_adapter'  => NULL,
			'write_adapter' => NULL,
		],

		// DNSBL lighttpd HTTPS port. Default ''.
		'pfb_dnsport_ssl' => [
			'section'       => $dnsbl,
			'default'       => '',
			'read_adapter'  => NULL,
			'write_adapter' => NULL,
		],

		// TOP1M whitelist enable. Default ''.
		'alexa_enable' => [
			'section'       => $dnsbl,
			'default'       => '',
			'read_adapter'  => NULL,
			'write_adapter' => NULL,
		],

		// TOP1M type selector: 'tranco' | 'cisco' | 'openpagerank' | 'majestic' | 'cloudflare'.
		// Legacy 'alexa' (dead service, #872) coalesces to 'tranco', and legacy 'domcop'
		// (list moved hosting, #928) coalesces to 'openpagerank', at the read boundary
		// via pfb_cfg_top1m_source_read(). Default 'tranco'.
		'alexa_type' => [
			'section'       => $dnsbl,
			'default'       => 'tranco',
			'read_adapter'  => 'pfb_cfg_top1m_source_read',
			'write_adapter' => 'pfb_cfg_top1m_source_write',
		],

		// TOP1M domain count (numeric string). Default '1000'.
		'alexa_count' => [
			'section'       => $dnsbl,
			'default'       => '1000',
			'read_adapter'  => NULL,
			'write_adapter' => NULL,
		],

		// TOP1M TLD inclusions for whitelisting. Default ''.
		'alexa_inclusion' => [
			'section'       => $dnsbl,
			'default'       => '',
			'read_adapter'  => NULL,
			'write_adapter' => NULL,
		],

		// ADR-59: masked, write-only Cloudflare Radar Bearer token -- consumed only
		// when alexa_type == 'cloudflare' (every other provider ignores it), fed to
		// pfb_download() via pfb_top1m_auth_headers() + the header-auth plumbing.
		// Plain string (no adapter): the DNSBL page never echoes the stored value back
		// on GET, and a blank POST preserves the existing value rather than clearing it
		// (pfblockerng_dnsbl.php's save handler) -- see PFB_FILTER_TOKEN (pfblockerng.inc)
		// for the accepted charset. Default ''.
		'top1m_token' => [
			'section'       => $dnsbl,
			'default'       => '',
			'read_adapter'  => NULL,
			'write_adapter' => NULL,
		],

		// Resolver cache backup/restore option. Default ''.
		'pfb_cache' => [
			'section'       => $dnsbl,
			'default'       => '',
			'read_adapter'  => NULL,
			'write_adapter' => NULL,
		],

		// Full resolver-cache flush after a successful DNSBL data swap. Default off.
		'pfb_cache_flush' => [
			'section'       => $dnsbl,
			'default'       => '',
			'read_adapter'  => 'pfb_cfg_toggle_read',
			'write_adapter' => 'pfb_cfg_toggle_write',
		],

		// Global logging/blocking mode. Default ''.
		'global_log' => [
			'section'       => $dnsbl,
			'default'       => '',
			'read_adapter'  => NULL,
			'write_adapter' => NULL,
		],

		// ADR-22: scheme-parsing leniency: 'on' | 'off' | ''. Default 'off'.
		// PfbLenient adapter (off-value = 'off', not '').
		'pfb_dnsbl_lenient' => [
			'section'       => $dnsbl,
			'default'       => 'off',
			'read_adapter'  => 'pfb_cfg_lenient_read',
			'write_adapter' => 'pfb_cfg_lenient_write',
		],

		// Python DNS reply logging. Default ''.
		'pfb_py_reply' => [
			'section'       => $dnsbl,
			'default'       => '',
			'read_adapter'  => NULL,
			'write_adapter' => NULL,
		],

		// HSTS null-blocking mode: 'on' | ''. Default ''.
		'pfb_hsts' => [
			'section'       => $dnsbl,
			'default'       => '',
			'read_adapter'  => 'pfb_cfg_toggle_read',
			'write_adapter' => 'pfb_cfg_toggle_write',
		],

		// ADR-08: IDN mode — adopted into the gateway as a PfbIdnMode enum (ADR-28
		// reframe: preserve behaviour on upgrade, not byte-identical storage). Read
		// normalises legacy 'on' -> All; write persists the canonical token
		// ('on'=All | 'confusable' | 'off'), reusing the pre-4.0.0 'on' token so All
		// round-trips with zero migration. Legacy '' and the 4.0.0-alpha 'all' token
		// read as Off; unknown tokens also fall through to Off.
		// See ADR-28 §2.2 + CfgAdaptersTest.
		'pfb_idn' => [
			'section'       => $dnsbl,
			'default'       => '',
			'read_adapter'  => 'pfb_cfg_idn_mode_read',
			'write_adapter' => 'pfb_cfg_idn_mode_write',
		],

		// Confusable: block malicious homoglyphs (default on). Default 'on'.
		'pfb_idn_block_malicious' => [
			'section'       => $dnsbl,
			'default'       => 'on',
			'read_adapter'  => NULL,
			'write_adapter' => NULL,
		],

		// Confusable: escalate suspicious mixed-script to block (opt-in). Default ''.
		'pfb_idn_escalate_suspicious' => [
			'section'       => $dnsbl,
			'default'       => '',
			'read_adapter'  => NULL,
			'write_adapter' => NULL,
		],

		// Python regex: 'on' | ''. Default ''.
		'pfb_regex' => [
			'section'       => $dnsbl,
			'default'       => '',
			'read_adapter'  => NULL,
			'write_adapter' => NULL,
		],

		// Python regex list (textarea). Default ''.
		'pfb_regex_list' => [
			'section'       => $dnsbl,
			'default'       => '',
			'read_adapter'  => NULL,
			'write_adapter' => NULL,
		],

		// Python regex static cap ('on'|''). Default ''.
		'pfb_regex_cap' => [
			'section'       => $dnsbl,
			'default'       => '',
			'read_adapter'  => NULL,
			'write_adapter' => NULL,
		],

		// CNAME validation. Default ''.
		'pfb_cname' => [
			'section'       => $dnsbl,
			'default'       => '',
			'read_adapter'  => NULL,
			'write_adapter' => NULL,
		],

		// TLD Allow option. Default ''.
		'pfb_pytld' => [
			'section'       => $dnsbl,
			'default'       => '',
			'read_adapter'  => NULL,
			'write_adapter' => NULL,
		],

		// Log events via DNSBL Webserver vs python. Default ''.
		'pfb_py_nolog' => [
			'section'       => $dnsbl,
			'default'       => '',
			'read_adapter'  => NULL,
			'write_adapter' => NULL,
		],

		// No AAAA blocking: 'on' | ''. Default ''.
		'pfb_noaaaa' => [
			'section'       => $dnsbl,
			'default'       => '',
			'read_adapter'  => NULL,
			'write_adapter' => NULL,
		],

		// No AAAA list (textarea). Default ''.
		'pfb_noaaaa_list' => [
			'section'       => $dnsbl,
			'default'       => '',
			'read_adapter'  => NULL,
			'write_adapter' => NULL,
		],

		// DNSBL bypass enable: 'on' | ''. Default ''.
		'pfb_gp' => [
			'section'       => $dnsbl,
			'default'       => '',
			'read_adapter'  => NULL,
			'write_adapter' => NULL,
		],

		// DNSBL bypass local IP list (textarea). Default ''.
		'pfb_gp_bypass_list' => [
			'section'       => $dnsbl,
			'default'       => '',
			'read_adapter'  => NULL,
			'write_adapter' => NULL,
		],

		// TLD blacklist (textarea). Default ''.
		'tldblacklist' => [
			'section'       => $dnsbl,
			'default'       => '',
			'read_adapter'  => NULL,
			'write_adapter' => NULL,
		],

		// TLD exclusion (textarea). Default ''.
		'tldexclusion' => [
			'section'       => $dnsbl,
			'default'       => '',
			'read_adapter'  => NULL,
			'write_adapter' => NULL,
		],

		// DNSBL suppression/whitelist (base64). Default ''.
		'suppression' => [
			'section'       => $dnsbl,
			'default'       => '',
			'read_adapter'  => NULL,
			'write_adapter' => NULL,
		],

		// DNSBL action for IP blocking. Default 'Disabled'.
		'action' => [
			'section'       => $dnsbl,
			'default'       => 'Disabled',
			'read_adapter'  => NULL,
			'write_adapter' => NULL,
		],

		// Auto-create floating pass rule. Default 'Disabled'.
		'pfb_dnsbl_rule' => [
			'section'       => $dnsbl,
			'default'       => 'Disabled',
			'read_adapter'  => NULL,
			'write_adapter' => NULL,
		],

		// Allow-interface for DNSBL (multi-select). Default ''.
		'dnsbl_allow_int' => [
			'section'       => $dnsbl,
			'default'       => '',
			'read_adapter'  => NULL,
			'write_adapter' => NULL,
		],

		// Python control integration. Default ''.
		'pfb_control' => [
			'section'       => $dnsbl,
			'default'       => '',
			'read_adapter'  => NULL,
			'write_adapter' => NULL,
		],

		// Legacy DNS-TXT control transport (deprecated). Default ''.
		'pfb_control_legacy' => [
			'section'       => $dnsbl,
			'default'       => '',
			'read_adapter'  => NULL,
			'write_adapter' => NULL,
		],

		// Python cache max (numeric string). Default '' (unlimited).
		'pfb_py_cache_max' => [
			'section'       => $dnsbl,
			'default'       => '',
			'read_adapter'  => NULL,
			'write_adapter' => NULL,
		],

		// TLD blocking enable. Default ''.
		'pfb_tld' => [
			'section'       => $dnsbl,
			'default'       => '',
			'read_adapter'  => NULL,
			'write_adapter' => NULL,
		],

		// Aliaslog (logging mode). Default ''.
		'aliaslog' => [
			'section'       => $dnsbl,
			'default'       => '',
			'read_adapter'  => NULL,
			'write_adapter' => NULL,
		],

		// ADR-36: NAT DNS-redirect enable: 'on' | '' (checkbox). Default '' (off).
		'dnsbl_redir' => [
			'section'       => $dnsbl,
			'default'       => '',
			'read_adapter'  => 'pfb_cfg_toggle_read',
			'write_adapter' => 'pfb_cfg_toggle_write',
		],

		// ADR-36: NAT DNS-redirect interface multi-select (comma-joined string). Default ''.
		'dnsbl_redir_int' => [
			'section'       => $dnsbl,
			'default'       => '',
			'read_adapter'  => NULL,
			'write_adapter' => NULL,
		],

		// ADR-36: NAT DNS-redirect exception alias/IP string. Default ''.
		'dnsbl_redir_exclude' => [
			'section'       => $dnsbl,
			'default'       => '',
			'read_adapter'  => NULL,
			'write_adapter' => NULL,
		],

		// ADR-37: DoT/DoQ block enable: 'on' | '' (checkbox). Default '' (off).
		'dnsbl_dot_block' => [
			'section'       => $dnsbl,
			'default'       => '',
			'read_adapter'  => 'pfb_cfg_toggle_read',
			'write_adapter' => 'pfb_cfg_toggle_write',
		],

		// ADR-37: DoT/DoQ block interface multi-select (comma-joined string). Default ''.
		'dnsbl_dot_block_int' => [
			'section'       => $dnsbl,
			'default'       => '',
			'read_adapter'  => NULL,
			'write_adapter' => NULL,
		],

		// ADR-37: DoT/DoQ block exception alias/IP string. Default ''.
		'dnsbl_dot_block_exclude' => [
			'section'       => $dnsbl,
			'default'       => '',
			'read_adapter'  => NULL,
			'write_adapter' => NULL,
		],

		// ADR-37: DoT/DoQ block rule action: 'reject' (default) | 'block'.
		// Mirrors the IP-settings inbound/outbound Rule Action selector. Reject
		// fast-fails the client (outbound LAN->WAN rule); block silently drops.
		'dnsbl_dot_block_action' => [
			'section'       => $dnsbl,
			'default'       => 'reject',
			'read_adapter'  => NULL,
			'write_adapter' => NULL,
		],

		// ADR-37: DoT/DoQ block floating mode: 'on' | '' (checkbox). Default '' (off).
		// On = a single floating rule (direction 'in') over the selected interfaces
		// instead of one rule per interface. Off preserves the per-interface default.
		'dnsbl_dot_block_floating' => [
			'section'       => $dnsbl,
			'default'       => '',
			'read_adapter'  => 'pfb_cfg_toggle_read',
			'write_adapter' => 'pfb_cfg_toggle_write',
		],

		// -------------------------------------------------------------------
		// ADR-38: syslog export settings (General / Log Settings section, $gen)
		// -------------------------------------------------------------------

		// Master toggle — emit security events to syslog: 'on' | '' (checkbox).
		// Default '' (off) — zero impact on existing installs.
		// ADR-38 Amendment 1: only the master toggle is configurable. The export
		// facility (LOG_LOCAL6) and severity (LOG_INFO) are fixed in
		// pfb_syslog_event() — events route to the dedicated pfblockerng_syslog.log
		// by program name, so facility never affects routing, and every event is
		// the same class of informational record, so a severity picker is moot.
		'log_syslog' => [
			'section'       => $gen,
			'default'       => '',
			'read_adapter'  => 'pfb_cfg_toggle_read',
			'write_adapter' => 'pfb_cfg_toggle_write',
		],

		// -------------------------------------------------------------------
		// SafeSearch section (pfblockerngsafesearch — flat, no /config/0)
		// -------------------------------------------------------------------

		// SafeSearch enable mode. Default 'Disable'.
		'safesearch_enable' => [
			'section'       => $ss,
			'default'       => 'Disable',
			'read_adapter'  => NULL,
			'write_adapter' => NULL,
		],

		// YouTube SafeSearch mode. Default 'Disable'.
		'safesearch_youtube' => [
			'section'       => $ss,
			'default'       => 'Disable',
			'read_adapter'  => NULL,
			'write_adapter' => NULL,
		],

		// DNS-over-HTTPS blocking mode. Default 'Disable'.
		'safesearch_doh' => [
			'section'       => $ss,
			'default'       => 'Disable',
			'read_adapter'  => NULL,
			'write_adapter' => NULL,
		],

		// DoH domain exclusion list (CSV). Default ''.
		'safesearch_doh_list' => [
			'section'       => $ss,
			'default'       => '',
			'read_adapter'  => NULL,
			'write_adapter' => NULL,
		],

		// -------------------------------------------------------------------
		// IP settings section (pfblockerngipsettings/config/0)
		// -------------------------------------------------------------------

		// ADR-53: IPv4 suppression customlist -- CIDR/host carve-outs from the
		// Deny alias set, stored as a base64-encoded newline-separated list
		// (same shape as the DNSBL 'suppression' blob above). Registered so
		// every call site routes through the gateway; this is a legacy key
		// from the original addon (mirrors the '1.0.0' vintage of the sibling
		// DNSBL blob fields). Default ''.
		'v4suppression' => [
			'section'       => $ip,
			'default'       => '',
			'read_adapter'  => NULL,
			'write_adapter' => NULL,
		],

		// ADR-53: IPv6 suppression customlist -- the v4 blob's v6 sibling
		// (same base64/newline-separated shape). Default ''.
		'v6suppression' => [
			'section'       => $ip,
			'default'       => '',
			'read_adapter'  => NULL,
			'write_adapter' => NULL,
		],
	];

	return $registry;
}

// Read the configured DNSBL block-page template filename. issue #713: this is a FOREIGN key
// (ADR-29 §2.5 out-of-scope), written directly by pfblockerng_dnsbl.php as 'dnsbl_webpage' —
// so it is read here via a direct config_get_path(), mirroring how the DNSBL settings page
// stores/reads it. config_get_path()'s default arg only substitutes when the key is ABSENT,
// not when present-but-empty (''), so the `?:` coercion below is required — a
// saved-then-cleared 'dnsbl_webpage' must still report 'dnsbl_default.php'. Fixes the dead
// read of the mis-spelled 'dnsblwebpage' key, which always returned ''.
function pfb_dnsbl_webpage(): string
{
	return config_get_path('installedpackages/pfblockerngdnsblsettings/config/0/dnsbl_webpage', 'dnsbl_default.php') ?: 'dnsbl_default.php';
}

/**
 * PfbConfig — the centralized gateway for registered config.xml keys.
 *
 * All reads and writes of registered keys (pfb_cfg_registry()) must flow
 * through this class. Non-registered (foreign) keys continue to use
 * config_get_path / config_set_path / config_del_path directly.
 *
 * API:
 *   PfbConfig::read($key)                          — read one field
 *   PfbConfig::write($key, $value)                 — write one field
 *   PfbConfig::delete($key)                        — delete one field
 *   PfbConfig::readSection($section)               — read a whole section array
 *   PfbConfig::writeSection($section, $data)       — write a section array, normalising
 *                                                     its registered fields through their
 *                                                     adapters (issue #930)
 *   PfbConfig::deleteSection($section)             — delete a whole section
 *
 * @see pfb_cfg_registry()
 */
final class PfbConfig
{
	/**
	 * Read a single registered field.
	 *
	 * Returns the registered default when the key is absent/null; applies
	 * the registered read adapter (stored string -> runtime enum/string).
	 *
	 * @param  string $key  The exact config.xml field key (e.g. 'pfb_keep').
	 * @return mixed        Runtime value (enum or string).
	 * @throws InvalidArgumentException When $key is not in the registry.
	 */
	public static function read(string $key): mixed
	{
		$entry   = self::entry($key);
		$path    = $entry['section'] . '/' . $key;
		$raw     = config_get_path($path, NULL);
		$stored  = ($raw === NULL) ? $entry['default'] : (string) $raw;
		$adapter = $entry['read_adapter'];
		return ($adapter !== NULL) ? $adapter($stored) : $stored;
	}

	/**
	 * Write a single registered field.
	 *
	 * Applies the registered write adapter (runtime value -> exact legacy
	 * stored string) before calling config_set_path. Does NOT call
	 * write_config() — callers must persist when appropriate.
	 *
	 * @param  string $key   The exact config.xml field key.
	 * @param  mixed  $value Runtime value (enum or string).
	 * @throws InvalidArgumentException When $key is not in the registry.
	 */
	public static function write(string $key, mixed $value): void
	{
		$entry   = self::entry($key);
		$path    = $entry['section'] . '/' . $key;
		$adapter = $entry['write_adapter'];
		$stored  = ($adapter !== NULL) ? $adapter($value) : (string) $value;
		config_set_path($path, $stored);
	}

	/**
	 * Delete a single registered field.
	 *
	 * @param  string $key  The exact config.xml field key.
	 * @throws InvalidArgumentException When $key is not in the registry.
	 */
	public static function delete(string $key): void
	{
		$entry = self::entry($key);
		$path  = $entry['section'] . '/' . $key;
		config_del_path($path);
	}

	/**
	 * Read a whole section as a raw array (no per-key adapters applied).
	 *
	 * This is the equivalent of config_get_path($section, []) for callers
	 * (www/ pages, pfb_global) that load an entire section blob at once
	 * and access keys individually.
	 *
	 * @param  string $section  The full config.xml section path (e.g.
	 *                          'installedpackages/pfblockerng/config/0').
	 * @return array            Raw config array (empty when absent).
	 */
	public static function readSection(string $section): array
	{
		$raw = config_get_path($section, []);
		return is_array($raw) ? $raw : [];
	}

	/**
	 * Write a whole section array, normalising every registered field of
	 * $section through its adapter pair before persisting (issue #930).
	 *
	 * For each key in $data that is registered to this EXACT section (a
	 * registered key name living under a DIFFERENT section path is foreign
	 * data and is left untouched) and carries BOTH a read and a write
	 * adapter, the value is round-tripped read_adapter() then
	 * write_adapter() — coalescing a legacy/read-only token (e.g. alexa_type
	 * 'domcop'/'alexa', pfb_idn 'all'), a NULL, a non-scalar (a crafted POST
	 * array), or junk input to the field's canonical stored form, exactly as
	 * a single-key PfbConfig::write() would. Unregistered keys and
	 * adapter-less (plain-string) registered keys pass through byte-identical.
	 * Consequence: canonical storage is enforced on section writes too — a
	 * legacy token riding a readSection()->writeSection()
	 * round-trip (a restored backup, an HA sync, a hand-edited config.xml)
	 * is coalesced to canonical on the next save. Does NOT call
	 * write_config() — callers persist.
	 *
	 * Read adapter runs FIRST (mixed -> runtime value; the non-scalar guard
	 * handles arrays/NULL/junk and is idempotent on an already-adapted enum
	 * instance), write adapter SECOND (runtime value -> canonical stored
	 * string) — calling the write adapter directly on a raw array or NULL
	 * would TypeError (write adapters are typed EnumClass|string).
	 *
	 * @param string $section  The full config.xml section path.
	 * @param array  $data     Section data to persist.
	 */
	public static function writeSection(string $section, array $data): void
	{
		foreach (pfb_cfg_registry() as $key => $entry) {
			if ($entry['section'] !== $section) {
				continue;
			}
			$read_adapter  = $entry['read_adapter'];
			$write_adapter = $entry['write_adapter'];
			if ($read_adapter === NULL || $write_adapter === NULL) {
				continue;
			}
			if (!array_key_exists($key, $data)) {
				continue;
			}
			$data[$key] = $write_adapter($read_adapter($data[$key]));
		}
		config_set_path($section, $data);
	}

	/**
	 * Delete a whole section (e.g. during package removal / wipe).
	 *
	 * Equivalent to config_del_path($section).
	 *
	 * @param string $section  The full config.xml section path.
	 */
	public static function deleteSection(string $section): void
	{
		config_del_path($section);
	}

	// -----------------------------------------------------------------------
	// Private helpers
	// -----------------------------------------------------------------------

	/**
	 * Look up a registry entry, throwing on an unregistered key.
	 *
	 * @param  string $key
	 * @return array{section:string,default:string,read_adapter:callable|null,write_adapter:callable|null}
	 * @throws InvalidArgumentException
	 */
	private static function entry(string $key): array
	{
		$registry = pfb_cfg_registry();
		if (!array_key_exists($key, $registry)) {
			throw new InvalidArgumentException(
				"PfbConfig: key '{$key}' is not in the field registry. "
				. 'Use config_get_path() directly for foreign/unregistered keys.'
			);
		}
		return $registry[$key];
	}
}

// Settings-family snapshots capture only pfBlockerNG-owned installedpackages sections. Foreign
// config remains live while the registered marker records the exact schema family.
const PFB_SETTINGS_FAMILY_RANK = ['3.2' => 0, '4.0' => 1, '4.1' => 2];

function pfb_settings_family_from_version(string $version): ?string
{
	$version = ltrim(trim($version), 'vV');
	if (preg_match('/^(\d+\.\d+)(?:\.\d+)?(?:[.-].*)?$/', $version, $match) !== 1
		|| !isset(PFB_SETTINGS_FAMILY_RANK[$match[1]])) {
		return NULL;
	}
	return $match[1];
}

function pfb_settings_family_current(): ?string
{
	$value = PfbConfig::read('settings_family');
	return is_string($value) && isset(PFB_SETTINGS_FAMILY_RANK[$value]) ? $value : NULL;
}

function pfb_settings_family_save(string $family): bool
{
	if (!isset(PFB_SETTINGS_FAMILY_RANK[$family])) {
		return FALSE;
	}
	$installed = config_get_path('installedpackages', []);
	if (!is_array($installed)) {
		return TRUE;
	}
	$owned = [];
	foreach ($installed as $section => $value) {
		if (str_starts_with((string) $section, 'pfblockerng')) {
			$owned[(string) $section] = $value;
		}
	}
	if ($owned === []) {
		return TRUE;
	}

	global $pfb;
	$root = (string) ($pfb['dbdir'] ?? '/var/db/pfblockerng');
	$effective_owner = function_exists('posix_geteuid') ? posix_geteuid() : 0;
	$expected_owner = ($root === '/var/db/pfblockerng') ? 0 : $effective_owner;
	$root_stat = @lstat($root);
	if ($root_stat !== FALSE && (($root_stat['mode'] & 0170000) !== 0040000 || is_link($root)
		|| (($root_stat['mode'] & 0022) !== 0) || $root_stat['uid'] !== $expected_owner)) {
		return FALSE;
	}
	if ($root_stat === FALSE && !@mkdir($root, 0755, TRUE)) {
		return FALSE;
	}
	$root_stat = @lstat($root);
	if ($root_stat === FALSE || (($root_stat['mode'] & 0170000) !== 0040000) || is_link($root)
		|| (($root_stat['mode'] & 0022) !== 0) || $root_stat['uid'] !== $expected_owner) {
		return FALSE;
	}

	$slot = $root . '/settings-' . $family . '.xml';
	$slot_stat = @lstat($slot);
	if ($slot_stat !== FALSE && (($slot_stat['mode'] & 0170000) !== 0100000 || is_link($slot)
		|| ($slot_stat['mode'] & 07777) !== 0600 || $slot_stat['uid'] !== $expected_owner)) {
		return FALSE;
	}
	$payload = base64_encode(serialize($owned));
	if (function_exists('dump_xml_config')) {
		$xml = dump_xml_config(['family' => $family, 'payload' => $payload], 'pfblockerng-settings');
	} else {
		$doc = new SimpleXMLElement('<pfblockerng-settings/>');
		$doc->addChild('family', $family);
		$doc->addChild('payload', $payload);
		$xml = $doc->asXML();
	}
	if (!is_string($xml) || $xml === '') {
		return FALSE;
	}

	$tmp = @tempnam($root, '.settings-');
	if (!is_string($tmp)) {
		return FALSE;
	}
	$written = @file_put_contents($tmp, $xml, LOCK_EX);
	$exact = ($written === strlen($xml) && @file_get_contents($tmp) === $xml);
	if (!$exact || !@chmod($tmp, 0600)) {
		@unlink($tmp);
		return FALSE;
	}
	$tmp_stat = @lstat($tmp);
	if ($tmp_stat === FALSE
		|| (($tmp_stat['mode'] & 0170000) !== 0100000)
		|| (($tmp_stat['mode'] & 07777) !== 0600)
		|| $tmp_stat['uid'] !== $expected_owner || !@rename($tmp, $slot)) {
		@unlink($tmp);
		return FALSE;
	}
	clearstatcache(TRUE, $slot);
	$slot_stat = @lstat($slot);
	return $slot_stat !== FALSE
		&& (($slot_stat['mode'] & 0170000) === 0100000)
		&& (($slot_stat['mode'] & 07777) === 0600)
		&& $slot_stat['uid'] === $expected_owner
		&& @file_get_contents($slot) === $xml;
}

function pfb_settings_family_replace(string $family): bool
{
	if (!isset(PFB_SETTINGS_FAMILY_RANK[$family])) {
		return FALSE;
	}
	global $pfb;
	$root = (string) ($pfb['dbdir'] ?? '/var/db/pfblockerng');
	$effective_owner = function_exists('posix_geteuid') ? posix_geteuid() : 0;
	$expected_owner = ($root === '/var/db/pfblockerng') ? 0 : $effective_owner;
	$slot = $root . '/settings-' . $family . '.xml';
	$slot_stat = @lstat($slot);
	if ($slot_stat === FALSE) {
		return TRUE;
	}
	$root_stat = @lstat($root);
	if ($root_stat === FALSE || is_link($root) || (($root_stat['mode'] & 0170000) !== 0040000)
		|| (($root_stat['mode'] & 0022) !== 0) || $root_stat['uid'] !== $expected_owner
		|| (($slot_stat['mode'] & 0170000) !== 0100000)
		|| is_link($slot) || (($slot_stat['mode'] & 07777) !== 0600)
		|| $slot_stat['uid'] !== $expected_owner) {
		return FALSE;
	}
	$parsed = NULL;
	if (function_exists('parse_xml_config')) {
		$parsed = parse_xml_config($slot, 'pfblockerng-settings');
	} else {
		$doc = @simplexml_load_file($slot, 'SimpleXMLElement', LIBXML_NONET | LIBXML_NOBLANKS);
		if ($doc !== FALSE && $doc->getName() === 'pfblockerng-settings') {
			$parsed = [
				'family'  => (string) ($doc->family ?? ''),
				'payload' => (string) ($doc->payload ?? ''),
			];
		}
	}
	if (!is_array($parsed)
		|| !isset($parsed['family'], $parsed['payload'])
		|| !is_string($parsed['family'])
		|| $parsed['family'] !== $family
		|| !is_string($parsed['payload'])) {
		return FALSE;
	}
	$encoded = base64_decode($parsed['payload'], TRUE);
	if ($encoded === FALSE) {
		return FALSE;
	}
	try {
		$owned = @unserialize($encoded, ['allowed_classes' => FALSE]);
	} catch (Throwable) {
		return FALSE;
	}
	if (!is_array($owned) || $owned === []) {
		return FALSE;
	}
	foreach ($owned as $section => $_value) {
		if (!is_string($section) || !str_starts_with($section, 'pfblockerng')) {
			return FALSE;
		}
	}
	$validate_value = static function (mixed $value, array &$active_references) use (&$validate_value): bool {
		if (!is_array($value)) {
			return is_scalar($value) || $value === NULL;
		}
		foreach ($value as $key => $nested) {
			$reference = ReflectionReference::fromArrayElement($value, $key);
			if ($reference !== NULL) {
				$reference_id = $reference->getId();
				if (isset($active_references[$reference_id])) {
					return FALSE;
				}
				$active_references[$reference_id] = TRUE;
				$valid = $validate_value($nested, $active_references);
				unset($active_references[$reference_id]);
				if (!$valid) {
					return FALSE;
				}
			} elseif (!$validate_value($nested, $active_references)) {
				return FALSE;
			}
		}
		return TRUE;
	};
	$active_references = [];
	if (!$validate_value($owned, $active_references)) {
		return FALSE;
	}
	$installed = config_get_path('installedpackages', []);
	if (!is_array($installed)) {
		$installed = [];
	}
	$rebuilt = [];
	$owned_sections = array_keys($owned);
	$owned_index = 0;
	foreach ($installed as $section => $value) {
		if (str_starts_with((string) $section, 'pfblockerng')) {
			if (isset($owned_sections[$owned_index])) {
				$owned_section = $owned_sections[$owned_index++];
				$rebuilt[$owned_section] = $owned[$owned_section];
				unset($owned[$owned_section]);
			}
			continue;
		}
		$rebuilt[$section] = $value;
	}
	foreach ($owned as $section => $value) {
		$rebuilt[$section] = $value;
	}
	// Whole-tree write deliberately bypasses field adapters so unknown and empty snapshot values,
	// along with owned-section ordering, are restored exactly.
	config_set_path('installedpackages', $rebuilt);
	write_config('pfBlockerNG: restore settings family');
	return TRUE;
}

function pfb_settings_family_record(string $family): bool
{
	if (!isset(PFB_SETTINGS_FAMILY_RANK[$family])) {
		return FALSE;
	}
	try {
		PfbConfig::write('settings_family', $family);
		write_config('pfBlockerNG: record settings family');
		return TRUE;
	} catch (Throwable) {
		return FALSE;
	}
}

/**
 * The operator's view of a config section: installer-seeded schema markers
 * stripped, so "is this pre-existing operator configuration?" decisions
 * (install-default grandfathers, migrations, seeds) never fire on the
 * installer's own bookkeeping (issues #1770/#1771/#1775).
 */
function pfb_gconfig_operator_view(array $gconfig): array {
	unset($gconfig['settings_family']);
	return $gconfig;
}

function pfb_settings_downgrade_context_target(string $current_family): ?string
{
	if (!isset(PFB_SETTINGS_FAMILY_RANK[$current_family])) {
		return NULL;
	}
	global $pfb;
	$override = isset($pfb['downgrade_context_path']);
	$path = $override ? (string) $pfb['downgrade_context_path'] : '/var/run/pfblockerng-downgrade-context.json';
	$stat = $path === '' ? FALSE : @lstat($path);
	if ($stat === FALSE || (($stat['mode'] & 0170000) !== 0100000)
		|| (($stat['mode'] & 07777) !== 0600)) {
		return NULL;
	}
	$owner = @fileowner($path);
	if ((!$override && $owner !== 0) || ($override && function_exists('posix_geteuid') && $owner !== posix_geteuid())) {
		return NULL;
	}
	$size = @filesize($path);
	if ($size === FALSE || $size > 512) {
		return NULL;
	}
	$raw = @file_get_contents($path);
	if (!is_string($raw)) {
		return NULL;
	}
	try {
		$context = json_decode($raw, TRUE, 512, JSON_THROW_ON_ERROR);
	} catch (Throwable) {
		return NULL;
	}
	$keys = is_array($context) ? array_keys($context) : [];
	sort($keys);
	if (!is_array($context)
		|| $keys !== ['created_at', 'source_family', 'target_family', 'version']
		|| !isset($context['version'], $context['source_family'], $context['target_family'], $context['created_at'])
		|| $context['version'] !== 1
		|| !is_string($context['source_family'])
		|| !is_string($context['target_family'])
		|| !is_int($context['created_at'])
		|| $context['source_family'] !== $current_family
		|| !isset(PFB_SETTINGS_FAMILY_RANK[$context['source_family']])
		|| !isset(PFB_SETTINGS_FAMILY_RANK[$context['target_family']])) {
		return NULL;
	}
	$now = time();
	if ($context['created_at'] > $now || $now - $context['created_at'] > 300
		|| PFB_SETTINGS_FAMILY_RANK[$context['target_family']]
			>= PFB_SETTINGS_FAMILY_RANK[$context['source_family']]) {
		return NULL;
	}
	return $context['target_family'];
}

function pfb_settings_downgrade_context_consume(): void
{
	global $pfb;
	$path = isset($pfb['downgrade_context_path'])
		? (string) $pfb['downgrade_context_path']
		: '/var/run/pfblockerng-downgrade-context.json';
	$stat = $path === '' ? FALSE : @lstat($path);
	if ($stat !== FALSE && (($stat['mode'] & 0170000) === 0100000)) {
		@unlink($path);
	}
}

function pfb_settings_family_pre_uninstall(): void
{
	$current_family = pfb_settings_family_current();
	if ($current_family === NULL) {
		pfb_settings_downgrade_context_consume();
		throw new RuntimeException('pfBlockerNG: settings-family marker invalid');
	}
	if (!pfb_settings_family_save($current_family)) {
		pfb_settings_downgrade_context_consume();
		throw new RuntimeException('pfBlockerNG: settings-family snapshot failed');
	}
	$restore_family = pfb_settings_downgrade_context_target($current_family);
	if ($restore_family !== NULL && !pfb_settings_family_replace($restore_family)) {
		pfb_settings_downgrade_context_consume();
		throw new RuntimeException('pfBlockerNG: settings-family restore failed');
	}
	pfb_settings_downgrade_context_consume();
}

// ---------------------------------------------------------------------------
// ADR-29 — Migration registry + driver: pfb_migration_registry() is the ordered,
// idempotent, since-version-gated inventory of every upgrade migration (shape below);
// each entry delegates to an existing *_migrate/*_seed helper and carries its original
// write_config() message. 'apply' returns the updated section array to persist, or NULL
// for a no-op (already migrated / fresh install). The pfblockerng_install.inc driver calls
// pfb_run_migrations() to execute all entries in registry order; helper bodies are
// UNCHANGED, this registry only wraps them.
// Tests: tests/php/MigrationRegistryTest.php
// ---------------------------------------------------------------------------

/**
 * pfb_migration_registry — the ordered list of upgrade migrations.
 *
 * Returns an array of migration descriptor maps, in the order they must run.
 * Each entry's 'apply' callable wraps an existing *_migrate / *_seed helper.
 *
 * @return list<array{id:string,section:string,apply:callable,message:string,since:string}>
 */
function pfb_migration_registry(): array
{
	$dnsbl = 'installedpackages/pfblockerngdnsblsettings/config/0';
	$gen   = 'installedpackages/pfblockerng/config/0';

	return [
		// 1. ADR-02: force DNSBL to python-only mode.
		[
			'id'      => 'adr02-dnsbl-python-mode',
			'section' => $dnsbl,
			'apply'   => 'pfb_dnsbl_python_migrate',
			'message' => 'pfBlockerNG: migrated DNSBL to Python-only mode',
			'since'   => '2.0.0',
		],
		// 2. PFBL-03: one-time seed of the deprecated legacy DNS-TXT control toggle.
		[
			'id'      => 'pfbl03-control-legacy-seed',
			'section' => $dnsbl,
			'apply'   => 'pfb_control_legacy_seed',
			'message' => 'pfBlockerNG: seeded legacy DNSBL control toggle (PFBL-03)',
			'since'   => '3.2.0',
		],
		// 3. ADR-22: preserve permissive DNSBL scheme parsing for existing installs.
		[
			'id'      => 'adr22-dnsbl-lenient',
			'section' => $dnsbl,
			'apply'   => 'pfb_dnsbl_lenient_migrate',
			'message' => 'pfBlockerNG: preserve permissive DNSBL parsing for existing install (ADR-22 migration)',
			'since'   => '3.2.0',
		],
		// 4. Issue #281: seed pfb_keep to preserve settings across pkg upgrade.
		[
			'id'      => 'issue281-pfb-keep-seed',
			'section' => $gen,
			'apply'   => 'pfb_keep_migrate',
			'message' => 'pfBlockerNG: preserve settings across upgrade (seed Keep flag, issue #281)',
			'since'   => '3.2.0',
		],
	];
}

/**
 * pfb_run_migrations — execute all registered upgrade migrations in order.
 *
 * Iterates pfb_migration_registry(). For each entry: reads the registered
 * section, calls apply($cfg), and when the result is non-NULL writes it back
 * and calls write_config() with the entry's message. Each migration's own
 * apply() is responsible for run-once / idempotency (NULL = already done).
 */
function pfb_run_migrations(): void
{
	foreach (pfb_migration_registry() as $migration) {
		$cfg    = PfbConfig::readSection($migration['section']);
		$result = ($migration['apply'])($cfg);
		if ($result !== NULL) {
			PfbConfig::writeSection($migration['section'], $result);
			write_config($migration['message']);
		}
	}
}

// ---------------------------------------------------------------------------
// Issue #357 — pfSense's alias-rename path (update_alias_name()) rewrites core config
// sections but not installedpackages/*, so the four per-row Advanced Inbound/Outbound
// alias keys (aliasports_in/out, aliasaddr_in/out) go stale after a rename.
// pfb_alias_rename_followup() rewrites them in-memory via PfbConfig; the caller persists
// via write_config().
// ---------------------------------------------------------------------------

/**
 * pfb_alias_rename_followup — follow a firewall-alias rename into
 * pfBlockerNG's stored Advanced Inbound/Outbound references.
 *
 * pfSense's alias rename does not update installedpackages/*, so rewrite
 * the four alias keys everywhere pfBlockerNG stores them: the multi-row IP/
 * DNSBL feed list sections AND the single-config DNSBL-settings and GeoIP
 * continent sections (config/0), through the PfbConfig section gateway. Does
 * NOT persist (write_config is the caller's job). Returns TRUE if anything
 * changed.
 *
 * @param  string $old_name  The alias name before the rename.
 * @param  string $new_name  The alias name after the rename.
 * @return bool              TRUE when at least one key was rewritten.
 */
function pfb_alias_rename_followup(string $old_name, string $new_name): bool
{
	if ($old_name === '' || $new_name === '' || $old_name === $new_name) {
		return FALSE;
	}

	$changed = FALSE;
	$keys    = ['aliasports_in', 'aliasports_out', 'aliasaddr_in', 'aliasaddr_out'];

	// Multi-row list sections: each feed row can carry the four alias keys.
	$list_sections = ['pfblockernglistsv4', 'pfblockernglistsv6', 'pfblockerngdnsbl'];

	foreach ($list_sections as $section) {
		$path = "installedpackages/{$section}/config";
		$rows = PfbConfig::readSection($path);
		if (empty($rows)) {
			continue;
		}

		$section_dirty = FALSE;
		foreach ($rows as $i => $row) {
			foreach ($keys as $key) {
				if (($rows[$i][$key] ?? '') === $old_name) {
					$rows[$i][$key] = $new_name;
					$section_dirty  = TRUE;
					$changed        = TRUE;
				}
			}
		}

		if ($section_dirty) {
			PfbConfig::writeSection($path, $rows);
		}
	}

	// Single-config sections store the same four keys on config/0: the DNSBL
	// settings tab (pfblockerng_dnsbl.php) and every GeoIP continent tab
	// (pfblockerng.php). pfSense's alias rename skips installedpackages/* here
	// too, so the built DNSBL/GeoIP rule stops matching the stale name and
	// silently drops its In/Out restriction (#708). The continent section names
	// are 'pfblockerng' + the continent name lowercased with spaces removed
	// (the $conf_type the GeoIP page derives from $pfb['continents']).
	$cfg0_sections = [
		'pfblockerngdnsblsettings',
		'pfblockerngtopspammers',
		'pfblockerngafrica',
		'pfblockerngantarctica',
		'pfblockerngasia',
		'pfblockerngeurope',
		'pfblockerngnorthamerica',
		'pfblockerngoceania',
		'pfblockerngsouthamerica',
		'pfblockerngproxyandsatellite',
	];

	foreach ($cfg0_sections as $section) {
		$path = "installedpackages/{$section}/config/0";
		$cfg  = PfbConfig::readSection($path);
		if (empty($cfg)) {
			continue;
		}

		$section_dirty = FALSE;
		foreach ($keys as $key) {
			if (($cfg[$key] ?? '') === $old_name) {
				$cfg[$key]     = $new_name;
				$section_dirty = TRUE;
				$changed       = TRUE;
			}
		}

		if ($section_dirty) {
			PfbConfig::writeSection($path, $cfg);
		}
	}

	return $changed;
}

// ---------------------------------------------------------------------------
// Issue #356 — per-field alias-type validation helper.
//
// The four Advanced Inbound/Outbound alias fields accept different alias
// types: port fields (aliasports_*) require a port-bearing alias
// (port/url_ports/urltable_ports); address fields (aliasaddr_*) require an
// address-bearing alias (host/network/url/urltable). This helper encodes that rule in
// one testable place so the category-edit validation loop and any future caller stay in sync.
// ---------------------------------------------------------------------------

/**
 * pfb_alias_field_type_ok — check whether an alias type is valid for a
 * given Advanced Inbound/Outbound field.
 *
 * Port fields (aliasports_*) require a port-bearing alias (port/url_ports/urltable_ports);
 * address fields (aliasaddr_*) require an address-bearing alias (host/network/url/urltable).
 * Unknown field names return FALSE (fail closed).
 *
 * @param  string $field       One of aliasports_in, aliasports_out,
 *                             aliasaddr_in, aliasaddr_out.
 * @param  string $alias_type  The alias type string (pfb_alias_type() value).
 * @return bool                TRUE when the alias type is allowed for this field.
 */
function pfb_alias_field_type_ok(string $field, string $alias_type): bool
{
	if ($field === 'aliasports_in' || $field === 'aliasports_out') {
		// Any port-bearing alias type (port/url_ports/urltable_ports), matching the
		// broadened Custom Port autocomplete (pfb_port_alias_types()).
		return in_array($alias_type, pfb_port_alias_types(), TRUE);
	}
	if ($field === 'aliasaddr_in' || $field === 'aliasaddr_out') {
		// Any address-bearing alias type (host/network/url/urltable), matching the
		// broadened autocomplete + the DNS-redirect exception source (pfb_exclude_alias_types()).
		return in_array($alias_type, pfb_exclude_alias_types(), TRUE);
	}
	return FALSE;
}

/**
 * pfb_adv_alias_field_errors — validate the Advanced Inbound/Outbound alias
 * fields of a category-edit POST (issue #356, #636).
 *
 * Each non-empty field must name an EXISTING firewall alias whose type the field
 * accepts (port fields -> a port alias; address fields -> an address-bearing alias).
 *
 * Existence AND type are resolved from pfb_alias_type(), which reads the
 * 'aliases/alias' configuration directly — the same source the page builds its
 * alias dropdowns/autocomplete from and the same resolver the DNS-redirect
 * exception path uses. This deliberately replaces BOTH pfSense helpers:
 *   - is_alias() consults the in-memory $aliastable cache, populated only by
 *     alias_make_table() during filter generation, so on the category-edit page
 *     that cache is empty and every existing alias is reported missing (#636);
 *   - alias_get_type() gives reserved system table names (bogons, virusprot, ...)
 *     precedence over the configuration, so a reserved name passes save-time
 *     validation here while the rule builder (which requires an aliases/alias
 *     entry with a non-empty address) silently ignores it — an accepted setting
 *     that is dead at rule build. Reserved names must be rejected at save.
 *
 * @param  array $post           The submitted form ($_POST).
 * @return array<int, string>    Human-readable input-error strings (empty when valid).
 */
function pfb_adv_alias_field_errors(array $post): array
{
	$adv_alias_fields = [
		'aliasports_in'  => ['dir' => 'Port In',         'type_label' => 'Port-type'],
		'aliasports_out' => ['dir' => 'Port Out',        'type_label' => 'Port-type'],
		'aliasaddr_in'   => ['dir' => 'Destination In',  'type_label' => 'Host, Network, URL or URL-Table-type'],
		'aliasaddr_out'  => ['dir' => 'Source Out',      'type_label' => 'Host, Network, URL or URL-Table-type'],
	];

	$errors = [];
	foreach ($adv_alias_fields as $field => $meta) {
		if (empty($post[$field])) {
			continue;
		}
		// A crafted request can submit the field as an array (aliasaddr_in[]=...);
		// pfb_alias_type() is string-typed, so a non-string would TypeError. Treat
		// it as non-existent — same verdict the untyped resolver reached.
		$alias_type = is_string($post[$field]) ? (pfb_alias_type($post[$field]) ?? '') : '';
		if ($alias_type === '') {
			$errors[] = "Settings: Advanced {$meta['dir']}bound Alias error - Must use an existing Alias";
		} elseif (!pfb_alias_field_type_ok($field, $alias_type)) {
			$errors[] = "Settings: Advanced {$meta['dir']}bound Alias error - Must use a {$meta['type_label']} alias";
		}
	}
	return $errors;
}

/**
 * The regex-description length the Regex List help text documents, and the
 * width the Alerts tab column is sized for (issue #1868). Advisory: exceeded
 * descriptions are flagged in the editor, never rejected at save.
 */
const PFB_REGEX_DESCRIPTION_MAX = 15;

/**
 * pfb_split_regex_line — split a regex-list line at the first UNESCAPED '#'.
 *
 * issue #1867: a '#' preceded by an ODD number of backslashes is escaped and
 * belongs to the pattern; an EVEN run (none included) leaves it as the
 * description marker. The escaped form needs no unescaping — Python's re reads
 * "\#" as a literal '#' already — so the pattern half travels verbatim all the
 * way to re.compile().
 *
 * Twins that must agree, each with its own tests: pfb_split_regex_line() in
 * pfb_unbound.py (the resolver's load path), the split_line() helper inside this
 * file's validator probe, and the Pattern/Comment token pair in
 * tools/webassets/lezer-pfb-regex-list/src/pfb-regex-list.grammar (the editor).
 *
 * @return array{0: string, 1: ?string} [pattern, description]; description NULL
 *     when the line carries no marker at all (distinct from an empty one).
 */
function pfb_split_regex_line(string $line): array
{
	$backslashes = 0;
	$length = strlen($line);
	for ($index = 0; $index < $length; $index++) {
		$character = $line[$index];
		if ($character === '\\') {
			$backslashes++;
			continue;
		}
		if ($character === '#' && $backslashes % 2 === 0) {
			return [substr($line, 0, $index), substr($line, $index + 1)];
		}
		$backslashes = 0;
	}
	return [$line, NULL];
}

/**
 * pfb_dnsbl_regex_description_warnings — advisory notes about over-long regex
 * descriptions (issue #1868).
 *
 * The Regex List help text caps a description at 15 characters because the
 * Alerts tab shows it, but the cap was never checked anywhere the admin could
 * see it. This is deliberately NOT wired into
 * pfb_dnsbl_regex_validation_errors(): a config that already carries a longer
 * description must keep saving, so the note reaches the admin through the lint
 * gutter instead and never blocks a save.
 *
 * @return array<int, array{line: int, message: string, severity: string}>
 */
function pfb_dnsbl_regex_description_warnings(string $contents): array
{
	$warnings = [];
	$lines = preg_split('/\R/', $contents);
	if ($lines === FALSE) {
		return [];
	}
	foreach ($lines as $offset => $line) {
		$trimmed = trim($line);
		if ($trimmed === '' || str_starts_with($trimmed, '#')) {
			continue;
		}
		[$pattern, $description] = pfb_split_regex_line($line);
		if ($description === NULL || trim($pattern) === '') {
			continue;
		}
		// A second '#' ends the description, matching what the resolver keeps
		// as the Alerts name.
		$description = trim(pfb_split_regex_line($description)[0]);
		if ($description === '' || strlen($description) <= PFB_REGEX_DESCRIPTION_MAX) {
			continue;
		}
		$warnings[] = [
			'line' => $offset + 1,
			'message' => sprintf(
				'description is %d characters; keep it to %d or fewer — the Alerts tab shows it',
				strlen($description),
				PFB_REGEX_DESCRIPTION_MAX
			),
			'severity' => 'warning',
		];
	}
	return $warnings;
}

/**
 * pfb_dnsbl_regex_validation_errors — validate the DNSBL regex form in one
 * bounded Python pass, preserving source line numbers and resolver semantics.
 *
 * @param bool $regex_cap Mirrors the "Limit long/complex regex" toggle: gates the
 *     save-time length-cap diagnostic so it agrees with the resolver's load-time drop.
 * @return array<int, string> Non-empty validation or infrastructure diagnostics.
 */
function pfb_dnsbl_regex_validation_errors(string $contents, string $python, bool $regex_cap, string $timeout_bin = '/usr/bin/timeout'): array
{
	if ($contents === '') {
		return [];
	}
	if ($python === '' || !is_executable($python)) {
		return ['Python regex validator: interpreter unavailable'];
	}
	if ($timeout_bin === '' || !is_executable($timeout_bin)) {
		return ['Python regex validator: timeout launcher unavailable'];
	}
	$stderr = tmpfile();
	if ($stderr === FALSE) {
		return ['Python regex validator: unable to create diagnostics file'];
	}
	$stderr_path = stream_get_meta_data($stderr)['uri'];
	$probe = <<<'PYTHON'
import re
import sys

shapes = (
    re.compile(r"\([^()]*[+*][^()]*\)\s*[+*{]"),  # _REGEX_NESTED_QUANTIFIER mirror (pfb_unbound.py)
    re.compile(r"\([^()]*\|[^()]*\)\s*[+*{]"),  # _REGEX_ALTERNATION_OVERLAP mirror (pfb_unbound.py)
    re.compile(r"\([^()]*[+*][^()]*\)\([^()]*\)\s*[+*]"),  # _REGEX_ADJACENT_GROUP_QUANTIFIER mirror (pfb_unbound.py)
    re.compile(r"(?:\)|\]|\w)\{\d+(?:,\d*)?\}\{\d+(?:,\d*)?\}"),  # _REGEX_STACKED_BOUNDED_REPEAT mirror (pfb_unbound.py)
)

failed = False

def report(line_number, pattern, message):
    print(f"line {line_number}: {pattern!r}: {message}", file=sys.stderr)

regex_cap = len(sys.argv) > 1 and sys.argv[1] == "1"


def split_line(line):
    # issue #1867 mirror of pfb_split_regex_line() (PHP) and pfb_unbound.py's
    # twin: the description starts at the first '#' preceded by an EVEN number
    # of backslashes, so an escaped "\#" stays in the pattern.
    backslashes = 0
    for index, character in enumerate(line):
        if character == "\\":
            backslashes += 1
            continue
        if character == "#" and backslashes % 2 == 0:
            return line[:index]
        backslashes = 0
    return line


for line_number, line in enumerate(sys.stdin, start=1):
    line = line.rstrip("\r\n")
    if not line.strip() or line.lstrip().startswith("#"):
        continue
    pattern = split_line(line).strip().lower()
    if not pattern:
        continue
    if any(ord(character) < 0x20 or ord(character) == 0x7f for character in pattern):
        report(line_number, pattern, "contains ASCII control character")
        failed = True
        continue
    if any(shape.search(pattern) is not None for shape in shapes):
        report(line_number, pattern, "catastrophic-backtracking shape")
        failed = True
        continue
    budget = len(re.findall(r"(?<!\\)[+*]", pattern)) + len(re.findall(r"(?<!\\)\|", pattern))  # _REGEX_UNBOUNDED_QUANTIFIER + _REGEX_ALTERNATION mirror (pfb_unbound.py)
    if budget > 12:  # _REGEX_BUDGET_MAX mirror (pfb_unbound.py)
        report(line_number, pattern, "too many quantifiers/alternations")
        failed = True
        continue
    if regex_cap and len(pattern) > 200:  # REGEX_STATIC_LEN_CAP mirror (pfb_unbound.py)
        report(line_number, pattern, 'over the 200-character length cap ("Limit long/complex regex")')
        failed = True
        continue
    try:
        re.compile(pattern)
    except Exception as error:
        report(line_number, pattern, f"Python regex compile error: {error}")
        failed = True

raise SystemExit(1 if failed else 0)
PYTHON;
	$command = array($timeout_bin, '-s', 'TERM', '-k', '1', '5', $python, '-c', $probe, $regex_cap ? '1' : '0');
	$descriptors = array(
		0 => array('pipe', 'r'),
		1 => array('file', '/dev/null', 'w'),
		2 => array('file', $stderr_path, 'a'),
	);
	$pipes = array();
	$process = @proc_open($command, $descriptors, $pipes);
	if (!is_resource($process)) {
		fclose($stderr);
		return ['Python regex validator: launcher failed'];
	}
	if (!isset($pipes[0]) || !is_resource($pipes[0])) {
		proc_close($process);
		fclose($stderr);
		return ['Python regex validator: stdin unavailable'];
	}
	$write_ok = TRUE;
	$offset = 0;
	$length = strlen($contents);
	while ($offset < $length) {
		$written = @fwrite($pipes[0], substr($contents, $offset, 8192));
		if ($written === FALSE || $written === 0) {
			$write_ok = FALSE;
			break;
		}
		$offset += $written;
	}
	if (isset($pipes[0]) && is_resource($pipes[0])) {
		fclose($pipes[0]);
	}
	$exit_code = proc_close($process);
	fflush($stderr);
	rewind($stderr);
	$diagnostics = (string) stream_get_contents($stderr);
	fclose($stderr);
	$diagnostics = str_replace("\0", '\\0', $diagnostics);
	$lines = array_values(array_filter(array_map('trim', preg_split('/\R/', $diagnostics)), static fn(string $line): bool => $line !== ''));
	if (!$write_ok) {
		return ['Python regex validator: stdin write failed'];
	}
	if ($exit_code === 1 && $lines !== []) {
		return $lines;
	}
	if ($exit_code !== 0) {
		$detail = $lines[0] ?? 'no diagnostic';
		return ["Python regex validator: process failed with exit {$exit_code}: {$detail}"];
	}
	return [];
}

/**
 * pfb_header_reserved_error — reject a source Header that collides with a
 * package-synthesized name (issue #1270): DNSBL-IP and the 9 GeoIP continent
 * aliases write to the SAME <header><vtype>.txt path a user list's Header
 * would use (pfb_determine_list_detail() folder routing), so an identical
 * Header silently collides last-writer-wins on disk. Unconditional (not
 * action-scoped) — the collision does not depend on which action/folder the
 * offending list itself routes to.
 *
 * The reserved set is read from $pfb['continents'] (its 9 VALUES) — never
 * $pfb['continent_list'], which is missing pfB_PS — so a future continent
 * addition is automatically covered.
 *
 * @param  string $header  Candidate Header value (already normalised by the
 *                          caller when judging a stored/imported value).
 * @return string          Human-readable error, or '' when not reserved.
 */
function pfb_header_reserved_error(string $header): string
{
	if ($header === '') {
		return '';
	}
	global $pfb;
	$reserved = array_merge(['DNSBLIP'], array_values($pfb['continents']));
	if (in_array($header, $reserved, TRUE)) {
		return "Header field '{$header}' is reserved by pfBlockerNG (DNSBL-IP or a GeoIP continent alias) and cannot be used.";
	}
	return '';
}

/**
 * pfb_normalize_row_header — apply the SAME \W-strip sync_package_pfblockerng()
 * persists onto a stored list-row Header, then judge the RESULT against
 * pfb_header_reserved_error() (issue #1270): a Header arriving via config
 * import/HA-sync (never through the GUI) can normalise onto a reserved name
 * with no save-time check ever having run.
 *
 * @param  string $header  Raw (possibly punctuated) stored Header.
 * @return array{header: string, changed: bool, reserved_error: string}
 */
function pfb_normalize_row_header(string $header): array
{
	$normalized = preg_replace('/\W/', '', $header);
	return [
		'header'         => $normalized,
		'changed'        => $normalized !== $header,
		'reserved_error' => pfb_header_reserved_error($normalized),
	];
}

/**
 * pfb_reserved_header_skip_active — TRUE iff a list-row Header collides with a
 * reserved package-owned name (issue #1270) and the row is NOT the package's
 * own synthesized entry for that name. sync_package_pfblockerng() reads
 * config independently in more than one loop (the download loop and the
 * alias/firewall-rule loop, besides the header-normalize loop); each must
 * refuse the same collision, so the check is one shared, directly-callable
 * predicate rather than re-inlined per loop.
 *
 * @param  bool   $is_reserved_owner  TRUE for the loop's OWN synthesized
 *                                     DNSBLIP row (its `isset($list['dnsblip'])`
 *                                     marker) — exempt from its own guard.
 * @param  string $header             The row's raw Header value.
 */
function pfb_reserved_header_skip_active(bool $is_reserved_owner, string $header): bool
{
	return !$is_reserved_owner && pfb_header_reserved_error($header) !== '';
}

// ---------------------------------------------------------------------------
// ADR-38: pure key=value syslog event formatters (pfb_syslog_format_ip() etc.) — the fixed
// key order, empty-value omission rules, and quoting/escaping are specified in
// .ADRs/ADR_38_System_Log_Integration/ and pinned by tests/php/SyslogFormatTest.php.
// PURE — no globals, no I/O, no config reads.
// ---------------------------------------------------------------------------

/**
 * pfb_syslog_escape — escape a single value for syslog key=value emission:
 * strip newlines, then quote if needed. Shared by pfb_syslog_format_ip() and
 * pfb_syslog_format_dnsbl() (ADR-38).
 *
 * @param string $v  Raw value.
 * @return string    Escaped/quoted value.
 */
function pfb_syslog_escape(string $v): string
{
	// Strip embedded newlines to keep the message single-line.
	$v = str_replace(["\r\n", "\r", "\n"], ' ', $v);
	// Quote if the value contains space, '=', or '"'.
	if (strpos($v, ' ') !== FALSE || strpos($v, '=') !== FALSE || strpos($v, '"') !== FALSE) {
		$v = '"' . str_replace('"', '\\"', $v) . '"';
	}
	return $v;
}

/**
 * pfb_syslog_format_ip — format an IP security event as a key=value string.
 *
 * @param array<string,string> $fields  Associative array of event fields.
 *                                      Keys: act, dir, if, proto, src, dst,
 *                                      sport, dport, ipver, geoip, alias,
 *                                      feed, host, asn.
 * @return string  Space-separated "k=v ..." body; never multi-line.
 */
function pfb_syslog_format_ip(array $fields): string
{
	// Sentinels treated as "absent" for optional fields.
	static $absent_sentinels = ['', 'Unknown', 'Unk', 'null'];

	$parts = [];

	// Required fields — always emitted. Cast to string: a caller may pass a
	// non-string scalar (e.g. FALSE), and pfb_syslog_escape()'s string param
	// would silently coerce it at the call boundary anyway — cast here too
	// for uniformity with the optional-field sites below.
	$parts[] = 'act='   . pfb_syslog_escape((string) ($fields['act'] ?? ''));
	$parts[] = 'dir='   . pfb_syslog_escape((string) ($fields['dir'] ?? ''));
	$parts[] = 'if='    . pfb_syslog_escape((string) ($fields['if'] ?? ''));
	$parts[] = 'proto=' . pfb_syslog_escape((string) ($fields['proto'] ?? ''));
	$parts[] = 'src='   . pfb_syslog_escape((string) ($fields['src'] ?? ''));
	$parts[] = 'dst='   . pfb_syslog_escape((string) ($fields['dst'] ?? ''));

	// Optional integer-ish fields — omit when empty. Cast BEFORE the '' check
	// so a non-string scalar (e.g. FALSE) compares/escapes as its coerced
	// string form, not its raw type.
	$sport = (string) ($fields['sport'] ?? '');
	if ($sport !== '') {
		$parts[] = 'sport=' . pfb_syslog_escape($sport);
	}
	$dport = (string) ($fields['dport'] ?? '');
	if ($dport !== '') {
		$parts[] = 'dport=' . pfb_syslog_escape($dport);
	}

	// Required IP version.
	$parts[] = 'ipver=' . pfb_syslog_escape((string) ($fields['ipver'] ?? ''));

	// Optional enrichment fields — omit when empty or a known absent-sentinel.
	// Cast BEFORE the in_array() sentinel check: a non-string scalar (e.g.
	// FALSE) must coerce to '' first so it matches the '' sentinel, exactly
	// as the retired $get() closure's `: string` return type did.
	foreach (['geoip', 'alias', 'feed', 'host', 'asn'] as $key) {
		$val = (string) ($fields[$key] ?? '');
		if (!in_array($val, $absent_sentinels, TRUE)) {
			$parts[] = $key . '=' . pfb_syslog_escape($val);
		}
	}

	return implode(' ', $parts);
}

// ---------------------------------------------------------------------------
// ADR-38 Amendment 1 — DNSBL syslog + unified.log formatters. pfb_syslog_format_dnsbl()
// (PHP port of the retired Python syslog_format_dnsbl()) formats a DNSBL block event as
// key=value; fixed order act qname qip qtype [group] [feed] btype eval (group/feed omitted
// when ''); escaping matches pfb_syslog_format_ip. pfb_unified_format_ip/_dnsbl/_dnsreply
// render comma-joined unified.log/dnsbl.log rows in FIXED column order — no escaping.
// All four are PURE — no globals, no I/O, no config reads.
// ---------------------------------------------------------------------------

/**
 * pfb_syslog_format_dnsbl — format a DNSBL block event as a key=value string.
 *
 * PHP port of the retired Python syslog_format_dnsbl().  The escaping rule is
 * identical to pfb_syslog_format_ip: values containing a space, '=', or '"'
 * are double-quoted; internal '"' chars are backslash-escaped; newlines are
 * replaced with a space.
 *
 * Fixed key order: act qname qip qtype [group] [feed] btype eval.
 * group/feed are omitted entirely when their value is ''.
 *
 * @param array<string,string> $fields  Keys: q_name, q_ip, q_type, group,
 *                                      feed, b_type, b_eval.  Missing => ''.
 * @return string  Space-separated "k=v ..." body; never multi-line.
 */
function pfb_syslog_format_dnsbl(array $fields): string
{
	// Cast every extraction to string: a caller may pass a non-string scalar
	// (e.g. FALSE), and the '' emptiness check below must see its coerced
	// string form — exactly as the retired $get() closure's `: string`
	// return type did.
	$parts   = [];
	$parts[] = 'act=dnsbl';
	$parts[] = 'qname='  . pfb_syslog_escape((string) ($fields['q_name'] ?? ''));
	$parts[] = 'qip='    . pfb_syslog_escape((string) ($fields['q_ip'] ?? ''));
	$parts[] = 'qtype='  . pfb_syslog_escape((string) ($fields['q_type'] ?? ''));

	// Optional fields — omit the token entirely when the value is ''.
	$group = (string) ($fields['group'] ?? '');
	if ($group !== '') {
		$parts[] = 'group=' . pfb_syslog_escape($group);
	}
	$feed = (string) ($fields['feed'] ?? '');
	if ($feed !== '') {
		$parts[] = 'feed=' . pfb_syslog_escape($feed);
	}

	$parts[] = 'btype=' . pfb_syslog_escape((string) ($fields['b_type'] ?? ''));
	$parts[] = 'eval='  . pfb_syslog_escape((string) ($fields['b_eval'] ?? ''));

	return implode(' ', $parts);
}

/**
 * pfb_unified_format_ip — render an IP unified.log row as a comma-joined string.
 *
 * Owns the column schema for IP rows in unified.log.  Raw passthrough — no
 * escaping applied; the caller appends "\n".
 *
 * @param array<string,string> $fields  Keys (in column order): l_type, log,
 *                                      details, dup.  Missing => ''.
 * @return string  Comma-joined, no trailing newline.
 */
function pfb_unified_format_ip(array $fields): string
{
	return implode(',', [
		$fields['l_type']   ?? '',
		$fields['log']      ?? '',
		$fields['details']  ?? '',
		$fields['dup']      ?? '',
	]);
}

/**
 * pfb_unified_format_dnsbl — render a dnsbl.log CSV line as a comma-joined string.
 *
 * Owns the 11-column schema for DNSBL rows in unified.log (mirrors dnsbl.log
 * exactly).  Raw passthrough — no escaping; the caller appends "\n".
 *
 * Column order: l_type, datetime, q_name, q_ip, p_type, b_type, group,
 *               b_eval, feed, dup, q_type.
 *
 * @param array<string,string> $fields  Keys matching the column names above.
 *                                      Missing => ''.
 * @return string  Comma-joined, no trailing newline.
 */
function pfb_unified_format_dnsbl(array $fields): string
{
	return implode(',', [
		$fields['l_type']    ?? '',
		$fields['datetime']  ?? '',
		$fields['q_name']    ?? '',
		$fields['q_ip']      ?? '',
		$fields['p_type']    ?? '',
		$fields['b_type']    ?? '',
		$fields['group']     ?? '',
		$fields['b_eval']    ?? '',
		$fields['feed']      ?? '',
		$fields['dup']       ?? '',
		$fields['q_type']    ?? '',
	]);
}

/**
 * pfb_unified_format_dnsreply — render a DNS-reply unified.log row as a comma-joined string.
 *
 * Owns the 10-column schema for DNS-reply rows in unified.log.  Raw
 * passthrough — no escaping; the caller appends "\n".
 *
 * Column order: l_type, datetime, m_type, o_type, q_type, ttl, q_name,
 *               q_ip, r_addr, iso_code.
 *
 * @param array<string,string> $fields  Keys matching the column names above.
 *                                      Missing => ''.
 * @return string  Comma-joined, no trailing newline.
 */
function pfb_unified_format_dnsreply(array $fields): string
{
	return implode(',', [
		$fields['l_type']    ?? '',
		$fields['datetime']  ?? '',
		$fields['m_type']    ?? '',
		$fields['o_type']    ?? '',
		$fields['q_type']    ?? '',
		$fields['ttl']       ?? '',
		$fields['q_name']    ?? '',
		$fields['q_ip']      ?? '',
		$fields['r_addr']    ?? '',
		$fields['iso_code']  ?? '',
	]);
}

// ---------------------------------------------------------------------------
// issue #1369 (ADR-38 Amendment 3) -- ASN CSV-column helpers. The internal
// pipe-delimited ASN blob (mmdblookup output flattened by pfblockerng.sh's
// iptoasn(), e.g. "|ASN:  AS50360 | domain:  4vendeta.com | name:  Tamatiya
// EOOD |") stays the wire/cache format for iptoasn()/asncache.asn/the syslog
// asn= value -- these two helpers are the ONLY place that blob is decoded
// into the three plain CSV columns (asn, asn_domain, asn_name) the IP log
// writer now emits, replacing the single blob field in ip_block/permit/
// match.log + unified.log. PURE -- no globals; pfb_asn_csv_fields()'s only
// I/O is an in-memory stream.
// ---------------------------------------------------------------------------

/**
 * pfb_asn_blob_split — split the internal ASN blob into its three labelled
 * parts. The blob is either a bare state literal ('null' when ASN reporting
 * was off at write time, 'Unknown' when the lookup found nothing, or empty)
 * or the pipe-delimited "label:  value" shape above: split on '|' into
 * segments, each segment split at its FIRST ':' into label/value. A blob
 * with no '|' or no ':' (unrecognised shape) is treated as a bare ASN state
 * literal, verbatim.
 *
 * @param string $blob Raw internal ASN value ($asn as pfb_daemon_filterlog builds it).
 * @return array{asn: string, domain: string, name: string}
 */
function pfb_asn_blob_split(string $blob): array
{
	$blob = trim($blob);

	if ($blob === '' || strpos($blob, '|') === FALSE || strpos($blob, ':') === FALSE) {
		return ['asn' => ($blob === '' ? 'Unknown' : $blob), 'domain' => '', 'name' => ''];
	}

	$parts = ['asn' => '', 'domain' => '', 'name' => ''];
	foreach (explode('|', $blob) as $segment) {
		$segment = trim($segment);
		if ($segment === '') {
			continue;
		}
		$colon = strpos($segment, ':');
		if ($colon === FALSE) {
			continue;
		}
		$label = strtolower(trim(substr($segment, 0, $colon)));
		$value = trim(substr($segment, $colon + 1));
		if (array_key_exists($label, $parts) && $value !== '') {
			$parts[$label] = $value;
		}
	}

	if ($parts['asn'] === '') {
		$parts['asn'] = 'Unknown';
	}

	return $parts;
}

/**
 * pfb_asn_csv_fields — render the 3 new ASN CSV columns (asn, asn_domain,
 * asn_name) from the internal blob (pfb_asn_blob_split()), CSV-escaped via
 * native fputcsv() with an explicit empty escape argument -- RFC4180
 * double-quote doubling, never PHP's default backslash-escape quirk -- so a
 * comma/quote/colon/Unicode value in the domain or organisation name
 * round-trips through fgetcsv() with no bespoke escaping. CR/LF is
 * normalized to a single space FIRST so the written row always stays one
 * physical line (reverse-tail readers rely on this).
 *
 * @param string $blob Raw internal ASN blob/state.
 * @return string Three comma-joined, CSV-escaped fields (no trailing newline).
 */
function pfb_asn_csv_fields(string $blob): string
{
	$split = pfb_asn_blob_split($blob);

	$row = array_map(
		static function (string $v): string {
			return str_replace(["\r\n", "\r", "\n"], ' ', $v);
		},
		[$split['asn'], $split['domain'], $split['name']]
	);

	$fh = fopen('php://temp', 'r+');
	fputcsv($fh, $row, ',', '"', '');
	rewind($fh);
	$line = (string) stream_get_contents($fh);
	fclose($fh);

	return rtrim($line, "\r\n");
}

/**
 * pfb_csv_field — one CSV field under the same issue-#1369 contract
 * pfb_asn_csv_fields() writes (fputcsv semantics, explicit empty escape,
 * CR/LF normalized to spaces): quoted ONLY when the value needs it, so
 * well-formed values serialize byte-identically to the bare join they
 * replace. issue #1784: admin-authored descr/hostname values reach the
 * comma-joined alert $details line unfiltered; quoting at the join is the
 * single guard (every reader is already fgetcsv-quote-aware).
 */
function pfb_csv_field(string $value): string
{
	$value = str_replace(["\r\n", "\r", "\n"], ' ', $value);
	if (strpbrk($value, ",\"") === FALSE) {
		return $value;
	}
	return '"' . str_replace('"', '""', $value) . '"';
}

/**
 * pfb_ip_log_row_schema_ok — exact field-count schema gate for a raw
 * (pre-timestamp-shift) IP feature-log row as delivered to convert_ip_log().
 * Only the current 23-field feature-row / 24-field Unified-row schema (see
 * .ADRs/ADR_38_System_Log_Integration/ Amendment 3) is supported; ANY other
 * count -- including every pre-upgrade legacy (21-field feature / 22-field
 * Unified) row still on disk -- must be rejected BEFORE a single indexed
 * field access, so a short/garbage row never trips an "undefined array key"
 * notice downstream.
 *
 * $mode distinguishes 'Unified' (leading event-type field already stripped
 * by the caller, trailing duplicate marker still attached -- 23 raw fields)
 * from every other caller (duplicate marker already popped -- 22 raw fields).
 *
 * @param array<int,mixed> $fields Raw fgetcsv() row, before convert_ip_log()'s
 *                                 own timestamp-shift reorder.
 * @param string            $mode  'Unified' or 'non_unified'.
 * @return bool
 */
function pfb_ip_log_row_schema_ok(array $fields, string $mode): bool
{
	return count($fields) === ($mode === 'Unified' ? 23 : 22);
}

// ---------------------------------------------------------------------------
// ADR-38 — PHP syslog event emitter. pfb_syslog_event(string $body) emits ONE record with
// ident 'pfblockerng' at a FIXED facility (LOG_LOCAL6) and severity (LOG_INFO) — not
// user-configurable: the package <logging> PROGRAM-name filter routes events regardless of
// facility, and every event is the same informational-security class. Reads log_syslog FRESH
// on every call (no per-process cache) since the long-running pfb_filter daemon is the sole
// caller and the user can toggle it live; no-op when off (PfbToggle::Off / '').
// ---------------------------------------------------------------------------

/**
 * pfb_syslog_event — emit a single syslog record for one security event.
 *
 * Reads log_syslog FRESH from PfbConfig on every call. Fixed facility LOG_LOCAL6
 * and severity LOG_INFO. No-op when the toggle is off.
 *
 * TEST SEAM: when $GLOBALS['pfb_test_syslog_spy'] is set (to any non-null value),
 * the call is recorded in $GLOBALS['pfb_test_syslog_calls'] instead of hitting
 * the real built-ins. The legacy $GLOBALS['pfb_test_syslog_reset'] flag is
 * accepted but inert (there is no longer a cache to reset).
 *
 * @param  string $body  The key=value message body (output of pfb_syslog_format_ip()).
 * @return void
 */
function pfb_syslog_event(string $body): void
{
	// Legacy reset flag is a no-op now (no cache) — clear it so it cannot leak.
	unset($GLOBALS['pfb_test_syslog_reset']);

	// Fresh gate: read the current toggle on every call.
	if (PfbConfig::read('log_syslog') !== PfbToggle::On) {
		return;
	}

	pfb_syslog_emit($body);
}


/**
 * pfb_syslog_emit — the raw pfblockerng-ident syslog emitter (issue #1769 B3).
 *
 * openlog('pfblockerng')/syslog/closelog is the ONLY mechanism that reaches
 * /var/log/pfblockerng_syslog.log: the syslog.d routing is program-based
 * (`!pfblockerng`), so a bare logger()/syslog() call without the ident lands
 * in NO file at all (probed live on CE 2.8 — not system.log either, since
 * user.info clears no selector there). Ungated — callers that need the
 * log_syslog toggle gate go through pfb_syslog_event().
 *
 * TEST SEAM: same spy as pfb_syslog_event() — when
 * $GLOBALS['pfb_test_syslog_spy'] is set, the call is recorded in
 * $GLOBALS['pfb_test_syslog_calls'] instead of hitting the real built-ins.
 */
function pfb_syslog_emit(string $body): void
{
	if (isset($GLOBALS['pfb_test_syslog_spy'])) {
		$GLOBALS['pfb_test_syslog_calls'][] = [
			'ident'    => 'pfblockerng',
			'facility' => LOG_LOCAL6,
			'severity' => LOG_INFO,
			'body'     => $body,
		];
		return;
	}

	openlog('pfblockerng', LOG_PID, LOG_LOCAL6);
	syslog(LOG_INFO, $body);
	closelog();
}

// ---------------------------------------------------------------------------
// ADR-43 — Due-ledger library: persisted per-job next-due ledger (pfb_due_ledger.json under
// $pfb['dbdir']) recording {last_run, next_due, jitter} so a tick decides what's due without
// per-job clock reads. Invariants (§2.C): absent/corrupt -> is_due TRUE (fail-safe, sole
// boot-stampede defence pending earlyshellcmd archival); next_due past -> TRUE, future ->
// FALSE; mark_ran sets next_due = now + interval + seeded_jitter(job, seed, max). Atomic
// writes (.tmp + LOCK_EX + rename); clock/seed INJECTABLE for PHPUnit determinism.
// Tests: tests/php/DueLedgerTest.php
// ---------------------------------------------------------------------------

/**
 * pfb_due_ledger_seeded_jitter — deterministic jitter offset for a job/seed pair.
 *
 * Returns a stable offset in [1, $max] for $max > 0, or 0 for $max === 0.
 * The result is identical for the same ($job_key, $seed, $max) triple on every
 * call, so the schedule is stable across reboots once the ledger is restored.
 * Different $job_key values with the same $seed produce different offsets (with
 * high probability for typical $max values), spreading concurrent jobs across
 * time and preventing upstream stampedes that today's rand(0,23) jitter prevents.
 *
 * PURE — no I/O, no globals, never calls rand() or time().
 *
 * @param string $job_key  Job identifier (e.g. 'dcc', 'bl').
 * @param string $seed     Per-install seed (e.g. derived from hostname or config).
 * @param int    $max      Maximum jitter (seconds or any unit). 0 disables jitter.
 * @return int             Jitter in [1, $max] when $max > 0; else 0.
 */
function pfb_due_ledger_seeded_jitter(string $job_key, string $seed, int $max): int
{
	if ($max <= 0) {
		return 0;
	}
	// crc32() returns a signed 32-bit int stored as 64-bit on PHP 8 / 64-bit FreeBSD.
	// abs() maps to [0, 2^31-1]; % $max gives [0, max-1]; +1 shifts to [1, max].
	// Guarantees non-zero: every job gets a spread offset, preventing stampedes.
	return (abs(crc32($seed . ':' . $job_key)) % $max) + 1;
}

/**
 * pfb_due_ledger_is_due_from_entry — decide due/not-due from a pre-read entry.
 *
 * Separating the I/O from the decision enables deterministic unit tests:
 * the caller reads the entry (or passes null for absent), this function decides.
 *
 * PURE — no I/O, no globals, no side effects.
 *
 * @param array|null $entry  {last_run: int, next_due: int, jitter: int} or NULL.
 * @param int        $now    Current epoch timestamp (injectable in tests).
 * @return bool              TRUE iff the job is due or the entry is absent.
 */
function pfb_due_ledger_is_due_from_entry(?array $entry, int $now): bool
{
	if ($entry === NULL) {
		// Absent (new install, wiped RAM-disk) ⇒ due now; jitter applied on mark_ran.
		return TRUE;
	}
	return $entry['next_due'] <= $now;
}

/**
 * pfb_due_ledger_read_entry — read one job entry from the on-disk ledger.
 *
 * Returns NULL on absent file, I/O error, or any corruption (fail-safe: absent
 * is always treated as "due now" by pfb_due_ledger_is_due_from_entry).
 *
 * @param string $job_key     Job identifier (e.g. 'dcc', 'bl').
 * @param string $ledger_dir  Directory that contains pfb_due_ledger.json.
 * @return array|null         {last_run: int, next_due: int, jitter: int} or NULL.
 */
function pfb_due_ledger_read_entry(string $job_key, string $ledger_dir): ?array
{
	$path = $ledger_dir . '/pfb_due_ledger.json';
	if (!is_file($path)) {
		return NULL;
	}
	$fp = @fopen($path, 'r');
	if ($fp === FALSE) {
		return NULL;
	}
	if (!flock($fp, LOCK_SH)) {
		fclose($fp);
		return NULL;
	}
	$raw = stream_get_contents($fp);
	flock($fp, LOCK_UN);
	fclose($fp);
	if ($raw === FALSE || $raw === '') {
		return NULL;
	}
	$data = json_decode($raw, TRUE);
	if (!is_array($data)) {
		return NULL;	// corrupt or not a JSON object
	}
	$entry = $data[$job_key] ?? NULL;
	if (!is_array($entry)) {
		return NULL;	// key absent
	}
	// Validate structure: all three integer fields must be present.
	if (!isset($entry['last_run'], $entry['next_due'], $entry['jitter'])
		|| !is_int($entry['last_run'])
		|| !is_int($entry['next_due'])
		|| !is_int($entry['jitter'])) {
		return NULL;	// malformed entry — fail-safe
	}
	return $entry;
}

/**
 * pfb_due_ledger_write_entry — atomically persist one job entry to the ledger.
 *
 * Reads the existing ledger (to preserve other jobs' entries), merges $entry
 * under $job_key, then writes to a .tmp file with LOCK_EX and renames to the
 * target (atomic on POSIX / FreeBSD same-filesystem rename).
 *
 * @param string $job_key     Job identifier.
 * @param array  $entry       {last_run: int, next_due: int, jitter: int}.
 * @param string $ledger_dir  Directory that contains pfb_due_ledger.json.
 * @return void
 */
function pfb_due_ledger_write_entry(string $job_key, array $entry, string $ledger_dir): void
{
	$path = $ledger_dir . '/pfb_due_ledger.json';
	$tmp  = $path . '.tmp';

	// Merge with existing data (tolerate absent/corrupt: start with empty object).
	$data = [];
	if (is_file($path)) {
		$raw = @file_get_contents($path);
		if ($raw !== FALSE && $raw !== '') {
			$decoded = json_decode($raw, TRUE);
			if (is_array($decoded)) {
				$data = $decoded;
			}
		}
	}
	$data[$job_key] = $entry;
	file_put_contents($tmp, json_encode($data, JSON_PRETTY_PRINT), LOCK_EX);
	rename($tmp, $path);
}

/**
 * pfb_due_ledger_is_due — is the named job due to run on this tick?
 *
 * Reads the persisted entry for $job_key and applies the due rule. The $interval,
 * $seed, and $jitter_max parameters are accepted for API parity with mark_ran but
 * do not affect the is_due decision (the decision is based solely on next_due vs now).
 *
 * Absent or corrupt entry ⇒ TRUE (fail-safe: run now, jitter applied on mark_ran).
 * next_due ≤ $now         ⇒ TRUE (catch-up: missed window runs on the next tick).
 * next_due >  $now        ⇒ FALSE (not yet due).
 *
 * @param string $job_key     Job identifier (e.g. 'dcc', 'bl_weekly').
 * @param int    $interval    Job cadence in seconds (for API parity; not used here).
 * @param int    $now         Current epoch timestamp (injectable in tests).
 * @param string $seed        Per-install seed (for API parity; not used here).
 * @param int    $jitter_max  Max jitter in seconds (for API parity; not used here).
 * @param string $ledger_dir  Directory that contains pfb_due_ledger.json.
 * @return bool               TRUE iff the job should run this tick.
 */
function pfb_due_ledger_is_due(
	string $job_key,
	int    $interval,
	int    $now,
	string $seed,
	int    $jitter_max,
	string $ledger_dir
): bool {
	return pfb_due_ledger_is_due_from_entry(
		pfb_due_ledger_read_entry($job_key, $ledger_dir),
		$now
	);
}

/**
 * pfb_due_ledger_mark_ran — record that the job ran and schedule the next run.
 *
 * Persists {last_run: $now, next_due: $now+$interval+jitter, jitter: jitter}
 * where jitter = pfb_due_ledger_seeded_jitter($job_key, $seed, $jitter_max).
 * The same (job_key, seed, max) triple always produces the same jitter, so the
 * per-job schedule spread is stable across reboots (given a stable install seed).
 *
 * @param string $job_key     Job identifier (e.g. 'dcc', 'bl').
 * @param int    $interval    Job cadence in seconds.
 * @param int    $now         Current epoch timestamp (injectable in tests).
 * @param string $seed        Per-install seed.
 * @param int    $jitter_max  Max jitter in seconds (0 = no jitter).
 * @param string $ledger_dir  Directory that contains pfb_due_ledger.json.
 * @return void
 */
function pfb_due_ledger_mark_ran(
	string $job_key,
	int    $interval,
	int    $now,
	string $seed,
	int    $jitter_max,
	string $ledger_dir
): void {
	$jitter = pfb_due_ledger_seeded_jitter($job_key, $seed, $jitter_max);
	pfb_due_ledger_write_entry($job_key, [
		'last_run' => $now,
		'next_due' => $now + $interval + $jitter,
		'jitter'   => $jitter,
	], $ledger_dir);
}

/**
 * pfb_due_ledger_mark_ran_anchored — record a run and schedule the next occurrence,
 * anchored to the PREVIOUS next_due instead of "now" (issue #573: cron phase creep).
 *
 * pfb_due_ledger_mark_ran() anchors on $now (tick-start wall clock), so
 * next_due = tick_start + interval. Whenever the NEXT tick happens to start even a
 * fraction of a second faster than the previous one did, next_due misses it by that
 * fraction and the pass slips a full tick interval late. Repeated across ticks the
 * phase creeps monotonically forward; once it crosses a calendar-hour boundary, any
 * per-feed EveryDay/Weekly schedule whose configured hour lands on the now-skipped
 * hour silently misses its window (their gates in pfblockerng_sync_cron() are
 * hour-equality checks, so a skipped hour is a skipped run, not a late one).
 *
 * This variant re-anchors on the entry's PREVIOUS next_due instead of $now whenever
 * that base represents an on-time (or barely-missed) occurrence, so the cadence
 * locks to its original phase with zero cumulative slip. Falls back to plain
 * catch-up-from-now in every other case:
 *   - entry NULL (no prior run), or next_due == 0 (a set_pending placeholder with
 *     nothing meaningful to anchor to)             ⇒ base = $now.
 *   - next_due in the future relative to $now (clock skew, or an already-pending
 *     future entry)                                ⇒ base = $now (never anchor
 *     forward).
 *   - next_due more than one $interval in the past (a real catch-up: offline box,
 *     or the schedule was gated off for a long stretch) ⇒ base = $now, so the
 *     schedule re-phases from this catch-up run rather than firing every tick
 *     until a stale anchor drags current.
 *   - otherwise — 0 ≤ ($now - next_due) < $interval, the ordinary "missed the
 *     boundary by a fraction of a tick" case this fix targets ⇒ base = the entry's
 *     next_due, so the new next_due advances by exactly $interval every cycle.
 *
 * @param string $job_key     Job identifier (e.g. 'cron').
 * @param int    $interval    Job cadence in seconds.
 * @param int    $now         Current epoch timestamp (injectable in tests).
 * @param string $seed        Per-install seed.
 * @param int    $jitter_max  Max jitter in seconds (0 = no jitter).
 * @param string $ledger_dir  Directory that contains pfb_due_ledger.json.
 * @return void
 */
function pfb_due_ledger_mark_ran_anchored(
	string $job_key,
	int    $interval,
	int    $now,
	string $seed,
	int    $jitter_max,
	string $ledger_dir
): void {
	$entry = pfb_due_ledger_read_entry($job_key, $ledger_dir);

	$base = $now;
	if ($entry !== NULL
		&& $entry['next_due'] > 0
		&& $now >= $entry['next_due']
		&& ($now - $entry['next_due']) < $interval) {
		$base = $entry['next_due'];
	}

	$jitter = pfb_due_ledger_seeded_jitter($job_key, $seed, $jitter_max);
	pfb_due_ledger_write_entry($job_key, [
		'last_run' => $now,
		'next_due' => $base + $interval + $jitter,
		'jitter'   => $jitter,
	], $ledger_dir);
}

/**
 * pfb_tick_interval_clamp — clamp a raw pfb_tick_interval config value to a valid cron minute.
 *
 * Accepts the raw string from PfbConfig::read('pfb_tick_interval') and returns an int
 * suitable for use as the cron minute field (1–60). Non-numeric or out-of-range values
 * are clamped: 0 → 1, >60 → 60, non-int (e.g. 'abc') → 1.
 *
 * @param string $raw   Raw config value (e.g. '15', '0', '100', 'abc').
 * @return int          Clamped interval in [1, 60].
 */
function pfb_tick_interval_clamp(string $raw): int
{
	return max(1, min(60, (int) $raw));
}

/**
 * pfb_next_tick_boundary — when does the next cron tick fire?
 *
 * The ADR-43 scheduler is one cron tick that fires every $tick_min minutes (the cron minute
 * field is "star-slash-N"), so it runs at each minute-of-hour that is a multiple of $tick_min,
 * rolling to :00 of the next hour. Given the current wall-clock, returns the next boundary so
 * the Update page can show "next run at" and "time remaining" for the actual scheduled cron
 * (not the legacy per-feed interval cadence).
 *
 * @param int $tick_min  Clamped tick interval in minutes (see pfb_tick_interval_clamp).
 * @param int $cur_hour  Current hour (0–23).
 * @param int $cur_min   Current minute (0–59).
 * @param int $cur_sec   Current second (0–59).
 * @return array{0:int,1:int,2:int}  [next_hour (0–23), next_min (0–59), seconds_remaining].
 */
function pfb_next_tick_boundary(int $tick_min, int $cur_hour, int $cur_min, int $cur_sec): array
{
	$tick_min = max(1, $tick_min);
	$cur_hour_sec = ($cur_min * 60) + $cur_sec;

	$next_min = (intdiv($cur_min, $tick_min) + 1) * $tick_min;
	if ($next_min >= 60) {
		// The minute field never fires past :59, so it rolls to :00 of the next hour.
		return [($cur_hour + 1) % 24, 0, 3600 - $cur_hour_sec];
	}
	return [$cur_hour, $next_min, ($next_min * 60) - $cur_hour_sec];
}

/**
 * pfb_tick_seed — stable per-install seed for the due-ledger jitter.
 *
 * Uses the system hostname (stable across reboots unless the admin changes it).
 *
 * @return string  Non-empty seed string.
 */
function pfb_tick_seed(): string
{
	$h = php_uname('n');
	return ($h !== '') ? $h : 'pfblockerng';
}

/**
 * pfb_tick_due_jobs — which scheduled jobs are due this tick?
 *
 * Delegates to the due-ledger API for each job. The $now, $seed, and
 * $dbdir are injectable so PHPUnit can verify cadence without filesystem or
 * wall-clock dependencies. ss_refresh is not returned — it runs every tick
 * unconditionally (called directly by pfblockerng_tick()).
 *
 * @param int    $now            Current epoch timestamp.
 * @param string $seed           Per-install seed for seeded_jitter.
 * @param string $dbdir          Ledger directory (live = $pfb['dbdir']).
 * @param int    $cron_interval  Feed cron interval in seconds.
 * @param int    $bl_interval    Blacklist interval in seconds (86400 or 604800).
 * @return array<string,bool>    Map: job_key => TRUE when due.
 */
function pfb_tick_due_jobs(
	int    $now,
	string $seed,
	string $dbdir,
	int    $cron_interval,
	int    $bl_interval
): array {
	$jitter_max = 23 * 3600;	// 82800 s mirrors the old rand(0,23)*3600 spread

	return [
		'cron' => pfb_due_ledger_is_due('cron', $cron_interval, $now, $seed, 0,           $dbdir),
		'dcc'  => pfb_due_ledger_is_due('dcc',  86400,          $now, $seed, $jitter_max,  $dbdir),
		'bl'   => pfb_due_ledger_is_due('bl',   $bl_interval,   $now, $seed, $jitter_max,  $dbdir),
	];
}

// ---------------------------------------------------------------------------
// ADR-43 — apply-on-change maintenance window + pending helpers
// ---------------------------------------------------------------------------

/**
 * pfb_quiet_hours_in_window — is $now inside the configured apply-on-change window?
 *
 * When set, detected changes are only applied INSIDE the window; outside they are
 * deferred (pending) until the next tick inside the window. Format: "HH:MM-HH:MM"
 * in local time (e.g. "02:00-06:00"). Wrapping midnight is supported ("23:00-03:00").
 *
 * Empty string ⇒ TRUE (apply immediately, no deferral — the default).
 * Malformed string ⇒ TRUE (fail-safe: apply immediately rather than defer forever).
 * Zero-width window (start == end) ⇒ TRUE (no meaningful deferral, apply immediately).
 *
 * @param int    $now    Current epoch timestamp (injectable for tests).
 * @param string $window "HH:MM-HH:MM" (local time) or '' (no window, apply immediately).
 * @return bool          TRUE = apply now; FALSE = outside window, defer.
 */
function pfb_quiet_hours_in_window(int $now, string $window): bool
{
	if ($window === '') {
		return TRUE;
	}
	if (!preg_match('/^(\d{1,2}):(\d{2})-(\d{1,2}):(\d{2})$/', $window, $m)) {
		return TRUE;	// malformed → fail-safe: apply immediately
	}
	// Validate hour ≤ 23 and minute ≤ 59 for both endpoints; the regex allows h=25/m=99.
	// Out-of-range → fail-safe: apply immediately (defers forever otherwise).
	if ((int)$m[1] > 23 || (int)$m[2] > 59 || (int)$m[3] > 23 || (int)$m[4] > 59) {
		return TRUE;	// out-of-range → fail-safe: apply immediately
	}
	$start = (int)$m[1] * 60 + (int)$m[2];
	$end   = (int)$m[3] * 60 + (int)$m[4];
	$cur   = (int)date('G', $now) * 60 + (int)date('i', $now);

	if ($start === $end) {
		return TRUE;	// zero-width window = no deferral
	}
	if ($start < $end) {
		return $cur >= $start && $cur < $end;	// normal window e.g. 02:00–06:00
	}
	return $cur >= $start || $cur < $end;		// wraps midnight e.g. 23:00–03:00
}

/**
 * pfb_due_ledger_set_pending — mark a job as pending-apply (deferred by quiet-hours window).
 *
 * Reads the existing ledger entry and sets pending_apply=TRUE, then writes back atomically.
 * If no entry exists, creates a "due-now" placeholder with pending_apply=TRUE.
 *
 * The pending flag is cleared implicitly when pfb_due_ledger_mark_ran() writes a clean
 * {last_run, next_due, jitter} entry (no pending_apply key).
 *
 * @param string $job_key    Job identifier (e.g. 'cron', 'dcc', 'bl').
 * @param string $ledger_dir Directory that contains pfb_due_ledger.json.
 * @return void
 */
function pfb_due_ledger_set_pending(string $job_key, string $ledger_dir): void
{
	$entry = pfb_due_ledger_read_entry($job_key, $ledger_dir);
	if ($entry === NULL) {
		$entry = ['last_run' => 0, 'next_due' => 0, 'jitter' => 0];
	}
	$entry['pending_apply'] = TRUE;
	pfb_due_ledger_write_entry($job_key, $entry, $ledger_dir);
}

/**
 * pfb_due_ledger_is_pending — is there a deferred apply pending for this job?
 *
 * Returns TRUE iff pfb_due_ledger_set_pending() has been called for this job and
 * pfb_due_ledger_mark_ran() has not yet cleared it.
 *
 * @param string $job_key    Job identifier (e.g. 'cron', 'dcc', 'bl').
 * @param string $ledger_dir Directory that contains pfb_due_ledger.json.
 * @return bool              TRUE when pending_apply is set and not yet cleared.
 */
function pfb_due_ledger_is_pending(string $job_key, string $ledger_dir): bool
{
	$entry = pfb_due_ledger_read_entry($job_key, $ledger_dir);
	return $entry !== NULL && !empty($entry['pending_apply']);
}

/**
 * pfblockerng_tick — ADR-43: apply-on-change due-ledger tick dispatcher.
 *
 * Reads the ledger and handles both cadence advancement and separate-process dispatch via
 * exec() for each due job (feeds, dcc, bl). ss_refresh runs every tick; the scheduled
 * log maintenance (pfb_log_mgmt) runs only on an idle tick (see below).
 *
 * Lives here (not in the www/ dispatcher script) rather than the reverse so the
 * PHPUnit bootstrap can load and call the real entrypoint off-appliance: the www
 * script is never require()'d by the test suite, so before this move the tick had
 * zero off-box coverage (review finding ADR43-5). Both www dispatch verbs -- the direct
 * `pfblockerng.php tick` and the crontab's `cron-tick` (gated by .pfb_cron_disable) -- just
 * call this function.
 *
 * Apply-on-change (ADR-40 IP / ADR-10 DNSBL): a due job dispatches pfb_trigger, which
 * calls sync_package_pfblockerng() — ADR-40 gates alias apply on pfb_alias_set_different()
 * and ADR-10 uses zero-downtime swap for DNSBL; no apply happens when nothing changed.
 *
 * Optional quiet-hours window (pfb_quiet_hours): when set and the current time is OUTSIDE
 * the window, a due job is deferred (pending_apply recorded in the ledger); the next tick
 * inside the window applies it. Default '' = apply immediately on every due tick.
 *
 * Cadence seeding from legacy knobs (§2.G — no config.xml migration):
 *   feed cron : PfbConfig::read('pfb_interval') hours; skip scheduled runs when 'Disabled'.
 *   dcc       : 86400 s daily, jitter = seeded_jitter (stable per install).
 *   bl        : 86400 or 604800 s, jitter = seeded_jitter (stable per install).
 *
 * Scheduled log maintenance (pfb_log_mgmt) runs at the end of every tick, independent of
 * the feed-cron cadence above (issue #573: with pfb_interval='Disabled' the feed cron
 * never dispatches, so log maintenance can no longer ride its tail the way it used to
 * inside pfblockerng_sync_cron()) -- but ONLY on an IDLE tick: skipped when this tick just
 * dispatched an update pass (cron/dcc/bl) or one from an earlier tick is still running
 * (pfb_update_pass_running()). Both dispatch and a backgrounded pass append to
 * $pfb['log']/$pfb['extraslog'] for potentially minutes; pfb_log_mgmt()'s
 * tail-to-temp-then-cat-over trim is a read/truncate/rewrite window that would lose any
 * lines the concurrent writer appends during it.
 */
function pfblockerng_tick(): void
{
	global $pfb;

	$now   = time();
	$seed  = pfb_tick_seed();
	$dbdir = $pfb['dbdir'];
	// Set TRUE by any branch below that actually dispatches (exec()s) an update pass
	// this tick -- gates the log-maintenance race guard at the tail of this function.
	$dispatched = FALSE;

	// --- Cadence from legacy knobs ---
	$raw_interval  = PfbConfig::read('pfb_interval');
	$cron_disabled = ($raw_interval === 'Disabled');
	$cron_secs     = $cron_disabled ? 0 : (max(1, (int)$raw_interval) * 3600);

	$bl_secs = 86400;
	if (!empty($pfb['blconfig']['blacklist_freq']) && $pfb['blconfig']['blacklist_freq'] === 'Weekly') {
		$bl_secs = 604800;
	}

	// --- Due check ---
	$due = pfb_tick_due_jobs($now, $seed, $dbdir, $cron_secs, $bl_secs);

	// --- Apply-on-change window (ADR-43) ---
	// Empty window = apply immediately (default). Non-empty = defer outside window.
	$window = (string) PfbConfig::read('pfb_quiet_hours');
	$in_win = pfb_quiet_hours_in_window($now, $window);

	// --- Dispatch due (or pending) jobs; defer when outside the apply window ---

	// Scheduled feed cron: dispatch the `cron` verb (-> pfblockerng_sync_cron), NOT pfb_trigger
	// directly. pfblockerng_sync_cron applies each feed's per-list Update Frequency
	// ($list['cron']: EveryDay/Weekly/NNhour) before its final sync_package_pfblockerng('cron'),
	// and runs the ADR-19 software-update check at the end -- both of which a bare
	// `pfb_trigger scope=both` skips (it would poll every feed every tick and never
	// run the once-per-pass update check). Apply-on-change still happens via ADR-40
	// (IP) + ADR-10 (DNSBL) inside that final sync. Backgrounded so the tick stays
	// fast. The scheduled log trim no longer rides this dispatch (issue #573) --
	// see pfb_log_mgmt() at the end of this function.
	$cron_entry   = pfb_due_ledger_read_entry('cron', $dbdir);
	$cron_pending = $cron_entry !== NULL && !empty($cron_entry['pending_apply']);
	if ((!$cron_disabled && $due['cron']) || $cron_pending) {
		if ($in_win && pfb_feed_pass_busy()) {
			// issue #1175: a running feed pass would race the shared recompute staging --
			// defer via pending so the NEXT tick retries. busy() is advisory only: the
			// child's atomic begin() may still lose a dispatcher race and skip one cycle.
			logger(LOG_INFO, localize_text('Tick: feed cron deferred (another feed pass is running).'), LOG_PREFIX_PKG_PFBLOCKERNG);
			pfb_due_ledger_set_pending('cron', $dbdir);
		} elseif ($in_win) {
			if ($cron_disabled) {
				logger(LOG_NOTICE, localize_text('Tick: dispatching pending manual apply.'), LOG_PREFIX_PKG_PFBLOCKERNG);
				unset($cron_entry['pending_apply']);
				pfb_due_ledger_write_entry('cron', $cron_entry, $dbdir);
				exec("{$pfb['php']} /usr/local/www/pfblockerng/pfblockerng.php pfb_trigger scope=both force=false trigger=manual >> {$pfb['runlog']} 2>&1 &");
			} else {
				logger(LOG_NOTICE, localize_text('Tick: dispatching feed cron.'), LOG_PREFIX_PKG_PFBLOCKERNG);
				pfb_due_ledger_mark_ran_anchored('cron', $cron_secs, $now, $seed, 0, $dbdir);
				exec("{$pfb['php']} /usr/local/www/pfblockerng/pfblockerng.php cron >> {$pfb['runlog']} 2>&1 &");
			}
			$dispatched = TRUE;
		} else {
			logger(LOG_INFO, localize_text('Tick: feed cron deferred (outside apply window).'), LOG_PREFIX_PKG_PFBLOCKERNG);
			pfb_due_ledger_set_pending('cron', $dbdir);
		}
	}

	// MaxMind/TOP1M/ASN: daily, jittered.
	if ($due['dcc'] || pfb_due_ledger_is_pending('dcc', $dbdir)) {
		if ($in_win) {
			logger(LOG_NOTICE, localize_text('Tick: dispatching dcc.'), LOG_PREFIX_PKG_PFBLOCKERNG);
			exec("{$pfb['php']} /usr/local/www/pfblockerng/pfblockerng.php dcc >> {$pfb['extraslog']} 2>&1 &");
			pfb_due_ledger_mark_ran('dcc', 86400, $now, $seed, 23 * 3600, $dbdir);
			$dispatched = TRUE;
		} else {
			logger(LOG_INFO, localize_text('Tick: dcc deferred (outside apply window).'), LOG_PREFIX_PKG_PFBLOCKERNG);
			pfb_due_ledger_set_pending('dcc', $dbdir);
		}
	}

	// Blacklist: daily or weekly, jittered. Build bl_string from blconfig.
	if (($due['bl'] || pfb_due_ledger_is_pending('bl', $dbdir)) && $pfb['enable'] == 'on' &&
	    !empty($pfb['blconfig']) &&
	    !empty($pfb['blconfig']['blacklist_enable']) && $pfb['blconfig']['blacklist_enable'] != 'Disable' &&
	    !empty($pfb['blconfig']['blacklist_selected']) && isset($pfb['blconfig']['item'])) {

		if ($in_win) {
			$bl_str = '';
			$bl_sel = array_flip(explode(',', $pfb['blconfig']['blacklist_selected'])) ?: [];
			foreach ($pfb['blconfig']['item'] as $bl_item) {
				if (isset($bl_sel[$bl_item['xml']]) && !empty($bl_item['selected'])) {
					$bl_str .= ",{$bl_item['xml']}";
				}
			}
			$bl_str = pfb_filter(ltrim($bl_str, ','), PFB_FILTER_CSV, 'Tick bl dispatch');

			if (!empty($bl_str)) {
				logger(LOG_NOTICE, localize_text('Tick: dispatching bl.'), LOG_PREFIX_PKG_PFBLOCKERNG);
				exec("{$pfb['php']} /usr/local/www/pfblockerng/pfblockerng.php bl " . escapeshellarg($bl_str) . " >> {$pfb['extraslog']} 2>&1 &");
				pfb_due_ledger_mark_ran('bl', $bl_secs, $now, $seed, 23 * 3600, $dbdir);
				$dispatched = TRUE;
			}
		} else {
			logger(LOG_INFO, localize_text('Tick: bl deferred (outside apply window).'), LOG_PREFIX_PKG_PFBLOCKERNG);
			pfb_due_ledger_set_pending('bl', $dbdir);
		}
	}

	// SafeSearch CNAME freshness: every tick (cheap DNS re-resolution).
	pfblockerng_ss_refresh();

	// ADR-61: apply-stage reconciliation. Unconditional -- never gated on $due or
	// pending state -- and touches ONLY stage='apply' entries (Semantics #5);
	// download/parse/dedup stages keep their normal cadence, untouched here.
	foreach (pfb_sync_status_list_open($dbdir) as $entry) {
		if ($entry['stage'] !== 'apply') {
			continue;
		}
		if ($entry['facility'] === 'ip') {
			pfb_ip_apply_retry($entry['item']);
		} elseif ($entry['facility'] === 'dnsbl') {
			pfb_dnsbl_apply_retry();
		}
	}

	// Scheduled log maintenance (issue #573): runs on every IDLE tick, independent of
	// the feed-cron gate above -- pfb_interval='Disabled' must not silently stop log
	// upkeep. pfb_log_mgmt() self-gates by its own configured per-log line/age caps, so
	// calling it every idle tick is safe: most calls are a no-op. Skipped when THIS tick
	// dispatched an update pass ($dispatched) or an earlier one is still running
	// (pfb_update_pass_running()) -- both append to the same log files pfb_log_mgmt()'s
	// tail-to-temp-then-cat-over trim reads/truncates/rewrites, and racing that window
	// against a live writer loses whatever it appends meanwhile.
	if (!$dispatched && !pfb_update_pass_running()) {
		pfb_log_mgmt();
	} elseif ($dispatched) {
		// Skip is observable on the pfblockerng_syslog.log surface (issue #1769
		// B3/B4: pfb_syslog_emit is the only mechanism that reaches it) -- never
		// $pfb['log'], whose byte-identity on a dispatching tick is pinned and
		// which pfb_log_mgmt() itself trims.
		pfb_syslog_emit(localize_text('Tick: log maintenance skipped (this tick dispatched an update pass).'));
	} else {
		// Same surface as the $dispatched arm (issue #1769 B4): writing this to
		// $pfb['log'] would grow the very file whose trim is being deferred.
		pfb_syslog_emit(localize_text('Tick: log maintenance deferred (an update pass is running).'));
	}
}

// ---------------------------------------------------------------------------
// ADR-61 — Sync-status ledger: a general-purpose open-issues ledger recording
// {facility, item, stage} -> {message, first_seen, last_seen} in
// pfb_sync_status.json under a ledger dir, mirroring pfb_due_ledger_*'s pure,
// clock-injectable, atomic-write idiom above. Writers/clearers live in
// pfblockerng.inc; pfblockerng_tick() (above) retries open stage=apply entries
// every tick. Tests: tests/php/PfbSyncStatusLedgerTest.php
// ---------------------------------------------------------------------------

/**
 * pfb_sync_status_read_all — read the full ledger as a nested array.
 *
 * Absent file, unreadable file, or corrupt/non-object JSON all read as an
 * empty ledger (fail-open for display), never throws.
 *
 * @param string $ledger_dir Directory that contains pfb_sync_status.json.
 * @return array<string,array<string,array<string,array{message:string,first_seen:int,last_seen:int}>>>
 */
function pfb_sync_status_read_all(string $ledger_dir): array
{
	$path = $ledger_dir . '/pfb_sync_status.json';
	if (!is_file($path)) {
		return [];
	}
	$fp = @fopen($path, 'r');
	if ($fp === FALSE) {
		return [];
	}
	if (!flock($fp, LOCK_SH)) {
		fclose($fp);
		return [];
	}
	$raw = stream_get_contents($fp);
	flock($fp, LOCK_UN);
	fclose($fp);
	if ($raw === FALSE || $raw === '') {
		return [];
	}
	$data = json_decode($raw, TRUE);
	return is_array($data) ? $data : [];	// corrupt/non-object -> empty, fail-open
}

/**
 * pfb_sync_status_write_all — atomically persist the full ledger.
 *
 * Silent no-op on an unwritable directory (@-suppressed): the ledger is a
 * display-only signal, never worth crashing the caller's pipeline over.
 * Stages a .tmp file then renames it into place (atomic on a same-filesystem
 * POSIX rename), matching pfb_due_ledger_write_entry()'s idiom.
 *
 * @param array  $data       Full ledger structure (see pfb_sync_status_read_all()).
 * @param string $ledger_dir Directory that contains pfb_sync_status.json.
 * @return void
 */
function pfb_sync_status_write_all(array $data, string $ledger_dir): void
{
	$path = $ledger_dir . '/pfb_sync_status.json';
	$tmp  = $path . '.tmp';
	$json = json_encode($data, JSON_PRETTY_PRINT);
	if ($json === FALSE) {
		// e.g. invalid UTF-8 in a message (raw exec() stderr) -- file_put_contents(FALSE)
		// casts to "" and succeeds, which would silently rename an EMPTY ledger over the
		// real one; bail before touching the tmp file at all.
		return;
	}
	if (@file_put_contents($tmp, $json, LOCK_EX) === FALSE) {
		return;	// unwritable dir -- fail safe, never throws to the caller
	}
	@rename($tmp, $path);
}

/**
 * pfb_sync_status_locked — run $fn with an exclusive cross-process lock held for the
 * WHOLE read-modify-write span, not just the final write. Closes the TOCTOU window
 * between pfb_sync_status_read_all() and pfb_sync_status_write_all() that would
 * otherwise let two concurrent writers (e.g. the tick's synchronous apply-retry step
 * racing a still-running backgrounded sync pass) silently discard one another's update.
 *
 * @param string   $ledger_dir Directory that contains pfb_sync_status.json.
 * @param callable $fn         The read-modify-write body to run under the lock.
 * @return void
 */
function pfb_sync_status_locked(string $ledger_dir, callable $fn): void
{
	$lock_path = $ledger_dir . '/pfb_sync_status.json.lock';
	$fp        = @fopen($lock_path, 'c');
	if ($fp === FALSE || !flock($fp, LOCK_EX)) {
		if ($fp !== FALSE) {
			fclose($fp);
		}
		$fn();	// can't lock (unwritable dir) -- degrade to best-effort, same fail-open contract as write_all()
		return;
	}
	try {
		$fn();
	} finally {
		flock($fp, LOCK_UN);
		fclose($fp);
	}
}

/**
 * pfb_sync_status_open — open (or refresh) one {facility,item,stage} entry.
 *
 * Idempotent by key: opening an already-open key updates message/last_seen in
 * place and preserves the original first_seen — it never duplicates the entry.
 *
 * @param string        $facility   'ip' | 'dnsbl'.
 * @param string        $item       The alias/group/feed name the entry is about.
 * @param string        $stage      'download' | 'parse' | 'apply' | 'dedup'.
 * @param string        $message    Human-readable failure description.
 * @param string        $ledger_dir Directory that contains pfb_sync_status.json.
 * @param callable|null $clock_fn   Returns the current epoch timestamp; defaults to time().
 * @return void
 */
function pfb_sync_status_open(
	string    $facility,
	string    $item,
	string    $stage,
	string    $message,
	string    $ledger_dir,
	?callable $clock_fn = null
): void {
	$now = ($clock_fn !== NULL) ? $clock_fn() : time();
	pfb_sync_status_locked($ledger_dir, function () use ($facility, $item, $stage, $message, $now, $ledger_dir) {
		$data       = pfb_sync_status_read_all($ledger_dir);
		$existing   = $data[$facility][$item][$stage] ?? NULL;
		$first_seen = (is_array($existing) && isset($existing['first_seen'])) ? $existing['first_seen'] : $now;

		$data[$facility][$item][$stage] = [
			'message'    => $message,
			'first_seen' => $first_seen,
			'last_seen'  => $now,
		];
		pfb_sync_status_write_all($data, $ledger_dir);
	});
}

/**
 * pfb_sync_status_close — clear one {facility,item,stage} entry, if open.
 *
 * Closing an absent key is a safe no-op — no write, no exception.
 *
 * @param string $facility   'ip' | 'dnsbl'.
 * @param string $item       The alias/group/feed name the entry is about.
 * @param string $stage      'download' | 'parse' | 'apply' | 'dedup'.
 * @param string $ledger_dir Directory that contains pfb_sync_status.json.
 * @return void
 */
function pfb_sync_status_close(string $facility, string $item, string $stage, string $ledger_dir): void
{
	pfb_sync_status_locked($ledger_dir, function () use ($facility, $item, $stage, $ledger_dir) {
		$data = pfb_sync_status_read_all($ledger_dir);
		if (!isset($data[$facility][$item][$stage])) {
			return;	// absent key -- safe no-op
		}
		unset($data[$facility][$item][$stage]);
		if (empty($data[$facility][$item])) {
			unset($data[$facility][$item]);
		}
		if (empty($data[$facility])) {
			unset($data[$facility]);
		}
		pfb_sync_status_write_all($data, $ledger_dir);
	});
}

/**
 * pfb_sync_status_list_open — enumerate open entries, optionally filtered by facility.
 *
 * @param string      $ledger_dir Directory that contains pfb_sync_status.json.
 * @param string|null $facility   'ip' | 'dnsbl' | NULL for every facility.
 * @return list<array{facility:string,item:string,stage:string,message:string,first_seen:int,last_seen:int}>
 */
function pfb_sync_status_list_open(string $ledger_dir, ?string $facility = null): array
{
	$data = pfb_sync_status_read_all($ledger_dir);
	$out  = [];
	foreach ($data as $fac => $items) {
		if ($facility !== NULL && $fac !== $facility) {
			continue;
		}
		if (!is_array($items)) {
			continue;	// corrupt shape -- skip, never throw
		}
		foreach ($items as $item => $stages) {
			if (!is_array($stages)) {
				continue;
			}
			foreach ($stages as $stage => $entry) {
				if (!is_array($entry)) {
					continue;
				}
				$out[] = [
					'facility'   => (string) $fac,
					'item'       => (string) $item,
					'stage'      => (string) $stage,
					'message'    => (string) ($entry['message'] ?? ''),
					'first_seen' => (int) ($entry['first_seen'] ?? 0),
					'last_seen'  => (int) ($entry['last_seen'] ?? 0),
				];
			}
		}
	}
	return $out;
}

/**
 * pfb_ip_download_ledger_update — translate one IP feed's download result into the
 * sync-status ledger. FALSE opens facility=ip stage=download for $item; TRUE closes
 * the same key. Extracted from the download loop so the ledger write is unit-testable
 * without invoking the full sync_package_pfblockerng() pass.
 *
 * @param bool   $download_ok TRUE when pfb_download() succeeded for this item.
 * @param string $item        The alias/feed header identifying this download.
 * @param string $message     Human-readable failure text (ignored on success).
 * @param string $ledger_dir  Directory that contains pfb_sync_status.json.
 * @return void
 */
function pfb_ip_download_ledger_update(bool $download_ok, string $item, string $message, string $ledger_dir): void
{
	if ($download_ok) {
		pfb_sync_status_close('ip', $item, 'download', $ledger_dir);
	} else {
		pfb_sync_status_open('ip', $item, 'download', $message, $ledger_dir);
	}
}

/**
 * pfb_dnsbl_download_ledger_update — translate one DNSBL feed's download result into
 * the sync-status ledger. FALSE opens facility=dnsbl stage=download for $item; TRUE
 * closes the same key. Mirrors pfb_ip_download_ledger_update() (issue #998).
 *
 * @param bool   $download_ok TRUE when pfb_download() succeeded for this item.
 * @param string $item        The pfB_/DNSBL_-prefixed alias, NOT the per-row $header --
 *                             the widget's deep-link match depends on the prefix.
 * @param string $message     Human-readable failure text (ignored on success).
 * @param string $ledger_dir  Directory that contains pfb_sync_status.json.
 * @return void
 */
function pfb_dnsbl_download_ledger_update(bool $download_ok, string $item, string $message, string $ledger_dir): void
{
	if ($download_ok) {
		pfb_sync_status_close('dnsbl', $item, 'download', $ledger_dir);
	} else {
		pfb_sync_status_open('dnsbl', $item, 'download', $message, $ledger_dir);
	}
}

/**
 * pfb_sync_status_dedup_check — mirror the shell's "Sanity check" line (pfblockerng.sh's
 * closingprocess(), 'Database Sanity check [ PASSED / FAILED ]') into the IP dedup ledger
 * key -- the same LAST-line-wins read as the widget's `grep 'Sanity check' | tail -1`.
 * FAILED opens facility=ip item=dedup stage=dedup; PASSED closes it. No line recorded yet
 * (dedup never run) is left untouched -- nothing known to report either way.
 *
 * @param string $log_path   Absolute path to pfblockerng.log.
 * @param string $ledger_dir Directory that contains pfb_sync_status.json.
 * @return void
 */
function pfb_sync_status_dedup_check(string $log_path, string $ledger_dir): void
{
	// issue #1052: bounded tail read, not @file() of the WHOLE log -- a 'nolimit'
	// log has no size cap. The sanity line is written every dedup pass, so the
	// last match always sits within this trailing window.
	$tail_bytes = 65536;

	$fh = @fopen($log_path, 'rb');
	if ($fh === FALSE) {
		return;
	}
	$stat   = fstat($fh);
	$size   = ($stat !== FALSE) ? $stat['size'] : 0;
	$offset = ($size > $tail_bytes) ? $size - $tail_bytes : 0;
	if (fseek($fh, $offset) === -1) {
		fclose($fh);
		return;
	}
	$tail = stream_get_contents($fh);
	fclose($fh);
	if ($tail === FALSE) {
		return;
	}

	$last = '';
	foreach (explode("\n", $tail) as $line) {
		if (strpos($line, 'Sanity check') !== FALSE) {
			$last = $line;
		}
	}
	if ($last === '') {
		return;
	}

	if (strpos($last, 'PASSED') !== FALSE) {
		pfb_sync_status_close('ip', 'dedup', 'dedup', $ledger_dir);
	} else {
		pfb_sync_status_open('ip', 'dedup', 'dedup', trim($last), $ledger_dir);
	}
}

/**
 * pfb_sync_status_close_removed_alias — close the stage=download ledger entry for an
 * IP/DNSBL alias removed by our own WebUI (renamed or deleted). $gtype selects the
 * download-key shape (pfb_ip/dnsbl_download_ledger_update's own prefix/suffix rules);
 * an empty $aliasname or an unrecognized $gtype (e.g. 'geoip') is a no-op.
 *
 * Only the download stage closes -- apply/parse/dedup stay tick-managed (issue
 * #1014/#1019; ADR-61 §2.2 symmetric ownership).
 *
 * @param string $gtype     'ipv4' | 'ipv6' | 'dnsbl' (any other value is a no-op).
 * @param string $aliasname The REMOVED alias's raw aliasname (empty = no-op).
 * @param string $ledger_dir Directory that contains pfb_sync_status.json.
 * @return void
 */
function pfb_sync_status_close_removed_alias(string $gtype, string $aliasname, string $ledger_dir): void
{
	if ($aliasname === '') {
		return;
	}

	switch ($gtype) {
		case 'ipv4':
			pfb_sync_status_close('ip', "pfB_{$aliasname}_v4", 'download', $ledger_dir);
			break;
		case 'ipv6':
			pfb_sync_status_close('ip', "pfB_{$aliasname}_v6", 'download', $ledger_dir);
			break;
		case 'dnsbl':
			pfb_sync_status_close('dnsbl', "DNSBL_{$aliasname}", 'download', $ledger_dir);
			break;
		default:
			// unknown gtype (e.g. 'geoip') -- no download ledger key shape defined, no-op
			break;
	}
}

/**
 * pfb_py_sync_status_list_open — read-only reader for Python's OWN status ledger
 * (pfb_py_status.json, written EXCLUSIVELY by pfb_unbound.py -- this function never
 * writes it), returning entries in the SAME shape as pfb_sync_status_list_open() so
 * the widget can merge both sources. Every degenerate input (absent/unreadable file,
 * non-array JSON, a malformed entry) reads as "no open Python-side entries" -- never
 * a PHP warning/exception.
 *
 * @param string $status_dir Directory that contains pfb_py_status.json (the Unbound
 *                            chroot dir, e.g. $pfb['dnsbldir']).
 * @return list<array{facility:string,item:string,stage:string,message:string,first_seen:int,last_seen:int}>
 */
function pfb_py_sync_status_list_open(string $status_dir): array
{
	$path = $status_dir . '/pfb_py_status.json';
	if (!is_file($path)) {
		return [];
	}
	$raw = @file_get_contents($path);
	if ($raw === FALSE || $raw === '') {
		return [];
	}
	$data = json_decode($raw, TRUE);
	if (!is_array($data) || !array_is_list($data)) {
		return [];	// wrong top-level type (object/scalar) -- fail-open, never throw
	}

	$out = [];
	foreach ($data as $entry) {
		if (!is_array($entry) || !isset($entry['facility'], $entry['item'], $entry['stage'])) {
			continue;	// malformed entry -- skip it, never abort the whole read
		}
		$out[] = [
			'facility'   => (string) $entry['facility'],
			'item'       => (string) $entry['item'],
			'stage'      => (string) $entry['stage'],
			'message'    => (string) ($entry['message'] ?? ''),
			'first_seen' => (int) ($entry['first_seen'] ?? 0),
			'last_seen'  => (int) ($entry['last_seen'] ?? 0),
		];
	}
	return $out;
}

// ---------------------------------------------------------------------------
// ADR-53 — pure suppression-line validator (v4 mask lift /8-/32)
// ---------------------------------------------------------------------------

/**
 * pfb_validate_suppression_line — validate one line of a v4/v6 suppression textarea.
 *
 * Mirrors the tolerant textarea shape the page already accepts: a line starting
 * with '#', or blank, is a no-op (skip, no error); an inline comment introduced
 * by '#' (e.g. "10.0.0.1/32 # example.com") is stripped before validating the
 * address/mask. IPv4 accepts masks /8-/32, IPv6 accepts masks /32-/128 (ADR-53 §2.3
 * fork 1 — pure fail-open-typo guards; both carve engines are themselves mask-agnostic).
 *
 * PURE — no config access, no I/O; only the pfSense is_subnetv4()/is_subnetv6()
 * predicates.
 *
 * @param  string $line   One raw textarea line (as split on "\n" post-ingestion-sanitize, issue #1723), untrimmed.
 * @param  string $family 'ipv4' or 'ipv6'.
 * @return string|null    NULL when the line is valid (or a comment/blank no-op);
 *                         otherwise the input_errors message for this line.
 */
function pfb_validate_suppression_line(string $line, string $family): ?string
{
	// Blank/comment no-op: judge by the first NONBLANK character, so an
	// indented '#' (ASCII or Unicode whitespace) is still a comment.
	$stripped = pfb_strip($line);
	if (pfb_is_empty($stripped) || str_starts_with($stripped, '#')) {
		return NULL;
	}

	$host  = array_map('trim', preg_split('/(?=#)/', $line));
	$entry = $host[0];

	if ($family === 'ipv6') {
		// Mask-range check runs BEFORE the general subnet-shape check so an
		// out-of-range-but-otherwise-well-formed mask (/31, /129) gets the message
		// naming the accepted range, rather than the generic malformed-input one.
		$mask = strstr($entry, '/', FALSE);
		if ($mask !== FALSE && ctype_digit(substr($mask, 1))) {
			$mask_num = (int) substr($mask, 1);
			if ($mask_num < 32 || $mask_num > 128) {
				return "IPv6 Suppression: Invalid mask [ {$entry} ]. Mask must be between /32 and /128.";
			}
		}

		if (!is_subnetv6($entry)) {
			return "IPv6 Suppression: Invalid IPv6 subnet address defined [ {$entry} ]";
		}

		return NULL;
	}

	// Mask-range check runs BEFORE the general subnet-shape check so an
	// out-of-range-but-otherwise-well-formed mask (/7, /33) gets the message
	// naming the accepted range, rather than the generic malformed-input one.
	$mask = strstr($entry, '/', FALSE);
	if ($mask !== FALSE && ctype_digit(substr($mask, 1))) {
		$mask_num = (int) substr($mask, 1);
		if ($mask_num < 8 || $mask_num > 32) {
			return "IPv4 Suppression: Invalid mask [ {$entry} ]. Mask must be between /8 and /32.";
		}
	}

	if (!is_subnetv4($entry)) {
		return "IPv4 Suppression: Invalid IPv4 subnet address defined [ {$entry} ]";
	}

	return NULL;
}

// ---------------------------------------------------------------------------
// ADR-53 — pure IPv6 CIDR set-subtraction engine. IPv6 suppression can't carve by host
// enumeration (a /64 minus a /128 hole is 2^64 hosts -- ADR-53 §1.2) and `iprange` mangles v6
// input outright (parses a v6 literal as a hostname); unlike the v4 engine's `iprange --except`,
// this is pure-PHP set subtraction over fixed-width 128-bit binary-string ranges, emitting the
// minimal covering-CIDR remainder via pfSense's REAL ip_range_to_subnet_array() (never
// redefined here; a faithful double stands in under PHPUnit, tests/php/pfsense_doubles.php).
// Every binary-string comparison uses strcmp(), NEVER bare <, >, <=, >=, min(), max(): a 128-char
// '0'/'1' string is a PHP "numeric string" and normal comparison risks silent float coercion.
// ---------------------------------------------------------------------------

/**
 * pfb_v6_cidr_to_range — parse one IPv6 CIDR token ('addr/bits') into its
 * [start, end] 128-bit binary-string range (fixed-width '0'/'1' strings,
 * lexically ordered exactly like the address's numeric value).
 *
 * A blank line or a '#'-led comment (the same tolerance
 * pfb_validate_suppression_line() applies to the persisted suppression file)
 * parses to NULL with $is_blank = TRUE -- a silent no-op, never an error. Any
 * other syntactically invalid token (no '/', out-of-range mask, unparseable
 * address) also returns NULL, but with $is_blank = FALSE so the caller
 * reports it.
 *
 * PURE.
 *
 * @param  string     $token     One raw CIDR line, untrimmed.
 * @param  bool|null &$is_blank  Set TRUE for a comment/blank no-op, FALSE otherwise.
 * @return array{0:string,1:string}|null [start_bin, end_bin], or NULL when unparseable.
 */
function pfb_v6_cidr_to_range(string $token, ?bool &$is_blank = null): ?array
{
	$is_blank = FALSE;
	$token = trim($token);
	if ($token === '' || str_starts_with($token, '#')) {
		$is_blank = TRUE;
		return NULL;
	}

	// A bare address (no /mask) is the dominant member-file shape a feed
	// emits -- treat it as its own /128, never as a malformed token (dropping
	// it would silently UNBLOCK the host; caught live by the ADR-53 v6 smoke).
	if (strpos($token, '/') === FALSE) {
		if (!is_ipaddrv6($token)) {
			return NULL;
		}
		$addr = $token;
		$bits = 128;
	} elseif (!is_subnetv6($token)) {
		return NULL;
	} else {
		[$addr, $bits_raw] = explode('/', $token, 2);
		$bits = (int) $bits_raw;
	}

	$packed = @inet_pton($addr);
	if ($packed === FALSE || strlen($packed) !== 16) {
		return NULL;
	}
	$addr_bin = '';
	foreach (str_split($packed) as $byte) {
		$addr_bin .= sprintf('%08b', ord($byte));
	}

	$host_len = 128 - $bits;
	$start    = substr($addr_bin, 0, $bits) . str_repeat('0', $host_len);
	$end      = substr($addr_bin, 0, $bits) . str_repeat('1', $host_len);

	return [$start, $end];
}

/**
 * pfb_v6_bin_inc — increment a 128-bit binary string by one address.
 *
 * PURE.
 *
 * @return string|null The incremented string, or NULL on overflow (input was
 *                      all '1's -- ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff).
 */
function pfb_v6_bin_inc(string $bin): ?string
{
	$pos = strrpos($bin, '0');
	if ($pos === FALSE) {
		return NULL;
	}
	return substr($bin, 0, $pos) . '1' . str_repeat('0', strlen($bin) - $pos - 1);
}

/**
 * pfb_v6_bin_dec — decrement a 128-bit binary string by one address.
 *
 * PURE.
 *
 * @return string|null The decremented string, or NULL on underflow (input was
 *                      all '0's -- ::).
 */
function pfb_v6_bin_dec(string $bin): ?string
{
	$pos = strrpos($bin, '1');
	if ($pos === FALSE) {
		return NULL;
	}
	return substr($bin, 0, $pos) . '0' . str_repeat('1', strlen($bin) - $pos - 1);
}

/**
 * pfb_v6_bin_to_addr — pack a 128-bit binary string back into a textual IPv6
 * address. Any valid textual form works: ip_range_to_subnet_array() re-derives
 * its own binary representation from whatever is passed in, so the specific
 * notation returned here is not load-bearing.
 *
 * PURE.
 */
function pfb_v6_bin_to_addr(string $bin): string
{
	$bin    = str_pad($bin, 128, '0', STR_PAD_LEFT);
	$packed = '';
	foreach (str_split($bin, 8) as $byte_bin) {
		$packed .= chr(bindec($byte_bin));
	}
	return inet_ntop($packed);
}

/**
 * pfb_v6_emit_covering_cidrs — the minimal covering-CIDR set for one
 * [start, end] binary-string range, via pfSense's ip_range_to_subnet_array().
 *
 * @return string[] CIDR strings ('addr/bits').
 */
function pfb_v6_emit_covering_cidrs(string $start_bin, string $end_bin): array
{
	return ip_range_to_subnet_array(pfb_v6_bin_to_addr($start_bin), pfb_v6_bin_to_addr($end_bin));
}

/**
 * pfb_cidr_subtract_v6 — set-subtract $holes from $cidrs (both IPv6 CIDR
 * arrays), returning the minimal covering-CIDR remainder (ADR-53 §2.1 v6
 * engine).
 *
 * Each entry in $cidrs is carved independently: every hole that intersects it
 * is removed (fully, partially, or not at all), so a hole spanning multiple
 * entries subtracts from each in turn; a hole containing an entry removes it
 * entirely; an entry with no intersecting hole re-emits unchanged (still
 * routed through ip_range_to_subnet_array() so notation/merging stays
 * consistent with the carved path -- ADR-53 §2.3 fork 4). An
 * entirely-suppressed input legitimately returns [] (ADR-53 §2.2
 * empty-is-legit).
 *
 * A malformed token in EITHER array is skipped -- never a throw that aborts
 * the whole file -- and appended to $errors verbatim; a blank/'#'-comment
 * line is a silent no-op and never reported.
 *
 * PURE -- no config access, no I/O.
 *
 * @param  string[]       $cidrs    Feed/member CIDR lines to carve.
 * @param  string[]       $holes    Suppression CIDR lines to carve out.
 * @param  string[]|null &$errors   By-ref out param: the raw malformed tokens
 *                                  skipped from either array (both sides pooled).
 * @return string[] The covering-CIDR remainder (no particular guaranteed order).
 */
function pfb_cidr_subtract_v6(array $cidrs, array $holes, ?array &$errors = null): array
{
	$errors = [];

	$entries = [];
	foreach ($cidrs as $token) {
		$is_blank = FALSE;
		$range    = pfb_v6_cidr_to_range((string) $token, $is_blank);
		if ($range === NULL) {
			if (!$is_blank) {
				$errors[] = (string) $token;
			}
			continue;
		}
		$entries[] = $range;
	}

	$hole_ranges = [];
	foreach ($holes as $token) {
		$is_blank = FALSE;
		$range    = pfb_v6_cidr_to_range((string) $token, $is_blank);
		if ($range === NULL) {
			if (!$is_blank) {
				$errors[] = (string) $token;
			}
			continue;
		}
		$hole_ranges[] = $range;
	}

	// Sort once, up front (not per entry): the per-entry filter below preserves
	// this order, so no repeated sort is needed.
	usort($hole_ranges, static function (array $a, array $b): int {
		return strcmp($a[0], $b[0]);
	});

	$out = [];
	foreach ($entries as [$estart, $eend]) {
		// Clip every hole that intersects this entry to the entry's own bounds.
		$intersecting = [];
		foreach ($hole_ranges as [$hstart, $hend]) {
			if (strcmp($hstart, $eend) > 0 || strcmp($hend, $estart) < 0) {
				continue; // no overlap with this entry
			}
			$intersecting[] = [
				strcmp($hstart, $estart) > 0 ? $hstart : $estart, // clipped start
				strcmp($hend, $eend) < 0 ? $hend : $eend,         // clipped end
			];
		}

		if (empty($intersecting)) {
			// array_push(...$x) appends in place (amortised O(k) for k new
			// elements) -- NEVER `$out = array_merge($out, $x)` here, which would
			// recopy the whole accumulated $out on every one of up to ~100k
			// entries (an O(n^2) blowup measured at 22s for a 100k-line file;
			// this form measured well under a second for the same input).
			array_push($out, ...pfb_v6_emit_covering_cidrs($estart, $eend));
			continue;
		}

		// Walk the (already sorted) intersecting holes, emitting the gap before
		// each one, then advancing the cursor past it; a final gap after the
		// last hole (if any) closes out the entry.
		$cursor = $estart;
		foreach ($intersecting as [$hstart, $hend]) {
			if ($cursor === NULL) {
				break; // already carved to the top of the address space
			}
			if (strcmp($hstart, $cursor) > 0) {
				$gap_end = pfb_v6_bin_dec($hstart);
				if ($gap_end !== NULL) {
					array_push($out, ...pfb_v6_emit_covering_cidrs($cursor, $gap_end));
				}
			}
			if (strcmp($hend, $cursor) >= 0) {
				$cursor = pfb_v6_bin_inc($hend);
			}
		}
		if ($cursor !== NULL && strcmp($cursor, $eend) <= 0) {
			array_push($out, ...pfb_v6_emit_covering_cidrs($cursor, $eend));
		}
	}

	return $out;
}

/**
 * pfb_suppress_file_v6 — set-subtract $suppfile's IPv6 suppression entries
 * from $file's member-list CIDR lines and publish the covering-CIDR
 * remainder, atomically.
 *
 * Fail-safe (ADR-53 §2.2): either input missing/unreadable -> FALSE, $file is
 * left untouched -- never a truncated publish on error. On success, publishes
 * via a same-directory tmp+rename (an atomic POSIX rename, so no reader ever
 * observes a partial file); a legitimately-empty remainder (everything
 * suppressed) still publishes an empty file, never a stale one. A non-CIDR
 * line in either input is dropped and logged (pfb_logger), never fatal.
 *
 * PURE aside from the single target-file write (+ its companion log lines).
 *
 * @param  string $file     Member/deny CIDR list to carve (rewritten in place).
 * @param  string $suppfile Suppression CIDR list (the holes).
 * @return bool TRUE on a successful publish (including an empty one), FALSE
 *              on any fail-safe path (previous $file left intact).
 */
function pfb_suppress_file_v6(string $file, string $suppfile): bool
{
	if (!is_readable($file) || !is_readable($suppfile)) {
		return FALSE;
	}

	$cidrs = @file($file, FILE_IGNORE_NEW_LINES);
	$holes = @file($suppfile, FILE_IGNORE_NEW_LINES);
	if ($cidrs === FALSE || $holes === FALSE) {
		return FALSE;
	}

	$errors = [];
	$result = pfb_cidr_subtract_v6($cidrs, $holes, $errors);

	foreach ($errors as $bad_token) {
		pfb_logger("IPv6 Suppression: dropping malformed entry [ {$bad_token} ]", 2);
	}

	$tmp  = $file . '.tmp';
	$body = empty($result) ? '' : implode(PHP_EOL, $result) . PHP_EOL;
	if (@file_put_contents($tmp, $body, LOCK_EX) === FALSE) {
		// ADR-53 review finding H1: a failed write can still leave a stray
		// (empty/partial, or pre-existing debris from a prior crashed run) file
		// at $tmp -- unlink it on this branch too, matching the rename-failure
		// branch below.
		@unlink($tmp);
		return FALSE;
	}
	if (!@rename($tmp, $file)) {
		@unlink($tmp);
		return FALSE;
	}

	return TRUE;
}

// ---------------------------------------------------------------------------
// ADR-53 — prefix-aware killstates suppression exclusion
// ---------------------------------------------------------------------------

/**
 * pfb_ip_suppressed — TRUE iff $ip falls inside any suppression CIDR in
 * $entries (ADR-53 §2.2 killstates contract).
 *
 * Replaces the old exact-IP hashmap + subnetv4_expand() '/24' materialisation
 * in pfb_remove_states(), which could only express a bare host or an exact
 * '/24' entry -- any other containing mask (e.g. a v4 '/16', or any v6 mask)
 * silently stayed unsuppressed (ADR-53 §1.2). Uses the same ip_in_subnet()
 * loop shape pfb_local_ip() already applies to local subnets, so any mask is
 * honoured natively -- no materialisation, no per-family branching needed
 * here (ip_in_subnet() itself returns FALSE on a family mismatch).
 *
 * $entries are raw suppression-textarea lines (untrimmed; may carry a
 * trailing '#' comment or be entirely blank/comment) -- the same tolerance
 * pfb_validate_suppression_line() applies. A malformed entry (no '/', bad
 * address) is silently skipped, never fatal.
 *
 * PURE -- no config reads; the caller passes the already-decoded suppression
 * list(s).
 *
 * Cost: a linear scan of $entries per call. Suppression lists are small and
 * user-authored, so this is fine at this scale.
 * ponytail: an interval tree would be overkill here — revisit only if a
 * suppression list ever grows into the thousands of entries.
 *
 * @param  string   $ip      The firewall-state IP to test (v4 or v6).
 * @param  string[] $entries Decoded suppression lines (one family or mixed).
 * @return bool TRUE when $ip is covered by any entry.
 */
function pfb_ip_suppressed(string $ip, array $entries): bool
{
	return pfb_ip_suppressed_match($ip, $entries) !== NULL;
}

/**
 * pfb_ip_suppressed_match — same coverage test as pfb_ip_suppressed(), but
 * returns the MOST SPECIFIC (longest-prefix) covering entry instead of a
 * bool (issue #422, follow-up to ADR-53). Feeds two Alerts surfaces
 * that need to act on the actual customlist line, not just a yes/no: the
 * un-suppress ('delete_ip') handler (which entry to remove + re-add) and the
 * suppressed-row icon detection in the Alerts render loop.
 *
 * Skip/strip rules are identical to the pre-#422 pfb_ip_suppressed() (that
 * function is now a one-line wrapper around this one). One deliberate
 * tolerance on top: a bare host (no '/') is normalised to /32 (v4) or /128
 * (v6) before the ip_in_subnet() containment test -- ip_in_subnet() itself
 * requires a mask (a bare token never matches anything), while BOTH carve
 * engines treat a bare suppression hole as a single host (iprange for v4;
 * pfb_v6_cidr_to_range() for v6), so without the normalisation a hand-edited
 * bare entry would suppress at update time yet read as "not suppressed"
 * here (killstates would keep cutting the host's states; the Alerts
 * un-suppress could never resolve it). When both a host-exact and a broader
 * containing CIDR cover $ip, the host-specific entry wins (mirrors the old
 * /32-before-/24 precedence); a tie in prefix length keeps the first-seen
 * entry.
 *
 * PURE -- no config access, no I/O.
 *
 * @param  string   $ip      The IP to test (v4 or v6).
 * @param  string[] $entries Decoded suppression lines (one family or mixed).
 * @return string|null The RAW entry (as passed in $entries, comment intact)
 *                      with the longest prefix, or NULL when none covers $ip.
 */
function pfb_ip_suppressed_match(string $ip, array $entries): ?string
{
	$best      = NULL;
	$best_bits = -1;

	foreach ($entries as $raw) {
		$entry = trim((string) $raw);
		if ($entry === '' || str_starts_with($entry, '#')) {
			continue;
		}
		// Strip a trailing inline '#' comment, same as pfb_text_area_decode().
		$stripped = trim(strstr($entry, '#', TRUE) ?: $entry);

		// Bare host -> exact single-host CIDR BEFORE the containment test:
		// ip_in_subnet() requires a mask, but the carve engines suppress a
		// bare hole as a single host -- the predicate must agree with them.
		if (!str_contains($stripped, '/')) {
			$stripped .= str_contains($stripped, ':') ? '/128' : '/32';
		}

		if (!ip_in_subnet($ip, $stripped)) {
			continue;
		}

		$bits = (int) substr(strrchr($stripped, '/'), 1);

		if ($bits > $best_bits) {
			$best      = $raw;
			$best_bits = $bits;
		}
	}

	return $best;
}

// ---------------------------------------------------------------------------
// ADR-53 -- Alerts "+" / widget live-punch plan (any mask + v6). The Alerts "+" button
// (and the dashboard widget, sharing its stats read) used to punch a hole in a live pf table
// by deleting an exact '/24' and re-adding 254 sibling hosts, refusing anything "blocked by a
// CIDR other than /24" (ADR-53 §1.2). This replaces that with the same covering-CIDR
// set-subtraction already proven for the persisted engines (the v4 `iprange --except` pass,
// the v6 PHP pass): locate the table entr(y/ies) that actually contain the host, delete them,
// and re-add only the covering-CIDR remainder -- any mask, both families.
// ---------------------------------------------------------------------------

/**
 * pfb_live_table_snapshot -- stream a live pf table's current membership via
 * `pfctl -T show`, the SOLE source (issue #1467: the ADR-40 mirror file is
 * never read here -- a live punch never rewrites the mirror, so a second
 * punch inside the same containing entry would read a stale set and
 * silently revert the first punch). Extracted from the Alerts "+"
 * (addsuppress) handler (issue #1412) so the temporary Unlock icon's live
 * punch shares the exact same read instead of re-deriving it.
 *
 * Issue #1471: streamed as a \Generator (yielded line-by-line via fgets),
 * never slurped whole -- a Deny table can hold millions of entries, and
 * materialising them all as a PHP string array would exhaust the web-UI PHP
 * process's memory.
 *
 * A capture failure (scratch file, pfctl exit, or reopen) throws
 * \RuntimeException rather than yielding an empty result -- an empty result
 * is otherwise indistinguishable from a genuinely empty table, and a caller
 * (pfb_live_punch_run()) acting on that false "empty" would misreport a
 * capture failure as "not currently blocked". The throw fires lazily, on the
 * generator's first iteration.
 *
 * Issue #1852 -- ONE exception to the above: a table absent from the loaded
 * ruleset (a fresh alias not yet referenced by any rule/reload -- verified
 * on pfSense CE 2.8 / PHP 8.3: `pfctl -t <absent> -T show` exits rc=255,
 * stderr "pfctl: Table does not exist.") yields EMPTY rather than throwing --
 * that condition genuinely means "no live members", not a capture failure,
 * and a user clicking Alerts "+" on such a host must not fatal. Distinguished
 * by classifying `pfctl`'s own stderr (captured to a SEPARATE temp file, per
 * ADR-53 below, never merged into the stdout membership parse); any other
 * non-zero exit still throws.
 *
 * NOT pure -- execs pfctl.
 *
 * @param  string $pfctl    Absolute path to the pfctl binary ($pfb['pfctl']).
 * @param  string $aliasdir Unused since #1467 -- the mirror is never read;
 *                           kept for call-site signature compatibility.
 * @param  string $dbdir    Scratch-file directory for the pfctl-show capture ($pfb['dbdir']).
 * @param  string $table    The pf table name (caller-validated, e.g. via PFB_FILTER_WORD).
 * @return \Generator<string> Raw membership lines (bare host or CIDR tokens; blank/'#'-comment lines tolerated).
 * @throws \RuntimeException On a scratch-file, pfctl-exit, or reopen failure.
 */
function pfb_live_table_snapshot(string $pfctl, string $aliasdir, string $dbdir, string $table): \Generator
{
	$table_esc = escapeshellarg($table);
	$scan_tmp  = tempnam($dbdir, 'pfb_punch_');
	if ($scan_tmp === FALSE) {
		throw new \RuntimeException("table={$table}: tempnam() failed in dbdir={$dbdir}");
	}
	$err_tmp = tempnam($dbdir, 'pfb_punch_err_');
	if ($err_tmp === FALSE) {
		@unlink($scan_tmp);
		throw new \RuntimeException("table={$table}: tempnam() failed in dbdir={$dbdir}");
	}

	// ADR-53/#1852: stdout and stderr capture to SEPARATE temp files -- NOT
	// 2>&1 -- the stdout file is parsed line-by-line as membership entries
	// below; merging stderr into it would feed any pfctl diagnostic line
	// into that parse as if it were a table member. stderr is classified
	// below on a non-zero exit, to tell an absent table (benign) from a
	// genuine pfctl failure (loud).
	$exec_out = [];
	$rc       = 0;
	exec(
		"{$pfctl} -t {$table_esc} -T show > " . escapeshellarg($scan_tmp) . ' 2>' . escapeshellarg($err_tmp),
		$exec_out,
		$rc
	);
	if ($rc !== 0) {
		$stderr_text = (string) @file_get_contents($err_tmp);
		@unlink($scan_tmp);
		@unlink($err_tmp);
		// pfctl's own wording for a table absent from the loaded ruleset
		// (probed on pfSense CE 2.8 / PHP 8.3.19: rc=255, stderr
		// "pfctl: Table does not exist."). A fresh alias not yet referenced
		// by any rule/reload is "no live members", not a capture failure --
		// yield nothing rather than throw. Any other non-zero exit (a
		// genuine pfctl failure) still throws loudly.
		if (str_contains($stderr_text, 'Table does not exist')) {
			return;
		}
		throw new \RuntimeException("table={$table}: pfctl -T show exited rc={$rc}: " . trim($stderr_text));
	}
	@unlink($err_tmp);

	$handle = @fopen($scan_tmp, 'r');
	if ($handle === FALSE) {
		@unlink($scan_tmp);
		throw new \RuntimeException("table={$table}: fopen() failed on the pfctl-show capture");
	}
	try {
		while (($line = @fgets($handle)) !== FALSE) {
			yield trim($line);
		}
	} finally {
		// Issue #1852: an abandoned (never-fully-drained) generator's finally
		// only runs at the tail of request shutdown (bugs.php.net #76006), by
		// which point $handle can already be an invalid resource -- guard
		// instead of a bare fclose(). @unlink() still runs unconditionally so
		// the scratch file is never leaked either way.
		if (is_resource($handle)) {
			fclose($handle);
		}
		@unlink($scan_tmp);
	}
}

/**
 * pfb_v4_carve_single -- the covering-CIDR remainder of one IPv4 CIDR (or
 * bare host, normalised to '/32') with a single host removed. The IPv4
 * sibling of pfb_cidr_subtract_v6(), scoped to the one-entry/one-hole shape
 * the live punch actually needs -- pfb_cidr_subtract_v6() stays the only
 * general multi-hole engine (the v4 persisted engine already has its own for
 * that, `iprange --except`). A v4 range fits a plain PHP int (32 bits,
 * ip2long32() already returns it unsigned on 64-bit PHP), so no
 * binary-string arithmetic is needed here.
 *
 * PURE.
 *
 * @param  string $cidr    The containing table entry ('addr/bits' or bare host).
 * @param  string $host_ip The single IPv4 host to carve out (assumed to fall
 *                          inside $cidr -- the caller establishes containment
 *                          via ip_in_subnet() before calling).
 * @return string[] Covering CIDRs for $cidr minus $host_ip (empty when $cidr
 *                    IS $host_ip -- an exact host match, nothing left to add back).
 */
function pfb_v4_carve_single(string $cidr, string $host_ip): array
{
	$cidr  = str_contains($cidr, '/') ? $cidr : "{$cidr}/32";
	[$addr, $bits] = explode('/', $cidr, 2);
	$bits  = (int) $bits;
	$mask  = $bits === 0 ? 0 : ((0xFFFFFFFF << (32 - $bits)) & 0xFFFFFFFF);
	$start = ip2long32($addr) & $mask;
	$end   = $start | ((~$mask) & 0xFFFFFFFF);
	$hole  = ip2long32($host_ip);

	$out = [];
	if ($hole > $start) {
		array_push($out, ...ip_range_to_subnet_array(long2ip32($start), long2ip32($hole - 1)));
	}
	if ($hole < $end) {
		array_push($out, ...ip_range_to_subnet_array(long2ip32($hole + 1), long2ip32($end)));
	}
	return $out;
}

/**
 * pfb_live_punch_plan -- compute the live pf-table punch for the Alerts "+"
 * / widget suppression action (ADR-53 §2.1 fork 3): which existing table
 * entries contain $ip (to `pfctl -T delete`) and which covering CIDRs
 * replace them (to `pfctl -T add`) -- a genuine set-subtraction, replacing
 * the retired /24-only 254-host re-add loop.
 *
 * $table_entries are raw lines from the table's live membership snapshot
 * (pfb_live_table_snapshot(), issue #1467: `pfctl -T show`, the sole
 * source) -- bare host tokens ("1.2.3.4") or CIDR tokens ("1.2.3.0/24"),
 * either family; blank/'#'-comment lines are tolerated (skipped). A bare
 * host token is treated as an exact /32 or /128 -- containing ONLY itself,
 * so punching it needs no covering-CIDR add (delete only, same as the old
 * exact-/32-match case).
 *
 * PURE -- no pfctl/pf-table access; the caller supplies the already-read
 * membership snapshot (issue #1471: any iterable, including the streamed
 * \Generator pfb_live_table_snapshot() returns -- see the alerts page call
 * site) and applies the returned plan.
 *
 * Two containing entries whose remainders overlap near the punched host
 * (e.g. a /16 and a nested /24, both containing it) can each carve the same
 * near-host covering CIDR -- the returned lists are deduplicated so a
 * duplicate remainder never costs a wasted exec in pfb_live_punch_apply().
 *
 * @param  string            $ip             The host to carve out (v4 or v6).
 * @param  iterable<string>  $table_entries  Raw table membership lines.
 * @return array{delete: string[], add: string[]} 'delete' = every containing
 *         entry to remove; 'add' = the covering-CIDR remainder to re-add
 *         (empty when every containing entry was an exact host match);
 *         both deduplicated.
 */
function pfb_live_punch_plan(string $ip, iterable $table_entries): array
{
	$delete    = [];
	$add       = [];
	$is_v6     = str_contains($ip, ':');
	$host_cidr = $ip . ($is_v6 ? '/128' : '/32');

	foreach ($table_entries as $entry) {
		$entry = trim((string) $entry);
		if ($entry === '' || str_starts_with($entry, '#')) {
			continue;
		}
		$cidr = str_contains($entry, '/') ? $entry : $entry . ($is_v6 ? '/128' : '/32');

		if (!ip_in_subnet($ip, $cidr)) {
			continue;
		}

		$delete[] = $entry;

		if ($cidr === $host_cidr) {
			continue; // exact host match -- nothing to re-add
		}

		if ($is_v6) {
			array_push($add, ...pfb_cidr_subtract_v6([$cidr], [$host_cidr]));
		} else {
			array_push($add, ...pfb_v4_carve_single($cidr, $ip));
		}
	}

	return ['delete' => array_values(array_unique($delete)), 'add' => array_values(array_unique($add))];
}

/**
 * pfb_live_punch_apply -- issue #1470: fail-closed executor for a
 * pfb_live_punch_plan() plan. Order is INVERTED vs the naive shape: every
 * $plan['add'] remainder execs FIRST, every $plan['delete'] containing entry
 * LAST. Every remainder is a covering-CIDR SUBSET of a still-present
 * containing entry (the plan's contract), so adding it first never changes
 * live match behaviour; deleting the containing entr(y/ies) only once every
 * remainder is already in place means no intermediate state ever unblocks
 * the host or a sibling.
 *
 * On an add failure: stop (no further adds, no deletes), best-effort
 * `-T delete` every remainder THIS call already added (its own rc is
 * ignored -- those leftovers are subsets of the still-present containing
 * entry, harmless), and return ok=FALSE. On a delete failure: stop at the
 * first failure (no rollback -- entries already deleted had their remainder
 * carved in the add phase; the failed entry still blocks the host, which is
 * the fail-closed outcome).
 *
 * NEVER routes through pfb_pfctl_table_op(): that opens an ADR-61
 * sync-status 'apply' ledger entry on failure, and the tick's retry sweep
 * (pfb_ip_apply_retry() -> `-T replace` from the aliasdir mirror) would
 * revert OTHER valid live punches whose stores still claim carved.
 *
 * Rollback neutrality: the best-effort rollback above may delete a remainder
 * that happens to coincide with an independent, pre-existing table member --
 * harmless, since rollback only ever runs before any delete, so a still-
 * present containing entry still covers that member until the next reload
 * restores the canonical set.
 *
 * NOT pure -- execs pfctl.
 *
 * @param  string $pfctl Absolute path to the pfctl binary ($pfb['pfctl']).
 * @param  string $table The pf table name (caller-validated).
 * @param  array{delete: string[], add: string[]} $plan pfb_live_punch_plan()'s output.
 * @return array{ok: bool, fail: ?string} ok=TRUE iff every op succeeded (or the
 *         plan was empty, zero execs); 'fail' names the first failing op as
 *         "<op> <entry>", NULL when ok.
 */
function pfb_live_punch_apply(string $pfctl, string $table, array $plan): array {
	$table_esc = escapeshellarg($table);
	$applied   = [];

	foreach ($plan['add'] as $entry) {
		$out = [];
		$rc  = 0;
		exec("{$pfctl} -t {$table_esc} -T add " . escapeshellarg($entry) . ' 2>&1', $out, $rc);
		if (pfb_pfctl_op_failed('add', $rc, implode(' ', $out))) {
			foreach ($applied as $rollback_entry) {
				exec("{$pfctl} -t {$table_esc} -T delete " . escapeshellarg($rollback_entry) . ' 2>&1');
			}
			pfb_logger('[pfb_live_punch_apply] ' . pfb_pfctl_error_message($table, 'add', $rc, implode(' ', $out)) . " entry={$entry}\n", 2);
			return ['ok' => FALSE, 'fail' => "add {$entry}"];
		}
		$applied[] = $entry;
	}

	foreach ($plan['delete'] as $entry) {
		$out = [];
		$rc  = 0;
		exec("{$pfctl} -t {$table_esc} -T delete " . escapeshellarg($entry) . ' 2>&1', $out, $rc);
		if (pfb_pfctl_op_failed('delete', $rc, implode(' ', $out))) {
			pfb_logger('[pfb_live_punch_apply] ' . pfb_pfctl_error_message($table, 'delete', $rc, implode(' ', $out)) . " entry={$entry}\n", 2);
			return ['ok' => FALSE, 'fail' => "delete {$entry}"];
		}
	}

	return ['ok' => TRUE, 'fail' => NULL];
}

/**
 * pfb_pfctl_checked_op -- issue #1505: fail-closed single-entry `pfctl -T
 * add|delete` for the four Alerts page mutation sites (delete_ip,
 * delete_ipwhitelist, ip_remove=lock, ip_white) that used to ignore exec()'s
 * status outright. Builds a one-entry plan and runs it through the SAME
 * fail-closed executor pfb_live_punch_apply() -- never pfb_pfctl_table_op():
 * see that function's docblock (ADR-61 ledger).
 *
 * $op is a fixed caller literal 'add'|'delete', never request-supplied
 * (mirrors pfb_pfctl_table_op()'s $op contract).
 *
 * @param  string $pfctl Absolute path to the pfctl binary ($pfb['pfctl']).
 * @param  string $table The pf table name (caller-validated, unescaped).
 * @param  string $op    'add' or 'delete' -- a fixed caller literal.
 * @param  string $entry The single table entry to add/delete.
 * @return array{ok: bool, fail: ?string} see pfb_live_punch_apply().
 * @throws InvalidArgumentException on an $op outside add|delete -- a plan keyed
 *         by any other verb would silently succeed with zero execs.
 */
function pfb_pfctl_checked_op(string $pfctl, string $table, string $op, string $entry): array {
	if (!in_array($op, ['add', 'delete'], TRUE)) {
		throw new InvalidArgumentException("pfb_pfctl_checked_op: op must be 'add' or 'delete', got [ {$op} ]");
	}
	$plan = ['delete' => [], 'add' => []];
	$plan[$op][] = $entry;
	return pfb_live_punch_apply($pfctl, $table, $plan);
}

/**
 * pfb_live_punch_run -- issue #1467 (CWE-362): orchestrates one Alerts "+" /
 * Unlock live punch (snapshot -> plan -> apply) under the feed-pass lock
 * (pfblockerng.inc's pfb_feed_pass_acquire()/_release()), so a concurrent
 * ADR-40 replace can never interleave mid-punch -- a replace between our
 * adds and our delete would wipe the adds (restoring the canonical set) and
 * leave the delete alone to open the WHOLE containing entry until the next
 * reload.
 *
 * $was_held is captured BEFORE acquiring: pfb_feed_pass_acquire() is
 * reentrant (a nested call while this process already holds the lock is a
 * no-op success), so an unconditional release here would drop an OUTER
 * caller's hold. This call releases only when IT was the one that
 * transitioned the lock from free to held.
 *
 * The snapshot and its consumption by pfb_live_punch_plan() both happen
 * inside the lock scope (the plan call fully drains the generator before
 * returning) -- a plan computed before a concurrent replace must never be
 * applied after one.
 *
 * NOT pure -- execs pfctl, touches the feed-pass lock.
 *
 * @param  string $pfctl    Absolute path to the pfctl binary ($pfb['pfctl']).
 * @param  string $aliasdir Passed through to pfb_live_table_snapshot() (unused there).
 * @param  string $dbdir    Scratch-file directory ($pfb['dbdir']).
 * @param  string $table    The pf table name (caller-validated).
 * @param  string $ip       The host to carve out (v4 or v6).
 * @return array{status: string, fail: ?string, del_cnt: int, add_cnt: int}
 *         status is one of 'applied'|'not_blocked'|'busy'|'failed'; 'fail'
 *         names the cause for 'failed' (NULL otherwise, prefixed
 *         "snapshot: " for a capture failure); the counts are 0 outside
 *         'applied'.
 */
function pfb_live_punch_run(string $pfctl, string $aliasdir, string $dbdir, string $table, string $ip): array {
	$was_held = isset($GLOBALS['pfb_feed_pass_lock']) && is_resource($GLOBALS['pfb_feed_pass_lock']);

	if (!pfb_feed_pass_acquire()) {
		return ['status' => 'busy', 'fail' => NULL, 'del_cnt' => 0, 'add_cnt' => 0];
	}

	try {
		$plan = pfb_live_punch_plan($ip, pfb_live_table_snapshot($pfctl, $aliasdir, $dbdir, $table));

		if (empty($plan['delete'])) {
			return ['status' => 'not_blocked', 'fail' => NULL, 'del_cnt' => 0, 'add_cnt' => 0];
		}

		$apply = pfb_live_punch_apply($pfctl, $table, $plan);
		if (!$apply['ok']) {
			return ['status' => 'failed', 'fail' => $apply['fail'], 'del_cnt' => 0, 'add_cnt' => 0];
		}

		return ['status' => 'applied', 'fail' => NULL, 'del_cnt' => count($plan['delete']), 'add_cnt' => count($plan['add'])];
	} catch (\RuntimeException $e) {
		pfb_logger("[pfb_live_punch_run] snapshot: {$e->getMessage()}\n", 2);
		return ['status' => 'failed', 'fail' => 'snapshot: ' . $e->getMessage(), 'del_cnt' => 0, 'add_cnt' => 0];
	} finally {
		if (!$was_held) {
			pfb_feed_pass_release();
		}
	}
}

/**
 * Apply an Alerts IP mutation after the page has filtered its inputs.
 *
 * @return array{redirect: bool, savemsg: string}
 */
function pfb_alerts_ip_action($action, string $ip, string $table, string $descr, array $clists, array $ip_unlock): array
{
	global $pfb;

	$result = ['redirect' => TRUE, 'savemsg' => ''];

	if ($action === 'addsuppress') {
		$is_v6  = strpos($ip, ':') !== FALSE;
		$family = $is_v6 ? 6 : 4;
		$apply  = pfb_live_punch_run($pfb['pfctl'], $pfb['aliasdir'], $pfb['dbdir'], $table, $ip);

		switch ($apply['status']) {
			case 'applied':
				$savemsg2 = ' : Removed ' . $apply['del_cnt'] . ' entr' . ($apply['del_cnt'] == 1 ? 'y' : 'ies')
					. ', added ' . $apply['add_cnt'] . ' covering CIDR' . ($apply['add_cnt'] == 1 ? '' : 's');
				break;
			case 'not_blocked':
				$savemsg2 = " : Not currently blocked by Table [ {$table} ]";
				break;
			case 'busy':
				$savemsg2 = ' : An update/reload pass is currently in progress, suppression will apply at the next reload';
				break;
			default:
				$savemsg2 = " : Live punch failed [ {$apply['fail']} ], suppression will still apply at the next reload";
				break;
		}

		$supp_key       = $is_v6 ? 'ipsuppression_v6' : 'ipsuppression';
		$cfg_key        = $is_v6 ? 'v6suppression' : 'v4suppression';
		$host_line      = $is_v6 ? "{$ip}/128" : "{$ip}/32";
		$supp_data      = isset($clists[$supp_key]['data']) && is_array($clists[$supp_key]['data'])
			? $clists[$supp_key]['data'] : [];
		$refresh_suppfile = FALSE;
		if (isset($supp_data[$host_line])) {
			$result['savemsg'] = gettext("Host IP address {$ip} already exists in the IPv{$family} Suppression customlist.");
		} elseif (pfb_ip_suppressed($ip, array_keys($supp_data))) {
			$result['savemsg'] = gettext("Host IP address {$ip} is already covered by an existing IPv{$family} Suppression entry.");
			$refresh_suppfile = TRUE;
		} else {
			$supp_dat = $host_line;
			if (!empty($descr)) {
				$supp_dat .= " # {$descr}";
			}
			$result['savemsg'] = gettext("Host IP address {$ip}") . gettext($savemsg2) . gettext(" and added to the IPv{$family} Suppression customlist.");
			$data = '';
			foreach ($supp_data as $line) {
				$data .= "{$line}";
			}
			$data .= "{$supp_dat}\r\n";
			$clists[$supp_key]['base64'] = pfb_text_area_encode($data);
			PfbConfig::write($cfg_key, $clists[$supp_key]['base64']);
			write_config("pfBlockerNG: Added {$ip} to the IPv{$family} Suppression customlist", FALSE);
			$refresh_suppfile = TRUE;
		}

		if ($refresh_suppfile) {
			$pfb['ipconfig'][$cfg_key] = $clists[$supp_key]['base64'] ?? '';
			pfb_create_suppression_file();
		}
		return $result;
	}

	if ($action === 'unlock') {
		$apply = pfb_live_punch_run($pfb['pfctl'], $pfb['aliasdir'], $pfb['dbdir'], $table, $ip);
		switch ($apply['status']) {
			case 'applied':
				pfb_unlock('unlock', 'ip', $ip_unlock, $ip, $table);
				$result['savemsg'] = "The IP [ {$ip} ] has been temporarily Unlocked from table [ {$table} ]!";
				break;
			case 'not_blocked':
				$result['savemsg'] = "The IP [ {$ip} ] is not currently blocked by table [ {$table} ] -- no unlock was recorded.";
				break;
			case 'busy':
				$result['savemsg'] = "Table [ {$table} ] is mid-update -- please retry the Unlock once the current run finishes.";
				break;
			default:
				$result['savemsg'] = "The live unlock of IP [ {$ip} ] failed [ {$apply['fail']} ] -- table [ {$table} ] still blocks it; see the pfBlockerNG log.";
				break;
		}
		return $result;
	}

	if ($action === 'lock') {
		$apply = pfb_pfctl_checked_op($pfb['pfctl'], $table, 'add', $ip);
		if ($apply['ok']) {
			pfb_unlock('lock', 'ip', $ip_unlock, $ip, $table);
			$result['savemsg'] = "The IP [ {$ip} ] has been re-locked into table [ {$table} ]!";
		} else {
			$result['savemsg'] = "The live re-lock of IP [ {$ip} ] failed [ {$apply['fail']} ] -- table [ {$table} ] does not block it; see the pfBlockerNG log.";
		}
		return $result;
	}

	if ($action === 'ip_white') {
		$vtype = strpos($table, '_v4') !== FALSE ? '4' : '6';
		$list_key = 'ipwhitelist' . $vtype;
		$metadata = $clists[$list_key][$table] ?? NULL;
		if (!is_array($metadata) || !isset($metadata['base64_idx'])) {
			$result['savemsg'] = "Cannot Whitelist - Permit alias [ {$table} ] metadata missing.";
			return $result;
		}
		$data = isset($metadata['data']) && is_array($metadata['data']) ? $metadata['data'] : [];
		if (isset($data[$ip])) {
			$result['redirect'] = FALSE;
			return $result;
		}

		$apply = pfb_pfctl_checked_op($pfb['pfctl'], $table, 'add', $ip);
		if (!$apply['ok']) {
			$result['savemsg'] = "The add of [ {$ip} ] to aliastable [ {$table} ] failed [ {$apply['fail']} ] -- see the pfBlockerNG log.";
			return $result;
		}

		@file_put_contents("{$pfb['aliasdir']}/{$table}.txt", "\n{$ip}", LOCK_EX);
		$whitelist_string = !empty($descr) ? "{$ip} # {$descr}\r\n" : "{$ip}\r\n";
		$custom = '';
		foreach ($data as $line) {
			$custom .= "{$line}";
		}
		$custom .= $whitelist_string;
		$clists[$list_key][$table]['base64'] = pfb_text_area_encode($custom);
		$base64_idx = $metadata['base64_idx'];
		// foreign structure: pfblockernglistsv4/v6/config/{row}/custom is a dynamic per-row key, not a registered config field
		config_set_path("installedpackages/pfblockernglistsv{$vtype}/config/{$base64_idx}/custom", $clists[$list_key][$table]['base64']);
		write_config("pfBlockerNG: Added [ {$ip} ] to [ {$table} ] Whitelist", FALSE);
		$aname = substr(substr($table, 4), 0, -3);
		touch("{$pfb['permitdir']}/{$aname}_custom_v{$vtype}.update");
		$result['savemsg'] = "The IP [ {$ip} ] has been added to the [ {$table} ] Permit Alias customlist.";
		return $result;
	}

	$result['savemsg'] = gettext('Cannot Lock/Unlock - Invalid action.');
	return $result;
}

/**
 * ADR-65 SS2.1: ask the live DNSBL matcher whether $domain is blocked, via the
 * read-only query channel (pfb_py_query / pfb_py_query.reply) -- no counter/
 * log/cache sink is touched, only the decision-cache LRU may warm.
 *
 * @param string $domain    Domain to query (trailing dot stripped; PFBL-01 validated).
 * @param string $qtype     Informational only -- the matcher's decision ignores it.
 * @param float  $timeout_s Bounded-wait budget in seconds (a deadline AND a hard poll
 *                          cap both bound the wait -- CLAUDE.md "No orphaned waits").
 * @return array{blocked:bool,b_type:string,group:string,b_eval:string,feed:string,p_type:string}|null
 *         The matcher's verdict, or NULL when none was obtained (invalid domain,
 *         request-encode, lock open/acquire, or write failure; timeout; or a malformed reply)
 *         -- callers must treat NULL and blocked=false identically ("no block"),
 *         never distinguish them.
 */
function pfb_dnsbl_query(string $domain, string $qtype = 'A', float $timeout_s = 5.0): ?array {
	global $pfb;

	$channel    = "{$pfb['dnsbldir']}/pfb_py_query";
	$reply_path = "{$pfb['dnsbldir']}/pfb_py_query.reply";

	$domain = rtrim($domain, '.');
	$clean  = pfb_filter($domain, PFB_FILTER_DOMAIN, 'pfb_dnsbl_query');
	if (empty($clean)) {
		pfb_logger("\nADR-65: pfb_dnsbl_query rejected an invalid domain [ " . htmlspecialchars($domain) . " ]", 2);
		return NULL;
	}

	$id      = uniqid('pfbq_', TRUE);
	$payload = json_encode(array('id' => $id, 'domain' => $clean, 'qtype' => $qtype));
	if ($payload === FALSE) {
		pfb_logger("\nADR-65: pfb_dnsbl_query failed to encode the request for [ {$clean} ]", 2);
		return NULL;
	}

	// The two Lighttpd hit parsers share one request/reply slot. Serialize the
	// complete transaction so neither can overwrite or clean up the other's files.
	$wait_s    = max($timeout_s, 0.0);
	$deadline  = microtime(TRUE) + $wait_s;
	$lock_path = "{$pfb['dnsbldir']}/pfb_py_query.lock";
	$lock = is_dir($lock_path) ? FALSE : @fopen($lock_path, 'c');
	if ($lock === FALSE) {
		pfb_logger("\nADR-65: query channel lock open failed [ {$lock_path} ]", 2);
		return NULL;
	}

	$locked = FALSE;
	$max_lock_polls = (int) ceil($wait_s / 0.02) + 2;
	$lock_polls = 0;
	$first_lock_attempt = TRUE;
	do {
		$allow_expired_attempt = $first_lock_attempt && $wait_s <= 0.0;
		$first_lock_attempt = FALSE;
		if (!$allow_expired_attempt && microtime(TRUE) >= $deadline) {
			break;
		}
		$would_block = 0;
		if (@flock($lock, LOCK_EX | LOCK_NB, $would_block)) {
			// A waiter can be descheduled between its deadline check and flock().
			// Never publish after that budget expires; timeout=0 still gets one
			// immediate non-blocking attempt.
			if (!$allow_expired_attempt && microtime(TRUE) >= $deadline) {
				@flock($lock, LOCK_UN);
				break;
			}
			$locked = TRUE;
			break;
		}
		if ($would_block !== 1) {
			@fclose($lock);
			pfb_logger("\nADR-65: query channel lock acquire failed [ {$lock_path} ]", 2);
			return NULL;
		}
		$lock_polls++;
		$remaining_s = $deadline - microtime(TRUE);
		if ($lock_polls >= $max_lock_polls || $remaining_s <= 0.0) {
			break;
		}
		usleep((int) min(20000, ceil($remaining_s * 1000000)));
	} while (TRUE);
	if (!$locked) {
		@fclose($lock);
		pfb_logger("\nADR-65: query channel lock timed out [ {$lock_path} ]", 2);
		return NULL;
	}

	try {
		if (!pfb_unbound_py_atomic_write_root($channel, $payload . "\n")) {
			// The shared atomic-write helper logs a PFBL-03 "control channel" message,
			// which misattributes a query-channel write failure -- emit an ADR-65-scoped
			// line so it is attributable.
			pfb_logger("\nADR-65: pfb_dnsbl_query failed to publish the request for [ {$clean} ]", 2);
			return NULL;
		}
		// ADR-65 SS2.1: the query request is group-writable (0660) for the attributing
		// daemon, unlike the owner-only 0640 control-command channel.
		@chmod($channel, 0660);

		$max_polls = (int) ceil($wait_s / 0.2) + 2;
		$verdict   = NULL;
		$polls     = 0;
		$first_poll = TRUE;

		do {
			$allow_expired_poll = $first_poll && $wait_s <= 0.0;
			$first_poll = FALSE;
			if (!$allow_expired_poll && microtime(TRUE) >= $deadline) {
				break;
			}
			if (file_exists($reply_path)) {
				$raw = @file_get_contents($reply_path);
				// An oversized read is treated as malformed -- a genuine reply is < 1 KB.
				if ($raw !== FALSE && strlen($raw) <= 65536) {
					$rec = json_decode($raw, TRUE);
					if (
						is_array($rec)
						&& (($rec['id'] ?? NULL) === $id)
						&& is_bool($rec['blocked'] ?? NULL)
						&& is_string($rec['b_type'] ?? NULL)
						&& is_string($rec['group'] ?? NULL)
						&& is_string($rec['b_eval'] ?? NULL)
						&& is_string($rec['feed'] ?? NULL)
						&& is_string($rec['p_type'] ?? NULL)
					) {
						// A reply that becomes readable after the shared deadline is
						// late even if this process was descheduled while reading it.
						if (!$allow_expired_poll && microtime(TRUE) >= $deadline) {
							break;
						}
						$verdict = array(
							'blocked' => $rec['blocked'],
							'b_type'  => $rec['b_type'],
							'group'   => $rec['group'],
							'b_eval'  => $rec['b_eval'],
							'feed'    => $rec['feed'],
							'p_type'  => $rec['p_type'],
						);
						break;
					}
				}
			}
			$polls++;
			$remaining_s = $deadline - microtime(TRUE);
			if ($polls >= $max_polls || $remaining_s <= 0.0) {
				break;
			}
			usleep((int) min(200000, ceil($remaining_s * 1000000)));
		} while (TRUE);

		if ($verdict === NULL) {
			pfb_logger("\nADR-65: pfb_dnsbl_query timed out waiting for a verdict [ {$clean} ]", 2);
			if (file_exists($reply_path)) {
				@unlink($reply_path);
			}
			@unlink($channel);
			return NULL;
		}

		@unlink($reply_path);
		@unlink($channel);
		return $verdict;
	} finally {
		@flock($lock, LOCK_UN);
		@fclose($lock);
	}
}

// ---------------------------------------------------------------------------
// issue #1669 — pure
// decision helpers for the gated "Edit Hooks" GUI hook-script editor
// (pfblockerng_edit_hooks.php). Pure logic lives here (house precedent: the
// setup-wizard decision helpers, pfblockerng.inc:3763) so it is covered by the
// fast PHPUnit tier (tests/php/HookEditorHelpersTest.php) instead of only the
// page. The page uses ONLY these three functions for every validation/path
// decision -- it never inlines a regex or a path check of its own.
// ---------------------------------------------------------------------------

/*
 * Compose the on-disk filename for a NEW hook script from the create-flow's three
 * fields, or return NULL if any of them is invalid. Never trusts a client-supplied
 * filename -- the caller only ever gets a name THIS function built.
 *
 *   $when -- 'pre' | 'post' (the fire point / file-prefix), anything else -> NULL.
 *   $core -- the user-chosen name core, word characters only (^[A-Za-z0-9_]+$,
 *            issue #1669 design comment). Empty, containing anything outside that
 *            class (including whitespace or non-ASCII), or longer than 200 bytes
 *            -> NULL. The 200-byte bound is a sanity cap, not a filesystem limit:
 *            FreeBSD NAME_MAX is 255 bytes and the composed name's fixed overhead
 *            ('hook_pre_' + '.py') is at most 12 bytes, so 200 leaves headroom
 *            while still rejecting a pathological value.
 *   $lang -- 'sh' | 'py' (also the file extension). ADR-12 addendum: PHP is NOT
 *            offered (the owner resolved the issue #1669 language fork against
 *            widening the runner's accepted-extension contract) -- 'php' or any
 *            other value -> NULL.
 *
 * On success returns 'hook_<when>_<core>.<lang>' -- a bare basename, matching
 * exactly the hook_<when>_*.{sh,py} pattern pfb_hook_scripts()/
 * pfb_hook_script_valid() already gate on, so a composed name is always one the
 * picker will also offer once it exists on disk.
 */
function pfb_hook_editor_compose_filename(string $when, string $core, string $lang): ?string {
	if ($when !== 'pre' && $when !== 'post') {
		return NULL;
	}
	if ($lang !== 'sh' && $lang !== 'py') {
		return NULL;
	}
	// \A...\z, never bare ^...$: PCRE's bare '$' matches not only at the true end of
	// the subject but also just BEFORE a single trailing "\n" -- so a core of
	// "x\n" would pass '^[A-Za-z0-9_]+$' and compose 'hook_pre_x\n.sh', letting the
	// create flow write a basename with an embedded LF. '\A' and '\z' anchor to the
	// absolute start/end only, with no such
	// special case, so a trailing newline (or anything else outside the class) is
	// rejected outright. The length bound is folded into the same pattern via
	// {1,200} rather than a separate strlen() check, so there is exactly one
	// anchored match to reason about.
	if ($core === '' || preg_match('/\A[A-Za-z0-9_]{1,200}\z/', $core) !== 1) {
		return NULL;
	}
	return "hook_{$when}_{$core}.{$lang}";
}

/*
 * Resolve $basename to a safe absolute path inside $dir (default
 * PFB_HOOK_SCRIPT_DIR), or return NULL if it is not safe. $dir is overridable so
 * the off-appliance unit tests can point at a fixture directory (mirrors
 * pfb_hook_scripts()'s own $dir seam).
 *
 * Containment (mirrors the runner's own checks, pfblockerng.inc pfb_hook_scripts()
 * / the pfb_run_hooks() exec path):
 *   0. $basename must not carry a NUL byte -- basename() does not strip one
 *      (a NUL is not a path-separator character to basename(), so it survives
 *      step 1's equality check unchanged
 *      and would otherwise reach the filesystem calls below, where it is silently
 *      truncated -- returning a bogus non-existent-file PATH instead of NULL).
 *      Defense-in-depth only: unreachable via the page's own flows today, since
 *      pfb_hook_editor_compose_filename() and pfb_hook_script_valid() both already
 *      reject a NUL-bearing name earlier in every real call chain.
 *   1. $basename must equal basename($basename) -- rejects any path separator,
 *      '../' traversal, or an absolute path BEFORE touching the filesystem.
 *   2. $dir must resolve (realpath()) to a real directory.
 *   3. If a file already exists at the candidate path, it must realpath() to
 *      something that is STILL directly inside the resolved directory
 *      (dirname($real) === $real_dir) and be a regular file -- a symlink that
 *      escapes the directory resolves elsewhere and is rejected. A candidate that
 *      does not exist yet (the create flow, writing a brand-new file) has nothing
 *      on disk to walk a symlink through, so step 1's basename-equality check is
 *      the only defence needed there, and the not-yet-existing path is returned.
 */
function pfb_hook_editor_path(string $basename, ?string $dir = null): ?string {
	if ($basename === '' || str_contains($basename, "\0") || basename($basename) !== $basename) {
		return NULL;
	}
	if ($dir === NULL) {
		$dir = PFB_HOOK_SCRIPT_DIR;
	}
	$real_dir = realpath($dir);
	if ($real_dir === FALSE) {
		return NULL;
	}
	$candidate = $real_dir . '/' . $basename;
	if (!file_exists($candidate)) {
		return $candidate;
	}
	$real = realpath($candidate);
	if ($real === FALSE || dirname($real) !== $real_dir || !is_file($real)) {
		return NULL;
	}
	return $real;
}

/*
 * issue #1871: remove a hook script on behalf of the Edit Hooks page.
 *
 * The Web UI could create and save hook scripts but never delete one, so a typo in
 * the Name field at creation time was unrecoverable without shell access. This is a
 * root-privileged file removal driven by a GUI request, so it deletes NOTHING it has
 * not first cleared through pfb_hook_script_valid() -- the same allow-list the picker
 * offers from, the save handler accepts, and the runner executes. That single gate
 * covers every hostile shape at once: a traversal or absolute path fails its bare-
 * basename check, and a non-hook file, a wrong Pre/Post, or a symlink whose real path
 * leaves the hook directory all fail pfb_hook_scripts()' membership test.
 *
 * Returns TRUE only when a file was actually removed, so a double submit reports
 * failure on the second pass rather than a phantom success.
 */
function pfb_hook_editor_delete(string $script, string $when, ?string $dir = null): bool
{
	if (!pfb_hook_script_valid($script, $when, $dir)) {
		return FALSE;
	}
	$path = pfb_hook_editor_path($script, $dir);
	if ($path === NULL || !is_file($path)) {
		return FALSE;
	}
	return @unlink($path);
}

/*
 * The PFB_* env-var names pfb_run_hooks() exports, as pinned by the runner source
 * (pfblockerng.inc pfb_run_hooks() + pfb_hook_lifecycle_ctx() + the pre/post call
 * sites in pfblockerng_apply.inc) and documented verbatim on the Hooks tab
 * (pfblockerng_hooks.php "Environment" help section). Fired on EVERY hook (pre and
 * post): WHEN, TRIGGER, POST_INSTALL, PRE_UNINSTALL, PKG_OP. Fired on POST hooks
 * only (nothing has changed yet when a pre hook runs): IP_CHANGED, DNSBL_CHANGED,
 * STATUS, CHANGED_IP_ALIASES, CHANGED_DNSBL_GROUPS. Kept as one flat list here (the
 * template does not need the pre/post split) -- do NOT touch the runner to make
 * this "generated"; it is a pinned enumeration reviewed against the source above.
 */
const PFB_HOOK_EDITOR_ENV_VARS = [
	'PFB_WHEN', 'PFB_TRIGGER', 'PFB_POST_INSTALL', 'PFB_PRE_UNINSTALL', 'PFB_PKG_OP',
	'PFB_IP_CHANGED', 'PFB_DNSBL_CHANGED', 'PFB_STATUS', 'PFB_CHANGED_IP_ALIASES', 'PFB_CHANGED_DNSBL_GROUPS',
];

/*
 * Pre-filled template body for a NEW hook script, language-appropriate ($lang
 * 'sh' | 'py'; an unrecognised value falls back to the 'sh' shape so this never
 * throws). Documents the hook contract (env vars + failure semantics) as a
 * reminder, then a hello-world body that fires the log using one of the vars
 * (issue #1669 design comment). $when is folded into the header text only (which
 * fire point this particular file is being created as); it does not change which
 * vars are documented -- the full contract applies to every hook file.
 */
function pfb_hook_editor_template(string $when, string $lang): string {
	$when_label = ($when === 'pre' || $when === 'post') ? $when : 'pre|post';

	$contract = "pfBlockerNG update hook (ADR-12) -- created as a '{$when_label}' hook.\n" .
		"\n" .
		"Fires as root during the pfBlockerNG update pass. A non-zero exit OR a timeout\n" .
		"is LOGGED and the update CONTINUES -- a hook can never abort or stall an\n" .
		"update. A hook that hangs is SIGTERM'd at its configured timeout, then\n" .
		"SIGKILL'd after a short grace period.\n" .
		"\n" .
		"Environment (set on every hook):\n" .
		"  PFB_WHEN               -- fire point: pre | post\n" .
		"  PFB_TRIGGER            -- cron | update | force-reload\n" .
		"  PFB_POST_INSTALL       -- 1 on the post-install/upgrade resync, else 0\n" .
		"  PFB_PRE_UNINSTALL      -- 1 on the pre-deinstall teardown, else 0\n" .
		"  PFB_PKG_OP             -- install|upgrade|reinstall|delete, or '' outside a pkg op\n" .
		"\n" .
		"Set on 'post' hooks only (nothing has changed yet when 'pre' runs):\n" .
		"  PFB_IP_CHANGED         -- 1 if the IP/firewall side changed this pass, else 0\n" .
		"  PFB_DNSBL_CHANGED      -- 1 if the DNSBL side changed this pass, else 0\n" .
		"  PFB_STATUS             -- overall pass status (currently always 'ok')\n" .
		"  PFB_CHANGED_IP_ALIASES   -- space-separated pfB_* aliases updated this pass\n" .
		"  PFB_CHANGED_DNSBL_GROUPS -- space-separated DNSBL_* groups updated this pass\n";

	if ($lang === 'py') {
		// env-based, versioned shebang: pfSense ships python3.11 with NO unversioned
		// 'python3' symlink, so a bare '#!/usr/bin/env python3' is an rc=127 footgun
		// here -- the version must be spelled out. (This is a template string for a
		// hook SCRIPT the OS execs directly via its own shebang -- not this package
		// invoking an appliance interpreter itself; see scripts/check_appliance_python.py.)
		$header = "#!/usr/bin/env python3.11\n" .
			"# NOTE: verify the interpreter version above matches this box's installed python3\n" .
			"# (pfSense CE ships python3.11 with no unversioned 'python3' symlink).\n";
		$comment = "#\n# " . str_replace("\n", "\n# ", rtrim($contract)) . "\n#\n";
		$body = "import os\n" .
			"\n" .
			"print(\"Firing {} hook (trigger: {})\".format(os.environ.get('PFB_WHEN'), os.environ.get('PFB_TRIGGER')))\n";
		return $header . $comment . "\n" . $body;
	}

	$header = "#!/bin/sh\n";
	$comment = "#\n# " . str_replace("\n", "\n# ", rtrim($contract)) . "\n#\n";
	$body = "echo \"Firing \${PFB_WHEN} hook (trigger: \${PFB_TRIGGER})\"\n";
	return $header . $comment . "\n" . $body;
}

/*
 * Picks the CodeMirror 6 hook-editor mode ('py' | 'sh', issue #1669 --
 * python + shell only, no PHP per the ADR-12 addendum) from $script's own extension --
 * the same basename pfb_hook_scripts()/pfb_hook_script_valid() already gate to
 * hook_<when>_*.{sh,py}. $fallback (itself coerced to 'py'|'sh', default 'sh') is used
 * when $script is empty (nothing loaded yet -- a fresh page load or a failed create
 * POST) or carries an unrecognised extension, so this never returns anything outside
 * {'py', 'sh'} for the page to echo into the JS init.
 */
function pfb_hook_editor_lang_for(string $script, string $fallback): string {
	if ($script !== '') {
		$ext = strtolower(pathinfo($script, PATHINFO_EXTENSION));
		if ($ext === 'py' || $ext === 'sh') {
			return $ext;
		}
	}
	return ($fallback === 'py') ? 'py' : 'sh';
}

/*
 * issue #1732: the lint endpoint's sh stderr extractor. Mirrors
 * tests/smoke/test_smoke_lint_probe.py's _SH_DIAG_RE (`/bin/sh -n /dev/stdin` on the
 * appliance emits "/dev/stdin: <line>: Syntax error: <detail>") -- keep the two in
 * sync. A non-empty stderr that matches nothing degrades to one line-1 diagnostic
 * carrying the raw text rather than being dropped silently.
 */
function pfb_lint_parse_sh_stderr(string $stderr): array {
	if ($stderr === '') {
		return [];
	}
	$diagnostics = [];
	foreach (preg_split('/\R/', $stderr) as $line) {
		if ($line === '' || preg_match('/(\d+): Syntax error: (.+)$/', $line, $match) !== 1) {
			continue;
		}
		$diagnostics[] = ['line' => (int) $match[1], 'message' => 'Syntax error: ' . $match[2], 'severity' => 'error'];
	}
	if ($diagnostics === []) {
		return [['line' => 1, 'message' => trim($stderr), 'severity' => 'error']];
	}
	return $diagnostics;
}

/*
 * issue #1732: the lint endpoint's Python stderr extractor. Mirrors the
 * compile-probe's own "line N: msg" format (SyntaxError.lineno/.msg, kept in sync with
 * tests/smoke/test_smoke_lint_probe.py's _PY_PROBE). Same unmatched-line degradation as
 * pfb_lint_parse_sh_stderr().
 */
function pfb_lint_parse_py_stderr(string $stderr): array {
	if ($stderr === '') {
		return [];
	}
	$diagnostics = [];
	foreach (preg_split('/\R/', $stderr) as $line) {
		if ($line === '' || preg_match('/^line (\d+): (.*)$/', $line, $match) !== 1) {
			continue;
		}
		$diagnostics[] = ['line' => (int) $match[1], 'message' => $match[2], 'severity' => 'error'];
	}
	if ($diagnostics === []) {
		return [['line' => 1, 'message' => trim($stderr), 'severity' => 'error']];
	}
	return $diagnostics;
}

/*
 * issue #1732: reshapes pfb_dnsbl_regex_validation_errors()'s return (each entry either
 * a "line N: ..." content diagnostic or a bare infra-failure string) into the lint
 * endpoint's line-mapped diagnostic shape. An infra string carries no line of its own,
 * so it surfaces as a line-1 warning rather than a false line-1 error.
 */
function pfb_lint_parse_regex_errors(array $errors): array {
	$diagnostics = [];
	foreach ($errors as $error) {
		if (preg_match('/^line (\d+): (.*)$/s', $error, $match) === 1) {
			$diagnostics[] = ['line' => (int) $match[1], 'message' => $match[2], 'severity' => 'error'];
		} else {
			$diagnostics[] = ['line' => 1, 'message' => $error, 'severity' => 'warning'];
		}
	}
	return $diagnostics;
}

/*
 * issue #1732: the shared no-shell launcher for the sh/py lint probes -- same argv-array
 * proc_open() shape as pfb_dnsbl_regex_validation_errors() (tmpfile stderr, 8192-byte
 * stdin write loop, NUL-scrubbed stderr), generalised to an arbitrary $command so both
 * probes share one launch path. Content is piped on stdin only -- never written to disk,
 * never executed by a shell (proc_open() with an argv array never spawns one). Returns
 * ['exit' => int, 'stderr' => string, 'failure' => string], failure '' on a clean launch.
 */
function pfb_lint_probe_run(array $command, string $content): array {
	$stderr = tmpfile();
	if ($stderr === FALSE) {
		return ['exit' => -1, 'stderr' => '', 'failure' => 'unable to create diagnostics file'];
	}
	$stderr_path = stream_get_meta_data($stderr)['uri'];
	$descriptors = array(
		0 => array('pipe', 'r'),
		1 => array('file', '/dev/null', 'w'),
		2 => array('file', $stderr_path, 'a'),
	);
	$pipes = array();
	$process = @proc_open($command, $descriptors, $pipes);
	if (!is_resource($process)) {
		fclose($stderr);
		return ['exit' => -1, 'stderr' => '', 'failure' => 'launcher failed'];
	}
	if (!isset($pipes[0]) || !is_resource($pipes[0])) {
		proc_close($process);
		fclose($stderr);
		return ['exit' => -1, 'stderr' => '', 'failure' => 'stdin unavailable'];
	}
	$write_ok = TRUE;
	$offset = 0;
	$length = strlen($content);
	while ($offset < $length) {
		$written = @fwrite($pipes[0], substr($content, $offset, 8192));
		if ($written === FALSE || $written === 0) {
			$write_ok = FALSE;
			break;
		}
		$offset += $written;
	}
	if (isset($pipes[0]) && is_resource($pipes[0])) {
		fclose($pipes[0]);
	}
	$exit_code = proc_close($process);
	fflush($stderr);
	rewind($stderr);
	$stderr_contents = (string) stream_get_contents($stderr);
	fclose($stderr);
	$stderr_contents = str_replace("\0", '\\0', $stderr_contents);
	if (!$write_ok) {
		return ['exit' => $exit_code, 'stderr' => $stderr_contents, 'failure' => 'stdin write failed'];
	}
	return ['exit' => $exit_code, 'stderr' => $stderr_contents, 'failure' => ''];
}

/*
 * issue #1732: `[$timeout_bin] $sh -n /dev/stdin` lint runner -- the /dev/stdin operand
 * is load-bearing (tests/smoke/test_smoke_lint_probe.py: bare stdin loses the line
 * number on the appliance). '' content and a missing/non-executable interpreter/timeout
 * short-circuit before any process is launched; a nonzero exit with empty stderr (e.g. a
 * timeout SIGTERM) degrades to a line-1 warning naming the exit code instead of silently
 * reporting nothing.
 */
function pfb_lint_sh_diagnostics(string $content, string $sh = '/bin/sh', string $timeout_bin = '/usr/bin/timeout'): array {
	if ($content === '') {
		return [];
	}
	if ($sh === '' || !is_executable($sh) || $timeout_bin === '' || !is_executable($timeout_bin)) {
		return [['line' => 1, 'message' => 'sh syntax checker unavailable', 'severity' => 'warning']];
	}
	$command = array($timeout_bin, '-s', 'TERM', '-k', '1', '5', $sh, '-n', '/dev/stdin');
	$result = pfb_lint_probe_run($command, $content);
	if ($result['failure'] !== '') {
		// sh exits at the FIRST syntax error -- an over-pipe-buffer body can EPIPE the
		// stdin write loop (failure = 'stdin write failed') while stderr already holds a
		// real line-mapped diagnostic; prefer that over the generic launch-failed warning.
		if (!pfb_is_blank($result['stderr'])) {
			return pfb_lint_parse_sh_stderr($result['stderr']);
		}
		return [['line' => 1, 'message' => 'sh syntax checker launch failed: ' . $result['failure'], 'severity' => 'warning']];
	}
	if ($result['exit'] === 0) {
		return [];
	}
	if (pfb_is_blank($result['stderr'])) {
		return [['line' => 1, 'message' => "sh syntax checker exited {$result['exit']} with no diagnostic", 'severity' => 'warning']];
	}
	return pfb_lint_parse_sh_stderr($result['stderr']);
}

/*
 * issue #1732: `[$timeout_bin] $python -c PROBE` lint runner. PROBE below MUST stay
 * byte-identical to _PY_PROBE in tests/smoke/test_smoke_lint_probe.py -- that smoke test
 * pins the live appliance's SyntaxError.lineno/.msg semantics for this exact script.
 * Same short-circuit/degradation shape as pfb_lint_sh_diagnostics().
 */
function pfb_lint_py_diagnostics(string $content, string $python, string $timeout_bin = '/usr/bin/timeout'): array {
	if ($content === '') {
		return [];
	}
	if ($python === '' || !is_executable($python) || $timeout_bin === '' || !is_executable($timeout_bin)) {
		return [['line' => 1, 'message' => 'python syntax checker unavailable', 'severity' => 'warning']];
	}
	$probe = <<<'PYTHON'
import sys
try:
    compile(sys.stdin.read(), '<hook>', 'exec')
except SyntaxError as error:
    print('line {}: {}'.format(error.lineno or 1, error.msg), file=sys.stderr)
    raise SystemExit(1)
raise SystemExit(0)
PYTHON;
	$command = array($timeout_bin, '-s', 'TERM', '-k', '1', '5', $python, '-c', $probe);
	$result = pfb_lint_probe_run($command, $content);
	if ($result['failure'] !== '') {
		return [['line' => 1, 'message' => 'python syntax checker launch failed: ' . $result['failure'], 'severity' => 'warning']];
	}
	if ($result['exit'] === 0) {
		return [];
	}
	if ($result['exit'] === 1 && !pfb_is_blank($result['stderr'])) {
		return pfb_lint_parse_py_stderr($result['stderr']);
	}
	return [['line' => 1, 'message' => "python syntax checker exited {$result['exit']} with no diagnostic", 'severity' => 'warning']];
}

/*
 * issue #1732: the pfblockerng_lint.php dispatcher -- one lang-keyed entry point over
 * the three validators above. Sanitizes via the shared pfb_sanitize_text_area() (issue
 * #1723) helper first, the same idiom pfblockerng_dnsbl.php and
 * pfblockerng_edit_hooks.php's save handlers run at ingestion -- lint must judge what
 * save would persist, not the raw POST. $python/$sh/$timeout_bin default to the live
 * appliance paths (null) and exist as parameters only so tests can substitute fixture
 * interpreters.
 */
function pfb_lint_diagnostics(
	string $lang,
	string $content,
	bool $cap,
	?string $python = null,
	?string $sh = null,
	?string $timeout_bin = null
): array {
	$content = pfb_sanitize_text_area($content);
	$timeout_bin ??= '/usr/bin/timeout';
	return match ($lang) {
		// issue #1868: the advisory description-length notes ride the lint path
		// only — pfb_dnsbl_regex_validation_errors() (what save consults) never
		// sees them, so a long description warns without blocking a save.
		'regex' => array_merge(
			pfb_lint_parse_regex_errors(
				pfb_dnsbl_regex_validation_errors($content, $python ?? pfb_python_interpreter(), $cap, $timeout_bin)
			),
			pfb_dnsbl_regex_description_warnings($content)
		),
		'sh' => pfb_lint_sh_diagnostics($content, $sh ?? '/bin/sh', $timeout_bin),
		'py' => pfb_lint_py_diagnostics($content, $python ?? pfb_python_interpreter(), $timeout_bin),
		default => [],
	};
}

// logger() and localize_text() are pfSense-core helpers (src/etc/inc/util.inc)
// on pfSense Plus / master, but absent from released pfSense CE <= 2.8.1. Define
// fallbacks ONLY when core does not provide them, so this package runs on both:
// where core has them (Plus/master) these definitions are skipped and core wins
// unchanged; on CE 2.8.1 they fill the gap. Behaviour mirrors the core versions.
if (!function_exists('localize_text')) {
	function localize_text(...$args) {
		$arg0_len = strlen($args[0]);
		if (($arg0_len > 0) && ($arg0_len < 4096)) {
			$args[0] = gettext($args[0]);
		}
		return (count($args) == 1) ? $args[0] : sprintf(...$args);
	}
}

if (!function_exists('logger')) {
	function logger(int $priority, mixed $message, ?string $prefix = null, ?int $facilities = null): void {
		$log_prefix = match ($priority) {
			LOG_EMERG	=> 'EMERGENCY',
			LOG_ALERT	=> 'ALERT',
			LOG_CRIT	=> 'CRITICAL',
			LOG_ERR		=> 'ERROR',
			LOG_WARNING	=> 'WARNING',
			LOG_NOTICE	=> 'NOTICE',
			LOG_INFO	=> 'INFO',
			LOG_DEBUG	=> 'DEBUG',
			default		=> 'DEBUG'
		};
		if (isset($prefix)) {
			$log_prefix .= ' [' . gettext($prefix) . ']';
		}
		$pri = isset($facilities) ? ($priority | $facilities) : $priority;
		if (is_string($message)) {
			$message = str_replace(PHP_EOL, '', $message);
			$log_string = (strlen($message) > 0) ? "{$log_prefix} {$message}" : $log_prefix;
		} else {
			$log_string = $log_prefix . ' ' . str_replace(PHP_EOL, '', var_export($message, TRUE));
		}
		syslog($pri, $log_string);
	}
}
?>
