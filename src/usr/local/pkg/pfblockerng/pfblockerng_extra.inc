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
// $enum->toStored(). Goal: preserve upgrade behaviour, not byte-identical storage — a
// downgrade-unknown token falls through to the safe default.
// Tests: tests/php/CfgAdaptersTest.php, tests/php/RollbackContractTest.php.
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
// unknown -> Off. Reusing 'on' for All keeps pre-4.0.0 installs migration-free and
// downgrade-safe (an older release reading 'on' still blocks all IDN).
enum PfbIdnMode: string implements PfbStoredEnum
{
	use PfbStoredEnumAdapter;

	// All reuses the original 'on' token (pre-ADR-08 block-all-IDN) as its backing value:
	// it round-trips with ZERO migration AND is downgrade-safe — an older release reading
	// 'on' still blocks all IDN. Only Confusable is a genuinely new token (an old release
	// treats it as off, which is acceptable). The SAME token feeds config.xml, py_unbound.ini,
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
// write vocabulary only ever emits live tokens, so it is downgrade-safe.
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
// @return array<string, array{url: string, container: string, parse: string, header: bool, domain_col: int, auth: string|array{header: string, scheme: string}, label: string, licence: string}>
function pfb_top1m_providers(): array
{
	return array(
		PfbTop1mSource::Tranco->value	=> array(
			'url'		=> 'https://tranco-list.eu/top-1m.csv.zip',
			'container'	=> 'zip',
			'parse'		=> 'rank_domain',
			'header'	=> FALSE,
			'domain_col'	=> 1,
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
// CONSTRAINTS (ADR-29 §5, ADR-28 §2.2): registry keys are the EXACT existing config.xml keys
// (no renames); stored values NEVER change (adapters map to the legacy stored string on
// write); round-trip identity write(read(v)) == v for every canonical stored value.
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
 * @return array<string,array{section:string,default:string,read_adapter:callable|null,write_adapter:callable|null,since:string}>
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

		// Master enable/disable: 'on' | '' (checkbox).
		'enable_cb' => [
			'section'       => $gen,
			'default'       => '',
			'read_adapter'  => 'pfb_cfg_toggle_read',
			'write_adapter' => 'pfb_cfg_toggle_write',
			'since'         => '1.0.0',
		],

		// Keep blocklists when pfBlockerNG is disabled: 'on' | 'off' | ''.
		// Default ON — the #281 canonical default; GUI and pfb_global() agree.
		// Uses the lenient adapter so an unchecked-save (off) is stored as the
		// explicit 'off' token, distinguishable from a never-configured install
		// (key absent) which the registry default returns as 'on'. The empty-string
		// '' is a LEGACY READ token for installs written before this fix; it maps
		// to Off on read, same as 'off'. Write always emits 'off' (backward-safe:
		// older releases that read 'off' for pfb_keep treat it as "disabled").
		'pfb_keep' => [
			'section'       => $gen,
			'default'       => 'on',
			'read_adapter'  => 'pfb_cfg_lenient_read',
			'write_adapter' => 'pfb_cfg_lenient_write',
			'since'         => '2.1.0',
		],

		// Update interval: numeric hour string | 'Disabled'. Default '1'.
		'pfb_interval' => [
			'section'       => $gen,
			'default'       => '1',
			'read_adapter'  => NULL,
			'write_adapter' => NULL,
			'since'         => '1.0.0',
		],

		// Cron start minute ('0'|'15'|'30'|'45'). Default '0'.
		'pfb_min' => [
			'section'       => $gen,
			'default'       => '0',
			'read_adapter'  => NULL,
			'write_adapter' => NULL,
			'since'         => '1.0.0',
		],

		// Cron start hour (0-23 as string). Default '0'.
		'pfb_hour' => [
			'section'       => $gen,
			'default'       => '0',
			'read_adapter'  => NULL,
			'write_adapter' => NULL,
			'since'         => '1.0.0',
		],

		// Once-a-day start hour (0-23 as string). Default '0'.
		'pfb_dailystart' => [
			'section'       => $gen,
			'default'       => '0',
			'read_adapter'  => NULL,
			'write_adapter' => NULL,
			'since'         => '1.0.0',
		],

		// Max daily download failure threshold ('0' = unlimited). Default '0'.
		'skipfeed' => [
			'section'       => $gen,
			'default'       => '0',
			'read_adapter'  => NULL,
			'write_adapter' => NULL,
			'since'         => '1.0.0',
		],

		// ADR-11: CSV of active aggregate alias types (e.g. 'Deny,Permit'). Default ''.
		'pfb_agg_types' => [
			'section'       => $gen,
			'default'       => '',
			'read_adapter'  => NULL,
			'write_adapter' => NULL,
			'since'         => '3.2.0',
		],

		// Log rotation limits (all numeric strings; default '20000').
		'log_max_log' => [
			'section'       => $gen,
			'default'       => '20000',
			'read_adapter'  => NULL,
			'write_adapter' => NULL,
			'since'         => '2.0.0',
		],
		'log_max_errlog' => [
			'section'       => $gen,
			'default'       => '20000',
			'read_adapter'  => NULL,
			'write_adapter' => NULL,
			'since'         => '2.0.0',
		],
		'log_max_extraslog' => [
			'section'       => $gen,
			'default'       => '20000',
			'read_adapter'  => NULL,
			'write_adapter' => NULL,
			'since'         => '2.0.0',
		],
		'log_max_ip_blocklog' => [
			'section'       => $gen,
			'default'       => '20000',
			'read_adapter'  => NULL,
			'write_adapter' => NULL,
			'since'         => '2.0.0',
		],
		'log_max_ip_permitlog' => [
			'section'       => $gen,
			'default'       => '20000',
			'read_adapter'  => NULL,
			'write_adapter' => NULL,
			'since'         => '2.0.0',
		],
		'log_max_ip_matchlog' => [
			'section'       => $gen,
			'default'       => '20000',
			'read_adapter'  => NULL,
			'write_adapter' => NULL,
			'since'         => '2.0.0',
		],
		'log_max_ip_parse_err' => [
			'section'       => $gen,
			'default'       => '20000',
			'read_adapter'  => NULL,
			'write_adapter' => NULL,
			'since'         => '4.0.0',
		],
		'log_max_dnslog' => [
			'section'       => $gen,
			'default'       => '20000',
			'read_adapter'  => NULL,
			'write_adapter' => NULL,
			'since'         => '2.0.0',
		],
		'log_max_dnsbl_parse_err' => [
			'section'       => $gen,
			'default'       => '20000',
			'read_adapter'  => NULL,
			'write_adapter' => NULL,
			'since'         => '2.0.0',
		],
		'log_max_dnsreplylog' => [
			'section'       => $gen,
			'default'       => '20000',
			'read_adapter'  => NULL,
			'write_adapter' => NULL,
			'since'         => '2.0.0',
		],
		'log_max_unilog' => [
			'section'       => $gen,
			'default'       => '20000',
			'read_adapter'  => NULL,
			'write_adapter' => NULL,
			'since'         => '2.0.0',
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
			'since'         => '4.0.0',
		];
	}

	$registry = $registry + [

		// Software update check last-seen version (string or null). Default ''.
		'pfb_software_check' => [
			'section'       => $gen,
			'default'       => '',
			'read_adapter'  => NULL,
			'write_adapter' => NULL,
			'since'         => '2.0.0',
		],

		// Internal-address feed-host filter toggle: 'on'|'off'. Default 'on' (new install).
		'pfb_feed_internal_filter' => [
			'section'       => $gen,
			'default'       => 'on',
			'read_adapter'  => NULL,
			'write_adapter' => NULL,
			'since'         => '3.1.0',
		],

		// Allowlist for internal-feed hosts (base64-encoded). Default ''.
		'pfb_feed_internal_allowlist' => [
			'section'       => $gen,
			'default'       => '',
			'read_adapter'  => NULL,
			'write_adapter' => NULL,
			'since'         => '3.1.0',
		],

		// ADR-49: opt-in plain-text feed sanity scan. Checkbox 'on'|''(off).
		// Default off (absent = off = today's behaviour: the scan never runs).
		'pfb_feed_sanity' => [
			'section'       => $gen,
			'default'       => '',                       // absent -> Off (new-install default too)
			'read_adapter'  => 'pfb_cfg_toggle_read',
			'write_adapter' => 'pfb_cfg_toggle_write',
			'since'         => '4.0.0',
		],

		// Reuse blocklists across updates: 'on' | '' (checkbox). Default ''.
		'pfb_reuse' => [
			'section'       => $gen,
			'default'       => '',
			'read_adapter'  => 'pfb_cfg_toggle_read',
			'write_adapter' => 'pfb_cfg_toggle_write',
			'since'         => '2.0.0',
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
			'since'         => '4.0.0',
		],

		// ADR-40: alias-table delta batch size (integer as string). Default '512'.
		// Clamped to [64, 4096] on read. Batch=512 is optimal for sub-1M tables
		// (zero ICMP stalls at 100k/1k-churn); batch=1024+ for 1M+ tables.
		'pfb_alias_delta_batch' => [
			'section'       => $gen,
			'default'       => '512',
			'read_adapter'  => NULL,
			'write_adapter' => NULL,
			'since'         => '4.0.0',
		],

		// ADR-43: tick-cron dispatch interval in minutes (1–60). Default '15'.
		// One cron tick fires every */pfb_tick_interval; jobs run only when due
		// per the due-ledger. Default 15 matches the tightest existing job (ss_refresh).
		'pfb_tick_interval' => [
			'section'       => $gen,
			'default'       => '15',
			'read_adapter'  => NULL,
			'write_adapter' => NULL,
			'since'         => '4.0.0',
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
			'since'         => '4.0.0',
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
			'since'         => '1.0.0',
		],

		// ADR-13: auto-create/remove DNSBL sinkhole VIPs: 'on' | '' (checkbox).
		'pfb_dnsvip_auto' => [
			'section'       => $dnsbl,
			'default'       => '',
			'read_adapter'  => 'pfb_cfg_toggle_read',
			'write_adapter' => 'pfb_cfg_toggle_write',
			'since'         => '3.0.0',
		],

		// [ #381 ] Opt out of automatic DNSBL sinkhole NAT rule generation: 'on' | '' (checkbox).
		// Default '' = NAT generated (current behaviour); 'on' = user manages NAT manually.
		'pfb_dnsbl_nonat' => [
			'section'       => $dnsbl,
			'default'       => '',
			'read_adapter'  => 'pfb_cfg_toggle_read',
			'write_adapter' => 'pfb_cfg_toggle_write',
			'since'         => '4.0.0',
		],

		// VIP interface for DNSBL sinkhole. Default 'lo0'.
		'dnsbl_interface' => [
			'section'       => $dnsbl,
			'default'       => 'lo0',
			'read_adapter'  => NULL,
			'write_adapter' => NULL,
			'since'         => '1.0.0',
		],

		// DNSBL IPv4 sinkhole VIP id string. Default ''.
		'pfb_dnsvip4' => [
			'section'       => $dnsbl,
			'default'       => '',
			'read_adapter'  => NULL,
			'write_adapter' => NULL,
			'since'         => '1.0.0',
		],

		// DNSBL IPv6 sinkhole VIP id string. Default ''.
		'pfb_dnsvip6' => [
			'section'       => $dnsbl,
			'default'       => '',
			'read_adapter'  => NULL,
			'write_adapter' => NULL,
			'since'         => '1.0.0',
		],

		// DNSBL lighttpd HTTP port. Default '' (system default).
		'pfb_dnsport' => [
			'section'       => $dnsbl,
			'default'       => '',
			'read_adapter'  => NULL,
			'write_adapter' => NULL,
			'since'         => '1.0.0',
		],

		// DNSBL lighttpd HTTPS port. Default ''.
		'pfb_dnsport_ssl' => [
			'section'       => $dnsbl,
			'default'       => '',
			'read_adapter'  => NULL,
			'write_adapter' => NULL,
			'since'         => '1.0.0',
		],

		// TOP1M whitelist enable. Default ''.
		'alexa_enable' => [
			'section'       => $dnsbl,
			'default'       => '',
			'read_adapter'  => NULL,
			'write_adapter' => NULL,
			'since'         => '1.0.0',
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
			'since'         => '2.0.0',
		],

		// TOP1M domain count (numeric string). Default '1000'.
		'alexa_count' => [
			'section'       => $dnsbl,
			'default'       => '1000',
			'read_adapter'  => NULL,
			'write_adapter' => NULL,
			'since'         => '1.0.0',
		],

		// TOP1M TLD inclusions for whitelisting. Default ''.
		'alexa_inclusion' => [
			'section'       => $dnsbl,
			'default'       => '',
			'read_adapter'  => NULL,
			'write_adapter' => NULL,
			'since'         => '1.0.0',
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
			'since'         => '4.0.0',
		],

		// Resolver cache backup/restore option. Default ''.
		'pfb_cache' => [
			'section'       => $dnsbl,
			'default'       => '',
			'read_adapter'  => NULL,
			'write_adapter' => NULL,
			'since'         => '1.0.0',
		],

		// Global logging/blocking mode. Default ''.
		'global_log' => [
			'section'       => $dnsbl,
			'default'       => '',
			'read_adapter'  => NULL,
			'write_adapter' => NULL,
			'since'         => '1.0.0',
		],

		// ADR-22: scheme-parsing leniency: 'on' | 'off' | ''. Default 'off'.
		// PfbLenient adapter (off-value = 'off', not '').
		'pfb_dnsbl_lenient' => [
			'section'       => $dnsbl,
			'default'       => 'off',
			'read_adapter'  => 'pfb_cfg_lenient_read',
			'write_adapter' => 'pfb_cfg_lenient_write',
			'since'         => '3.1.0',
		],

		// Python DNS reply logging. Default ''.
		'pfb_py_reply' => [
			'section'       => $dnsbl,
			'default'       => '',
			'read_adapter'  => NULL,
			'write_adapter' => NULL,
			'since'         => '3.0.0',
		],

		// HSTS null-blocking mode: 'on' | ''. Default ''.
		'pfb_hsts' => [
			'section'       => $dnsbl,
			'default'       => '',
			'read_adapter'  => 'pfb_cfg_toggle_read',
			'write_adapter' => 'pfb_cfg_toggle_write',
			'since'         => '3.0.0',
		],

		// ADR-08: IDN mode — adopted into the gateway as a PfbIdnMode enum (ADR-28
		// reframe: preserve behaviour on upgrade, not byte-identical storage). Read
		// normalises legacy 'on' -> All; write persists the canonical token
		// ('on'=All | 'confusable' | 'off'), reusing the pre-4.0.0 'on' token so All
		// round-trips with zero migration. Legacy '' and the 4.0.0-alpha 'all' token
		// read as Off. Downgrade-safe: older releases string-compared these tokens,
		// so an unknown token falls through to their off default.
		// See ADR-28 §2.2 + CfgAdaptersTest + RollbackContractTest.
		'pfb_idn' => [
			'section'       => $dnsbl,
			'default'       => '',
			'read_adapter'  => 'pfb_cfg_idn_mode_read',
			'write_adapter' => 'pfb_cfg_idn_mode_write',
			'since'         => '3.0.0',
		],

		// Confusable: block malicious homoglyphs (default on). Default 'on'.
		'pfb_idn_block_malicious' => [
			'section'       => $dnsbl,
			'default'       => 'on',
			'read_adapter'  => NULL,
			'write_adapter' => NULL,
			'since'         => '3.0.0',
		],

		// Confusable: escalate suspicious mixed-script to block (opt-in). Default ''.
		'pfb_idn_escalate_suspicious' => [
			'section'       => $dnsbl,
			'default'       => '',
			'read_adapter'  => NULL,
			'write_adapter' => NULL,
			'since'         => '3.0.0',
		],

		// Python regex: 'on' | ''. Default ''.
		'pfb_regex' => [
			'section'       => $dnsbl,
			'default'       => '',
			'read_adapter'  => NULL,
			'write_adapter' => NULL,
			'since'         => '3.0.0',
		],

		// Python regex list (textarea). Default ''.
		'pfb_regex_list' => [
			'section'       => $dnsbl,
			'default'       => '',
			'read_adapter'  => NULL,
			'write_adapter' => NULL,
			'since'         => '3.0.0',
		],

		// Python regex static cap ('on'|''). Default ''.
		'pfb_regex_cap' => [
			'section'       => $dnsbl,
			'default'       => '',
			'read_adapter'  => NULL,
			'write_adapter' => NULL,
			'since'         => '3.0.0',
		],

		// CNAME validation. Default ''.
		'pfb_cname' => [
			'section'       => $dnsbl,
			'default'       => '',
			'read_adapter'  => NULL,
			'write_adapter' => NULL,
			'since'         => '3.0.0',
		],

		// TLD Allow option. Default ''.
		'pfb_pytld' => [
			'section'       => $dnsbl,
			'default'       => '',
			'read_adapter'  => NULL,
			'write_adapter' => NULL,
			'since'         => '3.0.0',
		],

		// Log events via DNSBL Webserver vs python. Default ''.
		'pfb_py_nolog' => [
			'section'       => $dnsbl,
			'default'       => '',
			'read_adapter'  => NULL,
			'write_adapter' => NULL,
			'since'         => '3.0.0',
		],

		// No AAAA blocking: 'on' | ''. Default ''.
		'pfb_noaaaa' => [
			'section'       => $dnsbl,
			'default'       => '',
			'read_adapter'  => NULL,
			'write_adapter' => NULL,
			'since'         => '3.0.0',
		],

		// No AAAA list (textarea). Default ''.
		'pfb_noaaaa_list' => [
			'section'       => $dnsbl,
			'default'       => '',
			'read_adapter'  => NULL,
			'write_adapter' => NULL,
			'since'         => '3.0.0',
		],

		// DNSBL bypass enable: 'on' | ''. Default ''.
		'pfb_gp' => [
			'section'       => $dnsbl,
			'default'       => '',
			'read_adapter'  => NULL,
			'write_adapter' => NULL,
			'since'         => '3.0.0',
		],

		// DNSBL bypass local IP list (textarea). Default ''.
		'pfb_gp_bypass_list' => [
			'section'       => $dnsbl,
			'default'       => '',
			'read_adapter'  => NULL,
			'write_adapter' => NULL,
			'since'         => '3.0.0',
		],

		// TLD blacklist (textarea). Default ''.
		'tldblacklist' => [
			'section'       => $dnsbl,
			'default'       => '',
			'read_adapter'  => NULL,
			'write_adapter' => NULL,
			'since'         => '1.0.0',
		],

		// TLD exclusion (textarea). Default ''.
		'tldexclusion' => [
			'section'       => $dnsbl,
			'default'       => '',
			'read_adapter'  => NULL,
			'write_adapter' => NULL,
			'since'         => '1.0.0',
		],

		// DNSBL suppression/whitelist (base64). Default ''.
		'suppression' => [
			'section'       => $dnsbl,
			'default'       => '',
			'read_adapter'  => NULL,
			'write_adapter' => NULL,
			'since'         => '1.0.0',
		],

		// DNSBL action for IP blocking. Default 'Disabled'.
		'action' => [
			'section'       => $dnsbl,
			'default'       => 'Disabled',
			'read_adapter'  => NULL,
			'write_adapter' => NULL,
			'since'         => '1.0.0',
		],

		// Auto-create floating pass rule. Default 'Disabled'.
		'pfb_dnsbl_rule' => [
			'section'       => $dnsbl,
			'default'       => 'Disabled',
			'read_adapter'  => NULL,
			'write_adapter' => NULL,
			'since'         => '1.0.0',
		],

		// Allow-interface for DNSBL (multi-select). Default ''.
		'dnsbl_allow_int' => [
			'section'       => $dnsbl,
			'default'       => '',
			'read_adapter'  => NULL,
			'write_adapter' => NULL,
			'since'         => '1.0.0',
		],

		// Python control integration. Default ''.
		'pfb_control' => [
			'section'       => $dnsbl,
			'default'       => '',
			'read_adapter'  => NULL,
			'write_adapter' => NULL,
			'since'         => '3.0.0',
		],

		// Legacy DNS-TXT control transport (deprecated). Default ''.
		'pfb_control_legacy' => [
			'section'       => $dnsbl,
			'default'       => '',
			'read_adapter'  => NULL,
			'write_adapter' => NULL,
			'since'         => '3.0.0',
		],

		// Python cache max (numeric string). Default '' (unlimited).
		'pfb_py_cache_max' => [
			'section'       => $dnsbl,
			'default'       => '',
			'read_adapter'  => NULL,
			'write_adapter' => NULL,
			'since'         => '3.0.0',
		],

		// TLD blocking enable. Default ''.
		'pfb_tld' => [
			'section'       => $dnsbl,
			'default'       => '',
			'read_adapter'  => NULL,
			'write_adapter' => NULL,
			'since'         => '1.0.0',
		],

		// Aliaslog (logging mode). Default ''.
		'aliaslog' => [
			'section'       => $dnsbl,
			'default'       => '',
			'read_adapter'  => NULL,
			'write_adapter' => NULL,
			'since'         => '1.0.0',
		],

		// ADR-36: NAT DNS-redirect enable: 'on' | '' (checkbox). Default '' (off).
		'dnsbl_redir' => [
			'section'       => $dnsbl,
			'default'       => '',
			'read_adapter'  => 'pfb_cfg_toggle_read',
			'write_adapter' => 'pfb_cfg_toggle_write',
			'since'         => '4.0.0',
		],

		// ADR-36: NAT DNS-redirect interface multi-select (comma-joined string). Default ''.
		'dnsbl_redir_int' => [
			'section'       => $dnsbl,
			'default'       => '',
			'read_adapter'  => NULL,
			'write_adapter' => NULL,
			'since'         => '4.0.0',
		],

		// ADR-36: NAT DNS-redirect exception alias/IP string. Default ''.
		'dnsbl_redir_exclude' => [
			'section'       => $dnsbl,
			'default'       => '',
			'read_adapter'  => NULL,
			'write_adapter' => NULL,
			'since'         => '4.0.0',
		],

		// ADR-37: DoT/DoQ block enable: 'on' | '' (checkbox). Default '' (off).
		'dnsbl_dot_block' => [
			'section'       => $dnsbl,
			'default'       => '',
			'read_adapter'  => 'pfb_cfg_toggle_read',
			'write_adapter' => 'pfb_cfg_toggle_write',
			'since'         => '4.0.0',
		],

		// ADR-37: DoT/DoQ block interface multi-select (comma-joined string). Default ''.
		'dnsbl_dot_block_int' => [
			'section'       => $dnsbl,
			'default'       => '',
			'read_adapter'  => NULL,
			'write_adapter' => NULL,
			'since'         => '4.0.0',
		],

		// ADR-37: DoT/DoQ block exception alias/IP string. Default ''.
		'dnsbl_dot_block_exclude' => [
			'section'       => $dnsbl,
			'default'       => '',
			'read_adapter'  => NULL,
			'write_adapter' => NULL,
			'since'         => '4.0.0',
		],

		// ADR-37: DoT/DoQ block rule action: 'reject' (default) | 'block'.
		// Mirrors the IP-settings inbound/outbound Rule Action selector. Reject
		// fast-fails the client (outbound LAN->WAN rule); block silently drops.
		'dnsbl_dot_block_action' => [
			'section'       => $dnsbl,
			'default'       => 'reject',
			'read_adapter'  => NULL,
			'write_adapter' => NULL,
			'since'         => '4.0.0',
		],

		// ADR-37: DoT/DoQ block floating mode: 'on' | '' (checkbox). Default '' (off).
		// On = a single floating rule (direction 'in') over the selected interfaces
		// instead of one rule per interface. Off preserves the per-interface default.
		'dnsbl_dot_block_floating' => [
			'section'       => $dnsbl,
			'default'       => '',
			'read_adapter'  => 'pfb_cfg_toggle_read',
			'write_adapter' => 'pfb_cfg_toggle_write',
			'since'         => '4.0.0',
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
			'since'         => '4.0.0',
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
			'since'         => '2.0.0',
		],

		// YouTube SafeSearch mode. Default 'Disable'.
		'safesearch_youtube' => [
			'section'       => $ss,
			'default'       => 'Disable',
			'read_adapter'  => NULL,
			'write_adapter' => NULL,
			'since'         => '2.0.0',
		],

		// DNS-over-HTTPS blocking mode. Default 'Disable'.
		'safesearch_doh' => [
			'section'       => $ss,
			'default'       => 'Disable',
			'read_adapter'  => NULL,
			'write_adapter' => NULL,
			'since'         => '2.0.0',
		],

		// DoH domain exclusion list (CSV). Default ''.
		'safesearch_doh_list' => [
			'section'       => $ss,
			'default'       => '',
			'read_adapter'  => NULL,
			'write_adapter' => NULL,
			'since'         => '2.0.0',
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
			'since'         => '1.0.0',
		],

		// ADR-53: IPv6 suppression customlist -- the v4 blob's v6 sibling
		// (same base64/newline-separated shape). Genuinely new (no pre-registry
		// era to inherit from v4suppression's), so 'since' is the current
		// development version rather than a legacy '1.0.0'. Default ''.
		'v6suppression' => [
			'section'       => $ip,
			'default'       => '',
			'read_adapter'  => NULL,
			'write_adapter' => NULL,
			'since'         => '4.0.0',
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
	 * Consequence: the RollbackContract "never re-emitted" legacy-token
	 * guarantee (see class docblock / ADR-29 §2.3) now holds on section
	 * writes too — a legacy token riding a readSection()->writeSection()
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
	 * @return array{section:string,default:string,read_adapter:callable|null,write_adapter:callable|null,since:string}
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
// ADR-29 §2.3 — Rollback / backward-compat contract. pfb_cfg_field_vocab() documents the
// FULL STORED VOCABULARY per field adapter; RollbackContractTest.php asserts the FORWARD
// invariant (every legacy token yields a sane runtime value) and the BACKWARD invariant
// (every write emits ONLY a legacy-vocabulary token, never a novel on-disk one — a write may
// normalise to a behaviour-equivalent canonical token, e.g. pfb_idn All persisting 'on').
// SINCE-VERSION: 'since' records the release that introduced the key; pre-registry keys use
// the earliest release still shipping that key's line (no config-version migration exists).
// ---------------------------------------------------------------------------

/**
 * pfb_cfg_field_vocab — the legacy stored vocabulary for each adapter type.
 *
 * Returns a map of adapter-type label => array of ALL strings a pre-ADR-29
 * release might have persisted for a field of that type.  Tests iterate over
 * each registered field's adapter to select the matching vocabulary, then
 * assert:
 *
 *   FORWARD: read_adapter($stored) does not crash and returns a well-formed
 *            runtime value for EVERY token in the vocabulary.
 *   BACKWARD: write_adapter(read_adapter($stored)) ∈ vocabulary for every
 *             canonical stored token (i.e. the gateway never emits a novel
 *             on-disk string an older release would not recognise).
 *
 * Adapter types:
 *   'toggle'  — PfbToggle fields: 'on' | '' (checked/unchecked checkbox).
 *   'lenient' — PfbLenient fields: 'on' | 'off' | '' ('' = pre-ADR-22 absent).
 *   'plain'   — null/null adapters: any string; identity through (no novel token).
 *
 * The idn-mode adapter (pfb_cfg_idn_mode_read/write) IS wired at PfbConfig level
 * for pfb_idn. All canonicalises to the legacy 'on' token, so writes only emit the
 * idn vocabulary ('on'|'confusable'|'off'); the dropped 4.0.0-alpha 'all' token is
 * read as Off and never written.
 *
 * The top1m_source adapter (pfb_cfg_top1m_source_read/write, issue #877) is wired
 * for alexa_type and returns a PfbTop1mSource enum. Legacy 'alexa' (dead service,
 * #872) coalesces to Tranco on read, and legacy 'domcop' (list moved hosting,
 * #928) coalesces to OpenPageRank on read; neither is ever re-emitted by a write.
 * The write vocabulary is 'tranco'|'cisco'|'openpagerank'|'majestic'|'cloudflare'
 * (majestic added ADR-59, cloudflare added ADR-59; openpagerank replaced
 * ADR-59's domcop in #928).
 *
 * @return array<string,list<string>>
 */
function pfb_cfg_field_vocab(): array
{
	return [
		// Toggle checkbox: 'on' (enabled) | '' (disabled / absent). No novel tokens.
		'toggle'  => ['on', ''],

		// Lenient flag: 'on' (enabled) | 'off' (disabled) | '' (pre-ADR-22 absent).
		// '' is a legacy stored value that maps to Off on read; write emits 'off'.
		// 'off' is a legacy token (predates ADR-22 — the migration only runs when
		// the key is entirely absent, not when it is 'off'). Backward-safe: any
		// older release that reads 'off' treats it as "disabled", which is correct.
		'lenient' => ['on', 'off', ''],

		// IDN mode (PfbIdnMode): the tokens a write can emit. 'on' = All (reuses the
		// pre-4.0.0 block-all token, so it round-trips and an older release still blocks
		// all IDN), 'confusable', 'off'. Legacy reads '' / 'all' (4.0.0-alpha) -> Off, but
		// neither is ever WRITTEN, so they are not in the backward (write) vocabulary.
		'idn'     => ['on', 'confusable', 'off'],

		// Alias-table apply mode (PfbAliasDeltaMode, ADR-40): tokens a write can emit.
		// 'auto' (default), 'delta', 'replace'. Unknown tokens read as 'auto' (default()).
		// An older release (pre-4.0.0) has no knowledge of these fields; they simply
		// do not exist in config.xml, and the feature falls back to full replace.
		'alias_delta_mode' => ['auto', 'delta', 'replace'],

		// TOP1M source selector (PfbTop1mSource, issue #877): the tokens a write can
		// emit. 'tranco' (default) | 'cisco' | 'openpagerank' | 'majestic' | 'cloudflare'
		// (majestic added ADR-59, cloudflare added ADR-59; openpagerank
		// replaced ADR-59's domcop in #928). Two
		// tokens are READ-ONLY legacy values — 'alexa' (dead service, #872) and
		// 'domcop' (list moved hosting, #928) — pfb_cfg_top1m_source_read() coalesces
		// them to PfbTop1mSource::Tranco / ::OpenPageRank respectively and neither is
		// ever re-emitted by a write.
		'top1m_source' => ['tranco', 'cisco', 'openpagerank', 'majestic', 'cloudflare'],

		// Plain string (null/null adapters): identity. Backward-safe by construction.
		// The 'plain' vocabulary contains the sentinel empty string; individual
		// field values are arbitrary strings (numeric, named option, etc.) but the
		// contract only requires that no novel token is INTRODUCED by the adapter.
		'plain'   => [''],
	];
}

/**
 * pfb_cfg_field_adapter_type — return the adapter type label for a registry entry.
 *
 * Returns 'toggle', 'lenient', or 'plain' — matching the keys in pfb_cfg_field_vocab().
 * Used by RollbackContractTest to look up the vocabulary for each registered field.
 *
 * @param  array $entry  A registry entry from pfb_cfg_registry().
 * @return string        Adapter type label.
 */
function pfb_cfg_field_adapter_type(array $entry): string
{
	$read = $entry['read_adapter'];
	if ($read === NULL) {
		return 'plain';
	}
	if ($read === 'pfb_cfg_lenient_read') {
		return 'lenient';
	}
	if ($read === 'pfb_cfg_idn_mode_read') {
		return 'idn';
	}
	if ($read === 'pfb_cfg_alias_delta_mode_read') {
		return 'alias_delta_mode';
	}
	if ($read === 'pfb_cfg_top1m_source_read') {
		return 'top1m_source';
	}
	// All other adapters are toggle (pfb_cfg_toggle_read).
	return 'toggle';
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

	// Production path: openlog / syslog / closelog via PHP built-ins.
	// Test spy path: record the call in $GLOBALS['pfb_test_syslog_calls'] when a
	// spy is installed (never calls the real built-ins in test mode).
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
 * Reads the ledger, dispatches each job that is due (feeds, dcc, bl) via exec() as a
 * separate process, then marks each as ran. ss_refresh runs every tick; the scheduled
 * log maintenance (pfb_log_mgmt) runs only on an idle tick (see below).
 *
 * Lives here (not in the www/ dispatcher script) rather than the reverse so the
 * PHPUnit bootstrap can load and call the real entrypoint off-appliance: the www
 * script is never require()'d by the test suite, so before this move the tick had
 * zero off-box coverage (review finding ADR43-5). The www dispatch
 * (`pfblockerng.php tick`) still just calls this function.
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
 *   feed cron : PfbConfig::read('pfb_interval') hours; skip when 'Disabled'.
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

	// Feed cron: dispatch the `cron` verb (-> pfblockerng_sync_cron), NOT pfb_trigger
	// directly.  pfblockerng_sync_cron applies each feed's per-list Update Frequency
	// ($list['cron']: EveryDay/Weekly/NNhour) before its final sync_package_pfblockerng('cron'),
	// and runs the ADR-19 software-update check at the end -- both of which a bare
	// `pfb_trigger scope=both` skips (it would poll every feed every tick and never
	// run the once-per-pass update check). Apply-on-change still happens via ADR-40
	// (IP) + ADR-10 (DNSBL) inside that final sync. Backgrounded so the tick stays
	// fast. The scheduled log trim no longer rides this dispatch (issue #573) --
	// see pfb_log_mgmt() at the end of this function.
	if (!$cron_disabled && ($due['cron'] || pfb_due_ledger_is_pending('cron', $dbdir))) {
		if ($in_win) {
			logger(LOG_NOTICE, localize_text('Tick: dispatching feed cron.'), LOG_PREFIX_PKG_PFBLOCKERNG);
			exec("/usr/local/bin/php /usr/local/www/pfblockerng/pfblockerng.php cron >> {$pfb['runlog']} 2>&1 &");
			pfb_due_ledger_mark_ran_anchored('cron', $cron_secs, $now, $seed, 0, $dbdir);
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
			exec("/usr/local/bin/php /usr/local/www/pfblockerng/pfblockerng.php dcc >> {$pfb['extraslog']} 2>&1 &");
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
				exec("/usr/local/bin/php /usr/local/www/pfblockerng/pfblockerng.php bl " . escapeshellarg($bl_str) . " >> {$pfb['extraslog']} 2>&1 &");
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
 * @param  string $line   One raw textarea line (as split on "\r\n"), untrimmed.
 * @param  string $family 'ipv4' or 'ipv6'.
 * @return string|null    NULL when the line is valid (or a comment/blank no-op);
 *                         otherwise the input_errors message for this line.
 */
function pfb_validate_suppression_line(string $line, string $family): ?string
{
	if (str_starts_with($line, '#') || trim($line) === '') {
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
		// Strip a trailing inline '#' comment, same as pfbng_text_area_decode().
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
 * $table_entries are raw lines from the table's membership snapshot (the
 * ADR-40 mirror file, or a `pfctl -T show` fallback) -- bare host tokens
 * ("1.2.3.4") or CIDR tokens ("1.2.3.0/24"), either family; blank/'#'-comment
 * lines are tolerated (skipped). A bare host token is treated as an exact
 * /32 or /128 -- containing ONLY itself, so punching it needs no
 * covering-CIDR add (delete only, same as the old exact-/32-match case).
 *
 * PURE -- no pfctl/pf-table access; the caller supplies the already-read
 * membership snapshot (streamed, never slurped whole -- see the alerts page
 * call site) and applies the returned plan.
 *
 * @param  string   $ip             The host to carve out (v4 or v6).
 * @param  string[] $table_entries  Raw table membership lines.
 * @return array{delete: string[], add: string[]} 'delete' = every containing
 *         entry to remove; 'add' = the covering-CIDR remainder to re-add
 *         (empty when every containing entry was an exact host match).
 */
function pfb_live_punch_plan(string $ip, array $table_entries): array
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

	return ['delete' => $delete, 'add' => $add];
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
