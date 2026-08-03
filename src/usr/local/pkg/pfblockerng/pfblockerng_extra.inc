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
// ADR-28 — config field enums (PfbStoredEnum contract): adapter fields use the
// registered default only for an absent key; present empty, legacy, and junk tokens are
// parsed by the enum. Writes use $enum->toStored(), with Off represented by '' on disk.
// Tests: tests/php/CfgAdaptersTest.php.
// ---------------------------------------------------------------------------

// PfbStoredEnum — the contract every config-backed enum implements. Reads own raw-token
// fallback; field-aware gateway writes own empty Off storage and absence deletion.
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
		return $this->value === 'off' ? '' : $this->value;
	}
}

// PfbToggle — the single on/off enum for every checkbox field. The enum keeps 'off' as
// its runtime/backing value while PfbStoredEnumAdapter::toStored() emits '' on disk;
// absent adapter keys alone use the field's registered default.
enum PfbToggle: string implements PfbStoredEnum
{
	use PfbStoredEnumAdapter;

	case On  = 'on';
	case Off = 'off';

	/**
	 * Recognise either token in ANY case before giving up (issue #1887).
	 *
	 * Writes emit canonical 'on'/empty storage, so this only affects legacy or foreign
	 * input: a hand-edited config.xml, a restored backup, an
	 * HA sync, another tool touching installedpackages/*. Without it, 'On' or 'OFF' fell
	 * past tryFrom() into the Off fallback and silently disabled a feature for an
	 * operator who spelled it the obvious way, with nothing logged.
	 *
	 * Deliberately narrow: only a case variant of the recognised 'on'/'off' read tokens is accepted.
	 * 'yes', 'true' and '1' remain junk and still fall back to Off, so a typo cannot
	 * enable something. Pinned in both directions by ToggleCaseInsensitiveTest.
	 */
	protected static function fromLegacy(string $raw): static
	{
		return self::tryFrom(strtolower($raw)) ?? self::default();
	}

	// Parse-fallback ONLY (empty/unknown/non-scalar -> "not On"). NOT the absent default:
	// the gateway substitutes the registry default only for NULL and passes present empty here.
	public static function default(): static
	{
		return self::Off;
	}
}

// PfbIdnMode — ADR-08 IDN-feature mode selector, adopted into the PfbConfig gateway.
// Used by pfb_idn / $pfb['dnsbl_idn']. Canonical tokens (config.xml, py_unbound.ini, and
// the Python IdnMode enum share one vocabulary): 'on' (=All), 'confusable', with '' as
// stored Off; legacy 'off' and unknown values also parse as Off. Reusing 'on' for All keeps existing installs migration-free and
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
// grandfathered to 'replace' by the registry pass at install/upgrade (issue #1921).
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

// PfbTop1mSource — TOP1M source selector (top1m_source, issue #877).
// Used by top1m_source (config key) / $pfb['dnsbl_top1m_type'] (runtime). Canonical tokens:
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

/**
 * Whether the Advanced Text Editor (CodeMirror 6) is enabled — issue #1887.
 *
 * A named accessor rather than the comparison spelled out at each call site: it was
 * written identically on five pages (General, DNSBL, IP, Category Edit, Edit Hooks),
 * and each copy had to name the config key, know the stored vocabulary and get the
 * enum comparison right. Here the caller asks the question and gets a bool; the key,
 * the registered default and the stored token stay behind the gateway.
 *
 * Reading a toggle is not a privileged operation, so this belongs in the shared file
 * (contrast the write side — see issue #1895).
 */
function pfb_editor_enabled(): bool
{
	return PfbConfig::read('gen/pfb_syntax_highlight') === PfbToggle::On;
}

function pfb_dnsbl_toggle_enabled(mixed $stored): bool
{
	return pfb_cfg_toggle_read($stored) === PfbToggle::On;
}

function pfb_ip_suppression_enabled(mixed $stored): bool
{
	return pfb_cfg_toggle_read($stored) === PfbToggle::On;
}

/** Keep list-editor mounting independent from the row-reorder mode. */
function pfb_editor_mount_lists_for_sort(array $fields, string $sort, bool $enabled): string
{
	return pfb_editor_mount_lists($fields, $enabled);
}

/** Label and help rendered for the General-page editor toggle. */
function pfb_editor_toggle_label(): string
{
	return 'Advanced Text Editor';
}

function pfb_editor_toggle_help(): string
{
	return 'Client-side editor for the list and script fields (e.g. the DNSBL Regex '
		. 'List, custom lists, IP suppression lists, hook scripts): syntax highlighting, '
		. 'line numbers and undo/redo everywhere, plus inline linting on the DNSBL Regex '
		. 'List and hook scripts. Unchecking this leaves those fields as plain text boxes '
		. 'and skips loading the editor assets &mdash; useful for low-end client machines. '
		. 'Validation always stays server-side either way.';
}

/** Render one CodeMirror asset tag when the Advanced Text Editor is enabled. */
function pfb_editor_asset(string $asset, bool $enabled): string
{
	if (!$enabled) {
		return '';
	}

	$asset = basename($asset);
	return '<script src="vendor/codemirror/' . htmlspecialchars($asset, ENT_QUOTES, 'UTF-8')
		. '?v=' . pfb_file_mtime('/usr/local/www/pfblockerng/vendor/codemirror/' . $asset)
		. '"></script>';
}

/** Render the shared plain-list CodeMirror mount call. */
function pfb_editor_mount_lists(array $fields, bool $enabled): string
{
	if (!$enabled) {
		return '';
	}

	$fields = array_values(array_map('strval', $fields));
	return "if (window.pfbCM) {\n\twindow.pfbCM.mountLists(" . json_encode($fields, JSON_THROW_ON_ERROR) . ");\n}";
}

/** Render the DNSBL regex-list CodeMirror mount, including live lint options. */
function pfb_editor_mount_regex(bool $enabled): string
{
	if (!$enabled) {
		return '';
	}

	return <<<'JS'
var pfbRegexListEl = document.getElementById('pfb_regex_list');
if (pfbRegexListEl && window.pfbCM) {
	window.pfbCM.fromTextarea(pfbRegexListEl, {
		lintUrl: '/pfblockerng/pfblockerng_lint.php',
		lintExtraParams: function() {
			var capEl = document.getElementById('pfb_regex_cap');
			return { cap: (capEl && capEl.checked) ? '1' : '0' };
		}
	});
}
JS;
}

/** Render the hook editor mount using the server-selected language. */
function pfb_editor_mount_hook(bool $enabled, string $language): string
{
	if (!$enabled) {
		return '';
	}

	$language = json_encode($language, JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT | JSON_THROW_ON_ERROR);
	return "var pfbHookEditorEl = document.getElementById('pfb_hook_editor_content');\n"
		. "if (pfbHookEditorEl && window.pfbHooksCM) {\n"
		. "\twindow.pfbHooksCM.fromTextarea(pfbHookEditorEl, {$language}, {\n"
		. "\t\tlintUrl: '/pfblockerng/pfblockerng_lint.php'\n"
		. "\t});\n"
		. "}";
}

/** Render a shipped JavaScript asset URL with the package mtime cache-buster. */
function pfb_js_asset(string $src, string $path, string $attributes = ''): string
{
	return '<script src="' . htmlspecialchars($src, ENT_QUOTES, 'UTF-8')
		. '?v=' . pfb_file_mtime($path) . '"' . $attributes . '></script>';
}

/** The DNSBL regex-list help shown by the Form_Textarea field. */
function pfb_dnsbl_regex_help_text(): string
{
	return 'List of Regex\'s to block via DNSBL:<br /><br />
		Enter a single regex per line.<br /><br />
		End a line with "<strong>#</strong>" to give it a Description, as in&emsp;"regex (Regular Expression) # Regex Description".<br /><br />
		The first <strong>unescaped</strong> "#" on the line starts the Description, whether or not a space precedes it. To match a literal "#" inside a pattern, escape it as "<strong>\\#</strong>".<br /><br />
		Keep the Description to 15 characters or fewer — it is shown on the Alerts Tab, and a longer one is flagged in this editor. If no Description is entered a default Regex line number will be utilized.<br /><br />
		This List is stored as \'Base64\' format in the config.xml file.<br /><br />
		Changes to this option will require a Force Update to take effect.';
}

/** Whether regex validation must run for a save request. */
function pfb_dnsbl_regex_validation_required(bool $interpreterUsable, mixed $featureToggle): bool
{
	return $interpreterUsable || $featureToggle === 'on';
}

/** Render the category editor pre-script help and select size for the current feed type. */
function pfb_category_script_pre_settings(string $listPrefix, array $options): array
{
	$help = 'Pre-processing Shell script, run after download and charset normalization: '
		. 'it receives a staged copy of the normalized feed text (UTF-8, control characters stripped, '
		. 'lines right-trimmed) and rewrites that copy in place.<br />'
		. 'Script location: /usr/local/pkg/pfblockerng/list_scripts/<strong>ip_pre_SCRIPT NAME.sh|py</strong> or <strong>dnsbl_pre_SCRIPT NAME.sh|py</strong>';
	if ($listPrefix === 'dnsbl') {
		$help .= '<br /><span class="text-danger">Note:</span>&nbsp;'
			. 'A DNSBL pre-process script must not remove IP-shaped or ABP-shaped lines: the '
			. 'DNSBLIP alias is synthesized from addresses extracted out of domain feeds, and '
			. 'removed lines silently shrink it.';
	}

	return [
		'help' => $help,
		'size' => count($options) ?: '1',
	];
}

/** Render the stable anchor/section layout shared by DNSBL, IP, widget, and log pages. */
function pfb_page_anchor_layout(string $page): array
{
	return match ($page) {
		'dnsbl' => [
			'legacy_rows' => [],
			'whitelist' => 'DNSBL_Whitelist_customlist',
		],
		'ip' => [
			'legacy_rows' => [],
			'suppression' => 'IPv4_Suppression_customlist',
		],
		'log' => [
			'legacy_rows' => [],
			'endofpage' => '<div id="endofpage"></div>',
			'outside_form' => TRUE,
		],
		default => throw new InvalidArgumentException("unknown anchor layout: {$page}"),
	};
}

// Page-specific render seams.  Pages keep their request handling and markup here,
// while these small callables let the same shipped wiring be exercised without loading
// a full pfSense request off-appliance.
function pfb_dnsbl_editor_render(bool $enabled): array
{
	return [
		'asset' => pfb_editor_asset('cm-regex.min.js', $enabled),
		'regex' => pfb_editor_mount_regex($enabled),
		'lists' => pfb_editor_mount_lists(['pfb_gp_bypass_list', 'pfb_noaaaa_list', 'whitelist', 'tld_wildcard_exclusion', 'tld_wildcard_blacklist'], $enabled),
	];
}

function pfb_dnsbl_regex_help_render(): string
{
	return pfb_dnsbl_regex_help_text();
}

function pfb_dnsbl_regex_validation_required_page(bool $interpreterUsable, mixed $featureToggle): bool
{
	return pfb_dnsbl_regex_validation_required($interpreterUsable, $featureToggle);
}

function pfb_dnsbl_anchor_layout_render(): array
{
	return pfb_page_anchor_layout('dnsbl');
}

function pfb_dnsbl_js_asset_render(string $path = '/usr/local/www/pfblockerng/pfBlockerNG.js'): string
{
	return pfb_js_asset('pfBlockerNG.js', $path, ' type="text/javascript"');
}

function pfb_ip_editor_render(bool $enabled): array
{
	return [
		'asset' => pfb_editor_asset('cm-regex.min.js', $enabled),
		'lists' => pfb_editor_mount_lists(['v4suppression', 'v6suppression'], $enabled),
	];
}

function pfb_ip_anchor_layout_render(): array
{
	return pfb_page_anchor_layout('ip');
}

function pfb_ip_js_asset_render(string $path = '/usr/local/www/pfblockerng/pfBlockerNG.js'): string
{
	return pfb_js_asset('pfBlockerNG.js', $path, ' type="text/javascript"');
}

function pfb_general_editor_render(bool $enabled): array
{
	return [
		'asset' => pfb_editor_asset('cm-regex.min.js', $enabled),
		'lists' => pfb_editor_mount_lists(['pfb_feed_internal_allowlist'], $enabled),
	];
}

function pfb_general_toggle_label(): string
{
	return pfb_editor_toggle_label();
}

function pfb_general_toggle_help(): string
{
	return pfb_editor_toggle_help();
}

function pfb_category_editor_render(bool $enabled, string $sort): array
{
	return [
		'asset' => pfb_editor_asset('cm-regex.min.js', $enabled),
		'mount' => pfb_editor_mount_lists_for_sort(['custom'], $sort, $enabled),
	];
}

function pfb_category_script_pre_render(string $listPrefix, array $options): array
{
	return pfb_category_script_pre_settings($listPrefix, $options);
}

function pfb_category_edit_js_asset_render(string $path = '/usr/local/www/pfblockerng/pfBlockerNG.js'): string
{
	return pfb_js_asset('pfBlockerNG.js', $path, ' type="text/javascript"');
}

function pfb_hooks_editor_render(bool $enabled, string $language): array
{
	return [
		'asset' => pfb_editor_asset('cm-hooks.min.js', $enabled),
		'mount' => pfb_editor_mount_hook($enabled, $language),
	];
}

function pfb_category_js_asset_render(string $path = '/usr/local/www/pfblockerng/pfBlockerNG.js'): string
{
	return pfb_js_asset('pfBlockerNG.js', $path, ' type="text/javascript"');
}

function pfb_geoip_js_asset_render(string $path = '/usr/local/www/pfblockerng/pfBlockerNG.js'): string
{
	return pfb_js_asset('pfBlockerNG.js', $path, ' type="text/javascript"');
}

function pfb_log_anchor_layout_render(): array
{
	return pfb_page_anchor_layout('log');
}

function pfb_widget_anchor_layout_render(string $page): array
{
	return pfb_page_anchor_layout($page);
}

/** Read a PfbToggle from a raw stored value. */
function pfb_cfg_toggle_read(mixed $stored): PfbToggle
{
	return PfbToggle::fromStored($stored);
}

/** Write a PfbToggle (enum or legacy string) back to its stored string. */
function pfb_cfg_toggle_write(PfbToggle|string $toggle): string
{
	$toggle = $toggle instanceof PfbToggle ? $toggle : PfbToggle::fromStored($toggle);
	return $toggle->toStored();
}

/** Read a PfbIdnMode from a raw stored value (legacy 'on' -> All). */
function pfb_cfg_idn_mode_read(mixed $stored): PfbIdnMode
{
	return PfbIdnMode::fromStored($stored);
}

/**
 * Write a PfbIdnMode (enum or legacy string) back to its canonical stored token
 * ('on' | 'confusable' | ''). All persists as its recognised 'on' token (preserving
 * the prior block-all-IDN behaviour); the 4.0.0-alpha 'all' token falls back to Off.
 */
function pfb_cfg_idn_mode_write(PfbIdnMode|string $mode): string
{
	$mode = $mode instanceof PfbIdnMode ? $mode : PfbIdnMode::fromStored($mode);
	return $mode->toStored();
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
// CONSTRAINTS (ADR-29 §5, ADR-28 §2.2 + 2026-07-20 amendments): registry keys carry the
// current domain vocabulary; a key rename ships with a one-time post-install migration
// (issue #1898). Adapters accept supported forward-upgrade legacy tokens and write the
// current canonical string; write(read(v)) == v for every canonical value.
// Tests: tests/php/CfgGatewayTest.php (round-trip, default, inventory).
// ---------------------------------------------------------------------------

// issue #1931: the one greppable home of every real config.xml section path. Registry
// keys below are '<alias>/<bare-key>'; PfbConfig resolves the alias through this map.
const PFB_SECTIONS = [
	'gen'   => 'installedpackages/pfblockerng/config/0',
	'dnsbl' => 'installedpackages/pfblockerngdnsblsettings/config/0',
	'ss'    => 'installedpackages/pfblockerngsafesearch',
	'ip'    => 'installedpackages/pfblockerngipsettings/config/0',
	'rep'   => 'installedpackages/pfblockerngreputation/config/0',
];

// issue #1921: dedicated map key standing for "key genuinely absent" inside a
// 'grandfather' map below -- a PHP array literal coerces a NULL key to '', so absence
// cannot be a map key on its own; NUL can never appear in a stored config scalar, so
// this sentinel is unambiguous wherever it appears as a map key.
const PFB_GF_ABSENT = "\0absent";

/**
 * pfb_cfg_registry — the declarative field registry for all registered
 * installedpackages/pfblockerng* scalar keys.
 *
 * Returns a flat map of path-key => descriptor. A path key is '<alias>/<bare-key>',
 * where <alias> indexes PFB_SECTIONS for the real config.xml section path and
 * <bare-key> is the exact field name used in config.xml.
 *
 * Read adapter: callable(mixed $stored): <enum|string>  — stored string -> runtime value.
 * Write adapter: callable(<enum|string> $value): string — runtime value -> stored string.
 * null adapter = plain string (identity; no conversion).
 *
 * Optional 'write_priv': overrides PfbConfig::WRITE_PRIV_DEFAULT for this field's
 * write-authorization check (issue #1895). Absent for every entry except
 * 'gen/pfb_software_check' (the #485 Software-page secondary gate).
 *
 * issue #1921 — grandfathering decisions, carried as declarative slots (data only in
 * this step; the install/upgrade pass that consumes them is a later step):
 * Optional 'old_name': the retired pre-#1898 spelling this key's value migrates from
 * (PFB_LEGACY_KEY_RENAMES). Orthogonal to grandfather/no_grandfather -- a key can carry
 * both.
 * Optional 'grandfather': map raw-stored-value => new-value, applied ONCE by the
 * (upcoming) registry pass at install/upgrade. The PFB_GF_ABSENT key covers genuine
 * absence; every other map key is a literal stored value ('' included). An unmapped
 * stored value passes through unchanged.
 * Optional 'no_grandfather': the recorded reason issue #1920 found no grandfather is
 * needed for this key -- the config-gateway.md "did the behaviour this field controls
 * change for someone upgrading?" trigger question, answered no.
 * Every entry carries exactly one of {'grandfather', 'no_grandfather'}, except the two
 * keys CfgRegistryGrandfatherGateTest::EXCEPTIONS documents (a mode instrument and a
 * cross-key bespoke seed), which carry neither.
 *
 * @return array<string,array{default:string,read_adapter:callable|null,write_adapter:callable|null,write_priv?:string,old_name?:string,grandfather?:array<string,string>,no_grandfather?:string}>
 */
function pfb_cfg_registry(): array
{
	static $registry = NULL;
	if ($registry !== NULL) {
		return $registry;
	}

	$registry = [

		// -------------------------------------------------------------------
		// General section (pfblockerng/config/0)
		// -------------------------------------------------------------------

		// Settings snapshot schema marker. Missing installs are the legacy 3.2 family.
		'gen/settings_family' => [
			'default'       => '3.2',
			'read_adapter'  => NULL,
			'write_adapter' => NULL,
		],

		// Master enable/disable: 'on' | '' (checkbox).
		'gen/enable_cb' => [
			'default'       => '',
			'read_adapter'  => 'pfb_cfg_toggle_read',
			'write_adapter' => 'pfb_cfg_toggle_write',
			'no_grandfather' => 'v3.2.16 absent-key fallback equals current default',
		],

		// Keep blocklists when pfBlockerNG is disabled: 'on' | ''.
		// Default ON — the #281 canonical default; GUI and pfb_global() agree.
		// A present empty unchecked-save is Off; only a never-configured (absent)
		// key uses the registered default On.
		'gen/pfb_keep' => [
			'default'       => 'on',
			'read_adapter'  => 'pfb_cfg_toggle_read',
			'write_adapter' => 'pfb_cfg_toggle_write',
			'grandfather'   => [PFB_GF_ABSENT => 'on'],
		],

		// Update interval: numeric hour string | 'Disabled'. Default '1'.
		'gen/pfb_interval' => [
			'default'       => '1',
			'read_adapter'  => NULL,
			'write_adapter' => NULL,
			'no_grandfather' => 'v3.2.16 absent-key fallback equals current default',
		],

		// Cron start minute ('0'|'15'|'30'|'45'). Default '0'.
		'gen/pfb_min' => [
			'default'       => '0',
			'read_adapter'  => NULL,
			'write_adapter' => NULL,
			'no_grandfather' => 'v3.2.16 absent-key fallback equals current default',
		],

		// Cron start hour (0-23 as string). Default '0'.
		'gen/pfb_hour' => [
			'default'       => '0',
			'read_adapter'  => NULL,
			'write_adapter' => NULL,
			'no_grandfather' => 'v3.2.16 absent-key fallback equals current default',
		],

		// Once-a-day start hour (0-23 as string). Default '0'.
		'gen/pfb_dailystart' => [
			'default'       => '0',
			'read_adapter'  => NULL,
			'write_adapter' => NULL,
			'no_grandfather' => 'v3.2.16 absent-key fallback equals current default',
		],

		// Max daily download failure threshold ('0' = unlimited). Default '0'.
		'gen/skipfeed' => [
			'default'       => '0',
			'read_adapter'  => NULL,
			'write_adapter' => NULL,
			'no_grandfather' => 'v3.2.16 absent-key fallback equals current default',
		],

		// ADR-11: CSV of active aggregate alias types (e.g. 'Deny,Permit'). Default ''.
		'gen/pfb_agg_types' => [
			'default'       => '',
			'read_adapter'  => NULL,
			'write_adapter' => NULL,
			'no_grandfather' => 'ADR-11 opt-in aggregate aliases; new 4.0 field, \'\' = feature off = pre-4.0 behaviour',
		],

		// Log rotation limits (all numeric strings; default '20000').
		'gen/log_max_log' => [
			'default'       => '20000',
			'read_adapter'  => NULL,
			'write_adapter' => NULL,
			'no_grandfather' => 'v3.2.16 absent-key fallback equals current default',
		],
		'gen/log_max_errlog' => [
			'default'       => '20000',
			'read_adapter'  => NULL,
			'write_adapter' => NULL,
			'no_grandfather' => 'v3.2.16 absent-key fallback equals current default',
		],
		'gen/log_max_extraslog' => [
			'default'       => '20000',
			'read_adapter'  => NULL,
			'write_adapter' => NULL,
			'no_grandfather' => 'v3.2.16 absent-key fallback equals current default',
		],
		'gen/log_max_ip_blocklog' => [
			'default'       => '20000',
			'read_adapter'  => NULL,
			'write_adapter' => NULL,
			'no_grandfather' => 'v3.2.16 absent-key fallback equals current default',
		],
		'gen/log_max_ip_permitlog' => [
			'default'       => '20000',
			'read_adapter'  => NULL,
			'write_adapter' => NULL,
			'no_grandfather' => 'v3.2.16 absent-key fallback equals current default',
		],
		'gen/log_max_ip_matchlog' => [
			'default'       => '20000',
			'read_adapter'  => NULL,
			'write_adapter' => NULL,
			'no_grandfather' => 'v3.2.16 absent-key fallback equals current default',
		],
		'gen/log_max_ip_parse_err' => [
			'default'       => '20000',
			'read_adapter'  => NULL,
			'write_adapter' => NULL,
			'no_grandfather' => '#1004 new 4.0 log sink; no pre-4.0 counterpart, default matches siblings',
		],
		'gen/log_max_dnslog' => [
			'default'       => '20000',
			'read_adapter'  => NULL,
			'write_adapter' => NULL,
			'no_grandfather' => 'v3.2.16 absent-key fallback equals current default',
		],
		'gen/log_max_dnsbl_parse_err' => [
			'default'       => '20000',
			'read_adapter'  => NULL,
			'write_adapter' => NULL,
			'no_grandfather' => 'v3.2.16 absent-key fallback equals current default',
		],
		'gen/log_max_dnsreplylog' => [
			'default'       => '20000',
			'read_adapter'  => NULL,
			'write_adapter' => NULL,
			'no_grandfather' => 'v3.2.16 absent-key fallback equals current default',
		],
		'gen/log_max_unilog' => [
			'default'       => '20000',
			'read_adapter'  => NULL,
			'write_adapter' => NULL,
			'no_grandfather' => 'v3.2.16 absent-key fallback equals current default',
		],
	];

	$log_types = [
		'log', 'errlog', 'extraslog', 'ip_blocklog', 'ip_permitlog',
		'ip_matchlog', 'ip_parse_err', 'dnslog', 'dnsbl_parse_err', 'dnsreplylog', 'unilog',
	];

	// ADR-60: per-log age-based retention cap (days; '0' = off), independent of
	// log_max_<type>'s line-count cap and its 'nolimit' opt-out (S2.2/S2.3 item 3).
	foreach ($log_types as $log_type) {
		$registry['gen/log_max_days_' . $log_type] = [
			'default'        => '0',
			'read_adapter'   => NULL,
			'write_adapter'  => NULL,
			'no_grandfather' => 'ADR-60 age cap; new 4.0 field, \'0\' = off = pre-ADR-60 behaviour',
		];
	}

	$registry = $registry + [

		// issue #1109: log-retention trim hysteresis margin percent (global,
		// applies uniformly to both the line-count and age caps). Default '0'.
		'gen/pfb_log_trim_margin_pct' => [
			'default'       => '0',
			'read_adapter'  => NULL,
			'write_adapter' => NULL,
			'no_grandfather' => '#1109 hysteresis margin; new 4.0 field, \'0\' = exact trim = prior behaviour',
		],

		// Software update check last-seen version (string or null). Default ''.
		// issue #1887: toggle adapter adopted, and the effective ON default moves from
		// the hand-written reader (`!== 'off'`) into the registry where every other
		// toggle keeps its default. Absent behaves exactly as before (enabled).
		'gen/pfb_software_check' => [
			'default'       => 'on',
			'read_adapter'  => 'pfb_cfg_toggle_read',
			'write_adapter' => 'pfb_cfg_toggle_write',
			// issue #1895: the #485 Software-page secondary gate -- this field's write
			// authorization is 'pkg_mgr_installed.php', not the package's own general page.
			'write_priv'    => 'pkg_mgr_installed.php',
			'no_grandfather' => 'ADR-19 Software page capability; #1887 relocated the pre-existing ON default into the registry, absent unchanged',
		],

		// Internal-address feed-host filter toggle: 'on'|''. Default 'on'.
		// A present empty token is explicit Off; absent uses the registered default.
		'gen/pfb_feed_internal_filter' => [
			'default'       => 'on',
			'read_adapter'  => 'pfb_cfg_toggle_read',
			'write_adapter' => 'pfb_cfg_toggle_write',
			'no_grandfather' => 'legacy absent state now matches the registered default',
		],

		// Allowlist for internal-feed hosts (base64-encoded). Default ''.
		'gen/pfb_feed_internal_allowlist' => [
			'default'       => '',
			'read_adapter'  => NULL,
			'write_adapter' => NULL,
			'no_grandfather' => '#1770 companion; \'\' = no exemptions, no pre-4.0 behaviour',
		],

		// ADR-49: opt-in plain-text feed sanity scan. Checkbox 'on'|''(off).
		// Default off (absent = off = today's behaviour: the scan never runs).
		'gen/pfb_feed_sanity' => [
			'default'       => '',                       // absent -> Off (new-install default too)
			'read_adapter'  => 'pfb_cfg_toggle_read',
			'write_adapter' => 'pfb_cfg_toggle_write',
			'no_grandfather' => 'ADR-49 opt-in sanity scan; new 4.0 field, \'\' = off = prior behaviour',
		],

		// Reuse blocklists across updates: 'on' | '' (checkbox). Default ''.
		'gen/pfb_reuse' => [
			'default'       => '',
			'read_adapter'  => 'pfb_cfg_toggle_read',
			'write_adapter' => 'pfb_cfg_toggle_write',
			'no_grandfather' => 'v3.2.16 absent-key fallback equals current default',
		],

		// ADR-40: alias-table apply mode: 'auto' | 'delta' | 'replace'. New-install default 'auto'.
		// 'auto' = delta for small churn (< ~5%), full replace for initial load / large churn;
		// 'delta' = ALWAYS forward delta, NO large-churn replace fallback (power-user override);
		// 'replace' = always full -T replace (pre-ADR-40 behaviour).
		// Existing installs are grandfather-seeded to 'replace' by the registry pass at
		// install/upgrade (issue #1921); only brand-new installs take the 'auto' default.
		'gen/pfb_alias_delta_mode' => [
			'default'       => 'auto',
			'read_adapter'  => 'pfb_cfg_alias_delta_mode_read',
			'write_adapter' => 'pfb_cfg_alias_delta_mode_write',
			'grandfather'   => [PFB_GF_ABSENT => 'replace'],
		],

		// ADR-40: alias-table delta batch size (integer as string). Default '512'.
		// Clamped to [64, 4096] on read. Batch=512 is optimal for sub-1M tables
		// (zero ICMP stalls at 100k/1k-churn); batch=1024+ for 1M+ tables.
		'gen/pfb_alias_delta_batch' => [
			'default'       => '512',
			'read_adapter'  => NULL,
			'write_adapter' => NULL,
			'no_grandfather' => 'ADR-40 companion; delta mode is new in 4.0, grandfathered installs run \'replace\' where batch is inert',
		],

		// ADR-43: tick-cron dispatch interval in minutes (1–60). Default '15'.
		// One cron tick fires every */pfb_tick_interval; jobs run only when due
		// per the due-ledger. Default 15 matches the tightest existing job (ss_refresh).
		'gen/pfb_tick_interval' => [
			'default'       => '15',
			'read_adapter'  => NULL,
			'write_adapter' => NULL,
			'no_grandfather' => 'ADR-43 trigger-tick engine replaces the cron fleet uniformly for all installs (accepted redesign, no per-install variance)',
		],

		// ADR-43: optional apply-on-change maintenance window ("HH:MM-HH:MM", local time).
		// When set: detected changes outside the window are deferred (pending); the first tick
		// inside the window applies them. Empty string (default) = apply immediately (no deferral).
		// Wrapping windows (e.g. "23:00-03:00") span midnight. Malformed = fail-safe (apply now).
		'gen/pfb_quiet_hours' => [
			'default'       => '',
			'read_adapter'  => NULL,
			'write_adapter' => NULL,
			'no_grandfather' => 'ADR-43 opt-in apply-on-change window; new 4.0 field, \'\' = no window',
		],

		// issue #1669 slice C / #1888: client-side editor (syntax highlighting, line numbers,
		// linting, undo/redo) for list/script fields
		// (CodeMirror 6), gating asset emission on pfblockerng_dnsbl.php. NEW feature --
		// no prior behaviour to preserve, so both fresh installs and upgraders take the
		// same 'on' absent-default; no grandfather seed is needed (config-gateway.md's
		// two-case forward-compat rule). PfbToggle presence handling preserves a
		// present empty Off while absent resolves to the default. Mirrors pfb_keep.
		'gen/pfb_syntax_highlight' => [
			'default'       => 'on',
			'read_adapter'  => 'pfb_cfg_toggle_read',
			'write_adapter' => 'pfb_cfg_toggle_write',
			'no_grandfather' => '#1669 new 4.0 UI editor highlighting, cosmetic only, on-for-all at introduction',
		],

		// -------------------------------------------------------------------
		// DNSBL settings section (pfblockerngdnsblsettings/config/0)
		// -------------------------------------------------------------------

		// DNSBL master enable: 'on' | '' (checkbox).
		'dnsbl/pfb_dnsbl' => [
			'default'       => '',
			'read_adapter'  => 'pfb_cfg_toggle_read',
			'write_adapter' => 'pfb_cfg_toggle_write',
			'no_grandfather' => 'v3.2.16 absent-key fallback equals current default',
		],

		// ADR-13: auto-create/remove DNSBL sinkhole VIPs: 'on' | '' (checkbox).
		'dnsbl/pfb_dnsvip_auto' => [
			'default'       => '',
			'read_adapter'  => 'pfb_cfg_toggle_read',
			'write_adapter' => 'pfb_cfg_toggle_write',
			'no_grandfather' => 'ADR-13 opt-in auto-VIP; new 4.0 field, \'\' = manual VIP handling = prior behaviour',
		],

		// [ #381 ] Opt out of automatic DNSBL sinkhole NAT rule generation: 'on' | '' (checkbox).
		// Default '' = NAT generated (current behaviour); 'on' = user manages NAT manually.
		'dnsbl/pfb_dnsbl_nonat' => [
			'default'       => '',
			'read_adapter'  => 'pfb_cfg_toggle_read',
			'write_adapter' => 'pfb_cfg_toggle_write',
			'no_grandfather' => '#381 opt-OUT toggle; new 4.0 field, \'\' = NAT rules generated = prior behaviour',
		],

		// VIP interface for DNSBL sinkhole. Default 'lo0'.
		'dnsbl/dnsbl_interface' => [
			'default'       => 'lo0',
			'read_adapter'  => NULL,
			'write_adapter' => NULL,
			'no_grandfather' => 'v3.2.16 absent-key fallback equals current default',
		],

		// DNSBL IPv4 sinkhole VIP id string. Default ''.
		'dnsbl/pfb_dnsvip4' => [
			'default'       => '',
			'read_adapter'  => NULL,
			'write_adapter' => NULL,
			'no_grandfather' => 'v3.2.16 absent-key fallback equals current default',
		],

		// DNSBL IPv6 sinkhole VIP id string. Default ''.
		'dnsbl/pfb_dnsvip6' => [
			'default'       => '',
			'read_adapter'  => NULL,
			'write_adapter' => NULL,
			'no_grandfather' => 'v3.2.16 absent-key fallback equals current default',
		],

		// DNSBL lighttpd HTTP port. Default '' (system default).
		'dnsbl/pfb_dnsport' => [
			'default'       => '',
			'read_adapter'  => NULL,
			'write_adapter' => NULL,
			'no_grandfather' => 'v3.2.16 absent-key fallback equals current default',
		],

		// DNSBL lighttpd HTTPS port. Default ''.
		'dnsbl/pfb_dnsport_ssl' => [
			'default'       => '',
			'read_adapter'  => NULL,
			'write_adapter' => NULL,
			'no_grandfather' => 'v3.2.16 absent-key fallback equals current default',
		],

		// TOP1M whitelist enable. Default ''.
		'dnsbl/top1m_enable' => [
			'default'       => '',
			'read_adapter'  => NULL,
			'write_adapter' => NULL,
			'old_name'      => 'alexa_enable',
			'no_grandfather' => 'v3.2.16 absent-key fallback equals current default (as alexa_enable)',
		],

		// TOP1M type selector: 'tranco' | 'cisco' | 'openpagerank' | 'majestic' | 'cloudflare'.
		// Legacy 'alexa' (dead service, #872) coalesces to 'tranco', and legacy 'domcop'
		// (list moved hosting, #928) coalesces to 'openpagerank', at the read boundary
		// via pfb_cfg_top1m_source_read(). Default 'tranco'.
		'dnsbl/top1m_source' => [
			'default'       => 'tranco',
			'read_adapter'  => 'pfb_cfg_top1m_source_read',
			'write_adapter' => 'pfb_cfg_top1m_source_write',
			'old_name'      => 'alexa_type',
			'no_grandfather' => 'v3.2.16 absent-key fallback equals current default (as alexa_type)',
		],

		// TOP1M domain count (numeric string). Default '1000'.
		'dnsbl/top1m_count' => [
			'default'       => '1000',
			'read_adapter'  => NULL,
			'write_adapter' => NULL,
			'old_name'      => 'alexa_count',
			'no_grandfather' => 'v3.2.16 absent-key fallback equals current default (as alexa_count)',
		],

		// TOP1M TLD inclusions for whitelisting. Default ''.
		'dnsbl/top1m_inclusion' => [
			'default'       => '',
			'read_adapter'  => NULL,
			'write_adapter' => NULL,
			'old_name'      => 'alexa_inclusion',
			'no_grandfather' => 'v3.2.16 absent-key fallback equals current default (as alexa_inclusion)',
		],

		// ADR-59: masked, write-only Cloudflare Radar Bearer token -- consumed only
		// when top1m_source == 'cloudflare' (every other provider ignores it), fed to
		// pfb_download() via pfb_top1m_auth_headers() + the header-auth plumbing.
		// Plain string (no adapter): the DNSBL page never echoes the stored value back
		// on GET, and a blank POST preserves the existing value rather than clearing it
		// (pfblockerng_dnsbl.php's save handler) -- see PFB_FILTER_TOKEN (pfblockerng.inc)
		// for the accepted charset. Default ''.
		'dnsbl/top1m_token' => [
			'default'       => '',
			'read_adapter'  => NULL,
			'write_adapter' => NULL,
			'no_grandfather' => 'ADR-59 Cloudflare Radar credential; new 4.0 field, \'\' = none',
		],

		// Resolver cache backup/restore option. Default on (the de-facto page default
		// since 3.2 -- #1907 owner decision). A present '' remains an explicit uncheck;
		// no grandfather arm is needed.
		'dnsbl/pfb_cache' => [
			'default'       => 'on',
			'read_adapter'  => 'pfb_cfg_toggle_read',
			'write_adapter' => 'pfb_cfg_toggle_write',
			'no_grandfather' => 'v3.2 deliberate empty checkbox state is preserved by the owner-ruled storage contract',
		],

		// Full resolver-cache flush after a successful DNSBL data swap. Default off.
		'dnsbl/pfb_cache_flush' => [
			'default'       => '',
			'read_adapter'  => 'pfb_cfg_toggle_read',
			'write_adapter' => 'pfb_cfg_toggle_write',
			'no_grandfather' => 'the post-swap flush exists only in the 4.0 no-reload pipeline; latency delta is the accepted zero-downtime redesign itself, not this default; default-off is a uniform decision at introduction',
		],

		// Global logging/blocking mode. Default ''.
		'dnsbl/global_log' => [
			'default'       => '',
			'read_adapter'  => NULL,
			'write_adapter' => NULL,
			'no_grandfather' => 'v3.2.16 absent-key fallback equals current default',
		],

		// ADR-22: scheme-parsing leniency: 'on' | ''. Default 'off'.
		// Toggle adapter: Off stores the empty token.
		'dnsbl/pfb_dnsbl_lenient' => [
			'default'       => 'off',
			'read_adapter'  => 'pfb_cfg_toggle_read',
			'write_adapter' => 'pfb_cfg_toggle_write',
			'grandfather'   => [PFB_GF_ABSENT => 'on'],
		],

		// Python DNS reply logging. Default on (the de-facto page default since 3.2 --
		// #1907 owner decision). A present empty token is deliberate Off.
		// Bespoke pre-ADR-02 migration (pfb_python_gated_toggles_migrate) additionally
		// disables a stored 'on' that was inert under pre-upgrade Unbound mode.
		'dnsbl/pfb_py_reply' => [
			'default'       => 'on',
			'read_adapter'  => 'pfb_cfg_toggle_read',
			'write_adapter' => 'pfb_cfg_toggle_write',
			'no_grandfather' => 'v3.2 deliberate empty checkbox state is preserved by the owner-ruled storage contract',
		],

		// HSTS null-blocking mode: 'on' | ''. Default on (the de-facto page default
		// since 3.2 -- #1907 owner decision). A present empty token is deliberate Off.
		// Bespoke pre-ADR-02 migration (pfb_python_gated_toggles_migrate)
		// additionally disables a stored 'on' that was inert under pre-upgrade Unbound
		// mode.
		'dnsbl/pfb_hsts' => [
			'default'       => 'on',
			'read_adapter'  => 'pfb_cfg_toggle_read',
			'write_adapter' => 'pfb_cfg_toggle_write',
			'no_grandfather' => 'v3.2 deliberate empty checkbox state is preserved by the owner-ruled storage contract',
		],

		// ADR-08: IDN mode — adopted into the gateway as a PfbIdnMode enum (ADR-28
		// reframe: preserve behaviour on upgrade, not byte-identical storage). Read
		// normalises legacy 'on' -> All; write persists the canonical token
		// ('on'=All | 'confusable' | ''=Off), reusing the pre-4.0.0 'on' token so All
		// round-trips with zero migration. Legacy '' and the 4.0.0-alpha 'all' token
		// read as Off; unknown tokens also fall through to Off.
		// See ADR-28 §2.2 + CfgAdaptersTest.
		'dnsbl/pfb_idn' => [
			'default'       => '',
			'read_adapter'  => 'pfb_cfg_idn_mode_read',
			'write_adapter' => 'pfb_cfg_idn_mode_write',
			'no_grandfather' => 'v3.2.16 absent-key fallback equals current default',
		],

		// Confusable: block malicious homoglyphs (default on). A present empty token is
		// deliberate Off; only an absent key receives the registered default On.
		'dnsbl/pfb_idn_block_malicious' => [
			'default'       => 'on',
			'read_adapter'  => 'pfb_cfg_toggle_read',
			'write_adapter' => 'pfb_cfg_toggle_write',
			'no_grandfather' => 'v3.2 deliberate empty checkbox state is preserved by the owner-ruled storage contract',
		],

		// Confusable: escalate suspicious mixed-script to block (opt-in). Default ''.
		'dnsbl/pfb_idn_escalate_suspicious' => [
			'default'       => '',
			'read_adapter'  => 'pfb_cfg_toggle_read',
			'write_adapter' => 'pfb_cfg_toggle_write',
			'no_grandfather' => 'ADR-08 opt-in sub-toggle; homoglyph feature has no 3.2 counterpart, \'\' = no escalation',
		],

		// Python regex: 'on' | ''. Default ''.
		'dnsbl/pfb_regex' => [
			'default'       => '',
			'read_adapter'  => NULL,
			'write_adapter' => NULL,
			'no_grandfather' => 'v3.2.16 absent-key fallback equals current default',
		],

		// Python regex list (textarea). Default ''.
		'dnsbl/pfb_regex_list' => [
			'default'       => '',
			'read_adapter'  => NULL,
			'write_adapter' => NULL,
			'no_grandfather' => 'v3.2.16 absent-key fallback equals current default',
		],

		// Python regex static cap ('on'|''). Default ''.
		'dnsbl/pfb_regex_cap' => [
			'default'       => '',
			'read_adapter'  => 'pfb_cfg_toggle_read',
			'write_adapter' => 'pfb_cfg_toggle_write',
			'no_grandfather' => 'ADR-07 opt-in cap; \'\' = uncapped = prior behaviour',
		],

		// CNAME validation. Default ''.
		'dnsbl/pfb_cname' => [
			'default'       => '',
			'read_adapter'  => NULL,
			'write_adapter' => NULL,
			'no_grandfather' => 'v3.2.16 absent-key fallback equals current default',
		],

		// TLD Allow option. Default ''.
		'dnsbl/tld_allow' => [
			'default'       => '',
			'read_adapter'  => NULL,
			'write_adapter' => NULL,
			'old_name'      => 'pfb_pytld',
			'no_grandfather' => 'v3.2.16 absent-key fallback equals current default (as pfb_pytld)',
		],

		// issue #1921: TLD Allow sort order for the python list emit. Default ''.
		// Consumed via the dnsbl section blob (pfblockerng_dnsbl.php), not a per-key read --
		// stored '' is legal (config-gateway.md's foreign-key exclusion list previously
		// carried this and its 4 siblings below as "unregistered"; registered here for
		// old_name parity, no consumer change).
		'dnsbl/tld_allow_sort' => [
			'default'        => '',
			'read_adapter'   => NULL,
			'write_adapter'  => NULL,
			'old_name'       => 'pfb_pytld_sort',
			'no_grandfather' => '3.2-era field; v3.2.16 absent fallback equals default; registered for old_name parity (#1921)',
		],

		// issue #1921: TLD Allow generic-TLD bucket (CSV). Default ''.
		'dnsbl/tld_allow_gtld' => [
			'default'        => '',
			'read_adapter'   => NULL,
			'write_adapter'  => NULL,
			'old_name'       => 'pfb_pytlds_gtld',
			'no_grandfather' => '3.2-era field; v3.2.16 absent fallback equals default; registered for old_name parity (#1921)',
		],

		// issue #1921: TLD Allow country-code TLD bucket (CSV). Default ''.
		'dnsbl/tld_allow_cctld' => [
			'default'        => '',
			'read_adapter'   => NULL,
			'write_adapter'  => NULL,
			'old_name'       => 'pfb_pytlds_cctld',
			'no_grandfather' => '3.2-era field; v3.2.16 absent fallback equals default; registered for old_name parity (#1921)',
		],

		// issue #1921: TLD Allow infrastructure-TLD bucket (CSV). Default ''.
		'dnsbl/tld_allow_itld' => [
			'default'        => '',
			'read_adapter'   => NULL,
			'write_adapter'  => NULL,
			'old_name'       => 'pfb_pytlds_itld',
			'no_grandfather' => '3.2-era field; v3.2.16 absent fallback equals default; registered for old_name parity (#1921)',
		],

		// issue #1921: TLD Allow brand/generic-TLD bucket (CSV). Default ''.
		'dnsbl/tld_allow_bgtld' => [
			'default'        => '',
			'read_adapter'   => NULL,
			'write_adapter'  => NULL,
			'old_name'       => 'pfb_pytlds_bgtld',
			'no_grandfather' => '3.2-era field; v3.2.16 absent fallback equals default; registered for old_name parity (#1921)',
		],

		// Log events via DNSBL Webserver vs python. Default ''.
		'dnsbl/pfb_py_nolog' => [
			'default'       => '',
			'read_adapter'  => NULL,
			'write_adapter' => NULL,
			'no_grandfather' => 'v3.2.16 absent-key fallback equals current default',
		],

		// No AAAA blocking: 'on' | ''. Default ''.
		'dnsbl/pfb_noaaaa' => [
			'default'       => '',
			'read_adapter'  => NULL,
			'write_adapter' => NULL,
			'no_grandfather' => 'v3.2.16 absent-key fallback equals current default',
		],

		// No AAAA list (textarea). Default ''.
		'dnsbl/pfb_noaaaa_list' => [
			'default'       => '',
			'read_adapter'  => NULL,
			'write_adapter' => NULL,
			'no_grandfather' => 'v3.2.16 absent-key fallback equals current default',
		],

		// DNSBL bypass enable: 'on' | ''. Default ''.
		'dnsbl/pfb_gp' => [
			'default'       => '',
			'read_adapter'  => NULL,
			'write_adapter' => NULL,
			'no_grandfather' => 'v3.2.16 absent-key fallback equals current default',
		],

		// DNSBL bypass local IP list (textarea). Default ''.
		'dnsbl/pfb_gp_bypass_list' => [
			'default'       => '',
			'read_adapter'  => NULL,
			'write_adapter' => NULL,
			'no_grandfather' => 'v3.2.16 absent-key fallback equals current default',
		],

		// TLD blacklist (textarea). Default ''.
		'dnsbl/tld_wildcard_blacklist' => [
			'default'       => '',
			'read_adapter'  => NULL,
			'write_adapter' => NULL,
			'old_name'      => 'tldblacklist',
			'no_grandfather' => 'v3.2.16 absent-key fallback equals current default (as tldblacklist)',
		],

		// TLD exclusion (textarea). Default ''.
		'dnsbl/tld_wildcard_exclusion' => [
			'default'       => '',
			'read_adapter'  => NULL,
			'write_adapter' => NULL,
			'old_name'      => 'tldexclusion',
			'no_grandfather' => 'v3.2.16 absent-key fallback equals current default (as tldexclusion)',
		],

		// DNSBL whitelist (base64), stored as 'suppression' until issue #1921. Default ''.
		'dnsbl/whitelist' => [
			'default'       => '',
			'read_adapter'  => NULL,
			'write_adapter' => NULL,
			'old_name'      => 'suppression',
			'no_grandfather' => 'v3.2.16 absent-key fallback equals current default (dnsbl-section whitelist blob, as suppression)',
		],

		// DNSBL action for IP blocking. Default 'Disabled'.
		'dnsbl/action' => [
			'default'       => 'Disabled',
			'read_adapter'  => NULL,
			'write_adapter' => NULL,
			'no_grandfather' => 'v3.2.16 absent-key fallback equals current default',
		],

		// Auto-create floating pass rule. Default 'Disabled'.
		'dnsbl/pfb_dnsbl_rule' => [
			'default'       => 'Disabled',
			'read_adapter'  => NULL,
			'write_adapter' => NULL,
			'no_grandfather' => 'v3.2.16 absent-key fallback equals current default',
		],

		// Allow-interface for DNSBL (multi-select). Default ''.
		'dnsbl/dnsbl_allow_int' => [
			'default'       => '',
			'read_adapter'  => NULL,
			'write_adapter' => NULL,
			'no_grandfather' => 'v3.2.16 absent-key fallback equals current default',
		],

		// Python control integration. Default ''.
		'dnsbl/pfb_control' => [
			'default'       => '',
			'read_adapter'  => NULL,
			'write_adapter' => NULL,
			'no_grandfather' => 'v3.2.16 absent-key fallback equals current default',
		],

		// Legacy DNS-TXT control transport (deprecated). Default ''.
		'dnsbl/pfb_control_legacy' => [
			'default'       => '',
			'read_adapter'  => NULL,
			'write_adapter' => NULL,
		],

		// Python cache max (numeric string). Default '' (unlimited).
		'dnsbl/pfb_py_cache_max' => [
			'default'       => '',
			'read_adapter'  => NULL,
			'write_adapter' => NULL,
			'no_grandfather' => 'the 10000 cap it bounds is a 4.0-only construct; \'\'/absent resolve to that cap everywhere -- uniform decision at introduction',
		],

		// TLD blocking enable. Default ''.
		'dnsbl/tld_wildcard' => [
			'default'       => '',
			'read_adapter'  => NULL,
			'write_adapter' => NULL,
			'old_name'      => 'pfb_tld',
			'no_grandfather' => 'v3.2.16 absent-key fallback equals current default (as pfb_tld)',
		],

		// Aliaslog (logging mode). Default ''.
		'dnsbl/aliaslog' => [
			'default'       => '',
			'read_adapter'  => NULL,
			'write_adapter' => NULL,
			'no_grandfather' => 'v3.2.16 absent-key fallback equals current default',
		],

		// ADR-36: NAT DNS-redirect enable: 'on' | '' (checkbox). Default '' (off).
		'dnsbl/dnsbl_redir' => [
			'default'       => '',
			'read_adapter'  => 'pfb_cfg_toggle_read',
			'write_adapter' => 'pfb_cfg_toggle_write',
			'no_grandfather' => 'ADR-36 opt-in DNS-redirect feature; \'\' = no redirect rules = prior behaviour',
		],

		// ADR-36: NAT DNS-redirect interface multi-select (comma-joined string). Default ''.
		'dnsbl/dnsbl_redir_int' => [
			'default'       => '',
			'read_adapter'  => NULL,
			'write_adapter' => NULL,
			'no_grandfather' => 'ADR-36 companion; inert while dnsbl_redir is off',
		],

		// ADR-36: NAT DNS-redirect exception alias/IP string. Default ''.
		'dnsbl/dnsbl_redir_exclude' => [
			'default'       => '',
			'read_adapter'  => NULL,
			'write_adapter' => NULL,
			'no_grandfather' => 'ADR-36 companion; inert while dnsbl_redir is off',
		],

		// ADR-37: DoT/DoQ block enable: 'on' | '' (checkbox). Default '' (off).
		'dnsbl/dnsbl_dot_block' => [
			'default'       => '',
			'read_adapter'  => 'pfb_cfg_toggle_read',
			'write_adapter' => 'pfb_cfg_toggle_write',
			'no_grandfather' => 'ADR-37 opt-in DoT/DoQ block feature; \'\' = no block rules = prior behaviour',
		],

		// ADR-37: DoT/DoQ block interface multi-select (comma-joined string). Default ''.
		'dnsbl/dnsbl_dot_block_int' => [
			'default'       => '',
			'read_adapter'  => NULL,
			'write_adapter' => NULL,
			'no_grandfather' => 'ADR-37 companion; inert while dnsbl_dot_block is off',
		],

		// ADR-37: DoT/DoQ block exception alias/IP string. Default ''.
		'dnsbl/dnsbl_dot_block_exclude' => [
			'default'       => '',
			'read_adapter'  => NULL,
			'write_adapter' => NULL,
			'no_grandfather' => 'ADR-37 companion; inert while dnsbl_dot_block is off',
		],

		// ADR-37: DoT/DoQ block rule action: 'reject' (default) | 'block'.
		// Mirrors the IP-settings inbound/outbound Rule Action selector. Reject
		// fast-fails the client (outbound LAN->WAN rule); block silently drops.
		'dnsbl/dnsbl_dot_block_action' => [
			'default'       => 'reject',
			'read_adapter'  => NULL,
			'write_adapter' => NULL,
			'no_grandfather' => 'sub-setting of the off-by-default ADR-37 feature; a 3.2 upgrader has the feature off, so \'reject\' cannot change established behaviour',
		],

		// ADR-37: DoT/DoQ block floating mode: 'on' | '' (checkbox). Default '' (off).
		// On = a single floating rule (direction 'in') over the selected interfaces
		// instead of one rule per interface. Off preserves the per-interface default.
		'dnsbl/dnsbl_dot_block_floating' => [
			'default'       => '',
			'read_adapter'  => 'pfb_cfg_toggle_read',
			'write_adapter' => 'pfb_cfg_toggle_write',
			'no_grandfather' => 'ADR-37 companion; inert while dnsbl_dot_block is off',
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
		'gen/log_syslog' => [
			'default'       => '',
			'read_adapter'  => 'pfb_cfg_toggle_read',
			'write_adapter' => 'pfb_cfg_toggle_write',
			'no_grandfather' => 'ADR-38 opt-in syslog export; v3.2.16 had no syslog export, \'\' = off',
		],

		// -------------------------------------------------------------------
		// SafeSearch section (pfblockerngsafesearch — flat, no /config/0)
		// -------------------------------------------------------------------

		// SafeSearch enable mode. Default 'Disable'.
		'ss/safesearch_enable' => [
			'default'       => 'Disable',
			'read_adapter'  => NULL,
			'write_adapter' => NULL,
			'no_grandfather' => 'v3.2.16 absent-key fallback equals current default',
		],

		// YouTube SafeSearch mode. Default 'Disable'.
		'ss/safesearch_youtube' => [
			'default'       => 'Disable',
			'read_adapter'  => NULL,
			'write_adapter' => NULL,
			'no_grandfather' => 'v3.2.16 absent-key fallback equals current default',
		],

		// DNS-over-HTTPS blocking mode. Default 'Disable'.
		'ss/safesearch_doh' => [
			'default'       => 'Disable',
			'read_adapter'  => NULL,
			'write_adapter' => NULL,
			'no_grandfather' => 'v3.2.16 absent-key fallback equals current default',
		],

		// DoH domain exclusion list (CSV). Default ''.
		'ss/safesearch_doh_list' => [
			'default'       => '',
			'read_adapter'  => NULL,
			'write_adapter' => NULL,
			'no_grandfather' => 'v3.2.16 absent-key fallback equals current default',
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
		'ip/v4suppression' => [
			'default'       => '',
			'read_adapter'  => NULL,
			'write_adapter' => NULL,
			'no_grandfather' => 'v3.2.16 textarea decode, absent = empty; ADR-53 conversion keys on literal absence and stays ordered before the registry pass',
		],

		// ADR-53: IPv6 suppression customlist -- the v4 blob's v6 sibling
		// (same base64/newline-separated shape). Default ''.
		'ip/v6suppression' => [
			'default'       => '',
			'read_adapter'  => NULL,
			'write_adapter' => NULL,
			'no_grandfather' => '#760 new 4.0 v6 leg; \'\' = empty list, no pre-4.0 v6 suppression existed',
		],

		// issue #1931: IP page "Enable Suppression" toggle -- path-addressed, no longer
		// collides with dnsbl/whitelist. Default on (the de-facto page default since
		// 3.2 -- #1907 owner decision). A present '' remains an explicit uncheck;
		// no grandfather arm is needed.
		'ip/suppression' => [
			'default'       => 'on',
			'read_adapter'  => 'pfb_cfg_toggle_read',
			'write_adapter' => 'pfb_cfg_toggle_write',
			'no_grandfather' => 'v3.2 deliberate empty checkbox state is preserved by the owner-ruled storage contract',
		],

		// -------------------------------------------------------------------
		// Reputation section (pfblockerngreputation/config/0)
		// -------------------------------------------------------------------

		// issue #1896: 'Max' per-list Reputation toggle: 'on' | 'off' | ''. Default '' (off).
		'rep/enable_rep' => [
			'default'       => '',
			'read_adapter'  => 'pfb_cfg_toggle_read',
			'write_adapter' => 'pfb_cfg_toggle_write',
			'no_grandfather' => 'v3.2.16 absent-key fallback equals current default',
		],

		// issue #1896: 'pMax' collective Reputation toggle (no Country Exclusion):
		// 'on' | 'off' | ''. Default '' (off).
		'rep/enable_pdup' => [
			'default'       => '',
			'read_adapter'  => 'pfb_cfg_toggle_read',
			'write_adapter' => 'pfb_cfg_toggle_write',
			'no_grandfather' => 'v3.2.16 absent-key fallback equals current default',
		],

		// issue #1896: 'dMax' collective Reputation toggle (Country Exclusion applied):
		// 'on' | 'off' | ''. Default '' (off).
		'rep/enable_dedup' => [
			'default'       => '',
			'read_adapter'  => 'pfb_cfg_toggle_read',
			'write_adapter' => 'pfb_cfg_toggle_write',
			'no_grandfather' => 'v3.2.16 absent-key fallback equals current default',
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
 *   PfbConfig::write($key, $value)                 — write one field, gated by the
 *                                                     field's write_priv (issue #1895)
 *   PfbConfig::delete($key)                        — delete one field
 *   PfbConfig::readSection($section)               — read a whole section array
 *   PfbConfig::writeSection($section, $data)       — write a section array, normalising
 *                                                     its registered fields through their
 *                                                     adapters (issue #930), gated per
 *                                                     registered field like write() --
 *                                                     but DELTA-AWARE (issue #1895
 *                                                     addendum): a present field only
 *                                                     asserts its write_priv when its
 *                                                     canonical value actually changes
 *   PfbConfig::deleteSection($section)             — delete a whole section
 *   PfbConfig::writeSystem($key, $value)           — write one field with NO privilege
 *                                                     check, for no-session system callers
 *                                                     (cron/install/migrations/CLI/core
 *                                                     hooks; issue #1895)
 *   PfbConfig::writeSectionSystem($section, $data) — writeSection() with NO privilege check,
 *                                                     same system-caller contract
 *
 * Authorization model (issue #1895): write()/writeSection() enforce a per-field page
 * privilege via isAllowedPage(), fail-closed when that check is undefined or false --
 * a system-context caller with no web session must say so explicitly via the
 * writeSystem()/writeSectionSystem() escape hatch, never rely on a silent pass.
 * writeSection() adds a delta-aware carve-out on top (issue #1895 addendum): a
 * registered field present in the section blob is an authorization event only when
 * its canonical incoming value differs from its canonical currently-stored value --
 * an unchanged read-modify-write pass-through (e.g. the General settings page saving
 * an unrelated field) is not a write of that field. write() has no such carve-out and
 * stays strict -- see assertWriteAllowedOnChange().
 *
 * @see pfb_cfg_registry()
 */
final class PfbConfig
{
	// issue #1895: the package's own general-settings page -- the default write-authorization
	// page privilege for every registered field that does not declare its own 'write_priv'.
	private const WRITE_PRIV_DEFAULT = 'pfblockerng/pfblockerng_general.php';

	/**
	 * Read a single registered field.
	 *
	 * Returns the registered default when the key is absent/null; applies
	 * the registered read adapter (stored string -> runtime enum/string).
	 *
	 * @param  string $key  The registered path-form field key (e.g. 'gen/pfb_keep').
	 * @return mixed        Runtime value (enum or string).
	 * @throws InvalidArgumentException When $key is not in the registry.
	 */
	public static function read(string $key): mixed
	{
		$entry   = self::entry($key);
		$path    = self::sectionPath($key);
		$raw     = config_get_path($path, NULL);
		$stored  = self::notConfigured($entry, $raw);
		$adapter = $entry['read_adapter'];
		return ($adapter !== NULL) ? $adapter($stored) : (string) $stored;
	}

	/**
	 * Write a single registered field.
	 *
	 * Applies the registered write adapter (runtime value -> exact legacy
	 * stored string) before calling config_set_path. Does NOT call
	 * write_config() — callers must persist when appropriate.
	 *
	 * Enforces the field's write_priv page privilege (issue #1895) — a no-session
	 * system caller (cron/install/migrations/CLI/core hooks) must use writeSystem().
	 *
	 * Unlike writeSection() (see its docblock), this check is STRICT, not delta-aware:
	 * an explicit single-key write() call is always an authorization event, whether or
	 * not the value actually changes, because there is no read-modify-write section
	 * saver behind it that could be carrying an unrelated field's unchanged value along
	 * for the ride. writeSection()'s pass-through carve-out exists specifically for that
	 * read-modify-write case (e.g. the General settings page); write() has no such case
	 * to carve out.
	 *
	 * @param  string $key   The registered path-form field key.
	 * @param  mixed  $value Runtime value (enum or string).
	 * @throws InvalidArgumentException When $key is not in the registry.
	 * @throws RuntimeException         When the caller lacks the field's write_priv.
	 */
	public static function write(string $key, mixed $value): void
	{
		$entry = self::entry($key);
		self::assertWriteAllowed($key, $entry);
		self::writeRaw($key, $value);
	}

	/**
	 * Write a single registered field with NO privilege check.
	 *
	 * For system-context callers with no web session -- cron, the installer,
	 * migrations, CLI tooling, pfSense-core hooks (issue #1895). isAllowedPage()
	 * is unreachable/meaningless in those contexts, so write() would fail-closed
	 * on them; this is the explicit escape hatch for that legitimate case. Never
	 * callable from src/usr/local/www/ (enforced by RequireConfigGatewaySniff).
	 *
	 * @param  string $key   The registered path-form field key.
	 * @param  mixed  $value Runtime value (enum or string).
	 * @throws InvalidArgumentException When $key is not in the registry.
	 */
	public static function writeSystem(string $key, mixed $value): void
	{
		self::writeRaw($key, $value);
	}

	/**
	 * Delete a single registered field.
	 *
	 * @param  string $key  The registered path-form field key.
	 * @throws InvalidArgumentException When $key is not in the registry.
	 */
	public static function delete(string $key): void
	{
		self::entry($key);
		$path = self::sectionPath($key);
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
	 * adapter, a present value is round-tripped read_adapter() then
	 * write_adapter() — coalescing a legacy/read-only token (e.g. top1m_source
	 * 'domcop'/'alexa', pfb_idn 'all'), a non-scalar (a crafted POST array),
	 * or junk input to the field's canonical stored form. NULL omits the
	 * adapter key, exactly as a single-key PfbConfig::write() would. Unregistered keys and
	 * adapter-less (plain-string) registered keys pass through byte-identical.
	 * Consequence: canonical storage is enforced on section writes too — a
	 * legacy token riding a readSection()->writeSection()
	 * round-trip (a restored backup, an HA sync, a hand-edited config.xml)
	 * is coalesced to canonical on the next save. Does NOT call
	 * write_config() — callers persist.
	 *
	 * Read adapter runs FIRST (mixed -> runtime value; the non-scalar guard
	 * handles arrays/junk and is idempotent on an already-adapted enum
	 * instance), write adapter SECOND (runtime value -> canonical stored
	 * string). NULL is omitted before adapter dispatch, so it cannot reach a
	 * typed write adapter.
	 *
	 * Privilege gate is DELTA-AWARE (issue #1895 addendum): a registered field
	 * present in $data is only an authorization event when its canonical
	 * incoming value differs from the canonical currently-stored value --
	 * see assertWriteAllowedOnChange(). This is what write() does NOT do: a
	 * single-key write() call is always an explicit authorization event, delta
	 * or not, because there is no read-modify-write section saver behind it to
	 * carry an unrelated field's unchanged value along for the ride.
	 *
	 * @param string $section  The full config.xml section path.
	 * @param array  $data     Section data to persist.
	 */
	public static function writeSection(string $section, array $data): void
	{
		// ALL privilege checks run BEFORE any mutation (issue #1895): a section blob can
		// carry several registered fields with different write_priv values, and a later
		// field failing its check must never leave an earlier field's config_set_path
		// already applied. Registered fields only -- a key registered to a DIFFERENT
		// section, or not registered at all, is foreign data and carries no gate here.
		foreach (pfb_cfg_registry() as $reg_key => $entry) {
			[$alias, $bare] = explode('/', $reg_key, 2);
			if ((PFB_SECTIONS[$alias] ?? NULL) !== $section || !array_key_exists($bare, $data)) {
				continue;
			}
			self::assertWriteAllowedOnChange($bare, $entry, $section, $data[$bare]);
		}
		self::writeSectionRaw($section, $data);
	}

	/**
	 * writeSection() with NO privilege check — see writeSystem() for the contract.
	 *
	 * @param string $section  The full config.xml section path.
	 * @param array  $data     Section data to persist.
	 */
	public static function writeSectionSystem(string $section, array $data): void
	{
		self::writeSectionRaw($section, $data);
	}

	/**
	 * Write a whole section array with NO adapter canonicalisation and NO privilege
	 * check (issue #1921).
	 *
	 * writeSectionRaw() (writeSection()/writeSectionSystem()'s shared body) is "raw"
	 * only with respect to the privilege check -- it still round-trips every
	 * adapter-bearing registered field present in $data through
	 * write_adapter(read_adapter(...)). A migration transforms RAW config.xml
	 * storage: persisting its result through that round-trip would canonicalise a
	 * still-raw legacy value on a BYSTANDER key (e.g. a stored top1m_source
	 * 'alexa' the migration never touched) before the registry pass
	 * (pfb_registry_pass(), issue #1921) gets a chance to see and grandfather it --
	 * canonicalisation is that pass's job, not a migration's. This method persists
	 * $data byte-for-byte via config_set_path(), with no adapter involvement at all.
	 *
	 * System-context, same no-session contract as writeSystem()/writeSectionSystem()
	 * (issue #1895) -- for migrations/install/upgrade callers only, never www/.
	 *
	 * @param string $section  The full config.xml section path.
	 * @param array  $data     Section data to persist, byte-identical.
	 */
	public static function writeSectionRawSystem(string $section, array $data): void
	{
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
	 * Resolve a path-form registry key ('<alias>/<bare-key>') to the real
	 * config.xml field path via PFB_SECTIONS (issue #1931). Defensive only --
	 * unreachable for a registered key (CfgGatewayTest's alias-prefix gate).
	 *
	 * @param  string $key  A registered path-form key (e.g. 'gen/pfb_keep').
	 * @return string       The real config.xml field path.
	 * @throws InvalidArgumentException When $key is malformed or its alias is unknown.
	 */
	private static function sectionPath(string $key): string
	{
		$slash = strpos($key, '/');
		if ($slash === FALSE || !array_key_exists(substr($key, 0, $slash), PFB_SECTIONS)) {
			throw new InvalidArgumentException("PfbConfig: malformed registry key '{$key}'.");
		}
		return PFB_SECTIONS[substr($key, 0, $slash)] . substr($key, $slash);
	}

	/**
	 * write() body proper, with NO privilege check — shared by write() and
	 * writeSystem() (issue #1895).
	 *
	 * @param  string $key   The registered path-form field key.
	 * @param  mixed  $value Runtime value (enum or string).
	 * @throws InvalidArgumentException When $key is not in the registry.
	 */
	private static function writeRaw(string $key, mixed $value): void
	{
		$entry   = self::entry($key);
		$path    = self::sectionPath($key);
		$adapter = $entry['write_adapter'];
		if ($adapter !== NULL && $value === NULL) {
			config_del_path($path);
			return;
		}
		$value   = self::notConfigured($entry, $value);
		$stored  = ($adapter !== NULL) ? $adapter($value) : (string) $value;
		config_set_path($path, $stored);
	}

	/**
	 * writeSection() body proper, with NO privilege check — shared by writeSection()
	 * and writeSectionSystem() (issue #1895).
	 *
	 * @param string $section  The full config.xml section path.
	 * @param array  $data     Section data to persist.
	 */
	private static function writeSectionRaw(string $section, array $data): void
	{
		foreach (pfb_cfg_registry() as $reg_key => $entry) {
			[$alias, $bare] = explode('/', $reg_key, 2);
			if ((PFB_SECTIONS[$alias] ?? NULL) !== $section) {
				continue;
			}
			$read_adapter  = $entry['read_adapter'];
			$write_adapter = $entry['write_adapter'];
			if ($read_adapter === NULL || $write_adapter === NULL) {
				continue;
			}
			if (!array_key_exists($bare, $data)) {
				continue;
			}
			if ($data[$bare] === NULL) {
				unset($data[$bare]);
				continue;
			}
			$data[$bare] = $write_adapter($read_adapter(self::notConfigured($entry, $data[$bare])));
		}
		config_set_path($section, $data);
	}

	/**
	 * Enforce the field's write_priv page privilege (issue #1895).
	 *
	 * Authorization is a property of the WRITE, not the call site: this class is
	 * pulled into essentially every page of the package (and several core hooks)
	 * through pfblockerng_extra.inc, so any code with the include in scope can reach
	 * a registered-field write. A page's own isAllowedPage() gate protects only that
	 * page's request path -- nothing stops a future caller elsewhere from invoking
	 * the writer with no gate at all. Re-asserting the privilege here makes it a
	 * property of the write itself.
	 *
	 * Fails CLOSED when isAllowedPage() is undefined or returns FALSE. priv.inc (the
	 * function's home) is only ever loaded on the web auth include chain, so in a
	 * no-session context (cron, install, migrations, CLI, a pfSense-core hook) the
	 * function is simply absent; treating an undefined check the same as an explicit
	 * refusal is deliberate -- a silent pass (or a silent no-op write) is exactly the
	 * trap issue #1895 documents. A legitimate system-context caller must say so
	 * explicitly, via PfbConfig::writeSystem()/writeSectionSystem().
	 *
	 * @param  string $key    The field key, named in the exception exactly as the caller
	 *                        passed it (path-form from write(); bare from writeSection()).
	 * @param  array  $entry  The registry entry (consulted for its optional 'write_priv').
	 * @throws RuntimeException When the caller lacks the field's required page privilege.
	 */
	private static function assertWriteAllowed(string $key, array $entry): void
	{
		$priv = $entry['write_priv'] ?? self::WRITE_PRIV_DEFAULT;
		if (!function_exists('isAllowedPage') || !isAllowedPage($priv)) {
			throw new RuntimeException(
				"PfbConfig: write of key '{$key}' requires page privilege '{$priv}' "
				. '(isAllowedPage() denied or undefined). System-context callers with no '
				. 'web session (cron/install/migrations/CLI/core hooks) must use '
				. 'PfbConfig::writeSystem()/writeSectionSystem() instead.'
			);
		}
	}

	/**
	 * writeSection()'s delta-aware privilege gate for one registered field (issue #1895
	 * addendum, composition bug found reviewing #1895 against pfblockerng_general.php).
	 *
	 * The General settings page does a whole-section readSection() -> modify one field
	 * -> writeSection() round trip. That carries every OTHER registered field's value
	 * along unchanged. Once assertWriteAllowed() ran unconditionally for every present
	 * field, a field with a write_priv override the current page doesn't hold (e.g.
	 * pfb_software_check, gated to 'pkg_mgr_installed.php') would trip on its own
	 * pass-through value even though nothing about it changed -- a supported save flow
	 * throwing on an unrelated edit. Fix: a present field is an authorization event ONLY
	 * when its canonical incoming value differs from the canonical currently-stored
	 * value. An unchanged pass-through is not a write of that field in any sense an
	 * operator would recognise; a real change still asserts the privilege, still BEFORE
	 * any mutation (self::writeSectionRaw() runs only after every field in the loop has
	 * cleared this gate).
	 *
	 * Both sides are canonicalised through the exact same pipeline write() and
	 * writeSectionRaw() already use, so this can never disagree with what actually gets
	 * stored: adapter NULL carries a deletion sentinel, present empty remains Off, and
	 * other adapter values round-trip write_adapter(read_adapter($value)) (the same
	 * normalisation writeSectionRaw()'s loop applies to the incoming side); a plain
	 * field is cast (string) (matching writeRaw()'s cast). The stored side reads via
	 * config_get_path() directly (bypassing the registry default, then applying it here)
	 * -- adapter absence remains distinct from an explicit registered-default value,
	 * while plain-field absence still canonicalises to its registered default.
	 *
	 * write() has no equivalent carve-out -- an explicit single-key write() call is
	 * always an authorization event, changed or not, because there is no read-modify-
	 * write section saver behind it carrying an unrelated field's value along.
	 *
	 * @param  string $key     The bare field key (named in the exception; $section . '/' .
	 *                         $key must be the real config.xml field path).
	 * @param  array  $entry   The registry entry (consulted for its optional 'write_priv').
	 * @param  string $section The full config.xml section path $key lives under.
	 * @param  mixed  $incoming The incoming (pre-normalisation) value for $key in the section blob.
	 * @throws RuntimeException When the field's canonical value actually changes and the
	 *                          caller lacks its required page privilege.
	 */
	private static function assertWriteAllowedOnChange(string $key, array $entry, string $section, mixed $incoming): void
	{
		$stored_raw = config_get_path($section . '/' . $key, NULL);
		if (self::canonicalize($entry, $stored_raw) === self::canonicalize($entry, $incoming)) {
			return;
		}
		self::assertWriteAllowed($key, $entry);
	}

	/**
	 * Canonicalise a raw or runtime value for one registered field to the exact stored
	 * string it would persist as, for the delta comparison in
	 * assertWriteAllowedOnChange() (issue #1895 addendum).
	 *
	 * Mirrors the two normalisation pipelines already in this class byte-for-byte so the
	 * comparison can never diverge from what an actual write would store:
	 *   - adapter-bearing field (both read_adapter and write_adapter set, always paired
	 *     -- see pfb_cfg_registry()): NULL is a deletion sentinel; other values use
	 *     write_adapter(read_adapter(notConfigured($value))), the same round trip
	 *     writeSectionRaw()'s normalisation loop applies.
	 *   - plain scalar field: (string) notConfigured($value), matching writeRaw()'s cast.
	 *   - plain NON-scalar (a crafted-POST array riding the section blob):
	 *     writeSectionRaw() persists it verbatim, so it must compare by SHAPE -- a
	 *     (string) cast would collapse every array to 'Array', making two different
	 *     arrays read "unchanged" (skipping the privilege assert for a value that
	 *     genuinely changes on disk) and emitting an Array-to-string warning.
	 *
	 * @param  array $entry  The registry entry.
	 * @param  mixed $value  Raw stored value (from config_get_path()) or the incoming
	 *                       section-blob value for this key.
	 * @return string        The canonical stored form $value would persist as.
	 */
	private static function canonicalize(array $entry, mixed $value): string
	{
		if ($entry['read_adapter'] !== NULL && $value === NULL) {
			// Keep deletion distinct from an explicit stored default. This makes a
			// section write from default -> NULL an authorization event, while
			// absent -> NULL remains a no-op (both sides carry this sentinel).
			return "\0PfbConfig::delete";
		}
		$value         = self::notConfigured($entry, $value);
		$read_adapter  = $entry['read_adapter'];
		$write_adapter = $entry['write_adapter'];
		if ($read_adapter !== NULL && $write_adapter !== NULL) {
			return $write_adapter($read_adapter($value));
		}
		if (!is_scalar($value)) {
			return 'nonscalar:' . md5(serialize($value));
		}
		return (string) $value;
	}

	/**
	 * Substitute a registered default at the configuration boundary.
	 *
	 * Adapter-backed fields distinguish absence (NULL) from a present empty token:
	 * NULL uses the registered default, while '' remains raw and the adapter parses it
	 * as Off. Plain scalar fields retain their existing NULL/'' defaulting behaviour.
	 * This shared rule is used by read(), write(), writeSection(), and canonicalize().
	 *
	 * @param  array{default:string,read_adapter:callable|null,write_adapter:callable|null} $entry
	 * @param  mixed $value  Raw stored value, or the runtime value on a write path.
	 * @return mixed         Registered default only for the field's not-configured state.
	 */
	private static function notConfigured(array $entry, mixed $value): mixed
	{
		if ($entry['read_adapter'] !== NULL) {
			return $value === NULL ? $entry['default'] : $value;
		}
		return ($value === NULL || $value === '') ? $entry['default'] : $value;
	}

	/**
	 * Look up a registry entry by its path-form key, throwing on an unregistered key.
	 *
	 * @param  string $key  A path-form key (e.g. 'gen/pfb_keep').
	 * @return array{default:string,read_adapter:callable|null,write_adapter:callable|null,write_priv?:string}
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
	$value = PfbConfig::read('gen/settings_family');
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
		// issue #1895: called from install/migration/upgrade paths with no web session --
		// a plain write() would silently fail-closed here and this catch would swallow it.
		PfbConfig::writeSystem('gen/settings_family', $family);
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
//
// issue #1921: the four grandfather/preservation migrations that used to live here
// (#1887's two '' preservations, ADR-22's lenient seed, issue #281's pfb_keep seed) are
// folded into pfb_registry_pass() (pfblockerng.inc), the one registry-driven pass the
// installer runs AFTER this driver. What remains here is genuinely cross-key or
// per-row work pfb_registry_pass() cannot express: the dynamic per-feed row rename,
// and two bespoke migrations keyed on ANOTHER field's value (ADR-02, PFBL-03) rather
// than a simple absent/''-map. write-back MUST stay RAW (writeSectionRawSystem(), not
// writeSectionSystem()) -- see pfb_run_migrations()'s inline comment: canonicalising a
// still-raw bystander value here, ahead of the registry pass, would destroy exactly
// the value that pass needs to grandfather.
// Tests: tests/php/MigrationRegistryTest.php
// ---------------------------------------------------------------------------

/**
 * pfb_migration_registry — the ordered list of upgrade migrations.
 *
 * Returns an array of migration descriptor maps, in the order they must run.
 * Each entry's 'apply' callable wraps an existing *_migrate / *_seed helper.
 *
 * An entry declares EITHER a single 'section' (apply() takes and returns that
 * section's blob) OR a 'sections' list (issue #1898 — apply() takes and returns a
 * section => blob map, persisted under one write_config()).
 *
 * @return list<array{id:string,section?:string,sections?:list<string>,apply:callable,message:string,since:string}>
 */
function pfb_migration_registry(): array
{
	$dnsbl = 'installedpackages/pfblockerngdnsblsettings/config/0';

	return [
		// 0. issue #1898: retire the compatibility-only stored per-row key name. The
		// scalar-section renames now live as registry 'old_name' slots consumed by
		// pfb_registry_pass() (issue #1921); this entry keeps only what that pass
		// cannot reach -- the dynamic per-feed row key. Multi-section ('sections',
		// not 'section') because the spec still names both affected paths.
		[
			'id'       => 'issue1898-legacy-key-rename',
			'sections' => [$dnsbl, 'installedpackages/pfblockerngdnsbl/config'],
			'apply'    => 'pfb_legacy_key_rename_migrate',
			'message'  => 'pfBlockerNG: retire legacy configuration key names (issue #1898)',
			'since'    => '3.2.0',
		],
		// 1. issue #1907: disable pfb_py_reply/pfb_hsts when inert under pre-upgrade
		// Unbound mode. MUST run immediately before adr02-dnsbl-python-mode -- it reads
		// 'dnsbl_mode' as pre-upgrade evidence that the very next entry overwrites.
		[
			'id'      => 'issue1907-python-gated-toggles',
			'section' => $dnsbl,
			'apply'   => 'pfb_python_gated_toggles_migrate',
			'message' => 'pfBlockerNG: disable python-gated DNSBL toggles inert under pre-upgrade Unbound mode (issue #1907)',
			'since'   => '3.2.0',
		],
		// 2. ADR-02: force DNSBL to python-only mode.
		[
			'id'      => 'adr02-dnsbl-python-mode',
			'section' => $dnsbl,
			'apply'   => 'pfb_dnsbl_python_migrate',
			'message' => 'pfBlockerNG: migrated DNSBL to Python-only mode',
			'since'   => '2.0.0',
		],
		// 3. PFBL-03: one-time seed of the deprecated legacy DNS-TXT control toggle --
		// a cross-key bespoke seed keyed on pfb_control's value, not a simple
		// absent/''-map, so pfb_registry_pass() cannot express it either
		// (CfgRegistryGrandfatherGateTest::EXCEPTIONS).
		[
			'id'      => 'pfbl03-control-legacy-seed',
			'section' => $dnsbl,
			'apply'   => 'pfb_control_legacy_seed',
			'message' => 'pfBlockerNG: seeded legacy DNSBL control toggle (PFBL-03)',
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
		// issue #1898: an entry may declare a LIST of sections instead of one. Its apply()
		// then receives, and returns, a section => blob map, and the whole set is persisted
		// under a SINGLE write_config() -- so a migration spanning several sections is
		// all-or-nothing rather than one flush per section.
		if (isset($migration['sections'])) {
			$blobs = [];
			foreach ($migration['sections'] as $section) {
				$blobs[$section] = PfbConfig::readSection($section);
			}
			$result = ($migration['apply'])($blobs);
			if ($result !== NULL) {
				foreach ($result as $section => $data) {
					// issue #1895: upgrade migrations run with no web session in scope.
					// issue #1921: RAW write-back -- a migration transforms raw storage;
					// canonicalising a bystander key here, ahead of pfb_registry_pass(),
					// would destroy the raw value that pass needs to grandfather.
					PfbConfig::writeSectionRawSystem($section, $data);
				}
				write_config($migration['message']);
			}
			continue;
		}
		$cfg    = PfbConfig::readSection($migration['section']);
		$result = ($migration['apply'])($cfg);
		if ($result !== NULL) {
			// issue #1895: upgrade migrations run with no web session in scope.
			// issue #1921: RAW write-back -- see the 'sections' branch above.
			PfbConfig::writeSectionRawSystem($migration['section'], $result);
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
			// issue #1895: this function runs from pfSense's firewall_aliases_edit
			// pre_write_config hook, gated only by the core firewall-alias privilege --
			// never a pfBlockerNG page privilege -- so a plain writeSection() here would
			// break that supported path. System-context write is correct, not a workaround.
			PfbConfig::writeSectionSystem($path, $rows);
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
			PfbConfig::writeSectionSystem($path, $cfg);
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
 * pfb_dnsbl_regex_rules.py (the ONE Python copy -- the resolver imports it and this
 * file's validator probe runs it), and the Pattern/Comment token pair in
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
 * Runs pfb_dnsbl_regex_rules.py (issue #1765) as the save-time probe -- the
 * SAME module pfb_unbound.py imports, not a duplicated nowdoc.
 *
 * @param bool $regex_cap Mirrors the "Limit long/complex regex" toggle: gates the
 *     save-time length-cap diagnostic so it agrees with the resolver's load-time drop.
 * @param ?string $script Test seam, like $python and $timeout_bin: NULL resolves the
 *     shipped module beside this file, which is what production always uses.
 * @return array<int, string> Non-empty validation or infrastructure diagnostics.
 */
function pfb_dnsbl_regex_validation_errors(string $contents, string $python, bool $regex_cap, string $timeout_bin = '/usr/bin/timeout', ?string $script = NULL): array
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
	$script = $script ?? __DIR__ . '/pfb_dnsbl_regex_rules.py';
	// is_file() as well as is_readable(): a directory is readable, and handing one to
	// the interpreter would surface a generic launcher diagnostic instead of this one.
	if (!is_file($script) || !is_readable($script)) {
		return ['Python regex validator: rules module unavailable'];
	}
	$stderr = tmpfile();
	if ($stderr === FALSE) {
		return ['Python regex validator: unable to create diagnostics file'];
	}
	$stderr_path = stream_get_meta_data($stderr)['uri'];
	$command = array($timeout_bin, '-s', 'TERM', '-k', '1', '5', $python, $script, $regex_cap ? '1' : '0');
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
// when ''); escaping matches pfb_syslog_format_ip. pfb_unified_format_ip/_dnsreply
// render comma-joined unified.log rows; Amendment 4 keeps the DNSBL formatter as a
// pure schema oracle while production preserves the Python writer's RFC4180 bytes.
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
 * pfb_unified_format_dnsbl — render plain DNSBL fields as a comma-joined string.
 *
 * Retained as the pure 11-column schema/compatibility oracle. ADR-38 Amendment 4:
 * the production daemon preserves the Python writer's RFC4180 row bytes instead,
 * because this formatter deliberately applies no escaping.
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
	if (PfbConfig::read('gen/log_syslog') !== PfbToggle::On) {
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
 * Returns NULL on absent file, I/O error, any corruption, OR a lock-acquire
 * timeout (fail-safe: absent is always treated as "due now" by
 * pfb_due_ledger_is_due_from_entry). Only the timeout also sets $unavailable --
 * see below, and never conflate the two.
 *
 * issue #1780: a bounded lock acquire can also EXPIRE -- that is NOT the
 * same as "absent" (NULL already means "absent / corrupt" to every existing
 * caller), so it is signalled out-of-band via $unavailable, never via the
 * return value (the public return type/contract is unchanged, so every www/
 * consumer keeps compiling and rendering exactly as before). $unavailable is
 * set TRUE ONLY when the lock acquire itself timed out; every other path
 * (success, absent file, corrupt JSON, unreadable file) sets it FALSE. A
 * caller that gates a dispatch or persistence decision on this read MUST
 * treat $unavailable===TRUE as "I do not know" -- fail closed, never write
 * back, never treat it as "due" or "absent".
 *
 * @param string    $job_key      Job identifier (e.g. 'dcc', 'bl').
 * @param string    $ledger_dir   Directory that contains pfb_due_ledger.json.
 * @param float     $timeout_s    Bounded SH-acquire budget in seconds (issue #1780).
 * @param bool|null $unavailable  Out param: TRUE iff the lock acquire expired.
 * @return array|null             {last_run: int, next_due: int, jitter: int} or NULL.
 */
function pfb_due_ledger_read_entry(string $job_key, string $ledger_dir, float $timeout_s = 5.0, ?bool &$unavailable = NULL): ?array
{
	$unavailable = FALSE;
	$path = $ledger_dir . '/pfb_due_ledger.json';
	if (!is_file($path)) {
		return NULL;
	}
	$fp = @fopen($path, 'r');
	if ($fp === FALSE) {
		return NULL;
	}
	if (!pfb_flock_bounded($fp, LOCK_SH, $timeout_s)) {
		fclose($fp);
		pfb_logger("\nADR-43: due-ledger read lock timed out [ {$path} ]", 2);
		$unavailable = TRUE;
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
 * issue #1780: a lock-acquire expiry on the underlying read must fail
 * CLOSED (FALSE), never fall through to is_due_from_entry(NULL, ...)'s
 * "absent ⇒ due" rule -- an unreadable (but not actually absent) ledger must
 * never look spuriously due.
 *
 * @param string $job_key     Job identifier (e.g. 'dcc', 'bl_weekly').
 * @param int    $interval    Job cadence in seconds (for API parity; not used here).
 * @param int    $now         Current epoch timestamp (injectable in tests).
 * @param string $seed        Per-install seed (for API parity; not used here).
 * @param int    $jitter_max  Max jitter in seconds (for API parity; not used here).
 * @param string $ledger_dir  Directory that contains pfb_due_ledger.json.
 * @param float  $timeout_s   Bounded lock-acquire budget in seconds (issue #1780; injectable for tests).
 * @return bool               TRUE iff the job should run this tick.
 */
function pfb_due_ledger_is_due(
	string $job_key,
	int    $interval,
	int    $now,
	string $seed,
	int    $jitter_max,
	string $ledger_dir,
	float  $timeout_s = 5.0
): bool {
	$unavailable = FALSE;
	$entry = pfb_due_ledger_read_entry($job_key, $ledger_dir, $timeout_s, $unavailable);
	if ($unavailable) {
		return FALSE;
	}
	return pfb_due_ledger_is_due_from_entry($entry, $now);
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
 * issue #1780: deliberately takes NO $unavailable channel, unlike its sibling
 * readers. Its own read is a best-effort ANCHOR lookup, not a dispatch or
 * persistence decision: an unreadable entry falls through to the base = $now
 * branch above, which is the same conservative catch-up-from-now the NULL case
 * already takes. There is no "looks due when it is not" collision to close here.
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
 * Accepts the raw string from PfbConfig::read('gen/pfb_tick_interval') and returns an int
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
 * wall-clock dependencies. SafeSearch and apply reconciliation have their own zero-jitter 900-second entries.
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
	$ss_refresh_due = pfb_due_ledger_is_due('ss_refresh', 900, $now, $seed, 0, $dbdir);

	return [
		'cron'       => pfb_due_ledger_is_due('cron',       $cron_interval, $now, $seed, 0,          $dbdir),
		'dcc'        => pfb_due_ledger_is_due('dcc',        86400,          $now, $seed, $jitter_max, $dbdir),
		'bl'         => pfb_due_ledger_is_due('bl',         $bl_interval,   $now, $seed, $jitter_max, $dbdir),
		'ss_refresh' => $ss_refresh_due,
		'apply_reconcile' => pfb_due_ledger_is_due('apply_reconcile', 900, $now, $seed, 0, $dbdir),
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
 * issue #1780: a lock-acquire expiry on the underlying read must ABORT
 * this write entirely -- falling through to the "absent" placeholder branch
 * would persist a ZEROED {last_run:0, next_due:0, jitter:0} entry over a REAL
 * (but momentarily unreadable) schedule, since write_entry()'s own unlocked
 * merge-read would pick the real entry back up off disk and stomp its
 * next_due/last_run to 0 with the placeholder.
 *
 * @param string $job_key    Job identifier (e.g. 'cron', 'dcc', 'bl').
 * @param string $ledger_dir Directory that contains pfb_due_ledger.json.
 * @param float  $timeout_s  Bounded lock-acquire budget in seconds (issue #1780; injectable for tests).
 * @return void
 */
function pfb_due_ledger_set_pending(string $job_key, string $ledger_dir, float $timeout_s = 5.0): void
{
	$unavailable = FALSE;
	$entry = pfb_due_ledger_read_entry($job_key, $ledger_dir, $timeout_s, $unavailable);
	if ($unavailable) {
		// The read already logged the expiry loudly -- abort, never persist a
		// zeroed placeholder over a real entry we simply could not read this instant.
		return;
	}
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
 * issue #1780: a lock-acquire expiry on the underlying read must return
 * FALSE -- an unreadable ledger is not evidence of a pending deferred apply.
 *
 * @param string $job_key    Job identifier (e.g. 'cron', 'dcc', 'bl').
 * @param string $ledger_dir Directory that contains pfb_due_ledger.json.
 * @param float  $timeout_s  Bounded lock-acquire budget in seconds (issue #1780; injectable for tests).
 * @return bool              TRUE when pending_apply is set and not yet cleared.
 */
function pfb_due_ledger_is_pending(string $job_key, string $ledger_dir, float $timeout_s = 5.0): bool
{
	$unavailable = FALSE;
	$entry = pfb_due_ledger_read_entry($job_key, $ledger_dir, $timeout_s, $unavailable);
	if ($unavailable) {
		return FALSE;
	}
	return $entry !== NULL && !empty($entry['pending_apply']);
}

/**
 * pfblockerng_tick — ADR-43: apply-on-change due-ledger tick dispatcher.
 *
 * Reads the ledger and handles both cadence advancement and separate-process dispatch via
 * exec() for each due job (feeds, dcc, bl). SafeSearch and apply reconciliation run when
 * their own due-ledger entries are due; scheduled log maintenance (pfb_log_mgmt) runs only
 * on an idle tick (see below).
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
 *   feed cron : PfbConfig::read('gen/pfb_interval') hours; skip scheduled runs when 'Disabled'.
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
 *
 * $ps_lines is injectable for hermetic off-appliance tests; NULL preserves the
 * appliance's host process-table scan. $ss_refresh is an optional test seam; NULL calls
 * the production SafeSearch refresher. $ss_lock_opener and $ss_lock_timeout are test seams
 * for the bounded refresh lock; defaults use fopen() and a 5-second budget. The apply
 * reconciliation callable, lock opener, and timeout are equivalent test seams.
 */
function pfblockerng_tick(
	?array $ps_lines = NULL,
	?callable $ss_refresh = NULL,
	?callable $ss_lock_opener = NULL,
	float $ss_lock_timeout = 5.0,
	?callable $apply_reconcile = NULL,
	?callable $apply_lock_opener = NULL,
	float $apply_lock_timeout = 5.0
): void
{
	global $pfb;

	$now   = time();
	$seed  = pfb_tick_seed();
	$dbdir = $pfb['dbdir'];
	// Set TRUE by any branch below that actually dispatches (exec()s) an update pass
	// this tick -- gates the log-maintenance race guard at the tail of this function.
	$dispatched = FALSE;

	// --- Cadence from legacy knobs ---
	$raw_interval  = PfbConfig::read('gen/pfb_interval');
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
	$window = (string) PfbConfig::read('gen/pfb_quiet_hours');
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
	// issue #1780: a lock-acquire expiry on this read must NOT dispatch,
	// NOT mark ran, and must leave the ledger untouched -- $cron_unavailable
	// gates the whole decision below regardless of what $due['cron'] (a
	// SEPARATE read, inside pfb_tick_due_jobs() above) came back as, so a
	// timeout here can never be raced into a spurious dispatch by that other
	// read having happened to succeed. $dispatched stays FALSE, so log
	// maintenance below still runs; the read itself already logged the expiry
	// loudly. The next tick retries.
	$cron_unavailable = FALSE;
	$cron_entry        = pfb_due_ledger_read_entry('cron', $dbdir, 5.0, $cron_unavailable);
	$cron_pending      = !$cron_unavailable && $cron_entry !== NULL && !empty($cron_entry['pending_apply']);
	if (!$cron_unavailable && ((!$cron_disabled && $due['cron']) || $cron_pending)) {
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
	if (($due['bl'] || pfb_due_ledger_is_pending('bl', $dbdir)) && $pfb['enable'] === PfbToggle::On &&
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

	// SafeSearch CNAME freshness: independent 900-second due-ledger cadence.
	if ($due['ss_refresh']) {
		$ss_lock_path = "{$dbdir}/pfb_ss_refresh.lock";
		$ss_default_opener = ($ss_lock_opener === NULL);
		$ss_lock = $ss_default_opener ? @fopen($ss_lock_path, 'c') : $ss_lock_opener($ss_lock_path);
		if ($ss_lock === FALSE) {
			pfb_logger("\nTick: SafeSearch lock open failed [ {$ss_lock_path} ]", 2);
		} else {
			$ss_lock_timed_out = FALSE;
			if (!pfb_flock_bounded($ss_lock, LOCK_EX, $ss_lock_timeout, $ss_lock_timed_out)) {
				$reason = $ss_lock_timed_out ? 'timed out' : 'acquire failed';
				pfb_logger("\nTick: SafeSearch lock {$reason} [ {$ss_lock_path} ]", 2);
				if ($ss_default_opener) {
					@fclose($ss_lock);
				}
			} else {
				try {
					// Another tick may have completed while this one waited for the lock.
					if (pfb_due_ledger_is_due('ss_refresh', 900, $now, $seed, 0, $dbdir)) {
						if ($ss_refresh !== NULL) {
							$ss_refresh();
						} else {
							pfblockerng_ss_refresh();
						}
						pfb_due_ledger_mark_ran_anchored('ss_refresh', 900, $now, $seed, 0, $dbdir);
					}
				} finally {
					@flock($ss_lock, LOCK_UN);
					@fclose($ss_lock);
				}
			}
		}
	}

	// ADR-61: apply-stage reconciliation has its own zero-jitter 900-second
	// ledger entry, independent of feed tick cadence. Only apply entries are touched.
	if ($due['apply_reconcile']) {
		$apply_lock_path = "{$dbdir}/pfb_apply_reconcile.lock";
		$apply_default_opener = ($apply_lock_opener === NULL);
		$apply_lock = $apply_default_opener ? @fopen($apply_lock_path, 'c') : $apply_lock_opener($apply_lock_path);
		if ($apply_lock === FALSE || !is_resource($apply_lock)) {
			pfb_logger("\nTick: apply reconciliation lock open failed [ {$apply_lock_path} ]", 2);
		} else {
			$apply_lock_timed_out = FALSE;
			if (!pfb_flock_bounded($apply_lock, LOCK_EX, $apply_lock_timeout, $apply_lock_timed_out)) {
				$reason = $apply_lock_timed_out ? 'timed out' : 'acquire failed';
				pfb_logger("\nTick: apply reconciliation lock {$reason} [ {$apply_lock_path} ]", 2);
				if ($apply_default_opener) {
					@fclose($apply_lock);
				}
			} else {
				try {
					// Another tick may have completed while this one waited for the lock.
					if (pfb_due_ledger_is_due('apply_reconcile', 900, $now, $seed, 0, $dbdir)) {
						if ($apply_reconcile !== NULL) {
							$apply_reconcile();
						} else {
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
						}
						pfb_due_ledger_mark_ran_anchored('apply_reconcile', 900, $now, $seed, 0, $dbdir);
					}
				} catch (Throwable $e) {
					pfb_logger("\nTick: apply reconciliation failed: {$e->getMessage()}", 2);
				} finally {
					@flock($apply_lock, LOCK_UN);
					if ($apply_default_opener) {
						@fclose($apply_lock);
					}
				}
			}
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
	if (!$dispatched && !pfb_update_pass_running($ps_lines)) {
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
// when apply_reconcile is due. Tests: tests/php/PfbSyncStatusLedgerTest.php
// ---------------------------------------------------------------------------

/**
 * pfb_sync_status_read_all — read the full ledger as a nested array.
 *
 * Absent file, unreadable file, corrupt/non-object JSON, or a lock-acquire
 * timeout all read as an empty ledger (fail-open for display), never throws.
 * Only the timeout also sets $unavailable -- see below, and never conflate the
 * two: [] alone cannot tell a caller which happened.
 *
 * issue #1780: a bounded lock acquire can also EXPIRE -- that is NOT the
 * same as "empty" ([] already means "empty ledger" to every existing caller),
 * so it is signalled out-of-band via $unavailable, never via the return value
 * (the public return type/contract is unchanged, so every www/ consumer keeps
 * compiling and rendering exactly as before). $unavailable is set TRUE ONLY
 * when the lock acquire itself timed out; every other path (success, absent
 * file, corrupt JSON, unreadable file) sets it FALSE. A caller that performs a
 * read-modify-write on this data (open/close, below) MUST treat
 * $unavailable===TRUE as "I do not know" -- abort, never write back an
 * apparently-empty (in truth just-unreadable) ledger over intact data.
 *
 * @param string    $ledger_dir   Directory that contains pfb_sync_status.json.
 * @param float     $timeout_s    Bounded SH-acquire budget in seconds (issue #1780).
 * @param bool|null $unavailable  Out param: TRUE iff the lock acquire expired.
 * @return array<string,array<string,array<string,array{message:string,first_seen:int,last_seen:int}>>>
 */
function pfb_sync_status_read_all(string $ledger_dir, float $timeout_s = 5.0, ?bool &$unavailable = NULL): array
{
	$unavailable = FALSE;
	$path = $ledger_dir . '/pfb_sync_status.json';
	if (!is_file($path)) {
		return [];
	}
	$fp = @fopen($path, 'r');
	if ($fp === FALSE) {
		return [];
	}
	if (!pfb_flock_bounded($fp, LOCK_SH, $timeout_s)) {
		fclose($fp);
		pfb_logger("\nADR-61: sync-status ledger read lock timed out [ {$path} ]", 2);
		$unavailable = TRUE;
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
 * @param float    $timeout_s  Bounded EX-acquire budget in seconds (issue #1780).
 * @return void
 */
function pfb_sync_status_locked(string $ledger_dir, callable $fn, float $timeout_s = 5.0): void
{
	$lock_path = $ledger_dir . '/pfb_sync_status.json.lock';
	$fp        = @fopen($lock_path, 'c');
	if ($fp === FALSE) {
		$fn();	// can't open (unwritable dir) -- degrade to best-effort, same fail-open contract as write_all()
		return;
	}
	if (!pfb_flock_bounded($fp, LOCK_EX, $timeout_s)) {
		fclose($fp);
		// issue #1780: the acquire timed out -- log it loudly (observable, was
		// silent) before degrading to the same fail-open contract as above.
		pfb_logger("\nADR-61: sync-status ledger lock timed out [ {$lock_path} ] -- proceeding unlocked", 2);
		$fn();
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
 * issue #1780: if the read-modify-write's own read of the ledger
 * (pfb_sync_status_read_all(), a SEPARATE lock from this function's outer EX
 * span below) expires, this call ABORTS -- it never persists an
 * apparently-empty (in truth just-unreadable) ledger over intact data, and
 * never adds the new key it was asked to open either.
 *
 * @param string        $facility   'ip' | 'dnsbl'.
 * @param string        $item       The alias/group/feed name the entry is about.
 * @param string        $stage      'download' | 'parse' | 'apply' | 'dedup'.
 * @param string        $message    Human-readable failure description.
 * @param string        $ledger_dir Directory that contains pfb_sync_status.json.
 * @param callable|null $clock_fn   Returns the current epoch timestamp; defaults to time().
 * @param float         $timeout_s  Bounded lock-acquire budget in seconds (issue #1780; injectable for tests).
 * @return void
 */
function pfb_sync_status_open(
	string    $facility,
	string    $item,
	string    $stage,
	string    $message,
	string    $ledger_dir,
	?callable $clock_fn = null,
	float     $timeout_s = 5.0
): void {
	$now = ($clock_fn !== NULL) ? $clock_fn() : time();
	pfb_sync_status_locked($ledger_dir, function () use ($facility, $item, $stage, $message, $now, $ledger_dir, $timeout_s) {
		$unavailable = FALSE;
		$data = pfb_sync_status_read_all($ledger_dir, $timeout_s, $unavailable);
		if ($unavailable) {
			// The read already logged the expiry loudly -- abort the read-modify-write
			// rather than risk persisting an empty-looking ledger over intact data.
			return;
		}
		$existing   = $data[$facility][$item][$stage] ?? NULL;
		$first_seen = (is_array($existing) && isset($existing['first_seen'])) ? $existing['first_seen'] : $now;

		$data[$facility][$item][$stage] = [
			'message'    => $message,
			'first_seen' => $first_seen,
			'last_seen'  => $now,
		];
		pfb_sync_status_write_all($data, $ledger_dir);
	}, $timeout_s);
}

/**
 * pfb_sync_status_close — clear one {facility,item,stage} entry, if open.
 *
 * Closing an absent key is a safe no-op — no write, no exception.
 *
 * issue #1780: if the read-modify-write's own read of the ledger
 * expires, this call ABORTS -- same rationale as pfb_sync_status_open() above.
 *
 * @param string $facility   'ip' | 'dnsbl'.
 * @param string $item       The alias/group/feed name the entry is about.
 * @param string $stage      'download' | 'parse' | 'apply' | 'dedup'.
 * @param string $ledger_dir Directory that contains pfb_sync_status.json.
 * @param float  $timeout_s  Bounded lock-acquire budget in seconds (issue #1780; injectable for tests).
 * @return void
 */
function pfb_sync_status_close(string $facility, string $item, string $stage, string $ledger_dir, float $timeout_s = 5.0): void
{
	pfb_sync_status_locked($ledger_dir, function () use ($facility, $item, $stage, $ledger_dir, $timeout_s) {
		$unavailable = FALSE;
		$data = pfb_sync_status_read_all($ledger_dir, $timeout_s, $unavailable);
		if ($unavailable) {
			return;
		}
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
	}, $timeout_s);
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
		$cfg_key        = $is_v6 ? 'v6suppression' : 'v4suppression';	// bare -- blob index
		$cfg_key_path   = $is_v6 ? 'ip/v6suppression' : 'ip/v4suppression';	// issue #1931: gateway key
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
			PfbConfig::write($cfg_key_path, $clists[$supp_key]['base64']);
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
 * @param callable|null $now Monotonic clock seam for deterministic wait tests.
 * @return array{blocked:bool,b_type:string,group:string,b_eval:string,feed:string,p_type:string}|null
 *         The matcher's verdict, or NULL when none was obtained (invalid domain,
 *         request-encode, lock open/acquire, or write failure; timeout; or a malformed reply)
 *         -- callers must treat NULL and blocked=false identically ("no block"),
 *         never distinguish them.
 */
function pfb_dnsbl_query(string $domain, string $qtype = 'A', float $timeout_s = 5.0, ?callable $now = NULL): ?array {
	global $pfb;
	$now ??= static fn (): float => microtime(TRUE);

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
	$deadline  = $now() + $wait_s;
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
		if (!$allow_expired_attempt && $now() >= $deadline) {
			break;
		}
		$would_block = 0;
		if (@flock($lock, LOCK_EX | LOCK_NB, $would_block)) {
			// A waiter can be descheduled between its deadline check and flock().
			// Never publish after that budget expires; timeout=0 still gets one
			// immediate non-blocking attempt.
			if (!$allow_expired_attempt && $now() >= $deadline) {
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
		$remaining_s = $deadline - $now();
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
			if (!$allow_expired_poll && $now() >= $deadline) {
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
						if (!$allow_expired_poll && $now() >= $deadline) {
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
			$remaining_s = $deadline - $now();
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

/** Return the shared Update sub-tabs with the requested tab active. */
function pfb_edit_hooks_tabs(string $active): array
{
	return [
		[gettext('Run'), $active === 'run', '/pfblockerng/pfblockerng_update.php'],
		[gettext('Hooks'), $active === 'hooks', '/pfblockerng/pfblockerng_hooks.php'],
		[gettext('Edit Hooks'), $active === 'edit', '/pfblockerng/pfblockerng_edit_hooks.php'],
	];
}

/** Build the default Edit Hooks request state, with an optional redirect. */
function pfb_edit_hooks_default_state(?string $redirect = NULL): array
{
	return [
		'errors' => [], 'sel_when' => '', 'sel_script' => '', 'content' => '',
		'new_core' => '', 'new_lang' => 'sh', 'new_when' => '', 'notice' => NULL,
		'redirect' => $redirect,
	];
}

/** Shared warning content for the root-equivalent Edit Hooks surface. */
function pfb_edit_hooks_warning(): array
{
	return [
		'style' => 'danger',
		'title' => gettext('Advanced Users Only'),
		'message' => gettext('The capabilities offered here can be dangerous. No support is available. Scripts you create or edit on this page run as ROOT during every pfBlockerNG update pass -- the same trust class as pfSense Diagnostics > Command Prompt / Edit File. Use them at your own risk!'),
	];
}

/** Return the redirect used when the page's secondary privilege gate refuses access. */
function pfb_edit_hooks_access(bool $allowed): ?string
{
	return $allowed ? NULL : '/index.php';
}

/** Preserve form values exactly; Form_Input/Form_Textarea escape at render. */
function pfb_edit_hooks_form_value(mixed $value): mixed
{
	return $value;
}

/** Native submit-field names used by the create/save buttons. */
function pfb_edit_hooks_submit_field(string $action): string
{
	return in_array($action, ['create', 'save'], TRUE) ? 'pfb_eh_' . $action : '';
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
