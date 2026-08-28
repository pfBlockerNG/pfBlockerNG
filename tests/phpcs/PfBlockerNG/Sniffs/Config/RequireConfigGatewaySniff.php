<?php

/*
 * ADR-29 / issue #1895 — enforce the config-gateway access rules mechanically.
 *
 * Carries two independent checks (two error codes, one sniff class):
 *
 * CHECK 1 — RawRegisteredKeyAccess (ADR-29).
 * Flags any config_get_path / config_set_path / config_del_path call whose
 * first argument is a static string literal that resolves to a REGISTERED
 * installedpackages/pfblockerng* key (i.e. a key present in
 * pfb_cfg_registry()).  Raw access outside the PfbConfig gateway is a
 * regression risk; all registered keys MUST be read/written through
 * PfbConfig::read() / PfbConfig::write() / PfbConfig::delete().
 *
 * PRECISE by design — does NOT flag:
 *   a) Dynamic-path calls (first argument contains a variable or expression).
 *   b) Non-registered / foreign keys (pfblockerngipsettings/*, widget-*,
 *      per-row/per-feed/per-continent dynamic structures, pfSense-core
 *      sections: aliases/*, filter/*, system/*, interfaces, unbound/*).
 *   c) Section-level calls (path stops at the section, no trailing key name).
 *   d) The gateway's own implementation (pfblockerng_extra.inc) — excluded
 *      via phpcs.xml.dist <exclude-pattern>.
 *   e) Out-of-scope keys documented in ADR-29 §2.5 (e.g. 'dnsbl_webpage' — a
 *      foreign key written directly by pfblockerng_dnsbl.php and read via
 *      pfb_dnsbl_webpage(); it is not in the registered path set).
 *
 * Scope is an explicit, auditable list of full config paths (the registered
 * paths derived from pfb_cfg_registry()) embedded as a sniff property.  The
 * list must be kept in sync with pfb_cfg_registry() in pfblockerng_extra.inc.
 *
 * CHECK 2 — SystemWriteInWww (issue #1895).
 * PfbConfig::writeSystem() / PfbConfig::writeSectionSystem() / (issue #1921)
 * writeSectionRawSystem() write with NO per-field write_priv authorization check
 * (see the docblocks on those methods in pfblockerng_extra.inc) — they exist only
 * for no-session system callers (cron/install/migrations/CLI/core hooks). Any file
 * whose path (normalised to forward slashes) contains "/usr/local/www/" — the
 * pfSense web UI, which always runs inside an authenticated session — MUST NOT
 * call any of the three; it flags a static PfbConfig::writeSystem(...) /
 * PfbConfig::writeSectionSystem(...) / PfbConfig::writeSectionRawSystem(...) call
 * (case-insensitive method AND class name, matching PHP's own case-insensitivity)
 * wherever it appears under www/.
 *
 * PRECISE by design, same T_STRING-token mechanism as check 1 — does NOT
 * flag:
 *   a) The same call outside www/ (e.g. pfblockerng_extra.inc itself, cron/
 *      install/migration code under pkg/pfblockerng/) — the legitimate
 *      system-caller use case.
 *   b) PfbConfig::write() / PfbConfig::writeSection() (authorization-checked
 *      variants) — different method name.
 *   c) The same method name on any class other than PfbConfig.
 *   d) A comment or string literal that merely mentions
 *      "PfbConfig::writeSystem" — T_STRING only matches real code tokens.
 *
 * OUT OF SCOPE by design (static greppability, not full data-flow analysis):
 * a call reached through an alias/variable (`$c::writeSystem()`) or through
 * reflection/`call_user_func()` will NOT be flagged.
 *
 * Wired from phpcs.xml.dist as PfBlockerNG.Config.RequireConfigGateway.
 */

namespace PfBlockerNG\Sniffs\Config;

use PHP_CodeSniffer\Files\File;
use PHP_CodeSniffer\Sniffs\Sniff;
use PHP_CodeSniffer\Util\Tokens;

class RequireConfigGatewaySniff implements Sniff
{
	/**
	 * Raw config API calls that are gated.
	 *
	 * @var string[]
	 */
	private const GATED_FUNCTIONS = [
		'config_get_path',
		'config_set_path',
		'config_del_path',
	];

	/**
	 * PfbConfig methods that bypass per-field write_priv authorization (#1895) —
	 * confined to no-session system callers (cron/install/migrations/CLI/core
	 * hooks). Lower-case; compared case-insensitively (PHP method names are
	 * case-insensitive).
	 *
	 * @var string[]
	 */
	private const SYSTEM_WRITE_METHODS = [
		'writesystem',
		'writesectionsystem',
		// issue #1921: writeSectionRawSystem() also bypasses per-field write_priv
		// authorization (same no-session system-caller contract) -- reserved for
		// migrations/install/upgrade, never www/.
		'writesectionrawsystem',
	];

	/**
	 * Substring a normalised (forward-slash) file path must contain for the
	 * SystemWriteInWww check to apply — the pfSense web UI tree.
	 */
	private const WWW_PATH_MARKER = '/usr/local/www/';

	/**
	 * The complete set of registered installedpackages/pfblockerng* key paths.
	 *
	 * Each entry is the full config.xml path: <section>/<key>.  Only a static
	 * string first argument that exactly matches one of these paths is flagged.
	 *
	 * Source of truth: pfb_cfg_registry() in pfblockerng_extra.inc.
	 * Keep in sync when a new key is added to the registry.
	 *
	 * @var string[]
	 */
	public $registeredPaths = [
		// installedpackages/pfblockerng/config/0 (general settings)
		// Settings snapshot schema marker (drift caught by issue #1902 parity test).
		'installedpackages/pfblockerng/config/0/settings_family',
		'installedpackages/pfblockerng/config/0/enable_cb',
		'installedpackages/pfblockerng/config/0/pfb_keep',
		'installedpackages/pfblockerng/config/0/pfb_scheduled_feed_updates',
		'installedpackages/pfblockerng/config/0/pfb_schedule_weekday',
		'installedpackages/pfblockerng/config/0/pfb_schedule_hour',
		'installedpackages/pfblockerng/config/0/pfb_schedule_minute',
		'installedpackages/pfblockerng/config/0/skipfeed',
		'installedpackages/pfblockerng/config/0/pfb_agg_types',
		'installedpackages/pfblockerng/config/0/log_max_log',
		'installedpackages/pfblockerng/config/0/log_max_errlog',
		'installedpackages/pfblockerng/config/0/log_max_extraslog',
		'installedpackages/pfblockerng/config/0/log_max_ip_blocklog',
		'installedpackages/pfblockerng/config/0/log_max_ip_permitlog',
		'installedpackages/pfblockerng/config/0/log_max_ip_matchlog',
		'installedpackages/pfblockerng/config/0/log_max_ip_parse_err',
		'installedpackages/pfblockerng/config/0/log_max_dnslog',
		'installedpackages/pfblockerng/config/0/log_max_dnsbl_parse_err',
		'installedpackages/pfblockerng/config/0/log_max_dnsreplylog',
		'installedpackages/pfblockerng/config/0/log_max_unilog',
		// ADR-60: per-log age-based retention cap (days; '0' = off)
		'installedpackages/pfblockerng/config/0/log_max_days_log',
		'installedpackages/pfblockerng/config/0/log_max_days_errlog',
		'installedpackages/pfblockerng/config/0/log_max_days_extraslog',
		'installedpackages/pfblockerng/config/0/log_max_days_ip_blocklog',
		'installedpackages/pfblockerng/config/0/log_max_days_ip_permitlog',
		'installedpackages/pfblockerng/config/0/log_max_days_ip_matchlog',
		'installedpackages/pfblockerng/config/0/log_max_days_ip_parse_err',
		'installedpackages/pfblockerng/config/0/log_max_days_dnslog',
		'installedpackages/pfblockerng/config/0/log_max_days_dnsbl_parse_err',
		'installedpackages/pfblockerng/config/0/log_max_days_dnsreplylog',
		'installedpackages/pfblockerng/config/0/log_max_days_unilog',
		'installedpackages/pfblockerng/config/0/pfb_software_check',
		'installedpackages/pfblockerng/config/0/pfb_feed_internal_filter',
		'installedpackages/pfblockerng/config/0/pfb_feed_internal_allowlist',
		// ADR-49: opt-in plain-text feed sanity scan toggle
		'installedpackages/pfblockerng/config/0/pfb_feed_sanity',
		'installedpackages/pfblockerng/config/0/pfb_reuse',
		// ADR-40: alias-table apply mode + batch size
		'installedpackages/pfblockerng/config/0/pfb_alias_delta_mode',
		'installedpackages/pfblockerng/config/0/pfb_alias_delta_batch',
		// ADR-43: apply-on-change window
		'installedpackages/pfblockerng/config/0/pfb_quiet_hours',
		// issue #1109: log-retention trim hysteresis margin percent
		'installedpackages/pfblockerng/config/0/pfb_log_trim_margin_pct',
		// installedpackages/pfblockerngdnsblsettings/config/0 (DNSBL settings)
		'installedpackages/pfblockerngdnsblsettings/config/0/pfb_dnsbl',
		'installedpackages/pfblockerngdnsblsettings/config/0/pfb_dnsvip_auto',
		'installedpackages/pfblockerngdnsblsettings/config/0/pfb_dnsbl_nonat',
		'installedpackages/pfblockerngdnsblsettings/config/0/dnsbl_interface',
		'installedpackages/pfblockerngdnsblsettings/config/0/pfb_dnsvip4',
		'installedpackages/pfblockerngdnsblsettings/config/0/pfb_dnsvip6',
		'installedpackages/pfblockerngdnsblsettings/config/0/pfb_dnsport',
		'installedpackages/pfblockerngdnsblsettings/config/0/pfb_dnsport_ssl',
		'installedpackages/pfblockerngdnsblsettings/config/0/top1m_enable',
		'installedpackages/pfblockerngdnsblsettings/config/0/top1m_source',
		'installedpackages/pfblockerngdnsblsettings/config/0/top1m_count',
		'installedpackages/pfblockerngdnsblsettings/config/0/top1m_inclusion',
		// ADR-59 P5: masked Cloudflare Radar Bearer token
		'installedpackages/pfblockerngdnsblsettings/config/0/top1m_token',
		'installedpackages/pfblockerngdnsblsettings/config/0/pfb_cache',
		'installedpackages/pfblockerngdnsblsettings/config/0/pfb_cache_flush',
		'installedpackages/pfblockerngdnsblsettings/config/0/global_log',
		'installedpackages/pfblockerngdnsblsettings/config/0/pfb_dnsbl_lenient',
		'installedpackages/pfblockerngdnsblsettings/config/0/pfb_py_reply',
		'installedpackages/pfblockerngdnsblsettings/config/0/pfb_hsts',
		'installedpackages/pfblockerngdnsblsettings/config/0/pfb_idn',
		'installedpackages/pfblockerngdnsblsettings/config/0/pfb_idn_block_malicious',
		'installedpackages/pfblockerngdnsblsettings/config/0/pfb_idn_escalate_suspicious',
		'installedpackages/pfblockerngdnsblsettings/config/0/pfb_regex',
		'installedpackages/pfblockerngdnsblsettings/config/0/pfb_regex_list',
		'installedpackages/pfblockerngdnsblsettings/config/0/pfb_regex_cap',
		'installedpackages/pfblockerngdnsblsettings/config/0/pfb_cname',
		'installedpackages/pfblockerngdnsblsettings/config/0/tld_allow',
		'installedpackages/pfblockerngdnsblsettings/config/0/pfb_psl_include_private',
		'installedpackages/pfblockerngdnsblsettings/config/0/pfb_psl_allow_private',
		// issue #2371: feed-at-suffix PSL policy fields.
		'installedpackages/pfblockerngdnsblsettings/config/0/pfb_psl_feed_private_policy',
		'installedpackages/pfblockerngdnsblsettings/config/0/pfb_psl_feed_icann_policy',
		// issue #1921: TLD Allow sort + bucket scalars (renamed from pfb_pytld* by #1898).
		'installedpackages/pfblockerngdnsblsettings/config/0/tld_allow_sort',
		'installedpackages/pfblockerngdnsblsettings/config/0/tld_allow_gtld',
		'installedpackages/pfblockerngdnsblsettings/config/0/tld_allow_cctld',
		'installedpackages/pfblockerngdnsblsettings/config/0/tld_allow_itld',
		'installedpackages/pfblockerngdnsblsettings/config/0/tld_allow_bgtld',
		'installedpackages/pfblockerngdnsblsettings/config/0/pfb_py_nolog',
		'installedpackages/pfblockerngdnsblsettings/config/0/pfb_noaaaa',
		'installedpackages/pfblockerngdnsblsettings/config/0/pfb_noaaaa_list',
		'installedpackages/pfblockerngdnsblsettings/config/0/pfb_gp',
		'installedpackages/pfblockerngdnsblsettings/config/0/pfb_gp_bypass_list',
		'installedpackages/pfblockerngdnsblsettings/config/0/tld_wildcard_blacklist',
		'installedpackages/pfblockerngdnsblsettings/config/0/tld_wildcard_exclusion',
		'installedpackages/pfblockerngdnsblsettings/config/0/whitelist',
		'installedpackages/pfblockerngdnsblsettings/config/0/action',
		'installedpackages/pfblockerngdnsblsettings/config/0/pfb_dnsbl_rule',
		'installedpackages/pfblockerngdnsblsettings/config/0/dnsbl_allow_int',
		'installedpackages/pfblockerngdnsblsettings/config/0/pfb_control',
		'installedpackages/pfblockerngdnsblsettings/config/0/pfb_control_legacy',
		'installedpackages/pfblockerngdnsblsettings/config/0/pfb_py_cache_max',
		'installedpackages/pfblockerngdnsblsettings/config/0/tld_wildcard',
		'installedpackages/pfblockerngdnsblsettings/config/0/aliaslog',
		// ADR-36: NAT DNS-redirect fields
		'installedpackages/pfblockerngdnsblsettings/config/0/dnsbl_redir',
		'installedpackages/pfblockerngdnsblsettings/config/0/dnsbl_redir_int',
		'installedpackages/pfblockerngdnsblsettings/config/0/dnsbl_redir_exclude',
		// ADR-37: DoT/DoQ block fields
		'installedpackages/pfblockerngdnsblsettings/config/0/dnsbl_dot_block',
		'installedpackages/pfblockerngdnsblsettings/config/0/dnsbl_dot_block_int',
		'installedpackages/pfblockerngdnsblsettings/config/0/dnsbl_dot_block_exclude',
		'installedpackages/pfblockerngdnsblsettings/config/0/dnsbl_dot_block_action',
		'installedpackages/pfblockerngdnsblsettings/config/0/dnsbl_dot_block_floating',
		// ADR-38: syslog export toggle
		'installedpackages/pfblockerng/config/0/log_syslog',
		// issue #1669 slice C: CodeMirror 6 live syntax-highlight toggle (default on)
		'installedpackages/pfblockerng/config/0/pfb_syntax_highlight',
		// installedpackages/pfblockerngsafesearch (flat section, no /config/0)
		'installedpackages/pfblockerngsafesearch/safesearch_enable',
		'installedpackages/pfblockerngsafesearch/safesearch_youtube',
		'installedpackages/pfblockerngsafesearch/safesearch_doh',
		'installedpackages/pfblockerngsafesearch/safesearch_doh_list',
		// ADR-53: installedpackages/pfblockerngipsettings/config/0 (IPv4/IPv6 suppression)
		'installedpackages/pfblockerngipsettings/config/0/v4suppression',
		'installedpackages/pfblockerngipsettings/config/0/v6suppression',
		// issue #1931: IP page "Enable Suppression" toggle
		'installedpackages/pfblockerngipsettings/config/0/suppression',
		// issue #1896: installedpackages/pfblockerngreputation/config/0 (Reputation toggles)
		'installedpackages/pfblockerngreputation/config/0/enable_rep',
		'installedpackages/pfblockerngreputation/config/0/enable_pdup',
		'installedpackages/pfblockerngreputation/config/0/enable_dedup',
		// issue #2123: the IP-page checkboxes whose default moved into the registry
		'installedpackages/pfblockerngipsettings/config/0/enable_dup',
		'installedpackages/pfblockerngipsettings/config/0/enable_agg',
		'installedpackages/pfblockerngipsettings/config/0/enable_log',
		'installedpackages/pfblockerngipsettings/config/0/enable_rdns',
		'installedpackages/pfblockerngipsettings/config/0/database_cc',
		'installedpackages/pfblockerngipsettings/config/0/enable_float',
		'installedpackages/pfblockerngipsettings/config/0/killstates',
		// issue #2123: the DNSBL "Advanced In/Outbound Firewall Rule Settings" checkboxes.
		// The per-feed-row and per-continent keys of the same bare name live under
		// DYNAMIC paths, so they are unreachable by this exact-path check and stay on the
		// foreign-key exclusion list.
		'installedpackages/pfblockerngdnsblsettings/config/0/autoaddrnot_in',
		'installedpackages/pfblockerngdnsblsettings/config/0/autoports_in',
		'installedpackages/pfblockerngdnsblsettings/config/0/autoaddr_in',
		'installedpackages/pfblockerngdnsblsettings/config/0/autonot_in',
		'installedpackages/pfblockerngdnsblsettings/config/0/autoaddrnot_out',
		'installedpackages/pfblockerngdnsblsettings/config/0/autoports_out',
		'installedpackages/pfblockerngdnsblsettings/config/0/autoaddr_out',
		'installedpackages/pfblockerngdnsblsettings/config/0/autonot_out',
		// issue #2123: installedpackages/pfblockerngglobal (flat section, no /config/0)
		'installedpackages/pfblockerngglobal/alertrefresh',
		// issue #2123: installedpackages/pfblockerngsync/config/0
		'installedpackages/pfblockerngsync/config/0/syncinterfaces',
	];

	/**
	 * @return array<int, int|string>
	 */
	public function register()
	{
		return [T_STRING];
	}

	/**
	 * Dispatch to both independent checks. Neither may short-circuit the
	 * other — a T_STRING token can only match one of the two gated-name sets,
	 * but each check performs its own early return, so both always run.
	 *
	 * @param int $stackPtr
	 */
	public function process(File $phpcsFile, $stackPtr)
	{
		$this->processRawConfigPathCall($phpcsFile, (int) $stackPtr);
		$this->processSystemWriteInWww($phpcsFile, (int) $stackPtr);
	}

	/**
	 * CHECK 1 — ADR-29 RawRegisteredKeyAccess.
	 *
	 * @param int $stackPtr
	 */
	private function processRawConfigPathCall(File $phpcsFile, int $stackPtr): void
	{
		$tokens = $phpcsFile->getTokens();

		// Must be one of the gated raw API calls.
		$name = strtolower((string) $tokens[$stackPtr]['content']);
		if (!in_array($name, self::GATED_FUNCTIONS, TRUE)) {
			return;
		}

		// Must be a function call (next non-whitespace token is '(').
		if (!$this->isFunctionCall($phpcsFile, $tokens, $stackPtr)) {
			return;
		}

		// Find the opening parenthesis.
		$openParen = $phpcsFile->findNext(T_WHITESPACE, $stackPtr + 1, NULL, TRUE);
		if ($openParen === FALSE || $tokens[$openParen]['code'] !== T_OPEN_PARENTHESIS) {
			return;
		}

		// The first argument must be a static single-quoted or double-quoted string
		// literal (no variable interpolation — $tokens will be T_CONSTANT_ENCAPSED_STRING
		// for single-quoted; double-quoted with no interpolation also tokenises as a
		// single T_CONSTANT_ENCAPSED_STRING or T_DOUBLE_QUOTED_STRING).
		//
		// Skip whitespace AND comment tokens so that a comment between the opening
		// parenthesis and the first argument (e.g. config_get_path(/* note */ '...'))
		// does not evade the sniff (false negative).
		$skipTokens = [
			T_WHITESPACE,
			T_COMMENT,
			T_DOC_COMMENT,
			T_DOC_COMMENT_OPEN_TAG,
			T_DOC_COMMENT_CLOSE_TAG,
			T_DOC_COMMENT_STAR,
			T_DOC_COMMENT_WHITESPACE,
			T_DOC_COMMENT_STRING,
			T_DOC_COMMENT_TAG,
		];
		$firstArg = $openParen + 1;
		while ($firstArg < count($tokens) && in_array($tokens[$firstArg]['code'], $skipTokens, TRUE)) {
			$firstArg++;
		}
		if ($firstArg >= count($tokens)) {
			return;
		}

		$code = $tokens[$firstArg]['code'];

		// Double-quoted strings with variable interpolation are split into multiple
		// tokens by PHPCS (T_DOUBLE_QUOTED_STRING + T_VARIABLE + …).  A pure static
		// double-quoted string with no interpolation tokenises as a single
		// T_DOUBLE_QUOTED_STRING.  T_CONSTANT_ENCAPSED_STRING covers single-quoted.
		if ($code !== T_CONSTANT_ENCAPSED_STRING && $code !== T_DOUBLE_QUOTED_STRING) {
			// Not a static string literal — dynamic path; do not flag.
			return;
		}

		// Extract the path string (strip surrounding quotes).
		$raw  = (string) $tokens[$firstArg]['content'];
		$path = trim($raw, '\'"');

		// If the path itself contains a variable reference it is dynamic; skip.
		if (strpos($path, '$') !== FALSE) {
			return;
		}

		// Check against the registered path set.
		if (!in_array($path, (array) $this->registeredPaths, TRUE)) {
			return;
		}

		$phpcsFile->addError(
			sprintf(
				'ADR-29: raw %s() call targeting registered key "%s" '
				. 'must be replaced by PfbConfig::read/write/delete(). '
				. 'Direct config_*_path access to registered keys bypasses '
				. 'the gateway (defaults, adapters, canonical storage).',
				$name,
				$path
			),
			$stackPtr,
			'RawRegisteredKeyAccess'
		);
	}

	/**
	 * CHECK 2 — issue #1895 SystemWriteInWww.
	 *
	 * Flags a static PfbConfig::writeSystem(...) / PfbConfig::writeSectionSystem(...)
	 * call found anywhere under a /usr/local/www/ path. Requires the T_DOUBLE_COLON
	 * call form on the exact class name PfbConfig (case-insensitive) — the opposite
	 * shape from check 1's isFunctionCall(), which disqualifies T_DOUBLE_COLON.
	 *
	 * @param int $stackPtr
	 */
	private function processSystemWriteInWww(File $phpcsFile, int $stackPtr): void
	{
		$tokens = $phpcsFile->getTokens();

		// Must be one of the gated system-write method names.
		$name = strtolower((string) $tokens[$stackPtr]['content']);
		if (!in_array($name, self::SYSTEM_WRITE_METHODS, TRUE)) {
			return;
		}

		// Must be a call (next non-whitespace-or-comment token is '(') -- walking past
		// Tokens::$emptyTokens (whitespace AND every comment/doc-comment type), not just
		// T_WHITESPACE, so a comment wedged between the tokens (e.g.
		// PfbConfig::/*x*/writeSystem(...)) cannot evade the sniff.
		$next = $phpcsFile->findNext(Tokens::$emptyTokens, $stackPtr + 1, NULL, TRUE);
		if ($next === FALSE || $tokens[$next]['code'] !== T_OPEN_PARENTHESIS) {
			return;
		}

		// Must be a static call: previous non-whitespace-or-comment token is T_DOUBLE_COLON.
		$doubleColon = $phpcsFile->findPrevious(Tokens::$emptyTokens, $stackPtr - 1, NULL, TRUE);
		if ($doubleColon === FALSE || $tokens[$doubleColon]['code'] !== T_DOUBLE_COLON) {
			return;
		}

		// The class name immediately before '::' must be PfbConfig (case-insensitive).
		// A leading namespace separator further back (e.g. \PfbConfig::) is not
		// examined and does not disqualify the match.
		$classToken = $phpcsFile->findPrevious(Tokens::$emptyTokens, $doubleColon - 1, NULL, TRUE);
		if ($classToken === FALSE || $tokens[$classToken]['code'] !== T_STRING) {
			return;
		}
		if (strtolower((string) $tokens[$classToken]['content']) !== 'pfbconfig') {
			return;
		}

		// Only enforce under the pfSense web UI tree — the authenticated-session
		// surface these two methods are not authorized for (issue #1895).
		$filename = str_replace('\\', '/', $phpcsFile->getFilename());
		if (strpos($filename, self::WWW_PATH_MARKER) === FALSE) {
			return;
		}

		$phpcsFile->addError(
			sprintf(
				'issue #1895: PfbConfig::%s() bypasses per-field write_priv authorization '
				. 'and is reserved for no-session system contexts (cron/install/migrations/'
				. 'CLI/core hooks) — www/ code must use PfbConfig::write()/writeSection() '
				. 'instead, so isAllowedPage() authorization applies.',
				$tokens[$stackPtr]['content']
			),
			$stackPtr,
			'SystemWriteInWww'
		);
	}

	/**
	 * True when the T_STRING at $i is a direct function call (next non-whitespace
	 * token is '(') and not a method/property access, declaration, or object
	 * instantiation.
	 *
	 * @param array<int, array<string, mixed>> $tokens
	 */
	private function isFunctionCall(File $phpcsFile, array $tokens, int $i): bool
	{
		$next = $phpcsFile->findNext(T_WHITESPACE, $i + 1, NULL, TRUE);
		if ($next === FALSE || $tokens[$next]['code'] !== T_OPEN_PARENTHESIS) {
			return FALSE;
		}

		$prev = $phpcsFile->findPrevious(T_WHITESPACE, $i - 1, NULL, TRUE);
		if ($prev === FALSE) {
			return TRUE;
		}

		$disqualifiers = [
			T_OBJECT_OPERATOR,
			T_NULLSAFE_OBJECT_OPERATOR,
			T_DOUBLE_COLON,
			T_FUNCTION,
			T_NEW,
		];

		return !in_array($tokens[$prev]['code'], $disqualifiers, TRUE);
	}
}
