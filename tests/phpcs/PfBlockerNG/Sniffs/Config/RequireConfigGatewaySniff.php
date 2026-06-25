<?php

/*
 * ADR-29 item — enforce the config-gateway access rule mechanically.
 *
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
 *   e) Out-of-scope keys documented in ADR-29 §2.5 (dnsbl_webpage is
 *      registered as 'dnsblwebpage'; the legacy 'dnsbl_webpage' raw key used
 *      in pfblockerng_dnsbl.php is not in the registered path set).
 *
 * Scope is an explicit, auditable list of full config paths (the registered
 * paths derived from pfb_cfg_registry()) embedded as a sniff property.  The
 * list must be kept in sync with pfb_cfg_registry() in pfblockerng_extra.inc.
 *
 * Wired from phpcs.xml.dist as PfBlockerNG.Config.RequireConfigGateway.
 */

namespace PfBlockerNG\Sniffs\Config;

use PHP_CodeSniffer\Files\File;
use PHP_CodeSniffer\Sniffs\Sniff;

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
		'installedpackages/pfblockerng/config/0/enable_cb',
		'installedpackages/pfblockerng/config/0/pfb_keep',
		'installedpackages/pfblockerng/config/0/pfb_interval',
		'installedpackages/pfblockerng/config/0/pfb_min',
		'installedpackages/pfblockerng/config/0/pfb_hour',
		'installedpackages/pfblockerng/config/0/pfb_dailystart',
		'installedpackages/pfblockerng/config/0/skipfeed',
		'installedpackages/pfblockerng/config/0/pfb_agg_types',
		'installedpackages/pfblockerng/config/0/log_max_log',
		'installedpackages/pfblockerng/config/0/log_max_errlog',
		'installedpackages/pfblockerng/config/0/log_max_extraslog',
		'installedpackages/pfblockerng/config/0/log_max_ip_blocklog',
		'installedpackages/pfblockerng/config/0/log_max_ip_permitlog',
		'installedpackages/pfblockerng/config/0/log_max_ip_matchlog',
		'installedpackages/pfblockerng/config/0/log_max_dnslog',
		'installedpackages/pfblockerng/config/0/log_max_dnsbl_parse_err',
		'installedpackages/pfblockerng/config/0/log_max_dnsreplylog',
		'installedpackages/pfblockerng/config/0/log_max_unilog',
		'installedpackages/pfblockerng/config/0/log_rotate_log',
		'installedpackages/pfblockerng/config/0/log_rotate_errlog',
		'installedpackages/pfblockerng/config/0/log_rotate_extraslog',
		'installedpackages/pfblockerng/config/0/log_rotate_ip_blocklog',
		'installedpackages/pfblockerng/config/0/log_rotate_ip_permitlog',
		'installedpackages/pfblockerng/config/0/log_rotate_ip_matchlog',
		'installedpackages/pfblockerng/config/0/log_rotate_dnslog',
		'installedpackages/pfblockerng/config/0/log_rotate_dnsbl_parse_err',
		'installedpackages/pfblockerng/config/0/log_rotate_dnsreplylog',
		'installedpackages/pfblockerng/config/0/log_rotate_unilog',
		'installedpackages/pfblockerng/config/0/log_reset_keep_log',
		'installedpackages/pfblockerng/config/0/log_reset_keep_errlog',
		'installedpackages/pfblockerng/config/0/log_reset_keep_extraslog',
		'installedpackages/pfblockerng/config/0/log_reset_keep_ip_blocklog',
		'installedpackages/pfblockerng/config/0/log_reset_keep_ip_permitlog',
		'installedpackages/pfblockerng/config/0/log_reset_keep_ip_matchlog',
		'installedpackages/pfblockerng/config/0/log_reset_keep_dnslog',
		'installedpackages/pfblockerng/config/0/log_reset_keep_dnsbl_parse_err',
		'installedpackages/pfblockerng/config/0/log_reset_keep_dnsreplylog',
		'installedpackages/pfblockerng/config/0/log_reset_keep_unilog',
		'installedpackages/pfblockerng/config/0/pfb_software_check',
		'installedpackages/pfblockerng/config/0/pfb_feed_internal_filter',
		'installedpackages/pfblockerng/config/0/pfb_feed_internal_allowlist',
		'installedpackages/pfblockerng/config/0/pfb_reuse',
		// ADR-40: alias-table apply mode + batch size
		'installedpackages/pfblockerng/config/0/pfb_alias_delta_mode',
		'installedpackages/pfblockerng/config/0/pfb_alias_delta_batch',
		// installedpackages/pfblockerngdnsblsettings/config/0 (DNSBL settings)
		'installedpackages/pfblockerngdnsblsettings/config/0/pfb_dnsbl',
		'installedpackages/pfblockerngdnsblsettings/config/0/pfb_dnsvip_auto',
		'installedpackages/pfblockerngdnsblsettings/config/0/pfb_dnsbl_nonat',
		'installedpackages/pfblockerngdnsblsettings/config/0/dnsbl_interface',
		'installedpackages/pfblockerngdnsblsettings/config/0/pfb_dnsvip4',
		'installedpackages/pfblockerngdnsblsettings/config/0/pfb_dnsvip6',
		'installedpackages/pfblockerngdnsblsettings/config/0/pfb_dnsport',
		'installedpackages/pfblockerngdnsblsettings/config/0/pfb_dnsport_ssl',
		'installedpackages/pfblockerngdnsblsettings/config/0/alexa_enable',
		'installedpackages/pfblockerngdnsblsettings/config/0/alexa_type',
		'installedpackages/pfblockerngdnsblsettings/config/0/alexa_count',
		'installedpackages/pfblockerngdnsblsettings/config/0/alexa_inclusion',
		'installedpackages/pfblockerngdnsblsettings/config/0/pfb_cache',
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
		'installedpackages/pfblockerngdnsblsettings/config/0/pfb_pytld',
		'installedpackages/pfblockerngdnsblsettings/config/0/pfb_py_nolog',
		'installedpackages/pfblockerngdnsblsettings/config/0/pfb_noaaaa',
		'installedpackages/pfblockerngdnsblsettings/config/0/pfb_noaaaa_list',
		'installedpackages/pfblockerngdnsblsettings/config/0/pfb_gp',
		'installedpackages/pfblockerngdnsblsettings/config/0/pfb_gp_bypass_list',
		'installedpackages/pfblockerngdnsblsettings/config/0/tldblacklist',
		'installedpackages/pfblockerngdnsblsettings/config/0/tldexclusion',
		'installedpackages/pfblockerngdnsblsettings/config/0/suppression',
		'installedpackages/pfblockerngdnsblsettings/config/0/action',
		'installedpackages/pfblockerngdnsblsettings/config/0/pfb_dnsbl_rule',
		'installedpackages/pfblockerngdnsblsettings/config/0/dnsbl_allow_int',
		'installedpackages/pfblockerngdnsblsettings/config/0/pfb_control',
		'installedpackages/pfblockerngdnsblsettings/config/0/pfb_control_legacy',
		'installedpackages/pfblockerngdnsblsettings/config/0/pfb_py_cache_max',
		'installedpackages/pfblockerngdnsblsettings/config/0/pfb_tld',
		'installedpackages/pfblockerngdnsblsettings/config/0/aliaslog',
		'installedpackages/pfblockerngdnsblsettings/config/0/dnsblwebpage',
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
		// installedpackages/pfblockerngsafesearch (flat section, no /config/0)
		'installedpackages/pfblockerngsafesearch/safesearch_enable',
		'installedpackages/pfblockerngsafesearch/safesearch_youtube',
		'installedpackages/pfblockerngsafesearch/safesearch_doh',
		'installedpackages/pfblockerngsafesearch/safesearch_doh_list',
	];

	/**
	 * @return array<int, int|string>
	 */
	public function register()
	{
		return [T_STRING];
	}

	/**
	 * @param int $stackPtr
	 */
	public function process(File $phpcsFile, $stackPtr)
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
				. 'the gateway (defaults, adapters, rollback contract).',
				$name,
				$path
			),
			$stackPtr,
			'RawRegisteredKeyAccess'
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
