<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;

/**
 * issue #1887 — no typed $pfb[] toggle mirror may be compared against a string token.
 *
 * The mirrors carry PfbToggle, and in PHP 8 an enum never equals a string — loosely or
 * strictly — so a leftover `== 'on'` comparison is not a type error but a branch that
 * silently never (or always) runs. The live-VM dispatches caught three of these the
 * off-box suite could not see:
 *
 *  - pfb_dnsbl_loaded_input_paths() dropped the TOP1M whitelist from the ADR-42 reload
 *    fingerprint (`($pfb['dnsbl_top1m'] ?? '') === 'on'`), so a TOP1M change stopped
 *    triggering the zero-downtime swap — smoke run 30538966282 starved 600s on it.
 *  - pfb_manage_dnsbl_vip()'s `$auto` gate (`== 'on'`) went permanently false, so the
 *    ADR-13 auto-VIP was never provisioned — UI run 30540321500.
 *  - The IP preprocess exec args pinned aggregation to 'off'
 *    (`($pfb['agg'] ?? '') === 'on' ? 'on' : 'off'`).
 *
 * All three shared one shape: an intervening `?? ''` between the subscript and the
 * comparison, which the conversion regexes did not match. This guard closes the class
 * by scanning the tree for ANY typed mirror compared to a quoted token on one line —
 * whatever sits between them.
 */
final class ToggleMirrorComparisonGuardTest extends TestCase
{
	/** Every $pfb[] mirror that carries PfbToggle after issue #1887. */
	private const TYPED_MIRRORS = [
		'enable', 'keep', 'dnsbl', 'dnsbl_vip_auto', 'dnsbl_nonat', 'dnsbl_hsts',
		'unbound_state', 'dnsbl_cache_flush', 'dnsbl_lenient', 'supp', 'dnsbl_top1m',
		'dnsbl_res_cache', 'dnsbl_py_reply', 'dnsbl_regex', 'dnsbl_regex_cap',
		'dnsbl_cname', 'dnsbl_tld_allow', 'dnsbl_py_nolog', 'dnsbl_noaaaa', 'dnsbl_gp',
		'float', 'dup', 'agg', 'global_log', 'dnsbl_control', 'dnsbl_control_legacy',
		'dnsbl_idn_block_malicious', 'dnsbl_idn_escalate_suspicious',
		'dnsbl_psl_include_private', 'dnsbl_psl_allow_private',
		'rep', 'prep', 'drep',
	];

	public function testNoTypedMirrorIsComparedAgainstAStringToken(): void
	{
		$mirror = '\$pfb\[\'(?:' . implode('|', self::TYPED_MIRRORS) . ')\'\]';
		// The mirror and a string comparison on the same LINE, tolerating anything
		// between them (a `?? ''`, parentheses, casts) — the shape the fixed regexes
		// missed. Comparisons against PfbToggle::* do not match: the token there is
		// not quoted.
		// Interstitial tolerance is deliberately narrow: an optional `?? <fallback>`
		// plus closing parens — the shapes the fixed regexes actually missed.
		$coalesce = '(?:\s*\?\?\s*(?:\'[a-z]*\'|PfbToggle::\w+))?';
		$pattern = '/' . $mirror . $coalesce . '\s*\)*\s*(?:===|!==|==|!=)\s*\'(?:on|off|)\'/';
		// The reverse orientation ('on' == $pfb[...]) has no in-tree precedent but
		// costs one more scan to close.
		$reverse = '/\'(?:on|off)\'\s*(?:===|!==|==|!=)\s*\(*' . $mirror . '/';

		$offences = [];
		$root = dirname(__DIR__, 2) . '/src';
		$it = new RecursiveIteratorIterator(
			new RecursiveDirectoryIterator($root, FilesystemIterator::SKIP_DOTS)
		);
		foreach ($it as $file) {
			/** @var SplFileInfo $file */
			if (!$file->isFile() || !preg_match('/\.(php|inc)$/', $file->getPathname())) {
				continue;
			}
			// Whole-tree static type rule: comments are not executable input.
			foreach (explode("\n", php_strip_whitespace($file->getPathname())) as $n => $line) {
				// Adapter feeds are fine: the raw section value is compared/coalesced
				// BEFORE pfb_cfg_toggle_read() types it.
				if (str_contains($line, 'pfb_cfg_toggle_read(')) {
					continue;
				}
				if (preg_match($pattern, $line) || preg_match($reverse, $line)) {
					$offences[] = substr($file->getPathname(), strlen($root) + 1) . ':' . ($n + 1)
						. ': ' . trim($line);
				}
			}
		}

		$this->assertSame(
			[],
			$offences,
			"typed toggle mirrors must be compared against PfbToggle::On/Off — an enum never "
				. "equals a string, so these branches silently never (or always) run:\n  "
				. implode("\n  ", $offences)
		);
	}

	/**
	 * Companion lens the comparison sweep is blind to (PR #1899 adversarial review):
	 * a typed mirror reaching a STRING context. `<?=$pfb['supp']?>` in the Alerts
	 * page's inline JS was a fatal on every page load — "Object of class PfbToggle
	 * could not be converted to string" — and no comparison-shaped regex can see it.
	 * Three sink shapes: echo tags, double-quoted/heredoc interpolation, and string
	 * concatenation. A mirror needed as a token goes through an explicit
	 * `=== PfbToggle::On ? 'on' : 'off'` (or `->value` at a boundary), never raw.
	 */
	public function testNoTypedMirrorReachesAStringContext(): void
	{
		$mirror = '\$pfb\[\'(?:' . implode('|', self::TYPED_MIRRORS) . ')\'\]';
		$sinks = [
			'echo tag'      => '/<\?=\s*' . $mirror . '\s*\?>/',
			'interpolation' => '/\{' . $mirror . '\}/',
			'concatenation' => '/(?:\.\s*' . $mirror . '|' . $mirror . '\s*\.\s*[\'"])/',
		];

		$offences = [];
		$root = dirname(__DIR__, 2) . '/src';
		$it = new RecursiveIteratorIterator(
			new RecursiveDirectoryIterator($root, FilesystemIterator::SKIP_DOTS)
		);
		foreach ($it as $file) {
			/** @var SplFileInfo $file */
			if (!$file->isFile() || !preg_match('/\.(php|inc)$/', $file->getPathname())) {
				continue;
			}
			foreach (explode("\n", php_strip_whitespace($file->getPathname())) as $n => $line) {
				foreach ($sinks as $kind => $rx) {
					if (preg_match($rx, $line)) {
						$offences[] = substr($file->getPathname(), strlen($root) + 1) . ':' . ($n + 1)
							. " [{$kind}]: " . trim($line);
					}
				}
			}
		}

		$this->assertSame(
			[],
			$offences,
			"typed toggle mirrors must never reach a string context raw — PHP fatals with "
				. "'Object of class PfbToggle could not be converted to string':\n  "
				. implode("\n  ", $offences)
		);
	}

	/**
	 * The behavioural half of the smoke defect: with the TOP1M mirror On, the TOP1M
	 * whitelist file belongs to the ADR-42 reload fingerprint's input set; with it Off,
	 * it does not. Both directions, so the test cannot pass on a constant.
	 */
	public function testTop1mWhitelistBelongsToTheFingerprintInputSetWhenEnabled(): void
	{
		$base = [
			'unbound_py_wh'      => '/var/unbound/pfb_py_whitelist.txt',
			'unbound_py_sources' => '/var/unbound/pfb_py_sources.ini',
			'unbound_py_hsts'    => '/var/unbound/pfb_py_hsts.txt',
			'unbound_py_psl'     => '/var/unbound/dnsbl_psl',
			'unbound_py_top1m'   => '/var/unbound/pfb_py_top1m.txt',
		];

		$on  = pfb_dnsbl_loaded_input_paths($base + ['dnsbl_top1m' => PfbToggle::On]);
		$off = pfb_dnsbl_loaded_input_paths($base + ['dnsbl_top1m' => PfbToggle::Off]);

		$this->assertContains('/var/unbound/pfb_py_top1m.txt', $on,
			'TOP1M enabled: the whitelist file must be fingerprinted, or a TOP1M change never triggers the reload');
		$this->assertNotContains('/var/unbound/pfb_py_top1m.txt', $off,
			'TOP1M disabled: the whitelist file must stay out of the fingerprint');
	}
}
