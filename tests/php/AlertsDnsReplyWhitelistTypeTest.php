<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\TestCase;

/**
 * issue #1777: convert_dns_reply_log()'s call into dnsbl_whitelist_type()
 * (:~2498) builds `$dns_fields` with only 2 of the 5 keys the callee reads
 * (2 and 6) -- unlike its two convert_dnsbl_log() siblings (:2170/:2312),
 * which pass the raw dnsbl.log $fields array carrying all of 2/5/6/7/8.
 * dnsbl_whitelist_type() unconditionally reads $fields[5]/[7]/[8] at its top
 * (pfb_hsc($fields[7]), pfb_hsc($fields[8]), then the != 'DNSBL_TLD' compare
 * on $fields[5]) -- so every DNS-reply row rendered raises 3 "Undefined array
 * key" diagnostics.
 *
 * Fix: supply keys 5/7/8 -- traced against the function's own read sites
 * (dnsbl_whitelist_type() body, :1964-2111) rather than guessed:
 *   - key 5 (DNSBL Mode, gates the != 'DNSBL_TLD' branch split) has no reply-
 *     log analogue; '' preserves the CURRENT (pre-fix, implicit-NULL) branch
 *     selection byte-for-byte, since NULL != 'DNSBL_TLD' is also true.
 *   - key 7 (Evaluated Domain): ''. A prior revision of this fix set key 7 to
 *     $fields[6] (the replied domain), reasoning only about the
 *     exclusion-icon id -- it missed that dnsbl_whitelist_type() ALSO feeds
 *     key 7 into the dot-prefixed wildcard-whitelist walk
 *     (dnsbl_whitelist_type() ~:2056, `ltrim($fields[7], '.')`). A real
 *     domain there enters that walk and can flip $isWhitelist_found to TRUE
 *     for any dot-prefixed whitelist entry that is an ancestor domain --
 *     silently reclassifying an unrelated reply row as already-whitelisted
 *     (issue #1777 review, BLOCKING; see
 *     testConvertDnsReplyLogKeepsPreFixClassificationForDotPrefixedWhitelistEntry
 *     below). '' is chosen because ltrim(NULL, '.') === ltrim('', '.') ===
 *     '', so it reproduces the pre-fix NULL read exactly and never enters
 *     the walk.
 *   - key 8 (Feed Name) is read only inside the `$fields[6] != 'Unknown'`
 *     branch (dnsbl_whitelist_type :2023), which the caller's own hardcoded
 *     `'6' => 'Unknown'` provably never enters -- no reply-log analogue
 *     exists and none is needed; '' is inert by construction, not a guess.
 *
 * Note: the $isExclusion branch (dnsbl_whitelist_type :1978, the OTHER
 * reachable consumer of key 7) needs pfSense's array_get_path() to run --
 * no test double exists for it and this fix's file scope does not extend to
 * adding one to pfsense_doubles.php, so that branch is exercised live (the
 * functional-UI sweep), not here; the diagnostic-elimination proof below
 * covers the actual bug (undefined keys 5/7/8), independent of that branch.
 *
 * AlertsPageLoader.php (already used by AlertsRowOutputEncodingTest for the
 * sibling convert_dnsbl_log() callers) defines both functions off-appliance
 * from the REAL shipped source; the globals stood up in setUp() mirror
 * convert_dns_reply_log()'s own `global` declaration (:2434).
 */
#[CoversFunction('convert_dns_reply_log')]
#[CoversFunction('dnsbl_whitelist_type')]
final class AlertsDnsReplyWhitelistTypeTest extends TestCase
{
	/** @var array<string, mixed> */
	private array $savedGlobals = [];

	public static function setUpBeforeClass(): void
	{
		require_once __DIR__ . '/AlertsPageLoader.php';
		pfb_test_load_alerts_page_functions();
	}

	protected function setUp(): void
	{
		foreach ([
			'pfb', 'local_hosts', 'filterfieldsarray', 'clists', 'counter',
			'pfbentries', 'skipcount', 'dnsfilterlimit', 'dnsfilterlimitentries',
		] as $g) {
			$this->savedGlobals[$g] = $GLOBALS[$g] ?? null;
		}

		$GLOBALS['pfb'] = ['filterlogentries' => FALSE];
		// Pre-seeded with the fixture's own SRC IP (below) so the UNRELATED,
		// pre-existing local_hosts-miss warning never fires and pollutes the
		// diagnostics list this test is scoped to.
		$GLOBALS['local_hosts'] = ['10.0.0.9' => ''];
		$GLOBALS['filterfieldsarray'] = [];
		$GLOBALS['clists'] = [
			'dnsbl'          => ['options' => []],
			'dnsblwhitelist' => ['data' => []],
			'tld_wildcard_exclusion' => ['data' => []],
		];
		$GLOBALS['counter'] = ['DNS' => 0, 'Unified' => 0];
		$GLOBALS['pfbentries'] = 1000;
		$GLOBALS['skipcount'] = 0;
		$GLOBALS['dnsfilterlimit'] = FALSE;
		$GLOBALS['dnsfilterlimitentries'] = 100;
	}

	protected function tearDown(): void
	{
		foreach ($this->savedGlobals as $g => $v) {
			if ($v === null) {
				unset($GLOBALS[$g]);
			} else {
				$GLOBALS[$g] = $v;
			}
		}
	}

	/** DNS-reply $fields row per convert_dns_reply_log()'s own field-index comments (:2441-2449). */
	private function replyFields(string $domain, string $srcIp): array
	{
		return [
			0 => 'DNS-Reply',
			1 => '2026-01-01 00:00:00',	// Timestamp
			2 => 'Reply',			// DNS Reply Type
			3 => 'A',			// DNS Reply Orig Type
			4 => 'A',			// DNS Reply Final Type
			5 => '300',			// DNS Reply TTL
			6 => $domain,			// DNS Reply Domain
			7 => $srcIp,			// DNS Reply SRC IP
			8 => '198.51.100.9',		// DNS Reply DST IP
			9 => 'US',			// DNS Reply GeoIP
		];
	}

	private function runCapturing(callable $fn): array
	{
		$diagnostics = [];
		set_error_handler(static function (int $errno, string $errstr) use (&$diagnostics): bool {
			$diagnostics[] = $errstr;
			return TRUE;
		});
		try {
			$fn();
		} finally {
			restore_error_handler();
		}
		return $diagnostics;
	}

	public function testConvertDnsReplyLogEmitsNoUndefinedArrayKeyDiagnostics(): void
	{
		$fields = $this->replyFields('reply.example.test', '10.0.0.9');

		$diagnostics = $this->runCapturing(static function () use ($fields): void {
			ob_start();
			convert_dns_reply_log('Reports', $fields);
			ob_get_clean();
		});

		$undefined = array_values(array_filter(
			$diagnostics,
			static fn(string $d): bool => str_contains($d, 'Undefined array key')
		));
		$this->assertSame(
			[],
			$undefined,
			"convert_dns_reply_log() -> dnsbl_whitelist_type() must emit zero 'Undefined array key' diagnostics, got:\n"
			. implode("\n", $undefined)
		);
	}

	/**
	 * issue #1777 review (BLOCKING): a dot-prefixed DNSBL whitelist entry
	 * ("[.]example.com") must NOT silently reclassify an unrelated DNS-reply
	 * row for a descendant domain ("ads.example.com") as already-whitelisted.
	 * Before this fix, $dns_fields['7'] was $fields[6] (the replied domain),
	 * which entered dnsbl_whitelist_type()'s dot-prefixed wildcard-whitelist
	 * walk (~:2054-2090) and matched "example.com" as an ancestor of
	 * "ads.example.com", flipping $isWhitelist_found to TRUE and rendering
	 * the "delete_domainwildcard" trash icon instead of the pre-fix
	 * "add to DNSBL" icon (dnsbl_add).
	 */
	public function testConvertDnsReplyLogKeepsPreFixClassificationForDotPrefixedWhitelistEntry(): void
	{
		$GLOBALS['clists']['dnsblwhitelist']['data'] = ['.example.com' => 'entry'];

		$fields = $this->replyFields('ads.example.com', '10.0.0.9');

		$output = '';
		$diagnostics = $this->runCapturing(function () use ($fields, &$output): void {
			ob_start();
			convert_dns_reply_log('Reports', $fields);
			$output = ob_get_clean();
		});

		$undefined = array_values(array_filter(
			$diagnostics,
			static fn(string $d): bool => str_contains($d, 'Undefined array key')
		));
		$this->assertSame(
			[],
			$undefined,
			"convert_dns_reply_log() -> dnsbl_whitelist_type() must emit zero 'Undefined array key' diagnostics, got:\n"
			. implode("\n", $undefined)
		);

		$this->assertStringNotContainsString(
			'delete_domainwildcard',
			$output,
			'a dot-prefixed DNSBL whitelist entry for "example.com" must not silently classify an unrelated '
			. 'DNS-reply row for "ads.example.com" as already-whitelisted (isWhitelist_found must stay FALSE)'
		);
		$this->assertStringContainsString(
			'dnsbl_add',
			$output,
			'the pre-fix classification renders the "Add Domain to DNSBL" icon, not the wildcard-whitelist delete icon'
		);
	}

	public function testConvertDnsReplyLogReportsKeepsWideDomainTruncationWidth(): void
	{
		$domain = 'WIDE-REPLY07-' . str_repeat('c', 40) . '-tail';
		$this->assertGreaterThan(45, strlen($domain));
		$fields = $this->replyFields($domain, '10.0.0.9');

		$output = '';
		$diagnostics = $this->runCapturing(function () use ($fields, &$output): void {
			ob_start();
			convert_dns_reply_log('Reports', $fields);
			$output = ob_get_clean();
		});

		$this->assertSame([], $diagnostics, 'wide Reports rendering must not add PHP diagnostics');
		$this->assertStringContainsString(
			'<td title="' . $domain . '">' . substr($domain, 0, 44) . '<small>...</small></td>',
			$output,
			'Reports DNS-reply domains must retain the existing 44-character display width'
		);
		$this->assertStringNotContainsString(
			'<td title="' . $domain . '">' . substr($domain, 0, 29) . '<small>...</small></td>',
			$output,
			'Reports DNS-reply domains must not use the Unified 29-character display width'
		);
	}
}
