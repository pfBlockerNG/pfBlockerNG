<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\TestCase;

/**
 * Issue #1782: pfblockerng_alerts.php decodes its Custom_List/Suppression/Exclusion
 * customlists WITHOUT $idn=TRUE, so a Unicode row keys the Alerts page's lookup map by
 * the raw Unicode label -- while every runtime consumer (pfb_dnsbl_whitelist_lines(),
 * the TLD-wildcard manifest builder) and the DNSBL log fields compared against that map
 * (dnsbl.log's evaluated-domain field) carry the punycode form. The row never matches:
 * "add to exclusion"/"already whitelisted" recognition silently fails and a duplicate
 * gets appended instead.
 *
 * Uses the REAL decode statements (AlertsCustomlistDecodeLoader.php evals them straight
 * out of pfblockerng_alerts.php) so this test is red against the unfixed call sites and
 * green once they pass $idn=TRUE, with no test edits either side.
 */
#[CoversFunction('dnsbl_log_details')]
#[CoversFunction('dnsbl_whitelist_type')]
final class AlertsCustomlistIdnRecognitionTest extends TestCase
{
	public static function setUpBeforeClass(): void
	{
		require_once __DIR__ . '/AlertsPageLoader.php';
		require_once __DIR__ . '/AlertsCustomlistDecodeLoader.php';
		pfb_test_load_alerts_page_functions();
	}

	/**
	 * Run $fn under the C locale (see TextAreaDecodeTest::underCLocale() -- the IDN
	 * branch is gated on !ctype_print(), which is locale-sensitive).
	 */
	private static function underCLocale(callable $fn): void
	{
		$prev = setlocale(LC_CTYPE, '0');
		setlocale(LC_CTYPE, 'C');
		try {
			$fn();
		} finally {
			setlocale(LC_CTYPE, $prev);
		}
	}

	private static function enc(string $line): string
	{
		return base64_encode($line);
	}

	// -------------------------------------------------------------------
	// alerts.php's 'ipsuppression'/'ipsuppression_v6'/'dnsblwhitelist'/'tld_wildcard_exclusion'
	// decode loop must key its map by punycode, matching every runtime decoder.
	// -------------------------------------------------------------------

	public function testTldExclusionRowKeyedByPunycodeNotUnicode(): void
	{
		self::underCLocale(function (): void {
			$data = pfb_test_alerts_decode_suppression_list('tld_wildcard_exclusion', self::enc('bücher.de'));

			$this->assertArrayHasKey('xn--bcher-kva.de', $data, 'expected the punycode key the log/runtime carry');
			$this->assertArrayNotHasKey('bücher.de', $data, 'a raw-Unicode key can never match a punycode log field');
		});
	}

	/**
	 * The named issue scenario: an IDN TLD-exclusion row entered on the DNSBL page
	 * (stored as raw Unicode, per PR #1781/#1731) is RECOGNISED -- not duplicated --
	 * by the Alerts handler when a dnsbl.log row blocks its punycode form via TLD
	 * wildcard matching.
	 */
	public function testIdnTldExclusionRowRecognisedByDnsblLogDetails(): void
	{
		self::underCLocale(function (): void {
			$GLOBALS['clists'] = [
				'tld_wildcard_exclusion' => ['data' => pfb_test_alerts_decode_suppression_list('tld_wildcard_exclusion', self::enc('bücher.de # my note'))],
			];

			$fields = [
				2 => 'sub.xn--bcher-kva.de',	// Blocked Domain (full queried name, punycode wire form)
				5 => 'DNSBL_TLD',		// Mode: TLD wildcard block
				7 => 'xn--bcher-kva.de',	// Evaluated Domain -- the excluded TLD root, punycode
			];

			[$isTLD, , , $isExclusion, , , $wt_line] = dnsbl_log_details($fields);

			$this->assertTrue($isTLD, 'sanity: DNSBL_TLD mode field must set isTLD');
			$this->assertTrue($isExclusion, 'the IDN TLD-exclusion row must be recognised for its punycode-evaluated domain, not treated as absent');
			$this->assertStringContainsString('xn--bcher-kva.de', $wt_line);
		});
	}

	/**
	 * Same asymmetry class for 'suppression' (the DNSBL Whitelist customlist,
	 * PfbConfig field 'suppression'/type 'dnsblwhitelist'): pfb_dnsbl_whitelist_lines()
	 * already decodes it with $idn=TRUE (pfblockerng.inc), so the Alerts page's
	 * render-time "already whitelisted" icon must key it the same way.
	 */
	public function testIdnDnsblWhitelistRowRecognisedByRenderTimeCheck(): void
	{
		self::underCLocale(function (): void {
			$clists = [
				'dnsblwhitelist' => ['data' => pfb_test_alerts_decode_suppression_list('dnsblwhitelist', self::enc('bücher.de'))],
			];

			$fields = [
				2 => 'xn--bcher-kva.de',	// Blocked Domain, punycode wire form
				5 => 'DNSBL',			// Not a TLD block
				6 => 'SomeGroup',
				7 => 'xn--bcher-kva.de',
				8 => 'SomeFeed',
			];

			[, , $isWhitelistFound] = dnsbl_whitelist_type($fields, $clists, false, false, $fields[2]);

			$this->assertTrue($isWhitelistFound, 'the IDN DNSBL Whitelist row must be recognised for its punycode blocked-domain field');
		});
	}

	// -------------------------------------------------------------------
	// alerts.php's per-DNSBL-group/per-IP-alias Custom_List decode block must
	// likewise key by punycode (pfblockerng_apply.inc:1758 decodes the SAME
	// per-row 'custom' field with $idn=TRUE for the DNSBL feed pipeline).
	// -------------------------------------------------------------------

	public function testGroupCustomlistRowKeyedByPunycodeNotUnicode(): void
	{
		self::underCLocale(function (): void {
			$data = pfb_test_alerts_decode_group_customlist('dnsbl', 'DNSBL_TestGroup', self::enc('bücher.de'));

			$this->assertArrayHasKey('xn--bcher-kva.de', $data, 'expected the punycode key the DNSBL feed pipeline/log carry');
			$this->assertArrayNotHasKey('bücher.de', $data, 'a raw-Unicode key can never match a punycode-derived $domain');
		});
	}
}
