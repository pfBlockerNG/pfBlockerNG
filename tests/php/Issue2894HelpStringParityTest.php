<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;

/**
 * Issue #2894 — spelling, grammar, and fused help-string concatenations in
 * user-facing help. All defects are literal text in shipped help strings that
 * render in the webConfigurator; help/label text only, no behaviour change.
 *
 * Contract pinned here:
 *   1. the corrected strings appear byte-for-byte (wording + separator);
 *   2. no defect spelling/pattern remains anywhere in the shipped files
 *      (rendered output is what the browser shows, so asserting on the
 *      source of these static help strings is byte-for-byte equivalent);
 *   3. the IPv4 and IPv6 Suppression CIDR helps are internally consistent
 *      (same separator before the parenthetical).
 */
final class Issue2894HelpStringParityTest extends TestCase
{
	private const FILES = [
		'src/usr/local/pkg/pfblockerng/pfblockerng_geoip.inc',
		'src/usr/local/www/pfblockerng/pfblockerng_category.php',
		'src/usr/local/www/pfblockerng/pfblockerng_category_edit.php',
		'src/usr/local/www/pfblockerng/pfblockerng_dnsbl.php',
		'src/usr/local/www/pfblockerng/pfblockerng_alerts.php',
		'src/usr/local/www/pfblockerng/pfblockerng_safesearch.php',
		// pfblockerng_ip.php (site #5, funcionality) is DEFERRED: that file is
		// owned by the #2895 lane and must not be touched by this branch.
	];

	/** Corrected fragments the issue requires, byte-for-byte on source. */
	private const CORRECTED = [
		// #1+#3 geoip.inc:710-711 — alias-address help: the fused link/sentence
		// separator and the Addresses(es) spelling are pinned via the sibling-
		// construction regex in testAliasAddressHelpMatchesSiblingConstruction.
		// #2 IPv4 — space before the parenthetical.
		'IPv4 Alias (Excluding the Custom List IP addresses)',
		// #2 IPv6 — space before the parenthetical.
		'IPv6 Alias (Excluding the Custom List IP addresses)',
		// #4
		'downloading lists',
		// #5 (funcionality, pfblockerng_ip.php) is DEFERRED: that file is owned
		// by the #2895 lane and must not be touched by this branch.
		"It's also <strong>not</strong> recommended",
		// #8
		"It's important to select a broad range",
		// #9
		'Whitelist an IP/Domain',
		// #10
		'Dashboard widget reports',
		// #11
		'Detailed listing: ',
		// #12
		'Check YouTube Content Restrictions',
	];

	/** Defect fragments that must no longer appear in any of the files. */
	private const ABSENT = [
		'AliasesDo',                 // #1 fused
		'Addresses(es)',             // #3
		'downloadling',              // #4
		'funcionality',              // #5
		'overriden',                 // #6
		'Its also',                  // #7
		'Its important',             // #8
		'Whitelist a IP/Domain',     // #9
		'that that',                 // #10
		'Detailed listing :',        // #11
		'Check Youtube',             // #12
		'Alias(Excluding',           // #2 fused
	];

	private static function source(string $rel): string
	{
		$source = file_get_contents(dirname(__DIR__, 2) . '/' . $rel);
		if ($source === FALSE) {
			throw new RuntimeException("failed to read {$rel}");
		}
		return $source;
	}

	/**
	 * The fragment asserts are on rendered help text; these static strings ship
	 * inside PHP single-quoted literals, so unescape \' and \\ before comparing.
	 */
	private static function rendered(string $source): string
	{
		return str_replace(["\\'", '\\\\'], ["'", '\\'], $source);
	}

	public function testCorrectedFragmentsArePresent(): void
	{
		$sources = [];
		foreach (self::FILES as $rel) {
			$sources[$rel] = self::rendered(self::source($rel));
		}
		foreach (self::CORRECTED as $fragment) {
			if ($fragment === '') {
				continue;
			}
			$found = FALSE;
			foreach ($sources as $rel => $source) {
				if (str_contains($source, $fragment)) {
					$found = TRUE;
					break;
				}
			}
			$this->assertTrue(
				$found,
				"corrected fragment [ {$fragment} ] must be present after the #2894 fix"
			);
		}
	}

	public function testDefectFragmentsAreAbsent(): void
	{
		foreach (self::FILES as $rel) {
			$source = self::rendered(self::source($rel));
			foreach (self::ABSENT as $fragment) {
				$this->assertTrue(
					!str_contains($source, $fragment),
					"[ {$fragment} ] must not remain in {$rel} (issue #2894)"
				);
			}
		}
	}

	public function testSuppressionCidrHelpsAreConsistent(): void
	{
		$source = self::rendered(self::source('src/usr/local/www/pfblockerng/pfblockerng_category_edit.php'));
		$v4 = 'this entire IPv4 Alias (Excluding the Custom List IP addresses)';
		$v6 = 'this entire IPv6 Alias (Excluding the Custom List IP addresses)';
		$this->assertTrue(str_contains($source, $v4), 'IPv4 suppression help must carry the space before the parenthetical');
		$this->assertTrue(str_contains($source, $v6), 'IPv6 suppression help must carry the space before the parenthetical');
	}

	public function testAliasAddressHelpMatchesSiblingConstruction(): void
	{
		$source = self::source('src/usr/local/pkg/pfblockerng/pfblockerng_geoip.inc');
		// Sibling port-alias help: link, then a literal newline before "Do not".
		$this->assertTrue(
			(bool) preg_match('/Aliases<\/a>\s*\n\s*Do not manually enter port numbers/', $source),
			'sibling port-alias help construction must remain'
		);
		// The address help must separate the same way (newline, not fused).
		$this->assertTrue(
			(bool) preg_match('/Aliases<\/a>\s*\n\s*Do not manually enter Address\(es\)\./', $source),
			'alias-address help must separate the link and the sentence like its sibling'
		);
	}
}
