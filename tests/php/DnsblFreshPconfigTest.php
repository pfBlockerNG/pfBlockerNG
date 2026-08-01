<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;

/**
 * Fresh DNSBL-page $pconfig assembly guard (issue #1768).
 *
 * A fresh install / first page load runs pfblockerng_dnsbl.php's $pconfig
 * assembly (:49-132) against an EMPTY installedpackages/pfblockerngdnsblsettings
 * section ($pfb['dconfig'] = [] -- the shape PfbConfig::readSection() returns
 * when the section has never been saved). Every explode()/base64_decode()
 * call in that block reads its $pfb['dconfig'][...] operand directly; on an
 * absent key that operand is NULL, and PHP 8.1+ deprecates passing NULL to
 * explode()'s/base64_decode()'s non-nullable string parameter -- these are
 * the "Passing null" deprecations issue #1768 reports blocking the release
 * functional-UI gate.
 *
 * Scope: the assertions below check only the "Passing null" deprecation
 * class. The SAME block also has ~20 untouched bare
 * `$pfb['dconfig']['key'] ?: default` reads that still emit "Undefined array
 * key" warnings on an absent key -- those are the pre-existing, explicitly
 * out-of-scope "3e bare-read class" (#1768 brief); asserting the FULL
 * diagnostics list empty would conflate the two and this test would never
 * go green.
 *
 * The page carries top-level execution and cannot be require()d
 * off-appliance, so the $pconfig block is eval-extracted verbatim from the
 * REAL source (CategoryEditFreshRowPconfigTest's pattern, issue #1211),
 * anchored on the unique `$pconfig = array();` line through the trailing
 * `tld_wildcard_blacklist` assignment -- non-greedy, so the regex matches whatever the
 * RHS guard state is (pre-fix bare read or post-fix `?? ''`-guarded) and
 * survives the fix -- and run as a pure function of ($dconfig, $default_tlds).
 */
final class DnsblFreshPconfigTest extends TestCase
{
	public static function setUpBeforeClass(): void
	{
		$src = file_get_contents(
			dirname(__DIR__, 2) . '/src/usr/local/www/pfblockerng/pfblockerng_dnsbl.php'
		);
		if ($src === FALSE) {
			throw new RuntimeException('test bootstrap: failed to read pfblockerng_dnsbl.php');
		}

		if (!function_exists('pfb_dnsbl_oracle_fresh_pconfig')) {
			if (!preg_match(
				'/\$pconfig\s*= array\(\);\n'
				. '(.*?\n\s*\$pconfig\[\'tld_wildcard_blacklist\'\][^\n]*\n)/s',
				$src,
				$m
			)) {
				throw new RuntimeException('test bootstrap: dnsbl fresh $pconfig block not found');
			}
			eval(
				'function pfb_dnsbl_oracle_fresh_pconfig(array $dconfig, array $default_tlds): array {'
				. ' global $pfb; $pfb[\'dconfig\'] = $dconfig;'
				. ' $pconfig = array();'
				. $m[1]
				. ' return $pconfig; }'
			);
		}
	}

	/** @return array{0: array, 1: string[]} [$pconfig, $diagnostics] */
	private function runCapturingDiagnostics(array $dconfig, array $default_tlds): array
	{
		$diagnostics = [];
		set_error_handler(static function (int $errno, string $errstr) use (&$diagnostics): bool {
			$diagnostics[] = $errstr;
			return TRUE;
		});
		try {
			$pconfig = pfb_dnsbl_oracle_fresh_pconfig($dconfig, $default_tlds);
		} finally {
			restore_error_handler();
		}
		return [$pconfig, $diagnostics];
	}

	/** @return string[] the diagnostics whose message is a "Passing null" deprecation */
	private static function nullDeprecationsOnly(array $diagnostics): array
	{
		return array_values(array_filter(
			$diagnostics,
			static fn(string $d): bool => str_contains($d, 'Passing null')
		));
	}

	public function testFreshDnsblPconfigEmitsNoPassingNullDeprecations(): void
	{
		[$pconfig, $diagnostics] = $this->runCapturingDiagnostics(
			[],
			['arpa', 'example.com', 'com', 'net', 'org', 'edu', 'ca', 'co', 'io']
		);

		$nullDeprecations = self::nullDeprecationsOnly($diagnostics);
		$this->assertSame(
			[],
			$nullDeprecations,
			"fresh-config \$pconfig assembly must emit zero 'Passing null' deprecations, got:\n" . implode("\n", $nullDeprecations)
		);
		$this->assertIsArray($pconfig);
	}

	public function testPopulatedDnsblPconfigDecodeExplodeSitesPassThroughUnchanged(): void
	{
		// Axis 2 (populated key): the guard must be a no-op when the field IS
		// present -- proves the fix didn't clobber real decode/explode output.
		$dconfig = [
			'dnsbl_allow_int'        => 'wan,lan',
			'tld_allow_gtld'         => 'com,net',
			'tld_allow_cctld'        => 'uk,de',
			'tld_allow_itld'         => 'xn--p1ai',
			'tld_allow_bgtld'        => 'app,dev',
			'pfb_regex_list'         => base64_encode("foo\nbar"),
			'pfb_noaaaa_list'        => base64_encode('example.com'),
			'pfb_gp_bypass_list'     => base64_encode('192.0.2.1'),
			'whitelist'              => base64_encode('192.0.2.0/24'),
			'top1m_inclusion'        => 'com,net,org',
			'tld_wildcard_exclusion' => base64_encode('example.test'),
			'tld_wildcard_blacklist' => base64_encode('bad.example'),
		];

		[$pconfig, $diagnostics] = $this->runCapturingDiagnostics(
			$dconfig,
			['arpa', 'lan.local', 'com', 'net', 'org', 'edu', 'ca', 'co', 'io']
		);

		$this->assertSame([], self::nullDeprecationsOnly($diagnostics));
		$this->assertSame(['wan', 'lan'], $pconfig['dnsbl_allow_int']);
		$this->assertSame(['com', 'net'], $pconfig['tld_allow_gtld']);
		$this->assertSame(['uk', 'de'], $pconfig['tld_allow_cctld']);
		$this->assertSame(['xn--p1ai'], $pconfig['tld_allow_itld']);
		$this->assertSame(['app', 'dev'], $pconfig['tld_allow_bgtld']);
		$this->assertSame("foo\nbar", $pconfig['pfb_regex_list']);
		$this->assertSame('example.com', $pconfig['pfb_noaaaa_list']);
		$this->assertSame('192.0.2.1', $pconfig['pfb_gp_bypass_list']);
		$this->assertSame('192.0.2.0/24', $pconfig['whitelist']);
		$this->assertSame(['com', 'net', 'org'], $pconfig['top1m_inclusion']);
		$this->assertSame('example.test', $pconfig['tld_wildcard_exclusion']);
		$this->assertSame('bad.example', $pconfig['tld_wildcard_blacklist']);
	}
}
