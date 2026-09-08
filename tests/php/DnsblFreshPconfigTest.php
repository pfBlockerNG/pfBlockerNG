<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;

/**
 * DNSBL-page $pconfig consumer guard (issues #1768 and #3137).
 *
 * The page carries top-level execution and cannot be require()d off-appliance, so its
 * real $pconfig assembly block is eval-extracted as an executable function. Tests seed
 * authoritative config.xml state separately from a deliberately stale $pfb['dconfig']
 * mirror: consumer assertions therefore fail while registered fields still bypass
 * PfbConfig::read(), without asserting on source text.
 *
 * The original #1768 contract remains: fresh and populated CSV/base64 inputs emit no
 * "Passing null" deprecations. Issue #3137 additionally pins empty/default, stored "0",
 * populated/multiline, malformed, missing, and decode-exactly-once behavior while those
 * fields move to the gateway. Other pre-existing diagnostics remain outside this class.
 *
 * Extraction is anchored on the unique `$pconfig = array();` line through the trailing
 * `tld_wildcard_blacklist` assignment and runs as a function of the raw section mirror,
 * registered config state, and local-domain-derived default TLD list.
 */
final class DnsblFreshPconfigTest extends TestCase
{
	private const DNSBL_SECTION = 'installedpackages/pfblockerngdnsblsettings/config/0';
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
	private function runCapturingDiagnostics(
		array $dconfig,
		array $default_tlds,
		?array $stored = NULL
	): array {
		$hadConfig = array_key_exists('config', $GLOBALS);
		$previousConfig = $GLOBALS['config'] ?? NULL;
		$diagnostics = [];
		set_error_handler(static function (int $errno, string $errstr) use (&$diagnostics): bool {
			$diagnostics[] = $errstr;
			return TRUE;
		});
		try {
			$GLOBALS['config'] = [];
			config_set_path(self::DNSBL_SECTION, $stored ?? $dconfig);
			$pconfig = pfb_dnsbl_oracle_fresh_pconfig($dconfig, $default_tlds);
		} finally {
			restore_error_handler();
			if ($hadConfig) {
				$GLOBALS['config'] = $previousConfig;
			} else {
				unset($GLOBALS['config']);
			}
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

	public function testListAndTextareaConsumersUseAuthoritativeGatewayValuesWithoutChangingFallbacks(): void
	{
		$mirror = [
			'dnsbl_allow_int'        => 'mirror',
			'tld_allow_gtld'         => 'mirror',
			'tld_allow_cctld'        => 'mirror',
			'tld_allow_itld'         => 'mirror',
			'tld_allow_bgtld'        => 'mirror',
			'pfb_regex_list'         => base64_encode('mirror'),
			'pfb_noaaaa_list'        => base64_encode('mirror'),
			'pfb_gp_bypass_list'     => base64_encode('mirror'),
			'whitelist'              => base64_encode('mirror'),
			'top1m_inclusion'        => 'mirror',
			'tld_wildcard_exclusion' => base64_encode('mirror'),
			'tld_wildcard_blacklist' => base64_encode('mirror'),
		];
		$stored = [
			'dnsbl_allow_int'        => '0',
			'tld_allow_gtld'         => '',
			'tld_allow_cctld'        => 'uk,de',
			'tld_allow_bgtld'        => 'app,dev',
			'pfb_regex_list'         => base64_encode(" foo\nbar "),
			'pfb_noaaaa_list'        => '%%%',
			'pfb_gp_bypass_list'     => base64_encode('0'),
			'whitelist'              => base64_encode(base64_encode('once')),
			'top1m_inclusion'        => '',
			'tld_wildcard_exclusion' => base64_encode("one\ntwo"),
		];
		$default_tlds = ['arpa', 'corp', 'com', 'net'];

		[$pconfig, $diagnostics] = $this->runCapturingDiagnostics($mirror, $default_tlds, $stored);

		$this->assertSame([], self::nullDeprecationsOnly($diagnostics));
		$this->assertSame(['0'], $pconfig['dnsbl_allow_int'], "stored CSV '0' is one entry");
		$this->assertSame($default_tlds, $pconfig['tld_allow_gtld'],
			'an empty stored gTLD list keeps the local-domain-derived display fallback');
		$this->assertSame(['uk', 'de'], $pconfig['tld_allow_cctld']);
		$this->assertSame([], $pconfig['tld_allow_itld'], 'a missing CSV field remains an empty list');
		$this->assertSame(['app', 'dev'], $pconfig['tld_allow_bgtld']);
		$this->assertSame(" foo\nbar ", $pconfig['pfb_regex_list']);
		$this->assertSame('', $pconfig['pfb_noaaaa_list'], 'malformed base64 keeps the current empty fallback');
		$this->assertSame('0', $pconfig['pfb_gp_bypass_list'], "decoded textarea '0' must survive");
		$this->assertSame(base64_encode('once'), $pconfig['whitelist'],
			'a gateway-backed textarea must be decoded exactly once');
		$this->assertSame(['com', 'net', 'org', 'ca', 'co', 'io'], $pconfig['top1m_inclusion']);
		$this->assertSame("one\ntwo", $pconfig['tld_wildcard_exclusion']);
		$this->assertSame('', $pconfig['tld_wildcard_blacklist'], 'a missing textarea remains empty');
	}
}
