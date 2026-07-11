<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\TestCase;

/**
 * issue #1155 — pfb_unbound_python_whitelist() computed a min-TLD-segment
 * count into a function-LOCAL $tld_segments, then discarded it (only the CSV
 * whitelist string is returned/written). pfb_unbound_python() separately ran
 * `if (!isset($tld_segments)) { $tld_segments = '1'; }` on its OWN
 * never-assigned local, so the manifest's python_tld_seg key ALWAYS emitted
 * 1 regardless of the discarded computation. The Python consumer
 * (whitelist_lookup_domain) gates a parent-suffix walk on this value and
 * only wildcard suppression entries can match that walk, so a fixed literal
 * 1 is behaviourally identical to the dead computation it replaces — this
 * pins that both dead-code sites are gone, the manifest emits literal 1,
 * and pfb_unbound_python_whitelist()'s own CSV output stays byte-identical
 * (Oracle A) across the deletion.
 */
#[CoversFunction('pfb_unbound_python_whitelist')]
#[CoversFunction('pfb_unbound_python')]
final class PythonWhitelistTldSegTest extends TestCase
{
	private const SRC = __DIR__ . '/../../src/usr/local/pkg/pfblockerng/pfblockerng.inc';

	protected function setUp(): void
	{
		$GLOBALS['config'] = [];
		$this->seedGlobalPrereqs();
	}

	/**
	 * Seed the minimum config keys pfb_global() reads (mirrors
	 * DnsblVipDisableNoticeTest::seedGlobalPrereqs() / TickEntrypointTest::
	 * seedTickPrereqs() — the established minimum pfb_global() needs to run
	 * warning-free off-box), since pfb_unbound_python_whitelist() calls
	 * pfb_global() internally.
	 */
	private function seedGlobalPrereqs(): void
	{
		$gen   = 'installedpackages/pfblockerng/config/0';
		$ip    = 'installedpackages/pfblockerngipsettings/config/0';
		$dnsbl = 'installedpackages/pfblockerngdnsblsettings/config/0';

		config_set_path("{$gen}/pfb_min",        '0');
		config_set_path("{$gen}/pfb_hour",       '0');
		config_set_path("{$gen}/pfb_dailystart", '0');
		config_set_path("{$gen}/skipfeed",       '0');

		config_set_path("{$ip}/suppression",     '');
		config_set_path("{$ip}/database_cc",     '');
		config_set_path("{$ip}/maxmind_locale",  'en');
		config_set_path("{$ip}/asn_reporting",   'disabled');
		config_set_path("{$ip}/asn_token",       '');
		config_set_path("{$ip}/maxmind_account", '');
		config_set_path("{$ip}/maxmind_key",     '');

		config_set_path('installedpackages/pfblockerngglobal/pfbextdns', '8.8.8.8');

		config_set_path("{$dnsbl}/pfb_dnsvip4",     '');
		config_set_path("{$dnsbl}/pfb_dnsvip6",     '');
		config_set_path("{$dnsbl}/pfb_dnsport",     '8081');
		config_set_path("{$dnsbl}/pfb_dnsport_ssl", '8443');
		config_set_path("{$dnsbl}/alexa_enable",    '');
		config_set_path("{$dnsbl}/pfb_cache",       '');
		config_set_path("{$dnsbl}/pfb_py_reply",    '');
		config_set_path("{$dnsbl}/pfb_regex",       '');
		config_set_path("{$dnsbl}/pfb_regex_list",  '');
		config_set_path("{$dnsbl}/pfb_cname",       '');
		config_set_path("{$dnsbl}/pfb_pytld",       '');
		config_set_path("{$dnsbl}/pfb_py_nolog",    '');
		config_set_path("{$dnsbl}/pfb_noaaaa",      '');
		config_set_path("{$dnsbl}/pfb_noaaaa_list", '');
		config_set_path("{$dnsbl}/pfb_gp",          '');
		config_set_path("{$dnsbl}/pfb_gp_bypass_list", '');

		if (!isset($GLOBALS['g']['unbound_chroot_path'])) {
			$GLOBALS['g']['unbound_chroot_path'] = '/var/unbound';
		}

		PfbConfig::write('pfb_dnsbl', 'on');
		PfbConfig::write('pfb_dnsvip_auto', '');
		PfbConfig::write('dnsbl_interface', 'lo0');
	}

	private function setSuppression(string $decoded): void
	{
		config_set_path(
			'installedpackages/pfblockerngdnsblsettings/config/0/suppression',
			base64_encode($decoded)
		);
	}

	// --- A: ORACLE — pfb_unbound_python_whitelist() output, pinned across the change ---

	/**
	 * Scenario: a mixed suppression list — bare domain, leading-dot wildcard,
	 * www.-prefixed, and a blank line.
	 * Then: the CSV output strips www., marks the wildcard ',1', everything
	 *       else ',0', and drops the blank line — unaffected by removing the
	 *       discarded min-segment computation.
	 */
	public function testMixedSuppressionListProducesExpectedCsv(): void
	{
		$this->setSuppression("example.com\r\n.wild.org\r\nwww.stripme.net\r\n\r\n");

		$this->assertSame(
			"example.com,0\nwild.org,1\nstripme.net,0\n",
			pfb_unbound_python_whitelist()
		);
	}

	public function testLeadingDotWildcardEntryGetsSuffixOne(): void
	{
		$this->setSuppression(".wild.org\r\n");
		$this->assertSame("wild.org,1\n", pfb_unbound_python_whitelist());
	}

	public function testWwwPrefixIsStrippedAndSuffixedZero(): void
	{
		$this->setSuppression("www.stripme.net\r\n");
		$this->assertSame("stripme.net,0\n", pfb_unbound_python_whitelist());
	}

	public function testEmptySuppressionReturnsEmptyString(): void
	{
		$this->setSuppression('');
		$this->assertSame('', pfb_unbound_python_whitelist());
	}

	// --- B: SOURCE-SHAPE — the dead computation is GONE, manifest emits literal 1 ---

	/**
	 * Brace-counts from `function {$name}(` to its matching closing brace,
	 * so the assertions below inspect ONLY that function's body — never a
	 * neighbour (tld_analysis()'s own write-only $tld_segments was removed
	 * by issue #1168, pinned by TldAnalysisTldSegTest).
	 */
	private function functionBody(string $name): string
	{
		$source = file_get_contents(self::SRC);
		$this->assertNotFalse($source, 'failed to read pfblockerng.inc');

		$needle = "\nfunction {$name}(";
		$start = strpos($source, $needle);
		$this->assertNotFalse($start, "function {$name}() not found in source");
		$start++; // step past the leading \n onto 'function'

		$braceOpen = strpos($source, '{', $start);
		$this->assertNotFalse($braceOpen, "no opening brace found for {$name}()");

		$depth = 0;
		for ($i = $braceOpen, $len = strlen($source); $i < $len; $i++) {
			if ($source[$i] === '{') {
				$depth++;
			} elseif ($source[$i] === '}') {
				$depth--;
				if ($depth === 0) {
					$body = substr($source, $start, $i - $start + 1);
					$this->assertNotSame('', trim($body), "empty body extracted for {$name}() -- vacuous extraction");
					return $body;
				}
			}
		}
		$this->fail("no matching closing brace found for {$name}()");
	}

	public function testWhitelistFunctionHasNoTldSegmentsToken(): void
	{
		$body = $this->functionBody('pfb_unbound_python_whitelist');
		$this->assertStringNotContainsString('tld_segments', $body,
			'issue #1155: the min-segment computation must be deleted, not just unused');
	}

	public function testPythonFunctionHasNoIssetTldSegmentsGuard(): void
	{
		$body = $this->functionBody('pfb_unbound_python');
		$this->assertDoesNotMatchRegularExpression('/isset\(\s*\$tld_segments\s*\)/', $body,
			'issue #1155: the never-assigned isset($tld_segments) guard must be deleted');
	}

	public function testManifestEmitsLiteralPythonTldSegOne(): void
	{
		$body = $this->functionBody('pfb_unbound_python');
		$this->assertMatchesRegularExpression('/python_tld_seg\s*=\s*1\b/', $body,
			'issue #1155: python_tld_seg must emit the literal 1, not a variable');
	}
}
