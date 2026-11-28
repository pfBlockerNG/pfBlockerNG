<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;

/**
 * Issue #1349: DNSBL statistics must use in-memory counts without rebuilding
 * redundant plaintext group summaries or retaining the old TLD-analysis seam.
 */
final class DnsblPlaintextSummaryRetirementTest extends TestCase
{
	private const INC = __DIR__ . '/../../src/usr/local/pkg/pfblockerng/pfblockerng.inc';
	private const APPLY = __DIR__ . '/../../src/usr/local/pkg/pfblockerng/pfblockerng_apply.inc';
	private const INSTALL = __DIR__ . '/../../src/usr/local/pkg/pfblockerng/pfblockerng_install.inc';

	private string $source;
	private string $installSource;

	protected function setUp(): void
	{
		$umbrella = php_strip_whitespace(self::INC);
		$apply = php_strip_whitespace(self::APPLY);
		$installSource = php_strip_whitespace(self::INSTALL);
		$this->assertNotSame('', $umbrella, 'failed to read pfblockerng.inc');
		$this->assertNotSame('', $installSource, 'failed to read pfblockerng_install.inc');
		$source = $umbrella . "\n" . $apply;
		$this->assertNotSame('', trim($source), 'pfblockerng.inc + pfblockerng_apply.inc must be nonempty');
		$this->assertStringContainsString('function dnsbl_save_stats(', $source);
		$this->assertStringContainsString('function pfb_update_unbound(', $source);
		$this->source = $source;
		$this->installSource = $installSource;
	}

	public function testLegacySummaryAndAnalysisSurfaceIsFullyRetired(): void
	{
		$allProduction = $this->source . "\n" . $this->installSource;
		foreach ([
			'function tld_analysis(',
			'function dnsbl_alias_update(',
			"\$pfb['tld_update']",
			"\$pfb['dnsalias']",
			'failed to open master alias file',
		] as $legacyToken) {
			$this->assertStringNotContainsString($legacyToken, $allProduction, "retired token survived: {$legacyToken}");
		}

		$this->assertMatchesRegularExpression(
			'/function dnsbl_stats_update\(\$mode, \$alias, \$alias_cnt\)/',
			$this->source
		);
		$this->assertMatchesRegularExpression(
			'/function pfb_dnsbl_tld_stats_finalize\(array \$group_counts\): bool/',
			$this->source
		);

		$statsBody = $this->functionBody('dnsbl_stats_update');
		$finalizerBody = $this->functionBody('pfb_dnsbl_tld_stats_finalize');
		foreach (['folder', 'lists', 'path', 'fopen(', 'fgets(', 'fwrite(', 'glob(', 'dnsalias'] as $ioToken) {
			$this->assertStringNotContainsString($ioToken, $statsBody, "stats helper retained I/O input/work: {$ioToken}");
			$this->assertStringNotContainsString($ioToken, $finalizerBody, "TLD finalizer retained I/O input/work: {$ioToken}");
		}

		$cleanup = 'rmdir_recursive("{$pfb[\'dbdir\']}/dnsblalias");';
		$this->assertSame(1, substr_count($this->source, $cleanup), 'full clear must remove the exact legacy directory once');
		$this->assertSame(1, substr_count($this->installSource, $cleanup), 'install/upgrade must remove the exact legacy directory once');
		$this->assertStringNotContainsString('dnsblalias', str_replace($cleanup, '', $allProduction));
	}

	public function testAllStatsRowsUseCountsWithoutPlaintextFeedLists(): void
	{
		if (!str_contains($this->source, 'function dnsbl_stats_update(')) {
			$this->assertStringContainsString('function dnsbl_alias_update(', $this->source);
			return;
		}

		$this->assertStringContainsString("dnsbl_stats_update('update', \$alias, \$alias_cnt);", $this->source);

		$finalizerBody = $this->functionBody('pfb_dnsbl_tld_stats_finalize');
		$this->assertStringContainsString("\$group_counts['DNSBL_TLD'] = \$tld_cnt;", $finalizerBody);
		$this->assertStringContainsString("\$pfb['alias_dnsbl_all'][]", $finalizerBody);
		$this->assertStringContainsString('foreach ($group_counts as $alias => $alias_cnt)', $finalizerBody);
		$this->assertSame(1, substr_count($finalizerBody, 'dnsbl_save_stats();'));
		$this->assertStringNotContainsString("['feeds']", $finalizerBody);
	}

	public function testTldStatsFinalizationRetainsTheReloadAndDomainGates(): void
	{
		if (!str_contains($this->source, 'function pfb_dnsbl_tld_stats_finalize(')) {
			$this->assertStringContainsString('function tld_analysis(', $this->source);
			return;
		}

		$reloadBody = $this->functionBody('pfb_update_unbound');
		$enableGate = strpos($reloadBody, 'if (pfb_dnsbl_active() && !$pfb[\'save\'])');
		$toggleGate = strpos($reloadBody, "if (\$pfb['dnsbl_tld_wildcard'])", $enableGate);
		$domainGate = strpos($reloadBody, "if (\$pfb['domain_update'])", $toggleGate);
		$finalizeCall = strpos($reloadBody, 'if (!pfb_dnsbl_tld_stats_finalize($dnsbl_tld_group_counts))', $domainGate);
		$this->assertNotFalse($enableGate);
		$this->assertNotFalse($toggleGate);
		$this->assertNotFalse($domainGate);
		$this->assertNotFalse($finalizeCall);
		$this->assertLessThan($toggleGate, $enableGate);
		$this->assertLessThan($domainGate, $toggleGate);
		$this->assertLessThan($finalizeCall, $domainGate);

		$this->assertSame(2, substr_count($this->source, 'pfb_dnsbl_tld_stats_finalize('), 'expected one definition and one gated call');
	}

	private function functionBody(string $name): string
	{
		$start = strpos($this->source, "function {$name}(");
		$this->assertNotFalse($start, "function {$name}() not found");
		$braceOpen = strpos($this->source, '{', $start);
		$this->assertNotFalse($braceOpen, "function {$name}() has no opening brace");

		$depth = 0;
		for ($i = $braceOpen, $length = strlen($this->source); $i < $length; $i++) {
			if ($this->source[$i] === '{') {
				$depth++;
			} elseif ($this->source[$i] === '}') {
				$depth--;
				if ($depth === 0) {
					$body = substr($this->source, $start, $i - $start + 1);
					$this->assertNotSame('', trim($body), "function {$name}() extraction was empty");
					return $body;
				}
			}
		}

		$this->fail("function {$name}() has no matching closing brace");
	}
}
