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
		$this->assertStringContainsString("\$pfb['changed_dnsbl_groups'][] = \$alias", $source);
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
			'/function pfb_dnsbl_tld_stats_finalize\(array \$group_counts\): void/',
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

		$changed = strpos($this->source, "\$pfb['changed_dnsbl_groups'][] = \$alias");
		$route = strpos($this->source, "if (\$pfb['aliasupdate'] && !\$pfb['dnsbl_tld_wildcard'])", $changed);
		$this->assertNotFalse($changed);
		$this->assertNotFalse($route);
		$this->assertLessThan($route, $changed, 'changed-group append must precede the TLD routing split');

		$this->assertStringContainsString("dnsbl_stats_update('update', \$alias, \$alias_cnt);", $this->source);
		$this->assertStringContainsString("\$dnsbl_tld_group_counts[\$alias] = \$alias_cnt;", $this->source);
		$this->assertStringContainsString("dnsbl_stats_update('disabled', \$alias, '');", $this->source);
		foreach ([
			"dnsbl_stats_update('update', 'DNSBL_IDN', \$idn_cnt);",
			"dnsbl_stats_update('update', 'DNSBL_Homoglyph', 1);",
			"dnsbl_stats_update('update', 'DNSBL_Homoglyph_Suspect', 1);",
			"dnsbl_stats_update('update', 'DNSBL_TLD_Allow', \$tld_allow_cnt);",
			"dnsbl_stats_update('update', 'DNSBL_Regex', \$regex_cnt);",
		] as $specialCall) {
			$this->assertStringContainsString($specialCall, $this->source, "missing special stats row: {$specialCall}");
		}

		$finalizerBody = $this->functionBody('pfb_dnsbl_tld_stats_finalize');
		$this->assertStringContainsString("\$group_counts['DNSBL_TLD'] = \$tld_cnt;", $finalizerBody);
		$this->assertStringContainsString("\$pfb['alias_dnsbl_all'][]", $finalizerBody);
		$this->assertStringContainsString('foreach ($group_counts as $alias => $alias_cnt)', $finalizerBody);
		$this->assertSame(1, substr_count($finalizerBody, 'dnsbl_save_stats();'));
		$this->assertStringNotContainsString("['feeds']", $finalizerBody);
	}

	public function testDisabledGroupHasValidatedAliasBeforeStatsUpdate(): void
	{
		$groupLoop = strpos($this->source, 'foreach ($lists as $list)');
		$this->assertNotFalse($groupLoop);
		$assignmentMatched = preg_match(
			'/\$alias\s*=\s*"DNSBL_\{\$list\[\'aliasname\'\]\}";/',
			$this->source,
			$assignmentMatch,
			PREG_OFFSET_CAPTURE,
			$groupLoop
		);
		$this->assertSame(1, $assignmentMatched, 'DNSBL alias assignment not found');
		$aliasAssignment = $assignmentMatch[0][1];
		$aliasValidation = strpos(
			$this->source,
			"if (empty(pfb_filter(\$alias, PFB_FILTER_WORD, 'DNSBL - Processes')))",
			$groupLoop
		);
		$invalidAliasSkip = strpos($this->source, 'continue;', $aliasValidation === false ? $groupLoop : $aliasValidation);
		$activeBranch = strpos($this->source, "if (\$list['action'] != 'Disabled' && isset(\$list['row']))", $groupLoop);
		$disabledStats = strpos($this->source, "dnsbl_stats_update('disabled', \$alias, '');", $groupLoop);
		$this->assertNotFalse($aliasAssignment);
		$this->assertNotFalse($aliasValidation);
		$this->assertNotFalse($invalidAliasSkip);
		$this->assertNotFalse($activeBranch);
		$this->assertNotFalse($disabledStats);
		$this->assertLessThan($aliasValidation, $aliasAssignment, 'alias must exist before validation');
		$this->assertLessThan($invalidAliasSkip, $aliasValidation, 'validation must precede its invalid-alias skip');
		$this->assertLessThan($activeBranch, $invalidAliasSkip, 'validation and invalid-alias skip must precede the branch');
		$this->assertLessThan($disabledStats, $activeBranch, 'disabled stats must consume the validated alias');
	}

	public function testTldStatsFinalizationRetainsTheReloadAndDomainGates(): void
	{
		if (!str_contains($this->source, 'function pfb_dnsbl_tld_stats_finalize(')) {
			$this->assertStringContainsString('function tld_analysis(', $this->source);
			return;
		}

		$reloadBody = $this->functionBody('pfb_update_unbound');
		$enableGate = strpos($reloadBody, "if (\$pfb['enable'] === PfbToggle::On && \$pfb['dnsbl'] === PfbToggle::On && !\$pfb['save'])");
		$toggleGate = strpos($reloadBody, "if (\$pfb['dnsbl_tld_wildcard'])", $enableGate);
		$domainGate = strpos($reloadBody, "if (\$pfb['domain_update'])", $toggleGate);
		$finalizeCall = strpos($reloadBody, 'pfb_dnsbl_tld_stats_finalize($dnsbl_tld_group_counts);', $domainGate);
		$this->assertNotFalse($enableGate);
		$this->assertNotFalse($toggleGate);
		$this->assertNotFalse($domainGate);
		$this->assertNotFalse($finalizeCall);
		$this->assertLessThan($toggleGate, $enableGate);
		$this->assertLessThan($domainGate, $toggleGate);
		$this->assertLessThan($finalizeCall, $domainGate);

		$reloadPredicate = strpos(
			$this->source,
			"if (pfb_dnsbl_reload_needed(!empty(\$pfb['dnsbl_publish_failed']), !empty(\$pfb_data_changed), !empty(\$pfbupdate),"
		);
		$reloadInvocation = strpos($this->source, 'pfb_update_unbound($mode, $pfbupdate, $pfbpython, $dnsbl_tld_group_counts);', $reloadPredicate);
		$this->assertNotFalse($reloadPredicate);
		$this->assertNotFalse($reloadInvocation);
		$this->assertLessThan($reloadInvocation, $reloadPredicate, 'finalization data must enter only through the reload predicate');
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
