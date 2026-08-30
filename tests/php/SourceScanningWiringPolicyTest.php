<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;

/**
 * Issue #2103 audit ledger and regression policy.
 *
 * PRODUCTION COMMENTS AND DOCBLOCKS MUST NEVER BE LOAD-BEARING FOR A TEST.
 * Behavioral suites do not inspect production source. The few hybrid/static suites below
 * retain only comment-free executable-code pins because their outer property is destructive,
 * appliance-only, off-limits in this issue, or inherently a whole-tree static invariant.
 */
final class SourceScanningWiringPolicyTest extends TestCase
{
	private const SOURCE_EXECUTION = [
		'AlertDetailsCsvFieldTest.php',
		'AlertsAsnCsvTest.php',
		'AlertsCustomlistIdnRecognitionTest.php',
		'AlertsDnsblFeedGroupCellGroupingTest.php',
		'AlertsDnsblLoggedFieldsRenderTest.php',
		'AlertsDnsblLimitGateTest.php',
		'AlertsDnsReplyWhitelistTypeTest.php',
		'AlertsFeedMatchCellGroupingTest.php',
		'AlertsFilterFieldsInitTest.php',
		'AlertsFreshTopBlockTest.php',
		'AlertsIpConvertPrefetchParityTest.php',
		'AlertsIpUnlockIconTest.php',
		'AlertsMultibyteTruncationTest.php',
		'AlertsPieBlockAndStatsGuardTest.php',
		'AlertsRowOutputEncodingTest.php',
		'AlertsStatHostnameCellTest.php',
		'BlacklistLangFallbackTest.php',
		'CategoryEditAutoSortTest.php',
		'CategoryEditCustomFlagTest.php',
		'CategoryEditFreshRowPconfigTest.php',
		'CategoryEditIdnWildcardTest.php',
		'CategoryEditPostGuardTest.php',
		'CategoryEditReservedHeaderTest.php',
		'CategoryFeedsAliasTruncationRenderTest.php',
		'CategoryPostdataInvalidPrefixGuardTest.php',
		'DnsblCustomListWildcardValidationTest.php',
		'DnsblFeedIdnWildcardTest.php',
		'DnsblFreshPconfigTest.php',
		'DnsblWildcardRowValidationTest.php',
		'FeedsAltSelectedKeyTest.php',
		'FeedsCustomOutputEncodingTest.php',
		'FeedsUrlCompareAltHeaderUndefinedKeyTest.php',
		'FeedsUrlCompareIconRenderTest.php',
		'FilterlogFieldGuardTest.php',
		'FreshConfigNullGuardCloseoutTest.php',
		'GeoipContinentUndefinedBucketTest.php',
		'HooksSanitizeIngestionTest.php',
		'InstallGeneralToIpMigrationTest.php',
		'InstallGrandfatherChokepointTest.php',
		'IpArrayFieldIngressGuardTest.php',
		'IpSettingsAdvAliasValidationTest.php',
		'Issue1792SinkholeLabelTest.php',
		'Issue1792SweepSitesTest.php',
		'LogSelectedTypeTest.php',
		'LogValidateFilepathTest.php',
		'PfbWidgetOracleTest.php',
		'Top1mDccBaselineIntegrityTest.php',
		'Top1mDccDetectorTest.php',
		'WidgetAliasHiddenTest.php',
		'WidgetIncludeConventionTest.php',
		'WidgetSortTableTest.php',
		'WhitelistTrashIconTest.php',
		'WizardDisableCsrfTest.php',
	];

	private const EXCLUDED_NON_WIRING = [
		'DnsblRegexEntryErrorTest.php' => 'executes the shipped Python helper',
		'FeedsDiscontinuedTest.php' => 'parses the shipped JSON feed catalogue',
		'HookEditorDeleteTest.php' => 'requires and calls the page-only include',
		'PrivPageMatchesTest.php' => 'requires shipped privilege data',
		'RequireConfigGatewaySniffTest.php' => 'whole-tree PHPCS analyzer contract',
		'SourceScanningWiringPolicyTest.php' => 'comment-mutation audit harness, not a wiring assertion',
		'SrcPhpDeprecationLintTest.php' => 'whole-tree PHP lint contract',
		'TickEntrypointTest.php' => 'calls the bootstrap-loaded entrypoint',
	];

	private const BEHAVIORAL = [
		'AnchorRowRelocationWiringTest.php',
		'CategoryEditCustomEditorSortModePlacementTest.php',
		'CategoryEditCustomEditorWiringTest.php',
		'ClearSqliteTimestampFormatTest.php',
		'CountryNetworksCountGuardTest.php',
		'DnsblListEditorWiringTest.php',
		'DnsblListScriptWiringTest.php',
		'DnsblQueryClientTest.php',
		'DnsblRegexHighlightWiringTest.php',
		'DnsblRegexToggleGateWiringTest.php',
		'EditHooksPageWiringTest.php',
		'EditHooksSyntaxHighlightWiringTest.php',
		'GeneralAllowlistEditorWiringTest.php',
		'GeoipContinentCatStderrGuardTest.php',
		'GeoipDocLinkTest.php',
		'IpRegexBoundaryGuardTest.php',
		'IpRegexPrefilterGuardTest.php',
		'IpSuppressionEditorWiringTest.php',
		'LintEndpointWiringTest.php',
		'ListScriptReparseWiringTest.php',
		'LogTimestampBaselineTest.php',
		'PfbJsCacheBustingWiringTest.php',
		'PythonTldWildcardIniEmitTest.php',
		'PythonWhitelistTldSegTest.php',
		'RegexIniTransportTest.php',
		'TldBridgeEmitTest.php',
		'Top1mApplyRefreshMatrixTest.php',
		'UpdateAjaxTailJsonEncodingTest.php',
		'WidgetGetTableArgOrderTest.php',
		'WidgetPostAllowedTest.php',
		'WidgetSubmitPostGuardTest.php',
	];

	private const RETAINED = [
		'AlertsPfctlCheckedSitesTest.php' => 'off-limits live Alerts pfctl/render dispatch',
		'AlertsStatPipelineLocaleSafetyTest.php' => 'off-limits live Alerts command pipeline',
		'AlertsUnboundCachePolicyTest.php' => 'off-limits live Alerts/Unbound cache dispatch',
		'AliasCntGrepCountGuardTest.php' => '#993 live sync/download/firewall orchestration',
		'DnsblCustomRowStateEnabledInvariantTest.php' => '#993 live sync row synthesis dispatch',
		'DnsblFeedCountWiringTest.php' => 'live DNSBL and Unbound service restart dispatch',
		'DnsblIpCountGuardTest.php' => '#993 live sync/download/firewall orchestration',
		'DnsblPlaintextSummaryRetirementTest.php' => 'inherently cross-file retired-code invariant',
		'DnsblRegexHelpTextTest.php' => 'page render call lacks a help-text smoke assertion',
		'DownloadExtractionExitCodeTest.php' => 'six live archive extraction bodies',
		'DownloadRetvalFailsafeTest.php' => 'live download fail-safe initialization and final gate',
		'DownloadTrailingNewlineWiringTest.php' => 'live download finalization dispatch',
		'EscapedPathFilesystemCallTest.php' => 'inherently whole-tree filesystem safety rule',
		'GeoipOrigTrailingNewlineWiringTest.php' => '#993 live download/apply orchestration',
		'GeoipPackageGenerationCoverageTest.php' => 'destructive package install dispatch',
		'GeneralSyntaxHighlightToggleWiringTest.php' => 'config-backed page save dispatch',
		'GroupActionWiringTest.php' => 'appliance config-backed page dispatch',
		'GunzipTrailingNewlineWiringTest.php' => '#993 live download/apply orchestration',
		'HookEditFileContainmentTest.php' => 'destructive page file operations and include boundary',
		'InstallDnsblMoveRestartGuardTest.php' => 'destructive installer and live service restart',
		'InstallPrePassWriteOrderTest.php' => 'destructive package installer lifecycle',
		'IpParseLineWiringTest.php' => '#993 live sync/download/firewall orchestration',
		'IpRecomputeOrderChangeTest.php' => '#993 live config-order recompute dispatch',
		'IpRecomputeRanWiringTest.php' => '#993 live firewall and closing dispatch',
		'ListScriptTransformRerunWiringTest.php' => '#993 two live sync feed loops',
		'ListScriptExitStatusTest.php' => '#993 six live list-script loop dispatches',
		'ListScriptFailureLedgerWiringTest.php' => '#993 four live failure-ledger loop dispatches',
		'LogFormatConsumersTest.php' => 'live external-command and top-level page consumers',
		'LogLinecountGuardTest.php' => 'top-level authenticated AJAX dispatch',
		'LogNowTokenRetiredTest.php' => 'inherently whole-tree retired-code invariant',
		'PfbFeedNormalizeTest.php' => '#993 two live sync parse loops',
		'PfbSettingsFamilyPostInstallCaptureTest.php' => 'destructive package installer lifecycle',
		'PfbSettingsFamilyTest.php' => 'destructive package uninstall lifecycle',
		'PfbSyncStatusDnsblWritersTest.php' => '#993 live sync plus off-limits Alerts dispatch',
		'PfbSyncStatusIpWritersTest.php' => '#993 live sync/download/firewall orchestration',
		'ProbeBodyPurgeTest.php' => 'destructive package installer caller',
		'SyncCronPflexOrderTest.php' => 'off-limits live scheduling surface',
		'TimestampCosmeticNormalizationTest.php' => 'multiple live top-level/external producers',
		'ToggleMirrorComparisonGuardTest.php' => 'inherently whole-tree config-type rule',
		'ToggleEmptyPreservationTest.php' => 'six config-backed page save bindings',
		'Top1mTeardownWiringTest.php' => 'destructive uninstall and live sync teardown callers',
	];

	public function testAuditListsEveryConvertedSuiteExactlyOnce(): void
	{
		$audited = array_merge(
			self::BEHAVIORAL,
			self::SOURCE_EXECUTION,
			array_keys(self::RETAINED),
			array_keys(self::EXCLUDED_NON_WIRING)
		);
		$this->assertCount(133, $audited);
		$this->assertCount(133, array_unique($audited));
		foreach ($audited as $file) {
			$this->assertFileExists(__DIR__ . "/{$file}");
		}
	}

	public function testBehavioralSuitesDoNotStripAndSearchProductionSource(): void
	{
		foreach (self::BEHAVIORAL as $file) {
			$source = file_get_contents(__DIR__ . "/{$file}");
			$this->assertIsString($source);
			$this->assertStringNotContainsString('php_strip_whitespace', $source, $file);
		}
	}

	public function testEveryRetainedPinHasAnExplicitReasonAndIgnoresComments(): void
	{
		foreach (self::RETAINED as $file => $reason) {
			$this->assertNotSame('', trim($reason), $file);
			$source = file_get_contents(__DIR__ . "/{$file}");
			$this->assertIsString($source);
			$this->assertStringContainsString('php_strip_whitespace', $source, $file);
		}
	}

	public function testRewordingANearbyProductionCommentDoesNotChangeRetainedPinScope(): void
	{
		$sourcePath = dirname(__DIR__, 2) . '/src/usr/local/pkg/pfblockerng/pfblockerng_apply.inc';
		$source = file_get_contents($sourcePath);
		$this->assertIsString($source);
		$rewritten = str_replace(
			'// issue #1925: normalize once per file; the parse below reads .norm',
			'// nearby production explanation rewritten without preserving its old words',
			$source,
			$count
		);
		$this->assertSame(1, $count, 'comment-rewording fixture drifted');

		$temp = tempnam(sys_get_temp_dir(), 'pfb-comment-reword-');
		$this->assertIsString($temp);
		try {
			$this->assertNotFalse(file_put_contents($temp, $rewritten));
			$originalCode = php_strip_whitespace($sourcePath);
			$rewrittenCode = php_strip_whitespace($temp);
			$start = 'pfb_list_script_cleanup_staged(';
			$end = 'if (!empty($domain_data)) {';
			$this->assertSame(
				$this->sourceScope($originalCode, $start, $end),
				$this->sourceScope($rewrittenCode, $start, $end),
				'retained DNSBL staged-script pin must ignore nearby comment wording'
			);
		} finally {
			@unlink($temp);
		}
	}

	public function testRewordingEveryProductionPhpCommentDoesNotBreakSourceExecutionTests(): void
	{
		$root = dirname(__DIR__, 2);
		$temp = sys_get_temp_dir() . '/pfb-comment-reword-' . bin2hex(random_bytes(8));
		$this->copyTree("{$root}/src", "{$temp}/src", TRUE);
		$this->copyTree("{$root}/tests/php", "{$temp}/tests/php");

		$tests = [];
		foreach (self::SOURCE_EXECUTION as $file) {
			$target = "{$temp}/tests/php/{$file}";
			$tests[] = $target;
		}

		$command = array_merge([
			PHP_BINARY,
			"{$root}/vendor/bin/phpunit",
			'--configuration',
			"{$root}/phpunit.xml",
			'--do-not-cache-result',
		], $tests);
		$descriptors = [
			1 => ['pipe', 'w'],
			2 => ['pipe', 'w'],
		];

		try {
			$process = proc_open($command, $descriptors, $pipes, $root);
			$this->assertIsResource($process);
			$stdout = stream_get_contents($pipes[1]);
			$stderr = stream_get_contents($pipes[2]);
			fclose($pipes[1]);
			fclose($pipes[2]);
			$status = proc_close($process);
			$this->assertSame(0, $status, sprintf(
				"nested source-execution suite FAILED inside this wrapper's comment-reworded copy of "
				. "the tree (%s, removed on teardown). Every test name and message below belongs to "
				. "that NESTED run, not to this wrapper:\n%s\n%s",
				$temp,
				$stdout,
				$stderr
			));
		} finally {
			$this->removeTree($temp);
		}
	}

	private function copyTree(string $source, string $target, bool $rewordComments = FALSE): void
	{
		$this->assertTrue(mkdir($target, 0700, TRUE));
		$iterator = new RecursiveIteratorIterator(
			new RecursiveDirectoryIterator($source, FilesystemIterator::SKIP_DOTS),
			RecursiveIteratorIterator::SELF_FIRST
		);
		foreach ($iterator as $item) {
			$relative = $iterator->getSubPathName();
			$destination = "{$target}/{$relative}";
			if ($item->isDir()) {
				$this->assertTrue(mkdir($destination, 0700));
				continue;
			}
			$content = file_get_contents($item->getPathname());
			$this->assertIsString($content);
			if ($rewordComments && preg_match('/\.(?:inc|php)$/', $item->getFilename()) === 1) {
				$content = $this->rewordPhpComments($content);
			}
			$this->assertNotFalse(file_put_contents($destination, $content));
		}
	}

	private function sourceScope(string $source, string $start, string $end): string
	{
		$from = strrpos($source, $start);
		$this->assertNotFalse($from, "missing retained-pin start: {$start}");
		$to = strpos($source, $end, $from + strlen($start));
		$this->assertNotFalse($to, "missing retained-pin end: {$end}");
		return substr($source, $from, $to + strlen($end) - $from);
	}

	private function rewordPhpComments(string $source): string
	{
		$rewritten = '';
		foreach (token_get_all($source) as $token) {
			if (is_array($token) && $token[0] === T_ENCAPSED_AND_WHITESPACE) {
				$rewritten .= (string) preg_replace(
					'/(^|\n)([ \t]*)\/\/[^\n]*/',
					'$1$2// generated production comment reworded by issue 2103 regression',
					$token[1]
				);
				continue;
			}
			if (!is_array($token) || !in_array($token[0], [T_COMMENT, T_DOC_COMMENT], TRUE)) {
				$rewritten .= is_array($token) ? $token[1] : $token;
				continue;
			}
			$trimmed = ltrim($token[1]);
			if (str_starts_with($trimmed, '//')) {
				$replacement = '// production comment reworded by issue 2103 regression';
			} elseif (str_starts_with($trimmed, '#')) {
				$replacement = '# production comment reworded by issue 2103 regression';
			} else {
				$replacement = '/* production comment reworded by issue 2103 regression */';
			}
			$rewritten .= $replacement . str_repeat("\n", substr_count($token[1], "\n"));
		}
		return $rewritten;
	}

	private function removeTree(string $root): void
	{
		if (!is_dir($root)) {
			return;
		}
		$iterator = new RecursiveIteratorIterator(
			new RecursiveDirectoryIterator($root, FilesystemIterator::SKIP_DOTS),
			RecursiveIteratorIterator::CHILD_FIRST
		);
		foreach ($iterator as $item) {
			$item->isDir() ? rmdir($item->getPathname()) : unlink($item->getPathname());
		}
		rmdir($root);
	}
}
