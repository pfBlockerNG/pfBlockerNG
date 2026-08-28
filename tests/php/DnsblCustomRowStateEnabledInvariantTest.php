<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\TestCase;

/**
 * Issues #1323/#2114 -- custom rows must stay Enabled and carry explicit parser
 * metadata. The three live sync routes share one row-construction decision;
 * behavior tests exercise that decision with each route's inputs.
 */
#[CoversFunction('pfb_dnsbl_custom_row')]
#[CoversFunction('pfb_dnsbl_hold_stale_rebuild_skip')]
final class DnsblCustomRowStateEnabledInvariantTest extends TestCase
{
	public function testDnsblNormalizationRouteBuildsEnabledCustomRow(): void
	{
		$this->assertSame(
			[
				'header' => 'normalization_custom',
				'custom' => 'normal.example',
				'format' => 'regex',
				'state'  => 'Enabled',
				'url'    => 'custom',
			],
			pfb_dnsbl_custom_row('normalization', 'normal.example')
		);
	}

	public function testDnsblDownloadRouteBuildsEnabledCustomRow(): void
	{
		$this->assertSame(
			[
				'header' => 'download_custom',
				'custom' => ['download.example', '||ads.download.example^'],
				'format' => 'regex',
				'state'  => 'Enabled',
				'url'    => 'custom',
			],
			pfb_dnsbl_custom_row('download', ['download.example', '||ads.download.example^'])
		);
	}

	public function testIpAliasDownloadRouteBuildsEnabledCustomRow(): void
	{
		$this->assertSame(
			[
				'header' => 'ip-alias_custom',
				'custom' => "192.0.2.1\n198.51.100.7",
				'format' => 'regex',
				'state'  => 'Enabled',
				'url'    => 'custom',
			],
			pfb_dnsbl_custom_row('ip-alias', "192.0.2.1\n198.51.100.7")
		);
	}

	public function testIpAliasCustomRowSelectsRegexParserWithoutDiagnostics(): void
	{
		$source = file_get_contents(
			dirname(__DIR__, 2) . '/src/usr/local/pkg/pfblockerng/pfblockerng_apply.inc'
		);
		if (!is_string($source)) {
			throw new RuntimeException('test bootstrap: failed to read pfblockerng_apply.inc');
		}
		$marker = strpos($source, "// Set 'auto' format for all lists");
		$start = $marker === FALSE ? FALSE : strpos($source, 'if (', $marker);
		$end = $start === FALSE ? FALSE : strpos($source, '// issue #1925:', $start);
		if ($start === FALSE || $end === FALSE) {
			throw new RuntimeException('test bootstrap: IP parser-selection block not found');
		}

		$row = pfb_dnsbl_custom_row('ip-alias', "192.0.2.1\n198.51.100.7");
		$diagnostics = [];
		set_error_handler(
			static function (int $severity, string $message) use (&$diagnostics): bool {
				$diagnostics[] = $message;
				return TRUE;
			},
			E_WARNING | E_DEPRECATED
		);
		try {
			eval(substr($source, $start, $end - $start));
		} finally {
			restore_error_handler();
		}

		$this->assertSame('regex', $pftype);
		$this->assertSame([], $diagnostics);
	}

	public function testLiveSyncDispatchKeepsAllThreeRoutesOnSharedRowSeam(): void
	{
		$source = php_strip_whitespace(
			dirname(__DIR__, 2) . '/src/usr/local/pkg/pfblockerng/pfblockerng_apply.inc'
		);
		$call = 'pfb_dnsbl_custom_row($list[\'aliasname\'], $list[\'custom\'])';
		$this->assertSame(
			3,
			substr_count($source, $call),
			'live sync_package_pfblockerng download/firewall/service dispatch has no '
			. 'off-appliance PHPUnit driver (#993); this executable-code pin keeps all '
			. 'three routes on the shared custom-row synthesis seam'
		);
	}

	public function testEnabledCustomRowNeverTriggersHoldStaleRebuildSkip(): void
	{
		$customRow = pfb_dnsbl_custom_row('Some', 'example.com');
		$isHold = $customRow['state'] == 'Hold';
		$this->assertFalse($isHold, 'a synthesized custom row must never read as Hold');

		foreach ([TRUE, FALSE] as $staleGenerationRebuild) {
			foreach ([TRUE, FALSE] as $origExists) {
				$this->assertFalse(
					pfb_dnsbl_hold_stale_rebuild_skip($staleGenerationRebuild, $isHold, $origExists),
					"a custom row (state=Enabled) must never trigger the Hold-skip guard "
					. "(stale_rebuild={$staleGenerationRebuild}, orig_exists={$origExists})"
				);
			}
		}
	}
}
