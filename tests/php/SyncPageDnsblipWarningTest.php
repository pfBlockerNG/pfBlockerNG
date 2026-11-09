<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * The Sync page's DNSBL IP rule warning must follow the node's own pfB-DNS
 * setting (issue #3770): DNSBL only runs through pfB-DNS, so with pfB-DNS off
 * no DNSBL IP aliases exist for the High Availability peer to miss.
 *
 * The page cannot be require()d off-appliance, so the warning call is
 * eval-extracted from the real source and run against seeded config. The
 * pfB-DNS argument the page reads from config is pinned by the off row.
 */
final class SyncPageDnsblipWarningTest extends TestCase
{
	private mixed $savedConfig;

	public static function setUpBeforeClass(): void
	{
		if (function_exists('pfb_sync_page_dnsblip_warning')) {
			return;
		}
		$src = file_get_contents(
			dirname(__DIR__, 2) . '/src/usr/local/www/pfblockerng/pfblockerng_sync.php'
		);
		if ($src === FALSE || !preg_match('/^(if \(pfblockerng_sync_dnsblip_mismatch\((?:.*\n)*?\})$/m', $src, $block)) {
			throw new RuntimeException('test bootstrap: sync-page DNSBL IP warning block not found');
		}
		if (!str_contains($block[1], 'print_info_box(')) {
			throw new RuntimeException('test bootstrap: extract is not the warning block');
		}

		eval('function pfb_sync_page_dnsblip_warning(array $pconfig): void {' . "\n" . $block[1] . "\n}");
	}

	protected function setUp(): void
	{
		$this->savedConfig = $GLOBALS['config'] ?? NULL;
		$GLOBALS['config'] = [];
		$GLOBALS['pfb_test_info_boxes'] = [];
	}

	protected function tearDown(): void
	{
		$GLOBALS['config'] = $this->savedConfig;
		unset($GLOBALS['pfb_test_info_boxes']);
	}

	/** @return iterable<string, array{PfbToggle, bool}> */
	public static function pfbDnsCases(): iterable
	{
		yield 'pfB-DNS on warns' => [PfbToggle::On, TRUE];
		yield 'pfB-DNS off stays silent' => [PfbToggle::Off, FALSE];
	}

	#[DataProvider('pfbDnsCases')]
	public function testTheWarningFollowsPfbDns(PfbToggle $pfbDns, bool $warns): void
	{
		PfbConfig::writeSystem('gen/enable_cb', PfbToggle::On);
		PfbConfig::writeSystem('dnsbl/pfb_dnsbl', PfbToggle::On);
		PfbConfig::writeSystem('dnsbl/action', 'Deny_Both');
		PfbConfig::writeSystem('dns/pfb_dns', $pfbDns);
		config_set_path('hasync/synchronizerules', 'on');

		pfb_sync_page_dnsblip_warning(['syncscope' => 'lists', 'varsynconchanges' => 'auto']);

		$this->assertCount($warns ? 1 : 0, $GLOBALS['pfb_test_info_boxes']);
		if ($warns) {
			$this->assertSame('warning', $GLOBALS['pfb_test_info_boxes'][0][1]);
		}
	}
}
