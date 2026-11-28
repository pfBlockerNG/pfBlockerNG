<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;

/** Issue #2308: Extras share the runtime schedule, but never the feed cron cache. */
final class ExtrasScheduleRuntimeTest extends TestCase
{
	private mixed $originalPfb = NULL;
	private mixed $originalConfig = NULL;

	protected function setUp(): void
	{
		$this->originalPfb = $GLOBALS['pfb'];
		$this->originalConfig = $GLOBALS['config'] ?? NULL;
		$GLOBALS['config'] ??= [];
	}

	protected function tearDown(): void
	{
		$GLOBALS['pfb'] = $this->originalPfb;
		$GLOBALS['config'] = $this->originalConfig;
	}

	private function general(string $master = ''): array
	{
		return [
			'pfb_scheduled_feed_updates' => $master,
			'pfb_schedule_weekday' => '3',
			'pfb_schedule_hour' => '2',
			'pfb_schedule_minute' => '15',
		];
	}

	private function feedSections(): array
	{
		return [
			'ipv4' => [[
				'action' => 'Deny_Inbound',
				'cron' => 'EveryDay',
				'schedule_override' => '',
				'row' => [['header' => 'feed', 'url' => 'https://example.test/feed', 'state' => 'Enabled']],
			]],
			'ipv6' => [],
			'dnsbl' => [],
		];
	}

	public function testExtraEligibilityAndCadenceAffectSecretFreeHash(): void
	{
		$base = pfb_schedule_runtime_model($this->general(), $this->feedSections(), [
			'dcc' => TRUE,
			'bl' => ['enabled' => TRUE, 'cadence' => 'EveryDay'],
		]);
		$weekly = pfb_schedule_runtime_model($this->general(), $this->feedSections(), [
			'dcc' => TRUE,
			'bl' => ['enabled' => TRUE, 'cadence' => 'Weekly'],
		]);
		$disabled = pfb_schedule_runtime_model($this->general(), $this->feedSections(), [
			'dcc' => FALSE,
			'bl' => ['enabled' => FALSE, 'cadence' => 'EveryDay'],
		]);

		$this->assertIsArray($base);
		$this->assertIsArray($weekly);
		$this->assertIsArray($disabled);
		$this->assertNotSame($base['config_hash'], $weekly['config_hash']);
		$this->assertNotSame($base['config_hash'], $disabled['config_hash']);
		$this->assertStringNotContainsString('secret', $base['config_hash']);
	}

	public function testMalformedBlacklistIdentitySuppressesRuntimeInsteadOfThrowing(): void
	{
		config_set_path('installedpackages/pfblockerng/config/0', [
			'pfb_scheduled_feed_updates' => 'on', 'pfb_schedule_weekday' => '7',
			'pfb_schedule_hour' => '1', 'pfb_schedule_minute' => '0',
		]);
		config_set_path('installedpackages/pfblockernglistsv4/config', []);
		config_set_path('installedpackages/pfblockernglistsv6/config', []);
		config_set_path('installedpackages/pfblockerngdnsbl/config', []);
		config_set_path('installedpackages/pfblockerngblacklist', [
			'blacklist_enable' => 'Enable', 'blacklist_selected' => 'one', 'blacklist_freq' => 'EveryDay',
			'item' => [['xml' => [], 'selected' => 'yes', 'title' => 'One', 'feed' => 'https://example.test/one']],
		]);

		$this->assertNull(pfb_schedule_runtime_config());

		config_set_path('installedpackages/pfblockerngblacklist', [
			'blacklist_enable' => 'Enable', 'blacklist_selected' => 'bad;id', 'blacklist_freq' => 'EveryDay',
			'item' => [[
				'xml' => 'bad;id', 'selected' => 'yes', 'title' => 'Bad', 'feed' => 'https://example.test/bad',
			]],
		]);
		$this->assertNull(pfb_schedule_runtime_config());

		config_set_path('installedpackages/pfblockerngblacklist', [
			'blacklist_enable' => 'Enable', 'blacklist_selected' => '0', 'blacklist_freq' => 'EveryDay',
			'item' => [[
				'xml' => '0', 'selected' => 'yes', 'title' => 'Zero', 'feed' => 'https://example.test/zero',
			]],
		]);
		$this->assertNull(pfb_schedule_runtime_config());
	}

	/** Issue #3475: the Blacklist page saves blacklist_selected comma-joined; the comma must stay valid. */
	public function testCommaJoinedBlacklistSelectionBuildsRuntimeModel(): void
	{
		$this->assertTrue(pfb_blacklist_identity_valid('shallalist,ut1'));
		$this->assertFalse(pfb_blacklist_identity_valid('shallalist;ut1'));

		config_set_path('installedpackages/pfblockerng/config/0', [
			'pfb_scheduled_feed_updates' => 'on', 'pfb_schedule_weekday' => '7',
			'pfb_schedule_hour' => '1', 'pfb_schedule_minute' => '0',
		]);
		config_set_path('installedpackages/pfblockernglistsv4/config', []);
		config_set_path('installedpackages/pfblockernglistsv6/config', []);
		config_set_path('installedpackages/pfblockerngdnsbl/config', []);
		config_set_path('installedpackages/pfblockerngblacklist', [
			'blacklist_enable' => 'Enable', 'blacklist_selected' => 'shallalist,ut1', 'blacklist_freq' => 'EveryDay',
			'item' => [
				['xml' => 'shallalist', 'selected' => 'yes', 'title' => 'Shallalist', 'feed' => 'https://example.test/shalla'],
				['xml' => 'ut1', 'selected' => 'yes', 'title' => 'UT1', 'feed' => 'https://example.test/ut1'],
			],
		]);

		$model = pfb_schedule_runtime_config();

		$this->assertNotNull($model);
		// Only the second token (ut1) can enable the job: shallalist is discontinued.
		$this->assertTrue($model['entries']['extra:bl']['enabled']);
	}
}
