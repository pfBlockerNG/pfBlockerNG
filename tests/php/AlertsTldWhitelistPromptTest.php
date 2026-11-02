<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\TestCase;

/**
 * issue #3647: the whitelist icon on a row blocked by a TLD Blacklist entry opens the DNSBL
 * Whitelist flow. The prompt is plain text (a `title` attribute read by confirm()), never marked up.
 */
#[CoversFunction('dnsbl_whitelist_type')]
final class AlertsTldWhitelistPromptTest extends TestCase
{
	/** @var array<string, mixed> */
	private array $savedGlobals = [];

	public static function setUpBeforeClass(): void
	{
		require_once __DIR__ . '/AlertsPageLoader.php';
		pfb_test_load_alerts_page_functions();
	}

	protected function setUp(): void
	{
		foreach (['pfb'] as $g) {
			$this->savedGlobals[$g] = $GLOBALS[$g] ?? null;
		}
		$GLOBALS['pfb'] = ['dnsbl_py_blacklist' => false];
	}

	protected function tearDown(): void
	{
		foreach ($this->savedGlobals as $g => $v) {
			$GLOBALS[$g] = $v;
		}
	}

	/** @return array{id: string, title: string} */
	private function iconFor(string $mode): array
	{
		$fields = [2 => 'bad.example', 5 => $mode, 6 => 'TLD', 7 => 'www.bad.example', 8 => 'TLD'];
		[$icon] = dnsbl_whitelist_type($fields, [], false, false, 'bad.example');
		$this->assertSame(1, preg_match('/id="([^"]*)" title="([^"]*)"/', (string) $icon, $m), 'no icon id/title in: ' . $icon);
		return ['id' => $m[1], 'title' => html_entity_decode($m[2])];
	}

	public function testTldBlockedRowPromptNamesTheDnsblWhitelist(): void
	{
		$icon = $this->iconFor('DNSBL_TLD');

		$this->assertStringStartsWith('DNSBLWT|tld|bad.example|', $icon['id'], 'sanity: this is the whole-TLD whitelist icon');
		$this->assertStringNotContainsString('<strong>', $icon['title'], 'confirm() shows plain text; markup would appear literally');
	}

	public function testDnsblRowKeepsItsOwnWhitelistIcon(): void
	{
		$icon = $this->iconFor('DNSBL');

		$this->assertStringStartsWith('DNSBLWT|add|', $icon['id'], 'a plain DNSBL row keeps the add icon, not the TLD one');
	}
}
