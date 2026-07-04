<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * Pin the Alerts-tab "default GET request" whitelist built by
 * pfb_alerts_default_page(). Reads $pfb['config_global']['pfbpageload'] and
 * maps it to '?view=<name>' for a fixed whitelist of 7 known views; anything
 * else (an unknown value, or the key/section absent entirely) falls back to
 * the plain '' default.
 *
 * Coverage mandate (CLAUDE.md): every whitelisted view, plus the unknown and
 * absent-input branches.
 */
#[CoversFunction('pfb_alerts_default_page')]
final class AlertsDefaultPageTest extends TestCase
{
	/** Saved $GLOBALS['pfb'], restored in tearDown. */
	private mixed $savedPfb = null;
	private bool $hadPfb = false;

	protected function setUp(): void
	{
		$this->hadPfb = array_key_exists('pfb', $GLOBALS);
		$this->savedPfb = $GLOBALS['pfb'] ?? null;
	}

	protected function tearDown(): void
	{
		if ($this->hadPfb) {
			$GLOBALS['pfb'] = $this->savedPfb;
		} else {
			unset($GLOBALS['pfb']);
		}
	}

	/**
	 * Each whitelisted view maps to its own '?view=<name>' query string.
	 *
	 * @return array<string,array{0:string}>
	 */
	public static function whitelistedViewsProvider(): array
	{
		return [
			'dnsbl_stat'       => ['dnsbl_stat'],
			'dnsbl_reply_stat' => ['dnsbl_reply_stat'],
			'ip_block_stat'    => ['ip_block_stat'],
			'ip_permit_stat'   => ['ip_permit_stat'],
			'ip_match_stat'    => ['ip_match_stat'],
			'reply'            => ['reply'],
			'unified'          => ['unified'],
		];
	}

	#[DataProvider('whitelistedViewsProvider')]
	public function testWhitelistedViewProducesQueryString(string $view): void
	{
		$GLOBALS['pfb'] = ['config_global' => ['pfbpageload' => $view]];

		$this->assertSame("?view={$view}", pfb_alerts_default_page());
	}

	/**
	 * An unrecognized view name falls back to the '' default — never echoed
	 * back unfiltered into the query string.
	 */
	public function testUnknownViewFallsBackToDefault(): void
	{
		$GLOBALS['pfb'] = ['config_global' => ['pfbpageload' => 'not_a_real_view']];

		$this->assertSame('', pfb_alerts_default_page());
	}

	/**
	 * No 'pfbpageload' key set at all (fresh page load) falls back to ''.
	 */
	public function testAbsentPfbpageloadFallsBackToDefault(): void
	{
		$GLOBALS['pfb'] = ['config_global' => []];

		$this->assertSame('', pfb_alerts_default_page());
	}

	/**
	 * No 'config_global' section at all falls back to ''.
	 */
	public function testAbsentConfigGlobalFallsBackToDefault(): void
	{
		$GLOBALS['pfb'] = [];

		$this->assertSame('', pfb_alerts_default_page());
	}
}
