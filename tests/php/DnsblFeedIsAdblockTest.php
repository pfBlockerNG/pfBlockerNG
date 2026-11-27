<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * issue #4272 (owner decisions, second round): a feed is an Adblock feed when its first non-blank
 * line is an Adblock-family header or, failing that, when any line is an Adblock rule. The AdGuard
 * Turkish filter has no header; its 'site#$?#…' rules each blocked the whole site.
 *
 * A '#'-led line never counts: hosts and IP feeds open with banners such as '#####', '###-----',
 * '##Title:' or '#%#%', and taking them for Adblock feeds would drop their IP lines and non-ICANN
 * hosts. A generic '##.ad' rule alone therefore leaves a feed per-line, where the capture guard still
 * takes it to the ABP path; site cosmetic rules ('site##', 'site#$?#') start with the site and count.
 */
final class DnsblFeedIsAdblockTest extends TestCase
{
	private string $dir;

	protected function setUp(): void
	{
		$this->dir = sys_get_temp_dir() . '/pfb_feed_is_abp_' . bin2hex(random_bytes(8));
		$this->assertTrue(mkdir($this->dir, 0700, TRUE));
	}

	protected function tearDown(): void
	{
		foreach (glob($this->dir . '/*') ?: [] as $file) {
			@unlink($file);
		}
		@rmdir($this->dir);
	}

	private function feed(string $content): string
	{
		$path = $this->dir . '/feed.norm';
		file_put_contents($path, $content);
		return $path;
	}

	/** @return array<string, array{string, bool}> */
	public static function feedProvider(): array
	{
		$hosts = "0.0.0.0 ads.example.com\n0.0.0.0 tracker.example.org\n";
		return [
			'Adblock header'                => ["[Adblock Plus 2.0]\nexample.com\n", TRUE],
			'anchor rule, no header'        => ["! Title: x\nexample.com\n||ads.example.com^\n", TRUE],
			'exception rule'                => ["example.com\n@@||cdn.example.com^\n", TRUE],
			'regex rule'                    => ["example.com\n/^ad[0-9]+\\.example\\.com$/\n", TRUE],
			'generic cosmetic class only'   => ["example.com\n##.ad-banner\n", FALSE],
			'generic cosmetic id only'      => ["example.com\n###ad\n", FALSE],
			'BOM-led anchor rule'           => ["\xEF\xBB\xBF||ads.example.com^\n", TRUE],
			'site cosmetic'                 => ["example.com\nsite.com##.ad\n", TRUE],
			'AdGuard extended CSS'          => ["eksisozluk.com#\$?#.ads\n", TRUE],
			'AdGuard extended exception'    => ["site.com#@\$?#.ads\n", TRUE],
			'AdGuard scriptlet exception'   => ["site.com#@%#//scriptlet('abort')\n", TRUE],
			'AdGuard CSS exception'         => ["site.com#@\$#body { color: red }\n", TRUE],
			'AdGuard HTML filter'           => ["site.com\$\$script[data-src=\"ad\"]\n", TRUE],
			'AdGuard HTML exception'        => ["site.com\$@\$script[data-src=\"ad\"]\n", TRUE],
			'plain hosts'                   => [$hosts, FALSE],
			'StevenBlack banner'            => ["##################################################\n##### Version Information #\n{$hosts}", FALSE],
			'title comments'                => ["### WindowsSpyBlocker - Hosts spy rules\n### License: MIT\n{$hosts}", FALSE],
			'section comment'               => ["## Section\n{$hosts}", FALSE],
			'dash banner'                   => ["###-------------------\n{$hosts}", FALSE],
			'star banner'                   => ["##**********************\n{$hosts}", FALSE],
			'underscore banner'             => ["###_____\n{$hosts}", FALSE],
			'title banner'                  => ["##Title: My hosts\n{$hosts}", FALSE],
			'percent banner'                => ["#%#%#%#%#%\n{$hosts}", FALSE],
			'bracket banner'                => ["##[ list ]\n{$hosts}", FALSE],
			'colon banner'                  => ["##:comment\n{$hosts}", FALSE],
			'IP feed with banners'          => ["##################################################\n# Feodo Tracker\n1.2.3.4\n5.6.7.8\n", FALSE],
			'domain list'                   => ["example.com\nads.example.org\n", FALSE],
			'URL feed'                      => ["example.com/ads/banner.gif\nhttp://bad.example.org/x\n", FALSE],
			'empty'                         => ['', FALSE],
		];
	}

	#[DataProvider('feedProvider')]
	public function testAFeedIsAdblockByItsHeaderOrByAnAdblockRule(string $content, bool $adblock): void
	{
		$this->assertSame($adblock, pfb_dnsbl_feed_is_abp($this->feed($content)));
	}

	public function testAMissingFeedFileIsNotAdblock(): void
	{
		$this->assertFalse(pfb_dnsbl_feed_is_abp($this->dir . '/absent.norm'));
	}
}
