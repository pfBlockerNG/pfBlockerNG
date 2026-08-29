<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;

/**
 * Guards the shipped feeds catalogue (www/pfblockerng/pfblockerng_feeds.json):
 *   - the file is valid JSON (a syntax slip would break the feeds UI page), and
 *   - the Alienvault feed carries status 'discontinued' (#319) so the
 *     discontinued-feed filter in pfblockerng.inc drops it from the picker.
 *
 * The source has been dead/stale since 2021; per the maintainer the feed is
 * flagged rather than deleted (same treatment as the other discontinued feeds).
 */
final class FeedsDiscontinuedTest extends TestCase
{
	/** @return array<string, mixed> */
	private function loadFeeds(): array
	{
		$path = dirname(__DIR__, 2) . '/src/usr/local/www/pfblockerng/pfblockerng_feeds.json';
		$this->assertFileExists($path, 'feeds catalogue must exist');

		$decoded = json_decode((string) file_get_contents($path), TRUE);
		$this->assertIsArray($decoded, 'feeds catalogue must be valid JSON: ' . json_last_error_msg());

		return $decoded;
	}

	// The catalogue parses as JSON — a syntax error would blank the feeds page.
	public function testFeedsCatalogueIsValidJson(): void
	{
		$this->assertNotEmpty($this->loadFeeds());
	}

	// The Alienvault feed is flagged discontinued so the pfblockerng.inc filter drops it.
	public function testAlienvaultFeedIsDiscontinued(): void
	{
		$feeds = $this->loadFeeds();

		$alienvault = NULL;
		foreach ($feeds['ipv4']['PRI2']['feeds'] as $feed) {
			if (($feed['feed'] ?? '') === 'Alienvault') {
				$alienvault = $feed;
				break;
			}
		}

		$this->assertNotNull($alienvault, 'Alienvault feed must still be present in ipv4/PRI2 (flagged, not deleted)');
		$this->assertSame('discontinued', $alienvault['status'] ?? NULL, 'Alienvault feed must be marked discontinued (#319)');
	}

	public function testCctIpFeedIsDiscontinuedWithReason(): void
	{
		$feeds = $this->loadFeeds();
		$cctHeaders = [];
		array_walk_recursive($feeds, static function (mixed $value, string|int $key) use (&$cctHeaders): void {
			if ($key === 'header' && $value === 'CCT_IP') {
				$cctHeaders[] = $value;
			}
		});
		$this->assertCount(1, $cctHeaders, 'CCT_IP must have exactly one catalogue identity');

		$cct = NULL;
		foreach ($feeds['ipv4']['PRI4']['feeds'] as $feed) {
			if (($feed['header'] ?? '') === 'CCT_IP') {
				$cct = $feed;
				break;
			}
		}

		$this->assertNotNull($cct, 'CCT_IP must remain in the catalogue as a discontinued feed');
		$this->assertSame('discontinued', $cct['status'] ?? NULL);
		$this->assertSame('https://cybercrime-tracker.net/csv.php', $cct['url'] ?? NULL);
		$this->assertStringContainsString('requires cookies', $cct['info'] ?? '');
		$this->assertStringContainsString('TYPE,URL,IP CSV', $cct['info'] ?? '');
		$this->assertStringContainsString('#1679', $cct['info'] ?? '');
	}
}
