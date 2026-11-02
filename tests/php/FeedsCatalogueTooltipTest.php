<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;

/**
 * Catalogue-level tooltip invariants for www/pfblockerng/pfblockerng_feeds.json (#2918).
 *
 * Every 'info' and 'description' string reaches the page as a native title attribute
 * or as group copy, so each must be plain text: no markup, no double quote (it would
 * end the title attribute early), and no tracker issue reference. Discontinued feeds
 * are removed from the picker (pfblockerng.inc), so their wording is never rendered;
 * this test is the only place that checks it.
 */
final class FeedsCatalogueTooltipTest extends TestCase
{
	public function testTooltipAndDescriptionStringsArePlainTextWithoutIssueReferences(): void
	{
		$path = dirname(__DIR__, 2) . '/src/usr/local/www/pfblockerng/pfblockerng_feeds.json';
		$this->assertFileExists($path, 'feeds catalogue must exist');

		$feeds = json_decode((string) file_get_contents($path), TRUE);
		$this->assertIsArray($feeds, 'feeds catalogue must be valid JSON: ' . json_last_error_msg());

		$offenders = [];
		array_walk_recursive($feeds, static function (mixed $value, string|int $key) use (&$offenders): void {
			if (($key !== 'info' && $key !== 'description') || !is_string($value)) {
				return;
			}
			if (preg_match('/[<>"]|#\d/', $value) === 1) {
				$offenders[] = $value;
			}
		});

		$this->assertSame([], $offenders, 'tooltip and description strings must be plain text with no issue reference');
	}
}
