<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;

/**
 * Reputation (and sibling List-Action) help in pfblockerng_geoip.inc used a bare
 * `<ul>` as a plain indentation wrapper — no `<li>` child — which is malformed
 * list markup and gives the long filesystem paths / feed URL inside no wrapping
 * affordance, so their tails paint past a narrow viewport (issue #2897: the
 * pfB_Match_Exempt_v4.txt path was permanently unreachable at 414px because the
 * Collective List Reputation panel-body is not a scroll container).
 *
 * Every remaining <ul> must carry <li> content, not serve as a text wrapper.
 * Real narrow-screen wrapping of the file/URL examples is covered by
 * tests/smoke/ui/test_help_general_ip.py.
 */
final class GeoipReputationHelpMarkupTest extends TestCase
{
	private static function source(): string
	{
		$source = file_get_contents(dirname(__DIR__, 2) . '/src/usr/local/pkg/pfblockerng/pfblockerng_geoip.inc');
		if ($source === FALSE) {
			throw new RuntimeException('failed to read pfblockerng_geoip.inc');
		}
		return $source;
	}

	/** @return array<int, array{string, string}> [open tag (incl. attributes), body] per <ul>...</ul> span */
	private static function ulSpans(string $source): array
	{
		self::assertGreaterThan(
			0,
			preg_match_all('/<ul\b([^>]*)>(.*?)<\/ul>/s', $source, $m, PREG_SET_ORDER),
			'pfblockerng_geoip.inc must still contain <ul> lists to validate'
		);
		$spans = [];
		foreach ($m as $ul) {
			$spans[] = [$ul[1], $ul[2]];
		}
		return $spans;
	}

	public function testNoListIsABareTextIndentWrapper(): void
	{
		foreach (self::ulSpans(self::source()) as [$openTag, $body]) {
			if (trim(strip_tags($body)) === '') {
				continue; // an empty <ul></ul> is valid markup, not a text wrapper
			}
			$this->assertStringContainsString(
				'<li',
				$body,
				"a <ul> with visible text and no <li> is malformed list markup"
					. ' (open tag: <ul' . $openTag . '>; body starts: '
					. substr($body, 0, 60) . '...)'
			);
		}
	}
}
