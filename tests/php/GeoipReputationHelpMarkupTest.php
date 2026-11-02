<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;

/**
 * Reputation (and sibling List-Action) help in pfblockerng_geoip.inc once used a bare
 * `<ul>` as a plain indentation wrapper — no `<li>` child — which is malformed list
 * markup, and gave its long path/URL examples no wrapping affordance (issue #2897: the
 * exempt-list path overflowed a 414px viewport). Every `<ul>` carries `<li>` content,
 * and each long unbreakable example sits in a literal that may wrap anywhere.
 */
final class GeoipReputationHelpMarkupTest extends TestCase
{
	/** The examples that are one long unbreakable token. */
	private const LONG_TOKENS = [
		'/var/db/pfblockerng/match/generated/pfB_Match_Exempt_v4.txt',
		'https://rules.emergingthreatspro.com/XXXXXXXXXXXXXXXX/reputation/iprepdata.txt.gz',
		'/var/db/pfblockerng/match/generated/pfB_Match_ET_v4.txt',
		'/var/db/pfblockerng/ET',
	];

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

	public function testLongTokenExamplesDeclareWrapAffordance(): void
	{
		$source = self::source();
		foreach (self::LONG_TOKENS as $token) {
			$this->assertMatchesRegularExpression(
				'/<code style="overflow-wrap:\s*anywhere">' . preg_quote($token, '/') . '<\/code>/',
				$source,
				"the long example [ {$token} ] must be a literal that wraps inside a narrow viewport"
			);
		}
	}
}
