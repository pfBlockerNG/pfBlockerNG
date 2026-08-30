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
 * Contract pinned here:
 *   1. every `<ul>` in the file carries `<li>` content (no bare-text indent hack);
 *   2. the five fragments the issue names keep their wording byte-for-byte;
 *   3. the fragments carrying a long unbreakable token sit in a list that
 *      declares a wrap affordance (overflow-wrap: anywhere), so the token can
 *      break inside a narrow viewport instead of overflowing it.
 */
final class GeoipReputationHelpMarkupTest extends TestCase
{
	private const WORDING = [
		'Analyzing all Blocklists as a whole:',
		'/var/db/pfblockerng/match/generated/pfB_Match_Exempt_v4.txt',
		'https://rules.emergingthreatspro.com/XXXXXXXXXXXXXXXX/reputation/iprepdata.txt.gz',
		'/var/db/pfblockerng/match/generated/pfB_Match_ET_v4.txt',
		'/var/db/pfblockerng/ET',
	];

	/** The fragments whose wording is one long unbreakable token. */
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

	public function testIssueWordingIsByteEquivalent(): void
	{
		$source = self::source();
		foreach (self::WORDING as $wording) {
			$this->assertStringContainsString(
				$wording,
				$source,
				'the #2897 fix is markup/wrapping only; the help wording must survive byte-for-byte'
			);
		}
	}

	public function testLongTokenFragmentsDeclareWrapAffordance(): void
	{
		$spans = self::ulSpans(self::source());
		foreach (self::LONG_TOKENS as $token) {
			$found = FALSE;
			foreach ($spans as [$openTag, $body]) {
				if (str_contains($body, $token)) {
					$found = TRUE;
					$this->assertMatchesRegularExpression(
						'/overflow-wrap\s*:\s*anywhere|word-break\s*:\s*break-all/',
						$openTag,
						"the list holding the long token [ {$token} ] must declare a wrap affordance"
							. ' so the token breaks inside a narrow viewport instead of overflowing it'
					);
				}
			}
			$this->assertTrue($found, "long token [ {$token} ] must still sit inside a <ul> list");
		}
	}
}
