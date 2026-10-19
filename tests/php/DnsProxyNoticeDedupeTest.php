<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * issue #3515 -- pfb_dns_proxy_notify() files one notice per condition. A condition that still stands is not filed again by
 * the next apply or cron tick; a change of condition is filed, so a condition that returns after another is filed again.
 * pfSense stores the id and the text htmlentities()-encoded, so the comparison is made on the encoded form, and ids are
 * compared the same way: two distinct ids never share a notice.
 */
#[CoversFunction('pfb_dns_proxy_notify')]
final class DnsProxyNoticeDedupeTest extends TestCase
{
	private const ID = 'pfBlockerNG DNS Proxy';
	private const URL = '/services_unbound.php';

	private array $savedPfb = [];

	protected function setUp(): void
	{
		$this->savedPfb = $GLOBALS['pfb'] ?? [];
		$tmp = sys_get_temp_dir() . '/pfb_notice_dedupe_' . uniqid('', TRUE);
		mkdir($tmp, 0777, TRUE);
		$GLOBALS['pfb'] = ['logdir' => $tmp, 'log' => "{$tmp}/pfb.log", 'errlog' => "{$tmp}/pfb.err"];
		$GLOBALS['pfb_test_file_notices'] = [];
	}

	protected function tearDown(): void
	{
		$GLOBALS['pfb'] = $this->savedPfb;
		$GLOBALS['pfb_test_file_notices'] = [];
	}

	/** @return list<array{0:string,1:string}> the (id, text) of each notice filed, in the order pfSense filed them */
	private static function filed(): array
	{
		return array_map(static fn (array $notice): array => [$notice['id'], $notice['notice']], $GLOBALS['pfb_test_file_notices'] ?? []);
	}

	/** @return array<string,array{string}> text pfSense stores encoded: quotes, markup, ampersands, entity-looking text, non-ASCII */
	public static function hostileTexts(): array
	{
		return [
			'quotes and apostrophes' => ['Resolver "moved" and \'kept\''],
			'markup'                 => ['<b>Stop</b> <script>alert(1)</script>'],
			'ampersands'             => ['Resolver A & B &amp; C'],
			'entity-looking text'    => ['&quot;moved&quot; &lt;kept&gt;'],
			'non-ASCII'              => ['Résumé — “moved”'],
		];
	}

	#[DataProvider('hostileTexts')]
	public function testAStandingNoticeWithHostileTextIsNotFiledAgainAgainstItsEncodedRow(string $text): void
	{
		// Given the condition was raised once
		pfb_dns_proxy_notify(self::ID, $text, self::URL);
		$this->assertCount(1, $GLOBALS['pfb_test_file_notices'], 'before: one notice is filed');
		$stored = get_notices();
		$this->assertSame(htmlentities($text), $stored[0]['notice'] ?? NULL, 'before: pfSense stores the text encoded');

		// When the next apply meets the same condition
		pfb_dns_proxy_notify(self::ID, $text, self::URL);

		// Then it is not filed again: the stored, encoded row is what the new text is compared with
		$this->assertCount(1, $GLOBALS['pfb_test_file_notices'], 'the same condition is not a second notice');
	}

	/** @return array<string,array{list<string>,list<string>}> condition sequences, and the notices they file */
	public static function conditionSequences(): array
	{
		return [
			'the same condition twice'                  => [['A', 'A'], ['A']],
			'a change, then the same change again'      => [['A', 'B', 'B'], ['A', 'B']],
			'A, B, then A again: A is filed again'      => [['A', 'B', 'A'], ['A', 'B', 'A']],
			'A, B, A, then A again: no third A'         => [['A', 'B', 'A', 'A'], ['A', 'B', 'A']],
		];
	}

	/** @param list<string> $conditions @param list<string> $expected */
	#[DataProvider('conditionSequences')]
	public function testEachChangeOfConditionIsFiledAndAReturningConditionIsFiledAgain(array $conditions, array $expected): void
	{
		foreach ($conditions as $condition) {
			pfb_dns_proxy_notify(self::ID, $condition, self::URL);
		}

		$this->assertSame($expected, array_column($GLOBALS['pfb_test_file_notices'], 'notice'), 'one notice per change of condition, in order');
	}

	/** @return array<string,array{string,string}> two distinct ids, including ids that differ only in their encoding */
	public static function distinctIds(): array
	{
		return [
			'two plain ids'                 => ['pfBlockerNG DNS Proxy', 'pfBlockerNG DNS Other'],
			'ids differing in an ampersand' => ['A & B', 'A &amp; B'],
			'ids differing in quotes'       => ['it\'s "one"', 'it&#039;s &quot;one&quot;'],
		];
	}

	#[DataProvider('distinctIds')]
	public function testDifferentIdsNeverShareANoticeEvenForTheSameText(string $first, string $second): void
	{
		pfb_dns_proxy_notify($first, 'Same text', self::URL);
		pfb_dns_proxy_notify($second, 'Same text', self::URL);
		pfb_dns_proxy_notify($first, 'Same text', self::URL);

		$this->assertSame([[$first, 'Same text'], [$second, 'Same text']], self::filed(),
			'two notices, one per id; the first id is not filed again while its notice stands');
	}

	/** @return array<string,array{string}> ids with quotes, markup and ampersands: each still matches its own row */
	public static function hostileIds(): array
	{
		return [
			'an ampersand'     => ['A & B'],
			'an encoded id'    => ['A &amp; B'],
			'quotes and markup' => ['it\'s "one" <i>'],
		];
	}

	#[DataProvider('hostileIds')]
	public function testAHostileIdStillMatchesItsOwnStandingNotice(string $id): void
	{
		pfb_dns_proxy_notify($id, 'Same text', self::URL);
		pfb_dns_proxy_notify($id, 'Same text', self::URL);

		$this->assertSame([[$id, 'Same text']], self::filed(), 'the same id and text is one notice');
	}
}
