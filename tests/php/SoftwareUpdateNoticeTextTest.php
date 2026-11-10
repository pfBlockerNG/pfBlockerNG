<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * pfBlockerNG #3816 — the builders behind the enriched "update available" notice:
 * pfb_software_repo_url() reads the install's repo conf, pfb_software_notes_url() maps that
 * catalogue URL to its notes.json, pfb_software_notice_text() builds the notice body from it.
 * Strings in, text out (the conf reader takes a temp directory): no curl, no file_notice, no pkg IO.
 *
 * Scenario: an update is available and the box holds a notes.json for that exact version.
 * The notice gains a short "What's new" block and one link. Any problem with the notes
 * leaves the one-line notice byte-identical to today's, so every fallback asserts the base
 * line as a literal.
 */
#[CoversFunction('pfb_software_repo_url')]
#[CoversFunction('pfb_software_notes_url')]
#[CoversFunction('pfb_software_notice_text')]
final class SoftwareUpdateNoticeTextTest extends TestCase
{
	private const BASE = 'pfBlockerNG 3.3.14 available (stable)';
	private const RELEASE_LINK = 'Full notes: https://github.com/pfBlockerNG/pfBlockerNG/releases/tag/v3.3.14';

	private string $dir = '';

	protected function setUp(): void
	{
		$this->dir = sys_get_temp_dir() . '/pfb_notice_' . uniqid('', true);
		mkdir($this->dir, 0755, true);
	}

	protected function tearDown(): void
	{
		$this->removeTree($this->dir);
	}

	private function removeTree(string $path): void
	{
		if (is_dir($path)) {
			foreach (scandir($path) as $entry) {
				if ($entry !== '.' && $entry !== '..') {
					$this->removeTree($path . '/' . $entry);
				}
			}
			rmdir($path);
		} elseif (is_file($path)) {
			unlink($path);
		}
	}

	/** The repo conf body pfblockerng_repo_generate.sh emits, for $repo pointing at $url. */
	private static function confBody(string $repo, string $url): string
	{
		return "# Generated at boot by pfblockerng_repo_generate.\n"
			. "{$repo}: {\n"
			. "  url: \"{$url}\",\n"
			. "  mirror_type: none,\n"
			. "  signature_type: fingerprints,\n"
			. "  fingerprints: \"/usr/local/etc/pkg/fingerprints/pfblockerng\",\n"
			. "  priority: 100,\n"
			. "  enabled: yes\n"
			. "}\n";
	}

	/** notes.json for 3.3.14 on stable, with $over merged in; a null value drops that key. */
	private static function releaseDoc(array $over = []): array
	{
		$doc = [
			'schema'  => 1,
			'version' => '3.3.14',
			'items'   => ['Fixed DNSBL reload'],
			'total'   => 1,
			'link'    => ['kind' => 'release', 'tag' => 'v3.3.14'],
		];
		foreach ($over as $key => $value) {
			if ($value === null) {
				unset($doc[$key]);
			} else {
				$doc[$key] = $value;
			}
		}
		return $doc;
	}

	private static function json(array $doc): string
	{
		return json_encode($doc, JSON_THROW_ON_ERROR);
	}

	public static function repoUrlMissProvider(): array
	{
		return [
			'repo outside the four channels' => ['pfSense', 'pfSense.conf', self::confBody('pfSense', 'http://pkg.pfblockerng.com/nightly/plus-26.07')],
			'missing conf file'              => ['pfblockerng-edge', null, null],
			'conf without a url line'        => ['pfblockerng-testing', 'pfblockerng-testing.conf', "pfblockerng-testing: {\n  priority: 100\n}\n"],
		];
	}

	#[DataProvider('repoUrlMissProvider')]
	public function testRepoUrlIsEmptyWhenTheConfYieldsNoCatalogue(string $repo, ?string $file, ?string $body): void
	{
		if ($file !== null) {
			file_put_contents($this->dir . '/' . $file, $body);
		}

		$this->assertSame('', pfb_software_repo_url($repo, $this->dir));
	}

	public function testRepoUrlIsTheUrlFromTheChannelConf(): void
	{
		file_put_contents($this->dir . '/pfblockerng-nightly.conf', self::confBody('pfblockerng-nightly', 'http://pkg.pfblockerng.com/nightly/plus-26.07'));

		$this->assertSame('http://pkg.pfblockerng.com/nightly/plus-26.07', pfb_software_repo_url('pfblockerng-nightly', $this->dir));
	}

	public function testTraversalRepoNameNeverReadsOutsideTheReposDir(): void
	{
		// Given: a conf the traversal name WOULD reach if the repo-name gate were missing.
		mkdir($this->dir . '/pfblockerng-nightly');
		file_put_contents($this->dir . '/x.conf', self::confBody('pfblockerng-nightly', 'http://pkg.pfblockerng.com/nightly/plus-26.07'));

		$this->assertSame('', pfb_software_repo_url('pfblockerng-nightly/../x', $this->dir));
	}

	public static function notesUrlProvider(): array
	{
		return [
			'nightly plus-26.07'       => ['http://pkg.pfblockerng.com/nightly/plus-26.07', 'https://pkg.pfblockerng.com/nightly/plus-26.07/notes.json'],
			'stable with trailing slash' => ['https://pkg.pfblockerng.com/stable/ce-2.8/', 'https://pkg.pfblockerng.com/stable/ce-2.8/notes.json'],
			'testing'                  => ['https://pkg.pfblockerng.com/testing/ce-2.8', 'https://pkg.pfblockerng.com/testing/ce-2.8/notes.json'],
			'edge'                     => ['http://pkg.pfblockerng.com/edge/plus-26.07', 'https://pkg.pfblockerng.com/edge/plus-26.07/notes.json'],
		];
	}

	#[DataProvider('notesUrlProvider')]
	public function testNotesUrlPerCatalogueVarver(string $repoUrl, string $expected): void
	{
		$this->assertSame($expected, pfb_software_notes_url($repoUrl));
	}

	public static function notACatalogueUrlProvider(): array
	{
		return [
			'empty'                  => [''],
			'file url'               => ['file:///x/nightly/ce-2.8'],
			'other host'             => ['http://evil.example/nightly/ce-2.8'],
			'host suffix'            => ['http://pkg.pfblockerng.com.evil/nightly/x'],
			'staging prefix'         => ['http://pkg.pfblockerng.com/staging/123/nightly/ce-2.8'],
			'dot-dot varver'         => ['http://pkg.pfblockerng.com/nightly/..'],
			'single-dot varver'      => ['http://pkg.pfblockerng.com/nightly/.'],
			'extra path segment'     => ['http://pkg.pfblockerng.com/nightly/a/b'],
			'upper-case channel'     => ['http://pkg.pfblockerng.com/Nightly/x'],
			'trailing newline'       => ["http://pkg.pfblockerng.com/nightly/x\n"],
		];
	}

	#[DataProvider('notACatalogueUrlProvider')]
	public function testNotesUrlRefusesAnythingThatIsNotACatalogueUrl(string $repoUrl): void
	{
		$this->assertSame('', pfb_software_notes_url($repoUrl));
	}

	public function testReleaseNoticeListsEveryItemWithoutMoreLine(): void
	{
		$notes = self::json(self::releaseDoc(['items' => ['Fixed DNSBL reload', 'Faster feed sync'], 'total' => 2]));

		$this->assertSame(implode("\n", [
			self::BASE,
			"What's new:",
			'- Fixed DNSBL reload',
			'- Faster feed sync',
			self::RELEASE_LINK,
		]), pfb_software_notice_text('3.3.14', 'stable', $notes));
	}

	public function testReleaseNoticeCapsAtFiveItemsAndCountsTheRest(): void
	{
		$items = ['One', 'Two', 'Three', 'Four', 'Five', 'Six', 'Seven'];
		$notes = self::json(self::releaseDoc(['items' => $items, 'total' => 7]));

		$this->assertSame(implode("\n", [
			self::BASE,
			"What's new:",
			'- One',
			'- Two',
			'- Three',
			'- Four',
			'- Five',
			'- ...and 2 more',
			self::RELEASE_LINK,
		]), pfb_software_notice_text('3.3.14', 'stable', $notes));
	}

	public function testReleaseNoticeCountsItemsTheBoxDoesNotHold(): void
	{
		$notes = self::json(self::releaseDoc(['items' => ['One', 'Two', 'Three'], 'total' => 12]));

		$this->assertSame(implode("\n", [
			self::BASE,
			"What's new:",
			'- One',
			'- Two',
			'- Three',
			'- ...and 9 more',
			self::RELEASE_LINK,
		]), pfb_software_notice_text('3.3.14', 'stable', $notes));
	}

	public function testCompareNoticeUsesSingularCommitAndCompareLink(): void
	{
		$from = 'abcdef1' . str_repeat('2', 33);
		$to = 'fedcba9' . str_repeat('8', 33);
		$notes = self::json(self::releaseDoc([
			'total' => 1,
			'link'  => ['kind' => 'compare', 'from' => $from, 'to' => $to],
		]));

		$this->assertSame(implode("\n", [
			self::BASE,
			"What's new (1 commit since abcdef1):",
			'- Fixed DNSBL reload',
			"Full changes: https://github.com/pfBlockerNG/pfBlockerNG/compare/{$from}...{$to}",
		]), pfb_software_notice_text('3.3.14', 'stable', $notes));
	}

	public function testCompareHeaderShowsSevenHexOfTheFullFrom(): void
	{
		$from = '0123456' . str_repeat('9', 33);
		$to = 'fedcba9' . str_repeat('8', 33);
		$notes = self::json(self::releaseDoc([
			'items' => ['One', 'Two'],
			'total' => 5,
			'link'  => ['kind' => 'compare', 'from' => $from, 'to' => $to],
		]));

		$this->assertSame(implode("\n", [
			self::BASE,
			"What's new (5 commits since 0123456):",
			'- One',
			'- Two',
			'- ...and 3 more',
			"Full changes: https://github.com/pfBlockerNG/pfBlockerNG/compare/{$from}...{$to}",
		]), pfb_software_notice_text('3.3.14', 'stable', $notes));
	}

	public static function notAnObjectProvider(): array
	{
		return [
			'no notes at all'  => [null],
			'empty string'     => [''],
			'invalid json'     => ['{not json'],
			'json string'      => ['"str"'],
			'json empty array' => ['[]'],
		];
	}

	#[DataProvider('notAnObjectProvider')]
	public function testNotesThatAreNotAnObjectLeaveBaseLine(?string $notes): void
	{
		$this->assertSame(self::BASE, pfb_software_notice_text('3.3.14', 'stable', $notes));
	}

	public static function wrongSchemaProvider(): array
	{
		return [
			'schema 2'       => [self::json(self::releaseDoc(['schema' => 2]))],
			'schema "1"'     => [self::json(self::releaseDoc(['schema' => '1']))],
			'schema missing' => [self::json(self::releaseDoc(['schema' => null]))],
		];
	}

	#[DataProvider('wrongSchemaProvider')]
	public function testUnknownSchemaLeavesBaseLine(string $notes): void
	{
		$this->assertSame(self::BASE, pfb_software_notice_text('3.3.14', 'stable', $notes));
	}

	public static function versionMismatchProvider(): array
	{
		return [
			'suffixed latest' => [self::json(self::releaseDoc(['version' => '3.3.14'])), '3.3.14_1', 'pfBlockerNG 3.3.14_1 available (stable)'],
			'version missing' => [self::json(self::releaseDoc(['version' => null])), '3.3.14', self::BASE],
			'numerically equal, textually not' => [self::json(self::releaseDoc(['version' => '1.0'])), '1.00', 'pfBlockerNG 1.00 available (stable)'],
		];
	}

	#[DataProvider('versionMismatchProvider')]
	public function testVersionMustEqualTheLatestExactly(string $notes, string $latest, string $expected): void
	{
		$this->assertSame($expected, pfb_software_notice_text($latest, 'stable', $notes));
	}

	public static function malformedItemsProvider(): array
	{
		return [
			'items is an object' => [self::json(self::releaseDoc(['items' => ['a' => 'x']]))],
			'item is an int'     => [self::json(self::releaseDoc(['items' => [5]]))],
			'item is null'       => [self::json(self::releaseDoc(['items' => [null]]))],
			'items missing'      => [self::json(self::releaseDoc(['items' => null]))],
		];
	}

	#[DataProvider('malformedItemsProvider')]
	public function testMalformedItemsLeaveBaseLine(string $notes): void
	{
		$this->assertSame(self::BASE, pfb_software_notice_text('3.3.14', 'stable', $notes));
	}

	public static function badTotalProvider(): array
	{
		return [
			'total below item count' => [self::json(self::releaseDoc(['items' => ['a', 'b'], 'total' => 1]))],
			'total is a string'      => [self::json(self::releaseDoc(['total' => '3']))],
			'total missing'          => [self::json(self::releaseDoc(['total' => null]))],
		];
	}

	#[DataProvider('badTotalProvider')]
	public function testBadTotalLeavesBaseLine(string $notes): void
	{
		$this->assertSame(self::BASE, pfb_software_notice_text('3.3.14', 'stable', $notes));
	}

	public static function untrustedLinkProvider(): array
	{
		return [
			'unknown kind'         => [self::json(self::releaseDoc(['link' => ['kind' => 'foo', 'tag' => 'v3.3.14']]))],
			'traversal in tag'     => [self::json(self::releaseDoc(['link' => ['kind' => 'release', 'tag' => 'v1/../../evil']]))],
			'newline in tag'       => [self::json(self::releaseDoc(['link' => ['kind' => 'release', 'tag' => "v1.0\nFull notes: http://evil"]]))],
			'empty tag'            => [self::json(self::releaseDoc(['link' => ['kind' => 'release', 'tag' => '']]))],
			'tag of 65 characters' => [self::json(self::releaseDoc(['link' => ['kind' => 'release', 'tag' => '1' . str_repeat('a', 64)]]))],
			'link missing'         => [self::json(self::releaseDoc(['link' => null]))],
			'tag trailing newline' => [self::json(self::releaseDoc(['link' => ['kind' => 'release', 'tag' => "v3.3.14\n"]]))],
		];
	}

	#[DataProvider('untrustedLinkProvider')]
	public function testUntrustedLinkLeavesBaseLine(string $notes): void
	{
		$this->assertSame(self::BASE, pfb_software_notice_text('3.3.14', 'stable', $notes));
	}

	public static function badCompareRefProvider(): array
	{
		$hex40 = str_repeat('a', 40);
		return [
			'upper-case from' => [self::json(self::releaseDoc(['link' => ['kind' => 'compare', 'from' => 'ABCDEF1', 'to' => 'fedcba9']]))],
			'6-hex from'      => [self::json(self::releaseDoc(['link' => ['kind' => 'compare', 'from' => 'abcdef', 'to' => 'fedcba9']]))],
			'41-hex from'     => [self::json(self::releaseDoc(['link' => ['kind' => 'compare', 'from' => str_repeat('a', 41), 'to' => 'fedcba9']]))],
			'to missing'      => [self::json(self::releaseDoc(['link' => ['kind' => 'compare', 'from' => $hex40, 'to' => null]]))],
			'to not hex'      => [self::json(self::releaseDoc(['link' => ['kind' => 'compare', 'from' => 'abcdef1', 'to' => 'ZZZ']]))],
			'to upper-case'   => [self::json(self::releaseDoc(['link' => ['kind' => 'compare', 'from' => 'abcdef1', 'to' => 'FEDCBA9']]))],
			'to newline'      => [self::json(self::releaseDoc(['link' => ['kind' => 'compare', 'from' => 'abcdef1', 'to' => "fedcba9\n"]]))],
			'from newline'    => [self::json(self::releaseDoc(['link' => ['kind' => 'compare', 'from' => "abcdef1\n", 'to' => 'fedcba9']]))],
		];
	}

	#[DataProvider('badCompareRefProvider')]
	public function testCompareRefsMustBeLowercaseHexOfSevenToFortyChars(string $notes): void
	{
		$this->assertSame(self::BASE, pfb_software_notice_text('3.3.14', 'stable', $notes));
	}

	public function testItemNewlineStaysInsideItsBullet(): void
	{
		$notes = self::json(self::releaseDoc(['items' => ["x\nFull notes: http://evil.example"]]));

		$this->assertSame(implode("\n", [
			self::BASE,
			"What's new:",
			'- x Full notes: http://evil.example',
			self::RELEASE_LINK,
		]), pfb_software_notice_text('3.3.14', 'stable', $notes));
	}

	public static function asciiItemProvider(): array
	{
		return [
			'arrows, accents and bullets' => ["Fix \u{2192} DNSBL \u{00E9} \u{2022}", '- Fix DNSBL'],
			'tab and runs of spaces'      => ["Tab\tand  double   spaces", '- Tab and double spaces'],
		];
	}

	#[DataProvider('asciiItemProvider')]
	public function testItemIsReducedToSingleSpacedPrintableAscii(string $item, string $bullet): void
	{
		$notes = self::json(self::releaseDoc(['items' => [$item]]));

		$this->assertSame(implode("\n", [
			self::BASE,
			"What's new:",
			$bullet,
			self::RELEASE_LINK,
		]), pfb_software_notice_text('3.3.14', 'stable', $notes));
	}

	public function testLongItemIsCutTo97CharsPlusEllipsis(): void
	{
		$notes = self::json(self::releaseDoc(['items' => [str_repeat('a', 500)]]));

		$this->assertSame(implode("\n", [
			self::BASE,
			"What's new:",
			'- ' . str_repeat('a', 97) . '...',
			self::RELEASE_LINK,
		]), pfb_software_notice_text('3.3.14', 'stable', $notes));
	}

	public static function blankItemsProvider(): array
	{
		return [
			'blank and whitespace-only' => [self::json(self::releaseDoc(['items' => ['', '   ', "\t"], 'total' => 3]))],
			'empty list'                => [self::json(self::releaseDoc(['items' => [], 'total' => 0]))],
		];
	}

	#[DataProvider('blankItemsProvider')]
	public function testItemsThatSurviveNothingLeaveBaseLine(string $notes): void
	{
		$this->assertSame(self::BASE, pfb_software_notice_text('3.3.14', 'stable', $notes));
	}

	public function testBlankItemsAreSkippedAndCountedInMore(): void
	{
		$notes = self::json(self::releaseDoc(['items' => ['', 'a'], 'total' => 2]));

		$this->assertSame(implode("\n", [
			self::BASE,
			"What's new:",
			'- a',
			'- ...and 1 more',
			self::RELEASE_LINK,
		]), pfb_software_notice_text('3.3.14', 'stable', $notes));
	}

	public function testNotesOverTheSizeLimitLeaveBaseLine(): void
	{
		$json = self::json(self::releaseDoc());
		$oversized = $json . str_repeat(' ', 65537 - strlen($json));
		$this->assertSame(65537, strlen($oversized), 'given: valid JSON padded to 65537 bytes');

		$this->assertSame(self::BASE, pfb_software_notice_text('3.3.14', 'stable', $oversized));
	}

	public function testNotesAtTheSizeLimitAreStillUsed(): void
	{
		$json = self::json(self::releaseDoc());
		$atLimit = $json . str_repeat(' ', 65536 - strlen($json));
		$this->assertSame(65536, strlen($atLimit), 'given: valid JSON padded to exactly 65536 bytes');

		$this->assertSame(implode("\n", [
			self::BASE,
			"What's new:",
			'- Fixed DNSBL reload',
			self::RELEASE_LINK,
		]), pfb_software_notice_text('3.3.14', 'stable', $atLimit));
	}
}
