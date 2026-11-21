<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * The GeoIP pages rendered from the geo-catalog (#4037): the rows Core publishes (docs/specs/go-updater-pipeline.md §7,
 * JSON Lines in byte order) give the continent pages and the Reputation page pfblockerng_get_countries() writes from the
 * continent files, byte for byte. A name is data in the generated page whatever it holds; a catalog the renderer cannot
 * trust is refused whole and leaves the pages on disk as they were; a page Core names that is not one of the nine
 * continent pages is skipped and reported. Every page is staged beside its target before any target is replaced.
 */
#[CoversFunction('pfb_geoip_render_catalog')]
#[CoversFunction('pfb_build_reputation_tab')]
final class GeoipCatalogRenderTest extends TestCase
{
	/** What the renderer returns when every page was written and none was skipped. */
	private const WRITTEN = ['error' => NULL, 'skipped' => []];

	private string $tmp = '';
	private mixed $originalPfb = NULL;
	private bool $hadPfb = FALSE;

	protected function setUp(): void
	{
		$this->hadPfb = array_key_exists('pfb', $GLOBALS);
		$this->originalPfb = $GLOBALS['pfb'] ?? NULL;
		$this->tmp = sys_get_temp_dir() . '/pfb_geoip_catalog_' . getmypid() . '_' . bin2hex(random_bytes(6));
		foreach (['cc', 'today', 'www'] as $d) {
			$this->assertTrue(mkdir("{$this->tmp}/{$d}", 0700, TRUE));
		}
		$pfb = is_array($this->originalPfb) ? $this->originalPfb : [];
		$GLOBALS['pfb'] = array_merge($pfb, [
			'ccdir' => "{$this->tmp}/cc",
			'ccdir_tmp' => "{$this->tmp}/cc-tmp",
			'log' => "{$this->tmp}/pfblockerng.log",
			'errlog' => "{$this->tmp}/error.log",
			'extraslog' => "{$this->tmp}/extras.log",
			// The Reputation log line goes to the extras log only; the test of that line prints it.
			'extras_update' => TRUE,
		]);
	}

	protected function tearDown(): void
	{
		if ($this->hadPfb) {
			$GLOBALS['pfb'] = $this->originalPfb;
		} else {
			unset($GLOBALS['pfb']);
		}
		if (in_array(GeoipCatalogTestStream::SCHEME, stream_get_wrappers(), TRUE)) {
			stream_wrapper_unregister(GeoipCatalogTestStream::SCHEME);
		}
		exec('rm -rf ' . escapeshellarg($this->tmp));
	}

	/**
	 * Given continent files with a country that is also a Top Spammer (so the Reputation list holds its ISO twice),
	 * when today's function writes the pages and the renderer is given the rows Core publishes for the same files,
	 * then both write the same pages, byte for byte.
	 */
	public function testCatalogRowsRenderThePagesTodaysFunctionWrites(): void
	{
		$this->continentFile('Africa_v4.txt', 'Africa', 'Africa', 4, [['Zulu', 'ZZ', ['1.1.1.1']], ['Alpha', 'AA', ['1.1.1.2', '1.1.1.3']]]);
		$this->continentFile('Africa_v6.txt', 'Africa', 'Africa', 6, [['Alpha', 'AA', ['2001:db8::1']]]);
		$this->continentFile('Top_Spammers_v4.info', 'Top Spammers', 'Top_Spammers', 4, [['Zulu', 'ZZ', ['1.1.1.1']]]);
		set_error_handler(static fn (): bool => TRUE, E_WARNING | E_NOTICE);
		try {
			$this->assertTrue(pfblockerng_get_countries("{$this->tmp}/today"));
		} finally {
			restore_error_handler();
		}

		$catalog = $this->catalog([
			['kind' => 'country', 'page' => 'Africa', 'family' => 4, 'position' => 1, 'iso' => 'AA', 'country' => 'Alpha', 'networks' => 2],
			['kind' => 'country', 'page' => 'Africa', 'family' => 4, 'position' => 2, 'iso' => 'ZZ', 'country' => 'Zulu', 'networks' => 1],
			['kind' => 'country', 'page' => 'Africa', 'family' => 6, 'position' => 1, 'iso' => 'AA', 'country' => 'Alpha', 'networks' => 1],
			['kind' => 'country', 'page' => 'Top_Spammers', 'family' => 4, 'position' => 1, 'iso' => 'ZZ', 'country' => 'Zulu', 'networks' => 1],
			['kind' => 'page', 'page' => 'Africa', 'continent' => 'Africa'],
			['kind' => 'page', 'page' => 'Top_Spammers', 'continent' => 'Top Spammers'],
			['kind' => 'reputation', 'position' => 1, 'iso' => 'AA', 'country' => 'Alpha', 'networks' => 2],
			['kind' => 'reputation', 'position' => 2, 'iso' => 'ZZ', 'country' => 'Zulu', 'networks' => 1],
			['kind' => 'reputation', 'position' => 3, 'iso' => 'ZZ', 'country' => 'Zulu', 'networks' => 1],
		]);
		$this->assertSame(self::WRITTEN, pfb_geoip_render_catalog($catalog, "{$this->tmp}/www"));

		$today = $this->contents("{$this->tmp}/today");
		$this->assertSame(['pfblockerng_Africa.php', 'pfblockerng_Top_Spammers.php', 'pfblockerng_reputation.php'], array_keys($today));
		$this->assertSame($today, $this->contents("{$this->tmp}/www"));
		// A staged page is published with the mode today's pages get, not a temporary file's 0600.
		foreach (array_keys($today) as $page) {
			$this->assertSame(sprintf('%o', fileperms("{$this->tmp}/today/{$page}")), sprintf('%o', fileperms("{$this->tmp}/www/{$page}")),
				"{$page}: its mode");
		}
		$this->assertSame(array_keys($today), self::entries("{$this->tmp}/www"), 'no temporary file is left');
	}

	/** @return array<string, array{string}> */
	public static function hostileNames(): array
	{
		return [
			'a double quote' => ['Say "hi"'],
			'a variable' => ['Cost $var'],
			'a braced variable' => ['Braced {$x}'],
			'a dollar brace' => ['Dollar ${x}'],
			'an expression in braces' => ['Call {${strtoupper(\'x\')}}'],
			'a backslash at the end' => ['Ends in \\'],
			'an escape sequence' => ['Tab \\t and \\x41 and \\u{41}'],
			'an opening tag' => ['<?php echo 1; ?>'],
			'a closing tag' => ['?> after'],
			'a NUL' => ["Ko\0rea"],
			'a line break' => ["Two\nlines"],
			'multi-byte text' => ['Côte d’Ivoire 日本 🇯🇵'],
			'a 64 KiB name' => [str_repeat('"$\\{', 16384)],
		];
	}

	/**
	 * Given a catalog whose continent and country names hold PHP syntax, when the pages are rendered, then each page
	 * parses, has the token structure of the same page rendered with a plain name, and defines exactly the names it was
	 * given: nothing in a row is executed or interpolated.
	 */
	#[DataProvider('hostileNames')]
	public function testAHostileNameIsDataInTheGeneratedPages(string $name): void
	{
		$benign = $this->renderNamed('Plain', "{$this->tmp}/benign");
		$this->assertSame(self::WRITTEN, pfb_geoip_render_catalog($this->namedCatalog($name), "{$this->tmp}/www"));

		foreach (['pfblockerng_Africa.php', 'pfblockerng_reputation.php'] as $page) {
			$path = "{$this->tmp}/www/{$page}";
			exec(PHP_BINARY . ' -l ' . escapeshellarg($path) . ' 2>&1', $lint, $rc);
			$this->assertSame(0, $rc, "{$page} must parse: " . implode("\n", $lint));
			$this->assertSame(self::structure($benign[$page]), self::structure((string) file_get_contents($path)),
				"{$page} must have the token structure of the page with a plain name");
		}
		$africa = (string) file_get_contents("{$this->tmp}/www/pfblockerng_Africa.php");
		$this->assertSame($name, self::assigned($africa, '$continent'));
		$this->assertSame('Africa', self::assigned($africa, '$continent_en'));
		$this->assertSame(['ZZ' => "{$name} ZZ (3)"], self::assigned($africa, '$options_countries4'));
		$this->assertSame('1', self::assigned($africa, '$options_countries4_cnt'));
		$this->assertSame([], self::assigned($africa, '$options_countries6'));
		$reputation = (string) file_get_contents("{$this->tmp}/www/pfblockerng_reputation.php");
		$this->assertSame(['ZZ' => "{$name} ZZ (3)"], self::assigned($reputation, '$options_ccexclude'));
	}

	/**
	 * Given an ISO listed twice in a list (a country that is also a Top Spammer, in the Reputation list), when the pages
	 * are rendered, then both rows are written in position order, as today's array literal holds them: the option keeps
	 * its first position and shows its last row, and the list's count counts both.
	 */
	public function testADuplicateIsoIsWrittenTwiceAsToday(): void
	{
		$catalog = $this->catalog([
			['kind' => 'page', 'page' => 'Asia', 'continent' => 'Asia'],
			['kind' => 'country', 'page' => 'Asia', 'family' => 4, 'position' => 1, 'iso' => 'CN', 'country' => 'First', 'networks' => 5],
			['kind' => 'country', 'page' => 'Asia', 'family' => 4, 'position' => 2, 'iso' => 'JP', 'country' => 'Japan', 'networks' => 7],
			['kind' => 'country', 'page' => 'Asia', 'family' => 4, 'position' => 3, 'iso' => 'CN', 'country' => 'Second', 'networks' => 6],
			['kind' => 'reputation', 'position' => 2, 'iso' => 'CN', 'country' => 'China', 'networks' => 9],
			['kind' => 'reputation', 'position' => 1, 'iso' => 'CN', 'country' => 'China', 'networks' => 5],
		]);
		$this->assertSame(self::WRITTEN, pfb_geoip_render_catalog($catalog, "{$this->tmp}/www"));

		$asia = (string) file_get_contents("{$this->tmp}/www/pfblockerng_Asia.php");
		$this->assertStringContainsString("= array(\t\"CN\" => \"First CN (5)\",\n\t\t\"JP\" => \"Japan JP (7)\",\n\t\t\"CN\" => \"Second CN (6)\"\n\t);", $asia);
		$this->assertSame(['CN' => 'Second CN (6)', 'JP' => 'Japan JP (7)'], self::assigned($asia, '$options_countries4'));
		$this->assertSame('3', self::assigned($asia, '$options_countries4_cnt'));
		$reputation = (string) file_get_contents("{$this->tmp}/www/pfblockerng_reputation.php");
		$this->assertSame(['CN' => 'China CN (9)'], self::assigned($reputation, '$options_ccexclude'));
		$this->assertStringContainsString("= array(\t\"CN\" => \"China CN (5)\",\n\t\t\"CN\" => \"China CN (9)\"\n\t);", $reputation);
	}

	/** @return array<string, array{string}> */
	public static function untrustedCatalogs(): array
	{
		$page = '{"kind":"page","page":"Africa","continent":"Africa"}';
		$country = static fn (string $fields): string => '{"kind":"country","page":"Africa","family":4,' . $fields . '}';
		$plain = '"position":1,"iso":"ZZ","country":"Zulu","networks":3';
		return [
			'not JSON' => ["{$page}\nnot json\n"],
			'a JSON array' => ["{$page}\n[\"page\",\"Africa\"]\n"],
			'a JSON string' => ["{$page}\n\"page\"\n"],
			'an unknown kind' => ["{$page}\n{\"kind\":\"asn\",\"position\":1,\"iso\":\"ZZ\",\"country\":\"Zulu\",\"networks\":3}\n"],
			'no kind' => ["{\"page\":\"Africa\",\"continent\":\"Africa\"}\n"],
			'a field missing' => ["{$page}\n" . $country('"position":1,"iso":"ZZ","country":"Zulu"') . "\n"],
			'an unknown field' => ["{$page}\n" . $country($plain . ',"asn":"AS1"') . "\n"],
			'a page row with a country field' => ["{\"kind\":\"page\",\"page\":\"Africa\",\"continent\":\"Africa\",\"iso\":\"ZZ\"}\n"],
			'a reputation row with a page' => ["{$page}\n{\"kind\":\"reputation\",\"page\":\"Africa\",{$plain}}\n"],
			'family 5' => ["{$page}\n" . str_replace('"family":4', '"family":5', $country($plain)) . "\n"],
			'family as a string' => ["{$page}\n" . str_replace('"family":4', '"family":"4"', $country($plain)) . "\n"],
			'position 0' => ["{$page}\n" . $country('"position":0,"iso":"ZZ","country":"Zulu","networks":3') . "\n"],
			'a fractional position' => ["{$page}\n" . $country('"position":1.5,"iso":"ZZ","country":"Zulu","networks":3') . "\n"],
			'a position twice in a list' => ["{$page}\n" . $country($plain) . "\n" . $country(str_replace('"ZZ"', '"AA"', $plain)) . "\n"],
			'a gap in the positions' => ["{$page}\n" . $country('"position":2,"iso":"ZZ","country":"Zulu","networks":3') . "\n"],
			'negative networks' => ["{$page}\n" . $country('"position":1,"iso":"ZZ","country":"Zulu","networks":-1') . "\n"],
			'networks as a string' => ["{$page}\n" . $country('"position":1,"iso":"ZZ","country":"Zulu","networks":"3"') . "\n"],
			'an ISO with a space' => ["{$page}\n" . $country('"position":1,"iso":"Z Z","country":"Zulu","networks":3') . "\n"],
			'an ISO with a quote' => ["{$page}\n" . $country('"position":1,"iso":"Z\"","country":"Zulu","networks":3') . "\n"],
			'an empty ISO' => ["{$page}\n" . $country('"position":1,"iso":"","country":"Zulu","networks":3') . "\n"],
			'an ISO ending in a newline' => ["{$page}\n" . $country('"position":1,"iso":"ZZ\n","country":"Zulu","networks":3') . "\n"],
			'an ISO with a letter outside ASCII' => ["{$page}\n" . $country('"position":1,"iso":"ZÉ","country":"Zulu","networks":3') . "\n"],
			'a country that is not a string' => ["{$page}\n" . $country('"position":1,"iso":"ZZ","country":["Zulu"],"networks":3') . "\n"],
			'a country that is a number' => ["{$page}\n" . $country('"position":1,"iso":"ZZ","country":5,"networks":3') . "\n"],
			'a country that is null' => ["{$page}\n" . $country('"position":1,"iso":"ZZ","country":null,"networks":3') . "\n"],
			'a country that is true' => ["{$page}\n" . $country('"position":1,"iso":"ZZ","country":true,"networks":3') . "\n"],
			'a continent that is not a string' => ["{\"kind\":\"page\",\"page\":\"Africa\",\"continent\":null}\n"],
			'a page twice' => ["{$page}\n{$page}\n"],
			'a page Core does not know twice' => ["{\"kind\":\"page\",\"page\":\"Foo\",\"continent\":\"Foo\"}\n{\"kind\":\"page\",\"page\":\"Foo\",\"continent\":\"Foo\"}\n"],
			'a country row of a page without its page row' => [$country($plain) . "\n"],
			'a country row of an unknown page without its page row' => ["{$page}\n" . str_replace('"Africa"', '"Foo"', $country($plain)) . "\n"],
			'a malformed country row of an unknown page' => ["{\"kind\":\"page\",\"page\":\"Foo\",\"continent\":\"Foo\"}\n"
				. str_replace('"Africa"', '"Foo"', $country('"position":1,"iso":"Z Z","country":"Zulu","networks":3')) . "\n"],
			'a blank line between rows' => ["{$page}\n\n" . $country($plain) . "\n"],
			'no newline after the last row' => ["{$page}\n" . $country($plain)],
			'a page name with a path' => ["{\"kind\":\"page\",\"page\":\"..\/Africa\",\"continent\":\"Africa\"}\n"],
			'a page name ending in a newline' => ["{\"kind\":\"page\",\"page\":\"Africa\\n\",\"continent\":\"Africa\"}\n"],
			'a page name that is a number' => ["{\"kind\":\"page\",\"page\":5,\"continent\":\"Africa\"}\n"],
			'an empty page name' => ["{\"kind\":\"page\",\"page\":\"\",\"continent\":\"Africa\"}\n"],
		];
	}

	/**
	 * Given a catalog with a row the renderer cannot trust, when it is rendered, then it is refused with a reason and no
	 * page is written: the pages already on disk stay as they were.
	 */
	#[DataProvider('untrustedCatalogs')]
	public function testAnUntrustedCatalogIsRefusedWholeAndLeavesThePages(string $body): void
	{
		file_put_contents("{$this->tmp}/www/pfblockerng_Africa.php", 'previous Africa');
		file_put_contents("{$this->tmp}/www/pfblockerng_reputation.php", 'previous Reputation');
		file_put_contents("{$this->tmp}/catalog", $body);

		['error' => $error, 'skipped' => $skipped] = pfb_geoip_render_catalog("{$this->tmp}/catalog", "{$this->tmp}/www");

		$this->assertIsString($error);
		$this->assertNotSame('', $error);
		$this->assertSame([], $skipped);
		$this->assertSame(['pfblockerng_Africa.php' => 'previous Africa', 'pfblockerng_reputation.php' => 'previous Reputation'],
			$this->contents("{$this->tmp}/www"));
		$this->assertSame(['pfblockerng_Africa.php', 'pfblockerng_reputation.php'], self::entries("{$this->tmp}/www"));
	}

	/**
	 * Given a catalog with a tenth page Core found in its continent files (Foo) beside a known one, when it is rendered,
	 * then the known page and the Reputation page are written, Foo and every country row naming it are skipped and Foo
	 * is reported: it becomes no file and none of its countries reaches a page.
	 */
	public function testAPageThatIsNotAContinentPageIsSkippedAndReported(): void
	{
		$known = [
			['kind' => 'page', 'page' => 'Africa', 'continent' => 'Africa'],
			['kind' => 'country', 'page' => 'Africa', 'family' => 4, 'position' => 1, 'iso' => 'ZZ', 'country' => 'Zulu', 'networks' => 3],
			['kind' => 'reputation', 'position' => 1, 'iso' => 'ZZ', 'country' => 'Zulu', 'networks' => 3],
		];
		$this->assertTrue(mkdir("{$this->tmp}/known", 0700));
		$this->assertSame(self::WRITTEN, pfb_geoip_render_catalog($this->catalog($known), "{$this->tmp}/known"));

		$result = pfb_geoip_render_catalog($this->catalog([...$known,
			['kind' => 'page', 'page' => 'Foo', 'continent' => 'Fooland'],
			['kind' => 'country', 'page' => 'Foo', 'family' => 4, 'position' => 1, 'iso' => 'FF', 'country' => 'Fooland', 'networks' => 1],
			['kind' => 'country', 'page' => 'Foo', 'family' => 6, 'position' => 1, 'iso' => 'FF', 'country' => 'Fooland', 'networks' => 1],
		]), "{$this->tmp}/www");

		$this->assertSame(['error' => NULL, 'skipped' => ['Foo']], $result);
		$this->assertSame($this->contents("{$this->tmp}/known"), $this->contents("{$this->tmp}/www"));
		$this->assertSame(['pfblockerng_Africa.php', 'pfblockerng_reputation.php'], self::entries("{$this->tmp}/www"));
	}

	/** @return array<string, array{string}> */
	public static function packagePageNames(): array
	{
		return ['the Reputation page' => ['reputation'], 'the DNSBL page' => ['dnsbl']];
	}

	/**
	 * Given a catalog naming another package page as a continent page, with a country row, when it is rendered, then that
	 * page is skipped: its page file is not written from the row (the Reputation page is the one its own rows give), and
	 * the name is reported.
	 */
	#[DataProvider('packagePageNames')]
	public function testAnotherPackagePageNamedAsAContinentPageIsSkipped(string $name): void
	{
		$reputation = [['kind' => 'reputation', 'position' => 1, 'iso' => 'ZZ', 'country' => 'Zulu', 'networks' => 3]];
		$this->assertTrue(mkdir("{$this->tmp}/known", 0700));
		$this->assertSame(self::WRITTEN, pfb_geoip_render_catalog($this->catalog($reputation), "{$this->tmp}/known"));

		$result = pfb_geoip_render_catalog($this->catalog([...$reputation,
			['kind' => 'page', 'page' => $name, 'continent' => 'Injected'],
			['kind' => 'country', 'page' => $name, 'family' => 4, 'position' => 1, 'iso' => 'II', 'country' => 'Injected', 'networks' => 1],
		]), "{$this->tmp}/www");

		$this->assertSame(['error' => NULL, 'skipped' => [$name]], $result);
		$this->assertSame($this->contents("{$this->tmp}/known"), $this->contents("{$this->tmp}/www"));
		$this->assertSame(['pfblockerng_reputation.php'], self::entries("{$this->tmp}/www"));
	}

	/**
	 * Given pages on disk and a target that is a directory (a continent page, or the Reputation page that is staged with
	 * them), when a catalog is rendered, then nothing is written: every page keeps its old bytes, no temporary file is
	 * left, and the failure names the page.
	 */
	#[DataProvider('blockedPages')]
	public function testATargetThatCannotBeReplacedLeavesEveryPage(string $blocked): void
	{
		$pages = ['pfblockerng_Africa.php', 'pfblockerng_Asia.php', 'pfblockerng_reputation.php'];
		foreach ($pages as $page) {
			$this->assertTrue($page === $blocked ? mkdir("{$this->tmp}/www/{$page}") : file_put_contents("{$this->tmp}/www/{$page}", "old {$page}") !== FALSE);
		}
		$catalog = $this->catalog([
			['kind' => 'page', 'page' => 'Africa', 'continent' => 'Africa'],
			['kind' => 'page', 'page' => 'Asia', 'continent' => 'Asia'],
			['kind' => 'reputation', 'position' => 1, 'iso' => 'ZZ', 'country' => 'Zulu', 'networks' => 3],
		]);

		['error' => $error, 'skipped' => $skipped] = pfb_geoip_render_catalog($catalog, "{$this->tmp}/www");

		$this->assertIsString($error);
		$this->assertStringContainsString($blocked, $error);
		$this->assertSame([], $skipped);
		$this->assertSame($pages, self::entries("{$this->tmp}/www"), 'no temporary file is left');
		$this->assertDirectoryExists("{$this->tmp}/www/{$blocked}");
		foreach (array_diff($pages, [$blocked]) as $page) {
			$this->assertSame("old {$page}", file_get_contents("{$this->tmp}/www/{$page}"), "{$page} keeps its old bytes");
		}
	}

	/** @return array<string, array{string}> */
	public static function blockedPages(): array
	{
		return ['a continent page' => ['pfblockerng_Asia.php'], 'the Reputation page' => ['pfblockerng_reputation.php']];
	}

	/**
	 * Given a target page that is a symbolic link, when a catalog is rendered, then the link is replaced by the page and
	 * the file it pointed to is not written through it.
	 */
	public function testASymbolicLinkAtATargetIsReplacedNotWrittenThrough(): void
	{
		file_put_contents("{$this->tmp}/outside", 'outside');
		$this->assertTrue(symlink("{$this->tmp}/outside", "{$this->tmp}/www/pfblockerng_Africa.php"));
		$this->assertTrue(mkdir("{$this->tmp}/plain", 0700));
		$this->assertSame(self::WRITTEN, pfb_geoip_render_catalog($this->namedCatalog('Plain'), "{$this->tmp}/plain"));

		$this->assertSame(self::WRITTEN, pfb_geoip_render_catalog($this->namedCatalog('Plain'), "{$this->tmp}/www"));

		clearstatcache();
		$this->assertFalse(is_link("{$this->tmp}/www/pfblockerng_Africa.php"));
		$this->assertSame('outside', file_get_contents("{$this->tmp}/outside"));
		$this->assertSame($this->contents("{$this->tmp}/plain"), $this->contents("{$this->tmp}/www"));
	}

	/**
	 * Given a catalog of exactly PFB_GEOIP_CATALOG_MAX bytes (a valid row padded with JSON white space), when it is
	 * rendered, then its page is written; one byte more is refused before it is decoded and writes nothing.
	 */
	public function testACatalogOverTheBoundIsRefusedBeforeItIsDecoded(): void
	{
		$this->assertSame(16 << 20, PFB_GEOIP_CATALOG_MAX);
		$row = '{"kind":"page","page":"Africa","continent":"Africa"}';
		$padded = static fn (int $size): string => $row . str_repeat(' ', $size - strlen($row) - 1) . "\n";

		file_put_contents("{$this->tmp}/catalog", $padded(PFB_GEOIP_CATALOG_MAX));
		$this->assertSame(PFB_GEOIP_CATALOG_MAX, filesize("{$this->tmp}/catalog"));
		$this->assertSame(self::WRITTEN, pfb_geoip_render_catalog("{$this->tmp}/catalog", "{$this->tmp}/www"));
		$this->assertSame(['pfblockerng_Africa.php', 'pfblockerng_reputation.php'], self::entries("{$this->tmp}/www"));

		file_put_contents("{$this->tmp}/catalog", $padded(PFB_GEOIP_CATALOG_MAX + 1));
		$this->assertTrue(mkdir("{$this->tmp}/over", 0700));
		['error' => $error, 'skipped' => $skipped] = pfb_geoip_render_catalog("{$this->tmp}/catalog", "{$this->tmp}/over");
		$this->assertIsString($error);
		$this->assertStringContainsString('larger than ' . PFB_GEOIP_CATALOG_MAX . ' bytes', $error);
		$this->assertSame([], $skipped);
		$this->assertSame([], self::entries("{$this->tmp}/over"));
	}

	/** @return array<string, array{string}> */
	public static function emptyCatalogs(): array
	{
		return ['an empty body' => [''], 'the body Core writes for no row' => ["\n"]];
	}

	/**
	 * Given a catalog without a row, when it is rendered, then the result is what today's function writes from no
	 * continent data: the Reputation page with an empty country list, and no continent page written (one already on disk
	 * stays).
	 */
	#[DataProvider('emptyCatalogs')]
	public function testAnEmptyCatalogWritesTheReputationPageWithoutCountries(string $body): void
	{
		file_put_contents("{$this->tmp}/www/pfblockerng_Africa.php", 'previous Africa');
		file_put_contents("{$this->tmp}/catalog", $body);
		set_error_handler(static fn (): bool => TRUE, E_WARNING | E_NOTICE);
		try {
			$this->assertTrue(pfblockerng_get_countries("{$this->tmp}/today"));
		} finally {
			restore_error_handler();
		}

		$this->assertSame(self::WRITTEN, pfb_geoip_render_catalog("{$this->tmp}/catalog", "{$this->tmp}/www"));

		$this->assertSame(['pfblockerng_reputation.php'], array_keys($this->contents("{$this->tmp}/today")));
		$this->assertSame([
			'pfblockerng_Africa.php' => 'previous Africa',
			'pfblockerng_reputation.php' => (string) file_get_contents("{$this->tmp}/today/pfblockerng_reputation.php"),
		], $this->contents("{$this->tmp}/www"));
	}

	public function testACatalogThatCannotBeReadIsRefused(): void
	{
		['error' => $error, 'skipped' => $skipped] = pfb_geoip_render_catalog("{$this->tmp}/missing", "{$this->tmp}/www");

		$this->assertIsString($error);
		$this->assertSame([], $skipped);
		$this->assertStringContainsString("{$this->tmp}/missing", $error);
		$this->assertSame([], $this->contents("{$this->tmp}/www"));
	}

	/** Given an output folder that cannot be created, when a valid catalog is rendered, then the failure is reported. */
	public function testPagesThatCannotBeWrittenAreReported(): void
	{
		file_put_contents("{$this->tmp}/not-a-folder", '');

		['error' => $error] = pfb_geoip_render_catalog($this->namedCatalog('Plain'), "{$this->tmp}/not-a-folder/www");

		$this->assertIsString($error);
		$this->assertStringContainsString("{$this->tmp}/not-a-folder/www", $error);
	}

	/** @return list<string> a name a render stages each page it can write under: ".<page file>.<12 lower-case hex digits>" */
	private static function stagedNames(): array
	{
		return array_map(static fn (string $page): string => ".pfblockerng_{$page}.php.0123456789ab", PFB_GEOIP_PAGES);
	}

	/**
	 * Given a staged file of each page left in the page folder by an earlier render that died before publishing it, when
	 * a catalog is rendered, then every one of them is gone, those of pages this catalog does not write included.
	 */
	public function testStagedFilesOfAnEarlierRenderAreRemoved(): void
	{
		foreach (self::stagedNames() as $name) {
			$this->assertNotFalse(file_put_contents("{$this->tmp}/www/{$name}", 'stale'));
		}
		$this->assertCount(10, self::entries("{$this->tmp}/www"));

		$this->assertSame(self::WRITTEN, pfb_geoip_render_catalog($this->namedCatalog('Plain'), "{$this->tmp}/www"));

		$this->assertSame(['pfblockerng_Africa.php', 'pfblockerng_reputation.php'], self::entries("{$this->tmp}/www"));
	}

	/**
	 * Given entries that look like staged files but are not of the exact form a render creates (another page name, a
	 * suffix of another length or case, no leading dot), and entries of that form that are not regular files (a
	 * directory, a symbolic link), when a catalog is rendered, then each is left as it was, and the link's target too.
	 */
	public function testEntriesThatAreNotStagedFilesAreLeftAlone(): void
	{
		$www = "{$this->tmp}/www";
		$files = [
			'.pfblockerng_Foo.php.0123456789ab', '.pfblockerng_dnsbl.php.0123456789ab', '.pfblockerng_Africa.php.0123456789a',
			'.pfblockerng_Africa.php.0123456789abc', '.pfblockerng_Africa.php.0123456789AB', 'pfblockerng_Africa.php.0123456789ab',
			'.pfblockerng_Africa.php.0123456789ab.bak', '.pfblockerng_Africa.php0123456789ab', '.pfblockerng_africa.php.0123456789ab',
		];
		foreach ($files as $name) {
			$this->assertNotFalse(file_put_contents("{$www}/{$name}", $name));
		}
		$this->assertTrue(mkdir("{$www}/.pfblockerng_Asia.php.0123456789ab"));
		$this->assertNotFalse(file_put_contents("{$www}/.pfblockerng_Asia.php.0123456789ab/inside", 'inside'));
		file_put_contents("{$this->tmp}/outside", 'outside');
		$this->assertTrue(symlink("{$this->tmp}/outside", "{$www}/.pfblockerng_reputation.php.0123456789ab"));
		$this->assertTrue(symlink("{$this->tmp}/missing", "{$www}/.pfblockerng_Europe.php.0123456789ab"));

		$this->assertSame(self::WRITTEN, pfb_geoip_render_catalog($this->namedCatalog('Plain'), $www));

		$expected = [...$files, '.pfblockerng_Asia.php.0123456789ab', '.pfblockerng_reputation.php.0123456789ab',
			'.pfblockerng_Europe.php.0123456789ab', 'pfblockerng_Africa.php', 'pfblockerng_reputation.php'];
		sort($expected, SORT_STRING);
		$this->assertSame($expected, self::entries($www));
		foreach ($files as $name) {
			$this->assertSame($name, file_get_contents("{$www}/{$name}"), "{$name} keeps its bytes");
		}
		$this->assertSame('inside', file_get_contents("{$www}/.pfblockerng_Asia.php.0123456789ab/inside"));
		$this->assertSame("{$this->tmp}/outside", readlink("{$www}/.pfblockerng_reputation.php.0123456789ab"));
		$this->assertSame('outside', file_get_contents("{$this->tmp}/outside"));
		$this->assertSame("{$this->tmp}/missing", readlink("{$www}/.pfblockerng_Europe.php.0123456789ab"));
	}

	/**
	 * Given a page folder whose writes throw (a stream that fails part way through staging the first page), when a
	 * catalog is rendered, then the exception reaches the caller and the file staged so far is removed: the folder holds
	 * the old page alone.
	 */
	public function testAnExceptionWhileStagingLeavesNoStagedFile(): void
	{
		file_put_contents("{$this->tmp}/www/pfblockerng_Africa.php", 'old Africa');
		GeoipCatalogTestStream::register($this->tmp, TRUE);

		try {
			pfb_geoip_render_catalog($this->namedCatalog('Plain'), GeoipCatalogTestStream::SCHEME . '://www');
			$this->fail('the write failure must reach the caller');
		} catch (RuntimeException $e) {
			$this->assertSame(GeoipCatalogTestStream::FAILURE, $e->getMessage());
		}

		$this->assertSame(['pfblockerng_Africa.php'], self::entries("{$this->tmp}/www"));
		$this->assertSame('old Africa', file_get_contents("{$this->tmp}/www/pfblockerng_Africa.php"));
	}

	/**
	 * Given a page folder whose files can be written but not synced to disk, when a catalog is rendered, then staging
	 * fails: no page is published, the old page keeps its bytes, no staged file is left, and the failure names the page.
	 */
	public function testAStagedPageThatCannotBeSyncedPublishesNothing(): void
	{
		file_put_contents("{$this->tmp}/www/pfblockerng_Africa.php", 'old Africa');
		GeoipCatalogTestStream::register($this->tmp, FALSE);

		['error' => $error, 'skipped' => $skipped] = pfb_geoip_render_catalog($this->namedCatalog('Plain'),
			GeoipCatalogTestStream::SCHEME . '://www');

		$this->assertIsString($error);
		$this->assertStringContainsString('pfblockerng_Africa.php cannot be written', $error);
		$this->assertSame([], $skipped);
		$this->assertSame(['pfblockerng_Africa.php'], self::entries("{$this->tmp}/www"));
		$this->assertSame('old Africa', file_get_contents("{$this->tmp}/www/pfblockerng_Africa.php"));
	}

	/** @return array<string, array{int}> */
	public static function umasks(): array
	{
		return ['umask 022' => [0022], 'umask 077' => [0077]];
	}

	/**
	 * Given pages on disk with mode 0640, when a catalog is rendered under $umask, then each replaced page keeps 0640, as
	 * the old write in place kept it, and a page that did not exist gets the mode file_put_contents() gives a new file.
	 */
	#[DataProvider('umasks')]
	public function testAReplacedPageKeepsItsModeAndANewPageGetsAFreshFilesMode(int $umask): void
	{
		$www = "{$this->tmp}/www";
		foreach (['pfblockerng_Africa.php', 'pfblockerng_reputation.php'] as $page) {
			file_put_contents("{$www}/{$page}", "old {$page}");
			$this->assertTrue(chmod("{$www}/{$page}", 0640));
		}
		$catalog = $this->catalog([
			['kind' => 'page', 'page' => 'Africa', 'continent' => 'Africa'],
			['kind' => 'page', 'page' => 'Asia', 'continent' => 'Asia'],
		]);
		$previous = umask($umask);
		try {
			$this->assertNotFalse(file_put_contents("{$this->tmp}/fresh", 'fresh'));
			$result = pfb_geoip_render_catalog($catalog, $www);
		} finally {
			umask($previous);
		}
		clearstatcache();

		$this->assertSame(self::WRITTEN, $result);
		$this->assertSame('640', sprintf('%o', fileperms("{$www}/pfblockerng_Africa.php") & 07777));
		$this->assertSame('640', sprintf('%o', fileperms("{$www}/pfblockerng_reputation.php") & 07777));
		$this->assertSame(sprintf('%o', fileperms("{$this->tmp}/fresh") & 07777), sprintf('%o', fileperms("{$www}/pfblockerng_Asia.php") & 07777));
		$this->assertNotSame('old pfblockerng_Africa.php', file_get_contents("{$www}/pfblockerng_Africa.php"));
	}

	/**
	 * Given a page on disk owned by another user and group, when a catalog is rendered, then the replaced page keeps that
	 * owner and group. Only root can give a file away, so the case needs root (CI runs as root).
	 */
	public function testAReplacedPageKeepsItsOwnerAndGroup(): void
	{
		if (!function_exists('posix_getuid') || posix_getuid() !== 0) {
			$this->markTestSkipped('only root can give a page to another owner');
		}
		$page = "{$this->tmp}/www/pfblockerng_Africa.php";
		file_put_contents($page, 'old Africa');
		$this->assertTrue(chown($page, 4037) && chgrp($page, 4038));

		$this->assertSame(self::WRITTEN, pfb_geoip_render_catalog($this->namedCatalog('Plain'), "{$this->tmp}/www"));
		clearstatcache();

		$this->assertSame([4037, 4038], [fileowner($page), filegroup($page)]);
		$this->assertNotSame('old Africa', file_get_contents($page));
	}

	/** Given a page Core names with a name of digits, when it is skipped, then it is reported as the string it is. */
	public function testASkippedPageNamedWithDigitsIsReportedAsAString(): void
	{
		$result = pfb_geoip_render_catalog($this->catalog([['kind' => 'page', 'page' => '123', 'continent' => 'Digits']]),
			"{$this->tmp}/www");

		$this->assertSame(['error' => NULL, 'skipped' => ['123']], $result);
	}

	/** @return array<string, array{mixed}> */
	public static function emptyCountryOptions(): array
	{
		return ['NULL' => [NULL], 'an empty array' => [[]], 'the integer 0' => [0], 'the string 0' => ['0'], 'an empty string' => ['']];
	}

	/**
	 * Given a value empty() holds empty, when pfb_build_reputation_tab() is given it, then it writes the Reputation page
	 * without countries, byte for byte the page the function wrote before the catalog renderer shared its page source.
	 */
	#[DataProvider('emptyCountryOptions')]
	public function testAnEmptyValueWritesTheReputationPageWithoutCountries(mixed $options): void
	{
		$golden = json_decode((string) file_get_contents(__DIR__ . '/fixtures/geoip_pre_move_golden.json'), TRUE, 512, JSON_THROW_ON_ERROR);

		$this->assertTrue(pfb_build_reputation_tab($options, "{$this->tmp}/www"));

		$this->assertSame($golden['reputation_empty'], hash_file('sha256', "{$this->tmp}/www/pfblockerng_reputation.php"));
		$this->assertFileDoesNotExist("{$this->tmp}/extras.log", 'a page without countries is not logged');
	}

	/**
	 * Given a catalog whose Reputation list has countries, when it is rendered, then the line pfb_build_reputation_tab()
	 * logs for such a page is written once to the screen and the extras log after the page is published.
	 */
	public function testAReputationPageWithCountriesIsLoggedAsToday(): void
	{
		unset($GLOBALS['pfb']['extras_update']);
		// pfb_logger()'s stamp and one space, then the line as logged, its own leading space included.
		$line = '/^\d{4}-\d\d-\d\d \d\d:\d\d:\d\d ' . preg_quote(' pfBlockerNG Reputation Tab') . '\n$/D';
		$this->expectOutputRegex($line);

		$this->assertSame(self::WRITTEN, pfb_geoip_render_catalog($this->namedCatalog('Plain'), "{$this->tmp}/www"));

		$this->assertFileExists("{$this->tmp}/extras.log");
		$this->assertMatchesRegularExpression($line, (string) file_get_contents("{$this->tmp}/extras.log"));
	}

	/**
	 * Given a catalog whose Reputation list is empty, or whose Reputation page cannot be published, when it is rendered,
	 * then no Reputation line is logged.
	 */
	public function testNoReputationLineIsLoggedWithoutCountriesOrWithoutAPublishedPage(): void
	{
		$this->assertSame(self::WRITTEN, pfb_geoip_render_catalog($this->catalog([
			['kind' => 'page', 'page' => 'Africa', 'continent' => 'Africa'],
		]), "{$this->tmp}/www"));
		$this->assertFileDoesNotExist("{$this->tmp}/extras.log");

		$this->assertTrue(mkdir("{$this->tmp}/blocked/pfblockerng_reputation.php", 0700, TRUE));
		$this->assertIsString(pfb_geoip_render_catalog($this->namedCatalog('Plain'), "{$this->tmp}/blocked")['error']);
		$this->assertFileDoesNotExist("{$this->tmp}/extras.log");
	}

	/** @return array<string,string> the pages one catalog renders with $name as the continent and the country name */
	private function renderNamed(string $name, string $dir): array
	{
		$this->assertTrue(mkdir($dir, 0700));
		$this->assertSame(self::WRITTEN, pfb_geoip_render_catalog($this->namedCatalog($name), $dir));
		return $this->contents($dir);
	}

	private function namedCatalog(string $name): string
	{
		return $this->catalog([
			['kind' => 'page', 'page' => 'Africa', 'continent' => $name],
			['kind' => 'country', 'page' => 'Africa', 'family' => 4, 'position' => 1, 'iso' => 'ZZ', 'country' => $name, 'networks' => 3],
			['kind' => 'reputation', 'position' => 1, 'iso' => 'ZZ', 'country' => $name, 'networks' => 3],
		]);
	}

	/**
	 * Write $rows as Core publishes the geo-catalog: one JSON object a line, the lines in byte order.
	 *
	 * @param list<array<string,mixed>> $rows
	 */
	private function catalog(array $rows): string
	{
		$lines = array_map(static fn (array $row): string => json_encode($row, JSON_THROW_ON_ERROR), $rows);
		sort($lines, SORT_STRING);
		$path = "{$this->tmp}/catalog-" . bin2hex(random_bytes(4));
		$this->assertNotFalse(file_put_contents($path, implode("\n", $lines) . "\n"));
		return $path;
	}

	/** @param list<array{string, string, list<string>}> $countries [name, ISO, networks] */
	private function continentFile(string $file, string $continent, string $continentEn, int $family, array $countries): void
	{
		$lines = ["# Continent IPv{$family}: {$continent}", "# Continent en: {$continentEn}"];
		foreach ($countries as [$country, $iso, $networks]) {
			array_push($lines, "# Country: {$country}", "# ISO Code: {$iso}", '# Total Networks: ' . count($networks), ...$networks);
		}
		$this->assertNotFalse(file_put_contents("{$this->tmp}/cc/{$file}", implode("\n", $lines) . "\n"));
	}

	/** @return array<string,string> every file in $dir, name => content */
	private function contents(string $dir): array
	{
		$out = [];
		foreach (glob("{$dir}/*") ?: [] as $file) {
			$out[basename($file)] = (string) file_get_contents($file);
		}
		ksort($out, SORT_STRING);
		return $out;
	}

	/** @return list<string> every entry in $dir, dot files (a temporary page) included, in byte order */
	private static function entries(string $dir): array
	{
		$entries = array_values(array_diff(scandir($dir) ?: [], ['.', '..']));
		sort($entries, SORT_STRING);
		return $entries;
	}

	/** @return list<string> the page's tokens by kind, without their text */
	private static function structure(string $source): array
	{
		return array_map(static fn (array|string $t): string => is_array($t) ? token_name($t[0]) : $t, token_get_all($source));
	}

	/**
	 * The value the page assigns to $variable: its first assignment statement's right-hand side, cut at the statement's
	 * ';' token (so a ';' inside a string does not end it) and evaluated alone.
	 */
	private static function assigned(string $source, string $variable): mixed
	{
		$tokens = token_get_all($source);
		foreach ($tokens as $i => $token) {
			if (!is_array($token) || $token[0] !== T_VARIABLE || $token[1] !== $variable) {
				continue;
			}
			$j = $i + 1;
			while (is_array($tokens[$j]) && $tokens[$j][0] === T_WHITESPACE) {
				$j++;
			}
			if ($tokens[$j] !== '=') {
				continue;
			}
			$expression = '';
			for ($k = $j + 1; $tokens[$k] !== ';'; $k++) {
				$expression .= is_array($tokens[$k]) ? $tokens[$k][1] : $tokens[$k];
			}
			return eval("return {$expression};");
		}
		throw new RuntimeException("the page assigns no {$variable}");
	}
}

/**
 * A stream wrapper over a real folder ("<SCHEME>://<path>" is "<root>/<path>") whose files can be opened and written but,
 * like every userspace stream, not synced; with $failWrites, its first write throws instead.
 */
final class GeoipCatalogTestStream
{
	public const SCHEME = 'pfbgeoipcatalogtest';
	public const FAILURE = 'the write fails';

	/** @var resource|null */
	public $context;
	private static string $root = '';
	private static bool $failWrites = FALSE;
	/** @var resource|false */
	private $handle = FALSE;
	/** @var resource|false */
	private $dir = FALSE;

	public static function register(string $root, bool $failWrites): void
	{
		self::$root = $root;
		self::$failWrites = $failWrites;
		if (!stream_wrapper_register(self::SCHEME, self::class)) {
			throw new RuntimeException('the test stream cannot be registered');
		}
	}

	private static function real(string $path): string
	{
		return self::$root . '/' . substr($path, strlen(self::SCHEME . '://'));
	}

	public function stream_open(string $path, string $mode, int $options, ?string &$opened): bool
	{
		$this->handle = @fopen(self::real($path), $mode);
		return $this->handle !== FALSE;
	}

	public function stream_write(string $data): int
	{
		if (self::$failWrites) {
			throw new RuntimeException(self::FAILURE);
		}
		return (int) fwrite($this->handle, $data);
	}

	public function stream_flush(): bool
	{
		return fflush($this->handle);
	}

	public function stream_close(): void
	{
		fclose($this->handle);
	}

	/** @return array<int|string, int>|false */
	public function url_stat(string $path, int $flags): array|false
	{
		return ($flags & STREAM_URL_STAT_LINK) !== 0 ? @lstat(self::real($path)) : @stat(self::real($path));
	}

	/** @return array<int|string, int>|false */
	public function stream_stat(): array|false
	{
		return fstat($this->handle);
	}

	public function unlink(string $path): bool
	{
		return unlink(self::real($path));
	}

	public function rename(string $from, string $to): bool
	{
		return rename(self::real($from), self::real($to));
	}

	public function stream_metadata(string $path, int $option, mixed $value): bool
	{
		return match ($option) {
			STREAM_META_ACCESS => chmod(self::real($path), $value),
			STREAM_META_OWNER, STREAM_META_OWNER_NAME => chown(self::real($path), $value),
			STREAM_META_GROUP, STREAM_META_GROUP_NAME => chgrp(self::real($path), $value),
			default => FALSE,
		};
	}

	public function dir_opendir(string $path, int $options): bool
	{
		$this->dir = opendir(self::real($path));
		return $this->dir !== FALSE;
	}

	public function dir_readdir(): string|false
	{
		return readdir($this->dir);
	}

	public function dir_rewinddir(): bool
	{
		rewinddir($this->dir);
		return TRUE;
	}

	public function dir_closedir(): bool
	{
		closedir($this->dir);
		return TRUE;
	}
}
