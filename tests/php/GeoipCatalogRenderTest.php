<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * The GeoIP pages rendered from the geo-catalog (#4037): the rows Core publishes (docs/specs/go-updater-pipeline.md §7,
 * JSON Lines in byte order) give the continent pages and the Reputation page pfblockerng_get_countries() writes from the
 * continent files, byte for byte. A name is data in the generated page whatever it holds; a catalog the renderer cannot
 * trust is refused whole and leaves the pages on disk as they were.
 */
#[CoversFunction('pfb_geoip_render_catalog')]
final class GeoipCatalogRenderTest extends TestCase
{
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
		]);
	}

	protected function tearDown(): void
	{
		if ($this->hadPfb) {
			$GLOBALS['pfb'] = $this->originalPfb;
		} else {
			unset($GLOBALS['pfb']);
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
		$this->assertNull(pfb_geoip_render_catalog($catalog, "{$this->tmp}/www"));

		$today = $this->pages("{$this->tmp}/today");
		$this->assertSame(['pfblockerng_Africa.php', 'pfblockerng_Top_Spammers.php', 'pfblockerng_reputation.php'], array_keys($today));
		$this->assertSame($today, $this->pages("{$this->tmp}/www"));
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
		$this->assertNull(pfb_geoip_render_catalog($this->namedCatalog($name), "{$this->tmp}/www"));

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
		$this->assertNull(pfb_geoip_render_catalog($catalog, "{$this->tmp}/www"));

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
			'a country that is not a string' => ["{$page}\n" . $country('"position":1,"iso":"ZZ","country":["Zulu"],"networks":3') . "\n"],
			'a continent that is not a string' => ["{\"kind\":\"page\",\"page\":\"Africa\",\"continent\":null}\n"],
			'a page twice' => ["{$page}\n{$page}\n"],
			'a country row of a page without its page row' => [$country($plain) . "\n"],
			'a blank line between rows' => ["{$page}\n\n" . $country($plain) . "\n"],
			'no newline after the last row' => ["{$page}\n" . $country($plain)],
			'an unknown continent page' => ["{\"kind\":\"page\",\"page\":\"Atlantis\",\"continent\":\"Atlantis\"}\n"],
			'the Reputation page named as a continent page' => ["{\"kind\":\"page\",\"page\":\"reputation\",\"continent\":\"Reputation\"}\n"],
			'another package page named as a continent page' => ["{\"kind\":\"page\",\"page\":\"dnsbl\",\"continent\":\"DNSBL\"}\n"],
			'a page name with a path' => ["{\"kind\":\"page\",\"page\":\"..\/Africa\",\"continent\":\"Africa\"}\n"],
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

		$error = pfb_geoip_render_catalog("{$this->tmp}/catalog", "{$this->tmp}/www");

		$this->assertIsString($error);
		$this->assertNotSame('', $error);
		$this->assertSame(['pfblockerng_Africa.php' => 'previous Africa', 'pfblockerng_reputation.php' => 'previous Reputation'],
			$this->contents("{$this->tmp}/www"));
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

		$this->assertNull(pfb_geoip_render_catalog("{$this->tmp}/catalog", "{$this->tmp}/www"));

		$this->assertSame(['pfblockerng_reputation.php'], array_keys($this->pages("{$this->tmp}/today")));
		$this->assertSame([
			'pfblockerng_Africa.php' => 'previous Africa',
			'pfblockerng_reputation.php' => (string) file_get_contents("{$this->tmp}/today/pfblockerng_reputation.php"),
		], $this->contents("{$this->tmp}/www"));
	}

	public function testACatalogThatCannotBeReadIsRefused(): void
	{
		$error = pfb_geoip_render_catalog("{$this->tmp}/missing", "{$this->tmp}/www");

		$this->assertIsString($error);
		$this->assertStringContainsString("{$this->tmp}/missing", $error);
		$this->assertSame([], $this->contents("{$this->tmp}/www"));
	}

	/** Given an output folder that cannot be created, when a valid catalog is rendered, then the failure is reported. */
	public function testPagesThatCannotBeWrittenAreReported(): void
	{
		file_put_contents("{$this->tmp}/not-a-folder", '');

		$error = pfb_geoip_render_catalog($this->namedCatalog('Plain'), "{$this->tmp}/not-a-folder/www");

		$this->assertIsString($error);
		$this->assertStringContainsString("{$this->tmp}/not-a-folder/www", $error);
	}

	/** @return array<string,string> the pages one catalog renders with $name as the continent and the country name */
	private function renderNamed(string $name, string $dir): array
	{
		$this->assertTrue(mkdir($dir, 0700));
		$this->assertNull(pfb_geoip_render_catalog($this->namedCatalog($name), $dir));
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

	/** @return array<string,string> every file in $dir, name => sha256 */
	private function pages(string $dir): array
	{
		return array_map(static fn (string $content): string => hash('sha256', $content), $this->contents($dir));
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
