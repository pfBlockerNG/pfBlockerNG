<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;

/**
 * Independent coverage for issue #1576's package seam.
 *
 * Generation runs behaviorally against temporary output. Installer dispatch stays
 * static because executing install.inc performs appliance-only migrations and
 * service changes; comment-free PHP keeps that pin independent of prose.
 */
final class GeoipPackageGenerationCoverageTest extends TestCase
{
	private static string $installSource;
	private string $tmp;
	private string $ccdir;
	private string $output;
	private mixed $originalPfb;
	private bool $hadPfb = FALSE;

	public static function setUpBeforeClass(): void
	{
		self::$installSource = php_strip_whitespace(
			dirname(__DIR__, 2) . '/src/usr/local/pkg/pfblockerng/pfblockerng_install.inc'
		);
		if (self::$installSource === '') {
			throw new RuntimeException('test bootstrap: failed to read comment-free install source');
		}
	}

	protected function setUp(): void
	{
		$this->hadPfb = array_key_exists('pfb', $GLOBALS);
		$this->originalPfb = $GLOBALS['pfb'] ?? NULL;
		$this->tmp = sys_get_temp_dir() . '/pfb_geoip_coverage_' . getmypid() . '_' . uniqid();
		$this->ccdir = "{$this->tmp}/cc";
		$this->output = "{$this->tmp}/www";
		mkdir($this->ccdir, 0777, TRUE);
		mkdir($this->output, 0777, TRUE);

		$pfb = $GLOBALS['pfb'] ?? [];
		$GLOBALS['pfb'] = is_array($pfb) ? array_merge($pfb, [
			'ccdir' => $this->ccdir,
			'ccdir_tmp' => "{$this->tmp}/cc-tmp",
			'log' => "{$this->tmp}/pfblockerng.log",
			'errlog' => "{$this->tmp}/error.log",
			'extraslog' => "{$this->tmp}/extras.log",
			'extras_update' => FALSE,
			'complete' => FALSE,
		]) : [
			'ccdir' => $this->ccdir,
			'ccdir_tmp' => "{$this->tmp}/cc-tmp",
			'log' => "{$this->tmp}/pfblockerng.log",
			'errlog' => "{$this->tmp}/error.log",
			'extraslog' => "{$this->tmp}/extras.log",
			'extras_update' => FALSE,
			'complete' => FALSE,
		];
	}

	protected function tearDown(): void
	{
		$this->removeTree($this->tmp);
		if ($this->hadPfb) {
			$GLOBALS['pfb'] = $this->originalPfb;
		} else {
			unset($GLOBALS['pfb']);
		}
	}

	public function testPackageGeoipInterfaceGeneratesCountryAndReputationArtifacts(): void
	{
		$this->assertTrue(function_exists('pfblockerng_get_countries'));
		$this->assertTrue(function_exists('pfb_build_reputation_tab'));
		foreach ([
			'Africa' => 'Africa', 'Antarctica' => 'Antarctica', 'Asia' => 'Asia', 'Europe' => 'Europe',
			'North America' => 'North_America', 'Oceania' => 'Oceania', 'South America' => 'South_America',
			'Proxy and Satellite' => 'Proxy_and_Satellite', 'Top Spammers' => 'Top_Spammers',
		] as $continent => $slug) {
			$this->writeContinent($continent, $slug, '4', []);
			$this->writeContinent($continent, $slug, '6', []);
		}
		$this->writeContinent('Africa', 'Africa', '4', [['Alpha', 'AA', ['1.1.1.1']]]);
		$this->generateWithoutWarnings();
		$this->assertFileExists("{$this->output}/pfblockerng_Africa.php");
		$this->assertFileExists("{$this->output}/pfblockerng_reputation.php");
		$africa = $this->page('Africa');
		$this->assertStringContainsString('"AA" => "Alpha AA (1)"', $africa);
		$this->assertStringContainsString('"AA" => "Alpha AA (1)"', (string) file_get_contents("{$this->output}/pfblockerng_reputation.php"));
	}

	public function testStateMatrixAndSpecialCountryOptionsThroughPackageInterface(): void
	{
		foreach ([
			'Africa' => 'Africa',
			'Antarctica' => 'Antarctica',
			'Asia' => 'Asia',
			'Europe' => 'Europe',
			'North America' => 'North_America',
			'Oceania' => 'Oceania',
			'South America' => 'South_America',
			'Proxy and Satellite' => 'Proxy_and_Satellite',
			'Top Spammers' => 'Top_Spammers',
		] as $continent => $slug) {
			$this->writeContinent($continent, $slug, '4', []);
			$this->writeContinent($continent, $slug, '6', []);
		}

		$this->generateWithoutWarnings();
		$emptyAfrica = $this->page('Africa');
		$this->assertCountVars($emptyAfrica, 0, 0);
		$this->assertStringNotContainsString('Alpha AA', $emptyAfrica);

		// Africa v4-only; Asia v6-only; Antarctica both; Europe neither.
		$this->writeContinent('Africa', 'Africa', '4', [
			['Zulu', 'ZZ', ['1.1.1.1']],
			['Alpha', 'AA', ['1.1.1.2']],
		]);
		$this->writeContinent('Asia', 'Asia', '6', [
			['Asia', 'AS', ['2001:db8::1']],
		]);
		$this->writeContinent('Antarctica', 'Antarctica', '4', [
			['Antarctica', 'AQ', ['2.2.2.2']],
		]);
		$this->writeContinent('Antarctica', 'Antarctica', '6', [
			['Antarctica', 'AQ', ['2001:db8::2']],
		]);
		$this->writeContinent('South America', 'South_America', '4', [
			['Represented', 'US_rep', ['3.3.3.3']],
		]);
		$this->writeContinent('Proxy and Satellite', 'Proxy_and_Satellite', '4', [
			['Proxy', 'A1', ['4.4.4.4']],
			['Satellite', 'A2', ['5.5.5.5']],
		]);
		$this->writeContinent('Top Spammers', 'Top_Spammers', '4', [
			['Top', 'Top', []],
		]);

		$this->generateWithoutWarnings();

		$this->assertCountVars($this->page('Africa'), 2, 0);
		$this->assertStringContainsString('"AA" => "Alpha AA (1)"', $this->page('Africa'));
		$this->assertStringContainsString('"ZZ" => "Zulu ZZ (1)"', $this->page('Africa'));

		$this->assertCountVars($this->page('Asia'), 0, 1);
		$this->assertStringContainsString('"AS" => "Asia AS (1)"', $this->page('Asia'));

		$this->assertCountVars($this->page('Antarctica'), 1, 1);
		$this->assertStringContainsString('"AQ" => "Antarctica AQ (1)"', $this->page('Antarctica'));

		$this->assertCountVars($this->page('Europe'), 0, 0);

		$this->assertCountVars($this->page('South_America'), 1, 0);
		$this->assertStringContainsString('"US_rep" => "Represented US_rep (1)"', $this->page('South_America'));

		$proxy = $this->page('Proxy_and_Satellite');
		$this->assertCountVars($proxy, 2, 0);
		$this->assertStringContainsString('"A1" => "Proxy A1 (1)"', $proxy);
		$this->assertStringContainsString('"A2" => "Satellite A2 (1)"', $proxy);

		$top = $this->page('Top_Spammers');
		$this->assertCountVars($top, 1, 0);
		$this->assertStringContainsString('"Top" => "Top Top (0)"', $top);

		$reputation = (string) file_get_contents("{$this->output}/pfblockerng_reputation.php");
		$alpha = strpos($reputation, '"AA" => "Alpha AA (1)"');
		$zulu = strpos($reputation, '"ZZ" => "Zulu ZZ (1)"');
		$this->assertIsInt($alpha);
		$this->assertIsInt($zulu);
		$this->assertLessThan($zulu, $alpha);
		$this->assertStringNotContainsString('"US_rep" =>', $reputation);
	}

	/**
	 * install.inc performs destructive migrations/config writes and cannot be
	 * included off-appliance; pin its two executable generator dispatches without
	 * source comments, then verify the generated page emits the shared helper call.
	 * Comments/docblocks cannot define this dispatch boundary.
	 */
	public function testInstallerDispatchesCountryAndReputationGenerators(): void
	{
		$countries = strpos(self::$installSource, 'if (pfblockerng_get_countries())');
		$reputation = strpos(self::$installSource, 'if (pfb_build_reputation_tab())');
		$this->assertNotFalse($countries, 'install.inc must dispatch country-page generation');
		$this->assertNotFalse($reputation, 'install.inc must dispatch reputation-page generation');
		$this->assertLessThan($reputation, $countries);

		foreach ([
			'Africa' => 'Africa',
			'Antarctica' => 'Antarctica',
			'Asia' => 'Asia',
			'Europe' => 'Europe',
			'North America' => 'North_America',
			'Oceania' => 'Oceania',
			'South America' => 'South_America',
			'Proxy and Satellite' => 'Proxy_and_Satellite',
			'Top Spammers' => 'Top_Spammers',
		] as $continent => $slug) {
			$this->writeContinent($continent, $slug, '4', []);
			$this->writeContinent($continent, $slug, '6', []);
		}
		$this->generateWithoutWarnings();
		$this->assertStringContainsString('pfb_geoip_doc_link()', $this->page('Africa'));
	}

	public function testInstallerReportsBothGeneratorFailures(): void
	{
		$this->assertMatchesRegularExpression(
			'/if\s*\(pfblockerng_get_countries\(\)\)\s*\{\s*update_status\(" done\."\);\s*'
			. '\}\s*else\s*\{\s*update_status\(" failed\."\);\s*\}/',
			self::$installSource
		);
		$this->assertMatchesRegularExpression(
			'/if\s*\(pfb_build_reputation_tab\(\)\)\s*\{\s*update_status\(" done\."\);\s*'
			. '\}\s*else\s*\{\s*update_status\(" failed\."\);\s*\}/',
			self::$installSource
		);
	}

	private function generateWithoutWarnings(): void
	{
		$warnings = [];
		set_error_handler(static function (int $severity, string $message) use (&$warnings): bool {
			$warnings[] = "{$severity}: {$message}";
			return TRUE;
		});
		try {
			pfblockerng_get_countries($this->output);
		} finally {
			restore_error_handler();
		}
		$this->assertSame([], $warnings, implode('; ', $warnings));
	}

	private function page(string $slug): string
	{
		$page = "{$this->output}/pfblockerng_{$slug}.php";
		$this->assertFileExists($page);
		return (string) file_get_contents($page);
	}

	private function assertCountVars(string $page, int $v4, int $v6): void
	{
		$this->assertMatchesRegularExpression('/\\$options_countries4_cnt\\s*=\\s*"' . $v4 . '";/', $page);
		$this->assertMatchesRegularExpression('/\\$options_countries6_cnt\\s*=\\s*"' . $v6 . '";/', $page);
	}

	/**
	 * @param list<array{0:string,1:string,2:list<string>}> $countries
	 */
	private function writeContinent(string $continent, string $slug, string $type, array $countries): void
	{
		$filename = $continent === 'Top Spammers' ? "{$slug}_v{$type}.info" : "{$slug}_v{$type}.txt";
		$lines = ["# Continent IPv{$type}: {$continent}", "# Continent en: {$slug}"];
		foreach ($countries as [$country, $iso, $addresses]) {
			@touch("{$this->ccdir}/{$iso}_v{$type}.txt");
			$lines[] = "# Country: {$country}";
			$lines[] = "# ISO Code: {$iso}";
			$lines[] = $addresses === [] ? '# Total Networks: NA' : '# Total Networks: ' . count($addresses);
			array_push($lines, ...$addresses);
		}
		file_put_contents("{$this->ccdir}/{$filename}", implode("\n", $lines) . "\n");
	}

	private function removeTree(string $path): void
	{
		if (!is_dir($path)) {
			return;
		}
		foreach (scandir($path) ?: [] as $entry) {
			if ($entry === '.' || $entry === '..') {
				continue;
			}
			$child = "{$path}/{$entry}";
			is_dir($child) ? $this->removeTree($child) : @unlink($child);
		}
		@rmdir($path);
	}
}
