<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;

/**
 * Real package-interface proof for the GeoIP page generators moved out of the
 * web entry point (issue #1576).  The optional output root keeps all generated
 * pages in a disposable filesystem while country source files stay in ccdir.
 */
final class GeoipPackageGenerationTest extends TestCase
{
	private string $tmp;
	private string $ccdir;
	private string $output;
	private mixed $originalPfb;
	private bool $hadPfb = FALSE;

	protected function setUp(): void
	{
		$this->hadPfb = array_key_exists('pfb', $GLOBALS);
		$this->originalPfb = $GLOBALS['pfb'] ?? NULL;

		$this->tmp = sys_get_temp_dir() . '/pfb_geoip_package_' . getmypid();
		$this->ccdir = "{$this->tmp}/cc";
		$this->output = "{$this->tmp}/www";
		@mkdir($this->ccdir, 0777, TRUE);
		@mkdir($this->output, 0777, TRUE);

		$GLOBALS['pfb']['ccdir'] = $this->ccdir;
		$GLOBALS['pfb']['ccdir_tmp'] = "{$this->tmp}/cc-tmp";
		$GLOBALS['pfb']['log'] = "{$this->tmp}/pfblockerng.log";
		$GLOBALS['pfb']['errlog'] = "{$this->tmp}/error.log";
		$GLOBALS['pfb']['extraslog'] = "{$this->tmp}/extras.log";
		$GLOBALS['pfb']['extras_update'] = FALSE;
		$GLOBALS['pfb']['complete'] = FALSE;
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

	public function testPackageUmbrellaGeneratesContinentAndReputationPagesAcrossStateTransitions(): void
	{
		$this->writeFixtures();

		$this->assertNoPhpWarning(fn(): mixed => pfblockerng_get_countries($this->output));

		$continents = [
			'Top_Spammers',
			'Africa',
			'Antarctica',
			'Asia',
			'Europe',
			'North_America',
			'Oceania',
			'South_America',
			'Proxy_and_Satellite',
		];
		foreach ($continents as $continent) {
			$page = "{$this->output}/pfblockerng_{$continent}.php";
			$this->assertFileExists($page, "generated {$continent} page");
			$this->assertSame(0, $this->phpLint($page), "generated {$continent} page must pass php -l");
		}

		$africa = (string) file_get_contents("{$this->output}/pfblockerng_Africa.php");
		$this->assertStringContainsString("\$options_countries4_cnt\t= \"3\";", $africa);
		$this->assertStringContainsString("\$options_countries6_cnt\t= \"1\";", $africa);
		$this->assertStringContainsString('"AA" => "Alpha AA (2)"', $africa);
		$this->assertStringContainsString('"BB" => "Beta BB (1)"', $africa);
		$this->assertFileExists("{$this->ccdir}/AA_v4.txt");
		$this->assertFileExists("{$this->ccdir}/BB_v4.txt");
		$this->assertFileExists("{$this->ccdir}/US_rep_v4.txt", 'represented ISO output');
		$this->assertFileExists("{$this->ccdir}/Top_v4.txt", 'Top Spammer placeholder output');

		$reputation = "{$this->output}/pfblockerng_reputation.php";
		$this->assertFileExists($reputation);
		$firstReputation = (string) file_get_contents($reputation);
		$this->assertStringContainsString("'ccexclude'", $firstReputation);
		$this->assertSame(0, $this->phpLint($reputation));

		// Populate -> empty: headers remain valid continent inputs, so the page
		// is regenerated with zero options instead of retaining stale output.
		$this->writeContinent('Africa', 'Africa', '4', []);
		$this->writeContinent('Africa', 'Africa', '6', []);
		$this->assertNoPhpWarning(fn(): mixed => pfblockerng_get_countries($this->output));
		$emptyAfrica = (string) file_get_contents("{$this->output}/pfblockerng_Africa.php");
		$this->assertMatchesRegularExpression('/\$options_countries4\s*=\s*array\(\);/', $emptyAfrica);
		$this->assertMatchesRegularExpression('/\$options_countries6\s*=\s*array\(\);/', $emptyAfrica);
		$this->assertMatchesRegularExpression('/\$options_countries4_cnt\s*=\s*"0";/', $emptyAfrica);
		$this->assertStringNotContainsString('Alpha AA', $emptyAfrica);
		$this->assertSame(0, $this->phpLint("{$this->output}/pfblockerng_Africa.php"));
		$emptyReputation = (string) file_get_contents($reputation);
		$this->assertStringNotContainsString('"AA" => "Alpha AA', $emptyReputation);
		$this->assertSame(0, $this->phpLint($reputation));

		// Direct package builder calls preserve the zero-arg/default form and are
		// deterministic for both empty and populated option strings.
		pfb_build_reputation_tab('', $this->output);
		$emptyDirect = (string) file_get_contents($reputation);
		pfb_build_reputation_tab('', $this->output);
		$this->assertSame($emptyDirect, (string) file_get_contents($reputation));
		pfb_build_reputation_tab("\t\"US\" => \"United States (1)\"\n\t", $this->output);
		$populatedDirect = (string) file_get_contents($reputation);
		$this->assertStringContainsString('"US" => "United States (1)"', $populatedDirect);
		$this->assertSame(0, $this->phpLint($reputation));
	}

	private function writeFixtures(): void
	{
		$this->writeContinent('Africa', 'Africa', '4', [
			['Alpha', 'AA', ['1.1.1.1', '1.1.1.2']],
			['Beta', 'BB', ['2.2.2.2']],
			['Represented', 'US_rep', ['3.3.3.3']],
		]);
		$this->writeContinent('Africa', 'Africa', '6', [
			['Alpha', 'AA', ['2001:db8::1']],
		]);
		$this->writeContinent('Antarctica', 'Antarctica', '4', [
			['Antarctica', 'AQ', ['4.4.4.4']],
		]);
		$this->writeContinent('Antarctica', 'Antarctica', '6', []);
		$this->writeContinent('Asia', 'Asia', '4', []);
		$this->writeContinent('Asia', 'Asia', '6', [
			['Asia', 'AS', ['2001:db8::2']],
		]);
		$this->writeContinent('Europe', 'Europe', '4', []);
		$this->writeContinent('Europe', 'Europe', '6', []);
		foreach (['North America', 'Oceania', 'South America', 'Proxy and Satellite'] as $continent) {
			$slug = str_replace(' ', '_', $continent);
			$this->writeContinent($continent, $slug, '4', [
				[$continent, 'ZZ', ['5.5.5.5']],
			]);
			$this->writeContinent($continent, $slug, '6', []);
		}
		$this->writeContinent('Top Spammers', 'Top_Spammers', '4', [
			['Top', 'Top', []],
		]);
		$this->writeContinent('Top Spammers', 'Top_Spammers', '6', [
			['Top', 'Top', []],
		]);
		foreach (['AA', 'BB', 'US_rep', 'AQ', 'AS', 'ZZ'] as $iso) {
			foreach (['4', '6'] as $type) {
				touch("{$this->ccdir}/{$iso}_v{$type}.txt");
			}
		}
	}

	/** @param list<array{0:string,1:string,2:list<string>}> $countries */
	private function writeContinent(string $continent, string $english, string $type, array $countries): void
	{
		$slug = str_replace(' ', '_', $continent);
		$filename = $continent === 'Top Spammers' ? "{$slug}_v{$type}.info" : "{$slug}_v{$type}.txt";
		$lines = ["# Continent IPv{$type}: {$continent}", "# Continent en: {$english}"];
		foreach ($countries as [$country, $iso, $addresses]) {
			$lines[] = "# Country: {$country}";
			$lines[] = "# ISO Code: {$iso}";
			$lines[] = $addresses === [] ? '# Total Networks: NA' : '# Total Networks: ' . count($addresses);
			array_push($lines, ...$addresses);
		}
		file_put_contents("{$this->ccdir}/{$filename}", implode("\n", $lines) . "\n");
	}

	private function assertNoPhpWarning(callable $operation): void
	{
		$warnings = [];
		set_error_handler(static function (int $severity, string $message) use (&$warnings): bool {
			$warnings[] = "{$severity}: {$message}";
			return TRUE;
		});
		try {
			$operation();
		} finally {
			restore_error_handler();
		}
		$this->assertSame([], $warnings, 'GeoIP generation emitted PHP warnings: ' . implode('; ', $warnings));
	}

	private function phpLint(string $file): int
	{
		$output = [];
		$status = 1;
		exec('php -l ' . escapeshellarg($file) . ' 2>&1', $output, $status);
		return $status;
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
