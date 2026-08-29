<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;

/**
 * Byte oracle captured by executing the pre-move functions from 4b5ef5a5.
 *
 * It intentionally does not use the frozen missing-symbol test: the oracle compares
 * real package output with the pre-move country files, every continent/special page,
 * and both empty/populated Reputation outputs.
 */
final class GeoipPreMoveGoldenOracleTest extends TestCase
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
		$this->tmp = sys_get_temp_dir() . '/pfb_geoip_golden_' . getmypid() . '_' . uniqid();
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
		]) : [];
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

	public function testPackageBytesMatchPreMoveGolden(): void
	{
		$golden = json_decode(
			(string) file_get_contents(__DIR__ . '/fixtures/geoip_pre_move_golden.json'),
			TRUE,
			512,
			JSON_THROW_ON_ERROR
		);
		$this->assertSame('4b5ef5a5', $golden['captured_from']);
		$this->seed();
		$this->generateWithoutWarnings();

		$this->assertSame($golden['country_files'], $this->hashTree($this->ccdir));
		$this->assertSame(
			$golden['continent_pages'],
			$this->hashFiles($this->output, array_keys($golden['continent_pages']))
		);

		pfb_build_reputation_tab('', $this->output);
		$this->assertSame(
			$golden['reputation_empty'],
			hash_file('sha256', "{$this->output}/pfblockerng_reputation.php")
		);

		$et = "	\"ZZ\" => \"Zulu ZZ (1)\",\n		\"AA\" => \"Alpha AA (1)\"\n	";
		pfb_build_reputation_tab($et, $this->output);
		$this->assertSame(
			$golden['reputation_populated'],
			hash_file('sha256', "{$this->output}/pfblockerng_reputation.php")
		);
	}

	public function testPopulatedReputationPreservesLiteralTabMarkerInCountryOptions(): void
	{
		$this->seed();
		$hostile = "\t\"__PFB_REPUTATION_TAB_ONLY__\" => \"Hostile (1)\"\n\t";

		pfb_build_reputation_tab($hostile, $this->output);

		$page = (string) file_get_contents("{$this->output}/pfblockerng_reputation.php");
		$this->assertStringContainsString($hostile, $page);
	}

	public function testUnreadableContinentInputUsesSafeContinuation(): void
	{
		$this->seed();
		$bad = "{$this->ccdir}/Africa_v4.txt";
		unlink($bad);
		mkdir($bad, 0777, TRUE);

		$this->generateExpectingDirectoryReadFailure();
		$this->assertFileExists("{$this->output}/pfblockerng_Antarctica.php");
		$this->assertFileExists("{$this->output}/pfblockerng_Africa.php");
		$africa = (string) file_get_contents("{$this->output}/pfblockerng_Africa.php");
		$this->assertMatchesRegularExpression('/\\$options_countries4_cnt\\s*=\\s*"0";/', $africa);
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

	private function generateExpectingDirectoryReadFailure(): void
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
		$this->assertNotEmpty($warnings);
		$this->assertStringContainsString('Is a directory', implode('; ', $warnings));
	}

	private function seed(): void
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
	}

	/** @param list<array{0:string,1:string,2:list<string>}> $countries */
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

	/** @return array<string,string> */
	private function hashTree(string $dir): array
	{
		$hashes = [];
		foreach (glob("{$dir}/*_v*.txt") ?: [] as $file) {
			$hashes[basename($file)] = hash_file('sha256', $file);
		}
		ksort($hashes);
		return $hashes;
	}

	/** @param list<string> $names @return array<string,string> */
	private function hashFiles(string $dir, array $names): array
	{
		$hashes = [];
		foreach ($names as $name) {
			$hashes[$name] = hash_file('sha256', "{$dir}/{$name}");
		}
		return $hashes;
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
