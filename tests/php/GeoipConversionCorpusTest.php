<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * The GeoIP conversion corpus (#4034) driven against today's PHP: every scenario under tests/geoip/fixtures/parity runs
 * through the real pfblockerng_uc_countries(), as the dcc verb calls it (with a page folder, so pfblockerng_get_countries()
 * splits the per-country lists out of the continent files inside the staged generation). The same files run against
 * go/pfb_core/geoip (convert_corpus_test.go there); a case that passes here and fails there, or the reverse, is a
 * divergence.
 *
 * A scenario's folders, under one temporary root:
 *   share/   the MaxMind CSVs ($pfb['geoipshare']); "share" names its files, "share_mtime" the Locations file's mtime.
 *   cc/      the live country folder ($pfb['ccdir']); db/geoip.txt is $pfb['geoip_isos']; log/ is $pfb['logdir'].
 *   "seed" writes files under the root before the run: a previous generation.
 *   A file's content is a string, {"b64": bytes}, or {"prefix", "repeat", "times", "suffix"} for a long line.
 *
 * Logical outcome ("expect"; "old_expect" where Core deliberately differs, an owner decision):
 *   ok      pfblockerng_uc_countries()'s return.
 *   files   {"<path>": content ({"b64": bytes} when it is not UTF-8), or null when absent}: only the files named.
 *   tree    sha256 over every file under cc/, db/ and log/ and any other folder the run leaves at the root (sorted
 *           "<path>\0<sha256 of content>\n" lines), so a stray file or a staged folder left behind changes it. The pages
 *           (www/) are slice 8's (#4037) and are not part of it, nor is Go's catalog file (cc/.geo_catalog).
 *   catalog the geo-catalog (#4034 slice 5b), or null when there is none: what the continent pages and the Reputation
 *           page in www/ hold, read back from them here; Go's cc/.geo_catalog there. A "page" row per continent page
 *           ({"kind", "page": $continent_en, "continent": $continent}), a "country" row per option of its lists
 *           ({"kind", "page", "family": 4|6, "position" from 1, "iso", "country", "networks"}), and a "reputation"
 *           row per option of the Reputation tab ({"kind", "position", "iso", "country", "networks"}). Spelled as the
 *           sha256 of the rows' lines
 *           "<kind>\0<page>\0<continent>\0<family>\0<position>\0<iso>\0<country>\0<networks>\n" (a field a row
 *           lacks is empty), sorted in byte order, so that it does not depend on either side's JSON encoder.
 * A continent file's "# Generated from MaxMind Inc. on: <local time>" line reads "{now}" in both.
 */
#[CoversFunction('pfblockerng_get_countries')]
final class GeoipConversionCorpusTest extends TestCase
{
	private string $root = '';
	/** @var array<string,mixed> */
	private array $savedPfb = [];
	private bool $hadPfb = FALSE;

	public static function corpus(): array
	{
		$cases = [];
		foreach (glob(__DIR__ . '/../geoip/fixtures/parity/*.json') ?: [] as $file) {
			$cases[basename($file, '.json')] = [$file];
		}
		return $cases;
	}

	protected function setUp(): void
	{
		self::loadConversion();
		$base = sys_get_temp_dir() . '/pfb_geoip_corpus_' . getmypid() . '_' . bin2hex(random_bytes(4));
		// www/ is the page folder (/usr/local/www/pfblockerng), which always exists on an appliance.
		foreach (['share', 'cc', 'db', 'log', 'tools', 'www'] as $d) {
			$this->assertTrue(mkdir("{$base}/{$d}", 0700, TRUE));
		}
		$this->root = (string) realpath($base);
		$this->hadPfb = array_key_exists('pfb', $GLOBALS);
		$this->savedPfb = $GLOBALS['pfb'] ?? [];
		$GLOBALS['pfb'] = array_merge($this->savedPfb, [
			'geoipshare' => "{$this->root}/share",
			'ccdir' => "{$this->root}/cc",
			'ccdir_tmp' => "{$this->root}/tools/cc_tmp",
			'geoip_isos' => "{$this->root}/db/geoip.txt",
			'dbdir' => "{$this->root}/db",
			'logdir' => "{$this->root}/log",
			'log' => "{$this->root}/tools/pfblockerng.log",
			'errlog' => "{$this->root}/tools/error.log",
			'extraslog' => "{$this->root}/tools/extras.log",
			'maxmind_locale' => 'en',
		]);
	}

	protected function tearDown(): void
	{
		if ($this->hadPfb) {
			$GLOBALS['pfb'] = $this->savedPfb;
		} else {
			unset($GLOBALS['pfb']);
		}
		if ($this->root !== '') {
			exec('rm -rf ' . escapeshellarg($this->root));
		}
	}

	#[DataProvider('corpus')]
	public function testCorpusScenarioMatchesPhp(string $file): void
	{
		$case = json_decode((string) file_get_contents($file), TRUE, 512, JSON_THROW_ON_ERROR);
		$this->assertSame(1, $case['schema'], 'corpus schema');
		$GLOBALS['pfb']['maxmind_locale'] = $case['locale'] ?? 'en';
		foreach ($case['share'] ?? [] as $name => $content) {
			$this->write("share/{$name}", $content);
		}
		$locations = "{$this->root}/share/GeoLite2-Country-Locations-{$GLOBALS['pfb']['maxmind_locale']}.csv";
		if (isset($case['share_mtime']) && is_file($locations)) {
			$this->assertTrue(touch($locations, (int) strtotime($case['share_mtime'])));
		}
		foreach ($case['seed'] ?? [] as $rel => $content) {
			$this->write($rel, $content);
		}
		$want = $case['old_expect'] ?? $case['expect'];

		// A hostile row has today's code read keys that are not there; on an appliance that is a logged warning and the
		// conversion goes on, so here too: the warnings are collected while it runs, not turned into a test failure.
		set_error_handler(static fn (): bool => TRUE, E_WARNING | E_NOTICE | E_DEPRECATED);
		try {
			$actual = ['ok' => pfblockerng_uc_countries("{$this->root}/www")];
		} finally {
			restore_error_handler();
		}
		clearstatcache();
		$actual['files'] = [];
		foreach (array_keys($want['files'] ?? []) as $rel) {
			$path = "{$this->root}/{$rel}";
			$actual['files'][$rel] = is_file($path) ? self::shown(self::normalize((string) file_get_contents($path))) : NULL;
		}
		$actual['tree'] = $this->tree();
		$rows = $this->catalog();
		$actual['catalog'] = $rows === NULL ? NULL : self::catalogDigest($rows);

		$want += ['files' => []];
		ksort($want);
		ksort($actual);
		$this->assertSame($want, $actual, basename($file) . ": {$case['description']}\ntree:\n" . $this->listing());

		// The pages themselves, byte for byte, as pfblockerng_get_countries() wrote them when the golden was recorded: the
		// template must not move while the code around it is cut apart (#4037).
		$pages = json_decode((string) file_get_contents(__DIR__ . '/../geoip/fixtures/parity_pages.json'), TRUE, 512,
			JSON_THROW_ON_ERROR);
		$this->assertSame($pages[basename($file, '.json')], $this->pages(), basename($file) . ': the pages written');
	}

	/** @return array<string,string> every page under www/, file name => sha256 of its bytes */
	private function pages(): array
	{
		$out = [];
		foreach (glob("{$this->root}/www/*") ?: [] as $page) {
			$out[basename($page)] = hash_file('sha256', $page);
		}
		ksort($out, SORT_STRING);
		return $out;
	}

	/** The country table Go embeds (go/pfb_core/geoip/countries.json) is pfblockerng_uc_countries()'s, in its order. */
	public function testGoCountryTableIsPhps(): void
	{
		$src = (string) file_get_contents(dirname(__DIR__, 2) . '/src/usr/local/www/pfblockerng/pfblockerng.php');
		$this->assertSame(1, preg_match('/\$pfb_geoip_all = array\(.*?\n\t\t\t\t\);/s', $src, $m));
		$pfb_geoip_all = [];
		eval($m[0]);
		$php = [];
		foreach ($pfb_geoip_all as $id => $c) {
			$php[] = [(string) $id, $c['iso'], $c['name'], $c['continent']];
		}
		$go = json_decode((string) file_get_contents(dirname(__DIR__, 2) . '/go/pfb_core/geoip/countries.json'), TRUE,
			512, JSON_THROW_ON_ERROR);
		$this->assertCount(250, $php);
		$this->assertSame($php, $go);
	}

	/**
	 * The PHP comparisons the conversion leans on, as go/pfb_core/geoip/testdata/php_semantics.json records them for the
	 * Go port: strnatcmp() (ksort(SORT_NATURAL) orders the countries with it), == between two CSV fields, and == 1.
	 */
	public function testPhpSemanticsTableIsPhps(): void
	{
		$table = json_decode((string) file_get_contents(dirname(__DIR__, 2) . '/go/pfb_core/geoip/testdata/php_semantics.json'),
			TRUE, 512, JSON_THROW_ON_ERROR);
		$this->assertNotEmpty($table['natcmp']);
		foreach ($table['natcmp'] as [$a, $b, $sign]) {
			$this->assertSame($sign, strnatcmp($a, $b) <=> 0, var_export([$a, $b], TRUE));
		}
		foreach ($table['equal'] as [$a, $b, $equal]) {
			$this->assertSame($equal, $a == $b, var_export([$a, $b], TRUE));
		}
		foreach ($table['is_one'] as [$s, $one]) {
			$this->assertSame($one, $s == 1, var_export($s, TRUE));
		}
	}

	/**
	 * What fgetcsv() reads from each input of go/pfb_core/geoip/testdata/fgetcsv.json, the table the Go CSV reader is
	 * held to (base64 throughout; a blank line's field is null).
	 */
	public function testFgetcsvTableIsPhps(): void
	{
		$table = json_decode((string) file_get_contents(dirname(__DIR__, 2) . '/go/pfb_core/geoip/testdata/fgetcsv.json'),
			TRUE, 512, JSON_THROW_ON_ERROR);
		$this->assertNotEmpty($table);
		foreach ($table as $case) {
			$h = fopen('php://memory', 'w+');
			$this->assertNotFalse($h);
			fwrite($h, (string) base64_decode($case['in'], TRUE));
			rewind($h);
			$records = [];
			while (($r = fgetcsv($h, NULL, ',', '"', '\\')) !== FALSE) {
				$records[] = array_map(static fn (?string $f): ?string => $f === NULL ? NULL : base64_encode($f), $r);
			}
			fclose($h);
			$this->assertSame($case['records'], $records, var_export(base64_decode($case['in'], TRUE), TRUE));
		}
	}

	/**
	 * The catalog the pages hold: each continent page's $continent, $continent_en and option lists, and the Reputation
	 * page's $options_ccexclude, as rows (see the class comment); NULL when www/ holds no page.
	 *
	 * @return list<array<string,mixed>>|null
	 */
	private function catalog(): ?array
	{
		$rows = [];
		foreach (glob("{$this->root}/www/pfblockerng_*.php") ?: [] as $page) {
			$src = (string) file_get_contents($page);
			if (basename($page) === 'pfblockerng_reputation.php') {
				$this->assertSame(1, preg_match('/^\$options_ccexclude\t= array\((.*?)\);$/ms', $src, $m), $page);
				foreach (self::options($m[1]) as $i => [$iso, $country, $networks]) {
					$rows[] = ['kind' => 'reputation', 'position' => $i + 1, 'iso' => $iso, 'country' => $country,
						'networks' => $networks];
				}
				continue;
			}
			$this->assertSame(1, preg_match('/^\$continent\t+= "(.*)";\t\/\/ Continent name \(Locale/m', $src, $c), $page);
			$this->assertSame(1, preg_match('/^\$continent_en\t+= "(.*)";\t\/\/ Continent name \(English/m', $src, $en), $page);
			$this->assertSame("pfblockerng_{$en[1]}.php", basename($page));
			$rows[] = ['kind' => 'page', 'page' => $en[1], 'continent' => $c[1]];
			foreach ([4, 6] as $family) {
				$this->assertSame(1, preg_match("/^\\\$options_countries{$family}\t+= array\((.*?)\);\$/ms", $src, $m), $page);
				foreach (self::options($m[1]) as $i => [$iso, $country, $networks]) {
					$rows[] = ['kind' => 'country', 'page' => $en[1], 'family' => $family, 'position' => $i + 1, 'iso' => $iso,
						'country' => $country, 'networks' => $networks];
				}
			}
		}
		return $rows === [] ? NULL : $rows;
	}

	/**
	 * The options of a generated array literal: '"<iso>" => "<country> <iso> (<networks>)"', in order.
	 *
	 * @return list<array{string, string, int}>
	 */
	private static function options(string $literal): array
	{
		preg_match_all('/"([^"]*)" => "([^"]*)"/', $literal, $m, PREG_SET_ORDER);
		$out = [];
		foreach ($m as [, $iso, $label]) {
			if (preg_match('/^(.*) ' . preg_quote($iso, '/') . ' \((\d+)\)$/s', $label, $l) !== 1) {
				throw new RuntimeException("an option label that is not \"<country> {$iso} (<n>)\": {$label}");
			}
			$out[] = [$iso, $l[1], (int) $l[2]];
		}
		return $out;
	}

	/** @param list<array<string,mixed>> $rows */
	private static function catalogDigest(array $rows): string
	{
		$lines = [];
		foreach ($rows as $row) {
			$fields = [];
			foreach (['kind', 'page', 'continent', 'family', 'position', 'iso', 'country', 'networks'] as $key) {
				$fields[] = (string) ($row[$key] ?? '');
			}
			$lines[] = implode("\0", $fields) . "\n";
		}
		sort($lines, SORT_STRING);
		return hash('sha256', implode('', $lines));
	}

	/** @param string|array<string,mixed> $content */
	private function write(string $rel, string|array $content): void
	{
		if (is_array($content)) {
			$content = isset($content['b64']) ? (string) base64_decode($content['b64'], TRUE)
				: ($content['prefix'] ?? '') . str_repeat($content['repeat'], $content['times']) . ($content['suffix'] ?? '');
		}
		$path = "{$this->root}/{$rel}";
		if (!is_dir(dirname($path))) {
			$this->assertTrue(mkdir(dirname($path), 0700, TRUE));
		}
		$this->assertNotFalse(file_put_contents($path, $content));
	}

	/** @return string|array{b64: string} a file's content as the corpus spells it: bytes that are not UTF-8 as base64 */
	private static function shown(string $content): string|array
	{
		return mb_check_encoding($content, 'UTF-8') ? $content : ['b64' => base64_encode($content)];
	}

	private static function normalize(string $content): string
	{
		return (string) preg_replace('/^# Generated from MaxMind Inc\. on: \d{4}-\d\d-\d\d \d\d:\d\d:\d\d$/m',
			'# Generated from MaxMind Inc. on: {now}', $content);
	}

	/** @return array<string,string> every file the tree digest covers, relative path => sha256 of its content */
	private function files(): array
	{
		$out = [];
		$it = new RecursiveIteratorIterator(new RecursiveDirectoryIterator($this->root, FilesystemIterator::SKIP_DOTS));
		foreach ($it as $info) {
			$rel = substr($info->getPathname(), strlen($this->root) + 1);
			$top = explode('/', $rel)[0];
			if (!$info->isFile() || in_array($top, ['share', 'tools'], TRUE) || str_starts_with($top, 'www')) {
				continue;
			}
			$out[$rel] = hash('sha256', self::normalize((string) file_get_contents($info->getPathname())));
		}
		ksort($out, SORT_STRING);
		return $out;
	}

	private function tree(): string
	{
		$lines = '';
		foreach ($this->files() as $rel => $sum) {
			$lines .= "{$rel}\0{$sum}\n";
		}
		return hash('sha256', $lines);
	}

	private function listing(): string
	{
		$out = '';
		foreach ($this->files() as $rel => $sum) {
			$out .= "{$sum}  {$rel}\n";
		}
		return $out;
	}

	private static function loadConversion(): void
	{
		if (function_exists('pfblockerng_uc_countries')) {
			return;
		}
		$source = (string) file_get_contents(dirname(__DIR__, 2) . '/src/usr/local/www/pfblockerng/pfblockerng.php');
		$start = strpos($source, "\nfunction pfblockerng_uc_countries(");
		// The function ends the file: it runs to the first "\n}\n" after its opening line.
		$end = $start === FALSE ? FALSE : strpos($source, "\n}\n", $start + 1);
		if ($start === FALSE || $end === FALSE) {
			throw new RuntimeException('pfblockerng_uc_countries() not found in pfblockerng.php');
		}
		eval(substr($source, $start + 1, $end - $start + 1));
	}
}
