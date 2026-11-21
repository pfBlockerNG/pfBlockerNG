<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * The ASN table corpus (#4034 slice 5c) driven against today's shell: every scenario under tests/geoip/fixtures/asn runs
 * through the real `pfblockerng.sh asn_table`, which turns IPinfo's asn.csv into pfblockerng_asn.txt (the AS choices of
 * the IP page's ASN field). The same files run against go/pfb_core/geoip (asn_corpus_test.go there); a case that passes
 * here and fails there, or the reverse, is a divergence.
 *
 * A scenario:
 *   csv     asn.csv: a string, {"b64": bytes}, {"prefix", "repeat", "times", "suffix"} for a long line, null when there
 *           is none, or {"dir": true} for a folder of that name.
 *   expect  table (pfblockerng_asn.txt afterwards, as content; it holds "AS0 [ previous ]\n" before the run) and log
 *           (what the run appends to the Extras log, its time reading "{now}").
 *
 * The functions run under LC_ALL=C: the corpus pins the byte-wise reading of cut and sort, which is FreeBSD's as well
 * as GNU's in that locale.
 */
final class GeoipAsnTableCorpusTest extends TestCase
{
	private string $root = '';

	public static function corpus(): array
	{
		$cases = [];
		foreach (glob(__DIR__ . '/../geoip/fixtures/asn/*.json') ?: [] as $file) {
			$cases[basename($file, '.json')] = [$file];
		}
		return $cases;
	}

	protected function setUp(): void
	{
		$base = sys_get_temp_dir() . '/pfb_asn_corpus_' . getmypid() . '_' . bin2hex(random_bytes(4));
		$this->assertTrue(mkdir($base, 0700, TRUE));
		$this->root = (string) realpath($base);
	}

	protected function tearDown(): void
	{
		exec('rm -rf ' . escapeshellarg($this->root));
	}

	/** @param array<string,mixed>|string $content */
	private static function bytes(array|string $content): string
	{
		if (is_string($content)) {
			return $content;
		}
		return isset($content['b64']) ? (string) base64_decode($content['b64'], TRUE)
			: ($content['prefix'] ?? '') . str_repeat($content['repeat'], $content['times']) . ($content['suffix'] ?? '');
	}

	#[DataProvider('corpus')]
	public function testScenario(string $file): void
	{
		$case = json_decode((string) file_get_contents($file), TRUE, 512, JSON_THROW_ON_ERROR);
		$csv = "{$this->root}/asn.csv";
		$table = "{$this->root}/pfblockerng_asn.txt";
		$log = "{$this->root}/extras.log";
		file_put_contents($table, "AS0 [ previous ]\n");
		if (is_array($case['csv']) && !empty($case['csv']['dir'])) {
			mkdir($csv);
		} elseif ($case['csv'] !== NULL) {
			file_put_contents($csv, self::bytes($case['csv']));
		}

		$script = 'PFB_SOURCED=1; . "$1"; pathasncsv="$2"; pathasntable="$3"; extraslog="$4"; now="{now}"; asn_table';
		$sh = dirname(__DIR__, 2) . '/src/usr/local/pkg/pfblockerng/pfblockerng.sh';
		$proc = proc_open(['/usr/bin/env', '-i', 'PATH=/usr/bin:/bin', 'LC_ALL=C', 'sh', '-c', $script, 'sh', $sh, $csv, $table, $log],
			[1 => ['file', '/dev/null', 'w'], 2 => ['pipe', 'w']], $pipes);
		$this->assertIsResource($proc);
		$stderr = stream_get_contents($pipes[2]);
		fclose($pipes[2]);
		$this->assertSame(0, proc_close($proc), "asn_table failed: {$stderr}");

		$this->assertSame(self::bytes($case['expect']['table']), (string) file_get_contents($table), 'pfblockerng_asn.txt');
		$this->assertSame($case['expect']['log'], is_file($log) ? (string) file_get_contents($log) : '', 'the Extras log');
	}
}
