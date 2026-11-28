<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * Issue #4036 slice 7a: freezes what today's manifest writer, pfb_unbound_python_sources(), makes of a feed's staged NDJSON
 * rows as the parity fixture tests/core/fixtures/dnsbl_resources_parity.json; go/pfb_core/dnsbl passes the same file. A case's
 * answer is the manifest's feed rows in order, each with the lines of its .raw file, and the DNSBL widget's count per group
 * (Core's alone since #3977 removed the PHP counter, so this test compares the feed rows only). A
 * writer that publishes nothing answers {"error": ...}. Today's PHP gives old_expect where a case has one (a departure Core
 * makes on purpose), else expect. A staged line is a string, or {"b64": bytes}; "top1m": "missing" turns TOP1M on without
 * its source file.
 */
#[CoversFunction('pfb_unbound_python_sources')]
#[CoversFunction('pfb_dnsbl_ndjson_parse_row')]
final class DnsblResourcesParityTest extends TestCase
{
	private const FIXTURE = __DIR__ . '/../core/fixtures/dnsbl_resources_parity.json';

	private string $tmp;
	private bool $hadPfb;
	private array $originalPfb;

	protected function setUp(): void
	{
		$this->hadPfb = array_key_exists('pfb', $GLOBALS);
		$this->originalPfb = $GLOBALS['pfb'] ?? [];
		$this->tmp = sys_get_temp_dir() . '/pfb_dnsbl_parity_' . uniqid('', TRUE);
		mkdir("{$this->tmp}/dnsbl", 0777, TRUE);
		mkdir("{$this->tmp}/db", 0777, TRUE);
		$GLOBALS['pfb'] = array_merge($GLOBALS['pfb'] ?? [], [
			'log'                => "{$this->tmp}/pfblockerng.log",
			'errlog'             => "{$this->tmp}/error.log",
			'unbound_py_rawdir'  => "{$this->tmp}/pfb_py_raw",
			'dnsdir'             => "{$this->tmp}/dnsbl",
			'unbound_py_sources' => "{$this->tmp}/pfb_py_sources.json",
			'unbound_py_top1m'   => "{$this->tmp}/pfb_py_top1m.txt",
			'dbdir'              => "{$this->tmp}/db",
			'dnsbl_top1m'        => PfbToggle::Off,
			'dnsbl_tld_wildcard' => '',
			'dnsblconfig'        => ['tld_wildcard_blacklist' => '', 'tld_wildcard_exclusion' => ''],
		]);
	}

	protected function tearDown(): void
	{
		if ($this->hadPfb) {
			$GLOBALS['pfb'] = $this->originalPfb;
		} else {
			unset($GLOBALS['pfb']);
		}
		rmdir_recursive($this->tmp);
	}

	public static function cases(): array
	{
		$doc = json_decode((string) file_get_contents(self::FIXTURE), TRUE, 512, JSON_THROW_ON_ERROR);
		$out = [];
		foreach ($doc['cases'] as $case) {
			$out[$case['id']] = [$case];
		}
		return $out;
	}

	public function testTheFixtureIsWellFormed(): void
	{
		$doc = json_decode((string) file_get_contents(self::FIXTURE), TRUE, 512, JSON_THROW_ON_ERROR);
		$this->assertSame(1, $doc['schema']);
		$ids = array_column($doc['cases'], 'id');
		$this->assertSame(array_values(array_unique($ids)), $ids, 'a case id appears once');
		foreach ($doc['cases'] as $case) {
			$this->assertSame([], array_diff(array_keys($case), ['id', 'description', 'feeds', 'top1m', 'expect', 'old_expect', 'refused', 'invalid', 'dropped']),
				"{$case['id']}: only known keys");
		}
	}

	#[DataProvider('cases')]
	public function testTodaysWriterGivesTheFixturesAnswer(array $case): void
	{
		$feeds = [];
		foreach ($case['feeds'] as $feed) {
			$staged = implode('', array_map(static fn(string|array $line): string => (is_array($line) ? base64_decode($line['b64'], TRUE) : $line) . "\n", $feed['staged']));
			file_put_contents("{$this->tmp}/dnsbl/{$feed['header']}.txt", $staged);
			$feeds[] = array_intersect_key($feed, array_flip(['header', 'group', 'log', 'provenance', 'mode', 'top1m']));
		}

		if (($case['top1m'] ?? NULL) === 'missing') {
			$GLOBALS['pfb']['dnsbl_top1m'] = PfbToggle::On;
		}
		$want = $case['old_expect'] ?? $case['expect'];

		$manifest = pfb_unbound_python_sources($feeds);

		if (isset($want['error'])) {
			$this->assertFalse($manifest, "{$case['id']}: the writer refuses to publish");
			return;
		}
		$this->assertIsArray($manifest, "{$case['id']}: the writer published");
		$answer = ['feeds' => []];
		foreach ($manifest['feeds'] as $row) {
			$raw = (string) file_get_contents(dirname($GLOBALS['pfb']['unbound_py_sources']) . "/{$row['raw']}");
			$answer['feeds'][] = [
				'feed'       => $row['feed'],
				'group'      => $row['group'],
				'logFlag'    => $row['log_flag'],
				'provenance' => $row['provenance'],
				'mode'       => $row['mode'] ?? 'deny',
				'top1m'      => $row['top1m'] ?? FALSE,
				'rows'       => $raw === '' ? [] : explode("\n", substr($raw, 0, -1)),
			];
		}
		$this->assertSame(['feeds' => $want['feeds']], $answer, "{$case['id']}: today's manifest feed rows and .raw lines");
	}
}
