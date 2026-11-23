<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * Issue #4038 sub-slice 9g: freezes today's SafeSearch stage as tests/core/fixtures/dnsbl_safesearch_parity.json;
 * go/pfb_core/dnsbl (SafeSearchTable) passes the same file. The stage is the block of the apply pass that reads the shipped
 * pfb_dnsbl.*.conf lists into $safesearch_hosts (pfblockerng_apply.inc, from "Loading DNSBL SafeSearch" to the CSV write),
 * run verbatim on the case's files, followed by pfb_ss_csv() with the case's fixture resolver: the host's resolver is never
 * asked. A case's answer is the CSV text the decider would load. A file is the case's text, "shipped" for the package's own
 * list, or absent for a missing file. Today's PHP gives old_expect where a case has one (a departure Core makes on purpose:
 * it leaves out a row of the wrong shape, and lists its host in expect.refused), else expect.
 */
#[CoversFunction('pfb_ss_csv')]
#[CoversFunction('pfb_ss_csv_rows')]
final class DnsblSafeSearchParityTest extends TestCase
{
	private const FIXTURE = __DIR__ . '/../core/fixtures/dnsbl_safesearch_parity.json';
	private const APPLY = __DIR__ . '/../../src/usr/local/pkg/pfblockerng/pfblockerng_apply.inc';
	private const SHIPPED = __DIR__ . '/../../src/usr/local/pkg/pfblockerng';
	private const FILES = ['safesearch', 'youtube_restrict', 'youtube_restrictmoderate', 'doh'];

	private string $tmp;
	private bool $hadPfb;
	private array $originalPfb;

	protected function setUp(): void
	{
		$this->hadPfb = array_key_exists('pfb', $GLOBALS);
		$this->originalPfb = $GLOBALS['pfb'] ?? [];
		$this->tmp = sys_get_temp_dir() . '/pfb_ss_parity_' . uniqid('', TRUE);
		mkdir("{$this->tmp}/pkg", 0777, TRUE);
		mkdir("{$this->tmp}/dnsbl", 0777, TRUE);
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

	/** The SafeSearch block of today's apply pass, exactly as it stands in the file. */
	private static function block(): string
	{
		$src = (string) file_get_contents(self::APPLY);
		$from = strpos($src, "\t\t\t// SafeSearch\n\t\t\tpfb_logger(\"\\n Loading DNSBL SafeSearch...\", 1);");
		$to = strpos($src, "\t\t\t// Create the decider's CSV list of SafeSearch hosts");
		self::assertIsInt($from, 'the SafeSearch block starts where the test expects it');
		self::assertIsInt($to, 'the SafeSearch block ends where the test expects it');
		self::assertSame(1, substr_count($src, 'Loading DNSBL SafeSearch...'), 'one SafeSearch block');
		return substr($src, $from, $to - $from);
	}

	public function testTheFixtureIsWellFormed(): void
	{
		$doc = json_decode((string) file_get_contents(self::FIXTURE), TRUE, 512, JSON_THROW_ON_ERROR);
		$this->assertSame(1, $doc['schema']);
		$ids = array_column($doc['cases'], 'id');
		$this->assertSame(array_values(array_unique($ids)), $ids, 'a case id appears once');
		foreach ($doc['cases'] as $case) {
			$this->assertSame([], array_diff(array_keys($case), ['id', 'description', 'policy', 'files', 'resolver', 'expect', 'old_expect']),
				"{$case['id']}: only known keys");
			$this->assertSame([], array_diff(array_keys($case['files']), self::FILES), "{$case['id']}: only known files");
			$this->assertNotSame($case['old_expect'] ?? NULL, $case['expect'], "{$case['id']}: old_expect is a departure");
		}
	}

	#[DataProvider('cases')]
	public function testTodaysSafeSearchStageGivesTheFixturesAnswer(array $case): void
	{
		$pfb = [
			'log'                 => "{$this->tmp}/pfblockerng.log",
			'errlog'              => "{$this->tmp}/error.log",
			'dnsbldir'            => "{$this->tmp}/dnsbl",
			'safesearch_enable'   => $case['policy']['safeSearch'] ? 'Enable' : 'Disable',
			'safesearch_youtube'  => $case['policy']['safeSearchYoutube'],
			'safesearch_doh'      => $case['policy']['safeSearchDoh'] ? 'Enable' : 'Disable',
			'safesearch_doh_list' => $case['policy']['safeSearchDohList'],
		];
		foreach (self::FILES as $name) {
			$path = "{$this->tmp}/pkg/pfb_dnsbl.{$name}.conf";
			$pfb["dnsbl_{$name}"] = $path;
			$text = $case['files'][$name] ?? NULL;
			if ($text === 'shipped') {
				copy(self::SHIPPED . "/pfb_dnsbl.{$name}.conf", $path);
			} elseif ($text !== NULL) {
				file_put_contents($path, $text);
			}
		}
		$GLOBALS['pfb'] = array_merge($GLOBALS['pfb'] ?? [], $pfb);
		$resolver = static fn(string $target): array => $case['resolver'][$target] ?? ['', ''];

		// file() of a missing list warns and reads nothing, as on the box; only that warning is taken.
		set_error_handler(static fn(int $no, string $msg): bool => $no === E_WARNING && str_contains($msg, 'Failed to open stream'));
		try {
			$csv = (static function () use ($resolver): string {
				global $pfb;
				eval(self::block());
				return pfb_ss_csv($safesearch_hosts, $resolver);
			})();
		} finally {
			restore_error_handler();
		}

		$want = $case['old_expect'] ?? $case['expect'];
		$this->assertSame($want['csv'], $csv, "{$case['id']}: today's SafeSearch CSV");
	}
}
