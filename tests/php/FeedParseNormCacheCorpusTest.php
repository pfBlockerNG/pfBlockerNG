<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

// The data providers run before setUpBeforeClass().
require_once __DIR__ . '/FeedParseCorpusFile.php';

/**
 * The normalize cache parity corpus (issue #3976, go/pfb_core/feedparse/testdata/normcache.json, schema in that
 * directory's README.md): the storage half of pfb_feed_normalize(), replayed through the production function with the
 * converter off (interpreter ''), which is the path Core's feedparse.NormalizeFile takes. A case is a directory of files
 * before and the directory, the `changed` signal and the returned path after. The Go runner replays the same file.
 *
 * The ASCII inputs make the host's sed and the appliance's agree; the encoding rules themselves are normalize.json's.
 */
#[CoversFunction('pfb_feed_normalize')]
#[CoversFunction('pfb_hash_read')]
final class FeedParseNormCacheCorpusTest extends TestCase
{
	private const CORPUS = __DIR__ . '/../../go/pfb_core/feedparse/testdata/normcache.json';
	/** The files of a feed this corpus sets up and checks, by the suffix after "feed". */
	/** The smallest well-formed case: the loader tests break one thing at a time. */
	private const WELL = '{"id": "a", "description": "d", "setup": {"orig": "a.example\n"}, "expect": {"path": "norm", "changed": true, "normalized": true, "files": {"orig": "a.example\n", "norm": "a.example\n", "xxhash128": "00000000000000000000000000000000"}}}';
	private const FILES = ['orig' => '.orig', 'norm' => '.norm', 'xxhash128' => '.norm.src.xxhash128', 'md5' => '.norm.src.md5'];

	private string $dir;
	private string $logs;
	private mixed $savedPfb = NULL;

	protected function setUp(): void
	{
		$this->dir = sys_get_temp_dir() . '/pfb_fpnc_' . getmypid() . '_' . bin2hex(random_bytes(4));
		mkdir($this->dir, 0700, TRUE);
		$this->savedPfb = $GLOBALS['pfb'] ?? NULL;
		// The logs sit beside the case directory, which holds exactly the feed's files.
		$this->logs = sys_get_temp_dir() . '/pfb_fpnc_log_' . getmypid() . '_' . bin2hex(random_bytes(4));
		$GLOBALS['pfb'] = ['log' => $this->logs, 'errlog' => "{$this->logs}.err"];
	}

	protected function tearDown(): void
	{
		foreach (scandir($this->dir) ?: [] as $f) {
			if ($f !== '.' && $f !== '..') {
				@unlink("{$this->dir}/{$f}");
			}
		}
		@rmdir($this->dir);
		@unlink($this->logs);
		@unlink("{$this->logs}.err");
		$GLOBALS['pfb'] = $this->savedPfb;
	}

	/** @return array<string, array{array<string, mixed>}> */
	public static function cases(): array
	{
		$out = [];
		foreach (FeedParseCorpusFile::load(self::CORPUS, ['cases'])['cases'] as $case) {
			self::checkCase($case);
			$out[$case['id']] = [$case];
		}
		return $out;
	}

	/** @param array<string, mixed> $case */
	private static function checkCase(array $case): void
	{
		$w = "case {$case['id']}";
		FeedParseCorpusFile::keys($case, ['id', 'description', 'setup', 'expect'], $w);
		self::checkFiles($case['setup'], "{$w} setup");
		$e = $case['expect'];
		FeedParseCorpusFile::keys($e, ['path', 'changed', 'normalized', 'files'], "{$w} expect");
		if (!in_array($e['path'], ['norm', 'orig'], TRUE) || !is_bool($e['changed']) || !is_bool($e['normalized'])) {
			throw new RuntimeException("{$w} expect: path is norm or orig, changed and normalized are bools");
		}
		self::checkFiles($e['files'], "{$w} expect.files");
	}

	/** The files of a directory state: a subset of orig, norm (bytes: text or hex form) and the two sidecars (text). */
	private static function checkFiles(mixed $files, string $where): void
	{
		if (!is_array($files)) {
			throw new RuntimeException("{$where}: object expected");
		}
		$allowed = ['xxhash128', 'md5'];
		foreach (['orig', 'norm'] as $k) {
			array_push($allowed, $k, "{$k}_hex");
		}
		$unknown = array_diff(array_keys($files), $allowed);
		if ($unknown !== []) {
			throw new RuntimeException("{$where}: unknown keys " . implode(', ', $unknown));
		}
		foreach (['orig', 'norm'] as $k) {
			if (array_key_exists($k, $files) || array_key_exists("{$k}_hex", $files)) {
				FeedParseCorpusFile::bytes($files, $k, "{$where} {$k}");
			}
		}
		foreach (['xxhash128', 'md5'] as $k) {
			if (array_key_exists($k, $files) && !is_string($files[$k])) {
				throw new RuntimeException("{$where}.{$k}: a string");
			}
		}
	}

	/** @param array<string, mixed> $files @return array<string, string> the files of a state by name, bytes decoded */
	private static function stateBytes(array $files): array
	{
		$out = [];
		foreach (['orig', 'norm'] as $k) {
			if (array_key_exists($k, $files) || array_key_exists("{$k}_hex", $files)) {
				$out[$k] = FeedParseCorpusFile::bytes($files, $k, '');
			}
		}
		foreach (['xxhash128', 'md5'] as $k) {
			if (array_key_exists($k, $files)) {
				$out[$k] = $files[$k];
			}
		}
		return $out;
	}

	/** @param array<string, mixed> $case */
	#[DataProvider('cases')]
	public function testCaseMatchesPfbFeedNormalize(array $case): void
	{
		$this->assertSame($this->wantResult($case['expect']), $this->replay($case), "{$case['id']}: {$case['description']}");
	}

	/**
	 * @param array<string, mixed> $expect
	 * @return array<string, mixed>
	 */
	private function wantResult(array $expect): array
	{
		$files = self::stateBytes($expect['files']);
		ksort($files);
		return ['path' => $expect['path'], 'changed' => $expect['changed'], 'normalized' => $expect['normalized'], 'files' => $files];
	}

	/**
	 * Set up the case's directory, run the production function, and report what it returned and left behind: every file of
	 * the directory, a stray temporary file included.
	 *
	 * @param array<string, mixed> $case
	 * @return array<string, mixed>
	 */
	private function replay(array $case): array
	{
		foreach (self::stateBytes($case['setup']) as $k => $bytes) {
			file_put_contents("{$this->dir}/feed" . self::FILES[$k], $bytes);
		}
		$r = pfb_feed_normalize("{$this->dir}/feed.orig", '');
		$path = match ($r['path']) {
			"{$this->dir}/feed.norm" => 'norm',
			"{$this->dir}/feed.orig" => 'orig',
			default => $r['path'],
		};
		$byName = array_flip(array_map(static fn(string $suffix): string => "feed{$suffix}", self::FILES));
		$files = [];
		foreach (scandir($this->dir) ?: [] as $name) {
			if ($name !== '.' && $name !== '..') {
				$files[$byName[$name] ?? $name] = (string) file_get_contents("{$this->dir}/{$name}");
			}
		}
		ksort($files);
		return ['path' => $path, 'changed' => $r['changed'], 'normalized' => $r['normalized'], 'files' => $files];
	}

	/**
	 * @return array<string, array{string}>
	 */
	public static function malformedProvider(): array
	{
		$ok = self::WELL;
		$doc = static fn(string $case): string => '{"schema": 1, "cases": [' . $case . ']}';
		return [
			'unknown top key'      => [str_replace('"schema": 1', '"schema": 1, "x": 1', $doc($ok))],
			'unknown case key'     => [$doc(str_replace('"description": "d",', '"description": "d", "x": 1,', $ok))],
			'unknown setup key'    => [$doc(str_replace('"setup": {"orig"', '"setup": {"x": "y", "orig"', $ok))],
			'orig and orig_hex'    => [$doc(str_replace('"setup": {"orig": "a.example\n"}', '"setup": {"orig": "a", "orig_hex": "ff"}', $ok))],
			'orig_hex is UTF-8'    => [$doc(str_replace('"setup": {"orig": "a.example\n"}', '"setup": {"orig_hex": "61"}', $ok))],
			'sidecar not a string' => [$doc(str_replace('"xxhash128": "00000000000000000000000000000000"', '"xxhash128": 0', $ok))],
			'bad path'             => [$doc(str_replace('"path": "norm"', '"path": "x"', $ok))],
			'changed not a bool'   => [$doc(str_replace('"changed": true', '"changed": 1', $ok))],
			'missing files'        => [$doc(str_replace(', "files": {"orig": "a.example\n", "norm": "a.example\n", "xxhash128": "00000000000000000000000000000000"}', '', $ok))],
			'duplicate id'         => ['{"schema": 1, "cases": [' . $ok . ',' . $ok . ']}'],
			'empty cases'          => ['{"schema": 1, "cases": []}'],
		];
	}

	public function testLoaderAcceptsAWellFormedDocument(): void
	{
		foreach (FeedParseCorpusFile::load(self::scratch('{"schema": 1, "cases": [' . self::WELL . ']}'), ['cases'])['cases'] as $case) {
			self::checkCase($case);
		}
		$this->addToAssertionCount(1);
	}

	#[DataProvider('malformedProvider')]
	public function testLoaderIsStrict(string $json): void
	{
		$this->expectException(RuntimeException::class);
		foreach (FeedParseCorpusFile::load(self::scratch($json), ['cases'])['cases'] as $case) {
			self::checkCase($case);
		}
	}

	private static function scratch(string $json): string
	{
		$path = (string) tempnam(sys_get_temp_dir(), 'pfb_fpnc_doc_');
		file_put_contents($path, $json);
		$ownerPid = getmypid();
		register_shutdown_function(static function () use ($path, $ownerPid): void {
			// pcntl_fork() inherits shutdown callbacks: only the process that wrote the file removes it.
			if (getmypid() === $ownerPid) {
				@unlink($path);
			}
		});
		return $path;
	}
}
