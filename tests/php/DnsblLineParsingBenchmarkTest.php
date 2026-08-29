<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversNothing;
use PHPUnit\Framework\TestCase;

#[CoversNothing]
final class DnsblLineParsingBenchmarkTest extends TestCase
{
	private string $tmp;

	protected function setUp(): void
	{
		$this->tmp = sys_get_temp_dir() . '/pfb_benchmark_' . uniqid('', TRUE);
		mkdir("{$this->tmp}/dnsbl", 0777, TRUE);
	}

	protected function tearDown(): void
	{
		$files = new RecursiveIteratorIterator(
			new RecursiveDirectoryIterator($this->tmp, FilesystemIterator::SKIP_DOTS),
			RecursiveIteratorIterator::CHILD_FIRST
		);
		foreach ($files as $file) {
			$file->isDir() ? rmdir((string) $file) : unlink((string) $file);
		}
		rmdir($this->tmp);
	}

	public function testWorkerReportsLineCountFromVersionedManifestReference(): void
	{
		$root = dirname(__DIR__, 2);
		file_put_contents("{$this->tmp}/dnsbl/benchfeed.txt",
			pfb_dnsbl_ndjson_emit_row(PfbDnsblRowKind::Domain, 'one.example') .
			pfb_dnsbl_ndjson_emit_row(PfbDnsblRowKind::Domain, 'two.example'));

		$command = implode(' ', array_map('escapeshellarg', [
			PHP_BINARY,
			"{$root}/scripts/bench_dnsbl_line_parsing.php",
			$root,
			$this->tmp,
			'1',
		]));
		exec("{$command} 2>&1", $output, $status);

		$this->assertSame(0, $status, implode("\n", $output));
		$this->assertContains('raw_line_count=2', $output);
		$manifest = json_decode((string) file_get_contents("{$this->tmp}/pfb_py_sources.json"), TRUE);
		$this->assertIsArray($manifest);
		$raw = $manifest['feeds'][0]['raw'] ?? NULL;
		$this->assertIsString($raw);
		$this->assertMatchesRegularExpression(
			'#^pfb_py_raw\.[0-9a-f]{32}/benchfeed\.raw$#',
			$raw
		);
		$this->assertFileExists("{$this->tmp}/{$raw}");
	}
}
