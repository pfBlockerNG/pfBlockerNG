<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;

final class DnsStatsBatchResourceTest extends TestCase
{
	public function testOpaqueCategoryNamesAndMissingNegativeColumnKeepOrdinaryBuckets(): void
	{
		$path = tempnam(sys_get_temp_dir(), 'opaque-');
		try {
			file_put_contents($path, "DNS-reply,2031-02-15 09:00:00,cache,A,A,30,a.test,src,dst,US\n");
			$this->assertSame(['stats' => ['suffix' => ['cache' => 1], 'opaque' => ['a.test' => 1],
				'missing' => ['Unknown' => 1]], 'count' => 1, 'chart' => []],
				pfb_dns_stats($path, ['suffix' => 3, 'opaque' => 7, 'missing' => 0], 'Unknown'));
		} finally {
			unlink($path);
		}
		$this->assertFileDoesNotExist($path);
	}

	public function testLargeIgnoredMultilineFieldsKeepFullDataWithinAConsumerMemoryLimit(): void
	{
		$this->assertMultilineFieldsFitConsumerMemoryLimit(str_repeat('x', 262144) . "\ntrailer");
	}

	public function testLargeLaterPhysicalLineKeepsFullDataWithinAConsumerMemoryLimit(): void
	{
		$this->assertMultilineFieldsFitConsumerMemoryLimit("short\n" . str_repeat('x', 262144));
	}

	private function assertMultilineFieldsFitConsumerMemoryLimit(string $domain): void
	{
		$dir = sys_get_temp_dir() . '/dns-resource-' . bin2hex(random_bytes(8));
		mkdir($dir, 0700);
		$fixture = $dir . '/events.csv';
		$worker = $dir . '/worker.php';
		try {
			$stream = fopen($fixture, 'xb');
			try {
				for ($i = 0; $i < 128; $i++) {
					fputcsv($stream, ['DNS-reply', '2031-02-15 09:00:00', 'cache', 'A', 'A', '30',
						$domain, 'src', 'dst', 'US'], ',', '"', '');
				}
			} finally {
				fclose($stream);
			}
			$reflection = new ReflectionFunction('pfb_dns_stats');
			$source = file((string) $reflection->getFileName());
			$body = implode('', array_slice($source, $reflection->getStartLine() - 1,
				$reflection->getEndLine() - $reflection->getStartLine() + 1));
			file_put_contents($worker, "<?php\n" . $body . <<<'PHP'

$result = pfb_dns_stats($argv[1], ['replytype' => 3], 'Unknown');
echo json_encode($result, JSON_THROW_ON_ERROR);
PHP
			);
			$process = proc_open([PHP_BINARY, '-d', 'memory_limit=32M', '-d', 'display_errors=stderr', $worker, $fixture],
				[0 => ['pipe', 'r'], 1 => ['pipe', 'w'], 2 => ['pipe', 'w']], $pipes);
			$this->assertIsResource($process, 'could not start memory-limited statistics worker');
			fclose($pipes[0]);
			$stdout = stream_get_contents($pipes[1]);
			$stderr = stream_get_contents($pipes[2]);
			fclose($pipes[1]);
			fclose($pipes[2]);
			$status = proc_close($process);
			$this->assertSame(0, $status, "worker stdout: {$stdout}\nworker stderr: {$stderr}");
			$this->assertSame('', $stderr);
			$this->assertSame(['stats' => ['replytype' => ['cache' => 128]], 'count' => 256, 'chart' => []],
				json_decode($stdout, TRUE, 512, JSON_THROW_ON_ERROR));
		} finally {
			if (is_file($worker)) {
				unlink($worker);
			}
			if (is_file($fixture)) {
				unlink($fixture);
			}
			rmdir($dir);
		}
		$this->assertDirectoryDoesNotExist($dir);
	}
}
