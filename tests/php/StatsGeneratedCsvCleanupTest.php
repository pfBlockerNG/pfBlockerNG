<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;

final class StatsGeneratedCsvCleanupTest extends TestCase
{
	public function testUpgradeRemovesTheFormerPublicStatsSnapshot(): void
	{
		$dir = '/var/tmp/agents/3759-ui/cleanup-' . bin2hex(random_bytes(8));
		mkdir($dir, 0700, TRUE);
		$csv = $dir . '/chart_stats.csv';
		file_put_contents($csv, "edate,ecount\n2031-02-15 (09),1\n");
		$source = file_get_contents(__DIR__ . '/../../src/usr/local/pkg/pfblockerng/pfblockerng_install.inc');
		$start = strpos($source, '// Remove cache databases');
		$end = strpos($source, 'update_status(', $start);
		$cleanup = substr($source, $start, $end - $start);
		// Run the real upgrade block with its fixed appliance paths rebased to an isolated directory.
		$cleanup = str_replace(
			['/usr/local/www/pfblockerng/chart_stats.csv', '/var/unbound/pfb_py_tld.txt'],
			[$csv, $dir . '/pfb_py_tld.txt'],
			$cleanup
		);
		$script = '<?php function unlink_if_exists($file) { if (file_exists($file)) { unlink($file); } }'
			. ' function rmdir_recursive($path) {}'
			. ' $pfb = ' . var_export([
				'asn_cache' => $dir . '/asn', 'ip_cache' => $dir . '/ip',
				'dnsbl_cache' => $dir . '/dnsbl', 'dbdir' => $dir,
			], TRUE) . '; ' . $cleanup;
		try {
			$process = proc_open([PHP_BINARY], [0 => ['pipe', 'r'], 1 => ['pipe', 'w'], 2 => ['pipe', 'w']], $pipes);
			$this->assertIsResource($process);
			fwrite($pipes[0], $script);
			fclose($pipes[0]);
			$output = stream_get_contents($pipes[1]);
			$error = stream_get_contents($pipes[2]);
			fclose($pipes[1]);
			fclose($pipes[2]);
			$this->assertSame(0, proc_close($process), $output . $error);
			$this->assertFileDoesNotExist($csv, 'Upgrade left the old unauthenticated Stats snapshot in the web root');
		} finally {
			if (file_exists($csv)) {
				unlink($csv);
			}
			rmdir($dir);
		}
	}
}
