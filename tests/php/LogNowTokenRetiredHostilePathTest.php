<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;

final class LogNowTokenRetiredHostilePathTest extends TestCase
{
	private string $root;

	protected function setUp(): void
	{
		$this->root = sys_get_temp_dir() . '/pfb_log_now_path_' . bin2hex(random_bytes(8));
		$this->assertTrue(mkdir($this->root . '/tests/php', 0755, true));
		$this->assertTrue(mkdir($this->root . '/src', 0755, true));
		$this->assertTrue(copy(__DIR__ . '/LogNowTokenRetiredTest.php', $this->root . '/tests/php/LogNowTokenRetiredTest.php'));
		$this->assertNotFalse(file_put_contents($this->root . '/src/café.inc', "<?php\npfb_logger('x', 1, ' [ NOW ]');\n"));

		$output = [];
		exec('git -C ' . escapeshellarg($this->root) . ' init -q 2>&1', $output, $exit);
		$this->assertSame(0, $exit, 'scratch git init failed: ' . implode("\n", $output));
		$output = [];
		exec('git -C ' . escapeshellarg($this->root) . ' config core.quotePath true 2>&1', $output, $exit);
		$this->assertSame(0, $exit, 'scratch git config failed: ' . implode("\n", $output));
		$output = [];
		exec('git -C ' . escapeshellarg($this->root) . ' add -- src 2>&1', $output, $exit);
		$this->assertSame(0, $exit, 'scratch git add failed: ' . implode("\n", $output));
	}

	protected function tearDown(): void
	{
		rmdir_recursive($this->root);
	}

	public function testRetiredTokenScanReportsHostileTrackedPath(): void
	{
		$phpunit = dirname(__DIR__, 2) . '/vendor/bin/phpunit';
		$test = $this->root . '/tests/php/LogNowTokenRetiredTest.php';

		exec(escapeshellarg($phpunit) . ' --colors=never --no-configuration ' . escapeshellarg($test) . ' 2>&1', $output, $exit);

		$this->assertSame(1, $exit, "retired-token scan must fail for the hostile tracked path:\n" . implode("\n", $output));
		$this->assertStringContainsString('src/café.inc:2', implode("\n", $output));
	}
}
