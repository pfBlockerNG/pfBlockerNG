<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;

require_once __DIR__ . '/support/ProcessRunner.php';

final class LogNowTokenRetiredHostilePathTest extends TestCase
{
	private string $root;

	protected function setUp(): void
	{
		$this->root = sys_get_temp_dir() . '/pfb_log_now_path_' . bin2hex(random_bytes(8));
		$this->assertTrue(mkdir($this->root . '/tests/php', 0755, true));
		$this->assertTrue(mkdir($this->root . '/tests/php/support', 0755, true));
		$this->assertTrue(mkdir($this->root . '/src', 0755, true));
		$this->assertTrue(copy(__DIR__ . '/LogNowTokenRetiredTest.php', $this->root . '/tests/php/LogNowTokenRetiredTest.php'));
		$this->assertTrue(copy(__DIR__ . '/support/ProcessRunner.php', $this->root . '/tests/php/support/ProcessRunner.php'));
		$this->assertNotFalse(file_put_contents($this->root . '/src/café.inc', "<?php\npfb_logger('x', 1, ' [ NOW ]');\n"));

		foreach ([['init', '-q'], ['config', 'core.quotePath', 'true'], ['add', '--', 'src']] as $arguments) {
			$result = pfb_test_run_process(['git', '-C', $this->root, ...$arguments], 10.0, pfb_test_scrubbed_git_env());
			$this->assertSame(0, $result['exit'], 'scratch git failed: ' . $result['stderr']);
		}
	}

	protected function tearDown(): void
	{
		rmdir_recursive($this->root);
	}

	public function testRetiredTokenScanReportsHostileTrackedPath(): void
	{
		$phpunit = dirname(__DIR__, 2) . '/vendor/bin/phpunit';
		$test = $this->root . '/tests/php/LogNowTokenRetiredTest.php';

		$result = pfb_test_run_process([$phpunit, '--colors=never', '--no-configuration', $test], 10.0, pfb_test_scrubbed_git_env());

		$this->assertSame(1, $result['exit'], "retired-token scan must fail for the hostile tracked path:\n{$result['stdout']}{$result['stderr']}");
		$this->assertStringContainsString('src/café.inc:2', $result['stdout'] . $result['stderr']);
	}

	public function testProcessRunnerKillsChildAtHardDeadline(): void
	{
		$this->expectException(RuntimeException::class);
		$this->expectExceptionMessage('STUCK/ENVIRONMENT: process exceeded hard deadline');

		pfb_test_run_process([PHP_BINARY, '-r', 'sleep(5);'], 0.05);
	}

	public function testScratchGitIgnoresInheritedRepositoryContext(): void
	{
		$originalGitDir = getenv('GIT_DIR');
		$originalGlobalConfig = getenv('GIT_CONFIG_GLOBAL');
		putenv('GIT_DIR=/foreign/repository');
		putenv('GIT_CONFIG_GLOBAL=/foreign/config');
		try {
			$environment = pfb_test_scrubbed_git_env();
		} finally {
			putenv($originalGitDir === false ? 'GIT_DIR' : "GIT_DIR={$originalGitDir}");
			putenv($originalGlobalConfig === false ? 'GIT_CONFIG_GLOBAL' : "GIT_CONFIG_GLOBAL={$originalGlobalConfig}");
		}
		$this->assertArrayNotHasKey('GIT_DIR', $environment);
		$this->assertSame('/dev/null', $environment['GIT_CONFIG_GLOBAL']);
		$this->assertSame('/dev/null', $environment['GIT_CONFIG_SYSTEM']);

		$result = pfb_test_run_process(['git', '-C', $this->root, 'ls-files', '-z', '--', 'src'], 10.0, $environment);
		$this->assertSame("src/café.inc\0", $result['stdout']);
	}

	public function testRetiredTokenScanIgnoresInheritedGitContext(): void
	{
		$foreign = $this->root . '/foreign';
		$this->assertTrue(mkdir($foreign));
		$result = pfb_test_run_process(['git', '-C', $foreign, 'init', '-q'], 10.0, pfb_test_scrubbed_git_env());
		$this->assertSame(0, $result['exit'], 'foreign git init failed: ' . $result['stderr']);

		$phpunit = dirname(__DIR__, 2) . '/vendor/bin/phpunit';
		$test = $this->root . '/tests/php/LogNowTokenRetiredTest.php';
		$environment = pfb_test_scrubbed_git_env();
		$environment['GIT_DIR'] = $foreign . '/.git';
		$result = pfb_test_run_process([$phpunit, '--colors=never', '--no-configuration', $test], 10.0, $environment);

		$this->assertSame(1, $result['exit'], "retired-token scan must ignore inherited Git context:\n{$result['stdout']}{$result['stderr']}");
		$this->assertStringContainsString('src/café.inc:2', $result['stdout'] . $result['stderr']);
	}

	public function testRetiredTokenScanRejectsEmptyTrackedSet(): void
	{
		$environment = pfb_test_scrubbed_git_env();
		$result = pfb_test_run_process(['git', '-C', $this->root, 'rm', '-q', '--cached', 'src/café.inc'], 10.0, $environment);
		$this->assertSame(0, $result['exit'], 'scratch git rm failed: ' . $result['stderr']);

		$phpunit = dirname(__DIR__, 2) . '/vendor/bin/phpunit';
		$test = $this->root . '/tests/php/LogNowTokenRetiredTest.php';
		$result = pfb_test_run_process([$phpunit, '--colors=never', '--no-configuration', $test], 10.0, $environment);

		$this->assertSame(1, $result['exit'], "retired-token scan must reject an empty tracked set:\n{$result['stdout']}{$result['stderr']}");
		$this->assertStringContainsString('an empty scan must not pass', $result['stdout'] . $result['stderr']);
	}
}
