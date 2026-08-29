<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;

require_once __DIR__ . '/support/ProcessRunner.php';

final class SrcPhpDeprecationLintHostilePathTest extends TestCase
{
	private string $root;

	protected function setUp(): void
	{
		$this->root = sys_get_temp_dir() . '/pfb_src_php_lint_' . bin2hex(random_bytes(8));
		$this->assertTrue(mkdir($this->root . '/tests/php/support', 0755, true));
		$this->assertTrue(mkdir($this->root . '/src', 0755, true));
		$this->assertTrue(copy(__DIR__ . '/SrcPhpDeprecationLintTest.php', $this->root . '/tests/php/SrcPhpDeprecationLintTest.php'));
		$this->assertTrue(copy(__DIR__ . '/support/ProcessRunner.php', $this->root . '/tests/php/support/ProcessRunner.php'));
		$this->assertNotFalse(file_put_contents($this->root . '/src/common.inc', "<?php\n"));
		$this->assertNotFalse(file_put_contents($this->root . '/src/bad.inc', "<?php\nif (\n"));

		foreach ([['init', '-q'], ['add', '--', 'src']] as $arguments) {
			$result = pfb_test_run_process(['git', '-C', $this->root, ...$arguments], 10.0, pfb_test_scrubbed_git_env());
			$this->assertSame(0, $result['exit'], 'scratch git failed: ' . $result['stderr']);
		}
	}

	protected function tearDown(): void
	{
		rmdir_recursive($this->root);
	}

	public function testLintIgnoresForeignPartialGitIndex(): void
	{
		$foreign = $this->root . '/foreign';
		$this->assertTrue(mkdir($foreign . '/src', 0755, true));
		$this->assertNotFalse(file_put_contents($foreign . '/src/common.inc', "<?php\n"));

		foreach ([['init', '-q'], ['add', '--', 'src/common.inc']] as $arguments) {
			$result = pfb_test_run_process(['git', '-C', $foreign, ...$arguments], 10.0, pfb_test_scrubbed_git_env());
			$this->assertSame(0, $result['exit'], 'foreign git failed: ' . $result['stderr']);
		}

		$environment = pfb_test_scrubbed_git_env();
		$environment['GIT_DIR'] = $foreign . '/.git';
		$result = pfb_test_run_process(
			[
				dirname(__DIR__, 2) . '/vendor/bin/phpunit',
				'--colors=never',
				'--no-configuration',
				$this->root . '/tests/php/SrcPhpDeprecationLintTest.php',
			],
			10.0,
			$environment
		);

		$this->assertSame(1, $result['exit'], "lint must scan the current checkout despite foreign Git context:\n{$result['stdout']}{$result['stderr']}");
		$this->assertStringContainsString('src/bad.inc', $result['stdout'] . $result['stderr']);
	}
}
