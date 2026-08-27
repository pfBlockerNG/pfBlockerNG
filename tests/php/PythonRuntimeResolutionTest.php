<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * Pins the appliance Python runtime boundary used by DNSBL validation and
 * update hooks. The package dependency is authoritative: py311/python311
 * selects the matching versioned interpreter through the shared wrapper, while
 * module dependencies and malformed or ambiguous versions must never be treated as it.
 */
#[CoversFunction('pfb_python_interpreter')]
#[CoversFunction('pfb_hook_script_command')]
final class PythonRuntimeResolutionTest extends TestCase
{
	private static string $python;

	public static function setUpBeforeClass(): void
	{
		parent::setUpBeforeClass();
		self::$python = self::commandPath('python3');
	}

	private static function commandPath(string $command): string
	{
		$output = [];
		$status = 1;
		exec('command -v ' . escapeshellarg($command) . ' 2>/dev/null', $output, $status);
		if ($status !== 0 || $output === [] || trim($output[0]) === '') {
			throw new RuntimeException("required test command not found: {$command}");
		}
		return trim($output[0]);
	}

	/** @return array<string, array{array<int, string|int>}> */
	public static function supportedDependencyProvider(): array
	{
		return [
			'py311' => [['py311']],
			'python311' => [['python311']],
			'whitespace is trimmed' => [['  py311  ']],
			'duplicate aliases collapse' => [['py311', 'python311', 'py311-sqlite3']],
			'non-string array member is ignored' => [[123, 'py311']],
			'module dependency is not interpreter' => [['py311-sqlite3']],
		];
	}

	#[DataProvider('supportedDependencyProvider')]
	public function testInterpreterDerivesFromExactDependency(array $dependencies): void
	{
		$expected = $dependencies === ['py311-sqlite3'] ? '' : '/usr/local/bin/' . 'python3.11';
		$this->assertSame($expected, pfb_python_interpreter($dependencies), json_encode($dependencies));
	}

	/** @return array<string, array{array<int, string>}> */
	public static function unsupportedDependencyProvider(): array
	{
		return [
			'absent' => [[]],
			'ambiguous versions' => [['py311', 'python312']],
			'malformed nonnumeric version' => [['python3x']],
			'python dotted name is not package dependency' => [['python3.11']],
			'one digit version is rejected' => [['py3']],
			'whitespace-only dependency is ignored' => [['   ']],
		];
	}

	#[DataProvider('unsupportedDependencyProvider')]
	public function testInterpreterRejectsAbsentAmbiguousAndMalformedDependencies(array $dependencies): void
	{
		$this->assertSame('', pfb_python_interpreter($dependencies), json_encode($dependencies));
	}

	public function testPythonHookUsesWrapperAndEscapedScriptPath(): void
	{
		$path = '/usr/local/pkg/pfblockerng/hooks/hook_post_delta.py';

		$this->assertSame(
			escapeshellarg(PFB_PYTHON_WRAPPER) . ' ' . escapeshellarg($path),
			pfb_hook_script_command('hook_post_delta.py', $path, PFB_PYTHON_WRAPPER)
		);
	}

	public function testShellHookRunsDirectly(): void
	{
		$path = '/usr/local/pkg/pfblockerng/hooks/hook_post_delta.sh';

		$this->assertSame(escapeshellarg($path), pfb_hook_script_command('hook_post_delta.sh', $path, PFB_PYTHON_WRAPPER));
	}

	public function testPythonHookFailsClosedWhenInterpreterUnavailable(): void
	{
		$this->assertSame(
			'',
			pfb_hook_script_command(
				'hook_post_delta.py',
				'/usr/local/pkg/pfblockerng/hooks/hook_post_delta.py',
				''
			)
		);
	}

	public function testPythonHookRunsWithExplicitInterpreterDespiteInvalidShebang(): void
	{
		$dir = sys_get_temp_dir() . '/pfb_python_hook_' . getmypid() . '_' . bin2hex(random_bytes(3));
		mkdir($dir, 0700, TRUE);
		$script = $dir . '/hook_post_invalid.py';
		$marker = $dir . '/executed';
		$python_marker = json_encode($marker, JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR);
		file_put_contents(
			$script,
			"#!/definitely/not/a/python/interpreter\n" .
			"from pathlib import Path\n" .
			"Path({$python_marker}).write_text('ran\\n')\n"
		);
		chmod($script, 0600);
		$python_dir = $dir . '/bin';
		mkdir($python_dir, 0700);
		$this->assertTrue(symlink(self::$python, $python_dir . '/python3.11'));
		$old_dependencies = getenv('PFB_PYTHON_DEPENDENCIES');
		$old_python_dir = getenv('PFB_PYTHON_DIR');
		putenv('PFB_PYTHON_DEPENDENCIES=py311');
		putenv('PFB_PYTHON_DIR=' . $python_dir);
		try {
			$command = pfb_hook_script_command('hook_post_invalid.py', $script, PFB_PYTHON_WRAPPER);
			$output = [];
			$status = -1;
			exec($command . ' 2>&1', $output, $status);
			$this->assertSame(0, $status, implode("\n", $output));
			$this->assertSame("ran\n", file_get_contents($marker));
		} finally {
			$old_dependencies === FALSE ? putenv('PFB_PYTHON_DEPENDENCIES') : putenv('PFB_PYTHON_DEPENDENCIES=' . $old_dependencies);
			$old_python_dir === FALSE ? putenv('PFB_PYTHON_DIR') : putenv('PFB_PYTHON_DIR=' . $old_python_dir);
			@unlink($script);
			@unlink($marker);
			@unlink($python_dir . '/python3.11');
			@rmdir($python_dir);
			@rmdir($dir);
		}
	}
}
