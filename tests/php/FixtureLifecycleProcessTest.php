<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

require_once __DIR__ . '/support/ProcessRunner.php';

final class FixtureLifecycleProcessTest extends TestCase
{
	/** @return array<string,array{string}> */
	public static function fixtureClasses(): array
	{
		return [
			'inline fixtures' => ['FixtureInlineLifecycleTest'],
			'setup fixtures' => ['FixtureSetupLifecycleTest'],
		];
	}

	/** @return array<string,mixed> */
	private function runProbe(string $class, string $script): array
	{
		$root = var_export(dirname(__DIR__, 2), TRUE);
		$classLiteral = var_export($class, TRUE);
		$scriptLiteral = var_export($script, TRUE);
		$probe = <<<PHP
require {$root} . '/vendor/autoload.php';
\$class = {$classLiteral};
require {$root} . '/tests/php/' . \$class . '.php';
\$object = new \$class('testProbe');
try {
	if (\$class === 'FixtureInlineLifecycleTest') {
		\$method = new ReflectionMethod(\$class, 'runChildScript');
		\$result = \$method->invoke(\$object, {$scriptLiteral}, sys_get_temp_dir());
		\$result['stderrBytes'] = strlen(\$result['stderr']);
		unset(\$result['stderr']);
	} else {
		\$method = new ReflectionMethod(\$class, 'runChild');
		\$result = \$method->invoke(\$object, sys_get_temp_dir(), {$scriptLiteral});
	}
} catch (RuntimeException \$error) {
	\$result = ['timeout' => str_starts_with(\$error->getMessage(), 'STUCK/ENVIRONMENT: process exceeded hard deadline:')];
}
echo json_encode(\$result);
PHP;
		// The outer watchdog reaps the whole probe group if its inner deadline regresses.
		$result = pfb_test_run_process([
			(string) $GLOBALS['pfb']['timeout'], '-s', 'TERM', '-k', '5', '30',
			PHP_BINARY, '-r', $probe,
		], 40.0);
		$this->assertSame(0, $result['exit'], "STUCK/ENVIRONMENT: fixture probe did not complete:\n{$result['stdout']}{$result['stderr']}");
		return json_decode($result['stdout'], TRUE, 512, JSON_THROW_ON_ERROR);
	}

	#[DataProvider('fixtureClasses')]
	public function testChildCanFinishAfterFillingItsStderrPipe(string $class): void
	{
		$result = $this->runProbe($class, 'fwrite(STDERR, str_repeat("x", 1048576)); echo json_encode(["complete" => TRUE]);');
		$expected = $class === 'FixtureInlineLifecycleTest'
			? ['status' => 0, 'stdout' => '{"complete":true}', 'stderrBytes' => 1048576]
			: ['complete' => TRUE];
		$this->assertSame($expected, $result);
	}

	#[DataProvider('fixtureClasses')]
	public function testStalledChildReportsItsOwnDeadlineBeforeTheOuterWatchdog(string $class): void
	{
		$result = $this->runProbe($class, 'sleep(60); echo json_encode(["complete" => TRUE]);');
		$this->assertSame(['timeout' => TRUE], $result);
	}
}
