<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

final class WidgetPostAllowedTest extends TestCase
{
	private const ROOT = __DIR__ . '/../..';
	private const WIDGET = self::ROOT . '/src/usr/local/www/widgets/widgets/pfblockerng.widget.php';

	public static function setUpBeforeClass(): void
	{
		require_once dirname(__DIR__, 2) . '/src/usr/local/www/widgets/include/widget-pfblockerng.inc';
	}

	/** @return array<string,array{array<string,string>,bool}> */
	public static function truthTableProvider(): array
	{
		return [
			'absent header' => [[], FALSE],
			'same-origin' => [['HTTP_SEC_FETCH_SITE' => 'same-origin'], TRUE],
			'none' => [['HTTP_SEC_FETCH_SITE' => 'none'], TRUE],
			'cross-site' => [['HTTP_SEC_FETCH_SITE' => 'cross-site'], FALSE],
			'same-site' => [['HTTP_SEC_FETCH_SITE' => 'same-site'], FALSE],
			'empty' => [['HTTP_SEC_FETCH_SITE' => ''], FALSE],
		];
	}

	#[DataProvider('truthTableProvider')]
	public function testGuardTruthTable(array $server, bool $expected): void
	{
		$this->assertSame($expected, pfb_widget_post_guard(['pfb_submit' => '1'], $server, 'pfb_submit'));
	}

	/** @return array<string,array{string}> */
	public static function mutationFields(): array
	{
		return [
			'settings' => ['pfb_submit'],
			'failed' => ['pfblockerngack'],
			'all counts' => ['pfblockerngclearall'],
			'ip counts' => ['pfblockerngclearip'],
			'dnsbl counts' => ['pfblockerngcleardnsbl'],
		];
	}

	#[DataProvider('mutationFields')]
	public function testEveryShippedMutationBranchStaysClosedWithoutFetchMetadata(string $field): void
	{
		$result = $this->runWidget([], [$field => '1']);
		$this->assertSame(0, $result['status'], $result['stderr']);
		$this->assertStringContainsString('<form id="formicons"', $result['stdout']);
	}

	/** @return array{status:int,stdout:string,stderr:string} */
	private function runWidget(array $get, array $post): array
	{
		$root = var_export(self::ROOT, TRUE);
		$widget = var_export(self::WIDGET, TRUE);
		$getCode = var_export($get, TRUE);
		$postCode = var_export($post, TRUE);
		$script = <<<PHP
\$_GET = {$getCode};
\$_POST = {$postCode};
\$_SERVER = [];
\$widgetname = 'pfblockerng';
\$shim = sys_get_temp_dir() . '/pfb_widget_shim_' . getmypid();
mkdir(\$shim, 0777, TRUE);
file_put_contents(\$shim . '/guiconfig.inc', "<?php");
set_include_path(\$shim . PATH_SEPARATOR . get_include_path());
require {$root} . '/tests/php/bootstrap.php';
require {$widget};
PHP;
		$descriptors = [1 => ['pipe', 'w'], 2 => ['pipe', 'w']];
		$process = proc_open([PHP_BINARY, '-r', $script], $descriptors, $pipes);
		$this->assertIsResource($process);
		$stdout = stream_get_contents($pipes[1]);
		$stderr = stream_get_contents($pipes[2]);
		fclose($pipes[1]);
		fclose($pipes[2]);
		$status = proc_close($process);
		return ['status' => $status, 'stdout' => (string) $stdout, 'stderr' => (string) $stderr];
	}
}
