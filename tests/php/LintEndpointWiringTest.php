<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;

final class LintEndpointWiringTest extends TestCase
{
	private const ROOT = __DIR__ . '/../..';
	private const PAGE = self::ROOT . '/src/usr/local/www/pfblockerng/pfblockerng_lint.php';

	public function testRealPageRejectsWrongMethodBeforeDispatch(): void
	{
		$result = $this->request(['lang' => 'regex', 'content' => 'x'], ['REQUEST_METHOD' => 'GET']);
		$this->assertSame('POST only', $result['body']['error']);
	}

	public function testRealPageDispatchesAllowedRegexAndRejectsDeniedPython(): void
	{
		$regex = $this->request(
			['lang' => 'regex', 'content' => 'example.com'],
			['REQUEST_METHOD' => 'POST'],
			['pfblockerng/pfblockerng_dnsbl.php' => TRUE]
		);
		$this->assertArrayHasKey('diagnostics', $regex['body']);

		$python = $this->request(
			['lang' => 'py', 'content' => 'x'],
			['REQUEST_METHOD' => 'POST'],
			['diag_command.php' => FALSE]
		);
		$this->assertSame('insufficient privilege', $python['body']['error']);
	}

	public function testRealPageRejectsArrayAndOversizeContent(): void
	{
		$array = $this->request(
			['lang' => 'regex', 'content' => ['x']],
			['REQUEST_METHOD' => 'POST'],
			['pfblockerng/pfblockerng_dnsbl.php' => TRUE]
		);
		$this->assertSame('content must be a string', $array['body']['error']);

		$large = $this->request(
			['lang' => 'regex', 'content' => str_repeat('x', 1048577)],
			['REQUEST_METHOD' => 'POST'],
			['pfblockerng/pfblockerng_dnsbl.php' => TRUE]
		);
		$this->assertSame('content too large', $large['body']['error']);
	}

	/** @param array<string,mixed> $post @param array<string,string> $server @param array<string,bool> $allowed @return array{body:array<string,mixed>} */
	private function request(array $post, array $server, array $allowed = []): array
	{
		$payload = json_encode(compact('post', 'server', 'allowed'), JSON_THROW_ON_ERROR);
		$root = var_export(self::ROOT, TRUE);
		$page = var_export(self::PAGE, TRUE);
		$script = <<<PHP
\$request = json_decode(stream_get_contents(STDIN), TRUE, 512, JSON_THROW_ON_ERROR);
\$GLOBALS['pfb_test_allowed_pages'] = \$request['allowed'];
\$_SERVER = \$request['server'];
\$_POST = \$request['post'];
\$shim = sys_get_temp_dir() . '/pfb_lint_shim_' . getmypid();
mkdir(\$shim, 0777, TRUE);
file_put_contents(\$shim . '/guiconfig.inc', "<?php");
set_include_path(\$shim . PATH_SEPARATOR . get_include_path());
require {$root} . '/tests/php/bootstrap.php';
require {$page};
PHP;
		$descriptors = [0 => ['pipe', 'r'], 1 => ['pipe', 'w'], 2 => ['pipe', 'w']];
		$process = proc_open([PHP_BINARY, '-r', $script], $descriptors, $pipes);
		$this->assertIsResource($process);
		fwrite($pipes[0], $payload);
		fclose($pipes[0]);
		$stdout = stream_get_contents($pipes[1]);
		$stderr = stream_get_contents($pipes[2]);
		fclose($pipes[1]);
		fclose($pipes[2]);
		$status = proc_close($process);
		$this->assertSame('', trim((string) $stderr), (string) $stderr);
		$body = json_decode((string) $stdout, TRUE);
		$this->assertIsArray($body, (string) $stdout);
		$this->assertSame(0, $status);
		return ['body' => $body];
	}
}
