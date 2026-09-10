<?php

declare(strict_types=1);

require_once __DIR__ . '/PidShimHarnessTrait.php';

use PHPUnit\Framework\TestCase;

final class LintEndpointWiringTest extends TestCase
{
	use PidShimHarnessTrait;

	private const ROOT = __DIR__ . '/../..';
	private const PAGE = self::ROOT . '/src/usr/local/www/pfblockerng/pfblockerng_lint.php';

	protected function pidShimPrefix(): string
	{
		return 'pfb_lint_shim_';
	}

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

	/**
	 * Scenario: the include shim is per-invocation scratch.
	 * Given a run of the real page,
	 * When it finishes,
	 * Then the temp directory holds nothing keyed to that run -- a shim left
	 * behind is what lets a later run on a recycled PID collide (issue #2612).
	 */
	public function testRealPageRunLeavesNoShimResidue(): void
	{
		// A checkout without this fix, sharing the host, can already hold a bare
		// pfb_lint_shim_<pid>, so only what this run added counts.
		$before = glob(sys_get_temp_dir() . '/pfb_lint_shim_*') ?: [];
		$result = $this->request(['lang' => 'regex', 'content' => 'x'], ['REQUEST_METHOD' => 'GET']);
		$this->assertSame('POST only', $result['body']['error']);
		$this->assertSame([], array_diff($this->shimResidue($result['pid']), $before));
	}

	/**
	 * Scenario: the OS recycles a PID an earlier suite run already used.
	 * Given a shim directory already sitting at this run's PID-keyed path,
	 * When the real page is requested,
	 * Then it still answers clean JSON on a clean stderr, instead of the
	 * mkdir()/"headers already sent" cascade of issue #2612, and adds no
	 * residue of its own beside the directory it inherited.
	 */
	public function testRealPageSurvivesAShimLeftOverFromARecycledPid(): void
	{
		$result = $this->request(
			['lang' => 'regex', 'content' => 'x'],
			['REQUEST_METHOD' => 'GET'],
			[],
			TRUE
		);
		$this->assertSame('POST only', $result['body']['error']);
		$this->assertSame([], array_diff($this->shimResidue($result['pid']), $this->planted));
	}

	/** @param array<string,mixed> $post @param array<string,string> $server @param array<string,bool> $allowed @return array{body:array<string,mixed>,pid:int} */
	private function request(array $post, array $server, array $allowed = [], bool $plantStaleShim = FALSE): array
	{
		$payload = json_encode(compact('post', 'server', 'allowed'), JSON_THROW_ON_ERROR);
		$root = var_export(self::ROOT, TRUE);
		$page = var_export(self::PAGE, TRUE);
		$preamble = $this->pidShimPreamble('lint include shim creation failed');
		$script = <<<PHP
\$request = json_decode(stream_get_contents(STDIN), TRUE, 512, JSON_THROW_ON_ERROR);
\$GLOBALS['pfb_test_allowed_pages'] = \$request['allowed'];
\$_SERVER = \$request['server'];
\$_POST = \$request['post'];
{$preamble}
require {$root} . '/tests/php/bootstrap.php';
require {$page};
PHP;
		$descriptors = [0 => ['pipe', 'r'], 1 => ['pipe', 'w'], 2 => ['pipe', 'w']];
		$process = proc_open([PHP_BINARY, '-r', $script], $descriptors, $pipes);
		$this->assertIsResource($process);
		$pid = (int) proc_get_status($process)['pid'];
		if ($plantStaleShim) {
			// The child blocks on STDIN until the pipe is closed below, so the
			// plant always lands before it creates its own shim.
			$this->plantStaleShim($pid);
		}
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
		return ['body' => $body, 'pid' => $pid];
	}
}
