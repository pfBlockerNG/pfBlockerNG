<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\TestCase;

/**
 * issue #2839 row 3 -- $pfb['chroot_cmd'] is the unbound-control command prefix consumed
 * by pfb_unbound_control_exec() and every sibling call site. Off-appliance it defaulted to
 * unset, so a caller reached without a test-supplied override just named a bogus command
 * after whatever verb followed it -- harmless only because that happens to fail too. On an
 * installed host pfb_global() sets it to the REAL chroot(8)+unbound-control invocation with
 * no test involvement at all, which is why six existing suites each have to defuse it
 * themselves before touching it. tests/php/bootstrap.php now seeds an inert recorder
 * default, the same idiom PFB_UNBOUND_START_CMD established for the daemon-start boundary,
 * so a caller that never sets its own override still never reaches the shipped command.
 *
 * Run in an isolated process, never the shared suite process: many other test files call
 * pfb_global() directly, which unconditionally overwrites $pfb['chroot_cmd'] with the real
 * appliance command, so only a fresh process proves the value bootstrap.php itself seeds
 * rather than whatever a same-process neighbour left behind.
 */
#[CoversFunction('pfb_unbound_control_exec')]
final class ChrootCmdBootstrapDefaultTest extends TestCase
{
	private const SALVAGE_SECONDS = 10;

	private string $dir = '';

	protected function setUp(): void
	{
		$dir = tempnam(sys_get_temp_dir(), 'pfbchroot');
		$this->assertNotFalse($dir);
		$this->assertTrue(unlink($dir) && mkdir($dir, 0700));
		$this->dir = $dir;
	}

	protected function tearDown(): void
	{
		if ($this->dir !== '' && is_dir($this->dir)) {
			rmdir_recursive($this->dir);
		}
		$this->dir = '';
	}

	/**
	 * Given a fresh process that requires ONLY bootstrap.php -- no test sets its own
	 *   chroot_cmd, exactly like a caller that forgot to,
	 * When it runs the shared unbound-control seam directly,
	 * Then the bootstrap default recorder -- never the unset '(unset)' string and never
	 *   the real appliance chroot+unbound-control invocation -- receives the command.
	 */
	public function testControlCallerReachesTheBootstrapDefaultRecorderUntouched(): void
	{
		$runner = "{$this->dir}/runner.php";
		$out = "{$this->dir}/out.json";
		file_put_contents($runner, "<?php\n"
			. 'require ' . var_export(__DIR__ . '/bootstrap.php', TRUE) . ";\n"
			. "\$before = \$GLOBALS['pfb']['chroot_cmd'] ?? NULL;\n"
			. "\$result = [];\n"
			. "\$retval = pfb_unbound_control_exec(\"{\$before} status 2>&1 < /dev/null\", 'status', \$result);\n"
			. "\$recorderLog = \$GLOBALS['pfb_test_chroot_cmd_log'] ?? '';\n"
			. 'file_put_contents(' . var_export($out, TRUE) . ", json_encode([\n"
			. "\t'chroot_cmd' => \$before,\n"
			. "\t'retval' => \$retval,\n"
			. "\t'recorder_log' => \$recorderLog === '' ? '' : (string) @file_get_contents(\$recorderLog),\n"
			. "]));\n");

		$output = [];
		$status = 0;
		$timeout = (string) ($GLOBALS['pfb']['timeout'] ?? '/usr/bin/timeout');
		exec(escapeshellarg($timeout) . ' -s TERM -k 2 ' . self::SALVAGE_SECONDS . ' ' .
			escapeshellarg(PHP_BINARY) . ' ' . escapeshellarg($runner) . ' 2>&1', $output, $status);
		$this->assertSame(0, $status, 'the isolated runner must exit cleanly: ' . implode("\n", $output));

		$payload = json_decode((string) file_get_contents($out), TRUE);
		$this->assertIsArray($payload, 'the isolated runner must publish its JSON result');
		$this->assertNotNull($payload['chroot_cmd'],
			'the harness must default chroot_cmd before any test runs -- an untouched caller '
			. 'must never see the appliance-off "(unset)" gap');
		$this->assertNotSame('', $payload['chroot_cmd']);
		$this->assertStringNotContainsString('/usr/local/sbin/unbound-control', $payload['chroot_cmd'],
			'the untouched default must never be the real appliance chroot+unbound-control invocation');
		$this->assertSame(0, $payload['retval'], 'the bootstrap default recorder must answer successfully');
		$this->assertStringContainsString('status', $payload['recorder_log'],
			'the control verb must actually reach the bootstrap default recorder');
	}
}
