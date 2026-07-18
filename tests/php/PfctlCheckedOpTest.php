<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\TestCase;

/**
 * pfb_pfctl_checked_op() -- issue #1505: the one-op checked wrapper the four
 * Alerts page mutation sites (delete_ip, delete_ipwhitelist, ip_remove=lock,
 * ip_white) route through instead of a raw, status-ignored exec(). Builds a
 * single-entry pfb_live_punch_apply() plan and delegates to it -- these tests
 * pin the wrapper's own contract (op->plan mapping, return shape, escaping),
 * not pfb_live_punch_apply()'s internals (already covered by
 * AlertsLivePunchApplyTest).
 *
 * Same injectable pfctl shim pattern as AlertsLivePunchApplyTest.
 */
#[CoversFunction('pfb_pfctl_checked_op')]
final class PfctlCheckedOpTest extends TestCase
{
	private string $tmp;
	private string $shim;
	private string $logPath;
	private string $rulesPath;
	private string $table = 'pfB_Test_v4';

	protected function setUp(): void
	{
		global $pfb;

		$this->tmp = sys_get_temp_dir() . '/pfb_pfctl_checked_op_' . getmypid() . '_' . bin2hex(random_bytes(6));
		mkdir($this->tmp, 0777, TRUE);
		$this->logPath   = "{$this->tmp}/calls.log";
		$this->rulesPath = "{$this->tmp}/rules.tsv";
		putenv("PFB_TEST_LOG={$this->logPath}");
		putenv("PFB_TEST_RULES={$this->rulesPath}");
		$this->shim = $this->writeShim();

		// pfb_live_punch_apply() logs via pfb_logger() on failure -- same seeding
		// as AlertsLivePunchApplyTest.
		$pfb['logdir'] = "{$this->tmp}/log";
		$pfb['log']    = "{$pfb['logdir']}/pfblockerng.log";
		$pfb['errlog'] = "{$pfb['logdir']}/pfblockerng_error.log";
		@mkdir($pfb['logdir'], 0777, TRUE);
		@file_put_contents($pfb['log'], '');
		@file_put_contents($pfb['errlog'], '');
	}

	protected function tearDown(): void
	{
		putenv('PFB_TEST_LOG');
		putenv('PFB_TEST_RULES');
		rmdir_recursive($this->tmp);
	}

	/** Same shim shape as AlertsLivePunchApplyTest::writeShim(). */
	private function writeShim(): string
	{
		$shim = "{$this->tmp}/pfctl_shim.sh";
		file_put_contents($shim, <<<'SH'
#!/bin/sh
table=""
op=""
entry=""
while [ "$#" -gt 0 ]; do
	case "$1" in
		-t) table="$2"; shift 2 ;;
		-T) op="$2"; shift 2 ;;
		*) entry="$1"; shift ;;
	esac
done
printf '%s|%s|%s\n' "$op" "$table" "$entry" >> "$PFB_TEST_LOG"
if [ -z "$entry" ]; then
	printf 'pfctl: no address specified\n' >&2
	exit 1
fi
if [ -f "$PFB_TEST_RULES" ]; then
	while IFS='|' read -r r_op r_entry r_rc r_err; do
		if [ "$r_op" = "$op" ] && [ "$r_entry" = "$entry" ]; then
			if [ -n "$r_err" ]; then
				printf '%s\n' "$r_err" >&2
			fi
			exit "$r_rc"
		fi
	done < "$PFB_TEST_RULES"
fi
if [ "$op" = "add" ]; then
	printf '1/1 addresses added.\n'
else
	printf '1/1 addresses deleted.\n'
fi
exit 0
SH
		);
		chmod($shim, 0755);
		return $shim;
	}

	/** Script the shim to fail a specific op+entry call with $rc/$err. */
	private function scriptFailure(string $op, string $entry, int $rc, string $err): void
	{
		file_put_contents($this->rulesPath, "{$op}|{$entry}|{$rc}|{$err}\n", FILE_APPEND);
	}

	/** @return array<int,array{0:string,1:string,2:string}> [op, table, entry] rows. */
	private function readLog(): array
	{
		$content = trim((string) @file_get_contents($this->logPath));
		if ($content === '') {
			return [];
		}
		$rows = [];
		foreach (explode("\n", $content) as $line) {
			$rows[] = explode('|', $line, 3);
		}
		return $rows;
	}

	public function testOpAddEmitsDashTAddArgv(): void
	{
		$result = pfb_pfctl_checked_op($this->shim, $this->table, 'add', '198.18.0.1/32');

		$this->assertTrue($result['ok']);
		$this->assertNull($result['fail']);
		$this->assertSame([['add', $this->table, '198.18.0.1/32']], $this->readLog());
	}

	public function testOpDeleteEmitsDashTDeleteArgv(): void
	{
		$result = pfb_pfctl_checked_op($this->shim, $this->table, 'delete', '198.18.0.1/32');

		$this->assertTrue($result['ok']);
		$this->assertNull($result['fail']);
		$this->assertSame([['delete', $this->table, '198.18.0.1/32']], $this->readLog());
	}

	public function testInvalidOpThrowsInsteadOfSilentSuccess(): void
	{
		// A plan keyed by any verb pfb_live_punch_apply() does not iterate would
		// return ok=TRUE with zero execs -- the guard must refuse it loudly.
		$this->expectException(InvalidArgumentException::class);

		pfb_pfctl_checked_op($this->shim, $this->table, 'kill', '198.18.0.1/32');
	}

	public function testScriptedFailureReturnsOkFalseWithFailString(): void
	{
		$this->scriptFailure('add', '198.18.0.1/32', 1, 'pfctl: forced failure');

		$result = pfb_pfctl_checked_op($this->shim, $this->table, 'add', '198.18.0.1/32');

		$this->assertFalse($result['ok']);
		$this->assertSame('add 198.18.0.1/32', $result['fail']);
	}

	public function testScriptedDeleteFailureReturnsOkFalseWithFailString(): void
	{
		$this->scriptFailure('delete', '198.18.0.1/32', 1, 'pfctl: forced failure');

		$result = pfb_pfctl_checked_op($this->shim, $this->table, 'delete', '198.18.0.1/32');

		$this->assertFalse($result['ok']);
		$this->assertSame('delete 198.18.0.1/32', $result['fail']);
	}

	public function testHostileEntryReachesShimAsOneArgvTokenNoShellInjection(): void
	{
		$canary = "{$this->tmp}/pwned";
		$hostileEntry = "1.2.3.4;touch {$canary}";

		$result = pfb_pfctl_checked_op($this->shim, $this->table, 'add', $hostileEntry);

		$this->assertTrue($result['ok'], 'a metacharacter-laden entry must still reach pfctl as ONE literal argv, not fail the op');
		$this->assertSame(
			[['add', $this->table, $hostileEntry]],
			$this->readLog(),
			'the entry must ride as one literal argv field, never split into a second shell command'
		);
		$this->assertFileDoesNotExist($canary, 'the embedded `;touch` must never execute as a second shell command');
	}
}
