<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;

/**
 * issue #3041 — PHP top-level const/define() execute in file order, never hoisted
 * (unlike functions/enums). The CLI dispatch (`if (isset($argv[1])) {`) calls
 * pfb_global() mid-file; a dispatch-referenced constant declared BELOW it is
 * undefined when the dispatch runs, fatalling every CLI invocation
 * (pfblockerng.inc filterlog|dnsbl|index).
 */
final class CliDispatchConstantOrderTest extends TestCase
{
	private const SALVAGE_SECONDS = 10;

	/**
	 * Given the real pfblockerng.inc source,
	 * When every top-level (column-0, unconditional) const/define() declaration
	 *   is compared against the CLI dispatch line,
	 * Then every one of them precedes the dispatch -- a later declaration is
	 *   unreachable from pfb_global()/the daemon branches the dispatch calls.
	 *   Pins the whole bug class, not just the six declarations issue #3041 moves.
	 */
	public function testEveryTopLevelConstantPrecedesTheCliDispatch(): void
	{
		$path = dirname(__DIR__, 2) . '/src/usr/local/pkg/pfblockerng/pfblockerng.inc';
		$lines = file($path, FILE_IGNORE_NEW_LINES);
		$this->assertNotFalse($lines, 'failed to read pfblockerng.inc');

		$dispatchLine = null;
		foreach ($lines as $i => $line) {
			if (str_starts_with($line, 'if (isset($argv[1])) {')) {
				$dispatchLine = $i + 1;
				break;
			}
		}
		$this->assertNotNull($dispatchLine, 'CLI dispatch line `if (isset($argv[1])) {` not found');

		$offenders = [];
		foreach ($lines as $i => $line) {
			$lineNo = $i + 1;
			if (preg_match('/^const\s+([A-Za-z_][A-Za-z0-9_]*)/', $line, $m)
				|| preg_match('/^define\(\s*[\'"]([A-Za-z_][A-Za-z0-9_]*)[\'"]/', $line, $m)) {
				if ($lineNo >= $dispatchLine) {
					$offenders[] = "{$m[1]} @ {$lineNo}";
				}
			}
		}

		$this->assertSame([], $offenders,
			"top-level constant(s) declared at/after the CLI dispatch (line {$dispatchLine}): "
			. implode(', ', $offenders));
	}

	/**
	 * Given a bare CLI invocation of the real pfblockerng.inc ('filterlog', the
	 *   IP filter daemon verb) with no dispatch-defusing bootstrap involved,
	 * When the include reaches the dispatch and it calls pfb_global(),
	 * Then the process exits 0 with no fatal error -- reproduces issue #3041's
	 *   64 red-smoke hits verbatim (pre-fix: exit 255, "Undefined constant
	 *   PFB_DNSBL_CONCRETE_MECHANISMS").
	 */
	public function testCliDispatchEntryRunsWithoutFatal(): void
	{
		$runner = dirname(__DIR__, 2) . '/tests/php/bin/cli_dispatch_entry.php';
		$this->assertFileExists($runner);

		$output = [];
		$status = 0;
		$timeout = (string) ($GLOBALS['pfb']['timeout'] ?? '/usr/bin/timeout');
		exec(escapeshellarg($timeout) . ' -s TERM -k 2 ' . self::SALVAGE_SECONDS . ' ' .
			escapeshellarg(PHP_BINARY) . ' ' . escapeshellarg($runner) . ' filterlog 2>&1', $output, $status);
		$rendered = implode("\n", $output);

		$this->assertSame(0, $status, "CLI dispatch entry must exit 0, got {$status}:\n{$rendered}");
		$this->assertStringNotContainsString('Fatal error', $rendered, $rendered);
		$this->assertStringNotContainsString('Undefined constant', $rendered, $rendered);
	}
}
