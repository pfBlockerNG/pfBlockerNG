<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;

/**
 * pfb_daemon_filterlog()'s CSV field-count guard (issue #1768).
 *
 * SyslogEventTest exercises the daemon's DNSBL stdin branch in a bounded child
 * process. This filter.log field-split path stays a pure extracted test because
 * reaching it also requires pfSense firewall state. A short/malformed filterlog
 * line (fewer space-separated fields than the BSD/syslog $f_pos offset expects) left
 * $f[$f_pos] undefined, and `explode(',', $f[$f_pos])` on that undefined
 * offset passed NULL to explode() -- a PHP 8.1+ deprecation, and part of the
 * #1768 "Passing null" gate failure.
 *
 * This test extracts the exact field-split snippet verbatim from the real
 * source (same eval-extraction technique as DnsblFreshPconfigTest/
 * AlertsFreshTopBlockTest), anchored on the unique `$log_type = 'BSD';` line
 * through the `$d = explode(',', $f[$f_pos]...)` line -- non-greedy, so the
 * regex matches whatever the RHS guard state is and survives the fix -- and
 * runs it as a pure function of $line.
 */
final class FilterlogFieldGuardTest extends TestCase
{
	public static function setUpBeforeClass(): void
	{
		$src = file_get_contents(
			dirname(__DIR__, 2) . '/src/usr/local/pkg/pfblockerng/pfblockerng.inc'
		);
		if ($src === FALSE) {
			throw new RuntimeException('test bootstrap: failed to read pfblockerng.inc');
		}

		if (!function_exists('pfb_filterlog_oracle_field_guard')) {
			if (!preg_match(
				'/(\$log_type = \'BSD\';\n.*?\n\s*\$d = explode\(\',\', \$f\[\$f_pos\][^\n]*\n)/s',
				$src,
				$m
			)) {
				throw new RuntimeException('test bootstrap: filterlog field-split snippet not found');
			}
			eval(
				'function pfb_filterlog_oracle_field_guard(string $line): array {'
				. $m[1]
				. ' return [$f_pos, $f, $d]; }'
			);
		}
	}

	/** @return array{0: array, 1: string[]} [[$f_pos, $f, $d], $diagnostics] */
	private function runCapturingDiagnostics(string $line): array
	{
		$diagnostics = [];
		set_error_handler(static function (int $errno, string $errstr) use (&$diagnostics): bool {
			$diagnostics[] = $errstr;
			return TRUE;
		}, E_WARNING | E_DEPRECATED);
		try {
			$result = pfb_filterlog_oracle_field_guard($line);
		} finally {
			restore_error_handler();
		}
		return [$result, $diagnostics];
	}

	public function testShortBsdLineDoesNotPassNullToExplode(): void
	{
		// BSD format: $f_pos = 5. Only 3 space-separated fields -- $f[5] is
		// undefined.
		[[$f_pos, $f, $d], $diagnostics] = $this->runCapturingDiagnostics('a b c');

		$this->assertSame(5, $f_pos);
		$this->assertArrayNotHasKey(5, $f);
		$this->assertSame(
			[],
			$diagnostics,
			"short BSD-format line must emit zero diagnostics, got:\n" . implode("\n", $diagnostics)
		);
		$this->assertSame([''], $d);
	}

	public function testShortSyslogLineDoesNotPassNullToExplode(): void
	{
		// A leading '<' selects syslog format: $f_pos = 7. Only 3
		// space-separated fields -- $f[7] is undefined.
		[[$f_pos, $f, $d], $diagnostics] = $this->runCapturingDiagnostics('<14>a b c');

		$this->assertSame(7, $f_pos);
		$this->assertArrayNotHasKey(7, $f);
		$this->assertSame(
			[],
			$diagnostics,
			"short syslog-format line must emit zero diagnostics, got:\n" . implode("\n", $diagnostics)
		);
		$this->assertSame([''], $d);
	}

	public function testLongEnoughBsdLineFieldPassesThroughUnchanged(): void
	{
		// Axis 2: a line WITH a field at $f_pos must still reach $d unchanged
		// (the guard is a no-op when the field is present).
		$line = 'a b c d e tracker,extra';
		[[$f_pos, $f, $d], $diagnostics] = $this->runCapturingDiagnostics($line);

		$this->assertSame(5, $f_pos);
		$this->assertSame('tracker,extra', $f[5]);
		$this->assertSame([], $diagnostics);
		$this->assertSame(['tracker', 'extra'], $d);
	}
}
