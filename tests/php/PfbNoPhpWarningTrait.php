<?php

declare(strict_types=1);

/**
 * Asserts a callable runs without raising a PHP warning.
 *
 * The margin guards' window arithmetic overflows to a float on an out-of-range
 * margin, and PHP's (int) cast of an unrepresentable float both warns AND yields
 * 0 -- a zero retention window wipes the log (issue #1258). The warning is the
 * tell, so the hostile-margin rows assert its absence rather than only the value.
 *
 * Shared by LogTrimNeededTest and LogAgeTrimNeededTest: one definition, so a change
 * to what counts as a warning (E_NOTICE, E_DEPRECATED) cannot drift between them.
 */
trait PfbNoPhpWarningTrait
{
	/** Runs $fn under a handler that records E_WARNING instead of printing it; fails the test if any fired. */
	private function assertNoPhpWarning(callable $fn): mixed
	{
		$warnings = [];
		set_error_handler(static function (int $errno, string $errstr) use (&$warnings): bool {
			$warnings[] = $errstr;
			return TRUE;
		}, E_WARNING);
		try {
			$result = $fn();
		} finally {
			restore_error_handler();
		}
		$this->assertSame([], $warnings, 'must not trigger a PHP warning: ' . implode('; ', $warnings));
		return $result;
	}
}
