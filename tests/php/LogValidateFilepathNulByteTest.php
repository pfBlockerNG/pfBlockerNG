<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\TestCase;

/**
 * Pin pfb_validate_filepath() against a NUL byte anywhere in the candidate path
 * (issue #1126): the function validates only pathinfo()'s DIRNAME against the
 * logdir allowlist and never rejects an embedded "\0", so a NUL-laced basename
 * passes validation and then reaches fopen()/glob()/unlink() -- each throws an
 * uncaught PHP 8 ValueError ("must not contain any null bytes"), an
 * @-unsuppressible fatal the validator's #1097 FALSE-return guards cannot
 * intercept (it fires INSIDE the call, before any return value exists).
 *
 * The function is loaded off-appliance via LogPageLoader.php (it takes
 * $pfb_logtypes as a plain parameter, so no page-level fixture/global is needed).
 */
#[CoversFunction('pfb_validate_filepath')]
final class LogValidateFilepathNulByteTest extends TestCase
{
	public static function setUpBeforeClass(): void
	{
		require_once __DIR__ . '/LogPageLoader.php';
		pfb_test_load_log_page_functions();
	}

	/** A $pfb_logtypes fixture shaped like the real page's: 'logdir' keys carry a trailing slash. */
	private function logtypes(): array
	{
		return [
			'defaultlogs' => ['logdir' => '/var/log/pfblockerng/'],
			'python'      => ['logdir' => '/var/unbound/'],
		];
	}

	// --- Genuinely RED before the fix: a NUL anywhere in the FINAL path segment
	// passes the allowlist because pathinfo(..., PATHINFO_DIRNAME) never sees it
	// (the NUL lives in the basename, not the dirname the function checks). ---

	public function testTrailingNulOnAllowedFileIsRejected(): void
	{
		// issue #1126's exact reported shape: logFile=<allowed-dir>/py_error.log%00
		$this->assertFalse(
			pfb_validate_filepath("/var/log/pfblockerng/py_error.log\0", $this->logtypes())
		);
	}

	public function testNulPrefixingBasenameIsRejected(): void
	{
		$this->assertFalse(
			pfb_validate_filepath("/var/log/pfblockerng/\0foo.log", $this->logtypes())
		);
	}

	public function testNulEmbeddedMidBasenameIsRejected(): void
	{
		$this->assertFalse(
			pfb_validate_filepath("/var/log/pfblockerng/py\0error.log", $this->logtypes())
		);
	}

	// --- Before-state / no-regression controls (CLAUDE.md "assert the
	// before-state", "branch coverage") -- unchanged by the fix. ---

	public function testBareNulIsRejected(): void
	{
		$this->assertFalse(pfb_validate_filepath("\0", $this->logtypes()));
	}

	public function testCleanAllowedPathStillAccepted(): void
	{
		// Over-rejection control: the guard must not touch a clean, allowed path.
		$this->assertTrue(
			pfb_validate_filepath('/var/log/pfblockerng/ok.log', $this->logtypes())
		);
	}

	public function testCleanDisallowedDirStillRejected(): void
	{
		$this->assertFalse(pfb_validate_filepath('/etc/passwd', $this->logtypes()));
	}

	public function testEmptyStringStillRejected(): void
	{
		$this->assertFalse(pfb_validate_filepath('', $this->logtypes()));
	}

	public function testNulPlusTraversalAlreadyRejectedByDirnameAllowlist(): void
	{
		// A NUL combined with a '../' traversal does NOT additionally defeat the
		// allowlist: pathinfo()'s dirname computation never resolves '..', so the
		// traversal segments stay literally in the dirname string and the isset()
		// lookup already misses -- independent of, and unchanged by, the NUL guard.
		$this->assertFalse(
			pfb_validate_filepath('/var/log/pfblockerng/a' . "\0" . '/../../../etc/passwd', $this->logtypes())
		);
	}

	public function testVarUnboundPfbPrefixedFileStillAccepted(): void
	{
		// The /var/unbound/ carve-out for pfb_-prefixed files must survive the
		// guard: no NUL present, so this row's value is untouched by the fix.
		$this->assertTrue(
			pfb_validate_filepath('/var/unbound/pfb_dnsbl.log', $this->logtypes())
		);
	}

	public function testVarUnboundNonPfbNonexistentFileStillRejected(): void
	{
		// Not pfb_-prefixed, and the CWD-relative file_exists() check (a
		// pre-existing quirk of the carve-out, not this fix's concern) can't find
		// it here, so the carve-out's early FALSE fires -- unchanged by the guard.
		$this->assertFalse(
			pfb_validate_filepath('/var/unbound/uuid-9f3e7c21-4a11-nonexistent', $this->logtypes())
		);
	}
}
