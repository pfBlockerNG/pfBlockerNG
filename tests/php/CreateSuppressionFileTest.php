<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\TestCase;

/**
 * pfb_create_suppression_file() -- ADR-53 Phase 6: decodes the v4/v6 suppression
 * customlists into the on-disk files the alias-build loop's suppression engines
 * read (pfbsuppression.txt / pfbsuppression_v6.txt). Previously uncovered by
 * PHPUnit -- this file covers BOTH the pre-existing v4 behaviour (a regression
 * pin) and the NEW v6 sibling this phase adds (the red->green wiring proof).
 *
 * BEHAVIOUR CHANGE (ADR-53 Phase 6): before this phase, pfb_create_suppression_file()
 * knew only v4suppression -- $pfb['supptxt_v6'] did not exist and no
 * pfbsuppression_v6.txt was ever written, regardless of $pfb['ipconfig']['v6suppression'].
 * testV6SuppressionWrittenToOwnFile() and testBothFamiliesWrittenIndependently() are the
 * red->green proof: both FAIL (undefined array key / missing file) against the pre-Phase-6
 * function and PASS once the v6 branch lands.
 *
 * pfbng_text_area_decode(text, FALSE, TRUE) (the mode pfb_create_suppression_file() uses)
 * lowercases + trims each non-comment, non-blank line and joins with a single "\n" --
 * NOT the original "\r\n" -- so the expected file content below reflects that shape.
 */
#[CoversFunction('pfb_create_suppression_file')]
final class CreateSuppressionFileTest extends TestCase
{
	private string $dir;

	protected function setUp(): void
	{
		$this->dir = sys_get_temp_dir() . '/pfb_supptxt_test_' . getmypid() . '_' . uniqid();
		mkdir($this->dir, 0777, TRUE);
		$GLOBALS['pfb']['supptxt']    = "{$this->dir}/pfbsuppression.txt";
		$GLOBALS['pfb']['supptxt_v6'] = "{$this->dir}/pfbsuppression_v6.txt";
		$GLOBALS['pfb']['ipconfig']   = ['v4suppression' => '', 'v6suppression' => ''];
	}

	protected function tearDown(): void
	{
		@unlink($GLOBALS['pfb']['supptxt']);
		@unlink($GLOBALS['pfb']['supptxt_v6']);
		@rmdir($this->dir);
	}

	// --- v4: pre-existing behaviour, pinned here as a regression oracle ---

	public function testV4SuppressionWrittenToOwnFile(): void
	{
		$GLOBALS['pfb']['ipconfig']['v4suppression'] = base64_encode("10.0.0.1/32\r\n");

		pfb_create_suppression_file();

		$this->assertFileExists($GLOBALS['pfb']['supptxt']);
		$this->assertSame("10.0.0.1/32\n", file_get_contents($GLOBALS['pfb']['supptxt']));
	}

	public function testV4SuppressionAbsentUnlinksExistingFile(): void
	{
		file_put_contents($GLOBALS['pfb']['supptxt'], 'stale content');
		$GLOBALS['pfb']['ipconfig']['v4suppression'] = '';

		pfb_create_suppression_file();

		$this->assertFileDoesNotExist($GLOBALS['pfb']['supptxt'], 'empty v4suppression must unlink the stale file');
	}

	// --- v6: NEW in Phase 6 -- the red->green wiring proof ---

	public function testV6SuppressionWrittenToOwnFile(): void
	{
		$GLOBALS['pfb']['ipconfig']['v6suppression'] = base64_encode("2001:db8::1/128\r\n");

		pfb_create_suppression_file();

		$this->assertFileExists($GLOBALS['pfb']['supptxt_v6'], 'ADR-53 Phase 6: pfbsuppression_v6.txt must now be written');
		$this->assertSame("2001:db8::1/128\n", file_get_contents($GLOBALS['pfb']['supptxt_v6']));
	}

	public function testV6SuppressionAbsentUnlinksExistingFile(): void
	{
		file_put_contents($GLOBALS['pfb']['supptxt_v6'], 'stale content');
		$GLOBALS['pfb']['ipconfig']['v6suppression'] = '';

		pfb_create_suppression_file();

		$this->assertFileDoesNotExist($GLOBALS['pfb']['supptxt_v6'], 'empty v6suppression must unlink the stale file');
	}

	public function testBothFamiliesWrittenIndependently(): void
	{
		$GLOBALS['pfb']['ipconfig']['v4suppression'] = base64_encode("10.0.0.1/32\r\n");
		$GLOBALS['pfb']['ipconfig']['v6suppression'] = base64_encode("2001:db8::1/128\r\n");

		pfb_create_suppression_file();

		$this->assertSame("10.0.0.1/32\n", file_get_contents($GLOBALS['pfb']['supptxt']), 'v4 file must hold only the v4 entry');
		$this->assertSame("2001:db8::1/128\n", file_get_contents($GLOBALS['pfb']['supptxt_v6']), 'v6 file must hold only the v6 entry');
	}

	// --- ADR-53 adversarial-review finding B: the key ABSENT (not merely '') ---
	//
	// setUp() always seeds ['v4suppression' => '', 'v6suppression' => ''] --
	// this masks a real PHP8 "undefined array key" warning that fires on every
	// install whose config predates a save of these keys (v6suppression is
	// NEVER install-migrated; v4suppression only migrates when a legacy
	// pfBlockerNGSuppress alias existed). PHPUnit does not fail a test merely
	// for triggering a PHP warning (verified: a bare `$arr['missing']` read
	// reports "OK, but there were issues!" with exit 0, not a failure) -- these
	// tests install their own error handler and assert zero warnings were
	// raised, so the fix is actually enforced.

	private function assertNoWarningsDuring(callable $fn, string $message): void
	{
		$warnings = [];
		set_error_handler(static function (int $errno, string $errstr) use (&$warnings): bool {
			$warnings[] = $errstr;
			return true; // swallow -- we assert on the collected list instead
		}, E_WARNING);

		try {
			$fn();
		} finally {
			restore_error_handler();
		}

		$this->assertSame([], $warnings, $message . '; got: ' . var_export($warnings, TRUE));
	}

	public function testV4SuppressionKeyAbsentDoesNotWarn(): void
	{
		// The key is literally UNSET, not ''.
		unset($GLOBALS['pfb']['ipconfig']['v4suppression']);

		$this->assertNoWarningsDuring(
			static function (): void {
				pfb_create_suppression_file();
			},
			'pfb_create_suppression_file() must not emit a PHP8 "undefined array key" warning '
				. 'when v4suppression is absent from config (every install until its first save)'
		);
	}

	public function testV6SuppressionKeyAbsentDoesNotWarn(): void
	{
		unset($GLOBALS['pfb']['ipconfig']['v6suppression']);

		$this->assertNoWarningsDuring(
			static function (): void {
				pfb_create_suppression_file();
			},
			'pfb_create_suppression_file() must not emit a PHP8 "undefined array key" warning '
				. 'when v6suppression is absent from config (never install-migrated, so absent '
				. 'on every install until the IP-settings page is saved once post-upgrade)'
		);
	}
}
