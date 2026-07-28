<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\TestCase;

/**
 * Pin the JSON-encoding contract of the Update page's AJAX live-log-tail endpoint
 * (pfblockerng_update.php, ?ajax=tail branch):
 * print(json_encode(pfb_log_tail_payload(...))). An invalid-UTF-8 byte in the
 * tailed log line must not make json_encode() return FALSE -- print(FALSE) is an
 * empty response body, which fails the client's JSON.parse() and stalls the live
 * tail (issue #1814).
 *
 * Reachability: the ?ajax=tail branch is top-level code (before any function
 * definition) that calls exit() right after the print(), and needs
 * guiconfig.inc's session/webConfigurator runtime -- the same reachability gap
 * already documented for pfblockerng_lint.php's endpoint (see
 * LintEndpointWiringTest::testJsonEncodeCarriesInvalidUtf8Substitute, which pins
 * that endpoint's identical JSON_INVALID_UTF8_SUBSTITUTE contract the same way)
 * and for pfblockerng_dnsbl.php/pfblockerng_edit_hooks.php's page renders. This
 * class follows that established convention:
 *   - testJsonEncodeCallSiteCarriesInvalidUtf8SubstituteFlag pins the exact
 *     call-site source text -- a REAL red-before/green-after proof (fails until
 *     the production line carries the flag, unlike an equivalence check).
 *   - testInvalidUtf8SubstituteFlagFixesEncodingOfTailedInvalidByte is an
 *     equivalence/documentation test against the real pfb_log_tail_payload()
 *     output shape: it demonstrates the defect + fix mechanics on an actual
 *     hostile payload, but -- since it does not read the production file -- it
 *     cannot itself flip red/green off the production edit (see this change's
 *     handoff for the recorded deviation).
 */
#[CoversFunction('pfb_log_tail_payload')]
final class UpdateAjaxTailJsonEncodingTest extends TestCase
{
	private const UPDATE_PAGE_PATH = __DIR__ . '/../../src/usr/local/www/pfblockerng/pfblockerng_update.php';
	private const UPDATE_PID = '/var/run/pfb_runnow.pid';

	protected function setUp(): void
	{
		global $pfb;
		@mkdir($pfb['logdir'], 0777, TRUE);
		@file_put_contents($pfb['runlog'], '');
		@file_put_contents($pfb['log'], '');
		$GLOBALS['pfb_test_valid_pids'] = [];
	}

	protected function tearDown(): void
	{
		$GLOBALS['pfb_test_valid_pids'] = [];
	}

	public function testJsonEncodeCallSiteCarriesInvalidUtf8SubstituteFlag(): void
	{
		$src = file_get_contents(self::UPDATE_PAGE_PATH);
		$this->assertNotFalse($src, 'test oracle: failed to read ' . self::UPDATE_PAGE_PATH);

		$anchor = 'print(json_encode(pfb_log_tail_payload(';
		$pos = strpos($src, $anchor);
		$this->assertNotFalse($pos, 'the ajax=tail endpoint must call print(json_encode(pfb_log_tail_payload(...)))');

		// pfb_log_tail_payload(...)'s own arguments contain nested parens (e.g. "(int)
		// $_GET['offset']"), so a naive "up to the next )" scan would stop inside them.
		// The statement is single-line in production; bound the scan to that line instead.
		$eol = strpos($src, "\n", $pos);
		$this->assertNotFalse($eol, 'test oracle: could not find the end of the call-site line');
		$line = substr($src, $pos, $eol - $pos);

		$this->assertStringContainsString(
			'JSON_INVALID_UTF8_SUBSTITUTE',
			$line,
			'the ajax=tail json_encode(...) call must pass JSON_INVALID_UTF8_SUBSTITUTE -- else an invalid ' .
				'byte in the tailed log line makes json_encode() return FALSE (print(FALSE) => empty body => ' .
				'the client JSON.parse() fails and the live tail stalls)'
		);
	}

	public function testInvalidUtf8SubstituteFlagFixesEncodingOfTailedInvalidByte(): void
	{
		global $pfb;
		// Finished-run branch (deterministic single read, no polling state to juggle): a
		// tailed line ending in a lone invalid lead byte (the byte-substr/log-rotation shape).
		file_put_contents($pfb['runlog'], "line one\nbad line \xFF end");
		$GLOBALS['pfb_test_valid_pids'][self::UPDATE_PID] = FALSE; // process gone -> flush trailing partial

		$payload = pfb_log_tail_payload('update', -1, FALSE);
		$this->assertStringContainsString("\xFF", $payload['data'], 'test oracle: the invalid byte must reach the payload');

		// Pre-fix: exactly what the ajax=tail call site did before JSON_INVALID_UTF8_SUBSTITUTE
		// was added -- an invalid byte anywhere in the payload makes json_encode() return FALSE.
		$this->assertFalse(json_encode($payload), 'documents the pre-fix defect: an invalid UTF-8 byte makes json_encode() return FALSE');

		// Post-fix: the flag the call site now carries.
		$json = json_encode($payload, JSON_INVALID_UTF8_SUBSTITUTE);
		$this->assertNotFalse($json, 'with the flag, an invalid byte must not make json_encode() return FALSE');
		$this->assertTrue(mb_check_encoding($json, 'UTF-8'), 'the JSON body must be valid UTF-8');
		// json_encode() escapes non-ASCII as the literal backslash-u-f-f-f-d text (no
		// JSON_UNESCAPED_UNICODE), so decode back to check for the actual U+FFFD codepoint
		// rather than string-searching the escaped JSON text.
		$decoded = json_decode($json, TRUE);
		$this->assertIsArray($decoded, 'the JSON must decode back to an array');
		$this->assertStringContainsString("\u{FFFD}", $decoded['data'], 'the invalid byte must be substituted with U+FFFD, not dropped');
	}
}
