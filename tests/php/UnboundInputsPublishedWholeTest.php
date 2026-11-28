<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;

/**
 * Issue #4201: the files Unbound and the DNS gateway's decider load from /var/unbound are published whole, through
 * pfb_unbound_py_atomic_write(): a staged file beside the target, synced, then renamed over it. An in-place
 * file_put_contents() truncates the target first, so a kill or a full disk left a truncated file to load. The behavioural
 * tests beside each writer cut a write short; this pins the writers no cheap harness reaches (the aborted-removal recovery and
 * the apply's SafeSearch block) by source, as CrowdsecWiringTest does.
 */
final class UnboundInputsPublishedWholeTest extends TestCase
{
	private static function source(string $relative): string
	{
		return (string) php_strip_whitespace(dirname(__DIR__, 2) . "/src/usr/local/pkg/pfblockerng/{$relative}");
	}

	private const IN_PLACE_WRITE = '/file_put_contents\s*\([^;]*?(?:unbound_py_(?:conf|wh|ss)\b|unbound\.tmp|\$ss_file\b)[^;]*;/';

	/** The detector below finds each in-place write it exists to forbid. */
	public function testTheInPlaceWriteDetectorFindsEachForbiddenWrite(): void
	{
		foreach ([
			"@file_put_contents(\$pfb['unbound_py_conf'], \$pfb_py_conf, LOCK_EX);",
			"@file_put_contents(\$pfb['unbound_py_wh'], \$dnsbl_whitelist, LOCK_EX);",
			"file_put_contents(\$pfb['unbound_py_ss'], \$rows);",
			"@file_put_contents(\$ss_file, \$csv, FILE_APPEND);",
			"@file_put_contents(\"{\$pfb['dnsbldir']}/unbound.tmp\", \$conf, LOCK_EX);",
		] as $write) {
			$this->assertSame(1, preg_match(self::IN_PLACE_WRITE, $write), $write);
		}
	}

	public function testNoWriterRewritesTheDecidersInputsOrUnboundTmpInPlace(): void
	{
		$found = [];
		foreach (['pfblockerng.inc', 'pfblockerng_apply.inc'] as $file) {
			preg_match_all(self::IN_PLACE_WRITE, self::source($file), $hits);
			foreach ($hits[0] as $hit) {
				$found[] = "{$file}: {$hit}";
			}
		}
		$this->assertSame([], $found, 'every one of these goes through pfb_unbound_py_atomic_write()');
	}

	public function testTheSafeSearchCsvIsNotBuiltInAStagingFileAPassCanLeaveBehind(): void
	{
		$this->assertStringNotContainsString('pfb_py_ss.raw', self::source('pfblockerng_apply.inc'),
			'rows appended to a staging file a killed pass left were published by the next pass');
	}

	/** Issue #4201: an aborted removal writes the DNS proxy's module ini again, whole. */
	public function testAnAbortedRemovalWritesTheModuleIniWhole(): void
	{
		$code = self::source('pfblockerng.inc');
		$recover = substr($code, (int) strpos($code, 'function pfb_package_removal_recover('));
		$recover = substr($recover, 0, (int) strpos($recover, 'function ', 1));
		$this->assertStringContainsString("pfb_unbound_py_atomic_write(\$pfb['unbound_py_conf'], pfb_unbound_python_ini('enabled'))", $recover);
	}

	/** Issue #4201: the pass makes its patch live only through pfb_unbound_conf_publish(), which keeps a whole backup first. */
	public function testThePassPublishesItsUnboundConfPatchWithAWholeBackup(): void
	{
		$code = self::source('pfblockerng.inc');
		$update = substr($code, (int) strpos($code, 'function pfb_update_unbound('));
		$update = substr($update, 0, (int) strpos($update, 'function ', 1));
		$this->assertMatchesRegularExpression('/if\s*\(\s*!\s*pfb_unbound_conf_publish\(\$pfb\[\'dnsbldir\'\]\)\s*\)\s*\{\s*pfb_logger\(/', $update,
			'a patch that did not go live is reported, not passed over');
		$this->assertStringNotContainsString('unbound.bk"', $update, 'no backup of its own beside the helper');
	}
}
