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

	public function testNoWriterRewritesTheDecidersInputsOrUnboundTmpInPlace(): void
	{
		$found = [];
		foreach (['pfblockerng.inc', 'pfblockerng_apply.inc'] as $file) {
			preg_match_all('/file_put_contents\s*\([^;]*?(?:unbound_py_(?:conf|wh|ss)\b|unbound\.tmp|\$ss_file\b)[^;]*;/', self::source($file), $hits);
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

	/** Issue #4201: the apply publishes the whole CSV of every host, and flags the reload only when it was replaced. */
	public function testTheApplyPublishesTheSafeSearchCsvAndReloadsOnlyWhenItWasReplaced(): void
	{
		$this->assertMatchesRegularExpression(
			'/if\s*\(\s*pfb_ss_publish\(\s*pfb_ss_csv\(\s*\$safesearch_hosts\s*\)\s*\)\s*\)\s*\{\s*\$safesearch_update\s*=\s*TRUE;\s*touch\("\{\$pfb\[\'dnsbl_file\'\]\}\.reload"\);\s*\}/',
			self::source('pfblockerng_apply.inc')
		);
	}

	/** Issue #4201: an aborted removal writes the DNS proxy's module ini again, whole. */
	public function testAnAbortedRemovalWritesTheModuleIniWhole(): void
	{
		$code = self::source('pfblockerng.inc');
		$recover = substr($code, (int) strpos($code, 'function pfb_package_removal_recover('));
		$recover = substr($recover, 0, (int) strpos($recover, 'function ', 1));
		$this->assertStringContainsString("pfb_unbound_py_atomic_write(\$pfb['unbound_py_conf'], pfb_unbound_python_ini('enabled'))", $recover);
	}
}
