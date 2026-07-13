<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;

/**
 * issue #1255 — pfb_unbound_python() must emit the `python_tld_wildcard` ini
 * flag, derived from $pfb['dnsbl_tld'] via the SAME on/off pattern as the
 * sibling `python_hsts` key (HSTS parity: a shipped static file + an ini
 * boolean enable flag). pfb_unbound_python() needs a live pfSense/VIP/DNS
 * environment to execute end-to-end (no lighter harness exists for ANY of
 * its ini keys — python_hsts/python_idn/python_cname are pinned the same
 * source-inspection way in PythonWhitelistTldSegTest.php; true end-to-end
 * ini + Python behaviour is proven by the live-VM smoke suite), so this pins
 * the wiring at the source level: the derivation reads dnsbl_tld and the
 * heredoc emits the key.
 */
final class PythonTldWildcardIniEmitTest extends TestCase
{
	private const SRC = __DIR__ . '/../../src/usr/local/pkg/pfblockerng/pfblockerng.inc';

	/**
	 * Brace-counts from `function {$name}(` to its matching closing brace, so the
	 * assertions below inspect ONLY that function's body (mirrors
	 * PythonWhitelistTldSegTest::functionBody()).
	 */
	private function functionBody(string $name): string
	{
		$source = file_get_contents(self::SRC);
		$this->assertNotFalse($source, 'failed to read pfblockerng.inc');

		$needle = "\nfunction {$name}(";
		$start = strpos($source, $needle);
		$this->assertNotFalse($start, "function {$name}() not found in source");
		$start++; // step past the leading \n onto 'function'

		$braceOpen = strpos($source, '{', $start);
		$this->assertNotFalse($braceOpen, "no opening brace found for {$name}()");

		$depth = 0;
		for ($i = $braceOpen, $len = strlen($source); $i < $len; $i++) {
			if ($source[$i] === '{') {
				$depth++;
			} elseif ($source[$i] === '}') {
				$depth--;
				if ($depth === 0) {
					$body = substr($source, $start, $i - $start + 1);
					$this->assertNotSame('', trim($body), "empty body extracted for {$name}() -- vacuous extraction");
					return $body;
				}
			}
		}
		$this->fail("no matching closing brace found for {$name}()");
	}

	public function testPythonTldWildcardDerivedFromDnsblTld(): void
	{
		$body = $this->functionBody('pfb_unbound_python');
		$this->assertMatchesRegularExpression(
			"/\\\$python_tld_wildcard\s*=\s*'off';.*if\s*\(\s*\\\$pfb\['dnsbl_tld'\]/s",
			$body,
			'issue #1255: python_tld_wildcard must default off and flip on $pfb[\'dnsbl_tld\'] (mirrors python_hsts @ $pfb[\'dnsbl_hsts\'])'
		);
	}

	public function testManifestEmitsPythonTldWildcardKey(): void
	{
		$body = $this->functionBody('pfb_unbound_python');
		$this->assertMatchesRegularExpression(
			'/python_tld_wildcard\s*=\s*\{\$python_tld_wildcard\}/',
			$body,
			'issue #1255: the ini heredoc must carry a python_tld_wildcard key'
		);
	}
}
