<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\TestCase;

/**
 * ADR-66 Phase 1 -- the PHP-side halves of the two TLD cross-language
 * bridges (the Python-side reader halves live in
 * tests/test_adr66_tld_bridges.py, sharing the same key-name seam so a
 * half-renamed bridge fails loudly in Phases 2/3).
 *
 * C1 -- ini bridge writer: pfb_unbound_python() derives tld_allow/
 * tld_allow_list from $pfb['dnsbl_tld_allow'] + the four pfb_pytlds_{gtld,cctld,
 * itld,bgtld} config fields and emits them into the MAIN-ini heredoc
 * (mirrors PythonTldWildcardIniEmitTest.php's structural pin -- no lighter
 * harness exists for pfb_unbound_python(), a live pfSense/VIP/DNS
 * environment; true end-to-end ini + Python behaviour is proven by the
 * live-VM smoke suite).
 *
 * C3 -- manifest bridge writer: a LIVE call of pfb_unbound_python_sources()
 * (mirrors UnboundPythonSourcesTest.php's $pfb setup) proving
 * config.tld_blacklist/tld_exclusion carry the configured values when
 * $pfb['dnsbl_tld'] is truthy, and are emptied when falsy.
 */
#[CoversFunction('pfb_unbound_python')]
#[CoversFunction('pfb_unbound_python_sources')]
final class TldBridgeEmitTest extends TestCase
{
	private const SRC = __DIR__ . '/../../src/usr/local/pkg/pfblockerng/pfblockerng.inc';

	private string $tmp;
	private bool $hadPfb = false;
	private array $originalPfb = [];

	protected function setUp(): void
	{
		$this->hadPfb = array_key_exists('pfb', $GLOBALS);
		$this->originalPfb = $GLOBALS['pfb'] ?? [];

		$this->tmp = sys_get_temp_dir() . '/pfb_tldbridge_' . uniqid('', true);
		mkdir("{$this->tmp}/dnsbl", 0777, true);
		mkdir("{$this->tmp}/db", 0777, true);

		$GLOBALS['pfb'] = array_merge($GLOBALS['pfb'] ?? [], [
			'log'                => "{$this->tmp}/pfblockerng.log",
			'errlog'             => "{$this->tmp}/error.log",
			'unbound_py_rawdir'  => "{$this->tmp}/pfb_py_raw",
			'dnsdir'             => "{$this->tmp}/dnsbl",
			'unbound_py_sources' => "{$this->tmp}/pfb_py_sources.json",
			'dbdir'              => "{$this->tmp}/db",
			'dnsbl_top1m'        => 'off',
			'dnsbl_tld_data'     => "{$this->tmp}/does_not_exist",
			'dnsbl_unlock'       => "{$this->tmp}/dnsbl_unlock",
			'dnsbl_tld'          => '',
			'dnsblconfig'        => [
				'tldblacklist' => '',
				'tldexclusion' => '',
				'suppression'  => '',
			],
		]);
	}

	protected function tearDown(): void
	{
		if ($this->hadPfb) {
			$GLOBALS['pfb'] = $this->originalPfb;
		} else {
			unset($GLOBALS['pfb']);
		}

		rmdir_recursive($this->tmp);
	}

	/**
	 * Brace-counts from `function {$name}(` to its matching closing brace
	 * (mirrors PythonTldWildcardIniEmitTest::functionBody()).
	 */
	private function functionBody(string $name): string
	{
		$source = file_get_contents(self::SRC);
		$this->assertNotFalse($source, 'failed to read pfblockerng.inc');

		$needle = "\nfunction {$name}(";
		$start = strpos($source, $needle);
		$this->assertNotFalse($start, "function {$name}() not found in source");
		$start++;

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

	// ------------------------------------------------------------------ //
	// C1 -- ini bridge writer (structural).
	// ------------------------------------------------------------------ //
	public function testIniWriterDerivesTldAllowFromDnsblPytld(): void
	{
		$body = $this->functionBody('pfb_unbound_python');
		$this->assertMatchesRegularExpression(
			"/\\\$tld_allow\s*=\s*'off';\s*\\\$tld_allow_list\s*=\s*'';\s*if\s*\(\s*\\\$pfb\['dnsbl_tld_allow'\]\s*==\s*'on'\s*\)/s",
			$body,
			'the tld_allow/tld_allow_list pair must default off/empty and derive from $pfb[\'dnsbl_tld_allow\']'
		);
	}

	public function testIniWriterReadsAllFourPytldsConfigFields(): void
	{
		$body = $this->functionBody('pfb_unbound_python');
		foreach (['pfb_pytlds_gtld', 'pfb_pytlds_cctld', 'pfb_pytlds_itld', 'pfb_pytlds_bgtld'] as $field) {
			$this->assertStringContainsString(
				"dnsblconfig']['{$field}']",
				$body,
				"pfb_unbound_python() must read dnsblconfig['{$field}'] into tld_allow_list"
			);
		}
	}

	public function testIniHeredocEmitsTldAllowKeys(): void
	{
		$body = $this->functionBody('pfb_unbound_python');
		$this->assertMatchesRegularExpression(
			'/tld_allow\s*=\s*\{\$tld_allow\}/',
			$body,
			'the ini heredoc must carry a tld_allow key'
		);
		$this->assertMatchesRegularExpression(
			'/tld_allow_list\s*=\s*\{\$tld_allow_list\}/',
			$body,
			'the ini heredoc must carry a tld_allow_list key'
		);
	}

	// ------------------------------------------------------------------ //
	// C3 -- manifest bridge writer (live call).
	// ------------------------------------------------------------------ //
	public function testManifestTldKeysEmptyWhenDnsblTldOff(): void
	{
		$GLOBALS['pfb']['dnsbl_tld'] = '';
		$GLOBALS['pfb']['dnsblconfig']['tldblacklist'] = base64_encode('evil-tld');
		$GLOBALS['pfb']['dnsblconfig']['tldexclusion'] = base64_encode('good.example');

		$m = pfb_unbound_python_sources([]);

		$this->assertSame([], $m['config']['tld_blacklist'], 'OFF must empty tld_blacklist even though it was configured');
		$this->assertSame([], $m['config']['tld_exclusion'], 'OFF must empty tld_exclusion even though it was configured');
	}

	public function testManifestTldKeysPopulatedWhenDnsblTldOn(): void
	{
		$GLOBALS['pfb']['dnsbl_tld'] = 'on';
		$GLOBALS['pfb']['dnsblconfig']['tldblacklist'] = base64_encode('evil-tld');
		$GLOBALS['pfb']['dnsblconfig']['tldexclusion'] = base64_encode('good.example');

		$m = pfb_unbound_python_sources([]);

		$this->assertSame(['evil-tld'], $m['config']['tld_blacklist'], 'ON must populate tld_blacklist from config');
		$this->assertSame(['good.example'], $m['config']['tld_exclusion'], 'ON must populate tld_exclusion from config');
	}
}
