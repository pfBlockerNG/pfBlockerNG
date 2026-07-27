<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\TestCase;

/**
 * XMLRPC sync target IDN punycode conversion (issue #1778).
 *
 * #1731 widened PFB_FILTER_HOSTNAME to accept an IDN sync target at save time
 * (pfblockerng_sync.php:104), but pfblockerng_sync_on_changes()'s runtime gate
 * (is_ipaddr/is_hostname/is_domain, ~17186) and pfblockerng_do_xmlrpc_sync()'s
 * connection (setConnectionData(), ~17288) stayed bare-ASCII -- a saved Unicode
 * target saved cleanly and then failed every sync attempt. The fix
 * punycode-converts $sync_to_ip at the point of use, immediately after it is
 * read from config and before the gate; the original is kept for the
 * human-facing log lines.
 *
 * Unlike a top-level-executing page (pfblockerng_category_edit.php,
 * CategoryEditPostGuardTest), pfblockerng.inc is require_once'd WHOLE by the
 * test bootstrap, so pfblockerng_sync_on_changes() is a real, directly
 * callable function here -- no eval-extraction needed. Reaching the real
 * XMLRPC connection call (rather than hand-copying the gate) needs a double
 * for pfSense's xmlrpc_client.inc: pfsense_xmlrpc_client
 * (tests/php/pfsense_doubles.php) captures setConnectionData()'s argument
 * into $GLOBALS['pfb_test_xmlrpc_connection'] instead of dialing out, backed
 * by an empty satisfies-require_once() shim (tests/php/shims/xmlrpc_client.inc).
 */
#[CoversFunction('pfblockerng_sync_on_changes')]
final class XmlrpcSyncIdnTargetTest extends TestCase
{
	private mixed $savedConfig = null;

	protected function setUp(): void
	{
		$this->savedConfig = $GLOBALS['config'] ?? null;
		unset($GLOBALS['pfb_test_xmlrpc_connection']);
	}

	protected function tearDown(): void
	{
		if ($this->savedConfig === null) {
			unset($GLOBALS['config']);
		} else {
			$GLOBALS['config'] = $this->savedConfig;
		}
		unset($GLOBALS['pfb_test_xmlrpc_connection']);
	}

	private function seedSyncConfig(string $target): void
	{
		$GLOBALS['config'] = [
			'installedpackages' => [
				'pfblockerngsync' => [
					'config' => [
						0 => [
							'varsynconchanges' => 'manual',
							'varsynctimeout'   => 5,
							'row' => [
								0 => [
									'varsyncdestinenable' => true,
									'varsyncipaddress'    => $target,
									'varsyncport'         => 443,
									'varsyncpassword'     => 'secret',
									'varsyncprotocol'     => 'https',
									'varsyncusername'     => 'admin',
								],
							],
						],
					],
				],
			],
		];
	}

	// --- red-first: the defect this issue fixes -----------------------------

	public function testIdnTargetReachesConnectionAsPunycode(): void
	{
		// 'bücher.example' <-> 'xn--bcher-kva.example' is the same IDN/punycode
		// pair PfbFilterContractTest pins for PFB_FILTER_HOSTNAME (#1731) -- the
		// save-time filter already accepts this exact target.
		$this->seedSyncConfig('bücher.example');
		pfblockerng_sync_on_changes();

		$this->assertArrayHasKey(
			'pfb_test_xmlrpc_connection',
			$GLOBALS,
			'a valid IDN target must pass the runtime gate and reach the XMLRPC connection (pre-fix: the bare-ASCII gate rejects it, so no connection is ever attempted)'
		);
		$this->assertSame(
			'xn--bcher-kva.example',
			$GLOBALS['pfb_test_xmlrpc_connection']['ip'] ?? null,
			'the connection must receive the punycode form, not the raw Unicode target'
		);
	}

	// --- before-state pins: green both sides of the fix ---------------------

	public function testPlainAsciiHostnameTargetUnchanged(): void
	{
		$this->seedSyncConfig('sync-peer.example');
		pfblockerng_sync_on_changes();

		$this->assertSame(
			'sync-peer.example',
			$GLOBALS['pfb_test_xmlrpc_connection']['ip'] ?? null,
			'a plain ASCII hostname target must reach the connection byte-identical'
		);
	}

	public function testIpv4TargetUnchanged(): void
	{
		$this->seedSyncConfig('192.0.2.10');
		pfblockerng_sync_on_changes();

		$this->assertSame(
			'192.0.2.10',
			$GLOBALS['pfb_test_xmlrpc_connection']['ip'] ?? null,
			'an IPv4 literal target must reach the connection unchanged'
		);
	}

	public function testIpv6TargetStillBracketWrapped(): void
	{
		$this->seedSyncConfig('2001:db8::53');
		pfblockerng_sync_on_changes();

		$this->assertSame(
			'[2001:db8::53]',
			$GLOBALS['pfb_test_xmlrpc_connection']['ip'] ?? null,
			'an IPv6 literal target must still receive its bracket wrap (pfblockerng_do_xmlrpc_sync, ~17259) at the connection site'
		);
	}

	public function testUnconvertibleUnicodeTargetStillRejected(): void
	{
		// A lone combining mark (U+0301): not a legal standalone label --
		// idn_to_ascii() refuses it (returns FALSE), so $sync_to_ip is left
		// unchanged and the existing gate rejects it exactly as before the fix.
		$this->seedSyncConfig("\xCC\x81");
		pfblockerng_sync_on_changes();

		$this->assertArrayNotHasKey(
			'pfb_test_xmlrpc_connection',
			$GLOBALS,
			'a Unicode target idn_to_ascii() cannot convert must still be rejected by the gate, never reach the connection'
		);
	}
}
