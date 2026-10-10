<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;

/**
 * IP-page $pconfig consumer guard (issue #3450).
 *
 * Ten display fields on pfblockerng_ip.php were read from the page's section mirror
 * (`$pfb['iconfig']`) with their own `?:` default. They now resolve through
 * PfbConfig::read(), so the registry owns the default and the page can no longer disagree
 * with the runtime.
 *
 * The page carries top-level execution and cannot be require()d off-appliance, so its real
 * $pconfig assembly block is eval-extracted as an executable function, the arrangement
 * DnsblFreshPconfigTest uses. Authoritative config.xml state is seeded separately from a
 * deliberately stale $pfb['iconfig'] mirror: an assertion fails while a field still reads
 * the mirror, and no assertion looks at source text.
 *
 * Extraction is anchored on the `$pconfig['ip_placeholder']` line through the
 * `$pconfig['autorule_suffix']` line. The masked credentials (maxmind_key, asn_token) sit
 * inside that window on purpose: they must keep rendering blank on a GET.
 */
final class IpPagePconfigGatewayReadTest extends TestCase
{
	private const IP_SECTION = 'installedpackages/pfblockerngipsettings/config/0';

	public static function setUpBeforeClass(): void
	{
		$src = file_get_contents(
			dirname(__DIR__, 2) . '/src/usr/local/www/pfblockerng/pfblockerng_ip.php'
		);
		if ($src === FALSE) {
			throw new RuntimeException('test bootstrap: failed to read pfblockerng_ip.php');
		}

		if (!function_exists('pfb_ip_oracle_pconfig')) {
			if (!preg_match(
				'/(\$pconfig\[\'ip_placeholder\'\][^\n]*\n'
				. '.*?\$pconfig\[\'autorule_suffix\'\][^\n]*\n)/s',
				$src,
				$m
			)) {
				throw new RuntimeException('test bootstrap: ip $pconfig block not found');
			}
			eval(
				'function pfb_ip_oracle_pconfig(array $iconfig): array {'
				. ' global $pfb; $pfb[\'iconfig\'] = $iconfig;'
				. ' $pconfig = array();'
				. $m[1]
				. ' return $pconfig; }'
			);
		}
	}

	/**
	 * Mirror values the page must not read: any field still sourced from it fails.
	 *
	 * @return array<string,string>
	 */
	private static function staleMirror(): array
	{
		return [
			'ip_placeholder'       => 'mirror',
			'maxmind_locale'       => 'mirror',
			'asn_reporting'        => 'mirror',
			'maxmind_account'      => 'mirror',
			'inbound_interface'    => 'mirror1,mirror2',
			'inbound_deny_action'  => 'mirror',
			'outbound_interface'   => 'mirror1,mirror2',
			'outbound_deny_action' => 'mirror',
			'pass_order'           => 'mirror',
			'autorule_suffix'      => 'mirror',
			'maxmind_key'          => 'mirror-key',
			'asn_token'            => 'mirror-token',
		];
	}

	/** @return array<string,mixed> the page's $pconfig for the given authoritative section (NULL = never saved) */
	private function runBlock(array $mirror, ?array $stored): array
	{
		$hadConfig      = array_key_exists('config', $GLOBALS);
		$previousConfig = $GLOBALS['config'] ?? NULL;
		$hadPfb         = array_key_exists('pfb', $GLOBALS);
		$previousPfb    = $GLOBALS['pfb'] ?? NULL;
		$previousPost   = $_POST;
		try {
			$GLOBALS['config'] = [];
			if ($stored !== NULL) {
				config_set_path(self::IP_SECTION, $stored);
			}
			$_POST = [];
			return pfb_ip_oracle_pconfig($mirror);
		} finally {
			$_POST = $previousPost;
			if ($hadConfig) {
				$GLOBALS['config'] = $previousConfig;
			} else {
				unset($GLOBALS['config']);
			}
			if ($hadPfb) {
				$GLOBALS['pfb'] = $previousPfb;
			} else {
				unset($GLOBALS['pfb']);
			}
		}
	}

	public function testStoredValuesWinOverAStaleMirror(): void
	{
		$stored = [
			'ip_placeholder'       => '10.9.9.9',
			'maxmind_locale'       => 'fr',
			'asn_reporting'        => '24hour',
			'maxmind_account'      => '7654321',
			'inbound_interface'    => 'wan,opt1',
			'inbound_deny_action'  => 'reject',
			'outbound_interface'   => 'lan',
			'outbound_deny_action' => 'block',
			'pass_order'           => 'order_3',
			'autorule_suffix'      => 'ar',
		];

		$pconfig = $this->runBlock(self::staleMirror(), $stored);

		$this->assertSame('10.9.9.9', $pconfig['ip_placeholder']);
		$this->assertSame('fr', $pconfig['maxmind_locale']);
		$this->assertSame('24hour', $pconfig['asn_reporting']);
		$this->assertSame('7654321', $pconfig['maxmind_account']);
		$this->assertSame(['wan', 'opt1'], $pconfig['inbound_interface']);
		$this->assertSame('reject', $pconfig['inbound_deny_action']);
		$this->assertSame(['lan'], $pconfig['outbound_interface']);
		$this->assertSame('block', $pconfig['outbound_deny_action']);
		$this->assertSame('order_3', $pconfig['pass_order']);
		$this->assertSame('ar', $pconfig['autorule_suffix']);
	}

	public function testAbsentValuesResolveToTheRegistryDefaults(): void
	{
		$pconfig = $this->runBlock(self::staleMirror(), NULL);

		$this->assertSame('127.1.7.7', $pconfig['ip_placeholder']);
		$this->assertSame('en', $pconfig['maxmind_locale']);
		$this->assertSame('disabled', $pconfig['asn_reporting']);
		$this->assertSame('', $pconfig['maxmind_account']);
		$this->assertSame([], $pconfig['inbound_interface'], 'an absent interface list renders no selection');
		$this->assertSame('block', $pconfig['inbound_deny_action']);
		$this->assertSame([], $pconfig['outbound_interface']);
		$this->assertSame('reject', $pconfig['outbound_deny_action']);
		$this->assertSame('order_0', $pconfig['pass_order']);
		$this->assertSame('autorule', $pconfig['autorule_suffix']);
	}

	public function testEmptyStoredValuesResolveToTheRegistryDefaults(): void
	{
		$stored = [
			'ip_placeholder'       => '',
			'maxmind_locale'       => '',
			'asn_reporting'        => '',
			'maxmind_account'      => '',
			'inbound_interface'    => '',
			'inbound_deny_action'  => '',
			'outbound_interface'   => '',
			'outbound_deny_action' => '',
			'pass_order'           => '',
			'autorule_suffix'      => '',
		];

		$pconfig = $this->runBlock(self::staleMirror(), $stored);

		$this->assertSame('127.1.7.7', $pconfig['ip_placeholder']);
		$this->assertSame('en', $pconfig['maxmind_locale']);
		$this->assertSame('disabled', $pconfig['asn_reporting']);
		$this->assertSame([], $pconfig['inbound_interface']);
		$this->assertSame('block', $pconfig['inbound_deny_action']);
		$this->assertSame('reject', $pconfig['outbound_deny_action']);
		$this->assertSame('order_0', $pconfig['pass_order']);
		$this->assertSame('autorule', $pconfig['autorule_suffix']);
	}

	// issue #924 / #2922: the masked credentials never populate the form from stored state.
	public function testMaskedCredentialsStayBlankOnAGetEvenWithStoredCredentials(): void
	{
		$pconfig = $this->runBlock(self::staleMirror(), [
			'maxmind_key' => 'stored-secret-key',
			'asn_token'   => 'stored-secret-token',
		]);

		$this->assertSame('', $pconfig['maxmind_key']);
		$this->assertSame('', $pconfig['asn_token']);
	}
}
