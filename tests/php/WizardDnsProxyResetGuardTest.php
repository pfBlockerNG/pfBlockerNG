<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\TestCase;

/**
 * issue #3515 -- the wizard's reset puts the Resolver back first and stops when it cannot. A moved Resolver whose snapshot
 * is gone still carries our block, so the reset is refused there and sweeps nothing.
 */
#[CoversFunction('step4_submitphpaction')]
final class WizardDnsProxyResetGuardTest extends TestCase
{
	private const SAVED = 'installedpackages/pfblockerngdns/config/0/pfb_dns_saved';
	private const BLOCK = "server:\n# pfBlockerNG DNS proxy\nport: 5354\n# end pfBlockerNG DNS proxy";
	/** The directories and files a reset unlinks; each is pointed at the temp dir, never at the host's root. */
	private const SWEPT = [
		'asn_cache', 'dbdir', 'denydir', 'dnsbl_cache', 'dnsbl_info', 'dnsbl_resolver', 'dnsbl_supptxt', 'dnsdir',
		'dnsorigdir', 'etdir', 'ip_cache', 'matchdir', 'nativedir', 'origdir', 'permitdir', 'snapdir', 'supptxt', 'supptxt_v6',
	];

	private string $dir;

	protected function setUp(): void
	{
		$this->dir = sys_get_temp_dir() . '/pfb_wizard_reset_' . getmypid() . '_' . uniqid();
		mkdir($this->dir, 0777, TRUE);
		file_put_contents("{$this->dir}/feeds.json", '[]');
		$GLOBALS['pfb'] = [
			'feeds'  => "{$this->dir}/feeds.json",
			'logdir' => $this->dir,
			'log'    => "{$this->dir}/pfb.log",
			'errlog' => "{$this->dir}/pfb.err",
		];
		foreach (self::SWEPT as $key) {
			$GLOBALS['pfb'][$key] = "{$this->dir}/{$key}";
		}
		$GLOBALS['config'] = [];
		$GLOBALS['input_errors'] = [];
		$GLOBALS['pfb_test_file_notices'] = [];
	}

	protected function tearDown(): void
	{
		$GLOBALS['input_errors'] = [];
		rmdir_recursive($this->dir);
	}

	public function testAResolverThatCannotBePutBackStopsTheResetAndSweepsNothing(): void
	{
		// Given our block is in the Resolver, the snapshot is gone, and the package has settings
		$GLOBALS['config']['unbound'] = [
			'active_interface' => 'lo0',
			'custom_options'   => base64_encode(self::BLOCK),
		];
		config_set_path(self::SAVED, '');
		config_set_path('installedpackages/pfblockerng/config/0/enable_cb', 'on');

		// When the wizard resets
		try {
			step4_submitphpaction();
		} catch (\Throwable $e) {
			$this->fail('the reset ran past the Resolver guard instead of refusing: ' . $e->getMessage());
		}

		// Then the reset is refused, the operator is told why, and the package settings are still there
		$errors = array_filter($GLOBALS['input_errors'], static fn ($e): bool => is_string($e) && str_contains($e, 'could not be put back'));
		$this->assertCount(1, $errors, 'the reset names the DNS proxy as the cause');
		$this->assertSame('on', config_get_path('installedpackages/pfblockerng/config/0/enable_cb'), 'nothing was swept');
	}
}
