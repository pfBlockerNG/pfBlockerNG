<?php

declare(strict_types=1);

require_once __DIR__ . '/ConfigXmlDiskTrait.php';

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * issue #3515 -- the wizard's reset puts the Resolver back first and stops when it cannot. A moved Resolver whose snapshot
 * is gone still carries our block, so the reset is refused there and sweeps nothing. So is a restore that config.xml did not
 * take: the Resolver is still moved on disk, and the reset must not take this process's unwritten copy for a restored one.
 */
#[CoversFunction('step4_submitphpaction')]
final class WizardDnsProxyResetGuardTest extends TestCase
{
	use ConfigXmlDiskTrait;

	private const SAVED = 'installedpackages/pfblockerngdns/config/0/pfb_dns_saved';
	private const BLOCK = "server:\n# pfBlockerNG DNS proxy\nport: 5354\n# end pfBlockerNG DNS proxy";
	/** The directories and files a reset unlinks; each is pointed at the temp dir, never at the host's root. */
	private const SWEPT = [
		'asn_cache', 'dbdir', 'denydir', 'dnsbl_cache', 'dnsbl_info', 'dnsbl_resolver', 'dnsbl_supptxt', 'dnsdir',
		'dnsorigdir', 'etdir', 'ip_cache', 'matchdir', 'nativedir', 'origdir', 'permitdir', 'snapdir', 'supptxt', 'supptxt_v6',
	];
	private const GLOBALS = ['pfb', 'config', 'input_errors', 'stepid', 'pfb_test_file_notices', 'pfb_test_write_config_hook',
		'pfb_test_write_config_result', 'pfb_test_config_read_hook', 'pfb_test_config_read_calls', 'pfb_test_config_read_lock_held', 'pfb_test_lock_held'];
	/** What the doubled write_config() throws: the reset that got past every guard and the sweep stops here, before it restarts services and exits the process. */
	private const RESET_WRITE = 'pfBlockerNG: Default Wizard configuration saved';

	private string $dir;
	private array $savedGlobals = [];

	protected function setUp(): void
	{
		foreach (self::GLOBALS as $name) {
			$this->savedGlobals[$name] = [array_key_exists($name, $GLOBALS), $GLOBALS[$name] ?? NULL];
		}
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
		$GLOBALS['pfb_test_write_config_hook'] = static function (string $description): void {
			if ($description === self::RESET_WRITE) {
				throw new \RuntimeException(self::RESET_WRITE);
			}
		};
	}

	protected function tearDown(): void
	{
		foreach ($this->savedGlobals as $name => [$existed, $value]) {
			if ($existed) {
				$GLOBALS[$name] = $value;
			} else {
				unset($GLOBALS[$name]);
			}
		}
		$this->savedGlobals = [];
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

	/** @return array<string,array{string}> a stored marker that is no snapshot, on a Resolver that carries no block of ours */
	public static function unconfirmedMarkers(): array
	{
		return [
			'the single character 0'           => ['0'],
			'the text of an interrupted write' => ['!!!truncated-snapshot!!!'],
			'base64 of text that is not JSON'  => [base64_encode('not json')],
		];
	}

	#[DataProvider('unconfirmedMarkers')]
	public function testAMarkerThatIsNoSnapshotStopsTheResetAndSweepsNothing(string $marker): void
	{
		// Given a stored marker that is no snapshot, no block of ours in a Resolver on loopback, and package settings
		$GLOBALS['config']['unbound'] = ['active_interface' => 'lo0', 'custom_options' => base64_encode('do-ip6: no')];
		config_set_path(self::SAVED, $marker);
		config_set_path('installedpackages/pfblockerng/config/0/enable_cb', 'on');
		$before = $GLOBALS['config'];

		// When the wizard resets
		try {
			step4_submitphpaction();
		} catch (\Throwable $e) {
			$this->fail('the reset ran past the Resolver guard instead of refusing: ' . $e->getMessage());
		}

		// Then the reset is refused, the operator is told the saved state cannot be confirmed, and nothing was swept: the
		// marker, the Resolver and the package settings are exactly as they were
		$errors = array_values(array_filter($GLOBALS['input_errors'], static fn ($e): bool => is_string($e) && str_contains($e, 'was not reset')));
		$this->assertCount(1, $errors, 'the reset is refused with one message: ' . json_encode($GLOBALS['input_errors']));
		$this->assertStringContainsString('cannot be confirmed', $errors[0]);
		$this->assertSame($marker, (string) config_get_path(self::SAVED, ''), 'the marker is kept verbatim');
		$this->assertSame($before, $GLOBALS['config'], 'nothing was swept or rebuilt');
	}

	public function testALoopbackOnlyResolverWithAnEmptyMarkerIsResetLikeAnyOther(): void
	{
		// Given the same Resolver and an empty marker: loopback alone does not say pfB-DNS ever moved it
		$GLOBALS['config']['unbound'] = ['active_interface' => 'lo0', 'custom_options' => base64_encode('do-ip6: no')];
		config_set_path(self::SAVED, '');
		config_set_path('installedpackages/pfblockerngdns/config/0/canary', 'x');
		// the two default feed groups the reset adds
		file_put_contents("{$this->dir}/feeds.json", (string) json_encode([
			'ipv4'  => ['PRI1' => ['description' => 'Primary', 'feeds' => []]],
			'dnsbl' => ['ADs_Basic' => ['description' => 'Ads', 'feeds' => []]],
		]));

		// When the wizard resets, up to the write of its default configuration
		try {
			step4_submitphpaction();
			$this->fail('the reset must reach its configuration write');
		} catch (\RuntimeException $stop) {
			$this->assertSame(self::RESET_WRITE, $stop->getMessage());
		}

		// Then the guard did not refuse, and the package sections were swept before that write
		$refusals = array_filter($GLOBALS['input_errors'], static fn ($e): bool => is_string($e) && str_contains($e, 'was not reset'));
		$this->assertSame([], array_values($refusals));
		$this->assertNull(config_get_path('installedpackages/pfblockerngdns/config/0/canary'), 'the old package section is gone');
	}

	#[DataProvider('refusedWrites')]
	public function testAResolverWhoseRestoreConfigXmlRefusesStopsTheResetAndSweepsNothing(mixed $answer): void
	{
		// Given a Resolver pfB-DNS moved (a snapshot, our block), package settings, and a config.xml that refuses the restore's write
		$snapshot = [
			'active_interface' => ['present' => TRUE, 'value' => 'lan'],
			'enablessl'        => ['present' => FALSE, 'value' => NULL],
			'custom_options'   => ['present' => FALSE, 'value' => NULL],
		];
		$GLOBALS['config']['unbound'] = ['active_interface' => 'lo0', 'custom_options' => base64_encode(self::BLOCK)];
		config_set_path(self::SAVED, base64_encode((string) json_encode($snapshot)));
		config_set_path('installedpackages/pfblockerng/config/0/enable_cb', 'on');
		foreach (['dns_proxy_pidfile', 'dns_proxy_ready', 'dns_proxy_cert', 'dns_proxy_cert_legacy', 'dns_proxy_ctl'] as $file) {
			$GLOBALS['pfb'][$file] = "{$this->dir}/{$file}";
		}
		$this->configXmlOnDisk($answer, 'Restored the DNS Resolver');
		// the reset that got past the guard still stops at its own write, never at a process exit
		$refusing = $GLOBALS['pfb_test_write_config_hook'];
		$GLOBALS['pfb_test_write_config_hook'] = static function (string $description) use ($refusing): void {
			if ($description === self::RESET_WRITE) {
				throw new \RuntimeException(self::RESET_WRITE);
			}
			$refusing($description);
		};
		$before = $GLOBALS['config'];

		// When the wizard resets
		try {
			step4_submitphpaction();
		} catch (\Throwable $e) {
			$this->fail('the reset ran past the Resolver guard instead of refusing: ' . $e->getMessage());
		}

		// Then the reset is refused with the DNS proxy as the cause, and the Resolver, the snapshot and the package settings are as stored
		$errors = array_filter($GLOBALS['input_errors'], static fn ($e): bool => is_string($e) && str_contains($e, 'could not be put back'));
		$this->assertCount(1, $errors, 'the reset names the DNS proxy as the cause: ' . json_encode($GLOBALS['input_errors']));
		$this->assertSame($before, $GLOBALS['config'], 'nothing was swept, rebuilt or restored in this process\'s copy');
		$this->assertSame($before, $this->disk, 'and config.xml holds the moved Resolver and the snapshot');
	}
}
