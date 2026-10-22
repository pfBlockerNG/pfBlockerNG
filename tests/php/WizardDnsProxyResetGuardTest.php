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
	private const GLOBALS = ['pfb', 'config', 'input_errors', 'stepid', 'pfb_test_file_notices', 'pfb_test_write_config_hook', 'pfb_test_write_config_calls',
		'pfb_test_write_config_result', 'pfb_test_config_read_hook', 'pfb_test_config_read_calls', 'pfb_test_config_read_lock_held', 'pfb_test_lock_held', 'pfb_test_try_lock_fail',
		'pfb_test_lock_events'];
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
		if (in_array(WizardSweepProbeStream::SCHEME, stream_get_wrappers(), TRUE)) {
			stream_wrapper_unregister(WizardSweepProbeStream::SCHEME);
		}
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
		PfbConfig::writeSystem('gen/enable_cb', PfbToggle::On);
		foreach (['dns_proxy_pidfile', 'dns_proxy_ready', 'dns_proxy_rc_kept', 'dns_proxy_cert', 'dns_proxy_cert_legacy', 'dns_proxy_ctl'] as $file) {
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

	/**
	 * pfB-DNS moved the Resolver after this request read config.xml: the copy shows the user's Resolver and no snapshot, config.xml
	 * holds the move, our block and the snapshot.
	 */
	private function seedStaleCopyOfAMovedResolver(): void
	{
		$snapshot = [
			'active_interface' => ['present' => TRUE, 'value' => 'lan'],
			'enablessl'        => ['present' => FALSE, 'value' => NULL],
			'custom_options'   => ['present' => FALSE, 'value' => NULL],
		];
		$GLOBALS['config']['unbound'] = ['active_interface' => 'lo0', 'custom_options' => base64_encode(self::BLOCK)];
		config_set_path(self::SAVED, base64_encode((string) json_encode($snapshot)));
		PfbConfig::writeSystem('gen/enable_cb', PfbToggle::On);
		foreach (['dns_proxy_pidfile', 'dns_proxy_ready', 'dns_proxy_rc_kept', 'dns_proxy_cert', 'dns_proxy_cert_legacy', 'dns_proxy_ctl'] as $file) {
			$GLOBALS['pfb'][$file] = "{$this->dir}/{$file}";
		}
		file_put_contents("{$this->dir}/feeds.json", (string) json_encode([
			'ipv4'  => ['PRI1' => ['description' => 'Primary', 'feeds' => []]],
			'dnsbl' => ['ADs_Basic' => ['description' => 'Ads', 'feeds' => []]],
		]));
		$this->configXmlOnDisk();
		// the reset that got past the guard still stops at its own write, never at a process exit
		$disk = $GLOBALS['pfb_test_write_config_hook'];
		$GLOBALS['pfb_test_write_config_hook'] = static function (string $description) use ($disk): void {
			if ($description === self::RESET_WRITE) {
				throw new \RuntimeException(self::RESET_WRITE);
			}
			$disk($description);
		};
		$GLOBALS['config']['unbound'] = ['active_interface' => 'lan'];
		config_set_path(self::SAVED, '');
		$this->assertNull(pfb_dns_proxy_saved(), 'before: this request\'s copy shows nothing moved');
		$this->assertSame('lo0', $this->onDisk('unbound/active_interface'), 'before: config.xml holds the moved Resolver');
	}

	public function testAResetFromACopyThatPredatesTheTakeoverPutsTheResolverBackFirstAndThenResets(): void
	{
		// Given the stale copy, and a config.xml whose lock is free
		$this->seedStaleCopyOfAMovedResolver();

		// When the wizard resets, up to the write of its default configuration
		try {
			step4_submitphpaction();
			$this->fail('the reset must reach its configuration write once the Resolver is back');
		} catch (\RuntimeException $stop) {
			$this->assertSame(self::RESET_WRITE, $stop->getMessage());
		}

		// Then the Resolver config.xml held was put back before the sweep, and the guard did not refuse
		$this->assertContains('pfBlockerNG: Restored the DNS Resolver settings the DNS proxy had moved', $GLOBALS['pfb_test_write_config_calls'] ?? [],
			'the restore the stale copy hid was made');
		$refusals = array_filter($GLOBALS['input_errors'], static fn ($e): bool => is_string($e) && str_contains($e, 'was not reset'));
		$this->assertSame([], array_values($refusals));
	}

	public function testAResetFromACopyThatPredatesTheTakeoverIsRefusedWhenConfigXmlCannotBeLockedToCheck(): void
	{
		// Given the stale copy, and a config.xml whose lock stays taken: nothing says whether the Resolver is still moved
		$this->seedStaleCopyOfAMovedResolver();
		$GLOBALS['pfb_test_try_lock_fail'] = TRUE;
		$before = $GLOBALS['config'];

		// When the wizard resets
		try {
			step4_submitphpaction();
		} catch (\Throwable $e) {
			$this->fail('the reset ran past the Resolver guard on a copy it could not check: ' . $e->getMessage());
		}

		// Then the reset is refused with the DNS proxy as the cause, nothing was swept, and config.xml still holds the moved Resolver
		$errors = array_filter($GLOBALS['input_errors'], static fn ($e): bool => is_string($e) && str_contains($e, 'could not be put back'));
		$this->assertCount(1, $errors, 'the reset names the DNS proxy as the cause: ' . json_encode($GLOBALS['input_errors']));
		$this->assertSame($before, $GLOBALS['config'], 'nothing was swept or rebuilt in this process\'s copy');
		$this->assertSame('lo0', $this->onDisk('unbound/active_interface'), 'and config.xml holds the moved Resolver');
		$this->assertNotSame('', $this->onDisk(self::SAVED), 'with its snapshot');
	}

	/**
	 * Another save enabling pfB-DNS, as a lock holder does it: it takes the DNS config lock, and only with it moves the Resolver
	 * and stores the snapshot in config.xml (another process: this request's copy is not touched).
	 *
	 * @return bool TRUE iff it got the lock and wrote; FALSE when the lock was taken, so it waits for the holder
	 */
	private function anotherSaveEnablesPfbDns(): bool
	{
		$lock = try_lock(PFB_DNS_CONFIG_LOCK, PFB_DNS_CONFIG_LOCK_WAIT);
		if (!is_resource($lock)) {
			return FALSE;
		}
		$this->disk['unbound'] = ['active_interface' => 'lo0', 'custom_options' => base64_encode(self::BLOCK)];
		$this->disk['installedpackages']['pfblockerngdns']['config'][0]['pfb_dns_saved'] = base64_encode((string) json_encode([
			'active_interface' => ['present' => TRUE, 'value' => 'lan'],
			'enablessl'        => ['present' => FALSE, 'value' => NULL],
			'custom_options'   => ['present' => FALSE, 'value' => NULL],
		]));
		unlock($lock);
		return TRUE;
	}

	public function testAPfbDnsEnableAnotherSaveMakesDuringTheResetSurvivesTheResetsWrite(): void
	{
		// Given a Resolver pfB-DNS never moved, in this request's copy and in config.xml
		$GLOBALS['config']['unbound'] = ['active_interface' => 'lan'];
		config_set_path(self::SAVED, '');
		foreach (['dns_proxy_pidfile', 'dns_proxy_ready', 'dns_proxy_rc_kept', 'dns_proxy_cert', 'dns_proxy_cert_legacy', 'dns_proxy_ctl'] as $file) {
			$GLOBALS['pfb'][$file] = "{$this->dir}/{$file}";
		}
		file_put_contents("{$this->dir}/feeds.json", (string) json_encode([
			'ipv4'  => ['PRI1' => ['description' => 'Primary', 'feeds' => []]],
			'dnsbl' => ['ADs_Basic' => ['description' => 'Ads', 'feeds' => []]],
		]));
		$this->configXmlOnDisk();
		// and another save enabling pfB-DNS that arrives after the reset put the Resolver back: it gets in at the last instant
		// before the reset's write if the lock lets it, and otherwise waits for the lock and enables once the reset let go
		$enabled = FALSE;
		$disk = $GLOBALS['pfb_test_write_config_hook'];
		$GLOBALS['pfb_test_write_config_hook'] = function (string $description) use ($disk, &$enabled): void {
			if ($description === self::RESET_WRITE) {
				$enabled = $this->anotherSaveEnablesPfbDns();
				$disk($description);
				throw new \RuntimeException(self::RESET_WRITE);
			}
			$disk($description);
		};
		$this->assertSame('', $this->onDisk(self::SAVED), 'before: config.xml holds no snapshot');

		// When the wizard resets, up to and including the write of its default configuration
		try {
			step4_submitphpaction();
			$this->fail('the reset must reach its configuration write');
		} catch (\RuntimeException $stop) {
			$this->assertSame(self::RESET_WRITE, $stop->getMessage());
		}
		if (!$enabled) {
			$this->assertTrue($this->anotherSaveEnablesPfbDns(), 'the save that waited gets the lock once the reset has written');
		}

		// Then config.xml holds both: the reset's default configuration, and the moved Resolver with its snapshot
		$this->assertSame('on', $this->onDisk('installedpackages/pfblockerng/config/0/enable_cb'), 'the reset was written');
		$this->assertSame('ADs_Basic', $this->onDisk('installedpackages/pfblockerngdnsbl/config/0/aliasname'), 'with its default DNSBL group');
		$this->assertNotSame('', (string) $this->onDisk(self::SAVED, ''), 'the snapshot the other save stored survives the reset');
		$this->assertSame('lo0', $this->onDisk('unbound/active_interface'), 'and so does the Resolver it moved');
	}

	public function testARefusedResetLetsGoOfTheConfigLock(): void
	{
		// Given a stored marker that is no snapshot (the reset is refused after config.xml was read under the lock)
		$GLOBALS['config']['unbound'] = ['active_interface' => 'lo0', 'custom_options' => base64_encode('do-ip6: no')];
		config_set_path(self::SAVED, '0');

		// When the wizard resets
		step4_submitphpaction();

		// Then it is refused, and the lock is free for the next save
		$this->assertCount(1, $GLOBALS['input_errors'], json_encode($GLOBALS['input_errors']));
		$this->assertStringContainsString('is invalid', (string) $GLOBALS['input_errors'][0]);
		$this->assertEmpty($GLOBALS['pfb_test_lock_held'] ?? FALSE, 'the refused reset still holds the DNS config lock');
	}

	/** A Resolver pfB-DNS never moved, in this request's copy and in config.xml, a masterfile, and the two default feed groups. */
	private function seedNeverMovedResolverOnDisk(): void
	{
		$GLOBALS['config']['unbound'] = ['active_interface' => 'lan'];
		config_set_path(self::SAVED, '');
		foreach (['dns_proxy_pidfile', 'dns_proxy_ready', 'dns_proxy_rc_kept', 'dns_proxy_cert', 'dns_proxy_cert_legacy', 'dns_proxy_ctl'] as $file) {
			$GLOBALS['pfb'][$file] = "{$this->dir}/{$file}";
		}
		mkdir($GLOBALS['pfb']['dbdir']);
		file_put_contents("{$GLOBALS['pfb']['dbdir']}/masterfile", 'x');
		file_put_contents("{$this->dir}/feeds.json", (string) json_encode([
			'ipv4'  => ['PRI1' => ['description' => 'Primary', 'feeds' => []]],
			'dnsbl' => ['ADs_Basic' => ['description' => 'Ads', 'feeds' => []]],
		]));
		$this->configXmlOnDisk();
	}

	public function testAPfbDnsEnableThatLandsBeforeTheResetTakesTheLockRefusesTheReset(): void
	{
		// Given a Resolver pfB-DNS never moved, and another save that enabled pfB-DNS after the restore read config.xml and
		// before the reset took the lock: config.xml holds the move by the reset's own read, the first to see it
		$this->seedNeverMovedResolverOnDisk();
		$freshReads = 0;
		$disk = $GLOBALS['pfb_test_config_read_hook'];
		$GLOBALS['pfb_test_config_read_hook'] = function () use ($disk, &$freshReads): void {
			if (end($GLOBALS['pfb_test_config_read_calls']) === [FALSE, FALSE] && ++$freshReads === 2) {
				$this->disk['unbound'] = ['active_interface' => 'lo0', 'custom_options' => base64_encode(self::BLOCK)];
				$this->disk['installedpackages']['pfblockerngdns']['config'][0]['pfb_dns_saved'] = base64_encode((string) json_encode([
					'active_interface' => ['present' => TRUE, 'value' => 'lan'],
					'enablessl'        => ['present' => FALSE, 'value' => NULL],
					'custom_options'   => ['present' => FALSE, 'value' => NULL],
				]));
			}
			$disk();
		};
		$this->assertNull(pfb_dns_proxy_saved(), 'before: this request\'s copy shows nothing moved');

		// When the wizard resets
		try {
			step4_submitphpaction();
		} catch (\Throwable $e) {
			$this->fail('the reset ran past the Resolver guard on a Resolver the other save moved: ' . $e->getMessage());
		}

		// Then the reset is refused with the DNS proxy as the cause, nothing was written, and config.xml keeps the move
		$errors = array_filter($GLOBALS['input_errors'], static fn ($e): bool => is_string($e) && str_contains($e, 'could not be put back'));
		$this->assertCount(1, $errors, 'the reset names the DNS proxy as the cause: ' . json_encode($GLOBALS['input_errors']));
		$this->assertNotContains(self::RESET_WRITE, $GLOBALS['pfb_test_write_config_calls'] ?? [], 'the reset wrote nothing');
		$this->assertNotSame('', (string) $this->onDisk(self::SAVED, ''), 'the snapshot the other save stored is kept');
		$this->assertSame('lo0', $this->onDisk('unbound/active_interface'), 'and so is the Resolver it moved');
	}

	public function testTheResetDeletesThePackageFilesOnlyAfterItsWriteLetGoOfTheLock(): void
	{
		// Given a Resolver pfB-DNS never moved, and the package's database directory behind a probe that records, for each file
		// the reset deletes there, whether the DNS config lock was held, and stops the reset at its first deletion
		$this->seedNeverMovedResolverOnDisk();
		stream_wrapper_register(WizardSweepProbeStream::SCHEME, WizardSweepProbeStream::class);
		WizardSweepProbeStream::$unlinks = [];
		$GLOBALS['pfb']['dbdir'] = WizardSweepProbeStream::SCHEME . '://db';
		$atWrite = NULL;
		$disk = $GLOBALS['pfb_test_write_config_hook'];
		$GLOBALS['pfb_test_write_config_hook'] = static function (string $description) use ($disk, &$atWrite): void {
			if ($description === self::RESET_WRITE) {
				$atWrite = ['lock held' => !empty($GLOBALS['pfb_test_lock_held']), 'files deleted' => count(WizardSweepProbeStream::$unlinks)];
			}
			$disk($description);
		};

		// When the wizard resets, through its write and up to the first file it deletes
		try {
			step4_submitphpaction();
			$this->fail('the reset must reach its file sweep');
		} catch (\RuntimeException $stop) {
			$this->assertSame(WizardSweepProbeStream::STOP, $stop->getMessage());
		}

		// Then the write ran under the lock before any file was deleted, and the first deletion came once the lock was free
		$this->assertSame(['lock held' => TRUE, 'files deleted' => 0], $atWrite);
		$this->assertSame([[WizardSweepProbeStream::SCHEME . '://db/masterfile', FALSE]], WizardSweepProbeStream::$unlinks,
			'the first file deleted, and whether the DNS config lock was held then');
	}
}

/**
 * A directory whose files the reset deletes: every unlink() is recorded with whether the DNS config lock was held at that instant,
 * and the first one stops the reset (what follows the sweep restarts services and exits the process). Nothing exists in it.
 */
final class WizardSweepProbeStream
{
	public const SCHEME = 'pfbwizsweep';
	public const STOP = 'the reset reached its file sweep';

	/** @var resource|null set by PHP for every stream wrapper */
	public $context;

	/** @var list<array{string,bool}> each path unlinked, with whether the DNS config lock was held */
	public static array $unlinks = [];

	public function unlink(string $path): bool
	{
		self::$unlinks[] = [$path, !empty($GLOBALS['pfb_test_lock_held'])];
		throw new \RuntimeException(self::STOP);
	}

	/** @return array<int|string,int>|false */
	public function url_stat(string $path, int $flags): array|false
	{
		return FALSE;
	}
}
