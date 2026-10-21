<?php

declare(strict_types=1);

require_once __DIR__ . '/DnsProxyCertificateFixtures.php';
require_once __DIR__ . '/SyncPrereqSeedTrait.php';

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * issue #3515 -- a check of the Resolver that could not run is never reported as a Resolver that was put back, or as a saved
 * copy that is invalid.
 *
 * The restore and the ownership checks that follow it read config.xml afresh under the config lock. When the lock stays taken
 * (or config.xml cannot be read) this process's copy of config.xml says nothing reliable about the Resolver, so every word the
 * operator is told about it must be about the check, not about the Resolver:
 *   - with pfB-DNS off and this copy showing it in use (a snapshot, our block, a stored marker or a running proxy), the restore's
 *     notice says the state could not be checked, not that the Resolver "was not put back"; with no such sign (a box that never
 *     enabled pfB-DNS, issue #3559) it says nothing at all;
 *   - a package removal stopped for a failed check says so, whatever else went wrong in it (Unbound's python settings that
 *     config.xml did not take): it never also says "the DNS Resolver itself was put back";
 *   - a saved copy (pfb_dns_saved) that cannot be read from this copy is "could not be confirmed", never "invalid", in the
 *     removal's notice and in the wizard's refusal.
 * The same removal and the same wizard with the lock free keep their own wording: the contrast is asserted first in each case.
 */
#[CoversFunction('pfb_dns_proxy_resolver')]
#[CoversFunction('pfb_dns_proxy_deinstall')]
#[CoversFunction('pfb_package_removal_stopped')]
#[CoversFunction('step4_submitphpaction')]
final class DnsProxyUncheckedOwnershipWordingTest extends TestCase
{
	use SyncPrereqSeedTrait;

	private const SAVED = 'installedpackages/pfblockerngdns/config/0/pfb_dns_saved';
	private const BLOCK = "server:\n# pfBlockerNG DNS proxy\nport: 5354\n# end pfBlockerNG DNS proxy";
	private const GLOBALS = [
		'pfb', 'config', 'g', 'input_errors', 'stepid', 'pfb_test_service_calls', 'pfb_test_write_config_calls', 'pfb_test_file_notices',
		'pfb_test_rcfiles', 'pfb_test_rcfile_writes', 'pfb_test_valid_pids', 'pfb_test_try_lock_fail', 'pfb_test_lock_held',
		'pfb_test_lock_events', 'pfb_test_config_read_fails',
	];

	private string $tmp;
	private array $savedGlobals = [];

	protected function setUp(): void
	{
		foreach (self::GLOBALS as $name) {
			$this->savedGlobals[$name] = [array_key_exists($name, $GLOBALS), $GLOBALS[$name] ?? NULL];
			if ($name === 'g') {	// $g keeps the harness's own keys: the seed only adds the chroot path, and tearDown puts it back
				continue;
			}
			unset($GLOBALS[$name]);
		}
		$this->tmp = sys_get_temp_dir() . '/pfb_dns_unchecked_' . uniqid('', TRUE);
		mkdir($this->tmp, 0777, TRUE);
		file_put_contents("{$this->tmp}/feeds.json", '[]');
		$GLOBALS['pfb'] = array_merge($this->savedGlobals['pfb'][1] ?? [], [
			'logdir' => $this->tmp,
			'log'    => "{$this->tmp}/pfb.log",
			'errlog' => "{$this->tmp}/pfb.err",
			'feeds'  => "{$this->tmp}/feeds.json",
		]);
		$GLOBALS['config'] = [];
		$this->seedSyncPrereqs();
		$GLOBALS['input_errors'] = [];
		$GLOBALS['pfb_test_service_calls'] = [];
		$GLOBALS['pfb_test_write_config_calls'] = [];
		$GLOBALS['pfb_test_file_notices'] = [];
		$GLOBALS['pfb_test_valid_pids'] = [];
		@unlink(PFB_DNS_PROXY_RCFILE);
		DnsProxyCertificateFixtures::seedResolver($this->tmp);
	}

	protected function tearDown(): void
	{
		@unlink(PFB_DNS_PROXY_RCFILE);
		foreach ($this->savedGlobals as $name => [$existed, $value]) {
			if ($existed) {
				$GLOBALS[$name] = $value;
			} else {
				unset($GLOBALS[$name]);
			}
		}
		$this->savedGlobals = [];
		rmdir_recursive($this->tmp);
	}

	/** The user's Resolver, never moved. */
	private function seedUntouchedResolver(): void
	{
		$GLOBALS['config']['unbound'] += [
			'enable' => '', 'tlsport' => '853', 'port' => '53', 'active_interface' => 'lan,opt1', 'enablessl' => '',
			'custom_options' => base64_encode('do-ip6: no'),
		];
		config_set_path(self::SAVED, '');
	}

	/** A Resolver on loopback beside a stored marker that is no snapshot: recovery required, nothing owned. */
	private function seedUnreadableMarker(): void
	{
		$this->seedUntouchedResolver();
		$GLOBALS['config']['unbound']['active_interface'] = 'lo0';
		config_set_path(self::SAVED, '!!!truncated-snapshot!!!');
	}

	/** Our block in the Resolver and no snapshot to put it back from. */
	private function seedBlockWithoutSnapshot(): void
	{
		$this->seedUntouchedResolver();
		$GLOBALS['config']['unbound']['active_interface'] = 'lo0';
		$GLOBALS['config']['unbound']['custom_options'] = base64_encode("do-ip6: no\n" . self::BLOCK);
	}

	/** A valid snapshot: the copy says the Resolver was moved. */
	private function seedSnapshot(): void
	{
		$this->seedUntouchedResolver();
		config_set_path(self::SAVED, base64_encode((string) json_encode(array_fill_keys(PFB_DNS_PROXY_RESOLVER_KEYS, ['present' => FALSE, 'value' => NULL]))));
	}

	/** A Resolver the copy shows untouched, with the DNS proxy running: a sign of pfB-DNS from outside this (maybe stale) copy. */
	private function seedRunningProxy(): void
	{
		$this->seedUntouchedResolver();
		$GLOBALS['pfb_test_valid_pids'][PFB_DNS_PROXY_PIDFILE] = TRUE;
	}

	/** The removal's stop, for the Resolver as seeded: pfb_dns_proxy_deinstall() must refuse it, then the hook's notice is raised. */
	private function stopTheRemoval(): string
	{
		$this->assertFalse(pfb_dns_proxy_deinstall(), 'the removal must stop');
		pfb_package_removal_stopped();
		$stopped = array_values(array_filter(array_column($GLOBALS['pfb_test_file_notices'], 'notice'),
			static fn (string $notice): bool => str_contains($notice, 'removal was stopped')));
		$this->assertCount(1, $stopped, 'one removal-stopped notice: ' . json_encode(array_column($GLOBALS['pfb_test_file_notices'], 'notice')));
		return $stopped[0];
	}

	/** @return list<string> every notice the operator was shown */
	private function notices(): array
	{
		return array_column($GLOBALS['pfb_test_file_notices'], 'notice');
	}

	/** Does this process's copy, or a running proxy, show pfB-DNS in use: the restore's grounds for a notice without a fresh read. */
	private static function inUse(): bool
	{
		return pfb_dns_proxy_owns_resolver() || pfb_dns_proxy_recovery_required() || pfb_dns_proxy_running();
	}

	/** @return array<string,array{string}> why config.xml was not read afresh, as the double that refuses it */
	public static function noFreshRead(): array
	{
		return ['the lock stays taken' => ['pfb_test_try_lock_fail'], 'config.xml cannot be parsed' => ['pfb_test_config_read_fails']];
	}

	// -----------------------------------------------------------------------
	// W1 -- the restore with pfB-DNS off and no fresh read (the lock refused, or config.xml unreadable)
	// -----------------------------------------------------------------------

	/** @return array<string,array{string,string}> a sign that pfB-DNS was in use (a seeding method's name), and why no fresh read */
	public static function inUseStates(): array
	{
		$cases = [];
		foreach (['a valid snapshot' => 'seedSnapshot', 'our block and no snapshot' => 'seedBlockWithoutSnapshot',
			'a stored marker that is no snapshot' => 'seedUnreadableMarker', 'a running DNS proxy' => 'seedRunningProxy'] as $state => $seed) {
			foreach (self::noFreshRead() as $why => [$double]) {
				$cases["{$state}, {$why}"] = [$seed, $double];
			}
		}
		return $cases;
	}

	#[DataProvider('inUseStates')]
	public function testARestoreThatCannotTakeTheLockSaysTheResolversStateCouldNotBeCheckedNotThatItWasNotPutBack(string $seed, string $double): void
	{
		// Given a sign that pfB-DNS was in use, and config.xml that cannot be read afresh (another save holds the lock, or it cannot be parsed)
		$this->$seed();
		$this->assertTrue(self::inUse(), 'before: the copy or the running proxy shows pfB-DNS in use');
		$GLOBALS[$double] = TRUE;
		$before = $GLOBALS['config'];

		// When pfB-DNS is off and the restore is asked for
		$changed = pfb_dns_proxy_resolver(FALSE);

		// Then nothing changed, and the one notice is about the check: it names the lock and the retry, and claims no Resolver was left
		$this->assertFalse($changed);
		$this->assertSame($before, $GLOBALS['config']);
		$this->assertSame([], $GLOBALS['pfb_test_write_config_calls']);
		$this->assertSame(['DNS proxy: the state of the DNS Resolver could not be checked because config.xml was locked by another ' .
		    'save or could not be read; the next apply retries.'], $this->notices());
	}

	#[DataProvider('noFreshRead')]
	public function testARestoreThatCannotTakeTheLockOnABoxThatNeverUsedPfbDnsSaysNothing(string $double): void
	{
		// Given a Resolver pfB-DNS never touched, no snapshot or marker, no proxy running, and config.xml that cannot be read afresh
		$this->seedUntouchedResolver();
		$this->assertFalse(self::inUse(), 'before: nothing shows pfB-DNS in use');
		$GLOBALS[$double] = TRUE;
		$before = $GLOBALS['config'];

		// When an apply with pfB-DNS off asks for the restore
		$changed = pfb_dns_proxy_resolver(FALSE);

		// Then nothing changed, nothing was written or stopped, and no notice tells the operator about a feature they never used
		$this->assertFalse($changed);
		$this->assertSame($before, $GLOBALS['config']);
		$this->assertSame([], $GLOBALS['pfb_test_write_config_calls']);
		$this->assertSame([], $GLOBALS['pfb_test_service_calls']);
		$this->assertSame([], $this->notices());
	}

	public function testAMoveThatCannotTakeTheLockKeepsItsOwnWording(): void
	{
		// Given an untouched Resolver and a lock that stays taken
		$this->seedUntouchedResolver();
		$GLOBALS['pfb_test_try_lock_fail'] = TRUE;

		// When pfB-DNS is on and the move is asked for
		$changed = pfb_dns_proxy_resolver(TRUE);

		// Then the notice says the Resolver was not moved: a move that did not happen is known to have not happened
		$this->assertFalse($changed);
		$this->assertCount(1, $this->notices());
		$this->assertStringContainsString('not moved', $this->notices()[0]);
		$this->assertStringNotContainsString('could not be checked', $this->notices()[0]);
	}

	// -----------------------------------------------------------------------
	// W2 -- the removal stopped for a failed check, with Unbound's python settings that config.xml did not take
	// -----------------------------------------------------------------------

	public function testARemovalStoppedForPythonSettingsSaysTheResolverWasPutBackOnlyWhenTheCheckRan(): void
	{
		// Given an untouched Resolver, Unbound's python settings that config.xml did not take, and a free lock
		$this->seedUntouchedResolver();
		$GLOBALS['pfb']['python_removal_failed'] = TRUE;

		// When the removal stops
		$text = $this->stopTheRemoval();

		// Then it says the Resolver was put back: the check ran and found nothing moved
		$this->assertStringContainsString('itself was put back', $text);
		$this->assertStringNotContainsString('could not be checked', $text);
	}

	public function testARemovalStoppedForPythonSettingsWhileTheCheckCouldNotRunSaysOnlyThatItCouldNotBeChecked(): void
	{
		// Given the same removal, and another save holding the config lock
		$this->seedUntouchedResolver();
		$GLOBALS['pfb']['python_removal_failed'] = TRUE;
		$GLOBALS['pfb_test_try_lock_fail'] = TRUE;

		// When the removal stops
		$text = $this->stopTheRemoval();

		// Then it says the Resolver's state could not be checked, and no notice of the removal says anything was put back
		$this->assertStringContainsString('could not be checked', $text);
		$this->assertStringContainsString('locked by another save', $text);
		$this->assertStringContainsString('remove the package again', $text);
		foreach ($this->notices() as $notice) {
			$this->assertStringNotContainsString('was put back', $notice);
			$this->assertStringNotContainsString('not put back', $notice);
		}
	}

	public function testACheckThatFailedOnceDoesNotColourTheNextRemoval(): void
	{
		// Given a removal whose check could not run
		$this->seedUntouchedResolver();
		$GLOBALS['pfb']['python_removal_failed'] = TRUE;
		$GLOBALS['pfb_test_try_lock_fail'] = TRUE;
		$this->assertFalse(pfb_dns_proxy_deinstall(), 'before: the check could not run, so the removal stops');
		$GLOBALS['pfb_test_file_notices'] = [];

		// When the lock is free again and the next removal stops for the python settings
		unset($GLOBALS['pfb_test_try_lock_fail']);
		$text = $this->stopTheRemoval();

		// Then it is judged on its own check, which ran
		$this->assertStringContainsString('itself was put back', $text);
		$this->assertStringNotContainsString('could not be checked', $text);
	}

	// -----------------------------------------------------------------------
	// W3 -- a saved copy this process cannot read is "could not be confirmed", never "invalid"
	// -----------------------------------------------------------------------

	/** @return array<string,array{string}> the Resolver's state recovery is required in, as a seeding method's name */
	public static function recoveryStates(): array
	{
		return ['a stored marker that is no snapshot' => ['seedUnreadableMarker'], 'our block and no snapshot' => ['seedBlockWithoutSnapshot']];
	}

	#[DataProvider('recoveryStates')]
	public function testARemovalStoppedForARecoveryItCouldNotCheckSaysTheSavedCopyCouldNotBeConfirmed(string $seed): void
	{
		// Given a Resolver recovery is required for, and a lock that stays taken
		$this->$seed();
		$GLOBALS['pfb_test_try_lock_fail'] = TRUE;

		// When the removal stops
		$text = $this->stopTheRemoval();

		// Then it names the failed check and a saved copy that could not be confirmed; it calls nothing invalid or carried
		$this->assertStringContainsString('could not be checked', $text);
		$this->assertStringContainsString('could not be confirmed', $text);
		$this->assertStringNotContainsString('invalid', $text);
		$this->assertStringNotContainsString('still carries', $text);
		$this->assertStringNotContainsString('still depends', $text);
	}

	public function testARemovalStoppedForAnInvalidMarkerWithTheLockFreeStillCallsItInvalid(): void
	{
		// Given the same marker and a free lock: the check ran
		$this->seedUnreadableMarker();

		// When the removal stops
		$text = $this->stopTheRemoval();

		// Then the marker is what it was shown to be
		$this->assertStringContainsString('is invalid', $text);
		$this->assertStringNotContainsString('could not be checked', $text);
	}

	public function testTheWizardsRefusalForARecoveryItCouldNotCheckSaysTheSavedCopyCouldNotBeConfirmed(): void
	{
		// Given a Resolver recovery is required for, and a lock that stays taken
		$this->seedUnreadableMarker();
		$GLOBALS['pfb_test_try_lock_fail'] = TRUE;

		// When the wizard resets
		step4_submitphpaction();

		// Then the one refusal says the saved copy could not be confirmed (config.xml locked), and never that it is invalid
		$this->assertCount(1, $GLOBALS['input_errors'], json_encode($GLOBALS['input_errors']));
		$error = (string) $GLOBALS['input_errors'][0];
		$this->assertStringContainsString('was not reset', $error);
		$this->assertStringContainsString('could not be confirmed', $error);
		$this->assertStringContainsString('locked by another save', $error);
		$this->assertStringNotContainsString('invalid', $error);
	}

	public function testTheWizardsRefusalForAnInvalidMarkerWithTheLockFreeStillCallsItInvalid(): void
	{
		// Given the same marker and a free lock: the check ran
		$this->seedUnreadableMarker();

		// When the wizard resets
		step4_submitphpaction();

		// Then the refusal is the one for a saved copy that is invalid
		$this->assertCount(1, $GLOBALS['input_errors'], json_encode($GLOBALS['input_errors']));
		$this->assertStringContainsString('is invalid', (string) $GLOBALS['input_errors'][0]);
		$this->assertStringNotContainsString('locked by another save', (string) $GLOBALS['input_errors'][0]);
	}
}
