<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\TestCase;

require_once __DIR__ . '/SyncPolicyFixtureTrait.php';

/**
 * Issue #3453 -- drift: this node's current policy digest against the digest of the last accepted
 * receive (docs/specs/xmlrpc-per-field-sync.md, "Reporting"; acceptance 12, drift part).
 *
 * Drift is NULL without an accepted digest, FALSE while the stored policy still equals it and TRUE after a
 * local policy edit. Receiver-local leaves and the key order of a settings map never count; the row order
 * of a list does.
 */
#[CoversFunction('pfb_sync_receive_drift')]
#[CoversFunction('pfb_sync_policy_current_digest')]
#[CoversFunction('pfb_sync_receive_suppressed')]
#[CoversFunction('pfb_sync_receive_accepted_clear')]
final class SyncPolicyDriftTest extends TestCase
{
	use SyncPolicyFixtureTrait;

	private string $dir;
	private mixed $savedConfig;
	private mixed $savedPfb;

	protected function setUp(): void
	{
		$this->savedConfig = $GLOBALS['config'] ?? NULL;
		$this->savedPfb    = $GLOBALS['pfb'] ?? NULL;

		$this->dir = sys_get_temp_dir() . '/pfb_sync_drift_' . bin2hex(random_bytes(6));
		mkdir($this->dir, 0700);

		$GLOBALS['pfb']['dbdir']          = $this->dir;
		$GLOBALS['pfb']['log']            = "{$this->dir}/pfblockerng.log";
		$GLOBALS['pfb']['pending_marker'] = "{$this->dir}/pfb_pending_changes";
		$GLOBALS['pfb_test_mwexec_bg']    = [];
		$GLOBALS['pfb_test_logger_calls'] = [];

		pfb_sync_receive_changed(FALSE);
		$GLOBALS['config'] = ['installedpackages' => [
			'pfblockerng'              => ['config' => [0 => ['pfb_keep' => 'old', 'pfb_schedule_hour' => '1']]],
			'pfblockerngipsettings'    => ['config' => [0 => ['inbound_interface' => 'wan']]],
			'pfblockernglistsv4'       => ['config' => [0 => self::group('Alpha', 'LOCAL-a')]],
			'pfblockerngsync'          => ['config' => [0 => ['syncscope' => 'policy']]],
		]];
	}

	protected function tearDown(): void
	{
		foreach (glob("{$this->dir}/*") ?: [] as $file) {
			unlink($file);
		}
		rmdir($this->dir);

		if ($this->savedConfig === NULL) {
			unset($GLOBALS['config']);
		} else {
			$GLOBALS['config'] = $this->savedConfig;
		}
		if ($this->savedPfb === NULL) {
			unset($GLOBALS['pfb']);
		} else {
			$GLOBALS['pfb'] = $this->savedPfb;
		}
		unset($GLOBALS['pfb_test_mwexec_bg'], $GLOBALS['pfb_test_logger_calls']);
		pfb_sync_receive_changed(FALSE);
	}

	// ---- fixtures ----------------------------------------------------------------------

	/** @return array<string,mixed> */
	private static function group(string $alias, ?string $srcint = NULL): array
	{
		return ['aliasname' => $alias, 'action' => 'Deny_Inbound', 'cron' => 'EveryDay', 'row' => [0 => [
			'format' => 'auto', 'state' => 'Enabled', 'url' => "https://feeds.example/{$alias}", 'header' => "Hdr{$alias}",
		]]] + ($srcint === NULL ? [] : ['srcint' => $srcint]);
	}

	/** @return array<string,mixed> a policy payload: two v4 rows and two settings keys */
	private static function payload(): array
	{
		return [
			'pfblockerng'        => ['config' => [0 => ['pfb_keep' => 'new', 'pfb_schedule_hour' => '7']]],
			'pfblockernglistsv4' => ['config' => [0 => self::group('Alpha'), 1 => self::group('Bravo')]],
			'pfblockerngsync'    => ['config' => [0 => ['syncscope' => 'policy']]],
		];
	}

	/** Runs the receive hook and applies its result the way core's xmlrpc.php does. */
	private function receive(array $sections): void
	{
		$result = $this->assertNoDiagnostics(
			static fn (): array => pfblockerng_plugin_xmlrpc_recv(['installedpackages' => $sections])
		);
		foreach ($result as $path => $value) {
			if ($path !== 'xmlrpc_recv_result') {
				config_set_path($path, $value);
			}
		}
	}

	private function stateFile(): string
	{
		return "{$this->dir}/pfb_sync_receive.json";
	}

	// ---- 10 ---------------------------------------------------------------------------

	public function testDriftIsNullWithoutAStateFile(): void
	{
		$this->assertFileDoesNotExist($this->stateFile());
		$this->assertNull(pfb_sync_receive_drift($this->dir));
	}

	public function testDriftIsNullForACorruptStateFile(): void
	{
		file_put_contents($this->stateFile(), '{"accepted_digest": "ab');
		$this->assertNull(pfb_sync_receive_drift($this->dir));
	}

	public function testDriftIsNullAfterTheAcceptedDigestIsCleared(): void
	{
		$this->receive(self::payload());
		$this->assertFalse(pfb_sync_receive_drift($this->dir), 'fixture: a digest is accepted first');

		pfb_sync_receive_accepted_clear($this->dir);

		$this->assertNull(pfb_sync_receive_drift($this->dir));
	}

	// ---- 11 ---------------------------------------------------------------------------

	public function testNoDriftRightAfterAnAcceptedReceive(): void
	{
		$this->receive(self::payload());

		$this->assertFalse(pfb_sync_receive_drift($this->dir));
		$this->assertSame(
			pfb_sync_receive_state_read($this->dir)['accepted_digest'],
			pfb_sync_policy_current_digest()
		);
		$this->assertTrue(pfb_sync_receive_suppressed(), 'the suppression predicate agrees with the helper');
	}

	// ---- 12 ---------------------------------------------------------------------------

	public function testLocalPolicyEditIsDrift(): void
	{
		$this->receive(self::payload());

		config_set_path('installedpackages/pfblockerng/config/0/pfb_keep', 'edited locally');

		$this->assertTrue(pfb_sync_receive_drift($this->dir));
		$this->assertFalse(pfb_sync_receive_suppressed());
	}

	// ---- 13 ---------------------------------------------------------------------------

	public function testLocalOnlyEditIsNotDrift(): void
	{
		$this->receive(self::payload());

		config_set_path('installedpackages/pfblockerngipsettings/config/0/inbound_interface', 'lan');
		config_set_path('installedpackages/pfblockernglistsv4/config/0/srcint', 'LOCAL-changed');

		$this->assertFalse(pfb_sync_receive_drift($this->dir));
	}

	// ---- 14 ---------------------------------------------------------------------------

	public function testListRowReorderIsDrift(): void
	{
		$this->receive(self::payload());
		$rows = config_get_path('installedpackages/pfblockernglistsv4/config');
		$this->assertCount(2, $rows, 'fixture: two rows were received');

		config_set_path('installedpackages/pfblockernglistsv4/config', array_reverse($rows));

		$this->assertTrue(pfb_sync_receive_drift($this->dir));
	}

	public function testSettingsMapKeyReorderIsNotDrift(): void
	{
		$this->receive(self::payload());
		$map = config_get_path('installedpackages/pfblockerng/config/0');
		$this->assertGreaterThanOrEqual(2, count($map), 'fixture: the settings map has several keys');

		config_set_path('installedpackages/pfblockerng/config/0', array_reverse($map, TRUE));

		$this->assertNotSame(array_keys($map), array_keys(config_get_path('installedpackages/pfblockerng/config/0')));
		$this->assertFalse(pfb_sync_receive_drift($this->dir));
	}
}
