<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\TestCase;

/**
 * Issue #3452 -- three receive properties the other Sync tests pin only by outcome, each mutation
 * proven: the pending marker exists before the tick is started, a suppressed manual sync returns
 * before its banner, and a leading-zero leaf change counts as a change (strict comparison).
 */
#[CoversFunction('pfblockerng_plugin_xmlrpc_recv_done')]
#[CoversFunction('pfblockerng_sync_on_changes')]
#[CoversFunction('pfb_sync_receive_policy')]
final class SyncPolicyReceiveOrderTest extends TestCase
{
	private string $dir;
	private mixed $savedConfig;
	private mixed $savedPfb;

	protected function setUp(): void
	{
		$this->savedConfig = $GLOBALS['config'] ?? NULL;
		$this->savedPfb    = $GLOBALS['pfb'] ?? NULL;

		$this->dir = sys_get_temp_dir() . '/pfb_sync_order_' . bin2hex(random_bytes(6));
		mkdir($this->dir, 0700);
		$GLOBALS['pfb']['dbdir']          = $this->dir;
		$GLOBALS['pfb']['log']            = "{$this->dir}/pfblockerng.log";
		$GLOBALS['pfb']['pending_marker'] = "{$this->dir}/pfb_pending_changes";
		$GLOBALS['pfb_test_mwexec_bg']    = [];
		$GLOBALS['pfb_test_logger_calls'] = [];
		unset($GLOBALS['pfb_test_xmlrpc_connection']);
		pfb_sync_receive_changed(FALSE);
	}

	protected function tearDown(): void
	{
		foreach (glob("{$this->dir}/*") ?: [] as $file) {
			unlink($file);
		}
		rmdir($this->dir);

		$GLOBALS['config'] = $this->savedConfig;
		if ($this->savedConfig === NULL) {
			unset($GLOBALS['config']);
		}
		$GLOBALS['pfb'] = $this->savedPfb;
		if ($this->savedPfb === NULL) {
			unset($GLOBALS['pfb']);
		}
		unset($GLOBALS['pfb_test_mwexec_bg'], $GLOBALS['pfb_test_logger_calls'], $GLOBALS['pfb_test_xmlrpc_connection']);
		pfb_sync_receive_changed(FALSE);
	}

	/** @return array<string,mixed> */
	private static function alpha(string $action): array
	{
		return [
			'aliasname' => 'Alpha', 'action' => $action, 'cron' => 'EveryDay', 'srcint' => 'LOCAL-SENTINEL-srcint',
			'row' => [0 => ['format' => 'auto', 'state' => 'Enabled', 'url' => 'https://feeds.example/Alpha', 'header' => 'HdrAlpha']],
		];
	}

	private function seedNode(): void
	{
		$GLOBALS['config'] = ['installedpackages' => [
			'pfblockerng'        => ['config' => [0 => ['pfb_schedule_hour' => '7']]],
			'pfblockernglistsv4' => ['config' => [0 => self::alpha('Deny_Inbound')]],
			'pfblockerngsync'    => ['config' => [0 => [
				'varsynconchanges' => 'manual', 'varsynctimeout' => '5', 'syncscope' => 'policy',
				'row' => [0 => [
					'varsyncdestinenable' => 'on', 'varsyncipaddress' => '192.0.2.10', 'varsyncport' => '443',
					'varsyncprotocol' => 'https', 'varsyncusername' => 'admin', 'varsyncpassword' => 'target-pass',
				]],
			]]],
		]];
	}

	/** Runs a policy receive and applies its result the way core's xmlrpc.php does. @return array<string,mixed> */
	private function receive(array $sections): array
	{
		$result = pfblockerng_plugin_xmlrpc_recv(['installedpackages' => $sections + [
			'pfblockerngsync' => ['config' => [0 => ['syncscope' => 'policy']]],
		]]);
		foreach ($result as $path => $value) {
			if ($path !== 'xmlrpc_recv_result') {
				config_set_path($path, $value);
			}
		}
		return $result;
	}

	// M1: the marker is already on disk, and the apply record already reads 'waiting', when the tick is started.
	public function testPendingMarkerExistsBeforeTheTickIsStarted(): void
	{
		$this->seedNode();
		$this->receive(['pfblockernglistsv4' => ['config' => [0 => self::alpha('Alias_Native')]]]);
		$marker = $GLOBALS['pfb']['pending_marker'];
		$this->assertFileDoesNotExist($marker, 'before-state: the receive itself marks nothing');

		$seen = [];
		$GLOBALS['pfb_test_mwexec_bg'] = new class ($seen, $marker, $this->dir) implements ArrayAccess {
			public function __construct(private array &$seen, private string $marker, private string $dir) {}
			public function offsetExists(mixed $o): bool { return FALSE; }
			public function offsetGet(mixed $o): mixed { return NULL; }
			public function offsetSet(mixed $o, mixed $v): void
			{
				$this->seen[] = [$v, file_exists($this->marker), pfb_sync_receive_state_read($this->dir)['apply']['outcome'] ?? NULL];
			}
			public function offsetUnset(mixed $o): void {}
		};

		pfblockerng_plugin_xmlrpc_recv_done(NULL);

		$this->assertCount(1, $seen, 'exactly one tick is started');
		$this->assertTrue($seen[0][1], 'the pending marker must exist when mwexec_bg() starts the tick');
		$this->assertSame('waiting', $seen[0][2], 'the apply record must read waiting when mwexec_bg() starts the tick');
	}

	// M2: a suppressed manual sync returns before it announces itself.
	public function testSuppressedManualSyncReturnsBeforeTheBanner(): void
	{
		$this->seedNode();
		$this->receive(['pfblockernglistsv4' => ['config' => [0 => self::alpha('Alias_Native')]]]);
		$this->assertTrue(pfb_sync_receive_suppressed(), 'before-state: the received policy suppresses the send');

		pfblockerng_sync_on_changes();

		$this->assertArrayNotHasKey('pfb_test_xmlrpc_connection', $GLOBALS);
		$this->assertNotContains('XMLRPC sync is starting.', array_column($GLOBALS['pfb_test_logger_calls'], 'message'));
		$this->assertStringNotContainsString('===[  XMLRPC Sync ]', (string) @file_get_contents("{$this->dir}/pfblockerng.log"));

		pfb_sync_receive_accepted_clear($this->dir);
		pfblockerng_sync_on_changes();

		$this->assertContains('XMLRPC sync is starting.', array_column($GLOBALS['pfb_test_logger_calls'], 'message'), 'control: unsuppressed, the banner shows');
		$this->assertStringContainsString('===[  XMLRPC Sync ]', (string) @file_get_contents("{$this->dir}/pfblockerng.log"));
	}

	// M4: '7' -> '007' is a change (strict !==, never numeric-string equality).
	public function testLeadingZeroLeafChangeIsReportedAsChanged(): void
	{
		$this->seedNode();

		$result = $this->receive(['pfblockerng' => ['config' => [0 => ['pfb_schedule_hour' => '007']]]]);

		$this->assertArrayHasKey('installedpackages/pfblockerng', $result);
		$this->assertSame('007', $result['installedpackages/pfblockerng']['config'][0]['pfb_schedule_hour']);
		$this->assertSame('changed', pfb_sync_receive_state_read($this->dir)['last']['outcome']);
	}
}
