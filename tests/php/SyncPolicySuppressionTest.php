<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * Issue #3452 — received-digest suppression of the automatic send, and its end by a Sync-page
 * save (docs/specs/xmlrpc-per-field-sync.md, "Apply on receive and authority", acceptance 11).
 *
 * The accepted digest is produced by a real policy receive through pfblockerng_plugin_xmlrpc_recv()
 * applied the way core's xmlrpc.php applies it. The Sync page cannot be require()d off-appliance,
 * so its real save branch is eval-extracted from the source; exit/header are the only edits.
 */
#[CoversFunction('pfblockerng_plugin_xmlrpc_send')]
#[CoversFunction('pfb_sync_receive_suppressed')]
#[CoversFunction('pfb_sync_receive_accepted_clear')]
final class SyncPolicySuppressionTest extends TestCase
{
	private string $dir;
	private mixed $savedConfig;
	private mixed $savedPfb;
	private mixed $savedPost;

	protected function setUp(): void
	{
		$this->savedConfig = $GLOBALS['config'] ?? NULL;
		$this->savedPfb    = $GLOBALS['pfb'] ?? NULL;
		$this->savedPost   = $_POST;

		$this->dir = sys_get_temp_dir() . '/pfb_sync_suppress_' . bin2hex(random_bytes(6));
		mkdir($this->dir, 0700);
		$GLOBALS['pfb']['dbdir']          = $this->dir;
		$GLOBALS['pfb']['log']            = "{$this->dir}/pfblockerng.log";
		$GLOBALS['pfb']['pending_marker'] = "{$this->dir}/pfb_pending_changes";
		$GLOBALS['pfb_test_logger_calls'] = [];
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
		$_POST = $this->savedPost;
		unset($GLOBALS['pfb_test_logger_calls']);
		pfb_sync_receive_changed(FALSE);
	}

	// ---- fixtures ----------------------------------------------------------------------

	/** @return array<string,mixed> */
	private static function alpha(string $action): array
	{
		return [
			'aliasname' => 'Alpha', 'action' => $action, 'cron' => 'EveryDay', 'srcint' => 'LOCAL-SENTINEL-srcint',
			'row' => [0 => ['format' => 'auto', 'state' => 'Enabled', 'url' => 'https://feeds.example/Alpha', 'header' => 'HdrAlpha']],
		];
	}

	/** The node stores its own Sync section, auto mode and $scope, plus a Deny_Inbound list. */
	private function seedNode(string $scope): void
	{
		$GLOBALS['config'] = ['installedpackages' => [
			'pfblockernglistsv4' => ['config' => [0 => self::alpha('Deny_Inbound')]],
			'pfblockerngsync'    => ['config' => [0 => [
				'varsynconchanges' => 'auto', 'varsynctimeout' => '5', 'syncscope' => $scope,
				'row' => [0 => [
					'varsyncdestinenable' => 'on', 'varsyncipaddress' => '192.0.2.10', 'varsyncport' => '443',
					'varsyncpassword' => 'target-pass', 'varsyncprotocol' => 'https', 'varsyncusername' => 'admin',
				]],
			]]],
		]];
	}

	/** A real accepted policy receive (action Deny_Inbound -> Alias_Native), applied as core does. */
	private function acceptPolicyReceive(): void
	{
		$sections = [
			'pfblockernglistsv4' => ['config' => [0 => self::alpha('Alias_Native')]],
			'pfblockerngsync'    => ['config' => [0 => ['syncscope' => 'policy']]],
		];
		$result = pfblockerng_plugin_xmlrpc_recv(['installedpackages' => $sections]);
		foreach ($result as $path => $value) {
			if ($path !== 'xmlrpc_recv_result') {
				config_set_path($path, $value);
			}
		}
		$this->assertNotNull($this->state()['accepted_digest'], 'before-state: the receive recorded an accepted digest');
	}

	private function state(): array
	{
		return pfb_sync_receive_state_read($this->dir);
	}

	private function stateFile(): string
	{
		return "{$this->dir}/pfb_sync_receive.json";
	}

	/** @return array<string,array{string}> */
	public static function scopes(): array
	{
		return ['policy' => ['policy'], 'all' => ['all'], 'lists' => ['lists']];
	}

	// ---- automatic send ----------------------------------------------------------------

	#[DataProvider('scopes')]
	public function testAcceptedDigestSuppressesTheAutomaticSendInEveryScope(string $scope): void
	{
		$this->seedNode($scope);
		$this->acceptPolicyReceive();
		$this->assertTrue(pfb_sync_receive_suppressed());

		$suppressed = pfblockerng_plugin_xmlrpc_send();

		unlink($this->stateFile());
		$this->assertNotSame([], pfblockerng_plugin_xmlrpc_send(), 'before-state: without the state file the same node sends');
		$this->assertSame([], $suppressed, 'the node must not echo a received policy back');
	}

	#[DataProvider('scopes')]
	public function testLocalPolicyEditLiftsTheSuppression(string $scope): void
	{
		$this->seedNode($scope);
		$this->acceptPolicyReceive();
		$this->assertSame([], pfblockerng_plugin_xmlrpc_send(), 'before-state: suppressed');

		config_set_path('installedpackages/pfblockernglistsv4/config/0/action', 'Deny_Both');

		$this->assertNotSame([], pfblockerng_plugin_xmlrpc_send());
	}

	#[DataProvider('scopes')]
	public function testClearingTheAcceptedDigestLiftsTheSuppression(string $scope): void
	{
		$this->seedNode($scope);
		$this->acceptPolicyReceive();
		$this->assertSame([], pfblockerng_plugin_xmlrpc_send(), 'before-state: suppressed');

		pfb_sync_receive_accepted_clear($this->dir);

		$this->assertNotSame([], pfblockerng_plugin_xmlrpc_send());
	}

	public function testWithoutAStateFileTheAutomaticSendIsUnchanged(): void
	{
		$this->seedNode('policy');

		$paths = pfblockerng_plugin_xmlrpc_send();

		$this->assertContains('installedpackages/pfblockernglistsv4/config/0/action', $paths);
		$this->assertContains('installedpackages/pfblockerngsync/config/0/syncscope', $paths);
	}

	// ---- Sync page save ----------------------------------------------------------------

	/**
	 * Runs the page's real POST/save branch with $post; exit/header are the only edits.
	 * @param array<string,mixed> $post
	 * @return array{bool,array<int,string>} [saved, input errors]
	 */
	private function submitSyncPage(array $post): array
	{
		static $branch = NULL;
		if ($branch === NULL) {
			$src = file_get_contents(dirname(__DIR__, 2) . '/src/usr/local/www/pfblockerng/pfblockerng_sync.php');
			$this->assertNotFalse($src);
			$this->assertSame(1, preg_match('/^(\$pfb\[\'sconfig\'\] = .*?)^\$pgtitle = /ms', $src, $m), 'the save branch must be extractable');
			$branch = $m[1];
			$this->assertSame(1, substr_count($branch, "\texit;\n"), 'one exit in the save branch');
			$this->assertSame(1, substr_count($branch, "\t\t\theader('Location: /pfblockerng/pfblockerng_sync.php');\n"));
			$branch = str_replace(["\t\t\theader('Location: /pfblockerng/pfblockerng_sync.php');\n", "exit;"], ['', 'return [TRUE, []];'], $branch);
			eval('function pfb_test_sync_page_submit(): array { global $pfb; ' . $branch . ' return [FALSE, $input_errors]; }');
		}

		$_POST = $post;
		return pfb_test_sync_page_submit();
	}

	/** @return array<string,string> */
	private static function validPost(string $scope): array
	{
		return [
			'save' => 'Save', 'varsynconchanges' => 'auto', 'varsynctimeout' => '150', 'syncscope' => $scope,
			'varsyncprotocol-0' => 'https', 'varsyncipaddress-0' => '192.0.2.10', 'varsyncport-0' => '443',
			'varsyncusername-0' => 'admin', 'varsyncpassword-0' => 'target-pass', 'varsyncdestinenable-0' => 'on',
		];
	}

	public function testValidSyncPageSaveClearsTheAcceptedDigest(): void
	{
		$this->seedNode('policy');
		$this->acceptPolicyReceive();

		[$saved, $errors] = $this->submitSyncPage(self::validPost('all'));

		$this->assertSame([TRUE, []], [$saved, $errors], 'the save must be written');
		$this->assertNull($this->state()['accepted_digest']);
		$this->assertSame('all', config_get_path('installedpackages/pfblockerngsync/config/0/syncscope'));
		$this->assertNotSame([], pfblockerng_plugin_xmlrpc_send(), 'the role flip lets the node send again');
	}

	public function testInvalidSyncPageSaveLeavesTheAcceptedDigest(): void
	{
		$this->seedNode('policy');
		$this->acceptPolicyReceive();
		$digest = $this->state()['accepted_digest'];

		[$saved, $errors] = $this->submitSyncPage(self::validPost('bogus'));

		$this->assertFalse($saved);
		$this->assertSame(['The Sync scope is invalid.'], $errors);
		$this->assertSame($digest, $this->state()['accepted_digest']);
	}
}
