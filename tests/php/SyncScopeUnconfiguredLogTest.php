<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * Issue #3452 -- a manual sync with targets but no configured scope sends nothing and says so:
 * one value-free warning, never the transport's " Failed!" (the guard in
 * pfblockerng_do_xmlrpc_sync() stays; this pins what the operator reads).
 */
#[CoversFunction('pfblockerng_sync_on_changes')]
final class SyncScopeUnconfiguredLogTest extends TestCase
{
	private const WARNING  = 'XMLRPC sync scope is not configured; nothing was sent.';
	private const UNSTORED = "\0unstored";

	private string $dir;
	private mixed $savedConfig;
	private mixed $savedPfb;

	protected function setUp(): void
	{
		$this->savedConfig = $GLOBALS['config'] ?? NULL;
		$this->savedPfb    = $GLOBALS['pfb'] ?? NULL;

		$this->dir = sys_get_temp_dir() . '/pfb_scope_unconf_' . bin2hex(random_bytes(6));
		mkdir($this->dir, 0700);
		$GLOBALS['pfb']['dbdir']          = $this->dir;
		$GLOBALS['pfb']['log']            = "{$this->dir}/pfblockerng.log";
		$GLOBALS['pfb_test_logger_calls'] = [];
		unset($GLOBALS['pfb_test_xmlrpc_connection'], $GLOBALS['pfb_test_xmlrpc_connections'], $GLOBALS['pfb_test_xmlrpc_calls']);
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
		unset($GLOBALS['pfb_test_logger_calls'], $GLOBALS['pfb_test_xmlrpc_connection'], $GLOBALS['pfb_test_xmlrpc_connections'], $GLOBALS['pfb_test_xmlrpc_calls']);
	}

	/** @param array<int,array<string,string>>|NULL $row */
	private function seed(mixed $scope, string $mode, ?array $row): void
	{
		$sync = ['varsynconchanges' => $mode, 'varsynctimeout' => '5'];
		if ($scope !== self::UNSTORED) {
			$sync['syncscope'] = $scope;
		}
		if ($row !== NULL) {
			$sync['row'] = $row;
		}
		$GLOBALS['config'] = ['installedpackages' => [
			'pfblockerngglobal' => ['feed_foo' => 'on'],
			'pfblockerngsync'   => ['config' => [0 => $sync]],
		]];
	}

	/** @return array<int,array<string,string>> */
	private static function target(): array
	{
		return [0 => [
			'varsyncdestinenable' => 'on', 'varsyncipaddress' => '192.0.2.10', 'varsyncport' => '443',
			'varsyncprotocol' => 'https', 'varsyncusername' => 'admin', 'varsyncpassword' => 'secret-pass',
		]];
	}

	/** @return list<string> */
	private function messages(): array
	{
		return array_column($GLOBALS['pfb_test_logger_calls'] ?? [], 'message');
	}

	private function pfbLog(): string
	{
		return (string) @file_get_contents("{$this->dir}/pfblockerng.log");
	}

	/** @return array<string,array{mixed}> */
	public static function unconfiguredScopes(): array
	{
		return ['unstored' => [self::UNSTORED], 'empty' => [''], 'bogus' => ['bogus']];
	}

	#[DataProvider('unconfiguredScopes')]
	public function testUnconfiguredScopeSendsNothingAndWarnsOnceWithoutFailed(mixed $scope): void
	{
		$this->seed($scope, 'manual', self::target());

		pfblockerng_sync_on_changes();

		$this->assertArrayNotHasKey('pfb_test_xmlrpc_connection', $GLOBALS, 'nothing is sent');
		$this->assertSame([], $GLOBALS['pfb_test_xmlrpc_calls'] ?? []);
		$this->assertSame(1, count(array_keys($this->messages(), self::WARNING, TRUE)), 'the warning is logged exactly once');
		$warned = array_values(array_filter(
			$GLOBALS['pfb_test_logger_calls'],
			static fn (array $c): bool => $c['message'] === self::WARNING
		));
		$this->assertSame(LOG_WARNING, $warned[0]['priority']);
		$this->assertStringNotContainsString('Failed!', $this->pfbLog(), 'a not-sent sync is not a transport failure');
		$this->assertStringNotContainsString('secret-pass', implode("\n", $this->messages()) . $this->pfbLog());
		$this->assertStringNotContainsString('192.0.2.10', implode("\n", $this->messages()), 'the warning carries no config value');
	}

	public function testConfiguredPolicyScopeStillSendsAndDoesNotWarn(): void
	{
		$this->seed('policy', 'manual', self::target());

		pfblockerng_sync_on_changes();

		$this->assertArrayHasKey('pfb_test_xmlrpc_connection', $GLOBALS, 'control: a configured scope sends');
		$this->assertNotContains(self::WARNING, $this->messages());
		$this->assertStringNotContainsString('Failed!', $this->pfbLog());
	}

	public function testUnconfiguredScopeWithoutTargetsKeepsTheNoTargetsWarning(): void
	{
		$this->seed(self::UNSTORED, 'manual', NULL);

		pfblockerng_sync_on_changes();

		$this->assertNotContains(self::WARNING, $this->messages());
		$this->assertContains('Manual XMLRPC sync is enabled but there are no replication targets configured.', $this->messages());
	}

	public function testUnconfiguredScopeInAutoModeStaysSilent(): void
	{
		$this->seed(self::UNSTORED, 'auto', self::target());

		pfblockerng_sync_on_changes();

		$this->assertNotContains(self::WARNING, $this->messages());
		$this->assertArrayNotHasKey('pfb_test_xmlrpc_connection', $GLOBALS);
	}
}
