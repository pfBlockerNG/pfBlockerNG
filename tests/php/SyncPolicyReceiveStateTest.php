<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\TestCase;

/**
 * Issue #3452 (PR #3480 review) -- the receive state file, {dbdir}/pfb_sync_receive.json, is shared by
 * the receive request, the settling tick and the Sync page save:
 *
 *   - every writer re-reads the state while it holds the publisher's lock, so a concurrent writer's
 *     update (an accepted digest above all) is never published over;
 *   - a changed policy receive whose state cannot be published fails closed: no paths, no apply;
 *   - a failed apply-record publication is logged and changes nothing else.
 *
 * "Concurrent writer" is emulated deterministically: the publisher's `before_document` seam fires once
 * the writer holds the lock and before it builds its document, where the test publishes the other
 * writer's state. A publication failure is a lock sidecar that cannot be opened (it is a directory).
 */
#[CoversFunction('pfb_sync_receive_record')]
#[CoversFunction('pfb_sync_apply_record')]
#[CoversFunction('pfb_sync_receive_accepted_clear')]
#[CoversFunction('pfb_sync_receive_policy')]
#[CoversFunction('pfblockerng_plugin_xmlrpc_recv_done')]
final class SyncPolicyReceiveStateTest extends TestCase
{
	private const DIGEST_A = 'aa';
	private const SENTINEL = 'SENTINEL-payload-value-3480';

	private string $dir = '';
	private mixed $savedConfig = NULL;
	private mixed $savedPfb = NULL;

	protected function setUp(): void
	{
		$this->savedConfig = $GLOBALS['config'] ?? NULL;
		$this->savedPfb    = $GLOBALS['pfb'] ?? NULL;

		$this->dir = sys_get_temp_dir() . '/pfb_sync_state_' . bin2hex(random_bytes(6));
		mkdir($this->dir, 0700);
		$GLOBALS['pfb']['dbdir']          = $this->dir;
		$GLOBALS['pfb']['log']            = "{$this->dir}/pfblockerng.log";
		$GLOBALS['pfb']['pending_marker'] = "{$this->dir}/pfb_pending_changes";
		$GLOBALS['pfb_test_mwexec_bg']    = [];
		$GLOBALS['pfb_test_logger_calls'] = [];
		$GLOBALS['config']                = ['installedpackages' => [
			'pfblockerngsafesearch' => ['safesearch_enable' => 'off'],
			'pfblockerngsync'       => ['config' => [0 => ['syncscope' => 'policy']]],
		]];
		pfb_sync_receive_changed(FALSE);
	}

	protected function tearDown(): void
	{
		foreach (glob("{$this->dir}/{,.}*", GLOB_BRACE) ?: [] as $entry) {
			if (is_dir($entry) && !in_array(basename($entry), ['.', '..'], TRUE)) {
				rmdir($entry);
			} elseif (is_file($entry)) {
				unlink($entry);
			}
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
		unset($GLOBALS['pfb_test_mwexec_bg'], $GLOBALS['pfb_test_logger_calls']);
		pfb_sync_receive_changed(FALSE);
	}

	private function publish(array $state): void
	{
		file_put_contents("{$this->dir}/pfb_sync_receive.json", json_encode($state));
	}

	/** An `$io` whose seam publishes $other once, while the writer holds the lock. @param-out bool $ran */
	private function otherWriterPublishes(array $other, bool &$ran): array
	{
		return ['before_document' => function () use ($other, &$ran): void {
			$ran = TRUE;
			$this->publish($other);
		}];
	}

	private function breakPublication(): void
	{
		@unlink("{$this->dir}/pfb_sync_receive.json.lock");
		mkdir("{$this->dir}/pfb_sync_receive.json.lock");
	}

	/** @return list<string> */
	private function messages(): array
	{
		return array_column($GLOBALS['pfb_test_logger_calls'], 'message');
	}

	private function receiveChangedPolicy(): array
	{
		return pfblockerng_plugin_xmlrpc_recv(['installedpackages' => [
			'pfblockerngsafesearch' => ['safesearch_enable' => self::SENTINEL],
			'pfblockerngsync'       => ['config' => [0 => ['syncscope' => 'policy']]],
		]]);
	}

	// ---- every writer re-reads the state under the lock ---------------------------------

	public function testApplyRecordKeepsTheAcceptedDigestAnotherWriterPublishedMeanwhile(): void
	{
		$open = ['time' => 100, 'opened' => 100, 'outcome' => 'waiting'];
		$this->publish(['accepted_digest' => self::DIGEST_A, 'last' => NULL, 'apply' => $open]);
		$ran = FALSE;

		pfb_sync_apply_record(
			'applied', 'update pass completed; firewall reload started', $this->dir, FALSE, NULL,
			$this->otherWriterPublishes(['accepted_digest' => 'bb', 'last' => ['time' => 150, 'outcome' => 'changed'], 'apply' => $open], $ran)
		);

		$state = pfb_sync_receive_state_read($this->dir);
		$this->assertSame('bb', $state['accepted_digest'], 'the other writer\'s accepted digest survives');
		$this->assertSame('changed', $state['last']['outcome'] ?? NULL, 'the other writer\'s receive record survives');
		$this->assertSame('applied', $state['apply']['outcome'] ?? NULL, 'the apply record still moved');
		$this->assertTrue($ran, 'before-state check: the other writer published while this one held the lock');
	}

	public function testApplyRecordDecidesOnTheApplyRecordAnotherWriterPublishedMeanwhile(): void
	{
		// Read before the lock, the record would still look open and be moved; under the lock it was settled by the other writer.
		$this->publish(['accepted_digest' => NULL, 'last' => NULL, 'apply' => ['time' => 100, 'opened' => 100, 'outcome' => 'waiting']]);
		$ran = FALSE;

		pfb_sync_apply_record(
			'failed', 'apply failed; pending changes kept', $this->dir, FALSE, NULL,
			$this->otherWriterPublishes(['accepted_digest' => NULL, 'last' => NULL, 'apply' => ['time' => 120, 'opened' => 100, 'outcome' => 'applied']], $ran)
		);

		$this->assertSame('applied', pfb_sync_receive_state_read($this->dir)['apply']['outcome'] ?? NULL, 'a settled record is not moved again');
		$this->assertTrue($ran, 'before-state check: the other writer published while this one held the lock');
	}

	public function testReceiveRecordKeepsTheApplyRecordAnotherWriterPublishedMeanwhile(): void
	{
		$this->publish(['accepted_digest' => NULL, 'last' => NULL]);
		$ran = FALSE;
		$settled = ['time' => 120, 'opened' => 100, 'outcome' => 'applied'];

		pfb_sync_receive_record(
			'unchanged', self::DIGEST_A, '', $this->dir,
			$this->otherWriterPublishes(['accepted_digest' => NULL, 'last' => NULL, 'apply' => $settled], $ran)
		);

		$state = pfb_sync_receive_state_read($this->dir);
		$this->assertSame($settled, $state['apply'] ?? NULL, 'the other writer\'s apply record survives');
		$this->assertSame(self::DIGEST_A, $state['accepted_digest']);
		$this->assertSame('unchanged', $state['last']['outcome'] ?? NULL);
		$this->assertTrue($ran, 'before-state check: the other writer published while this one held the lock');
	}

	public function testRefusedReceiveKeepsTheAcceptedDigestAnotherWriterPublishedMeanwhile(): void
	{
		$this->publish(['accepted_digest' => self::DIGEST_A, 'last' => NULL]);
		$ran = FALSE;

		pfb_sync_receive_record(
			'refused', NULL, 'syncscope is not policy', $this->dir,
			$this->otherWriterPublishes(['accepted_digest' => 'bb', 'last' => NULL], $ran)
		);

		$this->assertSame('bb', pfb_sync_receive_state_read($this->dir)['accepted_digest'], 'a refusal keeps the digest accepted last');
		$this->assertTrue($ran, 'before-state check: the other writer published while this one held the lock');
	}

	public function testAcceptedClearKeepsTheRecordsAnotherWriterPublishedMeanwhile(): void
	{
		$this->publish(['accepted_digest' => self::DIGEST_A, 'last' => NULL]);
		$ran = FALSE;
		$apply = ['time' => 120, 'opened' => 120, 'outcome' => 'waiting'];

		pfb_sync_receive_accepted_clear(
			$this->dir,
			$this->otherWriterPublishes(['accepted_digest' => self::DIGEST_A, 'last' => ['time' => 120, 'outcome' => 'changed'], 'apply' => $apply], $ran)
		);

		$state = pfb_sync_receive_state_read($this->dir);
		$this->assertNull($state['accepted_digest'], 'the clear itself took effect');
		$this->assertSame('changed', $state['last']['outcome'] ?? NULL, 'the other writer\'s receive record survives');
		$this->assertSame($apply, $state['apply'] ?? NULL, 'the other writer\'s apply record survives');
		$this->assertTrue($ran, 'before-state check: the other writer published while this one held the lock');
	}

	// ---- a changed receive that cannot publish its state fails closed -------------------

	public function testChangedReceiveWithUnpublishableStateReturnsNoPathsAndStartsNoApply(): void
	{
		$control = $this->receiveChangedPolicy();
		$this->assertArrayHasKey('installedpackages/pfblockerngsafesearch', $control, 'before-state check: the payload is a change');
		$this->assertTrue(pfb_sync_receive_changed(), 'before-state check: and it is flagged for the apply');
		pfb_sync_receive_changed(FALSE);
		unlink("{$this->dir}/pfb_sync_receive.json");
		$GLOBALS['pfb_test_logger_calls'] = [];

		$this->breakPublication();
		$result = $this->receiveChangedPolicy();
		pfblockerng_plugin_xmlrpc_recv_done(NULL);

		$this->assertSame([], $result, 'no configuration path is handed back');
		$this->assertFalse(pfb_sync_receive_changed());
		$this->assertSame([], $GLOBALS['pfb_test_mwexec_bg'], 'no tick is dispatched');
		$this->assertFileDoesNotExist($GLOBALS['pfb']['pending_marker'], 'nothing is marked pending');
		$this->assertFileDoesNotExist("{$this->dir}/pfb_sync_receive.json");
		$this->assertStringContainsString('XMLRPC policy receive: state not published.', implode("\n", $this->messages()));
		$this->assertStringNotContainsString(self::SENTINEL, implode("\n", $this->messages()), 'the log line carries no payload value');
	}

	public function testApplyRecordPublicationFailureIsLoggedValueFreeAndChangesNothingElse(): void
	{
		$state = ['accepted_digest' => self::DIGEST_A, 'last' => ['time' => 1, 'outcome' => 'changed']];
		$this->publish($state);
		$this->breakPublication();

		pfb_sync_apply_record('waiting', '', $this->dir, TRUE);

		$this->assertSame($state, pfb_sync_receive_state_read($this->dir), 'the state is as it was');
		$this->assertStringContainsString('XMLRPC policy receive: state not published.', implode("\n", $this->messages()));
		$this->assertStringNotContainsString(self::DIGEST_A, implode("\n", $this->messages()));
	}
}
