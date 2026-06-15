<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\TestCase;

/**
 * PFBL-03 privileged DNSBL-control writer: pfb_unbound_py_write_control() and its
 * permission-specific publisher pfb_unbound_py_atomic_write_root().
 *
 * Scenario: the writer is the ROOT-only producer of the local privileged command
 * channel (/var/unbound/pfb_py_control, here redirected to a temp dnsbldir). It
 * validates the command + argument (the semantic layer), assembles a JSON record with
 * a monotonically-advancing sequence, and atomically publishes it. These tests pin:
 *   - the command allow-list (disable/enable/addbypass/removebypass) and rejection of
 *     anything else (no file written);
 *   - argument validation at the WRITER (invalid IP / out-of-range duration rejected,
 *     no side effect) -- the reader re-validates independently (Python suite);
 *   - the record shape (cmd/ip/duration/seq/ts) and the seq advance (replay safety);
 *   - the publisher's command-channel permission model (owner root, group unbound,
 *     mode 0640) and its atomic, no-temp-left-behind behaviour.
 *
 * Run against a temp $pfb sandbox (no live box, no chroot). chown('root') is a no-op
 * for a non-root test runner; mode 0640 is asserted because it does not need privilege.
 */
#[CoversFunction('pfb_unbound_py_write_control')]
#[CoversFunction('pfb_unbound_py_atomic_write_root')]
final class UnboundPyControlWriteTest extends TestCase
{
	private string $tmp;
	private array $originalPfb = [];
	private bool $hadPfb = false;

	protected function setUp(): void
	{
		$this->hadPfb = array_key_exists('pfb', $GLOBALS);
		$this->originalPfb = $GLOBALS['pfb'] ?? [];

		$this->tmp = sys_get_temp_dir() . '/pfb_control_' . uniqid('', true);
		mkdir($this->tmp, 0777, true);

		$GLOBALS['pfb'] = array_merge($GLOBALS['pfb'] ?? [], [
			'dnsbldir' => $this->tmp,
			'supp'     => 'off',	// pfb_filter()'s private/reserved IP exclusion off for the test
		]);
	}

	protected function tearDown(): void
	{
		if ($this->hadPfb) {
			$GLOBALS['pfb'] = $this->originalPfb;
		} else {
			unset($GLOBALS['pfb']);
		}
		$this->rrmdir($this->tmp);
	}

	private function rrmdir(string $dir): void
	{
		if (!is_dir($dir)) {
			return;
		}
		foreach (scandir($dir) as $f) {
			if ($f === '.' || $f === '..') {
				continue;
			}
			$p = "{$dir}/{$f}";
			is_dir($p) ? $this->rrmdir($p) : @unlink($p);
		}
		@rmdir($dir);
	}

	private function channel(): string
	{
		return "{$this->tmp}/pfb_py_control";
	}

	private function readRecord(): array
	{
		$raw = file_get_contents($this->channel());
		$this->assertNotFalse($raw);
		$rec = json_decode(trim($raw), true);
		$this->assertIsArray($rec);
		return $rec;
	}

	// --- the four valid commands (record shape) -----------------------------

	public function testDisableWritesRecordSeqOne(): void
	{
		// Given: no channel yet (BEFORE).
		$this->assertFileDoesNotExist($this->channel());

		// When: a root-issued disable is written.
		$this->assertSame(1, pfb_unbound_py_write_control('disable'));

		// Then: a fresh record, seq 1, no ip/duration.
		$rec = $this->readRecord();
		$this->assertSame('disable', $rec['cmd']);
		$this->assertSame(1, $rec['seq']);
		$this->assertArrayNotHasKey('ip', $rec);
		$this->assertArrayNotHasKey('duration', $rec);
		$this->assertArrayHasKey('ts', $rec);
	}

	public function testDisableWithValidDurationCarriesIt(): void
	{
		$this->assertSame(1, pfb_unbound_py_write_control('disable', '', '60'));
		$rec = $this->readRecord();
		$this->assertSame('disable', $rec['cmd']);
		$this->assertSame(60, $rec['duration']);
	}

	public function testEnableWritesRecord(): void
	{
		$this->assertSame(1, pfb_unbound_py_write_control('enable'));
		$rec = $this->readRecord();
		$this->assertSame('enable', $rec['cmd']);
		$this->assertArrayNotHasKey('ip', $rec);
	}

	public function testAddbypassCarriesIpAndDuration(): void
	{
		$this->assertSame(1, pfb_unbound_py_write_control('addbypass', '192.0.2.10', '120'));
		$rec = $this->readRecord();
		$this->assertSame('addbypass', $rec['cmd']);
		$this->assertSame('192.0.2.10', $rec['ip']);
		$this->assertSame(120, $rec['duration']);
	}

	public function testAddbypassWithoutDurationOmitsIt(): void
	{
		$this->assertSame(1, pfb_unbound_py_write_control('addbypass', '2001:db8::1'));
		$rec = $this->readRecord();
		$this->assertSame('addbypass', $rec['cmd']);
		$this->assertSame('2001:db8::1', $rec['ip']);
		$this->assertArrayNotHasKey('duration', $rec);
	}

	public function testRemovebypassCarriesIpIgnoresDuration(): void
	{
		// removebypass takes no duration; a 4th arg must be ignored (no 'duration' key).
		$this->assertSame(1, pfb_unbound_py_write_control('removebypass', '192.0.2.10', '60'));
		$rec = $this->readRecord();
		$this->assertSame('removebypass', $rec['cmd']);
		$this->assertSame('192.0.2.10', $rec['ip']);
		$this->assertArrayNotHasKey('duration', $rec);
	}

	// --- the sequence advance (replay safety) -------------------------------

	public function testSequenceAdvancesAcrossCalls(): void
	{
		// BEFORE: first write -> seq 1.
		$this->assertSame(1, pfb_unbound_py_write_control('disable'));
		// AFTER each subsequent write the seq strictly advances, read from the prior record.
		$this->assertSame(2, pfb_unbound_py_write_control('enable'));
		$this->assertSame(3, pfb_unbound_py_write_control('disable'));
		$this->assertSame(3, $this->readRecord()['seq']);
	}

	public function testSequenceFromCorruptChannelRestartsAtOne(): void
	{
		// A non-JSON / seq-less channel is treated as seq 0 -> next write is 1 (fail-safe).
		file_put_contents($this->channel(), "garbage not json\n");
		$this->assertSame(1, pfb_unbound_py_write_control('enable'));
		$this->assertSame(1, $this->readRecord()['seq']);
	}

	// --- argument validation at the writer (no side effect on reject) -------

	public function testInvalidCommandRejectedNoFileWritten(): void
	{
		$this->assertFileDoesNotExist($this->channel());
		$this->assertFalse(pfb_unbound_py_write_control('nuke-everything'));
		$this->assertFileDoesNotExist($this->channel());
	}

	public function testEmptyCommandRejected(): void
	{
		$this->assertFalse(pfb_unbound_py_write_control(''));
		$this->assertFileDoesNotExist($this->channel());
	}

	public function testAddbypassWithInvalidIpRejectedNoFileWritten(): void
	{
		$this->assertFalse(pfb_unbound_py_write_control('addbypass', '999.1.1.1'));
		$this->assertFileDoesNotExist($this->channel());
	}

	public function testAddbypassWithEmptyIpRejected(): void
	{
		$this->assertFalse(pfb_unbound_py_write_control('addbypass', ''));
		$this->assertFileDoesNotExist($this->channel());
	}

	public function testRemovebypassWithInvalidIpRejected(): void
	{
		$this->assertFalse(pfb_unbound_py_write_control('removebypass', 'not-an-ip'));
		$this->assertFileDoesNotExist($this->channel());
	}

	public function testDurationZeroRejected(): void
	{
		$this->assertFalse(pfb_unbound_py_write_control('disable', '', '0'));
		$this->assertFileDoesNotExist($this->channel());
	}

	public function testDurationAboveMaxRejected(): void
	{
		$this->assertFalse(pfb_unbound_py_write_control('disable', '', '3601'));
		$this->assertFileDoesNotExist($this->channel());
	}

	public function testDurationBoundariesAccepted(): void
	{
		// 1 and 3600 are the inclusive valid bounds.
		$this->assertSame(1, pfb_unbound_py_write_control('disable', '', '1'));
		$this->assertSame(1, $this->readRecord()['duration']);

		$this->assertSame(2, pfb_unbound_py_write_control('disable', '', '3600'));
		$this->assertSame(3600, $this->readRecord()['duration']);
	}

	public function testNonNumericDurationRejected(): void
	{
		$this->assertFalse(pfb_unbound_py_write_control('addbypass', '192.0.2.10', 'abc'));
		$this->assertFileDoesNotExist($this->channel());
	}

	// --- the publisher's command-channel permission model -------------------

	public function testPublishedChannelIsMode0640(): void
	{
		$this->assertSame(1, pfb_unbound_py_write_control('disable'));
		clearstatcache();
		// Owner read/write, group read, no other access (the command-channel model).
		$this->assertSame('0640', substr(sprintf('%o', fileperms($this->channel())), -4));
	}

	public function testAtomicWriteRootLeavesNoStagingTempBehind(): void
	{
		$path = "{$this->tmp}/cmd";
		$this->assertTrue(pfb_unbound_py_atomic_write_root($path, "x\n"));
		$leftover = array_filter(scandir($this->tmp), static function ($f) {
			return strpos($f, '.pfbctl_') === 0;
		});
		$this->assertSame([], array_values($leftover));
	}

	public function testAtomicWriteRootFailsWhenDirMissing(): void
	{
		// Staging dir absent -> tempnam fails -> FALSE, fail-safe (no crash).
		$this->assertFalse(
			pfb_unbound_py_atomic_write_root("{$this->tmp}/nope/deep/cmd", 'x')
		);
	}
}
