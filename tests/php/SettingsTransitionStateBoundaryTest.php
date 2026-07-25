<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;

final class SettingsTransitionStateBoundaryTest extends TestCase
{
	private string $root;

	protected function setUp(): void
	{
		$this->root = sys_get_temp_dir() . '/pfb_state_boundary_' . bin2hex(random_bytes(5));
		mkdir($this->root, 0700, TRUE);
	}

	protected function tearDown(): void
	{
		$this->removeTree($this->root);
	}

	public function testReadRejectsStateWithWorldReadableMode(): void
	{
		$path = $this->writeState($this->validState());
		chmod($path, 0644);
		$this->assertThrows(InvalidArgumentException::class, fn() => pfb_settings_transition_state_read($this->root));
	}

	public function testReadRejectsStateWithHardlinkCountGreaterThanOne(): void
	{
		$path = $this->writeState($this->validState());
		$this->assertTrue(link($path, $this->root . '/state-copy'));
		$this->assertThrows(InvalidArgumentException::class, fn() => pfb_settings_transition_state_read($this->root));
	}

	public function testRecordDivergenceRejectsSameFamilyBeforePublication(): void
	{
		$this->assertThrows(
			InvalidArgumentException::class,
			fn() => pfb_settings_transition_state_record_divergence(
				'3.2', '3.2', str_repeat('a', 64), str_repeat('b', 64), $this->root
			)
		);
		$this->assertSame([], pfb_settings_transition_state_read($this->root)['divergences']);
		$this->assertFileDoesNotExist($this->root . '/transition-state.json');
	}

	public function testReadRejectsMalformedSameFamilyDivergence(): void
	{
		$this->writeState([
			'state_version' => 1,
			'activations' => ['3.2' => '', '4.0' => ''],
			'divergences' => [[
				'source_family' => '4.0',
				'target_family' => '4.0',
				'source_snapshot_sha256' => str_repeat('a', 64),
				'target_snapshot_sha256' => str_repeat('b', 64),
				'acknowledged' => FALSE,
			]],
		]);
		$this->assertThrows(InvalidArgumentException::class, fn() => pfb_settings_transition_state_read($this->root));
	}

	public function testReadRejectsWrongOwnerWhenPrivilegeAllowsConstruction(): void
	{
		if (!function_exists('posix_geteuid') || posix_geteuid() !== 0) {
			$this->markTestSkipped('running as non-root; cannot chown transition state to a wrong owner');
		}
		$other = function_exists('posix_getpwnam') ? posix_getpwnam('nobody') : FALSE;
		if (!is_array($other) || !isset($other['uid'])) {
			$this->markTestSkipped('nobody account unavailable; cannot chown transition state to a wrong owner');
		}
		$path = $this->writeState($this->validState());
		if (!chown($path, (int) $other['uid'])) {
			$this->markTestSkipped('chown to nobody failed; cannot construct wrong-owner transition state');
		}
		$this->assertThrows(InvalidArgumentException::class, fn() => pfb_settings_transition_state_read($this->root));
	}

	private function validState(): array
	{
		return [
			'state_version' => 1,
			'activations' => ['3.2' => '', '4.0' => ''],
			'divergences' => [],
		];
	}

	private function writeState(array $state): string
	{
		$path = $this->root . '/transition-state.json';
		file_put_contents($path, json_encode($state, JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR));
		chmod($path, 0600);
		return $path;
	}

	private function assertThrows(string $class, Closure $call): void
	{
		try {
			$call();
		} catch (Throwable $error) {
			$this->assertInstanceOf($class, $error);
			return;
		}
		$this->fail('expected ' . $class);
	}

	private function removeTree(string $path): void
	{
		if (!is_dir($path) || is_link($path)) {
			@unlink($path);
			return;
		}
		foreach (scandir($path) ?: [] as $entry) {
			if ($entry !== '.' && $entry !== '..') {
				$this->removeTree($path . '/' . $entry);
			}
		}
		@rmdir($path);
	}
}
