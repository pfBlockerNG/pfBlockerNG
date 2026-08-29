<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\TestCase;

#[CoversFunction('pfb_unbound_python_sources')]
#[CoversFunction('pfb_unbound_python_sources_patch')]
#[CoversFunction('pfb_unbound_py_publication_lock')]
#[CoversFunction('pfb_unbound_py_gc')]
#[CoversFunction('pfb_unbound_py_teardown_raw_set')]
final class DnsblManifestAtomicGenerationTest extends TestCase
{
	private string $tmp;
	private array $originalPfb = [];
	private bool $hadPfb = FALSE;

	protected function setUp(): void
	{
		$this->hadPfb = array_key_exists('pfb', $GLOBALS);
		$this->originalPfb = $GLOBALS['pfb'] ?? [];
		$this->tmp = sys_get_temp_dir() . '/pfb_generation_' . uniqid('', TRUE);
		mkdir("{$this->tmp}/dnsbl", 0777, TRUE);
		mkdir("{$this->tmp}/db", 0777, TRUE);
		$GLOBALS['pfb'] = array_merge($GLOBALS['pfb'] ?? [], [
			'log'                => "{$this->tmp}/pfblockerng.log",
			'errlog'             => "{$this->tmp}/error.log",
			'dnsbldir'           => $this->tmp,
			'unbound_py_rawdir'  => "{$this->tmp}/pfb_py_raw",
			'dnsdir'             => "{$this->tmp}/dnsbl",
			'unbound_py_sources' => "{$this->tmp}/pfb_py_sources.json",
			'unbound_py_top1m'   => "{$this->tmp}/pfb_py_top1m.txt",
			'dbdir'              => "{$this->tmp}/db",
			'dnsbl_top1m'        => 'off',
			'dnsbl_unlock'       => "{$this->tmp}/dnsbl_unlock",
			'dnsbl_tld_wildcard' => '',
			'dnsblconfig'        => ['tld_wildcard_blacklist' => '', 'tld_wildcard_exclusion' => '', 'whitelist' => ''],
		]);
		$this->writeFeed('one.example');
	}

	protected function tearDown(): void
	{
		unset($GLOBALS['pfb_test_process_running']);
		if ($this->hadPfb) {
			$GLOBALS['pfb'] = $this->originalPfb;
		} else {
			unset($GLOBALS['pfb']);
		}
		rmdir_recursive($this->tmp);
	}

	private function writeFeed(string $domain): void
	{
		file_put_contents("{$this->tmp}/dnsbl/feed1.txt",
			pfb_dnsbl_ndjson_emit_row(PfbDnsblRowKind::Domain, $domain));
	}

	private function publish(array $publicationOps = []): array|false
	{
		return pfb_unbound_python_sources([
			['header' => 'feed1', 'group' => 'Group', 'log' => '1', 'provenance' => 'feed'],
		], $publicationOps);
	}

	private function manifestRaw(array $manifest): string
	{
		return "{$this->tmp}/{$manifest['feeds'][0]['raw']}";
	}

	private function versionDirs(): array
	{
		$dirs = glob("{$this->tmp}/pfb_py_raw.*") ?: [];
		return array_values(array_filter($dirs,
			static fn(string $path): bool => preg_match('/pfb_py_raw\.[0-9a-f]{32}$/D', $path) === 1));
	}

	private function readEvent(mixed $stream, string $awaited, bool $child = FALSE): string
	{
		$line = @fgets($stream);
		if ($line !== FALSE) {
			if (str_starts_with($line, 'SALVAGE_EXPIRED ')) {
				$this->fail(trim(substr($line, strlen('SALVAGE_EXPIRED '))));
			}
			return $line;
		}
		$meta = stream_get_meta_data($stream);
		$reason = ($meta['timed_out'] ?? FALSE) ? 'timeout' : (feof($stream) ? 'EOF' : 'read failure');
		$message = "salvage cap expired / stuck or environment: awaiting {$awaited}";
		if ($child) {
			@fwrite($stream, "SALVAGE_EXPIRED {$message} ({$reason})\n");
			exit(2);
		}
		$this->fail("{$message} ({$reason})");
	}

	/** @return array{0:mixed,1:mixed} */
	private function signalPair(): array
	{
		$pair = @stream_socket_pair(STREAM_PF_UNIX, STREAM_SOCK_STREAM, 0);
		if ($pair === FALSE) {
			$this->markTestSkipped('stream_socket_pair() failed -- cannot signal across the fork.');
		}
		return $pair;
	}

	private function expectChildEvent(mixed $stream, string $expected, string $awaited): void
	{
		$event = trim($this->readEvent($stream, $awaited, TRUE));
		if ($event !== $expected) {
			@fwrite($stream, "EVENT_ERROR awaiting {$awaited}; expected {$expected}; got {$event}\n");
			exit(2);
		}
	}

	private function cleanupPublicationHolder(?int &$pid, mixed &$parent, ?Throwable &$cleanupError): void
	{
		if (is_resource($parent)) {
			@fwrite($parent, "RELEASE\n");
			try {
				$event = trim($this->readEvent($parent, 'publication timeout holder cleanup'));
				if ($event !== 'UNLOCKED') {
					throw new RuntimeException(
						"publication timeout holder cleanup expected UNLOCKED, got {$event}"
					);
				}
			} catch (Throwable $error) {
				$cleanupError ??= $error;
			}
			@fclose($parent);
			$parent = NULL;
		}
		if (is_int($pid) && $pid > 0) {
			$waited = pcntl_waitpid($pid, $status, WNOHANG);
			if ($waited === 0) {
				if (function_exists('posix_kill')) {
					@posix_kill($pid, SIGKILL);
					$waited = pcntl_waitpid($pid, $status);
				} elseif ($cleanupError === NULL) {
					$cleanupError = new RuntimeException('publication timeout holder cannot be reaped: posix_kill unavailable');
				}
			}
			if ($waited < 0 && $cleanupError === NULL) {
				$cleanupError = new RuntimeException('publication timeout holder waitpid failed');
			} elseif ($waited > 0 && (!pcntl_wifexited($status) || pcntl_wexitstatus($status) !== 0)
				&& $cleanupError === NULL) {
				$cleanupError = new RuntimeException('publication timeout holder exited unsuccessfully');
			}
			$pid = NULL;
		}
	}

	private function assertContendedOperationTimesOut(callable $operation): void
	{
		if (!function_exists('pcntl_fork') || !function_exists('posix_kill')) {
			$this->markTestSkipped('pcntl_fork() and posix_kill() required for fork cleanup.');
		}

		$manifestBefore = (string) file_get_contents($GLOBALS['pfb']['unbound_py_sources']);
		$holderPid = NULL;
		$operationPid = NULL;
		$holderParent = NULL;
		$operationParent = NULL;
		try {
			[$holderParent, $holderChild] = $this->signalPair();
			stream_set_timeout($holderParent, 5);
			stream_set_timeout($holderChild, 5);
			$holderPid = pcntl_fork();
			if ($holderPid === 0) {
				fclose($holderParent);
				$lock = pfb_unbound_py_publication_lock();
				if (!is_resource($lock)) {
					fwrite($holderChild, "HOLDER_ERROR\n");
					fclose($holderChild);
					exit(1);
				}
				fwrite($holderChild, "LOCKED\n");
				$this->expectChildEvent($holderChild, 'RELEASE', 'publication holder release');
				pfb_unbound_py_publication_unlock($lock);
				fwrite($holderChild, "UNLOCKED\n");
				fclose($holderChild);
				exit(0);
			}
			$this->assertGreaterThan(0, $holderPid);
			fclose($holderChild);
			$this->assertSame("LOCKED\n", $this->readEvent($holderParent, 'publication holder acquisition'));

			[$operationParent, $operationChild] = $this->signalPair();
			stream_set_timeout($operationParent, 5);
			stream_set_timeout($operationChild, 5);
			$operationPid = pcntl_fork();
			if ($operationPid === 0) {
				fclose($holderParent);
				fclose($operationParent);
				try {
					$ok = $operation();
					fwrite($operationChild, "RESULT\n");
					fwrite($operationChild, json_encode(['ok' => $ok]) . "\n");
				} catch (Throwable $error) {
					$message = preg_replace('/\s+/', ' ', trim($error->getMessage()));
					$message = is_string($message) && $message !== '' ? substr($message, 0, 512) : get_class($error);
					@fwrite($operationChild, "OPERATION_ERROR {$message}\n");
					@fclose($operationChild);
					exit(1);
				}
				fclose($operationChild);
				exit(0);
			}
			$this->assertGreaterThan(0, $operationPid);
			fclose($operationChild);

			$operationVerdict = $this->readEvent($operationParent, 'contended operation verdict');
			if (str_starts_with($operationVerdict, 'OPERATION_ERROR ')) {
				throw new RuntimeException(trim($operationVerdict));
			}
			$this->assertSame("RESULT\n", $operationVerdict);
			$result = json_decode($this->readEvent($operationParent, 'contended operation result'), TRUE);
			$this->assertIsArray($result);
			$this->assertArrayHasKey('ok', $result);
			$this->assertFalse($result['ok'], 'contended interactive operation must publish a false skip verdict');
			$this->assertSame($manifestBefore, file_get_contents($GLOBALS['pfb']['unbound_py_sources']),
				'lock timeout must not mutate the published manifest');
			fwrite($holderParent, "RELEASE\n");
			$this->assertSame("UNLOCKED\n", $this->readEvent($holderParent, 'publication holder unlock'));
			fclose($holderParent);
			pcntl_waitpid($holderPid, $holderStatus);
			$holderPid = NULL;
			pcntl_waitpid($operationPid, $operationStatus);
			$operationPid = NULL;
			$this->assertTrue(pcntl_wifexited($holderStatus) && pcntl_wexitstatus($holderStatus) === 0,
				'publication holder must exit cleanly after the release event');
			$this->assertTrue(pcntl_wifexited($operationStatus) && pcntl_wexitstatus($operationStatus) === 0,
				'contended operation must exit cleanly after publishing its verdict');
		} finally {
			if (is_resource($holderParent)) {
				@fwrite($holderParent, "RELEASE\n");
				fclose($holderParent);
			}
			if (is_resource($operationParent)) {
				fclose($operationParent);
			}
			foreach ([$holderPid, $operationPid] as $pid) {
				if (is_int($pid) && $pid > 0) {
					if (pcntl_waitpid($pid, $childStatus, WNOHANG) === 0 && function_exists('posix_kill')) {
						posix_kill($pid, SIGKILL);
					}
					pcntl_waitpid($pid, $childStatus);
				}
			}
		}
	}

	public function testSuccessfulPublicationKeepsOldSetAndCommitsOneCompleteGeneration(): void
	{
		mkdir($GLOBALS['pfb']['unbound_py_rawdir']);
		file_put_contents("{$GLOBALS['pfb']['unbound_py_rawdir']}/old.raw", 'old-bytes');
		$oldManifest = json_encode(['version' => 1, 'config' => [], 'feeds' => [
			['raw' => 'pfb_py_raw/old.raw', 'feed' => 'Old'],
		]], JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);
		file_put_contents($GLOBALS['pfb']['unbound_py_sources'], $oldManifest);

		$manifest = $this->publish();

		$this->assertIsArray($manifest);
		$this->assertMatchesRegularExpression('/^pfb_py_raw\.[0-9a-f]{32}\/feed1\.raw$/D', $manifest['feeds'][0]['raw']);
		$this->assertSame("one.example\n", file_get_contents($this->manifestRaw($manifest)));
		$this->assertSame('old-bytes', file_get_contents("{$GLOBALS['pfb']['unbound_py_rawdir']}/old.raw"));
		$this->assertSame($manifest, json_decode((string) file_get_contents($GLOBALS['pfb']['unbound_py_sources']), TRUE));
		$this->assertSame([], glob("{$this->tmp}/pfb_py_raw.stage.*") ?: []);
		$diskBytes = filesize("{$GLOBALS['pfb']['unbound_py_rawdir']}/old.raw")
			+ filesize($this->manifestRaw($manifest)) + filesize($GLOBALS['pfb']['unbound_py_sources']);
		$this->assertSame(9 + 12 + filesize($GLOBALS['pfb']['unbound_py_sources']), $diskBytes);
	}

	public function testExactExistingGenerationIsReusedWithoutStageLeak(): void
	{
		$first = $this->publish();
		$this->assertIsArray($first);
		$firstRaw = $this->manifestRaw($first);
		$inode = fileinode($firstRaw);

		$second = $this->publish();

		$this->assertSame($first['feeds'][0]['raw'], $second['feeds'][0]['raw']);
		$this->assertSame($inode, fileinode($this->manifestRaw($second)));
		$this->assertCount(1, $this->versionDirs());
		$this->assertSame([], glob("{$this->tmp}/pfb_py_raw.stage.*") ?: []);
	}

	public function testCorruptExistingGenerationFailsWithoutChangingOldPublication(): void
	{
		$old = $this->publish();
		$this->assertIsArray($old);
		$oldJson = (string) file_get_contents($GLOBALS['pfb']['unbound_py_sources']);
		$oldRaw = (string) file_get_contents($this->manifestRaw($old));

		$this->writeFeed('two.example');
		$new = $this->publish();
		$this->assertIsArray($new);
		file_put_contents($this->manifestRaw($new), 'corrupt');
		file_put_contents($GLOBALS['pfb']['unbound_py_sources'], $oldJson);

		$this->assertFalse($this->publish());
		$this->assertSame($oldJson, file_get_contents($GLOBALS['pfb']['unbound_py_sources']));
		$this->assertSame($oldRaw, file_get_contents($this->manifestRaw($old)));
		$this->assertSame('corrupt', file_get_contents($this->manifestRaw($new)), 'immutable collision target must not be changed');
		$this->assertSame([], glob("{$this->tmp}/pfb_py_raw.stage.*") ?: []);
	}

	public function testLockAndSourceFailuresLeavePublishedStateUntouched(): void
	{
		$old = $this->publish();
		$this->assertIsArray($old);
		$oldJson = (string) file_get_contents($GLOBALS['pfb']['unbound_py_sources']);
		$oldRaw = (string) file_get_contents($this->manifestRaw($old));

		$originalManifestPath = $GLOBALS['pfb']['unbound_py_sources'];
		file_put_contents("{$this->tmp}/not-a-directory", 'x');
		$GLOBALS['pfb']['unbound_py_sources'] = "{$this->tmp}/not-a-directory/manifest.json";
		$this->assertFalse($this->publish(), 'lock parent regular file must fail closed');
		$GLOBALS['pfb']['unbound_py_sources'] = $originalManifestPath;

		unlink("{$this->tmp}/dnsbl/feed1.txt");
		mkdir("{$this->tmp}/dnsbl/feed1.txt");
		$this->assertFalse($this->publish(), 'source open/read failure must abort the generation');
		$this->assertSame($oldJson, file_get_contents($originalManifestPath));
		$this->assertSame($oldRaw, file_get_contents($this->manifestRaw($old)));
		$this->assertSame([], glob("{$this->tmp}/pfb_py_raw.stage.*") ?: []);
	}

	public function testInjectedPublicationBoundariesPreservePriorGeneration(): void
	{
		$old = $this->publish();
		$this->assertIsArray($old);
		$oldJson = (string) file_get_contents($GLOBALS['pfb']['unbound_py_sources']);
		$oldRaw = (string) file_get_contents($this->manifestRaw($old));
		$oldDirs = $this->versionDirs();
		$this->writeFeed('two.example');

		$this->assertFalse($this->publish([
			'stage_mkdir' => static fn(string $dir, int $mode): bool => FALSE,
		]), 'staging failure must abort');
		$this->assertFalse($this->publish([
			'generation_rename' => static fn(string $from, string $to): bool => FALSE,
		]), 'generation rename failure must abort');
		$this->assertFalse($this->publish([
			'manifest_atomic' => [
				'rename' => static fn(string $from, string $to): bool => FALSE,
			],
		]), 'manifest rename failure must abort publication');

		$this->assertSame($oldJson, file_get_contents($GLOBALS['pfb']['unbound_py_sources']));
		$this->assertSame($oldRaw, file_get_contents($this->manifestRaw($old)));
		$this->assertSame($oldDirs, $this->versionDirs(), 'failed boundaries must not leak raw generations');
		$this->assertSame([], glob("{$this->tmp}/pfb_py_raw.stage.*") ?: []);
	}

	public function testRepeatedEncodeFailuresDoNotAccumulateUnreferencedGenerations(): void
	{
		$old = $this->publish();
		$this->assertIsArray($old);
		$oldJson = (string) file_get_contents($GLOBALS['pfb']['unbound_py_sources']);
		$oldRaw = (string) file_get_contents($this->manifestRaw($old));
		$oldDirs = $this->versionDirs();

		foreach (['two.example', 'three.example'] as $domain) {
			$this->writeFeed($domain);
			$generated = pfb_unbound_python_sources([
				['header' => 'feed1', 'group' => NAN, 'log' => '1', 'provenance' => 'feed'],
			]);
			$this->assertFalse($generated, 'manifest encode failure must abort publication');
			$this->assertSame($oldJson, file_get_contents($GLOBALS['pfb']['unbound_py_sources']));
			$this->assertSame($oldRaw, file_get_contents($this->manifestRaw($old)));
			$this->assertSame($oldDirs, $this->versionDirs(), 'encode failure leaked a raw generation');
		}
	}

	public function testDefaultScalarPatchSucceedsWhenPublicationLockIsUncontended(): void
	{
		$manifest = $this->publish();
		$this->assertIsArray($manifest);

		$this->assertTrue(pfb_unbound_python_sources_patch('user_unlock', ['allow.example']));

		$patched = json_decode((string) file_get_contents($GLOBALS['pfb']['unbound_py_sources']), TRUE);
		$this->assertSame(['allow.example'], $patched['config']['user_unlock']);
	}

	public function testDefaultScalarPatchRetriesUntilPublicationLockIsReleased(): void
	{
		if (!function_exists('pcntl_fork') || !function_exists('posix_kill')) {
			$this->markTestSkipped('pcntl_fork() and posix_kill() required for fork cleanup.');
		}

		$manifest = $this->publish();
		$this->assertIsArray($manifest);
		$rawRefs = array_column($manifest['feeds'], 'raw');
		$holderPid = NULL;
		$patchPid = NULL;
		$holderParent = NULL;
		$patchParent = NULL;
		try {
			[$holderParent, $holderChild] = $this->signalPair();
			stream_set_timeout($holderParent, 5);
			stream_set_timeout($holderChild, 5);
			$holderPid = pcntl_fork();
			if ($holderPid === 0) {
				fclose($holderParent);
				$lock = pfb_unbound_py_publication_lock();
				if (!is_resource($lock)) {
					fwrite($holderChild, "HOLDER_ERROR\n");
					fclose($holderChild);
					exit(1);
				}
				fwrite($holderChild, "LOCKED\n");
				$this->expectChildEvent($holderChild, 'RELEASE', 'scalar patch holder release');
				pfb_unbound_py_publication_unlock($lock);
				fclose($holderChild);
				exit(0);
			}
			$this->assertGreaterThan(0, $holderPid);
			fclose($holderChild);
			$this->assertSame("LOCKED\n", $this->readEvent($holderParent, 'scalar patch holder acquisition'));

			[$patchParent, $patchChild] = $this->signalPair();
			stream_set_timeout($patchParent, 5);
			stream_set_timeout($patchChild, 5);
			$patchPid = pcntl_fork();
			if ($patchPid === 0) {
				fclose($holderParent);
				fclose($patchParent);
				fwrite($patchChild, "ATTEMPT\n");
				$ok = pfb_unbound_python_sources_patch('user_unlock', ['allow.example'], [
					'lock' => function () use ($patchChild) {
						$lockPath = dirname($GLOBALS['pfb']['unbound_py_sources']) . '/pfb_py_sources.lock';
						$probe = @fopen($lockPath, 'c');
						$wouldBlock = 0;
						$contended = $probe !== FALSE
							&& !@flock($probe, LOCK_EX | LOCK_NB, $wouldBlock)
							&& $wouldBlock === 1;
						if (!$contended) {
							fwrite($patchChild, "PROBE_FAILED\n");
							if (is_resource($probe)) {
								fclose($probe);
							}
							return FALSE;
						}
						fwrite($patchChild, "CONTENDED\n");
						fclose($probe);
						return pfb_unbound_py_publication_lock(0.25);
					},
				]);
				fwrite($patchChild, $ok ? "DONE\n" : "FAILED\n");
				fclose($patchChild);
				exit($ok ? 0 : 1);
			}
			$this->assertGreaterThan(0, $patchPid);
			fclose($patchChild);
			$this->assertSame("ATTEMPT\n", $this->readEvent($patchParent, 'scalar patch attempt'));
			$this->assertSame("CONTENDED\n", $this->readEvent($patchParent, 'scalar patch lock contention'));
			fwrite($holderParent, "RELEASE\n");
			$this->assertSame("DONE\n", $this->readEvent($patchParent, 'scalar patch completion'));
			pcntl_waitpid($holderPid, $holderStatus);
			$holderPid = NULL;
			pcntl_waitpid($patchPid, $patchStatus);
			$patchPid = NULL;
			$this->assertTrue(pcntl_wifexited($holderStatus) && pcntl_wexitstatus($holderStatus) === 0);
			$this->assertTrue(pcntl_wifexited($patchStatus) && pcntl_wexitstatus($patchStatus) === 0);
		} finally {
			if (is_resource($holderParent)) {
				@fwrite($holderParent, "RELEASE\n");
				fclose($holderParent);
			}
			if (is_resource($patchParent)) {
				fclose($patchParent);
			}
			foreach ([$holderPid, $patchPid] as $pid) {
				if (is_int($pid) && $pid > 0) {
					if (pcntl_waitpid($pid, $childStatus, WNOHANG) === 0 && function_exists('posix_kill')) {
						posix_kill($pid, SIGKILL);
					}
					pcntl_waitpid($pid, $childStatus);
				}
			}
		}
		$patched = json_decode((string) file_get_contents($GLOBALS['pfb']['unbound_py_sources']), TRUE);
		$this->assertSame($rawRefs, array_column($patched['feeds'], 'raw'));
		$this->assertSame(['allow.example'], $patched['config']['user_unlock']);
	}

	public function testScalarPatchTimesOutWithoutMutatingManifest(): void
	{
		if (!function_exists('pcntl_fork') || !function_exists('posix_kill')) {
			$this->markTestSkipped('pcntl_fork() and posix_kill() required for fork cleanup.');
		}

		$manifest = $this->publish();
		$this->assertIsArray($manifest);

		$this->assertContendedOperationTimesOut(
			static fn(): bool => pfb_unbound_python_sources_patch('user_unlock', ['allow.example'])
		);

		$patched = json_decode((string) file_get_contents($GLOBALS['pfb']['unbound_py_sources']), TRUE);
		$this->assertSame([], $patched['config']['user_unlock']);
		$log = (string) file_get_contents($GLOBALS['pfb']['log']);
		$this->assertStringContainsString('retry the action or run a DNSBL update', $log);
	}

	public function testContendedOperationExceptionIsReportedAndReaped(): void
	{
		$this->publish();
		$this->expectException(RuntimeException::class);
		$this->expectExceptionMessage('OPERATION_ERROR operation exploded with a second line');

		$this->assertContendedOperationTimesOut(static function (): bool {
			throw new RuntimeException("operation exploded\nwith a second line");
		});
	}

	public function testGarbageCollectionTimesOutWithoutRemovingRawGenerations(): void
	{
		$first = $this->publish();
		$this->assertIsArray($first);
		$this->writeFeed('two.example');
		$second = $this->publish();
		$this->assertIsArray($second);
		$stage = "{$this->tmp}/pfb_py_raw.stage.abcdef0123456789abcdef0123456789";
		mkdir($stage);

		$this->assertContendedOperationTimesOut(static fn(): bool => pfb_unbound_py_gc(TRUE));

		$this->assertDirectoryExists(dirname($this->manifestRaw($first)));
		$this->assertDirectoryExists(dirname($this->manifestRaw($second)));
		$this->assertDirectoryExists($stage);
	}

	public function testGarbageCollectionRequiresConvergenceAndProtectsCurrentGeneration(): void
	{
		$first = $this->publish();
		$this->assertIsArray($first);
		$this->writeFeed('two.example');
		$second = $this->publish();
		$this->assertIsArray($second);
		$stage = "{$this->tmp}/pfb_py_raw.stage.abcdef0123456789abcdef0123456789";
		mkdir($stage);

		$this->assertFalse(pfb_unbound_py_gc(FALSE));
		$this->assertDirectoryExists(dirname($this->manifestRaw($first)));
		$this->assertDirectoryExists($stage);

		$GLOBALS['pfb_test_process_running'] = ['unbound' => TRUE];
		file_put_contents("{$this->tmp}/unbound.conf", "python-script: /var/unbound/pfb_unbound.py\n");
		$this->assertTrue(pfb_dnsbl_converged());
		$this->assertTrue(pfb_unbound_py_gc(TRUE));
		$this->assertDirectoryDoesNotExist(dirname($this->manifestRaw($first)));
		$this->assertDirectoryDoesNotExist($stage);
		$this->assertSame("two.example\n", file_get_contents($this->manifestRaw($second)));
	}

	public function testGarbageCollectionAcceptsDuplicateValidRawReferences(): void
	{
		$feeds = [
			['header' => 'feed1', 'group' => 'Group A', 'log' => '1', 'provenance' => 'feed'],
			['header' => 'feed1', 'group' => 'Group B', 'log' => '1', 'provenance' => 'feed'],
		];
		$first = pfb_unbound_python_sources($feeds);
		$this->assertIsArray($first);
		$this->assertCount(2, $first['feeds']);
		$this->assertSame($first['feeds'][0]['raw'], $first['feeds'][1]['raw']);

		$this->writeFeed('two.example');
		$second = pfb_unbound_python_sources($feeds);
		$this->assertIsArray($second);
		$this->assertCount(2, $this->versionDirs());

		$this->assertTrue(pfb_unbound_py_gc(TRUE));
		$this->assertDirectoryDoesNotExist(dirname($this->manifestRaw($first)));
		$this->assertDirectoryExists(dirname($this->manifestRaw($second)));
		$this->assertSame("two.example\n", file_get_contents($this->manifestRaw($second)));
	}

	public function testTeardownRemovesOnlyStrictRawArtifactsAndManifest(): void
	{
		$manifest = $this->publish();
		$this->assertIsArray($manifest);
		mkdir($GLOBALS['pfb']['unbound_py_rawdir']);
		mkdir("{$this->tmp}/pfb_py_raw.stage.abcdef0123456789abcdef0123456789");
		mkdir("{$this->tmp}/pfb_py_raw.neighbor");

		$this->assertTrue(pfb_unbound_py_teardown_raw_set());
		$this->assertFileDoesNotExist($GLOBALS['pfb']['unbound_py_sources']);
		$this->assertDirectoryDoesNotExist(dirname($this->manifestRaw($manifest)));
		$this->assertDirectoryDoesNotExist($GLOBALS['pfb']['unbound_py_rawdir']);
		$this->assertSame([], glob("{$this->tmp}/pfb_py_raw.stage.*") ?: []);
		$this->assertDirectoryExists("{$this->tmp}/pfb_py_raw.neighbor");
	}

	public function testTeardownRemovesOnlyTop1mRuntimeArtifacts(): void
	{
		$base = "{$GLOBALS['pfb']['dbdir']}/top-1m.csv.zip";
		$artifacts = [
			$GLOBALS['pfb']['unbound_py_top1m'],
			"{$base}.orig",
			"{$base}.xxhash128",
			"{$base}.md5",
			"{$base}.source",
			"{$base}.orig.etag",
			"{$base}.orig.lastmod",
			"{$GLOBALS['pfb']['dbdir']}/.pfbtop1m_stage",
			"{$this->tmp}/.pfbtop1m_fixed",
		];
		foreach ($artifacts as $artifact) {
			file_put_contents($artifact, 'owned');
		}
		$decoys = [
			"{$GLOBALS['pfb']['dbdir']}/top-1m.csv.zip.orig.neighbor",
			"{$GLOBALS['pfb']['dbdir']}/pfbtop1m_stage",
			"{$this->tmp}/pfb_py_neighbor.txt",
		];
		foreach ($decoys as $decoy) {
			file_put_contents($decoy, 'keep');
		}

		$this->assertTrue(pfb_unbound_py_teardown_raw_set());
		foreach ($artifacts as $artifact) {
			$this->assertFileDoesNotExist($artifact);
		}
		foreach ($decoys as $decoy) {
			$this->assertSame('keep', file_get_contents($decoy));
		}
	}

	// -----------------------------------------------------------------------
	// issue #1780 F4 (review round) — restore the error-vs-timeout distinction
	// the bounded refactor collapsed: pfb_unbound_py_publication_lock() must
	// still log "timed out" (not "unavailable") on a genuine lock-acquire
	// expiry.
	//
	// This does NOT by itself discriminate the F4 defect: the pre-refactor code
	// already logged "timed out" unconditionally on ANY pfb_flock_bounded()
	// failure (timeout or a real flock() error alike), so a genuine timeout
	// scenario produces the SAME message before and after this fix -- it is a
	// regression guard confirming the restored $timed_out-based branching did
	// not swap the two messages. The genuine discriminating proof (a REAL
	// flock() error, as opposed to a timeout) lives at the shared helper level:
	// PfbFlockBoundedTest::testBoundedAcquireRealErrorReturnsFalsePromptlyWithTimedOutFalse
	// forces an actual (non-would-block) flock() failure via a php://memory
	// stream (portable across platforms, verified). Forcing that SAME kind of
	// failure through this consumer's own fopen() of a real regular file is not
	// portably/deterministically reproducible without new dependency injection
	// this fix does not add (documented as a deviation in the PR handoff).
	// -----------------------------------------------------------------------

	public function testPublicationLockTimeoutLogsTimedOutNotUnavailable(): void
	{
		if (!function_exists('pcntl_fork') || !function_exists('posix_kill')) {
			$this->markTestSkipped('pcntl_fork() and posix_kill() required for fork cleanup.');
		}

		$lockPath   = dirname($GLOBALS['pfb']['unbound_py_sources']) . '/pfb_py_sources.lock';
		$holderParent = NULL;
		$holderChild = NULL;
		$pid = NULL;
		$primaryError = NULL;
		$cleanupError = NULL;
		try {
			[$holderParent, $holderChild] = $this->signalPair();
			stream_set_timeout($holderParent, 5);
			stream_set_timeout($holderChild, 5);
			$pid = pcntl_fork();
			if ($pid === -1) {
				$this->markTestSkipped('pcntl_fork() failed.');
			}
			if ($pid === 0) {
				fclose($holderParent);
				$fp = @fopen($lockPath, 'c');
				if ($fp === FALSE || !@flock($fp, LOCK_EX)) {
					@fwrite($holderChild, "HOLDER_ERROR\n");
					@fclose($holderChild);
					exit(1);
				}
				fwrite($holderChild, "LOCKED\n");
				$this->expectChildEvent($holderChild, 'RELEASE', 'publication timeout holder release');
				@flock($fp, LOCK_UN);
				fclose($fp);
				fwrite($holderChild, "UNLOCKED\n");
				fclose($holderChild);
				exit(0);
			}
			fclose($holderChild);
			$holderChild = NULL;
			$this->assertSame("LOCKED\n", $this->readEvent($holderParent, 'publication timeout holder acquisition'));

			$result = pfb_unbound_py_publication_lock(0.15);

			$this->assertFalse($result, 'a contended publication lock acquire past its own budget must return FALSE');

			$log = (string) file_get_contents($GLOBALS['pfb']['errlog']);
			$this->assertStringContainsString('DNSBL publication lock timed out', $log,
				'a genuine lock-acquire expiry must log "timed out", got errlog=' . var_export($log, TRUE));
			$this->assertStringNotContainsString('DNSBL publication lock unavailable', $log,
				'a genuine expiry must NOT log "unavailable" -- that string is reserved for a real flock() '
				. 'error or an fopen() failure, never a mere timeout');
			fwrite($holderParent, "RELEASE\n");
			$this->assertSame("UNLOCKED\n", $this->readEvent($holderParent, 'publication timeout holder release'));
			fclose($holderParent);
			$holderParent = NULL;
			pcntl_waitpid($pid, $waitStatus);
			$this->assertTrue(pcntl_wifexited($waitStatus) && pcntl_wexitstatus($waitStatus) === 0,
				'publication timeout holder must exit cleanly after the release event');
			$pid = NULL;
		} catch (Throwable $error) {
			$primaryError = $error;
		}
		$this->cleanupPublicationHolder($pid, $holderParent, $cleanupError);
		if (is_resource($holderChild)) {
			@fclose($holderChild);
		}
		if ($primaryError !== NULL) {
			throw $primaryError;
		}
		if ($cleanupError !== NULL) {
			throw $cleanupError;
		}
	}
}
