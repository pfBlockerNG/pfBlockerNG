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
			'dbdir'              => "{$this->tmp}/db",
			'dnsbl_top1m'        => 'off',
			'dnsbl_tld_data'     => "{$this->tmp}/does_not_exist",
			'dnsbl_unlock'       => "{$this->tmp}/dnsbl_unlock",
			'dnsbl_tld_wildcard' => '',
			'dnsblconfig'        => ['tldblacklist' => '', 'tldexclusion' => '', 'suppression' => ''],
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

	private function assertContendedOperationTimesOut(callable $operation): void
	{
		$manifestBefore = (string) file_get_contents($GLOBALS['pfb']['unbound_py_sources']);
		$holderPid = NULL;
		$operationPid = NULL;
		$holderParent = NULL;
		$operationParent = NULL;
		try {
			[$holderParent, $holderChild] = stream_socket_pair(STREAM_PF_UNIX, STREAM_SOCK_STREAM, 0);
			stream_set_timeout($holderParent, 5);
			stream_set_timeout($holderChild, 5);
			$holderPid = pcntl_fork();
			if ($holderPid === 0) {
				fclose($holderParent);
				$lock = pfb_unbound_py_publication_lock();
				fwrite($holderChild, "LOCKED\n");
				fgets($holderChild);
				pfb_unbound_py_publication_unlock($lock);
				fclose($holderChild);
				exit(0);
			}
			$this->assertGreaterThan(0, $holderPid);
			fclose($holderChild);
			$this->assertSame("LOCKED\n", fgets($holderParent));

			[$operationParent, $operationChild] = stream_socket_pair(STREAM_PF_UNIX, STREAM_SOCK_STREAM, 0);
			stream_set_timeout($operationParent, 5);
			stream_set_timeout($operationChild, 5);
			$operationPid = pcntl_fork();
			if ($operationPid === 0) {
				fclose($operationParent);
				$started = microtime(TRUE);
				$ok = $operation();
				fwrite($operationChild, json_encode([
					'ok' => $ok,
					'elapsed' => microtime(TRUE) - $started,
				]) . "\n");
				fclose($operationChild);
				exit(0);
			}
			$this->assertGreaterThan(0, $operationPid);
			fclose($operationChild);

			$read = [$operationParent];
			$write = NULL;
			$except = NULL;
			$this->assertSame(1, stream_select($read, $write, $except, 1),
				'contended interactive operation exceeded its bounded lock wait');
			$result = json_decode((string) fgets($operationParent), TRUE);
			$this->assertIsArray($result);
			$this->assertFalse($result['ok'], 'contended interactive operation must skip mutation');
			$this->assertLessThan(1.0, $result['elapsed'], 'contended lock wait exceeded its deadline margin');
			$this->assertSame($manifestBefore, file_get_contents($GLOBALS['pfb']['unbound_py_sources']),
				'lock timeout must not mutate the published manifest');
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
		$manifest = $this->publish();
		$this->assertIsArray($manifest);
		$rawRefs = array_column($manifest['feeds'], 'raw');
		$holderPid = NULL;
		$patchPid = NULL;
		$holderParent = NULL;
		$patchParent = NULL;
		try {
			[$holderParent, $holderChild] = stream_socket_pair(STREAM_PF_UNIX, STREAM_SOCK_STREAM, 0);
			stream_set_timeout($holderParent, 5);
			stream_set_timeout($holderChild, 5);
			$holderPid = pcntl_fork();
			if ($holderPid === 0) {
				fclose($holderParent);
				$lock = pfb_unbound_py_publication_lock();
				fwrite($holderChild, "LOCKED\n");
				fgets($holderChild);
				pfb_unbound_py_publication_unlock($lock);
				fclose($holderChild);
				exit(0);
			}
			$this->assertGreaterThan(0, $holderPid);
			fclose($holderChild);
			$this->assertSame("LOCKED\n", fgets($holderParent));

			[$patchParent, $patchChild] = stream_socket_pair(STREAM_PF_UNIX, STREAM_SOCK_STREAM, 0);
			stream_set_timeout($patchParent, 5);
			stream_set_timeout($patchChild, 5);
			$patchPid = pcntl_fork();
			if ($patchPid === 0) {
				fclose($patchParent);
				fwrite($patchChild, "ATTEMPT\n");
				$ok = pfb_unbound_python_sources_patch('user_unlock', ['allow.example']);
				fwrite($patchChild, $ok ? "DONE\n" : "FAILED\n");
				fclose($patchChild);
				exit($ok ? 0 : 1);
			}
			$this->assertGreaterThan(0, $patchPid);
			fclose($patchChild);
			$this->assertSame("ATTEMPT\n", fgets($patchParent));
			$read = [$patchParent];
			$write = NULL;
			$except = NULL;
			$this->assertSame(0, stream_select($read, $write, $except, 0, 200000),
				'patch completed before the publication lock was released');
			fwrite($holderParent, "RELEASE\n");
			$this->assertSame("DONE\n", fgets($patchParent));
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
}
