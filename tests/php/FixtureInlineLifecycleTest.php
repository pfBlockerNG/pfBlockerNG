<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

require_once __DIR__ . '/support/ProcessRunner.php';

/** Local fixture creation must neither adopt stale roots nor outlive its process. */
final class FixtureInlineLifecycleTest extends TestCase
{
	private const ROOT = __DIR__ . '/../..';

	/** @var list<string> observation base directories to sweep, recorded before creation */
	private array $bases = [];

	protected function tearDown(): void
	{
		foreach ($this->bases as $base) {
			rmdir_recursive($base);
		}
		$this->bases = [];
		parent::tearDown();
	}

	private function newObservationBase(): string
	{
		$base = sys_get_temp_dir() . '/pfb_inline_lifecycle_' . getmypid() . '_' . bin2hex(random_bytes(8));
		$this->bases[] = $base;
		if (!mkdir($base, 0700, TRUE)) {
			throw new RuntimeException("observation base directory creation failed: {$base}");
		}
		return (string) realpath($base);
	}

	/** @return array{status:int,stdout:string,stderr:string} */
	private function runChildScript(string $script, string $base): array
	{
		$result = pfb_test_run_process([PHP_BINARY, '-d', 'sys_temp_dir=' . $base, '-r', $script]);
		return ['status' => $result['exit'], 'stdout' => $result['stdout'], 'stderr' => $result['stderr']];
	}

	/** @return array<string, mixed> */
	private function decodeMarkedResult(string $namingSite, array $result, string $marker): array
	{
		$this->assertSame(
			0, $result['status'],
			"{$namingSite}: child process exited nonzero -- stderr: {$result['stderr']}"
		);
		$pos = strrpos($result['stdout'], $marker);
		$this->assertIsInt($pos, "{$namingSite}: child produced no {$marker} payload; stdout: {$result['stdout']}");
		$decoded = json_decode(substr($result['stdout'], $pos + strlen($marker)), TRUE, 512, JSON_THROW_ON_ERROR);
		$this->assertIsArray($decoded, "{$namingSite}: expected a decoded array payload from {$marker}");
		return $decoded;
	}

	/** @param list<string> $extraPreCreateSubpaths @return array<string,mixed> */
	private function runCollisionProbe(
		string $namingSite,
		string $class,
		string $method,
		string $markerSubpath,
		array $extraPreCreateSubpaths
	): array {
		$base = $this->newObservationBase();
		$repoRoot = var_export(realpath(self::ROOT), TRUE);
		$classCode = var_export($class, TRUE);
		$methodCode = var_export($method, TRUE);
		$markerSubpathCode = var_export($markerSubpath, TRUE);
		$extraCode = var_export($extraPreCreateSubpaths, TRUE);
		$prefixCode = var_export('/' . $namingSite, TRUE);
		$script = <<<PHP
\$pid = getmypid();
\$fixtureRoot = sys_get_temp_dir() . {$prefixCode} . \$pid;
if (!mkdir(\$fixtureRoot, 0755, TRUE)) {
	throw new RuntimeException('cannot plant stale fixture root');
}
foreach ({$extraCode} as \$extraSub) {
	if (!mkdir(\$fixtureRoot . \$extraSub, 0755, TRUE)) {
		throw new RuntimeException('cannot plant stale fixture child');
	}
}
\$markerDir = \$fixtureRoot . {$markerSubpathCode};
if (!is_dir(\$markerDir) && !mkdir(\$markerDir, 0755, TRUE)) {
	throw new RuntimeException('cannot plant stale marker directory');
}
\$markerFile = \$markerDir . '/stale-marker.txt';
\$markerContent = 'stale-from-prior-pid-' . \$pid . "\\n";
if (file_put_contents(\$markerFile, \$markerContent) !== strlen(\$markerContent)) {
	throw new RuntimeException('cannot plant stale marker');
}

require {$repoRoot} . '/vendor/autoload.php';
require {$repoRoot} . '/tests/php/bootstrap.php';
require {$repoRoot} . '/tests/php/' . {$classCode} . '.php';

\$class = {$classCode};
\$method = {$methodCode};
\$object = new \$class(\$method);
\$class::setUpBeforeClass();
(new ReflectionMethod(\$class, 'setUp'))->invoke(\$object);

\$events = [];
set_error_handler(static function (int \$severity, string \$message) use (&\$events): bool {
	\$events[] = ['unsuppressed' => (error_reporting() & \$severity) !== 0, 'message' => \$message];
	return TRUE;
});
\$error = NULL;
try {
	\$object->{\$method}();
} catch (Throwable \$e) {
	\$error = get_class(\$e) . ': ' . \$e->getMessage();
}
restore_error_handler();
(new ReflectionMethod(\$class, 'tearDown'))->invoke(\$object);

\$markerStillExists = file_exists(\$markerFile);
\$markerByteIdentical = \$markerStillExists ? (file_get_contents(\$markerFile) === \$markerContent) : FALSE;
echo "\\n__PFB_COLLISION_RESULT__" . json_encode(compact('events', 'error', 'markerFile', 'markerContent', 'markerStillExists', 'markerByteIdentical'));
PHP;
		$result = $this->runChildScript($script, $base);
		$payload = $this->decodeMarkedResult($namingSite, $result, '__PFB_COLLISION_RESULT__');
		$this->assertStringStartsWith($base . '/', $payload['markerFile']);
		$this->assertFileExists($payload['markerFile'], 'fixture shutdown erased a stale root');
		$this->assertSame($payload['markerContent'], file_get_contents($payload['markerFile']));
		return $payload;
	}

	/** @return array<string,mixed> */
	private function runCreationRefusalProbe(string $namingSite, string $class, string $method): array
	{
		$base = $this->newObservationBase();
		$repoRoot = var_export(realpath(self::ROOT), TRUE);
		$classCode = var_export($class, TRUE);
		$methodCode = var_export($method, TRUE);
		$script = <<<PHP
require {$repoRoot} . '/vendor/autoload.php';
require {$repoRoot} . '/tests/php/bootstrap.php';
require {$repoRoot} . '/tests/php/' . {$classCode} . '.php';

\$class = {$classCode};
\$method = {$methodCode};
\$object = new \$class(\$method);
\$class::setUpBeforeClass();
(new ReflectionMethod(\$class, 'setUp'))->invoke(\$object);

\$events = [];
set_error_handler(static function (int \$severity, string \$message) use (&\$events): bool {
	\$events[] = ['unsuppressed' => (error_reporting() & \$severity) !== 0, 'message' => \$message];
	return TRUE;
});

ini_set('open_basedir', {$repoRoot});

\$error = NULL;
try {
	(new ReflectionMethod(\$class, \$method))->invoke(\$object);
} catch (Throwable \$e) {
	\$error = get_class(\$e) . ': ' . \$e->getMessage();
}

echo "\\n__PFB_REFUSAL_RESULT__" . json_encode(compact('events', 'error'));
PHP;
		$result = $this->runChildScript($script, $base);
		// The restriction also blocks bootstrap cleanup; parent teardown owns that residue.
		return $this->decodeMarkedResult($namingSite, $result, '__PFB_REFUSAL_RESULT__');
	}

	/** @return array<string,array{string,string,string,string,list<string>}> */
	public static function inlineFixtureRows(): array
	{
		return [
			'blacklist finalize' => [
				'pfb2764_', 'DownloadExtractionExitCodeTest', 'testBlacklistTarFinalizeTreatsDirectoryOnlyTreeAsEmpty',
				'', ['/feed_cat'],
			],
			'exact prefetch' => [
				'pfb_833_exact_', 'IpPrefetchTest', 'test_single_file_folder_exact_match_resolves_correctly_per_row_and_batched',
				'', [],
			],
			'CIDR prefetch' => [
				'pfb_833_cidr_', 'IpPrefetchTest', 'test_single_file_folder_cidr_only_coverage_resolves_correctly_per_row_and_batched',
				'', [],
			],
			'miss prefetch' => [
				'pfb_831_', 'IpPrefetchTest', 'test_single_file_folder_miss_row_is_correctly_seeded_after_the_833_fix',
				'/cc', [],
			],
			'ET prefetch' => [
				'pfb_832_et_', 'IpPrefetchTest', 'test_et_header_still_listed_ip_is_found_by_the_real_validate_exec',
				'', [],
			],
			'hook scripts' => [
				'pfb_hook_test_', 'PfbHookScriptsTest', 'testEnumerationExcludesSymlinksEscapingTheDirAndIncludesContainedAlias',
				'', [],
			],
		];
	}

	#[DataProvider('inlineFixtureRows')]
	public function testStalePidRootIsNotAdopted(
		string $prefix, string $class, string $method, string $markerSubpath, array $extraPreCreateSubpaths
	): void {
		$payload = $this->runCollisionProbe($prefix, $class, $method, $markerSubpath, $extraPreCreateSubpaths);
		$this->assertSame([], $payload['events'], "{$prefix} emitted fixture warnings: " . json_encode($payload['events']));
		$this->assertNull($payload['error'], "{$prefix} public test failed: " . ($payload['error'] ?? ''));
		$this->assertTrue($payload['markerStillExists'], "{$prefix} erased the stale marker");
		$this->assertTrue($payload['markerByteIdentical'], "{$prefix} changed the stale marker");
	}

	#[DataProvider('inlineFixtureRows')]
	public function testCreationStopsAtFirstUnsuppressedMkdirFailure(
		string $prefix, string $class, string $method, string $markerSubpath, array $extraPreCreateSubpaths
	): void {
		$payload = $this->runCreationRefusalProbe($prefix, $class, $method);
		$this->assertCount(1, $payload['events'], "{$prefix} continued after failed creation: " . json_encode($payload['events']));
		$this->assertStringStartsWith('mkdir():', $payload['events'][0]['message']);
		$this->assertTrue($payload['events'][0]['unsuppressed'], "{$prefix} suppressed directory creation failure");
		$this->assertNotNull($payload['error'], "{$prefix} ignored failed directory creation");
	}

	public function testHookBuilderAllocationsAreIsolatedAndRemovedAtExit(): void
	{
		$base = $this->newObservationBase();
		$repoRoot = var_export(realpath(self::ROOT), TRUE);
		$script = <<<PHP
require {$repoRoot} . '/vendor/autoload.php';
require {$repoRoot} . '/tests/php/bootstrap.php';
require {$repoRoot} . '/tests/php/PfbHookScriptsTest.php';

\$make = new ReflectionMethod('PfbHookScriptsTest', 'makeSymlinkFixture');
\$first = \$make->invoke(NULL);
\$second = \$make->invoke(NULL);

\$inspect = static function (array \$fixture): array {
	\$dir = \$fixture['dir'];
	\$realDir = realpath(\$dir);
	\$realFile = realpath(\$dir . '/hook_pre_real.sh');
	\$aliasReal = realpath(\$dir . '/hook_pre_alias.sh');
	\$escapeReal = realpath(\$dir . '/hook_pre_escape.sh');
	\$todirReal = realpath(\$dir . '/hook_pre_todir.sh');
	return [
		'directoryExists' => is_dir(\$dir),
		'realFileIsPlainFile' => is_file(\$dir . '/hook_pre_real.sh') && !is_link(\$dir . '/hook_pre_real.sh'),
		'aliasIsLink' => is_link(\$dir . '/hook_pre_alias.sh'),
		'aliasResolvesInsideToRealFile' => (\$aliasReal !== FALSE && \$aliasReal === \$realFile),
		'escapeIsLink' => is_link(\$dir . '/hook_pre_escape.sh'),
		'escapeResolvesOutsideDir' => (\$escapeReal !== FALSE && \$realDir !== FALSE
			&& strncmp(\$escapeReal, \$realDir, strlen(\$realDir)) !== 0),
		'todirIsLinkToSameDir' => (is_link(\$dir . '/hook_pre_todir.sh') && is_dir(\$dir . '/hook_pre_todir.sh')
			&& \$todirReal !== FALSE && \$todirReal === \$realDir),
		'dangleIsLink' => is_link(\$dir . '/hook_pre_dangle.sh'),
		'dangleUnresolvable' => (realpath(\$dir . '/hook_pre_dangle.sh') === FALSE),
		'outsideIsExecutableFile' => (is_file(\$fixture['outside']) && is_executable(\$fixture['outside'])),
	];
};

\$firstInspection = \$inspect(\$first);
\$secondInspection = \$inspect(\$second);

echo "\\n__PFB_HOOK_RESULT__" . json_encode(compact('first', 'second', 'firstInspection', 'secondInspection'));
// No explicit fixture cleanup: the owning process must remove both allocations.
PHP;
		$result = $this->runChildScript($script, $base);
		$payload = $this->decodeMarkedResult('pfb_hook_test_ builder', $result, '__PFB_HOOK_RESULT__');
		$first = $payload['first'];
		$second = $payload['second'];

		$this->assertNotSame(
			$first['dir'], $second['dir'],
			'two hook fixture allocations shared the same directory'
		);

		foreach (['first' => $payload['firstInspection'], 'second' => $payload['secondInspection']] as $label => $inspection) {
			$this->assertTrue($inspection['directoryExists'], "{$label} hook directory was never created");
			$this->assertTrue($inspection['realFileIsPlainFile'], "pfb_hook_test_ {$label}: hook_pre_real.sh must be a plain file");
			$this->assertTrue($inspection['aliasIsLink'], "pfb_hook_test_ {$label}: hook_pre_alias.sh must be a symlink");
			$this->assertTrue(
				$inspection['aliasResolvesInsideToRealFile'],
				"pfb_hook_test_ {$label}: the contained alias must resolve to the real file inside the dir"
			);
			$this->assertTrue($inspection['escapeIsLink'], "pfb_hook_test_ {$label}: hook_pre_escape.sh must be a symlink");
			$this->assertTrue(
				$inspection['escapeResolvesOutsideDir'],
				"pfb_hook_test_ {$label}: the escaping symlink must resolve outside the dir"
			);
			$this->assertTrue(
				$inspection['todirIsLinkToSameDir'],
				"pfb_hook_test_ {$label}: hook_pre_todir.sh must be a self-referential symlink to the dir"
			);
			$this->assertTrue($inspection['dangleIsLink'], "pfb_hook_test_ {$label}: hook_pre_dangle.sh must be a symlink");
			$this->assertTrue($inspection['dangleUnresolvable'], "pfb_hook_test_ {$label}: the dangling symlink must not resolve");
			$this->assertTrue(
				$inspection['outsideIsExecutableFile'],
				"pfb_hook_test_ {$label}: the outside script must exist and remain executable"
			);
		}

		foreach ([$first, $second] as $fixture) {
			$this->assertStringStartsWith($base . '/', $fixture['dir']);
			$this->assertStringStartsWith($base . '/', $fixture['outside']);
			$this->assertDirectoryDoesNotExist($fixture['dir'], 'hook directory survived process exit');
			$this->assertFileDoesNotExist($fixture['outside'], 'outside hook script survived process exit');
		}
	}
}
