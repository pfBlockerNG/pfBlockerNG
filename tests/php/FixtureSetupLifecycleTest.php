<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/** Fixture allocations stay isolated across setup calls and expire with their owning process. */
final class FixtureSetupLifecycleTest extends TestCase
{
	private const ROOT = __DIR__ . '/../..';

	/** @var list<string> parent-owned observation roots to sweep in tearDown() */
	private array $observationRoots = [];

	protected function tearDown(): void
	{
		foreach ($this->observationRoots as $root) {
			// The GeoIP fixture can leave a read-only share behind on failure.
			exec('/bin/chmod -R u+rwx ' . escapeshellarg($root) . ' 2>/dev/null');
			rmdir_recursive($root);
		}
		$this->observationRoots = [];
		parent::tearDown();
	}

	/** @return array<string,array{0:string,1:string,2:list<string>,3:bool}> */
	public static function setupFixtureRows(): array
	{
		return [
			'DownloadGeoipStagePublishTest' => [
				'DownloadGeoipStagePublishTest', 'testTheExtractionFlagGateTracksWhetherTheHostTarIsLibarchive',
				['dir'], FALSE,
			],
			'DownloadStagePublishTest' => [
				'DownloadStagePublishTest', 'testSuccessfulExtractionPublishesTheStagedContent',
				['dir'], FALSE,
			],
			'DownloadStagePublishDirTest' => [
				'DownloadStagePublishDirTest', 'testSuccessfulExtractionPublishesTheStagedDirectory',
				['dir'], FALSE,
			],
			'GeoipOrigTrailingNewlineWiringTest' => [
				'GeoipOrigTrailingNewlineWiringTest', 'testPublicationPipelineOrdersMirrorBeforeConsumer',
				['dir'], TRUE,
			],
			'GeoipPackageGenerationTest' => [
				'GeoipPackageGenerationTest', 'testPackageUmbrellaGeneratesContinentAndReputationPagesAcrossStateTransitions',
				['tmp'], FALSE,
			],
			'GunzipTrailingNewlineWiringTest' => [
				'GunzipTrailingNewlineWiringTest', 'testGunzipPipelineTerminatesBeforeEtConsumer',
				['dir'], TRUE,
			],
			'PfbResolveListScriptTest' => [
				'PfbResolveListScriptTest', 'testContainedFileResolvesToPrimaryDir',
				['dir1', 'dir2'], FALSE,
			],
			'PrivPageMatchesTest' => [
				'PrivPageMatchesTest', 'testNoDuplicateMatchEntries',
				['wwwRoot'], FALSE,
			],
		];
	}

	/** @return string a fresh parent-owned directory the child's sys_temp_dir points at */
	private function newObservationRoot(string $label): string
	{
		$root = sys_get_temp_dir() . '/pfb_fixture_setup_obs_' . $label . '_' . getmypid() . '_' . bin2hex(random_bytes(8));
		if (!mkdir($root, 0700, TRUE)) {
			throw new RuntimeException("observation root creation failed: {$root}");
		}
		$this->observationRoots[] = $root;
		return (string) realpath($root);
	}

	/** @return array<string,mixed> */
	private function runChild(string $observationRoot, string $script): array
	{
		$descriptors = [1 => ['pipe', 'w'], 2 => ['pipe', 'w']];
		$process = proc_open(
			[PHP_BINARY, '-d', "sys_temp_dir={$observationRoot}", '-r', $script],
			$descriptors,
			$pipes
		);
		$this->assertIsResource($process);
		$stdout = (string) stream_get_contents($pipes[1]);
		$stderr = (string) stream_get_contents($pipes[2]);
		fclose($pipes[1]);
		fclose($pipes[2]);
		$status = proc_close($process);
		$this->assertSame(0, $status, "child process exited {$status}, stderr: {$stderr}");
		$decoded = json_decode(trim($stdout), TRUE);
		$this->assertIsArray($decoded, "child stdout was not JSON: {$stdout}\nstderr: {$stderr}");
		return $decoded;
	}

	private function beforeClassLine(string $class, bool $needsSetUpBeforeClass): string
	{
		return $needsSetUpBeforeClass ? "{$class}::setUpBeforeClass();" : '';
	}

	/** Observe marker contents before process shutdown removes the allocations. */
	private function buildRepeatScript(string $class, string $ctorMethod, array $props, bool $needsSetUpBeforeClass): string
	{
		$root = var_export(realpath(self::ROOT), TRUE);
		$ctorLit = var_export($ctorMethod, TRUE);
		$propsLit = var_export($props, TRUE);
		$before = $this->beforeClassLine($class, $needsSetUpBeforeClass);

		return <<<PHP
require {$root} . '/vendor/autoload.php';
require {$root} . '/tests/php/bootstrap.php';
require {$root} . '/tests/php/{$class}.php';
{$before}
\$warnings = [];
set_error_handler(static function (int \$severity, string \$message) use (&\$warnings): bool {
	\$warnings[] = \$message;
	return TRUE;
});
\$props = {$propsLit};
\$object = new {$class}({$ctorLit});
\$setup = new ReflectionMethod({$class}::class, 'setUp');
\$setup->invoke(\$object);
\$first = [];
\$markers = [];
\$firstExists = [];
foreach (\$props as \$p) {
	\$path = (new ReflectionProperty({$class}::class, \$p))->getValue(\$object);
	\$first[\$p] = \$path;
	\$firstExists[\$p] = is_dir(\$path);
	\$marker = \$path . '/pfb_setup_repeat_marker';
	file_put_contents(\$marker, 'first-allocation:' . \$p);
	\$markers[\$p] = \$marker;
}
\$secondThrew = FALSE;
\$secondThrowClass = NULL;
try {
	\$setup->invoke(\$object);
} catch (Throwable \$e) {
	\$secondThrew = TRUE;
	\$secondThrowClass = get_class(\$e);
}
\$second = [];
\$secondExists = [];
\$markerContents = [];
foreach (\$props as \$p) {
	\$second[\$p] = (new ReflectionProperty({$class}::class, \$p))->getValue(\$object);
	\$secondExists[\$p] = is_dir(\$second[\$p]);
	\$markerContents[\$p] = file_get_contents(\$markers[\$p]);
}
echo json_encode(compact('first', 'second', 'firstExists', 'secondExists', 'markerContents', 'secondThrew', 'secondThrowClass', 'warnings'));
PHP;
	}

	#[DataProvider('setupFixtureRows')]
	public function testRepeatedSetupOnTheSameObjectProducesDisjointAllocations(
		string $class, string $ctorMethod, array $props, bool $needsSetUpBeforeClass
	): void {
		$root = $this->newObservationRoot('repeat_' . $class);
		$result = $this->runChild($root, $this->buildRepeatScript($class, $ctorMethod, $props, $needsSetUpBeforeClass));

		foreach ($props as $p) {
			$this->assertArrayHasKey($p, $result['first'], "{$class}::\${$p} missing from the first allocation's report");
			$this->assertArrayHasKey($p, $result['second'], "{$class}::\${$p} missing from the second allocation's report");
			$this->assertStringStartsWith("{$root}/", $result['first'][$p],
				"{$class}::\${$p} was allocated outside the observed root -- the window this test watches saw nothing");
			$this->assertStringStartsWith("{$root}/", $result['second'][$p],
				"{$class} second allocation escaped the observed root");

			$this->assertTrue($result['firstExists'][$p], "{$class} first fixture was never created");
			$this->assertTrue($result['secondExists'][$p], "{$class} second fixture was never created");
			$this->assertNotSame(
				$result['first'][$p], $result['second'][$p],
				"{$class}::\${$p} reused the first allocation's path"
			);
		}

		$this->assertFalse($result['secondThrew'], "{$class} repeated setup failed");
		$this->assertSame([], $result['warnings'], "{$class} repeated setup emitted warnings");
		foreach ($props as $p) {
			$this->assertSame('first-allocation:' . $p, $result['markerContents'][$p],
				"{$class} second setup changed the first allocation");
			$this->assertDirectoryDoesNotExist($result['first'][$p], "{$class} first allocation survived shutdown");
			$this->assertDirectoryDoesNotExist($result['second'][$p], "{$class} second allocation survived shutdown");
		}
	}

	/** One allocation isolates exit cleanup from a repeated-setup collision. */
	private function buildExitScript(string $class, string $ctorMethod, array $props, bool $needsSetUpBeforeClass): string
	{
		$root = var_export(realpath(self::ROOT), TRUE);
		$ctorLit = var_export($ctorMethod, TRUE);
		$propsLit = var_export($props, TRUE);
		$before = $this->beforeClassLine($class, $needsSetUpBeforeClass);

		return <<<PHP
require {$root} . '/vendor/autoload.php';
require {$root} . '/tests/php/bootstrap.php';
require {$root} . '/tests/php/{$class}.php';
{$before}
set_error_handler(static function (int \$severity, string \$message): bool { return TRUE; });
\$props = {$propsLit};
\$object = new {$class}({$ctorLit});
(new ReflectionMethod({$class}::class, 'setUp'))->invoke(\$object);
\$paths = [];
\$exists = [];
foreach (\$props as \$p) {
	\$paths[\$p] = (new ReflectionProperty({$class}::class, \$p))->getValue(\$object);
	\$exists[\$p] = is_dir(\$paths[\$p]);
}
echo json_encode(compact('paths', 'exists'));
PHP;
	}

	#[DataProvider('setupFixtureRows')]
	public function testProcessEndingAfterSetupWithoutTeardownLeavesNoResidue(
		string $class, string $ctorMethod, array $props, bool $needsSetUpBeforeClass
	): void {
		$root = $this->newObservationRoot('exit_' . $class);
		$result = $this->runChild($root, $this->buildExitScript($class, $ctorMethod, $props, $needsSetUpBeforeClass));

		foreach ($props as $p) {
			$path = $result['paths'][$p];
			$this->assertTrue($result['exists'][$p], "{$class} fixture was never created");
			$this->assertStringStartsWith("{$root}/", $path,
				"{$class}::\${$p} was allocated outside the observed root -- the window this test watches saw nothing");
			$this->assertDirectoryDoesNotExist($path,
				"{$class}::\${$p} ({$path}) survived process exit without tearDown() running -- " .
				'no shutdown fallback removed it');
		}
	}

	/** Exercise the read-only share shape used by the GeoIP permission fixture. */
	private function buildGeoipReadOnlyShareExitScript(string $ctorMethod): string
	{
		$class = 'DownloadGeoipStagePublishTest';
		$root = var_export(realpath(self::ROOT), TRUE);
		$ctorLit = var_export($ctorMethod, TRUE);

		return <<<PHP
require {$root} . '/vendor/autoload.php';
require {$root} . '/tests/php/bootstrap.php';
require {$root} . '/tests/php/{$class}.php';
set_error_handler(static function (int \$severity, string \$message): bool { return TRUE; });
\$object = new {$class}({$ctorLit});
\$object->assertTrue(TRUE);
\$result = pfb_test_as_unprivileged(static function () use (\$object): array {
(new ReflectionMethod({$class}::class, 'setUp'))->invoke(\$object);
\$dir = (new ReflectionProperty({$class}::class, 'dir'))->getValue(\$object);
\$share = (new ReflectionProperty({$class}::class, 'share'))->getValue(\$object);
file_put_contents(\$share . '/leftover.txt', 'stale-share-content');
chmod(\$share, 0555);
\$exists = is_dir(\$dir) && file_get_contents(\$share . '/leftover.txt') === 'stale-share-content';
	return compact('dir', 'share', 'exists');
});
echo json_encode(\$result);
PHP;
	}

	public function testProcessExitRemovesAReadOnlyGeoipShareWithoutTeardown(): void
	{
		$root = $this->newObservationRoot('exit_readonly_share_DownloadGeoipStagePublishTest');
		$result = $this->runChild(
			$root,
			$this->buildGeoipReadOnlyShareExitScript('testTheExtractionFlagGateTracksWhetherTheHostTarIsLibarchive')
		);

		$this->assertTrue($result['exists'], 'the read-only fixture was never populated');
		$this->assertStringStartsWith("{$root}/", $result['dir'],
			'DownloadGeoipStagePublishTest::$dir was allocated outside the observed root');
		$this->assertStringStartsWith($result['dir'] . '/', $result['share'],
			'DownloadGeoipStagePublishTest::$share must sit inside $dir for this test to watch it');
		$this->assertDirectoryDoesNotExist($result['dir'], 'the read-only GeoIP fixture survived shutdown');
	}

	/**
	 * Restrict writes after loading the real fixture; mkdir fails without injected exceptions.
	 * The parent reaps the bootstrap sandbox too, since the restriction blocks its cleanup.
	 */
	private function buildCreationRefusalScript(string $class, string $ctorMethod, bool $needsSetUpBeforeClass): string
	{
		$root = var_export(realpath(self::ROOT), TRUE);
		$ctorLit = var_export($ctorMethod, TRUE);
		$before = $this->beforeClassLine($class, $needsSetUpBeforeClass);

		return <<<PHP
require {$root} . '/vendor/autoload.php';
require {$root} . '/tests/php/bootstrap.php';
require {$root} . '/tests/php/{$class}.php';
{$before}
\$object = new {$class}({$ctorLit});
\$events = [];
set_error_handler(static function (int \$severity, string \$message) use (&\$events): bool {
	\$events[] = ['unsuppressed' => (error_reporting() & \$severity) !== 0, 'message' => \$message];
	return TRUE;
});
ini_set('open_basedir', {$root});
try {
	(new ReflectionMethod({$class}::class, 'setUp'))->invoke(\$object);
	\$error = NULL;
} catch (Throwable \$e) {
	\$error = get_class(\$e) . ': ' . \$e->getMessage();
}
echo json_encode(compact('events', 'error'));
PHP;
	}

	#[DataProvider('setupFixtureRows')]
	public function testSetupStopsAtTheFirstMkdirFailureUnderARestrictedFilesystem(
		string $class, string $ctorMethod, array $props, bool $needsSetUpBeforeClass
	): void {
		$root = $this->newObservationRoot('creation_refusal_' . $class);
		$result = $this->runChild($root, $this->buildCreationRefusalScript($class, $ctorMethod, $needsSetUpBeforeClass));

		$this->assertCount(1, $result['events'], "{$class} continued after failed directory creation");
		$this->assertStringStartsWith('mkdir():', $result['events'][0]['message']);

		$this->assertTrue($result['events'][0]['unsuppressed'],
			"{$class} suppressed the mkdir failure's severity bit");

		$this->assertNotNull($result['error'],
			"{$class}::setUp() returned normally after its first mkdir() failed instead of raising or propagating " .
			'an error that stops construction before any later write');
	}
}
