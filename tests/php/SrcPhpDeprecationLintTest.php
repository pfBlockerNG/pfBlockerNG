<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;

/**
 * Issue #1657 pinned url_compare() in pfblockerng_feeds.php after it declared
 * four optional parameters BEFORE the required $a_key, which PHP 8 deprecates
 * (one Deprecated notice per optional parameter ahead of the required one).
 * Its guard (formerly FeedsUrlCompareDeprecationTest) covered that one file
 * only, because a tree-wide `php -d error_reporting=E_ALL -l` sweep run for
 * that issue found a SECOND, then-unfixed offender in the same defect class:
 * pfBlockerNG_get_table() in src/usr/local/www/widgets/widgets/
 * pfblockerng.widget.php ("Optional parameter $mode declared before required
 * parameter $pfb_table"). Issue #1693 fixed that widget and widens the guard
 * here to every tracked src/*.php file, so this whole defect class -- not
 * just one file at a time -- stays pinned tree-wide.
 *
 * Scope: src/*.php only. src/*.inc is NOT yet covered by this sweep: the same
 * E_ALL lint extended to src/*.inc finds a separate, pre-existing offender --
 * pfb_unlock() in src/usr/local/pkg/pfblockerng/pfblockerng.inc, declaring an
 * optional parameter ahead of a required one -- tracked in its own issue,
 * #1699, and deliberately out of scope for this test.
 */
final class SrcPhpDeprecationLintTest extends TestCase
{
	private const MIN_EXPECTED_FILE_COUNT = 21;

	public function testEverySrcPhpFileLintsCleanUnderErrorReportingEAll(): void
	{
		$root = dirname(__DIR__, 2);
		$srcDir = $root . '/src';
		$this->assertDirectoryExists($srcDir);

		$files = self::findPhpFiles($srcDir);
		sort($files);

		$this->assertGreaterThanOrEqual(
			self::MIN_EXPECTED_FILE_COUNT,
			count($files),
			'Directory walk under src/ must discover at least ' . self::MIN_EXPECTED_FILE_COUNT
				. ' tracked *.php files -- a broken walk must never pass by finding zero.'
				. ' Found ' . count($files) . ":\n" . implode("\n", $files)
		);

		$failures = [];

		foreach ($files as $path) {
			$cmd = escapeshellarg(PHP_BINARY)
				. ' -d error_reporting=E_ALL -l '
				. escapeshellarg($path)
				. ' 2>&1';

			$output = (string) shell_exec($cmd);

			$parses = strpos($output, 'No syntax errors detected') !== false;
			$hasDiagnostic = preg_match('/\b(Deprecated|Warning|Notice)\b/', $output) === 1;

			if (!$parses || $hasDiagnostic) {
				$relative = substr($path, strlen($root) + 1);
				$failures[] = "{$relative}:\n{$output}";
			}
		}

		$this->assertSame(
			[],
			$failures,
			'php -l -d error_reporting=E_ALL must confirm parse and emit no'
				. ' Deprecated/Warning/Notice diagnostics for every tracked src/*.php file;'
				. ' offending file(s):' . "\n" . implode("\n---\n", $failures)
		);
	}

	/**
	 * @return string[] absolute paths of every *.php file found under $dir
	 */
	private static function findPhpFiles(string $dir): array
	{
		$found = [];
		$iterator = new RecursiveIteratorIterator(
			new RecursiveDirectoryIterator($dir, FilesystemIterator::SKIP_DOTS)
		);

		foreach ($iterator as $file) {
			if ($file->isFile() && substr($file->getFilename(), -4) === '.php') {
				$found[] = $file->getPathname();
			}
		}

		return $found;
	}
}
