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
 * Enumeration is the CANONICAL TRACKED SET (`git ls-files 'src/*.php'`), not
 * a directory walk: a walk would also lint an ignored or generated file if
 * one happened to exist on disk in some checkout, and a hardcoded minimum
 * file count is a maintenance trap in the deletion direction (legitimately
 * removing a src/*.php file would turn the guard red for no reason). The
 * non-vacuity guard is instead `assertNotEmpty()` -- an empty list is the
 * only vacuous case, and it can no longer be reached by a legitimate
 * deletion. `git ls-files` itself is asserted to succeed so a missing git
 * binary or a checkout outside a repo cannot silently produce that empty
 * list -- the exact fail-open shape this guard exists to prevent.
 *
 * Scope: src/*.php only. src/*.inc is NOT yet covered by this sweep: the same
 * E_ALL lint extended to src/*.inc finds a separate, pre-existing offender --
 * pfb_unlock() in src/usr/local/pkg/pfblockerng/pfblockerng.inc, declaring an
 * optional parameter ahead of a required one -- tracked in its own issue,
 * #1699, and deliberately out of scope for this test.
 */
final class SrcPhpDeprecationLintTest extends TestCase
{
	public function testEverySrcPhpFileLintsCleanUnderErrorReportingEAll(): void
	{
		$root = dirname(__DIR__, 2);
		$srcDir = $root . '/src';
		$this->assertDirectoryExists($srcDir);

		$files = self::trackedPhpFiles($root);

		$this->assertNotEmpty(
			$files,
			'git ls-files must discover at least one tracked src/*.php file --'
				. ' a broken enumeration must never pass by finding zero.'
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
	 * Enumerate the tracked src/*.php set via `git ls-files -z`, NUL-split so a
	 * tracked path containing a space or a newline can never corrupt the list.
	 * A non-zero exit (git missing, $root not a repo, etc.) throws rather than
	 * silently returning an empty/partial list -- a silent empty list here is
	 * exactly the fail-open shape this guard exists to prevent.
	 *
	 * @return string[] absolute paths of every tracked src/*.php file
	 */
	private static function trackedPhpFiles(string $root): array
	{
		$cmd = ['git', '-C', $root, 'ls-files', '-z', '--', 'src/*.php'];
		$descriptors = [
			0 => ['pipe', 'r'],
			1 => ['pipe', 'w'],
			2 => ['pipe', 'w'],
		];

		$proc = proc_open($cmd, $descriptors, $pipes);
		if (!is_resource($proc)) {
			throw new RuntimeException('test bootstrap: failed to spawn `' . implode(' ', $cmd) . '`');
		}

		fclose($pipes[0]);
		$stdout = (string) stream_get_contents($pipes[1]);
		$stderr = (string) stream_get_contents($pipes[2]);
		fclose($pipes[1]);
		fclose($pipes[2]);
		$exitCode = proc_close($proc);

		if ($exitCode !== 0) {
			throw new RuntimeException(
				'test bootstrap: `' . implode(' ', $cmd) . "` exited {$exitCode}: {$stderr}"
			);
		}

		$relative = array_filter(explode("\0", $stdout), static fn(string $p): bool => $p !== '');
		$absolute = array_map(static fn(string $p): string => $root . '/' . $p, $relative);
		sort($absolute);

		return $absolute;
	}
}
