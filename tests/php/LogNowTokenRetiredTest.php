<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;

/**
 * issue #1008 retired pfb_logger()'s '[ NOW ]' opt-in scrub (LogTimestampBaselineTest
 * pins the writer side); issue #1047 found 9 pfblockerng.php call sites still carrying
 * the literal ' [ NOW ]' token, so it printed verbatim (no substitution left to hide
 * it). PHP-code tripwire: no shipped PHP/INC executable token may contain the literal.
 */
final class LogNowTokenRetiredTest extends TestCase
{
	private const NOW_TOKEN = ' [ NOW ]';

	public function testNoTrackedSrcFileContainsLiteralNowToken(): void
	{
		$repoRoot = dirname(__DIR__, 2);

		$proc = proc_open(
			['git', '-C', $repoRoot, 'ls-files', '-z', '--', 'src/*.php', 'src/*.inc'],
			[1 => ['pipe', 'w'], 2 => ['pipe', 'w']],
			$pipes
		);
		$this->assertIsResource($proc, 'git ls-files must start to enumerate tracked src/ files');
		$stdout = (string) stream_get_contents($pipes[1]);
		$stderr = (string) stream_get_contents($pipes[2]);
		fclose($pipes[1]);
		fclose($pipes[2]);
		$exit = proc_close($proc);
		$this->assertSame(0, $exit, "git ls-files must succeed to enumerate tracked src/ files; got: {$stderr}");
		$files = array_filter(explode("\0", $stdout), static fn(string $path): bool => $path !== '');

		$violations = [];
		foreach ($files as $relpath) {
			$path = "{$repoRoot}/{$relpath}";
			if (!is_file($path)) {
				continue;
			}
			// PRODUCTION COMMENTS AND DOCBLOCKS MUST NEVER BE LOAD-BEARING FOR A TEST.
			$lines = explode("\n", php_strip_whitespace($path));
			foreach ($lines as $i => $line) {
				if (!str_contains($line, self::NOW_TOKEN)) {
					continue;
				}
				$violations[] = "{$relpath}:" . ($i + 1);
			}
		}

		$this->assertSame(
			[],
			$violations,
			"the literal '" . self::NOW_TOKEN . "' token must be deleted from every tracked src/ file "
			. "(pfb_logger() no longer substitutes it -- it would print verbatim); found: " . implode(', ', $violations)
		);
	}
}
