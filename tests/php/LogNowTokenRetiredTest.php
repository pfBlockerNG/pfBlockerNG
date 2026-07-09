<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;

/**
 * issue #1008 retired pfb_logger()'s '[ NOW ]' opt-in scrub (LogTimestampBaselineTest
 * pins the writer side); issue #1047 found 9 pfblockerng.php call sites still carrying
 * the literal ' [ NOW ]' token, so it printed verbatim (no substitution left to hide
 * it). Tree-wide tripwire: no tracked src/ file may contain the literal token outside
 * a documented comment-only mention (ALLOWLIST below).
 */
final class LogNowTokenRetiredTest extends TestCase
{
	private const NOW_TOKEN = ' [ NOW ]';

	/**
	 * file:line -> reason, for a genuine comment-only historical mention.
	 * Empty: every current tracked src/ file is clean.
	 *
	 * @var array<string,string>
	 */
	private const ALLOWLIST = [];

	public function testNoTrackedSrcFileContainsLiteralNowToken(): void
	{
		$repoRoot = dirname(__DIR__, 2);

		exec('git -C ' . escapeshellarg($repoRoot) . ' ls-files -- src 2>&1', $files, $exit);
		$this->assertSame(0, $exit, 'git ls-files must succeed to enumerate tracked src/ files; got: ' . implode("\n", $files));

		$violations = [];
		foreach ($files as $relpath) {
			$path = "{$repoRoot}/{$relpath}";
			if (!is_file($path)) {
				continue;
			}
			$lines = explode("\n", (string) file_get_contents($path));
			foreach ($lines as $i => $line) {
				if (!str_contains($line, self::NOW_TOKEN)) {
					continue;
				}
				$key = "{$relpath}:" . ($i + 1);
				if (!array_key_exists($key, self::ALLOWLIST)) {
					$violations[] = $key;
				}
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
