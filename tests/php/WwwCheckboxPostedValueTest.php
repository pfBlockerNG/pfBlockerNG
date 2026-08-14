<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;

/**
 * Every checkbox this package renders must say what it POSTS (issue #2367).
 *
 * pfSense's Form_Checkbox defaults its value argument to 'yes'
 * (``__construct($name, $title, $description, $checked, $value = 'yes')``), while this
 * package's save paths validate with PFB_FILTER_ON_OFF, which accepts only 'on' and ''.
 * A checkbox built without the argument therefore renders and saves without error, and
 * silently persists the DISABLED token every time — including when it is ticked, leaving no
 * UI path back. The Software page shipped that way for a release.
 *
 * The page-specific round-trip lives in SoftwareCheckPostRoundTripTest; this is the class
 * guard, so the next page to omit the argument fails here rather than after a user cannot
 * re-enable a setting.
 */
final class WwwCheckboxPostedValueTest extends TestCase
{
	private const WWW = __DIR__ . '/../../src/usr/local/www';

	/** @return list<string> every shipped PHP file under src/usr/local/www. */
	private function pages(): array
	{
		$found = [];
		$it = new RecursiveIteratorIterator(new RecursiveDirectoryIterator(self::WWW, FilesystemIterator::SKIP_DOTS));
		foreach ($it as $file) {
			if ($file->isFile() && strtolower((string) $file->getExtension()) === 'php') {
				$found[] = (string) $file->getPathname();
			}
		}
		sort($found);

		return $found;
	}

	/**
	 * The constructor arguments of every ``new Form_Checkbox(...)`` in a file, comments and
	 * line breaks already stripped so formatting cannot change the answer.
	 *
	 * @return list<list<string>>
	 */
	private function checkboxArgs(string $path): array
	{
		$source = php_strip_whitespace($path);
		preg_match_all("/new Form_Checkbox\(((?:[^()]|\([^()]*\))*)\)/", $source, $matches);

		$calls = [];
		foreach ($matches[1] as $args) {
			$calls[] = array_map('trim', explode(',', $args));
		}

		return $calls;
	}

	public function testEveryCheckboxPassesItsPostedValueExplicitly(): void
	{
		$offenders = [];
		$seen      = 0;

		foreach ($this->pages() as $page) {
			foreach ($this->checkboxArgs($page) as $args) {
				$seen++;
				// name, title, description, checked, value: fewer than five arguments means
				// the page inherits pfSense's 'yes'.
				if (count($args) < 5 || $args[4] === '') {
					$offenders[] = basename($page) . ': new Form_Checkbox(' . implode(', ', $args) . ')';
				}
			}
		}

		// A guard that finds nothing to guard is not a guard: if the sweep stops matching,
		// this count goes to zero and says so instead of passing quietly.
		$this->assertGreaterThan(20, $seen, 'the sweep found almost no checkboxes; its pattern has stopped matching');
		$this->assertSame(
			[],
			$offenders,
			"these checkboxes inherit pfSense's default posted value 'yes', which no PFB_FILTER_ON_OFF "
			. "save path accepts:\n  " . implode("\n  ", $offenders)
		);
	}
}
