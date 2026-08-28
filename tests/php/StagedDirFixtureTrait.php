<?php

declare(strict_types=1);

/**
 * Shared directory-fixture reading and teardown for the staged-publication suites.
 *
 * Both staging helpers name their scratch and backup directories with a leading dot,
 * and glob() never returns dot entries — so a litter assertion spelled with glob()
 * cannot fail on leftovers, which is the whole point of those assertions. Every
 * suite that asserts "nothing was left behind" therefore needs the same dot-aware
 * listing, and the same recursive teardown that copes with a tree the fixture only
 * half-created.
 *
 * Extracted from DownloadStagePublishDirTest and DownloadGeoipStagePublishTest so
 * the two carry one listing rather than two copies (PR #2782 review nitpick).
 */
trait StagedDirFixtureTrait
{
	/**
	 * Entry names under $path, dot entries included. An unreadable directory reports
	 * a sentinel rather than an empty listing, so it fails its assertion loudly
	 * instead of reading as "nothing was left behind".
	 *
	 * @return string[]
	 */
	private function entries(string $path): array
	{
		$found = @scandir($path);
		return $found === FALSE
			? array('<unreadable>')
			: array_values(array_diff($found, array('.', '..')));
	}

	/** Remove a fixture tree without following symlinks out of it. */
	private function removeTree(string $path): void
	{
		foreach ($this->entries($path) as $name) {
			$child = "{$path}/{$name}";
			is_dir($child) && !is_link($child) ? $this->removeTree($child) : @unlink($child);
		}
		@rmdir($path);
	}
}
