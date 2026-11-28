<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * #3977, the removal list: the Core Updater runs every Update, so the PHP code that sequenced, fetched, parsed, deduplicated
 * and aggregated is gone. Each name below is neither defined nor called anywhere under src/, and each removed file is gone
 * with every reference to it ("no dual path after this PR").
 */
final class CutoverRemovalListTest extends TestCase
{
	private const SRC = __DIR__ . '/../../src';

	/** @return array<string, array{0: string}> */
	public static function removedFunctions(): array
	{
		return array_map(static fn (string $name): array => [$name], array_combine($names = [
			'pfblockerng_sync_cron', 'pfb_update_check', 'sync_package_pfblockerng',
			'pfb_top1m_dispatch_if_changed', 'pfblockerng_download_extras', 'pfblockerng_uc_countries',
			'pfb_schedule_extra_run', 'pfb_feed_normalize',
		], $names));
	}

	/** @return array<string, array{0: string}> */
	public static function removedFiles(): array
	{
		return array_map(static fn (string $path): array => [$path], array_combine($paths = [
			'usr/local/pkg/pfblockerng/pfblockerng_cron.inc',
			'usr/local/pkg/pfblockerng/pfb_feed_normalize.py',
		], $paths));
	}

	/** @return list<string> every line under src/ that names $word as a whole word, with its path */
	private static function mentions(string $word): array
	{
		exec('grep -rnw -- ' . escapeshellarg($word) . ' ' . escapeshellarg(self::SRC), $lines);
		return $lines;
	}

	#[DataProvider('removedFunctions')]
	public function testTheFunctionIsNeitherDefinedNorCalled(string $name): void
	{
		$calls = array_filter(self::mentions($name), static fn (string $line): bool => preg_match('/\b' . $name . '\s*\(/', $line) === 1
			&& preg_match('~^[^:]+:\d+:\s*(//|\*|#)~', $line) !== 1);
		$this->assertSame([], array_values($calls));
	}

	#[DataProvider('removedFiles')]
	public function testTheFileIsGoneAndNothingLoadsIt(string $path): void
	{
		$this->assertFileDoesNotExist(self::SRC . "/{$path}");
		$loads = array_filter(self::mentions(basename($path)), static fn (string $line): bool =>
			preg_match('/\b(require|include)(_once)?\b/', $line) === 1);
		$this->assertSame([], array_values($loads));
	}

	/** The Extras verbs are gone: the Core Updater fetches and converts every Extra in its Updates (#3977). */
	public function testTheExtrasVerbsAreGoneFromTheCli(): void
	{
		$page = php_strip_whitespace(self::SRC . '/usr/local/www/pfblockerng/pfblockerng.php');
		foreach (['dc', 'dcc', 'bu', 'uc', 'gc', 'al', 'asn', 'asn_shell', 'bl', 'bls', 'ugc'] as $verb) {
			$this->assertStringNotContainsString("case '{$verb}':", $page, $verb);
			$this->assertStringNotContainsString("'{$verb}',", $page, "{$verb} in the verb list");
		}
	}
}
