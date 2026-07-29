<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;

/**
 * issue #1871 — pfblockerng_hook_edit.inc is reachable from ONE page and no other.
 *
 * The file holds the only destructive hook-script operation in the package: a
 * root-privileged unlink() driven by a GUI request. Its safety rests on two
 * independent things, and this class pins the second one.
 *
 * The first is the set of gates inside the function itself (privilege, allow-list,
 * resolved directory, original path, existence, true resolved path, writability) —
 * covered by HookEditorDeleteTest.
 *
 * The second is EXISTENCE: the function is only in scope where it is allowed to be
 * used. The read-only hook helpers live in pfblockerng_extra.inc, which
 * pfblockerng.inc pulls into essentially every page of the package; anything
 * defined there is callable from the dashboard, the alerts page, and the
 * firewall_aliases_edit config hook. Putting a destructive primitive in that
 * blast radius and relying on callers to behave is exactly the arrangement this
 * separation exists to prevent.
 *
 * Convention alone does not hold that line — a future contributor adding one
 * require_once would silently undo it, and no other test in the suite would
 * notice. So the containment is asserted here, over the real shipping tree.
 */
final class HookEditFileContainmentTest extends TestCase
{
	private const INC = 'pfblockerng_hook_edit.inc';

	/** The one page permitted to include it. */
	private const ALLOWED_INCLUDER = 'src/usr/local/www/pfblockerng/pfblockerng_edit_hooks.php';

	private static string $root = '';

	public static function setUpBeforeClass(): void
	{
		parent::setUpBeforeClass();
		self::$root = dirname(__DIR__, 2);
	}

	/** @return list<string> every shipping file that names the include, repo-relative */
	private static function referencingFiles(): array
	{
		$found = [];
		$directory = new RecursiveDirectoryIterator(self::$root . '/src', FilesystemIterator::SKIP_DOTS);
		foreach (new RecursiveIteratorIterator($directory) as $file) {
			/** @var SplFileInfo $file */
			if (!$file->isFile()) {
				continue;
			}
			$path = $file->getPathname();
			if (!preg_match('/\.(php|inc)$/', $path)) {
				continue;
			}
			$contents = (string) file_get_contents($path);
			if (str_contains($contents, self::INC)) {
				$found[] = ltrim(str_replace(self::$root, '', $path), '/');
			}
		}
		sort($found);
		return $found;
	}

	public function testTheIncludeFileExists(): void
	{
		// Guards the assertions below against vacuity: if the file were renamed or
		// removed, "nothing includes it" would otherwise read as a clean pass.
		$this->assertFileExists(self::$root . '/src/usr/local/pkg/pfblockerng/' . self::INC);
	}

	public function testExactlyOnePageIncludesIt(): void
	{
		$referencing = self::referencingFiles();
		// The file names itself in its own header comment; that is not an include.
		$referencing = array_values(array_filter(
			$referencing,
			static fn (string $path): bool => !str_ends_with($path, self::INC)
		));

		$this->assertSame(
			[self::ALLOWED_INCLUDER],
			$referencing,
			"pfblockerng_hook_edit.inc holds a root-privileged unlink() and must stay reachable from the "
				. "privilege-gated Edit Hooks page ONLY. Files naming it now:\n  " . implode("\n  ", $referencing)
				. "\nIf a second page genuinely needs hook deletion, it needs its own privilege gate first — "
				. "and this list needs updating deliberately, not incidentally."
		);
	}

	public function testThePackageWideIncludesDoNotPullItIn(): void
	{
		// The specific regression that matters: pfblockerng.inc and
		// pfblockerng_extra.inc are loaded almost everywhere, so either one taking a
		// dependency on this file would restore the blast radius the split removed,
		// while the test above would still pass if the reference were indirect.
		foreach (['pfblockerng.inc', 'pfblockerng_extra.inc'] as $wide) {
			$contents = (string) file_get_contents(self::$root . '/src/usr/local/pkg/pfblockerng/' . $wide);
			$this->assertStringNotContainsString(
				self::INC,
				$contents,
				"{$wide} is included by nearly every page; it must not pull in the destructive hook-edit file"
			);
		}
	}

	public function testTheDeleteFunctionIsDefinedNowhereElse(): void
	{
		// Belt and braces on the whole arrangement: the containment is worthless if
		// a copy of the function is also defined in a widely-included file.
		$definitions = [];
		$directory = new RecursiveDirectoryIterator(self::$root . '/src', FilesystemIterator::SKIP_DOTS);
		foreach (new RecursiveIteratorIterator($directory) as $file) {
			/** @var SplFileInfo $file */
			if (!$file->isFile() || !preg_match('/\.(php|inc)$/', $file->getPathname())) {
				continue;
			}
			$contents = (string) file_get_contents($file->getPathname());
			if (preg_match('/^function\s+pfb_hook_editor_delete\s*\(/m', $contents)) {
				$definitions[] = basename($file->getPathname());
			}
		}
		$this->assertSame([self::INC], $definitions, 'the delete function must be defined in exactly one file');
	}
}
