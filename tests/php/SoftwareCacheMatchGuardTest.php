<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\TestCase;

/**
 * pfb_software_cache_matches_install() reads two values out of a JSON cache file and casts
 * them to string. The file is written by this package, but it is a file on disk: a truncated
 * write, a hand-edit, or a future writer can put an array where a scalar belongs, and the
 * cast then emits "Array to string conversion" into php_error.log on every call — noise the
 * UI test tiers read as a page defect (issue #2367).
 *
 * The verdict was already right (a non-matching cache is not adopted); what these cases pin
 * is that reaching it is silent.
 */
#[CoversFunction('pfb_software_cache_matches_install')]
final class SoftwareCacheMatchGuardTest extends TestCase
{
	/**
	 * Run the matcher with warnings captured rather than converted, so the assertion is
	 * about what it emitted and not merely about not throwing.
	 *
	 * @param array<string,mixed> $cache
	 * @return array{0:bool,1:list<string>}
	 */
	private function match(array $cache, string $pkgname, string $repo): array
	{
		$seen = [];
		set_error_handler(static function (int $errno, string $msg) use (&$seen): bool {
			$seen[] = $msg;
			return TRUE;
		});

		try {
			$verdict = pfb_software_cache_matches_install($cache, $pkgname, $repo);
		} finally {
			restore_error_handler();
		}

		return [$verdict, $seen];
	}

	/** An array-valued pkgname is rejected, and says nothing to the error log doing it. */
	public function testArrayPkgnameIsRejectedSilently(): void
	{
		[$verdict, $seen] = $this->match(
			['pkgname' => ['pfSense-pkg-pfBlockerNG'], 'repo' => 'pfblockerng-stable'],
			'pfSense-pkg-pfBlockerNG',
			'pfblockerng-stable'
		);

		$this->assertFalse($verdict, 'an array pkgname cannot identify the install');
		$this->assertSame([], $seen, 'the matcher must not emit a diagnostic: ' . implode(' | ', $seen));
	}

	/** Same for the repo half, which is read only after the pkgname half matches. */
	public function testArrayRepoIsRejectedSilently(): void
	{
		[$verdict, $seen] = $this->match(
			['pkgname' => 'pfSense-pkg-pfBlockerNG', 'repo' => ['pfblockerng-stable']],
			'pfSense-pkg-pfBlockerNG',
			'pfblockerng-stable'
		);

		$this->assertFalse($verdict, 'an array repo cannot identify the catalogue');
		$this->assertSame([], $seen, 'the matcher must not emit a diagnostic: ' . implode(' | ', $seen));
	}

	/**
	 * A present-but-null half is refused the same way an array one is. JSON's null reaches
	 * PHP as null, and coalescing it to '' before the guard would let a cache that names
	 * nothing match an install whose own name is empty — the asymmetry the guard exists to
	 * remove, since the repo half already refuses null.
	 */
	public function testNullHalvesAreRefusedLikeAnyOtherNonScalar(): void
	{
		[$name_verdict, $name_seen] = $this->match(
			['pkgname' => NULL, 'repo' => 'pfblockerng-stable'],
			'',
			'pfblockerng-stable'
		);
		$this->assertFalse($name_verdict, 'a null pkgname names no install, empty live name or not');
		$this->assertSame([], $name_seen, 'the matcher must not emit a diagnostic: ' . implode(' | ', $name_seen));

		[$repo_verdict] = $this->match(
			['pkgname' => 'pfSense-pkg-pfBlockerNG', 'repo' => NULL],
			'pfSense-pkg-pfBlockerNG',
			''
		);
		$this->assertFalse($repo_verdict, 'a null repo names no catalogue, empty live repo or not');
	}

	/**
	 * The branches that must not change: a matching cache still matches, a repo-less cache
	 * (every box that predates #2148) is still adopted, and a real mismatch is still refused.
	 */
	public function testScalarBranchesAreUnchanged(): void
	{
		[$match] = $this->match(
			['pkgname' => 'pfSense-pkg-pfBlockerNG', 'repo' => 'pfblockerng-stable'],
			'pfSense-pkg-pfBlockerNG',
			'pfblockerng-stable'
		);
		$this->assertTrue($match, 'a cache describing this install matches');

		[$legacy] = $this->match(
			['pkgname' => 'pfSense-pkg-pfBlockerNG'],
			'pfSense-pkg-pfBlockerNG',
			'pfblockerng-stable'
		);
		$this->assertTrue($legacy, 'a cache with no repo key predates #2148 and is adopted');

		[$other_repo] = $this->match(
			['pkgname' => 'pfSense-pkg-pfBlockerNG', 'repo' => 'pfblockerng-edge'],
			'pfSense-pkg-pfBlockerNG',
			'pfblockerng-stable'
		);
		$this->assertFalse($other_repo, 'a cache from another catalogue is refused');

		[$other_name] = $this->match(
			['pkgname' => 'pfSense-pkg-pfBlockerNG-devel', 'repo' => 'pfblockerng-stable'],
			'pfSense-pkg-pfBlockerNG',
			'pfblockerng-stable'
		);
		$this->assertFalse($other_name, 'a cache naming another package is refused');
	}
}
