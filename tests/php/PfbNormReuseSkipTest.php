<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * issue #1797: the downstream-skip decision after normalization. Both loops
 * skip ONLY when a fresh non-custom download normalized to byte-identical
 * content over a reusable staged '.txt'; every other condition fail-safes to
 * a full reparse (Reload/Force semantics, custom re-synthesis, the
 * stale-.orig download-failure fallback of #1022/#1031, stale staging
 * generation of #1083, user pre/post scripts).
 */
#[CoversFunction('pfb_dnsbl_norm_reuse_skip')]
#[CoversFunction('pfb_ip_norm_reuse_skip')]
final class PfbNormReuseSkipTest extends TestCase
{
	public function testDnsblSkipsOnlyForAFreshUnchangedDownloadOntoCurrentStagingWithoutAUserScript(): void
	{
		$this->assertTrue(pfb_dnsbl_norm_reuse_skip(TRUE, FALSE, FALSE, FALSE, TRUE, TRUE, FALSE));
	}

	/** @return array<string, array{bool,bool,bool,bool,bool,bool,bool}> */
	public static function dnsblNoSkipRows(): array
	{
		return [
			'no fresh download (Reload/Force reparses)' => [FALSE, FALSE, FALSE, FALSE, TRUE, TRUE, FALSE],
			'custom list (re-synthesized per pass)'     => [TRUE, TRUE, FALSE, FALSE, TRUE, TRUE, FALSE],
			'stale-.orig download-failure fallback'     => [TRUE, FALSE, TRUE, FALSE, TRUE, TRUE, FALSE],
			'normalized content changed'                => [TRUE, FALSE, FALSE, TRUE, TRUE, TRUE, FALSE],
			'no staged .txt to reuse'                   => [TRUE, FALSE, FALSE, FALSE, FALSE, TRUE, FALSE],
			'stale staging generation (#1083)'          => [TRUE, FALSE, FALSE, FALSE, TRUE, FALSE, FALSE],
			'user pre/post script owns the full pass'   => [TRUE, FALSE, FALSE, FALSE, TRUE, TRUE, TRUE],
		];
	}

	#[DataProvider('dnsblNoSkipRows')]
	public function testDnsblNeverSkipsWhenAnyGuardFails(bool $fresh, bool $custom, bool $stale, bool $changed, bool $txt, bool $generation, bool $script): void
	{
		$this->assertFalse(pfb_dnsbl_norm_reuse_skip($fresh, $custom, $stale, $changed, $txt, $generation, $script));
	}

	public function testIpSkipsOnlyForAFreshUnchangedDownloadWithoutUserScripts(): void
	{
		$this->assertTrue(pfb_ip_norm_reuse_skip(TRUE, FALSE, FALSE, FALSE, TRUE, FALSE));
	}

	/** @return array<string, array{bool,bool,bool,bool,bool,bool}> */
	public static function ipNoSkipRows(): array
	{
		return [
			'no fresh download (Reload/Force reparses)' => [FALSE, FALSE, FALSE, FALSE, TRUE, FALSE],
			'custom list (re-synthesized per pass)'     => [TRUE, TRUE, FALSE, FALSE, TRUE, FALSE],
			'stale-.orig download-failure fallback'     => [TRUE, FALSE, TRUE, FALSE, TRUE, FALSE],
			'normalized content changed'                => [TRUE, FALSE, FALSE, TRUE, TRUE, FALSE],
			'no staged .txt to reuse'                   => [TRUE, FALSE, FALSE, FALSE, FALSE, FALSE],
			'user pre/post script owns the full pass'   => [TRUE, FALSE, FALSE, FALSE, TRUE, TRUE],
		];
	}

	#[DataProvider('ipNoSkipRows')]
	public function testIpNeverSkipsWhenAnyGuardFails(bool $fresh, bool $custom, bool $stale, bool $changed, bool $txt, bool $script): void
	{
		$this->assertFalse(pfb_ip_norm_reuse_skip($fresh, $custom, $stale, $changed, $txt, $script));
	}
}
