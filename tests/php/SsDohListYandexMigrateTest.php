<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\TestCase;

/**
 * pfb_ss_doh_list_yandex_migrate() — the issue-#740 install/upgrade migration for the
 * 'safesearch_doh_list' CSV. The shipped conf entry for Yandex was the malformed
 * hostname "yandex.dns" (never a real endpoint); its paired UI option key is now
 * 'dns.yandex'. An install with the dead 'yandex.dns' token still selected would
 * silently lose that selection on upgrade, so the token is rewritten in place.
 * (The procedural application in pfblockerng_install.inc — PfbConfig::read/write —
 * is smoke/manual-verified; this pins the pure decision the hook delegates to.)
 *
 * Contract:
 *   - NULL/empty/non-string $stored => NULL (nothing to migrate).
 *   - legacy token 'yandex.dns' absent as a CSV element => NULL (no write needed).
 *   - legacy token present => rewritten CSV with 'yandex.dns' replaced by
 *     'dns.yandex', element order preserved, de-duplicated against an
 *     already-present 'dns.yandex'.
 */
#[CoversFunction('pfb_ss_doh_list_yandex_migrate')]
final class SsDohListYandexMigrateTest extends TestCase
{
	public function testNullInputYieldsNull(): void
	{
		$this->assertNull(pfb_ss_doh_list_yandex_migrate(null));
	}

	public function testEmptyStringYieldsNull(): void
	{
		$this->assertNull(pfb_ss_doh_list_yandex_migrate(''));
	}

	public function testLegacyTokenAloneIsRewritten(): void
	{
		$this->assertSame('dns.yandex', pfb_ss_doh_list_yandex_migrate('yandex.dns'));
	}

	public function testLegacyTokenAmongOthersPreservesOrder(): void
	{
		$this->assertSame('dns.google,dns.yandex', pfb_ss_doh_list_yandex_migrate('dns.google,yandex.dns'));
	}

	public function testTokenAbsentYieldsNull(): void
	{
		// 'dns.google' does not contain the legacy element -> nothing to migrate.
		$this->assertNull(pfb_ss_doh_list_yandex_migrate('dns.google'));
	}

	public function testAlreadyMigratedYieldsNull(): void
	{
		// Already the corrected token, run-once -> NULL (no re-write).
		$this->assertNull(pfb_ss_doh_list_yandex_migrate('dns.yandex'));
	}

	public function testLegacyAndCorrectedTokenBothPresentDeduplicates(): void
	{
		$this->assertSame('dns.yandex', pfb_ss_doh_list_yandex_migrate('dns.yandex,yandex.dns'));
	}

	public function testLegacyBeforeCorrectedTokenAlsoDeduplicates(): void
	{
		// Reverse order of the case above — dedup must be order-independent.
		$this->assertSame('dns.yandex', pfb_ss_doh_list_yandex_migrate('yandex.dns,dns.yandex'));
	}
}
