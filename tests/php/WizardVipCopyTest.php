<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;

/**
 * User-facing copy may not name a sinkhole VIP address the picker cannot produce.
 *
 * The wizard and the architecture notes both described the sweep pool retired with
 * ADR-13 (issue #2869), sending an admin looking for an address the package never
 * assigns. pfb_dnsbl_vip_candidates() is the only source of truth for these.
 */
final class WizardVipCopyTest extends TestCase
{
	private const WIZARD = __DIR__ . '/../../src/usr/local/www/wizards/pfblockerng_wizard.xml';

	private const NOTES = __DIR__ . '/../../docs/misc/architecture-notes.md';

	private static function read(string $path): string
	{
		$body = file_get_contents($path);
		self::assertIsString($body, "{$path} must be readable");
		return $body;
	}

	/**
	 * Any IPv4 literal the wizard shows for the auto-VIP must be one the picker
	 * actually returns -- a literal that drifts is worse than no literal at all.
	 */
	public function testWizardNamesNoVipAddressThePickerCannotProduce(): void
	{
		$wizard = self::read(self::WIZARD);
		$candidates = pfb_dnsbl_vip_candidates(AF_INET);
		$this->assertNotSame([], $candidates, 'the picker must have candidates to compare against');

		preg_match_all('/\b(?:(?:\d{1,3}|[xX])\.){3}(?:\d{1,3}|[xX])\b/', $wizard, $matches);
		$claimed = array_values(array_unique($matches[0]));
		$invented = array_values(array_diff($claimed, $candidates));

		$this->assertSame([], $invented,
			'the wizard names IPv4 sinkhole addresses the picker never returns: '
			. implode(', ', $invented) . ' (picker returns: ' . implode(', ', $candidates) . ')');
	}

	/**
	 * The v6 half of the same claim. The defect had one, so the guard needs one: an
	 * invented ULA in the wizard passed every check while only IPv4 was scanned.
	 */
	public function testWizardNamesNoIpv6AddressThePickerCannotProduce(): void
	{
		$wizard = self::read(self::WIZARD);
		$candidates = pfb_dnsbl_vip_candidates(AF_INET6);
		$this->assertNotSame([], $candidates, 'the picker must have v6 candidates to compare against');

		preg_match_all('/\bfd[0-9a-f]{2}:[0-9a-fA-FxX:]*[0-9a-fA-FxX]\b/', $wizard, $matches);
		$claimed = array_values(array_unique($matches[0]));
		$invented = array_values(array_diff($claimed, $candidates));

		$this->assertSame([], $invented,
			'the wizard names IPv6 sinkhole addresses the picker never returns: '
			. implode(', ', $invented) . ' (picker returns: ' . implode(', ', $candidates) . ')');
	}

	/** The retired sweep pool must not survive in shipped copy or in the notes. */
	public function testRetiredSweepPoolIsGoneFromCopyAndNotes(): void
	{
		foreach ([self::WIZARD, self::NOTES] as $path) {
			$body = self::read($path);
			foreach (['10.10.X.53', '10.10.x.53', 'fd00:X::53', 'fd00::53', '10.10.10.53'] as $retired) {
				$this->assertStringNotContainsString($retired, $body,
					basename($path) . ' still describes the sweep pool ADR-13 retired: ' . $retired);
			}
		}
	}
}
