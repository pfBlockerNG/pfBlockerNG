<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;

/**
 * GeoIP pages point at IP-tab MaxMind credentials without requiring a live key
 * to be cleared. Missing-key callouts stay gated on pfb_maxmind_credential_notice().
 */
final class GeoipCredentialNoticeUiTest extends TestCase
{
	private static function category(): string
	{
		$source = file_get_contents(dirname(__DIR__, 2) . '/src/usr/local/www/pfblockerng/pfblockerng_category.php');
		if ($source === FALSE) {
			throw new RuntimeException('failed to read category page');
		}
		return $source;
	}

	private static function geoipInc(): string
	{
		$source = file_get_contents(dirname(__DIR__, 2) . '/src/usr/local/pkg/pfblockerng/pfblockerng_geoip.inc');
		if ($source === FALSE) {
			throw new RuntimeException('failed to read geoip template');
		}
		return $source;
	}

	private static function ipPage(): string
	{
		$source = file_get_contents(dirname(__DIR__, 2) . '/src/usr/local/www/pfblockerng/pfblockerng_ip.php');
		if ($source === FALSE) {
			throw new RuntimeException('failed to read IP page');
		}
		return $source;
	}

	public function testGeoipSummaryAlwaysPointsAtIpTabCredentials(): void
	{
		$source = self::category();
		$geoipCallout = strpos($source, "if (\$gtype == 'geoip') {\n\tprint_callout('GeoIP database GeoLite2");
		$this->assertNotFalse($geoipCallout, 'GeoIP attribution callout missing');
		$callout = substr($source, $geoipCallout, 1800);
		$this->assertStringContainsString('href="/pfblockerng/pfblockerng_ip.php"', $callout);
		$this->assertStringContainsString('MaxMind GeoIP configuration', $callout);
		$this->assertStringContainsString('MaxMind Account ID and License Key', $callout);
	}

	public function testGeoipSummaryMissingKeyCalloutLinksToIpTab(): void
	{
		$source = self::category();
		$this->assertStringContainsString(
			'pfb_maxmind_credential_notice($pfb[\'maxmind_key\'], $pfb[\'maxmind_account\'])',
			$source
		);
		$notice = strpos($source, '$mmsg = pfb_maxmind_credential_notice');
		$callout = strpos($source, "print_callout('<br /><p><strong>' . \$mmsg");
		if ($callout === FALSE) {
			$callout = strpos($source, "print_callout('<p><strong>' . \$mmsg");
		}
		$this->assertNotFalse($notice);
		$this->assertNotFalse($callout, 'missing-key print_callout missing on GeoIP summary');
		$this->assertLessThan($callout, $notice);
		$window = substr($source, $callout, 500);
		$this->assertStringContainsString('href="/pfblockerng/pfblockerng_ip.php"', $window);
		$this->assertStringContainsString("\$mmsg !== ''", $source);
	}

	public function testContinentTemplatePointsAtIpTabAndGatesTheWarning(): void
	{
		$source = self::geoipInc();
		$this->assertStringContainsString(
			'pfb_maxmind_credential_notice($pfb[\'maxmind_key\'], $pfb[\'maxmind_account\'])',
			$source
		);
		$notes = strpos($source, 'GeoIP data by MaxMind Inc.');
		$this->assertNotFalse($notes);
		$notesWindow = substr($source, $notes, 900);
		$this->assertStringContainsString('href="/pfblockerng/pfblockerng_ip.php"', $notesWindow);
		$this->assertStringContainsString('MaxMind GeoIP configuration', $notesWindow);

		$callout = strpos($source, 'print_callout(', $notes);
		$this->assertNotFalse($callout, 'continent missing-key print_callout missing');
		$calloutWindow = substr($source, $callout, 500);
		$this->assertStringContainsString('href="/pfblockerng/pfblockerng_ip.php"', $calloutWindow);
		$this->assertStringContainsString('$mmsg', $calloutWindow);
	}

	public function testBlankIpSaveDoesNotClearStoredMaxMindKey(): void
	{
		$source = self::ipPage();
		$this->assertStringContainsString(
			'// issue #924: blank keeps the existing stored key -- only overwrite on a non-empty',
			$source
		);
		$this->assertMatchesRegularExpression(
			'/if \(\$pfb_maxmind_key_post !== \'\'\) \{\s*\$pfb\[\'iconfig\'\]\[\'maxmind_key\'\] = pfb_filter\(\$pfb_maxmind_key_post/',
			$source
		);
		$this->assertStringContainsString(
			"['placeholder' => 'Enter your MaxMind GeoLite2 License Key -- leave blank to keep the current key']",
			$source
		);
	}
}
