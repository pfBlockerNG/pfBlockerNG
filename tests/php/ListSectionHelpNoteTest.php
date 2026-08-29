<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;

/**
 * Toggle-to-list pointers: DNSBL lists are JS-hidden until enabled; IP suppression is not.
 */
final class ListSectionHelpNoteTest extends TestCase
{
	public function testHiddenUntilEnabledUsesAppearsWhenEnabled(): void
	{
		$note = pfb_list_section_help_note(['Regex List'], TRUE);
		$this->assertStringContainsString('<strong>Regex List</strong> section below', $note);
		$this->assertStringContainsString('appears when this is enabled', $note);
	}

	public function testTwoSectionsUseAppearAndAnd(): void
	{
		$note = pfb_list_section_help_note(['TLD Exclusion List', 'TLD Blacklist'], TRUE);
		$this->assertStringContainsString('<strong>TLD Exclusion List</strong>', $note);
		$this->assertStringContainsString('and <strong>TLD Blacklist</strong> sections below', $note);
		$this->assertStringContainsString('appear when this is enabled', $note);
	}

	public function testAlwaysVisibleIpNoteHasNoAppearsClause(): void
	{
		$note = pfb_list_section_help_note(['IPv4 Suppression', 'IPv6 Suppression'], FALSE);
		$this->assertStringContainsString('<strong>IPv4 Suppression</strong>', $note);
		$this->assertStringContainsString('<strong>IPv6 Suppression</strong>', $note);
		$this->assertStringNotContainsString('appears when this is enabled', $note);
		$this->assertStringNotContainsString('appear when this is enabled', $note);
	}

	public function testDnsblTogglesNameTheSectionsTheJsShows(): void
	{
		$source = file_get_contents(dirname(__DIR__, 2) . '/src/usr/local/www/pfblockerng/pfblockerng_dnsbl.php');
		$this->assertNotFalse($source);
		$pairs = [
			'pfb_regex' => "pfb_list_section_help_note(['Regex List'], TRUE)",
			'pfb_noaaaa' => "pfb_list_section_help_note(['no-AAAA List'], TRUE)",
			'pfb_gp' => "pfb_list_section_help_note(['DNSBL Group Policy'], TRUE)",
			'tld_allow' => "pfb_list_section_help_note(['TLD Allow list'], TRUE)",
			'tld_wildcard' => "pfb_list_section_help_note(['TLD Exclusion List', 'TLD Blacklist'], TRUE)",
		];
		foreach ($pairs as $id => $call) {
			$this->assertStringContainsString($call, $source, "{$id} must point at its list section(s)");
		}
	}

	public function testIpSuppressionPointsAtBothListsWithoutAHideClause(): void
	{
		$source = file_get_contents(dirname(__DIR__, 2) . '/src/usr/local/www/pfblockerng/pfblockerng_ip.php');
		$this->assertNotFalse($source);
		$this->assertStringContainsString(
			"pfb_list_section_help_note(['IPv4 Suppression', 'IPv6 Suppression'], FALSE)",
			$source
		);
	}

	public function testEveryNotedTitleIsAFormSectionOnTheSamePage(): void
	{
		$pages = [
			dirname(__DIR__, 2) . '/src/usr/local/www/pfblockerng/pfblockerng_dnsbl.php',
			dirname(__DIR__, 2) . '/src/usr/local/www/pfblockerng/pfblockerng_ip.php',
		];
		$titles = [];
		foreach ($pages as $path) {
			$source = file_get_contents($path);
			$this->assertNotFalse($source, $path);
			$this->assertGreaterThan(
				0,
				preg_match_all(
					"/pfb_list_section_help_note\(\[(.*?)\],\s*(?:TRUE|FALSE)\)/s",
					$source,
					$calls
				),
				basename($path) . ' must call pfb_list_section_help_note'
			);
			foreach ($calls[1] as $inner) {
				preg_match_all("/'([^']+)'/", $inner, $named);
				foreach ($named[1] as $title) {
					$titles[$path][] = $title;
					$this->assertStringContainsString(
						"new Form_Section('{$title}'",
						$source,
						"note title '{$title}' must be a Form_Section on " . basename($path)
					);
				}
			}
		}
		$flat = array_merge(...array_values($titles));
		$this->assertCount(8, $flat, 'six toggles name eight sections');
	}
}
