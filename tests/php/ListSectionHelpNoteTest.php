<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;

/**
 * Toggle-to-list pointers. Page call-sites are asserted with the tab changes.
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
}
