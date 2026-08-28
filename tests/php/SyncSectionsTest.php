<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\TestCase;

/**
 * Pin the XMLRPC sync section list built by pfblockerng_sync_sections().
 *
 * The function replaces two formerly-inlined copies of this same list (in
 * pfblockerng_do_xmlrpc_sync() and pfblockerng_plugin_xmlrpc_send()) — this
 * test pins the section names + fixed order so a future edit to one call
 * site can't silently drift from the other.
 *
 * Coverage mandate (CLAUDE.md): both branches of the include_interfaces flag.
 */
#[CoversFunction('pfblockerng_sync_sections')]
final class SyncSectionsTest extends TestCase
{
	/**
	 * $include_interfaces = FALSE returns exactly the 16 non-interface
	 * sections, in the documented fixed order.
	 */
	public function testExcludesInterfaceSectionsWhenFalse(): void
	{
		$this->assertSame(
			[
				'pfblockernglistsv4',
				'pfblockernglistsv6',
				'pfblockerngreputation',
				'pfblockerngtopspammers',
				'pfblockerngafrica',
				'pfblockerngantarctica',
				'pfblockerngasia',
				'pfblockerngeurope',
				'pfblockerngnorthamerica',
				'pfblockerngoceania',
				'pfblockerngsouthamerica',
				'pfblockerngproxyandsatellite',
				'pfblockerngdnsbl',
				'pfblockerngblacklist',
				'pfblockerngglobal',
				'pfblockerngsafesearch',
			],
			pfblockerng_sync_sections(FALSE)
		);
	}

	/**
	 * $include_interfaces = TRUE prepends the 3 interface sections ahead of
	 * the same 16 non-interface sections.
	 */
	public function testPrependsInterfaceSectionsWhenTrue(): void
	{
		$this->assertSame(
			[
				'pfblockerng',
				'pfblockerngipsettings',
				'pfblockerngdnsblsettings',
				'pfblockernglistsv4',
				'pfblockernglistsv6',
				'pfblockerngreputation',
				'pfblockerngtopspammers',
				'pfblockerngafrica',
				'pfblockerngantarctica',
				'pfblockerngasia',
				'pfblockerngeurope',
				'pfblockerngnorthamerica',
				'pfblockerngoceania',
				'pfblockerngsouthamerica',
				'pfblockerngproxyandsatellite',
				'pfblockerngdnsbl',
				'pfblockerngblacklist',
				'pfblockerngglobal',
				'pfblockerngsafesearch',
			],
			pfblockerng_sync_sections(TRUE)
		);
	}
}
