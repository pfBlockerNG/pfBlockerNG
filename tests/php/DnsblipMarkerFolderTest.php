<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\TestCase;

/**
 * Issue #655 — the DNSBLIP reprocess '.update' marker must land in the folder that
 * matches its configured action ($pfb['dnsbl_ip']), not a hardcoded denydir.
 *
 * The IP-feed loop resolves the DNSBLIP working folder from the action via
 * pfb_determine_list_detail() and gates reprocessing on "{folder}/{header}.update".
 * The Deny actions and Alias_Deny route to denydir; Alias_Native routes to nativedir. The
 * marker was written to a hardcoded denydir, so for Alias_Native it landed where the loop never
 * looked → a changed DNSBLIP feed fell into the "exists" branch and was NOT reprocessed.
 *
 * Feature: DNSBLIP reprocess-marker folder follows the action
 *   Background:
 *     Given the per-action working dirs (deny/native) and a DNSBL settings section with
 *           no Advanced Invert (so the force-Native override does not fire)
 *   Branch coverage (both folders + the disabled no-op):
 *     * Alias Native -> marker in nativedir, NOT denydir  (the #655 bug)
 *     * Alias Deny / Deny Both -> marker in denydir, NOT nativedir
 *     * Disabled -> no marker written (unroutable action)
 */
#[CoversFunction('pfb_dnsblip_mark_reprocess')]
#[CoversFunction('pfb_dnsblip_action_folder')]
final class DnsblipMarkerFolderTest extends TestCase
{
	/** @var array<string,array{bool,mixed}> Saved globals to restore. */
	private array $saved = [];

	private string $denydir;
	private string $nativedir;

	protected function setUp(): void
	{
		foreach (['pfb', 'pfbarr', 'config'] as $g) {
			$this->saved[$g] = [array_key_exists($g, $GLOBALS), $GLOBALS[$g] ?? null];
		}

		// Real, isolated temp dirs so we can assert the marker file's actual location.
		$base = sys_get_temp_dir() . '/pfb_marker_' . uniqid('', TRUE);
		$this->denydir   = "{$base}/deny";
		$this->nativedir = "{$base}/native";
		mkdir($this->denydir, 0o777, TRUE);
		mkdir($this->nativedir, 0o777, TRUE);

		$GLOBALS['pfb']['denydir']   = $this->denydir;
		$GLOBALS['pfb']['nativedir'] = $this->nativedir;
		$GLOBALS['pfb']['origdir']   = "{$base}/orig";
		$GLOBALS['pfb']['reuse']     = '';

		// Advanced keys present but OFF: autoports/autoaddr block is a no-op AND the
		// "Invert -> force Native" override (which would mask the routing) does not fire.
		$off = [];
		foreach (['autoproto', 'autonot', 'autoaddrnot', 'agateway', 'autoports', 'autoaddr'] as $k) {
			$off["{$k}_in"]  = '';
			$off["{$k}_out"] = '';
		}
		$GLOBALS['config'] = ['installedpackages' => ['pfblockerngdnsblsettings' => ['config' => [0 => $off]]]];
	}

	protected function tearDown(): void
	{
		foreach ($this->saved as $g => [$existed, $value]) {
			if ($existed) {
				$GLOBALS[$g] = $value;
			} else {
				unset($GLOBALS[$g]);
			}
		}
	}

	public function testAliasNativeMarkerLandsInNativeFolderNotDeny(): void
	{
		// Given: the marker is absent from both candidate folders
		$this->assertFileDoesNotExist("{$this->nativedir}/DNSBLIP_v4.update");
		$this->assertFileDoesNotExist("{$this->denydir}/DNSBLIP_v4.update");

		// When: a changed DNSBLIP_v4 feed whose action is 'Alias Native' is marked
		pfb_dnsblip_mark_reprocess('Alias_Native', '_v4');

		// Then: the marker lands in nativedir (where the feed loop looks) and NOT in
		// denydir — the exact mismatch that hid a changed Alias_Native DNSBLIP (#655).
		$this->assertFileExists("{$this->nativedir}/DNSBLIP_v4.update");
		$this->assertFileDoesNotExist("{$this->denydir}/DNSBLIP_v4.update");
	}

	public function testAliasDenyMarkerLandsInDenyFolderNotNative(): void
	{
		// When: the action is 'Alias Deny'
		pfb_dnsblip_mark_reprocess('Alias_Deny', '_v4');

		// Then: denydir gets the marker, nativedir does not — proving the native result
		// above is a real branch, not a constant.
		$this->assertFileExists("{$this->denydir}/DNSBLIP_v4.update");
		$this->assertFileDoesNotExist("{$this->nativedir}/DNSBLIP_v4.update");
	}

	public function testDenyBothMarkerHonoursV6Suffix(): void
	{
		// When: a non-'Alias' Deny action marks the IPv6 feed
		pfb_dnsblip_mark_reprocess('Deny_Both', '_v6');

		// Then: denydir gets the _v6 marker (vtype propagates), nativedir untouched.
		$this->assertFileExists("{$this->denydir}/DNSBLIP_v6.update");
		$this->assertFileDoesNotExist("{$this->nativedir}/DNSBLIP_v6.update");
	}

	public function testDisabledActionWritesNoMarker(): void
	{
		// When: the action is the unroutable 'Disabled'
		pfb_dnsblip_mark_reprocess('Disabled', '_v4');

		// Then: no marker is written anywhere (folder resolves to '').
		$this->assertFileDoesNotExist("{$this->denydir}/DNSBLIP_v4.update");
		$this->assertFileDoesNotExist("{$this->nativedir}/DNSBLIP_v4.update");
	}

	public function testActionFolderResolvesEachActionClass(): void
	{
		// The shared resolver the loop and the marker both rely on.
		$this->assertSame($this->nativedir, pfb_dnsblip_action_folder('Alias_Native'));
		$this->assertSame($this->denydir, pfb_dnsblip_action_folder('Alias_Deny'));
		$this->assertSame($this->denydir, pfb_dnsblip_action_folder('Deny_Both'));
		$this->assertSame('', pfb_dnsblip_action_folder('Disabled'));
	}
}
