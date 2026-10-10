<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

require_once __DIR__ . '/SyncPolicyFixtureTrait.php';

/**
 * Issue #3451 — pfb_sync_policy_merge() refuses hostile or malformed input.
 *
 * Both whole inputs are validated before any output is built; a refusal is an
 * \InvalidArgumentException that names the section and never echoes a value, and it leaves
 * both caller arrays untouched and raises no PHP diagnostic.
 *
 * Every case starts from a pair of snapshots that merge cleanly (testBaselinePairMerges...)
 * and changes exactly one position, so only that position can be the reason for the refusal.
 * String payloads contain EVILVALUE so a value echoed into the message is caught.
 *
 * The success-path contract lives in SyncPolicyMergeTest.
 */
#[CoversFunction('pfb_sync_policy_merge')]
final class SyncPolicyMergeRefusalTest extends TestCase
{
	use SyncPolicyFixtureTrait;

	/** Marks a path to be removed rather than set. */
	private const UNSET = "\0unset";

	// ---- baseline ------------------------------------------------------------------------

	/** @return array<string,mixed> */
	private static function feedRow(string $alias): array
	{
		return ['format' => 'auto', 'state' => 'Enabled', 'url' => "https://feeds.example/{$alias}", 'header' => "Hdr{$alias}"];
	}

	/** @return array<string,mixed> */
	private static function groupRow(string $alias, bool $receiver): array
	{
		return [
			'aliasname' => $alias, 'action' => 'Deny_Inbound', 'cron' => 'EveryDay', 'row' => [0 => self::feedRow($alias)],
		] + ($receiver ? ['srcint' => "LOCAL-SENTINEL-{$alias}"] : []);
	}

	/** @return array<string,mixed> */
	private static function item(string $xml, bool $receiver): array
	{
		return ['title' => "Title {$xml}", 'xml' => $xml, 'feed' => 'f', 'size' => '1', 'selected' => 'on']
			+ ($receiver ? ['username' => "SECRET-user-{$xml}", 'password' => "SECRET-pass-{$xml}"] : []);
	}

	/** @return array<string,mixed> one valid section of every kind, as sender ($receiver = FALSE) or receiver */
	private static function snapshot(bool $receiver): array
	{
		return [
			'pfblockerng'            => ['config' => [0 => ['pfb_keep' => $receiver ? 'old' : 'on']
				+ ($receiver ? ['log_syslog' => 'LOCAL-SENTINEL-syslog'] : [])]],
			'pfblockernglistsv4'     => ['config' => [0 => self::groupRow('Alpha', $receiver)]],
			'pfblockernglistsv6'     => ['config' => [0 => self::groupRow('Gamma', $receiver)]],
			'pfblockerngafrica'      => ['config' => [0 => [
				'aliasname' => 'Africa', 'action' => 'Deny_Inbound', 'row' => [0 => self::feedRow('Africa')],
			] + ($receiver ? ['agateway_in' => 'LOCAL-SENTINEL-gw'] : [])]],
			'pfblockerngdnsbl'       => ['config' => [0 => self::groupRow('Beta', $receiver)]],
			'pfblockerngblacklist'   => ['blacklist_enable' => 'on', 'item' => [
				0 => self::item('shallalist.xml', $receiver), 1 => self::item('ut1-capitole.xml', $receiver),
			]],
			'pfblockerngglobal'      => ['feed_Foo' => 'on'] + ($receiver ? ['alertrefresh' => 'LOCAL-SENTINEL-alert'] : []),
			'pfblockerngsafesearch'  => ['safesearch_enable' => 'on'],
		];
	}

	/**
	 * @param 'incoming'|'current' $side
	 * @return array{0: array<string,mixed>, 1: array<string,mixed>, 2: string} [incoming, current, section named by the refusal]
	 */
	private static function pair(string $side, string $path, mixed $value): array
	{
		$trees    = ['incoming' => self::snapshot(FALSE), 'current' => self::snapshot(TRUE)];
		$segments = explode('/', $path);
		$section  = $segments[0];
		if ($value === self::UNSET) {
			$last = array_pop($segments);
			$node = &$trees[$side];
			foreach ($segments as $segment) {
				$node = &$node[$segment];
			}
			unset($node[$last]);
		} else {
			self::setPath($trees[$side], $segments, $value);
		}
		return [$trees['incoming'], $trees['current'], $section];
	}

	// ---- providers -----------------------------------------------------------------------

	/** @return array<string,array{array<string,mixed>,array<string,mixed>,string}> */
	public static function refusals(): array
	{
		$cases = [];
		$add   = static function (string $name, string $side, string $path, mixed $value) use (&$cases): void {
			$cases["{$side} {$path} = {$name}"] = self::pair($side, $path, $value);
		};

		// A leaf is a string or []: anything else, at every kind of leaf position.
		$badLeaves = [
			'int 0' => 0, 'int 1' => 1, 'true' => TRUE, 'false' => FALSE, 'null' => NULL, 'float' => 1.5,
			'list' => ['a'], 'map' => ['a' => ['b']], 'evil list' => ['EVILVALUE'], 'evil map' => ['a' => ['EVILVALUE']],
		];
		$leafPaths = [
			'pfblockerng/config/0/pfb_keep',
			'pfblockerngafrica/config/0/action',
			'pfblockerngglobal/feed_Foo',
			'pfblockerngsafesearch/safesearch_enable',
			'pfblockernglistsv4/config/0/action',
			'pfblockernglistsv4/config/0/row/0/url',
			'pfblockerngblacklist/blacklist_enable',
			'pfblockerngblacklist/item/0/title',
		];
		foreach ($leafPaths as $path) {
			foreach ($badLeaves as $name => $value) {
				$add($name, 'incoming', $path, $value);
			}
		}

		// A section is an array; an empty incoming string is not an empty section.
		foreach (['pfblockerng', 'pfblockernglistsv4', 'pfblockerngafrica', 'pfblockerngglobal', 'pfblockerngblacklist'] as $section) {
			foreach (['string' => 'EVILVALUE', 'empty string' => '', 'int' => 1] as $name => $value) {
				$add($name, 'incoming', $section, $value);
			}
			foreach (['string' => 'EVILVALUE', 'int' => 1] as $name => $value) {
				$add($name, 'current', $section, $value);
			}
		}

		// Container positions hold arrays.
		foreach (['pfblockerng', 'pfblockernglistsv4', 'pfblockerngafrica'] as $section) {
			foreach (['string' => 'EVILVALUE', 'empty string' => '', 'int' => 1] as $name => $value) {
				$add($name, 'incoming', "{$section}/config", $value);
			}
		}
		foreach (['pfblockerng/config/0', 'pfblockerngafrica/config/0'] as $path) {
			foreach (['string' => 'EVILVALUE', 'int' => 1] as $name => $value) {
				$add($name, 'incoming', $path, $value);
			}
		}
		foreach (['string' => 'EVILVALUE', 'int' => 1] as $name => $value) {
			$add($name, 'incoming', 'pfblockernglistsv4/config/0', $value);
			$add($name, 'incoming', 'pfblockernglistsv4/config/0/row/0', $value);
			$add($name, 'incoming', 'pfblockerngafrica/config/0/row/0', $value);
		}
		foreach (['string' => 'EVILVALUE', 'empty string' => ''] as $name => $value) {
			$add($name, 'incoming', 'pfblockernglistsv4/config/0/row', $value);
		}
		foreach (['string' => 'EVILVALUE', 'int' => 1, 'empty string' => ''] as $name => $value) {
			$add($name, 'incoming', 'pfblockerngblacklist/item', $value);
			$add($name, 'incoming', 'pfblockerngblacklist/item/0', $value);
		}
		// Receiver side: a non-empty non-array group row or blacklist container is corrupt.
		foreach (['pfblockernglistsv4/config/0', 'pfblockerngblacklist/item', 'pfblockerngblacklist/item/0'] as $path) {
			$add('string', 'current', $path, 'EVILVALUE');
		}

		// aliasname: a non-empty string of word characters, unique per side, in every G section.
		$badAliases = [
			'missing' => self::UNSET, 'empty' => '', 'empty list' => [], 'int' => 7, 'space' => 'a b EVILVALUE',
			'dash' => 'a-EVILVALUE', 'umlaut' => 'ü', 'semicolon' => 'EVILVALUE;rm', 'traversal' => 'a/../EVILVALUE',
			'newline' => "a\nEVILVALUE",
		];
		foreach (['pfblockernglistsv4', 'pfblockernglistsv6', 'pfblockerngdnsbl'] as $section) {
			foreach ($badAliases as $name => $value) {
				$add($name, 'incoming', "{$section}/config/0/aliasname", $value);
			}
			foreach (['missing' => self::UNSET, 'empty' => '', 'empty list' => [], 'space' => 'a b EVILVALUE'] as $name => $value) {
				$add($name, 'current', "{$section}/config/0/aliasname", $value);
			}
			foreach (['incoming', 'current'] as $side) {
				$pair = self::pair($side, "{$section}/config/0/aliasname", 'EVILVALUEdup');
				$i    = $side === 'incoming' ? 0 : 1;
				$pair[$i][$section]['config'][1] = $pair[$i][$section]['config'][0];
				$cases["{$side} duplicate aliasname ({$section})"] = $pair;
			}
		}

		// Feed header: already normalised (no \W); '' and [] are fine and not listed here.
		foreach (['pfblockernglistsv4', 'pfblockerngdnsbl', 'pfblockerngafrica'] as $section) {
			foreach (['space' => 'bad EVILVALUE header', 'dash' => 'a-EVILVALUE', 'bang' => 'EVILVALUE!', 'int' => 5, 'list' => ['EVILVALUE']] as $name => $value) {
				$add($name, 'incoming', "{$section}/config/0/row/0/header", $value);
			}
		}

		// Blacklist item identity: a non-empty string xml, unique per side.
		foreach (['incoming', 'current'] as $side) {
			foreach (['missing' => self::UNSET, 'empty' => '', 'empty list' => [], 'int' => 5] as $name => $value) {
				$add($name, $side, 'pfblockerngblacklist/item/0/xml', $value);
			}
			$pair = self::pair($side, 'pfblockerngblacklist/item/0/xml', 'EVILVALUE.xml');
			$pair[$side === 'incoming' ? 0 : 1]['pfblockerngblacklist']['item'][1]['xml'] = 'EVILVALUE.xml';
			$cases["{$side} duplicate xml"] = $pair;
		}

		return $cases;
	}

	// ---- tests ---------------------------------------------------------------------------

	public function testBaselinePairMergesSoRefusalsAreAttributableToOneBadPosition(): void
	{
		$out = $this->assertNoDiagnostics(static fn (): array => pfb_sync_policy_merge(self::snapshot(FALSE), self::snapshot(TRUE)));
		$this->assertSame('LOCAL-SENTINEL-Alpha', $out['pfblockernglistsv4']['config'][0]['srcint']);
		$this->assertSame('SECRET-user-shallalist.xml', $out['pfblockerngblacklist']['item'][0]['username']);
		$this->assertSame('on', $out['pfblockerng']['config'][0]['pfb_keep']);
	}

	/**
	 * @param array<string,mixed> $incoming
	 * @param array<string,mixed> $current
	 */
	#[DataProvider('refusals')]
	public function testHostileInputIsRefusedWithoutSideEffects(array $incoming, array $current, string $section): void
	{
		$incoming0   = $incoming;
		$current0    = $current;
		$diagnostics = [];
		$caught      = NULL;

		set_error_handler(static function (int $errno, string $errstr) use (&$diagnostics): bool {
			$diagnostics[] = $errstr;
			return TRUE;
		});
		try {
			pfb_sync_policy_merge($incoming, $current);
		} catch (InvalidArgumentException $e) {
			$caught = $e;
		} finally {
			restore_error_handler();
		}

		$this->assertInstanceOf(InvalidArgumentException::class, $caught, 'hostile input must be refused');
		$this->assertStringContainsString($section, $caught->getMessage(), 'the message names the section');
		$this->assertStringNotContainsString('EVILVALUE', $caught->getMessage(), 'the message never echoes a value');
		$this->assertSame([], $diagnostics, 'refusal must not raise a PHP diagnostic: ' . implode('; ', $diagnostics));
		$this->assertSame($incoming0, $incoming, 'incoming is untouched');
		$this->assertSame($current0, $current, 'current is untouched');
	}

	// Spec: local content from the sender is ignored, not validated, so hostile shapes there are no refusal.
	public function testInjectedLocalsOfAnyShapeAreIgnoredNotRefused(): void
	{
		$incoming = self::snapshot(FALSE);
		$hostile  = [
			'pfblockernglistsv4/config/0/srcint'       => ['a' => ['EVILVALUE']],
			'pfblockernglistsv4/config/0/agateway_in'  => 7,
			'pfblockerng/config/0/log_syslog'          => ['EVILVALUE'],
			'pfblockerngafrica/config/0/agateway_in'   => ['EVILVALUE'],
			'pfblockerngglobal/alertrefresh'           => [1],
			'pfblockerngglobal/widget-x'               => ['EVILVALUE'],
			'pfblockerngblacklist/item/0/username'     => ['EVILVALUE'],
			'pfblockerngblacklist/item/0/password'     => 5,
		];
		foreach ($hostile as $path => $value) {
			self::setPath($incoming, explode('/', $path), $value);
		}
		$current  = self::snapshot(TRUE);
		$incoming0 = $incoming;
		$current0  = $current;

		$out = $this->assertNoDiagnostics(static fn (): array => pfb_sync_policy_merge($incoming, $current));

		$this->assertSame('LOCAL-SENTINEL-Alpha', $out['pfblockernglistsv4']['config'][0]['srcint']);
		$this->assertArrayNotHasKey('agateway_in', $out['pfblockernglistsv4']['config'][0]);
		$this->assertSame('LOCAL-SENTINEL-syslog', $out['pfblockerng']['config'][0]['log_syslog']);
		$this->assertSame('LOCAL-SENTINEL-gw', $out['pfblockerngafrica']['config'][0]['agateway_in']);
		$this->assertSame('LOCAL-SENTINEL-alert', $out['pfblockerngglobal']['alertrefresh']);
		$this->assertArrayNotHasKey('widget-x', $out['pfblockerngglobal']);
		$this->assertSame('SECRET-user-shallalist.xml', $out['pfblockerngblacklist']['item'][0]['username']);
		$this->assertSame('SECRET-pass-shallalist.xml', $out['pfblockerngblacklist']['item'][0]['password']);
		$this->assertStringNotContainsString('EVILVALUE', serialize($out));
		$this->assertSame($incoming0, $incoming);
		$this->assertSame($current0, $current);
	}
}
