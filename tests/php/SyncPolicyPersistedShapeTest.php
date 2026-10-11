<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * Issue #3452 (PR #3480 B1) -- pfb_sync_persisted_shape(): the value pfSense settles on for one
 * config subtree once write_config() wrote it and later requests reread config.xml, per the pinned
 * writer and parser (pfsense/pfsense src/etc/inc/xmlparse.inc @9363ac5b: dump_xml_config_sub()
 * :253-320, endElement() :102-133). The policy receive compares and digests this shape, so a
 * repeated identical receive is 'unchanged' whatever empty containers the sender's disk holds.
 */
#[CoversFunction('pfb_sync_persisted_shape')]
final class SyncPolicyPersistedShapeTest extends TestCase
{
	/** @return iterable<string,array{0:mixed,1:mixed}> */
	public static function shapes(): iterable
	{
		yield 'an empty listtag array is written as nothing' => [['config' => [], 'k' => 'v'], ['k' => 'v']];
		yield 'a map left without a child element reads back as an empty string' => [['config' => []], ''];
		yield 'an empty map is written as an empty element' => [[], ''];
		yield 'a non-listtag empty map keeps its key as an empty string' => [['skipfeed' => [], 'k' => 'v'], ['skipfeed' => '', 'k' => 'v']];
		yield 'a list entry that reads back empty is dropped and the list renumbered' => [
			['row' => [0 => '', 1 => [], 2 => ['url' => 'x'], 3 => ['state' => []]]],
			['row' => [0 => ['url' => 'x'], 1 => ['state' => '']]],
		];
		yield 'a list whose every entry is dropped is dropped too' => [['row' => [''], 'k' => 'v'], ['k' => 'v']];
		yield 'a nested emptied list empties its parent entry' => [['config' => [0 => ['row' => []]]], ''];
		yield 'a scalar under a listtag key reads back as a one-entry list' => [['item' => 'x'], ['item' => ['x']]];
		yield 'listtag names match case-insensitively' => [['Row' => [], 'k' => 'v'], ['k' => 'v']];
		yield 'FALSE is not written, TRUE reads back empty, a number as its string' => [
			['f' => FALSE, 't' => TRUE, 'n' => 7],
			['t' => '', 'n' => '7'],
		];
		yield 'strings stay byte-exact, leading zeros and spaces included' => [['a' => '007', 'b' => ' x '], ['a' => '007', 'b' => ' x ']];
	}

	#[DataProvider('shapes')]
	public function testValueReadsBackInThePersistedShape(mixed $value, mixed $persisted): void
	{
		$this->assertSame($persisted, pfb_sync_persisted_shape($value));
	}

	#[DataProvider('shapes')]
	public function testPersistedShapeIsSettled(mixed $_value, mixed $persisted): void
	{
		// Writing and rereading a persisted value changes nothing more.
		$this->assertSame($persisted, pfb_sync_persisted_shape($persisted));
	}
}
