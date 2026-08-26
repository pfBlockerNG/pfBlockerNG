<?php

declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\TestCase;

/**
 * pfb_render_memo() — the page-scope memoisation helper added for issue #809 (Alerts
 * page render-time performance). One render request is one PHP process, so a caller
 * passes in a function-static array that lives for exactly one page load; this helper
 * caches the resolver's return value per key in it, including a falsy result
 * (NULL/FALSE/''/0) — array_key_exists() rather than isset() so those are never
 * mistaken for "not yet resolved" and re-run.
 */
#[CoversFunction('pfb_render_memo')]
final class RenderMemoTest extends TestCase
{
	public function testRepeatedKeyResolvesOnce(): void
	{
		// Given a store and a resolver that counts its own invocations.
		$store = array();
		$calls = 0;
		$resolver = function () use (&$calls) {
			$calls++;
			return 'resolved-value';
		};

		// When the same key is resolved three times.
		$first	= pfb_render_memo($store, 'domain.example', $resolver);
		$second	= pfb_render_memo($store, 'domain.example', $resolver);
		$third	= pfb_render_memo($store, 'domain.example', $resolver);

		// Then the resolver ran exactly once, and every call sees its value.
		$this->assertSame(1, $calls, "expected the resolver to run exactly once for a repeated key, got [{$calls}] invocations");
		$this->assertSame('resolved-value', $first, "expected the first call to return [resolved-value], got [{$first}]");
		$this->assertSame('resolved-value', $second, "expected the second call to return the memoized [resolved-value], got [{$second}]");
		$this->assertSame('resolved-value', $third, "expected the third call to return the memoized [resolved-value], got [{$third}]");
	}

	public function testDistinctKeysResolveOnceEach(): void
	{
		// Given a store shared by two distinct keys, each with its own counting resolver.
		$store	= array();
		$callsA	= 0;
		$callsB	= 0;

		$resolverA = function () use (&$callsA) {
			$callsA++;
			return 'value-a';
		};
		$resolverB = function () use (&$callsB) {
			$callsB++;
			return 'value-b';
		};

		// When each key is resolved twice (interleaved).
		$a1 = pfb_render_memo($store, 'a', $resolverA);
		$b1 = pfb_render_memo($store, 'b', $resolverB);
		$a2 = pfb_render_memo($store, 'a', $resolverA);
		$b2 = pfb_render_memo($store, 'b', $resolverB);

		// Then each key's resolver ran exactly once, and neither key's value leaked
		// into the other.
		$this->assertSame(1, $callsA, "expected key [a]'s resolver to run once, got [{$callsA}] invocations");
		$this->assertSame(1, $callsB, "expected key [b]'s resolver to run once, got [{$callsB}] invocations");
		$this->assertSame('value-a', $a1, "expected key [a] first call to return [value-a], got [{$a1}]");
		$this->assertSame('value-a', $a2, "expected key [a] second call to return the memoized [value-a], got [{$a2}]");
		$this->assertSame('value-b', $b1, "expected key [b] first call to return [value-b], got [{$b1}]");
		$this->assertSame('value-b', $b2, "expected key [b] second call to return the memoized [value-b], got [{$b2}]");
	}

	public function testNullResultIsCachedNotReResolved(): void
	{
		// Given a resolver that returns NULL.
		$store = array();
		$calls = 0;
		$resolver = function () use (&$calls) {
			$calls++;
			return null;
		};

		// When resolved twice.
		$first	= pfb_render_memo($store, 'k', $resolver);
		$second	= pfb_render_memo($store, 'k', $resolver);

		// Then NULL is treated as a valid cached result, not "unresolved".
		$this->assertNull($first, 'expected the first call to return the resolver\'s NULL');
		$this->assertNull($second, 'expected the second call to return the memoized NULL, not re-resolve');
		$this->assertSame(1, $calls, "expected the resolver to run exactly once despite NULL being falsy, got [{$calls}] invocations");
		$this->assertArrayHasKey('k', $store, 'expected the store to record the NULL result via array_key_exists()');
	}

	public function testFalseResultIsCachedNotReResolved(): void
	{
		// Given a resolver that returns FALSE.
		$store = array();
		$calls = 0;
		$resolver = function () use (&$calls) {
			$calls++;
			return FALSE;
		};

		// When resolved twice.
		$first	= pfb_render_memo($store, 'k', $resolver);
		$second	= pfb_render_memo($store, 'k', $resolver);

		// Then FALSE is treated as a valid cached result, not "unresolved".
		$this->assertFalse($first, 'expected the first call to return the resolver\'s FALSE');
		$this->assertFalse($second, 'expected the second call to return the memoized FALSE, not re-resolve');
		$this->assertSame(1, $calls, "expected the resolver to run exactly once despite FALSE being falsy, got [{$calls}] invocations");
	}

	public function testEmptyStringResultIsCachedNotReResolved(): void
	{
		// Given a resolver that returns ''.
		$store = array();
		$calls = 0;
		$resolver = function () use (&$calls) {
			$calls++;
			return '';
		};

		// When resolved twice.
		$first	= pfb_render_memo($store, 'k', $resolver);
		$second	= pfb_render_memo($store, 'k', $resolver);

		// Then '' is treated as a valid cached result, not "unresolved".
		$this->assertSame('', $first, 'expected the first call to return the resolver\'s empty string');
		$this->assertSame('', $second, "expected the second call to return the memoized '', not re-resolve");
		$this->assertSame(1, $calls, "expected the resolver to run exactly once despite '' being falsy, got [{$calls}] invocations");
	}

	public function testZeroResultIsCachedNotReResolved(): void
	{
		// Given a resolver that returns 0.
		$store = array();
		$calls = 0;
		$resolver = function () use (&$calls) {
			$calls++;
			return 0;
		};

		// When resolved twice.
		$first	= pfb_render_memo($store, 'k', $resolver);
		$second	= pfb_render_memo($store, 'k', $resolver);

		// Then 0 is treated as a valid cached result, not "unresolved".
		$this->assertSame(0, $first, 'expected the first call to return the resolver\'s 0');
		$this->assertSame(0, $second, 'expected the second call to return the memoized 0, not re-resolve');
		$this->assertSame(1, $calls, "expected the resolver to run exactly once despite 0 being falsy, got [{$calls}] invocations");
	}

	public function testIndependentStoresDoNotCrossContaminate(): void
	{
		// Given two independent stores, resolved under the SAME key with different resolvers.
		$storeOne = array();
		$storeTwo = array();

		$resolverOne = function () {
			return 'from-store-one';
		};
		$resolverTwo = function () {
			return 'from-store-two';
		};

		// When the same key is resolved in each store.
		$resultOne = pfb_render_memo($storeOne, 'same-key', $resolverOne);
		$resultTwo = pfb_render_memo($storeTwo, 'same-key', $resolverTwo);

		// Then each store resolves independently -- no shared state between them.
		$this->assertSame('from-store-one', $resultOne, "expected store one's own resolution for [same-key], got [{$resultOne}]");
		$this->assertSame('from-store-two', $resultTwo, "expected store two's own resolution for [same-key], got [{$resultTwo}]");
		$this->assertSame(array('same-key' => 'from-store-one'), $storeOne,
			'expected store one to hold only its own resolved value, got ' . json_encode($storeOne));
		$this->assertSame(array('same-key' => 'from-store-two'), $storeTwo,
			'expected store two to hold only its own resolved value, unaffected by store one, got ' . json_encode($storeTwo));
	}
}
