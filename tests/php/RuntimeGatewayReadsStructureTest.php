<?php

declare(strict_types=1);

use PhpParser\Node;
use PhpParser\Node\Expr;
use PhpParser\Node\Stmt;
use PhpParser\NodeFinder;
use PhpParser\ParserFactory;
use PhpParser\PrettyPrinter\Standard;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * Issue #3450: the runtime consumers of the 12 newly registered IP scalars read them
 * through PfbConfig::read(), so the registry default is the only default. The value tests
 * prove PfbConfig's semantics; only a structure pin fails when a consumer goes back to the
 * old `$pfb['ipconfig'][...] ?: <default>` expression.
 */
final class RuntimeGatewayReadsStructureTest extends TestCase
{
	private const SRC = __DIR__ . '/../../src/usr/local/';

	/** The registered IP keys a raw array read of which would bypass the registry default (the DNSBL ones are pinned by RuntimeToggleOwnershipStructureTest). */
	private const KEYS = [
		'ip_placeholder', 'maxmind_locale', 'maxmind_account', 'maxmind_key', 'asn_reporting', 'asn_token',
		'inbound_interface', 'inbound_deny_action', 'outbound_interface', 'outbound_deny_action',
		'pass_order', 'autorule_suffix',
	];

	/** @return iterable<string,array{0:string,1:?string,2:list<string>}> file, function (NULL = whole file), expected gateway keys */
	public static function consumerProvider(): iterable
	{
		yield 'sync_package_pfblockerng' => ['pkg/pfblockerng/pfblockerng_apply.inc', 'sync_package_pfblockerng', [
			'ip/inbound_deny_action', 'ip/outbound_deny_action', 'ip/pass_order', 'ip/autorule_suffix',
			'ip/ip_placeholder', '"ip/{$type}_interface"',
		]];
		yield 'pfb_global' => ['pkg/pfblockerng/pfblockerng.inc', 'pfb_global', [
			'ip/maxmind_locale', 'ip/asn_reporting', 'ip/asn_token', 'ip/maxmind_account', 'ip/maxmind_key',
		]];
		yield 'pfb_ip_placeholder' => ['pkg/pfblockerng/pfblockerng.inc', 'pfb_ip_placeholder', ['ip/ip_placeholder']];
		yield 'dnsbl page quick-fill' => ['www/pfblockerng/pfblockerng_dnsbl.php', NULL, ['ip/inbound_interface', 'ip/outbound_interface']];
	}

	/** @param list<string> $expected */
	#[DataProvider('consumerProvider')]
	public function testConsumerReadsRegisteredKeysThroughTheGatewayOnly(string $file, ?string $function, array $expected): void
	{
		$source = file_get_contents(self::SRC . $file);
		if (!is_string($source)) {
			throw new RuntimeException("test bootstrap: failed to read {$file}");
		}
		$ast = (new ParserFactory())->createForNewestSupportedVersion()->parse($source);
		if (!is_array($ast)) {
			throw new RuntimeException("test bootstrap: failed to parse {$file}");
		}

		$finder = new NodeFinder();
		$scope = $ast;
		if ($function !== NULL) {
			$node = $finder->findFirst($ast, static fn (Node $n): bool =>
				$n instanceof Stmt\Function_ && $n->name->toString() === $function);
			$this->assertInstanceOf(Stmt\Function_::class, $node, "{$function} must exist");
			$scope = [$node];
		}

		$printer = new Standard();
		$text = static fn (Node $arg): ?string => match (TRUE) {
			$arg instanceof Node\Scalar\String_ => $arg->value,
			$arg instanceof Node\Scalar\InterpolatedString => $printer->prettyPrintExpr($arg),
			default => NULL,
		};

		$reads = [];
		foreach ($finder->findInstanceOf($scope, Expr\StaticCall::class) as $call) {
			if ($call->class instanceof Node\Name && $call->class->toString() === 'PfbConfig'
				&& $call->name instanceof Node\Identifier && $call->name->toString() === 'read'
				&& isset($call->args[0]) && $call->args[0] instanceof Node\Arg) {
				$reads[] = $text($call->args[0]->value);
			}
		}
		foreach ($expected as $key) {
			$this->assertContains($key, $reads, "{$file}: {$key} must be read through PfbConfig::read()");
		}

		// A registered key read off any array but the $pfb result bag is a raw read that bypasses the default.
		$raw = [];
		foreach ($finder->findInstanceOf($scope, Expr\ArrayDimFetch::class) as $fetch) {
			$bag = $fetch->var instanceof Expr\Variable && $fetch->var->name === 'pfb';
			$dim = $fetch->dim === NULL ? NULL : $text($fetch->dim);
			if (!$bag && $dim !== NULL && (in_array($dim, self::KEYS, TRUE) || str_ends_with($dim, '_interface"'))) {
				$raw[] = $dim;
			}
		}
		$this->assertSame([], $raw, "{$file}: registered keys must not be read from a raw config array");
	}
}
