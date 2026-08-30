<?php

declare(strict_types=1);

use PhpParser\Node;
use PhpParser\Node\Expr;
use PhpParser\Node\Stmt;
use PhpParser\NodeFinder;
use PhpParser\ParserFactory;
use PHPUnit\Framework\TestCase;

final class RuntimeToggleOwnershipStructureTest extends TestCase
{
	private const INC = __DIR__ . '/../../src/usr/local/pkg/pfblockerng/pfblockerng.inc';

	public function testAdvancedToggleOwnershipControlsEveryConsumer(): void
	{
		$parser = (new ParserFactory())->createForNewestSupportedVersion();
		$source = file_get_contents(self::INC);
		if (!is_string($source)) {
			throw new RuntimeException('test bootstrap: failed to read pfblockerng.inc');
		}
		$ast = $parser->parse($source);
		if (!is_array($ast)) {
			throw new RuntimeException('test bootstrap: failed to parse pfblockerng.inc');
		}

		$finder = new NodeFinder();
		$function = $finder->findFirst($ast, static fn (Node $node): bool =>
			$node instanceof Stmt\Function_ && $node->name->toString() === 'pfb_determine_list_detail');
		$this->assertInstanceOf(Stmt\Function_::class, $function);

		$expected = $parser->parse(<<<'PHP'
<?php
$registered = $confconfig === 'pfblockerngdnsblsettings' && (string) $key === '0';
$toggle_enabled = static function (string $field) use ($conf_config, $registered): bool {
	if ($registered) {
		return PfbConfig::read("dnsbl/{$field}") === PfbToggle::On;
	}
	return pfb_dnsbl_toggle_enabled($conf_config[$field] ?? '');
};
$pfbarr['anot' . $dir] = $toggle_enabled('autonot' . $dir) ? 'on' : '';
$pfbarr['aaddrnot' . $dir] = $toggle_enabled('autoaddrnot' . $dir) ? 'on' : '';
if ($toggle_enabled($akey . $dir)) {}
PHP
		);
		$this->assertIsArray($expected);

		$toggleAssignments = $finder->find($function->stmts, static fn (Node $node): bool =>
			$node instanceof Expr\Assign && self::isVariable($node->var, 'toggle_enabled'));
		$this->assertCount(1, $toggleAssignments, 'the selected reader must have exactly one definition and no reassignment');

		$registeredAssignments = $finder->find($function->stmts, static fn (Node $node): bool =>
			$node instanceof Expr\Assign && self::isVariable($node->var, 'registered'));
		$this->assertCount(1, $registeredAssignments, 'the static-home predicate must have exactly one definition');

		$expressions = $finder->findInstanceOf($function->stmts, Stmt\Expression::class);
		self::assertOneMatchingNode($expressions, $expected[0], 'the static settings singleton predicate');
		self::assertOneMatchingNode($expressions, $expected[1], 'the complete selected-reader closure');
		self::assertOneMatchingNode($expressions, $expected[2], 'the complete autonot consumer expression');
		self::assertOneMatchingNode($expressions, $expected[3], 'the complete autoaddrnot consumer expression');

		$expectedCondition = $expected[4] instanceof Stmt\If_ ? $expected[4]->cond : NULL;
		$this->assertInstanceOf(Expr::class, $expectedCondition);
		$conditions = $finder->find($function->stmts, static fn (Node $node): bool =>
			$node instanceof Stmt\If_ && self::canonical($node->cond) === self::canonical($expectedCondition));
		$this->assertCount(1, $conditions, 'the autoports/autoaddr condition must be exactly the selected-reader call');

		$toggleCalls = $finder->find($function->stmts, static fn (Node $node): bool =>
			$node instanceof Expr\FuncCall && self::isVariable($node->name, 'toggle_enabled'));
		$this->assertCount(3, $toggleCalls, 'the selected reader must feed exactly the three advanced-field consumers');

		$gatewayCalls = $finder->find($function->stmts, static fn (Node $node): bool =>
			$node instanceof Expr\StaticCall
			&& $node->class instanceof Node\Name
			&& $node->class->toString() === 'PfbConfig'
			&& $node->name instanceof Node\Identifier
			&& $node->name->toString() === 'read');
		$this->assertCount(1, $gatewayCalls, 'PfbConfig may appear only in the registered branch of the selected reader');

		$dynamicCalls = $finder->find($function->stmts, static fn (Node $node): bool =>
			$node instanceof Expr\FuncCall
			&& $node->name instanceof Node\Name
			&& $node->name->toString() === 'pfb_dnsbl_toggle_enabled');
		$this->assertCount(1, $dynamicCalls, 'the foreign-key adapter may appear only in the dynamic branch of the selected reader');
	}

	/** @param list<Node> $nodes */
	private static function assertOneMatchingNode(array $nodes, Node $expected, string $label): void
	{
		$canonical = self::canonical($expected);
		$matches = array_filter($nodes, static fn (Node $node): bool => self::canonical($node) === $canonical);
		self::assertCount(1, $matches, "{$label} must match the complete AST exactly");
	}

	private static function isVariable(Node $node, string $name): bool
	{
		return $node instanceof Expr\Variable && $node->name === $name;
	}

	private static function canonical(mixed $value): mixed
	{
		if ($value instanceof Node) {
			$result = ['type' => $value->getType()];
			foreach ($value->getSubNodeNames() as $name) {
				$result[$name] = self::canonical($value->{$name});
			}
			return $result;
		}
		if (is_array($value)) {
			return array_map(self::canonical(...), $value);
		}
		return $value;
	}
}
