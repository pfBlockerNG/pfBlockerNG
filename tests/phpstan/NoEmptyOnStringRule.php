<?php

declare(strict_types=1);

namespace PfBlockerNG\PHPStan;

use PhpParser\Node;
use PhpParser\Node\Expr\Empty_;
use PHPStan\Analyser\Scope;
use PHPStan\Rules\Rule;
use PHPStan\Rules\RuleErrorBuilder;
use PHPStan\Type\Constant\ConstantBooleanType;
use PHPStan\Type\NeverType;
use PHPStan\Type\TypeCombinator;

/**
 * Issue #1787: empty() on a string operand lies — empty('0') is TRUE, so a
 * valid "0" value reads as absent (the issue-#1707 bug class). Whenever the
 * operand's statically-known type is a string (nullable/string|false wrappers
 * included), the honest predicates are pfb_is_empty() (exact ''/NULL) and
 * pfb_is_blank() (nothing but whitespace).
 *
 * Deliberately silent on mixed/untyped operands (most legacy config-array
 * reads): the gate stops NEW typed-string empty() calls without flagging the
 * whole legacy surface. As annotations tighten, coverage grows for free.
 *
 * @implements Rule<Empty_>
 */
final class NoEmptyOnStringRule implements Rule
{
	public function getNodeType(): string
	{
		return Empty_::class;
	}

	public function processNode(Node $node, Scope $scope): array
	{
		$type = $scope->getType($node->expr);
		// ?string and string|false still answer "is this an empty string?"
		// with empty()'s '0' lie — strip the wrappers before deciding.
		$bare = TypeCombinator::removeNull($type);
		$bare = TypeCombinator::remove($bare, new ConstantBooleanType(false));
		if ($bare instanceof NeverType || !$bare->isString()->yes()) {
			return [];
		}
		return [
			RuleErrorBuilder::message(
				"empty() on a string operand lies: empty('0') is TRUE. " .
				"Use pfb_is_empty() for ''/NULL or pfb_is_blank() for whitespace-only (issue #1787)."
			)->identifier('pfBlockerNG.emptyOnString')->build(),
		];
	}
}
