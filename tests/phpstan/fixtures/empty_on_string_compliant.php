<?php

// Fixture for NoEmptyOnStringRuleTest: none of the empty() calls below sit on
// a statically-string-typed operand, so NoEmptyOnStringRule MUST stay silent —
// the gate bans the string lie, not empty() itself (issue #1787).

function pfb_fixture_empty_on_array(array $rows): bool {
	return empty($rows); // arrays are empty()'s legitimate use
}

function pfb_fixture_empty_on_untyped($config): bool {
	return empty($config); // mixed/untyped legacy reads stay un-flagged
}

function pfb_fixture_exact_comparison(string $value): bool {
	return $value === ''; // the honest check needs no helper to pass the gate
}
