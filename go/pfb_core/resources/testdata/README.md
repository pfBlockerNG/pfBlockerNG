`canonical.json` is the shared fixture for the canonical member order of a resource body: each case's `want` is what PHP's
`pfb_canonical_alias_set` (`array_unique`, then `usort` with `strcmp`) makes of `input`. It is run by Go
(`TestCanonicalFixture`) and by PHPUnit, so both sides keep one order.
