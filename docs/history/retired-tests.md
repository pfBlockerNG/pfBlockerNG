# Retired named tests

This append-only ledger records intentional named-test retirements that have no successor.
The blocking checker judges only records added in the current staged or pull-request diff;
existing rows are history and cannot discharge a later retirement.

One-line JSON-bullet schema:
`- {"date":"YYYY-MM-DD","test":"<old repo path>::<exact declaration name>","reason":"<nonblank reason>"}`

`date` is a real ISO date no later than today. `test` is the canonical identity, or a bare
name only when it selects exactly one retirement in the current diff.
