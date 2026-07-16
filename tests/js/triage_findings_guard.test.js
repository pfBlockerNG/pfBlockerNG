'use strict';

const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const workflowPath = path.resolve(__dirname, '../../.claude/workflows/triage-findings.js');
const workflow = fs.readFileSync(workflowPath, 'utf8');
const guardStart = 'for (const verdict of verdicts) {';
const guardEnd = '\nlog(';
const start = workflow.indexOf(guardStart);
const end = workflow.indexOf(guardEnd, start);

assert.notEqual(start, -1, `expected guard start ${JSON.stringify(guardStart)} in ${workflowPath}`);
assert.notEqual(end, -1, `expected guard end ${JSON.stringify(guardEnd)} in ${workflowPath}`);

const runGuard = new Function('verdicts', workflow.slice(start, end));

function verdict(id, decision, disposition) {
	return { id, verdict: decision, issue_gate: { disposition } };
}

test('DEFER requires an actionable issue gate', () => {
	assert.throws(
		() => runGuard([verdict('defer-hardening', 'DEFER', 'hardening-only')]),
		/defer-hardening: DEFER requires an actionable issue_gate/
	);
	assert.doesNotThrow(() => runGuard([verdict('defer-actionable', 'DEFER', 'actionable')]));
});

test('hardening-only findings require SKIP', () => {
	assert.throws(
		() => runGuard([verdict('hardening-apply', 'APPLY', 'hardening-only')]),
		/hardening-apply: hardening-only findings must be SKIP/
	);
	assert.doesNotThrow(() => runGuard([verdict('hardening-skip', 'SKIP', 'hardening-only')]));
});
