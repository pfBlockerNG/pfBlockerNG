// Unit coverage for the Dashboard widget's client-side render helpers.
// Run: node --test tests/js/  (from repo root) — no browser / jQuery needed.
//
// These pin the escaping contract: col1 (count) and col3 (update) are escaped
// by the client before DOM insertion; col0 (alias), col2 (packets), and col4 (img)
// are server-rendered markup that passes through unescaped.

'use strict';

const { test } = require('node:test');
const assert = require('node:assert/strict');
const { pfBlockerNG_escapeHtml, pfBlockerNG_buildWidgetRow } = require('../../src/usr/local/www/widgets/javascript/pfblockerng.js');

// ── pfBlockerNG_escapeHtml ────────────────────────────────────────────────────

test('pfBlockerNG_escapeHtml: escapes & to &amp;', () => {
	assert.equal(pfBlockerNG_escapeHtml('a&b'), 'a&amp;b');
});

test('pfBlockerNG_escapeHtml: escapes < to &lt;', () => {
	assert.equal(pfBlockerNG_escapeHtml('<script>'), '&lt;script&gt;');
});

test('pfBlockerNG_escapeHtml: escapes > to &gt;', () => {
	assert.equal(pfBlockerNG_escapeHtml('x>y'), 'x&gt;y');
});

test('pfBlockerNG_escapeHtml: escapes " to &quot;', () => {
	assert.equal(pfBlockerNG_escapeHtml('say "hi"'), 'say &quot;hi&quot;');
});

test("pfBlockerNG_escapeHtml: escapes ' to &#39;", () => {
	assert.equal(pfBlockerNG_escapeHtml("it's"), 'it&#39;s');
});

test('pfBlockerNG_escapeHtml: leaves a plain string untouched', () => {
	assert.equal(pfBlockerNG_escapeHtml('hello world'), 'hello world');
});

test('pfBlockerNG_escapeHtml: coerces non-string input via String()', () => {
	// Numbers and booleans must not throw; they stringify cleanly.
	assert.equal(pfBlockerNG_escapeHtml(42), '42');
	assert.equal(pfBlockerNG_escapeHtml(true), 'true');
	assert.equal(pfBlockerNG_escapeHtml(null), 'null');
});

// ── pfBlockerNG_buildWidgetRow ────────────────────────────────────────────────

// Scenario: a row whose data columns contain HTML metacharacters.
//
// Given cols where col1 (count) and col3 (update) contain raw < > characters,
// When pfBlockerNG_buildWidgetRow renders the row,
// Then col1 and col3 appear HTML-escaped in the output (proving they cannot
//   inject markup), AND col0 / col2 / col4 pass through verbatim (they are
//   server-rendered markup — escaping them would corrupt the intentional HTML).

test('pfBlockerNG_buildWidgetRow: col1 (count) is HTML-escaped before render', () => {
	// Given: col1 contains a raw < character.
	var cols = ['SafeAlias', '<b>1,234</b>', '0', 'Jan 01 00:00', '<i class="fa"></i>'];

	// Before (regression anchor): verify the raw value is NOT already escaped in cols[1].
	assert.ok(cols[1].includes('<'), 'precondition: col1 contains raw HTML metachar');

	// When
	var row = pfBlockerNG_buildWidgetRow(cols);

	// Then: the output must contain the escaped form, not the raw tag.
	assert.ok(row.includes('&lt;b&gt;'), 'col1 metachar must be escaped in output');
	assert.ok(!row.includes('<b>'), 'col1 raw tag must NOT appear in output');
});

test('pfBlockerNG_buildWidgetRow: col3 (update) is HTML-escaped before render', () => {
	// Given: col3 contains a raw " character (e.g. a malformed timestamp).
	var cols = ['SafeAlias', '999', '0', '"<script>alert(1)</script>"', '<i class="fa"></i>'];

	// Before (regression anchor): verify the raw value is NOT already escaped in cols[3].
	assert.ok(cols[3].includes('<'), 'precondition: col3 contains raw HTML metachar');

	// When
	var row = pfBlockerNG_buildWidgetRow(cols);

	// Then
	assert.ok(row.includes('&lt;script&gt;'), 'col3 metachar must be escaped in output');
	assert.ok(!row.includes('<script>'), 'col3 raw tag must NOT appear in output');
});

test('pfBlockerNG_buildWidgetRow: col0 (alias) passes through as server-rendered markup', () => {
	// Given: col0 is a server-built anchor (popup enabled path).
	var anchorHtml = '<a href="/firewall_aliases_edit.php?id=5" data-popover="true">pfB_Deny_v4</a>';
	var cols = [anchorHtml, '1,234', '<a href="/alerts">500</a>', 'Jan 01 00:00', '<i class="fa-solid fa-turn-up"></i>'];

	// When
	var row = pfBlockerNG_buildWidgetRow(cols);

	// Then: the anchor in col0 must survive verbatim.
	assert.ok(row.includes(anchorHtml), 'col0 server-rendered anchor must pass through unescaped');
});

test('pfBlockerNG_buildWidgetRow: col2 (packets) passes through as server-rendered markup', () => {
	// Given: col2 is a server-built alerts link.
	var packetLink = '<a href="/pfblockerng/pfblockerng_alerts.php?filterip=pfB_Deny_v4">500</a>';
	var cols = ['pfB_Deny_v4', '1,234', packetLink, 'Jan 01 00:00', '<i class="fa-solid fa-turn-up"></i>'];

	// When
	var row = pfBlockerNG_buildWidgetRow(cols);

	// Then: the link in col2 must survive verbatim.
	assert.ok(row.includes(packetLink), 'col2 server-rendered link must pass through unescaped');
});

test('pfBlockerNG_buildWidgetRow: col4 (img) passes through as server-rendered markup', () => {
	// Given: col4 is a server-built icon.
	var iconHtml = '<i class="fa-solid fa-turn-up text-success"></i>';
	var cols = ['pfB_Deny_v4', '1,234', '500', 'Jan 01 00:00', iconHtml];

	// When
	var row = pfBlockerNG_buildWidgetRow(cols);

	// Then: the icon in col4 must survive verbatim.
	assert.ok(row.includes(iconHtml), 'col4 server-rendered icon must pass through unescaped');
});

test('pfBlockerNG_buildWidgetRow: plain row (no metacharacters) renders correctly', () => {
	// Given: a normal row with no special characters.
	var cols = ['pfB_Deny_v4', '1,234', '0', 'Jun 01 12:00', '<i class="fa-solid fa-turn-down"></i>'];

	// When
	var row = pfBlockerNG_buildWidgetRow(cols);

	// Then: all five columns appear in the expected td structure.
	assert.ok(row.includes('<td><small>pfB_Deny_v4</small></td>'), 'col0 present');
	assert.ok(row.includes('<td><small>1,234</small></td>'), 'col1 present');
	assert.ok(row.includes('<td><small>0</small></td>'), 'col2 present');
	assert.ok(row.includes('<td><small>Jun 01 12:00</small></td>'), 'col3 present');
	assert.ok(row.includes('<td><i class="fa-solid fa-turn-down"></i></td></tr>'), 'col4 present');
});
