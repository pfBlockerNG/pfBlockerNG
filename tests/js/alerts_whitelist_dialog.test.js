// Issue #3647: the Reports > Alerts whitelist-icon dialog for a TLD-blocked domain.
// Run: node --test tests/js/  (from repo root) — no browser / jQuery needed.
//
// The page's inline script is not a module, so each test loads a fresh "page": the PRODUCTION
// DNSBLWT click handler plus the add_description()/dnsbl_whitelist() helpers it hands off to are
// sliced out of pfblockerng_alerts.php and run in their own vm context against a recording jQuery
// double. A fresh context per test is a fresh page load; clicks inside one test share globals the
// way real clicks on one page do. The real jQuery UI rendering is Tier B
// (tests/smoke/ui/test_alerts_tld_whitelist_dialog.py).

'use strict';

const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');

const SOURCE = fs.readFileSync(
	path.join(__dirname, '../../src/usr/local/www/pfblockerng/pfblockerng_alerts.php'),
	'utf8'
);

function between(start, end) {
	const from = SOURCE.indexOf(start);
	const to = SOURCE.indexOf(end, from);
	assert.ok(from >= 0 && to > from, 'source marker not found: ' + (from < 0 ? start : end));
	return SOURCE.slice(from, to);
}

function topLevelFunction(name) {
	return between('function ' + name + '(', '\n}\n') + '\n}\n';
}

const HANDLER = between("\t$('[id^=DNSBLWT]').click(", "\t$('[id^=PFBIPSUP]').click(");
const HELPERS = topLevelFunction('add_description') + topLevelFunction('dnsbl_whitelist');

const TLD_ICON = 'DNSBLWT|tld|bad.example|www.bad.example';
const ADD_ICON = 'DNSBLWT|add|bad.example|FeedA|DNSBL';
const DNSBL_ADD_ICON = 'DNSBLWT|dnsbl_add|bad.example|ListA|ListB';
const WHITELIST_BUTTONS = ['1. Wildcard Whitelist', '2. Whitelist', 'Cancel'];
const BLOCK_BUTTONS = ['1. Wildcard Block', '2. Block', 'Cancel'];

function loadPage() {
	const vals = {};
	const dialogs = [];
	const submits = [];
	const selectWhitelist = [];
	let handler;

	function $(selector) {
		const el = {
			click(fn) { handler = fn; return el; },
			val(v) { if (v === undefined) return vals[selector]; vals[selector] = v; return el; },
			appendTo() { return el; },
			html(h) { el.markup = h; return el; },
			// $(this).dialog('close') passes a string; only an options object opens a dialog.
			dialog(opts) { if (typeof opts === 'object') dialogs.push({ markup: el.markup, opts }); return el; },
			css() { return el; },
			find() { return el; },
			addClass() { return el; },
			remove() { return el; },
			submit() { submits.push(Object.assign({}, vals)); return el; },
		};
		return el;
	}

	// In a browser `domain` and `table` resolve to the form inputs of the same id (truthy elements).
	const context = vm.createContext({
		$, domain: {}, table: {},
		confirm: () => true,
		prompt: () => '',
		select_whitelist: (mode, list) => selectWhitelist.push({ mode, list: Array.from(list) }),
	});
	vm.runInContext(HELPERS, context);
	vm.runInContext(HANDLER, context);

	const newest = () => dialogs[dialogs.length - 1];
	return {
		submits,
		selectWhitelist,
		click(id) {
			handler.call({ id }, { target: { title: 'confirm text' } });
			return newest();
		},
		press(label) {
			const button = newest().opts.buttons[label];
			assert.ok(button, 'no button ' + label + ' in ' + Object.keys(newest().opts.buttons));
			button.call({});
			return newest();
		},
		labels: (dialog) => Object.keys(dialog.opts.buttons),
		vals,
	};
}

test('TLD dialog on a fresh page is labelled and whitelists into the DNSBL Whitelist', () => {
	const page = loadPage();

	const opened = page.click(TLD_ICON);
	assert.deepEqual(page.labels(opened), WHITELIST_BUTTONS);
	assert.equal(opened.opts.title, 'Domain Whitelisting:');
	assert.deepEqual(page.submits, [], 'nothing is submitted before the description step is answered');

	const described = page.press('2. Whitelist');
	assert.equal(described.opts.title, 'Whitelist description:');
	page.press('No');

	assert.equal(page.submits.length, 1);
	assert.equal(page.submits[0]['#addwhitelistdom'], 'true');
	assert.equal(page.submits[0]['#domain'], 'bad.example');
	assert.equal(page.submits[0]['#table'], 'www.bad.example');
	assert.equal(page.submits[0]['#dnsbl_exclude'] || '', '');
	assert.equal(page.submits[0]['#dnsbl_add'], undefined);
	assert.equal(page.submits[0]['#ip_white'], undefined);
});

test('TLD wildcard button whitelists the wildcard into the DNSBL Whitelist', () => {
	const page = loadPage();
	page.click(TLD_ICON);
	page.press('1. Wildcard Whitelist');
	page.press('No');

	assert.equal(page.submits[0]['#dnsbl_wildcard'], 'true');
	assert.equal(page.submits[0]['#addwhitelistdom'], 'true');
	assert.equal(page.submits[0]['#domain'], 'bad.example');
	assert.equal(page.submits[0]['#table'], 'www.bad.example');
	assert.equal(page.submits[0]['#dnsbl_exclude'] || '', '');
});

test('add dialog keeps its whitelist labels and feed target', () => {
	const page = loadPage();
	const opened = page.click(ADD_ICON);
	assert.deepEqual(page.labels(opened), WHITELIST_BUTTONS);
	assert.equal(opened.opts.title, 'Domain Whitelisting:');
	page.press('2. Whitelist');
	page.press('No');

	assert.equal(page.submits[0]['#addwhitelistdom'], 'true');
	assert.equal(page.submits[0]['#table'], 'FeedA');
});

test('dnsbl_add dialog keeps its block labels and customlist target', () => {
	const page = loadPage();
	const opened = page.click(DNSBL_ADD_ICON);
	assert.deepEqual(page.labels(opened), BLOCK_BUTTONS);
	assert.equal(opened.opts.title, 'Domain Blocking:');
	page.press('2. Block');

	assert.deepEqual(page.selectWhitelist, [{ mode: 'dns_reply', list: ['ListA', 'ListB'] }]);
	assert.deepEqual(page.submits, []);
});

for (const [name, icon, title] of [
	['add', ADD_ICON, 'Domain Whitelisting:'],
	['dnsbl_add', DNSBL_ADD_ICON, 'Domain Blocking:'],
]) {
	test('TLD dialog keeps its own label after a ' + name + ' dialog ran', () => {
		const page = loadPage();
		assert.equal(page.click(icon).opts.title, title, 'before-state: the earlier dialog really ran');

		const tld = page.click(TLD_ICON);
		assert.deepEqual(page.labels(tld), WHITELIST_BUTTONS);
		assert.equal(tld.opts.title, 'Domain Whitelisting:');
	});
}
