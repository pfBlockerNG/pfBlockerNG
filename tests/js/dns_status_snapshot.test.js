'use strict';

const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const page = fs.readFileSync(require('node:path').join(__dirname,
	'../../src/usr/local/www/pfblockerng/pfblockerng_dns_general.php'), 'utf8');
const script = page.match(/<script>\s*(events\.push\([\s\S]*?)<\/script>/)[1];

// Only the DOM operations used by the shipped polling script; parsing and HTTP remain platform boundaries.
class Element {
	constructor(tag = 'document', attrs = {}) {
		this.tag = tag;
		this.attrs = attrs;
		this.childNodes = [];
		this.hidden = attrs.hidden !== undefined;
		this.classes = new Set((attrs.class || '').split(' '));
		this.classList = {
			contains: name => this.classes.has(name),
			toggle: (name, on) => on ? this.classes.add(name) : this.classes.delete(name),
		};
	}
	get id() { return this.attrs.id; }
	get cells() { return this.childNodes.filter(node => node.tag === 'td'); }
	get textContent() { return this.text || this.childNodes.map(node => node.textContent).join(''); }
	set textContent(value) { this.text = value; this.childNodes = []; }
	getAttribute(name) { return this.attrs[name] ?? null; }
	setAttribute(name, value) { this.attrs[name] = value; }
	removeAttribute(name) { delete this.attrs[name]; }
	hasAttribute(name) { return name in this.attrs; }
	contains(node) { return node === this || this.childNodes.some(child => child.contains(node)); }
	replaceChildren(...nodes) {
		this.childNodes = nodes;
		for (const node of nodes) { node.parent = this; }
	}
	matches(selector) {
		if (selector.startsWith('#')) { return this.id === selector.slice(1); }
		if (selector.startsWith('.')) { return selector.slice(1).split('.').every(name => this.classes.has(name)); }
		const match = selector.match(/^([a-z]+)?\[([^=\]]+)(?:="([^"]*)")?\]$/);
		return !!match && (!match[1] || this.tag === match[1]) && this.hasAttribute(match[2]) &&
			(match[3] === undefined || this.attrs[match[2]] === match[3]);
	}
	querySelectorAll(selector) {
		const parts = selector.split(' > ');
		const result = [];
		for (const child of this.childNodes) {
			if (child.matches(parts.at(-1)) && (parts.length === 1 || child.parent.matches(parts[0]))) { result.push(child); }
			result.push(...child.querySelectorAll(selector));
		}
		return result;
	}
	querySelector(selector) { return this.querySelectorAll(selector)[0] || null; }
	getElementById(id) { return this.querySelector('#' + id); }
}

function parse(html) {
	const root = new Element();
	let current = root;
	for (const token of html.match(/<[^>]+>|[^<]+/g) || []) {
		if (token.startsWith('</')) {
			current = current.parent;
		} else if (token.startsWith('<')) {
			const tag = token.match(/^<([a-z0-9]+)/)[1];
			const attrs = Object.fromEntries([...token.matchAll(/([a-z-]+)="([^"]*)"/g)].map(match => [match[1], match[2]]));
			const child = new Element(tag, attrs);
			child.parent = current;
			current.childNodes.push(child);
			current = child;
		} else {
			const text = new Element('text');
			text.textContent = token;
			text.parent = current;
			current.childNodes.push(text);
		}
	}
	return root;
}

function snapshot(name, addresses) {
	return '<div id="pfb-dns-status"><div id="pfb-dns-status-overview">' +
		'<div id="pfb-dns-status-service">Running</div><div id="pfb-dns-status-name">' + name + '</div></div>' +
		'<div id="pfb-dns-status-ddr"><div id="pfb-dns-status-ddr_panel-body" class="panel-body collapse in">' +
		addresses.map(address => '<tr data-address="' + address + '" data-state="matched"><td>LAN</td><td>' +
			address + '</td><td>Advertised</td></tr>').join('') + '</div></div>' +
		'<p id="pfb-dns-ddr-refresh-status" role="status" hidden="hidden"></p></div>';
}

const drain = () => new Promise(resolve => setImmediate(resolve));
async function harness(reply = snapshot('applied.example.com', ['192.0.2.9:53'])) {
	const document = parse(snapshot('old.example.com', ['192.0.2.1:53', '127.0.0.1:53', '[::1]:53']));
	const form = new Element('input', { id: 'pfb_dns_name' });
	form.value = 'unsaved.example.com';
	document.childNodes.push(form);
	document.activeElement = form;
	const timers = new Map();
	const requests = [];
	const events = [];
	const listeners = {};
	let sequence = 0;
	const context = {
		document, events, AbortController, DOMParser: class { parseFromString(html) { return parse(html); } },
		setTimeout(fn, delay) { const id = ++sequence; timers.set(id, { fn, delay }); return id; },
		clearTimeout(id) { timers.delete(id); },
		window: { addEventListener(name, fn) { listeners[name] = fn; } },
		async fetch(url, options) {
			requests.push({ url, options });
			if (reply instanceof Error) { throw reply; }
			return { ok: true, redirected: false, headers: { get() { return 'application/json'; } },
				async json() { return { html: reply }; } };
		},
	};
	vm.runInNewContext(script, context);
	events[0]();
	await drain();
	return { document, form, requests, timers, listeners, async poll() {
		const timer = [...timers].find(([, value]) => value.delay === 30000);
		assert.ok(timer, 'A completed refresh must schedule the next bounded poll');
		timers.delete(timer[0]);
		timer[1].fn();
		await drain();
	} };
}

test('initial applied page schedules polling without fetching a second snapshot', async () => {
	const view = await harness();
	assert.equal(view.requests.length, 0, 'The initial HTML is already one complete applied snapshot');
});

test('one refresh fetch replaces the complete applied overview and inventory regardless of listener count', async () => {
	const view = await harness();
	view.requests.length = 0;
	await view.poll();
	assert.equal(view.requests.length, 1, 'Three old listener rows must not cause three control snapshots');
	assert.equal(view.requests[0].url, 'pfblockerng_dns_general.php?ajax=ddr');
	assert.equal(view.requests[0].options.cache, 'no-store');
	assert.equal(view.requests[0].options.credentials, 'same-origin');
	assert.equal(view.document.getElementById('pfb-dns-status-name').textContent, 'applied.example.com');
	const rows = view.document.getElementById('pfb-dns-status').querySelectorAll('tr[data-address]');
	assert.deepEqual(rows.map(row => row.getAttribute('data-address')), ['192.0.2.9:53']);
	assert.equal(view.form.value, 'unsaved.example.com', 'Status refresh must not touch the form');
});

test('a valid unavailable snapshot replaces stale applied values instead of retaining a saved name', async () => {
	const view = await harness(snapshot('Unavailable', []));
	await view.poll();
	assert.equal(view.document.getElementById('pfb-dns-status-name').textContent, 'Unavailable');
	assert.equal(view.document.getElementById('pfb-dns-status').querySelectorAll('tr[data-address]').length, 0);
});

for (const [name, response] of [['network', new Error('offline')], ['missing overview', '<p>No status</p>'],
	['duplicate status', snapshot('forged.example.com', []) + snapshot('forged.example.com', [])]]) {
	test(name + ' failure retains the applied snapshot and exposes an accessible refresh failure', async () => {
		const view = await harness(response);
		const overview = view.document.getElementById('pfb-dns-status-overview');
		await view.poll();
		assert.equal(view.document.getElementById('pfb-dns-status-overview'), overview);
		assert.equal(view.document.getElementById('pfb-dns-status-name').textContent, 'old.example.com');
		const note = view.document.getElementById('pfb-dns-ddr-refresh-status');
		assert.equal(note.hidden, false);
		assert.equal(note.getAttribute('role'), 'status');
		assert.match(note.textContent, /could not be refreshed/);
		assert.equal(view.form.value, 'unsaved.example.com');
	});
}

test('pagehide stops subsequent automatic snapshots', async () => {
	const view = await harness();
	view.listeners.pagehide();
	assert.equal([...view.timers.values()].filter(timer => timer.delay === 30000).length, 0);
});
