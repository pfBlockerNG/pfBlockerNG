'use strict';
// issue #3647 harness: runs the PRODUCTION Reports > Alerts whitelist-icon click handler (and the
// add_description()/dnsbl_whitelist() helpers it hands off to) in a fresh "page" with a recording jQuery
// double. release/3.3 ships no browser tier, so this is its executable JS tier.
//
// usage: node run_alerts_whitelist_dialog_3_3.js <pfblockerng_alerts.php>   (steps as JSON on stdin)
// steps: {"click": "<icon id>"} | {"press": "<button label of the newest dialog>"}
// stdout: JSON {steps: [{dialog, submits, vals, selectWhitelist}...]}, one entry per step.
const fs = require('fs');
const vm = require('vm');

const source = fs.readFileSync(process.argv[2], 'utf8');
const steps = JSON.parse(fs.readFileSync(0, 'utf8'));

function between(start, end) {
	const from = source.indexOf(start);
	const to = source.indexOf(end, from);
	if (from < 0 || to < 0) throw new Error('missing source marker: ' + (from < 0 ? start : end));
	return source.slice(from, to);
}

function topLevelFunction(name) {
	return between('function ' + name + '(', '\n}\n') + '\n}\n';
}

const vals = {};
const dialogs = [];
const submits = [];
const selectWhitelist = [];
const handlers = {};

function $(selector) {
	const el = {
		click(fn) { handlers[selector] = fn; return el; },
		val(v) { if (v === undefined) return vals[selector]; vals[selector] = v; return el; },
		appendTo() { return el; },
		html(h) { el.markup = h; return el; },
		dialog(opts) { if (typeof opts === 'object') dialogs.push({ markup: el.markup, opts }); return el; },
		css() { return el; },
		find() { return el; },
		addClass() { return el; },
		remove() { return el; },
		submit() { submits.push(Object.assign({}, vals)); return el; },
	};
	return el;
}

// In the browser `domain` and `table` resolve to the form inputs of the same id (truthy elements).
const sandbox = {
	$, domain: {}, table: {},
	confirm: () => true,
	prompt: () => '',
	select_whitelist: (mode, list) => selectWhitelist.push({ mode, list }),
};
vm.createContext(sandbox);

vm.runInContext(topLevelFunction('add_description') + topLevelFunction('dnsbl_whitelist'), sandbox);
vm.runInContext(between("\t$('[id^=DNSBLWT]').click(", "\t$('[id^=PFBIPSUP]').click("), sandbox);

function snapshot() {
	const d = dialogs[dialogs.length - 1];
	return {
		dialog: d && {
			title: d.opts.title,
			message: d.markup.replace(/<[^>]*>/g, ''),
			buttons: Object.keys(d.opts.buttons),
		},
		submits: submits.slice(),
		vals: Object.assign({}, vals),
		selectWhitelist: selectWhitelist.slice(),
	};
}

const log = [];
for (const step of steps) {
	if (step.click !== undefined) {
		handlers['[id^=DNSBLWT]'].call({ id: step.click }, { target: { title: 'confirm text' } });
	} else {
		const d = dialogs[dialogs.length - 1];
		const button = d.opts.buttons[step.press];
		if (!button) throw new Error('no button ' + step.press + ' in ' + Object.keys(d.opts.buttons));
		button.call({ dialog: () => {} });
	}
	log.push(snapshot());
}
process.stdout.write(JSON.stringify({ steps: log }));
