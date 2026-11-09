/*
 * Shared request-local Stats panels and charts.
 *
 * Copyright (c) 2015-2026 Rubicon Communications, LLC (Netgate)
 * Copyright (c) 2015-2024 BBcan177@gmail.com
 * All rights reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
(function () {
	'use strict';
	const configElement = document.getElementById('Alert_Stats_Config');
	if (!configElement) { return; }
	const config = JSON.parse(configElement.textContent);
	const picker = document.getElementById('Alert_Stats_Range');
	const shown = picker.value;
	const loading = document.getElementById('Alert_Stats_Loading');
	const status = document.getElementById('Alert_Stats_Status');
	const retry = document.getElementById('Alert_Stats_Retry');
	const panels = new Map();
	let payload = null;
	let request = null;
	let generation = 0;
	let timeline = null;
	let observer = null;

	function fluidPie(id) {
		const svg = document.getElementById(id).querySelector('svg');
		if (!svg) { return; }
		const width = svg.getAttribute('width');
		const height = svg.getAttribute('height');
		if (width && height && !svg.getAttribute('viewBox')) {
			svg.setAttribute('viewBox', '0 0 ' + width + ' ' + height);
		}
		svg.removeAttribute('width');
		svg.removeAttribute('height');
		svg.setAttribute('preserveAspectRatio', 'xMidYMid meet');
	}

	function destroyTimeline() {
		if (!timeline) { return; }
		timeline.chart.tooltip.hidden(true);
		timeline.svg.selectAll('*').interrupt();
		timeline.svg.interrupt().remove();
		document.querySelectorAll('.nvtooltip').forEach(function (tooltip) { tooltip.remove(); });
		timeline = null;
	}

	function renderTimeline() {
		const container = document.getElementById('chart');
		if (!container || !payload) { return; }
		destroyTimeline();
		const data = payload.timeline.slice();
		const count = data.length;
		if (count && count < 24) {
			for (let i = 24 - count; i > 0; i--) {
				data.push({edate: 'Placeholder ' + i, ecount: 0, series: 0});
			}
		}
		const chart = nv.models.discreteBarChart()
			.margin({top: 5, left: 65, right: 25, bottom: 60})
			.x(function (point) { return point.edate; })
			.y(function (point) { return point.ecount; })
			.showYAxis(true).showXAxis(true);
		chart.xAxis.tickPadding(10).axisLabel('Date (Hr) [ Found: ' + count + ' hours ]');
		chart.yAxis.tickFormat(d3.format('.0f')).tickPadding(10).axisLabel('Event(s)');
		const colors = config.style === 'multi' ? [
			'#9BB7D4', '#C74375', '#BF1932', '#7BC4C4', '#E2583E', '#53B0AE',
			'#DECDBE', '#9B1B30', '#5A5B9F', '#F0C05A', '#45B5AA', '#D94F70',
			'#DD4124', '#009473', '#B163A3', '#955251', '#F7CAC9', '#92A8D1',
			'#88B04B', '#5F4B8B', '#FF6F61', '#2484C1', '#65A620', '#7B6888'
		] : [
			'#E0E0E0', '#DCDCDC', '#D8D8D8', '#D3D3D3', '#D0D0D0', '#C8C8C8',
			'#C0C0C0', '#BEBEBE', '#B8B8B8', '#B0B0B0', '#A9A9A9', '#A8A8A8',
			'#A0A0A0', '#989898', '#909090', '#888888', '#808080', '#787878',
			'#707070', '#696969', '#686868', '#606060', '#585858', '#505050'
		];
		chart.color(function (point) {
			const hour = point.edate.slice(-3, -1);
			if (config.style === 'greyscale' || config.style === 'multi') {
				return colors[Number(hour)];
			}
			return hour === '00' ? config.color1 : config.color2;
		});
		const svg = d3.select(container).append('svg').attr('id', 'svg');
		nv.utils.initSVG(svg);
		const measure = svg.append('g').attr('class', 'nvd3 nv-axis');
		const tickWidth = measure.append('text').text(data.length ? data[0].edate : '')
			.node().getComputedTextLength() + 16;
		measure.remove();
		function updateTicks() {
			const width = nv.utils.availableWidth(null, svg, chart.margin());
			const step = Math.max(1, Math.ceil(data.length * tickWidth / Math.max(1, width)));
			chart.xAxis.tickValues(data.filter(function (point, index) {
				return index % step === 0;
			}).map(function (point) { return point.edate; }));
		}
		updateTicks();
		svg.datum([{key: 'Series 1', values: data, color: '#0000ff'}]).transition().duration(300).call(chart);
		timeline = {chart: chart, svg: svg, updateTicks: updateTicks};
	}

	function renderPie(data, target, size) {
		const pie = new d3pie(target || data.id, {
			size: Object.assign({canvasHeight: 390, canvasWidth: 560, pieInnerRadius: 60, pieOuterRadius: '78%'}, size || {}),
			data: {sortOrder: 'value-asc', content: data.content},
			labels: {
				outer: {pieDistance: 25}, inner: {format: 'percentage', hideWhenLessThanPercentage: 3},
				mainLabel: {font: 'verdana', fontSize: 14},
				percentage: {color: '#ffffff', font: 'verdana', fontSize: 10, decimalPlaces: 0},
				value: {color: '#adadad', font: 'verdana', fontSize: 15},
				lines: {enabled: true, style: 'curved', color: 'segment'},
				truncation: {enabled: true, truncateLength: 15}
			},
			effects: {
				load: {speed: 300}, pullOutSegmentOnClick: {effect: 'linear', speed: 400, size: 20},
				highlightSegmentOnMouseover: true, highlightLuminosity: -0.7
			},
			tooltips: {
				enabled: true, type: 'placeholder', string: '{label}: {percentage}% ({value})', placeholderParser: null,
				styles: {fadeInSpeed: 250, backgroundColor: '#000000', backgroundOpacity: 0.5,
					color: '#f7f7f7', borderRadius: 2, font: 'verdana', fontSize: 14, padding: 4}
			},
			misc: {gradient: {enabled: true, percentage: 50}, pieCenterOffset: {x: 0, y: 0},
				colors: {background: null, segmentStroke: '#ffffff'}}
		});
		fluidPie(target || data.id);
		return pie;
	}

	function zoomPie(data, button) {
		const title = button.getAttribute('aria-label');
		const modal = $('<div class="modal fade" tabindex="-1" role="dialog"><div class="modal-dialog modal-lg pfb-pie-zoom-dialog" role="document"><div class="modal-content">'
			+ '<div class="modal-header"><button type="button" class="close" data-dismiss="modal" aria-label="Close"><span aria-hidden="true">&times;</span></button>'
			+ '<h4 class="modal-title"></h4></div><div class="modal-body"><div class="pfb-pie-zoomed" id="' + data.id + '_zoom"></div></div></div></div></div>');
		modal.find('.modal-title').text(title);
		let zoomed = null;
		modal.on('shown.bs.modal', function () { zoomed = renderPie(data, data.id + '_zoom', {canvasHeight: 600, canvasWidth: 860, pieInnerRadius: 90}); });
		modal.on('hidden.bs.modal', function () { if (zoomed) { zoomed.destroy(); } modal.remove(); button.focus(); });
		$('body').append(modal);
		modal.modal('show');
	}

	function mountPie(panel) {
		const holder = document.getElementById(panel.data.pie.id);
		const column = holder.parentElement;
		// The pie's height follows its own shape, capped like the table beside it.
		holder.style.maxHeight = column.style.maxHeight;
		panel.pie = renderPie(panel.data.pie);
		const heading = panel.body.closest('.panel') && panel.body.closest('.panel').querySelector('.panel-title');
		const button = document.createElement('button');
		button.type = 'button';
		button.className = 'btn btn-default btn-xs pfb-pie-zoom';
		button.setAttribute('aria-label', 'Zoom ' + (heading ? heading.textContent.trim() : 'chart'));
		button.innerHTML = '<i class="fa-solid fa-magnifying-glass-plus" aria-hidden="true"></i>';
		button.addEventListener('click', function () { zoomPie(panel.data.pie, button); });
		holder.appendChild(button);
	}

	function mount(panel) {
		if (panel.mounted) { return; }
		panel.mounted = true;
		if (observer) { observer.unobserve(panel.body); }
		if (config.url) {
			// HTML is rendered and escaped by the authenticated package renderer, never supplied by a log as markup.
			panel.body.innerHTML = panel.data.html;
		}
		panel.body.style.minHeight = '';
		// Stats columns shrink to their content and only scroll past the configured height.
		panel.body.querySelectorAll('.pfb-stats-col').forEach(function (column) {
			if (column.style.height) { column.style.maxHeight = column.style.height; column.style.height = ''; }
			if (column.style.overflowY === 'scroll') { column.style.overflowY = 'auto'; }
		});
		if (panel.body.querySelector('#chart')) { renderTimeline(); }
		if (panel.data.pie) { mountPie(panel); }
		if (window.Sortable) {
			panel.body.querySelectorAll('table[data-sortable]').forEach(function (table) { Sortable.initTable(table); });
		}
	}

	function disposePanels() {
		if (observer) { observer.disconnect(); observer = null; }
		destroyTimeline();
		panels.forEach(function (panel) { if (panel.pie) { panel.pie.destroy(); } });
		panels.clear();
	}

	function accept(data) {
		disposePanels();
		payload = data;
		document.getElementById('Alert_Stats_Total').textContent = data.total === null ? '—' : data.total;
		if (config.url) {
			observer = new IntersectionObserver(function (entries) {
				entries.forEach(function (entry) {
					if (entry.isIntersecting && entry.target.getClientRects().length) {
						const panel = panels.get(entry.target.id);
						if (panel) { mount(panel); }
					}
				});
			});
		}
		data.panels.forEach(function (item) {
			const body = document.getElementById('Alert_Stats_' + item.id + '_panel-body');
			if (!body) { return; }
			const panel = {data: item, body: body, mounted: false, pie: null};
			panels.set(body.id, panel);
			if (observer) { observer.observe(body); } else { mount(panel); }
		});
		if (status) {
			loading.setAttribute('aria-busy', 'false');
			status.textContent = data.total === null ? 'No log statistics selected.' :
				(data.total === 0 ? 'No events found.' : 'Statistics loaded.');
			retry.hidden = true;
		}
	}

	async function load() {
		if (request) { return; }
		const current = ++generation;
		const controller = new AbortController();
		request = controller;
		loading.setAttribute('aria-busy', 'true');
		status.textContent = 'Loading statistics…';
		retry.hidden = true;
		try {
			const response = await fetch(config.url, {credentials: 'same-origin', cache: 'no-store',
				headers: {'Accept': 'application/json', 'X-Requested-With': 'XMLHttpRequest'}, signal: controller.signal});
			const text = await response.text();
			if (text.trim() === 'SESSION_TIMEOUT' || text.trim() === '"SESSION_TIMEOUT"' ||
				!(response.headers.get('Content-Type') || '').includes('application/json')) {
				throw new Error('session');
			}
			if (!response.ok) { throw new Error('request'); }
			const data = JSON.parse(text);
			if (!Array.isArray(data.panels) || !Array.isArray(data.timeline) ||
				!(data.total === null || Number.isInteger(data.total))) { throw new Error('response'); }
			if (current === generation) { accept(data); }
		} catch (error) {
			if (current !== generation || error.name === 'AbortError') { return; }
			loading.setAttribute('aria-busy', 'false');
			status.textContent = error.message === 'session' ?
				'Your session has expired. Sign in again, then retry.' : 'Statistics could not be loaded. Retry to try again.';
			retry.hidden = false;
		} finally {
			if (current === generation) { request = null; }
		}
	}

	// One range for every panel (fetched or server-rendered): reload this URL with it, keeping view and other parameters.
	function rangeChange() {
		const url = new URL(location.href);
		url.searchParams.set('range', picker.value);
		location.assign(url);
	}

	// A page restored from the back/forward cache keeps its old data: show the range that data belongs to.
	function restored() { picker.value = shown; }

	function expanded(event) {
		const panel = panels.get(event.target.id);
		if (!panel) { return; }
		mount(panel);
		if (panel.pie) { panel.pie.redraw(); fluidPie(panel.data.pie.id); }
		if (panel.body.querySelector('#chart') && timeline) { timeline.updateTicks(); timeline.chart.update(); }
	}

	function resize() {
		if (timeline && document.getElementById('chart').getClientRects().length) {
			timeline.updateTicks(); timeline.chart.update();
		}
	}

	function dispose(event) {
		if (event.persisted) { return; }
		generation++;
		if (request) { request.abort(); request = null; }
		disposePanels();
		picker.removeEventListener('change', rangeChange);
		window.removeEventListener('pageshow', restored);
		window.removeEventListener('resize', resize);
		window.removeEventListener('pagehide', dispose);
		$(document).off('shown.bs.collapse.pfbStats', expanded);
		if (retry) { retry.removeEventListener('click', load); }
	}

	picker.addEventListener('change', rangeChange);
	window.addEventListener('pageshow', restored);
	$(document).on('shown.bs.collapse.pfbStats', '.panel-body', expanded);
	window.addEventListener('resize', resize);
	window.addEventListener('pagehide', dispose);
	if (retry) { retry.addEventListener('click', load); }
	if (config.url) { load(); } else { accept(config.payload); }
}());
