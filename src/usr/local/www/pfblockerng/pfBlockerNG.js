/*
 * pfBlockerNG.js
 *
 * part of pfSense (https://www.pfsense.org)
 * Copyright (c) 2016-2026 Rubicon Communications, LLC (Netgate)
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

// Called by widget (Suppression/Whitelist href links) and CustomList anchors
// Scroll to page anchor and open collapsed window
window.onload = function() {
	if (location.hash) {
		var elId = location.hash.replace('#','');
		var scrollToEl = document.getElementById(elId);
		// A hash naming no element (bad/stale bookmark) must not crash onload (#714).
		if (scrollToEl) {
			scrollToEl.scrollIntoView(true);
		}

		// Toggle Collapsible window
		$("[id$='customlist_panel-body']").removeClass('out').addClass('in');
	}
}

// 'GeoIP ISOs'/ASNs Auto-Complete for Source (URL) field lookup
function pfb_autocomplete_function(input_type, destroy, pageload) {

	var rowid = input_type.attr('id').split('-')[1];
	var url_fld = '#url-' + rowid;
	var hdr_fld = '#header-' + rowid;

	if (input_type.val() == 'geoip') {

		// clear source field when clicking 'geoip' selectbox
		if (!pageload) {
			$(url_fld).val('');
			$(hdr_fld).val('');
		}

		$(url_fld).autocomplete( {
			minLength: 0,
			source: geoiparray,
			select: function(event,ui) {
					$(url_fld).val('');
					$(hdr_fld).val('');
				},
			change: function(event,ui) {
					if (ui.item == null) {
						$(url_fld).val('');
						$(hdr_fld).val('');
						$(url_fld).focus();
					}
					else {
						var header = ui.item.label.split(' ')[0];
						$(hdr_fld).val(header);
					}
			}
		})
	}

	else if (input_type.val() == 'asn') {

		$(url_fld).autocomplete( {
			minLength: 3,
			delay: 200,
			source: '/pfblockerng/pfblockerng_category_edit.php',
			select: function(event,ui) {
					$(url_fld).val('');
					$(hdr_fld).val('');
				},
			change: function(event,ui) {
					if (ui.item == null) {
						$(url_fld).val('');
						$(hdr_fld).val('');
						$(url_fld).focus();
					}
					else {
						var header = ui.item.label.split(' ')[0];
						$(hdr_fld).val(header);
					}
				}
		});
	}

	else if (destroy && $(url_fld).data('ui-autocomplete')) {
		$(url_fld).autocomplete('destroy');
		$(url_fld).removeData('autocomplete');
	}
}

// 'GeoIP ISOs'/ASNs Auto-Complete for Source (URL) field lookup
function pfb_autocomplete() {

	$("[id^='format-']").each(function() {
		pfb_autocomplete_function($(this), false, true);		// on page load

		$(this).click(function() {
			pfb_autocomplete_function($(this), true, false);	// on click
		})
	});
}


// Remove label columns that contain 'XXXX' (To gain full page width)
function pfb_remove_label() {
	$("label:contains('XXXX')").remove();
}


// Greyout 'Disabled' State fields
// Greyout selects whose value is 'Disabled' (live on change + on initial load).
function pfb_greyout(sel) {

	$(sel).click(function() {
		if ($(this).val() == 'Disabled') {
			$(this).css('background-color', 'lightgrey');
		} else {
			$(this).css('background-color', '');
		}
	});
	$(sel).each(function() {
		if ($(this).val() == 'Disabled') {
			$(this).css('background-color', 'lightgrey');
		}
	});
}

function pfb_chg_state_bkgd() {
	pfb_greyout("select[id^='state-']");
}

// ADR-63: shared drag+anchor-click reorder component. PRODUCTION-DORMANT --
// defining these functions is inert; no page calls pfb_reorder_init() yet.
// Row identity for anchor-click move logic is resolved via DOM traversal
// (closest()/find()), never by parsing an injected control's own id: core's
// add_row() (pfSenseHelpers.js) only renumbers <input>/<select>/[id^=deleterow],
// not a generic <button>, so an anchor button's own id can go briefly stale.
function pfb_reorder_init(container, rowSelector, onAfterMove, dragEnabled) {
	var $container = $(container);
	var anchorClass = 'pfb-reorder-anchor';
	var chkClass = 'pfb-reorder-chk';

	function fire() {
		if (typeof onAfterMove === 'function') {
			onAfterMove();
		}
	}

	$container.find(rowSelector).each(function(i) {
		if ($(this).find('.' + chkClass).length) {
			return;
		}
		$(this).append(
			'<span class="pfb-reorder-ctl">' +
			'<input type="checkbox" class="' + chkClass + '" id="pfb_reorder_chk-' + i + '">' +
			'<button type="button" class="' + anchorClass + '" id="pfb_reorder_anchor-' + i + '" ' +
			'title="Move checked entries before this row (shift-click: after)">&#8645;</button>' +
			'</span>'
		);
	});

	// Delegated (container-level): survives renumber()'s id/name rewrite of
	// per-row controls, unlike a per-element binding (ADR-63 S2 Decision 1).
	$container.off('click.pfb_reorder').on('click.pfb_reorder', '.' + anchorClass, function(e) {
		var anchorRow = $(this).closest(rowSelector);
		var rows = $container.find(rowSelector);
		var checked = rows.filter(function() {
			return $(this).find('.' + chkClass).is(':checked');
		}).not(anchorRow).toArray();

		// Preserve the checked rows' relative order: "before" walks top-to-bottom
		// inserting each just before the anchor; "after" walks bottom-to-top
		// inserting each just after it (reversing the walk keeps insertion order).
		if (e.shiftKey) {
			for (var i = checked.length - 1; i >= 0; i--) {
				$(checked[i]).insertAfter(anchorRow);
			}
		} else {
			for (var j = 0; j < checked.length; j++) {
				$(checked[j]).insertBefore(anchorRow);
			}
		}
		fire();
	});

	if (dragEnabled) {
		$container.sortable({
			items: rowSelector,
			cursor: 'move',
			distance: 10,
			opacity: 0.8,
			helper: function(e, ui) {
				ui.children().each(function() {
					$(this).width($(this).width());
				});
				return ui;
			},
			stop: fire
		});
	}
}

// Sortable-independent DOM-order read, byte-format-identical to
// $(container).sortable('serialize', {key:'ids[]'}) -- works even when
// .sortable() was never initialised (ADR-63 S1.8's serialize trap).
function pfb_reorder_read_order(container, rowSelector) {
	var parts = [];
	$(container).find(rowSelector).each(function() {
		var m = /(.+)[-=_](.+)/.exec(this.id);
		if (m) {
			parts.push('ids[]=' + encodeURIComponent(m[2]));
		}
	});
	return parts.join('&');
}


events.push(function() {

	// Disable the 'Row move anchor' when adding a new Feed or whole Alias/Group; until a config save
	if ((pagetype == 'dnsbl' || pagetype == 'advanced') && disable_move) {
		$('[name^=Lmove]').each(function () {
			$(this).prop('disabled', true);
			$(this).attr('title', 'Save changes before Row move allowed!');
		})
		$('[name^=Xmove]').each(function () {
			$(this).prop('disabled', true);
			$(this).attr('title', '');
		})
	}

	pfb_remove_label();

	// Greyout 'Disabled' Action fields
	pfb_greyout("select[id^='action']");

	// Greyout 'Disabled' State fields
	pfb_chg_state_bkgd();
	$('#addrow').click(function() {
		pfb_chg_state_bkgd();
	});

	// Change all 'state' fields to 'Enabled'
	$('#chgstate').click(function() {

		if (action.length > 0) {
			$('#act').val(action);
		}
		if (atype.length > 0) {
			$('#atype').val(atype);
		}
		$('#chgstate').val('Enable All');
	});

	if (pagetype == 'dnsbl') {

		$('#addrow').click(function() {
			$('.repeatable:last').find('sub').each(function() {
				$(this).append('&nbsp; ').text(Number($(this).text()) + 1 );
			});
			pfb_remove_label();
		})
	}
	else if (pagetype == 'advanced') {

		if (geoiparray != 'disabled') {
			pfb_autocomplete();
			$('#addrow').click(function() {
				pfb_autocomplete();

				$('.repeatable:last').find('sub').each(function() {
					$(this).append('&nbsp; ').text(Number($(this).text()) + 1 );
				});
				pfb_remove_label();
			})
		}

		// Lock user-input when Disabled
		function enable_change_port_in() {
			var endis = ! $('#autoports_in').prop('checked');
			document.getElementById('aliasports_in').disabled = endis;
		}
		function enable_change_port_out() {
			var endis = ! $('#autoports_out').prop('checked');
			document.getElementById('aliasports_out').disabled = endis;
		}

		function enable_change_in() {
			var endis = ! $('#autoaddr_in').prop('checked');
			document.getElementById('aliasaddr_in').disabled = endis;
			document.getElementById('autonot_in').disabled = endis;
		}
		function enable_change_out() {
			var endis = ! $('#autoaddr_out').prop('checked');
			document.getElementById('aliasaddr_out').disabled = endis;
			document.getElementById('autonot_out').disabled = endis;
		}

		$('#autoports_in').click(function() {
			enable_change_port_in();
		});
		$('#autoports_out').click(function() {
			enable_change_port_out();
		});

		$('#autoaddr_in').click(function() {
			enable_change_in();
		});
		$('#autoaddr_out').click(function() {
			enable_change_out();
		});

		enable_change_in();
		enable_change_out();
		enable_change_port_in();
		enable_change_port_out();

		// Auto-Complete for Adv. In/Out Ports Select boxes
		$('#aliasports_in').autocomplete( {
			source: portsarray
		})
		$('#aliasports_out').autocomplete( {
			source: portsarray
		})

		// Auto-Complete for Adv. In/Out Address Select boxes
		$('#aliasaddr_in').autocomplete( {
			source: networksarray
		})
		$('#aliasaddr_out').autocomplete( {
			source: networksarray
		})
	}
});
