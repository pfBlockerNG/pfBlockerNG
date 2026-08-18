#shellcheck shell=sh
# pfblockerng_repo_generate.sh — consented pkg.conf SSL_CA_CERT_PATH re-apply
# (issue #2518, "STEP B"). Sibling suite to generate_hook_spec.sh: that file pins
# the hook's original repo-conf regeneration job; this one pins its second job,
# added at boot because pfSense-repo-setup deletes and regenerates pkg.conf on
# upgrades and branch switches, wiping the SSL_CA_CERT_PATH line the PHP side
# appends on consent (#2515/#2516/#2518).
#
# Cross-language contract: tests/fixtures/pkg_conf/{plus_pinned,plus_patched,
# ce_unpinned}.conf are the SAME bytes the PHP appender's tests assert against —
# every content assertion here diffs against those fixtures (or a value derived
# from one via `sed`), never a hand-retyped heredoc, so the two implementations
# cannot silently drift apart.
#
# Consent lives in config.xml as the registered field pfb_pkg_ca_consent under
# installedpackages/pfblockerng/config/0 (what PfbConfig::read('gen/pfb_pkg_ca_consent')
# reads) as a DIRECT CHILD of the FIRST <config> block under <pfblockerng> --
# never nested under a <row> or any other wrapper, and never a later <config>
# row -- granted as the literal token `on` (case-insensitive: PfbToggle::
# fromLegacy() also accepts On/ON). `_pc_config_xml()` below builds exactly that
# production shape; a dedicated block of rows further down (issue #2518 B2)
# deliberately builds every WRONG shape a naive scan could be fooled by: nested
# one level deeper (A_row -- literally the shape this suite used to test before
# B2, which is why those old assertions were re-pointed), a same-named sibling
# field or later/second <config> row racing the scope search, and the three
# shapes PfbConfig reads as consent that this hook deliberately does NOT match
# (an attribute-carrying open tag, a CDATA value, the whole element collapsed
# onto one line) -- each pinned as a documented, bounded limitation rather than
# left silently untested.
#
# Tip: run with `shellspec tests/shell/generate_hook_pkgconf_spec.sh`.

HOOK="${PFB_ROOT}/scripts/rc.d/pfblockerng_repo_generate.sh"
FIX="${PFB_ROOT}/tests/fixtures/pkg_conf"

# ── helpers ───────────────────────────────────────────────────────────────────

# Stand up a temp box dir at $1 with none of the channel confs (keeps this suite
# independent from generate_hook_spec.sh's regeneration behaviour unless an
# example opts in) and no config.xml / pkg.conf yet — each example stages those.
_pc_box() {
    _pcb_dir="$1"
    mkdir -p "${_pcb_dir}"
    PFB_STABLE_CONF="${_pcb_dir}/pfblockerng-stable.conf"
    PFB_TESTING_CONF="${_pcb_dir}/pfblockerng-testing.conf"
    PFB_EDGE_CONF="${_pcb_dir}/pfblockerng-edge.conf"
    PFB_NIGHTLY_CONF="${_pcb_dir}/pfblockerng-nightly.conf"
    PFB_PRODUCT_LABEL="${_pcb_dir}/product_label"
    PFB_VERSION_FILE="${_pcb_dir}/version"
    printf 'pfSense\n' > "${PFB_PRODUCT_LABEL}"
    printf '2.8.1\n' > "${PFB_VERSION_FILE}"
    PFB_PKG_CONF="${_pcb_dir}/pkg.conf"
    PFB_CONFIG_XML="${_pcb_dir}/config.xml"
    export PFB_STABLE_CONF PFB_TESTING_CONF PFB_EDGE_CONF PFB_NIGHTLY_CONF \
           PFB_PRODUCT_LABEL PFB_VERSION_FILE PFB_PKG_CONF PFB_CONFIG_XML
    unset _pcb_dir
}

_pc_unset_box() {
    unset PFB_STABLE_CONF PFB_TESTING_CONF PFB_EDGE_CONF PFB_NIGHTLY_CONF \
          PFB_PRODUCT_LABEL PFB_VERSION_FILE PFB_PKG_CONF PFB_CONFIG_XML \
          PFB_SSL_CA_CERT_PATH
}

# Write a config.xml carrying the consent element with body $1 ("on" / "off" /
# "" / omitted entirely when $1 is "absent"), as a DIRECT CHILD of config/0 --
# the exact production shape (issue #2518 B2's "C_ok"; PfbConfig::read() never
# sees a <row> wrapper, so this helper stopped emitting one). The A_row/F/G/J/
# L/M/E/H/I rows further down build every OTHER shape by hand, on purpose.
_pc_config_xml() {
    _pcx_body="$1"
    case "${_pcx_body}" in
        absent)
            cat > "${PFB_CONFIG_XML}" <<'EOF'
<?xml version="1.0"?>
<pfsense>
	<installedpackages>
		<pfblockerng>
			<config>
				<other>1</other>
			</config>
		</pfblockerng>
	</installedpackages>
</pfsense>
EOF
            ;;
        *)
            cat > "${PFB_CONFIG_XML}" <<EOF
<?xml version="1.0"?>
<pfsense>
	<installedpackages>
		<pfblockerng>
			<config>
				<pfb_pkg_ca_consent>${_pcx_body}</pfb_pkg_ca_consent>
			</config>
		</pfblockerng>
	</installedpackages>
</pfsense>
EOF
            ;;
    esac
    unset _pcx_body
}

# A CA hash dir with exactly one entry, at $1.
_pc_ca_dir_with_entry() {
    mkdir -p "$1"
    true > "$1/dummy.0"
}

# ── CONSENT AXIS ────────────────────────────────────────────────────────────

Describe 'pkgconf re-apply — consent on (C_ok, the production shape): patches plus_pinned.conf to plus_patched.conf'
    setup() {
        _c1_dir="$(mktemp -d "${SHELLSPEC_TMPBASE:-/tmp}/pc_consent_on.XXXXXX")"
        _pc_box "${_c1_dir}"
        cp "${FIX}/plus_pinned.conf" "${PFB_PKG_CONF}"
        _pc_config_xml on
    }
    cleanup() { rm -rf "${_c1_dir}"; _pc_unset_box; }
    Before 'setup'
    After  'cleanup'

    It 'before-state: pkg.conf is the pinned fixture, no SSL_CA_CERT_PATH yet'
      The contents of file "${PFB_PKG_CONF}" should not include "SSL_CA_CERT_PATH"
      The value "$(cmp -s "${PFB_PKG_CONF}" "${FIX}/plus_pinned.conf" && echo 0 || echo 1)" should equal 0
    End

    It 'patches pkg.conf to be byte-identical to plus_patched.conf, exit 0'
      When run sh "${HOOK}" onestart
      The status should be success
      The stderr should include "INFO"
      The value "$(cmp -s "${PFB_PKG_CONF}" "${FIX}/plus_patched.conf" && echo 0 || echo 1)" should equal 0
    End
End

Describe 'pkgconf re-apply — consent element absent: pkg.conf byte-unchanged'
    setup() {
        _c2_dir="$(mktemp -d "${SHELLSPEC_TMPBASE:-/tmp}/pc_consent_absent.XXXXXX")"
        _pc_box "${_c2_dir}"
        cp "${FIX}/plus_pinned.conf" "${PFB_PKG_CONF}"
        _pc_config_xml absent
    }
    cleanup() { rm -rf "${_c2_dir}"; _pc_unset_box; }
    Before 'setup'
    After  'cleanup'

    It 'before-state: pkg.conf is the pinned fixture'
      The value "$(cmp -s "${PFB_PKG_CONF}" "${FIX}/plus_pinned.conf" && echo 0 || echo 1)" should equal 0
    End

    It 'leaves pkg.conf byte-unchanged, exit 0'
      When run sh "${HOOK}" onestart
      The status should be success
      The value "$(cmp -s "${PFB_PKG_CONF}" "${FIX}/plus_pinned.conf" && echo 0 || echo 1)" should equal 0
    End
End

Describe 'pkgconf re-apply — consent element present but empty: unchanged'
    setup() {
        _c3_dir="$(mktemp -d "${SHELLSPEC_TMPBASE:-/tmp}/pc_consent_empty.XXXXXX")"
        _pc_box "${_c3_dir}"
        cp "${FIX}/plus_pinned.conf" "${PFB_PKG_CONF}"
        _pc_config_xml ""
    }
    cleanup() { rm -rf "${_c3_dir}"; _pc_unset_box; }
    Before 'setup'
    After  'cleanup'

    It 'before-state: pkg.conf is the pinned fixture'
      The value "$(cmp -s "${PFB_PKG_CONF}" "${FIX}/plus_pinned.conf" && echo 0 || echo 1)" should equal 0
    End

    It 'leaves pkg.conf byte-unchanged, exit 0'
      When run sh "${HOOK}" onestart
      The status should be success
      The value "$(cmp -s "${PFB_PKG_CONF}" "${FIX}/plus_pinned.conf" && echo 0 || echo 1)" should equal 0
    End
End

Describe 'pkgconf re-apply — consent element present with off: unchanged'
    setup() {
        _c4_dir="$(mktemp -d "${SHELLSPEC_TMPBASE:-/tmp}/pc_consent_off.XXXXXX")"
        _pc_box "${_c4_dir}"
        cp "${FIX}/plus_pinned.conf" "${PFB_PKG_CONF}"
        _pc_config_xml off
    }
    cleanup() { rm -rf "${_c4_dir}"; _pc_unset_box; }
    Before 'setup'
    After  'cleanup'

    It 'before-state: pkg.conf is the pinned fixture'
      The value "$(cmp -s "${PFB_PKG_CONF}" "${FIX}/plus_pinned.conf" && echo 0 || echo 1)" should equal 0
    End

    It 'leaves pkg.conf byte-unchanged, exit 0'
      When run sh "${HOOK}" onestart
      The status should be success
      The value "$(cmp -s "${PFB_PKG_CONF}" "${FIX}/plus_pinned.conf" && echo 0 || echo 1)" should equal 0
    End
End

Describe 'pkgconf re-apply — config.xml missing entirely: unchanged, exit 0'
    setup() {
        _c5_dir="$(mktemp -d "${SHELLSPEC_TMPBASE:-/tmp}/pc_consent_noxml.XXXXXX")"
        _pc_box "${_c5_dir}"
        cp "${FIX}/plus_pinned.conf" "${PFB_PKG_CONF}"
        rm -f "${PFB_CONFIG_XML}"
    }
    cleanup() { rm -rf "${_c5_dir}"; _pc_unset_box; }
    Before 'setup'
    After  'cleanup'

    It 'before-state: config.xml does not exist'
      The path "${PFB_CONFIG_XML}" should not be exist
    End

    It 'leaves pkg.conf byte-unchanged, exit 0'
      When run sh "${HOOK}" onestart
      The status should be success
      The value "$(cmp -s "${PFB_PKG_CONF}" "${FIX}/plus_pinned.conf" && echo 0 || echo 1)" should equal 0
    End
End

Describe 'pkgconf re-apply — config.xml unreadable: unchanged, exit 0'
    setup() {
        _c6_dir="$(mktemp -d "${SHELLSPEC_TMPBASE:-/tmp}/pc_consent_unreadable.XXXXXX")"
        _pc_box "${_c6_dir}"
        cp "${FIX}/plus_pinned.conf" "${PFB_PKG_CONF}"
        _pc_config_xml on
        chmod 000 "${PFB_CONFIG_XML}"
    }
    cleanup() { chmod 600 "${PFB_CONFIG_XML}" 2>/dev/null; rm -rf "${_c6_dir}"; _pc_unset_box; }
    Before 'setup'
    After  'cleanup'

    It 'before-state: config.xml exists but is unreadable'
      The path "${PFB_CONFIG_XML}" should be exist
    End

    It 'leaves pkg.conf byte-unchanged, exit 0'
      When run sh "${HOOK}" onestart
      The status should be success
      The value "$(cmp -s "${PFB_PKG_CONF}" "${FIX}/plus_pinned.conf" && echo 0 || echo 1)" should equal 0
    End
End

# ── CONSENT SCOPING AXIS (issue #2518 F1) ────────────────────────────────────
# The gate is scoped to the FIRST <config> block inside the single
# <pfblockerng> element (exactly config/0, the path PfbConfig::read() reads)
# and matches the element as a WHOLE LINE. These rows pin the two ways an
# unscoped/substring gate would false-positive: an XML comment, and a second
# <config> row disagreeing with config/0.
#
# REPOINTED (issue #2518 B2): these three rows used to wrap the consent element
# in a <row>, same as the rest of this file before B2. That shape is ALSO
# rejected by the depth-1 fix below (it is exactly the A_row case), which would
# have made the "second <config> row" row below stop proving what its name
# says -- a row-wrapped element never matches regardless of which <config> it
# sits in, so "patches (scoped to config/0)" would have started failing for a
# reason unrelated to scoping. Rebuilt as direct children (the production
# shape) so each row again isolates exactly one axis.

Describe 'pkgconf re-apply — consent element inside a single-line XML comment: no patch'
    setup() {
        _f1_dir="$(mktemp -d "${SHELLSPEC_TMPBASE:-/tmp}/pc_f1_comment.XXXXXX")"
        _pc_box "${_f1_dir}"
        cp "${FIX}/plus_pinned.conf" "${PFB_PKG_CONF}"
        cat > "${PFB_CONFIG_XML}" <<'EOF'
<?xml version="1.0"?>
<pfsense>
	<installedpackages>
		<pfblockerng>
			<config>
				<!-- <pfb_pkg_ca_consent>on</pfb_pkg_ca_consent> -->
			</config>
		</pfblockerng>
	</installedpackages>
</pfsense>
EOF
    }
    cleanup() { rm -rf "${_f1_dir}"; _pc_unset_box; }
    Before 'setup'
    After  'cleanup'

    It 'before-state: pkg.conf is the pinned fixture'
      The value "$(cmp -s "${PFB_PKG_CONF}" "${FIX}/plus_pinned.conf" && echo 0 || echo 1)" should equal 0
    End

    It 'leaves pkg.conf byte-unchanged, exit 0'
      When run sh "${HOOK}" onestart
      The status should be success
      The value "$(cmp -s "${PFB_PKG_CONF}" "${FIX}/plus_pinned.conf" && echo 0 || echo 1)" should equal 0
    End
End

Describe 'pkgconf re-apply — config/0 says off, a second <config> block (config/1) says on: no patch (scoped to config/0)'
    setup() {
        _f2_dir="$(mktemp -d "${SHELLSPEC_TMPBASE:-/tmp}/pc_f1_second_on.XXXXXX")"
        _pc_box "${_f2_dir}"
        cp "${FIX}/plus_pinned.conf" "${PFB_PKG_CONF}"
        cat > "${PFB_CONFIG_XML}" <<'EOF'
<?xml version="1.0"?>
<pfsense>
	<installedpackages>
		<pfblockerng>
			<config>
				<pfb_pkg_ca_consent>off</pfb_pkg_ca_consent>
			</config>
			<config>
				<pfb_pkg_ca_consent>on</pfb_pkg_ca_consent>
			</config>
		</pfblockerng>
	</installedpackages>
</pfsense>
EOF
    }
    cleanup() { rm -rf "${_f2_dir}"; _pc_unset_box; }
    Before 'setup'
    After  'cleanup'

    It 'before-state: pkg.conf is the pinned fixture'
      The value "$(cmp -s "${PFB_PKG_CONF}" "${FIX}/plus_pinned.conf" && echo 0 || echo 1)" should equal 0
    End

    It 'leaves pkg.conf byte-unchanged, exit 0'
      When run sh "${HOOK}" onestart
      The status should be success
      The value "$(cmp -s "${PFB_PKG_CONF}" "${FIX}/plus_pinned.conf" && echo 0 || echo 1)" should equal 0
    End
End

Describe 'pkgconf re-apply — config/0 says on, a second <config> block (config/1) says off: patches (scoped to config/0)'
    setup() {
        _f3_dir="$(mktemp -d "${SHELLSPEC_TMPBASE:-/tmp}/pc_f1_second_off.XXXXXX")"
        _pc_box "${_f3_dir}"
        cp "${FIX}/plus_pinned.conf" "${PFB_PKG_CONF}"
        cat > "${PFB_CONFIG_XML}" <<'EOF'
<?xml version="1.0"?>
<pfsense>
	<installedpackages>
		<pfblockerng>
			<config>
				<pfb_pkg_ca_consent>on</pfb_pkg_ca_consent>
			</config>
			<config>
				<pfb_pkg_ca_consent>off</pfb_pkg_ca_consent>
			</config>
		</pfblockerng>
	</installedpackages>
</pfsense>
EOF
    }
    cleanup() { rm -rf "${_f3_dir}"; _pc_unset_box; }
    Before 'setup'
    After  'cleanup'

    It 'before-state: pkg.conf is the pinned fixture'
      The value "$(cmp -s "${PFB_PKG_CONF}" "${FIX}/plus_pinned.conf" && echo 0 || echo 1)" should equal 0
    End

    It 'patches pkg.conf to be byte-identical to plus_patched.conf, exit 0'
      When run sh "${HOOK}" onestart
      The status should be success
      The stderr should include "INFO"
      The value "$(cmp -s "${PFB_PKG_CONF}" "${FIX}/plus_patched.conf" && echo 0 || echo 1)" should equal 0
    End
End

# ── DEPTH AXIS (issue #2518 B2, "A_row") ─────────────────────────────────────
# PfbConfig::read() sees pfb_pkg_ca_consent ONLY as a direct child of config/0.
# The gate used to be depth-blind (it matched the element at ANY nesting depth
# inside the scoped <config> block) -- this is literally the shape every row
# above used to test before B2 (see the REPOINTED note above): a real box that
# somehow got the element wrapped one level deeper would have its "no" silently
# read as "yes" by the shell hook while PfbConfig kept reading NULL/off.

Describe 'pkgconf re-apply — A_row: consent nested one level under <row> inside config/0: no patch'
    setup() {
        _dep1_dir="$(mktemp -d "${SHELLSPEC_TMPBASE:-/tmp}/pc_depth_row.XXXXXX")"
        _pc_box "${_dep1_dir}"
        cp "${FIX}/plus_pinned.conf" "${PFB_PKG_CONF}"
        cat > "${PFB_CONFIG_XML}" <<'EOF'
<?xml version="1.0"?>
<pfsense>
	<installedpackages>
		<pfblockerng>
			<config>
				<row>
					<pfb_pkg_ca_consent>on</pfb_pkg_ca_consent>
				</row>
			</config>
		</pfblockerng>
	</installedpackages>
</pfsense>
EOF
    }
    cleanup() { rm -rf "${_dep1_dir}"; _pc_unset_box; }
    Before 'setup'
    After  'cleanup'

    It 'before-state: pkg.conf is the pinned fixture'
      The value "$(cmp -s "${PFB_PKG_CONF}" "${FIX}/plus_pinned.conf" && echo 0 || echo 1)" should equal 0
    End

    It 'leaves pkg.conf byte-unchanged, exit 0 (PfbConfig reads config/0 as a DIRECT child -- <row> is not that path, so raw is NULL/off)'
      When run sh "${HOOK}" onestart
      The status should be success
      The value "$(cmp -s "${PFB_PKG_CONF}" "${FIX}/plus_pinned.conf" && echo 0 || echo 1)" should equal 0
    End
End

# ── LATCH AXIS (issue #2518 B2, "F/G/J/L/M") ─────────────────────────────────
# The gate used to `next` past a line opening <pfblockerng>/<config> WITHOUT
# checking whether that same line also closes it -- so in_pb/in_cfg latched
# open to EOF whenever the open and close landed on one line (a self-closed
# <pfblockerng></pfblockerng> or <config></config>, or the whole element
# collapsed onto one line). Every row below is a shape where that latch let a
# LATER, unrelated <config> block's own field read as config/0's consent, even
# though config/0 itself carries no consent (or an empty one). Each one is
# reproduced against a distinct way the open+close can land on one line.

Describe 'pkgconf re-apply — F_emptycfg: config/0 is <config></config>, consent lives only in config/1: no patch'
    setup() {
        _lat1_dir="$(mktemp -d "${SHELLSPEC_TMPBASE:-/tmp}/pc_latch_emptycfg.XXXXXX")"
        _pc_box "${_lat1_dir}"
        cp "${FIX}/plus_pinned.conf" "${PFB_PKG_CONF}"
        cat > "${PFB_CONFIG_XML}" <<'EOF'
<?xml version="1.0"?>
<pfsense>
	<installedpackages>
		<pfblockerng>
			<config></config>
			<config>
				<pfb_pkg_ca_consent>on</pfb_pkg_ca_consent>
			</config>
		</pfblockerng>
	</installedpackages>
</pfsense>
EOF
    }
    cleanup() { rm -rf "${_lat1_dir}"; _pc_unset_box; }
    Before 'setup'
    After  'cleanup'

    It 'before-state: pkg.conf is the pinned fixture'
      The value "$(cmp -s "${PFB_PKG_CONF}" "${FIX}/plus_pinned.conf" && echo 0 || echo 1)" should equal 0
    End

    It 'leaves pkg.conf byte-unchanged, exit 0 (config/0 is the empty FIRST <config>; the 2nd is config/1, never read)'
      When run sh "${HOOK}" onestart
      The status should be success
      The value "$(cmp -s "${PFB_PKG_CONF}" "${FIX}/plus_pinned.conf" && echo 0 || echo 1)" should equal 0
    End
End

Describe 'pkgconf re-apply — G_sibling: another packages field literally named <pfblockerng> precedes the real block: no patch'
    setup() {
        _lat2_dir="$(mktemp -d "${SHELLSPEC_TMPBASE:-/tmp}/pc_latch_sibling.XXXXXX")"
        _pc_box "${_lat2_dir}"
        cp "${FIX}/plus_pinned.conf" "${PFB_PKG_CONF}"
        cat > "${PFB_CONFIG_XML}" <<'EOF'
<?xml version="1.0"?>
<pfsense>
	<installedpackages>
		<someotherpkg>
			<pfblockerng>yes</pfblockerng>
			<config>
				<pfb_pkg_ca_consent>on</pfb_pkg_ca_consent>
			</config>
		</someotherpkg>
		<pfblockerng>
			<config>
				<other>1</other>
			</config>
		</pfblockerng>
	</installedpackages>
</pfsense>
EOF
    }
    cleanup() { rm -rf "${_lat2_dir}"; _pc_unset_box; }
    Before 'setup'
    After  'cleanup'

    It 'before-state: pkg.conf is the pinned fixture'
      The value "$(cmp -s "${PFB_PKG_CONF}" "${FIX}/plus_pinned.conf" && echo 0 || echo 1)" should equal 0
    End

    It 'leaves pkg.conf byte-unchanged, exit 0 (the real pfblockerng config/0 carries no consent element at all)'
      When run sh "${HOOK}" onestart
      The status should be success
      The value "$(cmp -s "${PFB_PKG_CONF}" "${FIX}/plus_pinned.conf" && echo 0 || echo 1)" should equal 0
    End
End

Describe 'pkgconf re-apply — J_emptypb: <pfblockerng></pfblockerng> self-closed, consent only in an unrelated package: no patch'
    setup() {
        _lat3_dir="$(mktemp -d "${SHELLSPEC_TMPBASE:-/tmp}/pc_latch_emptypb.XXXXXX")"
        _pc_box "${_lat3_dir}"
        cp "${FIX}/plus_pinned.conf" "${PFB_PKG_CONF}"
        cat > "${PFB_CONFIG_XML}" <<'EOF'
<?xml version="1.0"?>
<pfsense>
	<installedpackages>
		<pfblockerng></pfblockerng>
		<someotherpkg>
			<config>
				<pfb_pkg_ca_consent>on</pfb_pkg_ca_consent>
			</config>
		</someotherpkg>
	</installedpackages>
</pfsense>
EOF
    }
    cleanup() { rm -rf "${_lat3_dir}"; _pc_unset_box; }
    Before 'setup'
    After  'cleanup'

    It 'before-state: pkg.conf is the pinned fixture'
      The value "$(cmp -s "${PFB_PKG_CONF}" "${FIX}/plus_pinned.conf" && echo 0 || echo 1)" should equal 0
    End

    It 'leaves pkg.conf byte-unchanged, exit 0 (pfblockerng carries no <config> at all)'
      When run sh "${HOOK}" onestart
      The status should be success
      The value "$(cmp -s "${PFB_PKG_CONF}" "${FIX}/plus_pinned.conf" && echo 0 || echo 1)" should equal 0
    End
End

Describe 'pkgconf re-apply — L_inline: <pfblockerng><enable_cb>on</enable_cb></pfblockerng> on one line, consent only in an unrelated package: no patch'
    setup() {
        _lat4_dir="$(mktemp -d "${SHELLSPEC_TMPBASE:-/tmp}/pc_latch_inline.XXXXXX")"
        _pc_box "${_lat4_dir}"
        cp "${FIX}/plus_pinned.conf" "${PFB_PKG_CONF}"
        cat > "${PFB_CONFIG_XML}" <<'EOF'
<?xml version="1.0"?>
<pfsense>
	<installedpackages>
		<pfblockerng><enable_cb>on</enable_cb></pfblockerng>
		<someotherpkg>
			<config>
				<pfb_pkg_ca_consent>on</pfb_pkg_ca_consent>
			</config>
		</someotherpkg>
	</installedpackages>
</pfsense>
EOF
    }
    cleanup() { rm -rf "${_lat4_dir}"; _pc_unset_box; }
    Before 'setup'
    After  'cleanup'

    It 'before-state: pkg.conf is the pinned fixture'
      The value "$(cmp -s "${PFB_PKG_CONF}" "${FIX}/plus_pinned.conf" && echo 0 || echo 1)" should equal 0
    End

    It 'leaves pkg.conf byte-unchanged, exit 0 (the whole pfblockerng element opens and closes on its own line)'
      When run sh "${HOOK}" onestart
      The status should be success
      The value "$(cmp -s "${PFB_PKG_CONF}" "${FIX}/plus_pinned.conf" && echo 0 || echo 1)" should equal 0
    End
End

Describe 'pkgconf re-apply — M_emptycfg_other: pfblockerng config/0 is <config></config>, consent in a sibling packages config: no patch'
    setup() {
        _lat5_dir="$(mktemp -d "${SHELLSPEC_TMPBASE:-/tmp}/pc_latch_emptycfg_other.XXXXXX")"
        _pc_box "${_lat5_dir}"
        cp "${FIX}/plus_pinned.conf" "${PFB_PKG_CONF}"
        cat > "${PFB_CONFIG_XML}" <<'EOF'
<?xml version="1.0"?>
<pfsense>
	<installedpackages>
		<pfblockerng>
			<config></config>
		</pfblockerng>
		<someotherpkg>
			<config>
				<pfb_pkg_ca_consent>on</pfb_pkg_ca_consent>
			</config>
		</someotherpkg>
	</installedpackages>
</pfsense>
EOF
    }
    cleanup() { rm -rf "${_lat5_dir}"; _pc_unset_box; }
    Before 'setup'
    After  'cleanup'

    It 'before-state: pkg.conf is the pinned fixture'
      The value "$(cmp -s "${PFB_PKG_CONF}" "${FIX}/plus_pinned.conf" && echo 0 || echo 1)" should equal 0
    End

    It 'leaves pkg.conf byte-unchanged, exit 0 (pfblockerng config/0 is empty; the sibling package is a different subtree)'
      When run sh "${HOOK}" onestart
      The status should be success
      The value "$(cmp -s "${PFB_PKG_CONF}" "${FIX}/plus_pinned.conf" && echo 0 || echo 1)" should equal 0
    End
End

# ── CASE-INSENSITIVE CONSENT AXIS (issue #2518 nitpick N-case-token) ────────
# PfbToggle::fromLegacy() accepts On/ON in any case (HA sync, restored backups,
# hand edits); the awk used to match only the lowercase literal "on".

Describe 'pkgconf re-apply — consent value "On" (mixed case): patches'
    setup() {
        _ci1_dir="$(mktemp -d "${SHELLSPEC_TMPBASE:-/tmp}/pc_case_mixed.XXXXXX")"
        _pc_box "${_ci1_dir}"
        cp "${FIX}/plus_pinned.conf" "${PFB_PKG_CONF}"
        _pc_config_xml On
    }
    cleanup() { rm -rf "${_ci1_dir}"; _pc_unset_box; }
    Before 'setup'
    After  'cleanup'

    It 'before-state: pkg.conf is the pinned fixture'
      The value "$(cmp -s "${PFB_PKG_CONF}" "${FIX}/plus_pinned.conf" && echo 0 || echo 1)" should equal 0
    End

    It 'patches pkg.conf to be byte-identical to plus_patched.conf, exit 0'
      When run sh "${HOOK}" onestart
      The status should be success
      The stderr should include "INFO"
      The value "$(cmp -s "${PFB_PKG_CONF}" "${FIX}/plus_patched.conf" && echo 0 || echo 1)" should equal 0
    End
End

Describe 'pkgconf re-apply — consent value "ON" (upper case): patches'
    setup() {
        _ci2_dir="$(mktemp -d "${SHELLSPEC_TMPBASE:-/tmp}/pc_case_upper.XXXXXX")"
        _pc_box "${_ci2_dir}"
        cp "${FIX}/plus_pinned.conf" "${PFB_PKG_CONF}"
        _pc_config_xml ON
    }
    cleanup() { rm -rf "${_ci2_dir}"; _pc_unset_box; }
    Before 'setup'
    After  'cleanup'

    It 'before-state: pkg.conf is the pinned fixture'
      The value "$(cmp -s "${PFB_PKG_CONF}" "${FIX}/plus_pinned.conf" && echo 0 || echo 1)" should equal 0
    End

    It 'patches pkg.conf to be byte-identical to plus_patched.conf, exit 0'
      When run sh "${HOOK}" onestart
      The status should be success
      The stderr should include "INFO"
      The value "$(cmp -s "${PFB_PKG_CONF}" "${FIX}/plus_patched.conf" && echo 0 || echo 1)" should equal 0
    End
End

# ── DOCUMENTED LIMITATIONS AXIS (issue #2518 B2, "E/H/I") ────────────────────
# PfbConfig reads all three of these shapes as consent (SimpleXML/config parsing
# decodes attributes, CDATA, and whitespace collapsing uniformly); this hook
# deliberately does NOT match any of them -- matching them in POSIX sh text
# scanning is disproportionate to how pfSense's own config writer actually
# serialises (verified against a live config.xml: none of these three shapes
# occur there). Each is a BOUNDED miss: the boot re-apply is skipped, but the
# cron tick (pfb_pkgconf_ca_tick(), synchronous with every PHP-side write) still
# re-applies on that box. Pinned here so the gap stays a documented, deliberate
# choice instead of silent, untested behaviour.

Describe 'pkgconf re-apply — E_attr: <pfblockerng version="1.0"> carries an XML attribute: documented limitation, no patch'
    setup() {
        _lim1_dir="$(mktemp -d "${SHELLSPEC_TMPBASE:-/tmp}/pc_limit_attr.XXXXXX")"
        _pc_box "${_lim1_dir}"
        cp "${FIX}/plus_pinned.conf" "${PFB_PKG_CONF}"
        cat > "${PFB_CONFIG_XML}" <<'EOF'
<?xml version="1.0"?>
<pfsense>
	<installedpackages>
		<pfblockerng version="1.0">
			<config>
				<pfb_pkg_ca_consent>on</pfb_pkg_ca_consent>
			</config>
		</pfblockerng>
	</installedpackages>
</pfsense>
EOF
    }
    cleanup() { rm -rf "${_lim1_dir}"; _pc_unset_box; }
    Before 'setup'
    After  'cleanup'

    It 'before-state: pkg.conf is the pinned fixture'
      The value "$(cmp -s "${PFB_PKG_CONF}" "${FIX}/plus_pinned.conf" && echo 0 || echo 1)" should equal 0
    End

    It 'leaves pkg.conf byte-unchanged, exit 0 -- PfbConfig reads "on" here; the boot hook does not, by design (cron still re-applies)'
      When run sh "${HOOK}" onestart
      The status should be success
      The value "$(cmp -s "${PFB_PKG_CONF}" "${FIX}/plus_pinned.conf" && echo 0 || echo 1)" should equal 0
    End
End

Describe 'pkgconf re-apply — H_cdata: CDATA-wrapped consent value: documented limitation, no patch'
    setup() {
        _lim2_dir="$(mktemp -d "${SHELLSPEC_TMPBASE:-/tmp}/pc_limit_cdata.XXXXXX")"
        _pc_box "${_lim2_dir}"
        cp "${FIX}/plus_pinned.conf" "${PFB_PKG_CONF}"
        cat > "${PFB_CONFIG_XML}" <<'EOF'
<?xml version="1.0"?>
<pfsense>
	<installedpackages>
		<pfblockerng>
			<config>
				<pfb_pkg_ca_consent><![CDATA[on]]></pfb_pkg_ca_consent>
			</config>
		</pfblockerng>
	</installedpackages>
</pfsense>
EOF
    }
    cleanup() { rm -rf "${_lim2_dir}"; _pc_unset_box; }
    Before 'setup'
    After  'cleanup'

    It 'before-state: pkg.conf is the pinned fixture'
      The value "$(cmp -s "${PFB_PKG_CONF}" "${FIX}/plus_pinned.conf" && echo 0 || echo 1)" should equal 0
    End

    It 'leaves pkg.conf byte-unchanged, exit 0 -- PfbConfig reads "on" here; the boot hook does not, by design (cron still re-applies)'
      When run sh "${HOOK}" onestart
      The status should be success
      The value "$(cmp -s "${PFB_PKG_CONF}" "${FIX}/plus_pinned.conf" && echo 0 || echo 1)" should equal 0
    End
End

Describe 'pkgconf re-apply — I_oneline: the whole pfblockerng/config/consent element collapsed onto one line: documented limitation, no patch'
    setup() {
        _lim3_dir="$(mktemp -d "${SHELLSPEC_TMPBASE:-/tmp}/pc_limit_oneline.XXXXXX")"
        _pc_box "${_lim3_dir}"
        cp "${FIX}/plus_pinned.conf" "${PFB_PKG_CONF}"
        cat > "${PFB_CONFIG_XML}" <<'EOF'
<?xml version="1.0"?>
<pfsense>
	<installedpackages>
		<pfblockerng><config><pfb_pkg_ca_consent>on</pfb_pkg_ca_consent></config></pfblockerng>
	</installedpackages>
</pfsense>
EOF
    }
    cleanup() { rm -rf "${_lim3_dir}"; _pc_unset_box; }
    Before 'setup'
    After  'cleanup'

    It 'before-state: pkg.conf is the pinned fixture'
      The value "$(cmp -s "${PFB_PKG_CONF}" "${FIX}/plus_pinned.conf" && echo 0 || echo 1)" should equal 0
    End

    It 'leaves pkg.conf byte-unchanged, exit 0 -- PfbConfig reads "on" here; the boot hook does not, by design (cron still re-applies)'
      When run sh "${HOOK}" onestart
      The status should be success
      The value "$(cmp -s "${PFB_PKG_CONF}" "${FIX}/plus_pinned.conf" && echo 0 || echo 1)" should equal 0
    End
End

# ── TARGET-FILE AXIS (consent on throughout) ─────────────────────────────────

Describe 'pkgconf re-apply — ce_unpinned.conf (no PKG_ENV block): unchanged'
    setup() {
        _t1_dir="$(mktemp -d "${SHELLSPEC_TMPBASE:-/tmp}/pc_target_ce.XXXXXX")"
        _pc_box "${_t1_dir}"
        cp "${FIX}/ce_unpinned.conf" "${PFB_PKG_CONF}"
        _pc_config_xml on
    }
    cleanup() { rm -rf "${_t1_dir}"; _pc_unset_box; }
    Before 'setup'
    After  'cleanup'

    It 'before-state: pkg.conf is the CE unpinned fixture'
      The value "$(cmp -s "${PFB_PKG_CONF}" "${FIX}/ce_unpinned.conf" && echo 0 || echo 1)" should equal 0
    End

    It 'leaves pkg.conf byte-unchanged, exit 0'
      When run sh "${HOOK}" onestart
      The status should be success
      The value "$(cmp -s "${PFB_PKG_CONF}" "${FIX}/ce_unpinned.conf" && echo 0 || echo 1)" should equal 0
    End
End

Describe 'pkgconf re-apply — plus_patched.conf (already carries the line): idempotent'
    setup() {
        _t2_dir="$(mktemp -d "${SHELLSPEC_TMPBASE:-/tmp}/pc_target_patched.XXXXXX")"
        _pc_box "${_t2_dir}"
        cp "${FIX}/plus_patched.conf" "${PFB_PKG_CONF}"
        _pc_config_xml on
    }
    cleanup() { rm -rf "${_t2_dir}"; _pc_unset_box; }
    Before 'setup'
    After  'cleanup'

    It 'before-state: pkg.conf already carries SSL_CA_CERT_PATH'
      The contents of file "${PFB_PKG_CONF}" should include "SSL_CA_CERT_PATH"
    End

    It 'leaves pkg.conf byte-unchanged, exit 0'
      When run sh "${HOOK}" onestart
      The status should be success
      The value "$(cmp -s "${PFB_PKG_CONF}" "${FIX}/plus_patched.conf" && echo 0 || echo 1)" should equal 0
    End
End

# issue #2518 F2: this row pins "the hook never conjures a file that was never
# there", but it does NOT by itself pin the -h/-f guards -- verified live by
# running a copy of the hook with both guards deleted against this exact
# scenario: it still leaves no file behind, because the shape-guard reads
# further down (grep/grep -c/sed against a nonexistent PFB_PKG_CONF) all fail
# closed on their own. The -h guard's necessity is what the symlink row below
# actually exercises (without it, a matching-shape symlink target would get
# replaced by the tmp+mv patch, detaching the link); no row here isolates -f
# specifically, and none is added for it -- restructuring the hook only to make
# that guard independently observable would test the test, not the hook.
Describe 'pkgconf re-apply — pkg.conf absent: no file conjured, exit 0'
    setup() {
        _t3_dir="$(mktemp -d "${SHELLSPEC_TMPBASE:-/tmp}/pc_target_absent.XXXXXX")"
        _pc_box "${_t3_dir}"
        _pc_config_xml on
    }
    cleanup() { rm -rf "${_t3_dir}"; _pc_unset_box; }
    Before 'setup'
    After  'cleanup'

    It 'before-state: pkg.conf does not exist'
      The path "${PFB_PKG_CONF}" should not be exist
    End

    It 'still does not exist afterward, exit 0'
      When run sh "${HOOK}" onestart
      The status should be success
      The path "${PFB_PKG_CONF}" should not be exist
    End
End

Describe 'pkgconf re-apply — pkg.conf is a symlink: link intact, target unchanged'
    setup() {
        _t4_dir="$(mktemp -d "${SHELLSPEC_TMPBASE:-/tmp}/pc_target_symlink.XXXXXX")"
        _pc_box "${_t4_dir}"
        _t4_real="${_t4_dir}/real-pkg.conf"
        cp "${FIX}/plus_pinned.conf" "${_t4_real}"
        ln -s "${_t4_real}" "${PFB_PKG_CONF}"
        _pc_config_xml on
    }
    cleanup() { rm -rf "${_t4_dir}"; _pc_unset_box; unset _t4_real; }
    Before 'setup'
    After  'cleanup'

    It 'before-state: pkg.conf is a symlink to the pinned fixture'
      The path "${PFB_PKG_CONF}" should be symlink
      The value "$(cmp -s "${_t4_real}" "${FIX}/plus_pinned.conf" && echo 0 || echo 1)" should equal 0
    End

    It 'leaves the link and its target byte-unchanged, exit 0'
      When run sh "${HOOK}" onestart
      The status should be success
      The path "${PFB_PKG_CONF}" should be symlink
      The value "$(cmp -s "${_t4_real}" "${FIX}/plus_pinned.conf" && echo 0 || echo 1)" should equal 0
    End
End

Describe 'pkgconf re-apply — pkg.conf is a directory: no write, exit 0'
    setup() {
        _t5_dir="$(mktemp -d "${SHELLSPEC_TMPBASE:-/tmp}/pc_target_dir.XXXXXX")"
        _pc_box "${_t5_dir}"
        rm -f "${PFB_PKG_CONF}"
        mkdir -p "${PFB_PKG_CONF}"
        _pc_config_xml on
    }
    cleanup() { rm -rf "${_t5_dir}"; _pc_unset_box; }
    Before 'setup'
    After  'cleanup'

    It 'before-state: pkg.conf path is a directory'
      The path "${PFB_PKG_CONF}" should be directory
    End

    It 'stays a directory, exit 0'
      When run sh "${HOOK}" onestart
      The status should be success
      The path "${PFB_PKG_CONF}" should be directory
    End
End

Describe 'pkgconf re-apply — running the hook twice is idempotent end to end'
    setup() {
        _t6_dir="$(mktemp -d "${SHELLSPEC_TMPBASE:-/tmp}/pc_target_twice.XXXXXX")"
        _pc_box "${_t6_dir}"
        cp "${FIX}/plus_pinned.conf" "${PFB_PKG_CONF}"
        _pc_config_xml on
    }
    cleanup() { rm -rf "${_t6_dir}"; _pc_unset_box; }
    Before 'setup'
    After  'cleanup'

    It 'before-state: pkg.conf is the pinned fixture'
      The value "$(cmp -s "${PFB_PKG_CONF}" "${FIX}/plus_pinned.conf" && echo 0 || echo 1)" should equal 0
    End

    It 'the second run is identical to the first, both match plus_patched.conf'
      When run sh -c 'sh "${1}" onestart >/dev/null 2>&1; sh "${1}" onestart' -- "${HOOK}"
      The status should be success
      The value "$(cmp -s "${PFB_PKG_CONF}" "${FIX}/plus_patched.conf" && echo 0 || echo 1)" should equal 0
    End
End

# ── SHAPE-GUARD AXIS (consent on, all -> unchanged) ──────────────────────────

Describe 'pkgconf re-apply — two PKG_ENV blocks: unchanged'
    setup() {
        _s1_dir="$(mktemp -d "${SHELLSPEC_TMPBASE:-/tmp}/pc_shape_twoblocks.XXXXXX")"
        _pc_box "${_s1_dir}"
        cat "${FIX}/plus_pinned.conf" > "${PFB_PKG_CONF}"
        cat "${FIX}/plus_pinned.conf" | tail -n +3 >> "${PFB_PKG_CONF}"
        _pc_config_xml on
        _s1_sum="$(cksum < "${PFB_PKG_CONF}")"
    }
    cleanup() { rm -rf "${_s1_dir}"; _pc_unset_box; unset _s1_sum; }
    Before 'setup'
    After  'cleanup'

    It 'before-state: pkg.conf carries two PKG_ENV { openers'
      The value "$(grep -c '^PKG_ENV {$' "${PFB_PKG_CONF}")" should equal 2
    End

    It 'leaves pkg.conf byte-unchanged, exit 0'
      When run sh "${HOOK}" onestart
      The status should be success
      The value "$(cksum < "${PFB_PKG_CONF}")" should equal "${_s1_sum}"
    End
End

Describe 'pkgconf re-apply — PKG_ENV { with no closing }: unchanged'
    setup() {
        _s2_dir="$(mktemp -d "${SHELLSPEC_TMPBASE:-/tmp}/pc_shape_noclose.XXXXXX")"
        _pc_box "${_s2_dir}"
        cat > "${PFB_PKG_CONF}" <<'EOF'
ABI=FreeBSD:16:amd64
PKG_ENV {
	SSL_CA_CERT_FILE=/etc/ssl/netgate-ca.pem
EOF
        _pc_config_xml on
        _s2_sum="$(cksum < "${PFB_PKG_CONF}")"
    }
    cleanup() { rm -rf "${_s2_dir}"; _pc_unset_box; unset _s2_sum; }
    Before 'setup'
    After  'cleanup'

    It 'before-state: pkg.conf has no closing brace'
      The contents of file "${PFB_PKG_CONF}" should not include "}"
    End

    It 'leaves pkg.conf byte-unchanged, exit 0'
      When run sh "${HOOK}" onestart
      The status should be success
      The value "$(cksum < "${PFB_PKG_CONF}")" should equal "${_s2_sum}"
    End
End

Describe 'pkgconf re-apply — block with no SSL_CA_CERT_FILE= line: unchanged'
    setup() {
        _s3_dir="$(mktemp -d "${SHELLSPEC_TMPBASE:-/tmp}/pc_shape_nofile.XXXXXX")"
        _pc_box "${_s3_dir}"
        cat > "${PFB_PKG_CONF}" <<'EOF'
ABI=FreeBSD:16:amd64
PKG_ENV {
	SSL_CLIENT_CERT_FILE=/x/cert.pem
}
EOF
        _pc_config_xml on
        _s3_sum="$(cksum < "${PFB_PKG_CONF}")"
    }
    cleanup() { rm -rf "${_s3_dir}"; _pc_unset_box; unset _s3_sum; }
    Before 'setup'
    After  'cleanup'

    It 'before-state: the block carries no SSL_CA_CERT_FILE= line'
      The contents of file "${PFB_PKG_CONF}" should not include "SSL_CA_CERT_FILE"
    End

    It 'leaves pkg.conf byte-unchanged, exit 0'
      When run sh "${HOOK}" onestart
      The status should be success
      The value "$(cksum < "${PFB_PKG_CONF}")" should equal "${_s3_sum}"
    End
End

Describe 'pkgconf re-apply — SSL_CA_CERT_PATH already present at top level: unchanged'
    setup() {
        _s4_dir="$(mktemp -d "${SHELLSPEC_TMPBASE:-/tmp}/pc_shape_toplevelpath.XXXXXX")"
        _pc_box "${_s4_dir}"
        cat > "${PFB_PKG_CONF}" <<'EOF'
SSL_CA_CERT_PATH=/some/other/dir
ABI=FreeBSD:16:amd64
PKG_ENV {
	SSL_CA_CERT_FILE=/etc/ssl/netgate-ca.pem
}
EOF
        _pc_config_xml on
        _s4_sum="$(cksum < "${PFB_PKG_CONF}")"
    }
    cleanup() { rm -rf "${_s4_dir}"; _pc_unset_box; unset _s4_sum; }
    Before 'setup'
    After  'cleanup'

    It 'before-state: SSL_CA_CERT_PATH already appears outside the block'
      The contents of file "${PFB_PKG_CONF}" should include "SSL_CA_CERT_PATH=/some/other/dir"
    End

    It 'leaves pkg.conf byte-unchanged, exit 0'
      When run sh "${HOOK}" onestart
      The status should be success
      The value "$(cksum < "${PFB_PKG_CONF}")" should equal "${_s4_sum}"
    End
End

Describe 'pkgconf re-apply — single-line PKG_ENV form: unchanged'
    setup() {
        _s5_dir="$(mktemp -d "${SHELLSPEC_TMPBASE:-/tmp}/pc_shape_singleline.XXXXXX")"
        _pc_box "${_s5_dir}"
        printf 'PKG_ENV { SSL_CA_CERT_FILE=/x }\n' > "${PFB_PKG_CONF}"
        _pc_config_xml on
        _s5_sum="$(cksum < "${PFB_PKG_CONF}")"
    }
    cleanup() { rm -rf "${_s5_dir}"; _pc_unset_box; unset _s5_sum; }
    Before 'setup'
    After  'cleanup'

    It 'before-state: pkg.conf is the single-line form'
      The contents of file "${PFB_PKG_CONF}" should include "PKG_ENV { SSL_CA_CERT_FILE=/x }"
    End

    It 'leaves pkg.conf byte-unchanged, exit 0'
      When run sh "${HOOK}" onestart
      The status should be success
      The value "$(cksum < "${PFB_PKG_CONF}")" should equal "${_s5_sum}"
    End
End

Describe 'pkgconf re-apply — indented "  PKG_ENV {": unchanged'
    setup() {
        _s6_dir="$(mktemp -d "${SHELLSPEC_TMPBASE:-/tmp}/pc_shape_indented.XXXXXX")"
        _pc_box "${_s6_dir}"
        cat > "${PFB_PKG_CONF}" <<'EOF'
ABI=FreeBSD:16:amd64
  PKG_ENV {
	SSL_CA_CERT_FILE=/etc/ssl/netgate-ca.pem
  }
EOF
        _pc_config_xml on
        _s6_sum="$(cksum < "${PFB_PKG_CONF}")"
    }
    cleanup() { rm -rf "${_s6_dir}"; _pc_unset_box; unset _s6_sum; }
    Before 'setup'
    After  'cleanup'

    It 'before-state: PKG_ENV { is indented, not at column 0'
      The contents of file "${PFB_PKG_CONF}" should include "  PKG_ENV {"
    End

    It 'leaves pkg.conf byte-unchanged, exit 0'
      When run sh "${HOOK}" onestart
      The status should be success
      The value "$(cksum < "${PFB_PKG_CONF}")" should equal "${_s6_sum}"
    End
End

Describe 'pkgconf re-apply — commented-out "#PKG_ENV {": unchanged'
    setup() {
        _s7_dir="$(mktemp -d "${SHELLSPEC_TMPBASE:-/tmp}/pc_shape_commented.XXXXXX")"
        _pc_box "${_s7_dir}"
        cat > "${PFB_PKG_CONF}" <<'EOF'
ABI=FreeBSD:16:amd64
#PKG_ENV {
#	SSL_CA_CERT_FILE=/etc/ssl/netgate-ca.pem
#}
EOF
        _pc_config_xml on
        _s7_sum="$(cksum < "${PFB_PKG_CONF}")"
    }
    cleanup() { rm -rf "${_s7_dir}"; _pc_unset_box; unset _s7_sum; }
    Before 'setup'
    After  'cleanup'

    It 'before-state: PKG_ENV { is commented out'
      The contents of file "${PFB_PKG_CONF}" should include "#PKG_ENV {"
    End

    It 'leaves pkg.conf byte-unchanged, exit 0'
      When run sh "${HOOK}" onestart
      The status should be success
      The value "$(cksum < "${PFB_PKG_CONF}")" should equal "${_s7_sum}"
    End
End

Describe 'pkgconf re-apply — CRLF line endings throughout: unchanged'
    setup() {
        _s8_dir="$(mktemp -d "${SHELLSPEC_TMPBASE:-/tmp}/pc_shape_crlf.XXXXXX")"
        _pc_box "${_s8_dir}"
        sed 's/$/\r/' "${FIX}/plus_pinned.conf" > "${PFB_PKG_CONF}"
        _pc_config_xml on
        _s8_sum="$(cksum < "${PFB_PKG_CONF}")"
    }
    cleanup() { rm -rf "${_s8_dir}"; _pc_unset_box; unset _s8_sum; }
    Before 'setup'
    After  'cleanup'

    It 'before-state: pkg.conf carries CRLF line endings'
      _s8_cr="$(printf '\r')"
      The value "$(grep -cF "${_s8_cr}" "${PFB_PKG_CONF}")" should not equal 0
    End

    It 'leaves pkg.conf byte-unchanged, exit 0'
      When run sh "${HOOK}" onestart
      The status should be success
      The value "$(cksum < "${PFB_PKG_CONF}")" should equal "${_s8_sum}"
    End
End

Describe 'pkgconf re-apply — PKG_ENV block contains a nested column-0 "}" (sub-object): refused, no patch'
    # A nested UCL sub-object's own closing brace can be mistaken for PKG_ENV's
    # own close by naive first-`}`-after-open scanning (issue #2518 nitpick
    # N-nested-brace) -- SUBOBJ closes on the FIRST column-0 "}" in this
    # fixture, one line before PKG_ENV's real close. Un-refused, the insertion
    # awk would land the new line inside SUBOBJ instead: it would look patched
    # (grep for SSL_CA_CERT_PATH finds it) but verify nothing (libpkg would set
    # the key on SUBOBJ, not PKG_ENV).
    setup() {
        _s9_dir="$(mktemp -d "${SHELLSPEC_TMPBASE:-/tmp}/pc_shape_nested_brace.XXXXXX")"
        _pc_box "${_s9_dir}"
        cat > "${PFB_PKG_CONF}" <<'EOF'
ABI=FreeBSD:16:amd64
PKG_ENV {
	SSL_CA_CERT_FILE=/etc/ssl/netgate-ca.pem
	SUBOBJ {
}
}
EOF
        _pc_config_xml on
        _s9_sum="$(cksum < "${PFB_PKG_CONF}")"
    }
    cleanup() { rm -rf "${_s9_dir}"; _pc_unset_box; unset _s9_sum; }
    Before 'setup'
    After  'cleanup'

    It 'before-state: the block contains a nested sub-object with its own closing brace'
      The value "$(grep -c '^}$' "${PFB_PKG_CONF}")" should equal 2
    End

    It 'leaves pkg.conf byte-unchanged, exit 0'
      When run sh "${HOOK}" onestart
      The status should be success
      The value "$(cksum < "${PFB_PKG_CONF}")" should equal "${_s9_sum}"
    End
End

Describe 'pkgconf re-apply — pkg.conf itself is unreadable: no shell error text, exit 0'
    # grep -c on an unreadable file prints nothing to stdout and exits nonzero;
    # an unguarded `[ "$_pcr_open_count" -eq 1 ]` then errors with a literal
    # "Illegal number:" on stderr -- contradicting this hook's own "never print"
    # intent (issue #2518 nitpick N-illegal-number). rc must still be 0 (boot
    # safety), which it already was; only the stray stderr text is the bug.
    setup() {
        _u1_dir="$(mktemp -d "${SHELLSPEC_TMPBASE:-/tmp}/pc_pkgconf_unreadable.XXXXXX")"
        _pc_box "${_u1_dir}"
        cp "${FIX}/plus_pinned.conf" "${PFB_PKG_CONF}"
        _pc_config_xml on
        PFB_SSL_CA_CERT_PATH="${_u1_dir}/certs"
        _pc_ca_dir_with_entry "${PFB_SSL_CA_CERT_PATH}"
        export PFB_SSL_CA_CERT_PATH
        chmod 000 "${PFB_PKG_CONF}"
    }
    cleanup() { chmod 600 "${PFB_PKG_CONF}" 2>/dev/null; rm -rf "${_u1_dir}"; _pc_unset_box; }
    Before 'setup'
    After  'cleanup'

    It 'before-state: pkg.conf exists but is unreadable'
      The path "${PFB_PKG_CONF}" should be exist
    End

    It 'prints no "Illegal number" shell error, exit 0'
      When run sh "${HOOK}" onestart
      The status should be success
      The stderr should not include "Illegal number"
    End
End

Describe 'pkgconf re-apply — pkg.conf permission bits: preserved across the patch'
    # awk's `>` redirect creates the temp file at the process umask, not at
    # pkg.conf's own mode (issue #2518 nitpick N-mode) -- proven in the CI
    # image: mode 600 in, 644 out, before the fix. The PHP appender already
    # preserves the original file's permission bits (fileperms()+chmod()); the
    # shell side did not.
    setup() {
        _m1_dir="$(mktemp -d "${SHELLSPEC_TMPBASE:-/tmp}/pc_mode.XXXXXX")"
        _pc_box "${_m1_dir}"
        cp "${FIX}/plus_pinned.conf" "${PFB_PKG_CONF}"
        chmod 0600 "${PFB_PKG_CONF}"
        _pc_config_xml on
    }
    cleanup() { rm -rf "${_m1_dir}"; _pc_unset_box; }
    Before 'setup'
    After  'cleanup'

    It 'before-state: pkg.conf mode is 0600'
      The value "$(stat -c '%a' "${PFB_PKG_CONF}")" should equal 600
    End

    It 'preserves the original permission bits after patching, exit 0'
      When run sh "${HOOK}" onestart
      The status should be success
      The stderr should include "INFO"
      The value "$(stat -c '%a' "${PFB_PKG_CONF}")" should equal 600
    End
End

Describe 'pkgconf re-apply — pkg.conf whose final brace carries no trailing newline: newline-less state preserved'
    # awk's `print` always terminates its last output record, so patching a
    # pkg.conf whose last byte is "}" (no trailing newline) used to ADD one --
    # a divergence from the PHP appender, which round-trips the exact bytes it
    # was given (issue #2518 nitpick N-trailing-newline; PHP pins this with
    # testAddPatchesWhenFinalBraceHasNoTrailingNewline).
    setup() {
        _nl1_dir="$(mktemp -d "${SHELLSPEC_TMPBASE:-/tmp}/pc_no_trailing_nl.XXXXXX")"
        _pc_box "${_nl1_dir}"
        printf '%s' "$(cat "${FIX}/plus_pinned.conf")" > "${PFB_PKG_CONF}"
        _pc_config_xml on
        _nl1_expected="${_nl1_dir}/expected-patched.conf"
        printf '%s' "$(cat "${FIX}/plus_patched.conf")" > "${_nl1_expected}"
    }
    cleanup() { rm -rf "${_nl1_dir}"; _pc_unset_box; unset _nl1_expected; }
    Before 'setup'
    After  'cleanup'

    It 'before-state: pkg.conf final brace carries no trailing newline'
      The value "$(tail -c1 "${PFB_PKG_CONF}")" should equal '}'
    End

    It 'patches without adding a trailing newline, exit 0'
      When run sh "${HOOK}" onestart
      The status should be success
      The stderr should include "INFO"
      The value "$(cmp -s "${PFB_PKG_CONF}" "${_nl1_expected}" && echo 0 || echo 1)" should equal 0
    End
End

# ── CA-PATH AXIS (consent on, plus_pinned.conf) ──────────────────────────────

Describe 'pkgconf re-apply — PFB_SSL_CA_CERT_PATH does not exist: unchanged'
    setup() {
        _p1_dir="$(mktemp -d "${SHELLSPEC_TMPBASE:-/tmp}/pc_ca_missing.XXXXXX")"
        _pc_box "${_p1_dir}"
        cp "${FIX}/plus_pinned.conf" "${PFB_PKG_CONF}"
        _pc_config_xml on
        PFB_SSL_CA_CERT_PATH="${_p1_dir}/no-such-dir"
        export PFB_SSL_CA_CERT_PATH
    }
    cleanup() { rm -rf "${_p1_dir}"; _pc_unset_box; }
    Before 'setup'
    After  'cleanup'

    It 'before-state: the CA path does not exist'
      The path "${PFB_SSL_CA_CERT_PATH}" should not be exist
    End

    It 'leaves pkg.conf byte-unchanged, exit 0'
      When run sh "${HOOK}" onestart
      The status should be success
      The value "$(cmp -s "${PFB_PKG_CONF}" "${FIX}/plus_pinned.conf" && echo 0 || echo 1)" should equal 0
    End
End

Describe 'pkgconf re-apply — PFB_SSL_CA_CERT_PATH exists but is empty: unchanged'
    setup() {
        _p2_dir="$(mktemp -d "${SHELLSPEC_TMPBASE:-/tmp}/pc_ca_empty.XXXXXX")"
        _pc_box "${_p2_dir}"
        cp "${FIX}/plus_pinned.conf" "${PFB_PKG_CONF}"
        _pc_config_xml on
        PFB_SSL_CA_CERT_PATH="${_p2_dir}/empty-certs"
        mkdir -p "${PFB_SSL_CA_CERT_PATH}"
        export PFB_SSL_CA_CERT_PATH
    }
    cleanup() { rm -rf "${_p2_dir}"; _pc_unset_box; }
    Before 'setup'
    After  'cleanup'

    It 'before-state: the CA path is an empty directory'
      The path "${PFB_SSL_CA_CERT_PATH}" should be directory
      The value "$(ls -A "${PFB_SSL_CA_CERT_PATH}" | wc -l | tr -d ' ')" should equal 0
    End

    It 'leaves pkg.conf byte-unchanged, exit 0'
      When run sh "${HOOK}" onestart
      The status should be success
      The value "$(cmp -s "${PFB_PKG_CONF}" "${FIX}/plus_pinned.conf" && echo 0 || echo 1)" should equal 0
    End
End

Describe 'pkgconf re-apply — PFB_SSL_CA_CERT_PATH is a regular file: unchanged'
    setup() {
        _p3_dir="$(mktemp -d "${SHELLSPEC_TMPBASE:-/tmp}/pc_ca_regfile.XXXXXX")"
        _pc_box "${_p3_dir}"
        cp "${FIX}/plus_pinned.conf" "${PFB_PKG_CONF}"
        _pc_config_xml on
        PFB_SSL_CA_CERT_PATH="${_p3_dir}/not-a-dir"
        true > "${PFB_SSL_CA_CERT_PATH}"
        export PFB_SSL_CA_CERT_PATH
    }
    cleanup() { rm -rf "${_p3_dir}"; _pc_unset_box; }
    Before 'setup'
    After  'cleanup'

    It 'before-state: the CA path is a regular file, not a directory'
      The path "${PFB_SSL_CA_CERT_PATH}" should be file
    End

    It 'leaves pkg.conf byte-unchanged, exit 0'
      When run sh "${HOOK}" onestart
      The status should be success
      The value "$(cmp -s "${PFB_PKG_CONF}" "${FIX}/plus_pinned.conf" && echo 0 || echo 1)" should equal 0
    End
End

Describe 'pkgconf re-apply — PFB_SSL_CA_CERT_PATH contains one entry: patched'
    setup() {
        _p4_dir="$(mktemp -d "${SHELLSPEC_TMPBASE:-/tmp}/pc_ca_oneentry.XXXXXX")"
        _pc_box "${_p4_dir}"
        cp "${FIX}/plus_pinned.conf" "${PFB_PKG_CONF}"
        _pc_config_xml on
        PFB_SSL_CA_CERT_PATH="${_p4_dir}/custom-certs"
        _pc_ca_dir_with_entry "${PFB_SSL_CA_CERT_PATH}"
        export PFB_SSL_CA_CERT_PATH
        # The fixture-derived expectation: plus_patched.conf with its literal
        # /etc/ssl/certs value swapped for this example's custom CA dir — still
        # asserting against the fixture bytes, not a hand-retyped heredoc.
        _p4_expected="${_p4_dir}/expected-patched.conf"
        sed "s#/etc/ssl/certs#${PFB_SSL_CA_CERT_PATH}#" "${FIX}/plus_patched.conf" > "${_p4_expected}"
    }
    cleanup() { rm -rf "${_p4_dir}"; _pc_unset_box; unset _p4_expected; }
    Before 'setup'
    After  'cleanup'

    It 'before-state: the custom CA dir has exactly one entry'
      The path "${PFB_SSL_CA_CERT_PATH}" should be directory
      The value "$(ls -A "${PFB_SSL_CA_CERT_PATH}" | wc -l | tr -d ' ')" should equal 1
    End

    It 'patches pkg.conf with the custom CA path, exit 0'
      When run sh "${HOOK}" onestart
      The status should be success
      The stderr should include "INFO"
      The value "$(cmp -s "${PFB_PKG_CONF}" "${_p4_expected}" && echo 0 || echo 1)" should equal 0
    End
End

# ── CA-PATH VALIDATION AXIS (issue #2518 F4.1: character whitelist) ─────────
# Mirrors PHP's pfb_pkgconf_ca_add() guard `^/[A-Za-z0-9._/+-]+$` exactly
# (including that a bare "/" is refused): a value landing inside the PKG_ENV
# block containing '#' would make libucl treat the rest of the line as a
# comment and silently truncate the CA path; a space or quote corrupts the
# block. Each hostile value is refused rather than written.

Describe 'pkgconf re-apply — CA path containing a "#": refused, no patch'
    setup() {
        _v1_dir="$(mktemp -d "${SHELLSPEC_TMPBASE:-/tmp}/pc_val_hash.XXXXXX")"
        _pc_box "${_v1_dir}"
        cp "${FIX}/plus_pinned.conf" "${PFB_PKG_CONF}"
        _pc_config_xml on
        PFB_SSL_CA_CERT_PATH="${_v1_dir}/weird#certs"
        _pc_ca_dir_with_entry "${PFB_SSL_CA_CERT_PATH}"
        export PFB_SSL_CA_CERT_PATH
    }
    cleanup() { rm -rf "${_v1_dir}"; _pc_unset_box; }
    Before 'setup'
    After  'cleanup'

    It 'before-state: the CA dir is populated but its path contains #'
      The path "${PFB_SSL_CA_CERT_PATH}" should be directory
    End

    It 'leaves pkg.conf byte-unchanged, exit 0'
      When run sh "${HOOK}" onestart
      The status should be success
      The value "$(cmp -s "${PFB_PKG_CONF}" "${FIX}/plus_pinned.conf" && echo 0 || echo 1)" should equal 0
    End
End

Describe 'pkgconf re-apply — CA path containing a space: refused, no patch'
    setup() {
        _v2_dir="$(mktemp -d "${SHELLSPEC_TMPBASE:-/tmp}/pc_val_space.XXXXXX")"
        _pc_box "${_v2_dir}"
        cp "${FIX}/plus_pinned.conf" "${PFB_PKG_CONF}"
        _pc_config_xml on
        PFB_SSL_CA_CERT_PATH="${_v2_dir}/weird certs"
        _pc_ca_dir_with_entry "${PFB_SSL_CA_CERT_PATH}"
        export PFB_SSL_CA_CERT_PATH
    }
    cleanup() { rm -rf "${_v2_dir}"; _pc_unset_box; }
    Before 'setup'
    After  'cleanup'

    It 'before-state: the CA dir is populated but its path contains a space'
      The path "${PFB_SSL_CA_CERT_PATH}" should be directory
    End

    It 'leaves pkg.conf byte-unchanged, exit 0'
      When run sh "${HOOK}" onestart
      The status should be success
      The value "$(cmp -s "${PFB_PKG_CONF}" "${FIX}/plus_pinned.conf" && echo 0 || echo 1)" should equal 0
    End
End

Describe 'pkgconf re-apply — CA path containing a double quote: refused, no patch'
    setup() {
        _v3_dir="$(mktemp -d "${SHELLSPEC_TMPBASE:-/tmp}/pc_val_quote.XXXXXX")"
        _pc_box "${_v3_dir}"
        cp "${FIX}/plus_pinned.conf" "${PFB_PKG_CONF}"
        _pc_config_xml on
        PFB_SSL_CA_CERT_PATH="${_v3_dir}/weird\"certs"
        _pc_ca_dir_with_entry "${PFB_SSL_CA_CERT_PATH}"
        export PFB_SSL_CA_CERT_PATH
    }
    cleanup() { rm -rf "${_v3_dir}"; _pc_unset_box; }
    Before 'setup'
    After  'cleanup'

    It 'before-state: the CA dir is populated but its path contains a double quote'
      The path "${PFB_SSL_CA_CERT_PATH}" should be directory
    End

    It 'leaves pkg.conf byte-unchanged, exit 0'
      When run sh "${HOOK}" onestart
      The status should be success
      The value "$(cmp -s "${PFB_PKG_CONF}" "${FIX}/plus_pinned.conf" && echo 0 || echo 1)" should equal 0
    End
End

Describe 'pkgconf re-apply — CA path is a bare "/": refused, no patch'
    setup() {
        _v4_dir="$(mktemp -d "${SHELLSPEC_TMPBASE:-/tmp}/pc_val_bareslash.XXXXXX")"
        _pc_box "${_v4_dir}"
        cp "${FIX}/plus_pinned.conf" "${PFB_PKG_CONF}"
        _pc_config_xml on
        PFB_SSL_CA_CERT_PATH="/"
        export PFB_SSL_CA_CERT_PATH
    }
    cleanup() { rm -rf "${_v4_dir}"; _pc_unset_box; }
    Before 'setup'
    After  'cleanup'

    It 'before-state: the CA path is the bare root directory'
      The path "${PFB_SSL_CA_CERT_PATH}" should be directory
    End

    It 'leaves pkg.conf byte-unchanged, exit 0'
      When run sh "${HOOK}" onestart
      The status should be success
      The value "$(cmp -s "${PFB_PKG_CONF}" "${FIX}/plus_pinned.conf" && echo 0 || echo 1)" should equal 0
    End
End

# ── CA-PATH POPULATED AXIS (issue #2518 F4.2 / nitpick N-dotfile-guard) ─────
# REPOINTED (issue #2518 nitpick N-dotfile-guard): PHP's pfb_pkgconf_dir_populated()
# used to count dotfiles via scandir() (excluding only '.'/'..'), and this glob
# used two extra dotfile-matching words to agree with it. The rationale for
# "populated" was always "an empty hash dir makes the patch a no-op" -- and a
# directory holding only e.g. ".DS_Store" is equally a no-op, so the PHP side is
# changing to count only NON-dot entries. A bare `*` glob already agrees with
# that (POSIX globs never match a dotfile), so the two extra glob words are
# gone; this row's expectation flips from "patched" to "unchanged" to match.

Describe 'pkgconf re-apply — CA dir containing only a dotfile: NOT populated (matches PHP scandir excluding dotfiles), unchanged'
    setup() {
        _d1_dir="$(mktemp -d "${SHELLSPEC_TMPBASE:-/tmp}/pc_ca_dotfiles.XXXXXX")"
        _pc_box "${_d1_dir}"
        cp "${FIX}/plus_pinned.conf" "${PFB_PKG_CONF}"
        _pc_config_xml on
        PFB_SSL_CA_CERT_PATH="${_d1_dir}/dotfiles-only"
        mkdir -p "${PFB_SSL_CA_CERT_PATH}"
        true > "${PFB_SSL_CA_CERT_PATH}/.hidden"
        export PFB_SSL_CA_CERT_PATH
    }
    cleanup() { rm -rf "${_d1_dir}"; _pc_unset_box; }
    Before 'setup'
    After  'cleanup'

    It 'before-state: the CA dir has only a dotfile entry'
      The path "${PFB_SSL_CA_CERT_PATH}" should be directory
      The value "$(ls -A "${PFB_SSL_CA_CERT_PATH}" | wc -l | tr -d ' ')" should equal 1
    End

    It 'leaves pkg.conf byte-unchanged, exit 0'
      When run sh "${HOOK}" onestart
      The status should be success
      The value "$(cmp -s "${PFB_PKG_CONF}" "${FIX}/plus_pinned.conf" && echo 0 || echo 1)" should equal 0
    End
End

# ── HOSTILE-INPUT ROWS (consent on) ──────────────────────────────────────────

Describe 'pkgconf re-apply — hostile unrelated line survives byte-for-byte'
    # A line carrying spaces, quotes, #, and shell metacharacters, unrelated to
    # the PKG_ENV block, must not be touched or interpreted -- the patch is a
    # pure text insertion, never evaluated as shell. Asserted with a full-file
    # cmp against an expected file built from the SAME two fixture-derived
    # pieces as the input (the padding line + plus_patched.conf's tail) so a
    # mutation that inserts the new line in the wrong place (e.g. after the
    # block's closing `}` instead of before it) is caught -- a line-count or
    # grep-presence check alone cannot tell WHERE the line landed.
    setup() {
        _h1_dir="$(mktemp -d "${SHELLSPEC_TMPBASE:-/tmp}/pc_hostile_line.XXXXXX")"
        _pc_box "${_h1_dir}"
        {
            printf '%s\n' 'ABI=FreeBSD:16:amd64'
            printf '%s\n' 'HOSTILE="a $(rm -rf /) value" # comment; `backtick` & $VAR | pipe'
            cat "${FIX}/plus_pinned.conf" | tail -n +3
        } > "${PFB_PKG_CONF}"
        _pc_config_xml on
        _h1_expected="${_h1_dir}/expected-patched.conf"
        {
            printf '%s\n' 'ABI=FreeBSD:16:amd64'
            printf '%s\n' 'HOSTILE="a $(rm -rf /) value" # comment; `backtick` & $VAR | pipe'
            cat "${FIX}/plus_patched.conf" | tail -n +3
        } > "${_h1_expected}"
    }
    cleanup() { rm -rf "${_h1_dir}"; _pc_unset_box; unset _h1_expected; }
    Before 'setup'
    After  'cleanup'

    It 'before-state: pkg.conf carries the hostile unrelated line'
      The contents of file "${PFB_PKG_CONF}" should include 'HOSTILE="a $(rm -rf /) value"'
    End

    It 'patches exactly one added line and leaves the hostile line byte-unchanged, exit 0'
      When run sh "${HOOK}" onestart
      The status should be success
      The stderr should include "INFO"
      The value "$(cmp -s "${PFB_PKG_CONF}" "${_h1_expected}" && echo 0 || echo 1)" should equal 0
    End
End

Describe 'pkgconf re-apply — a 5 MB pkg.conf still patches correctly'
    # Asserted with a full-file cmp (not grep/wc-l counts, which cannot tell
    # WHERE the inserted line landed) against an expected file sharing the same
    # padding as the input, so a mutation misplacing the line is caught even at
    # this size.
    setup() {
        _h2_dir="$(mktemp -d "${SHELLSPEC_TMPBASE:-/tmp}/pc_hostile_big.XXXXXX")"
        _pc_box "${_h2_dir}"
        _h2_padding="${_h2_dir}/padding.txt"
        {
            printf '%s\n' 'ABI=FreeBSD:16:amd64'
            i=0
            while [ "${i}" -lt 120000 ]; do
                printf 'PADDING_LINE_%d_filler_text_to_reach_size\n' "${i}"
                i=$((i + 1))
            done
        } > "${_h2_padding}"
        cat "${_h2_padding}" > "${PFB_PKG_CONF}"
        cat "${FIX}/plus_pinned.conf" | tail -n +3 >> "${PFB_PKG_CONF}"
        _pc_config_xml on
        _h2_expected="${_h2_dir}/expected-patched.conf"
        cat "${_h2_padding}" > "${_h2_expected}"
        cat "${FIX}/plus_patched.conf" | tail -n +3 >> "${_h2_expected}"
    }
    cleanup() { rm -rf "${_h2_dir}"; _pc_unset_box; unset _h2_padding _h2_expected; }
    Before 'setup'
    After  'cleanup'

    It 'before-state: pkg.conf is at least 5 MB'
      The value "$([ "$(wc -c < "${PFB_PKG_CONF}")" -gt 5000000 ] && echo 0 || echo 1)" should equal 0
    End

    # cmp is a byte-stream comparator (not a whole-file-into-a-shell-string
    # substring match like "The contents of file ... should include"), so it
    # stays fast even at this size while still proving exact placement.
    It 'patches the file correctly, exit 0'
      When run sh "${HOOK}" onestart
      The status should be success
      The stderr should include "INFO"
      The value "$(cmp -s "${PFB_PKG_CONF}" "${_h2_expected}" && echo 0 || echo 1)" should equal 0
    End
End

Describe 'pkgconf re-apply — a pkg.conf path containing a space is handled'
    setup() {
        _h3_dir="$(mktemp -d "${SHELLSPEC_TMPBASE:-/tmp}/pc_hostile_space.XXXXXX")"
        _pc_box "${_h3_dir}"
        PFB_PKG_CONF="${_h3_dir}/pkg conf with spaces.conf"
        export PFB_PKG_CONF
        cp "${FIX}/plus_pinned.conf" "${PFB_PKG_CONF}"
        _pc_config_xml on
    }
    cleanup() { rm -rf "${_h3_dir}"; _pc_unset_box; }
    Before 'setup'
    After  'cleanup'

    It 'before-state: pkg.conf lives at a path containing a space'
      The path "${PFB_PKG_CONF}" should be exist
    End

    It 'patches the space-containing path correctly, exit 0'
      When run sh "${HOOK}" onestart
      The status should be success
      The stderr should include "INFO"
      The value "$(cmp -s "${PFB_PKG_CONF}" "${FIX}/plus_patched.conf" && echo 0 || echo 1)" should equal 0
    End
End

# ── NON-REGRESSION: both jobs run in a single invocation ─────────────────────

Describe 'pkgconf re-apply — a channel conf regenerates AND pkg.conf gets patched in one run'
    setup() {
        _n1_dir="$(mktemp -d "${SHELLSPEC_TMPBASE:-/tmp}/pc_nonreg_both.XXXXXX")"
        _pc_box "${_n1_dir}"
        printf '# stub pending\n' > "${PFB_STABLE_CONF}"
        cp "${FIX}/plus_pinned.conf" "${PFB_PKG_CONF}"
        _pc_config_xml on
    }
    cleanup() { rm -rf "${_n1_dir}"; _pc_unset_box; }
    Before 'setup'
    After  'cleanup'

    It 'before-state: the stable conf is the stub, pkg.conf is the pinned fixture'
      The contents of file "${PFB_STABLE_CONF}" should include "pending"
      The value "$(cmp -s "${PFB_PKG_CONF}" "${FIX}/plus_pinned.conf" && echo 0 || echo 1)" should equal 0
    End

    It 'both the repo conf and pkg.conf are updated, exit 0'
      When run sh "${HOOK}" onestart
      The status should be success
      The stderr should include "regenerated"
      The stderr should include "INFO"
      The contents of file "${PFB_STABLE_CONF}" should include "pfblockerng-stable: {"
      The contents of file "${PFB_STABLE_CONF}" should not include "pending"
      The value "$(cmp -s "${PFB_PKG_CONF}" "${FIX}/plus_patched.conf" && echo 0 || echo 1)" should equal 0
    End
End
