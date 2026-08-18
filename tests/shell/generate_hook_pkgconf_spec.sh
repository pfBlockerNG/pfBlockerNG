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
# reads), granted as the literal token `on`. `<config>` is NOT unique tree-wide
# (every installed package gets one) so `_pkgconf_ca_reapply()` scopes its read
# to the FIRST <config> block inside the single <pfblockerng> element — exactly
# config/0 — and requires the element on a line BY ITSELF (whole-line match),
# so a single-line XML comment wrapping it does not count as consent (issue
# #2518 F1). The rows below cover every other value, a same-value-but-wrong-block
# case, an XML comment, and every other value as "no consent".
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
# "" / omitted entirely when $1 is "absent").
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
				<row>
					<other>1</other>
				</row>
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
				<row>
					<pfb_pkg_ca_consent>${_pcx_body}</pfb_pkg_ca_consent>
				</row>
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

Describe 'pkgconf re-apply — consent on: patches plus_pinned.conf to plus_patched.conf'
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
				<row>
					<!-- <pfb_pkg_ca_consent>on</pfb_pkg_ca_consent> -->
				</row>
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

Describe 'pkgconf re-apply — config/0 says off, a second <config> block says on: no patch (scoped to config/0)'
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
				<row>
					<pfb_pkg_ca_consent>off</pfb_pkg_ca_consent>
				</row>
			</config>
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

Describe 'pkgconf re-apply — config/0 says on, a second <config> block says off: patches (scoped to config/0)'
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
				<row>
					<pfb_pkg_ca_consent>on</pfb_pkg_ca_consent>
				</row>
			</config>
			<config>
				<row>
					<pfb_pkg_ca_consent>off</pfb_pkg_ca_consent>
				</row>
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

# ── CA-PATH POPULATED AXIS (issue #2518 F4.2: dotfile-only directory) ───────
# PHP's pfb_pkgconf_dir_populated() uses scandir(), which counts dotfiles as
# entries (excluding only '.'/'..'); a POSIX `for dir/*` glob does not match
# dotfiles, so the two implementations must agree here or a dir holding only
# e.g. ".DS_Store" reads "populated" on one side and "empty" on the other.

Describe 'pkgconf re-apply — CA dir containing only a dotfile: populated (matches PHP scandir), patched'
    setup() {
        _d1_dir="$(mktemp -d "${SHELLSPEC_TMPBASE:-/tmp}/pc_ca_dotfiles.XXXXXX")"
        _pc_box "${_d1_dir}"
        cp "${FIX}/plus_pinned.conf" "${PFB_PKG_CONF}"
        _pc_config_xml on
        PFB_SSL_CA_CERT_PATH="${_d1_dir}/dotfiles-only"
        mkdir -p "${PFB_SSL_CA_CERT_PATH}"
        true > "${PFB_SSL_CA_CERT_PATH}/.hidden"
        export PFB_SSL_CA_CERT_PATH
        _d1_expected="${_d1_dir}/expected-patched.conf"
        sed "s#/etc/ssl/certs#${PFB_SSL_CA_CERT_PATH}#" "${FIX}/plus_patched.conf" > "${_d1_expected}"
    }
    cleanup() { rm -rf "${_d1_dir}"; _pc_unset_box; unset _d1_expected; }
    Before 'setup'
    After  'cleanup'

    It 'before-state: the CA dir has only a dotfile entry'
      The path "${PFB_SSL_CA_CERT_PATH}" should be directory
      The value "$(ls -A "${PFB_SSL_CA_CERT_PATH}" | wc -l | tr -d ' ')" should equal 1
    End

    It 'patches pkg.conf with the custom CA path, exit 0'
      When run sh "${HOOK}" onestart
      The status should be success
      The stderr should include "INFO"
      The value "$(cmp -s "${PFB_PKG_CONF}" "${_d1_expected}" && echo 0 || echo 1)" should equal 0
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
