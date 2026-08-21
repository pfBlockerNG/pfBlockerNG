#shellcheck shell=sh
# pfblockerng_repo_generate.sh — consent-gated login.conf CA carry (issue
# #2617). Sibling suite to generate_hook_login_conf_spec.sh: that file pins
# the standalone login.conf editing primitive itself
# (_logincap_setenv_add()/_logincap_setenv_remove()); this one pins JOB 2 --
# the CONSENT READ (_login_ca_consent()) and its wiring into `onestart`
# (_login_ca_reconcile()) -- exercised end to end via `sh "${HOOK}" onestart`.
#
# This suite supersedes generate_hook_pkgconf_spec.sh (issue #2518), which
# pinned the retired pkg.conf PKG_ENV patcher byte-for-byte. That machinery is
# gone; only the CONSENT-SCOPING semantics survive here, retargeted onto
# login.conf as the write target. Every row asserts login.conf bytes against
# tests/fixtures/login_conf/{stock,stock_with_ca}.conf (or a byte snapshot
# taken right after staging, for a NOOP row), never a hand-retyped heredoc --
# same oracle style as generate_hook_login_conf_spec.sh.
#
# DEFAULT-ON (owner ruling, issue #2617): pfb_pkg_ca_consent is a registered
# config field read on the PHP side at installedpackages/pfblockerng/config/0
# -- PfbConfig::read('gen/pfb_pkg_ca_consent') -- as a DIRECT CHILD of the
# FIRST <config> block under the single <pfblockerng> section (config/0):
# never nested under a <row> or any other wrapper, and never a later <config>
# row. PHP writes the literal token "on" for an explicit On and an EMPTY token
# for an explicit Off; an ABSENT element (including a missing/unreadable
# config.xml) means the registered default, which is now On -- this is the
# headline behaviour change from issue #2518's fail-closed default.
#
# Tip: run with `shellspec --shell "$(command -v dash)" tests/shell/generate_hook_ca_consent_spec.sh`.

HOOK="${PFB_ROOT}/scripts/rc.d/pfblockerng_repo_generate.sh"
FIX_LOGIN="${PFB_ROOT}/tests/fixtures/login_conf"

# ── helpers ───────────────────────────────────────────────────────────────────

# Stand up a temp box dir at $1: a real, populated CA directory (login.conf's
# populated-directory guard needs one on disk), the four channel-conf paths
# pointed at names that are never created (JOB 1 stays a no-op -- covered by
# its own suite, generate_hook_spec.sh), and no config.xml yet -- each example
# stages that itself.
_cc_box() {
    _ccb_dir="$1"
    mkdir -p "${_ccb_dir}"
    PFB_STABLE_CONF="${_ccb_dir}/pfblockerng-stable.conf"
    PFB_TESTING_CONF="${_ccb_dir}/pfblockerng-testing.conf"
    PFB_EDGE_CONF="${_ccb_dir}/pfblockerng-edge.conf"
    PFB_NIGHTLY_CONF="${_ccb_dir}/pfblockerng-nightly.conf"
    PFB_CONFIG_XML="${_ccb_dir}/config.xml"
    PFB_LOGIN_CONF="${_ccb_dir}/login.conf"
    PFB_SSL_CA_CERT_PATH="${_ccb_dir}/ca-certs"
    _cc_ca_dir_with_entry "${PFB_SSL_CA_CERT_PATH}"
    PFB_CAP_MKDB="$(command -v cap_mkdb 2>/dev/null || printf '%s' /usr/bin/cap_mkdb)"
    export PFB_STABLE_CONF PFB_TESTING_CONF PFB_EDGE_CONF PFB_NIGHTLY_CONF \
           PFB_CONFIG_XML PFB_LOGIN_CONF PFB_SSL_CA_CERT_PATH PFB_CAP_MKDB
    unset _ccb_dir
}

_cc_unset_box() {
    unset PFB_STABLE_CONF PFB_TESTING_CONF PFB_EDGE_CONF PFB_NIGHTLY_CONF \
          PFB_CONFIG_XML PFB_LOGIN_CONF PFB_SSL_CA_CERT_PATH PFB_CAP_MKDB
}

# A CA hash dir with exactly one entry, at $1.
_cc_ca_dir_with_entry() {
    mkdir -p "$1"
    true > "$1/dummy.0"
}

# Write a config.xml carrying the consent element with body $1 ("on" / "off" /
# "" / omitted entirely when $1 is "absent"), as a DIRECT CHILD of config/0 --
# the exact production shape PfbConfig::read() sees. The rows further down
# (8-11) build every OTHER shape by hand, on purpose.
_cc_config_xml() {
    _ccx_body="$1"
    case "${_ccx_body}" in
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
				<pfb_pkg_ca_consent>${_ccx_body}</pfb_pkg_ca_consent>
			</config>
		</pfblockerng>
	</installedpackages>
</pfsense>
EOF
            ;;
    esac
    unset _ccx_body
}

# Stage login.conf fixture $1 (basename under FIX_LOGIN, no .conf) into
# PFB_LOGIN_CONF, with the fixture's literal /etc/ssl/certs rewritten to this
# test's real CA dir.
_cc_stage_login() {
    sed "s#/etc/ssl/certs#${PFB_SSL_CA_CERT_PATH}#g" "${FIX_LOGIN}/$1.conf" > "${PFB_LOGIN_CONF}"
}

# Same substitution, written to an arbitrary path $2 for use as a diff oracle
# (never as the live file the hook edits).
_cc_expected_login() {
    sed "s#/etc/ssl/certs#${PFB_SSL_CA_CERT_PATH}#g" "${FIX_LOGIN}/$1.conf" > "$2"
}

_cc_cmp() {
    cmp -s "$1" "$2" && echo 0 || echo 1
}

# Catastrophic-damage smoke check (never the primary oracle): when cap_mkdb is
# on PATH, the compiled .db must exist after a real write; when it is absent
# (Linux CI), trivially OK.
_cc_db_ok() {
    command -v "${PFB_CAP_MKDB}" >/dev/null 2>&1 || return 0
    [ -f "${PFB_LOGIN_CONF}.db" ]
}

# `Skip if` condition: true (rc 0) iff cap_mkdb is NOT on PATH.
no_cap_mkdb() {
    command -v cap_mkdb >/dev/null 2>&1 && return 1
    return 0
}

# ── CONSENT AXIS (rows 1-7: the production config/0 shape) ──────────────────

Describe 'onestart consent — 1: consent element absent from config/0: ADD (the default-on flip)'
    setup() {
        _r1_dir="$(mktemp -d "${SHELLSPEC_TMPBASE:-/tmp}/cc_absent.XXXXXX")"
        _cc_box "${_r1_dir}"
        _cc_stage_login stock
        _cc_config_xml absent
        _cc_expected_login stock_with_ca "${_r1_dir}/expected.conf"
    }
    cleanup() { rm -rf "${_r1_dir}"; _cc_unset_box; unset _r1_dir; }
    Before 'setup'
    After  'cleanup'

    It 'before-state: login.conf is the stock fixture'
      The value "$(_cc_cmp "${PFB_LOGIN_CONF}" "${FIX_LOGIN}/stock.conf")" should equal 0
    End

    It 'carries SSL_CA_CERT_PATH into login.conf even though config/0 says nothing at all'
      When run sh "${HOOK}" onestart
      The status should be success
      The stderr should include "INFO"
      The value "$(_cc_cmp "${PFB_LOGIN_CONF}" "${_r1_dir}/expected.conf")" should equal 0
    End
End

Describe 'onestart consent — 2: <pfb_pkg_ca_consent>on</pfb_pkg_ca_consent>: ADD'
    setup() {
        _r2_dir="$(mktemp -d "${SHELLSPEC_TMPBASE:-/tmp}/cc_on.XXXXXX")"
        _cc_box "${_r2_dir}"
        _cc_stage_login stock
        _cc_config_xml on
        _cc_expected_login stock_with_ca "${_r2_dir}/expected.conf"
    }
    cleanup() { rm -rf "${_r2_dir}"; _cc_unset_box; unset _r2_dir; }
    Before 'setup'
    After  'cleanup'

    It 'carries SSL_CA_CERT_PATH into login.conf'
      When run sh "${HOOK}" onestart
      The status should be success
      The stderr should include "INFO"
      The value "$(_cc_cmp "${PFB_LOGIN_CONF}" "${_r2_dir}/expected.conf")" should equal 0
    End
End

Describe 'onestart consent — 3: <pfb_pkg_ca_consent>On</pfb_pkg_ca_consent> (mixed case): ADD'
    setup() {
        _r3_dir="$(mktemp -d "${SHELLSPEC_TMPBASE:-/tmp}/cc_mixedcase.XXXXXX")"
        _cc_box "${_r3_dir}"
        _cc_stage_login stock
        _cc_config_xml On
        _cc_expected_login stock_with_ca "${_r3_dir}/expected.conf"
    }
    cleanup() { rm -rf "${_r3_dir}"; _cc_unset_box; unset _r3_dir; }
    Before 'setup'
    After  'cleanup'

    It 'carries SSL_CA_CERT_PATH into login.conf -- PfbToggle::fromLegacy() accepts On/ON'
      When run sh "${HOOK}" onestart
      The status should be success
      The stderr should include "INFO"
      The value "$(_cc_cmp "${PFB_LOGIN_CONF}" "${_r3_dir}/expected.conf")" should equal 0
    End
End

Describe 'onestart consent — 4: <pfb_pkg_ca_consent></pfb_pkg_ca_consent> (present, empty = explicit opt-out): REMOVE'
    setup() {
        _r4_dir="$(mktemp -d "${SHELLSPEC_TMPBASE:-/tmp}/cc_empty.XXXXXX")"
        _cc_box "${_r4_dir}"
        _cc_stage_login stock_with_ca
        _cc_config_xml ""
        _cc_expected_login stock "${_r4_dir}/expected.conf"
    }
    cleanup() { rm -rf "${_r4_dir}"; _cc_unset_box; unset _r4_dir; }
    Before 'setup'
    After  'cleanup'

    It 'before-state: login.conf already carries SSL_CA_CERT_PATH'
      The contents of file "${PFB_LOGIN_CONF}" should include "SSL_CA_CERT_PATH"
    End

    It 'strips SSL_CA_CERT_PATH from login.conf -- present-but-empty is an explicit opt-out, never "absent"'
      When run sh "${HOOK}" onestart
      The status should be success
      The stderr should include "INFO"
      The value "$(_cc_cmp "${PFB_LOGIN_CONF}" "${_r4_dir}/expected.conf")" should equal 0
    End
End

Describe 'onestart consent — 5: <pfb_pkg_ca_consent/> (self-closed, empty): REMOVE'
    setup() {
        _r5_dir="$(mktemp -d "${SHELLSPEC_TMPBASE:-/tmp}/cc_selfclosed.XXXXXX")"
        _cc_box "${_r5_dir}"
        _cc_stage_login stock_with_ca
        cat > "${PFB_CONFIG_XML}" <<'EOF'
<?xml version="1.0"?>
<pfsense>
	<installedpackages>
		<pfblockerng>
			<config>
				<pfb_pkg_ca_consent/>
			</config>
		</pfblockerng>
	</installedpackages>
</pfsense>
EOF
        _cc_expected_login stock "${_r5_dir}/expected.conf"
    }
    cleanup() { rm -rf "${_r5_dir}"; _cc_unset_box; unset _r5_dir; }
    Before 'setup'
    After  'cleanup'

    It 'strips SSL_CA_CERT_PATH -- the self-closed shape is also an explicit opt-out'
      When run sh "${HOOK}" onestart
      The status should be success
      The stderr should include "INFO"
      The value "$(_cc_cmp "${PFB_LOGIN_CONF}" "${_r5_dir}/expected.conf")" should equal 0
    End
End

Describe 'onestart consent — 6: <pfb_pkg_ca_consent>off</pfb_pkg_ca_consent>: REMOVE'
    setup() {
        _r6_dir="$(mktemp -d "${SHELLSPEC_TMPBASE:-/tmp}/cc_off.XXXXXX")"
        _cc_box "${_r6_dir}"
        _cc_stage_login stock_with_ca
        _cc_config_xml off
        _cc_expected_login stock "${_r6_dir}/expected.conf"
    }
    cleanup() { rm -rf "${_r6_dir}"; _cc_unset_box; unset _r6_dir; }
    Before 'setup'
    After  'cleanup'

    It 'strips SSL_CA_CERT_PATH from login.conf'
      When run sh "${HOOK}" onestart
      The status should be success
      The stderr should include "INFO"
      The value "$(_cc_cmp "${PFB_LOGIN_CONF}" "${_r6_dir}/expected.conf")" should equal 0
    End
End

Describe 'onestart consent — 7: config.xml missing entirely: ADD (default-on)'
    setup() {
        _r7_dir="$(mktemp -d "${SHELLSPEC_TMPBASE:-/tmp}/cc_noxml.XXXXXX")"
        _cc_box "${_r7_dir}"
        _cc_stage_login stock
        rm -f "${PFB_CONFIG_XML}"
        _cc_expected_login stock_with_ca "${_r7_dir}/expected.conf"
    }
    cleanup() { rm -rf "${_r7_dir}"; _cc_unset_box; unset _r7_dir; }
    Before 'setup'
    After  'cleanup'

    It 'before-state: config.xml does not exist'
      The path "${PFB_CONFIG_XML}" should not be exist
    End

    It 'carries SSL_CA_CERT_PATH into login.conf -- a missing config.xml also defaults on'
      When run sh "${HOOK}" onestart
      The status should be success
      The stderr should include "INFO"
      The value "$(_cc_cmp "${PFB_LOGIN_CONF}" "${_r7_dir}/expected.conf")" should equal 0
    End
End

# ── SCOPING/HARDENING AXIS (rows 8-11) ───────────────────────────────────────

Describe 'onestart consent — 8: decoy "<pfblockerng>" substring in an earlier sibling package, real block explicitly opts out: REMOVE (not ADD)'
    # Under the OLD fail-closed default (issue #2518), a decoy "<pfblockerng>"
    # substring that opens AND closes on the same line (anywhere in the line,
    # not just at its start) permanently latches seen_pb without ever properly
    # scoping into the REAL block -- a bounded FALSE NEGATIVE back then. Under
    # DEFAULT-ON that same miss reads as "element absent" = On, inverting into
    # a FALSE POSITIVE against an explicit opt-out. _login_ca_consent() anchors
    # the opening match to a full line (mirroring the consent element's own
    # full-line requirement) so a decoy embedded inside another element's text
    # -- not starting its own line -- never opens the scope. Pinned choice:
    # decoy-then-real-optout resolves to REMOVE.
    setup() {
        _r8_dir="$(mktemp -d "${SHELLSPEC_TMPBASE:-/tmp}/cc_decoy.XXXXXX")"
        _cc_box "${_r8_dir}"
        _cc_stage_login stock_with_ca
        cat > "${PFB_CONFIG_XML}" <<'EOF'
<?xml version="1.0"?>
<pfsense>
	<installedpackages>
		<someotherpkg>
			<note>see &lt;doc&gt; reference: <pfblockerng>ignored</pfblockerng> for details</note>
		</someotherpkg>
		<pfblockerng>
			<config>
				<pfb_pkg_ca_consent></pfb_pkg_ca_consent>
			</config>
		</pfblockerng>
	</installedpackages>
</pfsense>
EOF
        _cc_expected_login stock "${_r8_dir}/expected.conf"
    }
    cleanup() { rm -rf "${_r8_dir}"; _cc_unset_box; unset _r8_dir; }
    Before 'setup'
    After  'cleanup'

    It 'strips SSL_CA_CERT_PATH -- the decoy never opens the scope, the real explicit opt-out is read'
      When run sh "${HOOK}" onestart
      The status should be success
      The stderr should include "INFO"
      The value "$(_cc_cmp "${PFB_LOGIN_CONF}" "${_r8_dir}/expected.conf")" should equal 0
    End
End

Describe 'onestart consent — 9: a sibling packages own pfb_pkg_ca_consent field is on, ours is explicit empty: REMOVE (never read the sibling)'
    setup() {
        _r9_dir="$(mktemp -d "${SHELLSPEC_TMPBASE:-/tmp}/cc_sibling.XXXXXX")"
        _cc_box "${_r9_dir}"
        _cc_stage_login stock_with_ca
        cat > "${PFB_CONFIG_XML}" <<'EOF'
<?xml version="1.0"?>
<pfsense>
	<installedpackages>
		<someotherpkg>
			<config>
				<pfb_pkg_ca_consent>on</pfb_pkg_ca_consent>
			</config>
		</someotherpkg>
		<pfblockerng>
			<config>
				<pfb_pkg_ca_consent></pfb_pkg_ca_consent>
			</config>
		</pfblockerng>
	</installedpackages>
</pfsense>
EOF
        _cc_expected_login stock "${_r9_dir}/expected.conf"
    }
    cleanup() { rm -rf "${_r9_dir}"; _cc_unset_box; unset _r9_dir; }
    Before 'setup'
    After  'cleanup'

    It 'strips SSL_CA_CERT_PATH -- the sibling packages own field is a different subtree entirely'
      When run sh "${HOOK}" onestart
      The status should be success
      The stderr should include "INFO"
      The value "$(_cc_cmp "${PFB_LOGIN_CONF}" "${_r9_dir}/expected.conf")" should equal 0
    End
End

Describe 'onestart consent — 10: ours nested under <row> (not depth-0), no depth-0 element at all: ADD'
    # PfbConfig::read() sees pfb_pkg_ca_consent ONLY as a direct child of
    # config/0; a <row>-nested copy is not that path, so config/0 itself
    # carries no consent element -- matching the PHP side's own scoping, which
    # is exactly why this resolves to the default-on ADD rather than reading
    # the nested copy at all.
    setup() {
        _r10_dir="$(mktemp -d "${SHELLSPEC_TMPBASE:-/tmp}/cc_nested_row.XXXXXX")"
        _cc_box "${_r10_dir}"
        _cc_stage_login stock
        cat > "${PFB_CONFIG_XML}" <<'EOF'
<?xml version="1.0"?>
<pfsense>
	<installedpackages>
		<pfblockerng>
			<config>
				<row>
					<pfb_pkg_ca_consent></pfb_pkg_ca_consent>
				</row>
			</config>
		</pfblockerng>
	</installedpackages>
</pfsense>
EOF
        _cc_expected_login stock_with_ca "${_r10_dir}/expected.conf"
    }
    cleanup() { rm -rf "${_r10_dir}"; _cc_unset_box; unset _r10_dir; }
    Before 'setup'
    After  'cleanup'

    It 'carries SSL_CA_CERT_PATH -- the nested copy is invisible to config/0, so it reads as absent = on'
      When run sh "${HOOK}" onestart
      The status should be success
      The stderr should include "INFO"
      The value "$(_cc_cmp "${PFB_LOGIN_CONF}" "${_r10_dir}/expected.conf")" should equal 0
    End
End

Describe 'onestart consent — 11: config/0 explicit empty, a SECOND <config> row (config/1) says on: REMOVE (config/0 wins)'
    setup() {
        _r11_dir="$(mktemp -d "${SHELLSPEC_TMPBASE:-/tmp}/cc_second_config.XXXXXX")"
        _cc_box "${_r11_dir}"
        _cc_stage_login stock_with_ca
        cat > "${PFB_CONFIG_XML}" <<'EOF'
<?xml version="1.0"?>
<pfsense>
	<installedpackages>
		<pfblockerng>
			<config>
				<pfb_pkg_ca_consent></pfb_pkg_ca_consent>
			</config>
			<config>
				<pfb_pkg_ca_consent>on</pfb_pkg_ca_consent>
			</config>
		</pfblockerng>
	</installedpackages>
</pfsense>
EOF
        _cc_expected_login stock "${_r11_dir}/expected.conf"
    }
    cleanup() { rm -rf "${_r11_dir}"; _cc_unset_box; unset _r11_dir; }
    Before 'setup'
    After  'cleanup'

    It 'strips SSL_CA_CERT_PATH -- only the FIRST <config> block (config/0) is ever read'
      When run sh "${HOOK}" onestart
      The status should be success
      The stderr should include "INFO"
      The value "$(_cc_cmp "${PFB_LOGIN_CONF}" "${_r11_dir}/expected.conf")" should equal 0
    End
End

# ── NOOP / REFUSAL AXIS (rows 12-14) ─────────────────────────────────────────

Describe 'onestart consent — 12: consent on, login.conf already carries the value: NOOP'
    setup() {
        _r12_dir="$(mktemp -d "${SHELLSPEC_TMPBASE:-/tmp}/cc_noop_add.XXXXXX")"
        _cc_box "${_r12_dir}"
        _cc_stage_login stock_with_ca
        _cc_config_xml on
        cp "${PFB_LOGIN_CONF}" "${_r12_dir}/before.conf"
        rm -f "${PFB_LOGIN_CONF}.db"
    }
    cleanup() { rm -rf "${_r12_dir}"; _cc_unset_box; unset _r12_dir; }
    Before 'setup'
    After  'cleanup'

    It 'leaves login.conf byte-identical, prints no INFO, exit 0'
      When run sh "${HOOK}" onestart
      The status should be success
      The stderr should not include "INFO"
      The value "$(_cc_cmp "${PFB_LOGIN_CONF}" "${_r12_dir}/before.conf")" should equal 0
    End

    It 'does not regenerate a .db on this no-op, even when cap_mkdb is on PATH'
      Skip if 'cap_mkdb not on PATH' no_cap_mkdb
      When run sh "${HOOK}" onestart
      The status should be success
      The path "${PFB_LOGIN_CONF}.db" should not be exist
    End
End

Describe 'onestart consent — 13: consent off, login.conf never patched: NOOP'
    setup() {
        _r13_dir="$(mktemp -d "${SHELLSPEC_TMPBASE:-/tmp}/cc_noop_remove.XXXXXX")"
        _cc_box "${_r13_dir}"
        _cc_stage_login stock
        _cc_config_xml off
        cp "${PFB_LOGIN_CONF}" "${_r13_dir}/before.conf"
    }
    cleanup() { rm -rf "${_r13_dir}"; _cc_unset_box; unset _r13_dir; }
    Before 'setup'
    After  'cleanup'

    It 'leaves login.conf byte-identical, prints no INFO, exit 0'
      When run sh "${HOOK}" onestart
      The status should be success
      The stderr should not include "INFO"
      The value "$(_cc_cmp "${PFB_LOGIN_CONF}" "${_r13_dir}/before.conf")" should equal 0
    End
End

Describe 'onestart consent — 14: consent on but the CA directory is empty: login.conf unchanged, boot still exits 0'
    setup() {
        _r14_dir="$(mktemp -d "${SHELLSPEC_TMPBASE:-/tmp}/cc_empty_ca_dir.XXXXXX")"
        _cc_box "${_r14_dir}"
        _cc_stage_login stock
        _cc_config_xml on
        cp "${PFB_LOGIN_CONF}" "${_r14_dir}/before.conf"
        rm -f "${PFB_SSL_CA_CERT_PATH}"/*
    }
    cleanup() { rm -rf "${_r14_dir}"; _cc_unset_box; unset _r14_dir; }
    Before 'setup'
    After  'cleanup'

    It 'before-state: the CA directory exists but is empty'
      The path "${PFB_SSL_CA_CERT_PATH}" should be exist
      The value "$(find "${PFB_SSL_CA_CERT_PATH}" -mindepth 1 | wc -l | tr -d ' ')" should equal 0
    End

    It 'the editor refuses to add against an unpopulated CA dir -- login.conf unchanged, boot must not wedge'
      When run sh "${HOOK}" onestart
      The status should be success
      The value "$(_cc_cmp "${PFB_LOGIN_CONF}" "${_r14_dir}/before.conf")" should equal 0
    End
End

# ── VERB-INDEPENDENCE AXIS (row 15) ──────────────────────────────────────────

Describe 'login-ca-sync/-revoke verbs — 15: consent-INDEPENDENT, unlike onestart'
    # The PHP caller flushes config to disk before invoking either verb
    # directly, so the verb trusts its own caller rather than re-reading
    # consent; a boot reconcile (_login_ca_reconcile(), exercised by rows 1-14
    # above) self-heals any mismatch between the two paths.
    setup() {
        _r15_dir="$(mktemp -d "${SHELLSPEC_TMPBASE:-/tmp}/cc_verb_independent.XXXXXX")"
        _cc_box "${_r15_dir}"
        _cc_stage_login stock
        _cc_config_xml off
        _cc_expected_login stock_with_ca "${_r15_dir}/expected.conf"
    }
    cleanup() { rm -rf "${_r15_dir}"; _cc_unset_box; unset _r15_dir; }
    Before 'setup'
    After  'cleanup'

    It 'login-ca-sync still ADDS even though config/0 says off -- the verb never consults consent'
      When run sh "${HOOK}" login-ca-sync
      The status should be success
      The stderr should include "INFO"
      The value "$(_cc_cmp "${PFB_LOGIN_CONF}" "${_r15_dir}/expected.conf")" should equal 0
    End
End
