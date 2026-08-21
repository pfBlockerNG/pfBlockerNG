#shellcheck shell=sh
# pfblockerng_repo_generate.sh — login.conf `default`-class setenv editor
# (issue #2617). Sibling suite to generate_hook_pkgconf_spec.sh: that file
# pins JOB 2 (pkg.conf's PKG_ENV re-apply); this one pins the standalone
# login.conf editing primitive (_logincap_setenv_add() /
# _logincap_setenv_remove()), exercised through the `login-ca-sync` /
# `login-ca-revoke` CLI verbs. Neither verb is wired into onestart or the
# pkg.conf ca-sync/ca-revoke commands yet -- that integration is a separate
# change; this suite only pins the editor itself.
#
# Every content assertion diffs the resulting file against a fixture under
# tests/fixtures/login_conf/ (or a sed-substituted copy of one), or -- for the
# hostile/two-record shapes with no fixture counterpart -- against a byte
# snapshot taken right after staging, never a hand-retyped heredoc.
#
# Ground truth (measured on a live box, never contradicted here):
#   1. getcap keeps only the FIRST setenv in a class record; duplicates
#      compile but are dead.
#   2. a non-default class defining its own setenv shadows `default` for its
#      users; such a class is reported, never edited.
#   3. /etc/login.conf.db (compiled by cap_mkdb) is what libc actually reads.
#   4. cap_mkdb validates nothing -- the byte-exact result is the only oracle.
#
# cap_mkdb(1) is BSD/FreeBSD userland (present on the pfSense box and on
# macOS, typically ABSENT on a Linux CI runner) -- assertions on the compiled
# .db are guarded by `command -v cap_mkdb` and never the primary oracle.
#
# Tip: run with `shellspec --shell "$(command -v dash)" tests/shell/generate_hook_login_conf_spec.sh`.

HOOK="${PFB_ROOT}/scripts/rc.d/pfblockerng_repo_generate.sh"
FIX="${PFB_ROOT}/tests/fixtures/login_conf"

# ── helpers ───────────────────────────────────────────────────────────────────

# Stand up a temp box dir at $1: a real, populated CA directory (the
# populated-directory guard needs one to exist on disk) and cap_mkdb resolved
# off PATH when present, /usr/bin/cap_mkdb as an inert fallback name
# otherwise (never invoked directly by the spec -- only by the hook, and only
# when -x).
_lc_box() {
    _lcb_dir="$1"
    mkdir -p "${_lcb_dir}"
    PFB_LOGIN_CONF="${_lcb_dir}/login.conf"
    PFB_SSL_CA_CERT_PATH="${_lcb_dir}/ca-certs"
    _lc_ca_dir_with_entry "${PFB_SSL_CA_CERT_PATH}"
    PFB_CAP_MKDB="$(command -v cap_mkdb 2>/dev/null || printf '%s' /usr/bin/cap_mkdb)"
    export PFB_LOGIN_CONF PFB_SSL_CA_CERT_PATH PFB_CAP_MKDB
    unset _lcb_dir
}

_lc_unset_box() {
    unset PFB_LOGIN_CONF PFB_SSL_CA_CERT_PATH PFB_CAP_MKDB
}

# A CA hash dir with exactly one entry, at $1.
_lc_ca_dir_with_entry() {
    mkdir -p "$1"
    true > "$1/dummy.0"
}

# Write fixture $1 (basename under $FIX, no .conf) to $PFB_LOGIN_CONF, with
# the fixture's literal /etc/ssl/certs rewritten to this test's real CA dir.
_lc_stage() {
    sed "s#/etc/ssl/certs#${PFB_SSL_CA_CERT_PATH}#g" "${FIX}/$1.conf" > "${PFB_LOGIN_CONF}"
}

# Same substitution, written to an arbitrary path $2 for use as a diff oracle
# (never as the live file the hook edits).
_lc_expected() {
    sed "s#/etc/ssl/certs#${PFB_SSL_CA_CERT_PATH}#g" "${FIX}/$1.conf" > "$2"
}

_lc_cmp() {
    cmp -s "$1" "$2" && echo 0 || echo 1
}

# Catastrophic-damage smoke check (never the primary oracle -- see file
# header): when cap_mkdb is on PATH, the compiled .db must exist after a
# write; when it is absent (Linux CI), trivially OK -- nothing to check.
_lc_db_ok() {
    command -v "${PFB_CAP_MKDB}" >/dev/null 2>&1 || return 0
    [ -f "${PFB_LOGIN_CONF}.db" ]
}

# `Skip if` condition: true (rc 0) iff cap_mkdb is NOT on PATH.
no_cap_mkdb() {
    command -v cap_mkdb >/dev/null 2>&1 && return 1
    return 0
}

# ── ADD (login-ca-sync) ──────────────────────────────────────────────────────

Describe 'login-ca-sync — 1: stock shape, one setenv entry already present'
    setup() {
        _a1_dir="$(mktemp -d "${SHELLSPEC_TMPBASE:-/tmp}/lc_stock.XXXXXX")"
        _lc_box "${_a1_dir}"
        _lc_stage stock
        _lc_expected stock_with_ca "${_a1_dir}/expected.conf"
    }
    cleanup() { rm -rf "${_a1_dir}"; _lc_unset_box; unset _a1_dir; }
    Before 'setup'
    After  'cleanup'

    It 'appends SSL_CA_CERT_PATH to the default class, byte-identical to the expected fixture'
      When run sh "${HOOK}" login-ca-sync
      The status should be success
      The stderr should include "INFO"
      The value "$(_lc_cmp "${PFB_LOGIN_CONF}" "${_a1_dir}/expected.conf")" should equal 0
    End
End

Describe 'login-ca-sync — 2: default has no setenv at all'
    setup() {
        _a2_dir="$(mktemp -d "${SHELLSPEC_TMPBASE:-/tmp}/lc_no_setenv.XXXXXX")"
        _lc_box "${_a2_dir}"
        _lc_stage no_setenv
        _lc_expected no_setenv_with_ca "${_a2_dir}/expected.conf"
    }
    cleanup() { rm -rf "${_a2_dir}"; _lc_unset_box; unset _a2_dir; }
    Before 'setup'
    After  'cleanup'

    It 'inserts a new setenv capability immediately after the default:\ label'
      When run sh "${HOOK}" login-ca-sync
      The status should be success
      The stderr should include "INFO"
      The value "$(_lc_cmp "${PFB_LOGIN_CONF}" "${_a2_dir}/expected.conf")" should equal 0
    End
End

Describe 'login-ca-sync — 3: already carries our value, byte-identical no-op'
    setup() {
        _a3_dir="$(mktemp -d "${SHELLSPEC_TMPBASE:-/tmp}/lc_idempotent.XXXXXX")"
        _lc_box "${_a3_dir}"
        _lc_stage stock_with_ca
        cp "${PFB_LOGIN_CONF}" "${_a3_dir}/before.conf"
        rm -f "${PFB_LOGIN_CONF}.db"
    }
    cleanup() { rm -rf "${_a3_dir}"; _lc_unset_box; unset _a3_dir; }
    Before 'setup'
    After  'cleanup'

    It 'leaves login.conf byte-identical, prints no INFO, and never compiles on this no-op'
      When run sh "${HOOK}" login-ca-sync
      The status should be success
      The stderr should not include "INFO"
      The value "$(_lc_cmp "${PFB_LOGIN_CONF}" "${_a3_dir}/before.conf")" should equal 0
    End

    It 'does not create a .db on this no-op, even when cap_mkdb is on PATH'
      Skip if 'cap_mkdb not on PATH' no_cap_mkdb
      When run sh "${HOOK}" login-ca-sync
      The status should be success
      The path "${PFB_LOGIN_CONF}.db" should not be exist
    End
End

Describe 'login-ca-sync — 4: a DIFFERENT value already present'
    setup() {
        _a4_dir="$(mktemp -d "${SHELLSPEC_TMPBASE:-/tmp}/lc_foreign.XXXXXX")"
        _lc_box "${_a4_dir}"
        _lc_stage different_value
        cp "${PFB_LOGIN_CONF}" "${_a4_dir}/before.conf"
    }
    cleanup() { rm -rf "${_a4_dir}"; _lc_unset_box; unset _a4_dir; }
    Before 'setup'
    After  'cleanup'

    It 'leaves login.conf byte-unchanged and warns about the different value'
      When run sh "${HOOK}" login-ca-sync
      The status should be success
      The stderr should include "WARNING"
      The stderr should include "different value"
      The value "$(_lc_cmp "${PFB_LOGIN_CONF}" "${_a4_dir}/before.conf")" should equal 0
    End
End

Describe 'login-ca-sync — 5: default has TWO setenv lines, only the FIRST is patched'
    setup() {
        _a5_dir="$(mktemp -d "${SHELLSPEC_TMPBASE:-/tmp}/lc_duplicate.XXXXXX")"
        _lc_box "${_a5_dir}"
        _lc_stage duplicate_setenv
        _lc_expected duplicate_setenv_with_ca "${_a5_dir}/expected.conf"
    }
    cleanup() { rm -rf "${_a5_dir}"; _lc_unset_box; unset _a5_dir; }
    Before 'setup'
    After  'cleanup'

    It 'before-state: default carries two setenv capability lines'
      The value "$(grep -c ':setenv=' "${PFB_LOGIN_CONF}")" should equal 2
    End

    It 'appends to the first line only; the second (PFBTEST_D=4) is untouched'
      When run sh "${HOOK}" login-ca-sync
      The status should be success
      The stderr should include "INFO"
      The value "$(_lc_cmp "${PFB_LOGIN_CONF}" "${_a5_dir}/expected.conf")" should equal 0
      The contents of file "${PFB_LOGIN_CONF}" should include "setenv=PFBTEST_D=4:"
    End
End

Describe 'login-ca-sync — 6: a sibling class defines its own setenv (shadowing)'
    setup() {
        _a6_dir="$(mktemp -d "${SHELLSPEC_TMPBASE:-/tmp}/lc_sibling.XXXXXX")"
        _lc_box "${_a6_dir}"
        _lc_stage other_class_setenv
        _lc_expected other_class_setenv_with_ca "${_a6_dir}/expected.conf"
    }
    cleanup() { rm -rf "${_a6_dir}"; _lc_unset_box; unset _a6_dir; }
    Before 'setup'
    After  'cleanup'

    It 'patches default normally AND reports the shadowing class by name, without touching it'
      When run sh "${HOOK}" login-ca-sync
      The status should be success
      The stderr should include "staff"
      The value "$(_lc_cmp "${PFB_LOGIN_CONF}" "${_a6_dir}/expected.conf")" should equal 0
      The contents of file "${PFB_LOGIN_CONF}" should include "setenv=STAFF_ONLY=1:"
    End
End

Describe 'login-ca-sync — 7: setenv shares its line with other capabilities'
    setup() {
        _a7_dir="$(mktemp -d "${SHELLSPEC_TMPBASE:-/tmp}/lc_shared.XXXXXX")"
        _lc_box "${_a7_dir}"
        _lc_stage shared_line
        _lc_expected shared_line_with_ca "${_a7_dir}/expected.conf"
    }
    cleanup() { rm -rf "${_a7_dir}"; _lc_unset_box; unset _a7_dir; }
    Before 'setup'
    After  'cleanup'

    It 'appends inside the setenv value only; neighbouring a=1/b=2 capabilities survive in order'
      When run sh "${HOOK}" login-ca-sync
      The status should be success
      The stderr should include "INFO"
      The value "$(_lc_cmp "${PFB_LOGIN_CONF}" "${_a7_dir}/expected.conf")" should equal 0
      The contents of file "${PFB_LOGIN_CONF}" should include "a=1:setenv="
      The contents of file "${PFB_LOGIN_CONF}" should include ":b=2:"
    End
End

Describe 'login-ca-sync — 8: unpopulated CA directory refuses (issue #2524)'
    setup() {
        _a8_dir="$(mktemp -d "${SHELLSPEC_TMPBASE:-/tmp}/lc_unpopulated.XXXXXX")"
        _lc_box "${_a8_dir}"
        _lc_stage stock
        cp "${PFB_LOGIN_CONF}" "${_a8_dir}/before.conf"
        rm -f "${PFB_SSL_CA_CERT_PATH}"/*
    }
    cleanup() { rm -rf "${_a8_dir}"; _lc_unset_box; unset _a8_dir; }
    Before 'setup'
    After  'cleanup'

    It 'before-state: the CA directory exists but is empty'
      The path "${PFB_SSL_CA_CERT_PATH}" should be exist
      The value "$(find "${PFB_SSL_CA_CERT_PATH}" -mindepth 1 | wc -l | tr -d ' ')" should equal 0
    End

    It 'refuses -- login.conf byte-unchanged, exit failure'
      When run sh "${HOOK}" login-ca-sync
      The status should not be success
      The value "$(_lc_cmp "${PFB_LOGIN_CONF}" "${_a8_dir}/before.conf")" should equal 0
    End
End

Describe 'login-ca-sync — 9: symlinked login.conf refuses, target untouched'
    setup() {
        _a9_dir="$(mktemp -d "${SHELLSPEC_TMPBASE:-/tmp}/lc_symlink.XXXXXX")"
        _lc_box "${_a9_dir}"
        _lc_stage stock
        mv "${PFB_LOGIN_CONF}" "${_a9_dir}/real.conf"
        ln -s "${_a9_dir}/real.conf" "${PFB_LOGIN_CONF}"
        cp "${_a9_dir}/real.conf" "${_a9_dir}/before.conf"
    }
    cleanup() { rm -rf "${_a9_dir}"; _lc_unset_box; unset _a9_dir; }
    Before 'setup'
    After  'cleanup'

    It 'before-state: PFB_LOGIN_CONF is a symlink to the real file'
      The path "${PFB_LOGIN_CONF}" should be symlink
    End

    It 'leaves the symlink target byte-unchanged and the path still a symlink'
      When run sh "${HOOK}" login-ca-sync
      The status should not be success
      The path "${PFB_LOGIN_CONF}" should be symlink
      The value "$(_lc_cmp "${_a9_dir}/real.conf" "${_a9_dir}/before.conf")" should equal 0
    End
End

Describe 'login-ca-sync — 10: PFB_SSL_CA_CERT_PATH containing a space refuses'
    setup() {
        _a10_dir="$(mktemp -d "${SHELLSPEC_TMPBASE:-/tmp}/lc_space.XXXXXX")"
        mkdir -p "${_a10_dir}"
        PFB_LOGIN_CONF="${_a10_dir}/login.conf"
        PFB_SSL_CA_CERT_PATH="${_a10_dir}/bad path"
        _lc_ca_dir_with_entry "${PFB_SSL_CA_CERT_PATH}"
        PFB_CAP_MKDB="$(command -v cap_mkdb 2>/dev/null || printf '%s' /usr/bin/cap_mkdb)"
        export PFB_LOGIN_CONF PFB_SSL_CA_CERT_PATH PFB_CAP_MKDB
        sed "s#/etc/ssl/certs#${PFB_SSL_CA_CERT_PATH}#g" "${FIX}/stock.conf" > "${PFB_LOGIN_CONF}"
        cp "${PFB_LOGIN_CONF}" "${_a10_dir}/before.conf"
    }
    cleanup() { rm -rf "${_a10_dir}"; _lc_unset_box; unset _a10_dir; }
    Before 'setup'
    After  'cleanup'

    It 'refuses on the whitelist -- login.conf byte-unchanged'
      When run sh "${HOOK}" login-ca-sync
      The status should not be success
      The value "$(_lc_cmp "${PFB_LOGIN_CONF}" "${_a10_dir}/before.conf")" should equal 0
    End
End

Describe 'login-ca-sync — 11: HOSTILE two setenv fields on one line'
    setup() {
        _a11_dir="$(mktemp -d "${SHELLSPEC_TMPBASE:-/tmp}/lc_hostile_two.XXXXXX")"
        _lc_box "${_a11_dir}"
        printf '%s\n' \
            'default:\' \
            '	:passwd_format=sha512:\' \
            '	:setenv=BLOCKSIZE=K:setenv=FOO=1:\' \
            '	:umask=022:' \
            > "${PFB_LOGIN_CONF}"
        cp "${PFB_LOGIN_CONF}" "${_a11_dir}/before.conf"
    }
    cleanup() { rm -rf "${_a11_dir}"; _lc_unset_box; unset _a11_dir; }
    Before 'setup'
    After  'cleanup'

    It 'refuses rather than risk deleting the pre-existing BLOCKSIZE capability -- byte-unchanged'
      When run sh "${HOOK}" login-ca-sync
      The status should not be success
      The stderr should include "WARNING"
      The value "$(_lc_cmp "${PFB_LOGIN_CONF}" "${_a11_dir}/before.conf")" should equal 0
    End
End

Describe 'login-ca-sync — 12: HOSTILE getcap escape (\072) inside the value'
    setup() {
        _a12_dir="$(mktemp -d "${SHELLSPEC_TMPBASE:-/tmp}/lc_hostile_escape.XXXXXX")"
        _lc_box "${_a12_dir}"
        printf '%s\n' \
            'default:\' \
            '	:passwd_format=sha512:\' \
            '	:setenv=BLOCKSIZE\072K:\' \
            '	:umask=022:' \
            > "${PFB_LOGIN_CONF}"
        cp "${PFB_LOGIN_CONF}" "${_a12_dir}/before.conf"
    }
    cleanup() { rm -rf "${_a12_dir}"; _lc_unset_box; unset _a12_dir; }
    Before 'setup'
    After  'cleanup'

    It 'refuses a value carrying a getcap backslash escape -- byte-unchanged'
      When run sh "${HOOK}" login-ca-sync
      The status should not be success
      The stderr should include "WARNING"
      The value "$(_lc_cmp "${PFB_LOGIN_CONF}" "${_a12_dir}/before.conf")" should equal 0
    End
End

Describe 'login-ca-sync — 13: HOSTILE unterminated setenv field'
    setup() {
        _a13_dir="$(mktemp -d "${SHELLSPEC_TMPBASE:-/tmp}/lc_hostile_unterm.XXXXXX")"
        _lc_box "${_a13_dir}"
        printf '%s\n' \
            'default:\' \
            '	:passwd_format=sha512:\' \
            '	:setenv=BLOCKSIZE=K\' \
            '	:umask=022:' \
            > "${PFB_LOGIN_CONF}"
        cp "${PFB_LOGIN_CONF}" "${_a13_dir}/before.conf"
    }
    cleanup() { rm -rf "${_a13_dir}"; _lc_unset_box; unset _a13_dir; }
    Before 'setup'
    After  'cleanup'

    It 'refuses a setenv field with no closing colon -- byte-unchanged, not silently "fixed"'
      When run sh "${HOOK}" login-ca-sync
      The status should not be success
      The stderr should include "WARNING"
      The value "$(_lc_cmp "${PFB_LOGIN_CONF}" "${_a13_dir}/before.conf")" should equal 0
    End
End

Describe 'login-ca-sync — 14: bare "default:" label with no continuation'
    setup() {
        _a14_dir="$(mktemp -d "${SHELLSPEC_TMPBASE:-/tmp}/lc_bare_label.XXXXXX")"
        _lc_box "${_a14_dir}"
        printf '%s\n' \
            'default:' \
            'standard:\' \
            '	:tc=default:' \
            > "${PFB_LOGIN_CONF}"
        cp "${PFB_LOGIN_CONF}" "${_a14_dir}/before.conf"
    }
    cleanup() { rm -rf "${_a14_dir}"; _lc_unset_box; unset _a14_dir; }
    Before 'setup'
    After  'cleanup'

    It 'never guesses at a default label with no continuation -- byte-unchanged'
      When run sh "${HOOK}" login-ca-sync
      The status should not be success
      The stderr should include "WARNING"
      The value "$(_lc_cmp "${PFB_LOGIN_CONF}" "${_a14_dir}/before.conf")" should equal 0
    End
End

Describe 'login-ca-sync — 15: TWO default records, only the FIRST is patched'
    setup() {
        _a15_dir="$(mktemp -d "${SHELLSPEC_TMPBASE:-/tmp}/lc_two_default.XXXXXX")"
        _lc_box "${_a15_dir}"
        printf '%s\n' \
            'default:\' \
            '	:passwd_format=sha512:\' \
            '	:setenv=BLOCKSIZE=K:\' \
            '	:umask=022:' \
            '' \
            'standard:\' \
            '	:tc=default:' \
            '' \
            'default:\' \
            '	:setenv=X=1:' \
            > "${PFB_LOGIN_CONF}"
        printf '%s\n' \
            'default:\' \
            '	:passwd_format=sha512:\' \
            "	:setenv=BLOCKSIZE=K,SSL_CA_CERT_PATH=${PFB_SSL_CA_CERT_PATH}:\\" \
            '	:umask=022:' \
            '' \
            'standard:\' \
            '	:tc=default:' \
            '' \
            'default:\' \
            '	:setenv=X=1:' \
            > "${_a15_dir}/expected.conf"
    }
    cleanup() { rm -rf "${_a15_dir}"; _lc_unset_box; unset _a15_dir; }
    Before 'setup'
    After  'cleanup'

    It 'before-state: two records are both labelled default'
      The value "$(grep -c '^default:' "${PFB_LOGIN_CONF}")" should equal 2
    End

    It 'patches only the FIRST default record; the second is byte-untouched'
      When run sh "${HOOK}" login-ca-sync
      The status should be success
      The stderr should include "INFO"
      The value "$(_lc_cmp "${PFB_LOGIN_CONF}" "${_a15_dir}/expected.conf")" should equal 0
      The contents of file "${PFB_LOGIN_CONF}" should include "setenv=X=1:"
    End
End

Describe 'login-ca-sync — 16: login.conf missing entirely'
    setup() {
        _a16_dir="$(mktemp -d "${SHELLSPEC_TMPBASE:-/tmp}/lc_missing.XXXXXX")"
        _lc_box "${_a16_dir}"
        rm -f "${PFB_LOGIN_CONF}"
    }
    cleanup() { rm -rf "${_a16_dir}"; _lc_unset_box; unset _a16_dir; }
    Before 'setup'
    After  'cleanup'

    It 'refuses without conjuring a file that was never there'
      When run sh "${HOOK}" login-ca-sync
      The status should not be success
      The path "${PFB_LOGIN_CONF}" should not be exist
    End
End

Describe 'login-ca-sync — 17: cap_mkdb smoke (guarded)'
    setup() {
        _a17_dir="$(mktemp -d "${SHELLSPEC_TMPBASE:-/tmp}/lc_db_smoke.XXXXXX")"
        _lc_box "${_a17_dir}"
        _lc_stage stock
    }
    cleanup() { rm -rf "${_a17_dir}"; _lc_unset_box; unset _a17_dir; }
    Before 'setup'
    After  'cleanup'

    It 'compiles login.conf.db after a successful add, when cap_mkdb is on PATH'
      Skip if 'cap_mkdb not on PATH' no_cap_mkdb
      When run sh "${HOOK}" login-ca-sync
      The status should be success
      The stderr should include "INFO"
      The path "${PFB_LOGIN_CONF}.db" should be exist
    End
End

# ── REMOVE (login-ca-revoke) ─────────────────────────────────────────────────

Describe 'login-ca-revoke — 18: strips ours, leaves siblings in order'
    setup() {
        _r18_dir="$(mktemp -d "${SHELLSPEC_TMPBASE:-/tmp}/lc_revoke_multi.XXXXXX")"
        _lc_box "${_r18_dir}"
        _lc_stage multi_value
        _lc_expected multi_value_removed "${_r18_dir}/expected.conf"
    }
    cleanup() { rm -rf "${_r18_dir}"; _lc_unset_box; unset _r18_dir; }
    Before 'setup'
    After  'cleanup'

    It 'before-state: setenv carries BLOCKSIZE=K, ours, and OTHERVAR=Y in order'
      The contents of file "${PFB_LOGIN_CONF}" should include "setenv=BLOCKSIZE=K,SSL_CA_CERT_PATH="
    End

    It 'removes only our entry; BLOCKSIZE=K and OTHERVAR=Y survive in order'
      When run sh "${HOOK}" login-ca-revoke
      The status should be success
      The stderr should include "INFO"
      The value "$(_lc_cmp "${PFB_LOGIN_CONF}" "${_r18_dir}/expected.conf")" should equal 0
    End
End

Describe 'login-ca-revoke — 19: ours is the only value, own line: line removed cleanly'
    setup() {
        _r19_dir="$(mktemp -d "${SHELLSPEC_TMPBASE:-/tmp}/lc_revoke_only.XXXXXX")"
        _lc_box "${_r19_dir}"
        _lc_stage only_ours
        _lc_expected only_ours_removed "${_r19_dir}/expected.conf"
    }
    cleanup() { rm -rf "${_r19_dir}"; _lc_unset_box; unset _r19_dir; }
    Before 'setup'
    After  'cleanup'

    It 'removes the whole setenv line; continuations on either side stay valid'
      When run sh "${HOOK}" login-ca-revoke
      The status should be success
      The stderr should include "INFO"
      The value "$(_lc_cmp "${PFB_LOGIN_CONF}" "${_r19_dir}/expected.conf")" should equal 0
      The value "$(_lc_db_ok && echo ok || echo bad)" should equal ok
    End
End

Describe 'login-ca-revoke — 20: ours is the only value AND the record'\''s last line'
    setup() {
        _r20_dir="$(mktemp -d "${SHELLSPEC_TMPBASE:-/tmp}/lc_revoke_lastline.XXXXXX")"
        _lc_box "${_r20_dir}"
        _lc_stage only_ours_last_line
        _lc_expected only_ours_removed "${_r20_dir}/expected.conf"
    }
    cleanup() { rm -rf "${_r20_dir}"; _lc_unset_box; unset _r20_dir; }
    Before 'setup'
    After  'cleanup'

    It 'before-state: the setenv line is the class'"'"'s final line (no continuation)'
      The value "$(sed -n '7p' "${PFB_LOGIN_CONF}")" should include "setenv=SSL_CA_CERT_PATH="
    End

    It 'removes the line and strips the now-unneeded trailing backslash from the new last line'
      When run sh "${HOOK}" login-ca-revoke
      The status should be success
      The stderr should include "INFO"
      The value "$(_lc_cmp "${PFB_LOGIN_CONF}" "${_r20_dir}/expected.conf")" should equal 0
    End
End

Describe 'login-ca-revoke — 21: ours is the only value, shared line: field spliced out'
    setup() {
        _r21_dir="$(mktemp -d "${SHELLSPEC_TMPBASE:-/tmp}/lc_revoke_shared.XXXXXX")"
        _lc_box "${_r21_dir}"
        _lc_stage shared_only_ours
        _lc_expected shared_only_ours_removed "${_r21_dir}/expected.conf"
    }
    cleanup() { rm -rf "${_r21_dir}"; _lc_unset_box; unset _r21_dir; }
    Before 'setup'
    After  'cleanup'

    It 'splices out only the setenv field; a=1/b=2 remain on their shared line'
      When run sh "${HOOK}" login-ca-revoke
      The status should be success
      The stderr should include "INFO"
      The value "$(_lc_cmp "${PFB_LOGIN_CONF}" "${_r21_dir}/expected.conf")" should equal 0
      The contents of file "${PFB_LOGIN_CONF}" should include "a=1:b=2:"
    End
End

Describe 'login-ca-revoke — 22: stock (never had ours), byte-identical no-op'
    setup() {
        _r22_dir="$(mktemp -d "${SHELLSPEC_TMPBASE:-/tmp}/lc_revoke_absent.XXXXXX")"
        _lc_box "${_r22_dir}"
        _lc_stage stock
        cp "${PFB_LOGIN_CONF}" "${_r22_dir}/before.conf"
    }
    cleanup() { rm -rf "${_r22_dir}"; _lc_unset_box; unset _r22_dir; }
    Before 'setup'
    After  'cleanup'

    It 'returns success without changing a file that never had our value, no INFO'
      When run sh "${HOOK}" login-ca-revoke
      The status should be success
      The stderr should not include "INFO"
      The value "$(_lc_cmp "${PFB_LOGIN_CONF}" "${_r22_dir}/before.conf")" should equal 0
    End
End

Describe 'login-ca-revoke — 23: still removes with an EMPTY CA directory'
    setup() {
        _r23_dir="$(mktemp -d "${SHELLSPEC_TMPBASE:-/tmp}/lc_revoke_unpopulated.XXXXXX")"
        _lc_box "${_r23_dir}"
        _lc_stage multi_value
        _lc_expected multi_value_removed "${_r23_dir}/expected.conf"
        rm -f "${PFB_SSL_CA_CERT_PATH}"/*
    }
    cleanup() { rm -rf "${_r23_dir}"; _lc_unset_box; unset _r23_dir; }
    Before 'setup'
    After  'cleanup'

    It 'still removes the line -- an admin opting out must not be trapped by a now-empty CA dir'
      When run sh "${HOOK}" login-ca-revoke
      The status should be success
      The stderr should include "INFO"
      The value "$(_lc_cmp "${PFB_LOGIN_CONF}" "${_r23_dir}/expected.conf")" should equal 0
    End
End

Describe 'login-ca-revoke — 24: symlinked login.conf refuses, target untouched'
    setup() {
        _r24_dir="$(mktemp -d "${SHELLSPEC_TMPBASE:-/tmp}/lc_revoke_symlink.XXXXXX")"
        _lc_box "${_r24_dir}"
        _lc_stage stock_with_ca
        mv "${PFB_LOGIN_CONF}" "${_r24_dir}/real.conf"
        ln -s "${_r24_dir}/real.conf" "${PFB_LOGIN_CONF}"
        cp "${_r24_dir}/real.conf" "${_r24_dir}/before.conf"
    }
    cleanup() { rm -rf "${_r24_dir}"; _lc_unset_box; unset _r24_dir; }
    Before 'setup'
    After  'cleanup'

    It 'leaves the symlink target byte-unchanged (SSL_CA_CERT_PATH still present), path still a symlink'
      When run sh "${HOOK}" login-ca-revoke
      The status should not be success
      The path "${PFB_LOGIN_CONF}" should be symlink
      The value "$(_lc_cmp "${_r24_dir}/real.conf" "${_r24_dir}/before.conf")" should equal 0
      The contents of file "${_r24_dir}/real.conf" should include "SSL_CA_CERT_PATH="
    End
End

Describe 'login-ca-revoke — 25: login.conf missing entirely, success'
    setup() {
        _r25_dir="$(mktemp -d "${SHELLSPEC_TMPBASE:-/tmp}/lc_revoke_missing.XXXXXX")"
        _lc_box "${_r25_dir}"
        rm -f "${PFB_LOGIN_CONF}"
    }
    cleanup() { rm -rf "${_r25_dir}"; _lc_unset_box; unset _r25_dir; }
    Before 'setup'
    After  'cleanup'

    It 'reports success without conjuring a file that was never there'
      When run sh "${HOOK}" login-ca-revoke
      The status should be success
      The path "${PFB_LOGIN_CONF}" should not be exist
    End
End

Describe 'login-ca-revoke — 26: a foreign value is never stripped'
    setup() {
        _r26_dir="$(mktemp -d "${SHELLSPEC_TMPBASE:-/tmp}/lc_revoke_foreign.XXXXXX")"
        _lc_box "${_r26_dir}"
        _lc_stage different_value
        cp "${PFB_LOGIN_CONF}" "${_r26_dir}/before.conf"
    }
    cleanup() { rm -rf "${_r26_dir}"; _lc_unset_box; unset _r26_dir; }
    Before 'setup'
    After  'cleanup'

    It 'leaves login.conf byte-identical, no INFO -- the value present is not ours'
      When run sh "${HOOK}" login-ca-revoke
      The status should be success
      The stderr should not include "INFO"
      The value "$(_lc_cmp "${PFB_LOGIN_CONF}" "${_r26_dir}/before.conf")" should equal 0
    End
End
