#shellcheck shell=sh
# migrate-channel.sh — move an installed pfBlockerNG onto one of the four pkg
# channels (issue #2148).
#
# WHY A PROGRAMMABLE pkg STUB: every behaviour worth pinning here is a decision
# about pkg STATE — which identity is installed, which repo it came from, what the
# target catalogue offers, and what the box looks like afterwards. A stub that only
# logged its arguments could prove the script CALLED something; it could not prove
# the script refuses to mutate a box it cannot verify, or that a downgrade actually
# lands the older version. So the stub below keeps real state in three tab-separated
# files (installed / catalog / payload) and mutates it, and the examples assert the
# resulting state, not the command line.
#
# Behavioural contracts pinned here:
#   usage        — --channel is mandatory; `release`, an unknown name and a
#                  wrong-case name are all rejected (exit 2) with pkg never invoked.
#   pre-flight   — an unsubscribed target, or a second project conf still on the
#                  box, fails (exit 4) BEFORE pkg is invoked at all.
#   inventory    — none / more than one / an unrecognised pfBlockerNG identity
#                  fails (exit 3) before any mutation.
#   availability — a target catalogue that does not offer the canonical package
#                  fails (exit 4) with the installed package untouched.
#   no-op        — canonical already on the target repo reports and mutates nothing.
#   legacy       — a suffixed identity (-devel, and the historical -NIGHTLY
#                  spelling) is deleted and replaced by the canonical package from
#                  the target repo.
#   reverse      — a repository-qualified `install -f` lands an OLDER version when
#                  moving to a slower channel.
#   verification — a mutation that leaves the wrong repo, an incomplete payload, or
#                  a lost config section fails (exit 6) instead of reporting success.
#
# Before-and-after mandate (CLAUDE.md): every migrating example asserts the
# installed identity/version/repo BEFORE the run, so green proves the migration
# caused the change rather than merely matching a pre-existing state.
#
# Tip: run with `shellspec tests/shell/migrate_channel_spec.sh` from the repo root.

SCRIPT="${PFB_ROOT}/scripts/migrate-channel.sh"

TAB="$(printf '\t')"

# ── the programmable pkg stub ─────────────────────────────────────────────────
#
# State files under $PFB_STUB_DIR:
#   installed  name<TAB>version<TAB>repo   — the box's installed packages
#   catalog    repo<TAB>name<TAB>version   — what each repo offers
#   payload    absolute path per line      — the canonical package's file manifest
#   calls.log  one line per invocation     — created only when pkg is actually run
#
# Knobs (env, all optional): PFB_STUB_FAIL_INSTALL, PFB_STUB_FAIL_DELETE,
# PFB_STUB_INSTALL_REPO (land in a different repo than requested),
# PFB_STUB_SKIP_PAYLOAD (a manifest path install deliberately does not create),
# PFB_STUB_DROP_CONFIG (install wipes the config section).
_write_pkg_stub() {
    cat > "$1" <<'STUB'
#!/bin/sh
set -u
_d="${PFB_STUB_DIR}"
_root="${PFBLOCKERNG_ROOT%/}"
printf '%s\n' "$*" >> "${_d}/calls.log"
_tab="$(printf '\t')"

_field() { # _field <file> <key-col> <key> <want-col>
    awk -F"${_tab}" -v k="$3" -v kc="$2" -v wc="$4" '$kc == k { print $wc; found=1 } END { exit !found }' "$1"
}

_cmd="$1"; shift
case "${_cmd}" in
query)
    if [ "$1" = "-g" ]; then
        shift
        _prefix="${2%\*}"
        awk -F"${_tab}" -v p="${_prefix}" 'index($1, p) == 1 { print $1; found=1 } END { exit !found }' "${_d}/installed"
        exit $?
    fi
    case "$1" in
    '%R') _field "${_d}/installed" 1 "$2" 3 ;;
    '%v') _field "${_d}/installed" 1 "$2" 2 ;;
    *) exit 64 ;;
    esac
    exit $?
    ;;
rquery)
    [ "$1" = "-r" ] || exit 64
    _repo="$2"; shift 2
    [ "$1" = '%v' ] || exit 64
    awk -F"${_tab}" -v r="${_repo}" -v n="$2" '$1 == r && $2 == n { print $3; found=1 } END { exit !found }' "${_d}/catalog"
    exit $?
    ;;
delete)
    [ "${PFB_STUB_FAIL_DELETE:-0}" = "1" ] && exit 1
    shift # -y
    awk -F"${_tab}" -v n="$1" '$1 != n' "${_d}/installed" > "${_d}/installed.new"
    mv "${_d}/installed.new" "${_d}/installed"
    exit 0
    ;;
install)
    [ "${PFB_STUB_FAIL_INSTALL:-0}" = "1" ] && exit 1
    while [ $# -gt 0 ]; do
        case "$1" in
        -f | -y) shift ;;
        -r) _repo="$2"; shift 2 ;;
        *) _name="$1"; shift ;;
        esac
    done
    # Real `pkg install` resolves the HIGHEST version the repo offers, and a catalogue
    # routinely offers several (retention + containment). `sort -V` stands in for pkg's
    # component-wise numeric ordering.
    _ver="$(awk -F"${_tab}" -v r="${_repo}" -v n="${_name}" '$1 == r && $2 == n { print $3 }' "${_d}/catalog" | sort -V | tail -n 1)"
    [ -n "${_ver}" ] || exit 1
    awk -F"${_tab}" -v n="${_name}" '$1 != n' "${_d}/installed" > "${_d}/installed.new"
    printf '%s\t%s\t%s\n' "${_name}" "${_ver}" "${PFB_STUB_INSTALL_REPO:-${_repo}}" >> "${_d}/installed.new"
    mv "${_d}/installed.new" "${_d}/installed"
    while IFS= read -r _p; do
        [ -n "${_p}" ] || continue
        [ "${_p}" = "${PFB_STUB_SKIP_PAYLOAD:-}" ] && continue
        mkdir -p "${_root}$(dirname "${_p}")"
        true > "${_root}${_p}"
    done < "${_d}/payload"
    if [ "${PFB_STUB_DROP_CONFIG:-0}" = "1" ]; then
        printf '<pfsense></pfsense>\n' > "${_root}/cf/conf/config.xml"
    fi
    exit 0
    ;;
info)
    [ "$1" = "-l" ] || exit 64
    _v="$(_field "${_d}/installed" 1 "$2" 2)" || exit 70
    printf '%s-%s:\n' "$2" "${_v}"
    while IFS= read -r _p; do
        [ -n "${_p}" ] || continue
        printf '\t%s\n' "${_p}"
    done < "${_d}/payload"
    exit 0
    ;;
version)
    # `pkg version -t <a> <b>` -> '>' | '=' | '<'. The script uses it to pick the build
    # `install` will resolve, so the two must agree — both go through `sort -V` here.
    [ "$1" = "-t" ] || exit 64
    [ "${PFB_STUB_BREAK_VERSION:-0}" = "1" ] && exit 64
    if [ "$2" = "$3" ]; then
        printf '=\n'
    elif [ "$(printf '%s\n%s\n' "$2" "$3" | sort -V | tail -n 1)" = "$2" ]; then
        printf '>\n'
    else
        printf '<\n'
    fi
    exit 0
    ;;
*)
    exit 64
    ;;
esac
STUB
    chmod +x "$1"
}

# Stand up a stubbed box in a fresh tmpdir. $1 = the conf(s) to place, as a
# space-separated list of channel conf basenames. Installed packages, catalogue
# rows and the payload manifest are seeded by the per-example helpers below.
_make_box() {
    _mb_dir="$(mktemp -d "${SHELLSPEC_TMPBASE:-/tmp}/migrate_ch.XXXXXX")"
    mkdir -p "${_mb_dir}/usr/local/etc/pkg/repos" "${_mb_dir}/cf/conf" "${_mb_dir}/stub"
    true > "${_mb_dir}/stub/installed"
    true > "${_mb_dir}/stub/catalog"
    true > "${_mb_dir}/stub/payload"
    _write_pkg_stub "${_mb_dir}/stub/pkg"
    printf '<pfsense><installedpackages><pfblockerng><enable>on</enable></pfblockerng></installedpackages></pfsense>\n' \
        > "${_mb_dir}/cf/conf/config.xml"

    BOX="${_mb_dir}"
    PFBLOCKERNG_ROOT="${_mb_dir}"
    PKG_BIN="${_mb_dir}/stub/pkg"
    PFB_STUB_DIR="${_mb_dir}/stub"
    export PFBLOCKERNG_ROOT PKG_BIN PFB_STUB_DIR
    unset _mb_dir
}

_unset_box() {
    unset PFBLOCKERNG_ROOT PKG_BIN PFB_STUB_DIR BOX \
          PFB_STUB_FAIL_INSTALL PFB_STUB_FAIL_DELETE PFB_STUB_INSTALL_REPO \
          PFB_STUB_SKIP_PAYLOAD PFB_STUB_DROP_CONFIG PFB_STUB_BREAK_VERSION
}

_subscribe()   { true > "${BOX}/usr/local/etc/pkg/repos/pfblockerng-$1.conf"; }
_legacy_conf() { true > "${BOX}/usr/local/etc/pkg/repos/pfblockerng.conf"; }
_install()     { printf '%s\t%s\t%s\n' "$1" "$2" "$3" >> "${PFB_STUB_DIR}/installed"; }
_publish()     { printf '%s\t%s\t%s\n' "$1" "$2" "$3" >> "${PFB_STUB_DIR}/catalog"; }
_manifest()    { printf '%s\n' "$@" >> "${PFB_STUB_DIR}/payload"; }

# The oracles the examples assert on.
_installed_names()   { cut -f1 "${PFB_STUB_DIR}/installed" | tr '\n' ' ' | sed 's/ *$//'; }
_installed_version() { awk -F"${TAB}" -v n="$1" '$1 == n { print $2 }' "${PFB_STUB_DIR}/installed"; }
_installed_repo()    { awk -F"${TAB}" -v n="$1" '$1 == n { print $3 }' "${PFB_STUB_DIR}/installed"; }
_pkg_calls()         { cat "${PFB_STUB_DIR}/calls.log" 2>/dev/null || true; }

# ── USAGE: the target channel is explicit or the script refuses ───────────────
#
# There is deliberately no default: the whole point of the ticket is that a box
# ends up on the channel its operator NAMED. A silent default would be the exact
# "existing configured users are never silently moved" failure.

Describe 'migrate-channel.sh — the target channel is mandatory and exact'
    setup() { _make_box; _subscribe stable; }
    cleanup() { rm -rf "${BOX}"; _unset_box; }
    Before 'setup'
    After  'cleanup'

    It 'refuses to run with no --channel and never invokes pkg'
      When run sh "${SCRIPT}"
      The status should equal 2
      The stderr should include "--channel is required"
      The stderr should include "Usage:"
      The path "${PFB_STUB_DIR}/calls.log" should not be exist
    End

    It 'rejects the legacy shared repo as a target'
      When run sh "${SCRIPT}" --channel release
      The status should equal 2
      The stderr should include "'release' is the legacy shared repo"
      The path "${PFB_STUB_DIR}/calls.log" should not be exist
    End

    It 'rejects a wrong-case channel rather than guessing'
      When run sh "${SCRIPT}" --channel Stable
      The status should equal 2
      The stderr should include "unknown channel 'Stable'"
    End

    It 'rejects an unknown channel'
      When run sh "${SCRIPT}" --channel devel
      The status should equal 2
      The stderr should include "unknown channel 'devel'"
    End

    It 'prints usage for --help without touching the box'
      When run sh "${SCRIPT}" --help
      The status should be success
      The stdout should include "add-repo.sh --channel <ch>"
      The path "${PFB_STUB_DIR}/calls.log" should not be exist
    End
End

# ── PRE-FLIGHT: the repository configuration must already match ───────────────
#
# add-repo.sh owns repository configuration; this script owns the installed
# package. Running them out of order is the mistake a user actually makes, so it
# must fail loudly and BEFORE pkg is invoked — not half-way through a delete.

Describe 'migrate-channel.sh — the box must already be subscribed to the target'
    setup() { _make_box; _install "pfSense-pkg-pfBlockerNG-devel" "3.2.15" "pfblockerng"; _legacy_conf; }
    cleanup() { rm -rf "${BOX}"; _unset_box; }
    Before 'setup'
    After  'cleanup'

    It 'before-state: the box carries the legacy identity and only the legacy conf'
      The value "$(_installed_names)" should equal "pfSense-pkg-pfBlockerNG-devel"
      The path "${BOX}/usr/local/etc/pkg/repos/pfblockerng-edge.conf" should not be exist
    End

    It 'fails before invoking pkg when the target channel is not subscribed'
      When run sh "${SCRIPT}" --channel edge
      The status should equal 4
      The stderr should include "not subscribed to the edge channel"
      The stderr should include "add-repo.sh --channel edge"
      The path "${PFB_STUB_DIR}/calls.log" should not be exist
      The value "$(_installed_names)" should equal "pfSense-pkg-pfBlockerNG-devel"
    End
End

Describe 'migrate-channel.sh — exactly one project repository may be configured'
    # A second enabled project repo is not untidiness: every project repo shares
    # priority 100 and pkg does not order across equal-priority repositories, so
    # whatever this script installs could be silently replaced on the next upgrade.
    setup() {
        _make_box
        _subscribe testing
        _legacy_conf
        _install "pfSense-pkg-pfBlockerNG" "4.0.0" "pfblockerng"
        _publish "pfblockerng-testing" "pfSense-pkg-pfBlockerNG" "4.0.1"
    }
    cleanup() { rm -rf "${BOX}"; _unset_box; }
    Before 'setup'
    After  'cleanup'

    It 'before-state: both the testing conf and the legacy conf are present'
      The path "${BOX}/usr/local/etc/pkg/repos/pfblockerng-testing.conf" should be exist
      The path "${BOX}/usr/local/etc/pkg/repos/pfblockerng.conf" should be exist
    End

    It 'fails before invoking pkg and names the stray conf'
      When run sh "${SCRIPT}" --channel testing
      The status should equal 4
      The stderr should include "another pfBlockerNG repository is still configured"
      The stderr should include "pfblockerng.conf"
      The path "${PFB_STUB_DIR}/calls.log" should not be exist
      The value "$(_installed_repo pfSense-pkg-pfBlockerNG)" should equal "pfblockerng"
    End
End

# ── INVENTORY: refuse any installed state the script cannot reason about ──────

Describe 'migrate-channel.sh — nothing installed'
    setup() { _make_box; _subscribe stable; _publish "pfblockerng-stable" "pfSense-pkg-pfBlockerNG" "4.0.0"; }
    cleanup() { rm -rf "${BOX}"; _unset_box; }
    Before 'setup'
    After  'cleanup'

    It 'reports that there is nothing to migrate and installs nothing'
      When run sh "${SCRIPT}" --channel stable
      The status should equal 3
      The stderr should include "no pfBlockerNG package is installed"
      The value "$(_installed_names)" should equal ""
      The value "$(_pkg_calls)" should not include "install"
    End
End

Describe 'migrate-channel.sh — a mixed installation'
    setup() {
        _make_box
        _subscribe stable
        _install "pfSense-pkg-pfBlockerNG" "4.0.0" "pfblockerng"
        _install "pfSense-pkg-pfBlockerNG-devel" "3.2.15" "pfblockerng"
        _publish "pfblockerng-stable" "pfSense-pkg-pfBlockerNG" "4.0.0"
    }
    cleanup() { rm -rf "${BOX}"; _unset_box; }
    Before 'setup'
    After  'cleanup'

    It 'refuses to guess which one to keep, and mutates nothing'
      When run sh "${SCRIPT}" --channel stable
      The status should equal 3
      The stderr should include "more than one pfBlockerNG package is installed"
      The stderr should include "pfSense-pkg-pfBlockerNG-devel"
      The value "$(_installed_names)" should equal "pfSense-pkg-pfBlockerNG pfSense-pkg-pfBlockerNG-devel"
      The value "$(_pkg_calls)" should not include "delete"
    End
End

Describe 'migrate-channel.sh — an identity the project never shipped'
    setup() {
        _make_box
        _subscribe stable
        _install "pfSense-pkg-pfBlockerNG-fork" "9.9.9" "somewhere"
        _publish "pfblockerng-stable" "pfSense-pkg-pfBlockerNG" "4.0.0"
    }
    cleanup() { rm -rf "${BOX}"; _unset_box; }
    Before 'setup'
    After  'cleanup'

    It 'refuses to migrate a package whose configuration it cannot reason about'
      When run sh "${SCRIPT}" --channel stable
      The status should equal 3
      The stderr should include "unrecognised pfBlockerNG identity"
      The value "$(_installed_names)" should equal "pfSense-pkg-pfBlockerNG-fork"
      The value "$(_pkg_calls)" should not include "delete"
    End
End

# ── AVAILABILITY: never delete what cannot be replaced ────────────────────────

Describe 'migrate-channel.sh — the target catalogue offers nothing'
    setup() {
        _make_box
        _subscribe edge
        _install "pfSense-pkg-pfBlockerNG-devel" "3.2.15" "pfblockerng"
    }
    cleanup() { rm -rf "${BOX}"; _unset_box; }
    Before 'setup'
    After  'cleanup'

    It 'before-state: the legacy identity is installed'
      The value "$(_installed_names)" should equal "pfSense-pkg-pfBlockerNG-devel"
    End

    It 'fails on the catalogue read and leaves the installed package alone'
      When run sh "${SCRIPT}" --channel edge
      The status should equal 4
      The stderr should include "does not offer pfSense-pkg-pfBlockerNG"
      The value "$(_installed_names)" should equal "pfSense-pkg-pfBlockerNG-devel"
      The value "$(_pkg_calls)" should not include "delete"
      The stdout should include "Installed: pfSense-pkg-pfBlockerNG-devel"
    End
End

# ── NO-OP: already there ──────────────────────────────────────────────────────

Describe 'migrate-channel.sh — already on the requested channel'
    setup() {
        _make_box
        _subscribe edge
        _install "pfSense-pkg-pfBlockerNG" "4.1.0.a1" "pfblockerng-edge"
        _publish "pfblockerng-edge" "pfSense-pkg-pfBlockerNG" "4.1.0.a1"
    }
    cleanup() { rm -rf "${BOX}"; _unset_box; }
    Before 'setup'
    After  'cleanup'

    It 'reports the no-op and performs no package operation'
      When run sh "${SCRIPT}" --channel edge
      The status should be success
      The stdout should include "Already on the edge channel"
      The value "$(_pkg_calls)" should not include "install"
      The value "$(_pkg_calls)" should not include "delete"
      The value "$(_installed_version pfSense-pkg-pfBlockerNG)" should equal "4.1.0.a1"
    End
End

# ── LEGACY SUFFIXED IDENTITY -> CANONICAL ─────────────────────────────────────

Describe 'migrate-channel.sh — pfSense-pkg-pfBlockerNG-devel onto stable'
    setup() {
        _make_box
        _subscribe stable
        _install "pfSense-pkg-pfBlockerNG-devel" "3.2.15" "pfblockerng"
        _publish "pfblockerng-stable" "pfSense-pkg-pfBlockerNG" "4.0.0"
        _manifest "/usr/local/pkg/pfblockerng/pfblockerng.inc"
    }
    cleanup() { rm -rf "${BOX}"; _unset_box; }
    Before 'setup'
    After  'cleanup'

    It 'before-state: the box carries the retired -devel identity from the legacy repo'
      The value "$(_installed_names)" should equal "pfSense-pkg-pfBlockerNG-devel"
      The value "$(_installed_repo pfSense-pkg-pfBlockerNG-devel)" should equal "pfblockerng"
    End

    It 'replaces it with the canonical package from the stable repo'
      When run sh "${SCRIPT}" --channel stable
      The status should be success
      The stdout should include "Removing the legacy identity pfSense-pkg-pfBlockerNG-devel"
      The stdout should include "Done"
      The value "$(_installed_names)" should equal "pfSense-pkg-pfBlockerNG"
      The value "$(_installed_repo pfSense-pkg-pfBlockerNG)" should equal "pfblockerng-stable"
      The value "$(_installed_version pfSense-pkg-pfBlockerNG)" should equal "4.0.0"
      The value "$(_pkg_calls)" should include "delete -y pfSense-pkg-pfBlockerNG-devel"
      The value "$(_pkg_calls)" should include "install -y -r pfblockerng-stable pfSense-pkg-pfBlockerNG"
    End
End

Describe 'migrate-channel.sh — the historical -NIGHTLY spelling is recognised'
    # ADR-18 shipped the nightly identity upper-cased. Dropping it from the shipped
    # set would read those boxes as an unknown identity and strand them.
    setup() {
        _make_box
        _subscribe nightly
        _install "pfSense-pkg-pfBlockerNG-NIGHTLY" "20260601" "pfblockerng-nightly"
        _publish "pfblockerng-nightly" "pfSense-pkg-pfBlockerNG" "20260807"
        _manifest "/usr/local/pkg/pfblockerng/pfblockerng.inc"
    }
    cleanup() { rm -rf "${BOX}"; _unset_box; }
    Before 'setup'
    After  'cleanup'

    It 'before-state: the upper-cased legacy identity is installed'
      The value "$(_installed_names)" should equal "pfSense-pkg-pfBlockerNG-NIGHTLY"
    End

    It 'migrates it to the canonical nightly package'
      When run sh "${SCRIPT}" --channel nightly
      The status should be success
      The value "$(_installed_names)" should equal "pfSense-pkg-pfBlockerNG"
      The value "$(_installed_version pfSense-pkg-pfBlockerNG)" should equal "20260807"
      The stdout should include "Removing the legacy identity pfSense-pkg-pfBlockerNG-NIGHTLY"
      The value "$(_pkg_calls)" should include "delete -y pfSense-pkg-pfBlockerNG-NIGHTLY"
    End
End

# ── REVERSE MOVEMENT: a repository-qualified downgrade ────────────────────────

Describe 'migrate-channel.sh — moving back from edge to stable installs the older build'
    # Ordinary `pkg upgrade` will not do this: the target version is LOWER and it
    # lives in a different repository. `pkg install -f -r <repo>` is the proven form.
    setup() {
        _make_box
        _subscribe stable
        _install "pfSense-pkg-pfBlockerNG" "4.1.0.a1" "pfblockerng-edge"
        _publish "pfblockerng-stable" "pfSense-pkg-pfBlockerNG" "4.0.0"
        _manifest "/usr/local/pkg/pfblockerng/pfblockerng.inc"
    }
    cleanup() { rm -rf "${BOX}"; _unset_box; }
    Before 'setup'
    After  'cleanup'

    It 'before-state: the newer edge build is installed from the edge repo'
      The value "$(_installed_version pfSense-pkg-pfBlockerNG)" should equal "4.1.0.a1"
      The value "$(_installed_repo pfSense-pkg-pfBlockerNG)" should equal "pfblockerng-edge"
    End

    It 'forces the reinstall from the stable repo and lands the lower version'
      When run sh "${SCRIPT}" --channel stable
      The status should be success
      The value "$(_installed_version pfSense-pkg-pfBlockerNG)" should equal "4.0.0"
      The value "$(_installed_repo pfSense-pkg-pfBlockerNG)" should equal "pfblockerng-stable"
      The stdout should include "Reinstalling pfSense-pkg-pfBlockerNG from pfblockerng-stable (repository-qualified)"
      The value "$(_pkg_calls)" should include "install -f -y -r pfblockerng-stable pfSense-pkg-pfBlockerNG"
      The value "$(_pkg_calls)" should not include "delete"
    End
End

Describe 'migrate-channel.sh — switching between channels serving the identical artifact'
    # Stable, testing and edge intentionally carry the same bytes for one tagged
    # release. The installed VERSION is then unchanged, but the subscription the
    # package upgrades within must still move — that is the whole operation.
    setup() {
        _make_box
        _subscribe testing
        _install "pfSense-pkg-pfBlockerNG" "4.0.0" "pfblockerng-edge"
        _publish "pfblockerng-testing" "pfSense-pkg-pfBlockerNG" "4.0.0"
        _manifest "/usr/local/pkg/pfblockerng/pfblockerng.inc"
    }
    cleanup() { rm -rf "${BOX}"; _unset_box; }
    Before 'setup'
    After  'cleanup'

    It 'before-state: the identical version is installed, but from the edge repo'
      The value "$(_installed_version pfSense-pkg-pfBlockerNG)" should equal "4.0.0"
      The value "$(_installed_repo pfSense-pkg-pfBlockerNG)" should equal "pfblockerng-edge"
    End

    It 'keeps the version and moves the origin repository to testing'
      When run sh "${SCRIPT}" --channel testing
      The status should be success
      The value "$(_installed_version pfSense-pkg-pfBlockerNG)" should equal "4.0.0"
      The value "$(_installed_repo pfSense-pkg-pfBlockerNG)" should equal "pfblockerng-testing"
      The stdout should include "Reinstalling pfSense-pkg-pfBlockerNG from pfblockerng-testing (repository-qualified)"
    End
End

Describe 'migrate-channel.sh — a catalogue offering several builds'
    # The ordinary shape, not an edge case: retention keeps the newest few builds and
    # containment back-fills a faster channel with its slower channels' builds, so a
    # channel catalogue routinely offers more than one version of the canonical
    # package. `pkg install` resolves the HIGHEST, so the script must predict the same
    # one — naming any other would fail its own post-migration version check and report
    # a successful migration as broken.
    setup() {
        _make_box
        _subscribe edge
        _install "pfSense-pkg-pfBlockerNG-devel" "3.2.15" "pfblockerng"
        # Deliberately NOT in ascending catalogue order: taking the first line would
        # pick 4.0.0, and taking the last would pick 3.9.0.
        _publish "pfblockerng-edge" "pfSense-pkg-pfBlockerNG" "4.0.0"
        _publish "pfblockerng-edge" "pfSense-pkg-pfBlockerNG" "4.1.0.a1"
        _publish "pfblockerng-edge" "pfSense-pkg-pfBlockerNG" "3.9.0"
        _manifest "/usr/local/pkg/pfblockerng/pfblockerng.inc"
    }
    cleanup() { rm -rf "${BOX}"; _unset_box; }
    Before 'setup'
    After  'cleanup'

    It 'before-state: the edge catalogue offers three builds, unordered'
      The value "$(wc -l < "${PFB_STUB_DIR}/catalog" | tr -d ' ')" should equal "3"
    End

    It 'targets the highest build the catalogue offers, not the first one listed'
      When run sh "${SCRIPT}" --channel edge
      The status should be success
      The stdout should include "Target:    pfSense-pkg-pfBlockerNG-4.1.0.a1"
      The value "$(_installed_version pfSense-pkg-pfBlockerNG)" should equal "4.1.0.a1"
      The value "$(_installed_repo pfSense-pkg-pfBlockerNG)" should equal "pfblockerng-edge"
      The stdout should include "Done"
    End

    It 'names the comparator when it cannot answer, instead of dying on the symptom'
      # A degraded `pkg version -t` would silently reduce the loop to "keep the first
      # line" — the exact behaviour this replaced — and the migration would then fail
      # its own post-install version check with no hint as to why.
      PFB_STUB_BREAK_VERSION=1
      export PFB_STUB_BREAK_VERSION
      When run sh "${SCRIPT}" --channel edge
      The status should equal 4
      The stdout should include "Installed: pfSense-pkg-pfBlockerNG-devel"
      The stderr should include "gave no usable answer comparing"
      The value "$(_pkg_calls)" should not include "install"
      The value "$(_installed_names)" should equal "pfSense-pkg-pfBlockerNG-devel"
    End
End

# ── FAILURE CANNOT REPORT SUCCESS ─────────────────────────────────────────────

Describe 'migrate-channel.sh — the replacement install fails after the delete'
    setup() {
        _make_box
        _subscribe stable
        _install "pfSense-pkg-pfBlockerNG-devel" "3.2.15" "pfblockerng"
        _publish "pfblockerng-stable" "pfSense-pkg-pfBlockerNG" "4.0.0"
        PFB_STUB_FAIL_INSTALL=1
        export PFB_STUB_FAIL_INSTALL
    }
    cleanup() { rm -rf "${BOX}"; _unset_box; }
    Before 'setup'
    After  'cleanup'

    It 'reports the empty box and hands over a command that actually finishes the job'
      # NOT "re-run this script": with nothing installed it exits 3 ("nothing to
      # migrate") — see the "nothing installed" Describe above — so a re-run would
      # strand the operator at the one moment the box has no pfBlockerNG at all.
      When run sh "${SCRIPT}" --channel stable
      The status should equal 5
      The stdout should include "Removing the legacy identity pfSense-pkg-pfBlockerNG-devel"
      The stderr should include "the box currently has NO pfBlockerNG installed"
      The stderr should include "install -y -r pfblockerng-stable pfSense-pkg-pfBlockerNG"
      The stderr should not include "re-run this script"
      The value "$(_installed_names)" should equal ""
    End
End

Describe 'migrate-channel.sh — the install lands in a different repository'
    setup() {
        _make_box
        _subscribe stable
        _install "pfSense-pkg-pfBlockerNG" "4.0.0" "pfblockerng-edge"
        _publish "pfblockerng-stable" "pfSense-pkg-pfBlockerNG" "4.0.0"
        _manifest "/usr/local/pkg/pfblockerng/pfblockerng.inc"
        PFB_STUB_INSTALL_REPO="pfblockerng-edge"
        export PFB_STUB_INSTALL_REPO
    }
    cleanup() { rm -rf "${BOX}"; _unset_box; }
    Before 'setup'
    After  'cleanup'

    It 'fails verification rather than claiming the channel switch succeeded'
      When run sh "${SCRIPT}" --channel stable
      The status should equal 6
      The stdout should include "Reinstalling pfSense-pkg-pfBlockerNG from pfblockerng-stable (repository-qualified)"
      The stderr should include "the box is not on the stable channel"
    End
End

Describe 'migrate-channel.sh — the installed payload is incomplete'
    setup() {
        _make_box
        _subscribe stable
        _install "pfSense-pkg-pfBlockerNG-devel" "3.2.15" "pfblockerng"
        _publish "pfblockerng-stable" "pfSense-pkg-pfBlockerNG" "4.0.0"
        _manifest "/usr/local/pkg/pfblockerng/pfblockerng.inc" "/usr/local/www/pfblockerng/pfblockerng_software.php"
        PFB_STUB_SKIP_PAYLOAD="/usr/local/www/pfblockerng/pfblockerng_software.php"
        export PFB_STUB_SKIP_PAYLOAD
    }
    cleanup() { rm -rf "${BOX}"; _unset_box; }
    Before 'setup'
    After  'cleanup'

    It 'fails verification and names the missing file'
      When run sh "${SCRIPT}" --channel stable
      The status should equal 6
      The stdout should include "Installing pfSense-pkg-pfBlockerNG from pfblockerng-stable"
      The stderr should include "the installed payload is incomplete"
      The stderr should include "pfblockerng_software.php"
    End
End

Describe 'migrate-channel.sh — the configuration section is lost'
    # Configuration preservation is the package lifecycle hooks' job, not this
    # script's. Checking it here is what stops a silent loss being reported as a
    # successful migration.
    setup() {
        _make_box
        _subscribe stable
        _install "pfSense-pkg-pfBlockerNG-devel" "3.2.15" "pfblockerng"
        _publish "pfblockerng-stable" "pfSense-pkg-pfBlockerNG" "4.0.0"
        _manifest "/usr/local/pkg/pfblockerng/pfblockerng.inc"
        PFB_STUB_DROP_CONFIG=1
        export PFB_STUB_DROP_CONFIG
    }
    cleanup() { rm -rf "${BOX}"; _unset_box; }
    Before 'setup'
    After  'cleanup'

    It 'before-state: the config carries the pfblockerng section'
      The contents of file "${BOX}/cf/conf/config.xml" should include "<pfblockerng>"
    End

    It 'fails verification and points at the configuration backup'
      When run sh "${SCRIPT}" --channel stable
      The status should equal 6
      The stdout should include "Installing pfSense-pkg-pfBlockerNG from pfblockerng-stable"
      The stderr should include "installedpackages/pfblockerng section is gone"
      The stderr should include "restore your configuration backup"
    End
End
