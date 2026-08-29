#!/bin/sh
# image-upgrade.sh — upgrade a published pfSense (CE or Plus) smoke base to a
# newer release and publish the result as a new tag (ADR-04's "upgrade in
# place" flow).
#
# Drive it FROM YOUR MACHINE: the KVM boot + in-VM upgrade must run on a KVM host
# (your Proxmox host), so pass its SSH coordinates and the script runs qemu there
# over SSH while `oras` pull/push stay LOCAL (nothing extra to install on Proxmox
# beyond its native qemu). The guest is reached by jumping THROUGH Proxmox, so the
# guest SSH key never leaves your machine. Omit --proxmox to run locally (i.e.
# directly on the KVM host), as before.
#
# TYPE (--type ce|plus, default ce) follows image-publish.sh's scheme: it derives
# the image name (pfsense-ce|pfsense-plus), the qcow2 filename, the description and
# the OCI artifact-type. The published artifact is BYTE-IDENTICAL to what you would
# get by running this upgrade by hand and then `image-publish.sh --type <type>
# <tag>` — the two share scripts/image-lib.sh, so they cannot drift.
#
# The publish TAG is the upgraded system's major.minor (2.8.1 -> 2.9 once the box
# reports 2.9.0; 26.05.1 -> 26.05), unless --to overrides it.
#
# Flow: pull the current image from GHCR (local) -> stream it to the Proxmox host
# -> boot it under QEMU/KVM there (read-write, with internet) ->
# [optional: pkg update -f + verified pkg upgrade, reboot, wait SSH back] ->
# check for an available OS upgrade (pfSense-upgrade -c). Current and no
# verified package apply -> exit 0 without publishing. Current after a
# verified package apply (or /etc/version already moved, e.g. BETA->RC) ->
# publish without running pfSense-upgrade or the version-change poll.
# Otherwise run pfSense-upgrade over an SSH jump -> wait for /etc/version
# to change + reboot -> reconcile pfBlockerNG's baked
# RUN_DEPENDS against the NEW version's matrix row (install what's missing, e.g.
# after a py_flavor flip; shed stale old-flavor/extra packages; verify pkg info -e
# + a python import probe, fail-closed) -> health-gate (webConfigurator HTTP
# or pfctl live ruleset; confirms it boots and works on the NEW version) ->
# wait for pfSense's boot verification to make the new boot environment
# permanent on disk (fall back to an explicit bectl activate; fail closed —
# issue #1858) -> power off cleanly -> compress on Proxmox -> stream back ->
# boot the exported artifact once and refuse to publish it under a tag whose
# family it does not come up with, or whose pkg ABI disagrees with its own
# kernel or the caller's --expect-freebsd-major (issues #1858, #2242) -> push
# the new tag (local).
# The source tag is left untouched, so the old image is always kept.
#
# Usage:
#   ./scripts/image-upgrade.sh --from <current-version> [--type ce|plus] [options]
#
# Examples:
#   ./scripts/image-upgrade.sh --from 2.8 --proxmox root@pve.lan --ssh-key ~/.ssh/smoke_ed25519
#   ./scripts/image-upgrade.sh --from 2.8 --to 2.9 --proxmox pve.lan --proxmox-port 2222
#   ./scripts/image-upgrade.sh --from 2.8 --to 2.8 --force --upgrade-pkgs   # patch refresh
#   # Plus (its MAC + SMBIOS uuid are license-keyed — pass the Plus VM's own):
#   ./scripts/image-upgrade.sh --from 26.03 --type plus --proxmox pve.lan \
#       --mac <plus-mac> --smbios-uuid <plus-uuid> --ssh-key ~/.ssh/smoke_ed25519
#
# Proxmox connection (the KVM host that boots the VM):
#   --proxmox [USER@]HOST   SSH target of the Proxmox/KVM host. If omitted (and
#                           PROXMOX_SSH_HOST is unset), runs locally.
#   --proxmox-port N        SSH port           (default: $PROXMOX_SSH_PORT or 22)
#   --proxmox-ssh-key PATH  SSH private key     (default: $PROXMOX_SSH_KEY)
#   --remote-tmpdir DIR     scratch dir on the KVM host for the image copies
#                           (several GB) (default: $PROXMOX_TMPDIR or /tmp)
#   USER defaults to $PROXMOX_SSH_USER or root.
#
# Options:
#   --from VERSION   current published tag to upgrade (required)
#   --to VERSION     tag to publish as, in major.minor form — the pre-push
#                    artifact verification compares it against the booted
#                    version's FAMILY (default: major.minor of the upgraded box)
#   --type T         ce (default) | plus — derives the image name, description and
#                    artifact-type (image-publish.sh's scheme)
#   --registry REF   GHCR namespace for the derived --type ref (default:
#                    $SMOKE_IMAGE_REPO or ghcr.io/pfblockerng)
#   --image REF      GHCR image ref without tag (default: the --type-derived
#                    ${registry}/${name}); overrides the derived ref
#   --description D  OCI description (default: "<edition> <tag>", as image-publish.sh)
#   --artifact-type T  OCI artifact-type (default: the --type-derived value)
#   --ssh-key PATH   GUEST SSH private key (default: $SMOKE_SSH_KEY) — its public
#                    half is baked into the image's root authorized_keys
#   --ssh-port N     Proxmox-local port forwarded to the guest's :22 (default: 2222)
#   --mac LIST       the 8 guest NIC MACs, NEWLINE-separated, one per NIC
#                    (net0..net7); pfSense assigns interfaces by MAC so all must
#                    match the image (mirror of boot_vm.sh's SMOKE_VM_MAC).
#                    Default: $SMOKE_VM_MAC, else the committed CE source-VM list
#                    (ce). For --type plus the identity is the SMOKE_PLUS_MAC secret
#                    and is REQUIRED (see below).
#   --smbios-uuid U  SMBIOS type-1 uuid; must match the image (default:
#                    $SMOKE_VM_SMBIOS_UUID, else the CE pin). The Netgate Device ID
#                    (Plus) derives from the MAC set + this uuid.
#
# Plus identity (license/NDI — REQUIRED for --type plus): the source VM's MACs and
# SMBIOS uuid come from the SMOKE_PLUS_MAC (8-MAC list) and SMOKE_PLUS_SMBIOS_UUID
# secrets. image-upgrade REFUSES to boot Plus unless the effective MAC set and uuid
# equal those secrets — a wrong NDI can burn the license. CE uses public defaults.
#   --compression T  qcow2 compression for the published image: zstd|zlib|off (default: zstd)
#   --upgrade-timeout S  MAX seconds to wait for the pfSense-upgrade+reboot
#                    (default: 1200). The poll exits the instant /etc/version
#                    changes, so this only bounds how long a STUCK upgrade waits
#                    before the run fails — it is not added to a successful run.
#   Env knobs (mainly for the spec): VERIFY_BOOT_TIMEOUT — seconds to wait for
#   the artifact-verification boot's SSH (default: 600); PROMOTE_TIMEOUT /
#   PROMOTE_INTERVAL — seconds to wait / poll step for pfSense's own boot
#   verification to promote the new BE (defaults: 300 / 10); METADATA_TIMEOUT /
#   METADATA_INTERVAL — seconds to wait / poll step for pfSense's post-boot
#   package metadata refresh to settle (defaults: 600 / 5). VERIFY_BOOT_TIMEOUT
#   and METADATA_TIMEOUT accept 0..86400; METADATA_INTERVAL accepts 1..3600;
#   invalid values use their defaults. Every boot wait adds the metadata wait to
#   its own budget, so the worst case is its own timeout PLUS METADATA_TIMEOUT.
#   --upgrade-pkgs   before pfSense-upgrade, run `pkg update -f` + `pkg upgrade -y`
#                    to upgrade baked deps (qemu-guest-agent, etc.) to their latest
#                    versions; reboots the guest and waits for SSH before proceeding.
#                    Default OFF; pass this flag to enable. build-image.yml does NOT
#                    pass this flag (it calls this script directly), so callers that
#                    only want the pfSense-upgrade step are unaffected.
#                    Fail-closed (issue #2299): pkg's ABI and the kernel's FreeBSD
#                    major must stay put across the refresh; a plan that crosses a
#                    major, or a failed pkg update/upgrade, aborts the run.
#   --branch NAME    switch the pfSense update branch to NAME before running the OS
#                    upgrade. pfSense stores the selected branch in config.xml key
#                    system/pkg_repo_conf_path; applying the change calls
#                    pkg_switch_repo() (runs pfSense-repo-setup -U and refreshes pkg
#                    metadata), followed by an explicit `pkg update -f` so the
#                    subsequent pfSense-upgrade -c check sees the new branch's
#                    versions. Use this to upgrade TO a pre-release or development
#                    build. Branch names are dynamic — use the exact name reported by
#                    pfSense-repoc -p on that pfSense version. The script validates
#                    NAME against the list of available repos on the booted image and
#                    fails if it is not found. Default empty = leave the image's
#                    configured branch unchanged. Example (Plus pre-release):
#                    --branch pfSense-plus-v26.07-DEVTEST
#   --facts-out FILE gather the upgraded box's version facts (etc_version,
#                    php_version, py_flavor, freebsd_version/major) into FILE
#                    after the health gate — the activation-PR step consumes
#                    them (issue #1837). Best-effort; default off.
#   --expect-freebsd-major N  require the EXPORTED artifact's pkg ABI major to
#                    equal N (digits only), in addition to it always having to
#                    agree with the artifact's own kernel major — refuses to
#                    publish a disk whose FreeBSD major silently drifted from
#                    what the caller expected (issue #2242). Default empty =
#                    only the ABI-vs-kernel self-consistency check applies.
#   --keep           keep the work dirs (image copies, console log) afterwards
#   --force          overwrite the target tag if it already exists
#
# Auth: as in image-publish.sh (local oras login, or SMOKE_GHCR_USER/SMOKE_GHCR_TOKEN).

set -e

log()  { printf '==> %s\n' "$*"; }
warn() { printf 'WARNING: %s\n' "$*" >&2; }
die()  { printf 'ERROR: %s\n' "$*" >&2; exit 1; }

# Shared type/tag/push helpers — sourced so the published artifact is byte-identical
# to running image-publish.sh --type <type> with the derived tag.
SCRIPT_DIR=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
[ -f "$SCRIPT_DIR/image-lib.sh" ] || die "image-lib.sh not found next to this script: $SCRIPT_DIR/image-lib.sh"
# shellcheck source=scripts/image-lib.sh
. "$SCRIPT_DIR/image-lib.sh"
# Post-upgrade dependency reconcile+shed decision logic (issue #1806 final
# step) — pure functions, tested by tests/shell/dep_reconcile_spec.sh.
# shellcheck source=scripts/lib/dep-reconcile.sh
. "$SCRIPT_DIR/lib/dep-reconcile.sh"

FROM=""
TO=""
# Image type: ce (default — the common case) | plus. Derives the image name,
# description and artifact-type from the type (image-publish.sh's scheme). The
# registry NAMESPACE defaults to ghcr.io/pfblockerng; --image/--registry override.
TYPE=ce
REGISTRY="${SMOKE_IMAGE_REPO:-ghcr.io/pfblockerng}"
IMAGE=""
DESCRIPTION=""
ARTIFACT_TYPE=""
GUEST_KEY="${SMOKE_SSH_KEY:-}"
GUEST_PORT=2222
# Source-VM hardware identity — MUST match the image (mirror of boot_vm.sh).
# SMOKE_VM_MAC is a NEWLINE-separated list of 8 MACs, one per NIC (net0..net7);
# pfSense assigns interfaces by MAC, and the Plus Netgate Device ID (NDI/license)
# is keyed to the WHOLE set + the SMBIOS uuid. So all 8 must match the source VM.
# CE defaults to the committed public list; Plus comes from the SMOKE_PLUS_* secrets
# and is enforced below. The CE pin (net0 = BC:24:11:37:9C:AC) is the public default.
DEFAULT_CE_MAC="$(printf '%s\n' \
    BC:24:11:37:9C:AC \
    BC:24:11:80:42:35 \
    BC:24:11:D6:90:DD \
    BC:24:11:FB:41:8A \
    BC:24:11:2D:95:0A \
    BC:24:11:36:D3:34 \
    BC:24:11:02:0B:68 \
    BC:24:11:46:D1:DE)"
DEFAULT_CE_SMBIOS_UUID="58fd7964-c40c-4f47-bf02-3fdad18f8b00"
# Explicit override (full 8-MAC list / uuid) or empty — resolved by --type below.
MAC="${SMOKE_VM_MAC:-}"
SMBIOS_UUID="${SMOKE_VM_SMBIOS_UUID:-}"
COMPRESSION=zstd
UPGRADE_TIMEOUT=1200
UPGRADE_PKGS=0
BRANCH=""
FACTS_OUT=""
EXPECT_FREEBSD_MAJOR=""
KEEP=0
FORCE=0

# Proxmox SSH coordinates (env fallbacks; --proxmox overrides).
image_px_defaults

# The non-interactive pfSense upgrade command. NOTE: confirm the exact flags for
# the running CE release during the spike (ADR-04 §6 flags this) — `yes |`
# is a hedge against any interactive prompt; the version-poll below detects the
# real completion regardless of how it reboots.
UPGRADE_CMD='yes | /usr/local/sbin/pfSense-upgrade -d'

# After pfSense-upgrade completes and a new version is detected, poll up to this
# many seconds for the box to be "working fine" before proceeding to shutdown.
HEALTH_TIMEOUT=300

while [ $# -gt 0 ]; do
    # shellcheck disable=SC2034 # PX_* are consumed by the sourced image-lib.sh helpers
    case "$1" in
        --proxmox)         PX_TARGET="$2"; shift 2 ;;
        --proxmox-port)    PX_PORT="$2"; shift 2 ;;
        --proxmox-ssh-key) PX_KEY="$2"; shift 2 ;;
        --remote-tmpdir)   REMOTE_TMPDIR="$2"; shift 2 ;;
        --from)            FROM="$2"; shift 2 ;;
        --to)              TO="$2"; shift 2 ;;
        --type)            TYPE="$2"; shift 2 ;;
        --registry)        REGISTRY="$2"; shift 2 ;;
        --image)           IMAGE="$2"; shift 2 ;;
        --description)     DESCRIPTION="$2"; shift 2 ;;
        --artifact-type)   ARTIFACT_TYPE="$2"; shift 2 ;;
        --ssh-key)         GUEST_KEY="$2"; shift 2 ;;
        --ssh-port)        GUEST_PORT="$2"; shift 2 ;;
        --mac)             MAC="$2"; shift 2 ;;
        --smbios-uuid)     SMBIOS_UUID="$2"; shift 2 ;;
        --compression)     COMPRESSION="$2"; shift 2 ;;
        --upgrade-timeout) UPGRADE_TIMEOUT="$2"; shift 2 ;;
        --upgrade-pkgs)    UPGRADE_PKGS=1; shift ;;
        --branch)          BRANCH="$2"; shift 2 ;;
        --facts-out)       FACTS_OUT="$2"; shift 2 ;;
        --expect-freebsd-major)
            EXPECT_FREEBSD_MAJOR="$2"
            case "$EXPECT_FREEBSD_MAJOR" in
                *[!0-9]*) die "--expect-freebsd-major must be digits only (got '$EXPECT_FREEBSD_MAJOR')" ;;
            esac
            shift 2 ;;
        --keep)            KEEP=1; shift ;;
        --force)           FORCE=1; shift ;;
        -h|--help)         sed -n '2,/^# Auth:/p' "$0"; exit 0 ;;
        *)                 die "unknown option: $1" ;;
    esac
done

image_px_target_split

[ -n "$FROM" ] || die "missing --from <current-version>"
[ -n "$GUEST_KEY" ] || die "missing --ssh-key (or set SMOKE_SSH_KEY)"
[ -f "$GUEST_KEY" ] || die "guest ssh key not found: $GUEST_KEY"
case "$COMPRESSION" in zstd|zlib|off) ;; *) die "--compression must be zstd|zlib|off" ;; esac

# Only pfSense images get an OS upgrade (civm is not an upgradable OS).
case "$TYPE" in ce|plus) ;; *) die "--type must be ce|plus (got '$TYPE')" ;; esac
# Derive the image-shaped fields from the type (image-publish.sh's scheme). An
# explicit --image / --description / --artifact-type always wins; the DESCRIPTION
# default needs the published TAG, so it is filled in after the version is known.
image_type_fields "$TYPE" || die "--type must be ce|plus (got '$TYPE')"
[ -n "$IMAGE" ]         || IMAGE="${REGISTRY%/}/${IMG_NAME}"
[ -n "$ARTIFACT_TYPE" ] || ARTIFACT_TYPE="$IMG_ATYPE"

# Resolve the source-VM identity per type. pfSense assigns interfaces by MAC, so
# all 8 must match the image. CE uses the committed PUBLIC defaults (the source
# VM's own — a MAC is not sensitive). Plus MUST use its own license/NDI-keyed
# identity from the SMOKE_PLUS_* secrets: booting Plus with the wrong MAC set or
# SMBIOS uuid registers a wrong Netgate Device ID and can burn the license, so we
# REFUSE unless the effective identity equals the Plus secret.
if [ "$TYPE" = plus ]; then
    [ -n "$MAC" ]         || MAC="${SMOKE_PLUS_MAC:-}"
    [ -n "$SMBIOS_UUID" ] || SMBIOS_UUID="${SMOKE_PLUS_SMBIOS_UUID:-}"
    { [ -n "${SMOKE_PLUS_MAC:-}" ] && [ -n "${SMOKE_PLUS_SMBIOS_UUID:-}" ]; } \
        || die "--type plus needs the Plus source-VM identity: set the SMOKE_PLUS_MAC (newline-separated 8-MAC list) and SMOKE_PLUS_SMBIOS_UUID secrets"
    { [ -n "$MAC" ] && [ "$MAC" = "$SMOKE_PLUS_MAC" ]; } \
        || die "--type plus: the guest MAC list must equal SMOKE_PLUS_MAC (the license/NDI-keyed identity); refusing to boot Plus with a wrong NDI"
    [ "$SMBIOS_UUID" = "$SMOKE_PLUS_SMBIOS_UUID" ] \
        || die "--type plus: the SMBIOS uuid must equal SMOKE_PLUS_SMBIOS_UUID; refusing to boot Plus with a wrong NDI"
else
    [ -n "$MAC" ]         || MAC="$DEFAULT_CE_MAC"
    [ -n "$SMBIOS_UUID" ] || SMBIOS_UUID="$DEFAULT_CE_SMBIOS_UUID"
fi

# A full 8-MAC list is mandatory (one per NIC, net0..net7) — a single MAC would
# leave net1..7 with random MACs and break interface assignment / the Plus NDI.
_mac_count=$(printf '%s\n' "$MAC" | grep -c '.')
[ "$_mac_count" -eq 8 ] || die "expected 8 NIC MACs (newline-separated, net0..net7), got ${_mac_count}"

PX_REMOTE=0
[ -n "$PX_HOST" ] && PX_REMOTE=1

# ssh option words (intentionally unquoted at use; no spaces in port/key).
image_px_ssh_opts

# ssh_guest — reach the VM's forwarded :22. When driving a remote Proxmox host we
# jump THROUGH it (ProxyCommand -W), so the guest key stays on this machine and
# the hostfwd only needs to bind Proxmox's localhost.
ssh_guest() {
    if [ "$PX_REMOTE" -eq 1 ]; then
        # shellcheck disable=SC2086
        ssh -o ProxyCommand="ssh -o BatchMode=yes $PX_PORT_OPT $PX_KEY_OPT ${PX_USER}@${PX_HOST} -W %h:%p" \
            -p "$GUEST_PORT" -i "$GUEST_KEY" \
            -o BatchMode=yes -o StrictHostKeyChecking=no \
            -o UserKnownHostsFile=/dev/null -o ConnectTimeout=5 \
            root@127.0.0.1 "$@"
    else
        ssh -p "$GUEST_PORT" -i "$GUEST_KEY" \
            -o BatchMode=yes -o StrictHostKeyChecking=no \
            -o UserKnownHostsFile=/dev/null -o ConnectTimeout=5 \
            root@127.0.0.1 "$@"
    fi
}

# pfb_pkg_update_retry BEGIN
# pfb_pkg_update_retry LOGFILE CONTEXT — refresh the pkg catalogue (`pkg update
# -f`), retrying while pkg reports its own database busy/locked and dying on
# any other failure. Shared by the --branch path and the --upgrade-pkgs path so
# both honour the same PKG_LOCK_RETRIES/PKG_LOCK_INTERVAL knobs and fail
# identically on a stuck lock or a genuine refresh error. CONTEXT is inserted
# verbatim after "failed" in the non-lock failure message and carries its own
# preposition (e.g. "after branch switch", "during --upgrade-pkgs").
pfb_pkg_update_retry() {
    _pkr_log="$1"; _pkr_context="$2"
    true > "$_pkr_log"
    _pkr_retries="${PKG_LOCK_RETRIES:-12}"
    _pkr_interval="${PKG_LOCK_INTERVAL:-5}"
    case "$_pkr_retries" in '' | *[!0-9]*) _pkr_retries=0 ;; esac
    [ "$_pkr_retries" -ge 1 ] || die "PKG_LOCK_RETRIES must be a positive integer"
    [ "$_pkr_retries" -le 12 ] || die "PKG_LOCK_RETRIES must be between 1 and 12"
    case "$_pkr_interval" in *[!0-9]*) die "PKG_LOCK_INTERVAL must be a non-negative integer" ;; esac
    [ "$_pkr_interval" -le 5 ] || die "PKG_LOCK_INTERVAL must be between 0 and 5"
    _pkr_try=1
    while true; do
        _pkr_rc=0
        _pkr_out=$(ssh_guest 'pkg update -f' 2>&1) || _pkr_rc=$?
        printf '%s\n' "$_pkr_out" | tee -a "$_pkr_log"
        [ "$_pkr_rc" -eq 0 ] && return 0
        case "$_pkr_out" in
            *'Cannot get an exclusive lock on a database'* | *'Package database is busy'*) ;;
            *) die "pkg catalogue refresh failed ${_pkr_context} (see $_pkr_log)" ;;
        esac
        if [ "$_pkr_try" -ge "$_pkr_retries" ]; then
            die "pkg catalogue refresh still locked after ${_pkr_retries} attempts (see $_pkr_log)"
        fi
        warn "pkg catalogue refresh: pkg database locked; retry ${_pkr_try}/${_pkr_retries} in ${_pkr_interval}s"
        _pkr_try=$((_pkr_try + 1))
        sleep "$_pkr_interval"
    done
}
# pfb_pkg_update_retry END

# pfb_switch_branch BEGIN
# pfb_switch_branch NAME LOG_DIR — validate NAME against Netgate's live branch
# catalogue, then persist and apply it through pfSense's supported config path.
# pkg_list_repos() only reports installed repo configurations; it does not list
# a new release branch such as 2_9_0 while the image still runs 2.8.1.
pfb_switch_branch() {
    _psb_branch="$1"; _psb_log_dir="$2"
    case "$_psb_branch" in
        *\'*) die "--branch name must not contain a single quote: $_psb_branch" ;;
    esac
    if [ -z "$_psb_branch" ] || \
       [ "$(printf '%s/' "$_psb_branch" | LC_ALL=C tr -d '0-9A-Za-z._-')" != '/' ]; then
        die "invalid update branch name: $_psb_branch"
    fi
    case "$_psb_branch" in
        [._-]*) die "invalid update branch name: $_psb_branch" ;;
    esac
    log "switching pfSense update branch to '${_psb_branch}' (via pkg_switch_repo)"

    if ! _psb_catalog=$(ssh_guest '/usr/local/sbin/pfSense-repoc -p' 2>&1); then
        printf '%s\n' "$_psb_catalog" > "${_psb_log_dir}/branch-catalog.log"
        die "could not list available pfSense update branches (see ${_psb_log_dir}/branch-catalog.log)"
    fi
    printf '%s\n' "$_psb_catalog" > "${_psb_log_dir}/branch-catalog.log"
    _psb_names=$(printf '%s\n' "$_psb_catalog" | awk 'NF { print $1 }')
    if ! printf '%s\n' "$_psb_names" | grep -Fqx "$_psb_branch"; then
        _psb_available=$(printf '%s\n' "$_psb_names" | awk 'BEGIN { sep = "" } { printf "%s%s", sep, $0; sep = " " } END { print "" }')
        die "branch '${_psb_branch}' not found on this image. Available repos: ${_psb_available:-<none listed; see ${_psb_log_dir}/branch-catalog.log>}"
    fi

    _psb_php=$(printf '%s\n' \
        "require_once('pkg-utils.inc');" \
        "config_set_path('system/pkg_repo_conf_path', '${_psb_branch}');" \
        "write_config('image-upgrade: switch update branch to ${_psb_branch}');" \
        "pkg_switch_repo();" \
        "echo 'PFB_BRANCH_OK' . PHP_EOL;" \
        "exec" \
        "exit")
    _psb_out=$(printf '%s\n' "$_psb_php" | ssh_guest 'pfSsh.php' 2>&1 || true)
    printf '%s\n' "$_psb_out" > "${_psb_log_dir}/branch-switch.log"
    if ! printf '%s' "$_psb_out" | grep -q 'PFB_BRANCH_OK'; then
        die "branch switch to '${_psb_branch}' did not confirm success (PFB_BRANCH_OK not in output; see ${_psb_log_dir}/branch-switch.log)"
    fi

    log "branch switch confirmed — refreshing pkg catalogue (pkg update -f)"
    pfb_pkg_update_retry "${_psb_log_dir}/pkg-update-branch.log" "after branch switch"
}
# pfb_switch_branch END

# pfb_upgrade_run BEGIN
# pfb_upgrade_run CMD LABEL [LOG] — run a pfSense-upgrade invocation on the
# guest, appending every attempt's output to LOG when given;
# retrying while it answers "Another instance is already running... Aborting!".
# pkg_switch_repo() (the --branch path) leaves that lock held for tens of
# seconds, and the refusal is NOT a verdict: taking it at face value let a
# refused upgrade look like a started one and turned a short lock into the
# version-poll timeout (issue #1844). An unclearable lock dies loudly here,
# before any downstream step can misread it. Echoes the successful output.
# LOCK_RETRIES / LOCK_INTERVAL are overridable for the spec.
pfb_upgrade_run() {
    _pur_cmd="$1"; _pur_label="$2"; _pur_log="${3:-}"
    _pur_i=0
    while [ "$_pur_i" -lt "${LOCK_RETRIES:-20}" ]; do
        _pur_out=$(ssh_guest "$_pur_cmd" 2>&1 || true)
        # Persist EVERY attempt (append) so an unclearable lock still leaves the
        # refusal text in the log — the old `| tee` path recorded it, and the
        # operator needs it to tell a lock apart from a failed upgrade.
        [ -n "$_pur_log" ] && printf '%s\n' "$_pur_out" >> "$_pur_log"
        case "$_pur_out" in
            *"Another instance is already running"*)
                _pur_i=$((_pur_i + 1))
                warn "${_pur_label}: pfSense-upgrade lock held (attempt ${_pur_i}/${LOCK_RETRIES:-20}); retrying"
                sleep "${LOCK_INTERVAL:-15}"
                ;;
            *)
                printf '%s\n' "$_pur_out"
                return 0
                ;;
        esac
    done
    die "${_pur_label}: pfSense-upgrade lock never cleared after ${LOCK_RETRIES:-20} attempts — refusing to continue"
}
# pfb_upgrade_run END

# pfb_call_site BEGIN
# The two call sites, as functions so the spec drives the SHIPPED shape. They
# take the log path and redirect — NEVER a pipe: a function on the left of a
# pipe runs in a subshell, so its die() cannot abort the script and `set -e`
# only sees the pipeline's last command (issue #1844).
pfb_call_site_check() {
    _pcs_log="$1"
    true > "$_pcs_log"
    pfb_upgrade_run 'pfSense-upgrade -c' 'upgrade check' "$_pcs_log"
}

pfb_call_site_upgrade() {
    _pcs_log="$1"
    true > "$_pcs_log"
    pfb_upgrade_run "$UPGRADE_CMD" 'upgrade' "$_pcs_log" > /dev/null
}
# pfb_call_site END

# pfb_pkg_refresh_verdict BEGIN
# Dry-run text -> up-to-date | pending | fail-closed.
# "pending" only when pkg printed an upgrade/install/reinstall plan.
# Anything else (fetch error, lock, empty) is fail-closed — not a publish signal.
pfb_pkg_refresh_verdict() {
    _dry=$1
    if printf '%s' "$_dry" | grep -q 'Your packages are up to date'; then
        printf '%s\n' up-to-date
        return 0
    fi
    if printf '%s' "$_dry" | grep -qiE 'Number of packages to be (upgraded|installed|reinstalled|removed|downgraded)'; then
        printf '%s\n' pending
        return 0
    fi
    printf '%s\n' fail-closed
}
# pfb_pkg_refresh_verdict END

# pfb_abi_major BEGIN
# pfb_abi_major ABI — the FreeBSD major from `pkg config ABI` output
# (FreeBSD:MAJOR:arch, e.g. FreeBSD:16:amd64 -> 16); empty when ABI carries no
# second `:`-field, or that field is not all-digits (unset/garbled pkg config
# output — caller fails closed).
pfb_abi_major() {
    printf '%s\n' "$1" | awk -F: '$2 ~ /^[0-9]+$/ { print $2 }'
}
# pfb_abi_major END

# pfb_kern_major BEGIN
# pfb_kern_major UNAME_R — the text before the first `.` in `uname -r` (e.g.
# 15.0-RELEASE -> 15). A value with no dot (e.g. 15-STABLE) is returned whole,
# so it fails a major-version compare instead of coincidentally matching.
pfb_kern_major() {
    printf '%s\n' "$1" | cut -d. -f1
}
# pfb_kern_major END

# pfb_refresh_pkgs BEGIN
# pfb_refuse_foreign_major TEXT BASE_MAJOR WHAT LOG — die when TEXT names any
# FreeBSD:<major>: token whose major is not BASE_MAJOR. Applied to the dry-run
# plan AND the applied -y log: an outdated pkg binary restricts the dry-run to
# pkg's own self-upgrade, so a foreign-major listing can first appear in either.
pfb_refuse_foreign_major() {
    _prf_text=$1; _prf_base=$2; _prf_what=$3; _prf_log=$4
    for _prf_tok in $(printf '%s\n' "$_prf_text" | grep -oE 'FreeBSD:[0-9]+:'); do
        _prf_major=$(printf '%s' "$_prf_tok" | cut -d: -f2)
        if [ "$_prf_major" != "$_prf_base" ]; then
            die "${_prf_what} references FreeBSD:${_prf_major}: (base is FreeBSD:${_prf_base}:) — refusing to continue (issue #2299; see ${_prf_log})"
        fi
    done
}

# pfb_refresh_pkgs LOG_DIR — --upgrade-pkgs body: refresh the pkg catalogue and
# apply any pending upgrade, gated on the FreeBSD ABI/kernel major staying put
# throughout. The same-version daily refresh (image-refresh.yml, from==to) is
# the one path that runs unattended with nobody watching the plan; letting it
# swallow a repo-flip-driven ABI change (issue #2242) or a pkg-reported major
# crossing installs foreign-major packages onto the running tag (issue #2299).
# uname -r is the reference because it is the ALREADY-BOOTED kernel's major;
# libpkg's own version is not snapshotted here — its package ABI is covered by
# the post-reboot `pkg query '%n %q'` sweep below.
# Sets the global PKG_WAS_UPGRADED (0 up to date, 1 after an applied upgrade).
pfb_refresh_pkgs() {
    _prp_log_dir="$1"

    # 2>/dev/null + last-non-empty-line: ssh_guest always prints its
    # known-hosts warning on stderr, and a foreign-major pkg binary warns on
    # stderr too — either would corrupt a `2>&1` capture into a multi-line
    # value (issue #2299).
    _prp_abi0=$(ssh_guest '/usr/local/sbin/pkg config ABI' 2>/dev/null | tr -d '\r' | awk 'NF { v = $0 } END { print v }')
    _prp_abi0_major=$(pfb_abi_major "$_prp_abi0")
    [ -n "$_prp_abi0_major" ] \
        || die "could not read pkg ABI before pkg update -f (got: ${_prp_abi0:-<empty>})"
    _prp_kern0=$(ssh_guest 'uname -r' 2>/dev/null | tr -d '\r' | awk 'NF { v = $0 } END { print v }')
    _prp_kern0_major=$(pfb_kern_major "$_prp_kern0")
    [ -n "$_prp_kern0_major" ] \
        || die "could not read kernel version before pkg update -f (got: ${_prp_kern0:-<empty>})"
    # Catch an already-mismatched box (e.g. a prior repo flip) before touching
    # pkg at all — pkg update -f is not the place to discover it.
    [ "$_prp_abi0_major" = "$_prp_kern0_major" ] \
        || die "pkg ABI ${_prp_abi0} does not match kernel ${_prp_kern0} before pkg update -f — refusing to continue (issue #2299)"

    log "refreshing package catalogue (pkg update -f)"
    pfb_pkg_update_retry "${_prp_log_dir}/pkg-update.log" "during --upgrade-pkgs"

    _prp_abi1=$(ssh_guest '/usr/local/sbin/pkg config ABI' 2>/dev/null | tr -d '\r' | awk 'NF { v = $0 } END { print v }')
    _prp_abi1_major=$(pfb_abi_major "$_prp_abi1")
    [ -n "$_prp_abi1_major" ] \
        || die "could not read pkg ABI after pkg update -f (got: ${_prp_abi1:-<empty>})"
    if [ "$_prp_abi1_major" != "$_prp_abi0_major" ]; then
        die "pkg ABI ${_prp_abi1} after pkg update -f, was ${_prp_abi0} — refusing to continue (issue #2299)"
    fi

    # Dry-run detect: pkg prints "Your packages are up to date" when nothing is
    # pending; otherwise it prints an upgrade plan, or — the case this gate
    # exists for — a FreeBSD major-crossing refusal. Parse the output; do NOT
    # rely solely on exit code: real pkg(8) exits 1 whenever a plan is PENDING
    # (upstream pkg.c: dry_run -> rc=false) and 0 only when up to date, so a
    # pending plan's rc=1 is normal, not a failure.
    log "checking for pending package upgrades (pkg upgrade -n)"
    _prp_dry_rc=0
    _prp_dry=$(ssh_guest 'pkg upgrade -n' 2>&1) || _prp_dry_rc=$?
    printf '%s\n' "$_prp_dry" | tee "${_prp_log_dir}/pkg-upgrade-dryrun.log"
    case "$_prp_dry" in
        *'Major OS version upgrade detected'* | *'wrong architecture'* | \
        *'Newer FreeBSD version'* | *'IGNORE_OSVERSION'*)
            die "pkg upgrade -n reports a FreeBSD major crossing (issue #2299; see ${_prp_log_dir}/pkg-upgrade-dryrun.log)"
            ;;
    esac
    # The phrase gate above only catches pkg's own wording; a plan can also
    # just LIST a foreign-major package (an outdated pkg binary restricts the
    # dry-run to pkg's own self-upgrade, masking the real plan until -y
    # re-execs) — so scan every FreeBSD:<major>: token in the plan too.
    pfb_refuse_foreign_major "$_prp_dry" "$_prp_abi0_major" "pkg upgrade -n plan" "${_prp_log_dir}/pkg-upgrade-dryrun.log"
    _prp_verdict=$(pfb_pkg_refresh_verdict "$_prp_dry")

    if [ "$_prp_verdict" = up-to-date ]; then
        log "packages already up to date — skipping pkg upgrade + reboot"
        PKG_WAS_UPGRADED=0
        return 0
    fi
    if [ "$_prp_verdict" = fail-closed ]; then
        die "pkg upgrade -n did not report a plan or an up-to-date result (rc=${_prp_dry_rc}; see ${_prp_log_dir}/pkg-upgrade-dryrun.log)"
    fi

    log "package upgrades pending — running pkg upgrade -y"
    # Do not pipe: tee's 0 would hide a failed apply (#1844 same class).
    if ! ssh_guest 'env ASSUME_ALWAYS_YES=yes pkg upgrade -y' >"${_prp_log_dir}/pkg-upgrade.log" 2>&1; then
        cat "${_prp_log_dir}/pkg-upgrade.log"
        die "pkg upgrade -y failed (see ${_prp_log_dir}/pkg-upgrade.log)"
    fi
    cat "${_prp_log_dir}/pkg-upgrade.log"
    # The real cross-major plan can surface only here (pkg self-upgraded and
    # re-exec'd under -y) — scan the applied log for the same phrases, before
    # the reboot that would otherwise commit a foreign-major install.
    case "$(cat "${_prp_log_dir}/pkg-upgrade.log")" in
        *'Major OS version upgrade detected'* | *'wrong architecture'* | \
        *'Newer FreeBSD version'* | *'IGNORE_OSVERSION'*)
            die "pkg upgrade -y reports a FreeBSD major crossing (issue #2299; see ${_prp_log_dir}/pkg-upgrade.log)"
            ;;
    esac
    pfb_refuse_foreign_major "$(cat "${_prp_log_dir}/pkg-upgrade.log")" "$_prp_abi0_major" "pkg upgrade -y log" "${_prp_log_dir}/pkg-upgrade.log"
    log "rebooting after pkg upgrade"
    # /sbin/reboot drops the connection — expected; ignore the exit code.
    ssh_guest '/sbin/reboot' 2>/dev/null || true
    log "waiting for SSH after pkg-upgrade reboot..."
    wait_guest_ssh 300
    log "box is back after pkg-upgrade reboot"

    _prp_abi2=$(ssh_guest '/usr/local/sbin/pkg config ABI' 2>/dev/null | tr -d '\r' | awk 'NF { v = $0 } END { print v }')
    _prp_abi2_major=$(pfb_abi_major "$_prp_abi2")
    _prp_kern2=$(ssh_guest 'uname -r' 2>/dev/null | tr -d '\r' | awk 'NF { v = $0 } END { print v }')
    _prp_kern2_major=$(pfb_kern_major "$_prp_kern2")
    if [ "$_prp_abi2_major" != "$_prp_abi0_major" ] || [ "$_prp_abi2_major" != "$_prp_kern2_major" ]; then
        die "pkg ABI ${_prp_abi2} (kernel ${_prp_kern2}) after pkg-upgrade reboot, was ${_prp_abi0} — refusing to continue (issue #2299)"
    fi

    # The box-level ABI/kernel check above is not enough: pkg upgrade -y can
    # install a foreign-major package without moving the box's own reported
    # ABI/kernel major, so sweep every installed package's ABI directly.
    _prp_query_rc=0
    _prp_pkg_abis=$(ssh_guest '/usr/local/sbin/pkg query "%n %q"' 2>/dev/null) || _prp_query_rc=$?
    _prp_pkg_abis=$(printf '%s\n' "$_prp_pkg_abis" | tr -d '\r')
    [ "$_prp_query_rc" -eq 0 ] \
        || die "pkg query of installed package ABIs failed (rc=${_prp_query_rc}) after pkg-upgrade reboot — refusing to trust a partial list (issue #2299)"
    [ -n "$_prp_pkg_abis" ] \
        || die "could not read installed package ABIs after pkg-upgrade reboot (issue #2299)"
    # A fully wildcarded ABI (FreeBSD:*:*) is arch- and major-independent; blank
    # lines are not packages.
    _prp_bad_abis=$(printf '%s\n' "$_prp_pkg_abis" | awk -v want="$_prp_abi0_major" 'NF { split($2, a, ":"); if (a[2] != want && a[2] != "*") print }')
    if [ -n "$_prp_bad_abis" ]; then
        die "installed package(s) report a foreign FreeBSD ABI major after pkg-upgrade reboot (base ${_prp_abi0_major}; issue #2299): $(printf '%s\n' "$_prp_bad_abis" | head -n 10)"
    fi

    PKG_WAS_UPGRADED=1
}
# pfb_refresh_pkgs END

# pfb_publish_decision BEGIN
# PKG_WAS_UPGRADED OLD_VER POST_VER CHECK_CURRENT(0|1) -> skip-os | run-os | nothing-to-publish | fail-closed
# A wording miss on pfSense-upgrade -c plus no version change is run-os (then die
# if the version still does not move). Do not guess a publish.
# Empty POST after a verified apply is always fail-closed, including
# ``1 <old> '' 0`` (OS upgrade available). We do not know what the box is
# running; run-os would also be a guess. The next dispatch can upgrade.
pfb_publish_decision() {
    _pkg=$1
    _old=$2
    _post=$3
    _current=$4
    if [ "$_pkg" -eq 1 ] && [ -z "$_post" ]; then
        # Verified apply but no version string — do not publish OLD_VER, and
        # do not run-os either (CHECK_CURRENT is ignored here on purpose).
        printf '%s\n' fail-closed
        return 0
    fi
    if [ "$_pkg" -eq 1 ] && [ -n "$_post" ] && [ "$_post" != "$_old" ]; then
        printf '%s\n' skip-os
        return 0
    fi
    if [ "$_current" -eq 1 ]; then
        if [ "$_pkg" -eq 1 ]; then
            printf '%s\n' skip-os
        else
            printf '%s\n' nothing-to-publish
        fi
        return 0
    fi
    printf '%s\n' run-os
}
# pfb_publish_decision END

# pfb_verify_artifact BEGIN
# pfb_verify_artifact FILE TAG — boot the EXPORTED qcow2 once and refuse to
# publish it unless the version it actually comes up with belongs to TAG's
# family. The running box is not proof: a box captured before its boot finished
# made a 26.03.1 disk pass every in-run check and ship as :26.07 (issue #1858).
# Also refuses to publish when the artifact's own pkg ABI disagrees with its
# kernel (a half-upgraded disk), or — when EXPECT_FREEBSD_MAJOR is set — when
# the ABI major disagrees with the caller's expectation (issue #2242). The
# artifact is the last word before a push. `uname -r` (the kernel that boots
# the disk) is the reference for that self-consistency check; /bin/freebsd-version
# is never read on the artifact.
# FILE is the KVM host's out.qcow2 — the exact bytes the pushed local copy was
# streamed from, so booting it there costs no second transfer. The boot writes
# to that copy; the local one is already on disk and is what gets pushed.
pfb_verify_artifact() {
    _pva_file=$1; _pva_tag=$2
    log "verifying the exported artifact boots ${_pva_tag} before publishing"
    # Run the boot in THIS shell — never $() or a pipe: die() must abort the
    # script (the #1844 rule above), and QPID must land in the top-level shell
    # so cleanup() can reap a wedged verification QEMU.
    pfb_boot_artifact_version "$_pva_file" > "${LOCAL_DIR}/verify-version"
    _pva_ver=$(sed -n '1p' "${LOCAL_DIR}/verify-version" | tr -d '\r')
    _pva_abi=$(sed -n '2p' "${LOCAL_DIR}/verify-version" | tr -d '\r')
    _pva_kern=$(sed -n '3p' "${LOCAL_DIR}/verify-version" | tr -d '\r')
    [ -n "$_pva_ver" ] \
        || die "could not read a version from the exported artifact — refusing to publish"
    _pva_fam=$(image_version_tag "$_pva_ver")
    if [ "$_pva_fam" != "$_pva_tag" ]; then
        die "exported artifact boots ${_pva_ver} (family ${_pva_fam}), not ${_pva_tag} — refusing to publish a mislabelled image"
    fi
    [ -n "$_pva_abi" ] \
        || die "could not read pkg ABI from the exported artifact — refusing to publish"
    [ -n "$_pva_kern" ] \
        || die "could not read kernel release from the exported artifact — refusing to publish"
    # abi_major: 2nd ':'-field of "FreeBSD:15:amd64"; kern_major: text before
    # the first '.' of "15.0-CURRENT" — both plain POSIX-parameter parsing.
    # `set -f` disables globbing for the unquoted `$_pva_abi` word-split below: an
    # ABI containing a literal `*` (e.g. a garbled probe) would otherwise glob-match
    # a filename in cwd and silently hand back a real-looking digit major (issue #2242).
    # shellcheck disable=SC2086  # intentional: IFS=: word-splits the ABI string
    _pva_abi_maj=$(set -f; IFS=:; set -- $_pva_abi; printf '%s' "${2-}")
    case "$_pva_abi_maj" in
        '' | *[!0-9]*) die "could not read pkg ABI from the exported artifact — refusing to publish" ;;
    esac
    _pva_kern_maj=${_pva_kern%%.*}
    if [ "$_pva_abi_maj" != "$_pva_kern_maj" ]; then
        die "exported artifact's pkg ABI ${_pva_abi} disagrees with its kernel ${_pva_kern} — refusing to publish (issue #2242)"
    fi
    if [ -n "$EXPECT_FREEBSD_MAJOR" ] && [ "$_pva_abi_maj" != "$EXPECT_FREEBSD_MAJOR" ]; then
        die "exported artifact's pkg ABI ${_pva_abi} is FreeBSD major ${_pva_abi_maj}, expected ${EXPECT_FREEBSD_MAJOR} for ${_pva_tag} — refusing to publish (issue #2242)"
    fi
    log "artifact verified: boots ${_pva_ver} (pkg ABI ${_pva_abi}, kernel ${_pva_kern})"
}
# pfb_verify_artifact END

# pfb_boot_artifact_version DISK — boot DISK once with the SAME topology the
# upgrade ran under (same MACs, same SMBIOS uuid, same mgmt hostfwd; the upgrade
# VM is already gone, so GUEST_PORT is free) and echo three lines: /etc/version,
# pkg config ABI, uname -r (issue #2242 — the artifact's own ABI/kernel are what
# pfb_verify_artifact checks). A value that could not be read is an empty line;
# the line count stays fixed at 3. Everything else goes to stderr.
pfb_boot_artifact_version() {
    _pbav_disk=$1
    log "booting the exported artifact to read the version it really comes up with" >&2
    _pbav_cmd=$(printf '%s' "$QEMU_CMD" | sed \
        -e "s#${REMOTE_DIR}/work.qcow2#${_pbav_disk}#" \
        -e "s#${REMOTE_DIR}/qemu.pid#${REMOTE_DIR}/verify.pid#" \
        -e "s#${REMOTE_DIR}/console.log#${REMOTE_DIR}/verify-console.log#")
    # The upgrade's command line is data, not a contract: if its shape drifts,
    # the substitutions above silently no-op and this would re-boot the disk we
    # already observed instead of the exported artifact. Every seam must take.
    for _pbav_want in "$_pbav_disk" "${REMOTE_DIR}/verify.pid" "${REMOTE_DIR}/verify-console.log"; do
        case $_pbav_cmd in
            *"$_pbav_want"*) ;;
            *) die "verification boot command does not carry '${_pbav_want}' — QEMU_CMD drifted from the shape the substitutions expect; refusing to boot the wrong disk" ;;
        esac
    done
    case $_pbav_cmd in
        *"${REMOTE_DIR}/work.qcow2"*|*"${REMOTE_DIR}/qemu.pid"*|*"${REMOTE_DIR}/console.log"*)
            die "verification boot command still references the upgrade VM's files — refusing to boot the wrong disk" ;;
    esac
    px "$_pbav_cmd" >&2
    QPID=$(px "cat '${REMOTE_DIR}/verify.pid'" | tr -d '\r')
    [ -n "$QPID" ] || die "verification boot did not write a pidfile (see ${REMOTE_DIR}/verify-console.log on the KVM host)"
    wait_guest_ssh "${VERIFY_BOOT_TIMEOUT:-600}" verify-console.log >&2
    _pbav_ver=$(ssh_guest 'cat /etc/version' 2>/dev/null | tr -d '\r')
    _pbav_abi=$(ssh_guest '/usr/local/sbin/pkg config ABI' 2>/dev/null | tr -d '\r')
    _pbav_kern=$(ssh_guest 'uname -r' 2>/dev/null | tr -d '\r')
    ssh_guest '/sbin/shutdown -p now' >/dev/null 2>&1 || true
    _pbav_elapsed=0
    while px "kill -0 $QPID 2>/dev/null"; do
        if [ "$_pbav_elapsed" -ge 120 ]; then
            px "kill $QPID 2>/dev/null" || true
            break
        fi
        sleep 3; _pbav_elapsed=$((_pbav_elapsed + 3))
    done
    QPID=""
    printf '%s\n%s\n%s\n' "$_pbav_ver" "$_pbav_abi" "$_pbav_kern"
}

# pfb_promote_be BEGIN
# pfb_promote_be — make the upgrade permanent on DISK before the box is captured.
# pfSense-upgrade renames the running BE to <be>_<ts>, installs the new release
# as <be>, activates it FOR THE NEXT BOOT ONLY and reboots; the permanent
# activation happens at the END of that boot, in pfSense-rc's automatic boot
# verification. The image job used to shut the box down seconds after its first
# SSH answer — long before pfSense-rc got there — so the exported disk still
# booted the archived pre-upgrade BE (issue #1858: :26.07 shipped a 26.03.1
# disk). Wait for that promotion, fall back to doing it ourselves if the box
# never gets there, and fail closed if the disk would still boot the old system.
# PROMOTE_TIMEOUT / PROMOTE_INTERVAL are overridable for the spec.
pfb_promote_be() {
    # Parse locally (-H: headerless, script-stable fields), so this works the
    # same on any pfSense and is drivable in the spec.
    _pbe_running=$(ssh_guest 'bectl list -H' 2>/dev/null | tr -d '\r' \
        | awk '$2 ~ /N/ { print $1; exit }')
    [ -n "$_pbe_running" ] \
        || die "could not identify the running boot environment from 'bectl list' — refusing to promote a guess"
    log "waiting for pfSense to make boot environment '${_pbe_running}' permanent"
    _pbe_elapsed=0
    while [ "$_pbe_elapsed" -lt "${PROMOTE_TIMEOUT:-300}" ]; do
        pfb_be_is_permanent "$_pbe_running" && {
            log "boot environment '${_pbe_running}' is active on reboot"
            return 0
        }
        sleep "${PROMOTE_INTERVAL:-10}"
        _pbe_elapsed=$((_pbe_elapsed + ${PROMOTE_INTERVAL:-10}))
    done
    # No automatic promotion (manual verification configured, or a boot that
    # never finished): do what pfSense-rc would have done, then re-check.
    warn "no automatic boot verification after ${PROMOTE_TIMEOUT:-300}s — activating '${_pbe_running}' explicitly"
    ssh_guest "bectl activate '${_pbe_running}'" >/dev/null 2>&1 || true
    pfb_be_is_permanent "$_pbe_running" \
        || die "boot environment '${_pbe_running}' is not active on reboot — refusing to publish a disk that boots the pre-upgrade system"
    log "boot environment '${_pbe_running}' is active on reboot"
}

# pfb_be_is_permanent BE — true when `bectl list` marks BE active on reboot (R).
pfb_be_is_permanent() {
    ssh_guest 'bectl list -H' 2>/dev/null | tr -d '\r' \
        | awk -v be="$1" '$1 == be && $2 ~ /R/ { found = 1 } END { exit !found }'
}
# pfb_promote_be END

# pfb_wait_pkg_metadata BEGIN
# The three-word predicate tests/smoke/helpers.py drives (issues #2242, #2458): one
# round-trip answers present / running / gone. Both alternatives are bracket-escaped
# (`[-]`, `[.]`) so the pattern text in this command's own argv never satisfies itself
# as a `pgrep -f` match. pfSense's root login shell is tcsh, so it runs under /bin/sh.
PFB_METADATA_PROBE='if /bin/test -f /var/run/pfSense_version.rc; then echo present; elif /bin/pgrep -f "pfSense[-]upgrade|rc[.]update_pkg_metadata" >/dev/null 2>&1; then echo running; else echo gone; fi'

# pfb_wait_pkg_metadata [TIMEOUT] — block until pfSense's post-boot package metadata
# refresh has published /var/run/pfSense_version.rc, which rc.update_pkg_metadata does
# only after `pfSense-upgrade -uf` finishes both phases. While that job runs it rewrites
# pkg's effective ABI, so reading `pkg config ABI` / `pkg query`, applying a pkg upgrade
# or powering the VM off mid-refresh samples or freezes a half-written state (#2242).
#
# `gone` is not a verdict on its own: the boot flag clears before the job starts, so it
# means "not started yet" until a `running` probe has been seen and "exited without the
# sentinel" after one. Only `present` is success; both failure shapes die loudly rather
# than let the caller proceed against an unsettled box (#2458).
pfb_wait_pkg_metadata() {
    _pwpm_timeout="${1:-${METADATA_TIMEOUT:-600}}"
    _pwpm_interval="${METADATA_INTERVAL:-5}"
    # Validate before comparison/arithmetic; only bounded decimal values are
    # configured integers, so whitespace, zero intervals and shell overflows fall
    # back before they can hide the deadline or pin the elapsed counter.
    case "$_pwpm_interval" in '' | *[!0-9]* | 0 | 0[0-9]*) _pwpm_interval=5 ;; esac
    if ! [ "$_pwpm_interval" -ge 1 ] 2>/dev/null || ! [ "$_pwpm_interval" -le 3600 ] 2>/dev/null; then
        _pwpm_interval=5
    fi
    case "$_pwpm_timeout" in '' | *[!0-9]*) _pwpm_timeout=600 ;; esac
    if ! [ "$_pwpm_timeout" -le 86400 ] 2>/dev/null; then
        _pwpm_timeout=600
    fi
    _pwpm_elapsed=0
    _pwpm_seen=0
    log "waiting for the pfSense package metadata refresh to settle"
    while true; do
        # 2>/dev/null + last-non-empty-line for the same reason pfb_refresh_pkgs does it:
        # ssh_guest always prints a known-hosts warning on stderr (issue #2299).
        _pwpm_word=$(ssh_guest "/bin/sh -c '${PFB_METADATA_PROBE}'" 2>/dev/null | tr -d '\r' | awk 'NF { v = $0 } END { print v }')
        if [ "$_pwpm_word" = present ]; then
            return 0
        fi
        if [ "$_pwpm_word" = running ]; then
            _pwpm_seen=1
        elif [ "$_pwpm_word" = gone ] && [ "$_pwpm_seen" -eq 1 ]; then
            die "pfSense package metadata refresh exited without publishing /var/run/pfSense_version.rc — the job was seen running and is now gone, so the refresh FAILED (issues #2242, #2458)"
        fi
        if [ "$_pwpm_elapsed" -ge "$_pwpm_timeout" ]; then
            die "pfSense package metadata did not settle within ${_pwpm_timeout}s (last probe: ${_pwpm_word:-<empty>}) — refusing to read pkg state or power the box off mid-refresh (issues #2242, #2458)"
        fi
        sleep "$_pwpm_interval"
        _pwpm_elapsed=$((_pwpm_elapsed + _pwpm_interval))
    done
}
# pfb_wait_pkg_metadata END

# pfb_wait_upgraded_box BEGIN
# pfb_wait_upgraded_box OLD_VERSION LOG — block until the box pfSense-upgrade
# rebooted comes back reporting a version other than OLD_VERSION, then until its
# package metadata refresh has settled. Sets the global NEW_VER; dies if the
# version never changes within UPGRADE_TIMEOUT.
#
# This path never reaches wait_guest_ssh, so it needs its own settle gate. The
# version poll is not one: /etc/version is written by the installer BEFORE
# rc.update_pkg_metadata runs, so it can answer while pkg's effective ABI is
# still being rewritten (issues #2242, #2458). Everything after this point reads
# or writes the pkg database — the dependency reconcile's `pkg query` / `pkg
# install` / `pkg delete` / `pkg info -e`, the health gate — and then powers the
# disk off for export, so a half-written refresh would be captured into the
# published artifact.
pfb_wait_upgraded_box() {
    _pwub_old=$1
    _pwub_log=$2
    log "waiting for the upgraded box to come back..."
    NEW_VER=""
    _pwub_elapsed=0
    sleep 20  # let the reboot begin so we don't read the pre-reboot version
    while [ "$_pwub_elapsed" -lt "$UPGRADE_TIMEOUT" ]; do
        _pwub_v=$(ssh_guest 'cat /etc/version' 2>/dev/null | tr -d '\r' || true)
        if [ -n "$_pwub_v" ] && [ "$_pwub_v" != "$_pwub_old" ]; then
            NEW_VER="$_pwub_v"
            break
        fi
        sleep 15; _pwub_elapsed=$((_pwub_elapsed + 15))
    done
    if [ -z "$NEW_VER" ]; then
        die "version did not change within ${UPGRADE_TIMEOUT}s (still '${_pwub_old}'; see ${_pwub_log})"
    fi
    pfb_wait_pkg_metadata
}
# pfb_wait_upgraded_box END

# wait_guest_ssh BEGIN
# wait_guest_ssh TIMEOUT [CONSOLE] — poll until root SSH answers or TIMEOUT
# seconds elapse, then until the package metadata refresh has settled; CONSOLE
# names the boot's console log for the failure message (the verification boot
# writes verify-console.log, not console.log). TIMEOUT bounds the SSH poll only,
# so the call's worst case is TIMEOUT + METADATA_TIMEOUT — both hard caps, and
# both end by dying rather than returning.
#
# Answering SSH is not a settled box. Every caller here goes straight on to read
# pkg's ABI, apply a pkg upgrade, sample the exported artifact's ABI, or power the
# verify VM off — all of which race pfSense's post-boot metadata refresh — so the
# metadata wait belongs here, once, rather than at each call site (issue #2458).
wait_guest_ssh() {
    _wgs_timeout="$1"
    # issue #2488: validate before the AND-list can hide test(1)'s numeric error.
    case "$_wgs_timeout" in '' | *[!0-9]*) _wgs_timeout=600 ;; esac
    if ! [ "$_wgs_timeout" -le 86400 ] 2>/dev/null; then
        _wgs_timeout=600
    fi
    _wgs_console="${2:-console.log}"
    _wgs_elapsed=0
    while ! ssh_guest true 2>/dev/null; do
        [ "$_wgs_elapsed" -ge "$_wgs_timeout" ] && \
            die "VM did not answer SSH within ${_wgs_timeout}s (see $REMOTE_DIR/${_wgs_console} on the KVM host)"
        sleep 5; _wgs_elapsed=$((_wgs_elapsed + 5))
    done
    pfb_wait_pkg_metadata
}
# wait_guest_ssh END

# nth_mac N — echo the Nth line (0-based) of the newline-separated MAC list, i.e.
# the MAC for NIC net${N}. Mirrors boot_vm.sh so every NIC gets the source-VM MAC.
nth_mac() {
    printf '%s\n' "$MAC" | sed -n "$(($1 + 1))p"
}

# Local tooling: oras always; ssh only when driving a remote host.
command -v oras >/dev/null 2>&1 || die "required local tool not found: oras"
if [ "$PX_REMOTE" -eq 1 ]; then
    command -v ssh >/dev/null 2>&1 || die "required local tool not found: ssh"
    log "KVM host: ${PX_USER}@${PX_HOST}${PX_PORT:+:$PX_PORT} (qemu runs there over SSH; guest reached via jump)"
else
    log "running locally (assuming this IS the KVM host)"
fi

# KVM-host tooling (native qemu). Detect the system emulator binary.
QEMU_BIN=$(px "command -v qemu-system-x86_64 || command -v kvm" 2>/dev/null | head -n1 | tr -d '\r')
[ -n "$QEMU_BIN" ] || die "no qemu-system-x86_64/kvm on the KVM host"
px "command -v qemu-img >/dev/null 2>&1" || die "qemu-img not found on the KVM host"
px "test -e /dev/kvm" || warn "/dev/kvm not present on the KVM host — the guest will be very slow under TCG"

image_ghcr_login

LOCAL_DIR=$(mktemp -d)
REMOTE_DIR=$(px "mkdir -p '$REMOTE_TMPDIR' && mktemp -d -p '$REMOTE_TMPDIR'" | tr -d '\r')
[ -n "$REMOTE_DIR" ] || die "could not create a work dir under $REMOTE_TMPDIR on the KVM host"
QPID=""

cleanup() {
    if [ -n "$QPID" ]; then
        px "kill -0 $QPID 2>/dev/null && { echo 'killing leftover QEMU'; kill $QPID; }" 2>/dev/null || true
    fi
    if [ "$KEEP" -eq 0 ]; then
        px "rm -rf '$REMOTE_DIR'" >/dev/null 2>&1 || true
        rm -rf "$LOCAL_DIR" 2>/dev/null || true
    else
        log "work dirs kept — local: $LOCAL_DIR   KVM host: ${PX_HOST:+$PX_HOST:}$REMOTE_DIR"
    fi
}
trap cleanup EXIT INT TERM

# --- pull current image (local), stream to the KVM host --------------------
log "pulling ${IMAGE}:${FROM} (local oras)"
oras pull "${IMAGE}:${FROM}" -o "$LOCAL_DIR"
BASE=$(find "$LOCAL_DIR" -maxdepth 1 -name '*.qcow2' | head -n1)
[ -n "$BASE" ] || die "no qcow2 found in pulled artifact ${IMAGE}:${FROM}"

# Stream to a writable working copy on the KVM host. We boot THIS copy; the GHCR
# source tag is never modified.
log "streaming base image to the KVM host -> $REMOTE_DIR/work.qcow2"
px "cat > '$REMOTE_DIR/work.qcow2'" < "$BASE"
px "test -s '$REMOTE_DIR/work.qcow2'" || die "streamed image is empty on the KVM host"

# --- boot under QEMU on the KVM host (internet ON for the upgrade) ----------
# Mirror the smoke 8-NIC topology (tests/smoke/boot_vm.sh) so the image boots
# without pfSense re-detecting hardware and dropping to the interface-reassignment
# console prompt. Only the first three are assigned in the image:
#   net0 WAN  — SLIRP 192.168.89.0/24, NATs to the internet (the upgrade download).
#   net1 MGMT — SLIRP 192.168.43.0/24 (a /24 so qemu's SLIRP DHCP is predictable;
#               a /16 leased an unexpected address the forward missed); the ssh
#               host-forward targets the mgmt NIC's DHCP address 192.168.43.15 (the
#               upgrade's control path). The mgmt /24 overlaps neither WAN
#               (192.168.89.0/24), the LAN (192.168.1.0/24), nor the DNSBL sinkhole
#               VIP 10.10.10.1 (matches tests/smoke/boot_vm.sh).
#   net2 LAN  — present but isolated (no civm peer during an upgrade).
#   net3..7   — unassigned; present only so the 8-NIC image sees no change.
# EVERY NIC carries its source-VM MAC (net${i} = the i-th line of $MAC), exactly
# as boot_vm.sh does: pfSense assigns interfaces by MAC, so the mgmt path (net1 ->
# 192.168.43.15, the upgrade's SSH control channel) and — for Plus — the whole
# license/NDI-keyed set must match the image, or pfSense re-detects hardware and
# drops to the interface-reassignment prompt (and Plus would register a wrong NDI).
M0=$(nth_mac 0); M1=$(nth_mac 1); M2=$(nth_mac 2); M3=$(nth_mac 3)
M4=$(nth_mac 4); M5=$(nth_mac 5); M6=$(nth_mac 6); M7=$(nth_mac 7)
log "booting VM on the KVM host (guest mgmt :22 -> 127.0.0.1:$GUEST_PORT there)"
QEMU_CMD="$QEMU_BIN \
    -enable-kvm -machine pc -cpu host \
    -smp 2,sockets=1,cores=2 -m 4096 \
    -smbios type=1,uuid=$SMBIOS_UUID \
    -device virtio-scsi-pci,id=virtioscsi0 \
    -drive file=$REMOTE_DIR/work.qcow2,if=none,id=drive-scsi0,format=qcow2,discard=unmap,detect-zeroes=unmap \
    -device scsi-hd,bus=virtioscsi0.0,drive=drive-scsi0,bootindex=100,rotation_rate=1 \
    -netdev user,id=net0,net=192.168.89.0/24,host=192.168.89.2 \
    -device virtio-net-pci,mac=$M0,netdev=net0,id=nic0 \
    -netdev user,id=net1,net=192.168.43.0/24,host=192.168.43.2,hostfwd=tcp:127.0.0.1:$GUEST_PORT-192.168.43.15:22 \
    -device virtio-net-pci,mac=$M1,netdev=net1,id=nic1 \
    -netdev user,id=net2,net=10.20.0.0/24,restrict=on \
    -device virtio-net-pci,mac=$M2,netdev=net2,id=nic2 \
    -netdev user,id=net3,net=10.30.0.0/24,restrict=on \
    -device virtio-net-pci,mac=$M3,netdev=net3,id=nic3 \
    -netdev user,id=net4,net=10.40.0.0/24,restrict=on \
    -device virtio-net-pci,mac=$M4,netdev=net4,id=nic4 \
    -netdev user,id=net5,net=10.50.0.0/24,restrict=on \
    -device virtio-net-pci,mac=$M5,netdev=net5,id=nic5 \
    -netdev user,id=net6,net=10.60.0.0/24,restrict=on \
    -device virtio-net-pci,mac=$M6,netdev=net6,id=nic6 \
    -netdev user,id=net7,net=10.70.0.0/24,restrict=on \
    -device virtio-net-pci,mac=$M7,netdev=net7,id=nic7 \
    -display none -serial file:$REMOTE_DIR/console.log \
    -pidfile $REMOTE_DIR/qemu.pid -daemonize"
px "$QEMU_CMD"
QPID=$(px "cat '$REMOTE_DIR/qemu.pid'" | tr -d '\r')
[ -n "$QPID" ] || die "QEMU did not write a pidfile (see ${PX_HOST:+$PX_HOST:}$REMOTE_DIR/console.log)"

log "waiting for SSH..."
wait_guest_ssh 300

OLD_VER=$(ssh_guest 'cat /etc/version' 2>/dev/null | tr -d '\r')
log "current version on box: ${OLD_VER:-unknown}"

# --- optional: upgrade baked deps (pkg update -f + conditional pkg upgrade) -
PKG_WAS_UPGRADED=0
if [ "$UPGRADE_PKGS" -eq 1 ]; then
    pfb_refresh_pkgs "$LOCAL_DIR"
fi

# --- optional: switch the pfSense update branch ----------------------------
# When --branch is given, validate the name against the repos available on the
# booted image, write it into config.xml via pkg_switch_repo(), then refresh
# the pkg catalogue so the subsequent pfSense-upgrade -c check sees the new
# branch's versions. Fail-closed: a wrong/missing branch name aborts the run
# rather than silently upgrading on the wrong (stable) branch.
if [ -n "$BRANCH" ]; then
    pfb_switch_branch "$BRANCH" "$LOCAL_DIR"
fi

# --- check whether an OS upgrade is available ------------------------------
# pfSense-upgrade -c reports the available version without applying it. Parsing
# is best-effort (the wording varies by release). Current and no verified
# package apply -> nothing to publish. Current after a verified package apply,
# or /etc/version already moved by pkg (BETA->RC), -> publish without
# pfSense-upgrade or the version-change poll.
_post_pkg_ver=""
if [ "$PKG_WAS_UPGRADED" -eq 1 ]; then
    _post_pkg_ver=$(ssh_guest 'cat /etc/version' 2>/dev/null | tr -d '\r' || true)
fi
_check_current=0
if [ "$PKG_WAS_UPGRADED" -eq 0 ] || [ -z "$_post_pkg_ver" ] || [ "$_post_pkg_ver" = "$OLD_VER" ]; then
    log "checking for an available OS upgrade (pfSense-upgrade -c)"
    UPGRADE_CHECK=$(pfb_call_site_check "$LOCAL_DIR/upgrade-check.log")
    printf '%s\n' "$UPGRADE_CHECK" | sed 's/^/    /'
    if printf '%s' "$UPGRADE_CHECK" | grep -qiE 'up.to.date|already.*(latest|current)|no [a-z ]*update'; then
        _check_current=1
    fi
fi
_decision=$(pfb_publish_decision "${PKG_WAS_UPGRADED}" "${OLD_VER}" "${_post_pkg_ver}" "${_check_current}")
SKIP_OS_UPGRADE=0
NEW_VER=""
if [ "$_decision" = fail-closed ]; then
    die "post-apply version probe empty; not publishing a guess at '${OLD_VER}'"
fi
if [ "$_decision" = nothing-to-publish ]; then
    log "no OS upgrade available — box is current at '${OLD_VER}'; nothing to publish."
    exit 0
fi
if [ "$_decision" = skip-os ]; then
    NEW_VER="${_post_pkg_ver:-$OLD_VER}"
    SKIP_OS_UPGRADE=1
    log "skipping OS upgrade — publishing package refresh at '${NEW_VER}'."
fi

if [ "$SKIP_OS_UPGRADE" -eq 0 ]; then
    # --- run the pfSense upgrade -----------------------------------------------
    log "running pfSense upgrade (this reboots the box; up to ${UPGRADE_TIMEOUT}s)"
    # Connection will drop when the box reboots — that is expected, so ignore it.
    # The lock retry still applies: a refused upgrade must never be mistaken for a
    # started one (issue #1844).
    pfb_call_site_upgrade "$LOCAL_DIR/upgrade.log"

    # --- wait for the new version to come up -----------------------------------
    pfb_wait_upgraded_box "$OLD_VER" "$LOCAL_DIR/upgrade.log"
fi
log "upgraded: ${OLD_VER} -> ${NEW_VER}"

# --- post-upgrade dependency reconcile + shed (issue #1806 final step) -----
# Repair pfBlockerNG's baked CORE RUN_DEPENDS set for the box's NEW version
# before the health gate/publish below: most notably a py_flavor flip (e.g.
# py311 -> py312) strands every old-flavor package. Matrix-driven off the CI
# matrix's per-pfsense_version rows (--print-ci; one row per version, unlike
# the per-freebsd_major-deduped BUILD matrix); best-effort when the NEW
# version has no matrix row yet (a version not yet added) — warn + skip the
# install/shed plan, but still verify the OLD row's own deps so a genuinely
# broken set (e.g. a flip that already happened) is still caught. Fail-closed
# like the health gate below: a verify failure aborts BEFORE publish.
# A matrix row's extra_pkgs (e.g. CE's textproc/py-charset-normalizer) NEVER
# enter install/verify — that package is deliberately not baked into the
# image (per-leg smoke harness installs it; a real install resolves it from
# our self-hosted repo as an ordinary RUN_DEPENDS). extra_pkgs participate
# ONLY in shed, and only once genuinely dropped by the NEW row — see
# scripts/lib/dep-reconcile.sh's header for the full rationale.
# scripts/lib/dep-reconcile.sh's pfb_dep_* functions are the tested, pure
# needed-set/diff logic (tests/shell/dep_reconcile_spec.sh); everything below
# is the live ssh/pkg(8) wiring around them (live-proof-only).
_DEP_MATRIX="$(sh "$SCRIPT_DIR/read-version-matrix.sh" --print-ci 2>/dev/null)" \
    || { warn "could not read the version matrix — skipping dependency reconcile"; _DEP_MATRIX="[]"; }

# _dep_row VERSION — echo the CI-matrix row (compact JSON) whose pfsense_version
# equals VERSION and whose channel matches this run's --type (case-insensitive
# — the matrix spells it "CE"/"Plus"), or empty when none matches.
_dep_row() {
    printf '%s' "$_DEP_MATRIX" | jq -c --arg v "$1" --arg t "$TYPE" \
        '[.[] | select(.pfsense_version == $v and ((.channel // "") | ascii_downcase) == $t)][0] // empty'
}

_DEP_OLD_ROW="$(_dep_row "$FROM")"
_DEP_NEW_MATRIX_VER="$(image_version_tag "$NEW_VER")"
_DEP_NEW_ROW="$(_dep_row "$_DEP_NEW_MATRIX_VER")"

if [ -z "$_DEP_OLD_ROW" ]; then
    warn "no matrix row for ${TYPE} ${FROM} — skipping dependency reconcile (no known baseline to diff against)"
else
    _DEP_OLD_FLAVOR="$(printf '%s' "$_DEP_OLD_ROW" | jq -r '.py_flavor')"
    _DEP_OLD_EXTRA="$(printf '%s' "$_DEP_OLD_ROW" | jq -r '.extra_pkgs[]? // empty')"
    _DEP_INSTALLED="$(ssh_guest "pkg query '%n'" 2>/dev/null || true)"

    if [ -z "$_DEP_NEW_ROW" ]; then
        # Best-effort: a version not yet added to the matrix. NEVER attempt an
        # install/shed plan against an unknown target (nothing to diff against) —
        # only verify the OLD row's own expectations are still met, so a genuine
        # break (e.g. a py_flavor flip the box already went through) is still
        # caught rather than silently waved through.
        warn "no matrix row for ${TYPE} ${_DEP_NEW_MATRIX_VER} yet — skipping install/shed plan; verifying ${FROM}'s own deps only"
        _DEP_VERIFY_FLAVOR="$_DEP_OLD_FLAVOR"
    else
        _DEP_NEW_FLAVOR="$(printf '%s' "$_DEP_NEW_ROW" | jq -r '.py_flavor')"
        _DEP_NEW_EXTRA="$(printf '%s' "$_DEP_NEW_ROW" | jq -r '.extra_pkgs[]? // empty')"

        log "reconciling pfBlockerNG dependencies (${_DEP_OLD_FLAVOR} -> ${_DEP_NEW_FLAVOR})"
        _DEP_PLAN="$(pfb_dep_plan "$_DEP_OLD_FLAVOR" "$_DEP_OLD_EXTRA" "$_DEP_NEW_FLAVOR" "$_DEP_NEW_EXTRA" "$_DEP_INSTALLED")"
        _DEP_INSTALL_LIST="$(printf '%s\n' "$_DEP_PLAN" | sed -n 's/^install //p')"
        _DEP_SHED_LIST="$(printf '%s\n' "$_DEP_PLAN" | sed -n 's/^shed //p')"

        if [ -n "$_DEP_INSTALL_LIST" ]; then
            log "installing missing dependencies: $(printf '%s' "$_DEP_INSTALL_LIST" | tr '\n' ' ')"
            ssh_guest "env ASSUME_ALWAYS_YES=yes pkg install -y $(printf '%s' "$_DEP_INSTALL_LIST" | tr '\n' ' ')" \
                2>&1 | tee "$LOCAL_DIR/dep-install.log" || true
        fi

        if [ -n "$_DEP_SHED_LIST" ]; then
            log "shedding stale dependencies: $(printf '%s' "$_DEP_SHED_LIST" | tr '\n' ' ')"
            ssh_guest "pkg delete -y $(printf '%s' "$_DEP_SHED_LIST" | tr '\n' ' ')" \
                2>&1 | tee "$LOCAL_DIR/dep-shed.log" \
                || warn "pkg delete of stale deps reported a non-zero exit (see $LOCAL_DIR/dep-shed.log)"
        fi

        _DEP_VERIFY_FLAVOR="$_DEP_NEW_FLAVOR"
    fi

    # Verify (always, whether or not a plan ran above): every CORE needed
    # package resolves in the pkg db (pkg info -e — one round trip per
    # package, as specified), and the core python import probe succeeds —
    # fail-closed: a bad dependency set must never be published (same shape
    # as the health gate below). extra_pkgs are DELIBERATELY excluded from
    # verify (contract correction — see scripts/lib/dep-reconcile.sh's header
    # and pfSense_versions.md's CE-only note): CE's charset-normalizer is not
    # baked into the image, so demanding it here would fail-close every
    # healthy CE image upgrade.
    _DEP_VERIFY_FAIL=0
    for _dep_pkg in $(pfb_dep_core_pkgs "$_DEP_VERIFY_FLAVOR"); do
        ssh_guest "pkg info -e '$_dep_pkg'" >/dev/null 2>&1 || {
            warn "dependency verify: ${_dep_pkg} not resolved on the guest"
            _DEP_VERIFY_FAIL=1
        }
    done
    _DEP_PY_DOTTED="$(pfb_dep_python_dotted "$_DEP_VERIFY_FLAVOR")"
    ssh_guest "/usr/local/bin/python${_DEP_PY_DOTTED} -c 'import maxminddb, sqlite3'" >/dev/null 2>&1 || {
        warn "dependency verify: python${_DEP_PY_DOTTED} import probe failed (maxminddb, sqlite3)"
        _DEP_VERIFY_FAIL=1
    }
    [ "$_DEP_VERIFY_FAIL" -eq 0 ] || die "post-upgrade dependency verify failed — refusing to publish (see warnings above)"
    log "dependency verify OK"
fi

# --- health gate: wait until box is "working fine" -------------------------
# Poll up to HEALTH_TIMEOUT seconds. The box is considered healthy when EITHER:
#   a) the webConfigurator answers HTTP (login page is up), OR
#   b) pfctl -sr returns a live (non-empty) ruleset.
# If neither within HEALTH_TIMEOUT, die — fail-closed; no publish.
log "health-gating upgraded box (up to ${HEALTH_TIMEOUT}s for webConfigurator/pfctl)..."
_hg_elapsed=0
_hg_healthy=0
while [ "$_hg_elapsed" -lt "$HEALTH_TIMEOUT" ]; do
    # Check webConfigurator: fetch https://127.0.0.1/ on-box (port 443).
    # fetch(1) is the FreeBSD/pfSense http client available on all pfSense versions.
    if ssh_guest 'fetch -qT 15 --no-verify-peer --no-verify-hostname -o /dev/null https://127.0.0.1/ 2>/dev/null' 2>/dev/null; then
        log "health gate PASS: webConfigurator answered HTTP"
        _hg_healthy=1
        break
    fi
    # Fallback: check pfctl for a live ruleset.
    _pf_rules=$(ssh_guest '/sbin/pfctl -sr' 2>/dev/null | grep -c '.' || true)
    if [ "${_pf_rules:-0}" -gt 0 ]; then
        log "health gate PASS: pfctl shows ${_pf_rules} live rules"
        _hg_healthy=1
        break
    fi
    sleep 10; _hg_elapsed=$((_hg_elapsed + 10))
done
[ "$_hg_healthy" -eq 1 ] || die "upgraded box did not become healthy within ${HEALTH_TIMEOUT}s (webConfigurator and pfctl both failed; see $LOCAL_DIR/upgrade.log)"

# --- wait until the upgrade is permanent on disk (issue #1858) -------------
pfb_promote_be

# --- optional: gather box facts for the activation PR (issue #1837) --------
# Best-effort: the publish must not depend on it.
if [ -n "$FACTS_OUT" ]; then
    log "gathering box facts -> $FACTS_OUT (best-effort)"
    image_gather_facts "$FACTS_OUT" ssh_guest \
        || warn "box-facts gathering failed; the activation PR will be skipped"
fi

# --- power off cleanly -----------------------------------------------------
log "shutting the box down"
ssh_guest '/sbin/shutdown -p now' 2>/dev/null || true
_elapsed=0
while px "kill -0 $QPID 2>/dev/null"; do
    if [ "$_elapsed" -ge 120 ]; then
        warn "QEMU still up 120s after poweroff; killing"
        px "kill $QPID 2>/dev/null" || true
        break
    fi
    sleep 3; _elapsed=$((_elapsed + 3))
done
QPID=""

# --- publish the new version (old tag kept) --------------------------------
# Tag: explicit --to wins; otherwise the major.minor of the detected new version
# (2.9.0 -> 2.9, 26.05.1 -> 26.05). Description defaults to the same "<edition>
# <tag>" wording image-publish.sh emits, so the artifacts match exactly.
TAG="${TO:-$(image_version_tag "$NEW_VER")}"
[ -n "$TAG" ] || die "could not determine target tag"
[ -n "$DESCRIPTION" ] || DESCRIPTION="${IMG_DESC} ${TAG}"
QCOW_NAME="${IMG_PRETTY}_${TAG}.qcow2"

if [ "$FORCE" -eq 0 ] && oras manifest fetch "${IMAGE}:${TAG}" >/dev/null 2>&1; then
    die "tag ${IMAGE}:${TAG} already exists (use --force). The source tag ${FROM} is kept regardless."
fi

# Compress on the KVM host (native qemu-img), then stream the smaller result back.
log "compressing upgraded image on the KVM host (compression: $COMPRESSION)"
case "$COMPRESSION" in
    zstd)
        px "qemu-img convert -O qcow2 -c -o compression_type=zstd '$REMOTE_DIR/work.qcow2' '$REMOTE_DIR/out.qcow2'" || {
            warn "zstd unsupported; falling back to zlib"
            px "qemu-img convert -O qcow2 -c '$REMOTE_DIR/work.qcow2' '$REMOTE_DIR/out.qcow2'"
        } ;;
    zlib) px "qemu-img convert -O qcow2 -c '$REMOTE_DIR/work.qcow2' '$REMOTE_DIR/out.qcow2'" ;;
    off)  px "qemu-img convert -O qcow2 '$REMOTE_DIR/work.qcow2' '$REMOTE_DIR/out.qcow2'" ;;
esac

OUT="$LOCAL_DIR/${QCOW_NAME}"
log "streaming upgraded image back -> $(basename "$OUT")"
px "cat '$REMOTE_DIR/out.qcow2'" > "$OUT"
[ -s "$OUT" ] || die "streamed upgraded image is empty: $OUT"

pfb_verify_artifact "$REMOTE_DIR/out.qcow2" "$TAG"

log "pushing ${IMAGE}:${TAG} (local oras)"
# Shared push — identical to image-publish.sh --type ${TYPE} ${TAG} (same image
# ref, qcow2 title, description and artifact-type). NEW_VER stamps the full
# pfSense version annotation the tracker's patch/GA detection compares against.
image_oci_push "$OUT" "$IMAGE" "$TAG" "$ARTIFACT_TYPE" "$DESCRIPTION" "$QCOW_NAME" "$NEW_VER"

log "done. ${IMAGE}:${TAG} published; ${IMAGE}:${FROM} kept."
