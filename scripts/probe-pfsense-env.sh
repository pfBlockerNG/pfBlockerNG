#!/bin/sh
# probe-pfsense-env.sh — collect pfSense + pkg environment facts
# Run on a pfSense CE machine AND a pfSense Plus machine; compare outputs.
# Covers every discriminator and pkg URL variable discussed in the repo design.
#
# Usage: sh probe-pfsense-env.sh 2>&1 | tee probe-$(uname -n)-$(date +%Y%m%d).txt

set -u

sep() { printf '\n=== %s ===\n' "$1"; }
sub() { printf '\n--- %s ---\n' "$1"; }
try_file() {
    if [ -f "$1" ]; then printf '%s: %s\n' "$1" "$(cat "$1")";
    else printf '%s: not found\n' "$1"; fi
}
try_dir() {
    if [ -d "$1" ]; then printf 'EXISTS: %s\n' "$1"; ls -la "$1" 2>/dev/null;
    else printf 'ABSENT: %s\n' "$1"; fi
}

# ── 1. Timestamp ────────────────────────────────────────────────────────────
sep "TIMESTAMP"
date

# ── 2. OS identity (raw — what pkg derives its variables from) ───────────────
sep "OS IDENTITY (uname / sysctl)"
uname -a
printf '\nOS fields pkg uses for URL variable expansion:\n'
# \${VAR} labels are intentionally literal — these show pkg's variable names.
printf "  \${OSNAME}:         %s\n" "$(uname -s)"
printf "  \${RELEASE}:        %s\n" "$(uname -r)"
printf "  \${VERSION_MAJOR}:  %s\n" "$(uname -r | cut -d. -f1)"
printf "  \${VERSION_MINOR}:  %s\n" "$(uname -r | cut -d. -f2 | cut -d- -f1)"
printf "  \${ARCH}:           %s\n" "$(uname -m)"
printf '\nsysctl kern.*:\n'
sysctl kern.ostype kern.osrelease kern.osrevision kern.version 2>/dev/null

# ── 3. pkg built-in variable values ─────────────────────────────────────────
sep "PKG BUILT-IN VARIABLES"
printf "  \${ABI}:       %s\n" "$(pkg config ABI 2>/dev/null || echo 'ERROR')"
printf "  \${OSVERSION}: %s\n" "$(pkg config OSVERSION 2>/dev/null || echo 'not supported')"

sub "pkg -vv (full effective configuration)"
pkg -vv 2>/dev/null || echo "pkg -vv failed"

# ── 4. pfSense product identity (PHP globals) ────────────────────────────────
sep "PFSENSE PRODUCT IDENTITY (globals.inc)"
# shellcheck disable=SC2016  # PHP variables ($g, $k, $v) must not expand in shell
php -r '
require_once("/etc/inc/globals.inc");
$keys = [
    "product_name", "product_label", "product_label_html",
    "product_version", "pkg_repos_path", "default-config-flavor",
    "etc_path",
];
foreach ($keys as $k) {
    $v = isset($g[$k]) ? $g[$k] : "(not set)";
    printf("  %-28s %s\n", $k . ":", $v);
}
' 2>/dev/null || echo "PHP globals read failed"

sub "HTTP_USER_AGENT pkg will send (product_label/product_version[:uniqueid])"
# shellcheck disable=SC2016  # PHP variables ($env) must not expand in shell
php -r '
require_once("/etc/inc/globals.inc");
require_once("/etc/inc/pkg-utils.inc");
$env = pkg_env();
printf("  HTTP_USER_AGENT: %s\n", isset($env["HTTP_USER_AGENT"]) ? $env["HTTP_USER_AGENT"] : "(not set)");
' 2>/dev/null || echo "PHP pkg_env() read failed"

# ── 5. Version + flavor files ────────────────────────────────────────────────
sep "VERSION AND FLAVOR FILES"
for f in /etc/version /etc/versionpatch /etc/default-config-flavor \
          /etc/platform /etc/product /etc/os-release; do
    try_file "$f"
done

# ── 6. CE / Plus filesystem discriminators ───────────────────────────────────
sep "CE VS PLUS FILESYSTEM DISCRIMINATORS"
if [ -f /etc/inc/globals.plus.inc ]; then
    printf 'globals.plus.inc: EXISTS  → Plus system\n'
else
    printf 'globals.plus.inc: ABSENT  → CE system\n'
fi

printf '\npfSense product-name directories:\n'
for d in "/usr/local/etc/pfSense" \
         "/usr/local/etc/pfSense Plus" \
         "/usr/local/etc/pfSense-plus"; do
    try_dir "$d"
done

printf '\nrepo-setup binaries in /usr/local/sbin/:\n'
ls -la /usr/local/sbin/*repo-setup 2>/dev/null || echo "none matching *repo-setup"
ls -la /usr/local/sbin/pfSense* 2>/dev/null | head -20 || true

# ── 7. pkg repo directories and conf contents ────────────────────────────────
sep "PKG REPO DIRECTORIES"
for d in "/etc/pkg" \
         "/usr/local/etc/pkg" \
         "/usr/local/etc/pkg/repos" \
         "/usr/local/etc/pfSense/pkg/repos" \
         "/usr/local/etc/pfSense Plus/pkg/repos" \
         "/usr/local/etc/pfSense-plus/pkg/repos"; do
    try_dir "$d"
    printf '\n'
done

sep "PKG REPO CONF FILE CONTENTS"
for dir in "/etc/pkg" \
            "/usr/local/etc/pkg/repos" \
            "/usr/local/etc/pfSense/pkg/repos" \
            "/usr/local/etc/pfSense Plus/pkg/repos"; do
    [ -d "$dir" ] || continue
    for f in "$dir"/*.conf "$dir"/*.name "$dir"/*.default; do
        [ -f "$f" ] || continue
        sub "$f"
        cat "$f"
    done
done

# ── 8. Installed PHP, Python, pfSense base packages ─────────────────────────
sep "INSTALLED PHP PACKAGES"
pkg info | grep -E '^php' | sort

sep "INSTALLED PYTHON PACKAGES"
pkg info | grep -E '^py[0-9]' | sort

sep "INSTALLED PFSENSE BASE PACKAGES"
pkg info | grep -iE '^pf[Ss]ense' | sort

# ── 9. pkg.conf locations ────────────────────────────────────────────────────
sep "PKG.CONF LOCATIONS"
for f in "/usr/local/etc/pkg.conf" "/etc/pkg.conf"; do
    if [ -f "$f" ]; then
        sub "$f"
        cat "$f"
    else
        printf '%s: not found\n' "$f"
    fi
done

sep "PROBE COMPLETE"
