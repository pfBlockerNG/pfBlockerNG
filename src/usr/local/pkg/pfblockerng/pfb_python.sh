#!/bin/sh
# Resolve and execute pfBlockerNG's package-provided Python interpreter.
#
# Normal mode queries /usr/local/sbin/pkg for the installed
# current pfSense-pkg-pfBlockerNG channel package (plus legacy -devel), then
# reads its direct dependencies. The only
# accepted direct dependency names are pyNN/pythonNN (NN is at least two
# digits); module dependencies and ambiguous versions fail closed.
#
# --print-interpreter prints the resolved path for the PHP compatibility seam.
# With PFB_PYTHON_DEPENDENCIES set (newline-separated direct dependencies),
# this mode intentionally skips the executable check for off-box tests. Live
# --print-interpreter and every execution require an executable interpreter.
# PFB_PYTHON_DIR overrides /usr/local/bin; PFB_PKG_BIN overrides
# /usr/local/sbin/pkg. These environment variables are test seams, not
# appliance fallbacks.

diag() {
	printf '%s\n' "pfb_python.sh: $*" >&2
}

fail() {
	diag "$1"
	exit 1
}

trim() {
	_pfb_trim_value=$1
	_pfb_trim_value=${_pfb_trim_value#"${_pfb_trim_value%%[![:space:]]*}"}
	_pfb_trim_value=${_pfb_trim_value%"${_pfb_trim_value##*[![:space:]]}"}
	printf '%s' "${_pfb_trim_value}"
}

print_mode=0
if [ "$#" -gt 0 ] && [ "$1" = '--print-interpreter' ]; then
	print_mode=1
	shift
fi

if [ "$print_mode" -eq 1 ] && [ "$#" -gt 0 ]; then
	fail 'usage: --print-interpreter takes no arguments'
fi

python_dir=${PFB_PYTHON_DIR:-/usr/local/bin}
dependencies_set=0
if [ "${PFB_PYTHON_DEPENDENCIES+x}" = x ]; then
	dependencies_set=1
	dependencies=${PFB_PYTHON_DEPENDENCIES}
else
	pkg_bin=${PFB_PKG_BIN:-/usr/local/sbin/pkg}
	pkg_names=$(
		"${pkg_bin}" query -g '%n' 'pfSense-pkg-pfBlockerNG*' 2>/dev/null
	)
	pkg_status=$?
	if [ "${pkg_status}" -ne 0 ]; then
		fail "package-name query failed (expected a current pfSense-pkg-pfBlockerNG channel or legacy -devel via ${pkg_bin})"
	fi

	pkg_name=''
	while IFS= read -r candidate || [ -n "${candidate}" ]; do
		candidate_lc=$(printf '%s' "${candidate}" | LC_ALL=C tr '[:upper:]' '[:lower:]')
		case "${candidate_lc}" in
			pfsense-pkg-pfblockerng|pfsense-pkg-pfblockerng-testing|pfsense-pkg-pfblockerng-edge|pfsense-pkg-pfblockerng-devel|pfsense-pkg-pfblockerng-nightly)
				pkg_name=${candidate}
				break
				;;
		esac
	done <<EOF
${pkg_names}
EOF
	if [ -z "${pkg_name}" ]; then
		fail "no valid pfBlockerNG package (expected a current channel or legacy -devel, got ${pkg_names:-none})"
	fi

	dependencies=$(
		"${pkg_bin}" query '%dn' "${pkg_name}" 2>/dev/null
	)
	dep_status=$?
	if [ "${dep_status}" -ne 0 ]; then
		fail "dependency query failed for ${pkg_name} (expected direct pyNN/pythonNN dependencies)"
	fi
fi

version=''
version_count=0
while IFS= read -r raw_dependency || [ -n "${raw_dependency}" ]; do
	dependency=$(trim "${raw_dependency}")
	case "${dependency}" in
		py[0-9][0-9]*|python[0-9][0-9]*)
			case "${dependency}" in
				python*) digits=${dependency#python} ;;
				py*) digits=${dependency#py} ;;
			esac
			case "${digits}" in
				''|*[!0-9]*) continue ;;
			esac
			major=${digits%"${digits#?}"}
			minor=${digits#?}
			candidate_version=${major}.${minor}
			if [ -z "${version}" ]; then
				version=${candidate_version}
				version_count=1
			elif [ "${version}" != "${candidate_version}" ]; then
				version_count=2
			fi
			;;
	esac
done <<EOF
${dependencies}
EOF

if [ "${version_count}" -ne 1 ]; then
	fail "expected exactly one pyNN/pythonNN dependency, got ${dependencies:-none}"
fi

interpreter=${python_dir%/}/python${version}
if [ "${print_mode}" -eq 1 ] && [ "${dependencies_set}" -eq 1 ]; then
	printf '%s\n' "${interpreter}"
	exit 0
fi

if [ ! -x "${interpreter}" ]; then
	fail "interpreter is not executable (expected ${interpreter})"
fi

if [ "${print_mode}" -eq 1 ]; then
	printf '%s\n' "${interpreter}"
	exit 0
fi

if exec "${interpreter}" "$@"; then
	:
else
	status=$?
	diag "failed to execute interpreter ${interpreter}"
	exit "${status}"
fi
