#!/bin/sh
# shellcheck shell=sh
# issue #3140: every pfblockerng.sh invocation paid two read_xml_tag.sh execs (~157 ms
# each) for values PHP already holds when it drives the pass. PHP exports
# PFB_REENTRY_TIMEOUT / PFB_IP_PLACEHOLDER once per sync; the init block now prefers
# the environment and keeps the reader as the fallback (boot-time and hand-run
# invocations). These rows drive the SHIPPED init lines — extracted from
# pfblockerng.sh with the reader path substituted for a recording fake — so the
# environment preference, the normalization, and the empty-value fallback are pinned
# as shipped, not re-implemented in the spec.

# The shipped init line that seeds the ONE global budget (same extraction key as
# pfblockerng_reentry_bounds_spec.sh's init_budget_line source pin), with the reader
# swapped for the per-example fake.
init_budget_line() {
	grep -E '^[[:space:]]*pfbreentrytimeout=' "${PFB_PKGDIR}/pfblockerng.sh" |
		sed "s#/usr/local/sbin/read_xml_tag.sh#${fake}#"
}

# The shipped ip_placeholder assignment together with its existing empty-value
# fallback (assignment line + if/fi block), reader path substituted for the fake.
init_placeholder_lines() {
	grep -F -A3 'ip_placeholder="$' "${PFB_PKGDIR}/pfblockerng.sh" |
		sed "s#/usr/local/sbin/read_xml_tag.sh#${fake}#"
}

# Write the recording fake reader: appends one line per invocation to reader_log and
# prints the current contents of reader_out (the configured config.xml answer).
make_reader_fake() {
	fake="${work}/read_xml_tag.sh"
	{
		printf '#!/bin/sh\n'
		printf 'printf "%%s\\n" "$0 $*" >> "%s"\n' "${reader_log}"
		printf '[ -f "%s" ] && cat "%s"\n' "${reader_out}" "${reader_out}"
	} > "${fake}"
	chmod +x "${fake}"
}

# Reset the per-example reader recording and configured output.
reset_reader() {
	true > "${reader_log}"
	[ -f "${reader_out}" ] || true > "${reader_out}"
}

# Eval the SHIPPED budget init line against $1 (or unset it for '__UNSET__') with the
# fake reader configured to print $2, and report the normalized value plus how many
# times the reader ran: 'timeout=<n>|reads=<n>'.
run_budget_line() {
	if [ "${1:-}" = '__UNSET__' ]; then
		unset PFB_REENTRY_TIMEOUT
	else
		PFB_REENTRY_TIMEOUT="$1"
	fi
	printf '%s\n' "${2:-}" > "${reader_out}"
	reset_reader
	eval "$(init_budget_line)"
	printf 'timeout=%s|reads=%s\n' \
		"${pfbreentrytimeout}" "$(wc -l < "${reader_log}")"
}

# Eval the SHIPPED ip_placeholder assignment + fallback block against $1 (or unset it
# for '__UNSET__') with the fake reader configured to print $2, and report the
# resulting value plus how many times the reader ran: 'ph=<v>|reads=<n>'.
run_placeholder_lines() {
	if [ "${1:-}" = '__UNSET__' ]; then
		unset PFB_IP_PLACEHOLDER
	else
		PFB_IP_PLACEHOLDER="$1"
	fi
	[ -f "${reader_out}" ] || true > "${reader_out}"
	printf '%s' "${2:-}" > "${reader_out}"
	reset_reader
	eval "$(init_placeholder_lines)"
	printf 'ph=%s|reads=%s\n' "${ip_placeholder}" "$(wc -l < "${reader_log}")"
}

Describe 'pfblockerng.sh init: re-entry timeout prefers the exported environment (issue #3140)'
	setup() {
		work="$(mktemp -d "${SHELLSPEC_TMPBASE:-/tmp}/pfbinitenv.XXXXXX")"
		reader_log="${work}/reader.log"
		reader_out="${work}/reader.out"
		make_reader_fake
	}
	cleanup() {
		unset PFB_REENTRY_TIMEOUT pfbreentrytimeout
		rm -rf "${work}"
	}
	BeforeAll 'pfb_source'
	Before 'setup'
	After 'cleanup'

	It 'honours the exported PFB_REENTRY_TIMEOUT without invoking the reader (S1)'
		When call run_budget_line 900 1800
		The output should equal 'timeout=900|reads=0'
	End

	It 'falls back to the reader when PFB_REENTRY_TIMEOUT is unset (S2)'
		When call run_budget_line '__UNSET__' 900
		The output should equal 'timeout=900|reads=1'
	End

	It 'normalizes a hostile PFB_REENTRY_TIMEOUT to the default without the reader (S3)'
		When call run_budget_line abc 1800
		The output should equal 'timeout=1800|reads=0'
	End

	It 'falls back to the reader when PFB_REENTRY_TIMEOUT is empty (S4)'
		When call run_budget_line '' 900
		The output should equal 'timeout=900|reads=1'
	End

	It 'normalizes a trailing-space env value to the default (S3b)'
		When call run_budget_line '300 ' 1800
		The output should equal 'timeout=1800|reads=0'
	End

	It 'normalizes a newline-carrying env value to the default (S3b)'
		nl="$(printf '\nx')"; nl="${nl%x}"
		When call run_budget_line "300${nl}" 1800
		The output should equal 'timeout=1800|reads=0'
	End

	It 'keeps the shipped init line on the reader path (S8)'
		# Source pin: keeps pfblockerng_reentry_bounds_spec.sh's init_budget_line
		# expectations (reader, config path, from_reader resolver) green.
		When call init_budget_line
		The stdout should include 'read_xml_tag.sh'
		The stdout should include 'installedpackages/pfblockerng/config/pfb_reentry_timeout'
		The stdout should include 'pfb_reentry_timeout_from_reader'
	End
End

Describe 'pfblockerng.sh init: ip_placeholder prefers the exported environment (issue #3140)'
	setup() {
		work="$(mktemp -d "${SHELLSPEC_TMPBASE:-/tmp}/pfbinitph.XXXXXX")"
		reader_log="${work}/reader.log"
		reader_out="${work}/reader.out"
		make_reader_fake
	}
	cleanup() {
		unset PFB_IP_PLACEHOLDER ip_placeholder
		rm -rf "${work}"
	}
	BeforeAll 'pfb_source'
	Before 'setup'
	After 'cleanup'

	It 'honours the exported PFB_IP_PLACEHOLDER without invoking the reader (S5)'
		When call run_placeholder_lines 10.9.8.7 127.1.7.7
		The output should equal 'ph=10.9.8.7|reads=0'
	End

	It 'falls back to the reader when PFB_IP_PLACEHOLDER is unset (S6)'
		When call run_placeholder_lines '__UNSET__' 10.1.1.1
		The output should equal 'ph=10.1.1.1|reads=1'
	End

	It 'keeps the 127.1.7.7 fallback when the reader yields an empty value (S7)'
		When call run_placeholder_lines '' ''
		The output should equal 'ph=127.1.7.7|reads=1'
	End

	It 'holds shell metacharacters literally without executing them (S5b)'
		# The env value is only ever expanded inside double quotes; if a regression ever
		# left the assignment unquoted, eval would run `rm` and the value would not be
		# the literal. A canary file proves nothing behind the ';' executed.
		canary="${work}/canary"; true > "${canary}"
		When call run_placeholder_lines '10.0.0.1;rm' ''
		The output should equal 'ph=10.0.0.1;rm|reads=0'
		The file "${canary}" should be exist
	End
End
