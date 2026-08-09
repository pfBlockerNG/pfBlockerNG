#!/bin/sh
# run-in-docker.sh — run any repo command inside the CI runner image instead of on
# the host. Same toolchain the gates grade with, and on Apple Silicon it is also the
# faster way to run the suite: measured 59s vs 201s for `python3 -m pytest -q`,
# because this repo's tests are process-spawn bound and Linux fork/exec is far
# cheaper than macOS, which pays a security check on every exec.
#
#   scripts/run-in-docker.sh python3 -m pytest -q
#   scripts/run-in-docker.sh ruff check .
#   scripts/run-in-docker.sh shellspec --shell dash
#   scripts/run-in-docker.sh              # no command: an interactive shell
#
# WHAT IT MOUNTS, AND WHY IT IS NOT JUST THE REPO: a linked git worktree's `.git` is
# a FILE pointing at the main repo's .git directory, which lives OUTSIDE the
# worktree. Mount only the worktree and every git-dependent step fails — in this
# repo that is a collection error, not a skip, because the pytest suite reads the
# build matrix through git at import time. So the git common dir is mounted too,
# at its own absolute path, whenever it sits outside the tree. Paths are identical
# inside and out, so anything printing a path stays copy-pasteable.
#
# WHY --user: the container would otherwise run as root, and root bypasses the
# chmod-based permission tests (the same reason the PHPUnit permission cases guard
# on posix_getuid). Running as the invoking user keeps those honest.
#
# KNOWN DIFFERENCES from a host run, all Linux-vs-macOS rather than bugs: the
# process-group signal tests and one mtime race test fail in the container, and a
# couple of platform-gated cases skip differently. CI grades on Linux, so the
# container is the closer answer where they disagree.
#
# IT ALWAYS RUNS THE COMMAND. Every reason the container cannot be reached — docker
# missing, daemon down, image absent and unpullable, a local build that fails, not even a
# git work tree — prints one line naming that reason and then runs on the host instead.
# The container is an optimisation, and a wrapper that refuses to run is worse than no
# wrapper; naming the reason is what keeps a host run from being mistaken for a graded one.
#
# Env:
#   PFB_IMAGE   full image ref (default: ghcr.io/pfblockerng/ci-runner:<VERSION>)
#   PFB_VM      non-empty -> use the ci-runner-vm image (qemu, oras, Playwright)
#   PFB_BUILD   non-empty -> build the image locally instead of pulling (needs no
#               credentials, which is the point while the packages are private)
#   PFB_DOCKER_ARGS  extra args for `docker run` (e.g. "-e FOO=bar --network none")

set -eu

# No command: drop into a shell in the same directory. Settled BEFORE anything that can
# fall back, so the host path has an argv to exec too.
if [ "$#" -eq 0 ]; then
	set -- sh
fi

# The container is an optimisation, not a requirement: the command runs either way. Every
# reason we cannot reach it is a fallback rather than an error, because refusing to run at
# all would make this wrapper worse than typing the command directly — but each says WHY,
# so a run that quietly graded on the host toolchain is never mistaken for a container one.
# PFB_RUNNER travels with the process because the stderr line does not survive the ways
# this gets used: `2>/dev/null` deletes it, a captured `$(...)` never shows it, and in a
# long test run it scrolls past thousands of lines. `exec` rules out a closing summary, so
# the fact has to be carried in-band — anything downstream, or `env | grep PFB_RUNNER`,
# can then tell a host run from a graded one without having watched the scrollback.
fallback() {
	reason="$1"
	shift
	echo "run-in-docker: ${reason} — running on the host instead" >&2
	PFB_RUNNER=host
	export PFB_RUNNER
	exec "$@"
}

command -v docker >/dev/null 2>&1 ||
	fallback "docker is not installed or not on PATH" "$@"
docker info >/dev/null 2>&1 ||
	fallback "the docker daemon is not reachable (is Docker Desktop running?)" "$@"

git rev-parse --is-inside-work-tree >/dev/null 2>&1 ||
	fallback "not inside a git work tree, so there is nothing to mount" "$@"
root="$(git rev-parse --show-toplevel)"

# `--git-common-dir` is the MAIN repo's .git even from a linked worktree, which is
# exactly the path the worktree's .git file points at.
#
# It can come back RELATIVE, and relative to the CWD — not to the repo root. Joining
# it to the root instead silently produced <root>/../.git from any subdirectory, which
# then failed to resolve. --path-format=absolute settles it outright where git is new
# enough (2.31+); the fallback resolves against the cwd, which is what git means.
common="$(git rev-parse --path-format=absolute --git-common-dir 2>/dev/null || true)"
if [ -z "$common" ]; then
	common="$(git rev-parse --git-common-dir)"
	case "$common" in
	/*) ;;
	*) common="$(pwd)/${common}" ;;
	esac
fi
common="$(CDPATH='' cd "$common" && pwd)"

# The image tracks the series the checkout names, so the wrapper cannot drift from the
# toolchain the gates use. PFB_IMAGE overrides it outright — which is also the escape
# hatch on a checkout that has no VERSION, so the file is only required when it is the
# thing actually being read.
#
# The published packages are currently PRIVATE, so pulling needs a GHCR login that a
# fresh machine will not have. This resolves against what is already on the box first
# and only reaches for the registry as a fallback, so a locally built image just works
# and nobody waits on an auth error to find that out. Both the bare series tag and the
# per-arch tag the build job produces are accepted, since a local build of one image
# usually carries the arch suffix.
image_name='ci-runner'
[ -n "${PFB_VM:-}" ] && image_name='ci-runner-vm'

case "$(uname -m)" in
arm64 | aarch64) host_arch='arm64' ;;
x86_64 | amd64) host_arch='amd64' ;;
*) host_arch="$(uname -m)" ;;
esac

have_locally() { docker image inspect "$1" >/dev/null 2>&1; }

if [ -n "${PFB_IMAGE:-}" ]; then
	image="$PFB_IMAGE"
	candidates="$PFB_IMAGE"
else
	version_file="${root}/.github/docker/VERSION"
	[ -f "$version_file" ] ||
		fallback "no ${version_file} — this checkout predates the CI runner images (set PFB_IMAGE to pick one)" "$@"
	version="$(tr -d '[:space:]' < "$version_file")"
	image="ghcr.io/pfblockerng/${image_name}:${version}"
	candidates="${image} ${image}-${host_arch}"
fi

# PFB_BUILD skips this lookup deliberately. The tag a build writes is one of the
# candidates, so consulting the cache first would make every run after the first find its
# own previous output and reuse it — silently serving a stale image after the Dockerfile
# edit that prompted the rebuild. Docker's layer cache makes an honest re-build near-free.
selected=''
if [ -z "${PFB_BUILD:-}" ]; then
	for candidate in $candidates; do
		if have_locally "$candidate"; then
			selected="$candidate"
			break
		fi
	done
fi

if [ -z "$selected" ]; then
	if [ -z "${PFB_BUILD:-}" ]; then
		if docker pull -q "$image" >/dev/null 2>&1; then
			selected="$image"
		else
			# The one fallback with a cure the caller can apply, so it names it.
			fallback "${image} is absent locally and could not be pulled (the packages are private; PFB_BUILD=1 builds it)" "$@"
		fi
	else
		# Building is the reliable path while the packages are private: the Dockerfile is
		# right here, and it is the same recipe the publish workflow runs. A build that
		# fails is still just "no container available" — the command runs on the host, and
		# docker has already printed the reason above, so the line here only has to say
		# which stage gave up.
		build_tag="${image}-${host_arch}"
		[ -n "${PFB_IMAGE:-}" ] && build_tag="$PFB_IMAGE"
		echo "run-in-docker: building ${build_tag} locally (PFB_BUILD set)" >&2
		build_args=''
		if [ "$image_name" = 'ci-runner-vm' ]; then
			# The VM image extends the base one, so that has to exist first.
			base="ghcr.io/pfblockerng/ci-runner:${version:-latest}-${host_arch}"
			have_locally "$base" ||
				docker build --platform "linux/${host_arch}" \
					--file "${root}/.github/docker/ci-runner.Dockerfile" --tag "$base" "$root" >&2 ||
				fallback "the base image ${base} failed to build (docker's output is above)" "$@"
			build_args="--build-arg BASE_IMAGE=${base}"
		fi
		# shellcheck disable=SC2086
		docker build --platform "linux/${host_arch}" ${build_args} \
			--file "${root}/.github/docker/${image_name}.Dockerfile" \
			--tag "$build_tag" "$root" >&2 ||
			fallback "${build_tag} failed to build (docker's output is above)" "$@"
		selected="$build_tag"
	fi
fi
image="$selected"

# Only mount the git common dir separately when it is not already under the tree
# being mounted — for a normal clone it is just <root>/.git and the first mount
# already covers it.
git_mount=''
case "$common" in
"${root}"/*) ;;
*) git_mount="$common" ;;
esac

# A TTY only when there is one to attach, so this stays usable in a pipe or a script.
tty_args=''
if [ -t 0 ] && [ -t 1 ]; then
	tty_args='-it'
fi

# HOME must be writable: the invoking user has no passwd entry in the image, so the
# default home would be / and any tool wanting a cache directory would fail.
# PFB_RUNNER is set on both paths, so its ABSENCE means the wrapper was not involved at
# all — a two-value flag would leave a plain host run indistinguishable from a fallback.
# Word-splitting tty_args/git_mount/PFB_DOCKER_ARGS is intentional — they are
# argument lists, not single arguments.
# shellcheck disable=SC2086
exec docker run --rm ${tty_args} \
	--user "$(id -u):$(id -g)" \
	--env HOME=/tmp \
	--env PFB_RUNNER=container \
	--volume "${root}:${root}" \
	${git_mount:+--volume "${git_mount}:${git_mount}"} \
	--workdir "$(pwd)" \
	${PFB_DOCKER_ARGS:-} \
	"$image" \
	"$@"
