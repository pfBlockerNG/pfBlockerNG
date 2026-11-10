# Release channels and publication context

Scope: release channels, tags, publication, Ports/package context. Load when: authoring release, changing release workflows, updating publication path.

Authoring contract = issue #2140. Workflow at current repo revision supply operational job names and inputs.

## Channel contract

All channels publish exact package identity `pfSense-pkg-pfBlockerNG`. Channel = metadata + catalog placement, not package-name suffix. The tag trailer carries the channel via `pfBlockerNG-Release-Channel: <stable|testing|edge>`; tag and trailer must agree with deterministic version rule below. Exact configured release line validated separately. Every operation use pinned source SHA.

| Channel | Source | Tag and package version | Release and notes |
| --- | --- | --- | --- |
| Stable | configured `release/X.Y` | `vX.Y.Z` / `X.Y.Z` | final Release; authored notes |
| Testing | configured `release/X.Y` | `vX.Y.Z.aN`, `.bN`, or `.rN` with `Z != 0` / exact version | prerelease; authored notes |
| Edge | configured `release/X.Y` | `vX.Y.0.aN`, `.bN`, or `.rN` / exact version | prerelease; authored notes |
| Nightly | explicit pinned source SHA | `YYYYMMDDHHMMSS.<7-character source SHA>` | no GitHub Release; no release notes |

Stable, Testing, Edge may share release line. For prerelease tag: `Z == 0` selects Edge, `Z != 0` selects Testing.

## Nightly identity and ordering

Nightly independent of Stable, Testing, Edge. Every scheduled or manual invocation builds one snapshot. Use UTC `YYYYMMDDHHMMSS.<7-character source SHA>`. Failed runs stay failed; dispatch another when wanted. No counter, deduplication, or durable state exists. Identity include:

- source SHA;
- FreeBSD-ports SHA; and
- matrix/dependency digest.

Ports recipe static: publication must not make routine version commit. Nightly have no target final, no PORTEPOCH. Timestamped Nightly versions intentionally outrank semantic releases; reverse movement = explicit repo-qualified downgrade, never inferred fallback.

## Publication boundaries

Stable, Testing, Edge may create one Release per exact immutable tag and attach artifacts verified from that source. Release workflow create tag only after build/check gates pass, leave draft; `release-with-changelog` author notes and publish it. Nightly create no tag, no Release, no notes — must not enter release-note path.

Use `scripts/release-version.sh` as parser and validator. It receive tag and channel/source context, reject channel that disagree with patch-zero rule. Published Release immutable. Asset, checksum, source, provenance identity must stay paired; existing identity may be retried only without rebuilding it.

## Maintained lines and fixes

Stable, Testing, Edge can coexist on every maintained `release/X.Y`; tagged patch number select Testing or Edge. Branch-name ordering never select channel. Fixes start on oldest affected maintained line, then move forward with `git cherry-pick -x` through newer lines, finally configured development source — separate PRs and gates.

Self-hosted catalog keep exact package identity, record channel metadata outside package name. EOL route-only behavior and unsupported downgrade policy unchanged; retained artifacts give availability and provenance, not general downgrade guarantee.

### Cutting a new `release/X.Y` from `devel`

Each line's CI builds with the ports recipe that tracks it, set by defaults in the branch's own files (#3825): `devel` says `nightly`, a release line says `edge`. A branch cut from `devel` inherits `nightly`, so its first commit switches every default to `edge`:

- `.github/workflows/build-pkg-linux.yml`: both `channel` input defaults.
- `channel:` passed by `smoke.yml`, `smoke-single.yml`, `ui-tests.yml`, `build-image.yml`.
- `PKG_CHANNEL` in `version-tracker.yml`.
- `_CHANNEL` default in `scripts/local-smoke.sh`; the `--channel` default in `scripts/smoke-on-box.sh`.
- `DEFAULT_CHANNEL` in `tests/smoke/pkg_identity.py`.

Enumerate with `git grep -n nightly -- .github/workflows scripts/local-smoke.sh scripts/smoke-on-box.sh tests/smoke/pkg_identity.py`; do not trust this list alone. The `-edge` port's `files/modules.txt` and tuples in `pfBlockerNG/FreeBSD-ports` must match the new line's `go/pfb_dns_gateway/go.mod` before its first build.

## Scope

This context document authoring and publication contracts only. Not select branches, not mutate catalogs, not alter on-box update client, not add release workflow mechanisms. Builder, publisher, catalog, client migration work stay with issue owners named by #2140.
