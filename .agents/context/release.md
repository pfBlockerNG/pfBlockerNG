# Release channels and publication context

Scope: release channels, tags, publication, and Ports/package context. Load when: authoring a
release, changing release workflows, or updating the publication path.

Load this context when authoring a release, changing release workflows, or updating the
Ports/package publication path. The authoring contract is issue #2140; the workflow at the
current repository revision supplies the operational job names and inputs.

## Channel contract

All channels publish the exact package identity `pfSense-pkg-pfBlockerNG`. Channel is
metadata and catalog placement, not a package-name suffix. Channel is explicit and
configured, and never inferred from a tag suffix. The tag trailer carries only the channel,
using `pfBlockerNG-Release-Channel: <stable|testing|edge>`; the exact configured release line
is validated separately. Every operation uses a pinned source SHA.

| Channel | Source | Tag and package version | Release and notes |
| --- | --- | --- | --- |
| Stable | configured `release/X.Y` | `vX.Y.Z` / `X.Y.Z` | final Release; authored notes |
| Testing | configured `release/X.Y` | `vX.Y.Z.aN`, `.bN`, or `.rN` / exact version | prerelease; authored notes |
| Edge | configured `release/X.Y` | same Testing grammar / exact version | follows Testing; authored notes |
| Nightly | explicit pinned source SHA | untagged; date counter only | no GitHub Release; no release notes |

Stable, Testing, and Edge share one release-line target. Edge follows Testing only when no distinct target
exists; distinct-target Edge uses its configured target/line. With no distinct
target configured, mirror the exact existing Testing Release and artifact bytes,
checksums, source, provenance, tag, and notes. Do not rebuild or create a second Release.
When the target becomes Stable, Edge follows Testing until a new target exists.

## Nightly identity and ordering

Nightly is independent of Stable, Testing, and Edge. Generate it only when the immutable
input changes. Use UTC date `YYYYMMDD`; changed inputs on the same date receive
`YYYYMMDD_1`, then `_2`. An unchanged input or skipped day is a no-op. Identity includes:

- source SHA;
- FreeBSD-ports SHA; and
- matrix/dependency digest.

The Ports recipe is static: publication must not make a routine version commit. Nightly has
no target final and no PORTEPOCH. Bare date versions intentionally outrank semantic releases;
reverse movement is an explicit repo-qualified downgrade, never an inferred fallback.
The ordering rule is that bare date versions intentionally outrank semantic releases.

## Publication boundaries

Stable, Testing, and Edge may create one Release per exact immutable tag and attach artifacts
verified from that source. The release workflow creates the tag only after build/check gates
pass and leaves a draft; `release-with-changelog` authors notes and publishes it. Nightly
creates no tag, Release, or notes and must not enter the release-note path.

Use `scripts/release-version.sh` as the parser and validator. It receives the tag and explicit
channel/source context; callers must not duplicate its grammar or guess a channel from a
suffix. A published Release is immutable. Asset, checksum, source, and provenance identity
must remain paired, and an existing identity may be retried only without rebuilding it.

## Maintained lines and fixes

Stable and Testing can coexist on every maintained `release/X.Y`; one explicitly configured
line supplies Edge. Branch-name ordering never selects an Edge line. Fixes start on the oldest
affected maintained line, then move forward with `git cherry-pick -x` through newer lines and
finally the configured development source, with separate PRs and gates.

The self-hosted catalog keeps the exact package identity and records channel metadata outside
the package name. EOL route-only behavior and unsupported downgrade policy remain unchanged;
retained artifacts provide availability and provenance, not a general downgrade guarantee.

## Scope

This context documents authoring and publication contracts only. It does not select branches,
mutate catalogs, alter the on-box update client, or add release workflow mechanisms. Builder,
publisher, catalog, and client migration work remains with the issue owners named by #2140.
