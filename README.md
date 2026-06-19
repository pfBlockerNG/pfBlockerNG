# ci-metadata

Orphan branch holding the pfBlockerNG CI/build metadata. This branch has its
own independent history — it is **not** in the `main → devel` chain.

## Contents

| File | Purpose |
| ---- | ------- |
| `supported-versions.json` | **Single source of truth** for which pfSense versions pfBlockerNG supports and their build environments |
| `supported-versions.schema.json` | JSON Schema for the matrix (validation) |

## Editing the matrix

Edit `supported-versions.json` via a PR targeting `ci-metadata`.
**Do not push directly** — the branch is protected (PR-only) so every
change has a git audit trail (diff/blame/rollback).

Changes here drive all downstream automation:

- `.pkg` artifact builds (one per distinct FreeBSD major)
- `build-image.yml`'s `resolve-version` job (maps `pfsense_ce_version → (freebsd_version, php_version)`)
- CI smoke fan-out (all `ci: true` CE entries)

## Lifecycle policy

- **Add** a new entry when a pfSense beta or GA lands (curated — a human edits this file).
  Set `status: "beta"` until the release goes GA.
- **Drop** the oldest CE entry only when the newest CE goes GA. The supported window
  is always _(previous GA + current GA)_, transiently `+1` during an active beta.
- **Plus** entries are always `ci: false` (build-only — no licensed CI image).
- **EOL (route-only)** — when a version is end-of-lifed but still has installs
  in the field, set `role: "route-only"` + `ci: false` + `last_tag: "<last
  Release tag>"` instead of dropping the entry. It is no longer built or smoked,
  but its last `.pkg` stays served from a frozen catalog so existing installs
  keep updating (ADR-27 Part 2). Absent `role` = `build` (normal); the reader
  keeps a `route-only` entry out of `--print-build`/`-ci`/`-test`, only in
  `--print-route`.

## How workflows read this

```sh
# Fetch the matrix at runtime (default token, no extra permissions needed):
git fetch origin ci-metadata
git show origin/ci-metadata:supported-versions.json

# Or via actions/checkout:
# - ref: ci-metadata
# - sparse-checkout: supported-versions.json
```

See `.github/actions/read-version-matrix/action.yml` for the composite action
and `scripts/read-version-matrix.sh` for the standalone shell reader.

## Future migration

If CI infrastructure grows, `supported-versions.json` can move to a dedicated
public `pfBlockerNG-ci-infra` repo (read via raw URL — no token, no checkout).
That is a mechanical URL swap in the reader; no schema or lifecycle changes needed.
