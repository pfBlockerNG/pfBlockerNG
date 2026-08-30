# pfSense Plus 25.11 package artifacts

## Goal

Support pfSense Plus 25.11 package catalogs and Nightly artifacts for FreeBSD 16, PHP 8.4, and Python 3.11. Reject installer targets whose catalog does not exist before creating or replacing an active pkg repository configuration.

This work is tracked by [issue #2926](https://github.com/pfBlockerNG/pfBlockerNG/issues/2926).

## Fixed constraints

- A FreeBSD major may validly have multiple PHP and Python combinations. FreeBSD major alone is not a build identity.
- Nightly build identity is the tuple `(freebsd_major, php_version, py_flavor)`.
- Rows with the same build identity share one package build. Their `extra_pkgs` values are unioned, deduplicated, and sorted.
- pfSense Plus 25.11 uses FreeBSD 16, PHP 8.4, and Python 3.11 (`py311`).
- Netgate already ships `py-charset-normalizer` for Plus 25.11. Its matrix row therefore has `extra_pkgs: []`.
- No licensed `ghcr.io/pfblockerng/pfsense-plus:25.11` image exists. The row has `ci: false`; creating an image and adding a VM smoke leg are out of scope.
- Package identity remains `pfSense-pkg-pfBlockerNG`.
- Nightly handoff JSON keeps its existing schema and field shape. This is a correction of major-only validation and routing, not a new wire object.
- An installer must not create or replace an active `*.conf` repository file until the candidate catalog path has been shown to exist.
- Producer and publisher changes must land in compatibility-safe order.

## Decisions

### Build identity and matrix reduction

`scripts/read-version-matrix.sh` groups build-role rows by the complete build identity rather than by `freebsd_major` alone. Rows for FreeBSD 16/PHP 8.4/Python 3.11 and FreeBSD 16/PHP 8.5/Python 3.11 remain separate. Rows with an identical tuple still reduce to one build and retain the existing `extra_pkgs` union behavior.

The matrix reader no longer rejects different PHP or Python versions solely because they share a FreeBSD major. It continues to reject malformed rows and any ambiguity within one exact build identity.

The `ci-metadata` matrix gains this active build-role row:

- `pfsense_version`: `25.11`
- `channel` and `variant`: `Plus`
- `freebsd_version`: `16.0-RELEASE`
- `freebsd_major`: `16`
- `php_version`: `8.4`
- `py_flavor`: `py311`
- `status`: `active`
- `ci`: `false`
- `image_name`: `pfsense-plus`
- `extra_pkgs`: `[]`
- `upgrade.available`: `false`

### Nightly producer

The Nightly workflow names each result artifact with all build-identity components, for example `nightly-result-16-php8.4-py311`. This prevents two valid FreeBSD 16 builds from overwriting or merging each other's result directories.

`scripts/nightly_provenance.py` indexes expected and observed builds by the complete tuple. It accepts repeated FreeBSD majors when the runtime tuple differs, requires exactly one result for every build tuple, and rejects duplicate or changed tuples. Package ABI remains `FreeBSD:<major>:*`; PHP and Python compatibility remains bound by the validated matrix row and embedded build record.

### Nightly publisher

`pfBlockerNG/pkg` applies the same build-identity function at the ingestion boundary. Its Nightly publisher:

1. Validates each handoff build against one exact build-matrix tuple.
2. Locates each result directory by its tuple-bearing artifact name.
3. Matches every build-role route row to exactly one compatible tuple.
4. Rejects missing, duplicate, unused, or ambiguous builds before writing any catalog.
5. Fans one verified package artifact out only to route rows with the same FreeBSD, PHP, and Python tuple.

The generalized consumer accepts current one-build-per-major handoffs naturally because each such handoff also has unique complete tuples. It lands before the producer, avoiding an incompatible publication window.

### Installer target validation

Both authoritative installer copies use the existing repository hook to generate a candidate conf into a non-`*.conf` temporary file. The candidate contains the same edition/version derivation and canonical URL that would become active; no second version parser is introduced.

The installer extracts the candidate URL and probes its `meta.conf` with the native FreeBSD `fetch` command under a bounded timeout. A successful probe permits the candidate file to replace the active channel conf. A failed probe:

- exits with status 4;
- reports the candidate URL as unsupported or unavailable;
- removes the temporary file;
- leaves an existing active conf byte-identical, or leaves the conf absent on a fresh install;
- does not retire any peer channel conf.

Installing or refreshing the boot hook and trusted fingerprint may occur before the probe. Those operations do not activate a repository path.

After candidate activation, the existing repository-scoped `pkg update`, offered-version selection, package convergence, and post-install verification remain unchanged.

### Deployment order

1. Land the generalized Nightly consumer and installer in `pfBlockerNG/pkg`.
2. Land matrix reduction, Nightly producer, provenance, and installer changes in `pfBlockerNG/pfBlockerNG`.
3. Land the Plus 25.11 row on the protected `ci-metadata` branch.
4. Dispatch one Nightly pinned to the landed `devel` source SHA.
5. Verify OCI handoff publication, the `pfBlockerNG/pkg` publication commit, and the live Plus 25.11 catalog.

## Error handling

- A malformed matrix row fails before build fan-out.
- A duplicate complete build identity that cannot be reduced deterministically fails matrix generation.
- Missing or duplicate Nightly results fail handoff creation.
- A route row with zero or multiple tuple matches fails publisher validation before catalog mutation.
- Artifact ABI, digest, source SHA, ports SHA, matrix digest, build record, and dependency-builder checks remain mandatory.
- Installer probe failure is not classified as a pkg database failure and does not print pfSense repository-repair guidance. No pkg command has run yet.
- Existing bounded publication waits, retries, signature checks, and push containment remain unchanged.

## Acceptance criteria

1. Given two build-role rows sharing FreeBSD 16 but using PHP 8.4 and PHP 8.5, the build matrix contains both exact tuples.
2. Given multiple rows with one exact tuple, the build matrix contains one row whose `extra_pkgs` is the sorted union.
3. Given Nightly results for both FreeBSD 16 tuples, handoff creation accepts both and preserves their exact matrix rows.
4. Given the same handoff, the publisher routes the PHP 8.4 artifact only to Plus 25.11 and routes the PHP 8.5 artifact only to matching rows.
5. Given a duplicate, missing, changed, or ambiguous tuple, producer or publisher validation fails before catalog mutation.
6. Given an absent candidate catalog, the installer exits 4 without creating or changing an active repository conf and without invoking pkg.
7. Given an existing candidate catalog, the installer activates the generated conf and continues through the unchanged convergence path.
8. The `ci-metadata` row for Plus 25.11 has FreeBSD 16, PHP 8.4, `py311`, `extra_pkgs: []`, and `ci: false`.
9. A published Nightly creates `nightly/plus-25.11` with a canonical package whose manifest records the PHP 8.4 and Python 3.11 dependency set.
10. The Plus 25.11 Nightly build emits no charset-normalizer dependency side artifact.

## Verification

Behavior changes use unchanged red-before/green-after regression tests in each affected repository.

### `pfBlockerNG/pfBlockerNG`

- Matrix shell tests cover tuple split, identical-tuple merge, and `extra_pkgs` union.
- Nightly provenance tests cover repeated major with different runtime tuples, complete result coverage, and duplicate tuple rejection.
- Workflow contract tests pin tuple-bearing result artifact names.
- Installer tests use a fake bounded catalog probe and assert failed probes preserve both fresh and pre-existing conf state.
- Focused suites run first; repository gates and CI run after integration.

### `pfBlockerNG/pkg`

- Handoff tests cover repeated major with different runtime tuples and exact build coverage.
- Publisher tests cover tuple-specific route fan-out and missing, duplicate, unused, and ambiguous inputs.
- Installer tests mirror failed-probe preservation and successful activation.
- Focused suites run first; repository gates and CI run after integration.

### Published Nightly

- Nightly workflow completes successfully for its pinned source and matrix SHAs.
- OCI handoff contains separate FreeBSD 16/PHP 8.4 and FreeBSD 16/PHP 8.5 builds.
- `pfBlockerNG/pkg` records the exact source run and Nightly version in its publication commit.
- Live `nightly/plus-25.11` catalog exists and contains the expected canonical package.
- Package manifest inspection confirms PHP 8.4, Python 3.11, and no separately built charset-normalizer package.

No 25.11 VM smoke claim is made because the row is deliberately `ci: false`.

## Out of scope

- Creating or publishing a licensed pfSense Plus 25.11 VM image.
- Adding a Plus 25.11 VM smoke or UI leg.
- Publishing a tagged Stable, Testing, or Edge release.
- Changing package identity, catalog retention, signing, or Nightly version ordering.
- Refactoring unrelated matrix, installer, or publication code.

## Open forks

None.
