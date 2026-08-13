# Archive

Completed one-shot tooling, kept for provenance and removed from active
maintenance scope. Nothing here runs in CI or ships in a release archive
(release archives contain only `src/`).

## `redmine_to_github.py` + `redmine-import.yml` + `test_redmine_to_github.py`

One-shot migration of open pfBlockerNG issues from the pfSense Redmine tracker
(<https://redmine.pfsense.org>) to GitHub issues on this repository, preserving
comment threads. The migration is **complete** — imported issues carry the
`redmine-imported` label.

The workflow was moved out of `.github/workflows/` so it can no longer be
dispatched. To run the migration again (idempotent), move `redmine-import.yml`
back under `.github/workflows/` and dispatch it, or run the script directly
(requires `REDMINE_API_KEY` + `GITHUB_TOKEN` in the environment).

The test exercises the script's pure helpers; it lives here beside the script
as provenance and is not part of the active `pytest` suite (`testpaths =
["tests"]`).
