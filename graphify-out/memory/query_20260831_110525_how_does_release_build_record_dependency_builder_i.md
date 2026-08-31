---
type: "query"
date: "2026-08-31T11:05:25.699841+00:00"
question: "How does release build-record dependency_builder interact with matrix_row.extra_pkgs and release/3.3 compatibility, and which tests cover that workflow/schema contract?"
contributor: "graphify"
outcome: "useful"
---

# Q: How does release build-record dependency_builder interact with matrix_row.extra_pkgs and release/3.3 compatibility, and which tests cover that workflow/schema contract?

## Answer

The release workflow writes build records in .github/workflows/release.yml; scripts/pfb_pkg.py validates the strict schema. tests/test_release_tag_after_verify.py exercises release/3.3 matrix/extras emission, while tests/test_pfb_pkg.py covers dependency_builder validation.

## Outcome

- Signal: useful