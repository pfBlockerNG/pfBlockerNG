---
type: "query"
date: "2026-09-14T11:05:04.377233+00:00"
question: "pfb_run_migrations pfb_install_registry_writeback pfb_install_settings_migrate_record"
contributor: "graphify"
outcome: "useful"
---

# Q: pfb_run_migrations pfb_install_registry_writeback pfb_install_settings_migrate_record

## Answer

Installer snapshots/restores the target family, captures section modes, runs migrations via pfb_install_settings_family_finalize, then performs registry writeback. The new policy must preserve this ordering and keep stored group choices separate from effective global overrides.

## Outcome

- Signal: useful