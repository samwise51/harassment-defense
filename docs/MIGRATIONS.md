# Migration, rollback, and recovery

## Safety rules

Never run the first v0.2.0 migration against the only copy of a production database. Stop application writes, back up the complete `private` directory, verify the backup, and rehearse on a synthetic or copied database in an isolated Compose project.

## Rehearsal

1. Keep production running while preparing an **offline copy** of `private` using a method appropriate to the host. Do not inspect evidence contents.
2. Place the copy in an isolated, owner-only directory and set development configuration to that copy.
3. Run `python defense.py migrate` or start `compose.dev.yaml` against the copy.
4. Run `python -m pytest -q` separately against disposable fixtures.
5. Confirm row counts for `accounts`, `incidents`, and `artifacts`, open representative records through the authenticated UI, and run evidence integrity checks.
6. Record the backup path, hashes, and restore test outcome before approving production downtime.

Migration 001 is additive: it retains all three v0.1.0 tables and rows, adds nullable/defaulted columns, creates new tables/indexes, backfills timestamps/usernames, and records `PRAGMA user_version=1` plus `schema_migrations` version 1. Re-running it is idempotent.

## Production upgrade (human-reviewed operation)

1. Schedule downtime and stop only the Harassment Defense web/worker containers.
2. Make a consistent backup of the entire production `private` directory and `.env`; protect both as sensitive.
3. Build the reviewed v0.2.0 image.
4. Run migration once, inspect output/status, then start web and worker.
5. Verify authentication, legacy records, evidence counts/integrity, and localhost-only binding.

These production operations were **not** performed during development.

## Rollback

The application does not attempt a destructive down-migration. To roll back safely:

1. Stop v0.2.0 web and worker to prevent writes.
2. Preserve the failed upgraded directory for diagnosis.
3. Restore the complete pre-upgrade `private` backup as a unit (database, evidence, reports) with owner UID/GID 10001 and modes `0700` for directories and `0600` for sensitive files.
4. Start the previously pinned v0.1.0 image and verify localhost binding, authentication, row counts, and evidence integrity.

Any records created only in v0.2.0 will not exist in the pre-upgrade backup. Export/reconciliation requires a separately reviewed procedure; never overwrite the backup in place.
