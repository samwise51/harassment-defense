# Architecture and schema

## Runtime

```text
Browser on localhost
  -> Flask web process (authentication, CSRF, validation, UI)
      -> SQLite (metadata, cases, audit trail, durable queue)
      -> StorageBackend -> LocalStorage (private original files)
  -> research worker
      -> atomic SQLite job claim
      -> SourceAdapter -> MockTikTokAdapter (v0.2 only)

Future, explicitly authorized boundaries:
  SourceAdapter -> official/authorized platform API
  StorageBackend -> S3-compatible private object store
  AIProvider -> OpenAI / Anthropic / Google / Ollama
```

The application has no OpenClaw dependency. External agents can be integrated later only through a separately designed authenticated API.

## Database schema

Existing v0.1.0 tables are retained and extended additively:

- `accounts`: original `handle`, `note`, and timestamps plus platform, username, profile URL, optional compatibility `person_id`, classification, review status, and research notes.
- `incidents`: original fields plus update timestamp.
- `artifacts`: original evidence metadata plus MIME type, source, and storage backend.

New tables:

- `schema_migrations`: applied version ledger.
- `people`: optional display name, notes, timestamps.
- `identity_associations`: account/person link, status, basis, optional evidence, suggestion source, human-review state, active state.
- `identity_audit`: append-only history for association creation, replacement, and removal.
- `investigations`: case ID, title, description, optional protected person, status, notes, timestamps.
- `investigation_accounts`: many-to-many account links with protected/watched role.
- `investigation_incidents`: many-to-many case/incident links.
- `artifact_incidents`: allows one content object to support multiple incidents without duplicate files.
- `research_jobs`: durable queue state, selected accounts, scope, source adapter, progress, outcome, result/error JSON, processed references, cancellation, and lease metadata.
- `relationships`: polymorphic account/person edges, evidence references, review state, optional confidence, and correction/removal lifecycle.

SQLite foreign keys are enabled per connection, WAL mode supports the small web/worker concurrency level, and atomic `BEGIN IMMEDIATE` claims prevent two workers from taking one queued job.

## Storage

`LocalStorage` streams in 1 MiB chunks, computes SHA-256 while writing, generates server-side object keys, enforces a configurable per-file byte limit, uses directory mode `0700` and file mode `0600`, and rejects non-basename keys. Originals are never transformed. Duplicate content reuses one stored object and creates another `artifact_incidents` association.

The `StorageBackend` protocol isolates object operations. The S3-compatible class is an explicit unavailable placeholder; credential, retention, encryption, and authorization design must precede implementation.

## SQLite versus PostgreSQL

SQLite is the safer v0.2.0 choice: one trusted operator, low write concurrency, simple backups, and no destructive engine migration. PostgreSQL becomes advantageous when there are multiple concurrent users/workers, sustained write contention, remote application nodes, row-level security requirements, high-volume graph/report queries, or operational requirements for replication and point-in-time recovery. Migrate only with tested dual-engine migrations and a rehearsed rollback.

## Research and AI safety boundaries

Source outcomes distinguish successful checks from no data, outages, authentication failure, and incomplete work. The only enabled adapter is synthetic. AI result types require citations, uncertainty, allegation labeling, and human review. No cloud provider receives evidence in this release; provider implementations must require explicit authorization and treat evidence text as untrusted data rather than tool instructions.
