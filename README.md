# Harassment Defense v0.2.0 research foundation

Self-hosted, localhost-only Flask application for organizing investigations, people, social-media accounts, incidents, original evidence, and authorized research jobs. It does **not** scrape TikTok, identify unknown people, make accusations automatically, or require OpenClaw.

## Features

- Optional-name person records and separately modeled social-media accounts.
- Evidence-backed, reversible account/person associations with audit history. AI suggestions remain pending.
- Investigation cases with protected/watched accounts, incidents, notes, status, and non-destructive archiving.
- Streamed, configurable evidence uploads with SHA-256 integrity, metadata, duplicate-content reuse, private authenticated downloads, and no incident-count cap.
- Durable SQLite research queue with progress, cancellation, atomic claiming, restart-safe results, and distinct source outcomes.
- Synthetic mock TikTok adapter. No network collection or unauthorized scraping.
- Provider-neutral typed AI contracts; no AI provider or cloud transmission is enabled.
- CSRF checks, authenticated state-changing routes, restrictive cookies/headers, safe storage keys, and localhost Docker binding.

See [Architecture](docs/ARCHITECTURE.md), [migration and recovery](docs/MIGRATIONS.md), and [security review](docs/SECURITY.md).

## Development (isolated from production)

Create development-only credentials in `.env.dev` (never copy production credentials):

```fish
cp .env.example .env.dev
python -c 'import secrets; from pathlib import Path; p=Path(".env.dev"); p.write_text("APP_ADMIN_TOKEN="+secrets.token_urlsafe(36)+"\nAPP_SECRET_KEY="+secrets.token_urlsafe(48)+"\nDATABASE_PATH=/app/private/cases.db\nEVIDENCE_STORAGE_PATH=/app/private/evidence\nREPORTS_PATH=/app/private/reports\nMAX_EVIDENCE_FILE_MB=512\nMAX_REQUEST_MB=1024\n")'
chmod 600 .env.dev
docker compose -f compose.dev.yaml up -d --build
```

Open `http://127.0.0.1:18088`. The standalone file uses project name `harassment-defense-dev`, named volume `hd-dev-private`, and no production bind mount. Do not combine it with `compose.yaml`.

Run tests locally:

```fish
python -m venv .venv
.venv/bin/pip install -r requirements-dev.txt
.venv/bin/pytest -q
```

All tests use disposable databases, synthetic records, and isolated evidence directories.

## Production-shaped deployment

`compose.yaml` remains bound to `127.0.0.1:8088`, uses `./private:/app/private`, and starts one web process plus one research worker. Before upgrading, follow `docs/MIGRATIONS.md`, especially the offline backup and restore rehearsal. Never test migrations against the live database.

Configuration:

| Variable | Default | Purpose |
|---|---:|---|
| `DATABASE_PATH` | `/app/private/cases.db` | SQLite database |
| `EVIDENCE_STORAGE_PATH` | `/app/private/evidence` | Original evidence objects |
| `REPORTS_PATH` | `/app/private/reports` | Human-reviewed exports |
| `MAX_EVIDENCE_FILE_MB` | `512` | Per-file streamed upload limit |
| `MAX_REQUEST_MB` | `1024` | Whole HTTP request limit |
| `COOKIE_SECURE` | `0` | Set to `1` only behind correctly configured local HTTPS |

Storage remains unencrypted at application level. Use full-disk encryption, restrictive host permissions, and encrypted backups.
