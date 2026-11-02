# Harassment Defense — Web UI (Phase 1)

Private evidence-management web app: add TikTok accounts, incident URLs and descriptions, upload screenshot/recording evidence, review claims, verify file hashes, and export a Markdown case summary. It does **not** scrape TikTok, check posts automatically, use AI yet, or submit reports. An account watchlist is a manual tracking list.

## CachyOS / fish-shell install

Unzip the project to `~/harassment-defense-web`. Open a fish terminal there and run:

```fish
cd ~/harassment-defense-web
cp .env.example .env
python -c 'import secrets; from pathlib import Path; p=Path(".env"); p.write_text("APP_ADMIN_TOKEN="+secrets.token_urlsafe(36)+"\nAPP_SECRET_KEY="+secrets.token_urlsafe(48)+"\n")'
mkdir -p private
sudo chown -R 10001:10001 private
chmod 700 private
chmod 600 .env
docker compose up -d --build
```

Open **http://127.0.0.1:8088** in a browser on the laptop. The login password is the value after `APP_ADMIN_TOKEN=` in `.env`. To view it locally: `grep '^APP_ADMIN_TOKEN=' .env` (do not share this output). To see logs: `docker compose logs --tail=80`. Shut down: `docker compose down` (does not delete case data).

**Only local machine access is enabled** by the explicit `127.0.0.1` port binding. Do not expose the port on LAN or Internet without HTTPS, authentication hardening, and careful privacy review. Avoid copying private evidence into unrelated OpenClaw workspaces. No VPN rotation, fake accounts, or mass reporting.

## Data and upgrades

The persistent data is in `./private` and includes `cases.db`, `evidence/`, and `reports/`. A Phase 1 CLI database can be migrated *only while the container is stopped*: copy the original `private` directory into the new project (back up both first), then ensure files belong to UID 10001. The existing CLI database schema is reused. Never overwrite a nonempty `private` folder.

## Limits and security

- Each evidence file: 50 MB; total request: 100 MB; 12 files per incident.
- Allowed filename extensions: JPG, PNG, WEBP, GIF, PDF, TXT, MP4, MOV, WEBM, M4A, MP3, WAV. **File content is not malware-scanned or verified for real type.** Do not upload untrusted executable content; downloads are forced as attachments.
- Data is **not encrypted at rest**. Restrict laptop users and secure full-disk encryption/backups.
- Auth uses a local password from `.env` and a cookie session. Intended for one trusted local operator, not multi-user or public hosting. No brute-force limiter; keep localhost-only.
- Avoid including unnecessary identifying data. AI interpretations, when added later, must be labeled unverified and require human review.
- Exports include sensitive incident descriptions; store and share carefully.
