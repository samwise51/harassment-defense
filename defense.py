#!/usr/bin/env python3
"""Harassment Defense database, migration, reporting, and compatibility CLI."""
from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import mimetypes
import os
import re
import sqlite3
import sys
import uuid
from pathlib import Path
from urllib.parse import urlparse

from storage import LocalStorage

BASE = Path(__file__).resolve().parent
DB = Path(os.environ.get('DATABASE_PATH', BASE / 'private' / 'cases.db'))
EVIDENCE = Path(os.environ.get('EVIDENCE_STORAGE_PATH', BASE / 'private' / 'evidence'))
REPORTS = Path(os.environ.get('REPORTS_PATH', BASE / 'private' / 'reports'))
MIGRATIONS = BASE / 'migrations'


def now() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat(timespec='seconds')


def connect(db_path: Path | None = None) -> sqlite3.Connection:
    path = Path(db_path or DB)
    if not path.exists():
        raise RuntimeError('Database is not initialized. Run: python defense.py migrate')
    con = sqlite3.connect(path, timeout=30)
    con.row_factory = sqlite3.Row
    con.execute('PRAGMA foreign_keys=ON')
    con.execute('PRAGMA busy_timeout=30000')
    con.execute('PRAGMA journal_mode=WAL')
    return con


def _legacy_schema(con: sqlite3.Connection) -> None:
    con.executescript('''
      CREATE TABLE IF NOT EXISTS accounts(
        id INTEGER PRIMARY KEY, handle TEXT NOT NULL UNIQUE, note TEXT NOT NULL DEFAULT '', added_utc TEXT NOT NULL);
      CREATE TABLE IF NOT EXISTS incidents(
        id TEXT PRIMARY KEY, account_id INTEGER REFERENCES accounts(id), url TEXT NOT NULL DEFAULT '',
        observed_utc TEXT NOT NULL, recorded_utc TEXT NOT NULL, description TEXT NOT NULL,
        claim_status TEXT NOT NULL DEFAULT 'unverified', review_status TEXT NOT NULL DEFAULT 'needs_review');
      CREATE TABLE IF NOT EXISTS artifacts(
        id INTEGER PRIMARY KEY, incident_id TEXT NOT NULL REFERENCES incidents(id), original_name TEXT NOT NULL,
        stored_name TEXT NOT NULL UNIQUE, sha256 TEXT NOT NULL, bytes INTEGER NOT NULL, added_utc TEXT NOT NULL);
    ''')


def _columns(con: sqlite3.Connection, table: str) -> set[str]:
    return {row[1] for row in con.execute(f'PRAGMA table_info({table})')}


def _add_column(con: sqlite3.Connection, table: str, name: str, declaration: str) -> None:
    if name not in _columns(con, table):
        con.execute(f'ALTER TABLE {table} ADD COLUMN {name} {declaration}')


def migrate(db_path: Path | None = None) -> None:
    global DB
    path = Path(db_path or DB)
    path.parent.mkdir(parents=True, exist_ok=True)
    os.chmod(path.parent, 0o700)
    EVIDENCE.mkdir(parents=True, exist_ok=True)
    REPORTS.mkdir(parents=True, exist_ok=True)
    os.chmod(EVIDENCE, 0o700)
    os.chmod(REPORTS, 0o700)
    with sqlite3.connect(path) as con:
        con.execute('PRAGMA foreign_keys=ON')
        _legacy_schema(con)
        # Additive columns preserve every v0.1.0 row and keep its original names.
        for table, name, declaration in (
            ('accounts','platform',"TEXT NOT NULL DEFAULT 'tiktok'"),
            ('accounts','username','TEXT'),
            ('accounts','profile_url',"TEXT NOT NULL DEFAULT ''"),
            ('accounts','person_id','INTEGER REFERENCES people(id) ON DELETE SET NULL'),
            ('accounts','classification',"TEXT NOT NULL DEFAULT 'potentially_involved'"),
            ('accounts','review_status',"TEXT NOT NULL DEFAULT 'needs_review'"),
            ('accounts','research_notes',"TEXT NOT NULL DEFAULT ''"),
            ('accounts','created_utc','TEXT'),
            ('accounts','updated_utc','TEXT'),
            ('incidents','updated_utc','TEXT'),
            ('artifacts','mime_type',"TEXT NOT NULL DEFAULT 'application/octet-stream'"),
            ('artifacts','source',"TEXT NOT NULL DEFAULT 'user_upload'"),
            ('artifacts','storage_backend',"TEXT NOT NULL DEFAULT 'local'"),
        ):
            _add_column(con, table, name, declaration)
        stamp = now()
        con.execute("UPDATE accounts SET username=handle WHERE username IS NULL OR username='' ")
        con.execute('UPDATE accounts SET created_utc=added_utc WHERE created_utc IS NULL')
        con.execute('UPDATE accounts SET updated_utc=added_utc WHERE updated_utc IS NULL')
        con.execute('UPDATE incidents SET updated_utc=recorded_utc WHERE updated_utc IS NULL')
        sql = (MIGRATIONS / '001_research_foundation.sql').read_text(encoding='utf-8')
        con.executescript(sql)
        con.execute('INSERT OR IGNORE INTO schema_migrations(version,name,applied_utc) VALUES(1,?,?)',
                    ('research foundation', stamp))
        con.execute('INSERT OR IGNORE INTO artifact_incidents(artifact_id,incident_id,created_utc) SELECT id,incident_id,added_utc FROM artifacts')
        con.execute('PRAGMA user_version=1')
    os.chmod(path, 0o600)


def init_for_path(db_path: Path, evidence_path: Path, reports_path: Path) -> None:
    global DB, EVIDENCE, REPORTS
    DB, EVIDENCE, REPORTS = db_path, evidence_path, reports_path
    migrate(db_path)


def is_tiktok_url(raw: str) -> bool:
    if not raw:
        return True
    parsed = urlparse(raw)
    hostname = (parsed.hostname or '').lower()
    return parsed.scheme == 'https' and (hostname == 'tiktok.com' or hostname.endswith('.tiktok.com'))


def normalize_handle(raw: str) -> str:
    value = raw.strip().removeprefix('@')
    if not re.fullmatch(r'[A-Za-z0-9._]{2,30}', value):
        raise ValueError('Handle must contain 2–30 letters, digits, dots or underscores')
    return value.lower()


def safe_filename(name: str) -> str:
    return Path(name.replace('\\', '/')).name[:180] or 'evidence'


ALLOWED_SUFFIXES = {'.png','.jpg','.jpeg','.webp','.gif','.pdf','.txt','.mp4','.mov','.webm','.m4a','.mp3','.wav'}


def sha256_file(path: Path) -> str:
    digest=hashlib.sha256()
    with path.open('rb') as source:
        for block in iter(lambda:source.read(1024*1024),b''): digest.update(block)
    return digest.hexdigest()


def save_upload(con: sqlite3.Connection, incident_id: str, upload, max_bytes: int, source: str = 'user_upload') -> tuple[int, bool]:
    original = safe_filename(upload.filename)
    suffix = Path(original).suffix.lower()
    if suffix not in ALLOWED_SUFFIXES:
        raise ValueError(f'Unsupported evidence type: {original}')
    backend = LocalStorage(EVIDENCE)
    stored = backend.store(upload.stream, suffix, max_bytes)
    duplicate = con.execute('SELECT id,stored_name FROM artifacts WHERE sha256=? AND bytes=? ORDER BY id LIMIT 1',
                            (stored.sha256, stored.size)).fetchone()
    if duplicate:
        backend.delete(stored.key)
        con.execute('INSERT OR IGNORE INTO artifact_incidents(artifact_id,incident_id,created_utc) VALUES(?,?,?)',
                    (duplicate['id'], incident_id, now()))
        return duplicate['id'], True
    mime = upload.mimetype or mimetypes.guess_type(original)[0] or 'application/octet-stream'
    cur = con.execute('''INSERT INTO artifacts(incident_id,original_name,stored_name,sha256,bytes,added_utc,mime_type,source,storage_backend)
                         VALUES(?,?,?,?,?,?,?,?,?)''',
                      (incident_id, original, stored.key, stored.sha256, stored.size, now(), mime[:120], source[:120], 'local'))
    artifact_id = cur.lastrowid
    con.execute('INSERT INTO artifact_incidents(artifact_id,incident_id,created_utc) VALUES(?,?,?)',
                (artifact_id, incident_id, now()))
    return artifact_id, False


def create_account(con: sqlite3.Connection, handle: str, **values) -> int:
    username = normalize_handle(handle)
    stamp = now()
    con.execute('''INSERT OR IGNORE INTO accounts(handle,username,platform,note,research_notes,profile_url,classification,review_status,added_utc,created_utc,updated_utc)
                   VALUES(?,?,?,?,?,?,?,?,?,?,?)''',
                (username,username,values.get('platform','tiktok'),values.get('note',''),values.get('research_notes',''),
                 values.get('profile_url',''),values.get('classification','potentially_involved'),values.get('review_status','needs_review'),stamp,stamp,stamp))
    return con.execute('SELECT id FROM accounts WHERE handle=?',(username,)).fetchone()[0]


def associate_identity(con: sqlite3.Connection, account_id: int, person_id: int, status: str,
                       basis: str, evidence_id: int | None = None, source: str = 'researcher',
                       review_status: str = 'approved') -> int:
    if source == 'ai':
        review_status = 'pending'
    stamp = now()
    prior = con.execute("SELECT * FROM identity_associations WHERE account_id=? AND active=1 AND review_status='approved'",(account_id,)).fetchone()
    if prior and review_status == 'approved':
        con.execute('UPDATE identity_associations SET active=0,updated_utc=? WHERE id=?',(stamp,prior['id']))
        con.execute('INSERT INTO identity_audit(association_id,account_id,person_id,action,prior_json,created_utc) VALUES(?,?,?,?,?,?)',
                    (prior['id'],account_id,prior['person_id'],'replaced',json.dumps(dict(prior)),stamp))
    cur = con.execute('''INSERT INTO identity_associations(account_id,person_id,status,basis,evidence_id,suggestion_source,review_status,active,created_utc,updated_utc)
                         VALUES(?,?,?,?,?,?,?,?,?,?)''',
                      (account_id,person_id,status,basis[:4000],evidence_id,source,review_status,1,stamp,stamp))
    association_id = cur.lastrowid
    if review_status == 'approved':
        con.execute('UPDATE accounts SET person_id=?,updated_utc=? WHERE id=?',(person_id,stamp,account_id))
    con.execute('INSERT INTO identity_audit(association_id,account_id,person_id,action,new_json,created_utc) VALUES(?,?,?,?,?,?)',
                (association_id,account_id,person_id,'created',json.dumps({'status':status,'basis':basis,'review_status':review_status}),stamp))
    return association_id


def remove_identity(con: sqlite3.Connection, association_id: int) -> None:
    row = con.execute('SELECT * FROM identity_associations WHERE id=?',(association_id,)).fetchone()
    if not row:
        raise ValueError('Association not found')
    stamp = now()
    con.execute('UPDATE identity_associations SET active=0,review_status=?,updated_utc=? WHERE id=?',('rejected',stamp,association_id))
    con.execute('UPDATE accounts SET person_id=NULL,updated_utc=? WHERE id=? AND person_id=?',(stamp,row['account_id'],row['person_id']))
    con.execute('INSERT INTO identity_audit(association_id,account_id,person_id,action,prior_json,created_utc) VALUES(?,?,?,?,?,?)',
                (association_id,row['account_id'],row['person_id'],'removed',json.dumps(dict(row)),stamp))


def generate_report() -> Path:
    with connect() as con:
        rows = con.execute('SELECT i.*,a.handle FROM incidents i LEFT JOIN accounts a ON a.id=i.account_id ORDER BY i.observed_utc,i.id').fetchall()
        artifacts = con.execute('''SELECT x.incident_id,a.* FROM artifact_incidents x JOIN artifacts a ON a.id=x.artifact_id ORDER BY x.incident_id,a.id''').fetchall()
    grouped: dict[str,list] = {}
    for artifact in artifacts:
        grouped.setdefault(artifact['incident_id'],[]).append(artifact)
    lines = ['# Harassment evidence summary','',f'Generated (UTC): {now()}','',
             '**Draft for human review only. Descriptions are allegations, not independently verified findings.**','']
    for item in rows:
        lines += [f"## Incident {item['id']}",'',f"- Account: @{item['handle']}" if item['handle'] else '- Account: unknown',
                  f"- URL: {item['url'] or 'not provided'}",f"- Observed: {item['observed_utc']}",
                  f"- Review status: {item['review_status']}",f"- Claim assessment: {item['claim_status']}",
                  '- Description (user supplied):','',item['description'],'']
        for artifact in grouped.get(item['id'],[]):
            lines += [f"- Evidence: {artifact['original_name']} | SHA-256 `{artifact['sha256']}` | {artifact['bytes']} bytes",'']
    REPORTS.mkdir(parents=True,exist_ok=True)
    path = REPORTS / ('case-summary-'+dt.datetime.now(dt.timezone.utc).strftime('%Y%m%d-%H%M%S-%f')+'.md')
    path.write_text('\n'.join(lines),encoding='utf-8')
    os.chmod(path,0o600)
    return path


def cmd_watch(args) -> None:
    with connect() as con:
        create_account(con,args.handle,note=args.note or '')
    print('Watchlist entry:', '@'+normalize_handle(args.handle),'(manual evidence submission only; no scraping)')


def cmd_incident(args) -> None:
    if not is_tiktok_url(args.url): raise SystemExit('URL must be an https:// TikTok URL or omitted')
    if not args.description.strip(): raise SystemExit('Description cannot be empty')
    try: observed=dt.datetime.fromisoformat((args.observed or now()).replace('Z','+00:00')).isoformat()
    except ValueError: raise SystemExit('Observed timestamp must be ISO-8601')
    incident_id=uuid.uuid4().hex[:12];stamp=now();created=[]
    try:
        with connect() as con:
            account_id=create_account(con,args.handle) if args.handle else None
            con.execute('INSERT INTO incidents(id,account_id,url,observed_utc,recorded_utc,description,updated_utc) VALUES(?,?,?,?,?,?,?)',(incident_id,account_id,args.url or '',observed,stamp,args.description.strip()[:20000],stamp))
            for raw_path in args.file or []:
                path=Path(raw_path).expanduser().resolve(strict=True)
                if not path.is_file(): raise ValueError('Evidence path must be a regular file')
                class Upload: pass
                upload=Upload();upload.filename=path.name;upload.mimetype=mimetypes.guess_type(path.name)[0]
                with path.open('rb') as stream:
                    upload.stream=stream
                    artifact_id,duplicate=save_upload(con,incident_id,upload,int(os.environ.get('MAX_EVIDENCE_FILE_MB','512'))*1024*1024)
                    if not duplicate: created.append(con.execute('SELECT stored_name FROM artifacts WHERE id=?',(artifact_id,)).fetchone()[0])
    except Exception:
        storage=LocalStorage(EVIDENCE)
        for key in created: storage.delete(key)
        raise
    print('Saved incident:',incident_id,'| evidence files:',len(args.file or []))


def cmd_verify(_args) -> None:
    failed=0
    with connect() as con: rows=con.execute('SELECT stored_name,sha256 FROM artifacts').fetchall()
    storage=LocalStorage(EVIDENCE)
    for row in rows:
        if not storage.verify(row['stored_name'],row['sha256']):
            failed+=1;print('FAILED:',row['stored_name'])
    print('Verified',len(rows)-failed,'of',len(rows),'evidence files')
    if failed: raise SystemExit(1)


def cmd_list(args) -> None:
    with connect() as con:
        if args.kind == 'accounts':
            for row in con.execute('SELECT handle,note,added_utc FROM accounts ORDER BY added_utc DESC'):
                print('@'+row['handle'],'|',row['added_utc'],'|',row['note'])
        else:
            for row in con.execute('SELECT i.id,a.handle,i.observed_utc,i.review_status,i.description FROM incidents i LEFT JOIN accounts a ON a.id=i.account_id ORDER BY i.recorded_utc DESC'):
                print(row['id'],'|','@'+row['handle'] if row['handle'] else 'unknown account','|',row['observed_utc'],'|',row['review_status'],'|',row['description'][:90])


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest='command',required=True)
    for name in ('init','migrate'):
        command = commands.add_parser(name); command.set_defaults(func=lambda _args: migrate())
    watch = commands.add_parser('watch'); watch.add_argument('--handle',required=True); watch.add_argument('--note',default=''); watch.set_defaults(func=cmd_watch)
    incident=commands.add_parser('incident');incident.add_argument('--handle');incident.add_argument('--url',default='');incident.add_argument('--description',required=True);incident.add_argument('--observed');incident.add_argument('--file',action='append');incident.set_defaults(func=cmd_incident)
    listing = commands.add_parser('list'); listing.add_argument('kind',choices=['accounts','incidents']); listing.set_defaults(func=cmd_list)
    report = commands.add_parser('report'); report.set_defaults(func=lambda _args: print('Report:',generate_report()))
    verify = commands.add_parser('verify'); verify.set_defaults(func=cmd_verify)
    args = parser.parse_args(); args.func(args)


if __name__ == '__main__':
    main()
