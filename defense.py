#!/usr/bin/env python3
"""Local harassment evidence tracker. Python 3.10+, standard library only."""
import argparse
import datetime as dt
import hashlib
import json
import os
import re
import shutil
import sqlite3
import sys
import uuid
from pathlib import Path
from urllib.parse import urlparse

BASE = Path(__file__).resolve().parent
DB = BASE / 'private' / 'cases.db'
EVIDENCE = BASE / 'private' / 'evidence'
REPORTS = BASE / 'private' / 'reports'

def now():
    return dt.datetime.now(dt.timezone.utc).isoformat(timespec='seconds')

def connect():
    if not DB.exists():
        raise SystemExit('Not initialized. Run: python defense.py init')
    con = sqlite3.connect(DB)
    con.row_factory = sqlite3.Row
    con.execute('PRAGMA foreign_keys=ON')
    return con

def is_tiktok_url(raw):
    if not raw:
        return True
    u = urlparse(raw)
    hostname = (u.hostname or '').lower()
    return u.scheme == 'https' and (hostname == 'tiktok.com' or hostname.endswith('.tiktok.com'))

def sha256_file(path):
    h = hashlib.sha256()
    with path.open('rb') as f:
        for b in iter(lambda: f.read(1024 * 1024), b''):
            h.update(b)
    return h.hexdigest()

def cmd_init(_):
    for p in (DB.parent, EVIDENCE, REPORTS):
        p.mkdir(parents=True, exist_ok=True)
        os.chmod(p, 0o700)
    with sqlite3.connect(DB) as con:
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
    os.chmod(DB, 0o600)
    print('Initialized private local case directory:', DB.parent)

def normalize_handle(raw):
    raw = raw.strip().removeprefix('@')
    if not re.fullmatch(r'[A-Za-z0-9._]{2,30}', raw):
        raise SystemExit('Handle must contain 2–30 letters, digits, dots or underscores')
    return raw.lower()

def cmd_watch(args):
    h = normalize_handle(args.handle)
    with connect() as con:
        con.execute('INSERT OR IGNORE INTO accounts(handle,note,added_utc) VALUES (?,?,?)', (h,args.note or '',now()))
    print('Watchlist entry:', '@' + h, '(manual evidence submission only; no scraping)')

def cmd_incident(args):
    if not is_tiktok_url(args.url):
        raise SystemExit('URL must be an https:// TikTok URL or omitted')
    if not args.description.strip():
        raise SystemExit('Description cannot be empty')
    handle = normalize_handle(args.handle) if args.handle else None
    incident_id = uuid.uuid4().hex[:12]
    observed = args.observed or now()
    try:
        dt.datetime.fromisoformat(observed.replace('Z','+00:00'))
    except ValueError:
        raise SystemExit('Observed timestamp must be ISO-8601 e.g. 2026-11-02T14:30:00-05:00')
    evidence_files = [Path(p).expanduser().resolve(strict=True) for p in (args.file or [])]
    for f in evidence_files:
        if not f.is_file():
            raise SystemExit('Evidence path must be a regular file: '+str(f))
        if f.stat().st_size > 1024*1024*1024:
            raise SystemExit('Evidence file over 1 GiB; split or handle manually: '+str(f))
    staged = []
    try:
        for path in evidence_files:
            dest_name = uuid.uuid4().hex + path.suffix.lower()[:16]
            dest = EVIDENCE / dest_name
            with path.open('rb') as src, dest.open('xb') as dst:
                os.chmod(dest,0o600)
                shutil.copyfileobj(src,dst,1024*1024)
            staged.append((path.name,dest_name,sha256_file(dest),dest.stat().st_size))
        with connect() as con:
            account_id = None
            if handle:
                con.execute('INSERT OR IGNORE INTO accounts(handle,note,added_utc) VALUES (?,?,?)',(handle,'',now()))
                account_id = con.execute('SELECT id FROM accounts WHERE handle=?',(handle,)).fetchone()[0]
            con.execute('''INSERT INTO incidents(id,account_id,url,observed_utc,recorded_utc,description)
                           VALUES (?,?,?,?,?,?)''',(incident_id,account_id,args.url or '',observed,now(),args.description.strip()))
            for orig,stored,digest,size in staged:
                con.execute('INSERT INTO artifacts(incident_id,original_name,stored_name,sha256,bytes,added_utc) VALUES(?,?,?,?,?,?)',
                            (incident_id,orig,stored,digest,size,now()))
    except Exception:
        for _, stored, _, _ in staged:
            (EVIDENCE/stored).unlink(missing_ok=True)
        raise
    print('Saved incident:',incident_id, '| evidence files:',len(staged))

def cmd_list(args):
    with connect() as con:
        if args.kind=='accounts':
            rows = con.execute('SELECT handle,note,added_utc FROM accounts ORDER BY added_utc DESC').fetchall()
            for r in rows:
                print('@'+r['handle'], '|',r['added_utc'],'|',r['note'])
        else:
            rows = con.execute('''SELECT i.id,a.handle,i.observed_utc,i.review_status,i.description FROM incidents i
                                  LEFT JOIN accounts a ON a.id=i.account_id ORDER BY i.recorded_utc DESC''').fetchall()
            for r in rows:
                print(r['id'], '|', '@'+r['handle'] if r['handle'] else 'unknown account', '|',r['observed_utc'], '|',r['review_status'], '|',r['description'][:90])

def cmd_report(args):
    with connect() as con:
        rows = con.execute('''SELECT i.*,a.handle FROM incidents i LEFT JOIN accounts a ON a.id=i.account_id
                              ORDER BY i.observed_utc,i.id''').fetchall()
        artifacts = con.execute('SELECT * FROM artifacts ORDER BY incident_id,id').fetchall()
    by_incident={}
    for a in artifacts:
        by_incident.setdefault(a['incident_id'],[]).append(a)
    lines=['# Harassment evidence summary','',f'Generated (UTC): {now()}','',
           '**Draft for human review only. Descriptions are allegations, not independently verified findings.**','']
    for i in rows:
        lines += [f"## Incident {i['id']}", '', f"- Account: @{i['handle']}" if i['handle'] else '- Account: unknown',
                  f"- URL: {i['url'] or 'not provided'}",f"- Observed: {i['observed_utc']}",
                  f"- Review status: {i['review_status']}",f"- Claim assessment: {i['claim_status']}",
                  '- Description (user supplied):', '', i['description'], '']
        for a in by_incident.get(i['id'],[]):
            lines += [f"- Evidence: {a['original_name']} | SHA-256 `{a['sha256']}` | {a['bytes']} bytes",'']
    report=REPORTS / ('case-summary-'+dt.datetime.now(dt.timezone.utc).strftime('%Y%m%d-%H%M%S')+'.md')
    report.write_text('\n'.join(lines),encoding='utf-8')
    os.chmod(report,0o600)
    print('Report:',report)

def cmd_verify(_):
    with connect() as con:
        rows=con.execute('SELECT stored_name,sha256 FROM artifacts').fetchall()
    failed=0
    for a in rows:
        p=EVIDENCE/a['stored_name']
        if not p.is_file() or sha256_file(p)!=a['sha256']:
            failed+=1
            print('FAILED:',a['stored_name'])
    print('Verified',len(rows)-failed,'of',len(rows),'evidence files')
    if failed:
        sys.exit(1)

def main():
    p=argparse.ArgumentParser(description=__doc__)
    sub=p.add_subparsers(dest='command',required=True)
    x=sub.add_parser('init');x.set_defaults(func=cmd_init)
    x=sub.add_parser('watch');x.add_argument('--handle',required=True);x.add_argument('--note',default='');x.set_defaults(func=cmd_watch)
    x=sub.add_parser('incident');x.add_argument('--handle');x.add_argument('--url',default='');x.add_argument('--description',required=True);x.add_argument('--observed');x.add_argument('--file',action='append');x.set_defaults(func=cmd_incident)
    x=sub.add_parser('list');x.add_argument('kind',choices=['accounts','incidents']);x.set_defaults(func=cmd_list)
    x=sub.add_parser('report');x.set_defaults(func=cmd_report)
    x=sub.add_parser('verify');x.set_defaults(func=cmd_verify)
    args=p.parse_args();args.func(args)

if __name__=='__main__':
    main()
