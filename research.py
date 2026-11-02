"""Durable SQLite-backed research queue and authorized source adapter contracts."""
from __future__ import annotations

import json
import os
import sqlite3
import uuid
from dataclasses import asdict, dataclass
from typing import Literal, Protocol

import defense

Outcome = Literal['no_relevant_activity','no_new_source_data','source_unavailable',
                  'authentication_failure','incomplete','completed_successfully']


@dataclass(frozen=True)
class SourceItem:
    reference: str
    account_id: int
    summary: str
    relevant: bool


@dataclass(frozen=True)
class SourceResult:
    outcome: Outcome
    items: tuple[SourceItem, ...]
    processed_references: tuple[str, ...]
    warning: str = ''


class SourceAdapter(Protocol):
    name: str
    def collect(self, account_ids: list[int], scope: str, previously_processed: set[str]) -> SourceResult: ...


class MockTikTokAdapter:
    """Synthetic adapter only; performs no network access or scraping."""
    name = 'mock_tiktok'

    def collect(self, account_ids: list[int], scope: str, previously_processed: set[str]) -> SourceResult:
        if 'simulate:unavailable' in scope:
            return SourceResult('source_unavailable',(),(), 'Synthetic source outage')
        if 'simulate:auth_failure' in scope:
            return SourceResult('authentication_failure',(),(), 'Synthetic authentication failure')
        refs = tuple(f'mock://tiktok/account/{account_id}/item/1' for account_id in account_ids)
        fresh = [ref for ref in refs if ref not in previously_processed]
        if not fresh:
            return SourceResult('no_new_source_data',(),refs)
        items = tuple(SourceItem(ref,int(ref.split('/')[4]),'Synthetic development item; no real person or allegation.',False) for ref in fresh)
        return SourceResult('no_relevant_activity',items,refs)


ADAPTERS: dict[str,SourceAdapter] = {'mock_tiktok': MockTikTokAdapter()}


def create_job(investigation_id: int | None, account_ids: list[int], scope: str,
               adapter: str = 'mock_tiktok', con: sqlite3.Connection | None = None) -> str:
    if adapter not in ADAPTERS:
        raise ValueError('Unknown or unauthorized source adapter')
    own = con is None
    connection = con or defense.connect()
    try:
        if investigation_id is not None and not connection.execute('SELECT 1 FROM investigations WHERE id=?',(investigation_id,)).fetchone():
            raise ValueError('Investigation not found')
        known = {row[0] for row in connection.execute('SELECT id FROM accounts WHERE id IN (%s)' % ','.join('?'*len(account_ids)),account_ids)} if account_ids else set()
        if known != set(account_ids):
            raise ValueError('One or more selected accounts do not exist')
        job_id = uuid.uuid4().hex
        stamp = defense.now()
        connection.execute('''INSERT INTO research_jobs(id,investigation_id,selected_account_ids,scope,source_adapter,created_utc,updated_utc)
                              VALUES(?,?,?,?,?,?,?)''',(job_id,investigation_id,json.dumps(sorted(set(account_ids))),scope[:4000],adapter,stamp,stamp))
        if own: connection.commit()
        return job_id
    finally:
        if own: connection.close()


def claim_next(worker_id: str, con: sqlite3.Connection | None = None):
    own = con is None
    connection = con or defense.connect()
    try:
        connection.execute('BEGIN IMMEDIATE')
        row = connection.execute("SELECT * FROM research_jobs WHERE status='queued' AND cancel_requested=0 ORDER BY created_utc LIMIT 1").fetchone()
        if not row:
            connection.commit(); return None
        stamp = defense.now()
        changed = connection.execute("UPDATE research_jobs SET status='running',progress=1,started_utc=?,updated_utc=?,lease_owner=?,lease_utc=? WHERE id=? AND status='queued'",
                                     (stamp,stamp,worker_id,stamp,row['id'])).rowcount
        connection.commit()
        return connection.execute('SELECT * FROM research_jobs WHERE id=?',(row['id'],)).fetchone() if changed else None
    finally:
        if own: connection.close()


def cancel_job(job_id: str, con: sqlite3.Connection | None = None) -> bool:
    own = con is None; connection = con or defense.connect()
    try:
        stamp = defense.now()
        changed = connection.execute("""UPDATE research_jobs SET cancel_requested=1,
          status=CASE WHEN status='queued' THEN 'canceled' ELSE status END,
          completed_utc=CASE WHEN status='queued' THEN ? ELSE completed_utc END,updated_utc=?
          WHERE id=? AND status IN ('queued','running')""",(stamp,stamp,job_id)).rowcount
        if own: connection.commit()
        return bool(changed)
    finally:
        if own: connection.close()


def run_job(job_id: str, con: sqlite3.Connection | None = None) -> None:
    own = con is None; connection = con or defense.connect()
    try:
        row = connection.execute('SELECT * FROM research_jobs WHERE id=?',(job_id,)).fetchone()
        if not row or row['status'] != 'running':
            raise ValueError('Job is not running')
        if row['cancel_requested']:
            _finish(connection,job_id,'canceled',0,None,[],[],''); return
        adapter = ADAPTERS.get(row['source_adapter'])
        if not adapter:
            _finish(connection,job_id,'failed',0,'incomplete',[],[], 'Source adapter is unavailable'); return
        try:
            connection.execute('UPDATE research_jobs SET progress=25,updated_utc=? WHERE id=?',(defense.now(),job_id)); connection.commit()
            result = adapter.collect(json.loads(row['selected_account_ids']),row['scope'],set(json.loads(row['processed_references'])))
            current = connection.execute('SELECT cancel_requested FROM research_jobs WHERE id=?',(job_id,)).fetchone()
            if current['cancel_requested']:
                _finish(connection,job_id,'canceled',25,'incomplete',[],list(result.processed_references),'Canceled by user'); return
            status = 'failed' if result.outcome in ('source_unavailable','authentication_failure') else 'completed'
            _finish(connection,job_id,status,100,result.outcome,[asdict(i) for i in result.items],list(result.processed_references),result.warning)
        except Exception as exc:
            _finish(connection,job_id,'failed',0,'incomplete',[],[],str(exc)[:2000])
    finally:
        if own: connection.close()


def _finish(con, job_id, status, progress, outcome, results, references, error):
    stamp = defense.now()
    con.execute('''UPDATE research_jobs SET status=?,progress=?,outcome=?,results_json=?,processed_references=?,error=?,completed_utc=?,updated_utc=?,lease_owner=NULL,lease_utc=NULL WHERE id=?''',
                (status,progress,outcome,json.dumps(results),json.dumps(references),error,stamp,stamp,job_id))
    con.commit()


def work_once(worker_id: str | None = None) -> bool:
    job = claim_next(worker_id or f'worker-{os.getpid()}')
    if not job: return False
    run_job(job['id']); return True
