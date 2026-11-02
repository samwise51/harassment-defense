import json

import defense
import research


def _account():
    with defense.connect() as con: return defense.create_account(con,'fictional.research')


def test_job_creation_transitions_and_mock_execution(application):
    account=_account();job_id=research.create_job(None,[account],'Synthetic scope')
    claimed=research.claim_next('pytest-worker');assert claimed['id']==job_id and claimed['status']=='running'
    research.run_job(job_id)
    with defense.connect() as con: row=con.execute('SELECT * FROM research_jobs WHERE id=?',(job_id,)).fetchone()
    assert row['status']=='completed' and row['progress']==100 and row['outcome']=='no_relevant_activity'
    assert json.loads(row['results_json'])[0]['reference'].startswith('mock://')


def test_source_failure_is_not_reported_as_no_activity(application):
    account=_account();job_id=research.create_job(None,[account],'simulate:unavailable')
    research.claim_next('pytest-worker');research.run_job(job_id)
    with defense.connect() as con: row=con.execute('SELECT status,outcome FROM research_jobs WHERE id=?',(job_id,)).fetchone()
    assert tuple(row)==('failed','source_unavailable')


def test_queued_job_cancellation(application):
    job_id=research.create_job(None,[],'Synthetic cancellation')
    assert research.cancel_job(job_id)
    with defense.connect() as con: row=con.execute('SELECT status,cancel_requested FROM research_jobs WHERE id=?',(job_id,)).fetchone()
    assert tuple(row)==('canceled',1)


def test_atomic_claim_prevents_duplicate_processing(application):
    job_id=research.create_job(None,[],'Synthetic once')
    assert research.claim_next('worker-one')['id']==job_id
    assert research.claim_next('worker-two') is None
