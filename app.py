from __future__ import annotations

import hmac
import json
import os
import secrets
import uuid
from functools import wraps
from pathlib import Path

from flask import Flask, abort, flash, redirect, render_template, request, send_file, session, url_for

import defense
import research
from storage import LocalStorage

CLASSIFICATIONS = ('protected','watched','potentially_involved','unrelated')
ACCOUNT_REVIEWS = ('needs_review','reviewed')
IDENTITY_STATUSES = ('unknown','user_provided','publicly_self_identified','evidence_supported','human_verified','disputed')
CASE_STATUSES = ('active','paused','under_review','archived')


def create_app(config: dict | None = None) -> Flask:
    app = Flask(__name__)
    app.config.update(
        SECRET_KEY=os.environ.get('APP_SECRET_KEY') or secrets.token_hex(32),
        ADMIN_TOKEN=os.environ.get('APP_ADMIN_TOKEN',''),
        DATABASE_PATH=os.environ.get('DATABASE_PATH',str(defense.DB)),
        EVIDENCE_PATH=os.environ.get('EVIDENCE_STORAGE_PATH',str(defense.EVIDENCE)),
        REPORTS_PATH=os.environ.get('REPORTS_PATH',str(defense.REPORTS)),
        MAX_EVIDENCE_FILE_BYTES=int(os.environ.get('MAX_EVIDENCE_FILE_MB','512'))*1024*1024,
        MAX_CONTENT_LENGTH=int(os.environ.get('MAX_REQUEST_MB','1024'))*1024*1024,
        SESSION_COOKIE_HTTPONLY=True,SESSION_COOKIE_SAMESITE='Strict',SESSION_COOKIE_SECURE=os.getenv('COOKIE_SECURE')=='1',
    )
    if config: app.config.update(config)
    if not app.config.get('TESTING') and len(app.config['ADMIN_TOKEN']) < 20:
        raise RuntimeError('Set APP_ADMIN_TOKEN to a long random value')
    defense.DB = Path(app.config['DATABASE_PATH'])
    defense.EVIDENCE = Path(app.config['EVIDENCE_PATH'])
    defense.REPORTS = Path(app.config['REPORTS_PATH'])
    defense.migrate()

    def db(): return defense.connect()

    def require_auth(fn):
        @wraps(fn)
        def wrapped(*args,**kwargs):
            if not session.get('authenticated'): return redirect(url_for('login',next=request.path))
            return fn(*args,**kwargs)
        return wrapped

    def csrf_token():
        if 'csrf' not in session: session['csrf']=secrets.token_urlsafe(32)
        return session['csrf']
    app.jinja_env.globals['csrf_token']=csrf_token

    @app.before_request
    def csrf_protection():
        if request.method in ('POST','PUT','PATCH','DELETE'):
            expected=session.get('csrf',''); supplied=request.form.get('csrf_token','')
            if not expected or not hmac.compare_digest(expected,supplied): abort(400)

    @app.after_request
    def security_headers(response):
        response.headers['X-Content-Type-Options']='nosniff'
        response.headers['X-Frame-Options']='DENY'
        response.headers['Referrer-Policy']='no-referrer'
        response.headers['Content-Security-Policy']="default-src 'self'; style-src 'self'; script-src 'self'; img-src 'self' data:; form-action 'self'; frame-ancestors 'none'"
        response.headers['Cache-Control']='no-store'
        return response

    @app.get('/login')
    def login(): return render_template('login.html',title='Sign in')

    @app.post('/login')
    def login_post():
        if hmac.compare_digest(request.form.get('password',''),app.config['ADMIN_TOKEN']):
            session.clear();session['authenticated']=True;session['csrf']=secrets.token_urlsafe(32)
            flash('Signed in.','success');return redirect(url_for('index'))
        flash('Incorrect access password.','error');return redirect(url_for('login'))

    @app.post('/logout')
    @require_auth
    def logout(): session.clear(); return redirect(url_for('login'))

    @app.get('/')
    @require_auth
    def index():
        with db() as con:
            counts={name:con.execute(f'SELECT COUNT(*) FROM {name}').fetchone()[0] for name in ('investigations','people','accounts','incidents','artifacts','research_jobs')}
            incidents=con.execute('''SELECT i.*,a.handle,(SELECT COUNT(*) FROM artifact_incidents x WHERE x.incident_id=i.id) file_count FROM incidents i LEFT JOIN accounts a ON a.id=i.account_id ORDER BY i.recorded_utc DESC LIMIT 10''').fetchall()
            cases=con.execute("SELECT * FROM investigations WHERE status!='archived' ORDER BY updated_utc DESC LIMIT 8").fetchall()
        return render_template('dashboard.html',title='Dashboard',counts=counts,incidents=incidents,cases=cases)

    @app.get('/people')
    @require_auth
    def people():
        with db() as con: rows=con.execute('''SELECT p.*,(SELECT COUNT(*) FROM identity_associations x WHERE x.person_id=p.id AND x.active=1 AND x.review_status='approved') account_count FROM people p ORDER BY p.updated_utc DESC''').fetchall()
        return render_template('people.html',title='People',people=rows)

    @app.post('/people')
    @require_auth
    def add_person():
        name=request.form.get('display_name','').strip()[:200] or None; notes=request.form.get('notes','').strip()[:10000];stamp=defense.now()
        with db() as con: person_id=con.execute('INSERT INTO people(display_name,notes,created_utc,updated_utc) VALUES(?,?,?,?)',(name,notes,stamp,stamp)).lastrowid
        flash('Person record created.','success');return redirect(url_for('person_detail',person_id=person_id))

    @app.get('/people/<int:person_id>')
    @require_auth
    def person_detail(person_id):
        with db() as con:
            person=con.execute('SELECT * FROM people WHERE id=?',(person_id,)).fetchone()
            accounts=con.execute('''SELECT a.*,x.id association_id,x.status association_status,x.basis,x.evidence_id FROM identity_associations x JOIN accounts a ON a.id=x.account_id WHERE x.person_id=? AND x.active=1 AND x.review_status='approved' ORDER BY a.handle''',(person_id,)).fetchall()
            available=con.execute("SELECT * FROM accounts WHERE person_id IS NULL ORDER BY handle").fetchall()
        if not person: abort(404)
        return render_template('person_detail.html',title=person['display_name'] or 'Unnamed person',person=person,accounts=accounts,available=available,statuses=IDENTITY_STATUSES)

    @app.post('/people/<int:person_id>')
    @require_auth
    def edit_person(person_id):
        with db() as con: changed=con.execute('UPDATE people SET display_name=?,notes=?,updated_utc=? WHERE id=?',(request.form.get('display_name','').strip()[:200] or None,request.form.get('notes','').strip()[:10000],defense.now(),person_id)).rowcount
        if not changed: abort(404)
        flash('Person updated.','success');return redirect(url_for('person_detail',person_id=person_id))

    @app.post('/people/<int:person_id>/accounts')
    @require_auth
    def link_person_account(person_id):
        try:
            account_id=int(request.form['account_id']);status=request.form.get('status','unknown')
            if status not in IDENTITY_STATUSES: raise ValueError('Invalid association status')
            evidence_id=int(request.form['evidence_id']) if request.form.get('evidence_id') else None
            with db() as con:
                if not con.execute('SELECT 1 FROM people WHERE id=?',(person_id,)).fetchone(): abort(404)
                defense.associate_identity(con,account_id,person_id,status,request.form.get('basis','').strip(),evidence_id)
            flash('Account association saved with audit history.','success')
        except (ValueError,KeyError) as exc: flash(str(exc),'error')
        return redirect(url_for('person_detail',person_id=person_id))

    @app.post('/identity-associations/<int:association_id>/remove')
    @require_auth
    def unlink_identity(association_id):
        with db() as con:
            row=con.execute('SELECT person_id FROM identity_associations WHERE id=?',(association_id,)).fetchone()
            if not row: abort(404)
            defense.remove_identity(con,association_id);person_id=row['person_id']
        flash('Association removed; history retained.','success');return redirect(url_for('person_detail',person_id=person_id))

    @app.get('/accounts')
    @require_auth
    def accounts():
        with db() as con: rows=con.execute('''SELECT a.*,p.display_name,(SELECT COUNT(*) FROM incidents i WHERE i.account_id=a.id) incident_count FROM accounts a LEFT JOIN people p ON p.id=a.person_id ORDER BY a.updated_utc DESC''').fetchall()
        return render_template('accounts.html',title='Accounts',accounts=rows,classifications=CLASSIFICATIONS)

    @app.post('/accounts')
    @require_auth
    def add_account():
        try:
            classification=request.form.get('classification','potentially_involved')
            if classification not in CLASSIFICATIONS: raise ValueError('Invalid classification')
            with db() as con: account_id=defense.create_account(con,request.form.get('handle',''),profile_url=request.form.get('profile_url','').strip()[:1000],classification=classification,research_notes=request.form.get('research_notes','').strip()[:10000])
            flash('Account saved.','success');return redirect(url_for('account_detail',account_id=account_id))
        except ValueError as exc: flash(str(exc),'error');return redirect(url_for('accounts'))

    @app.get('/accounts/<int:account_id>')
    @require_auth
    def account_detail(account_id):
        with db() as con:
            account=con.execute('SELECT a.*,p.display_name FROM accounts a LEFT JOIN people p ON p.id=a.person_id WHERE a.id=?',(account_id,)).fetchone()
            incidents=con.execute('SELECT * FROM incidents WHERE account_id=? ORDER BY recorded_utc DESC',(account_id,)).fetchall()
            associations=con.execute('SELECT x.*,p.display_name FROM identity_associations x JOIN people p ON p.id=x.person_id WHERE x.account_id=? ORDER BY x.created_utc DESC',(account_id,)).fetchall()
        if not account: abort(404)
        return render_template('account_detail.html',title='@'+account['handle'],account=account,incidents=incidents,associations=associations,classifications=CLASSIFICATIONS,reviews=ACCOUNT_REVIEWS)

    @app.post('/accounts/<int:account_id>')
    @require_auth
    def edit_account(account_id):
        classification=request.form.get('classification');review=request.form.get('review_status')
        if classification not in CLASSIFICATIONS or review not in ACCOUNT_REVIEWS: abort(400)
        with db() as con: changed=con.execute('UPDATE accounts SET profile_url=?,classification=?,review_status=?,research_notes=?,updated_utc=? WHERE id=?',(request.form.get('profile_url','').strip()[:1000],classification,review,request.form.get('research_notes','').strip()[:10000],defense.now(),account_id)).rowcount
        if not changed: abort(404)
        flash('Account updated.','success');return redirect(url_for('account_detail',account_id=account_id))

    @app.get('/investigations')
    @require_auth
    def investigations():
        with db() as con:
            rows=con.execute('''SELECT v.*,p.display_name,(SELECT COUNT(*) FROM investigation_accounts x WHERE x.investigation_id=v.id) account_count,(SELECT COUNT(*) FROM investigation_incidents y WHERE y.investigation_id=v.id) incident_count FROM investigations v LEFT JOIN people p ON p.id=v.protected_person_id ORDER BY v.updated_utc DESC''').fetchall()
            people_rows=con.execute('SELECT * FROM people ORDER BY display_name').fetchall()
        return render_template('investigations.html',title='Investigations',investigations=rows,people=people_rows)

    @app.post('/investigations')
    @require_auth
    def add_investigation():
        title=request.form.get('title','').strip()[:300]
        if not title: flash('Case title is required.','error');return redirect(url_for('investigations'))
        stamp=defense.now();case_id='HD-'+uuid.uuid4().hex[:8].upper();person_id=int(request.form['protected_person_id']) if request.form.get('protected_person_id') else None
        with db() as con: investigation_id=con.execute('INSERT INTO investigations(case_id,title,description,protected_person_id,notes,created_utc,updated_utc) VALUES(?,?,?,?,?,?,?)',(case_id,title,request.form.get('description','').strip()[:20000],person_id,request.form.get('notes','').strip()[:10000],stamp,stamp)).lastrowid
        flash('Investigation created.','success');return redirect(url_for('investigation_detail',investigation_id=investigation_id))

    @app.get('/investigations/<int:investigation_id>')
    @require_auth
    def investigation_detail(investigation_id):
        with db() as con:
            item=con.execute('SELECT v.*,p.display_name FROM investigations v LEFT JOIN people p ON p.id=v.protected_person_id WHERE v.id=?',(investigation_id,)).fetchone()
            linked=con.execute('SELECT a.*,x.role FROM investigation_accounts x JOIN accounts a ON a.id=x.account_id WHERE x.investigation_id=? ORDER BY x.role,a.handle',(investigation_id,)).fetchall()
            incidents=con.execute('SELECT i.*,a.handle FROM investigation_incidents x JOIN incidents i ON i.id=x.incident_id LEFT JOIN accounts a ON a.id=i.account_id WHERE x.investigation_id=? ORDER BY i.recorded_utc DESC',(investigation_id,)).fetchall()
            jobs=con.execute('SELECT * FROM research_jobs WHERE investigation_id=? ORDER BY created_utc DESC',(investigation_id,)).fetchall()
            available_accounts=con.execute('SELECT * FROM accounts ORDER BY handle').fetchall(); available_incidents=con.execute('SELECT * FROM incidents ORDER BY recorded_utc DESC').fetchall()
        if not item: abort(404)
        return render_template('investigation_detail.html',title=item['case_id'],item=item,linked=linked,incidents=incidents,jobs=jobs,accounts=available_accounts,available_incidents=available_incidents,statuses=CASE_STATUSES)

    @app.post('/investigations/<int:investigation_id>')
    @require_auth
    def edit_investigation(investigation_id):
        status=request.form.get('status')
        if status not in CASE_STATUSES: abort(400)
        with db() as con: changed=con.execute('UPDATE investigations SET title=?,description=?,status=?,notes=?,updated_utc=? WHERE id=?',(request.form.get('title','').strip()[:300],request.form.get('description','').strip()[:20000],status,request.form.get('notes','').strip()[:10000],defense.now(),investigation_id)).rowcount
        if not changed: abort(404)
        flash('Investigation updated. Evidence was not deleted.','success');return redirect(url_for('investigation_detail',investigation_id=investigation_id))

    @app.post('/investigations/<int:investigation_id>/accounts')
    @require_auth
    def link_case_account(investigation_id):
        role=request.form.get('role');account_id=request.form.get('account_id',type=int)
        if role not in ('protected','watched') or not account_id: abort(400)
        with db() as con:
            con.execute('INSERT OR IGNORE INTO investigation_accounts(investigation_id,account_id,role,created_utc) VALUES(?,?,?,?)',(investigation_id,account_id,role,defense.now()))
            con.execute('UPDATE investigations SET updated_utc=? WHERE id=?',(defense.now(),investigation_id))
        flash('Account linked to investigation.','success');return redirect(url_for('investigation_detail',investigation_id=investigation_id))

    @app.post('/investigations/<int:investigation_id>/incidents')
    @require_auth
    def link_case_incident(investigation_id):
        incident_id=request.form.get('incident_id','')
        with db() as con: con.execute('INSERT OR IGNORE INTO investigation_incidents(investigation_id,incident_id,created_utc) VALUES(?,?,?)',(investigation_id,incident_id,defense.now()))
        flash('Incident linked to investigation.','success');return redirect(url_for('investigation_detail',investigation_id=investigation_id))

    @app.get('/incidents')
    @require_auth
    def incidents():
        with db() as con:
            rows=con.execute('''SELECT i.*,a.handle,(SELECT COUNT(*) FROM artifact_incidents x WHERE x.incident_id=i.id) file_count FROM incidents i LEFT JOIN accounts a ON a.id=i.account_id ORDER BY i.recorded_utc DESC''').fetchall(); account_rows=con.execute('SELECT * FROM accounts ORDER BY handle').fetchall()
        return render_template('incidents.html',title='Incidents',incidents=rows,accounts=account_rows,max_mb=app.config['MAX_EVIDENCE_FILE_BYTES']//1024//1024)

    @app.post('/incidents')
    @require_auth
    def add_incident():
        raw=request.form.get('url','').strip();description=request.form.get('description','').strip()
        if not defense.is_tiktok_url(raw): flash('Use a valid HTTPS TikTok URL.','error');return redirect(url_for('incidents'))
        if not description: flash('Description is required.','error');return redirect(url_for('incidents'))
        incident_id=uuid.uuid4().hex[:12];stamp=defense.now();account_id=request.form.get('account_id',type=int)
        created_keys=[]
        try:
            with db() as con:
                con.execute('INSERT INTO incidents(id,account_id,url,observed_utc,recorded_utc,description,updated_utc) VALUES(?,?,?,?,?,?,?)',(incident_id,account_id,raw,stamp,stamp,description[:20000],stamp))
                duplicates=0
                for upload in request.files.getlist('evidence'):
                    if upload and upload.filename:
                        artifact_id,duplicate=defense.save_upload(con,incident_id,upload,app.config['MAX_EVIDENCE_FILE_BYTES']);duplicates+=int(duplicate)
                        if not duplicate:
                            created_keys.append(con.execute('SELECT stored_name FROM artifacts WHERE id=?',(artifact_id,)).fetchone()[0])
            flash(f'Incident recorded. {duplicates} duplicate file(s) reused.' if duplicates else 'Incident recorded.','success')
            return redirect(url_for('incident',incident_id=incident_id))
        except (ValueError,OSError) as exc:
            storage=LocalStorage(defense.EVIDENCE)
            for key in created_keys: storage.delete(key)
            flash('Unable to save incident: '+str(exc),'error');return redirect(url_for('incidents'))

    @app.get('/incidents/<incident_id>')
    @require_auth
    def incident(incident_id):
        with db() as con:
            item=con.execute('SELECT i.*,a.handle FROM incidents i LEFT JOIN accounts a ON a.id=i.account_id WHERE i.id=?',(incident_id,)).fetchone()
            files=con.execute('SELECT a.* FROM artifact_incidents x JOIN artifacts a ON a.id=x.artifact_id WHERE x.incident_id=? ORDER BY a.id',(incident_id,)).fetchall()
        if not item: abort(404)
        return render_template('incident.html',title='Incident '+incident_id,item=item,files=files)

    @app.post('/incidents/<incident_id>/review')
    @require_auth
    def review(incident_id):
        status=request.form.get('review_status');claim=request.form.get('claim_status')
        if status not in ('needs_review','reviewed','reported') or claim not in ('unverified','supported','contradicted','mixed'): abort(400)
        with db() as con: con.execute('UPDATE incidents SET review_status=?,claim_status=?,updated_utc=? WHERE id=?',(status,claim,defense.now(),incident_id))
        flash('Review saved.','success');return redirect(url_for('incident',incident_id=incident_id))

    @app.get('/evidence')
    @require_auth
    def evidence_list():
        with db() as con: rows=con.execute('SELECT * FROM artifacts ORDER BY added_utc DESC').fetchall()
        return render_template('evidence.html',title='Evidence',evidence=rows)

    @app.get('/evidence/<int:artifact_id>')
    @require_auth
    def evidence(artifact_id):
        with db() as con: artifact=con.execute('SELECT * FROM artifacts WHERE id=?',(artifact_id,)).fetchone()
        if not artifact: abort(404)
        try: path=LocalStorage(defense.EVIDENCE).path(artifact['stored_name'])
        except ValueError: abort(404)
        if not path.is_file(): abort(404)
        return send_file(path,as_attachment=True,download_name=artifact['original_name'],mimetype=artifact['mime_type'])

    @app.post('/evidence/<int:artifact_id>/verify')
    @require_auth
    def verify_evidence(artifact_id):
        with db() as con: artifact=con.execute('SELECT * FROM artifacts WHERE id=?',(artifact_id,)).fetchone()
        if not artifact: abort(404)
        valid=LocalStorage(defense.EVIDENCE).verify(artifact['stored_name'],artifact['sha256'])
        flash('Integrity verified.' if valid else 'Integrity check FAILED.','success' if valid else 'error')
        return redirect(url_for('evidence_list'))

    @app.post('/verify')
    @require_auth
    def verify_all_evidence():
        with db() as con: rows=con.execute('SELECT original_name,stored_name,sha256 FROM artifacts').fetchall()
        storage=LocalStorage(defense.EVIDENCE)
        failed=[row['original_name'] for row in rows if not storage.verify(row['stored_name'],row['sha256'])]
        flash(f'Integrity check: all {len(rows)} evidence files verified.' if not failed else 'Integrity FAILED for: '+', '.join(failed[:8]),'success' if not failed else 'error')
        return redirect(url_for('evidence_list'))

    @app.get('/research-jobs')
    @require_auth
    def research_jobs():
        with db() as con:
            jobs=con.execute('SELECT j.*,v.case_id FROM research_jobs j LEFT JOIN investigations v ON v.id=j.investigation_id ORDER BY j.created_utc DESC').fetchall(); cases=con.execute("SELECT * FROM investigations WHERE status!='archived' ORDER BY title").fetchall(); account_rows=con.execute('SELECT * FROM accounts ORDER BY handle').fetchall()
        return render_template('research_jobs.html',title='Research Jobs',jobs=jobs,cases=cases,accounts=account_rows)

    @app.post('/research-jobs')
    @require_auth
    def add_research_job():
        try:
            account_ids=[int(value) for value in request.form.getlist('account_ids')];investigation_id=request.form.get('investigation_id',type=int)
            job_id=research.create_job(investigation_id,account_ids,request.form.get('scope','').strip(),'mock_tiktok')
            flash('Mock research job queued.','success');return redirect(url_for('research_job_detail',job_id=job_id))
        except ValueError as exc: flash(str(exc),'error');return redirect(url_for('research_jobs'))

    @app.get('/research-jobs/<job_id>')
    @require_auth
    def research_job_detail(job_id):
        with db() as con: job=con.execute('SELECT * FROM research_jobs WHERE id=?',(job_id,)).fetchone()
        if not job: abort(404)
        return render_template('research_job_detail.html',title='Research job',job=job,results=json.loads(job['results_json']))

    @app.post('/research-jobs/<job_id>/run')
    @require_auth
    def run_research_job(job_id):
        with db() as con:
            stamp=defense.now();changed=con.execute("UPDATE research_jobs SET status='running',started_utc=?,updated_utc=?,lease_owner='web-manual',lease_utc=? WHERE id=? AND status='queued'",(stamp,stamp,stamp,job_id)).rowcount
        if changed: research.run_job(job_id);flash('Mock research completed.','success')
        else: flash('Only queued jobs can be run.','error')
        return redirect(url_for('research_job_detail',job_id=job_id))

    @app.post('/research-jobs/<job_id>/cancel')
    @require_auth
    def cancel_research_job(job_id):
        flash('Cancellation requested.' if research.cancel_job(job_id) else 'Job could not be canceled.','success')
        return redirect(url_for('research_job_detail',job_id=job_id))

    @app.post('/report')
    @require_auth
    def report():
        path=defense.generate_report();return send_file(path,as_attachment=True,download_name=path.name,mimetype='text/markdown')

    @app.errorhandler(413)
    def too_large(_): flash('Request exceeds the configured upload limit.','error');return redirect(url_for('incidents'))

    return app


app=create_app()

if __name__=='__main__':
    app.run(host='127.0.0.1',port=8080,debug=False)
