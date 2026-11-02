import os, secrets, hmac, uuid, hashlib, datetime as dt
from pathlib import Path
from functools import wraps
from urllib.parse import urlparse
from flask import Flask, render_template, request, redirect, url_for, flash, abort, send_file, session
import defense

app=Flask(__name__)
app.secret_key=os.environ.get('APP_SECRET_KEY') or secrets.token_hex(32)
app.config.update(MAX_CONTENT_LENGTH=100*1024*1024, SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE='Strict')
if os.getenv('COOKIE_SECURE')=='1': app.config['SESSION_COOKIE_SECURE']=True
ADMIN_TOKEN=os.environ.get('APP_ADMIN_TOKEN','')
if not ADMIN_TOKEN or len(ADMIN_TOKEN)<20:
    raise RuntimeError('Set APP_ADMIN_TOKEN in .env to a long random value')

def require_auth(fn):
    @wraps(fn)
    def wrapped(*a,**kw):
        if not session.get('authenticated'):
            return redirect(url_for('login',next=request.path))
        return fn(*a,**kw)
    return wrapped

def form_csrf():
    if 'csrf' not in session: session['csrf']=secrets.token_urlsafe(32)
    return session['csrf']
app.jinja_env.globals['csrf_token']=form_csrf

@app.before_request
def csrf_protection():
    if request.method=='POST':
        expected=session.get('csrf','')
        supplied=request.form.get('csrf_token','')
        if not expected or not hmac.compare_digest(expected,supplied): abort(400)

@app.get('/login')
def login(): return render_template('login.html',title='Sign in')

@app.post('/login')
def login_post():
    if hmac.compare_digest(request.form.get('password',''),ADMIN_TOKEN):
        session.clear();session['authenticated']=True;flash('Signed in.','success');return redirect(url_for('index'))
    flash('Incorrect access password.','error');return redirect(url_for('login'))

@app.post('/logout')
@require_auth
def logout(): session.clear();return redirect(url_for('login'))

@app.get('/')
@require_auth
def index():
    with defense.connect() as con:
        accounts=con.execute('SELECT * FROM accounts ORDER BY added_utc DESC').fetchall()
        incidents=con.execute('''SELECT i.*, a.handle,(SELECT COUNT(*) FROM artifacts x WHERE x.incident_id=i.id) AS file_count FROM incidents i LEFT JOIN accounts a ON i.account_id=a.id ORDER BY i.recorded_utc DESC LIMIT 100''').fetchall()
        counts=(con.execute('SELECT COUNT(*) FROM accounts').fetchone()[0],con.execute('SELECT COUNT(*) FROM incidents').fetchone()[0],con.execute('SELECT COUNT(*) FROM artifacts').fetchone()[0])
    return render_template('index.html',title='Dashboard',accounts=accounts,incidents=incidents,counts=counts)

@app.post('/accounts')
@require_auth
def add_account():
    try: handle=defense.normalize_handle(request.form.get('handle',''))
    except SystemExit as e: flash(str(e),'error');return redirect(url_for('index'))
    note=request.form.get('note','').strip()[:1500]
    with defense.connect() as con:
        con.execute('INSERT OR IGNORE INTO accounts(handle,note,added_utc) VALUES(?,?,?)',(handle,note,defense.now()))
    flash('Added @'+handle+' to your watchlist.','success');return redirect(url_for('index'))

def safe_name(name): return Path(name.replace('\\','/')).name[:180] or 'evidence'

@app.post('/incidents')
@require_auth
def add_incident():
    raw=request.form.get('url','').strip();desc=request.form.get('description','').strip()
    if not defense.is_tiktok_url(raw): flash('Use a valid HTTPS TikTok URL.','error');return redirect(url_for('index'))
    if not desc: flash('Please add an incident description.','error');return redirect(url_for('index'))
    handle=request.form.get('handle','').strip()
    try: handle=defense.normalize_handle(handle) if handle else None
    except SystemExit as e: flash(str(e),'error');return redirect(url_for('index'))
    incident_id=uuid.uuid4().hex[:12];staged=[]
    files=[f for f in request.files.getlist('evidence') if f and f.filename]
    if len(files)>12: flash('Attach at most 12 files per incident.','error');return redirect(url_for('index'))
    allowed={'.png','.jpg','.jpeg','.webp','.gif','.pdf','.txt','.mp4','.mov','.webm','.m4a','.mp3','.wav'}
    try:
        for f in files:
            orig=safe_name(f.filename)
            suffix=Path(orig).suffix.lower()
            if suffix not in allowed: raise ValueError('Unsupported file type: '+orig)
            dest_name=uuid.uuid4().hex+suffix
            target=defense.EVIDENCE/dest_name
            with target.open('xb') as out:
                os.chmod(target,0o600)
                size=0;sha=hashlib.sha256()
                while True:
                    block=f.stream.read(1024*1024)
                    if not block:break
                    size+=len(block)
                    if size>50*1024*1024:raise ValueError('Individual evidence files must be 50 MB or smaller.')
                    sha.update(block);out.write(block)
            staged.append((orig,dest_name,sha.hexdigest(),size))
        with defense.connect() as con:
            account_id=None
            if handle:
                con.execute('INSERT OR IGNORE INTO accounts(handle,note,added_utc) VALUES(?,?,?)',(handle,'',defense.now()))
                account_id=con.execute('SELECT id FROM accounts WHERE handle=?',(handle,)).fetchone()['id']
            con.execute('INSERT INTO incidents(id,account_id,url,observed_utc,recorded_utc,description) VALUES(?,?,?,?,?,?)',(incident_id,account_id,raw,defense.now(),defense.now(),desc[:20000]))
            for orig,stored,digest,size in staged:
                con.execute('INSERT INTO artifacts(incident_id,original_name,stored_name,sha256,bytes,added_utc) VALUES(?,?,?,?,?,?)',(incident_id,orig,stored,digest,size,defense.now()))
    except Exception as exc:
        for _,stored,_,_ in staged: (defense.EVIDENCE/stored).unlink(missing_ok=True)
        # Also purge abandoned partial uploads (which did not reach staged)
        if 'dest_name' in locals():
            p=defense.EVIDENCE/dest_name
            if p.exists() and all(x[1]!=dest_name for x in staged):p.unlink()
        flash('Unable to save incident: '+str(exc),'error');return redirect(url_for('index'))
    flash('Incident '+incident_id+' recorded.','success');return redirect(url_for('incident',incident_id=incident_id))

@app.get('/incidents/<incident_id>')
@require_auth
def incident(incident_id):
    with defense.connect() as con:
        item=con.execute('SELECT i.*, a.handle FROM incidents i LEFT JOIN accounts a ON a.id=i.account_id WHERE i.id=?',(incident_id,)).fetchone()
        files=con.execute('SELECT * FROM artifacts WHERE incident_id=? ORDER BY id',(incident_id,)).fetchall()
    if not item:abort(404)
    return render_template('incident.html',title='Incident '+incident_id,item=item,files=files)

@app.post('/incidents/<incident_id>/review')
@require_auth
def review(incident_id):
    status=request.form.get('review_status')
    claim=request.form.get('claim_status')
    if status not in ('needs_review','reviewed','reported') or claim not in ('unverified','supported','contradicted','mixed'):abort(400)
    with defense.connect() as con:
        con.execute('UPDATE incidents SET review_status=?, claim_status=? WHERE id=?',(status,claim,incident_id))
    flash('Review status saved.','success');return redirect(url_for('incident',incident_id=incident_id))

@app.get('/evidence/<int:artifact_id>')
@require_auth
def evidence(artifact_id):
    with defense.connect() as con: artifact=con.execute('SELECT * FROM artifacts WHERE id=?',(artifact_id,)).fetchone()
    if not artifact:abort(404)
    path=defense.EVIDENCE/artifact['stored_name']
    if not path.is_file():abort(404)
    return send_file(path,as_attachment=True,download_name=artifact['original_name'],mimetype='application/octet-stream')

@app.post('/report')
@require_auth
def report():
    class Args: pass
    defense.cmd_report(Args())
    files=sorted(defense.REPORTS.glob('case-summary-*.md'),key=lambda p:p.stat().st_mtime,reverse=True)
    if not files:abort(500)
    return send_file(files[0],as_attachment=True,download_name=files[0].name,mimetype='text/markdown')

@app.post('/verify')
@require_auth
def verify():
    with defense.connect() as con: files=con.execute('SELECT * FROM artifacts').fetchall()
    bad=[row['original_name'] for row in files if not (defense.EVIDENCE/row['stored_name']).is_file() or defense.sha256_file(defense.EVIDENCE/row['stored_name'])!=row['sha256']]
    flash(('Integrity check: all '+str(len(files))+' evidence files verified.') if not bad else ('Integrity FAILED for: '+', '.join(bad[:8])), 'error' if bad else 'success')
    return redirect(url_for('index'))

@app.errorhandler(413)
def too_large(_): flash('Upload too large: maximum total request is 100 MB.','error');return redirect(url_for('index'))

if __name__=='__main__':
    defense.cmd_init(None)
    app.run(host='127.0.0.1',port=8080,debug=False)
