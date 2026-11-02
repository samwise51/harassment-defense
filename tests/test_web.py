import io

import defense


def test_unauthorized_access_is_redirected(client):
    for path in ('/','/people','/accounts','/investigations','/incidents','/evidence','/research-jobs'):
        assert client.get(path).status_code==302


def test_csrf_is_required(client):
    with client.session_transaction() as session: session['authenticated']=True
    assert client.post('/people',data={'display_name':'Synthetic'}).status_code==400


def test_people_accounts_and_cases_through_ui(client,auth):
    response=client.post('/people',data={**auth,'display_name':'','notes':'Synthetic notes'});assert response.status_code==302
    response=client.post('/accounts',data={**auth,'handle':'fictional.web','classification':'watched','research_notes':'Synthetic'});assert response.status_code==302
    response=client.post('/investigations',data={**auth,'title':'Synthetic UI case','description':'Fictional only'});assert response.status_code==302
    assert b'Synthetic UI case' in client.get('/investigations').data


def test_existing_incident_review_report_and_upload(application,client,auth):
    with defense.connect() as con: account=defense.create_account(con,'fictional.compat')
    response=client.post('/incidents',data={**auth,'account_id':str(account),'description':'Entirely fictional description','url':'https://www.tiktok.com/@fictional/video/123','evidence':(io.BytesIO(b'synthetic image bytes'),'screen.png')},content_type='multipart/form-data')
    assert response.status_code==302
    with defense.connect() as con: incident=con.execute('SELECT id FROM incidents').fetchone()[0]
    response=client.post(f'/incidents/{incident}/review',data={**auth,'review_status':'reviewed','claim_status':'unverified'});assert response.status_code==302
    assert client.post('/report',data=auth).status_code==200


def test_private_evidence_download_requires_auth(application,client,auth):
    test_existing_incident_review_report_and_upload(application,client,auth)
    with defense.connect() as con: artifact=con.execute('SELECT id FROM artifacts').fetchone()[0]
    with client.session_transaction() as session: session.clear()
    assert client.get(f'/evidence/{artifact}').status_code==302


def test_failed_multifile_upload_removes_staged_object(application,client,auth):
    response=client.post('/incidents',data={**auth,'description':'Synthetic failed upload','evidence':[(io.BytesIO(b'valid first file'),'first.txt'),(io.BytesIO(b'invalid second file'),'second.exe')]},content_type='multipart/form-data')
    assert response.status_code==302
    with defense.connect() as con:
        assert con.execute('SELECT COUNT(*) FROM incidents').fetchone()[0]==0
        assert con.execute('SELECT COUNT(*) FROM artifacts').fetchone()[0]==0
    assert list(defense.EVIDENCE.iterdir())==[]


def test_authenticated_navigation_pages_render(client,auth):
    for path in ('/','/people','/accounts','/investigations','/incidents','/evidence','/research-jobs'):
        response=client.get(path)
        assert response.status_code==200
        assert b'Harassment Defense' in response.data
