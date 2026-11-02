import os
from pathlib import Path

os.environ.setdefault('APP_ADMIN_TOKEN','synthetic-test-admin-token-000000000000')
os.environ.setdefault('APP_SECRET_KEY','synthetic-test-secret-key-0000000000000')
os.environ.setdefault('DATABASE_PATH','/tmp/harassment-defense-pytest-global/cases.db')
os.environ.setdefault('EVIDENCE_STORAGE_PATH','/tmp/harassment-defense-pytest-global/evidence')
os.environ.setdefault('REPORTS_PATH','/tmp/harassment-defense-pytest-global/reports')

import pytest
from app import create_app


@pytest.fixture
def application(tmp_path):
    app=create_app({
        'TESTING':True,'ADMIN_TOKEN':'test-password','SECRET_KEY':'test-secret',
        'DATABASE_PATH':str(tmp_path/'cases.db'),'EVIDENCE_PATH':str(tmp_path/'evidence'),
        'REPORTS_PATH':str(tmp_path/'reports'),'MAX_EVIDENCE_FILE_BYTES':1024,
        'MAX_CONTENT_LENGTH':4096,
    })
    return app


@pytest.fixture
def client(application): return application.test_client()


@pytest.fixture
def auth(client):
    with client.session_transaction() as session:
        session['authenticated']=True;session['csrf']='test-csrf'
    return {'csrf_token':'test-csrf'}
