import io
from pathlib import Path

import pytest
from werkzeug.datastructures import FileStorage

import defense
from storage import LocalStorage


def _incident(con,ident):
    stamp=defense.now();con.execute('INSERT INTO incidents(id,url,observed_utc,recorded_utc,description,updated_utc) VALUES(?,?,?,?,?,?)',(ident,'',stamp,stamp,'Synthetic incident',stamp))


def test_evidence_hash_integrity_and_duplicate_reuse(application):
    payload=b'synthetic evidence bytes'
    with defense.connect() as con:
        _incident(con,'synthetic001');_incident(con,'synthetic002')
        first,duplicate1=defense.save_upload(con,'synthetic001',FileStorage(io.BytesIO(payload),filename='proof.txt',content_type='text/plain'),1024)
        second,duplicate2=defense.save_upload(con,'synthetic002',FileStorage(io.BytesIO(payload),filename='copy.txt',content_type='text/plain'),1024)
        row=con.execute('SELECT * FROM artifacts WHERE id=?',(first,)).fetchone()
        assert first==second and not duplicate1 and duplicate2
        assert con.execute('SELECT COUNT(*) FROM artifact_incidents WHERE artifact_id=?',(first,)).fetchone()[0]==2
    assert LocalStorage(defense.EVIDENCE).verify(row['stored_name'],row['sha256'])


def test_file_limit_streaming_and_invalid_extension(application):
    with defense.connect() as con:
        _incident(con,'synthetic003')
        with pytest.raises(ValueError,match='exceeds'):
            defense.save_upload(con,'synthetic003',FileStorage(io.BytesIO(b'x'*1025),filename='large.mp4',content_type='video/mp4'),1024)
        with pytest.raises(ValueError,match='Unsupported'):
            defense.save_upload(con,'synthetic003',FileStorage(io.BytesIO(b'x'),filename='bad.exe'),1024)


def test_storage_rejects_path_traversal(application):
    storage=LocalStorage(defense.EVIDENCE)
    with pytest.raises(ValueError): storage.path('../cases.db')
    with pytest.raises(ValueError): storage.open('/etc/passwd')
