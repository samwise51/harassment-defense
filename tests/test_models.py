import sqlite3
from pathlib import Path

import defense


def test_people_names_optional(application):
    with defense.connect() as con:
        stamp=defense.now()
        con.execute('INSERT INTO people(display_name,notes,created_utc,updated_utc) VALUES(NULL,?,?,?)',('',stamp,stamp))
        con.execute('INSERT INTO people(display_name,notes,created_utc,updated_utc) VALUES(?,?,?,?)',('Fictional Casey','',stamp,stamp))
        rows=con.execute('SELECT display_name FROM people ORDER BY id').fetchall()
    assert [r[0] for r in rows] == [None,'Fictional Casey']


def test_multiple_accounts_and_reassociation_are_audited(application):
    with defense.connect() as con:
        stamp=defense.now()
        p1=con.execute('INSERT INTO people(display_name,notes,created_utc,updated_utc) VALUES(?,?,?,?)',('Fictional Alex','',stamp,stamp)).lastrowid
        p2=con.execute('INSERT INTO people(display_name,notes,created_utc,updated_utc) VALUES(?,?,?,?)',('Fictional Blair','',stamp,stamp)).lastrowid
        a1=defense.create_account(con,'fictional.one');a2=defense.create_account(con,'fictional.two')
        defense.associate_identity(con,a1,p1,'user_provided','Synthetic user statement')
        defense.associate_identity(con,a2,p1,'evidence_supported','Synthetic evidence basis')
        defense.associate_identity(con,a1,p2,'disputed','Corrected by fictional reviewer')
        assert con.execute('SELECT COUNT(*) FROM identity_associations WHERE person_id=? AND active=1',(p1,)).fetchone()[0] == 1
        assert con.execute('SELECT person_id FROM accounts WHERE id=?',(a1,)).fetchone()[0] == p2
        assert con.execute('SELECT COUNT(*) FROM identity_audit WHERE account_id=?',(a1,)).fetchone()[0] >= 3


def test_ai_identity_suggestion_requires_review(application):
    with defense.connect() as con:
        stamp=defense.now();person=con.execute('INSERT INTO people(display_name,notes,created_utc,updated_utc) VALUES(NULL,?,?,?)',('',stamp,stamp)).lastrowid
        account=defense.create_account(con,'fictional.ai')
        association=defense.associate_identity(con,account,person,'unknown','Synthetic suggestion',source='ai')
        row=con.execute('SELECT review_status FROM identity_associations WHERE id=?',(association,)).fetchone()
        assert row[0]=='pending'
        assert con.execute('SELECT person_id FROM accounts WHERE id=?',(account,)).fetchone()[0] is None


def test_investigation_links_roles_and_incident(application):
    with defense.connect() as con:
        stamp=defense.now();protected=defense.create_account(con,'fictional.protected',classification='protected');watched=defense.create_account(con,'fictional.watched',classification='watched')
        case=con.execute('INSERT INTO investigations(case_id,title,created_utc,updated_utc) VALUES(?,?,?,?)',('HD-TEST0001','Synthetic case',stamp,stamp)).lastrowid
        incident='synthetic001';con.execute('INSERT INTO incidents(id,account_id,url,observed_utc,recorded_utc,description,updated_utc) VALUES(?,?,?,?,?,?,?)',(incident,watched,'',stamp,stamp,'Entirely fictional incident',stamp))
        con.execute('INSERT INTO investigation_accounts VALUES(?,?,?,?)',(case,protected,'protected',stamp));con.execute('INSERT INTO investigation_accounts VALUES(?,?,?,?)',(case,watched,'watched',stamp));con.execute('INSERT INTO investigation_incidents VALUES(?,?,?)',(case,incident,stamp))
        assert con.execute('SELECT COUNT(*) FROM investigation_accounts WHERE investigation_id=?',(case,)).fetchone()[0]==2
        assert con.execute('SELECT COUNT(*) FROM investigation_incidents WHERE investigation_id=?',(case,)).fetchone()[0]==1


def test_v010_migration_preserves_rows(tmp_path,monkeypatch):
    db=tmp_path/'legacy.db';con=sqlite3.connect(db)
    defense._legacy_schema(con);con.execute("INSERT INTO accounts(handle,note,added_utc) VALUES('fictionallegacy','kept','2026-01-01T00:00:00+00:00')");con.execute("INSERT INTO incidents(id,url,observed_utc,recorded_utc,description) VALUES('legacy000001','','2026-01-01T00:00:00+00:00','2026-01-01T00:00:00+00:00','preserved')");con.commit();con.close()
    monkeypatch.setattr(defense,'EVIDENCE',tmp_path/'evidence');monkeypatch.setattr(defense,'REPORTS',tmp_path/'reports')
    defense.migrate(db)
    con=sqlite3.connect(db)
    assert con.execute('SELECT note FROM accounts WHERE handle="fictionallegacy"').fetchone()[0]=='kept'
    assert con.execute('SELECT description FROM incidents WHERE id="legacy000001"').fetchone()[0]=='preserved'
    assert con.execute('PRAGMA user_version').fetchone()[0]==1
    assert con.execute('SELECT COUNT(*) FROM schema_migrations').fetchone()[0]==1
    con.close()
