CREATE TABLE IF NOT EXISTS schema_migrations(version INTEGER PRIMARY KEY,name TEXT NOT NULL,applied_utc TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS people(id INTEGER PRIMARY KEY,display_name TEXT,notes TEXT NOT NULL DEFAULT '',created_utc TEXT NOT NULL,updated_utc TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS identity_associations(
 id INTEGER PRIMARY KEY,account_id INTEGER NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,person_id INTEGER NOT NULL REFERENCES people(id) ON DELETE CASCADE,
 status TEXT NOT NULL DEFAULT 'unknown' CHECK(status IN ('unknown','user_provided','publicly_self_identified','evidence_supported','human_verified','disputed')),
 basis TEXT NOT NULL DEFAULT '',evidence_id INTEGER REFERENCES artifacts(id) ON DELETE SET NULL,suggestion_source TEXT NOT NULL DEFAULT 'researcher' CHECK(suggestion_source IN ('researcher','user','ai')),
 review_status TEXT NOT NULL DEFAULT 'approved' CHECK(review_status IN ('pending','approved','rejected')),active INTEGER NOT NULL DEFAULT 1 CHECK(active IN (0,1)),created_utc TEXT NOT NULL,updated_utc TEXT NOT NULL);
CREATE UNIQUE INDEX IF NOT EXISTS one_active_identity_per_account ON identity_associations(account_id) WHERE active=1 AND review_status='approved';
CREATE TABLE IF NOT EXISTS identity_audit(id INTEGER PRIMARY KEY,association_id INTEGER REFERENCES identity_associations(id) ON DELETE SET NULL,account_id INTEGER NOT NULL,person_id INTEGER,action TEXT NOT NULL,prior_json TEXT,new_json TEXT,actor TEXT NOT NULL DEFAULT 'human_reviewer',created_utc TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS investigations(id INTEGER PRIMARY KEY,case_id TEXT NOT NULL UNIQUE,title TEXT NOT NULL,description TEXT NOT NULL DEFAULT '',protected_person_id INTEGER REFERENCES people(id) ON DELETE SET NULL,status TEXT NOT NULL DEFAULT 'active' CHECK(status IN ('active','paused','under_review','archived')),notes TEXT NOT NULL DEFAULT '',created_utc TEXT NOT NULL,updated_utc TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS investigation_accounts(investigation_id INTEGER NOT NULL REFERENCES investigations(id) ON DELETE CASCADE,account_id INTEGER NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,role TEXT NOT NULL CHECK(role IN ('protected','watched')),created_utc TEXT NOT NULL,PRIMARY KEY(investigation_id,account_id,role));
CREATE TABLE IF NOT EXISTS investigation_incidents(investigation_id INTEGER NOT NULL REFERENCES investigations(id) ON DELETE CASCADE,incident_id TEXT NOT NULL REFERENCES incidents(id) ON DELETE CASCADE,created_utc TEXT NOT NULL,PRIMARY KEY(investigation_id,incident_id));
CREATE TABLE IF NOT EXISTS artifact_incidents(artifact_id INTEGER NOT NULL REFERENCES artifacts(id) ON DELETE CASCADE,incident_id TEXT NOT NULL REFERENCES incidents(id) ON DELETE CASCADE,created_utc TEXT NOT NULL,PRIMARY KEY(artifact_id,incident_id));
CREATE TABLE IF NOT EXISTS research_jobs(
 id TEXT PRIMARY KEY,investigation_id INTEGER REFERENCES investigations(id) ON DELETE SET NULL,selected_account_ids TEXT NOT NULL DEFAULT '[]',scope TEXT NOT NULL DEFAULT '',source_adapter TEXT NOT NULL,
 status TEXT NOT NULL DEFAULT 'queued' CHECK(status IN ('queued','running','completed','failed','canceled')),progress INTEGER NOT NULL DEFAULT 0 CHECK(progress BETWEEN 0 AND 100),
 outcome TEXT CHECK(outcome IN ('no_relevant_activity','no_new_source_data','source_unavailable','authentication_failure','incomplete','completed_successfully')),
 results_json TEXT NOT NULL DEFAULT '[]',error TEXT NOT NULL DEFAULT '',processed_references TEXT NOT NULL DEFAULT '[]',cancel_requested INTEGER NOT NULL DEFAULT 0 CHECK(cancel_requested IN (0,1)),lease_owner TEXT,lease_utc TEXT,
 created_utc TEXT NOT NULL,started_utc TEXT,completed_utc TEXT,updated_utc TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS research_jobs_status_created ON research_jobs(status,created_utc);
CREATE TABLE IF NOT EXISTS relationships(id INTEGER PRIMARY KEY,source_kind TEXT NOT NULL CHECK(source_kind IN ('account','person')),source_id INTEGER NOT NULL,target_kind TEXT NOT NULL CHECK(target_kind IN ('account','person')),target_id INTEGER NOT NULL,relationship_type TEXT NOT NULL,evidence_ids TEXT NOT NULL DEFAULT '[]',review_status TEXT NOT NULL DEFAULT 'pending' CHECK(review_status IN ('pending','approved','rejected','corrected','removed')),confidence REAL CHECK(confidence IS NULL OR confidence BETWEEN 0 AND 1),notes TEXT NOT NULL DEFAULT '',created_utc TEXT NOT NULL,updated_utc TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS accounts_person_id ON accounts(person_id);
CREATE INDEX IF NOT EXISTS artifacts_sha256 ON artifacts(sha256,bytes);
