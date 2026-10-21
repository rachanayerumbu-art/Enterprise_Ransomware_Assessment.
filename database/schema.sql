-- Enterprise Ransomware Risk Assessment System
-- SQLite Database Schema

CREATE TABLE IF NOT EXISTS risks (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    risk_id TEXT UNIQUE NOT NULL,
    title TEXT NOT NULL,
    description TEXT NOT NULL,
    affected_asset TEXT NOT NULL,
    threat_source TEXT NOT NULL,
    existing_controls TEXT,
    likelihood INTEGER NOT NULL CHECK(likelihood BETWEEN 1 AND 5),
    impact INTEGER NOT NULL CHECK(impact BETWEEN 1 AND 5),
    risk_score INTEGER NOT NULL,
    risk_level TEXT NOT NULL,
    nist_function TEXT NOT NULL,
    nist_category TEXT NOT NULL,
    nist_category_id TEXT NOT NULL,
    nist_explanation TEXT,
    recommended_mitigation TEXT NOT NULL,
    risk_owner TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'Open',
    target_date TEXT,
    is_sample INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS audit_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    action TEXT NOT NULL,
    risk_id TEXT,
    details TEXT,
    timestamp TEXT NOT NULL DEFAULT (datetime('now'))
);

-- Trigger: keep updated_at current on every UPDATE
CREATE TRIGGER IF NOT EXISTS risks_updated_at
AFTER UPDATE ON risks
FOR EACH ROW
BEGIN
    UPDATE risks SET updated_at = datetime('now') WHERE id = OLD.id;
END;
