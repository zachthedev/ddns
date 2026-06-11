-- Audit trail of DNS record changes. Append-only; no retention purge
-- (rows are tiny and compliance prefers complete history).
CREATE TABLE audit_events (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	occurred_at TEXT NOT NULL,
	token_id TEXT NOT NULL,
	caller_ip TEXT,
	hostname TEXT NOT NULL,
	record_type TEXT NOT NULL,
	previous_ip TEXT,
	new_ip TEXT NOT NULL,
	outcome TEXT NOT NULL CHECK (outcome IN ('updated', 'no-change'))
);

-- History reads are always tenant-scoped by token, newest first, with an
-- optional hostname filter; both indexes lead with the tenant key.
CREATE INDEX idx_audit_token_time ON audit_events (token_id, occurred_at DESC);
CREATE INDEX idx_audit_token_hostname_time ON audit_events (token_id, hostname, occurred_at DESC);
