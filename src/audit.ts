/** One row in the audit trail. Cache fast-path hits are deliberately not
 * recorded: they touch nothing and would add hundreds of noise rows per day.
 * Only requests that reached the DNS API produce events. */
export interface AuditEvent {
	occurredAt: string;
	tokenId: string;
	callerIp: string | null;
	hostname: string;
	recordType: string;
	previousIp: string | null;
	newIp: string;
	outcome: 'updated' | 'no-change';
}

export interface HistoryQuery {
	tokenId: string;
	hostname: string | null;
	limit: number;
}

export const HISTORY_DEFAULT_LIMIT = 100;
export const HISTORY_MAX_LIMIT = 1000;

/** Appends audit events in one batch. Best-effort: an audit failure must
 * never fail the DNS update that already happened; it is logged instead. */
export async function writeAuditEvents(env: Env, events: AuditEvent[]): Promise<void> {
	if (events.length === 0) return;
	try {
		const statement = env.AUDIT_DB.prepare(
			'INSERT INTO audit_events (occurred_at, token_id, caller_ip, hostname, record_type, previous_ip, new_ip, outcome) VALUES (?, ?, ?, ?, ?, ?, ?, ?)',
		);
		await env.AUDIT_DB.batch(
			events.map((e) => statement.bind(e.occurredAt, e.tokenId, e.callerIp, e.hostname, e.recordType, e.previousIp, e.newIp, e.outcome)),
		);
	} catch (error) {
		console.error(`Failed to write ${String(events.length)} audit event(s):`, error);
	}
}

/** Returns the caller's own audit rows, newest first. Tenant isolation is
 * the token ID: callers only ever see events created with their token. */
export async function queryHistory(env: Env, query: HistoryQuery): Promise<Record<string, unknown>[]> {
	const limit = Math.min(Math.max(Math.trunc(query.limit), 1), HISTORY_MAX_LIMIT);
	const base = 'SELECT occurred_at, hostname, record_type, previous_ip, new_ip, outcome, caller_ip FROM audit_events WHERE token_id = ?';
	const statement =
		query.hostname !== null && query.hostname !== ''
			? env.AUDIT_DB.prepare(`${base} AND hostname = ? ORDER BY occurred_at DESC, id DESC LIMIT ?`).bind(
					query.tokenId,
					query.hostname,
					limit,
				)
			: env.AUDIT_DB.prepare(`${base} ORDER BY occurred_at DESC, id DESC LIMIT ?`).bind(query.tokenId, limit);
	const { results } = await statement.all();
	return results;
}
