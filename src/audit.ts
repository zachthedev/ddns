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

/**
 * The sort key of the last row already returned, which the next page resumes at.
 *
 * A timestamp alone cannot resume the walk: a batch writes several rows in one
 * millisecond, so a boundary can land inside a group sharing a timestamp, and a
 * comparison would then either repeat that group or drop the rest of it. The
 * row id is the only value that is unique and stable enough to settle it.
 *
 * That id is a table-wide sequence, so a caller can read the deployment's total
 * audit volume off a cursor, and by polling can time other tenants' activity. On
 * a deployment one household runs, it says nothing the caller does not own.
 *
 * Signing or encrypting the pair with a deployment secret would close the
 * channel and keep the walk identical, and it is not done here because no such
 * secret is guaranteed to exist: ACCESS_KEY is optional, and the deployments
 * that leave it unset are exactly the shared ones where this would matter. The
 * README states the caveat rather than the mechanism pretending it away.
 */
export interface HistoryCursor {
	occurredAt: string;
	id: number;
}

export interface HistoryQuery {
	tokenId: string;
	hostname: string | null;
	limit: number;
	before: HistoryCursor | null;
}

export interface HistoryPage {
	events: Record<string, unknown>[];
	/** Pass back as `before` to continue; null when this page is the last. */
	cursor: string | null;
}

export const HISTORY_DEFAULT_LIMIT = 100;
export const HISTORY_MAX_LIMIT = 1000;

/** The exact shape `new Date().toISOString()` writes into `occurred_at`. */
const OCCURRED_AT_PATTERN = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/;

/** Plain digits, short of the range where an integer stops being exact. */
const ROW_ID_PATTERN = /^\d{1,15}$/;

/**
 * Reads a `before` value, or null when it is not one this module emitted.
 *
 * The wire form is `<occurred_at>|<id>`, which callers pass back verbatim. Both
 * halves are matched against the shape the writer produces rather than coerced:
 * `Number` alone accepts `0x10`, `1e3`, and a leading newline, so a value that
 * never came from here would read as one that did.
 */
export function parseHistoryCursor(raw: string): HistoryCursor | null {
	const separator = raw.lastIndexOf('|');
	if (separator <= 0) {
		return null;
	}
	const occurredAt = raw.slice(0, separator);
	const id = raw.slice(separator + 1);
	if (!OCCURRED_AT_PATTERN.test(occurredAt) || !isCanonicalTimestamp(occurredAt) || !ROW_ID_PATTERN.test(id)) {
		return null;
	}
	return { occurredAt, id: Number(id) };
}

/**
 * Whether the value is a date and not merely shaped like one.
 *
 * The pattern admits `2026-99-99T99:99:99.999Z`, which sorts above every real
 * row and would hand back the first page again. That is the restart the 422
 * exists to prevent, reached through a value the pattern let through.
 */
function isCanonicalTimestamp(value: string): boolean {
	const parsed = new Date(value);
	return !Number.isNaN(parsed.getTime()) && parsed.toISOString() === value;
}

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

/** Returns the caller's own audit rows, newest first, with the cursor that
 * continues them. Tenant isolation is the token ID: callers only ever see
 * events created with their token, and the cursor is applied inside that
 * scope, so one cannot walk into another's rows. */
export async function queryHistory(env: Env, query: HistoryQuery): Promise<HistoryPage> {
	// Finite before clamped: Math.trunc(NaN) is NaN, and every comparison
	// against it is false, so the clamp would pass it through to the bind and
	// SQLite would reject the statement.
	const requested = Number.isFinite(query.limit) ? query.limit : HISTORY_DEFAULT_LIMIT;
	const limit = Math.min(Math.max(Math.trunc(requested), 1), HISTORY_MAX_LIMIT);
	const filters = ['token_id = ?'];
	const binds: (string | number)[] = [query.tokenId];
	if (query.hostname !== null && query.hostname !== '') {
		filters.push('hostname = ?');
		binds.push(query.hostname);
	}
	if (query.before !== null) {
		// Two predicates rather than one row-value comparison, because the sort
		// mixes directions. The first is a plain range on the leading index
		// column, which is what keeps a deep page costing the page rather than
		// the history behind it; the second drops the rows of the boundary group
		// that already went out.
		filters.push('occurred_at <= ? AND (occurred_at < ? OR id > ?)');
		binds.push(query.before.occurredAt, query.before.occurredAt, query.before.id);
	}
	// Ascending inside a group sharing a timestamp. An audit row is written
	// after the response through waitUntil, so it can land well after the
	// timestamp it carries; taking the highest id last means a row arriving into
	// a group the walk is still crossing is picked up rather than sorted behind
	// a cursor that already passed it.
	const sql = `SELECT id, occurred_at, hostname, record_type, previous_ip, new_ip, outcome, caller_ip FROM audit_events WHERE ${filters.join(' AND ')} ORDER BY occurred_at DESC, id ASC LIMIT ?`;
	// One row past the page, so a full page is told from a last page without a
	// second query and without ever answering with an empty final page.
	const { results } = await env.AUDIT_DB.prepare(sql)
		.bind(...binds, limit + 1)
		.all();
	const page = results.slice(0, limit);
	const last = page.at(-1);
	const cursor = last === undefined || results.length <= limit ? null : `${String(last['occurred_at'])}|${String(last['id'])}`;
	return {
		// `id` orders the walk and is not something the caller asked for.
		events: page.map(({ id: _id, ...event }) => event),
		// Read back through the parser before it goes out. A row whose timestamp
		// this module did not write, from a backfill or an operator insert, would
		// otherwise produce a cursor the next request refuses, and the walk would
		// die on a 422 blaming the caller for a value the server handed it. One
		// page and no cursor is the honest answer instead.
		cursor: cursor !== null && parseHistoryCursor(cursor) !== null ? cursor : null,
	};
}
