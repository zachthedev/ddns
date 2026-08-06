import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { writeAuditEvents, queryHistory, parseHistoryCursor, type AuditEvent } from '../src/audit';
import { createMockEnv } from './helpers/mocks';

describe('writeAuditEvents', () => {
	let env: Env;
	let consoleErrorSpy: ReturnType<typeof vi.spyOn>;

	beforeEach(() => {
		env = createMockEnv();
		consoleErrorSpy = vi.spyOn(console, 'error').mockImplementation(() => {});
		vi.spyOn(console, 'log').mockImplementation(() => {});
	});

	afterEach(() => {
		vi.restoreAllMocks();
	});

	const makeEvent = (overrides: Partial<AuditEvent> = {}): AuditEvent => ({
		occurredAt: '2024-06-01T12:00:00.000Z',
		tokenId: 'token-id-123',
		callerIp: '1.2.3.4',
		hostname: 'test.example.com',
		recordType: 'A',
		previousIp: '1.2.3.0',
		newIp: '1.2.3.4',
		outcome: 'updated',
		...overrides,
	});

	// -------------------------------------------------------------------------
	// Empty-array fast path
	// -------------------------------------------------------------------------

	describe('empty-array fast path', () => {
		it('makes no D1 calls when the events array is empty', async () => {
			await writeAuditEvents(env, []);

			const auditDbMock = vi.mocked(env.AUDIT_DB) as any;
			expect(auditDbMock.prepare).not.toHaveBeenCalled();
			expect(auditDbMock.batch).not.toHaveBeenCalled();
		});

		it('resolves without error when given an empty array', async () => {
			await expect(writeAuditEvents(env, [])).resolves.toBeUndefined();
		});
	});

	// -------------------------------------------------------------------------
	// Single event
	// -------------------------------------------------------------------------

	describe('single event', () => {
		it('calls prepare once then batch with one bound statement', async () => {
			const event = makeEvent();

			await writeAuditEvents(env, [event]);

			const auditDbMock = vi.mocked(env.AUDIT_DB) as any;
			expect(auditDbMock.prepare).toHaveBeenCalledTimes(1);
			expect(auditDbMock.batch).toHaveBeenCalledTimes(1);

			const [batchArg] = auditDbMock.batch.mock.calls[0] as [unknown[]];
			expect(batchArg).toHaveLength(1);
		});

		it('binds all eight fields in the correct column order', async () => {
			const event = makeEvent({
				occurredAt: '2024-06-01T12:00:00.000Z',
				tokenId: 'token-id-123',
				callerIp: '5.6.7.8',
				hostname: 'host.example.com',
				recordType: 'AAAA',
				previousIp: '::1',
				newIp: '2001:db8::1',
				outcome: 'updated',
			});

			await writeAuditEvents(env, [event]);

			const auditDbMock = vi.mocked(env.AUDIT_DB) as any;
			const stmtMock = auditDbMock.prepare();
			expect(stmtMock.bind).toHaveBeenCalledWith(
				'2024-06-01T12:00:00.000Z',
				'token-id-123',
				'5.6.7.8',
				'host.example.com',
				'AAAA',
				'::1',
				'2001:db8::1',
				'updated',
			);
		});

		it('passes null callerIp and previousIp when they are absent', async () => {
			const event = makeEvent({ callerIp: null, previousIp: null });

			await writeAuditEvents(env, [event]);

			const auditDbMock = vi.mocked(env.AUDIT_DB) as any;
			const stmtMock = auditDbMock.prepare();
			const bindArgs = stmtMock.bind.mock.calls.at(-1) as unknown[];
			expect(bindArgs[2]).toBeNull(); // callerIp
			expect(bindArgs[5]).toBeNull(); // previousIp
		});

		it('uses outcome no-change when the DNS content was already current', async () => {
			const event = makeEvent({ outcome: 'no-change' });

			await writeAuditEvents(env, [event]);

			const auditDbMock = vi.mocked(env.AUDIT_DB) as any;
			const stmtMock = auditDbMock.prepare();
			const bindArgs = stmtMock.bind.mock.calls.at(-1) as unknown[];
			expect(bindArgs[7]).toBe('no-change');
		});
	});

	// -------------------------------------------------------------------------
	// Multiple events
	// -------------------------------------------------------------------------

	describe('multiple events', () => {
		it('calls batch with one bound statement per event', async () => {
			const events = [makeEvent({ hostname: 'h1.example.com' }), makeEvent({ hostname: 'h2.example.com' })];

			await writeAuditEvents(env, events);

			const auditDbMock = vi.mocked(env.AUDIT_DB) as any;
			const [batchArg] = auditDbMock.batch.mock.calls[0] as [unknown[]];
			expect(batchArg).toHaveLength(2);
		});
	});

	// -------------------------------------------------------------------------
	// Error handling
	// -------------------------------------------------------------------------

	describe('error handling', () => {
		it('does not throw when AUDIT_DB.batch rejects', async () => {
			const auditDbMock = vi.mocked(env.AUDIT_DB) as any;
			auditDbMock.batch.mockRejectedValue(new Error('D1 batch failed'));

			await expect(writeAuditEvents(env, [makeEvent()])).resolves.toBeUndefined();
		});

		it('logs the failure to console.error when batch rejects', async () => {
			const auditDbMock = vi.mocked(env.AUDIT_DB) as any;
			auditDbMock.batch.mockRejectedValue(new Error('D1 batch failed'));

			await writeAuditEvents(env, [makeEvent()]);

			expect(consoleErrorSpy).toHaveBeenCalled();
		});
	});
});

describe('queryHistory', () => {
	let env: Env;

	beforeEach(() => {
		env = createMockEnv();
		vi.spyOn(console, 'error').mockImplementation(() => {});
	});

	afterEach(() => {
		vi.restoreAllMocks();
	});

	// -------------------------------------------------------------------------
	// Base query (no hostname filter)
	// -------------------------------------------------------------------------

	describe('base query without hostname filter', () => {
		it('returns the rows from AUDIT_DB without the cursor field', async () => {
			const auditDbMock = vi.mocked(env.AUDIT_DB) as any;
			const stmtMock = auditDbMock.prepare();
			stmtMock.all.mockResolvedValue({ results: [{ id: 7, hostname: 'test.example.com', outcome: 'updated' }] });

			const page = await queryHistory(env, { tokenId: 'tid', hostname: null, limit: 100, before: null });

			// `id` exists to order and resume the walk. It is not something the
			// caller asked for, and it counts rows every tenant wrote.
			expect(page.events).toEqual([{ hostname: 'test.example.com', outcome: 'updated' }]);
		});

		it('binds token_id and one row past the limit when no hostname filter is set', async () => {
			const auditDbMock = vi.mocked(env.AUDIT_DB) as any;
			const stmtMock = auditDbMock.prepare();
			stmtMock.all.mockResolvedValue({ results: [] });

			await queryHistory(env, { tokenId: 'token-id-123', hostname: null, limit: 50, before: null });

			// One past, so a full page is told from a last page without a second
			// query and without ever answering with an empty final page.
			expect(stmtMock.bind).toHaveBeenCalledWith('token-id-123', 51);
		});
	});

	// -------------------------------------------------------------------------
	// Hostname filter
	// -------------------------------------------------------------------------

	describe('hostname filter', () => {
		it('binds token_id, hostname, and the limit when hostname is provided', async () => {
			const auditDbMock = vi.mocked(env.AUDIT_DB) as any;
			const stmtMock = auditDbMock.prepare();
			stmtMock.all.mockResolvedValue({ results: [] });

			await queryHistory(env, { tokenId: 'token-id-123', hostname: 'test.example.com', limit: 100, before: null });

			expect(stmtMock.bind).toHaveBeenCalledWith('token-id-123', 'test.example.com', 101);
		});

		it('uses the unfiltered query when hostname is an empty string', async () => {
			const auditDbMock = vi.mocked(env.AUDIT_DB) as any;
			const stmtMock = auditDbMock.prepare();
			stmtMock.all.mockResolvedValue({ results: [] });

			await queryHistory(env, { tokenId: 'tid', hostname: '', limit: 100, before: null });

			// Empty string is treated as no filter: only two args bound
			expect(stmtMock.bind).toHaveBeenCalledWith('tid', 101);
		});
	});

	// -------------------------------------------------------------------------
	// Pagination
	// -------------------------------------------------------------------------

	describe('pagination', () => {
		const rows = (count: number, at?: string): Record<string, unknown>[] =>
			Array.from({ length: count }, (_unused, i) => ({
				id: i + 1,
				occurred_at: at ?? `2026-08-06T00:00:00.00${String(i)}Z`,
				hostname: 'a.example.com',
			}));

		it('reports no cursor when the page is the last', async () => {
			const auditDbMock = vi.mocked(env.AUDIT_DB) as any;
			const stmtMock = auditDbMock.prepare();
			stmtMock.all.mockResolvedValue({ results: rows(2) });

			const page = await queryHistory(env, { tokenId: 'tid', hostname: null, limit: 2, before: null });

			expect(page.cursor).toBeNull();
			expect(page.events).toHaveLength(2);
		});

		it('reports no cursor when there are no rows at all', async () => {
			const auditDbMock = vi.mocked(env.AUDIT_DB) as any;
			const stmtMock = auditDbMock.prepare();
			stmtMock.all.mockResolvedValue({ results: [] });

			const page = await queryHistory(env, { tokenId: 'tid', hostname: null, limit: 2, before: null });

			expect(page.cursor).toBeNull();
			expect(page.events).toEqual([]);
		});

		it('trims the extra row and reports the last row it returned', async () => {
			const auditDbMock = vi.mocked(env.AUDIT_DB) as any;
			const stmtMock = auditDbMock.prepare();
			stmtMock.all.mockResolvedValue({ results: rows(3) });

			const page = await queryHistory(env, { tokenId: 'tid', hostname: null, limit: 2, before: null });

			// The row past the limit is what proves more exist; it is not returned,
			// and the cursor names the last row that was.
			expect(page.events).toHaveLength(2);
			expect(page.cursor).toBe('2026-08-06T00:00:00.001Z|2');
		});

		it('resumes inside a group rather than excluding the whole group', async () => {
			// A batch writes several rows in one millisecond, so a page boundary
			// can land inside a group. Excluding the timestamp would drop the rest
			// of that group; including it without the id would repeat it.
			const auditDbMock = vi.mocked(env.AUDIT_DB) as any;
			const stmtMock = auditDbMock.prepare();
			stmtMock.all.mockResolvedValue({ results: [] });

			await queryHistory(env, {
				tokenId: 'tid',
				hostname: null,
				limit: 10,
				before: { occurredAt: '2026-08-06T00:00:01.000Z', id: 2 },
			});

			expect(stmtMock.bind).toHaveBeenCalledWith('tid', '2026-08-06T00:00:01.000Z', '2026-08-06T00:00:01.000Z', 2, 11);
		});

		it('orders a shared timestamp ascending so a late write is not sorted behind the cursor', async () => {
			// An audit row is written after the response through waitUntil, so it
			// can land well after the timestamp it carries. Taking the highest id
			// last means a row arriving into a group the walk is still crossing is
			// picked up rather than skipped.
			const auditDbMock = vi.mocked(env.AUDIT_DB) as any;
			auditDbMock.prepare().all.mockResolvedValue({ results: [] });

			await queryHistory(env, { tokenId: 'tid', hostname: null, limit: 10, before: null });

			expect(auditDbMock.prepare.mock.calls.at(-1)?.[0]).toContain('ORDER BY occurred_at DESC, id ASC');
		});

		it('withholds a cursor it could not read back', async () => {
			// A row whose timestamp this module did not write, from a backfill or
			// an operator insert, would otherwise produce a cursor the next
			// request refuses, and the walk would die on a 422 blaming the caller
			// for a value the server handed it.
			const auditDbMock = vi.mocked(env.AUDIT_DB) as any;
			auditDbMock.prepare().all.mockResolvedValue({
				results: [
					{ id: 1, occurred_at: '2026-08-06 00:00:00', hostname: 'a.example.com' },
					{ id: 2, occurred_at: '2026-08-06 00:00:00', hostname: 'b.example.com' },
				],
			});

			const page = await queryHistory(env, { tokenId: 'tid', hostname: null, limit: 1, before: null });

			expect(page.events).toHaveLength(1);
			expect(page.cursor).toBeNull();
		});

		it('applies the cursor inside the tenant scope', async () => {
			// A cursor is caller-supplied, so it must never be able to reach past
			// the token filter into another tenant's rows.
			const auditDbMock = vi.mocked(env.AUDIT_DB) as any;
			auditDbMock.prepare().all.mockResolvedValue({ results: [] });

			await queryHistory(env, { tokenId: 'tid', hostname: null, limit: 10, before: { occurredAt: 'x', id: 1 } });

			expect(auditDbMock.prepare.mock.calls.at(-1)?.[0]).toContain('token_id = ? AND occurred_at <= ? AND (occurred_at < ? OR id > ?)');
		});
	});

	// -------------------------------------------------------------------------
	// Cursor parsing
	// -------------------------------------------------------------------------

	describe('parseHistoryCursor', () => {
		it('reads back a cursor this module emitted', () => {
			expect(parseHistoryCursor('2026-08-06T00:00:01.000Z|42')).toEqual({ occurredAt: '2026-08-06T00:00:01.000Z', id: 42 });
		});

		it.each([
			['no separator', '2026-08-06T00:00:01.000Z'],
			['an empty timestamp', '|42'],
			['a timestamp the writer cannot produce', 'not-a-timestamp|1'],
			// Shaped like a date and not one. It sorts above every real row, so
			// admitting it would hand back the first page and read as a restart.
			['a month and day out of range', '2026-99-99T99:99:99.999Z|1'],
			['a day that does not exist that month', '2026-02-30T00:00:00.000Z|1'],
			['a timestamp without milliseconds', '2026-08-06T00:00:01Z|1'],
			['a quoted timestamp', "x' OR 1=1--|1"],
			['a non-numeric id', '2026-08-06T00:00:01.000Z|abc'],
			['a fractional id', '2026-08-06T00:00:01.000Z|1.5'],
			['a negative id', '2026-08-06T00:00:01.000Z|-1'],
			// Number() takes all three; the pattern is what refuses them, so a
			// value that never came from here cannot read as one that did.
			['a hexadecimal id', '2026-08-06T00:00:01.000Z|0x10'],
			['an exponent id', '2026-08-06T00:00:01.000Z|1e3'],
			['a padded id', '2026-08-06T00:00:01.000Z| 7 '],
			['an id past the exact integer range', '2026-08-06T00:00:01.000Z|9007199254740993'],
		])('rejects a cursor with %s', (_label, raw) => {
			expect(parseHistoryCursor(raw)).toBeNull();
		});

		it('rejects a value long enough to be a payload rather than a cursor', () => {
			expect(parseHistoryCursor(`${'A'.repeat(20000)}|1`)).toBeNull();
		});
	});

	// -------------------------------------------------------------------------
	// Limit clamping
	// -------------------------------------------------------------------------

	describe('limit clamping', () => {
		it.each([
			['clamps to the maximum when the caller supplies a value above it', 5000, 1001],
			['clamps to one when the caller supplies zero', 0, 2],
			['clamps to one when the caller supplies a negative value', -10, 2],
			['passes through a value within the valid range unchanged', 42, 43],
			// The module holds its own boundary rather than trusting its one
			// caller: Math.trunc(NaN) is NaN, every comparison against it is
			// false, and the clamp would hand NaN to the bind for SQLite to
			// reject as a type mismatch.
			['falls back to the default when the value is not a number', Number.NaN, 101],
		])('%s', async (_label, limit, bound) => {
			const auditDbMock = vi.mocked(env.AUDIT_DB) as any;
			const stmtMock = auditDbMock.prepare();
			stmtMock.all.mockResolvedValue({ results: [] });

			await queryHistory(env, { tokenId: 'tid', hostname: null, limit, before: null });

			expect(stmtMock.bind).toHaveBeenCalledWith('tid', bound);
		});
	});
});
