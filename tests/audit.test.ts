import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { writeAuditEvents, queryHistory, type AuditEvent } from '../src/audit';
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
		it('returns the rows from AUDIT_DB', async () => {
			const auditDbMock = vi.mocked(env.AUDIT_DB) as any;
			const stmtMock = auditDbMock.prepare();
			const fakeRows = [{ hostname: 'test.example.com', outcome: 'updated' }];
			stmtMock.all.mockResolvedValue({ results: fakeRows });

			const results = await queryHistory(env, { tokenId: 'tid', hostname: null, limit: 100 });

			expect(results).toEqual(fakeRows);
		});

		it('binds token_id and limit when no hostname filter is set', async () => {
			const auditDbMock = vi.mocked(env.AUDIT_DB) as any;
			const stmtMock = auditDbMock.prepare();
			stmtMock.all.mockResolvedValue({ results: [] });

			await queryHistory(env, { tokenId: 'token-id-123', hostname: null, limit: 50 });

			expect(stmtMock.bind).toHaveBeenCalledWith('token-id-123', 50);
		});
	});

	// -------------------------------------------------------------------------
	// Hostname filter
	// -------------------------------------------------------------------------

	describe('hostname filter', () => {
		it('binds token_id, hostname, and limit when hostname is provided', async () => {
			const auditDbMock = vi.mocked(env.AUDIT_DB) as any;
			const stmtMock = auditDbMock.prepare();
			stmtMock.all.mockResolvedValue({ results: [] });

			await queryHistory(env, { tokenId: 'token-id-123', hostname: 'test.example.com', limit: 100 });

			expect(stmtMock.bind).toHaveBeenCalledWith('token-id-123', 'test.example.com', 100);
		});

		it('uses the unfiltered query when hostname is an empty string', async () => {
			const auditDbMock = vi.mocked(env.AUDIT_DB) as any;
			const stmtMock = auditDbMock.prepare();
			stmtMock.all.mockResolvedValue({ results: [] });

			await queryHistory(env, { tokenId: 'tid', hostname: '', limit: 100 });

			// Empty string is treated as no filter: only two args bound
			expect(stmtMock.bind).toHaveBeenCalledWith('tid', 100);
		});
	});

	// -------------------------------------------------------------------------
	// Limit clamping
	// -------------------------------------------------------------------------

	describe('limit clamping', () => {
		it('clamps limit to 1000 when the caller supplies a value above the maximum', async () => {
			const auditDbMock = vi.mocked(env.AUDIT_DB) as any;
			const stmtMock = auditDbMock.prepare();
			stmtMock.all.mockResolvedValue({ results: [] });

			await queryHistory(env, { tokenId: 'tid', hostname: null, limit: 5000 });

			expect(stmtMock.bind).toHaveBeenCalledWith('tid', 1000);
		});

		it('clamps limit to 1 when the caller supplies zero', async () => {
			const auditDbMock = vi.mocked(env.AUDIT_DB) as any;
			const stmtMock = auditDbMock.prepare();
			stmtMock.all.mockResolvedValue({ results: [] });

			await queryHistory(env, { tokenId: 'tid', hostname: null, limit: 0 });

			expect(stmtMock.bind).toHaveBeenCalledWith('tid', 1);
		});

		it('clamps limit to 1 when the caller supplies a negative value', async () => {
			const auditDbMock = vi.mocked(env.AUDIT_DB) as any;
			const stmtMock = auditDbMock.prepare();
			stmtMock.all.mockResolvedValue({ results: [] });

			await queryHistory(env, { tokenId: 'tid', hostname: null, limit: -10 });

			expect(stmtMock.bind).toHaveBeenCalledWith('tid', 1);
		});

		it('passes through a value within the valid range unchanged', async () => {
			const auditDbMock = vi.mocked(env.AUDIT_DB) as any;
			const stmtMock = auditDbMock.prepare();
			stmtMock.all.mockResolvedValue({ results: [] });

			await queryHistory(env, { tokenId: 'tid', hostname: null, limit: 42 });

			expect(stmtMock.bind).toHaveBeenCalledWith('tid', 42);
		});
	});
});
