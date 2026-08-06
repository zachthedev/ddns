import { vi } from 'vitest';
import { ALERT_DISTINCT } from '../../src/refusals';

export const createMockCloudflareClient = () => {
	const mockClient = {
		user: {
			tokens: {
				verify: vi.fn(),
			},
		},
		zones: {
			list: vi.fn(),
		},
		dns: {
			records: {
				list: vi.fn(),
				update: vi.fn(),
			},
		},
	};

	return mockClient;
};

/**
 * Stands in for the SDK's `PagePromise`, which is both awaitable and async
 * iterable. The worker consumes list endpoints with `for await`, so a mock
 * that only resolves to the page would never yield an item.
 *
 * Pass the pages a real multi-page response would deliver in order.
 */
export const mockPage = <T>(...pages: { result: T[] }[]): Promise<{ result: T[] }> & AsyncIterable<T> => {
	const first = pages[0] ?? { result: [] };
	return Object.assign(Promise.resolve(first), {
		async *[Symbol.asyncIterator](): AsyncGenerator<T> {
			for (const page of pages) {
				// The SDK fetches each page over the network, so the worker sees a
				// suspension point at every page boundary. Keep that shape here.
				yield* await Promise.resolve(page.result);
			}
		},
	});
};

/** KV refuses an expirationTtl under this, and the worker must respect it. */
const KV_MIN_EXPIRATION_TTL = 60;

export const createMockKVNamespace = (): KVNamespace => {
	const storage = new Map<string, string>();

	return {
		get: vi.fn((key: string) => Promise.resolve(storage.get(key) ?? null)),
		put: vi.fn((key: string, value: string, options?: { expirationTtl?: number }) => {
			// The real namespace rejects a short TTL, and the worker swallows the
			// rejection, so a mock that accepts one turns a cache that never
			// exists into a passing test.
			const ttl = options?.expirationTtl;
			if (ttl !== undefined && ttl < KV_MIN_EXPIRATION_TTL) {
				return Promise.reject(
					new Error(
						`KV PUT failed: 400 Invalid expiration_ttl of ${String(ttl)}. Expiration TTL must be at least ${String(KV_MIN_EXPIRATION_TTL)}.`,
					),
				);
			}
			storage.set(key, value);
			return Promise.resolve(undefined);
		}),
		delete: vi.fn((key: string) => {
			storage.delete(key);
			return Promise.resolve(undefined);
		}),
		list: vi.fn(() => Promise.resolve({ keys: [], list_complete: true, cursor: '' })),
		getWithMetadata: vi.fn(),
	} as unknown as KVNamespace;
};

/**
 * Returns a D1PreparedStatement mock whose bind() returns itself so callers
 * can chain .bind(...).all() or pass it to batch(). The all() default returns
 * an empty results set; override per-test via mockResolvedValue.
 */
export const createMockD1Statement = () => {
	const stmt = {
		bind: vi.fn(),
		all: vi.fn().mockResolvedValue({ results: [] }),
		run: vi.fn().mockResolvedValue({ success: true }),
		first: vi.fn().mockResolvedValue(null),
		raw: vi.fn().mockResolvedValue([]),
	};
	// bind() returns the same statement so chaining works
	stmt.bind.mockReturnValue(stmt);
	return stmt;
};

export const createMockAuditDb = () => {
	const stmt = createMockD1Statement();
	return {
		prepare: vi.fn().mockReturnValue(stmt),
		batch: vi.fn().mockResolvedValue([]),
		exec: vi.fn().mockResolvedValue({ count: 0, duration: 0 }),
		dump: vi.fn().mockResolvedValue(new ArrayBuffer(0)),
	} as unknown as D1Database;
};

/**
 * Stands in for the refusal-counter namespace, backed by a Map so a tally
 * accumulates across calls the way a real Durable Object instance would.
 * `getByName` returns the same stub per token, so tests can assert on it.
 *
 * The real object is exercised in tests/refusals.test.ts; this only has to
 * behave the way the worker reads it.
 */
export const createMockRefusals = () => {
	const tallies = new Map<string, { day: string; n: number; names: string[]; warned: boolean }>();
	const stubs = new Map<string, { add: ReturnType<typeof vi.fn>; tally: ReturnType<typeof vi.fn> }>();
	const getByName = vi.fn((tokenId: string) => {
		const existing = stubs.get(tokenId);
		if (existing !== undefined) {
			return existing;
		}
		const stub = {
			add: vi.fn((day: string, hostnames: string[]) => {
				const state = tallies.get(tokenId);
				const current = state?.day === day ? state : { day, n: 0, names: [], warned: false };
				const names = [...new Set([...current.names, ...hostnames])];
				// The object decides when a tally is worth reporting, and reports
				// it once; the worker only reads the flag. The threshold is
				// imported rather than copied, so a change to it cannot leave the
				// worker-level test asserting against a stale number.
				const alert = names.length >= ALERT_DISTINCT && !current.warned;
				tallies.set(tokenId, { day, n: current.n + hostnames.length, names, warned: alert || current.warned });
				return Promise.resolve({ total: current.n + hostnames.length, distinct: names.length, hostnames: names, alert });
			}),
			tally: vi.fn((day: string) => {
				const state = tallies.get(tokenId);
				if (state?.day !== day) {
					return Promise.resolve({ total: 0, distinct: 0, hostnames: [] });
				}
				return Promise.resolve({ total: state.n, distinct: state.names.length, hostnames: state.names });
			}),
		};
		stubs.set(tokenId, stub);
		return stub;
	});
	return { namespace: { getByName } as unknown as Env['REFUSALS'], getByName, stubs };
};

export const createMockEnv = (): Env => {
	const env: Env = {
		DDNS_KV: createMockKVNamespace(),
		AUDIT_DB: createMockAuditDb(),
		ACCESS_KEY: '',
		RATE_LIMITER: { limit: vi.fn().mockResolvedValue({ success: true }) },
		REFUSALS: createMockRefusals().namespace,
	};
	return env;
};

export interface MockCtx {
	/** Passed to worker.fetch as the ExecutionContext. */
	ctx: ExecutionContext;
	/** Standalone mock handles for assertions (method references off the
	 * ExecutionContext type would trip unbound-method). */
	waitUntil: ReturnType<typeof vi.fn>;
	passThroughOnException: ReturnType<typeof vi.fn>;
}

export const createMockCtx = (): MockCtx => {
	const waitUntil = vi.fn();
	const passThroughOnException = vi.fn();
	const ctx: ExecutionContext = {
		waitUntil,
		passThroughOnException,
		exports: {} as ExecutionContext['exports'],
		tracing: {} as ExecutionContext['tracing'],
		props: {},
	};
	return { ctx, waitUntil, passThroughOnException };
};

export const createMockRequest = (
	url: string,
	options: Partial<{
		method: string;
		headers: Record<string, string>;
		body: string;
		connectingIp: string | null;
	}> = {},
): Request => {
	const headers = new Headers(options.headers ?? {});

	// Cloudflare always sets this at the edge, so it is the default here too.
	// Pass `connectingIp: null` for the case where it is genuinely absent.
	if (options.connectingIp === null) {
		headers.delete('CF-Connecting-IP');
	} else if (options.connectingIp !== undefined) {
		headers.set('CF-Connecting-IP', options.connectingIp);
	} else if (!headers.has('CF-Connecting-IP')) {
		headers.set('CF-Connecting-IP', '192.168.1.1');
	}

	return new Request(url, {
		method: options.method ?? 'GET',
		headers,
		body: options.body,
	});
};

/** Emits a Basic auth header: `Basic base64(user:token)`. */
export const createAuthHeader = (user: string, token: string): string => {
	return `Basic ${btoa(`${user}:${token}`)}`;
};

/** Emits a Bearer auth header: `Bearer <rawToken>`. */
export const createBearerHeader = (rawToken: string): string => {
	return `Bearer ${rawToken}`;
};

/**
 * Wires the standard single-zone / single-record happy-path mocks used by
 * tests that exercise the post-auth update pipeline without customising the
 * Cloudflare API responses.
 *
 * Zone id: 'zone123', record id: 'record123', hostname: 'test.example.com',
 * current content: '192.168.1.1', token id: 'token-id-123'.
 */
export const wireStandardHappyPath = (mockClient: ReturnType<typeof createMockCloudflareClient>): void => {
	mockClient.user.tokens.verify.mockResolvedValue({ id: 'token-id-123', status: 'active' });
	mockClient.zones.list.mockReturnValue(
		mockPage({
			result: [{ id: 'zone123', name: 'example.com' }],
		}),
	);
	mockClient.dns.records.list.mockReturnValue(
		mockPage({
			result: [
				{
					id: 'record123',
					name: 'test.example.com',
					type: 'A',
					content: '192.168.1.1',
					proxied: false,
					ttl: 1,
				},
			],
		}),
	);
	mockClient.dns.records.update.mockResolvedValue(undefined);
};
