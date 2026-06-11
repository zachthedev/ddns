import { vi } from 'vitest';

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

export const createMockKVNamespace = (): KVNamespace => {
	const storage = new Map<string, string>();

	return {
		get: vi.fn((key: string) => Promise.resolve(storage.get(key) ?? null)),
		put: vi.fn((key: string, value: string, _options?: { expirationTtl?: number }) => {
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

export const createMockEnv = (): Env => {
	const env: Env = {
		DDNS_KV: createMockKVNamespace(),
		AUDIT_DB: createMockAuditDb(),
		NTFY_URL: 'https://ntfy.example.com/test-topic',
		ACCESS_KEY: '',
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
	}> = {},
): Request => {
	const headers = new Headers(options.headers ?? {});

	// Add default CF-Connecting-IP if not provided
	if (!headers.has('CF-Connecting-IP')) {
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
	mockClient.zones.list.mockResolvedValue({
		result: [{ id: 'zone123', name: 'example.com' }],
	});
	mockClient.dns.records.list.mockResolvedValue({
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
	});
	mockClient.dns.records.update.mockResolvedValue(undefined);
};
