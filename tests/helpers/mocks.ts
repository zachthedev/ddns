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

export const createMockEnv = (): Env => {
	const env: Env = {
		DDNS_KV: createMockKVNamespace(),
		NTFY_URL: 'https://ntfy.example.com/test-topic',
	};
	return env;
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
 * current content: '192.168.1.1'.
 */
export const wireStandardHappyPath = (mockClient: ReturnType<typeof createMockCloudflareClient>): void => {
	mockClient.user.tokens.verify.mockResolvedValue({ status: 'active' });
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
