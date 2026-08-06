import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import worker, { HttpError } from '../src/index';
import {
	createMockCloudflareClient,
	createMockEnv,
	createMockRequest,
	createMockCtx,
	createAuthHeader,
	createBearerHeader,
	mockPage,
	wireStandardHappyPath,
} from './helpers/mocks';
import { Cloudflare } from 'cloudflare';

// vi.mock factories are hoisted above import declarations, so any class or
// variable the factory references must be created inside vi.hoisted() so it
// is also hoisted and available when the factory runs.
const {
	MockAPIError,
	MockBadRequestError,
	MockAuthenticationError,
	MockPermissionDeniedError,
	MockInternalServerError,
	MockRateLimitError,
	MockNotFoundError,
	MockConflictError,
} = vi.hoisted(() => {
	class MockAPIError extends Error {
		status: number;
		constructor(status: number, message = 'API error') {
			super(message);
			this.name = 'APIError';
			this.status = status;
		}
	}
	class MockBadRequestError extends MockAPIError {
		constructor(message = 'bad request') {
			super(400, message);
			this.name = 'BadRequestError';
		}
	}
	class MockAuthenticationError extends MockAPIError {
		constructor(message = 'unauthorized') {
			super(401, message);
			this.name = 'AuthenticationError';
		}
	}
	class MockPermissionDeniedError extends MockAPIError {
		constructor(message = 'forbidden') {
			super(403, message);
			this.name = 'PermissionDeniedError';
		}
	}
	class MockInternalServerError extends MockAPIError {
		constructor(message = 'server error') {
			super(500, message);
			this.name = 'InternalServerError';
		}
	}
	class MockRateLimitError extends MockAPIError {
		constructor(message = 'rate limited') {
			super(429, message);
			this.name = 'RateLimitError';
		}
	}
	class MockNotFoundError extends MockAPIError {
		constructor(message = 'not found') {
			super(404, message);
			this.name = 'NotFoundError';
		}
	}
	class MockConflictError extends MockAPIError {
		constructor(message = 'conflict') {
			super(409, message);
			this.name = 'ConflictError';
		}
	}
	return {
		MockAPIError,
		MockBadRequestError,
		MockAuthenticationError,
		MockPermissionDeniedError,
		MockInternalServerError,
		MockRateLimitError,
		MockNotFoundError,
		MockConflictError,
	};
});

// src/index.ts narrows auth failures with `instanceof` against the SDK's error
// classes, so the mocked module must export real classes for those names.
vi.mock('cloudflare', () => ({
	Cloudflare: vi.fn(),
	APIError: MockAPIError,
	BadRequestError: MockBadRequestError,
	AuthenticationError: MockAuthenticationError,
	PermissionDeniedError: MockPermissionDeniedError,
	InternalServerError: MockInternalServerError,
	RateLimitError: MockRateLimitError,
	NotFoundError: MockNotFoundError,
}));

// Mock pushNtfy to prevent actual notifications
vi.mock('../src/pushNtfy', () => ({
	pushNtfy: vi.fn().mockResolvedValue(undefined),
}));

describe('HttpError', () => {
	it('creates error with status code and message', () => {
		const error = new HttpError(404, 'Not found');

		expect(error).toBeInstanceOf(Error);
		expect(error).toBeInstanceOf(HttpError);
		expect(error.statusCode).toBe(404);
		expect(error.message).toBe('Not found');
		expect(error.name).toBe('HttpError');
	});

	it('maintains proper prototype chain', () => {
		const error = new HttpError(500, 'Server error');

		expect(error.constructor).toBe(HttpError);
		expect(Object.getPrototypeOf(error)).toBe(HttpError.prototype);
	});
});

describe('Worker fetch handler', () => {
	let env: Env;
	let ctx: ExecutionContext;
	let waitUntilMock: ReturnType<typeof vi.fn>;
	let mockCloudflareClient: ReturnType<typeof createMockCloudflareClient>;

	beforeEach(() => {
		env = createMockEnv();
		({ ctx, waitUntil: waitUntilMock } = createMockCtx());
		mockCloudflareClient = createMockCloudflareClient();

		vi.spyOn(console, 'log').mockImplementation(() => {});
		vi.spyOn(console, 'error').mockImplementation(() => {});
		vi.spyOn(console, 'warn').mockImplementation(() => {});

		// vitest 4: constructor mocks must be `function`/class form, not arrows
		vi.mocked(Cloudflare).mockImplementation(function () {
			return mockCloudflareClient as any;
		});
	});

	afterEach(() => {
		vi.restoreAllMocks();
		vi.clearAllMocks();
	});

	// -------------------------------------------------------------------------
	// Rate limiter  (RATE_LIMITER binding, first thing in the try block)
	// -------------------------------------------------------------------------

	describe('Rate limiter', () => {
		const validAuth = { Authorization: createAuthHeader('user@example.com', 'token') };

		it('allows the request when RATE_LIMITER returns success:true', async () => {
			const rateLimiterMock = vi.mocked(env.RATE_LIMITER) as any;
			rateLimiterMock.limit.mockResolvedValue({ success: true });

			mockCloudflareClient.user.tokens.verify.mockResolvedValue({ id: 'tid', status: 'active' } as any);
			mockCloudflareClient.zones.list.mockReturnValue(mockPage({ result: [] }));

			const request = createMockRequest('https://example.com/update?ip4=1.2.3.4&hostnames=test.example.com', {
				headers: validAuth,
			});

			const response = await worker.fetch(request, env, ctx);

			// Auth and param parsing ran; rejected by missing zone, not rate limit.
			expect(response.status).toBe(400);
		});

		it('returns 429 with rate-limit error body when RATE_LIMITER returns success:false', async () => {
			const rateLimiterMock = vi.mocked(env.RATE_LIMITER) as any;
			rateLimiterMock.limit.mockResolvedValue({ success: false });

			const request = createMockRequest('https://example.com/update?ip4=1.2.3.4&hostnames=test.example.com', {
				headers: validAuth,
			});

			const response = await worker.fetch(request, env, ctx);

			expect(response.status).toBe(429);
			const body = (await response.json()) as any;
			expect(body).toEqual({ success: false, error: 'Rate limit exceeded.' });
		});

		it('does not call parseAuthorization or tokens.verify when rate limited', async () => {
			const rateLimiterMock = vi.mocked(env.RATE_LIMITER) as any;
			rateLimiterMock.limit.mockResolvedValue({ success: false });

			// No Authorization header — if auth ran first it would return 401, not 429
			const request = createMockRequest('https://example.com/update?ip4=1.2.3.4&hostnames=test.example.com');

			const response = await worker.fetch(request, env, ctx);

			expect(response.status).toBe(429);
			expect(mockCloudflareClient.user.tokens.verify).not.toHaveBeenCalled();
		});

		it('uses the CF-Connecting-IP header as the rate limit key', async () => {
			const rateLimiterMock = vi.mocked(env.RATE_LIMITER) as any;
			rateLimiterMock.limit.mockResolvedValue({ success: true });

			mockCloudflareClient.user.tokens.verify.mockResolvedValue({ id: 'tid', status: 'active' } as any);
			mockCloudflareClient.zones.list.mockReturnValue(mockPage({ result: [] }));

			const request = createMockRequest('https://example.com/update?ip4=1.2.3.4&hostnames=test.example.com', {
				headers: { ...validAuth, 'CF-Connecting-IP': '10.20.30.40' },
			});

			await worker.fetch(request, env, ctx);

			expect(rateLimiterMock.limit).toHaveBeenCalledWith({ key: '10.20.30.40' });
		});

		it('uses "unknown" as the rate limit key when CF-Connecting-IP is absent', async () => {
			const rateLimiterMock = vi.mocked(env.RATE_LIMITER) as any;
			rateLimiterMock.limit.mockResolvedValue({ success: false });

			// createMockRequest adds a default CF-Connecting-IP; build the request
			// manually to omit it entirely.
			const request = new Request('https://example.com/update?ip4=1.2.3.4&hostnames=test.example.com', {
				method: 'GET',
				headers: { Authorization: createAuthHeader('user', 'token') },
			});

			await worker.fetch(request, env, ctx);

			expect(rateLimiterMock.limit).toHaveBeenCalledWith({ key: 'unknown' });
		});
	});

	// -------------------------------------------------------------------------
	// Auth parsing  (parseAuthorization)
	// -------------------------------------------------------------------------

	describe('Auth parsing', () => {
		it('accepts Basic credentials and constructs SDK with apiToken only (no apiEmail)', async () => {
			mockCloudflareClient.user.tokens.verify.mockResolvedValue({ id: 'tid', status: 'active' } as any);
			mockCloudflareClient.zones.list.mockReturnValue(mockPage({ result: [] }));

			const request = createMockRequest('https://example.com/update?ip4=1.2.3.4&hostnames=test.example.com', {
				headers: { Authorization: createAuthHeader('user@example.com', 'valid-token') },
			});

			const response = await worker.fetch(request, env, ctx);

			// Fails with 'No zones available' but confirms auth passed and Cloudflare
			// was initialised with apiToken only (username portion is discarded).
			expect(response.status).toBe(400);
			expect(vi.mocked(Cloudflare)).toHaveBeenCalledWith(expect.objectContaining({ apiToken: 'valid-token' }));
			// apiEmail must never be passed
			expect(vi.mocked(Cloudflare)).not.toHaveBeenCalledWith(expect.objectContaining({ apiEmail: expect.anything() }));
		});

		it('accepts Basic credentials with a non-email username (username is ignored for auth)', async () => {
			mockCloudflareClient.user.tokens.verify.mockResolvedValue({ id: 'tid', status: 'active' } as any);
			mockCloudflareClient.zones.list.mockReturnValue(mockPage({ result: [] }));

			const request = createMockRequest('https://example.com/update?ip4=1.2.3.4&hostnames=test.example.com', {
				headers: { Authorization: createAuthHeader('somedevice', 'mytoken') },
			});

			const response = await worker.fetch(request, env, ctx);

			expect(response.status).toBe(400);
			expect(vi.mocked(Cloudflare)).toHaveBeenCalledWith(expect.objectContaining({ apiToken: 'mytoken' }));
		});

		it('accepts Bearer raw-token and constructs SDK with that token directly', async () => {
			mockCloudflareClient.user.tokens.verify.mockResolvedValue({ id: 'tid', status: 'active' } as any);
			mockCloudflareClient.zones.list.mockReturnValue(mockPage({ result: [] }));

			const request = createMockRequest('https://example.com/update?ip4=1.2.3.4&hostnames=test.example.com', {
				headers: { Authorization: createBearerHeader('raw-api-token') },
			});

			const response = await worker.fetch(request, env, ctx);

			expect(response.status).toBe(400);
			expect(vi.mocked(Cloudflare)).toHaveBeenCalledWith(expect.objectContaining({ apiToken: 'raw-api-token' }));
		});

		it('rejects request without Authorization header', async () => {
			const request = createMockRequest('https://example.com/update?ip4=1.2.3.4&hostnames=test.example.com');

			const response = await worker.fetch(request, env, ctx);

			expect(response.status).toBe(401);
			const body = (await response.json()) as any;
			expect(body).toEqual({
				success: false,
				error: 'Authorization required.',
			});
		});

		it('rejects request with empty Authorization header', async () => {
			const request = createMockRequest('https://example.com/update?ip4=1.2.3.4&hostnames=test.example.com', {
				headers: { Authorization: '' },
			});

			const response = await worker.fetch(request, env, ctx);

			expect(response.status).toBe(401);
			const body = (await response.json()) as any;
			expect(body).toEqual({ success: false, error: 'Authorization required.' });
		});

		it('rejects request with unknown scheme', async () => {
			const request = createMockRequest('https://example.com/update?ip4=1.2.3.4&hostnames=test.example.com', {
				headers: { Authorization: 'Digest abc123' },
			});

			const response = await worker.fetch(request, env, ctx);

			expect(response.status).toBe(401);
			const body = (await response.json()) as any;
			expect(body).toEqual({ success: false, error: 'Invalid authorization credentials.' });
		});

		it('rejects request with scheme only (missing payload)', async () => {
			const request = createMockRequest('https://example.com/update?ip4=1.2.3.4&hostnames=test.example.com', {
				headers: { Authorization: 'Basic' },
			});

			const response = await worker.fetch(request, env, ctx);

			expect(response.status).toBe(401);
			const body = (await response.json()) as any;
			expect(body).toEqual({ success: false, error: 'Invalid authorization credentials.' });
		});

		it('rejects request with empty Bearer token', async () => {
			const request = createMockRequest('https://example.com/update?ip4=1.2.3.4&hostnames=test.example.com', {
				headers: { Authorization: 'Bearer ' },
			});

			const response = await worker.fetch(request, env, ctx);

			expect(response.status).toBe(401);
			const body = (await response.json()) as any;
			expect(body).toEqual({
				success: false,
				error: 'Invalid authorization credentials.',
			});
		});

		it('rejects Basic with invalid base64 payload', async () => {
			const request = createMockRequest('https://example.com/update?ip4=1.2.3.4&hostnames=test.example.com', {
				headers: { Authorization: 'Basic !!invalid!!base64!!' },
			});

			const response = await worker.fetch(request, env, ctx);

			expect(response.status).toBe(401);
			const body = (await response.json()) as any;
			expect(body).toEqual({
				success: false,
				error: 'Invalid authorization credentials.',
			});
		});

		it('rejects Basic where decoded value has no colon delimiter', async () => {
			const request = createMockRequest('https://example.com/update?ip4=1.2.3.4&hostnames=test.example.com', {
				headers: { Authorization: `Basic ${btoa('nodelemiter')}` },
			});

			const response = await worker.fetch(request, env, ctx);

			expect(response.status).toBe(401);
			const body = (await response.json()) as any;
			expect(body).toEqual({
				success: false,
				error: 'Invalid authorization credentials.',
			});
		});

		it('rejects Basic where decoded value contains control characters', async () => {
			const request = createMockRequest('https://example.com/update?ip4=1.2.3.4&hostnames=test.example.com', {
				headers: { Authorization: `Basic ${btoa('user:\x00token')}` },
			});

			const response = await worker.fetch(request, env, ctx);

			expect(response.status).toBe(401);
			const body = (await response.json()) as any;
			expect(body).toEqual({
				success: false,
				error: 'Invalid authorization credentials.',
			});
		});

		it('rejects Basic where token after colon is empty', async () => {
			const request = createMockRequest('https://example.com/update?ip4=1.2.3.4&hostnames=test.example.com', {
				headers: { Authorization: `Basic ${btoa('user:')}` },
			});

			const response = await worker.fetch(request, env, ctx);

			expect(response.status).toBe(401);
			const body = (await response.json()) as any;
			expect(body).toEqual({
				success: false,
				error: 'Invalid authorization credentials.',
			});
		});

		it('applies auth check to GET requests', async () => {
			const request = createMockRequest('https://example.com/update?ip4=1.2.3.4&hostnames=test.example.com', {
				headers: { 'CF-Connecting-IP': '203.0.113.1' },
			});

			const response = await worker.fetch(request, createMockEnv(), createMockCtx().ctx);

			expect(response.status).toBe(401);
		});

		it('applies auth check to POST requests', async () => {
			const request = createMockRequest('https://example.com/update', {
				method: 'POST',
				headers: { 'CF-Connecting-IP': '203.0.113.1' },
				body: JSON.stringify({ test: 'data' }),
			});

			const response = await worker.fetch(request, createMockEnv(), createMockCtx().ctx);

			expect(response.status).toBe(401);
		});

		it('applies auth check to HEAD requests', async () => {
			const request = createMockRequest('https://example.com/update', {
				method: 'HEAD',
				headers: { 'CF-Connecting-IP': '203.0.113.1' },
			});

			const response = await worker.fetch(request, createMockEnv(), createMockCtx().ctx);

			expect(response.status).toBe(401);
		});
	});

	// -------------------------------------------------------------------------
	// Access gate  (checkAccess)
	// -------------------------------------------------------------------------

	describe('Access gate', () => {
		it('verifies the token before touching KV when no ACCESS_KEY is set', async () => {
			// The token is the only credential in open mode, so an unverified
			// caller must not be able to spend a KV read per hostname first.
			env.ACCESS_KEY = '';
			const order: string[] = [];
			mockCloudflareClient.user.tokens.verify.mockImplementation(() => {
				order.push('verify');
				return Promise.reject(new MockAuthenticationError());
			});
			(vi.mocked(env.DDNS_KV) as any).get.mockImplementation(() => {
				order.push('kv');
				return Promise.resolve(null);
			});

			const request = createMockRequest('https://example.com/update?ip4=1.2.3.4&hostnames=a.example.com,b.example.com', {
				headers: { Authorization: createAuthHeader('user', 'token') },
			});

			const response = await worker.fetch(request, env, ctx);

			expect(response.status).toBe(401);
			expect(order).toEqual(['verify']);
		});

		it('does not serve one token a cache entry another token wrote', async () => {
			// A shared ACCESS_KEY is one deployment secret, not a per-caller
			// identity, so without partitioning the fast path would confirm a
			// cached IP to anyone holding it. For a proxied record that value is
			// the origin address.
			env.ACCESS_KEY = 'secret-key';
			const victimKey = 'ip:victim-token:vpn.example.com:A';
			const storage = new Map([[victimKey, JSON.stringify({ ip: '203.0.113.77', updatedAt: '2024-01-01T00:00:00.000Z' })]]);
			(vi.mocked(env.DDNS_KV) as any).get.mockImplementation((key: string) => Promise.resolve(storage.get(key) ?? null));
			mockCloudflareClient.user.tokens.verify.mockResolvedValue({ id: 'attacker-token', status: 'active' } as any);
			mockCloudflareClient.zones.list.mockReturnValue(mockPage({ result: [] }));

			const request = createMockRequest('https://example.com/update?ip4=203.0.113.77&hostnames=vpn.example.com', {
				headers: { Authorization: createAuthHeader('secret-key', 'attacker-cf-token') },
			});

			const response = await worker.fetch(request, env, ctx);

			// A correct IP guess must not come back as the cached-and-current 200.
			expect(response.status).toBe(400);
			expect((vi.mocked(env.DDNS_KV) as any).get).toHaveBeenCalledWith('ip:attacker-token:vpn.example.com:A');
			expect((vi.mocked(env.DDNS_KV) as any).get).not.toHaveBeenCalledWith(victimKey);
		});

		it('passes through when ACCESS_KEY is empty (open mode)', async () => {
			env.ACCESS_KEY = '';
			mockCloudflareClient.user.tokens.verify.mockResolvedValue({ id: 'tid', status: 'active' } as any);
			mockCloudflareClient.zones.list.mockReturnValue(mockPage({ result: [] }));

			const request = createMockRequest('https://example.com/update?ip4=1.2.3.4&hostnames=test.example.com', {
				headers: { Authorization: createAuthHeader('user', 'token') },
			});

			const response = await worker.fetch(request, env, ctx);

			// Fails with 'No zones available' but confirms gate did not block and
			// tokens.verify was called (i.e. we reached the update phase).
			expect(response.status).toBe(400);
			expect(mockCloudflareClient.user.tokens.verify).toHaveBeenCalled();
		});

		it('allows Basic request when ACCESS_KEY matches the Basic username', async () => {
			env.ACCESS_KEY = 'secret-key';
			mockCloudflareClient.user.tokens.verify.mockResolvedValue({ id: 'tid', status: 'active' } as any);
			mockCloudflareClient.zones.list.mockReturnValue(mockPage({ result: [] }));

			const request = createMockRequest('https://example.com/update?ip4=1.2.3.4&hostnames=test.example.com', {
				// Username = access key, token = CF api token
				headers: { Authorization: createAuthHeader('secret-key', 'cf-token') },
			});

			const response = await worker.fetch(request, env, ctx);

			// Fails with 'No zones available' — gate passed and verify was called.
			expect(response.status).toBe(400);
			expect(mockCloudflareClient.user.tokens.verify).toHaveBeenCalled();
		});

		it('allows Bearer request when ACCESS_KEY matches the X-Access-Key header', async () => {
			env.ACCESS_KEY = 'secret-key';
			mockCloudflareClient.user.tokens.verify.mockResolvedValue({ id: 'tid', status: 'active' } as any);
			mockCloudflareClient.zones.list.mockReturnValue(mockPage({ result: [] }));

			const request = createMockRequest('https://example.com/update?ip4=1.2.3.4&hostnames=test.example.com', {
				headers: {
					Authorization: createBearerHeader('cf-token'),
					'X-Access-Key': 'secret-key',
				},
			});

			const response = await worker.fetch(request, env, ctx);

			expect(response.status).toBe(400);
			expect(mockCloudflareClient.user.tokens.verify).toHaveBeenCalled();
		});

		it('rejects with 401 and does NOT call tokens.verify when access key is wrong', async () => {
			env.ACCESS_KEY = 'secret-key';

			const request = createMockRequest('https://example.com/update?ip4=1.2.3.4&hostnames=test.example.com', {
				headers: { Authorization: createAuthHeader('wrong-key', 'cf-token') },
			});

			const response = await worker.fetch(request, env, ctx);

			expect(response.status).toBe(401);
			const body = (await response.json()) as any;
			expect(body).toEqual({ success: false, error: 'Access denied.' });
			// Gate fires before tokens.verify — Cloudflare should never be called for verify
			expect(mockCloudflareClient.user.tokens.verify).not.toHaveBeenCalled();
		});

		it('rejects with 401 and does NOT call tokens.verify when no access key is provided', async () => {
			env.ACCESS_KEY = 'secret-key';

			// Bearer auth with no X-Access-Key header and no username slot
			const request = createMockRequest('https://example.com/update?ip4=1.2.3.4&hostnames=test.example.com', {
				headers: { Authorization: createBearerHeader('cf-token') },
			});

			const response = await worker.fetch(request, env, ctx);

			expect(response.status).toBe(401);
			const body = (await response.json()) as any;
			expect(body).toEqual({ success: false, error: 'Access denied.' });
			expect(mockCloudflareClient.user.tokens.verify).not.toHaveBeenCalled();
		});
	});

	// -------------------------------------------------------------------------
	// DNS record construction  (constructDNSRecords / resolveIps param validation)
	// -------------------------------------------------------------------------

	describe('DNS record construction', () => {
		const validAuth = { Authorization: createAuthHeader('user@example.com', 'token') };

		beforeEach(() => {
			mockCloudflareClient.user.tokens.verify.mockResolvedValue({ id: 'tid', status: 'active' } as any);
		});

		it.each([
			['a malformed connecting address', 'not-an-ip'],
			['an over-long connecting address', 'x'.repeat(300)],
			['a v4-mapped v6 connecting address', '::ffff:203.0.113.1'],
			['no connecting address at all', null],
		])('skips the ip4=auto slot on %s', async (_label, connectingIp) => {
			// `auto` takes the connecting IP only when it really is of that
			// family; a substring check would accept the mapped form here.
			const request = createMockRequest('https://example.com/update?ip4=auto&hostnames=test.example.com', {
				headers: validAuth,
				connectingIp,
			});

			const response = await worker.fetch(request, env, ctx);

			expect(response.status).toBe(422);
			const body = (await response.json()) as any;
			expect(body.error).toContain("Provide 'ip4' and/or 'ip6'");
		});

		it('uses the client address when ip4=auto and it is a valid IPv4 address', async () => {
			mockCloudflareClient.zones.list.mockReturnValue(mockPage({ result: [] }));

			const request = createMockRequest('https://example.com/update?ip4=auto&hostnames=test.example.com', {
				headers: { ...validAuth, 'CF-Connecting-IP': '203.0.113.1' },
			});

			const response = await worker.fetch(request, env, ctx);

			// Fails with 'No zones available' but confirms IP was resolved and
			// zones.list was reached (auth + param parsing both passed).
			expect(response.status).toBe(400);
		});

		it('ip4=auto when client connected over IPv6 with ip6=auto also set produces only AAAA records', async () => {
			mockCloudflareClient.zones.list.mockReturnValue(
				mockPage({
					result: [{ id: 'zone1', name: 'example.com' }],
				}),
			);
			mockCloudflareClient.dns.records.list.mockReturnValue(
				mockPage({
					result: [{ id: 'r1', name: 'test.example.com', type: 'AAAA', content: '::', proxied: false, ttl: 1 }],
				}),
			);
			mockCloudflareClient.dns.records.update.mockResolvedValue(undefined);
			(vi.mocked(env.DDNS_KV) as any).get.mockResolvedValue(null);
			(vi.mocked(env.DDNS_KV) as any).put.mockResolvedValue(undefined);

			// CF-Connecting-IP is an IPv6 address: ip4=auto slot is silently skipped,
			// ip6=auto slot picks up the address.
			const request = createMockRequest('https://example.com/update?ip4=auto&ip6=auto&hostnames=test.example.com', {
				headers: { ...validAuth, 'CF-Connecting-IP': '2001:db8::1' },
			});

			const response = await worker.fetch(request, env, ctx);
			const body = (await response.json()) as any;

			expect(response.status).toBe(200);
			// Only AAAA record was constructed and updated
			expect(body.data.records).toHaveLength(1);
			expect(body.data.records[0]).toMatchObject({ type: 'AAAA' });
			expect(mockCloudflareClient.dns.records.list).toHaveBeenCalledWith(expect.objectContaining({ type: 'AAAA' }));
		});

		it('ip4=auto over IPv6 connection with no ip6 → 422 missing-IP', async () => {
			// ip4=auto silently skips because CF-Connecting-IP contains ':',
			// no ip6 is provided, so both slots end up null → 422.
			const request = createMockRequest('https://example.com/update?ip4=auto&hostnames=test.example.com', {
				headers: { ...validAuth, 'CF-Connecting-IP': '2001:db8::1' },
			});

			const response = await worker.fetch(request, env, ctx);

			expect(response.status).toBe(422);
			const body = (await response.json()) as any;
			expect(body).toEqual({
				success: false,
				error: "Missing IP. Provide 'ip4' and/or 'ip6'; 'auto' uses the client IP.",
			});
		});

		it('ip6=auto when client connected over IPv4 silently skips AAAA and falls through to ip4 only', async () => {
			mockCloudflareClient.zones.list.mockReturnValue(mockPage({ result: [] }));

			// CF-Connecting-IP is IPv4: ip6=auto slot is silently skipped,
			// ip4 literal is resolved, zones.list is reached.
			const request = createMockRequest('https://example.com/update?ip4=1.2.3.4&ip6=auto&hostnames=test.example.com', {
				headers: { ...validAuth, 'CF-Connecting-IP': '203.0.113.1' },
			});

			const response = await worker.fetch(request, env, ctx);

			// Fails with 'No zones available' but confirms ip4 resolved and proceeded.
			expect(response.status).toBe(400);
			expect(mockCloudflareClient.zones.list).toHaveBeenCalled();
		});

		it('rejects ip4 literal that contains a colon (not a valid IPv4 address)', async () => {
			const request = createMockRequest('https://example.com/update?ip4=2001:db8::1&hostnames=test.example.com', {
				headers: validAuth,
			});

			const response = await worker.fetch(request, env, ctx);

			expect(response.status).toBe(422);
			const body = (await response.json()) as any;
			expect(body).toEqual({
				success: false,
				error: "The 'ip4' parameter must be a valid IPv4 address.",
			});
		});

		it('rejects ip6 value that does not contain a colon', async () => {
			const request = createMockRequest('https://example.com/update?ip4=1.2.3.4&ip6=notanipv6&hostnames=test.example.com', {
				headers: validAuth,
			});

			const response = await worker.fetch(request, env, ctx);

			expect(response.status).toBe(422);
			const body = (await response.json()) as any;
			expect(body).toEqual({
				success: false,
				error: "The 'ip6' parameter must be a valid IPv6 address.",
			});
		});

		it('rejects request when neither ip4 nor ip6 is provided', async () => {
			const request = createMockRequest('https://example.com/update?hostnames=test.example.com', {
				headers: validAuth,
			});

			const response = await worker.fetch(request, env, ctx);

			expect(response.status).toBe(422);
			const body = (await response.json()) as any;
			expect(body).toEqual({
				success: false,
				error: "Missing IP. Provide 'ip4' and/or 'ip6'; 'auto' uses the client IP.",
			});
		});

		it('rejects request without hostnames parameter', async () => {
			const request = createMockRequest('https://example.com/update?ip4=1.2.3.4', {
				headers: validAuth,
			});

			const response = await worker.fetch(request, env, ctx);

			expect(response.status).toBe(422);
			const body = (await response.json()) as any;
			expect(body).toEqual({
				success: false,
				error: "Missing 'hostnames' parameter.",
			});
		});

		it('rejects empty hostname list', async () => {
			const request = createMockRequest('https://example.com/update?ip4=1.2.3.4&hostnames=,,,', {
				headers: validAuth,
			});

			const response = await worker.fetch(request, env, ctx);

			expect(response.status).toBe(422);
			const body = (await response.json()) as any;
			expect(body).toEqual({
				success: false,
				error: 'No hostnames provided.',
			});
		});

		// The ceiling is on records, since each IP family turns one hostname
		// into a record and every record carries its own fan-out cost.
		it.each([
			['single family at the ceiling', 40, 'ip4=1.2.3.4'],
			['dual stack at the ceiling', 20, 'ip4=1.2.3.4&ip6=2001:db8::1'],
		])('accepts %s', async (_label, count, ipParams) => {
			const hostnames = Array.from({ length: count }, (_, i) => `h${String(i)}.example.com`).join(',');
			mockCloudflareClient.zones.list.mockReturnValue(mockPage({ result: [{ id: 'zone1', name: 'example.com' }] }));
			mockCloudflareClient.dns.records.list.mockReturnValue(mockPage({ result: [] }));

			const request = createMockRequest(`https://example.com/update?${ipParams}&hostnames=${hostnames}`, {
				headers: validAuth,
			});

			const response = await worker.fetch(request, env, ctx);
			const body = (await response.json()) as any;

			// Refused for having no matching record, not for its size.
			expect(response.status).toBe(400);
			expect(body.error).toContain('No matching record found');
		});

		it.each([
			['single family', 41, 'ip4=1.2.3.4', 41],
			['dual stack', 21, 'ip4=1.2.3.4&ip6=2001:db8::1', 42],
		])('rejects %s past the record ceiling before spending a KV read', async (_label, count, ipParams, records) => {
			const hostnames = Array.from({ length: count }, (_, i) => `h${String(i)}.example.com`).join(',');

			const request = createMockRequest(`https://example.com/update?${ipParams}&hostnames=${hostnames}`, {
				headers: validAuth,
			});

			const response = await worker.fetch(request, env, ctx);

			expect(response.status).toBe(422);
			const body = (await response.json()) as any;
			expect(body).toEqual({
				success: false,
				error: `Too many DNS records: ${String(records)} requested, 40 allowed per request. Each hostname counts once per IP family.`,
			});
			expect((vi.mocked(env.DDNS_KV) as any).get).not.toHaveBeenCalled();
		});

		it('collapses a repeated hostname into one record', async () => {
			// Undeduplicated, each copy races the same DNS record with its own
			// update call and files its own audit row for one logical change.
			const hostnames = Array.from({ length: 30 }, () => 'test.example.com').join(',');
			wireStandardHappyPath(mockCloudflareClient);
			(vi.mocked(env.DDNS_KV) as any).get.mockResolvedValue(null);

			const request = createMockRequest(`https://example.com/update?ip4=1.2.3.5&hostnames=${hostnames}`, {
				headers: validAuth,
			});

			const response = await worker.fetch(request, env, ctx);
			const body = (await response.json()) as any;

			expect(response.status).toBe(200);
			expect(body.data.records).toHaveLength(1);
			expect(mockCloudflareClient.dns.records.update).toHaveBeenCalledTimes(1);
		});

		// The address reaches the Cloudflare API and the response body, so a
		// substring check would let arbitrary caller text through.
		it.each([
			['an octet above 255', 'ip4=256.1.1.1'],
			['too few octets', 'ip4=1.2.3'],
			['too many octets', 'ip4=1.2.3.4.5'],
			['a leading zero', 'ip4=01.2.3.4'],
			['letters', 'ip4=a.b.c.d'],
			['an embedded newline', 'ip4=1.2.3.4%0A%3Cscript%3E'],
			['an eight-thousand character value', `ip4=${'x'.repeat(8000)}.`],
			['an IPv6 address in the ip4 slot', 'ip4=%3A%3A1'],
		])('rejects ip4 with %s', async (_label, param) => {
			const request = createMockRequest(`https://example.com/update?${param}&hostnames=test.example.com`, { headers: validAuth });

			const response = await worker.fetch(request, env, ctx);

			expect(response.status).toBe(422);
			const body = (await response.json()) as any;
			expect(body.error).toBe("The 'ip4' parameter must be a valid IPv4 address.");
		});

		it.each([
			['a doubled elision', '2001:db8::1::2'],
			['too many groups', '2001:db8:0:0:0:0:0:0:1'],
			['too few groups without elision', '2001:db8:0:0:0:0:0'],
			['a non-hex group', 'gggg::1'],
			['an over-long group', '12345::1'],
			['an IPv4 address in the ip6 slot', '1.2.3.4'],
			['a bad embedded dotted quad', '2001:db8::ffff:1.2.3.256'],
			// The URL parser rewrites the dotted tail to hex while RFC 5952 keeps
			// it, so the two spellings would never compare equal against the
			// stored record. An AAAA holding a v4-mapped address is not a useful
			// DDNS target anyway. Both spellings of the same address, because
			// refusing only the dotted one lets the identical address through by
			// the other name and flaps exactly the same way.
			['a v4-mapped address', '::ffff:192.168.1.1'],
			['an uppercase v4-mapped address', '::FFFF:203.0.113.9'],
			['a v4-mapped address spelled in hex', '::ffff:cb00:7101'],
			['a v4-mapped address spelled in uppercase hex', '::FFFF:C000:221'],
			['a v4-mapped address with a leading elision', '0:0:0:0:0:ffff:1:2'],
			// Stray colons: a check that splits on ':' and drops empty groups
			// accepts every one of these.
			['a triple colon', ':::'],
			['a triple colon between groups', '1:::2'],
			['a trailing colon after an elision', '1::2:'],
			['a leading single colon', ':1:2:3:4:5:6:7:8'],
			['a trailing single colon', '1:2:3:4:5:6:7:8:'],
			['a bracket escape attempt', '::1]/@evil.example'],
			['a zone identifier', '::1%eth0'],
			['a CIDR suffix', '::1/64'],
		])('rejects ip6 with %s', async (_label, value) => {
			const request = createMockRequest(`https://example.com/update?ip6=${encodeURIComponent(value)}&hostnames=test.example.com`, {
				headers: validAuth,
			});

			const response = await worker.fetch(request, env, ctx);

			expect(response.status).toBe(422);
			const body = (await response.json()) as any;
			expect(body.error).toBe("The 'ip6' parameter must be a valid IPv6 address.");
		});

		it.each([
			['a dotted quad', 'ip4', '1.2.3.4'],
			['the unspecified v4 address', 'ip4', '0.0.0.0'],
			['the broadcast address', 'ip4', '255.255.255.255'],
			['a compressed v6 address', 'ip6', '2001:db8::1'],
			['v6 loopback', 'ip6', '::1'],
			['the unspecified v6 address', 'ip6', '::'],
			['a fully expanded v6 address', 'ip6', '2001:0db8:0000:0000:0000:0000:0000:0001'],
		])('accepts %s', async (_label, param, value) => {
			mockCloudflareClient.zones.list.mockReturnValue(mockPage({ result: [] }));

			const request = createMockRequest(`https://example.com/update?${param}=${encodeURIComponent(value)}&hostnames=test.example.com`, {
				headers: validAuth,
			});

			const response = await worker.fetch(request, env, ctx);
			const body = (await response.json()) as any;

			// Refused later for having no zones, never for the address itself.
			expect(response.status).toBe(400);
			expect(body.error).toBe('No zones available with current permissions.');
		});

		// Canonicalising is the reason this function returns a value rather than
		// a boolean: Cloudflare stores the canonical form, so forwarding another
		// spelling leaves the comparison permanently unequal and every poll
		// issues a real update, an audit row, and a notification.
		it.each([
			['an uppercase v6 address', '2001:0DB8::1', '2001:db8::1'],
			['a fully expanded v6 address', '2001:0db8:0000:0000:0000:0000:0000:0001', '2001:db8::1'],
			['a v6 address with leading zeros in a group', '2001:db8:0:0:0:0:0:0001', '2001:db8::1'],
		])('stores the canonical spelling of %s', async (_label, sent, canonical) => {
			mockCloudflareClient.zones.list.mockReturnValue(mockPage({ result: [{ id: 'zone1', name: 'example.com' }] }));
			mockCloudflareClient.dns.records.list.mockReturnValue(
				mockPage({ result: [{ id: 'r1', name: 'test.example.com', type: 'AAAA', content: '2001:db8::9', proxied: false, ttl: 1 }] }),
			);
			mockCloudflareClient.dns.records.update.mockResolvedValue(undefined);

			const request = createMockRequest(`https://example.com/update?ip6=${encodeURIComponent(sent)}&hostnames=test.example.com`, {
				headers: validAuth,
			});

			const response = await worker.fetch(request, env, ctx);
			const body = (await response.json()) as any;

			expect(response.status).toBe(200);
			expect(mockCloudflareClient.dns.records.update).toHaveBeenCalledWith('r1', expect.objectContaining({ content: canonical }));
			expect(body.data.records[0].ip).toBe(canonical);
		});

		it('treats a differently spelled but identical address as no change', async () => {
			// The flap this prevents: a record already holding the canonical form
			// would otherwise be rewritten on every poll.
			mockCloudflareClient.zones.list.mockReturnValue(mockPage({ result: [{ id: 'zone1', name: 'example.com' }] }));
			mockCloudflareClient.dns.records.list.mockReturnValue(
				mockPage({ result: [{ id: 'r1', name: 'test.example.com', type: 'AAAA', content: '2001:db8::1', proxied: false, ttl: 1 }] }),
			);

			const request = createMockRequest(
				'https://example.com/update?ip6=2001%3A0DB8%3A0000%3A0000%3A0000%3A0000%3A0000%3A0001&hostnames=test.example.com',
				{
					headers: validAuth,
				},
			);

			const response = await worker.fetch(request, env, ctx);
			const body = (await response.json()) as any;

			expect(response.status).toBe(200);
			expect(body.data.updated).toBe(false);
			expect(mockCloudflareClient.dns.records.update).not.toHaveBeenCalled();
		});

		// Query parameters arrive percent-decoded, so an unchecked hostname
		// carries whatever the caller encoded into the log lines that quote it.
		it.each([
			['an embedded newline', 'a%0AFAKE-LOG-LINE'],
			['a space', 'has%20space.example.com'],
			['a leading dot', '.example.com'],
			['a mid-label wildcard', 'a.*.example.com'],
			['an underscore', 'under_score.example.com'],
		])('rejects a hostname with %s', async (_label, encoded) => {
			const request = createMockRequest(`https://example.com/update?ip4=1.2.3.4&hostnames=${encoded}`, {
				headers: validAuth,
			});

			const response = await worker.fetch(request, env, ctx);

			expect(response.status).toBe(422);
			const body = (await response.json()) as any;
			expect(body.error).toContain('Not a valid hostname');
			// The echoed name is re-encoded, so a newline cannot break the line.
			expect(body.error).not.toContain('\n');
		});

		it.each([
			['a plain fqdn', 'test.example.com'],
			['a wildcard', '*.example.com'],
			['a zone apex', 'example.com'],
			['a punycode idn', 'xn--bcher-kva.example.com'],
			['a hyphenated label', 'my-host-1.example.com'],
		])('accepts %s', async (_label, hostname) => {
			mockCloudflareClient.zones.list.mockReturnValue(mockPage({ result: [] }));

			const request = createMockRequest(`https://example.com/update?ip4=1.2.3.4&hostnames=${encodeURIComponent(hostname)}`, {
				headers: validAuth,
			});

			const response = await worker.fetch(request, env, ctx);
			const body = (await response.json()) as any;

			// Refused later for having no zones, never for its shape.
			expect(body.error).not.toContain('Not a valid hostname');
		});

		it('rejects a hostname longer than a DNS name may be', async () => {
			// An over-long name also pushes the KV cache key past its own limit.
			const hostname = `${'a'.repeat(250)}.example.com`;

			const request = createMockRequest(`https://example.com/update?ip4=1.2.3.4&hostnames=${hostname}`, {
				headers: validAuth,
			});

			const response = await worker.fetch(request, env, ctx);

			expect(response.status).toBe(422);
			const body = (await response.json()) as any;
			expect(body.error).toContain('exceeds 253 characters');
			expect((vi.mocked(env.DDNS_KV) as any).get).not.toHaveBeenCalled();
		});

		// The zone parameter is held to the same shape as a hostname. It reaches
		// the log lines that quote it, the refusal tally, and the /history
		// response that echoes the tally back to the caller.
		it.each([
			['an embedded newline', 'x%0AError+handling+request:+forged'],
			['a space', 'has%20space.example'],
			['an underscore', 'under_score.example'],
			['a value longer than a DNS name may be', `${'a'.repeat(250)}.example.com`],
		])('rejects a zone parameter with %s', async (_label, encoded) => {
			const request = createMockRequest(`https://example.com/update?ip4=1.2.3.4&hostnames=a.example.com&zone=${encoded}`, {
				headers: validAuth,
			});

			const response = await worker.fetch(request, env, ctx);

			expect(response.status).toBe(422);
			const body = (await response.json()) as any;
			expect(body.error).toContain('Not a valid zone name');
			// The echoed value is re-encoded, so a newline cannot break the line.
			expect(body.error).not.toContain('\n');
		});

		it.each([
			['zone', `zone=${'a'.repeat(59)}${encodeURIComponent('\u{1F600}')}.example.com&hostnames=a.example.com`],
			['hostnames', `hostnames=${'a'.repeat(59)}${encodeURIComponent('\u{1F600}')}${'b'.repeat(250)}.example.com`],
		])('answers an astral character on the %s truncation boundary with 422, not 500', async (_label, query) => {
			// The message quotes a shortened copy of the value. Cutting UTF-16
			// units lands mid-pair at exactly this offset, and encoding a lone
			// surrogate throws, which would turn a rejected input into the 500 a
			// DDNS client retries against forever.
			const request = createMockRequest(`https://example.com/update?ip4=1.2.3.4&${query}`, { headers: validAuth });

			const response = await worker.fetch(request, env, ctx);

			expect(response.status).toBe(422);
		});

		it('pins the content type so nothing sniffs a caller-supplied value', async () => {
			const request = createMockRequest('https://example.com/update?ip4=1.2.3.4&hostnames=a.example.com&zone=under_score.example', {
				headers: validAuth,
			});

			const response = await worker.fetch(request, env, ctx);

			expect(response.headers.get('Content-Type')).toBe('application/json');
			expect(response.headers.get('X-Content-Type-Options')).toBe('nosniff');
		});

		it('trims whitespace from ip4 parameter', async () => {
			mockCloudflareClient.zones.list.mockReturnValue(
				mockPage({
					result: [{ id: 'zone1', name: 'example.com' }],
				}),
			);
			mockCloudflareClient.dns.records.list.mockReturnValue(mockPage({ result: [] }));

			const request = createMockRequest('https://example.com/update?ip4=%20%201.2.3.4%20&hostnames=test.example.com', {
				headers: validAuth,
			});

			await worker.fetch(request, env, ctx);

			// The A-record lookup ran with the trimmed address
			expect(mockCloudflareClient.dns.records.list).toHaveBeenCalledWith(
				expect.objectContaining({ name: { exact: 'test.example.com' }, type: 'A' }),
			);
		});

		it('detects IPv4 address and queries for A record', async () => {
			mockCloudflareClient.zones.list.mockReturnValue(
				mockPage({
					result: [{ id: 'zone1', name: 'example.com' }],
				}),
			);
			mockCloudflareClient.dns.records.list.mockReturnValue(mockPage({ result: [] }));

			const request = createMockRequest('https://example.com/update?ip4=192.168.1.1&hostnames=test.example.com', {
				headers: validAuth,
			});

			await worker.fetch(request, env, ctx);

			expect(mockCloudflareClient.dns.records.list).toHaveBeenCalledWith({
				zone_id: 'zone1',
				name: { exact: 'test.example.com' },
				type: 'A',
				per_page: 100,
			});
		});

		it('ip6-only request (no ip4) produces only AAAA records', async () => {
			mockCloudflareClient.zones.list.mockReturnValue(
				mockPage({
					result: [{ id: 'zone1', name: 'example.com' }],
				}),
			);
			mockCloudflareClient.dns.records.list.mockReturnValue(
				mockPage({
					result: [{ id: 'r1', name: 'test.example.com', type: 'AAAA', content: '::', proxied: false, ttl: 1 }],
				}),
			);
			mockCloudflareClient.dns.records.update.mockResolvedValue(undefined);
			(vi.mocked(env.DDNS_KV) as any).get.mockResolvedValue(null);
			(vi.mocked(env.DDNS_KV) as any).put.mockResolvedValue(undefined);

			const request = createMockRequest('https://example.com/update?ip6=2001:db8::1&hostnames=test.example.com', {
				headers: validAuth,
			});

			const response = await worker.fetch(request, env, ctx);
			const body = (await response.json()) as any;

			expect(response.status).toBe(200);
			expect(body.data.records).toHaveLength(1);
			expect(body.data.records[0]).toMatchObject({ type: 'AAAA', ip: '2001:db8::1' });
			expect(mockCloudflareClient.dns.records.list).toHaveBeenCalledWith(expect.objectContaining({ type: 'AAAA' }));
		});

		it('handles multiple hostnames separated by commas', async () => {
			mockCloudflareClient.zones.list.mockReturnValue(
				mockPage({
					result: [{ id: 'zone1', name: 'example.com' }],
				}),
			);
			mockCloudflareClient.dns.records.list.mockReturnValue(mockPage({ result: [] }));

			const request = createMockRequest('https://example.com/update?ip4=1.2.3.4&hostnames=test1.example.com,test2.example.com', {
				headers: validAuth,
			});

			const response = await worker.fetch(request, env, ctx);

			// Fails with 'No matching record found'; both records are queried in
			// parallel so both list calls fire before the error propagates.
			expect(response.status).toBe(400);
			expect(mockCloudflareClient.dns.records.list).toHaveBeenCalledTimes(2);
		});

		it('adds an AAAA record per hostname when ip6 is provided alongside ip4', async () => {
			mockCloudflareClient.zones.list.mockReturnValue(
				mockPage({
					result: [{ id: 'zone1', name: 'example.com' }],
				}),
			);

			// A for h1, AAAA for h1, A for h2, AAAA for h2
			mockCloudflareClient.dns.records.list
				.mockReturnValueOnce(
					mockPage({ result: [{ id: 'r1', name: 'h1.example.com', type: 'A', content: '1.2.3.0', proxied: false, ttl: 1 }] }),
				)
				.mockReturnValueOnce(
					mockPage({ result: [{ id: 'r2', name: 'h1.example.com', type: 'AAAA', content: '::1', proxied: false, ttl: 1 }] }),
				)
				.mockReturnValueOnce(
					mockPage({ result: [{ id: 'r3', name: 'h2.example.com', type: 'A', content: '1.2.3.0', proxied: false, ttl: 1 }] }),
				)
				.mockReturnValueOnce(
					mockPage({ result: [{ id: 'r4', name: 'h2.example.com', type: 'AAAA', content: '::1', proxied: false, ttl: 1 }] }),
				);
			mockCloudflareClient.dns.records.update.mockResolvedValue(undefined);
			(vi.mocked(env.DDNS_KV) as any).get.mockResolvedValue(null);
			(vi.mocked(env.DDNS_KV) as any).put.mockResolvedValue(undefined);

			const request = createMockRequest('https://example.com/update?ip4=1.2.3.4&ip6=2001:db8::1&hostnames=h1.example.com,h2.example.com', {
				headers: validAuth,
			});

			const response = await worker.fetch(request, env, ctx);
			const body = (await response.json()) as any;

			expect(response.status).toBe(200);
			// 2 A records + 2 AAAA records = 4 entries
			expect(body.data.records).toHaveLength(4);
			// All four DNS record lookups ran
			expect(mockCloudflareClient.dns.records.list).toHaveBeenCalledTimes(4);
		});

		it('rejects ntfy param that exceeds 512 characters', async () => {
			const longUrl = `https://ntfy.example.com/${'a'.repeat(490)}`;
			const request = createMockRequest(
				`https://example.com/update?ip4=1.2.3.4&hostnames=test.example.com&ntfy=${encodeURIComponent(longUrl)}`,
				{ headers: validAuth },
			);

			const response = await worker.fetch(request, env, ctx);

			expect(response.status).toBe(422);
			const body = (await response.json()) as any;
			expect(body).toEqual({ success: false, error: "The 'ntfy' parameter is too long." });
		});

		it('rejects ntfy param that is not a valid URL', async () => {
			const request = createMockRequest('https://example.com/update?ip4=1.2.3.4&hostnames=test.example.com&ntfy=not-a-url', {
				headers: validAuth,
			});

			const response = await worker.fetch(request, env, ctx);

			expect(response.status).toBe(422);
			const body = (await response.json()) as any;
			expect(body).toEqual({ success: false, error: "The 'ntfy' parameter must be a valid https URL." });
		});

		it('rejects ntfy param that uses a non-https protocol', async () => {
			const request = createMockRequest(
				'https://example.com/update?ip4=1.2.3.4&hostnames=test.example.com&ntfy=http://ntfy.example.com/topic',
				{ headers: validAuth },
			);

			const response = await worker.fetch(request, env, ctx);

			expect(response.status).toBe(422);
			const body = (await response.json()) as any;
			expect(body).toEqual({ success: false, error: "The 'ntfy' parameter must be a valid https URL." });
		});

		it('accepts a valid https ntfy URL and proceeds to update', async () => {
			mockCloudflareClient.zones.list.mockReturnValue(mockPage({ result: [] }));

			const request = createMockRequest(
				'https://example.com/update?ip4=1.2.3.4&hostnames=test.example.com&ntfy=https%3A%2F%2Fntfy.example.com%2Ftopic',
				{ headers: validAuth },
			);

			const response = await worker.fetch(request, env, ctx);

			// Fails with 'No zones available' but confirms ntfy validation passed
			expect(response.status).toBe(400);
		});
	});

	// -------------------------------------------------------------------------
	// Token verification
	// -------------------------------------------------------------------------

	describe('Token verification', () => {
		const validAuth = { Authorization: createAuthHeader('user@example.com', 'token') };

		it('accepts an active token', async () => {
			mockCloudflareClient.user.tokens.verify.mockResolvedValue({ id: 'tid', status: 'active' } as any);
			mockCloudflareClient.zones.list.mockReturnValue(mockPage({ result: [] }));

			const request = createMockRequest('https://example.com/update?ip4=1.2.3.4&hostnames=test.example.com', {
				headers: validAuth,
			});

			await worker.fetch(request, env, ctx);

			// Fails with 'No zones available' but confirms token.verify was called
			expect(mockCloudflareClient.user.tokens.verify).toHaveBeenCalled();
		});

		it('rejects an inactive token', async () => {
			mockCloudflareClient.user.tokens.verify.mockResolvedValue({ id: 'tid', status: 'expired' } as any);

			const request = createMockRequest('https://example.com/update?ip4=1.2.3.4&hostnames=test.example.com', {
				headers: validAuth,
			});

			const response = await worker.fetch(request, env, ctx);

			expect(response.status).toBe(401);
			const body = (await response.json()) as any;
			expect(body).toEqual({
				success: false,
				error: 'Authentication failed: token expired',
			});
		});

		// The ID keys the zone cache and the audit rows' tenant column, so an
		// active token without one must not reach either.
		it.each([
			['a missing id', { status: 'active' }],
			['an empty id', { id: '', status: 'active' }],
			['a non-string id', { id: 12345, status: 'active' }],
		])('returns 401 when tokens.verify returns %s', async (_label, verification) => {
			mockCloudflareClient.user.tokens.verify.mockResolvedValue(verification as any);

			const request = createMockRequest('https://example.com/update?ip4=1.2.3.4&hostnames=test.example.com', {
				headers: validAuth,
			});

			const response = await worker.fetch(request, env, ctx);

			expect(response.status).toBe(401);
			const body = (await response.json()) as any;
			expect(body).toEqual({
				success: false,
				error: 'Authentication failed: token has no identity.',
			});
			expect(mockCloudflareClient.zones.list).not.toHaveBeenCalled();
		});

		it('returns 401 when tokens.verify rejects with a BadRequestError', async () => {
			mockCloudflareClient.user.tokens.verify.mockRejectedValue(new MockBadRequestError());

			const request = createMockRequest('https://example.com/update?ip4=1.2.3.4&hostnames=test.example.com', {
				headers: validAuth,
			});

			const response = await worker.fetch(request, env, ctx);

			expect(response.status).toBe(401);
			const body = (await response.json()) as any;
			expect(body).toEqual({ success: false, error: 'Authentication failed: invalid token.' });
		});

		it('returns 401 when tokens.verify rejects with an AuthenticationError', async () => {
			mockCloudflareClient.user.tokens.verify.mockRejectedValue(new MockAuthenticationError());

			const request = createMockRequest('https://example.com/update?ip4=1.2.3.4&hostnames=test.example.com', {
				headers: validAuth,
			});

			const response = await worker.fetch(request, env, ctx);

			expect(response.status).toBe(401);
			const body = (await response.json()) as any;
			expect(body).toEqual({ success: false, error: 'Authentication failed: invalid token.' });
		});

		it('returns 401 when tokens.verify rejects with a PermissionDeniedError', async () => {
			mockCloudflareClient.user.tokens.verify.mockRejectedValue(new MockPermissionDeniedError());

			const request = createMockRequest('https://example.com/update?ip4=1.2.3.4&hostnames=test.example.com', {
				headers: validAuth,
			});

			const response = await worker.fetch(request, env, ctx);

			expect(response.status).toBe(401);
			const body = (await response.json()) as any;
			expect(body).toEqual({ success: false, error: 'Authentication failed: invalid token.' });
		});

		it('returns 500 when tokens.verify rejects with a non-auth APIError', async () => {
			// Only the three auth classes map to 401; every other SDK error rethrows.
			mockCloudflareClient.user.tokens.verify.mockRejectedValue(new MockInternalServerError());

			const request = createMockRequest('https://example.com/update?ip4=1.2.3.4&hostnames=test.example.com', {
				headers: validAuth,
			});

			const response = await worker.fetch(request, env, ctx);

			expect(response.status).toBe(500);
			const body = (await response.json()) as any;
			expect(body).toEqual({ success: false, error: 'Internal Server Error' });
		});

		it('returns 500 when tokens.verify rejects with a plain Error (non-APIError)', async () => {
			mockCloudflareClient.user.tokens.verify.mockRejectedValue(new Error('Network error'));

			const request = createMockRequest('https://example.com/update?ip4=1.2.3.4&hostnames=test.example.com', {
				headers: validAuth,
			});

			const response = await worker.fetch(request, env, ctx);

			expect(response.status).toBe(500);
			const body = (await response.json()) as any;
			expect(body).toEqual({ success: false, error: 'Internal Server Error' });
		});
	});

	// -------------------------------------------------------------------------
	// KV cache  (read / write / fast-path)
	// -------------------------------------------------------------------------

	describe('KV cache', () => {
		const validAuth = { Authorization: createAuthHeader('user@example.com', 'token') };

		beforeEach(() => {
			mockCloudflareClient.user.tokens.verify.mockResolvedValue({ id: 'tid', status: 'active' } as any);
		});

		// Gate OFF (ACCESS_KEY = ''): verify runs first, then fast-path check.
		it('skips zone listing and returns 200 when ALL records match their cached IPs (gate off)', async () => {
			env.ACCESS_KEY = '';
			const kvMock = vi.mocked(env.DDNS_KV) as any;
			// Cache contains a JSON entry with matching IP
			kvMock.get.mockResolvedValue(JSON.stringify({ ip: '1.2.3.4', updatedAt: '2024-01-01T00:00:00.000Z' }));

			const request = createMockRequest('https://example.com/update?ip4=1.2.3.4&hostnames=test.example.com', {
				headers: validAuth,
			});

			const response = await worker.fetch(request, env, ctx);

			expect(response.status).toBe(200);
			const body = (await response.json()) as any;
			expect(body).toEqual({
				success: true,
				message: 'No IP change detected',
				data: {
					updated: false,
					records: [{ hostname: 'test.example.com', type: 'A', ip: '1.2.3.4', updated: false }],
				},
			});
			// Short-circuits: zones.list must not be called
			expect(mockCloudflareClient.zones.list).not.toHaveBeenCalled();
			// Gate is off: verify MUST have been called before the fast-path check
			expect(mockCloudflareClient.user.tokens.verify).toHaveBeenCalled();
		});

		// Gate ON (ACCESS_KEY non-empty): fast-path check runs before verify.
		it('stops at the token check when ALL records match cached IPs (gate on)', async () => {
			env.ACCESS_KEY = 'gate-key';
			const kvMock = vi.mocked(env.DDNS_KV) as any;
			kvMock.get.mockResolvedValue(JSON.stringify({ ip: '1.2.3.4', updatedAt: '2024-01-01T00:00:00.000Z' }));

			const request = createMockRequest('https://example.com/update?ip4=1.2.3.4&hostnames=test.example.com', {
				headers: { Authorization: createAuthHeader('gate-key', 'cf-token') },
			});

			const response = await worker.fetch(request, env, ctx);

			expect(response.status).toBe(200);
			const body = (await response.json()) as any;
			expect(body).toEqual({
				success: true,
				message: 'No IP change detected',
				data: {
					updated: false,
					records: [{ hostname: 'test.example.com', type: 'A', ip: '1.2.3.4', updated: false }],
				},
			});
			// The token check names the cache partition, so it is the one call a
			// full cache hit still makes. Nothing beyond it runs.
			expect(mockCloudflareClient.user.tokens.verify).toHaveBeenCalledTimes(1);
			expect(mockCloudflareClient.zones.list).not.toHaveBeenCalled();
			expect(mockCloudflareClient.dns.records.list).not.toHaveBeenCalled();
		});

		it('uses cache key ip:<tokenId>:<hostname>:<type>', async () => {
			const kvMock = vi.mocked(env.DDNS_KV) as any;
			kvMock.get.mockResolvedValue(null);
			kvMock.put.mockResolvedValue(undefined);

			mockCloudflareClient.zones.list.mockReturnValue(
				mockPage({
					result: [{ id: 'zone1', name: 'example.com' }],
				}),
			);
			mockCloudflareClient.dns.records.list.mockReturnValue(
				mockPage({
					result: [{ id: 'r1', name: 'test.example.com', type: 'A', content: '1.2.3.0', proxied: false, ttl: 1 }],
				}),
			);
			mockCloudflareClient.dns.records.update.mockResolvedValue(undefined);

			const request = createMockRequest('https://example.com/update?ip4=1.2.3.4&hostnames=test.example.com', {
				headers: validAuth,
			});

			await worker.fetch(request, env, ctx);

			expect(kvMock.get).toHaveBeenCalledWith('ip:tid:test.example.com:A');
			expect(kvMock.put).toHaveBeenCalledWith('ip:tid:test.example.com:A', expect.any(String), { expirationTtl: 2592000 });
		});

		it('writes JSON {ip, updatedAt} to KV with expirationTtl 2592000', async () => {
			const kvMock = vi.mocked(env.DDNS_KV) as any;
			kvMock.get.mockResolvedValue(null);
			kvMock.put.mockResolvedValue(undefined);

			mockCloudflareClient.zones.list.mockReturnValue(
				mockPage({
					result: [{ id: 'zone1', name: 'example.com' }],
				}),
			);
			mockCloudflareClient.dns.records.list.mockReturnValue(
				mockPage({
					result: [{ id: 'r1', name: 'test.example.com', type: 'A', content: '1.2.3.0', proxied: false, ttl: 1 }],
				}),
			);
			mockCloudflareClient.dns.records.update.mockResolvedValue(undefined);

			const request = createMockRequest('https://example.com/update?ip4=1.2.3.4&hostnames=test.example.com', {
				headers: validAuth,
			});

			await worker.fetch(request, env, ctx);

			// Find the ip-namespace put (as opposed to any zones-namespace put).
			const ipPutCall = (kvMock.put.mock.calls as [string, string, unknown][]).find(([key]) => key.startsWith('ip:'));
			expect(ipPutCall).toBeDefined();
			const [, rawValue, putOptions] = ipPutCall ?? ['', '', {}];
			const parsed = JSON.parse(rawValue) as { ip: string; updatedAt: string };
			expect(parsed.ip).toBe('1.2.3.4');
			expect(typeof parsed.updatedAt).toBe('string');
			expect(putOptions).toEqual({ expirationTtl: 2592000 });
		});

		it('treats malformed cached JSON as a cache miss and proceeds', async () => {
			const kvMock = vi.mocked(env.DDNS_KV) as any;
			kvMock.get.mockResolvedValue('not-json-at-all');

			mockCloudflareClient.zones.list.mockReturnValue(mockPage({ result: [] }));

			const request = createMockRequest('https://example.com/update?ip4=1.2.3.4&hostnames=test.example.com', {
				headers: validAuth,
			});

			const response = await worker.fetch(request, env, ctx);

			// Proceeded past the cache miss and reached zone listing
			expect(mockCloudflareClient.zones.list).toHaveBeenCalled();
			expect(response.status).toBe(400);
		});

		it('treats a cached entry with a non-string ip as a miss and proceeds', async () => {
			const kvMock = vi.mocked(env.DDNS_KV) as any;
			// Valid JSON, but ip is not a string (a corrupt or partial cache write).
			kvMock.get.mockResolvedValue(JSON.stringify({ ip: 12345, updatedAt: '2024-01-01T00:00:00.000Z' }));

			mockCloudflareClient.zones.list.mockReturnValue(mockPage({ result: [] }));

			const request = createMockRequest('https://example.com/update?ip4=1.2.3.4&hostnames=test.example.com', {
				headers: validAuth,
			});

			const response = await worker.fetch(request, env, ctx);

			// The non-string ip is discarded, so the fast path is skipped and zone listing runs.
			expect(mockCloudflareClient.zones.list).toHaveBeenCalled();
			expect(response.status).toBe(400);
		});

		it('treats a KV read error as a cache miss and proceeds', async () => {
			const kvMock = vi.mocked(env.DDNS_KV) as any;
			kvMock.get.mockRejectedValue(new Error('KV read error'));

			mockCloudflareClient.zones.list.mockReturnValue(mockPage({ result: [] }));

			const request = createMockRequest('https://example.com/update?ip4=1.2.3.4&hostnames=test.example.com', {
				headers: validAuth,
			});

			const response = await worker.fetch(request, env, ctx);

			expect(mockCloudflareClient.zones.list).toHaveBeenCalled();
			expect(response.status).toBe(400);
		});

		it('returns 200 and DNS update still succeeds when KV put throws', async () => {
			const kvMock = vi.mocked(env.DDNS_KV) as any;
			kvMock.get.mockResolvedValue(null);
			kvMock.put.mockRejectedValue(new Error('KV write error'));

			mockCloudflareClient.zones.list.mockReturnValue(
				mockPage({
					result: [{ id: 'zone1', name: 'example.com' }],
				}),
			);
			mockCloudflareClient.dns.records.list.mockReturnValue(
				mockPage({
					result: [{ id: 'r1', name: 'test.example.com', type: 'A', content: '1.2.3.0', proxied: false, ttl: 300 }],
				}),
			);
			mockCloudflareClient.dns.records.update.mockResolvedValue(undefined);

			const request = createMockRequest('https://example.com/update?ip4=1.2.3.4&hostnames=test.example.com', {
				headers: validAuth,
			});

			const response = await worker.fetch(request, env, ctx);

			expect(response.status).toBe(200);
			expect(mockCloudflareClient.dns.records.update).toHaveBeenCalled();
		});

		it('proceeds to update when cached IP differs from requested IP', async () => {
			const kvMock = vi.mocked(env.DDNS_KV) as any;
			kvMock.get.mockResolvedValue(JSON.stringify({ ip: '1.2.3.3', updatedAt: '2024-01-01T00:00:00.000Z' }));

			mockCloudflareClient.zones.list.mockReturnValue(mockPage({ result: [] }));

			const request = createMockRequest('https://example.com/update?ip4=1.2.3.4&hostnames=test.example.com', {
				headers: validAuth,
			});

			await worker.fetch(request, env, ctx);

			// Proceeded past the cache check
			expect(mockCloudflareClient.zones.list).toHaveBeenCalled();
		});

		it('proceeds to update when no cache entry exists', async () => {
			const kvMock = vi.mocked(env.DDNS_KV) as any;
			kvMock.get.mockResolvedValue(null);

			mockCloudflareClient.zones.list.mockReturnValue(mockPage({ result: [] }));

			const request = createMockRequest('https://example.com/update?ip4=1.2.3.4&hostnames=test.example.com', {
				headers: validAuth,
			});

			await worker.fetch(request, env, ctx);

			expect(mockCloudflareClient.zones.list).toHaveBeenCalled();
		});

		it('handles partial cache: cached hostname skipped, pending hostname fetches DNS', async () => {
			const kvMock = vi.mocked(env.DDNS_KV) as any;
			// First hostname cached and matching; second hostname not cached
			kvMock.get
				.mockResolvedValueOnce(JSON.stringify({ ip: '1.2.3.4', updatedAt: '2024-01-01T00:00:00.000Z' }))
				.mockResolvedValueOnce(null);
			kvMock.put.mockResolvedValue(undefined);

			mockCloudflareClient.zones.list.mockReturnValue(
				mockPage({
					result: [{ id: 'zone1', name: 'example.com' }],
				}),
			);
			mockCloudflareClient.dns.records.list.mockReturnValue(
				mockPage({
					result: [{ id: 'r2', name: 'h2.example.com', type: 'A', content: '1.2.3.0', proxied: false, ttl: 1 }],
				}),
			);
			mockCloudflareClient.dns.records.update.mockResolvedValue(undefined);

			const request = createMockRequest('https://example.com/update?ip4=1.2.3.4&hostnames=h1.example.com,h2.example.com', {
				headers: validAuth,
			});

			const response = await worker.fetch(request, env, ctx);
			const body = (await response.json()) as any;

			expect(response.status).toBe(200);
			// Both hostnames appear in the result
			expect(body.data.records).toHaveLength(2);
			// Only the non-cached hostname triggered a DNS lookup
			expect(mockCloudflareClient.dns.records.list).toHaveBeenCalledTimes(1);
			// The cached entry appears as updated:false
			const cachedEntry = (body.data.records as any[]).find((r: any) => r.hostname === 'h1.example.com');
			expect(cachedEntry).toMatchObject({ hostname: 'h1.example.com', updated: false });
		});
	});

	// -------------------------------------------------------------------------
	// Zones cache  (KV key zones:<tokenId>, TTL 300)
	// -------------------------------------------------------------------------

	describe('Zones cache', () => {
		const validAuth = { Authorization: createAuthHeader('user@example.com', 'token') };

		beforeEach(() => {
			mockCloudflareClient.user.tokens.verify.mockResolvedValue({ id: 'token-id-123', status: 'active' } as any);
		});

		// Well-formed JSON arrays whose elements are not zones. Trusting any of
		// them would put a non-string into the DNS record path.
		it.each([
			['a non-object element', [{ id: 'zone1', name: 'example.com' }, 'example.com']],
			['a null element', [{ id: 'zone1', name: 'example.com' }, null]],
			['an element missing name', [{ id: 'zone1', name: 'example.com' }, { id: 'zone2' }]],
			[
				'an element whose name is not a string',
				[
					{ id: 'zone1', name: 'example.com' },
					{ id: 'zone2', name: 123 },
				],
			],
		])('treats a cached zone array with %s as a miss', async (_label, cached) => {
			const kvMock = vi.mocked(env.DDNS_KV) as any;
			kvMock.get.mockImplementation((key: string) => Promise.resolve(key.startsWith('zones:') ? JSON.stringify(cached) : null));
			kvMock.put.mockResolvedValue(undefined);
			mockCloudflareClient.zones.list.mockReturnValue(mockPage({ result: [{ id: 'fresh', name: 'example.com' }] }));
			mockCloudflareClient.dns.records.list.mockReturnValue(
				mockPage({ result: [{ id: 'record1', name: 'test.example.com', type: 'A', content: '1.2.3.4' }] }),
			);
			mockCloudflareClient.dns.records.update.mockResolvedValue(undefined);

			const request = createMockRequest('https://example.com/update?ip4=1.2.3.5&hostnames=test.example.com', {
				headers: validAuth,
			});

			const response = await worker.fetch(request, env, ctx);

			expect(response.status).toBe(200);
			expect(mockCloudflareClient.zones.list).toHaveBeenCalled();
			expect(mockCloudflareClient.dns.records.list).toHaveBeenCalledWith(expect.objectContaining({ zone_id: 'fresh' }));
		});

		it('stops walking zone pages at the ceiling instead of spending unbounded subrequests', async () => {
			const warnSpy = vi.spyOn(console, 'warn').mockImplementation(() => {});
			const kvMock = vi.mocked(env.DDNS_KV) as any;
			kvMock.get.mockResolvedValue(null);
			kvMock.put.mockResolvedValue(undefined);
			// 1200 zones on the token, ceiling is 1000. The hosting zone sits past
			// the ceiling, so the walk stops and the hostname does not resolve.
			const zones = Array.from({ length: 1200 }, (_, i) => ({ id: `zone${String(i)}`, name: `z${String(i)}.example.net` }));
			mockCloudflareClient.zones.list.mockReturnValue(mockPage({ result: zones }, { result: [{ id: 'late', name: 'example.com' }] }));

			const request = createMockRequest('https://example.com/update?ip4=1.2.3.5&hostnames=test.example.com', {
				headers: validAuth,
			});

			const response = await worker.fetch(request, env, ctx);

			expect(response.status).toBe(400);
			expect(warnSpy).toHaveBeenCalledWith(expect.stringContaining('sees more than 1000 zones'));
			expect(mockCloudflareClient.dns.records.list).not.toHaveBeenCalled();
		});

		it('calls zones.list and queues a zones cache write when zones cache is a miss', async () => {
			const kvMock = vi.mocked(env.DDNS_KV) as any;
			// All gets return null: ip cache miss and zones cache miss
			kvMock.get.mockResolvedValue(null);
			kvMock.put.mockResolvedValue(undefined);

			mockCloudflareClient.zones.list.mockReturnValue(
				mockPage({
					result: [{ id: 'zone1', name: 'example.com' }],
				}),
			);
			mockCloudflareClient.dns.records.list.mockReturnValue(mockPage({ result: [] }));

			const request = createMockRequest('https://example.com/update?ip4=1.2.3.4&hostnames=test.example.com', {
				headers: validAuth,
			});

			await worker.fetch(request, env, ctx);

			// zones.list runs on a miss
			expect(mockCloudflareClient.zones.list).toHaveBeenCalledTimes(1);
			// The zones cache write rides waitUntil; at least one waitUntil call happened
			expect(waitUntilMock).toHaveBeenCalled();
			// Verify one of the waitUntil promises resolves to writeCachedZones
			// by checking the KV put after awaiting all waitUntil args
			const waitUntilArgs = (waitUntilMock.mock.calls as [Promise<void>][]).map(([p]) => p);
			await Promise.allSettled(waitUntilArgs);
			expect(kvMock.put).toHaveBeenCalledWith('zones:token-id-123', expect.any(String), { expirationTtl: 300 });
		});

		it('skips zones.list when zones cache is a hit and uses the cached zone for record lookup', async () => {
			const kvMock = vi.mocked(env.DDNS_KV) as any;
			const cachedZones = [{ id: 'zone-from-cache', name: 'example.com' }];

			// Zones cache hit, ip cache miss
			kvMock.get.mockImplementation((key: string) => {
				if (key === 'zones:token-id-123') return Promise.resolve(JSON.stringify(cachedZones));
				return Promise.resolve(null);
			});
			kvMock.put.mockResolvedValue(undefined);

			mockCloudflareClient.dns.records.list.mockReturnValue(
				mockPage({
					result: [{ id: 'r1', name: 'test.example.com', type: 'A', content: '1.2.3.0', proxied: false, ttl: 1 }],
				}),
			);
			mockCloudflareClient.dns.records.update.mockResolvedValue(undefined);

			const request = createMockRequest('https://example.com/update?ip4=1.2.3.4&hostnames=test.example.com', {
				headers: validAuth,
			});

			const response = await worker.fetch(request, env, ctx);

			expect(response.status).toBe(200);
			// zones.list NOT called — served from cache
			expect(mockCloudflareClient.zones.list).not.toHaveBeenCalled();
			// DNS record looked up with zone id from cache
			expect(mockCloudflareClient.dns.records.list).toHaveBeenCalledWith(expect.objectContaining({ zone_id: 'zone-from-cache' }));
		});

		it('treats malformed zones JSON as a cache miss and falls back to zones.list', async () => {
			const kvMock = vi.mocked(env.DDNS_KV) as any;
			kvMock.get.mockImplementation((key: string) => {
				if (key === 'zones:token-id-123') return Promise.resolve('not-valid-json');
				return Promise.resolve(null);
			});
			kvMock.put.mockResolvedValue(undefined);

			mockCloudflareClient.zones.list.mockReturnValue(
				mockPage({
					result: [{ id: 'zone1', name: 'example.com' }],
				}),
			);
			mockCloudflareClient.dns.records.list.mockReturnValue(mockPage({ result: [] }));

			const request = createMockRequest('https://example.com/update?ip4=1.2.3.4&hostnames=test.example.com', {
				headers: validAuth,
			});

			await worker.fetch(request, env, ctx);

			// Fell back to zones.list
			expect(mockCloudflareClient.zones.list).toHaveBeenCalledTimes(1);
		});

		it('treats a non-array zones JSON value as a cache miss and falls back to zones.list', async () => {
			const kvMock = vi.mocked(env.DDNS_KV) as any;
			kvMock.get.mockImplementation((key: string) => {
				if (key === 'zones:token-id-123') return Promise.resolve(JSON.stringify({ id: 'z', name: 'x' }));
				return Promise.resolve(null);
			});
			kvMock.put.mockResolvedValue(undefined);

			mockCloudflareClient.zones.list.mockReturnValue(
				mockPage({
					result: [{ id: 'zone1', name: 'example.com' }],
				}),
			);
			mockCloudflareClient.dns.records.list.mockReturnValue(mockPage({ result: [] }));

			const request = createMockRequest('https://example.com/update?ip4=1.2.3.4&hostnames=test.example.com', {
				headers: validAuth,
			});

			await worker.fetch(request, env, ctx);

			expect(mockCloudflareClient.zones.list).toHaveBeenCalledTimes(1);
		});

		it('writes zones cache with expirationTtl 300 via waitUntil', async () => {
			const kvMock = vi.mocked(env.DDNS_KV) as any;
			kvMock.get.mockResolvedValue(null);
			kvMock.put.mockResolvedValue(undefined);

			mockCloudflareClient.zones.list.mockReturnValue(
				mockPage({
					result: [{ id: 'zone1', name: 'example.com' }],
				}),
			);
			mockCloudflareClient.dns.records.list.mockReturnValue(mockPage({ result: [] }));

			const request = createMockRequest('https://example.com/update?ip4=1.2.3.4&hostnames=test.example.com', {
				headers: validAuth,
			});

			await worker.fetch(request, env, ctx);

			const waitUntilArgs = (waitUntilMock.mock.calls as [Promise<void>][]).map(([p]) => p);
			await Promise.allSettled(waitUntilArgs);

			expect(kvMock.put).toHaveBeenCalledWith('zones:token-id-123', expect.any(String), { expirationTtl: 300 });
			const zonesCall = (kvMock.put.mock.calls as [string, string, unknown][]).find(([k]) => k.startsWith('zones:'));
			expect(zonesCall).toBeDefined();
			const zonesJson = JSON.parse((zonesCall ?? ['', '[]'])[1]) as unknown;
			expect(Array.isArray(zonesJson)).toBe(true);
		});
	});

	// -------------------------------------------------------------------------
	// Zone and record matching
	// -------------------------------------------------------------------------

	// ---------------------------------------------------------------------------
	// Refusal counter  (one Durable Object per token)
	// ---------------------------------------------------------------------------

	describe('Refusal counter', () => {
		const validAuth = { Authorization: createAuthHeader('user@example.com', 'token') };

		beforeEach(() => {
			mockCloudflareClient.user.tokens.verify.mockResolvedValue({ id: 'token-id-123', status: 'active' } as any);
			vi.spyOn(console, 'error').mockImplementation(() => {});
		});

		/** The hostname lists handed to the caller's own counter instance. */
		const refusalCalls = (): string[][] => {
			// getByName hands back the same stub per token, so read that stub once
			// rather than collecting across every call that returned it.
			const stub = ((vi.mocked(env.REFUSALS) as any).getByName as (id: string) => { add: { mock: { calls: [string, string[]][] } } })(
				'token-id-123',
			);
			return stub.add.mock.calls.map(([, hostnames]) => hostnames);
		};

		/** Refusals counted against the caller, repeats included. */
		const counted = (): number => refusalCalls().reduce((total, hostnames) => total + hostnames.length, 0);

		/** The distinct names counted against the caller. */
		const countedNames = (): string[] => [...new Set(refusalCalls().flat())];

		/** The token holds example.com, so a name under elsewhere.com is a reach
		 * past its authority. A record missing inside example.com is not. */
		const outsideAuthority = (): void => {
			mockCloudflareClient.zones.list.mockReturnValue(mockPage({ result: [{ id: 'zone1', name: 'example.com' }] }));
			mockCloudflareClient.dns.records.list.mockReturnValue(mockPage({ result: [] }));
		};

		const settle = async (): Promise<void> => {
			await Promise.allSettled((waitUntilMock.mock.calls as [Promise<void>][]).map(([p]) => p));
		};

		it('counts every refusal in a batch however the caller orders it', async () => {
			// The evasion against a row-per-event design is to pad the batch so
			// the probed name is the one dropped. A tally has no selection to
			// steer, and no window to aim a burst at.
			outsideAuthority();
			const padded = [
				'p1.elsewhere.com',
				'p2.elsewhere.com',
				'p3.elsewhere.com',
				'p4.elsewhere.com',
				'p5.elsewhere.com',
				'probe.elsewhere.com',
			];

			const request = createMockRequest(`https://example.com/update?ip4=1.2.3.4&hostnames=${padded.join(',')}`, {
				headers: validAuth,
			});

			await worker.fetch(request, env, ctx);
			await settle();

			expect(counted()).toBe(6);
			expect((vi.mocked(env.REFUSALS) as any).getByName).toHaveBeenCalledWith('token-id-123');
		});

		it('loses nothing when a burst is followed by silence', async () => {
			// Nothing is deferred, so no tally waits on a successor request that
			// may never come.
			outsideAuthority();

			for (let i = 0; i < 5; i++) {
				const request = createMockRequest('https://example.com/update?ip4=1.2.3.4&hostnames=a.elsewhere.com,b.elsewhere.com', {
					headers: validAuth,
				});
				await worker.fetch(request, env, ctx);
			}
			await settle();

			expect(counted()).toBe(10);
		});

		it('reads back what it counted', async () => {
			outsideAuthority();

			const update = createMockRequest('https://example.com/update?ip4=1.2.3.4&hostnames=a.elsewhere.com,b.elsewhere.com', {
				headers: validAuth,
			});
			await worker.fetch(update, env, ctx);
			await settle();

			const history = createMockRequest('https://example.com/history', { headers: validAuth });
			const body = (await (await worker.fetch(history, env, ctx)).json()) as any;

			// The names come back too: the caller owns every hostname in the
			// list, and seeing which ones were refused is what makes the tally
			// worth anything to the party reading it.
			expect(body.data.refusedToday).toEqual({
				total: 2,
				distinct: 2,
				hostnames: ['a.elsewhere.com', 'b.elsewhere.com'],
			});
		});

		it('counts a zone filter naming a zone the token cannot see', async () => {
			// It refuses before any record lookup, which makes it the cheapest
			// probe available and exactly what the counter must not be blind to.
			mockCloudflareClient.zones.list.mockReturnValue(mockPage({ result: [{ id: 'zone1', name: 'example.com' }] }));

			const request = createMockRequest('https://example.com/update?ip4=1.2.3.4&hostnames=a.example.com&zone=other.example', {
				headers: validAuth,
			});

			const response = await worker.fetch(request, env, ctx);
			await settle();

			expect(response.status).toBe(400);
			expect(countedNames()).toEqual(['other.example']);
		});

		it('does not count a token that sees no zones at all', async () => {
			// An account with no zones yet, or a token scoped to none, is a setup
			// state every new user passes through. Counting it would put them in
			// the tally on their first afternoon.
			mockCloudflareClient.zones.list.mockReturnValue(mockPage({ result: [] }));

			const request = createMockRequest('https://example.com/update?ip4=1.2.3.4&hostnames=a.example.com', {
				headers: validAuth,
			});

			const response = await worker.fetch(request, env, ctx);
			await settle();

			expect(response.status).toBe(400);
			expect(counted()).toBe(0);
		});

		it('caches an empty zone list only briefly', async () => {
			// Two failure modes bracket this. The full TTL would keep answering
			// "no zones" after the account's first zone exists; no cache at all
			// would walk the API on every request from a zone-less token, with
			// nothing bounding the rate.
			mockCloudflareClient.zones.list.mockReturnValue(mockPage({ result: [] }));

			const request = createMockRequest('https://example.com/update?ip4=1.2.3.4&hostnames=a.example.com', { headers: validAuth });

			await worker.fetch(request, env, ctx);
			await settle();

			expect((vi.mocked(env.DDNS_KV) as any).put).toHaveBeenCalledWith('zones:token-id-123', '[]', { expirationTtl: 60 });
			// Written, not merely attempted. KV refuses a TTL under 60 and the
			// worker swallows the refusal, so asserting the call alone would pass
			// against a cache that never exists.
			await expect((vi.mocked(env.DDNS_KV) as any).get('zones:token-id-123')).resolves.toBe('[]');
		});

		it('reads the empty zone list back rather than walking the API again', async () => {
			mockCloudflareClient.zones.list.mockReturnValue(mockPage({ result: [] }));

			for (let poll = 0; poll < 5; poll++) {
				const request = createMockRequest('https://example.com/update?ip4=1.2.3.4&hostnames=a.example.com', { headers: validAuth });
				await worker.fetch(request, env, ctx);
				await settle();
			}

			expect(mockCloudflareClient.zones.list).toHaveBeenCalledTimes(1);
		});

		it.each([
			['a permission failure', 'MockPermissionDeniedError', 403, 'needs Zone'],
			['a revoked token', 'MockAuthenticationError', 401, 'Authentication failed'],
			['a rate limit', 'MockRateLimitError', 429, 'rate limiting'],
		])('answers %s while listing zones with an actionable status', async (_label, errorName, status, fragment) => {
			// A token with DNS edit but no Zone Read is the documented setup
			// mistake, and it fails here rather than on a record lookup. Left
			// alone it became a 500, which a DDNS client retries against forever.
			const failures: Record<string, new () => Error> = {
				MockPermissionDeniedError,
				MockAuthenticationError,
				MockRateLimitError,
			};
			const Failure = failures[errorName] ?? MockAuthenticationError;
			mockCloudflareClient.zones.list.mockImplementation(() => ({
				[Symbol.asyncIterator]: () => ({
					next: () => Promise.reject(new Failure()),
				}),
			}));

			const request = createMockRequest('https://example.com/update?ip4=1.2.3.4&hostnames=a.elsewhere.com', { headers: validAuth });

			const response = await worker.fetch(request, env, ctx);
			await settle();
			const body = (await response.json()) as any;

			expect(response.status).toBe(status);
			expect(body.error).toContain(fragment);
			// Neither counts: a token missing a scope is the documented setup
			// mistake, not a reach past authority.
			expect(counted()).toBe(0);
		});

		/** Threshold-crossing warnings, which is all this describe block reads. */
		const crossings = (warnSpy: { mock: { calls: unknown[][] } }): string[] =>
			warnSpy.mock.calls
				.map((call) => call[0])
				.filter((msg): msg is string => typeof msg === 'string' && msg.includes('reached past its authority'));

		it('logs once when a token crosses the refusal threshold', async () => {
			// The tally is otherwise readable only through /history, which is
			// scoped to the very token being counted, so a prober would be the
			// only party who could see it.
			const warnSpy = vi.spyOn(console, 'warn').mockImplementation(() => {});
			outsideAuthority();

			// 40 fresh names per request, so the 100-distinct threshold falls
			// inside the third and the fourth must not report it again.
			for (let round = 0; round < 4; round++) {
				const hostnames = Array.from({ length: 40 }, (_unused, i) => `r${String(round)}h${String(i)}.elsewhere.com`).join(',');
				const request = createMockRequest(`https://example.com/update?ip4=1.2.3.4&hostnames=${hostnames}`, { headers: validAuth });
				await worker.fetch(request, env, ctx);
				await settle();
			}

			expect(crossings(warnSpy)).toHaveLength(1);
			expect(crossings(warnSpy)[0]).toContain('120 distinct hostnames today');
		});

		it('never crosses the threshold on one hostname however long it is retried', async () => {
			// The reason the threshold counts distinct names. A DDNS client polls
			// every two minutes, so one hostname typed wrong passes any total
			// given an afternoon, and the alert would fire on a typo forever.
			const warnSpy = vi.spyOn(console, 'warn').mockImplementation(() => {});
			outsideAuthority();

			for (let poll = 0; poll < 200; poll++) {
				const request = createMockRequest('https://example.com/update?ip4=1.2.3.4&hostnames=typo.elsewhere.com', { headers: validAuth });
				await worker.fetch(request, env, ctx);
			}
			await settle();

			expect(counted()).toBe(200);
			expect(countedNames()).toEqual(['typo.elsewhere.com']);
			expect(crossings(warnSpy)).toHaveLength(0);
		});

		it('does not count a permission failure from the Cloudflare API', async () => {
			mockCloudflareClient.zones.list.mockReturnValue(mockPage({ result: [{ id: 'zone1', name: 'example.com' }] }));
			mockCloudflareClient.dns.records.list.mockImplementation(() => ({
				then: (_r: any, reject: any) => reject(new MockPermissionDeniedError()),
			}));

			const request = createMockRequest('https://example.com/update?ip4=1.2.3.4&hostnames=a.example.com', {
				headers: validAuth,
			});

			const response = await worker.fetch(request, env, ctx);
			await settle();

			expect(response.status).toBe(403);
			// The zone was already confirmed to be on the token, so a 403 here is
			// a missing DNS scope: a setup mistake, not a reach past authority.
			expect(counted()).toBe(0);
		});

		it('answers a revoked token with 401 and does not count it', async () => {
			// A token revoked between verify and the record call is a credential
			// event, not the caller overreaching.
			mockCloudflareClient.zones.list.mockReturnValue(mockPage({ result: [{ id: 'zone1', name: 'example.com' }] }));
			mockCloudflareClient.dns.records.list.mockImplementation(() => ({
				then: (_r: any, reject: any) => reject(new MockAuthenticationError()),
			}));

			const request = createMockRequest('https://example.com/update?ip4=1.2.3.4&hostnames=a.example.com', {
				headers: validAuth,
			});

			const response = await worker.fetch(request, env, ctx);
			await settle();
			const body = (await response.json()) as any;

			expect(response.status).toBe(401);
			expect(body.error).toBe('Authentication failed: invalid token.');
			expect(counted()).toBe(0);
		});

		it('does not count a transport failure against the caller', async () => {
			// The signal is a caller reaching for what it has no claim to, not
			// Cloudflare being unreachable.
			mockCloudflareClient.zones.list.mockReturnValue(mockPage({ result: [{ id: 'zone1', name: 'example.com' }] }));
			mockCloudflareClient.dns.records.list.mockImplementation(() => ({
				then: (_r: any, reject: any) => reject(new MockInternalServerError()),
			}));

			const request = createMockRequest('https://example.com/update?ip4=1.2.3.4&hostnames=a.example.com', {
				headers: validAuth,
			});

			const response = await worker.fetch(request, env, ctx);
			await settle();

			expect(response.status).toBe(500);
			expect(counted()).toBe(0);
		});

		it('does not count anything when every record succeeds', async () => {
			wireStandardHappyPath(mockCloudflareClient);
			(vi.mocked(env.DDNS_KV) as any).get.mockResolvedValue(null);

			const request = createMockRequest('https://example.com/update?ip4=1.2.3.5&hostnames=test.example.com', {
				headers: validAuth,
			});

			await worker.fetch(request, env, ctx);
			await settle();

			expect(counted()).toBe(0);
		});

		/** Refuses once against a freshly discovered list, leaving it cached. */
		const refuseOnce = async (): Promise<void> => {
			const request = createMockRequest('https://example.com/update?ip4=1.2.3.4&hostnames=a.elsewhere.com', { headers: validAuth });
			await worker.fetch(request, env, ctx);
			await settle();
		};

		it('keeps the cached zone list when a hostname is refused', async () => {
			// A zone added since the list was cached does read like a reach past
			// authority. Clearing on that reading costs a full zone walk on every
			// poll for as long as one hostname stays misspelled, and a
			// misspelling outlives any zone change.
			outsideAuthority();
			await refuseOnce();

			await refuseOnce();

			expect((vi.mocked(env.DDNS_KV) as any).delete).not.toHaveBeenCalledWith('zones:token-id-123');
		});

		it('walks the zone list once however long a hostname stays misspelled', async () => {
			// The cost bound the README's throughput section rests on. A token
			// can hold up to ZONE_LIST_MAX zones, so a per-request walk is the
			// worst amplification available to a caller that reaches the API.
			outsideAuthority();

			for (let poll = 0; poll < 10; poll++) {
				await refuseOnce();
			}

			expect(mockCloudflareClient.zones.list).toHaveBeenCalledTimes(1);
		});

		it('does not count a token whose zone list hit the ceiling', async () => {
			// The walk stops at ZONE_LIST_MAX, so a hostname in a zone past it was
			// never looked for rather than reached for. Counting it would put the
			// largest legitimate accounts in the tally, which is the population
			// the alert exists to exclude.
			vi.spyOn(console, 'warn').mockImplementation(() => {});
			const zones = Array.from({ length: 1200 }, (_unused, i) => ({ id: `zone${String(i)}`, name: `z${String(i)}.example.net` }));
			mockCloudflareClient.zones.list.mockReturnValue(mockPage({ result: zones }));

			const request = createMockRequest('https://example.com/update?ip4=1.2.3.4&hostnames=a.elsewhere.com', { headers: validAuth });
			const response = await worker.fetch(request, env, ctx);
			await settle();

			expect(response.status).toBe(400);
			expect(counted()).toBe(0);
		});

		it('counts a dual-stack hostname once, not once per family', async () => {
			// ip4 and ip6 make one hostname two records and two failures. Counting
			// both would make a dual-stack caller look twice as persistent as a
			// single-stack one asking the identical question.
			outsideAuthority();

			const request = createMockRequest('https://example.com/update?ip4=1.2.3.4&ip6=2001:db8::1&hostnames=a.elsewhere.com', {
				headers: validAuth,
			});
			await worker.fetch(request, env, ctx);
			await settle();

			expect(counted()).toBe(1);
			expect(countedNames()).toEqual(['a.elsewhere.com']);
		});

		it('does not count a name the token holds but the caller scoped out', async () => {
			// The caller's own `zone=` narrowing is not the token's permissions.
			// Counting it would put ordinary scoped traffic in the tally, and the
			// README defines a refusal as a name no zone on the token could hold.
			mockCloudflareClient.zones.list.mockReturnValue(
				mockPage({
					result: [
						{ id: 'zone1', name: 'example.com' },
						{ id: 'zone2', name: 'other.example' },
					],
				}),
			);

			const request = createMockRequest('https://example.com/update?ip4=1.2.3.4&hostnames=b.other.example&zone=example.com', {
				headers: validAuth,
			});
			const response = await worker.fetch(request, env, ctx);
			await settle();
			const body = (await response.json()) as any;

			expect(response.status).toBe(400);
			expect(body.error).toContain("outside the zone requested with 'zone='");
			expect(counted()).toBe(0);
		});

		it('does not fail the request when the counter is unreachable', async () => {
			(vi.mocked(env.REFUSALS) as any).getByName.mockImplementation(() => {
				throw new Error('Durable Object unavailable');
			});
			outsideAuthority();

			const request = createMockRequest('https://example.com/update?ip4=1.2.3.4&hostnames=a.elsewhere.com', {
				headers: validAuth,
			});

			const response = await worker.fetch(request, env, ctx);
			await expect(Promise.all((waitUntilMock.mock.calls as [Promise<void>][]).map(([p]) => p))).resolves.toBeDefined();

			expect(response.status).toBe(400);
		});

		it('reports zero rather than failing when the counter cannot be read', async () => {
			(vi.mocked(env.REFUSALS) as any).getByName.mockImplementation(() => {
				throw new Error('Durable Object unavailable');
			});

			const request = createMockRequest('https://example.com/history', { headers: validAuth });

			const response = await worker.fetch(request, env, ctx);
			const body = (await response.json()) as any;

			expect(response.status).toBe(200);
			expect(body.data.refusedToday).toEqual({ total: 0, distinct: 0, hostnames: [] });
		});
	});
	describe('Zone and record matching', () => {
		const validAuth = { Authorization: createAuthHeader('user@example.com', 'token') };

		beforeEach(() => {
			mockCloudflareClient.user.tokens.verify.mockResolvedValue({ id: 'tid', status: 'active' } as any);
			(vi.mocked(env.DDNS_KV) as any).get.mockResolvedValue(null);
		});

		it('queries only the zone that could host the hostname and updates there', async () => {
			mockCloudflareClient.zones.list.mockReturnValue(
				mockPage({
					result: [
						{ id: 'zone1', name: 'example.com' },
						{ id: 'zone2', name: 'test.com' },
					],
				}),
			);
			mockCloudflareClient.dns.records.list.mockReturnValue(
				mockPage({
					result: [{ id: 'record1', name: 'sub.test.com', type: 'A', content: '1.2.3.4' }],
				}),
			);

			mockCloudflareClient.dns.records.update.mockResolvedValue(undefined);

			const request = createMockRequest('https://example.com/update?ip4=1.2.3.5&hostnames=sub.test.com', {
				headers: validAuth,
			});

			const response = await worker.fetch(request, env, ctx);

			expect(response.status).toBe(200);
			// example.com cannot contain sub.test.com, so it is never queried.
			expect(mockCloudflareClient.dns.records.list).toHaveBeenCalledTimes(1);
			expect(mockCloudflareClient.dns.records.list).toHaveBeenCalledWith(expect.objectContaining({ zone_id: 'zone2' }));
			expect(mockCloudflareClient.dns.records.update).toHaveBeenCalledWith('record1', expect.objectContaining({ zone_id: 'zone2' }));
		});

		it('does not scale the record lookup with the number of zones on the token', async () => {
			const manyZones = Array.from({ length: 60 }, (_, i) => ({ id: `zone${String(i)}`, name: `z${String(i)}.example.net` }));
			mockCloudflareClient.zones.list.mockReturnValue(mockPage({ result: [...manyZones, { id: 'target', name: 'test.com' }] }));
			mockCloudflareClient.dns.records.list.mockReturnValue(
				mockPage({ result: [{ id: 'record1', name: 'sub.test.com', type: 'A', content: '1.2.3.4' }] }),
			);
			mockCloudflareClient.dns.records.update.mockResolvedValue(undefined);

			const request = createMockRequest('https://example.com/update?ip4=1.2.3.5&hostnames=sub.test.com', {
				headers: validAuth,
			});

			const response = await worker.fetch(request, env, ctx);

			expect(response.status).toBe(200);
			expect(mockCloudflareClient.dns.records.list).toHaveBeenCalledTimes(1);
		});

		it('matches a hostname case-insensitively against its zone name', async () => {
			mockCloudflareClient.zones.list.mockReturnValue(mockPage({ result: [{ id: 'zone1', name: 'example.com' }] }));
			mockCloudflareClient.dns.records.list.mockReturnValue(
				mockPage({ result: [{ id: 'record1', name: 'Test.EXAMPLE.com', type: 'A', content: '1.2.3.4' }] }),
			);
			mockCloudflareClient.dns.records.update.mockResolvedValue(undefined);

			const request = createMockRequest('https://example.com/update?ip4=1.2.3.5&hostnames=Test.EXAMPLE.com', {
				headers: validAuth,
			});

			const response = await worker.fetch(request, env, ctx);

			expect(response.status).toBe(200);
			expect(mockCloudflareClient.dns.records.list).toHaveBeenCalledWith(expect.objectContaining({ zone_id: 'zone1' }));
		});

		it('matches a hostname that is exactly the zone apex', async () => {
			mockCloudflareClient.zones.list.mockReturnValue(mockPage({ result: [{ id: 'zone1', name: 'example.com' }] }));
			mockCloudflareClient.dns.records.list.mockReturnValue(
				mockPage({ result: [{ id: 'record1', name: 'example.com', type: 'A', content: '1.2.3.4' }] }),
			);
			mockCloudflareClient.dns.records.update.mockResolvedValue(undefined);

			const request = createMockRequest('https://example.com/update?ip4=1.2.3.5&hostnames=example.com', {
				headers: validAuth,
			});

			const response = await worker.fetch(request, env, ctx);

			expect(response.status).toBe(200);
			expect(mockCloudflareClient.dns.records.list).toHaveBeenCalledWith(expect.objectContaining({ zone_id: 'zone1' }));
		});

		it('rejects a hostname that no zone on the token can host', async () => {
			mockCloudflareClient.zones.list.mockReturnValue(mockPage({ result: [{ id: 'zone1', name: 'example.com' }] }));

			const request = createMockRequest('https://example.com/update?ip4=1.2.3.5&hostnames=sub.elsewhere.com', {
				headers: validAuth,
			});

			const response = await worker.fetch(request, env, ctx);

			expect(response.status).toBe(400);
			const body = (await response.json()) as any;
			expect(body.error).toContain('No matching record found');
			// A zone that cannot contain the hostname costs no API call at all.
			expect(mockCloudflareClient.dns.records.list).not.toHaveBeenCalled();
		});

		it('does not treat a zone name as a suffix without a label boundary', async () => {
			mockCloudflareClient.zones.list.mockReturnValue(mockPage({ result: [{ id: 'zone1', name: 'example.com' }] }));

			const request = createMockRequest('https://example.com/update?ip4=1.2.3.5&hostnames=notexample.com', {
				headers: validAuth,
			});

			const response = await worker.fetch(request, env, ctx);

			expect(response.status).toBe(400);
			expect(mockCloudflareClient.dns.records.list).not.toHaveBeenCalled();
		});

		it('matches a hostname whose zone only appears on a later zones page', async () => {
			mockCloudflareClient.zones.list.mockReturnValue(
				mockPage({ result: [{ id: 'zone1', name: 'example.com' }] }, { result: [{ id: 'zone2', name: 'test.com' }] }),
			);
			mockCloudflareClient.dns.records.list.mockReturnValue(
				mockPage({ result: [{ id: 'record1', name: 'sub.test.com', type: 'A', content: '1.2.3.4' }] }),
			);
			mockCloudflareClient.dns.records.update.mockResolvedValue(undefined);

			const request = createMockRequest('https://example.com/update?ip4=1.2.3.5&hostnames=sub.test.com', {
				headers: validAuth,
			});

			const response = await worker.fetch(request, env, ctx);

			expect(response.status).toBe(200);
			expect(mockCloudflareClient.dns.records.update).toHaveBeenCalledWith('record1', expect.objectContaining({ zone_id: 'zone2' }));
		});

		it('spends exactly one bounded records request per candidate zone', async () => {
			// Both zones can host a.sub.example.com, so both are queried once.
			mockCloudflareClient.zones.list.mockReturnValue(
				mockPage({
					result: [
						{ id: 'apex', name: 'example.com' },
						{ id: 'delegated', name: 'sub.example.com' },
					],
				}),
			);
			mockCloudflareClient.dns.records.list.mockReturnValueOnce(mockPage({ result: [] }));
			mockCloudflareClient.dns.records.list.mockReturnValueOnce(
				mockPage({ result: [{ id: 'r1', name: 'a.sub.example.com', type: 'A', content: '1.2.3.4' }] }),
			);
			mockCloudflareClient.dns.records.update.mockResolvedValue(undefined);

			const request = createMockRequest('https://example.com/update?ip4=9.9.9.9&hostnames=a.sub.example.com', {
				headers: validAuth,
			});

			const response = await worker.fetch(request, env, ctx);

			expect(response.status).toBe(200);
			// Two candidate zones, two calls: the page is never re-walked.
			expect(mockCloudflareClient.dns.records.list).toHaveBeenCalledTimes(2);
			expect(mockCloudflareClient.dns.records.list).toHaveBeenCalledWith(expect.objectContaining({ per_page: 100 }));
		});

		it('rejects as ambiguous when two candidate zones both hold the hostname', async () => {
			mockCloudflareClient.zones.list.mockReturnValue(
				mockPage({
					result: [
						{ id: 'apex', name: 'example.com' },
						{ id: 'delegated', name: 'sub.example.com' },
					],
				}),
			);
			mockCloudflareClient.dns.records.list.mockReturnValueOnce(
				mockPage({ result: [{ id: 'r1', name: 'a.sub.example.com', type: 'A', content: '1.2.3.4' }] }),
			);
			mockCloudflareClient.dns.records.list.mockReturnValueOnce(
				mockPage({ result: [{ id: 'r2', name: 'a.sub.example.com', type: 'A', content: '5.6.7.8' }] }),
			);

			const request = createMockRequest('https://example.com/update?ip4=9.9.9.9&hostnames=a.sub.example.com', {
				headers: validAuth,
			});

			const response = await worker.fetch(request, env, ctx);

			expect(response.status).toBe(400);
			const body = (await response.json()) as any;
			expect(body.error).toContain('Multiple matching records found');
			expect(mockCloudflareClient.dns.records.update).not.toHaveBeenCalled();
		});

		it('filters zones by name when zone param is provided', async () => {
			mockCloudflareClient.zones.list.mockReturnValue(
				mockPage({
					result: [
						{ id: 'zone1', name: 'example.com' },
						{ id: 'zone2', name: 'other.com' },
					],
				}),
			);
			mockCloudflareClient.dns.records.list.mockReturnValue(
				mockPage({
					result: [{ id: 'r1', name: 'test.example.com', type: 'A', content: '1.2.3.0', proxied: false, ttl: 1 }],
				}),
			);
			mockCloudflareClient.dns.records.update.mockResolvedValue(undefined);

			const request = createMockRequest('https://example.com/update?ip4=1.2.3.4&hostnames=test.example.com&zone=example.com', {
				headers: validAuth,
			});

			const response = await worker.fetch(request, env, ctx);

			expect(response.status).toBe(200);
			// Only the matching zone was searched
			expect(mockCloudflareClient.dns.records.list).toHaveBeenCalledTimes(1);
			expect(mockCloudflareClient.dns.records.list).toHaveBeenCalledWith(expect.objectContaining({ zone_id: 'zone1' }));
		});

		it('returns 400 when zone filter matches no available zones', async () => {
			mockCloudflareClient.zones.list.mockReturnValue(
				mockPage({
					result: [{ id: 'zone1', name: 'example.com' }],
				}),
			);

			const request = createMockRequest('https://example.com/update?ip4=1.2.3.4&hostnames=test.example.com&zone=notmine.com', {
				headers: validAuth,
			});

			const response = await worker.fetch(request, env, ctx);

			expect(response.status).toBe(400);
			const body = (await response.json()) as any;
			expect(body).toEqual({
				success: false,
				error: "Zone 'notmine.com' not available with current permissions.",
			});
		});

		it('fails when no zones are available', async () => {
			mockCloudflareClient.zones.list.mockReturnValue(mockPage({ result: [] }));

			const request = createMockRequest('https://example.com/update?ip4=1.2.3.4&hostnames=test.example.com', {
				headers: validAuth,
			});

			const response = await worker.fetch(request, env, ctx);

			expect(response.status).toBe(400);
			const body = (await response.json()) as any;
			expect(body).toEqual({
				success: false,
				error: 'No zones available with current permissions.',
			});
		});

		it('fails when no matching record is found', async () => {
			mockCloudflareClient.zones.list.mockReturnValue(
				mockPage({
					result: [{ id: 'zone1', name: 'example.com' }],
				}),
			);
			mockCloudflareClient.dns.records.list.mockReturnValue(mockPage({ result: [] }));

			const request = createMockRequest('https://example.com/update?ip4=1.2.3.4&hostnames=test.example.com', {
				headers: validAuth,
			});

			const response = await worker.fetch(request, env, ctx);

			expect(response.status).toBe(400);
			const body = (await response.json()) as any;
			expect(body).toEqual({
				success: false,
				error: "No matching record found for 'test.example.com'. Create it manually first.",
				data: {
					updated: false,
					records: [{ hostname: 'test.example.com', type: 'A', ip: '1.2.3.4', updated: false }],
					failed: [
						{
							hostname: 'test.example.com',
							type: 'A',
							status: 400,
							error: "No matching record found for 'test.example.com'. Create it manually first.",
						},
					],
				},
			});
		});

		it('fails when multiple matching records are found across zones', async () => {
			mockCloudflareClient.zones.list.mockReturnValue(
				mockPage({
					result: [
						{ id: 'zone1', name: 'example.com' },
						{ id: 'zone2', name: 'example.com' },
					],
				}),
			);
			mockCloudflareClient.dns.records.list.mockReturnValue(
				mockPage({
					result: [{ id: 'record1', name: 'test.example.com', type: 'A', content: '1.2.3.4' }],
				}),
			);

			const request = createMockRequest('https://example.com/update?ip4=1.2.3.5&hostnames=test.example.com', {
				headers: validAuth,
			});

			const response = await worker.fetch(request, env, ctx);

			expect(response.status).toBe(400);
			const body = (await response.json()) as any;
			expect(body).toEqual({
				success: false,
				error: "Multiple matching records found for 'test.example.com'. Specify a unique hostname per zone.",
				data: {
					updated: false,
					records: [{ hostname: 'test.example.com', type: 'A', ip: '1.2.3.5', updated: false }],
					failed: [
						{
							hostname: 'test.example.com',
							type: 'A',
							status: 400,
							error: "Multiple matching records found for 'test.example.com'. Specify a unique hostname per zone.",
						},
					],
				},
			});
		});

		it('treats an empty zone param as no filter and searches all zones', async () => {
			mockCloudflareClient.zones.list.mockReturnValue(
				mockPage({
					result: [
						{ id: 'zone1', name: 'example.com' },
						{ id: 'zone2', name: 'test.com' },
					],
				}),
			);
			// Record lives in the second zone; an empty zone filter must not narrow the search.
			mockCloudflareClient.dns.records.list.mockReturnValue(
				mockPage({
					result: [{ id: 'record1', name: 'sub.test.com', type: 'A', content: '1.2.3.4' }],
				}),
			);
			mockCloudflareClient.dns.records.update.mockResolvedValue(undefined);

			const request = createMockRequest('https://example.com/update?ip4=1.2.3.5&hostnames=sub.test.com&zone=', {
				headers: validAuth,
			});

			const response = await worker.fetch(request, env, ctx);

			expect(response.status).toBe(200);
			// The empty zone string normalises to null, so zone2 stays in the set
			// and DNS containment picks it as the only zone that could host it.
			expect(mockCloudflareClient.dns.records.list).toHaveBeenCalledWith(expect.objectContaining({ zone_id: 'zone2' }));
		});
	});

	// -------------------------------------------------------------------------
	// Record update flow
	// -------------------------------------------------------------------------

	describe('Record update flow', () => {
		const validAuth = { Authorization: createAuthHeader('user@example.com', 'token') };

		beforeEach(() => {
			mockCloudflareClient.user.tokens.verify.mockResolvedValue({ id: 'token-id-123', status: 'active' } as any);
			(vi.mocked(env.DDNS_KV) as any).get.mockResolvedValue(null);
			(vi.mocked(env.DDNS_KV) as any).put.mockResolvedValue(undefined);
		});

		it('successfully updates a single DNS record and returns the correct shape', async () => {
			const { pushNtfy } = await import('../src/pushNtfy');
			const pushNtfyMock = vi.mocked(pushNtfy);

			mockCloudflareClient.zones.list.mockReturnValue(
				mockPage({
					result: [{ id: 'zone1', name: 'example.com' }],
				}),
			);
			mockCloudflareClient.dns.records.list.mockReturnValue(
				mockPage({
					result: [
						{ id: 'record1', name: 'test.example.com', type: 'A', content: '1.2.3.4', proxied: true, comment: 'Test record', ttl: 300 },
					],
				}),
			);
			mockCloudflareClient.dns.records.update.mockResolvedValue(undefined);

			const request = createMockRequest('https://example.com/update?ip4=1.2.3.5&hostnames=test.example.com', {
				headers: validAuth,
			});

			const response = await worker.fetch(request, env, ctx);

			expect(response.status).toBe(200);
			const body = (await response.json()) as any;
			expect(body).toEqual({
				success: true,
				message: 'DNS records updated successfully',
				data: {
					updated: true,
					records: [{ hostname: 'test.example.com', type: 'A', ip: '1.2.3.5', updated: true }],
				},
			});

			expect(mockCloudflareClient.dns.records.update).toHaveBeenCalledWith('record1', {
				content: '1.2.3.5',
				zone_id: 'zone1',
				name: 'test.example.com',
				type: 'A',
				proxied: true,
				comment: 'Test record',
				ttl: 300,
			});

			// pushNtfy is called via waitUntil on a change; resolve all waitUntil args.
			const waitUntilArgs = (waitUntilMock.mock.calls as [Promise<void>][]).map(([p]) => p);
			await Promise.allSettled(waitUntilArgs);
			expect(pushNtfyMock).toHaveBeenCalledWith(["DNS record for 'test.example.com' ('A') updated to '1.2.3.5'"], null);
		});

		it('does not call dns.records.update when existing content already matches target IP (DNS-delta no-op)', async () => {
			const { pushNtfy } = await import('../src/pushNtfy');
			const pushNtfyMock = vi.mocked(pushNtfy);

			mockCloudflareClient.zones.list.mockReturnValue(
				mockPage({
					result: [{ id: 'zone1', name: 'example.com' }],
				}),
			);
			// Existing DNS content already matches the requested IP
			mockCloudflareClient.dns.records.list.mockReturnValue(
				mockPage({
					result: [{ id: 'r1', name: 'test.example.com', type: 'A', content: '1.2.3.4', proxied: false, ttl: 1 }],
				}),
			);

			const request = createMockRequest('https://example.com/update?ip4=1.2.3.4&hostnames=test.example.com', {
				headers: validAuth,
			});

			const response = await worker.fetch(request, env, ctx);
			const body = (await response.json()) as any;

			expect(response.status).toBe(200);
			expect(body.message).toBe('DNS records already current');
			expect(body.data.updated).toBe(false);
			expect(body.data.records[0]).toMatchObject({ hostname: 'test.example.com', ip: '1.2.3.4', updated: false });
			// Update must not have been called
			expect(mockCloudflareClient.dns.records.update).not.toHaveBeenCalled();
			// Cache is still written even on a no-op
			expect((vi.mocked(env.DDNS_KV) as any).put).toHaveBeenCalled();
			// No change: pushNtfy must NOT be called at all
			expect(pushNtfyMock).not.toHaveBeenCalled();
		});

		it('does not call pushNtfy when no records changed', async () => {
			const { pushNtfy } = await import('../src/pushNtfy');
			const pushNtfyMock = vi.mocked(pushNtfy);

			mockCloudflareClient.zones.list.mockReturnValue(
				mockPage({
					result: [{ id: 'zone1', name: 'example.com' }],
				}),
			);
			mockCloudflareClient.dns.records.list.mockReturnValue(
				mockPage({
					result: [{ id: 'r1', name: 'test.example.com', type: 'A', content: '5.5.5.5', proxied: false, ttl: 1 }],
				}),
			);

			const request = createMockRequest('https://example.com/update?ip4=5.5.5.5&hostnames=test.example.com', {
				headers: validAuth,
			});

			await worker.fetch(request, env, ctx);

			// Resolve all waitUntil args to catch any deferred calls
			const waitUntilArgs = (waitUntilMock.mock.calls as [Promise<void>][]).map(([p]) => p);
			await Promise.allSettled(waitUntilArgs);
			expect(pushNtfyMock).not.toHaveBeenCalled();
		});

		it('successfully updates multiple DNS records and sends a grouped notification', async () => {
			const { pushNtfy } = await import('../src/pushNtfy');
			const pushNtfyMock = vi.mocked(pushNtfy);

			mockCloudflareClient.zones.list.mockReturnValue(
				mockPage({
					result: [{ id: 'zone1', name: 'example.com' }],
				}),
			);

			mockCloudflareClient.dns.records.list
				.mockReturnValueOnce(
					mockPage({ result: [{ id: 'record1', name: 'test1.example.com', type: 'A', content: '1.2.3.4', proxied: false, ttl: 1 }] }),
				)
				.mockReturnValueOnce(
					mockPage({ result: [{ id: 'record2', name: 'test2.example.com', type: 'A', content: '1.2.3.4', proxied: true, ttl: 300 }] }),
				);

			mockCloudflareClient.dns.records.update.mockResolvedValue(undefined);

			const request = createMockRequest('https://example.com/update?ip4=1.2.3.5&hostnames=test1.example.com,test2.example.com', {
				headers: validAuth,
			});

			const response = await worker.fetch(request, env, ctx);

			expect(response.status).toBe(200);
			const body = (await response.json()) as any;
			expect(body.data.records).toHaveLength(2);

			expect(mockCloudflareClient.dns.records.update).toHaveBeenCalledTimes(2);

			// pushNtfy runs via waitUntil; await all deferred promises first.
			const waitUntilArgs = (waitUntilMock.mock.calls as [Promise<void>][]).map(([p]) => p);
			await Promise.allSettled(waitUntilArgs);
			expect(pushNtfyMock).toHaveBeenCalledWith(
				expect.arrayContaining([
					"DNS record for 'test1.example.com' ('A') updated to '1.2.3.5'",
					"DNS record for 'test2.example.com' ('A') updated to '1.2.3.5'",
				]),
				null,
			);
		});

		it('handles records without optional fields by using defaults', async () => {
			mockCloudflareClient.zones.list.mockReturnValue(
				mockPage({
					result: [{ id: 'zone1', name: 'example.com' }],
				}),
			);
			mockCloudflareClient.dns.records.list.mockReturnValue(
				mockPage({
					result: [
						{
							id: 'record1',
							name: 'test.example.com',
							type: 'A',
							content: '1.2.3.4',
							// No proxied, comment, or ttl fields
						},
					],
				}),
			);
			mockCloudflareClient.dns.records.update.mockResolvedValue(undefined);

			const request = createMockRequest('https://example.com/update?ip4=1.2.3.5&hostnames=test.example.com', {
				headers: validAuth,
			});

			const response = await worker.fetch(request, env, ctx);

			expect(response.status).toBe(200);
			expect(mockCloudflareClient.dns.records.update).toHaveBeenCalledWith('record1', {
				content: '1.2.3.5',
				zone_id: 'zone1',
				name: 'test.example.com',
				type: 'A',
				proxied: false,
				comment: undefined,
				ttl: 1,
			});
		});

		it('calls pushNtfy exactly once when a record changes', async () => {
			const { pushNtfy } = await import('../src/pushNtfy');
			const pushNtfyMock = vi.mocked(pushNtfy);

			mockCloudflareClient.zones.list.mockReturnValue(
				mockPage({
					result: [{ id: 'zone1', name: 'example.com' }],
				}),
			);
			mockCloudflareClient.dns.records.list.mockReturnValue(
				mockPage({
					result: [{ id: 'r1', name: 'test.example.com', type: 'A', content: '1.2.3.0', proxied: false, ttl: 1 }],
				}),
			);
			mockCloudflareClient.dns.records.update.mockResolvedValue(undefined);

			const request = createMockRequest('https://example.com/update?ip4=1.2.3.4&hostnames=test.example.com', {
				headers: validAuth,
			});

			await worker.fetch(request, env, ctx);

			const waitUntilArgs = (waitUntilMock.mock.calls as [Promise<void>][]).map(([p]) => p);
			await Promise.allSettled(waitUntilArgs);
			expect(pushNtfyMock).toHaveBeenCalledTimes(1);
		});
	});

	// -------------------------------------------------------------------------
	// Audit events  (ctx.waitUntil + AUDIT_DB.batch)
	// -------------------------------------------------------------------------

	describe('Audit events', () => {
		const validAuth = { Authorization: createAuthHeader('user@example.com', 'token') };

		beforeEach(() => {
			mockCloudflareClient.user.tokens.verify.mockResolvedValue({ id: 'token-id-123', status: 'active' } as any);
			(vi.mocked(env.DDNS_KV) as any).get.mockResolvedValue(null);
			(vi.mocked(env.DDNS_KV) as any).put.mockResolvedValue(undefined);
		});

		it('calls ctx.waitUntil at least once with a Promise when a record reaches the DNS API', async () => {
			mockCloudflareClient.zones.list.mockReturnValue(
				mockPage({
					result: [{ id: 'zone1', name: 'example.com' }],
				}),
			);
			mockCloudflareClient.dns.records.list.mockReturnValue(
				mockPage({
					result: [{ id: 'r1', name: 'test.example.com', type: 'A', content: '1.2.3.0', proxied: false, ttl: 1 }],
				}),
			);
			mockCloudflareClient.dns.records.update.mockResolvedValue(undefined);

			const request = createMockRequest('https://example.com/update?ip4=1.2.3.4&hostnames=test.example.com', {
				headers: validAuth,
			});

			await worker.fetch(request, env, ctx);

			expect(waitUntilMock).toHaveBeenCalled();
			// All waitUntil arguments must be Promises
			for (const [arg] of waitUntilMock.mock.calls as [[unknown]]) {
				expect(arg).toBeInstanceOf(Promise);
			}
		});

		it('does NOT call ctx.waitUntil on the cache fast-path (nothing touched)', async () => {
			const kvMock = vi.mocked(env.DDNS_KV) as any;
			kvMock.get.mockResolvedValue(JSON.stringify({ ip: '1.2.3.4', updatedAt: '2024-01-01T00:00:00.000Z' }));

			const request = createMockRequest('https://example.com/update?ip4=1.2.3.4&hostnames=test.example.com', {
				headers: validAuth,
			});

			await worker.fetch(request, env, ctx);

			expect(waitUntilMock).not.toHaveBeenCalled();
		});

		it('audits and notifies the records that landed even when a sibling record fails', async () => {
			// Records are processed concurrently, so a refusal on one arrives
			// after another has already changed DNS. That change is real and must
			// not vanish from the audit trail because the response is an error.
			const { pushNtfy } = await import('../src/pushNtfy');
			const pushNtfyMock = vi.mocked(pushNtfy);
			mockCloudflareClient.zones.list.mockReturnValue(mockPage({ result: [{ id: 'zone1', name: 'example.com' }] }));
			// good.example.com resolves and changes; missing.example.com does not exist.
			mockCloudflareClient.dns.records.list.mockImplementation((params: any) =>
				params.name.exact === 'good.example.com'
					? mockPage({ result: [{ id: 'r1', name: 'good.example.com', type: 'A', content: '1.2.3.0', proxied: false, ttl: 1 }] })
					: mockPage({ result: [] }),
			);
			mockCloudflareClient.dns.records.update.mockResolvedValue(undefined);

			const request = createMockRequest('https://example.com/update?ip4=1.2.3.4&hostnames=good.example.com,missing.example.com', {
				headers: { ...validAuth, 'CF-Connecting-IP': '5.6.7.8' },
			});

			const response = await worker.fetch(request, env, ctx);

			// The request is still refused: one hostname could not be updated.
			expect(response.status).toBe(400);
			const body = (await response.json()) as any;
			expect(body.error).toContain("No matching record found for 'missing.example.com'");

			// The DNS change that did land was applied, so it must be recorded.
			expect(mockCloudflareClient.dns.records.update).toHaveBeenCalledWith('r1', expect.objectContaining({ content: '1.2.3.4' }));

			const waitUntilArgs = (waitUntilMock.mock.calls as [Promise<void>][]).map(([p]) => p);
			await Promise.allSettled(waitUntilArgs);

			const auditDbMock = vi.mocked(env.AUDIT_DB) as any;
			expect(auditDbMock.batch).toHaveBeenCalledTimes(1);
			const [batchArg] = auditDbMock.batch.mock.calls[0] as [unknown[]];
			expect(batchArg).toHaveLength(1);
			expect(auditDbMock.prepare().bind).toHaveBeenCalledWith(
				expect.stringMatching(/^\d{4}-\d{2}-\d{2}T/),
				'token-id-123',
				'5.6.7.8',
				'good.example.com',
				'A',
				'1.2.3.0',
				'1.2.3.4',
				'updated',
			);
			expect(pushNtfyMock).toHaveBeenCalledWith([expect.stringContaining('good.example.com')], null);
		});

		it('reports the records that landed in the error body', async () => {
			// A caller that reads only the status would otherwise conclude
			// nothing changed while its sibling record was repointed.
			mockCloudflareClient.zones.list.mockReturnValue(mockPage({ result: [{ id: 'zone1', name: 'example.com' }] }));
			mockCloudflareClient.dns.records.list.mockImplementation((params: any) =>
				params.name.exact === 'good.example.com'
					? mockPage({ result: [{ id: 'r1', name: 'good.example.com', type: 'A', content: '1.2.3.0', proxied: false, ttl: 1 }] })
					: mockPage({ result: [] }),
			);
			mockCloudflareClient.dns.records.update.mockResolvedValue(undefined);

			const request = createMockRequest('https://example.com/update?ip4=1.2.3.4&hostnames=good.example.com,missing.example.com', {
				headers: validAuth,
			});

			const response = await worker.fetch(request, env, ctx);
			const body = (await response.json()) as any;

			expect(response.status).toBe(400);
			expect(body.success).toBe(false);
			expect(body.data).toEqual({
				updated: true,
				records: [
					{ hostname: 'good.example.com', type: 'A', ip: '1.2.3.4', updated: true },
					// Present with updated: false, and named in `failed` below.
					// A record that was already current carries the same flag, so
					// the change list alone cannot tell the two apart.
					{ hostname: 'missing.example.com', type: 'A', ip: '1.2.3.4', updated: false },
				],
				failed: [
					{
						hostname: 'missing.example.com',
						type: 'A',
						status: 400,
						error: "No matching record found for 'missing.example.com'. Create it manually first.",
					},
				],
			});
		});

		it('surfaces the actionable refusal rather than a transient failure on an earlier record', async () => {
			// find() scans by index, so an early transport error would mask a
			// later 400. A 5xx is also what a DDNS client retries against, so
			// the caller would loop on a permanent misconfiguration.
			mockCloudflareClient.zones.list.mockReturnValue(mockPage({ result: [{ id: 'zone1', name: 'example.com' }] }));
			mockCloudflareClient.dns.records.list.mockImplementation((params: any) => {
				if (params.name.exact === 'aaa.example.com') {
					return { then: (_r: any, reject: any) => reject(new MockInternalServerError()) };
				}
				return mockPage({ result: [] });
			});

			const request = createMockRequest('https://example.com/update?ip4=1.2.3.4&hostnames=aaa.example.com,zzz.example.com', {
				headers: validAuth,
			});

			const response = await worker.fetch(request, env, ctx);
			const body = (await response.json()) as any;

			expect(response.status).toBe(400);
			expect(body.error).toContain("No matching record found for 'zzz.example.com'");
			// The status can only describe one record. Without the rest beside
			// it, a caller reading a terminal 400 stops retrying the transient
			// 500 on the record next to it, and that record never recovers.
			expect(body.data.failed).toEqual([
				{ hostname: 'aaa.example.com', type: 'A', status: 500, error: 'Internal Server Error' },
				{
					hostname: 'zzz.example.com',
					type: 'A',
					status: 400,
					error: "No matching record found for 'zzz.example.com'. Create it manually first.",
				},
			]);
		});

		it.each([
			['a permission failure', 'MockPermissionDeniedError', 403, 'The API token lacks permission for this record.'],
			['a rate limit', 'MockRateLimitError', 429, 'The Cloudflare API is rate limiting this token. Retry later.'],
			['a revoked token', 'MockAuthenticationError', 401, 'Authentication failed: invalid token.'],
			[
				'a record Cloudflare rejects',
				'MockBadRequestError',
				400,
				'Cloudflare rejected this record. Check that the name exists and its type matches the address family.',
			],
			['a zone that is gone', 'MockNotFoundError', 404, 'Cloudflare no longer has this zone or record.'],
			// 409 stands for every other terminal answer the API can give. None
			// have a branch of their own, and reporting them as 500 would send a
			// client to retry a request that can never succeed.
			['any other terminal answer', 'MockConflictError', 409, 'Cloudflare rejected this record.'],
		])('categorises %s against the record it happened to', async (_label, errorName, status, message) => {
			// Translated, not forwarded: the upstream message is Cloudflare's and
			// says nothing the caller can act on.
			const failures: Record<string, new () => Error> = {
				MockPermissionDeniedError,
				MockRateLimitError,
				MockAuthenticationError,
				MockBadRequestError,
				MockNotFoundError,
				MockConflictError,
			};
			const Failure = failures[errorName] ?? MockInternalServerError;
			mockCloudflareClient.zones.list.mockReturnValue(mockPage({ result: [{ id: 'zone1', name: 'example.com' }] }));
			mockCloudflareClient.dns.records.list.mockImplementation(() => ({
				then: (_r: any, reject: any) => reject(new Failure()),
			}));

			const request = createMockRequest('https://example.com/update?ip4=1.2.3.4&hostnames=a.example.com', { headers: validAuth });

			const response = await worker.fetch(request, env, ctx);
			const body = (await response.json()) as any;

			expect(body.data.failed).toEqual([{ hostname: 'a.example.com', type: 'A', status, error: message }]);
			// The status too, not only the per-record list. A body that says 429
			// under a 500 sends the client to retry against a throttled token.
			expect(response.status).toBe(status);
			expect(body.error).toBe(message);
		});

		it.each([
			['a dead credential over a record that could be fixed', 'MockAuthenticationError', 'MockNotFoundError', 401],
			['a terminal answer over a transient one', 'MockNotFoundError', 'MockInternalServerError', 404],
			['a terminal answer over a rate limit', 'MockPermissionDeniedError', 'MockRateLimitError', 403],
		])('reports %s', async (_label, firstName, secondName, status) => {
			// One status has to speak for a mixed batch. Every record's own
			// verdict is in data.failed either way, so the choice is about which
			// one a client acting on the status alone should see.
			const failures: Record<string, new () => Error> = {
				MockAuthenticationError,
				MockNotFoundError,
				MockInternalServerError,
				MockPermissionDeniedError,
				MockRateLimitError,
			};
			const First = failures[firstName] ?? MockInternalServerError;
			const Second = failures[secondName] ?? MockInternalServerError;
			mockCloudflareClient.zones.list.mockReturnValue(mockPage({ result: [{ id: 'zone1', name: 'example.com' }] }));
			mockCloudflareClient.dns.records.list.mockImplementation((params: any) => ({
				then: (_r: any, reject: any) => reject(params.name.exact === 'first.example.com' ? new First() : new Second()),
			}));

			const request = createMockRequest('https://example.com/update?ip4=1.2.3.4&hostnames=first.example.com,second.example.com', {
				headers: validAuth,
			});

			const response = await worker.fetch(request, env, ctx);
			const body = (await response.json()) as any;

			expect(response.status).toBe(status);
			// Whichever lost still reports its own verdict, so a client that
			// reads the list never loses the record the status did not describe.
			expect(body.data.failed).toHaveLength(2);
		});

		it('returns 500 when every failure is a transport error', async () => {
			mockCloudflareClient.zones.list.mockReturnValue(mockPage({ result: [{ id: 'zone1', name: 'example.com' }] }));
			mockCloudflareClient.dns.records.list.mockImplementation(() => ({
				then: (_r: any, reject: any) => reject(new MockInternalServerError()),
			}));

			const request = createMockRequest('https://example.com/update?ip4=1.2.3.4&hostnames=a.example.com', {
				headers: validAuth,
			});

			const response = await worker.fetch(request, env, ctx);
			const body = (await response.json()) as any;

			expect(response.status).toBe(500);
			expect(body).toEqual({
				success: false,
				error: 'Internal Server Error',
				data: {
					updated: false,
					records: [{ hostname: 'a.example.com', type: 'A', ip: '1.2.3.4', updated: false }],
					failed: [{ hostname: 'a.example.com', type: 'A', status: 500, error: 'Internal Server Error' }],
				},
			});
		});

		it('logs every failure in a batch, not only the one it reports', async () => {
			const errorSpy = vi.spyOn(console, 'error').mockImplementation(() => {});
			mockCloudflareClient.zones.list.mockReturnValue(mockPage({ result: [{ id: 'zone1', name: 'example.com' }] }));
			mockCloudflareClient.dns.records.list.mockReturnValue(mockPage({ result: [] }));

			const request = createMockRequest('https://example.com/update?ip4=1.2.3.4&hostnames=a.example.com,b.example.com,c.example.com', {
				headers: validAuth,
			});

			await worker.fetch(request, env, ctx);

			const failureLogs = errorSpy.mock.calls.filter(([msg]) => msg === 'Record update failed:');
			expect(failureLogs).toHaveLength(3);
		});

		it('writes no audit batch when every record in the request fails', async () => {
			mockCloudflareClient.zones.list.mockReturnValue(mockPage({ result: [{ id: 'zone1', name: 'example.com' }] }));
			mockCloudflareClient.dns.records.list.mockReturnValue(mockPage({ result: [] }));

			const request = createMockRequest('https://example.com/update?ip4=1.2.3.4&hostnames=a.example.com,b.example.com', {
				headers: validAuth,
			});

			const response = await worker.fetch(request, env, ctx);

			expect(response.status).toBe(400);
			const waitUntilArgs = (waitUntilMock.mock.calls as [Promise<void>][]).map(([p]) => p);
			await Promise.allSettled(waitUntilArgs);
			// Nothing reached DNS, so there is nothing to audit.
			expect((vi.mocked(env.AUDIT_DB) as any).batch).not.toHaveBeenCalled();
		});

		it('passes one correctly-shaped audit event to AUDIT_DB.batch per record that reached DNS', async () => {
			mockCloudflareClient.zones.list.mockReturnValue(
				mockPage({
					result: [{ id: 'zone1', name: 'example.com' }],
				}),
			);
			// Previous content differs from the new IP so an update fires
			mockCloudflareClient.dns.records.list.mockReturnValue(
				mockPage({
					result: [{ id: 'r1', name: 'test.example.com', type: 'A', content: '1.2.3.0', proxied: false, ttl: 1 }],
				}),
			);
			mockCloudflareClient.dns.records.update.mockResolvedValue(undefined);

			const request = createMockRequest('https://example.com/update?ip4=1.2.3.4&hostnames=test.example.com', {
				headers: { ...validAuth, 'CF-Connecting-IP': '5.6.7.8' },
			});

			await worker.fetch(request, env, ctx);

			// Await all waitUntil promises so the batch call has been made
			const waitUntilArgs = (waitUntilMock.mock.calls as [Promise<void>][]).map(([p]) => p);
			await Promise.allSettled(waitUntilArgs);

			const auditDbMock = vi.mocked(env.AUDIT_DB) as any;
			expect(auditDbMock.batch).toHaveBeenCalledTimes(1);

			// batch receives an array of bound statements; one per record
			const [batchArg] = auditDbMock.batch.mock.calls[0] as [unknown[]];
			expect(batchArg).toHaveLength(1);

			// The statement was bound with the correct field values
			const stmtMock = auditDbMock.prepare();
			expect(stmtMock.bind).toHaveBeenCalledWith(
				expect.stringMatching(/^\d{4}-\d{2}-\d{2}T/), // occurredAt ISO string
				'token-id-123', // tokenId from verify response
				'5.6.7.8', // callerIp from CF-Connecting-IP
				'test.example.com', // hostname
				'A', // recordType
				'1.2.3.0', // previousIp from existing DNS record content
				'1.2.3.4', // newIp
				'updated', // outcome
			);
		});

		it('records outcome no-change in the audit event when DNS content already matches', async () => {
			mockCloudflareClient.zones.list.mockReturnValue(
				mockPage({
					result: [{ id: 'zone1', name: 'example.com' }],
				}),
			);
			// Content matches → no update called, but record still reached DNS API
			mockCloudflareClient.dns.records.list.mockReturnValue(
				mockPage({
					result: [{ id: 'r1', name: 'test.example.com', type: 'A', content: '1.2.3.4', proxied: false, ttl: 1 }],
				}),
			);

			const request = createMockRequest('https://example.com/update?ip4=1.2.3.4&hostnames=test.example.com', {
				headers: validAuth,
			});

			await worker.fetch(request, env, ctx);

			// Await all waitUntil promises so the audit batch has been written
			const waitUntilArgs = (waitUntilMock.mock.calls as [Promise<void>][]).map(([p]) => p);
			await Promise.allSettled(waitUntilArgs);

			const auditDbMock = vi.mocked(env.AUDIT_DB) as any;
			const stmtMock = auditDbMock.prepare();
			// Last positional argument to bind is the outcome
			const bindArgs = stmtMock.bind.mock.calls.at(-1) as unknown[];
			expect(bindArgs[7]).toBe('no-change');
		});

		it('records previousIp null when the existing DNS record has no content', async () => {
			mockCloudflareClient.zones.list.mockReturnValue(
				mockPage({
					result: [{ id: 'zone1', name: 'example.com' }],
				}),
			);
			// Record exists but carries no content; previousIp must fall back to null.
			mockCloudflareClient.dns.records.list.mockReturnValue(
				mockPage({
					result: [{ id: 'r1', name: 'test.example.com', type: 'A', proxied: false, ttl: 1 }],
				}),
			);
			mockCloudflareClient.dns.records.update.mockResolvedValue(undefined);

			const request = createMockRequest('https://example.com/update?ip4=1.2.3.4&hostnames=test.example.com', {
				headers: validAuth,
			});

			await worker.fetch(request, env, ctx);

			const waitUntilArgs = (waitUntilMock.mock.calls as [Promise<void>][]).map(([p]) => p);
			await Promise.allSettled(waitUntilArgs);

			const auditDbMock = vi.mocked(env.AUDIT_DB) as any;
			const stmtMock = auditDbMock.prepare();
			const bindArgs = stmtMock.bind.mock.calls.at(-1) as unknown[];
			// previousIp is the 6th positional bind arg (index 5).
			expect(bindArgs[5]).toBeNull();
		});
	});

	// -------------------------------------------------------------------------
	// GET /history endpoint
	// -------------------------------------------------------------------------

	describe('GET /history endpoint', () => {
		const validAuth = { Authorization: createAuthHeader('user@example.com', 'token') };

		beforeEach(() => {
			mockCloudflareClient.user.tokens.verify.mockResolvedValue({ id: 'token-id-123', status: 'active' } as any);
		});

		it.each([
			['a fractional limit', '3.7'],
			['a limit just above an integer', '1.0000001'],
		])('truncates %s rather than binding a real to LIMIT', async (_label, limit) => {
			// SQLite rejects a REAL bound to LIMIT, which surfaced as a 500 on a
			// value the caller supplied.
			const request = createMockRequest(`https://example.com/history?limit=${limit}`, { headers: validAuth });

			const response = await worker.fetch(request, env, ctx);

			expect(response.status).toBe(200);
			const bindArgs = (vi.mocked(env.AUDIT_DB) as any).prepare().bind.mock.calls.at(-1) as unknown[];
			expect(Number.isInteger(bindArgs.at(-1))).toBe(true);
		});

		it('carries the cursor and the tally on the first page', async () => {
			const auditDbMock = vi.mocked(env.AUDIT_DB) as any;
			auditDbMock.prepare().all.mockResolvedValue({
				results: Array.from({ length: 3 }, (_unused, i) => ({ id: i + 1, occurred_at: `2026-08-06T00:00:00.00${String(i)}Z` })),
			});

			const request = createMockRequest('https://example.com/history?limit=2', { headers: validAuth });
			const body = (await (await worker.fetch(request, env, ctx)).json()) as any;

			expect(body.data.cursor).toBe('2026-08-06T00:00:00.001Z|2');
			expect(body.data.refusedToday).toEqual({ total: 0, distinct: 0, hostnames: [] });
		});

		it('omits the tally on a continuation page', async () => {
			// The tally describes the day, not the page. Repeating it down a walk
			// would spend one Durable Object round trip per page to say the same
			// thing.
			const auditDbMock = vi.mocked(env.AUDIT_DB) as any;
			auditDbMock.prepare().all.mockResolvedValue({ results: [] });

			const request = createMockRequest('https://example.com/history?before=2026-08-06T00%3A00%3A01.000Z%7C2', { headers: validAuth });
			const body = (await (await worker.fetch(request, env, ctx)).json()) as any;

			expect(body.data.refusedToday).toBeNull();
			expect((vi.mocked(env.REFUSALS) as any).getByName).not.toHaveBeenCalled();
		});

		it.each([
			['a hostname with an embedded newline', 'hostname=a%0Aforged'],
			['a hostname longer than a DNS name may be', `hostname=${'a'.repeat(250)}.example.com`],
		])('rejects %s the way /update does', async (_label, query) => {
			// Unchecked, a typo answers with an empty page, which reads as
			// "nothing ever happened to that name" rather than "you asked wrong".
			const request = createMockRequest(`https://example.com/history?${query}`, { headers: validAuth });

			const response = await worker.fetch(request, env, ctx);
			const body = (await response.json()) as any;

			expect(response.status).toBe(422);
			expect(body.error).toContain('Not a valid hostname');
		});

		it('rejects a bad parameter without spending a Cloudflare API call', async () => {
			// A request no token could answer should cost nothing beyond the
			// worker invocation, which is the same bargain the access key strikes.
			const request = createMockRequest('https://example.com/history?before=garbage', { headers: validAuth });

			await worker.fetch(request, env, ctx);

			expect(mockCloudflareClient.user.tokens.verify).not.toHaveBeenCalled();
		});

		it('rejects a cursor it did not emit rather than restarting the walk', async () => {
			// Ignoring it would answer with the first page, and a client walking
			// pages would read that as a fresh start and loop over the same rows.
			const request = createMockRequest('https://example.com/history?before=garbage', { headers: validAuth });

			const response = await worker.fetch(request, env, ctx);
			const body = (await response.json()) as any;

			expect(response.status).toBe(422);
			expect(body.error).toContain("'before' parameter must be a cursor");
		});

		it('reports at most fifty refused names however many the counter holds', async () => {
			// The counter keeps up to 200 of up to 253 characters, which would put
			// 50 KiB of them on a response whose point is the audit rows.
			const stub = (vi.mocked(env.REFUSALS) as any).getByName('token-id-123');
			stub.tally.mockResolvedValue({
				total: 400,
				distinct: 200,
				hostnames: Array.from({ length: 200 }, (_unused, i) => `h${String(i)}.example.com`),
			});

			const request = createMockRequest('https://example.com/history', { headers: validAuth });
			const body = (await (await worker.fetch(request, env, ctx)).json()) as any;

			expect(body.data.refusedToday.hostnames).toHaveLength(50);
			// The true count still reaches the caller, so a truncated list never
			// reads as the whole story.
			expect(body.data.refusedToday.distinct).toBe(200);
		});

		it('returns 200 with events array using default limit of 100', async () => {
			const auditDbMock = vi.mocked(env.AUDIT_DB) as any;
			const stmtMock = auditDbMock.prepare();
			stmtMock.all.mockResolvedValue({
				results: [{ hostname: 'test.example.com', outcome: 'updated' }],
			});

			const request = createMockRequest('https://example.com/history', {
				headers: validAuth,
			});

			const response = await worker.fetch(request, env, ctx);
			const body = (await response.json()) as any;

			expect(response.status).toBe(200);
			expect(body).toMatchObject({
				success: true,
				data: { events: [{ hostname: 'test.example.com', outcome: 'updated' }] },
			});
			// token_id bound first, then limit (100) — no hostname in the middle
			expect(stmtMock.bind).toHaveBeenCalledWith('token-id-123', 101);
		});

		it('respects an explicit limit parameter', async () => {
			const auditDbMock = vi.mocked(env.AUDIT_DB) as any;
			const stmtMock = auditDbMock.prepare();
			stmtMock.all.mockResolvedValue({ results: [] });

			const request = createMockRequest('https://example.com/history?limit=25', {
				headers: validAuth,
			});

			await worker.fetch(request, env, ctx);

			expect(stmtMock.bind).toHaveBeenCalledWith('token-id-123', 26);
		});

		it('clamps limit to 1000 when the provided value exceeds the maximum', async () => {
			const auditDbMock = vi.mocked(env.AUDIT_DB) as any;
			const stmtMock = auditDbMock.prepare();
			stmtMock.all.mockResolvedValue({ results: [] });

			const request = createMockRequest('https://example.com/history?limit=9999', {
				headers: validAuth,
			});

			await worker.fetch(request, env, ctx);

			expect(stmtMock.bind).toHaveBeenCalledWith('token-id-123', 1001);
		});

		it('clamps limit to 1 when the provided value is less than 1', async () => {
			const auditDbMock = vi.mocked(env.AUDIT_DB) as any;
			const stmtMock = auditDbMock.prepare();
			stmtMock.all.mockResolvedValue({ results: [] });

			const request = createMockRequest('https://example.com/history?limit=0', {
				headers: validAuth,
			});

			await worker.fetch(request, env, ctx);

			expect(stmtMock.bind).toHaveBeenCalledWith('token-id-123', 2);
		});

		it('falls back to default limit when limit param is non-numeric', async () => {
			const auditDbMock = vi.mocked(env.AUDIT_DB) as any;
			const stmtMock = auditDbMock.prepare();
			stmtMock.all.mockResolvedValue({ results: [] });

			const request = createMockRequest('https://example.com/history?limit=banana', {
				headers: validAuth,
			});

			await worker.fetch(request, env, ctx);

			expect(stmtMock.bind).toHaveBeenCalledWith('token-id-123', 101);
		});

		it('filters by hostname when the hostname query param is provided', async () => {
			const auditDbMock = vi.mocked(env.AUDIT_DB) as any;
			const stmtMock = auditDbMock.prepare();
			stmtMock.all.mockResolvedValue({ results: [] });

			const request = createMockRequest('https://example.com/history?hostname=test.example.com', {
				headers: validAuth,
			});

			await worker.fetch(request, env, ctx);

			// When hostname is set: token_id, hostname, limit are all bound in that order
			expect(stmtMock.bind).toHaveBeenCalledWith('token-id-123', 'test.example.com', 101);
		});

		it('returns 405 for non-GET requests to /history', async () => {
			const request = createMockRequest('https://example.com/history', {
				method: 'POST',
				headers: validAuth,
			});

			const response = await worker.fetch(request, env, ctx);

			expect(response.status).toBe(405);
			const body = (await response.json()) as any;
			expect(body).toEqual({ success: false, error: 'Method not allowed.' });
		});

		it('returns 404 for unknown paths instead of treating them as updates', async () => {
			const request = createMockRequest('https://example.com/nic/update?ip4=1.2.3.4&hostnames=test.example.com', {
				headers: validAuth,
			});

			const response = await worker.fetch(request, env, ctx);

			expect(response.status).toBe(404);
			const body = (await response.json()) as any;
			expect(body).toEqual({ success: false, error: 'Not found.' });
			expect(mockCloudflareClient.user.tokens.verify).not.toHaveBeenCalled();
		});
	});

	// -------------------------------------------------------------------------
	// Response shapes  (error mapping)
	// -------------------------------------------------------------------------

	describe('Response shapes', () => {
		const validAuth = { Authorization: createAuthHeader('user@example.com', 'token') };

		it('maps HttpError to the correct status code', async () => {
			// Missing ip4/ip6 triggers a 422 HttpError from resolveIps
			const request = createMockRequest('https://example.com/update?hostnames=test.example.com', {
				headers: validAuth,
			});

			const response = await worker.fetch(request, createMockEnv(), createMockCtx().ctx);

			expect(response.status).toBe(422);
			const body = (await response.json()) as any;
			expect(body).toEqual({
				success: false,
				error: "Missing IP. Provide 'ip4' and/or 'ip6'; 'auto' uses the client IP.",
			});
		});

		it('maps unexpected errors to 500', async () => {
			mockCloudflareClient.user.tokens.verify.mockRejectedValue(new Error('Network error'));

			const request = createMockRequest('https://example.com/update?ip4=1.2.3.4&hostnames=test.example.com', {
				headers: validAuth,
			});

			const response = await worker.fetch(request, createMockEnv(), createMockCtx().ctx);

			expect(response.status).toBe(500);
			const body = (await response.json()) as any;
			expect(body).toEqual({
				success: false,
				error: 'Internal Server Error',
			});
		});

		it('maps Cloudflare API errors to 500', async () => {
			mockCloudflareClient.user.tokens.verify.mockResolvedValue({ id: 'tid', status: 'active' } as any);
			mockCloudflareClient.zones.list.mockRejectedValue(new Error('API rate limit exceeded'));

			const request = createMockRequest('https://example.com/update?ip4=1.2.3.4&hostnames=test.example.com', {
				headers: validAuth,
			});

			const response = await worker.fetch(request, createMockEnv(), createMockCtx().ctx);

			expect(response.status).toBe(500);
			const body = (await response.json()) as any;
			expect(body).toEqual({
				success: false,
				error: 'Internal Server Error',
			});
		});

		it('success responses do not include a previousIp field', async () => {
			mockCloudflareClient.user.tokens.verify.mockResolvedValue({ id: 'tid', status: 'active' } as any);
			(vi.mocked(env.DDNS_KV) as any).get.mockResolvedValue(null);
			(vi.mocked(env.DDNS_KV) as any).put.mockResolvedValue(undefined);

			mockCloudflareClient.zones.list.mockReturnValue(
				mockPage({
					result: [{ id: 'zone1', name: 'example.com' }],
				}),
			);
			mockCloudflareClient.dns.records.list.mockReturnValue(
				mockPage({
					result: [{ id: 'r1', name: 'test.example.com', type: 'A', content: '1.2.3.0', proxied: false, ttl: 1 }],
				}),
			);
			mockCloudflareClient.dns.records.update.mockResolvedValue(undefined);

			const request = createMockRequest('https://example.com/update?ip4=1.2.3.4&hostnames=test.example.com', {
				headers: validAuth,
			});

			const response = await worker.fetch(request, env, ctx);
			const body = (await response.json()) as any;

			expect(body.data).not.toHaveProperty('previousIp');
		});
	});

	// -------------------------------------------------------------------------
	// Full update flow  (integration + edge cases)
	// -------------------------------------------------------------------------

	describe('Full update flow', () => {
		it('completes full pipeline with IP change detection, DNS update, KV storage, and notification', async () => {
			const { pushNtfy } = await import('../src/pushNtfy');
			const pushNtfyMock = vi.mocked(pushNtfy);
			const validAuth = { Authorization: createAuthHeader('user@example.com', 'token') };

			const kvMock = vi.mocked(env.DDNS_KV) as any;
			// Old KV entry with different IP (cache miss by IP value)
			kvMock.get.mockResolvedValue(JSON.stringify({ ip: '1.2.3.4', updatedAt: '2024-01-01T00:00:00.000Z' }));
			kvMock.put.mockResolvedValue(undefined);

			mockCloudflareClient.user.tokens.verify.mockResolvedValue({ id: 'token-id-123', status: 'active' } as any);
			mockCloudflareClient.zones.list.mockReturnValue(
				mockPage({
					result: [{ id: 'zone1', name: 'example.com' }],
				}),
			);
			mockCloudflareClient.dns.records.list.mockReturnValue(
				mockPage({
					result: [
						{ id: 'record1', name: 'test.example.com', type: 'A', content: '1.2.3.4', proxied: true, comment: 'Managed by DDNS', ttl: 300 },
					],
				}),
			);
			mockCloudflareClient.dns.records.update.mockResolvedValue(undefined);

			const request = createMockRequest('https://example.com/update?ip4=1.2.3.5&hostnames=test.example.com', {
				headers: validAuth,
			});

			const response = await worker.fetch(request, env, ctx);

			expect(response.status).toBe(200);
			const body = (await response.json()) as any;
			expect(body).toEqual({
				success: true,
				message: 'DNS records updated successfully',
				data: {
					updated: true,
					records: [{ hostname: 'test.example.com', type: 'A', ip: '1.2.3.5', updated: true }],
				},
			});

			// Verify all pipeline steps ran
			expect(kvMock.get).toHaveBeenCalledWith('ip:token-id-123:test.example.com:A');
			expect(mockCloudflareClient.user.tokens.verify).toHaveBeenCalled();
			expect(mockCloudflareClient.zones.list).toHaveBeenCalled();
			expect(mockCloudflareClient.dns.records.list).toHaveBeenCalled();
			expect(mockCloudflareClient.dns.records.update).toHaveBeenCalled();
			expect(kvMock.put).toHaveBeenCalledWith('ip:token-id-123:test.example.com:A', expect.any(String), { expirationTtl: 2592000 });
			expect(waitUntilMock).toHaveBeenCalled();

			// pushNtfy called after resolving waitUntil promises
			const waitUntilArgs = (waitUntilMock.mock.calls as [Promise<void>][]).map(([p]) => p);
			await Promise.allSettled(waitUntilArgs);
			expect(pushNtfyMock).toHaveBeenCalled();
		});

		it('Bearer raw-token happy path: full update succeeds', async () => {
			const { pushNtfy } = await import('../src/pushNtfy');
			const pushNtfyMock = vi.mocked(pushNtfy);

			const kvMock = vi.mocked(env.DDNS_KV) as any;
			kvMock.get.mockResolvedValue(null);
			kvMock.put.mockResolvedValue(undefined);

			wireStandardHappyPath(mockCloudflareClient);

			const request = createMockRequest('https://example.com/update?ip4=10.0.0.1&hostnames=test.example.com', {
				headers: { Authorization: createBearerHeader('my-raw-api-token') },
			});

			const response = await worker.fetch(request, env, ctx);

			expect(response.status).toBe(200);
			expect(vi.mocked(Cloudflare)).toHaveBeenCalledWith(expect.objectContaining({ apiToken: 'my-raw-api-token' }));
			const body = (await response.json()) as any;
			expect(body.success).toBe(true);

			const waitUntilArgs = (waitUntilMock.mock.calls as [Promise<void>][]).map(([p]) => p);
			await Promise.allSettled(waitUntilArgs);
			expect(pushNtfyMock).toHaveBeenCalledTimes(1);
		});

		it('returns 422 and skips KV storage when ip4 param is empty string', async () => {
			const request = createMockRequest('https://example.com/update?ip4=&hostnames=test.example.com', {
				headers: { Authorization: createAuthHeader('user@example.com', 'api-token') },
			});

			const response = await worker.fetch(request, env, ctx);

			expect(response.status).toBe(422);
			const body = (await response.json()) as any;
			expect(body).toEqual({
				success: false,
				error: "Missing IP. Provide 'ip4' and/or 'ip6'; 'auto' uses the client IP.",
			});
		});

		it('ip4 + ip6 both literal: 2 hostnames produce 4 records in the response', async () => {
			const { pushNtfy } = await import('../src/pushNtfy');
			const pushNtfyMock = vi.mocked(pushNtfy);

			const kvMock = vi.mocked(env.DDNS_KV) as any;
			kvMock.get.mockResolvedValue(null);
			kvMock.put.mockResolvedValue(undefined);

			mockCloudflareClient.user.tokens.verify.mockResolvedValue({ id: 'token-id-123', status: 'active' } as any);
			mockCloudflareClient.zones.list.mockReturnValue(
				mockPage({
					result: [{ id: 'zone1', name: 'example.com' }],
				}),
			);

			// A for h1, AAAA for h1, A for h2, AAAA for h2
			mockCloudflareClient.dns.records.list
				.mockReturnValueOnce(
					mockPage({ result: [{ id: 'r1', name: 'h1.example.com', type: 'A', content: '0.0.0.0', proxied: false, ttl: 1 }] }),
				)
				.mockReturnValueOnce(
					mockPage({ result: [{ id: 'r2', name: 'h1.example.com', type: 'AAAA', content: '::', proxied: false, ttl: 1 }] }),
				)
				.mockReturnValueOnce(
					mockPage({ result: [{ id: 'r3', name: 'h2.example.com', type: 'A', content: '0.0.0.0', proxied: false, ttl: 1 }] }),
				)
				.mockReturnValueOnce(
					mockPage({ result: [{ id: 'r4', name: 'h2.example.com', type: 'AAAA', content: '::', proxied: false, ttl: 1 }] }),
				);
			mockCloudflareClient.dns.records.update.mockResolvedValue(undefined);

			const request = createMockRequest('https://example.com/update?ip4=1.2.3.4&ip6=2001:db8::1&hostnames=h1.example.com,h2.example.com', {
				headers: { Authorization: createAuthHeader('user', 'token') },
			});

			const response = await worker.fetch(request, env, ctx);
			const body = (await response.json()) as any;

			expect(response.status).toBe(200);
			expect(body.data.records).toHaveLength(4);
			const types = (body.data.records as any[]).map((r: any) => r.type as string);
			expect(types.filter((t) => t === 'A')).toHaveLength(2);
			expect(types.filter((t) => t === 'AAAA')).toHaveLength(2);
			expect(mockCloudflareClient.dns.records.list).toHaveBeenCalledTimes(4);

			const waitUntilArgs = (waitUntilMock.mock.calls as [Promise<void>][]).map(([p]) => p);
			await Promise.allSettled(waitUntilArgs);
			expect(pushNtfyMock).toHaveBeenCalledTimes(1);
		});
	});
});
