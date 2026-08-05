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
const { MockAPIError, MockBadRequestError, MockAuthenticationError, MockPermissionDeniedError, MockInternalServerError } = vi.hoisted(
	() => {
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
		return { MockAPIError, MockBadRequestError, MockAuthenticationError, MockPermissionDeniedError, MockInternalServerError };
	},
);

// src/index.ts narrows auth failures with `instanceof` against the SDK's error
// classes, so the mocked module must export real classes for those names.
vi.mock('cloudflare', () => ({
	Cloudflare: vi.fn(),
	APIError: MockAPIError,
	BadRequestError: MockBadRequestError,
	AuthenticationError: MockAuthenticationError,
	PermissionDeniedError: MockPermissionDeniedError,
	InternalServerError: MockInternalServerError,
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

		it('uses client IPv4 when ip4=auto and CF-Connecting-IP contains a dot', async () => {
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
		it('skips zone listing and tokens.verify when ALL records match cached IPs (gate on)', async () => {
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
			expect(mockCloudflareClient.zones.list).not.toHaveBeenCalled();
			// Gate is on: verify must NOT be called on a full cache hit
			expect(mockCloudflareClient.user.tokens.verify).not.toHaveBeenCalled();
		});

		it('uses cache key ip:<hostname>:<type>', async () => {
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

			expect(kvMock.get).toHaveBeenCalledWith('ip:test.example.com:A');
			expect(kvMock.put).toHaveBeenCalledWith('ip:test.example.com:A', expect.any(String), { expirationTtl: 2592000 });
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
			expect(stmtMock.bind).toHaveBeenCalledWith('token-id-123', 100);
		});

		it('respects an explicit limit parameter', async () => {
			const auditDbMock = vi.mocked(env.AUDIT_DB) as any;
			const stmtMock = auditDbMock.prepare();
			stmtMock.all.mockResolvedValue({ results: [] });

			const request = createMockRequest('https://example.com/history?limit=25', {
				headers: validAuth,
			});

			await worker.fetch(request, env, ctx);

			expect(stmtMock.bind).toHaveBeenCalledWith('token-id-123', 25);
		});

		it('clamps limit to 1000 when the provided value exceeds the maximum', async () => {
			const auditDbMock = vi.mocked(env.AUDIT_DB) as any;
			const stmtMock = auditDbMock.prepare();
			stmtMock.all.mockResolvedValue({ results: [] });

			const request = createMockRequest('https://example.com/history?limit=9999', {
				headers: validAuth,
			});

			await worker.fetch(request, env, ctx);

			expect(stmtMock.bind).toHaveBeenCalledWith('token-id-123', 1000);
		});

		it('clamps limit to 1 when the provided value is less than 1', async () => {
			const auditDbMock = vi.mocked(env.AUDIT_DB) as any;
			const stmtMock = auditDbMock.prepare();
			stmtMock.all.mockResolvedValue({ results: [] });

			const request = createMockRequest('https://example.com/history?limit=0', {
				headers: validAuth,
			});

			await worker.fetch(request, env, ctx);

			expect(stmtMock.bind).toHaveBeenCalledWith('token-id-123', 1);
		});

		it('falls back to default limit when limit param is non-numeric', async () => {
			const auditDbMock = vi.mocked(env.AUDIT_DB) as any;
			const stmtMock = auditDbMock.prepare();
			stmtMock.all.mockResolvedValue({ results: [] });

			const request = createMockRequest('https://example.com/history?limit=banana', {
				headers: validAuth,
			});

			await worker.fetch(request, env, ctx);

			expect(stmtMock.bind).toHaveBeenCalledWith('token-id-123', 100);
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
			expect(stmtMock.bind).toHaveBeenCalledWith('token-id-123', 'test.example.com', 100);
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
			expect(kvMock.get).toHaveBeenCalledWith('ip:test.example.com:A');
			expect(mockCloudflareClient.user.tokens.verify).toHaveBeenCalled();
			expect(mockCloudflareClient.zones.list).toHaveBeenCalled();
			expect(mockCloudflareClient.dns.records.list).toHaveBeenCalled();
			expect(mockCloudflareClient.dns.records.update).toHaveBeenCalled();
			expect(kvMock.put).toHaveBeenCalledWith('ip:test.example.com:A', expect.any(String), { expirationTtl: 2592000 });
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
