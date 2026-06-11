import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import worker, { HttpError } from '../src/index';
import {
	createMockCloudflareClient,
	createMockEnv,
	createMockRequest,
	createAuthHeader,
	createBearerHeader,
	wireStandardHappyPath,
} from './helpers/mocks';
import { Cloudflare } from 'cloudflare';

// Mock the Cloudflare SDK
vi.mock('cloudflare', () => ({
	Cloudflare: vi.fn(),
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
	let mockCloudflareClient: ReturnType<typeof createMockCloudflareClient>;

	beforeEach(() => {
		env = createMockEnv();
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
	// Auth parsing  (constructClientOptions)
	// -------------------------------------------------------------------------

	describe('Auth parsing', () => {
		it('accepts Basic credentials and constructs SDK with apiToken only (no apiEmail)', async () => {
			mockCloudflareClient.user.tokens.verify.mockResolvedValue({ status: 'active' } as any);
			mockCloudflareClient.zones.list.mockResolvedValue({ result: [] } as any);

			const request = createMockRequest('https://example.com/update?ip4=1.2.3.4&hostnames=test.example.com', {
				headers: { Authorization: createAuthHeader('user@example.com', 'valid-token') },
			});

			const response = await worker.fetch(request, env);

			// Fails with 'No zones available' but confirms auth passed and Cloudflare
			// was initialised with apiToken only (username portion is discarded).
			expect(response.status).toBe(400);
			expect(vi.mocked(Cloudflare)).toHaveBeenCalledWith({
				apiToken: 'valid-token',
			});
			// apiEmail must never be passed
			expect(vi.mocked(Cloudflare)).not.toHaveBeenCalledWith(expect.objectContaining({ apiEmail: expect.anything() }));
		});

		it('accepts Basic credentials with a non-email username (username is ignored)', async () => {
			mockCloudflareClient.user.tokens.verify.mockResolvedValue({ status: 'active' } as any);
			mockCloudflareClient.zones.list.mockResolvedValue({ result: [] } as any);

			const request = createMockRequest('https://example.com/update?ip4=1.2.3.4&hostnames=test.example.com', {
				headers: { Authorization: createAuthHeader('somedevice', 'mytoken') },
			});

			const response = await worker.fetch(request, env);

			expect(response.status).toBe(400);
			expect(vi.mocked(Cloudflare)).toHaveBeenCalledWith({ apiToken: 'mytoken' });
		});

		it('accepts Bearer raw-token and constructs SDK with that token directly', async () => {
			mockCloudflareClient.user.tokens.verify.mockResolvedValue({ status: 'active' } as any);
			mockCloudflareClient.zones.list.mockResolvedValue({ result: [] } as any);

			const request = createMockRequest('https://example.com/update?ip4=1.2.3.4&hostnames=test.example.com', {
				headers: { Authorization: createBearerHeader('raw-api-token') },
			});

			const response = await worker.fetch(request, env);

			expect(response.status).toBe(400);
			expect(vi.mocked(Cloudflare)).toHaveBeenCalledWith({ apiToken: 'raw-api-token' });
		});

		it('rejects request without Authorization header', async () => {
			const request = createMockRequest('https://example.com/update?ip4=1.2.3.4&hostnames=test.example.com');

			const response = await worker.fetch(request, env);

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

			const response = await worker.fetch(request, env);

			expect(response.status).toBe(401);
			const body = (await response.json()) as any;
			expect(body).toEqual({ success: false, error: 'Authorization required.' });
		});

		it('rejects request with unknown scheme', async () => {
			const request = createMockRequest('https://example.com/update?ip4=1.2.3.4&hostnames=test.example.com', {
				headers: { Authorization: 'Digest abc123' },
			});

			const response = await worker.fetch(request, env);

			expect(response.status).toBe(401);
			const body = (await response.json()) as any;
			expect(body).toEqual({ success: false, error: 'Invalid authorization credentials.' });
		});

		it('rejects request with scheme only (missing payload)', async () => {
			const request = createMockRequest('https://example.com/update?ip4=1.2.3.4&hostnames=test.example.com', {
				headers: { Authorization: 'Basic' },
			});

			const response = await worker.fetch(request, env);

			expect(response.status).toBe(401);
			const body = (await response.json()) as any;
			expect(body).toEqual({ success: false, error: 'Invalid authorization credentials.' });
		});

		it('rejects request with empty Bearer token', async () => {
			const request = createMockRequest('https://example.com/update?ip4=1.2.3.4&hostnames=test.example.com', {
				headers: { Authorization: 'Bearer ' },
			});

			const response = await worker.fetch(request, env);

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

			const response = await worker.fetch(request, env);

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

			const response = await worker.fetch(request, env);

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

			const response = await worker.fetch(request, env);

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

			const response = await worker.fetch(request, env);

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

			const response = await worker.fetch(request, createMockEnv());

			expect(response.status).toBe(401);
		});

		it('applies auth check to POST requests', async () => {
			const request = createMockRequest('https://example.com/update', {
				method: 'POST',
				headers: { 'CF-Connecting-IP': '203.0.113.1' },
				body: JSON.stringify({ test: 'data' }),
			});

			const response = await worker.fetch(request, createMockEnv());

			expect(response.status).toBe(401);
		});

		it('applies auth check to HEAD requests', async () => {
			const request = createMockRequest('https://example.com/update', {
				method: 'HEAD',
				headers: { 'CF-Connecting-IP': '203.0.113.1' },
			});

			const response = await worker.fetch(request, createMockEnv());

			expect(response.status).toBe(401);
		});
	});

	// -------------------------------------------------------------------------
	// DNS record construction  (constructDNSRecords / resolveIps param validation)
	// -------------------------------------------------------------------------

	describe('DNS record construction', () => {
		const validAuth = { Authorization: createAuthHeader('user@example.com', 'token') };

		beforeEach(() => {
			mockCloudflareClient.user.tokens.verify.mockResolvedValue({ status: 'active' } as any);
		});

		it('uses client IPv4 when ip4=auto and CF-Connecting-IP contains a dot', async () => {
			mockCloudflareClient.zones.list.mockResolvedValue({ result: [] } as any);

			const request = createMockRequest('https://example.com/update?ip4=auto&hostnames=test.example.com', {
				headers: { ...validAuth, 'CF-Connecting-IP': '203.0.113.1' },
			});

			const response = await worker.fetch(request, env);

			// Fails with 'No zones available' but confirms IP was resolved and
			// zones.list was reached (auth + param parsing both passed).
			expect(response.status).toBe(400);
		});

		it('ip4=auto when client connected over IPv6 with ip6=auto also set produces only AAAA records', async () => {
			mockCloudflareClient.zones.list.mockResolvedValue({
				result: [{ id: 'zone1', name: 'example.com' }],
			} as any);
			mockCloudflareClient.dns.records.list.mockResolvedValue({
				result: [{ id: 'r1', name: 'test.example.com', type: 'AAAA', content: '::', proxied: false, ttl: 1 }],
			} as any);
			mockCloudflareClient.dns.records.update.mockResolvedValue(undefined);
			(vi.mocked(env.DDNS_KV) as any).get.mockResolvedValue(null);
			(vi.mocked(env.DDNS_KV) as any).put.mockResolvedValue(undefined);

			// CF-Connecting-IP is an IPv6 address: ip4=auto slot is silently skipped,
			// ip6=auto slot picks up the address.
			const request = createMockRequest('https://example.com/update?ip4=auto&ip6=auto&hostnames=test.example.com', {
				headers: { ...validAuth, 'CF-Connecting-IP': '2001:db8::1' },
			});

			const response = await worker.fetch(request, env);
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

			const response = await worker.fetch(request, env);

			expect(response.status).toBe(422);
			const body = (await response.json()) as any;
			expect(body).toEqual({
				success: false,
				error: "Missing IP. Provide 'ip4' and/or 'ip6'; 'auto' uses the client IP.",
			});
		});

		it('ip6=auto when client connected over IPv4 silently skips AAAA and falls through to ip4 only', async () => {
			mockCloudflareClient.zones.list.mockResolvedValue({ result: [] } as any);

			// CF-Connecting-IP is IPv4: ip6=auto slot is silently skipped,
			// ip4 literal is resolved, zones.list is reached.
			const request = createMockRequest('https://example.com/update?ip4=1.2.3.4&ip6=auto&hostnames=test.example.com', {
				headers: { ...validAuth, 'CF-Connecting-IP': '203.0.113.1' },
			});

			const response = await worker.fetch(request, env);

			// Fails with 'No zones available' but confirms ip4 resolved and proceeded.
			expect(response.status).toBe(400);
			expect(mockCloudflareClient.zones.list).toHaveBeenCalled();
		});

		it('rejects ip4 literal that contains a colon (not a valid IPv4 address)', async () => {
			const request = createMockRequest('https://example.com/update?ip4=2001:db8::1&hostnames=test.example.com', {
				headers: validAuth,
			});

			const response = await worker.fetch(request, env);

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

			const response = await worker.fetch(request, env);

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

			const response = await worker.fetch(request, env);

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

			const response = await worker.fetch(request, env);

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

			const response = await worker.fetch(request, env);

			expect(response.status).toBe(422);
			const body = (await response.json()) as any;
			expect(body).toEqual({
				success: false,
				error: 'No hostnames provided.',
			});
		});

		it('trims whitespace from ip4 parameter', async () => {
			mockCloudflareClient.zones.list.mockResolvedValue({
				result: [{ id: 'zone1', name: 'example.com' }],
			} as any);
			mockCloudflareClient.dns.records.list.mockResolvedValue({ result: [] } as any);

			const request = createMockRequest('https://example.com/update?ip4=%20%201.2.3.4%20&hostnames=test.example.com', {
				headers: validAuth,
			});

			await worker.fetch(request, env);

			// The A-record lookup ran with the trimmed address
			expect(mockCloudflareClient.dns.records.list).toHaveBeenCalledWith(expect.objectContaining({ name: 'test.example.com', type: 'A' }));
		});

		it('detects IPv4 address and queries for A record', async () => {
			mockCloudflareClient.zones.list.mockResolvedValue({
				result: [{ id: 'zone1', name: 'example.com' }],
			} as any);
			mockCloudflareClient.dns.records.list.mockResolvedValue({ result: [] } as any);

			const request = createMockRequest('https://example.com/update?ip4=192.168.1.1&hostnames=test.example.com', {
				headers: validAuth,
			});

			await worker.fetch(request, env);

			expect(mockCloudflareClient.dns.records.list).toHaveBeenCalledWith({
				zone_id: 'zone1',
				name: 'test.example.com',
				type: 'A',
			});
		});

		it('ip6-only request (no ip4) produces only AAAA records', async () => {
			mockCloudflareClient.zones.list.mockResolvedValue({
				result: [{ id: 'zone1', name: 'example.com' }],
			} as any);
			mockCloudflareClient.dns.records.list.mockResolvedValue({
				result: [{ id: 'r1', name: 'test.example.com', type: 'AAAA', content: '::', proxied: false, ttl: 1 }],
			} as any);
			mockCloudflareClient.dns.records.update.mockResolvedValue(undefined);
			(vi.mocked(env.DDNS_KV) as any).get.mockResolvedValue(null);
			(vi.mocked(env.DDNS_KV) as any).put.mockResolvedValue(undefined);

			const request = createMockRequest('https://example.com/update?ip6=2001:db8::1&hostnames=test.example.com', {
				headers: validAuth,
			});

			const response = await worker.fetch(request, env);
			const body = (await response.json()) as any;

			expect(response.status).toBe(200);
			expect(body.data.records).toHaveLength(1);
			expect(body.data.records[0]).toMatchObject({ type: 'AAAA', ip: '2001:db8::1' });
			expect(mockCloudflareClient.dns.records.list).toHaveBeenCalledWith(expect.objectContaining({ type: 'AAAA' }));
		});

		it('handles multiple hostnames separated by commas', async () => {
			mockCloudflareClient.zones.list.mockResolvedValue({
				result: [{ id: 'zone1', name: 'example.com' }],
			} as any);
			mockCloudflareClient.dns.records.list.mockResolvedValue({ result: [] } as any);

			const request = createMockRequest('https://example.com/update?ip4=1.2.3.4&hostnames=test1.example.com,test2.example.com', {
				headers: validAuth,
			});

			const response = await worker.fetch(request, env);

			// Fails with 'No matching record found' for the first hostname, but
			// confirms the comma-separated list was parsed and the first lookup ran.
			expect(response.status).toBe(400);
			expect(mockCloudflareClient.dns.records.list).toHaveBeenCalledTimes(1);
		});

		it('adds an AAAA record per hostname when ip6 is provided alongside ip4', async () => {
			mockCloudflareClient.zones.list.mockResolvedValue({
				result: [{ id: 'zone1', name: 'example.com' }],
			} as any);

			// A for h1, AAAA for h1, A for h2, AAAA for h2
			mockCloudflareClient.dns.records.list
				.mockResolvedValueOnce({
					result: [{ id: 'r1', name: 'h1.example.com', type: 'A', content: '1.2.3.0', proxied: false, ttl: 1 }],
				} as any)
				.mockResolvedValueOnce({
					result: [{ id: 'r2', name: 'h1.example.com', type: 'AAAA', content: '::1', proxied: false, ttl: 1 }],
				} as any)
				.mockResolvedValueOnce({
					result: [{ id: 'r3', name: 'h2.example.com', type: 'A', content: '1.2.3.0', proxied: false, ttl: 1 }],
				} as any)
				.mockResolvedValueOnce({
					result: [{ id: 'r4', name: 'h2.example.com', type: 'AAAA', content: '::1', proxied: false, ttl: 1 }],
				} as any);
			mockCloudflareClient.dns.records.update.mockResolvedValue(undefined);
			(vi.mocked(env.DDNS_KV) as any).get.mockResolvedValue(null);
			(vi.mocked(env.DDNS_KV) as any).put.mockResolvedValue(undefined);

			const request = createMockRequest('https://example.com/update?ip4=1.2.3.4&ip6=2001:db8::1&hostnames=h1.example.com,h2.example.com', {
				headers: validAuth,
			});

			const response = await worker.fetch(request, env);
			const body = (await response.json()) as any;

			expect(response.status).toBe(200);
			// 2 A records + 2 AAAA records = 4 entries
			expect(body.data.records).toHaveLength(4);
			// All four DNS record lookups ran
			expect(mockCloudflareClient.dns.records.list).toHaveBeenCalledTimes(4);
		});
	});

	// -------------------------------------------------------------------------
	// Token verification
	// -------------------------------------------------------------------------

	describe('Token verification', () => {
		const validAuth = { Authorization: createAuthHeader('user@example.com', 'token') };

		it('accepts an active token', async () => {
			mockCloudflareClient.user.tokens.verify.mockResolvedValue({ status: 'active' } as any);
			mockCloudflareClient.zones.list.mockResolvedValue({ result: [] } as any);

			const request = createMockRequest('https://example.com/update?ip4=1.2.3.4&hostnames=test.example.com', {
				headers: validAuth,
			});

			await worker.fetch(request, env);

			// Fails with 'No zones available' but confirms token.verify was called
			expect(mockCloudflareClient.user.tokens.verify).toHaveBeenCalled();
		});

		it('rejects an inactive token', async () => {
			mockCloudflareClient.user.tokens.verify.mockResolvedValue({ status: 'expired' } as any);

			const request = createMockRequest('https://example.com/update?ip4=1.2.3.4&hostnames=test.example.com', {
				headers: validAuth,
			});

			const response = await worker.fetch(request, env);

			expect(response.status).toBe(401);
			const body = (await response.json()) as any;
			expect(body).toEqual({
				success: false,
				error: 'Authentication failed: token expired',
			});
		});
	});

	// -------------------------------------------------------------------------
	// KV cache  (read / write / fast-path)
	// -------------------------------------------------------------------------

	describe('KV cache', () => {
		const validAuth = { Authorization: createAuthHeader('user@example.com', 'token') };

		beforeEach(() => {
			mockCloudflareClient.user.tokens.verify.mockResolvedValue({ status: 'active' } as any);
		});

		it('skips zone listing and returns 200 when ALL records match their cached IPs', async () => {
			const kvMock = vi.mocked(env.DDNS_KV) as any;
			// Cache contains a JSON entry with matching IP
			kvMock.get.mockResolvedValue(JSON.stringify({ ip: '1.2.3.4', updatedAt: '2024-01-01T00:00:00.000Z' }));

			const request = createMockRequest('https://example.com/update?ip4=1.2.3.4&hostnames=test.example.com', {
				headers: validAuth,
			});

			const response = await worker.fetch(request, env);

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
		});

		it('uses cache key ip:<hostname>:<type>', async () => {
			const kvMock = vi.mocked(env.DDNS_KV) as any;
			kvMock.get.mockResolvedValue(null);
			kvMock.put.mockResolvedValue(undefined);

			mockCloudflareClient.zones.list.mockResolvedValue({
				result: [{ id: 'zone1', name: 'example.com' }],
			} as any);
			mockCloudflareClient.dns.records.list.mockResolvedValue({
				result: [{ id: 'r1', name: 'test.example.com', type: 'A', content: '1.2.3.0', proxied: false, ttl: 1 }],
			} as any);
			mockCloudflareClient.dns.records.update.mockResolvedValue(undefined);

			const request = createMockRequest('https://example.com/update?ip4=1.2.3.4&hostnames=test.example.com', {
				headers: validAuth,
			});

			await worker.fetch(request, env);

			expect(kvMock.get).toHaveBeenCalledWith('ip:test.example.com:A');
			expect(kvMock.put).toHaveBeenCalledWith('ip:test.example.com:A', expect.any(String), { expirationTtl: 2592000 });
		});

		it('writes JSON {ip, updatedAt} to KV with expirationTtl 2592000', async () => {
			const kvMock = vi.mocked(env.DDNS_KV) as any;
			kvMock.get.mockResolvedValue(null);
			kvMock.put.mockResolvedValue(undefined);

			mockCloudflareClient.zones.list.mockResolvedValue({
				result: [{ id: 'zone1', name: 'example.com' }],
			} as any);
			mockCloudflareClient.dns.records.list.mockResolvedValue({
				result: [{ id: 'r1', name: 'test.example.com', type: 'A', content: '1.2.3.0', proxied: false, ttl: 1 }],
			} as any);
			mockCloudflareClient.dns.records.update.mockResolvedValue(undefined);

			const request = createMockRequest('https://example.com/update?ip4=1.2.3.4&hostnames=test.example.com', {
				headers: validAuth,
			});

			await worker.fetch(request, env);

			const [, rawValue, putOptions] = kvMock.put.mock.calls[0];
			const parsed = JSON.parse(rawValue) as { ip: string; updatedAt: string };
			expect(parsed.ip).toBe('1.2.3.4');
			expect(typeof parsed.updatedAt).toBe('string');
			expect(putOptions).toEqual({ expirationTtl: 2592000 });
		});

		it('treats malformed cached JSON as a cache miss and proceeds', async () => {
			const kvMock = vi.mocked(env.DDNS_KV) as any;
			kvMock.get.mockResolvedValue('not-json-at-all');

			mockCloudflareClient.zones.list.mockResolvedValue({ result: [] } as any);

			const request = createMockRequest('https://example.com/update?ip4=1.2.3.4&hostnames=test.example.com', {
				headers: validAuth,
			});

			const response = await worker.fetch(request, env);

			// Proceeded past the cache miss and reached zone listing
			expect(mockCloudflareClient.zones.list).toHaveBeenCalled();
			expect(response.status).toBe(400);
		});

		it('treats a KV read error as a cache miss and proceeds', async () => {
			const kvMock = vi.mocked(env.DDNS_KV) as any;
			kvMock.get.mockRejectedValue(new Error('KV read error'));

			mockCloudflareClient.zones.list.mockResolvedValue({ result: [] } as any);

			const request = createMockRequest('https://example.com/update?ip4=1.2.3.4&hostnames=test.example.com', {
				headers: validAuth,
			});

			const response = await worker.fetch(request, env);

			expect(mockCloudflareClient.zones.list).toHaveBeenCalled();
			expect(response.status).toBe(400);
		});

		it('returns 200 and DNS update still succeeds when KV put throws', async () => {
			const kvMock = vi.mocked(env.DDNS_KV) as any;
			kvMock.get.mockResolvedValue(null);
			kvMock.put.mockRejectedValue(new Error('KV write error'));

			mockCloudflareClient.zones.list.mockResolvedValue({
				result: [{ id: 'zone1', name: 'example.com' }],
			} as any);
			mockCloudflareClient.dns.records.list.mockResolvedValue({
				result: [{ id: 'r1', name: 'test.example.com', type: 'A', content: '1.2.3.0', proxied: false, ttl: 300 }],
			} as any);
			mockCloudflareClient.dns.records.update.mockResolvedValue(undefined);

			const request = createMockRequest('https://example.com/update?ip4=1.2.3.4&hostnames=test.example.com', {
				headers: validAuth,
			});

			const response = await worker.fetch(request, env);

			expect(response.status).toBe(200);
			expect(mockCloudflareClient.dns.records.update).toHaveBeenCalled();
		});

		it('proceeds to update when cached IP differs from requested IP', async () => {
			const kvMock = vi.mocked(env.DDNS_KV) as any;
			kvMock.get.mockResolvedValue(JSON.stringify({ ip: '1.2.3.3', updatedAt: '2024-01-01T00:00:00.000Z' }));

			mockCloudflareClient.zones.list.mockResolvedValue({ result: [] } as any);

			const request = createMockRequest('https://example.com/update?ip4=1.2.3.4&hostnames=test.example.com', {
				headers: validAuth,
			});

			await worker.fetch(request, env);

			// Proceeded past the cache check
			expect(mockCloudflareClient.zones.list).toHaveBeenCalled();
		});

		it('proceeds to update when no cache entry exists', async () => {
			const kvMock = vi.mocked(env.DDNS_KV) as any;
			kvMock.get.mockResolvedValue(null);

			mockCloudflareClient.zones.list.mockResolvedValue({ result: [] } as any);

			const request = createMockRequest('https://example.com/update?ip4=1.2.3.4&hostnames=test.example.com', {
				headers: validAuth,
			});

			await worker.fetch(request, env);

			expect(mockCloudflareClient.zones.list).toHaveBeenCalled();
		});

		it('handles partial cache: cached hostname skipped, pending hostname fetches DNS', async () => {
			const kvMock = vi.mocked(env.DDNS_KV) as any;
			// First hostname cached and matching; second hostname not cached
			kvMock.get
				.mockResolvedValueOnce(JSON.stringify({ ip: '1.2.3.4', updatedAt: '2024-01-01T00:00:00.000Z' }))
				.mockResolvedValueOnce(null);
			kvMock.put.mockResolvedValue(undefined);

			mockCloudflareClient.zones.list.mockResolvedValue({
				result: [{ id: 'zone1', name: 'example.com' }],
			} as any);
			mockCloudflareClient.dns.records.list.mockResolvedValue({
				result: [{ id: 'r2', name: 'h2.example.com', type: 'A', content: '1.2.3.0', proxied: false, ttl: 1 }],
			} as any);
			mockCloudflareClient.dns.records.update.mockResolvedValue(undefined);

			const request = createMockRequest('https://example.com/update?ip4=1.2.3.4&hostnames=h1.example.com,h2.example.com', {
				headers: validAuth,
			});

			const response = await worker.fetch(request, env);
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
	// Zone and record matching
	// -------------------------------------------------------------------------

	describe('Zone and record matching', () => {
		const validAuth = { Authorization: createAuthHeader('user@example.com', 'token') };

		beforeEach(() => {
			mockCloudflareClient.user.tokens.verify.mockResolvedValue({ status: 'active' } as any);
			(vi.mocked(env.DDNS_KV) as any).get.mockResolvedValue(null);
		});

		it('searches across multiple zones and updates record in matching zone', async () => {
			mockCloudflareClient.zones.list.mockResolvedValue({
				result: [
					{ id: 'zone1', name: 'example.com' },
					{ id: 'zone2', name: 'test.com' },
				],
			} as any);

			// First zone has no match; second zone does
			mockCloudflareClient.dns.records.list.mockResolvedValueOnce({ result: [] } as any);
			mockCloudflareClient.dns.records.list.mockResolvedValueOnce({
				result: [
					{
						id: 'record1',
						name: 'sub.test.com',
						type: 'A',
						content: '1.2.3.4',
					},
				],
			} as any);

			mockCloudflareClient.dns.records.update.mockResolvedValue(undefined);

			const request = createMockRequest('https://example.com/update?ip4=1.2.3.5&hostnames=sub.test.com', {
				headers: validAuth,
			});

			const response = await worker.fetch(request, env);

			expect(response.status).toBe(200);
			expect(mockCloudflareClient.dns.records.list).toHaveBeenCalledTimes(2);
			expect(mockCloudflareClient.dns.records.update).toHaveBeenCalledWith('record1', expect.objectContaining({ zone_id: 'zone2' }));
		});

		it('filters zones by name when zone param is provided', async () => {
			mockCloudflareClient.zones.list.mockResolvedValue({
				result: [
					{ id: 'zone1', name: 'example.com' },
					{ id: 'zone2', name: 'other.com' },
				],
			} as any);
			mockCloudflareClient.dns.records.list.mockResolvedValue({
				result: [{ id: 'r1', name: 'test.example.com', type: 'A', content: '1.2.3.0', proxied: false, ttl: 1 }],
			} as any);
			mockCloudflareClient.dns.records.update.mockResolvedValue(undefined);

			const request = createMockRequest('https://example.com/update?ip4=1.2.3.4&hostnames=test.example.com&zone=example.com', {
				headers: validAuth,
			});

			const response = await worker.fetch(request, env);

			expect(response.status).toBe(200);
			// Only the matching zone was searched
			expect(mockCloudflareClient.dns.records.list).toHaveBeenCalledTimes(1);
			expect(mockCloudflareClient.dns.records.list).toHaveBeenCalledWith(expect.objectContaining({ zone_id: 'zone1' }));
		});

		it('returns 400 when zone filter matches no available zones', async () => {
			mockCloudflareClient.zones.list.mockResolvedValue({
				result: [{ id: 'zone1', name: 'example.com' }],
			} as any);

			const request = createMockRequest('https://example.com/update?ip4=1.2.3.4&hostnames=test.example.com&zone=notmine.com', {
				headers: validAuth,
			});

			const response = await worker.fetch(request, env);

			expect(response.status).toBe(400);
			const body = (await response.json()) as any;
			expect(body).toEqual({
				success: false,
				error: "Zone 'notmine.com' not available with current permissions.",
			});
		});

		it('fails when no zones are available', async () => {
			mockCloudflareClient.zones.list.mockResolvedValue({ result: [] } as any);

			const request = createMockRequest('https://example.com/update?ip4=1.2.3.4&hostnames=test.example.com', {
				headers: validAuth,
			});

			const response = await worker.fetch(request, env);

			expect(response.status).toBe(400);
			const body = (await response.json()) as any;
			expect(body).toEqual({
				success: false,
				error: 'No zones available with current permissions.',
			});
		});

		it('fails when no matching record is found', async () => {
			mockCloudflareClient.zones.list.mockResolvedValue({
				result: [{ id: 'zone1', name: 'example.com' }],
			} as any);
			mockCloudflareClient.dns.records.list.mockResolvedValue({ result: [] } as any);

			const request = createMockRequest('https://example.com/update?ip4=1.2.3.4&hostnames=test.example.com', {
				headers: validAuth,
			});

			const response = await worker.fetch(request, env);

			expect(response.status).toBe(400);
			const body = (await response.json()) as any;
			expect(body).toEqual({
				success: false,
				error: "No matching record found for 'test.example.com'. Create it manually first.",
			});
		});

		it('fails when multiple matching records are found across zones', async () => {
			mockCloudflareClient.zones.list.mockResolvedValue({
				result: [
					{ id: 'zone1', name: 'example.com' },
					{ id: 'zone2', name: 'example.com' },
				],
			} as any);
			mockCloudflareClient.dns.records.list.mockResolvedValue({
				result: [
					{
						id: 'record1',
						name: 'test.example.com',
						type: 'A',
						content: '1.2.3.4',
					},
				],
			} as any);

			const request = createMockRequest('https://example.com/update?ip4=1.2.3.5&hostnames=test.example.com', {
				headers: validAuth,
			});

			const response = await worker.fetch(request, env);

			expect(response.status).toBe(400);
			const body = (await response.json()) as any;
			expect(body).toEqual({
				success: false,
				error: "Multiple matching records found for 'test.example.com'. Specify a unique hostname per zone.",
			});
		});
	});

	// -------------------------------------------------------------------------
	// Record update flow
	// -------------------------------------------------------------------------

	describe('Record update flow', () => {
		const validAuth = { Authorization: createAuthHeader('user@example.com', 'token') };

		beforeEach(() => {
			mockCloudflareClient.user.tokens.verify.mockResolvedValue({ status: 'active' } as any);
			(vi.mocked(env.DDNS_KV) as any).get.mockResolvedValue(null);
			(vi.mocked(env.DDNS_KV) as any).put.mockResolvedValue(undefined);
		});

		it('successfully updates a single DNS record and returns the correct shape', async () => {
			const { pushNtfy } = await import('../src/pushNtfy');
			const pushNtfyMock = vi.mocked(pushNtfy);

			mockCloudflareClient.zones.list.mockResolvedValue({
				result: [{ id: 'zone1', name: 'example.com' }],
			} as any);
			mockCloudflareClient.dns.records.list.mockResolvedValue({
				result: [
					{
						id: 'record1',
						name: 'test.example.com',
						type: 'A',
						content: '1.2.3.4',
						proxied: true,
						comment: 'Test record',
						ttl: 300,
					},
				],
			} as any);
			mockCloudflareClient.dns.records.update.mockResolvedValue(undefined);

			const request = createMockRequest('https://example.com/update?ip4=1.2.3.5&hostnames=test.example.com', {
				headers: validAuth,
			});

			const response = await worker.fetch(request, env);

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

			expect(pushNtfyMock).toHaveBeenCalledWith(["DNS record for 'test.example.com' ('A') updated to '1.2.3.5'"], env);
		});

		it('does not call dns.records.update when existing content already matches target IP (DNS-delta no-op)', async () => {
			const { pushNtfy } = await import('../src/pushNtfy');
			const pushNtfyMock = vi.mocked(pushNtfy);

			mockCloudflareClient.zones.list.mockResolvedValue({
				result: [{ id: 'zone1', name: 'example.com' }],
			} as any);
			// Existing DNS content already matches the requested IP
			mockCloudflareClient.dns.records.list.mockResolvedValue({
				result: [{ id: 'r1', name: 'test.example.com', type: 'A', content: '1.2.3.4', proxied: false, ttl: 1 }],
			} as any);

			const request = createMockRequest('https://example.com/update?ip4=1.2.3.4&hostnames=test.example.com', {
				headers: validAuth,
			});

			const response = await worker.fetch(request, env);
			const body = (await response.json()) as any;

			expect(response.status).toBe(200);
			expect(body.message).toBe('DNS records already current');
			expect(body.data.updated).toBe(false);
			expect(body.data.records[0]).toMatchObject({ hostname: 'test.example.com', ip: '1.2.3.4', updated: false });
			// Update must not have been called
			expect(mockCloudflareClient.dns.records.update).not.toHaveBeenCalled();
			// Cache is still written even on a no-op
			expect((vi.mocked(env.DDNS_KV) as any).put).toHaveBeenCalled();
			// No notification for unchanged records
			expect(pushNtfyMock).toHaveBeenCalledWith([], env);
		});

		it('passes empty array to pushNtfy when no records changed', async () => {
			const { pushNtfy } = await import('../src/pushNtfy');
			const pushNtfyMock = vi.mocked(pushNtfy);

			mockCloudflareClient.zones.list.mockResolvedValue({
				result: [{ id: 'zone1', name: 'example.com' }],
			} as any);
			mockCloudflareClient.dns.records.list.mockResolvedValue({
				result: [{ id: 'r1', name: 'test.example.com', type: 'A', content: '5.5.5.5', proxied: false, ttl: 1 }],
			} as any);

			const request = createMockRequest('https://example.com/update?ip4=5.5.5.5&hostnames=test.example.com', {
				headers: validAuth,
			});

			await worker.fetch(request, env);

			expect(pushNtfyMock).toHaveBeenCalledWith([], env);
		});

		it('successfully updates multiple DNS records and sends a grouped notification', async () => {
			const { pushNtfy } = await import('../src/pushNtfy');
			const pushNtfyMock = vi.mocked(pushNtfy);

			mockCloudflareClient.zones.list.mockResolvedValue({
				result: [{ id: 'zone1', name: 'example.com' }],
			} as any);

			mockCloudflareClient.dns.records.list
				.mockResolvedValueOnce({
					result: [{ id: 'record1', name: 'test1.example.com', type: 'A', content: '1.2.3.4', proxied: false, ttl: 1 }],
				} as any)
				.mockResolvedValueOnce({
					result: [{ id: 'record2', name: 'test2.example.com', type: 'A', content: '1.2.3.4', proxied: true, ttl: 300 }],
				} as any);

			mockCloudflareClient.dns.records.update.mockResolvedValue(undefined);

			const request = createMockRequest('https://example.com/update?ip4=1.2.3.5&hostnames=test1.example.com,test2.example.com', {
				headers: validAuth,
			});

			const response = await worker.fetch(request, env);

			expect(response.status).toBe(200);
			const body = (await response.json()) as any;
			expect(body.data.records).toHaveLength(2);

			expect(mockCloudflareClient.dns.records.update).toHaveBeenCalledTimes(2);
			expect(pushNtfyMock).toHaveBeenCalledWith(
				["DNS record for 'test1.example.com' ('A') updated to '1.2.3.5'", "DNS record for 'test2.example.com' ('A') updated to '1.2.3.5'"],
				env,
			);
		});

		it('handles records without optional fields by using defaults', async () => {
			mockCloudflareClient.zones.list.mockResolvedValue({
				result: [{ id: 'zone1', name: 'example.com' }],
			} as any);
			mockCloudflareClient.dns.records.list.mockResolvedValue({
				result: [
					{
						id: 'record1',
						name: 'test.example.com',
						type: 'A',
						content: '1.2.3.4',
						// No proxied, comment, or ttl fields
					},
				],
			} as any);
			mockCloudflareClient.dns.records.update.mockResolvedValue(undefined);

			const request = createMockRequest('https://example.com/update?ip4=1.2.3.5&hostnames=test.example.com', {
				headers: validAuth,
			});

			const response = await worker.fetch(request, env);

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

		it('calls pushNtfy exactly once per request that reaches the update phase', async () => {
			const { pushNtfy } = await import('../src/pushNtfy');
			const pushNtfyMock = vi.mocked(pushNtfy);

			mockCloudflareClient.zones.list.mockResolvedValue({
				result: [{ id: 'zone1', name: 'example.com' }],
			} as any);
			mockCloudflareClient.dns.records.list.mockResolvedValue({
				result: [{ id: 'r1', name: 'test.example.com', type: 'A', content: '1.2.3.0', proxied: false, ttl: 1 }],
			} as any);
			mockCloudflareClient.dns.records.update.mockResolvedValue(undefined);

			const request = createMockRequest('https://example.com/update?ip4=1.2.3.4&hostnames=test.example.com', {
				headers: validAuth,
			});

			await worker.fetch(request, env);

			expect(pushNtfyMock).toHaveBeenCalledTimes(1);
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

			const response = await worker.fetch(request, createMockEnv());

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

			const response = await worker.fetch(request, createMockEnv());

			expect(response.status).toBe(500);
			const body = (await response.json()) as any;
			expect(body).toEqual({
				success: false,
				error: 'Internal Server Error',
			});
		});

		it('maps Cloudflare API errors to 500', async () => {
			mockCloudflareClient.user.tokens.verify.mockResolvedValue({ status: 'active' } as any);
			mockCloudflareClient.zones.list.mockRejectedValue(new Error('API rate limit exceeded'));

			const request = createMockRequest('https://example.com/update?ip4=1.2.3.4&hostnames=test.example.com', {
				headers: validAuth,
			});

			const response = await worker.fetch(request, createMockEnv());

			expect(response.status).toBe(500);
			const body = (await response.json()) as any;
			expect(body).toEqual({
				success: false,
				error: 'Internal Server Error',
			});
		});

		it('success responses do not include a previousIp field', async () => {
			mockCloudflareClient.user.tokens.verify.mockResolvedValue({ status: 'active' } as any);
			(vi.mocked(env.DDNS_KV) as any).get.mockResolvedValue(null);
			(vi.mocked(env.DDNS_KV) as any).put.mockResolvedValue(undefined);

			mockCloudflareClient.zones.list.mockResolvedValue({
				result: [{ id: 'zone1', name: 'example.com' }],
			} as any);
			mockCloudflareClient.dns.records.list.mockResolvedValue({
				result: [{ id: 'r1', name: 'test.example.com', type: 'A', content: '1.2.3.0', proxied: false, ttl: 1 }],
			} as any);
			mockCloudflareClient.dns.records.update.mockResolvedValue(undefined);

			const request = createMockRequest('https://example.com/update?ip4=1.2.3.4&hostnames=test.example.com', {
				headers: validAuth,
			});

			const response = await worker.fetch(request, env);
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

			mockCloudflareClient.user.tokens.verify.mockResolvedValue({ status: 'active' } as any);
			mockCloudflareClient.zones.list.mockResolvedValue({
				result: [{ id: 'zone1', name: 'example.com' }],
			} as any);
			mockCloudflareClient.dns.records.list.mockResolvedValue({
				result: [
					{
						id: 'record1',
						name: 'test.example.com',
						type: 'A',
						content: '1.2.3.4',
						proxied: true,
						comment: 'Managed by DDNS',
						ttl: 300,
					},
				],
			} as any);
			mockCloudflareClient.dns.records.update.mockResolvedValue(undefined);

			const request = createMockRequest('https://example.com/update?ip4=1.2.3.5&hostnames=test.example.com', {
				headers: validAuth,
			});

			const response = await worker.fetch(request, env);

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

			const response = await worker.fetch(request, env);

			expect(response.status).toBe(200);
			expect(vi.mocked(Cloudflare)).toHaveBeenCalledWith({ apiToken: 'my-raw-api-token' });
			const body = (await response.json()) as any;
			expect(body.success).toBe(true);
			expect(pushNtfyMock).toHaveBeenCalledTimes(1);
		});

		it('returns 422 and skips KV storage when ip4 param is empty string', async () => {
			const request = createMockRequest('https://example.com/update?ip4=&hostnames=test.example.com', {
				headers: { Authorization: createAuthHeader('user@example.com', 'api-token') },
			});

			const response = await worker.fetch(request, env);

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

			mockCloudflareClient.user.tokens.verify.mockResolvedValue({ status: 'active' } as any);
			mockCloudflareClient.zones.list.mockResolvedValue({
				result: [{ id: 'zone1', name: 'example.com' }],
			} as any);

			// A for h1, AAAA for h1, A for h2, AAAA for h2
			mockCloudflareClient.dns.records.list
				.mockResolvedValueOnce({
					result: [{ id: 'r1', name: 'h1.example.com', type: 'A', content: '0.0.0.0', proxied: false, ttl: 1 }],
				} as any)
				.mockResolvedValueOnce({
					result: [{ id: 'r2', name: 'h1.example.com', type: 'AAAA', content: '::', proxied: false, ttl: 1 }],
				} as any)
				.mockResolvedValueOnce({
					result: [{ id: 'r3', name: 'h2.example.com', type: 'A', content: '0.0.0.0', proxied: false, ttl: 1 }],
				} as any)
				.mockResolvedValueOnce({
					result: [{ id: 'r4', name: 'h2.example.com', type: 'AAAA', content: '::', proxied: false, ttl: 1 }],
				} as any);
			mockCloudflareClient.dns.records.update.mockResolvedValue(undefined);

			const request = createMockRequest('https://example.com/update?ip4=1.2.3.4&ip6=2001:db8::1&hostnames=h1.example.com,h2.example.com', {
				headers: { Authorization: createAuthHeader('user', 'token') },
			});

			const response = await worker.fetch(request, env);
			const body = (await response.json()) as any;

			expect(response.status).toBe(200);
			expect(body.data.records).toHaveLength(4);
			// Both A and AAAA types present
			const types = (body.data.records as any[]).map((r: any) => r.type as string);
			expect(types.filter((t) => t === 'A')).toHaveLength(2);
			expect(types.filter((t) => t === 'AAAA')).toHaveLength(2);
			expect(mockCloudflareClient.dns.records.list).toHaveBeenCalledTimes(4);
			expect(pushNtfyMock).toHaveBeenCalledTimes(1);
		});
	});
});
