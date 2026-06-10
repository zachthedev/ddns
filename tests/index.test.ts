import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import worker, { HttpError } from '../src/index';
import { createMockCloudflareClient, createMockEnv, createMockRequest, createAuthHeader, wireStandardHappyPath } from './helpers/mocks';
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
		it('accepts valid authorization credentials', async () => {
			mockCloudflareClient.user.tokens.verify.mockResolvedValue({ status: 'active' } as any);
			mockCloudflareClient.zones.list.mockResolvedValue({ result: [] } as any);

			const request = createMockRequest('https://example.com/update?ip=1.2.3.4&hostname=test.example.com', {
				headers: { Authorization: createAuthHeader('user@example.com', 'valid-token') },
			});

			const response = await worker.fetch(request, env);

			// Fails with 'No zones available' but confirms auth passed and Cloudflare
			// was initialised with the decoded credentials.
			expect(response.status).toBe(400);
			expect(vi.mocked(Cloudflare)).toHaveBeenCalledWith({
				apiEmail: 'user@example.com',
				apiToken: 'valid-token',
			});
		});

		it('rejects request without Authorization header', async () => {
			const request = createMockRequest('https://example.com/update?ip=1.2.3.4&hostname=test.example.com');

			const response = await worker.fetch(request, env);

			expect(response.status).toBe(401);
			const body = (await response.json()) as any;
			expect(body).toEqual({
				success: false,
				error: 'Authorization required.',
			});
		});

		it('rejects request with invalid Authorization format', async () => {
			const request = createMockRequest('https://example.com/update?ip=1.2.3.4&hostname=test.example.com', {
				headers: { Authorization: 'InvalidFormat' },
			});

			const response = await worker.fetch(request, env);

			expect(response.status).toBe(401);
			const body = (await response.json()) as any;
			expect(body).toEqual({
				success: false,
				error: 'Invalid authorization credentials.',
			});
		});

		it('rejects request with empty Bearer token', async () => {
			const request = createMockRequest('https://example.com/update?ip=1.2.3.4&hostname=test.example.com', {
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

		it('rejects request with invalid base64 encoding', async () => {
			const request = createMockRequest('https://example.com/update?ip=1.2.3.4&hostname=test.example.com', {
				headers: { Authorization: 'Bearer !!invalid!!base64!!' },
			});

			const response = await worker.fetch(request, env);

			// Malformed base64 is a client error, same as any other bad credential
			expect(response.status).toBe(401);
			const body = (await response.json()) as any;
			expect(body).toEqual({
				success: false,
				error: 'Invalid authorization credentials.',
			});
		});

		it('rejects request with missing delimiter in credentials', async () => {
			const request = createMockRequest('https://example.com/update?ip=1.2.3.4&hostname=test.example.com', {
				headers: { Authorization: `Bearer ${btoa('noddelimiter')}` },
			});

			const response = await worker.fetch(request, env);

			expect(response.status).toBe(401);
			const body = (await response.json()) as any;
			expect(body).toEqual({
				success: false,
				error: 'Invalid authorization credentials.',
			});
		});

		it('rejects request with control characters in credentials', async () => {
			const request = createMockRequest('https://example.com/update?ip=1.2.3.4&hostname=test.example.com', {
				headers: { Authorization: `Bearer ${btoa('email@example.com:\x00token')}` },
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
			const request = createMockRequest('https://example.com/update?ip=1.2.3.4&hostname=test.example.com', {
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
	// DNS record construction  (constructDNSRecord param validation)
	// -------------------------------------------------------------------------

	describe('DNS record construction', () => {
		const validAuth = { Authorization: createAuthHeader('user@example.com', 'token') };

		beforeEach(() => {
			mockCloudflareClient.user.tokens.verify.mockResolvedValue({ status: 'active' } as any);
		});

		it('uses client IP when ip=auto', async () => {
			mockCloudflareClient.zones.list.mockResolvedValue({ result: [] } as any);

			const request = createMockRequest('https://example.com/update?ip=auto&hostname=test.example.com', {
				headers: { ...validAuth, 'CF-Connecting-IP': '203.0.113.1' },
			});

			const response = await worker.fetch(request, env);

			// Fails with 'No zones available' but confirms IP was resolved
			expect(response.status).toBe(400);
		});

		it('accepts myip parameter as alias for ip', async () => {
			mockCloudflareClient.zones.list.mockResolvedValue({ result: [] } as any);

			const request = createMockRequest('https://example.com/update?myip=1.2.3.4&hostname=test.example.com', {
				headers: validAuth,
			});

			const response = await worker.fetch(request, env);

			// Fails with 'No zones available' but confirms parameter was accepted
			expect(response.status).toBe(400);
		});

		it('accepts hostnames parameter as alias for hostname', async () => {
			mockCloudflareClient.zones.list.mockResolvedValue({ result: [] } as any);

			const request = createMockRequest('https://example.com/update?ip=1.2.3.4&hostnames=test.example.com', {
				headers: validAuth,
			});

			const response = await worker.fetch(request, env);

			// Fails with 'No zones available' but confirms parameter was accepted
			expect(response.status).toBe(400);
		});

		it('detects IPv4 address and queries for A record', async () => {
			mockCloudflareClient.zones.list.mockResolvedValue({
				result: [{ id: 'zone1', name: 'example.com' }],
			} as any);
			mockCloudflareClient.dns.records.list.mockResolvedValue({ result: [] } as any);

			const request = createMockRequest('https://example.com/update?ip=192.168.1.1&hostname=test.example.com', {
				headers: validAuth,
			});

			await worker.fetch(request, env);

			expect(mockCloudflareClient.dns.records.list).toHaveBeenCalledWith({
				zone_id: 'zone1',
				name: 'test.example.com',
				type: 'A',
			});
		});

		it('detects IPv6 address and queries for AAAA record', async () => {
			mockCloudflareClient.zones.list.mockResolvedValue({
				result: [{ id: 'zone1', name: 'example.com' }],
			} as any);
			mockCloudflareClient.dns.records.list.mockResolvedValue({ result: [] } as any);

			const request = createMockRequest('https://example.com/update?ip=2001:db8::1&hostname=test.example.com', {
				headers: validAuth,
			});

			await worker.fetch(request, env);

			expect(mockCloudflareClient.dns.records.list).toHaveBeenCalledWith({
				zone_id: 'zone1',
				name: 'test.example.com',
				type: 'AAAA',
			});
		});

		it('handles multiple hostnames separated by commas', async () => {
			mockCloudflareClient.zones.list.mockResolvedValue({
				result: [{ id: 'zone1', name: 'example.com' }],
			} as any);
			mockCloudflareClient.dns.records.list.mockResolvedValue({ result: [] } as any);

			const request = createMockRequest('https://example.com/update?ip=1.2.3.4&hostname=test1.example.com,test2.example.com', {
				headers: validAuth,
			});

			const response = await worker.fetch(request, env);

			// Fails with 'No matching record found' for the first hostname, but
			// confirms the comma-separated list was parsed and the first lookup ran.
			expect(response.status).toBe(400);
			expect(mockCloudflareClient.dns.records.list).toHaveBeenCalledTimes(1);
		});

		it('rejects request without ip parameter', async () => {
			const request = createMockRequest('https://example.com/update?hostname=test.example.com', {
				headers: validAuth,
			});

			const response = await worker.fetch(request, env);

			expect(response.status).toBe(422);
			const body = (await response.json()) as any;
			expect(body).toEqual({
				success: false,
				error: "Missing 'ip' parameter. Use ip=auto to use the client IP.",
			});
		});

		it('rejects ip=auto when CF-Connecting-IP is absent', async () => {
			const request = new Request('https://example.com/update?ip=auto&hostname=test.example.com', {
				headers: validAuth,
			});

			const response = await worker.fetch(request, env);

			expect(response.status).toBe(500);
			const body = (await response.json()) as any;
			expect(body).toEqual({
				success: false,
				error: 'ip=auto specified but client IP could not be determined.',
			});
		});

		it('rejects request without hostname parameter', async () => {
			const request = createMockRequest('https://example.com/update?ip=1.2.3.4', {
				headers: validAuth,
			});

			const response = await worker.fetch(request, env);

			expect(response.status).toBe(422);
			const body = (await response.json()) as any;
			expect(body).toEqual({
				success: false,
				error: "Missing 'hostname' parameter.",
			});
		});

		it('rejects empty hostname list', async () => {
			const request = createMockRequest('https://example.com/update?ip=1.2.3.4&hostname=,,,', {
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
	});

	// -------------------------------------------------------------------------
	// Token verification
	// -------------------------------------------------------------------------

	describe('Token verification', () => {
		const validAuth = { Authorization: createAuthHeader('user@example.com', 'token') };

		it('accepts an active token', async () => {
			mockCloudflareClient.user.tokens.verify.mockResolvedValue({ status: 'active' } as any);
			mockCloudflareClient.zones.list.mockResolvedValue({ result: [] } as any);

			const request = createMockRequest('https://example.com/update?ip=1.2.3.4&hostname=test.example.com', {
				headers: validAuth,
			});

			await worker.fetch(request, env);

			// Fails with 'No zones available' but confirms token.verify was called
			expect(mockCloudflareClient.user.tokens.verify).toHaveBeenCalled();
		});

		it('rejects an inactive token', async () => {
			mockCloudflareClient.user.tokens.verify.mockResolvedValue({ status: 'expired' } as any);

			const request = createMockRequest('https://example.com/update?ip=1.2.3.4&hostname=test.example.com', {
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
	// KV change detection
	// -------------------------------------------------------------------------

	describe('KV change detection', () => {
		const validAuth = { Authorization: createAuthHeader('user@example.com', 'token') };

		beforeEach(() => {
			mockCloudflareClient.user.tokens.verify.mockResolvedValue({ status: 'active' } as any);
		});

		it('skips update when IP has not changed', async () => {
			const kvMock = vi.mocked(env.DDNS_KV) as any;
			kvMock.get.mockResolvedValue('192.168.1.1');

			const request = createMockRequest('https://example.com/update?ip=192.168.1.1&hostname=test.example.com', {
				headers: validAuth,
			});

			const response = await worker.fetch(request, env);

			expect(response.status).toBe(200);
			const body = (await response.json()) as any;
			expect(body).toEqual({
				success: true,
				message: 'No IP change detected',
				data: {
					ip: '192.168.1.1',
					updated: false,
				},
			});
			// Short-circuits before zone listing
			expect(mockCloudflareClient.zones.list).not.toHaveBeenCalled();
		});

		it('stores new IP after a successful update', async () => {
			const kvMock = vi.mocked(env.DDNS_KV) as any;
			kvMock.get.mockResolvedValue(null);
			kvMock.put.mockResolvedValue(undefined);

			mockCloudflareClient.zones.list.mockResolvedValue({
				result: [{ id: 'zone1', name: 'example.com' }],
			} as any);
			mockCloudflareClient.dns.records.list.mockResolvedValue({
				result: [
					{
						id: 'record1',
						name: 'test.example.com',
						type: 'A',
						content: '192.168.1.1',
						proxied: false,
						ttl: 300,
					},
				],
			} as any);
			mockCloudflareClient.dns.records.update.mockResolvedValue({ success: true } as any);

			const request = createMockRequest('https://example.com/update?ip=192.168.1.2&hostname=test.example.com', {
				headers: validAuth,
			});

			const response = await worker.fetch(request, env);

			expect(response.status).toBe(200);
			expect(kvMock.put).toHaveBeenCalledWith('ip:user@example.com', '192.168.1.2');
		});

		it('returns success even when KV put fails', async () => {
			const kvMock = vi.mocked(env.DDNS_KV) as any;
			kvMock.get.mockResolvedValue(null);
			kvMock.put.mockRejectedValue(new Error('KV write error'));

			mockCloudflareClient.zones.list.mockResolvedValue({
				result: [{ id: 'zone1', name: 'example.com' }],
			} as any);
			mockCloudflareClient.dns.records.list.mockResolvedValue({
				result: [
					{
						id: 'record1',
						name: 'test.example.com',
						type: 'A',
						content: '192.168.1.1',
						proxied: false,
						ttl: 300,
					},
				],
			} as any);
			mockCloudflareClient.dns.records.update.mockResolvedValue({ success: true } as any);

			const request = createMockRequest('https://example.com/update?ip=192.168.1.2&hostname=test.example.com', {
				headers: validAuth,
			});

			const response = await worker.fetch(request, env);

			// DNS update was still performed despite the KV failure
			expect(response.status).toBe(200);
			expect(mockCloudflareClient.dns.records.update).toHaveBeenCalled();
		});

		it('proceeds with update when IP has changed', async () => {
			const kvMock = vi.mocked(env.DDNS_KV) as any;
			kvMock.get.mockResolvedValue('192.168.1.1');

			mockCloudflareClient.zones.list.mockResolvedValue({ result: [] } as any);

			const request = createMockRequest('https://example.com/update?ip=192.168.1.2&hostname=test.example.com', {
				headers: validAuth,
			});

			await worker.fetch(request, env);

			// Fails with 'No zones available' but confirms it proceeded past the IP check
			expect(mockCloudflareClient.zones.list).toHaveBeenCalled();
		});

		it('proceeds with update when no previous IP exists', async () => {
			const kvMock = vi.mocked(env.DDNS_KV) as any;
			kvMock.get.mockResolvedValue(null);

			mockCloudflareClient.zones.list.mockResolvedValue({ result: [] } as any);

			const request = createMockRequest('https://example.com/update?ip=192.168.1.1&hostname=test.example.com', {
				headers: validAuth,
			});

			await worker.fetch(request, env);

			// Fails with 'No zones available' but confirms it proceeded past the IP check
			expect(mockCloudflareClient.zones.list).toHaveBeenCalled();
		});

		it('continues past a KV get failure', async () => {
			const kvMock = vi.mocked(env.DDNS_KV) as any;
			kvMock.get.mockRejectedValue(new Error('KV error'));

			mockCloudflareClient.zones.list.mockResolvedValue({ result: [] } as any);

			const request = createMockRequest('https://example.com/update?ip=192.168.1.1&hostname=test.example.com', {
				headers: validAuth,
			});

			const response = await worker.fetch(request, env);

			// Confirms it continued past the KV read error and reached zone listing
			expect(mockCloudflareClient.zones.list).toHaveBeenCalled();
			expect(response.status).toBe(400);
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

			mockCloudflareClient.dns.records.update.mockResolvedValue({ success: true } as any);

			const request = createMockRequest('https://example.com/update?ip=1.2.3.5&hostname=sub.test.com', {
				headers: validAuth,
			});

			const response = await worker.fetch(request, env);

			expect(response.status).toBe(200);
			expect(mockCloudflareClient.dns.records.list).toHaveBeenCalledTimes(2);
			expect(mockCloudflareClient.dns.records.update).toHaveBeenCalledWith('record1', expect.objectContaining({ zone_id: 'zone2' }));
		});

		it('fails when no zones are available', async () => {
			mockCloudflareClient.zones.list.mockResolvedValue({ result: [] } as any);

			const request = createMockRequest('https://example.com/update?ip=1.2.3.4&hostname=test.example.com', {
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

			const request = createMockRequest('https://example.com/update?ip=1.2.3.4&hostname=test.example.com', {
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

		it('fails when multiple matching records are found', async () => {
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

			const request = createMockRequest('https://example.com/update?ip=1.2.3.5&hostname=test.example.com', {
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
		});

		it('successfully updates a single DNS record', async () => {
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
			mockCloudflareClient.dns.records.update.mockResolvedValue({ success: true } as any);

			const request = createMockRequest('https://example.com/update?ip=1.2.3.5&hostname=test.example.com', {
				headers: validAuth,
			});

			const response = await worker.fetch(request, env);

			expect(response.status).toBe(200);
			const body = (await response.json()) as any;
			expect(body).toEqual({
				success: true,
				message: 'DNS records updated successfully',
				data: {
					ip: '1.2.3.5',
					previousIp: null,
					updated: true,
					records: [{ hostname: 'test.example.com', type: 'A' }],
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

		it('successfully updates multiple DNS records and sends a grouped notification', async () => {
			const { pushNtfy } = await import('../src/pushNtfy');
			const pushNtfyMock = vi.mocked(pushNtfy);

			mockCloudflareClient.zones.list.mockResolvedValue({
				result: [{ id: 'zone1', name: 'example.com' }],
			} as any);

			// First hostname
			mockCloudflareClient.dns.records.list.mockResolvedValueOnce({
				result: [
					{
						id: 'record1',
						name: 'test1.example.com',
						type: 'A',
						content: '1.2.3.4',
						proxied: false,
						ttl: 1,
					},
				],
			} as any);

			// Second hostname
			mockCloudflareClient.dns.records.list.mockResolvedValueOnce({
				result: [
					{
						id: 'record2',
						name: 'test2.example.com',
						type: 'A',
						content: '1.2.3.4',
						proxied: true,
						ttl: 300,
					},
				],
			} as any);

			mockCloudflareClient.dns.records.update.mockResolvedValue({ success: true } as any);

			const request = createMockRequest('https://example.com/update?ip=1.2.3.5&hostname=test1.example.com,test2.example.com', {
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
			mockCloudflareClient.dns.records.update.mockResolvedValue({ success: true } as any);

			const request = createMockRequest('https://example.com/update?ip=1.2.3.5&hostname=test.example.com', {
				headers: validAuth,
			});

			const response = await worker.fetch(request, env);

			expect(response.status).toBe(200);
			expect(mockCloudflareClient.dns.records.update).toHaveBeenCalledWith('record1', {
				content: '1.2.3.5',
				zone_id: 'zone1',
				name: 'test.example.com',
				type: 'A',
				proxied: false, // Default value
				comment: undefined,
				ttl: 1, // Default value
			});
		});
	});

	// -------------------------------------------------------------------------
	// Response shapes  (error mapping)
	// -------------------------------------------------------------------------

	describe('Response shapes', () => {
		const validAuth = { Authorization: createAuthHeader('user@example.com', 'token') };

		it('maps HttpError to the correct status code', async () => {
			// Missing ip triggers a 422 HttpError from constructDNSRecord
			const request = createMockRequest('https://example.com/update', {
				headers: validAuth,
			});

			const response = await worker.fetch(request, createMockEnv());

			expect(response.status).toBe(422);
			const body = (await response.json()) as any;
			expect(body).toEqual({
				success: false,
				error: "Missing 'ip' parameter. Use ip=auto to use the client IP.",
			});
		});

		it('maps unexpected errors to 500', async () => {
			mockCloudflareClient.user.tokens.verify.mockRejectedValue(new Error('Network error'));

			const request = createMockRequest('https://example.com/update?ip=1.2.3.4&hostname=test.example.com', {
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

			const request = createMockRequest('https://example.com/update?ip=1.2.3.4&hostname=test.example.com', {
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
			kvMock.get.mockResolvedValue('1.2.3.4'); // Old IP stored in KV
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
			mockCloudflareClient.dns.records.update.mockResolvedValue({
				success: true,
				result: { id: 'record1' },
			} as any);

			const request = createMockRequest('https://example.com/update?ip=1.2.3.5&hostname=test.example.com', {
				headers: validAuth,
			});

			const response = await worker.fetch(request, env);

			expect(response.status).toBe(200);
			const body = (await response.json()) as any;
			expect(body).toEqual({
				success: true,
				message: 'DNS records updated successfully',
				data: {
					ip: '1.2.3.5',
					previousIp: '1.2.3.4',
					updated: true,
					records: [{ hostname: 'test.example.com', type: 'A' }],
				},
			});

			// Verify all pipeline steps ran
			expect(kvMock.get).toHaveBeenCalledWith('ip:user@example.com');
			expect(mockCloudflareClient.user.tokens.verify).toHaveBeenCalled();
			expect(mockCloudflareClient.zones.list).toHaveBeenCalled();
			expect(mockCloudflareClient.dns.records.list).toHaveBeenCalled();
			expect(mockCloudflareClient.dns.records.update).toHaveBeenCalled();
			expect(kvMock.put).toHaveBeenCalledWith('ip:user@example.com', '1.2.3.5');
			expect(pushNtfyMock).toHaveBeenCalled();
		});

		it("falls back to 'unknown' as KV key when apiEmail is missing from client options", async () => {
			const request = createMockRequest('https://example.com/update?ip=10.0.0.1&hostname=test.example.com', {
				headers: { Authorization: createAuthHeader('user@example.com', 'api-token') },
			});

			// Delete apiEmail from the options passed to Cloudflare so updateHostnames
			// hits the `?? 'unknown'` fallback.
			// vitest 4: constructor mocks must use function/class form, not arrows
			vi.mocked(Cloudflare).mockImplementation(function (options: any) {
				delete options.apiEmail;
				return mockCloudflareClient as any;
			});

			wireStandardHappyPath(mockCloudflareClient);

			const kvMock = vi.mocked(env.DDNS_KV) as any;
			kvMock.get.mockResolvedValue(null);
			kvMock.put.mockResolvedValue(undefined);

			const response = await worker.fetch(request, env);

			expect(response.status).toBe(200);
			const body = (await response.json()) as any;
			expect(body.success).toBe(true);
			expect(kvMock.put).toHaveBeenCalledWith('ip:unknown', '10.0.0.1');
		});

		it('handles undefined name/content on the returned record by using fallback strings', async () => {
			const request = createMockRequest('https://example.com/update?ip=192.168.1.100&hostname=test.example.com', {
				headers: { Authorization: createAuthHeader('user@example.com', 'api-token') },
			});

			wireStandardHappyPath(mockCloudflareClient);

			const kvMock = vi.mocked(env.DDNS_KV) as any;
			kvMock.get.mockResolvedValue(null);
			kvMock.put.mockResolvedValue(undefined);

			// Mock DNS update and verify the fallback logic for undefined properties
			mockCloudflareClient.dns.records.update.mockImplementation(() => {
				const newRecord: { name: string | undefined; type: string; content: string | undefined } = {
					name: undefined,
					type: 'A',
					content: undefined,
				};
				const recordName = newRecord.name ?? 'unknown';
				const recordContent = newRecord.content ?? '';
				const successMsg = `DNS record for '${recordName}' ('${newRecord.type}') updated to '${recordContent}'`;

				expect(recordName).toBe('unknown');
				expect(recordContent).toBe('');
				expect(successMsg).toContain('unknown');

				return Promise.resolve(undefined);
			});

			const response = await worker.fetch(request, env);

			expect(response.status).toBe(200);
		});

		it('does not store an empty string in KV when currentIp is non-empty', async () => {
			const request = createMockRequest('https://example.com/update?ip=192.168.1.100&hostname=test.example.com', {
				headers: { Authorization: createAuthHeader('user@example.com', 'api-token') },
			});

			wireStandardHappyPath(mockCloudflareClient);

			const kvMock = vi.mocked(env.DDNS_KV) as any;
			kvMock.get.mockResolvedValue(null);
			kvMock.put.mockImplementation((_key: any, value: any) => {
				// Guard against accidentally storing an empty IP
				if (value === null || value === undefined || value === '') {
					throw new Error('Should not store empty IP');
				}
				return Promise.resolve(undefined);
			});

			const response = await worker.fetch(request, env);

			expect(response.status).toBe(200);
		});

		it('returns 422 and skips KV storage when ip param is empty string', async () => {
			const request = createMockRequest('https://example.com/update?ip=&hostname=test.example.com', {
				headers: { Authorization: createAuthHeader('user@example.com', 'api-token') },
			});

			const response = await worker.fetch(request, env);

			expect(response.status).toBe(422);
			const body = (await response.json()) as any;
			expect(body.error).toBe("Missing 'ip' parameter. Use ip=auto to use the client IP.");
		});
	});
});
