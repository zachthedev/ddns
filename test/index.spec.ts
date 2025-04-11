import { env } from 'cloudflare:test';
import { describe, it, expect, vi, beforeEach, afterEach, beforeAll, afterAll } from 'vitest';
import worker from '../src/index';
import { pushNtfy } from '../src/pushNtfy';

// Mock functions
const mockVerify = vi.fn();
const mockListZones = vi.fn();
const mockListRecords = vi.fn();
const mockUpdateRecord = vi.fn();

vi.mock('cloudflare', () => {
	return {
		Cloudflare: vi.fn().mockImplementation(() => ({
			user: {
				tokens: {
					verify: mockVerify,
				},
			},
			zones: {
				list: mockListZones,
			},
			dns: {
				records: {
					list: mockListRecords,
					update: mockUpdateRecord,
				},
			},
		})),
	};
});

describe('UniFi DDNS Worker', () => {
	let originalFetch: typeof fetch;

	const env: Env = {
		NTFY_URL: 'https://ntfy.sh/example',
	};

	beforeAll(() => {
		originalFetch = global.fetch;
	});

	beforeEach(() => {
		// Clear all mocks before each test to prevent state leakage
		vi.clearAllMocks();
		// All calls to fetch—including those inside pushNtfy—are intercepted.
		global.fetch = vi.fn().mockResolvedValue(new Response('OK'));
	});

	afterAll(() => {
		global.fetch = originalFetch;
	});

	it('responds with 401 when API token is missing', async () => {
		const request = new Request('http://example.com/update?ip=192.0.2.1&hostname=home.example.com');
		const response = await worker.fetch(request, env);

		expect(response.status).toBe(401);
		expect(await response.text()).toBe('API Token missing.');
	});

	it('responds with 401 when token is missing after splitting the Authorization header', async () => {
		const request = new Request('http://example.com/update?ip=192.0.2.1&hostname=home.example.com', {
			headers: {
				Authorization: 'Basic',
			},
		});
		const response = await worker.fetch(request, env);

		expect(response.status).toBe(401);
		expect(await response.text()).toBe('Invalid API Token.');
	});

	it('responds with 401 when API token contains control characters', async () => {
		const badToken = btoa('email@example.com:\x00test');
		const request = new Request('http://example.com/update?ip=192.0.2.1&hostname=home.example.com', {
			headers: {
				Authorization: 'Basic ' + badToken,
			},
		});
		const response = await worker.fetch(request, env);

		expect(response.status).toBe(401);
		expect(await response.text()).toBe('Invalid API Token.');
	});

	it('responds with 401 when API token is invalid', async () => {
		const request = new Request('http://example.com/update?ip=192.0.2.1&hostname=home.example.com', {
			headers: {
				// CodeQL [js/hardcoded-credentials] Suppressing hardcoded credential warning for test
				Authorization: 'Basic invalidtoken',
			},
		});
		const response = await worker.fetch(request, env);

		expect(response.status).toBe(401);
		expect(await response.text()).toBe('Invalid API Token.');
	});

	it('responds with 401 when token is not active', async () => {
		mockVerify.mockResolvedValueOnce({ status: 'inactive' });

		const request = new Request('http://example.com/update?ip=192.0.2.1&hostname=home.example.com', {
			headers: {
				Authorization: 'Basic ' + btoa('email@example.com:validtoken'),
			},
		});
		const response = await worker.fetch(request, env);

		expect(response.status).toBe(401);
		expect(await response.text()).toBe("API Token status: 'inactive'");
	});

	it('responds with 422 when IP is missing', async () => {
		mockVerify.mockResolvedValueOnce({ status: 'active' });

		const request = new Request('http://example.com/update?hostname=home.example.com', {
			headers: {
				Authorization: 'Basic ' + btoa('email@example.com:validtoken'),
			},
		});
		const response = await worker.fetch(request, env);

		expect(response.status).toBe(422);
		expect(await response.text()).toBe("Missing 'ip' parameter. Use ip=auto to use the client IP.");
	});

	it('responds with 500 when IP is set to auto and is missing', async () => {
		mockVerify.mockResolvedValueOnce({ status: 'active' });

		const request = new Request('http://example.com/update?hostname=home.example.com&ip=auto', {
			headers: {
				Authorization: 'Basic ' + btoa('email@example.com:validtoken'),
			},
		});
		const response = await worker.fetch(request, env);

		expect(response.status).toBe(500);
		expect(await response.text()).toBe('ip=auto specified but client IP could not be determined.');
	});

	it('responds with 422 when hostname parameter is missing', async () => {
		mockVerify.mockResolvedValueOnce({ status: 'active' });

		const request = new Request('http://example.com/update?ip=192.0.2.1', {
			headers: {
				Authorization: 'Basic ' + btoa('email@example.com:validtoken'),
			},
		});
		const response = await worker.fetch(request, env);

		expect(response.status).toBe(422);
		expect(await response.text()).toBe("Missing 'hostname' parameter.");
	});

	it('responds with 422 when hostname parameter is empty', async () => {
		mockVerify.mockResolvedValueOnce({ status: 'active' });

		const request = new Request('http://example.com/update?ip=192.0.2.1&hostnames=,', {
			headers: {
				Authorization: 'Basic ' + btoa('email@example.com:validtoken'),
			},
		});
		const response = await worker.fetch(request, env);

		expect(response.status).toBe(422);
		expect(await response.text()).toBe('No hostnames provided.');
	});

	it('responds with 200 on valid update', async () => {
		mockVerify.mockResolvedValueOnce({ status: 'active' });
		mockListZones.mockResolvedValueOnce({ result: [{ id: 'zone-id' }] });
		mockListRecords.mockResolvedValueOnce({ result: [{ id: 'record-id', name: 'home.example.com', type: 'A' }] });
		mockUpdateRecord.mockResolvedValueOnce({});

		const request = new Request('http://example.com/update?ip=192.0.2.1&hostname=home.example.com', {
			headers: {
				Authorization: 'Basic ' + btoa('email@example.com:validtoken'),
			},
		});
		const response = await worker.fetch(request, env);

		expect(response.status).toBe(200);
	});

	it('responds with 200 on valid update when IP is set to auto', async () => {
		mockVerify.mockResolvedValueOnce({ status: 'active' });
		mockListZones.mockResolvedValueOnce({ result: [{ id: 'zone-id' }] });
		mockListRecords.mockResolvedValueOnce({ result: [{ id: 'record-id', name: 'home.example.com', type: 'A' }] });
		mockUpdateRecord.mockResolvedValueOnce({});

		const request = new Request('http://example.com/update?ip=auto&hostname=home.example.com', {
			headers: {
				Authorization: 'Basic ' + btoa('email@example.com:validtoken'),
				'CF-Connecting-IP': '192.0.2.1',
			},
		});
		const response = await worker.fetch(request, env);

		expect(response.status).toBe(200);
	});

	it('responds with 400 when no zones are found', async () => {
		mockVerify.mockResolvedValueOnce({ status: 'active' });
		mockListZones.mockResolvedValueOnce({ result: [] });

		const request = new Request('http://example.com/update?ip=192.0.2.1&hostname=home.example.com', {
			headers: {
				Authorization: 'Basic ' + btoa('email@example.com:validtoken'),
			},
		});
		const response = await worker.fetch(request, env);

		expect(response.status).toBe(400);
		expect(await response.text()).toBe('No zones available in API Token.');
	});

	it('responds with 400 when multiple records are found', async () => {
		mockVerify.mockResolvedValueOnce({ status: 'active' });
		mockListZones.mockResolvedValueOnce({ result: [{ id: 'zone-id' }] });
		mockListRecords.mockResolvedValueOnce({
			result: [
				{ id: 'record-id1', name: 'home', type: 'A' },
				{ id: 'record-id2', name: 'home', type: 'A' },
			],
		});

		const request = new Request('http://example.com/update?ip=192.0.2.1&hostname=home', {
			headers: {
				Authorization: 'Basic ' + btoa('email@example.com:validtoken'),
			},
		});
		const response = await worker.fetch(request, env);

		expect(response.status).toBe(400);
		expect(await response.text()).toBe("Multiple matching records found for 'home'. Specify a unique hostname per zone.");
	});

	it('responds with 400 when no records are found', async () => {
		mockVerify.mockResolvedValueOnce({ status: 'active' });
		mockListZones.mockResolvedValueOnce({ result: [{ id: 'zone-id' }] });
		mockListRecords.mockResolvedValueOnce({ result: [] });

		const request = new Request('http://example.com/update?ip=192.0.2.1&hostname=home.example.com', {
			headers: {
				Authorization: 'Basic ' + btoa('email@example.com:validtoken'),
			},
		});
		const response = await worker.fetch(request, env);

		expect(response.status).toBe(400);
		expect(await response.text()).toBe("No matching record found for 'home.example.com'. Create it manually first.");
	});

	it('responds with 500 for an unforeseen internal server error', async () => {
		mockVerify.mockImplementationOnce(() => {
			throw new Error('Unexpected Error');
		});

		const request = new Request('http://example.com/update?ip=192.0.2.1&hostname=home.example.com', {
			headers: {
				Authorization: 'Basic ' + btoa('email@example.com:validtoken'),
			},
		});
		const response = await worker.fetch(request, env);

		expect(response.status).toBe(500);
		expect(await response.text()).toBe('Internal Server Error');
	});

	it('responds with 200 on valid IPv6 update', async () => {
		mockVerify.mockResolvedValueOnce({ status: 'active' });
		mockListZones.mockResolvedValueOnce({ result: [{ id: 'zone-id' }] });
		mockListRecords.mockResolvedValueOnce({ result: [{ id: 'record-id', name: 'home.example.com', type: 'AAAA' }] });
		mockUpdateRecord.mockResolvedValueOnce({});

		const request = new Request('http://example.com/update?ip=2001:0db8:85a3:0000:0000:8a2e:0370:7334&hostname=home.example.com', {
			headers: {
				Authorization: 'Basic ' + btoa('email@example.com:validtoken'),
			},
		});
		const response = await worker.fetch(request, env);

		expect(response.status).toBe(200);
	});

	it('responds with 200 on valid update for comma separated hostnames', async () => {
		mockVerify.mockResolvedValueOnce({ status: 'active' });
		mockListZones.mockResolvedValueOnce({ result: [{ id: 'zone-id' }] });
		mockListRecords
			.mockResolvedValueOnce({ result: [{ id: 'record-id1', name: 'home.example.com', type: 'A' }] })
			.mockResolvedValueOnce({ result: [{ id: 'record-id2', name: 'office.example.com', type: 'A' }] });
		mockUpdateRecord.mockResolvedValueOnce({}).mockResolvedValueOnce({});

		const request = new Request('http://example.com/update?ip=192.0.2.1&hostname=home.example.com,office.example.com', {
			headers: {
				Authorization: 'Basic ' + btoa('email@example.com:validtoken'),
			},
		});
		const response = await worker.fetch(request, env);

		expect(response.status).toBe(200);
		expect(mockListRecords).toHaveBeenCalledTimes(2);
		expect(mockUpdateRecord).toHaveBeenCalledTimes(2);
	});
});

describe('pushNtfy', () => {
	let fetchSpy: ReturnType<typeof vi.spyOn>;

	beforeEach(() => {
		fetchSpy = vi.spyOn(global as any, 'fetch').mockResolvedValue(new Response('OK'));
	});

	afterEach(() => {
		fetchSpy.mockRestore();
	});

	it('throws error when NTFY_URL is missing', async () => {
		const env = {} as unknown as Env;
		await expect(pushNtfy('Test message', env)).rejects.toThrow('NTFY_URL missing from env or empty');
	});

	it('throws error when NTFY_URL is empty', async () => {
		const env = { NTFY_URL: '' } as unknown as Env;
		await expect(pushNtfy('Test message', env)).rejects.toThrow('NTFY_URL missing from env or empty');
	});

	it('calls fetch with correct params when NTFY_URL is provided', async () => {
		const env = { NTFY_URL: 'https://ntfy.sh/example' } as unknown as Env;
		await pushNtfy('Hello ntfy', env);
		expect(fetchSpy).toHaveBeenCalledWith(env.NTFY_URL, {
			method: 'POST',
			body: 'Hello ntfy',
			headers: { 'Content-Type': 'text/plain' },
		});
	});

	it('handles fetch errors gracefully', async () => {
		const testError = new Error('Network error');
		fetchSpy.mockRejectedValueOnce(testError);
		const consoleSpy = vi.spyOn(console, 'error').mockImplementation(() => {});
		const env = { NTFY_URL: 'https://ntfy.sh/example' } as unknown as Env;
		await pushNtfy('Error test', env);
		expect(consoleSpy).toHaveBeenCalledWith('Failed to send ntfy push: ', testError);
		consoleSpy.mockRestore();
	});
});
