import { SELF } from 'cloudflare:test';
import { describe, it, expect, vi, beforeEach, afterEach, beforeAll, afterAll } from 'vitest';
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
		const response = await SELF.fetch('http://example.com/update?ip=192.0.2.1&hostname=home.example.com');
		expect(response.status).toBe(401);
		expect(await response.text()).toBe('API Token missing.');
	});

	it('responds with 401 when token is missing after splitting the Authorization header', async () => {
		const response = await SELF.fetch('http://example.com/update?ip=192.0.2.1&hostname=home.example.com', {
			headers: {
				Authorization: 'Basic',
			},
		});
		expect(response.status).toBe(401);
		expect(await response.text()).toBe('Invalid API Token.');
	});

	it('responds with 401 when API token contains control characters', async () => {
		const badToken = btoa('email@example.com:\x00test');
		const response = await SELF.fetch('http://example.com/update?ip=192.0.2.1&hostname=home.example.com', {
			headers: {
				Authorization: 'Basic ' + badToken,
			},
		});
		expect(response.status).toBe(401);
		expect(await response.text()).toBe('Invalid API Token.');
	});

	it('responds with 401 when API token is invalid', async () => {
		const response = await SELF.fetch('http://example.com/update?ip=192.0.2.1&hostname=home.example.com', {
			headers: {
				// CodeQL [js/hardcoded-credentials] Suppressing hardcoded credential warning for test
				Authorization: 'Basic invalidtoken',
			},
		});
		expect(response.status).toBe(401);
		expect(await response.text()).toBe('Invalid API Token.');
	});

	it('responds with 401 when token is not active', async () => {
		mockVerify.mockResolvedValueOnce({ status: 'inactive' });

		const response = await SELF.fetch('http://example.com/update?ip=192.0.2.1&hostname=home.example.com', {
			headers: {
				Authorization: 'Basic ' + btoa('email@example.com:validtoken'),
			},
		});

		expect(response.status).toBe(401);
		expect(await response.text()).toBe('API Token status: inactive');
	});

	it('responds with 422 when IP is missing', async () => {
		mockVerify.mockResolvedValueOnce({ status: 'active' });
		const response = await SELF.fetch('http://example.com/update?hostname=home.example.com', {
			headers: {
				Authorization: 'Basic ' + btoa('email@example.com:validtoken'),
			},
		});
		expect(response.status).toBe(422);
		expect(await response.text()).toBe("Missing 'ip' parameter. Use ip=auto to use the client IP.");
	});

	it('responds with 500 when IP is set to auto and is missing', async () => {
		mockVerify.mockResolvedValueOnce({ status: 'active' });
		const response = await SELF.fetch('http://example.com/update?hostname=home.example.com&ip=auto', {
			headers: {
				Authorization: 'Basic ' + btoa('email@example.com:validtoken'),
			},
		});
		expect(response.status).toBe(500);
		expect(await response.text()).toBe('ip=auto specified but client IP could not be determined.');
	});

	it('responds with 422 when hostname is missing', async () => {
		mockVerify.mockResolvedValueOnce({ status: 'active' });
		const response = await SELF.fetch('http://example.com/update?ip=192.0.2.1', {
			headers: {
				Authorization: 'Basic ' + btoa('email@example.com:validtoken'),
			},
		});
		expect(response.status).toBe(422);
		expect(await response.text()).toBe("Missing 'hostname' parameter.");
	});

	it('responds with 200 on valid update', async () => {
		mockVerify.mockResolvedValueOnce({ status: 'active' });
		mockListZones.mockResolvedValueOnce({ result: [{ id: 'zone-id' }] });
		mockListRecords.mockResolvedValueOnce({ result: [{ id: 'record-id', name: 'home.example.com', type: 'A' }] });
		mockUpdateRecord.mockResolvedValueOnce({});

		const response = await SELF.fetch('http://example.com/update?ip=192.0.2.1&hostname=home.example.com', {
			headers: {
				Authorization: 'Basic ' + btoa('email@example.com:validtoken'),
			},
		});
		expect(response.status).toBe(200);
	});

	it('responds with 200 on valid update when IP is set to auto', async () => {
		mockVerify.mockResolvedValueOnce({ status: 'active' });
		mockListZones.mockResolvedValueOnce({ result: [{ id: 'zone-id' }] });
		mockListRecords.mockResolvedValueOnce({ result: [{ id: 'record-id', name: 'home.example.com', type: 'A' }] });
		mockUpdateRecord.mockResolvedValueOnce({});

		const response = await SELF.fetch('http://example.com/update?ip=auto&hostname=home.example.com', {
			headers: {
				Authorization: 'Basic ' + btoa('email@example.com:validtoken'),
				'CF-Connecting-IP': '192.0.2.1',
			},
		});
		expect(response.status).toBe(200);
	});

	it('responds with 400 when multiple zones are found', async () => {
		mockVerify.mockResolvedValueOnce({ status: 'active' });
		mockListZones.mockResolvedValueOnce({ result: [{ id: 'zone-id1' }, { id: 'zone-id2' }] });

		const response = await SELF.fetch('http://example.com/update?ip=192.0.2.1&hostname=home.example.com', {
			headers: {
				Authorization: 'Basic ' + btoa('email@example.com:validtoken'),
			},
		});

		expect(response.status).toBe(400);
		expect(await response.text()).toBe('Multiple zones found; API Token must be scoped to a single zone.');
	});

	it('responds with 400 when no zones are found', async () => {
		mockVerify.mockResolvedValueOnce({ status: 'active' });
		mockListZones.mockResolvedValueOnce({ result: [] });

		const response = await SELF.fetch('http://example.com/update?ip=192.0.2.1&hostname=home.example.com', {
			headers: {
				Authorization: 'Basic ' + btoa('email@example.com:validtoken'),
			},
		});

		expect(response.status).toBe(400);
		expect(await response.text()).toBe('No zones found; API Token must be scoped to a single zone.');
	});

	it('responds with 400 when multiple records are found', async () => {
		mockVerify.mockResolvedValueOnce({ status: 'active' });
		mockListZones.mockResolvedValueOnce({ result: [{ id: 'zone-id' }] });
		mockListRecords.mockResolvedValueOnce({
			result: [
				{ id: 'record-id1', name: 'home.example.com', type: 'A' },
				{ id: 'record-id2', name: 'home.example.com', type: 'A' },
			],
		});

		const response = await SELF.fetch('http://example.com/update?ip=192.0.2.1&hostname=home.example.com', {
			headers: {
				Authorization: 'Basic ' + btoa('email@example.com:validtoken'),
			},
		});

		expect(response.status).toBe(400);
		expect(await response.text()).toBe('Multiple matching records found for home.example.com.');
	});

	it('responds with 400 when no records are found', async () => {
		mockVerify.mockResolvedValueOnce({ status: 'active' });
		mockListZones.mockResolvedValueOnce({ result: [{ id: 'zone-id' }] });
		mockListRecords.mockResolvedValueOnce({ result: [] });

		const response = await SELF.fetch('http://example.com/update?ip=192.0.2.1&hostname=home.example.com', {
			headers: {
				Authorization: 'Basic ' + btoa('email@example.com:validtoken'),
			},
		});

		expect(response.status).toBe(400);
		expect(await response.text()).toBe('No matching record found for home.example.com. Create it manually first.');
	});

	it('responds with 500 for an unforeseen internal server error', async () => {
		mockVerify.mockImplementationOnce(() => {
			throw new Error('Unexpected Error');
		});

		const response = await SELF.fetch('http://example.com/update?ip=192.0.2.1&hostname=home.example.com', {
			headers: {
				Authorization: 'Basic ' + btoa('email@example.com:validtoken'),
			},
		});

		expect(response.status).toBe(500);
		expect(await response.text()).toBe('Internal Server Error');
	});

	it('responds with 200 on valid IPv6 update', async () => {
		mockVerify.mockResolvedValueOnce({ status: 'active' });
		mockListZones.mockResolvedValueOnce({ result: [{ id: 'zone-id' }] });
		mockListRecords.mockResolvedValueOnce({ result: [{ id: 'record-id', name: 'home.example.com', type: 'AAAA' }] });
		mockUpdateRecord.mockResolvedValueOnce({});

		const response = await SELF.fetch('http://example.com/update?ip=2001:0db8:85a3:0000:0000:8a2e:0370:7334&hostname=home.example.com', {
			headers: {
				Authorization: 'Basic ' + btoa('email@example.com:validtoken'),
			},
		});
		expect(response.status).toBe(200);
	});

	it('responds with 200 on valid update for comma separated hostnames', async () => {
		mockVerify.mockResolvedValueOnce({ status: 'active' });
		mockListZones.mockResolvedValueOnce({ result: [{ id: 'zone-id' }] });
		mockListRecords
			.mockResolvedValueOnce({ result: [{ id: 'record-id1', name: 'home.example.com', type: 'A' }] })
			.mockResolvedValueOnce({ result: [{ id: 'record-id2', name: 'office.example.com', type: 'A' }] });
		mockUpdateRecord.mockResolvedValueOnce({}).mockResolvedValueOnce({});

		const response = await SELF.fetch('http://example.com/update?ip=192.0.2.1&hostname=home.example.com,office.example.com', {
			headers: {
				Authorization: 'Basic ' + btoa('email@example.com:validtoken'),
			},
		});
		expect(response.status).toBe(200);
		expect(mockListRecords).toHaveBeenCalledTimes(2);
		expect(mockUpdateRecord).toHaveBeenCalledTimes(2);
	});

	it('responds with 500 when NTFY_URL is missing from env', async () => {
		mockVerify.mockResolvedValueOnce({ status: 'active' });
		mockListZones.mockResolvedValueOnce({ result: [{ id: 'zone-id' }] });
		mockListRecords.mockResolvedValueOnce({ result: [{ id: 'record-id', name: 'home.example.com', type: 'A' }] });
		mockUpdateRecord.mockResolvedValueOnce({});

		const envWithoutNtfy = {};

		const response = await SELF.fetch('http://example.com/update?ip=192.0.2.1&hostname=home.example.com', {
			headers: {
				Authorization: 'Basic ' + btoa('email@example.com:validtoken'),
			},
			bindings: envWithoutNtfy,
		} as any);

		expect(response.status).toBe(500);
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

	it('does nothing if NTFY_URL is not provided', async () => {
		const env = {} as unknown as Env;
		await pushNtfy('Test message', env);
		expect(fetchSpy).not.toHaveBeenCalled();
	});

	it('calls fetch with correct params when NTFY_URL is provided', async () => {
		const env = { NTFY_URL: 'http://ntfy.example.com' } as unknown as Env;
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
		const env = { NTFY_URL: 'http://ntfy.example.com' } as unknown as Env;
		await pushNtfy('Error test', env);
		expect(consoleSpy).toHaveBeenCalledWith('Failed to send ntfy push: ', testError);
		consoleSpy.mockRestore();
	});
});
