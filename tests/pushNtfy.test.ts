import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { pushNtfy } from '../src/pushNtfy';
import { createMockEnv } from './helpers/mocks';

describe('pushNtfy', () => {
	let env: Env;

	beforeEach(() => {
		env = createMockEnv();
		vi.spyOn(console, 'error').mockImplementation(() => {});
		vi.spyOn(console, 'log').mockImplementation(() => {});
		vi.stubGlobal('fetch', vi.fn());
	});

	afterEach(() => {
		vi.restoreAllMocks();
		vi.unstubAllGlobals();
	});

	// -------------------------------------------------------------------------
	// Environment validation
	// -------------------------------------------------------------------------

	describe('Environment validation', () => {
		it('skips notification when NTFY_URL is empty', async () => {
			env.NTFY_URL = '';
			const mockFetch = vi.mocked(fetch);

			await expect(pushNtfy('test message', env)).resolves.toBeUndefined();

			expect(mockFetch).not.toHaveBeenCalled();
		});

		it('skips notification when NTFY_URL is undefined', async () => {
			// @ts-expect-error - Testing undefined scenario
			delete env.NTFY_URL;
			const mockFetch = vi.mocked(fetch);

			await expect(pushNtfy('test message', env)).resolves.toBeUndefined();

			expect(mockFetch).not.toHaveBeenCalled();
		});
	});

	// -------------------------------------------------------------------------
	// Message handling
	// -------------------------------------------------------------------------

	describe('Message handling', () => {
		it('sends a single string message as-is', async () => {
			const mockFetch = vi.mocked(fetch);
			mockFetch.mockResolvedValueOnce(new Response('OK'));

			await pushNtfy('Single notification message', env);

			expect(mockFetch).toHaveBeenCalledWith(env.NTFY_URL, {
				method: 'POST',
				body: 'Single notification message',
				headers: { 'Content-Type': 'text/plain' },
				signal: expect.any(AbortSignal),
			});
			expect(mockFetch).toHaveBeenCalledTimes(1);
		});

		it('sends a single-element array as a plain message', async () => {
			const mockFetch = vi.mocked(fetch);
			mockFetch.mockResolvedValueOnce(new Response('OK'));

			await pushNtfy(['Single message in array'], env);

			expect(mockFetch).toHaveBeenCalledWith(env.NTFY_URL, {
				method: 'POST',
				body: 'Single message in array',
				headers: { 'Content-Type': 'text/plain' },
				signal: expect.any(AbortSignal),
			});
			expect(mockFetch).toHaveBeenCalledTimes(1);
		});

		it('formats a two-element array as a grouped notification', async () => {
			const mockFetch = vi.mocked(fetch);
			mockFetch.mockResolvedValueOnce(new Response('OK'));

			const messages = ['First update', 'Second update'];

			await pushNtfy(messages, env);

			const expectedBody = `DNS Records Updated:
• First update
• Second update`;

			expect(mockFetch).toHaveBeenCalledWith(env.NTFY_URL, {
				method: 'POST',
				body: expectedBody,
				headers: { 'Content-Type': 'text/plain' },
				signal: expect.any(AbortSignal),
			});
			expect(mockFetch).toHaveBeenCalledTimes(1);
		});

		it('formats a multi-element array as a grouped notification', async () => {
			const mockFetch = vi.mocked(fetch);
			mockFetch.mockResolvedValueOnce(new Response('OK'));

			const messages = ['First DNS update', 'Second DNS update', 'Third DNS update'];

			await pushNtfy(messages, env);

			const expectedBody = `DNS Records Updated:
• First DNS update
• Second DNS update
• Third DNS update`;

			expect(mockFetch).toHaveBeenCalledWith(env.NTFY_URL, {
				method: 'POST',
				body: expectedBody,
				headers: { 'Content-Type': 'text/plain' },
				signal: expect.any(AbortSignal),
			});
			expect(mockFetch).toHaveBeenCalledTimes(1);
		});

		it('skips notification for an empty array', async () => {
			const mockFetch = vi.mocked(fetch);

			await pushNtfy([], env);

			expect(mockFetch).not.toHaveBeenCalled();
		});

		it('skips notification for a single-element array containing undefined', async () => {
			const mockFetch = vi.mocked(fetch);

			// @ts-expect-error - Testing undefined scenario
			await pushNtfy([undefined], env);

			expect(mockFetch).not.toHaveBeenCalled();
		});
	});

	// -------------------------------------------------------------------------
	// Error handling
	// -------------------------------------------------------------------------

	describe('Error handling', () => {
		it('handles a fetch network error without throwing', async () => {
			const mockFetch = vi.mocked(fetch);
			mockFetch.mockRejectedValueOnce(new Error('Network error'));

			await expect(pushNtfy('Test message', env)).resolves.not.toThrow();

			expect(mockFetch).toHaveBeenCalledTimes(1);
		});

		it('handles a fetch timeout error without throwing', async () => {
			const mockFetch = vi.mocked(fetch);
			mockFetch.mockRejectedValueOnce(new Error('Request timeout'));

			await expect(pushNtfy('Test message', env)).resolves.not.toThrow();

			expect(mockFetch).toHaveBeenCalledTimes(1);
		});

		it('handles an HTTP error response without throwing', async () => {
			const mockFetch = vi.mocked(fetch);
			mockFetch.mockResolvedValueOnce(
				new Response('Server Error', {
					status: 500,
					statusText: 'Internal Server Error',
				}),
			);

			await expect(pushNtfy('Test message', env)).resolves.not.toThrow();

			expect(mockFetch).toHaveBeenCalledTimes(1);
		});
	});

	// -------------------------------------------------------------------------
	// Integration scenarios
	// -------------------------------------------------------------------------

	describe('Integration scenarios', () => {
		it('sends notification to the configured NTFY_URL', async () => {
			const mockFetch = vi.mocked(fetch);
			mockFetch.mockResolvedValueOnce(
				new Response('Message sent', {
					status: 200,
					statusText: 'OK',
				}),
			);

			await pushNtfy('Integration test message', env);

			expect(mockFetch).toHaveBeenCalledWith('https://ntfy.example.com/test-topic', {
				method: 'POST',
				body: 'Integration test message',
				headers: { 'Content-Type': 'text/plain' },
				signal: expect.any(AbortSignal),
			});
		});

		it('sends notification to a custom NTFY_URL', async () => {
			const mockFetch = vi.mocked(fetch);
			mockFetch.mockResolvedValueOnce(new Response('OK'));

			env.NTFY_URL = 'https://custom.ntfy.server/my-topic';

			await pushNtfy('Custom server test', env);

			expect(mockFetch).toHaveBeenCalledWith('https://custom.ntfy.server/my-topic', {
				method: 'POST',
				body: 'Custom server test',
				headers: { 'Content-Type': 'text/plain' },
				signal: expect.any(AbortSignal),
			});
		});
	});
});
