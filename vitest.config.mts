import { cloudflareTest } from '@cloudflare/vitest-pool-workers';
import { defineConfig } from 'vitest/config';

export default defineConfig({
	plugins: [cloudflareTest({ wrangler: { configPath: './wrangler.jsonc' } })],
	test: {
		// The first Durable Object call in a run pays for the namespace starting
		// up, which can outlast the 5s default on a cold or loaded machine.
		testTimeout: 15_000,
		coverage: {
			provider: 'istanbul',
			reporter: ['text', 'json-summary', 'json'],
			reportOnFailure: true,
			include: ['src/**/*.ts'],
		},
	},
});
