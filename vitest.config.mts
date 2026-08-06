import { cloudflareTest, readD1Migrations } from '@cloudflare/vitest-pool-workers';
import { defineConfig } from 'vitest/config';

// The real migrations, handed to the test worker so a suite can build the
// schema the deployment actually runs rather than a copy of it that drifts.
const migrations = await readD1Migrations('./migrations');

export default defineConfig({
	plugins: [
		cloudflareTest({
			wrangler: { configPath: './wrangler.jsonc' },
			miniflare: { bindings: { TEST_MIGRATIONS: migrations } },
		}),
	],
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
