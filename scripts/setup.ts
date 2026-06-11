#!/usr/bin/env bun
import { $ } from 'bun';
import { CONFIG_PATHS, ENV_KEYS, HEX_ID_PATTERN, UUID_PATTERN, loadConfig } from './lib/wrangler-config';

/**
 * One-time interactive setup for a new deployment (fork or first clone).
 * Provisions the KV namespaces and D1 audit database this worker needs
 * (binding names read from wrangler.jsonc), writes their IDs and optional
 * secrets to .env.local (gitignored), and applies D1 migrations.
 *
 * After running this, `bun run deploy` works locally (it reads .env.local
 * and syncs worker secrets), and the same values can be added as GitHub
 * Actions secrets for CI deploys.
 */

function extractFirst(pattern: RegExp, output: string, label: string): string {
	const match = new RegExp(pattern.source).exec(output);
	if (!match) {
		console.error(`Could not find an ID in wrangler output for ${label}:`);
		console.error(output);
		process.exit(1);
	}
	return match[0];
}

async function main(): Promise<void> {
	if (process.env['CI'] === 'true') {
		console.error('setup is interactive and not meant for CI. CI deploys read GitHub Actions secrets.');
		process.exit(1);
	}

	const config = await loadConfig();
	const kvBinding = config.kv_namespaces?.[0]?.binding;
	const d1 = config.d1_databases?.[0];
	if (kvBinding === undefined || kvBinding === '' || d1 === undefined) {
		console.error('wrangler.jsonc is missing the KV namespace or D1 database entry');
		process.exit(1);
	}

	console.log('Checking wrangler authentication…');
	const whoami = await $`bun x wrangler whoami`.nothrow().quiet();
	if (whoami.exitCode !== 0 || whoami.text().includes('not authenticated')) {
		console.error('Not logged in. Run `bun x wrangler login` first.');
		process.exit(1);
	}

	// `wrangler whoami` lists account IDs; with one account, use it directly,
	// otherwise ask which to deploy into.
	const accountIds = [...new Set(whoami.text().match(HEX_ID_PATTERN) ?? [])];
	let accountId = accountIds.length === 1 ? accountIds[0] : undefined;
	if (accountId === undefined) {
		const entered = prompt(`Cloudflare account ID to deploy into${accountIds.length > 0 ? ` (one of: ${accountIds.join(', ')})` : ''}:`);
		if (entered === null || entered.trim() === '') {
			console.error('An account ID is required.');
			process.exit(1);
		}
		accountId = entered.trim();
	}
	console.log(`Using account ${accountId}`);
	process.env[ENV_KEYS.accountId] = accountId;

	if (await Bun.file(CONFIG_PATHS.envLocal).exists()) {
		const overwrite = confirm('.env.local already exists. Re-provision resources and overwrite it?');
		if (!overwrite) {
			console.log('Keeping existing .env.local; nothing to do.');
			return;
		}
	}

	console.log(`Creating KV namespace ${kvBinding}…`);
	const prod = await $`bun x wrangler kv namespace create ${kvBinding}`.text();
	const kvId = extractFirst(HEX_ID_PATTERN, prod, kvBinding);
	console.log(`  production: ${kvId}`);

	console.log('Creating preview KV namespace…');
	const preview = await $`bun x wrangler kv namespace create ${kvBinding} --preview`.text();
	const kvPreviewId = extractFirst(HEX_ID_PATTERN, preview, `${kvBinding} --preview`);
	console.log(`  preview: ${kvPreviewId}`);

	console.log(`Creating D1 database ${d1.database_name}…`);
	const d1Out = await $`bun x wrangler d1 create ${d1.database_name}`.nothrow().text();
	const d1Id = extractFirst(UUID_PATTERN, d1Out, d1.database_name);
	console.log(`  database: ${d1Id}`);

	// Locking the worker to your own devices: the key rides in the UniFi
	// Username field (or X-Access-Key header) and is checked before any
	// Cloudflare API call.
	let accessKey = '';
	if (confirm('Generate an access key so only your devices can use this worker? (recommended)')) {
		accessKey = crypto.randomUUID().replaceAll('-', '');
		console.log(`  access key: ${accessKey}`);
		console.log('  Put this in the UniFi Username field after deploying.');
	}

	const lines = [
		'# Local deployment configuration. Not committed.',
		'# The same values go in GitHub Actions secrets for CI deploys.',
		`${ENV_KEYS.accountId}=${accountId}`,
		`${ENV_KEYS.kvId}=${kvId}`,
		`${ENV_KEYS.kvPreviewId}=${kvPreviewId}`,
		`${ENV_KEYS.d1Id}=${d1Id}`,
		...(accessKey !== '' ? [`${ENV_KEYS.accessKey}=${accessKey}`] : []),
		'',
	];
	await Bun.write(CONFIG_PATHS.envLocal, lines.join('\n'));
	console.log(`Wrote ${CONFIG_PATHS.envLocal}`);

	console.log('Applying D1 migrations…');
	process.env[ENV_KEYS.kvId] = kvId;
	process.env[ENV_KEYS.kvPreviewId] = kvPreviewId;
	process.env[ENV_KEYS.d1Id] = d1Id;
	await $`bun scripts/deploy.ts --generate-only`;
	await $`bun x wrangler d1 migrations apply AUDIT_DB --remote --config ${CONFIG_PATHS.deploy}`;

	console.log('\nSetup complete. Next steps:');
	console.log('  - bun run deploy            (deploy from this machine; also syncs secrets)');
	console.log(`  - add ${ENV_KEYS.kvId}, ${ENV_KEYS.kvPreviewId}, ${ENV_KEYS.d1Id}, CLOUDFLARE_API_TOKEN,`);
	console.log(`    CLOUDFLARE_ACCOUNT_ID (and optionally ${ENV_KEYS.accessKey}) as GitHub Actions`);
	console.log('    secrets to deploy on every push to main.');
	console.log('  - notifications: append &ntfy=https://ntfy.sh/<topic> to your update URL (raw, not percent-encoded).');
}

await main();
