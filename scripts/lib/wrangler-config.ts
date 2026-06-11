import { join } from 'node:path';
import { parse, stringify } from 'comment-json';

export interface KVNamespaceConfig {
	binding: string;
	id: string;
	preview_id: string;
}

export interface D1DatabaseConfig {
	binding: string;
	database_name: string;
	database_id: string;
	migrations_dir?: string;
}

export interface RouteConfig {
	pattern: string;
	custom_domain: boolean;
}

export interface WranglerConfig {
	[key: string]: unknown;
	name?: string;
	account_id?: string;
	kv_namespaces?: KVNamespaceConfig[];
	d1_databases?: D1DatabaseConfig[];
	routes?: RouteConfig[];
}

/** Repository root, derived from this file's location. */
export const REPO_ROOT: string = join(import.meta.dirname, '..', '..');

/** The committed config (placeholders only) and the generated deploy config. */
export const CONFIG_PATHS = {
	source: join(REPO_ROOT, 'wrangler.jsonc'),
	deploy: join(REPO_ROOT, 'wrangler.deploy.jsonc'),
	envLocal: join(REPO_ROOT, '.env.local'),
} as const;

/** Environment variable names shared by setup, deploy, and CI secrets. */
export const ENV_KEYS = {
	kvId: 'KV_NAMESPACE_ID',
	kvPreviewId: 'KV_NAMESPACE_PREVIEW_ID',
	d1Id: 'D1_DATABASE_ID',
	customDomain: 'CUSTOM_DOMAIN',
	accessKey: 'ACCESS_KEY',
	// Read natively by wrangler; never stored in config files.
	accountId: 'CLOUDFLARE_ACCOUNT_ID',
} as const;

/** Worker secrets that deploy syncs when present in the environment. */
export const OPTIONAL_WORKER_SECRETS = [ENV_KEYS.accessKey] as const;

/** Cloudflare account and KV namespace IDs are 32 hex characters. */
export const HEX_ID_PATTERN = /\b[0-9a-f]{32}\b/g;

/** D1 database IDs are UUIDs. */
export const UUID_PATTERN = /\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b/g;

/** Parses a JSONC config file, preserving comments for round-tripping. */
export async function loadConfig(configPath: string = CONFIG_PATHS.source): Promise<WranglerConfig> {
	const content: string = await Bun.file(configPath).text();
	return parse(content) as WranglerConfig;
}

/** Serializes a config back to JSONC with tabs, preserving comments. */
export function serializeConfig(config: WranglerConfig): string {
	return `${stringify(config, null, '\t')}\n`;
}
