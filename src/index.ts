import { Cloudflare, type ClientOptions } from 'cloudflare';
import { pushNtfy } from './pushNtfy';

/**
 * A DNS record this worker manages. Narrower than the SDK's record types:
 * every field is required because the worker constructs them itself.
 */
interface DDNSRecord {
	content: string;
	name: string;
	type: 'A' | 'AAAA';
	ttl: number;
}

interface UpdateRequest {
	records: DDNSRecord[];
	/** Optional explicit zone scoping via the `zone` query parameter. */
	zoneFilter: string | null;
}

// KV is a pure cache; DNS itself is the source of truth for the last IP.
// Entries expire so stale identities can never accumulate (issue #151), at
// the cost of one redundant API round-trip per record per TTL window.
const KV_KEY_PREFIX = 'ip';
const KV_TTL_SECONDS = 30 * 24 * 60 * 60;

interface CachedIp {
	ip: string;
	updatedAt: string;
}

function cacheKey(record: DDNSRecord): string {
	return `${KV_KEY_PREFIX}:${record.name}:${record.type}`;
}

export class HttpError extends Error {
	constructor(
		public readonly statusCode: number,
		message: string,
	) {
		super(message);
		this.name = new.target.name;
		Object.setPrototypeOf(this, new.target.prototype);
	}
}

interface RecordResult {
	hostname: string;
	type: string;
	ip: string;
	updated: boolean;
}

interface UpdateResponseBody {
	success: boolean;
	message: string;
	data: {
		updated: boolean;
		records: RecordResult[];
	};
}

function jsonResponse(body: UpdateResponseBody | { success: false; error: string }, status: number): Response {
	return new Response(JSON.stringify(body), {
		status,
		headers: { 'Content-Type': 'application/json' },
	});
}

/**
 * Extracts the Cloudflare API token from the Authorization header.
 *
 * Two forms are accepted:
 * - `Basic base64(username:token)`: what UniFi devices send. The username is
 *   ignored; only the DNS-scoped API token matters.
 * - `Bearer token`: the raw token, for direct callers.
 */
function constructClientOptions(request: Request): ClientOptions {
	const authHeader = request.headers.get('Authorization');
	if (authHeader === null || authHeader === '') {
		throw new HttpError(401, 'Authorization required.');
	}

	const [scheme, payload] = authHeader.split(' ');
	if (payload === undefined || payload === '') {
		throw new HttpError(401, 'Invalid authorization credentials.');
	}

	if (scheme === 'Bearer') {
		return { apiToken: payload };
	}

	if (scheme !== 'Basic') {
		throw new HttpError(401, 'Invalid authorization credentials.');
	}

	let decoded: string;
	try {
		decoded = atob(payload);
	} catch {
		throw new HttpError(401, 'Invalid authorization credentials.');
	}

	const delimiterIndex = decoded.indexOf(':');
	// eslint-disable-next-line no-control-regex
	if (delimiterIndex === -1 || /[\0-\x1F\x7F]/.test(decoded)) {
		throw new HttpError(401, 'Invalid authorization credentials.');
	}

	const token = decoded.slice(delimiterIndex + 1);
	if (token === '') {
		throw new HttpError(401, 'Invalid authorization credentials.');
	}

	return { apiToken: token };
}

function constructDNSRecords(request: Request): UpdateRequest {
	const { searchParams } = new URL(request.url);
	let ip = (searchParams.get('ip') ?? searchParams.get('myip'))?.trim() ?? null;
	const ip6 = searchParams.get('ip6')?.trim() ?? null;
	const hostnameParam = (searchParams.get('hostnames') ?? searchParams.get('hostname'))?.trim() ?? null;
	const zoneFilter = searchParams.get('zone')?.trim() ?? null;

	if (ip === null || ip === '') {
		throw new HttpError(422, "Missing 'ip' parameter. Use ip=auto to use the client IP.");
	} else if (ip === 'auto') {
		ip = request.headers.get('CF-Connecting-IP');
		if (ip === null || ip === '') {
			throw new HttpError(500, 'ip=auto specified but client IP could not be determined.');
		}
	}

	if (ip6 !== null && ip6 !== '' && !ip6.includes(':')) {
		throw new HttpError(422, "The 'ip6' parameter must be a valid IPv6 address.");
	}

	if (hostnameParam === null || hostnameParam === '') {
		throw new HttpError(422, "Missing 'hostname' parameter.");
	}
	const hostnames = hostnameParam
		.split(',')
		.map((s) => s.trim())
		.filter(Boolean);
	if (hostnames.length === 0) {
		throw new HttpError(422, 'No hostnames provided.');
	}

	// One record per hostname, plus an AAAA per hostname for dual-stack
	// callers that supply ip6 alongside an IPv4 ip.
	const records: DDNSRecord[] = [];
	for (const hostname of hostnames) {
		records.push({
			content: ip,
			name: hostname,
			type: ip.includes('.') ? 'A' : 'AAAA',
			ttl: 1,
		});
		if (ip6 !== null && ip6 !== '') {
			records.push({
				content: ip6,
				name: hostname,
				type: 'AAAA',
				ttl: 1,
			});
		}
	}

	return { records, zoneFilter: zoneFilter === '' ? null : zoneFilter };
}

/** Reads a record's cached IP; any failure or unparseable entry is a miss. */
async function readCachedIp(env: Env, record: DDNSRecord): Promise<string | null> {
	try {
		const raw = await env.DDNS_KV.get(cacheKey(record));
		if (raw === null) return null;
		const parsed = JSON.parse(raw) as Partial<CachedIp>;
		return typeof parsed.ip === 'string' ? parsed.ip : null;
	} catch (error) {
		console.error(`Failed to read IP cache for ${cacheKey(record)}:`, error);
		return null;
	}
}

/** Caches a record's IP with a TTL so stale entries clean themselves up. */
async function writeCachedIp(env: Env, record: DDNSRecord): Promise<void> {
	const value: CachedIp = { ip: record.content, updatedAt: new Date().toISOString() };
	try {
		await env.DDNS_KV.put(cacheKey(record), JSON.stringify(value), { expirationTtl: KV_TTL_SECONDS });
	} catch (error) {
		console.error(`Failed to write IP cache for ${cacheKey(record)}:`, error);
		// The cache is an optimization; the update already succeeded.
	}
}

async function updateHostnames(clientOptions: ClientOptions, updateRequest: UpdateRequest, env: Env): Promise<Response> {
	const { records, zoneFilter } = updateRequest;
	const cloudflare = new Cloudflare(clientOptions);

	// Verify token status
	const { status: tokenStatus } = await cloudflare.user.tokens.verify();
	if (tokenStatus !== 'active') {
		throw new HttpError(401, `Authentication failed: token ${tokenStatus}`);
	}

	// Fast path: when every record's cached IP already matches, skip the
	// zone and record API calls entirely.
	const cachedIps = await Promise.all(records.map(async (record) => readCachedIp(env, record)));
	const pending = records.filter((record, i) => cachedIps[i] !== record.content);
	if (pending.length === 0) {
		console.log('All records match their cached IPs. Skipping DNS update and notification.');
		return jsonResponse(
			{
				success: true,
				message: 'No IP change detected',
				data: {
					updated: false,
					records: records.map((r) => ({ hostname: r.name, type: r.type, ip: r.content, updated: false })),
				},
			},
			200,
		);
	}

	let { result: zones } = await cloudflare.zones.list();
	if (zoneFilter !== null) {
		zones = zones.filter((zone) => zone.name === zoneFilter);
		if (zones.length === 0) {
			throw new HttpError(400, `Zone '${zoneFilter}' not available with current permissions.`);
		}
	}
	if (zones.length === 0) {
		throw new HttpError(400, 'No zones available with current permissions.');
	}

	const updateMessages: string[] = [];
	const results: RecordResult[] = [];

	for (const record of records) {
		if (!pending.includes(record)) {
			results.push({ hostname: record.name, type: record.type, ip: record.content, updated: false });
			continue;
		}

		// Retrieve the matching DNS record across the visible zones
		const matches: {
			id: string;
			content: string | undefined;
			proxied: boolean;
			comment: string | undefined;
			ttl: number;
			zoneId: string;
		}[] = [];
		for (const zone of zones) {
			const { result: existing } = await cloudflare.dns.records.list({
				zone_id: zone.id,
				name: record.name as Cloudflare.DNS.Records.RecordListParams.Name,
				type: record.type,
			});
			matches.push(
				...existing
					.filter((rec) => rec.id)
					.map((rec) => ({
						id: rec.id,
						content: rec.content,
						// The SDK types mark proxied/ttl required, but the live API
						// can omit them; default at the boundary.
						proxied: rec.proxied ?? false,
						comment: rec.comment,
						ttl: rec.ttl ?? 1,
						zoneId: zone.id,
					})),
			);
		}

		const match = matches[0];
		if (match === undefined) {
			throw new HttpError(400, `No matching record found for '${record.name}'. Create it manually first.`);
		}
		if (matches.length > 1) {
			throw new HttpError(400, `Multiple matching records found for '${record.name}'. Specify a unique hostname per zone.`);
		}

		// Notifications key off the actual DNS delta, never the cache: a
		// cache miss on an unchanged record refreshes silently.
		const changed = match.content !== record.content;
		if (changed) {
			await cloudflare.dns.records.update(match.id, {
				content: record.content,
				zone_id: match.zoneId,
				name: record.name,
				type: record.type,
				proxied: match.proxied,
				comment: match.comment,
				ttl: match.ttl,
			});

			const successMsg = `DNS record for '${record.name}' ('${record.type}') updated to '${record.content}'`;
			console.log(successMsg);
			updateMessages.push(successMsg);
		} else {
			console.log(`DNS record for '${record.name}' ('${record.type}') already at '${record.content}'. Refreshing cache only.`);
		}

		await writeCachedIp(env, record);
		results.push({ hostname: record.name, type: record.type, ip: record.content, updated: changed });
	}

	// Send one grouped notification for the records that actually changed
	await pushNtfy(updateMessages, env);

	const anyUpdated = updateMessages.length > 0;
	return jsonResponse(
		{
			success: true,
			message: anyUpdated ? 'DNS records updated successfully' : 'DNS records already current',
			data: {
				updated: anyUpdated,
				records: results,
			},
		},
		200,
	);
}

export default {
	async fetch(request: Request, env: Env): Promise<Response> {
		// The handler only consumes query params; never log request bodies
		// (unauthenticated callers could write arbitrary content into logs).
		console.log('Incoming request:', {
			ip: request.headers.get('CF-Connecting-IP'),
			method: request.method,
			url: request.url,
		});

		try {
			const clientOptions = constructClientOptions(request);
			const updateRequest = constructDNSRecords(request);
			return await updateHostnames(clientOptions, updateRequest, env);
		} catch (err: unknown) {
			const isHttpError = err instanceof HttpError;
			const message = isHttpError ? err.message : 'Internal Server Error';
			const statusCode = isHttpError ? err.statusCode : 500;
			console.error(`Error updating DNS record: ${message}`, err);
			return jsonResponse({ success: false, error: message }, statusCode);
		}
	},
} satisfies ExportedHandler<Env>;
