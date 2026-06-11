import { Cloudflare } from 'cloudflare';
import { HISTORY_DEFAULT_LIMIT, queryHistory, writeAuditEvents, type AuditEvent } from './audit';
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

interface HistoryResponseBody {
	success: boolean;
	data: {
		events: Record<string, unknown>[];
	};
}

function jsonResponse(body: UpdateResponseBody | HistoryResponseBody | { success: false; error: string }, status: number): Response {
	return new Response(JSON.stringify(body), {
		status,
		headers: { 'Content-Type': 'application/json' },
	});
}

interface ParsedAuth {
	/** The Basic username, when one was sent. Carries the access key for UniFi callers. */
	username: string | null;
	/** The Cloudflare API token. */
	token: string;
}

/**
 * Extracts credentials from the Authorization header.
 *
 * Two forms are accepted:
 * - `Basic base64(username:token)`: what UniFi devices send. The username
 *   carries the access key when one is configured; auth itself only uses
 *   the DNS-scoped API token.
 * - `Bearer token`: the raw token, for direct callers.
 */
function parseAuthorization(request: Request): ParsedAuth {
	const authHeader = request.headers.get('Authorization');
	if (authHeader === null || authHeader === '') {
		throw new HttpError(401, 'Authorization required.');
	}

	const [scheme, payload] = authHeader.split(' ');
	if (payload === undefined || payload === '') {
		throw new HttpError(401, 'Invalid authorization credentials.');
	}

	if (scheme === 'Bearer') {
		return { username: null, token: payload };
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

	return { username: decoded.slice(0, delimiterIndex), token };
}

/** Constant-time string comparison via digest equality. */
async function timingSafeEquals(a: string, b: string): Promise<boolean> {
	const encoder = new TextEncoder();
	const [digestA, digestB] = await Promise.all([
		crypto.subtle.digest('SHA-256', encoder.encode(a)),
		crypto.subtle.digest('SHA-256', encoder.encode(b)),
	]);
	return crypto.subtle.timingSafeEqual(digestA, digestB);
}

/**
 * Optional pre-auth gate. When the ACCESS_KEY secret is set, callers must
 * present it in the Basic username (UniFi's Username field) or an
 * X-Access-Key header. Checked before any Cloudflare API call, KV read, or
 * D1 write, so strangers cost nothing beyond the worker invocation.
 */
async function checkAccess(env: Env, request: Request, auth: ParsedAuth): Promise<void> {
	if (!env.ACCESS_KEY) {
		return;
	}
	const provided = request.headers.get('X-Access-Key') ?? auth.username;
	if (provided === null || provided === '' || !(await timingSafeEquals(provided, env.ACCESS_KEY))) {
		throw new HttpError(401, 'Access denied.');
	}
}

interface ResolvedIps {
	v4: string | null;
	v6: string | null;
}

/**
 * Resolves the requested IPs from the ip4/ip6 parameters.
 *
 * Literals are validated against their address family. `auto` takes the
 * connecting IP only when it matches the slot's family and silently skips
 * the slot otherwise: dual-stack callers (UniFi may dial over either
 * family) can request both without flapping.
 */
function resolveIps(searchParams: URLSearchParams, request: Request): ResolvedIps {
	const raw4 = searchParams.get('ip4')?.trim() ?? null;
	const raw6 = searchParams.get('ip6')?.trim() ?? null;
	const connectingIp = request.headers.get('CF-Connecting-IP');

	let v4: string | null = null;
	if (raw4 !== null && raw4 !== '') {
		if (raw4 === 'auto') {
			if (connectingIp?.includes('.')) {
				v4 = connectingIp;
			} else {
				console.log('ip4=auto requested but the client did not connect over IPv4; skipping A records.');
			}
		} else if (!raw4.includes('.')) {
			throw new HttpError(422, "The 'ip4' parameter must be a valid IPv4 address.");
		} else {
			v4 = raw4;
		}
	}

	let v6: string | null = null;
	if (raw6 !== null && raw6 !== '') {
		if (raw6 === 'auto') {
			if (connectingIp?.includes(':')) {
				v6 = connectingIp;
			} else {
				console.log('ip6=auto requested but the client did not connect over IPv6; skipping AAAA records.');
			}
		} else if (!raw6.includes(':')) {
			throw new HttpError(422, "The 'ip6' parameter must be a valid IPv6 address.");
		} else {
			v6 = raw6;
		}
	}

	if (v4 === null && v6 === null) {
		throw new HttpError(422, "Missing IP. Provide 'ip4' and/or 'ip6'; 'auto' uses the client IP.");
	}

	return { v4, v6 };
}

function constructDNSRecords(request: Request): UpdateRequest {
	const { searchParams } = new URL(request.url);
	const { v4, v6 } = resolveIps(searchParams, request);
	const hostnameParam = searchParams.get('hostnames')?.trim() ?? null;
	const zoneFilter = searchParams.get('zone')?.trim() ?? null;

	if (hostnameParam === null || hostnameParam === '') {
		throw new HttpError(422, "Missing 'hostnames' parameter.");
	}
	const hostnames = hostnameParam
		.split(',')
		.map((s) => s.trim())
		.filter(Boolean);
	if (hostnames.length === 0) {
		throw new HttpError(422, 'No hostnames provided.');
	}

	// Per hostname: an A record when ip4 resolved, an AAAA when ip6 did.
	const records: DDNSRecord[] = [];
	for (const hostname of hostnames) {
		if (v4 !== null) {
			records.push({ content: v4, name: hostname, type: 'A', ttl: 1 });
		}
		if (v6 !== null) {
			records.push({ content: v6, name: hostname, type: 'AAAA', ttl: 1 });
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

/** Verifies the token is active and returns its ID (the audit tenant key). */
async function verifyToken(cloudflare: Cloudflare): Promise<string> {
	const verification = await cloudflare.user.tokens.verify();
	if (verification.status !== 'active') {
		throw new HttpError(401, `Authentication failed: token ${verification.status}`);
	}
	return verification.id;
}

async function updateHostnames(
	auth: ParsedAuth,
	updateRequest: UpdateRequest,
	request: Request,
	env: Env,
	ctx: ExecutionContext,
): Promise<Response> {
	const { records, zoneFilter } = updateRequest;
	const cloudflare = new Cloudflare({ apiToken: auth.token });
	const tokenId = await verifyToken(cloudflare);

	// Fast path: when every record's cached IP already matches, skip the
	// zone and record API calls entirely. Deliberately unaudited: nothing
	// was touched, and polling devices would add hundreds of rows per day.
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

	const callerIp = request.headers.get('CF-Connecting-IP');
	const updateMessages: string[] = [];
	const results: RecordResult[] = [];
	const auditEvents: AuditEvent[] = [];

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

		// Notifications and audit rows key off the actual DNS delta, never
		// the cache: a cache miss on an unchanged record refreshes silently.
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
		auditEvents.push({
			occurredAt: new Date().toISOString(),
			tokenId,
			callerIp,
			hostname: record.name,
			recordType: record.type,
			previousIp: match.content ?? null,
			newIp: record.content,
			outcome: changed ? 'updated' : 'no-change',
		});
	}

	// Audit writes ride after the response; a D1 hiccup never fails the update.
	ctx.waitUntil(writeAuditEvents(env, auditEvents));

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

/** GET /history: the caller's own audit rows, newest first. */
async function handleHistory(auth: ParsedAuth, request: Request, env: Env): Promise<Response> {
	const cloudflare = new Cloudflare({ apiToken: auth.token });
	const tokenId = await verifyToken(cloudflare);

	const { searchParams } = new URL(request.url);
	const hostname = searchParams.get('hostname')?.trim() ?? null;
	const limitParam = Number(searchParams.get('limit') ?? HISTORY_DEFAULT_LIMIT);
	const limit = Number.isFinite(limitParam) ? limitParam : HISTORY_DEFAULT_LIMIT;

	const events = await queryHistory(env, { tokenId, hostname, limit });
	return jsonResponse({ success: true, data: { events } }, 200);
}

export default {
	async fetch(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
		// The handler only consumes query params; never log request bodies
		// (unauthenticated callers could write arbitrary content into logs).
		console.log('Incoming request:', {
			ip: request.headers.get('CF-Connecting-IP'),
			method: request.method,
			url: request.url,
		});

		try {
			const auth = parseAuthorization(request);
			await checkAccess(env, request, auth);

			const { pathname } = new URL(request.url);
			if (pathname === '/history') {
				if (request.method !== 'GET') {
					throw new HttpError(405, 'Method not allowed.');
				}
				return await handleHistory(auth, request, env);
			}

			const updateRequest = constructDNSRecords(request);
			return await updateHostnames(auth, updateRequest, request, env, ctx);
		} catch (err: unknown) {
			const isHttpError = err instanceof HttpError;
			const message = isHttpError ? err.message : 'Internal Server Error';
			const statusCode = isHttpError ? err.statusCode : 500;
			console.error(`Error handling request: ${message}`, err);
			return jsonResponse({ success: false, error: message }, statusCode);
		}
	},
} satisfies ExportedHandler<Env>;
