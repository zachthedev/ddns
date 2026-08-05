import { AuthenticationError, BadRequestError, Cloudflare, PermissionDeniedError } from 'cloudflare';
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
	/** Optional per-caller notification target via the `ntfy` query parameter. */
	ntfyUrl: string | null;
}

const NTFY_URL_MAX_LENGTH = 512;

// The bound is on records, not hostnames, because the ip4 and ip6 slots each
// turn one hostname into a record and the cost follows records. One record
// spends a KV read, a records.list per candidate zone, an update when the IP
// moved, and a KV write, so 40 stays inside the 1000 subrequest ceiling even
// with several nested zones on the token. Batches this size need the paid
// plan; the free ceiling of 50 subrequests fits roughly six records.
const RECORDS_MAX = 40;

// RFC 1035: 253 characters for a full domain name. An over-long name also
// pushes the KV key past its own limit, which turns the cache into a
// permanent miss for that record.
const HOSTNAME_MAX_LENGTH = 253;

// Letters, digits and hyphens per label, with an optional wildcard leader.
// Query parameters arrive percent-decoded, so without this a newline inside
// a hostname reaches the log lines that quote it. IDNs belong here in their
// punycode form, which is what the Cloudflare API expects anyway.
const HOSTNAME_PATTERN = /^(\*\.)?[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)*$/i;

/**
 * Validates the caller-supplied ntfy URL. Any https endpoint is allowed
 * (self-hosted servers included): the notification body is worker-built
 * from API-validated DNS data and only fires after a successful update
 * through a valid token, so the relay value to an abuser is negligible.
 */
function resolveNtfyUrl(searchParams: URLSearchParams): string | null {
	const raw = searchParams.get('ntfy')?.trim() ?? null;
	if (raw === null || raw === '') {
		return null;
	}
	if (raw.length > NTFY_URL_MAX_LENGTH) {
		throw new HttpError(422, "The 'ntfy' parameter is too long.");
	}
	let parsed: URL;
	try {
		parsed = new URL(raw);
	} catch {
		throw new HttpError(422, "The 'ntfy' parameter must be a valid https URL.");
	}
	if (parsed.protocol !== 'https:') {
		throw new HttpError(422, "The 'ntfy' parameter must be a valid https URL.");
	}
	return raw;
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

/**
 * Cache keys carry the token ID so a caller only ever reads back entries
 * their own token wrote. A hostname-only key would let any valid token read
 * the cached IP for a name it has no authority over, which for a proxied
 * record is the origin address rather than anything DNS would resolve.
 */
function cacheKey(tokenId: string, record: DDNSRecord): string {
	return `${KV_KEY_PREFIX}:${tokenId}:${record.name}:${record.type}`;
}

export class HttpError extends Error {
	constructor(
		public readonly statusCode: number,
		message: string,
		/**
		 * Records that already reached DNS when a batch failed part-way. The
		 * response carries them so a caller reading only the status never
		 * concludes that nothing changed.
		 */
		public readonly applied: RecordResult[] = [],
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

interface ErrorResponseBody {
	success: false;
	error: string;
	/** Present only when a batch failed after some records already changed. */
	data?: {
		updated: boolean;
		records: RecordResult[];
	};
}

function jsonResponse(body: UpdateResponseBody | HistoryResponseBody | ErrorResponseBody, status: number): Response {
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
	const ntfyUrl = resolveNtfyUrl(searchParams);

	if (hostnameParam === null || hostnameParam === '') {
		throw new HttpError(422, "Missing 'hostnames' parameter.");
	}
	// Deduplicated: a repeated hostname would otherwise fan out into one
	// concurrent update per copy, all racing the same record, and file an
	// audit row per copy for a single logical change.
	const hostnames = [
		...new Set(
			hostnameParam
				.split(',')
				.map((s) => s.trim())
				.filter(Boolean),
		),
	];
	if (hostnames.length === 0) {
		throw new HttpError(422, 'No hostnames provided.');
	}
	const overlong = hostnames.find((hostname) => hostname.length > HOSTNAME_MAX_LENGTH);
	if (overlong !== undefined) {
		throw new HttpError(422, `Hostname exceeds ${String(HOSTNAME_MAX_LENGTH)} characters: '${overlong.slice(0, 60)}...'`);
	}
	const malformed = hostnames.find((hostname) => !HOSTNAME_PATTERN.test(hostname));
	if (malformed !== undefined) {
		throw new HttpError(422, `Not a valid hostname: '${encodeURIComponent(malformed)}'`);
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
	if (records.length > RECORDS_MAX) {
		throw new HttpError(
			422,
			`Too many DNS records: ${String(records.length)} requested, ${String(RECORDS_MAX)} allowed per request. Each hostname counts once per IP family.`,
		);
	}

	return { records, zoneFilter: zoneFilter === '' ? null : zoneFilter, ntfyUrl };
}

/** Reads a record's cached IP; any failure or unparseable entry is a miss. */
async function readCachedIp(env: Env, tokenId: string, record: DDNSRecord): Promise<string | null> {
	const key = cacheKey(tokenId, record);
	try {
		const raw = await env.DDNS_KV.get(key);
		if (raw === null) return null;
		const parsed = JSON.parse(raw) as Partial<CachedIp>;
		return typeof parsed.ip === 'string' ? parsed.ip : null;
	} catch (error) {
		console.error(`Failed to read IP cache for ${key}:`, error);
		return null;
	}
}

/** Caches a record's IP with a TTL so stale entries clean themselves up. */
async function writeCachedIp(env: Env, tokenId: string, record: DDNSRecord): Promise<void> {
	const value: CachedIp = { ip: record.content, updatedAt: new Date().toISOString() };
	const key = cacheKey(tokenId, record);
	try {
		await env.DDNS_KV.put(key, JSON.stringify(value), { expirationTtl: KV_TTL_SECONDS });
	} catch (error) {
		console.error(`Failed to write IP cache for ${key}:`, error);
		// The cache is an optimization; the update already succeeded.
	}
}

// A worker invocation is wall-clock bound, so the SDK defaults (60s per
// request, 2 retries) would let one stalled call spend the whole budget. A
// batch waits for every record to settle before responding, so this ceiling
// is also what bounds how long one slow record holds the whole response.
const API_TIMEOUT_MS = 5_000;
const API_MAX_RETRIES = 1;

function apiClient(auth: ParsedAuth): Cloudflare {
	return new Cloudflare({ apiToken: auth.token, timeout: API_TIMEOUT_MS, maxRetries: API_MAX_RETRIES });
}

/** Verifies the token is active and returns its ID (the audit tenant key). */
async function verifyToken(cloudflare: Cloudflare): Promise<string> {
	let verification: { id: string; status: string };
	try {
		verification = await cloudflare.user.tokens.verify();
	} catch (error) {
		// An invalid or expired token makes the verify call itself fail; that
		// is a client auth problem, not a server error.
		if (error instanceof BadRequestError || error instanceof AuthenticationError || error instanceof PermissionDeniedError) {
			throw new HttpError(401, 'Authentication failed: invalid token.');
		}
		throw error;
	}
	if (verification.status !== 'active') {
		throw new HttpError(401, `Authentication failed: token ${verification.status}`);
	}
	// The ID keys the zone cache and the audit rows' tenant column, so an
	// absent or empty one would pool separate tenants under a shared key.
	if (typeof verification.id !== 'string' || verification.id === '') {
		throw new HttpError(401, 'Authentication failed: token has no identity.');
	}
	return verification.id;
}

// Zone lists rarely change; caching them per token skips a zones.list call
// on every consecutive update. Stale entries self-heal via TTL.
const ZONES_TTL_SECONDS = 5 * 60;

// The zones endpoint caps per_page at 50; asking for the cap keeps the page
// walk short for tokens scoped to many zones. The ceiling bounds the walk at
// a caller-supplied token's zone count, which the worker does not control.
const ZONE_PAGE_SIZE = 50;
const ZONE_LIST_MAX = ZONE_PAGE_SIZE * 20;

interface CachedZone {
	id: string;
	name: string;
}

function zonesCacheKey(tokenId: string): string {
	return `zones:${tokenId}`;
}

/** Cached zones are read back as unknown: only the two fields used are trusted. */
function isCachedZone(value: unknown): value is CachedZone {
	if (typeof value !== 'object' || value === null) {
		return false;
	}
	const zone = value as Record<string, unknown>;
	return typeof zone['id'] === 'string' && typeof zone['name'] === 'string';
}

async function readCachedZones(env: Env, tokenId: string): Promise<CachedZone[] | null> {
	try {
		const raw = await env.DDNS_KV.get(zonesCacheKey(tokenId));
		if (raw === null) return null;
		const parsed = JSON.parse(raw) as unknown;
		return Array.isArray(parsed) && parsed.every(isCachedZone) ? parsed : null;
	} catch (error) {
		console.error(`Failed to read zones cache for token ${tokenId}:`, error);
		return null;
	}
}

async function writeCachedZones(env: Env, tokenId: string, zones: CachedZone[]): Promise<void> {
	try {
		await env.DDNS_KV.put(zonesCacheKey(tokenId), JSON.stringify(zones), { expirationTtl: ZONES_TTL_SECONDS });
	} catch (error) {
		console.error(`Failed to write zones cache for token ${tokenId}:`, error);
	}
}

interface ProcessedRecord {
	record: DDNSRecord;
	result: RecordResult;
	event: AuditEvent;
	message: string | null;
}

// One page covers every record sharing an exact name and type; a hostname
// with more A records than this is not a DDNS target.
const RECORD_PAGE_SIZE = 100;

/**
 * The zones that could hold a record for `hostname`, by DNS containment.
 *
 * The caller supplies the token, so the zone count is caller-controlled and
 * unbounded. Narrowing before the per-zone lookup keeps one update request
 * costing a fixed handful of API calls rather than one per zone on the token.
 * Comparison is lowercased because DNS names are case-insensitive.
 */
function zonesHosting(zones: CachedZone[], hostname: string): CachedZone[] {
	const name = hostname.toLowerCase();
	return zones.filter((zone) => {
		const zoneName = zone.name.toLowerCase();
		return name === zoneName || name.endsWith(`.${zoneName}`);
	});
}

/**
 * Looks up, compares, and (when the DNS content differs) updates one record.
 * Zone lookups run in parallel. Throws HttpError on no or ambiguous matches.
 *
 * A batch applies partially: records are processed concurrently, so a throw
 * here leaves siblings already updated. The caller audits and notifies for
 * those before surfacing the failure, so a refused request never hides a
 * change that reached DNS.
 */
async function processRecord(
	cloudflare: Cloudflare,
	env: Env,
	zones: CachedZone[],
	record: DDNSRecord,
	callerIp: string | null,
	tokenId: string,
): Promise<ProcessedRecord> {
	const candidates = zonesHosting(zones, record.name);
	const lists = await Promise.all(
		candidates.map(async (zone) => {
			// Awaited, not iterated: the SDK's page iterator stops only after
			// fetching an empty page, so draining costs one wasted call every
			// time. One page of RECORD_PAGE_SIZE covers an exact name+type.
			const { result } = await cloudflare.dns.records.list({
				zone_id: zone.id,
				name: { exact: record.name },
				type: record.type,
				per_page: RECORD_PAGE_SIZE,
			});
			return { zone, result };
		}),
	);
	const matches = lists.flatMap(({ zone, result }) =>
		result
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

	const match = matches[0];
	if (match === undefined) {
		throw new HttpError(400, `No matching record found for '${record.name}'. Create it manually first.`);
	}
	if (matches.length > 1) {
		throw new HttpError(400, `Multiple matching records found for '${record.name}'. Specify a unique hostname per zone.`);
	}

	// Notifications and audit rows key off the actual DNS delta, never the
	// cache: a cache miss on an unchanged record refreshes silently.
	const changed = match.content !== record.content;
	let message: string | null = null;
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

		message = `DNS record for '${record.name}' ('${record.type}') updated to '${record.content}'`;
		console.log(message);
	} else {
		console.log(`DNS record for '${record.name}' ('${record.type}') already at '${record.content}'. Refreshing cache only.`);
	}

	await writeCachedIp(env, tokenId, record);
	return {
		record,
		result: { hostname: record.name, type: record.type, ip: record.content, updated: changed },
		event: {
			occurredAt: new Date().toISOString(),
			tokenId,
			callerIp,
			hostname: record.name,
			recordType: record.type,
			previousIp: match.content ?? null,
			newIp: record.content,
			outcome: changed ? 'updated' : 'no-change',
		},
		message,
	};
}

async function updateHostnames(
	auth: ParsedAuth,
	updateRequest: UpdateRequest,
	request: Request,
	env: Env,
	ctx: ExecutionContext,
): Promise<Response> {
	const { records, zoneFilter, ntfyUrl } = updateRequest;
	const cloudflare = apiClient(auth);

	// Verification comes first on every path: it names the cache partition, and
	// it keeps an unverified caller at one API call rather than one KV read per
	// record. The cached fast path below therefore costs one verify call, which
	// is the price of never serving one caller's cache entry to another.
	// That path stays unaudited by design, because nothing was touched.
	const tokenId = await verifyToken(cloudflare);

	const cachedIps = await Promise.all(records.map(async (record) => readCachedIp(env, tokenId, record)));
	const pending = records.filter((record, i) => cachedIps[i] !== record.content);

	const allCurrentResponse = (): Response => {
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
	};

	if (pending.length === 0) {
		return allCurrentResponse();
	}

	let zones = await readCachedZones(env, tokenId);
	if (zones === null) {
		// Every zone the token can see, not just the first page: a hostname in
		// zone 21+ would otherwise report as having no matching record. The
		// result is cached per token, so the page walk is rare.
		const discovered: CachedZone[] = [];
		for await (const zone of cloudflare.zones.list({ per_page: ZONE_PAGE_SIZE })) {
			discovered.push({ id: zone.id, name: zone.name });
			if (discovered.length >= ZONE_LIST_MAX) {
				console.warn(`Token ${tokenId} sees more than ${String(ZONE_LIST_MAX)} zones; searching only the first ${String(ZONE_LIST_MAX)}.`);
				break;
			}
		}
		zones = discovered;
		ctx.waitUntil(writeCachedZones(env, tokenId, discovered));
	}
	if (zoneFilter !== null) {
		// Lowercased on both sides, matching zonesHosting: DNS names are
		// case-insensitive, and a case mismatch here would read as a token
		// permissions problem.
		const wanted = zoneFilter.toLowerCase();
		zones = zones.filter((zone) => zone.name.toLowerCase() === wanted);
		if (zones.length === 0) {
			throw new HttpError(400, `Zone '${zoneFilter}' not available with current permissions.`);
		}
	}
	if (zones.length === 0) {
		throw new HttpError(400, 'No zones available with current permissions.');
	}

	const callerIp = request.headers.get('CF-Connecting-IP');
	const visibleZones = zones;
	// Settled, not all: records are processed concurrently, so one failure
	// leaves siblings that already changed DNS. Those changes are real and
	// have to reach the audit trail and the notification whether or not the
	// request as a whole ends up refused.
	const settled = await Promise.allSettled(
		pending.map(async (record) => processRecord(cloudflare, env, visibleZones, record, callerIp, tokenId)),
	);
	const processed = settled.filter((outcome) => outcome.status === 'fulfilled').map((outcome) => outcome.value);
	const updateMessages = processed.map((p) => p.message).filter((m): m is string => m !== null);

	// Audit writes and the change notification ride after the response;
	// neither a D1 hiccup nor a slow ntfy server delays or fails the update.
	ctx.waitUntil(
		writeAuditEvents(
			env,
			processed.map((p) => p.event),
		),
	);
	if (updateMessages.length > 0) {
		ctx.waitUntil(pushNtfy(updateMessages, ntfyUrl));
	}

	const processedByRecord = new Map(processed.map((p) => [p.record, p]));
	const results: RecordResult[] = records.map(
		(record) => processedByRecord.get(record)?.result ?? { hostname: record.name, type: record.type, ip: record.content, updated: false },
	);

	// Only once what landed is recorded and reportable does a failure decide
	// the response.
	const rejected = settled.filter((outcome) => outcome.status === 'rejected').map((outcome) => outcome.reason as unknown);
	for (const reason of rejected) {
		console.error('Record update failed:', reason);
	}
	if (rejected.length > 0) {
		// An HttpError names what the caller must fix. Taking the first by
		// index instead would let a transient 500 on an early record mask it,
		// and 5xx is the status a DDNS client retries against.
		const actionable = rejected.find((reason) => reason instanceof HttpError);
		const applied = results.filter((result) => result.updated);
		if (actionable !== undefined) {
			throw new HttpError(actionable.statusCode, actionable.message, applied);
		}
		throw new HttpError(500, 'Internal Server Error', applied);
	}

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
	const cloudflare = apiClient(auth);
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
			// Edge-local per-IP throttle, before any other work. Best-effort
			// (per-colo counters), which is the right tool for cost capping.
			const rateKey = request.headers.get('CF-Connecting-IP') ?? 'unknown';
			const { success: withinLimit } = await env.RATE_LIMITER.limit({ key: rateKey });
			if (!withinLimit) {
				return jsonResponse({ success: false, error: 'Rate limit exceeded.' }, 429);
			}

			const auth = parseAuthorization(request);
			await checkAccess(env, request, auth);

			const { pathname } = new URL(request.url);
			if (pathname === '/history') {
				if (request.method !== 'GET') {
					throw new HttpError(405, 'Method not allowed.');
				}
				return await handleHistory(auth, request, env);
			}
			if (pathname !== '/update') {
				throw new HttpError(404, 'Not found.');
			}

			const updateRequest = constructDNSRecords(request);
			return await updateHostnames(auth, updateRequest, request, env, ctx);
		} catch (err: unknown) {
			const isHttpError = err instanceof HttpError;
			const message = isHttpError ? err.message : 'Internal Server Error';
			const statusCode = isHttpError ? err.statusCode : 500;
			const applied = isHttpError ? err.applied : [];
			console.error(`Error handling request: ${message}`, err);
			// A partly-applied batch reports what changed, so the caller does
			// not read the error as "nothing happened".
			if (applied.length > 0) {
				return jsonResponse({ success: false, error: message, data: { updated: true, records: applied } }, statusCode);
			}
			return jsonResponse({ success: false, error: message }, statusCode);
		}
	},
} satisfies ExportedHandler<Env>;
