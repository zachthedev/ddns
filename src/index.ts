import {
	APIError,
	AuthenticationError,
	BadRequestError,
	Cloudflare,
	NotFoundError,
	PermissionDeniedError,
	RateLimitError,
} from 'cloudflare';
import { HISTORY_DEFAULT_LIMIT, queryHistory, writeAuditEvents, type AuditEvent } from './audit';
import { pushNtfy } from './pushNtfy';
import type { RefusalTally } from './refusals';
export { RefusalCounter } from './refusals';

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
 * A rejected value, shortened for the message that quotes it back.
 *
 * `encodeURIComponent` throws on a lone surrogate, which would answer a rejected
 * input with the 500 a DDNS client retries against. Two things can produce one:
 * a cut that lands mid-pair, which the `u` flag prevents by cutting on code
 * points, and a value that already carried one, which `toWellFormed` replaces.
 * Encoding comes last so the result is always decodable, and it removes the
 * newline that would otherwise forge a line in the log.
 */
function quoteInput(value: string): string {
	return encodeURIComponent(value.toWellFormed().replace(/^([\s\S]{0,60})[\s\S]*$/u, '$1'));
}

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

/** Today in UTC, the bucket the refusal counter is kept and reported at. */
function currentDay(): string {
	return new Date().toISOString().slice(0, 10);
}

// Names quoted in the alert, enough to act on without dumping the whole list.
// Taken from the end, because the list is in the order the caller supplied it
// and the head is whatever it opened the day with. The tail at least describes
// what it is doing now.
const ALERT_SAMPLE = -5;

/**
 * Adds to the caller's refusal tally. Best-effort: the counter is a signal, so
 * losing one must never fail an update that already happened.
 *
 * The counter decides when a tally is worth reporting, and this logs it, because
 * the tally is otherwise readable only through `/history`, which is scoped to
 * the very token being counted. A caller probing hostnames it does not own has
 * no reason to read its own history, so without this the count would only ever
 * be seen by the one party it describes. A sample of the names rides along: the
 * operator who reads the log cannot query the tally it refers to.
 */
async function countRefusals(env: Env, tokenId: string, hostnames: string[]): Promise<void> {
	try {
		const tally = await env.REFUSALS.getByName(tokenId).add(currentDay(), hostnames);
		if (tally.alert) {
			const sample = tally.hostnames.slice(ALERT_SAMPLE).join(', ');
			console.warn(
				`Token ${tokenId} reached past its authority for ${String(tally.distinct)} distinct hostnames today, including: ${sample}`,
			);
		}
	} catch (error) {
		console.error(`Failed to count refusals for token ${tokenId}:`, error);
	}
}

/** The caller's refusals for today; an unreadable counter reads as none. */
async function readRefusalTally(env: Env, tokenId: string): Promise<RefusalTally> {
	try {
		return await env.REFUSALS.getByName(tokenId).tally(currentDay());
	} catch (error) {
		console.error(`Failed to read the refusal tally for token ${tokenId}:`, error);
		return { total: 0, distinct: 0, hostnames: [] };
	}
}

export class HttpError extends Error {
	constructor(
		public readonly statusCode: number,
		message: string,
		/**
		 * What the batch did before it failed, when the failure came from one.
		 * The response carries it so a caller reading only the status never
		 * concludes that nothing changed, and never takes one record's verdict
		 * for the rest of the batch.
		 */
		public readonly batch: BatchOutcome | null = null,
	) {
		super(message);
		this.name = new.target.name;
		Object.setPrototypeOf(this, new.target.prototype);
	}
}

/**
 * A hostname no zone on the token could hold.
 *
 * Its own class because it is the one refusal that says something about the
 * caller rather than about its configuration. A record that has not been
 * created yet, or a token missing a scope, is a setup step every new user goes
 * through; asking after a name outside the token's zones is not.
 */
export class OutsideAuthority extends HttpError {
	constructor(hostname: string) {
		super(400, `No matching record found for '${hostname}'. Create it manually first.`);
		this.name = new.target.name;
		Object.setPrototypeOf(this, new.target.prototype);
	}
}

interface RecordResult {
	hostname: string;
	type: string;
	/**
	 * The address this request asked for. On a record that failed it is what
	 * was requested rather than what DNS holds, so `failed` below is the only
	 * place to learn which of the two a `false` in `updated` means.
	 */
	ip: string;
	updated: boolean;
}

/**
 * One record that did not make it, with its own status.
 *
 * A batch fails per record, and the response can only carry one status. Without
 * this list a terminal 400 on a misspelled hostname speaks for a transient 500
 * on the record beside it, and the client stops retrying the one it should keep
 * retrying.
 */
interface RecordFailure {
	hostname: string;
	type: string;
	status: number;
	error: string;
}

/** What a batch did before it failed. */
interface BatchOutcome {
	/**
	 * Every record in the request, with what happened to it. The full list, not
	 * just the ones that changed: a record that was already current and one
	 * that failed both carry `updated: false`, so a list of changes alone
	 * cannot tell them apart.
	 */
	records: RecordResult[];
	failed: RecordFailure[];
}

/**
 * One rejection as the caller should see it: a status saying whether to retry,
 * and a message saying what to fix. SDK errors are translated rather than
 * forwarded, so nothing from the upstream response reaches the caller.
 */
function describeFailure(reason: unknown): { status: number; message: string } {
	if (reason instanceof AuthenticationError) {
		return { status: 401, message: 'Authentication failed: invalid token.' };
	}
	if (reason instanceof HttpError) {
		return { status: reason.statusCode, message: reason.message };
	}
	if (reason instanceof PermissionDeniedError) {
		return { status: 403, message: 'The API token lacks permission for this record.' };
	}
	if (reason instanceof RateLimitError) {
		return { status: 429, message: 'The Cloudflare API is rate limiting this token. Retry later.' };
	}
	// Both are terminal: the record as asked for cannot be written, and no
	// amount of retrying changes that. Left to the 500 below, a DDNS client
	// would spend a lookup and an update call on every poll forever.
	if (reason instanceof BadRequestError) {
		return { status: 400, message: 'Cloudflare rejected this record. Check that the name exists and its type matches the address family.' };
	}
	if (reason instanceof NotFoundError) {
		return { status: 404, message: 'Cloudflare no longer has this zone or record.' };
	}
	// Every other terminal answer the API can give, 409 and 422 among them.
	// Left to the 500 below they would read as a server fault, and a client
	// retries a server fault forever. The status is read through a shape rather
	// than off the class, whose generic parameters narrow to `any`, and an
	// absent one becomes NaN and falls through.
	const status = reason instanceof APIError ? Number((reason as { status: unknown }).status) : Number.NaN;
	if (status >= 400 && status < 500) {
		return { status, message: 'Cloudflare rejected this record.' };
	}
	return { status: 500, message: 'Internal Server Error' };
}

/**
 * Which failure speaks for a mixed batch, lowest first.
 *
 * A dead credential outranks every record-level answer, because none of them
 * can be acted on with a token that no longer works. A 400 comes next as the
 * one that names the caller's own request precisely. Terminal outranks
 * transient throughout, because 429 and 5xx are what a DDNS client retries
 * against, and a caller told only to retry later never fixes the record that
 * cannot work at all.
 */
function failureRank({ status }: { status: number }): number {
	if (status === 401) {
		return 0;
	}
	if (status === 400) {
		return 1;
	}
	if (status === 429) {
		return 3;
	}
	return status < 500 ? 2 : 4;
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
		/** Refusals counted against this token today, UTC. */
		refusedToday: RefusalTally;
	};
}

interface ErrorResponseBody {
	success: false;
	error: string;
	/** Present only when the failure came from a batch of records. */
	data?: {
		updated: boolean;
		records: RecordResult[];
		failed: RecordFailure[];
	};
}

function jsonResponse(body: UpdateResponseBody | HistoryResponseBody | ErrorResponseBody, status: number): Response {
	return new Response(JSON.stringify(body), {
		status,
		// Caller-supplied values are reflected into error bodies, so pin the
		// type rather than leave a sniffing browser to pick one. `no-store`
		// because /history carries audit rows, caller IPs, and the refused
		// hostnames, which a private cache would otherwise keep on disk.
		headers: {
			'Content-Type': 'application/json',
			'X-Content-Type-Options': 'nosniff',
			'Cache-Control': 'no-store',
		},
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

// Dotted quad, each octet 0-255. A substring check would let any text through
// as long as it held a dot, and that text reaches the Cloudflare API and the
// response body.
const IPV4_PATTERN = /^((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)$/;

// Everything an IPv6 literal may contain. Checked before the value is placed
// inside brackets below, so it cannot carry `]`, `/` or `@` and escape them.
//
// The dot is excluded, which rules out every dotted tail. The parser rewrites
// one to hex, and whether RFC 5952 renders it back dotted depends on the range:
// mapped and IPv4-compatible addresses yes, an embedded quad anywhere else no.
// Telling those apart means knowing how Cloudflare renders each one, so all
// dotted spellings are refused and the hex form of the same address, which is
// what the parser would have stored anyway, is accepted.
const IPV6_CHARSET = /^[0-9a-f:]+$/i;

// The IPv4-mapped range, `::ffff:0:0/96`, in the hex spelling the parser emits.
// Excluding the dot above only refuses the dotted way of writing it; every
// RFC 5952 implementation renders this range back as dotted whichever way it
// arrived, so the hex spelling flaps in exactly the same way. Neither is a
// useful AAAA target.
const IPV6_MAPPED_PREFIX = '::ffff:';

/**
 * The canonical form of the address, or null when it is not one of that family.
 *
 * IPv6 is delegated to the URL parser rather than matched by hand. Its grammar
 * is the platform's own, and a group-splitting check quietly accepts stray
 * colons (`:::`, `1::2:`, `:1:2:3:4:5:6:7:8`) that it rejects.
 *
 * The canonical spelling is what gets stored. Cloudflare canonicalises too, so
 * forwarding `2001:0DB8::1` verbatim would leave the comparison against the
 * stored record permanently unequal: every poll would issue a real update,
 * write an audit row, and fire a notification for a change that never happened.
 */
function canonicalIp(value: string, family: 'v4' | 'v6'): string | null {
	if (family === 'v4') {
		// The pattern already rejects leading zeros, so a match is canonical.
		return IPV4_PATTERN.test(value) ? value : null;
	}
	if (value.length > 45 || !value.includes(':') || !IPV6_CHARSET.test(value)) {
		return null;
	}
	try {
		// A bracketed host only parses when it is a valid IPv6 literal, and a
		// parse that succeeds always yields the bracketed compressed lower-case
		// form, so the brackets come straight back off.
		const { hostname } = new URL(`http://[${value}]/`);
		const canonical = hostname.slice(1, -1);
		return canonical.startsWith(IPV6_MAPPED_PREFIX) ? null : canonical;
	} catch {
		return null;
	}
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
	// Absent outside Cloudflare's edge; an empty value fails address
	// validation like any other non-address, so `auto` simply skips its slot.
	const connectingIp = request.headers.get('CF-Connecting-IP') ?? '';

	let v4: string | null = null;
	if (raw4 !== null && raw4 !== '') {
		if (raw4 === 'auto') {
			v4 = canonicalIp(connectingIp, 'v4');
			if (v4 === null) {
				console.log('ip4=auto requested but the client did not connect over IPv4; skipping A records.');
			}
		} else {
			v4 = canonicalIp(raw4, 'v4');
			if (v4 === null) {
				throw new HttpError(422, "The 'ip4' parameter must be a valid IPv4 address.");
			}
		}
	}

	let v6: string | null = null;
	if (raw6 !== null && raw6 !== '') {
		if (raw6 === 'auto') {
			v6 = canonicalIp(connectingIp, 'v6');
			if (v6 === null) {
				console.log('ip6=auto requested but the client did not connect over IPv6; skipping AAAA records.');
			}
		} else {
			v6 = canonicalIp(raw6, 'v6');
			if (v6 === null) {
				throw new HttpError(422, "The 'ip6' parameter must be a valid IPv6 address.");
			}
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
		throw new HttpError(422, `Hostname exceeds ${String(HOSTNAME_MAX_LENGTH)} characters: '${quoteInput(overlong)}...'`);
	}
	const malformed = hostnames.find((hostname) => !HOSTNAME_PATTERN.test(hostname));
	if (malformed !== undefined) {
		throw new HttpError(422, `Not a valid hostname: '${quoteInput(malformed)}'`);
	}
	// Held to the same shape as a hostname, and for the same reason: the value
	// reaches log lines, the refusal tally, and the `/history` response that
	// echoes the tally back.
	if (zoneFilter !== null && zoneFilter !== '' && (zoneFilter.length > HOSTNAME_MAX_LENGTH || !HOSTNAME_PATTERN.test(zoneFilter))) {
		throw new HttpError(422, `Not a valid zone name: '${quoteInput(zoneFilter)}'`);
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

// An empty result gets its own, shorter life. A token that can see no zones
// belongs to an account still being set up, and its first zone lands minutes
// later, so the full TTL would keep answering "no zones" after the zone exists.
// Not caching it at all is worse: every request from a zone-less token would
// walk the API instead of reading one KV key, with nothing bounding the rate.
// KV refuses anything under 60 seconds, and the refusal reaches the catch in
// writeCachedZones, so a lower value here is a cache that silently never exists.
const ZONES_EMPTY_TTL_SECONDS = 60;

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
		await env.DDNS_KV.put(zonesCacheKey(tokenId), JSON.stringify(zones), {
			expirationTtl: zones.length > 0 ? ZONES_TTL_SECONDS : ZONES_EMPTY_TTL_SECONDS,
		});
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
 * The two zone lists a record is judged against.
 *
 * They differ only when the caller sets `zone=`, and keeping them apart is what
 * stops the caller's own narrowing from reading as a reach past authority: a
 * hostname in another zone the token holds is excluded by the filter, not by
 * the token's permissions.
 */
interface ZoneScope {
	/** Every zone the token holds. Authority is decided against this. */
	authority: CachedZone[];
	/** The zones actually searched for the record. */
	searched: CachedZone[];
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
	scope: ZoneScope,
	record: DDNSRecord,
	callerIp: string | null,
	tokenId: string,
): Promise<ProcessedRecord> {
	if (zonesHosting(scope.authority, record.name).length === 0) {
		// Distinct from "the record does not exist yet", which is what a user
		// setting the worker up hits on every poll until they create it. No
		// zone on the token can hold this name at all, so the caller is asking
		// about something outside its authority. Only that is worth counting.
		throw new OutsideAuthority(record.name);
	}
	const candidates = zonesHosting(scope.searched, record.name);
	if (candidates.length === 0) {
		// The token holds a zone that could serve this name, and the caller's
		// own `zone=` excluded it. Neither a missing record nor a reach.
		throw new HttpError(400, `'${record.name}' is outside the zone requested with 'zone='.`);
	}
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
		try {
			for await (const zone of cloudflare.zones.list({ per_page: ZONE_PAGE_SIZE })) {
				discovered.push({ id: zone.id, name: zone.name });
				if (discovered.length >= ZONE_LIST_MAX) {
					console.warn(
						`Token ${tokenId} sees more than ${String(ZONE_LIST_MAX)} zones; searching only the first ${String(ZONE_LIST_MAX)}.`,
					);
					break;
				}
			}
		} catch (reason: unknown) {
			// Categorised by the same function the record path uses, so a new
			// error class lands in one place. Left uncategorised these become a
			// 500, which is the one status a DDNS client retries against forever.
			const { status, message } = describeFailure(reason);
			if (status >= 500) {
				throw reason;
			}
			throw new HttpError(
				status,
				// A token with DNS edit but no Zone Read is the documented setup
				// mistake, and it fails here rather than on a record lookup. The
				// generic per-record wording would send the user hunting through
				// their records for it.
				status === 403 ? 'The API token cannot list zones. It needs Zone > Zone > Read as well as Zone > DNS > Edit.' : message,
			);
		}
		zones = discovered;
		// Cached either way, an empty result under its own short TTL.
		ctx.waitUntil(writeCachedZones(env, tokenId, discovered));
	}

	// A refusal never drops the cached list. A zone added to the token since
	// the list was cached does read like a reach past authority, but clearing
	// on that reading costs a full zone walk on every poll for as long as one
	// hostname stays misspelled, and a misspelling outlives any zone change.
	// The TTL already bounds the staleness at ZONES_TTL_SECONDS.
	const authority = zones;

	/**
	 * Counts one reach past the token's authority, unless the zone list is capped.
	 *
	 * A list sitting at ZONE_LIST_MAX may be missing zones beyond it, and a name
	 * in one of those was never looked for rather than reached for. Counting it
	 * would put the largest legitimate accounts in the tally, which is precisely
	 * the population the alert exists to exclude.
	 */
	const refuse = (hostnames: string[]): void => {
		if (authority.length < ZONE_LIST_MAX) {
			ctx.waitUntil(countRefusals(env, tokenId, hostnames));
		}
	};

	if (zones.length === 0) {
		// Uncounted, unlike the zone filter below: seeing no zones at all says
		// the account has none yet or the token was scoped to none, both setup
		// states every new user passes through. Counting them would bury the
		// signal under first afternoons.
		throw new HttpError(400, 'No zones available with current permissions.');
	}
	if (zoneFilter !== null) {
		// Lowercased on both sides, matching zonesHosting: DNS names are
		// case-insensitive, and a case mismatch here would read as a token
		// permissions problem.
		const wanted = zoneFilter.toLowerCase();
		const scoped = zones.filter((zone) => zone.name.toLowerCase() === wanted);
		if (scoped.length === 0) {
			// One reach, not one per record: naming a zone the token cannot see
			// is a single assertion about authority however large the batch.
			refuse([wanted]);
			throw new HttpError(400, `Zone '${zoneFilter}' not available with current permissions.`);
		}
		zones = scoped;
	}

	const callerIp = request.headers.get('CF-Connecting-IP');
	const scope: ZoneScope = { authority, searched: zones };
	// Each outcome carries the record it belongs to, and none of them reject:
	// records are processed concurrently, so one failure leaves siblings that
	// already changed DNS. Those changes are real and have to reach the audit
	// trail and the notification whether or not the request ends up refused,
	// and each failure has to be reportable against its own hostname.
	const settled = await Promise.all(
		pending.map(async (record) =>
			processRecord(cloudflare, env, scope, record, callerIp, tokenId).then(
				(value): { record: DDNSRecord; processed: ProcessedRecord | null; reason: unknown } => ({
					record,
					processed: value,
					reason: null,
				}),
				(reason: unknown) => ({ record, processed: null, reason }),
			),
		),
	);
	const processed = settled.map((outcome) => outcome.processed).filter((p): p is ProcessedRecord => p !== null);
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
	const failed = settled.filter((outcome) => outcome.processed === null);
	for (const { reason } of failed) {
		console.error('Record update failed:', reason);
	}

	// Only a reach past authority counts. A 403 from the record call cannot be
	// one: the zone was already confirmed to be on the token, so it means a
	// missing DNS scope, which is a setup mistake like any other.
	// AuthenticationError is excluded: a token revoked mid-request is a
	// credential lifecycle event, not the caller overreaching.
	// Deduplicated: one hostname with both ip4 and ip6 is two records and two
	// failures, and counting it twice would make a dual-stack caller look twice
	// as persistent as a single-stack one asking the same question.
	const refused = [
		...new Set(failed.filter(({ reason }) => reason instanceof OutsideAuthority).map(({ record }) => record.name.toLowerCase())),
	];
	if (refused.length > 0) {
		refuse(refused);
	}

	if (failed.length > 0) {
		const described = failed.map(({ record, reason }) => ({ record, ...describeFailure(reason) }));
		const batch: BatchOutcome = {
			records: results,
			// Every failure, each against its own hostname. The single status
			// below can only describe one of them, and a client that reads only
			// the status would stop retrying a record that deserves a retry.
			failed: described.map(({ record, status, message }) => ({ hostname: record.name, type: record.type, status, error: message })),
		};
		// One status has to speak for the batch, and it is the most actionable
		// one rather than the first by index. Ranked rather than matched against
		// a list of known statuses, so a status describeFailure learns to emit
		// cannot silently degrade to the 500 the list would not have covered.
		const chosen = described.reduce((best, candidate) => (failureRank(candidate) < failureRank(best) ? candidate : best));
		throw new HttpError(chosen.status, chosen.message, batch);
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

	const [events, refusedToday] = await Promise.all([queryHistory(env, { tokenId, hostname, limit }), readRefusalTally(env, tokenId)]);
	return jsonResponse({ success: true, data: { events, refusedToday } }, 200);
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
			const batch = isHttpError ? err.batch : null;
			console.error(`Error handling request: ${message}`, err);
			// A failed batch reports what changed and what did not, so the
			// caller neither reads the error as "nothing happened" nor takes
			// one record's status for the whole request.
			if (batch !== null) {
				return jsonResponse(
					{
						success: false,
						error: message,
						data: { updated: batch.records.some((result) => result.updated), records: batch.records, failed: batch.failed },
					},
					statusCode,
				);
			}
			return jsonResponse({ success: false, error: message }, statusCode);
		}
	},
} satisfies ExportedHandler<Env>;
