import { DurableObject } from 'cloudflare:workers';

/**
 * One day's refusals for one token: how many, and against which names. Only the
 * current day is kept: the counter answers "is this token being refused right
 * now", and yesterday's number would grow storage without answering anything.
 */
interface RefusalState {
	day: string;
	n: number;
	names: string[];
	/** Storage writes spent on this day's tally, which is what WRITES_MAX caps. */
	w: number;
	/** Whether the day's alert was already reported, so it reports once. */
	warned: boolean;
}

/** What one token was refused today. */
export interface RefusalTally {
	/** Refusals counted, repeats included. */
	total: number;
	/** Entries in `hostnames`, which stops growing at DISTINCT_NAMES_MAX. */
	distinct: number;
	/** The names themselves, so a caller can see which of its own to fix. */
	hostnames: string[];
}

/** A tally, plus whether this call is the one that should report it. */
export interface RefusalUpdate extends RefusalTally {
	/**
	 * True on exactly one call per token per day: the first to find the tally
	 * at or past ALERT_DISTINCT.
	 *
	 * Decided here rather than by comparing counts at the caller, because a
	 * caller-side comparison fires on a transition. An `add` whose write lands
	 * but whose response is lost would take the transition with it, and every
	 * later call that day would see a tally that was already past the line.
	 * The flag persists, so the next call reports what the lost one would have.
	 */
	alert: boolean;
}

const STATE_KEY = 'count';

const DAY_MS = 24 * 60 * 60 * 1000;

/** How long past a tally's own day an instance keeps it before clearing. */
const RECLAIM_AFTER_DAY_MS = 2 * DAY_MS;

/**
 * Distinct names kept per day. The names come from the caller, so this set is
 * the one part of the object's storage a caller can grow. Past the cap the
 * total still climbs and the name list stops, which costs nothing that matters:
 * a caller reaching this many distinct names is already far past any threshold
 * the count feeds.
 */
const DISTINCT_NAMES_MAX = 200;

/**
 * Longest name kept, matching the DNS limit the worker validates against.
 *
 * Enforced here rather than trusted from the caller, so the stored value's size
 * is bounded by this object alone: DISTINCT_NAMES_MAX names of this length sit
 * under the 128 KiB per-value limit with room to spare, and a future caller
 * passing longer names cannot push every write past it.
 */
const NAME_MAX_LENGTH = 253;

/**
 * Storage writes a token can drive in a day before the tally goes quiet.
 *
 * Counted in writes rather than refusals, because writes are the resource. A
 * ceiling on the refusal total bounds the two call sites unequally: one carries
 * up to a full batch of names per request and the other carries exactly one, so
 * the same total lets the second drive many times the writes of the first. Past
 * this the tally has said everything it can, and a name not seen before is
 * still recorded.
 */
const WRITES_MAX = 500;

/**
 * Distinct names in a day past which the tally is worth an operator's eye.
 *
 * One request carries at most 40 records, so reaching this takes several full
 * batches of names no zone on the token can hold. Distinct rather than total,
 * because a DDNS client polls every two minutes: one hostname typed wrong
 * passes any total given an afternoon, and variety is what a caller sweeping
 * for names it does not hold produces and a misconfigured one does not.
 */
export const ALERT_DISTINCT = 100;

const DAY_PATTERN = /^\d{4}-\d{2}-\d{2}$/;

/**
 * Whether a day is one this object will count, measured against the clock the
 * caller stamps from.
 *
 * A day is a lexicographic comparison and an alarm anchor, and each end of the
 * window answers one of them. Behind the window, the alarm arms behind the
 * clock, so the tally written under that day is cleared on the way out. Ahead
 * of it, the stored day sits above every later call, each of which then reads
 * as a straggler: one such write takes the tally dark for the life of the
 * instance. The far end also keeps the alarm inside the ceiling the platform
 * will schedule against.
 *
 * The near end reaches back a full reclaim period rather than a day, because a
 * request that stamps its day just before midnight can land just after, and
 * that straggler has to arrive as one. The one caller stamps the current day,
 * whose ends sit a day clear of the window either way, so this is a backstop
 * rather than a line production approaches.
 */
function isDay(value: string): boolean {
	if (!DAY_PATTERN.test(value)) {
		return false;
	}
	const anchor = Date.parse(`${value}T00:00:00.000Z`);
	if (Number.isNaN(anchor)) {
		return false;
	}
	const now = Date.now();
	return anchor + RECLAIM_AFTER_DAY_MS > now && anchor < now + DAY_MS;
}

/** Stored state is read back as unknown: a shape that does not match is absent. */
function isRefusalState(value: unknown): value is RefusalState {
	if (typeof value !== 'object' || value === null) {
		return false;
	}
	const state = value as Record<string, unknown>;
	const names = state['names'];
	return (
		typeof state['day'] === 'string' &&
		Number.isSafeInteger(state['n']) &&
		Number.isSafeInteger(state['w']) &&
		typeof state['warned'] === 'boolean' &&
		Array.isArray(names) &&
		names.every((name) => typeof name === 'string')
	);
}

const EMPTY: RefusalUpdate = { total: 0, distinct: 0, hostnames: [], alert: false };

/**
 * Counts how often one token is refused, one instance per token.
 *
 * A refusal is caller-driven and unbounded in count, so it is counted rather
 * than recorded per event: a row apiece would let any caller grow a store every
 * tenant shares. KV cannot hold the count, having no atomic increment, so
 * concurrent requests lose updates to each other and any attempt to coalesce
 * writes lets a caller time its bursts to go unseen.
 *
 * A Durable Object removes both problems by construction. Requests to one
 * instance serialize, so nothing is lost to a race, and there is no window to
 * aim a burst at. Storage is one key per token, rewritten in place.
 */
export class RefusalCounter extends DurableObject<Env> {
	/**
	 * Adds names to today's tally and returns it, starting over when the day rolls.
	 *
	 * Names, not a count, because distinct names are the part worth reading: one
	 * hostname typed wrong is retried on every poll, so a total says only how
	 * long the mistake has been there. Variety is what a caller sweeping for
	 * names it does not hold produces and a misconfigured one does not.
	 *
	 * The caller stamps the day, and its RPC can land out of order, so a call
	 * carrying an older day is ignored rather than allowed to reset a newer
	 * tally. ISO dates compare lexicographically, which is what makes that a
	 * one-line check.
	 */
	async add(day: string, hostnames: string[]): Promise<RefusalUpdate> {
		// Shape first, then length: the array itself is the one input no other
		// guard covers, and a single oversized call would drive the total past
		// its own ceiling and disable the brake for the rest of the day.
		if (!Array.isArray(hostnames)) {
			return EMPTY;
		}
		const names = hostnames
			.slice(0, DISTINCT_NAMES_MAX)
			.filter((name) => typeof name === 'string' && name !== '' && name.length <= NAME_MAX_LENGTH);
		if (!isDay(day)) {
			// The caller stamps the current day, so reaching here says its clock
			// disagrees with this object's. Worth a line precisely because it
			// should not happen: the tally answers only through `/history`,
			// scoped to the token being counted, so a counter that stops
			// counting looks exactly like a quiet one. The day is escaped and
			// cut, since the value reaching here matched nothing.
			console.warn('refusals: ignoring a day outside the counted window', JSON.stringify(day).slice(0, 40));
			return EMPTY;
		}
		if (names.length === 0) {
			return EMPTY;
		}
		const stored = await this.ctx.storage.get(STATE_KEY);
		const state = isRefusalState(stored) ? stored : undefined;
		if (state !== undefined && state.day > day) {
			// Zero, not the stored tally: the caller reads the return as "this
			// many now", and a straggler must not look like a transition.
			return EMPTY;
		}
		const current = state?.day === day ? state : undefined;
		const merged = new Set(current?.names);
		const previousDistinct = merged.size;
		for (const name of names) {
			if (merged.size >= DISTINCT_NAMES_MAX) {
				break;
			}
			merged.add(name);
		}
		const kept = [...merged];
		const alert = kept.length >= ALERT_DISTINCT && current?.warned !== true;
		if (current !== undefined && current.w >= WRITES_MAX && merged.size === previousDistinct && !alert) {
			// Saturated, and this call taught it nothing new. Returning without
			// a write is what keeps the storage rate off the caller's clock.
			return { total: current.n, distinct: previousDistinct, hostnames: kept, alert: false };
		}
		const total = (current?.n ?? 0) + names.length;
		// Armed against the tally's own day rather than the moment of the call,
		// and only when the day changes: a per-call reset would double the
		// storage writes a caller can drive, and a timer from first contact
		// would wipe a tally still being added to.
		if (current === undefined) {
			// Before the write, not after. An alarm with no state behind it
			// fires once and deletes nothing; state with no alarm behind it is
			// an instance that never reclaims itself.
			await this.ctx.storage.setAlarm(Date.parse(`${day}T00:00:00.000Z`) + RECLAIM_AFTER_DAY_MS);
		}
		// `warned` is written with the tally that earned it, so the record of
		// having reported survives whatever happens to this call's response.
		await this.ctx.storage.put(STATE_KEY, {
			day,
			n: total,
			names: kept,
			w: (current?.w ?? 0) + 1,
			warned: alert || current?.warned === true,
		} satisfies RefusalState);
		return { total, distinct: kept.length, hostnames: kept, alert };
	}

	/** Today's tally; a stored tally from an earlier day reads as empty. */
	async tally(day: string): Promise<RefusalTally> {
		const stored = await this.ctx.storage.get(STATE_KEY);
		if (!isRefusalState(stored) || stored.day !== day) {
			return { total: 0, distinct: 0, hostnames: [] };
		}
		return { total: stored.n, distinct: stored.names.length, hostnames: stored.names };
	}

	/** Reclaims an instance whose tally is old enough to be past use. */
	override async alarm(): Promise<void> {
		await this.ctx.storage.deleteAll();
	}
}
