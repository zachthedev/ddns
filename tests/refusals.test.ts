import { env } from 'cloudflare:workers';
import { runDurableObjectAlarm } from 'cloudflare:test';
import { describe, it, expect } from 'vitest';

/**
 * Exercised against a real Durable Object rather than a stub: the reason this
 * counter is a DO at all is that instance requests serialize, and a stub would
 * assert that property rather than test it.
 */
describe('RefusalCounter', () => {
	const today = '2026-08-06';

	it('reports nothing for a token it has never seen', async () => {
		await expect(env.REFUSALS.getByName('fresh-token').tally(today)).resolves.toEqual({ total: 0, distinct: 0, hostnames: [] });
	});

	it('accumulates the total across calls', async () => {
		const counter = env.REFUSALS.getByName('accumulating-token');

		await counter.add(today, ['a.example.com', 'b.example.com', 'c.example.com']);
		await counter.add(today, ['d.example.com']);

		await expect(counter.tally(today)).resolves.toMatchObject({ total: 4, distinct: 4 });
	});

	it('counts one name refused repeatedly once', async () => {
		// The distinction the whole tally rests on. A hostname typed wrong is
		// retried on every poll, so a total says how long the mistake has been
		// there; only the distinct count says anything about the caller.
		const counter = env.REFUSALS.getByName('repeating-token');

		for (let poll = 0; poll < 20; poll++) {
			await counter.add(today, ['typo.example.com']);
		}

		await expect(counter.tally(today)).resolves.toEqual({
			total: 20,
			distinct: 1,
			hostnames: ['typo.example.com'],
		});
	});

	it('reports the names, so a caller can see which of its own to fix', async () => {
		const counter = env.REFUSALS.getByName('naming-token');

		await counter.add(today, ['one.example.com', 'two.example.com']);

		await expect(counter.tally(today)).resolves.toMatchObject({
			hostnames: ['one.example.com', 'two.example.com'],
		});
	});

	it('loses nothing when calls overlap', async () => {
		// The whole reason for a Durable Object: a KV read-modify-write drops
		// concurrent increments, and the loss scales with the caller's concurrency.
		const counter = env.REFUSALS.getByName('concurrent-token');

		await Promise.all(Array.from({ length: 50 }, async (_unused, i) => counter.add(today, [`host-${String(i)}.example.com`])));

		await expect(counter.tally(today)).resolves.toMatchObject({ total: 50, distinct: 50 });
	});

	it('keeps one token separate from another', async () => {
		await env.REFUSALS.getByName('token-a').add(today, ['a.example.com']);
		await env.REFUSALS.getByName('token-b').add(today, ['b.example.com', 'c.example.com']);

		await expect(env.REFUSALS.getByName('token-a').tally(today)).resolves.toMatchObject({ total: 1, distinct: 1 });
		await expect(env.REFUSALS.getByName('token-b').tally(today)).resolves.toMatchObject({ total: 2, distinct: 2 });
	});

	it('starts over when the day rolls', async () => {
		const counter = env.REFUSALS.getByName('rolling-token');
		await counter.add('2026-08-05', ['old.example.com', 'older.example.com']);

		await counter.add('2026-08-06', ['new.example.com']);

		await expect(counter.tally('2026-08-06')).resolves.toEqual({
			total: 1,
			distinct: 1,
			hostnames: ['new.example.com'],
		});
	});

	it('reports nothing for a day it holds no tally for', async () => {
		const counter = env.REFUSALS.getByName('stale-token');
		await counter.add('2026-08-05', ['old.example.com']);

		await expect(counter.tally('2026-08-06')).resolves.toEqual({ total: 0, distinct: 0, hostnames: [] });
	});

	it('stops collecting names at the cap while the total keeps climbing', async () => {
		// Names come from the caller, so the set is the one part of this
		// object's storage a caller can grow. Past the cap the count still has
		// to move, or a caller could hide behind its own flood.
		const counter = env.REFUSALS.getByName('flooding-token');
		const flood = (round: number): string[] => Array.from({ length: 150 }, (_unused, i) => `r${String(round)}n${String(i)}.example.com`);

		await counter.add(today, flood(0));
		await counter.add(today, flood(1));

		const tally = await counter.tally(today);
		expect(tally.total).toBe(300);
		expect(tally.distinct).toBe(200);
		expect(tally.hostnames).toHaveLength(200);
	});

	it('bounds one call by the same cap, however many names it carries', async () => {
		// The array length is the one input no other guard covers, and a single
		// oversized call would otherwise drive the total past its own ceiling
		// and disable the saturation brake for the rest of the day.
		const counter = env.REFUSALS.getByName('oversized-token');

		await counter.add(
			today,
			Array.from({ length: 5_000 }, (_unused, i) => `bulk-${String(i)}.example.com`),
		);

		await expect(counter.tally(today)).resolves.toMatchObject({ total: 200, distinct: 200 });
	});
});

describe('RefusalCounter guards', () => {
	const today = '2026-08-06';

	it.each([
		['an empty list', []],
		['entries that are not names', ['', '']],
	])('ignores %s rather than touching the tally', async (label, hostnames) => {
		// add() is the object's public contract and will outlive its one caller.
		const counter = env.REFUSALS.getByName(`guard-${label}`);
		await counter.add(today, ['real.example.com']);

		await expect(counter.add(today, hostnames)).resolves.toEqual({ total: 0, distinct: 0, hostnames: [], alert: false });

		await expect(counter.tally(today)).resolves.toMatchObject({ total: 1, distinct: 1 });
	});

	it('ignores an argument that is not a list of names', async () => {
		// The array itself is the one input no other guard covers, and the slice
		// that bounds its length would throw on anything else.
		const counter = env.REFUSALS.getByName('non-array-token');
		await counter.add(today, ['real.example.com']);

		await expect(counter.add(today, 'not-an-array' as unknown as string[])).resolves.toMatchObject({ total: 0 });

		await expect(counter.tally(today)).resolves.toMatchObject({ total: 1 });
	});

	it('refuses a name longer than a DNS name may be', async () => {
		// The object defends its own storage limit rather than trusting the
		// caller's validation: DISTINCT_NAMES_MAX names of this length is what
		// keeps the stored value inside the per-value limit.
		const counter = env.REFUSALS.getByName('long-name-token');

		await counter.add(today, [`${'a'.repeat(250)}.example.com`, 'short.example.com']);

		await expect(counter.tally(today)).resolves.toEqual({ total: 1, distinct: 1, hostnames: ['short.example.com'] });
	});

	it.each([
		['a batch per call', 40],
		['one name per call', 1],
	])('stops writing at the same point with %s', async (_label, perCall) => {
		// The ceiling counts writes, not refusals. Counting refusals would bound
		// the two call sites unequally: the zone path carries exactly one name
		// per request, so a refusal ceiling would let it drive many times the
		// writes of the record path for the same ceiling.
		const counter = env.REFUSALS.getByName(`saturating-${String(perCall)}`);
		const names = Array.from({ length: perCall }, () => 'same.example.com');
		for (let call = 0; call < 500; call++) {
			await counter.add(today, names);
		}

		const saturated = await counter.tally(today);
		await counter.add(today, names);

		await expect(counter.tally(today)).resolves.toMatchObject({ total: saturated.total });
		expect(saturated.total).toBe(500 * perCall);
	});

	it('records a name it has not seen even once the writes are spent', async () => {
		// The brake stops repetition, not discovery: a fresh name is the one
		// thing the tally has not already said.
		const counter = env.REFUSALS.getByName('saturated-but-learning');
		for (let call = 0; call < 500; call++) {
			await counter.add(today, ['same.example.com']);
		}

		await expect(counter.add(today, ['fresh.example.com'])).resolves.toMatchObject({ distinct: 2 });
	});

	it('keeps the names that are usable when a list is part junk', async () => {
		const counter = env.REFUSALS.getByName('part-junk-token');

		await counter.add(today, ['', 'real.example.com']);

		await expect(counter.tally(today)).resolves.toEqual({ total: 1, distinct: 1, hostnames: ['real.example.com'] });
	});

	it.each([
		['a day that is not a date', 'yesterday'],
		['a day out of range', '2026-13-45'],
		['a timestamp rather than a day', '2026-08-06T12:00:00Z'],
		// The alarm anchor is the day plus the reclaim window, and the platform
		// refuses to schedule past 2189. The pattern alone would admit this.
		['a day past the furthest alarm', '9999-12-31'],
	])('ignores %s rather than poisoning the tally', async (_label, day) => {
		// The day reaches both a lexicographic comparison and the alarm anchor,
		// where a value this does not admit would compare wrong or make setAlarm
		// throw.
		const counter = env.REFUSALS.getByName(`day-guard-${day}`);
		await counter.add(today, ['real.example.com']);

		await counter.add(day, ['bogus.example.com']);

		await expect(counter.tally(today)).resolves.toMatchObject({ total: 1, distinct: 1 });
	});

	it('ignores a call stamped with an older day', async () => {
		// The caller stamps the day and its RPC can land out of order, so a
		// straggler from yesterday must not reset today.
		const counter = env.REFUSALS.getByName('straggler-token');
		await counter.add('2026-08-06', ['today.example.com']);

		await counter.add('2026-08-05', ['yesterday.example.com']);

		await expect(counter.tally('2026-08-06')).resolves.toEqual({
			total: 1,
			distinct: 1,
			hostnames: ['today.example.com'],
		});
	});

	const names = (count: number, prefix: string): string[] =>
		Array.from({ length: count }, (_unused, i) => `${prefix}${String(i)}.example.com`);

	it('raises the alert on exactly one call per day', async () => {
		const counter = env.REFUSALS.getByName('alerting-token');

		await expect(counter.add(today, names(99, 'a'))).resolves.toMatchObject({ distinct: 99, alert: false });
		await expect(counter.add(today, names(2, 'b'))).resolves.toMatchObject({ distinct: 101, alert: true });
		await expect(counter.add(today, names(5, 'c'))).resolves.toMatchObject({ alert: false });
	});

	it('raises the alert again once the day rolls', async () => {
		// The flag is part of the day's tally, so a new day starts silent.
		const counter = env.REFUSALS.getByName('alert-rolling-token');
		await counter.add('2026-08-06', names(100, 'a'));

		await expect(counter.add('2026-08-07', names(100, 'a'))).resolves.toMatchObject({ alert: true });
	});

	it('raises the alert on the next call when one is lost after the write', async () => {
		// The flag lives with the tally rather than being derived from a
		// before-and-after comparison at the caller. An add whose write lands
		// but whose response is lost would take a transition with it, and every
		// later call that day would see a tally already past the line.
		const counter = env.REFUSALS.getByName('lost-response-token');
		await counter.add(today, names(100, 'a'));
		// Stand in for the lost response: the state now says warned, and a
		// caller that never saw the flag asks again.
		await expect(counter.add(today, names(1, 'b'))).resolves.toMatchObject({ alert: false });

		const fresh = env.REFUSALS.getByName('never-warned-token');
		await fresh.add(today, names(99, 'a'));

		await expect(fresh.add(today, names(99, 'a'))).resolves.toMatchObject({ alert: false });
		await expect(fresh.add(today, names(1, 'z'))).resolves.toMatchObject({ alert: true });
	});

	it('clears itself when the idle alarm fires', async () => {
		// Without this an instance persists for every token ever refused.
		const counter = env.REFUSALS.getByName('idle-token');
		await counter.add(today, ['a.example.com']);

		await runDurableObjectAlarm(counter);

		await expect(counter.tally(today)).resolves.toEqual({ total: 0, distinct: 0, hostnames: [] });
	});
});
