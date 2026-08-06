import { env } from 'cloudflare:workers';
import { applyD1Migrations, type D1Migration } from 'cloudflare:test';
import { beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { parseHistoryCursor, queryHistory } from '../src/audit';

/**
 * The paging contract, run against a real D1 built from the real migration.
 *
 * The rest of the audit suite mocks D1, which can only assert the shape of the
 * SQL that goes out. What this change exists to deliver is a walk that returns
 * every row exactly once across page boundaries that land inside a group of
 * rows sharing a timestamp, and no mock can answer whether that holds.
 */
// The test pool supplies this from the vitest config rather than
// wrangler.jsonc, so the generated Env cannot know about it.
const testMigrations = (env as unknown as { TEST_MIGRATIONS: D1Migration[] }).TEST_MIGRATIONS;

const OWNER = 'token-owner';
const STRANGER = 'token-stranger';

const stamp = (second: number, ms = 0): string =>
	`2027-03-04T09:${String(Math.floor(second / 60)).padStart(2, '0')}:${String(second % 60).padStart(2, '0')}.${String(ms).padStart(3, '0')}Z`;

const insert = async (occurredAt: string, tokenId: string, hostname: string): Promise<void> => {
	await env.AUDIT_DB.prepare(
		'INSERT INTO audit_events (occurred_at, token_id, caller_ip, hostname, record_type, previous_ip, new_ip, outcome) VALUES (?, ?, ?, ?, ?, ?, ?, ?)',
	)
		.bind(occurredAt, tokenId, '203.0.113.7', hostname, 'A', '1.2.3.4', '1.2.3.5', 'updated')
		.run();
};

/** Every hostname the walk returns, in order, following the cursor to the end. */
const walk = async (limit: number, hostname: string | null = null): Promise<string[]> => {
	const seen: string[] = [];
	let before = null as ReturnType<typeof parseHistoryCursor>;
	for (let page = 0; page < 500; page++) {
		const result = await queryHistory(env, { tokenId: OWNER, hostname, limit, before });
		seen.push(...result.events.map((event) => String(event['hostname'])));
		if (result.cursor === null) {
			return seen;
		}
		before = parseHistoryCursor(result.cursor);
		// A cursor the emitter produced and the parser refuses would strand the
		// walk on a 422 blaming the caller for a value the server handed it.
		expect(before).not.toBeNull();
	}
	throw new Error('the walk did not reach a last page');
};

describe('history pagination against a real D1', () => {
	beforeAll(async () => {
		await applyD1Migrations(env.AUDIT_DB, testMigrations);
	});

	beforeEach(async () => {
		await env.AUDIT_DB.prepare('DELETE FROM audit_events').run();
	});

	it('returns every row exactly once when a page boundary lands inside a shared timestamp', async () => {
		// A batch writes one row per record in the same millisecond, so a group
		// larger than a page is the ordinary case, not a contrived one.
		await insert(stamp(3), OWNER, 'newest.example.com');
		for (let i = 0; i < 25; i++) {
			await insert(stamp(2), OWNER, `tie-${String(i).padStart(2, '0')}.example.com`);
		}
		await insert(stamp(1), OWNER, 'oldest.example.com');
		const whole = await walk(100);

		for (const limit of [1, 2, 7, 26]) {
			const paged = await walk(limit);

			expect(paged).toEqual(whole);
			expect(new Set(paged).size).toBe(27);
		}
	});

	it('never returns another token rows, whatever the cursor says', async () => {
		await insert(stamp(2), OWNER, 'mine.example.com');
		await insert(stamp(2), STRANGER, 'theirs.example.com');
		await insert(stamp(1), OWNER, 'mine-older.example.com');

		const paged = await walk(1);

		expect(paged).toEqual(['mine.example.com', 'mine-older.example.com']);
	});

	it('picks up a row written into a group the walk is still crossing', async () => {
		// Audit rows ride ctx.waitUntil, so one can land in D1 well after the
		// timestamp it carries. Ordering a shared timestamp by ascending id puts
		// the late arrival after the cursor rather than behind it.
		for (let i = 0; i < 4; i++) {
			await insert(stamp(2), OWNER, `batch-${String(i)}.example.com`);
		}
		await insert(stamp(1), OWNER, 'older.example.com');

		const first = await queryHistory(env, { tokenId: OWNER, hostname: null, limit: 2, before: null });
		await insert(stamp(2), OWNER, 'late.example.com');
		const seen = first.events.map((event) => String(event['hostname']));
		let before = parseHistoryCursor(first.cursor ?? '');
		while (before !== null) {
			const next = await queryHistory(env, { tokenId: OWNER, hostname: null, limit: 2, before });
			seen.push(...next.events.map((event) => String(event['hostname'])));
			before = next.cursor === null ? null : parseHistoryCursor(next.cursor);
		}

		expect(seen).toContain('late.example.com');
		expect(new Set(seen).size).toBe(seen.length);
	});

	it('walks a hostname-filtered history the same way', async () => {
		for (let i = 0; i < 6; i++) {
			await insert(stamp(2), OWNER, i % 2 === 0 ? 'wanted.example.com' : 'other.example.com');
		}

		const paged = await walk(2, 'wanted.example.com');

		expect(paged).toEqual(['wanted.example.com', 'wanted.example.com', 'wanted.example.com']);
	});

	it('reports no cursor when the last page is exactly full', async () => {
		// The off-by-one that would hand back an empty final page and a cursor
		// pointing at nothing.
		await insert(stamp(2), OWNER, 'a.example.com');
		await insert(stamp(1), OWNER, 'b.example.com');

		const result = await queryHistory(env, { tokenId: OWNER, hostname: null, limit: 2, before: null });

		expect(result.events).toHaveLength(2);
		expect(result.cursor).toBeNull();
	});
});
