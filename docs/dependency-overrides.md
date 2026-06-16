# Dependency overrides

`package.json` pins a few transitive (indirect) dependencies through the `overrides` field. These are not
packages we depend on directly; they arrive through wrangler, vitest, and the cloudflare SDK. We override
them only to force a security-patched version ahead of when those parent packages adopt it themselves.

Each override is a temporary patch, not a permanent dependency. The moment the parent packages resolve the
same package to a version at or above the patched floor on their own, the override stops doing anything and
should be deleted so we are not carrying stale pins.

## Current overrides

| Package   | Pinned | Patched floor | Pulled in by                                          | Advisory                                                                 |
| --------- | ------ | ------------- | ----------------------------------------------------- | ------------------------------------------------------------------------ |
| esbuild   | 0.28.1 | >= 0.28.1     | wrangler, vitest, @cloudflare/vitest-pool-workers     | [GHSA-gv7w-rqvm-qjhr](https://github.com/advisories/GHSA-gv7w-rqvm-qjhr) |
| form-data | 4.0.6  | >= 4.0.6      | cloudflare (via @types/node-fetch)                    | [GHSA-hmw2-7cc7-3qxx](https://github.com/advisories/GHSA-hmw2-7cc7-3qxx) |
| ws        | 8.21.0 | >= 8.21.0     | wrangler, @cloudflare/vitest-pool-workers (miniflare) | [GHSA-96hv-2xvq-fx4p](https://github.com/advisories/GHSA-96hv-2xvq-fx4p) |

Added 2026-06-16. The advisories were published against versions that were already in the tree; the grouped
dependency bump in #175 did not introduce them. `bun audit` queries a live advisory database, so a
previously-green audit started flagging versions that were already installed.

## Removal check (run on every dependency bump)

When Dependabot opens its grouped bun update, or any time the parent packages move, test whether each
override still earns its place. From a clean working tree on the update branch:

1. Delete the override you want to test from the `overrides` block in `package.json`.
2. Re-resolve from scratch (this also re-applies the publish cooldown) and audit:
   ```sh
   rm bun.lock && bun install
   bun audit --audit-level=high
   ```
3. Decide based on the audit result:
   - **Clean**: the parents now resolve to a patched version on their own. Keep the override deleted and
     commit `package.json` + `bun.lock`.
   - **Still flagged**: the override is still doing work. Restore it with
     `git checkout package.json bun.lock && bun install`.

Keep this table in sync with the `overrides` block: every row here maps to one pin in `package.json`, and
dropping a pin means deleting its row.
