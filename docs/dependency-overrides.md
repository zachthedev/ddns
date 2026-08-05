# Dependency overrides

`package.json` pins transitive (indirect) dependencies through the `overrides` field. These are not packages
we depend on directly; they arrive through wrangler and the test toolchain. We override them only to force a
security-patched version ahead of when those parent packages adopt it themselves.

Each override is a temporary patch, not a permanent dependency. The moment the parent packages resolve the
same package to a version at or above the patched floor on their own, the override stops doing anything and
should be deleted so we are not carrying stale pins.

## Current overrides

| Package | Pinned | Patched floor | Pulled in by                                          | Advisory                                                                 |
| ------- | ------ | ------------- | ----------------------------------------------------- | ------------------------------------------------------------------------ |
| undici  | 7.29.0 | >= 7.29.0     | wrangler, @cloudflare/vitest-pool-workers (miniflare) | [GHSA-4cwx-7wf7-3272](https://github.com/advisories/GHSA-4cwx-7wf7-3272) |

miniflare pins undici to an exact version below the floor, so the parent range can never reach a patched
release on its own. That exact-pin shape is what makes an override load-bearing; a caret range that already
spans the floor does not need one.

`bun audit` queries a live advisory database, so an audit that passed yesterday can flag a version that was
already installed. A new row here usually means a fresh advisory, not a fresh dependency.

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

## Before adding a new override

A fresh `bun audit` failure is not proof that an override is needed. Run `rm bun.lock && bun install` first
and audit again: a lockfile carrying an old resolution flags a package whose parent range already spans the
patched floor. Add the override only if the advisory survives a clean re-resolve.
