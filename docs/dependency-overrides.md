# Dependency overrides

`package.json` can pin transitive (indirect) dependencies through the `overrides` field. These are not
packages we depend on directly; they arrive through wrangler and the test toolchain. We override one only to
force a security-patched version ahead of when its parent packages adopt it themselves.

Each override is a temporary patch, not a permanent dependency. The moment the parent packages resolve the
same package to a version at or above the patched floor on their own, the override stops doing anything and
should be deleted so we are not carrying stale pins.

## Current overrides

None. `package.json` carries no `overrides` block, which is the state to return to.

An override earns its place only when a parent pins an exact version below the patched floor, so the parent
range can never reach a patched release on its own. A caret range that already spans the floor needs no
override; it needs a re-resolve.

`bun audit` queries a live advisory database, so an audit that passed yesterday can flag a version that was
already installed. A new advisory usually means a stale lockfile entry, not a missing override.

## Clearing an audit failure

A `bun audit --audit-level=high` failure is not proof that an override is needed. Most are a lockfile
carrying an old resolution for a package whose parent range already spans the patched floor. From a clean
working tree:

1. Re-resolve from scratch. This also re-applies the publish cooldown:
   ```sh
   rm bun.lock && bun install
   bun audit --audit-level=high
   ```
2. Decide based on the result:
   - **Clean**: the parents reach a patched version on their own. Commit `bun.lock`.
   - **Still flagged**: check the parent's declared range for the flagged package. An exact pin below the
     floor is what an override is for. Add it to `overrides`, add a row to the table above, and re-run the
     audit.

Do not reach for `bun update <package>` on a transitive. Bun reads the name as a new direct dependency,
installs its latest major into `package.json`, and leaves the transitive copy at the version that was
flagged.

## Removal check (run on every dependency bump)

When Dependabot opens its grouped bun update, or any time the parent packages move, test whether each
override still earns its place. From a clean working tree on the update branch:

1. Delete the override you want to test from the `overrides` block in `package.json`.
2. Re-resolve from scratch and audit, as above.
3. Decide based on the audit result:
   - **Clean**: keep the override deleted, drop its row from the table, and commit `package.json` and
     `bun.lock`.
   - **Still flagged**: the override is still doing work. Restore it with
     `git checkout package.json bun.lock && bun install`.

Keep the table in sync with the `overrides` block: every row maps to one pin in `package.json`, and dropping
a pin means deleting its row.
