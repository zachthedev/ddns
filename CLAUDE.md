# uddns

Cloudflare Worker providing DDNS updates for UniFi OS devices, with per-caller
ntfy notifications, multi-zone tokens, a D1 audit trail, and a JSON API.
Originally derived from willswire/unifi-ddns; now an independent project.

Toolchain: bun (package manager and script runner), wrangler, vitest with
the Cloudflare Workers pool, ESLint + prettier, lefthook hooks.

- Install: `bun install`
- Verify everything: `bun run check:all`
- Deploy (local or CI): `bun run deploy` (see scripts/deploy.ts)
- First-time setup on a clone or fork: `bun run setup`

Cloudflare resource naming: `<type>-<project>-<purpose>-<env>`, e.g.
`kv-uddns-cache-prod`, `kv-uddns-cache-dev`, `d1-uddns-audit-prod`. Binding
names in code stay short (`DDNS_KV`, `AUDIT_DB`). The D1 name comes from
wrangler.jsonc and follows the convention automatically; KV namespaces
created by `bun run setup` get wrangler's default titles, and the
convention-named titles are applied by renaming in the dashboard (titles are
cosmetic; IDs and bindings are what matter). The production worker is named
`uddns` and is served at the custom domain `ddns.quist.network`.

Rules:

@.claude/rules/github-cli.md
