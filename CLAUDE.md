# ddns

Cloudflare Worker providing DDNS updates for UniFi devices. Fork of
willswire/unifi-ddns with notification, multi-zone, and JSON API features.

Toolchain: bun (package manager and script runner), wrangler, vitest with
the Cloudflare Workers pool, ESLint + prettier, lefthook hooks.

- Install: `bun install`
- Verify everything: `bun run check:all`
- Deploy (local or CI): `bun run deploy` (see scripts/deploy.ts)
- First-time setup on a clone or fork: `bun run setup`

Rules:

@.claude/rules/github-cli.md
