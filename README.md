# 🌩️ Cloudflare DDNS for UniFi OS

[![CodeQL](https://github.com/zachthedev/uddns/actions/workflows/github-code-scanning/codeql/badge.svg)](https://github.com/zachthedev/uddns/actions/workflows/github-code-scanning/codeql)
[![CI](https://github.com/zachthedev/uddns/actions/workflows/ci.yml/badge.svg)](https://github.com/zachthedev/uddns/actions/workflows/ci.yml)
[![Dependabot Updates](https://github.com/zachthedev/uddns/actions/workflows/dependabot/dependabot-updates/badge.svg)](https://github.com/zachthedev/uddns/actions/workflows/dependabot/dependabot-updates)
[![Deploy](https://github.com/zachthedev/uddns/actions/workflows/deploy.yml/badge.svg)](https://github.com/zachthedev/uddns/actions/workflows/deploy.yml)

A Cloudflare Worker that lets UniFi OS devices (UDM and UXG series) dynamically update DNS A/AAAA records on Cloudflare.

## Features

- **Push notifications** - Per-caller [ntfy](https://ntfy.sh) alerts via the `ntfy=` parameter (self-hosted servers supported), sent only when a DNS record actually changes
- **Multi-hostname updates** - Comma-separated hostnames in a single entry, including across multiple zones, with every record's own outcome reported when a batch fails part-way
- **Multi-zone tokens** - One token can manage records in several zones, with optional `zone=` scoping
- **Dual-stack** - Explicit `ip4`/`ip6` parameters with family-aware `auto`, updating A and AAAA together
- **Record preservation** - Proxy status, TTL, and comments on existing records survive updates
- **Token-only auth** - DNS-scoped API tokens; no account email anywhere
- **Access key lockdown** - Optional `ACCESS_KEY` secret locks the worker to your devices, checked timing-safe before any API call
- **Audit history** - Every DNS change recorded in D1, queryable at `GET /history`, scoped to your own token
- **Built for throughput** - KV-cached fast path, edge rate limiting, and a structured JSON API

## Why Use This?

UniFi Network Application 9.1.92+ ships native Cloudflare DDNS support (Service: Cloudflare, with hostname, zone name, and API token). If all you need is one hostname following your WAN IP, use that. This worker exists for everything the native client doesn't do: the feature list above.

## 🚀 **Setup Overview**

### 1. **Deploy the Cloudflare Worker**

#### **Option 1: Click to Deploy**

[![Deploy to Cloudflare Workers](https://deploy.workers.cloudflare.com/button)](https://deploy.workers.cloudflare.com/?url=https://github.com/zachthedev/uddns)

1. Click the button above.
2. Complete the deployment.
3. Note the `*.workers.dev` route.
4. Apply the D1 migrations afterwards (`bun x wrangler d1 migrations apply AUDIT_DB --remote`); the button flow provisions resources but does not run migrations, so `/history` and audit logging stay dark until you do. Options 2 and 3 handle this automatically.

#### **Option 2: Deploy with the CLI**

Requires [bun](https://bun.sh).

1. Clone this repository.
2. Install dependencies:
   ```sh
   bun install
   ```
3. Log in and run the interactive setup. It provisions the KV namespaces and
   the D1 audit database, writes their IDs to `.env.local` (gitignored), and
   offers to generate an access key:
   ```sh
   bun x wrangler login
   bun run setup
   ```
4. Deploy:
   ```sh
   bun run deploy
   ```
5. Note the `*.workers.dev` route.

#### **Option 3: Deploy on every push with GitHub Actions**

Fork this repository, run setup locally once (Option 2, steps 1 to 3), then add
these repository secrets; every push to `main` deploys automatically:

- `CLOUDFLARE_API_TOKEN` - API token with Workers Scripts, Workers KV, and D1 edit permissions
- `CLOUDFLARE_ACCOUNT_ID` - Your Cloudflare account ID
- `KV_NAMESPACE_ID` - Production namespace ID (from `.env.local`)
- `KV_NAMESPACE_PREVIEW_ID` - Preview namespace ID (from `.env.local`)
- `D1_DATABASE_ID` - Audit database ID (from `.env.local`)
- `ACCESS_KEY` - Optional; locks the worker to callers that present it

Notifications need no deployment configuration: callers pass their own ntfy
target with the `ntfy=` query parameter.

The committed `wrangler.jsonc` only ever contains placeholders; real IDs are
injected at deploy time from the environment.

### 2. **Generate a Cloudflare API Token**

1. Go to the [Cloudflare Dashboard](https://dash.cloudflare.com/).
2. Navigate to **Profile > API Tokens**
3. Create a custom token with **Zone → Zone → Read** and **Zone → DNS → Edit** (the worker lists your zones to find each hostname's record, so DNS Edit alone is not enough).
4. Scope the token to the zone(s) you want to update. One zone keeps the blast radius small; multiple zones are supported, but each hostname must match exactly one record across them.
5. Save the token securely.

### 3. **Configure UniFi OS**

1. Log in to your [UniFi OS Controller](https://unifi.ui.com/).
2. Go to **Settings > Internet > WAN > Dynamic DNS**.
3. Create New Dynamic DNS with the following information:
   - **Service:** `custom`
   - **Hostname:** `subdomain.example.com` or `example.com`
   - **Username:** Your `ACCESS_KEY` if you configured one (recommended); any value otherwise (the field is never used for authentication)
   - **Password:** Cloudflare User API Token scoped to DNS edit _(not an Account API Token)_
   - **Server:** `<worker-name>.<worker-subdomain>.workers.dev/update?ip4=%i&ip6=auto&hostnames=%h`
     _(Omit `https://`. Comma-separate to update several records at once: `hostnames=example.com,*.example.com`. A request carries up to 40 records, and each hostname counts once per IP family, so 40 hostnames with `ip4` alone or 20 with both. Batches near that size need the paid Workers plan; the free plan's 50-subrequest ceiling fits roughly six records. `ip4`/`ip6` each accept a literal address or `auto`, which uses the connecting IP when it matches that family and skips the slot otherwise; provide at least one. Optional `zone=example.com` restricts matching to one zone. Optional `ntfy=` sends change notifications to your ntfy server, pasted raw: `ntfy=https://ntfy.sh/my-topic`. Do not percent-encode it; inadyn treats `%` sequences as its own substitution variables.)_

## 📜 **Audit History**

Every DNS change (and every no-op touch of the API) is recorded in D1 with timestamp, hostname, record type, previous and new IP, caller IP, and outcome. Query your own history (scoped to the API token you authenticate with):

```sh
curl -H "Authorization: Bearer <api-token>" -H "X-Access-Key: <access-key-if-set>" \
  "https://<worker-url>/history?limit=50&hostname=example.com"
```

Cache fast-path hits are not recorded; only requests that reached the DNS API produce events.

Pages are capped at 1000 events. The response carries `data.cursor`, and passing it back as `before=`
continues from where the page ended; it is `null` on the last page. Treat the value as opaque and pass it
verbatim, and keep `hostname=` fixed across a walk, since the cursor is a position in the result set the
page came from. `data.refusedToday` below rides on the first page only, since it describes the day rather
than the page.

The cursor embeds the audit row's id, which is a table-wide sequence. On a deployment several people share,
that lets one of them read the total number of audit rows written before their own, and polling it times
the others' activity. It is aggregate volume, never row contents, and a deployment serving one household
leaks nothing to itself. Signing the cursor would close it, and that needs a deployment secret this worker
does not require: `ACCESS_KEY` is optional, and the deployments that leave it unset are the shared ones
where this matters.

The response also carries `data.refusedToday`: the times this token reached past its own authority today,
UTC, and the names it reached for.

```json
{ "total": 47, "distinct": 2, "hostnames": ["typo.example.net", "old.example.net"] }
```

Reaching past authority means a hostname no zone on the token could hold, or a `zone=` naming a zone it
cannot see. A record you have not created yet is **not** counted, nor is a token missing the Zone Read
scope, nor is a token that sees no zones at all: those are setup steps, and counting them would bury the
signal under every new user's first afternoon. The `hostnames` list is your own, so it names exactly which
of your entries to fix. It carries 50 of them, the last to be seen for the first time, since a name refused
again keeps its original place. `distinct` counts every name the tally kept, which itself stops at 200.

Refusals are **counted, not recorded per event**. Any active Cloudflare token can produce them without
limit, so a row apiece would let one caller grow a table every deployment shares. The tally lives in a
Durable Object, one instance per token: requests to an instance serialize, so nothing is lost to a race and
there is no batching window for a caller to time a burst against. Padding a batch changes the count, never
what the count sees. It resets when the UTC day rolls.

That moves per-caller growth rather than removing it: any active token that reaches past its authority
creates one instance. Each holds a single key, keeps at most 200 distinct names, spends at most 699 writes
a day before the tally goes quiet, and clears itself 24 to 48 hours after the last refusal, so the bound is
the reclaim window rather than the decision to count.

Crossing 100 **distinct** names in a day logs a warning to Workers Logs, because `/history` is scoped to
the very token being counted: without the log the tally would only ever be visible to the caller it
describes. Distinct rather than total, because a DDNS client polls every two minutes, so one hostname typed
wrong passes any total given an afternoon. Variety is what a caller sweeping for names it does not hold
produces and a misconfigured one does not.

Three limits are worth stating plainly. The tally is keyed on the API token, and a Cloudflare account
issues tokens freely, so an enumerator that rotates tokens before reaching the threshold never trips it.
The per-record IP cache is consulted before zones are read, so for up to its own 30-day TTL after a token
loses a zone, a name it used to hold still answers 200 and counts nothing; that is the record cache, not
the 5-minute zone cache. And a zone added within the last five minutes reads as outside the token's
authority until the zone cache expires. The warning is a cheap way to see a misconfigured or careless
caller, not a control that stops a determined one.

Nothing is counted against a token that sees more than 1000 zones. The zone walk stops at that ceiling, so
a hostname in a zone past it was never looked for rather than reached for.

## ⚡ **Throughput & Cost**

The worker is built to take heavy public traffic cheaply:

- **Steady-state polling is API-free.** With the access key configured, a request whose records all match the KV cache answers with zero Cloudflare API calls: one worker invocation, one rate-limit check, and one KV read per record. A device polling every 2 minutes costs ~22k invocations and ~44k KV reads per month per record pair, far inside the Workers paid plan's included 10M requests and 10M KV reads.
- **Cache misses stay lean.** Token verification and the zone list (cached per token for 5 minutes) front a parallel record lookup; only records whose DNS content actually differs trigger an update call. Audit writes and notifications ride `ctx.waitUntil` after the response.
- **Strangers are throttled at the edge.** The rate limiter (50 requests/minute per IP, per colo) returns 429 before authentication runs, and an unauthenticated or wrong-key request never reaches the Cloudflare API, KV, or D1. Enforcement is Cloudflare's best-effort, eventually-consistent counter, a cost cap against sustained abuse rather than a precise gate; short bursts can overshoot.
- **Ballpark beyond included quotas** (Workers paid plan pricing): ~$0.30 per additional 1M requests, ~$0.50 per additional 1M KV reads; D1 audit volume is negligible by design (rows only on actual DNS-touching events). A refusal costs one Durable Object call and up to two of its storage writes; `GET /history` costs one read-only call.

## 🛠️ **Testing & Troubleshooting**

Using this script with various Ubiquiti devices and different UniFi software versions can introduce unique challenges. If you encounter issues, start by checking the FAQ in `/docs/faq.md`. If you don’t find a solution, you can ask a question on the [discussions page](https://github.com/zachthedev/uddns/discussions/new?category=q-a). If the problem persists, please raise an issue [here](https://github.com/zachthedev/uddns/issues).

## 🙏 **Acknowledgments**

This project began as a fork of [willswire/unifi-ddns](https://github.com/willswire/unifi-ddns) and has since been rewritten end to end. Thanks to Will Walker for the original worker that made UniFi-to-Cloudflare DDNS approachable in the first place.
