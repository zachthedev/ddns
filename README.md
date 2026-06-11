# 🌩️ Cloudflare DDNS for UniFi OS

[![CodeQL](https://github.com/zachthedev/ddns/actions/workflows/github-code-scanning/codeql/badge.svg)](https://github.com/zachthedev/ddns/actions/workflows/github-code-scanning/codeql)
[![CI](https://github.com/zachthedev/ddns/actions/workflows/ci.yml/badge.svg)](https://github.com/zachthedev/ddns/actions/workflows/ci.yml)
[![Dependabot Updates](https://github.com/zachthedev/ddns/actions/workflows/dependabot/dependabot-updates/badge.svg)](https://github.com/zachthedev/ddns/actions/workflows/dependabot/dependabot-updates)
[![Deploy](https://github.com/zachthedev/ddns/actions/workflows/deploy.yml/badge.svg)](https://github.com/zachthedev/ddns/actions/workflows/deploy.yml)

A Cloudflare Worker script that enables UniFi devices (e.g., UDM-Pro, USG) to dynamically update DNS A/AAAA records on Cloudflare.

## Notice

This is a fork from [willswire](https://github.com/willswire/unifi-ddns) with the following enhancements:

- **Smart notifications** - Only sends [ntfy](https://ntfy.sh) alerts when a DNS record actually changes
- **API** - Returns structured JSON responses instead of plain text
- **Multi-hostname support** - Update multiple hostnames in a single request using comma-separated values
- **Multi-zone support** - API tokens can manage DNS records across multiple zones, with optional `zone=` scoping
- **Dual-stack support** - Update A and AAAA records together with the `ip6` parameter
- **Token-only auth** - DNS-scoped API tokens; no account email anywhere
- **Audit history** - Every DNS change recorded in D1, queryable at `GET /history`, scoped to your own token
- **Access key lockdown** - Optional `ACCESS_KEY` secret locks the worker to your devices, checked before any API call

## Why Use This?

UniFi Network Application 9.1.92+ ships native Cloudflare DDNS support (Service: Cloudflare, with hostname, zone name, and API token). If all you need is one hostname following your WAN IP, use that.

This worker exists for what the native client doesn't do:

- **Push notifications** via [ntfy](https://ntfy.sh) when your IP actually changes
- **Multi-hostname updates** in a single entry (comma-separated), including across multiple zones
- **Record preservation**: proxy status, TTL, and comments on existing records survive updates
- **`ip4=auto` / `ip6=auto`** for routers behind NAT that would otherwise report a private IP
- **Audit history** of DNS changes for compliance, queryable per token at `GET /history`

## 🚀 **Setup Overview**

### 1. **Deploy the Cloudflare Worker**

#### **Option 1: Click to Deploy**

[![Deploy to Cloudflare Workers](https://deploy.workers.cloudflare.com/button)](https://deploy.workers.cloudflare.com/?url=https://github.com/zachthedev/ddns)

1. Click the button above.
2. Complete the deployment.
3. Note the `*.workers.dev` route.

#### **Option 2: Deploy with the CLI**

Requires [bun](https://bun.sh).

1. Clone this repository.
2. Install dependencies:
   ```sh
   bun install
   ```
3. Log in and run the interactive setup. It provisions the KV namespaces,
   writes their IDs to `.env.local` (gitignored), and optionally configures
   the ntfy notification secret:
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

- `CLOUDFLARE_API_TOKEN` - API token with Workers deploy permissions
- `CLOUDFLARE_ACCOUNT_ID` - Your Cloudflare account ID
- `KV_NAMESPACE_ID` - Production namespace ID (from `.env.local`)
- `KV_NAMESPACE_PREVIEW_ID` - Preview namespace ID (from `.env.local`)
- `NTFY_URL` - Optional ntfy topic URL for change notifications

The committed `wrangler.jsonc` only ever contains placeholders; real IDs are
injected at deploy time from the environment.

### 2. **Generate a Cloudflare API Token**

1. Go to the [Cloudflare Dashboard](https://dash.cloudflare.com/).
2. Navigate to **Profile > API Tokens**
3. Create a token using the **Edit zone DNS** template.
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
     _(Omit `https://`. Comma-separate to update several records at once: `hostnames=example.com,*.example.com`. `ip4`/`ip6` each accept a literal address or `auto`, which uses the connecting IP when it matches that family and skips the slot otherwise; provide at least one. Optional `zone=example.com` restricts matching to one zone.)_

## 📜 **Audit History**

Every DNS change (and every no-op touch of the API) is recorded in D1 with timestamp, hostname, record type, previous and new IP, caller IP, and outcome. Query your own history (scoped to the API token you authenticate with):

```sh
curl -H "Authorization: Bearer <api-token>" -H "X-Access-Key: <access-key-if-set>" \
  "https://<worker-url>/history?limit=50&hostname=example.com"
```

Cache fast-path hits are not recorded; only requests that reached the DNS API produce events.

## 🛠️ **Testing & Troubleshooting**

Using this script with various Ubiquiti devices and different UniFi software versions can introduce unique challenges. If you encounter issues, start by checking the FAQ in `/docs/faq.md`. If you don’t find a solution, you can ask a question on the [discussions page](https://github.com/zachthedev/ddns/discussions/new?category=q-a). If the problem persists, please raise an issue [here](https://github.com/zachthedev/ddns/issues).
