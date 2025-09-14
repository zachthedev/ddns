# KV Namespace Setup for IP Change Detection

This document explains how to set up the optional KV namespace to enable IP change detection, which prevents unnecessary DNS updates when your IP hasn't changed.

## Why use KV?

Without KV namespace:
- The worker will update DNS records on every request
- Notifications will be sent for every update
- This can lead to unnecessary API calls and notifications

With KV namespace:
- The worker stores the last known IP address
- Only updates DNS when the IP actually changes
- Reduces API calls to Cloudflare DNS
- Reduces unnecessary notifications

## Setup Instructions

### 1. Create KV Namespaces

Using Wrangler CLI:

```bash
# Create production namespace
wrangler kv namespace create DDNS_KV

# Create preview namespace (for testing)
wrangler kv namespace create DDNS_KV --preview
```

This will output something like:
```
🌀 Creating namespace with title "ddns-DDNS_KV"
✨ Success!
Add the following to your configuration file in your kv_namespaces array:
{ binding = "DDNS_KV", id = "abc123def456", preview_id = "ghi789jkl012" }
```

### 2. Update wrangler.jsonc

Add the KV namespace configuration to your `wrangler.jsonc`:

```jsonc
{
	"$schema": "node_modules/wrangler/config-schema.json",
	"name": "ddns",
	"main": "src/index.ts",
	"compatibility_date": "2025-09-01",
	"compatibility_flags": ["nodejs_compat"],

	// KV Namespace for storing last known IP address
	"kv_namespaces": [
		{
			"binding": "DDNS_KV",
			"id": "your-production-namespace-id",
			"preview_id": "your-preview-namespace-id"
		}
	],

	// ... rest of configuration
}
```

### 3. Update TypeScript Types

Update `worker-configuration.d.ts`:

```typescript
declare namespace Cloudflare {
	interface Env {
		DDNS_KV: KVNamespace; // Remove the ? to make it required
	}
}
```

### 4. Redeploy

Deploy your worker with the updated configuration:

```bash
wrangler deploy
```

## Verification

After setup, you can verify KV is working by:

1. Making your first DDNS update - it should succeed and store the IP
2. Making a second request with the same IP - it should respond with "OK. No IP change detected."
3. Making a request with a different IP - it should update DNS and send notifications

## Troubleshooting

### Worker deploys but KV doesn't work

- Check that the namespace IDs in `wrangler.jsonc` match the ones created
- Verify the binding name is exactly "DDNS_KV"
- Check worker logs for KV errors

### KV namespace not found error

- Ensure you're using the correct account ID in wrangler
- Verify the namespace was created in the same account as your worker
- Check that you have the right permissions

## Alternative: GitHub Actions Setup

If you prefer to automate KV namespace creation in CI/CD, you can add this to your deployment workflow:

```yaml
- name: Create KV namespaces if needed
  run: |
    # This will create namespaces if they don't exist, or do nothing if they do
    wrangler kv namespace create DDNS_KV || true
    wrangler kv namespace create DDNS_KV --preview || true
  env:
    CLOUDFLARE_API_TOKEN: ${{ secrets.CLOUDFLARE_API_TOKEN }}
    CLOUDFLARE_ACCOUNT_ID: ${{ secrets.CLOUDFLARE_ACCOUNT_ID }}
```

Note: This approach requires you to manually extract the namespace IDs from the CI logs and update your `wrangler.jsonc` file.