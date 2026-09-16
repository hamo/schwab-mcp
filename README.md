# schwab-mcp

A private, self-hosted Schwab MCP server for Cloudflare Workers. It uses the current stateless Streamable HTTP transport at `/mcp`, Cloudflare Access for owner authentication, and a small first-party Schwab HTTP client.

This project is not affiliated with or endorsed by Charles Schwab, Cloudflare, or OpenAI. Brokerage activity involves risk. Review every live order yourself.

## Security model

```text
ChatGPT/Codex
    │ MCP OAuth 2.1 + PKCE
    ▼
Cloudflare Worker ── Cloudflare Access OIDC ── exact owner email
    │
    ├── /mcp (authenticated Streamable HTTP)
    ├── OAuth provider metadata (Cloudflare KV)
    └── encrypted flow state and Schwab tokens (single Durable Object)
                                      │
                                      ▼
                              Schwab Trader/Market APIs
```

The repository contains no credentials. The Worker checks the configured email after cryptographically verifying the Cloudflare Access ID token, including its signature, issuer, audience, authorized party, nonce, and lifetime. OAuth and approval state is encrypted and atomically consumed in Durable Object storage. Schwab tokens are encrypted with AES-256-GCM before Durable Object storage. Raw account numbers are redacted from MCP responses.

OAuth clients must use a Client ID Metadata Document (CIMD). Anonymous dynamic client registration is intentionally disabled, so arbitrary visitors cannot create persistent OAuth clients in the deployment. The consent page displays the client ID, exact redirect URI, and requested scopes before authentication. MCP access tokens last one hour and refresh tokens last 30 days.

Cloudflare Access must also have an `Allow` policy containing only the owner's exact email. The code-level email check is a second independent guard.

## Trading modes

| Mode       | Preparation tools          | Schwab write requests                |
| ---------- | -------------------------- | ------------------------------------ |
| `disabled` | Not registered             | Impossible through MCP               |
| `preview`  | Registered                 | Never sent                           |
| `live`     | Requires `mcp:trade` scope | Only after one-time browser approval |

The checked-in default is `disabled`. In live mode, preparing an order creates a ten-minute approval URL. Opening it requires a fresh Cloudflare Access login; the page shows the exact action and digest. Approval is one-time. The execution tool remains guarded by a second runtime mode check.

Use separate Worker names, KV namespaces, and Schwab applications for read-only, preview, and live deployments. The example configurations intentionally use placeholders:

- `wrangler.jsonc` — read-only default
- `wrangler.preview.jsonc` — dry-run order preparation
- `wrangler.live.jsonc` — live order support

## Implemented tools

The disabled/read-only deployment registers 20 tools:

- connection status, owner-only Schwab reauthorization, and allowed account hashes/fingerprints
- accounts, balances, and optional positions
- bulk and single-symbol quotes, including extended and fundamental fields
- price history with validated period/frequency combinations
- paged or raw option chains, preserving Schwab-provided Greeks, implied
  volatility, theoretical values, and market timestamps; plus expiration calendars
- market movers and market hours
- paged instrument search and CUSIP lookup
- account-scoped order lists and individual orders
- account-scoped transaction lists and individual transactions
- sanitized market-data permissions and streaming availability

Cross-account reads are implemented as separate account-scoped Schwab requests for only the hashes admitted by the deployment allowlist. User preferences omit account numbers, nicknames, streamer URLs, customer IDs, and correlation IDs.

Large quotes, candles, positions, orders, transactions, instrument searches, and option chains use bounded output pages. Pass each opaque `nextCursor` into the next call until it is `null`; cursor keys are based on stable Schwab identifiers instead of array offsets and are bound to the exact tool and normalized query. A cursor from another query is rejected. Each page is still a fresh Schwab request, so `fetchedAt` and Schwab-provided timestamps identify when values were observed. Records created after a traversal starts may appear on a later page, but inserting them cannot shift the continuation point. An individually oversized record is omitted with its stable key and size in `oversizedItems`, while the cursor advances so later records remain readable. `outputMode=raw` is available for queries already narrowed enough to remain below the MCP response limit.

When enabled, three trading tools prepare place, replace, and cancel actions. The typed order schema supports common equity, mutual-fund, option, multi-leg, trailing-stop, OCO, and trigger fields. Only a live deployment with the `mcp:trade` scope registers `schwab_execute_approved_order`, for a total of 24 tools.

Schwab refresh tokens periodically require an interactive login. When `schwab_connection_status` reports `reauthorizationRequired: true`, call `schwab_reauthorize`, open its ten-minute one-time URL, and complete Cloudflare Access plus Schwab login. The new Schwab session replaces the expired session only after authorization succeeds.

Continuous Schwab Streamer subscriptions are intentionally not included. Cloudflare cannot hibernate a Durable Object that holds an outbound WebSocket, so a persistent market-data connection consumes duration even while idle and can exhaust a free-plan allowance. The sanitized user-preference tool reports whether streaming is available without exposing the connection credentials.

## Deploy the read-only version

These steps work with Cloudflare's free tier, including SQLite-backed Durable Objects. You need a Schwab developer application and a Cloudflare account with a Workers subdomain.

1. Install and verify the project.

   ```sh
   npm ci --ignore-scripts
   npm run check
   npm run supply-chain
   ```

2. Sign in to Cloudflare and create a KV namespace.

   ```sh
   npx wrangler login
   npx wrangler kv namespace create OAUTH_KV
   ```

   Copy the public template to the ignored local deployment configuration:

   ```sh
   cp wrangler.jsonc wrangler.local.jsonc
   ```

   Put the returned namespace ID into `wrangler.local.jsonc`. Replace
   `REPLACE_WITH_WORKER_HOSTNAME` with the deployment's Worker or custom-domain
   hostname. Keep `wrangler.local.jsonc` private; Git ignores it by default.

3. Create a Cloudflare Access **SaaS application** using generic OIDC.

   - Redirect URL: `https://<worker-hostname>/callback`
   - Scopes: `openid`, `email`, `profile`
   - Enable PKCE.
   - Add one Access policy: `Allow` → `Emails` → your exact email.
   - Do not add broad domains, `Everyone`, bypass rules, or service-token rules.
   - Record the team domain, OIDC client ID, and OIDC client secret.

4. Configure the Schwab developer application.

   - Callback URL: `https://<worker-hostname>/schwab/callback`
   - Record the Schwab app key and secret.
   - Callback URLs must match exactly, including HTTPS and path.

5. Add Worker secrets interactively. None of these values belong in `wrangler.jsonc` or Git.

   ```sh
   npx wrangler secret put OWNER_EMAIL
   npx wrangler secret put ACCESS_TEAM_DOMAIN
   npx wrangler secret put ACCESS_CLIENT_ID
   npx wrangler secret put ACCESS_CLIENT_SECRET
   npx wrangler secret put SCHWAB_CLIENT_ID
   npx wrangler secret put SCHWAB_CLIENT_SECRET
   npx wrangler secret put TOKEN_ENCRYPTION_KEY
   npx wrangler secret put STATE_SIGNING_KEY
   ```

   Generate the two random values locally:

   ```sh
   openssl rand -base64 32
   openssl rand -base64 48
   ```

   Use the first output for `TOKEN_ENCRYPTION_KEY` and the second for `STATE_SIGNING_KEY`.

6. Deploy.

   ```sh
   npm run deploy
   ```

7. Add `https://<worker-hostname>/mcp` as a remote MCP server in ChatGPT/Codex. The client must support Client ID Metadata Documents. The first authorization runs through both Cloudflare Access and Schwab. The MCP endpoint uses Streamable HTTP; do not append `/sse`.

## Optional account allowlist

After the first connection, call `schwab_list_account_hashes`. It returns Schwab account hashes plus non-reversible base64url SHA-256 fingerprints, never raw account numbers. To restrict a deployment to selected accounts, store a comma-separated fingerprint list as another Worker secret:

```sh
npx wrangler secret put OWNER_ACCOUNT_FINGERPRINTS
```

The restriction is applied on subsequent tool calls. To expand the list beyond hashes captured during the original authorization, clear the deployment's Durable Object storage and reconnect Schwab.

## Local development

Copy `.dev.vars.example` to `.dev.vars` and fill it locally. `.dev.vars` is ignored by Git. Local OAuth callbacks must also be registered with Cloudflare Access and Schwab, so a temporary HTTPS Worker deployment is usually simpler than localhost for end-to-end testing.

```sh
npm run dev
```

## Supply chain

This repository does **not** import `@sudowealth/schwab-api`, `workers-mcp`, Clearbit, or another runtime API proxy. The Worker makes outbound calls only to the configured Cloudflare Access OIDC endpoints and official Schwab API hosts.

All npm versions are exact and `package-lock.json` is committed. CI installs the lockfile without lifecycle scripts, runs tests/types/lint/format checks, checks production vulnerabilities, and verifies npm registry signatures. See [SUPPLY_CHAIN.md](SUPPLY_CHAIN.md) and [SECURITY.md](SECURITY.md).

## References

- [OpenAI MCP setup](https://learn.chatgpt.com/zh-Hans/docs/extend/mcp)
- [Cloudflare remote MCP servers](https://developers.cloudflare.com/agents/model-context-protocol/guides/remote-mcp-server/)
- [Cloudflare Access for MCP](https://developers.cloudflare.com/cloudflare-one/access-controls/ai-controls/secure-mcp-servers/)
- [Cloudflare generic OIDC SaaS application](https://developers.cloudflare.com/cloudflare-one/access-controls/applications/http-apps/saas-apps/generic-oidc-saas/)

## License

MIT
