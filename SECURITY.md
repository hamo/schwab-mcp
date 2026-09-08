# Security policy

## Reporting a vulnerability

Please use GitHub's private vulnerability reporting for this repository. Do not open a public issue containing credentials, tokens, account identifiers, Worker URLs tied to a private deployment, or exploit details.

## Secret handling

Never commit any of the following:

- Schwab app keys, secrets, authorization codes, access tokens, or refresh tokens
- Cloudflare API tokens or Access OIDC secrets
- owner email or account fingerprints for a real deployment
- `TOKEN_ENCRYPTION_KEY` or `STATE_SIGNING_KEY`
- `.dev.vars`, `.env`, logs, storage exports, or screenshots containing the above

If a secret reaches Git history, revoke or rotate it immediately. Removing the text in a later commit is not sufficient.

## Trust boundaries

The deployment depends on the security of the owner's email identity provider, Cloudflare account, Schwab account, ChatGPT account, local browser, and deployment secrets. Public source code is not treated as a security boundary.

OAuth and approval state is HMAC-signed, encrypted at rest, expires after ten minutes, and is atomically consumed through the Durable Object. Cloudflare Access ID tokens are accepted only after signature and claim validation and an exact owner-email comparison. Schwab tokens are encrypted at rest with a deployment-specific key. The Durable Object is reachable only through an internal binding.

The user-preference tool exposes only market-data permission flags and whether Schwab streaming is available. It removes account numbers, display IDs, nicknames, streamer URLs, customer IDs, channel IDs, function IDs, and correlation IDs.

OAuth dynamic client registration is disabled. Client ID Metadata Documents are shown with their exact redirect URI and requested scopes on the consent page. MCP access and refresh credentials expire after one hour and seven days respectively; revoke access sooner by clearing the OAuth KV/metadata and the deployment's Durable Object storage, or by rotating the relevant deployment secrets.

## Trading

`TRADING_MODE=disabled` is the safe default and omits Schwab write tools from MCP discovery. `preview` exposes preparation only. `live` additionally requires the granted `mcp:trade` OAuth scope and a separate, expiring browser approval for the complete exact action digest before execution. Approval and execution transitions are atomic, and an approved action can be consumed only once. Actions too large to display in full are rejected.

Approval prevents an MCP client from silently executing a newly prepared action, but it does not verify that an order is financially suitable. A network interruption during order submission can leave the outcome uncertain. Inspect Schwab's order history before retrying.

Use a separate Worker, KV namespace, Durable Object namespace, encryption key, and preferably Schwab application for a live deployment. Do not change a read-only Worker in place to live mode.

## Logging

The Worker does not intentionally log tokens, order payloads, account hashes, or upstream error bodies. Keep Cloudflare log access restricted. Review any new logging before deployment.
