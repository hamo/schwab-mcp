# Supply-chain review

## Runtime dependencies

| Package                              | Purpose                                 | Pin   |
| ------------------------------------ | --------------------------------------- | ----- |
| `@cloudflare/workers-oauth-provider` | MCP OAuth authorization server          | exact |
| `@modelcontextprotocol/server`       | MCP server protocol implementation      | exact |
| `agents`                             | Cloudflare stateless MCP Worker handler | exact |
| `zod`                                | Tool input validation                   | exact |

There is no runtime dependency on the original `sudowealth/schwab-mcp` project or on `@sudowealth/schwab-api`. Schwab request construction and token handling are implemented in this repository so their behavior can be audited directly.

## Runtime network destinations

Application code permits only:

- `https://api.schwabapi.com` or the explicitly selected Schwab sandbox host
- the configured `*.cloudflareaccess.com` OIDC issuer
- Client ID Metadata Document resolution performed by Cloudflare's OAuth provider, with its strict-public-fetch compatibility flag

Anonymous OAuth dynamic client registration is disabled. CIMD retrieval is the only application-level network destination whose host is selected by an OAuth client; the OAuth provider validates the document and its redirect URIs.

The Schwab client rejects paths outside `/marketdata/v1/` and `/trader/v1/`. No external logo, analytics script, webhook, telemetry SDK, or API aggregation service is used by application code.

Cloudflare Wrangler itself may collect its documented anonymous CLI telemetry during local development or deployment; that is not part of the deployed Worker.

## Controls

- Exact package versions and npm lockfile v3
- `npm ci` in CI
- CI lifecycle scripts disabled
- npm vulnerability audit for production dependencies
- npm registry signature verification
- full-commit SHA pins for GitHub Actions
- no automated deployment from this public repository
- generated CycloneDX SBOM available with `npm run sbom`

Run:

```sh
npm run supply-chain
npm run sbom
```

At initial implementation, `npm audit --omit=dev` reported zero known vulnerabilities and `npm audit signatures` verified registry signatures for the installed dependency graph. These results are time-sensitive; rerun them before every deployment.

## Updates

Dependency updates should arrive as reviewed pull requests. Do not use floating versions or auto-merge. For every update, inspect release notes and the lockfile diff, rerun all checks and the Worker dry-run bundle, and repeat the registry signature and vulnerability audits.
