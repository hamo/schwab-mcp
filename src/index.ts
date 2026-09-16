import { OAuthProvider } from "@cloudflare/workers-oauth-provider";
import {
  getTradingMode,
  MCP_ACCESS_TOKEN_TTL_SECONDS,
  MCP_REFRESH_TOKEN_TTL_SECONDS,
  requireConfiguration,
} from "./config";
import { defaultHandler } from "./auth/handler";
import { McpApiHandler } from "./mcp/handler";
import { SchwabTokenVault } from "./storage/token-vault";
import type { Env, OAuthEnv } from "./types";

export { SchwabTokenVault };

function createProvider(env: Env): OAuthProvider<OAuthEnv> {
  requireConfiguration(env);
  const scopes = ["mcp:read"];
  if (getTradingMode(env) === "live") scopes.push("mcp:trade");
  const resource = env.MCP_RESOURCE_URL;
  const issuer = new URL(resource).origin;
  return new OAuthProvider<OAuthEnv>({
    apiRoute: "/mcp",
    apiHandler: McpApiHandler,
    defaultHandler,
    authorizeEndpoint: "/authorize",
    tokenEndpoint: "/oauth/token",
    clientIdMetadataDocumentEnabled: true,
    allowPlainPKCE: false,
    accessTokenTTL: MCP_ACCESS_TOKEN_TTL_SECONDS,
    refreshTokenTTL: MCP_REFRESH_TOKEN_TTL_SECONDS,
    scopesSupported: scopes,
    resourceMetadata: {
      resource,
      authorization_servers: [issuer],
      scopes_supported: scopes,
      bearer_methods_supported: ["header"],
      resource_name: "Private Schwab MCP",
    },
  });
}

export default {
  fetch(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
    return createProvider(env).fetch(request, env as OAuthEnv, ctx);
  },
  scheduled(
    _controller: ScheduledController,
    env: Env,
    ctx: ExecutionContext,
  ): void {
    ctx.waitUntil(
      createProvider(env)
        .purgeExpiredData(env as OAuthEnv)
        .then(() => undefined),
    );
  },
} satisfies ExportedHandler<Env>;
