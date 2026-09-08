import type { Env, TradingMode } from "./types";

export function getTradingMode(env: Pick<Env, "TRADING_MODE">): TradingMode {
  if (env.TRADING_MODE === "preview" || env.TRADING_MODE === "live") {
    return env.TRADING_MODE;
  }
  return "disabled";
}

export function requireConfiguration(env: Env): void {
  const required: Array<keyof Env> = [
    "MCP_RESOURCE_URL",
    "OWNER_EMAIL",
    "ACCESS_TEAM_DOMAIN",
    "ACCESS_CLIENT_ID",
    "ACCESS_CLIENT_SECRET",
    "SCHWAB_CLIENT_ID",
    "SCHWAB_CLIENT_SECRET",
    "TOKEN_ENCRYPTION_KEY",
    "STATE_SIGNING_KEY",
  ];

  const missing = required.filter((key) => {
    const value = env[key];
    return typeof value !== "string" || value.trim().length === 0;
  });
  if (missing.length > 0) {
    throw new Error(`Missing required configuration: ${missing.join(", ")}`);
  }

  const resource = new URL(env.MCP_RESOURCE_URL);
  if (resource.protocol !== "https:" || resource.pathname !== "/mcp") {
    throw new Error("MCP_RESOURCE_URL must be an HTTPS URL ending in /mcp");
  }

  accessBaseUrl(env);
  getTradingMode(env);
}

export function accessBaseUrl(env: Pick<Env, "ACCESS_TEAM_DOMAIN">): URL {
  const raw = env.ACCESS_TEAM_DOMAIN.trim().toLowerCase();
  const domain = raw.replace(/^https:\/\//, "").replace(/\/$/, "");
  const url = new URL(`https://${domain}`);
  if (
    url.pathname !== "/" ||
    !url.hostname.endsWith(".cloudflareaccess.com") ||
    url.hostname === "cloudflareaccess.com"
  ) {
    throw new Error(
      "ACCESS_TEAM_DOMAIN must be a *.cloudflareaccess.com hostname",
    );
  }
  return url;
}

export function accessOidcIssuer(
  env: Pick<Env, "ACCESS_TEAM_DOMAIN" | "ACCESS_CLIENT_ID">,
): string {
  const base = accessBaseUrl(env);
  return new URL(
    `/cdn-cgi/access/sso/oidc/${encodeURIComponent(env.ACCESS_CLIENT_ID)}`,
    base,
  ).href.replace(/\/$/, "");
}

export function schwabBaseUrl(env: Pick<Env, "SCHWAB_ENVIRONMENT">): string {
  return env.SCHWAB_ENVIRONMENT === "sandbox"
    ? "https://api-sandbox.schwabapi.com"
    : "https://api.schwabapi.com";
}
