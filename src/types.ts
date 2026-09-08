import type { OAuthHelpers } from "@cloudflare/workers-oauth-provider";

export type TradingMode = "disabled" | "preview" | "live";

export interface Env {
  OAUTH_KV: KVNamespace;
  TOKEN_VAULT: DurableObjectNamespace;

  MCP_RESOURCE_URL: string;
  TRADING_MODE: string;
  SCHWAB_ENVIRONMENT?: string;
  OWNER_ACCOUNT_FINGERPRINTS?: string;

  OWNER_EMAIL: string;
  ACCESS_TEAM_DOMAIN: string;
  ACCESS_CLIENT_ID: string;
  ACCESS_CLIENT_SECRET: string;
  SCHWAB_CLIENT_ID: string;
  SCHWAB_CLIENT_SECRET: string;
  TOKEN_ENCRYPTION_KEY: string;
  STATE_SIGNING_KEY: string;
}

export type OAuthEnv = Env & { OAUTH_PROVIDER: OAuthHelpers };

export interface AuthProps extends Record<string, unknown> {
  email: string;
  subject: string;
  scopes: string[];
}

export interface AccessIdentity {
  email: string;
  subject: string;
  name?: string;
}
