import { schwabBaseUrl } from "../config";
import { sha256 } from "../security/crypto";
import type { Env } from "../types";
import type { SchwabTokenResponse } from "./types";

const TOKEN_PATH = "/v1/oauth/token";
const AUTH_PATH = "/v1/oauth/authorize";
const MAX_ERROR_BODY = 2_000;

export interface SchwabRequestOptions {
  method?: "GET" | "POST" | "PUT" | "DELETE";
  query?: Record<string, string | number | boolean | undefined>;
  body?: unknown;
  fetcher?: typeof fetch;
}

export function buildSchwabAuthorizationUrl(
  request: Request,
  env: Env,
  state: string,
): string {
  const url = new URL(AUTH_PATH, schwabBaseUrl(env));
  url.searchParams.set("client_id", env.SCHWAB_CLIENT_ID);
  url.searchParams.set(
    "redirect_uri",
    new URL("/schwab/callback", request.url).href,
  );
  url.searchParams.set("response_type", "code");
  url.searchParams.set("state", state);
  return url.href;
}

export async function exchangeSchwabCode(
  request: Request,
  env: Env,
): Promise<SchwabTokenResponse> {
  const code = new URL(request.url).searchParams.get("code");
  if (!code) throw new Error("Schwab did not return an authorization code");
  return requestToken(
    env,
    new URLSearchParams({
      grant_type: "authorization_code",
      code,
      redirect_uri: new URL("/schwab/callback", request.url).href,
    }),
  );
}

export async function refreshSchwabToken(
  env: Env,
  refreshToken: string,
): Promise<SchwabTokenResponse> {
  const refreshed = await requestToken(
    env,
    new URLSearchParams({
      grant_type: "refresh_token",
      refresh_token: refreshToken,
      client_id: env.SCHWAB_CLIENT_ID,
    }),
    refreshToken,
  );
  return refreshed;
}

async function requestToken(
  env: Env,
  body: URLSearchParams,
  existingRefreshToken?: string,
): Promise<SchwabTokenResponse> {
  const credentials = btoa(
    `${env.SCHWAB_CLIENT_ID}:${env.SCHWAB_CLIENT_SECRET}`,
  );
  const response = await fetch(new URL(TOKEN_PATH, schwabBaseUrl(env)), {
    method: "POST",
    headers: {
      authorization: `Basic ${credentials}`,
      "content-type": "application/x-www-form-urlencoded",
      accept: "application/json",
    },
    body,
  });
  const raw = await readJson(response);
  if (!response.ok)
    throw new SchwabApiError(response.status, "Schwab token request failed");
  if (
    !isRecord(raw) ||
    typeof raw.access_token !== "string" ||
    (typeof raw.refresh_token !== "string" && !existingRefreshToken) ||
    typeof raw.token_type !== "string" ||
    typeof raw.expires_in !== "number"
  ) {
    throw new Error("Schwab returned an invalid token response");
  }
  const issuedAt = Date.now();
  return {
    accessToken: raw.access_token,
    refreshToken:
      typeof raw.refresh_token === "string"
        ? raw.refresh_token
        : existingRefreshToken!,
    tokenType: raw.token_type,
    ...(typeof raw.scope === "string" ? { scope: raw.scope } : {}),
    accessExpiresAt: issuedAt + raw.expires_in * 1_000,
    issuedAt,
  };
}

export async function schwabRequest<T>(
  env: Pick<Env, "SCHWAB_ENVIRONMENT">,
  accessToken: string,
  path: string,
  options: SchwabRequestOptions = {},
): Promise<T> {
  if (!path.startsWith("/marketdata/v1/") && !path.startsWith("/trader/v1/")) {
    throw new Error(
      "Refusing a Schwab API path outside the allowlisted API prefixes",
    );
  }
  const url = new URL(path, schwabBaseUrl(env));
  for (const [key, value] of Object.entries(options.query ?? {})) {
    if (value !== undefined) url.searchParams.set(key, String(value));
  }
  const headers = new Headers({
    authorization: `Bearer ${accessToken}`,
    accept: "application/json",
  });
  if (options.body !== undefined)
    headers.set("content-type", "application/json");
  const response = await (options.fetcher ?? fetch)(url, {
    method: options.method ?? "GET",
    headers,
    ...(options.body !== undefined
      ? { body: JSON.stringify(options.body) }
      : {}),
  });
  if (!response.ok) {
    const detail = (await response.text()).slice(0, MAX_ERROR_BODY);
    throw new SchwabApiError(response.status, safeErrorDetail(detail));
  }
  if (
    response.status === 204 ||
    response.headers.get("content-length") === "0"
  ) {
    return { ok: true, status: response.status } as T;
  }
  const contentType = response.headers.get("content-type") ?? "";
  if (contentType.includes("application/json"))
    return (await readJson(response)) as T;
  return {
    ok: true,
    status: response.status,
    location: response.headers.get("location"),
  } as T;
}

export async function selectAllowedAccountHashes(
  env: Env,
  accessToken: string,
): Promise<string[]> {
  const accounts = await schwabRequest<unknown>(
    env,
    accessToken,
    "/trader/v1/accounts/accountNumbers",
  );
  if (!Array.isArray(accounts))
    throw new Error("Schwab returned invalid account metadata");
  const hashes = accounts
    .map((account: unknown) =>
      account &&
      typeof account === "object" &&
      "hashValue" in account &&
      typeof account.hashValue === "string"
        ? account.hashValue
        : null,
    )
    .filter((value): value is string => value !== null);
  if (hashes.length === 0)
    throw new Error("No Schwab accounts were returned for this login");

  return filterAllowedAccountHashes(env, hashes);
}

export async function filterAllowedAccountHashes(
  env: Pick<Env, "OWNER_ACCOUNT_FINGERPRINTS">,
  hashes: string[],
): Promise<string[]> {
  const configured = (env.OWNER_ACCOUNT_FINGERPRINTS ?? "")
    .split(",")
    .map((value) => value.trim())
    .filter(Boolean);
  if (configured.length === 0) return hashes;

  const selected: string[] = [];
  for (const hash of hashes) {
    if (configured.includes(await sha256(hash))) selected.push(hash);
  }
  if (selected.length === 0) {
    throw new Error("No Schwab account matched OWNER_ACCOUNT_FINGERPRINTS");
  }
  return selected;
}

export class SchwabApiError extends Error {
  constructor(
    readonly status: number,
    message: string,
  ) {
    super(message);
    this.name = "SchwabApiError";
  }
}

function safeErrorDetail(raw: string): string {
  if (!raw) return "Schwab API request failed";
  try {
    const parsed = JSON.parse(raw) as Record<string, unknown>;
    const message = parsed.message ?? parsed.error_description ?? parsed.error;
    return typeof message === "string"
      ? message.slice(0, 500)
      : "Schwab API request failed";
  } catch {
    return "Schwab API request failed";
  }
}

async function readJson(response: Response): Promise<unknown> {
  return JSON.parse(await response.text()) as unknown;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}
