import { schwabBaseUrl } from "../config";
import { sha256 } from "../security/crypto";
import {
  fetchWithTimeout,
  readJsonWithLimit,
  readTextWithLimit,
} from "../security/http";
import type { Env } from "../types";
import type { SchwabTokenResponse } from "./types";

const TOKEN_PATH = "/v1/oauth/token";
const AUTH_PATH = "/v1/oauth/authorize";
const MAX_ERROR_BODY = 2_000;
const MAX_TOKEN_BODY = 64 * 1_024;
const MAX_API_BODY = 2 * 1_024 * 1_024;
const MAX_EXTENDED_API_BODY = 8 * 1_024 * 1_024;

export interface SchwabRequestOptions {
  method?: "GET" | "POST" | "PUT" | "DELETE";
  query?: Record<string, string | number | boolean | undefined>;
  body?: unknown;
  maxResponseBytes?: number;
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
  const response = await fetchWithTimeout(
    new URL(TOKEN_PATH, schwabBaseUrl(env)),
    {
      method: "POST",
      headers: {
        authorization: `Basic ${credentials}`,
        "content-type": "application/x-www-form-urlencoded",
        accept: "application/json",
      },
      body,
    },
  );
  let rawText: string;
  try {
    rawText = await readTextWithLimit(response, MAX_TOKEN_BODY);
  } catch (error) {
    if (!response.ok) {
      throw new SchwabApiError(response.status, "Schwab token request failed");
    }
    throw error;
  }
  let raw: unknown;
  try {
    raw = JSON.parse(rawText) as unknown;
  } catch {
    raw = undefined;
  }
  if (!response.ok) {
    const rawCode =
      isRecord(raw) && typeof raw.error === "string" ? raw.error : undefined;
    const code =
      rawCode && /^[A-Za-z0-9_.-]{1,64}$/u.test(rawCode) ? rawCode : undefined;
    throw new SchwabApiError(
      response.status,
      "Schwab token request failed",
      code,
    );
  }
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
  const maxResponseBytes = options.maxResponseBytes ?? MAX_API_BODY;
  if (
    !Number.isSafeInteger(maxResponseBytes) ||
    maxResponseBytes < 1 ||
    maxResponseBytes > MAX_EXTENDED_API_BODY
  ) {
    throw new Error("Invalid Schwab API response size limit");
  }
  if (!path.startsWith("/marketdata/v1/") && !path.startsWith("/trader/v1/")) {
    throw new Error(
      "Refusing a Schwab API path outside the allowlisted API prefixes",
    );
  }
  const url = new URL(path, schwabBaseUrl(env));
  if (
    !url.pathname.startsWith("/marketdata/v1/") &&
    !url.pathname.startsWith("/trader/v1/")
  ) {
    throw new Error(
      "Refusing a normalized Schwab API path outside the allowlist",
    );
  }
  for (const [key, value] of Object.entries(options.query ?? {})) {
    if (value !== undefined) url.searchParams.set(key, String(value));
  }
  const headers = new Headers({
    authorization: `Bearer ${accessToken}`,
    accept: "application/json",
  });
  if (options.body !== undefined)
    headers.set("content-type", "application/json");
  const response = await fetchWithTimeout(
    url,
    {
      method: options.method ?? "GET",
      headers,
      ...(options.body !== undefined
        ? { body: JSON.stringify(options.body) }
        : {}),
    },
    options.fetcher ?? fetch,
  );
  if (!response.ok) {
    const detail = await readTextWithLimit(response, MAX_ERROR_BODY);
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
    return (await readJsonWithLimit(response, maxResponseBytes)) as T;
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

export interface AllowedAccountSession {
  accessToken: string;
  accountHashes: string[];
}

export async function getAllowedAccounts(
  env: Pick<Env, "SCHWAB_ENVIRONMENT">,
  session: AllowedAccountSession,
  includePositions: boolean,
  fetcher?: typeof fetch,
): Promise<Array<{ accountHash: string; account: unknown }>> {
  return Promise.all(
    session.accountHashes.map(async (accountHash) => ({
      accountHash,
      account: await schwabRequest<unknown>(
        env,
        session.accessToken,
        `/trader/v1/accounts/${encodeURIComponent(accountHash)}`,
        {
          query: { fields: includePositions ? "positions" : undefined },
          ...(fetcher ? { fetcher } : {}),
        },
      ),
    })),
  );
}

export async function getAllowedOrders(
  env: Pick<Env, "SCHWAB_ENVIRONMENT">,
  session: AllowedAccountSession,
  query: Record<string, string | number | boolean | undefined>,
  fetcher?: typeof fetch,
): Promise<Array<{ accountHash: string; orders: unknown }>> {
  return Promise.all(
    session.accountHashes.map(async (accountHash) => ({
      accountHash,
      orders: await schwabRequest<unknown>(
        env,
        session.accessToken,
        `/trader/v1/accounts/${encodeURIComponent(accountHash)}/orders`,
        { query, ...(fetcher ? { fetcher } : {}) },
      ),
    })),
  );
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
    readonly code?: string,
  ) {
    super(message);
    this.name = "SchwabApiError";
  }
}

export function shouldRequireSchwabReauthorization(error: unknown): boolean {
  return (
    error instanceof SchwabApiError &&
    (error.status === 400 || error.status === 401)
  );
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

function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}
