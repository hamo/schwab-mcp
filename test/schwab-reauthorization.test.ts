import { afterEach, describe, expect, it, vi } from "vitest";

vi.mock("cloudflare:workers", () => ({
  DurableObject: class {},
  WorkerEntrypoint: class {},
}));
vi.mock("@cloudflare/workers-oauth-provider", () => ({
  AuthorizationError: class AuthorizationError extends Error {},
}));

import { defaultHandler } from "../src/auth/handler";
import { createState } from "../src/auth/state";
import { accessOidcIssuer } from "../src/config";
import { toBase64Url, utf8 } from "../src/security/encoding";
import { VaultClient } from "../src/storage/vault-client";
import type { OAuthEnv } from "../src/types";

interface StoredFlow {
  value: Record<string, unknown>;
  expiresAt: number;
}

class FakeVaultStub {
  readonly flows = new Map<string, StoredFlow>();
  session: Record<string, unknown> | null = null;

  fetch(input: RequestInfo | URL, init?: RequestInit): Promise<Response> {
    const request = new Request(input, init);
    const url = new URL(request.url);
    if (request.method === "POST" && url.pathname === "/flows") {
      return request.json().then((raw: unknown) => {
        const input = raw as {
          id: string;
          value: Record<string, unknown>;
          expiresAt: number;
        };
        this.flows.set(input.id, {
          value: input.value,
          expiresAt: input.expiresAt,
        });
        return Response.json({ stored: true });
      });
    }
    const consume = /^\/flows\/([0-9a-f-]{36})\/consume$/u.exec(url.pathname);
    if (request.method === "POST" && consume?.[1]) {
      return request.json().then((raw: unknown) => {
        const expectedKinds = (raw as { expectedKinds?: unknown })
          .expectedKinds;
        const stored = this.flows.get(consume[1]!);
        if (!stored || stored.expiresAt <= Date.now()) {
          this.flows.delete(consume[1]!);
          return Response.json(null);
        }
        if (
          !Array.isArray(expectedKinds) ||
          !expectedKinds.includes(stored.value.kind)
        ) {
          return Response.json(
            { error: "flow_purpose_mismatch" },
            { status: 409 },
          );
        }
        this.flows.delete(consume[1]!);
        return Response.json(stored.value);
      });
    }
    if (request.method === "PUT" && url.pathname === "/session") {
      return request.json().then((raw: unknown) => {
        this.session = raw as Record<string, unknown>;
        return Response.json({ connected: true, accountCount: 1 });
      });
    }
    return Promise.resolve(
      Response.json({ error: "not_found" }, { status: 404 }),
    );
  }
}

describe("Schwab browser reauthorization", () => {
  afterEach(() => {
    vi.restoreAllMocks();
    vi.unstubAllGlobals();
  });

  it("does not consume a prefetched GET and replaces the session only after owner login", async () => {
    const vault = new FakeVaultStub();
    const env = createEnv(vault);
    const startState = await createState(
      new VaultClient(env),
      { kind: "schwab-reauthorize-start" },
      env.STATE_SIGNING_KEY,
    );
    const startId = stateId(startState);

    const page = await handle(
      new Request(
        `https://worker.example/schwab/reauthorize?state=${encodeURIComponent(startState)}`,
      ),
      env,
    );
    expect(page.status).toBe(200);
    expect(vault.flows.has(startId)).toBe(true);
    const html = await page.text();
    const csrf = hiddenValue(html, "csrf");
    const cookie = page.headers.get("set-cookie")?.split(";", 1)[0];
    expect(cookie).toBeTruthy();

    const invalidPost = await handle(
      reauthorizationPost(startState, csrf, "wrong-cookie"),
      env,
    );
    expect(invalidPost.status).toBe(400);
    expect(vault.flows.has(startId)).toBe(true);

    const accessRedirect = await handle(
      reauthorizationPost(startState, csrf, cookie!),
      env,
    );
    expect(accessRedirect.status).toBe(302);
    expect(vault.flows.has(startId)).toBe(false);
    expect(accessRedirect.headers.get("cache-control")).toBe("no-store");
    expect(accessRedirect.headers.get("referrer-policy")).toBe("no-referrer");
    const accessUrl = new URL(accessRedirect.headers.get("location")!);
    const accessState = requiredParam(accessUrl, "state");
    const accessFlow = vault.flows.get(stateId(accessState));
    expect(accessFlow?.value.kind).toBe("access-schwab-reauthorize");

    const reused = await handle(
      reauthorizationPost(startState, csrf, cookie!),
      env,
    );
    expect(reused.status).toBe(400);

    const nonce = String(accessFlow?.value.nonce);
    const signing = await createAccessSigningMaterial(env, nonce);
    vi.stubGlobal("fetch", schwabAndAccessFetch(env, signing));

    const accessCallback = await handle(
      new Request(
        `https://worker.example/callback?code=access-code&state=${encodeURIComponent(accessState)}`,
      ),
      env,
    );
    expect(accessCallback.status).toBe(302);
    expect(vault.session).toBeNull();
    const schwabUrl = new URL(accessCallback.headers.get("location")!);
    expect(schwabUrl.hostname).toBe("api.schwabapi.com");
    const schwabState = requiredParam(schwabUrl, "state");

    const schwabCallback = await handle(
      new Request(
        `https://worker.example/schwab/callback?code=schwab-code&state=${encodeURIComponent(schwabState)}`,
      ),
      env,
    );
    expect(schwabCallback.status).toBe(200);
    expect(await schwabCallback.text()).toContain("Schwab reconnected");
    expect(vault.session).toMatchObject({
      accessToken: "new-access-token",
      refreshToken: "new-refresh-token",
      accountHashes: ["allowed_hash"],
    });
  });

  it("logs only safe token-exchange diagnostics", async () => {
    const vault = new FakeVaultStub();
    const env = createEnv(vault);
    const state = await createSchwabCallbackState(vault, env);
    vi.stubGlobal(
      "fetch",
      vi.fn(() =>
        Promise.resolve(
          Response.json(
            {
              error: "invalid_grant",
              error_description: "sensitive upstream detail",
            },
            { status: 400 },
          ),
        ),
      ),
    );
    const log = vi.spyOn(console, "error").mockImplementation(() => undefined);

    const response = await handle(
      new Request(
        `https://worker.example/schwab/callback?code=sensitive-authorization-code&state=${encodeURIComponent(state)}`,
      ),
      env,
    );

    expect(response.status).toBe(500);
    expect(log.mock.calls[0]?.[0]).toEqual({
      event: "schwab_authorization_failure",
      stage: "token_exchange",
      errorType: "schwab_api_error",
      status: 400,
      code: "invalid_grant",
    });
    const output = JSON.stringify(log.mock.calls);
    expect(output).not.toContain("sensitive-authorization-code");
    expect(output).not.toContain("sensitive upstream detail");
    expect(output).not.toContain(state);
  });

  it("does not log an unknown token-shaped upstream error value", async () => {
    const vault = new FakeVaultStub();
    const env = createEnv(vault);
    const state = await createSchwabCallbackState(vault, env);
    vi.stubGlobal(
      "fetch",
      vi.fn(() =>
        Promise.resolve(
          Response.json(
            { error: "sensitiveauthorizationcode" },
            { status: 400 },
          ),
        ),
      ),
    );
    const log = vi.spyOn(console, "error").mockImplementation(() => undefined);

    const response = await handle(
      new Request(
        `https://worker.example/schwab/callback?code=another-sensitive-code&state=${encodeURIComponent(state)}`,
      ),
      env,
    );

    expect(response.status).toBe(500);
    expect(log.mock.calls[0]?.[0]).toEqual({
      event: "schwab_authorization_failure",
      stage: "token_exchange",
      errorType: "schwab_api_error",
      status: 400,
    });
    const output = JSON.stringify(log.mock.calls);
    expect(output).not.toContain("sensitiveauthorizationcode");
    expect(output).not.toContain("another-sensitive-code");
    expect(output).not.toContain(state);
  });

  it("identifies account discovery without logging Schwab response details", async () => {
    const vault = new FakeVaultStub();
    const env = createEnv(vault);
    const state = await createSchwabCallbackState(vault, env);
    vi.stubGlobal(
      "fetch",
      vi.fn((input: RequestInfo | URL) => {
        const url = new URL(input instanceof Request ? input.url : input);
        if (url.pathname === "/v1/oauth/token") {
          return Promise.resolve(
            Response.json({
              access_token: "sensitive-access-token",
              refresh_token: "sensitive-refresh-token",
              token_type: "Bearer",
              expires_in: 1_800,
            }),
          );
        }
        if (url.pathname === "/trader/v1/accounts/accountNumbers") {
          return Promise.resolve(
            Response.json(
              {
                error: "server_error",
                message: "sensitive account detail",
              },
              { status: 503 },
            ),
          );
        }
        throw new Error(`Unexpected fetch: ${url.origin}${url.pathname}`);
      }),
    );
    const log = vi.spyOn(console, "error").mockImplementation(() => undefined);

    const response = await handle(
      new Request(
        `https://worker.example/schwab/callback?code=sensitive-authorization-code&state=${encodeURIComponent(state)}`,
      ),
      env,
    );

    expect(response.status).toBe(500);
    expect(log.mock.calls[0]?.[0]).toEqual({
      event: "schwab_authorization_failure",
      stage: "account_discovery",
      errorType: "schwab_api_error",
      status: 503,
      code: "server_error",
    });
    const output = JSON.stringify(log.mock.calls);
    expect(output).not.toContain("sensitive-authorization-code");
    expect(output).not.toContain("sensitive-access-token");
    expect(output).not.toContain("sensitive-refresh-token");
    expect(output).not.toContain("sensitive account detail");
    expect(output).not.toContain(state);
  });
});

function createSchwabCallbackState(
  vault: FakeVaultStub,
  env: OAuthEnv,
): Promise<string> {
  return createState(
    new VaultClient(env),
    {
      kind: "schwab-reauthorize",
      identity: { email: env.OWNER_EMAIL, subject: "owner-subject" },
    },
    env.STATE_SIGNING_KEY,
  );
}

function createEnv(vault: FakeVaultStub): OAuthEnv {
  const namespace = {
    idFromName: () => ({}) as DurableObjectId,
    get: () => vault,
  } as unknown as DurableObjectNamespace;
  return {
    TOKEN_VAULT: namespace,
    STATE_SIGNING_KEY: "state-signing-key",
    OWNER_EMAIL: "owner@example.com",
    ACCESS_TEAM_DOMAIN: "team.cloudflareaccess.com",
    ACCESS_CLIENT_ID: "access-client",
    ACCESS_CLIENT_SECRET: "access-secret",
    SCHWAB_CLIENT_ID: "schwab-client",
    SCHWAB_CLIENT_SECRET: "schwab-secret",
    SCHWAB_ENVIRONMENT: "production",
  } as OAuthEnv;
}

function handle(request: Request, env: OAuthEnv): Promise<Response> {
  const fetch = defaultHandler.fetch as unknown as (
    request: Request,
    env: OAuthEnv,
    ctx: ExecutionContext,
  ) => Response | Promise<Response>;
  if (!fetch) throw new Error("Missing default handler");
  return Promise.resolve(fetch(request, env, {} as ExecutionContext));
}

function reauthorizationPost(
  state: string,
  csrf: string,
  cookie: string,
): Request {
  return new Request("https://worker.example/schwab/reauthorize", {
    method: "POST",
    headers: {
      "content-type": "application/x-www-form-urlencoded",
      cookie,
    },
    body: new URLSearchParams({ state, csrf }),
  });
}

function hiddenValue(html: string, name: string): string {
  const match = new RegExp(`name="${name}" value="([^"]+)"`, "u").exec(html);
  if (!match?.[1]) throw new Error(`Missing ${name}`);
  return match[1];
}

function stateId(state: string): string {
  return state.slice(0, state.indexOf("."));
}

function requiredParam(url: URL, name: string): string {
  const value = url.searchParams.get(name);
  if (!value) throw new Error(`Missing ${name}`);
  return value;
}

async function createAccessSigningMaterial(env: OAuthEnv, nonce: string) {
  const pair = await crypto.subtle.generateKey(
    {
      name: "RSASSA-PKCS1-v1_5",
      modulusLength: 2_048,
      publicExponent: new Uint8Array([1, 0, 1]),
      hash: "SHA-256",
    },
    true,
    ["sign", "verify"],
  );
  const publicJwk = await crypto.subtle.exportKey("jwk", pair.publicKey);
  const now = Math.floor(Date.now() / 1_000);
  const header = jwtPart({ alg: "RS256", kid: "test-key", typ: "JWT" });
  const payload = jwtPart({
    iss: accessOidcIssuer(env),
    sub: "owner-subject",
    aud: env.ACCESS_CLIENT_ID,
    exp: now + 300,
    iat: now,
    nonce,
    email: env.OWNER_EMAIL,
  });
  const signature = toBase64Url(
    await crypto.subtle.sign(
      "RSASSA-PKCS1-v1_5",
      pair.privateKey,
      utf8(`${header}.${payload}`),
    ),
  );
  return {
    idToken: `${header}.${payload}.${signature}`,
    publicJwk: { ...publicJwk, kid: "test-key", use: "sig" },
  };
}

function schwabAndAccessFetch(
  env: OAuthEnv,
  signing: Awaited<ReturnType<typeof createAccessSigningMaterial>>,
) {
  return vi.fn((input: RequestInfo | URL) => {
    const url = new URL(input instanceof Request ? input.url : input);
    if (url.href === `${accessOidcIssuer(env)}/token`) {
      return Promise.resolve(
        Response.json({
          access_token: "access-token",
          id_token: signing.idToken,
        }),
      );
    }
    if (url.href === `${accessOidcIssuer(env)}/jwks`) {
      return Promise.resolve(Response.json({ keys: [signing.publicJwk] }));
    }
    if (url.pathname === "/v1/oauth/token") {
      return Promise.resolve(
        Response.json({
          access_token: "new-access-token",
          refresh_token: "new-refresh-token",
          token_type: "Bearer",
          expires_in: 1_800,
        }),
      );
    }
    if (url.pathname === "/trader/v1/accounts/accountNumbers") {
      return Promise.resolve(Response.json([{ hashValue: "allowed_hash" }]));
    }
    throw new Error(`Unexpected fetch: ${url.href}`);
  });
}

function jwtPart(value: unknown): string {
  return btoa(JSON.stringify(value))
    .replaceAll("+", "-")
    .replaceAll("/", "_")
    .replace(/=+$/u, "");
}
