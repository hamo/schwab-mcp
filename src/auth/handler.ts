import {
  AuthorizationError,
  type AuthRequest,
  type ClientInfo,
} from "@cloudflare/workers-oauth-provider";
import { getTradingMode } from "../config";
import { sha256 } from "../security/crypto";
import {
  buildSchwabAuthorizationUrl,
  exchangeSchwabCode,
  selectAllowedAccountHashes,
} from "../schwab/client";
import { VaultClient } from "../storage/vault-client";
import type { AccessIdentity, OAuthEnv } from "../types";
import {
  exchangeAccessCode,
  redirectToAccessForMcp,
  redirectToAccessForTrade,
  verifyAccessIdentity,
} from "./access";
import {
  clearCsrfCookie,
  consentPage,
  errorPage,
  readCookie,
  successPage,
  tradeApprovalPage,
} from "./pages";
import { consumeState, createState, FlowError } from "./state";

export const defaultHandler: ExportedHandler<OAuthEnv> = {
  async fetch(request, env): Promise<Response> {
    try {
      const url = new URL(request.url);
      if (request.method === "GET" && url.pathname === "/") {
        return Response.json({ name: "schwab-mcp", endpoint: "/mcp" });
      }
      if (url.pathname === "/authorize") return handleAuthorize(request, env);
      if (request.method === "GET" && url.pathname === "/callback") {
        return handleAccessCallback(request, env);
      }
      if (request.method === "GET" && url.pathname === "/schwab/callback") {
        return handleSchwabCallback(request, env);
      }
      if (url.pathname === "/trade/approve")
        return handleTradeApproval(request, env);
      return new Response("Not found", { status: 404 });
    } catch (error) {
      if (error instanceof FlowError) return errorPage(error.message);
      console.error(
        "Authorization flow failed",
        error instanceof Error ? error.name : "unknown",
      );
      return errorPage(
        "The authorization request could not be completed.",
        500,
      );
    }
  },
};

async function handleAuthorize(
  request: Request,
  env: OAuthEnv,
): Promise<Response> {
  if (request.method === "GET") {
    let oauthRequest: AuthRequest;
    try {
      oauthRequest = await env.OAUTH_PROVIDER.parseAuthRequest(request);
    } catch (error) {
      if (error instanceof AuthorizationError) return authorizationError(error);
      throw error;
    }
    const client = await env.OAUTH_PROVIDER.lookupClient(oauthRequest.clientId);
    if (!client) return errorPage("Unknown OAuth client");
    const csrf = crypto.randomUUID();
    const state = await createState(
      env.OAUTH_KV,
      { kind: "consent", oauthRequest, csrf },
      env.STATE_SIGNING_KEY,
    );
    return consentPage({
      clientName: safeClientName(client),
      state,
      csrf,
      tradingEnabled: getTradingMode(env) === "live",
    });
  }
  if (request.method === "POST") {
    const form = await request.formData();
    const state = await consumeState(
      env.OAUTH_KV,
      stringField(form, "state"),
      "consent",
      env.STATE_SIGNING_KEY,
    );
    const csrf = stringField(form, "csrf");
    if (
      !csrf ||
      csrf !== state.csrf ||
      readCookie(request, "__Host-schwab_mcp_csrf") !== csrf
    ) {
      return errorPage("Invalid or expired consent form");
    }
    const response = await redirectToAccessForMcp(
      request,
      env,
      state.oauthRequest,
    );
    return new Response(null, {
      status: 302,
      headers: {
        location: response.headers.get("location") ?? "/",
        "set-cookie": clearCsrfCookie(),
      },
    });
  }
  return new Response("Method not allowed", {
    status: 405,
    headers: { allow: "GET, POST" },
  });
}

async function handleAccessCallback(
  request: Request,
  env: OAuthEnv,
): Promise<Response> {
  const rawState = new URL(request.url).searchParams.get("state");
  const state = await consumeState(
    env.OAUTH_KV,
    rawState,
    ["access-mcp", "access-trade"] as const,
    env.STATE_SIGNING_KEY,
  );
  const tokens = await exchangeAccessCode(request, env, state.codeVerifier);
  const identity = await verifyAccessIdentity(
    env,
    tokens.id_token,
    state.nonce,
  );

  if (state.kind === "access-trade") {
    const pending = await new VaultClient(env).getPreparation(
      state.preparationId,
    );
    const csrf = crypto.randomUUID();
    const approvalState = await createState(
      env.OAUTH_KV,
      { kind: "trade-approval", preparationId: pending.id, identity, csrf },
      env.STATE_SIGNING_KEY,
    );
    return tradeApprovalPage({
      summary: pending.summary,
      digest: pending.digest,
      state: approvalState,
      csrf,
      expiresAt: pending.expiresAt,
    });
  }

  const vault = new VaultClient(env);
  if ((await vault.status()).connected)
    return completeMcpAuthorization(env, state.oauthRequest, identity);

  const schwabState = await createState(
    env.OAUTH_KV,
    { kind: "schwab", oauthRequest: state.oauthRequest, identity },
    env.STATE_SIGNING_KEY,
  );
  return Response.redirect(
    buildSchwabAuthorizationUrl(request, env, schwabState),
    302,
  );
}

async function handleSchwabCallback(
  request: Request,
  env: OAuthEnv,
): Promise<Response> {
  const state = await consumeState(
    env.OAUTH_KV,
    new URL(request.url).searchParams.get("state"),
    "schwab",
    env.STATE_SIGNING_KEY,
  );
  if (state.identity.email !== env.OWNER_EMAIL.trim().toLowerCase()) {
    return errorPage("Owner identity mismatch", 403);
  }
  const tokens = await exchangeSchwabCode(request, env);
  const accountHashes = await selectAllowedAccountHashes(
    env,
    tokens.accessToken,
  );
  await new VaultClient(env).storeSession({ ...tokens, accountHashes });
  return completeMcpAuthorization(env, state.oauthRequest, state.identity);
}

async function handleTradeApproval(
  request: Request,
  env: OAuthEnv,
): Promise<Response> {
  if (getTradingMode(env) !== "live")
    return errorPage("Live trading is disabled", 404);
  if (request.method === "GET") {
    const preparationId = new URL(request.url).searchParams.get("id");
    if (!preparationId || !/^[0-9a-f-]{36}$/.test(preparationId)) {
      return errorPage("Invalid trade approval link");
    }
    await new VaultClient(env).getPreparation(preparationId);
    return redirectToAccessForTrade(request, env, preparationId);
  }
  if (request.method === "POST") {
    const form = await request.formData();
    const state = await consumeState(
      env.OAUTH_KV,
      stringField(form, "state"),
      "trade-approval",
      env.STATE_SIGNING_KEY,
    );
    if (
      stringField(form, "csrf") !== state.csrf ||
      state.identity.email !== env.OWNER_EMAIL.trim().toLowerCase()
    ) {
      return errorPage("Trade approval was rejected", 403);
    }
    await new VaultClient(env).approvePreparation(state.preparationId);
    return successPage(
      "Trade approved",
      "Return to ChatGPT and continue. The approval is one-time and applies only to the displayed action.",
    );
  }
  return new Response("Method not allowed", {
    status: 405,
    headers: { allow: "GET, POST" },
  });
}

async function completeMcpAuthorization(
  env: OAuthEnv,
  request: AuthRequest,
  identity: AccessIdentity,
): Promise<Response> {
  const allowed = new Set(["mcp:read"]);
  if (getTradingMode(env) === "live") allowed.add("mcp:trade");
  const scope = request.scope.filter((item) => allowed.has(item));
  if (!scope.includes("mcp:read")) scope.push("mcp:read");
  const { redirectTo } = await env.OAUTH_PROVIDER.completeAuthorization({
    request,
    userId: `owner-${await sha256(identity.subject)}`,
    metadata: { owner: true },
    scope,
    props: { email: identity.email, subject: identity.subject },
  });
  return Response.redirect(redirectTo, 302);
}

function authorizationError(error: AuthorizationError): Response {
  if (!error.redirectUri) return errorPage(error.description);
  const redirect = new URL(error.redirectUri);
  redirect.searchParams.set("error", error.code);
  redirect.searchParams.set("error_description", error.description);
  if (error.state) redirect.searchParams.set("state", error.state);
  if (error.issuer) redirect.searchParams.set("iss", error.issuer);
  return Response.redirect(redirect.href, 302);
}

function safeClientName(client: ClientInfo): string {
  const name = client.clientName?.trim();
  return name ? name.slice(0, 200) : "An MCP client";
}

function stringField(form: FormData, key: string): string | null {
  const value = form.get(key);
  return typeof value === "string" ? value : null;
}
