import type { AuthRequest } from "@cloudflare/workers-oauth-provider";
import { accessOidcIssuer } from "../config";
import { fromBase64Url, toBase64Url, utf8 } from "../security/encoding";
import type { AccessIdentity, Env } from "../types";
import {
  createState,
  type AccessMcpState,
  type AccessTradeState,
} from "./state";

interface AccessTokens {
  access_token: string;
  id_token: string;
  token_type?: string;
}

interface JwtHeader {
  alg: string;
  kid: string;
  typ?: string;
}

interface JwtClaims {
  iss: string;
  sub: string;
  aud: string | string[];
  exp: number;
  iat: number;
  nbf?: number;
  nonce?: string;
  email: string;
  name?: string;
}

export async function redirectToAccessForMcp(
  request: Request,
  env: Env,
  oauthRequest: AuthRequest,
): Promise<Response> {
  const pkce = await createPkce();
  const state: AccessMcpState = {
    kind: "access-mcp",
    oauthRequest,
    codeVerifier: pkce.verifier,
    nonce: crypto.randomUUID(),
  };
  return redirectToAccess(
    request,
    env,
    await createState(env.OAUTH_KV, state, env.STATE_SIGNING_KEY),
    state.nonce,
    pkce.challenge,
  );
}

export async function redirectToAccessForTrade(
  request: Request,
  env: Env,
  preparationId: string,
): Promise<Response> {
  const pkce = await createPkce();
  const state: AccessTradeState = {
    kind: "access-trade",
    preparationId,
    codeVerifier: pkce.verifier,
    nonce: crypto.randomUUID(),
  };
  return redirectToAccess(
    request,
    env,
    await createState(env.OAUTH_KV, state, env.STATE_SIGNING_KEY),
    state.nonce,
    pkce.challenge,
  );
}

function redirectToAccess(
  request: Request,
  env: Env,
  state: string,
  nonce: string,
  codeChallenge: string,
): Response {
  const url = new URL(`${accessOidcIssuer(env)}/authorization`);
  url.searchParams.set("client_id", env.ACCESS_CLIENT_ID);
  url.searchParams.set("redirect_uri", new URL("/callback", request.url).href);
  url.searchParams.set("response_type", "code");
  url.searchParams.set("scope", "openid email profile");
  url.searchParams.set("state", state);
  url.searchParams.set("nonce", nonce);
  url.searchParams.set("code_challenge", codeChallenge);
  url.searchParams.set("code_challenge_method", "S256");
  return Response.redirect(url.href, 302);
}

export async function exchangeAccessCode(
  request: Request,
  env: Env,
  codeVerifier: string,
): Promise<AccessTokens> {
  const code = new URL(request.url).searchParams.get("code");
  if (!code)
    throw new Error("Cloudflare Access did not return an authorization code");
  const body = new URLSearchParams({
    grant_type: "authorization_code",
    client_id: env.ACCESS_CLIENT_ID,
    client_secret: env.ACCESS_CLIENT_SECRET,
    code,
    redirect_uri: new URL("/callback", request.url).href,
    code_verifier: codeVerifier,
  });
  const response = await fetch(`${accessOidcIssuer(env)}/token`, {
    method: "POST",
    headers: {
      "content-type": "application/x-www-form-urlencoded",
      accept: "application/json",
    },
    body,
  });
  const result = await readJson(response);
  if (!response.ok || !isAccessTokens(result)) {
    throw new Error(
      `Cloudflare Access token exchange failed (${response.status})`,
    );
  }
  return result;
}

export async function verifyAccessIdentity(
  env: Env,
  idToken: string,
  expectedNonce: string,
): Promise<AccessIdentity> {
  const [encodedHeader, encodedPayload, encodedSignature, ...extra] =
    idToken.split(".");
  if (
    !encodedHeader ||
    !encodedPayload ||
    !encodedSignature ||
    extra.length > 0
  ) {
    throw new Error("Invalid Cloudflare Access ID token");
  }
  const header = parsePart<JwtHeader>(encodedHeader);
  const claims = parsePart<JwtClaims>(encodedPayload);
  if (
    header.alg !== "RS256" ||
    !header.kid ||
    (header.typ && header.typ !== "JWT")
  ) {
    throw new Error("Unsupported Cloudflare Access ID token header");
  }

  const jwksResponse = await fetch(`${accessOidcIssuer(env)}/jwks`, {
    headers: { accept: "application/json" },
  });
  if (!jwksResponse.ok)
    throw new Error("Unable to fetch Cloudflare Access signing keys");
  const jwks = await readJson(jwksResponse);
  if (!isJwks(jwks)) throw new Error("Invalid Cloudflare Access signing keys");
  const jwk = jwks.keys.find((candidate) => candidate.kid === header.kid);
  if (!jwk || jwk.kty !== "RSA")
    throw new Error("Cloudflare Access signing key not found");
  const key = await crypto.subtle.importKey(
    "jwk",
    jwk,
    { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
    false,
    ["verify"],
  );
  const signed = utf8(`${encodedHeader}.${encodedPayload}`);
  const verified = await crypto.subtle.verify(
    "RSASSA-PKCS1-v1_5",
    key,
    fromBase64Url(encodedSignature),
    signed,
  );
  if (!verified)
    throw new Error("Invalid Cloudflare Access ID token signature");

  const now = Math.floor(Date.now() / 1000);
  const audience = Array.isArray(claims.aud) ? claims.aud : [claims.aud];
  if (
    claims.iss !== accessOidcIssuer(env) ||
    !audience.includes(env.ACCESS_CLIENT_ID) ||
    claims.exp <= now - 60 ||
    claims.iat > now + 60 ||
    (claims.nbf !== undefined && claims.nbf > now + 60) ||
    claims.nonce !== expectedNonce ||
    !claims.sub ||
    !claims.email ||
    claims.email.trim().toLowerCase() !== env.OWNER_EMAIL.trim().toLowerCase()
  ) {
    throw new Error(
      "Cloudflare Access identity did not satisfy the owner policy",
    );
  }
  return {
    email: claims.email.trim().toLowerCase(),
    subject: claims.sub,
    ...(claims.name ? { name: claims.name } : {}),
  };
}

async function createPkce(): Promise<{ verifier: string; challenge: string }> {
  const verifier = toBase64Url(crypto.getRandomValues(new Uint8Array(32)));
  const digest = await crypto.subtle.digest("SHA-256", utf8(verifier));
  return { verifier, challenge: toBase64Url(digest) };
}

function parsePart<T>(encoded: string): T {
  try {
    return JSON.parse(new TextDecoder().decode(fromBase64Url(encoded))) as T;
  } catch {
    throw new Error("Invalid Cloudflare Access ID token encoding");
  }
}

async function readJson(response: Response): Promise<unknown> {
  return JSON.parse(await response.text()) as unknown;
}

function isAccessTokens(value: unknown): value is AccessTokens {
  return (
    isRecord(value) &&
    typeof value.access_token === "string" &&
    typeof value.id_token === "string"
  );
}

function isJwks(
  value: unknown,
): value is { keys: Array<JsonWebKey & { kid?: string }> } {
  return (
    isRecord(value) &&
    Array.isArray(value.keys) &&
    value.keys.every((key: unknown) => isRecord(key))
  );
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}
