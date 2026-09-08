import { afterEach, describe, expect, it, vi } from "vitest";
import { verifyAccessIdentity } from "../src/auth/access";
import { toBase64Url, utf8 } from "../src/security/encoding";

function part(value: unknown): string {
  return btoa(JSON.stringify(value))
    .replaceAll("+", "-")
    .replaceAll("/", "_")
    .replace(/=+$/u, "");
}

describe("Cloudflare Access claims", () => {
  afterEach(() => vi.unstubAllGlobals());

  it("rejects invalid claim types before fetching signing keys", async () => {
    const token = `${part({ alg: "RS256", kid: "key" })}.${part({
      iss: "https://team.cloudflareaccess.com",
      sub: "owner",
      aud: "client",
      exp: "not-a-number",
      iat: 1,
      email: "owner@example.com",
    })}.signature`;
    await expect(
      verifyAccessIdentity(
        {
          ACCESS_TEAM_DOMAIN: "team.cloudflareaccess.com",
          ACCESS_CLIENT_ID: "client",
          OWNER_EMAIL: "owner@example.com",
        } as never,
        token,
        "nonce",
      ),
    ).rejects.toThrow("claims");
  });

  it("accepts only a valid signed owner token with the expected nonce", async () => {
    const now = Math.floor(Date.now() / 1_000);
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
    const header = part({ alg: "RS256", kid: "test-key", typ: "JWT" });
    const payload = part({
      iss: "https://team.cloudflareaccess.com/cdn-cgi/access/sso/oidc/client",
      sub: "owner-subject",
      aud: "client",
      exp: now + 300,
      iat: now,
      nonce: "expected-nonce",
      email: "OWNER@example.com",
    });
    const signature = toBase64Url(
      await crypto.subtle.sign(
        "RSASSA-PKCS1-v1_5",
        pair.privateKey,
        utf8(`${header}.${payload}`),
      ),
    );
    const token = `${header}.${payload}.${signature}`;
    vi.stubGlobal(
      "fetch",
      vi.fn(() =>
        Promise.resolve(
          Response.json({
            keys: [{ ...publicJwk, kid: "test-key", use: "sig" }],
          }),
        ),
      ),
    );
    const env = {
      ACCESS_TEAM_DOMAIN: "team.cloudflareaccess.com",
      ACCESS_CLIENT_ID: "client",
      OWNER_EMAIL: "owner@example.com",
    } as never;

    await expect(
      verifyAccessIdentity(env, token, "expected-nonce"),
    ).resolves.toEqual({
      email: "owner@example.com",
      subject: "owner-subject",
    });
    await expect(
      verifyAccessIdentity(env, token, "different-nonce"),
    ).rejects.toThrow("owner policy");
  });
});
