import { describe, expect, it } from "vitest";
import { verifyAccessIdentity } from "../src/auth/access";

function part(value: unknown): string {
  return btoa(JSON.stringify(value))
    .replaceAll("+", "-")
    .replaceAll("/", "_")
    .replace(/=+$/u, "");
}

describe("Cloudflare Access claims", () => {
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
});
