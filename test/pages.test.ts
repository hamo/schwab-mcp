import { describe, expect, it } from "vitest";
import { consentPage, tradeApprovalPage } from "../src/auth/pages";

describe("authorization pages", () => {
  it("makes invisible client metadata visible and sets browser defenses", async () => {
    const response = consentPage({
      clientName: "trusted\u202eclient",
      clientId: "https://client.example/metadata",
      redirectUri: "https://client.example/callback",
      scopes: ["mcp:read"],
      state: "state",
      csrf: "csrf",
      tradingEnabled: false,
      accessOrigin: "https://owner.cloudflareaccess.com",
    });
    const html = await response.text();

    expect(html).toContain("trusted\\u202eclient");
    expect(html).not.toContain("\u202e");
    expect(response.headers.get("content-security-policy")).toContain(
      "frame-ancestors 'none'",
    );
    expect(response.headers.get("content-security-policy")).toContain(
      "form-action 'self' https://owner.cloudflareaccess.com",
    );
    expect(response.headers.get("cache-control")).toBe("no-store");
  });

  it("escapes approval HTML and neutralizes formatting controls", async () => {
    const response = tradeApprovalPage({
      summary: "</pre><script>alert(1)</script>\u2066",
      digest: "digest",
      state: "state",
      csrf: "csrf",
      expiresAt: Date.now() + 60_000,
    });
    const html = await response.text();

    expect(html).toContain(
      "&lt;/pre&gt;&lt;script&gt;alert(1)&lt;/script&gt;\\u2066",
    );
    expect(html).not.toContain("<script>");
    expect(html).not.toContain("\u2066");
  });
});
