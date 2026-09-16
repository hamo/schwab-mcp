import { describe, expect, it } from "vitest";
import {
  clearCsrfCookie,
  consentPage,
  csrfCookieName,
  schwabReauthorizationPage,
  tradeApprovalPage,
} from "../src/auth/pages";

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

  it("requires a CSRF-protected POST before starting Schwab reauthorization", async () => {
    const response = schwabReauthorizationPage({
      state: "signed-state",
      csrf: "csrf-token",
    });
    const html = await response.text();

    expect(html).toContain('method="post"');
    expect(html).toContain('action="/schwab/reauthorize"');
    expect(html).toContain('name="state" value="signed-state"');
    expect(response.headers.get("set-cookie")).toContain("csrf-token");
    expect(response.headers.get("cache-control")).toBe("no-store");
    expect(response.headers.get("referrer-policy")).toBe("no-referrer");
  });

  it("isolates CSRF cookies for concurrent browser flows", () => {
    const consent = consentPage({
      clientName: "client",
      clientId: "https://client.example/metadata",
      redirectUri: "https://client.example/callback",
      scopes: ["mcp:read"],
      state: "consent-state",
      csrf: "consent-csrf",
      tradingEnabled: false,
      accessOrigin: "https://owner.cloudflareaccess.com",
    });
    const trade = tradeApprovalPage({
      summary: "order",
      digest: "digest",
      state: "trade-state",
      csrf: "trade-csrf",
      expiresAt: Date.now() + 60_000,
    });
    const reauthorization = schwabReauthorizationPage({
      state: "reauthorization-state",
      csrf: "reauthorization-csrf",
    });

    expect(consent.headers.get("set-cookie")).toContain(
      `${csrfCookieName("consent")}=consent-csrf`,
    );
    expect(trade.headers.get("set-cookie")).toContain(
      `${csrfCookieName("trade")}=trade-csrf`,
    );
    expect(reauthorization.headers.get("set-cookie")).toContain(
      `${csrfCookieName("schwab-reauthorization")}=reauthorization-csrf`,
    );
    expect(
      new Set([
        csrfCookieName("consent"),
        csrfCookieName("trade"),
        csrfCookieName("schwab-reauthorization"),
      ]),
    ).toHaveLength(3);
    expect(clearCsrfCookie("trade")).toContain(`${csrfCookieName("trade")}=;`);
  });
});
