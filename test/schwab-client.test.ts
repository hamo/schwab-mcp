import { describe, expect, it, vi } from "vitest";
import {
  getAllowedAccounts,
  getAllowedOrders,
  SchwabApiError,
  schwabRequest,
  shouldForgetSchwabSession,
} from "../src/schwab/client";

describe("Schwab HTTP client", () => {
  it("only calls the Schwab host and attaches the bearer token", async () => {
    const fetcher = vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
      const request = new Request(input, init);
      expect(new URL(request.url).origin).toBe("https://api.schwabapi.com");
      expect(request.headers.get("authorization")).toBe("Bearer access-token");
      return Promise.resolve(Response.json({ ok: true }));
    });
    await expect(
      schwabRequest(
        { SCHWAB_ENVIRONMENT: "production" },
        "access-token",
        "/marketdata/v1/quotes",
        { query: { symbols: "AAPL" }, fetcher },
      ),
    ).resolves.toEqual({ ok: true });
    expect(fetcher).toHaveBeenCalledOnce();
  });

  it("refuses non-allowlisted API paths before fetch", async () => {
    const fetcher = vi.fn();
    await expect(
      schwabRequest(
        { SCHWAB_ENVIRONMENT: "production" },
        "token",
        "https://evil.test/",
        {
          fetcher,
        },
      ),
    ).rejects.toThrow("outside the allowlisted API prefixes");
    expect(fetcher).not.toHaveBeenCalled();
  });

  it("refuses path traversal after URL normalization", async () => {
    const fetcher = vi.fn();
    await expect(
      schwabRequest(
        { SCHWAB_ENVIRONMENT: "production" },
        "token",
        "/marketdata/v1/../../v1/oauth/token",
        { fetcher },
      ),
    ).rejects.toThrow("normalized Schwab API path");
    expect(fetcher).not.toHaveBeenCalled();
  });

  it("bounds endpoint-specific response size overrides", async () => {
    const fetcher = vi.fn();
    await expect(
      schwabRequest(
        { SCHWAB_ENVIRONMENT: "production" },
        "token",
        "/marketdata/v1/chains",
        { maxResponseBytes: 8 * 1_024 * 1_024 + 1, fetcher },
      ),
    ).rejects.toThrow("response size limit");
    expect(fetcher).not.toHaveBeenCalled();
  });

  it("uses only account-scoped endpoints for allowlisted account reads", async () => {
    const urls: string[] = [];
    const fetcher = vi.fn((input: RequestInfo | URL) => {
      const url = input instanceof Request ? input.url : input;
      urls.push(new URL(url).pathname);
      return Promise.resolve(Response.json([]));
    });
    const session = {
      accessToken: "token",
      accountHashes: ["hash_one", "hash_two"],
    };

    await getAllowedAccounts(
      { SCHWAB_ENVIRONMENT: "production" },
      session,
      false,
      fetcher,
    );
    await getAllowedOrders(
      { SCHWAB_ENVIRONMENT: "production" },
      session,
      {
        fromEnteredTime: "2026-01-01T00:00:00Z",
        toEnteredTime: "2026-01-02T00:00:00Z",
      },
      fetcher,
    );

    expect(urls).toEqual([
      "/trader/v1/accounts/hash_one",
      "/trader/v1/accounts/hash_two",
      "/trader/v1/accounts/hash_one/orders",
      "/trader/v1/accounts/hash_two/orders",
    ]);
    expect(urls).not.toContain("/trader/v1/accounts");
    expect(urls).not.toContain("/trader/v1/orders");
  });

  it("forgets a session only when Schwab explicitly rejects its grant", () => {
    expect(
      shouldForgetSchwabSession(
        new SchwabApiError(400, "failed", "invalid_grant"),
      ),
    ).toBe(true);
    expect(
      shouldForgetSchwabSession(
        new SchwabApiError(401, "failed", "invalid_token"),
      ),
    ).toBe(true);
    expect(
      shouldForgetSchwabSession(new SchwabApiError(503, "unavailable")),
    ).toBe(false);
    expect(shouldForgetSchwabSession(new TypeError("network failed"))).toBe(
      false,
    );
  });
});
