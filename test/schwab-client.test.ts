import { afterEach, describe, expect, it, vi } from "vitest";
import {
  getAllowedAccounts,
  getAllowedOrders,
  refreshSchwabToken,
  safeSchwabErrorCode,
  SchwabApiError,
  schwabRequest,
  shouldRequireSchwabReauthorization,
} from "../src/schwab/client";

describe("Schwab HTTP client", () => {
  afterEach(() => vi.unstubAllGlobals());

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

  it("requires reauthorization for terminal token responses", () => {
    expect(
      shouldRequireSchwabReauthorization(
        new SchwabApiError(400, "failed", "invalid_grant"),
      ),
    ).toBe(true);
    expect(
      shouldRequireSchwabReauthorization(
        new SchwabApiError(401, "failed", "invalid_token"),
      ),
    ).toBe(true);
    expect(
      shouldRequireSchwabReauthorization(
        new SchwabApiError(401, "failed", "invalid_client"),
      ),
    ).toBe(true);
    expect(
      shouldRequireSchwabReauthorization(
        new SchwabApiError(503, "unavailable"),
      ),
    ).toBe(false);
    expect(
      shouldRequireSchwabReauthorization(new TypeError("network failed")),
    ).toBe(false);
  });

  it("only permits explicitly allowlisted error codes in logs", () => {
    expect(safeSchwabErrorCode("invalid_grant")).toBe("invalid_grant");
    expect(safeSchwabErrorCode("server_error")).toBe("server_error");
    expect(safeSchwabErrorCode("sensitiveauthorizationcode")).toBeUndefined();
    expect(safeSchwabErrorCode("12345678901234567890")).toBeUndefined();
  });

  it("classifies a non-JSON 401 token response as requiring reauthorization", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(() =>
        Promise.resolve(
          new Response("Unauthorized", {
            status: 401,
            headers: { "content-type": "text/plain" },
          }),
        ),
      ),
    );

    let thrown: unknown;
    try {
      await refreshSchwabToken(
        {
          SCHWAB_ENVIRONMENT: "production",
          SCHWAB_CLIENT_ID: "client",
          SCHWAB_CLIENT_SECRET: "secret",
        } as never,
        "expired-refresh-token",
      );
    } catch (error) {
      thrown = error;
    }

    expect(thrown).toBeInstanceOf(SchwabApiError);
    expect(shouldRequireSchwabReauthorization(thrown)).toBe(true);
  });

  it("classifies an oversized 400 token error without reading its body", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(() =>
        Promise.resolve(
          new Response("ignored", {
            status: 400,
            headers: { "content-length": String(64 * 1_024 + 1) },
          }),
        ),
      ),
    );

    let thrown: unknown;
    try {
      await refreshSchwabToken(
        {
          SCHWAB_ENVIRONMENT: "production",
          SCHWAB_CLIENT_ID: "client",
          SCHWAB_CLIENT_SECRET: "secret",
        } as never,
        "expired-refresh-token",
      );
    } catch (error) {
      thrown = error;
    }

    expect(thrown).toBeInstanceOf(SchwabApiError);
    expect(shouldRequireSchwabReauthorization(thrown)).toBe(true);
  });
});
