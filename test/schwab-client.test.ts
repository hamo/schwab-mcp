import { describe, expect, it, vi } from "vitest";
import { schwabRequest } from "../src/schwab/client";

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
});
