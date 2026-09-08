import { describe, expect, it } from "vitest";
import { formatOptionChainResponse } from "../src/mcp/option-chain";

describe("Schwab option-chain output", () => {
  const response = {
    symbol: "SPY",
    status: "SUCCESS",
    underlyingPrice: 674,
    callExpDateMap: {
      "2025-11-06:1": {
        "674.0": [
          {
            symbol: "SPY   251106C00674000",
            delta: 0.51,
            gamma: 0.03,
            theta: -0.4,
            vega: 0.08,
            rho: 0.01,
            volatility: 18.2,
            theoreticalOptionValue: 2.34,
            quoteTimeInLong: 1_762_400_000_000,
          },
        ],
      },
    },
    putExpDateMap: {
      "2025-11-06:1": {
        "674.0": [
          {
            symbol: "SPY   251106P00674000",
            delta: -0.49,
            theoreticalVolatility: 18.4,
          },
        ],
      },
    },
  };

  it("pages contracts while preserving Schwab analytics", () => {
    expect(
      formatOptionChainResponse(response, {
        outputMode: "paged",
        contractLimit: 1,
        cursorScope: "options-spy",
      }),
    ).toMatchObject({
      source: "schwab",
      metadata: { symbol: "SPY", underlyingPrice: 674 },
      page: { returned: 1, totalContracts: 2 },
      contracts: [
        {
          contractType: "CALL",
          contract: {
            delta: 0.51,
            theoreticalOptionValue: 2.34,
            quoteTimeInLong: 1_762_400_000_000,
          },
        },
      ],
    });
  });

  it("returns the untouched response in raw mode after validation", () => {
    expect(
      formatOptionChainResponse(response, {
        outputMode: "raw",
        contractLimit: 25,
        cursorScope: "options-spy",
      }),
    ).toBe(response);
  });

  it("accepts a valid response without a repeated top-level symbol", () => {
    const withoutSymbol: Record<string, unknown> = { ...response };
    delete withoutSymbol.symbol;
    expect(() =>
      formatOptionChainResponse(withoutSymbol, {
        outputMode: "paged",
        contractLimit: 25,
        cursorScope: "options-spy",
      }),
    ).not.toThrow();
  });

  it("rejects invalid Schwab Greek field types", () => {
    expect(() =>
      formatOptionChainResponse(
        {
          ...response,
          callExpDateMap: {
            "2025-11-06:1": {
              "674.0": [
                { symbol: "SPY   251106C00674000", delta: "not-a-number" },
              ],
            },
          },
        },
        {
          outputMode: "paged",
          contractLimit: 25,
          cursorScope: "options-spy",
        },
      ),
    ).toThrow();
  });

  it("continues with an opaque contract cursor", () => {
    const first = formatOptionChainResponse(response, {
      outputMode: "paged",
      contractLimit: 1,
      cursorScope: "options-spy",
    }) as { page: { nextCursor: string } };
    expect(
      formatOptionChainResponse(response, {
        outputMode: "paged",
        contractCursor: first.page.nextCursor,
        contractLimit: 1,
        cursorScope: "options-spy",
      }),
    ).toMatchObject({
      contracts: [{ contractType: "PUT" }],
      page: { nextCursor: null },
    });
  });

  it("rejects a cursor from another option query", () => {
    const first = formatOptionChainResponse(response, {
      outputMode: "paged",
      contractLimit: 1,
      cursorScope: "options-spy",
    }) as { page: { nextCursor: string } };
    expect(() =>
      formatOptionChainResponse(response, {
        outputMode: "paged",
        contractCursor: first.page.nextCursor,
        contractLimit: 1,
        cursorScope: "options-qqq",
      }),
    ).toThrow("does not match");
  });
});
