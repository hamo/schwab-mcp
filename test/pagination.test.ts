import { describe, expect, it } from "vitest";
import {
  formatAccountPositionsPage,
  formatAllowedOrdersPage,
  formatArrayPage,
  formatPriceHistoryPage,
  formatRecordPage,
} from "../src/mcp/pagination";

const page = {
  outputMode: "paged" as const,
  outputOffset: 1,
  outputLimit: 1,
};

describe("bounded MCP output pages", () => {
  it("pages arrays and records without dropping the full response", () => {
    expect(formatArrayPage(["a", "b", "c"], "items", page)).toMatchObject({
      page: { returned: 1, totalItems: 3, nextOffset: 2 },
      items: ["b"],
    });
    expect(
      formatRecordPage({ MSFT: { bid: 2 }, AAPL: { bid: 1 } }, "quotes", page),
    ).toMatchObject({
      page: { returned: 1, totalItems: 2, nextOffset: null },
      quotes: [{ key: "MSFT", item: { bid: 2 } }],
    });
  });

  it("reduces a requested page when serialized items approach the MCP limit", () => {
    const large = "x".repeat(50_000);
    expect(
      formatArrayPage([large, large, "tail"], "items", {
        outputMode: "paged",
        outputOffset: 0,
        outputLimit: 3,
      }),
    ).toMatchObject({
      page: { returned: 1, totalItems: 3, nextOffset: 1 },
      items: [large],
    });
  });

  it("pages candles while retaining price-history metadata", () => {
    expect(
      formatPriceHistoryPage(
        { symbol: "AAPL", previousClose: 100, candles: [{ n: 1 }, { n: 2 }] },
        page,
      ),
    ).toMatchObject({
      source: "schwab",
      metadata: { symbol: "AAPL", previousClose: 100 },
      page: { returned: 1, totalItems: 2 },
      candles: [{ n: 2 }],
    });
  });

  it("flattens account orders into a bounded page", () => {
    expect(
      formatAllowedOrdersPage(
        [
          { accountHash: "one", orders: [{ orderId: 1 }] },
          { accountHash: "two", orders: [{ orderId: 2 }] },
        ],
        page,
      ),
    ).toMatchObject({
      page: { returned: 1, totalItems: 2 },
      orders: [{ accountHash: "two", order: { orderId: 2 } }],
    });
  });

  it("pages positions without repeating them in account metadata", () => {
    expect(
      formatAccountPositionsPage(
        {
          securitiesAccount: {
            accountNumber: "••••1234",
            positions: [{ symbol: "AAPL" }, { symbol: "MSFT" }],
          },
        },
        page,
      ),
    ).toMatchObject({
      metadata: { securitiesAccount: { accountNumber: "••••1234" } },
      page: { returned: 1, totalItems: 2 },
      positions: [{ symbol: "MSFT" }],
    });
  });
});
