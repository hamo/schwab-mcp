import { describe, expect, it } from "vitest";
import {
  formatAccountPositionsPage,
  formatAllowedOrdersPage,
  formatArrayPage,
  formatInstrumentPage,
  formatPriceHistoryPage,
  formatRecordPage,
} from "../src/mcp/pagination";

const firstPage = {
  outputMode: "paged" as const,
  outputLimit: 1,
  cursorScope: "test-scope",
};

describe("bounded MCP output pages", () => {
  it("uses stable cursors for arrays and records", () => {
    const transactions = [
      { activityId: 1, value: "a" },
      { activityId: 2, value: "b" },
      { activityId: 3, value: "c" },
    ];
    const transactionFirst = formatArrayPage(
      transactions,
      "transactions",
      firstPage,
    );
    const transactionSecond = formatArrayPage(transactions, "transactions", {
      ...firstPage,
      outputCursor: nextCursor(transactionFirst),
    });
    expect(transactionSecond).toMatchObject({
      page: { returned: 1, totalItems: 3 },
      transactions: [{ activityId: 2, value: "b" }],
    });

    const quotes = { MSFT: { bid: 2 }, AAPL: { bid: 1 } };
    const quoteFirst = formatRecordPage(quotes, "quotes", firstPage);
    expect(
      formatRecordPage(quotes, "quotes", {
        ...firstPage,
        outputCursor: nextCursor(quoteFirst),
      }),
    ).toMatchObject({
      page: { returned: 1, totalItems: 2, nextCursor: null },
      quotes: [{ key: "MSFT", item: { bid: 2 } }],
    });
  });

  it("does not shift an existing continuation when a later item is inserted", () => {
    const first = formatArrayPage(
      [{ activityId: 1 }, { activityId: 2 }],
      "transactions",
      firstPage,
    );
    expect(
      formatArrayPage(
        [{ activityId: 1 }, { activityId: 2 }, { activityId: 3 }],
        "transactions",
        { ...firstPage, outputCursor: nextCursor(first) },
      ),
    ).toMatchObject({ transactions: [{ activityId: 2 }] });
  });

  it("reduces a requested page when serialized items approach the MCP limit", () => {
    const large = "x".repeat(50_000);
    expect(
      formatArrayPage(
        [
          { activityId: 1, large },
          { activityId: 2, large },
          { activityId: 3, value: "tail" },
        ],
        "transactions",
        { ...firstPage, outputLimit: 3 },
      ),
    ).toMatchObject({
      page: { returned: 1, totalItems: 3 },
      transactions: [{ activityId: 1, large }],
    });
  });

  it("rejects a cursor issued for a different query", () => {
    const first = formatRecordPage(
      { AAPL: { bid: 1 }, MSFT: { bid: 2 } },
      "quotes",
      firstPage,
    );
    expect(() =>
      formatRecordPage({ MSFT: { bid: 2 } }, "quotes", {
        ...firstPage,
        cursorScope: "different-query",
        outputCursor: nextCursor(first),
      }),
    ).toThrow("does not match");
  });

  it("reports and advances past a single oversized item", () => {
    const page = formatArrayPage(
      [
        { activityId: 1, large: "x".repeat(130_000) },
        { activityId: 2, value: "tail" },
      ],
      "transactions",
      { ...firstPage, outputLimit: 2 },
    );
    expect(page).toMatchObject({
      page: { returned: 0, omittedOversized: 1, totalItems: 2 },
      oversizedItems: [{ key: "1", serializedCharacters: 130_027 }],
      transactions: [],
    });
    expect(
      formatArrayPage(
        [
          { activityId: 1, large: "x".repeat(130_000) },
          { activityId: 2, value: "tail" },
        ],
        "transactions",
        { ...firstPage, outputCursor: nextCursor(page) },
      ),
    ).toMatchObject({ transactions: [{ activityId: 2, value: "tail" }] });
  });

  it("pages candles while retaining price-history metadata", () => {
    const value = {
      symbol: "AAPL",
      previousClose: 100,
      candles: [{ datetime: 1 }, { datetime: 2 }],
    };
    const first = formatPriceHistoryPage(value, firstPage);
    expect(
      formatPriceHistoryPage(value, {
        ...firstPage,
        outputCursor: nextCursor(first),
      }),
    ).toMatchObject({
      source: "schwab",
      metadata: { symbol: "AAPL", previousClose: 100 },
      page: { returned: 1, totalItems: 2 },
      candles: [{ datetime: 2 }],
    });
  });

  it("flattens account orders into a cursor page", () => {
    const value = [
      { accountHash: "one", orders: [{ orderId: 1 }] },
      { accountHash: "two", orders: [{ orderId: 2 }] },
    ];
    const first = formatAllowedOrdersPage(value, firstPage);
    expect(
      formatAllowedOrdersPage(value, {
        ...firstPage,
        outputCursor: nextCursor(first),
      }),
    ).toMatchObject({
      page: { returned: 1, totalItems: 2 },
      orders: [{ accountHash: "two", order: { orderId: 2 } }],
    });
  });

  it("pages positions without repeating them in account metadata", () => {
    const value = {
      securitiesAccount: {
        accountNumber: "••••1234",
        positions: [
          { instrument: { assetType: "EQUITY", symbol: "AAPL" } },
          { instrument: { assetType: "EQUITY", symbol: "MSFT" } },
        ],
      },
    };
    const first = formatAccountPositionsPage(value, firstPage);
    expect(
      formatAccountPositionsPage(value, {
        ...firstPage,
        outputCursor: nextCursor(first),
      }),
    ).toMatchObject({
      metadata: { securitiesAccount: { accountNumber: "••••1234" } },
      page: { returned: 1, totalItems: 2 },
      positions: [{ instrument: { assetType: "EQUITY", symbol: "MSFT" } }],
    });
  });

  it("pages instrument searches", () => {
    const value = {
      requestId: "test",
      instruments: [
        { symbol: "AAPL", cusip: "037833100" },
        { symbol: "MSFT", cusip: "594918104" },
      ],
    };
    const first = formatInstrumentPage(value, firstPage);
    expect(first).toMatchObject({
      metadata: { requestId: "test" },
      instruments: [{ symbol: "AAPL" }],
    });
    expect(
      formatInstrumentPage(value, {
        ...firstPage,
        outputCursor: nextCursor(first),
      }),
    ).toMatchObject({ instruments: [{ symbol: "MSFT" }] });
  });
});

function nextCursor(value: unknown): string {
  const cursor = (value as { page?: { nextCursor?: unknown } }).page
    ?.nextCursor;
  if (typeof cursor !== "string") throw new Error("Expected nextCursor");
  return cursor;
}
