import { describe, expect, it } from "vitest";
import {
  normalizePriceHistoryDates,
  optionChainInputSchema,
  priceHistoryInputSchema,
  quoteFieldsInputSchema,
  tradableSymbolSchema,
} from "../src/mcp/market-schemas";

describe("market-data inputs", () => {
  it("accepts one or several quote field groups", () => {
    expect(quoteFieldsInputSchema.parse("extended")).toEqual(["extended"]);
    expect(
      quoteFieldsInputSchema.parse(["quote", "fundamental", "reference"]),
    ).toEqual(["quote", "fundamental", "reference"]);
  });

  it("normalizes calendar dates to UTC epoch milliseconds", () => {
    expect(
      normalizePriceHistoryDates({
        symbol: "AAPL",
        startDate: "2026-01-02",
        endDate: "2026-01-03",
      }),
    ).toMatchObject({
      symbol: "AAPL",
      startDate: Date.UTC(2026, 0, 2),
      endDate: Date.UTC(2026, 0, 4) - 1,
    });
  });

  it("accepts an epoch start within a calendar end date", () => {
    expect(
      priceHistoryInputSchema.safeParse({
        symbol: "AAPL",
        startDate: Date.UTC(2026, 0, 3, 12),
        endDate: "2026-01-03",
      }).success,
    ).toBe(true);
  });

  it("rejects invalid period and frequency combinations", () => {
    expect(
      priceHistoryInputSchema.safeParse({
        symbol: "AAPL",
        periodType: "ytd",
        period: 2,
      }).success,
    ).toBe(false);
    expect(
      priceHistoryInputSchema.safeParse({
        symbol: "AAPL",
        periodType: "day",
        frequencyType: "monthly",
        frequency: 1,
      }).success,
    ).toBe(false);
    expect(
      priceHistoryInputSchema.safeParse({
        symbol: "AAPL",
        frequencyType: "daily",
        frequency: 5,
      }).success,
    ).toBe(false);
  });

  it("accepts advanced option-chain filters and bounds date order", () => {
    expect(
      optionChainInputSchema.safeParse({
        symbol: "SPY",
        strikeCount: 10,
        range: "NTM",
        expMonth: "DEC",
        optionType: "S",
      }).success,
    ).toBe(true);
    expect(
      optionChainInputSchema.safeParse({
        symbol: "SPY",
        fromDate: "2026-12-31",
        toDate: "2026-01-01",
      }).success,
    ).toBe(false);
  });

  it("accepts Schwab option contract symbols with internal padding", () => {
    expect(tradableSymbolSchema.parse("SPY   251106C00674000")).toBe(
      "SPY   251106C00674000",
    );
  });
});
