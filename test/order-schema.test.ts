import { describe, expect, it } from "vitest";
import { orderSchema, schwabIdSchema } from "../src/mcp/server";

describe("Schwab order input", () => {
  it("accepts typed advanced order fields", () => {
    expect(
      orderSchema.safeParse({
        session: "NORMAL",
        duration: "GOOD_TILL_CANCEL",
        orderType: "TRAILING_STOP",
        orderStrategyType: "SINGLE",
        stopPriceLinkBasis: "MARK",
        stopPriceLinkType: "PERCENT",
        stopPriceOffset: 5,
        taxLotMethod: "HIGH_COST",
        orderLegCollection: [
          {
            instruction: "SELL",
            quantity: 10,
            positionEffect: "CLOSING",
            quantityType: "SHARES",
            instrument: { symbol: "AAPL", assetType: "EQUITY" },
          },
        ],
      }).success,
    ).toBe(true);
  });

  it("rejects unreviewed extension fields at every level", () => {
    expect(
      orderSchema.safeParse({
        session: "NORMAL",
        duration: "DAY",
        orderType: "MARKET",
        orderStrategyType: "SINGLE",
        hiddenInstruction: "do-something-else",
        orderLegCollection: [
          {
            instruction: "BUY",
            quantity: 1,
            instrument: {
              symbol: "AAPL",
              assetType: "EQUITY",
              hiddenInstrumentField: true,
            },
          },
        ],
      }).success,
    ).toBe(false);
  });

  it("requires prices and trailing-stop parameters by order type", () => {
    const leg = {
      instruction: "BUY" as const,
      quantity: 1,
      instrument: {
        symbol: "SPY   251106C00674000",
        assetType: "OPTION" as const,
      },
    };
    expect(
      orderSchema.safeParse({
        session: "NORMAL",
        duration: "DAY",
        orderType: "LIMIT",
        orderStrategyType: "SINGLE",
        orderLegCollection: [leg],
      }).success,
    ).toBe(false);
    expect(
      orderSchema.safeParse({
        session: "NORMAL",
        duration: "DAY",
        orderType: "STOP",
        orderStrategyType: "SINGLE",
        orderLegCollection: [leg],
      }).success,
    ).toBe(false);
    expect(
      orderSchema.safeParse({
        session: "NORMAL",
        duration: "DAY",
        orderType: "TRAILING_STOP",
        orderStrategyType: "SINGLE",
        orderLegCollection: [leg],
      }).success,
    ).toBe(false);
  });

  it("rejects price fields that contradict the order type", () => {
    const base = {
      session: "NORMAL" as const,
      duration: "DAY" as const,
      orderStrategyType: "SINGLE" as const,
      orderLegCollection: [
        {
          instruction: "BUY" as const,
          quantity: 1,
          instrument: { symbol: "AAPL", assetType: "EQUITY" as const },
        },
      ],
    };
    expect(
      orderSchema.safeParse({ ...base, orderType: "MARKET", price: 100 })
        .success,
    ).toBe(false);
    expect(
      orderSchema.safeParse({
        ...base,
        orderType: "LIMIT",
        price: 100,
        stopPrice: 90,
      }).success,
    ).toBe(false);
  });

  it("accepts an OCO container with exactly two executable children", () => {
    const child = (instruction: "SELL" | "SELL_SHORT") => ({
      session: "NORMAL" as const,
      duration: "GOOD_TILL_CANCEL" as const,
      orderType: "LIMIT" as const,
      orderStrategyType: "SINGLE" as const,
      price: 100,
      orderLegCollection: [
        {
          instruction,
          quantity: 1,
          instrument: { symbol: "AAPL", assetType: "EQUITY" as const },
        },
      ],
    });
    expect(
      orderSchema.safeParse({
        orderStrategyType: "OCO",
        childOrderStrategies: [child("SELL"), child("SELL_SHORT")],
      }).success,
    ).toBe(true);
  });

  it("rejects strategy-inconsistent order compositions", () => {
    const executable = {
      session: "NORMAL" as const,
      duration: "DAY" as const,
      orderType: "MARKET" as const,
      orderLegCollection: [
        {
          instruction: "BUY" as const,
          quantity: 1,
          instrument: { symbol: "AAPL", assetType: "EQUITY" as const },
        },
      ],
    };
    expect(
      orderSchema.safeParse({
        ...executable,
        orderStrategyType: "OCO",
      }).success,
    ).toBe(false);
    expect(
      orderSchema.safeParse({
        ...executable,
        orderStrategyType: "TRIGGER",
      }).success,
    ).toBe(false);
    expect(
      orderSchema.safeParse({
        ...executable,
        orderStrategyType: "SINGLE",
        childOrderStrategies: [{ ...executable, orderStrategyType: "SINGLE" }],
      }).success,
    ).toBe(false);
  });

  it("normalizes safe numeric and decimal-string Schwab IDs", () => {
    expect(schwabIdSchema.parse(12345)).toBe("12345");
    expect(schwabIdSchema.parse("9007199254740993")).toBe("9007199254740993");
    expect(schwabIdSchema.safeParse(9_007_199_254_740_993).success).toBe(false);
  });
});
