import { describe, expect, it } from "vitest";
import { orderSchema } from "../src/mcp/server";

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
});
