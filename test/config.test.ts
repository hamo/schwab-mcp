import { describe, expect, it } from "vitest";
import { getTradingMode } from "../src/config";
import { tradeToolPolicy } from "../src/mcp/server";

describe("trading mode fail-closed behavior", () => {
  it("defaults unknown or missing-looking values to disabled", () => {
    expect(getTradingMode({ TRADING_MODE: "" })).toBe("disabled");
    expect(getTradingMode({ TRADING_MODE: "enabled" })).toBe("disabled");
  });

  it("never exposes write tools in a disabled deployment", () => {
    expect(tradeToolPolicy("disabled")).toEqual({
      preparation: false,
      execution: false,
    });
    expect(tradeToolPolicy("preview")).toEqual({
      preparation: true,
      execution: false,
    });
    expect(tradeToolPolicy("live")).toEqual({
      preparation: true,
      execution: true,
    });
  });
});
