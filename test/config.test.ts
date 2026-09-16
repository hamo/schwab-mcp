import { describe, expect, it } from "vitest";
import {
  getTradingMode,
  MCP_ACCESS_TOKEN_TTL_SECONDS,
  MCP_REFRESH_TOKEN_TTL_SECONDS,
} from "../src/config";
import { tradeToolPolicy } from "../src/mcp/server";

describe("trading mode fail-closed behavior", () => {
  it("defaults unknown or missing-looking values to disabled", () => {
    expect(getTradingMode({ TRADING_MODE: "" })).toBe("disabled");
    expect(getTradingMode({ TRADING_MODE: "enabled" })).toBe("disabled");
  });

  it("never exposes write tools in a disabled deployment", () => {
    expect(tradeToolPolicy("disabled", ["mcp:read", "mcp:trade"])).toEqual({
      preparation: false,
      execution: false,
    });
    expect(tradeToolPolicy("preview", ["mcp:read"])).toEqual({
      preparation: true,
      execution: false,
    });
    expect(tradeToolPolicy("live", ["mcp:read"])).toEqual({
      preparation: false,
      execution: false,
    });
    expect(tradeToolPolicy("live", ["mcp:read", "mcp:trade"])).toEqual({
      preparation: true,
      execution: true,
    });
  });
});

describe("MCP OAuth lifetime policy", () => {
  it("keeps access tokens short-lived and refresh grants valid for 30 days", () => {
    expect(MCP_ACCESS_TOKEN_TTL_SECONDS).toBe(60 * 60);
    expect(MCP_REFRESH_TOKEN_TTL_SECONDS).toBe(30 * 24 * 60 * 60);
  });
});
