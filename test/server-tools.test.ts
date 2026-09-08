import { afterEach, describe, expect, it, vi } from "vitest";
import { createSchwabMcpServer } from "../src/mcp/server";
import type { Env } from "../src/types";

const readTools = [
  "schwab_connection_status",
  "schwab_get_account",
  "schwab_get_instrument_by_cusip",
  "schwab_get_market_hours",
  "schwab_get_market_hours_for_market",
  "schwab_get_movers",
  "schwab_get_option_chain",
  "schwab_get_option_expirations",
  "schwab_get_order",
  "schwab_get_orders",
  "schwab_get_price_history",
  "schwab_get_quote",
  "schwab_get_quotes",
  "schwab_get_transaction",
  "schwab_get_transactions",
  "schwab_get_user_preferences",
  "schwab_list_account_hashes",
  "schwab_list_accounts",
  "schwab_search_instruments",
];

describe("MCP tool registration", () => {
  afterEach(() => vi.unstubAllGlobals());

  it("registers the complete read-only REST surface in disabled mode", () => {
    expect(toolNames("disabled", ["mcp:read"])).toEqual(readTools);
  });

  it("adds preparation in preview and gated execution in live mode", () => {
    expect(toolNames("preview", ["mcp:read"])).toHaveLength(22);
    expect(toolNames("live", ["mcp:read"])).toEqual(readTools);
    expect(toolNames("live", ["mcp:read", "mcp:trade"])).toHaveLength(23);
  });

  it("routes every added REST tool to its bounded Schwab endpoint", async () => {
    const urls: URL[] = [];
    vi.stubGlobal(
      "fetch",
      vi.fn((input: RequestInfo | URL) => {
        const url = new URL(input instanceof Request ? input.url : input);
        urls.push(url);
        return Promise.resolve(
          Response.json(
            url.pathname.endsWith("/userPreference")
              ? { streamerInfo: [], offers: [] }
              : {},
          ),
        );
      }),
    );
    const server = createServer("disabled", ["mcp:read"]);

    await callTool(server, "schwab_get_quote", { symbol: "AAPL" });
    await callTool(server, "schwab_get_option_expirations", { symbol: "SPY" });
    await callTool(server, "schwab_get_movers", {
      index: "$SPX",
      sort: "VOLUME",
      frequency: 0,
    });
    await callTool(server, "schwab_get_market_hours", {
      markets: ["equity", "option"],
    });
    await callTool(server, "schwab_get_market_hours_for_market", {
      market: "equity",
    });
    await callTool(server, "schwab_search_instruments", {
      search: "Apple",
      projection: "desc-search",
    });
    await callTool(server, "schwab_get_instrument_by_cusip", {
      cusip: "037833100",
    });
    await callTool(server, "schwab_get_transaction", {
      accountHash: "allowed_hash",
      transactionId: "9007199254740993",
    });
    await callTool(server, "schwab_get_user_preferences", {});

    expect(urls.map((url) => url.pathname)).toEqual([
      "/marketdata/v1/AAPL/quotes",
      "/marketdata/v1/expirationchain",
      "/marketdata/v1/movers/%24SPX",
      "/marketdata/v1/markets",
      "/marketdata/v1/markets/equity",
      "/marketdata/v1/instruments",
      "/marketdata/v1/instruments/037833100",
      "/trader/v1/accounts/allowed_hash/transactions/9007199254740993",
      "/trader/v1/userPreference",
    ]);
  });
});

function toolNames(tradingMode: string, scopes: string[]): string[] {
  const server = createServer(tradingMode, scopes);
  return Object.keys(registeredTools(server)).sort();
}

function createServer(tradingMode: string, scopes: string[]) {
  const stub = {
    fetch: () =>
      Promise.resolve(
        Response.json({
          accessToken: "access-token",
          accountHashes: ["allowed_hash"],
        }),
      ),
  } as unknown as DurableObjectStub;
  const namespace = {
    idFromName: () => ({}) as DurableObjectId,
    get: () => stub,
  } as unknown as DurableObjectNamespace;
  return createSchwabMcpServer(
    {
      TOKEN_VAULT: namespace,
      TRADING_MODE: tradingMode,
      SCHWAB_ENVIRONMENT: "production",
    } as Env,
    scopes,
  );
}

function registeredTools(server: ReturnType<typeof createSchwabMcpServer>) {
  return (
    server as unknown as {
      _registeredTools: Record<
        string,
        { handler: (args: Record<string, unknown>) => Promise<unknown> }
      >;
    }
  )._registeredTools;
}

async function callTool(
  server: ReturnType<typeof createSchwabMcpServer>,
  name: string,
  args: Record<string, unknown>,
): Promise<void> {
  const tool = registeredTools(server)[name];
  if (!tool) throw new Error(`Missing tool ${name}`);
  await tool.handler(args);
}
