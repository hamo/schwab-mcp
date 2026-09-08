import { McpServer } from "@modelcontextprotocol/server";
import { z } from "zod";
import { getTradingMode } from "../config";
import { sha256 } from "../security/crypto";
import {
  redactAccountNumbers,
  sanitizeUserPreferences,
} from "../security/redact";
import {
  getAllowedAccounts,
  getAllowedOrders,
  schwabRequest,
} from "../schwab/client";
import { reviewAction } from "../schwab/order-review";
import type { PendingAction } from "../schwab/types";
import { VaultClient, type AccessSession } from "../storage/vault-client";
import type { Env, TradingMode } from "../types";
import {
  instrumentProjectionSchema,
  marketSchema,
  marketSymbolSchema,
  moverIndexSchema,
  normalizePriceHistoryDates,
  optionChainInputSchema,
  priceHistoryInputSchema,
  quoteFieldsInputSchema,
} from "./market-schemas";

const accountHashSchema = z
  .string()
  .min(8)
  .max(128)
  .regex(/^[A-Za-z0-9_-]+$/, "Invalid account hash");
const symbolSchema = marketSymbolSchema;
const isoDateSchema = z.string().datetime({ offset: true });
const calendarDateSchema = z.string().date();
const cusipSchema = z
  .string()
  .trim()
  .length(9)
  .regex(/^[A-Za-z0-9]{9}$/, "Invalid CUSIP");
const searchTermSchema = z
  .string()
  .trim()
  .min(1)
  .max(128)
  .refine(
    (value) => !/[\u0000-\u001f\u007f]/u.test(value),
    "Invalid search term",
  );
const priceSchema = z.union([
  z.number().finite().nonnegative(),
  z
    .string()
    .min(1)
    .max(32)
    .regex(/^\d+(?:\.\d+)?$/),
]);

export const orderSchema: z.ZodType<Record<string, unknown>> = z.lazy(() =>
  z
    .object({
      session: z.enum(["NORMAL", "AM", "PM", "SEAMLESS"]),
      duration: z.enum([
        "DAY",
        "GOOD_TILL_CANCEL",
        "FILL_OR_KILL",
        "IMMEDIATE_OR_CANCEL",
        "END_OF_WEEK",
        "END_OF_MONTH",
        "NEXT_END_OF_MONTH",
        "UNKNOWN",
      ]),
      orderType: z.enum([
        "MARKET",
        "LIMIT",
        "STOP",
        "STOP_LIMIT",
        "TRAILING_STOP",
        "CABINET",
        "NON_MARKETABLE",
        "MARKET_ON_CLOSE",
        "EXERCISE",
        "TRAILING_STOP_LIMIT",
        "NET_DEBIT",
        "NET_CREDIT",
        "NET_ZERO",
        "LIMIT_ON_CLOSE",
      ]),
      orderStrategyType: z.enum([
        "SINGLE",
        "CANCEL",
        "RECALL",
        "PAIR",
        "FLATTEN",
        "TWO_DAY_SWAP",
        "BLAST_ALL",
        "OCO",
        "TRIGGER",
      ]),
      price: priceSchema.optional(),
      stopPrice: priceSchema.optional(),
      quantity: z.number().positive().finite().optional(),
      activationPrice: z.number().finite().nonnegative().optional(),
      cancelTime: z.string().min(1).max(64).optional(),
      releaseTime: z.string().min(1).max(64).optional(),
      destinationLinkName: z.string().min(1).max(64).optional(),
      specialInstruction: z
        .enum(["ALL_OR_NONE", "DO_NOT_REDUCE", "ALL_OR_NONE_DO_NOT_REDUCE"])
        .optional(),
      complexOrderStrategyType: z
        .enum([
          "NONE",
          "COVERED",
          "VERTICAL",
          "BACK_RATIO",
          "CALENDAR",
          "DIAGONAL",
          "STRADDLE",
          "STRANGLE",
          "COLLAR_SYNTHETIC",
          "BUTTERFLY",
          "CONDOR",
          "IRON_CONDOR",
          "VERTICAL_ROLL",
          "COLLAR_WITH_STOCK",
          "DOUBLE_DIAGONAL",
          "UNBALANCED_BUTTERFLY",
          "UNBALANCED_CONDOR",
          "UNBALANCED_IRON_CONDOR",
          "UNBALANCED_VERTICAL_ROLL",
          "MUTUAL_FUND_SWAP",
          "CUSTOM",
        ])
        .optional(),
      stopPriceLinkBasis: z
        .enum([
          "MANUAL",
          "BASE",
          "TRIGGER",
          "LAST",
          "BID",
          "ASK",
          "ASK_BID",
          "MARK",
          "AVERAGE",
        ])
        .optional(),
      stopPriceLinkType: z.enum(["VALUE", "PERCENT", "TICK"]).optional(),
      stopPriceOffset: z.number().finite().optional(),
      stopType: z.enum(["STANDARD", "BID", "ASK", "LAST", "MARK"]).optional(),
      priceLinkBasis: z
        .enum([
          "MANUAL",
          "BASE",
          "TRIGGER",
          "LAST",
          "BID",
          "ASK",
          "ASK_BID",
          "MARK",
          "AVERAGE",
        ])
        .optional(),
      priceLinkType: z.enum(["VALUE", "PERCENT", "TICK"]).optional(),
      taxLotMethod: z
        .enum([
          "FIFO",
          "LIFO",
          "HIGH_COST",
          "LOW_COST",
          "AVERAGE_COST",
          "SPECIFIC_LOT",
          "LOSS_HARVESTER",
        ])
        .optional(),
      orderLegCollection: z
        .array(
          z
            .object({
              instruction: z.enum([
                "BUY",
                "SELL",
                "BUY_TO_COVER",
                "SELL_SHORT",
                "BUY_TO_OPEN",
                "BUY_TO_CLOSE",
                "SELL_TO_OPEN",
                "SELL_TO_CLOSE",
                "EXCHANGE",
                "SELL_SHORT_EXEMPT",
              ]),
              quantity: z.number().positive().finite(),
              orderLegType: z
                .enum([
                  "EQUITY",
                  "OPTION",
                  "INDEX",
                  "MUTUAL_FUND",
                  "CASH_EQUIVALENT",
                  "FIXED_INCOME",
                  "CURRENCY",
                  "COLLECTIVE_INVESTMENT",
                ])
                .optional(),
              legId: z.number().int().nonnegative().optional(),
              positionEffect: z
                .enum(["OPENING", "CLOSING", "AUTOMATIC"])
                .optional(),
              quantityType: z
                .enum(["ALL_SHARES", "DOLLARS", "SHARES"])
                .optional(),
              divCapGains: z.enum(["REINVEST", "PAYOUT"]).optional(),
              toSymbol: symbolSchema.optional(),
              instrument: z
                .object({
                  symbol: symbolSchema,
                  assetType: z.enum([
                    "EQUITY",
                    "MUTUAL_FUND",
                    "OPTION",
                    "FUTURE",
                    "FOREX",
                    "INDEX",
                    "CASH_EQUIVALENT",
                    "FIXED_INCOME",
                    "PRODUCT",
                    "CURRENCY",
                    "COLLECTIVE_INVESTMENT",
                  ]),
                  cusip: cusipSchema.optional(),
                })
                .strict(),
            })
            .strict(),
        )
        .min(1)
        .max(20)
        .optional(),
      childOrderStrategies: z.array(orderSchema).min(1).max(10).optional(),
    })
    .strict()
    .refine(
      (order) =>
        order.orderLegCollection !== undefined ||
        order.childOrderStrategies !== undefined,
      "Order must contain legs or child strategies",
    ),
);

export function createSchwabMcpServer(
  env: Env,
  grantedScopes: string[],
): McpServer {
  const server = new McpServer({ name: "schwab-mcp", version: "0.1.0" });
  const vault = new VaultClient(env);
  const mode = getTradingMode(env);

  server.registerTool(
    "schwab_connection_status",
    {
      description:
        "Check whether this private MCP deployment has an encrypted Schwab session.",
      annotations: { readOnlyHint: true },
    },
    async () => result({ ...(await vault.status()), tradingMode: mode }),
  );

  server.registerTool(
    "schwab_list_account_hashes",
    {
      description:
        "List allowed account hashes and non-reversible fingerprints. No raw account numbers are returned.",
      annotations: { readOnlyHint: true },
    },
    async () => {
      const session = await vault.accessSession();
      return result(
        await Promise.all(
          session.accountHashes.map(async (accountHash) => ({
            accountHash,
            fingerprint: await sha256(accountHash),
          })),
        ),
      );
    },
  );

  server.registerTool(
    "schwab_list_accounts",
    {
      description:
        "List Schwab brokerage accounts. Raw account numbers are redacted.",
      inputSchema: z.object({ includePositions: z.boolean().default(false) }),
      annotations: { readOnlyHint: true },
    },
    async ({ includePositions }) => {
      const session = await vault.accessSession();
      const data = await getAllowedAccounts(env, session, includePositions);
      return result(redactAccountNumbers(data));
    },
  );

  server.registerTool(
    "schwab_get_account",
    {
      description: "Get one Schwab account by its encrypted account hash.",
      inputSchema: z.object({
        accountHash: accountHashSchema,
        includePositions: z.boolean().default(false),
      }),
      annotations: { readOnlyHint: true },
    },
    async ({ accountHash, includePositions }) => {
      const session = await allowedSession(vault, accountHash);
      const data = await schwabRequest<unknown>(
        env,
        session.accessToken,
        `/trader/v1/accounts/${encodeURIComponent(accountHash)}`,
        { query: { fields: includePositions ? "positions" : undefined } },
      );
      return result(redactAccountNumbers(data));
    },
  );

  server.registerTool(
    "schwab_get_quotes",
    {
      description: "Get current Schwab market quotes for up to 50 symbols.",
      inputSchema: z
        .object({
          symbols: z.array(symbolSchema).min(1).max(50),
          fields: quoteFieldsInputSchema.optional(),
          indicative: z.boolean().optional(),
        })
        .strict(),
      annotations: { readOnlyHint: true },
    },
    async ({ symbols, fields, indicative }) => {
      const session = await vault.accessSession();
      return result(
        await schwabRequest<unknown>(
          env,
          session.accessToken,
          "/marketdata/v1/quotes",
          {
            query: {
              symbols: symbols.join(","),
              fields: fields?.join(","),
              indicative,
            },
          },
        ),
      );
    },
  );

  server.registerTool(
    "schwab_get_quote",
    {
      description: "Get a detailed Schwab quote for one symbol.",
      inputSchema: z
        .object({
          symbol: symbolSchema,
          fields: quoteFieldsInputSchema.optional(),
        })
        .strict(),
      annotations: { readOnlyHint: true },
    },
    async ({ symbol, fields }) => {
      const session = await vault.accessSession();
      return result(
        await schwabRequest<unknown>(
          env,
          session.accessToken,
          `/marketdata/v1/${encodeURIComponent(symbol)}/quotes`,
          { query: { fields: fields?.join(",") } },
        ),
      );
    },
  );

  server.registerTool(
    "schwab_get_price_history",
    {
      description: "Get historical price candles for a symbol.",
      inputSchema: priceHistoryInputSchema,
      annotations: { readOnlyHint: true },
    },
    async ({ symbol, ...query }) => {
      const session = await vault.accessSession();
      return result(
        await schwabRequest<unknown>(
          env,
          session.accessToken,
          "/marketdata/v1/pricehistory",
          {
            query: normalizePriceHistoryDates({ symbol, ...query }),
          },
        ),
      );
    },
  );

  server.registerTool(
    "schwab_get_option_chain",
    {
      description:
        "Get a Schwab option chain. Narrow the date and strike range to limit output.",
      inputSchema: optionChainInputSchema,
      annotations: { readOnlyHint: true },
    },
    async (query) => {
      const session = await vault.accessSession();
      return result(
        await schwabRequest<unknown>(
          env,
          session.accessToken,
          "/marketdata/v1/chains",
          {
            query,
          },
        ),
      );
    },
  );

  server.registerTool(
    "schwab_get_option_expirations",
    {
      description: "List available option expiration dates for a symbol.",
      inputSchema: z.object({ symbol: symbolSchema }).strict(),
      annotations: { readOnlyHint: true },
    },
    async ({ symbol }) => {
      const session = await vault.accessSession();
      return result(
        await schwabRequest<unknown>(
          env,
          session.accessToken,
          "/marketdata/v1/expirationchain",
          { query: { symbol } },
        ),
      );
    },
  );

  server.registerTool(
    "schwab_get_movers",
    {
      description:
        "Get the most active or largest-moving securities for an index or market.",
      inputSchema: z
        .object({
          index: moverIndexSchema,
          sort: z.enum([
            "VOLUME",
            "TRADES",
            "PERCENT_CHANGE_UP",
            "PERCENT_CHANGE_DOWN",
          ]),
          frequency: z
            .union([
              z.literal(0),
              z.literal(1),
              z.literal(5),
              z.literal(10),
              z.literal(30),
              z.literal(60),
            ])
            .default(0),
        })
        .strict(),
      annotations: { readOnlyHint: true },
    },
    async ({ index, ...query }) => {
      const session = await vault.accessSession();
      return result(
        await schwabRequest<unknown>(
          env,
          session.accessToken,
          `/marketdata/v1/movers/${encodeURIComponent(index)}`,
          { query },
        ),
      );
    },
  );

  server.registerTool(
    "schwab_get_market_hours",
    {
      description: "Get Schwab market hours for one or more markets.",
      inputSchema: z
        .object({
          markets: z.array(marketSchema).min(1).max(5),
          date: calendarDateSchema.optional(),
        })
        .strict(),
      annotations: { readOnlyHint: true },
    },
    async ({ markets, date }) => {
      const session = await vault.accessSession();
      return result(
        await schwabRequest<unknown>(
          env,
          session.accessToken,
          "/marketdata/v1/markets",
          { query: { markets: markets.join(","), date } },
        ),
      );
    },
  );

  server.registerTool(
    "schwab_get_market_hours_for_market",
    {
      description: "Get Schwab market hours for a single market.",
      inputSchema: z
        .object({ market: marketSchema, date: calendarDateSchema.optional() })
        .strict(),
      annotations: { readOnlyHint: true },
    },
    async ({ market, date }) => {
      const session = await vault.accessSession();
      return result(
        await schwabRequest<unknown>(
          env,
          session.accessToken,
          `/marketdata/v1/markets/${encodeURIComponent(market)}`,
          { query: { date } },
        ),
      );
    },
  );

  server.registerTool(
    "schwab_search_instruments",
    {
      description: "Search Schwab instruments by symbol or description.",
      inputSchema: z
        .object({
          search: searchTermSchema,
          projection: instrumentProjectionSchema,
        })
        .strict(),
      annotations: { readOnlyHint: true },
    },
    async ({ search, projection }) => {
      const session = await vault.accessSession();
      return result(
        await schwabRequest<unknown>(
          env,
          session.accessToken,
          "/marketdata/v1/instruments",
          { query: { symbol: search, projection } },
        ),
      );
    },
  );

  server.registerTool(
    "schwab_get_instrument_by_cusip",
    {
      description: "Get Schwab instrument metadata for one CUSIP.",
      inputSchema: z.object({ cusip: cusipSchema }).strict(),
      annotations: { readOnlyHint: true },
    },
    async ({ cusip }) => {
      const session = await vault.accessSession();
      return result(
        await schwabRequest<unknown>(
          env,
          session.accessToken,
          `/marketdata/v1/instruments/${encodeURIComponent(cusip)}`,
        ),
      );
    },
  );

  server.registerTool(
    "schwab_get_orders",
    {
      description:
        "Get orders across all allowed Schwab accounts for a bounded date range.",
      inputSchema: z.object({
        fromEnteredTime: isoDateSchema,
        toEnteredTime: isoDateSchema,
        maxResults: z.number().int().positive().max(3000).default(100),
        status: z.string().max(64).optional(),
      }),
      annotations: { readOnlyHint: true },
    },
    async (query) => {
      const session = await vault.accessSession();
      return result(
        redactAccountNumbers(await getAllowedOrders(env, session, query)),
      );
    },
  );

  server.registerTool(
    "schwab_get_order",
    {
      description: "Get a specific Schwab order.",
      inputSchema: z.object({
        accountHash: accountHashSchema,
        orderId: z.string().min(1).max(64),
      }),
      annotations: { readOnlyHint: true },
    },
    async ({ accountHash, orderId }) => {
      const session = await allowedSession(vault, accountHash);
      return result(
        redactAccountNumbers(
          await schwabRequest<unknown>(
            env,
            session.accessToken,
            `/trader/v1/accounts/${encodeURIComponent(accountHash)}/orders/${encodeURIComponent(orderId)}`,
          ),
        ),
      );
    },
  );

  server.registerTool(
    "schwab_get_transactions",
    {
      description: "Get transactions for one allowed Schwab account.",
      inputSchema: z.object({
        accountHash: accountHashSchema,
        startDate: isoDateSchema,
        endDate: isoDateSchema,
        types: z.string().min(1).max(256),
        symbol: symbolSchema.optional(),
      }),
      annotations: { readOnlyHint: true },
    },
    async ({ accountHash, ...query }) => {
      const session = await allowedSession(vault, accountHash);
      return result(
        redactAccountNumbers(
          await schwabRequest<unknown>(
            env,
            session.accessToken,
            `/trader/v1/accounts/${encodeURIComponent(accountHash)}/transactions`,
            { query },
          ),
        ),
      );
    },
  );

  server.registerTool(
    "schwab_get_transaction",
    {
      description: "Get one transaction from an allowed Schwab account.",
      inputSchema: z
        .object({
          accountHash: accountHashSchema,
          transactionId: z.union([
            z.number().int().positive().safe(),
            z.string().min(1).max(20).regex(/^\d+$/),
          ]),
        })
        .strict(),
      annotations: { readOnlyHint: true },
    },
    async ({ accountHash, transactionId }) => {
      const session = await allowedSession(vault, accountHash);
      return result(
        redactAccountNumbers(
          await schwabRequest<unknown>(
            env,
            session.accessToken,
            `/trader/v1/accounts/${encodeURIComponent(accountHash)}/transactions/${encodeURIComponent(String(transactionId))}`,
          ),
        ),
      );
    },
  );

  server.registerTool(
    "schwab_get_user_preferences",
    {
      description:
        "Get non-identifying Schwab market-data permissions and whether streaming is available. Account and streamer identifiers are omitted.",
      annotations: { readOnlyHint: true },
    },
    async () => {
      const session = await vault.accessSession();
      return result(
        sanitizeUserPreferences(
          await schwabRequest<unknown>(
            env,
            session.accessToken,
            "/trader/v1/userPreference",
          ),
        ),
      );
    },
  );

  const tradePolicy = tradeToolPolicy(mode, grantedScopes);
  if (tradePolicy.preparation) {
    registerTradePreparationTools(
      server,
      env,
      vault,
      mode as Exclude<TradingMode, "disabled">,
    );
  }
  if (tradePolicy.execution) registerLiveExecutionTool(server, env, vault);
  return server;
}

export function tradeToolPolicy(
  mode: TradingMode,
  grantedScopes: string[],
): {
  preparation: boolean;
  execution: boolean;
} {
  return {
    preparation:
      mode === "preview" ||
      (mode === "live" && grantedScopes.includes("mcp:trade")),
    execution: mode === "live" && grantedScopes.includes("mcp:trade"),
  };
}

function registerTradePreparationTools(
  server: McpServer,
  env: Env,
  vault: VaultClient,
  mode: Exclude<TradingMode, "disabled">,
): void {
  server.registerTool(
    "schwab_prepare_place_order",
    {
      description:
        "Validate and prepare an order. Preview mode never sends it to Schwab.",
      inputSchema: z.object({
        accountHash: accountHashSchema,
        order: orderSchema,
      }),
      annotations: { readOnlyHint: mode === "preview" },
    },
    async ({ accountHash, order }) =>
      prepareTrade(env, vault, mode, { kind: "place", accountHash, order }),
  );
  server.registerTool(
    "schwab_prepare_replace_order",
    {
      description: "Validate and prepare replacement of an existing order.",
      inputSchema: z.object({
        accountHash: accountHashSchema,
        orderId: z.string().min(1).max(64),
        order: orderSchema,
      }),
      annotations: { readOnlyHint: mode === "preview" },
    },
    async ({ accountHash, orderId, order }) =>
      prepareTrade(env, vault, mode, {
        kind: "replace",
        accountHash,
        orderId,
        order,
      }),
  );
  server.registerTool(
    "schwab_prepare_cancel_order",
    {
      description: "Prepare cancellation of an existing order.",
      inputSchema: z.object({
        accountHash: accountHashSchema,
        orderId: z.string().min(1).max(64),
      }),
      annotations: { readOnlyHint: mode === "preview" },
    },
    async ({ accountHash, orderId }) =>
      prepareTrade(env, vault, mode, { kind: "cancel", accountHash, orderId }),
  );
}

function registerLiveExecutionTool(
  server: McpServer,
  env: Env,
  vault: VaultClient,
): void {
  server.registerTool(
    "schwab_execute_approved_order",
    {
      description:
        "Execute a prepared order only after the owner approved its exact digest in the browser.",
      inputSchema: z.object({
        preparationId: z.string().uuid(),
        digest: z.string().min(20).max(128),
      }),
      annotations: {
        readOnlyHint: false,
        destructiveHint: true,
        idempotentHint: false,
      },
    },
    async ({ preparationId, digest }) => {
      if (getTradingMode(env) !== "live")
        throw new Error("Live trading is disabled");
      const action = await vault.consumePreparation(preparationId, digest);
      const session = await allowedSession(vault, action.accountHash);
      const accountPath = `/trader/v1/accounts/${encodeURIComponent(action.accountHash)}/orders`;
      if (action.kind === "place") {
        return result(
          await schwabRequest<unknown>(env, session.accessToken, accountPath, {
            method: "POST",
            body: action.order,
          }),
        );
      }
      const orderPath = `${accountPath}/${encodeURIComponent(action.orderId)}`;
      if (action.kind === "replace") {
        return result(
          await schwabRequest<unknown>(env, session.accessToken, orderPath, {
            method: "PUT",
            body: action.order,
          }),
        );
      }
      return result(
        await schwabRequest<unknown>(env, session.accessToken, orderPath, {
          method: "DELETE",
        }),
      );
    },
  );
}

async function prepareTrade(
  env: Env,
  vault: VaultClient,
  mode: Exclude<TradingMode, "disabled">,
  action: PendingAction,
) {
  await allowedSession(vault, action.accountHash);
  const { digest, summary } = await reviewAction(action);
  if (mode === "preview") {
    return result({ mode, digest, summary, executable: false });
  }
  const pending = await vault.createPreparation(action);
  const origin = new URL(env.MCP_RESOURCE_URL).origin;
  return result({
    mode,
    digest,
    preparationId: pending.id,
    expiresAt: pending.expiresAt,
    approvalUrl: `${origin}/trade/approve?id=${encodeURIComponent(pending.id)}`,
    nextStep:
      "Open approvalUrl in a browser, approve the exact action, then call schwab_execute_approved_order.",
  });
}

async function allowedSession(
  vault: VaultClient,
  accountHash: string,
): Promise<AccessSession> {
  const session = await vault.accessSession();
  if (!session.accountHashes.includes(accountHash))
    throw new Error("Account hash is not allowed");
  return session;
}

function result(value: unknown) {
  const structuredContent = { result: value };
  let text = JSON.stringify(structuredContent, null, 2);
  if (text.length > 120_000) {
    text = JSON.stringify({
      error: "Response exceeded the safe MCP output limit. Narrow the query.",
    });
    return {
      isError: true,
      content: [{ type: "text" as const, text }],
      structuredContent: { error: "response_too_large" },
    };
  }
  return { content: [{ type: "text" as const, text }], structuredContent };
}
