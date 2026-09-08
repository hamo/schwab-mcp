import { McpServer } from "@modelcontextprotocol/server";
import { z } from "zod";
import { getTradingMode } from "../config";
import { canonicalJson, sha256 } from "../security/crypto";
import { redactAccountNumbers } from "../security/redact";
import { schwabRequest } from "../schwab/client";
import type { PendingAction } from "../schwab/types";
import { VaultClient, type AccessSession } from "../storage/vault-client";
import type { Env, TradingMode } from "../types";

const accountHashSchema = z
  .string()
  .min(8)
  .max(128)
  .regex(/^[A-Za-z0-9_-]+$/, "Invalid account hash");
const symbolSchema = z
  .string()
  .trim()
  .min(1)
  .max(32)
  .regex(/^[A-Za-z0-9.$/:_-]+$/);
const isoDateSchema = z.string().datetime({ offset: true });

const orderSchema = z
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
    orderType: z.string().min(1).max(64),
    orderStrategyType: z.enum(["SINGLE", "OCO", "TRIGGER"]),
    price: z.string().max(32).optional(),
    stopPrice: z.string().max(32).optional(),
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
            ]),
            quantity: z.number().positive().finite(),
            instrument: z
              .object({
                symbol: symbolSchema,
                assetType: z.string().min(1).max(64),
              })
              .passthrough(),
          })
          .passthrough(),
      )
      .min(1)
      .max(20),
  })
  .passthrough();

export function createSchwabMcpServer(env: Env): McpServer {
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
      const data = await schwabRequest<unknown>(
        env,
        session.accessToken,
        "/trader/v1/accounts",
        {
          query: { fields: includePositions ? "positions" : undefined },
        },
      );
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
      inputSchema: z.object({
        symbols: z.array(symbolSchema).min(1).max(50),
        fields: z
          .enum(["quote", "fundamental", "reference", "regular"])
          .optional(),
        indicative: z.boolean().optional(),
      }),
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
            query: { symbols: symbols.join(","), fields, indicative },
          },
        ),
      );
    },
  );

  server.registerTool(
    "schwab_get_price_history",
    {
      description: "Get historical price candles for a symbol.",
      inputSchema: z.object({
        symbol: symbolSchema,
        periodType: z.enum(["day", "month", "year", "ytd"]).optional(),
        period: z.number().int().positive().max(20).optional(),
        frequencyType: z
          .enum(["minute", "daily", "weekly", "monthly"])
          .optional(),
        frequency: z.number().int().positive().max(60).optional(),
        startDate: z.number().int().nonnegative().optional(),
        endDate: z.number().int().nonnegative().optional(),
        needExtendedHoursData: z.boolean().optional(),
        needPreviousClose: z.boolean().optional(),
      }),
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
            query: { symbol, ...query },
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
      inputSchema: z.object({
        symbol: symbolSchema,
        contractType: z.enum(["CALL", "PUT", "ALL"]).default("ALL"),
        strikeCount: z.number().int().positive().max(100).default(20),
        includeUnderlyingQuote: z.boolean().default(false),
        strategy: z.string().max(32).optional(),
        fromDate: z.string().date().optional(),
        toDate: z.string().date().optional(),
      }),
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
        redactAccountNumbers(
          await schwabRequest<unknown>(
            env,
            session.accessToken,
            "/trader/v1/orders",
            { query },
          ),
        ),
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

  const tradePolicy = tradeToolPolicy(mode);
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

export function tradeToolPolicy(mode: TradingMode): {
  preparation: boolean;
  execution: boolean;
} {
  return {
    preparation: mode === "preview" || mode === "live",
    execution: mode === "live",
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
      annotations: { readOnlyHint: true },
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
      annotations: { readOnlyHint: true },
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
      annotations: { readOnlyHint: true },
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
  const canonical = canonicalJson(action);
  if (canonical.length > 64_000) throw new Error("Order payload is too large");
  const digest = await sha256(canonical);
  const summary = JSON.stringify(action, null, 2);
  if (mode === "preview") {
    return result({ mode, digest, summary, executable: false });
  }
  const pending = await vault.createPreparation({ action, digest, summary });
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
