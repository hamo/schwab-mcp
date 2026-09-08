import {
  decodeUtf8,
  fromBase64Url,
  toBase64Url,
  utf8,
} from "../security/encoding";

export interface OutputPageOptions {
  outputMode: "paged" | "raw";
  outputCursor?: string | undefined;
  outputLimit: number;
}

const MAX_PAGE_ITEMS_JSON_CHARACTERS = 80_000;
const CURSOR_PREFIX = "v1.";

interface CursorItem {
  key: string;
  value: unknown;
}

export function formatArrayPage(
  value: unknown,
  itemKey: string,
  options: OutputPageOptions,
): unknown {
  if (options.outputMode === "raw") return value;
  if (!isUnknownArray(value))
    throw new Error("Schwab returned an invalid list");
  const items = value.map((item) => ({
    key: transactionKey(item),
    value: item,
  }));
  return { source: "schwab", ...pageResult(itemKey, items, options) };
}

export function formatRecordPage(
  value: unknown,
  itemKey: string,
  options: OutputPageOptions,
): unknown {
  if (options.outputMode === "raw") return value;
  if (!isRecord(value)) throw new Error("Schwab returned an invalid record");
  const entries = Object.entries(value).map(([key, item]) => ({
    key,
    value: { key, item },
  }));
  return { source: "schwab", ...pageResult(itemKey, entries, options) };
}

export function formatPriceHistoryPage(
  value: unknown,
  options: OutputPageOptions,
): unknown {
  if (options.outputMode === "raw") return value;
  if (!isRecord(value))
    throw new Error("Schwab returned invalid price history");
  const candles = value.candles;
  if (candles !== undefined && !isUnknownArray(candles)) {
    throw new Error("Schwab returned invalid price-history candles");
  }
  const metadata = { ...value };
  delete metadata.candles;
  return {
    source: "schwab",
    metadata,
    ...pageResult(
      "candles",
      (candles ?? []).map((candle) => ({
        key: candleKey(candle),
        value: candle,
      })),
      options,
    ),
  };
}

export function formatInstrumentPage(
  value: unknown,
  options: OutputPageOptions,
): unknown {
  if (options.outputMode === "raw") return value;
  if (!isRecord(value) || !isUnknownArray(value.instruments)) {
    throw new Error("Schwab returned invalid instruments");
  }
  const metadata = { ...value };
  delete metadata.instruments;
  return {
    source: "schwab",
    metadata,
    ...pageResult(
      "instruments",
      value.instruments.map((instrument) => ({
        key: instrumentKey(instrument),
        value: instrument,
      })),
      options,
    ),
  };
}

export function formatAllowedOrdersPage(
  value: unknown,
  options: OutputPageOptions,
): unknown {
  if (options.outputMode === "raw") return value;
  if (!isUnknownArray(value))
    throw new Error("Schwab returned invalid account orders");
  const orders: CursorItem[] = [];
  for (const accountResult of value) {
    if (
      !isRecord(accountResult) ||
      typeof accountResult.accountHash !== "string" ||
      !isUnknownArray(accountResult.orders)
    ) {
      throw new Error("Schwab returned invalid account orders");
    }
    for (const order of accountResult.orders) {
      orders.push({
        key: `${accountResult.accountHash}\u0000${orderKey(order)}`,
        value: { accountHash: accountResult.accountHash, order },
      });
    }
  }
  return { source: "schwab", ...pageResult("orders", orders, options) };
}

export function formatAccountPositionsPage(
  value: unknown,
  options: OutputPageOptions,
): unknown {
  if (options.outputMode === "raw") return value;
  if (!isRecord(value)) throw new Error("Schwab returned an invalid account");
  const account = value.securitiesAccount;
  if (!isRecord(account)) throw new Error("Schwab returned an invalid account");
  const positions = account.positions;
  if (positions !== undefined && !isUnknownArray(positions)) {
    throw new Error("Schwab returned invalid account positions");
  }
  const accountMetadata = { ...account };
  delete accountMetadata.positions;
  return {
    source: "schwab",
    metadata: { ...value, securitiesAccount: accountMetadata },
    ...pageResult(
      "positions",
      (positions ?? []).map((position) => ({
        key: positionKey(position),
        value: position,
      })),
      options,
    ),
  };
}

export function formatAllowedAccountPositionsPage(
  value: unknown,
  options: OutputPageOptions,
): unknown {
  if (options.outputMode === "raw") return value;
  if (!isUnknownArray(value))
    throw new Error("Schwab returned invalid accounts");
  const accounts: unknown[] = [];
  const positions: CursorItem[] = [];
  for (const accountResult of value) {
    if (
      !isRecord(accountResult) ||
      typeof accountResult.accountHash !== "string" ||
      !isRecord(accountResult.account)
    ) {
      throw new Error("Schwab returned invalid accounts");
    }
    const response = accountResult.account;
    const account = response.securitiesAccount;
    if (!isRecord(account))
      throw new Error("Schwab returned an invalid account");
    const accountPositions = account.positions;
    if (accountPositions !== undefined && !isUnknownArray(accountPositions)) {
      throw new Error("Schwab returned invalid account positions");
    }
    const accountMetadata = { ...account };
    delete accountMetadata.positions;
    accounts.push({
      accountHash: accountResult.accountHash,
      account: { ...response, securitiesAccount: accountMetadata },
    });
    for (const position of accountPositions ?? []) {
      positions.push({
        key: `${accountResult.accountHash}\u0000${positionKey(position)}`,
        value: { accountHash: accountResult.accountHash, position },
      });
    }
  }
  return {
    source: "schwab",
    accounts,
    ...pageResult("positions", positions, options),
  };
}

function pageResult(
  itemKey: string,
  unsorted: CursorItem[],
  options: OutputPageOptions,
): Record<string, unknown> {
  const values = [...unsorted].sort((left, right) =>
    compareKeys(left.key, right.key),
  );
  const afterKey = options.outputCursor
    ? decodeCursor(options.outputCursor)
    : undefined;
  const start =
    afterKey === undefined
      ? 0
      : values.findIndex(
          (candidate) => compareKeys(candidate.key, afterKey) > 0,
        );
  const effectiveStart = start < 0 ? values.length : start;
  const requestedEnd = Math.min(
    effectiveStart + options.outputLimit,
    values.length,
  );
  const selected: CursorItem[] = [];
  let serializedCharacters = 0;
  for (let index = effectiveStart; index < requestedEnd; index += 1) {
    const candidate = values[index];
    if (!candidate) break;
    const size = JSON.stringify(candidate.value)?.length ?? 4;
    if (
      selected.length > 0 &&
      serializedCharacters + size > MAX_PAGE_ITEMS_JSON_CHARACTERS
    ) {
      break;
    }
    selected.push(candidate);
    serializedCharacters += size;
  }
  const end = effectiveStart + selected.length;
  return {
    page: {
      cursor: options.outputCursor ?? null,
      limit: options.outputLimit,
      returned: selected.length,
      totalItems: values.length,
      nextCursor:
        end < values.length && selected.length > 0
          ? encodeCursor(selected[selected.length - 1]!.key)
          : null,
      fetchedAt: new Date().toISOString(),
    },
    [itemKey]: selected.map((item) => item.value),
  };
}

function transactionKey(value: unknown): string {
  if (!isRecord(value))
    throw new Error("Schwab returned an invalid transaction");
  return scalarKey(value.activityId, "transaction activityId");
}

function orderKey(value: unknown): string {
  if (!isRecord(value)) throw new Error("Schwab returned an invalid order");
  return scalarKey(value.orderId, "order orderId");
}

function candleKey(value: unknown): string {
  if (!isRecord(value)) throw new Error("Schwab returned an invalid candle");
  return scalarKey(value.datetime, "candle datetime");
}

function instrumentKey(value: unknown): string {
  if (!isRecord(value) || typeof value.symbol !== "string") {
    throw new Error("Schwab returned an invalid instrument");
  }
  const cusip = typeof value.cusip === "string" ? value.cusip : "";
  const assetType =
    typeof value.assetType === "string" ? value.assetType : "UNKNOWN";
  return `${value.symbol}\u0000${cusip}\u0000${assetType}`;
}

function positionKey(value: unknown): string {
  if (!isRecord(value) || !isRecord(value.instrument)) {
    throw new Error("Schwab returned an invalid position");
  }
  const symbol = value.instrument.symbol;
  const assetType = value.instrument.assetType;
  if (typeof symbol !== "string" || typeof assetType !== "string") {
    throw new Error("Schwab returned an invalid position instrument");
  }
  return `${assetType}\u0000${symbol}`;
}

function scalarKey(value: unknown, description: string): string {
  if (typeof value === "string" || typeof value === "number") {
    return String(value);
  }
  throw new Error(`Schwab returned an invalid ${description}`);
}

function encodeCursor(key: string): string {
  return `${CURSOR_PREFIX}${toBase64Url(utf8(key))}`;
}

function decodeCursor(cursor: string): string {
  if (!cursor.startsWith(CURSOR_PREFIX)) throw new Error("Invalid page cursor");
  try {
    return decodeUtf8(fromBase64Url(cursor.slice(CURSOR_PREFIX.length)));
  } catch {
    throw new Error("Invalid page cursor");
  }
}

function compareKeys(left: string, right: string): number {
  return left < right ? -1 : left > right ? 1 : 0;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function isUnknownArray(value: unknown): value is unknown[] {
  return Array.isArray(value);
}
