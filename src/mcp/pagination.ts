export interface OutputPageOptions {
  outputMode: "paged" | "raw";
  outputOffset: number;
  outputLimit: number;
}

const MAX_PAGE_ITEMS_JSON_CHARACTERS = 80_000;

export function formatArrayPage(
  value: unknown,
  itemKey: string,
  options: OutputPageOptions,
): unknown {
  if (options.outputMode === "raw") return value;
  if (!isUnknownArray(value))
    throw new Error("Schwab returned an invalid list");
  return { source: "schwab", ...pageResult(itemKey, value, options) };
}

export function formatRecordPage(
  value: unknown,
  itemKey: string,
  options: OutputPageOptions,
): unknown {
  if (options.outputMode === "raw") return value;
  if (!isRecord(value)) throw new Error("Schwab returned an invalid record");
  const entries = Object.entries(value)
    .sort(([left], [right]) => left.localeCompare(right))
    .map(([key, item]) => ({ key, item }));
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
    ...pageResult("candles", candles ?? [], options),
  };
}

export function formatAllowedOrdersPage(
  value: unknown,
  options: OutputPageOptions,
): unknown {
  if (options.outputMode === "raw") return value;
  if (!isUnknownArray(value))
    throw new Error("Schwab returned invalid account orders");
  const orders: unknown[] = [];
  for (const accountResult of value) {
    if (
      !isRecord(accountResult) ||
      typeof accountResult.accountHash !== "string" ||
      !isUnknownArray(accountResult.orders)
    ) {
      throw new Error("Schwab returned invalid account orders");
    }
    for (const order of accountResult.orders) {
      orders.push({ accountHash: accountResult.accountHash, order });
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
    ...pageResult("positions", positions ?? [], options),
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
  const positions: unknown[] = [];
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
      positions.push({ accountHash: accountResult.accountHash, position });
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
  values: unknown[],
  options: OutputPageOptions,
): Record<string, unknown> {
  const requestedEnd = Math.min(
    options.outputOffset + options.outputLimit,
    values.length,
  );
  const selected: unknown[] = [];
  let serializedCharacters = 0;
  for (let index = options.outputOffset; index < requestedEnd; index += 1) {
    const candidate = values[index];
    const size = JSON.stringify(candidate)?.length ?? 4;
    if (
      selected.length > 0 &&
      serializedCharacters + size > MAX_PAGE_ITEMS_JSON_CHARACTERS
    ) {
      break;
    }
    selected.push(candidate);
    serializedCharacters += size;
  }
  const end = options.outputOffset + selected.length;
  return {
    page: {
      offset: options.outputOffset,
      limit: options.outputLimit,
      returned: selected.length,
      totalItems: values.length,
      nextOffset: end < values.length ? end : null,
    },
    [itemKey]: selected,
  };
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function isUnknownArray(value: unknown): value is unknown[] {
  return Array.isArray(value);
}
