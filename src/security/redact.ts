const ACCOUNT_KEYS = new Set(["accountNumber", "accountId"]);

export function redactAccountNumbers(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(redactAccountNumbers);
  if (!value || typeof value !== "object") return value;
  const output: Record<string, unknown> = {};
  for (const [key, child] of Object.entries(value as Record<string, unknown>)) {
    if (
      ACCOUNT_KEYS.has(key) &&
      (typeof child === "string" || typeof child === "number")
    ) {
      const accountNumber = String(child);
      output[key] =
        accountNumber.length <= 4 ? "••••" : `••••${accountNumber.slice(-4)}`;
    } else {
      output[key] = redactAccountNumbers(child);
    }
  }
  return output;
}

export function sanitizeUserPreferences(value: unknown): {
  streamingAvailable: boolean;
  offers: Array<{
    level2Permissions?: boolean;
    marketDataPermission?: string;
  }>;
} {
  if (!isRecord(value)) return { streamingAvailable: false, offers: [] };
  const streamingAvailable =
    Array.isArray(value.streamerInfo) && value.streamerInfo.length > 0;
  const offers = Array.isArray(value.offers)
    ? value.offers.filter(isRecord).map((offer) => ({
        ...(typeof offer.level2Permissions === "boolean"
          ? { level2Permissions: offer.level2Permissions }
          : {}),
        ...(typeof offer.mktDataPermission === "string"
          ? { marketDataPermission: offer.mktDataPermission }
          : {}),
      }))
    : [];
  return { streamingAvailable, offers };
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}
