const ACCOUNT_KEYS = new Set(["accountNumber", "accountId"]);

export function redactAccountNumbers(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(redactAccountNumbers);
  if (!value || typeof value !== "object") return value;
  const output: Record<string, unknown> = {};
  for (const [key, child] of Object.entries(value as Record<string, unknown>)) {
    if (ACCOUNT_KEYS.has(key) && typeof child === "string") {
      output[key] = child.length <= 4 ? "••••" : `••••${child.slice(-4)}`;
    } else {
      output[key] = redactAccountNumbers(child);
    }
  }
  return output;
}
