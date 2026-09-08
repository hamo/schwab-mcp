import {
  decodeUtf8,
  fromBase64Url,
  toBase64Url,
  utf8,
} from "../security/encoding";

const CURSOR_PREFIX = "v2.";

export function encodePageCursor(scope: string, key: string): string {
  return `${CURSOR_PREFIX}${toBase64Url(utf8(JSON.stringify({ scope, key })))}`;
}

export function decodePageCursor(cursor: string, scope: string): string {
  if (!cursor.startsWith(CURSOR_PREFIX)) throw new Error("Invalid page cursor");
  try {
    const value = JSON.parse(
      decodeUtf8(fromBase64Url(cursor.slice(CURSOR_PREFIX.length))),
    ) as unknown;
    if (
      !isRecord(value) ||
      typeof value.scope !== "string" ||
      typeof value.key !== "string"
    ) {
      throw new Error("Invalid page cursor");
    }
    if (value.scope !== scope) {
      throw new Error("Page cursor does not match this tool or query");
    }
    return value.key;
  } catch (error) {
    if (
      error instanceof Error &&
      error.message === "Page cursor does not match this tool or query"
    ) {
      throw error;
    }
    throw new Error("Invalid page cursor");
  }
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}
