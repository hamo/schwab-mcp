export const DEFAULT_HTTP_TIMEOUT_MS = 15_000;

export async function fetchWithTimeout(
  input: RequestInfo | URL,
  init: RequestInit = {},
  fetcher: typeof fetch = fetch,
  timeoutMs = DEFAULT_HTTP_TIMEOUT_MS,
): Promise<Response> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    return await fetcher(input, { ...init, signal: controller.signal });
  } finally {
    clearTimeout(timer);
  }
}

export async function readTextWithLimit(
  response: Response,
  maxBytes: number,
): Promise<string> {
  const length = response.headers.get("content-length");
  if (length !== null && Number(length) > maxBytes) {
    throw new Error("Remote response exceeded the configured size limit");
  }
  if (!response.body) return "";

  const reader = response.body.getReader();
  const decoder = new TextDecoder();
  let size = 0;
  let text = "";
  while (true) {
    const { done, value } = await reader.read();
    if (done) break;
    size += value.byteLength;
    if (size > maxBytes) {
      await reader.cancel();
      throw new Error("Remote response exceeded the configured size limit");
    }
    text += decoder.decode(value, { stream: true });
  }
  return text + decoder.decode();
}

export async function readJsonWithLimit(
  response: Response,
  maxBytes: number,
): Promise<unknown> {
  return JSON.parse(await readTextWithLimit(response, maxBytes)) as unknown;
}
