import {
  constantTimeEqual,
  decodeUtf8,
  fromBase64,
  fromBase64Url,
  toBase64Url,
  utf8,
} from "./encoding";

export interface EncryptedValue {
  version: 1;
  iv: string;
  ciphertext: string;
}

export async function sha256(value: string): Promise<string> {
  return toBase64Url(await crypto.subtle.digest("SHA-256", utf8(value)));
}

export async function hmac(value: string, secret: string): Promise<string> {
  const key = await crypto.subtle.importKey(
    "raw",
    utf8(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"],
  );
  return toBase64Url(await crypto.subtle.sign("HMAC", key, utf8(value)));
}

export async function verifyHmac(
  value: string,
  signature: string,
  secret: string,
): Promise<boolean> {
  return constantTimeEqual(await hmac(value, secret), signature);
}

async function importAesKey(base64Key: string): Promise<CryptoKey> {
  const raw = fromBase64(base64Key);
  if (raw.byteLength !== 32) {
    throw new Error(
      "TOKEN_ENCRYPTION_KEY must contain exactly 32 base64-encoded bytes",
    );
  }
  return crypto.subtle.importKey("raw", raw, "AES-GCM", false, [
    "encrypt",
    "decrypt",
  ]);
}

export async function encryptJson(
  value: unknown,
  base64Key: string,
): Promise<EncryptedValue> {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ciphertext = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv },
    await importAesKey(base64Key),
    utf8(JSON.stringify(value)),
  );
  return {
    version: 1,
    iv: toBase64Url(iv),
    ciphertext: toBase64Url(ciphertext),
  };
}

export async function decryptJson<T>(
  encrypted: EncryptedValue,
  base64Key: string,
): Promise<T> {
  if (encrypted.version !== 1)
    throw new Error("Unsupported encrypted value version");
  const plaintext = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv: fromBase64Url(encrypted.iv) },
    await importAesKey(base64Key),
    fromBase64Url(encrypted.ciphertext),
  );
  return JSON.parse(decodeUtf8(plaintext)) as T;
}

export function canonicalJson(value: unknown): string {
  if (value === undefined) return "null";
  if (value === null || typeof value !== "object")
    return JSON.stringify(value) ?? "null";
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  const object = value as Record<string, unknown>;
  return `{${Object.keys(object)
    .sort()
    .map((key) => `${JSON.stringify(key)}:${canonicalJson(object[key])}`)
    .join(",")}}`;
}
