import { describe, expect, it } from "vitest";
import {
  canonicalJson,
  decryptJson,
  encryptJson,
  hmac,
  verifyHmac,
} from "../src/security/crypto";

function testKey(): string {
  const bytes = new Uint8Array(32);
  bytes.fill(7);
  return btoa(String.fromCharCode(...bytes));
}

describe("encrypted storage", () => {
  it("round-trips data without exposing plaintext", async () => {
    const value = { accessToken: "secret-token", accountHashes: ["hash"] };
    const encrypted = await encryptJson(value, testKey());
    expect(JSON.stringify(encrypted)).not.toContain("secret-token");
    await expect(decryptJson(encrypted, testKey())).resolves.toEqual(value);
  });

  it("rejects tampered state signatures", async () => {
    const signature = await hmac("state", "signing-key");
    await expect(verifyHmac("state", signature, "signing-key")).resolves.toBe(
      true,
    );
    await expect(
      verifyHmac("tampered", signature, "signing-key"),
    ).resolves.toBe(false);
  });

  it("canonicalizes object key order", () => {
    expect(canonicalJson({ z: 1, a: { y: 2, x: 3 } })).toBe(
      canonicalJson({ a: { x: 3, y: 2 }, z: 1 }),
    );
  });
});
