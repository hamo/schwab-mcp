import { describe, expect, it } from "vitest";
import { consumeState, createState } from "../src/auth/state";

class FakeKv {
  readonly values = new Map<string, string>();

  put(key: string, value: string): Promise<void> {
    this.values.set(key, value);
    return Promise.resolve();
  }

  get(key: string): Promise<string | null> {
    return Promise.resolve(this.values.get(key) ?? null);
  }

  delete(key: string): Promise<void> {
    this.values.delete(key);
    return Promise.resolve();
  }
}

describe("OAuth flow state", () => {
  it("is signed, purpose-bound, and one-time", async () => {
    const kv = new FakeKv() as unknown as KVNamespace;
    const token = await createState(
      kv,
      {
        kind: "consent",
        csrf: "csrf",
        oauthRequest: {
          responseType: "code",
          clientId: "client",
          redirectUri: "https://client.test/callback",
          scope: ["mcp:read"],
          state: "client-state",
        },
      },
      "state-secret",
    );
    await expect(
      consumeState(kv, token, "consent", "state-secret"),
    ).resolves.toMatchObject({
      kind: "consent",
    });
    await expect(
      consumeState(kv, token, "consent", "state-secret"),
    ).rejects.toThrow("already used");
  });
});
