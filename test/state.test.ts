import { describe, expect, it } from "vitest";
import { consumeState, createState } from "../src/auth/state";

class FakeFlowStore {
  readonly values = new Map<string, { value: unknown; expiresAt: number }>();

  storeFlow(id: string, value: unknown, expiresAt: number): Promise<void> {
    this.values.set(id, { value, expiresAt });
    return Promise.resolve();
  }

  consumeFlow(id: string): Promise<unknown> {
    const stored = this.values.get(id);
    this.values.delete(id);
    return Promise.resolve(
      stored && stored.expiresAt > Date.now() ? stored.value : null,
    );
  }
}

describe("OAuth flow state", () => {
  it("is signed, purpose-bound, and one-time", async () => {
    const store = new FakeFlowStore();
    const token = await createState(
      store,
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
      consumeState(store, token, "consent", "state-secret"),
    ).resolves.toMatchObject({
      kind: "consent",
    });
    await expect(
      consumeState(store, token, "consent", "state-secret"),
    ).rejects.toThrow("already used");
  });

  it("rejects oversized or malformed state before reading storage", async () => {
    const store = new FakeFlowStore();
    await expect(
      consumeState(store, `not-a-uuid.${"a".repeat(43)}`, "consent", "secret"),
    ).rejects.toThrow("Invalid state");
  });

  it("allows only one concurrent consumer", async () => {
    const store = new FakeFlowStore();
    const token = await createState(
      store,
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
    const outcomes = await Promise.allSettled([
      consumeState(store, token, "consent", "state-secret"),
      consumeState(store, token, "consent", "state-secret"),
    ]);
    expect(
      outcomes.filter((outcome) => outcome.status === "fulfilled"),
    ).toHaveLength(1);
  });
});
