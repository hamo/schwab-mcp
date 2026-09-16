import { afterEach, describe, expect, it, vi } from "vitest";
import type { StoredSchwabSession } from "../src/schwab/types";
import type { Env } from "../src/types";
import type {
  AtomicStorage,
  AtomicTransaction,
} from "../src/storage/atomic-take";

vi.mock("cloudflare:workers", () => ({
  DurableObject: class {
    protected readonly ctx: DurableObjectState;
    protected readonly env: Env;

    constructor(ctx: DurableObjectState, env: Env) {
      this.ctx = ctx;
      this.env = env;
    }
  },
}));

import { SchwabTokenVault } from "../src/storage/token-vault";

class FakeStorage implements AtomicStorage, AtomicTransaction {
  readonly values = new Map<string, unknown>();
  private tail = Promise.resolve();
  private alarm: number | null = null;

  transaction<T>(
    callback: (transaction: AtomicTransaction) => Promise<T>,
  ): Promise<T> {
    const previous = this.tail;
    let release!: () => void;
    this.tail = new Promise<void>((resolve) => {
      release = resolve;
    });
    return previous.then(async () => {
      try {
        return await callback(this);
      } finally {
        release();
      }
    });
  }

  get<T>(key: string): Promise<T | undefined> {
    return Promise.resolve(this.values.get(key) as T | undefined);
  }

  put<T>(key: string, value: T): Promise<void> {
    this.values.set(key, value);
    return Promise.resolve();
  }

  delete(key: string): Promise<boolean> {
    return Promise.resolve(this.values.delete(key));
  }

  getAlarm(): Promise<number | null> {
    return Promise.resolve(this.alarm);
  }

  setAlarm(value: number): Promise<void> {
    this.alarm = value;
    return Promise.resolve();
  }
}

describe("Schwab token vault refresh concurrency", () => {
  afterEach(() => {
    vi.unstubAllGlobals();
    vi.restoreAllMocks();
  });

  it("coalesces concurrent refreshes for the same expired session", async () => {
    const { vault } = await createVault(expiredSession("old", 1));
    const remoteFetch = vi.fn(() =>
      Promise.resolve(
        Response.json({
          access_token: "refreshed-access",
          refresh_token: "refreshed-refresh",
          token_type: "Bearer",
          expires_in: 1_800,
        }),
      ),
    );
    vi.stubGlobal("fetch", remoteFetch);

    const responses = await Promise.all([access(vault), access(vault)]);
    expect(remoteFetch).toHaveBeenCalledTimes(1);
    await expectJson(responses[0], { accessToken: "refreshed-access" });
    await expectJson(responses[1], { accessToken: "refreshed-access" });
  });

  it("allows an approved preparation to be consumed only once", async () => {
    const { vault } = await createVault(activeSession("active", 1));
    const created = await vault.fetch(
      new Request("https://vault.internal/preparations", {
        method: "POST",
        body: JSON.stringify({
          action: {
            kind: "cancel",
            accountHash: "allowed_hash",
            orderId: "12345",
          },
        }),
      }),
    );
    expect(created.status).toBe(200);
    const preparation: unknown = await created.json();
    if (
      !isRecord(preparation) ||
      typeof preparation.id !== "string" ||
      typeof preparation.digest !== "string"
    ) {
      throw new Error("Expected a preparation response");
    }
    const preparationId = preparation.id;
    const preparationDigest = preparation.digest;
    expect(
      (
        await vault.fetch(
          new Request(
            `https://vault.internal/preparations/${preparationId}/approve`,
            { method: "POST" },
          ),
        )
      ).status,
    ).toBe(200);

    const execute = () =>
      vault.fetch(
        new Request(
          `https://vault.internal/preparations/${preparationId}/consume`,
          {
            method: "POST",
            body: JSON.stringify({ digest: preparationDigest }),
          },
        ),
      );
    const responses = await Promise.all([execute(), execute()]);
    expect(responses.map((response) => response.status).sort()).toEqual([
      200, 409,
    ]);
    expect(
      (
        await vault.fetch(
          new Request(
            `https://vault.internal/preparations/${preparationId}/approve`,
            { method: "POST" },
          ),
        )
      ).status,
    ).toBe(404);
  });

  it("does not overwrite a new login with an old refresh result", async () => {
    const { vault } = await createVault(expiredSession("old", 1));
    const pending = deferred<Response>();
    const remoteFetch = vi.fn(() => pending.promise);
    vi.stubGlobal("fetch", remoteFetch);

    const oldAccess = access(vault);
    await vi.waitFor(() => expect(remoteFetch).toHaveBeenCalledTimes(1));
    await store(vault, activeSession("new", 2));
    pending.resolve(
      Response.json({
        access_token: "stale-refreshed-access",
        refresh_token: "stale-refreshed-refresh",
        token_type: "Bearer",
        expires_in: 1_800,
      }),
    );

    await expectJson(await oldAccess, { accessToken: "new-access" });
    await expectJson(await access(vault), { accessToken: "new-access" });
  });

  it("does not delete a new login after an old invalid_grant", async () => {
    const { vault } = await createVault(expiredSession("old", 1));
    const pending = deferred<Response>();
    const remoteFetch = vi.fn(() => pending.promise);
    vi.stubGlobal("fetch", remoteFetch);

    const oldAccess = access(vault);
    await vi.waitFor(() => expect(remoteFetch).toHaveBeenCalledTimes(1));
    await store(vault, activeSession("new", 2));
    pending.resolve(
      Response.json(
        { error: "invalid_grant", error_description: "expired" },
        { status: 400 },
      ),
    );

    await expectJson(await oldAccess, { accessToken: "new-access" });
    await expectJson(await access(vault), { accessToken: "new-access" });
  });

  it("marks a rejected refresh token as requiring reauthorization", async () => {
    const { vault } = await createVault(expiredSession("expired", 1));
    const remoteFetch = vi.fn(() =>
      Promise.resolve(
        Response.json(
          { error: "invalid_client", error_description: "expired" },
          { status: 401 },
        ),
      ),
    );
    vi.stubGlobal("fetch", remoteFetch);

    const response = await access(vault);
    expect(response.status).toBe(401);
    await expect(response.json()).resolves.toEqual({
      error: "schwab_reauthorization_required",
    });
    await expectJson(await status(vault), {
      connected: false,
      reauthorizationRequired: true,
    });
    expect(remoteFetch).toHaveBeenCalledTimes(1);

    const retry = await access(vault);
    expect(retry.status).toBe(401);
    expect(remoteFetch).toHaveBeenCalledTimes(1);
  });

  it("clears the reauthorization marker only after a new session is stored", async () => {
    const { vault } = await createVault(expiredSession("expired", 1));
    vi.stubGlobal(
      "fetch",
      vi.fn(() =>
        Promise.resolve(
          Response.json({ error: "invalid_grant" }, { status: 400 }),
        ),
      ),
    );
    expect((await access(vault)).status).toBe(401);

    await store(vault, activeSession("new", 2));

    await expectJson(await status(vault), {
      connected: true,
      reauthorizationRequired: false,
    });
    await expectJson(await access(vault), { accessToken: "new-access" });
  });

  it("retains a session after a transient Schwab token endpoint failure", async () => {
    const { vault } = await createVault(expiredSession("temporary", 1));
    vi.spyOn(console, "error").mockImplementation(() => undefined);
    vi.stubGlobal(
      "fetch",
      vi.fn(() =>
        Promise.resolve(
          Response.json({ error: "server_error" }, { status: 503 }),
        ),
      ),
    );

    expect((await access(vault)).status).toBe(500);
    await expectJson(await status(vault), {
      connected: true,
      reauthorizationRequired: false,
    });
  });

  it("preserves a flow when the expected purpose does not match", async () => {
    const { vault } = await createVault(activeSession("active", 1));
    const id = crypto.randomUUID();
    const stored = await vault.fetch(
      new Request("https://vault.internal/flows", {
        method: "POST",
        body: JSON.stringify({
          id,
          value: { kind: "schwab-reauthorize-start" },
          expiresAt: Date.now() + 60_000,
        }),
      }),
    );
    expect(stored.status).toBe(200);

    const mismatch = await consumeFlow(vault, id, ["consent"]);
    expect(mismatch.status).toBe(409);
    await expect(mismatch.json()).resolves.toEqual({
      error: "flow_purpose_mismatch",
    });

    await expectJson(
      await consumeFlow(vault, id, ["schwab-reauthorize-start"]),
      { kind: "schwab-reauthorize-start" },
    );
    await expect(
      (await consumeFlow(vault, id, ["schwab-reauthorize-start"])).json(),
    ).resolves.toBeNull();
  });
});

async function createVault(initial: StoredSchwabSession): Promise<{
  vault: SchwabTokenVault;
  storage: FakeStorage;
}> {
  const storage = new FakeStorage();
  const ctx = { storage } as unknown as DurableObjectState;
  const env = {
    SCHWAB_ENVIRONMENT: "production",
    SCHWAB_CLIENT_ID: "client-id",
    SCHWAB_CLIENT_SECRET: "client-secret",
    TOKEN_ENCRYPTION_KEY: btoa("x".repeat(32)),
  } as Env;
  const vault = new SchwabTokenVault(ctx, env);
  await store(vault, initial);
  return { vault, storage };
}

function expiredSession(prefix: string, issuedAt: number): StoredSchwabSession {
  return {
    ...activeSession(prefix, issuedAt),
    accessExpiresAt: Date.now() - 1,
  };
}

function activeSession(prefix: string, issuedAt: number): StoredSchwabSession {
  return {
    accessToken: `${prefix}-access`,
    refreshToken: `${prefix}-refresh`,
    tokenType: "Bearer",
    accessExpiresAt: Date.now() + 30 * 60 * 1_000,
    issuedAt,
    accountHashes: ["allowed_hash"],
  };
}

function access(vault: SchwabTokenVault): Promise<Response> {
  return vault.fetch(
    new Request("https://vault.internal/access", { method: "POST" }),
  );
}

function status(vault: SchwabTokenVault): Promise<Response> {
  return vault.fetch(new Request("https://vault.internal/status"));
}

function consumeFlow(
  vault: SchwabTokenVault,
  id: string,
  expectedKinds: string[],
): Promise<Response> {
  return vault.fetch(
    new Request(`https://vault.internal/flows/${id}/consume`, {
      method: "POST",
      body: JSON.stringify({ expectedKinds }),
    }),
  );
}

async function store(
  vault: SchwabTokenVault,
  session: StoredSchwabSession,
): Promise<void> {
  const response = await vault.fetch(
    new Request("https://vault.internal/session", {
      method: "PUT",
      body: JSON.stringify(session),
    }),
  );
  expect(response.status).toBe(200);
}

async function expectJson(
  response: Response,
  expected: Record<string, unknown>,
): Promise<void> {
  expect(response.status).toBe(200);
  await expect(response.json()).resolves.toMatchObject(expected);
}

function deferred<T>(): {
  promise: Promise<T>;
  resolve: (value: T) => void;
} {
  let resolve!: (value: T) => void;
  const promise = new Promise<T>((innerResolve) => {
    resolve = innerResolve;
  });
  return { promise, resolve };
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}
