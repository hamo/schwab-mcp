import { DurableObject } from "cloudflare:workers";
import { decryptJson, encryptJson } from "../security/crypto";
import {
  filterAllowedAccountHashes,
  refreshSchwabToken,
  shouldForgetSchwabSession,
} from "../schwab/client";
import { reviewAction } from "../schwab/order-review";
import type {
  PendingAction,
  PendingTrade,
  StoredSchwabSession,
} from "../schwab/types";
import type { Env } from "../types";

const TOKEN_KEY = "schwab-session";
const PREPARATION_TTL_MS = 10 * 60 * 1_000;
const MAX_FLOW_TTL_MS = 10 * 60 * 1_000;

export class SchwabTokenVault extends DurableObject<Env> {
  async fetch(request: Request): Promise<Response> {
    const url = new URL(request.url);
    try {
      if (request.method === "GET" && url.pathname === "/status")
        return this.status();
      if (request.method === "PUT" && url.pathname === "/session")
        return this.storeSession(request);
      if (request.method === "DELETE" && url.pathname === "/session")
        return this.deleteSession();
      if (request.method === "POST" && url.pathname === "/access")
        return this.accessSession();
      if (request.method === "POST" && url.pathname === "/preparations") {
        return this.createPreparation(request);
      }
      if (request.method === "POST" && url.pathname === "/flows") {
        return this.storeFlow(request);
      }

      const flowMatch = /^\/flows\/([0-9a-f-]{36})\/consume$/.exec(
        url.pathname,
      );
      if (request.method === "POST" && flowMatch?.[1]) {
        return this.consumeFlow(flowMatch[1]);
      }

      const preparationMatch =
        /^\/preparations\/([0-9a-f-]+)(?:\/(approve|consume))?$/.exec(
          url.pathname,
        );
      if (preparationMatch?.[1]) {
        const id = preparationMatch[1];
        if (request.method === "GET" && !preparationMatch[2])
          return this.getPreparation(id);
        if (request.method === "POST" && preparationMatch[2] === "approve") {
          return this.approvePreparation(id);
        }
        if (request.method === "POST" && preparationMatch[2] === "consume") {
          return this.consumePreparation(id, request);
        }
      }
      return Response.json({ error: "not_found" }, { status: 404 });
    } catch (error) {
      console.error(
        "Token vault operation failed",
        error instanceof Error ? error.name : "unknown",
      );
      return Response.json(
        { error: "vault_operation_failed" },
        { status: 500 },
      );
    }
  }

  private async status(): Promise<Response> {
    return Response.json({
      connected: (await this.ctx.storage.get(TOKEN_KEY)) !== undefined,
    });
  }

  private async storeSession(request: Request): Promise<Response> {
    const value = await readJson(request);
    if (!isStoredSession(value))
      return Response.json({ error: "invalid_session" }, { status: 400 });
    await this.ctx.storage.put(
      TOKEN_KEY,
      await encryptJson(value, this.env.TOKEN_ENCRYPTION_KEY),
    );
    return Response.json({
      connected: true,
      accountCount: value.accountHashes.length,
    });
  }

  private async deleteSession(): Promise<Response> {
    await this.ctx.storage.delete(TOKEN_KEY);
    return Response.json({ connected: false });
  }

  private async accessSession(): Promise<Response> {
    let session = await this.loadSession();
    if (!session)
      return Response.json({ error: "schwab_not_connected" }, { status: 401 });
    if (session.accessExpiresAt <= Date.now() + 120_000) {
      let refreshed;
      try {
        refreshed = await refreshSchwabToken(this.env, session.refreshToken);
      } catch (error) {
        if (shouldForgetSchwabSession(error)) {
          await this.ctx.storage.delete(TOKEN_KEY);
        }
        throw error;
      }
      session = { ...refreshed, accountHashes: session.accountHashes };
      await this.ctx.storage.put(
        TOKEN_KEY,
        await encryptJson(session, this.env.TOKEN_ENCRYPTION_KEY),
      );
    }
    const accountHashes = await filterAllowedAccountHashes(
      this.env,
      session.accountHashes,
    );
    return Response.json({
      accessToken: session.accessToken,
      accountHashes,
    });
  }

  private async createPreparation(request: Request): Promise<Response> {
    const input = await readJson(request);
    if (!isPreparationInput(input)) {
      return Response.json({ error: "invalid_preparation" }, { status: 400 });
    }
    const session = await this.loadSession();
    const accountHashes = session
      ? await filterAllowedAccountHashes(this.env, session.accountHashes)
      : [];
    if (!session || !accountHashes.includes(input.action.accountHash)) {
      return Response.json({ error: "account_not_allowed" }, { status: 403 });
    }
    const reviewed = await reviewAction(input.action);
    const createdAt = Date.now();
    const pending: PendingTrade = {
      id: crypto.randomUUID(),
      digest: reviewed.digest,
      summary: reviewed.summary,
      action: input.action,
      createdAt,
      expiresAt: createdAt + PREPARATION_TTL_MS,
    };
    await this.ctx.storage.put(
      this.preparationKey(pending.id),
      await encryptJson(pending, this.env.TOKEN_ENCRYPTION_KEY),
    );
    await this.scheduleCleanup(pending.expiresAt);
    return Response.json({
      id: pending.id,
      digest: pending.digest,
      summary: pending.summary,
      expiresAt: pending.expiresAt,
    });
  }

  private async getPreparation(id: string): Promise<Response> {
    const pending = await this.loadPreparation(id);
    if (!pending || pending.expiresAt <= Date.now()) {
      return Response.json({ error: "preparation_not_found" }, { status: 404 });
    }
    return Response.json({
      id: pending.id,
      digest: pending.digest,
      summary: pending.summary,
      expiresAt: pending.expiresAt,
      approved: pending.approvedAt !== undefined,
    });
  }

  private async approvePreparation(id: string): Promise<Response> {
    const pending = await this.loadPreparation(id);
    if (!pending || pending.expiresAt <= Date.now()) {
      return Response.json({ error: "preparation_not_found" }, { status: 404 });
    }
    const approved: PendingTrade = { ...pending, approvedAt: Date.now() };
    await this.ctx.storage.put(
      this.preparationKey(id),
      await encryptJson(approved, this.env.TOKEN_ENCRYPTION_KEY),
    );
    return Response.json({ approved: true });
  }

  private async consumePreparation(
    id: string,
    request: Request,
  ): Promise<Response> {
    const input = await readJson(request);
    const pending = await this.loadPreparation(id);
    if (
      !pending ||
      pending.expiresAt <= Date.now() ||
      pending.approvedAt === undefined ||
      !isRecord(input) ||
      input.digest !== pending.digest
    ) {
      return Response.json(
        { error: "preparation_not_approved" },
        { status: 409 },
      );
    }
    await this.ctx.storage.delete(this.preparationKey(id));
    return Response.json(pending.action);
  }

  private async storeFlow(request: Request): Promise<Response> {
    const input = await readJson(request);
    const now = Date.now();
    if (
      !isRecord(input) ||
      typeof input.id !== "string" ||
      !isUuid(input.id) ||
      !isRecord(input.value) ||
      typeof input.expiresAt !== "number" ||
      !Number.isFinite(input.expiresAt) ||
      input.expiresAt <= now ||
      input.expiresAt > now + MAX_FLOW_TTL_MS
    ) {
      return Response.json({ error: "invalid_flow" }, { status: 400 });
    }
    const flow: StoredFlow = {
      value: input.value,
      expiresAt: input.expiresAt,
    };
    await this.ctx.storage.put(
      this.flowKey(input.id),
      await encryptJson(flow, this.env.TOKEN_ENCRYPTION_KEY),
    );
    await this.scheduleCleanup(flow.expiresAt);
    return Response.json({ stored: true });
  }

  private async consumeFlow(id: string): Promise<Response> {
    const key = this.flowKey(id);
    const encrypted = await this.ctx.storage.transaction(
      async (transaction) => {
        const value = await transaction.get<ReturnTypeShape>(key);
        if (value !== undefined) await transaction.delete(key);
        return value;
      },
    );
    if (!encrypted) return Response.json(null);
    const flow = await decryptJson<StoredFlow>(
      encrypted,
      this.env.TOKEN_ENCRYPTION_KEY,
    );
    if (!isStoredFlow(flow) || flow.expiresAt <= Date.now()) {
      return Response.json(null);
    }
    return Response.json(flow.value);
  }

  private async loadSession(): Promise<StoredSchwabSession | null> {
    const encrypted = await this.ctx.storage.get<ReturnTypeShape>(TOKEN_KEY);
    return encrypted
      ? decryptJson<StoredSchwabSession>(
          encrypted,
          this.env.TOKEN_ENCRYPTION_KEY,
        )
      : null;
  }

  private async loadPreparation(id: string): Promise<PendingTrade | null> {
    const encrypted = await this.ctx.storage.get<ReturnTypeShape>(
      this.preparationKey(id),
    );
    return encrypted
      ? decryptJson<PendingTrade>(encrypted, this.env.TOKEN_ENCRYPTION_KEY)
      : null;
  }

  private preparationKey(id: string): string {
    return `preparation:${id}`;
  }

  private flowKey(id: string): string {
    return `flow:${id}`;
  }

  async alarm(): Promise<void> {
    const values = await this.ctx.storage.list<ReturnTypeShape>({
      prefix: "preparation:",
    });
    const now = Date.now();
    let nextExpiration: number | null = null;
    for (const [key, encrypted] of values) {
      const pending = await decryptJson<PendingTrade>(
        encrypted,
        this.env.TOKEN_ENCRYPTION_KEY,
      );
      if (pending.expiresAt <= now) {
        await this.ctx.storage.delete(key);
      } else if (
        nextExpiration === null ||
        pending.expiresAt < nextExpiration
      ) {
        nextExpiration = pending.expiresAt;
      }
    }
    const flows = await this.ctx.storage.list<ReturnTypeShape>({
      prefix: "flow:",
    });
    for (const [key, encrypted] of flows) {
      const flow = await decryptJson<StoredFlow>(
        encrypted,
        this.env.TOKEN_ENCRYPTION_KEY,
      );
      if (flow.expiresAt <= now) {
        await this.ctx.storage.delete(key);
      } else if (nextExpiration === null || flow.expiresAt < nextExpiration) {
        nextExpiration = flow.expiresAt;
      }
    }
    if (nextExpiration !== null)
      await this.ctx.storage.setAlarm(nextExpiration);
  }

  private async scheduleCleanup(expiresAt: number): Promise<void> {
    const current = await this.ctx.storage.getAlarm();
    if (current === null || expiresAt < current)
      await this.ctx.storage.setAlarm(expiresAt);
  }
}

type ReturnTypeShape = Awaited<ReturnType<typeof encryptJson>>;

interface StoredFlow {
  value: Record<string, unknown>;
  expiresAt: number;
}

function isStoredSession(value: unknown): value is StoredSchwabSession {
  return (
    isRecord(value) &&
    typeof value.accessToken === "string" &&
    typeof value.refreshToken === "string" &&
    typeof value.tokenType === "string" &&
    typeof value.accessExpiresAt === "number" &&
    typeof value.issuedAt === "number" &&
    Array.isArray(value.accountHashes) &&
    value.accountHashes.length > 0 &&
    value.accountHashes.length <= 20 &&
    value.accountHashes.every(
      (hash) =>
        typeof hash === "string" &&
        hash.length >= 8 &&
        hash.length <= 128 &&
        /^[A-Za-z0-9_-]+$/.test(hash),
    ) &&
    new Set(value.accountHashes).size === value.accountHashes.length
  );
}

async function readJson(request: Request): Promise<unknown> {
  return JSON.parse(await request.text()) as unknown;
}

function isPreparationInput(value: unknown): value is {
  action: PendingAction;
} {
  return isRecord(value) && isPendingAction(value.action);
}

function isPendingAction(value: unknown): value is PendingAction {
  if (!isRecord(value) || typeof value.accountHash !== "string") return false;
  if (value.kind === "place") return isRecord(value.order);
  if (value.kind === "replace") {
    return typeof value.orderId === "string" && isRecord(value.order);
  }
  return value.kind === "cancel" && typeof value.orderId === "string";
}

function isStoredFlow(value: unknown): value is StoredFlow {
  return (
    isRecord(value) &&
    isRecord(value.value) &&
    typeof value.expiresAt === "number" &&
    Number.isFinite(value.expiresAt)
  );
}

function isUuid(value: string): boolean {
  return /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(
    value,
  );
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}
