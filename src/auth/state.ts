import type { AuthRequest } from "@cloudflare/workers-oauth-provider";
import type { AccessIdentity } from "../types";
import { hmac, verifyHmac } from "../security/crypto";
import {
  FlowPurposeMismatchError,
  type FlowStateStore,
} from "../storage/vault-client";

export const STATE_TTL_SECONDS = 600;

export interface ConsentState {
  kind: "consent";
  oauthRequest: AuthRequest;
  csrf: string;
}

export interface AccessMcpState {
  kind: "access-mcp";
  oauthRequest: AuthRequest;
  codeVerifier: string;
  nonce: string;
}

export interface AccessTradeState {
  kind: "access-trade";
  preparationId: string;
  codeVerifier: string;
  nonce: string;
}

export interface SchwabReauthorizeStartState {
  kind: "schwab-reauthorize-start";
}

export interface AccessSchwabReauthorizeState {
  kind: "access-schwab-reauthorize";
  codeVerifier: string;
  nonce: string;
}

export interface SchwabState {
  kind: "schwab";
  oauthRequest: AuthRequest;
  identity: AccessIdentity;
}

export interface SchwabReauthorizeState {
  kind: "schwab-reauthorize";
  identity: AccessIdentity;
}

export interface TradeApprovalState {
  kind: "trade-approval";
  preparationId: string;
  identity: AccessIdentity;
  csrf: string;
}

export type StoredState =
  | ConsentState
  | AccessMcpState
  | AccessTradeState
  | SchwabReauthorizeStartState
  | AccessSchwabReauthorizeState
  | SchwabState
  | SchwabReauthorizeState
  | TradeApprovalState;

export async function createState(
  store: FlowStateStore,
  value: StoredState,
  signingKey: string,
): Promise<string> {
  const id = crypto.randomUUID();
  const signature = await hmac(id, signingKey);
  await store.storeFlow(id, value, Date.now() + STATE_TTL_SECONDS * 1_000);
  return `${id}.${signature}`;
}

export async function consumeState<T extends StoredState["kind"]>(
  store: FlowStateStore,
  token: string | null,
  expectedKind: T | readonly T[],
  signingKey: string,
): Promise<Extract<StoredState, { kind: T }>> {
  const id = await verifyStateToken(token, signingKey);
  const allowedKinds: readonly StoredState["kind"][] = Array.isArray(
    expectedKind,
  )
    ? expectedKind
    : [expectedKind];
  let raw: unknown;
  try {
    raw = await store.consumeFlow(id, allowedKinds);
  } catch (error) {
    if (error instanceof FlowPurposeMismatchError) {
      throw new FlowError("State purpose mismatch");
    }
    throw error;
  }
  if (!isRecord(raw) || typeof raw.kind !== "string") {
    throw new FlowError("State expired, invalid, or already used");
  }
  const value = raw as unknown as StoredState;
  if (!allowedKinds.includes(value.kind)) {
    throw new Error("Token vault returned an unexpected flow purpose");
  }
  return value as Extract<StoredState, { kind: T }>;
}

export async function verifyStateToken(
  token: string | null,
  signingKey: string,
): Promise<string> {
  if (!token) throw new FlowError("Missing state");
  if (
    !/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\.[A-Za-z0-9_-]{43}$/i.test(
      token,
    )
  ) {
    throw new FlowError("Invalid state");
  }
  const separator = token.lastIndexOf(".");
  if (separator < 1) throw new FlowError("Invalid state");
  const id = token.slice(0, separator);
  const signature = token.slice(separator + 1);
  if (!(await verifyHmac(id, signature, signingKey)))
    throw new FlowError("Invalid state");
  return id;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

export class FlowError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "FlowError";
  }
}
