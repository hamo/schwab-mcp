import type { AuthRequest } from "@cloudflare/workers-oauth-provider";
import type { AccessIdentity } from "../types";
import { hmac, verifyHmac } from "../security/crypto";

const STATE_TTL_SECONDS = 600;

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

export interface SchwabState {
  kind: "schwab";
  oauthRequest: AuthRequest;
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
  | SchwabState
  | TradeApprovalState;

export async function createState(
  kv: KVNamespace,
  value: StoredState,
  signingKey: string,
): Promise<string> {
  const id = crypto.randomUUID();
  const signature = await hmac(id, signingKey);
  await kv.put(`flow:${id}`, JSON.stringify(value), {
    expirationTtl: STATE_TTL_SECONDS,
  });
  return `${id}.${signature}`;
}

export async function consumeState<T extends StoredState["kind"]>(
  kv: KVNamespace,
  token: string | null,
  expectedKind: T | readonly T[],
  signingKey: string,
): Promise<Extract<StoredState, { kind: T }>> {
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

  const key = `flow:${id}`;
  const raw = await kv.get(key);
  if (!raw) throw new FlowError("State expired or already used");
  await kv.delete(key);

  let value: StoredState;
  try {
    value = JSON.parse(raw) as StoredState;
  } catch {
    throw new FlowError("Invalid stored state");
  }
  const allowedKinds: readonly StoredState["kind"][] = Array.isArray(
    expectedKind,
  )
    ? expectedKind
    : [expectedKind];
  if (!allowedKinds.includes(value.kind))
    throw new FlowError("State purpose mismatch");
  return value as Extract<StoredState, { kind: T }>;
}

export class FlowError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "FlowError";
  }
}
