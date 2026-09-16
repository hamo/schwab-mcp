import type { PendingAction, StoredSchwabSession } from "../schwab/types";
import type { Env } from "../types";

export interface AccessSession {
  accessToken: string;
  accountHashes: string[];
}

export interface VaultStatus {
  connected: boolean;
  reauthorizationRequired: boolean;
}

export interface PreparationSummary {
  id: string;
  digest: string;
  summary: string;
  expiresAt: number;
  approved?: boolean;
}

export interface FlowStateStore {
  storeFlow(id: string, value: unknown, expiresAt: number): Promise<void>;
  consumeFlow(id: string, expectedKinds: readonly string[]): Promise<unknown>;
}

export class FlowPurposeMismatchError extends Error {
  constructor() {
    super("Flow purpose mismatch");
    this.name = "FlowPurposeMismatchError";
  }
}

export class VaultClient implements FlowStateStore {
  private readonly stub: DurableObjectStub;

  constructor(env: Pick<Env, "TOKEN_VAULT">) {
    this.stub = env.TOKEN_VAULT.get(env.TOKEN_VAULT.idFromName("owner"));
  }

  status(): Promise<VaultStatus> {
    return this.request("/status");
  }

  storeSession(
    session: StoredSchwabSession,
  ): Promise<{ connected: boolean; accountCount: number }> {
    return this.request("/session", "PUT", session);
  }

  accessSession(): Promise<AccessSession> {
    return this.request("/access", "POST");
  }

  createPreparation(action: PendingAction): Promise<PreparationSummary> {
    return this.request("/preparations", "POST", { action });
  }

  getPreparation(id: string): Promise<PreparationSummary> {
    return this.request(`/preparations/${encodeURIComponent(id)}`);
  }

  approvePreparation(id: string): Promise<{ approved: boolean }> {
    return this.request(
      `/preparations/${encodeURIComponent(id)}/approve`,
      "POST",
    );
  }

  consumePreparation(id: string, digest: string): Promise<PendingAction> {
    return this.request(
      `/preparations/${encodeURIComponent(id)}/consume`,
      "POST",
      { digest },
    );
  }

  async storeFlow(
    id: string,
    value: unknown,
    expiresAt: number,
  ): Promise<void> {
    await this.request("/flows", "POST", { id, value, expiresAt });
  }

  async consumeFlow(
    id: string,
    expectedKinds: readonly string[],
  ): Promise<unknown> {
    const response = await this.stub.fetch(
      `https://vault.internal/flows/${encodeURIComponent(id)}/consume`,
      {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ expectedKinds }),
      },
    );
    if (response.status === 409) {
      const error = (await response.json().catch(() => ({}))) as {
        error?: string;
      };
      if (error.error === "flow_purpose_mismatch") {
        throw new FlowPurposeMismatchError();
      }
      throw new Error("Token vault request failed (409)");
    }
    return this.readResponse(response);
  }

  private async request<T>(
    path: string,
    method = "GET",
    body?: unknown,
  ): Promise<T> {
    const response = await this.stub.fetch(`https://vault.internal${path}`, {
      method,
      headers: { "content-type": "application/json" },
      ...(body !== undefined ? { body: JSON.stringify(body) } : {}),
    });
    return this.readResponse(response);
  }

  private async readResponse<T>(response: Response): Promise<T> {
    if (!response.ok) {
      const error = (await response.json().catch(() => ({}))) as {
        error?: string;
      };
      throw new Error(
        error.error ?? `Token vault request failed (${response.status})`,
      );
    }
    return JSON.parse(await response.text()) as T;
  }
}
