import type { PendingAction, StoredSchwabSession } from "../schwab/types";
import type { Env } from "../types";

export interface AccessSession {
  accessToken: string;
  accountHashes: string[];
}

export interface PreparationSummary {
  id: string;
  digest: string;
  summary: string;
  expiresAt: number;
  approved?: boolean;
}

export class VaultClient {
  private readonly stub: DurableObjectStub;

  constructor(env: Pick<Env, "TOKEN_VAULT">) {
    this.stub = env.TOKEN_VAULT.get(env.TOKEN_VAULT.idFromName("owner"));
  }

  status(): Promise<{ connected: boolean }> {
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
