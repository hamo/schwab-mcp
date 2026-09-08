export interface SchwabTokenResponse {
  accessToken: string;
  refreshToken: string;
  tokenType: string;
  scope?: string;
  accessExpiresAt: number;
  issuedAt: number;
}

export interface StoredSchwabSession extends SchwabTokenResponse {
  accountHashes: string[];
}

export type PendingAction =
  | { kind: "place"; accountHash: string; order: Record<string, unknown> }
  | {
      kind: "replace";
      accountHash: string;
      orderId: string;
      order: Record<string, unknown>;
    }
  | { kind: "cancel"; accountHash: string; orderId: string };

export interface PendingTrade {
  id: string;
  digest: string;
  summary: string;
  action: PendingAction;
  createdAt: number;
  expiresAt: number;
  approvedAt?: number;
}
