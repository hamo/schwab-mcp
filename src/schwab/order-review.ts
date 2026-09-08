import { canonicalJson, sha256 } from "../security/crypto";
import { makeFormattingCharactersVisible } from "../security/display";
import { utf8 } from "../security/encoding";
import type { PendingAction } from "./types";

export const MAX_REVIEWED_ACTION_BYTES = 16_384;

export interface ReviewedAction {
  digest: string;
  summary: string;
}

export async function reviewAction(
  action: PendingAction,
): Promise<ReviewedAction> {
  const canonical = canonicalJson(action);
  if (utf8(canonical).byteLength > MAX_REVIEWED_ACTION_BYTES) {
    throw new Error(
      `Order action exceeds the ${MAX_REVIEWED_ACTION_BYTES}-byte approval limit`,
    );
  }
  return {
    digest: await sha256(canonical),
    summary: makeFormattingCharactersVisible(JSON.stringify(action, null, 2)),
  };
}
