import { describe, expect, it } from "vitest";
import { reviewAction } from "../src/schwab/order-review";

describe("trade approval review", () => {
  it("shows the complete action represented by the digest", async () => {
    const action = {
      kind: "place" as const,
      accountHash: "account_hash",
      order: {
        session: "NORMAL",
        note: "tail-marker",
      },
    };
    const reviewed = await reviewAction(action);
    expect(reviewed.summary).toContain("tail-marker");
    expect(reviewed.summary).not.toContain("truncated");
    expect(reviewed.digest).toHaveLength(43);
  });

  it("rejects an action too large to review in full", async () => {
    await expect(
      reviewAction({
        kind: "place",
        accountHash: "account_hash",
        order: { note: "x".repeat(20_000) },
      }),
    ).rejects.toThrow("approval limit");
  });

  it("renders invisible formatting characters as explicit escapes", async () => {
    const reviewed = await reviewAction({
      kind: "place",
      accountHash: "account_hash",
      order: { destinationLinkName: "route\u202eABC\u2066" },
    });

    expect(reviewed.summary).toContain("route\\u202eABC\\u2066");
    expect(reviewed.summary).not.toContain("\u202e");
    expect(reviewed.summary).not.toContain("\u2066");
  });
});
