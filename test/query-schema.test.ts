import { describe, expect, it } from "vitest";
import { ordersQuerySchema, transactionsQuerySchema } from "../src/mcp/server";

describe("bounded historical query inputs", () => {
  it("rejects reversed order and transaction ranges", () => {
    expect(
      ordersQuerySchema.safeParse({
        fromEnteredTime: "2026-02-01T00:00:00Z",
        toEnteredTime: "2026-01-01T00:00:00Z",
      }).success,
    ).toBe(false);
    expect(
      transactionsQuerySchema.safeParse({
        accountHash: "allowed_hash",
        startDate: "2026-02-01T00:00:00Z",
        endDate: "2026-01-01T00:00:00Z",
        types: "TRADE",
      }).success,
    ).toBe(false);
  });

  it("rejects ranges over 366 days", () => {
    expect(
      ordersQuerySchema.safeParse({
        fromEnteredTime: "2024-01-01T00:00:00Z",
        toEnteredTime: "2026-01-01T00:00:00Z",
      }).success,
    ).toBe(false);
  });
});
