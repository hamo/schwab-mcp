import { describe, expect, it } from "vitest";
import { readJsonWithLimit, readTextWithLimit } from "../src/security/http";

describe("bounded remote responses", () => {
  it("reads a response inside the limit", async () => {
    await expect(
      readJsonWithLimit(Response.json({ ok: true }), 1_024),
    ).resolves.toEqual({ ok: true });
  });

  it("rejects a response larger than the byte limit", async () => {
    await expect(
      readTextWithLimit(new Response("x".repeat(100)), 50),
    ).rejects.toThrow("size limit");
  });
});
