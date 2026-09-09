import { describe, expect, it } from "vitest";
import { withAuthorizationErrorBoundary } from "../src/auth/error-boundary";
import { FlowError } from "../src/auth/state";

describe("authorization handler", () => {
  it("turns asynchronous flow errors into a safe response", async () => {
    const response = await withAuthorizationErrorBoundary(async () => {
      await Promise.resolve();
      throw new FlowError("State expired, invalid, or already used");
    });

    expect(response.status).toBe(400);
    expect(await response.text()).toContain(
      "State expired, invalid, or already used",
    );
  });
});
