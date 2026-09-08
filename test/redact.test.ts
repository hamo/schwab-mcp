import { describe, expect, it } from "vitest";
import { redactAccountNumbers } from "../src/security/redact";

describe("account number redaction", () => {
  it("redacts nested account numbers but preserves account hashes", () => {
    expect(
      redactAccountNumbers({
        accountNumber: "123456789",
        securitiesAccount: { accountId: "987654321", hashValue: "safe-hash" },
      }),
    ).toEqual({
      accountNumber: "••••6789",
      securitiesAccount: { accountId: "••••4321", hashValue: "safe-hash" },
    });
  });
});
