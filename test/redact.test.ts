import { describe, expect, it } from "vitest";
import {
  redactAccountNumbers,
  sanitizeUserPreferences,
} from "../src/security/redact";

describe("account number redaction", () => {
  it("redacts nested account numbers but preserves account hashes", () => {
    expect(
      redactAccountNumbers({
        accountNumber: "123456789",
        order: { accountNumber: 123456789 },
        securitiesAccount: { accountId: 987654321, hashValue: "safe-hash" },
      }),
    ).toEqual({
      accountNumber: "••••6789",
      order: { accountNumber: "••••6789" },
      securitiesAccount: { accountId: "••••4321", hashValue: "safe-hash" },
    });
  });

  it("does not expose account or streamer identifiers from preferences", () => {
    expect(
      sanitizeUserPreferences({
        accounts: [{ accountNumber: "123", nickName: "private" }],
        streamerInfo: [
          {
            streamerSocketUrl: "wss://streamer.example",
            schwabClientCustomerId: "secret-customer-id",
          },
        ],
        offers: [{ level2Permissions: true, mktDataPermission: "NP" }],
      }),
    ).toEqual({
      streamingAvailable: true,
      offers: [{ level2Permissions: true, marketDataPermission: "NP" }],
    });
  });
});
