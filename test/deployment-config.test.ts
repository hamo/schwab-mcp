import { describe, expect, it } from "vitest";
import liveSource from "../wrangler.live.jsonc?raw";
import previewSource from "../wrangler.preview.jsonc?raw";
import readonlySource from "../wrangler.jsonc?raw";

interface DeploymentConfig {
  name: string;
  compatibility_flags?: string[];
  workers_dev?: boolean;
  vars: { TRADING_MODE: string };
  observability?: { redact_query_string?: boolean };
}

const deployments = [
  { source: readonlySource, mode: "disabled" },
  { source: previewSource, mode: "preview" },
  { source: liveSource, mode: "live" },
] as const;

describe("deployment configuration security", () => {
  it.each(deployments)(
    "keeps CIMD SSRF protection and query-string redaction in $mode mode",
    ({ source, mode }) => {
      const config = parseJsonc(source);
      expect(config.vars.TRADING_MODE).toBe(mode);
      expect(config.compatibility_flags).toContain(
        "global_fetch_strictly_public",
      );
      expect(config.compatibility_flags).toContain("disallow_importable_env");
      expect(config.workers_dev).toBe(false);
      expect(config.observability?.redact_query_string).toBe(true);
    },
  );

  it("uses distinct Worker names for each trading boundary", () => {
    const names = deployments.map(({ source }) => parseJsonc(source).name);
    expect(new Set(names).size).toBe(deployments.length);
  });
});

function parseJsonc(source: string): DeploymentConfig {
  return JSON.parse(source.replace(/,\s*([}\]])/gu, "$1")) as DeploymentConfig;
}
