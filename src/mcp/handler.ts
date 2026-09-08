import { WorkerEntrypoint } from "cloudflare:workers";
import { createMcpHandler } from "agents/mcp/server";
import { createSchwabMcpServer } from "./server";
import type { AuthProps, OAuthEnv } from "../types";

export class McpApiHandler extends WorkerEntrypoint<OAuthEnv, AuthProps> {
  async fetch(request: Request): Promise<Response> {
    const props = this.ctx.props;
    if (
      !props.email ||
      !Array.isArray(props.scopes) ||
      !props.scopes.every((scope) => typeof scope === "string") ||
      !props.scopes.includes("mcp:read") ||
      props.email.trim().toLowerCase() !==
        this.env.OWNER_EMAIL.trim().toLowerCase()
    ) {
      return Response.json({ error: "forbidden" }, { status: 403 });
    }
    const handler = createMcpHandler(
      () => createSchwabMcpServer(this.env, props.scopes),
      {
        route: "/mcp",
        corsOptions: false,
        authContext: { props },
      },
    );
    return handler(request, this.env, this.ctx);
  }
}
