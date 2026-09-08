import { WorkerEntrypoint } from "cloudflare:workers";
import { createMcpHandler } from "agents/mcp/server";
import { createSchwabMcpServer } from "./server";
import type { AuthProps, OAuthEnv } from "../types";

export class McpApiHandler extends WorkerEntrypoint<OAuthEnv, AuthProps> {
  async fetch(request: Request): Promise<Response> {
    const props = this.ctx.props;
    if (
      !props.email ||
      props.email.trim().toLowerCase() !==
        this.env.OWNER_EMAIL.trim().toLowerCase()
    ) {
      return Response.json({ error: "forbidden" }, { status: 403 });
    }
    const handler = createMcpHandler(() => createSchwabMcpServer(this.env), {
      route: "/mcp",
      corsOptions: false,
      authContext: { props },
    });
    return handler(request, this.env, this.ctx);
  }
}
