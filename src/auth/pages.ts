export function consentPage(input: {
  clientName: string;
  state: string;
  csrf: string;
  tradingEnabled: boolean;
}): Response {
  const capabilities = input.tradingEnabled
    ? "Read Schwab account data. Trading tools may appear, but every live order requires a separate browser approval."
    : "Read Schwab account and market data. Trading tools are disabled for this deployment.";
  return htmlPage(
    "Authorize Schwab MCP",
    `<main><h1>Authorize Schwab MCP</h1>
      <p><strong>${escapeHtml(input.clientName)}</strong> is requesting access.</p>
      <p>${escapeHtml(capabilities)}</p>
      <p>You will sign in through Cloudflare Access. Only the configured owner email is accepted.</p>
      <form method="post" action="/authorize">
        <input type="hidden" name="state" value="${escapeHtml(input.state)}">
        <input type="hidden" name="csrf" value="${escapeHtml(input.csrf)}">
        <button type="submit">Continue</button>
      </form></main>`,
    { "set-cookie": csrfCookie(input.csrf) },
  );
}

export function tradeApprovalPage(input: {
  summary: string;
  digest: string;
  state: string;
  csrf: string;
  expiresAt: number;
}): Response {
  return htmlPage(
    "Approve Schwab order",
    `<main><h1>Approve live Schwab action</h1>
      <p class="warning">This action can place, replace, or cancel a real brokerage order.</p>
      <pre>${escapeHtml(input.summary)}</pre>
      <p>Digest: <code>${escapeHtml(input.digest)}</code></p>
      <p>Expires: ${escapeHtml(new Date(input.expiresAt).toISOString())}</p>
      <form method="post" action="/trade/approve">
        <input type="hidden" name="state" value="${escapeHtml(input.state)}">
        <input type="hidden" name="csrf" value="${escapeHtml(input.csrf)}">
        <button class="danger" type="submit">Approve this exact action</button>
      </form>
      <p>Close this page to deny. Unapproved requests expire automatically.</p></main>`,
  );
}

export function successPage(title: string, message: string): Response {
  return htmlPage(
    title,
    `<main><h1>${escapeHtml(title)}</h1><p>${escapeHtml(message)}</p></main>`,
  );
}

export function errorPage(message: string, status = 400): Response {
  return htmlPage(
    "Request blocked",
    `<main><h1>Request blocked</h1><p>${escapeHtml(message)}</p></main>`,
    {},
    status,
  );
}

export function readCookie(request: Request, name: string): string | null {
  const cookies = request.headers.get("cookie")?.split(";") ?? [];
  for (const cookie of cookies) {
    const [key, ...value] = cookie.trim().split("=");
    if (key === name) return value.join("=");
  }
  return null;
}

export function clearCsrfCookie(): string {
  return "__Host-schwab_mcp_csrf=; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=0";
}

function csrfCookie(value: string): string {
  return `__Host-schwab_mcp_csrf=${value}; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=600`;
}

function htmlPage(
  title: string,
  body: string,
  extraHeaders: Record<string, string> = {},
  status = 200,
): Response {
  const html = `<!doctype html><html lang="en"><head><meta charset="utf-8">
    <meta name="viewport" content="width=device-width,initial-scale=1">
    <title>${escapeHtml(title)}</title>
    <style>body{font:16px/1.5 system-ui,sans-serif;max-width:48rem;margin:4rem auto;padding:0 1rem;color:#17212b}main{border:1px solid #d9e0e7;border-radius:14px;padding:2rem}button{background:#1769aa;color:white;border:0;border-radius:8px;padding:.7rem 1rem;font-weight:650;cursor:pointer}.danger{background:#a51d2d}.warning{color:#8a1422;font-weight:700}pre{white-space:pre-wrap;background:#f5f7f9;padding:1rem;border-radius:8px;overflow:auto}code{overflow-wrap:anywhere}</style>
    </head><body>${body}</body></html>`;
  return new Response(html, {
    status,
    headers: {
      "content-type": "text/html; charset=utf-8",
      "cache-control": "no-store",
      "content-security-policy":
        "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'",
      "referrer-policy": "no-referrer",
      "x-content-type-options": "nosniff",
      ...extraHeaders,
    },
  });
}

function escapeHtml(value: string): string {
  return value
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");
}
