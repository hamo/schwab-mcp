import { makeFormattingCharactersVisible } from "../security/display";

export type CsrfFlow = "consent" | "trade" | "schwab-reauthorization";

const CSRF_COOKIE_NAMES: Record<CsrfFlow, string> = {
  consent: "__Host-schwab_mcp_consent_csrf",
  trade: "__Host-schwab_mcp_trade_csrf",
  "schwab-reauthorization": "__Host-schwab_mcp_reauth_csrf",
};

export function consentPage(input: {
  clientName: string;
  clientId: string;
  redirectUri: string;
  scopes: string[];
  state: string;
  csrf: string;
  tradingEnabled: boolean;
  accessOrigin: string;
}): Response {
  const capabilities = input.tradingEnabled
    ? "Read Schwab account data. Trading tools may appear, but every live order requires a separate browser approval."
    : "Read Schwab account and market data. Trading tools are disabled for this deployment.";
  return htmlPage(
    "Authorize Schwab MCP",
    `<main><h1>Authorize Schwab MCP</h1>
      <p><strong>${escapeHtml(input.clientName)}</strong> is requesting access.</p>
      <p>${escapeHtml(capabilities)}</p>
      <dl><dt>Client ID</dt><dd><code>${escapeHtml(input.clientId)}</code></dd>
      <dt>Redirect URI</dt><dd><code>${escapeHtml(input.redirectUri)}</code></dd>
      <dt>Requested scopes</dt><dd><code>${escapeHtml(input.scopes.join(" ") || "mcp:read")}</code></dd></dl>
      <p>You will sign in through Cloudflare Access. Only the configured owner email is accepted.</p>
      <form method="post" action="/authorize">
        <input type="hidden" name="state" value="${escapeHtml(input.state)}">
        <input type="hidden" name="csrf" value="${escapeHtml(input.csrf)}">
        <button type="submit">Continue</button>
      </form></main>`,
    {
      "set-cookie": csrfCookie("consent", input.csrf),
      "content-security-policy": contentSecurityPolicy(input.accessOrigin),
    },
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
    { "set-cookie": csrfCookie("trade", input.csrf) },
  );
}

export function schwabReauthorizationPage(input: {
  state: string;
  csrf: string;
}): Response {
  return htmlPage(
    "Reconnect Schwab",
    `<main><h1>Reconnect Schwab</h1>
      <p>Your Schwab authorization will be replaced only after the new login succeeds.</p>
      <p>You will first sign in through Cloudflare Access. Only the configured owner email is accepted.</p>
      <form method="post" action="/schwab/reauthorize">
        <input type="hidden" name="state" value="${escapeHtml(input.state)}">
        <input type="hidden" name="csrf" value="${escapeHtml(input.csrf)}">
        <button type="submit">Continue to Schwab</button>
      </form></main>`,
    { "set-cookie": csrfCookie("schwab-reauthorization", input.csrf) },
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

export function csrfCookieName(flow: CsrfFlow): string {
  return CSRF_COOKIE_NAMES[flow];
}

export function clearCsrfCookie(flow: CsrfFlow): string {
  return `${csrfCookieName(flow)}=; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=0`;
}

function csrfCookie(flow: CsrfFlow, value: string): string {
  return `${csrfCookieName(flow)}=${value}; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=600`;
}

function contentSecurityPolicy(formRedirectOrigin?: string): string {
  let formAction = "'self'";
  if (formRedirectOrigin !== undefined) {
    const origin = new URL(formRedirectOrigin);
    if (origin.protocol !== "https:" || origin.origin !== formRedirectOrigin) {
      throw new Error("Form redirect origin must be an HTTPS origin");
    }
    formAction += ` ${origin.origin}`;
  }
  return `default-src 'none'; style-src 'unsafe-inline'; form-action ${formAction}; frame-ancestors 'none'; base-uri 'none'`;
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
      "content-security-policy": contentSecurityPolicy(),
      "referrer-policy": "no-referrer",
      "x-content-type-options": "nosniff",
      ...extraHeaders,
    },
  });
}

function escapeHtml(value: string): string {
  return makeFormattingCharactersVisible(value)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");
}
